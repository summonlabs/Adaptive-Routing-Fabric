// arf_publisher -- a real publishing process.
//
// A publisher is a separate OS process with its own socket to the coordinator.
// It registers exactly one incarnation (publisher id plus worker boot id),
// executes a deterministic script of operations and reports one line per
// command, so a distributed test can assert what the runtime answered without
// reaching into the library and without polling a pipe for state.
//
// OUTPUT CONTRACT
// ---------------
//   READY                                   registration succeeded
//   <index> <OUTCOME> ...                   one line per executed command
//   DONE                                    the whole script ran without a refusal
//   CONNECT-FAILED | REGISTER-FAILED <O> | SCRIPT-ERROR ...
//   <index> TRANSPORT_ERROR <text>          the session failed mid-script
//
// The command line shape is
//   <index> <OUTCOME>[ policy=<id>][ suppression=<why>][ detail=<text>]
// with the 1-based index of the executed command, so create-policy reports
// exactly "2 POLICY_CREATED policy=<id> detail=policy created".
#include "tool_common.hpp"

#include <chrono>
#include <fstream>
#include <map>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using namespace arf_tool;

constexpr std::string_view tool_name = "arf_publisher";

void print_usage(std::ostream& stream) {
  stream << "Adaptive Routing Fabric publisher\n";
  stream << "\n";
  stream << "usage: arf_publisher --endpoint HOST:PORT --publisher ID --boot ID --session ID\n";
  stream << "                     [--script PATH] [--linger] [--output PATH]\n";
  stream << "                     [--fabric ID] [--namespace ID] [--source ID]\n";
  stream << "                     [--source-generation N] [--route ID]\n";
  stream << "\n";
  stream << "  --endpoint HOST:PORT  coordinator to connect to (ARF_ENDPOINT is consulted\n";
  stream << "                        when the flag is absent)\n";
  stream << "  --publisher ID        publisher identity to register\n";
  stream << "  --boot ID             worker boot incarnation to register; a boot that was\n";
  stream << "                        fenced is refused by the coordinator\n";
  stream << "  --session ID          this process incarnation, used as the identity prefix\n";
  stream << "                        of the client session\n";
  stream << "  --script PATH         command script to execute after registration\n";
  stream << "  --linger              stay alive after the script so a test can terminate\n";
  stream << "                        this process with a real OS process kill\n";
  stream << "  --output PATH         append the same lines to PATH, flushed per line, so a\n";
  stream << "                        test can poll a file instead of a pipe\n";
  stream << "  --fabric ID           authority scope fabric (default fabric-alpha)\n";
  stream << "  --namespace ID        authority scope routing namespace (default routing-core)\n";
  stream << "  --source ID           evidence source id (default: the publisher id)\n";
  stream << "  --source-generation N evidence source incarnation (default 1)\n";
  stream << "  --route ID            route used by declare for a policy this script did not\n";
  stream << "                        create (default route-1)\n";
  stream << "  --help                print this text and exit\n";
  stream << "\n";
  stream << "script grammar, one command per line, '#' starts a comment, blank lines ignored:\n";
  stream << "  create-policy <name> <route-id> <switch-bps> <reverse-bps>\n";
  stream << "  declare <policy-id|@policy> <path-id> <path-authority-generation>"
            " [route-generation]\n";
  stream << "  evidence <path-id> <METRIC_KIND> <value> [PRIMARY|AGGREGATED|OPERATOR|ESTIMATED]\n";
  stream << "  evaluate <policy-id|@policy>\n";
  stream << "  snapshot <policy-id|@policy>\n";
  stream << "  revalidate <policy-id|@policy>\n";
  stream << "  advance-epoch <reason>\n";
  stream << "  fence <publisher-id> <boot-id> <cause>\n";
  stream << "  say <free text>\n";
  stream << "\n";
  stream << "@policy means the policy most recently created by create-policy in this script;\n";
  stream << "using it before any create-policy is a script error. The observation sequence of\n";
  stream << "published evidence is strictly increasing per (path, metric).\n";
  stream << "\n";
  stream << "exit codes: 0 script applied, 1 command refused or session lost, 2 usage error,\n";
  stream << "            3 registration refused, 4 script error, 5 connect/handshake failure\n";
}

[[nodiscard]] bool read_script(const std::string& path, std::vector<std::string>& lines,
                               std::string& error) {
  std::ifstream stream(path, std::ios::in | std::ios::binary);
  if (!stream.is_open()) {
    error = "the script " + path + " could not be opened";
    return false;
  }
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    lines.push_back(std::move(line));
  }
  return true;
}

struct Options {
  Endpoint endpoint;
  PublisherId publisher;
  WorkerBootId worker_boot;
  std::string session_label;
  FabricId fabric;
  RoutingNamespace name_space;
  EvidenceSourceId source;
  std::uint32_t source_generation = 1;
  RouteId default_route;
  std::string script_path;
  std::string output_path;
  bool linger = false;
};

// The policy shape the script's create-policy command declares: one latency
// improvement trigger, the matching required evidence and a lexicographic
// objective on the same metric, with every other rule left at its disabled
// default so the runtime holds nothing the script did not ask for.
[[nodiscard]] PolicySemantics latency_semantics(const RouteId& route, std::uint32_t switch_bps,
                                                std::uint32_t reverse_bps) {
  PolicySemantics semantics;
  semantics.target.route = route;
  ImprovementRule improvement;
  improvement.kind = MetricKind::PATH_LATENCY;
  improvement.switch_improvement_bps = switch_bps;
  improvement.reverse_improvement_bps = reverse_bps;
  semantics.improvements.push_back(improvement);

  EvidenceRequirement requirement;
  requirement.kind = MetricKind::PATH_LATENCY;
  requirement.aggregation = AggregationKind::MEAN;
  // A MEAN requirement carries no EWMA alpha: the struct default is an alpha,
  // and EvidenceRequirement::valid() rejects an alpha beside a non-EWMA
  // aggregation rather than ignoring it.
  requirement.ewma_alpha_bps = 0;
  requirement.min_samples = 1;
  requirement.max_age = seconds(120);
  requirement.min_window = 0;
  requirement.min_quality = EvidenceQuality::AGGREGATED;
  requirement.required = true;
  semantics.evidence.push_back(requirement);

  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = MetricKind::PATH_LATENCY;
  term.weight_bps = 0;
  objective.terms.push_back(term);
  semantics.objective = objective;
  return semantics;
}

// The only sleep in the tools, and it exists for exactly one reason: --linger
// keeps a registered publisher alive so a test can terminate it with a real OS
// process kill instead of racing its exit.
void linger_until_terminated() {
  const std::chrono::milliseconds slice(100);
  for (;;) {
    std::this_thread::sleep_for(slice);
  }
}

// Executes one script against one registered session. All script state lives
// here: the current '@policy' binding, the route of every policy this script
// created, and the monotonic observation sequence per (path, metric).
class ScriptRunner {
 public:
  ScriptRunner(ClientSession& session, const Options& options, OutputChannel& channel)
      : session_(session), options_(options), channel_(channel) {}

  [[nodiscard]] int run(const std::vector<std::string>& lines) {
    for (const std::string& raw : lines) {
      const std::string_view text = trim(raw);
      if (text.empty() || text.front() == '#') {
        continue;
      }
      const std::vector<std::string> fields = split_fields(text);
      if (fields.empty()) {
        continue;
      }
      const std::size_t index = ++command_index_;
      const std::optional<int> terminal = execute(index, fields, text);
      if (terminal.has_value()) {
        return *terminal;
      }
    }
    return refused_ ? exit_refused : exit_ok;
  }

 private:
  [[nodiscard]] std::optional<int> execute(std::size_t index,
                                           const std::vector<std::string>& fields,
                                           std::string_view text) {
    const std::string& command = fields[0];
    if (command == "say") {
      report_plain(index, "OK", rest_after_fields(text, 1));
      return std::nullopt;
    }
    if (command == "create-policy") {
      return create_policy(index, fields);
    }
    if (command == "declare") {
      return declare(index, fields);
    }
    if (command == "evidence") {
      return evidence(index, fields);
    }
    if (command == "evaluate") {
      return evaluate(index, fields);
    }
    if (command == "snapshot") {
      return snapshot(index, fields);
    }
    if (command == "revalidate") {
      return revalidate(index, fields);
    }
    if (command == "advance-epoch") {
      return advance_epoch(index, text);
    }
    if (command == "fence") {
      return fence(index, fields, text);
    }
    return script_error(index, "unknown command '" + command + "'");
  }

  [[nodiscard]] std::optional<int> create_policy(std::size_t index,
                                                 const std::vector<std::string>& fields) {
    if (fields.size() != 5) {
      return script_error(
          index, "create-policy expects <name> <route-id> <switch-bps> <reverse-bps>");
    }
    const std::optional<AdaptivePolicyName> name = AdaptivePolicyName::parse(fields[1]);
    if (!name.has_value()) {
      return script_error(index, "'" + fields[1] + "' is not a valid policy name");
    }
    const std::optional<RouteId> route = RouteId::parse(fields[2]);
    if (!route.has_value()) {
      return script_error(index, "'" + fields[2] + "' is not a valid route id");
    }
    std::uint32_t switch_bps = 0;
    std::uint32_t reverse_bps = 0;
    if (!parse_bounded_u32(fields[3], switch_bps) || switch_bps > basis_points_scale) {
      return script_error(index, "'" + fields[3] + "' is not a basis point count");
    }
    if (!parse_bounded_u32(fields[4], reverse_bps) || reverse_bps > basis_points_scale) {
      return script_error(index, "'" + fields[4] + "' is not a basis point count");
    }

    CreatePolicyMessage message;
    message.name = *name;
    // A publisher authors policies only inside the fabric and routing namespace
    // it registered for, and the registration covers every route in it.
    message.scope = make_policy_scope(options_.fabric, options_.name_space);
    message.semantics = latency_semantics(*route, switch_bps, reverse_bps);

    std::string error;
    const std::optional<ResultMessage> created = session_.client->create_policy(message, error);
    if (!created.has_value()) {
      return transport_error(index, error);
    }
    if (!outcome_is_success(created->outcome)) {
      report(index, *created);
      return std::nullopt;
    }
    const AdaptivePolicyId policy = created->policy;

    // A DECLARED policy adapts nothing, and the script shape has no separate
    // activation step, so the policy is activated as part of this command.
    PolicyLifecycleMessage activation;
    activation.policy = policy;
    activation.event = PolicyEvent::ACTIVATE;
    activation.detail = "publisher activation";
    const std::optional<ResultMessage> activated =
        session_.client->policy_lifecycle(activation, error);
    if (!activated.has_value()) {
      return transport_error(index, error);
    }
    current_policy_ = policy;
    policy_routes_.emplace(policy.str(), *route);
    if (!outcome_is_success(activated->outcome)) {
      // The policy exists but is not adaptable. Its identity stays bound to
      // '@policy' so the diagnostics that follow name the right policy.
      report(index, *activated);
      return std::nullopt;
    }
    report(index, *created);
    return std::nullopt;
  }

  [[nodiscard]] std::optional<int> declare(std::size_t index,
                                           const std::vector<std::string>& fields) {
    if (fields.size() != 4 && fields.size() != 5) {
      return script_error(index,
                          "declare expects <policy-id|@policy> <path-id> "
                          "<path-authority-generation> [route-generation]");
    }
    std::string error;
    const std::optional<AdaptivePolicyId> policy = resolve_policy(fields[1], error);
    if (!policy.has_value()) {
      return script_error(index, error);
    }
    const std::optional<PathId> path = PathId::parse(fields[2]);
    if (!path.has_value()) {
      return script_error(index, "'" + fields[2] + "' is not a valid path id");
    }
    std::uint64_t authority_generation = 0;
    if (!parse_unsigned(fields[3], authority_generation) || authority_generation == 0) {
      return script_error(index, "'" + fields[3] + "' is not a path authority generation");
    }
    std::uint64_t route_generation = 1;
    if (fields.size() == 5 &&
        (!parse_unsigned(fields[4], route_generation) || route_generation == 0)) {
      return script_error(index, "'" + fields[4] + "' is not a route generation");
    }

    CandidateBinding binding;
    binding.path = *path;
    binding.path_authority.path = *path;
    binding.path_authority.generation = PathAuthorityGeneration::require(authority_generation);
    // The script declares a path it is entitled to offer; a denial is expressed
    // by a separate upstream notification, not by a declare that says "illegal".
    binding.path_authority.legal = true;
    binding.route.route = route_for(*policy);
    binding.route.generation = RouteGeneration::require(route_generation);
    binding.route.current = true;
    binding.available = true;
    binding.hard_failure = false;

    UpstreamNotification notification;
    notification.event = UpstreamEvent::DECLARE_CANDIDATE;
    notification.policy = *policy;
    notification.binding = binding;
    notification.provenance.publisher = options_.publisher;
    notification.provenance.worker_boot = options_.worker_boot;
    notification.provenance.epoch = session_.epoch;
    notification.provenance.attempt =
        make_upstream_attempt(session_.client->session(), ++notification_attempts_);
    notification.provenance.origin = "arf-publisher";

    UpstreamNotifyMessage message;
    message.notifications.push_back(notification);
    const std::optional<ResultMessage> result = session_.client->upstream_notify(message, error);
    if (!result.has_value()) {
      return transport_error(index, error);
    }
    report(index, *result);
    return std::nullopt;
  }

  [[nodiscard]] std::optional<int> evidence(std::size_t index,
                                            const std::vector<std::string>& fields) {
    if (fields.size() != 4 && fields.size() != 5) {
      return script_error(index,
                          "evidence expects <path-id> <METRIC_KIND> <value> "
                          "[PRIMARY|AGGREGATED|OPERATOR|ESTIMATED]");
    }
    const std::optional<PathId> path = PathId::parse(fields[1]);
    if (!path.has_value()) {
      return script_error(index, "'" + fields[1] + "' is not a valid path id");
    }
    const std::optional<MetricKind> kind = parse_metric_kind(fields[2]);
    if (!kind.has_value()) {
      return script_error(index, "'" + fields[2] + "' is not a metric kind");
    }
    std::int64_t value = 0;
    if (!parse_integer(fields[3], value)) {
      return script_error(index, "'" + fields[3] + "' is not an integer metric value");
    }
    const std::optional<MetricValue> metric = MetricValue::make(*kind, value);
    if (!metric.has_value()) {
      return script_error(index,
                          "'" + fields[3] + "' is outside the declared range of " + fields[2]);
    }
    std::string error;
    EvidenceQuality quality = EvidenceQuality::PRIMARY;
    if (fields.size() == 5) {
      const std::optional<EvidenceQuality> parsed = parse_evidence_quality(fields[4]);
      if (!parsed.has_value()) {
        return script_error(index, "'" + fields[4] + "' is not an evidence quality class");
      }
      quality = *parsed;
    }

    EvidencePublication publication;
    publication.source = options_.source;
    publication.source_generation = EvidenceSourceGeneration::require(options_.source_generation);
    publication.quality = quality;
    publication.path = *path;
    publication.value = *metric;
    publication.observation_sequence = next_observation_sequence(*path, *kind);

    PublishEvidenceMessage message;
    message.publications.push_back(publication);
    const std::optional<ResultMessage> result = session_.client->publish_evidence(message, error);
    if (!result.has_value()) {
      return transport_error(index, error);
    }
    report(index, *result);
    return std::nullopt;
  }

  [[nodiscard]] std::optional<int> evaluate(std::size_t index,
                                            const std::vector<std::string>& fields) {
    if (fields.size() != 2) {
      return script_error(index, "evaluate expects <policy-id|@policy>");
    }
    std::string error;
    const std::optional<AdaptivePolicyId> policy = resolve_policy(fields[1], error);
    if (!policy.has_value()) {
      return script_error(index, error);
    }
    EvaluateMessage message;
    message.policy = *policy;
    const std::optional<ResultMessage> result = session_.client->evaluate(message, error);
    if (!result.has_value()) {
      return transport_error(index, error);
    }
    report(index, *result);
    return std::nullopt;
  }

  [[nodiscard]] std::optional<int> snapshot(std::size_t index,
                                            const std::vector<std::string>& fields) {
    if (fields.size() != 2) {
      return script_error(index, "snapshot expects <policy-id|@policy>");
    }
    std::string error;
    const std::optional<AdaptivePolicyId> policy = resolve_policy(fields[1], error);
    if (!policy.has_value()) {
      return script_error(index, error);
    }
    SnapshotRequestMessage request;
    request.policy = *policy;
    // A snapshot response carries no OperationResult, so it is issued through
    // the raw frame surface: both documented response shapes are decoded here.
    const std::optional<Frame> response =
        session_.client->request(MessageId::SNAPSHOT_REQUEST, request.encode(), error);
    if (!response.has_value()) {
      return transport_error(index, error);
    }
    if (response->header.message_id == MessageId::ERROR) {
      const std::optional<ErrorMessage> failure = ErrorMessage::decode(response->payload);
      if (!failure.has_value()) {
        return transport_error(index, "the ERROR payload could not be decoded");
      }
      ResultMessage reported;
      reported.outcome = failure->outcome;
      reported.detail = failure->detail;
      reported.policy = *policy;
      report(index, reported);
      return std::nullopt;
    }
    if (response->header.message_id != MessageId::SNAPSHOT_RESPONSE) {
      return transport_error(index, "unexpected response " +
                                        std::string(to_string(response->header.message_id)) +
                                        " to SNAPSHOT_REQUEST");
    }
    const std::optional<SnapshotResponseMessage> decoded =
        SnapshotResponseMessage::decode(response->payload);
    if (!decoded.has_value()) {
      return transport_error(index, "the SNAPSHOT_RESPONSE payload could not be decoded");
    }
    report_plain(index, "OK", "snapshot=" + decoded->snapshot.str() + " digest=" + decoded->digest);
    return std::nullopt;
  }

  [[nodiscard]] std::optional<int> revalidate(std::size_t index,
                                              const std::vector<std::string>& fields) {
    if (fields.size() != 2) {
      return script_error(index, "revalidate expects <policy-id|@policy>");
    }
    std::string error;
    const std::optional<AdaptivePolicyId> policy = resolve_policy(fields[1], error);
    if (!policy.has_value()) {
      return script_error(index, error);
    }
    RevalidateMessage message;
    message.policy = *policy;
    message.attempt =
        make_revalidation_attempt(session_.client->session(), ++revalidation_attempts_);
    const std::optional<ResultMessage> result = session_.client->revalidate(message, error);
    if (!result.has_value()) {
      return transport_error(index, error);
    }
    report(index, *result);
    return std::nullopt;
  }

  [[nodiscard]] std::optional<int> advance_epoch(std::size_t index, std::string_view text) {
    const std::string reason = rest_after_fields(text, 1);
    const std::optional<ResultMessage> result =
        session_.client->advance_epoch(reason.empty() ? "operator" : reason, error_scratch_);
    if (!result.has_value()) {
      return transport_error(index, error_scratch_);
    }
    report(index, *result);
    return std::nullopt;
  }

  [[nodiscard]] std::optional<int> fence(std::size_t index,
                                         const std::vector<std::string>& fields,
                                         std::string_view text) {
    if (fields.size() < 4) {
      return script_error(index, "fence expects <publisher-id> <boot-id> <cause>");
    }
    const std::optional<PublisherId> publisher = PublisherId::parse(fields[1]);
    if (!publisher.has_value()) {
      return script_error(index, "'" + fields[1] + "' is not a valid publisher id");
    }
    const std::optional<WorkerBootId> worker_boot = WorkerBootId::parse(fields[2]);
    if (!worker_boot.has_value()) {
      return script_error(index, "'" + fields[2] + "' is not a valid worker boot id");
    }
    const std::string cause = rest_after_fields(text, 3);
    const std::optional<ResultMessage> result =
        session_.client->fence(*publisher, *worker_boot, cause, error_scratch_);
    if (!result.has_value()) {
      return transport_error(index, error_scratch_);
    }
    report(index, *result);
    return std::nullopt;
  }

  // Resolves a policy reference: either the literal '@policy' binding or an
  // explicit identity. A reference that cannot be resolved is a script error,
  // because the script asked for something it cannot name.
  [[nodiscard]] std::optional<AdaptivePolicyId> resolve_policy(const std::string& token,
                                                               std::string& error) const {
    if (token == "@policy") {
      if (!current_policy_.has_value()) {
        error = "'@policy' is used before any create-policy in this script";
        return std::nullopt;
      }
      return current_policy_;
    }
    const std::optional<AdaptivePolicyId> parsed = AdaptivePolicyId::parse(token);
    if (!parsed.has_value()) {
      error = "'" + token + "' is not a valid policy id";
      return std::nullopt;
    }
    return parsed;
  }

  [[nodiscard]] RouteId route_for(const AdaptivePolicyId& policy) const {
    const auto position = policy_routes_.find(policy.str());
    if (position != policy_routes_.end()) {
      return position->second;
    }
    return options_.default_route;
  }

  // Strictly increasing per (path, metric): the coordinator rejects a repeated
  // or decreasing observation sequence, so the publisher owns the counter.
  [[nodiscard]] std::uint64_t next_observation_sequence(const PathId& path, MetricKind kind) {
    const std::string key = path.str() + "|" + std::string(to_string(kind));
    std::uint64_t& sequence = sequences_[key];
    ++sequence;
    return sequence;
  }

  void report(std::size_t index, const ResultMessage& message) {
    std::string line = std::to_string(index);
    line += " ";
    line += to_string(message.outcome);
    if (message.policy.valid()) {
      line += " policy=";
      line += message.policy.str();
    }
    if (message.suppression != SuppressionReason::NONE) {
      line += " suppression=";
      line += to_string(message.suppression);
    }
    if (!message.detail.empty()) {
      line += " detail=";
      line += message.detail;
    }
    channel_.line(line);
    if (outcome_is_refusal(message.outcome)) {
      refused_ = true;
    }
  }

  void report_plain(std::size_t index, std::string_view outcome, std::string_view tail) {
    std::string line = std::to_string(index);
    line += " ";
    line += outcome;
    if (!tail.empty()) {
      line += " ";
      line += tail;
    }
    channel_.line(line);
  }

  [[nodiscard]] std::optional<int> script_error(std::size_t index, const std::string& text) {
    channel_.line("SCRIPT-ERROR line " + std::to_string(index) + ": " + text);
    return publisher_exit_script;
  }

  [[nodiscard]] std::optional<int> transport_error(std::size_t index, const std::string& text) {
    // The command produced no coordinator outcome. The script stops: a session
    // that lost its peer cannot answer any later command either.
    channel_.line(std::to_string(index) + " TRANSPORT_ERROR " + text);
    write_stderr_line(std::string(tool_name) + ": " + text);
    return exit_refused;
  }

  ClientSession& session_;
  const Options& options_;
  OutputChannel& channel_;
  std::optional<AdaptivePolicyId> current_policy_;
  std::map<std::string, RouteId> policy_routes_;
  std::map<std::string, std::uint64_t> sequences_;
  std::size_t command_index_ = 0;
  std::uint64_t revalidation_attempts_ = 0;
  std::uint64_t notification_attempts_ = 0;
  bool refused_ = false;
  std::string error_scratch_;
};

[[nodiscard]] int run(const ArgSet& args) {
  if (args.has("help")) {
    print_usage(std::cout);
    return exit_ok;
  }
  const auto usage_error = [](const std::string& message) {
    write_stderr_line(std::string(tool_name) + ": " + message);
    print_usage(std::cerr);
    return exit_usage;
  };

  const std::optional<std::string> unknown = args.first_unknown(
      {"endpoint", "publisher", "boot", "session", "script", "linger", "output", "fabric",
       "namespace", "source", "source-generation", "route", "help"});
  if (unknown.has_value()) {
    return usage_error("unknown option --" + *unknown);
  }

  Options options;
  const std::optional<std::string> publisher_text = args.value("publisher");
  if (!publisher_text.has_value() || publisher_text->empty()) {
    return usage_error("--publisher ID is required");
  }
  const std::optional<PublisherId> publisher = PublisherId::parse(*publisher_text);
  if (!publisher.has_value()) {
    return usage_error("--publisher '" + *publisher_text + "' is not a valid PublisherId");
  }
  options.publisher = *publisher;

  const std::optional<std::string> boot_text = args.value("boot");
  if (!boot_text.has_value() || boot_text->empty()) {
    return usage_error("--boot ID is required");
  }
  const std::optional<WorkerBootId> worker_boot = WorkerBootId::parse(*boot_text);
  if (!worker_boot.has_value()) {
    return usage_error("--boot '" + *boot_text + "' is not a valid WorkerBootId");
  }
  options.worker_boot = *worker_boot;

  const std::optional<std::string> session_text = args.value("session");
  if (!session_text.has_value() || session_text->empty()) {
    return usage_error("--session ID is required");
  }
  const std::optional<SessionId> session_id = SessionId::parse(*session_text);
  if (!session_id.has_value()) {
    return usage_error("--session '" + *session_text + "' is not a valid SessionId");
  }
  options.session_label = session_id->str();

  const std::string fabric_text = args.value("fabric").value_or(std::string(default_fabric));
  const std::optional<FabricId> fabric = FabricId::parse(fabric_text);
  if (!fabric.has_value()) {
    return usage_error("--fabric '" + fabric_text + "' is not a valid FabricId");
  }
  options.fabric = *fabric;

  const std::string namespace_text =
      args.value("namespace").value_or(std::string(default_routing_namespace));
  const std::optional<RoutingNamespace> name_space = RoutingNamespace::parse(namespace_text);
  if (!name_space.has_value()) {
    return usage_error("--namespace '" + namespace_text + "' is not a valid RoutingNamespace");
  }
  options.name_space = *name_space;

  const std::string source_text = args.value("source").value_or(options.publisher.str());
  const std::optional<EvidenceSourceId> source = EvidenceSourceId::parse(source_text);
  if (!source.has_value()) {
    return usage_error("--source '" + source_text + "' is not a valid EvidenceSourceId");
  }
  options.source = *source;

  if (const std::optional<std::string> generation_text = args.value("source-generation");
      generation_text.has_value()) {
    std::uint64_t generation = 0;
    if (!parse_unsigned(*generation_text, generation) || generation == 0) {
      return usage_error("--source-generation must be a positive integer");
    }
    options.source_generation = static_cast<std::uint32_t>(generation);
  }

  const std::string route_text = args.value("route").value_or(std::string(default_route));
  const std::optional<RouteId> route = RouteId::parse(route_text);
  if (!route.has_value()) {
    return usage_error("--route '" + route_text + "' is not a valid RouteId");
  }
  options.default_route = *route;

  std::string error;
  if (!resolve_endpoint(args, std::string_view(), options.endpoint, error)) {
    return usage_error(error);
  }
  options.script_path = args.value("script").value_or(std::string());
  options.output_path = args.value("output").value_or(std::string());
  options.linger = args.has("linger");
  if (!args.positional.empty()) {
    return usage_error("unexpected argument '" + args.positional[0] + "'");
  }

  OutputChannel channel;
  if (!options.output_path.empty()) {
    channel.open_mirror(options.output_path);
    if (!channel.mirror_ready()) {
      return usage_error(channel.mirror_error());
    }
  }

  // The script is read before a session is opened: a script that cannot be read
  // must not leave a registration behind on the coordinator.
  std::vector<std::string> script;
  if (!options.script_path.empty() && !read_script(options.script_path, script, error)) {
    channel.line("SCRIPT-ERROR " + error);
    return publisher_exit_script;
  }

  SessionRequest request;
  request.endpoint = options.endpoint;
  request.scope = make_authority_scope(options.fabric, options.name_space);
  request.id_prefix = options.session_label;
  request.publisher = options.publisher;
  request.worker_boot = options.worker_boot;
  ClientSession session = open_session(request);
  if (!session.outcome.connected || !session.outcome.greeting) {
    // The coordinator was never reached, or it closed before answering HELLO.
    // Either way the session does not exist, which is a connection failure
    // rather than a rejected registration.
    channel.line("CONNECT-FAILED");
    write_stderr_line(std::string(tool_name) + ": " + session.outcome.error);
    return publisher_exit_connect;
  }
  if (!session.outcome.registered) {
    // A fenced incarnation names the outcome it was refused with, which is how
    // a test proves that a fenced worker can never re-register.
    channel.line("REGISTER-FAILED " +
                 std::string(to_string(session.outcome.registration_outcome)));
    write_stderr_line(std::string(tool_name) + ": registration refused: " +
                      session.outcome.registration_detail);
    return publisher_exit_register;
  }
  channel.line("READY");

  ScriptRunner runner(session, options, channel);
  const int status = runner.run(script);
  if (status == exit_ok) {
    channel.line("DONE");
    if (options.linger) {
      linger_until_terminated();
    }
  }
  close_session(session);
  return status;
}

}  // namespace

int main(int argc, char** argv) {
  configure_standard_streams();
  const ArgSet args = parse_args(argc, argv);
  return run(args);
}

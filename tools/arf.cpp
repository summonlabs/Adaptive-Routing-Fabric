// arf -- the Adaptive Routing Fabric operator CLI.
//
// Every command except the locally answered ones (limits, version, help and
// store inspect) talks to a coordinator through CoordinatorClient. The CLI
// creates the publisher identity it mutates with, registers it, performs the
// command and ends the session, so an operator never has to manage authority by
// hand and a test can drive the runtime with one process per command.
//
// OUTPUT CONTRACT
// ---------------
//   mutations        one line: the coordinator's OperationResult rendering
//   state queries    one 'key=value' per line, in a documented order
//   snapshot/explain/diff   the coordinator's rendering of that view
//   store inspect    key=value: path, bytes, status, detail, then the record
//                    counts and the persisted epoch of a store that decoded
//   limits/version   key=value
//
// Nothing else is written to stdout. Diagnostics go to stderr, and the process
// exit code is 0 for an applied command or a deterministic no-adaptation
// answer, 1 for a refused command or an unreachable coordinator, and 2 for a
// usage error.
#include "tool_common.hpp"

#include <cstdint>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace arf_tool;

constexpr std::string_view tool_name = "arf";

// The CLI registers one stable publisher identity. A fresh identity per
// invocation would fill the coordinator's publisher table (Limits::max_publishers)
// and fence the previous invocation on every run, so the identity is stable and
// only the client session is per process.
constexpr std::string_view cli_publisher = "arf-cli";
constexpr std::string_view cli_worker_boot = "arf-cli-boot";
constexpr std::string_view cli_id_prefix = "arf-cli";
constexpr std::string_view cli_evidence_source = "operator-cli";

void print_usage(std::ostream& stream) {
  stream << "Adaptive Routing Fabric operator CLI\n";
  stream << "\n";
  stream << "usage: arf [--endpoint HOST:PORT] [--fabric ID] [--namespace ID] <command> [args]\n";
  stream << "\n";
  stream << "  --endpoint HOST:PORT  coordinator to talk to; falls back to $ARF_ENDPOINT,\n";
  stream << "                        then to 127.0.0.1:7331\n";
  stream << "  --fabric ID           authority scope fabric (default fabric-alpha)\n";
  stream << "  --namespace ID        authority scope routing namespace (default routing-core)\n";
  stream << "\n";
  stream << "commands:\n";
  stream << "  policy create --name NAME --route ROUTE [semantics] [--activate]\n";
  stream << "  policy show <policy-id>\n";
  stream << "  policy list [--limit N]\n";
  stream << "  policy update <policy-id> --route ROUTE [semantics]\n";
  stream << "  policy activate <policy-id>\n";
  stream << "  policy suspend <policy-id>\n";
  stream << "  policy resume <policy-id>\n";
  stream << "  evidence publish --path PATH --metric KIND --value V [--quality Q]\n";
  stream << "                   [--source ID] [--source-generation N] [--sequence N]\n";
  stream << "  evaluate <policy-id> [--defer]\n";
  stream << "  state show [--policy ID] [--limit N]\n";
  stream << "  explain <policy-id> [--topic TOPIC]\n";
  stream << "  snapshot <policy-id>\n";
  stream << "  diff <policy-id> <from-snapshot> <to-snapshot>\n";
  stream << "  revalidate <policy-id>\n";
  stream << "  revoke <policy-id> [--reason REASON] [--detail TEXT]\n";
  stream << "  retire <policy-id> [--detail TEXT]\n";
  stream << "  store inspect <path>\n";
  stream << "  limits\n";
  stream << "  version\n";
  stream << "  help [command]\n";
  stream << "\n";
  stream << "semantics options (policy create and policy update replace the whole value):\n";
  stream << "  --fabric ID --namespace ID --route ID [--multipath-set ID] [--site ID]\n";
  stream << "  [--path-class ID] [--scope-route ID] [--scope-multipath-set ID]\n";
  stream << "  --threshold KIND:SWITCH:CLEAR ...\n";
  stream << "  --improvement KIND:SWITCH_BPS:REVERSE_BPS ...\n";
  stream << "  --evidence KIND:AGGREGATION:MIN_SAMPLES:MAX_AGE_MS:MIN_QUALITY\n";
  stream << "             [:MIN_WINDOW_MS][:EWMA_ALPHA_BPS][:required|optional] ...\n";
  stream << "  --objective KIND[:WEIGHT_BPS] ...   (a non-zero weight selects\n";
  stream << "                                      WEIGHTED_SCORE, otherwise LEXICOGRAPHIC)\n";
  stream << "  --hold-down-ms N --cooldown-ms N --churn MAX:WINDOW_MS\n";
  stream << "  --dampening INCREMENT:MAX_PENALTY:DECAY_MS:DECAY_STEP:ESCALATION_MS:MAX_HOLD_MS\n";
  stream << "  --emergency unauthorized|unavailable|hard-failure ...\n";
  stream << "  --priority PATH:PRIORITY ...\n";
  stream << "\n";
  stream << "exit codes: 0 applied or a deterministic no-adaptation answer, 1 refused,\n";
  stream << "            2 usage error\n";
}

// One line per command, so 'arf help <command>' answers without the whole list.
[[nodiscard]] bool print_command_help(std::ostream& stream, std::string_view command) {
  if (command == "policy" || command == "policy-create") {
    stream << "policy create --name NAME --route ROUTE [semantics] [--activate]\n";
    stream << "  Creates a policy in the fabric/namespace scope and prints the creation\n";
    stream << "  result. --activate then activates it and prints the activation result.\n";
  } else if (command == "policy-show" || command == "policy-list") {
    stream << "policy show <policy-id> | policy list [--limit N]\n";
    stream << "  Prints epoch=<E>, count=<N> and one line per policy:\n";
    stream << "  policy=<id> name=<n> lifecycle=<l> generation=<g> epoch=<e> digest=<d>\n";
  } else if (command == "policy-update") {
    stream << "policy update <policy-id> --route ROUTE [semantics]\n";
    stream << "  Replaces the whole scope and semantics value; a partial patch is not\n";
    stream << "  supported because a generation boundary is a semantic boundary.\n";
  } else if (command == "policy-activate" || command == "policy-suspend" ||
             command == "policy-resume") {
    stream << "policy activate|suspend|resume <policy-id> [--detail TEXT]\n";
    stream << "  Sends the matching lifecycle event and prints the result.\n";
  } else if (command == "evidence" || command == "evidence-publish") {
    stream << "evidence publish --path PATH --metric KIND --value V [--quality Q]\n";
    stream << "                 [--source ID] [--source-generation N] [--sequence N]\n";
    stream << "  Publishes one bounded integer sample. The observation sequence must be\n";
    stream << "  strictly increasing per (source, path, metric); --source defaults to\n";
    stream << "  '" << cli_evidence_source << "' and --sequence to 1.\n";
  } else if (command == "evaluate") {
    stream << "evaluate <policy-id> [--defer]\n";
    stream << "  Runs the two-phase evaluation. --defer stops after phase one and prints\n";
    stream << "  the dependency snapshot instead of committing.\n";
  } else if (command == "state" || command == "state-show") {
    stream << "state show [--policy ID] [--limit N]\n";
    stream << "  Prints epoch=<E>, count=<N> and one 'policy=...' line per matching policy.\n";
  } else if (command == "explain") {
    stream << "explain <policy-id> [--topic TOPIC]\n";
    stream << "  TOPIC is one of WHY_ADAPTED, WHY_NOT_ADAPTED, EVIDENCE_THRESHOLD,\n";
    stream << "  STALE_EVIDENCE, REJECTED_CANDIDATE, CANDIDATE_COMPARISON, HYSTERESIS,\n";
    stream << "  HOLD_DOWN, STALE_GENERATION, ROLLBACK_REFUSED, AUTHORITY_OWNER,\n";
    stream << "  GOVERNING_EPOCH (default WHY_NOT_ADAPTED).\n";
  } else if (command == "snapshot") {
    stream << "snapshot <policy-id>\n";
    stream << "  Prints the coordinator's rendering of the immutable policy snapshot.\n";
  } else if (command == "diff") {
    stream << "diff <policy-id> <from-snapshot> <to-snapshot>\n";
    stream << "  Prints the deterministic diff between two retained snapshots.\n";
  } else if (command == "revalidate") {
    stream << "revalidate <policy-id>\n";
    stream << "  Sends the REVALIDATE lifecycle event with a fresh attempt identity.\n";
  } else if (command == "revoke") {
    stream << "revoke <policy-id> [--reason REASON] [--detail TEXT]\n";
    stream << "  REASON is one of ADMINISTRATIVE, SECURITY, POLICY_VIOLATION,\n";
    stream << "  AUTHORITY_REVOKED, OPERATOR_REQUEST (default ADMINISTRATIVE).\n";
  } else if (command == "retire") {
    stream << "retire <policy-id> [--detail TEXT]\n";
    stream << "  Sends the RETIRE lifecycle event. A retired policy never reactivates.\n";
  } else if (command == "store") {
    stream << "store inspect <path>\n";
    stream << "  Decodes a store file locally, without a coordinator, and prints path=,\n";
    stream << "  bytes=, status=, detail= and then, when it decoded, format_version=,\n";
    stream << "  epoch= and the record counts.\n";
  } else if (command == "limits") {
    stream << "limits\n  Prints every configured limit as name=value, in declaration order.\n";
  } else if (command == "version") {
    stream << "version\n";
    stream << "  Prints product=, version= and the persistence, wire, policy semantics,\n";
    stream << "  scoring and digest encoding versions.\n";
  } else if (command == "help") {
    stream << "help [command]\n  Prints the command list or one command's documentation.\n";
  } else {
    return false;
  }
  return true;
}

// The one command line summary every usage error repeats.
constexpr std::string_view command_line_summary =
    "usage: arf [--endpoint HOST:PORT] [--fabric ID] [--namespace ID] <command> [args]";

[[nodiscard]] int usage_error(const std::string& message) {
  write_stderr_line(std::string(tool_name) + ": " + message);
  write_stderr_line(command_line_summary);
  write_stderr_line("run 'arf help' for the complete command list");
  return exit_usage;
}

// Rejects an option the command does not accept, so a typo is a usage error
// instead of a silently ignored flag.
[[nodiscard]] std::optional<int> check_options(
    const ArgSet& args, std::initializer_list<std::string_view> allowed) {
  const std::optional<std::string> unknown = args.first_unknown(allowed);
  if (!unknown.has_value()) {
    return std::nullopt;
  }
  return usage_error("unknown option --" + *unknown);
}

[[nodiscard]] bool parse_scope(const ArgSet& args, FabricId& fabric, RoutingNamespace& name_space,
                               std::string& error) {
  const std::string fabric_text = args.value("fabric").value_or(std::string(default_fabric));
  const std::optional<FabricId> parsed_fabric = FabricId::parse(fabric_text);
  if (!parsed_fabric.has_value()) {
    error = "--fabric '" + fabric_text + "' is not a valid FabricId";
    return false;
  }
  const std::string namespace_text =
      args.value("namespace").value_or(std::string(default_routing_namespace));
  const std::optional<RoutingNamespace> parsed_namespace = RoutingNamespace::parse(namespace_text);
  if (!parsed_namespace.has_value()) {
    error = "--namespace '" + namespace_text + "' is not a valid RoutingNamespace";
    return false;
  }
  fabric = *parsed_fabric;
  name_space = *parsed_namespace;
  return true;
}

[[nodiscard]] std::optional<AdaptivePolicyId> parse_policy_argument(const std::string& text,
                                                                   std::string& error) {
  const std::optional<AdaptivePolicyId> policy = AdaptivePolicyId::parse(text);
  if (!policy.has_value()) {
    error = "'" + text + "' is not a valid AdaptivePolicyId";
    return std::nullopt;
  }
  return policy;
}

// ---------------------------------------------------------------------------
// Policy semantics options
// ---------------------------------------------------------------------------

// The complete value a create or an update carries. A partial patch is not
// supported by the runtime on purpose, so the parser builds a whole value and
// the engine's own validator is the single source of truth for its legality.
[[nodiscard]] bool parse_policy_options(const ArgSet& args, PolicyScope& scope,
                                        PolicySemantics& semantics, std::string& error) {
  if (!parse_scope(args, scope.fabric, scope.name_space, error)) {
    return false;
  }
  if (const std::optional<std::string> site_text = args.value("site");
      site_text.has_value() && !site_text->empty()) {
    const std::optional<SiteId> site = SiteId::parse(*site_text);
    if (!site.has_value()) {
      error = "--site '" + *site_text + "' is not a valid SiteId";
      return false;
    }
    scope.site = *site;
  }
  if (const std::optional<std::string> class_text = args.value("path-class");
      class_text.has_value() && !class_text->empty()) {
    const std::optional<PathClass> path_class = PathClass::parse(*class_text);
    if (!path_class.has_value()) {
      error = "--path-class '" + *class_text + "' is not a valid PathClass";
      return false;
    }
    scope.path_class = *path_class;
  }
  // An empty scope route list means every route in the named namespace; the
  // restricting flags exist so an operator can narrow that deliberately.
  for (const std::string& text : args.values("scope-route")) {
    const std::optional<RouteId> scope_route = RouteId::parse(text);
    if (!scope_route.has_value()) {
      error = "--scope-route '" + text + "' is not a valid RouteId";
      return false;
    }
    scope.routes.push_back(*scope_route);
  }
  for (const std::string& text : args.values("scope-multipath-set")) {
    const std::optional<MultipathSetId> scope_set = MultipathSetId::parse(text);
    if (!scope_set.has_value()) {
      error = "--scope-multipath-set '" + text + "' is not a valid MultipathSetId";
      return false;
    }
    scope.multipath_sets.push_back(*scope_set);
  }
  const std::string route_text = args.value("route").value_or(std::string(default_route));
  const std::optional<RouteId> route = RouteId::parse(route_text);
  if (!route.has_value()) {
    error = "--route '" + route_text + "' is not a valid RouteId";
    return false;
  }
  PolicyTarget target;
  target.route = *route;
  semantics.target = target;

  if (args.count("multipath-set") > 1) {
    error = "--multipath-set may be given at most once";
    return false;
  }
  if (const std::optional<std::string> set_text = args.value("multipath-set");
      set_text.has_value() && !set_text->empty()) {
    const std::optional<MultipathSetId> set = MultipathSetId::parse(*set_text);
    if (!set.has_value()) {
      error = "--multipath-set '" + *set_text + "' is not a valid MultipathSetId";
      return false;
    }
    semantics.target.multipath_set = *set;
  }

  for (const std::string& text : args.values("threshold")) {
    const std::vector<std::string> parts = split_on(text, ':');
    if (parts.size() != 3) {
      error = "--threshold expects KIND:SWITCH:CLEAR but received '" + text + "'";
      return false;
    }
    const std::optional<MetricKind> kind = parse_metric_kind(parts[0]);
    if (!kind.has_value()) {
      error = "--threshold names an unknown metric kind '" + parts[0] + "'";
      return false;
    }
    std::int64_t switch_value = 0;
    std::int64_t clear_value = 0;
    if (!parse_integer(parts[1], switch_value) || !parse_integer(parts[2], clear_value)) {
      error = "--threshold expects integer band values but received '" + text + "'";
      return false;
    }
    const std::optional<MetricValue> switch_metric = MetricValue::make(*kind, switch_value);
    const std::optional<MetricValue> clear_metric = MetricValue::make(*kind, clear_value);
    if (!switch_metric.has_value() || !clear_metric.has_value()) {
      error = "--threshold value is outside the declared range of " + parts[0];
      return false;
    }
    ThresholdRule rule;
    rule.kind = *kind;
    rule.switch_value = *switch_metric;
    rule.clear_value = *clear_metric;
    semantics.thresholds.push_back(rule);
  }

  for (const std::string& text : args.values("improvement")) {
    const std::vector<std::string> parts = split_on(text, ':');
    if (parts.size() != 3) {
      error = "--improvement expects KIND:SWITCH_BPS:REVERSE_BPS but received '" + text + "'";
      return false;
    }
    const std::optional<MetricKind> kind = parse_metric_kind(parts[0]);
    if (!kind.has_value()) {
      error = "--improvement names an unknown metric kind '" + parts[0] + "'";
      return false;
    }
    std::uint32_t switch_bps = 0;
    std::uint32_t reverse_bps = 0;
    if (!parse_bounded_u32(parts[1], switch_bps) || switch_bps > basis_points_scale ||
        !parse_bounded_u32(parts[2], reverse_bps) || reverse_bps > basis_points_scale) {
      error =
          "--improvement expects two basis point counts in 0..10000 but received '" + text + "'";
      return false;
    }
    ImprovementRule rule;
    rule.kind = *kind;
    rule.switch_improvement_bps = switch_bps;
    rule.reverse_improvement_bps = reverse_bps;
    semantics.improvements.push_back(rule);
  }

  for (const std::string& text : args.values("evidence")) {
    const std::vector<std::string> parts = split_on(text, ':');
    if (parts.size() < 5 || parts.size() > 8) {
      error =
          "--evidence expects "
          "KIND:AGGREGATION:MIN_SAMPLES:MAX_AGE_MS:MIN_QUALITY[:MIN_WINDOW_MS]"
          "[:EWMA_ALPHA_BPS][:required|optional] but received '" + text + "'";
      return false;
    }
    const std::optional<MetricKind> kind = parse_metric_kind(parts[0]);
    if (!kind.has_value()) {
      error = "--evidence names an unknown metric kind '" + parts[0] + "'";
      return false;
    }
    const std::optional<AggregationKind> aggregation = parse_aggregation_kind(parts[1]);
    if (!aggregation.has_value()) {
      error = "--evidence names an unknown aggregation '" + parts[1] + "'";
      return false;
    }
    std::uint32_t min_samples = 0;
    std::uint64_t max_age_ms = 0;
    if (!parse_bounded_u32(parts[2], min_samples) || min_samples == 0) {
      error = "--evidence requires a positive MIN_SAMPLES";
      return false;
    }
    if (!parse_unsigned(parts[3], max_age_ms) || max_age_ms == 0) {
      error = "--evidence requires a positive MAX_AGE_MS freshness bound";
      return false;
    }
    const std::optional<EvidenceQuality> quality = parse_evidence_quality(parts[4]);
    if (!quality.has_value()) {
      error = "--evidence names an unknown quality class '" + parts[4] + "'";
      return false;
    }
    EvidenceRequirement requirement;
    requirement.kind = *kind;
    requirement.aggregation = *aggregation;
    // An alpha belongs to EWMA alone; the struct default would otherwise make
    // every non-EWMA requirement invalid.
    requirement.ewma_alpha_bps = 0;
    requirement.min_samples = min_samples;
    requirement.max_age = milliseconds(max_age_ms);
    requirement.min_quality = *quality;
    if (parts.size() >= 6 && !parts[5].empty()) {
      std::uint64_t min_window_ms = 0;
      if (!parse_unsigned(parts[5], min_window_ms)) {
        error = "--evidence MIN_WINDOW_MS must be an integer";
        return false;
      }
      requirement.min_window = milliseconds(min_window_ms);
    }
    if (parts.size() >= 7 && !parts[6].empty()) {
      if (!parse_bounded_u32(parts[6], requirement.ewma_alpha_bps)) {
        error = "--evidence EWMA_ALPHA_BPS must be an integer";
        return false;
      }
      if (*aggregation != AggregationKind::EWMA) {
        error = "--evidence EWMA_ALPHA_BPS is only meaningful for the EWMA aggregation";
        return false;
      }
      if (requirement.ewma_alpha_bps == 0 || requirement.ewma_alpha_bps > basis_points_scale) {
        error = "--evidence EWMA_ALPHA_BPS must be in 1..10000";
        return false;
      }
    } else if (*aggregation == AggregationKind::EWMA) {
      error = "--evidence EWMA requires an explicit EWMA_ALPHA_BPS";
      return false;
    }
    if (parts.size() >= 8 && !parts[7].empty()) {
      if (parts[7] == "required") {
        requirement.required = true;
      } else if (parts[7] == "optional") {
        requirement.required = false;
      } else {
        error = "--evidence accepts 'required' or 'optional', not '" + parts[7] + "'";
        return false;
      }
    }
    semantics.evidence.push_back(requirement);
  }

  const std::vector<std::string> objective_texts = args.values("objective");
  if (!objective_texts.empty()) {
    ObjectiveSpec objective;
    bool weighted = false;
    for (const std::string& text : objective_texts) {
      const std::vector<std::string> parts = split_on(text, ':');
      if (parts.size() > 2 || parts[0].empty()) {
        error = "--objective expects KIND[:WEIGHT_BPS] but received '" + text + "'";
        return false;
      }
      const std::optional<MetricKind> kind = parse_metric_kind(parts[0]);
      if (!kind.has_value()) {
        error = "--objective names an unknown metric kind '" + parts[0] + "'";
        return false;
      }
      ObjectiveTerm term;
      term.kind = *kind;
      if (parts.size() == 2) {
        if (!parse_bounded_u32(parts[1], term.weight_bps)) {
          error = "--objective weight must be an integer number of basis points";
          return false;
        }
        weighted = weighted || term.weight_bps != 0;
      }
      objective.terms.push_back(term);
    }
    objective.mode = weighted ? ObjectiveMode::WEIGHTED_SCORE : ObjectiveMode::LEXICOGRAPHIC;
    semantics.objective = objective;
  }

  if (const std::optional<std::string> text = args.value("hold-down-ms"); text.has_value()) {
    std::uint64_t value = 0;
    if (!parse_unsigned(*text, value)) {
      error = "--hold-down-ms must be a non-negative integer";
      return false;
    }
    semantics.hold_down.duration = milliseconds(value);
  }
  if (const std::optional<std::string> text = args.value("cooldown-ms"); text.has_value()) {
    std::uint64_t value = 0;
    if (!parse_unsigned(*text, value)) {
      error = "--cooldown-ms must be a non-negative integer";
      return false;
    }
    semantics.cooldown.duration = milliseconds(value);
  }

  if (const std::optional<std::string> text = args.value("churn"); text.has_value()) {
    const std::vector<std::string> parts = split_on(*text, ':');
    std::uint32_t maximum = 0;
    std::uint64_t window_ms = 0;
    if (parts.size() != 2 || !parse_bounded_u32(parts[0], maximum) ||
        !parse_unsigned(parts[1], window_ms)) {
      error = "--churn expects MAX_ADAPTATIONS:WINDOW_MS but received '" + *text + "'";
      return false;
    }
    semantics.churn.max_adaptations_per_window = maximum;
    semantics.churn.window = milliseconds(window_ms);
  }

  if (const std::optional<std::string> text = args.value("dampening"); text.has_value()) {
    const std::vector<std::string> parts = split_on(*text, ':');
    std::uint32_t increment = 0;
    std::uint32_t max_penalty = 0;
    std::uint32_t decay_step = 0;
    std::uint64_t decay_ms = 0;
    std::uint64_t escalation_ms = 0;
    std::uint64_t max_hold_ms = 0;
    if (parts.size() != 6 || !parse_bounded_u32(parts[0], increment) ||
        !parse_bounded_u32(parts[1], max_penalty) || !parse_unsigned(parts[2], decay_ms) ||
        !parse_bounded_u32(parts[3], decay_step) || !parse_unsigned(parts[4], escalation_ms) ||
        !parse_unsigned(parts[5], max_hold_ms)) {
      error =
          "--dampening expects "
          "INCREMENT:MAX_PENALTY:DECAY_MS:DECAY_STEP:ESCALATION_MS:MAX_HOLD_MS but received '" +
          *text + "'";
      return false;
    }
    semantics.dampening.enabled = true;
    semantics.dampening.penalty_increment = increment;
    semantics.dampening.max_penalty = max_penalty;
    semantics.dampening.penalty_decay_interval = milliseconds(decay_ms);
    semantics.dampening.penalty_decay_step = decay_step;
    semantics.dampening.hold_down_escalation_step = milliseconds(escalation_ms);
    semantics.dampening.max_effective_hold_down = milliseconds(max_hold_ms);
  }

  for (const std::string& text : args.values("emergency")) {
    if (text == "unauthorized") {
      semantics.emergency.on_current_path_unauthorized = true;
    } else if (text == "unavailable") {
      semantics.emergency.on_current_path_unavailable = true;
    } else if (text == "hard-failure") {
      semantics.emergency.on_hard_failure_signal = true;
    } else {
      error = "--emergency accepts unauthorized, unavailable or hard-failure, not '" + text + "'";
      return false;
    }
    semantics.emergency.enabled = true;
  }

  for (const std::string& text : args.values("priority")) {
    const std::vector<std::string> parts = split_on(text, ':');
    if (parts.size() != 2) {
      error = "--priority expects PATH:PRIORITY but received '" + text + "'";
      return false;
    }
    const std::optional<PathId> path = PathId::parse(parts[0]);
    if (!path.has_value()) {
      error = "--priority names an invalid PathId '" + parts[0] + "'";
      return false;
    }
    CandidatePriority priority;
    priority.path = *path;
    if (!parse_bounded_u32(parts[1], priority.priority)) {
      error = "--priority value must be an integer";
      return false;
    }
    semantics.priorities.push_back(priority);
  }

  // The engine owns this validation, and running it here means a malformed
  // policy is a usage error rather than a round trip that cannot succeed.
  std::string reason;
  if (!semantics.valid(&reason)) {
    error = "policy semantics are invalid: " + reason;
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Session plumbing
// ---------------------------------------------------------------------------

// Runs \p body against a registered session. Every coordinator command goes
// through here so connection and registration failures are reported once.
template <class Body>
[[nodiscard]] int with_session(const Endpoint& endpoint, const FabricId& fabric,
                               const RoutingNamespace& name_space, Body&& body) {
  SessionRequest request;
  request.endpoint = endpoint;
  request.scope = make_authority_scope(fabric, name_space);
  request.id_prefix = std::string(cli_id_prefix);
  request.publisher = PublisherId::require(cli_publisher);
  request.worker_boot = WorkerBootId::require(cli_worker_boot);
  ClientSession session = open_session(request);
  if (!session.outcome.connected || !session.outcome.greeting) {
    write_stderr_line(std::string(tool_name) + ": " + endpoint.render() +
                      " is unreachable: " + session.outcome.error);
    return exit_refused;
  }
  if (!session.outcome.registered) {
    write_stderr_line(std::string(tool_name) +
                      ": the coordinator refused the operator registration: " +
                      std::string(to_string(session.outcome.registration_outcome)) + " " +
                      session.outcome.registration_detail);
    return exit_refused;
  }
  const int status = body(session);
  close_session(session);
  return status;
}

// Prints the coordinator's OperationResult rendering. A command the coordinator
// refused is exit 1; a deterministic no-adaptation answer is exit 0.
[[nodiscard]] int report_result(const std::optional<ResultMessage>& result,
                                const std::string& error) {
  if (!result.has_value()) {
    write_stderr_line(std::string(tool_name) + ": " + error);
    return exit_refused;
  }
  write_stdout_line(render_result(*result));
  return outcome_is_refusal(result->outcome) ? exit_refused : exit_ok;
}

// State-like output: one key=value line per fact, with the coordinator's
// canonical policy line labelled and kept in its own ordering.
[[nodiscard]] int report_state(const std::optional<ResultMessage>& result,
                               const std::string& error) {
  if (!result.has_value()) {
    write_stderr_line(std::string(tool_name) + ": " + error);
    return exit_refused;
  }
  if (outcome_is_refusal(result->outcome)) {
    write_stdout_line(render_result(*result));
    return exit_refused;
  }
  const std::vector<std::string> lines = split_lines(result->rendered);
  std::vector<std::string> rendered;
  for (const std::string& line : lines) {
    if (!line.empty()) {
      rendered.push_back(label_policy_line(line));
    }
  }
  write_stdout_line("epoch=" + std::to_string(result->epoch.value()));
  write_stdout_line("count=" + std::to_string(rendered.size()));
  for (const std::string& line : rendered) {
    write_stdout_line(line);
  }
  return exit_ok;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

[[nodiscard]] int command_policy_create(const ArgSet& args, const Endpoint& endpoint) {
  const std::optional<std::string> name_text = args.value("name");
  if (!name_text.has_value() || name_text->empty()) {
    return usage_error("policy create requires --name NAME");
  }
  const std::optional<AdaptivePolicyName> name = AdaptivePolicyName::parse(*name_text);
  if (!name.has_value()) {
    return usage_error("--name '" + *name_text + "' is not a valid AdaptivePolicyName");
  }
  PolicyScope scope;
  PolicySemantics semantics;
  std::string error;
  if (!parse_policy_options(args, scope, semantics, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, scope.fabric, scope.name_space, [&](ClientSession& session) {
    CreatePolicyMessage message;
    message.name = *name;
    message.scope = scope;
    message.semantics = semantics;
    const std::optional<ResultMessage> created = session.client->create_policy(message, error);
    const int status = report_result(created, error);
    if (status != exit_ok || !args.has("activate") || !created.has_value()) {
      return status;
    }
    // --activate exists so a script can create and activate in one process; the
    // activation answer is a second documented result line.
    PolicyLifecycleMessage activation;
    activation.policy = created->policy;
    activation.event = PolicyEvent::ACTIVATE;
    activation.detail = "operator activation";
    const std::optional<ResultMessage> activated =
        session.client->policy_lifecycle(activation, error);
    return report_result(activated, error);
  });
}

[[nodiscard]] int command_policy_update(const ArgSet& args, const std::vector<std::string>& words,
                                        const Endpoint& endpoint) {
  if (words.size() != 3) {
    return usage_error("policy update expects exactly one policy id");
  }
  std::string error;
  const std::optional<AdaptivePolicyId> policy = parse_policy_argument(words[2], error);
  if (!policy.has_value()) {
    return usage_error(error);
  }
  PolicyScope scope;
  PolicySemantics semantics;
  if (!parse_policy_options(args, scope, semantics, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, scope.fabric, scope.name_space, [&](ClientSession& session) {
    UpdatePolicyMessage message;
    message.policy = *policy;
    message.scope = scope;
    message.semantics = semantics;
    return report_result(session.client->update_policy(message, error), error);
  });
}

[[nodiscard]] int command_policy_lifecycle(const ArgSet& args,
                                           const std::vector<std::string>& words,
                                           const Endpoint& endpoint, PolicyEvent event,
                                           std::string_view verb) {
  if (words.size() != 3) {
    return usage_error("policy " + std::string(verb) + " expects exactly one policy id");
  }
  std::string error;
  const std::optional<AdaptivePolicyId> policy = parse_policy_argument(words[2], error);
  if (!policy.has_value()) {
    return usage_error(error);
  }
  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  const std::string detail =
      args.value("detail").value_or("operator " + std::string(to_string(event)));
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    PolicyLifecycleMessage message;
    message.policy = *policy;
    message.event = event;
    message.detail = detail;
    return report_result(session.client->policy_lifecycle(message, error), error);
  });
}

[[nodiscard]] int command_policy_query(const ArgSet& args, const std::vector<std::string>& words,
                                       const Endpoint& endpoint, bool single) {
  std::string error;
  QueryStateMessage message;
  message.limit = 0;
  if (single) {
    if (words.size() != 3) {
      return usage_error("policy show expects exactly one policy id");
    }
    const std::optional<AdaptivePolicyId> policy = parse_policy_argument(words[2], error);
    if (!policy.has_value()) {
      return usage_error(error);
    }
    message.policy = *policy;
  } else if (words.size() != 2) {
    return usage_error("policy list accepts no positional argument");
  }
  if (const std::optional<std::string> limit_text = args.value("limit"); limit_text.has_value()) {
    std::uint64_t limit = 0;
    if (!parse_unsigned(*limit_text, limit)) {
      return usage_error("--limit must be a non-negative integer");
    }
    message.limit = limit;
  }
  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    return report_state(session.client->query_state(message, error), error);
  });
}

[[nodiscard]] int command_evidence_publish(const ArgSet& args,
                                           const std::vector<std::string>& words,
                                           const Endpoint& endpoint) {
  if (words.size() != 2) {
    return usage_error("evidence publish accepts no positional argument");
  }
  std::string error;
  const std::optional<std::string> path_text = args.value("path");
  if (!path_text.has_value() || path_text->empty()) {
    return usage_error("evidence publish requires --path PATH");
  }
  const std::optional<PathId> path = PathId::parse(*path_text);
  if (!path.has_value()) {
    return usage_error("--path '" + *path_text + "' is not a valid PathId");
  }
  const std::optional<std::string> kind_text = args.value("metric");
  if (!kind_text.has_value() || kind_text->empty()) {
    return usage_error("evidence publish requires --metric KIND");
  }
  const std::optional<MetricKind> kind = parse_metric_kind(*kind_text);
  if (!kind.has_value()) {
    return usage_error("--metric '" + *kind_text + "' is not a metric kind");
  }
  const std::optional<std::string> value_text = args.value("value");
  if (!value_text.has_value() || value_text->empty()) {
    return usage_error("evidence publish requires --value V");
  }
  std::int64_t value = 0;
  if (!parse_integer(*value_text, value)) {
    return usage_error("--value must be an integer metric value");
  }
  const std::optional<MetricValue> metric = MetricValue::make(*kind, value);
  if (!metric.has_value()) {
    return usage_error("--value " + *value_text + " is outside the declared range of " +
                       *kind_text);
  }
  EvidenceQuality quality = EvidenceQuality::PRIMARY;
  if (const std::optional<std::string> quality_text = args.value("quality");
      quality_text.has_value() && !quality_text->empty()) {
    const std::optional<EvidenceQuality> parsed = parse_evidence_quality(*quality_text);
    if (!parsed.has_value()) {
      return usage_error("--quality '" + *quality_text + "' is not an evidence quality class");
    }
    quality = *parsed;
  }
  const std::string source_text = args.value("source").value_or(std::string(cli_evidence_source));
  const std::optional<EvidenceSourceId> source = EvidenceSourceId::parse(source_text);
  if (!source.has_value()) {
    return usage_error("--source '" + source_text + "' is not a valid EvidenceSourceId");
  }
  std::uint64_t source_generation = 1;
  if (const std::optional<std::string> generation_text = args.value("source-generation");
      generation_text.has_value()) {
    if (!parse_unsigned(*generation_text, source_generation) || source_generation == 0) {
      return usage_error("--source-generation must be a positive integer");
    }
  }
  std::uint64_t sequence = 1;
  if (const std::optional<std::string> sequence_text = args.value("sequence");
      sequence_text.has_value()) {
    if (!parse_unsigned(*sequence_text, sequence) || sequence == 0) {
      return usage_error("--sequence must be a positive integer");
    }
  }

  EvidencePublication publication;
  publication.source = *source;
  publication.source_generation = EvidenceSourceGeneration::require(source_generation);
  publication.quality = quality;
  publication.path = *path;
  publication.value = *metric;
  publication.observation_sequence = sequence;

  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    PublishEvidenceMessage message;
    message.publications.push_back(publication);
    return report_result(session.client->publish_evidence(message, error), error);
  });
}

[[nodiscard]] int command_evaluate(const ArgSet& args, const std::vector<std::string>& words,
                                   const Endpoint& endpoint) {
  if (words.size() != 2) {
    return usage_error("evaluate expects exactly one policy id");
  }
  std::string error;
  const std::optional<AdaptivePolicyId> policy = parse_policy_argument(words[1], error);
  if (!policy.has_value()) {
    return usage_error(error);
  }
  const bool defer = args.has("defer");
  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    EvaluateMessage message;
    message.policy = *policy;
    message.defer_commit = defer;
    return report_result(session.client->evaluate(message, error), error);
  });
}

[[nodiscard]] int command_explain(const ArgSet& args, const std::vector<std::string>& words,
                                  const Endpoint& endpoint) {
  if (words.size() != 2) {
    return usage_error("explain expects exactly one policy id");
  }
  std::string error;
  const std::optional<AdaptivePolicyId> policy = parse_policy_argument(words[1], error);
  if (!policy.has_value()) {
    return usage_error(error);
  }
  ExplanationTopic topic = ExplanationTopic::WHY_NOT_ADAPTED;
  if (const std::optional<std::string> topic_text = args.value("topic");
      topic_text.has_value() && !topic_text->empty()) {
    const std::optional<ExplanationTopic> parsed = parse_explanation_topic(*topic_text);
    if (!parsed.has_value()) {
      return usage_error("--topic '" + *topic_text + "' is not an explanation topic");
    }
    topic = *parsed;
  }
  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    ExplainRequestMessage message;
    message.topic = topic;
    message.policy = *policy;
    // The explanation rendering is itself key/value shaped and is the
    // documented output of this command.
    return report_result(session.client->explain(message, error), error);
  });
}

[[nodiscard]] int command_snapshot(const ArgSet& args, const std::vector<std::string>& words,
                                   const Endpoint& endpoint) {
  if (words.size() != 2) {
    return usage_error("snapshot expects exactly one policy id");
  }
  std::string error;
  const std::optional<AdaptivePolicyId> policy = parse_policy_argument(words[1], error);
  if (!policy.has_value()) {
    return usage_error(error);
  }
  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    SnapshotRequestMessage request;
    request.policy = *policy;
    // A snapshot response carries no OperationResult, so the raw frame surface
    // is used and both documented response shapes are decoded here.
    const std::optional<Frame> response =
        session.client->request(MessageId::SNAPSHOT_REQUEST, request.encode(), error);
    if (!response.has_value()) {
      write_stderr_line(std::string(tool_name) + ": " + error);
      return exit_refused;
    }
    if (response->header.message_id == MessageId::SNAPSHOT_RESPONSE) {
      const std::optional<SnapshotResponseMessage> decoded =
          SnapshotResponseMessage::decode(response->payload);
      if (!decoded.has_value()) {
        write_stderr_line(std::string(tool_name) + ": the SNAPSHOT_RESPONSE could not be decoded");
        return exit_refused;
      }
      write_stdout_line(decoded->rendered);
      return exit_ok;
    }
    if (response->header.message_id == MessageId::ERROR) {
      const std::optional<ErrorMessage> failure = ErrorMessage::decode(response->payload);
      if (!failure.has_value()) {
        write_stderr_line(std::string(tool_name) + ": the ERROR payload could not be decoded");
        return exit_refused;
      }
      ResultMessage reported;
      reported.outcome = failure->outcome;
      reported.detail = failure->detail;
      reported.policy = *policy;
      return report_result(reported, error);
    }
    write_stderr_line(std::string(tool_name) + ": unexpected response " +
                      std::string(to_string(response->header.message_id)) +
                      " to SNAPSHOT_REQUEST");
    return exit_refused;
  });
}

[[nodiscard]] int command_diff(const ArgSet& args, const std::vector<std::string>& words,
                               const Endpoint& endpoint) {
  if (words.size() != 4) {
    return usage_error("diff expects <policy-id> <from-snapshot> <to-snapshot>");
  }
  std::string error;
  const std::optional<AdaptivePolicyId> policy = parse_policy_argument(words[1], error);
  if (!policy.has_value()) {
    return usage_error(error);
  }
  const std::optional<SnapshotId> from = SnapshotId::parse(words[2]);
  if (!from.has_value()) {
    return usage_error("'" + words[2] + "' is not a valid SnapshotId");
  }
  const std::optional<SnapshotId> to = SnapshotId::parse(words[3]);
  if (!to.has_value()) {
    return usage_error("'" + words[3] + "' is not a valid SnapshotId");
  }
  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    DiffRequestMessage message;
    message.policy = *policy;
    message.from = *from;
    message.to = *to;
    return report_result(session.client->diff(message, error), error);
  });
}

[[nodiscard]] int command_revalidate(const ArgSet& args, const std::vector<std::string>& words,
                                     const Endpoint& endpoint) {
  if (words.size() != 2) {
    return usage_error("revalidate expects exactly one policy id");
  }
  std::string error;
  const std::optional<AdaptivePolicyId> policy = parse_policy_argument(words[1], error);
  if (!policy.has_value()) {
    return usage_error(error);
  }
  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    RevalidateMessage message;
    message.policy = *policy;
    // The attempt identity is derived from the session, which carries the
    // process nonce, so a replayed revalidation is recognisable and two
    // invocations never collide.
    message.attempt = make_revalidation_attempt(session.client->session(), 1);
    return report_result(session.client->revalidate(message, error), error);
  });
}

[[nodiscard]] int command_revoke(const ArgSet& args, const std::vector<std::string>& words,
                                 const Endpoint& endpoint) {
  if (words.size() != 2) {
    return usage_error("revoke expects exactly one policy id");
  }
  std::string error;
  const std::optional<AdaptivePolicyId> policy = parse_policy_argument(words[1], error);
  if (!policy.has_value()) {
    return usage_error(error);
  }
  RevocationReason reason = RevocationReason::ADMINISTRATIVE;
  if (const std::optional<std::string> reason_text = args.value("reason");
      reason_text.has_value() && !reason_text->empty()) {
    const std::optional<RevocationReason> parsed = parse_revocation_reason(*reason_text);
    if (!parsed.has_value()) {
      return usage_error("--reason '" + *reason_text + "' is not a revocation reason");
    }
    reason = *parsed;
  }
  const std::string detail = args.value("detail").value_or("operator revoke");
  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    RevokePolicyMessage message;
    message.policy = *policy;
    message.reason = reason;
    message.detail = detail;
    return report_result(session.client->revoke_policy(message, error), error);
  });
}

[[nodiscard]] int command_state_show(const ArgSet& args, const std::vector<std::string>& words,
                                     const Endpoint& endpoint) {
  if (words.size() != 2) {
    return usage_error("state show accepts no positional argument");
  }
  std::string error;
  QueryStateMessage message;
  message.limit = 0;
  if (const std::optional<std::string> policy_text = args.value("policy");
      policy_text.has_value() && !policy_text->empty()) {
    const std::optional<AdaptivePolicyId> policy = parse_policy_argument(*policy_text, error);
    if (!policy.has_value()) {
      return usage_error(error);
    }
    message.policy = *policy;
  }
  if (const std::optional<std::string> limit_text = args.value("limit"); limit_text.has_value()) {
    std::uint64_t limit = 0;
    if (!parse_unsigned(*limit_text, limit)) {
      return usage_error("--limit must be a non-negative integer");
    }
    message.limit = limit;
  }
  FabricId fabric;
  RoutingNamespace name_space;
  if (!parse_scope(args, fabric, name_space, error)) {
    return usage_error(error);
  }
  return with_session(endpoint, fabric, name_space, [&](ClientSession& session) {
    return report_state(session.client->query_state(message, error), error);
  });
}

[[nodiscard]] int command_store_inspect(const ArgSet& args, const std::vector<std::string>& words) {
  // The coordinator options are accepted and ignored: a harness may pass one
  // uniform command line to every command.
  if (const auto failure =
          check_options(args, {"help", "endpoint", "fabric", "namespace"})) {
    return *failure;
  }
  if (words.size() != 3) {
    return usage_error("store inspect expects exactly one path");
  }
  const std::string& path = words[2];
  std::string error;
  const std::optional<std::string> bytes = read_store_bytes(path, error);
  if (!bytes.has_value()) {
    write_stderr_line(std::string(tool_name) + ": " + error);
    return exit_refused;
  }
  const StoreDecodeResult decoded = decode_durable_state(*bytes);
  write_stdout_line("path=" + path);
  write_stdout_line("bytes=" + std::to_string(bytes->size()));
  write_stdout_line("status=" + std::string(to_string(decoded.status)));
  write_stdout_line("detail=" + decoded.detail);
  if (!decoded.ok()) {
    return exit_refused;
  }
  const DurableState& state = decoded.state;
  write_stdout_line("format_version=" + std::to_string(state.format_version));
  write_stdout_line("epoch=" + std::to_string(state.epoch.value()));
  write_stdout_line("policies=" + std::to_string(state.policies.size()));
  write_stdout_line("revocations=" + std::to_string(state.revocations.size()));
  write_stdout_line("preferences=" + std::to_string(state.preferences.size()));
  write_stdout_line("stable_states=" + std::to_string(state.stable_states.size()));
  write_stdout_line("timings=" + std::to_string(state.timings.size()));
  write_stdout_line("history=" + std::to_string(state.history.size()));
  return exit_ok;
}

[[nodiscard]] int command_limits(const ArgSet& args) {
  if (const auto failure = check_options(args, {"help", "endpoint", "fabric", "namespace"})) {
    return *failure;
  }
  for (const std::string& line : limit_lines()) {
    write_stdout_line(line);
  }
  return exit_ok;
}

[[nodiscard]] int command_version(const ArgSet& args) {
  if (const auto failure = check_options(args, {"help", "endpoint", "fabric", "namespace"})) {
    return *failure;
  }
  for (const std::string& line : version_lines()) {
    write_stdout_line(line);
  }
  return exit_ok;
}

[[nodiscard]] int run(const ArgSet& args) {
  if (args.has("help") && args.positional.empty()) {
    print_usage(std::cout);
    return exit_ok;
  }
  const std::vector<std::string>& words = args.positional;
  if (words.empty()) {
    write_stderr_line(std::string(tool_name) + ": a command is required");
    print_usage(std::cerr);
    return exit_usage;
  }
  const std::string& group = words[0];

  // The locally answered commands never open a session: a store can be
  // inspected, and a limit or a version read, with no coordinator running.
  if (group == "limits") {
    if (words.size() != 1) {
      return usage_error("limits accepts no positional argument");
    }
    return command_limits(args);
  }
  if (group == "version") {
    if (words.size() != 1) {
      return usage_error("version accepts no positional argument");
    }
    return command_version(args);
  }
  if (group == "help") {
    if (words.size() == 1) {
      print_usage(std::cout);
      return exit_ok;
    }
    if (words.size() != 2 || !print_command_help(std::cout, words[1])) {
      const std::string& topic = words.size() > 1 ? words[1] : group;
      return usage_error("no help is available for '" + topic + "'");
    }
    return exit_ok;
  }
  if (group == "store") {
    if (words.size() < 2 || words[1] != "inspect") {
      return usage_error("store expects the subcommand 'inspect'");
    }
    return command_store_inspect(args, words);
  }

  static constexpr std::initializer_list<std::string_view> session_options = {
      "endpoint", "fabric", "namespace", "help"};
  Endpoint endpoint;
  std::string error;
  const std::string& command = words.size() > 1 ? words[1] : std::string();
  if (group == "policy") {
    if (words.size() < 2) {
      return usage_error("policy requires a subcommand");
    }
    if (command == "create") {
      if (const auto failure = check_options(
              args, {"endpoint", "fabric", "namespace", "help", "name", "route", "multipath-set",
                     "site", "path-class", "scope-route", "scope-multipath-set", "threshold",
                     "improvement", "evidence", "objective", "hold-down-ms", "cooldown-ms", "churn",
                     "dampening", "emergency", "priority", "activate"})) {
        return *failure;
      }
      if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
        return usage_error(error);
      }
      return command_policy_create(args, endpoint);
    }
    if (command == "update") {
      if (const auto failure = check_options(
              args, {"endpoint", "fabric", "namespace", "help", "route", "multipath-set", "site",
                     "path-class", "scope-route", "scope-multipath-set", "threshold",
                     "improvement", "evidence", "objective", "hold-down-ms", "cooldown-ms", "churn",
                     "dampening", "emergency", "priority"})) {
        return *failure;
      }
      if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
        return usage_error(error);
      }
      return command_policy_update(args, words, endpoint);
    }
    if (command == "show" || command == "list") {
      if (const auto failure = check_options(args, {"endpoint", "fabric", "namespace", "help", "limit"})) {
        return *failure;
      }
      if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
        return usage_error(error);
      }
      return command_policy_query(args, words, endpoint, command == "show");
    }
    if (command == "activate" || command == "suspend" || command == "resume") {
      if (const auto failure = check_options(args, {"endpoint", "fabric", "namespace", "help", "detail"})) {
        return *failure;
      }
      if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
        return usage_error(error);
      }
      const PolicyEvent event = command == "activate"   ? PolicyEvent::ACTIVATE
                                : command == "suspend" ? PolicyEvent::SUSPEND
                                                       : PolicyEvent::RESUME;
      return command_policy_lifecycle(args, words, endpoint, event, command);
    }
    return usage_error("unknown policy subcommand '" + command + "'");
  }

  if (group == "evidence") {
    if (words.size() < 2 || command != "publish") {
      return usage_error("evidence expects the subcommand 'publish'");
    }
    if (const auto failure =
            check_options(args, {"endpoint", "fabric", "namespace", "help", "path", "metric",
                                 "value", "quality", "source", "source-generation", "sequence"})) {
      return *failure;
    }
    if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
      return usage_error(error);
    }
    return command_evidence_publish(args, words, endpoint);
  }

  if (group == "state") {
    if (words.size() < 2 || command != "show") {
      return usage_error("state expects the subcommand 'show'");
    }
    if (const auto failure =
            check_options(args, {"endpoint", "fabric", "namespace", "help", "policy", "limit"})) {
      return *failure;
    }
    if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
      return usage_error(error);
    }
    return command_state_show(args, words, endpoint);
  }

  struct CommandBinding {
    std::string_view name;
    std::initializer_list<std::string_view> options;
  };
  if (group == "evaluate") {
    if (const auto failure = check_options(args, {"endpoint", "fabric", "namespace", "help", "defer"})) {
      return *failure;
    }
    if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
      return usage_error(error);
    }
    return command_evaluate(args, words, endpoint);
  }
  if (group == "explain") {
    if (const auto failure = check_options(args, {"endpoint", "fabric", "namespace", "help", "topic"})) {
      return *failure;
    }
    if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
      return usage_error(error);
    }
    return command_explain(args, words, endpoint);
  }
  if (group == "snapshot") {
    if (const auto failure = check_options(args, session_options)) {
      return *failure;
    }
    if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
      return usage_error(error);
    }
    return command_snapshot(args, words, endpoint);
  }
  if (group == "diff") {
    if (const auto failure = check_options(args, session_options)) {
      return *failure;
    }
    if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
      return usage_error(error);
    }
    return command_diff(args, words, endpoint);
  }
  if (group == "revalidate") {
    if (const auto failure = check_options(args, session_options)) {
      return *failure;
    }
    if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
      return usage_error(error);
    }
    return command_revalidate(args, words, endpoint);
  }
  if (group == "revoke") {
    if (const auto failure = check_options(args, {"endpoint", "fabric", "namespace", "help", "reason", "detail"})) {
      return *failure;
    }
    if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
      return usage_error(error);
    }
    return command_revoke(args, words, endpoint);
  }
  if (group == "retire") {
    if (const auto failure = check_options(args, {"endpoint", "fabric", "namespace", "help", "detail"})) {
      return *failure;
    }
    if (!resolve_endpoint(args, default_endpoint_text, endpoint, error)) {
      return usage_error(error);
    }
    return command_policy_lifecycle(args, words, endpoint, PolicyEvent::RETIRE, "retire");
  }
  return usage_error("unknown command '" + group + "'");
}

}  // namespace

int main(int argc, char** argv) {
  configure_standard_streams();
  const ArgSet args = parse_args(argc, argv);
  return run(args);
}

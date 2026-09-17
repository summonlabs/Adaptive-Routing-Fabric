// Shared surface of the Adaptive Routing Fabric command line tools.
//
// arf, arf_coordinator and arf_publisher are one product surface: they must
// agree on how an endpoint is parsed, how a result is rendered and which
// outcome counts as a refusal. Everything they share lives here, header-only
// and self-contained, so a rendering rule cannot drift between them and no
// tool needs to know how another tool is built.
#ifndef ARF_TOOL_COMMON_HPP
#define ARF_TOOL_COMMON_HPP

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <fcntl.h>
#include <io.h>
#endif

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "adaptive_routing/adaptive_routing.hpp"

namespace arf_tool {

using namespace adaptive_routing;

// ---------------------------------------------------------------------------
// Process exit codes
// ---------------------------------------------------------------------------
//
// Every tool answers with one of these codes so that a harness can branch on
// the code instead of parsing text. They are part of the documented surface.
inline constexpr int exit_ok = 0;
inline constexpr int exit_refused = 1;
inline constexpr int exit_usage = 2;
// arf_publisher reserves three further codes for distributed failures a test
// has to distinguish without reading prose.
inline constexpr int publisher_exit_register = 3;
inline constexpr int publisher_exit_script = 4;
inline constexpr int publisher_exit_connect = 5;

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

[[nodiscard]] constexpr bool is_space(char value) noexcept {
  return value == ' ' || value == '\t' || value == '\r';
}

[[nodiscard]] inline bool starts_with(std::string_view text, std::string_view prefix) noexcept {
  return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

[[nodiscard]] inline std::string_view trim(std::string_view text) noexcept {
  std::size_t begin = 0;
  while (begin < text.size() && is_space(text[begin])) {
    ++begin;
  }
  std::size_t end = text.size();
  while (end > begin && is_space(text[end - 1])) {
    --end;
  }
  return text.substr(begin, end - begin);
}

// Whitespace separated fields of one line. Blank lines yield no fields, which
// is how a script skips them without a special case.
[[nodiscard]] inline std::vector<std::string> split_fields(std::string_view text) {
  std::vector<std::string> fields;
  std::size_t index = 0;
  while (index < text.size()) {
    while (index < text.size() && is_space(text[index])) {
      ++index;
    }
    const std::size_t start = index;
    while (index < text.size() && !is_space(text[index])) {
      ++index;
    }
    if (index > start) {
      fields.emplace_back(text.substr(start, index - start));
    }
  }
  return fields;
}

// The remainder of \p text after its first \p count whitespace separated
// fields, trimmed. Used by the free-text tails of the publisher script grammar
// so that a reason may contain spaces.
[[nodiscard]] inline std::string rest_after_fields(std::string_view text, std::size_t count) {
  std::size_t index = 0;
  std::size_t consumed = 0;
  while (consumed < count) {
    while (index < text.size() && is_space(text[index])) {
      ++index;
    }
    if (index >= text.size()) {
      return std::string();
    }
    while (index < text.size() && !is_space(text[index])) {
      ++index;
    }
    ++consumed;
  }
  return std::string(trim(text.substr(index)));
}

// Splits on a literal separator, keeping empty fields so that a malformed
// compound argument is reported rather than silently re-interpreted.
[[nodiscard]] inline std::vector<std::string> split_on(std::string_view text, char separator) {
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (true) {
    const std::size_t position = text.find(separator, start);
    if (position == std::string_view::npos) {
      parts.emplace_back(text.substr(start));
      return parts;
    }
    parts.emplace_back(text.substr(start, position - start));
    start = position + 1;
  }
}

[[nodiscard]] inline std::vector<std::string> split_lines(std::string_view text) {
  std::vector<std::string> lines;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t position = text.find('\n', start);
    if (position == std::string_view::npos) {
      if (start < text.size()) {
        lines.emplace_back(text.substr(start));
      }
      return lines;
    }
    lines.emplace_back(text.substr(start, position - start));
    start = position + 1;
  }
  return lines;
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------
//
// Digits only, checked overflow: a value that does not fit is a usage error,
// never a silent truncation. No parsing path accepts a floating point literal,
// because no metric in this product is a floating point value.
[[nodiscard]] inline bool parse_unsigned(std::string_view text, std::uint64_t& out) noexcept {
  if (text.empty() || text.size() > 20) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return false;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10) {
      return false;
    }
    value = value * 10 + digit;
  }
  out = value;
  return true;
}

[[nodiscard]] inline bool parse_integer(std::string_view text, std::int64_t& out) noexcept {
  bool negative = false;
  if (!text.empty() && (text.front() == '-' || text.front() == '+')) {
    negative = text.front() == '-';
    text.remove_prefix(1);
  }
  std::uint64_t magnitude = 0;
  if (!parse_unsigned(text, magnitude)) {
    return false;
  }
  const std::uint64_t limit =
      negative ? (1ULL << 63) : ((1ULL << 63) - 1ULL);
  if (magnitude > limit) {
    return false;
  }
  if (negative) {
    if (magnitude == (1ULL << 63)) {
      out = (std::numeric_limits<std::int64_t>::min)();
      return true;
    }
    out = -static_cast<std::int64_t>(magnitude);
    return true;
  }
  out = static_cast<std::int64_t>(magnitude);
  return true;
}

[[nodiscard]] inline bool parse_bounded_u32(std::string_view text, std::uint32_t& out) noexcept {
  std::uint64_t value = 0;
  if (!parse_unsigned(text, value) || value > (std::numeric_limits<std::uint32_t>::max)()) {
    return false;
  }
  out = static_cast<std::uint32_t>(value);
  return true;
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

// Options in command line order, so a usage error can name the first token the
// caller got wrong instead of a generic complaint. A repeated option keeps
// every occurrence, which is how the repeatable policy options are collected.
struct ArgSet {
  std::vector<std::pair<std::string, std::string>> options;
  std::vector<std::string> positional;

  [[nodiscard]] bool has(std::string_view name) const noexcept {
    for (const auto& entry : options) {
      if (entry.first == name) {
        return true;
      }
    }
    return false;
  }

  [[nodiscard]] std::size_t count(std::string_view name) const noexcept {
    std::size_t total = 0;
    for (const auto& entry : options) {
      if (entry.first == name) {
        ++total;
      }
    }
    return total;
  }

  [[nodiscard]] std::optional<std::string> value(std::string_view name) const {
    for (const auto& entry : options) {
      if (entry.first == name) {
        return entry.second;
      }
    }
    return std::nullopt;
  }

  [[nodiscard]] std::vector<std::string> values(std::string_view name) const {
    std::vector<std::string> collected;
    for (const auto& entry : options) {
      if (entry.first == name) {
        collected.push_back(entry.second);
      }
    }
    return collected;
  }

  [[nodiscard]] std::optional<std::string> first_unknown(
      std::initializer_list<std::string_view> allowed) const {
    for (const auto& entry : options) {
      bool known = false;
      for (const std::string_view name : allowed) {
        if (entry.first == name) {
          known = true;
          break;
        }
      }
      if (!known) {
        return entry.first;
      }
    }
    return std::nullopt;
  }
};

[[nodiscard]] inline ArgSet parse_args(int argc, char** argv) {
  ArgSet parsed;
  for (int index = 1; index < argc; ++index) {
    const char* raw = argv[index];
    const std::string token = raw == nullptr ? std::string() : std::string(raw);
    if (token == "-h") {
      parsed.options.emplace_back("help", std::string());
      continue;
    }
    if (!starts_with(token, "--")) {
      parsed.positional.push_back(token);
      continue;
    }
    const std::size_t separator = token.find('=');
    if (separator != std::string::npos) {
      parsed.options.emplace_back(token.substr(2, separator - 2), token.substr(separator + 1));
      continue;
    }
    const std::string name = token.substr(2);
    // A following "--" token is the next option, not this option's value: a
    // valueless flag must never swallow the token that follows it.
    const char* next = index + 1 < argc ? argv[index + 1] : nullptr;
    if (next != nullptr && !starts_with(std::string_view(next), "--")) {
      parsed.options.emplace_back(name, std::string(next));
      ++index;
    } else {
      parsed.options.emplace_back(name, std::string());
    }
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Endpoints and identities
// ---------------------------------------------------------------------------

// The endpoint a tool talks to when --endpoint is absent. A harness can point
// every tool at one ephemeral coordinator by exporting ARF_ENDPOINT once,
// which is what makes a coordinator bound to port 0 usable by a shell script.
inline constexpr std::string_view endpoint_environment_variable = "ARF_ENDPOINT";
inline constexpr std::string_view default_endpoint_text = "127.0.0.1:7331";

// The identity conventions shared by the tools. They are the fabric and
// routing namespace the documented examples and the distributed tests use.
inline constexpr std::string_view default_fabric = "fabric-alpha";
inline constexpr std::string_view default_routing_namespace = "routing-core";
inline constexpr std::string_view default_route = "route-1";

[[nodiscard]] inline bool parse_endpoint(std::string_view text, Endpoint& endpoint,
                                         std::string& error) {
  error.clear();
  std::string_view host;
  std::string_view port_text;
  if (!text.empty() && text.front() == '[') {
    const std::size_t closing = text.find(']');
    if (closing == std::string_view::npos) {
      error = "an IPv6 endpoint must close its bracket";
      return false;
    }
    host = text.substr(1, closing - 1);
    if (closing + 1 >= text.size() || text[closing + 1] != ':') {
      error = "an IPv6 endpoint must be written [ADDRESS]:PORT";
      return false;
    }
    port_text = text.substr(closing + 2);
  } else {
    const std::size_t separator = text.rfind(':');
    if (separator == std::string_view::npos) {
      error = "endpoint '" + std::string(text) + "' must be written HOST:PORT";
      return false;
    }
    host = text.substr(0, separator);
    port_text = text.substr(separator + 1);
  }
  if (host.empty()) {
    error = "endpoint '" + std::string(text) + "' names no host";
    return false;
  }
  std::uint64_t port = 0;
  if (!parse_unsigned(port_text, port) || port == 0 || port > 65535) {
    error = "endpoint '" + std::string(text) + "' does not carry a usable port";
    return false;
  }
  endpoint.host = std::string(host);
  endpoint.port = static_cast<std::uint16_t>(port);
  return true;
}

[[nodiscard]] inline std::optional<std::string> environment_value(const char* name) {
#if defined(_WIN32)
  char* buffer = nullptr;
  std::size_t size = 0;
  if (_dupenv_s(&buffer, &size, name) != 0 || buffer == nullptr) {
    return std::nullopt;
  }
  std::string value(buffer);
  std::free(buffer);
  return value;
#else
  const char* value = std::getenv(name);
  if (value == nullptr) {
    return std::nullopt;
  }
  return std::string(value);
#endif
}

// Resolves --endpoint, then ARF_ENDPOINT, then \p fallback (empty means the
// caller has no default and must report a usage error).
[[nodiscard]] inline bool resolve_endpoint(const ArgSet& args, std::string_view fallback,
                                           Endpoint& endpoint, std::string& error) {
  const std::optional<std::string> explicit_value = args.value("endpoint");
  if (explicit_value.has_value()) {
    return parse_endpoint(*explicit_value, endpoint, error);
  }
  const std::optional<std::string> configured = environment_value("ARF_ENDPOINT");
  if (configured.has_value() && !configured->empty()) {
    if (parse_endpoint(*configured, endpoint, error)) {
      return true;
    }
    error = std::string(endpoint_environment_variable) + " is not a usable endpoint: " + error;
    return false;
  }
  if (fallback.empty()) {
    error = "--endpoint HOST:PORT is required";
    return false;
  }
  return parse_endpoint(fallback, endpoint, error);
}

[[nodiscard]] inline AuthorityScope make_authority_scope(const FabricId& fabric,
                                                         const RoutingNamespace& name_space) {
  AuthorityScope scope;
  scope.fabric = fabric;
  scope.name_space = name_space;
  return scope;
}

// An empty route list in a policy scope means "every route in this namespace",
// never "every route everywhere": the fabric and namespace are always named.
[[nodiscard]] inline PolicyScope make_policy_scope(const FabricId& fabric,
                                                   const RoutingNamespace& name_space) {
  PolicyScope scope;
  scope.fabric = fabric;
  scope.name_space = name_space;
  return scope;
}

// A revalidation attempt identity that is unique per (session, counter). The
// attempt id is what makes a replayed revalidation recognisable, so it must
// never repeat inside one session; the session id carries the process nonce.
[[nodiscard]] inline RevalidationAttemptId make_revalidation_attempt(const SessionId& session,
                                                                    std::uint64_t counter) {
  std::string text = session.valid() ? session.str() : std::string("arf");
  const std::string suffix = "-rv" + std::to_string(counter);
  const std::size_t room = RevalidationAttemptId::max_length > suffix.size()
                               ? RevalidationAttemptId::max_length - suffix.size()
                               : 0;
  if (text.size() > room) {
    text.resize(room);
  }
  text += suffix;
  const std::optional<RevalidationAttemptId> parsed = RevalidationAttemptId::parse(text);
  if (parsed.has_value()) {
    return *parsed;
  }
  return RevalidationAttemptId::require("rv-" + std::to_string(counter));
}

// The wire codec requires every field of an upstream provenance, including the
// notifying authority's own attempt identity. A fresh identity per notification
// keeps a replayed notification recognisable, and the session prefix carries the
// process nonce so two publishers never collide.
[[nodiscard]] inline MutationAttemptId make_upstream_attempt(const SessionId& session,
                                                            std::uint64_t counter) {
  std::string text = session.valid() ? session.str() : std::string("arf");
  const std::string suffix = "-n" + std::to_string(counter);
  const std::size_t room =
      MutationAttemptId::max_length > suffix.size() ? MutationAttemptId::max_length - suffix.size()
                                                   : 0;
  if (text.size() > room) {
    text.resize(room);
  }
  text += suffix;
  const std::optional<MutationAttemptId> parsed = MutationAttemptId::parse(text);
  if (parsed.has_value()) {
    return *parsed;
  }
  return MutationAttemptId::require("n-" + std::to_string(counter));
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

// Puts stdout into binary mode so every tool writes bare LF line endings. A
// text-mode stream would translate LF to CRLF on Windows, and a harness that
// compares a line byte for byte would then pass on one platform only.
inline void configure_standard_streams() noexcept {
#if defined(_WIN32)
  (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
}

inline void write_stdout_line(std::string_view text) {
  // A closed stdout pipe is not a reason to end the process: the coordinator
  // and the publisher keep running so that a harness can terminate them on its
  // own terms, which is exactly what the distributed model requires.
  std::cout.write(text.data(), static_cast<std::streamsize>(text.size()));
  std::cout.put('\n');
  std::cout.flush();
}

inline void write_stderr_line(std::string_view text) {
  std::cerr.write(text.data(), static_cast<std::streamsize>(text.size()));
  std::cerr.put('\n');
  std::cerr.flush();
}

// A line oriented channel that writes the documented output to stdout and, when
// a mirror path was given, appends the same bytes to that file. Both
// destinations are flushed per line so a poller never has to guess whether a
// line it can see is complete.
class OutputChannel {
 public:
  OutputChannel() = default;

  // Opens the mirror in append mode: a publisher run appends to whatever an
  // earlier run wrote, which is what lets a test poll one file across several
  // publisher processes.
  void open_mirror(const std::string& path) {
    mirror_.open(path, std::ios::out | std::ios::app | std::ios::binary);
    if (!mirror_.is_open()) {
      mirror_error_ = "the output file " + path + " could not be opened for append";
    }
  }

  [[nodiscard]] bool mirror_ready() const noexcept { return mirror_.is_open(); }
  [[nodiscard]] const std::string& mirror_error() const noexcept { return mirror_error_; }

  void line(std::string_view text) {
    write_stdout_line(text);
    if (mirror_.is_open()) {
      mirror_.write(text.data(), static_cast<std::streamsize>(text.size()));
      mirror_.put('\n');
      mirror_.flush();
    }
  }

 private:
  std::ofstream mirror_;
  std::string mirror_error_;
};

// ---------------------------------------------------------------------------
// Outcome classification
// ---------------------------------------------------------------------------

// "Refused" is deliberately narrower than !outcome_is_success(): a runtime that
// answers NO_CHANGE, HOLD_DOWN_ACTIVE or INSUFFICIENT_EVIDENCE has done exactly
// what it was asked to do, and the caller has nothing to correct. A refusal is
// an input the caller must fix: a malformed request, an unknown identity, an
// unauthorized caller, a stale epoch, a resource bound or a failed commit.
enum class CommandVerdict { APPLIED, ANSWERED, REFUSED };

[[nodiscard]] constexpr CommandVerdict classify_outcome(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::POLICY_CREATED:
    case Outcome::POLICY_UPDATED:
    case Outcome::DECISION_COMMITTED:
    case Outcome::IDEMPOTENT:
      return CommandVerdict::APPLIED;
    // Deterministic answers: the runtime consulted live state and declined to
    // adapt, which is a result, not a defect in the request.
    case Outcome::NO_CHANGE:
    case Outcome::SUPPRESSED:
    case Outcome::STALE_EVIDENCE:
    case Outcome::STALE_PATH_AUTHORITY:
    case Outcome::STALE_MULTIPATH_SET:
    case Outcome::STALE_ROUTE:
    case Outcome::WITHDRAWN_UPSTREAM:
    case Outcome::HOLD_DOWN_ACTIVE:
    case Outcome::COOLDOWN_ACTIVE:
    case Outcome::HYSTERESIS_NOT_CLEARED:
    case Outcome::INSUFFICIENT_EVIDENCE:
    case Outcome::NO_ELIGIBLE_CANDIDATE:
    case Outcome::NO_CURRENT_PREFERENCE:
    case Outcome::CHURN_LIMIT_REACHED:
      return CommandVerdict::ANSWERED;
    default:
      return CommandVerdict::REFUSED;
  }
}

[[nodiscard]] inline bool outcome_is_refusal(Outcome outcome) noexcept {
  return classify_outcome(outcome) == CommandVerdict::REFUSED;
}

// The single rendering of a coordinator result: the coordinator's own
// OperationResult rendering when it supplied one, otherwise the same field
// order reconstructed from the response.
[[nodiscard]] inline std::string render_result(const ResultMessage& message) {
  if (!message.rendered.empty()) {
    return message.rendered;
  }
  std::string text(to_string(message.outcome));
  if (message.suppression != SuppressionReason::NONE) {
    text += " suppression=";
    text += to_string(message.suppression);
  }
  if (!message.detail.empty()) {
    text += " detail=";
    text += message.detail;
  }
  return text;
}

// QUERY_STATE renders one "<policy-id> name=... lifecycle=..." line per policy.
// The operator surface documents pure key=value lines, so the bare leading
// identity is labelled here rather than being left as an unlabelled token.
[[nodiscard]] inline std::string label_policy_line(std::string_view line) {
  const std::size_t space = line.find(' ');
  const std::string_view head = space == std::string_view::npos ? line : line.substr(0, space);
  if (head.find('=') != std::string_view::npos) {
    return std::string(line);
  }
  std::string labelled = "policy=";
  labelled.append(head);
  if (space != std::string_view::npos) {
    labelled.append(line.substr(space));
  }
  return labelled;
}

// ---------------------------------------------------------------------------
// Local reports
// ---------------------------------------------------------------------------

// Every configured limit, in the declaration order of Limits::describe().
[[nodiscard]] inline std::vector<std::string> limit_lines() {
  std::vector<std::string> lines;
  for (const auto& entry : Limits{}.describe()) {
    lines.push_back(entry.first + "=" + std::to_string(entry.second));
  }
  return lines;
}

// The version identities this build speaks, all taken from version.hpp so the
// CLI, the library and the persisted/wire formats cannot drift apart.
[[nodiscard]] inline std::vector<std::string> version_lines() {
  std::vector<std::string> lines;
  lines.push_back("product=" + std::string(product_name));
  lines.push_back("version=" + std::string(version_string));
  lines.push_back("persistence_format_version=" + std::to_string(persistence_format_version));
  lines.push_back("wire_protocol_version=" + std::to_string(wire_protocol_version));
  lines.push_back("policy_semantics_version=" + std::to_string(policy_semantics_version));
  lines.push_back("scoring_algorithm_version=" + std::to_string(scoring_algorithm_version));
  lines.push_back("digest_encoding_version=" + std::to_string(digest_encoding_version));
  return lines;
}

// ---------------------------------------------------------------------------
// Coordinator session
// ---------------------------------------------------------------------------

// A client process is short lived, so it creates the publisher identity it
// mutates with and registers it before it sends anything else: being connected
// is not authority.
struct SessionRequest {
  Endpoint endpoint;
  AuthorityScope scope;
  std::string id_prefix = "arf";
  // When unset, the identity the client generated for itself is registered.
  std::optional<PublisherId> publisher;
  std::optional<WorkerBootId> worker_boot;
  Ticks io_budget = seconds(30);
};

struct SessionOutcome {
  bool connected = false;
  // True once the coordinator answered HELLO. A peer that closes before the
  // greeting is a connection failure, not an authority decision, and the two
  // are reported differently.
  bool greeting = false;
  bool registered = false;
  // Transport or handshake failure text; empty when the session opened.
  std::string error;
  Outcome registration_outcome = Outcome::INTERNAL_ERROR;
  std::string registration_detail;
};

struct ClientSession {
  std::unique_ptr<CoordinatorClient> client;
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  SessionOutcome outcome;
};

[[nodiscard]] inline ClientSession open_session(const SessionRequest& request) {
  ClientSession session;
  CoordinatorClient::Config config;
  config.endpoint = request.endpoint;
  config.clock = std::make_shared<SteadyClock>();
  config.id_prefix = request.id_prefix;
  config.io_budget = request.io_budget;
  session.client = std::make_unique<CoordinatorClient>(std::move(config));

  std::string error;
  if (!session.client->connect(error)) {
    session.outcome.error = error;
    return session;
  }
  session.outcome.connected = true;
  const std::optional<HelloMessage> greeting = session.client->hello(error);
  if (!greeting.has_value()) {
    session.outcome.error = error.empty() ? "the coordinator did not answer HELLO" : error;
    return session;
  }
  session.outcome.greeting = true;
  session.epoch = greeting->epoch;
  session.authority_generation = greeting->authority_generation;

  const PublisherId publisher = request.publisher.has_value() ? *request.publisher
                                                             : session.client->publisher();
  const WorkerBootId worker_boot = request.worker_boot.has_value() ? *request.worker_boot
                                                                  : session.client->worker_boot();
  const std::optional<ResultMessage> registered = session.client->register_publisher(
      publisher, worker_boot, request.scope, error);
  if (!registered.has_value()) {
    session.outcome.error =
        error.empty() ? "REGISTER_PUBLISHER produced no response" : error;
    return session;
  }
  if (registered->epoch.valid()) {
    session.epoch = registered->epoch;
  }
  session.outcome.registration_outcome = registered->outcome;
  session.outcome.registration_detail = registered->detail;
  session.outcome.registered = outcome_is_success(registered->outcome);
  return session;
}

// Ends the session without ending the process: the peer is told, the handle is
// released, and a failure to say goodbye is not an error because the peer may
// already be gone.
inline void close_session(ClientSession& session) {
  if (session.client != nullptr) {
    session.client->bye();
  }
}

}  // namespace arf_tool

#endif  // ARF_TOOL_COMMON_HPP

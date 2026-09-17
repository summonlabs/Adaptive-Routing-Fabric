// Shared deterministic scaffolding for the Adaptive Routing Fabric examples.
//
// Everything here is built from the installed umbrella header alone: an example
// demonstrates what a caller of the public API can observe, never what a friend
// of the implementation can reach. Time comes from an injected TestClock, so no
// example sleeps and no report line depends on wall-clock time, process identity
// or an address.
#ifndef ARF_EXAMPLE_SUPPORT_HPP
#define ARF_EXAMPLE_SUPPORT_HPP

#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "adaptive_routing/adaptive_routing.hpp"

namespace arf_example {

using namespace adaptive_routing;

// ---------------------------------------------------------------------------
// Deterministic reporting
// ---------------------------------------------------------------------------

// True for the canonical 32 lowercase hex characters of a semantic digest.
[[nodiscard]] inline bool looks_like_digest(std::string_view text) {
  if (text.size() != 32U) {
    return false;
  }
  for (const char character : text) {
    const bool digit = character >= '0' && character <= '9';
    const bool lower = character >= 'a' && character <= 'f';
    if (!digit && !lower) {
      return false;
    }
  }
  return true;
}

// OperationResult::render() embeds process-unique policy and decision
// identities, which are unique rather than reproducible, and a suppressed
// decision carries its semantic digest as the detail text. A report prints only
// what is a pure function of the scenario: the outcome, the suppression reason
// and the engine's own prose. A digest detail is marked instead of printed,
// because it binds the engine-generated policy identity.
[[nodiscard]] inline std::string stable_render(const OperationResult& result) {
  std::string text(to_string(result.outcome));
  if (result.suppression != SuppressionReason::NONE) {
    text += " suppression=";
    text += to_string(result.suppression);
  }
  if (!result.detail.empty()) {
    text += " detail=";
    // The engine appends "digest=<hex>" to a suppressed decision's prose, and a
    // bare digest is used when there is nothing else to say. Both bind the
    // engine-generated policy identity, so both are marked rather than printed.
    constexpr std::string_view digest_marker = " digest=";
    const std::size_t marker_at = result.detail.find(digest_marker);
    if (marker_at != std::string::npos) {
      text += result.detail.substr(0, marker_at);
      text += " digest=<decision digest>";
    } else if (looks_like_digest(result.detail)) {
      text += "<decision digest>";
    } else {
      text += result.detail;
    }
  }
  return text;
}

// Collected expectations. One line per expectation, in call order, so the report
// is byte-identical for identical scenario outcomes.
class Report {
 public:
  explicit Report(std::string_view title) : title_(title) {
    std::cout << "== " << title_ << " ==\n";
  }
  Report(const Report&) = delete;
  Report& operator=(const Report&) = delete;
  ~Report() = default;

  void note(std::string_view what) { std::cout << "note  " << what << '\n'; }

  void note(std::string_view what, std::string_view observed) {
    std::cout << "note  " << what << ": " << observed << '\n';
  }

  void expect(bool condition, std::string_view what, std::string_view observed) {
    ++checks_;
    if (!condition) {
      ++failures_;
    }
    std::cout << (condition ? "ok    " : "FAIL  ") << what;
    if (!observed.empty()) {
      std::cout << " [observed: " << observed << ']';
    }
    std::cout << '\n';
  }

  void expect_outcome(const OperationResult& result, Outcome expected, std::string_view what) {
    std::string observed = "expected ";
    observed += to_string(expected);
    observed += ", observed ";
    observed += stable_render(result);
    expect(result.outcome == expected, what, observed);
  }

  // Prints the summary line and yields the process exit code the example uses.
  [[nodiscard]] int finish() const {
    std::cout << (failures_ == 0 ? "PASS  " : "FAIL  ") << checks_ << " check(s), " << failures_
              << " failed\n";
    return failures_ == 0 ? 0 : 1;
  }

 private:
  std::string title_;
  std::size_t checks_ = 0;
  std::size_t failures_ = 0;
};

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------

[[nodiscard]] inline FabricId fabric_id() { return FabricId::require("fabric-alpha"); }
[[nodiscard]] inline RoutingNamespace routing_namespace() {
  return RoutingNamespace::require("routing-core");
}
[[nodiscard]] inline RouteId route_id() { return RouteId::require("route-1"); }
[[nodiscard]] inline PathId path(std::string_view name) { return PathId::require(name); }

[[nodiscard]] inline AuthorityScope default_scope() {
  AuthorityScope scope;
  scope.fabric = fabric_id();
  scope.name_space = routing_namespace();
  return scope;
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

// One engine, one deterministic clock and one publisher identity. Every mutation
// carries a fresh mutation attempt id, exactly as a real coordinator would.
struct Fixture {
  std::shared_ptr<TestClock> clock = std::make_shared<TestClock>();
  std::unique_ptr<AdaptiveRoutingFabric> fabric;
  PublisherId publisher = PublisherId::require("publisher-a");
  WorkerBootId worker_boot = WorkerBootId::require("boot-a1");
  SessionId session = SessionId::require("session-a1");
  std::uint64_t attempts = 0;
  std::uint64_t policies = 0;

  Fixture() {
    EngineConfig config;
    config.clock = clock;
    config.id_prefix = "arf-example";
    fabric = std::make_unique<AdaptiveRoutingFabric>(std::move(config));
  }

  // A context for an explicit identity, used by the reincarnation example to
  // present a superseded worker boot.
  [[nodiscard]] MutationContext context_for(const CoordinatorEpoch& epoch, const PublisherId& who,
                                            const WorkerBootId& boot,
                                            const SessionId& session_id) {
    MutationContext ctx;
    ctx.epoch = epoch;
    ctx.publisher = who;
    ctx.worker_boot = boot;
    ctx.session = session_id;
    ctx.attempt = MutationAttemptId::require("attempt-" + std::to_string(++attempts));
    return ctx;
  }

  [[nodiscard]] MutationContext context(
      std::optional<AdaptivePolicyGeneration> policy_generation = std::nullopt,
      std::optional<EvidenceGeneration> evidence_generation = std::nullopt) {
    MutationContext ctx = context_for(fabric->epoch(), publisher, worker_boot, session);
    ctx.expected_policy_generation = policy_generation;
    ctx.expected_evidence_generation = evidence_generation;
    return ctx;
  }

  [[nodiscard]] AdaptivePolicyName next_policy_name() {
    return AdaptivePolicyName::require("policy-" + std::to_string(++policies));
  }
};

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

[[nodiscard]] inline OperationResult register_publisher(Fixture& fixture, const PublisherId& who,
                                                        const WorkerBootId& boot,
                                                        const SessionId& session_id) {
  return fixture.fabric->register_publisher(who, boot, default_scope(), session_id);
}

[[nodiscard]] inline OperationResult register_default_publisher(Fixture& fixture) {
  return register_publisher(fixture, fixture.publisher, fixture.worker_boot, fixture.session);
}

// ---------------------------------------------------------------------------
// Policy semantics
// ---------------------------------------------------------------------------

[[nodiscard]] inline EvidenceRequirement latency_requirement(std::uint32_t min_samples = 1,
                                                             Ticks max_age = seconds(300)) {
  EvidenceRequirement requirement;
  requirement.kind = MetricKind::PATH_LATENCY;
  requirement.aggregation = AggregationKind::MEAN;
  // A non-EWMA aggregation must not carry an alpha: the runtime rejects a
  // requirement whose fields do not describe the aggregation it names.
  requirement.ewma_alpha_bps = 0;
  requirement.min_samples = min_samples;
  requirement.max_age = max_age;
  requirement.min_window = 0;
  requirement.min_quality = EvidenceQuality::AGGREGATED;
  requirement.required = true;
  return requirement;
}

[[nodiscard]] inline EvidenceRequirement utilization_requirement(std::uint32_t min_samples = 1,
                                                                 Ticks max_age = seconds(300)) {
  EvidenceRequirement requirement;
  requirement.kind = MetricKind::PATH_UTILIZATION;
  requirement.aggregation = AggregationKind::MEAN;
  requirement.ewma_alpha_bps = 0;
  requirement.min_samples = min_samples;
  requirement.max_age = max_age;
  requirement.min_window = 0;
  requirement.min_quality = EvidenceQuality::AGGREGATED;
  requirement.required = true;
  return requirement;
}

// The relative-improvement shape: a candidate must beat the current preference
// by switch_bps to take over, and the displaced preference must beat it by
// reverse_bps to come back. A zero duration disables hold-down, which the
// runtime expresses explicitly rather than by omission.
[[nodiscard]] inline PolicySemantics latency_semantics(std::uint32_t switch_bps,
                                                       std::uint32_t reverse_bps,
                                                       Ticks hold_down = 0,
                                                       bool emergency_on_unauthorized = false) {
  PolicySemantics semantics;
  semantics.target.route = route_id();
  ImprovementRule rule;
  rule.kind = MetricKind::PATH_LATENCY;
  rule.switch_improvement_bps = switch_bps;
  rule.reverse_improvement_bps = reverse_bps;
  semantics.improvements.push_back(rule);
  semantics.evidence.push_back(latency_requirement());
  semantics.hold_down.duration = hold_down;
  if (emergency_on_unauthorized) {
    semantics.emergency.enabled = true;
    semantics.emergency.on_current_path_unauthorized = true;
  }
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = MetricKind::PATH_LATENCY;
  objective.terms.push_back(term);
  semantics.objective = objective;
  return semantics;
}

// The band shape: leave the current preference above switch_value utilisation
// and enter a candidate below clear_value. Both values are basis points.
[[nodiscard]] inline PolicySemantics utilization_semantics(std::int64_t switch_value,
                                                           std::int64_t clear_value,
                                                           Ticks hold_down = 0) {
  PolicySemantics semantics;
  semantics.target.route = route_id();
  const auto switch_metric = MetricValue::make(MetricKind::PATH_UTILIZATION, switch_value);
  const auto clear_metric = MetricValue::make(MetricKind::PATH_UTILIZATION, clear_value);
  ThresholdRule rule;
  rule.kind = MetricKind::PATH_UTILIZATION;
  rule.switch_value = switch_metric.value_or(MetricValue{});
  rule.clear_value = clear_metric.value_or(MetricValue{});
  semantics.thresholds.push_back(rule);
  semantics.evidence.push_back(utilization_requirement());
  semantics.hold_down.duration = hold_down;
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = MetricKind::PATH_UTILIZATION;
  objective.terms.push_back(term);
  semantics.objective = objective;
  return semantics;
}

// ---------------------------------------------------------------------------
// Policy mutations
// ---------------------------------------------------------------------------

struct PolicyCreation {
  OperationResult created;
  OperationResult activated;
  AdaptivePolicyId policy;
};

[[nodiscard]] inline PolicyCreation create_active_policy(Fixture& fixture,
                                                         const PolicySemantics& semantics) {
  PolicyCreation creation;
  CreatePolicyRequest create;
  create.name = fixture.next_policy_name();
  create.scope.fabric = fabric_id();
  create.scope.name_space = routing_namespace();
  create.semantics = semantics;
  create.context = fixture.context();
  creation.created = fixture.fabric->create_policy(create);
  creation.policy = creation.created.policy;
  PolicyLifecycleRequest activation;
  activation.policy = creation.policy;
  activation.event = PolicyEvent::ACTIVATE;
  activation.detail = "example activation";
  activation.context = fixture.context();
  creation.activated = fixture.fabric->transition_policy(activation);
  return creation;
}

[[nodiscard]] inline OperationResult declare_candidate(Fixture& fixture,
                                                       const AdaptivePolicyId& policy,
                                                       const PathId& candidate,
                                                       std::uint64_t authority_generation = 1) {
  CandidateBinding binding;
  binding.path = candidate;
  binding.path_authority.path = candidate;
  binding.path_authority.generation = PathAuthorityGeneration::require(authority_generation);
  binding.path_authority.legal = true;
  binding.route.route = route_id();
  binding.route.generation = RouteGeneration::require(1);
  binding.route.current = true;
  binding.available = true;
  const MutationContext context = fixture.context();
  UpstreamNotification notification;
  notification.event = UpstreamEvent::DECLARE_CANDIDATE;
  notification.policy = policy;
  notification.binding = binding;
  notification.provenance.publisher = fixture.publisher;
  notification.provenance.worker_boot = fixture.worker_boot;
  notification.provenance.epoch = context.epoch;
  notification.provenance.attempt = context.attempt;
  notification.provenance.origin = "path-authority";
  UpstreamNotifyRequest request;
  request.notifications.push_back(notification);
  request.context = context;
  return fixture.fabric->apply_upstream(request);
}

// Marks a bound path illegal. The generation stays what the notification names,
// which is what a real Path Authority denial carries.
[[nodiscard]] inline OperationResult invalidate_path(Fixture& fixture,
                                                     const AdaptivePolicyId& policy,
                                                     const PathId& candidate,
                                                     std::uint64_t authority_generation = 1,
                                                     std::string_view reason = "authority denied") {
  CandidateBinding binding;
  binding.path = candidate;
  binding.path_authority.path = candidate;
  binding.path_authority.generation = PathAuthorityGeneration::require(authority_generation);
  binding.path_authority.legal = false;
  binding.path_authority.denial_reason = std::string(reason);
  binding.route.route = route_id();
  binding.route.generation = RouteGeneration::require(1);
  binding.route.current = true;
  binding.available = true;
  const MutationContext context = fixture.context();
  UpstreamNotification notification;
  notification.event = UpstreamEvent::INVALIDATE_PATH;
  notification.policy = policy;
  notification.binding = binding;
  notification.provenance.publisher = fixture.publisher;
  notification.provenance.worker_boot = fixture.worker_boot;
  notification.provenance.epoch = context.epoch;
  notification.provenance.attempt = context.attempt;
  notification.provenance.origin = "path-authority";
  UpstreamNotifyRequest request;
  request.notifications.push_back(notification);
  request.context = context;
  return fixture.fabric->apply_upstream(request);
}

// Advances a bound path's Path Authority generation. Advancing the generation
// invalidates every evaluation that read the previous one.
[[nodiscard]] inline OperationResult advance_path_authority(Fixture& fixture,
                                                            const AdaptivePolicyId& policy,
                                                            const PathId& candidate,
                                                            std::uint64_t new_generation) {
  CandidateBinding binding;
  binding.path = candidate;
  binding.path_authority.path = candidate;
  binding.path_authority.generation = PathAuthorityGeneration::require(new_generation);
  binding.path_authority.legal = true;
  binding.route.route = route_id();
  binding.route.generation = RouteGeneration::require(1);
  binding.route.current = true;
  binding.available = true;
  const MutationContext context = fixture.context();
  UpstreamNotification notification;
  notification.event = UpstreamEvent::ADVANCE_PATH_AUTHORITY;
  notification.policy = policy;
  notification.binding = binding;
  notification.provenance.publisher = fixture.publisher;
  notification.provenance.worker_boot = fixture.worker_boot;
  notification.provenance.epoch = context.epoch;
  notification.provenance.attempt = context.attempt;
  notification.provenance.origin = "path-authority";
  UpstreamNotifyRequest request;
  request.notifications.push_back(notification);
  request.context = context;
  return fixture.fabric->apply_upstream(request);
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

// A sample is published under an explicit source generation. A corrected reading
// of the same path must arrive under a fresh source incarnation: the runtime
// aggregates every retained sample of the current incarnation, so mixing a
// correction into the old incarnation would silently average the two.
[[nodiscard]] inline OperationResult publish_metric(
    Fixture& fixture, const PathId& target, MetricKind kind, std::int64_t value,
    std::uint64_t sequence = 1, std::uint64_t source_generation = 1,
    EvidenceQuality quality = EvidenceQuality::AGGREGATED) {
  EvidencePublication publication;
  publication.source = EvidenceSourceId::require("telemetry-1");
  publication.source_generation = EvidenceSourceGeneration::require(source_generation);
  publication.quality = quality;
  publication.path = target;
  publication.value = MetricValue::make(kind, value).value_or(MetricValue{});
  publication.observation_sequence = sequence;
  PublishEvidenceRequest request;
  request.publications.push_back(publication);
  request.context = fixture.context();
  return fixture.fabric->publish_evidence(request);
}

[[nodiscard]] inline OperationResult publish_latency(Fixture& fixture, const PathId& target,
                                                     std::int64_t micros,
                                                     std::uint64_t sequence = 1,
                                                     std::uint64_t source_generation = 1) {
  return publish_metric(fixture, target, MetricKind::PATH_LATENCY, micros, sequence,
                        source_generation);
}

[[nodiscard]] inline OperationResult publish_utilization(Fixture& fixture, const PathId& target,
                                                         std::int64_t basis_points,
                                                         std::uint64_t sequence = 1,
                                                         std::uint64_t source_generation = 1) {
  return publish_metric(fixture, target, MetricKind::PATH_UTILIZATION, basis_points, sequence,
                        source_generation);
}

// ---------------------------------------------------------------------------
// Evaluation and inspection
// ---------------------------------------------------------------------------

[[nodiscard]] inline OperationResult evaluate_policy(Fixture& fixture,
                                                     const AdaptivePolicyId& policy) {
  EvaluateRequest request;
  request.policy = policy;
  request.context = fixture.context();
  return fixture.fabric->evaluate(request);
}

[[nodiscard]] inline AdaptationSnapshot snapshot_of(const Fixture& fixture,
                                                    const AdaptivePolicyId& policy) {
  return fixture.fabric->snapshot(policy);
}

// The preferred path of a policy, or an invalid PathId while no preference is
// established.
[[nodiscard]] inline PathId preferred_path(const Fixture& fixture,
                                           const AdaptivePolicyId& policy) {
  const AdaptationSnapshot snapshot = snapshot_of(fixture, policy);
  return snapshot.preference.established ? snapshot.preference.preferred_path : PathId();
}

[[nodiscard]] inline std::string render_path(const PathId& value) {
  return value.valid() ? value.str() : std::string("<none>");
}

[[nodiscard]] inline std::string render_ticks(Ticks value) {
  return std::to_string(value / ticks_per_millisecond) + "ms";
}

}  // namespace arf_example

#endif  // ARF_EXAMPLE_SUPPORT_HPP

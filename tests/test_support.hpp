// Shared deterministic fixture for the engine-level suites.
//
// Every helper here is built from the public API only. No test reaches into the
// library's private state, so a test that passes here proves the public surface
// behaves, not that an internal shortcut works.
#ifndef ARF_TEST_SUPPORT_HPP
#define ARF_TEST_SUPPORT_HPP

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "adaptive_routing/adaptive_routing.hpp"
#include "test_framework.hpp"

namespace arf_test {

using namespace adaptive_routing;

[[nodiscard]] inline FabricId fabric_id() { return FabricId::require("fabric-alpha"); }
[[nodiscard]] inline RoutingNamespace routing_namespace() {
  return RoutingNamespace::require("routing-core");
}
[[nodiscard]] inline RouteId route_id() { return RouteId::require("route-1"); }
[[nodiscard]] inline MultipathSetId set_id() { return MultipathSetId::require("set-1"); }
[[nodiscard]] inline PathId path(std::string_view name) { return PathId::require(name); }

// The deterministic clock every timing-sensitive test drives by hand. No test
// sleeps to make time pass.
struct Harness {
  std::shared_ptr<TestClock> clock;
  std::unique_ptr<AdaptiveRoutingFabric> fabric;
  // The engine's deterministic scheduling hook, held behind a shared_ptr so a
  // test can install or clear it at any point without rebuilding the engine.
  // Empty by default, which is what every ordinary scenario wants.
  std::shared_ptr<std::function<void(const DependencySnapshot&)>> hook =
      std::make_shared<std::function<void(const DependencySnapshot&)>>();
  PublisherId publisher = PublisherId::require("publisher-a");
  WorkerBootId worker_boot = WorkerBootId::require("boot-a1");
  SessionId session = SessionId::require("session-a1");
  std::uint64_t attempts = 0;
  std::uint64_t policies = 0;

  [[nodiscard]] MutationContext context(
      std::optional<AdaptivePolicyGeneration> policy_generation = std::nullopt,
      std::optional<EvidenceGeneration> evidence_generation = std::nullopt) {
    MutationContext ctx;
    ctx.epoch = fabric->epoch();
    ctx.publisher = publisher;
    ctx.worker_boot = worker_boot;
    ctx.session = session;
    ctx.attempt = MutationAttemptId::require("attempt-" + std::to_string(++attempts));
    ctx.expected_policy_generation = policy_generation;
    ctx.expected_evidence_generation = evidence_generation;
    return ctx;
  }

  // A context that reuses the previous attempt id, for replay and conflict
  // tests.
  [[nodiscard]] MutationContext replay_context(const MutationContext& previous) {
    MutationContext ctx = previous;
    ctx.epoch = fabric->epoch();
    return ctx;
  }

  [[nodiscard]] AdaptivePolicyName next_policy_name() {
    return AdaptivePolicyName::require("policy-" + std::to_string(++policies));
  }
};

[[nodiscard]] inline AuthorityScope default_scope() {
  AuthorityScope scope;
  scope.fabric = fabric_id();
  scope.name_space = routing_namespace();
  return scope;
}

// Limits used by the shared fixture.
//
// The scenarios observe the *newest* sample: the fixture therefore retains
// exactly one sample per (source, path, metric) series, which makes the MEAN
// aggregation the newest value rather than a smoothed history. A test that wants
// a longer observation window passes its own limits -- see the minimum
// observation window scenario -- so nothing is hidden by this default.
[[nodiscard]] inline Limits default_test_limits() {
  Limits limits;
  limits.max_evidence_samples_per_series = 1;
  return limits;
}

[[nodiscard]] inline Harness make_harness(Limits limits = default_test_limits()) {
  Harness harness;
  harness.clock = std::make_shared<TestClock>();
  EngineConfig config;
  config.limits = limits;
  config.clock = harness.clock;
  config.id_prefix = "arf-test";
  const std::shared_ptr<std::function<void(const DependencySnapshot&)>> hook = harness.hook;
  config.evaluation_hook = [hook](const DependencySnapshot& dependencies) {
    if (hook != nullptr && *hook) {
      (*hook)(dependencies);
    }
  };
  harness.fabric = std::make_unique<AdaptiveRoutingFabric>(std::move(config));
  const OperationResult registered = harness.fabric->register_publisher(
      harness.publisher, harness.worker_boot, default_scope(), harness.session);
  ARF_CHECK_MSG(registered.outcome == Outcome::POLICY_UPDATED, registered.render());
  return harness;
}

// ---------------------------------------------------------------------------
// Policy semantics
// ---------------------------------------------------------------------------

[[nodiscard]] inline EvidenceRequirement latency_requirement(
    std::uint32_t min_samples = 1, Ticks max_age = seconds(120), Ticks min_window = 0,
    EvidenceQuality quality = EvidenceQuality::AGGREGATED,
    AggregationKind aggregation = AggregationKind::MEAN) {
  EvidenceRequirement requirement;
  requirement.kind = MetricKind::PATH_LATENCY;
  requirement.aggregation = aggregation;
  // The alpha is only meaningful for EWMA; a non-EWMA aggregation carrying one
  // is rejected as a half-configured requirement.
  requirement.ewma_alpha_bps =
      aggregation == AggregationKind::EWMA ? basis_points_scale / 4 : 0;
  requirement.min_samples = min_samples;
  requirement.max_age = max_age;
  requirement.min_window = min_window;
  requirement.min_quality = quality;
  requirement.required = true;
  return requirement;
}

[[nodiscard]] inline EvidenceRequirement utilization_requirement(
    std::uint32_t min_samples = 1, Ticks max_age = seconds(120)) {
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

// The specification's relative-improvement shape: a candidate must beat the
// current preference by switch_bps to take over, and the displaced preference
// must beat it by reverse_bps to come back.
[[nodiscard]] inline PolicySemantics latency_semantics(std::uint32_t switch_bps,
                                                       std::uint32_t reverse_bps,
                                                       Ticks hold_down = 0,
                                                       Ticks cooldown = 0) {
  PolicySemantics semantics;
  semantics.target.route = route_id();
  ImprovementRule rule;
  rule.kind = MetricKind::PATH_LATENCY;
  rule.switch_improvement_bps = switch_bps;
  rule.reverse_improvement_bps = reverse_bps;
  semantics.improvements.push_back(rule);
  semantics.evidence.push_back(latency_requirement());
  semantics.hold_down.duration = hold_down;
  semantics.cooldown.duration = cooldown;
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = MetricKind::PATH_LATENCY;
  objective.terms.push_back(term);
  semantics.objective = objective;
  return semantics;
}

// The specification's band shape: leave the current preference above
// switch_value utilisation and enter a candidate below clear_value.
[[nodiscard]] inline PolicySemantics utilization_semantics(std::int64_t switch_value,
                                                           std::int64_t clear_value,
                                                           Ticks hold_down = 0) {
  PolicySemantics semantics;
  semantics.target.route = route_id();
  const auto switch_metric = MetricValue::make(MetricKind::PATH_UTILIZATION, switch_value);
  const auto clear_metric = MetricValue::make(MetricKind::PATH_UTILIZATION, clear_value);
  ARF_CHECK(switch_metric.has_value());
  ARF_CHECK(clear_metric.has_value());
  ThresholdRule rule;
  rule.kind = MetricKind::PATH_UTILIZATION;
  rule.switch_value = *switch_metric;
  rule.clear_value = *clear_metric;
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
// Mutation helpers
// ---------------------------------------------------------------------------

[[nodiscard]] inline OperationResult create_policy(Harness& harness,
                                                   const PolicySemantics& semantics,
                                                   const AdaptivePolicyName& name,
                                                   const MutationContext& context) {
  CreatePolicyRequest request;
  request.name = name;
  request.scope.fabric = fabric_id();
  request.scope.name_space = routing_namespace();
  request.semantics = semantics;
  request.context = context;
  return harness.fabric->create_policy(request);
}

// Creates a policy and activates it, returning its identity.
[[nodiscard]] inline AdaptivePolicyId create_active_policy(Harness& harness,
                                                           const PolicySemantics& semantics) {
  const MutationContext create_context = harness.context();
  const OperationResult created =
      create_policy(harness, semantics, harness.next_policy_name(), create_context);
  ARF_CHECK_MSG(created.outcome == Outcome::POLICY_CREATED, created.render());
  PolicyLifecycleRequest activation;
  activation.policy = created.policy;
  activation.event = PolicyEvent::ACTIVATE;
  activation.detail = "test activation";
  activation.context = harness.context();
  const OperationResult activated = harness.fabric->transition_policy(activation);
  ARF_CHECK_MSG(activated.outcome == Outcome::POLICY_UPDATED, activated.render());
  return created.policy;
}

[[nodiscard]] inline CandidateBinding make_binding(const PathId& id,
                                                   std::uint64_t authority_generation,
                                                   std::uint64_t route_generation = 1,
                                                   bool legal = true) {
  CandidateBinding binding;
  binding.path = id;
  binding.path_authority.path = id;
  binding.path_authority.generation =
      PathAuthorityGeneration::require(authority_generation);
  binding.path_authority.legal = legal;
  binding.route.route = route_id();
  binding.route.generation = RouteGeneration::require(route_generation);
  binding.route.current = true;
  binding.available = true;
  return binding;
}

[[nodiscard]] inline OperationResult declare_candidate(Harness& harness,
                                                       const AdaptivePolicyId& policy_id,
                                                       const CandidateBinding& binding) {
  UpstreamNotification notification;
  notification.event = UpstreamEvent::DECLARE_CANDIDATE;
  notification.policy = policy_id;
  notification.binding = binding;
  notification.provenance.publisher = harness.publisher;
  notification.provenance.worker_boot = harness.worker_boot;
  notification.provenance.epoch = harness.fabric->epoch();
  notification.provenance.origin = "path-authority";
  UpstreamNotifyRequest request;
  request.notifications.push_back(notification);
  request.context = harness.context();
  return harness.fabric->apply_upstream(request);
}

[[nodiscard]] inline OperationResult notify(Harness& harness, const UpstreamNotification& notification) {
  UpstreamNotifyRequest request;
  request.notifications.push_back(notification);
  request.context = harness.context();
  return harness.fabric->apply_upstream(request);
}

[[nodiscard]] inline EvidencePublication make_publication(const PathId& id, MetricKind kind,
                                                          std::int64_t value,
                                                          std::uint64_t sequence,
                                                          EvidenceQuality quality,
                                                          std::uint64_t source_generation = 1) {
  EvidencePublication publication;
  publication.source = EvidenceSourceId::require("telemetry-1");
  publication.source_generation = EvidenceSourceGeneration::require(source_generation);
  publication.quality = quality;
  publication.path = id;
  const auto metric = MetricValue::make(kind, value);
  ARF_CHECK(metric.has_value());
  publication.value = metric.value_or(MetricValue{});
  publication.observation_sequence = sequence;
  return publication;
}

[[nodiscard]] inline OperationResult publish(
    Harness& harness, const std::vector<EvidencePublication>& publications,
    std::optional<EvidenceGeneration> expected = std::nullopt) {
  PublishEvidenceRequest request;
  request.publications = publications;
  request.context = harness.context(std::nullopt, expected);
  return harness.fabric->publish_evidence(request);
}

[[nodiscard]] inline OperationResult publish_latency(Harness& harness, const PathId& id,
                                                     std::int64_t micros,
                                                     std::uint64_t sequence = 1,
                                                     EvidenceQuality quality =
                                                         EvidenceQuality::AGGREGATED) {
  return publish(harness,
                 {make_publication(id, MetricKind::PATH_LATENCY, micros, sequence, quality)});
}

[[nodiscard]] inline OperationResult publish_utilization(Harness& harness, const PathId& id,
                                                         std::int64_t basis_points,
                                                         std::uint64_t sequence = 1) {
  return publish(harness, {make_publication(id, MetricKind::PATH_UTILIZATION, basis_points,
                                            sequence, EvidenceQuality::AGGREGATED)});
}

// Publishes a fresh latency sample for two candidates in one batch. Both
// samples carry distinct observation sequences, so neither is rejected as out
// of order.
inline void feed_latency(Harness& harness, const PathId& first, std::int64_t first_value,
                         const PathId& second, std::int64_t second_value,
                         std::uint64_t sequence) {
  const OperationResult result =
      publish(harness,
              {make_publication(first, MetricKind::PATH_LATENCY, first_value, sequence * 2,
                                EvidenceQuality::AGGREGATED),
               make_publication(second, MetricKind::PATH_LATENCY, second_value, sequence * 2 + 1,
                                EvidenceQuality::AGGREGATED)});
  ARF_CHECK_MSG(result.outcome == Outcome::POLICY_UPDATED, result.render());
}

[[nodiscard]] inline OperationResult evaluate_policy(
    Harness& harness, const AdaptivePolicyId& policy_id,
    std::optional<AdaptivePolicyGeneration> expected = std::nullopt, bool defer = false) {
  EvaluateRequest request;
  request.policy = policy_id;
  request.context = harness.context(expected);
  request.defer_commit = defer;
  return harness.fabric->evaluate(request);
}

[[nodiscard]] inline PathId preferred_path(const Harness& harness,
                                           const AdaptivePolicyId& policy_id) {
  const AdaptationSnapshot snapshot = harness.fabric->snapshot(policy_id);
  return snapshot.preference.established ? snapshot.preference.preferred_path : PathId();
}

// Builds a policy with two candidates already declared, which is the starting
// point of most scenarios.
struct TwoCandidate {
  AdaptivePolicyId policy;
  PathId a = path("path-a");
  PathId b = path("path-b");
};

// The suffix keeps two fixtures in one engine from sharing path identities,
// which would otherwise make their evidence series collide.
[[nodiscard]] inline TwoCandidate make_two_candidate_policy(Harness& harness,
                                                            const PolicySemantics& semantics,
                                                            const std::string& suffix = std::string()) {
  TwoCandidate fixture;
  fixture.a = path("path-a" + suffix);
  fixture.b = path("path-b" + suffix);
  fixture.policy = create_active_policy(harness, semantics);
  const OperationResult first = declare_candidate(harness, fixture.policy, make_binding(fixture.a, 1));
  ARF_CHECK_MSG(first.outcome == Outcome::POLICY_UPDATED, first.render());
  const OperationResult second = declare_candidate(harness, fixture.policy, make_binding(fixture.b, 1));
  ARF_CHECK_MSG(second.outcome == Outcome::POLICY_UPDATED, second.render());
  return fixture;
}

}  // namespace arf_test

#endif  // ARF_TEST_SUPPORT_HPP

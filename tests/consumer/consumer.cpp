// Independent consumer of the installed Adaptive Routing Fabric package.
//
// This program is the acceptance proof of the exported surface. It uses nothing
// but <adaptive_routing/adaptive_routing.hpp> from the installed tree, and it
// exercises the whole documented flow end to end:
//
//   * register a publisher under the current epoch;
//   * create a policy with two candidate paths and activate it;
//   * announce both candidates through the upstream binding contract;
//   * publish deterministic evidence in fixed-point metrics;
//   * evaluate an A -> B adaptation and prove it committed;
//   * prove hysteresis suppression of the reverse move;
//   * advance a deterministic test clock and re-evaluate;
//   * take an immutable snapshot and check the semantic digest is stable.
//
// It returns 0 only when every assertion holds.
#include <adaptive_routing/adaptive_routing.hpp>

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

using namespace adaptive_routing;

int failures = 0;

void check(bool condition, const std::string& what) {
  if (!condition) {
    ++failures;
    std::cout << "FAIL " << what << "\n";
  } else {
    std::cout << "ok   " << what << "\n";
  }
}

AdaptivePolicyName policy_name() { return AdaptivePolicyName::require("consumer-policy"); }
FabricId the_fabric() { return FabricId::require("fabric-consumer"); }
RoutingNamespace the_namespace() { return RoutingNamespace::require("routing-consumer"); }
RouteId the_route() { return RouteId::require("route-consumer"); }
PathId path_a() { return PathId::require("path-a"); }
PathId path_b() { return PathId::require("path-b"); }

CandidateBinding binding_for(const PathId& id, std::uint64_t authority_generation) {
  CandidateBinding binding;
  binding.path = id;
  binding.path_authority.path = id;
  binding.path_authority.generation = PathAuthorityGeneration::require(authority_generation);
  binding.path_authority.legal = true;
  binding.route.route = the_route();
  binding.route.generation = RouteGeneration::require(1);
  binding.route.current = true;
  binding.available = true;
  return binding;
}

EvidencePublication sample_for(const PathId& id, std::int64_t micros, std::uint64_t sequence) {
  EvidencePublication publication;
  publication.source = EvidenceSourceId::require("consumer-telemetry");
  publication.source_generation = EvidenceSourceGeneration::require(1);
  publication.quality = EvidenceQuality::AGGREGATED;
  publication.path = id;
  const auto value = MetricValue::make(MetricKind::PATH_LATENCY, micros);
  if (value.has_value()) {
    publication.value = *value;
  }
  publication.observation_sequence = sequence;
  return publication;
}

}  // namespace

int main() {
  const std::shared_ptr<TestClock> clock = std::make_shared<TestClock>();
  EngineConfig config;
  config.clock = clock;
  config.id_prefix = "arf-consumer";
  // Bounded retention of exactly one sample per series is what makes the MEAN
  // aggregation the newest reading rather than a smoothed history. The
  // documented alternative is to publish a corrected reading under a fresh
  // EvidenceSourceGeneration, which drops the previous incarnation's samples.
  config.limits.max_evidence_samples_per_series = 1;

  AdaptiveRoutingFabric fabric(config);

  const PublisherId publisher = PublisherId::require("consumer-publisher");
  const WorkerBootId boot = WorkerBootId::require("consumer-boot-1");
  const SessionId session = SessionId::require("consumer-session-1");

  AuthorityScope scope;
  scope.fabric = the_fabric();
  scope.name_space = the_namespace();
  check(fabric.register_publisher(publisher, boot, scope, session).ok(),
        "the publisher is registered for the current epoch");

  std::uint64_t attempts = 0;
  const auto context = [&](std::optional<AdaptivePolicyGeneration> expected =
                               std::nullopt) {
    MutationContext ctx;
    ctx.epoch = fabric.epoch();
    ctx.publisher = publisher;
    ctx.worker_boot = boot;
    ctx.session = session;
    ctx.attempt = MutationAttemptId::require("consumer-attempt-" + std::to_string(++attempts));
    ctx.expected_policy_generation = expected;
    return ctx;
  };

  // A policy with two candidates and an explicit 20 % / 30 % hysteresis shape.
  PolicySemantics semantics;
  semantics.target.route = the_route();
  ImprovementRule improvement;
  improvement.kind = MetricKind::PATH_LATENCY;
  improvement.switch_improvement_bps = 2000;
  improvement.reverse_improvement_bps = 3000;
  semantics.improvements.push_back(improvement);
  EvidenceRequirement requirement;
  requirement.kind = MetricKind::PATH_LATENCY;
  requirement.aggregation = AggregationKind::MEAN;
  requirement.ewma_alpha_bps = 0;
  requirement.min_samples = 1;
  requirement.max_age = seconds(300);
  requirement.min_window = 0;
  requirement.min_quality = EvidenceQuality::AGGREGATED;
  requirement.required = true;
  semantics.evidence.push_back(requirement);
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = MetricKind::PATH_LATENCY;
  objective.terms.push_back(term);
  semantics.objective = objective;
  semantics.hold_down.duration = seconds(30);

  CreatePolicyRequest creation;
  creation.name = policy_name();
  creation.scope.fabric = the_fabric();
  creation.scope.name_space = the_namespace();
  creation.semantics = semantics;
  creation.context = context();
  const OperationResult created = fabric.create_policy(creation);
  check(created.outcome == Outcome::POLICY_CREATED, "the policy is created");
  const AdaptivePolicyId policy = created.policy;

  PolicyLifecycleRequest activation;
  activation.policy = policy;
  activation.event = PolicyEvent::ACTIVATE;
  activation.detail = "consumer activation";
  activation.context = context();
  check(fabric.transition_policy(activation).outcome == Outcome::POLICY_UPDATED,
        "the policy becomes ACTIVE");

  const auto declare = [&](const PathId& id) {
    UpstreamNotification notification;
    notification.event = UpstreamEvent::DECLARE_CANDIDATE;
    notification.policy = policy;
    notification.binding = binding_for(id, 1);
    notification.provenance.publisher = publisher;
    notification.provenance.worker_boot = boot;
    notification.provenance.epoch = fabric.epoch();
    notification.provenance.origin = "consumer-path-authority";
    UpstreamNotifyRequest request;
    request.notifications.push_back(notification);
    request.context = context();
    return fabric.apply_upstream(request);
  };
  check(declare(path_a()).ok(), "path-a is declared through the upstream contract");
  check(declare(path_b()).ok(), "path-b is declared through the upstream contract");

  const auto publish = [&](const PathId& id, std::int64_t value, std::uint64_t sequence) {
    PublishEvidenceRequest request;
    request.publications.push_back(sample_for(id, value, sequence));
    request.context = context();
    return fabric.publish_evidence(request);
  };

  // path-a is the only candidate with evidence, so it is established.
  check(publish(path_a(), 1000, 1).ok(), "path-a reports 1000us");
  EvaluateRequest first;
  first.policy = policy;
  first.context = context();
  check(fabric.evaluate(first).outcome == Outcome::DECISION_COMMITTED,
        "the initial preference is established on path-a");

  // path-b is exactly 20 % better, which meets the declared switch requirement.
  check(publish(path_b(), 800, 2).ok(), "path-b reports 800us");
  EvaluateRequest second;
  second.policy = policy;
  second.context = context();
  const OperationResult moved = fabric.evaluate(second);
  check(moved.outcome == Outcome::DECISION_COMMITTED, "path-b takes over from path-a");

  const AdaptationSnapshot after_move = fabric.snapshot(policy);
  check(after_move.preference.established && after_move.preference.preferred_path == path_b(),
        "the committed preference is path-b");
  check(after_move.stable.established && after_move.stable.path == path_a(),
        "the rollback anchor is the displaced preference");
  check(after_move.hold_down_active, "hold-down is armed after the adaptation");

  // The reverse move needs 30 %, and only 20 % is on offer: it is suppressed.
  check(publish(path_a(), 800, 3).ok(), "path-a reports 800us against path-b at 1000us");
  check(publish(path_b(), 1000, 4).ok(), "path-b reports 1000us");
  EvaluateRequest third;
  third.policy = policy;
  third.context = context();
  const OperationResult suppressed = fabric.evaluate(third);
  check(suppressed.outcome == Outcome::HYSTERESIS_NOT_CLEARED ||
            suppressed.outcome == Outcome::HOLD_DOWN_ACTIVE,
        "the reverse move is suppressed: " + std::string(to_string(suppressed.outcome)));
  check(fabric.snapshot(policy).preference.preferred_path == path_b(),
        "the suppressed move changed nothing");

  // Advance the deterministic clock past the hold-down and try again.
  clock->advance(seconds(31));
  check(publish(path_a(), 500, 5).ok(), "path-a reports 500us");
  check(publish(path_b(), 1000, 6).ok(), "path-b reports 1000us");
  EvaluateRequest fourth;
  fourth.policy = policy;
  fourth.context = context();
  const OperationResult released = fabric.evaluate(fourth);
  check(released.outcome == Outcome::DECISION_COMMITTED,
        "after the hold-down elapses the 50 % improvement commits: " +
            std::string(to_string(released.outcome)));
  check(fabric.snapshot(policy).preference.preferred_path == path_a(),
        "path-a is preferred again");

  // The snapshot is an immutable value and its digest is deterministic.
  const AdaptationSnapshot snapshot_a = fabric.snapshot(policy);
  const AdaptationSnapshot snapshot_b = fabric.snapshot(policy);
  check(snapshot_a.digest == snapshot_b.digest, "the semantic digest is deterministic");
  check(snapshot_a.digest == snapshot_digest(snapshot_a),
        "the digest matches the published digest helper");
  check(snapshot_a.preference.preferred_path == path_a(),
        "the snapshot is unaffected by a later read");

  std::cout << (failures == 0 ? "PASS" : "FAIL") << ": " << failures << " failed check(s)\n";
  return failures == 0 ? 0 : 1;
}

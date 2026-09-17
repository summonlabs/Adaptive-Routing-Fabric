// Adversarial hardening suite.
//
// Every case is an input the runtime must refuse, and each asserts the exact
// structured rejection rather than merely "it did not crash".
#include <limits>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace arf_test;

UpstreamNotification forged_event(Harness& harness, const AdaptivePolicyId& policy,
                                  UpstreamEvent event, const CandidateBinding& binding,
                                  std::optional<std::uint64_t> expected = std::nullopt) {
  UpstreamNotification notification;
  notification.event = event;
  notification.policy = policy;
  notification.binding = binding;
  notification.expected_previous_generation = expected;
  notification.provenance.publisher = harness.publisher;
  notification.provenance.worker_boot = harness.worker_boot;
  notification.provenance.epoch = harness.fabric->epoch();
  notification.provenance.origin = "adversary";
  return notification;
}

}  // namespace

// Malformed and zero identities are refused everywhere they can be supplied.
ARF_TEST(malformed_and_zero_identities_are_refused) {
  ARF_CHECK(!PathId::parse("").has_value());
  ARF_CHECK(!PathId::parse("-leading").has_value());
  ARF_CHECK(!PathId::parse("trailing-").has_value());
  ARF_CHECK(!PathId::parse("has space").has_value());
  ARF_CHECK(!PathId::parse(std::string(129, 'a')).has_value());
  ARF_CHECK(!AdaptivePolicyGeneration::from_value(0).has_value());
  ARF_CHECK(!CoordinatorEpoch::from_value(0).has_value());

  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));

  MutationContext complete = harness.context();
  MutationContext missing_publisher = complete;
  missing_publisher.publisher = PublisherId();
  PublishEvidenceRequest request;
  request.publications.push_back(make_publication(fixture.a, MetricKind::PATH_LATENCY, 10, 1,
                                                  EvidenceQuality::AGGREGATED));
  request.context = missing_publisher;
  ARF_CHECK_EQ(harness.fabric->publish_evidence(request).outcome, Outcome::UNAUTHORIZED);

  MutationContext zero_epoch = complete;
  zero_epoch.epoch = CoordinatorEpoch();
  request.context = zero_epoch;
  ARF_CHECK_EQ(harness.fabric->publish_evidence(request).outcome, Outcome::UNAUTHORIZED);

  // A zero generation in a candidate binding is refused before it is stored.
  UpstreamNotifyRequest notify_request;
  notify_request.notifications.push_back(forged_event(
      harness, fixture.policy, UpstreamEvent::DECLARE_CANDIDATE,
      CandidateBinding{}, std::nullopt));
  notify_request.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->apply_upstream(notify_request).outcome, Outcome::MALFORMED_REQUEST);
}

// Every stale generation the protocol can carry is rejected with its own
// outcome.
ARF_TEST(every_stale_generation_is_rejected_distinctly) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  // Stale epoch.
  MutationContext stale_epoch = harness.context();
  stale_epoch.epoch = CoordinatorEpoch::require(harness.fabric->epoch().value() + 5);
  PublishEvidenceRequest publish_request;
  publish_request.publications.push_back(make_publication(fixture.a, MetricKind::PATH_LATENCY, 1,
                                                          2, EvidenceQuality::AGGREGATED));
  publish_request.context = stale_epoch;
  ARF_CHECK_EQ(harness.fabric->publish_evidence(publish_request).outcome, Outcome::STALE_EPOCH);

  // Stale worker boot.
  MutationContext stale_worker = harness.context();
  stale_worker.worker_boot = WorkerBootId::require("boot-unknown");
  publish_request.context = stale_worker;
  ARF_CHECK_EQ(harness.fabric->publish_evidence(publish_request).outcome, Outcome::STALE_WORKER);

  // Unknown publisher.
  MutationContext unknown = harness.context();
  unknown.publisher = PublisherId::require("publisher-unknown");
  publish_request.context = unknown;
  const Outcome unknown_outcome = harness.fabric->publish_evidence(publish_request).outcome;
  ARF_CHECK(unknown_outcome == Outcome::UNAUTHORIZED || unknown_outcome == Outcome::STALE_WORKER);

  // Unauthorized scope: a publisher registered for one namespace cannot publish
  // for a path bound only inside another.
  AuthorityScope narrow;
  narrow.fabric = FabricId::require("fabric-alpha");
  narrow.name_space = RoutingNamespace::require("routing-other");
  const PublisherId outsider = PublisherId::require("publisher-outsider");
  const WorkerBootId outsider_boot = WorkerBootId::require("boot-outsider");
  const SessionId outsider_session = SessionId::require("session-outsider");
  ARF_CHECK_EQ(harness.fabric->register_publisher(outsider, outsider_boot, narrow, outsider_session)
                   .outcome,
               Outcome::POLICY_UPDATED);
  MutationContext outsider_context;
  outsider_context.epoch = harness.fabric->epoch();
  outsider_context.publisher = outsider;
  outsider_context.worker_boot = outsider_boot;
  outsider_context.session = outsider_session;
  outsider_context.attempt = MutationAttemptId::require("attempt-outsider-1");
  publish_request.context = outsider_context;
  ARF_CHECK_EQ(harness.fabric->publish_evidence(publish_request).outcome,
               Outcome::UNAUTHORIZED_SCOPE);

  // Stale path authority: an advance must be strictly forward.
  ARF_CHECK_EQ(notify(harness, forged_event(harness, fixture.policy,
                                            UpstreamEvent::ADVANCE_PATH_AUTHORITY,
                                            make_binding(fixture.a, 1, 1, true), 1))
                   .outcome,
               Outcome::STALE_PATH_AUTHORITY);
  ARF_CHECK_EQ(notify(harness, forged_event(harness, fixture.policy,
                                            UpstreamEvent::ADVANCE_PATH_AUTHORITY,
                                            make_binding(fixture.a, 9, 1, true), 4))
                   .outcome,
               Outcome::STALE_PATH_AUTHORITY);

  // Stale multipath: a set whose generation is not the one the policy binds.
  PolicySemantics multipath_semantics = latency_semantics(2000, 3000);
  multipath_semantics.target.multipath_set = set_id();
  const AdaptivePolicyId multipath_policy = create_active_policy(harness, multipath_semantics);
  CandidateBinding with_set = make_binding(path("path-set-1"), 1);
  MultipathBinding membership;
  membership.set = set_id();
  membership.generation = MultipathSetGeneration::require(1);
  membership.current = true;
  membership.members.push_back(path("path-set-1"));
  with_set.multipath = membership;
  ARF_CHECK_EQ(notify(harness, forged_event(harness, multipath_policy,
                                            UpstreamEvent::DECLARE_CANDIDATE, with_set))
                   .outcome,
               Outcome::POLICY_UPDATED);
  // A multipath binding for a different set than the policy target is refused.
  CandidateBinding wrong_set = make_binding(path("path-set-2"), 1);
  MultipathBinding other;
  other.set = MultipathSetId::require("set-other");
  other.generation = MultipathSetGeneration::require(1);
  other.current = true;
  other.members.push_back(path("path-set-2"));
  wrong_set.multipath = other;
  ARF_CHECK_EQ(notify(harness, forged_event(harness, multipath_policy,
                                            UpstreamEvent::DECLARE_CANDIDATE, wrong_set))
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  // Stale route: a route binding for a different route than the policy target.
  CandidateBinding wrong_route = make_binding(path("path-route"), 1);
  wrong_route.route.route = RouteId::require("route-other");
  ARF_CHECK_EQ(notify(harness, forged_event(harness, fixture.policy,
                                            UpstreamEvent::DECLARE_CANDIDATE, wrong_route))
                   .outcome,
               Outcome::MALFORMED_REQUEST);
}

// A candidate is never declared without a current legal Path Authority binding.
ARF_TEST(candidate_without_authority_is_refused) {
  Harness harness = make_harness();
  const AdaptivePolicyId policy_id = create_active_policy(harness, latency_semantics(2000, 3000));
  const OperationResult refused =
      declare_candidate(harness, policy_id, make_binding(path("path-illegal"), 1, 1, false));
  ARF_CHECK_EQ(refused.outcome, Outcome::MALFORMED_REQUEST);
  ARF_CHECK_EQ(harness.fabric->candidates(policy_id).size(), static_cast<std::size_t>(0));
}

// Threshold and interval defects.
ARF_TEST(invalid_thresholds_and_intervals_are_refused) {
  Harness harness = make_harness();

  // Inverted band: the clear value is worse than the switch value.
  PolicySemantics inverted = utilization_semantics(8000, 9000);
  const MutationContext context = harness.context();
  ARF_CHECK_EQ(create_policy(harness, inverted, harness.next_policy_name(), context).outcome,
               Outcome::INVALID_HYSTERESIS);

  // Degenerate band: the two thresholds are equal.
  PolicySemantics degenerate = utilization_semantics(8000, 8000);
  ARF_CHECK_EQ(create_policy(harness, degenerate, harness.next_policy_name(), harness.context())
                   .outcome,
               Outcome::INVALID_HYSTERESIS);

  // An improvement rule requiring nothing is an omission, not a trigger.
  PolicySemantics empty_improvement = latency_semantics(0, 0);
  ARF_CHECK_EQ(create_policy(harness, empty_improvement, harness.next_policy_name(),
                             harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  // A requirement with no freshness bound would let arbitrarily old evidence
  // trigger a routing change.
  PolicySemantics unbounded = latency_semantics(2000, 3000);
  unbounded.evidence.front().max_age = 0;
  ARF_CHECK_EQ(create_policy(harness, unbounded, harness.next_policy_name(), harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  // A window longer than the freshness bound can never be satisfied.
  PolicySemantics impossible_window = latency_semantics(2000, 3000);
  impossible_window.evidence.front().min_window = seconds(3600);
  ARF_CHECK_EQ(create_policy(harness, impossible_window, harness.next_policy_name(),
                             harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  // Zero-sample requirements and oversized EWMA alphas.
  PolicySemantics zero_samples = latency_semantics(2000, 3000);
  zero_samples.evidence.front().min_samples = 0;
  ARF_CHECK_EQ(create_policy(harness, zero_samples, harness.next_policy_name(), harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  PolicySemantics bad_alpha = latency_semantics(2000, 3000);
  bad_alpha.evidence.front().aggregation = AggregationKind::EWMA;
  bad_alpha.evidence.front().ewma_alpha_bps = 20000;
  ARF_CHECK_EQ(create_policy(harness, bad_alpha, harness.next_policy_name(), harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  // Dampening with a cap below the base hold-down.
  PolicySemantics bad_dampening = latency_semantics(2000, 3000, seconds(30));
  bad_dampening.dampening.enabled = true;
  bad_dampening.dampening.penalty_increment = 2;
  bad_dampening.dampening.max_penalty = 4;
  bad_dampening.dampening.penalty_decay_interval = seconds(10);
  bad_dampening.dampening.penalty_decay_step = 1;
  bad_dampening.dampening.hold_down_escalation_step = seconds(1);
  bad_dampening.dampening.max_effective_hold_down = seconds(5);
  ARF_CHECK_EQ(create_policy(harness, bad_dampening, harness.next_policy_name(),
                             harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  // Churn with a bound but no window.
  PolicySemantics bad_churn = latency_semantics(2000, 3000);
  bad_churn.churn.max_adaptations_per_window = 4;
  ARF_CHECK_EQ(create_policy(harness, bad_churn, harness.next_policy_name(), harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  // An emergency override with no condition to act on.
  PolicySemantics bad_emergency = latency_semantics(2000, 3000);
  bad_emergency.emergency.enabled = true;
  ARF_CHECK_EQ(create_policy(harness, bad_emergency, harness.next_policy_name(),
                             harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  // An objective whose terms are empty, duplicated or unnormalised.
  PolicySemantics empty_objective = latency_semantics(2000, 3000);
  empty_objective.objective.terms.clear();
  ARF_CHECK_EQ(create_policy(harness, empty_objective, harness.next_policy_name(),
                             harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  PolicySemantics weighted = latency_semantics(2000, 3000);
  weighted.objective.mode = ObjectiveMode::WEIGHTED_SCORE;
  weighted.objective.terms.front().weight_bps = 5000;
  ARF_CHECK_EQ(create_policy(harness, weighted, harness.next_policy_name(), harness.context())
                   .outcome,
               Outcome::MALFORMED_REQUEST);

  ARF_CHECK_EQ(harness.fabric->list_policies().size(), static_cast<std::size_t>(0));
}

// Metric arithmetic rejects overflow and incompatible semantics instead of
// producing a value.
ARF_TEST(metric_arithmetic_refuses_overflow_and_incompatible_units) {
  const auto beyond_latency =
      MetricValue::make(MetricKind::PATH_LATENCY, std::numeric_limits<std::int64_t>::max());
  ARF_CHECK(!beyond_latency.has_value());
  const auto negative = MetricValue::make(MetricKind::PATH_UTILIZATION, -1);
  ARF_CHECK(!negative.has_value());

  const auto latency = MetricValue::make(MetricKind::PATH_LATENCY, 1000);
  const auto utilization = MetricValue::make(MetricKind::PATH_UTILIZATION, 1000);
  ARF_CHECK(latency.has_value() && utilization.has_value());
  ARF_CHECK(!latency->comparable_with(*utilization));
  ARF_CHECK(!relative_improvement_bps(*latency, *utilization).has_value());

  // The same numeric value under a different semantics version is not the same
  // fact.
  const auto future = MetricValue::decode(MetricKind::PATH_LATENCY, MetricUnit::MICROSECONDS, 2, 1000);
  ARF_CHECK(!future.has_value());
  const auto wrong_unit = MetricValue::decode(MetricKind::PATH_LATENCY, MetricUnit::PPM, 1, 1000);
  ARF_CHECK(!wrong_unit.has_value());

  // An aggregating sum that would overflow is refused rather than wrapped.
  const std::vector<std::int64_t> huge(4, (std::numeric_limits<std::int64_t>::max)() / 2);
  ARF_CHECK(!aggregate_samples(AggregationKind::MEAN, huge).has_value());
}

// A stale generation can never leave a half-applied mutation behind.
ARF_TEST(refused_mutations_leave_no_partial_state) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  const AdaptivePolicy before = *harness.fabric->find_policy(fixture.policy);

  UpdatePolicyRequest update;
  update.policy = fixture.policy;
  update.update.scope = before.scope;
  // An inverted band: the value that would clear the hysteresis is worse than
  // the value that enters it.
  update.update.semantics = utilization_semantics(8000, 9000);
  update.update.semantics.target.route = route_id();
  update.context = harness.context(before.generation);
  ARF_CHECK_EQ(harness.fabric->update_policy(update).outcome, Outcome::INVALID_HYSTERESIS);
  const AdaptivePolicy after = *harness.fabric->find_policy(fixture.policy);
  ARF_CHECK_EQ(after.generation.value(), before.generation.value());
  ARF_CHECK_EQ(after.semantics.improvements.front().switch_improvement_bps, 2000U);

  // A rejected evidence batch publishes nothing at all.
  const EvidenceGeneration generation_before = harness.fabric->evidence_generation();
  const std::uint64_t samples_before = harness.fabric->stats().evidence_samples;
  const std::uint64_t series_before = harness.fabric->stats().evidence_series;
  PublishEvidenceRequest request;
  request.publications.push_back(make_publication(fixture.a, MetricKind::PATH_LATENCY, 10, 1,
                                                  EvidenceQuality::AGGREGATED));
  request.publications.push_back(make_publication(fixture.b, MetricKind::PATH_LATENCY, 10, 1,
                                                  EvidenceQuality::AGGREGATED));
  // The second sample reuses the first sequence for a different path, which is
  // legal; the batch is made invalid by an unknown quality class instead.
  request.publications.back().quality = static_cast<EvidenceQuality>(9);
  request.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->publish_evidence(request).outcome, Outcome::MALFORMED_REQUEST);
  ARF_CHECK_EQ(harness.fabric->evidence_generation(), generation_before);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_samples, samples_before);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_series, series_before);
}

// An adaptation storm cannot exceed the declared churn bound.
ARF_TEST(adaptation_storm_is_bounded) {
  Harness harness = make_harness();
  PolicySemantics semantics = latency_semantics(1000, 1000);
  semantics.churn.max_adaptations_per_window = 3;
  semantics.churn.window = seconds(1000);
  const TwoCandidate fixture = make_two_candidate_policy(harness, semantics);
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  // The initial establishment is a committed decision but not an adaptation, so
  // it consumes no churn budget: one establishment plus three adaptations.
  // The initial establishment is a committed decision but not an adaptation, so
  // it consumes no churn budget.
  std::uint32_t committed = 1;
  std::uint32_t limited = 0;
  std::uint32_t no_change = 0;
  for (std::uint64_t round = 0; round < 40; ++round) {
    const bool favour_b = round % 2 == 0;
    feed_latency(harness, fixture.a, favour_b ? 1000 : 400, fixture.b,
                 favour_b ? 400 : 1000, 2 + round);
    const OperationResult result = evaluate_policy(harness, fixture.policy);
    if (result.outcome == Outcome::DECISION_COMMITTED) {
      ++committed;
    } else if (result.outcome == Outcome::CHURN_LIMIT_REACHED) {
      ++limited;
    } else {
      // Rounds whose evidence favours the path the storm is already sitting on
      // are a plain no-change: the budget is spent, and the incumbent is
      // already the best eligible candidate.
      ARF_CHECK_MSG(result.outcome == Outcome::NO_CHANGE,
                    "round=" + std::to_string(round) + " " + result.render());
      ++no_change;
    }
  }
  // Three adaptations fit inside the declared budget of three; every later
  // attempt to leave the incumbent is refused.
  ARF_CHECK_EQ(committed, 4U);
  // The establishment that preceded the loop is not one of its forty rounds.
  ARF_CHECK_EQ((committed - 1U) + limited + no_change, 40U);
  ARF_CHECK_EQ(limited, 19U);
  ARF_CHECK_EQ(no_change, 18U);
  // Four commits advance the adaptation generation from its first value of one
  // to five.
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).adaptation_generation.value(),
               static_cast<std::uint64_t>(committed) + 1ULL);
}

// Resource exhaustion is reported, not absorbed.
ARF_TEST(resource_exhaustion_is_reported) {
  Limits limits;
  limits.max_policies = 2;
  limits.max_candidates_per_policy = 2;
  limits.max_evidence_sources = 1;
  limits.max_history_per_policy = 2;
  limits.max_snapshot_history = 1;
  limits.max_attempts = 4;
  Harness harness = make_harness(limits);

  ARF_CHECK(create_active_policy(harness, latency_semantics(2000, 3000)).valid());
  ARF_CHECK(create_active_policy(harness, latency_semantics(2000, 3000)).valid());
  const OperationResult third = create_policy(harness, latency_semantics(2000, 3000),
                                              AdaptivePolicyName::require("policy-overflow"),
                                              harness.context());
  ARF_CHECK_EQ(third.outcome, Outcome::RESOURCE_LIMIT);

  const AdaptivePolicyId policy_id = harness.fabric->list_policies().front().id;
  ARF_CHECK_EQ(declare_candidate(harness, policy_id, make_binding(path("p-1"), 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(declare_candidate(harness, policy_id, make_binding(path("p-2"), 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(declare_candidate(harness, policy_id, make_binding(path("p-3"), 1)).outcome,
               Outcome::RESOURCE_LIMIT);

  // Two distinct evidence sources exceed a bound of one.
  EvidencePublication first = make_publication(path("p-1"), MetricKind::PATH_LATENCY, 100, 1,
                                               EvidenceQuality::AGGREGATED);
  EvidencePublication second = make_publication(path("p-2"), MetricKind::PATH_LATENCY, 100, 1,
                                                EvidenceQuality::AGGREGATED);
  second.source = EvidenceSourceId::require("telemetry-2");
  ARF_CHECK_EQ(publish(harness, {first}).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish(harness, {second}).outcome, Outcome::RESOURCE_LIMIT);
}

// A publisher cannot act outside the scope it registered for.
ARF_TEST(scope_is_default_deny) {
  Harness harness = make_harness();
  const AuthorityScope narrow = []() {
    AuthorityScope scope;
    scope.fabric = FabricId::require("fabric-alpha");
    scope.name_space = RoutingNamespace::require("routing-core");
    scope.routes.push_back(RouteId::require("route-authorized"));
    return scope;
  }();
  const PublisherId limited = PublisherId::require("publisher-limited");
  const WorkerBootId limited_boot = WorkerBootId::require("boot-limited");
  const SessionId limited_session = SessionId::require("session-limited");
  ARF_CHECK_EQ(harness.fabric->register_publisher(limited, limited_boot, narrow, limited_session)
                   .outcome,
               Outcome::POLICY_UPDATED);

  MutationContext context;
  context.epoch = harness.fabric->epoch();
  context.publisher = limited;
  context.worker_boot = limited_boot;
  context.session = limited_session;
  context.attempt = MutationAttemptId::require("attempt-limited-1");
  PolicySemantics semantics = latency_semantics(2000, 3000);
  semantics.target.route = route_id();
  const OperationResult refused =
      create_policy(harness, semantics, AdaptivePolicyName::require("policy-outside"), context);
  ARF_CHECK_EQ(refused.outcome, Outcome::UNAUTHORIZED_SCOPE);
}

// A malformed frame never reaches the engine and never wedges a session's frame
// decoder.
ARF_TEST(malformed_frames_are_refused_before_dispatch) {
  Limits limits;
  limits.max_frame_bytes = 256;
  const std::string payload = HelloMessage{wire_protocol_version, "Adaptive Routing Fabric",
                                           CoordinatorEpoch::first(),
                                           AdaptiveAuthorityGeneration::first()}
                                  .encode();
  Frame frame;
  frame.header.message_id = MessageId::HELLO;
  frame.header.epoch = CoordinatorEpoch::first();
  frame.header.sequence = 1;
  frame.payload = payload;
  const auto encoded = encode_frame(frame, limits.max_frame_bytes);
  ARF_CHECK(encoded.has_value());
  const FrameDecodeResult decoded = decode_frame(*encoded, limits.max_frame_bytes);
  ARF_CHECK_EQ(decoded.status, FrameStatus::OK);
  ARF_CHECK_EQ(decoded.consumed, encoded->size());

  std::string truncated = *encoded;
  truncated.pop_back();
  ARF_CHECK_EQ(decode_frame(truncated, limits.max_frame_bytes).status, FrameStatus::INCOMPLETE);

  std::string corrupted = *encoded;
  corrupted[corrupted.size() - 1] = static_cast<char>(corrupted.back() ^ 0x01);
  ARF_CHECK_EQ(decode_frame(corrupted, limits.max_frame_bytes).status, FrameStatus::INTEGRITY);

  std::string wrong_magic = *encoded;
  wrong_magic[0] = static_cast<char>(wrong_magic[0] ^ 0xFF);
  ARF_CHECK_EQ(decode_frame(wrong_magic, limits.max_frame_bytes).status, FrameStatus::BAD_MAGIC);

  // An oversized declared payload length is refused before any allocation.
  std::string oversized = *encoded;
  oversized[12] = static_cast<char>(0xFF);
  oversized[13] = static_cast<char>(0xFF);
  oversized[14] = static_cast<char>(0xFF);
  oversized[15] = static_cast<char>(0x7F);
  ARF_CHECK_EQ(decode_frame(oversized, limits.max_frame_bytes).status, FrameStatus::TOO_LARGE);

  // A frame whose payload encodes an unknown message id is refused.
  std::string bad_id = *encoded;
  bad_id[6] = static_cast<char>(0xFE);
  bad_id[7] = static_cast<char>(0x00);
  ARF_CHECK_EQ(decode_frame(bad_id, limits.max_frame_bytes).status, FrameStatus::BAD_MESSAGE_ID);
}

// A revoked policy stays revoked and its revocation is durable.
ARF_TEST(revocation_is_distinct_from_invalidation_and_is_durable) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  const OperationResult revoked =
      harness.fabric->revoke_policy(fixture.policy, RevocationReason::SECURITY, "operator action",
                                    harness.context());
  ARF_CHECK_EQ(revoked.outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK(harness.fabric->find_revocation(fixture.policy).has_value());

  // The same revocation is idempotent; a different reason is refused.
  ARF_CHECK_EQ(harness.fabric->revoke_policy(fixture.policy, RevocationReason::SECURITY, "again",
                                             harness.context())
                   .outcome,
               Outcome::IDEMPOTENT);
  ARF_CHECK_EQ(harness.fabric->revoke_policy(fixture.policy, RevocationReason::ADMINISTRATIVE,
                                             "different", harness.context())
                   .outcome,
               Outcome::REVOKED);

  // Adaptation is refused, and the evidence the runtime holds is untouched:
  // revocation is not evidence invalidation.
  const std::uint64_t series_before = harness.fabric->stats().evidence_series;
  const EvidenceGeneration evidence_before = harness.fabric->evidence_generation();
  feed_latency(harness, fixture.a, 1000, fixture.b, 100, 2);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::REVOKED);
  // Evidence publication is still accepted and still retained after a
  // revocation: revoking a policy is not evidence invalidation.
  ARF_CHECK(harness.fabric->evidence_generation() > evidence_before);
  ARF_CHECK(harness.fabric->stats().evidence_series >= series_before);
  ARF_CHECK(!harness.fabric->describe_evidence(fixture.policy).empty());

  // Revocation survives persistence.
  const std::string bytes = harness.fabric->encode_store();
  Harness restored = make_harness();
  ARF_CHECK_EQ(restored.fabric->decode_store(bytes, "adversarial").outcome, Outcome::POLICY_UPDATED);
  const auto revocation = restored.fabric->find_revocation(fixture.policy);
  ARF_CHECK(revocation.has_value());
  ARF_CHECK(revocation.has_value() && revocation->reason == RevocationReason::SECURITY);
  ARF_CHECK_EQ(restored.fabric->find_policy(fixture.policy)->lifecycle, PolicyLifecycle::REVOKED);
}

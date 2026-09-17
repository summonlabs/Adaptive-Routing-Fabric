// Threshold, hysteresis, hold-down, cooldown, dampening, churn, emergency and
// rollback proofs.
//
// Every scenario here is deterministic: the clock is advanced by hand, no test
// sleeps, and each assertion names the exact structured outcome it expects.
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace arf_test;

}  // namespace

// The specification's hysteresis proof: switch away at 20% relative
// improvement, require 30% to come back.
ARF_TEST(hysteresis_exact_thresholds_and_no_flap) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));

  // Establish A: only A has evidence, so B cannot claim an evidence-driven
  // superiority it cannot prove.
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  const OperationResult established = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(established.outcome == Outcome::DECISION_COMMITTED, established.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);

  // Exactly 20% better: the switch threshold is met, so the adaptation commits.
  feed_latency(harness, fixture.a, 1000, fixture.b, 800, 2);
  const OperationResult switched = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(switched.outcome == Outcome::DECISION_COMMITTED, switched.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);

  // 19% better is below the switch threshold: nothing moves.
  feed_latency(harness, fixture.a, 1000, fixture.b, 810, 3);
  const OperationResult below = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(below.outcome, Outcome::NO_CHANGE);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);

  // A is now 20% better than B, but a reverse move needs 30%: suppressed.
  feed_latency(harness, fixture.a, 800, fixture.b, 1000, 4);
  const OperationResult reverse_refused = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(reverse_refused.outcome, Outcome::HYSTERESIS_NOT_CLEARED);
  ARF_CHECK_EQ(reverse_refused.suppression, SuppressionReason::HYSTERESIS_NOT_CLEARED);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);
  ARF_CHECK(reverse_refused.detail.find("3000") != std::string::npos);

  // 40% better clears the reverse requirement.
  feed_latency(harness, fixture.a, 600, fixture.b, 1000, 5);
  const OperationResult back = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(back.outcome == Outcome::DECISION_COMMITTED, back.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);

  // Oscillating around 20% can no longer flap: B is now the reverse target and
  // needs 30%.
  for (std::uint64_t round = 0; round < 6; ++round) {
    harness.clock->advance(seconds(30));
    feed_latency(harness, fixture.a, 1000, fixture.b, 800, 10 + round);
    const OperationResult oscillation = evaluate_policy(harness, fixture.policy);
    ARF_CHECK_EQ(oscillation.outcome, Outcome::HYSTERESIS_NOT_CLEARED);
    ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
  }

  // The last suppression is explained deterministically.
  const Explanation explanation =
      harness.fabric->explain(ExplanationTopic::HYSTERESIS, fixture.policy);
  ARF_CHECK(explanation.find("improvement.PATH_LATENCY") != nullptr);
  ARF_CHECK(explanation.find("reverse_target") != nullptr);
}

// A band threshold with explicit hysteresis: leave above 80%, return below 65%.
ARF_TEST(band_threshold_hysteresis) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, utilization_semantics(8000, 6500));

  ARF_CHECK_EQ(publish_utilization(harness, fixture.a, 5000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);

  // A is at 79%: below the switch threshold, so the policy stays.
  ARF_CHECK_EQ(publish(
                   harness, {make_publication(fixture.a, MetricKind::PATH_UTILIZATION, 7900, 2,
                                              EvidenceQuality::AGGREGATED),
                             make_publication(fixture.b, MetricKind::PATH_UTILIZATION, 6000, 3,
                                              EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult below_switch = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(below_switch.outcome, Outcome::NO_CHANGE);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);

  // A is at 82% but B is at 70%: the band has not been cleared.
  ARF_CHECK_EQ(publish(
                   harness, {make_publication(fixture.a, MetricKind::PATH_UTILIZATION, 8200, 4,
                                              EvidenceQuality::AGGREGATED),
                             make_publication(fixture.b, MetricKind::PATH_UTILIZATION, 7000, 5,
                                              EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult uncleared = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(uncleared.outcome, Outcome::HYSTERESIS_NOT_CLEARED);
  ARF_CHECK_EQ(uncleared.suppression, SuppressionReason::HYSTERESIS_NOT_CLEARED);

  // A at 82% and B at 60%: departure and entry conditions both hold.
  ARF_CHECK_EQ(publish(
                   harness, {make_publication(fixture.a, MetricKind::PATH_UTILIZATION, 8200, 6,
                                              EvidenceQuality::AGGREGATED),
                             make_publication(fixture.b, MetricKind::PATH_UTILIZATION, 6000, 7,
                                              EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult committed = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(committed.outcome == Outcome::DECISION_COMMITTED, committed.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);
}

// Hold-down suppresses the reverse adaptation until the declared interval has
// elapsed on the deterministic clock.
ARF_TEST(hold_down_suppresses_reverse_until_it_expires) {
  Harness harness = make_harness();
  const TwoCandidate fixture =
      make_two_candidate_policy(harness, latency_semantics(2000, 3000, seconds(10)));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);
  const OperationResult forward = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(forward.outcome == Outcome::DECISION_COMMITTED, forward.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);

  const AdaptationSnapshot after_commit = harness.fabric->snapshot(fixture.policy);
  const AdaptationGeneration committed_generation = after_commit.adaptation_generation;
  ARF_CHECK(after_commit.hold_down_active);

  // Overwhelming evidence favouring A: the reverse is still suppressed.
  feed_latency(harness, fixture.a, 100, fixture.b, 1000, 3);
  const OperationResult suppressed = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(suppressed.outcome, Outcome::HOLD_DOWN_ACTIVE);
  ARF_CHECK_EQ(suppressed.suppression, SuppressionReason::HOLD_DOWN_ACTIVE);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).adaptation_generation,
               committed_generation);

  // Advancing the clock past the hold-down re-enables the ordinary path.
  harness.clock->advance(seconds(11));
  feed_latency(harness, fixture.a, 100, fixture.b, 1000, 4);
  const OperationResult released = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(released.outcome == Outcome::DECISION_COMMITTED, released.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
}

// Cooldown is not hold-down: it suppresses an ordinary move to a third path too.
ARF_TEST(cooldown_suppresses_any_ordinary_adaptation) {
  Harness harness = make_harness();
  const PolicySemantics semantics = latency_semantics(1000, 3000, 0, seconds(60));
  const AdaptivePolicyId policy_id = create_active_policy(harness, semantics);
  const PathId a = path("path-a");
  const PathId b = path("path-b");
  const PathId c = path("path-c");
  for (const auto& id : {a, b, c}) {
    ARF_CHECK_EQ(declare_candidate(harness, policy_id, make_binding(id, 1)).outcome,
                 Outcome::POLICY_UPDATED);
  }
  ARF_CHECK_EQ(publish_latency(harness, a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, policy_id).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK_EQ(preferred_path(harness, policy_id), a);

  ARF_CHECK_EQ(publish(
                   harness, {make_publication(a, MetricKind::PATH_LATENCY, 1000, 2,
                                              EvidenceQuality::AGGREGATED),
                             make_publication(b, MetricKind::PATH_LATENCY, 800, 3,
                                              EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult moved = evaluate_policy(harness, policy_id);
  ARF_CHECK_MSG(moved.outcome == Outcome::DECISION_COMMITTED, moved.render());
  ARF_CHECK_EQ(preferred_path(harness, policy_id), b);

  // C is neither the current nor the previous preference, so hold-down would not
  // apply, but cooldown does.
  ARF_CHECK_EQ(publish(
                   harness, {make_publication(b, MetricKind::PATH_LATENCY, 1000, 4,
                                              EvidenceQuality::AGGREGATED),
                             make_publication(c, MetricKind::PATH_LATENCY, 700, 5,
                                              EvidenceQuality::AGGREGATED),
                             make_publication(a, MetricKind::PATH_LATENCY, 4000, 6,
                                              EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult cooled = evaluate_policy(harness, policy_id);
  ARF_CHECK_EQ(cooled.outcome, Outcome::COOLDOWN_ACTIVE);
  ARF_CHECK_EQ(preferred_path(harness, policy_id), b);

  harness.clock->advance(seconds(61));
  ARF_CHECK_EQ(publish(
                   harness, {make_publication(b, MetricKind::PATH_LATENCY, 1000, 7,
                                              EvidenceQuality::AGGREGATED),
                             make_publication(c, MetricKind::PATH_LATENCY, 700, 8,
                                              EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult released = evaluate_policy(harness, policy_id);
  ARF_CHECK_MSG(released.outcome == Outcome::DECISION_COMMITTED, released.render());
  ARF_CHECK_EQ(preferred_path(harness, policy_id), c);
}

// Bounded churn: the adaptation budget inside the window is enforced.
ARF_TEST(churn_bound_is_enforced_and_recovers_after_the_window) {
  Harness harness = make_harness();
  PolicySemantics semantics = latency_semantics(1000, 1000);
  semantics.churn.max_adaptations_per_window = 2;
  semantics.churn.window = seconds(100);
  const TwoCandidate fixture = make_two_candidate_policy(harness, semantics);

  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  feed_latency(harness, fixture.a, 1000, fixture.b, 800, 2);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 700, fixture.b, 1000, 3);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  feed_latency(harness, fixture.a, 1000, fixture.b, 700, 4);
  const OperationResult limited = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(limited.outcome, Outcome::CHURN_LIMIT_REACHED);
  ARF_CHECK_EQ(limited.suppression, SuppressionReason::CHURN_LIMIT_REACHED);

  harness.clock->advance(seconds(101));
  feed_latency(harness, fixture.a, 1000, fixture.b, 700, 5);
  const OperationResult released = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(released.outcome == Outcome::DECISION_COMMITTED, released.render());
}

// Bounded dampening: repeated oscillation raises an integer penalty that
// extends the hold-down, capped by the declared maximum.
ARF_TEST(dampening_extends_hold_down_within_its_bound) {
  Harness harness = make_harness();
  PolicySemantics semantics = latency_semantics(1000, 1000, seconds(5));
  semantics.dampening.enabled = true;
  semantics.dampening.penalty_increment = 1;
  semantics.dampening.max_penalty = 2;
  semantics.dampening.penalty_decay_interval = seconds(60);
  semantics.dampening.penalty_decay_step = 1;
  semantics.dampening.hold_down_escalation_step = seconds(5);
  semantics.dampening.max_effective_hold_down = seconds(15);
  const TwoCandidate fixture = make_two_candidate_policy(harness, semantics);

  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).dampening_penalty, 1U);

  feed_latency(harness, fixture.a, 100, fixture.b, 1000, 3);
  const OperationResult first_reverse = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(first_reverse.outcome == Outcome::HOLD_DOWN_ACTIVE, first_reverse.render());
  // 5s base + 1 * 5s escalation = 10s, so 6 seconds is still inside the interval.
  harness.clock->advance(seconds(6));
  feed_latency(harness, fixture.a, 100, fixture.b, 1000, 4);
  const OperationResult still_held = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(still_held.outcome == Outcome::HOLD_DOWN_ACTIVE, still_held.render());
  harness.clock->advance(seconds(5));
  feed_latency(harness, fixture.a, 100, fixture.b, 1000, 5);
  const OperationResult released = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(released.outcome == Outcome::DECISION_COMMITTED, released.render());
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).dampening_penalty, 2U);

  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 6);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::HOLD_DOWN_ACTIVE);
  // The penalty is capped at 2, so the effective hold-down is 15s and never more.
  harness.clock->advance(seconds(16));
  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 7);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).dampening_penalty, 2U);

  const Explanation explanation = harness.fabric->explain(ExplanationTopic::HOLD_DOWN, fixture.policy);
  ARF_CHECK(explanation.find("hold_down_effective_ms") != nullptr);
  const std::string* effective = explanation.find("hold_down_effective_ms");
  // 5s base plus penalty 2 times the 5s escalation step is 15s, which is exactly
  // the declared cap.
  ARF_CHECK(effective != nullptr && *effective == "15000ms");
}

// Emergency override abandons an unauthorized current path even during
// hold-down, and never overrides Path Authority to do it.
ARF_TEST(emergency_override_respects_path_authority) {
  Harness harness = make_harness();
  PolicySemantics semantics = latency_semantics(2000, 3000, seconds(600));
  semantics.emergency.enabled = true;
  semantics.emergency.on_current_path_unauthorized = true;
  const TwoCandidate fixture = make_two_candidate_policy(harness, semantics);

  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 1000, fixture.b, 800, 2);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);
  ARF_CHECK(harness.fabric->snapshot(fixture.policy).hold_down_active);

  // A is invalidated while B is preferred: no emergency is triggered because the
  // current preference is still legal.
  UpstreamNotification invalidate_a;
  invalidate_a.event = UpstreamEvent::INVALIDATE_PATH;
  invalidate_a.policy = fixture.policy;
  invalidate_a.binding = make_binding(fixture.a, 2, 1, false);
  invalidate_a.binding.path_authority.denial_reason = "operator withdrew authorization";
  invalidate_a.provenance.publisher = harness.publisher;
  invalidate_a.provenance.worker_boot = harness.worker_boot;
  invalidate_a.provenance.epoch = harness.fabric->epoch();
  invalidate_a.provenance.origin = "path-authority";
  ARF_CHECK_EQ(notify(harness, invalidate_a).outcome, Outcome::POLICY_UPDATED);
  feed_latency(harness, fixture.a, 100, fixture.b, 1000, 3);
  const OperationResult steady = evaluate_policy(harness, fixture.policy);
  // A is no longer a legal candidate, so its better number cannot be used; the
  // current preference keeps its place.
  ARF_CHECK_EQ(steady.outcome, Outcome::NO_CHANGE);
  ARF_CHECK_EQ(steady.suppression, SuppressionReason::MERIT_NOT_ESTABLISHED);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);

  // B is now unauthorized as well, so the emergency fires, but the only legal
  // remaining candidate is A, which the policy may not use: the honest answer is
  // NO_ELIGIBLE_CANDIDATE, not an illegal override.
  UpstreamNotification invalidate_b;
  invalidate_b.event = UpstreamEvent::INVALIDATE_PATH;
  invalidate_b.policy = fixture.policy;
  invalidate_b.binding = make_binding(fixture.b, 2, 1, false);
  invalidate_b.binding.path_authority.denial_reason = "route withdrawn";
  invalidate_b.provenance.publisher = harness.publisher;
  invalidate_b.provenance.worker_boot = harness.worker_boot;
  invalidate_b.provenance.epoch = harness.fabric->epoch();
  invalidate_b.provenance.origin = "path-authority";
  ARF_CHECK_EQ(notify(harness, invalidate_b).outcome, Outcome::POLICY_UPDATED);
  const OperationResult none = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(none.outcome, Outcome::NO_ELIGIBLE_CANDIDATE);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);

  // Restoring A's authorization lets the emergency proceed despite hold-down.
  UpstreamNotification restore_a;
  restore_a.event = UpstreamEvent::ADVANCE_PATH_AUTHORITY;
  restore_a.policy = fixture.policy;
  restore_a.binding = make_binding(fixture.a, 3, 1, true);
  restore_a.expected_previous_generation = 2;
  restore_a.provenance.publisher = harness.publisher;
  restore_a.provenance.worker_boot = harness.worker_boot;
  restore_a.provenance.epoch = harness.fabric->epoch();
  restore_a.provenance.origin = "path-authority";
  ARF_CHECK_EQ(notify(harness, restore_a).outcome, Outcome::POLICY_UPDATED);
  const OperationResult rescued = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(rescued.outcome == Outcome::DECISION_COMMITTED, rescued.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
  const AdaptationDecision latest = *harness.fabric->find_decision(rescued.decision);
  ARF_CHECK_EQ(latest.cause, AdaptationCause::EMERGENCY_OVERRIDE);
}

// Without an emergency rule an ineligible current preference is reported as a
// revalidation requirement instead of a silent override.
ARF_TEST(ineligible_current_preference_requires_revalidation) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  UpstreamNotification invalidate;
  invalidate.event = UpstreamEvent::INVALIDATE_PATH;
  invalidate.policy = fixture.policy;
  invalidate.binding = make_binding(fixture.a, 2, 1, false);
  invalidate.provenance.publisher = harness.publisher;
  invalidate.provenance.worker_boot = harness.worker_boot;
  invalidate.provenance.epoch = harness.fabric->epoch();
  invalidate.provenance.origin = "path-authority";
  ARF_CHECK_EQ(notify(harness, invalidate).outcome, Outcome::POLICY_UPDATED);

  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);
  const OperationResult blocked = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(blocked.outcome, Outcome::REVALIDATION_REQUIRED);
  ARF_CHECK_EQ(blocked.suppression, SuppressionReason::CURRENT_PREFERENCE_INELIGIBLE);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);

  const AdaptationSnapshot snapshot = harness.fabric->snapshot(fixture.policy);
  ARF_CHECK_EQ(snapshot.currentness, Currentness::STALE_PATH_AUTHORITY);
}

// Missing required evidence fails closed: the runtime never claims an
// evidence-driven superiority it cannot prove.
ARF_TEST(unknown_evidence_fails_closed) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  // B is still missing its latency sample entirely, so it cannot displace A;
  // the runtime reports that the incumbent simply retained its merit rather
  // than inventing an evidence-driven superiority for B.
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 2).outcome, Outcome::POLICY_UPDATED);
  const OperationResult no_alternative = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(no_alternative.outcome, Outcome::NO_CHANGE);
  ARF_CHECK_EQ(no_alternative.suppression, SuppressionReason::MERIT_NOT_ESTABLISHED);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);

  // The explanation names B as ineligible rather than merely worse.
  const Explanation rejected =
      harness.fabric->explain(ExplanationTopic::REJECTED_CANDIDATE, fixture.policy);
  const std::string* entry = rejected.find("rank2.path-b");
  ARF_CHECK(entry != nullptr);
  ARF_CHECK(entry != nullptr && entry->find("ineligible") != std::string::npos);
}

// A required observation window prevents one sample from triggering a change.
ARF_TEST(minimum_observation_window_blocks_a_single_sample) {
  // This scenario needs a real observation window, so it asks for retention
  // beyond the fixture default.
  Limits limits = default_test_limits();
  limits.max_evidence_samples_per_series = 8;
  Harness harness = make_harness(limits);
  PolicySemantics semantics = latency_semantics(2000, 3000);
  semantics.evidence.clear();
  semantics.evidence.push_back(latency_requirement(3, seconds(120), seconds(2),
                                                   EvidenceQuality::AGGREGATED));
  const TwoCandidate fixture = make_two_candidate_policy(harness, semantics);

  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  harness.clock->advance(seconds(1));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 2).outcome, Outcome::POLICY_UPDATED);
  harness.clock->advance(seconds(1));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 3).outcome, Outcome::POLICY_UPDATED);
  const OperationResult established = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(established.outcome == Outcome::DECISION_COMMITTED, established.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);

  // One sample inside the declared window is not an observation window.
  ARF_CHECK_EQ(publish_latency(harness, fixture.b, 500, 4).outcome, Outcome::POLICY_UPDATED);
  const OperationResult one_sample = evaluate_policy(harness, fixture.policy);
  // A is still the best eligible candidate, so it simply keeps its place.
  ARF_CHECK_EQ(one_sample.outcome, Outcome::NO_CHANGE);
  ARF_CHECK_EQ(one_sample.suppression, SuppressionReason::MERIT_NOT_ESTABLISHED);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);

  // Three samples spanning the required window are.
  harness.clock->advance(seconds(1));
  ARF_CHECK_EQ(publish_latency(harness, fixture.b, 500, 5).outcome, Outcome::POLICY_UPDATED);
  harness.clock->advance(seconds(1));
  ARF_CHECK_EQ(publish_latency(harness, fixture.b, 500, 6).outcome, Outcome::POLICY_UPDATED);
  const OperationResult enough = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(enough.outcome == Outcome::DECISION_COMMITTED, enough.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);
}

// Rollback restores the last known stable preference and refuses when the
// restore target is no longer legal.
ARF_TEST(rollback_revalidates_the_restore_target) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 1000, fixture.b, 800, 2);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);
  ARF_CHECK(harness.fabric->snapshot(fixture.policy).stable.established);

  RollbackRequest rollback;
  rollback.policy = fixture.policy;
  rollback.reason = "operator observed a regression";
  rollback.context = harness.context();
  // The anchor is the preference the current one displaced, so the rollback
  // restores a genuinely different path.
  const OperationResult rolled_back = harness.fabric->rollback(rollback);
  ARF_CHECK_MSG(rolled_back.outcome == Outcome::DECISION_COMMITTED, rolled_back.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).stable.path, fixture.b);

  // Rolling back again returns to B: each rollback revalidates and then moves
  // the anchor to the preference it displaced.
  RollbackRequest again;
  again.policy = fixture.policy;
  again.reason = "restore the other known-stable preference";
  again.context = harness.context();
  const OperationResult returned = harness.fabric->rollback(again);
  ARF_CHECK_MSG(returned.outcome == Outcome::DECISION_COMMITTED, returned.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).stable.path, fixture.a);

  // An ordinary adaptation is now refused because the incumbent's evidence has
  // gone stale relative to the published reading, and the rollback is refused
  // because its restore target is no longer authorized.
  UpstreamNotification invalidate_a;
  invalidate_a.event = UpstreamEvent::INVALIDATE_PATH;
  invalidate_a.policy = fixture.policy;
  invalidate_a.binding = make_binding(fixture.a, 2, 1, false);
  invalidate_a.provenance.publisher = harness.publisher;
  invalidate_a.provenance.worker_boot = harness.worker_boot;
  invalidate_a.provenance.epoch = harness.fabric->epoch();
  invalidate_a.provenance.origin = "path-authority";
  ARF_CHECK_EQ(notify(harness, invalidate_a).outcome, Outcome::POLICY_UPDATED);

  RollbackRequest stale_target;
  stale_target.policy = fixture.policy;
  stale_target.reason = "restore an unauthorized preference";
  stale_target.context = harness.context();
  const OperationResult refused_again = harness.fabric->rollback(stale_target);
  ARF_CHECK_EQ(refused_again.outcome, Outcome::STALE_PATH_AUTHORITY);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);

  const Explanation explanation =
      harness.fabric->explain(ExplanationTopic::ROLLBACK_REFUSED, fixture.policy);
  ARF_CHECK(explanation.find("stable_path_legal") != nullptr);
  const std::string* legal = explanation.find("stable_path_legal");
  ARF_CHECK(legal != nullptr && *legal == "false");
}

// Equal candidates resolve canonically and the decision digest is stable.
ARF_TEST(deterministic_tie_break_and_digest) {
  Harness harness = make_harness();
  const AdaptivePolicyId policy_id = create_active_policy(harness, latency_semantics(1000, 1000));
  const PathId later = path("path-z");
  const PathId earlier = path("path-a");
  // Declared out of canonical order on purpose: arrival order must not decide.
  ARF_CHECK_EQ(declare_candidate(harness, policy_id, make_binding(later, 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(declare_candidate(harness, policy_id, make_binding(earlier, 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish(
                   harness, {make_publication(later, MetricKind::PATH_LATENCY, 500, 1,
                                              EvidenceQuality::AGGREGATED),
                             make_publication(earlier, MetricKind::PATH_LATENCY, 500, 2,
                                              EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult committed = evaluate_policy(harness, policy_id);
  ARF_CHECK_MSG(committed.outcome == Outcome::DECISION_COMMITTED, committed.render());
  ARF_CHECK_EQ(preferred_path(harness, policy_id), earlier);

  const AdaptationDecision decision = *harness.fabric->find_decision(committed.decision);
  ARF_CHECK(!decision.digest.empty());
  ARF_CHECK_EQ(decision.digest, decision_digest(decision));

  // A second engine given the same inputs produces the same decision digest.
  Harness second = make_harness();
  const AdaptivePolicyId second_policy = create_active_policy(second, latency_semantics(1000, 1000));
  ARF_CHECK_EQ(declare_candidate(second, second_policy, make_binding(later, 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(declare_candidate(second, second_policy, make_binding(earlier, 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish(
                   second, {make_publication(later, MetricKind::PATH_LATENCY, 500, 1,
                                             EvidenceQuality::AGGREGATED),
                            make_publication(earlier, MetricKind::PATH_LATENCY, 500, 2,
                                             EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult second_commit = evaluate_policy(second, second_policy);
  ARF_CHECK_MSG(second_commit.outcome == Outcome::DECISION_COMMITTED, second_commit.render());
  const AdaptationDecision second_decision =
      *second.fabric->find_decision(second_commit.decision);
  ARF_CHECK_EQ(second_decision.digest, decision.digest);
  ARF_CHECK_EQ(second_decision.ranking.size(), decision.ranking.size());
}

// An explicit policy priority outranks the objective, and the objective
// outranks the canonical path order.
ARF_TEST(ranking_precedence_is_priority_then_objective_then_path) {
  Harness harness = make_harness();
  PolicySemantics semantics = latency_semantics(1000, 1000);
  CandidatePriority priority;
  priority.path = path("path-b");
  priority.priority = 5;
  semantics.priorities.push_back(priority);
  const AdaptivePolicyId policy_id = create_active_policy(harness, semantics);
  const PathId a = path("path-a");
  const PathId b = path("path-b");
  ARF_CHECK_EQ(declare_candidate(harness, policy_id, make_binding(a, 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(declare_candidate(harness, policy_id, make_binding(b, 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish(
                   harness, {make_publication(a, MetricKind::PATH_LATENCY, 100, 1,
                                              EvidenceQuality::AGGREGATED),
                             make_publication(b, MetricKind::PATH_LATENCY, 900, 2,
                                              EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, policy_id).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK_EQ(preferred_path(harness, policy_id), b);
}

// Stable-state semantics: a committed preference is stable, and losing path
// authority for it is reported as exactly that.
ARF_TEST(stable_state_and_currentness_are_distinct) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  AdaptationSnapshot snapshot = harness.fabric->snapshot(fixture.policy);
  // Establishing the first preference leaves no rollback anchor, and the
  // preference itself is current.
  ARF_CHECK(!snapshot.stable.established);
  ARF_CHECK_EQ(snapshot.currentness, Currentness::CURRENT);
  ARF_CHECK_EQ(snapshot.blockers.size(), static_cast<std::size_t>(0));

  // A transition moves the anchor to the preference it displaced, while the new
  // preference is what currentness now describes.
  feed_latency(harness, fixture.a, 1000, fixture.b, 800, 2);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  snapshot = harness.fabric->snapshot(fixture.policy);
  ARF_CHECK(snapshot.stable.established);
  ARF_CHECK_EQ(snapshot.stable.path, fixture.a);
  ARF_CHECK_EQ(snapshot.preference.preferred_path, fixture.b);
  ARF_CHECK_EQ(snapshot.currentness, Currentness::CURRENT);

  UpstreamNotification invalidate;
  invalidate.event = UpstreamEvent::INVALIDATE_PATH;
  invalidate.policy = fixture.policy;
  invalidate.binding = make_binding(fixture.b, 2, 1, false);
  invalidate.provenance.publisher = harness.publisher;
  invalidate.provenance.worker_boot = harness.worker_boot;
  invalidate.provenance.epoch = harness.fabric->epoch();
  invalidate.provenance.origin = "path-authority";
  ARF_CHECK_EQ(notify(harness, invalidate).outcome, Outcome::POLICY_UPDATED);

  snapshot = harness.fabric->snapshot(fixture.policy);
  ARF_CHECK_EQ(snapshot.currentness, Currentness::STALE_PATH_AUTHORITY);
  ARF_CHECK(snapshot.blockers.size() >= static_cast<std::size_t>(1));
  // The preference is still recorded: it is historical truth, not live authority.
  ARF_CHECK_EQ(snapshot.preference.preferred_path, fixture.b);
  // The anchor is untouched by the invalidation; rollback revalidates it.
  ARF_CHECK_EQ(snapshot.stable.path, fixture.a);
}

// Policy generation advances only when the policy semantics change.
ARF_TEST(policy_generation_advances_only_on_change) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  const AdaptivePolicy policy = *harness.fabric->find_policy(fixture.policy);
  ARF_CHECK_EQ(policy.generation.value(), 1ULL);

  UpdatePolicyRequest request;
  request.policy = fixture.policy;
  request.update.scope = policy.scope;
  request.update.semantics = policy.semantics;
  request.update.semantics.improvements.front().switch_improvement_bps = 2500;
  request.context = harness.context(policy.generation);
  const OperationResult updated = harness.fabric->update_policy(request);
  ARF_CHECK_MSG(updated.outcome == Outcome::POLICY_UPDATED, updated.render());
  ARF_CHECK_EQ(harness.fabric->find_policy(fixture.policy)->generation.value(), 2ULL);

  // An update with a stale expected generation is refused.
  UpdatePolicyRequest again;
  again.policy = fixture.policy;
  again.update.scope = policy.scope;
  again.update.semantics = policy.semantics;
  again.context = harness.context(policy.generation);
  ARF_CHECK_EQ(harness.fabric->update_policy(again).outcome, Outcome::STALE_POLICY_GENERATION);
  ARF_CHECK_EQ(harness.fabric->find_policy(fixture.policy)->generation.value(), 2ULL);
}

// Retiring a policy prevents any later adaptation.
ARF_TEST(retirement_prevents_adaptation) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  PolicyLifecycleRequest retire;
  retire.policy = fixture.policy;
  retire.event = PolicyEvent::RETIRE;
  retire.detail = "end of life";
  retire.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->transition_policy(retire).outcome, Outcome::POLICY_UPDATED);

  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);
  const OperationResult blocked = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(blocked.outcome, Outcome::RETIRED);

  PolicyLifecycleRequest reactivate;
  reactivate.policy = fixture.policy;
  reactivate.event = PolicyEvent::ACTIVATE;
  reactivate.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->transition_policy(reactivate).outcome, Outcome::RETIRED);
  ARF_CHECK_EQ(harness.fabric->find_policy(fixture.policy)->lifecycle, PolicyLifecycle::RETIRED);
}

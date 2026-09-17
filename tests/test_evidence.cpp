// Evidence publication, retention, freshness and snapshot immutability.
//
// Evidence is the only input that can move routing preference, so every rule
// that decides whether a sample is usable is driven here to an exact structured
// rejection: an accepted sample that should have been refused is how stale
// telemetry becomes routing authority.
//
// The shared fixture retains one sample per series so that a scenario observes
// the newest value; the tests that need history pass their own Limits, because
// Limits::max_evidence_samples_per_series is a product limit and nothing about
// it changed.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "adaptive_routing/adaptive_routing.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace arf_test;
using namespace adaptive_routing;

// Retention limits for a scenario that needs to observe a history.
[[nodiscard]] Limits retention_limits(std::uint64_t samples_per_series) {
  Limits limits = default_test_limits();
  limits.max_evidence_samples_per_series = samples_per_series;
  return limits;
}

// A policy with the named candidate paths already declared.
[[nodiscard]] AdaptivePolicyId policy_with_candidates(Harness& harness,
                                                      const PolicySemantics& semantics,
                                                      const std::vector<PathId>& candidates) {
  const AdaptivePolicyId policy = create_active_policy(harness, semantics);
  for (const PathId& candidate : candidates) {
    const OperationResult declared = declare_candidate(harness, policy, make_binding(candidate, 1));
    ARF_CHECK_MSG(declared.outcome == Outcome::POLICY_UPDATED, declared.render());
  }
  return policy;
}

[[nodiscard]] const CandidateEvaluation* find_ranking(const AdaptationDecision& decision,
                                                      const PathId& path) {
  for (const CandidateEvaluation& entry : decision.ranking) {
    if (entry.path == path) {
      return &entry;
    }
  }
  return nullptr;
}

// The decision journal is newest first.
[[nodiscard]] std::optional<AdaptationDecision> latest_decision(const Harness& harness,
                                                               const AdaptivePolicyId& policy) {
  const std::vector<AdaptationDecision> decisions = harness.fabric->decisions_for_policy(policy, 4);
  if (decisions.empty()) {
    return std::nullopt;
  }
  return decisions.front();
}

[[nodiscard]] const ResolvedEvidence* resolved(const EvidenceSnapshotPtr& snapshot,
                                               const PathId& path, MetricKind kind) {
  ARF_CHECK_MSG(snapshot != nullptr, "expected an evidence snapshot");
  return snapshot == nullptr ? nullptr : snapshot->find(path, kind);
}

}  // namespace

ARF_TEST(evidence_for_an_unbound_path_is_unauthorized_scope) {
  Harness harness = make_harness();
  const PathId bound = path("path-a");
  const AdaptivePolicyId policy =
      policy_with_candidates(harness, latency_semantics(1000, 1000), {bound});
  const EvidenceGeneration before = harness.fabric->evidence_generation();
  const Watermark watermark_before = harness.fabric->evidence_watermark();

  // A publisher never injects samples for a path no policy in its authority
  // scope binds.
  const PathId unbound = path("path-z");
  const OperationResult rejected = publish_latency(harness, unbound, 100);
  ARF_CHECK_EQ(rejected.outcome, Outcome::UNAUTHORIZED_SCOPE);
  ARF_CHECK_MSG(rejected.detail.find(unbound.str()) != std::string::npos,
                "the rejection must name the unbound path: " << rejected.detail);
  ARF_CHECK(!rejected.mutated);
  ARF_CHECK_EQ(harness.fabric->evidence_generation(), before);
  ARF_CHECK_EQ(harness.fabric->evidence_watermark(), watermark_before);
  ARF_CHECK_EQ(harness.fabric->describe_evidence(policy).size(), static_cast<std::size_t>(0));
  ARF_CHECK_EQ(harness.fabric->stats().evidence_series, 0ULL);

  // The same publisher may publish for a bound path, so the rejection above is
  // about scope and not about publication in general.
  const OperationResult accepted = publish_latency(harness, bound, 100);
  ARF_CHECK_MSG(accepted.outcome == Outcome::POLICY_UPDATED, accepted.render());
  ARF_CHECK(accepted.mutated);
  ARF_CHECK_EQ(harness.fabric->evidence_generation().value(), before.value() + 1ULL);
  ARF_CHECK_EQ(harness.fabric->describe_evidence(policy).size(), static_cast<std::size_t>(1));
}

ARF_TEST(source_generation_regression_is_stale_evidence) {
  Harness harness = make_harness(retention_limits(4));
  const PathId a = path("path-a");
  const AdaptivePolicyId policy =
      policy_with_candidates(harness, latency_semantics(1000, 1000), {a});

  // Incarnation 2 is current, so a sample from incarnation 1 describes a source
  // that no longer exists.
  const OperationResult ahead =
      publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 100, 1,
                                         EvidenceQuality::AGGREGATED, 2)});
  ARF_CHECK_MSG(ahead.outcome == Outcome::POLICY_UPDATED, ahead.render());
  const EvidenceGeneration after_ahead = harness.fabric->evidence_generation();

  const OperationResult behind =
      publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 50, 2,
                                         EvidenceQuality::AGGREGATED, 1)});
  ARF_CHECK_EQ(behind.outcome, Outcome::STALE_EVIDENCE);
  ARF_CHECK(!behind.mutated);
  ARF_CHECK_EQ(harness.fabric->evidence_generation(), after_ahead);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_samples, 1ULL);

  // The same generation continues normally.
  const OperationResult continued =
      publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 60, 2,
                                         EvidenceQuality::AGGREGATED, 2)});
  ARF_CHECK_MSG(continued.outcome == Outcome::POLICY_UPDATED, continued.render());
  ARF_CHECK_EQ(harness.fabric->evidence_generation().value(), after_ahead.value() + 1ULL);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_samples, 2ULL);
  ARF_CHECK_EQ(harness.fabric->describe_evidence(policy).front().source_generation.value(), 2ULL);
}

ARF_TEST(forward_source_generation_replaces_the_retained_incarnation) {
  Harness harness = make_harness(retention_limits(4));
  const PathId a = path("path-a");
  const AdaptivePolicyId policy =
      policy_with_candidates(harness, latency_semantics(1000, 1000), {a});

  const Ticks first_stamp = harness.clock->now();
  ARF_CHECK_EQ(publish_latency(harness, a, 100, 1).outcome, Outcome::POLICY_UPDATED);
  harness.clock->advance(seconds(1));
  ARF_CHECK_EQ(publish_latency(harness, a, 200, 2).outcome, Outcome::POLICY_UPDATED);

  // Two samples of incarnation 1 are retained and aggregate together.
  const std::vector<EvidenceSeriesView> before = harness.fabric->describe_evidence(policy);
  ARF_REQUIRE(before.size() == static_cast<std::size_t>(1));
  ARF_CHECK_EQ(before.front().retained, 2U);
  ARF_CHECK_EQ(before.front().total_published, 2ULL);
  ARF_CHECK_EQ(before.front().oldest_accepted_at, first_stamp);
  ARF_CHECK_EQ(before.front().newest_accepted_at, first_stamp + seconds(1));
  ARF_CHECK_EQ(before.front().source_generation.value(), 1ULL);
  const EvidenceSnapshotPtr before_snapshot = harness.fabric->capture_evidence(policy);
  ARF_REQUIRE(before_snapshot != nullptr);
  const ResolvedEvidence* before_value = resolved(before_snapshot, a, MetricKind::PATH_LATENCY);
  ARF_REQUIRE(before_value != nullptr);
  ARF_CHECK_EQ(before_value->aggregate.sample_count, 2U);
  ARF_CHECK_EQ(before_value->aggregate.value.value(), 150);  // MEAN{100, 200}

  const Watermark watermark_before = harness.fabric->evidence_watermark();
  harness.clock->advance(seconds(1));
  const Ticks fresh_stamp = harness.clock->now();
  // A new incarnation invalidates the retained samples of the old one.
  const OperationResult replaced =
      publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 300, 3,
                                         EvidenceQuality::AGGREGATED, 2)});
  ARF_CHECK_MSG(replaced.outcome == Outcome::POLICY_UPDATED, replaced.render());

  const std::vector<EvidenceSeriesView> after = harness.fabric->describe_evidence(policy);
  ARF_REQUIRE(after.size() == static_cast<std::size_t>(1));
  ARF_CHECK_EQ(after.front().retained, 1U);
  ARF_CHECK_EQ(after.front().total_published, 3ULL);
  ARF_CHECK_EQ(after.front().source_generation.value(), 2ULL);
  ARF_CHECK_EQ(after.front().oldest_accepted_at, fresh_stamp);
  ARF_CHECK_EQ(after.front().newest_accepted_at, fresh_stamp);
  // The invalidation watermark advanced exactly once, which is what makes an
  // in-flight evaluation of the old incarnation unable to commit.
  ARF_CHECK_EQ(harness.fabric->evidence_watermark().value(), watermark_before.value() + 1ULL);

  // The aggregate covers the new incarnation only: no smoothing across a source
  // restart.
  const EvidenceSnapshotPtr after_snapshot = harness.fabric->capture_evidence(policy);
  const ResolvedEvidence* after_value = resolved(after_snapshot, a, MetricKind::PATH_LATENCY);
  ARF_REQUIRE(after_value != nullptr);
  ARF_CHECK_EQ(after_value->aggregate.sample_count, 1U);
  ARF_CHECK_EQ(after_value->aggregate.value.value(), 300);
  ARF_CHECK_EQ(after_value->source_generation.value(), 2ULL);

  // An ordinary publication inside the same incarnation leaves the watermark
  // alone.
  harness.clock->advance(seconds(1));
  // The publication must name the current incarnation, exactly as the source
  // itself does.
  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 400, 4,
                                                 EvidenceQuality::AGGREGATED, 2)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(harness.fabric->evidence_watermark().value(), watermark_before.value() + 1ULL);
  const std::vector<EvidenceSeriesView> grown = harness.fabric->describe_evidence(policy);
  ARF_REQUIRE(grown.size() == static_cast<std::size_t>(1));
  ARF_CHECK_EQ(grown.front().retained, 2U);
  ARF_CHECK_EQ(grown.front().total_published, 4ULL);
  ARF_CHECK_EQ(grown.front().oldest_accepted_at, fresh_stamp);
}

ARF_TEST(non_increasing_observation_sequence_is_stale_evidence) {
  Harness harness = make_harness(retention_limits(4));
  const PathId a = path("path-a");
  const AdaptivePolicyId policy =
      policy_with_candidates(harness, latency_semantics(1000, 1000), {a});

  ARF_CHECK_EQ(publish_latency(harness, a, 100, 5).outcome, Outcome::POLICY_UPDATED);
  const EvidenceGeneration after_first = harness.fabric->evidence_generation();

  // An observation index is a monotonic position in the source's stream: a
  // repeat carries no new information and a regression describes the past.
  const OperationResult repeated = publish_latency(harness, a, 110, 5);
  ARF_CHECK_EQ(repeated.outcome, Outcome::STALE_EVIDENCE);
  ARF_CHECK(!repeated.mutated);
  const OperationResult regressed = publish_latency(harness, a, 120, 4);
  ARF_CHECK_EQ(regressed.outcome, Outcome::STALE_EVIDENCE);
  ARF_CHECK_EQ(harness.fabric->evidence_generation(), after_first);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_samples, 1ULL);

  const OperationResult resumed = publish_latency(harness, a, 130, 6);
  ARF_CHECK_MSG(resumed.outcome == Outcome::POLICY_UPDATED, resumed.render());
  ARF_CHECK_EQ(harness.fabric->evidence_generation().value(), after_first.value() + 1ULL);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_samples, 2ULL);
  const std::vector<EvidenceSeriesView> views = harness.fabric->describe_evidence(policy);
  ARF_REQUIRE(views.size() == static_cast<std::size_t>(1));
  ARF_CHECK_EQ(views.front().retained, 2U);
  ARF_CHECK_EQ(views.front().total_published, 2ULL);
}

ARF_TEST(quality_change_within_one_source_generation_is_malformed) {
  Harness harness = make_harness(retention_limits(4));
  const PathId a = path("path-a");
  const AdaptivePolicyId policy =
      policy_with_candidates(harness, latency_semantics(1000, 1000), {a});

  ARF_CHECK_EQ(publish_latency(harness, a, 100, 1, EvidenceQuality::AGGREGATED).outcome,
               Outcome::POLICY_UPDATED);
  const EvidenceGeneration after_first = harness.fabric->evidence_generation();

  // Quality is a property of the source incarnation, so changing it inside one
  // generation is a malformed publication rather than a new fact.
  const OperationResult changed =
      publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 200, 2,
                                         EvidenceQuality::PRIMARY, 1)});
  ARF_CHECK_EQ(changed.outcome, Outcome::MALFORMED_REQUEST);
  ARF_CHECK(!changed.mutated);
  ARF_CHECK_EQ(harness.fabric->evidence_generation(), after_first);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_samples, 1ULL);

  // The declared quality continues to be accepted.
  ARF_CHECK_EQ(publish_latency(harness, a, 200, 2, EvidenceQuality::AGGREGATED).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(harness.fabric->describe_evidence(policy).front().quality,
               EvidenceQuality::AGGREGATED);

  // A new incarnation may declare a different quality: it is a different source.
  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 300, 3,
                                                 EvidenceQuality::PRIMARY, 2)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const std::vector<EvidenceSeriesView> views = harness.fabric->describe_evidence(policy);
  ARF_REQUIRE(views.size() == static_cast<std::size_t>(1));
  ARF_CHECK_EQ(views.front().quality, EvidenceQuality::PRIMARY);
  ARF_CHECK_EQ(views.front().source_generation.value(), 2ULL);
}

ARF_TEST(retention_is_bounded_and_drops_the_oldest_samples) {
  const std::uint64_t capacity = 3;
  Harness harness = make_harness(retention_limits(capacity));
  const PathId a = path("path-a");
  const AdaptivePolicyId policy =
      policy_with_candidates(harness, latency_semantics(1000, 1000), {a});

  std::vector<Ticks> stamps;
  for (std::uint64_t index = 0; index < capacity + 2; ++index) {
    stamps.push_back(harness.clock->now());
    const std::int64_t value = 10 * static_cast<std::int64_t>(index + 1);
    ARF_CHECK_EQ(publish_latency(harness, a, value, index + 1).outcome,
                 Outcome::POLICY_UPDATED);
    harness.clock->advance(seconds(1));
  }

  const std::vector<EvidenceSeriesView> views = harness.fabric->describe_evidence(policy);
  ARF_REQUIRE(views.size() == static_cast<std::size_t>(1));
  // Every sample was accepted and recorded, but only the newest three are kept.
  ARF_CHECK_EQ(views.front().total_published, capacity + 2);
  ARF_CHECK_EQ(views.front().retained, capacity);
  ARF_CHECK_EQ(views.front().oldest_accepted_at, stamps[2]);
  ARF_CHECK_EQ(views.front().newest_accepted_at, stamps[4]);
  ARF_CHECK(views.front().oldest_accepted_at < views.front().newest_accepted_at);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_samples, capacity);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_series, 1ULL);

  // The aggregate is computed from the retained window, which is 30, 40 and 50.
  const EvidenceSnapshotPtr snapshot = harness.fabric->capture_evidence(policy);
  const ResolvedEvidence* value = resolved(snapshot, a, MetricKind::PATH_LATENCY);
  ARF_REQUIRE(value != nullptr);
  ARF_CHECK_EQ(value->aggregate.sample_count, static_cast<std::uint32_t>(capacity));
  ARF_CHECK_EQ(value->aggregate.value.value(), 40);
  ARF_CHECK_EQ(value->aggregate.oldest_observed_at, stamps[2]);
  ARF_CHECK_EQ(value->aggregate.newest_observed_at, stamps[4]);
  ARF_CHECK_EQ(value->aggregate.window(), stamps[4] - stamps[2]);
}

ARF_TEST(stale_evidence_blocks_adaptation_and_names_the_reason) {
  Harness harness = make_harness();
  // The band shape leaves the current preference above 8000 utilisation and
  // enters a candidate below 2000; its freshness bound is 120 seconds.
  const TwoCandidate fixture =
      make_two_candidate_policy(harness, utilization_semantics(8000, 2000));
  const PathId a = fixture.a;
  const PathId b = fixture.b;

  ARF_CHECK_EQ(publish_utilization(harness, a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish_utilization(harness, b, 9000, 1).outcome, Outcome::POLICY_UPDATED);
  const OperationResult established = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(established.outcome == Outcome::DECISION_COMMITTED, established.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), a);

  // B becomes the better candidate, but every sample for A is now older than
  // the declared maximum age.
  harness.clock->advance(seconds(121));
  ARF_CHECK_EQ(publish_utilization(harness, b, 500, 2).outcome, Outcome::POLICY_UPDATED);

  const OperationResult blocked = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(blocked.outcome, Outcome::STALE_EVIDENCE);
  ARF_CHECK_EQ(blocked.suppression, SuppressionReason::STALE_EVIDENCE);
  ARF_CHECK(!blocked.mutated);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), a);
  ARF_CHECK_EQ(harness.fabric->stats().decisions_committed, 1ULL);

  // The recorded decision carries the per candidate reason, so an operator sees
  // which dependency was stale rather than only that nothing happened.
  const std::optional<AdaptationDecision> recorded = latest_decision(harness, fixture.policy);
  ARF_REQUIRE(recorded.has_value());
  ARF_CHECK_EQ(recorded->outcome, Outcome::STALE_EVIDENCE);
  ARF_CHECK_EQ(recorded->suppression, SuppressionReason::STALE_EVIDENCE);
  ARF_CHECK_EQ(recorded->lifecycle, DecisionLifecycle::SUPPRESSED);
  const CandidateEvaluation* a_entry = find_ranking(*recorded, a);
  const CandidateEvaluation* b_entry = find_ranking(*recorded, b);
  ARF_REQUIRE(a_entry != nullptr);
  ARF_REQUIRE(b_entry != nullptr);
  ARF_CHECK_EQ(a_entry->eligible, false);
  ARF_CHECK_EQ(a_entry->rejection, SuppressionReason::STALE_EVIDENCE);
  ARF_CHECK_EQ(a_entry->rejection_outcome, Outcome::STALE_EVIDENCE);
  ARF_CHECK_EQ(b_entry->eligible, true);
  ARF_CHECK_EQ(b_entry->rejection, SuppressionReason::NONE);
  ARF_CHECK_EQ(b_entry->current_preference, false);

  // Fresh evidence for the current preference makes the same move succeed, so
  // the refusal above was about freshness and not about the policy.
  ARF_CHECK_EQ(publish_utilization(harness, a, 9000, 2).outcome, Outcome::POLICY_UPDATED);
  const OperationResult adapted = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(adapted.outcome == Outcome::DECISION_COMMITTED, adapted.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), b);
  ARF_CHECK_EQ(harness.fabric->stats().decisions_committed, 2ULL);
}

ARF_TEST(min_samples_is_honoured) {
  Harness harness = make_harness(retention_limits(4));
  PolicySemantics semantics = latency_semantics(1000, 1000);
  semantics.evidence.front().min_samples = 2;
  const TwoCandidate fixture = make_two_candidate_policy(harness, semantics);
  const PathId a = fixture.a;
  const PathId b = fixture.b;

  // One sample per candidate is not the two the policy declared.
  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 100, 1,
                                                 EvidenceQuality::AGGREGATED),
                                 make_publication(b, MetricKind::PATH_LATENCY, 1000, 1,
                                                 EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult insufficient = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(insufficient.outcome, Outcome::NO_ELIGIBLE_CANDIDATE);
  ARF_CHECK(!insufficient.mutated);
  ARF_CHECK_EQ(harness.fabric->stats().decisions_committed, 0ULL);
  const std::optional<AdaptationDecision> blocked = latest_decision(harness, fixture.policy);
  ARF_REQUIRE(blocked.has_value());
  for (const PathId& candidate : {a, b}) {
    const CandidateEvaluation* entry = find_ranking(*blocked, candidate);
    ARF_REQUIRE(entry != nullptr);
    ARF_CHECK_EQ(entry->eligible, false);
    ARF_CHECK_EQ(entry->rejection, SuppressionReason::INSUFFICIENT_SAMPLES);
    ARF_CHECK_EQ(entry->rejection_outcome, Outcome::INSUFFICIENT_EVIDENCE);
  }

  // The second sample per candidate satisfies the declaration, and the same
  // evaluation then commits the initial preference.
  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 100, 2,
                                                 EvidenceQuality::AGGREGATED),
                                 make_publication(b, MetricKind::PATH_LATENCY, 1000, 2,
                                                 EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult decided = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(decided.outcome == Outcome::DECISION_COMMITTED, decided.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), a);
  ARF_CHECK_EQ(harness.fabric->stats().decisions_committed, 1ULL);
}

ARF_TEST(min_window_is_honoured) {
  Harness harness = make_harness(retention_limits(4));
  PolicySemantics semantics = latency_semantics(1000, 1000);
  semantics.evidence.front().min_window = seconds(10);
  const TwoCandidate fixture = make_two_candidate_policy(harness, semantics);
  const PathId a = fixture.a;
  const PathId b = fixture.b;

  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 100, 1,
                                                 EvidenceQuality::AGGREGATED),
                                 make_publication(b, MetricKind::PATH_LATENCY, 1000, 1,
                                                 EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  // Two samples one second apart cover a one second observation window.
  harness.clock->advance(seconds(1));
  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 100, 2,
                                                 EvidenceQuality::AGGREGATED),
                                 make_publication(b, MetricKind::PATH_LATENCY, 1000, 2,
                                                 EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult narrow = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_EQ(narrow.outcome, Outcome::NO_ELIGIBLE_CANDIDATE);
  ARF_CHECK_EQ(harness.fabric->stats().decisions_committed, 0ULL);
  const std::optional<AdaptationDecision> blocked = latest_decision(harness, fixture.policy);
  ARF_REQUIRE(blocked.has_value());
  const CandidateEvaluation* narrow_entry = find_ranking(*blocked, a);
  ARF_REQUIRE(narrow_entry != nullptr);
  ARF_CHECK_EQ(narrow_entry->eligible, false);
  ARF_CHECK_EQ(narrow_entry->rejection, SuppressionReason::INSUFFICIENT_SAMPLES);
  ARF_CHECK_EQ(narrow_entry->rejection_outcome, Outcome::INSUFFICIENT_EVIDENCE);

  // A third sample ten seconds later spans eleven seconds, which clears the
  // declared minimum.
  harness.clock->advance(seconds(10));
  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 100, 3,
                                                 EvidenceQuality::AGGREGATED),
                                 make_publication(b, MetricKind::PATH_LATENCY, 1000, 3,
                                                 EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const OperationResult wide = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(wide.outcome == Outcome::DECISION_COMMITTED, wide.render());
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), a);
  ARF_CHECK_EQ(harness.fabric->stats().decisions_committed, 1ULL);
}

ARF_TEST(missing_required_metric_fails_closed_and_an_optional_one_does_not) {
  const PathId a = path("path-a");
  const PathId b = path("path-b");

  // A required metric with no declared evidence blocks every candidate: the
  // runtime fails closed rather than deciding from partial data.
  Harness strict = make_harness();
  PolicySemantics strict_semantics = latency_semantics(1000, 1000);
  strict_semantics.evidence.push_back(utilization_requirement());
  const AdaptivePolicyId strict_policy =
      policy_with_candidates(strict, strict_semantics, {a, b});
  ARF_CHECK_EQ(publish_latency(strict, a, 100, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish_latency(strict, b, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  const OperationResult closed = evaluate_policy(strict, strict_policy);
  ARF_CHECK_EQ(closed.outcome, Outcome::NO_ELIGIBLE_CANDIDATE);
  ARF_CHECK(!closed.mutated);
  ARF_CHECK_EQ(strict.fabric->stats().decisions_committed, 0ULL);
  ARF_CHECK_EQ(preferred_path(strict, strict_policy), PathId());
  const std::optional<AdaptationDecision> refused = latest_decision(strict, strict_policy);
  ARF_REQUIRE(refused.has_value());
  for (const PathId& candidate : {a, b}) {
    const CandidateEvaluation* entry = find_ranking(*refused, candidate);
    ARF_REQUIRE(entry != nullptr);
    ARF_CHECK_EQ(entry->eligible, false);
    ARF_CHECK_EQ(entry->rejection, SuppressionReason::EVIDENCE_UNKNOWN);
    ARF_CHECK_EQ(entry->rejection_outcome, Outcome::INSUFFICIENT_EVIDENCE);
  }

  // The identical shape with the same metric declared optional adapts, because
  // an absent optional metric is used when present and never blocks.
  Harness relaxed = make_harness();
  PolicySemantics relaxed_semantics = latency_semantics(1000, 1000);
  EvidenceRequirement optional = utilization_requirement();
  optional.required = false;
  relaxed_semantics.evidence.push_back(optional);
  const AdaptivePolicyId relaxed_policy =
      policy_with_candidates(relaxed, relaxed_semantics, {a, b});
  ARF_CHECK_EQ(publish_latency(relaxed, a, 100, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish_latency(relaxed, b, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  const OperationResult adapted = evaluate_policy(relaxed, relaxed_policy);
  ARF_CHECK_MSG(adapted.outcome == Outcome::DECISION_COMMITTED, adapted.render());
  ARF_CHECK_EQ(preferred_path(relaxed, relaxed_policy), a);
  ARF_CHECK_EQ(relaxed.fabric->stats().decisions_committed, 1ULL);
}

ARF_TEST(evidence_generation_advances_once_per_accepted_batch) {
  Harness harness = make_harness(retention_limits(4));
  const PathId a = path("path-a");
  const PathId b = path("path-b");
  const AdaptivePolicyId policy =
      policy_with_candidates(harness, latency_semantics(1000, 1000), {a, b});

  const EvidenceGeneration initial = harness.fabric->evidence_generation();
  ARF_CHECK_EQ(initial.value(), 1ULL);
  // A batch of two samples is one accepted publication.
  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 100, 1,
                                                 EvidenceQuality::AGGREGATED),
                                 make_publication(b, MetricKind::PATH_LATENCY, 1000, 1,
                                                 EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(harness.fabric->evidence_generation().value(), initial.value() + 1ULL);
  ARF_CHECK_EQ(publish_latency(harness, a, 110, 2).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(harness.fabric->evidence_generation().value(), initial.value() + 2ULL);

  // A rejected batch never advances it, whatever the rejection is.
  ARF_CHECK_EQ(publish_latency(harness, path("path-z"), 100).outcome,
               Outcome::UNAUTHORIZED_SCOPE);
  ARF_CHECK_EQ(publish_latency(harness, a, 120, 2).outcome, Outcome::STALE_EVIDENCE);
  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 130, 3,
                                                 EvidenceQuality::PRIMARY)})
                   .outcome,
               Outcome::MALFORMED_REQUEST);
  ARF_CHECK_EQ(publish(harness, {}).outcome, Outcome::MALFORMED_REQUEST);
  ARF_CHECK_EQ(harness.fabric->evidence_generation().value(), initial.value() + 2ULL);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_generation.value(), initial.value() + 2ULL);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_samples, 3ULL);
  ARF_CHECK_EQ(harness.fabric->describe_evidence(policy).size(), static_cast<std::size_t>(2));
}

ARF_TEST(evidence_snapshot_is_immutable) {
  Harness harness = make_harness(retention_limits(4));
  const PathId a = path("path-a");
  const PathId b = path("path-b");
  const AdaptivePolicyId policy =
      policy_with_candidates(harness, latency_semantics(1000, 1000), {a, b});

  ARF_CHECK_EQ(publish(harness, {make_publication(a, MetricKind::PATH_LATENCY, 100, 1,
                                                 EvidenceQuality::AGGREGATED),
                                 make_publication(b, MetricKind::PATH_LATENCY, 1000, 1,
                                                 EvidenceQuality::AGGREGATED)})
                   .outcome,
               Outcome::POLICY_UPDATED);
  const Ticks captured_at = harness.clock->now();
  const EvidenceSnapshotPtr first = harness.fabric->capture_evidence(policy);
  ARF_REQUIRE(first != nullptr);
  const ResolvedEvidence* first_a = resolved(first, a, MetricKind::PATH_LATENCY);
  ARF_REQUIRE(first_a != nullptr);
  ARF_CHECK_EQ(first_a->aggregate.sample_count, 1U);
  ARF_CHECK_EQ(first_a->aggregate.value.value(), 100);
  ARF_CHECK_EQ(first_a->source_generation.value(), 1ULL);
  ARF_CHECK_EQ(first->captured_at(), captured_at);
  ARF_CHECK_EQ(first->epoch(), harness.fabric->epoch());
  ARF_CHECK_EQ(first->values().size(), static_cast<std::size_t>(2));
  ARF_CHECK_EQ(first->bindings().size(), static_cast<std::size_t>(2));
  ARF_CHECK(first->find(path("path-z"), MetricKind::PATH_LATENCY) == nullptr);
  ARF_CHECK(first->find(a, MetricKind::PATH_UTILIZATION) == nullptr);
  const EvidenceGeneration first_generation = first->generation();

  // Publishing more evidence for the same path does not rewrite the snapshot a
  // slow evaluation is still reading.
  ARF_CHECK_EQ(publish_latency(harness, a, 300, 2).outcome, Outcome::POLICY_UPDATED);
  const EvidenceSnapshotPtr second = harness.fabric->capture_evidence(policy);
  ARF_REQUIRE(second != nullptr);
  ARF_CHECK(second.get() != first.get());
  ARF_CHECK(first->id() != second->id());
  ARF_CHECK(first_generation < second->generation());

  const ResolvedEvidence* first_a_again = resolved(first, a, MetricKind::PATH_LATENCY);
  ARF_REQUIRE(first_a_again != nullptr);
  ARF_CHECK_EQ(first_a_again->aggregate.value.value(), 100);
  ARF_CHECK_EQ(first_a_again->aggregate.sample_count, 1U);
  ARF_CHECK_EQ(first->generation(), first_generation);

  const ResolvedEvidence* second_a = resolved(second, a, MetricKind::PATH_LATENCY);
  ARF_REQUIRE(second_a != nullptr);
  ARF_CHECK_EQ(second_a->aggregate.value.value(), 200);  // MEAN{100, 300}
  ARF_CHECK_EQ(second_a->aggregate.sample_count, 2U);
  const ResolvedEvidence* second_b = resolved(second, b, MetricKind::PATH_LATENCY);
  ARF_REQUIRE(second_b != nullptr);
  ARF_CHECK_EQ(second_b->aggregate.value.value(), 1000);
  // The snapshots of a policy that does not exist is empty rather than a crash.
  ARF_CHECK(harness.fabric->capture_evidence(AdaptivePolicyId()) == nullptr);
}

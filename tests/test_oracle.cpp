// Independent decision oracle.
//
// The oracle re-derives the expected outcome from the raw inputs with its own
// arithmetic. It deliberately shares no production helper: no MetricValue, no
// relative_improvement_bps, no ranking comparator. If the oracle and the engine
// agree, they agree for independent reasons.
#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace arf_test;

struct OracleCandidate {
  PathId path;
  bool legal = true;
  bool available = true;
  bool route_current = true;
  std::optional<std::int64_t> latency;
};

struct OracleExpectation {
  std::optional<PathId> preferred;
  Outcome outcome = Outcome::NO_CHANGE;
  SuppressionReason suppression = SuppressionReason::NONE;
  std::uint32_t required_bps = 0;
};

// Floor-rounded relative improvement of candidate over current, in basis
// points, for a lower-is-better metric, written from first principles.
std::uint32_t oracle_improvement(std::int64_t current, std::int64_t candidate) {
  if (candidate >= current) {
    return 0;
  }
  if (current == 0) {
    return 10000;
  }
  const std::int64_t delta = current - candidate;
  return static_cast<std::uint32_t>((delta * 10000) / current);
}

OracleExpectation oracle_decide(const std::vector<OracleCandidate>& candidates,
                                const std::optional<PathId>& current,
                                const std::optional<PathId>& previous, std::uint32_t switch_bps,
                                std::uint32_t reverse_bps) {
  OracleExpectation expectation;
  std::vector<const OracleCandidate*> eligible;
  for (const auto& candidate : candidates) {
    if (candidate.legal && candidate.available && candidate.route_current &&
        candidate.latency.has_value()) {
      eligible.push_back(&candidate);
    }
  }
  if (eligible.empty()) {
    expectation.outcome = Outcome::NO_ELIGIBLE_CANDIDATE;
    expectation.suppression = SuppressionReason::NO_ELIGIBLE_ALTERNATIVE;
    return expectation;
  }
  // Deterministic order: best latency, then canonical path order.
  std::sort(eligible.begin(), eligible.end(),
            [](const OracleCandidate* a, const OracleCandidate* b) {
              if (*a->latency != *b->latency) {
                return *a->latency < *b->latency;
              }
              return a->path < b->path;
            });
  const PathId best = eligible.front()->path;
  if (!current.has_value()) {
    expectation.preferred = best;
    expectation.outcome = Outcome::DECISION_COMMITTED;
    return expectation;
  }
  if (best == *current) {
    expectation.preferred = *current;
    expectation.outcome = Outcome::NO_CHANGE;
    expectation.suppression = SuppressionReason::MERIT_NOT_ESTABLISHED;
    return expectation;
  }
  const OracleCandidate* current_candidate = nullptr;
  for (const auto& candidate : candidates) {
    if (candidate.path == *current) {
      current_candidate = &candidate;
    }
  }
  if (current_candidate == nullptr || !current_candidate->legal ||
      !current_candidate->route_current || !current_candidate->available ||
      !current_candidate->latency.has_value()) {
    expectation.preferred = *current;
    expectation.outcome = Outcome::REVALIDATION_REQUIRED;
    expectation.suppression = SuppressionReason::CURRENT_PREFERENCE_INELIGIBLE;
    return expectation;
  }
  const bool reverse = previous.has_value() && *previous == best;
  const std::uint32_t required = reverse ? reverse_bps : switch_bps;
  expectation.required_bps = required;
  const std::uint32_t observed =
      oracle_improvement(*current_candidate->latency, *eligible.front()->latency);
  if (observed < required) {
    expectation.preferred = *current;
    expectation.outcome = reverse ? Outcome::HYSTERESIS_NOT_CLEARED : Outcome::NO_CHANGE;
    expectation.suppression =
        reverse ? SuppressionReason::HYSTERESIS_NOT_CLEARED : SuppressionReason::BELOW_THRESHOLD;
    return expectation;
  }
  expectation.preferred = best;
  expectation.outcome = Outcome::DECISION_COMMITTED;
  return expectation;
}

}  // namespace

// Randomized small-case agreement between the engine and the independent oracle.
ARF_TEST(oracle_agrees_on_randomized_small_cases) {
  constexpr std::uint64_t case_count = 60;
  for (std::uint64_t seed = 1; seed <= case_count; ++seed) {
    Random random(seed * 2654435761ULL + 12345ULL);
    Harness harness = make_harness();
    // A rule that requires nothing in either direction is not a trigger, so the
    // switch requirement is never zero.
    const std::uint32_t switch_bps =
        static_cast<std::uint32_t>(500 + random.below(4) * 500);  // 500, 1000, 1500, 2000
    const std::uint32_t reverse_bps = static_cast<std::uint32_t>(random.below(5) * 500);
    const TwoCandidate fixture =
        make_two_candidate_policy(harness, latency_semantics(switch_bps, reverse_bps));

    std::vector<OracleCandidate> oracle_candidates;
    OracleCandidate first;
    first.path = fixture.a;
    OracleCandidate second;
    second.path = fixture.b;
    oracle_candidates.push_back(first);
    oracle_candidates.push_back(second);
    // Both candidates are declared up front; the schedule then only varies
    // legality, which is the axis the oracle models.
    for (const auto& candidate : oracle_candidates) {
      const OperationResult declared = declare_candidate(harness, fixture.policy,
                                                         make_binding(candidate.path, 1));
      ARF_CHECK_MSG(declared.outcome == Outcome::POLICY_UPDATED,
                    declared.render() + " seed=" + std::to_string(seed));
    }

    std::optional<PathId> current;
    std::optional<PathId> previous;
    std::uint64_t sequence = 1;
    for (std::uint32_t round = 0; round < 6; ++round) {
      std::vector<EvidencePublication> publications;
      for (auto& candidate : oracle_candidates) {
        if (random.below(4) == 0) {
          // No new sample this round. The runtime keeps the reading it already
          // holds, so the oracle keeps it too; only a candidate that has never
          // reported anything is treated as unknown.
          continue;
        }
        const std::int64_t latency = random.between(200, 2000);
        candidate.latency = latency;
        candidate.legal = random.below(8) != 0;
        // Availability and route currency are held constant so that the oracle
        // and the engine agree on a single varying axis.
        candidate.available = true;
        candidate.route_current = true;
        publications.push_back(make_publication(candidate.path, MetricKind::PATH_LATENCY, latency,
                                                sequence++, EvidenceQuality::AGGREGATED));
      }
      if (!publications.empty()) {
        const OperationResult published = publish(harness, publications);
        ARF_CHECK_MSG(published.outcome == Outcome::POLICY_UPDATED,
                      published.render() + " seed=" + std::to_string(seed));
      }
      // Upstream legality is applied through the documented notification
      // surface, one notification per candidate so the engine sees exactly what
      // the oracle assumes.
      for (const auto& candidate : oracle_candidates) {
        // Legality is re-stated every round so that a path can be restored as
        // well as withdrawn.
        const OperationResult restated =
            notify(harness, [&]() {
              UpstreamNotification notification;
              notification.event = UpstreamEvent::DECLARE_CANDIDATE;
              notification.policy = fixture.policy;
              notification.binding = make_binding(candidate.path, 1, 1, candidate.legal);
              notification.provenance.publisher = harness.publisher;
              notification.provenance.worker_boot = harness.worker_boot;
              notification.provenance.epoch = harness.fabric->epoch();
              notification.provenance.origin = "oracle";
              return notification;
            }());
        ARF_CHECK_MSG(restated.outcome == Outcome::POLICY_UPDATED,
                      restated.render() + " seed=" + std::to_string(seed));
      }

      const OracleExpectation expectation = oracle_decide(
          oracle_candidates, current, previous, switch_bps, reverse_bps);
      const OperationResult actual = evaluate_policy(harness, fixture.policy);
      const PathId actual_preferred = preferred_path(harness, fixture.policy);
      const std::string context =
          " seed=" + std::to_string(seed) + " round=" + std::to_string(round) +
          " engine=" + actual.render();
      ARF_CHECK_MSG(actual.outcome == expectation.outcome, context);
      if (expectation.suppression != SuppressionReason::NONE) {
        ARF_CHECK_MSG(actual.suppression == expectation.suppression, context);
      }
      if (expectation.preferred.has_value()) {
        ARF_CHECK_MSG(actual_preferred == *expectation.preferred, context);
      }
      if (actual.outcome == Outcome::DECISION_COMMITTED) {
        previous = current;
        current = actual_preferred;
      }
    }
  }
}

// The oracle also pins the two boundary values of the relative improvement
// arithmetic, which are the values a hysteresis defect would move.
ARF_TEST(oracle_boundary_improvements) {
  ARF_CHECK_EQ(oracle_improvement(1000, 800), 2000U);
  ARF_CHECK_EQ(oracle_improvement(1000, 1000), 0U);
  ARF_CHECK_EQ(oracle_improvement(1000, 1200), 0U);
  // Every modelled metric is non-negative and lower-is-better here, so a
  // candidate of 5 against a current value of 0 is not an improvement at all.
  ARF_CHECK_EQ(oracle_improvement(0, 5), 0U);
  ARF_CHECK_EQ(oracle_improvement(0, 0), 0U);
  ARF_CHECK_EQ(oracle_improvement(3, 2), 3333U);

  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 2000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  // 2000 bps exactly meets the requirement and must commit.
  feed_latency(harness, fixture.a, 1000, fixture.b, 800, 2);
  const OperationResult exact = evaluate_policy(harness, fixture.policy);
  ARF_CHECK_MSG(exact.outcome == Outcome::DECISION_COMMITTED, exact.render());
  const AdaptationDecision decision = *harness.fabric->find_decision(exact.decision);
  ARF_CHECK(decision.improvement_bps.has_value());
  ARF_CHECK_EQ(*decision.improvement_bps, 2000U);
  ARF_CHECK_EQ(decision.required_improvement_bps, 2000U);

  // One microsecond short of the requirement must not.
  Harness second = make_harness();
  const TwoCandidate other = make_two_candidate_policy(second, latency_semantics(2000, 2000));
  ARF_CHECK_EQ(publish_latency(second, other.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(second, other.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(second, other.a, 1000, other.b, 801, 2);
  ARF_CHECK_EQ(evaluate_policy(second, other.policy).outcome, Outcome::NO_CHANGE);
}

// Example: an 80%/65% utilization band with explicit hysteresis.
//
// The policy declares the band shape on PATH_UTILIZATION: the current preference
// may be left only at or above 80% utilization (switch_value = 8000 bps) and a
// candidate may be entered only at or below 65% (clear_value = 6500 bps). The
// gap between the two is what stops a path sitting near a single threshold from
// flapping. Both halves are exercised, including the refusal in the middle.
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

using namespace arf_example;

int main() {
  Report report("example_utilization_hysteresis: an 80%/65% band gates the move");
  Fixture fixture;
  report.expect_outcome(register_default_publisher(fixture), Outcome::POLICY_UPDATED,
                        "publisher is registered for the current epoch");

  const PolicyCreation creation =
      create_active_policy(fixture, utilization_semantics(8000, 6500));
  report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
  report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");

  const PathId a = path("path-a");
  const PathId b = path("path-b");
  report.expect_outcome(declare_candidate(fixture, creation.policy, a), Outcome::POLICY_UPDATED,
                        "path-a is declared as a candidate");
  report.expect_outcome(declare_candidate(fixture, creation.policy, b), Outcome::POLICY_UPDATED,
                        "path-b is declared as a candidate");

  // path-a is idle, so it clears the entry band and becomes the initial
  // preference.
  report.expect_outcome(publish_utilization(fixture, a, 3000), Outcome::POLICY_UPDATED,
                        "path-a reports 3000 bps of utilization");
  report.expect_outcome(evaluate_policy(fixture, creation.policy), Outcome::DECISION_COMMITTED,
                        "the initial preference is established");
  const PathId established = preferred_path(fixture, creation.policy);
  report.expect(established == a, "path-a is the preferred path", render_path(established));

  // path-b is objectively the better candidate at 2000 bps, but path-a at 3000
  // has not crossed the 8000 departure threshold, so the current preference may
  // not be left. The objective ranks candidates; the band decides whether the
  // preferred path may be abandoned at all.
  report.expect_outcome(publish_utilization(fixture, b, 2000), Outcome::POLICY_UPDATED,
                        "path-b reports 2000 bps of utilization");
  const OperationResult below = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(below, Outcome::NO_CHANGE,
                        "the current preference is below the departure threshold");
  report.expect(below.suppression == SuppressionReason::BELOW_THRESHOLD,
                "the suppression reason names the departure threshold",
                to_string(below.suppression));

  // path-a crosses the departure threshold, so leaving is now permitted. path-b
  // at 7000 is better than path-a but still sits inside the band: it has not
  // cleared 6500, so it may not be entered. This is the hysteresis refusal.
  report.expect_outcome(publish_utilization(fixture, a, 8200, 2, 2), Outcome::POLICY_UPDATED,
                        "path-a reports 8200 bps of utilization under a refreshed source");
  report.expect_outcome(publish_utilization(fixture, b, 7000, 2, 2), Outcome::POLICY_UPDATED,
                        "path-b reports 7000 bps of utilization under a refreshed source");
  const OperationResult band = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(band, Outcome::HYSTERESIS_NOT_CLEARED,
                        "path-b at 7000 is refused by the hysteresis band");
  report.expect(band.suppression == SuppressionReason::HYSTERESIS_NOT_CLEARED,
                "the suppression reason names the uncleared band", to_string(band.suppression));
  const PathId still_a = preferred_path(fixture, creation.policy);
  report.expect(still_a == a, "the refused candidate did not take over", render_path(still_a));

  // path-b clears the band, and only now is the departure threshold honoured.
  report.expect_outcome(publish_utilization(fixture, b, 6000, 3, 3), Outcome::POLICY_UPDATED,
                        "path-b reports 6000 bps of utilization under a refreshed source");
  report.expect_outcome(evaluate_policy(fixture, creation.policy), Outcome::DECISION_COMMITTED,
                        "path-b at 6000 is accepted");
  const AdaptationSnapshot after = snapshot_of(fixture, creation.policy);
  report.expect(after.preference.preferred_path == b, "path-b is the preferred path",
                render_path(after.preference.preferred_path));
  report.expect(fixture.fabric->stats().decisions_committed == 2,
                "only the two admissible adaptations were committed",
                std::to_string(fixture.fabric->stats().decisions_committed));

  report.note("7000 bps is better than 8200 but worse than the 6500 bps entry band");
  return report.finish();
}

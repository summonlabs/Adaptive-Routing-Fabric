// Example: hold-down suppresses the reverse adaptation and then releases it.
//
// After a committed move A -> B the policy's hold-down is armed. Evidence then
// favours A again. The reverse move is suppressed with HOLD_DOWN_ACTIVE and no
// generation advances, even though the evidence would otherwise be sufficient.
// Advancing the injected TestClock past the hold-down deadline releases exactly
// the same evidence, which proves the suppression was the interval and not the
// measurement.
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

using namespace arf_example;

int main() {
  Report report("example_hold_down_suppression: the reverse move waits out hold-down");
  Fixture fixture;
  report.expect_outcome(register_default_publisher(fixture), Outcome::POLICY_UPDATED,
                        "publisher is registered for the current epoch");

  const PolicyCreation creation =
      create_active_policy(fixture, latency_semantics(2000, 2000, seconds(5)));
  report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
  report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");

  const PathId a = path("path-a");
  const PathId b = path("path-b");
  report.expect_outcome(declare_candidate(fixture, creation.policy, a), Outcome::POLICY_UPDATED,
                        "path-a is declared as a candidate");
  report.expect_outcome(declare_candidate(fixture, creation.policy, b), Outcome::POLICY_UPDATED,
                        "path-b is declared as a candidate");

  report.expect_outcome(publish_latency(fixture, a, 1000), Outcome::POLICY_UPDATED,
                        "path-a reports 1000us");
  report.expect_outcome(evaluate_policy(fixture, creation.policy), Outcome::DECISION_COMMITTED,
                        "the initial preference is established on path-a");
  report.expect_outcome(publish_latency(fixture, b, 800), Outcome::POLICY_UPDATED,
                        "path-b reports 800us");
  report.expect_outcome(evaluate_policy(fixture, creation.policy), Outcome::DECISION_COMMITTED,
                        "path-b takes over and arms hold-down");

  const AdaptationSnapshot committed = snapshot_of(fixture, creation.policy);
  report.expect(committed.preference.preferred_path == b, "path-b is the preferred path",
                render_path(committed.preference.preferred_path));
  report.expect(committed.hold_down_active, "hold-down is active after the commit",
                render_ticks(committed.hold_down_remaining) + " remaining");
  const AdaptationGeneration armed = committed.preference.adaptation_generation;

  // A corrected reading for path-a arrives under a fresh source incarnation:
  // 400us is 5000 bps better than path-b's 800us, comfortably above the 2000 bps
  // reverse requirement.
  report.expect_outcome(publish_latency(fixture, a, 400, 2, 2), Outcome::POLICY_UPDATED,
                        "path-a now reports 400us");
  const OperationResult suppressed = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(suppressed, Outcome::HOLD_DOWN_ACTIVE,
                        "the reverse move is suppressed while hold-down runs");
  report.expect(suppressed.suppression == SuppressionReason::HOLD_DOWN_ACTIVE,
                "the suppression reason names hold-down", to_string(suppressed.suppression));

  const AdaptationSnapshot during = snapshot_of(fixture, creation.policy);
  report.expect(during.preference.preferred_path == b, "the preference did not move",
                render_path(during.preference.preferred_path));
  report.expect(during.preference.adaptation_generation == armed,
                "no adaptation generation advanced",
                std::to_string(during.preference.adaptation_generation.value()));

  // Time is now driven past the deadline. No sleep is involved: the injected
  // clock is the only source of elapsed time the runtime consults.
  fixture.clock->advance(seconds(5) + 1);
  const OperationResult released = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(released, Outcome::DECISION_COMMITTED,
                        "the same evidence commits once hold-down has elapsed");
  const AdaptationSnapshot after = snapshot_of(fixture, creation.policy);
  report.expect(after.preference.preferred_path == a, "path-a is the preferred path again",
                render_path(after.preference.preferred_path));
  report.expect(after.preference.adaptation_generation.value() > armed.value(),
                "the adaptation generation advanced with the released move",
                std::to_string(after.preference.adaptation_generation.value()));
  report.expect(after.hold_down_active && after.hold_down_remaining > 0,
                "hold-down is re-armed by the released commit",
                render_ticks(after.hold_down_remaining) + " remaining");

  report.note("the clock advanced by 5s + 1 tick; the runtime never slept and never read a wall "
              "clock");
  return report.finish();
}

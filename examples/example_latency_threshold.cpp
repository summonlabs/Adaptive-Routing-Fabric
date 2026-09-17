// Example: the explicit relative improvement rule moves the preference A -> B.
//
// A policy declares the relative-improvement shape on PATH_LATENCY: a challenger
// must beat the current preference by at least 2000 basis points (20%) before
// the runtime commits a move. The example drives A = 1000us and B = 800us
// through the public evaluation surface and asserts that the commit happens
// exactly at the declared boundary: B is 2000 bps better, which is neither
// rounded up nor compared as a floating point ratio.
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

using namespace arf_example;

int main() {
  Report report("example_latency_threshold: a 20% relative improvement commits A -> B");
  Fixture fixture;
  report.expect_outcome(register_default_publisher(fixture), Outcome::POLICY_UPDATED,
                        "publisher is registered for the current epoch");

  // 20% to take over, 40% to come back. The asymmetric reverse requirement is
  // what makes the move back strictly harder than the move out.
  const PolicyCreation creation = create_active_policy(fixture, latency_semantics(2000, 4000));
  report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
  report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");

  const PathId a = path("path-a");
  const PathId b = path("path-b");
  report.expect_outcome(declare_candidate(fixture, creation.policy, a), Outcome::POLICY_UPDATED,
                        "path-a is declared as a candidate");
  report.expect_outcome(declare_candidate(fixture, creation.policy, b), Outcome::POLICY_UPDATED,
                        "path-b is declared as a candidate");

  // Only path-a carries evidence yet, so the first commit is the initial
  // establishment rather than a move.
  report.expect_outcome(publish_latency(fixture, a, 1000), Outcome::POLICY_UPDATED,
                        "path-a reports 1000us");
  report.expect_outcome(evaluate_policy(fixture, creation.policy), Outcome::DECISION_COMMITTED,
                        "the initial preference is established");
  const PathId established = preferred_path(fixture, creation.policy);
  report.expect(established == a, "path-a is the preferred path", render_path(established));

  // 1000us -> 800us is exactly 2000 bps of relative improvement.
  report.expect_outcome(publish_latency(fixture, b, 800), Outcome::POLICY_UPDATED,
                        "path-b reports 800us");
  const OperationResult moved = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(moved, Outcome::DECISION_COMMITTED,
                        "the improvement rule commits the move to path-b");

  const AdaptationSnapshot after = snapshot_of(fixture, creation.policy);
  report.expect(after.preference.preferred_path == b, "path-b is the preferred path",
                render_path(after.preference.preferred_path));
  report.expect(after.preference.previous_path == a,
                "path-a is recorded as the displaced preference",
                render_path(after.preference.previous_path));

  const std::optional<AdaptationDecision> decision = fixture.fabric->find_decision(moved.decision);
  report.expect(decision.has_value(), "the committed decision is retrievable",
                decision.has_value() ? "found" : "missing");
  if (decision.has_value()) {
    report.expect(decision->improvement_bps.has_value() && *decision->improvement_bps == 2000,
                  "the engine measured exactly 2000 bps of relative improvement",
                  decision->improvement_bps.has_value()
                      ? std::to_string(*decision->improvement_bps) + " bps"
                      : std::string("none"));
    report.expect(decision->required_improvement_bps == 2000,
                  "the declared switch requirement is 2000 bps",
                  std::to_string(decision->required_improvement_bps) + " bps");
    report.expect(decision->current_preference == a && decision->target_preference == b,
                  "the decision records the A -> B move",
                  render_path(decision->current_preference) + " -> " +
                      render_path(decision->target_preference));
  }

  report.note("a candidate at 800us beats 1000us by exactly 20%; one basis point less is refused");
  return report.finish();
}

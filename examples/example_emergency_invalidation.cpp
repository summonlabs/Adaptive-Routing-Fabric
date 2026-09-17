// Example: an emergency override during hold-down, and its hard limit.
//
// The policy enables one emergency condition: the current preferred path losing
// Path Authority. The example first moves the preference to path-a, arms
// hold-down, and then has Path Authority revoke path-a while hold-down is still
// running. An ordinary policy would wait; this one abandons path-a immediately
// for the still-legal path-b, and the committed decision records
// EMERGENCY_OVERRIDE as its cause.
//
// The second half is the limit of that power: when path-b is revoked too, the
// runtime reports NO_ELIGIBLE_CANDIDATE. Emergency adaptation may bypass
// hysteresis, hold-down and cooldown, but it never invents a legal path and
// never reinstates an unauthorized one.
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

using namespace arf_example;

int main() {
  Report report("example_emergency_invalidation: emergency bypasses hold-down, not authority");
  Fixture fixture;
  report.expect_outcome(register_default_publisher(fixture), Outcome::POLICY_UPDATED,
                        "publisher is registered for the current epoch");

  const PolicyCreation creation =
      create_active_policy(fixture, latency_semantics(2000, 2000, seconds(5), true));
  report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
  report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");

  const PathId a = path("path-a");
  const PathId b = path("path-b");
  report.expect_outcome(declare_candidate(fixture, creation.policy, a), Outcome::POLICY_UPDATED,
                        "path-a is declared as a candidate");
  report.expect_outcome(declare_candidate(fixture, creation.policy, b), Outcome::POLICY_UPDATED,
                        "path-b is declared as a candidate");

  // Only path-b carries evidence, so path-b is established first. path-a then
  // beats it by exactly 20% and takes over, which arms hold-down behind path-a.
  report.expect_outcome(publish_latency(fixture, b, 1000), Outcome::POLICY_UPDATED,
                        "path-b reports 1000us");
  report.expect_outcome(evaluate_policy(fixture, creation.policy), Outcome::DECISION_COMMITTED,
                        "the initial preference is established on path-b");
  report.expect_outcome(publish_latency(fixture, a, 800), Outcome::POLICY_UPDATED,
                        "path-a reports 800us");
  report.expect_outcome(evaluate_policy(fixture, creation.policy), Outcome::DECISION_COMMITTED,
                        "path-a takes over and arms hold-down");

  const AdaptationSnapshot armed = snapshot_of(fixture, creation.policy);
  report.expect(armed.preference.preferred_path == a, "path-a is the preferred path",
                render_path(armed.preference.preferred_path));
  report.expect(armed.hold_down_active, "hold-down is active against a reverse move to path-b",
                render_ticks(armed.hold_down_remaining) + " remaining");

  // Path Authority revokes the path the runtime currently prefers. This is the
  // declared emergency condition.
  report.expect_outcome(invalidate_path(fixture, creation.policy, a, 1, "path withdrawn"),
                        Outcome::POLICY_UPDATED, "path-a is revoked by Path Authority");
  const OperationResult emergency = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(emergency, Outcome::DECISION_COMMITTED,
                        "the emergency rule abandons path-a for path-b");

  const AdaptationSnapshot after = snapshot_of(fixture, creation.policy);
  report.expect(after.preference.preferred_path == b, "path-b is the preferred path",
                render_path(after.preference.preferred_path));
  const std::optional<AdaptationDecision> decision =
      fixture.fabric->find_decision(emergency.decision);
  report.expect(decision.has_value(), "the emergency decision is retrievable",
                decision.has_value() ? "found" : "missing");
  if (decision.has_value()) {
    report.expect(decision->cause == AdaptationCause::EMERGENCY_OVERRIDE,
                  "the decision cause is EMERGENCY_OVERRIDE",
                  std::string(to_string(decision->cause)));
    report.expect(decision->target_preference == b,
                  "the emergency move reuses the still-legal path-b",
                  render_path(decision->target_preference));
  }

  // Path Authority now revokes path-b as well. Both candidates are illegal, and
  // the runtime refuses to adapt instead of overriding authority.
  report.expect_outcome(invalidate_path(fixture, creation.policy, b, 1, "path withdrawn"),
                        Outcome::POLICY_UPDATED, "path-b is revoked by Path Authority");
  const OperationResult blocked = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(blocked, Outcome::NO_ELIGIBLE_CANDIDATE,
                        "with no legal candidate the runtime refuses to adapt");
  report.expect(blocked.suppression == SuppressionReason::NO_ELIGIBLE_ALTERNATIVE,
                "the suppression reason names the missing alternative",
                to_string(blocked.suppression));
  const AdaptationSnapshot last = snapshot_of(fixture, creation.policy);
  report.expect(last.preference.preferred_path == b,
                "no illegal path was installed over path-b",
                render_path(last.preference.preferred_path));
  report.expect(fixture.fabric->stats().decisions_committed == 3,
                "exactly three adaptations were committed",
                std::to_string(fixture.fabric->stats().decisions_committed));

  report.note("emergency bypasses ordinary hysteresis and hold-down; Path Authority is never "
              "bypassed");
  return report.finish();
}

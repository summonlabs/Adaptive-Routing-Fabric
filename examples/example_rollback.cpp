// Example: rollback intent is revalidated, never applied blindly.
//
// fabric.hpp states the contract: "Explicit rollback intent. Revalidates the
// rollback target against current Path Authority and current multipath
// membership; a target that is no longer legal is refused rather than
// restored."
//
// The rollback anchor is the last preference that was *held* with matching
// dependencies -- that is, the preference the current one displaced.
// Establishing the first preference leaves no anchor, because nothing preceded
// it, and every later commit moves the anchor to what it displaced. This
// example drives every rollback answer that surface can produce and asserts the
// exact outcome of each one:
//
//   1. no anchor at all                -> ROLLBACK_REFUSED
//   2. a transition, then a rollback   -> DECISION_COMMITTED back to the
//                                         displaced preference, with the anchor
//                                         moved to the preference just left
//   3. the anchor lost its authority   -> STALE_PATH_AUTHORITY: the restore
//                                         target is revalidated before any
//                                         short circuit, so an illegal restore
//                                         is named instead of being reported as
//                                         a harmless no-op
//   4. a target change discarded the
//      anchor                          -> ROLLBACK_REFUSED
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

using namespace arf_example;

namespace {

// Each section lives in its own function so that no single stack frame holds
// every fixture, request and snapshot at once.
void section_without_anchor(Report& report) {
  {
    Fixture fixture;
    report.expect_outcome(register_default_publisher(fixture), Outcome::POLICY_UPDATED,
                          "publisher is registered for the current epoch");
    const PolicyCreation creation = create_active_policy(fixture, latency_semantics(2000, 4000));
    report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
    report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");
    const PathId a = path("path-a");
    report.expect_outcome(declare_candidate(fixture, creation.policy, a), Outcome::POLICY_UPDATED,
                          "path-a is declared as a candidate");
    report.expect_outcome(publish_latency(fixture, a, 1000), Outcome::POLICY_UPDATED,
                          "path-a reports 1000us");

    RollbackRequest request;
    request.policy = creation.policy;
    request.reason = "operator request before any adaptation";
    request.context = fixture.context();
    const OperationResult refused = fixture.fabric->rollback(request);
    report.expect_outcome(refused, Outcome::ROLLBACK_REFUSED,
                          "a rollback with no stable state to restore is refused");
    report.expect(outcome_is_rejection(refused.outcome),
                  "the refusal is reported as a rejection",
                  std::string(to_string(refused.outcome)));
  }
}

void section_revalidated_rollback(Report& report) {
  // A committed move, then repeated rollbacks, then a revoked anchor.
  Fixture fixture;
  report.expect_outcome(register_default_publisher(fixture), Outcome::POLICY_UPDATED,
                        "publisher is registered for the current epoch");
  const PolicyCreation creation = create_active_policy(fixture, latency_semantics(2000, 4000));
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
                        "path-b takes over from path-a");

  const AdaptationSnapshot committed = snapshot_of(fixture, creation.policy);
  report.expect(committed.preference.preferred_path == b, "path-b is the preferred path",
                render_path(committed.preference.preferred_path));
  report.expect(committed.stable.established && committed.stable.path == a,
                "the anchor is the preference the move displaced",
                render_path(committed.stable.path));

  // A rollback restores the anchor, and moves the anchor to the preference it
  // displaces, so it is a revalidated step back rather than a jump.
  RollbackRequest request;
  request.policy = creation.policy;
  request.reason = "operator request after the move";
  request.context = fixture.context();
  const OperationResult restored = fixture.fabric->rollback(request);
  report.expect_outcome(restored, Outcome::DECISION_COMMITTED,
                        "the displaced preference is restored");
  const AdaptationSnapshot back_on_a = snapshot_of(fixture, creation.policy);
  report.expect(back_on_a.preference.preferred_path == a, "path-a is preferred again",
                render_path(back_on_a.preference.preferred_path));
  report.expect(back_on_a.stable.path == b, "the anchor moved to path-b",
                render_path(back_on_a.stable.path));
  report.expect(back_on_a.preference.adaptation_generation >
                    committed.preference.adaptation_generation,
                "the rollback advanced the adaptation generation exactly once",
                std::to_string(back_on_a.preference.adaptation_generation.value()));
  report.expect(fixture.fabric->stats().decisions_committed == 3,
                "the rollback is recorded as one committed decision",
                std::to_string(fixture.fabric->stats().decisions_committed));

  RollbackRequest forward;
  forward.policy = creation.policy;
  forward.reason = "operator reverses the rollback";
  forward.context = fixture.context();
  report.expect_outcome(fixture.fabric->rollback(forward), Outcome::DECISION_COMMITTED,
                        "rolling back again returns to path-b");
  const AdaptationSnapshot back_on_b = snapshot_of(fixture, creation.policy);
  report.expect(back_on_b.preference.preferred_path == b, "path-b is preferred again",
                render_path(back_on_b.preference.preferred_path));
  report.expect(back_on_b.stable.path == a, "the anchor moved back to path-a",
                render_path(back_on_b.stable.path));

  // The anchor loses its Path Authority. Rollback is not a back door: the
  // restore target is revalidated against Path Authority before the runtime
  // decides whether there is anything to do, so an unauthorized restore is
  // refused by name and nothing is reinstated.
  report.expect_outcome(invalidate_path(fixture, creation.policy, a, 1, "authority denied"),
                        Outcome::POLICY_UPDATED, "path-a is revoked by Path Authority");
  RollbackRequest revoked;
  revoked.policy = creation.policy;
  revoked.reason = "operator request against a revoked anchor";
  revoked.context = fixture.context();
  const OperationResult blocked = fixture.fabric->rollback(revoked);
  report.expect_outcome(blocked, Outcome::STALE_PATH_AUTHORITY,
                        "the rollback is refused because the anchor is not authorized");
  report.expect(outcome_is_rejection(blocked.outcome),
                "the refusal is reported as a rejection",
                std::string(to_string(blocked.outcome)));
  const AdaptationSnapshot untouched = snapshot_of(fixture, creation.policy);
  report.expect(untouched.preference.preferred_path == b,
                "the illegal path was not reinstated by the rollback",
                render_path(untouched.preference.preferred_path));
  report.expect(fixture.fabric->stats().decisions_committed == 4,
                "the refused rollback committed nothing",
                std::to_string(fixture.fabric->stats().decisions_committed));
}

void section_retarget_discards_the_anchor(Report& report) {
  Fixture fixture;
  report.expect_outcome(register_default_publisher(fixture), Outcome::POLICY_UPDATED,
                        "publisher is registered for the current epoch");
  const PolicyCreation creation = create_active_policy(fixture, latency_semantics(2000, 4000));
  report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
  report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");
  PolicySemantics retargeted = latency_semantics(2000, 4000);
  retargeted.target.route = RouteId::require("route-2");
  // A policy update is generation-bound optimistic concurrency: the caller must
  // name the generation it edited, and a mismatch is refused rather than applied.
  const std::optional<AdaptivePolicy> current = fixture.fabric->find_policy(creation.policy);
  report.expect(current.has_value(), "the policy is readable before the update",
                current.has_value() ? "found" : "missing");
  UpdatePolicyRequest update;
  update.policy = creation.policy;
  update.update.scope.fabric = fabric_id();
  update.update.scope.name_space = routing_namespace();
  update.update.semantics = retargeted;
  update.context = fixture.context(current.has_value() ? current->generation
                                                       : AdaptivePolicyGeneration());
  report.expect_outcome(fixture.fabric->update_policy(update), Outcome::POLICY_UPDATED,
                        "the policy is retargeted to route-2");

  const AdaptationSnapshot retargeted_view = snapshot_of(fixture, creation.policy);
  report.expect(!retargeted_view.stable.established,
                "the target change discarded the stable anchor instead of reinterpreting it",
                retargeted_view.stable.established ? "established" : "not established");
  RollbackRequest after_update;
  after_update.policy = creation.policy;
  after_update.reason = "operator request after the target changed";
  after_update.context = fixture.context();
  report.expect_outcome(fixture.fabric->rollback(after_update), Outcome::ROLLBACK_REFUSED,
                        "a rollback with no stable anchor is refused");
}

}  // namespace

int main() {
  Report report("example_rollback: a restore target must still be stable and still be known");
  section_without_anchor(report);
  section_revalidated_rollback(report);
  section_retarget_discards_the_anchor(report);
  report.note("the rollback anchor is the preference the current one displaced, so a rollback "
              "either revalidates that anchor and steps back to it, or reports that there is no "
              "anchor to restore at all");
  return report.finish();
}

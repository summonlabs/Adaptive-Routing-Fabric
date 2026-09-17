// Example: evidence that moved under a running evaluation is refused.
//
// Evaluation is two-phase on purpose. Phase one snapshots every dependency --
// policy generation, evidence generation and watermarks, epoch, authority
// generation and every candidate binding -- and evaluates outside the engine
// lock. Phase two re-acquires the lock and verifies that not one of them moved.
//
// Here a phase-one ticket that is fully committable is held while newer evidence
// is published. The commit is refused with STALE_EVIDENCE and nothing changes.
// A fresh evaluation over the newer evidence then commits, which shows the
// adaptation was deferred rather than lost.
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

using namespace arf_example;

int main() {
  Report report("example_stale_evidence: a ticket over superseded evidence cannot commit");
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

  const AdaptationSnapshot before = snapshot_of(fixture, creation.policy);

  // Phase one only: the ticket is a proposal, never an authority.
  EvaluateRequest request;
  request.policy = creation.policy;
  request.context = fixture.context();
  const EvaluationTicket ticket = fixture.fabric->begin_evaluation(request);
  report.expect(ticket.committable(), "the phase-one ticket is committable",
                std::string(to_string(ticket.lifecycle)));
  report.expect(ticket.target_preference == a, "the ticket proposes path-a",
                render_path(ticket.target_preference));

  // Newer evidence arrives while the ticket is in flight.
  report.expect_outcome(publish_latency(fixture, b, 800), Outcome::POLICY_UPDATED,
                        "path-b reports 800us while the ticket is in flight");

  CommitDecisionRequest commit;
  commit.ticket = ticket;
  commit.context = fixture.context();
  const OperationResult refused = fixture.fabric->commit_evaluation(commit);
  report.expect_outcome(refused, Outcome::STALE_EVIDENCE,
                        "the commit is refused because the evidence generation moved");
  report.expect(fixture.fabric->stats().stale_commit_rejections == 1,
                "the stale commit rejection is counted",
                std::to_string(fixture.fabric->stats().stale_commit_rejections));

  const AdaptationSnapshot after = snapshot_of(fixture, creation.policy);
  report.expect(after.preference.established == before.preference.established,
                "no preference was installed by the refused commit",
                after.preference.established ? "established" : "not established");
  report.expect(after.adaptation_generation == before.adaptation_generation,
                "no adaptation generation advanced",
                std::to_string(after.adaptation_generation.value()));

  // The deferred adaptation is not lost: a fresh evaluation reads the evidence
  // the runtime actually holds now and commits on it.
  const OperationResult fresh = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(fresh, Outcome::DECISION_COMMITTED,
                        "a fresh evaluation commits on the current evidence");
  const PathId preferred = preferred_path(fixture, creation.policy);
  report.expect(preferred == b, "path-b is the preferred path", render_path(preferred));

  report.note("a ticket is a proposal; only commit_evaluation carries authority, and it "
              "re-verifies");
  return report.finish();
}

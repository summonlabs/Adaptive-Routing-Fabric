// Example: a path whose authority generation moved under a running evaluation.
//
// Path Authority is binding. An evaluation records the exact PathAuthorityBinding
// generation it read for every candidate. If Path Authority advances that
// generation before the commit, the recorded generation is no longer the current
// one, and the commit is refused with STALE_PATH_AUTHORITY rather than being
// applied against authority the runtime no longer holds.
//
// A fresh evaluation then commits against the new generation, and the committed
// preference carries it.
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

using namespace arf_example;

int main() {
  Report report("example_stale_path_authority: authority that moved cannot be committed against");
  Fixture fixture;
  report.expect_outcome(register_default_publisher(fixture), Outcome::POLICY_UPDATED,
                        "publisher is registered for the current epoch");

  const PolicyCreation creation = create_active_policy(fixture, latency_semantics(2000, 4000));
  report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
  report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");

  const PathId a = path("path-a");
  const PathId b = path("path-b");
  report.expect_outcome(declare_candidate(fixture, creation.policy, a, 1), Outcome::POLICY_UPDATED,
                        "path-a is declared at authority generation 1");
  report.expect_outcome(declare_candidate(fixture, creation.policy, b, 1), Outcome::POLICY_UPDATED,
                        "path-b is declared at authority generation 1");
  report.expect_outcome(publish_latency(fixture, a, 1000), Outcome::POLICY_UPDATED,
                        "path-a reports 1000us");

  const AdaptationSnapshot before = snapshot_of(fixture, creation.policy);

  EvaluateRequest request;
  request.policy = creation.policy;
  request.context = fixture.context();
  const EvaluationTicket ticket = fixture.fabric->begin_evaluation(request);
  report.expect(ticket.committable(), "the phase-one ticket is committable",
                std::string(to_string(ticket.lifecycle)));
  report.expect(ticket.target_preference == a, "the ticket proposes path-a",
                render_path(ticket.target_preference));
  report.expect(ticket.target_path_authority_generation.value() == 1,
                "the ticket recorded authority generation 1",
                std::to_string(ticket.target_path_authority_generation.value()));

  // Path Authority supersedes generation 1 with generation 2.
  report.expect_outcome(advance_path_authority(fixture, creation.policy, a, 2),
                        Outcome::POLICY_UPDATED, "path-a authority advances to generation 2");

  CommitDecisionRequest commit;
  commit.ticket = ticket;
  commit.context = fixture.context();
  const OperationResult refused = fixture.fabric->commit_evaluation(commit);
  report.expect_outcome(refused, Outcome::STALE_PATH_AUTHORITY,
                        "the commit is refused because the recorded authority is superseded");

  const AdaptationSnapshot after = snapshot_of(fixture, creation.policy);
  report.expect(after.preference.established == before.preference.established,
                "no preference was installed by the refused commit",
                after.preference.established ? "established" : "not established");
  report.expect(fixture.fabric->stats().stale_commit_rejections == 1,
                "the stale commit rejection is counted",
                std::to_string(fixture.fabric->stats().stale_commit_rejections));

  // A fresh evaluation reads the current authority generation and commits.
  const OperationResult fresh = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(fresh, Outcome::DECISION_COMMITTED,
                        "a fresh evaluation commits against the current authority");
  const AdaptationSnapshot settled = snapshot_of(fixture, creation.policy);
  report.expect(settled.preference.preferred_path == a, "path-a is the preferred path",
                render_path(settled.preference.preferred_path));
  report.expect(settled.preference.path_authority_generation.value() == 2,
                "the committed preference binds authority generation 2",
                std::to_string(settled.preference.path_authority_generation.value()));

  report.note("a superseded authority generation is never silently upgraded to the current one");
  return report.finish();
}

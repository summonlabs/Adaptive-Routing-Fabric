// Example: deterministic tie-breaking between identical candidates.
//
// The ranking is a total order: explicit policy priority first, then evidence
// quality, then the objective, and finally the canonical byte order of the
// PathId. Two candidates with identical metrics and equal priority therefore
// resolve to the canonically smaller PathId, and the order in which they were
// declared never enters the result.
//
// The example runs the identical scenario twice in two independent engines and
// asserts that the committed decision digest is byte-identical. The digest
// excludes decision ids, evaluation ids, mutation attempt ids and timestamps
// precisely so that two runs of the same scenario can be compared.
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

namespace {

using namespace arf_example;

struct TieRun {
  PathId winner;
  std::string preferred;
  std::string digest;
  bool both_eligible = false;
  bool metrics_equal = false;
  bool priority_equal = false;
  bool canonical_ranking = false;
};

// One complete run in a fresh engine. Nothing outside the arguments to the
// engine calls differs between runs.
[[nodiscard]] TieRun run_once(Report& report) {
  TieRun run;
  Fixture fixture;
  report.expect_outcome(register_default_publisher(fixture), Outcome::POLICY_UPDATED,
                        "publisher is registered for the current epoch");
  const PolicyCreation creation = create_active_policy(fixture, latency_semantics(2000, 4000));
  report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
  report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");

  const PathId a = path("path-a");
  const PathId b = path("path-b");
  // Declared in reverse canonical order on purpose.
  report.expect_outcome(declare_candidate(fixture, creation.policy, b), Outcome::POLICY_UPDATED,
                        "path-b is declared first");
  report.expect_outcome(declare_candidate(fixture, creation.policy, a), Outcome::POLICY_UPDATED,
                        "path-a is declared second");
  // Identical latency, identical observation sequence, no explicit priority.
  report.expect_outcome(publish_latency(fixture, a, 500), Outcome::POLICY_UPDATED,
                        "path-a reports 500us");
  report.expect_outcome(publish_latency(fixture, b, 500), Outcome::POLICY_UPDATED,
                        "path-b reports 500us");

  const OperationResult committed = evaluate_policy(fixture, creation.policy);
  report.expect_outcome(committed, Outcome::DECISION_COMMITTED,
                        "the tie is resolved and committed");
  run.winner = preferred_path(fixture, creation.policy);
  run.preferred = render_path(run.winner);
  const std::optional<AdaptationDecision> decision =
      fixture.fabric->find_decision(committed.decision);
  if (decision.has_value()) {
    run.digest = decision->digest;
    if (decision->ranking.size() == 2U) {
      const CandidateEvaluation& first = decision->ranking[0];
      const CandidateEvaluation& second = decision->ranking[1];
      run.both_eligible = first.eligible && second.eligible;
      run.priority_equal = first.priority == second.priority;
      run.canonical_ranking = first.path < second.path;
      run.metrics_equal = first.metrics.size() == 1U && second.metrics.size() == 1U &&
                          first.metrics[0].value() == second.metrics[0].value();
    }
  }
  return run;
}

}  // namespace

int main() {
  Report report("example_deterministic_tie_break: identical candidates resolve canonically");
  report.note("run 1 of 2");
  const TieRun first = run_once(report);
  report.note("run 2 of 2 in a fresh engine");
  const TieRun second = run_once(report);

  const PathId canonical = path("path-a");
  report.expect(first.winner == canonical, "the canonically smaller PathId wins", first.preferred);
  report.expect(second.winner == first.winner, "the second run resolves identically",
                second.preferred);
  report.expect(first.both_eligible && second.both_eligible,
                "both tied candidates are eligible", "2 eligible each run");
  report.expect(first.metrics_equal && second.metrics_equal,
                "the tied candidates carry identical metrics", "latency 500us each");
  report.expect(first.priority_equal && second.priority_equal,
                "the tied candidates carry equal priority", "priority 0 each");
  report.expect(first.canonical_ranking && second.canonical_ranking,
                "the ranking itself is in canonical PathId order", "path-a before path-b");
  const bool digests_agree = !first.digest.empty() && first.digest == second.digest;
  report.expect(digests_agree, "the committed decision digest is identical across runs",
                digests_agree ? "identical" : "different");

  report.note("path-b is declared before path-a in both runs; declaration order never decides");
  report.note("the digest binds the engine-generated policy identity, so the report states that the "
              "two runs agree instead of printing a value unique to this process");
  return report.finish();
}

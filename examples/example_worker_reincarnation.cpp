// Example: worker reincarnation permanently fences the previous boot.
//
// A PublisherId is an identity; a WorkerBootId is an incarnation of it. When the
// same publisher returns under a new boot id, the runtime does not merge the two:
// the previous incarnation is fenced permanently. Its evidence, its evaluations
// and its adaptations can no longer be presented, and re-registering the fenced
// boot is refused. Nothing about the fence is time limited.
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

using namespace arf_example;

int main() {
  Report report("example_worker_reincarnation: boot-a2 permanently fences boot-a1");
  Fixture fixture;
  const PublisherId worker = PublisherId::require("publisher-a");
  const WorkerBootId boot_one = WorkerBootId::require("boot-a1");
  const SessionId session_one = SessionId::require("session-a1");

  report.expect_outcome(register_publisher(fixture, worker, boot_one, session_one),
                        Outcome::POLICY_UPDATED, "boot-a1 registers the publisher");

  const PolicyCreation creation = create_active_policy(fixture, latency_semantics(2000, 4000));
  report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
  report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");

  const PathId a = path("path-a");
  report.expect_outcome(declare_candidate(fixture, creation.policy, a), Outcome::POLICY_UPDATED,
                        "boot-a1 declares path-a");
  report.expect_outcome(publish_latency(fixture, a, 1000), Outcome::POLICY_UPDATED,
                        "boot-a1 publishes evidence while it is live");
  const EvidenceGeneration live_generation = fixture.fabric->evidence_generation();

  // The worker restarts and returns under a fresh boot id.
  const WorkerBootId boot_two = WorkerBootId::require("boot-a2");
  const SessionId session_two = SessionId::require("session-a2");
  report.expect_outcome(register_publisher(fixture, worker, boot_two, session_two),
                        Outcome::POLICY_UPDATED, "boot-a2 registers the same publisher");
  report.expect(fixture.fabric->is_fenced(worker, boot_one),
                "boot-a1 is permanently fenced", "fenced");
  report.expect(!fixture.fabric->is_fenced(worker, boot_two),
                "boot-a2 is the live incarnation", "live");

  bool reincarnation_record = false;
  for (const FenceRecord& fence : fixture.fabric->describe_authority().fence_records) {
    if (fence.worker_boot == boot_one && fence.cause == "REINCARNATION") {
      reincarnation_record = true;
    }
  }
  report.expect(reincarnation_record, "the fence record names the reincarnation cause",
                "REINCARNATION");

  // A mutation presented by the fenced incarnation is refused before any state
  // is read, so it cannot be smuggled in behind a fresh mutation attempt id.
  PublishEvidenceRequest stale;
  EvidencePublication publication;
  publication.source = EvidenceSourceId::require("telemetry-1");
  publication.source_generation = EvidenceSourceGeneration::require(1);
  publication.quality = EvidenceQuality::AGGREGATED;
  publication.path = a;
  publication.value = MetricValue::make(MetricKind::PATH_LATENCY, 700).value_or(MetricValue{});
  publication.observation_sequence = 2;
  stale.publications.push_back(publication);
  stale.context = fixture.context_for(fixture.fabric->epoch(), worker, boot_one, session_one);
  report.expect_outcome(fixture.fabric->publish_evidence(stale), Outcome::FENCED_WORKER,
                        "a mutation from the fenced boot-a1 is refused");
  report.expect(fixture.fabric->evidence_generation() == live_generation,
                "the refused mutation advanced nothing",
                std::to_string(fixture.fabric->evidence_generation().value()));

  report.expect_outcome(register_publisher(fixture, worker, boot_one, session_two),
                        Outcome::FENCED_WORKER,
                        "the fenced boot cannot register a new session either");

  // The live incarnation carries full authority for the same publisher.
  fixture.worker_boot = boot_two;
  fixture.session = session_two;
  report.expect_outcome(publish_latency(fixture, a, 900, 2), Outcome::POLICY_UPDATED,
                        "boot-a2 publishes evidence");
  report.expect_outcome(evaluate_policy(fixture, creation.policy), Outcome::DECISION_COMMITTED,
                        "boot-a2 drives an evaluation to commit");
  const PathId preferred = preferred_path(fixture, creation.policy);
  report.expect(preferred == a, "path-a is the preferred path", render_path(preferred));

  report.note("fencing is per incarnation and permanent: it is not cleared by time or by a "
              "session");
  return report.finish();
}

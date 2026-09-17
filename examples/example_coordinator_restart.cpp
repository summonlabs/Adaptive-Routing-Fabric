// Example: coordinator restart over the same durable bytes.
//
// encode_store() is the exact byte image save() writes. This example builds an
// engine, commits a preference, encodes the store and applies those bytes to a
// fresh engine, which is what a restarted coordinator does. It then asserts the
// four properties recovery promises:
//
//   the policy survives            identity, semantics, generation and the last
//                                  committed preference are restored;
//   live authority does not        no registration, no session, no boot id and
//                                  no mutation context crosses the restart;
//   the epoch advances             a persisted epoch is never reused as live
//                                  authority;
//   evidence is not restored       the generation counter continues, the samples
//                                  do not, so the preference must be revalidated.
//
// Returns 0 when every expectation holds and 1 otherwise.
#include "example_support.hpp"

using namespace arf_example;

int main() {
  Report report("example_coordinator_restart: durable intent survives, live authority does not");
  Fixture before;
  report.expect_outcome(register_default_publisher(before), Outcome::POLICY_UPDATED,
                        "publisher is registered for the current epoch");

  const PolicyCreation creation = create_active_policy(before, latency_semantics(2000, 4000));
  report.expect_outcome(creation.created, Outcome::POLICY_CREATED, "policy is created");
  report.expect_outcome(creation.activated, Outcome::POLICY_UPDATED, "policy becomes ACTIVE");

  const PathId a = path("path-a");
  const PathId b = path("path-b");
  report.expect_outcome(declare_candidate(before, creation.policy, a), Outcome::POLICY_UPDATED,
                        "path-a is declared as a candidate");
  report.expect_outcome(declare_candidate(before, creation.policy, b), Outcome::POLICY_UPDATED,
                        "path-b is declared as a candidate");
  report.expect_outcome(publish_latency(before, a, 1000), Outcome::POLICY_UPDATED,
                        "path-a reports 1000us");
  report.expect_outcome(evaluate_policy(before, creation.policy), Outcome::DECISION_COMMITTED,
                        "the initial preference is established");
  report.expect_outcome(publish_latency(before, b, 800), Outcome::POLICY_UPDATED,
                        "path-b reports 800us");
  report.expect_outcome(evaluate_policy(before, creation.policy), Outcome::DECISION_COMMITTED,
                        "path-b takes over");
  const PathId committed = preferred_path(before, creation.policy);
  report.expect(committed == b, "path-b is the committed preference before the restart",
                render_path(committed));

  const CoordinatorEpoch epoch_before = before.fabric->epoch();
  const EvidenceGeneration evidence_before = before.fabric->evidence_generation();
  const std::optional<AdaptivePolicy> policy_before = before.fabric->find_policy(creation.policy);
  report.expect(policy_before.has_value(), "the policy exists before the restart",
                policy_before.has_value() ? "found" : "missing");
  const std::string store = before.fabric->encode_store();
  // The exact byte count is not reported: the store embeds the engine-generated
  // policy identity, whose encoding length is unique to this process rather than
  // reproducible.
  report.expect(!store.empty(), "the durable store encodes to bytes",
                store.empty() ? "empty" : "non-empty");

  // A fresh engine over exactly the same bytes. save()/load() differ only in
  // that they move those bytes through a file.
  Fixture after;
  report.expect_outcome(after.fabric->decode_store(store, "example-restart"),
                        Outcome::POLICY_UPDATED, "the store is decoded and applied");

  report.expect(after.fabric->epoch().value() == epoch_before.value() + 1,
                "the epoch advanced by exactly one",
                std::to_string(epoch_before.value()) + " -> " +
                    std::to_string(after.fabric->epoch().value()));

  const std::optional<AdaptivePolicy> recovered = after.fabric->find_policy(creation.policy);
  report.expect(recovered.has_value(), "the policy survives the restart",
                recovered.has_value() ? "found" : "missing");
  if (recovered.has_value() && policy_before.has_value()) {
    report.expect(recovered->name == policy_before->name, "the policy name is preserved",
                  recovered->name.str());
    report.expect(recovered->generation == policy_before->generation,
                  "the policy generation is preserved",
                  std::to_string(recovered->generation.value()));
    // Lifecycle is excluded from the comparison because conservative recovery
    // deliberately downgrades it; everything else must be byte-identical.
    AdaptivePolicy original = *policy_before;
    original.lifecycle = PolicyLifecycle::ACTIVE;
    AdaptivePolicy survivor = *recovered;
    survivor.lifecycle = PolicyLifecycle::ACTIVE;
    const bool digests_agree = policy_semantic_digest(original) == policy_semantic_digest(survivor);
    report.expect(digests_agree, "the recovered policy is semantically identical",
                  digests_agree ? "digests equal" : "digests differ");
    report.expect(recovered->lifecycle == PolicyLifecycle::REVALIDATION_REQUIRED,
                  "conservative recovery requires revalidation",
                  std::string(to_string(recovered->lifecycle)));
  }
  const PathId restored = preferred_path(after, creation.policy);
  report.expect(restored == b, "the committed preference is restored", render_path(restored));

  const AuthorityDescription authority = after.fabric->describe_authority();
  report.expect(authority.registrations.empty(), "no publisher registration survives",
                std::to_string(authority.registrations.size()) + " registration(s)");
  report.expect(after.fabric->stats().publishers == 0, "the publisher table is empty",
                std::to_string(after.fabric->stats().publishers));
  report.expect(!after.fabric->is_fenced(before.publisher, before.worker_boot),
                "the pre-restart boot id is not even remembered as fenced", "unknown");

  report.expect(after.fabric->describe_evidence(creation.policy).empty(),
                "no evidence series is restored", "0 series");
  const EvidenceSnapshotPtr recovered_evidence = after.fabric->capture_evidence(creation.policy);
  report.expect(recovered_evidence != nullptr && recovered_evidence->values().empty(),
                "the recovered evidence snapshot holds no value", "0 value(s)");
  report.expect(after.fabric->evidence_generation() == evidence_before,
                "the evidence generation counter continues where it stopped",
                std::to_string(after.fabric->evidence_generation().value()));

  // Requests that still speak for the pre-restart world are refused.
  PublishEvidenceRequest stale;
  EvidencePublication publication;
  publication.source = EvidenceSourceId::require("telemetry-1");
  publication.source_generation = EvidenceSourceGeneration::require(1);
  publication.quality = EvidenceQuality::AGGREGATED;
  publication.path = a;
  publication.value = MetricValue::make(MetricKind::PATH_LATENCY, 1000).value_or(MetricValue{});
  publication.observation_sequence = 1;
  stale.publications.push_back(publication);
  stale.context = after.context_for(epoch_before, before.publisher, before.worker_boot,
                                    before.session);
  report.expect_outcome(after.fabric->publish_evidence(stale), Outcome::STALE_EPOCH,
                        "a request carrying the pre-restart epoch is refused");
  PublishEvidenceRequest unknown = stale;
  unknown.context = after.context_for(after.fabric->epoch(), before.publisher, before.worker_boot,
                                      before.session);
  report.expect_outcome(after.fabric->publish_evidence(unknown), Outcome::UNAUTHORIZED,
                        "the pre-restart publisher is not registered in the new epoch");

  // Recovery is usable: a fresh incarnation registers, re-declares the candidate
  // and revalidation returns the policy to service.
  after.worker_boot = WorkerBootId::require("boot-b1");
  after.session = SessionId::require("session-b1");
  report.expect_outcome(register_default_publisher(after), Outcome::POLICY_UPDATED,
                        "a fresh incarnation registers on the recovered engine");
  report.expect_outcome(declare_candidate(after, creation.policy, a), Outcome::POLICY_UPDATED,
                        "the recovered policy re-declares path-a");
  PolicyLifecycleRequest revalidation;
  revalidation.policy = creation.policy;
  revalidation.event = PolicyEvent::REVALIDATE;
  revalidation.detail = "example revalidation";
  revalidation.context = after.context();
  report.expect_outcome(after.fabric->transition_policy(revalidation), Outcome::POLICY_UPDATED,
                        "revalidation returns the policy to ACTIVE");
  const std::optional<AdaptivePolicy> live = after.fabric->find_policy(creation.policy);
  report.expect(live.has_value() && live->lifecycle == PolicyLifecycle::ACTIVE,
                "the recovered policy is ACTIVE again",
                live.has_value() ? std::string(to_string(live->lifecycle)) : "missing");

  report.note("recovery restores intent, never process authority, and never evidence samples");
  return report.finish();
}

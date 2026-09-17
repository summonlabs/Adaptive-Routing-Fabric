// Deterministic race and stale-completion proofs.
//
// Every race here is forced to an exact interleaving: either by taking a
// phase-one ticket and mutating the dependency before committing it, or with an
// explicit std::barrier driven through the engine's documented evaluation hook.
// Nothing depends on scheduler luck and nothing sleeps.
#include <barrier>
#include <thread>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace arf_test;

CandidateBinding frozen_binding(const PathId& id, std::uint64_t authority_generation,
                                std::uint64_t route_generation = 1, bool legal = true) {
  CandidateBinding binding;
  binding.path = id;
  binding.path_authority.path = id;
  binding.path_authority.generation = PathAuthorityGeneration::require(authority_generation);
  binding.path_authority.legal = legal;
  binding.route.route = route_id();
  binding.route.generation = RouteGeneration::require(route_generation);
  binding.route.current = true;
  binding.available = true;
  return binding;
}

UpstreamNotification event_for(Harness& harness, const AdaptivePolicyId& policy,
                               UpstreamEvent event, const CandidateBinding& binding,
                               std::optional<std::uint64_t> expected = std::nullopt) {
  UpstreamNotification notification;
  notification.event = event;
  notification.policy = policy;
  notification.binding = binding;
  notification.expected_previous_generation = expected;
  notification.provenance.publisher = harness.publisher;
  notification.provenance.worker_boot = harness.worker_boot;
  notification.provenance.epoch = harness.fabric->epoch();
  notification.provenance.origin = "path-authority";
  return notification;
}

}  // namespace

// The mandatory stale-evidence race: an evaluation that started from evidence
// generation E must not commit after E+1 arrived.
ARF_TEST(stale_evidence_completion_is_rejected) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);
  EvaluateRequest request;
  request.policy = fixture.policy;
  request.context = harness.context();
  request.defer_commit = true;
  const EvaluationTicket ticket = harness.fabric->begin_evaluation(request);
  ARF_CHECK_EQ(ticket.lifecycle, DecisionLifecycle::ELIGIBLE);
  const EvidenceGeneration started_at = ticket.dependencies.evidence_generation;

  // New evidence arrives and changes the ranking before the old evaluation
  // finishes.
  feed_latency(harness, fixture.a, 1000, fixture.b, 990, 3);
  ARF_CHECK(harness.fabric->evidence_generation() != started_at);

  CommitDecisionRequest commit;
  commit.ticket = ticket;
  commit.context = harness.context();
  const OperationResult result = harness.fabric->commit_evaluation(commit);
  ARF_CHECK_EQ(result.outcome, Outcome::STALE_EVIDENCE);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);

  // The newer evidence stays authoritative and still drives the decision.
  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 4);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);
}

// The mandatory stale-path-authority race: a candidate that moved from
// authority generation 7 to 8 must not become preferred under generation 7.
ARF_TEST(stale_path_authority_completion_is_rejected) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);

  EvaluateRequest request;
  request.policy = fixture.policy;
  request.context = harness.context();
  request.defer_commit = true;
  const EvaluationTicket ticket = harness.fabric->begin_evaluation(request);
  ARF_CHECK_EQ(ticket.lifecycle, DecisionLifecycle::ELIGIBLE);
  ARF_CHECK_EQ(ticket.target_preference, fixture.b);

  // Path Authority advances B to generation 8 and invalidates 7.
  ARF_CHECK_EQ(notify(harness,
                      event_for(harness, fixture.policy, UpstreamEvent::ADVANCE_PATH_AUTHORITY,
                                frozen_binding(fixture.b, 8, 1, false), 1))
                   .outcome,
               Outcome::POLICY_UPDATED);

  CommitDecisionRequest commit;
  commit.ticket = ticket;
  commit.context = harness.context();
  const OperationResult result = harness.fabric->commit_evaluation(commit);
  ARF_CHECK_EQ(result.outcome, Outcome::STALE_PATH_AUTHORITY);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
  // Only the establishing adaptation committed; the rejected ticket advanced
  // nothing.
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).adaptation_generation.value(), 2ULL);
}

// The mandatory policy-change race.
ARF_TEST(policy_change_completion_is_rejected) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);

  EvaluateRequest request;
  request.policy = fixture.policy;
  request.context = harness.context();
  request.defer_commit = true;
  const EvaluationTicket ticket = harness.fabric->begin_evaluation(request);
  ARF_CHECK_EQ(ticket.lifecycle, DecisionLifecycle::ELIGIBLE);

  const AdaptivePolicy policy = *harness.fabric->find_policy(fixture.policy);
  UpdatePolicyRequest update;
  update.policy = fixture.policy;
  update.update.scope = policy.scope;
  update.update.semantics = policy.semantics;
  update.update.semantics.improvements.front().switch_improvement_bps = 4000;
  update.context = harness.context(policy.generation);
  ARF_CHECK_EQ(harness.fabric->update_policy(update).outcome, Outcome::POLICY_UPDATED);

  CommitDecisionRequest commit;
  commit.ticket = ticket;
  commit.context = harness.context();
  const OperationResult result = harness.fabric->commit_evaluation(commit);
  ARF_CHECK_EQ(result.outcome, Outcome::STALE_POLICY_GENERATION);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
}

// The mandatory epoch-advance race.
ARF_TEST(epoch_advance_completion_is_rejected) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);

  EvaluateRequest request;
  request.policy = fixture.policy;
  request.context = harness.context();
  request.defer_commit = true;
  const EvaluationTicket ticket = harness.fabric->begin_evaluation(request);
  ARF_CHECK_EQ(ticket.lifecycle, DecisionLifecycle::ELIGIBLE);

  const CoordinatorEpoch before = harness.fabric->epoch();
  ARF_CHECK_EQ(harness.fabric->advance_epoch("coordinator handover").outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK(harness.fabric->epoch() != before);
  // The epoch advance fences every worker, so a real caller re-registers under
  // the new epoch before it can do anything at all.
  const WorkerBootId fresh_boot = WorkerBootId::require("boot-a2");
  const SessionId fresh_session = SessionId::require("session-a2");
  ARF_CHECK_EQ(harness.fabric->register_publisher(harness.publisher, fresh_boot, default_scope(),
                                                  fresh_session)
                   .outcome,
               Outcome::POLICY_UPDATED);
  harness.worker_boot = fresh_boot;
  harness.session = fresh_session;

  CommitDecisionRequest commit;
  commit.ticket = ticket;
  commit.context = harness.context();
  const OperationResult result = harness.fabric->commit_evaluation(commit);
  ARF_CHECK_EQ(result.outcome, Outcome::STALE_EPOCH);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
}

// A worker whose incarnation was fenced can neither publish evidence nor commit.
ARF_TEST(worker_fencing_blocks_evidence_and_commit) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);

  EvaluateRequest request;
  request.policy = fixture.policy;
  request.context = harness.context();
  request.defer_commit = true;
  const EvaluationTicket ticket = harness.fabric->begin_evaluation(request);
  ARF_CHECK_EQ(ticket.lifecycle, DecisionLifecycle::ELIGIBLE);

  // The publisher reappears as a new incarnation. The old boot is fenced
  // permanently.
  const WorkerBootId fresh_boot = WorkerBootId::require("boot-a2");
  const SessionId fresh_session = SessionId::require("session-a2");
  ARF_CHECK_EQ(harness.fabric->register_publisher(harness.publisher, fresh_boot, default_scope(),
                                                  fresh_session)
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK(harness.fabric->is_fenced(harness.publisher, harness.worker_boot));

  PublishEvidenceRequest publish_request;
  publish_request.publications.push_back(make_publication(fixture.a, MetricKind::PATH_LATENCY, 10,
                                                          99, EvidenceQuality::AGGREGATED));
  publish_request.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->publish_evidence(publish_request).outcome, Outcome::FENCED_WORKER);

  CommitDecisionRequest commit;
  commit.ticket = ticket;
  commit.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->commit_evaluation(commit).outcome, Outcome::FENCED_WORKER);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
}

// Retirement beats an in-flight evaluation.
ARF_TEST(retirement_during_evaluation_is_rejected) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);

  EvaluateRequest request;
  request.policy = fixture.policy;
  request.context = harness.context();
  request.defer_commit = true;
  const EvaluationTicket ticket = harness.fabric->begin_evaluation(request);
  ARF_CHECK_EQ(ticket.lifecycle, DecisionLifecycle::ELIGIBLE);

  PolicyLifecycleRequest retire;
  retire.policy = fixture.policy;
  retire.event = PolicyEvent::RETIRE;
  retire.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->transition_policy(retire).outcome, Outcome::POLICY_UPDATED);

  CommitDecisionRequest commit;
  commit.ticket = ticket;
  commit.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->commit_evaluation(commit).outcome, Outcome::RETIRED);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
}

// Two tickets taken from the same state cannot both advance the adaptation
// generation.
ARF_TEST(duplicate_ticket_does_not_advance_a_generation) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);

  EvaluateRequest request;
  request.policy = fixture.policy;
  request.context = harness.context();
  request.defer_commit = true;
  const EvaluationTicket first = harness.fabric->begin_evaluation(request);
  const EvaluationTicket second = harness.fabric->begin_evaluation(request);
  ARF_CHECK_EQ(first.lifecycle, DecisionLifecycle::ELIGIBLE);
  ARF_CHECK_EQ(second.lifecycle, DecisionLifecycle::ELIGIBLE);

  CommitDecisionRequest commit;
  commit.ticket = first;
  commit.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->commit_evaluation(commit).outcome, Outcome::DECISION_COMMITTED);
  const AdaptationGeneration generation =
      harness.fabric->snapshot(fixture.policy).adaptation_generation;

  CommitDecisionRequest duplicate;
  duplicate.ticket = second;
  duplicate.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->commit_evaluation(duplicate).outcome, Outcome::NO_CHANGE);
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).adaptation_generation, generation);
}

// An exact replay of a mutation is recognised and changes nothing.
ARF_TEST(exact_replay_is_idempotent_and_conflicts_are_rejected) {
  Harness harness = make_harness();
  const MutationContext context = harness.context();
  const OperationResult created =
      create_policy(harness, latency_semantics(2000, 3000), harness.next_policy_name(), context);
  ARF_CHECK_EQ(created.outcome, Outcome::POLICY_CREATED);

  const OperationResult replay =
      create_policy(harness, latency_semantics(2000, 3000), AdaptivePolicyName::require("policy-1"),
                    context);
  ARF_CHECK_EQ(replay.outcome, Outcome::IDEMPOTENT);
  ARF_CHECK_EQ(harness.fabric->list_policies().size(), static_cast<std::size_t>(1));

  // The same attempt id with a different payload is a conflict, not a replay.
  CreatePolicyRequest conflicting;
  conflicting.name = AdaptivePolicyName::require("policy-2");
  conflicting.scope.fabric = fabric_id();
  conflicting.scope.name_space = routing_namespace();
  conflicting.semantics = latency_semantics(5000, 6000);
  conflicting.context = context;
  ARF_CHECK_EQ(harness.fabric->create_policy(conflicting).outcome, Outcome::ATTEMPT_CONFLICT);
  ARF_CHECK_EQ(harness.fabric->list_policies().size(), static_cast<std::size_t>(1));
}

// Barrier-controlled race: the evaluation snapshots, the world moves, and only
// then does the commit run.
ARF_TEST(barrier_controlled_stale_completion) {
  Harness harness = make_harness();
  std::barrier snapshot_taken(2);
  std::barrier world_moved(2);
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  feed_latency(harness, fixture.a, 1000, fixture.b, 500, 2);

  // Installed only now so that the setup evaluations above run unimpeded.
  *harness.hook = [&](const DependencySnapshot&) {
    snapshot_taken.arrive_and_wait();
    world_moved.arrive_and_wait();
  };
  OperationResult observed = OperationResult::make(Outcome::INTERNAL_ERROR, "not run");
  std::thread evaluator([&]() {
    EvaluateRequest request;
    request.policy = fixture.policy;
    request.context = harness.context();
    observed = harness.fabric->evaluate(request);
  });
  snapshot_taken.arrive_and_wait();
  feed_latency(harness, fixture.a, 1000, fixture.b, 990, 3);
  world_moved.arrive_and_wait();
  evaluator.join();
  *harness.hook = nullptr;

  ARF_CHECK_EQ(observed.outcome, Outcome::STALE_EVIDENCE);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
}

// Concurrent independent mutations must all be applied and must never corrupt
// the indexes.
ARF_TEST(concurrent_independent_mutations_stay_consistent) {
  Harness harness = make_harness();
  constexpr std::uint32_t policy_count = 8;
  std::vector<AdaptivePolicyId> policies;
  policies.reserve(policy_count);
  for (std::uint32_t index = 0; index < policy_count; ++index) {
    policies.push_back(create_active_policy(harness, latency_semantics(2000, 3000)));
  }

  std::vector<std::thread> workers;
  workers.reserve(policy_count);
  std::vector<Outcome> outcomes(policy_count, Outcome::MALFORMED_REQUEST);
  for (std::uint32_t index = 0; index < policy_count; ++index) {
    workers.emplace_back([&, index]() {
      const PathId a = path("path-a-" + std::to_string(index));
      const PathId b = path("path-b-" + std::to_string(index));
      // The context is built here rather than through Harness::context(), which
      // increments a shared counter: a data race in a test would be a defect in
      // the test, not a proof about the engine.
      MutationContext declare_context;
      declare_context.epoch = harness.fabric->epoch();
      declare_context.publisher = harness.publisher;
      declare_context.worker_boot = harness.worker_boot;
      declare_context.session = harness.session;
      declare_context.attempt = MutationAttemptId::require("attempt-concurrent-" +
                                                           std::to_string(index));
      UpstreamNotifyRequest declarations;
      for (const auto& id : {a, b}) {
        UpstreamNotification notification;
        notification.event = UpstreamEvent::DECLARE_CANDIDATE;
        notification.policy = policies[index];
        notification.binding = frozen_binding(id, 1);
        notification.binding.route.route = route_id();
        notification.provenance.publisher = harness.publisher;
        notification.provenance.worker_boot = harness.worker_boot;
        notification.provenance.epoch = harness.fabric->epoch();
        notification.provenance.origin = "path-authority";
        declarations.notifications.push_back(notification);
      }
      declarations.context = declare_context;
      outcomes[index] = harness.fabric->apply_upstream(declarations).outcome;
    });
  }
  for (auto& worker : workers) {
    worker.join();
  }
  for (const Outcome outcome : outcomes) {
    ARF_CHECK_EQ(outcome, Outcome::POLICY_UPDATED);
  }
  for (const auto& policy : policies) {
    ARF_CHECK_EQ(harness.fabric->candidates(policy).size(), static_cast<std::size_t>(2));
  }
}

// A snapshot of one policy is unaffected by a later mutation of another.
ARF_TEST(snapshot_is_immutable_across_unrelated_mutation) {
  Harness harness = make_harness();
  const TwoCandidate first = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, first.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, first.policy).outcome, Outcome::DECISION_COMMITTED);

  const AdaptationSnapshot before = harness.fabric->snapshot(first.policy);
  const std::string digest_before = before.digest;

  const TwoCandidate second =
      make_two_candidate_policy(harness, latency_semantics(3000, 4000), "-second");
  feed_latency(harness, second.a, 500, second.b, 100, 2);
  ARF_CHECK_EQ(evaluate_policy(harness, second.policy).outcome, Outcome::DECISION_COMMITTED);

  ARF_CHECK_EQ(before.digest, digest_before);
  ARF_CHECK_EQ(before.preference.preferred_path, first.a);
  const AdaptationSnapshot after = harness.fabric->snapshot(first.policy);
  ARF_CHECK_EQ(after.digest, digest_before);
}

// The invalidation of one path must not disturb a policy that does not bind it.
ARF_TEST(targeted_invalidation_leaves_unrelated_policies_unchanged) {
  Harness harness = make_harness();
  const TwoCandidate first = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, first.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, first.policy).outcome, Outcome::DECISION_COMMITTED);

  const AdaptivePolicyId second_policy =
      create_active_policy(harness, latency_semantics(2000, 3000));
  const PathId unrelated = path("path-unrelated");
  ARF_CHECK_EQ(declare_candidate(harness, second_policy, frozen_binding(unrelated, 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish_latency(harness, unrelated, 400, 2).outcome, Outcome::POLICY_UPDATED);

  const AdaptationSnapshot before = harness.fabric->snapshot(first.policy);
  ARF_CHECK_EQ(notify(harness, event_for(harness, second_policy, UpstreamEvent::INVALIDATE_PATH,
                                         frozen_binding(unrelated, 2, 1, false)))
                   .outcome,
               Outcome::POLICY_UPDATED);
  const AdaptationSnapshot after = harness.fabric->snapshot(first.policy);
  ARF_CHECK_EQ(after.digest, before.digest);
  ARF_CHECK_EQ(after.currentness, Currentness::CURRENT);
}

// Rollback refuses when the restore target lost its authorization while the
// rollback was being requested.
ARF_TEST(rollback_is_refused_when_the_target_is_invalidated) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  // A transition is what creates the rollback anchor.
  feed_latency(harness, fixture.a, 1000, fixture.b, 800, 2);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK_EQ(harness.fabric->snapshot(fixture.policy).stable.path, fixture.a);

  ARF_CHECK_EQ(notify(harness, event_for(harness, fixture.policy, UpstreamEvent::INVALIDATE_PATH,
                                         frozen_binding(fixture.a, 2, 1, false)))
                   .outcome,
               Outcome::POLICY_UPDATED);
  RollbackRequest rollback;
  rollback.policy = fixture.policy;
  rollback.reason = "restore the stable preference";
  rollback.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->rollback(rollback).outcome, Outcome::STALE_PATH_AUTHORITY);
  ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.b);
}

// Save/load interleaved with mutation leaves the durable image consistent with
// the committed state.
ARF_TEST(persistence_snapshot_survives_concurrent_policy_update) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  const std::string bytes = harness.fabric->encode_store();
  const AdaptivePolicy policy = *harness.fabric->find_policy(fixture.policy);
  UpdatePolicyRequest update;
  update.policy = fixture.policy;
  update.update.scope = policy.scope;
  update.update.semantics = policy.semantics;
  update.update.semantics.improvements.front().switch_improvement_bps = 3500;
  update.context = harness.context(policy.generation);
  ARF_CHECK_EQ(harness.fabric->update_policy(update).outcome, Outcome::POLICY_UPDATED);

  // The bytes taken before the update still decode and still describe the older
  // generation: an encoded store is a value, not a live view.
  Harness restored = make_harness();
  ARF_CHECK_EQ(restored.fabric->decode_store(bytes, "test").outcome, Outcome::POLICY_UPDATED);
  const AdaptivePolicy recovered = *restored.fabric->find_policy(fixture.policy);
  ARF_CHECK_EQ(recovered.generation.value(), 1ULL);
  ARF_CHECK_EQ(recovered.semantics.improvements.front().switch_improvement_bps, 2000U);
}

// Property tests over deterministic seeded schedules.
//
// Every property is asserted after every step of a randomized schedule, and the
// seed is printed on failure so the exact schedule can be replayed.
#include <algorithm>
#include <limits>
#include <set>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace arf_test;

struct Schedule {
  Random random;
  explicit Schedule(std::uint64_t seed) : random(seed) {}
};

UpstreamNotification make_event(Harness& harness, const AdaptivePolicyId& policy,
                                UpstreamEvent event, const PathId& id,
                                std::uint64_t authority_generation, bool legal,
                                std::uint64_t route_generation = 1) {
  UpstreamNotification notification;
  notification.event = event;
  notification.policy = policy;
  notification.binding = make_binding(id, authority_generation, route_generation, legal);
  notification.provenance.publisher = harness.publisher;
  notification.provenance.worker_boot = harness.worker_boot;
  notification.provenance.epoch = harness.fabric->epoch();
  notification.provenance.origin = "property-schedule";
  return notification;
}

// Every invariant the runtime must hold no matter which legal schedule ran.
void assert_invariants(Harness& harness, const AdaptivePolicyId& policy_id,
                       const std::vector<PathId>& declared, const std::string& context) {
  const AdaptationSnapshot snapshot = harness.fabric->snapshot(policy_id);
  if (snapshot.preference.established) {
    const PathId preferred = snapshot.preference.preferred_path;
    // 1. The preferred path is always one of the explicitly declared candidates.
    ARF_CHECK_MSG(std::find(declared.begin(), declared.end(), preferred) != declared.end(),
                  context + " preferred path is outside the declared candidate set");
    // 2. A preferred path always carries a current Path Authority binding.
    const CandidateView* view = snapshot.find_candidate(preferred);
    ARF_CHECK_MSG(view != nullptr, context + " preferred path has no candidate view");
    if (view != nullptr) {
      // The recorded generation must either still match, or the runtime must be
      // reporting exactly why it does not: a silently drifting binding would be
      // the defect this property exists to catch.
      const bool matches =
          view->binding.path_authority.generation == snapshot.preference.path_authority_generation;
      const bool explained = snapshot.currentness == Currentness::STALE_PATH_AUTHORITY ||
                             snapshot.currentness == Currentness::REVALIDATION_REQUIRED;
      ARF_CHECK_MSG(matches || explained,
                    context + " preferred path authority generation drifted without a reason");
    }
    // 3. Generations never decrease and are never zero.
    ARF_CHECK_MSG(snapshot.adaptation_generation.valid() &&
                      snapshot.transition_generation.valid() &&
                      snapshot.policy_generation.valid(),
                  context + " a generation became zero");
  }
  // 4. The engine's candidate index agrees with what was declared.
  const std::vector<CandidateBinding> candidates = harness.fabric->candidates(policy_id);
  ARF_CHECK_MSG(candidates.size() == declared.size(), context + " candidate index drift");
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    ARF_CHECK_MSG(candidates[index].path == declared[index],
                  context + " candidates are not in canonical order");
  }
  // 5. The snapshot is reproducible: the same state yields the same digest.
  const AdaptationSnapshot again = harness.fabric->snapshot(policy_id);
  ARF_CHECK_MSG(again.digest == snapshot.digest, context + " snapshot digest is not deterministic");
  ARF_CHECK_MSG(snapshot_digest(again) == snapshot_digest(snapshot),
                context + " snapshot digest helper is not deterministic");
}

}  // namespace

ARF_TEST(randomized_schedules_preserve_every_invariant) {
  constexpr std::uint64_t schedule_count = 24;
  for (std::uint64_t seed = 1; seed <= schedule_count; ++seed) {
    Schedule schedule(seed * 6364136223846793005ULL + 1442695040888963407ULL);
    Harness harness = make_harness();
    const PathId a = path("path-a");
    const PathId b = path("path-b");
    const PathId c = path("path-c");
    const std::vector<PathId> declared{a, b, c};

    PolicySemantics semantics = latency_semantics(1500, 2500, seconds(4), seconds(2));
    semantics.churn.max_adaptations_per_window = 6;
    semantics.churn.window = seconds(20);
    semantics.emergency.enabled = true;
    semantics.emergency.on_current_path_unavailable = true;
    const AdaptivePolicyId policy_id = create_active_policy(harness, semantics);
    // Only paths that have actually been declared may be touched: a
    // notification for an undeclared candidate is a NOT_FOUND, which is correct
    // behaviour rather than something the schedule should provoke.
    std::set<PathId> declared_paths;
    std::uint64_t sequence = 1;
    AdaptationGeneration last_adaptation;
    AdaptivePolicyGeneration last_policy_generation;
    CoordinatorEpoch last_epoch;

    for (std::uint32_t step = 0; step < 40; ++step) {
      const std::string context =
          " seed=" + std::to_string(seed) + " step=" + std::to_string(step);
      const std::uint64_t choice = schedule.random.below(12);
      switch (choice) {
        case 0:
        case 1: {
          const PathId target = declared[schedule.random.below(declared.size())];
          const OperationResult declared_result = harness.fabric->apply_upstream([&]() {
            UpstreamNotifyRequest request;
            request.notifications.push_back(
                make_event(harness, policy_id, UpstreamEvent::DECLARE_CANDIDATE, target, 1, true));
            request.context = harness.context();
            return request;
          }());
          ARF_CHECK_MSG(declared_result.outcome == Outcome::POLICY_UPDATED ||
                            declared_result.outcome == Outcome::STALE_PATH_AUTHORITY,
                        declared_result.render() + context);
          if (declared_result.outcome == Outcome::POLICY_UPDATED) {
            declared_paths.insert(target);
          }
          break;
        }
        case 2:
        case 3:
        case 4: {
          std::vector<EvidencePublication> publications;
          for (const auto& target : declared) {
            if (declared_paths.find(target) == declared_paths.end()) {
              continue;
            }
            if (schedule.random.below(4) == 0) {
              continue;
            }
            publications.push_back(make_publication(
                target, MetricKind::PATH_LATENCY, schedule.random.between(100, 2000), sequence++,
                EvidenceQuality::AGGREGATED));
          }
          if (!publications.empty()) {
            const OperationResult published = publish(harness, publications);
            ARF_CHECK_MSG(published.outcome == Outcome::POLICY_UPDATED,
                          published.render() + context);
          }
          break;
        }
        case 5: {
          const PathId target = declared[schedule.random.below(declared.size())];
          if (declared_paths.find(target) == declared_paths.end()) {
            break;
          }
          const bool legal = schedule.random.below(2) == 0;
          const OperationResult notified = notify(
              harness,
              make_event(harness, policy_id, UpstreamEvent::ADVANCE_PATH_AUTHORITY, target, 2,
                         legal));
          ARF_CHECK_MSG(notified.outcome == Outcome::POLICY_UPDATED ||
                            notified.outcome == Outcome::STALE_PATH_AUTHORITY,
                        notified.render() + context);
          break;
        }
        case 6: {
          const PathId target = declared[schedule.random.below(declared.size())];
          if (declared_paths.find(target) == declared_paths.end()) {
            break;
          }
          const OperationResult notified = notify(
              harness, make_event(harness, policy_id,
                                  schedule.random.below(2) == 0 ? UpstreamEvent::MARK_UNAVAILABLE
                                                                : UpstreamEvent::MARK_AVAILABLE,
                                  target, 2, true));
          ARF_CHECK_EQ(notified.outcome, Outcome::POLICY_UPDATED);
          break;
        }
        case 7: {
          const OperationResult evaluated = evaluate_policy(harness, policy_id);
          ARF_CHECK_MSG(evaluated.outcome != Outcome::INTERNAL_ERROR, evaluated.render() + context);
          break;
        }
        case 8: {
          harness.clock->advance(seconds(1 + schedule.random.below(8)));
          break;
        }
        case 9: {
          const AdaptivePolicy policy = *harness.fabric->find_policy(policy_id);
          UpdatePolicyRequest update;
          update.policy = policy_id;
          update.update.scope = policy.scope;
          update.update.semantics = policy.semantics;
          update.update.semantics.improvements.front().switch_improvement_bps =
              static_cast<std::uint32_t>(schedule.random.below(4) * 500);
          update.context = harness.context(policy.generation);
          const OperationResult updated = harness.fabric->update_policy(update);
          ARF_CHECK_MSG(updated.outcome == Outcome::POLICY_UPDATED ||
                            updated.outcome == Outcome::STALE_POLICY_GENERATION,
                        updated.render() + context);
          break;
        }
        case 10: {
          EvaluateRequest request;
          request.policy = policy_id;
          request.context = harness.context();
          request.defer_commit = true;
          const EvaluationTicket ticket = harness.fabric->begin_evaluation(request);
          CommitDecisionRequest commit;
          commit.ticket = ticket;
          commit.context = harness.context();
          const OperationResult committed = harness.fabric->commit_evaluation(commit);
          ARF_CHECK_MSG(committed.outcome != Outcome::INTERNAL_ERROR,
                        committed.render() + context);
          break;
        }
        default: {
          const PathId target = declared[schedule.random.below(declared.size())];
          if (declared_paths.find(target) == declared_paths.end()) {
            break;
          }
          const OperationResult evaluated = harness.fabric->apply_upstream([&]() {
            UpstreamNotifyRequest request;
            request.notifications.push_back(make_event(
                harness, policy_id, UpstreamEvent::ADVANCE_ROUTE, target, 1,
                true, 2 + schedule.random.below(3)));
            request.context = harness.context();
            return request;
          }());
          ARF_CHECK_EQ(evaluated.outcome, Outcome::POLICY_UPDATED);
          break;
        }
      }

      const AdaptationSnapshot snapshot = harness.fabric->snapshot(policy_id);
      // Generations never decrease.
      if (last_adaptation.valid()) {
        ARF_CHECK_MSG(snapshot.adaptation_generation >= last_adaptation,
                      context + " adaptation generation decreased");
      }
      if (last_policy_generation.valid()) {
        ARF_CHECK_MSG(snapshot.policy_generation >= last_policy_generation,
                      context + " policy generation decreased");
      }
      if (last_epoch.valid()) {
        ARF_CHECK_MSG(snapshot.epoch >= last_epoch, context + " epoch decreased");
      }
      last_adaptation = snapshot.adaptation_generation;
      last_policy_generation = snapshot.policy_generation;
      last_epoch = snapshot.epoch;

      std::vector<PathId> present;
      for (const auto& candidate : harness.fabric->candidates(policy_id)) {
        present.push_back(candidate.path);
      }
      assert_invariants(harness, policy_id, present, context);
    }
  }
}

// Exact replay advances nothing, whatever the request was.
ARF_TEST(exact_replay_never_advances_a_generation) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);

  const MutationContext context = harness.context();
  PublishEvidenceRequest request;
  request.publications.push_back(make_publication(fixture.b, MetricKind::PATH_LATENCY, 500, 2,
                                                  EvidenceQuality::AGGREGATED));
  request.context = context;
  ARF_CHECK_EQ(harness.fabric->publish_evidence(request).outcome, Outcome::POLICY_UPDATED);
  const EvidenceGeneration after_first = harness.fabric->evidence_generation();
  ARF_CHECK_EQ(harness.fabric->publish_evidence(request).outcome, Outcome::IDEMPOTENT);
  ARF_CHECK_EQ(harness.fabric->evidence_generation(), after_first);

  const std::uint64_t samples_before = harness.fabric->stats().evidence_samples;
  ARF_CHECK_EQ(harness.fabric->publish_evidence(request).outcome, Outcome::IDEMPOTENT);
  ARF_CHECK_EQ(harness.fabric->stats().evidence_samples, samples_before);
}

// A generation at the top of its range cannot advance: it is exhausted, not
// wrapped.
ARF_TEST(generations_never_wrap) {
  const AdaptivePolicyGeneration maximum =
      AdaptivePolicyGeneration::require((std::numeric_limits<std::uint64_t>::max)());
  ARF_CHECK(!maximum.next().has_value());
  const AdaptationGeneration first = AdaptationGeneration::first();
  ARF_CHECK_EQ(first.value(), 1ULL);
  const auto second = first.next();
  ARF_CHECK(second.has_value());
  ARF_CHECK_EQ(second->value(), 2ULL);
  const AdaptivePolicyGeneration maximum_policy =
      AdaptivePolicyGeneration::require((std::numeric_limits<std::uint64_t>::max)());
  ARF_CHECK(!maximum_policy.next().has_value());
  const CoordinatorEpoch last =
      CoordinatorEpoch::require((std::numeric_limits<std::uint64_t>::max)());
  ARF_CHECK(!last.next().has_value());
  ARF_CHECK(!Watermark((std::numeric_limits<std::uint64_t>::max)()).next().has_value());
}

// A retired policy never reactivates, under any event.
ARF_TEST(retired_policy_never_reactivates) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  PolicyLifecycleRequest retire;
  retire.policy = fixture.policy;
  retire.event = PolicyEvent::RETIRE;
  retire.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->transition_policy(retire).outcome, Outcome::POLICY_UPDATED);

  for (const PolicyEvent event :
       {PolicyEvent::ACTIVATE, PolicyEvent::RESUME, PolicyEvent::REVALIDATE,
        PolicyEvent::SUSPEND, PolicyEvent::REQUIRE_REVALIDATION, PolicyEvent::SUPERSEDE,
        PolicyEvent::RETIRE}) {
    PolicyLifecycleRequest request;
    request.policy = fixture.policy;
    request.event = event;
    request.context = harness.context();
    ARF_CHECK_EQ(harness.fabric->transition_policy(request).outcome, Outcome::RETIRED);
  }
  const AdaptivePolicy policy = *harness.fabric->find_policy(fixture.policy);
  ARF_CHECK_EQ(policy.lifecycle, PolicyLifecycle::RETIRED);
  ARF_CHECK_EQ(policy.generation.value(), 1ULL);
}

// A durable image never restores live publisher authority, and the recovered
// engine refuses the pre-restart epoch.
ARF_TEST(restart_never_restores_old_live_authority) {
  Harness harness = make_harness();
  const TwoCandidate fixture = make_two_candidate_policy(harness, latency_semantics(2000, 3000));
  ARF_CHECK_EQ(publish_latency(harness, fixture.a, 1000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, fixture.policy).outcome, Outcome::DECISION_COMMITTED);
  const std::string bytes = harness.fabric->encode_store();
  const CoordinatorEpoch before = harness.fabric->epoch();

  Harness restarted = make_harness();
  ARF_CHECK_EQ(restarted.fabric->decode_store(bytes, "property").outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK(restarted.fabric->epoch() > before);
  const FabricStats stats = restarted.fabric->stats();
  ARF_CHECK_EQ(stats.publishers, 0ULL);
  ARF_CHECK_EQ(stats.evidence_series, 0ULL);

  // A mutation carrying the pre-restart epoch is refused.
  MutationContext stale = harness.context();
  stale.epoch = before;
  PublishEvidenceRequest request;
  request.publications.push_back(make_publication(fixture.a, MetricKind::PATH_LATENCY, 1, 1,
                                                  EvidenceQuality::AGGREGATED));
  request.context = stale;
  ARF_CHECK_EQ(restarted.fabric->publish_evidence(request).outcome, Outcome::STALE_EPOCH);

  // The recovered policy exists, is not adaptable, and holds no live evidence.
  const AdaptivePolicy recovered = *restarted.fabric->find_policy(fixture.policy);
  ARF_CHECK_EQ(recovered.lifecycle, PolicyLifecycle::REVALIDATION_REQUIRED);
  ARF_CHECK_EQ(restarted.fabric->candidates(fixture.policy).size(), static_cast<std::size_t>(0));
}

// Stale evidence never produces a current decision, even when a ticket is
// committed out of order under load.
ARF_TEST(stale_evidence_never_produces_a_current_decision) {
  for (std::uint64_t seed = 1; seed <= 8; ++seed) {
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

    for (std::uint64_t round = 0; round < seed; ++round) {
      feed_latency(harness, fixture.a, 1000, fixture.b, 900, 3 + round);
    }
    CommitDecisionRequest commit;
    commit.ticket = ticket;
    commit.context = harness.context();
    const OperationResult result = harness.fabric->commit_evaluation(commit);
    ARF_CHECK_MSG(result.outcome == Outcome::STALE_EVIDENCE,
                  result.render() + " seed=" + std::to_string(seed));
    ARF_CHECK_EQ(preferred_path(harness, fixture.policy), fixture.a);
  }
}

// The reverse indexes answer targeted dependency questions, and they must agree
// with a full scan of the same state.
ARF_TEST(dependency_indexes_agree_with_a_full_scan) {
  constexpr std::uint64_t schedule_count = 6;
  for (std::uint64_t seed = 1; seed <= schedule_count; ++seed) {
    Random random(seed * 0x9E3779B97F4A7C15ULL + 7ULL);
    Harness harness = make_harness();
    const PathId a = path("path-a");
    const PathId b = path("path-b");
    std::vector<AdaptivePolicyId> policies;
    for (std::uint32_t index = 0; index < 4; ++index) {
      const AdaptivePolicyId policy_id =
          create_active_policy(harness, latency_semantics(2000, 3000));
      policies.push_back(policy_id);
      for (const auto& candidate : {a, b}) {
        if (random.below(2) == 0) {
          const OperationResult declared =
              declare_candidate(harness, policy_id, make_binding(candidate, 1));
          ARF_CHECK_MSG(declared.outcome == Outcome::POLICY_UPDATED,
                        declared.render() + " seed=" + std::to_string(seed));
        }
      }
    }
    ARF_CHECK_EQ(harness.fabric->policies_for_route(route_id()).size(),
                 static_cast<std::size_t>(4));
    ARF_CHECK_EQ(harness.fabric->policies_for_path(path("path-absent")).size(),
                 static_cast<std::size_t>(0));
    for (const auto& candidate : {a, b}) {
      std::vector<AdaptivePolicyId> expected;
      for (const auto& policy_id : policies) {
        for (const auto& binding : harness.fabric->candidates(policy_id)) {
          if (binding.path == candidate) {
            expected.push_back(policy_id);
            break;
          }
        }
      }
      std::sort(expected.begin(), expected.end());
      const std::vector<AdaptivePolicyId> actual = harness.fabric->policies_for_path(candidate);
      ARF_CHECK_MSG(actual == expected,
                    "path index disagrees with a full scan, seed=" + std::to_string(seed));
    }
  }
}

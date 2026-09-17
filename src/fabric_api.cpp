// Engine persistence binding and the public forwarding surface.
#include <algorithm>
#include <atomic>
#include <filesystem>

#include "adaptive_routing/persistence.hpp"
#include "engine_impl.hpp"

namespace adaptive_routing::detail {

DurableState Impl::build_durable(const State& state) const {
  DurableState durable;
  durable.format_version = persistence_format_version;
  durable.epoch = state.epoch;
  durable.authority_generation = state.authority_generation;
  durable.evidence_generation = state.evidence_generation;
  durable.evidence_watermark = state.evidence_watermark;
  durable.upstream_watermark = state.upstream_watermark;
  for (const auto& entry : state.policies) {
    durable.policies.push_back(entry.second.policy);
    DurablePreference preference;
    preference.policy = entry.first;
    preference.preference = entry.second.preference;
    durable.preferences.push_back(std::move(preference));
    DurableStable stable;
    stable.policy = entry.first;
    stable.stable = entry.second.stable;
    durable.stable_states.push_back(std::move(stable));
    DurableTiming timing;
    timing.policy = entry.first;
    const Ticks current = now();
    // Durable time is stored as a *remaining* duration. A monotonic tick value
    // is meaningless in a different boot and is never written.
    timing.hold_down_active =
        entry.second.timing.hold_down_active && entry.second.timing.hold_down_deadline > current;
    timing.hold_down_remaining = timing.hold_down_active
                                     ? entry.second.timing.hold_down_deadline - current
                                     : 0;
    timing.hold_down_policy_generation = entry.second.policy.generation;
    timing.hold_down_locked_path = entry.second.timing.hold_down_locked_path;
    timing.cooldown_active =
        entry.second.timing.cooldown_active && entry.second.timing.cooldown_deadline > current;
    timing.cooldown_remaining = timing.cooldown_active
                                    ? entry.second.timing.cooldown_deadline - current
                                    : 0;
    timing.dampening_penalty = entry.second.timing.dampening_penalty;
    timing.dampening_decay_remaining =
        entry.second.timing.dampening_last_decay > current
            ? entry.second.timing.dampening_last_decay - current
            : 0;
    for (const Ticks stamp : entry.second.timing.churn_commits) {
      timing.churn_ages.push_back(current >= stamp ? current - stamp : 0);
    }
    durable.timings.push_back(std::move(timing));
    for (const auto& record : entry.second.history) {
      DurableHistoryEntry history_entry;
      history_entry.policy = entry.first;
      history_entry.record = record;
      durable.history.push_back(std::move(history_entry));
    }
  }
  for (const auto& entry : state.revocations) {
    durable.revocations.push_back(entry.second);
  }
  return durable;
}

OperationResult Impl::apply_durable(State& state, const DurableState& durable,
                                    std::string_view origin) {
  if (durable.format_version != persistence_format_version) {
    return make_result(Outcome::UNSUPPORTED_VERSION, "durable state carries an unsupported format",
                       AdaptivePolicyId(), state);
  }
  if (durable.policies.size() > static_cast<std::size_t>(limits_.max_policies) ||
      durable.revocations.size() > static_cast<std::size_t>(limits_.max_revocations) ||
      durable.history.size() > static_cast<std::size_t>(limits_.max_decision_history)) {
    return make_result(Outcome::RESOURCE_LIMIT,
                       "durable state exceeds a configured resource limit", AdaptivePolicyId(),
                       state);
  }
  const auto next_epoch = durable.epoch.next();
  const auto next_authority = durable.authority_generation.next();
  if (!next_epoch.has_value() || !next_authority.has_value()) {
    return make_result(Outcome::GENERATION_OVERFLOW,
                       "durable epoch or authority generation is exhausted", AdaptivePolicyId(),
                       state);
  }

  // Live process authority never survives recovery, and previously retained
  // in-memory artefacts are discarded so that nothing references a pre-restart
  // world.
  state = State{};
  state.epoch = *next_epoch;
  state.authority_generation = *next_authority;
  state.evidence_generation = durable.evidence_generation;
  state.evidence_watermark = durable.evidence_watermark;
  state.upstream_watermark = durable.upstream_watermark;

  for (const auto& policy : durable.policies) {
    PolicyRecord record;
    record.policy = policy;
    record.preference.route = policy.semantics.target.route;
    record.preference.multipath_set = policy.semantics.target.multipath_set;
    record.preference.adaptation_generation = AdaptationGeneration::first();
    record.preference.transition_generation = TransitionGeneration::first();
    if (config_.conservative_recovery && !policy_lifecycle_terminal(policy.lifecycle)) {
      // Recovered policies must be revalidated against fresh upstream state
      // before they can adapt again.
      record.policy.lifecycle = PolicyLifecycle::REVALIDATION_REQUIRED;
    }
    state.policies.emplace(policy.id, std::move(record));
    state.policy_names.emplace(policy.name, policy.id);
  }
  for (const auto& durable_preference : durable.preferences) {
    const auto position = state.policies.find(durable_preference.policy);
    if (position == state.policies.end()) {
      continue;
    }
    RoutingPreference preference = durable_preference.preference;
    preference.provenance.cause = AdaptationCause::RECOVERED;
    position->second.preference = preference;
  }
  for (const auto& durable_stable : durable.stable_states) {
    const auto position = state.policies.find(durable_stable.policy);
    if (position == state.policies.end()) {
      continue;
    }
    position->second.stable = durable_stable.stable;
  }
  const Ticks current = now();
  for (const auto& timing : durable.timings) {
    const auto position = state.policies.find(timing.policy);
    if (position == state.policies.end()) {
      continue;
    }
    TimingState& target = position->second.timing;
    // Re-arming a remaining duration against the new boot's monotonic clock is
    // conservative: a restarted hold-down can only be longer, never shorter.
    target.hold_down_active = timing.hold_down_active;
    target.hold_down_deadline = current + timing.hold_down_remaining;
    target.hold_down_locked_path = timing.hold_down_locked_path;
    target.cooldown_active = timing.cooldown_active;
    target.cooldown_deadline = current + timing.cooldown_remaining;
    target.dampening_penalty = timing.dampening_penalty;
    target.dampening_last_decay = current + timing.dampening_decay_remaining;
    for (const Ticks age : timing.churn_ages) {
      target.churn_commits.push_back(current >= age ? current - age : 0);
    }
  }
  for (const auto& revocation : durable.revocations) {
    const auto position = state.policies.find(revocation.policy);
    if (position == state.policies.end()) {
      continue;
    }
    position->second.revocation = revocation;
    state.revocations.emplace(revocation.policy, revocation);
  }
  for (const auto& history_entry : durable.history) {
    const AdaptationRecord& record = history_entry.record;
    // The per-policy history is rebuilt as well as the journal, so that a save
    // taken after a recovery still contains the history section and
    // decisions_for_policy() still answers for a recovered policy.
    const auto owner = state.policies.find(history_entry.policy);
    if (owner != state.policies.end()) {
      owner->second.history.push_back(record);
      prune_history(owner->second, limits_);
    }
    state.decision_journal.push_back(AdaptationDecision{});
    AdaptationDecision& decision = state.decision_journal.back();
    decision.id = record.decision;
    decision.policy = history_entry.policy;
    decision.lifecycle = record.lifecycle;
    decision.outcome = record.outcome;
    decision.suppression = record.suppression;
    decision.cause = record.cause;
    decision.current_preference = record.from_path;
    decision.target_preference = record.to_path;
    decision.adaptation_generation = record.adaptation_generation;
    decision.evidence_generation = record.evidence_generation;
    decision.epoch = record.epoch;
    decision.committed_at = record.committed_at;
    decision.digest = record.digest;
    decision.provenance.cause = AdaptationCause::RECOVERED;
  }
  while (state.decision_journal.size() > limits_.max_decision_history) {
    state.decision_journal.pop_front();
  }
  for (const auto& entry : state.policies) {
    reindex_policy(state, entry.first);
  }
  ++counters_.recoveries;
  counters_.epoch = state.epoch;
  counters_.authority_generation = state.authority_generation;
  counters_.evidence_generation = state.evidence_generation;
  return make_result(Outcome::POLICY_UPDATED,
                     "recovered " + std::to_string(state.policies.size()) +
                         " policy record(s) from " + std::string(origin) +
                         "; epoch is now " + std::to_string(state.epoch.value()) +
                         " and every recovered policy requires revalidation",
                     AdaptivePolicyId(), state);
}

std::string Impl::encode_store() const {
  std::shared_lock lock(mutex_);
  return encode_durable_state(build_durable(state_));
}

OperationResult Impl::save(const std::string& path) const {
  const std::string bytes = [this]() {
    std::shared_lock lock(mutex_);
    return encode_durable_state(build_durable(state_));
  }();
  if (bytes.size() > static_cast<std::size_t>(limits_.max_store_bytes)) {
    std::shared_lock lock(mutex_);
    return make_result(Outcome::RESOURCE_LIMIT, "durable state exceeds the configured store bound",
                       AdaptivePolicyId(), state_);
  }
  std::string error;
  if (!write_store_atomic(path, bytes, error)) {
    std::shared_lock lock(mutex_);
    return make_result(Outcome::INTERNAL_ERROR, "store could not be written: " + error,
                       AdaptivePolicyId(), state_);
  }
  std::shared_lock lock(mutex_);
  OperationResult result = make_result(Outcome::POLICY_UPDATED,
                                       "store written: " + std::to_string(bytes.size()) +
                                           " byte(s)",
                                       AdaptivePolicyId(), state_);
  result.mutated = true;
  return result;
}

OperationResult Impl::load(const std::string& path) {
  std::error_code code;
  if (!std::filesystem::exists(path, code)) {
    return make_result(Outcome::NOT_FOUND, "store does not exist", AdaptivePolicyId(), state_);
  }
  std::string error;
  const auto bytes = read_store_bytes(path, error);
  if (!bytes.has_value()) {
    return make_result(Outcome::CORRUPT_STORE, "store could not be read: " + error,
                       AdaptivePolicyId(), state_);
  }
  return decode_store(*bytes, path);
}

OperationResult Impl::decode_store(std::string_view bytes, std::string_view origin) {
  const StoreDecodeResult decoded = decode_durable_state(bytes);
  if (!decoded.ok()) {
    std::shared_lock lock(mutex_);
    OperationResult result = make_result(
        Outcome::CORRUPT_STORE,
        "store rejected: " + std::string(to_string(decoded.status)) +
            (decoded.detail.empty() ? "" : " (" + decoded.detail + ")"),
        AdaptivePolicyId(), state_);
    return result;
  }
  std::unique_lock lock(mutex_);
  return apply_durable(state_, decoded.state, origin);
}

}  // namespace adaptive_routing::detail

// ---------------------------------------------------------------------------
// Public forwarding surface
// ---------------------------------------------------------------------------

namespace adaptive_routing {

std::string FabricStats::render() const {
  std::string text = "policies=" + std::to_string(policies);
  text += " adaptable=" + std::to_string(adaptable_policies);
  text += " revoked=" + std::to_string(revoked_policies);
  text += " retired=" + std::to_string(retired_policies);
  text += " candidates=" + std::to_string(candidates);
  text += " evidence_series=" + std::to_string(evidence_series);
  text += " evidence_samples=" + std::to_string(evidence_samples);
  text += " committed=" + std::to_string(decisions_committed);
  text += " suppressed=" + std::to_string(decisions_suppressed);
  text += " rejected=" + std::to_string(decisions_rejected);
  text += " evaluations=" + std::to_string(evaluations);
  text += " stale_commit_rejections=" + std::to_string(stale_commit_rejections);
  text += " idempotent_replays=" + std::to_string(idempotent_replays);
  text += " attempt_conflicts=" + std::to_string(attempt_conflicts);
  text += " publishers=" + std::to_string(publishers);
  text += " fenced_workers=" + std::to_string(fenced_workers);
  text += " revocations=" + std::to_string(revocations);
  text += " recoveries=" + std::to_string(recoveries);
  text += " epoch=" + std::to_string(epoch.value());
  text += " authority=" + std::to_string(authority_generation.value());
  text += " evidence_generation=" + std::to_string(evidence_generation.value());
  return text;
}

OperationResult AdaptiveRoutingFabric::create_policy(const CreatePolicyRequest& request) {
  return impl_->create_policy(request);
}

OperationResult AdaptiveRoutingFabric::update_policy(const UpdatePolicyRequest& request) {
  return impl_->update_policy(request);
}

OperationResult AdaptiveRoutingFabric::transition_policy(const PolicyLifecycleRequest& request) {
  return impl_->transition_policy(request);
}

OperationResult AdaptiveRoutingFabric::revoke_policy(const AdaptivePolicyId& policy,
                                                     RevocationReason reason, std::string detail,
                                                     const MutationContext& context) {
  return impl_->revoke_policy(policy, reason, std::move(detail), context);
}

std::optional<AdaptivePolicy> AdaptiveRoutingFabric::find_policy(
    const AdaptivePolicyId& policy) const {
  return impl_->find_policy(policy);
}

std::vector<AdaptivePolicy> AdaptiveRoutingFabric::list_policies() const {
  return impl_->list_policies();
}

std::optional<RevocationRecord> AdaptiveRoutingFabric::find_revocation(
    const AdaptivePolicyId& policy) const {
  return impl_->find_revocation(policy);
}

std::vector<RevocationRecord> AdaptiveRoutingFabric::list_revocations() const {
  return impl_->list_revocations();
}

OperationResult AdaptiveRoutingFabric::apply_upstream(const UpstreamNotifyRequest& request) {
  return impl_->apply_upstream(request);
}

std::vector<CandidateBinding> AdaptiveRoutingFabric::candidates(
    const AdaptivePolicyId& policy) const {
  return impl_->candidates(policy);
}

std::vector<AdaptivePolicyId> AdaptiveRoutingFabric::policies_for_path(const PathId& path) const {
  return impl_->policies_for_path(path);
}

std::vector<AdaptivePolicyId> AdaptiveRoutingFabric::policies_for_route(const RouteId& route) const {
  return impl_->policies_for_route(route);
}

std::vector<AdaptivePolicyId> AdaptiveRoutingFabric::policies_for_multipath_set(
    const MultipathSetId& set) const {
  return impl_->policies_for_multipath_set(set);
}

std::vector<AdaptivePolicyId> AdaptiveRoutingFabric::policies_for_evidence_source(
    const EvidenceSourceId& source) const {
  return impl_->policies_for_evidence_source(source);
}

OperationResult AdaptiveRoutingFabric::publish_evidence(const PublishEvidenceRequest& request) {
  return impl_->publish_evidence(request);
}

EvidenceGeneration AdaptiveRoutingFabric::evidence_generation() const noexcept {
  return impl_->evidence_generation();
}

Watermark AdaptiveRoutingFabric::evidence_watermark() const noexcept {
  return impl_->evidence_watermark();
}

Watermark AdaptiveRoutingFabric::upstream_watermark() const noexcept {
  return impl_->upstream_watermark();
}

std::vector<EvidenceSeriesView> AdaptiveRoutingFabric::describe_evidence(
    const AdaptivePolicyId& policy) const {
  return impl_->describe_evidence(policy);
}

EvidenceSnapshotPtr AdaptiveRoutingFabric::capture_evidence(const AdaptivePolicyId& policy) const {
  return impl_->capture_evidence(policy);
}

EvaluationTicket AdaptiveRoutingFabric::begin_evaluation(const EvaluateRequest& request) {
  return impl_->begin_evaluation(request);
}

OperationResult AdaptiveRoutingFabric::commit_evaluation(const CommitDecisionRequest& request) {
  return impl_->commit_evaluation(request);
}

OperationResult AdaptiveRoutingFabric::evaluate(const EvaluateRequest& request) {
  return impl_->evaluate(request);
}

std::optional<AdaptationDecision> AdaptiveRoutingFabric::find_decision(
    const AdaptationDecisionId& decision) const {
  return impl_->find_decision(decision);
}

std::vector<AdaptationDecision> AdaptiveRoutingFabric::list_decisions(std::uint64_t limit) const {
  return impl_->list_decisions(limit);
}

std::vector<AdaptationDecision> AdaptiveRoutingFabric::decisions_for_policy(
    const AdaptivePolicyId& policy, std::uint64_t limit) const {
  return impl_->decisions_for_policy(policy, limit);
}

OperationResult AdaptiveRoutingFabric::rollback(const RollbackRequest& request) {
  return impl_->rollback(request);
}

OperationResult AdaptiveRoutingFabric::revalidate(const AdaptivePolicyId& policy,
                                                  RevalidationAttemptId attempt,
                                                  const MutationContext& context) {
  return impl_->revalidate(policy, std::move(attempt), context);
}

AdaptationSnapshot AdaptiveRoutingFabric::snapshot(const AdaptivePolicyId& policy) const {
  return impl_->snapshot(policy);
}

std::vector<SnapshotId> AdaptiveRoutingFabric::retained_snapshots() const {
  return impl_->retained_snapshots();
}

std::optional<AdaptationSnapshot> AdaptiveRoutingFabric::find_snapshot(
    const SnapshotId& snapshot) const {
  return impl_->find_snapshot(snapshot);
}

Explanation AdaptiveRoutingFabric::explain(ExplanationTopic topic,
                                           const AdaptivePolicyId& policy) const {
  return impl_->explain(topic, policy);
}

Explanation AdaptiveRoutingFabric::explain_decision(const AdaptationDecisionId& decision) const {
  return impl_->explain_decision(decision);
}

std::string AdaptiveRoutingFabric::encode_store() const { return impl_->encode_store(); }

OperationResult AdaptiveRoutingFabric::save(const std::string& path) const {
  return impl_->save(path);
}

OperationResult AdaptiveRoutingFabric::load(const std::string& path) { return impl_->load(path); }

OperationResult AdaptiveRoutingFabric::decode_store(std::string_view bytes,
                                                    std::string_view origin) {
  return impl_->decode_store(bytes, origin);
}

}  // namespace adaptive_routing

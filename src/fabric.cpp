// Engine construction, authority, indexing and diagnostics.
#include "engine_impl.hpp"

#include <algorithm>

#include "adaptive_routing/version.hpp"

namespace adaptive_routing::detail {

const CandidateRecord* PolicyRecord::find_candidate(const PathId& path) const noexcept {
  // Candidates are kept sorted by PathId, so lookup is a binary search.
  std::size_t low = 0;
  std::size_t high = candidates.size();
  while (low < high) {
    const std::size_t middle = low + (high - low) / 2;
    if (candidates[middle].binding.path < path) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  if (low == candidates.size() || !(candidates[low].binding.path == path)) {
    return nullptr;
  }
  return &candidates[low];
}

CandidateRecord* PolicyRecord::find_candidate(const PathId& path) noexcept {
  return const_cast<CandidateRecord*>(
      static_cast<const PolicyRecord*>(this)->find_candidate(path));
}

Impl::Impl(EngineConfig config)
    : config_(std::move(config)),
      limits_(config_.limits),
      clock_(config_.clock != nullptr ? config_.clock
                                      : std::shared_ptr<Clock>(const_cast<SteadyClock*>(
                                            &SteadyClock::instance()),
                                            [](SteadyClock*) {})),
      ids_(config_.id_prefix) {
  state_.epoch = CoordinatorEpoch::first();
  state_.authority_generation = AdaptiveAuthorityGeneration::first();
  state_.evidence_generation = EvidenceGeneration::first();
}

Impl::~Impl() = default;

Ticks Impl::now() const { return clock_->now(); }

// ---------------------------------------------------------------------------
// Result helpers
// ---------------------------------------------------------------------------

Outcome Impl::lifecycle_outcome(PolicyLifecycle lifecycle) const {
  switch (lifecycle) {
    case PolicyLifecycle::ACTIVE:
      return Outcome::NO_CHANGE;
    case PolicyLifecycle::DECLARED:
      return Outcome::SUSPENDED;
    case PolicyLifecycle::SUSPENDED:
      return Outcome::SUSPENDED;
    case PolicyLifecycle::REVALIDATION_REQUIRED:
      return Outcome::REVALIDATION_REQUIRED;
    case PolicyLifecycle::REVOKED:
      return Outcome::REVOKED;
    case PolicyLifecycle::SUPERSEDED:
      return Outcome::POLICY_SUPERSEDED;
    case PolicyLifecycle::RETIRED:
      return Outcome::RETIRED;
  }
  return Outcome::INTERNAL_ERROR;
}

OperationResult Impl::make_result(Outcome outcome, std::string detail,
                                  const AdaptivePolicyId& policy, const State& state) const {
  OperationResult result;
  result.outcome = outcome;
  result.detail = std::move(detail);
  result.policy = policy;
  result.epoch = state.epoch;
  result.evidence_generation = state.evidence_generation;
  if (policy.valid()) {
    const auto position = state.policies.find(policy);
    if (position != state.policies.end()) {
      result.policy_generation = position->second.policy.generation;
      result.adaptation_generation = position->second.preference.adaptation_generation;
      result.transition_generation = position->second.preference.transition_generation;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Caller authority
// ---------------------------------------------------------------------------

Impl::CallerCheck Impl::check_caller(const State& state, const MutationContext& context,
                                     const std::optional<RouteId>& route,
                                     const std::optional<MultipathSetId>& set) const {
  CallerCheck check;
  if (!context.has_caller_identity()) {
    check.outcome = Outcome::UNAUTHORIZED;
    check.detail = "caller identity is incomplete";
    return check;
  }
  if (state.epoch != context.epoch) {
    check.outcome = Outcome::STALE_EPOCH;
    check.detail = "request epoch " + std::to_string(context.epoch.value()) +
                   " is not the current epoch " + std::to_string(state.epoch.value());
    return check;
  }
  if (state.fenced_boots.find(context.worker_boot) != state.fenced_boots.end()) {
    check.outcome = Outcome::FENCED_WORKER;
    check.detail = "worker boot " + context.worker_boot.str() + " is permanently fenced";
    return check;
  }
  const auto registration = state.registrations.find(context.publisher);
  if (registration == state.registrations.end()) {
    check.outcome = Outcome::UNAUTHORIZED;
    check.detail = "publisher " + context.publisher.str() + " is not registered";
    return check;
  }
  if (!(registration->second.worker_boot == context.worker_boot)) {
    check.outcome = Outcome::STALE_WORKER;
    check.detail = "worker boot " + context.worker_boot.str() + " is not the live incarnation of " +
                   context.publisher.str();
    return check;
  }
  if (!(registration->second.session == context.session)) {
    check.outcome = Outcome::UNAUTHORIZED;
    check.detail = "session does not own this publisher registration";
    return check;
  }
  if (!registration->second.scope.well_formed()) {
    check.outcome = Outcome::UNAUTHORIZED_SCOPE;
    check.detail = "registered authority scope is malformed";
    return check;
  }
  const FabricId& fabric = registration->second.scope.fabric;
  const RoutingNamespace& name_space = registration->second.scope.name_space;
  if (route.has_value()) {
    if (!registration->second.scope.covers_route(fabric, name_space, *route)) {
      check.outcome = Outcome::UNAUTHORIZED_SCOPE;
      check.detail = "authority scope does not cover route " + route->str();
      return check;
    }
  }
  if (set.has_value() && !registration->second.scope.covers_multipath_set(fabric, name_space, *set)) {
    check.outcome = Outcome::UNAUTHORIZED_SCOPE;
    check.detail = "authority scope does not cover multipath set " + set->str();
    return check;
  }
  check.ok = true;
  check.registration = &registration->second;
  return check;
}

// ---------------------------------------------------------------------------
// Attempt replay recognition
// ---------------------------------------------------------------------------

std::optional<OperationResult> Impl::replay_check(State& state, const MutationAttemptId& attempt,
                                                  std::string_view fingerprint) {
  if (!attempt.valid()) {
    OperationResult result = make_result(Outcome::MALFORMED_REQUEST,
                                         "mutation attempt id is invalid", AdaptivePolicyId(), state);
    return result;
  }
  const auto position = state.attempts.find(attempt);
  if (position == state.attempts.end()) {
    return std::nullopt;
  }
  if (position->second.fingerprint == fingerprint) {
    ++counters_.idempotent_replays;
    OperationResult result = make_result(Outcome::IDEMPOTENT,
                                         "exact replay of " +
                                             std::string(to_string(position->second.outcome)),
                                         AdaptivePolicyId(), state);
    result.detail += position->second.detail.empty() ? "" : " " + position->second.detail;
    return result;
  }
  ++counters_.attempt_conflicts;
  OperationResult result =
      make_result(Outcome::ATTEMPT_CONFLICT,
                  "attempt id reused with a different payload", AdaptivePolicyId(), state);
  return result;
}

void Impl::record_attempt(State& state, const MutationAttemptId& attempt, std::string fingerprint,
                          Outcome outcome, std::string detail) {
  if (!attempt.valid()) {
    return;
  }
  AttemptRecord record;
  record.attempt = attempt;
  record.fingerprint = std::move(fingerprint);
  record.outcome = outcome;
  record.detail = std::move(detail);
  const auto existing = state.attempts.find(attempt);
  if (existing != state.attempts.end()) {
    existing->second = std::move(record);
    return;
  }
  state.attempts.emplace(attempt, std::move(record));
  state.attempt_order.push_back(attempt);
  prune_attempts(state);
}

void Impl::prune_attempts(State& state) {
  while (state.attempt_order.size() > limits_.max_attempts) {
    const MutationAttemptId oldest = state.attempt_order.front();
    state.attempt_order.pop_front();
    state.attempts.erase(oldest);
  }
}

std::optional<std::string> Impl::fingerprint_policy(const PolicyScope& scope,
                                                    const PolicySemantics& semantics) const {
  Digest digest;
  digest.write_tag("policy-payload");
  digest.write_string(scope.render());
  digest.write_string(semantics.render());
  return digest.hex();
}

void Impl::prune_history(PolicyRecord& record, const Limits& limits) const {
  while (record.history.size() > limits.max_history_per_policy) {
    record.history.pop_front();
  }
}

void Impl::retain_snapshot(State& state,
                           std::shared_ptr<const AdaptationSnapshot> snapshot) const {
  const SnapshotId id = snapshot->id;
  state.snapshots[id] = std::move(snapshot);
  state.snapshot_order.push_back(id);
  while (state.snapshot_order.size() > limits_.max_snapshot_history) {
    const SnapshotId oldest = state.snapshot_order.front();
    state.snapshot_order.pop_front();
    state.snapshots.erase(oldest);
  }
}

// ---------------------------------------------------------------------------
// Reverse indexes
// ---------------------------------------------------------------------------

void Impl::unindex_policy(State& state, const AdaptivePolicyId& policy) {
  const auto record = state.policies.find(policy);
  if (record == state.policies.end()) {
    return;
  }
  for (const auto& candidate : record->second.candidates) {
    const auto position = state.policies_by_path.find(candidate.binding.path);
    if (position != state.policies_by_path.end()) {
      position->second.erase(policy);
      if (position->second.empty()) {
        state.policies_by_path.erase(position);
      }
    }
  }
  const RouteId route = record->second.policy.semantics.target.route;
  const auto by_route = state.policies_by_route.find(route);
  if (by_route != state.policies_by_route.end()) {
    by_route->second.erase(policy);
    if (by_route->second.empty()) {
      state.policies_by_route.erase(by_route);
    }
  }
  if (record->second.policy.semantics.target.multipath_set.has_value()) {
    const auto by_set =
        state.policies_by_set.find(*record->second.policy.semantics.target.multipath_set);
    if (by_set != state.policies_by_set.end()) {
      by_set->second.erase(policy);
      if (by_set->second.empty()) {
        state.policies_by_set.erase(by_set);
      }
    }
  }
  std::set<EvidenceSourceId> sources;
  for (const auto& entry : state.evidence) {
    for (const auto& candidate : record->second.candidates) {
      if (entry.first.path == candidate.binding.path) {
        sources.insert(entry.first.source);
      }
    }
  }
  for (const auto& source : sources) {
    const auto by_source = state.policies_by_source.find(source);
    if (by_source != state.policies_by_source.end()) {
      by_source->second.erase(policy);
      if (by_source->second.empty()) {
        state.policies_by_source.erase(by_source);
      }
    }
  }
}

void Impl::reindex_policy(State& state, const AdaptivePolicyId& policy) {
  const auto record = state.policies.find(policy);
  if (record == state.policies.end()) {
    return;
  }
  for (const auto& candidate : record->second.candidates) {
    // The per-path dependency fan-out is bounded so that one hot path cannot
    // make a targeted invalidation unbounded work.
    if (state.policies_by_path.size() >=
        static_cast<std::size_t>(limits_.max_policies_per_path) * 16U) {
      break;
    }
    state.policies_by_path[candidate.binding.path].insert(policy);
  }
  state.policies_by_route[record->second.policy.semantics.target.route].insert(policy);
  if (record->second.policy.semantics.target.multipath_set.has_value()) {
    state.policies_by_set[*record->second.policy.semantics.target.multipath_set].insert(policy);
  }
  for (const auto& entry : state.evidence) {
    for (const auto& candidate : record->second.candidates) {
      if (entry.first.path == candidate.binding.path) {
        state.policies_by_source[entry.first.source].insert(policy);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Invalidation
// ---------------------------------------------------------------------------

void Impl::apply_invalidation(State& state, const PathId& path, Outcome /*reason*/) {
  const auto advanced = state.upstream_watermark.next();
  if (advanced.has_value()) {
    state.upstream_watermark = *advanced;
  }
  const auto dependents = state.policies_by_path.find(path);
  if (dependents == state.policies_by_path.end()) {
    return;
  }
  // Targeted: only policies that actually bind this path are touched. An
  // unrelated path invalidation leaves every other policy's dependencies
  // exactly as they were.
  for (const auto& policy : dependents->second) {
    const auto record = state.policies.find(policy);
    if (record == state.policies.end()) {
      continue;
    }
    CandidateRecord* candidate = record->second.find_candidate(path);
    if (candidate == nullptr) {
      continue;
    }
    ++candidate->path_watermark;
  }
}

// ---------------------------------------------------------------------------
// Authority operations
// ---------------------------------------------------------------------------

OperationResult Impl::register_publisher(const PublisherId& publisher,
                                         const WorkerBootId& worker_boot,
                                         const AuthorityScope& scope, const SessionId& session) {
  std::unique_lock lock(mutex_);
  if (!publisher.valid() || !worker_boot.valid() || !session.valid()) {
    return make_result(Outcome::MALFORMED_REQUEST, "publisher, worker boot and session are required",
                       AdaptivePolicyId(), state_);
  }
  if (!scope.well_formed()) {
    return make_result(Outcome::MALFORMED_REQUEST,
                       "authority scope must name a fabric and a routing namespace",
                       AdaptivePolicyId(), state_);
  }
  if (state_.fenced_boots.find(worker_boot) != state_.fenced_boots.end()) {
    return make_result(Outcome::FENCED_WORKER,
                       "worker boot " + worker_boot.str() + " is permanently fenced",
                       AdaptivePolicyId(), state_);
  }
  const auto existing = state_.registrations.find(publisher);
  if (existing == state_.registrations.end() &&
      state_.registrations.size() >= static_cast<std::size_t>(limits_.max_publishers)) {
    return make_result(Outcome::RESOURCE_LIMIT, "publisher limit reached", AdaptivePolicyId(),
                       state_);
  }
  if (existing != state_.registrations.end()) {
    if (existing->second.worker_boot == worker_boot) {
      // Same incarnation re-registering: refresh the scope, keep the identity.
      existing->second.scope = scope;
      existing->second.session = session;
      existing->second.epoch = state_.epoch;
      existing->second.authority_generation = state_.authority_generation;
      return make_result(Outcome::IDEMPOTENT, "publisher incarnation re-registered",
                         AdaptivePolicyId(), state_);
    }
    // A new incarnation of a known publisher permanently fences the previous
    // one. The old boot can never publish evidence, commit an adaptation,
    // modify a policy or restore a stale preference again.
    FenceRecord fence;
    fence.publisher = publisher;
    fence.worker_boot = existing->second.worker_boot;
    fence.epoch = state_.epoch;
    fence.cause = "REINCARNATION";
    state_.fences.push_back(fence);
    state_.fenced_boots.insert(existing->second.worker_boot);
    state_.live_boots.erase(existing->second.worker_boot);
    ++counters_.fenced_workers;
  }
  PublisherRegistration registration;
  registration.publisher = publisher;
  registration.worker_boot = worker_boot;
  registration.scope = scope;
  registration.epoch = state_.epoch;
  registration.authority_generation = state_.authority_generation;
  registration.session = session;
  state_.registrations[publisher] = registration;
  state_.live_boots[worker_boot] = publisher;
  counters_.publishers = state_.registrations.size();
  return make_result(Outcome::POLICY_UPDATED, "publisher registered", AdaptivePolicyId(), state_);
}

OperationResult Impl::fence_publisher(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                      std::string_view cause) {
  std::unique_lock lock(mutex_);
  const auto existing = state_.registrations.find(publisher);
  if (existing == state_.registrations.end() || !(existing->second.worker_boot == worker_boot)) {
    return make_result(Outcome::NOT_FOUND, "no live registration for that publisher incarnation",
                       AdaptivePolicyId(), state_);
  }
  FenceRecord fence;
  fence.publisher = publisher;
  fence.worker_boot = worker_boot;
  fence.epoch = state_.epoch;
  fence.cause = cause.empty() ? "EXPLICIT" : std::string(cause);
  state_.fences.push_back(fence);
  state_.fenced_boots.insert(worker_boot);
  state_.live_boots.erase(worker_boot);
  state_.registrations.erase(existing);
  ++counters_.fenced_workers;
  counters_.publishers = state_.registrations.size();
  return make_result(Outcome::POLICY_UPDATED, "publisher fenced", AdaptivePolicyId(), state_);
}

OperationResult Impl::advance_epoch(std::string_view reason) {
  std::unique_lock lock(mutex_);
  const auto next = state_.epoch.next();
  if (!next.has_value()) {
    return make_result(Outcome::GENERATION_OVERFLOW, "coordinator epoch is exhausted",
                       AdaptivePolicyId(), state_);
  }
  state_.epoch = *next;
  const auto authority = state_.authority_generation.next();
  if (!authority.has_value()) {
    return make_result(Outcome::GENERATION_OVERFLOW, "authority generation is exhausted",
                       AdaptivePolicyId(), state_);
  }
  state_.authority_generation = *authority;
  // Every live worker is fenced by the epoch advance, and every policy must be
  // revalidated against fresh upstream state before it can adapt again.
  for (const auto& entry : state_.registrations) {
    FenceRecord fence;
    fence.publisher = entry.first;
    fence.worker_boot = entry.second.worker_boot;
    fence.epoch = state_.epoch;
    fence.cause = "EPOCH_ADVANCE";
    state_.fences.push_back(fence);
    state_.fenced_boots.insert(entry.second.worker_boot);
    ++counters_.fenced_workers;
  }
  state_.registrations.clear();
  state_.live_boots.clear();
  counters_.publishers = 0;
  state_.attempts.clear();
  state_.attempt_order.clear();
  for (auto& entry : state_.policies) {
    PolicyRecord& record = entry.second;
    record.timing.hold_down_active = false;
    record.timing.hold_down_deadline = 0;
    record.timing.cooldown_active = false;
    record.timing.cooldown_deadline = 0;
    record.timing.churn_commits.clear();
    if (policy_lifecycle_terminal(record.policy.lifecycle)) {
      continue;
    }
    record.policy.lifecycle = PolicyLifecycle::REVALIDATION_REQUIRED;
  }
  counters_.epoch = state_.epoch;
  counters_.authority_generation = state_.authority_generation;
  return make_result(Outcome::POLICY_UPDATED,
                     "epoch advanced to " + std::to_string(state_.epoch.value()) + ": " +
                         std::string(reason),
                     AdaptivePolicyId(), state_);
}

CoordinatorEpoch Impl::epoch() const {
  std::shared_lock lock(mutex_);
  return state_.epoch;
}

AdaptiveAuthorityGeneration Impl::authority_generation() const {
  std::shared_lock lock(mutex_);
  return state_.authority_generation;
}

AuthorityDescription Impl::describe_authority() const {
  std::shared_lock lock(mutex_);
  AuthorityDescription description;
  description.epoch = state_.epoch;
  description.authority_generation = state_.authority_generation;
  for (const auto& entry : state_.registrations) {
    description.registrations.push_back(entry.second);
  }
  description.fence_records = state_.fences;
  return description;
}

bool Impl::is_fenced(const PublisherId& /*publisher*/, const WorkerBootId& worker_boot) const {
  std::shared_lock lock(mutex_);
  return state_.fenced_boots.find(worker_boot) != state_.fenced_boots.end();
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

FabricStats Impl::stats() const {
  std::shared_lock lock(mutex_);
  FabricStats stats = counters_;
  stats.policies = state_.policies.size();
  stats.adaptable_policies = 0;
  stats.revoked_policies = 0;
  stats.retired_policies = 0;
  std::uint64_t candidates = 0;
  for (const auto& entry : state_.policies) {
    if (policy_lifecycle_adaptable(entry.second.policy.lifecycle)) {
      ++stats.adaptable_policies;
    }
    if (entry.second.policy.lifecycle == PolicyLifecycle::REVOKED) {
      ++stats.revoked_policies;
    }
    if (entry.second.policy.lifecycle == PolicyLifecycle::RETIRED) {
      ++stats.retired_policies;
    }
    candidates += entry.second.candidates.size();
  }
  stats.candidates = candidates;
  stats.evidence_series = state_.evidence.size();
  std::uint64_t samples = 0;
  for (const auto& entry : state_.evidence) {
    samples += entry.second.samples.size();
  }
  stats.evidence_samples = samples;
  stats.publishers = state_.registrations.size();
  stats.revocations = state_.revocations.size();
  stats.epoch = state_.epoch;
  stats.authority_generation = state_.authority_generation;
  stats.evidence_generation = state_.evidence_generation;
  return stats;
}

}  // namespace adaptive_routing::detail

// ---------------------------------------------------------------------------
// Public forwarding surface
// ---------------------------------------------------------------------------

namespace adaptive_routing {

AdaptiveRoutingFabric::AdaptiveRoutingFabric(EngineConfig config)
    : impl_(std::make_unique<detail::Impl>(std::move(config))) {}

AdaptiveRoutingFabric::~AdaptiveRoutingFabric() = default;
AdaptiveRoutingFabric::AdaptiveRoutingFabric(AdaptiveRoutingFabric&&) noexcept = default;
AdaptiveRoutingFabric& AdaptiveRoutingFabric::operator=(AdaptiveRoutingFabric&&) noexcept = default;

OperationResult AdaptiveRoutingFabric::register_publisher(const PublisherId& publisher,
                                                          const WorkerBootId& worker_boot,
                                                          const AuthorityScope& scope,
                                                          const SessionId& session) {
  return impl_->register_publisher(publisher, worker_boot, scope, session);
}

OperationResult AdaptiveRoutingFabric::fence_publisher(const PublisherId& publisher,
                                                       const WorkerBootId& worker_boot,
                                                       std::string_view cause) {
  return impl_->fence_publisher(publisher, worker_boot, cause);
}

OperationResult AdaptiveRoutingFabric::advance_epoch(std::string_view reason) {
  return impl_->advance_epoch(reason);
}

CoordinatorEpoch AdaptiveRoutingFabric::epoch() const noexcept { return impl_->epoch(); }

AdaptiveAuthorityGeneration AdaptiveRoutingFabric::authority_generation() const noexcept {
  return impl_->authority_generation();
}

AuthorityDescription AdaptiveRoutingFabric::describe_authority() const {
  return impl_->describe_authority();
}

bool AdaptiveRoutingFabric::is_fenced(const PublisherId& publisher,
                                      const WorkerBootId& worker_boot) const {
  return impl_->is_fenced(publisher, worker_boot);
}

FabricStats AdaptiveRoutingFabric::stats() const { return impl_->stats(); }

Limits AdaptiveRoutingFabric::limits() const { return impl_->limits(); }

const Clock& AdaptiveRoutingFabric::clock() const noexcept { return impl_->clock(); }

const EngineConfig& AdaptiveRoutingFabric::config() const noexcept { return impl_->config(); }

std::string render_outcome(Outcome outcome) { return std::string(to_string(outcome)); }

}  // namespace adaptive_routing

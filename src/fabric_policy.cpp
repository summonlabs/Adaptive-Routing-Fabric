// Policy lifecycle, upstream bindings and candidate indexing.
#include <algorithm>

#include "engine_impl.hpp"

namespace adaptive_routing::detail {
namespace {

void sort_candidates(std::vector<CandidateRecord>& candidates) {
  std::sort(candidates.begin(), candidates.end(),
            [](const CandidateRecord& a, const CandidateRecord& b) {
              return a.binding.path < b.binding.path;
            });
}

}  // namespace

OperationResult Impl::create_policy(const CreatePolicyRequest& request) {
  std::unique_lock lock(mutex_);
  std::string reason;
  if (!request.name.valid() || !request.scope.well_formed()) {
    return make_result(Outcome::MALFORMED_REQUEST,
                       "policy name and a fabric/namespace scope are required", AdaptivePolicyId(),
                       state_);
  }
  if (!request.semantics.valid(&reason)) {
    const Outcome outcome = reason.find("hysteresis") != std::string::npos ||
                                    reason.find("threshold") != std::string::npos
                                ? Outcome::INVALID_HYSTERESIS
                                : Outcome::MALFORMED_REQUEST;
    return make_result(outcome, reason, AdaptivePolicyId(), state_);
  }
  const std::optional<RouteId> route = request.semantics.target.route;
  const std::optional<MultipathSetId> set = request.semantics.target.multipath_set;
  const CallerCheck caller = check_caller(state_, request.context, route, set);
  if (!caller.ok) {
    return make_result(caller.outcome, caller.detail, AdaptivePolicyId(), state_);
  }
  // The policy scope must sit inside the caller's authority scope: a publisher
  // never authors a policy that reaches outside what it is authorized for.
  if (!caller.registration->scope.covers_route(request.scope.fabric, request.scope.name_space,
                                               request.semantics.target.route)) {
    return make_result(Outcome::UNAUTHORIZED_SCOPE,
                       "policy scope is outside the registered authority scope",
                       AdaptivePolicyId(), state_);
  }
  if (request.scope.routes.size() > limits_.max_scope_routes ||
      request.scope.multipath_sets.size() > limits_.max_scope_multipath_sets ||
      request.semantics.thresholds.size() > limits_.max_thresholds_per_policy ||
      request.semantics.evidence.size() > limits_.max_evidence_requirements_per_policy ||
      request.semantics.objective.terms.size() > limits_.max_objective_terms ||
      request.semantics.priorities.size() > limits_.max_candidates_per_policy) {
    return make_result(Outcome::RESOURCE_LIMIT, "policy exceeds a configured structural limit",
                       AdaptivePolicyId(), state_);
  }
  if (request.semantics.churn.enabled() &&
      request.semantics.churn.max_adaptations_per_window > limits_.max_adaptations_per_window) {
    return make_result(Outcome::RESOURCE_LIMIT, "churn bound exceeds the configured maximum",
                       AdaptivePolicyId(), state_);
  }
  if (request.semantics.dampening.enabled &&
      request.semantics.dampening.max_penalty > limits_.max_dampening_penalty) {
    return make_result(Outcome::RESOURCE_LIMIT, "dampening penalty exceeds the configured maximum",
                       AdaptivePolicyId(), state_);
  }
  const auto fingerprint = fingerprint_policy(request.scope, request.semantics);
  if (!fingerprint.has_value()) {
    return make_result(Outcome::INTERNAL_ERROR, "policy fingerprint could not be computed",
                       AdaptivePolicyId(), state_);
  }
  if (const auto replay = replay_check(state_, request.context.attempt, *fingerprint)) {
    return *replay;
  }
  const auto existing_name = state_.policy_names.find(request.name);
  if (existing_name != state_.policy_names.end()) {
    record_attempt(state_, request.context.attempt, *fingerprint, Outcome::ALREADY_EXISTS,
                   "policy name already exists");
    return make_result(Outcome::ALREADY_EXISTS, "policy name already exists", AdaptivePolicyId(),
                       state_);
  }
  if (state_.policies.size() >= static_cast<std::size_t>(limits_.max_policies)) {
    record_attempt(state_, request.context.attempt, *fingerprint, Outcome::RESOURCE_LIMIT,
                   "policy limit reached");
    return make_result(Outcome::RESOURCE_LIMIT, "policy limit reached", AdaptivePolicyId(), state_);
  }
  AdaptivePolicy policy;
  policy.id = ids_.next_policy_id();
  policy.name = request.name;
  policy.scope = request.scope;
  policy.semantics = request.semantics;
  policy.generation = AdaptivePolicyGeneration::first();
  policy.lifecycle = PolicyLifecycle::DECLARED;
  policy.epoch = state_.epoch;
  policy.owner = request.context.publisher;
  policy.authority_generation = state_.authority_generation;
  policy.declared_at = now();
  policy.updated_at = policy.declared_at;

  PolicyRecord record;
  record.policy = policy;
  record.preference.route = policy.semantics.target.route;
  record.preference.multipath_set = policy.semantics.target.multipath_set;
  record.preference.adaptation_generation = AdaptationGeneration::first();
  record.preference.transition_generation = TransitionGeneration::first();
  state_.policies.emplace(policy.id, std::move(record));
  state_.policy_names.emplace(policy.name, policy.id);
  reindex_policy(state_, policy.id);
  record_attempt(state_, request.context.attempt, *fingerprint, Outcome::POLICY_CREATED,
                 "policy created");
  OperationResult result = make_result(Outcome::POLICY_CREATED, "policy created", policy.id, state_);
  result.mutated = true;
  return result;
}

OperationResult Impl::update_policy(const UpdatePolicyRequest& request) {
  std::unique_lock lock(mutex_);
  if (!request.policy.valid()) {
    return make_result(Outcome::MALFORMED_REQUEST, "policy id is required", AdaptivePolicyId(),
                       state_);
  }
  std::string reason;
  if (!request.update.scope.well_formed() || !request.update.semantics.valid(&reason)) {
    const Outcome outcome = reason.find("hysteresis") != std::string::npos ||
                                    reason.find("threshold") != std::string::npos
                                ? Outcome::INVALID_HYSTERESIS
                                : Outcome::MALFORMED_REQUEST;
    return make_result(outcome, reason.empty() ? "policy update is malformed" : reason,
                       request.policy, state_);
  }
  const auto position = state_.policies.find(request.policy);
  if (position == state_.policies.end()) {
    return make_result(Outcome::NOT_FOUND, "policy does not exist", request.policy, state_);
  }
  const std::optional<RouteId> route = request.update.semantics.target.route;
  const std::optional<MultipathSetId> set = request.update.semantics.target.multipath_set;
  const CallerCheck caller = check_caller(state_, request.context, route, set);
  if (!caller.ok) {
    return make_result(caller.outcome, caller.detail, request.policy, state_);
  }
  if (!caller.registration->scope.covers_route(request.update.scope.fabric,
                                               request.update.scope.name_space,
                                               request.update.semantics.target.route)) {
    return make_result(Outcome::UNAUTHORIZED_SCOPE,
                       "policy scope is outside the registered authority scope", request.policy,
                       state_);
  }
  PolicyRecord& record = position->second;
  if (policy_lifecycle_terminal(record.policy.lifecycle)) {
    return make_result(lifecycle_outcome(record.policy.lifecycle),
                       "a terminal policy can never be updated", request.policy, state_);
  }
  if (!request.context.expected_policy_generation.has_value() ||
      *request.context.expected_policy_generation != record.policy.generation) {
    return make_result(Outcome::STALE_POLICY_GENERATION,
                       "expected policy generation does not match the current generation",
                       request.policy, state_);
  }
  if (request.update.scope.routes.size() > limits_.max_scope_routes ||
      request.update.scope.multipath_sets.size() > limits_.max_scope_multipath_sets ||
      request.update.semantics.thresholds.size() > limits_.max_thresholds_per_policy ||
      request.update.semantics.evidence.size() > limits_.max_evidence_requirements_per_policy ||
      request.update.semantics.objective.terms.size() > limits_.max_objective_terms) {
    return make_result(Outcome::RESOURCE_LIMIT, "policy exceeds a configured structural limit",
                       request.policy, state_);
  }
  const auto fingerprint = fingerprint_policy(request.update.scope, request.update.semantics);
  if (!fingerprint.has_value()) {
    return make_result(Outcome::INTERNAL_ERROR, "policy fingerprint could not be computed",
                       request.policy, state_);
  }
  if (const auto replay = replay_check(state_, request.context.attempt, *fingerprint)) {
    return *replay;
  }
  const auto next_generation = record.policy.generation.next();
  if (!next_generation.has_value()) {
    return make_result(Outcome::GENERATION_OVERFLOW, "policy generation is exhausted",
                       request.policy, state_);
  }
  const bool target_changed =
      !(record.policy.semantics.target.route == request.update.semantics.target.route) ||
      record.policy.semantics.target.multipath_set != request.update.semantics.target.multipath_set;
  unindex_policy(state_, request.policy);
  record.policy.scope = request.update.scope;
  record.policy.semantics = request.update.semantics;
  record.policy.generation = *next_generation;
  record.policy.updated_at = now();
  record.policy.epoch = state_.epoch;
  if (target_changed) {
    // Candidate bindings and preference belong to a target. Changing the target
    // discards them rather than silently reinterpreting them for a new route.
    record.candidates.clear();
    record.preference = RoutingPreference{};
    record.preference.route = record.policy.semantics.target.route;
    record.preference.multipath_set = record.policy.semantics.target.multipath_set;
    record.preference.adaptation_generation = AdaptationGeneration::first();
    record.preference.transition_generation = TransitionGeneration::first();
    record.stable = StableState{};
    record.timing = TimingState{};
  }
  reindex_policy(state_, request.policy);
  record_attempt(state_, request.context.attempt, *fingerprint, Outcome::POLICY_UPDATED,
                 "policy updated");
  OperationResult result =
      make_result(Outcome::POLICY_UPDATED, "policy updated", request.policy, state_);
  result.mutated = true;
  return result;
}

OperationResult Impl::transition_policy(const PolicyLifecycleRequest& request) {
  std::unique_lock lock(mutex_);
  if (!request.policy.valid() || !valid_policy_event(static_cast<std::uint8_t>(request.event))) {
    return make_result(Outcome::MALFORMED_REQUEST, "policy id and lifecycle event are required",
                       request.policy, state_);
  }
  const auto position = state_.policies.find(request.policy);
  if (position == state_.policies.end()) {
    return make_result(Outcome::NOT_FOUND, "policy does not exist", request.policy, state_);
  }
  PolicyRecord& record = position->second;
  const CallerCheck caller =
      check_caller(state_, request.context, record.policy.semantics.target.route,
                   record.policy.semantics.target.multipath_set);
  if (!caller.ok) {
    return make_result(caller.outcome, caller.detail, request.policy, state_);
  }
  if (policy_lifecycle_terminal(record.policy.lifecycle)) {
    return make_result(lifecycle_outcome(record.policy.lifecycle),
                       "a terminal policy never accepts a further lifecycle event",
                       request.policy, state_);
  }
  const auto next_lifecycle = apply_policy_event(record.policy.lifecycle, request.event);
  if (!next_lifecycle.has_value()) {
    return make_result(Outcome::MALFORMED_REQUEST,
                       "lifecycle event " + std::string(to_string(request.event)) +
                           " is not defined for state " +
                           std::string(to_string(record.policy.lifecycle)),
                       request.policy, state_);
  }
  if (request.event == PolicyEvent::REVALIDATE) {
    // Revalidation is earned, not asserted: a policy returns to service only
    // when it still has at least one legally usable candidate binding.
    bool usable = false;
    for (const auto& candidate : record.candidates) {
      if (candidate.binding.path_authority.legal && candidate.binding.route.current &&
          candidate.binding.available) {
        usable = true;
        break;
      }
    }
    if (!usable) {
      record.policy.lifecycle = PolicyLifecycle::REVALIDATION_REQUIRED;
      return make_result(Outcome::REVALIDATION_REQUIRED,
                         "no candidate binding is currently legal and available",
                         request.policy, state_);
    }
  }
  record.policy.lifecycle = *next_lifecycle;
  record.policy.epoch = state_.epoch;
  OperationResult result = make_result(Outcome::POLICY_UPDATED,
                                       "policy lifecycle is now " +
                                           std::string(to_string(record.policy.lifecycle)),
                                       request.policy, state_);
  result.mutated = true;
  return result;
}

OperationResult Impl::revoke_policy(const AdaptivePolicyId& policy_id, RevocationReason reason,
                                    std::string detail, const MutationContext& context) {
  std::unique_lock lock(mutex_);
  if (!policy_id.valid() || !valid_revocation_reason(static_cast<std::uint8_t>(reason))) {
    return make_result(Outcome::MALFORMED_REQUEST, "policy id and revocation reason are required",
                       policy_id, state_);
  }
  const auto position = state_.policies.find(policy_id);
  if (position == state_.policies.end()) {
    return make_result(Outcome::NOT_FOUND, "policy does not exist", policy_id, state_);
  }
  PolicyRecord& record = position->second;
  const CallerCheck caller = check_caller(state_, context, record.policy.semantics.target.route,
                                          record.policy.semantics.target.multipath_set);
  if (!caller.ok) {
    return make_result(caller.outcome, caller.detail, policy_id, state_);
  }
  const auto existing = state_.revocations.find(policy_id);
  if (existing != state_.revocations.end()) {
    if (existing->second.reason == reason) {
      return make_result(Outcome::IDEMPOTENT, "policy is already revoked for the same reason",
                         policy_id, state_);
    }
    return make_result(Outcome::REVOKED, "policy is already revoked for a different reason",
                       policy_id, state_);
  }
  if (policy_lifecycle_terminal(record.policy.lifecycle)) {
    return make_result(lifecycle_outcome(record.policy.lifecycle),
                       "a retired or superseded policy cannot be revoked", policy_id, state_);
  }
  if (state_.revocations.size() >= static_cast<std::size_t>(limits_.max_revocations)) {
    return make_result(Outcome::RESOURCE_LIMIT, "revocation limit reached", policy_id, state_);
  }
  RevocationRecord revocation;
  revocation.policy = policy_id;
  revocation.generation = record.policy.generation;
  revocation.authority_generation = state_.authority_generation;
  revocation.epoch = state_.epoch;
  revocation.publisher = context.publisher;
  revocation.reason = reason;
  revocation.detail = std::move(detail);
  state_.revocations.emplace(policy_id, revocation);
  record.revocation = revocation;
  // Revocation makes the policy permanently non-adaptable but does not discard
  // the evidence the runtime holds for unrelated policies, and it is distinct
  // from evidence invalidation.
  record.policy.lifecycle = PolicyLifecycle::REVOKED;
  record.policy.epoch = state_.epoch;
  OperationResult result = make_result(Outcome::POLICY_UPDATED,
                                       "policy revoked: " + revocation.render(), policy_id,
                                       state_);
  result.mutated = true;
  return result;
}

std::optional<AdaptivePolicy> Impl::find_policy(const AdaptivePolicyId& policy) const {
  std::shared_lock lock(mutex_);
  const auto position = state_.policies.find(policy);
  if (position == state_.policies.end()) {
    return std::nullopt;
  }
  return position->second.policy;
}

std::vector<AdaptivePolicy> Impl::list_policies() const {
  std::shared_lock lock(mutex_);
  std::vector<AdaptivePolicy> policies;
  policies.reserve(state_.policies.size());
  // std::map iteration is ordered by policy id, which is the canonical order.
  for (const auto& entry : state_.policies) {
    policies.push_back(entry.second.policy);
  }
  return policies;
}

std::optional<RevocationRecord> Impl::find_revocation(const AdaptivePolicyId& policy) const {
  std::shared_lock lock(mutex_);
  const auto position = state_.revocations.find(policy);
  if (position == state_.revocations.end()) {
    return std::nullopt;
  }
  return position->second;
}

std::vector<RevocationRecord> Impl::list_revocations() const {
  std::shared_lock lock(mutex_);
  std::vector<RevocationRecord> revocations;
  revocations.reserve(state_.revocations.size());
  for (const auto& entry : state_.revocations) {
    revocations.push_back(entry.second);
  }
  return revocations;
}

// ---------------------------------------------------------------------------
// Upstream bindings
// ---------------------------------------------------------------------------

OperationResult Impl::apply_upstream(const UpstreamNotifyRequest& request) {
  std::unique_lock lock(mutex_);
  if (request.notifications.empty()) {
    return make_result(Outcome::MALFORMED_REQUEST, "no upstream notification supplied",
                       AdaptivePolicyId(), state_);
  }
  if (request.notifications.size() > limits_.max_batch_size) {
    return make_result(Outcome::RESOURCE_LIMIT, "upstream batch exceeds the configured maximum",
                       AdaptivePolicyId(), state_);
  }
  Digest digest;
  digest.write_tag("upstream-batch");
  for (const auto& notification : request.notifications) {
    digest.write_string(notification.render());
  }
  const std::string fingerprint = digest.hex();
  if (const auto replay = replay_check(state_, request.context.attempt, fingerprint)) {
    return *replay;
  }
  for (const auto& notification : request.notifications) {
    if (!notification.policy.valid()) {
      return make_result(Outcome::MALFORMED_REQUEST, "notification names no policy",
                         AdaptivePolicyId(), state_);
    }
    const auto position = state_.policies.find(notification.policy);
    if (position == state_.policies.end()) {
      return make_result(Outcome::NOT_FOUND, "notification names an unknown policy",
                         notification.policy, state_);
    }
    PolicyRecord& record = position->second;
    if (!valid_upstream_event(static_cast<std::uint8_t>(notification.event))) {
      return make_result(Outcome::MALFORMED_REQUEST, "unknown upstream event",
                         notification.policy, state_);
    }
    if (!notification.binding.well_formed()) {
      return make_result(Outcome::MALFORMED_REQUEST, "upstream binding is malformed",
                         notification.policy, state_);
    }
    if (policy_lifecycle_terminal(record.policy.lifecycle)) {
      return make_result(lifecycle_outcome(record.policy.lifecycle),
                         "a terminal policy accepts no upstream binding", notification.policy,
                         state_);
    }
    // Provenance must agree with the calling session, otherwise a peer could
    // attribute an upstream fact to a different authority.
    if (notification.provenance.publisher.valid() &&
        !(notification.provenance.publisher == request.context.publisher)) {
      return make_result(Outcome::UNAUTHORIZED, "upstream provenance names a different publisher",
                         notification.policy, state_);
    }
    if (notification.provenance.worker_boot.valid() &&
        !(notification.provenance.worker_boot == request.context.worker_boot)) {
      return make_result(Outcome::STALE_WORKER,
                         "upstream provenance names a different worker incarnation",
                         notification.policy, state_);
    }
    if (notification.provenance.epoch.valid() &&
        !(notification.provenance.epoch == state_.epoch)) {
      return make_result(Outcome::STALE_EPOCH, "upstream provenance carries a stale epoch",
                         notification.policy, state_);
    }
    const CallerCheck caller =
        check_caller(state_, request.context, record.policy.semantics.target.route,
                     record.policy.semantics.target.multipath_set);
    if (!caller.ok) {
      return make_result(caller.outcome, caller.detail, notification.policy, state_);
    }
    if (record.policy.semantics.target.multipath_set.has_value() &&
        notification.binding.multipath.has_value() &&
        !(notification.binding.multipath->set == *record.policy.semantics.target.multipath_set)) {
      return make_result(Outcome::MALFORMED_REQUEST,
                         "multipath binding names a different set than the policy target",
                         notification.policy, state_);
    }
    if (!(notification.binding.route.route == record.policy.semantics.target.route)) {
      return make_result(Outcome::MALFORMED_REQUEST,
                         "route binding names a different route than the policy target",
                         notification.policy, state_);
    }
    if (!record.policy.scope.covers_route(record.policy.scope.fabric,
                                          record.policy.scope.name_space,
                                          notification.binding.route.site,
                                          notification.binding.route.route)) {
      return make_result(Outcome::UNAUTHORIZED_SCOPE, "candidate route is outside the policy scope",
                         notification.policy, state_);
    }
    if (!record.policy.scope.covers_path_class(notification.binding.path_class)) {
      return make_result(Outcome::UNAUTHORIZED_SCOPE,
                         "candidate path class is outside the policy scope", notification.policy,
                         state_);
    }

    CandidateRecord* candidate = record.find_candidate(notification.binding.path);
    const auto expected_matches = [&](const PathAuthorityGeneration& current) {
      return !notification.expected_previous_generation.has_value() ||
             *notification.expected_previous_generation == current.value();
    };

    switch (notification.event) {
      case UpstreamEvent::DECLARE_CANDIDATE: {
        if (candidate == nullptr) {
          if (record.candidates.size() >=
              static_cast<std::size_t>(limits_.max_candidates_per_policy)) {
            return make_result(Outcome::RESOURCE_LIMIT, "candidate limit reached for this policy",
                               notification.policy, state_);
          }
          if (record.candidates.size() + 1U > limits_.max_total_candidates) {
            return make_result(Outcome::RESOURCE_LIMIT, "total candidate limit reached",
                               notification.policy, state_);
          }
          if (!notification.binding.path_authority.legal) {
            return make_result(Outcome::MALFORMED_REQUEST,
                               "a candidate is declared only with a current legal path authority "
                               "binding",
                               notification.policy, state_);
          }
          CandidateRecord fresh;
          fresh.binding = notification.binding;
          record.candidates.push_back(fresh);
          sort_candidates(record.candidates);
          reindex_policy(state_, notification.policy);
        } else {
          if (!expected_matches(candidate->binding.path_authority.generation)) {
            return make_result(Outcome::STALE_PATH_AUTHORITY,
                               "expected previous path authority generation does not match",
                               notification.policy, state_);
          }
          candidate->binding = notification.binding;
        }
        break;
      }
      case UpstreamEvent::ADVANCE_PATH_AUTHORITY: {
        if (candidate == nullptr) {
          return make_result(Outcome::NOT_FOUND, "candidate is not declared", notification.policy,
                             state_);
        }
        if (!expected_matches(candidate->binding.path_authority.generation)) {
          return make_result(Outcome::STALE_PATH_AUTHORITY,
                             "expected previous path authority generation does not match",
                             notification.policy, state_);
        }
        if (!(notification.binding.path_authority.generation >
              candidate->binding.path_authority.generation)) {
          return make_result(Outcome::STALE_PATH_AUTHORITY, "path authority generation must advance",
                             notification.policy, state_);
        }
        candidate->binding.path_authority = notification.binding.path_authority;
        apply_invalidation(state_, candidate->binding.path, Outcome::STALE_PATH_AUTHORITY);
        break;
      }
      case UpstreamEvent::INVALIDATE_PATH: {
        if (candidate == nullptr) {
          apply_invalidation(state_, notification.binding.path, Outcome::STALE_PATH_AUTHORITY);
          break;
        }
        candidate->binding.path_authority.legal = false;
        candidate->binding.path_authority.denial_reason =
            notification.binding.path_authority.denial_reason.empty()
                ? std::string("invalidated upstream")
                : notification.binding.path_authority.denial_reason;
        if (notification.binding.path_authority.generation.valid()) {
          candidate->binding.path_authority.generation =
              notification.binding.path_authority.generation;
        }
        apply_invalidation(state_, candidate->binding.path, Outcome::STALE_PATH_AUTHORITY);
        break;
      }
      case UpstreamEvent::SET_MEMBERSHIP: {
        if (candidate == nullptr) {
          return make_result(Outcome::NOT_FOUND, "candidate is not declared", notification.policy,
                             state_);
        }
        candidate->binding.multipath = notification.binding.multipath;
        apply_invalidation(state_, candidate->binding.path, Outcome::STALE_MULTIPATH_SET);
        break;
      }
      case UpstreamEvent::INVALIDATE_MULTIPATH_SET: {
        if (candidate != nullptr && candidate->binding.multipath.has_value()) {
          candidate->binding.multipath->current = false;
        }
        apply_invalidation(state_, notification.binding.path, Outcome::STALE_MULTIPATH_SET);
        break;
      }
      case UpstreamEvent::ADVANCE_ROUTE: {
        if (candidate == nullptr) {
          return make_result(Outcome::NOT_FOUND, "candidate is not declared", notification.policy,
                             state_);
        }
        candidate->binding.route = notification.binding.route;
        apply_invalidation(state_, candidate->binding.path, Outcome::STALE_ROUTE);
        break;
      }
      case UpstreamEvent::INVALIDATE_ROUTE: {
        if (candidate != nullptr) {
          candidate->binding.route.current = false;
        }
        apply_invalidation(state_, notification.binding.path, Outcome::STALE_ROUTE);
        break;
      }
      case UpstreamEvent::ADVANCE_WEIGHT_POLICY: {
        if (candidate == nullptr) {
          return make_result(Outcome::NOT_FOUND, "candidate is not declared", notification.policy,
                             state_);
        }
        candidate->binding.weighted = notification.binding.weighted;
        break;
      }
      case UpstreamEvent::MARK_UNAVAILABLE: {
        if (candidate != nullptr) {
          candidate->binding.available = false;
        }
        apply_invalidation(state_, notification.binding.path, Outcome::STALE_ROUTE);
        break;
      }
      case UpstreamEvent::MARK_AVAILABLE: {
        if (candidate != nullptr) {
          candidate->binding.available = true;
        }
        apply_invalidation(state_, notification.binding.path, Outcome::STALE_ROUTE);
        break;
      }
      case UpstreamEvent::HARD_FAILURE_SIGNAL: {
        if (candidate != nullptr) {
          candidate->binding.hard_failure = true;
        }
        apply_invalidation(state_, notification.binding.path, Outcome::STALE_ROUTE);
        break;
      }
      case UpstreamEvent::CLEAR_HARD_FAILURE_SIGNAL: {
        if (candidate != nullptr) {
          candidate->binding.hard_failure = false;
        }
        break;
      }
    }
  }
  record_attempt(state_, request.context.attempt, fingerprint, Outcome::POLICY_UPDATED,
                 "upstream bindings applied");
  OperationResult result =
      make_result(Outcome::POLICY_UPDATED, "upstream bindings applied",
                  request.notifications.front().policy, state_);
  result.mutated = true;
  return result;
}

namespace {

template <class Key, class Map>
[[nodiscard]] std::vector<AdaptivePolicyId> policy_set_for(const Map& index, const Key& key) {
  std::vector<AdaptivePolicyId> policies;
  const auto position = index.find(key);
  if (position == index.end()) {
    return policies;
  }
  // std::set iteration is ordered by policy id, which is the canonical order.
  policies.assign(position->second.begin(), position->second.end());
  return policies;
}

}  // namespace

std::vector<AdaptivePolicyId> Impl::policies_for_path(const PathId& path) const {
  std::shared_lock lock(mutex_);
  return policy_set_for(state_.policies_by_path, path);
}

std::vector<AdaptivePolicyId> Impl::policies_for_route(const RouteId& route) const {
  std::shared_lock lock(mutex_);
  return policy_set_for(state_.policies_by_route, route);
}

std::vector<AdaptivePolicyId> Impl::policies_for_multipath_set(const MultipathSetId& set) const {
  std::shared_lock lock(mutex_);
  return policy_set_for(state_.policies_by_set, set);
}

std::vector<AdaptivePolicyId> Impl::policies_for_evidence_source(
    const EvidenceSourceId& source) const {
  std::shared_lock lock(mutex_);
  return policy_set_for(state_.policies_by_source, source);
}

std::vector<CandidateBinding> Impl::candidates(const AdaptivePolicyId& policy) const {
  std::shared_lock lock(mutex_);
  std::vector<CandidateBinding> bindings;
  const auto position = state_.policies.find(policy);
  if (position == state_.policies.end()) {
    return bindings;
  }
  bindings.reserve(position->second.candidates.size());
  for (const auto& candidate : position->second.candidates) {
    bindings.push_back(candidate.binding);
  }
  return bindings;
}

}  // namespace adaptive_routing::detail

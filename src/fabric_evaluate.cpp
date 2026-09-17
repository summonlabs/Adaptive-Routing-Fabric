// Two-phase policy evaluation, deterministic ranking and atomic decision commit.
#include <algorithm>
#include <atomic>

#include "engine_impl.hpp"

namespace adaptive_routing::detail {
namespace {

struct MetricLookup {
  bool ok = false;
  MetricValue value;
  SuppressionReason reason = SuppressionReason::EVIDENCE_UNKNOWN;
  EvidenceQuality quality = EvidenceQuality::ESTIMATED;
  Ticks age = 0;
  Ticks window = 0;
  std::uint32_t samples = 0;
};

[[nodiscard]] std::uint32_t priority_of(const PolicySemantics& semantics,
                                        const PathId& path) noexcept {
  for (const auto& entry : semantics.priorities) {
    if (entry.path == path) {
      return entry.priority;
    }
  }
  return 0;
}

// Orientation aware strict "a is better than b".
[[nodiscard]] bool metric_is_better(const MetricValue& a, const MetricValue& b) noexcept {
  return describe_metric(a.kind()).orientation == MetricOrientation::LOWER_IS_BETTER
             ? a.value() < b.value()
             : a.value() > b.value();
}

// Deterministic total order over candidates:
//   1. eligible before ineligible -- eligibility is a hard gate, not a
//      preference, so a high-priority candidate that fails path authority,
//      membership or evidence never outranks one that passed;
//   2. explicit policy priority, higher first;
//   3. weakest evidence quality actually used, stronger first;
//   4. objective: lexicographic terms in declaration order, or weighted score;
//   5. canonical PathId byte order.
[[nodiscard]] bool ranks_ahead(const CandidateEvaluation& a, const CandidateEvaluation& b,
                               const PolicySemantics& semantics) noexcept {
  if (a.eligible != b.eligible) {
    return a.eligible;
  }
  if (a.priority != b.priority) {
    return a.priority > b.priority;
  }
  const std::uint32_t quality_a = evidence_quality_rank(a.quality);
  const std::uint32_t quality_b = evidence_quality_rank(b.quality);
  if (quality_a != quality_b) {
    return quality_a > quality_b;
  }
  if (semantics.objective.mode == ObjectiveMode::WEIGHTED_SCORE) {
    const std::uint64_t score_a = a.score.value_or(0);
    const std::uint64_t score_b = b.score.value_or(0);
    if (score_a != score_b) {
      return score_a > score_b;
    }
  } else {
    const std::size_t terms = semantics.objective.terms.size();
    for (std::size_t index = 0; index < terms && index < a.metrics.size() &&
                               index < b.metrics.size();
         ++index) {
      if (!a.metrics[index].valid() || !b.metrics[index].valid()) {
        break;
      }
      if (a.metrics[index].value() != b.metrics[index].value()) {
        return metric_is_better(a.metrics[index], b.metrics[index]);
      }
    }
  }
  return a.path < b.path;
}

[[nodiscard]] MetricLookup lookup_metric(const EvaluationInputs& inputs, const PathId& path,
                                         const EvidenceRequirement& requirement) {
  MetricLookup lookup;
  if (inputs.evidence == nullptr) {
    lookup.reason = SuppressionReason::EVIDENCE_UNKNOWN;
    return lookup;
  }
  const ResolvedEvidence* resolved = inputs.evidence->find(path, requirement.kind);
  if (resolved == nullptr || !resolved->aggregate.valid()) {
    lookup.reason = SuppressionReason::EVIDENCE_UNKNOWN;
    return lookup;
  }
  lookup.quality = resolved->quality;
  lookup.age = resolved->aggregate.age(inputs.now);
  lookup.window = resolved->aggregate.window();
  lookup.samples = resolved->aggregate.sample_count;
  if (evidence_quality_rank(resolved->quality) < evidence_quality_rank(requirement.min_quality)) {
    lookup.reason = SuppressionReason::EVIDENCE_UNKNOWN;
    return lookup;
  }
  if (resolved->aggregate.sample_count < requirement.min_samples) {
    lookup.reason = SuppressionReason::INSUFFICIENT_SAMPLES;
    return lookup;
  }
  if (lookup.age > requirement.max_age) {
    lookup.reason = SuppressionReason::STALE_EVIDENCE;
    return lookup;
  }
  if (lookup.window < requirement.min_window) {
    lookup.reason = SuppressionReason::INSUFFICIENT_SAMPLES;
    return lookup;
  }
  lookup.ok = true;
  lookup.value = resolved->aggregate.value;
  return lookup;
}

[[nodiscard]] bool threshold_permits_departure(const MetricValue& current,
                                               const MetricValue& switch_value) noexcept {
  return describe_metric(current.kind()).orientation == MetricOrientation::LOWER_IS_BETTER
             ? current.value() >= switch_value.value()
             : current.value() <= switch_value.value();
}

[[nodiscard]] bool threshold_permits_entry(const MetricValue& candidate,
                                           const MetricValue& clear_value) noexcept {
  return describe_metric(candidate.kind()).orientation == MetricOrientation::LOWER_IS_BETTER
             ? candidate.value() <= clear_value.value()
             : candidate.value() >= clear_value.value();
}

}  // namespace

// ---------------------------------------------------------------------------
// Input capture
// ---------------------------------------------------------------------------

DependencySnapshot Impl::build_dependencies(const State& state, const PolicyRecord& record,
                                            const EvaluationId& evaluation) const {
  DependencySnapshot snapshot;
  snapshot.evaluation = evaluation;
  snapshot.policy = record.policy.id;
  snapshot.policy_generation = record.policy.generation;
  snapshot.evidence_generation = state.evidence_generation;
  snapshot.evidence_watermark = state.evidence_watermark;
  snapshot.upstream_watermark = state.upstream_watermark;
  snapshot.epoch = state.epoch;
  snapshot.authority_generation = state.authority_generation;
  snapshot.route_generation = record.candidates.empty()
                                  ? RouteGeneration()
                                  : record.candidates.front().binding.route.generation;
  snapshot.multipath_set = record.policy.semantics.target.multipath_set;
  if (!record.candidates.empty() && record.candidates.front().binding.multipath.has_value()) {
    snapshot.multipath_set_generation =
        record.candidates.front().binding.multipath->generation;
  }
  for (const auto& candidate : record.candidates) {
    snapshot.candidates.push_back(candidate.binding.path);
    snapshot.candidate_path_authority.push_back(candidate.binding.path_authority);
    snapshot.candidate_path_watermarks.push_back(candidate.path_watermark);
    if (candidate.binding.route.generation.valid()) {
      snapshot.route_generation = candidate.binding.route.generation;
    }
  }
  snapshot.captured_at = now();
  return snapshot;
}

EvaluationInputs Impl::copy_inputs(const State& state, const PolicyRecord& record) const {
  EvaluationInputs inputs;
  inputs.policy = record.policy;
  inputs.candidates = record.candidates;
  inputs.preference = record.preference;
  inputs.stable = record.stable;
  inputs.timing = record.timing;
  inputs.epoch = state.epoch;
  inputs.authority_generation = state.authority_generation;
  inputs.evidence_generation = state.evidence_generation;
  inputs.evidence_watermark = state.evidence_watermark;
  inputs.upstream_watermark = state.upstream_watermark;
  inputs.evidence = capture_evidence_locked(state, record);
  inputs.now = now();
  inputs.limits = limits_;
  return inputs;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

EvaluationTicket Impl::evaluate_inputs(const EvaluationInputs& inputs,
                                       const DependencySnapshot& dependencies) const {
  EvaluationTicket ticket;
  ticket.dependencies = dependencies;
  ticket.decision = AdaptationDecisionId();
  ticket.evaluated_at = inputs.now;
  ticket.current_preference = inputs.preference.established ? inputs.preference.preferred_path
                                                            : PathId();
  ticket.adaptation_generation = inputs.preference.adaptation_generation;
  ticket.transition_generation = inputs.preference.transition_generation;
  if (inputs.evidence != nullptr) {
    ticket.evidence_snapshot = inputs.evidence->id();
  }
  const PolicySemantics& semantics = inputs.policy.semantics;

  // --- candidate eligibility ---------------------------------------------
  for (const auto& candidate : inputs.candidates) {
    CandidateEvaluation evaluation;
    evaluation.path = candidate.binding.path;
    evaluation.path_authority_generation = candidate.binding.path_authority.generation;
    evaluation.route_generation = candidate.binding.route.generation;
    if (candidate.binding.multipath.has_value()) {
      evaluation.multipath_set_generation = candidate.binding.multipath->generation;
    }
    evaluation.priority = priority_of(semantics, candidate.binding.path);
    evaluation.current_preference =
        inputs.preference.established && inputs.preference.preferred_path == candidate.binding.path;
    evaluation.previous_preference =
        inputs.preference.previous_path.valid() && inputs.preference.previous_path == candidate.binding.path;
    evaluation.eligible = true;
    evaluation.rejection = SuppressionReason::NONE;
    evaluation.rejection_outcome = Outcome::NO_CHANGE;
    evaluation.quality = EvidenceQuality::PRIMARY;

    if (!candidate.binding.path_authority.legal) {
      evaluation.eligible = false;
      evaluation.rejection = SuppressionReason::UPSTREAM_DEPENDENCY_STALE;
      evaluation.rejection_outcome = Outcome::STALE_PATH_AUTHORITY;
    } else if (!candidate.binding.route.current) {
      evaluation.eligible = false;
      evaluation.rejection = SuppressionReason::UPSTREAM_DEPENDENCY_STALE;
      evaluation.rejection_outcome = Outcome::STALE_ROUTE;
    } else if (!candidate.binding.available) {
      evaluation.eligible = false;
      evaluation.rejection = SuppressionReason::UPSTREAM_DEPENDENCY_STALE;
      evaluation.rejection_outcome = Outcome::WITHDRAWN_UPSTREAM;
    } else if (semantics.target.multipath_set.has_value()) {
      if (!candidate.binding.multipath.has_value() ||
          !candidate.binding.multipath->current ||
          !(candidate.binding.multipath->set == *semantics.target.multipath_set) ||
          !candidate.binding.multipath->contains(candidate.binding.path)) {
        evaluation.eligible = false;
        evaluation.rejection = SuppressionReason::UPSTREAM_DEPENDENCY_STALE;
        evaluation.rejection_outcome = Outcome::STALE_MULTIPATH_SET;
      }
    }

    if (evaluation.eligible) {
      std::uint32_t weakest = 4;
      for (const auto& requirement : semantics.evidence) {
        const MetricLookup lookup = lookup_metric(inputs, candidate.binding.path, requirement);
        if (!lookup.ok) {
          if (requirement.required) {
            evaluation.eligible = false;
            evaluation.rejection = lookup.reason;
            evaluation.rejection_outcome = suppression_outcome(lookup.reason);
          }
          continue;
        }
        weakest = (std::min)(weakest, evidence_quality_rank(lookup.quality));
      }
      if (evaluation.eligible) {
        evaluation.quality = weakest >= 4   ? EvidenceQuality::PRIMARY
                             : weakest == 3 ? EvidenceQuality::AGGREGATED
                             : weakest == 2 ? EvidenceQuality::OPERATOR
                                            : EvidenceQuality::ESTIMATED;
      }
    }

    if (evaluation.eligible) {
      // The objective must be computable from declared evidence; a candidate is
      // never scored from absent data.
      std::vector<MetricValue> metrics;
      bool complete = true;
      SuppressionReason missing = SuppressionReason::EVIDENCE_UNKNOWN;
      for (const auto& term : semantics.objective.terms) {
        const EvidenceRequirement* requirement = nullptr;
        for (const auto& declared : semantics.evidence) {
          if (declared.kind == term.kind) {
            requirement = &declared;
            break;
          }
        }
        if (requirement == nullptr) {
          complete = false;
          missing = SuppressionReason::NO_TRIGGER_DECLARED;
          break;
        }
        const MetricLookup lookup = lookup_metric(inputs, candidate.binding.path, *requirement);
        if (!lookup.ok) {
          complete = false;
          missing = lookup.reason;
          break;
        }
        metrics.push_back(lookup.value);
      }
      if (!complete) {
        evaluation.eligible = false;
        evaluation.rejection = missing;
        evaluation.rejection_outcome = suppression_outcome(missing);
      } else {
        evaluation.metrics = metrics;
        if (semantics.objective.mode == ObjectiveMode::WEIGHTED_SCORE) {
          std::vector<ScoreTerm> terms;
          terms.reserve(semantics.objective.terms.size());
          for (const auto& term : semantics.objective.terms) {
            ScoreTerm score_term;
            score_term.kind = term.kind;
            score_term.weight_bps = term.weight_bps;
            terms.push_back(score_term);
          }
          const auto score = weighted_score(terms, metrics);
          if (!score.has_value()) {
            evaluation.eligible = false;
            evaluation.rejection = SuppressionReason::EVIDENCE_UNKNOWN;
            evaluation.rejection_outcome = Outcome::INCOMPATIBLE_METRIC;
          } else {
            evaluation.score = *score;
          }
        }
      }
    }

    ticket.ranking.push_back(std::move(evaluation));
  }

  std::stable_sort(ticket.ranking.begin(), ticket.ranking.end(),
                   [&semantics](const CandidateEvaluation& a, const CandidateEvaluation& b) {
                     return ranks_ahead(a, b, semantics);
                   });
  ticket.required_improvement_bps = 0;

  const CandidateEvaluation* best = nullptr;
  for (const auto& evaluation : ticket.ranking) {
    if (evaluation.eligible) {
      best = &evaluation;
      break;
    }
  }
  if (best == nullptr) {
    ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
    ticket.suppression = SuppressionReason::NO_ELIGIBLE_ALTERNATIVE;
    ticket.outcome = Outcome::NO_ELIGIBLE_CANDIDATE;
    ticket.detail = "no candidate satisfies path authority, multipath membership, scope and "
                    "evidence requirements";
    return ticket;
  }

  const CandidateRecord* current_binding = nullptr;
  if (inputs.preference.established) {
    for (const auto& candidate : inputs.candidates) {
      if (candidate.binding.path == inputs.preference.preferred_path) {
        current_binding = &candidate;
        break;
      }
    }
  }

  // --- emergency condition ------------------------------------------------
  bool emergency = false;
  std::string emergency_reason;
  if (semantics.emergency.enabled && inputs.preference.established) {
    if (semantics.emergency.on_current_path_unauthorized &&
        (current_binding == nullptr || !current_binding->binding.path_authority.legal)) {
      emergency = true;
      emergency_reason = "current preferred path is not authorized";
    }
    if (semantics.emergency.on_current_path_unavailable &&
        (current_binding == nullptr || !current_binding->binding.available)) {
      emergency = true;
      emergency_reason = "current preferred path is unavailable";
    }
    if (semantics.emergency.on_hard_failure_signal && current_binding != nullptr &&
        current_binding->binding.hard_failure) {
      emergency = true;
      emergency_reason = "hard failure signal on the current preferred path";
    }
  }
  ticket.emergency = emergency;

  // --- initial establishment ---------------------------------------------
  if (!inputs.preference.established) {
    for (const auto& rule : semantics.thresholds) {
      const EvidenceRequirement* requirement = nullptr;
      for (const auto& declared : semantics.evidence) {
        if (declared.kind == rule.kind) {
          requirement = &declared;
          break;
        }
      }
      if (requirement == nullptr) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = SuppressionReason::NO_TRIGGER_DECLARED;
        ticket.outcome = Outcome::NO_CHANGE;
        ticket.detail = "threshold rule has no declared evidence requirement";
        return ticket;
      }
      const MetricLookup lookup = lookup_metric(inputs, best->path, *requirement);
      if (!lookup.ok || !threshold_permits_entry(lookup.value, rule.clear_value)) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = lookup.ok ? SuppressionReason::HYSTERESIS_NOT_CLEARED
                                       : lookup.reason;
        ticket.outcome = suppression_outcome(ticket.suppression);
        ticket.detail = "best candidate does not clear the declared entry threshold for " +
                        std::string(to_string(rule.kind));
        return ticket;
      }
    }
    ticket.lifecycle = DecisionLifecycle::ELIGIBLE;
    ticket.target_preference = best->path;
    ticket.target_path_authority_generation = best->path_authority_generation;
    ticket.target_score = best->score;
    ticket.detail = "initial routing preference established from policy and current evidence";
    return ticket;
  }

  if (best->path == inputs.preference.preferred_path) {
    ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
    ticket.suppression = SuppressionReason::MERIT_NOT_ESTABLISHED;
    ticket.outcome = Outcome::NO_CHANGE;
    ticket.target_preference = best->path;
    ticket.target_path_authority_generation = best->path_authority_generation;
    ticket.target_score = best->score;
    ticket.detail = "the current preference is already the best eligible candidate";
    return ticket;
  }

  ticket.target_preference = best->path;
  ticket.target_path_authority_generation = best->path_authority_generation;
  ticket.target_score = best->score;

  // A current preference that is no longer eligible -- because it left the
  // candidate set, lost its Path Authority, left its multipath set, became
  // unavailable or lost its evidence -- is never used as the baseline of an
  // ordinary adaptation. The runtime says so, and only an explicitly configured
  // emergency rule may move away from it.
  bool current_eligible = current_binding != nullptr;
  if (current_eligible) {
    for (const auto& ranked : ticket.ranking) {
      if (ranked.path == inputs.preference.preferred_path) {
        current_eligible = ranked.eligible;
        break;
      }
    }
  }
  if (!current_eligible) {
    ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
    ticket.suppression = SuppressionReason::CURRENT_PREFERENCE_INELIGIBLE;
    ticket.outcome = Outcome::REVALIDATION_REQUIRED;
    ticket.detail = current_binding == nullptr
                        ? "the current preferred path is no longer part of the candidate set"
                        : "the current preferred path is no longer eligible";
    // The incumbent's own reason is more useful than a generic one, so an
    // evidence problem is reported as an evidence problem.
    for (const auto& ranked : ticket.ranking) {
      if (!(ranked.path == inputs.preference.preferred_path)) {
        continue;
      }
      if (ranked.rejection == SuppressionReason::STALE_EVIDENCE) {
        ticket.suppression = SuppressionReason::STALE_EVIDENCE;
        ticket.outcome = Outcome::STALE_EVIDENCE;
        ticket.detail = "the current preferred path has no current evidence";
      } else if (ranked.rejection == SuppressionReason::INSUFFICIENT_SAMPLES ||
                 ranked.rejection == SuppressionReason::EVIDENCE_UNKNOWN) {
        ticket.suppression = ranked.rejection;
        ticket.outcome = Outcome::INSUFFICIENT_EVIDENCE;
        ticket.detail = "the current preferred path has insufficient evidence";
      }
      break;
    }
    if (!emergency) {
      return ticket;
    }
  }

  const bool reverse = inputs.preference.previous_path.valid() &&
                       inputs.preference.previous_path == best->path;

  if (!emergency) {
    // hold-down: an ordinary reverse adaptation is suppressed for the declared
    // interval, extended deterministically by the dampening penalty.
    Ticks effective_hold_down = semantics.hold_down.duration;
    bool extended = false;
    if (semantics.dampening.enabled && inputs.timing.dampening_penalty != 0) {
      // effective = min(duration + penalty * escalation_step, cap)
      const std::uint64_t escalated =
          static_cast<std::uint64_t>(semantics.hold_down.duration) +
          static_cast<std::uint64_t>(inputs.timing.dampening_penalty) *
              semantics.dampening.hold_down_escalation_step;
      const std::uint64_t capped =
          (std::min)(escalated, semantics.dampening.max_effective_hold_down);
      if (capped > effective_hold_down) {
        effective_hold_down = static_cast<Ticks>(capped);
        extended = true;
      }
    }
    if (inputs.timing.hold_down_active && effective_hold_down != 0) {
      const Ticks elapsed = inputs.now >= inputs.timing.hold_down_deadline
                                ? 0
                                : inputs.timing.hold_down_deadline - inputs.now;
      if (reverse && elapsed != 0) {
        const Ticks base_remaining =
            inputs.timing.hold_down_deadline > inputs.now ? inputs.timing.hold_down_deadline - inputs.now : 0;
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = extended && base_remaining == 0
                                 ? SuppressionReason::DAMPENING_EXTENDED_HOLD_DOWN
                                 : SuppressionReason::HOLD_DOWN_ACTIVE;
        ticket.outcome = Outcome::HOLD_DOWN_ACTIVE;
        ticket.detail = "hold-down suppresses the reverse adaptation to " + best->path.str();
        return ticket;
      }
    }
    if (inputs.timing.cooldown_active && inputs.now < inputs.timing.cooldown_deadline) {
      ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
      ticket.suppression = SuppressionReason::COOLDOWN_ACTIVE;
      ticket.outcome = Outcome::COOLDOWN_ACTIVE;
      ticket.detail = "cooldown suppresses the adaptation";
      return ticket;
    }

    // Explicit band thresholds.
    for (const auto& rule : semantics.thresholds) {
      const EvidenceRequirement* requirement = nullptr;
      for (const auto& declared : semantics.evidence) {
        if (declared.kind == rule.kind) {
          requirement = &declared;
          break;
        }
      }
      if (requirement == nullptr || current_binding == nullptr) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = SuppressionReason::HYSTERESIS_NOT_CLEARED;
        ticket.outcome = Outcome::HYSTERESIS_NOT_CLEARED;
        ticket.detail = "threshold rule cannot be evaluated for " +
                        std::string(to_string(rule.kind));
        return ticket;
      }
      const MetricLookup current = lookup_metric(inputs, current_binding->binding.path, *requirement);
      const MetricLookup candidate = lookup_metric(inputs, best->path, *requirement);
      if (!current.ok || !candidate.ok) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = current.ok ? candidate.reason : current.reason;
        ticket.outcome = suppression_outcome(ticket.suppression);
        ticket.detail = "threshold rule lacks current evidence for " +
                        std::string(to_string(rule.kind));
        return ticket;
      }
      if (!threshold_permits_departure(current.value, rule.switch_value)) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = SuppressionReason::BELOW_THRESHOLD;
        ticket.outcome = Outcome::NO_CHANGE;
        ticket.detail = "current preference has not crossed the switch threshold for " +
                        std::string(to_string(rule.kind));
        return ticket;
      }
      if (!threshold_permits_entry(candidate.value, rule.clear_value)) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = SuppressionReason::HYSTERESIS_NOT_CLEARED;
        ticket.outcome = Outcome::HYSTERESIS_NOT_CLEARED;
        ticket.detail = "candidate has not cleared the hysteresis band for " +
                        std::string(to_string(rule.kind));
        return ticket;
      }
    }

    // Relative improvement rules with the asymmetric reverse requirement.
    for (const auto& rule : semantics.improvements) {
      const EvidenceRequirement* requirement = nullptr;
      for (const auto& declared : semantics.evidence) {
        if (declared.kind == rule.kind) {
          requirement = &declared;
          break;
        }
      }
      if (requirement == nullptr || current_binding == nullptr) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = SuppressionReason::BELOW_THRESHOLD;
        ticket.outcome = Outcome::NO_CHANGE;
        ticket.detail = "improvement rule cannot be evaluated for " +
                        std::string(to_string(rule.kind));
        return ticket;
      }
      const MetricLookup current = lookup_metric(inputs, current_binding->binding.path, *requirement);
      const MetricLookup candidate = lookup_metric(inputs, best->path, *requirement);
      if (!current.ok || !candidate.ok) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = current.ok ? candidate.reason : current.reason;
        ticket.outcome = suppression_outcome(ticket.suppression);
        ticket.detail = "improvement rule lacks current evidence for " +
                        std::string(to_string(rule.kind));
        return ticket;
      }
      const auto improvement = relative_improvement_bps(current.value, candidate.value);
      if (!improvement.has_value()) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = SuppressionReason::BELOW_THRESHOLD;
        ticket.outcome = Outcome::INCOMPATIBLE_METRIC;
        ticket.detail = "improvement comparison is not defined for " +
                        std::string(to_string(rule.kind));
        return ticket;
      }
      const std::uint32_t required =
          reverse ? rule.reverse_improvement_bps : rule.switch_improvement_bps;
      ticket.improvement_bps = *improvement;
      ticket.required_improvement_bps = required;
      if (*improvement < required) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = reverse ? SuppressionReason::HYSTERESIS_NOT_CLEARED
                                     : SuppressionReason::BELOW_THRESHOLD;
        ticket.outcome = suppression_outcome(ticket.suppression);
        ticket.detail = "observed improvement " + std::to_string(*improvement) +
                        " bps is below the required " + std::to_string(required) + " bps" +
                        (reverse ? " for a reverse adaptation" : "");
        return ticket;
      }
    }

    // Bounded churn.
    if (semantics.churn.enabled()) {
      std::uint32_t recent = 0;
      for (const Ticks stamp : inputs.timing.churn_commits) {
        if (inputs.now >= stamp && inputs.now - stamp <= semantics.churn.window) {
          ++recent;
        }
      }
      if (recent >= semantics.churn.max_adaptations_per_window) {
        ticket.lifecycle = DecisionLifecycle::SUPPRESSED;
        ticket.suppression = SuppressionReason::CHURN_LIMIT_REACHED;
        ticket.outcome = Outcome::CHURN_LIMIT_REACHED;
        ticket.detail = "churn bound reached: " + std::to_string(recent) +
                        " adaptation(s) inside the declared window";
        return ticket;
      }
    }
  }

  // --- weight proposal ----------------------------------------------------
  if (semantics.target.multipath_set.has_value() && best != nullptr) {
    for (const auto& candidate : inputs.candidates) {
      if (candidate.binding.path == best->path && candidate.binding.weighted.has_value()) {
        WeightProposal proposal;
        proposal.set = candidate.binding.weighted->set;
        proposal.base_generation = candidate.binding.weighted->generation;
        for (const auto& member : inputs.candidates) {
          PathWeight weight;
          weight.path = member.binding.path;
          weight.weight_bps = member.binding.path == best->path ? basis_points_scale : 0U;
          proposal.weights.push_back(weight);
        }
        if (proposal.well_formed()) {
          ticket.weight_proposal = proposal;
        }
        break;
      }
    }
  }

  ticket.lifecycle = DecisionLifecycle::ELIGIBLE;
  if (emergency) {
    ticket.detail = "emergency override: " + emergency_reason;
  } else {
    ticket.detail = "trigger satisfied for " + best->path.str();
  }
  return ticket;
}

// ---------------------------------------------------------------------------
// Dependency drift
// ---------------------------------------------------------------------------

std::optional<Outcome> Impl::dependency_drift(const State& state, const PolicyRecord& record,
                                              const DependencySnapshot& snapshot) const {
  if (record.candidates.size() != snapshot.candidates.size()) {
    return Outcome::REVALIDATION_REQUIRED;
  }
  for (std::size_t index = 0; index < record.candidates.size(); ++index) {
    const CandidateRecord& candidate = record.candidates[index];
    if (!(candidate.binding.path == snapshot.candidates[index])) {
      return Outcome::REVALIDATION_REQUIRED;
    }
    if (index < snapshot.candidate_path_watermarks.size() &&
        candidate.path_watermark != snapshot.candidate_path_watermarks[index]) {
      // Something about this path moved after the evaluation read it. The
      // precise cause is recovered by comparing the recorded facts.
      if (index < snapshot.candidate_path_authority.size()) {
        const PathAuthorityBinding& recorded = snapshot.candidate_path_authority[index];
        if (!(recorded.generation == candidate.binding.path_authority.generation) ||
            recorded.legal != candidate.binding.path_authority.legal) {
          return Outcome::STALE_PATH_AUTHORITY;
        }
      }
      if (candidate.binding.multipath.has_value()) {
        if (!candidate.binding.multipath->current || !snapshot.multipath_set_generation.valid() ||
            !(candidate.binding.multipath->generation == snapshot.multipath_set_generation)) {
          return Outcome::STALE_MULTIPATH_SET;
        }
      }
      if (!(candidate.binding.route.generation == snapshot.route_generation)) {
        return Outcome::STALE_ROUTE;
      }
      return Outcome::STALE_PATH_AUTHORITY;
    }
    if (index < snapshot.candidate_path_authority.size()) {
      const PathAuthorityBinding& recorded = snapshot.candidate_path_authority[index];
      if (!(recorded.generation == candidate.binding.path_authority.generation) ||
          recorded.legal != candidate.binding.path_authority.legal) {
        return Outcome::STALE_PATH_AUTHORITY;
      }
    }
  }
  (void)state;
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Phase one
// ---------------------------------------------------------------------------

EvaluationTicket Impl::begin_evaluation(const EvaluateRequest& request) {
  EvaluationTicket ticket;
  if (!request.policy.valid()) {
    ticket.lifecycle = DecisionLifecycle::REJECTED;
    ticket.outcome = Outcome::MALFORMED_REQUEST;
    ticket.detail = "policy id is required";
    return ticket;
  }
  if (outstanding_evaluations_.load() >= limits_.max_simultaneous_evaluations) {
    ticket.lifecycle = DecisionLifecycle::REJECTED;
    ticket.outcome = Outcome::EVALUATION_LIMIT;
    ticket.detail = "simultaneous evaluation limit reached";
    return ticket;
  }
  EvaluationInputs inputs;
  {
    std::shared_lock lock(mutex_);
    const auto position = state_.policies.find(request.policy);
    if (position == state_.policies.end()) {
      ticket.lifecycle = DecisionLifecycle::REJECTED;
      ticket.outcome = Outcome::NOT_FOUND;
      ticket.detail = "policy does not exist";
      return ticket;
    }
    const PolicyRecord& record = position->second;
    const CallerCheck caller =
        check_caller(state_, request.context, record.policy.semantics.target.route,
                     record.policy.semantics.target.multipath_set);
    if (!caller.ok) {
      ticket.lifecycle = DecisionLifecycle::REJECTED;
      ticket.outcome = caller.outcome;
      ticket.detail = caller.detail;
      return ticket;
    }
    if (record.policy.lifecycle != PolicyLifecycle::ACTIVE) {
      ticket.lifecycle = DecisionLifecycle::REJECTED;
      ticket.outcome = lifecycle_outcome(record.policy.lifecycle);
      ticket.detail = "policy lifecycle is " +
                      std::string(to_string(record.policy.lifecycle));
      return ticket;
    }
    if (request.context.expected_policy_generation.has_value() &&
        !(*request.context.expected_policy_generation == record.policy.generation)) {
      ticket.lifecycle = DecisionLifecycle::REJECTED;
      ticket.outcome = Outcome::STALE_POLICY_GENERATION;
      ticket.detail = "expected policy generation does not match";
      return ticket;
    }
    if (request.context.expected_evidence_generation.has_value() &&
        !(*request.context.expected_evidence_generation == state_.evidence_generation)) {
      ticket.lifecycle = DecisionLifecycle::REJECTED;
      ticket.outcome = Outcome::STALE_EVIDENCE;
      ticket.detail = "expected evidence generation does not match";
      return ticket;
    }
    ticket.dependencies = build_dependencies(state_, record, ids_.next_evaluation_id());
    inputs = copy_inputs(state_, record);
  }
  outstanding_evaluations_.fetch_add(1);
  ticket.decision = ids_.next_decision_id();
  EvaluationTicket computed = evaluate_inputs(inputs, ticket.dependencies);
  computed.decision = ticket.decision;
  // The deterministic scheduling hook runs with no lock held, after the
  // dependency snapshot was taken and before any commit verification.
  if (config_.evaluation_hook) {
    config_.evaluation_hook(computed.dependencies);
  }
  return computed;
}

// ---------------------------------------------------------------------------
// Phase two
// ---------------------------------------------------------------------------

OperationResult Impl::commit_evaluation(const CommitDecisionRequest& request) {
  std::unique_lock lock(mutex_);
  const EvaluationTicket& ticket = request.ticket;
  auto finish = [this](OperationResult result) {
    const std::uint64_t outstanding = outstanding_evaluations_.load();
    if (outstanding != 0) {
      outstanding_evaluations_.fetch_sub(1);
    }
    ++counters_.evaluations;
    return result;
  };
  if (ticket.lifecycle == DecisionLifecycle::REJECTED) {
    // Phase one already refused the evaluation before it read any dependency.
    return finish(make_result(ticket.outcome, ticket.detail, AdaptivePolicyId(), state_));
  }
  if (!ticket.dependencies.policy.valid()) {
    return finish(make_result(Outcome::MALFORMED_REQUEST, "evaluation ticket is malformed",
                              AdaptivePolicyId(), state_));
  }
  const CallerCheck caller = check_caller(state_, request.context, std::nullopt, std::nullopt);
  if (!caller.ok) {
    return finish(make_result(caller.outcome, caller.detail, ticket.dependencies.policy, state_));
  }
  const auto position = state_.policies.find(ticket.dependencies.policy);
  if (position == state_.policies.end()) {
    return finish(make_result(Outcome::NOT_FOUND, "policy does not exist",
                              ticket.dependencies.policy, state_));
  }
  PolicyRecord& record = position->second;
  // Authority first: an epoch or authority-generation advance outranks the
  // lifecycle change it causes, so the operator is told the real reason.
  if (!(state_.epoch == ticket.dependencies.epoch)) {
    return finish(make_result(Outcome::STALE_EPOCH,
                              "epoch advanced after the evaluation started",
                              ticket.dependencies.policy, state_));
  }
  if (!(state_.authority_generation == ticket.dependencies.authority_generation)) {
    return finish(make_result(Outcome::REVALIDATION_REQUIRED,
                              "authority generation advanced after the evaluation started",
                              ticket.dependencies.policy, state_));
  }
  if (record.policy.lifecycle != PolicyLifecycle::ACTIVE) {
    return finish(make_result(lifecycle_outcome(record.policy.lifecycle),
                              "policy lifecycle is " +
                                  std::string(to_string(record.policy.lifecycle)),
                              ticket.dependencies.policy, state_));
  }
  if (!(record.policy.generation == ticket.dependencies.policy_generation)) {
    return finish(make_result(Outcome::STALE_POLICY_GENERATION,
                              "policy generation advanced after the evaluation started",
                              ticket.dependencies.policy, state_));
  }
  if (ticket.lifecycle == DecisionLifecycle::ELIGIBLE) {
    if (!(state_.evidence_generation == ticket.dependencies.evidence_generation)) {
      ++counters_.stale_commit_rejections;
      return finish(make_result(Outcome::STALE_EVIDENCE,
                                "evidence generation advanced after the evaluation started",
                                ticket.dependencies.policy, state_));
    }
    if (!(state_.evidence_watermark == ticket.dependencies.evidence_watermark)) {
      ++counters_.stale_commit_rejections;
      return finish(make_result(Outcome::STALE_EVIDENCE,
                                "the evidence watermark advanced after the evaluation started",
                                ticket.dependencies.policy, state_));
    }
    if (const auto drift = dependency_drift(state_, record, ticket.dependencies)) {
      ++counters_.stale_commit_rejections;
      return finish(make_result(*drift,
                                "an upstream dependency changed after the evaluation started",
                                ticket.dependencies.policy, state_));
    }
  }
  const auto fingerprint = [&ticket]() {
    Digest digest;
    digest.write_tag("commit-decision");
    digest.write_string(ticket.dependencies.policy.str());
    digest.write_u64(ticket.dependencies.policy_generation.value());
    digest.write_u64(ticket.dependencies.evidence_generation.value());
    digest.write_string(ticket.target_preference.str());
    digest.write_string(ticket.detail);
    return digest.hex();
  }();
  if (const auto replay = replay_check(state_, request.context.attempt, fingerprint)) {
    return finish(*replay);
  }

  if (ticket.lifecycle != DecisionLifecycle::ELIGIBLE) {
    // A suppressed or rejected evaluation is still recorded: "no change" is
    // never reported without its reason.
    AdaptationDecision decision;
    decision.id = ticket.decision.valid() ? ticket.decision : ids_.next_decision_id();
    decision.policy = record.policy.id;
    decision.policy_generation = record.policy.generation;
    decision.lifecycle = DecisionLifecycle::SUPPRESSED;
    decision.cause = AdaptationCause::TRIGGER_SATISFIED;
    decision.suppression = ticket.suppression;
    decision.outcome = ticket.outcome;
    decision.epoch = state_.epoch;
    decision.authority_generation = state_.authority_generation;
    decision.route = record.policy.semantics.target.route;
    decision.route_generation = record.preference.route_generation;
    decision.multipath_set = record.policy.semantics.target.multipath_set;
    decision.multipath_set_generation = record.preference.multipath_set_generation;
    decision.evidence_generation = state_.evidence_generation;
    decision.evidence_watermark = state_.evidence_watermark;
    decision.upstream_watermark = state_.upstream_watermark;
    decision.had_current_preference = record.preference.established;
    decision.current_preference = record.preference.preferred_path;
    decision.current_preference_authority_generation =
        record.preference.path_authority_generation;
    decision.target_preference = ticket.target_preference;
    decision.target_preference_authority_generation = ticket.target_path_authority_generation;
    decision.adaptation_generation = record.preference.adaptation_generation;
    decision.transition_generation = record.preference.transition_generation;
    decision.required_improvement_bps = ticket.required_improvement_bps;
    decision.improvement_bps = ticket.improvement_bps;
    decision.candidates_considered = static_cast<std::uint32_t>(ticket.ranking.size());
    for (const auto& entry : ticket.ranking) {
      if (entry.eligible) {
        ++decision.candidates_eligible;
      }
    }
    decision.ranking = ticket.ranking;
    decision.evaluated_at = ticket.evaluated_at;
    decision.provenance.publisher = request.context.publisher;
    decision.provenance.worker_boot = request.context.worker_boot;
    decision.provenance.epoch = state_.epoch;
    decision.provenance.attempt = request.context.attempt;
    decision.provenance.policy_generation = record.policy.generation;
    decision.provenance.cause = AdaptationCause::TRIGGER_SATISFIED;
    decision.digest = decision_digest(decision);

    AdaptationRecord record_entry;
    record_entry.decision = decision.id;
    record_entry.lifecycle = decision.lifecycle;
    record_entry.outcome = decision.outcome;
    record_entry.suppression = decision.suppression;
    record_entry.cause = decision.cause;
    record_entry.from_path = decision.current_preference;
    record_entry.to_path = decision.target_preference;
    record_entry.adaptation_generation = decision.adaptation_generation;
    record_entry.evidence_generation = decision.evidence_generation;
    record_entry.epoch = decision.epoch;
    record_entry.committed_at = now();
    record_entry.digest = decision.digest;
    record.history.push_back(record_entry);
    prune_history(record, limits_);
    state_.decision_journal.push_back(decision);
    while (state_.decision_journal.size() > limits_.max_decision_history) {
      state_.decision_journal.pop_front();
    }
    ++counters_.decisions_suppressed;
    record_attempt(state_, request.context.attempt, fingerprint, decision.outcome, decision.digest);
    // The reason is carried verbatim so that an operator sees *why* nothing
    // changed; the digest follows it as the audit handle.
    OperationResult result = make_result(
        decision.outcome, ticket.detail + " digest=" + decision.digest, record.policy.id, state_);
    result.decision = decision.id;
    result.suppression = decision.suppression;
    return finish(result);
  }

  // --- commit --------------------------------------------------------------
  if (record.preference.established &&
      record.preference.preferred_path == ticket.target_preference) {
    // Two tickets taken from the same state must not both advance the adaptation
    // generation. The second one is a no-op, not a second adaptation.
    record_attempt(state_, request.context.attempt, fingerprint, Outcome::NO_CHANGE,
                   "the target preference is already current");
    OperationResult result = make_result(Outcome::NO_CHANGE,
                                         "the target preference is already current",
                                         record.policy.id, state_);
    result.decision = record.preference.decision;
    return finish(result);
  }
  const auto verification =
      verify_and_commit(state_, record, ticket, request.context, caller.registration);
  if (!verification.ok) {
    return finish(make_result(verification.outcome, verification.detail, record.policy.id, state_));
  }
  counters_.decisions_committed++;
  record_attempt(state_, request.context.attempt, fingerprint, Outcome::DECISION_COMMITTED,
                 "decision committed");
  OperationResult result = make_result(Outcome::DECISION_COMMITTED, ticket.detail, record.policy.id,
                                       state_);
  result.decision = record.preference.decision;
  result.mutated = true;
  return finish(result);
}

OperationResult Impl::evaluate(const EvaluateRequest& request) {
  const EvaluationTicket ticket = begin_evaluation(request);
  if (ticket.lifecycle == DecisionLifecycle::REJECTED && !ticket.dependencies.policy.valid()) {
    // Phase one refused before reading any dependency; nothing was issued, so
    // there is no outstanding evaluation to settle.
    return OperationResult::make(ticket.outcome, ticket.detail);
  }
  if (request.defer_commit) {
    if (ticket.lifecycle == DecisionLifecycle::REJECTED) {
      return OperationResult::make(ticket.outcome, ticket.detail);
    }
    OperationResult result = OperationResult::make(ticket.outcome, ticket.detail);
    result.decision = ticket.decision;
    result.suppression = ticket.suppression;
    return result;
  }
  CommitDecisionRequest commit;
  commit.ticket = ticket;
  commit.context = request.context;
  return commit_evaluation(commit);
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------

CommitVerification Impl::verify_and_commit(State& state, PolicyRecord& record,
                                           const EvaluationTicket& ticket,
                                           const MutationContext& context,
                                           const PublisherRegistration* /*registration*/) {
  CommitVerification verification;
  const PolicySemantics& semantics = record.policy.semantics;
  const Ticks current = now();

  // Re-check the suppression predicates that the evaluation decided: state may
  // have moved while the evaluation was running unlocked.
  const bool reverse = record.preference.previous_path.valid() &&
                       record.preference.previous_path == ticket.target_preference;
  if (!ticket.emergency) {
    Ticks effective_hold_down = semantics.hold_down.duration;
    if (semantics.dampening.enabled && record.timing.dampening_penalty != 0) {
      const std::uint64_t escalated =
          static_cast<std::uint64_t>(semantics.hold_down.duration) +
          static_cast<std::uint64_t>(record.timing.dampening_penalty) *
              semantics.dampening.hold_down_escalation_step;
      effective_hold_down = static_cast<Ticks>(
          (std::min)(escalated, semantics.dampening.max_effective_hold_down));
    }
    if (record.timing.hold_down_active && reverse && effective_hold_down != 0 &&
        current < record.timing.hold_down_deadline) {
      verification.outcome = Outcome::HOLD_DOWN_ACTIVE;
      verification.suppression = SuppressionReason::HOLD_DOWN_ACTIVE;
      verification.detail = "hold-down became active before the commit";
      return verification;
    }
    if (record.timing.cooldown_active && current < record.timing.cooldown_deadline) {
      verification.outcome = Outcome::COOLDOWN_ACTIVE;
      verification.suppression = SuppressionReason::COOLDOWN_ACTIVE;
      verification.detail = "cooldown became active before the commit";
      return verification;
    }
    if (semantics.churn.enabled()) {
      std::uint32_t recent = 0;
      for (const Ticks stamp : record.timing.churn_commits) {
        if (current >= stamp && current - stamp <= semantics.churn.window) {
          ++recent;
        }
      }
      if (recent >= semantics.churn.max_adaptations_per_window) {
        verification.outcome = Outcome::CHURN_LIMIT_REACHED;
        verification.suppression = SuppressionReason::CHURN_LIMIT_REACHED;
        verification.detail = "churn bound reached before the commit";
        return verification;
      }
    }
  }

  const CandidateRecord* target = record.find_candidate(ticket.target_preference);
  if (target == nullptr) {
    verification.outcome = Outcome::REVALIDATION_REQUIRED;
    verification.detail = "the target candidate disappeared before the commit";
    return verification;
  }
  if (!target->binding.path_authority.legal) {
    verification.outcome = Outcome::STALE_PATH_AUTHORITY;
    verification.detail = "the target candidate is no longer authorized";
    return verification;
  }
  if (ticket.target_path_authority_generation.valid() &&
      !(target->binding.path_authority.generation == ticket.target_path_authority_generation)) {
    verification.outcome = Outcome::STALE_PATH_AUTHORITY;
    verification.detail = "the target path authority generation moved before the commit";
    return verification;
  }

  // Pending transition bound.
  std::uint64_t pending = 0;
  for (const auto& entry : state.policies) {
    if (entry.second.timing.hold_down_active && current < entry.second.timing.hold_down_deadline) {
      ++pending;
    }
  }
  if (pending >= limits_.max_pending_transitions) {
    verification.outcome = Outcome::RESOURCE_LIMIT;
    verification.detail = "pending transition limit reached";
    return verification;
  }

  const auto adaptation = record.preference.adaptation_generation.next();
  const auto transition = record.preference.transition_generation.next();
  if (!adaptation.has_value() || !transition.has_value()) {
    verification.outcome = Outcome::GENERATION_OVERFLOW;
    verification.detail = "adaptation or transition generation is exhausted";
    return verification;
  }

  // --- atomic state transition -------------------------------------------
  const bool had_preference = record.preference.established;
  const PathId superseded = record.preference.preferred_path;
  const PathAuthorityGeneration superseded_authority =
      record.preference.path_authority_generation;
  const RouteGeneration superseded_route = record.preference.route_generation;
  const MultipathSetGeneration superseded_set = record.preference.multipath_set_generation;
  const AdaptationGeneration superseded_adaptation = record.preference.adaptation_generation;
  record.preference.previous_path = had_preference ? superseded : PathId();
  record.preference.preferred_path = target->binding.path;
  record.preference.path_authority_generation = target->binding.path_authority.generation;
  record.preference.route_generation = target->binding.route.generation;
  record.preference.multipath_set = semantics.target.multipath_set;
  if (target->binding.multipath.has_value()) {
    record.preference.multipath_set_generation = target->binding.multipath->generation;
  }
  record.preference.adaptation_generation = *adaptation;
  record.preference.transition_generation = *transition;
  record.preference.transition = ids_.next_transition_id();
  record.preference.weight_proposal = ticket.weight_proposal;
  record.preference.committed_at = current;
  record.preference.established = true;
  record.preference.provenance.publisher = context.publisher;
  record.preference.provenance.worker_boot = context.worker_boot;
  record.preference.provenance.epoch = state.epoch;
  record.preference.provenance.attempt = context.attempt;
  record.preference.provenance.policy_generation = record.policy.generation;
  record.preference.provenance.cause =
      ticket.emergency ? AdaptationCause::EMERGENCY_OVERRIDE : AdaptationCause::TRIGGER_SATISFIED;

  // The last known stable state is the preference that was *held* with matching
  // dependencies until this transition displaced it, which is what makes it a
  // meaningful rollback anchor. Establishing the first preference leaves no
  // anchor, because nothing preceded it. Whether the *current* preference is
  // stable is a separate question, answered by its currentness.
  if (had_preference) {
    record.stable.established = true;
    record.stable.path = superseded;
    record.stable.path_authority_generation = superseded_authority;
    record.stable.route_generation = superseded_route;
    record.stable.multipath_set_generation = superseded_set;
    record.stable.adaptation_generation = superseded_adaptation;
    record.stable.stabilized_at = current;
  } else {
    record.stable = StableState{};
  }

  // Establishing the very first preference is not an adaptation: there is
  // nothing to reverse, no churn has occurred and no oscillation is possible, so
  // hold-down, cooldown and the churn budget are left untouched. Every later
  // commit is an adaptation and arms all three.
  if (had_preference) {
    Ticks effective_hold_down = semantics.hold_down.duration;
    if (semantics.dampening.enabled) {
      const std::uint32_t penalty =
          (std::min)(semantics.dampening.max_penalty,
                     record.timing.dampening_penalty + semantics.dampening.penalty_increment);
      record.timing.dampening_penalty = penalty;
      const std::uint64_t escalated =
          static_cast<std::uint64_t>(semantics.hold_down.duration) +
          static_cast<std::uint64_t>(penalty) * semantics.dampening.hold_down_escalation_step;
      effective_hold_down = static_cast<Ticks>(
          (std::min)(escalated, semantics.dampening.max_effective_hold_down));
      record.timing.dampening_last_decay = current;
    }
    record.timing.hold_down_active = effective_hold_down != 0;
    record.timing.hold_down_deadline = current + effective_hold_down;
    record.timing.hold_down_locked_path = record.preference.previous_path;
    record.timing.cooldown_active = semantics.cooldown.duration != 0;
    record.timing.cooldown_deadline = current + semantics.cooldown.duration;
    record.timing.churn_commits.push_back(current);
    while (!record.timing.churn_commits.empty() &&
           record.timing.churn_commits.size() > limits_.max_adaptations_per_window) {
      record.timing.churn_commits.pop_front();
    }
  }

  AdaptationDecision decision;
  decision.id = ticket.decision.valid() ? ticket.decision : ids_.next_decision_id();
  decision.policy = record.policy.id;
  decision.policy_generation = record.policy.generation;
  decision.lifecycle = DecisionLifecycle::COMMITTED;
  decision.cause = record.preference.provenance.cause;
  decision.suppression = SuppressionReason::NONE;
  decision.outcome = Outcome::DECISION_COMMITTED;
  decision.epoch = state.epoch;
  decision.authority_generation = state.authority_generation;
  decision.route = semantics.target.route;
  decision.route_generation = record.preference.route_generation;
  decision.multipath_set = semantics.target.multipath_set;
  decision.multipath_set_generation = record.preference.multipath_set_generation;
  decision.evidence_snapshot = ticket.evidence_snapshot;
  decision.evidence_generation = ticket.dependencies.evidence_generation;
  decision.evidence_watermark = ticket.dependencies.evidence_watermark;
  decision.upstream_watermark = ticket.dependencies.upstream_watermark;
  decision.had_current_preference = had_preference;
  decision.current_preference = had_preference ? superseded : PathId();
  for (std::size_t index = 0; index < ticket.dependencies.candidates.size(); ++index) {
    if (ticket.dependencies.candidates[index] == superseded &&
        index < ticket.dependencies.candidate_path_authority.size()) {
      decision.current_preference_authority_generation =
          ticket.dependencies.candidate_path_authority[index].generation;
    }
  }
  decision.target_preference = record.preference.preferred_path;
  decision.target_preference_authority_generation = record.preference.path_authority_generation;
  decision.adaptation_generation = record.preference.adaptation_generation;
  decision.transition_generation = record.preference.transition_generation;
  decision.target_score = ticket.target_score;
  decision.improvement_bps = ticket.improvement_bps;
  decision.required_improvement_bps = ticket.required_improvement_bps;
  decision.candidates_considered = static_cast<std::uint32_t>(ticket.ranking.size());
  for (const auto& entry : ticket.ranking) {
    if (entry.eligible) {
      ++decision.candidates_eligible;
    }
  }
  decision.ranking = ticket.ranking;
  decision.evaluated_at = ticket.evaluated_at;
  decision.committed_at = current;
  decision.provenance = record.preference.provenance;
  decision.digest = decision_digest(decision);
  record.preference.decision = decision.id;

  AdaptationRecord record_entry;
  record_entry.decision = decision.id;
  record_entry.lifecycle = decision.lifecycle;
  record_entry.outcome = decision.outcome;
  record_entry.suppression = decision.suppression;
  record_entry.cause = decision.cause;
  record_entry.from_path = decision.current_preference;
  record_entry.to_path = decision.target_preference;
  record_entry.adaptation_generation = decision.adaptation_generation;
  record_entry.evidence_generation = decision.evidence_generation;
  record_entry.epoch = decision.epoch;
  record_entry.committed_at = current;
  record_entry.digest = decision.digest;
  record.history.push_back(record_entry);
  prune_history(record, limits_);
  state.decision_journal.push_back(decision);
  while (state.decision_journal.size() > limits_.max_decision_history) {
    state.decision_journal.pop_front();
  }

  verification.ok = true;
  verification.outcome = Outcome::DECISION_COMMITTED;
  verification.detail = ticket.detail;
  return verification;
}

// ---------------------------------------------------------------------------
// Rollback and revalidation
// ---------------------------------------------------------------------------

OperationResult Impl::rollback(const RollbackRequest& request) {
  std::unique_lock lock(mutex_);
  if (!request.policy.valid()) {
    return make_result(Outcome::MALFORMED_REQUEST, "policy id is required", request.policy, state_);
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
  if (record.policy.lifecycle != PolicyLifecycle::ACTIVE) {
    return make_result(lifecycle_outcome(record.policy.lifecycle),
                       "rollback requires an active policy", request.policy, state_);
  }
  const auto fingerprint = [&]() {
    Digest digest;
    digest.write_tag("rollback");
    digest.write_string(request.policy.str());
    digest.write_string(request.reason);
    return digest.hex();
  }();
  if (const auto replay = replay_check(state_, request.context.attempt, fingerprint)) {
    return *replay;
  }
  if (!record.stable.established) {
    record_attempt(state_, request.context.attempt, fingerprint, Outcome::ROLLBACK_REFUSED,
                   "no last known stable state");
    return make_result(Outcome::ROLLBACK_REFUSED,
                       "there is no last known stable state to restore", request.policy, state_);
  }
  const PathId target_path = record.stable.path;
  // Rollback is not an unconditional undo: the restore target is revalidated
  // against Path Authority, route currency and multipath membership BEFORE any
  // short circuit, so a rollback onto an unauthorized stable path is refused
  // rather than reported as a harmless no-op.
  const CandidateRecord* target = record.find_candidate(target_path);
  if (target == nullptr) {
    record_attempt(state_, request.context.attempt, fingerprint, Outcome::ROLLBACK_REFUSED,
                   "stable path is not a candidate");
    return make_result(Outcome::ROLLBACK_REFUSED,
                       "the last known stable path is no longer a candidate", request.policy,
                       state_);
  }
  if (!target->binding.path_authority.legal) {
    record_attempt(state_, request.context.attempt, fingerprint, Outcome::STALE_PATH_AUTHORITY,
                   "stable path is not authorized");
    return make_result(Outcome::STALE_PATH_AUTHORITY,
                       "the last known stable path is no longer authorized", request.policy,
                       state_);
  }
  if (!target->binding.route.current) {
    return make_result(Outcome::STALE_ROUTE, "the last known stable path has a stale route",
                       request.policy, state_);
  }
  if (!target->binding.available) {
    return make_result(Outcome::WITHDRAWN_UPSTREAM,
                       "the last known stable path is no longer available", request.policy,
                       state_);
  }
  if (record.policy.semantics.target.multipath_set.has_value()) {
    if (!target->binding.multipath.has_value() || !target->binding.multipath->current ||
        !target->binding.multipath->contains(target_path)) {
      return make_result(Outcome::STALE_MULTIPATH_SET,
                         "the last known stable path left the multipath set", request.policy,
                         state_);
    }
  }
  if (record.preference.established && record.preference.preferred_path == target_path) {
    record_attempt(state_, request.context.attempt, fingerprint, Outcome::NO_CHANGE,
                   "already at the stable preference");
    return make_result(Outcome::NO_CHANGE,
                       "the current preference is already the last known stable preference",
                       request.policy, state_);
  }
  const auto adaptation = record.preference.adaptation_generation.next();
  const auto transition = record.preference.transition_generation.next();
  if (!adaptation.has_value() || !transition.has_value()) {
    return make_result(Outcome::GENERATION_OVERFLOW, "generation is exhausted", request.policy,
                       state_);
  }
  AdaptationDecision decision;
  decision.id = ids_.next_decision_id();
  decision.policy = record.policy.id;
  decision.policy_generation = record.policy.generation;
  decision.lifecycle = DecisionLifecycle::ROLLED_BACK;
  decision.cause = AdaptationCause::ROLLBACK_REQUESTED;
  decision.outcome = Outcome::DECISION_COMMITTED;
  decision.epoch = state_.epoch;
  decision.authority_generation = state_.authority_generation;
  decision.route = record.policy.semantics.target.route;
  decision.route_generation = target->binding.route.generation;
  decision.multipath_set = record.policy.semantics.target.multipath_set;
  decision.evidence_generation = state_.evidence_generation;
  decision.evidence_watermark = state_.evidence_watermark;
  decision.upstream_watermark = state_.upstream_watermark;
  decision.had_current_preference = true;
  decision.current_preference = record.preference.preferred_path;
  decision.current_preference_authority_generation = record.preference.path_authority_generation;
  decision.target_preference = target_path;
  decision.target_preference_authority_generation = target->binding.path_authority.generation;
  decision.adaptation_generation = *adaptation;
  decision.transition_generation = *transition;
  decision.committed_at = now();
  decision.evaluated_at = decision.committed_at;
  decision.provenance.publisher = request.context.publisher;
  decision.provenance.worker_boot = request.context.worker_boot;
  decision.provenance.epoch = state_.epoch;
  decision.provenance.attempt = request.context.attempt;
  decision.provenance.policy_generation = record.policy.generation;
  decision.provenance.cause = AdaptationCause::ROLLBACK_REQUESTED;
  decision.digest = decision_digest(decision);

  const PathId displaced = record.preference.preferred_path;
  record.stable.established = true;
  record.stable.path = displaced;
  record.stable.path_authority_generation = record.preference.path_authority_generation;
  record.stable.route_generation = record.preference.route_generation;
  record.stable.multipath_set_generation = record.preference.multipath_set_generation;
  record.stable.adaptation_generation = record.preference.adaptation_generation;
  record.stable.stabilized_at = decision.committed_at;
  record.preference.previous_path = displaced;
  record.preference.preferred_path = target_path;
  record.preference.path_authority_generation = target->binding.path_authority.generation;
  record.preference.route_generation = target->binding.route.generation;
  if (target->binding.multipath.has_value()) {
    record.preference.multipath_set_generation = target->binding.multipath->generation;
  }
  record.preference.adaptation_generation = *adaptation;
  record.preference.transition_generation = *transition;
  record.preference.transition = ids_.next_transition_id();
  record.preference.decision = decision.id;
  record.preference.provenance = decision.provenance;
  record.preference.committed_at = decision.committed_at;
  record.timing.hold_down_active = record.policy.semantics.hold_down.duration != 0;
  record.timing.hold_down_deadline = decision.committed_at + record.policy.semantics.hold_down.duration;
  record.timing.hold_down_locked_path = record.preference.previous_path;
  record.timing.cooldown_active = record.policy.semantics.cooldown.duration != 0;
  record.timing.cooldown_deadline = decision.committed_at + record.policy.semantics.cooldown.duration;
  record.timing.churn_commits.push_back(decision.committed_at);

  AdaptationRecord record_entry;
  record_entry.decision = decision.id;
  record_entry.lifecycle = DecisionLifecycle::ROLLED_BACK;
  record_entry.outcome = Outcome::DECISION_COMMITTED;
  record_entry.cause = AdaptationCause::ROLLBACK_REQUESTED;
  record_entry.from_path = decision.current_preference;
  record_entry.to_path = decision.target_preference;
  record_entry.adaptation_generation = decision.adaptation_generation;
  record_entry.evidence_generation = decision.evidence_generation;
  record_entry.epoch = decision.epoch;
  record_entry.committed_at = decision.committed_at;
  record_entry.digest = decision.digest;
  record.history.push_back(record_entry);
  prune_history(record, limits_);
  state_.decision_journal.push_back(decision);
  while (state_.decision_journal.size() > limits_.max_decision_history) {
    state_.decision_journal.pop_front();
  }
  ++counters_.decisions_committed;
  record_attempt(state_, request.context.attempt, fingerprint, Outcome::DECISION_COMMITTED,
                 "rollback committed");
  OperationResult result = make_result(Outcome::DECISION_COMMITTED,
                                       "rolled back to the last known stable preference",
                                       request.policy, state_);
  result.decision = decision.id;
  result.mutated = true;
  return result;
}

OperationResult Impl::revalidate(const AdaptivePolicyId& policy, RevalidationAttemptId attempt,
                                 const MutationContext& context) {
  (void)attempt;
  PolicyLifecycleRequest request;
  request.policy = policy;
  request.event = PolicyEvent::REVALIDATE;
  request.detail = "operator requested revalidation";
  request.context = context;
  return transition_policy(request);
}

}  // namespace adaptive_routing::detail

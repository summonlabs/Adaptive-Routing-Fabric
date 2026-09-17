// Snapshots, diffs, explanations and decision queries.
#include <algorithm>

#include "engine_impl.hpp"

namespace adaptive_routing::detail {
namespace {

void add_entry(Explanation& explanation, std::string key, std::string value,
               std::uint64_t max_entries) {
  if (explanation.entries.size() >= static_cast<std::size_t>(max_entries)) {
    return;
  }
  ExplanationEntry entry;
  entry.key = std::move(key);
  entry.value = std::move(value);
  explanation.entries.push_back(std::move(entry));
}

[[nodiscard]] std::string ticks_ms(Ticks value) {
  return std::to_string(value / ticks_per_millisecond) + "ms";
}

}  // namespace

// ---------------------------------------------------------------------------
// Currentness
// ---------------------------------------------------------------------------

namespace {

struct CurrentnessAssessment {
  Currentness primary = Currentness::CURRENT;
  std::vector<Currentness> blockers;
};

void note_blocker(CurrentnessAssessment& assessment, Currentness value) {
  assessment.blockers.push_back(value);
  if (assessment.primary == Currentness::CURRENT) {
    assessment.primary = value;
  }
}

}  // namespace

AdaptationSnapshot Impl::snapshot(const AdaptivePolicyId& policy) const {
  // Snapshots are retained in a bounded history, so building one is a mutation:
  // it takes the exclusive lock rather than the shared one.
  std::unique_lock lock(mutex_);
  AdaptationSnapshot view;
  const auto position = state_.policies.find(policy);
  if (position == state_.policies.end()) {
    return view;
  }
  const PolicyRecord& record = position->second;
  const Ticks current = now();
  view.id = ids_.next_snapshot_id();
  view.epoch = state_.epoch;
  view.authority_generation = state_.authority_generation;
  view.policy = record.policy.id;
  view.policy_generation = record.policy.generation;
  view.policy_name = record.policy.name;
  view.scope = record.policy.scope;
  view.lifecycle = record.policy.lifecycle;
  view.semantics = record.policy.semantics;
  view.preference = record.preference;
  view.stable = record.stable;
  view.hold_down_active = record.timing.hold_down_active && record.timing.hold_down_deadline > current;
  view.hold_down_remaining =
      view.hold_down_active ? record.timing.hold_down_deadline - current : 0;
  view.cooldown_active = record.timing.cooldown_active && record.timing.cooldown_deadline > current;
  view.cooldown_remaining =
      view.cooldown_active ? record.timing.cooldown_deadline - current : 0;
  view.dampening_penalty = record.timing.dampening_penalty;
  view.adaptation_generation = record.preference.adaptation_generation;
  view.transition_generation = record.preference.transition_generation;
  view.evidence_generation = state_.evidence_generation;
  view.evidence_watermark = state_.evidence_watermark;
  view.upstream_watermark = state_.upstream_watermark;
  view.captured_at = current;
  view.history.assign(record.history.begin(), record.history.end());

  const EvaluationInputs inputs = copy_inputs(state_, record);
  view.evidence = inputs.evidence;
  const EvaluationTicket ticket =
      evaluate_inputs(inputs, build_dependencies(state_, record, EvaluationId()));
  for (const auto& candidate : record.candidates) {
    CandidateView entry;
    entry.binding = candidate.binding;
    entry.path_watermark = candidate.path_watermark;
    entry.priority = 0;
    for (const auto& ranked : ticket.ranking) {
      if (ranked.path == candidate.binding.path) {
        entry.eligible = ranked.eligible;
        entry.rejection = ranked.rejection;
        entry.quality = ranked.quality;
        entry.score = ranked.score;
        entry.metrics = ranked.metrics;
        entry.priority = ranked.priority;
        entry.current_preference = ranked.current_preference;
        entry.previous_preference = ranked.previous_preference;
        break;
      }
    }
    view.candidates.push_back(std::move(entry));
  }

  // --- currentness --------------------------------------------------------
  CurrentnessAssessment assessment;
  if (record.policy.lifecycle != PolicyLifecycle::ACTIVE) {
    note_blocker(assessment, Currentness::REVALIDATION_REQUIRED);
  }
  if (record.revocation.has_value()) {
    note_blocker(assessment, Currentness::REVALIDATION_REQUIRED);
  }
  if (record.policy.epoch.valid() && !(record.policy.epoch == state_.epoch)) {
    note_blocker(assessment, Currentness::STALE_EPOCH);
  }
  if (record.preference.established) {
    const auto candidate = record.find_candidate(record.preference.preferred_path);
    if (candidate == nullptr) {
      note_blocker(assessment, Currentness::REVALIDATION_REQUIRED);
    } else {
      if (!candidate->binding.path_authority.legal ||
          !(candidate->binding.path_authority.generation ==
            record.preference.path_authority_generation)) {
        note_blocker(assessment, Currentness::STALE_PATH_AUTHORITY);
      }
      if (!candidate->binding.route.current) {
        note_blocker(assessment, Currentness::STALE_ROUTE);
      }
      if (record.policy.semantics.target.multipath_set.has_value()) {
        if (!candidate->binding.multipath.has_value() ||
            !candidate->binding.multipath->current ||
            !(candidate->binding.multipath->generation ==
              record.preference.multipath_set_generation)) {
          note_blocker(assessment, Currentness::STALE_MULTIPATH_SET);
        }
      }
      if (!candidate->binding.available) {
        note_blocker(assessment, Currentness::REVALIDATION_REQUIRED);
      }
    }
  }
  // Evidence currentness is asserted about the facts the committed preference
  // rests on. A candidate that has never reported a metric is not stale -- the
  // runtime simply has no data for it, which is reported per candidate as an
  // ineligibility -- whereas the preferred path's evidence going stale is
  // exactly what must be visible here.
  if (record.preference.established) {
    for (const auto& requirement : record.policy.semantics.evidence) {
      if (!requirement.required) {
        continue;
      }
      const ResolvedEvidence* resolved =
          inputs.evidence == nullptr
              ? nullptr
              : inputs.evidence->find(record.preference.preferred_path, requirement.kind);
      if (resolved == nullptr || !resolved->aggregate.valid()) {
        note_blocker(assessment, Currentness::STALE_EVIDENCE);
        continue;
      }
      if (resolved->aggregate.sample_count < requirement.min_samples ||
          resolved->aggregate.age(inputs.now) > requirement.max_age ||
          resolved->aggregate.window() < requirement.min_window) {
        note_blocker(assessment, Currentness::STALE_EVIDENCE);
      }
    }
  }
  if (record.timing.hold_down_active && view.hold_down_remaining != 0) {
    note_blocker(assessment, Currentness::HOLD_DOWN_ACTIVE);
  }
  if (record.timing.cooldown_active && view.cooldown_remaining != 0) {
    note_blocker(assessment, Currentness::COOLDOWN_ACTIVE);
  }
  view.currentness = assessment.primary;
  view.blockers = assessment.blockers;
  view.digest = snapshot_digest(view);
  retain_snapshot(state_, std::make_shared<const AdaptationSnapshot>(view));
  return view;
}

std::vector<SnapshotId> Impl::retained_snapshots() const {
  std::shared_lock lock(mutex_);
  return std::vector<SnapshotId>(state_.snapshot_order.begin(), state_.snapshot_order.end());
}

std::optional<AdaptationSnapshot> Impl::find_snapshot(const SnapshotId& snapshot) const {
  std::shared_lock lock(mutex_);
  const auto position = state_.snapshots.find(snapshot);
  if (position == state_.snapshots.end()) {
    return std::nullopt;
  }
  return *position->second;
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

std::optional<AdaptationDecision> Impl::find_decision(const AdaptationDecisionId& decision) const {
  std::shared_lock lock(mutex_);
  for (const auto& entry : state_.decision_journal) {
    if (entry.id == decision) {
      return entry;
    }
  }
  for (const auto& entry : state_.policies) {
    for (const auto& record : entry.second.history) {
      if (record.decision == decision) {
        // The journal is bounded; a decision that aged out of it is still named
        // by the bounded per-policy history, so retain the digest-level record.
        AdaptationDecision summary;
        summary.id = record.decision;
        summary.policy = entry.first;
        summary.lifecycle = record.lifecycle;
        summary.outcome = record.outcome;
        summary.suppression = record.suppression;
        summary.cause = record.cause;
        summary.current_preference = record.from_path;
        summary.target_preference = record.to_path;
        summary.adaptation_generation = record.adaptation_generation;
        summary.evidence_generation = record.evidence_generation;
        summary.epoch = record.epoch;
        summary.committed_at = record.committed_at;
        summary.digest = record.digest;
        return summary;
      }
    }
  }
  return std::nullopt;
}

std::vector<AdaptationDecision> Impl::list_decisions(std::uint64_t limit) const {
  std::shared_lock lock(mutex_);
  std::vector<AdaptationDecision> decisions;
  const std::uint64_t bounded = (std::min)(limit, limits_.max_decision_history);
  decisions.reserve(static_cast<std::size_t>(bounded));
  for (auto iterator = state_.decision_journal.rbegin();
       iterator != state_.decision_journal.rend() &&
       decisions.size() < static_cast<std::size_t>(bounded);
       ++iterator) {
    decisions.push_back(*iterator);
  }
  return decisions;
}

std::vector<AdaptationDecision> Impl::decisions_for_policy(const AdaptivePolicyId& policy,
                                                          std::uint64_t limit) const {
  std::shared_lock lock(mutex_);
  std::vector<AdaptationDecision> decisions;
  const std::uint64_t bounded = (std::min)(limit, limits_.max_decision_history);
  for (auto iterator = state_.decision_journal.rbegin();
       iterator != state_.decision_journal.rend() &&
       decisions.size() < static_cast<std::size_t>(bounded);
       ++iterator) {
    if (iterator->policy == policy) {
      decisions.push_back(*iterator);
    }
  }
  return decisions;
}

// ---------------------------------------------------------------------------
// Explanations
// ---------------------------------------------------------------------------

Explanation Impl::build_explanation(const State& state, const PolicyRecord& record,
                                    const EvaluationInputs& inputs,
                                    ExplanationTopic topic) const {
  Explanation explanation;
  explanation.topic = topic;
  explanation.policy = record.policy.id;
  const auto max_entries = limits_.max_explanation_entries;
  const PolicySemantics& semantics = record.policy.semantics;

  switch (topic) {
    case ExplanationTopic::WHY_ADAPTED: {
      const AdaptationRecord* last = nullptr;
      for (const auto& entry : record.history) {
        if (entry.lifecycle == DecisionLifecycle::COMMITTED) {
          last = &entry;
        }
      }
      if (last == nullptr) {
        explanation.outcome = Outcome::NO_CHANGE;
        add_entry(explanation, "adapted", "never", max_entries);
        break;
      }
      explanation.decision = last->decision;
      explanation.outcome = last->outcome;
      add_entry(explanation, "adapted", last->from_path.str() + " -> " + last->to_path.str(),
                max_entries);
      add_entry(explanation, "cause", std::string(to_string(last->cause)), max_entries);
      add_entry(explanation, "adaptation_generation",
                std::to_string(last->adaptation_generation.value()), max_entries);
      add_entry(explanation, "evidence_generation",
                std::to_string(last->evidence_generation.value()), max_entries);
      add_entry(explanation, "decision_digest", last->digest, max_entries);
      for (const auto& decision : state.decision_journal) {
        if (decision.id == last->decision) {
          if (decision.improvement_bps.has_value()) {
            add_entry(explanation, "observed_improvement_bps",
                      std::to_string(*decision.improvement_bps), max_entries);
          }
          add_entry(explanation, "required_improvement_bps",
                    std::to_string(decision.required_improvement_bps), max_entries);
          if (decision.target_score.has_value()) {
            add_entry(explanation, "target_score", std::to_string(*decision.target_score),
                      max_entries);
          }
          break;
        }
      }
      break;
    }
    case ExplanationTopic::WHY_NOT_ADAPTED: {
      const AdaptationRecord* last = nullptr;
      for (const auto& entry : record.history) {
        last = &entry;
      }
      if (last != nullptr) {
        explanation.decision = last->decision;
        explanation.outcome = last->outcome;
        explanation.suppression = last->suppression;
        add_entry(explanation, "last_outcome", std::string(to_string(last->outcome)), max_entries);
        add_entry(explanation, "last_suppression", std::string(to_string(last->suppression)),
                  max_entries);
        add_entry(explanation, "last_decision", last->decision.str(), max_entries);
      } else {
        add_entry(explanation, "last_outcome", "never evaluated", max_entries);
      }
      add_entry(explanation, "lifecycle", std::string(to_string(record.policy.lifecycle)),
                max_entries);
      add_entry(explanation, "hold_down_active",
                record.timing.hold_down_active ? "true" : "false", max_entries);
      add_entry(explanation, "cooldown_active", record.timing.cooldown_active ? "true" : "false",
                max_entries);
      add_entry(explanation, "candidate_count", std::to_string(record.candidates.size()),
                max_entries);
      break;
    }
    case ExplanationTopic::EVIDENCE_THRESHOLD: {
      for (const auto& rule : semantics.thresholds) {
        add_entry(explanation, "threshold." + std::string(to_string(rule.kind)), rule.render(),
                  max_entries);
      }
      for (const auto& rule : semantics.improvements) {
        add_entry(explanation, "improvement." + std::string(to_string(rule.kind)), rule.render(),
                  max_entries);
      }
      for (const auto& candidate : record.candidates) {
        for (const auto& requirement : semantics.evidence) {
          const ResolvedEvidence* resolved =
              inputs.evidence == nullptr
                  ? nullptr
                  : inputs.evidence->find(candidate.binding.path, requirement.kind);
          const std::string key =
              "value." + candidate.binding.path.str() + "." + std::string(to_string(requirement.kind));
          if (resolved == nullptr || !resolved->aggregate.valid()) {
            add_entry(explanation, key, "absent", max_entries);
          } else {
            add_entry(explanation, key,
                      resolved->aggregate.render() +
                          " age_ms=" + ticks_ms(resolved->aggregate.age(inputs.now)),
                      max_entries);
          }
        }
      }
      break;
    }
    case ExplanationTopic::STALE_EVIDENCE: {
      for (const auto& candidate : record.candidates) {
        for (const auto& requirement : semantics.evidence) {
          const ResolvedEvidence* resolved =
              inputs.evidence == nullptr
                  ? nullptr
                  : inputs.evidence->find(candidate.binding.path, requirement.kind);
          const std::string key =
              "freshness." + candidate.binding.path.str() + "." +
              std::string(to_string(requirement.kind));
          if (resolved == nullptr || !resolved->aggregate.valid()) {
            add_entry(explanation, key, "no sample retained", max_entries);
            continue;
          }
          const Ticks age = resolved->aggregate.age(inputs.now);
          const std::string verdict =
              (age > requirement.max_age ||
               resolved->aggregate.sample_count < requirement.min_samples ||
               resolved->aggregate.window() < requirement.min_window)
                  ? "stale"
                  : "current";
          add_entry(explanation, key,
                    verdict + " age_ms=" + ticks_ms(age) + " max_age_ms=" +
                        ticks_ms(requirement.max_age) + " samples=" +
                        std::to_string(resolved->aggregate.sample_count) + " min_samples=" +
                        std::to_string(requirement.min_samples) + " window_ms=" +
                        ticks_ms(resolved->aggregate.window()) + " min_window_ms=" +
                        ticks_ms(requirement.min_window),
                    max_entries);
        }
      }
      break;
    }
    case ExplanationTopic::REJECTED_CANDIDATE:
    case ExplanationTopic::CANDIDATE_COMPARISON: {
      const EvaluationTicket ticket =
          evaluate_inputs(inputs, build_dependencies(state, record, EvaluationId()));
      std::uint32_t position = 0;
      for (const auto& ranked : ticket.ranking) {
        ++position;
        const std::string key = "rank" + std::to_string(position) + "." + ranked.path.str();
        std::string value = ranked.eligible ? "eligible" : "ineligible";
        if (!ranked.eligible) {
          value += ":" + std::string(to_string(ranked.rejection));
        }
        value += " quality=" + std::string(to_string(ranked.quality));
        value += " priority=" + std::to_string(ranked.priority);
        if (ranked.score.has_value()) {
          value += " score=" + std::to_string(*ranked.score);
        }
        for (std::size_t index = 0; index < ranked.metrics.size(); ++index) {
          value += " ";
          value += ranked.metrics[index].render();
        }
        if (ranked.observed_improvement_bps.has_value()) {
          value += " improvement_bps=" + std::to_string(*ranked.observed_improvement_bps);
        }
        if (ranked.current_preference) {
          value += " current";
        }
        if (ranked.previous_preference) {
          value += " previous";
        }
        add_entry(explanation, key, value, max_entries);
      }
      explanation.outcome = ticket.outcome;
      explanation.suppression = ticket.suppression;
      break;
    }
    case ExplanationTopic::HYSTERESIS: {
      for (const auto& rule : semantics.thresholds) {
        add_entry(explanation, "band." + std::string(to_string(rule.kind)), rule.render(),
                  max_entries);
      }
      for (const auto& rule : semantics.improvements) {
        add_entry(explanation, "improvement." + std::string(to_string(rule.kind)), rule.render(),
                  max_entries);
      }
      if (record.preference.previous_path.valid()) {
        add_entry(explanation, "reverse_target", record.preference.previous_path.str(),
                  max_entries);
      } else {
        add_entry(explanation, "reverse_target", "none", max_entries);
      }
      add_entry(explanation, "dampening_penalty", std::to_string(record.timing.dampening_penalty),
                max_entries);
      break;
    }
    case ExplanationTopic::HOLD_DOWN: {
      Ticks effective = semantics.hold_down.duration;
      if (semantics.dampening.enabled) {
        const std::uint64_t escalated =
            static_cast<std::uint64_t>(semantics.hold_down.duration) +
            static_cast<std::uint64_t>(record.timing.dampening_penalty) *
                semantics.dampening.hold_down_escalation_step;
        effective = static_cast<Ticks>(
            (std::min)(escalated, semantics.dampening.max_effective_hold_down));
      }
      const Ticks current = now();
      add_entry(explanation, "hold_down_declared_ms", ticks_ms(semantics.hold_down.duration),
                max_entries);
      add_entry(explanation, "hold_down_effective_ms", ticks_ms(effective), max_entries);
      add_entry(explanation, "hold_down_active", record.timing.hold_down_active ? "true" : "false",
                max_entries);
      add_entry(explanation, "hold_down_remaining_ms",
                record.timing.hold_down_active && record.timing.hold_down_deadline > current
                    ? ticks_ms(record.timing.hold_down_deadline - current)
                    : "0ms",
                max_entries);
      add_entry(explanation, "cooldown_declared_ms", ticks_ms(semantics.cooldown.duration),
                max_entries);
      add_entry(explanation, "cooldown_active", record.timing.cooldown_active ? "true" : "false",
                max_entries);
      add_entry(explanation, "cooldown_remaining_ms",
                record.timing.cooldown_active && record.timing.cooldown_deadline > current
                    ? ticks_ms(record.timing.cooldown_deadline - current)
                    : "0ms",
                max_entries);
      break;
    }
    case ExplanationTopic::STALE_GENERATION: {
      add_entry(explanation, "policy_generation",
                std::to_string(record.policy.generation.value()), max_entries);
      add_entry(explanation, "evidence_generation",
                std::to_string(state.evidence_generation.value()), max_entries);
      add_entry(explanation, "evidence_watermark",
                std::to_string(state.evidence_watermark.value()), max_entries);
      add_entry(explanation, "upstream_watermark",
                std::to_string(state.upstream_watermark.value()), max_entries);
      add_entry(explanation, "adaptation_generation",
                std::to_string(record.preference.adaptation_generation.value()), max_entries);
      add_entry(explanation, "transition_generation",
                std::to_string(record.preference.transition_generation.value()), max_entries);
      for (const auto& candidate : record.candidates) {
        add_entry(explanation, "candidate." + candidate.binding.path.str(),
                  "authority_generation=" +
                      std::to_string(candidate.binding.path_authority.generation.value()) +
                      " route_generation=" +
                      std::to_string(candidate.binding.route.generation.value()) +
                      " path_watermark=" + std::to_string(candidate.path_watermark),
                  max_entries);
      }
      break;
    }
    case ExplanationTopic::ROLLBACK_REFUSED: {
      add_entry(explanation, "stable_established",
                record.stable.established ? "true" : "false", max_entries);
      if (record.stable.established) {
        add_entry(explanation, "stable_path", record.stable.path.str(), max_entries);
        const auto candidate = record.find_candidate(record.stable.path);
        add_entry(explanation, "stable_path_is_candidate", candidate != nullptr ? "true" : "false",
                  max_entries);
        if (candidate != nullptr) {
          add_entry(explanation, "stable_path_legal",
                    candidate->binding.path_authority.legal ? "true" : "false", max_entries);
          add_entry(explanation, "stable_path_available",
                    candidate->binding.available ? "true" : "false", max_entries);
        }
      }
      add_entry(explanation, "current_preference",
                record.preference.established ? record.preference.preferred_path.str() : "none",
                max_entries);
      break;
    }
    case ExplanationTopic::AUTHORITY_OWNER: {
      for (const auto& entry : state.registrations) {
        add_entry(explanation, "publisher." + entry.first.str(), entry.second.render(),
                  max_entries);
      }
      for (const auto& fence : state.fences) {
        add_entry(explanation, "fence." + fence.worker_boot.str(), fence.render(), max_entries);
      }
      add_entry(explanation, "policy_owner", record.policy.owner.str(), max_entries);
      break;
    }
    case ExplanationTopic::GOVERNING_EPOCH: {
      add_entry(explanation, "epoch", std::to_string(state.epoch.value()), max_entries);
      add_entry(explanation, "authority_generation",
                std::to_string(state.authority_generation.value()), max_entries);
      add_entry(explanation, "policy_epoch", std::to_string(record.policy.epoch.value()),
                max_entries);
      add_entry(explanation, "epoch_matches_policy", state.epoch == record.policy.epoch ? "true" : "false",
                max_entries);
      break;
    }
  }
  // The truncation marker replaces the last retained entry so that the caller
  // can tell the answer was cut short. With a bound of zero nothing is retained,
  // so there is nothing to replace and no marker to place.
  if (max_entries != 0 && explanation.entries.size() >= static_cast<std::size_t>(max_entries)) {
    ExplanationEntry entry;
    entry.key = "truncated";
    entry.value = "explanation entry limit reached";
    explanation.entries.back() = std::move(entry);
  }
  return explanation;
}

Explanation Impl::explain(ExplanationTopic topic, const AdaptivePolicyId& policy) const {
  std::shared_lock lock(mutex_);
  const auto position = state_.policies.find(policy);
  if (position == state_.policies.end()) {
    Explanation explanation;
    explanation.topic = topic;
    explanation.policy = policy;
    explanation.outcome = Outcome::NOT_FOUND;
    add_entry(explanation, "error", "policy does not exist", limits_.max_explanation_entries);
    return explanation;
  }
  const EvaluationInputs inputs = copy_inputs(state_, position->second);
  return build_explanation(state_, position->second, inputs, topic);
}

Explanation Impl::explain_decision(const AdaptationDecisionId& decision) const {
  std::shared_lock lock(mutex_);
  Explanation explanation;
  explanation.topic = ExplanationTopic::WHY_ADAPTED;
  explanation.decision = decision;
  const auto max_entries = limits_.max_explanation_entries;
  for (const auto& entry : state_.decision_journal) {
    if (!(entry.id == decision)) {
      continue;
    }
    explanation.policy = entry.policy;
    explanation.outcome = entry.outcome;
    explanation.suppression = entry.suppression;
    add_entry(explanation, "lifecycle", std::string(to_string(entry.lifecycle)), max_entries);
    add_entry(explanation, "cause", std::string(to_string(entry.cause)), max_entries);
    add_entry(explanation, "epoch", std::to_string(entry.epoch.value()), max_entries);
    add_entry(explanation, "route", entry.route.str(), max_entries);
    add_entry(explanation, "current_preference",
              entry.had_current_preference ? entry.current_preference.str() : "none", max_entries);
    add_entry(explanation, "target_preference", entry.target_preference.str(), max_entries);
    add_entry(explanation, "policy_generation",
              std::to_string(entry.policy_generation.value()), max_entries);
    add_entry(explanation, "evidence_generation",
              std::to_string(entry.evidence_generation.value()), max_entries);
    add_entry(explanation, "evidence_snapshot", entry.evidence_snapshot.str(), max_entries);
    add_entry(explanation, "adaptation_generation",
              std::to_string(entry.adaptation_generation.value()), max_entries);
    add_entry(explanation, "transition_generation",
              std::to_string(entry.transition_generation.value()), max_entries);
    add_entry(explanation, "required_improvement_bps",
              std::to_string(entry.required_improvement_bps), max_entries);
    if (entry.improvement_bps.has_value()) {
      add_entry(explanation, "observed_improvement_bps", std::to_string(*entry.improvement_bps),
                max_entries);
    }
    if (entry.target_score.has_value()) {
      add_entry(explanation, "target_score", std::to_string(*entry.target_score), max_entries);
    }
    add_entry(explanation, "candidates_considered", std::to_string(entry.candidates_considered),
              max_entries);
    add_entry(explanation, "candidates_eligible", std::to_string(entry.candidates_eligible),
              max_entries);
    add_entry(explanation, "decision_digest", entry.digest, max_entries);
    add_entry(explanation, "authority", entry.provenance.render(), max_entries);
    return explanation;
  }
  explanation.outcome = Outcome::NOT_FOUND;
  add_entry(explanation, "error",
            "decision is not retained in the bounded journal and no policy history names it",
            max_entries);
  return explanation;
}

}  // namespace adaptive_routing::detail

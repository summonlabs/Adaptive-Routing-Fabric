// Digests, snapshots, diffs and explanations.
#include "adaptive_routing/view.hpp"

#include <algorithm>
#include <cstdio>

#include "adaptive_routing/version.hpp"

namespace adaptive_routing {
namespace {

constexpr std::uint64_t fnv_offset_a = 14695981039346656037ULL;
constexpr std::uint64_t fnv_offset_b = 0x9E3779B97F4A7C15ULL;
constexpr std::uint64_t fnv_prime = 1099511628211ULL;

void mix(std::uint64_t& lane, const unsigned char byte) noexcept {
  lane ^= static_cast<std::uint64_t>(byte);
  lane *= fnv_prime;
}

void write_tag(Digest& digest, std::string_view tag) { digest.write_tag(tag); }

template <class Id>
void write_id(Digest& digest, const Id& id) {
  digest.write_string(id.view());
}

template <class Gen>
void write_generation(Digest& digest, const Gen& generation) {
  digest.write_u64(generation.value());
}

void write_metric(Digest& digest, const MetricValue& value) {
  if (!value.valid()) {
    digest.write_u8(0);
    return;
  }
  digest.write_u8(1);
  digest.write_u8(static_cast<std::uint8_t>(value.kind()));
  digest.write_u8(static_cast<std::uint8_t>(value.unit()));
  digest.write_u32(value.semantics_version());
  digest.write_i64(value.value());
}

void write_semantics(Digest& digest, const PolicySemantics& semantics) {
  write_tag(digest, "semantics");
  digest.write_u32(semantics.semantics_version);
  write_id(digest, semantics.target.route);
  digest.write_bool(semantics.target.multipath_set.has_value());
  if (semantics.target.multipath_set.has_value()) {
    write_id(digest, *semantics.target.multipath_set);
  }

  // Trigger rules are sets keyed by metric; they are sorted so that two
  // policies with identical semantics but a different declaration order digest
  // identically.
  std::vector<ThresholdRule> thresholds(semantics.thresholds);
  std::sort(thresholds.begin(), thresholds.end(),
            [](const ThresholdRule& a, const ThresholdRule& b) {
              return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
            });
  digest.write_u64(thresholds.size());
  for (const auto& rule : thresholds) {
    digest.write_u8(static_cast<std::uint8_t>(rule.kind));
    write_metric(digest, rule.switch_value);
    write_metric(digest, rule.clear_value);
  }

  std::vector<ImprovementRule> improvements(semantics.improvements);
  std::sort(improvements.begin(), improvements.end(),
            [](const ImprovementRule& a, const ImprovementRule& b) {
              return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
            });
  digest.write_u64(improvements.size());
  for (const auto& rule : improvements) {
    digest.write_u8(static_cast<std::uint8_t>(rule.kind));
    digest.write_u32(rule.switch_improvement_bps);
    digest.write_u32(rule.reverse_improvement_bps);
  }

  std::vector<EvidenceRequirement> requirements(semantics.evidence);
  std::sort(requirements.begin(), requirements.end(),
            [](const EvidenceRequirement& a, const EvidenceRequirement& b) {
              return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
            });
  digest.write_u64(requirements.size());
  for (const auto& requirement : requirements) {
    digest.write_u8(static_cast<std::uint8_t>(requirement.kind));
    digest.write_u8(static_cast<std::uint8_t>(requirement.aggregation));
    digest.write_u32(requirement.ewma_alpha_bps);
    digest.write_u32(requirement.min_samples);
    digest.write_u64(requirement.max_age);
    digest.write_u64(requirement.min_window);
    digest.write_u8(static_cast<std::uint8_t>(requirement.min_quality));
    digest.write_bool(requirement.required);
  }

  digest.write_u64(semantics.hold_down.duration);
  digest.write_u64(semantics.cooldown.duration);
  digest.write_bool(semantics.dampening.enabled);
  digest.write_u32(semantics.dampening.penalty_increment);
  digest.write_u32(semantics.dampening.max_penalty);
  digest.write_u64(semantics.dampening.penalty_decay_interval);
  digest.write_u32(semantics.dampening.penalty_decay_step);
  digest.write_u64(semantics.dampening.hold_down_escalation_step);
  digest.write_u64(semantics.dampening.max_effective_hold_down);
  digest.write_u32(semantics.churn.max_adaptations_per_window);
  digest.write_u64(semantics.churn.window);

  digest.write_u8(static_cast<std::uint8_t>(semantics.objective.mode));
  digest.write_u32(semantics.objective.scoring_version);
  digest.write_u64(semantics.objective.terms.size());
  for (const auto& term : semantics.objective.terms) {
    digest.write_u8(static_cast<std::uint8_t>(term.kind));
    digest.write_u32(term.weight_bps);
  }

  digest.write_bool(semantics.emergency.enabled);
  digest.write_bool(semantics.emergency.on_current_path_unauthorized);
  digest.write_bool(semantics.emergency.on_current_path_unavailable);
  digest.write_bool(semantics.emergency.on_hard_failure_signal);

  std::vector<CandidatePriority> priorities(semantics.priorities);
  std::sort(priorities.begin(), priorities.end(),
            [](const CandidatePriority& a, const CandidatePriority& b) { return a.path < b.path; });
  digest.write_u64(priorities.size());
  for (const auto& entry : priorities) {
    write_id(digest, entry.path);
    digest.write_u32(entry.priority);
  }
}

void write_scope(Digest& digest, const PolicyScope& scope) {
  write_tag(digest, "scope");
  write_id(digest, scope.fabric);
  write_id(digest, scope.name_space);
  digest.write_bool(scope.site.has_value());
  if (scope.site.has_value()) {
    write_id(digest, *scope.site);
  }
  digest.write_bool(scope.path_class.valid());
  if (scope.path_class.valid()) {
    write_id(digest, scope.path_class);
  }
  std::vector<RouteId> routes(scope.routes);
  std::sort(routes.begin(), routes.end());
  digest.write_u64(routes.size());
  for (const auto& route : routes) {
    write_id(digest, route);
  }
  std::vector<MultipathSetId> sets(scope.multipath_sets);
  std::sort(sets.begin(), sets.end());
  digest.write_u64(sets.size());
  for (const auto& set : sets) {
    write_id(digest, set);
  }
}

void write_currentness(Digest& digest, Currentness currentness) {
  digest.write_u8(static_cast<std::uint8_t>(currentness));
}

[[nodiscard]] std::string hex_of(const Digest& digest) { return digest.hex(); }

}  // namespace

Digest::Digest() noexcept : low_(fnv_offset_a), high_(fnv_offset_b) {}

void Digest::write_u8(std::uint8_t value) noexcept {
  mix(low_, static_cast<unsigned char>(value));
  mix(high_, static_cast<unsigned char>(value));
}

void Digest::write_u16(std::uint16_t value) noexcept {
  write_u8(static_cast<std::uint8_t>(value & 0xFFU));
  write_u8(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
}

void Digest::write_u32(std::uint32_t value) noexcept {
  for (int index = 0; index < 4; ++index) {
    write_u8(static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFU));
  }
}

void Digest::write_u64(std::uint64_t value) noexcept {
  for (int index = 0; index < 8; ++index) {
    write_u8(static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFU));
  }
}

void Digest::write_i64(std::int64_t value) noexcept { write_u64(static_cast<std::uint64_t>(value)); }

void Digest::write_bool(bool value) noexcept { write_u8(value ? 1U : 0U); }

void Digest::write_bytes(std::string_view bytes) noexcept {
  for (const char character : bytes) {
    write_u8(static_cast<std::uint8_t>(static_cast<unsigned char>(character)));
  }
}

void Digest::write_string(std::string_view text) noexcept {
  write_u64(text.size());
  write_bytes(text);
}

void Digest::write_tag(std::string_view tag) noexcept {
  write_u8(0x1FU);
  write_string(tag);
}

std::string Digest::hex() const {
  char buffer[33];
  std::snprintf(buffer, sizeof(buffer), "%016llx%016llx",
                static_cast<unsigned long long>(low_), static_cast<unsigned long long>(high_));
  return std::string(buffer, 32);
}

// ---------------------------------------------------------------------------
// Semantic digests
// ---------------------------------------------------------------------------

std::string policy_semantic_digest(const AdaptivePolicy& policy) {
  Digest digest;
  write_tag(digest, "adaptive-policy");
  digest.write_u32(digest_encoding_version);
  write_id(digest, policy.id);
  write_id(digest, policy.name);
  write_scope(digest, policy.scope);
  write_semantics(digest, policy.semantics);
  digest.write_u8(static_cast<std::uint8_t>(policy.lifecycle));
  write_generation(digest, policy.generation);
  return hex_of(digest);
}

std::string decision_digest(const AdaptationDecision& decision) {
  Digest digest;
  write_tag(digest, "adaptation-decision");
  digest.write_u32(digest_encoding_version);
  write_id(digest, decision.policy);
  write_generation(digest, decision.policy_generation);
  digest.write_u8(static_cast<std::uint8_t>(decision.lifecycle));
  digest.write_u8(static_cast<std::uint8_t>(decision.cause));
  digest.write_u16(static_cast<std::uint16_t>(decision.outcome));
  digest.write_u8(static_cast<std::uint8_t>(decision.suppression));
  write_generation(digest, decision.epoch);
  write_generation(digest, decision.authority_generation);
  write_id(digest, decision.route);
  write_generation(digest, decision.route_generation);
  digest.write_bool(decision.multipath_set.has_value());
  if (decision.multipath_set.has_value()) {
    write_id(digest, *decision.multipath_set);
    write_generation(digest, decision.multipath_set_generation);
  }
  write_generation(digest, decision.evidence_generation);
  digest.write_u64(decision.evidence_watermark.value());
  digest.write_u64(decision.upstream_watermark.value());
  digest.write_bool(decision.had_current_preference);
  write_id(digest, decision.current_preference);
  write_generation(digest, decision.current_preference_authority_generation);
  write_id(digest, decision.target_preference);
  write_generation(digest, decision.target_preference_authority_generation);
  write_generation(digest, decision.adaptation_generation);
  write_generation(digest, decision.transition_generation);
  digest.write_bool(decision.target_score.has_value());
  if (decision.target_score.has_value()) {
    digest.write_u64(*decision.target_score);
  }
  digest.write_bool(decision.improvement_bps.has_value());
  if (decision.improvement_bps.has_value()) {
    digest.write_u32(*decision.improvement_bps);
  }
  digest.write_u32(decision.required_improvement_bps);
  // The ranking is already canonical (total order with a PathId tie-break), so
  // it is digested in that order without re-sorting.
  digest.write_u64(decision.ranking.size());
  for (const auto& entry : decision.ranking) {
    write_id(digest, entry.path);
    digest.write_bool(entry.eligible);
    digest.write_u8(static_cast<std::uint8_t>(entry.rejection));
    digest.write_u8(static_cast<std::uint8_t>(entry.quality));
    digest.write_bool(entry.score.has_value());
    if (entry.score.has_value()) {
      digest.write_u64(*entry.score);
    }
    digest.write_u64(entry.metrics.size());
    for (const auto& metric : entry.metrics) {
      write_metric(digest, metric);
    }
    digest.write_u32(entry.priority);
    digest.write_bool(entry.current_preference);
    digest.write_bool(entry.previous_preference);
    digest.write_u32(entry.required_improvement_bps);
    digest.write_bool(entry.observed_improvement_bps.has_value());
    if (entry.observed_improvement_bps.has_value()) {
      digest.write_u32(*entry.observed_improvement_bps);
    }
  }
  return hex_of(digest);
}

std::string snapshot_digest(const AdaptationSnapshot& snapshot) {
  Digest digest;
  write_tag(digest, "adaptation-snapshot");
  digest.write_u32(digest_encoding_version);
  write_generation(digest, snapshot.epoch);
  write_generation(digest, snapshot.authority_generation);
  write_id(digest, snapshot.policy);
  write_generation(digest, snapshot.policy_generation);
  write_id(digest, snapshot.policy_name);
  write_scope(digest, snapshot.scope);
  digest.write_u8(static_cast<std::uint8_t>(snapshot.lifecycle));
  write_semantics(digest, snapshot.semantics);

  digest.write_bool(snapshot.preference.established);
  if (snapshot.preference.established) {
    write_id(digest, snapshot.preference.preferred_path);
    write_generation(digest, snapshot.preference.path_authority_generation);
    write_generation(digest, snapshot.preference.route_generation);
    digest.write_bool(snapshot.preference.multipath_set.has_value());
    if (snapshot.preference.multipath_set.has_value()) {
      write_id(digest, *snapshot.preference.multipath_set);
      write_generation(digest, snapshot.preference.multipath_set_generation);
    }
    digest.write_bool(snapshot.preference.weight_proposal.has_value());
    if (snapshot.preference.weight_proposal.has_value()) {
      write_id(digest, snapshot.preference.weight_proposal->set);
      write_generation(digest, snapshot.preference.weight_proposal->base_generation);
      digest.write_u64(snapshot.preference.weight_proposal->weights.size());
      for (const auto& weight : snapshot.preference.weight_proposal->weights) {
        write_id(digest, weight.path);
        digest.write_u32(weight.weight_bps);
      }
    }
  }

  digest.write_bool(snapshot.stable.established);
  if (snapshot.stable.established) {
    write_id(digest, snapshot.stable.path);
    write_generation(digest, snapshot.stable.path_authority_generation);
    write_generation(digest, snapshot.stable.route_generation);
    write_generation(digest, snapshot.stable.adaptation_generation);
  }

  digest.write_u64(snapshot.candidates.size());
  for (const auto& candidate : snapshot.candidates) {
    write_id(digest, candidate.binding.path);
    write_generation(digest, candidate.binding.path_authority.generation);
    digest.write_bool(candidate.binding.path_authority.legal);
    digest.write_bool(candidate.binding.available);
    digest.write_bool(candidate.binding.hard_failure);
    digest.write_bool(candidate.binding.multipath.has_value());
    if (candidate.binding.multipath.has_value()) {
      write_id(digest, candidate.binding.multipath->set);
      write_generation(digest, candidate.binding.multipath->generation);
    }
    write_generation(digest, candidate.binding.route.generation);
    digest.write_bool(candidate.eligible);
    digest.write_u8(static_cast<std::uint8_t>(candidate.rejection));
    digest.write_u8(static_cast<std::uint8_t>(candidate.quality));
    digest.write_bool(candidate.score.has_value());
    if (candidate.score.has_value()) {
      digest.write_u64(*candidate.score);
    }
    digest.write_u32(candidate.priority);
    digest.write_bool(candidate.current_preference);
    digest.write_bool(candidate.previous_preference);
    digest.write_u64(candidate.path_watermark);
  }

  write_currentness(digest, snapshot.currentness);
  digest.write_u64(snapshot.blockers.size());
  for (const auto blocker : snapshot.blockers) {
    write_currentness(digest, blocker);
  }
  digest.write_bool(snapshot.hold_down_active);
  digest.write_u64(snapshot.hold_down_remaining);
  digest.write_bool(snapshot.cooldown_active);
  digest.write_u64(snapshot.cooldown_remaining);
  digest.write_u32(snapshot.dampening_penalty);
  write_generation(digest, snapshot.adaptation_generation);
  write_generation(digest, snapshot.transition_generation);
  // The engine-global evidence generation and the invalidation watermarks are
  // deliberately excluded. They move whenever *any* policy's evidence changes,
  // so including them would make a policy's semantic digest change without that
  // policy changing at all. What the policy actually depends on -- each
  // candidate's path authority generation, route generation, multipath
  // generation and per-path invalidation watermark, plus its own evidence
  // bindings -- is already digested above.

  digest.write_u64(snapshot.history.size());
  for (const auto& record : snapshot.history) {
    digest.write_string(record.digest);
    digest.write_u8(static_cast<std::uint8_t>(record.lifecycle));
    digest.write_u16(static_cast<std::uint16_t>(record.outcome));
    digest.write_u8(static_cast<std::uint8_t>(record.suppression));
    write_id(digest, record.from_path);
    write_id(digest, record.to_path);
    write_generation(digest, record.adaptation_generation);
    write_generation(digest, record.evidence_generation);
  }
  return hex_of(digest);
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

const CandidateView* AdaptationSnapshot::find_candidate(const PathId& path) const noexcept {
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

std::string AdaptationSnapshot::render() const {
  std::string text = "snapshot=" + id.str();
  text += " policy=" + policy.str() + "@" + std::to_string(policy_generation.value());
  text += " name=" + policy_name.str();
  text += " lifecycle=" + std::string(to_string(lifecycle));
  text += " epoch=" + std::to_string(epoch.value());
  text += " authority=" + std::to_string(authority_generation.value());
  text += "\n  scope[" + scope.render() + "]";
  text += "\n  semantics[" + semantics.render() + "]";
  text += "\n  preference[" + preference.render() + "]";
  text += "\n  stable[" + stable.render() + "]";
  text += "\n  currentness=" + std::string(to_string(currentness));
  for (const auto blocker : blockers) {
    text += " blocker=" + std::string(to_string(blocker));
  }
  text += "\n  hold_down=" + std::string(hold_down_active ? "active" : "clear") +
          " remaining_ms=" + std::to_string(hold_down_remaining / ticks_per_millisecond);
  text += " cooldown=" + std::string(cooldown_active ? "active" : "clear") +
          " remaining_ms=" + std::to_string(cooldown_remaining / ticks_per_millisecond);
  text += " dampening_penalty=" + std::to_string(dampening_penalty);
  text += "\n  adaptation=" + std::to_string(adaptation_generation.value());
  text += " transition=" + std::to_string(transition_generation.value());
  text += " evidence=" + std::to_string(evidence_generation.value());
  text += " evidence_watermark=" + std::to_string(evidence_watermark.value());
  text += " upstream_watermark=" + std::to_string(upstream_watermark.value());
  for (const auto& candidate : candidates) {
    text += "\n  candidate[" + candidate.binding.render();
    text += candidate.eligible ? " ELIGIBLE" : " INELIGIBLE";
    if (candidate.rejection != SuppressionReason::NONE) {
      text += ":" + std::string(to_string(candidate.rejection));
    }
    if (candidate.score.has_value()) {
      text += " score=" + std::to_string(*candidate.score);
    }
    if (candidate.current_preference) {
      text += " current";
    }
    if (candidate.previous_preference) {
      text += " previous";
    }
    text += "]";
  }
  for (const auto& record : history) {
    text += "\n  history[" + std::string(to_string(record.lifecycle)) + " " +
            std::string(to_string(record.outcome)) + " " + record.from_path.str() + "->" +
            record.to_path.str() + " digest=" + record.digest + "]";
  }
  text += "\n  digest=" + digest;
  return text;
}

// ---------------------------------------------------------------------------
// Diffs
// ---------------------------------------------------------------------------

std::string_view to_string(DiffKind kind) noexcept {
  switch (kind) {
    case DiffKind::POLICY_CHANGED:
      return "POLICY_CHANGED";
    case DiffKind::POLICY_LIFECYCLE_CHANGED:
      return "POLICY_LIFECYCLE_CHANGED";
    case DiffKind::CANDIDATE_ELIGIBILITY_CHANGED:
      return "CANDIDATE_ELIGIBILITY_CHANGED";
    case DiffKind::EVIDENCE_GENERATION_CHANGED:
      return "EVIDENCE_GENERATION_CHANGED";
    case DiffKind::PREFERRED_PATH_CHANGED:
      return "PREFERRED_PATH_CHANGED";
    case DiffKind::ADAPTATION_SUPPRESSED:
      return "ADAPTATION_SUPPRESSED";
    case DiffKind::HOLD_DOWN_ENTERED:
      return "HOLD_DOWN_ENTERED";
    case DiffKind::HOLD_DOWN_EXITED:
      return "HOLD_DOWN_EXITED";
    case DiffKind::COOLDOWN_ENTERED:
      return "COOLDOWN_ENTERED";
    case DiffKind::COOLDOWN_EXITED:
      return "COOLDOWN_EXITED";
    case DiffKind::AUTHORITY_CHANGED:
      return "AUTHORITY_CHANGED";
    case DiffKind::CURRENTNESS_CHANGED:
      return "CURRENTNESS_CHANGED";
    case DiffKind::STABLE_STATE_CHANGED:
      return "STABLE_STATE_CHANGED";
    case DiffKind::DAMPENING_CHANGED:
      return "DAMPENING_CHANGED";
    case DiffKind::TRANSITION_CHANGED:
      return "TRANSITION_CHANGED";
  }
  return "UNKNOWN";
}

bool valid_diff_kind(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 15; }

namespace {

void add_entry(std::vector<DiffEntry>& entries, DiffKind kind, std::string field,
               std::string before, std::string after) {
  DiffEntry entry;
  entry.kind = kind;
  entry.field = std::move(field);
  entry.before = std::move(before);
  entry.after = std::move(after);
  entries.push_back(std::move(entry));
}

[[nodiscard]] std::string render_candidate_set(const AdaptationSnapshot& snapshot) {
  std::string text;
  for (const auto& candidate : snapshot.candidates) {
    text += candidate.binding.path.str();
    text += candidate.eligible ? ":eligible," : ":ineligible,";
  }
  return text;
}

}  // namespace

AdaptationDiff compute_diff(const AdaptationSnapshot& before, const AdaptationSnapshot& after) {
  AdaptationDiff diff;
  diff.from = before.id;
  diff.to = after.id;
  diff.policy = after.policy.valid() ? after.policy : before.policy;

  if (before.digest != after.digest) {
    add_entry(diff.entries, DiffKind::POLICY_CHANGED, "semantic_digest", before.digest,
              after.digest);
  }
  if (before.lifecycle != after.lifecycle) {
    add_entry(diff.entries, DiffKind::POLICY_LIFECYCLE_CHANGED, "lifecycle",
              std::string(to_string(before.lifecycle)), std::string(to_string(after.lifecycle)));
  }
  if (before.policy_generation != after.policy_generation) {
    add_entry(diff.entries, DiffKind::POLICY_CHANGED, "policy_generation",
              std::to_string(before.policy_generation.value()),
              std::to_string(after.policy_generation.value()));
  }
  if (before.authority_generation != after.authority_generation || before.epoch != after.epoch) {
    add_entry(diff.entries, DiffKind::AUTHORITY_CHANGED, "authority",
              std::to_string(before.authority_generation.value()) + "@" +
                  std::to_string(before.epoch.value()),
              std::to_string(after.authority_generation.value()) + "@" +
                  std::to_string(after.epoch.value()));
  }
  if (render_candidate_set(before) != render_candidate_set(after)) {
    add_entry(diff.entries, DiffKind::CANDIDATE_ELIGIBILITY_CHANGED, "candidates",
              render_candidate_set(before), render_candidate_set(after));
  }
  if (before.evidence_generation != after.evidence_generation) {
    add_entry(diff.entries, DiffKind::EVIDENCE_GENERATION_CHANGED, "evidence_generation",
              std::to_string(before.evidence_generation.value()),
              std::to_string(after.evidence_generation.value()));
  }
  const std::string before_path =
      before.preference.established ? before.preference.preferred_path.str() : std::string("<none>");
  const std::string after_path =
      after.preference.established ? after.preference.preferred_path.str() : std::string("<none>");
  if (before_path != after_path) {
    add_entry(diff.entries, DiffKind::PREFERRED_PATH_CHANGED, "preferred_path", before_path,
              after_path);
  }
  if (before.adaptation_generation != after.adaptation_generation) {
    add_entry(diff.entries, DiffKind::TRANSITION_CHANGED, "adaptation_generation",
              std::to_string(before.adaptation_generation.value()),
              std::to_string(after.adaptation_generation.value()));
  }
  if (before.transition_generation != after.transition_generation) {
    add_entry(diff.entries, DiffKind::TRANSITION_CHANGED, "transition_generation",
              std::to_string(before.transition_generation.value()),
              std::to_string(after.transition_generation.value()));
  }
  if (before.hold_down_active != after.hold_down_active) {
    add_entry(diff.entries,
              after.hold_down_active ? DiffKind::HOLD_DOWN_ENTERED : DiffKind::HOLD_DOWN_EXITED,
              "hold_down", before.hold_down_active ? "active" : "clear",
              after.hold_down_active ? "active" : "clear");
  }
  if (before.cooldown_active != after.cooldown_active) {
    add_entry(diff.entries,
              after.cooldown_active ? DiffKind::COOLDOWN_ENTERED : DiffKind::COOLDOWN_EXITED,
              "cooldown", before.cooldown_active ? "active" : "clear",
              after.cooldown_active ? "active" : "clear");
  }
  if (before.currentness != after.currentness) {
    add_entry(diff.entries, DiffKind::CURRENTNESS_CHANGED, "currentness",
              std::string(to_string(before.currentness)), std::string(to_string(after.currentness)));
  }
  if (before.stable.established != after.stable.established ||
      before.stable.path != after.stable.path) {
    add_entry(diff.entries, DiffKind::STABLE_STATE_CHANGED, "stable", before.stable.render(),
              after.stable.render());
  }
  if (before.dampening_penalty != after.dampening_penalty) {
    add_entry(diff.entries, DiffKind::DAMPENING_CHANGED, "dampening_penalty",
              std::to_string(before.dampening_penalty), std::to_string(after.dampening_penalty));
  }
  const auto last_outcome = [](const AdaptationSnapshot& snapshot) {
    return snapshot.history.empty() ? std::string("<none>")
                                    : std::string(to_string(snapshot.history.back().outcome));
  };
  if (last_outcome(before) != last_outcome(after)) {
    add_entry(diff.entries, DiffKind::ADAPTATION_SUPPRESSED, "last_outcome", last_outcome(before),
              last_outcome(after));
  }

  std::sort(diff.entries.begin(), diff.entries.end(),
            [](const DiffEntry& a, const DiffEntry& b) {
              if (a.kind != b.kind) {
                return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
              }
              return a.field < b.field;
            });
  return diff;
}

std::string AdaptationDiff::render() const {
  std::string text = "diff " + from.str() + " -> " + to.str();
  text += " policy=" + policy.str();
  if (entries.empty()) {
    text += "\n  <no semantic change>";
    return text;
  }
  for (const auto& entry : entries) {
    text += "\n  " + std::string(to_string(entry.kind)) + " " + entry.field + ": " +
            entry.before + " -> " + entry.after;
  }
  return text;
}

// ---------------------------------------------------------------------------
// Explanations
// ---------------------------------------------------------------------------

std::string_view to_string(ExplanationTopic topic) noexcept {
  switch (topic) {
    case ExplanationTopic::WHY_ADAPTED:
      return "WHY_ADAPTED";
    case ExplanationTopic::WHY_NOT_ADAPTED:
      return "WHY_NOT_ADAPTED";
    case ExplanationTopic::EVIDENCE_THRESHOLD:
      return "EVIDENCE_THRESHOLD";
    case ExplanationTopic::STALE_EVIDENCE:
      return "STALE_EVIDENCE";
    case ExplanationTopic::REJECTED_CANDIDATE:
      return "REJECTED_CANDIDATE";
    case ExplanationTopic::CANDIDATE_COMPARISON:
      return "CANDIDATE_COMPARISON";
    case ExplanationTopic::HYSTERESIS:
      return "HYSTERESIS";
    case ExplanationTopic::HOLD_DOWN:
      return "HOLD_DOWN";
    case ExplanationTopic::STALE_GENERATION:
      return "STALE_GENERATION";
    case ExplanationTopic::ROLLBACK_REFUSED:
      return "ROLLBACK_REFUSED";
    case ExplanationTopic::AUTHORITY_OWNER:
      return "AUTHORITY_OWNER";
    case ExplanationTopic::GOVERNING_EPOCH:
      return "GOVERNING_EPOCH";
  }
  return "UNKNOWN";
}

std::optional<ExplanationTopic> parse_explanation_topic(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 12; ++raw) {
    const auto topic = static_cast<ExplanationTopic>(raw);
    if (to_string(topic) == text) {
      return topic;
    }
  }
  return std::nullopt;
}

bool valid_explanation_topic(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 12; }

const std::string* Explanation::find(std::string_view key) const noexcept {
  for (const auto& entry : entries) {
    if (entry.key == key) {
      return &entry.value;
    }
  }
  return nullptr;
}

std::string Explanation::render() const {
  std::string text = std::string(to_string(topic));
  if (policy.valid()) {
    text += " policy=" + policy.str();
  }
  if (decision.valid()) {
    text += " decision=" + decision.str();
  }
  text += " outcome=" + std::string(to_string(outcome));
  if (suppression != SuppressionReason::NONE) {
    text += " suppression=" + std::string(to_string(suppression));
  }
  for (const auto& entry : entries) {
    text += "\n  " + entry.key + ": " + entry.value;
  }
  return text;
}

}  // namespace adaptive_routing

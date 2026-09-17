// Versioned, integrity-checked durable state and conservative recovery.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>

#include "adaptive_routing/codec.hpp"
#include "adaptive_routing/persistence.hpp"
#include "adaptive_routing/version.hpp"
#include "engine_impl.hpp"

namespace adaptive_routing {
namespace {

constexpr std::uint32_t store_magic = 0x50465241U;  // "ARFP" little-endian
constexpr std::uint64_t store_trailer_bytes = 8;
constexpr std::uint64_t fnv_prime = 1099511628211ULL;
constexpr std::uint64_t fnv_offset_a = 14695981039346656037ULL;
constexpr std::uint64_t fnv_offset_b = 0x9E3779B97F4A7C15ULL;

[[nodiscard]] std::uint64_t store_integrity(std::string_view bytes) noexcept {
  std::uint64_t low = fnv_offset_a;
  std::uint64_t high = fnv_offset_b;
  for (const char character : bytes) {
    const auto value = static_cast<std::uint8_t>(static_cast<unsigned char>(character));
    low ^= value;
    low *= fnv_prime;
    high += value;
    high ^= (high << 13);
    high *= fnv_prime;
  }
  return low ^ high;
}

void put_id(ByteWriter& writer, const auto& id) {
  writer.put_string(id.view());
}

template <class Strong>
[[nodiscard]] bool get_id(ByteReader& reader, Strong& out) {
  const auto text = reader.get_string(4096);
  if (!text.has_value()) {
    return false;
  }
  const auto parsed = Strong::parse(*text);
  if (!parsed.has_value()) {
    return false;
  }
  out = *parsed;
  return true;
}

template <class Gen>
[[nodiscard]] bool get_generation(ByteReader& reader, Gen& out) {
  const auto raw = reader.get_u64();
  if (!raw.has_value()) {
    return false;
  }
  const auto parsed = Gen::from_value(*raw);
  if (!parsed.has_value()) {
    return false;
  }
  out = *parsed;
  return true;
}

// Identities that are written unconditionally but may legitimately be absent
// (a preference that has never committed has no transition and no preferred
// path) travel as a length-prefixed string where the empty encoding means
// "absent". This mirrors put_id exactly.
template <class Strong>
[[nodiscard]] bool get_maybe_id(ByteReader& reader, Strong& out) {
  const auto text = reader.get_string(4096);
  if (!text.has_value()) {
    return false;
  }
  if (text->empty()) {
    out = Strong();
    return true;
  }
  const auto parsed = Strong::parse(*text);
  if (!parsed.has_value()) {
    return false;
  }
  out = *parsed;
  return true;
}

void put_optional_id(ByteWriter& writer, const auto& id) {
  writer.put_bool(id.valid());
  if (id.valid()) {
    put_id(writer, id);
  }
}

template <class Strong>
[[nodiscard]] bool get_optional_id(ByteReader& reader, Strong& out) {
  const auto present = reader.get_bool();
  if (!present.has_value()) {
    return false;
  }
  if (!*present) {
    out = Strong();
    return true;
  }
  return get_id(reader, out);
}

// Overloads for the std::optional form used by members such as the optional
// site and path class of a policy scope.
template <class Strong>
void put_optional_id(ByteWriter& writer, const std::optional<Strong>& id) {
  writer.put_bool(id.has_value());
  if (id.has_value()) {
    put_id(writer, *id);
  }
}

template <class Strong>
[[nodiscard]] bool get_optional_id(ByteReader& reader, std::optional<Strong>& out) {
  const auto present = reader.get_bool();
  if (!present.has_value()) {
    return false;
  }
  if (!*present) {
    out.reset();
    return true;
  }
  Strong value;
  if (!get_id(reader, value)) {
    return false;
  }
  out = value;
  return true;
}

void put_metric(ByteWriter& writer, const MetricValue& value) {
  writer.put_bool(value.valid());
  if (!value.valid()) {
    return;
  }
  writer.put_u8(static_cast<std::uint8_t>(value.kind()));
  writer.put_u8(static_cast<std::uint8_t>(value.unit()));
  writer.put_u32(value.semantics_version());
  writer.put_i64(value.value());
}

[[nodiscard]] bool get_metric(ByteReader& reader, MetricValue& out) {
  const auto present = reader.get_bool();
  if (!present.has_value()) {
    return false;
  }
  if (!*present) {
    out = MetricValue();
    return true;
  }
  const auto kind = reader.get_u8();
  const auto unit = reader.get_u8();
  const auto version = reader.get_u32();
  const auto value = reader.get_i64();
  if (!kind.has_value() || !unit.has_value() || !version.has_value() || !value.has_value()) {
    return false;
  }
  if (!valid_metric_kind(*kind) || !valid_metric_unit(*unit)) {
    return false;
  }
  const auto decoded =
      MetricValue::decode(static_cast<MetricKind>(*kind), static_cast<MetricUnit>(*unit), *version,
                          *value);
  if (!decoded.has_value()) {
    return false;
  }
  out = *decoded;
  return true;
}

void put_scope(ByteWriter& writer, const PolicyScope& scope) {
  put_id(writer, scope.fabric);
  put_id(writer, scope.name_space);
  put_optional_id(writer, scope.site);
  put_optional_id(writer, scope.path_class);
  writer.put_u64(scope.routes.size());
  for (const auto& route : scope.routes) {
    put_id(writer, route);
  }
  writer.put_u64(scope.multipath_sets.size());
  for (const auto& set : scope.multipath_sets) {
    put_id(writer, set);
  }
}

[[nodiscard]] bool get_scope(ByteReader& reader, PolicyScope& scope) {
  if (!get_id(reader, scope.fabric) || !get_id(reader, scope.name_space) ||
      !get_optional_id(reader, scope.site) || !get_optional_id(reader, scope.path_class)) {
    return false;
  }
  const auto route_count = reader.get_u64();
  if (!route_count.has_value() || *route_count > Limits{}.max_scope_routes) {
    return false;
  }
  for (std::uint64_t index = 0; index < *route_count; ++index) {
    RouteId route;
    if (!get_id(reader, route)) {
      return false;
    }
    scope.routes.push_back(route);
  }
  const auto set_count = reader.get_u64();
  if (!set_count.has_value() || *set_count > Limits{}.max_scope_multipath_sets) {
    return false;
  }
  for (std::uint64_t index = 0; index < *set_count; ++index) {
    MultipathSetId set;
    if (!get_id(reader, set)) {
      return false;
    }
    scope.multipath_sets.push_back(set);
  }
  return scope.well_formed();
}

void put_requirement(ByteWriter& writer, const EvidenceRequirement& requirement) {
  writer.put_u8(static_cast<std::uint8_t>(requirement.kind));
  writer.put_u8(static_cast<std::uint8_t>(requirement.aggregation));
  writer.put_u32(requirement.ewma_alpha_bps);
  writer.put_u32(requirement.min_samples);
  writer.put_u64(requirement.max_age);
  writer.put_u64(requirement.min_window);
  writer.put_u8(static_cast<std::uint8_t>(requirement.min_quality));
  writer.put_bool(requirement.required);
}

[[nodiscard]] bool get_requirement(ByteReader& reader, EvidenceRequirement& requirement) {
  const auto kind = reader.get_u8();
  const auto aggregation = reader.get_u8();
  const auto alpha = reader.get_u32();
  const auto min_samples = reader.get_u32();
  const auto max_age = reader.get_u64();
  const auto min_window = reader.get_u64();
  const auto quality = reader.get_u8();
  const auto required = reader.get_bool();
  if (!kind.has_value() || !aggregation.has_value() || !alpha.has_value() ||
      !min_samples.has_value() || !max_age.has_value() || !min_window.has_value() ||
      !quality.has_value() || !required.has_value()) {
    return false;
  }
  if (!valid_metric_kind(*kind) || !valid_aggregation_kind(*aggregation) ||
      !valid_evidence_quality(*quality)) {
    return false;
  }
  requirement.kind = static_cast<MetricKind>(*kind);
  requirement.aggregation = static_cast<AggregationKind>(*aggregation);
  requirement.ewma_alpha_bps = *alpha;
  requirement.min_samples = *min_samples;
  requirement.max_age = *max_age;
  requirement.min_window = *min_window;
  requirement.min_quality = static_cast<EvidenceQuality>(*quality);
  requirement.required = *required;
  return requirement.valid();
}

void put_semantics(ByteWriter& writer, const PolicySemantics& semantics) {
  writer.put_u32(semantics.semantics_version);
  put_id(writer, semantics.target.route);
  put_optional_id(writer, semantics.target.multipath_set);
  writer.put_u64(semantics.thresholds.size());
  for (const auto& rule : semantics.thresholds) {
    writer.put_u8(static_cast<std::uint8_t>(rule.kind));
    put_metric(writer, rule.switch_value);
    put_metric(writer, rule.clear_value);
  }
  writer.put_u64(semantics.improvements.size());
  for (const auto& rule : semantics.improvements) {
    writer.put_u8(static_cast<std::uint8_t>(rule.kind));
    writer.put_u32(rule.switch_improvement_bps);
    writer.put_u32(rule.reverse_improvement_bps);
  }
  writer.put_u64(semantics.evidence.size());
  for (const auto& requirement : semantics.evidence) {
    put_requirement(writer, requirement);
  }
  writer.put_u64(semantics.hold_down.duration);
  writer.put_u64(semantics.cooldown.duration);
  writer.put_bool(semantics.dampening.enabled);
  writer.put_u32(semantics.dampening.penalty_increment);
  writer.put_u32(semantics.dampening.max_penalty);
  writer.put_u64(semantics.dampening.penalty_decay_interval);
  writer.put_u32(semantics.dampening.penalty_decay_step);
  writer.put_u64(semantics.dampening.hold_down_escalation_step);
  writer.put_u64(semantics.dampening.max_effective_hold_down);
  writer.put_u32(semantics.churn.max_adaptations_per_window);
  writer.put_u64(semantics.churn.window);
  writer.put_u8(static_cast<std::uint8_t>(semantics.objective.mode));
  writer.put_u32(semantics.objective.scoring_version);
  writer.put_u64(semantics.objective.terms.size());
  for (const auto& term : semantics.objective.terms) {
    writer.put_u8(static_cast<std::uint8_t>(term.kind));
    writer.put_u32(term.weight_bps);
  }
  writer.put_bool(semantics.emergency.enabled);
  writer.put_bool(semantics.emergency.on_current_path_unauthorized);
  writer.put_bool(semantics.emergency.on_current_path_unavailable);
  writer.put_bool(semantics.emergency.on_hard_failure_signal);
  writer.put_u64(semantics.priorities.size());
  for (const auto& entry : semantics.priorities) {
    put_id(writer, entry.path);
    writer.put_u32(entry.priority);
  }
}

[[nodiscard]] bool get_semantics(ByteReader& reader, PolicySemantics& semantics) {
  const auto version = reader.get_u32();
  if (!version.has_value()) {
    return false;
  }
  semantics.semantics_version = *version;
  if (!get_id(reader, semantics.target.route) ||
      !get_optional_id(reader, semantics.target.multipath_set)) {
    return false;
  }
  const auto threshold_count = reader.get_u64();
  if (!threshold_count.has_value() || *threshold_count > Limits{}.max_thresholds_per_policy) {
    return false;
  }
  for (std::uint64_t index = 0; index < *threshold_count; ++index) {
    ThresholdRule rule;
    const auto kind = reader.get_u8();
    if (!kind.has_value() || !valid_metric_kind(*kind)) {
      return false;
    }
    rule.kind = static_cast<MetricKind>(*kind);
    if (!get_metric(reader, rule.switch_value) || !get_metric(reader, rule.clear_value)) {
      return false;
    }
    semantics.thresholds.push_back(rule);
  }
  const auto improvement_count = reader.get_u64();
  if (!improvement_count.has_value() || *improvement_count > Limits{}.max_objective_terms) {
    return false;
  }
  for (std::uint64_t index = 0; index < *improvement_count; ++index) {
    ImprovementRule rule;
    const auto kind = reader.get_u8();
    const auto switch_bps = reader.get_u32();
    const auto reverse_bps = reader.get_u32();
    if (!kind.has_value() || !valid_metric_kind(*kind) || !switch_bps.has_value() ||
        !reverse_bps.has_value()) {
      return false;
    }
    rule.kind = static_cast<MetricKind>(*kind);
    rule.switch_improvement_bps = *switch_bps;
    rule.reverse_improvement_bps = *reverse_bps;
    semantics.improvements.push_back(rule);
  }
  const auto evidence_count = reader.get_u64();
  if (!evidence_count.has_value() ||
      *evidence_count > Limits{}.max_evidence_requirements_per_policy) {
    return false;
  }
  for (std::uint64_t index = 0; index < *evidence_count; ++index) {
    EvidenceRequirement requirement;
    if (!get_requirement(reader, requirement)) {
      return false;
    }
    semantics.evidence.push_back(requirement);
  }
  const auto hold_down = reader.get_u64();
  const auto cooldown = reader.get_u64();
  const auto dampening_enabled = reader.get_bool();
  const auto penalty_increment = reader.get_u32();
  const auto max_penalty = reader.get_u32();
  const auto decay_interval = reader.get_u64();
  const auto decay_step = reader.get_u32();
  const auto escalation = reader.get_u64();
  const auto max_hold_down = reader.get_u64();
  const auto churn_max = reader.get_u32();
  const auto churn_window = reader.get_u64();
  const auto objective_mode = reader.get_u8();
  const auto scoring_version = reader.get_u32();
  if (!hold_down.has_value() || !cooldown.has_value() || !dampening_enabled.has_value() ||
      !penalty_increment.has_value() || !max_penalty.has_value() || !decay_interval.has_value() ||
      !decay_step.has_value() || !escalation.has_value() || !max_hold_down.has_value() ||
      !churn_max.has_value() || !churn_window.has_value() || !objective_mode.has_value() ||
      !scoring_version.has_value() || !valid_objective_mode(*objective_mode)) {
    return false;
  }
  semantics.hold_down.duration = *hold_down;
  semantics.cooldown.duration = *cooldown;
  semantics.dampening.enabled = *dampening_enabled;
  semantics.dampening.penalty_increment = *penalty_increment;
  semantics.dampening.max_penalty = *max_penalty;
  semantics.dampening.penalty_decay_interval = *decay_interval;
  semantics.dampening.penalty_decay_step = *decay_step;
  semantics.dampening.hold_down_escalation_step = *escalation;
  semantics.dampening.max_effective_hold_down = *max_hold_down;
  semantics.churn.max_adaptations_per_window = *churn_max;
  semantics.churn.window = *churn_window;
  semantics.objective.mode = static_cast<ObjectiveMode>(*objective_mode);
  semantics.objective.scoring_version = *scoring_version;
  const auto term_count = reader.get_u64();
  if (!term_count.has_value() || *term_count > Limits{}.max_objective_terms) {
    return false;
  }
  for (std::uint64_t index = 0; index < *term_count; ++index) {
    ObjectiveTerm term;
    const auto kind = reader.get_u8();
    const auto weight = reader.get_u32();
    if (!kind.has_value() || !valid_metric_kind(*kind) || !weight.has_value()) {
      return false;
    }
    term.kind = static_cast<MetricKind>(*kind);
    term.weight_bps = *weight;
    semantics.objective.terms.push_back(term);
  }
  const auto emergency_enabled = reader.get_bool();
  const auto on_unauthorized = reader.get_bool();
  const auto on_unavailable = reader.get_bool();
  const auto on_hard_failure = reader.get_bool();
  if (!emergency_enabled.has_value() || !on_unauthorized.has_value() ||
      !on_unavailable.has_value() || !on_hard_failure.has_value()) {
    return false;
  }
  semantics.emergency.enabled = *emergency_enabled;
  semantics.emergency.on_current_path_unauthorized = *on_unauthorized;
  semantics.emergency.on_current_path_unavailable = *on_unavailable;
  semantics.emergency.on_hard_failure_signal = *on_hard_failure;
  const auto priority_count = reader.get_u64();
  if (!priority_count.has_value() || *priority_count > Limits{}.max_candidates_per_policy) {
    return false;
  }
  for (std::uint64_t index = 0; index < *priority_count; ++index) {
    CandidatePriority entry;
    // Field order mirrors put_semantics exactly: identity, then the priority
    // value.
    if (!get_id(reader, entry.path)) {
      return false;
    }
    const auto priority = reader.get_u32();
    if (!priority.has_value()) {
      return false;
    }
    entry.priority = *priority;
    semantics.priorities.push_back(entry);
  }
  return true;
}

void put_provenance(ByteWriter& writer, const AdaptationProvenance& provenance) {
  put_id(writer, provenance.publisher);
  put_id(writer, provenance.worker_boot);
  writer.put_u64(provenance.epoch.value());
  put_id(writer, provenance.attempt);
  writer.put_u64(provenance.policy_generation.value());
  writer.put_u8(static_cast<std::uint8_t>(provenance.cause));
}

// Provenance is recorded for facts that may never have been established (a
// preference that never committed has no epoch and no attempt), so the
// generation fields allow zero and the identity fields allow the empty
// encoding. The order mirrors put_provenance exactly.
[[nodiscard]] bool get_provenance(ByteReader& reader, AdaptationProvenance& provenance) {
  if (!get_maybe_id(reader, provenance.publisher) ||
      !get_maybe_id(reader, provenance.worker_boot)) {
    return false;
  }
  const auto epoch = reader.get_u64();
  if (!epoch.has_value()) {
    return false;
  }
  if (*epoch != 0) {
    const auto parsed = CoordinatorEpoch::from_value(*epoch);
    if (!parsed.has_value()) {
      return false;
    }
    provenance.epoch = *parsed;
  }
  if (!get_maybe_id(reader, provenance.attempt)) {
    return false;
  }
  const auto policy_generation = reader.get_u64();
  if (!policy_generation.has_value()) {
    return false;
  }
  if (*policy_generation != 0) {
    const auto parsed = AdaptivePolicyGeneration::from_value(*policy_generation);
    if (!parsed.has_value()) {
      return false;
    }
    provenance.policy_generation = *parsed;
  }
  const auto cause = reader.get_u8();
  if (!cause.has_value() || !valid_adaptation_cause(*cause)) {
    return false;
  }
  provenance.cause = static_cast<AdaptationCause>(*cause);
  return true;
}

}  // namespace

std::string_view to_string(StoreDecodeStatus status) noexcept {
  switch (status) {
    case StoreDecodeStatus::OK:
      return "OK";
    case StoreDecodeStatus::EMPTY:
      return "EMPTY";
    case StoreDecodeStatus::BAD_MAGIC:
      return "BAD_MAGIC";
    case StoreDecodeStatus::BAD_VERSION:
      return "BAD_VERSION";
    case StoreDecodeStatus::TRUNCATED:
      return "TRUNCATED";
    case StoreDecodeStatus::INTEGRITY:
      return "INTEGRITY";
    case StoreDecodeStatus::MALFORMED:
      return "MALFORMED";
    case StoreDecodeStatus::TRAILING_BYTES:
      return "TRAILING_BYTES";
    case StoreDecodeStatus::DUPLICATE_POLICY:
      return "DUPLICATE_POLICY";
    case StoreDecodeStatus::INVALID_GENERATION:
      return "INVALID_GENERATION";
    case StoreDecodeStatus::IMPOSSIBLE_LIFECYCLE:
      return "IMPOSSIBLE_LIFECYCLE";
    case StoreDecodeStatus::MALFORMED_METRIC:
      return "MALFORMED_METRIC";
    case StoreDecodeStatus::MALFORMED_EVIDENCE_BINDING:
      return "MALFORMED_EVIDENCE_BINDING";
    case StoreDecodeStatus::INVALID_PREFERRED_CANDIDATE:
      return "INVALID_PREFERRED_CANDIDATE";
    case StoreDecodeStatus::TIMING_WITHOUT_POLICY:
      return "TIMING_WITHOUT_POLICY";
    case StoreDecodeStatus::ABSURD_COUNT:
      return "ABSURD_COUNT";
    case StoreDecodeStatus::COUNTER_OVERFLOW:
      return "OVERFLOW";
    case StoreDecodeStatus::TOO_LARGE:
      return "TOO_LARGE";
    case StoreDecodeStatus::MALFORMED_TIMING:
      return "MALFORMED_TIMING";
  }
  return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

std::string encode_durable_state(const DurableState& state) {
  ByteWriter body;
  body.put_u64(state.epoch.value());
  body.put_u64(state.authority_generation.value());
  body.put_u64(state.evidence_generation.value());
  body.put_u64(state.evidence_watermark.value());
  body.put_u64(state.upstream_watermark.value());

  body.put_u64(state.policies.size());
  for (const auto& policy : state.policies) {
    ByteWriter record;
    put_id(record, policy.id);
    put_id(record, policy.name);
    put_scope(record, policy.scope);
    put_semantics(record, policy.semantics);
    record.put_u64(policy.generation.value());
    record.put_u8(static_cast<std::uint8_t>(policy.lifecycle));
    record.put_u64(policy.epoch.value());
    put_id(record, policy.owner);
    record.put_u64(policy.authority_generation.value());
    record.put_u64(policy.declared_at);
    record.put_u64(policy.updated_at);
    body.put_bytes(record.buffer());
  }

  body.put_u64(state.revocations.size());
  for (const auto& revocation : state.revocations) {
    ByteWriter record;
    put_id(record, revocation.policy);
    record.put_u64(revocation.generation.value());
    record.put_u64(revocation.authority_generation.value());
    record.put_u64(revocation.epoch.value());
    put_id(record, revocation.publisher);
    record.put_u8(static_cast<std::uint8_t>(revocation.reason));
    record.put_string(revocation.detail);
    body.put_bytes(record.buffer());
  }

  body.put_u64(state.preferences.size());
  for (const auto& entry : state.preferences) {
    const RoutingPreference& preference = entry.preference;
    ByteWriter record;
    put_id(record, entry.policy);
    put_id(record, preference.route);
    put_optional_id(record, preference.multipath_set);
    record.put_u64(preference.multipath_set_generation.value());
    record.put_bool(preference.established);
    put_id(record, preference.preferred_path);
    record.put_u64(preference.path_authority_generation.value());
    put_optional_id(record, preference.previous_path);
    record.put_u64(preference.route_generation.value());
    record.put_u64(preference.adaptation_generation.value());
    record.put_u64(preference.transition_generation.value());
    put_id(record, preference.transition);
    record.put_bool(preference.weight_proposal.has_value());
    if (preference.weight_proposal.has_value()) {
      put_id(record, preference.weight_proposal->set);
      record.put_u64(preference.weight_proposal->base_generation.value());
      record.put_u64(preference.weight_proposal->weights.size());
      for (const auto& weight : preference.weight_proposal->weights) {
        put_id(record, weight.path);
        record.put_u32(weight.weight_bps);
      }
    }
    put_optional_id(record, preference.decision);
    put_provenance(record, preference.provenance);
    record.put_u64(preference.committed_at);
    body.put_bytes(record.buffer());
  }

  body.put_u64(state.stable_states.size());
  for (const auto& entry : state.stable_states) {
    const StableState& stable = entry.stable;
    ByteWriter record;
    put_id(record, entry.policy);
    record.put_bool(stable.established);
    put_id(record, stable.path);
    record.put_u64(stable.path_authority_generation.value());
    record.put_u64(stable.route_generation.value());
    record.put_u64(stable.multipath_set_generation.value());
    record.put_u64(stable.adaptation_generation.value());
    record.put_u64(stable.stabilized_at);
    body.put_bytes(record.buffer());
  }

  body.put_u64(state.timings.size());
  for (const auto& timing : state.timings) {
    ByteWriter record;
    put_id(record, timing.policy);
    record.put_bool(timing.hold_down_active);
    record.put_u64(timing.hold_down_remaining);
    record.put_u64(timing.hold_down_policy_generation.value());
    put_optional_id(record, timing.hold_down_locked_path);
    record.put_bool(timing.cooldown_active);
    record.put_u64(timing.cooldown_remaining);
    record.put_u32(timing.dampening_penalty);
    record.put_u64(timing.dampening_decay_remaining);
    record.put_u64(timing.churn_ages.size());
    for (const Ticks age : timing.churn_ages) {
      record.put_u64(age);
    }
    body.put_bytes(record.buffer());
  }

  body.put_u64(state.history.size());
  for (const auto& durable : state.history) {
    const AdaptationRecord& entry = durable.record;
    ByteWriter record;
    put_id(record, durable.policy);
    put_id(record, entry.decision);
    record.put_u8(static_cast<std::uint8_t>(entry.lifecycle));
    record.put_u16(static_cast<std::uint16_t>(entry.outcome));
    record.put_u8(static_cast<std::uint8_t>(entry.suppression));
    record.put_u8(static_cast<std::uint8_t>(entry.cause));
    put_optional_id(record, entry.from_path);
    put_optional_id(record, entry.to_path);
    record.put_u64(entry.adaptation_generation.value());
    record.put_u64(entry.evidence_generation.value());
    record.put_u64(entry.epoch.value());
    record.put_string(entry.digest);
    body.put_bytes(record.buffer());
  }

  std::string bytes;
  bytes.reserve(body.size() + 16 + static_cast<std::size_t>(store_trailer_bytes));
  for (int index = 0; index < 4; ++index) {
    bytes.push_back(static_cast<char>(
        static_cast<unsigned char>((store_magic >> (8 * index)) & 0xFFU)));
  }
  for (int index = 0; index < 4; ++index) {
    bytes.push_back(static_cast<char>(static_cast<unsigned char>(
        (persistence_format_version >> (8 * index)) & 0xFFU)));
  }
  bytes += body.buffer();
  const std::uint64_t integrity = store_integrity(bytes);
  for (int index = 0; index < 8; ++index) {
    bytes.push_back(static_cast<char>(
        static_cast<unsigned char>((integrity >> (8 * index)) & 0xFFU)));
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

StoreDecodeResult decode_durable_state(std::string_view bytes) {
  StoreDecodeResult result;
  const Limits limits{};
  if (bytes.empty()) {
    result.status = StoreDecodeStatus::EMPTY;
    result.detail = "store is empty";
    return result;
  }
  if (bytes.size() > limits.max_store_bytes) {
    result.status = StoreDecodeStatus::TOO_LARGE;
    result.detail = "store exceeds the configured maximum size";
    return result;
  }
  if (bytes.size() < 8 + store_trailer_bytes) {
    result.status = StoreDecodeStatus::TRUNCATED;
    result.detail = "store header is incomplete";
    return result;
  }
  std::uint32_t magic = 0;
  for (int index = 0; index < 4; ++index) {
    magic |= static_cast<std::uint32_t>(
                 static_cast<unsigned char>(bytes[static_cast<std::size_t>(index)]))
             << (8 * index);
  }
  if (magic != store_magic) {
    result.status = StoreDecodeStatus::BAD_MAGIC;
    result.detail = "store magic does not match";
    return result;
  }
  std::uint32_t version = 0;
  for (int index = 0; index < 4; ++index) {
    version |= static_cast<std::uint32_t>(
                   static_cast<unsigned char>(bytes[static_cast<std::size_t>(4 + index)]))
               << (8 * index);
  }
  if (version != persistence_format_version) {
    result.status = StoreDecodeStatus::BAD_VERSION;
    result.detail = "store format version is not supported";
    return result;
  }
  const std::string_view body = bytes.substr(8, bytes.size() - 8 - store_trailer_bytes);
  std::uint64_t integrity = 0;
  for (int index = 0; index < 8; ++index) {
    integrity |= static_cast<std::uint64_t>(static_cast<unsigned char>(
                     bytes[bytes.size() - store_trailer_bytes + static_cast<std::size_t>(index)]))
                 << (8 * index);
  }
  if (integrity != store_integrity(bytes.substr(0, bytes.size() - store_trailer_bytes))) {
    result.status = StoreDecodeStatus::INTEGRITY;
    result.detail = "store integrity trailer does not match the content";
    return result;
  }
  ByteReader reader(body);
  DurableState& state = result.state;
  const auto epoch = reader.get_u64();
  const auto authority = reader.get_u64();
  const auto evidence_generation = reader.get_u64();
  const auto evidence_watermark = reader.get_u64();
  const auto upstream_watermark = reader.get_u64();
  if (!epoch.has_value() || !authority.has_value() || !evidence_generation.has_value() ||
      !evidence_watermark.has_value() || !upstream_watermark.has_value()) {
    result.status = StoreDecodeStatus::TRUNCATED;
    result.detail = "store header is truncated";
    return result;
  }
  const auto parsed_epoch = CoordinatorEpoch::from_value(*epoch);
  const auto parsed_authority = AdaptiveAuthorityGeneration::from_value(*authority);
  const auto parsed_evidence = EvidenceGeneration::from_value(*evidence_generation);
  if (!parsed_epoch.has_value() || !parsed_authority.has_value() || !parsed_evidence.has_value()) {
    result.status = StoreDecodeStatus::INVALID_GENERATION;
    result.detail = "store header carries an invalid generation";
    return result;
  }
  if (*evidence_watermark != 0 && *evidence_generation == 0) {
    result.status = StoreDecodeStatus::MALFORMED_EVIDENCE_BINDING;
    result.detail = "evidence watermark is set without an evidence generation";
    return result;
  }
  state.epoch = *parsed_epoch;
  state.authority_generation = *parsed_authority;
  state.evidence_generation = *parsed_evidence;
  state.evidence_watermark = Watermark(*evidence_watermark);
  state.upstream_watermark = Watermark(*upstream_watermark);

  const auto policy_count = reader.get_u64();
  if (!policy_count.has_value()) {
    result.status = StoreDecodeStatus::TRUNCATED;
    result.detail = "policy record count is missing";
    return result;
  }
  if (*policy_count > limits.max_policies) {
    result.status = StoreDecodeStatus::ABSURD_COUNT;
    result.detail = "policy record count exceeds the configured maximum";
    return result;
  }
  std::vector<AdaptivePolicyId> seen;
  seen.reserve(static_cast<std::size_t>(*policy_count));
  for (std::uint64_t index = 0; index < *policy_count; ++index) {
    const auto record = reader.get_bytes(limits.max_persistence_record_bytes);
    if (!record.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      result.detail = "policy record is truncated or exceeds the record bound";
      return result;
    }
    ByteReader record_reader(*record);
    AdaptivePolicy policy;
    if (!get_id(record_reader, policy.id) || !get_id(record_reader, policy.name) ||
        !get_scope(record_reader, policy.scope) || !get_semantics(record_reader, policy.semantics)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "policy record could not be decoded";
      return result;
    }
    const auto generation = record_reader.get_u64();
    const auto lifecycle = record_reader.get_u8();
    const auto policy_epoch = record_reader.get_u64();
    if (!generation.has_value() || !lifecycle.has_value() || !policy_epoch.has_value() ||
        !valid_policy_lifecycle(*lifecycle)) {
      result.status = StoreDecodeStatus::IMPOSSIBLE_LIFECYCLE;
      result.detail = "policy record carries an invalid lifecycle or generation";
      return result;
    }
    const auto parsed_generation = AdaptivePolicyGeneration::from_value(*generation);
    const auto parsed_policy_epoch = CoordinatorEpoch::from_value(*policy_epoch);
    if (!parsed_generation.has_value() || !parsed_policy_epoch.has_value()) {
      result.status = StoreDecodeStatus::INVALID_GENERATION;
      result.detail = "policy record carries a zero generation";
      return result;
    }
    policy.generation = *parsed_generation;
    policy.lifecycle = static_cast<PolicyLifecycle>(*lifecycle);
    policy.epoch = *parsed_policy_epoch;
    if (!get_id(record_reader, policy.owner)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "policy owner is missing";
      return result;
    }
    const auto authority_generation = record_reader.get_u64();
    const auto declared_at = record_reader.get_u64();
    const auto updated_at = record_reader.get_u64();
    if (!authority_generation.has_value() || !declared_at.has_value() || !updated_at.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      result.detail = "policy record is truncated";
      return result;
    }
    const auto parsed_authority_generation =
        AdaptiveAuthorityGeneration::from_value(*authority_generation);
    if (!parsed_authority_generation.has_value()) {
      result.status = StoreDecodeStatus::INVALID_GENERATION;
      result.detail = "policy record carries a zero authority generation";
      return result;
    }
    policy.authority_generation = *parsed_authority_generation;
    policy.declared_at = *declared_at;
    policy.updated_at = *updated_at;
    if (!record_reader.finished()) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "policy record carries trailing bytes";
      return result;
    }
    std::string reason;
    if (policy.semantics.semantics_version != policy_semantics_version ||
        !policy.semantics.valid(&reason)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "policy semantics are not valid under this semantics version";
      return result;
    }
    if (std::find(seen.begin(), seen.end(), policy.id) != seen.end()) {
      result.status = StoreDecodeStatus::DUPLICATE_POLICY;
      result.detail = "the store names the same policy twice";
      return result;
    }
    seen.push_back(policy.id);
    state.policies.push_back(std::move(policy));
  }

  const auto revocation_count = reader.get_u64();
  if (!revocation_count.has_value()) {
    result.status = StoreDecodeStatus::TRUNCATED;
    return result;
  }
  if (*revocation_count > limits.max_revocations) {
    result.status = StoreDecodeStatus::ABSURD_COUNT;
    result.detail = "revocation count exceeds the configured maximum";
    return result;
  }
  for (std::uint64_t index = 0; index < *revocation_count; ++index) {
    const auto record = reader.get_bytes(limits.max_persistence_record_bytes);
    if (!record.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    ByteReader record_reader(*record);
    RevocationRecord revocation;
    if (!get_id(record_reader, revocation.policy)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "revocation record could not be decoded";
      return result;
    }
    const auto raw_generation = record_reader.get_u64();
    const auto raw_authority = record_reader.get_u64();
    const auto record_epoch = record_reader.get_u64();
    // Field order mirrors the encoder: the publishing identity precedes the
    // reason code.
    if (!get_id(record_reader, revocation.publisher)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "revocation record names no publisher";
      return result;
    }
    const auto reason = record_reader.get_u8();
    if (!raw_generation.has_value() || !raw_authority.has_value() || !record_epoch.has_value() ||
        !reason.has_value() || !valid_revocation_reason(*reason)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "revocation record carries an invalid enum or generation";
      return result;
    }
    const auto parsed_generation = AdaptivePolicyGeneration::from_value(*raw_generation);
    const auto parsed_revocation_authority =
        AdaptiveAuthorityGeneration::from_value(*raw_authority);
    const auto parsed_record_epoch = CoordinatorEpoch::from_value(*record_epoch);
    if (!parsed_generation.has_value() || !parsed_revocation_authority.has_value() ||
        !parsed_record_epoch.has_value()) {
      result.status = StoreDecodeStatus::INVALID_GENERATION;
      result.detail = "revocation record carries a zero generation";
      return result;
    }
    revocation.generation = *parsed_generation;
    revocation.authority_generation = *parsed_revocation_authority;
    revocation.epoch = *parsed_record_epoch;
    revocation.reason = static_cast<RevocationReason>(*reason);
    const auto detail = record_reader.get_string(4096);
    if (!detail.has_value() || !record_reader.finished()) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "revocation record is truncated or carries trailing bytes";
      return result;
    }
    revocation.detail = *detail;
    state.revocations.push_back(std::move(revocation));
  }

  const auto preference_count = reader.get_u64();
  if (!preference_count.has_value()) {
    result.status = StoreDecodeStatus::TRUNCATED;
    return result;
  }
  if (*preference_count > limits.max_policies) {
    result.status = StoreDecodeStatus::ABSURD_COUNT;
    result.detail = "preference count exceeds the configured maximum";
    return result;
  }
  for (std::uint64_t index = 0; index < *preference_count; ++index) {
    const auto record = reader.get_bytes(limits.max_persistence_record_bytes);
    if (!record.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    ByteReader record_reader(*record);
    DurablePreference durable;
    RoutingPreference& preference = durable.preference;
    if (!get_id(record_reader, durable.policy) || !get_id(record_reader, preference.route) ||
        !get_optional_id(record_reader, preference.multipath_set)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "preference record could not be decoded";
      return result;
    }
    const auto set_generation = record_reader.get_u64();
    const auto established = record_reader.get_bool();
    if (!set_generation.has_value() || !established.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    if (*set_generation != 0) {
      const auto parsed = MultipathSetGeneration::from_value(*set_generation);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      preference.multipath_set_generation = *parsed;
    }
    preference.established = *established;
    // The preferred path is written unconditionally as a plain identity and is
    // empty when no preference was ever committed.
    if (!get_maybe_id(record_reader, preference.preferred_path)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "preference record carries a malformed preferred path";
      return result;
    }
    const auto raw_authority_generation = record_reader.get_u64();
    if (!raw_authority_generation.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    if (preference.established) {
      if (!preference.preferred_path.valid()) {
        result.status = StoreDecodeStatus::INVALID_PREFERRED_CANDIDATE;
        result.detail = "an established preference carries no preferred path";
        return result;
      }
      const auto parsed_authority_generation =
          PathAuthorityGeneration::from_value(*raw_authority_generation);
      if (!parsed_authority_generation.has_value()) {
        result.status = StoreDecodeStatus::INVALID_PREFERRED_CANDIDATE;
        result.detail = "an established preference carries no path authority generation";
        return result;
      }
      preference.path_authority_generation = *parsed_authority_generation;
    } else if (*raw_authority_generation != 0) {
      const auto parsed_authority_generation =
          PathAuthorityGeneration::from_value(*raw_authority_generation);
      if (!parsed_authority_generation.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      preference.path_authority_generation = *parsed_authority_generation;
    }
    if (!get_optional_id(record_reader, preference.previous_path)) {
      result.status = StoreDecodeStatus::MALFORMED;
      return result;
    }
    const auto route_generation = record_reader.get_u64();
    const auto adaptation_generation = record_reader.get_u64();
    const auto transition_generation = record_reader.get_u64();
    if (!route_generation.has_value() || !adaptation_generation.has_value() ||
        !transition_generation.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    if (*route_generation != 0) {
      const auto parsed = RouteGeneration::from_value(*route_generation);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      preference.route_generation = *parsed;
    }
    const auto parsed_adaptation = AdaptationGeneration::from_value(*adaptation_generation);
    const auto parsed_transition = TransitionGeneration::from_value(*transition_generation);
    if (!parsed_adaptation.has_value() || !parsed_transition.has_value()) {
      result.status = StoreDecodeStatus::INVALID_GENERATION;
      result.detail = "preference record carries a zero generation";
      return result;
    }
    preference.adaptation_generation = *parsed_adaptation;
    preference.transition_generation = *parsed_transition;
    // Written unconditionally as a plain identity; empty means "no transition
    // plan has been issued yet".
    if (!get_maybe_id(record_reader, preference.transition)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "preference record carries a malformed transition identity";
      return result;
    }
    const auto has_proposal = record_reader.get_bool();
    if (!has_proposal.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    if (*has_proposal) {
      WeightProposal proposal;
      if (!get_id(record_reader, proposal.set)) {
        result.status = StoreDecodeStatus::MALFORMED;
        return result;
      }
      const auto base = record_reader.get_u64();
      const auto weight_count = record_reader.get_u64();
      if (!base.has_value() || !weight_count.has_value() ||
          *weight_count > limits.max_candidates_per_policy) {
        result.status = StoreDecodeStatus::ABSURD_COUNT;
        return result;
      }
      const auto parsed_base = WeightPolicyGeneration::from_value(*base);
      if (!parsed_base.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      proposal.base_generation = *parsed_base;
      for (std::uint64_t weight_index = 0; weight_index < *weight_count; ++weight_index) {
        PathWeight weight;
        if (!get_id(record_reader, weight.path)) {
          result.status = StoreDecodeStatus::MALFORMED;
          return result;
        }
        const auto value = record_reader.get_u32();
        if (!value.has_value() || *value > basis_points_scale) {
          result.status = StoreDecodeStatus::MALFORMED_METRIC;
          return result;
        }
        weight.weight_bps = *value;
        proposal.weights.push_back(weight);
      }
      if (!proposal.well_formed()) {
        result.status = StoreDecodeStatus::MALFORMED;
        result.detail = "weight proposal is not well formed";
        return result;
      }
      preference.weight_proposal = proposal;
    }
    if (!get_optional_id(record_reader, preference.decision) ||
        !get_provenance(record_reader, preference.provenance)) {
      result.status = StoreDecodeStatus::MALFORMED;
      return result;
    }
    const auto committed_at = record_reader.get_u64();
    if (!committed_at.has_value() || !record_reader.finished()) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "preference record is truncated or carries trailing bytes";
      return result;
    }
    preference.committed_at = *committed_at;
    const auto owner = std::find_if(state.policies.begin(), state.policies.end(),
                                    [&durable](const AdaptivePolicy& policy) {
                                      return policy.id == durable.policy;
                                    });
    if (owner == state.policies.end()) {
      result.status = StoreDecodeStatus::TIMING_WITHOUT_POLICY;
      result.detail = "preference state names a policy the store does not contain";
      return result;
    }
    if (!(owner->semantics.target.route == preference.route)) {
      result.status = StoreDecodeStatus::INVALID_PREFERRED_CANDIDATE;
      result.detail = "preference names a route the owning policy does not target";
      return result;
    }
    state.preferences.push_back(std::move(durable));
  }

  const auto stable_count = reader.get_u64();
  if (!stable_count.has_value() || *stable_count > limits.max_policies) {
    result.status = StoreDecodeStatus::ABSURD_COUNT;
    result.detail = "stable-state count exceeds the configured maximum";
    return result;
  }
  for (std::uint64_t index = 0; index < *stable_count; ++index) {
    const auto record = reader.get_bytes(limits.max_persistence_record_bytes);
    if (!record.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    ByteReader record_reader(*record);
    DurableStable durable;
    StableState& stable = durable.stable;
    if (!get_id(record_reader, durable.policy)) {
      result.status = StoreDecodeStatus::MALFORMED;
      return result;
    }
    const auto established = record_reader.get_bool();
    if (!established.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    stable.established = *established;
    // Written unconditionally as a plain identity, empty when the policy has
    // never been stable.
    if (!get_maybe_id(record_reader, stable.path)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "stable-state record carries a malformed path";
      return result;
    }
    const auto raw_stable_authority = record_reader.get_u64();
    if (!raw_stable_authority.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    if (*raw_stable_authority != 0) {
      const auto parsed = PathAuthorityGeneration::from_value(*raw_stable_authority);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      stable.path_authority_generation = *parsed;
    } else if (stable.established) {
      result.status = StoreDecodeStatus::INVALID_GENERATION;
      result.detail = "an established stable state carries no path authority generation";
      return result;
    }
    const auto route_generation = record_reader.get_u64();
    const auto multipath_generation = record_reader.get_u64();
    const auto adaptation_generation = record_reader.get_u64();
    const auto stabilized_at = record_reader.get_u64();
    if (!route_generation.has_value() || !multipath_generation.has_value() ||
        !adaptation_generation.has_value() || !stabilized_at.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    if (*route_generation != 0) {
      const auto parsed = RouteGeneration::from_value(*route_generation);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      stable.route_generation = *parsed;
    }
    if (*multipath_generation != 0) {
      const auto parsed = MultipathSetGeneration::from_value(*multipath_generation);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      stable.multipath_set_generation = *parsed;
    }
    if (*adaptation_generation != 0) {
      const auto parsed = AdaptationGeneration::from_value(*adaptation_generation);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      stable.adaptation_generation = *parsed;
    }
    stable.stabilized_at = *stabilized_at;
    if (!record_reader.finished()) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "stable-state record carries trailing bytes";
      return result;
    }
    const auto owner = std::find_if(state.policies.begin(), state.policies.end(),
                                    [&durable](const AdaptivePolicy& policy) {
                                      return policy.id == durable.policy;
                                    });
    if (owner == state.policies.end()) {
      result.status = StoreDecodeStatus::TIMING_WITHOUT_POLICY;
      result.detail = "stable state names a policy the store does not contain";
      return result;
    }
    state.stable_states.push_back(std::move(durable));
  }

  const auto timing_count = reader.get_u64();
  if (!timing_count.has_value() || *timing_count > limits.max_policies) {
    result.status = StoreDecodeStatus::ABSURD_COUNT;
    result.detail = "timing count exceeds the configured maximum";
    return result;
  }
  for (std::uint64_t index = 0; index < *timing_count; ++index) {
    const auto record = reader.get_bytes(limits.max_persistence_record_bytes);
    if (!record.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    ByteReader record_reader(*record);
    DurableTiming timing;
    if (!get_id(record_reader, timing.policy)) {
      result.status = StoreDecodeStatus::MALFORMED;
      return result;
    }
    const auto policy = std::find_if(state.policies.begin(), state.policies.end(),
                                     [&timing](const AdaptivePolicy& candidate) {
                                       return candidate.id == timing.policy;
                                     });
    if (policy == state.policies.end()) {
      // Hold-down or cooldown state that names no policy is rejected rather
      // than silently dropped: it would otherwise re-arm against nothing.
      result.status = StoreDecodeStatus::TIMING_WITHOUT_POLICY;
      result.detail = "timing state names a policy the store does not contain";
      return result;
    }
    const auto hold_down_active = record_reader.get_bool();
    const auto hold_down_remaining = record_reader.get_u64();
    const auto hold_down_generation = record_reader.get_u64();
    if (!hold_down_active.has_value() || !hold_down_remaining.has_value() ||
        !hold_down_generation.has_value()) {
      result.status = StoreDecodeStatus::MALFORMED_TIMING;
      return result;
    }
    timing.hold_down_active = *hold_down_active;
    timing.hold_down_remaining = *hold_down_remaining;
    if (*hold_down_generation != 0) {
      const auto parsed = AdaptivePolicyGeneration::from_value(*hold_down_generation);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      timing.hold_down_policy_generation = *parsed;
    }
    if (!get_optional_id(record_reader, timing.hold_down_locked_path)) {
      result.status = StoreDecodeStatus::MALFORMED_TIMING;
      return result;
    }
    const auto cooldown_active = record_reader.get_bool();
    const auto cooldown_remaining = record_reader.get_u64();
    if (!cooldown_active.has_value() || !cooldown_remaining.has_value()) {
      result.status = StoreDecodeStatus::MALFORMED_TIMING;
      return result;
    }
    timing.cooldown_active = *cooldown_active;
    timing.cooldown_remaining = *cooldown_remaining;
    const auto penalty = record_reader.get_u32();
    const auto decay_remaining = record_reader.get_u64();
    if (!penalty.has_value() || !decay_remaining.has_value() ||
        *penalty > limits.max_dampening_penalty) {
      result.status = StoreDecodeStatus::MALFORMED_TIMING;
      result.detail = "dampening penalty is out of range";
      return result;
    }
    timing.dampening_penalty = *penalty;
    timing.dampening_decay_remaining = *decay_remaining;
    const auto churn_count = record_reader.get_u64();
    if (!churn_count.has_value() || *churn_count > limits.max_adaptations_per_window) {
      result.status = StoreDecodeStatus::ABSURD_COUNT;
      return result;
    }
    for (std::uint64_t age_index = 0; age_index < *churn_count; ++age_index) {
      const auto age = record_reader.get_u64();
      if (!age.has_value()) {
        result.status = StoreDecodeStatus::MALFORMED_TIMING;
        return result;
      }
      timing.churn_ages.push_back(*age);
    }
    if (!record_reader.finished()) {
      result.status = StoreDecodeStatus::MALFORMED_TIMING;
      result.detail = "timing record carries trailing bytes";
      return result;
    }
    if (!timing.hold_down_active && timing.hold_down_remaining != 0) {
      result.status = StoreDecodeStatus::MALFORMED_TIMING;
      result.detail = "hold-down remainder is present while hold-down is inactive";
      return result;
    }
    if (!timing.cooldown_active && timing.cooldown_remaining != 0) {
      result.status = StoreDecodeStatus::MALFORMED_TIMING;
      result.detail = "cooldown remainder is present while cooldown is inactive";
      return result;
    }
    state.timings.push_back(std::move(timing));
  }

  const auto history_count = reader.get_u64();
  if (!history_count.has_value() || *history_count > limits.max_decision_history) {
    result.status = StoreDecodeStatus::ABSURD_COUNT;
    result.detail = "history count exceeds the configured maximum";
    return result;
  }
  for (std::uint64_t index = 0; index < *history_count; ++index) {
    const auto record = reader.get_bytes(limits.max_persistence_record_bytes);
    if (!record.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    ByteReader record_reader(*record);
    DurableHistoryEntry durable;
    AdaptationRecord& entry = durable.record;
    if (!get_id(record_reader, durable.policy) || !get_id(record_reader, entry.decision)) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "history record could not be decoded";
      return result;
    }
    const auto lifecycle = record_reader.get_u8();
    const auto outcome = record_reader.get_u16();
    const auto suppression = record_reader.get_u8();
    const auto cause = record_reader.get_u8();
    if (!lifecycle.has_value() || !outcome.has_value() || !suppression.has_value() ||
        !cause.has_value() || !valid_decision_lifecycle(*lifecycle) || !valid_outcome(*outcome) ||
        !valid_suppression_reason(*suppression) || !valid_adaptation_cause(*cause)) {
      result.status = StoreDecodeStatus::IMPOSSIBLE_LIFECYCLE;
      result.detail = "history record carries an invalid lifecycle or outcome";
      return result;
    }
    entry.lifecycle = static_cast<DecisionLifecycle>(*lifecycle);
    entry.outcome = static_cast<Outcome>(*outcome);
    entry.suppression = static_cast<SuppressionReason>(*suppression);
    entry.cause = static_cast<AdaptationCause>(*cause);
    if (!get_optional_id(record_reader, entry.from_path) ||
        !get_optional_id(record_reader, entry.to_path)) {
      result.status = StoreDecodeStatus::MALFORMED;
      return result;
    }
    const auto adaptation_generation = record_reader.get_u64();
    const auto history_evidence_generation = record_reader.get_u64();
    const auto record_epoch = record_reader.get_u64();
    if (!adaptation_generation.has_value() || !history_evidence_generation.has_value() ||
        !record_epoch.has_value()) {
      result.status = StoreDecodeStatus::TRUNCATED;
      return result;
    }
    if (*adaptation_generation != 0) {
      const auto parsed = AdaptationGeneration::from_value(*adaptation_generation);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      entry.adaptation_generation = *parsed;
    }
    if (*history_evidence_generation != 0) {
      const auto parsed = EvidenceGeneration::from_value(*history_evidence_generation);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      entry.evidence_generation = *parsed;
    }
    if (*record_epoch != 0) {
      const auto parsed = CoordinatorEpoch::from_value(*record_epoch);
      if (!parsed.has_value()) {
        result.status = StoreDecodeStatus::INVALID_GENERATION;
        return result;
      }
      entry.epoch = *parsed;
    }
    const auto digest = record_reader.get_string(4096);
    if (!digest.has_value() || !record_reader.finished()) {
      result.status = StoreDecodeStatus::MALFORMED;
      result.detail = "history record is truncated or carries trailing bytes";
      return result;
    }
    entry.digest = *digest;
    const auto owner = std::find_if(state.policies.begin(), state.policies.end(),
                                    [&durable](const AdaptivePolicy& policy) {
                                      return policy.id == durable.policy;
                                    });
    if (owner == state.policies.end()) {
      result.status = StoreDecodeStatus::TIMING_WITHOUT_POLICY;
      result.detail = "history names a policy the store does not contain";
      return result;
    }
    state.history.push_back(std::move(durable));
  }

  if (!reader.finished()) {
    result.status = StoreDecodeStatus::TRAILING_BYTES;
    result.detail = "store carries trailing bytes after the last record";
    result.state = DurableState{};
    return result;
  }
  result.status = StoreDecodeStatus::OK;
  return result;
}

bool write_store_atomic(const std::string& path, std::string_view bytes, std::string& error) {
  namespace fs = std::filesystem;
  std::error_code code;
  const fs::path destination(path);
  fs::path temporary = destination;
  temporary += ".tmp";
  {
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream) {
      error = "could not open the temporary store for writing";
      return false;
    }
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    stream.flush();
    if (!stream) {
      error = "could not write the temporary store";
      stream.close();
      fs::remove(temporary, code);
      return false;
    }
  }
  fs::rename(temporary, destination, code);
  if (code) {
    // Windows refuses a rename onto an existing file; removing the destination
    // first keeps the replacement atomic from the reader's point of view,
    // because a reader either sees the old file or the new one.
    fs::remove(destination, code);
    code.clear();
    fs::rename(temporary, destination, code);
    if (code) {
      error = "could not replace the store";
      fs::remove(temporary, code);
      return false;
    }
  }
  return true;
}

std::optional<std::string> read_store_bytes(const std::string& path, std::string& error) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    error = "store could not be opened";
    return std::nullopt;
  }
  std::string bytes;
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  if (size < 0) {
    error = "store size could not be determined";
    return std::nullopt;
  }
  stream.seekg(0, std::ios::beg);
  bytes.resize(static_cast<std::size_t>(size));
  stream.read(bytes.data(), size);
  if (!stream) {
    error = "store could not be read completely";
    return std::nullopt;
  }
  return bytes;
}

}  // namespace adaptive_routing

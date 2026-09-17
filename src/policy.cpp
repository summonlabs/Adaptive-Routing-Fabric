// Adaptation policy validation and rendering.
#include "adaptive_routing/policy.hpp"

#include <algorithm>
#include <cstdio>

#include "adaptive_routing/version.hpp"

namespace adaptive_routing {
namespace {

void set_reason(std::string* reason, const char* text) {
  if (reason != nullptr && reason->empty()) {
    *reason = text;
  }
}

template <class Id>
[[nodiscard]] bool has_duplicate_ids(const std::vector<Id>& values) {
  std::vector<Id> copy(values);
  std::sort(copy.begin(), copy.end());
  return std::adjacent_find(copy.begin(), copy.end()) != copy.end();
}

// orientation aware "value is at least as bad as the other"
[[nodiscard]] bool at_least_as_bad(const MetricValue& value, const MetricValue& reference) noexcept {
  return describe_metric(value.kind()).orientation == MetricOrientation::LOWER_IS_BETTER
             ? value.value() >= reference.value()
             : value.value() <= reference.value();
}

// orientation aware "value is at least as good as the other"
[[nodiscard]] bool at_least_as_good(const MetricValue& value, const MetricValue& reference) noexcept {
  return describe_metric(value.kind()).orientation == MetricOrientation::LOWER_IS_BETTER
             ? value.value() <= reference.value()
             : value.value() >= reference.value();
}

}  // namespace

// ---------------------------------------------------------------------------
// Scope and target
// ---------------------------------------------------------------------------

bool PolicyScope::well_formed() const noexcept {
  if (!fabric.valid() || !name_space.valid()) {
    return false;
  }
  if (has_duplicate_ids(routes) || has_duplicate_ids(multipath_sets)) {
    return false;
  }
  return true;
}

bool PolicyScope::covers_route(const FabricId& fabric_id, const RoutingNamespace& namespace_id,
                               const std::optional<SiteId>& site_id,
                               const RouteId& route) const noexcept {
  if (fabric != fabric_id || name_space != namespace_id) {
    return false;
  }
  if (site.has_value()) {
    // A site-restricted scope covers a route only when the route's site is known
    // and identical. An unknown site never satisfies it: default deny.
    if (!site_id.has_value() || *site_id != *site) {
      return false;
    }
  }
  if (routes.empty()) {
    return true;
  }
  return std::find(routes.begin(), routes.end(), route) != routes.end();
}

bool PolicyScope::covers_multipath_set(const FabricId& fabric_id,
                                       const RoutingNamespace& namespace_id,
                                       const std::optional<SiteId>& site_id,
                                       const MultipathSetId& set_id) const noexcept {
  if (fabric != fabric_id || name_space != namespace_id) {
    return false;
  }
  if (site.has_value()) {
    if (!site_id.has_value() || *site_id != *site) {
      return false;
    }
  }
  if (multipath_sets.empty()) {
    return true;
  }
  return std::find(multipath_sets.begin(), multipath_sets.end(), set_id) != multipath_sets.end();
}

bool PolicyScope::covers_path_class(const PathClass& value) const noexcept {
  if (!path_class.valid()) {
    return true;
  }
  return value.valid() && value == path_class;
}

std::string PolicyScope::render() const {
  std::string text = "fabric=" + fabric.str() + " namespace=" + name_space.str();
  if (site.has_value()) {
    text += " site=" + site->str();
  }
  if (path_class.valid()) {
    text += " path_class=" + path_class.str();
  }
  text += " routes=";
  if (routes.empty()) {
    text += "*";
  } else {
    for (std::size_t index = 0; index < routes.size(); ++index) {
      if (index != 0) {
        text += ",";
      }
      text += routes[index].str();
    }
  }
  text += " multipath_sets=";
  if (multipath_sets.empty()) {
    text += "*";
  } else {
    for (std::size_t index = 0; index < multipath_sets.size(); ++index) {
      if (index != 0) {
        text += ",";
      }
      text += multipath_sets[index].str();
    }
  }
  return text;
}

std::string PolicyTarget::render() const {
  std::string text = "route=" + route.str();
  if (multipath_set.has_value()) {
    text += " multipath_set=" + multipath_set->str();
  }
  return text;
}

// ---------------------------------------------------------------------------
// Trigger rules
// ---------------------------------------------------------------------------

bool ThresholdRule::valid() const noexcept {
  if (!switch_value.valid() || !clear_value.valid()) {
    return false;
  }
  if (switch_value.kind() != kind || clear_value.kind() != kind) {
    return false;
  }
  if (!switch_value.comparable_with(clear_value)) {
    return false;
  }
  // The band must be non-degenerate and correctly oriented: the value that
  // clears the hysteresis must be strictly better than the value that enters it.
  if (at_least_as_good(switch_value, clear_value)) {
    return false;
  }
  return at_least_as_bad(switch_value, clear_value);
}

std::string ThresholdRule::render() const {
  std::string text = std::string(to_string(kind));
  text += " switch>=" + std::to_string(switch_value.valid() ? switch_value.value() : 0);
  text += " clear<=" + std::to_string(clear_value.valid() ? clear_value.value() : 0);
  return text;
}

bool ImprovementRule::valid() const noexcept {
  if (switch_improvement_bps > basis_points_scale ||
      reverse_improvement_bps > basis_points_scale) {
    return false;
  }
  // An improvement rule that requires nothing in either direction is not a
  // trigger; it is an omission expressed as a zero.
  return switch_improvement_bps != 0 || reverse_improvement_bps != 0;
}

std::string ImprovementRule::render() const {
  std::string text = std::string(to_string(kind));
  text += " switch_bps=" + std::to_string(switch_improvement_bps);
  text += " reverse_bps=" + std::to_string(reverse_improvement_bps);
  return text;
}

std::string HoldDownRule::render() const {
  return "duration_ms=" + std::to_string(duration / ticks_per_millisecond);
}

std::string CooldownRule::render() const {
  return "duration_ms=" + std::to_string(duration / ticks_per_millisecond);
}

bool DampeningRule::valid() const noexcept {
  if (!enabled) {
    // A disabled dampening must not carry active escalation parameters: a
    // half-configured policy is rejected rather than silently ignored.
    return penalty_increment == 0 && max_penalty == 0 && penalty_decay_interval == 0 &&
           penalty_decay_step == 0 && hold_down_escalation_step == 0 &&
           max_effective_hold_down == 0;
  }
  if (penalty_increment == 0 || max_penalty < penalty_increment) {
    return false;
  }
  if (penalty_decay_interval == 0 || penalty_decay_step == 0) {
    return false;
  }
  if (hold_down_escalation_step == 0 || max_effective_hold_down == 0) {
    return false;
  }
  return true;
}

std::string DampeningRule::render() const {
  if (!enabled) {
    return "disabled";
  }
  return "increment=" + std::to_string(penalty_increment) + " max_penalty=" +
         std::to_string(max_penalty) + " decay_ms=" +
         std::to_string(penalty_decay_interval / ticks_per_millisecond) + " decay_step=" +
         std::to_string(penalty_decay_step) + " escalation_ms=" +
         std::to_string(hold_down_escalation_step / ticks_per_millisecond) + " max_hold_down_ms=" +
         std::to_string(max_effective_hold_down / ticks_per_millisecond);
}

std::string ChurnBounds::render() const {
  if (!enabled()) {
    return "unbounded";
  }
  return "max_per_window=" + std::to_string(max_adaptations_per_window) + " window_ms=" +
         std::to_string(window / ticks_per_millisecond);
}

// ---------------------------------------------------------------------------
// Objective
// ---------------------------------------------------------------------------

std::string_view to_string(ObjectiveMode mode) noexcept {
  switch (mode) {
    case ObjectiveMode::LEXICOGRAPHIC:
      return "LEXICOGRAPHIC";
    case ObjectiveMode::WEIGHTED_SCORE:
      return "WEIGHTED_SCORE";
  }
  return "UNKNOWN";
}

std::optional<ObjectiveMode> parse_objective_mode(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 2; ++raw) {
    const auto mode = static_cast<ObjectiveMode>(raw);
    if (to_string(mode) == text) {
      return mode;
    }
  }
  return std::nullopt;
}

bool valid_objective_mode(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 2; }

bool ObjectiveSpec::valid() const noexcept {
  if (terms.empty()) {
    return false;
  }
  if (scoring_version != weighted_score_formula_version) {
    return false;
  }
  std::vector<MetricKind> kinds;
  kinds.reserve(terms.size());
  std::uint64_t weight_sum = 0;
  for (const auto& term : terms) {
    if (!valid_metric_kind(static_cast<std::uint8_t>(term.kind))) {
      return false;
    }
    kinds.push_back(term.kind);
    if (mode == ObjectiveMode::LEXICOGRAPHIC) {
      // Lexicographic comparison ignores weights; carrying one would be a
      // silently ignored field, so it is rejected instead.
      if (term.weight_bps != 0) {
        return false;
      }
    } else {
      if (term.weight_bps == 0 || term.weight_bps > basis_points_scale) {
        return false;
      }
      weight_sum += term.weight_bps;
    }
  }
  std::sort(kinds.begin(), kinds.end());
  if (std::adjacent_find(kinds.begin(), kinds.end()) != kinds.end()) {
    return false;
  }
  if (mode == ObjectiveMode::WEIGHTED_SCORE && weight_sum != basis_points_scale) {
    // Weights must be an exact decomposition of unity so that two policies with
    // the same intent always produce the same score.
    return false;
  }
  return true;
}

std::string ObjectiveSpec::render() const {
  std::string text = std::string(to_string(mode));
  text += "(v" + std::to_string(scoring_version) + ")";
  for (const auto& term : terms) {
    text += " ";
    text += std::string(to_string(term.kind));
    if (mode == ObjectiveMode::WEIGHTED_SCORE) {
      text += ":" + std::to_string(term.weight_bps);
    }
  }
  return text;
}

std::string EmergencyRule::render() const {
  if (!enabled) {
    return "disabled";
  }
  std::string text = "enabled(";
  bool first = true;
  const auto append = [&text, &first](const char* name) {
    if (!first) {
      text += ",";
    }
    text += name;
    first = false;
  };
  if (on_current_path_unauthorized) {
    append("unauthorized");
  }
  if (on_current_path_unavailable) {
    append("unavailable");
  }
  if (on_hard_failure_signal) {
    append("hard_failure");
  }
  text += ")";
  return text;
}

// ---------------------------------------------------------------------------
// Evidence requirements
// ---------------------------------------------------------------------------

bool EvidenceRequirement::valid() const noexcept {
  if (!valid_metric_kind(static_cast<std::uint8_t>(kind))) {
    return false;
  }
  if (!valid_aggregation_kind(static_cast<std::uint8_t>(aggregation))) {
    return false;
  }
  if (min_samples == 0) {
    return false;
  }
  // A freshness bound is mandatory. Zero is not "unbounded"; it is a missing
  // declaration, and a policy that omits it would let arbitrarily old evidence
  // trigger a routing change.
  if (max_age == 0) {
    return false;
  }
  if (aggregation == AggregationKind::EWMA) {
    if (ewma_alpha_bps == 0 || ewma_alpha_bps > basis_points_scale) {
      return false;
    }
  } else if (ewma_alpha_bps != 0) {
    return false;
  }
  if (!valid_evidence_quality(static_cast<std::uint8_t>(min_quality))) {
    return false;
  }
  return min_window <= max_age;
}

std::string EvidenceRequirement::render() const {
  std::string text = std::string(to_string(kind));
  text += " " + std::string(to_string(aggregation));
  if (aggregation == AggregationKind::EWMA) {
    text += ":" + std::to_string(ewma_alpha_bps);
  }
  text += " min_samples=" + std::to_string(min_samples);
  text += " max_age_ms=" + std::to_string(max_age / ticks_per_millisecond);
  text += " min_window_ms=" + std::to_string(min_window / ticks_per_millisecond);
  text += " min_quality=" + std::string(to_string(min_quality));
  text += required ? " required" : " optional";
  return text;
}

// ---------------------------------------------------------------------------
// Policy semantics
// ---------------------------------------------------------------------------

bool PolicySemantics::has_trigger() const noexcept {
  return !thresholds.empty() || !improvements.empty();
}

bool PolicySemantics::valid(std::string* reason) const {
  if (reason != nullptr) {
    reason->clear();
  }
  if (semantics_version != policy_semantics_version) {
    set_reason(reason, "unsupported policy semantics version");
    return false;
  }
  if (!target.well_formed()) {
    set_reason(reason, "policy target is not well formed");
    return false;
  }
  if (!has_trigger()) {
    set_reason(reason, "policy declares no trigger condition");
    return false;
  }
  for (const auto& rule : thresholds) {
    if (!rule.valid()) {
      set_reason(reason, "threshold rule is inverted, degenerate or incomparable");
      return false;
    }
  }
  for (const auto& rule : improvements) {
    if (!rule.valid()) {
      set_reason(reason, "improvement rule is out of range or requires nothing");
      return false;
    }
  }
  {
    std::vector<MetricKind> kinds;
    kinds.reserve(improvements.size());
    for (const auto& rule : improvements) {
      kinds.push_back(rule.kind);
    }
    std::sort(kinds.begin(), kinds.end());
    if (std::adjacent_find(kinds.begin(), kinds.end()) != kinds.end()) {
      set_reason(reason, "duplicate improvement rule for one metric");
      return false;
    }
  }
  {
    std::vector<MetricKind> kinds;
    kinds.reserve(thresholds.size());
    for (const auto& rule : thresholds) {
      kinds.push_back(rule.kind);
    }
    std::sort(kinds.begin(), kinds.end());
    if (std::adjacent_find(kinds.begin(), kinds.end()) != kinds.end()) {
      set_reason(reason, "duplicate threshold rule for one metric");
      return false;
    }
  }
  if (evidence.empty()) {
    set_reason(reason, "policy declares no evidence requirement");
    return false;
  }
  {
    std::vector<MetricKind> kinds;
    kinds.reserve(evidence.size());
    for (const auto& requirement : evidence) {
      if (!requirement.valid()) {
        set_reason(reason, "evidence requirement is malformed or lacks a freshness bound");
        return false;
      }
      kinds.push_back(requirement.kind);
    }
    std::sort(kinds.begin(), kinds.end());
    if (std::adjacent_find(kinds.begin(), kinds.end()) != kinds.end()) {
      set_reason(reason, "duplicate evidence requirement for one metric");
      return false;
    }
  }
  if (!dampening.valid()) {
    set_reason(reason, "dampening rule is not bounded or is partially configured");
    return false;
  }
  if (dampening.enabled && hold_down.duration == 0) {
    set_reason(reason, "dampening requires a non-zero base hold-down");
    return false;
  }
  if (dampening.enabled && dampening.max_effective_hold_down < hold_down.duration) {
    set_reason(reason, "dampening cap is below the base hold-down");
    return false;
  }
  if (!churn.valid()) {
    set_reason(reason, "churn bound has no window");
    return false;
  }
  if (!objective.valid()) {
    set_reason(reason, "objective specification is empty, duplicated or not normalized");
    return false;
  }
  if (!emergency.valid()) {
    set_reason(reason, "emergency override is enabled without a condition");
    return false;
  }
  {
    std::vector<PathId> paths;
    paths.reserve(priorities.size());
    for (const auto& entry : priorities) {
      if (!entry.path.valid()) {
        set_reason(reason, "candidate priority names an invalid path");
        return false;
      }
      paths.push_back(entry.path);
    }
    std::sort(paths.begin(), paths.end());
    if (std::adjacent_find(paths.begin(), paths.end()) != paths.end()) {
      set_reason(reason, "duplicate candidate priority for one path");
      return false;
    }
  }
  // Every metric named by a trigger or by the objective must have a declared
  // evidence requirement, otherwise the trigger could never be evaluated from
  // declared data.
  for (const auto& rule : improvements) {
    bool covered = false;
    for (const auto& requirement : evidence) {
      covered = covered || (requirement.kind == rule.kind);
    }
    if (!covered) {
      set_reason(reason, "improvement rule uses a metric with no evidence requirement");
      return false;
    }
  }
  for (const auto& rule : thresholds) {
    bool covered = false;
    for (const auto& requirement : evidence) {
      covered = covered || (requirement.kind == rule.kind);
    }
    if (!covered) {
      set_reason(reason, "threshold rule uses a metric with no evidence requirement");
      return false;
    }
  }
  for (const auto& term : objective.terms) {
    bool covered = false;
    for (const auto& requirement : evidence) {
      covered = covered || (requirement.kind == term.kind);
    }
    if (!covered) {
      set_reason(reason, "objective term uses a metric with no evidence requirement");
      return false;
    }
  }
  return true;
}

std::string PolicySemantics::render() const {
  std::string text = "semantics_version=" + std::to_string(semantics_version) + " target[";
  text += target.render();
  text += "]";
  for (const auto& rule : thresholds) {
    text += " threshold[" + rule.render() + "]";
  }
  for (const auto& rule : improvements) {
    text += " improvement[" + rule.render() + "]";
  }
  for (const auto& requirement : evidence) {
    text += " evidence[" + requirement.render() + "]";
  }
  text += " hold_down[" + hold_down.render() + "]";
  text += " cooldown[" + cooldown.render() + "]";
  text += " dampening[" + dampening.render() + "]";
  text += " churn[" + churn.render() + "]";
  text += " objective[" + objective.render() + "]";
  text += " emergency[" + emergency.render() + "]";
  for (const auto& entry : priorities) {
    text += " priority[" + entry.path.str() + "=" + std::to_string(entry.priority) + "]";
  }
  return text;
}

}  // namespace adaptive_routing

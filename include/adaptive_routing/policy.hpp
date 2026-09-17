// Adaptation policy: identity, scope, thresholds, hysteresis, hold-down,
// cooldown, dampening, churn bounds, objective semantics and lifecycle.
//
// A policy is a first-class governed object. Its identity is stable across
// ordinary mutation; change is expressed by advancing its generation. Every
// element of the semantics below is explicit: there is no implicit threshold,
// no hidden heuristic and no default that silently permits adaptation. A policy
// with no trigger condition can never adapt.
#ifndef ADAPTIVE_ROUTING_POLICY_HPP
#define ADAPTIVE_ROUTING_POLICY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/clock.hpp"
#include "adaptive_routing/evidence.hpp"
#include "adaptive_routing/ids.hpp"
#include "adaptive_routing/lifecycle.hpp"
#include "adaptive_routing/metrics.hpp"
#include "adaptive_routing/version.hpp"

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

// Adaptive scope. Default deny: a policy authorizes adaptation only inside the
// fabric and routing namespace it names, and only for the routes, multipath
// sets, site and path class it admits. An empty route list means "every route
// in this namespace"; it never means "every route everywhere".
struct PolicyScope {
  FabricId fabric;
  RoutingNamespace name_space;
  std::optional<SiteId> site;
  // Invalid means "any path class".
  PathClass path_class;
  std::vector<RouteId> routes;
  std::vector<MultipathSetId> multipath_sets;

  [[nodiscard]] bool well_formed() const noexcept;
  [[nodiscard]] bool covers_route(const FabricId& fabric_id, const RoutingNamespace& namespace_id,
                                  const std::optional<SiteId>& site_id,
                                  const RouteId& route) const noexcept;
  [[nodiscard]] bool covers_multipath_set(const FabricId& fabric_id,
                                          const RoutingNamespace& namespace_id,
                                          const std::optional<SiteId>& site_id,
                                          const MultipathSetId& set_id) const noexcept;
  [[nodiscard]] bool covers_path_class(const PathClass& value) const noexcept;
  [[nodiscard]] std::string render() const;
};

// What a policy adapts. Adaptive Routing Fabric deliberately supports one route
// per policy: bounding the blast radius is a correctness property, not a
// limitation to be worked around. Wider change is expressed by more policies,
// each independently authorized, and by Route Convergence downstream.
struct PolicyTarget {
  RouteId route;
  std::optional<MultipathSetId> multipath_set;

  [[nodiscard]] bool well_formed() const noexcept { return route.valid(); }
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Trigger conditions
// ---------------------------------------------------------------------------

// Band threshold with explicit hysteresis.
//
// Semantics, orientation aware:
//   * the current preferred path may be left in the ordinary direction only
//     when its value for this metric is at least as bad as \c switch_value;
//   * a candidate may be entered only when its value for this metric is at
//     least as good as \c clear_value.
//
// For a LOWER_IS_BETTER metric "at least as bad" means value >= switch_value and
// "at least as good" means value <= clear_value, so a well formed band requires
// clear_value < switch_value. The reverse holds for HIGHER_IS_BETTER. An
// inverted or degenerate band is rejected as INVALID_HYSTERESIS.
struct ThresholdRule {
  MetricKind kind = MetricKind::PATH_UTILIZATION;
  MetricValue switch_value;
  MetricValue clear_value;

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::string render() const;
};

// Explicit relative improvement rule.
//
//   switch_improvement_bps  a candidate must beat the current preferred path by
//                           at least this many basis points to take over;
//   reverse_improvement_bps a candidate that is the *previous* preference must
//                           beat the current preferred path by at least this
//                           many basis points to be restored.
//
// The asymmetric reverse requirement is what makes A -> B -> A oscillation
// strictly harder than the original A -> B move.
struct ImprovementRule {
  MetricKind kind = MetricKind::PATH_LATENCY;
  std::uint32_t switch_improvement_bps = 0;
  std::uint32_t reverse_improvement_bps = 0;

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::string render() const;
};

// Hold-down: after a committed adaptation, an ordinary reverse adaptation is
// suppressed. This is not implicit; a duration of zero disables it.
struct HoldDownRule {
  Ticks duration = 0;
  [[nodiscard]] bool enabled() const noexcept { return duration != 0; }
  [[nodiscard]] std::string render() const;
};

// Cooldown: after a committed adaptation, no new non-emergency adaptation of any
// direction is accepted for the interval. Hold-down forbids the *reverse*
// direction; cooldown forbids *any* ordinary direction. They are distinct and
// independently configured.
struct CooldownRule {
  Ticks duration = 0;
  [[nodiscard]] bool enabled() const noexcept { return duration != 0; }
  [[nodiscard]] std::string render() const;
};

// Bounded dampening. Repeated oscillation raises an integer penalty that decays
// deterministically in fixed steps and extends the effective hold-down, capped
// by max_effective_hold_down. There is no unbounded hidden state: the penalty is
// bounded by max_penalty and the extension by max_effective_hold_down.
//
//   effective_hold_down = min(duration + penalty * hold_down_escalation_step,
//                             max_effective_hold_down)
struct DampeningRule {
  bool enabled = false;
  std::uint32_t penalty_increment = 0;
  std::uint32_t max_penalty = 0;
  Ticks penalty_decay_interval = 0;
  std::uint32_t penalty_decay_step = 0;
  Ticks hold_down_escalation_step = 0;
  Ticks max_effective_hold_down = 0;

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::string render() const;
};

// Bounded churn. A zero max_adaptations_per_window disables the bound, which is
// expressed explicitly rather than implied by an omitted field.
struct ChurnBounds {
  std::uint32_t max_adaptations_per_window = 0;
  Ticks window = 0;

  [[nodiscard]] bool enabled() const noexcept { return max_adaptations_per_window != 0; }
  [[nodiscard]] bool valid() const noexcept { return !enabled() || window != 0; }
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Objective semantics
// ---------------------------------------------------------------------------

enum class ObjectiveMode : std::uint8_t {
  // Terms are compared in declaration order; the first term that differs
  // decides. This is the "legality, health, loss, latency, utilization"
  // lexicographic form.
  LEXICOGRAPHIC = 1,
  // Terms are combined into one deterministic fixed-point score.
  WEIGHTED_SCORE = 2,
};

[[nodiscard]] std::string_view to_string(ObjectiveMode mode) noexcept;
[[nodiscard]] std::optional<ObjectiveMode> parse_objective_mode(std::string_view text) noexcept;
[[nodiscard]] bool valid_objective_mode(std::uint8_t raw) noexcept;

struct ObjectiveTerm {
  MetricKind kind = MetricKind::PATH_LATENCY;
  // Consulted only in WEIGHTED_SCORE mode; ignored, and required to be zero, in
  // LEXICOGRAPHIC mode.
  std::uint32_t weight_bps = 0;
};

struct ObjectiveSpec {
  ObjectiveMode mode = ObjectiveMode::LEXICOGRAPHIC;
  std::vector<ObjectiveTerm> terms;
  // Bound by every decision and by every digest. Changing the scoring formula
  // requires a different value, so two decisions produced by different formulas
  // never compare as identical authority.
  std::uint32_t scoring_version = weighted_score_formula_version;

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::string render() const;
};

// Explicit per-candidate policy priority. Higher wins. Priority is the first
// ranking key ahead of evidence quality and the objective, exactly as declared
// by Deterministic decision order in the documentation.
struct CandidatePriority {
  PathId path;
  std::uint32_t priority = 0;
};

// Emergency conditions. Emergency adaptation may bypass ordinary hysteresis,
// hold-down and cooldown only when explicitly enabled here. It never bypasses
// Path Authority, Multipath membership, scope, lifecycle or churn bounds.
struct EmergencyRule {
  bool enabled = false;
  bool on_current_path_unauthorized = false;
  bool on_current_path_unavailable = false;
  bool on_hard_failure_signal = false;

  [[nodiscard]] bool valid() const noexcept {
    return !enabled ||
           (on_current_path_unauthorized || on_current_path_unavailable || on_hard_failure_signal);
  }
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Policy semantics
// ---------------------------------------------------------------------------

struct PolicySemantics {
  // The semantics version the policy was authored under. A policy carrying a
  // version this runtime does not implement is rejected unread.
  std::uint32_t semantics_version = policy_semantics_version;
  PolicyTarget target;
  std::vector<ThresholdRule> thresholds;
  std::vector<ImprovementRule> improvements;
  std::vector<EvidenceRequirement> evidence;
  HoldDownRule hold_down;
  CooldownRule cooldown;
  DampeningRule dampening;
  ChurnBounds churn;
  ObjectiveSpec objective;
  EmergencyRule emergency;
  std::vector<CandidatePriority> priorities;

  // Structural validation of everything above. A malformed policy is rejected
  // at create/update time, never at evaluation time.
  [[nodiscard]] bool valid(std::string* reason) const;

  // True when the policy declares at least one trigger condition. A policy with
  // no trigger can never adapt and is rejected rather than being accepted and
  // silently doing nothing.
  [[nodiscard]] bool has_trigger() const noexcept;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

struct AdaptivePolicy {
  AdaptivePolicyId id;
  AdaptivePolicyName name;
  PolicyScope scope;
  PolicySemantics semantics;
  AdaptivePolicyGeneration generation;
  PolicyLifecycle lifecycle = PolicyLifecycle::DECLARED;
  CoordinatorEpoch epoch;
  PublisherId owner;
  AdaptiveAuthorityGeneration authority_generation;
  Ticks declared_at = 0;
  Ticks updated_at = 0;

  [[nodiscard]] bool well_formed() const noexcept {
    return id.valid() && name.valid() && scope.well_formed() && semantics.target.well_formed() &&
           generation.valid() && epoch.valid() && owner.valid();
  }
};

// ---------------------------------------------------------------------------
// Policy edit description
// ---------------------------------------------------------------------------

// A policy update replaces the whole semantics value. A partial patch is not
// supported on purpose: "what changed" must be answerable by comparing two
// complete generations, and every generation boundary is a semantic boundary.
struct PolicyUpdate {
  PolicyScope scope;
  PolicySemantics semantics;
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_POLICY_HPP

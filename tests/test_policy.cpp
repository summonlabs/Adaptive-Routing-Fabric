// Policy semantics validation, objective specification and engine rejection.
//
// A policy is the only place where adaptation authority is authored, so every
// structural defect below must be rejected at create time rather than being
// discovered during an evaluation. Each negative case is paired with the reason
// the validator must give, which keeps the assertions specific: a policy that
// fails for the wrong reason does not pass.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/adaptive_routing.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace arf_test;
using namespace adaptive_routing;

// Local requirement builder. These scenarios drive one validator field at a
// time (aggregation, alpha, sample count, freshness window, requiredness), so
// every field is stated explicitly rather than inherited from a helper default.
[[nodiscard]] EvidenceRequirement utilization_requirement_local(
    AggregationKind aggregation = AggregationKind::MEAN, std::uint32_t alpha = 0,
    std::uint32_t min_samples = 1, Ticks max_age = seconds(120), Ticks min_window = 0,
    bool required = true) {
  EvidenceRequirement requirement;
  requirement.kind = MetricKind::PATH_UTILIZATION;
  requirement.aggregation = aggregation;
  requirement.ewma_alpha_bps = alpha;
  requirement.min_samples = min_samples;
  requirement.max_age = max_age;
  requirement.min_window = min_window;
  requirement.min_quality = EvidenceQuality::AGGREGATED;
  requirement.required = required;
  return requirement;
}

[[nodiscard]] EvidenceRequirement latency_requirement_local(
    AggregationKind aggregation = AggregationKind::MEAN, std::uint32_t alpha = 0,
    std::uint32_t min_samples = 1, Ticks max_age = seconds(120), Ticks min_window = 0) {
  EvidenceRequirement requirement = utilization_requirement_local(
      aggregation, alpha, min_samples, max_age, min_window, true);
  requirement.kind = MetricKind::PATH_LATENCY;
  return requirement;
}

[[nodiscard]] MetricValue metric(MetricKind kind, std::int64_t value) {
  const auto made = MetricValue::make(kind, value);
  ARF_CHECK_MSG(made.has_value(), "test metric must be in range: " << to_string(kind));
  return made.value_or(MetricValue{});
}

// A band policy: leave the current preference above switch_value utilisation and
// enter a candidate below clear_value.
[[nodiscard]] PolicySemantics band_policy(std::int64_t switch_value, std::int64_t clear_value) {
  PolicySemantics semantics;
  semantics.target.route = route_id();
  ThresholdRule rule;
  rule.kind = MetricKind::PATH_UTILIZATION;
  rule.switch_value = metric(MetricKind::PATH_UTILIZATION, switch_value);
  rule.clear_value = metric(MetricKind::PATH_UTILIZATION, clear_value);
  semantics.thresholds.push_back(rule);
  semantics.evidence.push_back(utilization_requirement_local());
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = MetricKind::PATH_UTILIZATION;
  objective.terms.push_back(term);
  semantics.objective = objective;
  return semantics;
}

[[nodiscard]] PolicySemantics improvement_policy(std::uint32_t switch_bps,
                                                 std::uint32_t reverse_bps) {
  PolicySemantics semantics;
  semantics.target.route = route_id();
  ImprovementRule rule;
  rule.kind = MetricKind::PATH_LATENCY;
  rule.switch_improvement_bps = switch_bps;
  rule.reverse_improvement_bps = reverse_bps;
  semantics.improvements.push_back(rule);
  semantics.evidence.push_back(latency_requirement_local());
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = MetricKind::PATH_LATENCY;
  objective.terms.push_back(term);
  semantics.objective = objective;
  return semantics;
}

// A two-metric weighted policy, used for the weight-normalisation rules.
[[nodiscard]] PolicySemantics weighted_policy(std::uint32_t utilization_weight,
                                              std::uint32_t latency_weight) {
  PolicySemantics semantics;
  semantics.target.route = route_id();
  ImprovementRule rule;
  rule.kind = MetricKind::PATH_UTILIZATION;
  rule.switch_improvement_bps = 1000;
  rule.reverse_improvement_bps = 1000;
  semantics.improvements.push_back(rule);
  semantics.evidence.push_back(utilization_requirement_local());
  semantics.evidence.push_back(latency_requirement_local());
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::WEIGHTED_SCORE;
  ObjectiveTerm utilization_term;
  utilization_term.kind = MetricKind::PATH_UTILIZATION;
  utilization_term.weight_bps = utilization_weight;
  ObjectiveTerm latency_term;
  latency_term.kind = MetricKind::PATH_LATENCY;
  latency_term.weight_bps = latency_weight;
  objective.terms.push_back(utilization_term);
  objective.terms.push_back(latency_term);
  semantics.objective = objective;
  return semantics;
}

[[nodiscard]] DampeningRule bounded_dampening() {
  DampeningRule dampening;
  dampening.enabled = true;
  dampening.penalty_increment = 1;
  dampening.max_penalty = 4;
  dampening.penalty_decay_interval = seconds(30);
  dampening.penalty_decay_step = 1;
  dampening.hold_down_escalation_step = seconds(1);
  dampening.max_effective_hold_down = seconds(10);
  return dampening;
}

void check_rejected(const PolicySemantics& semantics, const char* expected_reason) {
  std::string reason;
  const bool valid = semantics.valid(&reason);
  ARF_CHECK_MSG(!valid, "expected a rejection (looking for [" << expected_reason << "])");
  if (!valid) {
    ARF_CHECK_MSG(reason.find(expected_reason) != std::string::npos,
                  "rejection reason [" << reason << "] does not mention [" << expected_reason
                                       << "]");
  }
}

void check_accepted(const PolicySemantics& semantics) {
  std::string reason;
  const bool valid = semantics.valid(&reason);
  ARF_CHECK_MSG(valid, "expected acceptance but the policy was rejected: " << reason);
}

}  // namespace

ARF_TEST(policy_semantics_accepts_the_documented_shapes) {
  // Positive controls: the negative cases below are only meaningful while these
  // two shapes are accepted.
  check_accepted(band_policy(8000, 2000));
  check_accepted(improvement_policy(1000, 1000));
  check_accepted(improvement_policy(10000, 0));
  check_accepted(weighted_policy(6000, 4000));
  check_accepted(weighted_policy(9999, 1));

  PolicySemantics semantics = band_policy(8000, 2000);
  ARF_CHECK(semantics.has_trigger());
  ARF_CHECK_EQ(semantics.semantics_version, policy_semantics_version);
  semantics.hold_down.duration = seconds(5);
  semantics.cooldown.duration = seconds(2);
  check_accepted(semantics);
  semantics.dampening = bounded_dampening();
  check_accepted(semantics);
  semantics.churn.max_adaptations_per_window = 4;
  semantics.churn.window = seconds(60);
  check_accepted(semantics);
  semantics.emergency.enabled = true;
  semantics.emergency.on_current_path_unavailable = true;
  check_accepted(semantics);
  CandidatePriority priority;
  priority.path = path("path-a");
  priority.priority = 7;
  semantics.priorities.push_back(priority);
  check_accepted(semantics);
  // An optional requirement is a legitimate declaration.
  semantics.evidence.push_back(latency_requirement_local());
  semantics.evidence.back().required = false;
  check_accepted(semantics);
}

ARF_TEST(policy_semantics_rejects_structural_defects) {
  PolicySemantics unsupported_version = band_policy(8000, 2000);
  unsupported_version.semantics_version = policy_semantics_version + 1;
  check_rejected(unsupported_version, "unsupported policy semantics version");

  PolicySemantics no_trigger = band_policy(8000, 2000);
  no_trigger.thresholds.clear();
  check_rejected(no_trigger, "no trigger condition");

  PolicySemantics no_target = band_policy(8000, 2000);
  no_target.target.route = RouteId();
  check_rejected(no_target, "target");

  PolicySemantics no_evidence = band_policy(8000, 2000);
  no_evidence.evidence.clear();
  check_rejected(no_evidence, "no evidence requirement");

  // Duplicate declarations for one metric are ambiguous, not additive.
  PolicySemantics duplicate_improvement = improvement_policy(1000, 1000);
  duplicate_improvement.improvements.push_back(duplicate_improvement.improvements.front());
  check_rejected(duplicate_improvement, "duplicate improvement rule");

  PolicySemantics duplicate_threshold = band_policy(8000, 2000);
  duplicate_threshold.thresholds.push_back(duplicate_threshold.thresholds.front());
  check_rejected(duplicate_threshold, "duplicate threshold rule");

  PolicySemantics duplicate_evidence = band_policy(8000, 2000);
  duplicate_evidence.evidence.push_back(duplicate_evidence.evidence.front());
  check_rejected(duplicate_evidence, "duplicate evidence requirement");

  PolicySemantics invalid_priority_path = band_policy(8000, 2000);
  CandidatePriority nameless;
  nameless.priority = 1;
  invalid_priority_path.priorities.push_back(nameless);
  check_rejected(invalid_priority_path, "invalid path");

  PolicySemantics duplicate_priority = band_policy(8000, 2000);
  CandidatePriority first;
  first.path = path("path-a");
  first.priority = 1;
  CandidatePriority second = first;
  second.priority = 2;
  duplicate_priority.priorities.push_back(first);
  duplicate_priority.priorities.push_back(second);
  check_rejected(duplicate_priority, "duplicate candidate priority");
}

ARF_TEST(policy_semantics_rejects_bad_hysteresis_bands) {
  // Inverted: a lower-is-better band must clear below where it switches.
  check_rejected(band_policy(2000, 8000), "inverted, degenerate or incomparable");
  // Degenerate: the two edges coincide, so there is no hysteresis at all.
  check_rejected(band_policy(5000, 5000), "inverted, degenerate or incomparable");
  check_rejected(band_policy(0, 0), "inverted, degenerate or incomparable");
  check_rejected(band_policy(10000, 10000), "inverted, degenerate or incomparable");
  // One step of separation is a valid band.
  check_accepted(band_policy(8000, 7999));

  // A threshold rule with no declared evidence can never be evaluated.
  PolicySemantics uncovered = band_policy(8000, 2000);
  uncovered.evidence.clear();
  uncovered.evidence.push_back(latency_requirement_local());
  uncovered.objective.terms.front().kind = MetricKind::PATH_LATENCY;
  check_rejected(uncovered, "threshold rule uses a metric with no evidence requirement");
}

ARF_TEST(policy_semantics_rejects_bad_improvement_rules) {
  // An improvement rule that requires nothing in either direction is an
  // omission expressed as a zero, not a trigger.
  check_rejected(improvement_policy(0, 0), "requires nothing");
  // Both directions are bounded by the unity scale.
  check_rejected(improvement_policy(10001, 0), "out of range");
  check_rejected(improvement_policy(0, 10001), "out of range");
  check_accepted(improvement_policy(10000, 10000));
  check_accepted(improvement_policy(0, 1000));

  PolicySemantics uncovered = improvement_policy(1000, 1000);
  uncovered.evidence.clear();
  uncovered.evidence.push_back(utilization_requirement_local());
  uncovered.objective.terms.front().kind = MetricKind::PATH_UTILIZATION;
  check_rejected(uncovered, "improvement rule uses a metric with no evidence requirement");
}

ARF_TEST(policy_semantics_rejects_malformed_evidence_requirements) {
  // A freshness bound is mandatory: zero is a missing declaration, not
  // "unbounded".
  PolicySemantics no_age = band_policy(8000, 2000);
  no_age.evidence.front().max_age = 0;
  check_rejected(no_age, "freshness bound");

  // A window longer than the freshness bound could never be satisfied.
  PolicySemantics window_beyond_age = band_policy(8000, 2000);
  window_beyond_age.evidence.front().max_age = seconds(120);
  window_beyond_age.evidence.front().min_window = seconds(121);
  check_rejected(window_beyond_age, "freshness bound");
  PolicySemantics window_at_age = band_policy(8000, 2000);
  window_at_age.evidence.front().min_window = window_at_age.evidence.front().max_age;
  check_accepted(window_at_age);

  // Zero samples is not a requirement.
  PolicySemantics no_samples = band_policy(8000, 2000);
  no_samples.evidence.front().min_samples = 0;
  check_rejected(no_samples, "freshness bound");

  // EWMA alpha is consulted only by EWMA, and then must be in (0, 10000].
  PolicySemantics ewma_zero = band_policy(8000, 2000);
  ewma_zero.evidence.front().aggregation = AggregationKind::EWMA;
  ewma_zero.evidence.front().ewma_alpha_bps = 0;
  check_rejected(ewma_zero, "freshness bound");
  PolicySemantics ewma_oversized = band_policy(8000, 2000);
  ewma_oversized.evidence.front().aggregation = AggregationKind::EWMA;
  ewma_oversized.evidence.front().ewma_alpha_bps = basis_points_scale + 1;
  check_rejected(ewma_oversized, "freshness bound");
  PolicySemantics ewma_full = band_policy(8000, 2000);
  ewma_full.evidence.front().aggregation = AggregationKind::EWMA;
  ewma_full.evidence.front().ewma_alpha_bps = basis_points_scale;
  check_accepted(ewma_full);
  PolicySemantics ewma_slow = band_policy(8000, 2000);
  ewma_slow.evidence.front().aggregation = AggregationKind::EWMA;
  ewma_slow.evidence.front().ewma_alpha_bps = 1;
  check_accepted(ewma_slow);

  // A non-EWMA aggregation carrying an EWMA alpha is a half-configured
  // requirement whose alpha would be silently ignored.
  PolicySemantics stray_alpha = band_policy(8000, 2000);
  stray_alpha.evidence.front().ewma_alpha_bps = 2500;
  check_rejected(stray_alpha, "freshness bound");

  PolicySemantics unknown_quality = band_policy(8000, 2000);
  unknown_quality.evidence.front().min_quality =
      static_cast<EvidenceQuality>(static_cast<std::uint8_t>(9));
  check_rejected(unknown_quality, "freshness bound");
}

ARF_TEST(objective_spec_rejects_unscorable_declarations) {
  PolicySemantics empty_terms = band_policy(8000, 2000);
  empty_terms.objective.terms.clear();
  check_rejected(empty_terms, "objective specification");

  PolicySemantics duplicate_terms = band_policy(8000, 2000);
  duplicate_terms.objective.terms.push_back(duplicate_terms.objective.terms.front());
  check_rejected(duplicate_terms, "objective specification");

  // Lexicographic comparison ignores weights, so a weight there is a silently
  // ignored field.
  PolicySemantics lexicographic_weight = band_policy(8000, 2000);
  lexicographic_weight.objective.terms.front().weight_bps = 1;
  check_rejected(lexicographic_weight, "objective specification");

  // Weighted scoring requires an exact decomposition of unity.
  check_rejected(weighted_policy(6000, 3000), "objective specification");
  check_rejected(weighted_policy(10001, 0), "objective specification");
  check_rejected(weighted_policy(5000, 5001), "objective specification");
  check_rejected(weighted_policy(0, 10000), "objective specification");
  check_rejected(weighted_policy(10000, 0), "objective specification");
  check_accepted(weighted_policy(4000, 6000));
  check_accepted(weighted_policy(1, 9999));

  // The scoring formula is part of the decision's identity, so an unknown
  // version cannot be interpreted.
  PolicySemantics unknown_scoring = band_policy(8000, 2000);
  unknown_scoring.objective.scoring_version = weighted_score_formula_version + 1;
  check_rejected(unknown_scoring, "objective specification");

  // An objective term with no declared evidence can never be computed.
  PolicySemantics uncovered_term = improvement_policy(1000, 1000);
  uncovered_term.objective.terms.front().kind = MetricKind::PATH_UTILIZATION;
  check_rejected(uncovered_term, "objective term uses a metric with no evidence requirement");
}

ARF_TEST(policy_semantics_rejects_malformed_dampening) {
  // A zero increment can never raise the penalty.
  PolicySemantics zero_increment = band_policy(8000, 2000);
  zero_increment.hold_down.duration = seconds(5);
  zero_increment.dampening = bounded_dampening();
  zero_increment.dampening.penalty_increment = 0;
  check_rejected(zero_increment, "dampening");

  // A cap below the increment could never be reached by one escalation.
  PolicySemantics cap_below_increment = band_policy(8000, 2000);
  cap_below_increment.hold_down.duration = seconds(5);
  cap_below_increment.dampening = bounded_dampening();
  cap_below_increment.dampening.penalty_increment = 3;
  cap_below_increment.dampening.max_penalty = 2;
  check_rejected(cap_below_increment, "dampening");

  // Decay is defined by an interval and a step; either one at zero leaves the
  // penalty with no way down.
  PolicySemantics no_decay_interval = band_policy(8000, 2000);
  no_decay_interval.hold_down.duration = seconds(5);
  no_decay_interval.dampening = bounded_dampening();
  no_decay_interval.dampening.penalty_decay_interval = 0;
  check_rejected(no_decay_interval, "dampening");

  PolicySemantics no_decay_step = band_policy(8000, 2000);
  no_decay_step.hold_down.duration = seconds(5);
  no_decay_step.dampening = bounded_dampening();
  no_decay_step.dampening.penalty_decay_step = 0;
  check_rejected(no_decay_step, "dampening");

  // Escalation and its cap define the effective hold-down.
  PolicySemantics no_escalation = band_policy(8000, 2000);
  no_escalation.hold_down.duration = seconds(5);
  no_escalation.dampening = bounded_dampening();
  no_escalation.dampening.hold_down_escalation_step = 0;
  check_rejected(no_escalation, "dampening");

  PolicySemantics no_cap = band_policy(8000, 2000);
  no_cap.hold_down.duration = seconds(5);
  no_cap.dampening = bounded_dampening();
  no_cap.dampening.max_effective_hold_down = 0;
  check_rejected(no_cap, "dampening");

  // A cap below the base hold-down would shorten an interval the policy already
  // promised.
  PolicySemantics cap_below_hold_down = band_policy(8000, 2000);
  cap_below_hold_down.hold_down.duration = seconds(5);
  cap_below_hold_down.dampening = bounded_dampening();
  cap_below_hold_down.dampening.max_effective_hold_down = seconds(2);
  check_rejected(cap_below_hold_down, "cap is below the base hold-down");

  // Dampening extends a hold-down; with no base hold-down there is nothing to
  // extend.
  PolicySemantics no_base_hold_down = band_policy(8000, 2000);
  no_base_hold_down.hold_down.duration = 0;
  no_base_hold_down.dampening = bounded_dampening();
  check_rejected(no_base_hold_down, "non-zero base hold-down");

  // Disabled dampening must not carry escalation parameters: a half-configured
  // policy is rejected rather than silently ignored.
  PolicySemantics disabled_with_parameters = band_policy(8000, 2000);
  disabled_with_parameters.dampening = bounded_dampening();
  disabled_with_parameters.dampening.enabled = false;
  check_rejected(disabled_with_parameters, "partially configured");
  PolicySemantics disabled_with_cap_only = band_policy(8000, 2000);
  disabled_with_cap_only.dampening.max_effective_hold_down = seconds(1);
  check_rejected(disabled_with_cap_only, "partially configured");
  PolicySemantics disabled_clean = band_policy(8000, 2000);
  check_accepted(disabled_clean);

  // The dampening cap must also stay inside the configured structural bound.
  PolicySemantics dampening_with_hold_down = band_policy(8000, 2000);
  dampening_with_hold_down.hold_down.duration = seconds(5);
  dampening_with_hold_down.dampening = bounded_dampening();
  check_accepted(dampening_with_hold_down);
}

ARF_TEST(policy_semantics_rejects_unbounded_churn_and_emergency) {
  // A churn bound without a window has no interval to count within.
  PolicySemantics no_window = band_policy(8000, 2000);
  no_window.churn.max_adaptations_per_window = 4;
  no_window.churn.window = 0;
  check_rejected(no_window, "churn bound");
  PolicySemantics bounded = band_policy(8000, 2000);
  bounded.churn.max_adaptations_per_window = 4;
  bounded.churn.window = seconds(60);
  check_accepted(bounded);
  // A window without a bound is inert: the bound is the enabling field.
  PolicySemantics window_only = band_policy(8000, 2000);
  window_only.churn.window = seconds(60);
  check_accepted(window_only);

  // Emergency adaptation never happens implicitly.
  PolicySemantics emergency = band_policy(8000, 2000);
  emergency.emergency.enabled = true;
  check_rejected(emergency, "emergency");
  emergency.emergency.on_hard_failure_signal = true;
  check_accepted(emergency);
  emergency.emergency.enabled = false;
  emergency.emergency.on_hard_failure_signal = false;
  check_accepted(emergency);
}

ARF_TEST(engine_classifies_policy_rejections) {
  Harness harness = make_harness();

  // A defective hysteresis band is specifically INVALID_HYSTERESIS rather than a
  // generic malformed request.
  const OperationResult inverted = create_policy(harness, band_policy(2000, 8000),
                                                 harness.next_policy_name(), harness.context());
  ARF_CHECK_EQ(inverted.outcome, Outcome::INVALID_HYSTERESIS);
  ARF_CHECK_MSG(inverted.detail.find("inverted") != std::string::npos,
                "expected the band defect to be named: " << inverted.detail);
  const OperationResult degenerate = create_policy(harness, band_policy(5000, 5000),
                                                   harness.next_policy_name(), harness.context());
  ARF_CHECK_EQ(degenerate.outcome, Outcome::INVALID_HYSTERESIS);
  // Any rejection whose reason names a threshold is classified the same way.
  PolicySemantics duplicate_threshold = band_policy(8000, 2000);
  duplicate_threshold.thresholds.push_back(duplicate_threshold.thresholds.front());
  const OperationResult duplicated = create_policy(harness, duplicate_threshold,
                                                   harness.next_policy_name(), harness.context());
  ARF_CHECK_EQ(duplicated.outcome, Outcome::INVALID_HYSTERESIS);

  // Everything else is a malformed request.
  std::vector<PolicySemantics> malformed;
  PolicySemantics unsupported_version = band_policy(8000, 2000);
  unsupported_version.semantics_version = policy_semantics_version + 1;
  malformed.push_back(unsupported_version);
  PolicySemantics no_trigger = band_policy(8000, 2000);
  no_trigger.thresholds.clear();
  malformed.push_back(no_trigger);
  malformed.push_back(improvement_policy(0, 0));
  malformed.push_back(improvement_policy(10001, 0));
  PolicySemantics no_evidence = band_policy(8000, 2000);
  no_evidence.evidence.clear();
  malformed.push_back(no_evidence);
  PolicySemantics no_age = band_policy(8000, 2000);
  no_age.evidence.front().max_age = 0;
  malformed.push_back(no_age);
  PolicySemantics window_beyond_age = band_policy(8000, 2000);
  window_beyond_age.evidence.front().min_window = seconds(121);
  malformed.push_back(window_beyond_age);
  PolicySemantics stray_alpha = band_policy(8000, 2000);
  stray_alpha.evidence.front().ewma_alpha_bps = 2500;
  malformed.push_back(stray_alpha);
  PolicySemantics ewma_zero = band_policy(8000, 2000);
  ewma_zero.evidence.front().aggregation = AggregationKind::EWMA;
  ewma_zero.evidence.front().ewma_alpha_bps = 0;
  malformed.push_back(ewma_zero);
  PolicySemantics empty_objective = band_policy(8000, 2000);
  empty_objective.objective.terms.clear();
  malformed.push_back(empty_objective);
  PolicySemantics unknown_scoring = band_policy(8000, 2000);
  unknown_scoring.objective.scoring_version = weighted_score_formula_version + 1;
  malformed.push_back(unknown_scoring);
  malformed.push_back(weighted_policy(6000, 3000));
  PolicySemantics uncovered_term = improvement_policy(1000, 1000);
  uncovered_term.objective.terms.front().kind = MetricKind::PATH_UTILIZATION;
  malformed.push_back(uncovered_term);
  PolicySemantics no_base_hold_down = band_policy(8000, 2000);
  no_base_hold_down.dampening = bounded_dampening();
  malformed.push_back(no_base_hold_down);
  PolicySemantics disabled_with_parameters = band_policy(8000, 2000);
  disabled_with_parameters.dampening = bounded_dampening();
  disabled_with_parameters.dampening.enabled = false;
  malformed.push_back(disabled_with_parameters);
  PolicySemantics no_window = band_policy(8000, 2000);
  no_window.churn.max_adaptations_per_window = 4;
  malformed.push_back(no_window);
  PolicySemantics emergency = band_policy(8000, 2000);
  emergency.emergency.enabled = true;
  malformed.push_back(emergency);

  for (const PolicySemantics& semantics : malformed) {
    const OperationResult rejected =
        create_policy(harness, semantics, harness.next_policy_name(), harness.context());
    ARF_CHECK_MSG(rejected.outcome == Outcome::MALFORMED_REQUEST, rejected.render());
    ARF_CHECK_MSG(!rejected.detail.empty(), "a rejection always names its reason");
    ARF_CHECK_MSG(!rejected.mutated, "a rejected policy is never created");
  }
  // Not one of the rejections above left a policy behind.
  ARF_CHECK_EQ(harness.fabric->stats().policies, 0ULL);
  ARF_CHECK_EQ(harness.fabric->list_policies().size(), static_cast<std::size_t>(0));

  // The same harness still accepts a well formed policy, so the rejections are
  // about the defects and not about the fixture.
  const OperationResult accepted = create_policy(harness, band_policy(8000, 2000),
                                                 harness.next_policy_name(), harness.context());
  ARF_CHECK_MSG(accepted.outcome == Outcome::POLICY_CREATED, accepted.render());
  ARF_CHECK_EQ(harness.fabric->stats().policies, 1ULL);
}

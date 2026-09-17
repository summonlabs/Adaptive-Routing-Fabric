// Lifecycle, currentness and transition-table contracts.
//
// The transition tables are the runtime's spine: a state that quietly accepts
// an event it should refuse is how a revoked policy comes back to life. The
// expectations below are written out pair by pair so that a widened table fails
// the suite instead of silently passing it.
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/adaptive_routing.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace arf_test;
using namespace adaptive_routing;

[[nodiscard]] std::string render_policy_lifecycle(std::optional<PolicyLifecycle> value) {
  return value.has_value() ? std::string(to_string(*value)) : std::string("<undefined>");
}

[[nodiscard]] std::string render_decision_lifecycle(std::optional<DecisionLifecycle> value) {
  return value.has_value() ? std::string(to_string(*value)) : std::string("<undefined>");
}

// The complete 7x8 policy table, restated independently of the implementation.
[[nodiscard]] std::optional<PolicyLifecycle> expected_policy_transition(PolicyLifecycle state,
                                                                       PolicyEvent event) {
  switch (state) {
    case PolicyLifecycle::DECLARED:
      if (event == PolicyEvent::ACTIVATE) return PolicyLifecycle::ACTIVE;
      if (event == PolicyEvent::REQUIRE_REVALIDATION) return PolicyLifecycle::REVALIDATION_REQUIRED;
      if (event == PolicyEvent::REVOKE) return PolicyLifecycle::REVOKED;
      if (event == PolicyEvent::SUPERSEDE) return PolicyLifecycle::SUPERSEDED;
      if (event == PolicyEvent::RETIRE) return PolicyLifecycle::RETIRED;
      return std::nullopt;
    case PolicyLifecycle::ACTIVE:
      if (event == PolicyEvent::SUSPEND) return PolicyLifecycle::SUSPENDED;
      if (event == PolicyEvent::REQUIRE_REVALIDATION) return PolicyLifecycle::REVALIDATION_REQUIRED;
      if (event == PolicyEvent::REVOKE) return PolicyLifecycle::REVOKED;
      if (event == PolicyEvent::SUPERSEDE) return PolicyLifecycle::SUPERSEDED;
      if (event == PolicyEvent::RETIRE) return PolicyLifecycle::RETIRED;
      return std::nullopt;
    case PolicyLifecycle::SUSPENDED:
      if (event == PolicyEvent::RESUME) return PolicyLifecycle::ACTIVE;
      if (event == PolicyEvent::REQUIRE_REVALIDATION) return PolicyLifecycle::REVALIDATION_REQUIRED;
      if (event == PolicyEvent::REVOKE) return PolicyLifecycle::REVOKED;
      if (event == PolicyEvent::SUPERSEDE) return PolicyLifecycle::SUPERSEDED;
      if (event == PolicyEvent::RETIRE) return PolicyLifecycle::RETIRED;
      return std::nullopt;
    case PolicyLifecycle::REVALIDATION_REQUIRED:
      if (event == PolicyEvent::REVALIDATE) return PolicyLifecycle::ACTIVE;
      if (event == PolicyEvent::SUSPEND) return PolicyLifecycle::SUSPENDED;
      if (event == PolicyEvent::REVOKE) return PolicyLifecycle::REVOKED;
      if (event == PolicyEvent::SUPERSEDE) return PolicyLifecycle::SUPERSEDED;
      if (event == PolicyEvent::RETIRE) return PolicyLifecycle::RETIRED;
      return std::nullopt;
    case PolicyLifecycle::REVOKED:
    case PolicyLifecycle::SUPERSEDED:
    case PolicyLifecycle::RETIRED:
      // Terminal: no event is defined, so a retired policy can never reactivate.
      return std::nullopt;
  }
  return std::nullopt;
}

// The complete 9x8 decision table, restated independently.
[[nodiscard]] std::optional<DecisionLifecycle> expected_decision_transition(
    DecisionLifecycle state, DecisionEvent event) {
  switch (state) {
    case DecisionLifecycle::PROPOSED:
      if (event == DecisionEvent::MARK_ELIGIBLE) return DecisionLifecycle::ELIGIBLE;
      if (event == DecisionEvent::SUPPRESS) return DecisionLifecycle::SUPPRESSED;
      if (event == DecisionEvent::REJECT) return DecisionLifecycle::REJECTED;
      return std::nullopt;
    case DecisionLifecycle::ELIGIBLE:
      if (event == DecisionEvent::COMMIT) return DecisionLifecycle::COMMITTED;
      if (event == DecisionEvent::SUPPRESS) return DecisionLifecycle::SUPPRESSED;
      if (event == DecisionEvent::REJECT) return DecisionLifecycle::REJECTED;
      if (event == DecisionEvent::EXPIRE) return DecisionLifecycle::EXPIRED;
      if (event == DecisionEvent::REQUIRE_REVALIDATION) {
        return DecisionLifecycle::REVALIDATION_REQUIRED;
      }
      return std::nullopt;
    case DecisionLifecycle::COMMITTED:
      if (event == DecisionEvent::SUPERSEDE) return DecisionLifecycle::SUPERSEDED;
      if (event == DecisionEvent::ROLLBACK) return DecisionLifecycle::ROLLED_BACK;
      if (event == DecisionEvent::REQUIRE_REVALIDATION) {
        return DecisionLifecycle::REVALIDATION_REQUIRED;
      }
      if (event == DecisionEvent::EXPIRE) return DecisionLifecycle::EXPIRED;
      return std::nullopt;
    case DecisionLifecycle::REVALIDATION_REQUIRED:
      if (event == DecisionEvent::SUPERSEDE) return DecisionLifecycle::SUPERSEDED;
      if (event == DecisionEvent::EXPIRE) return DecisionLifecycle::EXPIRED;
      if (event == DecisionEvent::REJECT) return DecisionLifecycle::REJECTED;
      return std::nullopt;
    case DecisionLifecycle::SUPPRESSED:
    case DecisionLifecycle::SUPERSEDED:
    case DecisionLifecycle::ROLLED_BACK:
    case DecisionLifecycle::EXPIRED:
    case DecisionLifecycle::REJECTED:
      return std::nullopt;
  }
  return std::nullopt;
}

[[nodiscard]] std::vector<PolicyLifecycle> all_policy_lifecycles() {
  return {PolicyLifecycle::DECLARED, PolicyLifecycle::ACTIVE, PolicyLifecycle::SUSPENDED,
          PolicyLifecycle::REVALIDATION_REQUIRED, PolicyLifecycle::REVOKED,
          PolicyLifecycle::SUPERSEDED, PolicyLifecycle::RETIRED};
}

[[nodiscard]] std::vector<PolicyEvent> all_policy_events() {
  return {PolicyEvent::ACTIVATE, PolicyEvent::SUSPEND, PolicyEvent::RESUME,
          PolicyEvent::REQUIRE_REVALIDATION, PolicyEvent::REVALIDATE, PolicyEvent::REVOKE,
          PolicyEvent::SUPERSEDE, PolicyEvent::RETIRE};
}

[[nodiscard]] std::vector<DecisionLifecycle> all_decision_lifecycles() {
  return {DecisionLifecycle::PROPOSED, DecisionLifecycle::ELIGIBLE, DecisionLifecycle::SUPPRESSED,
          DecisionLifecycle::COMMITTED, DecisionLifecycle::SUPERSEDED,
          DecisionLifecycle::ROLLED_BACK, DecisionLifecycle::REVALIDATION_REQUIRED,
          DecisionLifecycle::EXPIRED, DecisionLifecycle::REJECTED};
}

[[nodiscard]] std::vector<DecisionEvent> all_decision_events() {
  return {DecisionEvent::MARK_ELIGIBLE, DecisionEvent::SUPPRESS, DecisionEvent::COMMIT,
          DecisionEvent::SUPERSEDE, DecisionEvent::ROLLBACK, DecisionEvent::REQUIRE_REVALIDATION,
          DecisionEvent::EXPIRE, DecisionEvent::REJECT};
}

[[nodiscard]] std::vector<Currentness> all_currentness_values() {
  return {Currentness::CURRENT,          Currentness::STALE_EVIDENCE,
          Currentness::STALE_PATH_AUTHORITY, Currentness::STALE_MULTIPATH_SET,
          Currentness::STALE_ROUTE,      Currentness::STALE_POLICY,
          Currentness::STALE_EPOCH,      Currentness::FENCED_PUBLISHER,
          Currentness::HOLD_DOWN_ACTIVE, Currentness::COOLDOWN_ACTIVE,
          Currentness::REVALIDATION_REQUIRED};
}

// Local policy builder. The lifecycle scenarios only need a structurally valid
// policy, so every field the validator consults is stated here explicitly and
// this suite never depends on a helper default.
[[nodiscard]] EvidenceRequirement mean_latency_requirement() {
  EvidenceRequirement requirement;
  requirement.kind = MetricKind::PATH_LATENCY;
  requirement.aggregation = AggregationKind::MEAN;
  requirement.ewma_alpha_bps = 0;
  requirement.min_samples = 1;
  requirement.max_age = seconds(120);
  requirement.min_window = 0;
  requirement.min_quality = EvidenceQuality::AGGREGATED;
  requirement.required = true;
  return requirement;
}

[[nodiscard]] PolicySemantics latency_policy(std::uint32_t switch_bps,
                                             std::uint32_t reverse_bps) {
  PolicySemantics semantics;
  semantics.target.route = route_id();
  ImprovementRule rule;
  rule.kind = MetricKind::PATH_LATENCY;
  rule.switch_improvement_bps = switch_bps;
  rule.reverse_improvement_bps = reverse_bps;
  semantics.improvements.push_back(rule);
  semantics.evidence.push_back(mean_latency_requirement());
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = MetricKind::PATH_LATENCY;
  objective.terms.push_back(term);
  semantics.objective = objective;
  return semantics;
}

[[nodiscard]] PolicyLifecycle lifecycle_of(const Harness& harness,
                                           const AdaptivePolicyId& policy) {
  const auto found = harness.fabric->find_policy(policy);
  ARF_CHECK_MSG(found.has_value(), "policy must exist to read its lifecycle");
  return found.has_value() ? found->lifecycle : PolicyLifecycle::REVOKED;
}

[[nodiscard]] OperationResult transition(Harness& harness, const AdaptivePolicyId& policy,
                                         PolicyEvent event) {
  PolicyLifecycleRequest request;
  request.policy = policy;
  request.event = event;
  request.detail = "test lifecycle event";
  request.context = harness.context();
  return harness.fabric->transition_policy(request);
}

}  // namespace

ARF_TEST(policy_transition_table_is_exactly_the_documented_one) {
  const std::vector<PolicyLifecycle> states = all_policy_lifecycles();
  const std::vector<PolicyEvent> events = all_policy_events();
  ARF_CHECK_EQ(states.size(), static_cast<std::size_t>(7));
  ARF_CHECK_EQ(events.size(), static_cast<std::size_t>(8));

  std::size_t defined = 0;
  std::size_t undefined = 0;
  for (const PolicyLifecycle state : states) {
    for (const PolicyEvent event : events) {
      const auto applied = apply_policy_event(state, event);
      const auto expected = expected_policy_transition(state, event);
      const bool matches = applied == expected;
      ARF_CHECK_EQ(applied, expected);
      ARF_CHECK_MSG(matches, "policy transition mismatch: state="
                                 << to_string(state) << " event=" << to_string(event)
                                 << " expected=" << render_policy_lifecycle(expected)
                                 << " actual=" << render_policy_lifecycle(applied));
      if (expected.has_value()) {
        ++defined;
      } else {
        ++undefined;
      }
    }
  }
  // 5 defined transitions for each of the four non-terminal states, none for
  // the three terminal ones.
  ARF_CHECK_EQ(defined, static_cast<std::size_t>(20));
  ARF_CHECK_EQ(undefined, static_cast<std::size_t>(36));
}

ARF_TEST(policy_terminal_states_accept_no_event) {
  const std::vector<PolicyLifecycle> terminal = {PolicyLifecycle::REVOKED,
                                                 PolicyLifecycle::SUPERSEDED,
                                                 PolicyLifecycle::RETIRED};
  for (const PolicyLifecycle state : terminal) {
    ARF_CHECK_MSG(policy_lifecycle_terminal(state), "expected a terminal state: "
                                                        << to_string(state));
    ARF_CHECK_MSG(!policy_lifecycle_adaptable(state),
                  "a terminal state must never be adaptable: " << to_string(state));
    for (const PolicyEvent event : all_policy_events()) {
      ARF_CHECK_MSG(!apply_policy_event(state, event).has_value(),
                    "terminal state " << to_string(state) << " accepted event "
                                      << to_string(event));
    }
  }
  const std::vector<PolicyLifecycle> live = {PolicyLifecycle::DECLARED, PolicyLifecycle::ACTIVE,
                                             PolicyLifecycle::SUSPENDED,
                                             PolicyLifecycle::REVALIDATION_REQUIRED};
  for (const PolicyLifecycle state : live) {
    ARF_CHECK_MSG(!policy_lifecycle_terminal(state),
                  "expected a non-terminal state: " << to_string(state));
  }
  // Only ACTIVE may commit a new adaptation decision.
  ARF_CHECK(policy_lifecycle_adaptable(PolicyLifecycle::ACTIVE));
  ARF_CHECK(!policy_lifecycle_adaptable(PolicyLifecycle::DECLARED));
  ARF_CHECK(!policy_lifecycle_adaptable(PolicyLifecycle::SUSPENDED));
  ARF_CHECK(!policy_lifecycle_adaptable(PolicyLifecycle::REVALIDATION_REQUIRED));
}

ARF_TEST(decision_transition_table_is_exactly_the_documented_one) {
  const std::vector<DecisionLifecycle> states = all_decision_lifecycles();
  const std::vector<DecisionEvent> events = all_decision_events();
  ARF_CHECK_EQ(states.size(), static_cast<std::size_t>(9));
  ARF_CHECK_EQ(events.size(), static_cast<std::size_t>(8));

  std::size_t defined = 0;
  std::size_t undefined = 0;
  for (const DecisionLifecycle state : states) {
    for (const DecisionEvent event : events) {
      const auto applied = apply_decision_event(state, event);
      const auto expected = expected_decision_transition(state, event);
      const bool matches = applied == expected;
      ARF_CHECK_EQ(applied, expected);
      ARF_CHECK_MSG(matches, "decision transition mismatch: state="
                                 << to_string(state) << " event=" << to_string(event)
                                 << " expected=" << render_decision_lifecycle(expected)
                                 << " actual=" << render_decision_lifecycle(applied));
      if (expected.has_value()) {
        ++defined;
      } else {
        ++undefined;
      }
    }
  }
  // PROPOSED 3, ELIGIBLE 5, COMMITTED 4, REVALIDATION_REQUIRED 3.
  ARF_CHECK_EQ(defined, static_cast<std::size_t>(15));
  ARF_CHECK_EQ(undefined, static_cast<std::size_t>(57));

  const std::vector<DecisionLifecycle> terminal = {
      DecisionLifecycle::SUPPRESSED, DecisionLifecycle::SUPERSEDED,
      DecisionLifecycle::ROLLED_BACK, DecisionLifecycle::EXPIRED, DecisionLifecycle::REJECTED};
  for (const DecisionLifecycle state : terminal) {
    ARF_CHECK_MSG(decision_lifecycle_terminal(state),
                  "expected a terminal decision state: " << to_string(state));
    for (const DecisionEvent event : events) {
      ARF_CHECK_MSG(!apply_decision_event(state, event).has_value(),
                    "terminal decision state " << to_string(state) << " accepted event "
                                               << to_string(event));
    }
  }
  for (const DecisionLifecycle state : {DecisionLifecycle::PROPOSED, DecisionLifecycle::ELIGIBLE,
                                        DecisionLifecycle::COMMITTED,
                                        DecisionLifecycle::REVALIDATION_REQUIRED}) {
    ARF_CHECK_MSG(!decision_lifecycle_terminal(state),
                  "expected a non-terminal decision state: " << to_string(state));
  }
}

ARF_TEST(lifecycle_names_round_trip_and_reject_unknown_raw_values) {
  for (const PolicyLifecycle state : all_policy_lifecycles()) {
    ARF_CHECK_EQ(parse_policy_lifecycle(to_string(state)), state);
    ARF_CHECK(valid_policy_lifecycle(static_cast<std::uint8_t>(state)));
  }
  for (const PolicyEvent event : all_policy_events()) {
    ARF_CHECK_EQ(parse_policy_event(to_string(event)), event);
    ARF_CHECK(valid_policy_event(static_cast<std::uint8_t>(event)));
  }
  for (const DecisionLifecycle state : all_decision_lifecycles()) {
    ARF_CHECK_EQ(parse_decision_lifecycle(to_string(state)), state);
    ARF_CHECK(valid_decision_lifecycle(static_cast<std::uint8_t>(state)));
  }
  for (const DecisionEvent event : all_decision_events()) {
    ARF_CHECK_EQ(parse_decision_event(to_string(event)), event);
    ARF_CHECK(valid_decision_event(static_cast<std::uint8_t>(event)));
  }
  ARF_CHECK(!valid_policy_lifecycle(0));
  ARF_CHECK(!valid_policy_lifecycle(8));
  ARF_CHECK(!valid_policy_event(0));
  ARF_CHECK(!valid_policy_event(9));
  ARF_CHECK(!valid_decision_lifecycle(0));
  ARF_CHECK(!valid_decision_lifecycle(10));
  ARF_CHECK(!valid_decision_event(0));
  ARF_CHECK(!valid_decision_event(9));
  ARF_CHECK(!parse_policy_lifecycle("REVOKED_PENDING").has_value());
  ARF_CHECK(!parse_policy_lifecycle("revoked").has_value());
  ARF_CHECK(!parse_policy_event("NOOP").has_value());
  ARF_CHECK(!parse_decision_lifecycle("PROPOSED ").has_value());
  ARF_CHECK(!parse_decision_event("").has_value());
  // An out-of-range value renders as an explicit unknown rather than a number.
  const auto unknown_state = static_cast<PolicyLifecycle>(static_cast<std::uint8_t>(99));
  ARF_CHECK_EQ(to_string(unknown_state), std::string_view("UNKNOWN"));
  ARF_CHECK_EQ(to_string(static_cast<DecisionEvent>(static_cast<std::uint8_t>(0))),
               std::string_view("UNKNOWN"));
}

ARF_TEST(currentness_round_trips_and_only_current_is_current) {
  const std::vector<Currentness> values = all_currentness_values();
  ARF_CHECK_EQ(values.size(), static_cast<std::size_t>(11));
  std::size_t current_count = 0;
  for (const Currentness value : values) {
    ARF_CHECK_EQ(parse_currentness(to_string(value)), value);
    ARF_CHECK(valid_currentness(static_cast<std::uint8_t>(value)));
    if (currentness_is_current(value)) {
      ++current_count;
      ARF_CHECK_EQ(value, Currentness::CURRENT);
    }
  }
  // Every distinct reason the runtime refuses to believe a fact stays distinct;
  // exactly one value grants usable authority.
  ARF_CHECK_EQ(current_count, static_cast<std::size_t>(1));
  ARF_CHECK(currentness_is_current(Currentness::CURRENT));
  ARF_CHECK(!currentness_is_current(Currentness::STALE_EVIDENCE));
  ARF_CHECK(!currentness_is_current(Currentness::HOLD_DOWN_ACTIVE));
  ARF_CHECK(!valid_currentness(0));
  ARF_CHECK(!valid_currentness(12));
  ARF_CHECK(!parse_currentness("STALE").has_value());
  ARF_CHECK(!parse_currentness("").has_value());
}

ARF_TEST(policy_lifecycle_engine_sequence) {
  Harness harness = make_harness();
  const OperationResult created = create_policy(harness, latency_policy(1000, 1000),
                                               harness.next_policy_name(), harness.context());
  ARF_REQUIRE_MSG(created.outcome == Outcome::POLICY_CREATED, created.render());
  const AdaptivePolicyId policy = created.policy;
  ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::DECLARED);

  // A candidate has to exist before REVALIDATE can succeed, and a policy is
  // allowed to learn its candidate set while it is still DECLARED.
  const OperationResult declared =
      declare_candidate(harness, policy, make_binding(path("path-a"), 1));
  ARF_REQUIRE_MSG(declared.outcome == Outcome::POLICY_UPDATED, declared.render());

  // Every event that the table leaves undefined for DECLARED is refused and
  // leaves the state untouched.
  for (const PolicyEvent event :
       {PolicyEvent::SUSPEND, PolicyEvent::RESUME, PolicyEvent::REVALIDATE}) {
    const OperationResult rejected = transition(harness, policy, event);
    ARF_CHECK_MSG(rejected.outcome == Outcome::MALFORMED_REQUEST,
                  "DECLARED must refuse " << to_string(event) << ": " << rejected.render());
    ARF_CHECK_MSG(!rejected.mutated, "a refused event must not mutate the policy");
    ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::DECLARED);
  }

  const OperationResult activated = transition(harness, policy, PolicyEvent::ACTIVATE);
  ARF_CHECK_MSG(activated.outcome == Outcome::POLICY_UPDATED, activated.render());
  ARF_CHECK(activated.mutated);
  ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::ACTIVE);

  for (const PolicyEvent event : {PolicyEvent::ACTIVATE, PolicyEvent::RESUME,
                                  PolicyEvent::REVALIDATE}) {
    const OperationResult rejected = transition(harness, policy, event);
    ARF_CHECK_MSG(rejected.outcome == Outcome::MALFORMED_REQUEST,
                  "ACTIVE must refuse " << to_string(event) << ": " << rejected.render());
    ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::ACTIVE);
  }

  const OperationResult suspended = transition(harness, policy, PolicyEvent::SUSPEND);
  ARF_CHECK_MSG(suspended.outcome == Outcome::POLICY_UPDATED, suspended.render());
  ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::SUSPENDED);

  for (const PolicyEvent event : {PolicyEvent::ACTIVATE, PolicyEvent::SUSPEND,
                                  PolicyEvent::REVALIDATE}) {
    const OperationResult rejected = transition(harness, policy, event);
    ARF_CHECK_MSG(rejected.outcome == Outcome::MALFORMED_REQUEST,
                  "SUSPENDED must refuse " << to_string(event) << ": " << rejected.render());
    ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::SUSPENDED);
  }

  const OperationResult resumed = transition(harness, policy, PolicyEvent::RESUME);
  ARF_CHECK_MSG(resumed.outcome == Outcome::POLICY_UPDATED, resumed.render());
  ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::ACTIVE);

  const OperationResult revalidation =
      transition(harness, policy, PolicyEvent::REQUIRE_REVALIDATION);
  ARF_CHECK_MSG(revalidation.outcome == Outcome::POLICY_UPDATED, revalidation.render());
  ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::REVALIDATION_REQUIRED);

  for (const PolicyEvent event : {PolicyEvent::ACTIVATE, PolicyEvent::RESUME,
                                  PolicyEvent::REQUIRE_REVALIDATION}) {
    const OperationResult rejected = transition(harness, policy, event);
    ARF_CHECK_MSG(rejected.outcome == Outcome::MALFORMED_REQUEST,
                  "REVALIDATION_REQUIRED must refuse " << to_string(event) << ": "
                                                       << rejected.render());
    ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::REVALIDATION_REQUIRED);
  }

  // Revalidation is earned: the declared candidate is still legal and
  // available, so the policy returns to service.
  const OperationResult revalidated = transition(harness, policy, PolicyEvent::REVALIDATE);
  ARF_CHECK_MSG(revalidated.outcome == Outcome::POLICY_UPDATED, revalidated.render());
  ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::ACTIVE);

  const OperationResult revoked = transition(harness, policy, PolicyEvent::REVOKE);
  ARF_CHECK_MSG(revoked.outcome == Outcome::POLICY_UPDATED, revoked.render());
  ARF_CHECK_EQ(lifecycle_of(harness, policy), PolicyLifecycle::REVOKED);
}

ARF_TEST(revoked_and_retired_policies_never_reactivate) {
  Harness harness = make_harness();
  const AdaptivePolicyId revoked = create_active_policy(harness, latency_policy(1000, 1000));
  const OperationResult revoke_result = transition(harness, revoked, PolicyEvent::REVOKE);
  ARF_CHECK_MSG(revoke_result.outcome == Outcome::POLICY_UPDATED, revoke_result.render());
  ARF_CHECK_EQ(lifecycle_of(harness, revoked), PolicyLifecycle::REVOKED);

  // RETIRE, ACTIVATE and SUSPEND are the three events that would resurrect the
  // policy in some form; every other event must be refused as well.
  for (const PolicyEvent event : all_policy_events()) {
    const OperationResult rejected = transition(harness, revoked, event);
    ARF_CHECK_MSG(rejected.outcome == Outcome::REVOKED,
                  "a revoked policy must refuse " << to_string(event) << ": "
                                                  << rejected.render());
    ARF_CHECK_MSG(!rejected.mutated, "a revoked policy must never mutate again");
    ARF_CHECK_EQ(lifecycle_of(harness, revoked), PolicyLifecycle::REVOKED);
  }

  const AdaptivePolicyId retired = create_active_policy(harness, latency_policy(1000, 1000));
  const OperationResult retire_result = transition(harness, retired, PolicyEvent::RETIRE);
  ARF_CHECK_MSG(retire_result.outcome == Outcome::POLICY_UPDATED, retire_result.render());
  ARF_CHECK_EQ(lifecycle_of(harness, retired), PolicyLifecycle::RETIRED);
  for (const PolicyEvent event : all_policy_events()) {
    const OperationResult rejected = transition(harness, retired, event);
    ARF_CHECK_MSG(rejected.outcome == Outcome::RETIRED,
                  "a retired policy must refuse " << to_string(event) << ": "
                                                  << rejected.render());
    ARF_CHECK_EQ(lifecycle_of(harness, retired), PolicyLifecycle::RETIRED);
  }

  // A revoked policy is also no longer adaptable: evaluation refuses it.
  const OperationResult evaluated = evaluate_policy(harness, revoked);
  ARF_CHECK_MSG(evaluated.outcome == Outcome::REVOKED, evaluated.render());
}

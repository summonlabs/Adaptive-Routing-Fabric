// Structured outcomes, suppression reasons and the deterministic rejection
// precedence.
//
// Adaptive Routing Fabric never reports "no change" without a reason. Every
// entry point returns exactly one Outcome, and every suppressed decision also
// carries the finer grained SuppressionReason that produced it.
//
// REJECTION PRECEDENCE
// --------------------
// When an input is defective in more than one way the runtime must reject it
// for one specific, documented reason. The precedence order is fixed and is
// exposed through \c outcome_precedence() so the test suite can drive
// multi-defect inputs and assert the exact winner instead of trusting prose:
//
//   1  wire integrity            (WIRE_INTEGRITY)
//   2  frame decode              (WIRE_MALFORMED)
//   3  request decode            (MALFORMED_REQUEST)
//   4  caller identity           (UNAUTHORIZED)
//   5  epoch                     (STALE_EPOCH)
//   6  worker authority          (STALE_WORKER / FENCED_WORKER)
//   7  authority scope           (UNAUTHORIZED_SCOPE)
//   8  resource limits           (RESOURCE_LIMIT)
//   9  policy lifecycle          (SUSPENDED / REVALIDATION_REQUIRED / REVOKED /
//                                 RETIRED)
//  10  expected generations      (STALE_POLICY_GENERATION / STALE_EVIDENCE /
//                                 STALE_ROUTE / STALE_MULTIPATH_SET /
//                                 STALE_PATH_AUTHORITY)
//  11  attempt id                (ATTEMPT_CONFLICT)
//  12  upstream currentness      (STALE_*)
//  13  evidence currentness      (STALE_EVIDENCE / INSUFFICIENT_EVIDENCE)
//  14  candidate eligibility     (NO_ELIGIBLE_CANDIDATE)
//  15  hold-down / cooldown      (HOLD_DOWN_ACTIVE / COOLDOWN_ACTIVE)
//  16  trigger evaluation        (HYSTERESIS_NOT_CLEARED / NO_CHANGE)
//  17  churn limits              (CHURN_LIMIT_REACHED)
//  18  commit                    (DECISION_COMMITTED / GENERATION_OVERFLOW)
#ifndef ADAPTIVE_ROUTING_OUTCOME_HPP
#define ADAPTIVE_ROUTING_OUTCOME_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "adaptive_routing/ids.hpp"

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

enum class Outcome : std::uint16_t {
  POLICY_CREATED = 1,
  POLICY_UPDATED = 2,
  DECISION_COMMITTED = 3,
  IDEMPOTENT = 4,
  SUPPRESSED = 5,
  NO_CHANGE = 6,
  STALE_EVIDENCE = 7,
  STALE_PATH_AUTHORITY = 8,
  STALE_MULTIPATH_SET = 9,
  STALE_ROUTE = 10,
  STALE_POLICY_GENERATION = 11,
  STALE_EPOCH = 12,
  STALE_WORKER = 13,
  HOLD_DOWN_ACTIVE = 14,
  COOLDOWN_ACTIVE = 15,
  HYSTERESIS_NOT_CLEARED = 16,
  INSUFFICIENT_EVIDENCE = 17,
  NO_ELIGIBLE_CANDIDATE = 18,
  UNAUTHORIZED = 19,
  REVALIDATION_REQUIRED = 20,
  REVOKED = 21,
  RETIRED = 22,
  RESOURCE_LIMIT = 23,
  MALFORMED_REQUEST = 24,
  // Extensions required by the full rejection surface. Each one names a defect
  // that the base list above cannot express without ambiguity.
  ATTEMPT_CONFLICT = 25,
  GENERATION_OVERFLOW = 26,
  INCOMPATIBLE_METRIC = 27,
  INVALID_HYSTERESIS = 28,
  CHURN_LIMIT_REACHED = 29,
  ROLLBACK_REFUSED = 30,
  NOT_FOUND = 31,
  ALREADY_EXISTS = 32,
  SUSPENDED = 33,
  FENCED_WORKER = 34,
  UNAUTHORIZED_SCOPE = 35,
  CORRUPT_STORE = 36,
  WIRE_MALFORMED = 37,
  WIRE_INTEGRITY = 38,
  SESSION_LIMIT = 39,
  EVALUATION_LIMIT = 40,
  UNSUPPORTED_VERSION = 41,
  POLICY_SUPERSEDED = 42,
  INTERNAL_ERROR = 43,
  WITHDRAWN_UPSTREAM = 44,
  NO_CURRENT_PREFERENCE = 45,
  DECISION_SUPERSEDED = 46,
};

[[nodiscard]] std::string_view to_string(Outcome outcome) noexcept;
[[nodiscard]] std::optional<Outcome> parse_outcome(std::string_view text) noexcept;
[[nodiscard]] bool valid_outcome(std::uint16_t raw) noexcept;

// True for the outcomes that mean "the request was applied".
[[nodiscard]] bool outcome_is_success(Outcome outcome) noexcept;
// True for the outcomes that mean "the request was understood and refused".
[[nodiscard]] bool outcome_is_rejection(Outcome outcome) noexcept;

// Rank in the documented rejection precedence. Lower rank is checked first.
[[nodiscard]] std::uint32_t outcome_precedence(Outcome outcome) noexcept;

// ---------------------------------------------------------------------------
// Suppression reasons
// ---------------------------------------------------------------------------

enum class SuppressionReason : std::uint8_t {
  NONE = 0,
  BELOW_THRESHOLD = 1,
  HYSTERESIS_NOT_CLEARED = 2,
  HOLD_DOWN_ACTIVE = 3,
  COOLDOWN_ACTIVE = 4,
  INSUFFICIENT_SAMPLES = 5,
  STALE_EVIDENCE = 6,
  NO_ELIGIBLE_ALTERNATIVE = 7,
  POLICY_SUSPENDED = 8,
  REVALIDATION_REQUIRED = 9,
  CHURN_LIMIT_REACHED = 10,
  CURRENT_PREFERENCE_INELIGIBLE = 11,
  NO_TRIGGER_DECLARED = 12,
  MERIT_NOT_ESTABLISHED = 13,
  EVIDENCE_UNKNOWN = 14,
  DAMPENING_EXTENDED_HOLD_DOWN = 15,
  POLICY_NOT_ACTIVE = 16,
  POLICY_REVOKED = 17,
  POLICY_RETIRED = 18,
  UPSTREAM_DEPENDENCY_STALE = 19,
  REVERSE_REQUIREMENT_NOT_MET = 20,
};

[[nodiscard]] std::string_view to_string(SuppressionReason reason) noexcept;
[[nodiscard]] std::optional<SuppressionReason> parse_suppression_reason(std::string_view text) noexcept;
[[nodiscard]] bool valid_suppression_reason(std::uint8_t raw) noexcept;

// The outcome reported when a decision is suppressed for this reason.
[[nodiscard]] Outcome suppression_outcome(SuppressionReason reason) noexcept;

// ---------------------------------------------------------------------------
// Operation result
// ---------------------------------------------------------------------------

// The single structured result returned by every mutating entry point.
struct OperationResult {
  Outcome outcome = Outcome::MALFORMED_REQUEST;
  std::string detail;
  AdaptivePolicyId policy;
  AdaptivePolicyGeneration policy_generation;
  AdaptationDecisionId decision;
  AdaptationGeneration adaptation_generation;
  TransitionGeneration transition_generation;
  EvidenceGeneration evidence_generation;
  CoordinatorEpoch epoch;
  SuppressionReason suppression = SuppressionReason::NONE;
  bool mutated = false;

  [[nodiscard]] bool ok() const noexcept { return outcome_is_success(outcome); }
  [[nodiscard]] std::string render() const;

  [[nodiscard]] static OperationResult make(Outcome outcome, std::string detail);
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_OUTCOME_HPP

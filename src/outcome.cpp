// Structured outcomes and suppression reasons.
#include "adaptive_routing/outcome.hpp"

#include <array>
#include <utility>

namespace adaptive_routing {
namespace {

struct OutcomeEntry {
  Outcome outcome;
  std::string_view name;
  std::uint32_t precedence;
};

// The declaration order of this table IS the documented rejection precedence.
// Lower precedence rank is checked first; a multi-defect input is always
// rejected for the earliest stage it violates.
constexpr std::array<OutcomeEntry, 46> outcome_table{{
    // Successes carry rank 0: they are not rejections and never compete.
    {Outcome::POLICY_CREATED, "POLICY_CREATED", 0},
    {Outcome::POLICY_UPDATED, "POLICY_UPDATED", 0},
    {Outcome::DECISION_COMMITTED, "DECISION_COMMITTED", 0},
    {Outcome::IDEMPOTENT, "IDEMPOTENT", 0},
    // 1 integrity
    {Outcome::CORRUPT_STORE, "CORRUPT_STORE", 1},
    {Outcome::WIRE_INTEGRITY, "WIRE_INTEGRITY", 1},
    // 2 decode
    {Outcome::WIRE_MALFORMED, "WIRE_MALFORMED", 2},
    // 3 request decode and structural validation
    {Outcome::MALFORMED_REQUEST, "MALFORMED_REQUEST", 3},
    {Outcome::UNSUPPORTED_VERSION, "UNSUPPORTED_VERSION", 3},
    {Outcome::INVALID_HYSTERESIS, "INVALID_HYSTERESIS", 3},
    {Outcome::INCOMPATIBLE_METRIC, "INCOMPATIBLE_METRIC", 3},
    {Outcome::ALREADY_EXISTS, "ALREADY_EXISTS", 3},
    {Outcome::NOT_FOUND, "NOT_FOUND", 3},
    // 4 caller identity
    {Outcome::UNAUTHORIZED, "UNAUTHORIZED", 4},
    // 5 epoch
    {Outcome::STALE_EPOCH, "STALE_EPOCH", 5},
    // 6 worker authority
    {Outcome::STALE_WORKER, "STALE_WORKER", 6},
    {Outcome::FENCED_WORKER, "FENCED_WORKER", 6},
    // 7 authority scope
    {Outcome::UNAUTHORIZED_SCOPE, "UNAUTHORIZED_SCOPE", 7},
    // 8 resource limits
    {Outcome::RESOURCE_LIMIT, "RESOURCE_LIMIT", 8},
    {Outcome::SESSION_LIMIT, "SESSION_LIMIT", 8},
    {Outcome::EVALUATION_LIMIT, "EVALUATION_LIMIT", 8},
    // 9 policy lifecycle
    {Outcome::SUSPENDED, "SUSPENDED", 9},
    {Outcome::REVALIDATION_REQUIRED, "REVALIDATION_REQUIRED", 9},
    {Outcome::REVOKED, "REVOKED", 9},
    {Outcome::RETIRED, "RETIRED", 9},
    {Outcome::POLICY_SUPERSEDED, "POLICY_SUPERSEDED", 9},
    // 10 expected generations
    {Outcome::STALE_POLICY_GENERATION, "STALE_POLICY_GENERATION", 10},
    {Outcome::STALE_EVIDENCE, "STALE_EVIDENCE", 10},
    {Outcome::STALE_ROUTE, "STALE_ROUTE", 10},
    {Outcome::STALE_MULTIPATH_SET, "STALE_MULTIPATH_SET", 10},
    {Outcome::STALE_PATH_AUTHORITY, "STALE_PATH_AUTHORITY", 10},
    // 11 attempt id
    {Outcome::ATTEMPT_CONFLICT, "ATTEMPT_CONFLICT", 11},
    // 12 upstream currentness
    {Outcome::WITHDRAWN_UPSTREAM, "WITHDRAWN_UPSTREAM", 12},
    // 13 evidence currentness
    {Outcome::INSUFFICIENT_EVIDENCE, "INSUFFICIENT_EVIDENCE", 13},
    // 14 candidate eligibility
    {Outcome::NO_ELIGIBLE_CANDIDATE, "NO_ELIGIBLE_CANDIDATE", 14},
    {Outcome::NO_CURRENT_PREFERENCE, "NO_CURRENT_PREFERENCE", 14},
    // 15 hold-down and cooldown
    {Outcome::HOLD_DOWN_ACTIVE, "HOLD_DOWN_ACTIVE", 15},
    {Outcome::COOLDOWN_ACTIVE, "COOLDOWN_ACTIVE", 15},
    // 16 trigger evaluation
    {Outcome::HYSTERESIS_NOT_CLEARED, "HYSTERESIS_NOT_CLEARED", 16},
    {Outcome::NO_CHANGE, "NO_CHANGE", 16},
    {Outcome::SUPPRESSED, "SUPPRESSED", 16},
    // 17 churn limits
    {Outcome::CHURN_LIMIT_REACHED, "CHURN_LIMIT_REACHED", 17},
    // 18 commit
    {Outcome::GENERATION_OVERFLOW, "GENERATION_OVERFLOW", 18},
    {Outcome::DECISION_SUPERSEDED, "DECISION_SUPERSEDED", 18},
    {Outcome::ROLLBACK_REFUSED, "ROLLBACK_REFUSED", 18},
    // Unreachable through ordinary flow; present so that an internal invariant
    // failure still has a stable, reportable name.
    {Outcome::INTERNAL_ERROR, "INTERNAL_ERROR", 99},
}};

constexpr std::array<std::pair<SuppressionReason, std::string_view>, 21> suppression_table{{
    {SuppressionReason::NONE, "NONE"},
    {SuppressionReason::BELOW_THRESHOLD, "BELOW_THRESHOLD"},
    {SuppressionReason::HYSTERESIS_NOT_CLEARED, "HYSTERESIS_NOT_CLEARED"},
    {SuppressionReason::HOLD_DOWN_ACTIVE, "HOLD_DOWN_ACTIVE"},
    {SuppressionReason::COOLDOWN_ACTIVE, "COOLDOWN_ACTIVE"},
    {SuppressionReason::INSUFFICIENT_SAMPLES, "INSUFFICIENT_SAMPLES"},
    {SuppressionReason::STALE_EVIDENCE, "STALE_EVIDENCE"},
    {SuppressionReason::NO_ELIGIBLE_ALTERNATIVE, "NO_ELIGIBLE_ALTERNATIVE"},
    {SuppressionReason::POLICY_SUSPENDED, "POLICY_SUSPENDED"},
    {SuppressionReason::REVALIDATION_REQUIRED, "REVALIDATION_REQUIRED"},
    {SuppressionReason::CHURN_LIMIT_REACHED, "CHURN_LIMIT_REACHED"},
    {SuppressionReason::CURRENT_PREFERENCE_INELIGIBLE, "CURRENT_PREFERENCE_INELIGIBLE"},
    {SuppressionReason::NO_TRIGGER_DECLARED, "NO_TRIGGER_DECLARED"},
    {SuppressionReason::MERIT_NOT_ESTABLISHED, "MERIT_NOT_ESTABLISHED"},
    {SuppressionReason::EVIDENCE_UNKNOWN, "EVIDENCE_UNKNOWN"},
    {SuppressionReason::DAMPENING_EXTENDED_HOLD_DOWN, "DAMPENING_EXTENDED_HOLD_DOWN"},
    {SuppressionReason::POLICY_NOT_ACTIVE, "POLICY_NOT_ACTIVE"},
    {SuppressionReason::POLICY_REVOKED, "POLICY_REVOKED"},
    {SuppressionReason::POLICY_RETIRED, "POLICY_RETIRED"},
    {SuppressionReason::UPSTREAM_DEPENDENCY_STALE, "UPSTREAM_DEPENDENCY_STALE"},
    {SuppressionReason::REVERSE_REQUIREMENT_NOT_MET, "REVERSE_REQUIREMENT_NOT_MET"},
}};

[[nodiscard]] const OutcomeEntry* find_outcome(Outcome outcome) noexcept {
  for (const auto& entry : outcome_table) {
    if (entry.outcome == outcome) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace

std::string_view to_string(Outcome outcome) noexcept {
  const OutcomeEntry* entry = find_outcome(outcome);
  return entry == nullptr ? std::string_view("UNKNOWN") : entry->name;
}

std::optional<Outcome> parse_outcome(std::string_view text) noexcept {
  for (const auto& entry : outcome_table) {
    if (entry.name == text) {
      return entry.outcome;
    }
  }
  return std::nullopt;
}

bool valid_outcome(std::uint16_t raw) noexcept {
  return find_outcome(static_cast<Outcome>(raw)) != nullptr;
}

bool outcome_is_success(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::POLICY_CREATED:
    case Outcome::POLICY_UPDATED:
    case Outcome::DECISION_COMMITTED:
    case Outcome::IDEMPOTENT:
      return true;
    default:
      return false;
  }
}

bool outcome_is_rejection(Outcome outcome) noexcept { return !outcome_is_success(outcome); }

std::uint32_t outcome_precedence(Outcome outcome) noexcept {
  const OutcomeEntry* entry = find_outcome(outcome);
  return entry == nullptr ? 100U : entry->precedence;
}

std::string_view to_string(SuppressionReason reason) noexcept {
  for (const auto& entry : suppression_table) {
    if (entry.first == reason) {
      return entry.second;
    }
  }
  return "UNKNOWN";
}

std::optional<SuppressionReason> parse_suppression_reason(std::string_view text) noexcept {
  for (const auto& entry : suppression_table) {
    if (entry.second == text) {
      return entry.first;
    }
  }
  return std::nullopt;
}

bool valid_suppression_reason(std::uint8_t raw) noexcept {
  return raw <= 20;
}

Outcome suppression_outcome(SuppressionReason reason) noexcept {
  switch (reason) {
    case SuppressionReason::NONE:
      return Outcome::NO_CHANGE;
    case SuppressionReason::BELOW_THRESHOLD:
      return Outcome::NO_CHANGE;
    case SuppressionReason::HYSTERESIS_NOT_CLEARED:
      return Outcome::HYSTERESIS_NOT_CLEARED;
    case SuppressionReason::HOLD_DOWN_ACTIVE:
      return Outcome::HOLD_DOWN_ACTIVE;
    case SuppressionReason::COOLDOWN_ACTIVE:
      return Outcome::COOLDOWN_ACTIVE;
    case SuppressionReason::INSUFFICIENT_SAMPLES:
      return Outcome::INSUFFICIENT_EVIDENCE;
    case SuppressionReason::STALE_EVIDENCE:
      return Outcome::STALE_EVIDENCE;
    case SuppressionReason::NO_ELIGIBLE_ALTERNATIVE:
      return Outcome::NO_ELIGIBLE_CANDIDATE;
    case SuppressionReason::POLICY_SUSPENDED:
      return Outcome::SUSPENDED;
    case SuppressionReason::REVALIDATION_REQUIRED:
      return Outcome::REVALIDATION_REQUIRED;
    case SuppressionReason::CHURN_LIMIT_REACHED:
      return Outcome::CHURN_LIMIT_REACHED;
    case SuppressionReason::CURRENT_PREFERENCE_INELIGIBLE:
      return Outcome::REVALIDATION_REQUIRED;
    case SuppressionReason::NO_TRIGGER_DECLARED:
      return Outcome::NO_CHANGE;
    case SuppressionReason::MERIT_NOT_ESTABLISHED:
      return Outcome::NO_CHANGE;
    case SuppressionReason::EVIDENCE_UNKNOWN:
      return Outcome::INSUFFICIENT_EVIDENCE;
    case SuppressionReason::DAMPENING_EXTENDED_HOLD_DOWN:
      return Outcome::HOLD_DOWN_ACTIVE;
    case SuppressionReason::POLICY_NOT_ACTIVE:
      return Outcome::SUSPENDED;
    case SuppressionReason::POLICY_REVOKED:
      return Outcome::REVOKED;
    case SuppressionReason::POLICY_RETIRED:
      return Outcome::RETIRED;
    case SuppressionReason::UPSTREAM_DEPENDENCY_STALE:
      return Outcome::REVALIDATION_REQUIRED;
    case SuppressionReason::REVERSE_REQUIREMENT_NOT_MET:
      return Outcome::HYSTERESIS_NOT_CLEARED;
  }
  return Outcome::NO_CHANGE;
}

OperationResult OperationResult::make(Outcome outcome_value, std::string detail_value) {
  OperationResult result;
  result.outcome = outcome_value;
  result.detail = std::move(detail_value);
  return result;
}

std::string OperationResult::render() const {
  std::string text;
  text += std::string(to_string(outcome));
  if (suppression != SuppressionReason::NONE) {
    text += " suppression=";
    text += std::string(to_string(suppression));
  }
  if (policy.valid()) {
    text += " policy=";
    text += policy.str();
    if (policy_generation.valid()) {
      text += "@";
      text += std::to_string(policy_generation.value());
    }
  }
  if (decision.valid()) {
    text += " decision=";
    text += decision.str();
  }
  if (adaptation_generation.valid()) {
    text += " adaptation=";
    text += std::to_string(adaptation_generation.value());
  }
  if (transition_generation.valid()) {
    text += " transition=";
    text += std::to_string(transition_generation.value());
  }
  if (evidence_generation.valid()) {
    text += " evidence=";
    text += std::to_string(evidence_generation.value());
  }
  if (epoch.valid()) {
    text += " epoch=";
    text += std::to_string(epoch.value());
  }
  if (!detail.empty()) {
    text += " detail=";
    text += detail;
  }
  return text;
}

}  // namespace adaptive_routing

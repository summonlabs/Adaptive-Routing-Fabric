// Lifecycle and currentness transition tables.
#include "adaptive_routing/lifecycle.hpp"

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Policy lifecycle
// ---------------------------------------------------------------------------

std::string_view to_string(PolicyLifecycle lifecycle) noexcept {
  switch (lifecycle) {
    case PolicyLifecycle::DECLARED:
      return "DECLARED";
    case PolicyLifecycle::ACTIVE:
      return "ACTIVE";
    case PolicyLifecycle::SUSPENDED:
      return "SUSPENDED";
    case PolicyLifecycle::REVALIDATION_REQUIRED:
      return "REVALIDATION_REQUIRED";
    case PolicyLifecycle::REVOKED:
      return "REVOKED";
    case PolicyLifecycle::SUPERSEDED:
      return "SUPERSEDED";
    case PolicyLifecycle::RETIRED:
      return "RETIRED";
  }
  return "UNKNOWN";
}

std::optional<PolicyLifecycle> parse_policy_lifecycle(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 7; ++raw) {
    const auto value = static_cast<PolicyLifecycle>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

bool valid_policy_lifecycle(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 7; }

std::string_view to_string(PolicyEvent event) noexcept {
  switch (event) {
    case PolicyEvent::ACTIVATE:
      return "ACTIVATE";
    case PolicyEvent::SUSPEND:
      return "SUSPEND";
    case PolicyEvent::RESUME:
      return "RESUME";
    case PolicyEvent::REQUIRE_REVALIDATION:
      return "REQUIRE_REVALIDATION";
    case PolicyEvent::REVALIDATE:
      return "REVALIDATE";
    case PolicyEvent::REVOKE:
      return "REVOKE";
    case PolicyEvent::SUPERSEDE:
      return "SUPERSEDE";
    case PolicyEvent::RETIRE:
      return "RETIRE";
  }
  return "UNKNOWN";
}

std::optional<PolicyEvent> parse_policy_event(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 8; ++raw) {
    const auto value = static_cast<PolicyEvent>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

bool valid_policy_event(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 8; }

std::optional<PolicyLifecycle> apply_policy_event(PolicyLifecycle state,
                                                  PolicyEvent event) noexcept {
  switch (state) {
    case PolicyLifecycle::DECLARED:
      switch (event) {
        case PolicyEvent::ACTIVATE:
          return PolicyLifecycle::ACTIVE;
        case PolicyEvent::REQUIRE_REVALIDATION:
          return PolicyLifecycle::REVALIDATION_REQUIRED;
        case PolicyEvent::REVOKE:
          return PolicyLifecycle::REVOKED;
        case PolicyEvent::SUPERSEDE:
          return PolicyLifecycle::SUPERSEDED;
        case PolicyEvent::RETIRE:
          return PolicyLifecycle::RETIRED;
        default:
          return std::nullopt;
      }
    case PolicyLifecycle::ACTIVE:
      switch (event) {
        case PolicyEvent::SUSPEND:
          return PolicyLifecycle::SUSPENDED;
        case PolicyEvent::REQUIRE_REVALIDATION:
          return PolicyLifecycle::REVALIDATION_REQUIRED;
        case PolicyEvent::REVOKE:
          return PolicyLifecycle::REVOKED;
        case PolicyEvent::SUPERSEDE:
          return PolicyLifecycle::SUPERSEDED;
        case PolicyEvent::RETIRE:
          return PolicyLifecycle::RETIRED;
        default:
          return std::nullopt;
      }
    case PolicyLifecycle::SUSPENDED:
      switch (event) {
        case PolicyEvent::RESUME:
          return PolicyLifecycle::ACTIVE;
        case PolicyEvent::REQUIRE_REVALIDATION:
          return PolicyLifecycle::REVALIDATION_REQUIRED;
        case PolicyEvent::REVOKE:
          return PolicyLifecycle::REVOKED;
        case PolicyEvent::SUPERSEDE:
          return PolicyLifecycle::SUPERSEDED;
        case PolicyEvent::RETIRE:
          return PolicyLifecycle::RETIRED;
        default:
          return std::nullopt;
      }
    case PolicyLifecycle::REVALIDATION_REQUIRED:
      switch (event) {
        // Revalidation returns the policy to service only when it actually
        // succeeded; the caller performs the check and only then applies the
        // event.
        case PolicyEvent::REVALIDATE:
          return PolicyLifecycle::ACTIVE;
        case PolicyEvent::SUSPEND:
          return PolicyLifecycle::SUSPENDED;
        case PolicyEvent::REVOKE:
          return PolicyLifecycle::REVOKED;
        case PolicyEvent::SUPERSEDE:
          return PolicyLifecycle::SUPERSEDED;
        case PolicyEvent::RETIRE:
          return PolicyLifecycle::RETIRED;
        default:
          return std::nullopt;
      }
    case PolicyLifecycle::REVOKED:
    case PolicyLifecycle::SUPERSEDED:
    case PolicyLifecycle::RETIRED:
      // Terminal. A revoked, superseded or retired policy never reactivates and
      // never accepts a further lifecycle event.
      return std::nullopt;
  }
  return std::nullopt;
}

bool policy_lifecycle_terminal(PolicyLifecycle lifecycle) noexcept {
  return lifecycle == PolicyLifecycle::REVOKED || lifecycle == PolicyLifecycle::SUPERSEDED ||
         lifecycle == PolicyLifecycle::RETIRED;
}

bool policy_lifecycle_adaptable(PolicyLifecycle lifecycle) noexcept {
  return lifecycle == PolicyLifecycle::ACTIVE;
}

// ---------------------------------------------------------------------------
// Decision lifecycle
// ---------------------------------------------------------------------------

std::string_view to_string(DecisionLifecycle lifecycle) noexcept {
  switch (lifecycle) {
    case DecisionLifecycle::PROPOSED:
      return "PROPOSED";
    case DecisionLifecycle::ELIGIBLE:
      return "ELIGIBLE";
    case DecisionLifecycle::SUPPRESSED:
      return "SUPPRESSED";
    case DecisionLifecycle::COMMITTED:
      return "COMMITTED";
    case DecisionLifecycle::SUPERSEDED:
      return "SUPERSEDED";
    case DecisionLifecycle::ROLLED_BACK:
      return "ROLLED_BACK";
    case DecisionLifecycle::REVALIDATION_REQUIRED:
      return "REVALIDATION_REQUIRED";
    case DecisionLifecycle::EXPIRED:
      return "EXPIRED";
    case DecisionLifecycle::REJECTED:
      return "REJECTED";
  }
  return "UNKNOWN";
}

std::optional<DecisionLifecycle> parse_decision_lifecycle(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 9; ++raw) {
    const auto value = static_cast<DecisionLifecycle>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

bool valid_decision_lifecycle(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 9; }

std::string_view to_string(DecisionEvent event) noexcept {
  switch (event) {
    case DecisionEvent::MARK_ELIGIBLE:
      return "MARK_ELIGIBLE";
    case DecisionEvent::SUPPRESS:
      return "SUPPRESS";
    case DecisionEvent::COMMIT:
      return "COMMIT";
    case DecisionEvent::SUPERSEDE:
      return "SUPERSEDE";
    case DecisionEvent::ROLLBACK:
      return "ROLLBACK";
    case DecisionEvent::REQUIRE_REVALIDATION:
      return "REQUIRE_REVALIDATION";
    case DecisionEvent::EXPIRE:
      return "EXPIRE";
    case DecisionEvent::REJECT:
      return "REJECT";
  }
  return "UNKNOWN";
}

std::optional<DecisionEvent> parse_decision_event(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 8; ++raw) {
    const auto value = static_cast<DecisionEvent>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

bool valid_decision_event(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 8; }

std::optional<DecisionLifecycle> apply_decision_event(DecisionLifecycle state,
                                                      DecisionEvent event) noexcept {
  switch (state) {
    case DecisionLifecycle::PROPOSED:
      switch (event) {
        case DecisionEvent::MARK_ELIGIBLE:
          return DecisionLifecycle::ELIGIBLE;
        case DecisionEvent::SUPPRESS:
          return DecisionLifecycle::SUPPRESSED;
        case DecisionEvent::REJECT:
          return DecisionLifecycle::REJECTED;
        default:
          return std::nullopt;
      }
    case DecisionLifecycle::ELIGIBLE:
      switch (event) {
        case DecisionEvent::COMMIT:
          return DecisionLifecycle::COMMITTED;
        case DecisionEvent::SUPPRESS:
          return DecisionLifecycle::SUPPRESSED;
        case DecisionEvent::REJECT:
          return DecisionLifecycle::REJECTED;
        case DecisionEvent::EXPIRE:
          return DecisionLifecycle::EXPIRED;
        case DecisionEvent::REQUIRE_REVALIDATION:
          return DecisionLifecycle::REVALIDATION_REQUIRED;
        default:
          return std::nullopt;
      }
    case DecisionLifecycle::COMMITTED:
      switch (event) {
        case DecisionEvent::SUPERSEDE:
          return DecisionLifecycle::SUPERSEDED;
        case DecisionEvent::ROLLBACK:
          return DecisionLifecycle::ROLLED_BACK;
        case DecisionEvent::REQUIRE_REVALIDATION:
          return DecisionLifecycle::REVALIDATION_REQUIRED;
        case DecisionEvent::EXPIRE:
          return DecisionLifecycle::EXPIRED;
        default:
          return std::nullopt;
      }
    case DecisionLifecycle::REVALIDATION_REQUIRED:
      switch (event) {
        case DecisionEvent::SUPERSEDE:
          return DecisionLifecycle::SUPERSEDED;
        case DecisionEvent::EXPIRE:
          return DecisionLifecycle::EXPIRED;
        case DecisionEvent::REJECT:
          return DecisionLifecycle::REJECTED;
        default:
          return std::nullopt;
      }
    case DecisionLifecycle::SUPPRESSED:
    case DecisionLifecycle::SUPERSEDED:
    case DecisionLifecycle::ROLLED_BACK:
    case DecisionLifecycle::EXPIRED:
    case DecisionLifecycle::REJECTED:
      return std::nullopt;
  }
  return std::nullopt;
}

bool decision_lifecycle_terminal(DecisionLifecycle lifecycle) noexcept {
  switch (lifecycle) {
    case DecisionLifecycle::SUPPRESSED:
    case DecisionLifecycle::SUPERSEDED:
    case DecisionLifecycle::ROLLED_BACK:
    case DecisionLifecycle::EXPIRED:
    case DecisionLifecycle::REJECTED:
      return true;
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Currentness
// ---------------------------------------------------------------------------

std::string_view to_string(Currentness currentness) noexcept {
  switch (currentness) {
    case Currentness::CURRENT:
      return "CURRENT";
    case Currentness::STALE_EVIDENCE:
      return "STALE_EVIDENCE";
    case Currentness::STALE_PATH_AUTHORITY:
      return "STALE_PATH_AUTHORITY";
    case Currentness::STALE_MULTIPATH_SET:
      return "STALE_MULTIPATH_SET";
    case Currentness::STALE_ROUTE:
      return "STALE_ROUTE";
    case Currentness::STALE_POLICY:
      return "STALE_POLICY";
    case Currentness::STALE_EPOCH:
      return "STALE_EPOCH";
    case Currentness::FENCED_PUBLISHER:
      return "FENCED_PUBLISHER";
    case Currentness::HOLD_DOWN_ACTIVE:
      return "HOLD_DOWN_ACTIVE";
    case Currentness::COOLDOWN_ACTIVE:
      return "COOLDOWN_ACTIVE";
    case Currentness::REVALIDATION_REQUIRED:
      return "REVALIDATION_REQUIRED";
  }
  return "UNKNOWN";
}

std::optional<Currentness> parse_currentness(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 11; ++raw) {
    const auto value = static_cast<Currentness>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

bool valid_currentness(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 11; }

}  // namespace adaptive_routing

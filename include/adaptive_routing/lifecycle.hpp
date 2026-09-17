// Lifecycle, currentness and transition tables.
//
// Lifecycle is what an object *is*. Currentness is whether the facts an object
// depends on are still the facts the runtime believes in. They are deliberately
// different types: a policy can be ACTIVE and its decision STALE_EVIDENCE, and
// collapsing the two into one boolean is exactly the confusion this runtime
// exists to prevent.
#ifndef ADAPTIVE_ROUTING_LIFECYCLE_HPP
#define ADAPTIVE_ROUTING_LIFECYCLE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Policy lifecycle
// ---------------------------------------------------------------------------

enum class PolicyLifecycle : std::uint8_t {
  DECLARED = 1,
  ACTIVE = 2,
  SUSPENDED = 3,
  REVALIDATION_REQUIRED = 4,
  REVOKED = 5,
  SUPERSEDED = 6,
  RETIRED = 7,
};

enum class PolicyEvent : std::uint8_t {
  ACTIVATE = 1,
  SUSPEND = 2,
  RESUME = 3,
  REQUIRE_REVALIDATION = 4,
  REVALIDATE = 5,
  REVOKE = 6,
  SUPERSEDE = 7,
  RETIRE = 8,
};

[[nodiscard]] std::string_view to_string(PolicyLifecycle lifecycle) noexcept;
[[nodiscard]] std::optional<PolicyLifecycle> parse_policy_lifecycle(std::string_view text) noexcept;
[[nodiscard]] bool valid_policy_lifecycle(std::uint8_t raw) noexcept;

[[nodiscard]] std::string_view to_string(PolicyEvent event) noexcept;
[[nodiscard]] std::optional<PolicyEvent> parse_policy_event(std::string_view text) noexcept;
[[nodiscard]] bool valid_policy_event(std::uint8_t raw) noexcept;

// The complete transition table. Returns nullopt for every undefined
// (state, event) pair; the caller turns that into a structured rejection. Every
// state/event pair in the 7x8 table is exercised by the test suite.
[[nodiscard]] std::optional<PolicyLifecycle> apply_policy_event(PolicyLifecycle state,
                                                               PolicyEvent event) noexcept;

// A lifecycle that admits no further event. A retired policy never reactivates.
[[nodiscard]] bool policy_lifecycle_terminal(PolicyLifecycle lifecycle) noexcept;
// A lifecycle in which new adaptation decisions may be committed.
[[nodiscard]] bool policy_lifecycle_adaptable(PolicyLifecycle lifecycle) noexcept;

// ---------------------------------------------------------------------------
// Decision lifecycle
// ---------------------------------------------------------------------------

enum class DecisionLifecycle : std::uint8_t {
  PROPOSED = 1,
  ELIGIBLE = 2,
  SUPPRESSED = 3,
  COMMITTED = 4,
  SUPERSEDED = 5,
  ROLLED_BACK = 6,
  REVALIDATION_REQUIRED = 7,
  EXPIRED = 8,
  REJECTED = 9,
};

enum class DecisionEvent : std::uint8_t {
  MARK_ELIGIBLE = 1,
  SUPPRESS = 2,
  COMMIT = 3,
  SUPERSEDE = 4,
  ROLLBACK = 5,
  REQUIRE_REVALIDATION = 6,
  EXPIRE = 7,
  REJECT = 8,
};

[[nodiscard]] std::string_view to_string(DecisionLifecycle lifecycle) noexcept;
[[nodiscard]] std::optional<DecisionLifecycle> parse_decision_lifecycle(std::string_view text) noexcept;
[[nodiscard]] bool valid_decision_lifecycle(std::uint8_t raw) noexcept;

[[nodiscard]] std::string_view to_string(DecisionEvent event) noexcept;
[[nodiscard]] std::optional<DecisionEvent> parse_decision_event(std::string_view text) noexcept;
[[nodiscard]] bool valid_decision_event(std::uint8_t raw) noexcept;

// The complete 9x8 decision transition table.
[[nodiscard]] std::optional<DecisionLifecycle> apply_decision_event(DecisionLifecycle state,
                                                                   DecisionEvent event) noexcept;

[[nodiscard]] bool decision_lifecycle_terminal(DecisionLifecycle lifecycle) noexcept;

// ---------------------------------------------------------------------------
// Currentness
// ---------------------------------------------------------------------------

// Why the runtime does or does not currently believe a fact. Distinct values
// are kept distinct: an operator asking "why is this decision stale?" must get
// the actual cause, not a boolean.
enum class Currentness : std::uint8_t {
  CURRENT = 1,
  STALE_EVIDENCE = 2,
  STALE_PATH_AUTHORITY = 3,
  STALE_MULTIPATH_SET = 4,
  STALE_ROUTE = 5,
  STALE_POLICY = 6,
  STALE_EPOCH = 7,
  FENCED_PUBLISHER = 8,
  HOLD_DOWN_ACTIVE = 9,
  COOLDOWN_ACTIVE = 10,
  REVALIDATION_REQUIRED = 11,
};

[[nodiscard]] std::string_view to_string(Currentness currentness) noexcept;
[[nodiscard]] std::optional<Currentness> parse_currentness(std::string_view text) noexcept;
[[nodiscard]] bool valid_currentness(std::uint8_t raw) noexcept;

// CURRENT alone is usable authority. Every other value names a concrete reason
// the runtime refuses to treat the dependent fact as live.
[[nodiscard]] constexpr bool currentness_is_current(Currentness value) noexcept {
  return value == Currentness::CURRENT;
}

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_LIFECYCLE_HPP

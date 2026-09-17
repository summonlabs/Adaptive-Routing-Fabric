// Versioned, integrity-checked durable state.
//
// WHAT IS PERSISTED
// -----------------
// Policies, revocations, the last committed adaptive intent, the last stable
// intent, bounded adaptation history, invalidation watermarks and the
// restart-safe remainder of hold-down/cooldown/dampening state.
//
// WHAT IS NOT PERSISTED
// ---------------------
// Live process authority. No worker boot incarnation, no session identity and
// no live publisher registration survives a restart. Recovered policies are
// revalidated against fresh upstream state before they can adapt again.
//
// RESTART-SAFE TIME
// -----------------
// Raw monotonic ticks are never serialized: they are meaningless in a different
// boot. Durations are stored as *remaining* values and re-armed against the new
// boot's monotonic clock, which can extend an interval but never shorten it.
#ifndef ADAPTIVE_ROUTING_PERSISTENCE_HPP
#define ADAPTIVE_ROUTING_PERSISTENCE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/decision.hpp"
#include "adaptive_routing/policy.hpp"
#include "adaptive_routing/view.hpp"

namespace adaptive_routing {

// Restart-safe timing remainder for one policy.
struct DurableTiming {
  AdaptivePolicyId policy;
  bool hold_down_active = false;
  Ticks hold_down_remaining = 0;
  AdaptivePolicyGeneration hold_down_policy_generation;
  PathId hold_down_locked_path;
  bool cooldown_active = false;
  Ticks cooldown_remaining = 0;
  std::uint32_t dampening_penalty = 0;
  Ticks dampening_decay_remaining = 0;
  // Adaptation timestamps inside the current churn window, as ages rather than
  // absolute ticks.
  std::vector<Ticks> churn_ages;
};

// A durable preference is bound to the policy that owns it, so that two
// policies targeting the same route can never have their recovered intent
// confused with each other.
struct DurablePreference {
  AdaptivePolicyId policy;
  RoutingPreference preference;
};

struct DurableStable {
  AdaptivePolicyId policy;
  StableState stable;
};

// History is bound to the policy that owns it, so that a recovered engine can
// rebuild both the per-policy history and the decision journal, and so that a
// second save after a recovery does not quietly drop the history section.
struct DurableHistoryEntry {
  AdaptivePolicyId policy;
  AdaptationRecord record;
};

struct DurableState {
  std::uint32_t format_version = persistence_format_version;
  // The epoch that was current when the state was written. Recovery consumes the
  // next epoch; the persisted one is never reused as live authority.
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  EvidenceGeneration evidence_generation;
  Watermark evidence_watermark;
  Watermark upstream_watermark;
  std::vector<AdaptivePolicy> policies;
  std::vector<RevocationRecord> revocations;
  std::vector<DurablePreference> preferences;
  std::vector<DurableStable> stable_states;
  std::vector<DurableTiming> timings;
  std::vector<DurableHistoryEntry> history;
};

// Deterministic encoding. Layout:
//   magic "ARFP" | format version | record count | records | integrity trailer
// Every record is length-prefixed and bounded; the whole store is bounded by
// Limits::max_store_bytes.
[[nodiscard]] std::string encode_durable_state(const DurableState& state);

enum class StoreDecodeStatus : std::uint8_t {
  OK = 0,
  EMPTY = 1,
  BAD_MAGIC = 2,
  BAD_VERSION = 3,
  TRUNCATED = 4,
  INTEGRITY = 5,
  MALFORMED = 6,
  TRAILING_BYTES = 7,
  DUPLICATE_POLICY = 8,
  INVALID_GENERATION = 9,
  IMPOSSIBLE_LIFECYCLE = 10,
  MALFORMED_METRIC = 11,
  MALFORMED_EVIDENCE_BINDING = 12,
  INVALID_PREFERRED_CANDIDATE = 13,
  TIMING_WITHOUT_POLICY = 14,
  ABSURD_COUNT = 15,
  // Named COUNTER_OVERFLOW rather than OVERFLOW because several platform headers
  // define a macro of the latter name; an enumerator that a header can rewrite is
  // not a stable identifier.
  COUNTER_OVERFLOW = 16,
  TOO_LARGE = 17,
  MALFORMED_TIMING = 18,
};

[[nodiscard]] std::string_view to_string(StoreDecodeStatus status) noexcept;

struct StoreDecodeResult {
  StoreDecodeStatus status = StoreDecodeStatus::OK;
  std::string detail;
  DurableState state;

  [[nodiscard]] bool ok() const noexcept { return status == StoreDecodeStatus::OK; }
};

[[nodiscard]] StoreDecodeResult decode_durable_state(std::string_view bytes);

// Atomic replacement: the bytes are written to a sibling temporary file, flushed
// and then moved over the destination, so a crash mid-save leaves either the old
// store or the new one, never a half-written file.
[[nodiscard]] bool write_store_atomic(const std::string& path, std::string_view bytes,
                                      std::string& error);
[[nodiscard]] std::optional<std::string> read_store_bytes(const std::string& path, std::string& error);

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_PERSISTENCE_HPP

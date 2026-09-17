// Deterministic digests, immutable snapshots, deterministic diffs and
// structured explanations.
//
// DIGESTS ARE NOT CRYPTOGRAPHY
// ----------------------------
// The digest below is a deterministic non-cryptographic hash used for integrity
// checking, change detection and stale-decision comparison. It is not a
// signature, it is not a MAC and it provides no authentication. Adaptive
// Routing Fabric does not claim cryptographic authentication anywhere.
#ifndef ADAPTIVE_ROUTING_VIEW_HPP
#define ADAPTIVE_ROUTING_VIEW_HPP

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/decision.hpp"
#include "adaptive_routing/evidence.hpp"
#include "adaptive_routing/policy.hpp"

namespace adaptive_routing {

struct AdaptationSnapshot;

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

// Incremental deterministic digest over a canonical little-endian byte
// encoding. Two digests are equal exactly when the written byte sequences are
// equal, so all writers must agree on field order and encoding.
class Digest {
 public:
  Digest() noexcept;

  void write_u8(std::uint8_t value) noexcept;
  void write_u16(std::uint16_t value) noexcept;
  void write_u32(std::uint32_t value) noexcept;
  void write_u64(std::uint64_t value) noexcept;
  void write_i64(std::int64_t value) noexcept;
  void write_bool(bool value) noexcept;
  void write_bytes(std::string_view bytes) noexcept;
  // Length-prefixed, so that concatenation is unambiguous.
  void write_string(std::string_view text) noexcept;
  void write_tag(std::string_view tag) noexcept;

  [[nodiscard]] std::uint64_t low() const noexcept { return low_; }
  [[nodiscard]] std::uint64_t high() const noexcept { return high_; }
  // 32 lowercase hex characters: low half first.
  [[nodiscard]] std::string hex() const;

 private:
  std::uint64_t low_;
  std::uint64_t high_;
};

// ---------------------------------------------------------------------------
// Semantic digests
// ---------------------------------------------------------------------------

// Digest of a policy's semantic state: identity, scope, complete semantics,
// lifecycle and generation. Non-semantic values (ticks, session ids, process
// identity) are excluded so that the same policy semantics digest identically
// on every machine and every run.
[[nodiscard]] std::string policy_semantic_digest(const AdaptivePolicy& policy);

// Digest of a committed or suppressed decision's semantic content.
//
// Included:  policy identity, policy generation, lifecycle, cause, outcome,
//            suppression reason, epoch, route and route generation, multipath
//            set and generation, evidence generation, watermarks, current and
//            target preference with their authority generations, adaptation and
//            transition generations, scoring version, ranking (path,
//            eligibility, quality, score, metrics, priority, improvements).
//
// Excluded:  decision id, evaluation id, evidence snapshot id, worker boot id,
//            mutation attempt id, monotonic timestamps, candidate counters that
//            are derived from the ranking.
[[nodiscard]] std::string decision_digest(const AdaptationDecision& decision);

// Digest of a complete snapshot's semantic content.
[[nodiscard]] std::string snapshot_digest(const AdaptationSnapshot& snapshot);

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

struct CandidateView {
  CandidateBinding binding;
  bool eligible = false;
  SuppressionReason rejection = SuppressionReason::NONE;
  // The weakest evidence quality class the candidate's score depends on.
  EvidenceQuality quality = EvidenceQuality::ESTIMATED;
  std::optional<std::uint64_t> score;
  std::vector<MetricValue> metrics;
  std::uint32_t priority = 0;
  bool current_preference = false;
  bool previous_preference = false;
  std::uint64_t path_watermark = 0;
};

struct AdaptationRecord {
  AdaptationDecisionId decision;
  DecisionLifecycle lifecycle = DecisionLifecycle::PROPOSED;
  Outcome outcome = Outcome::NO_CHANGE;
  SuppressionReason suppression = SuppressionReason::NONE;
  AdaptationCause cause = AdaptationCause::DECLARED;
  PathId from_path;
  PathId to_path;
  AdaptationGeneration adaptation_generation;
  EvidenceGeneration evidence_generation;
  CoordinatorEpoch epoch;
  Ticks committed_at = 0;
  std::string digest;
};

// An immutable point-in-time view of one policy. Returned by value: the caller
// owns a frozen value that no later mutation can alter.
struct AdaptationSnapshot {
  SnapshotId id;
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  AdaptivePolicyId policy;
  AdaptivePolicyGeneration policy_generation;
  AdaptivePolicyName policy_name;
  PolicyScope scope;
  PolicyLifecycle lifecycle = PolicyLifecycle::DECLARED;
  PolicySemantics semantics;
  RoutingPreference preference;
  StableState stable;
  std::vector<CandidateView> candidates;
  EvidenceSnapshotPtr evidence;
  Currentness currentness = Currentness::CURRENT;
  std::vector<Currentness> blockers;
  bool hold_down_active = false;
  Ticks hold_down_remaining = 0;
  bool cooldown_active = false;
  Ticks cooldown_remaining = 0;
  std::uint32_t dampening_penalty = 0;
  AdaptationGeneration adaptation_generation;
  TransitionGeneration transition_generation;
  EvidenceGeneration evidence_generation;
  Watermark evidence_watermark;
  Watermark upstream_watermark;
  std::vector<AdaptationRecord> history;
  std::string digest;
  Ticks captured_at = 0;

  [[nodiscard]] const CandidateView* find_candidate(const PathId& path) const noexcept;
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Diffs
// ---------------------------------------------------------------------------

enum class DiffKind : std::uint8_t {
  POLICY_CHANGED = 1,
  POLICY_LIFECYCLE_CHANGED = 2,
  CANDIDATE_ELIGIBILITY_CHANGED = 3,
  EVIDENCE_GENERATION_CHANGED = 4,
  PREFERRED_PATH_CHANGED = 5,
  ADAPTATION_SUPPRESSED = 6,
  HOLD_DOWN_ENTERED = 7,
  HOLD_DOWN_EXITED = 8,
  COOLDOWN_ENTERED = 9,
  COOLDOWN_EXITED = 10,
  AUTHORITY_CHANGED = 11,
  CURRENTNESS_CHANGED = 12,
  STABLE_STATE_CHANGED = 13,
  DAMPENING_CHANGED = 14,
  TRANSITION_CHANGED = 15,
};

[[nodiscard]] std::string_view to_string(DiffKind kind) noexcept;
[[nodiscard]] bool valid_diff_kind(std::uint8_t raw) noexcept;

struct DiffEntry {
  DiffKind kind = DiffKind::POLICY_CHANGED;
  std::string field;
  std::string before;
  std::string after;
};

struct AdaptationDiff {
  SnapshotId from;
  SnapshotId to;
  AdaptivePolicyId policy;
  std::vector<DiffEntry> entries;

  [[nodiscard]] bool empty() const noexcept { return entries.empty(); }
  [[nodiscard]] std::string render() const;
};

// Deterministic: entries are ordered by (kind, field), so two diffs of the same
// two snapshots are byte-identical regardless of how the snapshots were built.
[[nodiscard]] AdaptationDiff compute_diff(const AdaptationSnapshot& before,
                                          const AdaptationSnapshot& after);

// ---------------------------------------------------------------------------
// Explanations
// ---------------------------------------------------------------------------

enum class ExplanationTopic : std::uint8_t {
  WHY_ADAPTED = 1,
  WHY_NOT_ADAPTED = 2,
  EVIDENCE_THRESHOLD = 3,
  STALE_EVIDENCE = 4,
  REJECTED_CANDIDATE = 5,
  CANDIDATE_COMPARISON = 6,
  HYSTERESIS = 7,
  HOLD_DOWN = 8,
  STALE_GENERATION = 9,
  ROLLBACK_REFUSED = 10,
  AUTHORITY_OWNER = 11,
  GOVERNING_EPOCH = 12,
};

[[nodiscard]] std::string_view to_string(ExplanationTopic topic) noexcept;
[[nodiscard]] std::optional<ExplanationTopic> parse_explanation_topic(std::string_view text) noexcept;
[[nodiscard]] bool valid_explanation_topic(std::uint8_t raw) noexcept;

struct ExplanationEntry {
  std::string key;
  std::string value;
};

struct Explanation {
  ExplanationTopic topic = ExplanationTopic::WHY_NOT_ADAPTED;
  AdaptivePolicyId policy;
  AdaptationDecisionId decision;
  Outcome outcome = Outcome::NO_CHANGE;
  SuppressionReason suppression = SuppressionReason::NONE;
  std::vector<ExplanationEntry> entries;

  [[nodiscard]] const std::string* find(std::string_view key) const noexcept;
  // Deterministic rendering: one "key: value" line per entry in insertion
  // order, which is the order the runtime established them.
  [[nodiscard]] std::string render() const;
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_VIEW_HPP

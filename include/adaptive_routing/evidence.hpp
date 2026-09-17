// Evidence contracts: samples, provenance, aggregation, freshness, snapshots.
//
// Adaptive Routing Fabric consumes evidence. It does not collect telemetry, it
// does not query a vendor monitoring system and it never fabricates a sample.
// Evidence enters the runtime through an explicit, bounded, provenance-bound
// publication and is stored as exact bounded integers.
//
// FRESHNESS IS NOT AUTHORITY
// --------------------------
// A recent sample is not automatically authoritative. A sample is usable only
// when its source generation is the current one, its scope matches the policy
// scope, its quality meets the policy's minimum, and its age and observation
// window satisfy the policy's declared freshness rules. Timestamps are never
// treated as authority for anything else.
#ifndef ADAPTIVE_ROUTING_EVIDENCE_HPP
#define ADAPTIVE_ROUTING_EVIDENCE_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/clock.hpp"
#include "adaptive_routing/ids.hpp"
#include "adaptive_routing/metrics.hpp"

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Quality and provenance class
// ---------------------------------------------------------------------------

// Declared by the publisher and recorded with every sample. RANK is used by the
// deterministic candidate ordering; a higher rank is trusted more.
enum class EvidenceQuality : std::uint8_t {
  PRIMARY = 1,
  AGGREGATED = 2,
  OPERATOR = 3,
  ESTIMATED = 4,
};

[[nodiscard]] std::string_view to_string(EvidenceQuality quality) noexcept;
[[nodiscard]] std::optional<EvidenceQuality> parse_evidence_quality(std::string_view text) noexcept;
[[nodiscard]] bool valid_evidence_quality(std::uint8_t raw) noexcept;
[[nodiscard]] std::uint32_t evidence_quality_rank(EvidenceQuality quality) noexcept;

// ---------------------------------------------------------------------------
// Samples and aggregates
// ---------------------------------------------------------------------------

struct EvidenceSample {
  PathId path;
  MetricValue value;
  // Monotonic tick at which the coordinator accepted the sample. Never a wall
  // clock, never persisted as an absolute value.
  Ticks accepted_at = 0;
  // Publisher-supplied, per-source monotonic observation index. Ordering by
  // observation index is stable and independent of arrival order.
  std::uint64_t observation_sequence = 0;
};

struct EvidenceAggregate {
  MetricValue value;
  std::uint32_t sample_count = 0;
  Ticks oldest_observed_at = 0;
  Ticks newest_observed_at = 0;
  AggregationKind aggregation = AggregationKind::MEAN;
  std::uint32_t ewma_alpha_bps = 0;
  // True when at least one sample contributed.
  [[nodiscard]] bool valid() const noexcept { return sample_count != 0 && value.valid(); }
  // Monotonic age of the newest contributing sample.
  [[nodiscard]] Ticks age(Ticks now) const noexcept {
    return now >= newest_observed_at ? now - newest_observed_at : 0;
  }
  // Contiguous observation span covered by the retained samples.
  [[nodiscard]] Ticks window() const noexcept {
    return newest_observed_at >= oldest_observed_at ? newest_observed_at - oldest_observed_at : 0;
  }
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Publications
// ---------------------------------------------------------------------------

struct EvidencePublication {
  EvidenceSourceId source;
  EvidenceSourceGeneration source_generation;
  EvidenceQuality quality = EvidenceQuality::PRIMARY;
  PathId path;
  MetricValue value;
  std::uint64_t observation_sequence = 0;

  [[nodiscard]] bool well_formed() const noexcept {
    return source.valid() && source_generation.valid() && path.valid() && value.valid();
  }
};

// ---------------------------------------------------------------------------
// Requirements
// ---------------------------------------------------------------------------

// A policy declares exactly which evidence it needs and how fresh it must be.
// Missing or stale required evidence fails closed: the candidate is not
// eligible for an evidence-driven superiority claim.
struct EvidenceRequirement {
  MetricKind kind = MetricKind::PATH_LATENCY;
  AggregationKind aggregation = AggregationKind::MEAN;
  std::uint32_t ewma_alpha_bps = 2500;
  std::uint32_t min_samples = 1;
  // Maximum allowed monotonic age of the newest contributing sample.
  Ticks max_age = 0;
  // Minimum required observation span between the oldest and the newest
  // retained contributing sample.
  Ticks min_window = 0;
  EvidenceQuality min_quality = EvidenceQuality::AGGREGATED;
  // When false the metric is optional: it is used when present and its absence
  // never blocks adaptation.
  bool required = true;

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Evidence snapshots
// ---------------------------------------------------------------------------

struct EvidenceBinding {
  EvidenceSourceId source;
  EvidenceSourceGeneration source_generation;
  PathId path;
  MetricKind kind = MetricKind::PATH_LATENCY;

  [[nodiscard]] friend bool operator==(const EvidenceBinding& a, const EvidenceBinding& b) noexcept {
    return a.source == b.source && a.source_generation == b.source_generation && a.path == b.path &&
           a.kind == b.kind;
  }
  [[nodiscard]] friend bool operator<(const EvidenceBinding& a, const EvidenceBinding& b) noexcept {
    if (a.source != b.source) return a.source < b.source;
    if (a.source_generation != b.source_generation) return a.source_generation < b.source_generation;
    if (a.path != b.path) return a.path < b.path;
    return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
  }
};

struct ResolvedEvidence {
  PathId path;
  MetricKind kind = MetricKind::PATH_LATENCY;
  EvidenceQuality quality = EvidenceQuality::PRIMARY;
  EvidenceSourceId source;
  EvidenceSourceGeneration source_generation;
  EvidenceAggregate aggregate;
};

// An immutable, self-contained view of every evidence value that contributed to
// an evaluation. Held by std::shared_ptr<const EvidenceSnapshot> so that an
// evaluation keeps reading exactly the evidence it snapshotted, even while new
// evidence is published concurrently.
class EvidenceSnapshot {
 public:
  EvidenceSnapshot() = default;

  [[nodiscard]] const EvidenceSnapshotId& id() const noexcept { return id_; }
  [[nodiscard]] EvidenceGeneration generation() const noexcept { return generation_; }
  [[nodiscard]] CoordinatorEpoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] Ticks captured_at() const noexcept { return captured_at_; }
  [[nodiscard]] const std::vector<EvidenceBinding>& bindings() const noexcept { return bindings_; }
  [[nodiscard]] const std::vector<ResolvedEvidence>& values() const noexcept { return values_; }

  [[nodiscard]] const ResolvedEvidence* find(const PathId& path, MetricKind kind) const noexcept;

 private:
  friend class EvidenceSnapshotBuilder;
  EvidenceSnapshotId id_;
  EvidenceGeneration generation_;
  CoordinatorEpoch epoch_;
  Ticks captured_at_ = 0;
  std::vector<EvidenceBinding> bindings_;
  std::vector<ResolvedEvidence> values_;
};

using EvidenceSnapshotPtr = std::shared_ptr<const EvidenceSnapshot>;

// Structural builder used by the engine and by persistence recovery. Not part
// of the ordinary caller surface: callers read snapshots, they do not author
// them.
class EvidenceSnapshotBuilder {
 public:
  EvidenceSnapshotBuilder(EvidenceSnapshotId id, EvidenceGeneration generation,
                          CoordinatorEpoch epoch, Ticks captured_at);

  void add_binding(EvidenceBinding binding);
  void add_value(ResolvedEvidence value);
  [[nodiscard]] EvidenceSnapshotPtr finish();

 private:
  EvidenceSnapshot snapshot_;
};

// ---------------------------------------------------------------------------
// Evidence series (bounded retention)
// ---------------------------------------------------------------------------

// A bounded ring of retained samples for one (source, path, metric). The ring
// capacity is Limits::max_evidence_samples_per_series and is consulted on every
// publication.
struct EvidenceSeriesView {
  EvidenceSourceId source;
  EvidenceSourceGeneration source_generation;
  EvidenceQuality quality = EvidenceQuality::PRIMARY;
  PathId path;
  MetricKind kind = MetricKind::PATH_LATENCY;
  std::uint32_t retained = 0;
  std::uint64_t total_published = 0;
  Ticks oldest_accepted_at = 0;
  Ticks newest_accepted_at = 0;
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_EVIDENCE_HPP

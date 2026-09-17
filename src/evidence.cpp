// Evidence contracts.
#include "adaptive_routing/evidence.hpp"

#include <algorithm>
#include <utility>

namespace adaptive_routing {

std::string_view to_string(EvidenceQuality quality) noexcept {
  switch (quality) {
    case EvidenceQuality::PRIMARY:
      return "PRIMARY";
    case EvidenceQuality::AGGREGATED:
      return "AGGREGATED";
    case EvidenceQuality::OPERATOR:
      return "OPERATOR";
    case EvidenceQuality::ESTIMATED:
      return "ESTIMATED";
  }
  return "UNKNOWN";
}

std::optional<EvidenceQuality> parse_evidence_quality(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 4; ++raw) {
    const auto quality = static_cast<EvidenceQuality>(raw);
    if (to_string(quality) == text) {
      return quality;
    }
  }
  return std::nullopt;
}

bool valid_evidence_quality(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 4; }

std::uint32_t evidence_quality_rank(EvidenceQuality quality) noexcept {
  switch (quality) {
    case EvidenceQuality::PRIMARY:
      return 4;
    case EvidenceQuality::AGGREGATED:
      return 3;
    case EvidenceQuality::OPERATOR:
      return 2;
    case EvidenceQuality::ESTIMATED:
      return 1;
  }
  return 0;
}

std::string EvidenceAggregate::render() const {
  if (!valid()) {
    return "absent";
  }
  std::string text = value.render();
  text += " samples=" + std::to_string(sample_count);
  text += " window_us=" + std::to_string(window() / ticks_per_microsecond);
  text += " agg=" + std::string(to_string(aggregation));
  return text;
}

// ---------------------------------------------------------------------------
// EvidenceSnapshot
// ---------------------------------------------------------------------------

const ResolvedEvidence* EvidenceSnapshot::find(const PathId& path, MetricKind kind) const noexcept {
  // The value vector is kept in canonical (path, kind) order by the builder, so
  // the lookup is a binary search rather than a linear scan.
  std::size_t low = 0;
  std::size_t high = values_.size();
  const auto kind_raw = static_cast<std::uint8_t>(kind);
  while (low < high) {
    const std::size_t middle = low + (high - low) / 2;
    const ResolvedEvidence& element = values_[middle];
    const bool before = element.path < path ||
                        (element.path == path &&
                         static_cast<std::uint8_t>(element.kind) < kind_raw);
    if (before) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  if (low == values_.size()) {
    return nullptr;
  }
  const ResolvedEvidence& candidate = values_[low];
  if (candidate.path == path && candidate.kind == kind) {
    return &candidate;
  }
  return nullptr;
}

EvidenceSnapshotBuilder::EvidenceSnapshotBuilder(EvidenceSnapshotId id, EvidenceGeneration generation,
                                                 CoordinatorEpoch epoch, Ticks captured_at) {
  snapshot_.id_ = std::move(id);
  snapshot_.generation_ = generation;
  snapshot_.epoch_ = epoch;
  snapshot_.captured_at_ = captured_at;
}

void EvidenceSnapshotBuilder::add_binding(EvidenceBinding binding) {
  snapshot_.bindings_.push_back(std::move(binding));
}

void EvidenceSnapshotBuilder::add_value(ResolvedEvidence value) {
  snapshot_.values_.push_back(std::move(value));
}

EvidenceSnapshotPtr EvidenceSnapshotBuilder::finish() {
  // Canonical order: bindings by (source, source generation, path, kind) and
  // values by (path, kind). Both orders are total, so a snapshot built from the
  // same facts in any arrival order is byte-identical.
  std::sort(snapshot_.bindings_.begin(), snapshot_.bindings_.end());
  snapshot_.bindings_.erase(std::unique(snapshot_.bindings_.begin(), snapshot_.bindings_.end()),
                            snapshot_.bindings_.end());
  std::sort(snapshot_.values_.begin(), snapshot_.values_.end(),
            [](const ResolvedEvidence& a, const ResolvedEvidence& b) {
              if (a.path != b.path) {
                return a.path < b.path;
              }
              return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
            });
  return std::make_shared<const EvidenceSnapshot>(std::move(snapshot_));
}

}  // namespace adaptive_routing

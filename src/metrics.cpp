// Fixed-point metric representation and deterministic arithmetic.
#include "adaptive_routing/metrics.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <limits>

namespace adaptive_routing {
namespace {

using Limits64 = std::numeric_limits<std::int64_t>;

[[nodiscard]] constexpr bool add_overflows(std::int64_t a, std::int64_t b) noexcept {
  if (b > 0) {
    return a > Limits64::max() - b;
  }
  return a < Limits64::min() - b;
}

[[nodiscard]] constexpr bool multiply_overflows(std::int64_t a, std::int64_t b) noexcept {
  if (a == 0 || b == 0) {
    return false;
  }
  if (a == -1) {
    return b == Limits64::min();
  }
  if (b == -1) {
    return a == Limits64::min();
  }
  const std::int64_t result = a * b;
  return result / b != a;
}

[[nodiscard]] constexpr bool add_ok(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept {
  if (add_overflows(a, b)) {
    return false;
  }
  out = a + b;
  return true;
}

[[nodiscard]] constexpr bool multiply_ok(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept {
  if (multiply_overflows(a, b)) {
    return false;
  }
  out = a * b;
  return true;
}

struct MetricEntry {
  MetricKind kind;
  MetricDescriptor descriptor;
};

constexpr std::int64_t latency_max = 4'000'000'000LL;

const std::array<MetricEntry, 10>& metric_table() {
  static const std::array<MetricEntry, 10> table{{
      {MetricKind::PATH_UTILIZATION,
       MetricDescriptor{MetricKind::PATH_UTILIZATION, MetricUnit::BASIS_POINTS,
                        MetricOrientation::LOWER_IS_BETTER, MetricProvenance::MEASURED, 1, 0,
                        basis_points_scale, "PATH_UTILIZATION"}},
      {MetricKind::LINK_UTILIZATION,
       MetricDescriptor{MetricKind::LINK_UTILIZATION, MetricUnit::BASIS_POINTS,
                        MetricOrientation::LOWER_IS_BETTER, MetricProvenance::MEASURED, 1, 0,
                        basis_points_scale, "LINK_UTILIZATION"}},
      {MetricKind::PATH_LATENCY,
       MetricDescriptor{MetricKind::PATH_LATENCY, MetricUnit::MICROSECONDS,
                        MetricOrientation::LOWER_IS_BETTER, MetricProvenance::MEASURED, 1, 0,
                        latency_max, "PATH_LATENCY"}},
      {MetricKind::QUEUE_PRESSURE,
       MetricDescriptor{MetricKind::QUEUE_PRESSURE, MetricUnit::BASIS_POINTS,
                        MetricOrientation::LOWER_IS_BETTER, MetricProvenance::MEASURED, 1, 0,
                        basis_points_scale, "QUEUE_PRESSURE"}},
      {MetricKind::PACKET_LOSS,
       MetricDescriptor{MetricKind::PACKET_LOSS, MetricUnit::PPM,
                        MetricOrientation::LOWER_IS_BETTER, MetricProvenance::MEASURED, 1, 0,
                        1'000'000LL, "PACKET_LOSS"}},
      {MetricKind::ERROR_RATE,
       MetricDescriptor{MetricKind::ERROR_RATE, MetricUnit::PPM,
                        MetricOrientation::LOWER_IS_BETTER, MetricProvenance::MEASURED, 1, 0,
                        1'000'000LL, "ERROR_RATE"}},
      {MetricKind::HEALTH_DEGRADATION,
       MetricDescriptor{MetricKind::HEALTH_DEGRADATION, MetricUnit::BASIS_POINTS,
                        MetricOrientation::LOWER_IS_BETTER, MetricProvenance::COMPUTED, 1, 0,
                        basis_points_scale, "HEALTH_DEGRADATION"}},
      {MetricKind::CONGESTION_SCORE,
       MetricDescriptor{MetricKind::CONGESTION_SCORE, MetricUnit::BASIS_POINTS,
                        MetricOrientation::LOWER_IS_BETTER, MetricProvenance::COMPUTED, 1, 0,
                        basis_points_scale, "CONGESTION_SCORE"}},
      {MetricKind::PATH_QUALITY,
       MetricDescriptor{MetricKind::PATH_QUALITY, MetricUnit::BASIS_POINTS,
                        MetricOrientation::HIGHER_IS_BETTER, MetricProvenance::COMPUTED, 1, 0,
                        basis_points_scale, "PATH_QUALITY"}},
      {MetricKind::OPERATOR_POLICY_SIGNAL,
       MetricDescriptor{MetricKind::OPERATOR_POLICY_SIGNAL, MetricUnit::FLAG,
                        MetricOrientation::HIGHER_IS_BETTER, MetricProvenance::OPERATOR_DECLARED, 1,
                        0, 1, "OPERATOR_POLICY_SIGNAL"}},
  }};
  return table;
}

[[nodiscard]] const MetricEntry* find_entry(MetricKind kind) noexcept {
  for (const auto& entry : metric_table()) {
    if (entry.kind == kind) {
      return &entry;
    }
  }
  return nullptr;
}

// Nearest-rank order statistic. rank = ceil(percent * count / 100), 1-based,
// clamped into range. Exact for every count including zero (caller guards).
[[nodiscard]] std::int64_t nearest_rank(std::vector<std::int64_t> samples, std::uint32_t percent) {
  std::sort(samples.begin(), samples.end());
  const std::uint64_t count = samples.size();
  const std::uint64_t numerator = static_cast<std::uint64_t>(percent) * count;
  const std::uint64_t rank = (numerator + 99U) / 100U;
  std::uint64_t index = rank == 0 ? 0 : rank - 1;
  if (index >= count) {
    index = count - 1;
  }
  return samples[static_cast<std::size_t>(index)];
}

}  // namespace

// ---------------------------------------------------------------------------
// Descriptors and names
// ---------------------------------------------------------------------------

const MetricDescriptor& describe_metric(MetricKind kind) noexcept {
  const MetricEntry* entry = find_entry(kind);
  static const MetricDescriptor fallback{};
  return entry == nullptr ? fallback : entry->descriptor;
}

std::string_view to_string(MetricKind kind) noexcept {
  const MetricEntry* entry = find_entry(kind);
  return entry == nullptr ? std::string_view("UNKNOWN") : entry->descriptor.name;
}

std::optional<MetricKind> parse_metric_kind(std::string_view text) noexcept {
  for (const auto& entry : metric_table()) {
    if (entry.descriptor.name == text) {
      return entry.kind;
    }
  }
  return std::nullopt;
}

bool valid_metric_kind(std::uint8_t raw) noexcept {
  return find_entry(static_cast<MetricKind>(raw)) != nullptr;
}

std::string_view to_string(MetricUnit unit) noexcept {
  switch (unit) {
    case MetricUnit::BASIS_POINTS:
      return "BASIS_POINTS";
    case MetricUnit::MICROSECONDS:
      return "MICROSECONDS";
    case MetricUnit::PPM:
      return "PPM";
    case MetricUnit::COUNT:
      return "COUNT";
    case MetricUnit::FLAG:
      return "FLAG";
  }
  return "UNKNOWN";
}

std::optional<MetricUnit> parse_metric_unit(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 5; ++raw) {
    const auto unit = static_cast<MetricUnit>(raw);
    if (to_string(unit) == text) {
      return unit;
    }
  }
  return std::nullopt;
}

bool valid_metric_unit(std::uint8_t raw) noexcept {
  return raw >= 1 && raw <= 5;
}

std::string_view to_string(MetricOrientation orientation) noexcept {
  switch (orientation) {
    case MetricOrientation::LOWER_IS_BETTER:
      return "LOWER_IS_BETTER";
    case MetricOrientation::HIGHER_IS_BETTER:
      return "HIGHER_IS_BETTER";
  }
  return "UNKNOWN";
}

bool valid_metric_orientation(std::uint8_t raw) noexcept {
  return raw >= 1 && raw <= 2;
}

std::string_view to_string(MetricProvenance provenance) noexcept {
  switch (provenance) {
    case MetricProvenance::MEASURED:
      return "MEASURED";
    case MetricProvenance::COMPUTED:
      return "COMPUTED";
    case MetricProvenance::OPERATOR_DECLARED:
      return "OPERATOR_DECLARED";
  }
  return "UNKNOWN";
}

bool valid_metric_provenance(std::uint8_t raw) noexcept {
  return raw >= 1 && raw <= 3;
}

std::string_view to_string(AggregationKind kind) noexcept {
  switch (kind) {
    case AggregationKind::MINIMUM:
      return "MINIMUM";
    case AggregationKind::MAXIMUM:
      return "MAXIMUM";
    case AggregationKind::MEAN:
      return "MEAN";
    case AggregationKind::MEDIAN:
      return "MEDIAN";
    case AggregationKind::PERCENTILE_95:
      return "PERCENTILE_95";
    case AggregationKind::EWMA:
      return "EWMA";
  }
  return "UNKNOWN";
}

std::optional<AggregationKind> parse_aggregation_kind(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 6; ++raw) {
    const auto kind = static_cast<AggregationKind>(raw);
    if (to_string(kind) == text) {
      return kind;
    }
  }
  return std::nullopt;
}

bool valid_aggregation_kind(std::uint8_t raw) noexcept {
  return raw >= 1 && raw <= 6;
}

// ---------------------------------------------------------------------------
// MetricValue
// ---------------------------------------------------------------------------

std::optional<MetricValue> MetricValue::make(MetricKind kind, std::int64_t value) noexcept {
  const MetricEntry* entry = find_entry(kind);
  if (entry == nullptr) {
    return std::nullopt;
  }
  return decode(kind, entry->descriptor.unit, entry->descriptor.semantics_version, value);
}

std::optional<MetricValue> MetricValue::decode(MetricKind kind, MetricUnit unit,
                                               std::uint32_t semantics_version,
                                               std::int64_t value) noexcept {
  const MetricEntry* entry = find_entry(kind);
  if (entry == nullptr) {
    return std::nullopt;
  }
  if (entry->descriptor.unit != unit ||
      entry->descriptor.semantics_version != semantics_version) {
    return std::nullopt;
  }
  if (value < entry->descriptor.minimum || value > entry->descriptor.maximum) {
    return std::nullopt;
  }
  MetricValue result;
  result.kind_ = kind;
  result.unit_ = unit;
  result.semantics_version_ = semantics_version;
  result.value_ = value;
  result.valid_ = true;
  return result;
}

bool MetricValue::comparable_with(const MetricValue& other) const noexcept {
  return valid_ && other.valid_ && kind_ == other.kind_ && unit_ == other.unit_ &&
         semantics_version_ == other.semantics_version_;
}

std::string MetricValue::render() const {
  if (!valid_) {
    return "invalid";
  }
  char buffer[160];
  std::snprintf(buffer, sizeof(buffer), "%s=%lld%s(v%u)",
                std::string(describe_metric(kind_).name).c_str(),
                static_cast<long long>(value_), std::string(to_string(unit_)).c_str(),
                semantics_version_);
  return std::string(buffer);
}

// ---------------------------------------------------------------------------
// Deterministic arithmetic
// ---------------------------------------------------------------------------

std::optional<std::uint32_t> relative_improvement_bps(const MetricValue& current,
                                                      const MetricValue& candidate) noexcept {
  if (!current.comparable_with(candidate)) {
    return std::nullopt;
  }
  const bool lower_is_better =
      current.orientation() == MetricOrientation::LOWER_IS_BETTER;
  const bool better = lower_is_better ? candidate.value() < current.value()
                                      : candidate.value() > current.value();
  if (!better) {
    return 0U;
  }
  std::int64_t delta = 0;
  if (!add_ok(candidate.value(), -current.value(), delta)) {
    return std::nullopt;
  }
  if (delta < 0) {
    delta = -delta;
  }
  const std::int64_t base = current.value() < 0 ? -current.value() : current.value();
  if (base == 0) {
    // The current value cannot be improved upon proportionally; a strictly
    // better candidate is a full improvement.
    return basis_points_scale;
  }
  std::int64_t scaled = 0;
  if (!multiply_ok(delta, static_cast<std::int64_t>(basis_points_scale), scaled)) {
    return std::nullopt;
  }
  const std::int64_t result = scaled / base;
  if (result <= 0) {
    return 0U;
  }
  if (result >= static_cast<std::int64_t>(basis_points_scale)) {
    return basis_points_scale;
  }
  return static_cast<std::uint32_t>(result);
}

std::optional<std::uint32_t> normalize_to_basis_points(const MetricValue& value) noexcept {
  if (!value.valid()) {
    return std::nullopt;
  }
  const MetricDescriptor& descriptor = value.descriptor();
  const std::int64_t span = descriptor.maximum - descriptor.minimum;
  if (span <= 0) {
    return std::nullopt;
  }
  const std::int64_t goodness =
      descriptor.orientation == MetricOrientation::LOWER_IS_BETTER
          ? descriptor.maximum - value.value()
          : value.value() - descriptor.minimum;
  if (goodness <= 0) {
    return 0U;
  }
  std::int64_t scaled = 0;
  if (!multiply_ok(goodness, static_cast<std::int64_t>(basis_points_scale), scaled)) {
    return std::nullopt;
  }
  const std::int64_t result = scaled / span;
  if (result <= 0) {
    return 0U;
  }
  if (result >= static_cast<std::int64_t>(basis_points_scale)) {
    return basis_points_scale;
  }
  return static_cast<std::uint32_t>(result);
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

std::optional<std::int64_t> aggregate_samples(AggregationKind aggregation,
                                              std::span<const std::int64_t> samples,
                                              std::uint32_t ewma_alpha_bps) {
  if (samples.empty()) {
    return std::nullopt;
  }
  switch (aggregation) {
    case AggregationKind::MINIMUM:
      return *std::min_element(samples.begin(), samples.end());
    case AggregationKind::MAXIMUM:
      return *std::max_element(samples.begin(), samples.end());
    case AggregationKind::MEAN: {
      std::int64_t sum = 0;
      for (const std::int64_t sample : samples) {
        if (!add_ok(sum, sample, sum)) {
          return std::nullopt;
        }
      }
      return sum / static_cast<std::int64_t>(samples.size());
    }
    case AggregationKind::MEDIAN: {
      std::vector<std::int64_t> copy(samples.begin(), samples.end());
      return nearest_rank(std::move(copy), 50);
    }
    case AggregationKind::PERCENTILE_95: {
      std::vector<std::int64_t> copy(samples.begin(), samples.end());
      return nearest_rank(std::move(copy), 95);
    }
    case AggregationKind::EWMA: {
      if (ewma_alpha_bps > basis_points_scale) {
        return std::nullopt;
      }
      const std::int64_t alpha = static_cast<std::int64_t>(ewma_alpha_bps);
      const std::int64_t complement = static_cast<std::int64_t>(basis_points_scale) - alpha;
      std::int64_t ewma = samples.front();
      for (std::size_t index = 1; index < samples.size(); ++index) {
        std::int64_t weighted_sample = 0;
        std::int64_t weighted_previous = 0;
        if (!multiply_ok(alpha, samples[index], weighted_sample)) {
          return std::nullopt;
        }
        if (!multiply_ok(complement, ewma, weighted_previous)) {
          return std::nullopt;
        }
        std::int64_t total = 0;
        if (!add_ok(weighted_sample, weighted_previous, total)) {
          return std::nullopt;
        }
        ewma = total / static_cast<std::int64_t>(basis_points_scale);
      }
      return ewma;
    }
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Weighted score
// ---------------------------------------------------------------------------

std::optional<std::uint64_t> weighted_score(std::span<const ScoreTerm> terms,
                                            std::span<const MetricValue> values) noexcept {
  if (terms.empty() || terms.size() != values.size()) {
    return std::nullopt;
  }
  std::int64_t numerator = 0;
  for (std::size_t index = 0; index < terms.size(); ++index) {
    if (values[index].kind() != terms[index].kind) {
      return std::nullopt;
    }
    const auto normalized = normalize_to_basis_points(values[index]);
    if (!normalized.has_value()) {
      return std::nullopt;
    }
    std::int64_t weighted = 0;
    if (!multiply_ok(static_cast<std::int64_t>(terms[index].weight_bps),
                     static_cast<std::int64_t>(*normalized), weighted)) {
      return std::nullopt;
    }
    if (!add_ok(numerator, weighted, numerator)) {
      return std::nullopt;
    }
  }
  if (numerator < 0) {
    return std::nullopt;
  }
  const std::int64_t rounded =
      (numerator + static_cast<std::int64_t>(basis_points_scale) / 2) /
      static_cast<std::int64_t>(basis_points_scale);
  if (rounded < 0) {
    return std::nullopt;
  }
  return static_cast<std::uint64_t>(rounded);
}

}  // namespace adaptive_routing

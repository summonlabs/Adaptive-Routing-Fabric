// Fixed-point metric representation and deterministic arithmetic.
//
// Adaptive Routing Fabric never stores an authoritative metric as a floating
// point value. Every metric is an exact integer in a declared unit, bounded by
// the metric's own range, tagged with the semantics version it was produced
// under. NaN and infinity cannot be represented, so they cannot enter policy
// state, a digest, persistence or the wire.
//
// COMPARABILITY
// -------------
// Two metric values are comparable only when their kind, unit and semantics
// version are all equal. Adaptive Routing Fabric never compares values from
// incompatible semantics: such a comparison is a structured
// INCOMPATIBLE_METRIC rejection, not a silent coercion.
//
// ARITHMETIC
// ----------
// Every operation below is exact integer arithmetic with checked overflow. When
// rounding is unavoidable (mean, EWMA, normalisation, weighted score) the
// rounding rule is fixed and documented at the function, so two processes given
// the same inputs produce bit-identical outputs.
#ifndef ADAPTIVE_ROUTING_METRICS_HPP
#define ADAPTIVE_ROUTING_METRICS_HPP

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Metric kinds
// ---------------------------------------------------------------------------

enum class MetricKind : std::uint8_t {
  PATH_UTILIZATION = 1,
  LINK_UTILIZATION = 2,
  PATH_LATENCY = 3,
  QUEUE_PRESSURE = 4,
  PACKET_LOSS = 5,
  ERROR_RATE = 6,
  HEALTH_DEGRADATION = 7,
  CONGESTION_SCORE = 8,
  PATH_QUALITY = 9,
  OPERATOR_POLICY_SIGNAL = 10,
};

enum class MetricUnit : std::uint8_t {
  BASIS_POINTS = 1,
  MICROSECONDS = 2,
  PPM = 3,
  COUNT = 4,
  FLAG = 5,
};

enum class MetricOrientation : std::uint8_t {
  LOWER_IS_BETTER = 1,
  HIGHER_IS_BETTER = 2,
};

// Provenance class of a metric value. Declared per metric kind: an operator
// signal is never interchangeable with a measured sample even when the numeric
// ranges coincide.
enum class MetricProvenance : std::uint8_t {
  MEASURED = 1,
  COMPUTED = 2,
  OPERATOR_DECLARED = 3,
};

struct MetricDescriptor {
  MetricKind kind = MetricKind::PATH_UTILIZATION;
  MetricUnit unit = MetricUnit::BASIS_POINTS;
  MetricOrientation orientation = MetricOrientation::LOWER_IS_BETTER;
  MetricProvenance provenance = MetricProvenance::MEASURED;
  std::uint32_t semantics_version = 1;
  std::int64_t minimum = 0;
  std::int64_t maximum = 10000;
  std::string_view name;
};

[[nodiscard]] const MetricDescriptor& describe_metric(MetricKind kind) noexcept;
[[nodiscard]] std::string_view to_string(MetricKind kind) noexcept;
[[nodiscard]] std::optional<MetricKind> parse_metric_kind(std::string_view text) noexcept;
[[nodiscard]] bool valid_metric_kind(std::uint8_t raw) noexcept;

[[nodiscard]] std::string_view to_string(MetricUnit unit) noexcept;
[[nodiscard]] std::optional<MetricUnit> parse_metric_unit(std::string_view text) noexcept;
[[nodiscard]] bool valid_metric_unit(std::uint8_t raw) noexcept;

[[nodiscard]] std::string_view to_string(MetricOrientation orientation) noexcept;
[[nodiscard]] bool valid_metric_orientation(std::uint8_t raw) noexcept;

[[nodiscard]] std::string_view to_string(MetricProvenance provenance) noexcept;
[[nodiscard]] bool valid_metric_provenance(std::uint8_t raw) noexcept;

// ---------------------------------------------------------------------------
// MetricValue
// ---------------------------------------------------------------------------

// A bounded, unit-tagged, semantics-versioned integer metric value. A default
// constructed value is invalid; every constructor validates against the
// metric's declared range.
class MetricValue {
 public:
  constexpr MetricValue() noexcept = default;

  // Builds a value, deriving unit/orientation/provenance from the metric kind
  // and rejecting anything outside the declared range.
  [[nodiscard]] static std::optional<MetricValue> make(MetricKind kind,
                                                       std::int64_t value) noexcept;

  // Builds a value from an explicitly decoded wire/persistence triple. The
  // unit and semantics version must match the metric kind exactly, otherwise
  // the value is rejected. This is the only path that accepts external units.
  [[nodiscard]] static std::optional<MetricValue> decode(MetricKind kind, MetricUnit unit,
                                                        std::uint32_t semantics_version,
                                                        std::int64_t value) noexcept;

  [[nodiscard]] constexpr bool valid() const noexcept { return valid_; }
  [[nodiscard]] constexpr MetricKind kind() const noexcept { return kind_; }
  [[nodiscard]] constexpr MetricUnit unit() const noexcept { return unit_; }
  [[nodiscard]] constexpr std::uint32_t semantics_version() const noexcept {
    return semantics_version_;
  }
  [[nodiscard]] constexpr std::int64_t value() const noexcept { return value_; }
  [[nodiscard]] const MetricDescriptor& descriptor() const noexcept { return describe_metric(kind_); }
  [[nodiscard]] MetricOrientation orientation() const noexcept {
    return describe_metric(kind_).orientation;
  }

  // Comparability, not equality: same kind, same unit, same semantics version.
  [[nodiscard]] bool comparable_with(const MetricValue& other) const noexcept;

  [[nodiscard]] std::string render() const;

 private:
  MetricKind kind_ = MetricKind::PATH_UTILIZATION;
  MetricUnit unit_ = MetricUnit::BASIS_POINTS;
  std::uint32_t semantics_version_ = 0;
  std::int64_t value_ = 0;
  bool valid_ = false;
};

// ---------------------------------------------------------------------------
// Deterministic arithmetic
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t basis_points_scale = 10000;

// Relative improvement of \p candidate over \p current expressed in basis
// points, using floor rounding. "Improvement" is orientation aware: for a
// lower-is-better metric a smaller candidate value is an improvement.
//
// Degenerate inputs are defined rather than undefined:
//   * incomparable values          -> nullopt
//   * current value == 0           -> 0 bps when the candidate is not strictly
//                                     better, 10000 bps when it is (the current
//                                     value cannot be improved upon
//                                     proportionally, so a strictly better
//                                     candidate is treated as a full
//                                     improvement);
//   * candidate not better         -> 0 bps (never a negative improvement).
[[nodiscard]] std::optional<std::uint32_t> relative_improvement_bps(
    const MetricValue& current, const MetricValue& candidate) noexcept;

// Maps a metric value onto 0..10000 where 10000 is "best representable" and 0
// is "worst representable", using exact integer arithmetic with floor rounding.
[[nodiscard]] std::optional<std::uint32_t> normalize_to_basis_points(
    const MetricValue& value) noexcept;

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

enum class AggregationKind : std::uint8_t {
  MINIMUM = 1,
  MAXIMUM = 2,
  MEAN = 3,
  MEDIAN = 4,
  PERCENTILE_95 = 5,
  EWMA = 6,
};

[[nodiscard]] std::string_view to_string(AggregationKind kind) noexcept;
[[nodiscard]] std::optional<AggregationKind> parse_aggregation_kind(std::string_view text) noexcept;
[[nodiscard]] bool valid_aggregation_kind(std::uint8_t raw) noexcept;

// Deterministic aggregation over a bounded sample vector.
//
//   MINIMUM / MAXIMUM  exact selection.
//   MEAN               floor(sum / count) over the signed sum, computed with
//                      checked i64 arithmetic; an overflowing sum is rejected.
//   MEDIAN             nearest-rank order statistic at rank ceil(50N/100),
//                      1-based, over a deterministic ascending sort.
//   PERCENTILE_95      nearest-rank order statistic at rank ceil(95N/100).
//   EWMA               seeded with the first sample in observation order, then
//                      ewma = floor((alpha*sample + (10000-alpha)*ewma) / 10000)
//                      with alpha in basis points; checked arithmetic.
//
// Returns nullopt when the input is empty, when the alpha is out of range for
// EWMA, or when checked arithmetic overflows.
[[nodiscard]] std::optional<std::int64_t> aggregate_samples(AggregationKind aggregation,
                                                            std::span<const std::int64_t> samples,
                                                            std::uint32_t ewma_alpha_bps = 2500);

// ---------------------------------------------------------------------------
// Weighted score
// ---------------------------------------------------------------------------

// One term of a weighted objective: a metric kind and a weight in basis points.
struct ScoreTerm {
  MetricKind kind = MetricKind::PATH_LATENCY;
  std::uint32_t weight_bps = 0;
};

// Deterministic weighted score:
//   score = ( sum_i weight_i * normalize(value_i) ) / 10000
// with the final division rounded half up. Every term must be present and
// comparable; a missing term yields nullopt so a candidate is never scored from
// absent data. Returns nullopt on overflow.
[[nodiscard]] std::optional<std::uint64_t> weighted_score(
    std::span<const ScoreTerm> terms, std::span<const MetricValue> values) noexcept;

// The formula version bound by every weighted decision. Changing the formula
// requires changing this constant, which makes the semantic change visible in
// digests, snapshots and persistence.
inline constexpr std::uint32_t weighted_score_formula_version = 1;

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_METRICS_HPP

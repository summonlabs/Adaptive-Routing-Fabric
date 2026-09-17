// Metric representation, comparability and deterministic arithmetic.
//
// Every expected value below is computed by hand and written as a literal, so
// the suite pins the rounding rules (floor for improvement and normalisation,
// half up for the weighted score, nearest rank for order statistics) instead of
// restating whatever the implementation happens to return.
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/adaptive_routing.hpp"
#include "test_framework.hpp"

namespace {

using namespace adaptive_routing;

struct ExpectedDescriptor {
  MetricKind kind;
  MetricUnit unit;
  MetricOrientation orientation;
  MetricProvenance provenance;
  std::int64_t minimum;
  std::int64_t maximum;
};

// The declared descriptor for every metric kind, transcribed from the contract.
[[nodiscard]] std::vector<ExpectedDescriptor> expected_descriptors() {
  return {
      {MetricKind::PATH_UTILIZATION, MetricUnit::BASIS_POINTS, MetricOrientation::LOWER_IS_BETTER,
       MetricProvenance::MEASURED, 0, 10000},
      {MetricKind::LINK_UTILIZATION, MetricUnit::BASIS_POINTS, MetricOrientation::LOWER_IS_BETTER,
       MetricProvenance::MEASURED, 0, 10000},
      {MetricKind::PATH_LATENCY, MetricUnit::MICROSECONDS, MetricOrientation::LOWER_IS_BETTER,
       MetricProvenance::MEASURED, 0, 4000000000LL},
      {MetricKind::QUEUE_PRESSURE, MetricUnit::BASIS_POINTS, MetricOrientation::LOWER_IS_BETTER,
       MetricProvenance::MEASURED, 0, 10000},
      {MetricKind::PACKET_LOSS, MetricUnit::PPM, MetricOrientation::LOWER_IS_BETTER,
       MetricProvenance::MEASURED, 0, 1000000},
      {MetricKind::ERROR_RATE, MetricUnit::PPM, MetricOrientation::LOWER_IS_BETTER,
       MetricProvenance::MEASURED, 0, 1000000},
      {MetricKind::HEALTH_DEGRADATION, MetricUnit::BASIS_POINTS,
       MetricOrientation::LOWER_IS_BETTER, MetricProvenance::COMPUTED, 0, 10000},
      {MetricKind::CONGESTION_SCORE, MetricUnit::BASIS_POINTS, MetricOrientation::LOWER_IS_BETTER,
       MetricProvenance::COMPUTED, 0, 10000},
      {MetricKind::PATH_QUALITY, MetricUnit::BASIS_POINTS, MetricOrientation::HIGHER_IS_BETTER,
       MetricProvenance::COMPUTED, 0, 10000},
      {MetricKind::OPERATOR_POLICY_SIGNAL, MetricUnit::FLAG, MetricOrientation::HIGHER_IS_BETTER,
       MetricProvenance::OPERATOR_DECLARED, 0, 1},
  };
}

[[nodiscard]] MetricValue require_value(MetricKind kind, std::int64_t value) {
  const auto made = MetricValue::make(kind, value);
  ARF_CHECK_MSG(made.has_value(), "expected " << to_string(kind) << " to accept " << value);
  return made.value_or(MetricValue{});
}

void check_aggregate(AggregationKind aggregation, const std::vector<std::int64_t>& samples,
                     std::int64_t expected, std::uint32_t alpha = 2500) {
  const auto actual = aggregate_samples(aggregation, samples, alpha);
  ARF_CHECK_MSG(actual.has_value(),
                "expected " << to_string(aggregation) << " to produce a value");
  if (!actual.has_value()) {
    return;
  }
  ARF_CHECK_EQ(*actual, expected);
  ARF_CHECK_MSG(*actual == expected, "aggregation "
                                         << to_string(aggregation) << " over " << samples.size()
                                         << " samples gave " << *actual << ", expected "
                                         << expected);
}

// A different unit than the one a descriptor declares, for the decode mismatch
// cases.
[[nodiscard]] MetricUnit other_unit(MetricUnit declared) {
  return declared == MetricUnit::BASIS_POINTS ? MetricUnit::MICROSECONDS
                                             : MetricUnit::BASIS_POINTS;
}

}  // namespace

ARF_TEST(metric_descriptor_table_is_complete_and_versioned) {
  const std::vector<ExpectedDescriptor> expected = expected_descriptors();
  ARF_CHECK_EQ(expected.size(), static_cast<std::size_t>(10));
  for (const ExpectedDescriptor& entry : expected) {
    const MetricDescriptor& descriptor = describe_metric(entry.kind);
    ARF_CHECK_EQ(descriptor.kind, entry.kind);
    ARF_CHECK_EQ(descriptor.unit, entry.unit);
    ARF_CHECK_EQ(descriptor.orientation, entry.orientation);
    ARF_CHECK_EQ(descriptor.provenance, entry.provenance);
    ARF_CHECK_EQ(descriptor.minimum, entry.minimum);
    ARF_CHECK_EQ(descriptor.maximum, entry.maximum);
    // One semantics version today: a value that carries another one is not
    // comparable with anything this runtime produced.
    ARF_CHECK_EQ(descriptor.semantics_version, static_cast<std::uint32_t>(1));
    ARF_CHECK_EQ(descriptor.name, to_string(entry.kind));
    ARF_CHECK_EQ(parse_metric_kind(descriptor.name), entry.kind);
    ARF_CHECK_EQ(descriptor.maximum > descriptor.minimum, true);
    ARF_CHECK(valid_metric_kind(static_cast<std::uint8_t>(entry.kind)));
  }
  // Orientation is per metric, not global: quality and the operator signal rise
  // with goodness while everything measured falls.
  ARF_CHECK_EQ(describe_metric(MetricKind::PATH_QUALITY).orientation,
               MetricOrientation::HIGHER_IS_BETTER);
  ARF_CHECK_EQ(describe_metric(MetricKind::OPERATOR_POLICY_SIGNAL).orientation,
               MetricOrientation::HIGHER_IS_BETTER);
  ARF_CHECK_EQ(describe_metric(MetricKind::PATH_LATENCY).orientation,
               MetricOrientation::LOWER_IS_BETTER);
  // Provenance separates a measurement from a computed or operator value even
  // when the numeric range coincides.
  ARF_CHECK_EQ(describe_metric(MetricKind::HEALTH_DEGRADATION).provenance,
               MetricProvenance::COMPUTED);
  ARF_CHECK_EQ(describe_metric(MetricKind::OPERATOR_POLICY_SIGNAL).provenance,
               MetricProvenance::OPERATOR_DECLARED);

  ARF_CHECK(!valid_metric_kind(0));
  ARF_CHECK(!valid_metric_kind(11));
  ARF_CHECK(!parse_metric_kind("").has_value());
  ARF_CHECK(!parse_metric_kind("path_latency").has_value());
  ARF_CHECK_EQ(to_string(static_cast<MetricKind>(static_cast<std::uint8_t>(200))),
               std::string_view("UNKNOWN"));

  ARF_CHECK(valid_metric_unit(static_cast<std::uint8_t>(MetricUnit::BASIS_POINTS)));
  ARF_CHECK(valid_metric_unit(static_cast<std::uint8_t>(MetricUnit::FLAG)));
  ARF_CHECK(!valid_metric_unit(0));
  ARF_CHECK(!valid_metric_unit(6));
  ARF_CHECK_EQ(parse_metric_unit(to_string(MetricUnit::MICROSECONDS)), MetricUnit::MICROSECONDS);
  ARF_CHECK(!parse_metric_unit("NANOSECONDS").has_value());
  ARF_CHECK(valid_metric_orientation(1));
  ARF_CHECK(valid_metric_orientation(2));
  ARF_CHECK(!valid_metric_orientation(3));
  ARF_CHECK(valid_metric_provenance(1));
  ARF_CHECK(valid_metric_provenance(3));
  ARF_CHECK(!valid_metric_provenance(4));

  ARF_CHECK_EQ(parse_aggregation_kind(to_string(AggregationKind::PERCENTILE_95)),
               AggregationKind::PERCENTILE_95);
  ARF_CHECK(valid_aggregation_kind(static_cast<std::uint8_t>(AggregationKind::EWMA)));
  ARF_CHECK(!valid_aggregation_kind(0));
  ARF_CHECK(!valid_aggregation_kind(7));
  ARF_CHECK(!parse_aggregation_kind("P95").has_value());
}

ARF_TEST(metric_value_make_enforces_the_declared_range) {
  for (const ExpectedDescriptor& entry : expected_descriptors()) {
    const auto at_minimum = MetricValue::make(entry.kind, entry.minimum);
    ARF_CHECK_MSG(at_minimum.has_value(),
                  "minimum must be representable for " << to_string(entry.kind));
    const auto at_maximum = MetricValue::make(entry.kind, entry.maximum);
    ARF_CHECK_MSG(at_maximum.has_value(),
                  "maximum must be representable for " << to_string(entry.kind));
    // One past either end is rejected rather than clamped.
    ARF_CHECK_MSG(!MetricValue::make(entry.kind, entry.maximum + 1).has_value(),
                  "above the maximum must be rejected for " << to_string(entry.kind));
    ARF_CHECK_MSG(!MetricValue::make(entry.kind, entry.minimum - 1).has_value(),
                  "below the minimum must be rejected for " << to_string(entry.kind));
    if (at_minimum.has_value()) {
      ARF_CHECK_EQ(at_minimum->value(), entry.minimum);
      ARF_CHECK_EQ(at_minimum->kind(), entry.kind);
      ARF_CHECK_EQ(at_minimum->unit(), entry.unit);
      ARF_CHECK_EQ(at_minimum->semantics_version(), static_cast<std::uint32_t>(1));
      ARF_CHECK_EQ(at_minimum->orientation(), entry.orientation);
      ARF_CHECK(at_minimum->valid());
      ARF_CHECK_EQ(at_minimum->descriptor().maximum, entry.maximum);
    }
  }
  // Negative values are outside every declared range: no metric in this runtime
  // is signed.
  ARF_CHECK(!MetricValue::make(MetricKind::PATH_LATENCY, -1).has_value());
  ARF_CHECK(!MetricValue::make(MetricKind::PATH_UTILIZATION, -1).has_value());
  ARF_CHECK(!MetricValue::make(MetricKind::OPERATOR_POLICY_SIGNAL, 2).has_value());
  // An unknown kind has no range to check against, so it is rejected outright.
  ARF_CHECK(!MetricValue::make(static_cast<MetricKind>(0), 0).has_value());
  ARF_CHECK(!MetricValue::make(static_cast<MetricKind>(11), 0).has_value());

  const MetricValue unset;
  ARF_CHECK(!unset.valid());
  ARF_CHECK_EQ(unset.render(), std::string("invalid"));
  const MetricValue latency = require_value(MetricKind::PATH_LATENCY, 1234);
  ARF_CHECK_EQ(latency.render(), latency.render());
  ARF_CHECK(latency.render().find("1234") != std::string::npos);
}

ARF_TEST(metric_decode_rejects_mismatched_unit_and_version) {
  const auto exact =
      MetricValue::decode(MetricKind::PATH_LATENCY, MetricUnit::MICROSECONDS, 1, 100);
  ARF_REQUIRE(exact.has_value());
  ARF_CHECK_EQ(exact->unit(), MetricUnit::MICROSECONDS);
  ARF_CHECK_EQ(exact->semantics_version(), static_cast<std::uint32_t>(1));
  ARF_CHECK_EQ(exact->value(), 100);
  // A value that claims a different unit or a different semantics version than
  // its kind declares is not the same fact and is refused.
  ARF_CHECK(!MetricValue::decode(MetricKind::PATH_LATENCY, MetricUnit::BASIS_POINTS, 1, 100)
                 .has_value());
  ARF_CHECK(!MetricValue::decode(MetricKind::PATH_LATENCY, MetricUnit::MICROSECONDS, 2, 100)
                 .has_value());
  ARF_CHECK(!MetricValue::decode(MetricKind::PATH_LATENCY, MetricUnit::MICROSECONDS, 0, 100)
                 .has_value());
  ARF_CHECK(!MetricValue::decode(MetricKind::PATH_LATENCY, MetricUnit::MICROSECONDS, 1, -1)
                 .has_value());
  ARF_CHECK(!MetricValue::decode(static_cast<MetricKind>(0), MetricUnit::BASIS_POINTS, 1, 0)
                 .has_value());

  for (const ExpectedDescriptor& entry : expected_descriptors()) {
    const MetricDescriptor& descriptor = describe_metric(entry.kind);
    ARF_CHECK(MetricValue::decode(entry.kind, descriptor.unit, descriptor.semantics_version,
                                 descriptor.maximum)
                  .has_value());
    ARF_CHECK(!MetricValue::decode(entry.kind, other_unit(descriptor.unit),
                                   descriptor.semantics_version, descriptor.minimum)
                   .has_value());
    ARF_CHECK(!MetricValue::decode(entry.kind, descriptor.unit, descriptor.semantics_version + 1,
                                   descriptor.minimum)
                   .has_value());
  }
}

ARF_TEST(metric_comparability_is_kind_bound) {
  const MetricValue utilization = require_value(MetricKind::PATH_UTILIZATION, 4000);
  const MetricValue same_kind = require_value(MetricKind::PATH_UTILIZATION, 8000);
  const MetricValue queue = require_value(MetricKind::QUEUE_PRESSURE, 4000);
  const MetricValue latency = require_value(MetricKind::PATH_LATENCY, 4000);
  const MetricValue quality = require_value(MetricKind::PATH_QUALITY, 4000);

  ARF_CHECK(utilization.comparable_with(same_kind));
  ARF_CHECK(same_kind.comparable_with(utilization));
  ARF_CHECK(utilization.comparable_with(utilization));
  // Same unit and same semantics version, different kind: still incomparable.
  ARF_CHECK_EQ(utilization.unit(), queue.unit());
  ARF_CHECK_EQ(utilization.semantics_version(), queue.semantics_version());
  ARF_CHECK(!utilization.comparable_with(queue));
  ARF_CHECK(!utilization.comparable_with(latency));
  ARF_CHECK(!quality.comparable_with(utilization));
  // An unset value carries no kind at all, so it is comparable with nothing,
  // including itself.
  const MetricValue unset;
  ARF_CHECK(!unset.comparable_with(unset));
  ARF_CHECK(!unset.comparable_with(utilization));
  ARF_CHECK(!utilization.comparable_with(unset));

  // A valid value always carries exactly its descriptor's unit and version, so
  // no comparable pair can disagree on either.
  for (const ExpectedDescriptor& entry : expected_descriptors()) {
    const MetricValue value = require_value(entry.kind, entry.minimum);
    ARF_CHECK_EQ(value.unit(), describe_metric(entry.kind).unit);
    ARF_CHECK_EQ(value.semantics_version(), describe_metric(entry.kind).semantics_version);
  }
}

ARF_TEST(relative_improvement_is_orientation_aware_and_floored) {
  const auto improvement = [](MetricKind kind, std::int64_t current, std::int64_t candidate) {
    return relative_improvement_bps(require_value(kind, current), require_value(kind, candidate));
  };

  // Exactly 20% better on a lower-is-better metric is exactly 2000 basis points.
  ARF_CHECK_EQ(improvement(MetricKind::PATH_LATENCY, 1000, 800),
               std::optional<std::uint32_t>(2000));
  ARF_CHECK_EQ(improvement(MetricKind::PATH_UTILIZATION, 10000, 8000),
               std::optional<std::uint32_t>(2000));
  ARF_CHECK_EQ(improvement(MetricKind::PATH_LATENCY, 250, 200), std::optional<std::uint32_t>(2000));
  ARF_CHECK_EQ(improvement(MetricKind::PATH_LATENCY, 5000, 4000),
               std::optional<std::uint32_t>(2000));
  // Not better: never a negative improvement.
  ARF_CHECK_EQ(improvement(MetricKind::PATH_LATENCY, 1000, 1000),
               std::optional<std::uint32_t>(0));
  ARF_CHECK_EQ(improvement(MetricKind::PATH_LATENCY, 1000, 1200),
               std::optional<std::uint32_t>(0));
  ARF_CHECK_EQ(improvement(MetricKind::PATH_LATENCY, 1000, 1000000),
               std::optional<std::uint32_t>(0));
  // Floor rounding: 1 part in 3 is 3333 bps, not 3334.
  ARF_CHECK_EQ(improvement(MetricKind::PATH_LATENCY, 3, 2), std::optional<std::uint32_t>(3333));
  ARF_CHECK_EQ(improvement(MetricKind::PATH_LATENCY, 3, 1), std::optional<std::uint32_t>(6666));
  // A full improvement cannot exceed unity.
  ARF_CHECK_EQ(improvement(MetricKind::PATH_LATENCY, 1, 0),
               std::optional<std::uint32_t>(10000));
  // Higher-is-better metrics invert the comparison.
  ARF_CHECK_EQ(improvement(MetricKind::PATH_QUALITY, 6000, 7000),
               std::optional<std::uint32_t>(1666));
  ARF_CHECK_EQ(improvement(MetricKind::PATH_QUALITY, 7000, 6000),
               std::optional<std::uint32_t>(0));
  ARF_CHECK_EQ(improvement(MetricKind::OPERATOR_POLICY_SIGNAL, 0, 1),
               std::optional<std::uint32_t>(10000));
  // A zero current value cannot be improved proportionally: a strictly better
  // candidate is a full improvement, anything else is none at all.
  ARF_CHECK_EQ(improvement(MetricKind::PATH_QUALITY, 0, 1),
               std::optional<std::uint32_t>(10000));
  ARF_CHECK_EQ(improvement(MetricKind::PATH_QUALITY, 0, 0),
               std::optional<std::uint32_t>(0));
  ARF_CHECK_EQ(improvement(MetricKind::PATH_UTILIZATION, 0, 0),
               std::optional<std::uint32_t>(0));
  // Incomparable values, and an unset value, have no relative improvement.
  ARF_CHECK(!relative_improvement_bps(require_value(MetricKind::PATH_UTILIZATION, 5000),
                                      require_value(MetricKind::PATH_LATENCY, 4000))
                 .has_value());
  ARF_CHECK(!relative_improvement_bps(MetricValue{}, require_value(MetricKind::PATH_LATENCY, 1))
                 .has_value());
  ARF_CHECK(!relative_improvement_bps(require_value(MetricKind::PATH_LATENCY, 1), MetricValue{})
                 .has_value());
}

ARF_TEST(normalize_is_monotone_and_hits_both_ends) {
  // Lower is better: the best representable value maps to 10000 and the worst
  // to 0.
  const auto normalize = [](MetricKind kind, std::int64_t value) {
    return normalize_to_basis_points(require_value(kind, value));
  };
  ARF_CHECK_EQ(normalize(MetricKind::PATH_UTILIZATION, 0), std::optional<std::uint32_t>(10000));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_UTILIZATION, 10000), std::optional<std::uint32_t>(0));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_UTILIZATION, 1), std::optional<std::uint32_t>(9999));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_UTILIZATION, 2500), std::optional<std::uint32_t>(7500));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_UTILIZATION, 5000), std::optional<std::uint32_t>(5000));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_UTILIZATION, 9999), std::optional<std::uint32_t>(1));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_LATENCY, 0), std::optional<std::uint32_t>(10000));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_LATENCY, 4000000000LL),
               std::optional<std::uint32_t>(0));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_LATENCY, 2000000000LL),
               std::optional<std::uint32_t>(5000));
  // 4 ms against a 4 s ceiling is 9990, an exact floor.
  ARF_CHECK_EQ(normalize(MetricKind::PATH_LATENCY, 4000000LL),
               std::optional<std::uint32_t>(9990));
  // Higher is better inverts the mapping.
  ARF_CHECK_EQ(normalize(MetricKind::PATH_QUALITY, 0), std::optional<std::uint32_t>(0));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_QUALITY, 10000), std::optional<std::uint32_t>(10000));
  ARF_CHECK_EQ(normalize(MetricKind::PATH_QUALITY, 2500), std::optional<std::uint32_t>(2500));
  ARF_CHECK_EQ(normalize(MetricKind::OPERATOR_POLICY_SIGNAL, 0), std::optional<std::uint32_t>(0));
  ARF_CHECK_EQ(normalize(MetricKind::OPERATOR_POLICY_SIGNAL, 1),
               std::optional<std::uint32_t>(10000));

  // Monotone in the metric's own direction across the whole range.
  std::optional<std::uint32_t> previous_lower;
  std::optional<std::uint32_t> previous_higher;
  for (std::int64_t step = 0; step <= 10; ++step) {
    const std::int64_t scaled = step * 1000;
    const auto lower = normalize(MetricKind::PATH_UTILIZATION, scaled);
    const auto higher = normalize(MetricKind::PATH_QUALITY, scaled);
    ARF_REQUIRE(lower.has_value() && higher.has_value());
    if (previous_lower.has_value()) {
      ARF_CHECK_MSG(*lower <= *previous_lower,
                    "lower-is-better normalisation must not rise: " << *lower << " after "
                                                                    << *previous_lower);
    }
    if (previous_higher.has_value()) {
      ARF_CHECK_MSG(*higher >= *previous_higher,
                    "higher-is-better normalisation must not fall: " << *higher << " after "
                                                                     << *previous_higher);
    }
    ARF_CHECK_EQ(*lower + *higher, static_cast<std::uint32_t>(10000));
    previous_lower = lower;
    previous_higher = higher;
  }
  ARF_CHECK_EQ(*previous_lower, static_cast<std::uint32_t>(0));
  ARF_CHECK_EQ(*previous_higher, static_cast<std::uint32_t>(10000));
  ARF_CHECK(!normalize_to_basis_points(MetricValue{}).has_value());
}

ARF_TEST(aggregate_samples_matches_hand_computed_values) {
  const std::vector<std::int64_t> four = {1, 2, 3, 4};
  check_aggregate(AggregationKind::MINIMUM, four, 1);
  check_aggregate(AggregationKind::MAXIMUM, four, 4);
  check_aggregate(AggregationKind::MEAN, four, 2);   // floor(10 / 4)
  check_aggregate(AggregationKind::MEDIAN, four, 2); // rank ceil(50*4/100) = 2
  check_aggregate(AggregationKind::PERCENTILE_95, four, 4);

  check_aggregate(AggregationKind::MINIMUM, {5, 3, 9, 1}, 1);
  check_aggregate(AggregationKind::MAXIMUM, {5, 3, 9, 1}, 9);
  check_aggregate(AggregationKind::MEAN, {1, 2}, 1);  // floor(3 / 2)
  check_aggregate(AggregationKind::MEAN, {0, 0, 0}, 0);
  check_aggregate(AggregationKind::MEAN, {10, 20, 30}, 20);

  // Median over an even count takes the lower middle order statistic, and the
  // input order must not matter.
  check_aggregate(AggregationKind::MEDIAN, {4, 1, 3, 2}, 2);
  check_aggregate(AggregationKind::MEDIAN, {10, 20, 30, 40}, 20);
  check_aggregate(AggregationKind::MEDIAN, {1, 2, 3, 4, 5, 6}, 3);
  check_aggregate(AggregationKind::MEDIAN, {6, 5, 4, 3, 2, 1}, 3);
  check_aggregate(AggregationKind::MEDIAN, {7}, 7);

  // Nearest rank: ceil(95N/100), so ten samples put the 95th at the maximum and
  // twenty samples at the nineteenth.
  check_aggregate(AggregationKind::PERCENTILE_95, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 10);
  check_aggregate(AggregationKind::PERCENTILE_95, {1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
                  19);
  check_aggregate(AggregationKind::PERCENTILE_95, {3, 1, 2}, 3);
  check_aggregate(AggregationKind::PERCENTILE_95, {42}, 42);

  // EWMA is seeded with the first sample in observation order and then rounded
  // down at every step.
  //   floor((2500*200 + 7500*100) / 10000) = 125
  check_aggregate(AggregationKind::EWMA, {100, 200}, 125, 2500);
  //   floor((2500*300 + 7500*125) / 10000) = floor(168.75) = 168
  check_aggregate(AggregationKind::EWMA, {100, 200, 300}, 168, 2500);
  //   floor((2500*2 + 7500*1) / 10000) = 1
  check_aggregate(AggregationKind::EWMA, {1, 2}, 1, 2500);
  //   floor((5000*2000 + 5000*1000) / 10000) = 1500
  check_aggregate(AggregationKind::EWMA, {1000, 2000}, 1500, 5000);
  //   floor((5000*3000 + 5000*1500) / 10000) = 2250
  check_aggregate(AggregationKind::EWMA, {1000, 2000, 3000}, 2250, 5000);
  check_aggregate(AggregationKind::EWMA, {7}, 7, 2500);
  // The extremes of the legal alpha range are exact: zero ignores every later
  // sample and 10000 ignores every earlier one.
  check_aggregate(AggregationKind::EWMA, {100, 200, 300}, 100, 0);
  check_aggregate(AggregationKind::EWMA, {100, 200, 300}, 300, 10000);

  // The same inputs always produce the same aggregate.
  const std::vector<std::int64_t> repeat = {9, 4, 7, 1, 8};
  for (const AggregationKind kind :
       {AggregationKind::MINIMUM, AggregationKind::MAXIMUM, AggregationKind::MEAN,
        AggregationKind::MEDIAN, AggregationKind::PERCENTILE_95, AggregationKind::EWMA}) {
    const auto first = aggregate_samples(kind, repeat, 2500);
    const auto second = aggregate_samples(kind, repeat, 2500);
    ARF_CHECK_EQ(first, second);
    ARF_REQUIRE(first.has_value());
    ARF_CHECK_EQ(aggregate_samples(kind, repeat, 2500).value_or(-1), *first);
  }

  // Degenerate inputs are refused rather than guessed.
  const std::vector<std::int64_t> empty;
  for (const AggregationKind kind :
       {AggregationKind::MINIMUM, AggregationKind::MAXIMUM, AggregationKind::MEAN,
        AggregationKind::MEDIAN, AggregationKind::PERCENTILE_95, AggregationKind::EWMA}) {
    ARF_CHECK_MSG(!aggregate_samples(kind, empty, 2500).has_value(),
                  "an empty sample set has no aggregate: " << to_string(kind));
  }
  ARF_CHECK(!aggregate_samples(AggregationKind::EWMA, four, 10001).has_value());
  ARF_CHECK(!aggregate_samples(AggregationKind::EWMA, four, 20000).has_value());
  // The alpha bound applies to EWMA only; the other aggregations never read it.
  ARF_CHECK_EQ(aggregate_samples(AggregationKind::MEAN, four, 99999),
               std::optional<std::int64_t>(2));
  // Checked arithmetic: a sum that does not fit is a rejection, not a wrap.
  const std::int64_t maximum = std::numeric_limits<std::int64_t>::max();
  const std::vector<std::int64_t> overflowing = {maximum, maximum};
  const std::vector<std::int64_t> extremes = {maximum, 0};
  ARF_CHECK(!aggregate_samples(AggregationKind::MEAN, overflowing, 2500).has_value());
  ARF_CHECK_EQ(aggregate_samples(AggregationKind::MINIMUM, extremes, 2500),
               std::optional<std::int64_t>(0));
}

ARF_TEST(weighted_score_is_exact_and_total) {
  const ScoreTerm utilization_term{MetricKind::PATH_UTILIZATION, 5000};
  const ScoreTerm quality_term{MetricKind::PATH_QUALITY, 5000};
  const std::vector<ScoreTerm> halves = {utilization_term, quality_term};
  // util 3000 normalises to 7000, quality 2999 to 2999.
  //   (5000*7000 + 5000*2999) / 10000 = 4999.5 -> 5000 half up
  const std::vector<MetricValue> half_up = {require_value(MetricKind::PATH_UTILIZATION, 3000),
                                            require_value(MetricKind::PATH_QUALITY, 2999)};
  ARF_CHECK_EQ(weighted_score(halves, half_up), std::optional<std::uint64_t>(5000));

  // A single term carrying the whole weight reproduces that term's
  // normalisation exactly.
  const std::vector<ScoreTerm> single = {ScoreTerm{MetricKind::PATH_UTILIZATION, 10000}};
  const std::vector<MetricValue> utilization = {require_value(MetricKind::PATH_UTILIZATION, 2000)};
  ARF_CHECK_EQ(weighted_score(single, utilization), std::optional<std::uint64_t>(8000));
  const std::vector<ScoreTerm> latency_only = {ScoreTerm{MetricKind::PATH_LATENCY, 10000}};
  const std::vector<MetricValue> best_latency = {require_value(MetricKind::PATH_LATENCY, 0)};
  ARF_CHECK_EQ(weighted_score(latency_only, best_latency), std::optional<std::uint64_t>(10000));
  const std::vector<MetricValue> worst_latency = {
      require_value(MetricKind::PATH_LATENCY, 4000000000LL)};
  ARF_CHECK_EQ(weighted_score(latency_only, worst_latency), std::optional<std::uint64_t>(0));

  // An exact 60/40 decomposition of unity.
  //   (6000*0 + 4000*5000) / 10000 = 2000
  const std::vector<ScoreTerm> sixty_forty = {ScoreTerm{MetricKind::PATH_LATENCY, 6000},
                                              ScoreTerm{MetricKind::PATH_UTILIZATION, 4000}};
  const std::vector<MetricValue> mixed = {require_value(MetricKind::PATH_LATENCY, 4000000000LL),
                                          require_value(MetricKind::PATH_UTILIZATION, 5000)};
  ARF_CHECK_EQ(weighted_score(sixty_forty, mixed), std::optional<std::uint64_t>(2000));

  // The arithmetic itself does not police the weights; the objective spec does
  // (see the policy suite). A zero weight contributes nothing.
  const std::vector<ScoreTerm> zero_weight = {ScoreTerm{MetricKind::PATH_LATENCY, 0},
                                              ScoreTerm{MetricKind::PATH_UTILIZATION, 10000}};
  ARF_CHECK_EQ(weighted_score(zero_weight, mixed), std::optional<std::uint64_t>(5000));

  // A missing, mismatched or unset term yields no score at all: a candidate is
  // never scored from absent data.
  ARF_CHECK(!weighted_score(halves, utilization).has_value());
  ARF_CHECK(!weighted_score(single, half_up).has_value());
  ARF_CHECK(!weighted_score(latency_only, utilization).has_value());
  const std::vector<MetricValue> unset_values = {MetricValue{}};
  ARF_CHECK(!weighted_score(single, unset_values).has_value());
  const std::vector<ScoreTerm> no_terms;
  const std::vector<MetricValue> no_values;
  ARF_CHECK(!weighted_score(no_terms, utilization).has_value());
  ARF_CHECK(!weighted_score(no_terms, no_values).has_value());

  // Identical inputs always produce an identical score, whatever the storage
  // the spans point at.
  const std::vector<ScoreTerm> terms_copy = halves;
  const std::vector<MetricValue> values_copy = half_up;
  const auto first = weighted_score(halves, half_up);
  const auto second = weighted_score(terms_copy, values_copy);
  ARF_CHECK_EQ(first, second);
  ARF_REQUIRE(first.has_value());
  ARF_CHECK(*first <= static_cast<std::uint64_t>(10000));
  ARF_CHECK(weighted_score(halves, half_up).value_or(0) == *first);
}

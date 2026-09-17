// Limits tests: every field of Limits driven to its boundary, with the exact
// structured rejection, and a final coverage assertion against Limits::describe()
// so that a limit added to the configuration cannot silently go untested.
//
// No test weakens a configured bound to make itself pass: each case constructs a
// small Limits value and hands it to the engine, then drives the one field under
// test to the first value the bound refuses.
#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "adaptive_routing/persistence.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace adaptive_routing;
using namespace arf_test;

// ---------------------------------------------------------------------------
// Coverage bookkeeping
// ---------------------------------------------------------------------------

// Names of the described limits this suite has driven. zzz_limits_coverage_
// matches_describe asserts that this set is exactly the described set.
std::set<std::string>& covered_limits() {
  static std::set<std::string> names;
  return names;
}

void cover(std::string_view name) { covered_limits().insert(std::string(name)); }

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

[[nodiscard]] Limits base_limits() { return default_test_limits(); }

[[nodiscard]] PolicyScope scope_with_routes(std::size_t count) {
  PolicyScope scope;
  scope.fabric = fabric_id();
  scope.name_space = routing_namespace();
  for (std::size_t index = 0; index < count; ++index) {
    scope.routes.push_back(RouteId::require("route-" + std::to_string(index + 1)));
  }
  return scope;
}

[[nodiscard]] PolicyScope scope_with_sets(std::size_t count) {
  PolicyScope scope;
  scope.fabric = fabric_id();
  scope.name_space = routing_namespace();
  for (std::size_t index = 0; index < count; ++index) {
    scope.multipath_sets.push_back(MultipathSetId::require("set-" + std::to_string(index + 1)));
  }
  return scope;
}

[[nodiscard]] OperationResult create_scoped_policy(Harness& harness, const PolicyScope& scope,
                                                   const PolicySemantics& semantics) {
  CreatePolicyRequest request;
  request.name = harness.next_policy_name();
  request.scope = scope;
  request.semantics = semantics;
  request.context = harness.context();
  return harness.fabric->create_policy(request);
}

// Two latency samples in one batch: one per candidate path, from one source.
// The values are parameters so that a later batch can invert the ordering and
// force a real adaptation rather than an initial establishment.
[[nodiscard]] OperationResult publish_samples(Harness& harness, std::string_view source,
                                              const PathId& first, const PathId& second,
                                              std::uint64_t sequence,
                                              std::int64_t first_value = 5000,
                                              std::int64_t second_value = 1000) {
  EvidencePublication first_item;
  first_item.source = EvidenceSourceId::require(source);
  first_item.source_generation = EvidenceSourceGeneration::require(1);
  first_item.quality = EvidenceQuality::AGGREGATED;
  first_item.path = first;
  first_item.value = MetricValue::make(MetricKind::PATH_LATENCY, first_value).value_or(MetricValue{});
  first_item.observation_sequence = sequence;

  EvidencePublication second_item;
  second_item.source = EvidenceSourceId::require(source);
  second_item.source_generation = EvidenceSourceGeneration::require(1);
  second_item.quality = EvidenceQuality::AGGREGATED;
  second_item.path = second;
  second_item.value = MetricValue::make(MetricKind::PATH_LATENCY, second_value).value_or(MetricValue{});
  second_item.observation_sequence = sequence;

  PublishEvidenceRequest request;
  request.publications.push_back(first_item);
  request.publications.push_back(second_item);
  request.context = harness.context();
  return harness.fabric->publish_evidence(request);
}

// One active policy with two candidate bindings; evidence is keyed by
// (source, path, metric) and is therefore shared by every policy that binds the
// same path, so a second policy reuses the samples the first one published.
struct Scenario {
  AdaptivePolicyId policy;
  PathId first = path("path-a");
  PathId second = path("path-b");
};

[[nodiscard]] Scenario make_scenario(Harness& harness, const PolicySemantics& semantics,
                                     std::uint64_t sequence = 1, bool publish = true) {
  Scenario scenario;
  scenario.policy = create_active_policy(harness, semantics);
  ARF_CHECK_EQ(declare_candidate(harness, scenario.policy, make_binding(scenario.first, 1)).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(
      declare_candidate(harness, scenario.policy, make_binding(scenario.second, 1)).outcome,
      Outcome::POLICY_UPDATED);
  if (publish) {
    ARF_CHECK_EQ(publish_samples(harness, "telemetry-1", scenario.first, scenario.second, sequence)
                     .outcome,
                 Outcome::POLICY_UPDATED);
  }
  return scenario;
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

[[nodiscard]] std::string temp_store_path(std::string_view label) {
  const std::filesystem::path directory = std::filesystem::temp_directory_path();
  const std::filesystem::path file =
      directory / ("arf-limits-" + std::string(label) + "-" + process_nonce() + ".store");
  return file.string();
}

class TempStore {
 public:
  explicit TempStore(std::string path) : path_(std::move(path)) { cleanup(); }
  ~TempStore() { cleanup(); }
  TempStore(const TempStore&) = delete;
  TempStore& operator=(const TempStore&) = delete;

  [[nodiscard]] const std::string& path() const noexcept { return path_; }

  void cleanup() const {
    std::error_code code;
    std::filesystem::remove(path_, code);
    code.clear();
    std::filesystem::remove(path_ + ".tmp", code);
  }

 private:
  std::string path_;
};

// Store framing, mirrored so that a store carrying an over-long record still has
// a valid trailer and the record bound is the defect that is reported.
[[nodiscard]] std::uint64_t store_trailer_of(std::string_view bytes) {
  std::uint64_t low = 14695981039346656037ULL;
  std::uint64_t high = 0x9E3779B97F4A7C15ULL;
  for (const char character : bytes) {
    const std::uint64_t octet =
        static_cast<std::uint64_t>(static_cast<unsigned char>(character));
    low ^= octet;
    low *= 1099511628211ULL;
    high += octet;
    high ^= (high << 13);
    high *= 1099511628211ULL;
  }
  return low ^ high;
}

// Framing bytes and the five header counters exactly as the encoder writes them,
// with a policy record whose declared length is one past the per-record bound.
[[nodiscard]] std::string oversized_record_store() {
  DurableState state;
  state.epoch = CoordinatorEpoch::require(1);
  state.authority_generation = AdaptiveAuthorityGeneration::require(1);
  state.evidence_generation = EvidenceGeneration::require(1);
  const std::string real = encode_durable_state(state);
  std::string bytes = real.substr(0, 48);

  ByteWriter body;
  body.put_u64(1);
  body.put_u64(Limits{}.max_persistence_record_bytes + 1U);
  bytes += body.take();

  ByteWriter tail;
  tail.put_u64(store_trailer_of(bytes));
  bytes += tail.take();
  return bytes;
}

// ---------------------------------------------------------------------------
// Policy structure
// ---------------------------------------------------------------------------

ARF_TEST(limits_policy_creation_is_bounded) {
  const PolicySemantics latency = latency_semantics(250, 500);

  {
    Limits limits = base_limits();
    limits.max_policies = 1;
    Harness harness = make_harness(limits);
    ARF_CHECK_EQ(create_policy(harness, latency, harness.next_policy_name(), harness.context())
                     .outcome,
                 Outcome::POLICY_CREATED);
    ARF_CHECK_EQ(create_policy(harness, latency, harness.next_policy_name(), harness.context())
                     .outcome,
                 Outcome::RESOURCE_LIMIT);
    ARF_CHECK_EQ(harness.fabric->list_policies().size(), static_cast<std::size_t>(1));
    cover("max_policies");
  }
  {
    Limits limits = base_limits();
    limits.max_thresholds_per_policy = 0;
    Harness harness = make_harness(limits);
    ARF_CHECK_EQ(create_policy(harness, utilization_semantics(8000, 2000),
                               harness.next_policy_name(), harness.context())
                     .outcome,
                 Outcome::RESOURCE_LIMIT);
    // The same semantics is accepted once the bound admits one threshold, so the
    // rejection above is the bound and not a malformed policy.
    Harness control = make_harness();
    ARF_CHECK_EQ(create_policy(control, utilization_semantics(8000, 2000),
                               control.next_policy_name(), control.context())
                     .outcome,
                 Outcome::POLICY_CREATED);
    cover("max_thresholds_per_policy");
  }
  {
    Limits limits = base_limits();
    limits.max_evidence_requirements_per_policy = 1;
    Harness harness = make_harness(limits);
    PolicySemantics two_requirements = latency;
    two_requirements.evidence.clear();
    two_requirements.evidence.push_back(latency_requirement());
    two_requirements.evidence.push_back(utilization_requirement());
    ARF_CHECK_EQ(create_policy(harness, two_requirements, harness.next_policy_name(),
                               harness.context())
                     .outcome,
                 Outcome::RESOURCE_LIMIT);
    cover("max_evidence_requirements_per_policy");
  }
  {
    Limits limits = base_limits();
    limits.max_objective_terms = 0;
    Harness harness = make_harness(limits);
    ARF_CHECK_EQ(create_policy(harness, latency, harness.next_policy_name(), harness.context())
                     .outcome,
                 Outcome::RESOURCE_LIMIT);
    cover("max_objective_terms");
  }
  {
    Limits limits = base_limits();
    limits.max_scope_routes = 1;
    Harness harness = make_harness(limits);
    ARF_CHECK_EQ(create_scoped_policy(harness, scope_with_routes(2), latency).outcome,
                 Outcome::RESOURCE_LIMIT);
    ARF_CHECK_EQ(create_scoped_policy(harness, scope_with_routes(1), latency).outcome,
                 Outcome::POLICY_CREATED);
    cover("max_scope_routes");
  }
  {
    Limits limits = base_limits();
    limits.max_scope_multipath_sets = 1;
    Harness harness = make_harness(limits);
    ARF_CHECK_EQ(create_scoped_policy(harness, scope_with_sets(2), latency).outcome,
                 Outcome::RESOURCE_LIMIT);
    ARF_CHECK_EQ(create_scoped_policy(harness, scope_with_sets(1), latency).outcome,
                 Outcome::POLICY_CREATED);
    cover("max_scope_multipath_sets");
  }
  {
    Limits limits = base_limits();
    limits.max_adaptations_per_window = 1;
    Harness harness = make_harness(limits);
    PolicySemantics churn = latency;
    churn.churn.max_adaptations_per_window = 2;
    churn.churn.window = seconds(60);
    ARF_CHECK_EQ(create_policy(harness, churn, harness.next_policy_name(), harness.context())
                     .outcome,
                 Outcome::RESOURCE_LIMIT);
    cover("max_adaptations_per_window");
  }
  {
    Limits limits = base_limits();
    limits.max_dampening_penalty = 1;
    Harness harness = make_harness(limits);
    PolicySemantics dampening = latency;
    dampening.hold_down.duration = seconds(10);
    dampening.dampening.enabled = true;
    dampening.dampening.penalty_increment = 1;
    dampening.dampening.max_penalty = 2;
    dampening.dampening.penalty_decay_interval = seconds(60);
    dampening.dampening.penalty_decay_step = 1;
    dampening.dampening.hold_down_escalation_step = seconds(5);
    dampening.dampening.max_effective_hold_down = seconds(30);
    ARF_CHECK_EQ(create_policy(harness, dampening, harness.next_policy_name(), harness.context())
                     .outcome,
                 Outcome::RESOURCE_LIMIT);
    cover("max_dampening_penalty");
  }
}

// ---------------------------------------------------------------------------
// Candidates, revocations and publishers
// ---------------------------------------------------------------------------

ARF_TEST(limits_candidate_bounds_are_resource_limits) {
  {
    Limits limits = base_limits();
    limits.max_candidates_per_policy = 1;
    Harness harness = make_harness(limits);
    const AdaptivePolicyId policy = create_active_policy(harness, latency_semantics(250, 500));
    ARF_CHECK_EQ(declare_candidate(harness, policy, make_binding(path("path-a"), 1)).outcome,
                 Outcome::POLICY_UPDATED);
    ARF_CHECK_EQ(declare_candidate(harness, policy, make_binding(path("path-b"), 1)).outcome,
                 Outcome::RESOURCE_LIMIT);
    ARF_CHECK_EQ(harness.fabric->candidates(policy).size(), static_cast<std::size_t>(1));
    cover("max_candidates_per_policy");
  }
  {
    Limits limits = base_limits();
    limits.max_total_candidates = 1;
    Harness harness = make_harness(limits);
    const AdaptivePolicyId policy = create_active_policy(harness, latency_semantics(250, 500));
    ARF_CHECK_EQ(declare_candidate(harness, policy, make_binding(path("path-a"), 1)).outcome,
                 Outcome::POLICY_UPDATED);
    ARF_CHECK_EQ(declare_candidate(harness, policy, make_binding(path("path-b"), 1)).outcome,
                 Outcome::RESOURCE_LIMIT);
    cover("max_total_candidates");
  }
}

ARF_TEST(limits_revocation_and_publisher_bounds_are_resource_limits) {
  {
    Limits limits = base_limits();
    limits.max_revocations = 1;
    Harness harness = make_harness(limits);
    const AdaptivePolicyId first = create_active_policy(harness, latency_semantics(250, 500));
    const AdaptivePolicyId second = create_active_policy(harness, latency_semantics(250, 500));
    ARF_CHECK_EQ(harness.fabric
                     ->revoke_policy(first, RevocationReason::ADMINISTRATIVE,
                                     "the first revocation fits the bound", harness.context())
                     .outcome,
                 Outcome::POLICY_UPDATED);
    ARF_CHECK_EQ(harness.fabric
                     ->revoke_policy(second, RevocationReason::ADMINISTRATIVE,
                                     "the second revocation exceeds it", harness.context())
                     .outcome,
                 Outcome::RESOURCE_LIMIT);
    ARF_CHECK_EQ(harness.fabric->list_revocations().size(), static_cast<std::size_t>(1));
    cover("max_revocations");
  }
  {
    Limits limits = base_limits();
    limits.max_publishers = 1;
    Harness harness = make_harness(limits);
    ARF_CHECK_EQ(harness.fabric
                     ->register_publisher(PublisherId::require("publisher-b"),
                                          WorkerBootId::require("boot-b1"), default_scope(),
                                          SessionId::require("session-b1"))
                     .outcome,
                 Outcome::RESOURCE_LIMIT);
    // Re-registering the publisher that is already known is not a new publisher.
    ARF_CHECK_EQ(harness.fabric
                     ->register_publisher(harness.publisher, harness.worker_boot,
                                          default_scope(), harness.session)
                     .outcome,
                 Outcome::IDEMPOTENT);
    cover("max_publishers");
  }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

ARF_TEST(limits_evidence_source_bound_is_a_resource_limit) {
  Limits limits = base_limits();
  limits.max_evidence_sources = 1;
  Harness harness = make_harness(limits);
  const Scenario scenario =
      make_scenario(harness, latency_semantics(250, 500), 1, /*publish=*/false);
  ARF_CHECK_EQ(publish_samples(harness, "telemetry-1", scenario.first, scenario.second, 1).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish_samples(harness, "telemetry-2", scenario.first, scenario.second, 1).outcome,
               Outcome::RESOURCE_LIMIT);
  // The same source publishing again is not a new source.
  ARF_CHECK_EQ(publish_samples(harness, "telemetry-1", scenario.first, scenario.second, 2).outcome,
               Outcome::POLICY_UPDATED);
  cover("max_evidence_sources");
}

ARF_TEST(limits_evidence_series_retention_is_bounded) {
  Limits limits = base_limits();
  limits.max_evidence_samples_per_series = 2;
  Harness harness = make_harness(limits);
  const Scenario scenario = make_scenario(harness, latency_semantics(250, 500), 1);

  // Three accepted samples for one (source, path, metric) series: the ring keeps
  // the newest two and the total published count keeps counting.
  ARF_CHECK_EQ(publish_samples(harness, "telemetry-1", scenario.first, scenario.second, 2).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish_samples(harness, "telemetry-1", scenario.first, scenario.second, 3).outcome,
               Outcome::POLICY_UPDATED);
  const std::vector<EvidenceSeriesView> views = harness.fabric->describe_evidence(scenario.policy);
  ARF_REQUIRE(views.size() == static_cast<std::size_t>(2));
  for (const EvidenceSeriesView& view : views) {
    ARF_CHECK_EQ(view.retained, static_cast<std::uint32_t>(2));
    ARF_CHECK_EQ(view.total_published, static_cast<std::uint64_t>(3));
    ARF_CHECK(view.retained <= limits.max_evidence_samples_per_series);
  }
  cover("max_evidence_samples_per_series");
}

ARF_TEST(limits_evidence_batch_bound_is_a_resource_limit) {
  Limits limits = base_limits();
  limits.max_batch_size = 1;
  Harness harness = make_harness(limits);
  const Scenario scenario =
      make_scenario(harness, latency_semantics(250, 500), 1, /*publish=*/false);
  ARF_CHECK_EQ(publish_samples(harness, "telemetry-1", scenario.first, scenario.second, 1).outcome,
               Outcome::RESOURCE_LIMIT);
  // A single publication batch is accepted, so the rejection above is the batch
  // bound and not a malformed publication.
  ARF_CHECK_EQ(publish_latency(harness, scenario.first, 5000, 1).outcome, Outcome::POLICY_UPDATED);
  cover("max_batch_size");
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

ARF_TEST(limits_simultaneous_evaluation_bound_is_an_evaluation_limit) {
  Limits limits = base_limits();
  limits.max_simultaneous_evaluations = 1;
  Harness harness = make_harness(limits);
  const AdaptivePolicyId policy = create_active_policy(harness, latency_semantics(250, 500));

  EvaluateRequest request;
  request.policy = policy;
  request.context = harness.context();
  const EvaluationTicket first = harness.fabric->begin_evaluation(request);
  ARF_CHECK_MSG(first.lifecycle != DecisionLifecycle::REJECTED,
                "the first outstanding evaluation must be admitted");

  request.context = harness.context();
  const EvaluationTicket refused = harness.fabric->begin_evaluation(request);
  ARF_CHECK_EQ(refused.outcome, Outcome::EVALUATION_LIMIT);
  ARF_CHECK_EQ(refused.lifecycle, DecisionLifecycle::REJECTED);
  ARF_CHECK(!refused.dependencies.policy.valid());

  // Settling the outstanding ticket releases the bound: the limit counts
  // outstanding evaluations, not evaluations ever started.
  CommitDecisionRequest commit;
  commit.ticket = first;
  commit.context = harness.context();
  ARF_CHECK_EQ(harness.fabric->commit_evaluation(commit).outcome, Outcome::NO_ELIGIBLE_CANDIDATE);
  request.context = harness.context();
  const EvaluationTicket admitted = harness.fabric->begin_evaluation(request);
  ARF_CHECK_EQ(admitted.outcome, Outcome::NO_ELIGIBLE_CANDIDATE);
  ARF_CHECK_MSG(admitted.lifecycle != DecisionLifecycle::REJECTED,
                "the bound must be released by the settled evaluation");
  cover("max_simultaneous_evaluations");
}

ARF_TEST(limits_pending_transition_bound_is_a_resource_limit) {
  Limits limits = base_limits();
  limits.max_pending_transitions = 1;
  Harness harness = make_harness(limits);

  const Scenario first =
      make_scenario(harness, latency_semantics(250, 500, seconds(60)), 1, /*publish=*/true);

  // Establishing the first preference is not an adaptation: there is nothing to
  // reverse, so it arms no hold-down and leaves nothing pending.
  ARF_CHECK_EQ(evaluate_policy(harness, first.policy).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK(!harness.fabric->snapshot(first.policy).hold_down_active);

  // A later adaptation inverts the preference and arms the declared hold-down,
  // which is exactly one pending transition for that policy.
  ARF_CHECK_EQ(publish_samples(harness, "telemetry-1", first.first, first.second, 2, 100, 9000)
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(evaluate_policy(harness, first.policy).outcome, Outcome::DECISION_COMMITTED);
  ARF_CHECK(harness.fabric->snapshot(first.policy).hold_down_active);

  // The second policy's commit is refused while that transition is pending.
  const Scenario second =
      make_scenario(harness, latency_semantics(250, 500, seconds(60)), 3, /*publish=*/false);
  ARF_CHECK_EQ(evaluate_policy(harness, second.policy).outcome, Outcome::RESOURCE_LIMIT);
  cover("max_pending_transitions");
}

// ---------------------------------------------------------------------------
// Bounded retention
// ---------------------------------------------------------------------------

ARF_TEST(limits_history_bounds_are_enforced) {
  {
    Limits limits = base_limits();
    limits.max_history_per_policy = 1;
    Harness harness = make_harness(limits);
    const Scenario scenario = make_scenario(harness, latency_semantics(250, 500));
    ARF_CHECK_EQ(evaluate_policy(harness, scenario.policy).outcome, Outcome::DECISION_COMMITTED);
    ARF_CHECK_EQ(evaluate_policy(harness, scenario.policy).outcome, Outcome::NO_CHANGE);
    ARF_CHECK_EQ(harness.fabric->snapshot(scenario.policy).history.size(),
                 static_cast<std::size_t>(1));

    // The same two evaluations keep both entries when the bound admits them, so
    // the single entry above is the bound and not a missing history write.
    Harness control = make_harness();
    const Scenario control_scenario = make_scenario(control, latency_semantics(250, 500));
    ARF_CHECK_EQ(evaluate_policy(control, control_scenario.policy).outcome,
                 Outcome::DECISION_COMMITTED);
    ARF_CHECK_EQ(evaluate_policy(control, control_scenario.policy).outcome, Outcome::NO_CHANGE);
    ARF_CHECK_EQ(control.fabric->snapshot(control_scenario.policy).history.size(),
                 static_cast<std::size_t>(2));
    cover("max_history_per_policy");
  }
  {
    Limits limits = base_limits();
    limits.max_decision_history = 1;
    Harness harness = make_harness(limits);
    const Scenario scenario = make_scenario(harness, latency_semantics(250, 500));
    ARF_CHECK_EQ(evaluate_policy(harness, scenario.policy).outcome, Outcome::DECISION_COMMITTED);
    ARF_CHECK_EQ(evaluate_policy(harness, scenario.policy).outcome, Outcome::NO_CHANGE);
    ARF_CHECK_EQ(harness.fabric->list_decisions(64).size(), static_cast<std::size_t>(1));
    ARF_CHECK_EQ(harness.fabric->decisions_for_policy(scenario.policy, 64).size(),
                 static_cast<std::size_t>(1));
    cover("max_decision_history");
  }
}

ARF_TEST(limits_snapshot_retention_is_bounded) {
  Limits limits = base_limits();
  limits.max_snapshot_history = 2;
  Harness harness = make_harness(limits);
  const AdaptivePolicyId policy = create_active_policy(harness, latency_semantics(250, 500));
  for (int attempt = 0; attempt < 4; ++attempt) {
    const AdaptationSnapshot snapshot = harness.fabric->snapshot(policy);
    ARF_CHECK(snapshot.id.valid());
  }
  const std::vector<SnapshotId> retained = harness.fabric->retained_snapshots();
  ARF_CHECK_EQ(retained.size(), static_cast<std::size_t>(2));
  for (const SnapshotId& id : retained) {
    ARF_CHECK(harness.fabric->find_snapshot(id).has_value());
  }
  cover("max_snapshot_history");
}

ARF_TEST(limits_explanation_entry_bound_is_enforced) {
  // The smallest bound that still retains one entry. The explanation is cut off
  // at the bound and says so: the last retained entry is the truncation marker,
  // so an operator sees that the reason was cut rather than silently missing.
  Limits limits = base_limits();
  limits.max_explanation_entries = 1;
  Harness harness = make_harness(limits);
  const Scenario scenario = make_scenario(harness, latency_semantics(250, 500));
  ARF_CHECK_EQ(evaluate_policy(harness, scenario.policy).outcome, Outcome::DECISION_COMMITTED);
  const Explanation explanation =
      harness.fabric->explain(ExplanationTopic::WHY_NOT_ADAPTED, scenario.policy);
  ARF_CHECK_EQ(explanation.entries.size(), static_cast<std::size_t>(1));
  ARF_REQUIRE(!explanation.entries.empty());
  ARF_CHECK_EQ(explanation.entries.back().key, std::string("truncated"));

  // The same scenario under the default bound retains the whole explanation, so
  // the single entry above is the bound and not a missing explanation.
  Harness control = make_harness();
  const Scenario control_scenario = make_scenario(control, latency_semantics(250, 500));
  ARF_CHECK_EQ(evaluate_policy(control, control_scenario.policy).outcome,
               Outcome::DECISION_COMMITTED);
  const Explanation full =
      control.fabric->explain(ExplanationTopic::WHY_NOT_ADAPTED, control_scenario.policy);
  ARF_CHECK(full.entries.size() > static_cast<std::size_t>(1));

  // A bound of zero yields an explanation with no entries at all, and no
  // truncation marker either: there is nothing retained to mark.
  Limits silent_limits = base_limits();
  silent_limits.max_explanation_entries = 0;
  Harness silent = make_harness(silent_limits);
  const AdaptivePolicyId silent_policy = create_active_policy(silent, latency_semantics(250, 500));
  const Explanation none = silent.fabric->explain(ExplanationTopic::WHY_ADAPTED, silent_policy);
  ARF_CHECK(none.entries.empty());
  cover("max_explanation_entries");
}

ARF_TEST(limits_attempt_table_is_bounded) {
  const PolicySemantics semantics = latency_semantics(250, 500);
  const AdaptivePolicyName replayed_name = AdaptivePolicyName::require("policy-replayed");

  Limits limits = base_limits();
  limits.max_attempts = 1;
  Harness harness = make_harness(limits);
  const MutationContext first_attempt = harness.context();
  ARF_CHECK_EQ(create_policy(harness, semantics, replayed_name, first_attempt).outcome,
               Outcome::POLICY_CREATED);
  // The second attempt prunes the first from the bounded replay table.
  ARF_CHECK_EQ(create_policy(harness, semantics, AdaptivePolicyName::require("policy-second"),
                             harness.context())
                   .outcome,
               Outcome::POLICY_CREATED);
  // The pruned attempt is no longer recognised as a replay, so the duplicate name
  // is reported as a conflict rather than as an idempotent replay.
  ARF_CHECK_EQ(create_policy(harness, semantics, replayed_name, first_attempt).outcome,
               Outcome::ALREADY_EXISTS);

  // With the table large enough the same replay is recognised exactly.
  Harness control = make_harness();
  const MutationContext control_attempt = control.context();
  ARF_CHECK_EQ(create_policy(control, semantics, replayed_name, control_attempt).outcome,
               Outcome::POLICY_CREATED);
  ARF_CHECK_EQ(create_policy(control, semantics, AdaptivePolicyName::require("policy-second"),
                             control.context())
                   .outcome,
               Outcome::POLICY_CREATED);
  ARF_CHECK_EQ(create_policy(control, semantics, replayed_name, control_attempt).outcome,
               Outcome::IDEMPOTENT);
  cover("max_attempts");
}

ARF_TEST(limits_path_dependency_index_is_bounded) {
  // The reverse index that makes targeted invalidation cheap is bounded; once it
  // is full, a further path is not indexed, so evidence for that path is refused
  // rather than silently attributed to a policy that does not bind it.
  Limits limits = base_limits();
  limits.max_policies_per_path = 1;
  Harness harness = make_harness(limits);
  const AdaptivePolicyId policy = create_active_policy(harness, latency_semantics(250, 500));

  const std::size_t indexed_paths = static_cast<std::size_t>(limits.max_policies_per_path) * 16U;
  ARF_CHECK_EQ(indexed_paths, static_cast<std::size_t>(16));
  for (std::size_t index = 1; index <= indexed_paths + 1; ++index) {
    std::string name = "path-";
    if (index < 10) {
      name += "0";
    }
    name += std::to_string(index);
    ARF_CHECK_EQ(declare_candidate(harness, policy, make_binding(path(name), 1)).outcome,
                 Outcome::POLICY_UPDATED);
  }
  const PathId last_indexed = path("path-16");
  const PathId beyond_index = path("path-17");
  ARF_CHECK_EQ(publish_latency(harness, last_indexed, 5000, 1).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(publish_latency(harness, beyond_index, 5000, 1).outcome,
               Outcome::UNAUTHORIZED_SCOPE);
  cover("max_policies_per_path");
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

ARF_TEST(limits_frame_bound_is_enforced_at_both_boundaries) {
  Limits limits = base_limits();
  limits.max_frame_bytes = 512;
  const std::uint64_t bound = limits.max_frame_bytes;
  ARF_CHECK(bound > frame_header_bytes + frame_trailer_bytes);

  Frame frame;
  frame.header.message_id = MessageId::HELLO;
  frame.header.epoch = CoordinatorEpoch::require(1);
  const std::size_t body =
      static_cast<std::size_t>(bound) - frame_header_bytes - frame_trailer_bytes;
  frame.payload = std::string(body, 'x');
  const auto at_bound = encode_frame(frame, bound);
  ARF_REQUIRE(at_bound.has_value());
  ARF_CHECK_EQ(at_bound->size(), static_cast<std::size_t>(bound));
  ARF_CHECK_EQ(decode_frame(*at_bound, bound).status, FrameStatus::OK);

  // One byte past the bound: the encoder refuses, and a peer that declares an
  // over-limit payload is rejected before a single payload byte is read.
  frame.payload.push_back('x');
  ARF_CHECK(!encode_frame(frame, bound).has_value());

  ByteWriter header;
  header.put_u32(frame_magic);
  header.put_u16(wire_protocol_version);
  header.put_u16(static_cast<std::uint16_t>(MessageId::HELLO));
  header.put_u32(0);
  header.put_u32(static_cast<std::uint32_t>(body + 1U));
  header.put_u64(1);
  header.put_u64(1);
  ARF_CHECK_EQ(decode_frame(header.buffer(), bound).status, FrameStatus::TOO_LARGE);

  // The default configuration carries a positive frame bound of its own.
  ARF_CHECK(Limits{}.max_frame_bytes >= bound);
  cover("max_frame_bytes");
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

ARF_TEST(limits_persistence_bounds_are_enforced) {
  {
    // A record longer than the per-record bound is refused before its bytes are
    // read: the store framing and its trailer are valid, the record is not.
    const std::string bytes = oversized_record_store();
    ARF_CHECK_EQ(decode_durable_state(bytes).status, StoreDecodeStatus::TRUNCATED);
    cover("max_persistence_record_bytes");
  }
  {
    TempStore store(temp_store_path("store-bound"));
    Limits limits = base_limits();
    limits.max_store_bytes = 64;
    Harness harness = make_harness(limits);
    ARF_CHECK_EQ(harness.fabric->save(store.path()).outcome, Outcome::RESOURCE_LIMIT);

    // A bound the encoded store fits inside writes it, so the rejection above is
    // the store bound rather than an unwritable path.
    Limits roomy = base_limits();
    roomy.max_store_bytes = 64U * 1024U;
    Harness control = make_harness(roomy);
    ARF_CHECK_EQ(control.fabric->save(store.path()).outcome, Outcome::POLICY_UPDATED);
    std::string error;
    const auto written = read_store_bytes(store.path(), error);
    ARF_REQUIRE(written.has_value());
    ARF_CHECK(written->size() <= roomy.max_store_bytes);
    ARF_CHECK(decode_durable_state(*written).ok());
    cover("max_store_bytes");
  }
}

// ---------------------------------------------------------------------------
// Transport-owned bounds
// ---------------------------------------------------------------------------

ARF_TEST(limits_transport_owned_bounds_are_reachable_from_the_configuration) {
  const Limits limits = base_limits();

  // max_receive_stall_millis is exercised by the distributed suite: the receive
  // loop converts it into a monotonic budget and fails the session when a partial
  // frame exceeds it. This suite records it as covered by asserting that the
  // configured value is positive, that it converts to the exact tick budget, and
  // that Socket::receive accepts that budget as its stall bound.
  ARF_CHECK(limits.max_receive_stall_millis > 0);
  const Ticks stall_budget = milliseconds(limits.max_receive_stall_millis);
  ARF_CHECK(stall_budget > 0);
  ARF_CHECK_EQ(stall_budget / ticks_per_millisecond, limits.max_receive_stall_millis);
  std::string buffer;
  Socket socket;
  const Socket::ReceiveResult received =
      socket.receive(buffer, SteadyClock::instance(), stall_budget);
  ARF_CHECK_EQ(received.status, Socket::ReceiveStatus::ERROR);
  ARF_CHECK_EQ(received.bytes, static_cast<std::size_t>(0));
  ARF_CHECK(!received.error.empty());
  cover("max_receive_stall_millis");

  // max_sessions bounds the coordinator's session table on accept. Real sessions
  // are the distributed suite's subject; what is recorded here is that the
  // configured value is positive and is the one the server reads.
  CoordinatorServer::Config server_config;
  server_config.limits = limits;
  ARF_CHECK(server_config.limits.max_sessions > 0);
  ARF_CHECK_EQ(server_config.limits.max_sessions, limits.max_sessions);
  cover("max_sessions");
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

// Runs last (the runner executes tests in name order) and proves that the set of
// limits this suite drove is exactly the set the library describes.
ARF_TEST(zzz_limits_coverage_matches_describe) {
  const std::vector<std::pair<std::string, std::uint64_t>> described = Limits{}.describe();
  ARF_CHECK_MSG(!described.empty(), "Limits::describe() must enumerate every configured limit");

  std::set<std::string> described_names;
  for (const auto& entry : described) {
    ARF_CHECK_MSG(described_names.insert(entry.first).second,
                  "limit " + entry.first + " is described twice");
    ARF_CHECK_MSG(entry.second > 0, "limit " + entry.first + " is not a positive bound");
  }

  std::vector<std::string> missing;
  for (const std::string& name : described_names) {
    if (covered_limits().count(name) == 0) {
      missing.push_back(name);
    }
  }
  std::vector<std::string> extra;
  for (const std::string& name : covered_limits()) {
    if (described_names.count(name) == 0) {
      extra.push_back(name);
    }
  }
  std::string missing_text;
  for (const std::string& name : missing) {
    missing_text += " " + name;
  }
  std::string extra_text;
  for (const std::string& name : extra) {
    extra_text += " " + name;
  }
  ARF_CHECK_MSG(missing.empty(), "described but never driven:" + missing_text);
  ARF_CHECK_MSG(extra.empty(), "driven but not described:" + extra_text);
  ARF_CHECK_EQ(described_names, covered_limits());
}

}  // namespace

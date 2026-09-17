// Persistence tests: durable state round trips, deterministic encoding, the
// corruption rejection matrix, atomic replacement and conservative recovery.
//
// The store's integrity trailer is mirrored here for the same reason the frame
// trailer is mirrored in test_wire.cpp: several corruption cases (trailing bytes,
// an absurd record count, a record past the per-record bound) need a store whose
// trailer is *valid*, so that the defect under test is the one that is reported
// rather than INTEGRITY. Stores the library encodes are decoded first, so a
// divergence between the mirror and the library is reported, not hidden.
#include <cstdint>
#include <filesystem>
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

// Defined with the durable values below; the framing helpers need its encoded
// bytes to learn the magic and the header layout instead of hardcoding them.
[[nodiscard]] DurableState base_state();

[[nodiscard]] std::uint64_t read_u64_at(std::string_view bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(
                 static_cast<unsigned char>(bytes[offset + index]))
             << (8U * index);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Store framing
// ---------------------------------------------------------------------------

// Reference implementation of the documented store trailer: a deterministic
// non-cryptographic hash over the framing bytes and the record body.
[[nodiscard]] std::uint64_t store_trailer_of(std::string_view header_and_body) {
  std::uint64_t low = 14695981039346656037ULL;
  std::uint64_t high = 0x9E3779B97F4A7C15ULL;
  for (const char character : header_and_body) {
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

void append_trailer(std::string& bytes) {
  ByteWriter tail;
  tail.put_u64(store_trailer_of(bytes));
  bytes += tail.take();
}

// The eight framing bytes (magic and format version) exactly as the encoder
// writes them, so this suite never hardcodes the magic it is asserting about.
[[nodiscard]] std::string store_framing() {
  const std::string bytes = encode_durable_state(base_state());
  return bytes.substr(0, 8);
}

// The five header counters (epoch, authority generation, evidence generation and
// both watermarks) exactly as the encoder writes them.
[[nodiscard]] std::string store_header_counters() {
  const std::string bytes = encode_durable_state(base_state());
  return bytes.substr(8, 40);
}

// A store whose framing and counters are real and whose record body is supplied
// by the caller, sealed with a valid trailer.
[[nodiscard]] std::string sealed_store(std::string_view body) {
  std::string bytes = store_framing();
  bytes += store_header_counters();
  bytes.append(body.data(), body.size());
  append_trailer(bytes);
  return bytes;
}

[[nodiscard]] std::string absurd_record_count_store() {
  ByteWriter body;
  body.put_u64(Limits{}.max_policies + 1U);
  return sealed_store(body.buffer());
}

[[nodiscard]] std::string oversized_record_store() {
  ByteWriter body;
  body.put_u64(1);                                           // one policy record
  body.put_u64(Limits{}.max_persistence_record_bytes + 1U);  // its declared length
  return sealed_store(body.buffer());
}

// ---------------------------------------------------------------------------
// Temporary store files
// ---------------------------------------------------------------------------

[[nodiscard]] std::string temp_store_path(std::string_view label) {
  const std::filesystem::path directory = std::filesystem::temp_directory_path();
  const std::filesystem::path file =
      directory /
      ("arf-persistence-" + std::string(label) + "-" + process_nonce() + ".store");
  return file.string();
}

// Removes the store and its sibling temporary on every exit path, including a
// failing assertion, so a failed run never leaves a file behind.
class TempStore {
 public:
  explicit TempStore(std::string path) : path_(std::move(path)) { cleanup(); }
  ~TempStore() { cleanup(); }
  TempStore(const TempStore&) = delete;
  TempStore& operator=(const TempStore&) = delete;
  TempStore(TempStore&&) = delete;
  TempStore& operator=(TempStore&&) = delete;

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

// ---------------------------------------------------------------------------
// Durable values
// ---------------------------------------------------------------------------

[[nodiscard]] PolicyScope durable_scope() {
  PolicyScope scope;
  scope.fabric = arf_test::fabric_id();
  scope.name_space = arf_test::routing_namespace();
  scope.site = SiteId::require("site-a");
  scope.path_class = PathClass::require("gold");
  scope.routes.push_back(RouteId::require("route-1"));
  scope.multipath_sets.push_back(MultipathSetId::require("set-1"));
  return scope;
}

// A semantics value that exercises every durable field: two threshold-free
// triggers, two evidence requirements, hold-down, cooldown, bounded dampening,
// churn bounds, a two term objective, an emergency rule and a candidate
// priority.
[[nodiscard]] PolicySemantics durable_semantics() {
  PolicySemantics semantics;
  semantics.target.route = arf_test::route_id();
  semantics.target.multipath_set = MultipathSetId::require("set-1");

  ThresholdRule threshold;
  threshold.kind = MetricKind::PATH_UTILIZATION;
  threshold.switch_value =
      MetricValue::make(MetricKind::PATH_UTILIZATION, 8000).value_or(MetricValue{});
  threshold.clear_value =
      MetricValue::make(MetricKind::PATH_UTILIZATION, 2000).value_or(MetricValue{});
  semantics.thresholds.push_back(threshold);

  ImprovementRule improvement;
  improvement.kind = MetricKind::PATH_LATENCY;
  improvement.switch_improvement_bps = 250;
  improvement.reverse_improvement_bps = 500;
  semantics.improvements.push_back(improvement);

  semantics.evidence.push_back(arf_test::utilization_requirement());
  semantics.evidence.push_back(arf_test::latency_requirement());

  semantics.hold_down.duration = seconds(30);
  semantics.cooldown.duration = seconds(10);

  semantics.dampening.enabled = true;
  semantics.dampening.penalty_increment = 1;
  semantics.dampening.max_penalty = 4;
  semantics.dampening.penalty_decay_interval = seconds(60);
  semantics.dampening.penalty_decay_step = 1;
  semantics.dampening.hold_down_escalation_step = seconds(5);
  semantics.dampening.max_effective_hold_down = seconds(120);

  semantics.churn.max_adaptations_per_window = 8;
  semantics.churn.window = seconds(300);

  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm utilization_term;
  utilization_term.kind = MetricKind::PATH_UTILIZATION;
  objective.terms.push_back(utilization_term);
  ObjectiveTerm latency_term;
  latency_term.kind = MetricKind::PATH_LATENCY;
  objective.terms.push_back(latency_term);
  semantics.objective = objective;

  semantics.emergency.enabled = true;
  semantics.emergency.on_current_path_unavailable = true;

  CandidatePriority priority;
  priority.path = PathId::require("path-b");
  priority.priority = 5;
  semantics.priorities.push_back(priority);
  return semantics;
}

[[nodiscard]] AdaptivePolicy durable_policy(std::string_view id, std::string_view name,
                                            PolicyLifecycle lifecycle, std::uint64_t generation) {
  AdaptivePolicy policy;
  policy.id = AdaptivePolicyId::require(id);
  policy.name = AdaptivePolicyName::require(name);
  policy.scope = durable_scope();
  policy.semantics = durable_semantics();
  policy.generation = AdaptivePolicyGeneration::require(generation);
  policy.lifecycle = lifecycle;
  policy.epoch = CoordinatorEpoch::require(4);
  policy.owner = PublisherId::require("publisher-a");
  policy.authority_generation = AdaptiveAuthorityGeneration::require(2);
  policy.declared_at = 1000;
  policy.updated_at = 2000;
  return policy;
}

// The smallest durable state that still decodes: the framing helpers are derived
// from it and the atomic write test uses it as the previous content.
[[nodiscard]] DurableState base_state() {
  DurableState state;
  state.format_version = persistence_format_version;
  state.epoch = CoordinatorEpoch::require(1);
  state.authority_generation = AdaptiveAuthorityGeneration::require(1);
  state.evidence_generation = EvidenceGeneration::require(1);
  return state;
}

// A durable state that carries a value for every field of every record type.
[[nodiscard]] DurableState sample_state() {
  DurableState state;
  state.format_version = persistence_format_version;
  state.epoch = CoordinatorEpoch::require(4);
  state.authority_generation = AdaptiveAuthorityGeneration::require(2);
  state.evidence_generation = EvidenceGeneration::require(7);
  state.evidence_watermark = Watermark(3);
  state.upstream_watermark = Watermark(5);

  const AdaptivePolicy active =
      durable_policy("policy-1", "policy-one", PolicyLifecycle::ACTIVE, 3);
  const AdaptivePolicy suspended =
      durable_policy("policy-2", "policy-two", PolicyLifecycle::SUSPENDED, 1);
  const AdaptivePolicy revoked =
      durable_policy("policy-3", "policy-three", PolicyLifecycle::REVOKED, 2);
  state.policies.push_back(active);
  state.policies.push_back(suspended);
  state.policies.push_back(revoked);

  RevocationRecord revocation;
  revocation.policy = revoked.id;
  revocation.generation = AdaptivePolicyGeneration::require(2);
  revocation.authority_generation = AdaptiveAuthorityGeneration::require(2);
  revocation.epoch = CoordinatorEpoch::require(4);
  revocation.publisher = PublisherId::require("publisher-a");
  revocation.reason = RevocationReason::SECURITY;
  revocation.detail = "security revocation";
  state.revocations.push_back(revocation);

  DurablePreference preference;
  preference.policy = active.id;
  RoutingPreference& intent = preference.preference;
  intent.route = arf_test::route_id();
  intent.multipath_set = MultipathSetId::require("set-1");
  intent.multipath_set_generation = MultipathSetGeneration::require(2);
  intent.preferred_path = PathId::require("path-b");
  intent.path_authority_generation = PathAuthorityGeneration::require(5);
  intent.previous_path = PathId::require("path-a");
  intent.route_generation = RouteGeneration::require(3);
  intent.adaptation_generation = AdaptationGeneration::require(6);
  intent.transition_generation = TransitionGeneration::require(8);
  intent.transition = TransitionPlanId::require("transition-1");
  WeightProposal proposal;
  proposal.set = WeightedPathSetId::require("weighted-1");
  proposal.base_generation = WeightPolicyGeneration::require(2);
  PathWeight weight;
  weight.path = PathId::require("path-b");
  weight.weight_bps = basis_points_scale;
  proposal.weights.push_back(weight);
  intent.weight_proposal = proposal;
  intent.decision = AdaptationDecisionId::require("decision-1");
  intent.provenance.publisher = PublisherId::require("publisher-a");
  intent.provenance.worker_boot = WorkerBootId::require("boot-a1");
  intent.provenance.epoch = CoordinatorEpoch::require(4);
  intent.provenance.attempt = MutationAttemptId::require("attempt-9");
  intent.provenance.policy_generation = AdaptivePolicyGeneration::require(3);
  intent.provenance.cause = AdaptationCause::EVIDENCE_OBSERVED;
  intent.committed_at = 12345;
  intent.established = true;
  state.preferences.push_back(preference);

  DurableStable stable;
  stable.policy = active.id;
  stable.stable.established = true;
  stable.stable.path = PathId::require("path-b");
  stable.stable.path_authority_generation = PathAuthorityGeneration::require(5);
  stable.stable.route_generation = RouteGeneration::require(3);
  stable.stable.multipath_set_generation = MultipathSetGeneration::require(2);
  stable.stable.adaptation_generation = AdaptationGeneration::require(6);
  stable.stable.stabilized_at = 12400;
  state.stable_states.push_back(stable);

  DurableTiming timing;
  timing.policy = active.id;
  timing.hold_down_active = true;
  timing.hold_down_remaining = seconds(20);
  timing.hold_down_policy_generation = AdaptivePolicyGeneration::require(3);
  timing.hold_down_locked_path = PathId::require("path-a");
  timing.cooldown_active = true;
  timing.cooldown_remaining = seconds(5);
  timing.dampening_penalty = 2;
  timing.dampening_decay_remaining = seconds(45);
  timing.churn_ages.push_back(seconds(1));
  timing.churn_ages.push_back(seconds(2));
  state.timings.push_back(timing);

  AdaptationRecord committed;
  committed.decision = AdaptationDecisionId::require("decision-1");
  committed.lifecycle = DecisionLifecycle::COMMITTED;
  committed.outcome = Outcome::DECISION_COMMITTED;
  committed.suppression = SuppressionReason::NONE;
  committed.cause = AdaptationCause::TRIGGER_SATISFIED;
  committed.from_path = PathId::require("path-a");
  committed.to_path = PathId::require("path-b");
  committed.adaptation_generation = AdaptationGeneration::require(6);
  committed.evidence_generation = EvidenceGeneration::require(7);
  committed.epoch = CoordinatorEpoch::require(4);
  committed.committed_at = 12345;
  committed.digest = "00112233445566778899aabbccddeeff";
  {
    DurableHistoryEntry entry;
    entry.policy = AdaptivePolicyId::require("policy-1");
    entry.record = committed;
    state.history.push_back(entry);
  }

  AdaptationRecord suppressed;
  suppressed.decision = AdaptationDecisionId::require("decision-2");
  suppressed.lifecycle = DecisionLifecycle::SUPPRESSED;
  suppressed.outcome = Outcome::NO_CHANGE;
  suppressed.suppression = SuppressionReason::BELOW_THRESHOLD;
  suppressed.cause = AdaptationCause::EVIDENCE_OBSERVED;
  suppressed.to_path = PathId::require("path-b");
  suppressed.adaptation_generation = AdaptationGeneration::require(6);
  suppressed.evidence_generation = EvidenceGeneration::require(7);
  suppressed.epoch = CoordinatorEpoch::require(4);
  suppressed.committed_at = 13000;
  suppressed.digest = "ffeeddccbbaa99887766554433221100";
  {
    DurableHistoryEntry entry;
    entry.policy = AdaptivePolicyId::require("policy-1");
    entry.record = suppressed;
    state.history.push_back(entry);
  }

  return state;
}

// One deterministic operation sequence: create, bind two candidates, publish
// one sample for each, commit the initial preference and revoke a second policy.
void drive_identical_history(Harness& harness) {
  const AdaptivePolicyId active =
      arf_test::create_active_policy(harness, arf_test::latency_semantics(250, 500));
  ARF_CHECK_EQ(arf_test::declare_candidate(harness, active,
                                           arf_test::make_binding(arf_test::path("path-a"), 1))
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::declare_candidate(harness, active,
                                           arf_test::make_binding(arf_test::path("path-b"), 1))
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::publish_latency(harness, arf_test::path("path-a"), 5000, 1).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::publish_latency(harness, arf_test::path("path-b"), 1000, 1).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::evaluate_policy(harness, active).outcome, Outcome::DECISION_COMMITTED);
  const AdaptivePolicyId withdrawn =
      arf_test::create_active_policy(harness, arf_test::latency_semantics(250, 500));
  ARF_CHECK_EQ(harness.fabric
                   ->revoke_policy(withdrawn, RevocationReason::ADMINISTRATIVE,
                                   "policy withdrawn", harness.context())
                   .outcome,
               Outcome::POLICY_UPDATED);
}

// ---------------------------------------------------------------------------
// Field by field comparison
// ---------------------------------------------------------------------------

void expect_semantics_equal(const PolicySemantics& actual, const PolicySemantics& expected) {
  ARF_CHECK_EQ(actual.semantics_version, expected.semantics_version);
  ARF_CHECK_EQ(actual.render(), expected.render());
  ARF_CHECK_EQ(actual.thresholds.size(), expected.thresholds.size());
  ARF_CHECK_EQ(actual.improvements.size(), expected.improvements.size());
  ARF_CHECK_EQ(actual.evidence.size(), expected.evidence.size());
  ARF_CHECK_EQ(actual.objective.terms.size(), expected.objective.terms.size());
  ARF_CHECK_EQ(actual.objective.mode, expected.objective.mode);
  ARF_CHECK_EQ(actual.priorities.size(), expected.priorities.size());
  ARF_CHECK_EQ(actual.hold_down.duration, expected.hold_down.duration);
  ARF_CHECK_EQ(actual.dampening.max_penalty, expected.dampening.max_penalty);
  ARF_CHECK_EQ(actual.churn.window, expected.churn.window);
  ARF_CHECK_EQ(actual.emergency.enabled, expected.emergency.enabled);
  if (!expected.priorities.empty()) {
    ARF_CHECK_EQ(actual.priorities.front().path, expected.priorities.front().path);
    ARF_CHECK_EQ(actual.priorities.front().priority, expected.priorities.front().priority);
  }
}

void expect_durable_equal(const DurableState& actual, const DurableState& expected) {
  ARF_CHECK_EQ(actual.format_version, expected.format_version);
  ARF_CHECK_EQ(actual.epoch, expected.epoch);
  ARF_CHECK_EQ(actual.authority_generation, expected.authority_generation);
  ARF_CHECK_EQ(actual.evidence_generation, expected.evidence_generation);
  ARF_CHECK_EQ(actual.evidence_watermark, expected.evidence_watermark);
  ARF_CHECK_EQ(actual.upstream_watermark, expected.upstream_watermark);

  ARF_REQUIRE(actual.policies.size() == expected.policies.size());
  for (std::size_t index = 0; index < expected.policies.size(); ++index) {
    const AdaptivePolicy& policy = actual.policies[index];
    const AdaptivePolicy& want = expected.policies[index];
    ARF_CHECK_EQ(policy.id, want.id);
    ARF_CHECK_EQ(policy.name, want.name);
    ARF_CHECK_EQ(policy.scope.render(), want.scope.render());
    ARF_CHECK_EQ(policy.generation, want.generation);
    ARF_CHECK_EQ(policy.lifecycle, want.lifecycle);
    ARF_CHECK_EQ(policy.epoch, want.epoch);
    ARF_CHECK_EQ(policy.owner, want.owner);
    ARF_CHECK_EQ(policy.authority_generation, want.authority_generation);
    ARF_CHECK_EQ(policy.declared_at, want.declared_at);
    ARF_CHECK_EQ(policy.updated_at, want.updated_at);
    expect_semantics_equal(policy.semantics, want.semantics);
  }

  ARF_REQUIRE(actual.revocations.size() == expected.revocations.size());
  for (std::size_t index = 0; index < expected.revocations.size(); ++index) {
    const RevocationRecord& revocation = actual.revocations[index];
    const RevocationRecord& want = expected.revocations[index];
    ARF_CHECK_EQ(revocation.policy, want.policy);
    ARF_CHECK_EQ(revocation.generation, want.generation);
    ARF_CHECK_EQ(revocation.authority_generation, want.authority_generation);
    ARF_CHECK_EQ(revocation.epoch, want.epoch);
    ARF_CHECK_EQ(revocation.publisher, want.publisher);
    ARF_CHECK_EQ(revocation.reason, want.reason);
    ARF_CHECK_EQ(revocation.detail, want.detail);
  }

  ARF_REQUIRE(actual.preferences.size() == expected.preferences.size());
  for (std::size_t index = 0; index < expected.preferences.size(); ++index) {
    const DurablePreference& entry = actual.preferences[index];
    const DurablePreference& want = expected.preferences[index];
    ARF_CHECK_EQ(entry.policy, want.policy);
    const RoutingPreference& intent = entry.preference;
    const RoutingPreference& expected_intent = want.preference;
    ARF_CHECK_EQ(intent.route, expected_intent.route);
    ARF_CHECK_EQ(intent.multipath_set.has_value(), expected_intent.multipath_set.has_value());
    if (expected_intent.multipath_set.has_value()) {
      ARF_CHECK_EQ(*intent.multipath_set, *expected_intent.multipath_set);
    }
    ARF_CHECK_EQ(intent.multipath_set_generation, expected_intent.multipath_set_generation);
    ARF_CHECK_EQ(intent.established, expected_intent.established);
    ARF_CHECK_EQ(intent.preferred_path, expected_intent.preferred_path);
    ARF_CHECK_EQ(intent.path_authority_generation, expected_intent.path_authority_generation);
    ARF_CHECK_EQ(intent.previous_path, expected_intent.previous_path);
    ARF_CHECK_EQ(intent.route_generation, expected_intent.route_generation);
    ARF_CHECK_EQ(intent.adaptation_generation, expected_intent.adaptation_generation);
    ARF_CHECK_EQ(intent.transition_generation, expected_intent.transition_generation);
    ARF_CHECK_EQ(intent.transition, expected_intent.transition);
    ARF_CHECK_EQ(intent.decision, expected_intent.decision);
    ARF_CHECK_EQ(intent.committed_at, expected_intent.committed_at);
    ARF_CHECK_EQ(intent.provenance.publisher, expected_intent.provenance.publisher);
    ARF_CHECK_EQ(intent.provenance.worker_boot, expected_intent.provenance.worker_boot);
    ARF_CHECK_EQ(intent.provenance.epoch, expected_intent.provenance.epoch);
    ARF_CHECK_EQ(intent.provenance.attempt, expected_intent.provenance.attempt);
    ARF_CHECK_EQ(intent.provenance.policy_generation,
                 expected_intent.provenance.policy_generation);
    ARF_CHECK_EQ(intent.provenance.cause, expected_intent.provenance.cause);
    ARF_CHECK_EQ(intent.weight_proposal.has_value(), expected_intent.weight_proposal.has_value());
    ARF_REQUIRE(intent.weight_proposal.has_value());
    ARF_CHECK_EQ(intent.weight_proposal->set, expected_intent.weight_proposal->set);
    ARF_CHECK_EQ(intent.weight_proposal->base_generation,
                 expected_intent.weight_proposal->base_generation);
    ARF_REQUIRE(intent.weight_proposal->weights.size() ==
                expected_intent.weight_proposal->weights.size());
    for (std::size_t weight = 0; weight < expected_intent.weight_proposal->weights.size();
         ++weight) {
      ARF_CHECK_EQ(intent.weight_proposal->weights[weight].path,
                   expected_intent.weight_proposal->weights[weight].path);
      ARF_CHECK_EQ(intent.weight_proposal->weights[weight].weight_bps,
                   expected_intent.weight_proposal->weights[weight].weight_bps);
    }
  }

  ARF_REQUIRE(actual.stable_states.size() == expected.stable_states.size());
  for (std::size_t index = 0; index < expected.stable_states.size(); ++index) {
    const DurableStable& stable = actual.stable_states[index];
    const DurableStable& want = expected.stable_states[index];
    ARF_CHECK_EQ(stable.policy, want.policy);
    ARF_CHECK_EQ(stable.stable.established, want.stable.established);
    ARF_CHECK_EQ(stable.stable.path, want.stable.path);
    ARF_CHECK_EQ(stable.stable.path_authority_generation,
                 want.stable.path_authority_generation);
    ARF_CHECK_EQ(stable.stable.route_generation, want.stable.route_generation);
    ARF_CHECK_EQ(stable.stable.multipath_set_generation,
                 want.stable.multipath_set_generation);
    ARF_CHECK_EQ(stable.stable.adaptation_generation, want.stable.adaptation_generation);
    ARF_CHECK_EQ(stable.stable.stabilized_at, want.stable.stabilized_at);
  }

  ARF_REQUIRE(actual.timings.size() == expected.timings.size());
  for (std::size_t index = 0; index < expected.timings.size(); ++index) {
    const DurableTiming& timing = actual.timings[index];
    const DurableTiming& want = expected.timings[index];
    ARF_CHECK_EQ(timing.policy, want.policy);
    ARF_CHECK_EQ(timing.hold_down_active, want.hold_down_active);
    ARF_CHECK_EQ(timing.hold_down_remaining, want.hold_down_remaining);
    ARF_CHECK_EQ(timing.hold_down_policy_generation, want.hold_down_policy_generation);
    ARF_CHECK_EQ(timing.hold_down_locked_path, want.hold_down_locked_path);
    ARF_CHECK_EQ(timing.cooldown_active, want.cooldown_active);
    ARF_CHECK_EQ(timing.cooldown_remaining, want.cooldown_remaining);
    ARF_CHECK_EQ(timing.dampening_penalty, want.dampening_penalty);
    ARF_CHECK_EQ(timing.dampening_decay_remaining, want.dampening_decay_remaining);
    ARF_CHECK_EQ(timing.churn_ages, want.churn_ages);
  }

  ARF_REQUIRE(actual.history.size() == expected.history.size());
  for (std::size_t index = 0; index < expected.history.size(); ++index) {
    const AdaptationRecord& record = actual.history[index].record;
    const AdaptationRecord& want = expected.history[index].record;
    ARF_CHECK_EQ(record.decision, want.decision);
    ARF_CHECK_EQ(record.lifecycle, want.lifecycle);
    ARF_CHECK_EQ(record.outcome, want.outcome);
    ARF_CHECK_EQ(record.suppression, want.suppression);
    ARF_CHECK_EQ(record.cause, want.cause);
    ARF_CHECK_EQ(record.from_path, want.from_path);
    ARF_CHECK_EQ(record.to_path, want.to_path);
    ARF_CHECK_EQ(record.adaptation_generation, want.adaptation_generation);
    ARF_CHECK_EQ(record.evidence_generation, want.evidence_generation);
    ARF_CHECK_EQ(record.epoch, want.epoch);
    ARF_CHECK_EQ(record.digest, want.digest);
  }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

ARF_TEST(persistence_durable_state_round_trips_every_field) {
  const DurableState original = sample_state();
  const std::string bytes = encode_durable_state(original);
  ARF_CHECK(bytes.size() > 64);

  // The trailer is the last eight bytes and covers everything before it.
  ARF_CHECK_EQ(read_u64_at(bytes, bytes.size() - 8),
               store_trailer_of(std::string_view(bytes).substr(0, bytes.size() - 8)));

  const StoreDecodeResult decoded = decode_durable_state(bytes);
  ARF_REQUIRE_MSG(decoded.ok(), decoded.detail);
  expect_durable_equal(decoded.state, original);

  // Re-encoding the decoded value reproduces the same bytes, so no field can
  // survive a decode in a half-restored state.
  ARF_CHECK_EQ(encode_durable_state(decoded.state), bytes);
}

ARF_TEST(persistence_encoding_is_deterministic) {
  const DurableState state = sample_state();
  ARF_CHECK_EQ(encode_durable_state(state), encode_durable_state(state));

  const StoreDecodeResult decoded = decode_durable_state(encode_durable_state(state));
  ARF_REQUIRE(decoded.ok());
  ARF_CHECK_EQ(encode_durable_state(decoded.state), encode_durable_state(state));

  // Two independently built copies of the same durable value encode identically.
  ARF_CHECK_EQ(encode_durable_state(sample_state()), encode_durable_state(sample_state()));
}

ARF_TEST(persistence_two_engines_with_identical_histories_encode_identical_stores) {
  // Two engines driven through the same operation sequence on their own
  // deterministic clocks must produce byte-identical stores: identity values,
  // generations, watermarks and timestamps all have to be reproducible.
  Harness first = make_harness();
  Harness second = make_harness();
  drive_identical_history(first);
  drive_identical_history(second);
  ARF_CHECK_EQ(first.fabric->encode_store(), second.fabric->encode_store());
  ARF_CHECK_EQ(first.fabric->epoch(), second.fabric->epoch());
  ARF_CHECK_EQ(first.fabric->evidence_generation(), second.fabric->evidence_generation());
  ARF_CHECK_EQ(first.fabric->stats().policies, second.fabric->stats().policies);
}

// ---------------------------------------------------------------------------
// Corruption
// ---------------------------------------------------------------------------

ARF_TEST(persistence_corruption_is_rejected_with_the_exact_status) {
  const std::string real = encode_durable_state(sample_state());
  ARF_REQUIRE(decode_durable_state(real).ok());

  ARF_CHECK_EQ(decode_durable_state(std::string_view()).status, StoreDecodeStatus::EMPTY);

  {
    std::string bad_magic = real;
    bad_magic[0] = static_cast<char>(static_cast<unsigned char>(bad_magic[0]) ^ 0x01U);
    ARF_CHECK_EQ(decode_durable_state(bad_magic).status, StoreDecodeStatus::BAD_MAGIC);
  }
  {
    std::string bad_version = real;
    bad_version[4] = static_cast<char>(static_cast<unsigned char>(bad_version[4]) + 1);
    ARF_CHECK_EQ(decode_durable_state(bad_version).status, StoreDecodeStatus::BAD_VERSION);
  }
  {
    // A flipped bit anywhere in the body is an integrity failure, not a
    // reinterpretation of the record it lands in.
    for (const std::size_t offset : {8U, 40U, 120U, 400U}) {
      ARF_REQUIRE(offset < real.size() - 8);
      std::string flipped = real;
      flipped[offset] = static_cast<char>(static_cast<unsigned char>(flipped[offset]) ^ 0x10U);
      ARF_CHECK_EQ(decode_durable_state(flipped).status, StoreDecodeStatus::INTEGRITY);
    }
  }
  {
    // A header generation of zero is never authority.
    DurableState state = sample_state();
    state.epoch = CoordinatorEpoch();
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::INVALID_GENERATION);
  }
  {
    DurableState state = sample_state();
    state.policies.front().generation = AdaptivePolicyGeneration();
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::INVALID_GENERATION);
  }
  {
    DurableState state = sample_state();
    state.revocations.front().epoch = CoordinatorEpoch();
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::INVALID_GENERATION);
  }
  {
    // The same policy identity twice. The copy is taken first: growing a vector
    // from a reference into itself is exactly the kind of aliasing a test must
    // not rely on.
    DurableState state = sample_state();
    const AdaptivePolicy duplicate = state.policies.front();
    state.policies.push_back(duplicate);
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::DUPLICATE_POLICY);
  }
  {
    // A metric outside its declared range.
    DurableState state = sample_state();
    state.preferences.front().preference.weight_proposal->weights.front().weight_bps =
        basis_points_scale + 1U;
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::MALFORMED_METRIC);
  }
  {
    // A metric value that is absent where a rule requires one leaves the policy
    // semantics invalid, which is a malformed record rather than a silent
    // default.
    DurableState state = sample_state();
    state.policies.front().semantics.thresholds.front().switch_value = MetricValue();
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::MALFORMED);
  }
  {
    // An established preference without a preferred candidate.
    DurableState state = sample_state();
    state.preferences.front().preference.preferred_path = PathId();
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::INVALID_PREFERRED_CANDIDATE);
  }
  {
    // An established preference that names a route its owner does not target.
    DurableState state = sample_state();
    state.preferences.front().preference.route = RouteId::require("route-2");
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::INVALID_PREFERRED_CANDIDATE);
  }
  {
    // Hold-down state that names no policy would re-arm against nothing.
    DurableState state = sample_state();
    state.timings.front().policy = AdaptivePolicyId::require("policy-absent");
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::TIMING_WITHOUT_POLICY);
  }
  {
    DurableState state = sample_state();
    state.stable_states.front().policy = AdaptivePolicyId::require("policy-absent");
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::TIMING_WITHOUT_POLICY);
  }
  {
    // A dampening penalty beyond the configured bound.
    DurableState state = sample_state();
    state.timings.front().dampening_penalty =
        static_cast<std::uint32_t>(Limits{}.max_dampening_penalty + 1U);
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::MALFORMED_TIMING);
  }
  {
    // A hold-down remainder while hold-down is inactive.
    DurableState state = sample_state();
    state.timings.front().hold_down_active = false;
    ARF_CHECK_EQ(decode_durable_state(encode_durable_state(state)).status,
                 StoreDecodeStatus::MALFORMED_TIMING);
  }
  ARF_CHECK_EQ(decode_durable_state(absurd_record_count_store()).status,
               StoreDecodeStatus::ABSURD_COUNT);
  ARF_CHECK_EQ(decode_durable_state(oversized_record_store()).status,
               StoreDecodeStatus::TRUNCATED);
  {
    // Trailing bytes after the last record: the body parses and then refuses to
    // end, which must never be reported as a successful decode.
    std::string with_trailing = real.substr(0, real.size() - 8);
    with_trailing.push_back('\0');
    with_trailing.push_back('\0');
    append_trailer(with_trailing);
    ARF_CHECK_EQ(decode_durable_state(with_trailing).status,
                 StoreDecodeStatus::TRAILING_BYTES);
  }
}

ARF_TEST(persistence_every_truncation_of_a_real_store_is_rejected) {
  const std::string bytes = encode_durable_state(sample_state());
  ARF_REQUIRE(bytes.size() > 64);
  ARF_REQUIRE(decode_durable_state(bytes).ok());

  std::size_t accepted = 0;
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    const StoreDecodeResult decoded =
        decode_durable_state(std::string_view(bytes).substr(0, length));
    if (decoded.ok()) {
      ++accepted;
    }
    if (length == 0) {
      ARF_CHECK_EQ(decoded.status, StoreDecodeStatus::EMPTY);
    } else if (length < 16) {
      // Below the framing and the trailer there is nothing to interpret.
      ARF_CHECK_EQ(decoded.status, StoreDecodeStatus::TRUNCATED);
    }
  }
  ARF_CHECK_EQ(accepted, static_cast<std::size_t>(0));
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

ARF_TEST(persistence_atomic_write_keeps_the_previous_store_when_replacement_fails) {
  TempStore store(temp_store_path("atomic"));
  const std::string first = encode_durable_state(base_state());
  const std::string second = encode_durable_state(sample_state());
  ARF_CHECK(first != second);

  std::string error;
  ARF_CHECK(write_store_atomic(store.path(), first, error));
  ARF_CHECK(error.empty());
  const auto written = read_store_bytes(store.path(), error);
  ARF_REQUIRE(written.has_value());
  ARF_CHECK_EQ(*written, first);

  // The replacement is made to fail by occupying the sibling temporary path with
  // a directory, which cannot be opened for writing.
  std::error_code code;
  std::filesystem::create_directory(store.path() + ".tmp", code);
  ARF_REQUIRE_MSG(!code, code.message());
  std::string replacement_error;
  ARF_CHECK(!write_store_atomic(store.path(), second, replacement_error));
  ARF_CHECK(!replacement_error.empty());

  // The previous store is untouched and still decodes: a failed replacement
  // never leaves a half-written file behind.
  const auto survived = read_store_bytes(store.path(), error);
  ARF_REQUIRE(survived.has_value());
  ARF_CHECK_EQ(*survived, first);
  ARF_CHECK(decode_durable_state(*survived).ok());

  // A successful replacement then makes the new content readable.
  std::filesystem::remove_all(store.path() + ".tmp", code);
  ARF_REQUIRE(!code);
  ARF_CHECK(write_store_atomic(store.path(), second, replacement_error));
  const auto replaced = read_store_bytes(store.path(), error);
  ARF_REQUIRE(replaced.has_value());
  ARF_CHECK_EQ(*replaced, second);
  ARF_CHECK(decode_durable_state(*replaced).ok());
}

ARF_TEST(persistence_read_store_bytes_reports_a_missing_file_without_throwing) {
  TempStore store(temp_store_path("missing"));
  store.cleanup();
  std::string error;
  const auto bytes = read_store_bytes(store.path(), error);
  ARF_CHECK(!bytes.has_value());
  ARF_CHECK(!error.empty());
}

// ---------------------------------------------------------------------------
// Engine recovery
// ---------------------------------------------------------------------------

ARF_TEST(persistence_engine_load_advances_the_epoch_and_drops_live_authority) {
  TempStore store(temp_store_path("engine"));
  Harness owner = make_harness();
  const AdaptivePolicyId active =
      arf_test::create_active_policy(owner, arf_test::latency_semantics(250, 500));
  ARF_CHECK_EQ(arf_test::declare_candidate(owner, active,
                                           arf_test::make_binding(arf_test::path("path-a"), 1))
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::declare_candidate(owner, active,
                                           arf_test::make_binding(arf_test::path("path-b"), 1))
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::publish_latency(owner, arf_test::path("path-a"), 5000, 1).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::publish_latency(owner, arf_test::path("path-b"), 1000, 1).outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::evaluate_policy(owner, active).outcome, Outcome::DECISION_COMMITTED);
  const AdaptivePolicyId withdrawn =
      arf_test::create_active_policy(owner, arf_test::latency_semantics(250, 500));
  ARF_CHECK_EQ(owner.fabric
                   ->revoke_policy(withdrawn, RevocationReason::ADMINISTRATIVE,
                                   "withdrawn for the restart scenario", owner.context())
                   .outcome,
               Outcome::POLICY_UPDATED);

  const CoordinatorEpoch saved_epoch = owner.fabric->epoch();
  ARF_CHECK_EQ(owner.fabric->save(store.path()).outcome, Outcome::POLICY_UPDATED);

  Harness restarted = make_harness();
  // A context captured before the load: it carries the pre-restart epoch and the
  // pre-restart registration.
  const MutationContext stale = restarted.context();
  const OperationResult loaded = restarted.fabric->load(store.path());
  ARF_CHECK_EQ(loaded.outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(restarted.fabric->epoch().value(), saved_epoch.value() + 1);
  ARF_CHECK_EQ(restarted.fabric->evidence_generation(), owner.fabric->evidence_generation());

  // Live process authority is not durable: no publisher registration survives,
  // so a mutation is refused even before its payload is looked at.
  ARF_CHECK(restarted.fabric->describe_authority().registrations.empty());
  PublishEvidenceRequest evidence;
  evidence.publications.push_back(arf_test::make_publication(
      arf_test::path("path-a"), MetricKind::PATH_LATENCY, 1500, 2, EvidenceQuality::AGGREGATED));
  evidence.context = stale;
  ARF_CHECK_EQ(restarted.fabric->publish_evidence(evidence).outcome, Outcome::STALE_EPOCH);
  MutationContext adopted = stale;
  adopted.epoch = restarted.fabric->epoch();
  evidence.context = adopted;
  ARF_CHECK_EQ(restarted.fabric->publish_evidence(evidence).outcome, Outcome::UNAUTHORIZED);

  // Recovered policies require revalidation; a revoked policy stays revoked.
  const std::vector<AdaptivePolicy> recovered = restarted.fabric->list_policies();
  ARF_CHECK_EQ(recovered.size(), static_cast<std::size_t>(2));
  for (const AdaptivePolicy& policy : recovered) {
    if (policy_lifecycle_terminal(policy.lifecycle)) {
      ARF_CHECK_EQ(policy.lifecycle, PolicyLifecycle::REVOKED);
    } else {
      ARF_CHECK_EQ(policy.lifecycle, PolicyLifecycle::REVALIDATION_REQUIRED);
    }
  }

  // No evidence is restored: the store carries durable intent, not telemetry.
  ARF_CHECK(restarted.fabric->describe_evidence(active).empty());
  const EvidenceSnapshotPtr snapshot = restarted.fabric->capture_evidence(active);
  ARF_REQUIRE(snapshot != nullptr);
  ARF_CHECK(snapshot->values().empty());

  // Once the policy is back in service and its candidate re-declared, the
  // required metric is still absent, so nothing is eligible.
  ARF_CHECK_EQ(restarted.fabric
                   ->register_publisher(restarted.publisher, restarted.worker_boot,
                                        arf_test::default_scope(), restarted.session)
                   .outcome,
               Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::declare_candidate(restarted, active,
                                           arf_test::make_binding(arf_test::path("path-a"), 1))
                   .outcome,
               Outcome::POLICY_UPDATED);
  PolicyLifecycleRequest resume;
  resume.policy = active;
  resume.event = PolicyEvent::REVALIDATE;
  resume.detail = "post recovery revalidation";
  resume.context = restarted.context();
  ARF_CHECK_EQ(restarted.fabric->transition_policy(resume).outcome, Outcome::POLICY_UPDATED);
  ARF_CHECK_EQ(arf_test::evaluate_policy(restarted, active).outcome,
               Outcome::NO_ELIGIBLE_CANDIDATE);
  // The refused evaluation is still recorded as a decision with its reason, and
  // the decision that was durable before the restart is recovered with its
  // owning policy intact, so the per-policy journal carries both.
  ARF_CHECK_EQ(restarted.fabric->decisions_for_policy(active, 16).size(),
               static_cast<std::size_t>(2));
}

ARF_TEST(persistence_repeated_save_load_cycles_advance_the_epoch_monotonically) {
  TempStore store(temp_store_path("cycles"));
  Harness engine = make_harness();
  const AdaptivePolicyId policy =
      arf_test::create_active_policy(engine, arf_test::latency_semantics(250, 500));
  ARF_CHECK(policy.valid());

  std::uint64_t expected_epoch = engine.fabric->epoch().value() + 1;
  for (int cycle = 0; cycle < 3; ++cycle) {
    ARF_CHECK_EQ(engine.fabric->save(store.path()).outcome, Outcome::POLICY_UPDATED);
    Harness restarted = make_harness();
    ARF_CHECK_EQ(restarted.fabric->load(store.path()).outcome, Outcome::POLICY_UPDATED);
    ARF_CHECK_EQ(restarted.fabric->epoch().value(), expected_epoch);
    ARF_CHECK_EQ(restarted.fabric->list_policies().size(), static_cast<std::size_t>(1));
    expected_epoch = restarted.fabric->epoch().value() + 1;
    // The next cycle saves from the newly recovered engine, so the epoch keeps
    // advancing instead of resetting.
    engine = std::move(restarted);
  }
  ARF_CHECK_EQ(engine.fabric->epoch().value(), static_cast<std::uint64_t>(4));
}

}  // namespace

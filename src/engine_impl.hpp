// Internal engine state.
//
// This header is private to the library. It is not installed and no public type
// depends on it.
//
// LOCKING CONTRACT
// ----------------
// One std::shared_mutex guards all mutable state.
//   * queries take a shared lock;
//   * mutations take an exclusive lock;
//   * evaluation phase one takes a shared lock only long enough to copy the
//     inputs it needs, then releases it and evaluates lock-free;
//   * evaluation phase two takes an exclusive lock and re-verifies every
//     dependency before mutating.
// No callback, no clock read and no allocation-heavy work ever runs while an
// exclusive lock is held beyond what the mutation itself requires. The
// evaluation hook is invoked after the shared lock is released, never under it.
#ifndef ADAPTIVE_ROUTING_SRC_ENGINE_IMPL_HPP
#define ADAPTIVE_ROUTING_SRC_ENGINE_IMPL_HPP

#include <atomic>
#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <vector>

#include "adaptive_routing/fabric.hpp"
#include "adaptive_routing/persistence.hpp"

namespace adaptive_routing::detail {

struct EvidenceKey {
  EvidenceSourceId source;
  PathId path;
  MetricKind kind = MetricKind::PATH_LATENCY;

  [[nodiscard]] friend bool operator<(const EvidenceKey& a, const EvidenceKey& b) noexcept {
    if (a.source != b.source) {
      return a.source < b.source;
    }
    if (a.path != b.path) {
      return a.path < b.path;
    }
    return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
  }
};

struct EvidenceSeries {
  EvidenceSourceId source;
  EvidenceSourceGeneration source_generation;
  EvidenceQuality quality = EvidenceQuality::PRIMARY;
  PathId path;
  MetricKind kind = MetricKind::PATH_LATENCY;
  // Retained in observation order. Bounded by
  // Limits::max_evidence_samples_per_series, consulted on every publication.
  std::deque<EvidenceSample> samples;
  std::uint64_t total_published = 0;
};

struct CandidateRecord {
  CandidateBinding binding;
  // Per-path monotonic invalidation watermark. Advanced by every upstream event
  // that can invalidate a decision which already selected this path.
  std::uint64_t path_watermark = 0;
};

// Restart-safe timing. In memory it is held as absolute monotonic deadlines;
// on disk it is held as remaining durations (see persistence.hpp).
struct TimingState {
  bool hold_down_active = false;
  Ticks hold_down_deadline = 0;
  PathId hold_down_locked_path;
  bool cooldown_active = false;
  Ticks cooldown_deadline = 0;
  std::uint32_t dampening_penalty = 0;
  Ticks dampening_last_decay = 0;
  // Monotonic timestamps of committed adaptations inside the churn window.
  std::deque<Ticks> churn_commits;
};

struct PolicyRecord {
  AdaptivePolicy policy;
  std::vector<CandidateRecord> candidates;  // kept sorted by PathId
  RoutingPreference preference;
  StableState stable;
  TimingState timing;
  std::deque<AdaptationRecord> history;
  std::optional<RevocationRecord> revocation;

  [[nodiscard]] const CandidateRecord* find_candidate(const PathId& path) const noexcept;
  [[nodiscard]] CandidateRecord* find_candidate(const PathId& path) noexcept;
};

struct AttemptRecord {
  MutationAttemptId attempt;
  std::string fingerprint;
  Outcome outcome = Outcome::NO_CHANGE;
  std::string detail;
};

// The complete engine state. Never copied; always accessed through Impl.
struct State {
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  EvidenceGeneration evidence_generation;
  Watermark evidence_watermark;
  Watermark upstream_watermark;

  std::map<AdaptivePolicyId, PolicyRecord> policies;
  std::map<AdaptivePolicyName, AdaptivePolicyId> policy_names;
  std::map<PublisherId, PublisherRegistration> registrations;
  std::map<WorkerBootId, PublisherId> live_boots;
  std::set<WorkerBootId> fenced_boots;
  std::vector<FenceRecord> fences;
  std::map<AdaptivePolicyId, RevocationRecord> revocations;
  std::map<EvidenceKey, EvidenceSeries> evidence;
  std::map<MutationAttemptId, AttemptRecord> attempts;
  std::deque<MutationAttemptId> attempt_order;
  std::map<SnapshotId, std::shared_ptr<const AdaptationSnapshot>> snapshots;
  std::deque<SnapshotId> snapshot_order;
  std::deque<AdaptationDecision> decision_journal;

  // Reverse indexes. A targeted path invalidation must not scan every policy.
  std::map<PathId, std::set<AdaptivePolicyId>> policies_by_path;
  std::map<RouteId, std::set<AdaptivePolicyId>> policies_by_route;
  std::map<MultipathSetId, std::set<AdaptivePolicyId>> policies_by_set;
  std::map<EvidenceSourceId, std::set<AdaptivePolicyId>> policies_by_source;
};

// Values copied out of the state under a shared lock and then evaluated
// lock-free. Nothing here aliases engine state.
struct EvaluationInputs {
  AdaptivePolicy policy;
  std::vector<CandidateRecord> candidates;
  RoutingPreference preference;
  StableState stable;
  TimingState timing;
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  EvidenceGeneration evidence_generation;
  Watermark evidence_watermark;
  Watermark upstream_watermark;
  EvidenceSnapshotPtr evidence;
  Ticks now = 0;
  Limits limits;
};

struct CommitVerification {
  bool ok = false;
  Outcome outcome = Outcome::NO_CHANGE;
  SuppressionReason suppression = SuppressionReason::NONE;
  std::string detail;
};

class Impl {
 public:
  explicit Impl(EngineConfig config);
  ~Impl();
  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  // --- authority -----------------------------------------------------------
  OperationResult register_publisher(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                     const AuthorityScope& scope, const SessionId& session);
  OperationResult fence_publisher(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                  std::string_view cause);
  OperationResult advance_epoch(std::string_view reason);
  [[nodiscard]] CoordinatorEpoch epoch() const;
  [[nodiscard]] AdaptiveAuthorityGeneration authority_generation() const;
  [[nodiscard]] AuthorityDescription describe_authority() const;
  [[nodiscard]] bool is_fenced(const PublisherId& publisher, const WorkerBootId& worker_boot) const;

  // --- policy --------------------------------------------------------------
  OperationResult create_policy(const CreatePolicyRequest& request);
  OperationResult update_policy(const UpdatePolicyRequest& request);
  OperationResult transition_policy(const PolicyLifecycleRequest& request);
  OperationResult revoke_policy(const AdaptivePolicyId& policy, RevocationReason reason,
                                std::string detail, const MutationContext& context);
  [[nodiscard]] std::optional<AdaptivePolicy> find_policy(const AdaptivePolicyId& policy) const;
  [[nodiscard]] std::vector<AdaptivePolicy> list_policies() const;
  [[nodiscard]] std::optional<RevocationRecord> find_revocation(
      const AdaptivePolicyId& policy) const;
  [[nodiscard]] std::vector<RevocationRecord> list_revocations() const;

  // --- upstream ------------------------------------------------------------
  OperationResult apply_upstream(const UpstreamNotifyRequest& request);
  [[nodiscard]] std::vector<CandidateBinding> candidates(const AdaptivePolicyId& policy) const;
  [[nodiscard]] std::vector<AdaptivePolicyId> policies_for_path(const PathId& path) const;
  [[nodiscard]] std::vector<AdaptivePolicyId> policies_for_route(const RouteId& route) const;
  [[nodiscard]] std::vector<AdaptivePolicyId> policies_for_multipath_set(
      const MultipathSetId& set) const;
  [[nodiscard]] std::vector<AdaptivePolicyId> policies_for_evidence_source(
      const EvidenceSourceId& source) const;

  // --- evidence ------------------------------------------------------------
  OperationResult publish_evidence(const PublishEvidenceRequest& request);
  [[nodiscard]] EvidenceGeneration evidence_generation() const;
  [[nodiscard]] Watermark evidence_watermark() const;
  [[nodiscard]] Watermark upstream_watermark() const;
  [[nodiscard]] std::vector<EvidenceSeriesView> describe_evidence(
      const AdaptivePolicyId& policy) const;
  [[nodiscard]] EvidenceSnapshotPtr capture_evidence(const AdaptivePolicyId& policy) const;

  // --- evaluation ----------------------------------------------------------
  [[nodiscard]] EvaluationTicket begin_evaluation(const EvaluateRequest& request);
  OperationResult commit_evaluation(const CommitDecisionRequest& request);
  OperationResult evaluate(const EvaluateRequest& request);

  // --- decisions -----------------------------------------------------------
  [[nodiscard]] std::optional<AdaptationDecision> find_decision(
      const AdaptationDecisionId& decision) const;
  [[nodiscard]] std::vector<AdaptationDecision> list_decisions(std::uint64_t limit) const;
  [[nodiscard]] std::vector<AdaptationDecision> decisions_for_policy(
      const AdaptivePolicyId& policy, std::uint64_t limit) const;
  OperationResult rollback(const RollbackRequest& request);
  OperationResult revalidate(const AdaptivePolicyId& policy, RevalidationAttemptId attempt,
                             const MutationContext& context);

  // --- views ---------------------------------------------------------------
  [[nodiscard]] AdaptationSnapshot snapshot(const AdaptivePolicyId& policy) const;
  [[nodiscard]] std::vector<SnapshotId> retained_snapshots() const;
  [[nodiscard]] std::optional<AdaptationSnapshot> find_snapshot(const SnapshotId& snapshot) const;
  [[nodiscard]] Explanation explain(ExplanationTopic topic, const AdaptivePolicyId& policy) const;
  [[nodiscard]] Explanation explain_decision(const AdaptationDecisionId& decision) const;

  // --- persistence ---------------------------------------------------------
  [[nodiscard]] std::string encode_store() const;
  OperationResult save(const std::string& path) const;
  OperationResult load(const std::string& path);
  OperationResult decode_store(std::string_view bytes, std::string_view origin);

  // --- diagnostics ---------------------------------------------------------
  [[nodiscard]] FabricStats stats() const;
  [[nodiscard]] Limits limits() const { return config_.limits; }
  [[nodiscard]] const Clock& clock() const noexcept { return *clock_; }
  [[nodiscard]] const EngineConfig& config() const noexcept { return config_; }

  // --- internal helpers used across translation units ----------------------

  [[nodiscard]] Ticks now() const;

  // Caller identity, epoch, worker authority and scope. Shared by every
  // mutating entry point so that the rejection precedence is identical
  // everywhere.
  struct CallerCheck {
    Outcome outcome = Outcome::NO_CHANGE;
    std::string detail;
    bool ok = false;
    const PublisherRegistration* registration = nullptr;
  };
  [[nodiscard]] CallerCheck check_caller(const State& state, const MutationContext& context,
                                         const std::optional<RouteId>& route,
                                         const std::optional<MultipathSetId>& set) const;

  // Replay recognition. Returns a result when the attempt id was already
  // applied with the same fingerprint (IDEMPOTENT) or with a different one
  // (ATTEMPT_CONFLICT).
  [[nodiscard]] std::optional<OperationResult> replay_check(State& state,
                                                            const MutationAttemptId& attempt,
                                                            std::string_view fingerprint);
  void record_attempt(State& state, const MutationAttemptId& attempt, std::string fingerprint,
                      Outcome outcome, std::string detail);
  [[nodiscard]] std::optional<std::string> fingerprint_policy(const PolicyScope& scope,
                                                              const PolicySemantics& semantics) const;
  [[nodiscard]] OperationResult make_result(Outcome outcome, std::string detail,
                                            const AdaptivePolicyId& policy,
                                            const State& state) const;
  [[nodiscard]] Outcome lifecycle_outcome(PolicyLifecycle lifecycle) const;

  void reindex_policy(State& state, const AdaptivePolicyId& policy);
  void unindex_policy(State& state, const AdaptivePolicyId& policy);
  void prune_attempts(State& state);
  void prune_history(PolicyRecord& record, const Limits& limits) const;
  void retain_snapshot(State& state,
                       std::shared_ptr<const AdaptationSnapshot> snapshot) const;

  [[nodiscard]] EvidenceSnapshotPtr capture_evidence_locked(const State& state,
                                                            const PolicyRecord& record) const;
  [[nodiscard]] std::optional<EvidenceAggregate> aggregate_for(
      const State& state, const PathId& path, const EvidenceRequirement& requirement) const;
  // Same computation, additionally reporting which series supplied the value so
  // that a snapshot can bind the exact source and source generation it used.
  [[nodiscard]] std::optional<EvidenceAggregate> aggregate_for(
      const State& state, const PathId& path, const EvidenceRequirement& requirement,
      const EvidenceSeries** source) const;
  [[nodiscard]] std::optional<MetricValue> metric_for(const State& state, const PathId& path,
                                                      MetricKind kind,
                                                      const PolicySemantics& semantics) const;

  [[nodiscard]] EvaluationInputs copy_inputs(const State& state,
                                             const PolicyRecord& record) const;
  [[nodiscard]] EvaluationTicket evaluate_inputs(const EvaluationInputs& inputs,
                                                 const DependencySnapshot& dependencies) const;
  [[nodiscard]] CommitVerification verify_and_commit(State& state, PolicyRecord& record,
                                                     const EvaluationTicket& ticket,
                                                     const MutationContext& context,
                                                     const PublisherRegistration* registration);
  [[nodiscard]] DependencySnapshot build_dependencies(const State& state,
                                                      const PolicyRecord& record,
                                                      const EvaluationId& evaluation) const;
  // Returns the precise reason the recorded dependencies no longer match, or
  // NO_CHANGE when they still do.
  [[nodiscard]] std::optional<Outcome> dependency_drift(const State& state,
                                                        const PolicyRecord& record,
                                                        const DependencySnapshot& snapshot) const;

  void apply_invalidation(State& state, const PathId& path, Outcome reason);
  [[nodiscard]] Explanation build_explanation(const State& state, const PolicyRecord& record,
                                              const EvaluationInputs& inputs,
                                              ExplanationTopic topic) const;

  [[nodiscard]] DurableState build_durable(const State& state) const;
  [[nodiscard]] OperationResult apply_durable(State& state, const DurableState& durable,
                                              std::string_view origin);

  EngineConfig config_;
  Limits limits_;
  std::shared_ptr<Clock> clock_;
  // Mutable because a shared-lock query (evidence capture, snapshot retention)
  // legitimately mints identities without mutating any guarded state.
  mutable IdFactory ids_;
  mutable std::shared_mutex mutex_;
  // Mutable because constructing a snapshot records it in the bounded snapshot
  // history. That history is a derived cache, never authoritative state, and the
  // const snapshot() entry point is the only const method that writes it.
  mutable State state_;
  FabricStats counters_;
  // Bounded by Limits::max_simultaneous_evaluations. Counts phase-one tickets
  // that have been issued and not yet settled by a commit.
  std::atomic<std::uint64_t> outstanding_evaluations_{0};
};

}  // namespace adaptive_routing::detail

#endif  // ADAPTIVE_ROUTING_SRC_ENGINE_IMPL_HPP

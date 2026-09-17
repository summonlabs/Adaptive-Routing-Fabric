// Adaptive Routing Fabric engine.
//
// OWNERSHIP AND LIFETIME
// ----------------------
// The engine owns every policy, candidate binding, evidence series, preference,
// decision and snapshot it returns. Values handed to a caller are copies: no
// returned object aliases engine state, and no returned pointer stays valid
// across a later mutation. The single exception is EvidenceSnapshotPtr, which is
// an immutable shared value and therefore safe to retain.
//
// THREAD SAFETY
// -------------
// Every public method is safe to call concurrently from any thread. Queries take
// a shared lock; mutations take an exclusive lock. Policy evaluation runs
// outside the exclusive lock in two phases, so a slow evaluation never blocks
// unrelated mutation and a stale evaluation can never commit.
//
// DETERMINISM
// -----------
// Given identical inputs, identical policy generations and identical upstream
// generations, the engine produces byte-identical decisions, digests and
// explanations. Iteration over unordered containers never influences a result;
// every ranking is total and canonical.
#ifndef ADAPTIVE_ROUTING_FABRIC_HPP
#define ADAPTIVE_ROUTING_FABRIC_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/authority.hpp"
#include "adaptive_routing/clock.hpp"
#include "adaptive_routing/decision.hpp"
#include "adaptive_routing/evidence.hpp"
#include "adaptive_routing/ids.hpp"
#include "adaptive_routing/limits.hpp"
#include "adaptive_routing/outcome.hpp"
#include "adaptive_routing/policy.hpp"
#include "adaptive_routing/upstream.hpp"
#include "adaptive_routing/view.hpp"

namespace adaptive_routing {

namespace detail {
// The engine implementation. Declared here only so that the public class can
// hold it by pointer; its definition is private to the library and is not
// installed.
class Impl;
}  // namespace detail

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

struct EngineConfig {
  Limits limits;
  // Elapsed-time source. Defaults to the production monotonic clock; tests
  // inject a deterministic clock and advance it explicitly.
  std::shared_ptr<Clock> clock;
  // Prefix used when the engine generates identities.
  std::string id_prefix = "arf";
  // Deterministic scheduling hook, invoked after an evaluation has snapshotted
  // its dependencies and before the commit verification runs. It exists so that
  // stale-completion races can be driven to an exact interleaving instead of
  // being hoped for; it must not mutate the engine.
  std::function<void(const DependencySnapshot&)> evaluation_hook;
  // Conservative recovery behaviour: when true, recovery marks every recovered
  // preference and policy as requiring revalidation.
  bool conservative_recovery = true;
};

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

struct FabricStats {
  std::uint64_t policies = 0;
  std::uint64_t adaptable_policies = 0;
  std::uint64_t revoked_policies = 0;
  std::uint64_t retired_policies = 0;
  std::uint64_t candidates = 0;
  std::uint64_t evidence_series = 0;
  std::uint64_t evidence_samples = 0;
  std::uint64_t decisions_committed = 0;
  std::uint64_t decisions_suppressed = 0;
  std::uint64_t decisions_rejected = 0;
  std::uint64_t evaluations = 0;
  std::uint64_t stale_commit_rejections = 0;
  std::uint64_t idempotent_replays = 0;
  std::uint64_t attempt_conflicts = 0;
  std::uint64_t publishers = 0;
  std::uint64_t fenced_workers = 0;
  std::uint64_t revocations = 0;
  std::uint64_t recoveries = 0;
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  EvidenceGeneration evidence_generation;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

class AdaptiveRoutingFabric {
 public:
  explicit AdaptiveRoutingFabric(EngineConfig config = {});
  ~AdaptiveRoutingFabric();

  AdaptiveRoutingFabric(const AdaptiveRoutingFabric&) = delete;
  AdaptiveRoutingFabric& operator=(const AdaptiveRoutingFabric&) = delete;
  AdaptiveRoutingFabric(AdaptiveRoutingFabric&&) noexcept;
  AdaptiveRoutingFabric& operator=(AdaptiveRoutingFabric&&) noexcept;

  // --- authority and epochs ------------------------------------------------

  // Registers a publisher incarnation for the current epoch. A fresh
  // WorkerBootId for an already known PublisherId permanently fences the
  // previous incarnation.
  OperationResult register_publisher(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                     const AuthorityScope& scope, const SessionId& session);
  // Fences a live incarnation without ending the process. Used on clean
  // disconnect, on scope revocation and on explicit administrative fencing.
  OperationResult fence_publisher(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                  std::string_view cause);
  // Advances the coordinator epoch, fences every live worker and requires
  // revalidation of every policy. Returns the new epoch in the result.
  OperationResult advance_epoch(std::string_view reason);

  [[nodiscard]] CoordinatorEpoch epoch() const noexcept;
  [[nodiscard]] AdaptiveAuthorityGeneration authority_generation() const noexcept;
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
  [[nodiscard]] std::optional<RevocationRecord> find_revocation(const AdaptivePolicyId& policy) const;
  [[nodiscard]] std::vector<RevocationRecord> list_revocations() const;

  // --- upstream bindings ---------------------------------------------------

  OperationResult apply_upstream(const UpstreamNotifyRequest& request);
  [[nodiscard]] std::vector<CandidateBinding> candidates(const AdaptivePolicyId& policy) const;

  // Targeted dependency queries. These answer "which policies depend on this
  // upstream fact?" from the reverse indexes rather than by scanning every
  // policy, which is exactly the question an operator asks before withdrawing a
  // path or a telemetry source. Results are in canonical policy-id order.
  [[nodiscard]] std::vector<AdaptivePolicyId> policies_for_path(const PathId& path) const;
  [[nodiscard]] std::vector<AdaptivePolicyId> policies_for_route(const RouteId& route) const;
  [[nodiscard]] std::vector<AdaptivePolicyId> policies_for_multipath_set(
      const MultipathSetId& set) const;
  [[nodiscard]] std::vector<AdaptivePolicyId> policies_for_evidence_source(
      const EvidenceSourceId& source) const;

  // --- evidence ------------------------------------------------------------

  OperationResult publish_evidence(const PublishEvidenceRequest& request);
  [[nodiscard]] EvidenceGeneration evidence_generation() const noexcept;
  [[nodiscard]] Watermark evidence_watermark() const noexcept;
  [[nodiscard]] Watermark upstream_watermark() const noexcept;
  [[nodiscard]] std::vector<EvidenceSeriesView> describe_evidence(
      const AdaptivePolicyId& policy) const;
  // Immutable evidence snapshot for the policy's exact candidate set.
  [[nodiscard]] EvidenceSnapshotPtr capture_evidence(const AdaptivePolicyId& policy) const;

  // --- evaluation ----------------------------------------------------------

  // Phase one. Snapshots every dependency, evaluates the policy outside the
  // engine lock and returns a ticket. The ticket is not authority: committing it
  // re-verifies every generation and watermark.
  [[nodiscard]] EvaluationTicket begin_evaluation(const EvaluateRequest& request);
  // Phase two. Re-acquires the lock, verifies the ticket's dependencies and
  // commits atomically or rejects with the exact stale dependency named.
  OperationResult commit_evaluation(const CommitDecisionRequest& request);
  // Convenience: begin_evaluation followed by commit_evaluation.
  OperationResult evaluate(const EvaluateRequest& request);

  // --- decisions -----------------------------------------------------------

  [[nodiscard]] std::optional<AdaptationDecision> find_decision(
      const AdaptationDecisionId& decision) const;
  [[nodiscard]] std::vector<AdaptationDecision> list_decisions(std::uint64_t limit) const;
  [[nodiscard]] std::vector<AdaptationDecision> decisions_for_policy(
      const AdaptivePolicyId& policy, std::uint64_t limit) const;
  // Explicit rollback intent. Revalidates the rollback target against current
  // Path Authority and current multipath membership; a target that is no longer
  // legal is refused rather than restored.
  OperationResult rollback(const RollbackRequest& request);
  // Requests revalidation of a policy against current upstream state.
  OperationResult revalidate(const AdaptivePolicyId& policy, RevalidationAttemptId attempt,
                             const MutationContext& context);

  // --- views ---------------------------------------------------------------

  [[nodiscard]] AdaptationSnapshot snapshot(const AdaptivePolicyId& policy) const;
  [[nodiscard]] std::vector<SnapshotId> retained_snapshots() const;
  [[nodiscard]] std::optional<AdaptationSnapshot> find_snapshot(const SnapshotId& snapshot) const;
  [[nodiscard]] Explanation explain(ExplanationTopic topic, const AdaptivePolicyId& policy) const;
  [[nodiscard]] Explanation explain_decision(const AdaptationDecisionId& decision) const;

  // --- persistence ---------------------------------------------------------

  // Deterministic encoding of the durable state. Integrity checked, versioned,
  // bounded and free of live process authority.
  [[nodiscard]] std::string encode_store() const;
  OperationResult save(const std::string& path) const;
  // Decodes and applies a durable state. Recovery is conservative: live
  // publisher authority is never restored, recovered preferences require
  // revalidation and old epoch traffic is rejected.
  OperationResult load(const std::string& path);
  OperationResult decode_store(std::string_view bytes, std::string_view origin);

  // --- diagnostics ---------------------------------------------------------

  [[nodiscard]] FabricStats stats() const;
  [[nodiscard]] Limits limits() const;
  [[nodiscard]] const Clock& clock() const noexcept;
  [[nodiscard]] const EngineConfig& config() const noexcept;

 private:
  std::unique_ptr<detail::Impl> impl_;
};

// Renders an outcome as its stable textual name.
[[nodiscard]] std::string render_outcome(Outcome outcome);

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_FABRIC_HPP

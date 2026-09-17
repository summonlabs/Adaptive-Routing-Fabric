// Routing preference, adaptation decisions, dependency snapshots and the
// two-phase evaluation ticket.
//
// PREFERENCE IS INTENT
// --------------------
// A committed decision records *desired* routing preference. It is not a route
// installation, it is not forwarding state and it is not convergence. The
// desired-versus-applied distinction is structural here: nothing in this header
// represents applied state, and no code path infers that traffic moved.
#ifndef ADAPTIVE_ROUTING_DECISION_HPP
#define ADAPTIVE_ROUTING_DECISION_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "adaptive_routing/authority.hpp"
#include "adaptive_routing/clock.hpp"
#include "adaptive_routing/evidence.hpp"
#include "adaptive_routing/ids.hpp"
#include "adaptive_routing/lifecycle.hpp"
#include "adaptive_routing/metrics.hpp"
#include "adaptive_routing/outcome.hpp"
#include "adaptive_routing/policy.hpp"
#include "adaptive_routing/upstream.hpp"

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Weight proposal
// ---------------------------------------------------------------------------

// A *proposal* handed to Weighted Path Fabric. Adaptive Routing Fabric never
// commits it: committing a weight policy is Weighted Path Fabric's authority.
struct PathWeight {
  PathId path;
  std::uint32_t weight_bps = 0;
};

struct WeightProposal {
  WeightedPathSetId set;
  // The weight generation the proposal was computed against.
  WeightPolicyGeneration base_generation;
  std::vector<PathWeight> weights;

  [[nodiscard]] bool well_formed() const noexcept;
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Transition plan
// ---------------------------------------------------------------------------

// The bounded, local description of a desired preference change. Route
// Convergence owns what happens next across the fabric; this record only says
// what Adaptive Routing Fabric wants the route-visible preference to become.
struct TransitionPlan {
  TransitionPlanId id;
  TransitionGeneration generation;
  RouteId route;
  PathId from_path;
  PathAuthorityGeneration from_path_authority_generation;
  PathId to_path;
  PathAuthorityGeneration to_path_authority_generation;
  AdaptationGeneration adaptation_generation;
  bool rollback = false;

  [[nodiscard]] bool well_formed() const noexcept {
    return id.valid() && generation.valid() && route.valid() && to_path.valid();
  }
};

// ---------------------------------------------------------------------------
// Preference
// ---------------------------------------------------------------------------

struct RoutingPreference {
  RouteId route;
  std::optional<MultipathSetId> multipath_set;
  MultipathSetGeneration multipath_set_generation;
  PathId preferred_path;
  PathAuthorityGeneration path_authority_generation;
  // The preference this one superseded. It is the anchor of the asymmetric
  // reverse hysteresis requirement: restoring it is strictly harder than the
  // move that displaced it.
  PathId previous_path;
  RouteGeneration route_generation;
  AdaptationGeneration adaptation_generation;
  TransitionGeneration transition_generation;
  TransitionPlanId transition;
  std::optional<WeightProposal> weight_proposal;
  AdaptationDecisionId decision;
  AdaptationProvenance provenance;
  Ticks committed_at = 0;
  bool established = false;

  [[nodiscard]] bool well_formed() const noexcept {
    return route.valid() && preferred_path.valid() && adaptation_generation.valid() &&
           transition_generation.valid();
  }
  [[nodiscard]] std::string render() const;
};

// Last known stable preference. Stability is *asserted by the runtime*, never
// inferred from the mere existence of a previous generation: a preference is
// recorded stable only when its dependencies matched, no transition was
// pending, hold-down was satisfied and no stale evidence dependency existed.
struct StableState {
  bool established = false;
  PathId path;
  PathAuthorityGeneration path_authority_generation;
  RouteGeneration route_generation;
  MultipathSetGeneration multipath_set_generation;
  AdaptationGeneration adaptation_generation;
  Ticks stabilized_at = 0;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Candidate evaluation
// ---------------------------------------------------------------------------

struct CandidateEvaluation {
  PathId path;
  bool eligible = false;
  // Why the candidate is not eligible, NONE when it is.
  SuppressionReason rejection = SuppressionReason::NONE;
  Outcome rejection_outcome = Outcome::NO_CHANGE;
  EvidenceQuality quality = EvidenceQuality::ESTIMATED;
  std::optional<std::uint64_t> score;
  // One entry per objective term, in declared term order.
  std::vector<MetricValue> metrics;
  std::uint32_t priority = 0;
  bool current_preference = false;
  bool previous_preference = false;
  std::uint32_t required_improvement_bps = 0;
  std::optional<std::uint32_t> observed_improvement_bps;
  PathAuthorityGeneration path_authority_generation;
  MultipathSetGeneration multipath_set_generation;
  RouteGeneration route_generation;
};

// ---------------------------------------------------------------------------
// Dependency snapshot and evaluation ticket
// ---------------------------------------------------------------------------

// Every generation, watermark and binding an evaluation read. Commit succeeds
// only when every element is still exactly what the evaluation saw.
struct DependencySnapshot {
  EvaluationId evaluation;
  AdaptivePolicyId policy;
  AdaptivePolicyGeneration policy_generation;
  EvidenceGeneration evidence_generation;
  Watermark evidence_watermark;
  Watermark upstream_watermark;
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  RouteGeneration route_generation;
  std::optional<MultipathSetId> multipath_set;
  MultipathSetGeneration multipath_set_generation;
  std::vector<PathAuthorityBinding> candidate_path_authority;
  std::vector<std::uint64_t> candidate_path_watermarks;
  std::vector<PathId> candidates;
  Ticks captured_at = 0;

  [[nodiscard]] std::string render() const;
};

// The two-phase evaluation handle. Phase one snapshots dependencies and
// evaluates outside the engine lock; phase two re-acquires the lock, verifies
// every generation/watermark and commits atomically. A ticket produced by a
// stale phase one is rejected with the exact stale dependency named.
struct EvaluationTicket {
  DependencySnapshot dependencies;
  // PROPOSED before commit, ELIGIBLE when the proposal is committable,
  // SUPPRESSED/REJECTED when phase one already proved no adaptation.
  DecisionLifecycle lifecycle = DecisionLifecycle::PROPOSED;
  AdaptationDecisionId decision;
  // The evidence snapshot this evaluation actually read. Recorded on the
  // resulting decision so that an audit can name the exact evidence state.
  EvidenceSnapshotId evidence_snapshot;
  Outcome outcome = Outcome::NO_CHANGE;
  SuppressionReason suppression = SuppressionReason::NONE;
  std::string detail;
  PathId current_preference;
  PathId target_preference;
  PathAuthorityGeneration target_path_authority_generation;
  AdaptationGeneration adaptation_generation;
  TransitionGeneration transition_generation;
  std::optional<std::uint64_t> target_score;
  std::optional<std::uint32_t> improvement_bps;
  std::uint32_t required_improvement_bps = 0;
  std::optional<WeightProposal> weight_proposal;
  bool rollback = false;
  bool emergency = false;
  std::vector<CandidateEvaluation> ranking;
  Ticks evaluated_at = 0;

  [[nodiscard]] bool committable() const noexcept {
    return lifecycle == DecisionLifecycle::ELIGIBLE;
  }
};

// ---------------------------------------------------------------------------
// Adaptation decision
// ---------------------------------------------------------------------------

struct AdaptationDecision {
  AdaptationDecisionId id;
  AdaptivePolicyId policy;
  AdaptivePolicyGeneration policy_generation;
  DecisionLifecycle lifecycle = DecisionLifecycle::PROPOSED;
  AdaptationCause cause = AdaptationCause::DECLARED;
  SuppressionReason suppression = SuppressionReason::NONE;
  Outcome outcome = Outcome::NO_CHANGE;
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  RouteId route;
  RouteGeneration route_generation;
  std::optional<MultipathSetId> multipath_set;
  MultipathSetGeneration multipath_set_generation;
  EvidenceSnapshotId evidence_snapshot;
  EvidenceGeneration evidence_generation;
  Watermark evidence_watermark;
  Watermark upstream_watermark;
  bool had_current_preference = false;
  PathId current_preference;
  PathAuthorityGeneration current_preference_authority_generation;
  PathId target_preference;
  PathAuthorityGeneration target_preference_authority_generation;
  AdaptationGeneration adaptation_generation;
  TransitionGeneration transition_generation;
  std::optional<std::uint64_t> target_score;
  std::optional<std::uint32_t> improvement_bps;
  std::uint32_t required_improvement_bps = 0;
  std::uint32_t candidates_considered = 0;
  std::uint32_t candidates_eligible = 0;
  std::vector<CandidateEvaluation> ranking;
  std::string digest;
  Ticks evaluated_at = 0;
  Ticks committed_at = 0;
  AdaptationProvenance provenance;

  [[nodiscard]] bool well_formed() const noexcept;
};

// ---------------------------------------------------------------------------
// Request descriptions
// ---------------------------------------------------------------------------

struct CreatePolicyRequest {
  AdaptivePolicyName name;
  PolicyScope scope;
  PolicySemantics semantics;
  MutationContext context;
};

struct UpdatePolicyRequest {
  AdaptivePolicyId policy;
  PolicyUpdate update;
  MutationContext context;
};

struct PolicyLifecycleRequest {
  AdaptivePolicyId policy;
  PolicyEvent event;
  std::string detail;
  MutationContext context;
};

struct PublishEvidenceRequest {
  std::vector<EvidencePublication> publications;
  MutationContext context;
};

struct EvaluateRequest {
  AdaptivePolicyId policy;
  MutationContext context;
  // When true the call returns the phase-one ticket without committing, which
  // is what makes an out-of-band deterministic stale-completion test possible
  // through the public surface rather than through a test-only hook.
  bool defer_commit = false;
};

struct CommitDecisionRequest {
  EvaluationTicket ticket;
  MutationContext context;
};

struct RollbackRequest {
  AdaptivePolicyId policy;
  std::string reason;
  MutationContext context;
};

struct UpstreamNotifyRequest {
  std::vector<UpstreamNotification> notifications;
  MutationContext context;
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_DECISION_HPP

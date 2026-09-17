// Mutation authority, scope, fencing, epochs and revocation.
//
// Being connected is not authority. Being a known publisher is not authority.
// Having a durable policy record is not authority. Every authoritative mutation
// binds the current coordinator epoch, the publisher, the worker boot
// incarnation, the authority scope, the expected generations and a mutation
// attempt id.
//
// AUTHORITY MODEL
// ---------------
// Exactly one coordinator owns mutation authority for an Adaptive Routing
// Fabric deployment. Adaptive Routing Fabric does not implement consensus and
// does not claim split-brain prevention between isolated coordinators. What it
// does implement is mandatory stale-epoch, stale-worker and stale-generation
// rejection: after an epoch advance or a coordinator restart no request
// carrying the previous epoch, the previous worker boot or a fenced session is
// ever accepted, and no request whose expected generation has moved is applied.
#ifndef ADAPTIVE_ROUTING_AUTHORITY_HPP
#define ADAPTIVE_ROUTING_AUTHORITY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/ids.hpp"

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Authority scope
// ---------------------------------------------------------------------------

// Default deny: a registration must name a fabric and a routing namespace. An
// empty routes vector authorizes every route inside that fabric/namespace pair;
// a non-empty vector authorizes exactly the listed routes. The same rule
// applies to multipath sets.
struct AuthorityScope {
  FabricId fabric;
  RoutingNamespace name_space;
  std::vector<RouteId> routes;
  std::vector<MultipathSetId> multipath_sets;

  [[nodiscard]] bool well_formed() const noexcept;
  // Namespace-level coverage, used when a policy identity does not exist yet.
  // A route-restricted scope never covers a namespace-level operation because
  // it cannot identify the route it would authorize.
  [[nodiscard]] bool covers_namespace(const FabricId& fabric_id,
                                      const RoutingNamespace& namespace_id) const noexcept;
  [[nodiscard]] bool covers_route(const FabricId& fabric_id, const RoutingNamespace& namespace_id,
                                  const RouteId& route) const noexcept;
  [[nodiscard]] bool covers_multipath_set(const FabricId& fabric_id,
                                          const RoutingNamespace& namespace_id,
                                          const MultipathSetId& set_id) const noexcept;
  [[nodiscard]] bool covers_all_routes() const noexcept { return routes.empty(); }
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Publisher registration
// ---------------------------------------------------------------------------

struct PublisherRegistration {
  PublisherId publisher;
  WorkerBootId worker_boot;
  AuthorityScope scope;
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  SessionId session;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Fencing
// ---------------------------------------------------------------------------

struct FenceRecord {
  PublisherId publisher;
  WorkerBootId worker_boot;
  CoordinatorEpoch epoch;
  // Deterministic cause: SESSION_LOST, EXPLICIT, EPOCH_ADVANCE, SHUTDOWN,
  // SCOPE_REVOKED, REINCARNATION.
  std::string cause;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

enum class RevocationReason : std::uint8_t {
  ADMINISTRATIVE = 1,
  SECURITY = 2,
  POLICY_VIOLATION = 3,
  AUTHORITY_REVOKED = 4,
  OPERATOR_REQUEST = 5,
};

[[nodiscard]] std::string_view to_string(RevocationReason reason) noexcept;
[[nodiscard]] std::optional<RevocationReason> parse_revocation_reason(std::string_view text) noexcept;
[[nodiscard]] bool valid_revocation_reason(std::uint8_t raw) noexcept;

// Revocation is durable, idempotent, generation-bound and reason-coded. It is
// distinct from evidence invalidation, from suspension and from retirement: a
// revoked policy is never reactivated, and revoking it does not discard the
// evidence the runtime holds for unrelated policies.
struct RevocationRecord {
  AdaptivePolicyId policy;
  AdaptivePolicyGeneration generation;
  AdaptiveAuthorityGeneration authority_generation;
  CoordinatorEpoch epoch;
  PublisherId publisher;
  RevocationReason reason = RevocationReason::ADMINISTRATIVE;
  std::string detail;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

enum class AdaptationCause : std::uint8_t {
  DECLARED = 1,
  POLICY_UPDATED = 2,
  EVIDENCE_OBSERVED = 3,
  TRIGGER_SATISFIED = 4,
  EMERGENCY_OVERRIDE = 5,
  ROLLBACK_REQUESTED = 6,
  PATH_AUTHORITY_INVALIDATED = 7,
  MULTIPATH_SET_INVALIDATED = 8,
  ROUTE_INVALIDATED = 9,
  EPOCH_ADVANCE = 10,
  RECOVERED = 11,
  REVALIDATED = 12,
  REVOKED = 13,
  RETIRED = 14,
};

[[nodiscard]] std::string_view to_string(AdaptationCause cause) noexcept;
[[nodiscard]] bool valid_adaptation_cause(std::uint8_t raw) noexcept;

struct AdaptationProvenance {
  PublisherId publisher;
  WorkerBootId worker_boot;
  CoordinatorEpoch epoch;
  MutationAttemptId attempt;
  AdaptivePolicyGeneration policy_generation;
  AdaptationCause cause = AdaptationCause::DECLARED;

  [[nodiscard]] std::string render() const;
};

// Provenance of an upstream binding notification, kept separate from adaptation
// provenance because the notifying authority is not the adapting authority.
struct UpstreamProvenance {
  PublisherId publisher;
  WorkerBootId worker_boot;
  CoordinatorEpoch epoch;
  MutationAttemptId attempt;
  std::string origin;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Mutation context
// ---------------------------------------------------------------------------

// The complete authority binding supplied with every mutation. A context with a
// missing element is malformed and rejected at the CALLER_IDENTITY or DECODE
// stage before any state is consulted.
struct MutationContext {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  SessionId session;
  MutationAttemptId attempt;
  std::optional<AdaptivePolicyGeneration> expected_policy_generation;
  std::optional<EvidenceGeneration> expected_evidence_generation;

  [[nodiscard]] bool has_caller_identity() const noexcept;
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Authority description
// ---------------------------------------------------------------------------

struct AuthorityDescription {
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;
  std::vector<PublisherRegistration> registrations;
  std::vector<FenceRecord> fence_records;

  [[nodiscard]] std::string render() const;
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_AUTHORITY_HPP

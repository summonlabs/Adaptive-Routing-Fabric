// Upstream binding contracts.
//
// Adaptive Routing Fabric consumes facts that other runtimes own. It never
// computes a candidate, never decides path legality, never invents multipath
// membership, never installs a route and never commits a weight policy. What it
// stores is a *binding*: the exact identity and generation of an upstream fact
// it was told about, plus a currentness verdict maintained by explicit
// invalidation.
//
// INTEGRATION SHAPE
// -----------------
// An upstream runtime (Path Authority, Multipath Fabric, Route Fabric,
// Weighted Path Fabric) notifies Adaptive Routing Fabric through
// \c UpstreamNotification. The notification carries the upstream provenance and
// the expected previous generation, so a notification that arrives out of order
// is rejected rather than applied. Adaptive Routing Fabric never calls back
// into an upstream runtime to change it.
#ifndef ADAPTIVE_ROUTING_UPSTREAM_HPP
#define ADAPTIVE_ROUTING_UPSTREAM_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/authority.hpp"
#include "adaptive_routing/ids.hpp"

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

// Path Authority is binding. A path is a candidate only while the exact
// PathAuthorityGeneration recorded here is the current one and that generation
// says the path is legally usable. Adaptive Routing Fabric never overrides a
// denial and never upgrades an unknown binding into a legal one.
struct PathAuthorityBinding {
  PathId path;
  PathAuthorityGeneration generation;
  bool legal = false;
  std::string denial_reason;

  [[nodiscard]] bool well_formed() const noexcept { return path.valid() && generation.valid(); }
  [[nodiscard]] std::string render() const;
};

// Multipath Fabric owns simultaneous-use membership. Adaptive Routing Fabric
// may choose among, or alter preference within, an exact current member set; it
// never adds or removes a member.
struct MultipathBinding {
  MultipathSetId set;
  MultipathSetGeneration generation;
  std::vector<PathId> members;
  bool current = false;

  [[nodiscard]] bool well_formed() const noexcept { return set.valid() && generation.valid(); }
  [[nodiscard]] bool contains(const PathId& path) const noexcept;
  [[nodiscard]] std::string render() const;
};

// Route Fabric owns route lifecycle and route state.
struct RouteBinding {
  RouteId route;
  RouteGeneration generation;
  // Site the route belongs to, as reported by the owning runtime. Used to match
  // the optional site dimension of a policy scope; an unknown site never
  // satisfies a site-restricted scope.
  SiteId site;
  bool current = false;
  // Free-form upstream route state label, carried for explanation only. It is
  // never parsed into an authority decision.
  std::string state;

  [[nodiscard]] bool well_formed() const noexcept { return route.valid() && generation.valid(); }
  [[nodiscard]] std::string render() const;
};

// Weighted Path Fabric owns explicit path weighting. Adaptive Routing Fabric
// may *propose* weights; it never commits them.
struct WeightedPolicyBinding {
  WeightedPathSetId set;
  WeightPolicyGeneration generation;
  bool current = false;

  [[nodiscard]] bool well_formed() const noexcept { return set.valid() && generation.valid(); }
  [[nodiscard]] std::string render() const;
};

// The complete upstream binding of one candidate path.
struct CandidateBinding {
  PathId path;
  PathAuthorityBinding path_authority;
  std::optional<MultipathBinding> multipath;
  RouteBinding route;
  std::optional<WeightedPolicyBinding> weighted;
  PathClass path_class;
  // Upstream reported the path unavailable (operationally down, administratively
  // removed). Distinct from illegal: a path can be legal and unavailable, or
  // unavailable and later legal again.
  bool available = true;
  // An explicit hard-failure signal supplied by an upstream authority. Consulted
  // only by an emergency rule that enables it.
  bool hard_failure = false;

  [[nodiscard]] bool well_formed() const noexcept {
    return path.valid() && path_authority.well_formed() && route.well_formed();
  }
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

enum class UpstreamEvent : std::uint8_t {
  DECLARE_CANDIDATE = 1,
  ADVANCE_PATH_AUTHORITY = 2,
  INVALIDATE_PATH = 3,
  SET_MEMBERSHIP = 4,
  INVALIDATE_MULTIPATH_SET = 5,
  ADVANCE_ROUTE = 6,
  INVALIDATE_ROUTE = 7,
  ADVANCE_WEIGHT_POLICY = 8,
  MARK_UNAVAILABLE = 9,
  MARK_AVAILABLE = 10,
  HARD_FAILURE_SIGNAL = 11,
  CLEAR_HARD_FAILURE_SIGNAL = 12,
};

[[nodiscard]] std::string_view to_string(UpstreamEvent event) noexcept;
[[nodiscard]] std::optional<UpstreamEvent> parse_upstream_event(std::string_view text) noexcept;
[[nodiscard]] bool valid_upstream_event(std::uint8_t raw) noexcept;

// True when the event can invalidate a candidate that an in-flight evaluation
// may already have selected. Used to advance the invalidation watermark.
[[nodiscard]] bool upstream_event_invalidates(UpstreamEvent event) noexcept;

struct UpstreamNotification {
  UpstreamEvent event = UpstreamEvent::DECLARE_CANDIDATE;
  // The policy whose candidate set the notification applies to.
  AdaptivePolicyId policy;
  CandidateBinding binding;
  UpstreamProvenance provenance;
  // Expected previous generation of the binding category the event touches.
  std::optional<std::uint64_t> expected_previous_generation;

  [[nodiscard]] std::string render() const;
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_UPSTREAM_HPP

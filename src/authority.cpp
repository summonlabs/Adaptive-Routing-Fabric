// Mutation authority, scope, fencing and revocation.
#include "adaptive_routing/authority.hpp"

#include <algorithm>

namespace adaptive_routing {

bool AuthorityScope::well_formed() const noexcept {
  if (!fabric.valid() || !name_space.valid()) {
    return false;
  }
  std::vector<RouteId> sorted_routes(routes);
  std::sort(sorted_routes.begin(), sorted_routes.end());
  if (std::adjacent_find(sorted_routes.begin(), sorted_routes.end()) != sorted_routes.end()) {
    return false;
  }
  std::vector<MultipathSetId> sorted_sets(multipath_sets);
  std::sort(sorted_sets.begin(), sorted_sets.end());
  return std::adjacent_find(sorted_sets.begin(), sorted_sets.end()) == sorted_sets.end();
}

bool AuthorityScope::covers_namespace(const FabricId& fabric_id,
                                      const RoutingNamespace& namespace_id) const noexcept {
  return fabric == fabric_id && name_space == namespace_id;
}

bool AuthorityScope::covers_route(const FabricId& fabric_id, const RoutingNamespace& namespace_id,
                                  const RouteId& route) const noexcept {
  if (!covers_namespace(fabric_id, namespace_id)) {
    return false;
  }
  if (routes.empty()) {
    return true;
  }
  return std::find(routes.begin(), routes.end(), route) != routes.end();
}

bool AuthorityScope::covers_multipath_set(const FabricId& fabric_id,
                                          const RoutingNamespace& namespace_id,
                                          const MultipathSetId& set_id) const noexcept {
  if (!covers_namespace(fabric_id, namespace_id)) {
    return false;
  }
  if (multipath_sets.empty()) {
    return true;
  }
  return std::find(multipath_sets.begin(), multipath_sets.end(), set_id) != multipath_sets.end();
}

std::string AuthorityScope::render() const {
  std::string text = "fabric=" + fabric.str() + " namespace=" + name_space.str();
  text += " routes=";
  if (routes.empty()) {
    text += "*";
  } else {
    for (std::size_t index = 0; index < routes.size(); ++index) {
      text += index == 0 ? "" : ",";
      text += routes[index].str();
    }
  }
  text += " multipath_sets=";
  if (multipath_sets.empty()) {
    text += "*";
  } else {
    for (std::size_t index = 0; index < multipath_sets.size(); ++index) {
      text += index == 0 ? "" : ",";
      text += multipath_sets[index].str();
    }
  }
  return text;
}

std::string PublisherRegistration::render() const {
  std::string text = "publisher=" + publisher.str() + " boot=" + worker_boot.str();
  text += " epoch=" + std::to_string(epoch.value());
  text += " authority=" + std::to_string(authority_generation.value());
  text += " session=" + session.str();
  text += " scope[" + scope.render() + "]";
  return text;
}

std::string FenceRecord::render() const {
  return "publisher=" + publisher.str() + " boot=" + worker_boot.str() + " epoch=" +
         std::to_string(epoch.value()) + " cause=" + cause;
}

std::string_view to_string(RevocationReason reason) noexcept {
  switch (reason) {
    case RevocationReason::ADMINISTRATIVE:
      return "ADMINISTRATIVE";
    case RevocationReason::SECURITY:
      return "SECURITY";
    case RevocationReason::POLICY_VIOLATION:
      return "POLICY_VIOLATION";
    case RevocationReason::AUTHORITY_REVOKED:
      return "AUTHORITY_REVOKED";
    case RevocationReason::OPERATOR_REQUEST:
      return "OPERATOR_REQUEST";
  }
  return "UNKNOWN";
}

std::optional<RevocationReason> parse_revocation_reason(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 5; ++raw) {
    const auto reason = static_cast<RevocationReason>(raw);
    if (to_string(reason) == text) {
      return reason;
    }
  }
  return std::nullopt;
}

bool valid_revocation_reason(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 5; }

std::string RevocationRecord::render() const {
  std::string text = "policy=" + policy.str();
  text += " generation=" + std::to_string(generation.value());
  text += " epoch=" + std::to_string(epoch.value());
  text += " reason=" + std::string(to_string(reason));
  text += " publisher=" + publisher.str();
  if (!detail.empty()) {
    text += " detail=" + detail;
  }
  return text;
}

std::string_view to_string(AdaptationCause cause) noexcept {
  switch (cause) {
    case AdaptationCause::DECLARED:
      return "DECLARED";
    case AdaptationCause::POLICY_UPDATED:
      return "POLICY_UPDATED";
    case AdaptationCause::EVIDENCE_OBSERVED:
      return "EVIDENCE_OBSERVED";
    case AdaptationCause::TRIGGER_SATISFIED:
      return "TRIGGER_SATISFIED";
    case AdaptationCause::EMERGENCY_OVERRIDE:
      return "EMERGENCY_OVERRIDE";
    case AdaptationCause::ROLLBACK_REQUESTED:
      return "ROLLBACK_REQUESTED";
    case AdaptationCause::PATH_AUTHORITY_INVALIDATED:
      return "PATH_AUTHORITY_INVALIDATED";
    case AdaptationCause::MULTIPATH_SET_INVALIDATED:
      return "MULTIPATH_SET_INVALIDATED";
    case AdaptationCause::ROUTE_INVALIDATED:
      return "ROUTE_INVALIDATED";
    case AdaptationCause::EPOCH_ADVANCE:
      return "EPOCH_ADVANCE";
    case AdaptationCause::RECOVERED:
      return "RECOVERED";
    case AdaptationCause::REVALIDATED:
      return "REVALIDATED";
    case AdaptationCause::REVOKED:
      return "REVOKED";
    case AdaptationCause::RETIRED:
      return "RETIRED";
  }
  return "UNKNOWN";
}

bool valid_adaptation_cause(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 14; }

std::string AdaptationProvenance::render() const {
  std::string text = "publisher=" + publisher.str() + " boot=" + worker_boot.str() + " epoch=" +
                     std::to_string(epoch.value()) + " cause=" + std::string(to_string(cause));
  if (attempt.valid()) {
    text += " attempt=" + attempt.str();
  }
  if (policy_generation.valid()) {
    text += " policy_generation=" + std::to_string(policy_generation.value());
  }
  return text;
}

std::string UpstreamProvenance::render() const {
  std::string text = "origin=" + origin + " publisher=" + publisher.str() + " boot=" +
                     worker_boot.str() + " epoch=" + std::to_string(epoch.value());
  if (attempt.valid()) {
    text += " attempt=" + attempt.str();
  }
  return text;
}

bool MutationContext::has_caller_identity() const noexcept {
  return epoch.valid() && publisher.valid() && worker_boot.valid() && session.valid() &&
         attempt.valid();
}

std::string MutationContext::render() const {
  std::string text = "epoch=" + std::to_string(epoch.value()) + " publisher=" + publisher.str() +
                     " boot=" + worker_boot.str() + " session=" + session.str() +
                     " attempt=" + attempt.str();
  if (expected_policy_generation.has_value()) {
    text += " expect_policy=" + std::to_string(expected_policy_generation->value());
  }
  if (expected_evidence_generation.has_value()) {
    text += " expect_evidence=" + std::to_string(expected_evidence_generation->value());
  }
  return text;
}

std::string AuthorityDescription::render() const {
  std::string text = "epoch=" + std::to_string(epoch.value()) + " authority=" +
                     std::to_string(authority_generation.value());
  for (const auto& registration : registrations) {
    text += "\n  registration[" + registration.render() + "]";
  }
  for (const auto& fence : fence_records) {
    text += "\n  fence[" + fence.render() + "]";
  }
  return text;
}

}  // namespace adaptive_routing

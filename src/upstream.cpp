// Upstream binding contracts.
#include "adaptive_routing/upstream.hpp"

#include <algorithm>

namespace adaptive_routing {

std::string PathAuthorityBinding::render() const {
  std::string text = "path=" + path.str() + " generation=" + std::to_string(generation.value());
  text += legal ? " legal" : " denied";
  if (!denial_reason.empty()) {
    text += "(" + denial_reason + ")";
  }
  return text;
}

bool MultipathBinding::contains(const PathId& path) const noexcept {
  return std::find(members.begin(), members.end(), path) != members.end();
}

std::string MultipathBinding::render() const {
  std::string text = "set=" + set.str() + " generation=" + std::to_string(generation.value());
  text += current ? " current" : " stale";
  text += " members=";
  for (std::size_t index = 0; index < members.size(); ++index) {
    text += index == 0 ? "" : ",";
    text += members[index].str();
  }
  return text;
}

std::string RouteBinding::render() const {
  std::string text = "route=" + route.str() + " generation=" + std::to_string(generation.value());
  text += current ? " current" : " stale";
  if (site.valid()) {
    text += " site=" + site.str();
  }
  if (!state.empty()) {
    text += " state=" + state;
  }
  return text;
}

std::string WeightedPolicyBinding::render() const {
  return "set=" + set.str() + " generation=" + std::to_string(generation.value()) +
         (current ? " current" : " stale");
}

std::string CandidateBinding::render() const {
  std::string text = "path=" + path.str();
  text += " authority[" + path_authority.render() + "]";
  text += " route[" + route.render() + "]";
  if (multipath.has_value()) {
    text += " multipath[" + multipath->render() + "]";
  }
  if (weighted.has_value()) {
    text += " weighted[" + weighted->render() + "]";
  }
  if (path_class.valid()) {
    text += " class=" + path_class.str();
  }
  text += available ? " available" : " unavailable";
  if (hard_failure) {
    text += " hard_failure";
  }
  return text;
}

std::string_view to_string(UpstreamEvent event) noexcept {
  switch (event) {
    case UpstreamEvent::DECLARE_CANDIDATE:
      return "DECLARE_CANDIDATE";
    case UpstreamEvent::ADVANCE_PATH_AUTHORITY:
      return "ADVANCE_PATH_AUTHORITY";
    case UpstreamEvent::INVALIDATE_PATH:
      return "INVALIDATE_PATH";
    case UpstreamEvent::SET_MEMBERSHIP:
      return "SET_MEMBERSHIP";
    case UpstreamEvent::INVALIDATE_MULTIPATH_SET:
      return "INVALIDATE_MULTIPATH_SET";
    case UpstreamEvent::ADVANCE_ROUTE:
      return "ADVANCE_ROUTE";
    case UpstreamEvent::INVALIDATE_ROUTE:
      return "INVALIDATE_ROUTE";
    case UpstreamEvent::ADVANCE_WEIGHT_POLICY:
      return "ADVANCE_WEIGHT_POLICY";
    case UpstreamEvent::MARK_UNAVAILABLE:
      return "MARK_UNAVAILABLE";
    case UpstreamEvent::MARK_AVAILABLE:
      return "MARK_AVAILABLE";
    case UpstreamEvent::HARD_FAILURE_SIGNAL:
      return "HARD_FAILURE_SIGNAL";
    case UpstreamEvent::CLEAR_HARD_FAILURE_SIGNAL:
      return "CLEAR_HARD_FAILURE_SIGNAL";
  }
  return "UNKNOWN";
}

std::optional<UpstreamEvent> parse_upstream_event(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 12; ++raw) {
    const auto event = static_cast<UpstreamEvent>(raw);
    if (to_string(event) == text) {
      return event;
    }
  }
  return std::nullopt;
}

bool valid_upstream_event(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 12; }

bool upstream_event_invalidates(UpstreamEvent event) noexcept {
  switch (event) {
    case UpstreamEvent::ADVANCE_PATH_AUTHORITY:
    case UpstreamEvent::INVALIDATE_PATH:
    case UpstreamEvent::SET_MEMBERSHIP:
    case UpstreamEvent::INVALIDATE_MULTIPATH_SET:
    case UpstreamEvent::ADVANCE_ROUTE:
    case UpstreamEvent::INVALIDATE_ROUTE:
    case UpstreamEvent::MARK_UNAVAILABLE:
    case UpstreamEvent::HARD_FAILURE_SIGNAL:
      return true;
    default:
      return false;
  }
}

std::string UpstreamNotification::render() const {
  std::string text = std::string(to_string(event)) + " policy=" + policy.str() + " binding[";
  text += binding.render();
  text += "] provenance[" + provenance.render() + "]";
  if (expected_previous_generation.has_value()) {
    text += " expected_previous=" + std::to_string(*expected_previous_generation);
  }
  return text;
}

}  // namespace adaptive_routing

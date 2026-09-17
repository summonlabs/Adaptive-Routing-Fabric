// Preference, decisions and evaluation tickets.
#include "adaptive_routing/decision.hpp"

#include <algorithm>

namespace adaptive_routing {

bool WeightProposal::well_formed() const noexcept {
  if (!set.valid() || !base_generation.valid() || weights.empty()) {
    return false;
  }
  for (const auto& weight : weights) {
    if (!weight.path.valid() || weight.weight_bps > basis_points_scale) {
      return false;
    }
  }
  return true;
}

std::string WeightProposal::render() const {
  std::string text = "set=" + set.str() + " base=" + std::to_string(base_generation.value());
  for (const auto& weight : weights) {
    text += " " + weight.path.str() + "=" + std::to_string(weight.weight_bps);
  }
  return text;
}

std::string RoutingPreference::render() const {
  if (!established) {
    return "route=" + route.str() + " preferred=<none>";
  }
  std::string text = "route=" + route.str();
  text += " preferred=" + preferred_path.str();
  text += "@" + std::to_string(path_authority_generation.value());
  if (previous_path.valid()) {
    text += " previous=" + previous_path.str();
  }
  if (multipath_set.has_value()) {
    text += " set=" + multipath_set->str() + "@" +
            std::to_string(multipath_set_generation.value());
  }
  text += " route_generation=" + std::to_string(route_generation.value());
  text += " adaptation=" + std::to_string(adaptation_generation.value());
  text += " transition=" + std::to_string(transition_generation.value());
  if (weight_proposal.has_value()) {
    text += " weight_proposal[" + weight_proposal->render() + "]";
  }
  return text;
}

std::string StableState::render() const {
  if (!established) {
    return "<never stable>";
  }
  std::string text = "path=" + path.str();
  text += "@" + std::to_string(path_authority_generation.value());
  text += " route_generation=" + std::to_string(route_generation.value());
  text += " adaptation=" + std::to_string(adaptation_generation.value());
  return text;
}

std::string DependencySnapshot::render() const {
  std::string text = "evaluation=" + evaluation.str();
  text += " policy=" + policy.str() + "@" + std::to_string(policy_generation.value());
  text += " evidence=" + std::to_string(evidence_generation.value());
  text += " evidence_watermark=" + std::to_string(evidence_watermark.value());
  text += " upstream_watermark=" + std::to_string(upstream_watermark.value());
  text += " epoch=" + std::to_string(epoch.value());
  text += " authority=" + std::to_string(authority_generation.value());
  text += " route_generation=" + std::to_string(route_generation.value());
  if (multipath_set.has_value()) {
    text += " set=" + multipath_set->str() + "@" +
            std::to_string(multipath_set_generation.value());
  }
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    text += " candidate[" + candidates[index].str();
    if (index < candidate_path_authority.size()) {
      text += "@" + std::to_string(candidate_path_authority[index].generation.value());
    }
    if (index < candidate_path_watermarks.size()) {
      text += " wm=" + std::to_string(candidate_path_watermarks[index]);
    }
    text += "]";
  }
  return text;
}

bool AdaptationDecision::well_formed() const noexcept {
  if (!id.valid() || !policy.valid() || !policy_generation.valid() || !route.valid()) {
    return false;
  }
  if (!epoch.valid() || !evidence_generation.valid()) {
    return false;
  }
  return true;
}

}  // namespace adaptive_routing

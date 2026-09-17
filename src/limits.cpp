// Configured resource limits.
#include "adaptive_routing/limits.hpp"

namespace adaptive_routing {

std::vector<std::pair<std::string, std::uint64_t>> Limits::describe() const {
  return {
      {"max_policies", max_policies},
      {"max_candidates_per_policy", max_candidates_per_policy},
      {"max_total_candidates", max_total_candidates},
      {"max_evidence_sources", max_evidence_sources},
      {"max_evidence_samples_per_series", max_evidence_samples_per_series},
      {"max_evidence_requirements_per_policy", max_evidence_requirements_per_policy},
      {"max_thresholds_per_policy", max_thresholds_per_policy},
      {"max_objective_terms", max_objective_terms},
      {"max_history_per_policy", max_history_per_policy},
      {"max_decision_history", max_decision_history},
      {"max_simultaneous_evaluations", max_simultaneous_evaluations},
      {"max_pending_transitions", max_pending_transitions},
      {"max_frame_bytes", max_frame_bytes},
      {"max_batch_size", max_batch_size},
      {"max_publishers", max_publishers},
      {"max_sessions", max_sessions},
      {"max_explanation_entries", max_explanation_entries},
      {"max_persistence_record_bytes", max_persistence_record_bytes},
      {"max_store_bytes", max_store_bytes},
      {"max_attempts", max_attempts},
      {"max_revocations", max_revocations},
      {"max_snapshot_history", max_snapshot_history},
      {"max_scope_routes", max_scope_routes},
      {"max_scope_multipath_sets", max_scope_multipath_sets},
      {"max_adaptations_per_window", max_adaptations_per_window},
      {"max_dampening_penalty", max_dampening_penalty},
      {"max_receive_stall_millis", max_receive_stall_millis},
      {"max_policies_per_path", max_policies_per_path},
  };
}

}  // namespace adaptive_routing

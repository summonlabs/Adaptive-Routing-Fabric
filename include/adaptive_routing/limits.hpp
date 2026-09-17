// Configured resource limits.
//
// Every field declared here is consulted by the code path named in its comment.
// A limit that is not consulted must not exist: the test suite drives each one
// to its boundary and asserts the exact structured rejection, and
// c Limits::describe() enumerates them so the suite can prove that the list is
// live rather than decorative.
#ifndef ADAPTIVE_ROUTING_LIMITS_HPP
#define ADAPTIVE_ROUTING_LIMITS_HPP

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace adaptive_routing {

struct Limits {
  // Consulted by: create_policy, restore, and the policy index.
  std::uint64_t max_policies = 100000;
  // Consulted by: declare_candidate / candidate binding.
  std::uint64_t max_candidates_per_policy = 32;
  // Consulted by: declare_candidate as a global bound on candidate bindings.
  std::uint64_t max_total_candidates = 1000000;
  // Consulted by: publish_evidence (distinct sources per policy scope).
  std::uint64_t max_evidence_sources = 4096;
  // Consulted by: the per (source, path, metric) bounded sample ring.
  std::uint64_t max_evidence_samples_per_series = 64;
  // Consulted by: the policy evidence-requirement vector.
  std::uint64_t max_evidence_requirements_per_policy = 8;
  // Consulted by: the policy threshold vector.
  std::uint64_t max_thresholds_per_policy = 8;
  // Consulted by: the policy objective-term vector.
  std::uint64_t max_objective_terms = 8;
  // Consulted by: the bounded per-policy adaptation history.
  std::uint64_t max_history_per_policy = 32;
  // Consulted by: the bounded commit/suppression journal.
  std::uint64_t max_decision_history = 4096;
  // Consulted by: begin_evaluation when too many tickets are outstanding.
  std::uint64_t max_simultaneous_evaluations = 256;
  // Consulted by: commit_decision pending-transition tracking.
  std::uint64_t max_pending_transitions = 256;
  // Consulted by: the framed wire encoder and the frame decoder.
  std::uint64_t max_frame_bytes = 1U << 20;
  // Consulted by: publish_evidence batch publication.
  std::uint64_t max_batch_size = 256;
  // Consulted by: register_publisher.
  std::uint64_t max_publishers = 64;
  // Consulted by: the coordinator session table on accept.
  std::uint64_t max_sessions = 128;
  // Consulted by: explanation construction.
  std::uint64_t max_explanation_entries = 512;
  // Consulted by: the persistence encoder (per record and for the whole store).
  std::uint64_t max_persistence_record_bytes = 16U << 20;
  std::uint64_t max_store_bytes = 64U << 20;
  // Consulted by: the bounded attempt-id table used for replay recognition.
  std::uint64_t max_attempts = 8192;
  // Consulted by: the durable revocation set.
  std::uint64_t max_revocations = 4096;
  // Consulted by: snapshot retention.
  std::uint64_t max_snapshot_history = 16;
  // Consulted by: the policy scope vector bounds.
  std::uint64_t max_scope_routes = 256;
  std::uint64_t max_scope_multipath_sets = 256;
  // Consulted by: policy churn bounds.
  std::uint64_t max_adaptations_per_window = 64;
  // Consulted by: the dampening penalty bound.
  std::uint64_t max_dampening_penalty = 1024;
  // Consulted by: the session receive loop as a product-level partial-frame
  // defence. Exceeding it fails the session explicitly; it is not a test
  // timeout and no test relies on it as one.
  std::uint64_t max_receive_stall_millis = 30000;
  // Consulted by: the upstream dependency index used by targeted invalidation.
  std::uint64_t max_policies_per_path = 4096;

  // Renders one "name=value" line per limit, in declaration order.
  [[nodiscard]] std::vector<std::pair<std::string, std::uint64_t>> describe() const;
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_LIMITS_HPP

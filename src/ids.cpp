// Identity factory and process nonce.
#include "adaptive_routing/ids.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace adaptive_routing {
namespace {

std::string make_nonce() {
  // Process identity plus a boot-relative counter. Identity *values* need to be
  // unique, not reproducible; only their encoding is part of the contract.
  static std::atomic<std::uint64_t> sequence{0};
  const std::uint64_t counter = ++sequence;
#if defined(_WIN32)
  const auto pid = static_cast<std::uint64_t>(::_getpid());
#else
  const auto pid = static_cast<std::uint64_t>(::getpid());
#endif
  const auto stamp = static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "%llu-%llu-%llu",
                static_cast<unsigned long long>(pid), static_cast<unsigned long long>(stamp),
                static_cast<unsigned long long>(counter));
  return std::string(buffer);
}

}  // namespace

const std::string& process_nonce() {
  static const std::string nonce = make_nonce();
  return nonce;
}

IdFactory::IdFactory(std::string prefix) : prefix_(std::move(prefix)), nonce_(process_nonce()) {}

std::string IdFactory::compose(std::string_view kind, std::uint64_t counter) const {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "-%llu", static_cast<unsigned long long>(counter));
  std::string result;
  result.reserve(prefix_.size() + kind.size() + nonce_.size() + 40);
  result += prefix_;
  if (!prefix_.empty()) {
    result += '-';
  }
  result += kind;
  result += '-';
  result += nonce_;
  result += buffer;
  return result;
}

AdaptivePolicyId IdFactory::next_policy_id() noexcept {
  return AdaptivePolicyId::require(compose("policy", ++counter_));
}

AdaptationDecisionId IdFactory::next_decision_id() noexcept {
  return AdaptationDecisionId::require(compose("decision", ++counter_));
}

TransitionPlanId IdFactory::next_transition_id() noexcept {
  return TransitionPlanId::require(compose("transition", ++counter_));
}

EvidenceSourceId IdFactory::next_evidence_source_id() noexcept {
  return EvidenceSourceId::require(compose("evidence", ++counter_));
}

EvidenceSnapshotId IdFactory::next_evidence_snapshot_id() noexcept {
  return EvidenceSnapshotId::require(compose("evsnap", ++counter_));
}

SnapshotId IdFactory::next_snapshot_id() noexcept {
  return SnapshotId::require(compose("snapshot", ++counter_));
}

WorkerBootId IdFactory::next_worker_boot_id() noexcept {
  return WorkerBootId::require(compose("boot", ++counter_));
}

SessionId IdFactory::next_session_id() noexcept {
  return SessionId::require(compose("session", ++counter_));
}

EvaluationId IdFactory::next_evaluation_id() noexcept {
  return EvaluationId::require(compose("eval", ++counter_));
}

}  // namespace adaptive_routing

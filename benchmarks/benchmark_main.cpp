// Adaptive Routing Fabric benchmarks.
//
// WHAT IS MEASURED
// ----------------
// Only completed operations are reported. Every loop counts an iteration only
// after the engine has returned the outcome that iteration is defined to
// produce, and the run checks the completed count against the requested count
// afterwards. Preparation is verified separately: a benchmark whose fixture did
// not come up reports zero completed iterations instead of a meaningless number.
//
// TIMING
// ------
// std::chrono::steady_clock is used ONLY for measurement. It is never read back
// into the library, never influences library state and never appears in a
// result. The numbers are specific to this machine, this compiler and this build
// configuration; only the shape of one run on one machine is meaningful.
//
// RESULT SHAPE
// ------------
// One line per benchmark: name, completed iterations, total nanoseconds for
// those iterations, and nanoseconds per operation. Nanoseconds per operation is
// computed with integer arithmetic from the same two numbers, so it never
// introduces a second measurement.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "adaptive_routing/adaptive_routing.hpp"

namespace {

using namespace adaptive_routing;

// Measurement only. The library's elapsed-time decisions read the injected
// TestClock below, never this clock.
using MeasurementClock = std::chrono::steady_clock;

[[nodiscard]] std::uint64_t elapsed_ns(MeasurementClock::time_point start) {
  const auto delta = MeasurementClock::now() - start;
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(delta).count());
}

// ---------------------------------------------------------------------------
// Result rows
// ---------------------------------------------------------------------------

struct Row {
  const char* name = "";
  std::uint64_t requested = 0;
  std::uint64_t completed = 0;
  std::uint64_t total_ns = 0;
};

// A row for a benchmark whose preparation did not complete. Reporting zero
// completed iterations is honest; timing an unprepared fixture is not.
[[nodiscard]] Row incomplete(const char* name, std::uint64_t requested) {
  Row row;
  row.name = name;
  row.requested = requested;
  row.completed = 0;
  row.total_ns = 0;
  return row;
}

// ---------------------------------------------------------------------------
// Engine fixture
// ---------------------------------------------------------------------------

struct Bench {
  std::shared_ptr<TestClock> clock = std::make_shared<TestClock>();
  std::unique_ptr<AdaptiveRoutingFabric> fabric;
  PublisherId publisher = PublisherId::require("bench-publisher");
  WorkerBootId worker_boot = WorkerBootId::require("bench-boot-1");
  SessionId session = SessionId::require("bench-session-1");
  std::uint64_t attempts = 0;
  std::uint64_t policies = 0;
  // False as soon as any preparation step did not produce the outcome it must.
  bool setup_ok = true;

  Bench() {
    EngineConfig config;
    config.clock = clock;
    config.id_prefix = "arf-bench";
    fabric = std::make_unique<AdaptiveRoutingFabric>(std::move(config));
    AuthorityScope authority;
    authority.fabric = FabricId::require("bench-fabric");
    authority.name_space = RoutingNamespace::require("bench-namespace");
    setup_ok =
        fabric->register_publisher(publisher, worker_boot, authority, session).outcome ==
        Outcome::POLICY_UPDATED;
  }

  // Records a preparation outcome. Preparation is never ignored: a fixture that
  // did not come up would otherwise silently time an empty loop.
  void require(bool step) { setup_ok = step && setup_ok; }

  [[nodiscard]] MutationContext context() {
    MutationContext ctx;
    ctx.epoch = fabric->epoch();
    ctx.publisher = publisher;
    ctx.worker_boot = worker_boot;
    ctx.session = session;
    ctx.attempt = MutationAttemptId::require("bench-attempt-" + std::to_string(++attempts));
    return ctx;
  }

  [[nodiscard]] AdaptivePolicyName next_policy_name() {
    return AdaptivePolicyName::require("bench-policy-" + std::to_string(++policies));
  }
};

[[nodiscard]] PolicySemantics latency_policy(std::uint32_t switch_bps,
                                             std::uint32_t reverse_bps, Ticks hold_down) {
  PolicySemantics semantics;
  semantics.target.route = RouteId::require("bench-route");
  ImprovementRule rule;
  rule.kind = MetricKind::PATH_LATENCY;
  rule.switch_improvement_bps = switch_bps;
  rule.reverse_improvement_bps = reverse_bps;
  semantics.improvements.push_back(rule);
  EvidenceRequirement requirement;
  requirement.kind = MetricKind::PATH_LATENCY;
  requirement.aggregation = AggregationKind::MEAN;
  requirement.ewma_alpha_bps = 0;
  requirement.min_samples = 1;
  requirement.max_age = seconds(600);
  requirement.min_window = 0;
  requirement.min_quality = EvidenceQuality::AGGREGATED;
  requirement.required = true;
  semantics.evidence.push_back(requirement);
  semantics.hold_down.duration = hold_down;
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = MetricKind::PATH_LATENCY;
  objective.terms.push_back(term);
  semantics.objective = objective;
  return semantics;
}

[[nodiscard]] bool create_active_policy(Bench& bench, const PolicySemantics& semantics,
                                        AdaptivePolicyId& policy) {
  CreatePolicyRequest create;
  create.name = bench.next_policy_name();
  create.scope.fabric = FabricId::require("bench-fabric");
  create.scope.name_space = RoutingNamespace::require("bench-namespace");
  create.semantics = semantics;
  create.context = bench.context();
  const OperationResult created = bench.fabric->create_policy(create);
  if (created.outcome != Outcome::POLICY_CREATED) {
    return false;
  }
  PolicyLifecycleRequest activation;
  activation.policy = created.policy;
  activation.event = PolicyEvent::ACTIVATE;
  activation.detail = "benchmark activation";
  activation.context = bench.context();
  if (bench.fabric->transition_policy(activation).outcome != Outcome::POLICY_UPDATED) {
    return false;
  }
  policy = created.policy;
  return true;
}

[[nodiscard]] bool declare_candidate(Bench& bench, const AdaptivePolicyId& policy,
                                     const PathId& candidate) {
  CandidateBinding binding;
  binding.path = candidate;
  binding.path_authority.path = candidate;
  binding.path_authority.generation = PathAuthorityGeneration::require(1);
  binding.path_authority.legal = true;
  binding.route.route = RouteId::require("bench-route");
  binding.route.generation = RouteGeneration::require(1);
  binding.route.current = true;
  binding.available = true;
  const MutationContext context = bench.context();
  UpstreamNotification notification;
  notification.event = UpstreamEvent::DECLARE_CANDIDATE;
  notification.policy = policy;
  notification.binding = binding;
  notification.provenance.publisher = bench.publisher;
  notification.provenance.worker_boot = bench.worker_boot;
  notification.provenance.epoch = context.epoch;
  notification.provenance.attempt = context.attempt;
  notification.provenance.origin = "benchmark";
  UpstreamNotifyRequest request;
  request.notifications.push_back(notification);
  request.context = context;
  return bench.fabric->apply_upstream(request).outcome == Outcome::POLICY_UPDATED;
}

[[nodiscard]] bool publish_latency(Bench& bench, const PathId& target, std::int64_t micros,
                                   std::uint64_t sequence, std::uint64_t source_generation) {
  EvidencePublication publication;
  publication.source = EvidenceSourceId::require("bench-telemetry");
  publication.source_generation = EvidenceSourceGeneration::require(source_generation);
  publication.quality = EvidenceQuality::AGGREGATED;
  publication.path = target;
  publication.value = MetricValue::make(MetricKind::PATH_LATENCY, micros).value_or(MetricValue{});
  publication.observation_sequence = sequence;
  PublishEvidenceRequest request;
  request.publications.push_back(publication);
  request.context = bench.context();
  return bench.fabric->publish_evidence(request).outcome == Outcome::POLICY_UPDATED;
}

// Evaluates once and reports whether the engine produced the expected outcome.
[[nodiscard]] bool evaluate_once(Bench& bench, const AdaptivePolicyId& policy,
                                 Outcome expected) {
  EvaluateRequest request;
  request.policy = policy;
  request.context = bench.context();
  return bench.fabric->evaluate(request).outcome == expected;
}

[[nodiscard]] PathId candidate_path(std::uint64_t index) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "bench-path-%02llu",
                static_cast<unsigned long long>(index));
  return PathId::require(buffer);
}


[[nodiscard]] std::string per_operation(std::uint64_t total_ns, std::uint64_t completed) {
  if (completed == 0) {
    return "n/a";
  }
  const std::uint64_t whole = total_ns / completed;
  const std::uint64_t hundredths = ((total_ns % completed) * 100U) / completed;
  return std::to_string(whole) + "." + (hundredths < 10U ? "0" : "") + std::to_string(hundredths);
}

class Table {
 public:
  Table() {
    std::cout << "Adaptive Routing Fabric benchmarks\n";
    std::cout << "Every number below is machine, compiler and build specific; compare rows only\n";
    std::cout << "within this run, on this machine, with this build configuration.\n\n";
    std::cout << std::left << std::setw(44) << "benchmark" << std::right << std::setw(12)
              << "iterations" << std::setw(16) << "total_ns" << std::setw(13) << "ns_per_op"
              << "\n";
    std::cout << std::string(85, '-') << "\n";
  }

  void row(const Row& entry) {
    std::cout << std::left << std::setw(44) << entry.name << std::right << std::setw(12)
              << entry.completed << std::setw(16) << entry.total_ns << std::setw(13)
              << per_operation(entry.total_ns, entry.completed);
    if (entry.completed != entry.requested) {
      std::cout << "  INCOMPLETE (requested " << entry.requested << ")";
    }
    std::cout << "\n";
  }
};

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// Registering a policy: create plus activate, the full admission of one policy.
Row benchmark_policy_registration() {
  constexpr std::uint64_t requested = 5000;
  const char* name = "policy_registration";
  Bench bench;
  const PolicySemantics semantics = latency_policy(2000, 4000, 0);
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    AdaptivePolicyId policy;
    if (create_active_policy(bench, semantics, policy)) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  return Row{name, requested, completed, total};
}

// Ingesting one evidence sample into an existing series. The retention ring is
// bounded, so the cost includes eviction once the bound is reached.
Row benchmark_evidence_ingestion() {
  constexpr std::uint64_t requested = 20000;
  constexpr std::uint64_t paths = 8;
  const char* name = "evidence_ingestion";
  Bench bench;
  AdaptivePolicyId policy;
  bench.require(create_active_policy(bench, latency_policy(2000, 4000, 0), policy));
  for (std::uint64_t index = 0; index < paths; ++index) {
    bench.require(declare_candidate(bench, policy, candidate_path(index)));
  }
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  std::uint64_t sequences[paths] = {0, 0, 0, 0, 0, 0, 0, 0};
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    const std::uint64_t slot = index % paths;
    ++sequences[slot];
    if (publish_latency(bench, candidate_path(slot), 1000, sequences[slot], 1)) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

// A full evaluation that finds the current preference already best. This is the
// steady state of a healthy policy, so it is the cost that matters in practice.
Row benchmark_policy_evaluation() {
  constexpr std::uint64_t requested = 20000;
  const char* name = "policy_evaluation";
  Bench bench;
  AdaptivePolicyId policy;
  bench.require(create_active_policy(bench, latency_policy(2000, 4000, 0), policy));
  bench.require(declare_candidate(bench, policy, candidate_path(0)));
  bench.require(declare_candidate(bench, policy, candidate_path(1)));
  bench.require(publish_latency(bench, candidate_path(0), 500, 1, 1));
  bench.require(publish_latency(bench, candidate_path(1), 900, 1, 1));
  bench.require(evaluate_once(bench, policy, Outcome::DECISION_COMMITTED));
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    if (evaluate_once(bench, policy, Outcome::NO_CHANGE)) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

// The suppression predicate: a reverse adaptation inside an armed hold-down is
// refused before thresholds and improvement rules are consulted.
Row benchmark_suppression_check() {
  constexpr std::uint64_t requested = 20000;
  const char* name = "suppression_check";
  Bench bench;
  AdaptivePolicyId policy;
  bench.require(create_active_policy(bench, latency_policy(2000, 2000, seconds(60)), policy));
  bench.require(declare_candidate(bench, policy, candidate_path(0)));
  bench.require(declare_candidate(bench, policy, candidate_path(1)));
  // path-0 is established first, then displaced by path-1, which arms hold-down
  // against the one path a reverse adaptation could return to: path-0.
  bench.require(publish_latency(bench, candidate_path(0), 1000, 1, 1));
  bench.require(evaluate_once(bench, policy, Outcome::DECISION_COMMITTED));
  bench.require(publish_latency(bench, candidate_path(1), 800, 1, 1));
  bench.require(evaluate_once(bench, policy, Outcome::DECISION_COMMITTED));
  bench.require(publish_latency(bench, candidate_path(0), 400, 2, 2));
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    if (evaluate_once(bench, policy, Outcome::HOLD_DOWN_ACTIVE)) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

// Committing a decision: phase two of an evaluation whose phase one already
// produced an eligible proposal. Tickets are issued before the timer starts, so
// the row measures the commit path alone. The ticket count stays below
// Limits::max_simultaneous_evaluations because every ticket is outstanding until
// it is settled.
Row benchmark_decision_commit() {
  constexpr std::uint64_t requested = 200;
  const char* name = "decision_commit";
  Bench bench;
  const PolicySemantics semantics = latency_policy(2000, 4000, 0);
  std::vector<AdaptivePolicyId> policies;
  policies.reserve(requested);
  for (std::uint64_t index = 0; index < requested; ++index) {
    AdaptivePolicyId policy;
    if (!create_active_policy(bench, semantics, policy)) {
      return incomplete(name, requested);
    }
    bench.require(declare_candidate(bench, policy, candidate_path(index)));
    bench.require(publish_latency(bench, candidate_path(index), 1000, 1, 1));
    policies.push_back(policy);
  }
  // Tickets are phase-one snapshots: publishing evidence after a ticket was
  // issued would supersede it with STALE_EVIDENCE. Every publication therefore
  // happens before the first ticket, and the tickets are then settled in order.
  std::vector<EvaluationTicket> tickets;
  tickets.reserve(requested);
  for (const AdaptivePolicyId& policy : policies) {
    EvaluateRequest request;
    request.policy = policy;
    request.context = bench.context();
    const EvaluationTicket ticket = bench.fabric->begin_evaluation(request);
    bench.require(ticket.committable());
    tickets.push_back(ticket);
  }
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (const EvaluationTicket& ticket : tickets) {
    CommitDecisionRequest commit;
    commit.ticket = ticket;
    commit.context = bench.context();
    if (bench.fabric->commit_evaluation(commit).outcome == Outcome::DECISION_COMMITTED) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

// Targeted path invalidation through the upstream binding index.
Row benchmark_path_invalidation() {
  constexpr std::uint64_t requested = 20000;
  const char* name = "path_invalidation";
  Bench bench;
  AdaptivePolicyId policy;
  bench.require(create_active_policy(bench, latency_policy(2000, 4000, 0), policy));
  const PathId target = candidate_path(0);
  bench.require(declare_candidate(bench, policy, target));
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    CandidateBinding binding;
    binding.path = target;
    binding.path_authority.path = target;
    binding.path_authority.generation = PathAuthorityGeneration::require(1);
    binding.path_authority.legal = false;
    binding.path_authority.denial_reason = "benchmark invalidation";
    binding.route.route = RouteId::require("bench-route");
    binding.route.generation = RouteGeneration::require(1);
    binding.route.current = true;
    binding.available = true;
    const MutationContext context = bench.context();
    UpstreamNotification notification;
    notification.event = UpstreamEvent::INVALIDATE_PATH;
    notification.policy = policy;
    notification.binding = binding;
    notification.provenance.publisher = bench.publisher;
    notification.provenance.worker_boot = bench.worker_boot;
    notification.provenance.epoch = context.epoch;
    notification.provenance.attempt = context.attempt;
    notification.provenance.origin = "benchmark";
    UpstreamNotifyRequest request;
    request.notifications.push_back(notification);
    request.context = context;
    if (bench.fabric->apply_upstream(request).outcome == Outcome::POLICY_UPDATED) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

// Building an immutable snapshot of one policy.
Row benchmark_snapshot() {
  constexpr std::uint64_t requested = 20000;
  const char* name = "snapshot";
  Bench bench;
  AdaptivePolicyId policy;
  bench.require(create_active_policy(bench, latency_policy(2000, 4000, 0), policy));
  bench.require(declare_candidate(bench, policy, candidate_path(0)));
  bench.require(declare_candidate(bench, policy, candidate_path(1)));
  bench.require(publish_latency(bench, candidate_path(0), 1000, 1, 1));
  bench.require(evaluate_once(bench, policy, Outcome::DECISION_COMMITTED));
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    if (bench.fabric->snapshot(policy).policy == policy) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

// The decision semantic digest: the comparison primitive behind stale-decision
// detection. The row also asserts that the digest is stable for a fixed value,
// which is what makes it usable as a comparison.
Row benchmark_semantic_digest() {
  constexpr std::uint64_t requested = 50000;
  const char* name = "semantic_digest";
  Bench bench;
  AdaptivePolicyId policy;
  bench.require(create_active_policy(bench, latency_policy(2000, 4000, 0), policy));
  bench.require(declare_candidate(bench, policy, candidate_path(0)));
  bench.require(declare_candidate(bench, policy, candidate_path(1)));
  bench.require(publish_latency(bench, candidate_path(0), 1000, 1, 1));
  bench.require(publish_latency(bench, candidate_path(1), 800, 1, 1));
  EvaluateRequest establish;
  establish.policy = policy;
  establish.context = bench.context();
  const OperationResult committed = bench.fabric->evaluate(establish);
  const std::optional<AdaptationDecision> decision =
      bench.fabric->find_decision(committed.decision);
  bench.require(decision.has_value());
  if (!bench.setup_ok || !decision.has_value()) {
    return incomplete(name, requested);
  }
  const std::string reference = decision_digest(*decision);
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    if (decision_digest(*decision) == reference) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

[[nodiscard]] std::string benchmark_store_path() {
  std::error_code code;
  const std::filesystem::path directory = std::filesystem::temp_directory_path(code);
  if (code) {
    return std::string();
  }
  return (directory / "arf_benchmark_store.bin").string();
}

// Writing the durable store: encode plus atomic file replacement.
Row benchmark_persistence_save(const std::string& path) {
  constexpr std::uint64_t requested = 500;
  const char* name = "persistence_save";
  Bench bench;
  AdaptivePolicyId policy;
  bench.require(create_active_policy(bench, latency_policy(2000, 4000, 0), policy));
  bench.require(declare_candidate(bench, policy, candidate_path(0)));
  bench.require(publish_latency(bench, candidate_path(0), 1000, 1, 1));
  bench.require(evaluate_once(bench, policy, Outcome::DECISION_COMMITTED));
  if (path.empty() || !bench.setup_ok) {
    return incomplete(name, requested);
  }
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    if (bench.fabric->save(path).outcome == Outcome::POLICY_UPDATED) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

// Reading and applying the durable store: file read, integrity check, decode and
// recovery of every record.
Row benchmark_persistence_load(const std::string& path) {
  constexpr std::uint64_t requested = 200;
  const char* name = "persistence_load";
  Bench bench;
  if (path.empty()) {
    return incomplete(name, requested);
  }
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    if (bench.fabric->load(path).outcome == Outcome::POLICY_UPDATED) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

// The population benchmark: how admission behaves while the policy index grows
// to ten thousand entries. The per-operation figure is the average admission
// cost across that growth, not the cost of a single steady-state insert.
Row benchmark_policy_population() {
  constexpr std::uint64_t requested = 10000;
  const char* name = "policy_population_10000";
  Bench bench;
  const PolicySemantics semantics = latency_policy(2000, 4000, 0);
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    AdaptivePolicyId policy;
    if (create_active_policy(bench, semantics, policy)) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  return Row{name, requested, completed, total};
}

// Targeted evidence fan-out. One hundred policies depend on the published path
// while two thousand unrelated policies share the same engine, so a scan over
// every policy would be visible here. The engine keeps a reverse index from path
// to dependent policy, so the fan-out costs the one hundred dependents and not
// the two thousand one hundred policies.
Row benchmark_targeted_evidence_fanout() {
  constexpr std::uint64_t requested = 5000;
  constexpr std::uint64_t dependents = 100;
  constexpr std::uint64_t unrelated = 2000;
  const char* name = "evidence_fanout_100_dependents_2100";
  Bench bench;
  const PolicySemantics semantics = latency_policy(2000, 4000, 0);
  const PathId shared = PathId::require("bench-shared-path");
  for (std::uint64_t index = 0; index < dependents; ++index) {
    AdaptivePolicyId policy;
    if (!create_active_policy(bench, semantics, policy)) {
      return incomplete(name, requested);
    }
    bench.require(declare_candidate(bench, policy, shared));
  }
  for (std::uint64_t index = 0; index < unrelated; ++index) {
    AdaptivePolicyId policy;
    if (!create_active_policy(bench, semantics, policy)) {
      return incomplete(name, requested);
    }
    bench.require(declare_candidate(bench, policy, candidate_path(index + 1000)));
  }
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  std::uint64_t sequence = 0;
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    ++sequence;
    if (publish_latency(bench, shared, 1000, sequence, 1)) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

// Candidate-count scaling: the same steady-state evaluation over 4, 8, 16 and 32
// declared candidates. Everything else is identical between the four rows.
Row benchmark_candidate_evaluation(std::uint64_t candidates, const char* name) {
  constexpr std::uint64_t requested = 5000;
  Bench bench;
  AdaptivePolicyId policy;
  bench.require(create_active_policy(bench, latency_policy(2000, 4000, 0), policy));
  for (std::uint64_t index = 0; index < candidates; ++index) {
    bench.require(declare_candidate(bench, policy, candidate_path(index)));
    // The first candidate is the best one, so the steady state is stable.
    const auto micros = 500 + static_cast<std::int64_t>(index);
    bench.require(publish_latency(bench, candidate_path(index), micros, 1, 1));
  }
  bench.require(evaluate_once(bench, policy, Outcome::DECISION_COMMITTED));
  if (!bench.setup_ok) {
    return incomplete(name, requested);
  }
  std::uint64_t completed = 0;
  const auto start = MeasurementClock::now();
  for (std::uint64_t index = 0; index < requested; ++index) {
    if (evaluate_once(bench, policy, Outcome::NO_CHANGE)) {
      ++completed;
    }
  }
  const std::uint64_t total = elapsed_ns(start);
  return Row{name, requested, completed, total};
}

}  // namespace

int main() {
  Table table;
  const std::string store = benchmark_store_path();

  table.row(benchmark_policy_registration());
  table.row(benchmark_evidence_ingestion());
  table.row(benchmark_policy_evaluation());
  table.row(benchmark_suppression_check());
  table.row(benchmark_decision_commit());
  table.row(benchmark_path_invalidation());
  table.row(benchmark_snapshot());
  table.row(benchmark_semantic_digest());
  table.row(benchmark_persistence_save(store));
  table.row(benchmark_persistence_load(store));
  table.row(benchmark_policy_population());
  table.row(benchmark_targeted_evidence_fanout());
  table.row(benchmark_candidate_evaluation(4, "candidate_evaluation_4"));
  table.row(benchmark_candidate_evaluation(8, "candidate_evaluation_8"));
  table.row(benchmark_candidate_evaluation(16, "candidate_evaluation_16"));
  table.row(benchmark_candidate_evaluation(32, "candidate_evaluation_32"));

  if (!store.empty()) {
    std::error_code code;
    std::filesystem::remove(store, code);
  }
  return 0;
}

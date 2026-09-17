// Evidence publication, retention, aggregation and snapshot capture.
#include <algorithm>

#include "engine_impl.hpp"

namespace adaptive_routing::detail {
namespace {

const EvidenceRequirement* find_requirement(const PolicySemantics& semantics,
                                            MetricKind kind) noexcept {
  for (const auto& requirement : semantics.evidence) {
    if (requirement.kind == kind) {
      return &requirement;
    }
  }
  return nullptr;
}

}  // namespace

OperationResult Impl::publish_evidence(const PublishEvidenceRequest& request) {
  std::unique_lock lock(mutex_);
  if (request.publications.empty()) {
    return make_result(Outcome::MALFORMED_REQUEST, "no evidence publication supplied",
                       AdaptivePolicyId(), state_);
  }
  if (request.publications.size() > limits_.max_batch_size) {
    return make_result(Outcome::RESOURCE_LIMIT, "evidence batch exceeds the configured maximum",
                       AdaptivePolicyId(), state_);
  }
  const CallerCheck caller = check_caller(state_, request.context, std::nullopt, std::nullopt);
  if (!caller.ok) {
    return make_result(caller.outcome, caller.detail, AdaptivePolicyId(), state_);
  }
  Digest digest;
  digest.write_tag("evidence-batch");
  for (const auto& publication : request.publications) {
    digest.write_string(publication.source.str());
    digest.write_u64(publication.source_generation.value());
    digest.write_u8(static_cast<std::uint8_t>(publication.quality));
    digest.write_string(publication.path.str());
    digest.write_u8(static_cast<std::uint8_t>(publication.value.kind()));
    digest.write_i64(publication.value.value());
    digest.write_u64(publication.observation_sequence);
  }
  const std::string fingerprint = digest.hex();
  if (const auto replay = replay_check(state_, request.context.attempt, fingerprint)) {
    return *replay;
  }
  // Per-series state carried across the validation pass so that ordering rules
  // are enforced against the batch as well as against what is already stored.
  struct BatchKeyState {
    std::uint64_t source_generation = 0;
    std::uint64_t last_sequence = 0;
    EvidenceQuality quality = EvidenceQuality::PRIMARY;
  };
  std::map<EvidenceKey, BatchKeyState> batch_state;
  for (const auto& publication : request.publications) {
    if (!publication.well_formed()) {
      return make_result(Outcome::MALFORMED_REQUEST,
                         "evidence publication is malformed: source, source generation, path and a "
                         "bounded metric value are required",
                         AdaptivePolicyId(), state_);
    }
    if (!valid_evidence_quality(static_cast<std::uint8_t>(publication.quality))) {
      return make_result(Outcome::MALFORMED_REQUEST, "evidence quality class is unknown",
                         AdaptivePolicyId(), state_);
    }
    // Evidence may only be published for a path some policy in the caller's
    // authority scope actually binds. A publisher cannot inject samples for an
    // unrelated routing domain.
    const auto dependents = state_.policies_by_path.find(publication.path);
    bool authorized = false;
    if (dependents != state_.policies_by_path.end()) {
      for (const auto& policy : dependents->second) {
        const auto position = state_.policies.find(policy);
        if (position == state_.policies.end()) {
          continue;
        }
        if (caller.registration->scope.covers_route(
                position->second.policy.scope.fabric, position->second.policy.scope.name_space,
                position->second.policy.semantics.target.route)) {
          authorized = true;
          break;
        }
      }
    }
    if (!authorized) {
      return make_result(Outcome::UNAUTHORIZED_SCOPE,
                         "no policy in the caller authority scope binds path " +
                             publication.path.str(),
                         AdaptivePolicyId(), state_);
    }
    // The batch is validated in full before a single sample is applied, so a
    // refused publication leaves no partial state behind. Ordering checks that
    // depend on the batch itself are made against the batch view below.
    const EvidenceKey key{publication.source, publication.path, publication.value.kind()};
    const auto batch_entry = batch_state.find(key);
    const auto stored = state_.evidence.find(key);
    const std::uint64_t stored_generation =
        stored == state_.evidence.end() ? 0 : stored->second.source_generation.value();
    const std::uint64_t batch_generation =
        batch_entry == batch_state.end() ? 0 : batch_entry->second.source_generation;
    const std::uint64_t effective_generation = (std::max)(stored_generation, batch_generation);
    if (effective_generation != 0 && publication.source_generation.value() < effective_generation) {
      return make_result(Outcome::STALE_EVIDENCE,
                         "evidence arrives from a superseded source incarnation",
                         AdaptivePolicyId(), state_);
    }
    const bool new_incarnation =
        effective_generation != 0 && publication.source_generation.value() > effective_generation;
    if (!new_incarnation && effective_generation != 0) {
      const EvidenceQuality stored_quality =
          stored != state_.evidence.end() && publication.source_generation.value() == stored_generation
              ? stored->second.quality
              : batch_entry->second.quality;
      if (stored_quality != publication.quality) {
        return make_result(Outcome::MALFORMED_REQUEST,
                           "evidence quality class changed without a source generation change",
                           AdaptivePolicyId(), state_);
      }
    }
    const std::uint64_t last_sequence =
        new_incarnation
            ? 0
            : (batch_entry != batch_state.end()
                   ? batch_entry->second.last_sequence
                   : (stored != state_.evidence.end() && !stored->second.samples.empty()
                          ? stored->second.samples.back().observation_sequence
                          : 0));
    if (last_sequence != 0 && publication.observation_sequence <= last_sequence) {
      return make_result(Outcome::STALE_EVIDENCE,
                         "evidence observation sequence is not strictly increasing",
                         AdaptivePolicyId(), state_);
    }
    if (stored == state_.evidence.end() && batch_entry == batch_state.end()) {
      std::set<EvidenceSourceId> distinct;
      for (const auto& entry : state_.evidence) {
        distinct.insert(entry.first.source);
      }
      for (const auto& entry : batch_state) {
        distinct.insert(entry.first.source);
      }
      if (distinct.find(publication.source) == distinct.end() &&
          distinct.size() >= static_cast<std::size_t>(limits_.max_evidence_sources)) {
        return make_result(Outcome::RESOURCE_LIMIT, "evidence source limit reached",
                           AdaptivePolicyId(), state_);
      }
    }
    BatchKeyState& tracker = batch_state[key];
    tracker.source_generation = publication.source_generation.value();
    tracker.quality = publication.quality;
    tracker.last_sequence = publication.observation_sequence;
  }

  // Validation passed: apply the batch.
  for (const auto& publication : request.publications) {
    const EvidenceKey key{publication.source, publication.path, publication.value.kind()};
    auto series = state_.evidence.find(key);
    if (series == state_.evidence.end()) {
      EvidenceSeries fresh;
      fresh.source = publication.source;
      fresh.source_generation = publication.source_generation;
      fresh.quality = publication.quality;
      fresh.path = publication.path;
      fresh.kind = publication.value.kind();
      series = state_.evidence.emplace(key, std::move(fresh)).first;
    } else if (publication.source_generation > series->second.source_generation) {
      // A new source incarnation invalidates the retained samples of the old
      // one; they are dropped rather than mixed with the new generation.
      series->second.samples.clear();
      series->second.source_generation = publication.source_generation;
      series->second.quality = publication.quality;
      const auto advanced = state_.evidence_watermark.next();
      if (advanced.has_value()) {
        state_.evidence_watermark = *advanced;
      }
    }
    EvidenceSample sample;
    sample.path = publication.path;
    sample.value = publication.value;
    sample.accepted_at = now();
    sample.observation_sequence = publication.observation_sequence;
    series->second.samples.push_back(sample);
    ++series->second.total_published;
    while (series->second.samples.size() >
           static_cast<std::size_t>(limits_.max_evidence_samples_per_series)) {
      series->second.samples.pop_front();
    }
  }
  const auto advanced = state_.evidence_generation.next();
  if (!advanced.has_value()) {
    return make_result(Outcome::GENERATION_OVERFLOW, "evidence generation is exhausted",
                       AdaptivePolicyId(), state_);
  }
  state_.evidence_generation = *advanced;
  counters_.evidence_generation = state_.evidence_generation;
  // Evidence publication makes the publishing scope relevant to any policy that
  // binds one of the published paths.
  for (const auto& publication : request.publications) {
    const auto dependents = state_.policies_by_path.find(publication.path);
    if (dependents != state_.policies_by_path.end()) {
      for (const auto& policy : dependents->second) {
        state_.policies_by_source[publication.source].insert(policy);
      }
    }
  }
  record_attempt(state_, request.context.attempt, fingerprint, Outcome::POLICY_UPDATED,
                 "evidence published");
  OperationResult result =
      make_result(Outcome::POLICY_UPDATED,
                  "evidence published: " + std::to_string(request.publications.size()) +
                      " sample(s)",
                  AdaptivePolicyId(), state_);
  result.mutated = true;
  return result;
}

EvidenceGeneration Impl::evidence_generation() const {
  std::shared_lock lock(mutex_);
  return state_.evidence_generation;
}

Watermark Impl::evidence_watermark() const {
  std::shared_lock lock(mutex_);
  return state_.evidence_watermark;
}

Watermark Impl::upstream_watermark() const {
  std::shared_lock lock(mutex_);
  return state_.upstream_watermark;
}

std::vector<EvidenceSeriesView> Impl::describe_evidence(const AdaptivePolicyId& policy) const {
  std::shared_lock lock(mutex_);
  std::vector<EvidenceSeriesView> views;
  const auto position = state_.policies.find(policy);
  if (position == state_.policies.end()) {
    return views;
  }
  for (const auto& candidate : position->second.candidates) {
    for (const auto& entry : state_.evidence) {
      if (!(entry.first.path == candidate.binding.path)) {
        continue;
      }
      EvidenceSeriesView view;
      view.source = entry.second.source;
      view.source_generation = entry.second.source_generation;
      view.quality = entry.second.quality;
      view.path = entry.second.path;
      view.kind = entry.second.kind;
      view.retained = static_cast<std::uint32_t>(entry.second.samples.size());
      view.total_published = entry.second.total_published;
      if (!entry.second.samples.empty()) {
        view.oldest_accepted_at = entry.second.samples.front().accepted_at;
        view.newest_accepted_at = entry.second.samples.back().accepted_at;
      }
      views.push_back(view);
    }
  }
  return views;
}

std::optional<EvidenceAggregate> Impl::aggregate_for(const State& state, const PathId& path,
                                                     const EvidenceRequirement& requirement) const {
  return aggregate_for(state, path, requirement, nullptr);
}

std::optional<EvidenceAggregate> Impl::aggregate_for(const State& state, const PathId& path,
                                                     const EvidenceRequirement& requirement,
                                                     const EvidenceSeries** source) const {
  const EvidenceSeries* chosen = nullptr;
  for (const auto& entry : state.evidence) {
    if (!(entry.first.path == path) || entry.first.kind != requirement.kind) {
      continue;
    }
    if (evidence_quality_rank(entry.second.quality) <
        evidence_quality_rank(requirement.min_quality)) {
      continue;
    }
    if (entry.second.samples.empty()) {
      continue;
    }
    if (chosen == nullptr) {
      chosen = &entry.second;
      continue;
    }
    const std::uint32_t rank = evidence_quality_rank(entry.second.quality);
    const std::uint32_t best = evidence_quality_rank(chosen->quality);
    if (rank > best || (rank == best && entry.first.source < chosen->source)) {
      chosen = &entry.second;
    }
  }
  if (chosen == nullptr) {
    return std::nullopt;
  }
  if (source != nullptr) {
    *source = chosen;
  }
  // Samples are aggregated in observation order so that EWMA is independent of
  // arrival order and MEDIAN/PERCENTILE have a deterministic input sequence.
  std::vector<const EvidenceSample*> ordered;
  ordered.reserve(chosen->samples.size());
  for (const auto& sample : chosen->samples) {
    ordered.push_back(&sample);
  }
  std::stable_sort(ordered.begin(), ordered.end(),
                   [](const EvidenceSample* a, const EvidenceSample* b) {
                     return a->observation_sequence < b->observation_sequence;
                   });
  std::vector<std::int64_t> values;
  values.reserve(ordered.size());
  for (const auto* sample : ordered) {
    values.push_back(sample->value.value());
  }
  const auto aggregated =
      aggregate_samples(requirement.aggregation, values, requirement.ewma_alpha_bps);
  if (!aggregated.has_value()) {
    return std::nullopt;
  }
  const auto value = MetricValue::make(requirement.kind, *aggregated);
  if (!value.has_value()) {
    return std::nullopt;
  }
  EvidenceAggregate result;
  result.value = *value;
  result.sample_count = static_cast<std::uint32_t>(values.size());
  result.oldest_observed_at = ordered.front()->accepted_at;
  result.newest_observed_at = ordered.back()->accepted_at;
  result.aggregation = requirement.aggregation;
  result.ewma_alpha_bps = requirement.ewma_alpha_bps;
  return result;
}

std::optional<MetricValue> Impl::metric_for(const State& state, const PathId& path, MetricKind kind,
                                            const PolicySemantics& semantics) const {
  const EvidenceRequirement* requirement = find_requirement(semantics, kind);
  if (requirement == nullptr) {
    return std::nullopt;
  }
  const auto aggregate = aggregate_for(state, path, *requirement);
  if (!aggregate.has_value()) {
    return std::nullopt;
  }
  if (aggregate->sample_count < requirement->min_samples) {
    return std::nullopt;
  }
  const Ticks current = now();
  if (aggregate->age(current) > requirement->max_age) {
    return std::nullopt;
  }
  if (aggregate->window() < requirement->min_window) {
    return std::nullopt;
  }
  return aggregate->value;
}

EvidenceSnapshotPtr Impl::capture_evidence_locked(const State& state,
                                                  const PolicyRecord& record) const {
  EvidenceSnapshotBuilder builder(ids_.next_evidence_snapshot_id(), state.evidence_generation,
                                  state.epoch, now());
  for (const auto& candidate : record.candidates) {
    for (const auto& requirement : record.policy.semantics.evidence) {
      const EvidenceSeries* series = nullptr;
      const auto aggregate =
          aggregate_for(state, candidate.binding.path, requirement, &series);
      if (!aggregate.has_value() || series == nullptr) {
        continue;
      }
      ResolvedEvidence resolved;
      resolved.path = candidate.binding.path;
      resolved.kind = requirement.kind;
      resolved.quality = series->quality;
      resolved.source = series->source;
      resolved.source_generation = series->source_generation;
      resolved.aggregate = *aggregate;
      builder.add_value(resolved);
      if (resolved.source.valid()) {
        EvidenceBinding binding;
        binding.source = resolved.source;
        binding.source_generation = resolved.source_generation;
        binding.path = resolved.path;
        binding.kind = resolved.kind;
        builder.add_binding(binding);
      }
    }
  }
  return builder.finish();
}

EvidenceSnapshotPtr Impl::capture_evidence(const AdaptivePolicyId& policy) const {
  std::shared_lock lock(mutex_);
  const auto position = state_.policies.find(policy);
  if (position == state_.policies.end()) {
    return nullptr;
  }
  return capture_evidence_locked(state_, position->second);
}

}  // namespace adaptive_routing::detail

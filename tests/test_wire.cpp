// Wire protocol tests: frame layout, framing faults, payload round trips and the
// negative decode surface.
//
// Two techniques carry most of the weight here.
//
//   * The frame layout is asserted byte by byte against a known frame, with the
//     trailer produced by a reference implementation of the documented
//     deterministic hash. The reference exists so that a structurally valid
//     frame carrying a deliberate semantic defect (an unknown wire version, an
//     unknown message id, a zero epoch) can be forged: without a matching
//     trailer the decoder would stop at INTEGRITY and the defect under test
//     would never be reached.
//
//   * The byte that carries an enum or a generation inside a payload is located
//     by encoding two variants of the same message that differ only in that
//     field and diffing the two encodings. The offsets therefore come from the
//     encoder itself, so a layout change can never make this suite silently
//     probe the wrong byte.
#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/wire.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace adaptive_routing;

// A message value under test. CANONICAL is the value every round trip compares
// against; ENUM changes exactly one enum-valued field and GENERATION changes
// exactly one generation-valued field, so that diffing an encoding against the
// canonical one reveals where those fields live.
enum class WireVariant : std::uint8_t {
  CANONICAL = 0,
  ENUM = 1,
  GENERATION = 2,
};

[[nodiscard]] constexpr bool variant_is(WireVariant variant, WireVariant wanted) noexcept {
  return static_cast<std::uint8_t>(variant) == static_cast<std::uint8_t>(wanted);
}

// Every generation-valued field is 1 in the canonical value and 2 in the
// generation variant. Differing only in the low byte is what makes zeroing that
// byte a zero-generation probe.
[[nodiscard]] constexpr std::uint64_t generation_value(WireVariant variant) noexcept {
  return variant_is(variant, WireVariant::GENERATION) ? 2U : 1U;
}

// ---------------------------------------------------------------------------
// Byte level helpers
// ---------------------------------------------------------------------------

[[nodiscard]] std::uint8_t byte_at(std::string_view bytes, std::size_t offset) {
  return static_cast<std::uint8_t>(static_cast<unsigned char>(bytes[offset]));
}

// Little-endian read of width 1, 2, 4 or 8 bytes.
[[nodiscard]] std::uint64_t read_le(std::string_view bytes, std::size_t offset, std::size_t width) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < width; ++index) {
    value |= static_cast<std::uint64_t>(byte_at(bytes, offset + index)) << (8U * index);
  }
  return value;
}

void expect_bytes(std::string_view what, std::string_view bytes, std::size_t offset,
                  std::initializer_list<std::uint8_t> expected) {
  std::size_t index = 0;
  for (const std::uint8_t want : expected) {
    const std::size_t at = offset + index;
    ++index;
    ARF_CHECK_MSG(at < bytes.size() && byte_at(bytes, at) == want,
                  std::string(what) + " byte " + std::to_string(at));
  }
}

// Offsets at which two encodings of the same message differ. The payload is
// rejected unless the two encodings have the same length, because a length
// difference would make the offsets meaningless.
[[nodiscard]] std::vector<std::size_t> differing_offsets(std::string_view canonical,
                                                         std::string_view variant) {
  std::vector<std::size_t> offsets;
  if (canonical.size() != variant.size()) {
    return offsets;
  }
  for (std::size_t index = 0; index < canonical.size(); ++index) {
    if (canonical[index] != variant[index]) {
      offsets.push_back(index);
    }
  }
  return offsets;
}

// ---------------------------------------------------------------------------
// Frame forging
// ---------------------------------------------------------------------------

// Reference implementation of the documented frame trailer: a deterministic
// non-cryptographic hash over the semantic header and the payload. It is a
// mirror of the library's own trailer by necessity -- the trailer is not
// invertible -- and every frame the library encodes is compared against it
// below, so a divergence between the two is reported as a layout failure.
[[nodiscard]] std::uint64_t trailer_of(std::string_view header_and_payload) {
  std::uint64_t low = 14695981039346656037ULL;
  std::uint64_t high = 0x9E3779B97F4A7C15ULL;
  for (const char character : header_and_payload) {
    const std::uint64_t octet =
        static_cast<std::uint64_t>(static_cast<unsigned char>(character));
    low ^= octet;
    low *= 1099511628211ULL;
    high += octet;
    high ^= (high << 13);
    high *= 1099511628211ULL;
  }
  return low ^ high;
}

// Fields of a frame as they appear on the wire, with a declared length that may
// deliberately disagree with the payload that follows it.
struct RawFrame {
  std::uint32_t magic = frame_magic;
  std::uint16_t wire_version = wire_protocol_version;
  std::uint16_t message_id = static_cast<std::uint16_t>(MessageId::HELLO);
  std::uint32_t flags = 0;
  std::uint32_t declared_length = 0;
  std::uint64_t sequence = 0;
  std::uint64_t epoch = 1;
};

[[nodiscard]] std::string forge_frame(const RawFrame& header, std::string_view payload) {
  ByteWriter writer;
  writer.put_u32(header.magic);
  writer.put_u16(header.wire_version);
  writer.put_u16(header.message_id);
  writer.put_u32(header.flags);
  const std::uint32_t declared =
      header.declared_length != 0 ? header.declared_length
                                  : static_cast<std::uint32_t>(payload.size());
  writer.put_u32(declared);
  writer.put_u64(header.sequence);
  writer.put_u64(header.epoch);
  std::string bytes = writer.take();
  bytes.append(payload.data(), payload.size());
  ByteWriter tail;
  tail.put_u64(trailer_of(bytes));
  bytes += tail.take();
  return bytes;
}

[[nodiscard]] Frame make_frame(MessageId id, std::string payload, std::uint64_t sequence,
                               std::uint32_t flags, std::uint64_t epoch_value) {
  Frame frame;
  frame.header.message_id = id;
  frame.header.flags = flags;
  frame.header.sequence = sequence;
  frame.header.epoch = CoordinatorEpoch::require(epoch_value);
  frame.payload = std::move(payload);
  frame.header.payload_length = static_cast<std::uint32_t>(frame.payload.size());
  return frame;
}

[[nodiscard]] std::uint64_t default_frame_limit() { return Limits{}.max_frame_bytes; }

// ---------------------------------------------------------------------------
// Frame framing
// ---------------------------------------------------------------------------

ARF_TEST(wire_frame_header_layout_is_byte_exact) {
  // The header width and the trailer width are part of the protocol contract:
  // a peer that disagrees about either one cannot interoperate.
  ARF_CHECK_EQ(frame_header_bytes, static_cast<std::size_t>(32));
  ARF_CHECK_EQ(frame_trailer_bytes, static_cast<std::size_t>(8));

  Frame frame = make_frame(MessageId::PUBLISH_EVIDENCE, "payload-xyz", 0x1122334455667788ULL,
                           0x01020304U, 7);
  const auto encoded = encode_frame(frame, default_frame_limit());
  ARF_REQUIRE(encoded.has_value());
  const std::string& bytes = *encoded;
  ARF_CHECK_EQ(bytes.size(), frame_header_bytes + frame.payload.size() + frame_trailer_bytes);
  ARF_CHECK_EQ(bytes.size(), static_cast<std::size_t>(51));

  expect_bytes("magic", bytes, 0, {0x41, 0x52, 0x46, 0x31});          // "ARF1"
  expect_bytes("wire version", bytes, 4, {0x01, 0x00});               // 1, little endian
  expect_bytes("message id", bytes, 6, {0x0A, 0x00});                 // PUBLISH_EVIDENCE = 10
  expect_bytes("flags", bytes, 8, {0x04, 0x03, 0x02, 0x01});          // 0x01020304
  expect_bytes("payload length", bytes, 12, {0x0B, 0x00, 0x00, 0x00});  // 11
  expect_bytes("sequence", bytes, 16,
               {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11});
  expect_bytes("epoch", bytes, 24, {0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
  ARF_CHECK_EQ(bytes.substr(frame_header_bytes, frame.payload.size()), frame.payload);
  ARF_CHECK_EQ(read_le(bytes, 0, 4), static_cast<std::uint64_t>(frame_magic));
  ARF_CHECK_EQ(read_le(bytes, 4, 2), static_cast<std::uint64_t>(wire_protocol_version));
  ARF_CHECK_EQ(read_le(bytes, 6, 2), static_cast<std::uint64_t>(MessageId::PUBLISH_EVIDENCE));
  ARF_CHECK_EQ(read_le(bytes, 8, 4), static_cast<std::uint64_t>(0x01020304U));
  ARF_CHECK_EQ(read_le(bytes, 12, 4), static_cast<std::uint64_t>(frame.payload.size()));
  ARF_CHECK_EQ(read_le(bytes, 16, 8), 0x1122334455667788ULL);
  ARF_CHECK_EQ(read_le(bytes, 24, 8), static_cast<std::uint64_t>(7));

  // The trailer occupies the eight bytes that follow the payload, and the
  // reference implementation of the documented hash reproduces it exactly.
  const std::size_t trailer_at = frame_header_bytes + frame.payload.size();
  ARF_CHECK_EQ(trailer_at, static_cast<std::size_t>(43));
  ARF_CHECK_EQ(read_le(bytes, trailer_at, 8),
               trailer_of(std::string_view(bytes).substr(0, trailer_at)));

  // The whole frame is a pure function of its fields: re-encoding is identical,
  // and a single bit anywhere in the header or the payload changes the trailer.
  const auto reencoded = encode_frame(frame, default_frame_limit());
  ARF_REQUIRE(reencoded.has_value());
  ARF_CHECK_EQ(*reencoded, bytes);
  Frame other = frame;
  other.header.sequence += 1;
  const auto other_bytes = encode_frame(other, default_frame_limit());
  ARF_REQUIRE(other_bytes.has_value());
  ARF_CHECK_MSG(*other_bytes != bytes, "the sequence is not covered by the frame encoding");
}

ARF_TEST(wire_frame_every_covered_byte_is_integrity_protected) {
  const std::string bytes = forge_frame(RawFrame{}, "body");
  const std::size_t covered = bytes.size() - frame_trailer_bytes;
  const std::uint64_t limit = default_frame_limit();
  ARF_REQUIRE(decode_frame(bytes, limit).status == FrameStatus::OK);

  // Every byte the trailer covers is genuinely covered: a single flipped bit is
  // never accepted. Header bytes may be rejected earlier by a structural check
  // (magic, version, message id), which is still a rejection.
  for (std::size_t offset = 0; offset < covered; ++offset) {
    for (const unsigned int raw_mask : {0x01U, 0x80U}) {
      const std::uint8_t mask = static_cast<std::uint8_t>(raw_mask);
      std::string mutated = bytes;
      mutated[offset] = static_cast<char>(byte_at(mutated, offset) ^ mask);
      const FrameDecodeResult decoded = decode_frame(mutated, limit);
      ARF_CHECK_MSG(decoded.status != FrameStatus::OK,
                    "a flipped bit at offset " + std::to_string(offset) + " was accepted");
    }
  }

  // Every one of the eight trailer bytes is validated against the content, so a
  // truncated or edited trailer is never accepted either.
  for (std::size_t offset = covered; offset < bytes.size(); ++offset) {
    std::string mutated = bytes;
    mutated[offset] = static_cast<char>(byte_at(mutated, offset) ^ 0x01U);
    ARF_CHECK_EQ(decode_frame(mutated, limit).status, FrameStatus::INTEGRITY);
  }
}

ARF_TEST(wire_decode_reports_incomplete_below_a_whole_frame) {
  const std::string bytes = forge_frame(RawFrame{}, "abc");
  const std::uint64_t limit = default_frame_limit();

  // 0..31 bytes: the fixed header alone cannot be interpreted.
  for (std::size_t length = 0; length < frame_header_bytes; ++length) {
    const FrameDecodeResult decoded =
        decode_frame(std::string_view(bytes).substr(0, length), limit);
    ARF_CHECK_EQ(decoded.status, FrameStatus::INCOMPLETE);
    ARF_CHECK_EQ(decoded.consumed, static_cast<std::size_t>(0));
  }

  // A frame that is missing its trailer, in whole or in part, is incomplete
  // rather than valid: the integrity value is not optional.
  for (const std::size_t missing : {1U, 2U, 4U, 7U, 8U}) {
    const FrameDecodeResult decoded =
        decode_frame(std::string_view(bytes).substr(0, bytes.size() - missing), limit);
    ARF_CHECK_EQ(decoded.status, FrameStatus::INCOMPLETE);
    ARF_CHECK_EQ(decoded.consumed, static_cast<std::size_t>(0));
  }

  const FrameDecodeResult whole = decode_frame(bytes, limit);
  ARF_CHECK_EQ(whole.status, FrameStatus::OK);
  ARF_CHECK_EQ(whole.consumed, bytes.size());
}

ARF_TEST(wire_decode_rejects_structural_faults) {
  const std::uint64_t limit = default_frame_limit();
  const std::string payload = "abc";
  const std::string valid = forge_frame(RawFrame{}, payload);
  ARF_REQUIRE(decode_frame(valid, limit).status == FrameStatus::OK);

  RawFrame bad_magic;
  bad_magic.magic = frame_magic + 1U;
  ARF_CHECK_EQ(decode_frame(forge_frame(bad_magic, payload), limit).status,
               FrameStatus::BAD_MAGIC);

  RawFrame bad_version;
  bad_version.wire_version = static_cast<std::uint16_t>(wire_protocol_version + 1U);
  ARF_CHECK_EQ(decode_frame(forge_frame(bad_version, payload), limit).status,
               FrameStatus::BAD_VERSION);

  for (const unsigned int raw_id : {0U, 24U, 0xFFFFU}) {
    RawFrame bad_id;
    bad_id.message_id = static_cast<std::uint16_t>(raw_id);
    ARF_CHECK_EQ(decode_frame(forge_frame(bad_id, payload), limit).status,
                 FrameStatus::BAD_MESSAGE_ID);
  }

  // A declared payload length beyond the configured frame bound is rejected
  // before a single payload byte is read, so the header alone is enough.
  const std::uint64_t small_limit = 512;
  RawFrame too_large;
  too_large.declared_length =
      static_cast<std::uint32_t>(small_limit - frame_header_bytes - frame_trailer_bytes + 1U);
  const std::string over_limit = forge_frame(too_large, std::string(16, 'x'));
  ARF_CHECK_EQ(decode_frame(over_limit, small_limit).status, FrameStatus::TOO_LARGE);
  ARF_CHECK_EQ(decode_frame(std::string_view(over_limit).substr(0, frame_header_bytes), small_limit)
                   .status,
               FrameStatus::TOO_LARGE);

  RawFrame absurd;
  absurd.declared_length = 0xFFFFFFFFU;
  const std::string absurd_frame = forge_frame(absurd, payload);
  ARF_CHECK_EQ(decode_frame(std::string_view(absurd_frame).substr(0, frame_header_bytes), limit)
                   .status,
               FrameStatus::TOO_LARGE);

  // One flipped bit in the header and one in the payload: both are integrity
  // failures, because the trailer covers the semantic header as well.
  std::string header_bit = valid;
  header_bit[8] = static_cast<char>(byte_at(header_bit, 8) ^ 0x80U);
  ARF_CHECK_EQ(decode_frame(header_bit, limit).status, FrameStatus::INTEGRITY);
  std::string epoch_bit = valid;
  epoch_bit[24] = static_cast<char>(byte_at(epoch_bit, 24) ^ 0x01U);
  ARF_CHECK_EQ(decode_frame(epoch_bit, limit).status, FrameStatus::INTEGRITY);
  std::string payload_bit = valid;
  payload_bit[frame_header_bytes] =
      static_cast<char>(byte_at(payload_bit, frame_header_bytes) ^ 0x40U);
  ARF_CHECK_EQ(decode_frame(payload_bit, limit).status, FrameStatus::INTEGRITY);

  // A structurally sound frame whose epoch is zero is malformed: an epoch is a
  // generation and generation zero is never a valid authority.
  RawFrame zero_epoch;
  zero_epoch.epoch = 0;
  ARF_CHECK_EQ(decode_frame(forge_frame(zero_epoch, payload), limit).status,
               FrameStatus::MALFORMED);
  ARF_CHECK_EQ(decode_frame(forge_frame(zero_epoch, payload), limit).frame.header.epoch.value(),
               static_cast<std::uint64_t>(0));
}

ARF_TEST(wire_decode_consumes_exactly_one_frame) {
  const std::uint64_t limit = default_frame_limit();
  const Frame first = make_frame(MessageId::EVALUATE, "first-payload", 11, 0, 3);
  const Frame second = make_frame(MessageId::RESULT, "second", 12, 0x80000000U, 3);
  const auto first_bytes = encode_frame(first, limit);
  const auto second_bytes = encode_frame(second, limit);
  ARF_REQUIRE(first_bytes.has_value());
  ARF_REQUIRE(second_bytes.has_value());

  const std::string buffer = *first_bytes + *second_bytes;
  const FrameDecodeResult decoded_first = decode_frame(buffer, limit);
  ARF_CHECK_EQ(decoded_first.status, FrameStatus::OK);
  ARF_CHECK_EQ(decoded_first.consumed,
               frame_header_bytes + first.payload.size() + frame_trailer_bytes);
  ARF_CHECK_EQ(decoded_first.frame.payload, first.payload);
  ARF_CHECK_EQ(decoded_first.frame.header.message_id, first.header.message_id);
  ARF_CHECK_EQ(decoded_first.frame.header.sequence, first.header.sequence);
  ARF_CHECK_EQ(decoded_first.frame.header.epoch, first.header.epoch);

  // A two frame buffer decodes twice: the second frame starts exactly where the
  // first one ended.
  const FrameDecodeResult decoded_second =
      decode_frame(std::string_view(buffer).substr(decoded_first.consumed), limit);
  ARF_CHECK_EQ(decoded_second.status, FrameStatus::OK);
  ARF_CHECK_EQ(decoded_second.consumed,
               frame_header_bytes + second.payload.size() + frame_trailer_bytes);
  ARF_CHECK_EQ(decoded_second.frame.payload, second.payload);
  ARF_CHECK_EQ(decoded_second.frame.header.message_id, second.header.message_id);
  ARF_CHECK_EQ(decoded_second.frame.header.flags, second.header.flags);
  ARF_CHECK_EQ(decoded_first.consumed + decoded_second.consumed, buffer.size());
  ARF_CHECK_EQ(decode_frame(std::string_view(buffer).substr(buffer.size()), limit).status,
               FrameStatus::INCOMPLETE);
}

// ---------------------------------------------------------------------------
// Payload values
// ---------------------------------------------------------------------------

[[nodiscard]] PolicyScope wire_scope() {
  PolicyScope scope;
  scope.fabric = arf_test::fabric_id();
  scope.name_space = arf_test::routing_namespace();
  scope.site = SiteId::require("site-a");
  scope.path_class = PathClass::require("gold");
  scope.routes.push_back(RouteId::require("route-1"));
  scope.multipath_sets.push_back(MultipathSetId::require("set-1"));
  return scope;
}

// A policy semantics that is valid, rich and (for the enum variant) carries the
// same shape with a different metric kind in every enum position.
[[nodiscard]] PolicySemantics wire_semantics(WireVariant variant) {
  const MetricKind kind = variant_is(variant, WireVariant::ENUM) ? MetricKind::PATH_LATENCY
                                                                 : MetricKind::PATH_UTILIZATION;
  PolicySemantics semantics;
  semantics.target.route = RouteId::require("route-1");
  semantics.target.multipath_set = MultipathSetId::require("set-1");
  ThresholdRule threshold;
  threshold.kind = kind;
  threshold.switch_value = MetricValue::make(kind, 8000).value_or(MetricValue{});
  threshold.clear_value = MetricValue::make(kind, 2000).value_or(MetricValue{});
  semantics.thresholds.push_back(threshold);
  ImprovementRule improvement;
  improvement.kind = kind;
  improvement.switch_improvement_bps = 250;
  improvement.reverse_improvement_bps = 500;
  semantics.improvements.push_back(improvement);
  EvidenceRequirement requirement;
  requirement.kind = kind;
  requirement.aggregation = AggregationKind::MEDIAN;
  // The EWMA smoothing constant is meaningful only for EWMA aggregation;
  // EvidenceRequirement::valid() requires it to be zero otherwise.
  requirement.ewma_alpha_bps = 0;
  requirement.min_samples = 3;
  requirement.max_age = seconds(120);
  requirement.min_window = seconds(5);
  requirement.min_quality = EvidenceQuality::AGGREGATED;
  requirement.required = true;
  semantics.evidence.push_back(requirement);
  semantics.hold_down.duration = seconds(30);
  semantics.cooldown.duration = seconds(10);
  semantics.churn.max_adaptations_per_window = 4;
  semantics.churn.window = seconds(300);
  ObjectiveSpec objective;
  objective.mode = ObjectiveMode::LEXICOGRAPHIC;
  ObjectiveTerm term;
  term.kind = kind;
  objective.terms.push_back(term);
  semantics.objective = objective;
  CandidatePriority priority;
  priority.path = PathId::require("path-a");
  priority.priority = 7;
  semantics.priorities.push_back(priority);
  return semantics;
}

[[nodiscard]] CandidateBinding wire_binding(WireVariant variant) {
  const std::uint64_t generation = generation_value(variant);
  CandidateBinding binding;
  binding.path = PathId::require("path-a");
  binding.path_authority.path = binding.path;
  binding.path_authority.generation = PathAuthorityGeneration::require(generation);
  binding.path_authority.legal = true;
  binding.path_authority.denial_reason = "none";
  MultipathBinding multipath;
  multipath.set = MultipathSetId::require("set-1");
  multipath.generation = MultipathSetGeneration::require(generation);
  multipath.current = true;
  multipath.members.push_back(binding.path);
  multipath.members.push_back(PathId::require("path-b"));
  binding.multipath = multipath;
  binding.route.route = RouteId::require("route-1");
  binding.route.generation = RouteGeneration::require(generation);
  binding.route.site = SiteId::require("site-a");
  binding.route.current = true;
  binding.route.state = "up";
  WeightedPolicyBinding weighted;
  weighted.set = WeightedPathSetId::require("weighted-1");
  weighted.generation = WeightPolicyGeneration::require(generation);
  weighted.current = true;
  binding.weighted = weighted;
  binding.path_class = PathClass::require("gold");
  binding.available = true;
  binding.hard_failure = false;
  return binding;
}

[[nodiscard]] EvidencePublication wire_publication(WireVariant variant, std::string_view source,
                                                   std::string_view path_name, MetricKind kind,
                                                   std::int64_t value, std::uint64_t sequence) {
  EvidencePublication publication;
  publication.source = EvidenceSourceId::require(source);
  publication.source_generation =
      EvidenceSourceGeneration::require(generation_value(variant));
  publication.quality = variant_is(variant, WireVariant::ENUM) ? EvidenceQuality::OPERATOR
                                                               : EvidenceQuality::AGGREGATED;
  publication.path = PathId::require(path_name);
  publication.value = MetricValue::make(kind, value).value_or(MetricValue{});
  publication.observation_sequence = sequence;
  return publication;
}

[[nodiscard]] UpstreamNotification wire_notification(WireVariant variant) {
  UpstreamNotification notification;
  notification.event = variant_is(variant, WireVariant::ENUM) ? UpstreamEvent::SET_MEMBERSHIP
                                                              : UpstreamEvent::DECLARE_CANDIDATE;
  notification.policy = AdaptivePolicyId::require("policy-1");
  notification.binding = wire_binding(variant);
  notification.provenance.publisher = PublisherId::require("publisher-a");
  notification.provenance.worker_boot = WorkerBootId::require("boot-a1");
  notification.provenance.epoch = CoordinatorEpoch::require(generation_value(variant));
  notification.provenance.attempt = MutationAttemptId::require("attempt-1");
  notification.provenance.origin = "path-authority";
  // A plain expected-generation counter, not a Generation: zero is a legal value
  // here, so it must not move with the generation variant.
  notification.expected_previous_generation = 3;
  return notification;
}

[[nodiscard]] EvaluationTicket wire_ticket(WireVariant variant) {
  const std::uint64_t generation = generation_value(variant);
  EvaluationTicket ticket;
  DependencySnapshot& dependencies = ticket.dependencies;
  dependencies.evaluation = EvaluationId::require("eval-1");
  dependencies.policy = AdaptivePolicyId::require("policy-1");
  dependencies.policy_generation = AdaptivePolicyGeneration::require(generation);
  dependencies.evidence_generation = EvidenceGeneration::require(generation);
  dependencies.evidence_watermark = Watermark(3);
  dependencies.upstream_watermark = Watermark(4);
  dependencies.epoch = CoordinatorEpoch::require(generation);
  dependencies.authority_generation = AdaptiveAuthorityGeneration::require(generation);
  dependencies.route_generation = RouteGeneration::require(generation);
  dependencies.multipath_set = MultipathSetId::require("set-1");
  dependencies.multipath_set_generation = MultipathSetGeneration::require(generation);
  PathAuthorityBinding authority;
  authority.path = PathId::require("path-a");
  authority.generation = PathAuthorityGeneration::require(generation);
  authority.legal = true;
  authority.denial_reason = "";
  dependencies.candidate_path_authority.push_back(authority);
  dependencies.candidate_path_watermarks.push_back(7);
  dependencies.candidates.push_back(PathId::require("path-a"));
  dependencies.captured_at = 111;

  ticket.lifecycle = variant_is(variant, WireVariant::ENUM) ? DecisionLifecycle::COMMITTED
                                                            : DecisionLifecycle::ELIGIBLE;
  ticket.decision = AdaptationDecisionId::require("decision-1");
  ticket.evidence_snapshot = EvidenceSnapshotId::require("evidence-1");
  ticket.outcome = Outcome::NO_CHANGE;
  ticket.suppression = SuppressionReason::NONE;
  ticket.detail = "wire ticket";
  ticket.current_preference = PathId::require("path-a");
  ticket.target_preference = PathId::require("path-b");
  ticket.target_path_authority_generation = PathAuthorityGeneration::require(generation);
  ticket.adaptation_generation = AdaptationGeneration::require(generation);
  ticket.transition_generation = TransitionGeneration::require(generation);
  ticket.target_score = 4242;
  ticket.improvement_bps = 321;
  ticket.required_improvement_bps = 100;
  WeightProposal proposal;
  proposal.set = WeightedPathSetId::require("weighted-1");
  proposal.base_generation = WeightPolicyGeneration::require(generation);
  PathWeight weight;
  weight.path = PathId::require("path-b");
  weight.weight_bps = basis_points_scale;
  proposal.weights.push_back(weight);
  ticket.weight_proposal = proposal;
  ticket.rollback = false;
  ticket.emergency = true;

  CandidateEvaluation ranking;
  ranking.path = PathId::require("path-b");
  ranking.eligible = true;
  ranking.rejection = SuppressionReason::NONE;
  ranking.rejection_outcome = Outcome::NO_CHANGE;
  ranking.quality = EvidenceQuality::AGGREGATED;
  ranking.score = 900;
  ranking.metrics.push_back(
      MetricValue::make(MetricKind::PATH_LATENCY, 1500).value_or(MetricValue{}));
  ranking.priority = 3;
  ranking.current_preference = false;
  ranking.previous_preference = true;
  ranking.required_improvement_bps = 100;
  ranking.observed_improvement_bps = 321;
  ranking.path_authority_generation = PathAuthorityGeneration::require(generation);
  ranking.multipath_set_generation = MultipathSetGeneration::require(generation);
  ranking.route_generation = RouteGeneration::require(generation);
  ticket.ranking.push_back(ranking);
  ticket.evaluated_at = 222;
  return ticket;
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

[[nodiscard]] HelloMessage make_hello(WireVariant variant) {
  HelloMessage message;
  message.wire_version = wire_protocol_version;
  message.product = std::string(product_name) + " " + std::string(version_string);
  message.epoch = CoordinatorEpoch::require(generation_value(variant));
  message.authority_generation = AdaptiveAuthorityGeneration::require(generation_value(variant));
  return message;
}

[[nodiscard]] RegisterPublisherMessage make_register(WireVariant) {
  RegisterPublisherMessage message;
  message.publisher = PublisherId::require("publisher-a");
  message.worker_boot = WorkerBootId::require("boot-a1");
  message.scope.fabric = arf_test::fabric_id();
  message.scope.name_space = arf_test::routing_namespace();
  message.scope.routes.push_back(RouteId::require("route-1"));
  message.scope.multipath_sets.push_back(MultipathSetId::require("set-1"));
  return message;
}

[[nodiscard]] FenceNoticeMessage make_fence(WireVariant) {
  FenceNoticeMessage message;
  message.publisher = PublisherId::require("publisher-a");
  message.worker_boot = WorkerBootId::require("boot-a1");
  message.cause = "EPOCH_ADVANCE";
  return message;
}

[[nodiscard]] CreatePolicyMessage make_create(WireVariant variant) {
  CreatePolicyMessage message;
  message.name = AdaptivePolicyName::require("policy-wire");
  message.scope = wire_scope();
  message.semantics = wire_semantics(variant);
  return message;
}

[[nodiscard]] UpdatePolicyMessage make_update(WireVariant variant) {
  UpdatePolicyMessage message;
  message.policy = AdaptivePolicyId::require("policy-1");
  message.scope = wire_scope();
  message.semantics = wire_semantics(variant);
  return message;
}

[[nodiscard]] PolicyLifecycleMessage make_lifecycle(WireVariant variant) {
  PolicyLifecycleMessage message;
  message.policy = AdaptivePolicyId::require("policy-1");
  message.event = variant_is(variant, WireVariant::ENUM) ? PolicyEvent::RETIRE
                                                         : PolicyEvent::SUSPEND;
  message.detail = "wire lifecycle";
  return message;
}

[[nodiscard]] RevokePolicyMessage make_revoke(WireVariant variant) {
  RevokePolicyMessage message;
  message.policy = AdaptivePolicyId::require("policy-1");
  message.reason = variant_is(variant, WireVariant::ENUM) ? RevocationReason::SECURITY
                                                          : RevocationReason::ADMINISTRATIVE;
  message.detail = "wire revocation";
  return message;
}

[[nodiscard]] UpstreamNotifyMessage make_upstream(WireVariant variant) {
  UpstreamNotifyMessage message;
  message.notifications.push_back(wire_notification(variant));
  UpstreamNotification second = wire_notification(WireVariant::CANONICAL);
  second.event = UpstreamEvent::MARK_UNAVAILABLE;
  second.expected_previous_generation.reset();
  message.notifications.push_back(second);
  return message;
}

[[nodiscard]] PublishEvidenceMessage make_publish(WireVariant variant) {
  PublishEvidenceMessage message;
  message.publications.push_back(
      wire_publication(variant, "telemetry-1", "path-a", MetricKind::PATH_LATENCY, 1500, 9));
  message.publications.push_back(
      wire_publication(WireVariant::CANONICAL, "telemetry-2", "path-b",
                       MetricKind::PATH_UTILIZATION, 4200, 10));
  return message;
}

[[nodiscard]] EvaluateMessage make_evaluate(WireVariant) {
  EvaluateMessage message;
  message.policy = AdaptivePolicyId::require("policy-1");
  message.defer_commit = true;
  return message;
}

[[nodiscard]] CommitDecisionMessage make_commit(WireVariant variant) {
  CommitDecisionMessage message;
  message.ticket = wire_ticket(variant);
  return message;
}

[[nodiscard]] RevalidateMessage make_revalidate(WireVariant) {
  RevalidateMessage message;
  message.policy = AdaptivePolicyId::require("policy-1");
  message.attempt = RevalidationAttemptId::require("revalidation-1");
  return message;
}

[[nodiscard]] RollbackMessage make_rollback(WireVariant) {
  RollbackMessage message;
  message.policy = AdaptivePolicyId::require("policy-1");
  message.reason = "operator requested";
  return message;
}

[[nodiscard]] QueryStateMessage make_query(WireVariant) {
  QueryStateMessage message;
  message.limit = 7;
  return message;
}

[[nodiscard]] SnapshotRequestMessage make_snapshot_request(WireVariant) {
  SnapshotRequestMessage message;
  message.policy = AdaptivePolicyId::require("policy-1");
  return message;
}

[[nodiscard]] SnapshotResponseMessage make_snapshot_response(WireVariant) {
  SnapshotResponseMessage message;
  message.snapshot = SnapshotId::require("snapshot-1");
  message.policy = AdaptivePolicyId::require("policy-1");
  message.digest = "0123456789abcdef0123456789abcdef";
  message.rendered = "lifecycle=ACTIVE preference=path-a";
  return message;
}

[[nodiscard]] ExplainRequestMessage make_explain(WireVariant variant) {
  ExplainRequestMessage message;
  message.topic = variant_is(variant, WireVariant::ENUM) ? ExplanationTopic::HOLD_DOWN
                                                         : ExplanationTopic::WHY_NOT_ADAPTED;
  message.policy = AdaptivePolicyId::require("policy-1");
  return message;
}

[[nodiscard]] DiffRequestMessage make_diff(WireVariant) {
  DiffRequestMessage message;
  message.policy = AdaptivePolicyId::require("policy-1");
  message.from = SnapshotId::require("snapshot-1");
  message.to = SnapshotId::require("snapshot-2");
  return message;
}

[[nodiscard]] AdvanceEpochMessage make_advance(WireVariant) {
  AdvanceEpochMessage message;
  message.reason = "coordinator restart";
  return message;
}

[[nodiscard]] ResultMessage make_result(WireVariant variant) {
  ResultMessage message;
  message.outcome = variant_is(variant, WireVariant::ENUM) ? Outcome::DECISION_COMMITTED
                                                           : Outcome::NO_CHANGE;
  message.suppression = SuppressionReason::NONE;
  message.detail = "wire result";
  message.policy = AdaptivePolicyId::require("policy-1");
  message.policy_generation = AdaptivePolicyGeneration::require(generation_value(variant));
  message.decision = AdaptationDecisionId::require("decision-1");
  message.adaptation_generation = AdaptationGeneration::require(generation_value(variant));
  message.transition_generation = TransitionGeneration::require(generation_value(variant));
  message.evidence_generation = EvidenceGeneration::require(generation_value(variant));
  message.epoch = CoordinatorEpoch::require(generation_value(variant));
  message.rendered = "outcome=NO_CHANGE";
  return message;
}

[[nodiscard]] ErrorMessage make_error(WireVariant variant) {
  ErrorMessage message;
  message.outcome = variant_is(variant, WireVariant::ENUM) ? Outcome::WIRE_INTEGRITY
                                                           : Outcome::MALFORMED_REQUEST;
  message.detail = "wire error";
  return message;
}

// ---------------------------------------------------------------------------
// Payload verification
// ---------------------------------------------------------------------------

void verify_hello(std::string_view payload) {
  const auto decoded = HelloMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const HelloMessage expected = make_hello(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->wire_version, expected.wire_version);
  ARF_CHECK_EQ(decoded->product, expected.product);
  ARF_CHECK_EQ(decoded->epoch, expected.epoch);
  ARF_CHECK_EQ(decoded->authority_generation, expected.authority_generation);
}

void verify_register(std::string_view payload) {
  const auto decoded = RegisterPublisherMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const RegisterPublisherMessage expected = make_register(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->publisher, expected.publisher);
  ARF_CHECK_EQ(decoded->worker_boot, expected.worker_boot);
  ARF_CHECK_EQ(decoded->scope.render(), expected.scope.render());
  ARF_CHECK_EQ(decoded->scope.routes.size(), expected.scope.routes.size());
  ARF_CHECK_EQ(decoded->scope.multipath_sets.size(), expected.scope.multipath_sets.size());
}

void verify_fence(std::string_view payload) {
  const auto decoded = FenceNoticeMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const FenceNoticeMessage expected = make_fence(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->publisher, expected.publisher);
  ARF_CHECK_EQ(decoded->worker_boot, expected.worker_boot);
  ARF_CHECK_EQ(decoded->cause, expected.cause);
}

void verify_create(std::string_view payload) {
  const auto decoded = CreatePolicyMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const CreatePolicyMessage expected = make_create(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->name, expected.name);
  ARF_CHECK_EQ(decoded->scope.render(), expected.scope.render());
  ARF_CHECK_EQ(decoded->semantics.render(), expected.semantics.render());
  ARF_CHECK_EQ(decoded->semantics.thresholds.size(), expected.semantics.thresholds.size());
  ARF_CHECK_EQ(decoded->semantics.improvements.size(), expected.semantics.improvements.size());
  ARF_CHECK_EQ(decoded->semantics.evidence.size(), expected.semantics.evidence.size());
  ARF_CHECK_EQ(decoded->semantics.objective.terms.size(),
               expected.semantics.objective.terms.size());
  ARF_CHECK_EQ(decoded->semantics.priorities.size(), expected.semantics.priorities.size());
  ARF_CHECK_EQ(decoded->semantics.hold_down.duration, expected.semantics.hold_down.duration);
  ARF_CHECK_EQ(decoded->semantics.semantics_version, expected.semantics.semantics_version);
}

void verify_update(std::string_view payload) {
  const auto decoded = UpdatePolicyMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const UpdatePolicyMessage expected = make_update(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->scope.render(), expected.scope.render());
  ARF_CHECK_EQ(decoded->semantics.render(), expected.semantics.render());
  ARF_CHECK_EQ(decoded->semantics.evidence.size(), expected.semantics.evidence.size());
  ARF_CHECK_EQ(decoded->semantics.churn.max_adaptations_per_window,
               expected.semantics.churn.max_adaptations_per_window);
}

void verify_lifecycle(std::string_view payload) {
  const auto decoded = PolicyLifecycleMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const PolicyLifecycleMessage expected = make_lifecycle(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->event, expected.event);
  ARF_CHECK_EQ(decoded->detail, expected.detail);
}

void verify_revoke(std::string_view payload) {
  const auto decoded = RevokePolicyMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const RevokePolicyMessage expected = make_revoke(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->reason, expected.reason);
  ARF_CHECK_EQ(decoded->detail, expected.detail);
}

void verify_upstream(std::string_view payload) {
  const auto decoded = UpstreamNotifyMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const UpstreamNotifyMessage expected = make_upstream(WireVariant::CANONICAL);
  ARF_REQUIRE(decoded->notifications.size() == expected.notifications.size());
  for (std::size_t index = 0; index < expected.notifications.size(); ++index) {
    const UpstreamNotification& actual = decoded->notifications[index];
    const UpstreamNotification& want = expected.notifications[index];
    ARF_CHECK_EQ(actual.event, want.event);
    ARF_CHECK_EQ(actual.policy, want.policy);
    ARF_CHECK_EQ(actual.binding.render(), want.binding.render());
    ARF_CHECK_EQ(actual.provenance.publisher, want.provenance.publisher);
    ARF_CHECK_EQ(actual.provenance.worker_boot, want.provenance.worker_boot);
    ARF_CHECK_EQ(actual.provenance.epoch, want.provenance.epoch);
    ARF_CHECK_EQ(actual.provenance.attempt, want.provenance.attempt);
    ARF_CHECK_EQ(actual.provenance.origin, want.provenance.origin);
    ARF_CHECK_EQ(actual.expected_previous_generation.has_value(),
                 want.expected_previous_generation.has_value());
    if (want.expected_previous_generation.has_value()) {
      ARF_CHECK_EQ(*actual.expected_previous_generation, *want.expected_previous_generation);
    }
  }
  const CandidateBinding& binding = decoded->notifications.front().binding;
  ARF_CHECK(binding.multipath.has_value());
  ARF_CHECK(binding.weighted.has_value());
  ARF_CHECK_EQ(binding.multipath->set, MultipathSetId::require("set-1"));
  ARF_CHECK_EQ(binding.multipath->members.size(), static_cast<std::size_t>(2));
  ARF_CHECK_EQ(binding.route.site, SiteId::require("site-a"));
  ARF_CHECK_EQ(binding.path_class, PathClass::require("gold"));
}

void verify_publish(std::string_view payload) {
  const auto decoded = PublishEvidenceMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const PublishEvidenceMessage expected = make_publish(WireVariant::CANONICAL);
  ARF_REQUIRE(decoded->publications.size() == expected.publications.size());
  for (std::size_t index = 0; index < expected.publications.size(); ++index) {
    const EvidencePublication& actual = decoded->publications[index];
    const EvidencePublication& want = expected.publications[index];
    ARF_CHECK_EQ(actual.source, want.source);
    ARF_CHECK_EQ(actual.source_generation, want.source_generation);
    ARF_CHECK_EQ(actual.quality, want.quality);
    ARF_CHECK_EQ(actual.path, want.path);
    ARF_CHECK_EQ(actual.value.kind(), want.value.kind());
    ARF_CHECK_EQ(actual.value.unit(), want.value.unit());
    ARF_CHECK_EQ(actual.value.value(), want.value.value());
    ARF_CHECK_EQ(actual.value.semantics_version(), want.value.semantics_version());
    ARF_CHECK_EQ(actual.observation_sequence, want.observation_sequence);
  }
}

void verify_evaluate(std::string_view payload) {
  const auto decoded = EvaluateMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const EvaluateMessage expected = make_evaluate(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->defer_commit, expected.defer_commit);
}

void verify_commit(std::string_view payload) {
  const auto decoded = CommitDecisionMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const CommitDecisionMessage expected = make_commit(WireVariant::CANONICAL);
  const EvaluationTicket& actual = decoded->ticket;
  const EvaluationTicket& want = expected.ticket;
  ARF_CHECK_EQ(actual.dependencies.render(), want.dependencies.render());
  ARF_CHECK_EQ(actual.dependencies.candidate_path_authority.size(),
               want.dependencies.candidate_path_authority.size());
  ARF_CHECK_EQ(actual.dependencies.candidate_path_watermarks.size(),
               want.dependencies.candidate_path_watermarks.size());
  ARF_CHECK_EQ(actual.dependencies.candidates.size(), want.dependencies.candidates.size());
  ARF_CHECK_EQ(actual.lifecycle, want.lifecycle);
  ARF_CHECK_EQ(actual.decision, want.decision);
  ARF_CHECK_EQ(actual.evidence_snapshot, want.evidence_snapshot);
  ARF_CHECK_EQ(actual.outcome, want.outcome);
  ARF_CHECK_EQ(actual.suppression, want.suppression);
  ARF_CHECK_EQ(actual.detail, want.detail);
  ARF_CHECK_EQ(actual.current_preference, want.current_preference);
  ARF_CHECK_EQ(actual.target_preference, want.target_preference);
  ARF_CHECK_EQ(actual.target_path_authority_generation, want.target_path_authority_generation);
  ARF_CHECK_EQ(actual.adaptation_generation, want.adaptation_generation);
  ARF_CHECK_EQ(actual.transition_generation, want.transition_generation);
  ARF_CHECK(actual.target_score.has_value() && want.target_score.has_value());
  ARF_CHECK_EQ(*actual.target_score, *want.target_score);
  ARF_CHECK(actual.improvement_bps.has_value() && want.improvement_bps.has_value());
  ARF_CHECK_EQ(*actual.improvement_bps, *want.improvement_bps);
  ARF_CHECK_EQ(actual.required_improvement_bps, want.required_improvement_bps);
  ARF_CHECK_EQ(actual.weight_proposal.has_value(), want.weight_proposal.has_value());
  ARF_REQUIRE(actual.weight_proposal.has_value());
  ARF_CHECK_EQ(actual.weight_proposal->set, want.weight_proposal->set);
  ARF_CHECK_EQ(actual.weight_proposal->base_generation, want.weight_proposal->base_generation);
  ARF_REQUIRE(actual.weight_proposal->weights.size() == want.weight_proposal->weights.size());
  ARF_CHECK_EQ(actual.weight_proposal->weights.front().path,
               want.weight_proposal->weights.front().path);
  ARF_CHECK_EQ(actual.weight_proposal->weights.front().weight_bps,
               want.weight_proposal->weights.front().weight_bps);
  ARF_CHECK_EQ(actual.rollback, want.rollback);
  ARF_CHECK_EQ(actual.emergency, want.emergency);
  ARF_REQUIRE(actual.ranking.size() == want.ranking.size());
  ARF_REQUIRE(!actual.ranking.empty());
  const CandidateEvaluation& ranked = actual.ranking.front();
  ARF_CHECK_EQ(ranked.path, want.ranking.front().path);
  ARF_CHECK_EQ(ranked.eligible, want.ranking.front().eligible);
  ARF_CHECK_EQ(ranked.rejection, want.ranking.front().rejection);
  ARF_CHECK_EQ(ranked.rejection_outcome, want.ranking.front().rejection_outcome);
  ARF_CHECK_EQ(ranked.quality, want.ranking.front().quality);
  ARF_CHECK(ranked.score.has_value());
  ARF_CHECK_EQ(*ranked.score, *want.ranking.front().score);
  ARF_REQUIRE(ranked.metrics.size() == 1);
  ARF_CHECK_EQ(ranked.metrics.front().value(), want.ranking.front().metrics.front().value());
  ARF_CHECK_EQ(ranked.priority, want.ranking.front().priority);
  ARF_CHECK_EQ(ranked.current_preference, want.ranking.front().current_preference);
  ARF_CHECK_EQ(ranked.previous_preference, want.ranking.front().previous_preference);
  ARF_CHECK_EQ(ranked.required_improvement_bps, want.ranking.front().required_improvement_bps);
  ARF_CHECK(ranked.observed_improvement_bps.has_value());
  ARF_CHECK_EQ(*ranked.observed_improvement_bps, *want.ranking.front().observed_improvement_bps);
  ARF_CHECK_EQ(ranked.path_authority_generation, want.ranking.front().path_authority_generation);
  ARF_CHECK_EQ(ranked.route_generation, want.ranking.front().route_generation);
  ARF_CHECK_EQ(ranked.multipath_set_generation,
               want.ranking.front().multipath_set_generation);
  ARF_CHECK_EQ(actual.evaluated_at, want.evaluated_at);
}

void verify_revalidate(std::string_view payload) {
  const auto decoded = RevalidateMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const RevalidateMessage expected = make_revalidate(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->attempt, expected.attempt);
}

void verify_rollback(std::string_view payload) {
  const auto decoded = RollbackMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const RollbackMessage expected = make_rollback(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->reason, expected.reason);
}

void verify_query(std::string_view payload) {
  const auto decoded = QueryStateMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const QueryStateMessage expected = make_query(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->policy.valid(), expected.policy.valid());
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->limit, expected.limit);
}

void verify_snapshot_request(std::string_view payload) {
  const auto decoded = SnapshotRequestMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  ARF_CHECK_EQ(decoded->policy, AdaptivePolicyId::require("policy-1"));
}

void verify_snapshot_response(std::string_view payload) {
  const auto decoded = SnapshotResponseMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const SnapshotResponseMessage expected = make_snapshot_response(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->snapshot, expected.snapshot);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->digest, expected.digest);
  ARF_CHECK_EQ(decoded->rendered, expected.rendered);
}

void verify_explain(std::string_view payload) {
  const auto decoded = ExplainRequestMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const ExplainRequestMessage expected = make_explain(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->topic, expected.topic);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
}

void verify_diff(std::string_view payload) {
  const auto decoded = DiffRequestMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const DiffRequestMessage expected = make_diff(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->from, expected.from);
  ARF_CHECK_EQ(decoded->to, expected.to);
}

void verify_advance(std::string_view payload) {
  const auto decoded = AdvanceEpochMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  ARF_CHECK_EQ(decoded->reason, make_advance(WireVariant::CANONICAL).reason);
}

void verify_result(std::string_view payload) {
  const auto decoded = ResultMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const ResultMessage expected = make_result(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->outcome, expected.outcome);
  ARF_CHECK_EQ(decoded->suppression, expected.suppression);
  ARF_CHECK_EQ(decoded->detail, expected.detail);
  ARF_CHECK_EQ(decoded->policy, expected.policy);
  ARF_CHECK_EQ(decoded->policy_generation, expected.policy_generation);
  ARF_CHECK_EQ(decoded->decision, expected.decision);
  ARF_CHECK_EQ(decoded->adaptation_generation, expected.adaptation_generation);
  ARF_CHECK_EQ(decoded->transition_generation, expected.transition_generation);
  ARF_CHECK_EQ(decoded->evidence_generation, expected.evidence_generation);
  ARF_CHECK_EQ(decoded->epoch, expected.epoch);
  ARF_CHECK_EQ(decoded->rendered, expected.rendered);
}

void verify_error(std::string_view payload) {
  const auto decoded = ErrorMessage::decode(payload);
  ARF_REQUIRE(decoded.has_value());
  const ErrorMessage expected = make_error(WireVariant::CANONICAL);
  ARF_CHECK_EQ(decoded->outcome, expected.outcome);
  ARF_CHECK_EQ(decoded->detail, expected.detail);
}

// ---------------------------------------------------------------------------
// The message table
// ---------------------------------------------------------------------------

struct WireCase {
  const char* name;
  MessageId id;
  std::string (*payload)(WireVariant);
  bool (*accepts)(std::string_view);
  void (*verify)(std::string_view);
  // False when the message encoding has no field of that category at all, in
  // which case the mutation is not expressible and the variant must be
  // byte-identical to the canonical encoding.
  bool carries_enum;
  bool carries_generation;
};

// One entry per payload message. A message without an enum or a generation field
// cannot express that mutation; the shared element codecs are driven directly
// for those rejection paths below.
const std::vector<WireCase>& wire_cases() {
  static const std::vector<WireCase> cases = {
      {"HelloMessage", MessageId::HELLO,
       [](WireVariant variant) { return make_hello(variant).encode(); },
       [](std::string_view payload) { return HelloMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_hello(payload); }, false, true},
      {"RegisterPublisherMessage", MessageId::REGISTER_PUBLISHER,
       [](WireVariant variant) { return make_register(variant).encode(); },
       [](std::string_view payload) {
         return RegisterPublisherMessage::decode(payload).has_value();
       },
       [](std::string_view payload) { verify_register(payload); }, false, false},
      {"FenceNoticeMessage", MessageId::FENCE_NOTICE,
       [](WireVariant variant) { return make_fence(variant).encode(); },
       [](std::string_view payload) { return FenceNoticeMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_fence(payload); }, false, false},
      {"CreatePolicyMessage", MessageId::CREATE_POLICY,
       [](WireVariant variant) { return make_create(variant).encode(); },
       [](std::string_view payload) { return CreatePolicyMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_create(payload); }, true, false},
      {"UpdatePolicyMessage", MessageId::UPDATE_POLICY,
       [](WireVariant variant) { return make_update(variant).encode(); },
       [](std::string_view payload) { return UpdatePolicyMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_update(payload); }, true, false},
      {"PolicyLifecycleMessage", MessageId::POLICY_LIFECYCLE,
       [](WireVariant variant) { return make_lifecycle(variant).encode(); },
       [](std::string_view payload) {
         return PolicyLifecycleMessage::decode(payload).has_value();
       },
       [](std::string_view payload) { verify_lifecycle(payload); }, true, false},
      {"RevokePolicyMessage", MessageId::REVOKE_POLICY,
       [](WireVariant variant) { return make_revoke(variant).encode(); },
       [](std::string_view payload) { return RevokePolicyMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_revoke(payload); }, true, false},
      {"UpstreamNotifyMessage", MessageId::UPSTREAM_NOTIFY,
       [](WireVariant variant) { return make_upstream(variant).encode(); },
       [](std::string_view payload) { return UpstreamNotifyMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_upstream(payload); }, true, true},
      {"PublishEvidenceMessage", MessageId::PUBLISH_EVIDENCE,
       [](WireVariant variant) { return make_publish(variant).encode(); },
       [](std::string_view payload) {
         return PublishEvidenceMessage::decode(payload).has_value();
       },
       [](std::string_view payload) { verify_publish(payload); }, true, true},
      {"EvaluateMessage", MessageId::EVALUATE,
       [](WireVariant variant) { return make_evaluate(variant).encode(); },
       [](std::string_view payload) { return EvaluateMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_evaluate(payload); }, false, false},
      {"CommitDecisionMessage", MessageId::COMMIT_DECISION,
       [](WireVariant variant) { return make_commit(variant).encode(); },
       [](std::string_view payload) { return CommitDecisionMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_commit(payload); }, true, true},
      {"RevalidateMessage", MessageId::REVALIDATE,
       [](WireVariant variant) { return make_revalidate(variant).encode(); },
       [](std::string_view payload) { return RevalidateMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_revalidate(payload); }, false, false},
      {"RollbackMessage", MessageId::ROLLBACK,
       [](WireVariant variant) { return make_rollback(variant).encode(); },
       [](std::string_view payload) { return RollbackMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_rollback(payload); }, false, false},
      {"QueryStateMessage", MessageId::QUERY_STATE,
       [](WireVariant variant) { return make_query(variant).encode(); },
       [](std::string_view payload) { return QueryStateMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_query(payload); }, false, false},
      {"SnapshotRequestMessage", MessageId::SNAPSHOT_REQUEST,
       [](WireVariant variant) { return make_snapshot_request(variant).encode(); },
       [](std::string_view payload) {
         return SnapshotRequestMessage::decode(payload).has_value();
       },
       [](std::string_view payload) { verify_snapshot_request(payload); }, false, false},
      {"SnapshotResponseMessage", MessageId::SNAPSHOT_RESPONSE,
       [](WireVariant variant) { return make_snapshot_response(variant).encode(); },
       [](std::string_view payload) {
         return SnapshotResponseMessage::decode(payload).has_value();
       },
       [](std::string_view payload) { verify_snapshot_response(payload); }, false, false},
      {"ExplainRequestMessage", MessageId::EXPLAIN_REQUEST,
       [](WireVariant variant) { return make_explain(variant).encode(); },
       [](std::string_view payload) { return ExplainRequestMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_explain(payload); }, true, false},
      {"DiffRequestMessage", MessageId::DIFF_REQUEST,
       [](WireVariant variant) { return make_diff(variant).encode(); },
       [](std::string_view payload) { return DiffRequestMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_diff(payload); }, false, false},
      {"AdvanceEpochMessage", MessageId::ADVANCE_EPOCH,
       [](WireVariant variant) { return make_advance(variant).encode(); },
       [](std::string_view payload) { return AdvanceEpochMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_advance(payload); }, false, false},
      {"ResultMessage", MessageId::RESULT,
       [](WireVariant variant) { return make_result(variant).encode(); },
       [](std::string_view payload) { return ResultMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_result(payload); }, true, true},
      {"ErrorMessage", MessageId::ERROR,
       [](WireVariant variant) { return make_error(variant).encode(); },
       [](std::string_view payload) { return ErrorMessage::decode(payload).has_value(); },
       [](std::string_view payload) { verify_error(payload); }, true, false},
  };
  return cases;
}

// ---------------------------------------------------------------------------
// Payload tests
// ---------------------------------------------------------------------------

ARF_TEST(wire_every_payload_message_round_trips) {
  ARF_CHECK_EQ(wire_cases().size(), static_cast<std::size_t>(21));
  for (const WireCase& entry : wire_cases()) {
    const std::string payload = entry.payload(WireVariant::CANONICAL);
    ARF_CHECK_MSG(entry.accepts(payload), std::string(entry.name) + " did not decode");
    entry.verify(payload);
    // Re-encoding a decoded value reproduces the bytes exactly, so no field can
    // survive a decode in a half-restored state.
    const std::string reencoded = entry.payload(WireVariant::CANONICAL);
    ARF_CHECK_EQ(reencoded, payload);
  }
}

ARF_TEST(wire_every_payload_decode_rejects_a_truncated_or_padded_buffer) {
  for (const WireCase& entry : wire_cases()) {
    const std::string payload = entry.payload(WireVariant::CANONICAL);
    ARF_REQUIRE(!payload.empty());

    // Truncation removes the final field, which is never optional.
    const std::string truncated = payload.substr(0, payload.size() - 1);
    ARF_CHECK_MSG(!entry.accepts(truncated), std::string(entry.name) + " accepted a truncation");

    // A decoder that stops at the last field it knows would accept anything
    // appended after it; a trailing byte is a protocol error instead.
    std::string padded = payload;
    padded.push_back('\0');
    ARF_CHECK_MSG(!entry.accepts(padded), std::string(entry.name) + " accepted a trailing byte");

    std::string padded_one = payload;
    padded_one.push_back(static_cast<char>(0xFF));
    ARF_CHECK_MSG(!entry.accepts(padded_one),
                  std::string(entry.name) + " accepted a trailing 0xFF byte");
  }
}

ARF_TEST(wire_every_payload_decode_rejects_an_unknown_enum) {
  for (const WireCase& entry : wire_cases()) {
    const std::string canonical = entry.payload(WireVariant::CANONICAL);
    const std::string variant = entry.payload(WireVariant::ENUM);
    if (!entry.carries_enum) {
      // The encoding has no enum field, so the two variants must be identical
      // and there is nothing to mutate; the shared element codecs cover the
      // enum validation those messages rely on.
      ARF_CHECK_MSG(canonical == variant,
                    std::string(entry.name) + " has no enum and yet the variants differ");
      continue;
    }
    const std::vector<std::size_t> offsets = differing_offsets(canonical, variant);
    ARF_CHECK_MSG(!offsets.empty(), std::string(entry.name) + " enum variant is identical");
    // The encoder writes fields in decode order, so the first differing byte is
    // the first enum the decoder reads. 0x7F is outside every enum domain.
    for (const std::size_t offset : offsets) {
      std::string mutated = canonical;
      mutated[offset] = static_cast<char>(0x7F);
      ARF_CHECK_MSG(!entry.accepts(mutated),
                    std::string(entry.name) + " accepted the unknown enum at offset " +
                        std::to_string(offset));
    }
  }
}

ARF_TEST(wire_every_payload_decode_rejects_a_zero_generation) {
  for (const WireCase& entry : wire_cases()) {
    const std::string canonical = entry.payload(WireVariant::CANONICAL);
    const std::string variant = entry.payload(WireVariant::GENERATION);
    if (!entry.carries_generation) {
      ARF_CHECK_MSG(canonical == variant,
                    std::string(entry.name) + " has no generation and yet the variants differ");
      continue;
    }
    const std::vector<std::size_t> offsets = differing_offsets(canonical, variant);
    ARF_CHECK_MSG(!offsets.empty(),
                  std::string(entry.name) + " generation variant is identical");
    // The canonical value is 1 and the variant is 2, so clearing the differing
    // byte is exactly a zero generation.
    for (const std::size_t offset : offsets) {
      std::string mutated = canonical;
      mutated[offset] = static_cast<char>(0x00);
      ARF_CHECK_MSG(!entry.accepts(mutated),
                    std::string(entry.name) + " accepted the zero generation at offset " +
                        std::to_string(offset));
    }
  }
}

// ---------------------------------------------------------------------------
// Shared element codecs
// ---------------------------------------------------------------------------

ARF_TEST(wire_ticket_with_a_weight_proposal_round_trips) {
  // A decision ticket carries the weight proposal it computed, and the proposal
  // is a proposal: the coordinator re-verifies it. It must therefore survive the
  // round trip field for field. The ticket is encoded as (path, weight_bps) per
  // weight, and this test fails if the decoder reads those two in the other
  // order -- a silently reordered proposal is a silently altered routing intent.
  EvaluationTicket ticket = wire_ticket(WireVariant::CANONICAL);
  WeightProposal proposal;
  proposal.set = WeightedPathSetId::require("weighted-1");
  proposal.base_generation = WeightPolicyGeneration::require(4);
  PathWeight first;
  first.path = PathId::require("path-b");
  first.weight_bps = basis_points_scale;
  proposal.weights.push_back(first);
  PathWeight second;
  second.path = PathId::require("path-c");
  second.weight_bps = 0;
  proposal.weights.push_back(second);
  ticket.weight_proposal = proposal;

  ByteWriter writer;
  encode_ticket(writer, ticket);
  const std::string bytes = writer.take();
  ARF_CHECK(!bytes.empty());
  ByteReader reader(bytes);
  const auto decoded = decode_ticket(reader);
  ARF_REQUIRE_MSG(decoded.has_value(),
                  "a decision ticket that carries a weight proposal did not decode");
  ARF_REQUIRE(decoded->weight_proposal.has_value());
  ARF_CHECK_EQ(decoded->weight_proposal->set, proposal.set);
  ARF_CHECK_EQ(decoded->weight_proposal->base_generation, proposal.base_generation);
  ARF_REQUIRE(decoded->weight_proposal->weights.size() == proposal.weights.size());
  for (std::size_t index = 0; index < proposal.weights.size(); ++index) {
    ARF_CHECK_EQ(decoded->weight_proposal->weights[index].path, proposal.weights[index].path);
    ARF_CHECK_EQ(decoded->weight_proposal->weights[index].weight_bps,
                 proposal.weights[index].weight_bps);
  }
  // Every other field of the ticket is unchanged by the presence of a proposal.
  ARF_CHECK_EQ(decoded->detail, ticket.detail);
  ARF_CHECK_EQ(decoded->lifecycle, ticket.lifecycle);
  ARF_CHECK_EQ(decoded->evaluated_at, ticket.evaluated_at);
}

ARF_TEST(wire_policy_candidate_priorities_round_trip) {
  // A policy's explicit candidate priorities are part of its semantics and are
  // the first ranking key of a decision, so the vector must survive the wire
  // exactly. Each entry is encoded as (identity, integer); a decoder that reads
  // the integer first turns the identity length prefix into a priority and
  // corrupts every entry, which is why this is driven on its own.
  PolicySemantics semantics = wire_semantics(WireVariant::CANONICAL);
  semantics.priorities.clear();
  CandidatePriority first;
  first.path = PathId::require("path-a");
  first.priority = 7;
  semantics.priorities.push_back(first);
  CandidatePriority second;
  second.path = PathId::require("path-b");
  second.priority = 3;
  semantics.priorities.push_back(second);
  std::string reason;
  ARF_CHECK_MSG(semantics.valid(&reason), reason);

  CreatePolicyMessage message = make_create(WireVariant::CANONICAL);
  message.semantics = semantics;
  const std::string payload = message.encode();
  const auto decoded = CreatePolicyMessage::decode(payload);
  ARF_REQUIRE_MSG(decoded.has_value(),
                  "a policy that carries candidate priorities did not decode");
  ARF_REQUIRE(decoded->semantics.priorities.size() == semantics.priorities.size());
  for (std::size_t index = 0; index < semantics.priorities.size(); ++index) {
    ARF_CHECK_EQ(decoded->semantics.priorities[index].path, semantics.priorities[index].path);
    ARF_CHECK_EQ(decoded->semantics.priorities[index].priority,
                 semantics.priorities[index].priority);
  }
  ARF_CHECK_EQ(decoded->semantics.render(), semantics.render());
}

ARF_TEST(wire_shared_element_codecs_validate_enums_and_generations) {
  // decode_metric: an unknown kind, an unknown unit, and a unit that does not
  // match the kind are all rejected.
  auto metric_payload = [](std::uint8_t kind, std::uint8_t unit) {
    ByteWriter writer;
    writer.put_bool(true);
    writer.put_u8(kind);
    writer.put_u8(unit);
    writer.put_u32(1);
    writer.put_i64(1500);
    return writer.take();
  };
  {
    const std::string payload = metric_payload(static_cast<std::uint8_t>(MetricKind::PATH_LATENCY),
                                               static_cast<std::uint8_t>(MetricUnit::MICROSECONDS));
    ByteReader reader(payload);
    ARF_CHECK(decode_metric(reader).has_value());
  }
  {
    const std::string payload = metric_payload(11, static_cast<std::uint8_t>(MetricUnit::MICROSECONDS));
    ByteReader reader(payload);
    ARF_CHECK(!decode_metric(reader).has_value());
  }
  {
    const std::string payload = metric_payload(static_cast<std::uint8_t>(MetricKind::PATH_LATENCY), 6);
    ByteReader reader(payload);
    ARF_CHECK(!decode_metric(reader).has_value());
  }
  {
    // BASIS_POINTS is not the unit of PATH_LATENCY, so the value is rejected
    // rather than reinterpreted.
    const std::string payload =
        metric_payload(static_cast<std::uint8_t>(MetricKind::PATH_LATENCY),
                       static_cast<std::uint8_t>(MetricUnit::BASIS_POINTS));
    ByteReader reader(payload);
    ARF_CHECK(!decode_metric(reader).has_value());
  }
  {
    const std::string payload = metric_payload(static_cast<std::uint8_t>(MetricKind::PATH_LATENCY), 0);
    ByteReader reader(payload);
    ARF_CHECK(!decode_metric(reader).has_value());
  }

  // decode_context: a zero epoch and a zero expected generation are rejected.
  {
    MutationContext context;
    context.epoch = CoordinatorEpoch::require(4);
    context.publisher = PublisherId::require("publisher-a");
    context.worker_boot = WorkerBootId::require("boot-a1");
    context.session = SessionId::require("session-a1");
    context.attempt = MutationAttemptId::require("attempt-1");
    context.expected_policy_generation = AdaptivePolicyGeneration::require(2);
    ByteWriter writer;
    encode_context(writer, context);
    ByteReader reader(writer.buffer());
    const auto decoded = decode_context(reader);
    ARF_REQUIRE(decoded.has_value());
    ARF_CHECK_EQ(decoded->epoch, context.epoch);
    ARF_CHECK_EQ(decoded->publisher, context.publisher);
    ARF_CHECK(decoded->expected_policy_generation.has_value());
    ARF_CHECK_EQ(*decoded->expected_policy_generation, *context.expected_policy_generation);
  }
  {
    ByteWriter writer;
    writer.put_u64(0);  // epoch zero
    writer.put_string("publisher-a");
    writer.put_string("boot-a1");
    writer.put_string("session-a1");
    writer.put_string("attempt-1");
    writer.put_bool(false);
    writer.put_bool(false);
    ByteReader reader(writer.buffer());
    ARF_CHECK(!decode_context(reader).has_value());
  }

  // decode_requirement: an unknown aggregation and an unknown quality class.
  {
    EvidenceRequirement requirement;
    requirement.kind = MetricKind::PATH_LATENCY;
    requirement.aggregation = AggregationKind::MEAN;
    requirement.ewma_alpha_bps = 0;
    requirement.min_samples = 2;
    requirement.max_age = seconds(90);
    requirement.min_window = seconds(5);
    requirement.min_quality = EvidenceQuality::AGGREGATED;
    requirement.required = true;
    ByteWriter writer;
    encode_requirement(writer, requirement);
    ByteReader reader(writer.buffer());
    const auto decoded = decode_requirement(reader);
    ARF_REQUIRE(decoded.has_value());
    ARF_CHECK_EQ(decoded->kind, requirement.kind);
    ARF_CHECK_EQ(decoded->aggregation, requirement.aggregation);
    ARF_CHECK_EQ(decoded->max_age, requirement.max_age);
  }
  for (const unsigned int aggregation : {0U, 7U, 0xFFU}) {
    ByteWriter writer;
    writer.put_u8(static_cast<std::uint8_t>(MetricKind::PATH_LATENCY));
    writer.put_u8(static_cast<std::uint8_t>(aggregation));
    writer.put_u32(0);
    writer.put_u32(1);
    writer.put_u64(1000);
    writer.put_u64(0);
    writer.put_u8(static_cast<std::uint8_t>(EvidenceQuality::AGGREGATED));
    writer.put_bool(true);
    ByteReader reader(writer.buffer());
    ARF_CHECK(!decode_requirement(reader).has_value());
  }

  // decode_publication: a zero source generation and an unknown quality.
  {
    const EvidencePublication publication = wire_publication(
        WireVariant::CANONICAL, "telemetry-1", "path-a", MetricKind::PATH_LATENCY, 1500, 1);
    ByteWriter writer;
    encode_publication(writer, publication);
    ByteReader reader(writer.buffer());
    ARF_CHECK(decode_publication(reader).has_value());
  }
  {
    ByteWriter writer;
    writer.put_string("telemetry-1");
    writer.put_u64(0);  // source generation zero
    writer.put_u8(static_cast<std::uint8_t>(EvidenceQuality::AGGREGATED));
    writer.put_string("path-a");
    writer.put_bool(true);
    writer.put_u8(static_cast<std::uint8_t>(MetricKind::PATH_LATENCY));
    writer.put_u8(static_cast<std::uint8_t>(MetricUnit::MICROSECONDS));
    writer.put_u32(1);
    writer.put_i64(1500);
    writer.put_u64(1);
    ByteReader reader(writer.buffer());
    ARF_CHECK(!decode_publication(reader).has_value());
  }
  {
    ByteWriter writer;
    writer.put_string("telemetry-1");
    writer.put_u64(1);
    writer.put_u8(9);  // unknown quality class
    writer.put_string("path-a");
    writer.put_bool(true);
    writer.put_u8(static_cast<std::uint8_t>(MetricKind::PATH_LATENCY));
    writer.put_u8(static_cast<std::uint8_t>(MetricUnit::MICROSECONDS));
    writer.put_u32(1);
    writer.put_i64(1500);
    writer.put_u64(1);
    ByteReader reader(writer.buffer());
    ARF_CHECK(!decode_publication(reader).has_value());
  }

  // decode_notification: an unknown upstream event.
  {
    UpstreamNotification notification = wire_notification(WireVariant::CANONICAL);
    ByteWriter writer;
    encode_notification(writer, notification);
    ByteReader reader(writer.buffer());
    ARF_CHECK(decode_notification(reader).has_value());
  }
  {
    UpstreamNotification notification = wire_notification(WireVariant::CANONICAL);
    ByteWriter writer;
    encode_notification(writer, notification);
    std::string bytes = writer.take();
    bytes[0] = static_cast<char>(0x7F);  // the event byte is written first
    ByteReader reader(bytes);
    ARF_CHECK(!decode_notification(reader).has_value());
  }

  // decode_binding: a zero path authority generation.
  {
    CandidateBinding binding = wire_binding(WireVariant::CANONICAL);
    ByteWriter writer;
    encode_binding(writer, binding);
    ByteReader reader(writer.buffer());
    ARF_CHECK(decode_binding(reader).has_value());
  }
  {
    CandidateBinding binding = wire_binding(WireVariant::CANONICAL);
    binding.path_authority.generation = PathAuthorityGeneration();
    ByteWriter writer;
    encode_binding(writer, binding);
    ByteReader reader(writer.buffer());
    ARF_CHECK(!decode_binding(reader).has_value());
  }

  // decode_scope: a route whose declared length exceeds the wire bound.
  {
    ByteWriter writer;
    writer.put_string(arf_test::fabric_id().view());
    writer.put_string(arf_test::routing_namespace().view());
    writer.put_bool(false);
    writer.put_bool(false);
    writer.put_u64(1);
    writer.put_u64(0xFFFFFFFFULL);  // absurd route identity length
    ByteReader reader(writer.buffer());
    ARF_CHECK(!decode_scope(reader).has_value());
  }
}

ARF_TEST(wire_declared_string_length_beyond_the_bound_costs_nothing) {
  // A declared length beyond the bound is rejected before a byte is allocated or
  // consumed, so an absurd declaration is free. The loop below only completes if
  // that is true.
  ByteWriter writer;
  writer.put_u64(0xFFFFFFFFULL);
  const std::string absurd = writer.take();
  ARF_CHECK(absurd.size() < wire_max_string_bytes);

  {
    ByteReader reader(absurd);
    ARF_CHECK(!reader.get_string(wire_max_string_bytes).has_value());
    ARF_CHECK_EQ(reader.offset(), static_cast<std::size_t>(8));
    ARF_CHECK_EQ(reader.remaining(), static_cast<std::size_t>(0));
  }

  std::uint64_t rejections = 0;
  for (std::uint64_t attempt = 0; attempt < 200000; ++attempt) {
    if (!AdvanceEpochMessage::decode(absurd).has_value()) {
      ++rejections;
    }
  }
  ARF_CHECK_EQ(rejections, 200000ULL);

  // The bound is inclusive: a string of exactly the bound is accepted and one
  // byte more is rejected.
  AdvanceEpochMessage at_bound;
  at_bound.reason = std::string(static_cast<std::size_t>(wire_max_string_bytes), 'r');
  ARF_CHECK(AdvanceEpochMessage::decode(at_bound.encode()).has_value());

  AdvanceEpochMessage over_bound;
  over_bound.reason = std::string(static_cast<std::size_t>(wire_max_string_bytes) + 1U, 'r');
  ARF_CHECK(!AdvanceEpochMessage::decode(over_bound.encode()).has_value());

  // A vector count beyond the element bound is rejected the same way.
  ByteWriter count_writer;
  count_writer.put_u64(wire_max_elements + 1U);
  ARF_CHECK(!UpstreamNotifyMessage::decode(count_writer.buffer()).has_value());
  ByteWriter at_bound_writer;
  at_bound_writer.put_u64(wire_max_elements);
  ARF_CHECK(!UpstreamNotifyMessage::decode(at_bound_writer.buffer()).has_value());
}

// ---------------------------------------------------------------------------
// Message identifiers
// ---------------------------------------------------------------------------

ARF_TEST(wire_message_ids_are_the_documented_stable_numbers) {
  struct Expected {
    MessageId id;
    std::uint16_t value;
  };
  const std::vector<Expected> expected = {
      {MessageId::HELLO, 1},
      {MessageId::HELLO_ACK, 2},
      {MessageId::REGISTER_PUBLISHER, 3},
      {MessageId::FENCE_NOTICE, 4},
      {MessageId::CREATE_POLICY, 5},
      {MessageId::UPDATE_POLICY, 6},
      {MessageId::POLICY_LIFECYCLE, 7},
      {MessageId::REVOKE_POLICY, 8},
      {MessageId::UPSTREAM_NOTIFY, 9},
      {MessageId::PUBLISH_EVIDENCE, 10},
      {MessageId::EVALUATE, 11},
      {MessageId::COMMIT_DECISION, 12},
      {MessageId::REVALIDATE, 13},
      {MessageId::ROLLBACK, 14},
      {MessageId::QUERY_STATE, 15},
      {MessageId::SNAPSHOT_REQUEST, 16},
      {MessageId::SNAPSHOT_RESPONSE, 17},
      {MessageId::EXPLAIN_REQUEST, 18},
      {MessageId::DIFF_REQUEST, 19},
      {MessageId::ADVANCE_EPOCH, 20},
      {MessageId::RESULT, 21},
      {MessageId::ERROR, 22},
      {MessageId::BYE, 23},
  };
  std::set<std::uint16_t> values;
  for (const Expected& entry : expected) {
    const std::uint16_t raw = static_cast<std::uint16_t>(entry.id);
    ARF_CHECK_EQ(raw, entry.value);
    ARF_CHECK_MSG(values.insert(raw).second,
                  "message id " + std::to_string(raw) + " is not unique");
    ARF_CHECK(valid_message_id(raw));
    // The stable textual name parses back to exactly the same identifier, so a
    // name can never drift away from its number.
    const auto parsed = parse_message_id(to_string(entry.id));
    ARF_CHECK(parsed.has_value());
    ARF_CHECK_EQ(*parsed, entry.id);
    ARF_CHECK_EQ(to_string(*parsed), to_string(entry.id));
  }
  // The set is exactly the documented range: no hole and no value beyond it.
  ARF_CHECK_EQ(values.size(), expected.size());
  ARF_CHECK_EQ(*values.begin(), static_cast<std::uint16_t>(1));
  ARF_CHECK_EQ(*values.rbegin(), static_cast<std::uint16_t>(23));
  ARF_CHECK(!valid_message_id(0));
  ARF_CHECK(!valid_message_id(24));
  ARF_CHECK(!parse_message_id("NOT_A_MESSAGE").has_value());
}

// Every wire case must name a message id the protocol declares, and the table
// must not name the same message twice.
ARF_TEST(wire_case_table_is_consistent) {
  std::set<std::uint16_t> ids;
  for (const WireCase& entry : wire_cases()) {
    ARF_CHECK(valid_message_id(static_cast<std::uint16_t>(entry.id)));
    ARF_CHECK_MSG(ids.insert(static_cast<std::uint16_t>(entry.id)).second,
                  std::string(entry.name) + " is listed twice");
    ARF_CHECK_MSG(entry.payload(WireVariant::CANONICAL).size() > 0,
                  std::string(entry.name) + " encodes to an empty payload");
  }
}

}  // namespace

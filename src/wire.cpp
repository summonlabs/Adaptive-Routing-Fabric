// Framed wire protocol: framing, integrity and payload codecs.
//
// ENCODING RULES
// --------------
//   * every integer is little-endian and written through ByteWriter;
//   * every enum travels as its explicit numeric value and is validated with the
//     matching valid_*() predicate before it is used;
//   * every identity is a length-prefixed string that must satisfy the charset
//     of its own domain, so a PathId can never be decoded into a RouteId;
//   * every generation must be non-zero; watermarks may be zero;
//   * every vector and every string is bounded before allocation;
//   * a decode that does not consume the whole payload is a trailing-byte
//     rejection.
#include "adaptive_routing/wire.hpp"

#include <algorithm>
#include <cstring>

namespace adaptive_routing {
namespace {

constexpr std::uint64_t fnv_prime = 1099511628211ULL;
constexpr std::uint64_t fnv_offset_a = 14695981039346656037ULL;
constexpr std::uint64_t fnv_offset_b = 0x9E3779B97F4A7C15ULL;

[[nodiscard]] std::uint64_t integrity_of(std::string_view header_and_payload) noexcept {
  std::uint64_t low = fnv_offset_a;
  std::uint64_t high = fnv_offset_b;
  for (const char character : header_and_payload) {
    const auto byte = static_cast<std::uint8_t>(static_cast<unsigned char>(character));
    low ^= byte;
    low *= fnv_prime;
    high += byte;
    high ^= (high << 13);
    high *= fnv_prime;
  }
  return low ^ high;
}

[[nodiscard]] bool read_u32(std::string_view bytes, std::size_t offset,
                            std::uint32_t& out) noexcept {
  if (offset + 4 > bytes.size()) {
    return false;
  }
  std::uint32_t value = 0;
  for (int index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(
                 static_cast<unsigned char>(bytes[offset + static_cast<std::size_t>(index)]))
             << (8 * index);
  }
  out = value;
  return true;
}

[[nodiscard]] bool read_u16(std::string_view bytes, std::size_t offset,
                            std::uint16_t& out) noexcept {
  if (offset + 2 > bytes.size()) {
    return false;
  }
  std::uint16_t value = 0;
  for (int index = 0; index < 2; ++index) {
    value |= static_cast<std::uint16_t>(
                 static_cast<unsigned char>(bytes[offset + static_cast<std::size_t>(index)]))
             << (8 * index);
  }
  out = value;
  return true;
}

[[nodiscard]] bool read_u64(std::string_view bytes, std::size_t offset,
                            std::uint64_t& out) noexcept {
  if (offset + 8 > bytes.size()) {
    return false;
  }
  std::uint64_t value = 0;
  for (int index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(
                 static_cast<unsigned char>(bytes[offset + static_cast<std::size_t>(index)]))
             << (8 * index);
  }
  out = value;
  return true;
}

void write_u32_at(std::string& bytes, std::size_t offset, std::uint32_t value) {
  for (int index = 0; index < 4; ++index) {
    bytes[offset + static_cast<std::size_t>(index)] =
        static_cast<char>(static_cast<unsigned char>((value >> (8 * index)) & 0xFFU));
  }
}

void write_u16_at(std::string& bytes, std::size_t offset, std::uint16_t value) {
  for (int index = 0; index < 2; ++index) {
    bytes[offset + static_cast<std::size_t>(index)] =
        static_cast<char>(static_cast<unsigned char>((value >> (8 * index)) & 0xFFU));
  }
}

void write_u64_at(std::string& bytes, std::size_t offset, std::uint64_t value) {
  for (int index = 0; index < 8; ++index) {
    bytes[offset + static_cast<std::size_t>(index)] =
        static_cast<char>(static_cast<unsigned char>((value >> (8 * index)) & 0xFFU));
  }
}

// ---------------------------------------------------------------------------
// Element helpers
// ---------------------------------------------------------------------------

template <class Strong>
void put_id(ByteWriter& writer, const Strong& id) {
  writer.put_string(id.view());
}

template <class Strong>
[[nodiscard]] bool get_id(ByteReader& reader, Strong& out) {
  const auto text = reader.get_string(wire_max_string_bytes);
  if (!text.has_value()) {
    return false;
  }
  const auto parsed = Strong::parse(*text);
  if (!parsed.has_value()) {
    return false;
  }
  out = *parsed;
  return true;
}

template <class Strong>
void put_optional_id(ByteWriter& writer, const Strong& id) {
  writer.put_bool(id.valid());
  if (id.valid()) {
    put_id(writer, id);
  }
}

template <class Strong>
[[nodiscard]] bool get_optional_id(ByteReader& reader, Strong& out) {
  const auto present = reader.get_bool();
  if (!present.has_value()) {
    return false;
  }
  if (!*present) {
    out = Strong();
    return true;
  }
  return get_id(reader, out);
}

// Overloads for the std::optional form used by structure members such as the
// optional site and multipath set of a policy scope.
template <class Strong>
void put_optional_id(ByteWriter& writer, const std::optional<Strong>& id) {
  writer.put_bool(id.has_value());
  if (id.has_value()) {
    put_id(writer, *id);
  }
}

template <class Strong>
[[nodiscard]] bool get_optional_id(ByteReader& reader, std::optional<Strong>& out) {
  const auto present = reader.get_bool();
  if (!present.has_value()) {
    return false;
  }
  if (!*present) {
    out.reset();
    return true;
  }
  Strong value;
  if (!get_id(reader, value)) {
    return false;
  }
  out = value;
  return true;
}

template <class Gen>
void put_generation(ByteWriter& writer, const Gen& generation) {
  writer.put_u64(generation.value());
}

template <class Gen>
[[nodiscard]] bool get_generation(ByteReader& reader, Gen& out) {
  const auto raw = reader.get_u64();
  if (!raw.has_value()) {
    return false;
  }
  const auto parsed = Gen::from_value(*raw);
  if (!parsed.has_value()) {
    return false;
  }
  out = *parsed;
  return true;
}

// Generations that are informational rather than authoritative may be absent;
// they travel with an explicit presence flag.
template <class Gen>
void put_optional_generation(ByteWriter& writer, const Gen& generation) {
  writer.put_bool(generation.valid());
  if (generation.valid()) {
    writer.put_u64(generation.value());
  }
}

template <class Gen>
[[nodiscard]] bool get_optional_generation(ByteReader& reader, Gen& out) {
  const auto present = reader.get_bool();
  if (!present.has_value()) {
    return false;
  }
  if (!*present) {
    out = Gen();
    return true;
  }
  const auto raw = reader.get_u64();
  if (!raw.has_value()) {
    return false;
  }
  const auto parsed = Gen::from_value(*raw);
  if (!parsed.has_value()) {
    return false;
  }
  out = *parsed;
  return true;
}

void put_watermark(ByteWriter& writer, const Watermark& watermark) {
  writer.put_u64(watermark.value());
}

[[nodiscard]] bool get_watermark(ByteReader& reader, Watermark& out) {
  const auto raw = reader.get_u64();
  if (!raw.has_value()) {
    return false;
  }
  out = Watermark(*raw);
  return true;
}

template <class Id>
void put_id_vector(ByteWriter& writer, const std::vector<Id>& values) {
  writer.put_u64(values.size());
  for (const auto& value : values) {
    put_id(writer, value);
  }
}

template <class Id>
[[nodiscard]] bool get_id_vector(ByteReader& reader, std::vector<Id>& out) {
  const auto count = reader.get_u64();
  if (!count.has_value() || *count > wire_max_elements) {
    return false;
  }
  out.clear();
  out.reserve(static_cast<std::size_t>(*count));
  for (std::uint64_t index = 0; index < *count; ++index) {
    Id value;
    if (!get_id(reader, value)) {
      return false;
    }
    out.push_back(value);
  }
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Message identifiers
// ---------------------------------------------------------------------------

std::string_view to_string(MessageId id) noexcept {
  switch (id) {
    case MessageId::HELLO:
      return "HELLO";
    case MessageId::HELLO_ACK:
      return "HELLO_ACK";
    case MessageId::REGISTER_PUBLISHER:
      return "REGISTER_PUBLISHER";
    case MessageId::FENCE_NOTICE:
      return "FENCE_NOTICE";
    case MessageId::CREATE_POLICY:
      return "CREATE_POLICY";
    case MessageId::UPDATE_POLICY:
      return "UPDATE_POLICY";
    case MessageId::POLICY_LIFECYCLE:
      return "POLICY_LIFECYCLE";
    case MessageId::REVOKE_POLICY:
      return "REVOKE_POLICY";
    case MessageId::UPSTREAM_NOTIFY:
      return "UPSTREAM_NOTIFY";
    case MessageId::PUBLISH_EVIDENCE:
      return "PUBLISH_EVIDENCE";
    case MessageId::EVALUATE:
      return "EVALUATE";
    case MessageId::COMMIT_DECISION:
      return "COMMIT_DECISION";
    case MessageId::REVALIDATE:
      return "REVALIDATE";
    case MessageId::ROLLBACK:
      return "ROLLBACK";
    case MessageId::QUERY_STATE:
      return "QUERY_STATE";
    case MessageId::SNAPSHOT_REQUEST:
      return "SNAPSHOT_REQUEST";
    case MessageId::SNAPSHOT_RESPONSE:
      return "SNAPSHOT_RESPONSE";
    case MessageId::EXPLAIN_REQUEST:
      return "EXPLAIN_REQUEST";
    case MessageId::DIFF_REQUEST:
      return "DIFF_REQUEST";
    case MessageId::ADVANCE_EPOCH:
      return "ADVANCE_EPOCH";
    case MessageId::RESULT:
      return "RESULT";
    case MessageId::ERROR:
      return "ERROR";
    case MessageId::BYE:
      return "BYE";
  }
  return "UNKNOWN";
}

std::optional<MessageId> parse_message_id(std::string_view text) noexcept {
  for (std::uint16_t raw = 1; raw <= 23; ++raw) {
    const auto id = static_cast<MessageId>(raw);
    if (to_string(id) == text) {
      return id;
    }
  }
  return std::nullopt;
}

bool valid_message_id(std::uint16_t raw) noexcept { return raw >= 1 && raw <= 23; }

std::string_view to_string(FrameStatus status) noexcept {
  switch (status) {
    case FrameStatus::OK:
      return "OK";
    case FrameStatus::INCOMPLETE:
      return "INCOMPLETE";
    case FrameStatus::BAD_MAGIC:
      return "BAD_MAGIC";
    case FrameStatus::BAD_VERSION:
      return "BAD_VERSION";
    case FrameStatus::BAD_MESSAGE_ID:
      return "BAD_MESSAGE_ID";
    case FrameStatus::TOO_LARGE:
      return "TOO_LARGE";
    case FrameStatus::INTEGRITY:
      return "INTEGRITY";
    case FrameStatus::MALFORMED:
      return "MALFORMED";
  }
  return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

std::optional<std::string> encode_frame(const Frame& frame, std::uint64_t max_frame_bytes) {
  if (!valid_message_id(static_cast<std::uint16_t>(frame.header.message_id))) {
    return std::nullopt;
  }
  if (frame.header.wire_version != wire_protocol_version) {
    return std::nullopt;
  }
  if (!frame.header.epoch.valid()) {
    return std::nullopt;
  }
  const std::uint64_t total = static_cast<std::uint64_t>(frame_header_bytes) +
                              frame.payload.size() + frame_trailer_bytes;
  if (total > max_frame_bytes) {
    return std::nullopt;
  }
  if (frame.payload.size() > 0xFFFFFFFFULL) {
    return std::nullopt;
  }
  std::string bytes(static_cast<std::size_t>(total), '\0');
  write_u32_at(bytes, 0, frame_magic);
  write_u16_at(bytes, 4, frame.header.wire_version);
  write_u16_at(bytes, 6, static_cast<std::uint16_t>(frame.header.message_id));
  write_u32_at(bytes, 8, frame.header.flags);
  write_u32_at(bytes, 12, static_cast<std::uint32_t>(frame.payload.size()));
  write_u64_at(bytes, 16, frame.header.sequence);
  write_u64_at(bytes, 24, frame.header.epoch.value());
  std::memcpy(bytes.data() + frame_header_bytes, frame.payload.data(), frame.payload.size());
  const std::uint64_t integrity =
      integrity_of(std::string_view(bytes.data(), frame_header_bytes + frame.payload.size()));
  write_u64_at(bytes, frame_header_bytes + frame.payload.size(), integrity);
  return bytes;
}

FrameDecodeResult decode_frame(std::string_view buffer, std::uint64_t max_frame_bytes) {
  FrameDecodeResult result;
  if (buffer.size() < frame_header_bytes) {
    result.status = FrameStatus::INCOMPLETE;
    return result;
  }
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint16_t raw_id = 0;
  std::uint32_t flags = 0;
  std::uint32_t payload_length = 0;
  std::uint64_t sequence = 0;
  std::uint64_t epoch_value = 0;
  // The header is fixed width and its presence was verified above; the reads are
  // still checked so that a future change to the header size cannot silently
  // read past the buffer.
  const bool header_read =
      read_u32(buffer, 0, magic) && read_u16(buffer, 4, version) && read_u16(buffer, 6, raw_id) &&
      read_u32(buffer, 8, flags) && read_u32(buffer, 12, payload_length) &&
      read_u64(buffer, 16, sequence) && read_u64(buffer, 24, epoch_value);
  if (!header_read) {
    result.status = FrameStatus::MALFORMED;
    return result;
  }
  if (magic != frame_magic) {
    result.status = FrameStatus::BAD_MAGIC;
    return result;
  }
  if (version != wire_protocol_version) {
    result.status = FrameStatus::BAD_VERSION;
    return result;
  }
  if (!valid_message_id(raw_id)) {
    result.status = FrameStatus::BAD_MESSAGE_ID;
    return result;
  }
  // The declared length is bounded before any further read, so an absurd length
  // costs nothing.
  const std::uint64_t maximum_payload =
      max_frame_bytes > (frame_header_bytes + frame_trailer_bytes)
          ? max_frame_bytes - (frame_header_bytes + frame_trailer_bytes)
          : 0;
  if (payload_length > maximum_payload) {
    result.status = FrameStatus::TOO_LARGE;
    return result;
  }
  const std::uint64_t total =
      static_cast<std::uint64_t>(frame_header_bytes) + payload_length + frame_trailer_bytes;
  if (buffer.size() < total) {
    result.status = FrameStatus::INCOMPLETE;
    return result;
  }
  const std::uint64_t expected =
      integrity_of(buffer.substr(0, frame_header_bytes + payload_length));
  std::uint64_t stored = 0;
  if (!read_u64(buffer, frame_header_bytes + payload_length, stored)) {
    result.status = FrameStatus::MALFORMED;
    return result;
  }
  if (expected != stored) {
    result.status = FrameStatus::INTEGRITY;
    return result;
  }
  const auto parsed_epoch = CoordinatorEpoch::from_value(epoch_value);
  if (!parsed_epoch.has_value()) {
    result.status = FrameStatus::MALFORMED;
    return result;
  }
  result.frame.header.wire_version = version;
  result.frame.header.message_id = static_cast<MessageId>(raw_id);
  result.frame.header.flags = flags;
  result.frame.header.payload_length = payload_length;
  result.frame.header.sequence = sequence;
  result.frame.header.epoch = *parsed_epoch;
  result.frame.payload.assign(buffer.substr(frame_header_bytes, payload_length));
  result.status = FrameStatus::OK;
  result.consumed = static_cast<std::size_t>(total);
  return result;
}

// ---------------------------------------------------------------------------
// Shared element codecs
// ---------------------------------------------------------------------------

void encode_context(ByteWriter& writer, const MutationContext& context) {
  put_generation(writer, context.epoch);
  put_id(writer, context.publisher);
  put_id(writer, context.worker_boot);
  put_id(writer, context.session);
  put_id(writer, context.attempt);
  writer.put_bool(context.expected_policy_generation.has_value());
  if (context.expected_policy_generation.has_value()) {
    put_generation(writer, *context.expected_policy_generation);
  }
  writer.put_bool(context.expected_evidence_generation.has_value());
  if (context.expected_evidence_generation.has_value()) {
    put_generation(writer, *context.expected_evidence_generation);
  }
}

std::optional<MutationContext> decode_context(ByteReader& reader) {
  MutationContext context;
  if (!get_generation(reader, context.epoch) || !get_id(reader, context.publisher) ||
      !get_id(reader, context.worker_boot) || !get_id(reader, context.session) ||
      !get_id(reader, context.attempt)) {
    return std::nullopt;
  }
  const auto has_policy = reader.get_bool();
  if (!has_policy.has_value()) {
    return std::nullopt;
  }
  if (*has_policy) {
    AdaptivePolicyGeneration generation;
    if (!get_generation(reader, generation)) {
      return std::nullopt;
    }
    context.expected_policy_generation = generation;
  }
  const auto has_evidence = reader.get_bool();
  if (!has_evidence.has_value()) {
    return std::nullopt;
  }
  if (*has_evidence) {
    EvidenceGeneration generation;
    if (!get_generation(reader, generation)) {
      return std::nullopt;
    }
    context.expected_evidence_generation = generation;
  }
  return context;
}

void encode_scope(ByteWriter& writer, const PolicyScope& scope) {
  put_id(writer, scope.fabric);
  put_id(writer, scope.name_space);
  put_optional_id(writer, scope.site);
  put_optional_id(writer, scope.path_class);
  put_id_vector(writer, scope.routes);
  put_id_vector(writer, scope.multipath_sets);
}

std::optional<PolicyScope> decode_scope(ByteReader& reader) {
  PolicyScope scope;
  if (!get_id(reader, scope.fabric) || !get_id(reader, scope.name_space)) {
    return std::nullopt;
  }
  if (!get_optional_id(reader, scope.site)) {
    return std::nullopt;
  }
  if (!get_optional_id(reader, scope.path_class)) {
    return std::nullopt;
  }
  if (!get_id_vector(reader, scope.routes) || !get_id_vector(reader, scope.multipath_sets)) {
    return std::nullopt;
  }
  if (!scope.well_formed()) {
    return std::nullopt;
  }
  return scope;
}

void encode_authority_scope(ByteWriter& writer, const AuthorityScope& scope) {
  put_id(writer, scope.fabric);
  put_id(writer, scope.name_space);
  put_id_vector(writer, scope.routes);
  put_id_vector(writer, scope.multipath_sets);
}

std::optional<AuthorityScope> decode_authority_scope(ByteReader& reader) {
  AuthorityScope scope;
  if (!get_id(reader, scope.fabric) || !get_id(reader, scope.name_space) ||
      !get_id_vector(reader, scope.routes) || !get_id_vector(reader, scope.multipath_sets)) {
    return std::nullopt;
  }
  if (!scope.well_formed()) {
    return std::nullopt;
  }
  return scope;
}

void encode_metric(ByteWriter& writer, const MetricValue& value) {
  writer.put_bool(value.valid());
  if (!value.valid()) {
    return;
  }
  writer.put_u8(static_cast<std::uint8_t>(value.kind()));
  writer.put_u8(static_cast<std::uint8_t>(value.unit()));
  writer.put_u32(value.semantics_version());
  writer.put_i64(value.value());
}

std::optional<MetricValue> decode_metric(ByteReader& reader) {
  const auto present = reader.get_bool();
  if (!present.has_value()) {
    return std::nullopt;
  }
  if (!*present) {
    return MetricValue();
  }
  const auto kind = reader.get_u8();
  const auto unit = reader.get_u8();
  const auto version = reader.get_u32();
  const auto value = reader.get_i64();
  if (!kind.has_value() || !unit.has_value() || !version.has_value() || !value.has_value()) {
    return std::nullopt;
  }
  if (!valid_metric_kind(*kind) || !valid_metric_unit(*unit)) {
    return std::nullopt;
  }
  const auto decoded =
      MetricValue::decode(static_cast<MetricKind>(*kind), static_cast<MetricUnit>(*unit), *version,
                          *value);
  if (!decoded.has_value()) {
    return std::nullopt;
  }
  return *decoded;
}

void encode_requirement(ByteWriter& writer, const EvidenceRequirement& requirement) {
  writer.put_u8(static_cast<std::uint8_t>(requirement.kind));
  writer.put_u8(static_cast<std::uint8_t>(requirement.aggregation));
  writer.put_u32(requirement.ewma_alpha_bps);
  writer.put_u32(requirement.min_samples);
  writer.put_u64(requirement.max_age);
  writer.put_u64(requirement.min_window);
  writer.put_u8(static_cast<std::uint8_t>(requirement.min_quality));
  writer.put_bool(requirement.required);
}

std::optional<EvidenceRequirement> decode_requirement(ByteReader& reader) {
  EvidenceRequirement requirement;
  const auto kind = reader.get_u8();
  const auto aggregation = reader.get_u8();
  const auto alpha = reader.get_u32();
  const auto min_samples = reader.get_u32();
  const auto max_age = reader.get_u64();
  const auto min_window = reader.get_u64();
  const auto quality = reader.get_u8();
  const auto required = reader.get_bool();
  if (!kind.has_value() || !aggregation.has_value() || !alpha.has_value() ||
      !min_samples.has_value() || !max_age.has_value() || !min_window.has_value() ||
      !quality.has_value() || !required.has_value()) {
    return std::nullopt;
  }
  if (!valid_metric_kind(*kind) || !valid_aggregation_kind(*aggregation) ||
      !valid_evidence_quality(*quality)) {
    return std::nullopt;
  }
  requirement.kind = static_cast<MetricKind>(*kind);
  requirement.aggregation = static_cast<AggregationKind>(*aggregation);
  requirement.ewma_alpha_bps = *alpha;
  requirement.min_samples = *min_samples;
  requirement.max_age = *max_age;
  requirement.min_window = *min_window;
  requirement.min_quality = static_cast<EvidenceQuality>(*quality);
  requirement.required = *required;
  if (!requirement.valid()) {
    return std::nullopt;
  }
  return requirement;
}

namespace {

void encode_semantics_body(ByteWriter& writer, const PolicySemantics& semantics) {
  writer.put_u32(semantics.semantics_version);
  put_id(writer, semantics.target.route);
  put_optional_id(writer, semantics.target.multipath_set);
  writer.put_u64(semantics.thresholds.size());
  for (const auto& rule : semantics.thresholds) {
    writer.put_u8(static_cast<std::uint8_t>(rule.kind));
    encode_metric(writer, rule.switch_value);
    encode_metric(writer, rule.clear_value);
  }
  writer.put_u64(semantics.improvements.size());
  for (const auto& rule : semantics.improvements) {
    writer.put_u8(static_cast<std::uint8_t>(rule.kind));
    writer.put_u32(rule.switch_improvement_bps);
    writer.put_u32(rule.reverse_improvement_bps);
  }
  writer.put_u64(semantics.evidence.size());
  for (const auto& requirement : semantics.evidence) {
    encode_requirement(writer, requirement);
  }
  writer.put_u64(semantics.hold_down.duration);
  writer.put_u64(semantics.cooldown.duration);
  writer.put_bool(semantics.dampening.enabled);
  writer.put_u32(semantics.dampening.penalty_increment);
  writer.put_u32(semantics.dampening.max_penalty);
  writer.put_u64(semantics.dampening.penalty_decay_interval);
  writer.put_u32(semantics.dampening.penalty_decay_step);
  writer.put_u64(semantics.dampening.hold_down_escalation_step);
  writer.put_u64(semantics.dampening.max_effective_hold_down);
  writer.put_u32(semantics.churn.max_adaptations_per_window);
  writer.put_u64(semantics.churn.window);
  writer.put_u8(static_cast<std::uint8_t>(semantics.objective.mode));
  writer.put_u32(semantics.objective.scoring_version);
  writer.put_u64(semantics.objective.terms.size());
  for (const auto& term : semantics.objective.terms) {
    writer.put_u8(static_cast<std::uint8_t>(term.kind));
    writer.put_u32(term.weight_bps);
  }
  writer.put_bool(semantics.emergency.enabled);
  writer.put_bool(semantics.emergency.on_current_path_unauthorized);
  writer.put_bool(semantics.emergency.on_current_path_unavailable);
  writer.put_bool(semantics.emergency.on_hard_failure_signal);
  writer.put_u64(semantics.priorities.size());
  for (const auto& entry : semantics.priorities) {
    put_id(writer, entry.path);
    writer.put_u32(entry.priority);
  }
}

[[nodiscard]] bool decode_semantics_body(ByteReader& reader, PolicySemantics& semantics) {
  const auto version = reader.get_u32();
  if (!version.has_value()) {
    return false;
  }
  semantics.semantics_version = *version;
  if (!get_id(reader, semantics.target.route) ||
      !get_optional_id(reader, semantics.target.multipath_set)) {
    return false;
  }
  const auto threshold_count = reader.get_u64();
  if (!threshold_count.has_value() || *threshold_count > wire_max_elements) {
    return false;
  }
  for (std::uint64_t index = 0; index < *threshold_count; ++index) {
    ThresholdRule rule;
    const auto kind = reader.get_u8();
    if (!kind.has_value() || !valid_metric_kind(*kind)) {
      return false;
    }
    rule.kind = static_cast<MetricKind>(*kind);
    const auto switch_value = decode_metric(reader);
    const auto clear_value = decode_metric(reader);
    if (!switch_value.has_value() || !clear_value.has_value()) {
      return false;
    }
    rule.switch_value = *switch_value;
    rule.clear_value = *clear_value;
    semantics.thresholds.push_back(rule);
  }
  const auto improvement_count = reader.get_u64();
  if (!improvement_count.has_value() || *improvement_count > wire_max_elements) {
    return false;
  }
  for (std::uint64_t index = 0; index < *improvement_count; ++index) {
    ImprovementRule rule;
    const auto kind = reader.get_u8();
    const auto switch_bps = reader.get_u32();
    const auto reverse_bps = reader.get_u32();
    if (!kind.has_value() || !valid_metric_kind(*kind) || !switch_bps.has_value() ||
        !reverse_bps.has_value()) {
      return false;
    }
    rule.kind = static_cast<MetricKind>(*kind);
    rule.switch_improvement_bps = *switch_bps;
    rule.reverse_improvement_bps = *reverse_bps;
    semantics.improvements.push_back(rule);
  }
  const auto evidence_count = reader.get_u64();
  if (!evidence_count.has_value() || *evidence_count > wire_max_elements) {
    return false;
  }
  for (std::uint64_t index = 0; index < *evidence_count; ++index) {
    const auto requirement = decode_requirement(reader);
    if (!requirement.has_value()) {
      return false;
    }
    semantics.evidence.push_back(*requirement);
  }
  const auto hold_down = reader.get_u64();
  const auto cooldown = reader.get_u64();
  const auto dampening_enabled = reader.get_bool();
  const auto penalty_increment = reader.get_u32();
  const auto max_penalty = reader.get_u32();
  const auto decay_interval = reader.get_u64();
  const auto decay_step = reader.get_u32();
  const auto escalation = reader.get_u64();
  const auto max_hold_down = reader.get_u64();
  const auto churn_max = reader.get_u32();
  const auto churn_window = reader.get_u64();
  const auto objective_mode = reader.get_u8();
  const auto scoring_version = reader.get_u32();
  if (!hold_down.has_value() || !cooldown.has_value() || !dampening_enabled.has_value() ||
      !penalty_increment.has_value() || !max_penalty.has_value() || !decay_interval.has_value() ||
      !decay_step.has_value() || !escalation.has_value() || !max_hold_down.has_value() ||
      !churn_max.has_value() || !churn_window.has_value() || !objective_mode.has_value() ||
      !scoring_version.has_value() || !valid_objective_mode(*objective_mode)) {
    return false;
  }
  semantics.hold_down.duration = *hold_down;
  semantics.cooldown.duration = *cooldown;
  semantics.dampening.enabled = *dampening_enabled;
  semantics.dampening.penalty_increment = *penalty_increment;
  semantics.dampening.max_penalty = *max_penalty;
  semantics.dampening.penalty_decay_interval = *decay_interval;
  semantics.dampening.penalty_decay_step = *decay_step;
  semantics.dampening.hold_down_escalation_step = *escalation;
  semantics.dampening.max_effective_hold_down = *max_hold_down;
  semantics.churn.max_adaptations_per_window = *churn_max;
  semantics.churn.window = *churn_window;
  semantics.objective.mode = static_cast<ObjectiveMode>(*objective_mode);
  semantics.objective.scoring_version = *scoring_version;
  const auto term_count = reader.get_u64();
  if (!term_count.has_value() || *term_count > wire_max_elements) {
    return false;
  }
  for (std::uint64_t index = 0; index < *term_count; ++index) {
    ObjectiveTerm term;
    const auto kind = reader.get_u8();
    const auto weight = reader.get_u32();
    if (!kind.has_value() || !valid_metric_kind(*kind) || !weight.has_value()) {
      return false;
    }
    term.kind = static_cast<MetricKind>(*kind);
    term.weight_bps = *weight;
    semantics.objective.terms.push_back(term);
  }
  const auto emergency_enabled = reader.get_bool();
  const auto on_unauthorized = reader.get_bool();
  const auto on_unavailable = reader.get_bool();
  const auto on_hard_failure = reader.get_bool();
  if (!emergency_enabled.has_value() || !on_unauthorized.has_value() ||
      !on_unavailable.has_value() || !on_hard_failure.has_value()) {
    return false;
  }
  semantics.emergency.enabled = *emergency_enabled;
  semantics.emergency.on_current_path_unauthorized = *on_unauthorized;
  semantics.emergency.on_current_path_unavailable = *on_unavailable;
  semantics.emergency.on_hard_failure_signal = *on_hard_failure;
  const auto priority_count = reader.get_u64();
  if (!priority_count.has_value() || *priority_count > wire_max_elements) {
    return false;
  }
  for (std::uint64_t index = 0; index < *priority_count; ++index) {
    CandidatePriority entry;
    // Field order mirrors encode_semantics_body exactly: identity, then the
    // priority value.
    if (!get_id(reader, entry.path)) {
      return false;
    }
    const auto priority = reader.get_u32();
    if (!priority.has_value()) {
      return false;
    }
    entry.priority = *priority;
    semantics.priorities.push_back(entry);
  }
  return true;
}

void encode_authority_provenance(ByteWriter& writer, const UpstreamProvenance& provenance) {
  put_id(writer, provenance.publisher);
  put_id(writer, provenance.worker_boot);
  put_generation(writer, provenance.epoch);
  put_id(writer, provenance.attempt);
  writer.put_string(provenance.origin);
}

[[nodiscard]] bool decode_upstream_provenance(ByteReader& reader, UpstreamProvenance& provenance) {
  if (!get_id(reader, provenance.publisher) || !get_id(reader, provenance.worker_boot) ||
      !get_generation(reader, provenance.epoch) || !get_id(reader, provenance.attempt)) {
    return false;
  }
  const auto origin = reader.get_string(wire_max_string_bytes);
  if (!origin.has_value()) {
    return false;
  }
  provenance.origin = *origin;
  return true;
}

void encode_path_authority(ByteWriter& writer, const PathAuthorityBinding& binding) {
  put_id(writer, binding.path);
  put_generation(writer, binding.generation);
  writer.put_bool(binding.legal);
  writer.put_string(binding.denial_reason);
}

[[nodiscard]] bool decode_path_authority(ByteReader& reader, PathAuthorityBinding& binding) {
  if (!get_id(reader, binding.path) || !get_generation(reader, binding.generation)) {
    return false;
  }
  const auto legal = reader.get_bool();
  const auto reason = reader.get_string(wire_max_string_bytes);
  if (!legal.has_value() || !reason.has_value()) {
    return false;
  }
  binding.legal = *legal;
  binding.denial_reason = *reason;
  return true;
}

void encode_multipath(ByteWriter& writer, const MultipathBinding& binding) {
  put_id(writer, binding.set);
  put_generation(writer, binding.generation);
  writer.put_bool(binding.current);
  put_id_vector(writer, binding.members);
}

[[nodiscard]] bool decode_multipath(ByteReader& reader, MultipathBinding& binding) {
  if (!get_id(reader, binding.set) || !get_generation(reader, binding.generation)) {
    return false;
  }
  const auto current = reader.get_bool();
  if (!current.has_value()) {
    return false;
  }
  binding.current = *current;
  return get_id_vector(reader, binding.members);
}

void encode_route(ByteWriter& writer, const RouteBinding& binding) {
  put_id(writer, binding.route);
  put_generation(writer, binding.generation);
  put_optional_id(writer, binding.site);
  writer.put_bool(binding.current);
  writer.put_string(binding.state);
}

[[nodiscard]] bool decode_route(ByteReader& reader, RouteBinding& binding) {
  if (!get_id(reader, binding.route) || !get_generation(reader, binding.generation) ||
      !get_optional_id(reader, binding.site)) {
    return false;
  }
  const auto current = reader.get_bool();
  const auto state = reader.get_string(wire_max_string_bytes);
  if (!current.has_value() || !state.has_value()) {
    return false;
  }
  binding.current = *current;
  binding.state = *state;
  return true;
}

void encode_weighted(ByteWriter& writer, const WeightedPolicyBinding& binding) {
  put_id(writer, binding.set);
  put_generation(writer, binding.generation);
  writer.put_bool(binding.current);
}

[[nodiscard]] bool decode_weighted(ByteReader& reader, WeightedPolicyBinding& binding) {
  if (!get_id(reader, binding.set) || !get_generation(reader, binding.generation)) {
    return false;
  }
  const auto current = reader.get_bool();
  if (!current.has_value()) {
    return false;
  }
  binding.current = *current;
  return true;
}

}  // namespace

void encode_semantics(ByteWriter& writer, const PolicySemantics& semantics) {
  encode_semantics_body(writer, semantics);
}

std::optional<PolicySemantics> decode_semantics(ByteReader& reader) {
  PolicySemantics semantics;
  if (!decode_semantics_body(reader, semantics)) {
    return std::nullopt;
  }
  if (semantics.semantics_version != policy_semantics_version) {
    return std::nullopt;
  }
  if (!semantics.valid(nullptr)) {
    return std::nullopt;
  }
  return semantics;
}

void encode_binding(ByteWriter& writer, const CandidateBinding& binding) {
  put_id(writer, binding.path);
  encode_path_authority(writer, binding.path_authority);
  writer.put_bool(binding.multipath.has_value());
  if (binding.multipath.has_value()) {
    encode_multipath(writer, *binding.multipath);
  }
  encode_route(writer, binding.route);
  writer.put_bool(binding.weighted.has_value());
  if (binding.weighted.has_value()) {
    encode_weighted(writer, *binding.weighted);
  }
  put_optional_id(writer, binding.path_class);
  writer.put_bool(binding.available);
  writer.put_bool(binding.hard_failure);
}

std::optional<CandidateBinding> decode_binding(ByteReader& reader) {
  CandidateBinding binding;
  if (!get_id(reader, binding.path)) {
    return std::nullopt;
  }
  PathAuthorityBinding authority;
  if (!decode_path_authority(reader, authority)) {
    return std::nullopt;
  }
  binding.path_authority = authority;
  const auto has_multipath = reader.get_bool();
  if (!has_multipath.has_value()) {
    return std::nullopt;
  }
  if (*has_multipath) {
    MultipathBinding multipath;
    if (!decode_multipath(reader, multipath)) {
      return std::nullopt;
    }
    binding.multipath = multipath;
  }
  if (!decode_route(reader, binding.route)) {
    return std::nullopt;
  }
  const auto has_weighted = reader.get_bool();
  if (!has_weighted.has_value()) {
    return std::nullopt;
  }
  if (*has_weighted) {
    WeightedPolicyBinding weighted;
    if (!decode_weighted(reader, weighted)) {
      return std::nullopt;
    }
    binding.weighted = weighted;
  }
  if (!get_optional_id(reader, binding.path_class)) {
    return std::nullopt;
  }
  const auto available = reader.get_bool();
  const auto hard_failure = reader.get_bool();
  if (!available.has_value() || !hard_failure.has_value()) {
    return std::nullopt;
  }
  binding.available = *available;
  binding.hard_failure = *hard_failure;
  if (!binding.well_formed()) {
    return std::nullopt;
  }
  return binding;
}

void encode_publication(ByteWriter& writer, const EvidencePublication& publication) {
  put_id(writer, publication.source);
  put_generation(writer, publication.source_generation);
  writer.put_u8(static_cast<std::uint8_t>(publication.quality));
  put_id(writer, publication.path);
  encode_metric(writer, publication.value);
  writer.put_u64(publication.observation_sequence);
}

std::optional<EvidencePublication> decode_publication(ByteReader& reader) {
  EvidencePublication publication;
  if (!get_id(reader, publication.source) ||
      !get_generation(reader, publication.source_generation)) {
    return std::nullopt;
  }
  const auto quality = reader.get_u8();
  if (!quality.has_value() || !valid_evidence_quality(*quality)) {
    return std::nullopt;
  }
  publication.quality = static_cast<EvidenceQuality>(*quality);
  if (!get_id(reader, publication.path)) {
    return std::nullopt;
  }
  const auto value = decode_metric(reader);
  const auto sequence = reader.get_u64();
  if (!value.has_value() || !sequence.has_value()) {
    return std::nullopt;
  }
  publication.value = *value;
  publication.observation_sequence = *sequence;
  if (!publication.well_formed()) {
    return std::nullopt;
  }
  return publication;
}

void encode_notification(ByteWriter& writer, const UpstreamNotification& notification) {
  writer.put_u8(static_cast<std::uint8_t>(notification.event));
  put_id(writer, notification.policy);
  encode_binding(writer, notification.binding);
  encode_authority_provenance(writer, notification.provenance);
  writer.put_bool(notification.expected_previous_generation.has_value());
  if (notification.expected_previous_generation.has_value()) {
    writer.put_u64(*notification.expected_previous_generation);
  }
}

std::optional<UpstreamNotification> decode_notification(ByteReader& reader) {
  UpstreamNotification notification;
  const auto event = reader.get_u8();
  if (!event.has_value() || !valid_upstream_event(*event)) {
    return std::nullopt;
  }
  notification.event = static_cast<UpstreamEvent>(*event);
  if (!get_id(reader, notification.policy)) {
    return std::nullopt;
  }
  const auto binding = decode_binding(reader);
  if (!binding.has_value()) {
    return std::nullopt;
  }
  notification.binding = *binding;
  if (!decode_upstream_provenance(reader, notification.provenance)) {
    return std::nullopt;
  }
  const auto has_expected = reader.get_bool();
  if (!has_expected.has_value()) {
    return std::nullopt;
  }
  if (*has_expected) {
    const auto expected = reader.get_u64();
    if (!expected.has_value()) {
      return std::nullopt;
    }
    notification.expected_previous_generation = *expected;
  }
  return notification;
}

void encode_candidate_evaluation(ByteWriter& writer, const CandidateEvaluation& evaluation) {
  put_id(writer, evaluation.path);
  writer.put_bool(evaluation.eligible);
  writer.put_u8(static_cast<std::uint8_t>(evaluation.rejection));
  writer.put_u16(static_cast<std::uint16_t>(evaluation.rejection_outcome));
  writer.put_u8(static_cast<std::uint8_t>(evaluation.quality));
  writer.put_bool(evaluation.score.has_value());
  if (evaluation.score.has_value()) {
    writer.put_u64(*evaluation.score);
  }
  writer.put_u64(evaluation.metrics.size());
  for (const auto& metric : evaluation.metrics) {
    encode_metric(writer, metric);
  }
  writer.put_u32(evaluation.priority);
  writer.put_bool(evaluation.current_preference);
  writer.put_bool(evaluation.previous_preference);
  writer.put_u32(evaluation.required_improvement_bps);
  writer.put_bool(evaluation.observed_improvement_bps.has_value());
  if (evaluation.observed_improvement_bps.has_value()) {
    writer.put_u32(*evaluation.observed_improvement_bps);
  }
  // Informational generations on a candidate evaluation may legitimately be
  // absent (a candidate without a multipath binding has no set generation), so
  // they travel with a presence flag rather than as a mandatory non-zero value.
  put_optional_generation(writer, evaluation.path_authority_generation);
  put_optional_generation(writer, evaluation.route_generation);
  put_optional_generation(writer, evaluation.multipath_set_generation);
}

std::optional<CandidateEvaluation> decode_candidate_evaluation(ByteReader& reader) {
  CandidateEvaluation evaluation;
  if (!get_id(reader, evaluation.path)) {
    return std::nullopt;
  }
  const auto eligible = reader.get_bool();
  const auto rejection = reader.get_u8();
  const auto rejection_outcome = reader.get_u16();
  const auto quality = reader.get_u8();
  const auto has_score = reader.get_bool();
  if (!eligible.has_value() || !rejection.has_value() || !rejection_outcome.has_value() ||
      !quality.has_value() || !has_score.has_value() ||
      !valid_suppression_reason(*rejection) || !valid_outcome(*rejection_outcome) ||
      !valid_evidence_quality(*quality)) {
    return std::nullopt;
  }
  evaluation.eligible = *eligible;
  evaluation.rejection = static_cast<SuppressionReason>(*rejection);
  evaluation.rejection_outcome = static_cast<Outcome>(*rejection_outcome);
  evaluation.quality = static_cast<EvidenceQuality>(*quality);
  if (*has_score) {
    const auto score = reader.get_u64();
    if (!score.has_value()) {
      return std::nullopt;
    }
    evaluation.score = *score;
  }
  const auto metric_count = reader.get_u64();
  if (!metric_count.has_value() || *metric_count > wire_max_elements) {
    return std::nullopt;
  }
  for (std::uint64_t index = 0; index < *metric_count; ++index) {
    const auto metric = decode_metric(reader);
    if (!metric.has_value()) {
      return std::nullopt;
    }
    evaluation.metrics.push_back(*metric);
  }
  const auto priority = reader.get_u32();
  const auto current = reader.get_bool();
  const auto previous = reader.get_bool();
  const auto required = reader.get_u32();
  const auto has_observed = reader.get_bool();
  if (!priority.has_value() || !current.has_value() || !previous.has_value() ||
      !required.has_value() || !has_observed.has_value()) {
    return std::nullopt;
  }
  evaluation.priority = *priority;
  evaluation.current_preference = *current;
  evaluation.previous_preference = *previous;
  evaluation.required_improvement_bps = *required;
  if (*has_observed) {
    const auto observed = reader.get_u32();
    if (!observed.has_value()) {
      return std::nullopt;
    }
    evaluation.observed_improvement_bps = *observed;
  }
  PathAuthorityGeneration authority_generation;
  RouteGeneration route_generation;
  MultipathSetGeneration multipath_generation;
  if (!get_optional_generation(reader, authority_generation) ||
      !get_optional_generation(reader, route_generation) ||
      !get_optional_generation(reader, multipath_generation)) {
    return std::nullopt;
  }
  evaluation.path_authority_generation = authority_generation;
  evaluation.route_generation = route_generation;
  evaluation.multipath_set_generation = multipath_generation;
  return evaluation;
}

// ---------------------------------------------------------------------------
// Evaluation ticket
// ---------------------------------------------------------------------------

void encode_ticket(ByteWriter& writer, const EvaluationTicket& ticket) {
  const DependencySnapshot& dependencies = ticket.dependencies;
  put_id(writer, dependencies.evaluation);
  put_id(writer, dependencies.policy);
  put_generation(writer, dependencies.policy_generation);
  put_generation(writer, dependencies.evidence_generation);
  put_watermark(writer, dependencies.evidence_watermark);
  put_watermark(writer, dependencies.upstream_watermark);
  put_generation(writer, dependencies.epoch);
  put_generation(writer, dependencies.authority_generation);
  put_optional_generation(writer, dependencies.route_generation);
  put_optional_id(writer, dependencies.multipath_set);
  put_optional_generation(writer, dependencies.multipath_set_generation);
  writer.put_u64(dependencies.candidate_path_authority.size());
  for (const auto& binding : dependencies.candidate_path_authority) {
    encode_path_authority(writer, binding);
  }
  writer.put_u64(dependencies.candidate_path_watermarks.size());
  for (const std::uint64_t watermark : dependencies.candidate_path_watermarks) {
    writer.put_u64(watermark);
  }
  put_id_vector(writer, dependencies.candidates);
  writer.put_u64(dependencies.captured_at);

  writer.put_u8(static_cast<std::uint8_t>(ticket.lifecycle));
  put_optional_id(writer, ticket.decision);
  put_optional_id(writer, ticket.evidence_snapshot);
  writer.put_u16(static_cast<std::uint16_t>(ticket.outcome));
  writer.put_u8(static_cast<std::uint8_t>(ticket.suppression));
  writer.put_string(ticket.detail);
  put_optional_id(writer, ticket.current_preference);
  put_optional_id(writer, ticket.target_preference);
  put_optional_generation(writer, ticket.target_path_authority_generation);
  put_optional_generation(writer, ticket.adaptation_generation);
  put_optional_generation(writer, ticket.transition_generation);
  writer.put_bool(ticket.target_score.has_value());
  if (ticket.target_score.has_value()) {
    writer.put_u64(*ticket.target_score);
  }
  writer.put_bool(ticket.improvement_bps.has_value());
  if (ticket.improvement_bps.has_value()) {
    writer.put_u32(*ticket.improvement_bps);
  }
  writer.put_u32(ticket.required_improvement_bps);
  writer.put_bool(ticket.weight_proposal.has_value());
  if (ticket.weight_proposal.has_value()) {
    put_id(writer, ticket.weight_proposal->set);
    put_generation(writer, ticket.weight_proposal->base_generation);
    writer.put_u64(ticket.weight_proposal->weights.size());
    for (const auto& weight : ticket.weight_proposal->weights) {
      put_id(writer, weight.path);
      writer.put_u32(weight.weight_bps);
    }
  }
  writer.put_bool(ticket.rollback);
  writer.put_bool(ticket.emergency);
  writer.put_u64(ticket.ranking.size());
  for (const auto& evaluation : ticket.ranking) {
    encode_candidate_evaluation(writer, evaluation);
  }
  writer.put_u64(ticket.evaluated_at);
}

std::optional<EvaluationTicket> decode_ticket(ByteReader& reader) {
  EvaluationTicket ticket;
  DependencySnapshot& dependencies = ticket.dependencies;
  if (!get_id(reader, dependencies.evaluation) || !get_id(reader, dependencies.policy) ||
      !get_generation(reader, dependencies.policy_generation) ||
      !get_generation(reader, dependencies.evidence_generation) ||
      !get_watermark(reader, dependencies.evidence_watermark) ||
      !get_watermark(reader, dependencies.upstream_watermark) ||
      !get_generation(reader, dependencies.epoch) ||
      !get_generation(reader, dependencies.authority_generation)) {
    return std::nullopt;
  }
  if (!get_optional_generation(reader, dependencies.route_generation) ||
      !get_optional_id(reader, dependencies.multipath_set) ||
      !get_optional_generation(reader, dependencies.multipath_set_generation)) {
    return std::nullopt;
  }
  const auto authority_count = reader.get_u64();
  if (!authority_count.has_value() || *authority_count > wire_max_elements) {
    return std::nullopt;
  }
  for (std::uint64_t index = 0; index < *authority_count; ++index) {
    PathAuthorityBinding binding;
    if (!decode_path_authority(reader, binding)) {
      return std::nullopt;
    }
    dependencies.candidate_path_authority.push_back(binding);
  }
  const auto watermark_count = reader.get_u64();
  if (!watermark_count.has_value() || *watermark_count > wire_max_elements) {
    return std::nullopt;
  }
  for (std::uint64_t index = 0; index < *watermark_count; ++index) {
    const auto value = reader.get_u64();
    if (!value.has_value()) {
      return std::nullopt;
    }
    dependencies.candidate_path_watermarks.push_back(*value);
  }
  if (!get_id_vector(reader, dependencies.candidates)) {
    return std::nullopt;
  }
  const auto captured = reader.get_u64();
  if (!captured.has_value()) {
    return std::nullopt;
  }
  dependencies.captured_at = *captured;

  const auto lifecycle = reader.get_u8();
  if (!lifecycle.has_value() || !valid_decision_lifecycle(*lifecycle)) {
    return std::nullopt;
  }
  ticket.lifecycle = static_cast<DecisionLifecycle>(*lifecycle);
  if (!get_optional_id(reader, ticket.decision) ||
      !get_optional_id(reader, ticket.evidence_snapshot)) {
    return std::nullopt;
  }
  const auto outcome = reader.get_u16();
  const auto suppression = reader.get_u8();
  if (!outcome.has_value() || !suppression.has_value() || !valid_outcome(*outcome) ||
      !valid_suppression_reason(*suppression)) {
    return std::nullopt;
  }
  ticket.outcome = static_cast<Outcome>(*outcome);
  ticket.suppression = static_cast<SuppressionReason>(*suppression);
  const auto detail = reader.get_string(wire_max_string_bytes);
  if (!detail.has_value()) {
    return std::nullopt;
  }
  ticket.detail = *detail;
  if (!get_optional_id(reader, ticket.current_preference) ||
      !get_optional_id(reader, ticket.target_preference) ||
      !get_optional_generation(reader, ticket.target_path_authority_generation) ||
      !get_optional_generation(reader, ticket.adaptation_generation) ||
      !get_optional_generation(reader, ticket.transition_generation)) {
    return std::nullopt;
  }
  const auto has_score = reader.get_bool();
  if (!has_score.has_value()) {
    return std::nullopt;
  }
  if (*has_score) {
    const auto score = reader.get_u64();
    if (!score.has_value()) {
      return std::nullopt;
    }
    ticket.target_score = *score;
  }
  const auto has_improvement = reader.get_bool();
  if (!has_improvement.has_value()) {
    return std::nullopt;
  }
  if (*has_improvement) {
    const auto improvement = reader.get_u32();
    if (!improvement.has_value()) {
      return std::nullopt;
    }
    ticket.improvement_bps = *improvement;
  }
  const auto required = reader.get_u32();
  if (!required.has_value()) {
    return std::nullopt;
  }
  ticket.required_improvement_bps = *required;
  const auto has_proposal = reader.get_bool();
  if (!has_proposal.has_value()) {
    return std::nullopt;
  }
  if (*has_proposal) {
    WeightProposal proposal;
    if (!get_id(reader, proposal.set) || !get_generation(reader, proposal.base_generation)) {
      return std::nullopt;
    }
    const auto weight_count = reader.get_u64();
    if (!weight_count.has_value() || *weight_count > wire_max_elements) {
      return std::nullopt;
    }
    for (std::uint64_t index = 0; index < *weight_count; ++index) {
      PathWeight weight;
      // Field order must mirror encode_ticket exactly: identity first, then the
      // weight in basis points.
      if (!get_id(reader, weight.path)) {
        return std::nullopt;
      }
      const auto value = reader.get_u32();
      if (!value.has_value()) {
        return std::nullopt;
      }
      weight.weight_bps = *value;
      proposal.weights.push_back(weight);
    }
    if (!proposal.well_formed()) {
      return std::nullopt;
    }
    ticket.weight_proposal = proposal;
  }
  const auto rollback = reader.get_bool();
  const auto emergency = reader.get_bool();
  if (!rollback.has_value() || !emergency.has_value()) {
    return std::nullopt;
  }
  ticket.rollback = *rollback;
  ticket.emergency = *emergency;
  const auto ranking_count = reader.get_u64();
  if (!ranking_count.has_value() || *ranking_count > wire_max_elements) {
    return std::nullopt;
  }
  for (std::uint64_t index = 0; index < *ranking_count; ++index) {
    const auto evaluation = decode_candidate_evaluation(reader);
    if (!evaluation.has_value()) {
      return std::nullopt;
    }
    ticket.ranking.push_back(*evaluation);
  }
  const auto evaluated = reader.get_u64();
  if (!evaluated.has_value()) {
    return std::nullopt;
  }
  ticket.evaluated_at = *evaluated;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return ticket;
}

// ---------------------------------------------------------------------------
// Payload messages
// ---------------------------------------------------------------------------

std::string HelloMessage::encode() const {
  ByteWriter writer;
  writer.put_u16(wire_version);
  writer.put_string(product);
  put_generation(writer, epoch);
  put_generation(writer, authority_generation);
  return writer.take();
}

std::optional<HelloMessage> HelloMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  HelloMessage message;
  const auto version = reader.get_u16();
  const auto product = reader.get_string(wire_max_string_bytes);
  if (!version.has_value() || !product.has_value()) {
    return std::nullopt;
  }
  message.wire_version = *version;
  message.product = *product;
  if (!get_generation(reader, message.epoch) ||
      !get_generation(reader, message.authority_generation)) {
    return std::nullopt;
  }
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string RegisterPublisherMessage::encode() const {
  ByteWriter writer;
  put_id(writer, publisher);
  put_id(writer, worker_boot);
  encode_authority_scope(writer, scope);
  return writer.take();
}

std::optional<RegisterPublisherMessage> RegisterPublisherMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  RegisterPublisherMessage message;
  if (!get_id(reader, message.publisher) || !get_id(reader, message.worker_boot)) {
    return std::nullopt;
  }
  const auto scope = decode_authority_scope(reader);
  if (!scope.has_value()) {
    return std::nullopt;
  }
  message.scope = *scope;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string FenceNoticeMessage::encode() const {
  ByteWriter writer;
  put_id(writer, publisher);
  put_id(writer, worker_boot);
  writer.put_string(cause);
  return writer.take();
}

std::optional<FenceNoticeMessage> FenceNoticeMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  FenceNoticeMessage message;
  if (!get_id(reader, message.publisher) || !get_id(reader, message.worker_boot)) {
    return std::nullopt;
  }
  const auto cause = reader.get_string(wire_max_string_bytes);
  if (!cause.has_value()) {
    return std::nullopt;
  }
  message.cause = *cause;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string CreatePolicyMessage::encode() const {
  ByteWriter writer;
  put_id(writer, name);
  encode_scope(writer, scope);
  encode_semantics(writer, semantics);
  return writer.take();
}

std::optional<CreatePolicyMessage> CreatePolicyMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  CreatePolicyMessage message;
  if (!get_id(reader, message.name)) {
    return std::nullopt;
  }
  const auto scope = decode_scope(reader);
  if (!scope.has_value()) {
    return std::nullopt;
  }
  message.scope = *scope;
  const auto semantics = decode_semantics(reader);
  if (!semantics.has_value()) {
    return std::nullopt;
  }
  message.semantics = *semantics;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string UpdatePolicyMessage::encode() const {
  ByteWriter writer;
  put_id(writer, policy);
  encode_scope(writer, scope);
  encode_semantics(writer, semantics);
  return writer.take();
}

std::optional<UpdatePolicyMessage> UpdatePolicyMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  UpdatePolicyMessage message;
  if (!get_id(reader, message.policy)) {
    return std::nullopt;
  }
  const auto scope = decode_scope(reader);
  if (!scope.has_value()) {
    return std::nullopt;
  }
  message.scope = *scope;
  const auto semantics = decode_semantics(reader);
  if (!semantics.has_value()) {
    return std::nullopt;
  }
  message.semantics = *semantics;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string PolicyLifecycleMessage::encode() const {
  ByteWriter writer;
  put_id(writer, policy);
  writer.put_u8(static_cast<std::uint8_t>(event));
  writer.put_string(detail);
  return writer.take();
}

std::optional<PolicyLifecycleMessage> PolicyLifecycleMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  PolicyLifecycleMessage message;
  if (!get_id(reader, message.policy)) {
    return std::nullopt;
  }
  const auto event = reader.get_u8();
  if (!event.has_value() || !valid_policy_event(*event)) {
    return std::nullopt;
  }
  message.event = static_cast<PolicyEvent>(*event);
  const auto detail = reader.get_string(wire_max_string_bytes);
  if (!detail.has_value()) {
    return std::nullopt;
  }
  message.detail = *detail;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string RevokePolicyMessage::encode() const {
  ByteWriter writer;
  put_id(writer, policy);
  writer.put_u8(static_cast<std::uint8_t>(reason));
  writer.put_string(detail);
  return writer.take();
}

std::optional<RevokePolicyMessage> RevokePolicyMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  RevokePolicyMessage message;
  if (!get_id(reader, message.policy)) {
    return std::nullopt;
  }
  const auto reason = reader.get_u8();
  if (!reason.has_value() || !valid_revocation_reason(*reason)) {
    return std::nullopt;
  }
  message.reason = static_cast<RevocationReason>(*reason);
  const auto detail = reader.get_string(wire_max_string_bytes);
  if (!detail.has_value()) {
    return std::nullopt;
  }
  message.detail = *detail;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string UpstreamNotifyMessage::encode() const {
  ByteWriter writer;
  writer.put_u64(notifications.size());
  for (const auto& notification : notifications) {
    encode_notification(writer, notification);
  }
  return writer.take();
}

std::optional<UpstreamNotifyMessage> UpstreamNotifyMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  UpstreamNotifyMessage message;
  const auto count = reader.get_u64();
  if (!count.has_value() || *count > wire_max_elements) {
    return std::nullopt;
  }
  for (std::uint64_t index = 0; index < *count; ++index) {
    const auto notification = decode_notification(reader);
    if (!notification.has_value()) {
      return std::nullopt;
    }
    message.notifications.push_back(*notification);
  }
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string PublishEvidenceMessage::encode() const {
  ByteWriter writer;
  writer.put_u64(publications.size());
  for (const auto& publication : publications) {
    encode_publication(writer, publication);
  }
  return writer.take();
}

std::optional<PublishEvidenceMessage> PublishEvidenceMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  PublishEvidenceMessage message;
  const auto count = reader.get_u64();
  if (!count.has_value() || *count > wire_max_elements) {
    return std::nullopt;
  }
  for (std::uint64_t index = 0; index < *count; ++index) {
    const auto publication = decode_publication(reader);
    if (!publication.has_value()) {
      return std::nullopt;
    }
    message.publications.push_back(*publication);
  }
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string EvaluateMessage::encode() const {
  ByteWriter writer;
  put_id(writer, policy);
  writer.put_bool(defer_commit);
  return writer.take();
}

std::optional<EvaluateMessage> EvaluateMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  EvaluateMessage message;
  if (!get_id(reader, message.policy)) {
    return std::nullopt;
  }
  const auto deferred = reader.get_bool();
  if (!deferred.has_value()) {
    return std::nullopt;
  }
  message.defer_commit = *deferred;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string CommitDecisionMessage::encode() const {
  ByteWriter writer;
  encode_ticket(writer, ticket);
  return writer.take();
}

std::optional<CommitDecisionMessage> CommitDecisionMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  CommitDecisionMessage message;
  const auto ticket = decode_ticket(reader);
  if (!ticket.has_value()) {
    return std::nullopt;
  }
  message.ticket = *ticket;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string RevalidateMessage::encode() const {
  ByteWriter writer;
  put_id(writer, policy);
  put_id(writer, attempt);
  return writer.take();
}

std::optional<RevalidateMessage> RevalidateMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  RevalidateMessage message;
  if (!get_id(reader, message.policy) || !get_id(reader, message.attempt)) {
    return std::nullopt;
  }
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string RollbackMessage::encode() const {
  ByteWriter writer;
  put_id(writer, policy);
  writer.put_string(reason);
  return writer.take();
}

std::optional<RollbackMessage> RollbackMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  RollbackMessage message;
  if (!get_id(reader, message.policy)) {
    return std::nullopt;
  }
  const auto reason = reader.get_string(wire_max_string_bytes);
  if (!reason.has_value()) {
    return std::nullopt;
  }
  message.reason = *reason;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string QueryStateMessage::encode() const {
  ByteWriter writer;
  put_optional_id(writer, policy);
  writer.put_u64(limit);
  return writer.take();
}

std::optional<QueryStateMessage> QueryStateMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  QueryStateMessage message;
  if (!get_optional_id(reader, message.policy)) {
    return std::nullopt;
  }
  const auto limit = reader.get_u64();
  if (!limit.has_value()) {
    return std::nullopt;
  }
  message.limit = *limit;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string SnapshotRequestMessage::encode() const {
  ByteWriter writer;
  put_id(writer, policy);
  return writer.take();
}

std::optional<SnapshotRequestMessage> SnapshotRequestMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  SnapshotRequestMessage message;
  if (!get_id(reader, message.policy)) {
    return std::nullopt;
  }
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string SnapshotResponseMessage::encode() const {
  ByteWriter writer;
  put_id(writer, snapshot);
  put_id(writer, policy);
  writer.put_string(digest);
  writer.put_string(rendered);
  return writer.take();
}

std::optional<SnapshotResponseMessage> SnapshotResponseMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  SnapshotResponseMessage message;
  if (!get_id(reader, message.snapshot) || !get_id(reader, message.policy)) {
    return std::nullopt;
  }
  const auto digest = reader.get_string(wire_max_string_bytes);
  const auto rendered = reader.get_string(wire_max_string_bytes);
  if (!digest.has_value() || !rendered.has_value()) {
    return std::nullopt;
  }
  message.digest = *digest;
  message.rendered = *rendered;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string ExplainRequestMessage::encode() const {
  ByteWriter writer;
  writer.put_u8(static_cast<std::uint8_t>(topic));
  put_id(writer, policy);
  return writer.take();
}

std::optional<ExplainRequestMessage> ExplainRequestMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  ExplainRequestMessage message;
  const auto topic = reader.get_u8();
  if (!topic.has_value() || !valid_explanation_topic(*topic)) {
    return std::nullopt;
  }
  message.topic = static_cast<ExplanationTopic>(*topic);
  if (!get_id(reader, message.policy)) {
    return std::nullopt;
  }
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string DiffRequestMessage::encode() const {
  ByteWriter writer;
  put_id(writer, policy);
  put_id(writer, from);
  put_id(writer, to);
  return writer.take();
}

std::optional<DiffRequestMessage> DiffRequestMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  DiffRequestMessage message;
  if (!get_id(reader, message.policy) || !get_id(reader, message.from) ||
      !get_id(reader, message.to)) {
    return std::nullopt;
  }
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string AdvanceEpochMessage::encode() const {
  ByteWriter writer;
  writer.put_string(reason);
  return writer.take();
}

std::optional<AdvanceEpochMessage> AdvanceEpochMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  AdvanceEpochMessage message;
  const auto reason = reader.get_string(wire_max_string_bytes);
  if (!reason.has_value()) {
    return std::nullopt;
  }
  message.reason = *reason;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string ResultMessage::encode() const {
  ByteWriter writer;
  writer.put_u16(static_cast<std::uint16_t>(outcome));
  writer.put_u8(static_cast<std::uint8_t>(suppression));
  writer.put_string(detail);
  put_optional_id(writer, policy);
  put_optional_generation(writer, policy_generation);
  put_optional_id(writer, decision);
  put_optional_generation(writer, adaptation_generation);
  put_optional_generation(writer, transition_generation);
  put_optional_generation(writer, evidence_generation);
  put_optional_generation(writer, epoch);
  writer.put_string(rendered);
  return writer.take();
}

std::optional<ResultMessage> ResultMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  ResultMessage message;
  const auto outcome = reader.get_u16();
  const auto suppression = reader.get_u8();
  if (!outcome.has_value() || !suppression.has_value() || !valid_outcome(*outcome) ||
      !valid_suppression_reason(*suppression)) {
    return std::nullopt;
  }
  message.outcome = static_cast<Outcome>(*outcome);
  message.suppression = static_cast<SuppressionReason>(*suppression);
  const auto detail = reader.get_string(wire_max_string_bytes);
  if (!detail.has_value()) {
    return std::nullopt;
  }
  message.detail = *detail;
  if (!get_optional_id(reader, message.policy) ||
      !get_optional_generation(reader, message.policy_generation) ||
      !get_optional_id(reader, message.decision) ||
      !get_optional_generation(reader, message.adaptation_generation) ||
      !get_optional_generation(reader, message.transition_generation) ||
      !get_optional_generation(reader, message.evidence_generation) ||
      !get_optional_generation(reader, message.epoch)) {
    return std::nullopt;
  }
  const auto rendered = reader.get_string(wire_max_string_bytes);
  if (!rendered.has_value()) {
    return std::nullopt;
  }
  message.rendered = *rendered;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

std::string ErrorMessage::encode() const {
  ByteWriter writer;
  writer.put_u16(static_cast<std::uint16_t>(outcome));
  writer.put_string(detail);
  return writer.take();
}

std::optional<ErrorMessage> ErrorMessage::decode(std::string_view payload) {
  ByteReader reader(payload);
  ErrorMessage message;
  const auto outcome = reader.get_u16();
  if (!outcome.has_value() || !valid_outcome(*outcome)) {
    return std::nullopt;
  }
  message.outcome = static_cast<Outcome>(*outcome);
  const auto detail = reader.get_string(wire_max_string_bytes);
  if (!detail.has_value()) {
    return std::nullopt;
  }
  message.detail = *detail;
  if (!reader.finished()) {
    return std::nullopt;
  }
  return message;
}

}  // namespace adaptive_routing

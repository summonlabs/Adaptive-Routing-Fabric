// Framed wire protocol.
//
// The transport is a framed, versioned, integrity-checked protocol. It never
// serializes a raw C++ layout, never trusts a declared length before bounding
// it, never accepts an unknown enum value and never accepts a frame with
// trailing bytes.
//
// INTEGRITY SCOPE
// ---------------
// The trailer covers the semantic header AND the payload, so a corrupted
// message id, epoch or length is detected exactly like a corrupted body.
//
// AUTHENTICATION
// --------------
// The trailer is a deterministic non-cryptographic hash. It detects corruption,
// not forgery: Adaptive Routing Fabric does not implement cryptographic
// authentication and does not claim it. Peer trust is established by the
// coordinator's epoch/worker/scope authority rules, not by a signature.
#ifndef ADAPTIVE_ROUTING_WIRE_HPP
#define ADAPTIVE_ROUTING_WIRE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/codec.hpp"
#include "adaptive_routing/decision.hpp"
#include "adaptive_routing/ids.hpp"
#include "adaptive_routing/outcome.hpp"
#include "adaptive_routing/policy.hpp"
#include "adaptive_routing/view.hpp"

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Message identifiers
// ---------------------------------------------------------------------------

// Stable numeric identifiers. A value is never reused for a different meaning.
enum class MessageId : std::uint16_t {
  HELLO = 1,
  HELLO_ACK = 2,
  REGISTER_PUBLISHER = 3,
  FENCE_NOTICE = 4,
  CREATE_POLICY = 5,
  UPDATE_POLICY = 6,
  POLICY_LIFECYCLE = 7,
  REVOKE_POLICY = 8,
  UPSTREAM_NOTIFY = 9,
  PUBLISH_EVIDENCE = 10,
  EVALUATE = 11,
  COMMIT_DECISION = 12,
  REVALIDATE = 13,
  ROLLBACK = 14,
  QUERY_STATE = 15,
  SNAPSHOT_REQUEST = 16,
  SNAPSHOT_RESPONSE = 17,
  EXPLAIN_REQUEST = 18,
  DIFF_REQUEST = 19,
  ADVANCE_EPOCH = 20,
  RESULT = 21,
  ERROR = 22,
  BYE = 23,
};

[[nodiscard]] std::string_view to_string(MessageId id) noexcept;
[[nodiscard]] std::optional<MessageId> parse_message_id(std::string_view text) noexcept;
[[nodiscard]] bool valid_message_id(std::uint16_t raw) noexcept;

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

struct FrameHeader {
  std::uint16_t wire_version = wire_protocol_version;
  MessageId message_id = MessageId::HELLO;
  std::uint32_t flags = 0;
  std::uint32_t payload_length = 0;
  std::uint64_t sequence = 0;
  CoordinatorEpoch epoch;
};

// magic(4) | wire_version(2) | message_id(2) | flags(4) | payload_length(4) |
// sequence(8) | epoch(8) = 32 bytes, then payload, then an 8 byte integrity
// trailer.
inline constexpr std::size_t frame_header_bytes = 32;
inline constexpr std::size_t frame_trailer_bytes = 8;
inline constexpr std::uint32_t frame_magic = 0x31465241U;  // "ARF1" little-endian

enum class FrameStatus : std::uint8_t {
  OK = 0,
  INCOMPLETE = 1,
  BAD_MAGIC = 2,
  BAD_VERSION = 3,
  BAD_MESSAGE_ID = 4,
  TOO_LARGE = 5,
  INTEGRITY = 6,
  MALFORMED = 7,
};

[[nodiscard]] std::string_view to_string(FrameStatus status) noexcept;

struct Frame {
  FrameHeader header;
  std::string payload;
};

struct FrameDecodeResult {
  FrameStatus status = FrameStatus::INCOMPLETE;
  Frame frame;
  std::size_t consumed = 0;
};

// Encodes one frame. Returns nullopt when the payload would exceed
// \p max_frame_bytes.
[[nodiscard]] std::optional<std::string> encode_frame(const Frame& frame,
                                                      std::uint64_t max_frame_bytes);

// Decodes one frame from the front of \p buffer. INCOMPLETE means "more bytes
// are needed"; every other failure is terminal for the session.
[[nodiscard]] FrameDecodeResult decode_frame(std::string_view buffer,
                                             std::uint64_t max_frame_bytes);

// ---------------------------------------------------------------------------
// Payload codecs
// ---------------------------------------------------------------------------

struct HelloMessage {
  std::uint16_t wire_version = wire_protocol_version;
  std::string product;
  CoordinatorEpoch epoch;
  AdaptiveAuthorityGeneration authority_generation;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<HelloMessage> decode(std::string_view payload);
};

struct RegisterPublisherMessage {
  PublisherId publisher;
  WorkerBootId worker_boot;
  AuthorityScope scope;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<RegisterPublisherMessage> decode(std::string_view payload);
};

struct FenceNoticeMessage {
  PublisherId publisher;
  WorkerBootId worker_boot;
  std::string cause;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<FenceNoticeMessage> decode(std::string_view payload);
};

struct CreatePolicyMessage {
  AdaptivePolicyName name;
  PolicyScope scope;
  PolicySemantics semantics;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<CreatePolicyMessage> decode(std::string_view payload);
};

struct UpdatePolicyMessage {
  AdaptivePolicyId policy;
  PolicyScope scope;
  PolicySemantics semantics;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<UpdatePolicyMessage> decode(std::string_view payload);
};

struct PolicyLifecycleMessage {
  AdaptivePolicyId policy;
  PolicyEvent event = PolicyEvent::ACTIVATE;
  std::string detail;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<PolicyLifecycleMessage> decode(std::string_view payload);
};

struct RevokePolicyMessage {
  AdaptivePolicyId policy;
  RevocationReason reason = RevocationReason::ADMINISTRATIVE;
  std::string detail;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<RevokePolicyMessage> decode(std::string_view payload);
};

struct UpstreamNotifyMessage {
  std::vector<UpstreamNotification> notifications;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<UpstreamNotifyMessage> decode(std::string_view payload);
};

struct PublishEvidenceMessage {
  std::vector<EvidencePublication> publications;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<PublishEvidenceMessage> decode(std::string_view payload);
};

struct EvaluateMessage {
  AdaptivePolicyId policy;
  bool defer_commit = false;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<EvaluateMessage> decode(std::string_view payload);
};

struct CommitDecisionMessage {
  // The ticket is re-verified on the coordinator; a replayed or edited ticket is
  // rejected by the same generation checks that protect a local commit.
  EvaluationTicket ticket;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<CommitDecisionMessage> decode(std::string_view payload);
};

struct RevalidateMessage {
  AdaptivePolicyId policy;
  RevalidationAttemptId attempt;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<RevalidateMessage> decode(std::string_view payload);
};

struct RollbackMessage {
  AdaptivePolicyId policy;
  std::string reason;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<RollbackMessage> decode(std::string_view payload);
};

struct QueryStateMessage {
  // An invalid policy means "list every policy".
  AdaptivePolicyId policy;
  std::uint64_t limit = 64;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<QueryStateMessage> decode(std::string_view payload);
};

struct SnapshotRequestMessage {
  AdaptivePolicyId policy;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<SnapshotRequestMessage> decode(std::string_view payload);
};

struct SnapshotResponseMessage {
  SnapshotId snapshot;
  AdaptivePolicyId policy;
  std::string digest;
  std::string rendered;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<SnapshotResponseMessage> decode(std::string_view payload);
};

struct ExplainRequestMessage {
  ExplanationTopic topic = ExplanationTopic::WHY_NOT_ADAPTED;
  AdaptivePolicyId policy;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<ExplainRequestMessage> decode(std::string_view payload);
};

struct DiffRequestMessage {
  AdaptivePolicyId policy;
  SnapshotId from;
  SnapshotId to;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<DiffRequestMessage> decode(std::string_view payload);
};

struct AdvanceEpochMessage {
  std::string reason;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<AdvanceEpochMessage> decode(std::string_view payload);
};

struct ResultMessage {
  Outcome outcome = Outcome::MALFORMED_REQUEST;
  SuppressionReason suppression = SuppressionReason::NONE;
  std::string detail;
  AdaptivePolicyId policy;
  AdaptivePolicyGeneration policy_generation;
  AdaptationDecisionId decision;
  AdaptationGeneration adaptation_generation;
  TransitionGeneration transition_generation;
  EvidenceGeneration evidence_generation;
  CoordinatorEpoch epoch;
  std::string rendered;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<ResultMessage> decode(std::string_view payload);
};

struct ErrorMessage {
  Outcome outcome = Outcome::MALFORMED_REQUEST;
  std::string detail;

  [[nodiscard]] std::string encode() const;
  [[nodiscard]] static std::optional<ErrorMessage> decode(std::string_view payload);
};

// ---------------------------------------------------------------------------
// Shared element codecs
// ---------------------------------------------------------------------------

void encode_context(ByteWriter& writer, const MutationContext& context);
[[nodiscard]] std::optional<MutationContext> decode_context(ByteReader& reader);

void encode_scope(ByteWriter& writer, const PolicyScope& scope);
[[nodiscard]] std::optional<PolicyScope> decode_scope(ByteReader& reader);

void encode_authority_scope(ByteWriter& writer, const AuthorityScope& scope);
[[nodiscard]] std::optional<AuthorityScope> decode_authority_scope(ByteReader& reader);

void encode_semantics(ByteWriter& writer, const PolicySemantics& semantics);
[[nodiscard]] std::optional<PolicySemantics> decode_semantics(ByteReader& reader);

void encode_metric(ByteWriter& writer, const MetricValue& value);
[[nodiscard]] std::optional<MetricValue> decode_metric(ByteReader& reader);

void encode_requirement(ByteWriter& writer, const EvidenceRequirement& requirement);
[[nodiscard]] std::optional<EvidenceRequirement> decode_requirement(ByteReader& reader);

void encode_binding(ByteWriter& writer, const CandidateBinding& binding);
[[nodiscard]] std::optional<CandidateBinding> decode_binding(ByteReader& reader);

void encode_publication(ByteWriter& writer, const EvidencePublication& publication);
[[nodiscard]] std::optional<EvidencePublication> decode_publication(ByteReader& reader);

void encode_notification(ByteWriter& writer, const UpstreamNotification& notification);
[[nodiscard]] std::optional<UpstreamNotification> decode_notification(ByteReader& reader);

void encode_ticket(ByteWriter& writer, const EvaluationTicket& ticket);
[[nodiscard]] std::optional<EvaluationTicket> decode_ticket(ByteReader& reader);

void encode_candidate_evaluation(ByteWriter& writer, const CandidateEvaluation& evaluation);
[[nodiscard]] std::optional<CandidateEvaluation> decode_candidate_evaluation(ByteReader& reader);

// Maximum accepted length of any single string carried by a payload.
inline constexpr std::uint64_t wire_max_string_bytes = 4096;
// Maximum accepted element count in any payload vector.
inline constexpr std::uint64_t wire_max_elements = 4096;

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_WIRE_HPP

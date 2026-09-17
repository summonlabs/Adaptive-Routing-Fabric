// Strongly typed identities, generations and watermarks.
//
// Adaptive Routing Fabric never uses interchangeable raw integers or strings
// for identity. Every identity domain has its own type, implicit conversion
// between domains is impossible, malformed encodings are rejected at
// construction and zero/invalid sentinel values are rejected wherever they are
// semantically meaningless.
//
// A PathId here is an *opaque reference* to a path decided elsewhere. Adaptive
// Routing Fabric does not interpret path structure and never derives one path
// identity from another.
#ifndef ADAPTIVE_ROUTING_IDS_HPP
#define ADAPTIVE_ROUTING_IDS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace adaptive_routing {

// Thrown only by the explicit \c require() factories, which exist for call sites
// that treat a malformed identity as a programming error. Untrusted input must
// use the \c parse() factories, which return std::nullopt.
class IdError : public std::invalid_argument {
 public:
  explicit IdError(std::string message) : std::invalid_argument(std::move(message)) {}
};

namespace detail {

[[nodiscard]] constexpr bool id_char_allowed(char c) noexcept {
  const bool upper = c >= 'A' && c <= 'Z';
  const bool lower = c >= 'a' && c <= 'z';
  const bool digit = c >= '0' && c <= '9';
  const bool punct = c == '.' || c == '_' || c == '-' || c == ':' || c == '@' || c == '#' ||
                     c == '+' || c == '/';
  return upper || lower || digit || punct;
}

[[nodiscard]] constexpr bool id_edge_char_allowed(char c) noexcept {
  return c != '.' && c != '-' && c != ':' && c != '@' && c != '#' && c != '+' && c != '/' &&
         c != '_';
}

[[nodiscard]] constexpr bool add_overflows_u64(std::uint64_t a, std::uint64_t b) noexcept {
  return a > (std::numeric_limits<std::uint64_t>::max)() - b;
}

[[nodiscard]] constexpr bool multiply_overflows_u64(std::uint64_t a, std::uint64_t b) noexcept {
  if (a == 0 || b == 0) {
    return false;
  }
  return a > (std::numeric_limits<std::uint64_t>::max)() / b;
}

}  // namespace detail

// ---------------------------------------------------------------------------
// StrongId
// ---------------------------------------------------------------------------

// Bounded, validated, deterministically ordered textual identity.
//
// Encoding rules (enforced by parse()):
//   * length >= 1 and <= Tag::max_length;
//   * every character is an ASCII letter, digit or one of . _ - : @ # + /;
//   * the first and last characters are alphanumeric.
template <class Tag>
class StrongId {
 public:
  using tag_type = Tag;
  static constexpr std::size_t max_length = Tag::max_length;
  static constexpr std::string_view domain_name = Tag::name;

  constexpr StrongId() noexcept = default;

  [[nodiscard]] static std::optional<StrongId> parse(std::string_view text) noexcept {
    if (text.empty() || text.size() > max_length) {
      return std::nullopt;
    }
    for (const char c : text) {
      if (!detail::id_char_allowed(c)) {
        return std::nullopt;
      }
    }
    if (!detail::id_edge_char_allowed(text.front()) || !detail::id_edge_char_allowed(text.back())) {
      return std::nullopt;
    }
    StrongId result;
    result.length_ = static_cast<std::uint16_t>(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
      result.storage_[i] = text[i];
    }
    return result;
  }

  [[nodiscard]] static StrongId require(std::string_view text) {
    const auto parsed = parse(text);
    if (!parsed.has_value()) {
      throw IdError("malformed " + std::string(domain_name) + " encoding");
    }
    return *parsed;
  }

  [[nodiscard]] constexpr bool valid() const noexcept { return length_ != 0; }
  [[nodiscard]] constexpr std::size_t size() const noexcept { return length_; }

  [[nodiscard]] std::string_view view() const noexcept {
    return std::string_view(storage_.data(), length_);
  }

  [[nodiscard]] std::string str() const { return std::string(view()); }

  [[nodiscard]] constexpr const char* data() const noexcept { return storage_.data(); }

  [[nodiscard]] friend constexpr bool operator==(const StrongId& a, const StrongId& b) noexcept {
    if (a.length_ != b.length_) {
      return false;
    }
    for (std::size_t i = 0; i < a.length_; ++i) {
      if (a.storage_[i] != b.storage_[i]) {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] friend constexpr bool operator!=(const StrongId& a, const StrongId& b) noexcept {
    return !(a == b);
  }

  // Deterministic ordering: byte-wise lexicographic, shorter prefix first. This
  // ordering is the canonical tie-break of the whole runtime.
  [[nodiscard]] friend constexpr bool operator<(const StrongId& a, const StrongId& b) noexcept {
    const std::size_t common = a.length_ < b.length_ ? a.length_ : b.length_;
    for (std::size_t i = 0; i < common; ++i) {
      if (a.storage_[i] != b.storage_[i]) {
        return a.storage_[i] < b.storage_[i];
      }
    }
    return a.length_ < b.length_;
  }

  [[nodiscard]] friend constexpr bool operator>(const StrongId& a, const StrongId& b) noexcept {
    return b < a;
  }
  [[nodiscard]] friend constexpr bool operator<=(const StrongId& a, const StrongId& b) noexcept {
    return !(b < a);
  }
  [[nodiscard]] friend constexpr bool operator>=(const StrongId& a, const StrongId& b) noexcept {
    return !(a < b);
  }

  [[nodiscard]] std::uint64_t hash() const noexcept {
    std::uint64_t state = 14695981039346656037ULL;
    for (std::size_t i = 0; i < length_; ++i) {
      state ^= static_cast<std::uint64_t>(static_cast<unsigned char>(storage_[i]));
      state *= 1099511628211ULL;
    }
    return state;
  }

 private:
  std::array<char, max_length> storage_{};
  std::uint16_t length_ = 0;
};

template <class Tag>
std::ostream& operator<<(std::ostream& stream, const StrongId<Tag>& id) {
  stream << id.view();
  return stream;
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

// Monotonic, non-wrapping generation counter. Zero is invalid: the first
// generation of any object is 1. Advancement is checked, so an exhausted
// counter produces a structured rejection instead of wrapping to zero.
template <class Tag>
class Generation {
 public:
  using value_type = std::uint64_t;
  static constexpr std::string_view domain_name = Tag::name;

  constexpr Generation() noexcept = default;

  [[nodiscard]] static constexpr std::optional<Generation> from_value(std::uint64_t value) noexcept {
    if (value == 0) {
      return std::nullopt;
    }
    Generation result;
    result.value_ = value;
    return result;
  }

  [[nodiscard]] static constexpr Generation require(std::uint64_t value) {
    const auto parsed = from_value(value);
    if (!parsed.has_value()) {
      throw IdError("zero is not a valid " + std::string(domain_name));
    }
    return *parsed;
  }

  [[nodiscard]] static constexpr Generation first() noexcept {
    Generation result;
    result.value_ = 1;
    return result;
  }

  [[nodiscard]] constexpr bool valid() const noexcept { return value_ != 0; }
  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }

  [[nodiscard]] constexpr std::optional<Generation> next() const noexcept {
    if (value_ == (std::numeric_limits<std::uint64_t>::max)()) {
      return std::nullopt;
    }
    return from_value(value_ + 1);
  }

  [[nodiscard]] friend constexpr bool operator==(Generation a, Generation b) noexcept {
    return a.value_ == b.value_;
  }
  [[nodiscard]] friend constexpr bool operator!=(Generation a, Generation b) noexcept {
    return a.value_ != b.value_;
  }
  [[nodiscard]] friend constexpr bool operator<(Generation a, Generation b) noexcept {
    return a.value_ < b.value_;
  }
  [[nodiscard]] friend constexpr bool operator>(Generation a, Generation b) noexcept {
    return a.value_ > b.value_;
  }
  [[nodiscard]] friend constexpr bool operator<=(Generation a, Generation b) noexcept {
    return a.value_ <= b.value_;
  }
  [[nodiscard]] friend constexpr bool operator>=(Generation a, Generation b) noexcept {
    return a.value_ >= b.value_;
  }

 private:
  std::uint64_t value_ = 0;
};

template <class Tag>
std::ostream& operator<<(std::ostream& stream, const Generation<Tag>& generation) {
  if (!generation.valid()) {
    stream << "<invalid>";
  } else {
    stream << generation.value();
  }
  return stream;
}

// ---------------------------------------------------------------------------
// Watermark
// ---------------------------------------------------------------------------

// Monotonic invalidation watermark. Unlike a generation, watermark zero is
// meaningful: it is the state of a record that has never been invalidated. An
// evaluation ticket records the watermarks it observed; commit rejects when any
// observed watermark has advanced, which is what prevents a slow evaluation
// from resurrecting an invalidated dependency.
class Watermark {
 public:
  constexpr Watermark() noexcept = default;
  explicit constexpr Watermark(std::uint64_t value) noexcept : value_(value) {}

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }

  [[nodiscard]] constexpr std::optional<Watermark> next() const noexcept {
    if (value_ == (std::numeric_limits<std::uint64_t>::max)()) {
      return std::nullopt;
    }
    return Watermark(value_ + 1);
  }

  [[nodiscard]] friend constexpr bool operator==(Watermark a, Watermark b) noexcept {
    return a.value_ == b.value_;
  }
  [[nodiscard]] friend constexpr bool operator!=(Watermark a, Watermark b) noexcept {
    return a.value_ != b.value_;
  }
  [[nodiscard]] friend constexpr bool operator<(Watermark a, Watermark b) noexcept {
    return a.value_ < b.value_;
  }
  [[nodiscard]] friend constexpr bool operator<=(Watermark a, Watermark b) noexcept {
    return a.value_ <= b.value_;
  }
  [[nodiscard]] friend constexpr bool operator>(Watermark a, Watermark b) noexcept {
    return a.value_ > b.value_;
  }
  [[nodiscard]] friend constexpr bool operator>=(Watermark a, Watermark b) noexcept {
    return a.value_ >= b.value_;
  }

 private:
  std::uint64_t value_ = 0;
};

// ---------------------------------------------------------------------------
// Identity domains
// ---------------------------------------------------------------------------

struct AdaptivePolicyIdTag {
  static constexpr std::size_t max_length = 96;
  static constexpr std::string_view name = "AdaptivePolicyId";
};
struct AdaptivePolicyNameTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "AdaptivePolicyName";
};
struct AdaptationDecisionIdTag {
  static constexpr std::size_t max_length = 96;
  static constexpr std::string_view name = "AdaptationDecisionId";
};
struct TransitionPlanIdTag {
  static constexpr std::size_t max_length = 96;
  static constexpr std::string_view name = "TransitionPlanId";
};
struct EvidenceSourceIdTag {
  static constexpr std::size_t max_length = 96;
  static constexpr std::string_view name = "EvidenceSourceId";
};
struct EvidenceSnapshotIdTag {
  static constexpr std::size_t max_length = 96;
  static constexpr std::string_view name = "EvidenceSnapshotId";
};
struct FabricIdTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "FabricId";
};
struct RoutingNamespaceTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "RoutingNamespace";
};
struct SiteIdTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "SiteId";
};
struct PathClassTag {
  static constexpr std::size_t max_length = 32;
  static constexpr std::string_view name = "PathClass";
};
struct PathIdTag {
  static constexpr std::size_t max_length = 128;
  static constexpr std::string_view name = "PathId";
};
struct MultipathSetIdTag {
  static constexpr std::size_t max_length = 96;
  static constexpr std::string_view name = "MultipathSetId";
};
struct WeightedPathSetIdTag {
  static constexpr std::size_t max_length = 96;
  static constexpr std::string_view name = "WeightedPathSetId";
};
struct RouteIdTag {
  static constexpr std::size_t max_length = 96;
  static constexpr std::string_view name = "RouteId";
};
struct PublisherIdTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "PublisherId";
};
struct WorkerBootIdTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "WorkerBootId";
};
struct MutationAttemptIdTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "MutationAttemptId";
};
struct RevalidationAttemptIdTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "RevalidationAttemptId";
};
struct SessionIdTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "SessionId";
};
struct RequestIdTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "RequestId";
};
struct SnapshotIdTag {
  static constexpr std::size_t max_length = 96;
  static constexpr std::string_view name = "SnapshotId";
};
struct EvaluationIdTag {
  static constexpr std::size_t max_length = 64;
  static constexpr std::string_view name = "EvaluationId";
};

struct AdaptivePolicyGenerationTag {
  static constexpr std::string_view name = "AdaptivePolicyGeneration";
};
struct AdaptationGenerationTag {
  static constexpr std::string_view name = "AdaptationGeneration";
};
struct TransitionGenerationTag {
  static constexpr std::string_view name = "TransitionGeneration";
};
struct EvidenceGenerationTag {
  static constexpr std::string_view name = "EvidenceGeneration";
};
struct EvidenceSourceGenerationTag {
  static constexpr std::string_view name = "EvidenceSourceGeneration";
};
struct PathAuthorityGenerationTag {
  static constexpr std::string_view name = "PathAuthorityGeneration";
};
struct MultipathSetGenerationTag {
  static constexpr std::string_view name = "MultipathSetGeneration";
};
struct WeightPolicyGenerationTag {
  static constexpr std::string_view name = "WeightPolicyGeneration";
};
struct RouteGenerationTag {
  static constexpr std::string_view name = "RouteGeneration";
};
struct AdaptiveAuthorityGenerationTag {
  static constexpr std::string_view name = "AdaptiveAuthorityGeneration";
};
struct CoordinatorEpochTag {
  static constexpr std::string_view name = "CoordinatorEpoch";
};
struct PolicySemanticsVersionTag {
  static constexpr std::string_view name = "PolicySemanticsVersion";
};

using AdaptivePolicyId = StrongId<AdaptivePolicyIdTag>;
using AdaptivePolicyName = StrongId<AdaptivePolicyNameTag>;
using AdaptationDecisionId = StrongId<AdaptationDecisionIdTag>;
using TransitionPlanId = StrongId<TransitionPlanIdTag>;
using EvidenceSourceId = StrongId<EvidenceSourceIdTag>;
using EvidenceSnapshotId = StrongId<EvidenceSnapshotIdTag>;
using FabricId = StrongId<FabricIdTag>;
using RoutingNamespace = StrongId<RoutingNamespaceTag>;
using SiteId = StrongId<SiteIdTag>;
using PathClass = StrongId<PathClassTag>;
using PathId = StrongId<PathIdTag>;
using MultipathSetId = StrongId<MultipathSetIdTag>;
using WeightedPathSetId = StrongId<WeightedPathSetIdTag>;
using RouteId = StrongId<RouteIdTag>;
using PublisherId = StrongId<PublisherIdTag>;
using WorkerBootId = StrongId<WorkerBootIdTag>;
using MutationAttemptId = StrongId<MutationAttemptIdTag>;
using RevalidationAttemptId = StrongId<RevalidationAttemptIdTag>;
using SessionId = StrongId<SessionIdTag>;
using RequestId = StrongId<RequestIdTag>;
using SnapshotId = StrongId<SnapshotIdTag>;
using EvaluationId = StrongId<EvaluationIdTag>;

using AdaptivePolicyGeneration = Generation<AdaptivePolicyGenerationTag>;
using AdaptationGeneration = Generation<AdaptationGenerationTag>;
using TransitionGeneration = Generation<TransitionGenerationTag>;
using EvidenceGeneration = Generation<EvidenceGenerationTag>;
using EvidenceSourceGeneration = Generation<EvidenceSourceGenerationTag>;
using PathAuthorityGeneration = Generation<PathAuthorityGenerationTag>;
using MultipathSetGeneration = Generation<MultipathSetGenerationTag>;
using WeightPolicyGeneration = Generation<WeightPolicyGenerationTag>;
using RouteGeneration = Generation<RouteGenerationTag>;
using AdaptiveAuthorityGeneration = Generation<AdaptiveAuthorityGenerationTag>;
using CoordinatorEpoch = Generation<CoordinatorEpochTag>;

// ---------------------------------------------------------------------------
// Identity generation
// ---------------------------------------------------------------------------

// Produces fresh, process-unique identities with a caller supplied prefix.
// Uniqueness across processes comes from a process nonce, within a process from
// a monotonic counter. Identity *values* are not required to be deterministic;
// their *encoding* is.
class IdFactory {
 public:
  explicit IdFactory(std::string prefix);

  [[nodiscard]] AdaptivePolicyId next_policy_id() noexcept;
  [[nodiscard]] AdaptationDecisionId next_decision_id() noexcept;
  [[nodiscard]] TransitionPlanId next_transition_id() noexcept;
  [[nodiscard]] EvidenceSourceId next_evidence_source_id() noexcept;
  [[nodiscard]] EvidenceSnapshotId next_evidence_snapshot_id() noexcept;
  [[nodiscard]] SnapshotId next_snapshot_id() noexcept;
  [[nodiscard]] WorkerBootId next_worker_boot_id() noexcept;
  [[nodiscard]] SessionId next_session_id() noexcept;
  [[nodiscard]] EvaluationId next_evaluation_id() noexcept;

  [[nodiscard]] const std::string& prefix() const noexcept { return prefix_; }

 private:
  [[nodiscard]] std::string compose(std::string_view kind, std::uint64_t counter) const;

  std::string prefix_;
  std::string nonce_;
  std::uint64_t counter_ = 0;
};

// Process-wide nonce, stable for the lifetime of the process.
[[nodiscard]] const std::string& process_nonce();

}  // namespace adaptive_routing

namespace std {

template <class Tag>
struct hash<adaptive_routing::StrongId<Tag>> {
  [[nodiscard]] std::size_t operator()(const adaptive_routing::StrongId<Tag>& id) const noexcept {
    return static_cast<std::size_t>(id.hash());
  }
};

template <class Tag>
struct hash<adaptive_routing::Generation<Tag>> {
  [[nodiscard]] std::size_t operator()(
      const adaptive_routing::Generation<Tag>& generation) const noexcept {
    return static_cast<std::size_t>(generation.value() * 1099511628211ULL);
  }
};

}  // namespace std

#endif  // ADAPTIVE_ROUTING_IDS_HPP

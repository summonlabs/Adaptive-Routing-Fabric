// Adaptive Routing Fabric 1.0.0 -- Summon Software Labs.
//
// Central version declaration. The library version, the installed CMake package
// version and the CLI version all derive from this single header so that they
// cannot drift apart. The representation versions below are versioned
// independently: a product release does not automatically change the on-disk
// format, the wire protocol, the policy semantics, the scoring algorithm or the
// digest encoding.
#ifndef ADAPTIVE_ROUTING_VERSION_HPP
#define ADAPTIVE_ROUTING_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace adaptive_routing {

inline constexpr std::uint32_t version_major = 1;
inline constexpr std::uint32_t version_minor = 0;
inline constexpr std::uint32_t version_patch = 0;

// Semantic version of the library, the CMake package and the CLI.
inline constexpr std::string_view version_string = "1.0.0";

// Persistence format version. On-disk records carry their own compatibility
// contract and are rejected when the format version does not match exactly.
inline constexpr std::uint32_t persistence_format_version = 1;

// Wire protocol version. A peer that announces any other version is rejected
// before a single message body is interpreted.
inline constexpr std::uint16_t wire_protocol_version = 1;

// Policy semantics version. Every persisted and every wire-carried policy binds
// the semantics version it was authored under. A policy authored under a
// different semantics version is never silently reinterpreted.
inline constexpr std::uint32_t policy_semantics_version = 1;

// Scoring algorithm version. Adaptations that use the weighted objective bind
// the formula version they were computed with, so decisions produced by
// different formulas never compare as identical authority.
inline constexpr std::uint32_t scoring_algorithm_version = 1;

// Semantic/decision digest encoding version.
inline constexpr std::uint32_t digest_encoding_version = 1;

// Stable textual product identity used by the CLI and by diagnostics.
inline constexpr std::string_view product_name = "Adaptive Routing Fabric";

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_VERSION_HPP

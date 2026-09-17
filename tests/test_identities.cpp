// Identity, generation, watermark and factory contracts.
//
// Ordering, hashing, the checked generation advance and the process nonce are
// the foundations every canonical tie-break and digest in the runtime rests on,
// so the cases below pin the exact encoding rules instead of restating the
// header prose.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <vector>

#include "adaptive_routing/adaptive_routing.hpp"
#include "test_framework.hpp"

namespace {

using namespace adaptive_routing;

// Encodings that must be accepted. The production implementation is
// deliberately not reused: an accidentally loosened charset has to fail here.
[[nodiscard]] std::vector<std::string> accepted_path_ids() {
  return {"a",
          "Z",
          "0",
          "9",
          "path-1",
          "A.B_c-d:e@f#g+h/i",
          "a.b",
          "a_b",
          "a:b",
          "a@b",
          "a#b",
          "a+b",
          "a/b",
          "AbC123xyz",
          std::string(PathId::max_length, 'x')};
}

// Encodings that must be rejected, one case per documented rule.
[[nodiscard]] std::vector<std::string> rejected_path_ids() {
  std::vector<std::string> cases;
  cases.emplace_back("");                                           // empty
  cases.emplace_back(std::string(PathId::max_length + 1, 'x'));  // over PathId's bound
  const char* const punctuation[] = {".", "-", ":", "@", "#", "+", "/", "_"};
  for (const char* symbol : punctuation) {
    cases.emplace_back(std::string(symbol) + "abc");  // leading punctuation
    cases.emplace_back(std::string("abc") + symbol);  // trailing punctuation
    cases.emplace_back(symbol);                       // punctuation only
  }
  const char illegal[] = {' ', '\t',  '\n', '!', '"', '*', '(', ')', '\\', '|', '~', '^', '=',
                          ',', ';',   '[',  ']', '{', '}', '<', '>', '?',  '%', '&', '$', '\'',
                          '\x60'};
  for (const char symbol : illegal) {
    cases.emplace_back(std::string("a") + symbol + "b");
  }
  cases.emplace_back(" leading-space");
  cases.emplace_back("trailing-space ");
  cases.emplace_back("\xC3\xA9");  // non-ASCII: a multi-byte UTF-8 sequence
  return cases;
}

// Independent byte-wise comparison used to cross-check the canonical ordering.
[[nodiscard]] bool byte_wise_less(std::string_view left, std::string_view right) {
  const std::size_t common = left.size() < right.size() ? left.size() : right.size();
  for (std::size_t index = 0; index < common; ++index) {
    const auto a = static_cast<unsigned char>(left[index]);
    const auto b = static_cast<unsigned char>(right[index]);
    if (a != b) {
      return a < b;
    }
  }
  return left.size() < right.size();
}

void check_order(std::string_view lesser, std::string_view greater) {
  const auto left = PathId::parse(lesser);
  const auto right = PathId::parse(greater);
  ARF_REQUIRE(left.has_value() && right.has_value());
  ARF_CHECK_MSG(*left < *right, "expected " << lesser << " < " << greater);
  ARF_CHECK_MSG(*right > *left, "expected " << greater << " > " << lesser);
  ARF_CHECK_MSG(*left <= *right, "expected " << lesser << " <= " << greater);
  ARF_CHECK_MSG(*right >= *left, "expected " << greater << " >= " << lesser);
  ARF_CHECK_MSG(!(*right < *left), "expected !(" << greater << " < " << lesser << ")");
  ARF_CHECK_MSG(!(*left == *right), "expected " << lesser << " != " << greater);
}

}  // namespace

ARF_TEST(strong_id_parse_accepts_documented_charset) {
  for (const std::string& text : accepted_path_ids()) {
    const auto parsed = PathId::parse(text);
    ARF_REQUIRE_MSG(parsed.has_value(), "expected " << text << " to parse");
    ARF_CHECK_MSG(parsed->valid(), "parsed identity must be valid: " << text);
    ARF_CHECK_MSG(parsed->view() == std::string_view(text), "view must round-trip: " << text);
    ARF_CHECK_EQ(parsed->size(), text.size());
    ARF_CHECK_EQ(parsed->str(), text);
    // parse() and require() must agree, otherwise the throwing factory would be
    // a second, divergent validation path.
    ARF_CHECK_EQ(PathId::require(text), *parsed);
  }
  // The bound belongs to the domain, not to a shared encoding helper.
  ARF_CHECK_EQ(PathId::max_length, static_cast<std::size_t>(128));
  ARF_CHECK_EQ(PathClass::max_length, static_cast<std::size_t>(32));
  ARF_CHECK_EQ(FabricId::max_length, static_cast<std::size_t>(64));
}

ARF_TEST(strong_id_parse_rejects_malformed_encodings) {
  for (const std::string& text : rejected_path_ids()) {
    ARF_CHECK_MSG(!PathId::parse(text).has_value(), "expected rejection of [" << text << "]");
    bool threw = false;
    try {
      const PathId required = PathId::require(text);
      ARF_CHECK_MSG(!required.valid(),
                    "require() must not yield a valid identity for [" << text << "]");
    } catch (const IdError&) {
      threw = true;
    }
    ARF_CHECK_MSG(threw, "require() must throw for [" << text << "]");
  }
  // The bound is per domain: a 33 character encoding fits PathId, whose bound
  // is 128, but not a domain whose declared maximum is 32.
  const std::string thirty_three(PathClass::max_length + 1, 'x');
  ARF_CHECK(PathId::parse(thirty_three).has_value());
  ARF_CHECK(!PathClass::parse(thirty_three).has_value());
  ARF_CHECK(!FabricId::parse(std::string(FabricId::max_length + 1, 'x')).has_value());
  ARF_CHECK(PathClass::parse(std::string(PathClass::max_length, 'x')).has_value());
  ARF_CHECK(FabricId::parse(std::string(FabricId::max_length, 'x')).has_value());

  // A default constructed identity carries no text at all and is never valid.
  const PathId empty;
  ARF_CHECK(!empty.valid());
  ARF_CHECK_EQ(empty.size(), static_cast<std::size_t>(0));
  ARF_CHECK_EQ(empty.view(), std::string_view());
  static_assert(std::is_base_of_v<std::invalid_argument, IdError>);
}

ARF_TEST(strong_id_ordering_is_byte_wise_lexicographic) {
  check_order("a", "b");
  check_order("a", "aa");  // a shorter prefix sorts first
  check_order("ab", "abc");
  check_order("path-1", "path-10");
  check_order("path-1", "path-2");
  check_order("path-10", "path-2");  // byte order, not numeric order
  check_order("Z", "a");             // ASCII code order, not case-insensitive
  check_order("0", "A");
  check_order("9", "A");
  check_order("A", "Z");
  check_order("a-b", "a.b");  // '-' is 0x2D, '.' is 0x2E

  // An invalid default identity has no bytes, so it sorts before every encoding.
  const PathId empty;
  const PathId any = PathId::require("a");
  ARF_CHECK_MSG(empty < any, "an empty identity must sort before any real one");
  ARF_CHECK(empty == PathId());
  ARF_CHECK(!(empty == any));
}

ARF_TEST(strong_id_ordering_is_total) {
  const std::vector<std::string> texts = {"z",      "a",    "A",     "0",    "path-10", "path-1",
                                          "path-2", "a.b",  "a_b",   "a-b",  "abcdef",  "abc",
                                          "ZZ",     "zz"};
  std::vector<PathId> ids;
  std::set<std::string> distinct;
  for (const std::string& text : texts) {
    const PathId id = PathId::require(text);
    ids.push_back(id);
    distinct.insert(id.str());
  }
  ARF_CHECK_EQ(distinct.size(), texts.size());

  for (const PathId& id : ids) {
    ARF_CHECK_MSG(!(id < id), "irreflexive ordering violated by " << id);
  }
  for (const PathId& a : ids) {
    for (const PathId& b : ids) {
      // Trichotomy: exactly one of less, equal or greater holds for any pair.
      const int holds = (a < b ? 1 : 0) + (a == b ? 1 : 0) + (a > b ? 1 : 0);
      ARF_CHECK_MSG(holds == 1, "trichotomy violated for " << a << " and " << b);
      ARF_CHECK_MSG((a <= b) == !(b < a), "<= disagrees with < for " << a << " and " << b);
      for (const PathId& c : ids) {
        if (a < b && b < c) {
          ARF_CHECK_MSG(a < c, "transitivity violated: " << a << " < " << b << " < " << c);
        }
      }
    }
  }

  // Sorting must reproduce the independent byte-wise order exactly.
  std::vector<PathId> sorted = ids;
  std::sort(sorted.begin(), sorted.end());
  std::vector<PathId> reference = ids;
  std::sort(reference.begin(), reference.end(), [](const PathId& a, const PathId& b) {
    return byte_wise_less(a.view(), b.view());
  });
  ARF_REQUIRE(sorted.size() == reference.size());
  for (std::size_t index = 0; index < sorted.size(); ++index) {
    ARF_CHECK_MSG(sorted[index] == reference[index],
                  "canonical order differs at index " << index << ": " << sorted[index]
                                                      << " vs " << reference[index]);
  }
}

ARF_TEST(strong_id_hash_agrees_with_equality) {
  const PathId id = PathId::require("path-17");
  const PathId same_text = PathId::require("path-17");
  const PathId other_text = PathId::require("path-18");
  ARF_CHECK(id == same_text);
  ARF_CHECK_EQ(id.hash(), same_text.hash());
  ARF_CHECK_EQ(std::hash<PathId>{}(id), static_cast<std::size_t>(id.hash()));
  ARF_CHECK_MSG(id.hash() != other_text.hash(),
                "distinct encodings collided: " << id << " and " << other_text);

  // A hash container must collapse equal texts and keep distinct ones apart.
  std::unordered_set<PathId> unique;
  unique.insert(id);
  unique.insert(same_text);
  unique.insert(other_text);
  ARF_CHECK_EQ(unique.size(), static_cast<std::size_t>(2));
  ARF_CHECK_EQ(unique.count(id), static_cast<std::size_t>(1));
  ARF_CHECK_EQ(unique.count(PathId::require("path-18")), static_cast<std::size_t>(1));
  ARF_CHECK_EQ(unique.count(PathId::require("path-19")), static_cast<std::size_t>(0));

  // Every accepted encoding in the sample hashes distinctly, which is what lets
  // the runtime key canonical sets by identity hash.
  std::set<std::uint64_t> hashes;
  for (const std::string& text : accepted_path_ids()) {
    hashes.insert(PathId::require(text).hash());
  }
  ARF_CHECK_EQ(hashes.size(), accepted_path_ids().size());
}

ARF_TEST(generation_rejects_zero_and_never_wraps) {
  const EvidenceGeneration unset;
  ARF_CHECK(!unset.valid());
  ARF_CHECK(!EvidenceGeneration::from_value(0).has_value());

  const EvidenceGeneration first = EvidenceGeneration::first();
  ARF_CHECK(first.valid());
  ARF_CHECK_EQ(first.value(), 1ULL);

  const auto second = first.next();
  ARF_REQUIRE(second.has_value());
  ARF_CHECK_EQ(second->value(), 2ULL);
  ARF_CHECK(first < *second);

  bool threw = false;
  try {
    const EvidenceGeneration rejected = EvidenceGeneration::require(0);
    ARF_CHECK_MSG(!rejected.valid(), "zero must never produce a valid generation");
  } catch (const IdError&) {
    threw = true;
  }
  ARF_CHECK(threw);

  const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
  const auto top = EvidenceGeneration::from_value(maximum);
  ARF_REQUIRE(top.has_value());
  ARF_CHECK_EQ(top->value(), maximum);
  // The checked advance is the whole point of Generation: an exhausted counter
  // reports "no next" instead of wrapping to zero.
  ARF_CHECK_MSG(!top->next().has_value(), "an exhausted generation must have no successor");

  const auto penultimate = EvidenceGeneration::from_value(maximum - 1ULL);
  ARF_REQUIRE(penultimate.has_value());
  const auto last = penultimate->next();
  ARF_REQUIRE(last.has_value());
  ARF_CHECK_EQ(last->value(), maximum);
  ARF_CHECK(!last->next().has_value());

  std::ostringstream stream;
  stream << unset;
  ARF_CHECK_EQ(stream.str(), std::string("<invalid>"));
}

ARF_TEST(watermark_accepts_zero_and_advances_monotonically) {
  const Watermark never_invalidated;
  ARF_CHECK_EQ(never_invalidated.value(), 0ULL);
  ARF_CHECK_EQ(Watermark(0).value(), 0ULL);
  ARF_CHECK(never_invalidated == Watermark(0));

  Watermark current = never_invalidated;
  std::uint64_t previous = current.value();
  for (int step = 0; step < 64; ++step) {
    const auto advanced = current.next();
    ARF_REQUIRE(advanced.has_value());
    ARF_CHECK_MSG(advanced->value() > previous,
                  "watermark must advance: " << advanced->value() << " after " << previous);
    ARF_CHECK_EQ(advanced->value(), previous + 1ULL);
    previous = advanced->value();
    current = *advanced;
  }
  ARF_CHECK_EQ(current.value(), 64ULL);

  ARF_CHECK(Watermark(6) < Watermark(7));
  ARF_CHECK(Watermark(7) == Watermark(7));
  ARF_CHECK(Watermark(8) > Watermark(7));
  ARF_CHECK(Watermark(7) <= Watermark(7));
  ARF_CHECK(Watermark(7) >= Watermark(7));
  ARF_CHECK(Watermark(7) != Watermark(8));

  const Watermark maximum(std::numeric_limits<std::uint64_t>::max());
  ARF_CHECK_MSG(!maximum.next().has_value(), "an exhausted watermark must have no successor");
  const auto from_zero = Watermark(0).next();
  ARF_REQUIRE(from_zero.has_value());
  ARF_CHECK_EQ(from_zero->value(), 1ULL);
}

ARF_TEST(id_factory_produces_valid_distinct_identities) {
  IdFactory factory("arf-test");
  ARF_CHECK_EQ(factory.prefix(), std::string("arf-test"));
  ARF_CHECK(!process_nonce().empty());

  const std::size_t per_domain = 64;
  std::set<std::string> encoded;
  for (std::size_t index = 0; index < per_domain; ++index) {
    const AdaptivePolicyId policy = factory.next_policy_id();
    const AdaptationDecisionId decision = factory.next_decision_id();
    const TransitionPlanId transition = factory.next_transition_id();
    const EvidenceSourceId source = factory.next_evidence_source_id();
    const EvidenceSnapshotId evidence_snapshot = factory.next_evidence_snapshot_id();
    const SnapshotId snapshot = factory.next_snapshot_id();
    const WorkerBootId boot = factory.next_worker_boot_id();
    const SessionId session = factory.next_session_id();
    const EvaluationId evaluation = factory.next_evaluation_id();

    const std::vector<std::string> texts = {policy.str(),   decision.str(),  transition.str(),
                                            source.str(),   evidence_snapshot.str(),
                                            snapshot.str(), boot.str(),      session.str(),
                                            evaluation.str()};
    for (const std::string& text : texts) {
      ARF_CHECK_MSG(!text.empty(), "the factory minted an empty identity");
      encoded.insert(text);
    }
    // Every domain must be able to read back exactly what it minted.
    ARF_CHECK_EQ(AdaptivePolicyId::parse(policy.view()), policy);
    ARF_CHECK_EQ(AdaptationDecisionId::parse(decision.view()), decision);
    ARF_CHECK_EQ(TransitionPlanId::parse(transition.view()), transition);
    ARF_CHECK_EQ(EvidenceSourceId::parse(source.view()), source);
    ARF_CHECK_EQ(EvidenceSnapshotId::parse(evidence_snapshot.view()), evidence_snapshot);
    ARF_CHECK_EQ(SnapshotId::parse(snapshot.view()), snapshot);
    ARF_CHECK_EQ(WorkerBootId::parse(boot.view()), boot);
    ARF_CHECK_EQ(SessionId::parse(session.view()), session);
    ARF_CHECK_EQ(EvaluationId::parse(evaluation.view()), evaluation);
  }
  // Distinct identities across every domain, not merely within one.
  ARF_CHECK_EQ(encoded.size(), per_domain * static_cast<std::size_t>(9));
  // Uniqueness across processes comes from the nonce, so every minted identity
  // must actually carry it.
  for (const std::string& text : encoded) {
    ARF_CHECK_MSG(text.find(process_nonce()) != std::string::npos,
                  "identity omits the process nonce: " << text);
  }

  // An empty prefix must still compose a valid encoding: it drops the separator
  // rather than emitting a leading dash.
  IdFactory bare("");
  const AdaptivePolicyId bare_policy = bare.next_policy_id();
  ARF_CHECK(bare_policy.valid());
  ARF_CHECK_EQ(bare_policy.str().rfind("policy-", 0), static_cast<std::size_t>(0));
}

ARF_TEST(identity_domains_are_separate_types) {
  const auto path_id = PathId::parse("x");
  const auto route_id = RouteId::parse("x");
  ARF_REQUIRE(path_id.has_value());
  ARF_REQUIRE(route_id.has_value());
  // The same text is a valid encoding in two domains, and the two values are
  // still different types: a PathId can never stand in for a RouteId.
  ARF_CHECK_EQ(path_id->view(), route_id->view());
  ARF_CHECK_EQ(path_id->hash(), route_id->hash());
  ARF_CHECK_EQ(PathId::domain_name, std::string_view("PathId"));
  ARF_CHECK_EQ(RouteId::domain_name, std::string_view("RouteId"));
  ARF_CHECK_MSG(PathId::domain_name != RouteId::domain_name,
                "identity domains must be textually distinguishable");
  static_assert(!std::is_same_v<PathId, RouteId>);
  static_assert(!std::is_convertible_v<PathId, RouteId>);
  static_assert(!std::is_convertible_v<RouteId, PathId>);
  static_assert(!std::is_constructible_v<PathId, RouteId>);
  static_assert(!std::is_assignable_v<PathId&, RouteId>);
  static_assert(!std::is_same_v<FabricId, RoutingNamespace>);
  static_assert(!std::is_convertible_v<FabricId, RoutingNamespace>);
}

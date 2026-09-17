// Time semantics.
//
// Adaptive Routing Fabric decides elapsed-time questions -- evidence age,
// observation windows, hold-down, cooldown, dampening decay and churn windows --
// exclusively from a monotonic tick source. A wall clock is never consulted for
// an elapsed-time decision, so a system-clock jump cannot create or destroy
// adaptation authority.
//
// WALL CLOCK USE
// --------------
// Wall clock time is used in exactly two places, both of them cosmetic:
//   * the CLI renders a human readable timestamp for c state show and
//     c policy show;
//   * diagnostics stamp the log line prefix.
// Neither is ever read back into a decision, a digest or a persisted record.
//
// PERSISTED TIME
// --------------
// Raw monotonic ticks are meaningless across process boots and are never
// serialized. Durable hold-down/cooldown state is persisted as a *remaining*
// duration plus the semantic decision it belongs to (see persistence.hpp); on
// recovery the remaining duration is re-armed against the new boot's monotonic
// clock, which is conservative: it can extend an interval, never shorten it.
#ifndef ADAPTIVE_ROUTING_CLOCK_HPP
#define ADAPTIVE_ROUTING_CLOCK_HPP

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace adaptive_routing {

// Monotonic duration in nanoseconds. The authoritative time unit of the
// runtime. Negative durations are never produced.
using Ticks = std::uint64_t;

inline constexpr Ticks ticks_per_microsecond = 1000ULL;
inline constexpr Ticks ticks_per_millisecond = 1000000ULL;
inline constexpr Ticks ticks_per_second = 1000000000ULL;

[[nodiscard]] constexpr Ticks milliseconds(std::uint64_t value) noexcept {
  return value * ticks_per_millisecond;
}

[[nodiscard]] constexpr Ticks seconds(std::uint64_t value) noexcept {
  return value * ticks_per_second;
}

// Elapsed-time source. Implementations must be monotonic: successive calls
// never return a smaller value.
class Clock {
 public:
  virtual ~Clock() = default;
  [[nodiscard]] virtual Ticks now() const noexcept = 0;
};

// Production clock. Uses std::chrono::steady_clock, which is monotonic and not
// affected by system clock adjustments.
class SteadyClock final : public Clock {
 public:
  [[nodiscard]] Ticks now() const noexcept override;
  [[nodiscard]] static const SteadyClock& instance() noexcept;
};

// Deterministic clock. Time advances only when a caller advances it, so every
// time-sensitive test is exact and no test sleeps to make time pass.
class TestClock final : public Clock {
 public:
  explicit TestClock(Ticks start = ticks_per_second) noexcept : now_(start) {}

  [[nodiscard]] Ticks now() const noexcept override { return now_; }

  void advance(Ticks delta) noexcept { now_ += delta; }
  void set(Ticks value) noexcept { now_ = value; }

 private:
  Ticks now_;
};

// Wall clock rendering for operator-facing output only. Never an input to a
// decision.
[[nodiscard]] std::string render_wall_clock_now();

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_CLOCK_HPP

// Clock implementations and wall-clock rendering.
#include "adaptive_routing/clock.hpp"

#include <chrono>
#include <ctime>
#include <cstdio>

namespace adaptive_routing {

Ticks SteadyClock::now() const noexcept {
  const auto value = std::chrono::steady_clock::now().time_since_epoch();
  const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(value).count();
  return nanos <= 0 ? 0 : static_cast<Ticks>(nanos);
}

const SteadyClock& SteadyClock::instance() noexcept {
  static const SteadyClock clock;
  return clock;
}

std::string render_wall_clock_now() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
  std::tm parts{};
#if defined(_WIN32)
  if (::gmtime_s(&parts, &seconds) != 0) {
    return std::string("1970-01-01T00:00:00Z");
  }
#else
  if (::gmtime_r(&seconds, &parts) == nullptr) {
    return std::string("1970-01-01T00:00:00Z");
  }
#endif
  char buffer[32];
  if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &parts) == 0) {
    return std::string("1970-01-01T00:00:00Z");
  }
  return std::string(buffer);
}

}  // namespace adaptive_routing

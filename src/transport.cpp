// Socket transport, coordinator server and coordinator client.
//
// PLATFORM ORDERING
// -----------------
// <winsock2.h> must be seen before <windows.h>. On this SDK <winsock2.h> pulls
// <windows.h> in itself, which defines the legacy macro ERROR (wingdi.h) and
// the min/max macros; ERROR would corrupt the frozen ReceiveStatus::ERROR
// enumerator, so it is undef'd again immediately after the platform headers.
//
// BLOCKING DISCIPLINE
// -------------------
// Every wait is bounded by select() driven by the monotonic clock. shutdown()
// is never used to cancel a blocked recv, because on Windows that is not
// reliable: the receive loop polls instead, so a stop flag is observed within
// one poll interval even on a socket that never delivers another byte.
#include "adaptive_routing/version.hpp"
#include "adaptive_routing/transport.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// The Windows SDK's ws2tcpip.h raises the static analyzer's C6101 (a returned
// structure the analyzer considers partially initialized) inside code this
// project does not own and cannot change. The suppression is scoped to exactly
// those two external headers and to that one finding; every first-party line in
// this file is still analyzed at the full level.
#pragma warning(push)
#pragma warning(disable : 6101)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma warning(pop)
// wingdi.h (pulled in through windows.h) defines ERROR as a legacy macro. The
// frozen transport header declares ReceiveStatus::ERROR, so the macro is
// removed here rather than worked around at every use site.
#undef ERROR
#else
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace adaptive_routing {
namespace {

#if defined(_WIN32)
using native_socket = SOCKET;
using socket_length = int;
constexpr native_socket invalid_native_socket = INVALID_SOCKET;
#else
using native_socket = int;
using socket_length = socklen_t;
constexpr native_socket invalid_native_socket = -1;
#endif

// The 20 ms poll interval keeps shutdown responsive: every wait in this file is
// a sequence of select() calls of at most this length, so a stop flag is seen
// quickly without ever blocking indefinitely on a silent peer.
constexpr Ticks poll_interval = 20ULL * ticks_per_millisecond;
// Upper bound of the bytes one receive() call appends, so a peer that streams
// without pause cannot make a single call unbounded. The session loop simply
// calls again.
constexpr std::size_t receive_chunk_bytes = 16U * 1024U;
constexpr std::size_t receive_call_bytes = 1U << 20;
// Per send() syscall slice; keeps the conversion to the platform send length
// well inside its range on every platform.
constexpr std::size_t send_chunk_bytes = 1U << 20;
// Backstop socket timeout for session sockets. send_all/receive gate every call
// on select() first, so this only bounds a call that the kernel makes blocking
// for a reason select() did not predict.
constexpr Ticks socket_timeout_backstop = 30ULL * ticks_per_second;
// A coordinator response that cannot be written within this budget means the
// peer is gone or wedged; the session is abandoned rather than pinned.
constexpr Ticks response_send_budget = 30ULL * ticks_per_second;
// Accept loop poll length: bounds how long stop() waits for the accept thread.
constexpr Ticks accept_poll_budget = 50ULL * ticks_per_millisecond;

// Windows SO_RCVTIMEO/SO_SNDTIMEO take a DWORD of milliseconds where zero means
// "no timeout", so a computed timeout is never allowed to round down to zero.
constexpr std::uint64_t max_timeout_millis = 2147483647ULL;

[[nodiscard]] constexpr Ticks saturating_add(Ticks left, Ticks right) noexcept {
  const Ticks limit = (std::numeric_limits<Ticks>::max)();
  return left > limit - right ? limit : left + right;
}

[[nodiscard]] constexpr Ticks min_ticks(Ticks left, Ticks right) noexcept {
  return left < right ? left : right;
}

// The monotonic clock is the only authority on elapsed time, and a caller may
// legitimately inject a clock that never advances (that is how this runtime
// makes time-sensitive behaviour deterministic). A wait bounded only by such a
// clock would never end, so a wait is additionally abandoned after a few
// consecutive timeouts that observed no clock progress at all. With a real
// clock every poll advances the clock, which resets the counter, so the budget
// alone decides.
class StagnantPollGuard {
 public:
  explicit StagnantPollGuard(const Clock& clock, std::uint32_t limit) noexcept
      : clock_(clock), observed_(clock.now()), limit_(limit) {}

  // Called only after a wait timed out. True means the loop must stop waiting.
  [[nodiscard]] bool exhausted() noexcept {
    const Ticks now = clock_.now();
    if (now != observed_) {
      observed_ = now;
      stagnant_ = 0;
      return false;
    }
    ++stagnant_;
    return stagnant_ >= limit_;
  }

 private:
  const Clock& clock_;
  Ticks observed_;
  std::uint32_t limit_;
  std::uint32_t stagnant_ = 0;
};

// A session thread must observe the stop flag and the accept loop must observe
// it too, so a wait gives up quickly when the injected clock never advances.
constexpr std::uint32_t io_stagnant_polls = 8;
constexpr std::uint32_t accept_stagnant_polls = 2;

[[nodiscard]] constexpr bool native_is_valid(std::uintptr_t raw) noexcept {
  return raw != 0 && raw != static_cast<std::uintptr_t>(invalid_native_socket);
}

[[nodiscard]] constexpr native_socket handle_of(std::uintptr_t raw) noexcept {
  return static_cast<native_socket>(raw);
}

[[nodiscard]] int last_socket_error() noexcept {
#if defined(_WIN32)
  return ::WSAGetLastError();
#else
  return errno;
#endif
}

[[nodiscard]] bool error_is_interrupted(int code) noexcept {
#if defined(_WIN32)
  return code == WSAEINTR;
#else
  return code == EINTR;
#endif
}

[[nodiscard]] bool error_is_would_block(int code) noexcept {
#if defined(_WIN32)
  return code == WSAEWOULDBLOCK;
#else
  return code == EAGAIN || code == EWOULDBLOCK;
#endif
}

[[nodiscard]] bool error_is_connect_pending(int code) noexcept {
#if defined(_WIN32)
  return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS || code == WSAEALREADY;
#else
  return code == EINPROGRESS || code == EALREADY;
#endif
}

// Explicit textual error for every platform failure, so no failure path reports
// a bare "socket error" without saying which one.
[[nodiscard]] std::string socket_error_text(int code) {
#if defined(_WIN32)
  switch (code) {
    case WSAECONNREFUSED:
      return "WSAECONNREFUSED (10061): connection refused";
    case WSAECONNRESET:
      return "WSAECONNRESET (10054): connection reset by peer";
    case WSAECONNABORTED:
      return "WSAECONNABORTED (10053): connection aborted";
    case WSAENOTCONN:
      return "WSAENOTCONN (10057): socket is not connected";
    case WSAETIMEDOUT:
      return "WSAETIMEDOUT (10060): the operation timed out";
    case WSAEHOSTUNREACH:
      return "WSAEHOSTUNREACH (10065): no route to host";
    case WSAEADDRINUSE:
      return "WSAEADDRINUSE (10048): address already in use";
    case WSAEADDRNOTAVAIL:
      return "WSAEADDRNOTAVAIL (10049): address not available";
    case WSAENOTSOCK:
      return "WSAENOTSOCK (10038): the handle is not a socket";
    case WSAEACCES:
      return "WSAEACCES (10013): access denied";
    case WSAEINVAL:
      return "WSAEINVAL (10022): invalid argument";
    case WSAEMFILE:
      return "WSAEMFILE (10024): too many open sockets";
    default:
      break;
  }
  return "winsock error " + std::to_string(code);
#else
  return std::to_string(code) + ": " + std::string(std::strerror(code));
#endif
}

[[nodiscard]] std::string gai_error_text(int code) {
#if defined(_WIN32)
  return std::string(::gai_strerrorA(code));
#else
  return std::string(::gai_strerror(code));
#endif
}

[[nodiscard]] bool set_non_blocking(native_socket handle, bool enabled) noexcept {
#if defined(_WIN32)
  u_long mode = enabled ? 1UL : 0UL;
  return ::ioctlsocket(handle, FIONBIO, &mode) == 0;
#else
  const int current = ::fcntl(handle, F_GETFL, 0);
  if (current < 0) {
    return false;
  }
  const int updated = enabled ? (current | O_NONBLOCK) : (current & ~O_NONBLOCK);
  return ::fcntl(handle, F_SETFL, updated) == 0;
#endif
}

// Rounds up so a timeout never becomes zero, which on Windows means "infinite".
[[nodiscard]] std::uint64_t timeout_millis(Ticks budget) noexcept {
  const std::uint64_t whole = budget / ticks_per_millisecond;
  const std::uint64_t rest = budget % ticks_per_millisecond;
  std::uint64_t millis = whole + (rest == 0 ? 0 : 1);
  if (millis == 0) {
    millis = 1;
  }
  return millis > max_timeout_millis ? max_timeout_millis : millis;
}

void set_socket_timeouts(native_socket handle, Ticks budget) noexcept {
  const std::uint64_t millis = timeout_millis(budget);
#if defined(_WIN32)
  const DWORD value = static_cast<DWORD>(millis);
  const char* data = reinterpret_cast<const char*>(&value);
  const int size = static_cast<int>(sizeof(value));
  (void)::setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, data, size);
  (void)::setsockopt(handle, SOL_SOCKET, SO_SNDTIMEO, data, size);
#else
  timeval value{};
  value.tv_sec = static_cast<long>(millis / 1000ULL);
  value.tv_usec = static_cast<long>((millis % 1000ULL) * 1000ULL);
  (void)::setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value));
  (void)::setsockopt(handle, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value));
#endif
}

void close_native(native_socket handle) noexcept {
#if defined(_WIN32)
  (void)::closesocket(handle);
#else
  (void)::close(handle);
#endif
}

// 1 = ready, 0 = timeout or interrupted, -1 = hard failure.
//
// The error set is watched as well as the read or write set. On Windows a
// socket whose non-blocking connect was refused, and a socket carrying a
// pending error such as a connection reset, are signalled there rather than in
// the read or write set; watching only the latter turns an immediate refusal
// into a reported timeout and hides a reset peer from the receive loop.
[[nodiscard]] int wait_socket(native_socket handle, bool for_read, Ticks timeout) noexcept {
  fd_set set;
  FD_ZERO(&set);
  FD_SET(handle, &set);
  fd_set errors;
  FD_ZERO(&errors);
  FD_SET(handle, &errors);
  timeval limit{};
  limit.tv_sec = static_cast<long>(timeout / ticks_per_second);
  limit.tv_usec = static_cast<long>((timeout % ticks_per_second) / ticks_per_microsecond);
  const int result = ::select(for_read ? static_cast<int>(handle) + 1 : 0,
                              for_read ? &set : nullptr, for_read ? nullptr : &set, &errors,
                              &limit);
  if (result > 0) {
    return 1;
  }
  if (result == 0) {
    return 0;
  }
  return error_is_interrupted(last_socket_error()) ? 0 : -1;
}

// Reads the pending socket error. SO_ERROR is cleared by the read, and zero
// means "no error was recorded".
[[nodiscard]] bool read_pending_socket_error(native_socket handle, int& code) noexcept {
  int value = 0;
  socket_length length = static_cast<socket_length>(sizeof(value));
  if (::getsockopt(handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&value), &length) != 0) {
    return false;
  }
  code = value;
  return true;
}

[[nodiscard]] int send_flags() noexcept {
#if defined(MSG_NOSIGNAL)
  // A peer that vanished must produce an error return, not SIGPIPE.
  return MSG_NOSIGNAL;
#else
  return 0;
#endif
}

struct AddrinfoList {
  addrinfo* head = nullptr;
  AddrinfoList() = default;
  AddrinfoList(const AddrinfoList&) = delete;
  AddrinfoList& operator=(const AddrinfoList&) = delete;
  ~AddrinfoList() {
    if (head != nullptr) {
      ::freeaddrinfo(head);
    }
  }
};

#if defined(_WIN32)
// Winsock is process-global: initialise it exactly once, from whichever thread
// gets there first, and release it when the process exits.
class WinsockRuntime {
 public:
  WinsockRuntime() noexcept {
    WSADATA data{};
    available_ = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }
  ~WinsockRuntime() {
    if (available_) {
      (void)::WSACleanup();
    }
  }
  WinsockRuntime(const WinsockRuntime&) = delete;
  WinsockRuntime& operator=(const WinsockRuntime&) = delete;

  [[nodiscard]] bool available() const noexcept { return available_; }

 private:
  bool available_ = false;
};

[[nodiscard]] bool ensure_winsock() noexcept {
  // Function-local statics are initialised once even under a thread race.
  static WinsockRuntime runtime;
  return runtime.available();
}
#else
[[nodiscard]] bool ensure_winsock() noexcept { return true; }
#endif

// ---------------------------------------------------------------------------
// Identity composition
// ---------------------------------------------------------------------------

// StrongId accepts only letters, digits and . _ - : @ # + /, and requires an
// alphanumeric first and last character. A caller supplied prefix is sanitised
// against that charset before it is used at all.
[[nodiscard]] std::string sanitize_prefix(std::string_view prefix) {
  std::string clean;
  clean.reserve(prefix.size());
  for (const char character : prefix) {
    if (detail::id_char_allowed(character)) {
      clean.push_back(character);
    }
  }
  std::size_t first = 0;
  while (first < clean.size() && !detail::id_edge_char_allowed(clean[first])) {
    ++first;
  }
  clean.erase(0, first);
  return clean;
}

// Composes "<prefix>-<kind>-<nonce>-<counter>" with an explicit length bound.
//
// IdFactory composes the same shape but validates with require(), which throws
// from a noexcept factory; an over-long prefix would therefore terminate the
// process. Here the prefix is truncated first and the nonce is dropped when it
// does not fit, so the identity is always well formed. The nonce is kept
// whenever it fits, which is what makes identities unique across processes.
template <class Tag>
[[nodiscard]] StrongId<Tag> compose_identity(std::string_view prefix, std::string_view kind,
                                             std::uint64_t counter, bool with_nonce) {
  const std::string& nonce = process_nonce();
  const std::string number = std::to_string(counter);
  const std::string clean = sanitize_prefix(prefix);
  const auto assemble = [&](const std::string& head, bool include_nonce) {
    std::string text = head;
    if (!text.empty()) {
      text.push_back('-');
    }
    text.append(kind);
    if (include_nonce) {
      text.push_back('-');
      text.append(nonce);
    }
    text.push_back('-');
    text.append(number);
    return text;
  };
  const auto budget = [&](bool include_nonce) {
    const std::size_t overhead = kind.size() + (include_nonce ? nonce.size() + 1 : 0) +
                                 number.size() + 2;  // two separators
    const std::size_t limit = Tag::max_length;
    return limit > overhead ? limit - overhead : 0;
  };

  std::string text;
  if (with_nonce && budget(true) > 0) {
    std::string head = clean;
    head.resize(std::min(head.size(), budget(true)));
    text = assemble(head, true);
  } else {
    std::string head = clean;
    head.resize(std::min(head.size(), budget(false)));
    text = assemble(head, false);
  }
  const std::optional<StrongId<Tag>> parsed = StrongId<Tag>::parse(text);
  if (parsed.has_value()) {
    return *parsed;
  }
  // Unreachable: the assembled text is charset clean, bounded and ends in a
  // digit. The shorter form is equally valid, so this is not an error path.
  return StrongId<Tag>::require(std::string(kind) + "-" + number);
}

// Mutation attempt identity, deterministic in (session, frame sequence).
[[nodiscard]] MutationAttemptId compose_attempt(const SessionId& session, std::uint64_t sequence) {
  const std::string suffix = "-" + std::to_string(sequence);
  std::string text = session.valid() ? session.str() : std::string("anonymous");
  const std::size_t limit = MutationAttemptId::max_length;
  const std::size_t room = limit > suffix.size() ? limit - suffix.size() : 0;
  if (text.size() > room) {
    text.resize(room);
  }
  text += suffix;
  const std::optional<MutationAttemptId> parsed = MutationAttemptId::parse(text);
  if (parsed.has_value()) {
    return *parsed;
  }
  return MutationAttemptId::require("attempt-" + std::to_string(sequence));
}

[[nodiscard]] Frame make_frame(MessageId id, std::string payload) {
  Frame frame;
  frame.header.wire_version = wire_protocol_version;
  frame.header.message_id = id;
  frame.header.flags = 0;
  frame.header.payload_length = static_cast<std::uint32_t>(payload.size());
  frame.payload = std::move(payload);
  return frame;
}

// One "name=value" free rendering line per policy, used by QUERY_STATE. Sorted
// output is the caller's responsibility; this only fixes the field order.
[[nodiscard]] std::string render_policy_line(const AdaptivePolicy& policy) {
  std::string line = policy.id.str();
  line += " name=";
  line += policy.name.str();
  line += " lifecycle=";
  line += std::string(to_string(policy.lifecycle));
  line += " generation=";
  line += std::to_string(policy.generation.value());
  line += " epoch=";
  line += std::to_string(policy.epoch.value());
  line += " digest=";
  line += policy_semantic_digest(policy);
  return line;
}

}  // namespace

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

std::string Endpoint::render() const {
  // The host is rendered verbatim: it is either a literal address or a name and
  // is never re-parsed out of this string.
  std::string text = host;
  text.push_back(':');
  text += std::to_string(port);
  return text;
}

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : native_(other.native_) { other.native_ = 0; }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    native_ = other.native_;
    other.native_ = 0;
  }
  return *this;
}

bool Socket::valid() const noexcept { return native_is_valid(native_); }

void Socket::close() noexcept {
  if (!native_is_valid(native_)) {
    native_ = 0;
    return;
  }
  const native_socket handle = handle_of(native_);
  // Cleared before the platform close so a re-entrant or repeated close can
  // never close the same handle twice.
  native_ = 0;
  close_native(handle);
}

Socket Socket::adopt(std::uintptr_t native) {
  Socket socket;
  socket.native_ = native;
  return socket;
}

std::uintptr_t Socket::native() const noexcept { return native_; }

void Socket::set_nodelay(bool enabled) noexcept {
  if (!valid()) {
    return;
  }
  const int value = enabled ? 1 : 0;
  (void)::setsockopt(handle_of(native_), IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&value),
                     static_cast<socket_length>(sizeof(value)));
}

std::optional<Socket> Socket::listen(const Endpoint& endpoint, std::string& error) {
  error.clear();
  if (!ensure_winsock()) {
    error = "winsock could not be initialised";
    return std::nullopt;
  }
  AddrinfoList addresses;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  const std::string service = std::to_string(endpoint.port);
  const char* node = endpoint.host.empty() ? nullptr : endpoint.host.c_str();
  const int resolved = ::getaddrinfo(node, service.c_str(), &hints, &addresses.head);
  if (resolved != 0) {
    error = "cannot resolve " + endpoint.render() + ": " + gai_error_text(resolved);
    return std::nullopt;
  }
  std::string last_error;
  for (addrinfo* candidate = addresses.head; candidate != nullptr; candidate = candidate->ai_next) {
    const native_socket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == invalid_native_socket) {
      last_error = socket_error_text(last_socket_error());
      continue;
    }
    const int one = 1;
    (void)::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one),
                       static_cast<socket_length>(sizeof(one)));
    const socket_length address_bytes = static_cast<socket_length>(candidate->ai_addrlen);
    if (::bind(handle, candidate->ai_addr, address_bytes) != 0) {
      last_error = "bind failed: " + socket_error_text(last_socket_error());
      close_native(handle);
      continue;
    }
    if (::listen(handle, SOMAXCONN) != 0) {
      last_error = "listen failed: " + socket_error_text(last_socket_error());
      close_native(handle);
      continue;
    }
    return adopt(static_cast<std::uintptr_t>(handle));
  }
  error = "cannot listen on " + endpoint.render();
  if (!last_error.empty()) {
    error += ": " + last_error;
  }
  return std::nullopt;
}

std::optional<Socket> Socket::accept_one(const Clock& clock, Ticks poll_budget) const {
  if (!valid()) {
    return std::nullopt;
  }
  const native_socket listener = handle_of(native_);
  const Ticks deadline = saturating_add(clock.now(), poll_budget);
  StagnantPollGuard guard(clock, accept_stagnant_polls);
  while (true) {
    const Ticks now = clock.now();
    const int ready = wait_socket(listener, true, now >= deadline ? 0 : deadline - now);
    if (ready < 0) {
      return std::nullopt;
    }
    if (ready == 0) {
      if (clock.now() >= deadline || guard.exhausted()) {
        return std::nullopt;
      }
      continue;
    }
    sockaddr_storage address{};
    socket_length length = static_cast<socket_length>(sizeof(address));
    const native_socket accepted =
        ::accept(listener, reinterpret_cast<sockaddr*>(&address), &length);
    if (accepted == invalid_native_socket) {
      const int code = last_socket_error();
      if (error_is_interrupted(code) || error_is_would_block(code)) {
        continue;
      }
      return std::nullopt;
    }
    set_socket_timeouts(accepted, socket_timeout_backstop);
    Socket socket = adopt(static_cast<std::uintptr_t>(accepted));
    // The protocol is small request/response exchanges; Nagle would only add
    // latency to every round trip.
    socket.set_nodelay(true);
    return socket;
  }
}

std::uint16_t Socket::local_port() const noexcept {
  if (!valid()) {
    return 0;
  }
  sockaddr_storage address{};
  socket_length length = static_cast<socket_length>(sizeof(address));
  if (::getsockname(handle_of(native_), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return 0;
  }
  if (address.ss_family == AF_INET) {
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
    return ntohs(ipv4->sin_port);
  }
  if (address.ss_family == AF_INET6) {
    const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(&address);
    return ntohs(ipv6->sin6_port);
  }
  return 0;
}

std::optional<Socket> Socket::connect(const Endpoint& endpoint, const Clock& clock, Ticks budget,
                                      std::string& error) {
  error.clear();
  if (!ensure_winsock()) {
    error = "winsock could not be initialised";
    return std::nullopt;
  }
  AddrinfoList addresses;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  const std::string service = std::to_string(endpoint.port);
  const char* node = endpoint.host.empty() ? nullptr : endpoint.host.c_str();
  const int resolved = ::getaddrinfo(node, service.c_str(), &hints, &addresses.head);
  if (resolved != 0) {
    error = "cannot resolve " + endpoint.render() + ": " + gai_error_text(resolved);
    return std::nullopt;
  }
  // One budget for the whole call, shared by every candidate address.
  const Ticks deadline = saturating_add(clock.now(), budget);
  std::string last_error;
  for (addrinfo* candidate = addresses.head; candidate != nullptr; candidate = candidate->ai_next) {
    const native_socket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == invalid_native_socket) {
      last_error = socket_error_text(last_socket_error());
      continue;
    }
    if (!set_non_blocking(handle, true)) {
      last_error = "cannot switch the socket to non-blocking mode";
      close_native(handle);
      continue;
    }
    bool connected = ::connect(handle, candidate->ai_addr,
                               static_cast<socket_length>(candidate->ai_addrlen)) == 0;
    if (!connected) {
      const int code = last_socket_error();
      if (!error_is_connect_pending(code)) {
        last_error = "connect failed: " + socket_error_text(code);
        close_native(handle);
        continue;
      }
      // Bounded wait for the handshake to finish, polled so the budget is
      // honoured exactly.
      StagnantPollGuard guard(clock, io_stagnant_polls);
      while (true) {
        const Ticks now = clock.now();
        const Ticks wait = now >= deadline ? 0 : min_ticks(deadline - now, poll_interval);
        const int ready = wait_socket(handle, false, wait);
        if (ready < 0) {
          last_error = "connect wait failed: " + socket_error_text(last_socket_error());
          break;
        }
        if (ready == 0) {
          if (clock.now() >= deadline || guard.exhausted()) {
            // A connect that already failed may still be reported here, so the
            // recorded outcome is preferred over a bare timeout.
            int pending = 0;
            if (read_pending_socket_error(handle, pending) && pending != 0) {
              last_error = "connect failed: " + socket_error_text(pending);
            } else {
              last_error = "connect timed out after " +
                           std::to_string(budget / ticks_per_millisecond) + " ms";
            }
            break;
          }
          continue;
        }
        int pending = 0;
        if (!read_pending_socket_error(handle, pending)) {
          last_error =
              "connect status could not be read: " + socket_error_text(last_socket_error());
          break;
        }
        if (pending == 0) {
          connected = true;
        } else {
          last_error = "connect failed: " + socket_error_text(pending);
        }
        break;
      }
    }
    if (!connected) {
      close_native(handle);
      continue;
    }
    if (!set_non_blocking(handle, false)) {
      last_error = "cannot restore blocking mode";
      close_native(handle);
      continue;
    }
    // The connect budget doubles as the per-call I/O timeout, so a peer that
    // accepts the connection and then stops reading cannot block a later send
    // indefinitely.
    set_socket_timeouts(handle, budget == 0 ? socket_timeout_backstop : budget);
    Socket socket = adopt(static_cast<std::uintptr_t>(handle));
    socket.set_nodelay(true);
    return socket;
  }
  error = "cannot connect to " + endpoint.render();
  if (!last_error.empty()) {
    error += ": " + last_error;
  }
  return std::nullopt;
}

bool Socket::send_all(std::string_view bytes, const Clock& clock, Ticks budget,
                      std::string& error) {
  error.clear();
  if (!valid()) {
    error = "cannot send on a socket that is not open";
    return false;
  }
  if (bytes.empty()) {
    return true;
  }
  const native_socket handle = handle_of(native_);
  const Ticks deadline = saturating_add(clock.now(), budget);
  // Non-blocking for the duration of the call: the loop then honours the budget
  // exactly instead of relying on SO_SNDTIMEO. A socket is owned by exactly one
  // thread here, so the temporary mode change cannot race.
  const bool switched = set_non_blocking(handle, true);
  std::size_t offset = 0;
  bool attempted = false;
  StagnantPollGuard guard(clock, io_stagnant_polls);
  while (offset < bytes.size()) {
    const Ticks now = clock.now();
    if (attempted && now >= deadline) {
      error = "send timed out after " + std::to_string(budget / ticks_per_millisecond) +
              " ms with " + std::to_string(bytes.size() - offset) + " bytes unsent";
      break;
    }
    // Every wait is a short poll, so a stalled peer is observed promptly even
    // while the socket send buffer stays full.
    const Ticks wait = now >= deadline ? 0 : min_ticks(deadline - now, poll_interval);
    const int ready = wait_socket(handle, false, wait);
    if (ready < 0) {
      error = "send wait failed: " + socket_error_text(last_socket_error());
      break;
    }
    if (ready == 0) {
      if (guard.exhausted()) {
        error = "send timed out: the socket stayed unwritable and the clock made no progress";
        break;
      }
      continue;
    }
    attempted = true;
    const std::size_t pending = bytes.size() - offset;
    const std::size_t chunk = pending > send_chunk_bytes ? send_chunk_bytes : pending;
    const int written =
        ::send(handle, bytes.data() + offset, static_cast<int>(chunk), send_flags());
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      continue;
    }
    if (written == 0) {
      error = "send reported a zero-length write";
      break;
    }
    const int code = last_socket_error();
    if (error_is_interrupted(code) || error_is_would_block(code)) {
      continue;
    }
    error = "send failed: " + socket_error_text(code);
    break;
  }
  if (switched) {
    (void)set_non_blocking(handle, false);
  }
  if (offset == bytes.size()) {
    error.clear();
    return true;
  }
  return false;
}

Socket::ReceiveResult Socket::receive(std::string& buffer, const Clock& clock, Ticks stall_budget) {
  ReceiveResult result;
  if (!valid()) {
    result.status = ReceiveStatus::ERROR;
    result.error = "cannot receive on a socket that is not open";
    return result;
  }
  const native_socket handle = handle_of(native_);
  const Ticks deadline = saturating_add(clock.now(), stall_budget);
  // The read chunk is deliberately heap allocated: a 16 KiB frame is a C6262
  // static-analysis finding and an unnecessary demand on a session thread's
  // stack. One allocation per call is nothing against a select/recv pair, and
  // a plain new[] avoids zero-filling the whole chunk on every call.
  const std::unique_ptr<char[]> scratch(new char[receive_chunk_bytes]);
  StagnantPollGuard guard(clock, io_stagnant_polls);
  while (true) {
    const bool have_data = result.bytes > 0;
    const Ticks now = clock.now();
    const bool expired = now >= deadline;
    if (have_data) {
      // Data already read is returned promptly: only bytes that are available
      // right now are drained, never a fresh wait.
      if (expired || result.bytes >= receive_call_bytes) {
        result.status = ReceiveStatus::DATA;
        return result;
      }
    } else if (expired) {
      result.status = ReceiveStatus::STALLED;
      return result;
    }
    const Ticks wait = have_data ? 0 : min_ticks(deadline - now, poll_interval);
    const int ready = wait_socket(handle, true, wait);
    if (ready < 0) {
      result.status = ReceiveStatus::ERROR;
      result.error = "receive wait failed: " + socket_error_text(last_socket_error());
      return result;
    }
    if (ready == 0) {
      if (have_data) {
        result.status = ReceiveStatus::DATA;
        return result;
      }
      // The budget elapsed on the monotonic clock, or the injected clock is not
      // advancing at all; either way this wait is over.
      if (guard.exhausted()) {
        result.status = ReceiveStatus::STALLED;
        return result;
      }
      continue;
    }
    const int received =
        ::recv(handle, scratch.get(), static_cast<int>(receive_chunk_bytes), 0);
    if (received > 0) {
      buffer.append(scratch.get(), static_cast<std::size_t>(received));
      result.bytes += static_cast<std::size_t>(received);
      continue;
    }
    if (received == 0) {
      // An orderly close delivers everything already read first; the next call
      // reports CLOSED.
      result.status = have_data ? ReceiveStatus::DATA : ReceiveStatus::CLOSED;
      return result;
    }
    const int code = last_socket_error();
    if (error_is_interrupted(code) || error_is_would_block(code)) {
      continue;
    }
    if (have_data) {
      result.status = ReceiveStatus::DATA;
      return result;
    }
    result.status = ReceiveStatus::ERROR;
    result.error = "receive failed: " + socket_error_text(code);
    return result;
  }
}

// ---------------------------------------------------------------------------
// Coordinator server
// ---------------------------------------------------------------------------

class CoordinatorServer::Impl {
 public:
  // CONTINUE keeps the session, CLOSE ends it cleanly, PROTOCOL_FAILURE ends it
  // and is counted as a wire-level failure.
  enum class Disposition { CONTINUE, CLOSE, PROTOCOL_FAILURE };

  // Why a session ended. Only an unclean end fences the publisher incarnation
  // the session owned: a peer that said goodbye, and a coordinator that is
  // shutting down, must never poison durable authority.
  enum class SessionEnd { CLEAN_BYE, SERVER_STOPPING, LOST };

  // One accepted connection. Every field below is touched by exactly one thread
  // (the session's own) except the finished flag, which the reaper observes.
  struct Session {
    std::uint64_t index = 0;
    SessionId id;
    Socket socket;
    std::thread thread;
    bool registered = false;
    PublisherId publisher;
    WorkerBootId worker_boot;
    AuthorityScope scope;
    std::uint64_t dispatched = 0;
    std::atomic<bool> finished{false};
  };

  explicit Impl(CoordinatorServer::Config config)
      : config_(std::move(config)),
        clock_(config_.clock ? config_.clock : std::make_shared<SteadyClock>()),
        engine_(std::make_unique<AdaptiveRoutingFabric>(engine_config())) {}

  ~Impl() { stop(); }

  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  [[nodiscard]] bool start(std::string& error);
  void stop();

  [[nodiscard]] std::uint16_t port() const noexcept { return bound_port_.load(); }
  [[nodiscard]] Endpoint endpoint() const {
    Endpoint result = config_.endpoint;
    result.port = bound_port_.load();
    return result;
  }
  [[nodiscard]] AdaptiveRoutingFabric& engine() noexcept { return *engine_; }
  [[nodiscard]] std::size_t session_count() const noexcept { return live_sessions_.load(); }
  [[nodiscard]] std::uint64_t sessions_accepted() const noexcept {
    return sessions_accepted_.load();
  }
  [[nodiscard]] std::uint64_t sessions_rejected() const noexcept {
    return sessions_rejected_.load();
  }
  [[nodiscard]] std::uint64_t protocol_failures() const noexcept {
    return protocol_failures_.load();
  }

 private:
  [[nodiscard]] EngineConfig engine_config() const {
    EngineConfig engine;
    engine.limits = config_.limits;
    engine.clock = clock_;
    engine.id_prefix = config_.id_prefix;
    // Recovery never trusts a recovered preference without a fresh
    // revalidation, which is the conservative product behaviour.
    engine.conservative_recovery = true;
    return engine;
  }

  void accept_loop();
  void reap_finished_sessions();
  void session_loop(const std::shared_ptr<Session>& session);
  [[nodiscard]] SessionEnd run_session(const std::shared_ptr<Session>& session);
  [[nodiscard]] Disposition dispatch(const std::shared_ptr<Session>& session, const Frame& frame);
  [[nodiscard]] Disposition reject_payload(const std::shared_ptr<Session>& session,
                                           std::uint64_t sequence, MessageId id);

  // One handler per message, so that no single stack frame holds the union of
  // every decoded payload. Each returns the disposition the session loop acts on.
  [[nodiscard]] Disposition handle_hello(const std::shared_ptr<Session>& session,
                                        const Frame& frame);
  [[nodiscard]] Disposition handle_register_publisher(const std::shared_ptr<Session>& session,
                                        const Frame& frame);
  [[nodiscard]] Disposition handle_fence_notice(const std::shared_ptr<Session>& session,
                                        const Frame& frame);
  [[nodiscard]] Disposition handle_query_state(const std::shared_ptr<Session>& session,
                                        const Frame& frame);
  [[nodiscard]] Disposition handle_snapshot_request(const std::shared_ptr<Session>& session,
                                        const Frame& frame);
  [[nodiscard]] Disposition handle_explain_request(const std::shared_ptr<Session>& session,
                                        const Frame& frame);
  [[nodiscard]] Disposition handle_diff_request(const std::shared_ptr<Session>& session,
                                        const Frame& frame);
  [[nodiscard]] Disposition handle_create_policy(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_update_policy(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_policy_lifecycle(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_revoke_policy(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_upstream_notify(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_publish_evidence(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_evaluate(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_commit_decision(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_revalidate(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_rollback(const std::shared_ptr<Session>& session,
                                        const Frame& frame, std::uint64_t attempt);
  [[nodiscard]] Disposition handle_advance_epoch(const std::shared_ptr<Session>& session,
                                                 const Frame& frame);
  [[nodiscard]] MutationContext make_context(const std::shared_ptr<Session>& session,
                                             std::uint64_t sequence) const;

  [[nodiscard]] bool write_response(const std::shared_ptr<Session>& session, MessageId id,
                                    std::uint64_t sequence, std::string_view payload);
  void respond(const std::shared_ptr<Session>& session, std::uint64_t sequence,
               const ResultMessage& message);
  void respond_error(const std::shared_ptr<Session>& session, std::uint64_t sequence,
                     Outcome outcome, std::string detail);
  void respond_operation(const std::shared_ptr<Session>& session, std::uint64_t sequence,
                         const OperationResult& result, bool mutating);
  void respond_snapshot(const std::shared_ptr<Session>& session, std::uint64_t sequence,
                        const SnapshotResponseMessage& message);

  // Operator-facing diagnostics only: never part of the protocol, never an
  // input to a decision, and silent unless Config::verbose is set.
  void diagnostic(std::string_view text) const {
    if (!config_.verbose) {
      return;
    }
    std::cerr << "adaptive-routing coordinator: " << text << '\n';
  }

  CoordinatorServer::Config config_;
  std::shared_ptr<Clock> clock_;
  std::unique_ptr<AdaptiveRoutingFabric> engine_;
  std::mutex mutex_;           // guards sessions_
  std::mutex listener_mutex_;  // serialises listener handle access
  std::vector<std::shared_ptr<Session>> sessions_;
  Socket listener_;
  std::thread accept_thread_;
  std::atomic<bool> running_{false};
  std::atomic<std::uint16_t> bound_port_{0};
  std::atomic<std::size_t> live_sessions_{0};
  std::atomic<std::uint64_t> sessions_accepted_{0};
  std::atomic<std::uint64_t> sessions_rejected_{0};
  std::atomic<std::uint64_t> protocol_failures_{0};
  std::atomic<std::uint64_t> session_counter_{0};
};

bool CoordinatorServer::Impl::start(std::string& error) {
  error.clear();
  if (running_.load(std::memory_order_acquire)) {
    error = "the coordinator is already running";
    return false;
  }
  engine_ = std::make_unique<AdaptiveRoutingFabric>(engine_config());
  if (!config_.store_path.empty()) {
    std::error_code status;
    const bool present = std::filesystem::exists(config_.store_path, status);
    if (status) {
      error = "store path " + config_.store_path + " cannot be inspected: " + status.message();
      return false;
    }
    // A missing store is a first run, not a failure; only an existing but
    // undecodable store is an error.
    if (present) {
      const OperationResult loaded = engine_->load(config_.store_path);
      if (!loaded.ok()) {
        error = "store " + config_.store_path + " could not be loaded: " + loaded.render();
        return false;
      }
      diagnostic("recovered durable state from " + config_.store_path);
    }
  }
  std::optional<Socket> listener = Socket::listen(config_.endpoint, error);
  if (!listener.has_value()) {
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(listener_mutex_);
    listener_ = std::move(*listener);
    bound_port_.store(listener_.local_port());
  }
  running_.store(true, std::memory_order_release);
  try {
    accept_thread_ = std::thread([this] { accept_loop(); });
  } catch (const std::system_error& failure) {
    running_.store(false, std::memory_order_release);
    {
      std::lock_guard<std::mutex> lock(listener_mutex_);
      listener_.close();
    }
    bound_port_.store(0);
    error = std::string("the accept thread could not be started: ") + failure.what();
    return false;
  }
  diagnostic("listening on " + endpoint().render());
  return true;
}

void CoordinatorServer::Impl::stop() {
  running_.store(false, std::memory_order_release);
  {
    std::lock_guard<std::mutex> lock(listener_mutex_);
    listener_.close();
  }
  // The accept loop polls with a bounded budget, so it leaves even when the
  // close above raced with an in-flight select.
  if (accept_thread_.joinable()) {
    accept_thread_.join();
  }
  std::vector<std::shared_ptr<Session>> sessions;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions.swap(sessions_);
  }
  for (const std::shared_ptr<Session>& session : sessions) {
    // Joined before the socket is touched: the session thread closes its own
    // handle, and no handle is ever closed twice.
    if (session->thread.joinable()) {
      session->thread.join();
    }
    session->socket.close();
  }
  bound_port_.store(0);
  diagnostic("stopped");
}

void CoordinatorServer::Impl::accept_loop() {
  const Clock& clock = *clock_;
  while (running_.load(std::memory_order_acquire)) {
    reap_finished_sessions();
    std::optional<Socket> accepted;
    {
      std::lock_guard<std::mutex> lock(listener_mutex_);
      accepted = listener_.accept_one(clock, accept_poll_budget);
    }
    if (!accepted.has_value()) {
      continue;  // nothing pending, or the listener was closed by stop()
    }
    if (live_sessions_.load() >= config_.limits.max_sessions) {
      accepted->close();
      ++sessions_rejected_;
      diagnostic("session refused: the configured session limit was reached");
      continue;
    }
    auto session = std::make_shared<Session>();
    session->index = session_counter_.fetch_add(1) + 1;
    session->id =
        compose_identity<SessionIdTag>(config_.id_prefix, "session", session->index, true);
    session->socket = std::move(*accepted);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      sessions_.push_back(session);
    }
    live_sessions_.fetch_add(1);
    try {
      session->thread = std::thread([this, session] { session_loop(session); });
    } catch (const std::system_error& failure) {
      live_sessions_.fetch_sub(1);
      {
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_.erase(std::remove(sessions_.begin(), sessions_.end(), session), sessions_.end());
      }
      session->socket.close();
      ++sessions_rejected_;
      diagnostic(std::string("session refused: ") + failure.what());
      continue;
    }
    ++sessions_accepted_;
    diagnostic("session " + session->id.str() + " accepted");
  }
}

void CoordinatorServer::Impl::reap_finished_sessions() {
  std::vector<std::shared_ptr<Session>> finished;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto entry = sessions_.begin();
    while (entry != sessions_.end()) {
      if ((*entry)->finished.load(std::memory_order_acquire)) {
        finished.push_back(*entry);
        entry = sessions_.erase(entry);
      } else {
        ++entry;
      }
    }
  }
  // Joined with no server lock held: a session thread never takes one, and the
  // header forbids joining under the engine lock.
  for (const std::shared_ptr<Session>& session : finished) {
    if (session->thread.joinable()) {
      session->thread.join();
    }
  }
}

void CoordinatorServer::Impl::session_loop(const std::shared_ptr<Session>& session) {
  // An exception escaping the loop leaves the session in the least trusted
  // state, so LOST is the starting point and only a proven clean end lowers it.
  SessionEnd ending = SessionEnd::LOST;
  try {
    ending = run_session(session);
  } catch (const std::exception& failure) {
    diagnostic(std::string("session aborted: ") + failure.what());
  } catch (...) {
    diagnostic("session aborted by an unknown internal error");
  }
  // Being connected is not authority, and neither is having been connected: an
  // incarnation that vanished without a goodbye is fenced so that its boot id
  // can never act again. Shutdown is deliberately excluded, because a
  // coordinator that is stopping must not poison the store it persists.
  const bool stopping = !running_.load(std::memory_order_acquire);
  if (ending == SessionEnd::LOST && !stopping && session->registered) {
    const OperationResult fenced =
        engine_->fence_publisher(session->publisher, session->worker_boot, "SESSION_LOST");
    if (!fenced.ok() && !fenced.mutated) {
      diagnostic("fencing a lost session reported " +
                 std::string(to_string(fenced.outcome)));
    }
    if (!config_.store_path.empty() && (fenced.ok() || fenced.mutated)) {
      const OperationResult saved = engine_->save(config_.store_path);
      if (!saved.ok()) {
        diagnostic("store save failed after fencing a lost session: " + saved.render());
      }
    }
  }
  session->socket.close();
  session->finished.store(true, std::memory_order_release);
  live_sessions_.fetch_sub(1);
  diagnostic("session " + session->id.str() + " ended");
}

CoordinatorServer::Impl::SessionEnd CoordinatorServer::Impl::run_session(
    const std::shared_ptr<Session>& session) {
  const Clock& clock = *clock_;
  const Ticks stall_budget = milliseconds(config_.limits.max_receive_stall_millis);
  std::string buffer;
  bool partial_frame = false;
  bool closing = false;
  Ticks partial_deadline = 0;
  while (running_.load(std::memory_order_acquire)) {
    const FrameDecodeResult decoded = decode_frame(buffer, config_.limits.max_frame_bytes);
    if (decoded.status == FrameStatus::OK) {
      buffer.erase(0, decoded.consumed);
      partial_frame = false;
      const Disposition disposition = dispatch(session, decoded.frame);
      if (disposition == Disposition::CONTINUE) {
        continue;
      }
      if (disposition == Disposition::PROTOCOL_FAILURE) {
        ++protocol_failures_;
        return SessionEnd::LOST;
      }
      // BYE: the peer declared the end of the conversation.
      return SessionEnd::CLEAN_BYE;
    }
    if (decoded.status != FrameStatus::INCOMPLETE) {
      // Every other status is terminal for the session: the byte stream is no
      // longer trustworthy and resynchronising it would be guesswork.
      ++protocol_failures_;
      diagnostic("session " + session->id.str() + " failed: frame " +
                 std::string(to_string(decoded.status)));
      return SessionEnd::LOST;
    }
    if (closing) {
      // Every complete frame has been dispatched above, so what is left in the
      // buffer is a frame the peer never finished.
      if (!buffer.empty()) {
        ++protocol_failures_;
      }
      // The peer closed the connection without saying goodbye.
      return SessionEnd::LOST;
    }
    // Only a frame that has actually started is bounded: an idle session is
    // never failed for being idle. The bound below is the product-level
    // partial-frame defence, measured on the monotonic clock.
    Ticks slice = poll_interval;
    if (!buffer.empty()) {
      const Ticks now = clock.now();
      if (!partial_frame) {
        partial_frame = true;
        partial_deadline = saturating_add(now, stall_budget);
      } else if (now >= partial_deadline) {
        ++protocol_failures_;
        diagnostic("session " + session->id.str() +
                   " failed: a partial frame exceeded max_receive_stall_millis");
        return SessionEnd::LOST;
      }
      slice = min_ticks(partial_deadline > now ? partial_deadline - now : 0, poll_interval);
    } else {
      partial_frame = false;
    }
    // A zero-length slice would return without ever polling the socket, so an
    // idle session always waits for the full poll interval.
    const Socket::ReceiveResult received = session->socket.receive(buffer, clock, slice);
    if (received.status == Socket::ReceiveStatus::CLOSED) {
      // The peer closed: whatever it completed is still dispatched, so the loop
      // runs once more before the session ends.
      closing = true;
      continue;
    }
    if (received.status == Socket::ReceiveStatus::ERROR) {
      ++protocol_failures_;
      diagnostic("session " + session->id.str() + " failed: " + received.error);
      return SessionEnd::LOST;
    }
    // DATA or STALLED: the frame decoder above decides what happens next.
  }
  // The loop left because the stop flag was cleared: this is a deliberate
  // teardown, not a lost peer.
  return SessionEnd::SERVER_STOPPING;
}

MutationContext CoordinatorServer::Impl::make_context(const std::shared_ptr<Session>& session,
                                                      std::uint64_t sequence) const {
  MutationContext context;
  context.epoch = engine_->epoch();
  context.publisher = session->publisher;
  context.worker_boot = session->worker_boot;
  context.session = session->id;
  // Deterministic in (session, frame sequence): a replay of the same frame on
  // the same session is recognised as an attempt replay, never as a new one.
  context.attempt = compose_attempt(session->id, sequence);
  return context;
}

bool CoordinatorServer::Impl::write_response(const std::shared_ptr<Session>& session, MessageId id,
                                             std::uint64_t sequence, std::string_view payload) {
  if (payload.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())) {
    return false;
  }
  Frame frame;
  frame.header.wire_version = wire_protocol_version;
  frame.header.message_id = id;
  frame.header.flags = 0;
  frame.header.sequence = sequence;
  frame.header.epoch = engine_->epoch();
  frame.header.payload_length = static_cast<std::uint32_t>(payload.size());
  frame.payload.assign(payload);
  const std::optional<std::string> encoded = encode_frame(frame, config_.limits.max_frame_bytes);
  if (!encoded.has_value()) {
    return false;
  }
  std::string error;
  return session->socket.send_all(*encoded, *clock_, response_send_budget, error);
}

void CoordinatorServer::Impl::respond(const std::shared_ptr<Session>& session,
                                      std::uint64_t sequence, const ResultMessage& message) {
  if (write_response(session, MessageId::RESULT, sequence, message.encode())) {
    return;
  }
  respond_error(session, sequence, Outcome::RESOURCE_LIMIT,
                "the response could not be encoded or written to the peer");
}

void CoordinatorServer::Impl::respond_error(const std::shared_ptr<Session>& session,
                                            std::uint64_t sequence, Outcome outcome,
                                            std::string detail) {
  ErrorMessage message;
  message.outcome = outcome;
  message.detail = std::move(detail);
  (void)write_response(session, MessageId::ERROR, sequence, message.encode());
}

void CoordinatorServer::Impl::respond_snapshot(const std::shared_ptr<Session>& session,
                                               std::uint64_t sequence,
                                               const SnapshotResponseMessage& message) {
  if (write_response(session, MessageId::SNAPSHOT_RESPONSE, sequence, message.encode())) {
    return;
  }
  respond_error(session, sequence, Outcome::RESOURCE_LIMIT,
                "the snapshot response could not be encoded or written to the peer");
}

void CoordinatorServer::Impl::respond_operation(const std::shared_ptr<Session>& session,
                                                std::uint64_t sequence,
                                                const OperationResult& result, bool mutating) {
  OperationResult reported = result;
  const bool durable = result.ok() || result.mutated;
  if (mutating && durable && !config_.store_path.empty()) {
    const OperationResult saved = engine_->save(config_.store_path);
    if (!saved.ok()) {
      // The mutation was applied in memory and the durability failure is
      // reported rather than silently swallowed.
      reported.outcome = saved.outcome;
      reported.mutated = false;
      const std::string note =
          "store save failed: " + std::string(to_string(saved.outcome)) + " " + saved.detail;
      reported.detail = reported.detail.empty() ? note : reported.detail + "; " + note;
    }
  }
  ResultMessage message;
  message.outcome = reported.outcome;
  message.suppression = reported.suppression;
  message.detail = reported.detail;
  message.policy = reported.policy;
  message.policy_generation = reported.policy_generation;
  message.decision = reported.decision;
  message.adaptation_generation = reported.adaptation_generation;
  message.transition_generation = reported.transition_generation;
  message.evidence_generation = reported.evidence_generation;
  message.epoch = reported.epoch.valid() ? reported.epoch : engine_->epoch();
  message.rendered = reported.render();
  respond(session, sequence, message);
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::reject_payload(
    const std::shared_ptr<Session>& session, std::uint64_t sequence, MessageId id) {
  respond_error(session, sequence, Outcome::MALFORMED_REQUEST,
                "the payload of " + std::string(to_string(id)) + " could not be decoded");
  return Disposition::CONTINUE;
}
CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_hello(
    const std::shared_ptr<Session>& session, const Frame& frame) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<HelloMessage> greeting = HelloMessage::decode(frame.payload);
  if (!greeting.has_value()) {
    return reject_payload(session, sequence, id);
  }
  if (greeting->wire_version != wire_protocol_version) {
    respond_error(session, sequence, Outcome::UNSUPPORTED_VERSION,
                  "the peer announced wire protocol version " +
                      std::to_string(greeting->wire_version) + ", this coordinator speaks " +
                      std::to_string(wire_protocol_version));
    return Disposition::PROTOCOL_FAILURE;
  }
  HelloMessage acknowledgement;
  acknowledgement.wire_version = wire_protocol_version;
  acknowledgement.product = std::string(product_name);
  acknowledgement.epoch = engine_->epoch();
  acknowledgement.authority_generation = engine_->authority_generation();
  (void)write_response(session, MessageId::HELLO_ACK, sequence, acknowledgement.encode());
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_register_publisher(
    const std::shared_ptr<Session>& session, const Frame& frame) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<RegisterPublisherMessage> message =
      RegisterPublisherMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  if (!message->scope.well_formed()) {
    respond_error(session, sequence, Outcome::MALFORMED_REQUEST,
                  "the authority scope names neither a fabric nor a routing namespace");
    return Disposition::CONTINUE;
  }
  const OperationResult result = engine_->register_publisher(
      message->publisher, message->worker_boot, message->scope, session->id);
  if (result.ok()) {
    session->registered = true;
    session->publisher = message->publisher;
    session->worker_boot = message->worker_boot;
    session->scope = message->scope;
  }
  respond_operation(session, sequence, result, true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_fence_notice(
    const std::shared_ptr<Session>& session, const Frame& frame) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<FenceNoticeMessage> message =
      FenceNoticeMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  const OperationResult result =
      engine_->fence_publisher(message->publisher, message->worker_boot, message->cause);
  respond_operation(session, sequence, result, true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_create_policy(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<CreatePolicyMessage> message = CreatePolicyMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  CreatePolicyRequest request;
  request.name = message->name;
  request.scope = message->scope;
  request.semantics = message->semantics;
  request.context = make_context(session, attempt);
  respond_operation(session, sequence, engine_->create_policy(request), true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_update_policy(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<UpdatePolicyMessage> message = UpdatePolicyMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  UpdatePolicyRequest request;
  request.policy = message->policy;
  request.update.scope = message->scope;
  request.update.semantics = message->semantics;
  request.context = make_context(session, attempt);
  respond_operation(session, sequence, engine_->update_policy(request), true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_policy_lifecycle(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<PolicyLifecycleMessage> message =
      PolicyLifecycleMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  PolicyLifecycleRequest request;
  request.policy = message->policy;
  request.event = message->event;
  request.detail = message->detail;
  request.context = make_context(session, attempt);
  respond_operation(session, sequence, engine_->transition_policy(request), true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_revoke_policy(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<RevokePolicyMessage> message = RevokePolicyMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  const OperationResult result = engine_->revoke_policy(
      message->policy, message->reason, message->detail, make_context(session, attempt));
  respond_operation(session, sequence, result, true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_upstream_notify(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<UpstreamNotifyMessage> message =
      UpstreamNotifyMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  UpstreamNotifyRequest request;
  request.notifications = message->notifications;
  request.context = make_context(session, attempt);
  respond_operation(session, sequence, engine_->apply_upstream(request), true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_publish_evidence(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<PublishEvidenceMessage> message =
      PublishEvidenceMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  PublishEvidenceRequest request;
  request.publications = message->publications;
  request.context = make_context(session, attempt);
  respond_operation(session, sequence, engine_->publish_evidence(request), true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_evaluate(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<EvaluateMessage> message = EvaluateMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  EvaluateRequest request;
  request.policy = message->policy;
  request.context = make_context(session, attempt);
  request.defer_commit = message->defer_commit;
  if (!message->defer_commit) {
    respond_operation(session, sequence, engine_->evaluate(request), true);
    return Disposition::CONTINUE;
  }
  // Deferred evaluation reports the phase-one ticket without committing:
  // the caller decides whether to send COMMIT_DECISION for it.
  const EvaluationTicket ticket = engine_->begin_evaluation(request);
  ResultMessage reported;
  reported.outcome = ticket.outcome;
  reported.suppression = ticket.suppression;
  reported.detail = ticket.detail;
  reported.policy = request.policy;
  reported.decision = ticket.decision;
  reported.adaptation_generation = ticket.adaptation_generation;
  reported.transition_generation = ticket.transition_generation;
  reported.evidence_generation = ticket.dependencies.evidence_generation;
  reported.epoch = ticket.dependencies.epoch.valid() ? ticket.dependencies.epoch
                                                    : engine_->epoch();
  reported.rendered = ticket.dependencies.render();
  respond(session, sequence, reported);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_commit_decision(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<CommitDecisionMessage> message =
      CommitDecisionMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  CommitDecisionRequest request;
  request.ticket = message->ticket;
  request.context = make_context(session, attempt);
  respond_operation(session, sequence, engine_->commit_evaluation(request), true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_revalidate(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<RevalidateMessage> message = RevalidateMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  const OperationResult result = engine_->revalidate(
      message->policy, message->attempt, make_context(session, attempt));
  respond_operation(session, sequence, result, true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_rollback(
    const std::shared_ptr<Session>& session, const Frame& frame, std::uint64_t attempt) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<RollbackMessage> message = RollbackMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  RollbackRequest request;
  request.policy = message->policy;
  request.reason = message->reason;
  request.context = make_context(session, attempt);
  respond_operation(session, sequence, engine_->rollback(request), true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_query_state(
    const std::shared_ptr<Session>& session, const Frame& frame) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<QueryStateMessage> message = QueryStateMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  std::vector<AdaptivePolicy> policies;
  if (message->policy.valid()) {
    std::optional<AdaptivePolicy> found = engine_->find_policy(message->policy);
    if (!found.has_value()) {
      respond_error(session, sequence, Outcome::NOT_FOUND,
                    "policy " + message->policy.str() + " does not exist");
      return Disposition::CONTINUE;
    }
    policies.push_back(*found);
  } else {
    policies = engine_->list_policies();
  }
  // Deterministic output: the canonical StrongId ordering, so two identical
  // states always render byte for byte identically.
  std::sort(policies.begin(), policies.end(),
            [](const AdaptivePolicy& left, const AdaptivePolicy& right) {
              return left.id < right.id;
            });
  std::string rendered;
  std::uint64_t emitted = 0;
  for (const AdaptivePolicy& policy : policies) {
    // A zero limit means "every matching policy"; any other limit bounds
    // the number of rendered lines.
    if (message->limit != 0 && emitted >= message->limit) {
      break;
    }
    if (!rendered.empty()) {
      rendered.push_back('\n');
    }
    rendered += render_policy_line(policy);
    ++emitted;
  }
  ResultMessage reported;
  reported.outcome = Outcome::NO_CHANGE;
  reported.policy = message->policy;
  reported.epoch = engine_->epoch();
  reported.detail = "policies=" + std::to_string(emitted);
  reported.rendered = std::move(rendered);
  respond(session, sequence, reported);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_snapshot_request(
    const std::shared_ptr<Session>& session, const Frame& frame) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<SnapshotRequestMessage> message =
      SnapshotRequestMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  if (!message->policy.valid()) {
    respond_error(session, sequence, Outcome::MALFORMED_REQUEST,
                  "SNAPSHOT_REQUEST must name a policy");
    return Disposition::CONTINUE;
  }
  if (!engine_->find_policy(message->policy).has_value()) {
    respond_error(session, sequence, Outcome::NOT_FOUND,
                  "policy " + message->policy.str() + " does not exist");
    return Disposition::CONTINUE;
  }
  const AdaptationSnapshot snapshot = engine_->snapshot(message->policy);
  SnapshotResponseMessage response;
  response.snapshot = snapshot.id;
  response.policy = message->policy;
  response.digest =
      snapshot.digest.empty() ? snapshot_digest(snapshot) : snapshot.digest;
  response.rendered = snapshot.render();
  respond_snapshot(session, sequence, response);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_explain_request(
    const std::shared_ptr<Session>& session, const Frame& frame) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<ExplainRequestMessage> message =
      ExplainRequestMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  const Explanation explanation = engine_->explain(message->topic, message->policy);
  ResultMessage reported;
  reported.outcome = explanation.outcome;
  reported.suppression = explanation.suppression;
  reported.policy = explanation.policy.valid() ? explanation.policy : message->policy;
  reported.decision = explanation.decision;
  reported.epoch = engine_->epoch();
  reported.detail = std::string(to_string(explanation.topic));
  reported.rendered = explanation.render();
  respond(session, sequence, reported);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_diff_request(
    const std::shared_ptr<Session>& session, const Frame& frame) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<DiffRequestMessage> message = DiffRequestMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  const std::optional<AdaptationSnapshot> before = engine_->find_snapshot(message->from);
  if (!before.has_value()) {
    respond_error(session, sequence, Outcome::NOT_FOUND,
                  "snapshot " + message->from.str() + " is not retained");
    return Disposition::CONTINUE;
  }
  const std::optional<AdaptationSnapshot> after = engine_->find_snapshot(message->to);
  if (!after.has_value()) {
    respond_error(session, sequence, Outcome::NOT_FOUND,
                  "snapshot " + message->to.str() + " is not retained");
    return Disposition::CONTINUE;
  }
  const AdaptationDiff difference = compute_diff(*before, *after);
  ResultMessage reported;
  reported.outcome = Outcome::NO_CHANGE;
  reported.policy = difference.policy.valid() ? difference.policy : message->policy;
  reported.epoch = engine_->epoch();
  reported.detail = difference.empty() ? "no differences" : "differences recorded";
  reported.rendered = difference.render();
  respond(session, sequence, reported);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::handle_advance_epoch(
    const std::shared_ptr<Session>& session, const Frame& frame) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  const std::optional<AdvanceEpochMessage> message = AdvanceEpochMessage::decode(frame.payload);
  if (!message.has_value()) {
    return reject_payload(session, sequence, id);
  }
  respond_operation(session, sequence, engine_->advance_epoch(message->reason), true);
  return Disposition::CONTINUE;
}

CoordinatorServer::Impl::Disposition CoordinatorServer::Impl::dispatch(
    const std::shared_ptr<Session>& session, const Frame& frame) {
  const MessageId id = frame.header.message_id;
  const std::uint64_t sequence = frame.header.sequence;
  // Every dispatched frame consumes one deterministic attempt sequence, so the
  // attempt identity of a mutation depends only on the session and the frame
  // order.
  const std::uint64_t attempt = ++session->dispatched;

  if (!session->registered && id != MessageId::HELLO && id != MessageId::BYE &&
      id != MessageId::REGISTER_PUBLISHER) {
    // Being connected is not authority: before REGISTER_PUBLISHER a session may
    // only greet or leave. The session stays open so the peer can still
    // register, but nothing else is accepted before it does.
    respond_error(session, sequence, Outcome::UNAUTHORIZED,
                  "session " + session->id.str() + " must register a publisher before " +
                      std::string(to_string(id)));
    return Disposition::CONTINUE;
  }

  // One handler per message. Keeping the payload structure, the request and the
  // snapshot of each arm inside its own function is what keeps this router's
  // frame small, and it gives every message a single place to be read.
  switch (id) {
    case MessageId::HELLO:
      return handle_hello(session, frame);
    case MessageId::REGISTER_PUBLISHER:
      return handle_register_publisher(session, frame);
    case MessageId::FENCE_NOTICE:
      return handle_fence_notice(session, frame);
    case MessageId::CREATE_POLICY:
      return handle_create_policy(session, frame, attempt);
    case MessageId::UPDATE_POLICY:
      return handle_update_policy(session, frame, attempt);
    case MessageId::POLICY_LIFECYCLE:
      return handle_policy_lifecycle(session, frame, attempt);
    case MessageId::REVOKE_POLICY:
      return handle_revoke_policy(session, frame, attempt);
    case MessageId::UPSTREAM_NOTIFY:
      return handle_upstream_notify(session, frame, attempt);
    case MessageId::PUBLISH_EVIDENCE:
      return handle_publish_evidence(session, frame, attempt);
    case MessageId::EVALUATE:
      return handle_evaluate(session, frame, attempt);
    case MessageId::COMMIT_DECISION:
      return handle_commit_decision(session, frame, attempt);
    case MessageId::REVALIDATE:
      return handle_revalidate(session, frame, attempt);
    case MessageId::ROLLBACK:
      return handle_rollback(session, frame, attempt);
    case MessageId::QUERY_STATE:
      return handle_query_state(session, frame);
    case MessageId::SNAPSHOT_REQUEST:
      return handle_snapshot_request(session, frame);
    case MessageId::EXPLAIN_REQUEST:
      return handle_explain_request(session, frame);
    case MessageId::DIFF_REQUEST:
      return handle_diff_request(session, frame);
    case MessageId::ADVANCE_EPOCH:
      return handle_advance_epoch(session, frame);
    case MessageId::BYE:
      return Disposition::CLOSE;
    case MessageId::HELLO_ACK:
    case MessageId::RESULT:
    case MessageId::ERROR:
    case MessageId::SNAPSHOT_RESPONSE:
      // Responses travel from the coordinator to the peer, never the other way.
      respond_error(session, sequence, Outcome::WIRE_MALFORMED,
                    std::string(to_string(id)) + " is not accepted by the coordinator");
      return Disposition::PROTOCOL_FAILURE;
    default:
      break;
  }
  // Unreachable through the framed decoder, which validates every message id.
  respond_error(session, sequence, Outcome::WIRE_MALFORMED,
                "unknown message id " + std::to_string(static_cast<std::uint16_t>(id)));
  return Disposition::PROTOCOL_FAILURE;
}

CoordinatorServer::CoordinatorServer(Config config) : impl_(std::make_unique<Impl>(std::move(config))) {}

CoordinatorServer::~CoordinatorServer() = default;

bool CoordinatorServer::start(std::string& error) { return impl_->start(error); }

void CoordinatorServer::stop() { impl_->stop(); }

std::uint16_t CoordinatorServer::port() const noexcept { return impl_->port(); }

Endpoint CoordinatorServer::endpoint() const { return impl_->endpoint(); }

AdaptiveRoutingFabric& CoordinatorServer::engine() noexcept { return impl_->engine(); }

std::size_t CoordinatorServer::session_count() const noexcept { return impl_->session_count(); }

std::uint64_t CoordinatorServer::sessions_accepted() const noexcept {
  return impl_->sessions_accepted();
}

std::uint64_t CoordinatorServer::sessions_rejected() const noexcept {
  return impl_->sessions_rejected();
}

std::uint64_t CoordinatorServer::protocol_failures() const noexcept {
  return impl_->protocol_failures();
}

// ---------------------------------------------------------------------------
// Coordinator client
// ---------------------------------------------------------------------------

class CoordinatorClient::Impl {
 public:
  explicit Impl(CoordinatorClient::Config config)
      : config_(std::move(config)),
        clock_(config_.clock ? config_.clock : std::make_shared<SteadyClock>()),
        session_(compose_identity<SessionIdTag>(config_.id_prefix, "session",
                                                next_identity_counter(), true)),
        publisher_(compose_identity<PublisherIdTag>(config_.id_prefix, "publisher",
                                                    next_identity_counter(), true)),
        worker_boot_(compose_identity<WorkerBootIdTag>(config_.id_prefix, "boot",
                                                       next_identity_counter(), true)) {}

  ~Impl() { close(); }

  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  [[nodiscard]] bool connect(std::string& error) {
    close();
    std::optional<Socket> socket = Socket::connect(config_.endpoint, *clock_, config_.io_budget, error);
    if (!socket.has_value()) {
      return false;
    }
    socket_ = std::move(*socket);
    return true;
  }

  void close() {
    socket_.close();
    buffer_.clear();
  }

  [[nodiscard]] bool connected() const noexcept { return socket_.valid(); }

  [[nodiscard]] std::optional<Frame> request(MessageId id, std::string_view payload,
                                             std::string& error) {
    return transact(id, payload, true, error);
  }

  [[nodiscard]] std::optional<HelloMessage> hello(std::string& error) {
    error.clear();
    HelloMessage greeting;
    greeting.wire_version = wire_protocol_version;
    greeting.product = std::string(product_name);
    greeting.epoch = epoch_;
    // The greeting carries the coordinator values the client last observed. The
    // wire format has no "absent" form for either field, so the first
    // generation stands in until HELLO_ACK replaces it.
    greeting.authority_generation = authority_generation_;
    const std::optional<Frame> response = transact(MessageId::HELLO, greeting.encode(), false, error);
    if (!response.has_value()) {
      return std::nullopt;
    }
    if (response->header.message_id != MessageId::HELLO_ACK) {
      error = "expected HELLO_ACK but received " +
              std::string(to_string(response->header.message_id));
      return std::nullopt;
    }
    const std::optional<HelloMessage> acknowledgement = HelloMessage::decode(response->payload);
    if (!acknowledgement.has_value()) {
      error = "the HELLO_ACK payload could not be decoded";
      return std::nullopt;
    }
    if (acknowledgement->wire_version != wire_protocol_version) {
      error = "the coordinator announced wire protocol version " +
              std::to_string(acknowledgement->wire_version);
      return std::nullopt;
    }
    absorb_epoch(acknowledgement->epoch);
    if (acknowledgement->authority_generation.valid()) {
      authority_generation_ = acknowledgement->authority_generation;
    }
    return acknowledgement;
  }

  [[nodiscard]] std::optional<ResultMessage> send(const Frame& frame, std::string& error) {
    const std::optional<Frame> response =
        transact(frame.header.message_id, frame.payload, true, error);
    if (!response.has_value()) {
      return std::nullopt;
    }
    return decode_result(*response, error);
  }

  [[nodiscard]] std::optional<Frame> send_snapshot(const SnapshotRequestMessage& message,
                                                   std::string& error) {
    return transact(MessageId::SNAPSHOT_REQUEST, message.encode(), true, error);
  }

  void bye() {
    if (socket_.valid()) {
      Frame frame = make_frame(MessageId::BYE, std::string());
      frame.header.sequence = ++sequence_;
      frame.header.epoch = epoch_;
      std::string error;
      // Best effort on purpose: the peer may already be gone, and the local
      // handle is always released.
      (void)write_frame(frame, error);
    }
    close();
  }

  CoordinatorClient::Config config_;
  std::shared_ptr<Clock> clock_;
  Socket socket_;
  SessionId session_;
  PublisherId publisher_;
  WorkerBootId worker_boot_;
  std::uint64_t sequence_ = 0;
  // The last epoch the coordinator announced. A frame header must always carry
  // a well formed epoch, and before the first HELLO_ACK the coordinator's epoch
  // is not known, so the first generation stands in as a placeholder until the
  // coordinator's own value arrives. The coordinator binds mutation authority
  // from its own epoch, never from this field.
  CoordinatorEpoch epoch_ = CoordinatorEpoch::first();
  AdaptiveAuthorityGeneration authority_generation_ = AdaptiveAuthorityGeneration::first();
  std::string buffer_;

 private:
  [[nodiscard]] static std::uint64_t next_identity_counter() noexcept {
    static std::atomic<std::uint64_t> counter{0};
    return counter.fetch_add(1, std::memory_order_relaxed) + 1;
  }

  [[nodiscard]] std::optional<Frame> transact(MessageId id, std::string_view payload, bool skip_ack,
                                              std::string& error) {
    error.clear();
    if (!socket_.valid()) {
      error = "the client is not connected to " + config_.endpoint.render();
      return std::nullopt;
    }
    Frame frame = make_frame(id, std::string(payload));
    frame.header.sequence = ++sequence_;
    frame.header.epoch = epoch_;
    if (!write_frame(frame, error)) {
      return std::nullopt;
    }
    const Ticks started = clock_->now();
    const Ticks deadline = saturating_add(started, config_.io_budget);
    while (true) {
      std::optional<Frame> response = read_frame(started, deadline, error);
      if (!response.has_value()) {
        return std::nullopt;
      }
      if (skip_ack && response->header.message_id == MessageId::HELLO_ACK) {
        continue;
      }
      return response;
    }
  }

  [[nodiscard]] bool write_frame(const Frame& frame, std::string& error) {
    if (frame.payload.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())) {
      error = "the payload of " + std::string(to_string(frame.header.message_id)) +
              " exceeds the wire length field";
      return false;
    }
    Frame outgoing = frame;
    outgoing.header.wire_version = wire_protocol_version;
    outgoing.header.flags = 0;
    if (!outgoing.header.epoch.valid()) {
      outgoing.header.epoch = epoch_;
    }
    outgoing.header.payload_length = static_cast<std::uint32_t>(outgoing.payload.size());
    const std::optional<std::string> encoded =
        encode_frame(outgoing, config_.limits.max_frame_bytes);
    if (!encoded.has_value()) {
      error = std::string(to_string(outgoing.header.message_id)) + " exceeds max_frame_bytes (" +
              std::to_string(config_.limits.max_frame_bytes) + ")";
      return false;
    }
    return socket_.send_all(*encoded, *clock_, config_.io_budget, error);
  }

  [[nodiscard]] std::optional<Frame> read_frame(Ticks started, Ticks deadline, std::string& error) {
    while (true) {
      const FrameDecodeResult decoded = decode_frame(buffer_, config_.limits.max_frame_bytes);
      if (decoded.status == FrameStatus::OK) {
        buffer_.erase(0, decoded.consumed);
        absorb_epoch(decoded.frame.header.epoch);
        return decoded.frame;
      }
      if (decoded.status != FrameStatus::INCOMPLETE) {
        error = "the coordinator sent an invalid frame (" +
                std::string(to_string(decoded.status)) + ")";
        abandon();
        return std::nullopt;
      }
      const Ticks now = clock_->now();
      if (now >= deadline) {
        error = "timed out after " + std::to_string(config_.io_budget / ticks_per_millisecond) +
                " ms waiting for a response from " + config_.endpoint.render();
        abandon();
        return std::nullopt;
      }
      const Socket::ReceiveResult received = socket_.receive(buffer_, *clock_, deadline - now);
      if (received.status == Socket::ReceiveStatus::STALLED) {
        // STALLED means the budget elapsed, or that the injected clock reported
        // no progress at all. A clock that reports no progress cannot have
        // elapsed the budget, so the wait continues instead of reporting a
        // timeout that the clock does not support.
        if (clock_->now() != started) {
          error = "timed out after " + std::to_string(config_.io_budget / ticks_per_millisecond) +
                  " ms waiting for a response from " + config_.endpoint.render();
          abandon();
          return std::nullopt;
        }
        continue;
      }
      if (received.status == Socket::ReceiveStatus::CLOSED) {
        error = "the coordinator closed the connection";
        abandon();
        return std::nullopt;
      }
      if (received.status == Socket::ReceiveStatus::ERROR) {
        error = "receive failed: " + received.error;
        abandon();
        return std::nullopt;
      }
    }
  }

  // A stream that timed out or decoded badly is abandoned: a late response
  // would otherwise be paired with the next request.
  void abandon() {
    socket_.close();
    buffer_.clear();
  }

  [[nodiscard]] std::optional<ResultMessage> decode_result(const Frame& response,
                                                           std::string& error) const {
    if (response.header.message_id == MessageId::RESULT) {
      const std::optional<ResultMessage> message = ResultMessage::decode(response.payload);
      if (!message.has_value()) {
        error = "the RESULT payload could not be decoded";
        return std::nullopt;
      }
      return message;
    }
    if (response.header.message_id == MessageId::ERROR) {
      const std::optional<ErrorMessage> failure = ErrorMessage::decode(response.payload);
      if (!failure.has_value()) {
        error = "the ERROR payload could not be decoded";
        return std::nullopt;
      }
      // A coordinator rejection is a result, not a transport failure: the
      // structured outcome and detail are handed back to the caller.
      ResultMessage message;
      message.outcome = failure->outcome;
      message.detail = failure->detail;
      message.epoch = response.header.epoch;
      message.rendered = std::string(to_string(failure->outcome)) + " " + failure->detail;
      return message;
    }
    error = "unexpected response " + std::string(to_string(response.header.message_id)) +
            " from " + config_.endpoint.render();
    return std::nullopt;
  }

  void absorb_epoch(const CoordinatorEpoch& epoch) {
    if (epoch.valid()) {
      epoch_ = epoch;
    }
  }
};

CoordinatorClient::CoordinatorClient(Config config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

CoordinatorClient::~CoordinatorClient() = default;

bool CoordinatorClient::connect(std::string& error) { return impl_->connect(error); }

void CoordinatorClient::close() { impl_->close(); }

bool CoordinatorClient::connected() const noexcept { return impl_->connected(); }

std::optional<Frame> CoordinatorClient::request(MessageId id, std::string_view payload,
                                                std::string& error) {
  return impl_->request(id, payload, error);
}

std::optional<HelloMessage> CoordinatorClient::hello(std::string& error) {
  return impl_->hello(error);
}

std::optional<ResultMessage> CoordinatorClient::send(const Frame& frame, std::string& error) {
  return impl_->send(frame, error);
}

std::optional<ResultMessage> CoordinatorClient::register_publisher(const PublisherId& publisher,
                                                                  const WorkerBootId& worker_boot,
                                                                  const AuthorityScope& scope,
                                                                  std::string& error) {
  RegisterPublisherMessage message;
  message.publisher = publisher;
  message.worker_boot = worker_boot;
  message.scope = scope;
  return impl_->send(make_frame(MessageId::REGISTER_PUBLISHER, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::fence(const PublisherId& publisher,
                                                      const WorkerBootId& worker_boot,
                                                      std::string_view cause, std::string& error) {
  FenceNoticeMessage message;
  message.publisher = publisher;
  message.worker_boot = worker_boot;
  message.cause = std::string(cause);
  return impl_->send(make_frame(MessageId::FENCE_NOTICE, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::advance_epoch(std::string_view reason,
                                                              std::string& error) {
  AdvanceEpochMessage message;
  message.reason = std::string(reason);
  return impl_->send(make_frame(MessageId::ADVANCE_EPOCH, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::create_policy(const CreatePolicyMessage& message,
                                                              std::string& error) {
  return impl_->send(make_frame(MessageId::CREATE_POLICY, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::update_policy(const UpdatePolicyMessage& message,
                                                              std::string& error) {
  return impl_->send(make_frame(MessageId::UPDATE_POLICY, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::policy_lifecycle(
    const PolicyLifecycleMessage& message, std::string& error) {
  return impl_->send(make_frame(MessageId::POLICY_LIFECYCLE, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::revoke_policy(const RevokePolicyMessage& message,
                                                              std::string& error) {
  return impl_->send(make_frame(MessageId::REVOKE_POLICY, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::upstream_notify(const UpstreamNotifyMessage& message,
                                                                std::string& error) {
  return impl_->send(make_frame(MessageId::UPSTREAM_NOTIFY, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::publish_evidence(
    const PublishEvidenceMessage& message, std::string& error) {
  return impl_->send(make_frame(MessageId::PUBLISH_EVIDENCE, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::evaluate(const EvaluateMessage& message,
                                                         std::string& error) {
  return impl_->send(make_frame(MessageId::EVALUATE, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::commit_decision(
    const CommitDecisionMessage& message, std::string& error) {
  return impl_->send(make_frame(MessageId::COMMIT_DECISION, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::revalidate(const RevalidateMessage& message,
                                                           std::string& error) {
  return impl_->send(make_frame(MessageId::REVALIDATE, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::rollback(const RollbackMessage& message,
                                                         std::string& error) {
  return impl_->send(make_frame(MessageId::ROLLBACK, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::query_state(const QueryStateMessage& message,
                                                            std::string& error) {
  return impl_->send(make_frame(MessageId::QUERY_STATE, message.encode()), error);
}

std::optional<SnapshotResponseMessage> CoordinatorClient::snapshot(
    const SnapshotRequestMessage& message, std::string& error) {
  const std::optional<Frame> response = impl_->send_snapshot(message, error);
  if (!response.has_value()) {
    return std::nullopt;
  }
  if (response->header.message_id == MessageId::ERROR) {
    const std::optional<ErrorMessage> failure = ErrorMessage::decode(response->payload);
    if (!failure.has_value()) {
      error = "the ERROR payload could not be decoded";
      return std::nullopt;
    }
    error = std::string(to_string(failure->outcome)) + ": " + failure->detail;
    return std::nullopt;
  }
  if (response->header.message_id != MessageId::SNAPSHOT_RESPONSE) {
    error = "unexpected response " + std::string(to_string(response->header.message_id)) +
            " to SNAPSHOT_REQUEST";
    return std::nullopt;
  }
  const std::optional<SnapshotResponseMessage> decoded =
      SnapshotResponseMessage::decode(response->payload);
  if (!decoded.has_value()) {
    error = "the SNAPSHOT_RESPONSE payload could not be decoded";
    return std::nullopt;
  }
  return decoded;
}

std::optional<ResultMessage> CoordinatorClient::explain(const ExplainRequestMessage& message,
                                                        std::string& error) {
  return impl_->send(make_frame(MessageId::EXPLAIN_REQUEST, message.encode()), error);
}

std::optional<ResultMessage> CoordinatorClient::diff(const DiffRequestMessage& message,
                                                     std::string& error) {
  return impl_->send(make_frame(MessageId::DIFF_REQUEST, message.encode()), error);
}

void CoordinatorClient::bye() { impl_->bye(); }

const SessionId& CoordinatorClient::session() const noexcept { return impl_->session_; }

const PublisherId& CoordinatorClient::publisher() const noexcept { return impl_->publisher_; }

const WorkerBootId& CoordinatorClient::worker_boot() const noexcept { return impl_->worker_boot_; }

}  // namespace adaptive_routing

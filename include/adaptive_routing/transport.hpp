// Socket transport, coordinator server and coordinator client.
//
// PROCESS MODEL
// -------------
// The distributed model is real: a coordinator process owns authority and
// publisher processes connect to it over a loopback TCP socket. Sessions are
// OS sockets, worker death is an OS process termination, and coordinator
// restart is a real process restart against the same store.
//
// BOUNDED RECEIVE
// ---------------
// A peer that sends a partial frame cannot pin a session forever. The receive
// loop is time-bounded by Limits::max_receive_stall_millis measured on the
// monotonic clock; exceeding it fails the session with an explicit protocol
// failure and closes the socket. This is a product-level bound, not a test
// timeout.
//
// SHUTDOWN
// --------
// On Windows a blocked recv is not reliably cancelled by shutdown(), so the
// receive loop is built on a polling wait with an explicit stop flag, and close
// is performed only by the owning thread. No thread is joined while holding the
// engine lock and no socket handle is closed twice.
#ifndef ADAPTIVE_ROUTING_TRANSPORT_HPP
#define ADAPTIVE_ROUTING_TRANSPORT_HPP

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "adaptive_routing/clock.hpp"
#include "adaptive_routing/fabric.hpp"
#include "adaptive_routing/limits.hpp"
#include "adaptive_routing/wire.hpp"

namespace adaptive_routing {

struct Endpoint {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

class Socket {
 public:
  Socket() = default;
  ~Socket();
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  [[nodiscard]] bool valid() const noexcept;
  void close() noexcept;

  // Connects to \p endpoint with a bounded total time budget.
  [[nodiscard]] static std::optional<Socket> connect(const Endpoint& endpoint, const Clock& clock,
                                                     Ticks budget, std::string& error);
  // Adopts an already accepted native handle.
  [[nodiscard]] static Socket adopt(std::uintptr_t native);

  [[nodiscard]] std::uintptr_t native() const noexcept;

  void set_nodelay(bool enabled) noexcept;

  // Sends the whole buffer or fails. Bounded by \p budget on the monotonic clock.
  [[nodiscard]] bool send_all(std::string_view bytes, const Clock& clock, Ticks budget,
                              std::string& error);

  enum class ReceiveStatus {
    DATA = 0,
    CLOSED = 1,
    STALLED = 2,
    ERROR = 3,
  };

  struct ReceiveResult {
    ReceiveStatus status = ReceiveStatus::DATA;
    std::size_t bytes = 0;
    std::string error;
  };

  // Reads whatever is available, waiting at most \p stall_budget in total
  // before reporting STALLED. Never blocks indefinitely.
  [[nodiscard]] ReceiveResult receive(std::string& buffer, const Clock& clock, Ticks stall_budget);

  // Local port of the bound socket of a listening listener, 0 when unknown.
  [[nodiscard]] static std::optional<Socket> listen(const Endpoint& endpoint, std::string& error);
  [[nodiscard]] std::optional<Socket> accept_one(const Clock& clock, Ticks poll_budget) const;
  [[nodiscard]] std::uint16_t local_port() const noexcept;

 private:
  std::uintptr_t native_ = 0;
};

// ---------------------------------------------------------------------------
// Coordinator server
// ---------------------------------------------------------------------------

class CoordinatorServer {
 public:
  struct Config {
    Endpoint endpoint;
    Limits limits;
    std::shared_ptr<Clock> clock;
    std::string id_prefix = "arf-coordinator";
    // When non-empty the engine persists to this path after every mutation and
    // loads from it at start.
    std::string store_path;
    bool verbose = false;
  };

  explicit CoordinatorServer(Config config);
  ~CoordinatorServer();
  CoordinatorServer(const CoordinatorServer&) = delete;
  CoordinatorServer& operator=(const CoordinatorServer&) = delete;

  // Binds, listens and starts the accept thread. Returns false with a reason.
  [[nodiscard]] bool start(std::string& error);
  // Stops accepting, closes every session, joins every thread and releases the
  // listening socket. Safe to call twice.
  void stop();

  [[nodiscard]] std::uint16_t port() const noexcept;
  [[nodiscard]] Endpoint endpoint() const;
  [[nodiscard]] AdaptiveRoutingFabric& engine() noexcept;
  [[nodiscard]] std::size_t session_count() const noexcept;
  [[nodiscard]] std::uint64_t sessions_accepted() const noexcept;
  [[nodiscard]] std::uint64_t sessions_rejected() const noexcept;
  [[nodiscard]] std::uint64_t protocol_failures() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Coordinator client
// ---------------------------------------------------------------------------

class CoordinatorClient {
 public:
  struct Config {
    Endpoint endpoint;
    Limits limits;
    std::shared_ptr<Clock> clock;
    std::string id_prefix = "arf-client";
    Ticks io_budget = seconds(30);
  };

  explicit CoordinatorClient(Config config);
  ~CoordinatorClient();
  CoordinatorClient(const CoordinatorClient&) = delete;
  CoordinatorClient& operator=(const CoordinatorClient&) = delete;

  [[nodiscard]] bool connect(std::string& error);
  void close();
  [[nodiscard]] bool connected() const noexcept;

  // Sends one frame and reads exactly one response frame. Returns nullopt and
  // fills \p error on transport failure.
  [[nodiscard]] std::optional<Frame> request(MessageId id, std::string_view payload,
                                             std::string& error);

  [[nodiscard]] std::optional<HelloMessage> hello(std::string& error);
  [[nodiscard]] std::optional<ResultMessage> send(const Frame& frame, std::string& error);
  [[nodiscard]] std::optional<ResultMessage> register_publisher(const PublisherId& publisher,
                                                               const WorkerBootId& worker_boot,
                                                               const AuthorityScope& scope,
                                                               std::string& error);
  [[nodiscard]] std::optional<ResultMessage> fence(const PublisherId& publisher,
                                                  const WorkerBootId& worker_boot,
                                                  std::string_view cause, std::string& error);
  [[nodiscard]] std::optional<ResultMessage> advance_epoch(std::string_view reason,
                                                          std::string& error);
  [[nodiscard]] std::optional<ResultMessage> create_policy(const CreatePolicyMessage& message,
                                                          std::string& error);
  [[nodiscard]] std::optional<ResultMessage> update_policy(const UpdatePolicyMessage& message,
                                                          std::string& error);
  [[nodiscard]] std::optional<ResultMessage> policy_lifecycle(const PolicyLifecycleMessage& message,
                                                             std::string& error);
  [[nodiscard]] std::optional<ResultMessage> revoke_policy(const RevokePolicyMessage& message,
                                                          std::string& error);
  [[nodiscard]] std::optional<ResultMessage> upstream_notify(const UpstreamNotifyMessage& message,
                                                            std::string& error);
  [[nodiscard]] std::optional<ResultMessage> publish_evidence(const PublishEvidenceMessage& message,
                                                             std::string& error);
  [[nodiscard]] std::optional<ResultMessage> evaluate(const EvaluateMessage& message,
                                                     std::string& error);
  [[nodiscard]] std::optional<ResultMessage> commit_decision(const CommitDecisionMessage& message,
                                                            std::string& error);
  [[nodiscard]] std::optional<ResultMessage> revalidate(const RevalidateMessage& message,
                                                       std::string& error);
  [[nodiscard]] std::optional<ResultMessage> rollback(const RollbackMessage& message,
                                                     std::string& error);
  [[nodiscard]] std::optional<ResultMessage> query_state(const QueryStateMessage& message,
                                                        std::string& error);
  [[nodiscard]] std::optional<SnapshotResponseMessage> snapshot(const SnapshotRequestMessage& message,
                                                               std::string& error);
  [[nodiscard]] std::optional<ResultMessage> explain(const ExplainRequestMessage& message,
                                                    std::string& error);
  [[nodiscard]] std::optional<ResultMessage> diff(const DiffRequestMessage& message,
                                                 std::string& error);
  [[nodiscard]] void bye();

  // Identity this client signs its mutations with.
  [[nodiscard]] const SessionId& session() const noexcept;
  [[nodiscard]] const PublisherId& publisher() const noexcept;
  [[nodiscard]] const WorkerBootId& worker_boot() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_TRANSPORT_HPP

// arf_coordinator -- the process that owns mutation authority.
//
// PROCESS MODEL
// -------------
// Authority lives in this process, not in a library instance shared by the
// tools: the coordinator binds a real listening socket, accepts real sessions
// and persists after every mutation, so a distributed test can prove the model
// by starting this process, connecting publisher processes to it and
// terminating it with a real OS process kill.
//
// LIFETIME
// --------
// The process lifetime belongs to the operator, never to a stream: stdout
// carries the readiness report only, and stdin is never read. A harness often
// hands a child a closed or empty stdin, so a coordinator that stopped on EOF
// would disappear the instant it announced itself. It runs until the operating
// system terminates the process; a console-driven termination runs the control
// handler below, which releases the listener and the sessions first, and every
// mutation was already persisted before its response was sent.
#include "tool_common.hpp"

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <ostream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace {

using namespace arf_tool;

constexpr std::string_view tool_name = "arf_coordinator";

void print_usage(std::ostream& stream) {
  stream << "Adaptive Routing Fabric coordinator\n";
  stream << "\n";
  stream << "usage: arf_coordinator [--host H] [--port N] [--store PATH] [--ready-file PATH]\n";
  stream << "                       [--max-sessions N]\n";
  stream << "\n";
  stream << "  --host H          interface to bind (default 127.0.0.1)\n";
  stream << "  --port N          TCP port to bind; 0 asks the operating system for an\n";
  stream << "                    ephemeral port (default 0)\n";
  stream << "  --store PATH      durable store; the engine loads it at start and rewrites\n";
  stream << "                    it after every mutation\n";
  stream << "  --ready-file PATH writes '<host>:<port>' as the first line of PATH once the\n";
  stream << "                    socket is bound, so a harness can wait without a pipe\n";
  stream << "  --max-sessions N  override Limits::max_sessions\n";
  stream << "  --help            print this text and exit\n";
  stream << "\n";
  stream << "stdout: 'LISTENING <host> <port>' once bound, then 'RECOVERED ...' when a store\n";
  stream << "was loaded. stdin is never read; the process runs until it is terminated.\n";
  stream << "\nexit codes: 0 clean stop, 1 startup refused, 2 usage error\n";
}

[[nodiscard]] std::string in_quotes(std::string_view text) {
  return "'" + std::string(text) + "'";
}

// The ready file is published by rename, so a poller never observes a file that
// exists but is still empty: either the file is absent or it already holds the
// complete endpoint line.
[[nodiscard]] bool publish_ready_file(const std::string& path, const std::string& endpoint_text,
                                      std::string& error) {
  const std::string temporary = path + ".tmp";
  {
    std::ofstream stream(temporary, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!stream.is_open()) {
      error = "the ready file " + in_quotes(temporary) + " could not be created";
      return false;
    }
    stream.write(endpoint_text.data(), static_cast<std::streamsize>(endpoint_text.size()));
    stream.put('\n');
    stream.flush();
    if (!stream.good()) {
      error = "the ready file " + in_quotes(temporary) + " could not be written";
      return false;
    }
  }
  std::error_code status;
  std::filesystem::rename(temporary, path, status);
  if (status) {
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    error = "the ready file " + in_quotes(path) + " could not be published: " + status.message();
    return false;
  }
  return true;
}

// The atomic store writer publishes through a sibling temporary file. A crash
// or a forced kill can leave that file behind, so a clean shutdown removes it:
// every session has been joined by stop(), nothing can be writing any more, and
// the next boot must not find a stale half-store beside the real one.
void discard_stale_store_temporary(const std::string& store_path) {
  if (store_path.empty()) {
    return;
  }
  const std::string temporary = store_path + ".tmp";
  std::error_code status;
  if (!std::filesystem::exists(temporary, status)) {
    return;
  }
  status.clear();
  std::filesystem::remove(temporary, status);
  if (status) {
    write_stderr_line(std::string(tool_name) + ": the stale store file " + in_quotes(temporary) +
                      " could not be removed: " + status.message());
  }
}

#if defined(_WIN32)
// The console control handler runs on a thread of its own. It only asks the
// server to stop, so a console-initiated termination releases the listener and
// the sessions; returning FALSE then lets the default handler end the process.
std::atomic<CoordinatorServer*> g_console_server{nullptr};

BOOL WINAPI console_control_handler(DWORD event) {
  switch (event) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      if (CoordinatorServer* server = g_console_server.load(); server != nullptr) {
        server->stop();
      }
      break;
    default:
      break;
  }
  return FALSE;
}
#endif

// Blocks the main thread for the lifetime of the process. A condition variable
// is used rather than a poll loop so the coordinator consumes no processor time
// while it waits, and it is deliberately never notified: nothing inside this
// process ends a coordinator.
void wait_for_termination(CoordinatorServer& server, const std::string& store_path) {
#if defined(_WIN32)
  g_console_server.store(&server);
  (void)::SetConsoleCtrlHandler(&console_control_handler, TRUE);
#endif
  std::mutex mutex;
  std::condition_variable signal;
  std::unique_lock<std::mutex> lock(mutex);
  signal.wait(lock);
  // Reached only if a future change notifies the wait; it releases exactly the
  // resources a console-driven stop releases.
  server.stop();
  discard_stale_store_temporary(store_path);
#if defined(_WIN32)
  g_console_server.store(nullptr);
#endif
}

// Reports what a start-up load recovered. The counts come from the store on
// disk rather than from live engine state, because that is what the operator
// asked about: the durable state this boot inherited.
void report_recovered(const std::string& store_path) {
  std::string error;
  const std::optional<std::string> bytes = read_store_bytes(store_path, error);
  if (!bytes.has_value()) {
    write_stderr_line(std::string(tool_name) +
                      ": the recovered store could not be re-read: " + error);
    return;
  }
  const StoreDecodeResult decoded = decode_durable_state(*bytes);
  if (!decoded.ok()) {
    write_stderr_line(std::string(tool_name) + ": the recovered store did not decode: " +
                      std::string(to_string(decoded.status)) + " " + decoded.detail);
    return;
  }
  const DurableState& state = decoded.state;
  std::string line = "RECOVERED store=" + store_path;
  line += " epoch=" + std::to_string(state.epoch.value());
  line += " policies=" + std::to_string(state.policies.size());
  line += " revocations=" + std::to_string(state.revocations.size());
  line += " preferences=" + std::to_string(state.preferences.size());
  line += " stable_states=" + std::to_string(state.stable_states.size());
  line += " timings=" + std::to_string(state.timings.size());
  line += " history=" + std::to_string(state.history.size());
  write_stdout_line(line);
}

[[nodiscard]] int run(const ArgSet& args) {
  if (args.has("help")) {
    print_usage(std::cout);
    return exit_ok;
  }
  const std::optional<std::string> unknown =
      args.first_unknown({"host", "port", "store", "ready-file", "max-sessions", "help"});
  if (unknown.has_value()) {
    write_stderr_line(std::string(tool_name) + ": unknown option --" + *unknown);
    print_usage(std::cerr);
    return exit_usage;
  }
  if (!args.positional.empty()) {
    write_stderr_line(std::string(tool_name) + ": unexpected argument " +
                      in_quotes(args.positional[0]));
    print_usage(std::cerr);
    return exit_usage;
  }

  CoordinatorServer::Config config;
  config.id_prefix = std::string(tool_name);
  config.endpoint.host = args.value("host").value_or(std::string("127.0.0.1"));
  config.clock = std::make_shared<SteadyClock>();

  if (const std::optional<std::string> port_text = args.value("port"); port_text.has_value()) {
    std::uint64_t port = 0;
    if (!parse_unsigned(*port_text, port) || port > 65535) {
      write_stderr_line(std::string(tool_name) + ": --port must be an integer in 0..65535");
      return exit_usage;
    }
    config.endpoint.port = static_cast<std::uint16_t>(port);
  }
  if (config.endpoint.host.empty()) {
    write_stderr_line(std::string(tool_name) + ": --host must not be empty");
    return exit_usage;
  }
  if (const std::optional<std::string> sessions_text = args.value("max-sessions");
      sessions_text.has_value()) {
    std::uint64_t sessions = 0;
    if (!parse_unsigned(*sessions_text, sessions) || sessions == 0) {
      write_stderr_line(std::string(tool_name) + ": --max-sessions must be a positive integer");
      return exit_usage;
    }
    config.limits.max_sessions = sessions;
  }

  const std::string store_path = args.value("store").value_or(std::string());
  const std::string ready_file = args.value("ready-file").value_or(std::string());
  config.store_path = store_path;

  // Whether the store was already on disk is recorded before start(): the
  // server loads it during start, and the RECOVERED report below describes what
  // this boot inherited rather than what it has since written.
  bool store_present = false;
  if (!store_path.empty()) {
    std::error_code status;
    const bool present = std::filesystem::exists(store_path, status);
    if (status) {
      write_stderr_line(std::string(tool_name) + ": the store path " + in_quotes(store_path) +
                        " cannot be inspected: " + status.message());
      return exit_refused;
    }
    store_present = present;
  }

  // A ready file left behind by an earlier boot names an endpoint that no
  // longer exists. It is removed before the socket is bound, so a poller can
  // never read the previous boot's endpoint and connect to nothing.
  if (!ready_file.empty()) {
    std::error_code stale;
    std::filesystem::remove(ready_file, stale);
  }

  CoordinatorServer server(std::move(config));
  std::string error;
  if (!server.start(error)) {
    write_stderr_line(std::string(tool_name) + ": " + error);
    return exit_refused;
  }

  const Endpoint bound = server.endpoint();
  // The readiness line is written before anything else and flushed immediately:
  // a harness that reads this line (or the ready file below) may connect the
  // instant it sees it.
  write_stdout_line("LISTENING " + bound.host + " " + std::to_string(bound.port));
  if (!ready_file.empty()) {
    if (!publish_ready_file(ready_file, bound.host + ":" + std::to_string(bound.port), error)) {
      write_stderr_line(std::string(tool_name) + ": " + error);
      server.stop();
      return exit_refused;
    }
  }
  if (store_present) {
    report_recovered(store_path);
  }

  // Every mutation was persisted before its response was sent, so there is
  // nothing left to write at the end of the process; the wait below only keeps
  // this process alive for as long as the operator wants a coordinator.
  wait_for_termination(server, store_path);
  return exit_ok;
}

}  // namespace

int main(int argc, char** argv) {
  configure_standard_streams();
  const ArgSet args = parse_args(argc, argv);
  return run(args);
}

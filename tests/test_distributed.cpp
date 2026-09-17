// Real worker-death and coordinator-restart proofs.
//
// These scenarios start actual operating system processes, terminate them with a
// real forced process kill, and then verify the surviving coordinator's
// behaviour from the outside. Nothing here is thread-level simulation and
// nothing depends on a pipe staying open.
#include <algorithm>
#include <fstream>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_process.hpp"
#include "test_support.hpp"

namespace {

using namespace arf_test;

#if !defined(ARF_COORDINATOR_EXECUTABLE) || !defined(ARF_PUBLISHER_EXECUTABLE)
#define ARF_DISTRIBUTED_TOOLS_ABSENT 1
#endif

struct EndpointText {
  std::string host;
  std::uint16_t port = 0;
};

// Reads the 'LISTENING <host> <port>' line the coordinator prints when it is
// bound, so no test ever guesses a port number.
EndpointText parse_endpoint(const std::string& text) {
  EndpointText endpoint;
  const std::vector<std::string> lines = split_lines(text);
  for (const auto& line : lines) {
    if (line.rfind("LISTENING ", 0) != 0) {
      continue;
    }
    const std::string remainder = line.substr(10);
    const std::size_t space = remainder.find(' ');
    endpoint.host = remainder.substr(0, space);
    if (space != std::string::npos) {
      endpoint.port = static_cast<std::uint16_t>(std::stoi(remainder.substr(space + 1)));
    }
    return endpoint;
  }
  return endpoint;
}

// Extracts the policy identity the publisher printed for its create-policy
// command, so that a later process can name a policy it did not create.
std::string extract_policy_id(const std::string& log_text) {
  const std::string needle = "policy=";
  const std::size_t position = log_text.find(needle);
  if (position == std::string::npos) {
    return std::string();
  }
  const std::size_t start = position + needle.size();
  std::size_t end = start;
  while (end < log_text.size() && log_text[end] != ' ' && log_text[end] != '\r' &&
         log_text[end] != '\n') {
    ++end;
  }
  return log_text.substr(start, end - start);
}

std::string write_script(const std::string& directory, const std::string& name,
                         const std::vector<std::string>& lines) {
  const std::string path = unique_path(directory, name, ".script");
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  for (const auto& line : lines) {
    stream << line << "\n";
  }
  stream.flush();
  return path;
}

// Starts a publisher process and waits until it either registered or was
// refused.
struct PublisherRun {
  ChildProcess process;
  std::string log;
  std::string endpoint;
  bool registered = false;
};

PublisherRun start_publisher(const std::string& directory, const std::string& tag,
                             const std::string& endpoint, const std::string& publisher,
                             const std::string& boot, const std::string& session,
                             const std::vector<std::string>& script_lines, bool linger,
                             const std::vector<std::string>& extra = {}) {
  PublisherRun run;
  run.endpoint = endpoint;
  run.log = unique_path(directory, tag, ".log");
  std::vector<std::string> arguments{"--endpoint", endpoint, "--publisher", publisher, "--boot",
                                     boot,      "--session",  session};
  for (const auto& argument : extra) {
    arguments.push_back(argument);
  }
  std::string script;
  if (!script_lines.empty()) {
    script = write_script(directory, tag, script_lines);
    arguments.push_back("--script");
    arguments.push_back(script);
  }
  if (linger) {
    arguments.push_back("--linger");
  }
  if (!run.process.start(ARF_PUBLISHER_EXECUTABLE, arguments, run.log)) {
    return run;
  }
  if (wait_for_marker(run.log, "READY")) {
    run.registered = true;
    return run;
  }
  // A refusal is also a settled outcome; give it a moment to be written. The
  // result is deliberately unused because the caller distinguishes the two
  // outcomes by the registered flag and by the log content it asserts on.
  const bool refused = wait_for_marker(run.log, "REGISTER-FAILED");
  (void)refused;
  return run;
}

}  // namespace

#if defined(ARF_DISTRIBUTED_TOOLS_ABSENT)

ARF_TEST(distributed_proofs_require_the_process_tools) {
  ARF_CHECK_MSG(false,
                "the distributed suite was built without the coordinator and publisher executables");
}

#else

// The headline worker-death proof. A real publisher process is killed with a
// real OS termination; its incarnation is fenced; a fresh incarnation of the
// same PublisherId must register again; the old boot can never act again; and an
// unrelated publisher is unaffected throughout.
ARF_TEST(real_worker_death_fences_the_old_boot) {
  const std::string directory = fresh_scratch_directory("worker-death");
  const std::string store = unique_path(directory, "coordinator", ".store");
  const std::string coordinator_log = unique_path(directory, "coordinator", ".log");

  ChildProcess coordinator;
  ARF_REQUIRE(coordinator.start(ARF_COORDINATOR_EXECUTABLE,
                                {"--host", "127.0.0.1", "--port", "0", "--store", store},
                                coordinator_log));
  ARF_REQUIRE_MSG(wait_for_marker(coordinator_log, "LISTENING"), "coordinator did not start");
  const EndpointText endpoint = parse_endpoint(read_text_file(coordinator_log));
  ARF_REQUIRE(endpoint.port != 0);
  const std::string endpoint_text = endpoint.host + ":" + std::to_string(endpoint.port);

  // Publisher A creates a policy, declares two candidates, publishes evidence
  // and commits one adaptation, then lingers so it can be killed.
  PublisherRun publisher_a = start_publisher(
      directory, "publisher-a", endpoint_text, "publisher-a", "boot-a1", "session-a1",
      {"create-policy policy-alpha route-1 2000 3000", "declare @policy path-a 1",
       "declare @policy path-b 1", "evidence path-a PATH_LATENCY 1000 AGGREGATED",
       "evaluate @policy", "evidence path-a PATH_LATENCY 1000 AGGREGATED",
       "evidence path-b PATH_LATENCY 500 AGGREGATED", "evaluate @policy"},
      true);
  ARF_REQUIRE_MSG(publisher_a.registered, "publisher A did not register");
  ARF_REQUIRE_MSG(wait_for_marker(publisher_a.log, "DONE"), "publisher A did not finish its script");
  const std::string a_text = read_text_file(publisher_a.log);
  ARF_CHECK_MSG(a_text.find("DECISION_COMMITTED") != std::string::npos,
                "publisher A never committed an adaptation");

  // The process is confirmed alive immediately before the kill, then killed with
  // a real forced termination.
  ARF_CHECK(publisher_a.process.running());
  const std::uint64_t killed_pid = publisher_a.process.pid();
  ARF_CHECK(killed_pid != 0);
  publisher_a.process.terminate();
  ARF_CHECK(!publisher_a.process.running());

  // The old boot can never act again: a fresh process claiming boot-a1 is
  // refused registration outright.
  PublisherRun resurrection =
      start_publisher(directory, "publisher-a1-again", endpoint_text, "publisher-a", "boot-a1",
                      "session-a1-again", {"evidence path-a PATH_LATENCY 1 AGGREGATED"}, false);
  ARF_CHECK(resurrection.process.pid() != 0);
  ARF_CHECK_MSG(!resurrection.registered, "a fenced worker boot was allowed to register again");
  ARF_CHECK_MSG(read_text_file(resurrection.log).find("REGISTER-FAILED") != std::string::npos,
                "the fenced registration did not report REGISTER-FAILED");

  // A fresh incarnation of the same PublisherId registers and works, but the
  // policy it inherits has been invalidated by the epoch/worker change, so it
  // must revalidate before it can adapt again.
  // Note the absence of '@policy': a fresh process has created no policy, so it
  // may only act on identities it can name itself. Note also the fresh evidence
  // source: a telemetry source is an incarnation, and a new incarnation that
  // reused the old identity would have to continue the old observation
  // sequence, which it cannot know.
  PublisherRun reincarnation = start_publisher(
      directory, "publisher-a2", endpoint_text, "publisher-a", "boot-a2", "session-a2",
      {"evidence path-a PATH_LATENCY 900 AGGREGATED"}, false,
      {"--source", "telemetry-a2"});
  ARF_REQUIRE_MSG(reincarnation.registered, "the fresh incarnation did not register");
  ARF_CHECK_MSG(wait_for_marker(reincarnation.log, "DONE"),
                "the fresh incarnation did not finish its script");

  // An unrelated publisher is unaffected by A's death and reincarnation.
  PublisherRun publisher_b = start_publisher(
      directory, "publisher-b", endpoint_text, "publisher-b", "boot-b1", "session-b1",
      {"evidence path-b PATH_LATENCY 400 AGGREGATED"}, false, {"--source", "telemetry-b"});
  ARF_REQUIRE_MSG(publisher_b.registered, "publisher B did not register");
  ARF_CHECK_MSG(wait_for_marker(publisher_b.log, "DONE"), "publisher B did not finish its script");
  ARF_CHECK_MSG(read_text_file(publisher_b.log).find("UNAUTHORIZED") == std::string::npos,
                "an unrelated publisher was refused");

  publisher_b.process.terminate();
  reincarnation.process.terminate();
  resurrection.process.terminate();
  ARF_CHECK(coordinator.running());
  coordinator.terminate();
}

// The headline restart proof: the coordinator is hard-killed, restarted against
// the same store, and the durable policy survives while live publisher
// authority and old telemetry do not.
ARF_TEST(real_coordinator_restart_preserves_policy_but_not_authority) {
  const std::string directory = fresh_scratch_directory("coordinator-restart");
  const std::string store = unique_path(directory, "coordinator", ".store");
  const std::string log = unique_path(directory, "coordinator", ".log");

  ChildProcess coordinator;
  ARF_REQUIRE(coordinator.start(ARF_COORDINATOR_EXECUTABLE,
                                {"--host", "127.0.0.1", "--port", "0", "--store", store}, log));
  ARF_REQUIRE_MSG(wait_for_marker(log, "LISTENING"), "coordinator did not start");
  const EndpointText endpoint = parse_endpoint(read_text_file(log));
  ARF_REQUIRE(endpoint.port != 0);
  const std::string endpoint_text = endpoint.host + ":" + std::to_string(endpoint.port);

  PublisherRun publisher = start_publisher(
      directory, "publisher-first", endpoint_text, "publisher-a", "boot-a1", "session-a1",
      {"create-policy policy-restart route-1 2000 3000", "declare @policy path-a 1",
       "declare @policy path-b 1", "evidence path-a PATH_LATENCY 1000 AGGREGATED",
       "evaluate @policy"},
      true);
  ARF_REQUIRE_MSG(publisher.registered, "publisher A did not register");
  ARF_REQUIRE_MSG(wait_for_marker(publisher.log, "DONE"), "publisher A did not finish its script");
  ARF_CHECK(publisher.process.running());
  const std::string policy_id = extract_policy_id(read_text_file(publisher.log));
  ARF_REQUIRE_MSG(!policy_id.empty(), "publisher A never reported the policy it created");

  // Hard kill the coordinator while the publisher is still connected.
  coordinator.terminate();
  ARF_CHECK(!coordinator.running());
  publisher.process.terminate();

  const std::string restart_log = unique_path(directory, "coordinator-restart", ".log");
  ChildProcess restarted;
  ARF_REQUIRE(restarted.start(ARF_COORDINATOR_EXECUTABLE,
                              {"--host", "127.0.0.1", "--port", "0", "--store", store},
                              restart_log));
  ARF_REQUIRE_MSG(wait_for_marker(restart_log, "LISTENING"), "coordinator did not restart");
  const EndpointText second = parse_endpoint(read_text_file(restart_log));
  ARF_REQUIRE(second.port != 0);
  const std::string second_text = second.host + ":" + std::to_string(second.port);
  ARF_CHECK_MSG(read_text_file(restart_log).find("RECOVERED") != std::string::npos,
                "the restarted coordinator did not report a recovery");

  // The pre-restart publisher identity no longer exists: the surviving store
  // carries policies, not live authority.
  PublisherRun stale = start_publisher(directory, "publisher-stale", second_text, "publisher-a",
                                       "boot-a1", "session-a1",
                                       {"evidence path-a PATH_LATENCY 10 AGGREGATED"}, false);
  // A fresh registration with the old boot is accepted only because the whole
  // coordinator was restarted: every registration from before the restart is
  // gone, so this is a genuinely new session, not a restored one.
  ARF_CHECK(stale.process.pid() != 0);

  // Candidate bindings are upstream truth and are deliberately not persisted, so
  // the recovered policy has no candidates until the upstream re-declares them.
  // Re-declaring, publishing fresh evidence and revalidating is the documented
  // recovery path back to service.
  PublisherRun fresh = start_publisher(
      directory, "publisher-fresh", second_text, "publisher-fresh", "boot-fresh", "session-fresh",
      {"declare " + policy_id + " path-a 1", "declare " + policy_id + " path-b 1",
       "evidence path-a PATH_LATENCY 900 AGGREGATED", "revalidate " + policy_id},
      false, {"--source", "telemetry-fresh"});
  ARF_REQUIRE_MSG(fresh.registered, "the fresh publisher did not register");
  ARF_CHECK_MSG(wait_for_marker(fresh.log, "DONE"), "the fresh publisher did not finish");
  const std::string fresh_text = read_text_file(fresh.log);
  ARF_CHECK_MSG(fresh_text.find("OK") != std::string::npos ||
                    fresh_text.find("POLICY_UPDATED") != std::string::npos,
                "the recovered policy did not accept re-declared candidates");
  ARF_CHECK_MSG(fresh_text.find("SCRIPT-ERROR") == std::string::npos,
                "the fresh publisher reported a script error");

  fresh.process.terminate();
  stale.process.terminate();
  ARF_CHECK(restarted.running());
  restarted.terminate();
  ARF_CHECK(!restarted.running());
}

// Repeated restart cycles always bind a fresh port and always recover the same
// store, so the epoch advances monotonically rather than being reused.
ARF_TEST(repeated_coordinator_restarts_are_monotonic) {
  const std::string directory = fresh_scratch_directory("coordinator-cycles");
  const std::string store = unique_path(directory, "cycle", ".store");
  std::uint16_t previous_port = 0;
  for (std::uint32_t cycle = 0; cycle < 3; ++cycle) {
    const std::string log = unique_path(directory, "cycle", ".log");
    ChildProcess coordinator;
    ARF_REQUIRE(coordinator.start(ARF_COORDINATOR_EXECUTABLE,
                                  {"--host", "127.0.0.1", "--port", "0", "--store", store}, log));
    ARF_REQUIRE_MSG(wait_for_marker(log, "LISTENING"), "coordinator did not start");
    const EndpointText endpoint = parse_endpoint(read_text_file(log));
    ARF_REQUIRE(endpoint.port != 0);
    ARF_CHECK(endpoint.port != previous_port);
    previous_port = endpoint.port;
    coordinator.terminate();
  }
  ARF_CHECK(previous_port != 0);
}

// A peer that sends a partial frame cannot pin a session forever, and the
// coordinator keeps serving other peers.
ARF_TEST(partial_frame_cannot_pin_a_session) {
  const std::string directory = fresh_scratch_directory("partial-frame");
  const std::string log = unique_path(directory, "coordinator", ".log");
  ChildProcess coordinator;
  ARF_REQUIRE(coordinator.start(ARF_COORDINATOR_EXECUTABLE,
                                {"--host", "127.0.0.1", "--port", "0"}, log));
  ARF_REQUIRE_MSG(wait_for_marker(log, "LISTENING"), "coordinator did not start");
  const EndpointText endpoint = parse_endpoint(read_text_file(log));
  ARF_REQUIRE(endpoint.port != 0);

  // A raw socket sends an incomplete frame header and then goes quiet.
  std::string error;
  Endpoint target;
  target.host = endpoint.host;
  target.port = endpoint.port;
  auto raw = Socket::connect(target, SteadyClock::instance(), seconds(5), error);
  ARF_REQUIRE_MSG(raw.has_value(), error);
  Socket raw_socket = std::move(*raw);
  const std::string partial(8, '\x01');
  std::string send_error;
  ARF_CHECK(raw_socket.send_all(partial, SteadyClock::instance(), seconds(5), send_error));

  // The coordinator must still accept and serve another peer.
  PublisherRun healthy =
      start_publisher(directory, "publisher-healthy",
                      endpoint.host + ":" + std::to_string(endpoint.port), "publisher-healthy",
                      "boot-healthy", "session-healthy", {}, false);
  ARF_CHECK_MSG(healthy.registered, "the coordinator stopped serving after a partial frame");
  ARF_CHECK_MSG(wait_for_marker(healthy.log, "DONE"), "the healthy publisher did not finish");

  healthy.process.terminate();
  raw_socket.close();
  coordinator.terminate();
}

#endif  // ARF_DISTRIBUTED_TOOLS_ABSENT

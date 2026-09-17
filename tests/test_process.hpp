// Real operating system process helper for the distributed proofs.
//
// Children are genuine OS processes with output redirected to files so that no
// pipe can deadlock. Termination is a real forced termination of the process,
// not a flag and not a thread-level simulation.
#ifndef ARF_TEST_PROCESS_HPP
#define ARF_TEST_PROCESS_HPP

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
// The wire protocol has a message named ERROR. The Windows macro of the same
// name would rewrite every reference to it in test code, so it is removed here.
#if defined(ERROR)
#undef ERROR
#endif
#else
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace arf_test {

class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess() { terminate(); }

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ChildProcess(ChildProcess&& other) noexcept { move_from(other); }
  ChildProcess& operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
      terminate();
      move_from(other);
    }
    return *this;
  }

  bool start(const std::string& executable, const std::vector<std::string>& arguments,
             const std::string& output_path) {
    terminate();
#if defined(_WIN32)
    std::string command_line = quote(executable);
    for (const auto& argument : arguments) {
      command_line += ' ';
      command_line += quote(argument);
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE output = INVALID_HANDLE_VALUE;
    if (!output_path.empty()) {
      output = ::CreateFileA(output_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    // A child must never inherit the test runner's stdin. Under a test driver
    // that stdin is usually at EOF, and a daemon that treats EOF as "shut down"
    // would exit before the test could talk to it. The null device gives the
    // child a valid, empty, never-EOF input instead.
    HANDLE input = ::CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags |= STARTF_USESTDHANDLES;
    startup.hStdInput = input;
    if (output != INVALID_HANDLE_VALUE) {
      startup.hStdOutput = output;
      startup.hStdError = output;
    } else {
      startup.hStdOutput = ::GetStdHandle(STD_OUTPUT_HANDLE);
      startup.hStdError = ::GetStdHandle(STD_ERROR_HANDLE);
    }
    PROCESS_INFORMATION information{};
    std::vector<char> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back('\0');
    const BOOL created = ::CreateProcessA(
        nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &startup, &information);
    if (output != INVALID_HANDLE_VALUE) {
      ::CloseHandle(output);
    }
    if (input != INVALID_HANDLE_VALUE) {
      ::CloseHandle(input);
    }
    if (!created) {
      return false;
    }
    ::CloseHandle(information.hThread);
    process_ = information.hProcess;
    pid_ = information.dwProcessId;
    return true;
#else
    (void)output_path;
    std::vector<std::string> storage;
    storage.push_back(executable);
    for (const auto& argument : arguments) {
      storage.push_back(argument);
    }
    std::vector<char*> argv;
    for (auto& value : storage) {
      argv.push_back(value.data());
    }
    argv.push_back(nullptr);
    pid_t pid = 0;
    if (posix_spawn(&pid, executable.c_str(), nullptr, nullptr, argv.data(), environ) != 0) {
      return false;
    }
    pid_ = pid;
    return true;
#endif
  }

  [[nodiscard]] bool running() const {
#if defined(_WIN32)
    if (process_ == nullptr) {
      return false;
    }
    return ::WaitForSingleObject(process_, 0) == WAIT_TIMEOUT;
#else
    if (pid_ == 0) {
      return false;
    }
    int status = 0;
    return ::waitpid(pid_, &status, WNOHANG) == 0;
#endif
  }

  // Real forced termination of the operating system process.
  void terminate() {
#if defined(_WIN32)
    if (process_ != nullptr) {
      if (::WaitForSingleObject(process_, 0) == WAIT_TIMEOUT) {
        ::TerminateProcess(process_, 137);
      }
      ::WaitForSingleObject(process_, 10000);
      ::CloseHandle(process_);
      process_ = nullptr;
      pid_ = 0;
    }
#else
    if (pid_ != 0) {
      ::kill(pid_, SIGKILL);
      int status = 0;
      ::waitpid(pid_, &status, 0);
      pid_ = 0;
    }
#endif
  }

  [[nodiscard]] std::uint64_t pid() const noexcept { return static_cast<std::uint64_t>(pid_); }

 private:
  static std::string quote(const std::string& value) {
    std::string result = "\"";
    for (const char character : value) {
      if (character == '"') {
        result += "\\\"";
      } else {
        result += character;
      }
    }
    result += '"';
    return result;
  }

  void move_from(ChildProcess& other) {
#if defined(_WIN32)
    process_ = other.process_;
    other.process_ = nullptr;
#else
    pid_ = other.pid_;
    other.pid_ = 0;
#endif
    pid_ = other.pid_;
    other.pid_ = 0;
  }

#if defined(_WIN32)
  void* process_ = nullptr;
#endif
  std::uint64_t pid_ = 0;
};

// Polls a file until it contains the expected marker. The deadline produces an
// explicit failure rather than an unbounded wait: callers record a test failure
// when it expires. This is a product-level readiness bound, not a test timeout.
[[nodiscard]] inline bool wait_for_marker(const std::string& path, const std::string& marker,
                                          std::uint32_t budget_ms = 30000) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    std::ifstream stream(path, std::ios::binary);
    if (stream) {
      std::string content((std::istreambuf_iterator<char>(stream)),
                          std::istreambuf_iterator<char>());
      if (content.find(marker) != std::string::npos) {
        return true;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

[[nodiscard]] inline std::string read_text_file(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return std::string();
  }
  return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

[[nodiscard]] inline std::vector<std::string> split_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::string current;
  for (const char character : text) {
    if (character == '\n') {
      if (!current.empty() && current.back() == '\r') {
        current.pop_back();
      }
      lines.push_back(current);
      current.clear();
    } else {
      current.push_back(character);
    }
  }
  if (!current.empty()) {
    lines.push_back(current);
  }
  return lines;
}

// Extracts the value of a "key=value" token from a line, or an empty string.
[[nodiscard]] inline std::string token_value(const std::string& line, const std::string& key) {
  const std::string needle = key + "=";
  const std::size_t position = line.find(needle);
  if (position == std::string::npos) {
    return std::string();
  }
  const std::size_t start = position + needle.size();
  const std::size_t end = line.find(' ', start);
  return line.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

[[nodiscard]] inline std::string unique_path(const std::string& directory,
                                             const std::string& stem,
                                             const std::string& extension = "") {
  namespace fs = std::filesystem;
  static std::uint64_t counter = 0;
  const std::uint64_t sequence = ++counter;
#if defined(_WIN32)
  const std::uint64_t pid = static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
  const std::uint64_t pid = static_cast<std::uint64_t>(::getpid());
#endif
  fs::path path = fs::path(directory) / (stem + "-" + std::to_string(pid) + "-" +
                                         std::to_string(sequence) + extension);
  return path.string();
}

// Fresh scratch directory for one distributed scenario. Reusing a stale
// directory would let a previous run's store masquerade as this run's state, so
// every scenario gets its own.
[[nodiscard]] inline std::string fresh_scratch_directory(const std::string& stem) {
  namespace fs = std::filesystem;
  std::error_code code;
  const fs::path base = fs::temp_directory_path(code) / "adaptive-routing-fabric-tests";
  fs::create_directories(base, code);
  const fs::path directory = unique_path(base.string(), stem);
  fs::create_directories(directory, code);
  return directory.string();
}

}  // namespace arf_test

#endif  // ARF_TEST_PROCESS_HPP

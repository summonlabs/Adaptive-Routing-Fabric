// Test runner.
#include "test_framework.hpp"

#include <algorithm>
#include <cstring>

namespace arf_test {
namespace {

std::mutex& registry_mutex() {
  static std::mutex instance;
  return instance;
}

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

void register_test(const char* name, TestFunction function) {
  const std::lock_guard<std::mutex> lock(registry_mutex());
  registry().push_back(TestCase{name, function});
}

RunState& state() {
  static RunState instance;
  return instance;
}

void report_failure(const char* file, int line, const std::string& message) {
  std::ostringstream stream;
  stream << file << ":" << line << ": " << message;
  const std::lock_guard<std::mutex> lock(state().failure_mutex);
  state().failure_messages.push_back(stream.str());
  ++state().failures;
}

int run_all(int argc, char** argv) {
  std::string filter;
  for (int index = 1; index < argc; ++index) {
    if (std::strncmp(argv[index], "--filter=", 9) == 0) {
      filter = argv[index] + 9;
    }
  }
  std::vector<TestCase> tests = registry();
  // Registration order is a property of the link, which is stable for a given
  // build; sorting makes the report identical across linkers.
  std::sort(tests.begin(), tests.end(),
            [](const TestCase& a, const TestCase& b) { return a.name < b.name; });
  std::uint64_t executed = 0;
  for (const auto& test : tests) {
    if (!filter.empty() && test.name.find(filter) == std::string::npos) {
      continue;
    }
    ++executed;
    state().current_test = test.name;
    const std::uint64_t before = state().failures.load();
    // An escaping exception is a failure of that test, not a reason to lose the
    // report of everything that already ran.
    try {
      test.function();
    } catch (const std::exception& error) {
      report_failure(__FILE__, __LINE__,
                     test.name + ": unhandled exception: " + std::string(error.what()));
    } catch (...) {
      report_failure(__FILE__, __LINE__, test.name + ": unhandled non-standard exception");
    }
    const std::uint64_t after = state().failures.load();
    std::cout << (after == before ? "[ ok ] " : "[FAIL] ") << test.name << "\n";
    // Flushed per test so that a crash in a later test still leaves the report
    // of everything that already ran.
    std::cout.flush();
  }
  std::cout << "checks=" << state().checks.load() << " failures=" << state().failures.load()
            << " tests=" << executed << "\n";
  if (state().failures.load() != 0) {
    std::cout << "--- failures ---\n";
    const std::lock_guard<std::mutex> lock(state().failure_mutex);
    for (const auto& message : state().failure_messages) {
      std::cout << message << "\n";
    }
  }
  return state().failures.load() == 0 ? 0 : 1;
}

}  // namespace arf_test

int main(int argc, char** argv) { return ::arf_test::run_all(argc, argv); }

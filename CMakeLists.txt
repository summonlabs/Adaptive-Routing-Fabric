cmake_minimum_required(VERSION 3.20)

project(AdaptiveRoutingFabric
        VERSION 1.0.0
        DESCRIPTION "Adaptive Routing Fabric -- evidence-driven path-selection adaptation runtime"
        HOMEPAGE_URL "https://github.com/summonlabs/Adaptive-Routing-Fabric"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

option(ARF_BUILD_TESTS "Build the Adaptive Routing Fabric test suite" ON)
option(ARF_BUILD_TOOLS "Build the Adaptive Routing Fabric CLI and process tools" ON)
option(ARF_BUILD_EXAMPLES "Build the Adaptive Routing Fabric examples" ON)
option(ARF_BUILD_BENCHMARKS "Build the Adaptive Routing Fabric benchmarks" ON)
option(ARF_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(ARF_ENABLE_ANALYZE "Enable MSVC static analysis (/analyze)" OFF)
option(ARF_ENABLE_ASAN "Enable AddressSanitizer where the toolchain supports it" OFF)

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
  # System and third-party headers are included with angle brackets and are
  # treated as external, so their diagnostics -- including static analysis
  # findings inside the Windows SDK -- are not first-party findings. The
  # library's own headers are quoted ("adaptive_routing/...") and stay
  # first-party, so this is a narrow scope, not a blanket suppression.
  add_compile_options(/external:anglebrackets /external:W0)
  if(ARF_WARNINGS_AS_ERRORS)
    add_compile_options(/WX)
  endif()
  if(ARF_ENABLE_ANALYZE)
    add_compile_options(/analyze)
  endif()
  if(ARF_ENABLE_ASAN)
    # Genuine MSVC AddressSanitizer. Debug information is emitted alongside the
    # instrumentation because AddressSanitizer needs it for a usable report, and
    # because compiling ASan with /WX and without it is itself a warning
    # (C5072). The runtime DLL is copied next to the built executables by the
    # asan-runtime target below.
    #
    # The x64 AddressSanitizer runtime ships as a separate Visual Studio
    # component, so its absence is diagnosed here instead of surfacing later as
    # an obscure linker error about clang_rt.asan_dynamic_runtime_thunk.
    get_filename_component(ARF_COMPILER_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    if(NOT EXISTS "${ARF_COMPILER_BIN_DIR}/clang_rt.asan_dynamic-x86_64.dll")
      message(FATAL_ERROR
        "ARF_ENABLE_ASAN was requested but this toolchain has no x64 AddressSanitizer runtime "
        "next to the compiler (${ARF_COMPILER_BIN_DIR}). Install the Visual Studio component "
        "'C++ AddressSanitizer' (Microsoft.VisualStudio.Component.VC.ASAN) for the toolchain you "
        "are building with, or configure with a toolchain that has it.")
    endif()
    add_compile_options(/fsanitize=address /Zi)
    # The AddressSanitizer runtime is pulled in by the linker's default
    # /INFERASANLIBS, inferred from the instrumented objects; /fsanitize=address
    # is a compiler option and is not accepted on the link line.
    add_link_options(/DEBUG /INFERASANLIBS)
  endif()
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  if(ARF_WARNINGS_AS_ERRORS)
    add_compile_options(-Werror)
  endif()
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------

set(ARF_LIBRARY_SOURCES
  src/authority.cpp
  src/clock.cpp
  src/codec.cpp
  src/decision.cpp
  src/evidence.cpp
  src/fabric.cpp
  src/fabric_api.cpp
  src/fabric_evaluate.cpp
  src/fabric_evidence.cpp
  src/fabric_policy.cpp
  src/fabric_query.cpp
  src/ids.cpp
  src/lifecycle.cpp
  src/limits.cpp
  src/metrics.cpp
  src/outcome.cpp
  src/persistence.cpp
  src/policy.cpp
  src/transport.cpp
  src/upstream.cpp
  src/view.cpp
  src/wire.cpp
)

set(ARF_LIBRARY_HEADERS
  include/adaptive_routing/adaptive_routing.hpp
  include/adaptive_routing/authority.hpp
  include/adaptive_routing/clock.hpp
  include/adaptive_routing/codec.hpp
  include/adaptive_routing/decision.hpp
  include/adaptive_routing/evidence.hpp
  include/adaptive_routing/fabric.hpp
  include/adaptive_routing/ids.hpp
  include/adaptive_routing/limits.hpp
  include/adaptive_routing/lifecycle.hpp
  include/adaptive_routing/metrics.hpp
  include/adaptive_routing/outcome.hpp
  include/adaptive_routing/persistence.hpp
  include/adaptive_routing/policy.hpp
  include/adaptive_routing/transport.hpp
  include/adaptive_routing/upstream.hpp
  include/adaptive_routing/version.hpp
  include/adaptive_routing/view.hpp
  include/adaptive_routing/wire.hpp
)

add_library(AdaptiveRoutingFabric ${ARF_LIBRARY_SOURCES} ${ARF_LIBRARY_HEADERS})
add_library(SummonSoftwareLabs::AdaptiveRoutingFabric ALIAS AdaptiveRoutingFabric)

target_include_directories(AdaptiveRoutingFabric
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_compile_features(AdaptiveRoutingFabric PUBLIC cxx_std_20)
set_target_properties(AdaptiveRoutingFabric PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  OUTPUT_NAME AdaptiveRoutingFabric
)

find_package(Threads REQUIRED)
target_link_libraries(AdaptiveRoutingFabric PUBLIC Threads::Threads)

if(WIN32)
  # Winsock is used by the coordinator transport and by the acceptance-proving
  # distributed tests. It stays on the public link interface because the
  # installed transport headers are part of the package surface.
  target_link_libraries(AdaptiveRoutingFabric PUBLIC ws2_32)
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------

install(TARGETS AdaptiveRoutingFabric
  EXPORT AdaptiveRoutingFabricTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT AdaptiveRoutingFabricTargets
  FILE AdaptiveRoutingFabricTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AdaptiveRoutingFabric
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/AdaptiveRoutingFabricConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/AdaptiveRoutingFabricConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AdaptiveRoutingFabric
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/AdaptiveRoutingFabricConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/AdaptiveRoutingFabricConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/AdaptiveRoutingFabricConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AdaptiveRoutingFabric
)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

if(ARF_BUILD_TOOLS)
  add_executable(arf tools/arf.cpp)
  target_link_libraries(arf PRIVATE SummonSoftwareLabs::AdaptiveRoutingFabric)
  target_include_directories(arf PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")

  add_executable(arf_coordinator tools/arf_coordinator.cpp)
  target_link_libraries(arf_coordinator PRIVATE SummonSoftwareLabs::AdaptiveRoutingFabric)
  target_include_directories(arf_coordinator PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")

  add_executable(arf_publisher tools/arf_publisher.cpp)
  target_link_libraries(arf_publisher PRIVATE SummonSoftwareLabs::AdaptiveRoutingFabric)
  target_include_directories(arf_publisher PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")

  install(TARGETS arf arf_coordinator arf_publisher
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

if(ARF_BUILD_EXAMPLES)
  set(ARF_EXAMPLES
    example_latency_threshold
    example_utilization_hysteresis
    example_hold_down_suppression
    example_emergency_invalidation
    example_stale_evidence
    example_stale_path_authority
    example_worker_reincarnation
    example_coordinator_restart
    example_deterministic_tie_break
    example_rollback
  )
  foreach(example_name ${ARF_EXAMPLES})
    add_executable(${example_name} examples/${example_name}.cpp)
    target_link_libraries(${example_name} PRIVATE SummonSoftwareLabs::AdaptiveRoutingFabric)
    target_include_directories(${example_name}
      PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/examples")
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

if(ARF_BUILD_BENCHMARKS)
  add_executable(arf_benchmarks benchmarks/benchmark_main.cpp)
  target_link_libraries(arf_benchmarks PRIVATE SummonSoftwareLabs::AdaptiveRoutingFabric)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(ARF_BUILD_TESTS)
  enable_testing()

  function(arf_add_test target_name)
    add_executable(${target_name} ${ARGN})
    target_link_libraries(${target_name} PRIVATE SummonSoftwareLabs::AdaptiveRoutingFabric)
    target_include_directories(${target_name}
      PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    if(ARF_ENABLE_ANALYZE AND MSVC)
      # Library, tools and examples are held to the analyzer's default 16 KiB
      # frame threshold. Test translation units contain deliberately exhaustive
      # scenario functions, so they are given a larger -- but still modest --
      # budget instead of scattering suppressions through the tests.
      target_compile_options(${target_name} PRIVATE /analyze:stacksize32768)
    endif()
    add_test(NAME ${target_name} COMMAND ${target_name})
  endfunction()

  arf_add_test(arf_tests_core
    tests/test_main.cpp
    tests/test_identities.cpp
    tests/test_lifecycle.cpp
    tests/test_policy.cpp
    tests/test_evidence.cpp
    tests/test_metrics.cpp
  )

  arf_add_test(arf_tests_state
    tests/test_main.cpp
    tests/test_thresholds.cpp
    tests/test_races.cpp
    tests/test_property.cpp
    tests/test_oracle.cpp
  )

  arf_add_test(arf_tests_io
    tests/test_main.cpp
    tests/test_limits.cpp
    tests/test_persistence.cpp
    tests/test_wire.cpp
    tests/test_adversarial.cpp
  )

  if(ARF_BUILD_TOOLS)
    arf_add_test(arf_tests_distributed
      tests/test_main.cpp
      tests/test_distributed.cpp
    )
    target_compile_definitions(arf_tests_distributed PRIVATE
      ARF_COORDINATOR_EXECUTABLE="$<TARGET_FILE:arf_coordinator>"
      ARF_PUBLISHER_EXECUTABLE="$<TARGET_FILE:arf_publisher>"
    )
    add_dependencies(arf_tests_distributed arf_coordinator arf_publisher)
  endif()
endif()

# AddressSanitizer deploys its runtime as a DLL; place it next to the built
# executables so the sanitized binaries can load it without touching PATH.
if(ARF_ENABLE_ASAN AND MSVC)
  add_custom_target(asan-runtime ALL
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${ARF_COMPILER_BIN_DIR}/clang_rt.asan_dynamic-x86_64.dll"
            "${CMAKE_BINARY_DIR}/clang_rt.asan_dynamic-x86_64.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${ARF_COMPILER_BIN_DIR}/clang_rt.asan_dbg_dynamic-x86_64.dll"
            "${CMAKE_BINARY_DIR}/clang_rt.asan_dbg_dynamic-x86_64.dll"
    VERBATIM
    COMMENT "Deploying the AddressSanitizer runtime next to the built binaries"
  )
endif()

install(FILES LICENSE README.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/AdaptiveRoutingFabric
  OPTIONAL
)

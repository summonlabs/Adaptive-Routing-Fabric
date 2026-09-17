cmake_minimum_required(VERSION 3.20)

project(AdaptiveRoutingFabricConsumer LANGUAGES CXX)

# This project is deliberately independent of the library source tree. It only
# ever uses the installed package, which is what proves the exported surface is
# complete: no include path into the source tree, no build-tree target.
find_package(AdaptiveRoutingFabric CONFIG REQUIRED)

add_executable(arf_consumer consumer.cpp)
target_link_libraries(arf_consumer PRIVATE SummonSoftwareLabs::AdaptiveRoutingFabric)
target_compile_features(arf_consumer PRIVATE cxx_std_20)

if(MSVC)
  target_compile_options(arf_consumer PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
  if(ARF_CONSUMER_WARNINGS_AS_ERRORS)
    target_compile_options(arf_consumer PRIVATE /WX)
  endif()
endif()

enable_testing()
add_test(NAME arf_consumer COMMAND arf_consumer)

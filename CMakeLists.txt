cmake_minimum_required(VERSION 3.25)
project(loki VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(loki_warnings INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(loki_warnings INTERFACE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
  target_compile_options(loki_warnings INTERFACE $<$<CONFIG:Debug>:-Werror>)
endif()

find_package(Threads REQUIRED)

# Git SHA for evidence manifests (best effort; "unknown" outside a repo).
execute_process(
  COMMAND git rev-parse --short HEAD
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  OUTPUT_VARIABLE LOKI_GIT_SHA
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT LOKI_GIT_SHA)
  set(LOKI_GIT_SHA "unknown")
endif()

add_library(loki_core STATIC)
target_include_directories(loki_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src/transport")
target_compile_features(loki_core PUBLIC cxx_std_20)
target_link_libraries(loki_core PUBLIC Threads::Threads)
target_compile_definitions(loki_core PUBLIC LOKI_GIT_SHA="${LOKI_GIT_SHA}")
target_link_libraries(loki_core PRIVATE loki_warnings)

include(CTest)
if(BUILD_TESTING)
  include(FetchContent)
  FetchContent_Declare(
    Catch2
    URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.8.1.tar.gz
  )
  FetchContent_MakeAvailable(Catch2)
endif()

foreach(d util config transport scheduler faults evidence replay control reactor)
  add_subdirectory("src/${d}")
endforeach()
add_subdirectory(src/cli)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

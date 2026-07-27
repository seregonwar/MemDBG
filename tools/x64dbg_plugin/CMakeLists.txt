cmake_minimum_required(VERSION 3.24)
project(memdbg_x64dbg_plugin LANGUAGES C CXX)

# x64dbg plugins are Windows + MSVC import libs only.
if(NOT WIN32)
  message(FATAL_ERROR "memdbg_x64dbg_plugin requires Windows (x64dbg Plugin SDK)")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(FRONTEND_ROOT "${REPO_ROOT}/frontend")
set(GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
file(MAKE_DIRECTORY "${GENERATED_INCLUDE_DIR}/memdbg/core")

file(WRITE "${GENERATED_INCLUDE_DIR}/memdbg/core/memdbg_version.h"
  "#ifndef MEMDBG_CORE_MEMDBG_VERSION_H\n"
  "#define MEMDBG_CORE_MEMDBG_VERSION_H\n"
  "#define MEMDBG_VERSION_MAJOR 0\n"
  "#define MEMDBG_VERSION_MINOR 0\n"
  "#define MEMDBG_VERSION_PATCH 0\n"
  "#define MEMDBG_VERSION_STRING \"0.0.0-dev\"\n"
  "#endif\n"
)

find_package(Threads REQUIRED)

include(FetchContent)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

# Official Plugin SDK from x64dbg release assets (headers + x64/x32 import libs).
# Override with -DMEMDBG_X64DBG_SDK=/path/to/extracted/x64dbg-pluginsdk-cmake
# (directory that contains CMakeLists.txt + pluginsdk/).
set(MEMDBG_X64DBG_SDK "" CACHE PATH
  "Path to extracted x64dbg-pluginsdk-cmake (contains CMakeLists.txt + pluginsdk/)")
if(MEMDBG_X64DBG_SDK STREQUAL "" AND DEFINED ENV{MEMDBG_X64DBG_SDK})
  set(MEMDBG_X64DBG_SDK "$ENV{MEMDBG_X64DBG_SDK}" CACHE PATH "" FORCE)
endif()

if(MEMDBG_X64DBG_SDK AND EXISTS "${MEMDBG_X64DBG_SDK}/CMakeLists.txt"
   AND EXISTS "${MEMDBG_X64DBG_SDK}/pluginsdk/_plugins.h")
  message(STATUS "x64dbg plugin: using local SDK at ${MEMDBG_X64DBG_SDK}")
  include("${MEMDBG_X64DBG_SDK}/CMakeLists.txt")
else()
  set(MEMDBG_X64DBG_SDK_URL
    "https://github.com/x64dbg/x64dbg/releases/download/2026.05.27/x64dbg-pluginsdk-cmake.zip"
    CACHE STRING "Download URL for official x64dbg Plugin SDK (cmake package)")
  set(MEMDBG_X64DBG_SDK_HASH
    "SHA256=b669d6364816cbaed5257adad0df34a98a1791810a81941191d6f4aea74eb04e"
    CACHE STRING "URL_HASH for MEMDBG_X64DBG_SDK_URL")
  message(STATUS "x64dbg plugin: FetchContent ${MEMDBG_X64DBG_SDK_URL}")
  FetchContent_Declare(x64dbg_pluginsdk
    URL "${MEMDBG_X64DBG_SDK_URL}"
    URL_HASH "${MEMDBG_X64DBG_SDK_HASH}"
  )
  FetchContent_MakeAvailable(x64dbg_pluginsdk)
  # The package's CMakeLists is meant to be included (defines INTERFACE x64dbg +
  # x64dbg_plugin()). MakeAvailable already add_subdirectory'd it.
  if(NOT TARGET x64dbg)
    include("${x64dbg_pluginsdk_SOURCE_DIR}/CMakeLists.txt")
  endif()
endif()

if(NOT TARGET x64dbg)
  message(FATAL_ERROR "x64dbg Plugin SDK did not define INTERFACE target 'x64dbg'")
endif()

set(MEMDBG_X64DBG_CLIENT_SOURCES
  ${FRONTEND_ROOT}/src/core/client/memdbg_client.cpp
  ${FRONTEND_ROOT}/src/core/client/client_operations.cpp
  ${FRONTEND_ROOT}/src/core/client/client_scan.cpp
  ${FRONTEND_ROOT}/src/core/client/client_debug.cpp
  ${FRONTEND_ROOT}/src/core/platform.cpp
  ${REPO_ROOT}/src/util/lz4.c
)

add_library(memdbg_x64dbg_util STATIC
  plugin_util.cpp
)
target_include_directories(memdbg_x64dbg_util PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${GENERATED_INCLUDE_DIR}
  ${REPO_ROOT}/include
)
target_compile_definitions(memdbg_x64dbg_util PRIVATE
  WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)

add_library(memdbg_x64dbg_session STATIC
  memdbg_session.cpp
  ${MEMDBG_X64DBG_CLIENT_SOURCES}
)
target_link_libraries(memdbg_x64dbg_session PUBLIC memdbg_x64dbg_util)

target_include_directories(memdbg_x64dbg_session PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${GENERATED_INCLUDE_DIR}
  ${REPO_ROOT}/include
  ${FRONTEND_ROOT}/src
  ${FRONTEND_ROOT}/src/core
  ${FRONTEND_ROOT}/src/core/client
)

target_link_libraries(memdbg_x64dbg_session PUBLIC Threads::Threads)
target_compile_definitions(memdbg_x64dbg_session PRIVATE
  WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_link_libraries(memdbg_x64dbg_session PUBLIC ws2_32 shell32)

# Official helper from x64dbg-pluginsdk-cmake: sets .dp64/.dp32 and links SDK libs.
x64dbg_plugin(memdbg_x64dbg_plugin plugin_main.cpp)
set_target_properties(memdbg_x64dbg_plugin PROPERTIES
  OUTPUT_NAME "MemDBG"
  PREFIX ""
)
target_include_directories(memdbg_x64dbg_plugin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(memdbg_x64dbg_plugin PRIVATE memdbg_x64dbg_session)
target_compile_definitions(memdbg_x64dbg_plugin PRIVATE
  WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)

# Host unit tests for pure helpers (no Plugin SDK / no .dp64 link).
add_executable(memdbg_x64dbg_plugin_util_test
  tests/test_plugin_util.cpp
  plugin_util.cpp
)
target_include_directories(memdbg_x64dbg_plugin_util_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${GENERATED_INCLUDE_DIR}
  ${REPO_ROOT}/include
)
target_compile_definitions(memdbg_x64dbg_plugin_util_test PRIVATE
  WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)

if(MSVC)
  target_compile_options(memdbg_x64dbg_util PRIVATE /W4 /WX)
  target_compile_options(memdbg_x64dbg_session PRIVATE /W4 /WX)
  target_compile_options(memdbg_x64dbg_plugin PRIVATE /W4 /WX)
  target_compile_options(memdbg_x64dbg_plugin_util_test PRIVATE /W4 /WX)
endif()

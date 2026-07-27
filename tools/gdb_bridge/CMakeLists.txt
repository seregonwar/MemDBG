cmake_minimum_required(VERSION 3.24)
project(memdbg_gdb_bridge_standalone LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(FRONTEND_ROOT "${REPO_ROOT}/frontend")
set(GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
file(MAKE_DIRECTORY "${GENERATED_INCLUDE_DIR}/memdbg/core")

# Minimal version header so protocol includes resolve.
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

add_executable(memdbg_gdb_bridge
  main.cpp
  rsp_server.cpp
  rsp_handler.cpp
  gdb_regs.cpp
  ${FRONTEND_ROOT}/src/core/client/memdbg_client.cpp
  ${FRONTEND_ROOT}/src/core/client/client_operations.cpp
  ${FRONTEND_ROOT}/src/core/client/client_scan.cpp
  ${FRONTEND_ROOT}/src/core/client/client_debug.cpp
  ${FRONTEND_ROOT}/src/core/platform.cpp
  ${REPO_ROOT}/src/util/lz4.c
)

target_include_directories(memdbg_gdb_bridge PRIVATE
  ${GENERATED_INCLUDE_DIR}
  ${REPO_ROOT}/include
  ${FRONTEND_ROOT}/src
  ${FRONTEND_ROOT}/src/core
  ${FRONTEND_ROOT}/src/core/client
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(memdbg_gdb_bridge PRIVATE Threads::Threads)

add_executable(memdbg_gdb_bridge_test
  tests/test_gdb_bridge.cpp
  gdb_regs.cpp
  rsp_server.cpp
  ${FRONTEND_ROOT}/src/core/platform.cpp
)

target_include_directories(memdbg_gdb_bridge_test PRIVATE
  ${GENERATED_INCLUDE_DIR}
  ${REPO_ROOT}/include
  ${FRONTEND_ROOT}/src
  ${FRONTEND_ROOT}/src/core
  ${FRONTEND_ROOT}/src/core/client
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(memdbg_gdb_bridge_test PRIVATE Threads::Threads)

if(WIN32)
  target_compile_definitions(memdbg_gdb_bridge PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(memdbg_gdb_bridge_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(memdbg_gdb_bridge PRIVATE ws2_32 shell32)
  target_link_libraries(memdbg_gdb_bridge_test PRIVATE ws2_32)
endif()

if(MSVC)
  target_compile_options(memdbg_gdb_bridge PRIVATE /W4 /WX)
  target_compile_options(memdbg_gdb_bridge_test PRIVATE /W4 /WX)
else()
  target_compile_options(memdbg_gdb_bridge PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_gdb_bridge_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

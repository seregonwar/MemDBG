# MemDBG - Android shell built with Dear ImGui + OpenGL ES 3 + EGL (via GLSurfaceView).
# Copyright (C) 2026 SeregonWar
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The NDK lib is loaded by MainActivity via System.loadLibrary("memdbg"). The app
# reuses the desktop frontend UI code (draw_app / draw_mobile_app) and renders
# through the ImGui OpenGL ES 3 backend (imgui_impl_opengl3.cpp).

cmake_minimum_required(VERSION 3.22.1)

# ---- MemDBG version ---------------------------------------------------------

set(MEMDBG_VERSION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../VERSION")
# CMakeLists lives at repo/mobile/android/app/src/main/cpp -> 6 levels up to repo root.
set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../")
if(DEFINED MEMDBG_RELEASE_VERSION AND NOT "${MEMDBG_RELEASE_VERSION}" STREQUAL "")
  set(MEMDBG_VERSION_RAW "${MEMDBG_RELEASE_VERSION}")
else()
  file(STRINGS "${MEMDBG_VERSION_FILE}" MEMDBG_VERSION_LINES LIMIT_COUNT 1)
  list(GET MEMDBG_VERSION_LINES 0 MEMDBG_VERSION_RAW)
endif()

string(STRIP "${MEMDBG_VERSION_RAW}" MEMDBG_VERSION_DISPLAY)
string(REGEX REPLACE "^[vV]" "" MEMDBG_VERSION_DISPLAY "${MEMDBG_VERSION_DISPLAY}")
string(REGEX MATCH "^[0-9]+(\\.[0-9]+)?(\\.[0-9]+)?(\\.[0-9]+)?" MEMDBG_VERSION_NUMERIC "${MEMDBG_VERSION_DISPLAY}")
string(REPLACE "." ";" MEMDBG_VERSION_PARTS "${MEMDBG_VERSION_NUMERIC}")

set(MEMDBG_VERSION_MAJOR 0)
set(MEMDBG_VERSION_MINOR 0)
set(MEMDBG_VERSION_PATCH 0)
list(LENGTH MEMDBG_VERSION_PARTS MEMDBG_VERSION_PART_COUNT)
if(MEMDBG_VERSION_PART_COUNT GREATER 0)
  list(GET MEMDBG_VERSION_PARTS 0 MEMDBG_VERSION_MAJOR)
endif()
if(MEMDBG_VERSION_PART_COUNT GREATER 1)
  list(GET MEMDBG_VERSION_PARTS 1 MEMDBG_VERSION_MINOR)
endif()
if(MEMDBG_VERSION_PART_COUNT GREATER 2)
  list(GET MEMDBG_VERSION_PARTS 2 MEMDBG_VERSION_PATCH)
endif()

project(memdbg_android VERSION ${MEMDBG_VERSION_NUMERIC} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(FRONTEND_ROOT "${REPO_ROOT}/frontend")
set(MEMDBG_GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/include)

configure_file(
  ${REPO_ROOT}/include/memdbg/core/memdbg_version.h.in
  ${MEMDBG_GENERATED_INCLUDE_DIR}/memdbg/core/memdbg_version.h
  @ONLY
)

# ---- Embedded assets (English locale + imgui.ini) ---------------------------
set(MEMDBG_EMBEDDED_ASSETS_INC ${FRONTEND_ROOT}/src/ui/embedded_assets.inc)
add_custom_command(
  OUTPUT "${MEMDBG_EMBEDDED_ASSETS_INC}"
  COMMAND python3
    "${REPO_ROOT}/tools/embed_assets.py"
    "${FRONTEND_ROOT}/locales"
    "${REPO_ROOT}/imgui.ini"
    "${MEMDBG_EMBEDDED_ASSETS_INC}"
  DEPENDS
    "${REPO_ROOT}/tools/embed_assets.py"
    "${REPO_ROOT}/imgui.ini"
    ${FRONTEND_ROOT}/locales/en.json
  COMMENT "Generating embedded assets (English locale + imgui.ini) for Android"
)
set_source_files_properties("${MEMDBG_EMBEDDED_ASSETS_INC}" PROPERTIES GENERATED TRUE)
set_source_files_properties(
  ${FRONTEND_ROOT}/src/app/shell/memdbg_app.cpp
  PROPERTIES OBJECT_DEPENDS "${MEMDBG_EMBEDDED_ASSETS_INC}"
)

# ---- Deps: Dear ImGui (OpenGL ES3 backend) + stb + nlohmann_json + lua ------

find_library(log-lib log)
find_library(android-lib android)
find_library(gles-lib GLESv3)
find_library(egl-lib EGL)

include(FetchContent)

FetchContent_Declare(
  imgui
  GIT_REPOSITORY https://github.com/ocornut/imgui.git
  GIT_TAG v1.90.9
)
FetchContent_Declare(
  stb
  GIT_REPOSITORY https://github.com/nothings/stb.git
  GIT_TAG 31c1ad37456438565541f4919958214b6e762fb4
)
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_Declare(
  lua
  GIT_REPOSITORY https://github.com/lua/lua.git
  GIT_TAG v5.4.8
)
FetchContent_MakeAvailable(imgui stb nlohmann_json lua)

# ImGui with the OpenGL ES 3 backend. IMGUI_IMPL_OPENGL_ES3 makes the backend
# include <GLES3/gl3.h> from the NDK directly (no external GL loader needed).
add_library(memdbg_imgui_gles3 STATIC
  ${imgui_SOURCE_DIR}/imgui.cpp
  ${imgui_SOURCE_DIR}/imgui_demo.cpp
  ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp
  ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(memdbg_imgui_gles3 PUBLIC
  ${imgui_SOURCE_DIR}
  ${imgui_SOURCE_DIR}/backends
)
target_compile_definitions(memdbg_imgui_gles3 PUBLIC
  IMGUI_DEFINE_MATH_OPERATORS
  IMGUI_IMPL_OPENGL_ES3
  IMGUI_DISABLE_OBSOLETE_FUNCTIONS
)
target_link_libraries(memdbg_imgui_gles3 PUBLIC ${gles-lib})

# Embedded Lua 5.4 runtime (same on-device plugin runtime as iOS).
set(MEMDBG_LUA_SOURCES
  ${lua_SOURCE_DIR}/lapi.c
  ${lua_SOURCE_DIR}/lauxlib.c
  ${lua_SOURCE_DIR}/lbaselib.c
  ${lua_SOURCE_DIR}/lcode.c
  ${lua_SOURCE_DIR}/lcorolib.c
  ${lua_SOURCE_DIR}/lctype.c
  ${lua_SOURCE_DIR}/ldblib.c
  ${lua_SOURCE_DIR}/ldebug.c
  ${lua_SOURCE_DIR}/ldo.c
  ${lua_SOURCE_DIR}/ldump.c
  ${lua_SOURCE_DIR}/lfunc.c
  ${lua_SOURCE_DIR}/lgc.c
  ${lua_SOURCE_DIR}/liolib.c
  ${lua_SOURCE_DIR}/llex.c
  ${lua_SOURCE_DIR}/lmathlib.c
  ${lua_SOURCE_DIR}/lmem.c
  ${lua_SOURCE_DIR}/loadlib.c
  ${lua_SOURCE_DIR}/lobject.c
  ${lua_SOURCE_DIR}/lopcodes.c
  ${lua_SOURCE_DIR}/lparser.c
  ${lua_SOURCE_DIR}/lstate.c
  ${lua_SOURCE_DIR}/lstring.c
  ${lua_SOURCE_DIR}/lstrlib.c
  ${lua_SOURCE_DIR}/ltable.c
  ${lua_SOURCE_DIR}/ltablib.c
  ${lua_SOURCE_DIR}/ltm.c
  ${lua_SOURCE_DIR}/lundump.c
  ${lua_SOURCE_DIR}/lutf8lib.c
  ${lua_SOURCE_DIR}/lvm.c
  ${lua_SOURCE_DIR}/lzio.c
)
add_library(memdbg_lua STATIC ${MEMDBG_LUA_SOURCES})
target_include_directories(memdbg_lua PUBLIC ${lua_SOURCE_DIR})

# ---- MemDBG native shared library (libmemdbg.so) ----------------------------

set(MOBILE_NATIVE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/native_android.cpp
)

set(MEMDBG_FRONTEND_SOURCES
  ${FRONTEND_ROOT}/src/app/shell/memdbg_app.cpp

  ${FRONTEND_ROOT}/src/core/crash_logger.cpp
  ${FRONTEND_ROOT}/src/core/discovery_client.cpp
  ${FRONTEND_ROOT}/src/core/github_profile.cpp
  ${FRONTEND_ROOT}/src/core/client/memdbg_client.cpp
  ${FRONTEND_ROOT}/src/core/platform.cpp
  ${FRONTEND_ROOT}/src/core/release_check.cpp
  ${FRONTEND_ROOT}/src/core/udp_log_listener.cpp

  ${FRONTEND_ROOT}/src/plugins/repository/plugin_manager.cpp
  ${FRONTEND_ROOT}/src/plugins/repository/gui_bridge.cpp

  ${FRONTEND_ROOT}/src/ui/icon_font.cpp
  ${FRONTEND_ROOT}/src/ui/ui_widgets.cpp
  ${FRONTEND_ROOT}/src/ui/file_picker.cpp

  ${FRONTEND_ROOT}/src/locale/locale.cpp
  ${FRONTEND_ROOT}/src/locale/locale_repository.cpp

  ${REPO_ROOT}/src/pal/lz4.c
  ${REPO_ROOT}/src/tracer/syscall_names.c

  ${FRONTEND_ROOT}/src/screens/home/screen_home.cpp
  ${FRONTEND_ROOT}/src/screens/consoles/screen_consoles.cpp
  ${FRONTEND_ROOT}/src/screens/processes/screen_processes.cpp
  ${FRONTEND_ROOT}/src/screens/memory/screen_memory.cpp
  ${FRONTEND_ROOT}/src/screens/scanner/screen_scanner.cpp
  ${FRONTEND_ROOT}/src/screens/pointer_scanner/screen_pointer_scanner.cpp
  ${FRONTEND_ROOT}/src/screens/aob_scanner/screen_aob_scanner.cpp
  ${FRONTEND_ROOT}/src/screens/trainer/screen_trainer.cpp
  ${FRONTEND_ROOT}/src/screens/plugins/screen_plugins.cpp
  ${FRONTEND_ROOT}/src/screens/plugins/screen_plugin_gui.cpp
  ${FRONTEND_ROOT}/src/screens/logs/screen_logs.cpp
  ${FRONTEND_ROOT}/src/screens/telemetry/screen_telemetry.cpp
  ${FRONTEND_ROOT}/src/screens/task_manager/screen_taskmgr.cpp
  ${FRONTEND_ROOT}/src/screens/settings/screen_settings.cpp
  ${FRONTEND_ROOT}/src/screens/credits/screen_credits.cpp
  ${FRONTEND_ROOT}/src/screens/debugger/debugger_disassembly.cpp
  ${FRONTEND_ROOT}/src/screens/debugger/screen_debugger.cpp
  ${FRONTEND_ROOT}/src/screens/tracer/screen_tracer.cpp

  ${FRONTEND_ROOT}/src/trainer/batchcode_parser.cpp
  ${FRONTEND_ROOT}/src/trainer/trainer_format.cpp

  ${FRONTEND_ROOT}/src/scanner/heuristics/auto_search.cpp
  ${FRONTEND_ROOT}/src/scanner/structure_compare.cpp
)

add_library(memdbg SHARED ${MOBILE_NATIVE_SOURCES} ${MEMDBG_FRONTEND_SOURCES})

target_compile_definitions(memdbg PRIVATE
  MEMDBG_PLATFORM_ANDROID
  # The shared frontend is compiled in "mobile mode" exactly like the iOS shell:
  # GLFW/OpenGL desktop paths, hosted GUI plugins and std::system network calls
  # are gated out, while the embedded Lua plugin runtime and the touch layout
  # (draw_mobile_app / set_mobile_safe_area) stay enabled. The guards reuse the
  # existing MEMDBG_PLATFORM_IOS branches; a later refactor can promote it to a
  # MEMDBG_PLATFORM_MOBILE umbrella macro.
  MEMDBG_PLATFORM_IOS
  MEMDBG_ENABLE_EMBEDDED_LUA
  IMGUI_DEFINE_MATH_OPERATORS
)

target_include_directories(memdbg PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${REPO_ROOT}/include
  ${FRONTEND_ROOT}/src
  ${FRONTEND_ROOT}/src/app
  ${FRONTEND_ROOT}/src/app/shell
  ${FRONTEND_ROOT}/src/core
  ${FRONTEND_ROOT}/src/core/client
  ${FRONTEND_ROOT}/src/ui
  ${FRONTEND_ROOT}/src/screens
  ${FRONTEND_ROOT}/src/screens/aob_scanner
  ${FRONTEND_ROOT}/src/screens/consoles
  ${FRONTEND_ROOT}/src/screens/credits
  ${FRONTEND_ROOT}/src/screens/debugger
  ${FRONTEND_ROOT}/src/screens/home
  ${FRONTEND_ROOT}/src/screens/logs
  ${FRONTEND_ROOT}/src/screens/memory
  ${FRONTEND_ROOT}/src/screens/plugins
  ${FRONTEND_ROOT}/src/screens/pointer_scanner
  ${FRONTEND_ROOT}/src/screens/processes
  ${FRONTEND_ROOT}/src/screens/scanner
  ${FRONTEND_ROOT}/src/screens/settings
  ${FRONTEND_ROOT}/src/screens/task_manager
  ${FRONTEND_ROOT}/src/screens/telemetry
  ${FRONTEND_ROOT}/src/screens/tracer
  ${FRONTEND_ROOT}/src/trainer
  ${FRONTEND_ROOT}/src/scanner
  ${FRONTEND_ROOT}/src/scanner/heuristics
  ${FRONTEND_ROOT}/src/locale
  ${FRONTEND_ROOT}/src/plugins
  ${FRONTEND_ROOT}/src/plugins/repository
  ${FRONTEND_ROOT}/src/proto
  ${stb_SOURCE_DIR}
  ${nlohmann_json_SOURCE_DIR}/include
  ${REPO_ROOT}/external/sjson
)

target_link_libraries(memdbg PRIVATE
  memdbg_imgui_gles3
  memdbg_lua
  nlohmann_json::nlohmann_json
  ${log-lib}
  ${android-lib}
  ${gles-lib}
  ${egl-lib}
)

if(NOT MSVC)
  target_compile_options(memdbg PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_imgui_gles3 PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()
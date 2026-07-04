# MemDBG - iOS/iPadOS shell built with Dear ImGui + Metal.
# Copyright (C) 2026 SeregonWar
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Usage (generates an Xcode project that the release workflow archives):
#   cmake -S mobile/ios -B build/ios -G Xcode \
#         -DCMAKE_SYSTEM_NAME=iOS \
#         -DCMAKE_OSX_ARCHITECTURES=arm64 \
#         -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
#         -DMEMDBG_RELEASE_VERSION=0.2.0
#   xcodebuild -project build/ios/MemDBG.xcodeproj \
#         -scheme MemDBGMobile -configuration Release -sdk iphoneos \
#         -archivePath build/ios/MemDBG.xcarchive CODE_SIGNING_ALLOWED=NO archive

cmake_minimum_required(VERSION 3.24)

# ---- MemDBG version ---------------------------------------------------------

set(MEMDBG_VERSION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../VERSION")
if(DEFINED MEMDBG_RELEASE_VERSION AND NOT "${MEMDBG_RELEASE_VERSION}" STREQUAL "")
  set(MEMDBG_VERSION_RAW "${MEMDBG_RELEASE_VERSION}")
else()
  file(STRINGS "${MEMDBG_VERSION_FILE}" MEMDBG_VERSION_LINES LIMIT_COUNT 1)
  list(GET MEMDBG_VERSION_LINES 0 MEMDBG_VERSION_RAW)
endif()

string(STRIP "${MEMDBG_VERSION_RAW}" MEMDBG_VERSION_DISPLAY)
string(REGEX REPLACE "^[vV]" "" MEMDBG_VERSION_DISPLAY "${MEMDBG_VERSION_DISPLAY}")
if(NOT MEMDBG_VERSION_DISPLAY MATCHES "^[0-9]+\\.[0-9]+(\\.[0-9]+)?(\\.[0-9]+)?([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$")
  message(FATAL_ERROR "Invalid MemDBG version: ${MEMDBG_VERSION_RAW}")
endif()
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

project(memdbg_mobile VERSION ${MEMDBG_VERSION_NUMERIC} LANGUAGES C CXX OBJCXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_OBJCXX_STANDARD 11)
set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)

set(FRONTEND_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../frontend")
set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MEMDBG_GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/include)

configure_file(
  ${REPO_ROOT}/include/memdbg/core/memdbg_version.h.in
  ${MEMDBG_GENERATED_INCLUDE_DIR}/memdbg/core/memdbg_version.h
  @ONLY
)

# ---- Embedded assets (English locale + imgui.ini) ---------------------------
# Generated at build time by tools/embed_assets.py — same recipe as the desktop frontend.
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
  COMMENT "Generating embedded assets (English locale + imgui.ini) for iOS"
)
set_source_files_properties("${MEMDBG_EMBEDDED_ASSETS_INC}" PROPERTIES GENERATED TRUE)
set_source_files_properties(
  ${FRONTEND_ROOT}/src/app/shell/memdbg_app.cpp
  PROPERTIES OBJECT_DEPENDS "${MEMDBG_EMBEDDED_ASSETS_INC}"
)

# ---- Dear ImGui (Metal backend) + stb + nlohmann_json -----------------------

find_package(Threads REQUIRED)

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
FetchContent_MakeAvailable(imgui stb nlohmann_json)

add_library(memdbg_imgui_metal STATIC
  ${imgui_SOURCE_DIR}/imgui.cpp
  ${imgui_SOURCE_DIR}/imgui_demo.cpp
  ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp
  ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_metal.mm
)
target_include_directories(memdbg_imgui_metal PUBLIC
  ${imgui_SOURCE_DIR}
  ${imgui_SOURCE_DIR}/backends
)
target_compile_definitions(memdbg_imgui_metal PUBLIC IMGUI_DEFINE_MATH_OPERATORS)
target_link_libraries(memdbg_imgui_metal PUBLIC
  "-framework Metal"
  "-framework MetalKit"
  "-framework Foundation"
  "-framework UIKit"
  "-framework QuartzCore"
)

# ---- MemDBG mobile executable -----------------------------------------------

set(MOBILE_SOURCES
  main.ios.mm
  AppDelegate.mm
  ViewController.mm

  # Shared frontend sources (re-using the desktop UI via draw_app()).
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

add_executable(MemDBGMobile ${MOBILE_SOURCES})

target_compile_definitions(MemDBGMobile PRIVATE
  MEMDBG_PLATFORM_IOS
  IMGUI_DEFINE_MATH_OPERATORS
)

target_include_directories(MemDBGMobile PRIVATE
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
)

target_link_libraries(MemDBGMobile PRIVATE
  memdbg_imgui_metal
  nlohmann_json::nlohmann_json
  Threads::Threads
  "-framework Metal"
  "-framework MetalKit"
  "-framework UIKit"
  "-framework Foundation"
  "-framework CoreGraphics"
  "-framework QuartzCore"
)

# Bundle + signing configuration.

set(IOS_SIGNING_TEAM "" CACHE STRING "Apple Developer Team ID (empty = unsigned/simulator)")
if(IOS_SIGNING_TEAM)
  set(IOS_SIGN_STYLE "Automatic")
  set(IOS_SIGN_ALLOWED "YES")
  set(IOS_SIGN_REQUIRED "YES")
  set(IOS_SIGN_IDENTITY "Apple Development")
  set(IOS_DEV_TEAM XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${IOS_SIGNING_TEAM}")
else()
  set(IOS_SIGN_STYLE "Manual")
  set(IOS_SIGN_ALLOWED "NO")
  set(IOS_SIGN_REQUIRED "NO")
  set(IOS_SIGN_IDENTITY "")
  set(IOS_DEV_TEAM "")
endif()

set_target_properties(MemDBGMobile PROPERTIES
  OUTPUT_NAME "MemDBG"
  MACOSX_BUNDLE TRUE
  MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist"
  MACOSX_BUNDLE_GUI_IDENTIFIER "io.github.seregonwar.memdbg.mobile"
  MACOSX_BUNDLE_BUNDLE_NAME "MemDBG"
  MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
  MACOSX_BUNDLE_BUNDLE_VERSION "1"
  XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
  XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "14.0"
  XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "io.github.seregonwar.memdbg.mobile"
  XCODE_ATTRIBUTE_CODE_SIGN_STYLE "${IOS_SIGN_STYLE}"
  XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "${IOS_SIGN_ALLOWED}"
  XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "${IOS_SIGN_REQUIRED}"
  XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "${IOS_SIGN_IDENTITY}"
  XCODE_ATTRIBUTE_ENABLE_BITCODE "NO"
  ${IOS_DEV_TEAM}
)

set_source_files_properties(
  "${CMAKE_CURRENT_SOURCE_DIR}/LaunchScreen.storyboard"
  PROPERTIES MACOSX_PACKAGE_LOCATION "Resources"
)
target_sources(MemDBGMobile PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/LaunchScreen.storyboard"
)

if(NOT MSVC)
  target_compile_options(MemDBGMobile PRIVATE -Wall -Wextra -Wpedantic)
endif()
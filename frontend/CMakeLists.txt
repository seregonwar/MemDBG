cmake_minimum_required(VERSION 3.24)

set(MEMDBG_VERSION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../VERSION")
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

project(memdbg_frontend VERSION ${MEMDBG_VERSION_NUMERIC} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(MEMDBG_PLUGIN_REPOSITORY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../plugin-repository")
set(MEMDBG_THEME_REPOSITORY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../theme-repository")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
foreach(config DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config} ${CMAKE_BINARY_DIR}/bin)
endforeach()

include(FetchContent)

set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  glfw
  GIT_REPOSITORY https://github.com/glfw/glfw.git
  GIT_TAG 3.4
)

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
  simdjson
  GIT_REPOSITORY https://github.com/simdjson/simdjson.git
  GIT_TAG v3.11.4
)

FetchContent_Declare(
  lua
  GIT_REPOSITORY https://github.com/lua/lua.git
  GIT_TAG v5.4.8
)

FetchContent_MakeAvailable(glfw imgui stb nlohmann_json simdjson lua)

set_source_files_properties(
  ${CMAKE_CURRENT_SOURCE_DIR}/../external/sjson/sJson.c
  PROPERTIES COMPILE_DEFINITIONS "JSON_IMPLEMENTATION")

find_package(OpenGL REQUIRED)
find_package(Threads REQUIRED)

add_library(imgui STATIC
  ${imgui_SOURCE_DIR}/imgui.cpp
  ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp
  ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)

target_include_directories(imgui PUBLIC
  ${imgui_SOURCE_DIR}
  ${imgui_SOURCE_DIR}/backends
)

target_link_libraries(imgui PUBLIC glfw OpenGL::GL)

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
  ${lua_SOURCE_DIR}/loslib.c
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
if(UNIX AND NOT APPLE)
  target_link_libraries(memdbg_lua PUBLIC m ${CMAKE_DL_LIBS})
endif()

# ---- memdbg_frontend ----

set(MEMDBG_APP_ICON_PNG ${CMAKE_CURRENT_SOURCE_DIR}/../assets/app-icon.png)
set(MEMDBG_APP_ICON_ICO ${CMAKE_CURRENT_SOURCE_DIR}/../assets/app-icon.ico)
set(MEMDBG_APP_ICON_ICNS ${CMAKE_CURRENT_SOURCE_DIR}/../assets/app-icon.icns)
set(MEMDBG_GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/include)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/../include/memdbg/core/memdbg_version.h.in
  ${MEMDBG_GENERATED_INCLUDE_DIR}/memdbg/core/memdbg_version.h
  @ONLY
)

# ---- Embedded assets (English locale + imgui.ini) ----
# Generated at build time by tools/embed_assets.py.
set(MEMDBG_EMBEDDED_ASSETS_INC ${CMAKE_CURRENT_SOURCE_DIR}/src/ui/embedded_assets.inc)
add_custom_command(
  OUTPUT ${MEMDBG_EMBEDDED_ASSETS_INC}
  COMMAND python3
    "${CMAKE_CURRENT_SOURCE_DIR}/../tools/embed_assets.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/locales"
    "${CMAKE_CURRENT_SOURCE_DIR}/../imgui.ini"
    "${MEMDBG_EMBEDDED_ASSETS_INC}"
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/../tools/embed_assets.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/../imgui.ini"
    ${CMAKE_CURRENT_SOURCE_DIR}/locales/en.json
  COMMENT "Generating embedded assets (English locale + imgui.ini)"
)
set_source_files_properties(${MEMDBG_EMBEDDED_ASSETS_INC} PROPERTIES GENERATED TRUE)
set_source_files_properties(
  src/app/shell/memdbg_app.cpp
  PROPERTIES OBJECT_DEPENDS ${MEMDBG_EMBEDDED_ASSETS_INC}
)

add_executable(memdbg_frontend
  # app (entry point, shell, shared state)
  src/app/main.cpp
  src/app/shell/memdbg_app.cpp
  src/app/shell/state.cpp
  src/app/shell/connection.cpp
  src/app/shell/chrome.cpp
  src/app/shell/session.cpp
  src/app/shell/mobile/mobile.cpp

  # core (backend clients)
  src/core/crash_logger.cpp
  src/core/discovery_client.cpp
  src/core/github_profile.cpp
  src/core/client/memdbg_client.cpp
  src/core/platform.cpp
  src/core/payload_fetcher.cpp
  src/core/release_check.cpp
  src/core/udp_log_listener.cpp

  # plugins (repository manifests + Lua/Python script runner)
  src/plugins/repository/plugin_manager.cpp
  src/plugins/repository/gui_bridge.cpp
  src/plugins/repository/lua_engine.cpp

  # sandbox (standalone hardened script execution)
  src/sandbox/sandbox_common.cpp
  src/sandbox/sandbox_lua.cpp

  # cheats (repository sources and catalog)
  src/cheats/cheat_repository.cpp

  # ui (widgets, theme, fonts, icons, file picker)
  src/ui/icon_font.cpp
  src/ui/ui_widgets.cpp
  src/ui/theme_manager.cpp
  src/ui/file_picker.cpp

  # locale (i18n / translations)
  src/locale/locale.cpp
  src/locale/locale_repository.cpp

  # pal (LZ4 decompression for client)
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/pal/lz4.c

  # tracer (syscall name lookup)
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/tracer/syscall_names.c

  # screens
  src/screens/home/screen_home.cpp
  src/screens/consoles/screen_consoles.cpp
  src/screens/processes/screen_processes.cpp
  src/screens/memory/screen_memory.cpp
  src/screens/scanner/scanner_helpers.cpp
  src/screens/scanner/scanner_compare.cpp
  src/screens/scanner/scanner_session.cpp
  src/screens/scanner/scanner_async.cpp
  src/screens/scanner/screen_scanner.cpp
  src/screens/pointer_scanner/screen_pointer_scanner.cpp
  src/screens/aob_scanner/screen_aob_scanner.cpp
  src/screens/trainer/screen_trainer.cpp
  src/screens/plugins/screen_plugins.cpp
  src/screens/plugins/screen_plugin_gui.cpp
  src/screens/logs/screen_logs.cpp
    src/screens/klog/screen_klog.cpp
  src/screens/telemetry/screen_telemetry.cpp
  src/screens/task_manager/screen_taskmgr.cpp
  src/screens/settings/screen_settings.cpp
  src/screens/credits/screen_credits.cpp
  src/screens/debugger/debugger_disassembly.cpp
  src/screens/debugger/debugger_patch_studio.cpp
  src/screens/debugger/debugger_notebook.cpp
  src/screens/debugger/screen_debugger.cpp
  src/screens/tracer/screen_tracer.cpp
  src/screens/lua/screen_lua.cpp

  # trainer
  src/trainer/batchcode_parser.cpp
  src/trainer/trainer_format.cpp

  # scanner (heuristics and structure comparison)
  src/scanner/heuristics/auto_search.cpp
  src/scanner/structure_compare.cpp

  # sJson (C99 JSON parser, compiled once)
  ${CMAKE_CURRENT_SOURCE_DIR}/../external/sjson/sJson.c
)

target_include_directories(memdbg_frontend PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/app
  ${CMAKE_CURRENT_SOURCE_DIR}/src/app/shell
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core/client
  ${CMAKE_CURRENT_SOURCE_DIR}/src/ui
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/aob_scanner
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/consoles
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/credits
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/debugger
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/home
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/logs
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/memory
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/plugins
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/pointer_scanner
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/processes
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/scanner
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/settings
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/task_manager
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/telemetry
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/trainer
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens/lua
  ${CMAKE_CURRENT_SOURCE_DIR}/src/trainer
  ${CMAKE_CURRENT_SOURCE_DIR}/src/scanner
  ${CMAKE_CURRENT_SOURCE_DIR}/src/scanner/heuristics
  ${CMAKE_CURRENT_SOURCE_DIR}/src/locale
  ${CMAKE_CURRENT_SOURCE_DIR}/src/plugins
  ${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/repository
  ${CMAKE_CURRENT_SOURCE_DIR}/src/sandbox
  ${CMAKE_CURRENT_SOURCE_DIR}/src/cheats
  ${CMAKE_CURRENT_SOURCE_DIR}/src/proto
  ${stb_SOURCE_DIR}
  ${nlohmann_json_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../external/sjson
)

target_compile_definitions(memdbg_frontend PRIVATE MEMDBG_ENABLE_EMBEDDED_LUA)
target_link_libraries(memdbg_frontend PRIVATE imgui memdbg_lua Threads::Threads)

if(MSVC)
  target_compile_options(memdbg_frontend PRIVATE /utf-8)
endif()

if(APPLE)
  target_sources(memdbg_frontend PRIVATE ${MEMDBG_APP_ICON_ICNS})
  set_source_files_properties(${MEMDBG_APP_ICON_ICNS}
    PROPERTIES MACOSX_PACKAGE_LOCATION "Resources"
  )
  set_target_properties(memdbg_frontend PROPERTIES
    OUTPUT_NAME "MemDBG"
    MACOSX_BUNDLE TRUE
    MACOSX_BUNDLE_BUNDLE_NAME "MemDBG"
    MACOSX_BUNDLE_GUI_IDENTIFIER "io.github.seregonwar.memdbg"
    MACOSX_BUNDLE_ICON_FILE "app-icon.icns"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_COPYRIGHT "Copyright (C) 2026 SeregonWar"
  )
  add_custom_command(TARGET memdbg_frontend POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:memdbg_frontend>/assets"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MEMDBG_APP_ICON_PNG}"
            "$<TARGET_FILE_DIR:memdbg_frontend>/assets/app-icon.png"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${MEMDBG_PLUGIN_REPOSITORY_DIR}"
            "$<TARGET_FILE_DIR:memdbg_frontend>/plugin-repository"
    COMMAND ${CMAKE_COMMAND} -E rm -f
            "$<TARGET_FILE_DIR:memdbg_frontend>/plugin-repository/.DS_Store"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${MEMDBG_THEME_REPOSITORY_DIR}"
            "$<TARGET_FILE_DIR:memdbg_frontend>/theme-repository"
    COMMAND ${CMAKE_COMMAND} -E rm -f
            "$<TARGET_FILE_DIR:memdbg_frontend>/theme-repository/.DS_Store"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/../cheat-repository"
            "$<TARGET_FILE_DIR:memdbg_frontend>/cheat-repository"
    COMMAND ${CMAKE_COMMAND} -E rm -f
            "$<TARGET_FILE_DIR:memdbg_frontend>/cheat-repository/.DS_Store"
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_BUNDLE_CONTENT_DIR:memdbg_frontend>/Resources/assets"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MEMDBG_APP_ICON_PNG}"
            "$<TARGET_BUNDLE_CONTENT_DIR:memdbg_frontend>/Resources/assets/app-icon.png"
  )
else()
  add_custom_command(TARGET memdbg_frontend POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:memdbg_frontend>/assets"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MEMDBG_APP_ICON_PNG}"
            "$<TARGET_FILE_DIR:memdbg_frontend>/assets/app-icon.png"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${MEMDBG_PLUGIN_REPOSITORY_DIR}"
            "$<TARGET_FILE_DIR:memdbg_frontend>/plugin-repository"
    COMMAND ${CMAKE_COMMAND} -E rm -f
            "$<TARGET_FILE_DIR:memdbg_frontend>/plugin-repository/.DS_Store"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${MEMDBG_THEME_REPOSITORY_DIR}"
            "$<TARGET_FILE_DIR:memdbg_frontend>/theme-repository"
    COMMAND ${CMAKE_COMMAND} -E rm -f
            "$<TARGET_FILE_DIR:memdbg_frontend>/theme-repository/.DS_Store"
  )
endif()

if(WIN32)
  file(TO_CMAKE_PATH "${MEMDBG_APP_ICON_ICO}" MEMDBG_APP_ICON_ICO_CMAKE)
  set(MEMDBG_WINDOWS_RC "${CMAKE_CURRENT_BINARY_DIR}/memdbg_frontend.rc")
  file(WRITE "${MEMDBG_WINDOWS_RC}" "IDI_MEMDBG_ICON ICON \"${MEMDBG_APP_ICON_ICO_CMAKE}\"\n")
  target_sources(memdbg_frontend PRIVATE "${MEMDBG_WINDOWS_RC}")
endif()

if(UNIX AND NOT APPLE)
  set(MEMDBG_DESKTOP_FILE "${CMAKE_CURRENT_BINARY_DIR}/MemDBG.desktop")
  file(WRITE "${MEMDBG_DESKTOP_FILE}"
"[Desktop Entry]\n"
"Type=Application\n"
"Name=MemDBG\n"
"Comment=Native memory debugger frontend\n"
"Exec=memdbg_frontend\n"
"Icon=app-icon\n"
"Terminal=false\n"
"Categories=Development;Debugger;\n"
  )
  add_custom_command(TARGET memdbg_frontend POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MEMDBG_DESKTOP_FILE}"
            "$<TARGET_FILE_DIR:memdbg_frontend>/MemDBG.desktop"
  )
endif()

# ---- memdbg_probe (standalone protocol tester) ----

add_executable(memdbg_probe
  src/proto/protocol_probe.cpp
  src/core/client/memdbg_client.cpp
  src/core/platform.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/pal/lz4.c
)

target_include_directories(memdbg_probe PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core/client
  ${CMAKE_CURRENT_SOURCE_DIR}/src/proto
)

target_link_libraries(memdbg_probe PRIVATE Threads::Threads)

# ---- memdbg_auto_search_test ----

add_executable(memdbg_auto_search_test
  tests/test_auto_search.cpp
  src/scanner/heuristics/auto_search.cpp
)

target_include_directories(memdbg_auto_search_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/app
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${CMAKE_CURRENT_SOURCE_DIR}/src/scanner
  ${CMAKE_CURRENT_SOURCE_DIR}/src/scanner/heuristics
  ${imgui_SOURCE_DIR}
  ${nlohmann_json_SOURCE_DIR}/include
)

# Standalone test — no DLL dependencies.  Static MSVC runtime produces
# a single self-contained .exe that works on any Windows machine.
if(MSVC)
  set_property(TARGET memdbg_auto_search_test PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---- memdbg_structure_compare_test ----

add_executable(memdbg_structure_compare_test
  tests/test_structure_compare.cpp
  src/scanner/structure_compare.cpp
)

target_include_directories(memdbg_structure_compare_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/scanner
)

# Standalone test — no DLL dependencies.
if(MSVC)
  set_property(TARGET memdbg_structure_compare_test PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---- memdbg_app_state_parsing_test ----

add_executable(memdbg_app_state_parsing_test
  tests/test_app_state_parsing.cpp
)

target_include_directories(memdbg_app_state_parsing_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/app
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${imgui_SOURCE_DIR}
  ${nlohmann_json_SOURCE_DIR}/include
)

# Standalone test — no DLL dependencies.
if(MSVC)
  set_property(TARGET memdbg_app_state_parsing_test PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---- memdbg_payload_fetcher_test ----

add_executable(memdbg_payload_fetcher_test
  tests/test_payload_fetcher.cpp
)

target_include_directories(memdbg_payload_fetcher_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
)

# Standalone test — no DLL dependencies.
if(MSVC)
  set_property(TARGET memdbg_payload_fetcher_test PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---- memdbg_trainer_formats_test ----

add_executable(memdbg_trainer_formats_test
  tests/test_trainer_formats.cpp
  src/trainer/batchcode_parser.cpp
  src/trainer/trainer_format.cpp
  src/core/client/memdbg_client.cpp
  src/core/crash_logger.cpp
  src/core/discovery_client.cpp
  src/core/payload_fetcher.cpp
  src/core/udp_log_listener.cpp
  src/core/platform.cpp
  src/locale/locale.cpp
  src/plugins/repository/lua_engine.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/pal/lz4.c

  # sJson (C99 JSON parser, compiled once)
  ${CMAKE_CURRENT_SOURCE_DIR}/../external/sjson/sJson.c
)

target_link_libraries(memdbg_trainer_formats_test PRIVATE imgui memdbg_lua Threads::Threads)

target_compile_definitions(memdbg_trainer_formats_test PRIVATE
  MEMDBG_ENABLE_EMBEDDED_LUA)

target_include_directories(memdbg_trainer_formats_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/app
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core/client
  ${CMAKE_CURRENT_SOURCE_DIR}/src/trainer
  ${CMAKE_CURRENT_SOURCE_DIR}/src/plugins
  ${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/repository
  ${CMAKE_CURRENT_SOURCE_DIR}/src/sandbox
  ${CMAKE_CURRENT_SOURCE_DIR}/../external/sjson
  ${imgui_SOURCE_DIR}
  ${nlohmann_json_SOURCE_DIR}/include
  ${simdjson_SOURCE_DIR}/singleheader
)

target_link_libraries(memdbg_trainer_formats_test PRIVATE simdjson)

# Static MSVC runtime avoids runtime DLL dependency that causes exit 127
# on Windows CI runners.
if(MSVC)
  set_property(TARGET memdbg_trainer_formats_test PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---- memdbg_locale_manager_test ----

add_executable(memdbg_locale_manager_test
  tests/test_locale_manager.cpp
  src/locale/locale.cpp
)

target_include_directories(memdbg_locale_manager_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/locale
  ${nlohmann_json_SOURCE_DIR}/include
)

# Static MSVC runtime avoids runtime DLL dependency that causes exit 127
# on Windows CI runners when the redistributable DLL search path differs.
if(MSVC)
  set_property(TARGET memdbg_locale_manager_test PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---- memdbg_plugin_manager_test ----

add_executable(memdbg_plugin_manager_test
  tests/test_plugin_manager.cpp
  src/plugins/repository/plugin_manager.cpp
  src/sandbox/sandbox_common.cpp
  src/sandbox/sandbox_lua.cpp
  src/core/platform.cpp
)

target_compile_definitions(memdbg_plugin_manager_test PRIVATE
  MEMDBG_ENABLE_EMBEDDED_LUA
  MEMDBG_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/.."
)

target_include_directories(memdbg_plugin_manager_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${CMAKE_CURRENT_SOURCE_DIR}/src/plugins
  ${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/repository
  ${CMAKE_CURRENT_SOURCE_DIR}/src/sandbox
  ${nlohmann_json_SOURCE_DIR}/include
)
target_link_libraries(memdbg_plugin_manager_test PRIVATE memdbg_lua Threads::Threads)

# ---- memdbg_sandbox_lua_test ----

add_executable(memdbg_sandbox_lua_test
  tests/sandbox/test_sandbox_lua.cpp
  src/sandbox/sandbox_common.cpp
  src/sandbox/sandbox_lua.cpp
)

target_compile_definitions(memdbg_sandbox_lua_test PRIVATE
  MEMDBG_ENABLE_EMBEDDED_LUA
  MEMDBG_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/.."
)

target_include_directories(memdbg_sandbox_lua_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/sandbox
  ${nlohmann_json_SOURCE_DIR}/include
)
target_link_libraries(memdbg_sandbox_lua_test PRIVATE memdbg_lua Threads::Threads)

# ---- memdbg_sandbox_fuzz_test ----

add_executable(memdbg_sandbox_fuzz_test
  tests/sandbox/test_sandbox_fuzz.cpp
  src/sandbox/sandbox_common.cpp
  src/sandbox/sandbox_lua.cpp
)

target_compile_definitions(memdbg_sandbox_fuzz_test PRIVATE
  MEMDBG_ENABLE_EMBEDDED_LUA
  MEMDBG_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/.."
)

target_include_directories(memdbg_sandbox_fuzz_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/sandbox
  ${nlohmann_json_SOURCE_DIR}/include
)
target_link_libraries(memdbg_sandbox_fuzz_test PRIVATE memdbg_lua Threads::Threads)

# ---- memdbg_sandbox_limits_test ----

add_executable(memdbg_sandbox_limits_test
  tests/sandbox/test_sandbox_limits.cpp
  src/sandbox/sandbox_common.cpp
  src/sandbox/sandbox_lua.cpp
)

target_compile_definitions(memdbg_sandbox_limits_test PRIVATE
  MEMDBG_ENABLE_EMBEDDED_LUA
  MEMDBG_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/.."
)

target_include_directories(memdbg_sandbox_limits_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/sandbox
  ${nlohmann_json_SOURCE_DIR}/include
)
target_link_libraries(memdbg_sandbox_limits_test PRIVATE memdbg_lua Threads::Threads)

# ---- memdbg_sandbox_hardened_test (regression suite for all known vulnerability vectors) ----

add_executable(memdbg_sandbox_hardened_test
  tests/sandbox/test_sandbox_hardened.cpp
  src/sandbox/sandbox_common.cpp
  src/sandbox/sandbox_lua.cpp
)

target_compile_definitions(memdbg_sandbox_hardened_test PRIVATE
  MEMDBG_ENABLE_EMBEDDED_LUA
  MEMDBG_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/.."
)

target_include_directories(memdbg_sandbox_hardened_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/sandbox
  ${nlohmann_json_SOURCE_DIR}/include
)
target_link_libraries(memdbg_sandbox_hardened_test PRIVATE memdbg_lua Threads::Threads)

# ---- memdbg_sandbox_python_test ----

add_executable(memdbg_sandbox_python_test
  tests/sandbox/test_sandbox_python.cpp
  src/sandbox/sandbox_common.cpp
  src/sandbox/sandbox_python.cpp
)

target_include_directories(memdbg_sandbox_python_test PRIVATE
  ${MEMDBG_GENERATED_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/sandbox
)
target_link_libraries(memdbg_sandbox_python_test PRIVATE Threads::Threads)

# ---- platform specific ----

if(APPLE)
  target_compile_definitions(memdbg_frontend PRIVATE GL_SILENCE_DEPRECATION)
endif()

if(WIN32)
  target_compile_definitions(memdbg_frontend PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(memdbg_probe PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(memdbg_trainer_formats_test PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(memdbg_plugin_manager_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(memdbg_sandbox_lua_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(memdbg_sandbox_fuzz_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(memdbg_sandbox_limits_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(memdbg_sandbox_python_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(memdbg_frontend PRIVATE ws2_32 shell32 comdlg32 ole32)
  target_link_libraries(memdbg_probe PRIVATE ws2_32 shell32)
  target_link_libraries(memdbg_trainer_formats_test PRIVATE ws2_32)
  target_link_libraries(memdbg_plugin_manager_test PRIVATE ws2_32 shell32)
  target_link_libraries(memdbg_sandbox_lua_test PRIVATE ws2_32)
  target_link_libraries(memdbg_sandbox_fuzz_test PRIVATE ws2_32)
  target_link_libraries(memdbg_sandbox_limits_test PRIVATE ws2_32)
  target_link_libraries(memdbg_sandbox_python_test PRIVATE ws2_32)
endif()

if(MSVC)
  target_compile_options(memdbg_frontend PRIVATE /W4)
  target_compile_options(memdbg_probe PRIVATE /W4)
  target_compile_options(memdbg_auto_search_test PRIVATE /W4)
  target_compile_options(memdbg_structure_compare_test PRIVATE /W4)
  target_compile_options(memdbg_app_state_parsing_test PRIVATE /W4)
  target_compile_options(memdbg_payload_fetcher_test PRIVATE /W4)
  target_compile_options(memdbg_trainer_formats_test PRIVATE /W4)
  target_compile_options(memdbg_locale_manager_test PRIVATE /W4)
  target_compile_options(memdbg_plugin_manager_test PRIVATE /W4)
  target_compile_options(memdbg_sandbox_lua_test PRIVATE /W4)
  target_compile_options(memdbg_sandbox_fuzz_test PRIVATE /W4)
  target_compile_options(memdbg_sandbox_limits_test PRIVATE /W4)
  target_compile_options(memdbg_sandbox_python_test PRIVATE /W4)
else()
  target_compile_options(memdbg_frontend PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_probe PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_auto_search_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_structure_compare_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_app_state_parsing_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_payload_fetcher_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_trainer_formats_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_locale_manager_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_plugin_manager_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_sandbox_lua_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_sandbox_fuzz_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_sandbox_limits_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_sandbox_python_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

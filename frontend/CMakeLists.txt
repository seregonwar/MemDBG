cmake_minimum_required(VERSION 3.24)

project(memdbg_frontend LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
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
  GIT_TAG master
)

FetchContent_MakeAvailable(glfw imgui stb)

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

# ---- memdbg_frontend ----

add_executable(memdbg_frontend
  # app (entry point, shell, shared state)
  src/app/main.cpp
  src/app/memdbg_app.cpp

  # core (backend clients)
  src/core/github_profile.cpp
  src/core/memdbg_client.cpp
  src/core/platform.cpp
  src/core/udp_log_listener.cpp

  # ui (widgets, theme, fonts, icons, file picker)
  src/ui/icon_font.cpp
  src/ui/ui_widgets.cpp
  src/ui/file_picker.cpp

  # pal (LZ4 decompression for client)
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/pal/lz4.c

  # screens
  src/screens/screen_home.cpp
  src/screens/screen_consoles.cpp
  src/screens/screen_processes.cpp
  src/screens/screen_memory.cpp
  src/screens/screen_scanner.cpp
  src/screens/screen_pointer_scanner.cpp
  src/screens/screen_aob_scanner.cpp
  src/screens/screen_trainer.cpp
  src/screens/screen_logs.cpp
  src/screens/screen_telemetry.cpp
  src/screens/screen_settings.cpp
  src/screens/screen_credits.cpp

  # trainer
  src/trainer/trainer_format.cpp

  # scanner (auto-search heuristic engine)
  src/scanner/auto_search.cpp
)

target_include_directories(memdbg_frontend PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/app
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${CMAKE_CURRENT_SOURCE_DIR}/src/ui
  ${CMAKE_CURRENT_SOURCE_DIR}/src/screens
  ${CMAKE_CURRENT_SOURCE_DIR}/src/trainer
  ${CMAKE_CURRENT_SOURCE_DIR}/src/scanner
  ${CMAKE_CURRENT_SOURCE_DIR}/src/proto
  ${stb_SOURCE_DIR}
)

target_link_libraries(memdbg_frontend PRIVATE imgui Threads::Threads)

add_custom_command(TARGET memdbg_frontend POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:memdbg_frontend>/assets"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/../assets/logo-nobg.png"
          "$<TARGET_FILE_DIR:memdbg_frontend>/assets/logo-nobg.png"
)

# ---- memdbg_probe (standalone protocol tester) ----

add_executable(memdbg_probe
  src/proto/protocol_probe.cpp
  src/core/memdbg_client.cpp
  src/core/platform.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/pal/lz4.c
)

target_include_directories(memdbg_probe PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${CMAKE_CURRENT_SOURCE_DIR}/src/proto
)

target_link_libraries(memdbg_probe PRIVATE Threads::Threads)

# ---- memdbg_auto_search_test ----

add_executable(memdbg_auto_search_test
  tests/test_auto_search.cpp
  src/scanner/auto_search.cpp
)

target_include_directories(memdbg_auto_search_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/app
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${CMAKE_CURRENT_SOURCE_DIR}/src/scanner
  ${imgui_SOURCE_DIR}
)

# ---- platform specific ----

if(APPLE)
  target_compile_definitions(memdbg_frontend PRIVATE GL_SILENCE_DEPRECATION)
endif()

if(WIN32)
  target_compile_definitions(memdbg_frontend PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(memdbg_probe PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(memdbg_frontend PRIVATE ws2_32 shell32)
  target_link_libraries(memdbg_probe PRIVATE ws2_32 shell32)
endif()

if(MSVC)
  target_compile_options(memdbg_frontend PRIVATE /W4)
  target_compile_options(memdbg_probe PRIVATE /W4)
  target_compile_options(memdbg_auto_search_test PRIVATE /W4)
else()
  target_compile_options(memdbg_frontend PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_probe PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_auto_search_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

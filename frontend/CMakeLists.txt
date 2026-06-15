cmake_minimum_required(VERSION 3.24)

project(memdbg_frontend LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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

add_executable(memdbg_frontend
  src/main.cpp
  src/github_profile.cpp
  src/memdbg_app.cpp
  src/memdbg_client.cpp
  src/udp_log_listener.cpp
)

target_include_directories(memdbg_frontend PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${stb_SOURCE_DIR}
)

target_link_libraries(memdbg_frontend PRIVATE imgui Threads::Threads)

add_executable(memdbg_probe
  src/protocol_probe.cpp
  src/memdbg_client.cpp
)

target_include_directories(memdbg_probe PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(memdbg_probe PRIVATE Threads::Threads)

if(APPLE)
  target_compile_definitions(memdbg_frontend PRIVATE GL_SILENCE_DEPRECATION)
endif()

if(MSVC)
  target_compile_options(memdbg_frontend PRIVATE /W4)
  target_compile_options(memdbg_probe PRIVATE /W4)
else()
  target_compile_options(memdbg_frontend PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(memdbg_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()

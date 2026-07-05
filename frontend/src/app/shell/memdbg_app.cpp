/*
 * MemDBG - ImGui console frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "icon_font.hpp"
#include "embedded_logo.hpp"
#include "embedded_assets.inc"
#include "github_profile.hpp"
#include "release_check.hpp"
#include "platform.hpp"
#include "locale/locale.hpp"
#include "locale/locale_repository.hpp"
#include "plugins/repository/gui_bridge.hpp"
#include "trainer/batchcode_parser.hpp"
#include "trainer/trainer_format.hpp"
#include "memdbg/core/memdbg_version.h"

#include "imgui.h"

#if !defined(MEMDBG_PLATFORM_IOS)
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "stb_image.h"

#if !defined(MEMDBG_PLATFORM_IOS)
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif
#endif

namespace memdbg::frontend {

namespace {

#if defined(MEMDBG_PLATFORM_IOS)
/* Metal texture handle (id<MTLTexture>) stored as void*; the iOS shell owns
 * the real upload via ImGui_ImplMetal, so the desktop OpenGL path is skipped. */
using TextureHandle = void *;
#else
using TextureHandle = GLuint;
#endif

struct TextureAsset {
  TextureHandle texture{};
  int width = 0;
  int height = 0;
  int content_width = 0;
  int content_height = 0;
  ImVec2 uv0 = ImVec2(0.0f, 0.0f);
  ImVec2 uv1 = ImVec2(1.0f, 1.0f);
  bool attempted = false;
};

static TextureAsset s_logo_texture;
static std::filesystem::path s_executable_dir;

static ImTextureID texture_id(TextureHandle texture) {
#if defined(MEMDBG_PLATFORM_IOS)
  return reinterpret_cast<ImTextureID>(texture);
#else
  return reinterpret_cast<ImTextureID>(static_cast<intptr_t>(texture));
#endif
}

[[maybe_unused]] static void init_executable_dir(const char *argv0) {
  if (argv0 == nullptr || argv0[0] == '\0') return;

  try {
    std::error_code ec;
    std::filesystem::path path(argv0);
    if (path.is_relative()) {
      path = std::filesystem::current_path(ec) / path;
      if (ec) { path = std::filesystem::path(argv0); ec.clear(); }
    }
    const std::filesystem::path canonical = std::filesystem::weakly_canonical(path, ec);
    if (!ec && !canonical.empty()) path = canonical;
    if (path.has_parent_path()) s_executable_dir = path.parent_path();
  } catch (...) { /* argv0 parsing is best-effort */ }
}

#if !defined(__APPLE__)
static void add_asset_candidates(std::vector<std::filesystem::path> &out,
                                 const std::filesystem::path &root,
                                 const std::filesystem::path &relative_path) {
  if (root.empty()) return;
  std::filesystem::path current = root;
  for (int depth = 0; depth < 6; ++depth) {
    out.push_back(current / relative_path);
    if (!current.has_parent_path() || current.parent_path() == current) break;
    current = current.parent_path();
  }
}

static std::filesystem::path find_asset_path(const char *relative_path) {
  const std::filesystem::path rel(relative_path);
  std::vector<std::filesystem::path> candidates;
  candidates.reserve(16);
  candidates.push_back(rel);
  add_asset_candidates(candidates, s_executable_dir, rel);

  std::error_code ec;
  add_asset_candidates(candidates, std::filesystem::current_path(ec), rel);

  for (const auto &candidate : candidates) {
    ec.clear();
    if (std::filesystem::exists(candidate, ec) && !ec) {
      const std::filesystem::path canonical = std::filesystem::weakly_canonical(candidate, ec);
      return !ec && !canonical.empty() ? canonical : candidate;
    }
  }
  return rel;
}
#endif

static void compute_content_uv(TextureAsset &asset, const unsigned char *pixels) {
  int min_x = asset.width;
  int min_y = asset.height;
  int max_x = -1;
  int max_y = -1;

  for (int y = 0; y < asset.height; ++y) {
    for (int x = 0; x < asset.width; ++x) {
      const unsigned char alpha = pixels[(static_cast<size_t>(y) * asset.width + x) * 4U + 3U];
      if (alpha < 8U) continue;
      min_x = std::min(min_x, x);
      min_y = std::min(min_y, y);
      max_x = std::max(max_x, x);
      max_y = std::max(max_y, y);
    }
  }

  if (max_x < min_x || max_y < min_y) {
    asset.content_width = asset.width;
    asset.content_height = asset.height;
    return;
  }

  asset.content_width = max_x - min_x + 1;
  asset.content_height = max_y - min_y + 1;
  asset.uv0 = ImVec2(static_cast<float>(min_x) / static_cast<float>(asset.width),
                     static_cast<float>(min_y) / static_cast<float>(asset.height));
  asset.uv1 = ImVec2(static_cast<float>(max_x + 1) / static_cast<float>(asset.width),
                     static_cast<float>(max_y + 1) / static_cast<float>(asset.height));
}

static bool load_texture_png_from_memory(TextureAsset &asset,
                                         const std::uint8_t *data,
                                         std::size_t data_size) {
  if (static_cast<bool>(asset.texture)) return true;
  if (asset.attempted) return false;
  asset.attempted = true;

  if (data == nullptr || data_size == 0U ||
      data_size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return false;
  }

  int width = 0, height = 0, channels = 0;
  const auto *bytes = reinterpret_cast<const unsigned char *>(data);
  unsigned char *pixels = stbi_load_from_memory(bytes, static_cast<int>(data_size),
                                                &width, &height, &channels, 4);
  if (pixels == nullptr || width <= 0 || height <= 0) {
    stbi_image_free(pixels);
    return false;
  }

  asset.width = width;
  asset.height = height;
  compute_content_uv(asset, pixels);

#if !defined(MEMDBG_PLATFORM_IOS)
  GLuint texture = 0;
  glGenTextures(1, &texture);
  glBindTexture(GL_TEXTURE_2D, texture);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA,
               GL_UNSIGNED_BYTE, pixels);
  glBindTexture(GL_TEXTURE_2D, 0);
  asset.texture = texture;
#endif

  stbi_image_free(pixels);
  return true;
}

static void shutdown_texture(TextureAsset &asset) {
#if !defined(MEMDBG_PLATFORM_IOS)
  if (static_cast<bool>(asset.texture)) {
    GLuint texture = static_cast<GLuint>(asset.texture);
    glDeleteTextures(1, &texture);
  }
#endif
  asset = TextureAsset{};
}

#if !defined(MEMDBG_PLATFORM_IOS)
static void set_window_icon(GLFWwindow *window) {
#if defined(__APPLE__)
  (void)window;
#else
  if (window == nullptr) return;

  try {
    const std::filesystem::path path = find_asset_path("assets/app-icon.png");
    if (path.empty()) return;
    int width = 0, height = 0, channels = 0;
    unsigned char *pixels = stbi_load(path.string().c_str(), &width, &height, &channels, 4);
    if (pixels == nullptr || width <= 0 || height <= 0) {
      stbi_image_free(pixels);
      return;
    }

    GLFWimage image{};
    image.width = width;
    image.height = height;
    image.pixels = pixels;
    glfwSetWindowIcon(window, 1, &image);
    stbi_image_free(pixels);
  } catch (...) { /* icon load is non-fatal */ }
#endif
}
#endif

} // namespace

/* ---- State helpers ---- */

void normalize_ports(AppState &state) {
  state.debug_port = std::clamp(state.debug_port, 1, 65535);
  state.udp_port    = std::clamp(state.udp_port, 1, 65535);
}

static void normalize_console_target(ConsoleTarget &target) {
  target.name = trim_copy(target.name);
  if (target.name.empty()) target.name = "Default";
  target.host = trim_copy(target.host);
  if (target.host.empty()) target.host = "192.168.1.100";
  target.debug_port = target.debug_port <= 0 ? 9020 : std::clamp(target.debug_port, 1, 65535);
  target.udp_port = target.udp_port <= 0 ? 9023 : std::clamp(target.udp_port, 1, 65535);
}

static ConsoleTarget current_console_target_from_fields(const AppState &state) {
  ConsoleTarget target;
  target.name = state.target_name;
  target.host = state.host;
  target.debug_port = state.debug_port;
  target.udp_port = state.udp_port;
  normalize_console_target(target);
  return target;
}

static void apply_console_target(AppState &state, const ConsoleTarget &target) {
  ConsoleTarget normalized = target;
  normalize_console_target(normalized);
  std::snprintf(state.target_name, sizeof(state.target_name), "%s", normalized.name.c_str());
  std::snprintf(state.host, sizeof(state.host), "%s", normalized.host.c_str());
  state.debug_port = normalized.debug_port;
  state.udp_port = normalized.udp_port;
}

static bool console_target_name_exists(const AppState &state, const std::string &name, int ignore_index) {
  for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
    if (i == ignore_index) continue;
    if (state.console_targets[i].name == name) return true;
  }
  return false;
}

static std::string unique_console_target_name(const AppState &state, std::string base, int ignore_index = -1) {
  base = trim_copy(base);
  if (base.empty()) base = "Target";
  if (!console_target_name_exists(state, base, ignore_index)) return base;

  for (int i = 2; i < 1000; ++i) {
    const std::string candidate = base + " " + std::to_string(i);
    if (!console_target_name_exists(state, candidate, ignore_index)) return candidate;
  }
  return base + " copy";
}

void ensure_console_targets(AppState &state) {
  normalize_ports(state);
  if (state.console_targets.empty()) {
    state.console_targets.push_back(current_console_target_from_fields(state));
  }
  for (auto &target : state.console_targets) normalize_console_target(target);
  if (state.selected_target_index < 0 ||
      state.selected_target_index >= static_cast<int>(state.console_targets.size())) {
    state.selected_target_index = 0;
  }
}

void select_console_target(AppState &state, int index) {
  ensure_console_targets(state);
  if (state.console_targets.empty()) return;
  index = std::clamp(index, 0, static_cast<int>(state.console_targets.size()) - 1);
  state.selected_target_index = index;
  apply_console_target(state, state.console_targets[static_cast<size_t>(index)]);
}

void save_current_console_target(AppState &state) {
  ensure_console_targets(state);
  if (state.console_targets.empty()) return;
  ConsoleTarget target = current_console_target_from_fields(state);
  target.name = unique_console_target_name(state, target.name, state.selected_target_index);
  state.console_targets[static_cast<size_t>(state.selected_target_index)] = target;
  apply_console_target(state, target);
}

void add_console_target(AppState &state) {
  ensure_console_targets(state);
  ConsoleTarget target = current_console_target_from_fields(state);
  target.name = unique_console_target_name(state, target.name);
  state.console_targets.push_back(target);
  state.selected_target_index = static_cast<int>(state.console_targets.size()) - 1;
  apply_console_target(state, target);
}

void remove_selected_console_target(AppState &state) {
  ensure_console_targets(state);
  if (state.console_targets.size() <= 1U) {
    state.console_targets.clear();
    state.selected_target_index = 0;
    ConsoleTarget target;
    state.console_targets.push_back(target);
    apply_console_target(state, target);
    return;
  }

  const int index = std::clamp(state.selected_target_index, 0,
                              static_cast<int>(state.console_targets.size()) - 1);
  state.console_targets.erase(state.console_targets.begin() + index);
  state.selected_target_index = std::min(index, static_cast<int>(state.console_targets.size()) - 1);
  apply_console_target(state, state.console_targets[static_cast<size_t>(state.selected_target_index)]);
}

bool ensure_udp_listener(AppState &state, std::string &error) {
  normalize_ports(state);
  if (state.udp_listener.running()) return true;
  if (state.udp_listener.start(static_cast<uint16_t>(state.udp_port))) return true;
  error = state.udp_listener.last_error();
  if (error.empty()) error = "UDP listener failed";
  return false;
}

/* ---- Persistent frontend settings ---- */

static std::filesystem::path frontend_settings_path() {
  return platform::app_config_dir() / "frontend.conf";
}

bool load_frontend_settings(AppState &state, std::string *error) {
  const std::filesystem::path path = frontend_settings_path();
  std::ifstream in(path);
  if (!in) return false;

  state.console_targets.clear();
  int saved_selected_target = 0;
  std::string line;
  while (std::getline(in, line)) {
    const size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    const std::string key = trim_copy(line.substr(0, eq));
    const std::string value = trim_copy(line.substr(eq + 1));
    if (key == "host" && !value.empty()) {
      std::snprintf(state.host, sizeof(state.host), "%s", value.c_str());
    } else if (key == "debug_port") {
      state.debug_port = std::atoi(value.c_str());
    } else if (key == "udp_port") {
      state.udp_port = std::atoi(value.c_str());
    } else if (key == "dump_path" && !value.empty()) {
      std::snprintf(state.dump_path, sizeof(state.dump_path), "%s", value.c_str());
    } else if (key == "language") {
      state.language = static_cast<int>(locale::lang_from_code(value.c_str()));
    } else if (key == "taskmgr_prefetch_on_connect") {
      state.taskmgr_prefetch_on_connect =
          value == "1" || value == "true" || value == "on" || value == "yes";
    } else if (key == "selected_target") {
      saved_selected_target = std::atoi(value.c_str());
    } else if (key.rfind("target.", 0) == 0) {
      const std::string rest = key.substr(7);
      const size_t dot = rest.find('.');
      if (dot == std::string::npos) continue;

      const std::string index_text = rest.substr(0, dot);
      char *end = nullptr;
      const long index = std::strtol(index_text.c_str(), &end, 10);
      if (end == index_text.c_str() || *end != '\0' || index < 0 || index >= 64) continue;

      const size_t target_index = static_cast<size_t>(index);
      if (state.console_targets.size() <= target_index)
        state.console_targets.resize(target_index + 1U);

      const std::string field = rest.substr(dot + 1);
      ConsoleTarget &target = state.console_targets[target_index];
      if (field == "name") {
        target.name = value;
      } else if (field == "host") {
        target.host = value;
      } else if (field == "debug_port") {
        target.debug_port = std::atoi(value.c_str());
      } else if (field == "udp_port") {
        target.udp_port = std::atoi(value.c_str());
      }
    }
  }

  normalize_ports(state);
  ensure_console_targets(state);
  state.selected_target_index = std::clamp(saved_selected_target, 0,
      static_cast<int>(state.console_targets.size()) - 1);
  select_console_target(state, state.selected_target_index);
  if (!in.eof() && error != nullptr) {
    *error = "Failed while reading " + path.string();
    return false;
  }
  return true;
}

bool save_frontend_settings(const AppState &state, std::string *error) {
  const std::filesystem::path path = frontend_settings_path();
  std::error_code ec;
  if (!path.parent_path().empty())
    std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (error != nullptr) *error = "Cannot create settings directory: " + ec.message();
    return false;
  }

  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    if (error != nullptr) *error = "Cannot write " + path.string();
    return false;
  }
  std::vector<ConsoleTarget> targets = state.console_targets;
  if (targets.empty()) targets.push_back(current_console_target_from_fields(state));
  for (auto &target : targets) normalize_console_target(target);

  int selected_target = state.selected_target_index;
  if (selected_target < 0 || selected_target >= static_cast<int>(targets.size()))
    selected_target = 0;
  targets[static_cast<size_t>(selected_target)] = current_console_target_from_fields(state);

  out << "host=" << state.host << "\n";
  out << "debug_port=" << state.debug_port << "\n";
  out << "udp_port=" << state.udp_port << "\n";
  out << "dump_path=" << state.dump_path << "\n";
  out << "language=" << locale::lang_code(static_cast<locale::Lang>(state.language)) << "\n";
  out << "taskmgr_prefetch_on_connect=" << (state.taskmgr_prefetch_on_connect ? 1 : 0) << "\n";
  out << "selected_target=" << selected_target << "\n";
  out << "target_count=" << targets.size() << "\n";
  for (size_t i = 0; i < targets.size(); ++i) {
    const ConsoleTarget &target = targets[i];
    out << "target." << i << ".name=" << target.name << "\n";
    out << "target." << i << ".host=" << target.host << "\n";
    out << "target." << i << ".debug_port=" << target.debug_port << "\n";
    out << "target." << i << ".udp_port=" << target.udp_port << "\n";
  }
  if (!out) {
    if (error != nullptr) *error = "Failed while writing " + path.string();
    return false;
  }
  return true;
}

/* ---- Async connect state (lives for duration of async op) ---- */
static std::future<bool> s_connect_future;
static Client              s_temp_client;
static HelloInfo           s_temp_hello;
static std::string         s_temp_error;

void connect_console(AppState &state) {
  if (state.connect_pending) return;  /* already connecting */
  if (s_connect_future.valid()) s_connect_future.wait();  /* drain previous async */
  ensure_console_targets(state);
  save_current_console_target(state);
  normalize_ports(state);
  state.client.disconnect();
  state.has_hello = false;
  state.processes.clear(); state.maps.clear(); state.memory.clear();
  state.scan_result = ScanResult{};
  state.scan_snapshot.clear(); state.scan_snapshot_value_len = 0;
  state.scan_is_unknown_session = false;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "No scan session");
  state.selected_pid = 0; state.selected_process_row = -1; state.selected_map_row = -1;
  state.has_process_info = false;
  s_temp_client.disconnect();
  state.connect_pending = true;

  if (state.crash_logging_enabled)
    state.crash_logger.log("connect", ("Connecting to " + std::string(state.host) + ":" + std::to_string(state.debug_port)).c_str());

  set_status(state, "Connecting to " + std::string(state.host) + "...");

  std::string host = state.host;
  uint16_t port = static_cast<uint16_t>(state.debug_port);
  s_connect_future = std::async(std::launch::async, [host, port]() -> bool {
    if (!s_temp_client.connect_to(host, port)) {
      s_temp_error = s_temp_client.last_error();
      return false;
    }
    if (!s_temp_client.hello(s_temp_hello)) {
      s_temp_error = s_temp_client.last_error();
      s_temp_client.disconnect();
      return false;
    }
    s_temp_error.clear();
    return true;
  });
}

/* ---- Async telemetry ---- */

void request_telemetry_async(AppState &state) {
  if (state.telemetry_pending) return;
  if (state.map_refresh_pending) return;
  if (!state.client.connected()) return;
  if (!(state.hello.capabilities & MEMDBG_CAP_PERF_TELEMETRY)) return;

  state.telemetry_pending = true;
  state.telemetry_future = std::async(std::launch::async, [&state]() -> bool {
    Client::TelemetrySnapshot snap;
    if (!state.client.telemetry(snap)) {
      state.telemetry_temp_error = state.client.last_error();
      return false;
    }
    state.telemetry_temp_snap = snap;
    state.telemetry_temp_error.clear();
    return true;
  });
}

static void poll_telemetry(AppState &state) {
  if (!state.telemetry_pending) return;
  if (!state.telemetry_future.valid()) return;

  auto status = state.telemetry_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.telemetry_pending = false;
  bool ok = false;
  try {
    ok = state.telemetry_future.get();
  } catch (const std::exception &ex) {
    state.telemetry_temp_error = ex.what();
  } catch (...) {
    state.telemetry_temp_error = "Unknown telemetry error";
  }

  if (!ok) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Telemetry failed: " + state.telemetry_temp_error).c_str());
    set_status(state, "Telemetry: " + state.telemetry_temp_error);
    state.telemetry_available = false;
    return;
  }

  state.telemetry_snap = state.telemetry_temp_snap;
  state.telemetry_available = true;
}

void request_maps_refresh_async(AppState &state) {
  if (state.map_refresh_pending) {
    set_status(state, "Memory maps refresh already in progress");
    return;
  }
  if (state.connect_pending || state.telemetry_pending || state.scan_async_pending) {
    set_status(state, "Wait for the active operation to finish");
    return;
  }
  if (!state.client.connected()) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", "Maps refresh failed: not connected");
    set_status(state, locale::tr("connect.no_console_before_maps"));
    push_notification(state, locale::tr("connect.no_console_before_maps"), 4.0);
    return;
  }
  if (state.selected_pid <= 0) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", "Maps refresh failed: no process selected");
    set_status(state, locale::tr("processes.select_pid_first"));
    return;
  }

  if (state.map_refresh_future.valid()) {
    state.map_refresh_future.wait();
  }

  state.map_refresh_pid = state.selected_pid;
  state.map_refresh_start_time = ImGui::GetTime();
  state.map_refresh_pending = true;
  state.map_refresh_temp_maps.clear();
  state.map_refresh_error.clear();
  set_status(state, "Refreshing memory maps...");

  int32_t pid = state.map_refresh_pid;
  state.map_refresh_future = std::async(std::launch::async,
      [pid, &client = state.client,
       &temp_maps = state.map_refresh_temp_maps,
       &error = state.map_refresh_error]() -> bool {
        std::vector<MapEntry> maps;
        if (!client.process_maps(pid, maps)) {
          error = client.last_error();
          if (error.empty()) error = "Memory maps refresh failed";
          return false;
        }
        temp_maps = std::move(maps);
        error.clear();
        return true;
      });
}

static void poll_map_refresh(AppState &state) {
  if (!state.map_refresh_pending) return;
  if (!state.map_refresh_future.valid()) return;

  auto status = state.map_refresh_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.map_refresh_pending = false;
  bool ok = false;
  try {
    ok = state.map_refresh_future.get();
  } catch (const std::exception &ex) {
    state.map_refresh_error = ex.what();
  } catch (...) {
    state.map_refresh_error = "Unknown maps refresh error";
  }

  if (state.map_refresh_pid != state.selected_pid) {
    state.map_refresh_temp_maps.clear();
    set_status(state, "Memory maps refresh discarded: selected process changed");
    return;
  }

  if (!ok) {
    std::string error = state.map_refresh_error.empty()
        ? "Memory maps refresh failed"
        : state.map_refresh_error;
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Maps refresh failed: " + error).c_str());
    set_status(state, error);
    push_notification(state, "Maps refresh failed: " + error, 5.0);
    return;
  }

  state.maps = std::move(state.map_refresh_temp_maps);
  state.selected_map_row = -1;
  std::string message =
      std::string(locale::tr("processes.maps_refreshed")) +
      " (" + std::to_string(state.maps.size()) + " maps)";
  set_status(state, message);
  if (state.crash_logging_enabled)
    state.crash_logger.log("refresh",
        ("Memory maps: " + std::to_string(state.maps.size()) + " maps").c_str());
}

/* ---- Tracer ---- */

void request_tracer_attach_async(AppState &state) {
  if (state.tracer_pending || state.tracer_detach_pending) return;
  if (!state.client.connected()) return;
  if (!(state.hello.capabilities & MEMDBG_CAP_TRACER)) return;
  if (client_async_busy(state)) return;

  int32_t pid = state.tracer_target_pid;
  if (pid <= 0) return;

  state.tracer_pending = true;
  state.tracer_detach_requested = false;
  state.tracer_status = {};
  state.tracer_events.clear();
  state.tracer_was_crashed = false;
  state.tracer_crash_dump_path.clear();
  state.tracer_error.clear();
  state.tracer_temp_error.clear();
  state.tracer_status_text[0] = '\0';

  state.tracer_future = std::async(std::launch::async, [&state, pid]() -> bool {
    const bool ok = state.client.tracer_attach(pid);
    if (!ok) state.tracer_temp_error = state.client.last_error();
    return ok;
  });
}

void request_tracer_detach_async(AppState &state) {
  if (state.tracer_detach_pending) return;
  if (state.tracer_pending) {
    /* The attach request owns the Client socket.  Send detach immediately
     * after it has completed rather than replacing its future (which would
     * synchronously wait and freeze the UI). */
    state.tracer_detach_requested = true;
    set_status(state, "Cancelling tracer attach...");
    return;
  }
  if (!state.client.connected()) {
    state.tracer_status = {};
    state.tracer_status_text[0] = '\0';
    state.tracer_target_pid = 0;
    return;
  }

  state.tracer_pending = true;
  state.tracer_detach_pending = true;
  state.tracer_detach_requested = false;
  state.tracer_error.clear();
  state.tracer_temp_error.clear();
  set_status(state, "Detaching tracer and resuming target...");
  state.tracer_future = std::async(std::launch::async, [&state]() -> bool {
    const bool ok = state.client.tracer_detach();
    if (!ok) state.tracer_temp_error = state.client.last_error();
    return ok;
  });
}

static void poll_tracer(AppState &state) {
  /* Complete an attach or detach without blocking the render thread. */
  if (state.tracer_pending && state.tracer_future.valid()) {
    const auto future_status =
        state.tracer_future.wait_for(std::chrono::milliseconds(0));
    if (future_status == std::future_status::ready) {
      const bool was_detach = state.tracer_detach_pending;
      bool ok = false;
      state.tracer_pending = false;
      state.tracer_detach_pending = false;
      try {
        ok = state.tracer_future.get();
      } catch (const std::exception &ex) {
        state.tracer_temp_error = ex.what();
      } catch (...) {
        state.tracer_temp_error = "Unknown tracer operation error";
      }

      if (!ok) {
        state.tracer_error = state.tracer_temp_error.empty()
            ? "Tracer operation failed"
            : state.tracer_temp_error;
        set_status(state, "Tracer: " + state.tracer_error);
        push_notification(state, "Tracer: " + state.tracer_error, 6.0);
      } else if (was_detach) {
        state.tracer_status = {};
        state.tracer_status.state = MEMDBG_TRACER_STATE_STOPPED;
        std::snprintf(state.tracer_status_text,
                      sizeof(state.tracer_status_text), "%s", "Stopped");
        state.tracer_target_pid = 0;
        state.tracer_next_poll = 0.0;
        state.tracer_next_event_poll = 0.0;
        set_status(state, "Tracer detached; target resumed");
      } else {
        std::snprintf(state.tracer_status_text,
                      sizeof(state.tracer_status_text), "%s", "Starting...");
        state.tracer_next_poll = 0.0;
        state.tracer_next_event_poll = 0.0;
      }

      if (!was_detach && state.tracer_detach_requested) {
        state.tracer_detach_requested = false;
        request_tracer_detach_async(state);
      }
    }
  }

  /* The attach/detach request owns the shared protocol client. */
  if (state.tracer_pending) return;
  if (!state.client.connected()) return;
  if (!(state.hello.capabilities & MEMDBG_CAP_TRACER)) return;

  if (state.tracer_status_pending && state.tracer_status_future.valid() &&
      state.tracer_status_future.wait_for(std::chrono::milliseconds(0)) ==
          std::future_status::ready) {
    bool ok = false;
    try {
      ok = state.tracer_status_future.get();
    } catch (const std::exception &ex) {
      state.tracer_status_error = ex.what();
    } catch (...) {
      state.tracer_status_error = "Unknown tracer status error";
    }
    state.tracer_status_pending = false;
    if (ok) {
      Client::TracerStatus new_st = state.tracer_temp_status;
      /* Check for state transition to crashed. */
      if (state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING &&
          new_st.state == MEMDBG_TRACER_STATE_CRASHED) {
        state.tracer_was_crashed = true;
        state.tracer_crash_dump_path = new_st.dump_path;
        state.tracer_crash_notification_time = ImGui::GetTime();
        push_notification(state,
            "Process crashed! Signal " + std::to_string(new_st.crash_signal) +
            ". Dump: " + new_st.dump_path, 10.0);
      }
      state.tracer_status = std::move(new_st);
      std::snprintf(state.tracer_status_text,
                    sizeof(state.tracer_status_text), "%s",
                    state.tracer_status.state == MEMDBG_TRACER_STATE_IDLE     ? "Idle" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING  ? "Running" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_CRASHED  ? "Crashed" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_EXITED   ? "Exited" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_STOPPED  ? "Stopped" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_STARTING ? "Starting..." : "?");
    } else if (!state.tracer_status_error.empty()) {
      state.tracer_error = state.tracer_status_error;
    }
  }

  if (state.tracer_events_pending && state.tracer_events_future.valid() &&
      state.tracer_events_future.wait_for(std::chrono::milliseconds(0)) ==
          std::future_status::ready) {
    bool ok = false;
    try {
      ok = state.tracer_events_future.get();
    } catch (const std::exception &ex) {
      state.tracer_events_error = ex.what();
    } catch (...) {
      state.tracer_events_error = "Unknown tracer event poll error";
    }
    state.tracer_events_pending = false;
    if (ok) {
      state.tracer_events.insert(state.tracer_events.end(),
                                  state.tracer_temp_events.begin(),
                                  state.tracer_temp_events.end());
      /* Keep max ~5000 events in memory. */
      if (state.tracer_events.size() > 5000)
        state.tracer_events.erase(state.tracer_events.begin(),
                                  state.tracer_events.begin() + (state.tracer_events.size() - 5000));
    } else if (!state.tracer_events_error.empty()) {
      state.tracer_error = state.tracer_events_error;
    }
  }

  /* Skip polling when no tracer session was ever started. */
  if (state.tracer_target_pid <= 0) return;

  const double now = ImGui::GetTime();
  if (!state.tracer_status_pending && !state.tracer_events_pending &&
      now >= state.tracer_next_poll) {
    state.tracer_next_poll = now + 0.5;
    state.tracer_status_pending = true;
    state.tracer_status_error.clear();
    state.tracer_status_future = std::async(std::launch::async, [&state]() -> bool {
      Client::TracerStatus status;
      const bool ok = state.client.tracer_status(status);
      if (ok)
        state.tracer_temp_status = std::move(status);
      else
        state.tracer_status_error = state.client.last_error();
      return ok;
    });
    return;
  }

  if (state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING &&
      !state.tracer_status_pending && !state.tracer_events_pending &&
      now >= state.tracer_next_event_poll) {
    state.tracer_next_event_poll = now + 0.1;
    state.tracer_events_pending = true;
    state.tracer_events_error.clear();
    state.tracer_events_future = std::async(std::launch::async, [&state]() -> bool {
      std::vector<Client::TracerEvent> events;
      const bool ok = state.client.tracer_poll(events);
      if (ok)
        state.tracer_temp_events = std::move(events);
      else
        state.tracer_events_error = state.client.last_error();
      return ok;
    });
  }
}

static ProcessMapSummary summarize_taskmgr_prefetch_maps(const std::vector<MapEntry> &maps) {
  ProcessMapSummary summary;
  summary.loaded = true;
  for (const auto &map : maps) {
    if (map.end <= map.start) continue;
    const uint64_t size = map.end - map.start;
    summary.map_count++;
    summary.total_mapped += size;
    if (map.protection & 1U) summary.readable_bytes += size;
    if (map.protection & 2U) summary.writable_bytes += size;
    if (map.protection & 4U) summary.executable_bytes += size;
    if ((map.protection & 3U) == 3U && !(map.protection & 4U))
      summary.rw_heap_bytes += size;
  }
  return summary;
}

static void merge_taskmgr_resource(AppState &state, TaskProcessResource &&incoming) {
  if (incoming.pid <= 0) return;
  TaskProcessResource &resource = state.taskmgr_resources[incoming.pid];
  resource.pid = incoming.pid;
  if (incoming.has_info) {
    resource.info = std::move(incoming.info);
    resource.has_info = true;
    resource.info_failed = false;
  } else if (incoming.info_failed) {
    resource.info_failed = true;
  }
  if (incoming.maps.loaded || incoming.maps_failed) {
    resource.maps = incoming.maps;
    resource.maps_failed = incoming.maps_failed;
  }
  if (!incoming.error.empty()) resource.error = std::move(incoming.error);
  resource.updated_at = ImGui::GetTime();
}

static void start_taskmgr_prefetch(AppState &state) {
  if (!state.taskmgr_prefetch_on_connect || state.taskmgr_prefetch_pending) return;
  if (!state.client.connected() || !state.has_hello) return;
  if (!(state.hello.capabilities & MEMDBG_CAP_PROCESS_LIST)) return;
  if (state.taskmgr_prefetch_future.valid()) state.taskmgr_prefetch_future.wait();

  state.taskmgr_prefetch_pending = true;
  state.taskmgr_prefetch_processes.clear();
  state.taskmgr_prefetch_resources.clear();
  state.taskmgr_prefetch_error.clear();

  const uint32_t capabilities = state.hello.capabilities;
  state.taskmgr_prefetch_future = std::async(std::launch::async,
      [&client = state.client,
       &processes_out = state.taskmgr_prefetch_processes,
       &resources_out = state.taskmgr_prefetch_resources,
       &error = state.taskmgr_prefetch_error,
       capabilities]() -> bool {
        std::vector<ProcessEntry> processes;
        if (!client.process_list(processes)) {
          error = client.last_error();
          return false;
        }

        std::unordered_map<int32_t, TaskProcessResource> resources;
        resources.reserve(processes.size());
        for (const auto &process : processes) {
          if (process.pid <= 0) continue;
          TaskProcessResource &resource = resources[process.pid];
          resource.pid = process.pid;
        }

        if (capabilities & MEMDBG_CAP_PROCESS_INFO) {
          constexpr size_t kBatchInfoMax = 128U;
          for (size_t base = 0; base < processes.size(); base += kBatchInfoMax) {
            const size_t end = std::min(base + kBatchInfoMax, processes.size());
            std::vector<int32_t> pids;
            pids.reserve(end - base);
            for (size_t i = base; i < end; ++i) {
              if (processes[i].pid > 0) pids.push_back(processes[i].pid);
            }
            if (pids.empty()) continue;

            std::vector<ProcessInfo> infos;
            if (client.batch_process_info(pids, infos)) {
              for (auto &info : infos) {
                if (info.pid <= 0) continue;
                TaskProcessResource &resource = resources[info.pid];
                resource.pid = info.pid;
                resource.info = std::move(info);
                resource.has_info = true;
              }
              continue;
            }

            const std::string batch_error = client.last_error();
            if (error.empty()) error = batch_error;
            for (int32_t pid : pids) {
              ProcessInfo info;
              TaskProcessResource &resource = resources[pid];
              resource.pid = pid;
              if (client.process_info(pid, info)) {
                resource.info = std::move(info);
                resource.has_info = true;
                resource.info_failed = false;
              } else {
                resource.info_failed = true;
                if (resource.error.empty()) resource.error = client.last_error();
              }
            }
          }
        }

        if (capabilities & MEMDBG_CAP_PROCESS_MAPS) {
          for (const auto &process : processes) {
            if (process.pid <= 0) continue;
            std::vector<MapEntry> maps;
            TaskProcessResource &resource = resources[process.pid];
            resource.pid = process.pid;
            if (client.process_maps(process.pid, maps)) {
              resource.maps = summarize_taskmgr_prefetch_maps(maps);
              resource.maps_failed = false;
            } else {
              resource.maps.loaded = true;
              resource.maps_failed = true;
              resource.error = client.last_error();
              if (error.empty()) error = resource.error;
            }
          }
        }

        processes_out = std::move(processes);
        resources_out = std::move(resources);
        return true;
      });
}

static void poll_taskmgr_prefetch(AppState &state) {
  if (!state.taskmgr_prefetch_pending || !state.taskmgr_prefetch_future.valid()) return;

  auto status = state.taskmgr_prefetch_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.taskmgr_prefetch_pending = false;
  bool ok = false;
  try {
    ok = state.taskmgr_prefetch_future.get();
  } catch (const std::exception &ex) {
    state.taskmgr_prefetch_error = ex.what();
  } catch (...) {
    state.taskmgr_prefetch_error = "Unknown task manager prefetch error";
  }

  if (ok) {
    if (!state.taskmgr_prefetch_processes.empty()) {
      state.processes = std::move(state.taskmgr_prefetch_processes);
    }
    for (auto &entry : state.taskmgr_prefetch_resources) {
      merge_taskmgr_resource(state, std::move(entry.second));
    }
    state.taskmgr_next_resource_fetch = ImGui::GetTime() + 1.0;
  }

  state.taskmgr_prefetch_processes.clear();
  state.taskmgr_prefetch_resources.clear();
}

/* Poll async connect result. Called at start of every frame. */
static void poll_connect(AppState &state) {
  if (!state.connect_pending) return;
  if (!s_connect_future.valid()) return;

  auto status = s_connect_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.connect_pending = false;
  bool ok = false;
  try {
    ok = s_connect_future.get();
  } catch (const std::exception &ex) {
    s_temp_error = ex.what();
  } catch (...) {
    s_temp_error = "Unknown connection error";
  }

  if (!ok) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Connection failed: " + s_temp_error).c_str());
    set_status(state, s_temp_error);
    push_notification(state, "Connection failed: " + s_temp_error, 5.0);
    return;
  }

  /* Success: transfer connected fd from temp client to main client */
  state.client.take_fd(s_temp_client.release_fd());
  state.hello = s_temp_hello;
  state.has_hello = true;
  state.taskmgr_resources.clear();
  state.taskmgr_fmem_by_name.clear();
  state.taskmgr_last_log_received = 0U;
  state.taskmgr_prefetch_processes.clear();
  state.taskmgr_prefetch_resources.clear();
  state.taskmgr_prefetch_error.clear();
  std::string udp_error;
  std::string message = "Connected to console " + std::string(state.host) + ":" + std::to_string(state.debug_port);
  if (!ensure_udp_listener(state, udp_error)) message += " (UDP: " + udp_error + ")";

  if (state.crash_logging_enabled)
    state.crash_logger.log("connect", ("Connected to " + std::string(state.host) + ":" + std::to_string(state.debug_port)).c_str());

  set_status(state, message);
  push_notification(state, "Connected to " + std::string(state.host) + ":" + std::to_string(state.debug_port));
  start_taskmgr_prefetch(state);
}

/* Modal spinner drawn during async connect */
static void draw_connect_spinner(AppState &state) {
  if (!state.connect_pending) return;

  const float scl = ui::dpi_scale();
  const ImVec2 center = ImGui::GetMainViewport()->GetCenter();
  ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
  ImGui::SetNextWindowSize(ImVec2(320.0f * scl, 120.0f * scl));

  ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(18, 24, 32, 245));
  ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(60, 120, 130, 100));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 14.0f * scl);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24, 20));

  ImGui::Begin("##ConnectSpinner", nullptr,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
               ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
               ImGuiWindowFlags_NoNav | ImGuiWindowFlags_AlwaysAutoResize);

  ImGui::TextColored(ui::colors().primary2, "%s  %s", icons::kConnect, locale::tr("connect.spinner"));
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s:%d", state.host, state.debug_port);

  /* Animated spinner using time-based rotation */
  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec2 sp = ImVec2(center.x + 100.0f * scl, center.y + 4.0f * scl);
  float radius = 14.0f * scl;
  float t = (float)ImGui::GetTime();
  const int segments = 8;
  for (int i = 0; i < segments; ++i) {
    float a = t * 4.0f + (float)i * 6.2831853f / (float)segments;
    float alpha = 0.15f + 0.85f * ((float)i / (float)segments);
    ImVec2 p(sp.x + radius * cosf(a), sp.y + radius * sinf(a));
    dl->AddCircleFilled(p, 2.5f * scl, IM_COL32(118, 232, 224, (int)(200 * alpha)));
  }

  ImGui::End();
  ImGui::PopStyleVar(3);
  ImGui::PopStyleColor(2);

  /* Dim background overlay */
  ImVec2 vp_pos = ImGui::GetMainViewport()->Pos;
  ImVec2 vp_size = ImGui::GetMainViewport()->Size;
  ImGui::GetBackgroundDrawList()->AddRectFilled(
      vp_pos, ImVec2(vp_pos.x + vp_size.x, vp_pos.y + vp_size.y),
      IM_COL32(0, 0, 0, 80));
}

void disconnect_console(AppState &state, const char *reason) {
  state.connect_pending = false;  /* cancel any in-flight async connect */

  /* Drain async futures before clearing flags (std::future blocks on destructor). */
  if (state.scan_async_future.valid()) state.scan_async_future.wait();
  if (state.telemetry_future.valid()) state.telemetry_future.wait();
  if (state.map_refresh_future.valid()) state.map_refresh_future.wait();
  if (state.taskmgr_resource_future.valid()) state.taskmgr_resource_future.wait();
  if (state.taskmgr_prefetch_future.valid()) state.taskmgr_prefetch_future.wait();
  if (state.heartbeat_future.valid()) state.heartbeat_future.wait();
  if (state.tracer_future.valid()) state.tracer_future.wait();
  if (state.tracer_status_future.valid()) state.tracer_status_future.wait();
  if (state.tracer_events_future.valid()) state.tracer_events_future.wait();
  if (s_connect_future.valid()) s_connect_future.wait();

  state.scan_async_pending = false;  /* cancel any in-flight async scan */
  state.telemetry_pending = false;  /* cancel any in-flight telemetry poll */
  state.map_refresh_pending = false;  /* cancel any in-flight map refresh */
  state.taskmgr_resource_pending = false;  /* cancel any in-flight task manager fetch */
  state.taskmgr_prefetch_pending = false;
  state.heartbeat_pending = false;
  state.heartbeat_error.clear();
  state.next_heartbeat = 0.0;
  const bool tracer_may_own_target = state.tracer_pending ||
      state.tracer_target_pid > 0 ||
      state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING;
  if (state.client.connected() && state.has_hello && tracer_may_own_target &&
      (state.hello.capabilities & MEMDBG_CAP_TRACER)) {
    /* Do not leave a traced process stopped when the frontend disconnects. */
    (void)state.client.tracer_detach();
  }
  state.tracer_pending = false;
  state.tracer_detach_pending = false;
  state.tracer_detach_requested = false;
  state.tracer_status_pending = false;
  state.tracer_events_pending = false;
  state.tracer_target_pid = 0;
  state.tracer_status = {};
  state.tracer_status_text[0] = '\0';
  state.tracer_error.clear();
  state.tracer_temp_events.clear();
  state.client.disconnect();
  state.has_hello = false;
  state.processes.clear(); state.maps.clear(); state.memory.clear();
  state.scan_result = ScanResult{};
  state.scan_snapshot.clear(); state.scan_snapshot_value_len = 0;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "No scan session");
  state.selected_pid = 0; state.selected_process_row = -1; state.selected_map_row = -1;
  state.has_process_info = false;
  state.telemetry_available = false;
  state.next_telemetry_poll = 0.0;
  state.taskmgr_resources.clear();
  state.taskmgr_fmem_by_name.clear();
  state.taskmgr_prefetch_processes.clear();
  state.taskmgr_prefetch_resources.clear();
  state.taskmgr_prefetch_error.clear();
  state.taskmgr_last_log_received = 0U;
  state.taskmgr_selected_row = -1;
  state.taskmgr_selected_pid = 0;
  state.taskmgr_detail_open = false;
  state.taskmgr_map_summary = ProcessMapSummary{};
  state.taskmgr_has_process_info = false;
  reset_debugger_state(state);

  /* Stop any running GUI plugin bridge */
  if (state.plugin_gui_bridge && state.plugin_gui_bridge->running()) {
    state.plugin_gui_bridge->stop();
    state.plugin_gui_starting = false;
    state.plugin_gui_error.clear();
  }

  if (state.crash_logging_enabled)
    state.crash_logger.log("connect", "Disconnected from console");

  const std::string message = reason != nullptr && reason[0] != '\0'
                                  ? std::string(reason)
                                  : "Console disconnected";
  set_status(state, message);
  push_notification(state, message);
}

/* ---- Sidebar navigation ---- */

static ImVec4 alpha(ImVec4 color, float value) {
  color.w *= value;
  return color;
}

static void text_ellipsis(const char *text, float max_width, ImVec4 color) {
  if (text == nullptr || text[0] == '\0') return;
  if (ImGui::CalcTextSize(text).x <= max_width || max_width <= 24.0f) {
    ImGui::TextColored(color, "%s", text);
    return;
  }

  const float ellipsis_w = ImGui::CalcTextSize("...").x;
  const size_t len = strlen(text);
  const float avg_w = ImGui::CalcTextSize(text).x / static_cast<float>(len);
  size_t keep = static_cast<size_t>((max_width - ellipsis_w) / avg_w);
  if (keep > len) keep = len;
  if (keep < 1U) keep = 1U;

  char buf[512];
  while (keep > 0U) {
    const size_t n = std::min(keep, sizeof(buf) - 4U);
    std::memcpy(buf, text, n);
    std::memcpy(buf + n, "...", 4U);
    if (ImGui::CalcTextSize(buf).x <= max_width) break;
    --keep;
  }
  ImGui::TextColored(color, "%s", buf);
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", text);
}

static void sidebar_section(const char *label) {
  ImGui::SetCursorPosX(10.0f * ui::dpi_scale());
  ImGui::TextColored(alpha(ui::colors().primary2, 0.70f), "%s", label);
}

static void stop_gui_plugin_if_idle(AppState &state) {
  if (state.screen != Screen::PluginGUI &&
      state.plugin_gui_bridge && state.plugin_gui_bridge->running()) {
    state.plugin_gui_bridge->stop();
    state.plugin_gui_starting = false;
    state.plugin_gui_error.clear();
  }
}

static void draw_gui_plugin_launcher(AppState &state) {
  /* Stop GUI plugin when navigating away */
  stop_gui_plugin_if_idle(state);

  /* Collect installed GUI plugins (tagged with "gui" in the manifest) */
  std::vector<plugins::PluginPackage> catalog = state.plugin_manager.catalog();
  std::vector<plugins::PluginPackage> gui_plugins;
  for (const auto &pkg : catalog) {
    if (!pkg.installed || !pkg.enabled) continue;
    bool has_gui = false;
    for (const auto &tag : pkg.tags) {
      std::string lower = tag;
      std::transform(lower.begin(), lower.end(), lower.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (lower == "gui") { has_gui = true; break; }
    }
    if (has_gui) gui_plugins.push_back(pkg);
  }

  if (gui_plugins.empty()) return;

  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const float width =
      std::max(96.0f * scl, ImGui::GetContentRegionAvail().x - 8.0f * scl);

  std::string active_name;
  for (const auto &pkg : gui_plugins) {
    if (state.plugin_gui_active_id == pkg.id &&
        state.screen == Screen::PluginGUI) {
      active_name = pkg.name;
      break;
    }
  }
  const bool bridge_running =
      state.plugin_gui_bridge && state.plugin_gui_bridge->running();

  ImGui::Dummy(ImVec2(0, 2.0f * scl));
  ImGui::SetCursorPosX(10.0f * scl);
  ImGui::TextColored(alpha(palette.primary2, 0.70f), "PLUGIN APPS");

  ImGui::SetCursorPosX(10.0f * scl);
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(11.0f * scl, 5.0f * scl));
  ImGui::PushStyleColor(ImGuiCol_Button, active_name.empty()
                                           ? palette.bg3
                                           : alpha(palette.primary, 0.58f));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, alpha(palette.primary2, 0.34f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, alpha(palette.primary, 0.82f));
  const std::string launcher_label =
      std::string(icons::kPlugins) + " Open plugin UI##GuiPluginLauncher";
  if (ImGui::Button(launcher_label.c_str(), ImVec2(width, 31.0f * scl))) {
    ImGui::OpenPopup("GuiPluginLauncherPopup");
  }
  if (ImGui::IsItemHovered()) {
    ImGui::SetTooltip("%s", "Open an installed GUI plugin without leaving the sidebar");
  }
  ImGui::PopStyleColor(3);
  ImGui::PopStyleVar();

  if (!active_name.empty()) {
    std::string status = bridge_running ? "Running: " : "Selected: ";
    status += active_name;
    ImGui::SetCursorPosX(14.0f * scl);
    text_ellipsis(status.c_str(), width - 8.0f * scl, palette.muted);
  } else {
    ImGui::SetCursorPosX(14.0f * scl);
    ImGui::TextColored(palette.dim, "%zu installed", gui_plugins.size());
  }

  if (ImGui::BeginPopup("GuiPluginLauncherPopup")) {
    ImGui::TextColored(palette.primary2, "%s Plugin apps", icons::kPlugins);
    ImGui::Separator();
    for (const auto &pkg : gui_plugins) {
      bool is_selected = (state.plugin_gui_active_id == pkg.id &&
                          state.screen == Screen::PluginGUI);
      std::string label = pkg.name + "##gui-plugin-" + pkg.id;
      if (ImGui::Selectable(label.c_str(), is_selected)) {
        /* Stop previous GUI plugin if running */
        if (state.plugin_gui_bridge && state.plugin_gui_bridge->running()) {
          state.plugin_gui_bridge->stop();
        }
        state.plugin_gui_active_id = pkg.id;
        state.plugin_gui_error.clear();
        state.screen = Screen::PluginGUI;
        set_status(state, "Opening GUI plugin: " + pkg.name);
      }
      if (is_selected) ImGui::SetItemDefaultFocus();
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("%s", pkg.short_description.c_str());
      }
      if (!pkg.version.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(palette.dim, "%s", pkg.version.c_str());
      }
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Manage plugins")) {
      state.screen = Screen::Plugins;
    }
    if (bridge_running && ImGui::MenuItem("Stop active plugin")) {
      state.plugin_gui_bridge->stop();
      state.plugin_gui_starting = false;
      state.plugin_gui_error.clear();
      set_status(state, "GUI plugin stopped");
    }
    ImGui::EndPopup();
  }

  ImGui::Dummy(ImVec2(0, 2));
}

static void nav_item(AppState &state, Screen screen, const char *icon, const char *label) {
  bool selected = state.screen == screen;
  ImGui::PushID(label);

  const float scl = ui::dpi_scale();
  const float row_h = 28.0f * scl;
  const float row_w = ImGui::GetContentRegionAvail().x;
  ImVec2 pos = ImGui::GetCursorScreenPos();
  ImGui::InvisibleButton("##nav", ImVec2(row_w, row_h));
  const bool hovered = ImGui::IsItemHovered();
  if (ImGui::IsItemClicked()) state.screen = screen;

  ImDrawList *dl = ImGui::GetWindowDrawList();
  const ImVec2 min(pos.x + 2.0f * scl, pos.y);
  const ImVec2 max(pos.x + row_w - 2.0f * scl, pos.y + row_h);

  if (selected || hovered) {
    const ImVec4 bg = selected
        ? ImVec4(32.0f/255.0f, 58.0f/255.0f, 45.0f/255.0f, 1.0f)
        : alpha(ui::colors().bg3, 0.70f);
    dl->AddRectFilled(min, max, ui::color_u32(bg), 1.0f * scl);
    dl->AddRect(min, max,
                ui::color_u32(selected ? alpha(ui::colors().border_hot, 0.92f)
                                       : alpha(ui::colors().border, 0.62f)),
                1.0f * scl);
  }

  if (selected) {
    dl->AddRectFilled(ImVec2(pos.x + 3.0f * scl, pos.y + 3.0f * scl),
                      ImVec2(pos.x + 6.0f * scl, pos.y + row_h - 3.0f * scl),
                      ui::color_u32(ui::colors().primary2), 1.0f * scl);
  }

  const ImVec4 icon_col = selected ? ui::colors().primary2 :
                          hovered ? ui::colors().primary2 : ui::colors().muted;
  const ImVec4 text_col = selected ? ui::colors().text :
                          hovered ? ui::colors().text : ui::colors().muted;
  const ImVec2 icon_size = ImGui::CalcTextSize(icon);
  const ImVec2 label_size = ImGui::CalcTextSize(label);
  const float icon_x = pos.x + 23.0f * scl - icon_size.x * 0.5f;
  const float icon_y = pos.y + (row_h - icon_size.y) * 0.5f;
  const float text_y = pos.y + (row_h - label_size.y) * 0.5f;
  dl->AddText(ImVec2(icon_x, icon_y), ui::color_u32(icon_col), icon);

  /* Ellipsis label if it exceeds available width */
  const float text_x = pos.x + 45.0f * scl;
  const float max_label_w = row_w - 45.0f * scl - 12.0f * scl;
  if (label_size.x <= max_label_w) {
    dl->AddText(ImVec2(text_x, text_y), ui::color_u32(text_col), label);
  } else {
    char buf[128];
    size_t len = std::strlen(label);
    size_t keep = len;
    if (keep < 1U) keep = 1U;
    while (keep > 0U) {
      size_t n = std::min(keep, sizeof(buf) - 4U);
      std::memcpy(buf, label, n);
      std::memcpy(buf + n, "...", 4U);
      if (ImGui::CalcTextSize(buf).x <= max_label_w) break;
      --keep;
    }
    dl->AddText(ImVec2(text_x, text_y), ui::color_u32(text_col), buf);
  }

  if (hovered) ImGui::SetTooltip("%s", label);
  ImGui::PopID();
}

static void draw_sidebar(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6,6));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4,2));
  ImGui::BeginChild("Sidebar", size, true, ImGuiWindowFlags_NoScrollbar);

  ImGui::TextColored(ui::colors().text, "%s", locale::tr("sidebar.brand"));
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().muted, "v%s", MEMDBG_VERSION_STRING);

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg3);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8,6));
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 2.0f);
  ImGui::BeginChild("SidebarStatus", ImVec2(0, 52.0f * scl), true, ImGuiWindowFlags_NoScrollbar);
  const bool connected = state.client.connected();
  const ImVec4 status_color = state.connect_pending ? ui::colors().warning :
                              connected ? ui::colors().success : ui::colors().dim;
  ui::status_dot(status_color);
  ImGui::SameLine();
  ImGui::BeginGroup();
  ImGui::TextColored(status_color, "%s", state.connect_pending ? locale::tr("status.connecting") :
                                          connected ? locale::tr("status.connected") : locale::tr("status.offline"));
  ImGui::TextColored(ui::colors().dim, "%s:%d", state.host, state.debug_port);
  ImGui::EndGroup();
  ImGui::SameLine();
  ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 72.0f * scl);
  ImGui::TextColored(state.udp_listener.running() ? ui::colors().success : ui::colors().dim,
                     "%s", state.udp_listener.running() ? locale::tr("sidebar.udp_on") : locale::tr("sidebar.udp_off"));
  ImGui::EndChild();
  ImGui::PopStyleVar(2); ImGui::PopStyleColor();

  /* Footer: fixed height, drawn first so scrollable area gets remaining space */
  const float footer_h = 42.0f * scl;
  const float avail_y = ImGui::GetContentRegionAvail().y;
  const float nav_h = avail_y - footer_h - 4.0f * scl;

  /* Scrollable nav area */
  if (nav_h > 40.0f * scl) {
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(3, 1));
    ImGui::BeginChild("SidebarNavList", ImVec2(0, nav_h), true);

    ImGui::Dummy(ImVec2(0, 3));
    sidebar_section(locale::tr("sidebar.section.main"));
    nav_item(state, Screen::Home, icons::kHome, locale::tr("nav.home"));
    nav_item(state, Screen::Consoles, icons::kConsole, locale::tr("nav.consoles"));

    ImGui::Dummy(ImVec2(0, 3));
    sidebar_section(locale::tr("sidebar.section.tools"));
    nav_item(state, Screen::Processes, icons::kProcess, locale::tr("nav.processes"));
    nav_item(state, Screen::Memory, icons::kMemory, locale::tr("nav.memory"));
    nav_item(state, Screen::Scanner, icons::kScanner, locale::tr("nav.scanner"));
    nav_item(state, Screen::PointerScanner, icons::kPointer, locale::tr("nav.pointer_scanner"));
    nav_item(state, Screen::AOBScanner, icons::kCode, locale::tr("nav.aob_scanner"));
    nav_item(state, Screen::Trainer, icons::kTrainer, locale::tr("nav.trainer"));
    nav_item(state, Screen::Plugins, icons::kPlugins, locale::tr("nav.plugins"));

    /* GUI plugin launcher */
    draw_gui_plugin_launcher(state);

    if (!state.client.connected() || payload_supports(state, MEMDBG_CAP_DEBUGGER))
      nav_item(state, Screen::Debugger, icons::kBug, locale::tr("nav.debugger"));

    ImGui::Dummy(ImVec2(0, 3));
    sidebar_section(locale::tr("sidebar.section.observe"));
    nav_item(state, Screen::TaskMgr, icons::kGauge, locale::tr("nav.taskmgr"));
    nav_item(state, Screen::Logs, icons::kLogs, locale::tr("nav.logs"));
    nav_item(state, Screen::Telemetry, icons::kTelemetry, locale::tr("nav.telemetry"));
    nav_item(state, Screen::Tracer, icons::kSearch, locale::tr("nav.tracer"));

    ImGui::Dummy(ImVec2(0, 3));
    sidebar_section(locale::tr("sidebar.section.system"));
    nav_item(state, Screen::Settings, icons::kSettings, locale::tr("nav.settings"));
    nav_item(state, Screen::Credits, icons::kCredits, locale::tr("nav.credits"));

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
  }

  /* Fixed footer */
  ImGui::SetCursorPosY(size.y - footer_h - ImGui::GetStyle().WindowPadding.y);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8, 5));
  ImGui::BeginChild("SidebarFooter", ImVec2(0, footer_h), true, ImGuiWindowFlags_NoScrollbar);
  ImGui::TextColored(ui::colors().dim, "TCP %d", state.debug_port);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "UDP %d", state.udp_port);
  ImGui::TextColored(ui::colors().dim, "PID %d", state.selected_pid);
  ImGui::EndChild();
  ImGui::PopStyleVar();

  ImGui::EndChild();
  ImGui::PopStyleVar(2); ImGui::PopStyleColor();
}

/* ---- Top bar ---- */

static float topbar_control_h() { return 32.0f * ui::dpi_scale(); }
static float topbar_logo_h() { return 34.0f * ui::dpi_scale(); }

static float topbar_center_y(float item_h) {
  return std::max(0.0f, (ImGui::GetWindowHeight() - item_h) * 0.5f);
}

static void topbar_align(float item_h = 0.0f) {
  if (item_h == 0.0f) item_h = topbar_control_h();
  ImGui::SetCursorPosY(topbar_center_y(item_h));
}

static void topbar_select_process(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.processes.size())) return;
  state.selected_process_row = row;
  state.selected_pid = state.processes[row].pid;
  state.maps.clear();
  state.selected_map_row = -1;
  state.memory.clear();
  state.scan_result = ScanResult{};
  state.scan_snapshot.clear();
  state.scan_snapshot_value_len = 0;
  state.scan_is_unknown_session = false;
  state.has_process_info = false;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "Process changed");
  set_status(state, "Selected PID " + std::to_string(state.selected_pid) + " (" + state.processes[row].name + ")");
}

static void topbar_refresh_processes(AppState &state) {
  if (!state.client.connected()) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", "Process refresh failed: not connected");
    set_status(state, "Connect a console before refreshing processes");
    push_notification(state, "Connect a console before loading processes", 4.0);
    return;
  }
  if (!state.client.process_list(state.processes)) {
    std::string error = state.client.last_error();
    if (error.empty()) error = "Process refresh failed";
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Process refresh failed: " + error).c_str());
    set_status(state, error);
    push_notification(state, "Process refresh failed: " + error, 5.0);
    return;
  }

  int new_row = -1;
  if (state.selected_pid > 0) {
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      if (state.processes[i].pid == state.selected_pid) { new_row = i; break; }
    }
  }
  if (new_row >= 0) {
    state.selected_process_row = new_row;
  } else {
    state.selected_pid = 0;
    state.selected_process_row = -1;
    state.has_process_info = false;
    state.maps.clear();
    state.selected_map_row = -1;
  }
  state.taskmgr_resources.clear();
  state.taskmgr_selected_row = -1;
  state.taskmgr_selected_pid = 0;
  state.taskmgr_detail_open = false;
  state.taskmgr_map_summary = ProcessMapSummary{};
  state.taskmgr_has_process_info = false;
  set_status(state, "Process list refreshed (" + std::to_string(state.processes.size()) + " entries)");
  if (state.crash_logging_enabled)
    state.crash_logger.log("refresh", ("Process list: " + std::to_string(state.processes.size()) + " entries").c_str());
}

static void topbar_refresh_maps(AppState &state) {
  request_maps_refresh_async(state);
}

static bool topbar_button(const char *id, const char *icon, const char *label,
                          float width, bool primary = false,
                          bool danger = false) {
  ImGui::PushID(id);
  topbar_align();
  std::string text = std::string(icon) + " " + label;
  bool pressed = false;
  if (danger)
    pressed = ui::danger_button(text.c_str(), ImVec2(width, topbar_control_h()));
  else if (primary)
    pressed = ui::primary_button(text.c_str(), ImVec2(width, topbar_control_h()));
  else
    pressed = ui::soft_button(text.c_str(), ImVec2(width, topbar_control_h()));
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", label);
  ImGui::PopID();
  return pressed;
}

static void topbar_chip(const char *id, const char *label, const char *value,
                        ImVec4 accent, float width) {
  ImGui::PushID(id);
  topbar_align();
  const float h = topbar_control_h();
  const ImVec2 pos = ImGui::GetCursorScreenPos();
  ImGui::InvisibleButton("##chip", ImVec2(width, h));
  const bool hovered = ImGui::IsItemHovered();

  ImDrawList *dl = ImGui::GetWindowDrawList();
  const ImVec4 bg = hovered ? ui::colors().bg3 : ui::colors().bg2;
  const float scl = ui::dpi_scale();
  dl->AddRectFilled(pos, ImVec2(pos.x + width, pos.y + h), ui::color_u32(bg), 2.0f * scl);
  dl->AddRect(pos, ImVec2(pos.x + width, pos.y + h),
              ui::color_u32(alpha(accent, hovered ? 0.96f : 0.58f)), 2.0f * scl);
  dl->AddRectFilled(ImVec2(pos.x + 5.0f * scl, pos.y + 6.0f * scl),
                    ImVec2(pos.x + 8.0f * scl, pos.y + h - 6.0f * scl),
                    ui::color_u32(accent), 1.0f * scl);
  const float text_y = pos.y + (h - ImGui::GetFontSize()) * 0.5f;
  dl->AddText(ImVec2(pos.x + 14.0f * scl, text_y),
              ui::color_u32(ui::colors().dim), label);
  const ImVec2 label_size = ImGui::CalcTextSize(label);
  dl->AddText(ImVec2(pos.x + 18.0f * scl + label_size.x, text_y),
              ui::color_u32(ui::colors().text), value);
  ImGui::PopID();
}

static void draw_process_combo(AppState &state, float width) {
  std::string preview = state.selected_pid > 0
      ? (std::to_string(state.selected_pid) + "  " + selected_process_name(state))
      : locale::tr("topbar.select_process");
  topbar_align();
  const float frame_pad_y = std::max(0.0f, (topbar_control_h() - ImGui::GetFontSize()) * 0.5f);
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9.0f, frame_pad_y));
  ImGui::SetNextItemWidth(width);
  if (ImGui::BeginCombo("##TopbarProcessCombo", preview.c_str())) {
    if (state.processes.empty()) {
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("topbar.no_process_list"));
    }
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const auto &process = state.processes[i];
      const bool selected = i == state.selected_process_row;
      std::string label = std::to_string(process.pid) + "  " + process.name;
      if (ImGui::Selectable(label.c_str(), selected)) topbar_select_process(state, i);
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }
  ImGui::PopStyleVar();
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("Select target process for all tools");
}

static std::string console_target_label(const ConsoleTarget &target) {
  ConsoleTarget normalized = target;
  normalize_console_target(normalized);
  return normalized.name + "  " + normalized.host + ":" + std::to_string(normalized.debug_port);
}

static void draw_console_target_combo(AppState &state, float width) {
  ensure_console_targets(state);
  const ConsoleTarget preview_target = current_console_target_from_fields(state);
  const std::string preview = console_target_label(preview_target);
  const bool locked = state.client.connected() || state.connect_pending;

  topbar_align();
  const float frame_pad_y = std::max(0.0f, (topbar_control_h() - ImGui::GetFontSize()) * 0.5f);
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9.0f, frame_pad_y));
  ImGui::BeginDisabled(locked);
  ImGui::SetNextItemWidth(width);
  if (ImGui::BeginCombo("##TopbarConsoleTarget", preview.c_str())) {
    for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
      const bool selected = i == state.selected_target_index;
      const std::string label = console_target_label(state.console_targets[static_cast<size_t>(i)]);
      if (ImGui::Selectable(label.c_str(), selected)) select_console_target(state, i);
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }
  ImGui::EndDisabled();
  ImGui::PopStyleVar();
  if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
    ImGui::SetTooltip("%s", locked ? "Disconnect before switching console target"
                                   : "Select the console target used by Connect");
  }
}

static void draw_top_bar(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8, 6));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(5, 0));
  ImGui::BeginChild("TopBar", size, true, ImGuiWindowFlags_NoScrollbar);
  const float topbar_w = ImGui::GetWindowWidth();

  load_texture_png_from_memory(s_logo_texture,
                               assets::kLogoNobgPng,
                               assets::kLogoNobgPngLen);
  const float logo_h = topbar_logo_h();
  const int logo_content_w = s_logo_texture.content_width > 0 ? s_logo_texture.content_width : s_logo_texture.width;
  const int logo_content_h = s_logo_texture.content_height > 0 ? s_logo_texture.content_height : s_logo_texture.height;
  const float logo_w = logo_content_h > 0
      ? logo_h * (static_cast<float>(logo_content_w) / static_cast<float>(logo_content_h))
      : 136.0f * scl;

  if (static_cast<bool>(s_logo_texture.texture)) {
    topbar_align(logo_h);
    ImGui::Image(texture_id(s_logo_texture.texture), ImVec2(logo_w, logo_h),
                 s_logo_texture.uv0, s_logo_texture.uv1);
  } else {
    topbar_align(logo_h);
    ImGui::Dummy(ImVec2(logo_w, logo_h));
  }
  ImGui::SameLine(0.0f, 12.0f * scl);

  const bool show_target_combo = topbar_w > 1780.0f * scl;
  if (show_target_combo) {
    draw_console_target_combo(state, 230.0f * scl);
    ImGui::SameLine();
  }

  ImGui::BeginDisabled(client_async_busy(state));
  if (topbar_button("TopbarRefreshPids", icons::kRefresh, locale::tr("topbar.pids"), 76.0f * scl))
    topbar_refresh_processes(state);
  ImGui::EndDisabled();
  ImGui::SameLine();
  if (!state.client.connected()) ImGui::BeginDisabled();
  draw_process_combo(state, show_target_combo ? 240.0f * scl :
                     (topbar_w > 1280.0f * scl ? 300.0f * scl : 230.0f * scl));
  if (!state.client.connected()) ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::BeginDisabled(client_async_busy(state));
  if (topbar_button("TopbarRefreshMaps", icons::kMemory, locale::tr("topbar.maps"), 82.0f * scl))
    topbar_refresh_maps(state);
  ImGui::EndDisabled();

  const bool connected = state.client.connected();
  const ImVec4 session_color = state.connect_pending ? ui::colors().warning :
                               connected ? ui::colors().success : ui::colors().danger;
  if (topbar_w > 1120.0f * scl) {
    ImGui::SameLine();
    topbar_chip("TopbarSession", locale::tr("topbar.chip_session"), connected ? locale::tr("topbar.online") : locale::tr("topbar.offline"), session_color, 136.0f * scl);
  }
  if (topbar_w > 1260.0f * scl) {
    ImGui::SameLine();
    std::string maps_value = state.map_refresh_pending ? "..." : std::to_string(state.maps.size());
    topbar_chip("TopbarMaps", locale::tr("topbar.chip_maps"), maps_value.c_str(), ui::colors().link, 104.0f * scl);
  }
  if (topbar_w > 1370.0f * scl) {
    ImGui::SameLine();
    topbar_chip("TopbarHits", locale::tr("topbar.chip_hits"), std::to_string(state.scan_result.count).c_str(), ui::colors().primary2, 104.0f * scl);
  }
  if (topbar_w > 1480.0f * scl) {
    ImGui::SameLine();
    topbar_chip("TopbarCheats", locale::tr("topbar.chip_cheats"), std::to_string(state.cheats.size()).c_str(), ui::colors().warning, 104.0f * scl);
  }

  std::string update_tag;
  std::string update_url;
  {
    std::lock_guard<std::mutex> lock(state.release_check.mutex);
    if (state.release_check.update_available) {
      update_tag = state.release_check.latest_tag;
      update_url = state.release_check.release_url;
    }
  }

  const bool has_update = !update_tag.empty();
  const float right_group_w = 392.0f * scl;
  const float right_w = right_group_w + (has_update ? 126.0f * scl : 0.0f);
  ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX() + 8.0f * scl, topbar_w - right_w));
  if (has_update) {
    std::string label = "Update " + update_tag;
    if (topbar_button("TopbarUpdate", icons::kNotify, label.c_str(), 118.0f * scl)) {
      if (!update_url.empty()) {
        (void)platform::open_url(update_url);
      }
    }
    if (ImGui::IsItemHovered()) {
      ImGui::SetTooltip("New MemDBG release available: %s", update_tag.c_str());
    }
    ImGui::SameLine();
  }
  if (connected) {
    ImGui::BeginDisabled(client_async_busy(state));
    if (topbar_button("TopbarPing", icons::kGauge, locale::tr("topbar.ping"), 96.0f * scl))
      set_status(state, state.client.ping() ? "Ping OK" : state.client.last_error());
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (topbar_button("TopbarLogs", icons::kLogs, locale::tr("topbar.logs"), 130.0f * scl))
      state.screen = Screen::Logs;
    ImGui::SameLine();
    ImGui::BeginDisabled(client_async_busy(state));
    std::string label = std::string(locale::tr("topbar.drop"));
    if (topbar_button("TopbarDrop", icons::kDisconnect, label.c_str(), 136.0f * scl, false, true))
      disconnect_console(state);
    ImGui::EndDisabled();
  } else {
    if (topbar_button("TopbarConfigure", icons::kConsole, locale::tr("topbar.console"), 96.0f * scl))
      state.screen = Screen::Consoles;
    ImGui::SameLine();
    if (topbar_button("TopbarSettings", icons::kSettings, locale::tr("topbar.settings"), 130.0f * scl))
      state.screen = Screen::Settings;
    ImGui::SameLine();
    if (state.connect_pending) {
      ImGui::BeginDisabled();
      (void)topbar_button("TopbarConnecting", icons::kConnect, locale::tr("topbar.connecting"), 136.0f * scl, true);
      ImGui::EndDisabled();
    } else {
      if (topbar_button("TopbarConnect", icons::kConnect, locale::tr("topbar.connect"), 136.0f * scl, true))
        connect_console(state);
    }
  }
  ImGui::EndChild();
  ImGui::PopStyleVar(2); ImGui::PopStyleColor();
}

/* ---- Status bar ---- */

static void draw_status_bar(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8, 4));
  ImGui::BeginChild("StatusBar", size, true, ImGuiWindowFlags_NoScrollbar);

  ui::status_dot(state.client.connected() ? ui::colors().success : ui::colors().muted);
  ImGui::SameLine();

  /* Status text with ellipsis on overflow */
  const float rhs_width = 580.0f * scl;
  float avail_for_status = ImGui::GetWindowWidth() - rhs_width - 32.0f * scl;
  if (avail_for_status < 80.0f * scl) avail_for_status = 80.0f * scl;
  text_ellipsis(state.status, avail_for_status, ui::colors().text);

  const auto log_stats = state.udp_listener.stats();
  ImGui::SameLine();
  ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX(), ImGui::GetWindowWidth() - rhs_width));
  ImGui::TextColored(ui::colors().dim, "%s", state.client.connected() ? locale::tr("status.session_open") : locale::tr("status.session_idle"));
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);
  ImGui::TextColored(ui::colors().dim, "TARGET pid=%d", state.selected_pid);
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);
  ImGui::TextColored(ui::colors().dim, "FPS %.0f", ImGui::GetIO().Framerate);
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);
  ImGui::TextColored(ui::colors().dim, "UDP %s", state.udp_listener.running() ? locale::tr("status.udp_on") : locale::tr("status.udp_off"));
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);

  /* Compact stats: abbreviate when narrow */
  if (ImGui::GetWindowWidth() > 1100.0f * scl) {
    ImGui::TextColored(ui::colors().dim, "rx=%llu lost=%llu evict=%llu",
                        static_cast<unsigned long long>(log_stats.received),
                        static_cast<unsigned long long>(log_stats.dropped),
                        static_cast<unsigned long long>(log_stats.evicted));
  } else {
    ImGui::TextColored(ui::colors().dim, "rx %llu",
                        static_cast<unsigned long long>(log_stats.received));
  }
  ImGui::EndChild();
  ImGui::PopStyleVar(); ImGui::PopStyleColor();
}

/* ---- Toast notifications ---- */

static float s_notification_bottom_reserved = 0.0f;

static void draw_notifications(AppState &state) {
  const float scl = ui::dpi_scale();
  const double now = ImGui::GetTime();
  ImGuiViewport *viewport = ImGui::GetMainViewport();
  const float toast_w = 380.0f * scl, toast_h = 56.0f * scl;
  const float pad = 20.0f * scl, spacing = 8.0f * scl;
  float x = viewport->WorkPos.x + viewport->WorkSize.x - toast_w - pad;
  float y_base = viewport->WorkPos.y + viewport->WorkSize.y - pad -
                 s_notification_bottom_reserved;

  int idx = 0;
  for (auto it = state.notifications.begin(); it != state.notifications.end(); ) {
    Notification &n = *it;
    double age = now - n.created_at;

    /* Remove expired or dismissed notifications */
    if (n.dismissed || (n.duration > 0.0 && age >= n.duration)) {
      it = state.notifications.erase(it);
      continue;
    }

    /* Fade-out over last 0.6s */
    float alpha = 1.0f;
    if (n.duration > 0.0 && age > n.duration - 0.6)
      alpha = static_cast<float>((n.duration - age) / 0.6);
    if (alpha < 0.05f) { ++it; ++idx; continue; }

    float y = y_base - (toast_h + spacing) * static_cast<float>(idx + 1);
    if (y < viewport->WorkPos.y + 40.0f * scl) { ++it; ++idx; continue; }

    ImGui::SetNextWindowPos(ImVec2(x, y));
    ImGui::SetNextWindowSize(ImVec2(toast_w, toast_h));

    ImVec4 toast_bg = ui::colors().bg2;
    toast_bg.w = 0.94f * alpha;
    ImVec4 toast_border = ui::colors().border_hot;
    toast_border.w = 0.72f * alpha;
    ImVec4 toast_accent = ui::colors().primary2;
    toast_accent.w = alpha;

    ImGui::PushStyleColor(ImGuiCol_WindowBg, toast_bg);
    ImGui::PushStyleColor(ImGuiCol_Border, toast_border);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f * scl);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 14));

    char window_id[64];
    std::snprintf(window_id, sizeof(window_id), "##Toast%d", idx);
    ImGui::Begin(window_id, nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                 ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                 ImGuiWindowFlags_NoNav);

    /* Accent bar + icon */
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 wpos = ImGui::GetWindowPos(), wsz = ImGui::GetWindowSize();
    dl->AddRectFilled(ImVec2(wpos.x + 6.0f * scl, wpos.y + 10.0f * scl),
                      ImVec2(wpos.x + 10.0f * scl, wpos.y + wsz.y - 10.0f * scl),
                      ui::color_u32(toast_accent), 3.0f * scl);

    ImGui::TextColored(toast_accent, "%s", icons::kNotify);
    ImGui::SameLine(34.0f * scl);

    /* Message text with wrapping */
    float text_w = toast_w - 100.0f * scl;
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + text_w);
    ImGui::TextColored(ImVec4(0.92f, 0.93f, 0.94f, alpha), "%s", n.message.c_str());
    ImGui::PopTextWrapPos();

    /* Dismiss button */
    ImGui::SameLine();
    ImGui::SetCursorPosX(toast_w - 40.0f * scl);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.65f, alpha));
    if (ImGui::SmallButton("x")) n.dismissed = true;
    ImGui::PopStyleColor();

    ImGui::End();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);

    ++it; ++idx;
  }
}

[[maybe_unused]] static void poll_release_check(AppState &state) {
  if (!state.release_check.worker_done.load()) {
    return;
  }

  std::string latest_tag;
  bool update_available = false;
  bool should_notify = false;
  {
    std::lock_guard<std::mutex> lock(state.release_check.mutex);
    if (!state.release_check.checked || state.release_check.notification_shown) {
      return;
    }
    latest_tag = state.release_check.latest_tag;
    update_available = state.release_check.update_available;
    state.release_check.notification_shown = true;
    should_notify = true;
  }

  if (!should_notify) return;
  if (update_available) {
    std::string message = "New MemDBG release available: " + latest_tag;
    set_status(state, message);
    push_notification(state, message, 10.0);
  }
}

static void poll_locale_repository(AppState &state) {
  locale::Manager &loc = locale::Manager::instance();
  locale::Repository &repo = locale::Repository::instance();
  (void)repo.poll_completed(loc);

  if (state.pending_language < 0 ||
      state.pending_language >= static_cast<int>(locale::Lang::COUNT)) {
    return;
  }

  locale::Lang pending = static_cast<locale::Lang>(state.pending_language);
  if (loc.is_loaded(pending) && loc.set_active(pending)) {
    state.language = state.pending_language;
    state.pending_language = -1;
    set_status(state, std::string(locale::tr("settings.language")) + ": " +
                     locale::lang_name(pending));
    return;
  }

  if (!repo.busy()) {
    const std::string error = repo.error();
    state.pending_language = -1;
    if (!error.empty()) set_status(state, error);
  }
}

static void poll_session_health(AppState &state) {
  if (state.has_hello && !state.client.connected() && !state.connect_pending) {
    const std::string error = state.client.last_error();
    const std::string message = error.empty()
                                    ? "Payload connection lost"
                                    : "Payload connection lost: " + error;
    disconnect_console(state, message.c_str());
    return;
  }

  if (state.heartbeat_pending) {
    if (!state.heartbeat_future.valid()) {
      state.heartbeat_pending = false;
      return;
    }

    auto status = state.heartbeat_future.wait_for(std::chrono::milliseconds(0));
    if (status != std::future_status::ready) {
      return;
    }

    bool ok = false;
    try {
      ok = state.heartbeat_future.get();
    } catch (const std::exception &ex) {
      state.heartbeat_error = ex.what();
    } catch (...) {
      state.heartbeat_error = "Unknown heartbeat error";
    }
    state.heartbeat_pending = false;

    if (!ok) {
      const std::string error = state.heartbeat_error.empty()
                                    ? state.client.last_error()
                                    : state.heartbeat_error;
      const std::string message = error.empty()
                                      ? "Payload connection lost"
                                      : "Payload connection lost: " + error;
      disconnect_console(state, message.c_str());
      return;
    }

    state.next_heartbeat = ImGui::GetTime() + 2.5;
    return;
  }

  if (!state.client.connected() || state.connect_pending ||
      state.telemetry_pending || state.scan_async_pending ||
      state.map_refresh_pending || state.taskmgr_resource_pending ||
      state.taskmgr_prefetch_pending || state.plugin_refresh_pending ||
      state.plugin_run_pending) {
    return;
  }

  const double now = ImGui::GetTime();
  if (now < state.next_heartbeat) {
    return;
  }

  if (state.heartbeat_future.valid()) {
    state.heartbeat_future.wait();
  }
  state.heartbeat_pending = true;
  state.heartbeat_error.clear();
  state.heartbeat_future = std::async(std::launch::async, [&state]() -> bool {
    if (state.client.ping()) {
      return true;
    }
    state.heartbeat_error = state.client.last_error();
    return false;
  });
}

/* ---- Screen dispatch ---- */

void draw_screen(AppState &state, ImVec2 avail) {
  switch (state.screen) {
  case Screen::Home:      draw_home(state, avail); break;
  case Screen::Consoles:  draw_consoles(state, avail); break;
  case Screen::Processes: draw_processes(state, avail); break;
  case Screen::Memory:    draw_memory(state, avail); break;
  case Screen::Scanner:        draw_scanner(state, avail); break;
  case Screen::PointerScanner: draw_pointer_scanner(state, avail); break;
  case Screen::AOBScanner:     draw_aob_scanner(state, avail); break;
  case Screen::Trainer:        draw_trainer(state, avail); break;
  case Screen::Plugins:        draw_plugins(state, avail); break;
  case Screen::PluginGUI:      draw_plugin_gui(state, avail); break;
  case Screen::Logs:      draw_logs(state, avail); break;
  case Screen::Telemetry: draw_telemetry(state, avail); break;
  case Screen::TaskMgr:   draw_taskmgr(state, avail); break;
  case Screen::Debugger:  draw_debugger(state, avail); break;
  case Screen::Tracer:    draw_tracer(state, avail); break;
  case Screen::Settings:  draw_settings(state, avail); break;
  case Screen::Credits:   draw_credits(state, avail); break;
  }
}

static void handle_global_shortcuts(AppState &state) {
  ImGuiIO &io = ImGui::GetIO();
  if (io.WantTextInput) return;

  if (ImGui::IsKeyPressed(ImGuiKey_F1)) state.screen = Screen::Home;
  if (ImGui::IsKeyPressed(ImGuiKey_F6)) state.screen = Screen::Processes;
  if (ImGui::IsKeyPressed(ImGuiKey_F7)) state.screen = Screen::Scanner;
  if (ImGui::IsKeyPressed(ImGuiKey_F8)) state.screen = Screen::Memory;
  if (ImGui::IsKeyPressed(ImGuiKey_F9)) state.screen = Screen::Trainer;
  if (ImGui::IsKeyPressed(ImGuiKey_F10)) state.screen = Screen::Logs;
  if (ImGui::IsKeyPressed(ImGuiKey_F11)) state.screen = Screen::Plugins;
  if (ImGui::IsKeyPressed(ImGuiKey_F5) && !state.connect_pending) {
    if (client_async_busy(state)) {
      set_status(state, "Wait for the active operation to finish");
    } else if (state.client.connected()) {
      disconnect_console(state);
    } else {
      connect_console(state);
    }
  }
}

/* ---- Mobile layout ---- */

struct MobileSafeArea {
  float left = 0.0f;
  float top = 0.0f;
  float right = 0.0f;
  float bottom = 0.0f;
};

static MobileSafeArea s_mobile_safe_area;
static bool s_mobile_tools_open = false;

void set_mobile_safe_area(float left, float top, float right, float bottom) {
  s_mobile_safe_area.left = std::max(0.0f, left);
  s_mobile_safe_area.top = std::max(0.0f, top);
  s_mobile_safe_area.right = std::max(0.0f, right);
  s_mobile_safe_area.bottom = std::max(0.0f, bottom);
}

static void mobile_info_row(const char *label, const std::string &value,
                            ImVec4 value_color) {
  const float scl = ui::dpi_scale();
  const float label_w = 92.0f * scl;
  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::SameLine(label_w);
  text_ellipsis(value.c_str(), ImGui::GetContentRegionAvail().x, value_color);
}

static bool mobile_nav_button(const char *id, const char *icon,
                              const char *label, bool enabled) {
  const float scl = ui::dpi_scale();
  const ImVec2 size(ImGui::GetContentRegionAvail().x, 42.0f * scl);
  const std::string text = std::string(icon) + "  " + label;
  ImGui::PushID(id);
  ImGui::BeginDisabled(!enabled);
  const bool clicked = ui::soft_button(text.c_str(), size);
  ImGui::EndDisabled();
  ImGui::PopID();
  return clicked && enabled;
}

static std::string mobile_target_endpoint(const ConsoleTarget &target) {
  return target.host + ":" + std::to_string(target.debug_port) +
         " / UDP " + std::to_string(target.udp_port);
}

static void mobile_persist_console_targets(AppState &state,
                                           const std::string &ok_message) {
  std::string error;
  if (save_frontend_settings(state, &error)) {
    set_status(state, ok_message);
    push_notification(state, ok_message, 3.0);
  } else {
    const std::string message = "Cannot save console targets: " + error;
    set_status(state, message);
    push_notification(state, message, 5.0);
  }
}

static void mobile_use_discovered_console(AppState &state,
                                          const DiscoveryConsole &console) {
  const std::string name = !console.name.empty() ? console.name : console.ip;
  std::snprintf(state.target_name, sizeof(state.target_name), "%s",
                name.c_str());
  std::snprintf(state.host, sizeof(state.host), "%s", console.ip.c_str());
  state.debug_port = console.debug_port;
  if (console.udp_log_port != 0U) state.udp_port = console.udp_log_port;
  normalize_ports(state);
}

static void poll_mobile_discovery(AppState &state) {
  if (!state.discovery_pending || !state.discovery_future.valid()) return;
  auto status = state.discovery_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  bool ok = false;
  try {
    ok = state.discovery_future.get();
  } catch (const std::exception &ex) {
    state.discovery_error = ex.what();
  } catch (...) {
    state.discovery_error = "Unknown discovery error";
  }
  state.discovery_pending = false;

  if (!ok && !state.discovery_error.empty()) {
    set_status(state, state.discovery_error);
    push_notification(state, state.discovery_error, 5.0);
  } else if (state.discovered_consoles.empty()) {
    set_status(state, "No MemDBG payloads found on the local network.");
  } else {
    set_status(state, "Found " +
                      std::to_string(state.discovered_consoles.size()) +
                      " payload(s).");
  }
}

static void start_mobile_discovery(AppState &state) {
  if (state.discovery_pending) return;
  if (state.discovery_future.valid()) state.discovery_future.wait();
  state.discovery_pending = true;
  state.discovery_error.clear();
  state.discovered_consoles.clear();
  set_status(state, "Searching local network...");
  state.discovery_future = std::async(std::launch::async, [&state]() -> bool {
    return state.discovery_client.discover(
        MEMDBG_DEFAULT_DISCOVERY_PORT, 1.5, state.discovered_consoles,
        state.discovery_error);
  });
}

static void draw_mobile_section_label(const char *label) {
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", label);
}

static bool mobile_action_button(const std::string &label, bool primary,
                                 bool danger = false) {
  const float scl = ui::dpi_scale();
  const ImVec2 size(ImGui::GetContentRegionAvail().x, 42.0f * scl);
  if (danger) return ui::danger_button(label.c_str(), size);
  if (primary) return ui::primary_button(label.c_str(), size);
  return ui::soft_button(label.c_str(), size);
}

static std::string mobile_format_bytes(uint64_t bytes) {
  const char *units[] = {"B", "KiB", "MiB", "GiB"};
  double value = static_cast<double>(bytes);
  int unit = 0;
  while (value >= 1024.0 && unit < 3) {
    value /= 1024.0;
    ++unit;
  }
  char buffer[64];
  if (unit == 0)
    std::snprintf(buffer, sizeof(buffer), "%llu %s",
                  static_cast<unsigned long long>(bytes), units[unit]);
  else
    std::snprintf(buffer, sizeof(buffer), "%.2f %s", value, units[unit]);
  return buffer;
}

static void mobile_select_map(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.maps.size())) return;
  const MapEntry &map = state.maps[row];
  state.selected_map_row = row;
  std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                hex_u64(map.start).c_str());
  std::snprintf(state.write_address, sizeof(state.write_address), "%s",
                hex_u64(map.start).c_str());
  std::snprintf(state.scan_start, sizeof(state.scan_start), "%s",
                hex_u64(map.start).c_str());
  std::snprintf(state.scan_length, sizeof(state.scan_length), "%s",
                hex_u64(map.end - map.start).c_str());
  set_status(state, "Selected map " + hex_u64(map.start) + " - " +
                        hex_u64(map.end));
}

static plugins::PluginRunContext mobile_build_plugin_context(
    const AppState &state) {
  plugins::PluginRunContext context;
  context.host = state.host;
  context.debug_port = state.debug_port;
  context.udp_port = state.udp_port;
  context.connected = state.client.connected();
  context.selected_pid = state.selected_pid;
  context.selected_process_name = selected_process_name(state);
  context.dump_path = state.dump_path;
  context.trainer_file_path = state.trainer_file_path;
  context.protocol_version = state.has_hello ? state.hello.protocol_version : 0U;
  context.capabilities = state.has_hello ? state.hello.capabilities : 0U;
  context.map_count = state.maps.size();
  context.scan_hit_count = state.scan_result.addresses.size();
  context.trainer_entry_count = state.cheats.size();
  return context;
}

static void mobile_start_plugin_refresh(AppState &state) {
  if (state.plugin_refresh_pending || state.plugin_run_pending) return;
  if (state.plugin_refresh_future.valid()) state.plugin_refresh_future.wait();
  state.plugin_refresh_error.clear();
  state.plugin_refresh_pending = true;
  set_status(state, "Refreshing plugin sources...");
  state.plugin_refresh_future = std::async(std::launch::async,
      [&state]() -> bool {
        std::string error;
        const bool ok = state.plugin_manager.refresh_all(&error);
        state.plugin_refresh_error = error;
        return ok;
      });
}

static void mobile_start_plugin_run(AppState &state,
                                    const plugins::PluginPackage &package) {
  if (!package.installed || state.plugin_refresh_pending ||
      state.plugin_run_pending) {
    return;
  }
  if (state.plugin_run_future.valid()) state.plugin_run_future.wait();
  const auto context = mobile_build_plugin_context(state);
  const std::string package_id = package.id;
  state.plugin_last_output.clear();
  state.plugin_last_error.clear();
  state.plugin_last_command.clear();
  state.plugin_last_id = package_id;
  state.plugin_run_pending = true;
  state.plugin_run_start_time = ImGui::GetTime();
  set_status(state, "Running plugin " + package.name + "...");
  state.plugin_run_future = std::async(std::launch::async,
      [&state, package_id, context]() {
        return state.plugin_manager.run_plugin(package_id, context);
      });
}

static std::string mobile_plugin_tags_text(
    const std::vector<std::string> &tags) {
  std::string out;
  for (const auto &tag : tags) {
    if (!out.empty()) out += ", ";
    out += tag;
  }
  return out;
}

static bool mobile_contains_ci(const std::string &haystack,
                               const std::string &needle) {
  if (needle.empty()) return true;
  auto lower = [](std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                     return static_cast<char>(std::tolower(c));
                   });
    return value;
  };
  return lower(haystack).find(lower(needle)) != std::string::npos;
}

static std::vector<plugins::PluginPackage> mobile_filtered_plugins(
    AppState &state, const std::vector<plugins::PluginSource> &sources) {
  if (state.plugin_source_filter < 0 ||
      state.plugin_source_filter > static_cast<int>(sources.size())) {
    state.plugin_source_filter = 0;
  }

  std::vector<plugins::PluginPackage> catalog = state.plugin_manager.catalog();
  if (state.plugin_source_filter > 0) {
    const auto &source = sources[static_cast<size_t>(
        state.plugin_source_filter - 1)];
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const plugins::PluginPackage &pkg) {
          return pkg.source_id != source.id;
        }), catalog.end());
  }

  const std::string filter = state.plugin_filter;
  if (!filter.empty()) {
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const plugins::PluginPackage &pkg) {
          return !mobile_contains_ci(pkg.name, filter) &&
                 !mobile_contains_ci(pkg.author, filter) &&
                 !mobile_contains_ci(pkg.id, filter) &&
                 !mobile_contains_ci(pkg.source_name, filter) &&
                 !mobile_contains_ci(pkg.short_description, filter) &&
                 !mobile_contains_ci(pkg.description, filter) &&
                 !mobile_contains_ci(mobile_plugin_tags_text(pkg.tags), filter);
        }), catalog.end());
  }

  std::sort(catalog.begin(), catalog.end(),
      [](const plugins::PluginPackage &a,
         const plugins::PluginPackage &b) {
        if (a.installed != b.installed) return a.installed > b.installed;
        if (a.enabled != b.enabled) return a.enabled > b.enabled;
        if (a.language != b.language)
          return static_cast<int>(a.language) > static_cast<int>(b.language);
        return a.name < b.name;
      });
  return catalog;
}

static std::string mobile_plugin_description(
    const plugins::PluginPackage &package) {
  if (!package.short_description.empty()) return package.short_description;
  if (!package.description.empty()) return package.description;
  return "No description provided.";
}

static void draw_mobile_network(AppState &state, ImVec2 size) {
  ensure_console_targets(state);
  poll_mobile_discovery(state);

  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const bool locked = connected || state.connect_pending;

  ImGui::BeginChild("MobileNetwork", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "Console");
  ImGui::SameLine();
  ui::status_dot(state.connect_pending ? palette.warning :
                 connected ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(connected ? palette.success :
                     state.connect_pending ? palette.warning : palette.danger,
                     "%s", state.connect_pending ? "Connecting" :
                          connected ? "Connected" : "Offline");

  ImGui::Spacing();
  ImGui::BeginChild("MobileNetworkSummary", ImVec2(0, 112.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  const ConsoleTarget current_target = {
      state.target_name, state.host, state.debug_port, state.udp_port
  };
  mobile_info_row("Target", state.target_name, palette.text);
  mobile_info_row("Endpoint", mobile_target_endpoint(current_target),
                  connected ? palette.text : palette.muted);
  mobile_info_row("UDP", state.udp_listener.running() ? "Listening" : "Stopped",
                  state.udp_listener.running() ? palette.success : palette.dim);
  mobile_info_row("Payload", state.has_hello ? "Handshake OK" : "No hello",
                  state.has_hello ? palette.success : palette.dim);
  ImGui::EndChild();

  ImGui::BeginDisabled(client_async_busy(state));
  if (connected) {
    if (mobile_action_button(std::string(icons::kGauge) + "  Ping payload",
                             false)) {
      set_status(state, state.client.ping() ? "Ping OK"
                                            : state.client.last_error());
    }
    if (mobile_action_button(std::string(icons::kDisconnect) +
                             "  Disconnect", false, true)) {
      disconnect_console(state);
    }
  } else {
    if (mobile_action_button(std::string(icons::kConnect) + "  Connect",
                             true)) {
      save_current_console_target(state);
      connect_console(state);
    }
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Target");
  ImGui::BeginDisabled(locked);
  std::string preview = state.console_targets.empty()
      ? "No saved targets"
      : state.console_targets[static_cast<size_t>(
            std::clamp(state.selected_target_index, 0,
                       static_cast<int>(state.console_targets.size()) - 1))].name;
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::BeginCombo("##MobileTargetProfile", preview.c_str())) {
    for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
      const ConsoleTarget &target = state.console_targets[static_cast<size_t>(i)];
      const bool selected = i == state.selected_target_index;
      const std::string label = target.name + "  " +
                                mobile_target_endpoint(target);
      if (ImGui::Selectable(label.c_str(), selected))
        select_console_target(state, i);
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }

  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText("Name##MobileTargetName", state.target_name,
                   sizeof(state.target_name));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText("IPv4##MobileTargetHost", state.host, sizeof(state.host));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Debug TCP##MobileDebugPort", &state.debug_port);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("UDP logs##MobileUdpPort", &state.udp_port);
  normalize_ports(state);

  const float gap = 6.0f * scl;
  const float button_w = (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f;
  if (ui::soft_button((std::string(icons::kSave) + " Save").c_str(),
                      ImVec2(button_w, 40.0f * scl))) {
    save_current_console_target(state);
    mobile_persist_console_targets(state, "Console target updated");
  }
  ImGui::SameLine(0, gap);
  if (ui::primary_button((std::string(icons::kAdd) + " Add").c_str(),
                         ImVec2(button_w, 40.0f * scl))) {
    add_console_target(state);
    mobile_persist_console_targets(state, "Console target added");
  }
  ImGui::SameLine(0, gap);
  if (ui::danger_button((std::string(icons::kTrash) + " Del").c_str(),
                        ImVec2(button_w, 40.0f * scl))) {
    remove_selected_console_target(state);
    mobile_persist_console_targets(state, "Console target removed");
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Saved");
  for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
    const ConsoleTarget &target = state.console_targets[static_cast<size_t>(i)];
    const bool selected = i == state.selected_target_index;
    ImGui::PushID(i);
    ImGui::BeginDisabled(locked);
    const std::string label =
        std::string(icons::kTarget) + "  " + (selected ? "* " : "") +
        target.name + "\n" + mobile_target_endpoint(target);
    if (ui::soft_button(label.c_str(),
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               52.0f * scl))) {
      select_console_target(state, i);
    }
    ImGui::EndDisabled();
    ImGui::PopID();
  }

  draw_mobile_section_label("Runtime");
  if (!state.udp_listener.running()) {
    if (mobile_action_button("Start UDP log listener", false)) {
      std::string error;
      if (ensure_udp_listener(state, error)) set_status(state, "UDP started");
      else set_status(state, error);
    }
  } else {
    if (mobile_action_button("Restart UDP log listener", false)) {
      state.udp_listener.stop();
      std::string error;
      if (ensure_udp_listener(state, error)) set_status(state, "UDP restarted");
      else set_status(state, error);
    }
    if (mobile_action_button("Stop UDP log listener", false)) {
      state.udp_listener.stop();
      set_status(state, "UDP stopped");
    }
  }

  draw_mobile_section_label("Discovery");
  ImGui::BeginDisabled(state.discovery_pending);
  if (mobile_action_button(std::string(icons::kRefresh) +
                           (state.discovery_pending ? "  Searching" :
                            "  Discover payloads"), false)) {
    start_mobile_discovery(state);
  }
  ImGui::EndDisabled();

  if (!state.discovered_consoles.empty()) {
    for (int i = 0; i < static_cast<int>(state.discovered_consoles.size()); ++i) {
      const DiscoveryConsole &console =
          state.discovered_consoles[static_cast<size_t>(i)];
      const std::string name = !console.name.empty() ? console.name : console.ip;
      const std::string endpoint =
          console.ip + ":" + std::to_string(console.debug_port) +
          " / UDP " + std::to_string(console.udp_log_port);
      ImGui::PushID(1000 + i);
      ImGui::BeginChild("MobileDiscoveredPayload", ImVec2(0, 86.0f * scl),
                        true, ImGuiWindowFlags_NoScrollbar);
      text_ellipsis(name.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.text);
      text_ellipsis(endpoint.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.muted);
      const float half = (ImGui::GetContentRegionAvail().x - gap) * 0.5f;
      ImGui::BeginDisabled(locked);
      if (ui::soft_button("Use", ImVec2(half, 32.0f * scl))) {
        mobile_use_discovered_console(state, console);
        set_status(state, "Selected discovered target " + console.ip);
      }
      ImGui::SameLine(0, gap);
      if (ui::primary_button("Save", ImVec2(half, 32.0f * scl))) {
        mobile_use_discovered_console(state, console);
        add_console_target(state);
        mobile_persist_console_targets(state, "Discovered target saved");
      }
      ImGui::EndDisabled();
      ImGui::EndChild();
      ImGui::PopID();
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static void draw_mobile_logs(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const auto stats = state.udp_listener.stats();
  auto logs = state.udp_listener.snapshot();

  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(12.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::BeginChild("MobileLogs", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);

  ImGui::TextColored(palette.primary2, "%s", "UDP Logs");
  ImGui::SameLine();
  ui::status_dot(state.udp_listener.running() ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(state.udp_listener.running() ? palette.success
                                                  : palette.muted,
                     "%s", state.udp_listener.running() ? "Listening"
                                                         : "Stopped");

  ImGui::BeginChild("MobileLogSummary", ImVec2(0, 138.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Port", std::to_string(stats.port),
                  state.udp_listener.running() ? palette.text : palette.dim);
  mobile_info_row("Received", std::to_string(stats.received), palette.text);
  mobile_info_row("Lost", std::to_string(stats.dropped), palette.muted);
  mobile_info_row("Buffered", std::to_string(logs.size()), palette.text);
  ImGui::Separator();
  const std::string error = state.udp_listener.last_error();
  text_ellipsis(error.empty() ? state.status : error.c_str(),
                ImGui::GetContentRegionAvail().x,
                error.empty() ? palette.muted : palette.warning);
  ImGui::EndChild();

  if (!state.udp_listener.running()) {
    if (mobile_action_button(std::string(icons::kPlay) +
                                 "  Start listener",
                             true)) {
      std::string error;
      if (ensure_udp_listener(state, error))
        set_status(state, "UDP listener started");
      else
        set_status(state, error);
    }
  } else if (mobile_action_button(std::string(icons::kStop) +
                                      "  Stop listener",
                                  false)) {
    state.udp_listener.stop();
    set_status(state, "UDP listener stopped");
  }

  if (ImGui::BeginTable("MobileLogActions", 2,
                        ImGuiTableFlags_SizingStretchSame)) {
    ImGui::TableNextColumn();
    if (mobile_action_button(std::string(icons::kCopy) + "  Copy", false)) {
      if (!logs.empty()) {
        std::string all;
        for (const auto &line : logs) all += line + "\n";
        ImGui::SetClipboardText(all.c_str());
        set_status(state, "Logs copied");
      } else {
        set_status(state, "No logs to copy");
      }
    }
    ImGui::TableNextColumn();
    if (mobile_action_button(std::string(icons::kTrash) + "  Clear", false)) {
      state.udp_listener.clear();
      logs.clear();
      set_status(state, "Logs cleared");
    }
    ImGui::EndTable();
  }

  draw_mobile_section_label("Messages");
  ImGui::BeginChild("MobileLogLines", ImVec2(0, 0), true);
  if (logs.empty()) {
    ImGui::TextColored(palette.muted, "%s", "No UDP messages yet");
    ImGui::TextWrapped("%s",
                       "Start the listener and keep this screen open while "
                       "the payload forwards runtime output.");
  } else {
    const float wrap_x = ImGui::GetCursorPosX() +
                         ImGui::GetContentRegionAvail().x;
    for (const auto &line : logs) {
      ImGui::PushTextWrapPos(wrap_x);
      ImGui::TextUnformatted(line.c_str());
      ImGui::PopTextWrapPos();
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.0f)
      ImGui::SetScrollHereY(1.0f);
  }
  ImGui::EndChild();

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
}

static void draw_mobile_plugin_source_popup(AppState &state) {
  const float scl = ui::dpi_scale();
  if (state.plugin_add_source_modal_open)
    ImGui::OpenPopup("MobileAddPluginSource");

  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowSize(
      ImVec2(std::min(430.0f * scl, viewport->WorkSize.x - 24.0f * scl), 0),
      ImGuiCond_Appearing);
  bool open = state.plugin_add_source_modal_open;
  if (ImGui::BeginPopupModal("MobileAddPluginSource", &open,
                             ImGuiWindowFlags_NoResize)) {
    ImGui::TextColored(ui::colors().primary2, "%s", "Add Plugin Source");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("Name##MobilePluginSourceName",
                     state.plugin_source_name,
                     sizeof(state.plugin_source_name));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("Manifest URL##MobilePluginSourceUrl",
                     state.plugin_source_url,
                     sizeof(state.plugin_source_url));
    ImGui::BeginDisabled(state.plugin_refresh_pending ||
                         state.plugin_run_pending);
    if (ui::primary_button((std::string(icons::kAdd) + "  Add").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  40.0f * scl))) {
      std::string error;
      if (state.plugin_manager.add_source(state.plugin_source_name,
                                          state.plugin_source_url, &error)) {
        std::snprintf(state.plugin_source_name,
                      sizeof(state.plugin_source_name), "%s",
                      "Community Repository");
        state.plugin_source_url[0] = '\0';
        state.plugin_add_source_modal_open = false;
        mobile_start_plugin_refresh(state);
        ImGui::CloseCurrentPopup();
      } else {
        set_status(state, error);
      }
    }
    ImGui::EndDisabled();
    if (ui::soft_button("Cancel",
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               38.0f * scl))) {
      state.plugin_add_source_modal_open = false;
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }
  if (!open) state.plugin_add_source_modal_open = false;
}

static void draw_mobile_plugin_output(AppState &state) {
  const bool has_output = state.plugin_run_pending ||
                          !state.plugin_last_error.empty() ||
                          !state.plugin_last_id.empty() ||
                          !state.plugin_last_command.empty() ||
                          !state.plugin_last_output.empty();
  if (!has_output) return;

  const float scl = ui::dpi_scale();
  draw_mobile_section_label("Runtime output");
  if (state.plugin_run_pending) {
    ui::draw_scan_progress("Plugin script", icons::kTerminal,
                           ImGui::GetTime() - state.plugin_run_start_time,
                           ImGui::GetContentRegionAvail().x);
    return;
  }

  if (!state.plugin_last_error.empty()) {
    ImGui::TextColored(ui::colors().danger, "%s",
                       state.plugin_last_error.c_str());
  } else {
    ImGui::TextColored(ui::colors().success, "Last run: %s",
                       state.plugin_last_id.c_str());
  }
  if (!state.plugin_last_command.empty()) {
    text_ellipsis(state.plugin_last_command.c_str(),
                  ImGui::GetContentRegionAvail().x, ui::colors().dim);
  }

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::BeginChild("MobilePluginOutputText", ImVec2(0, 150.0f * scl),
                    true);
  if (state.plugin_last_output.empty())
    ImGui::TextColored(ui::colors().dim, "%s", "Output will appear here.");
  else
    ImGui::TextUnformatted(state.plugin_last_output.c_str());
  ImGui::EndChild();
  ImGui::PopStyleColor();
}

static void draw_mobile_plugin_details(AppState &state,
                                       const plugins::PluginPackage &package) {
  const float scl = ui::dpi_scale();
  const bool ios_python =
#if defined(MEMDBG_PLATFORM_IOS)
      package.language == plugins::PluginLanguage::Python;
#else
      false;
#endif
  const bool runnable = package.installed && package.enabled && !ios_python;
  const float gap = 6.0f * scl;
  const float two_col = (ImGui::GetContentRegionAvail().x - gap) * 0.5f;

  ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                         ImGui::GetContentRegionAvail().x);
  ImGui::TextWrapped("%s", mobile_plugin_description(package).c_str());
  ImGui::PopTextWrapPos();
  ImGui::TextColored(ui::colors().dim, "%s  %s  %s",
                     plugins::language_name(package.language),
                     package.version.c_str(), package.source_name.c_str());

  ImGui::BeginDisabled(state.plugin_refresh_pending ||
                       state.plugin_run_pending);
  if (!package.installed) {
    if (ui::primary_button((std::string(icons::kDump) + "  Install").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  40.0f * scl))) {
      std::string error;
      if (state.plugin_manager.install_package(package.id,
                                               package.source_id, &error)) {
        set_status(state, "Plugin installed: " + package.name);
        push_notification(state, "Plugin installed: " + package.name);
      } else {
        set_status(state, error);
      }
    }
  } else {
    ImGui::BeginDisabled(!runnable);
    if (ui::primary_button((std::string(icons::kPlay) + "  Run").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  40.0f * scl))) {
      mobile_start_plugin_run(state, package);
    }
    ImGui::EndDisabled();
    if (ios_python) {
      ImGui::TextColored(ui::colors().warning, "%s",
                         "Python plugins are desktop-only on iOS.");
    }

    if (ui::soft_button((std::string(icons::kRefresh) + "  Update").c_str(),
                        ImVec2(two_col, 38.0f * scl))) {
      std::string error;
      if (state.plugin_manager.install_package(package.id,
                                               package.source_id, &error)) {
        set_status(state, "Plugin updated: " + package.name);
      } else {
        set_status(state, error);
      }
    }
    ImGui::SameLine(0, gap);
    if (ui::danger_button((std::string(icons::kTrash) + "  Remove").c_str(),
                          ImVec2(two_col, 38.0f * scl))) {
      std::string error;
      if (state.plugin_manager.uninstall_package(package.id, &error))
        set_status(state, "Plugin removed: " + package.name);
      else
        set_status(state, error);
    }

    bool enabled = package.enabled;
    if (ImGui::Checkbox("Enabled##MobilePluginEnabled", &enabled)) {
      std::string error;
      if (!state.plugin_manager.set_package_enabled(package.id, enabled,
                                                    &error)) {
        set_status(state, error);
      }
    }
  }
  ImGui::EndDisabled();

  if (!package.tags.empty()) {
    const std::string tags = mobile_plugin_tags_text(package.tags);
    text_ellipsis(tags.c_str(),
                  ImGui::GetContentRegionAvail().x, ui::colors().dim);
  }
}

static void draw_mobile_plugin_card(AppState &state,
                                    const plugins::PluginPackage &package,
                                    int index) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool selected = state.plugin_selected_row == index;
  const ImVec2 pos = ImGui::GetCursorScreenPos();
  const ImVec2 size(ImGui::GetContentRegionAvail().x, 76.0f * scl);
  ImGui::PushID(package.id.c_str());
  ImGui::InvisibleButton("##MobilePluginCard", size);
  if (ImGui::IsItemClicked()) {
    state.plugin_selected_row = selected ? -1 : index;
    state.plugin_description_expanded = false;
  }

  ImDrawList *draw = ImGui::GetWindowDrawList();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  const ImVec4 bg = selected ? ImVec4(0.06f, 0.22f, 0.17f, 1.0f)
      : ImGui::IsItemHovered() ? ImVec4(0.12f, 0.16f, 0.15f, 1.0f)
                               : palette.bg1;
  draw->AddRectFilled(pos, max, ui::color_u32(bg), 7.0f * scl);
  draw->AddRect(pos, max,
                ui::color_u32(selected ? palette.primary2 : palette.border),
                7.0f * scl, 0, 1.0f * scl);

  const char *language = plugins::language_name(package.language);
  const char *state_text = package.installed
      ? (package.enabled ? "Installed" : "Disabled")
      : "Available";
  const ImVec2 badge_min(pos.x + 10.0f * scl, pos.y + 12.0f * scl);
  const ImVec2 badge_max(badge_min.x + 46.0f * scl,
                         badge_min.y + 28.0f * scl);
  draw->AddRectFilled(badge_min, badge_max,
                      ui::color_u32(package.language == plugins::PluginLanguage::Lua
                                        ? ImVec4(0.16f, 0.18f, 0.34f, 1.0f)
                                        : ImVec4(0.14f, 0.24f, 0.32f, 1.0f)),
                      5.0f * scl);
  draw->AddText(ImVec2(badge_min.x + 7.0f * scl, badge_min.y + 6.0f * scl),
                ui::color_u32(palette.text), language);

  const float text_x = pos.x + 66.0f * scl;
  draw->PushClipRect(ImVec2(text_x, pos.y + 8.0f * scl),
                     ImVec2(max.x - 10.0f * scl, max.y - 8.0f * scl), true);
  draw->AddText(ImVec2(text_x, pos.y + 10.0f * scl),
                ui::color_u32(palette.text), package.name.c_str());
  const std::string meta = std::string(state_text) + "  |  " +
      (package.author.empty() ? "Unknown creator" : package.author);
  draw->AddText(ImVec2(text_x, pos.y + 31.0f * scl),
                ui::color_u32(package.installed ? palette.success :
                              palette.muted), meta.c_str());
  const std::string desc = mobile_plugin_description(package);
  draw->AddText(ImVec2(text_x, pos.y + 52.0f * scl),
                ui::color_u32(palette.dim), desc.c_str());
  draw->PopClipRect();

  ImGui::PopID();

  if (selected) {
    ImGui::Indent(8.0f * scl);
    draw_mobile_plugin_details(state, package);
    ImGui::Unindent(8.0f * scl);
  }
  ImGui::Spacing();
}

static void draw_mobile_plugins(AppState &state, ImVec2 size) {
  poll_plugin_tasks(state);
  const float scl = ui::dpi_scale();

  draw_mobile_plugin_source_popup(state);
  ImGui::BeginChild("MobilePlugins", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(ui::colors().primary2, "%s", "Plugins");
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%s",
                     state.plugin_run_pending ? "Running" :
                     state.plugin_refresh_pending ? "Refreshing" :
                     "Ready");

  std::vector<plugins::PluginSource> sources = state.plugin_manager.sources();
  std::vector<plugins::PluginPackage> catalog =
      mobile_filtered_plugins(state, sources);
  if (state.plugin_selected_row >= static_cast<int>(catalog.size()))
    state.plugin_selected_row = catalog.empty() ? -1 : 0;

  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("##MobilePluginSearch", "Search plugins...",
                           state.plugin_filter, sizeof(state.plugin_filter));

  const float gap = 6.0f * scl;
  const float button_w = (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f;
  ImGui::BeginDisabled(state.plugin_refresh_pending ||
                       state.plugin_run_pending);
  if (ui::soft_button((std::string(icons::kRefresh) + " Sync").c_str(),
                      ImVec2(button_w, 38.0f * scl))) {
    mobile_start_plugin_refresh(state);
  }
  ImGui::SameLine(0, gap);
  if (ui::primary_button((std::string(icons::kAdd) + " Source").c_str(),
                         ImVec2(button_w, 38.0f * scl))) {
    state.plugin_add_source_modal_open = true;
  }
  ImGui::SameLine(0, gap);
  if (ui::soft_button((std::string(icons::kSettings) + " GUI").c_str(),
                      ImVec2(button_w, 38.0f * scl))) {
    state.screen = Screen::PluginGUI;
    set_status(state, "GUI plugins use the desktop bridge on this build.");
  }
  ImGui::EndDisabled();

  if (!sources.empty()) {
    const char *preview = "All sources";
    std::string preview_label;
    if (state.plugin_source_filter > 0) {
      preview_label = sources[static_cast<size_t>(
          state.plugin_source_filter - 1)].name;
      preview = preview_label.c_str();
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("Source##MobilePluginSourceFilter", preview)) {
      if (ImGui::Selectable("All sources", state.plugin_source_filter == 0))
        state.plugin_source_filter = 0;
      for (size_t i = 0; i < sources.size(); ++i) {
        const bool selected =
            state.plugin_source_filter == static_cast<int>(i + 1U);
        if (ImGui::Selectable(sources[i].name.c_str(), selected))
          state.plugin_source_filter = static_cast<int>(i + 1U);
        if (selected) ImGui::SetItemDefaultFocus();
      }
      ImGui::EndCombo();
    }
  }

  draw_mobile_plugin_output(state);
  draw_mobile_section_label("Catalog");
  if (catalog.empty()) {
    ui::draw_empty_state("No plugins found",
                         "Refresh sources or change the search.");
  } else {
    for (size_t i = 0; i < catalog.size(); ++i) {
      draw_mobile_plugin_card(state, catalog[i], static_cast<int>(i));
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static uint32_t mobile_scan_value_len(const AppState &state) {
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (build_scan_value(state.scan_type, state.scan_value, value, value_len))
    return value_len;

  switch (state.scan_type) {
  case MEMDBG_VALUE_U8: return 1U;
  case MEMDBG_VALUE_U16: return 2U;
  case MEMDBG_VALUE_U32:
  case MEMDBG_VALUE_F32: return 4U;
  case MEMDBG_VALUE_U64:
  case MEMDBG_VALUE_F64:
  case MEMDBG_VALUE_POINTER: return 8U;
  default: return 1U;
  }
}

static bool mobile_scan_refine_match(int type, RefineMode mode,
                                     const std::vector<uint8_t> &old_bytes,
                                     const std::vector<uint8_t> &new_bytes) {
  const bool same = old_bytes == new_bytes;
  switch (mode) {
  case RefineMode::Changed:
    return !same;
  case RefineMode::Unchanged:
    return same;
  case RefineMode::Increased:
  case RefineMode::Decreased: {
    long double old_value = 0.0;
    long double new_value = 0.0;
    if (!bytes_to_number(type, old_bytes, old_value) ||
        !bytes_to_number(type, new_bytes, new_value)) {
      return false;
    }
    return mode == RefineMode::Increased ? new_value > old_value
                                         : new_value < old_value;
  }
  }
  return false;
}

static const char *mobile_refine_name(RefineMode mode) {
  switch (mode) {
  case RefineMode::Changed: return "Changed";
  case RefineMode::Unchanged: return "Unchanged";
  case RefineMode::Increased: return "Increased";
  case RefineMode::Decreased: return "Decreased";
  }
  return "Refine";
}

static bool mobile_has_batch_read(const AppState &state) {
  return (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;
}

static bool mobile_capture_snapshot_worker(Client &client, int32_t pid,
                                           const std::vector<uint64_t> &addrs,
                                           uint32_t value_len,
                                           bool has_batch_read,
                                           std::vector<ScanSnapshotEntry> &out,
                                           uint32_t &read_errors,
                                           uint64_t &elapsed_ns) {
  out.clear();
  read_errors = 0;
  elapsed_ns = 0;
  if (pid <= 0 || addrs.empty() || value_len == 0U) return true;

  const auto start = std::chrono::steady_clock::now();
  out.reserve(addrs.size());

  if (has_batch_read) {
    std::vector<memdbg_batch_read_item_t> batch_items;
    batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
    for (size_t base = 0U; base < addrs.size();
         base += MEMDBG_BATCH_READ_MAX_ITEMS) {
      batch_items.clear();
      const size_t chunk_end =
          std::min(base + MEMDBG_BATCH_READ_MAX_ITEMS, addrs.size());
      for (size_t i = base; i < chunk_end; ++i) {
        memdbg_batch_read_item_t item{};
        item.address = addrs[i];
        item.length = value_len;
        batch_items.push_back(item);
      }

      Client::BatchReadResult batch;
      if (!client.batch_read(pid, batch_items, batch)) {
        read_errors += static_cast<uint32_t>(chunk_end - base);
        continue;
      }

      uint32_t data_offset = 0U;
      for (const auto &entry : batch.entries) {
        if (data_offset > batch.data.size() ||
            entry.length > batch.data.size() - data_offset ||
            entry.status != 0U || entry.length != value_len) {
          read_errors++;
          data_offset += std::min<uint32_t>(
              entry.length,
              data_offset <= batch.data.size()
                  ? static_cast<uint32_t>(batch.data.size() - data_offset)
                  : 0U);
          continue;
        }

        ScanSnapshotEntry snap;
        snap.address = entry.address;
        snap.bytes.assign(batch.data.begin() + data_offset,
                          batch.data.begin() + data_offset + entry.length);
        out.push_back(std::move(snap));
        data_offset += entry.length;
      }
    }
  } else {
    for (uint64_t address : addrs) {
      std::vector<uint8_t> data;
      if (!client.memory_read(pid, address, value_len, data) ||
          data.size() != value_len) {
        read_errors++;
        continue;
      }
      ScanSnapshotEntry snap;
      snap.address = address;
      snap.bytes = std::move(data);
      out.push_back(std::move(snap));
    }
  }

  const auto end = std::chrono::steady_clock::now();
  elapsed_ns = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
          .count());
  return true;
}

static void mobile_prepare_scan_async(AppState &state,
                                      const std::string &label) {
  if (state.scan_async_future.valid()) state.scan_async_future.wait();
  {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    state.scan_async_temp_result = ScanResult{};
    state.scan_async_temp_snapshot.clear();
    state.scan_async_temp_snapshot_value_len = 0U;
    state.scan_async_temp_snapshot_type = state.scan_type;
    state.scan_async_temp_is_unknown = false;
    state.scan_async_temp_session_status[0] = '\0';
    state.scan_async_error.clear();
    state.auto_search_temp_candidates.clear();
  }
  state.scan_async_label = label;
  state.scan_async_start_time = ImGui::GetTime();
  state.scan_async_pending = true;
  state.scan_async_owner = Screen::Scanner;
}

static void mobile_start_range_scan(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) {
    set_status(state, "Connect a console before scanning");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before scanning");
    return;
  }
  if (!payload_supports(state, MEMDBG_CAP_SCAN_EXACT)) {
    set_status(state, "Payload does not support exact range scans");
    return;
  }

  uint64_t start = 0;
  uint64_t length = 0;
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!parse_u64(state.scan_start, start) ||
      !parse_u64(state.scan_length, length) || length == 0U) {
    set_status(state, "Enter a valid start and non-zero length");
    return;
  }
  if (!build_scan_value(state.scan_type, state.scan_value, value, value_len)) {
    set_status(state, "Invalid scan value");
    return;
  }

  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  memdbg_scan_exact_request_t request{};
  request.pid = state.selected_pid;
  request.start = start;
  request.length = length;
  request.value_type = static_cast<uint32_t>(state.scan_type);
  request.value_length = value_len;
  request.alignment = static_cast<uint32_t>(state.scan_alignment);
  request.max_results = static_cast<uint32_t>(state.scan_max_results);
  std::copy(value.begin(), value.end(), request.value);

  mobile_prepare_scan_async(state, "Range scan");
  const int32_t pid = state.selected_pid;
  const int scan_type = state.scan_type;
  Client &client = state.client;
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_value_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_type = state.scan_async_temp_snapshot_type;
  auto &temp_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = mobile_has_batch_read(state);

  state.scan_async_future = std::async(
      std::launch::async,
      [&client, request, pid, scan_type, value_len, has_batch, &temp_result,
       &temp_snapshot, &temp_value_len, &temp_type, &temp_unknown,
       &temp_status, &error_out, &mtx = state.scan_async_mtx]() -> bool {
        std::lock_guard<std::mutex> lock(mtx);
        ScanResult result;
        if (!client.scan_exact(request, result)) {
          error_out = client.last_error();
          return false;
        }

        uint32_t read_errors = 0;
        uint64_t snapshot_ns = 0;
        std::vector<ScanSnapshotEntry> snapshot;
        mobile_capture_snapshot_worker(client, pid, result.addresses,
                                       value_len, has_batch, snapshot,
                                       read_errors, snapshot_ns);

        const uint64_t capture_bytes =
            static_cast<uint64_t>(snapshot.size()) * value_len;
        result.read_calls += static_cast<uint32_t>(result.addresses.size());
        result.read_errors += read_errors;
        result.elapsed_ns += snapshot_ns;
        temp_result = std::move(result);
        temp_snapshot = std::move(snapshot);
        temp_value_len = value_len;
        temp_type = scan_type;
        temp_unknown = false;
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu values, %u read errors, %s",
                      has_batch ? "BATCH_READ" : "individual reads",
                      temp_snapshot.size(), read_errors,
                      bytes_per_second(capture_bytes, snapshot_ns).c_str());
        return true;
      });
}

static void mobile_start_process_scan(AppState &state, bool unknown) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) {
    set_status(state, "Connect a console before scanning");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before scanning");
    return;
  }
  const uint32_t required_cap =
      unknown ? MEMDBG_CAP_SCAN_UNKNOWN : MEMDBG_CAP_SCAN_PROCESS_EXACT;
  if (!payload_supports(state, required_cap)) {
    set_status(state, unknown ? "Payload does not support unknown scans"
                              : "Payload does not support process scans");
    return;
  }

  uint64_t start = 0;
  uint64_t end = 0;
  if (!parse_u64(state.scan_start, start) ||
      !parse_u64(state.scan_end, end) || (end != 0U && end <= start)) {
    set_status(state, "Enter a valid scan window");
    return;
  }

  std::array<uint8_t, 16> value{};
  uint32_t value_len = mobile_scan_value_len(state);
  if (!unknown &&
      !build_scan_value(state.scan_type, state.scan_value, value, value_len)) {
    set_status(state, "Invalid scan value");
    return;
  }

  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  memdbg_scan_process_exact_request_t request{};
  request.pid = state.selected_pid;
  request.value_type = static_cast<uint32_t>(state.scan_type);
  request.value_length = value_len;
  request.alignment = static_cast<uint32_t>(state.scan_alignment);
  request.max_results = static_cast<uint32_t>(state.scan_max_results);
  request.protection_mask = state.scan_readable_only ? 1U : 0U;
  request.start = start;
  request.end = end;
  if (!unknown) std::copy(value.begin(), value.end(), request.value);

  mobile_prepare_scan_async(state, unknown ? "Unknown value scan"
                                           : "Process scan");
  const int32_t pid = state.selected_pid;
  const int scan_type = state.scan_type;
  Client &client = state.client;
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_value_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_type = state.scan_async_temp_snapshot_type;
  auto &temp_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = mobile_has_batch_read(state);

  state.scan_async_future = std::async(
      std::launch::async,
      [&client, request, pid, scan_type, value_len, has_batch, unknown,
       &temp_result, &temp_snapshot, &temp_value_len, &temp_type,
       &temp_unknown, &temp_status, &error_out,
       &mtx = state.scan_async_mtx]() -> bool {
        std::lock_guard<std::mutex> lock(mtx);
        ScanResult result;
        const bool ok = unknown ? client.scan_unknown(request, result)
                                : client.scan_process_exact(request, result);
        if (!ok) {
          error_out = client.last_error();
          return false;
        }

        uint32_t read_errors = 0;
        uint64_t snapshot_ns = 0;
        std::vector<ScanSnapshotEntry> snapshot;
        mobile_capture_snapshot_worker(client, pid, result.addresses,
                                       value_len, has_batch, snapshot,
                                       read_errors, snapshot_ns);

        const uint64_t capture_bytes =
            static_cast<uint64_t>(snapshot.size()) * value_len;
        result.read_calls += static_cast<uint32_t>(result.addresses.size());
        result.read_errors += read_errors;
        result.elapsed_ns += snapshot_ns;
        temp_result = std::move(result);
        temp_snapshot = std::move(snapshot);
        temp_value_len = value_len;
        temp_type = scan_type;
        temp_unknown = unknown;
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu values, %u read errors, %s",
                      has_batch ? "BATCH_READ" : "individual reads",
                      temp_snapshot.size(), read_errors,
                      bytes_per_second(capture_bytes, snapshot_ns).c_str());
        return true;
      });
}

static void mobile_poll_scanner_async(AppState &state) {
  if (!state.scan_async_pending || !state.scan_async_future.valid()) return;
  if (state.scan_async_future.wait_for(std::chrono::milliseconds(0)) !=
      std::future_status::ready) {
    return;
  }

  state.scan_async_pending = false;
  bool ok = false;
  try {
    ok = state.scan_async_future.get();
  } catch (const std::exception &ex) {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    state.scan_async_error = ex.what();
  } catch (...) {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    state.scan_async_error = "Unknown scanner error";
  }

  if (state.scan_async_owner != Screen::Scanner) return;

  if (!ok) {
    std::string error;
    {
      std::lock_guard<std::mutex> lock(state.scan_async_mtx);
      error = state.scan_async_error.empty() ? "Scanner request failed"
                                             : state.scan_async_error;
      state.scan_async_error.clear();
    }
    set_status(state, error);
    push_notification(state, error, 5.0);
    return;
  }

  ScanResult result;
  std::vector<ScanSnapshotEntry> snapshot;
  uint32_t value_len = 0U;
  int type = MEMDBG_VALUE_U32;
  bool unknown = false;
  char status[256] = {};
  {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    result = std::move(state.scan_async_temp_result);
    snapshot = std::move(state.scan_async_temp_snapshot);
    value_len = state.scan_async_temp_snapshot_value_len;
    type = state.scan_async_temp_snapshot_type;
    unknown = state.scan_async_temp_is_unknown;
    std::memcpy(status, state.scan_async_temp_session_status, sizeof(status));
  }

  state.scan_result = std::move(result);
  state.scan_snapshot = std::move(snapshot);
  state.scan_snapshot_value_len = value_len;
  state.scan_snapshot_type = type;
  state.scan_is_unknown_session = unknown;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s", status[0] != '\0' ? status : "Scan complete");
  set_status(state, state.scan_session_status);
  push_notification(state, state.scan_async_label + ": " +
                               std::to_string(state.scan_result.count) +
                               " results");
}

static void mobile_refresh_scan_snapshot(AppState &state) {
  if (!state.client.connected() || state.selected_pid <= 0 ||
      state.scan_result.addresses.empty()) {
    set_status(state, "Run a scan before refreshing the baseline");
    return;
  }
  if (client_async_busy(state)) {
    set_status(state, "Wait for the active operation to finish");
    return;
  }

  const uint32_t value_len = mobile_scan_value_len(state);
  uint32_t read_errors = 0;
  uint64_t elapsed_ns = 0;
  std::vector<ScanSnapshotEntry> snapshot;
  mobile_capture_snapshot_worker(state.client, state.selected_pid,
                                 state.scan_result.addresses, value_len,
                                 mobile_has_batch_read(state), snapshot,
                                 read_errors, elapsed_ns);

  state.scan_snapshot = std::move(snapshot);
  state.scan_snapshot_value_len = value_len;
  state.scan_snapshot_type = state.scan_type;
  state.scan_is_unknown_session = false;
  state.scan_result.read_calls +=
      static_cast<uint32_t>(state.scan_result.addresses.size());
  state.scan_result.read_errors += read_errors;
  state.scan_result.elapsed_ns += elapsed_ns;
  const uint64_t capture_bytes =
      static_cast<uint64_t>(state.scan_snapshot.size()) * value_len;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s: %zu values, %u read errors, %s",
                mobile_has_batch_read(state) ? "BATCH_READ"
                                             : "individual reads",
                state.scan_snapshot.size(), read_errors,
                bytes_per_second(capture_bytes, elapsed_ns).c_str());
  set_status(state, state.scan_session_status);
}

static void mobile_refine_scan(AppState &state, RefineMode mode) {
  if (!state.client.connected() || state.selected_pid <= 0 ||
      state.scan_snapshot.empty() || state.scan_snapshot_value_len == 0U) {
    set_status(state, "Run a scan before refining");
    return;
  }
  if (client_async_busy(state)) {
    set_status(state, "Wait for the active operation to finish");
    return;
  }

  const uint32_t value_len = state.scan_snapshot_value_len;
  const auto old_snapshot = state.scan_snapshot;
  std::vector<uint64_t> addrs;
  addrs.reserve(old_snapshot.size());
  for (const auto &entry : old_snapshot) addrs.push_back(entry.address);

  uint32_t read_errors = 0;
  uint64_t elapsed_ns = 0;
  std::vector<ScanSnapshotEntry> current;
  mobile_capture_snapshot_worker(state.client, state.selected_pid, addrs,
                                 value_len, mobile_has_batch_read(state),
                                 current, read_errors, elapsed_ns);

  std::unordered_map<uint64_t, std::vector<uint8_t>> old_by_address;
  old_by_address.reserve(old_snapshot.size());
  for (const auto &entry : old_snapshot)
    old_by_address.emplace(entry.address, entry.bytes);

  std::vector<ScanSnapshotEntry> next_snapshot;
  std::vector<uint64_t> next_addresses;
  next_snapshot.reserve(current.size());
  next_addresses.reserve(current.size());
  uint64_t bytes_read = 0U;
  for (auto &entry : current) {
    auto it = old_by_address.find(entry.address);
    if (it == old_by_address.end()) continue;
    bytes_read += entry.bytes.size();
    if (!mobile_scan_refine_match(state.scan_snapshot_type, mode, it->second,
                                  entry.bytes)) {
      continue;
    }
    next_addresses.push_back(entry.address);
    next_snapshot.push_back(std::move(entry));
  }

  state.scan_snapshot = std::move(next_snapshot);
  state.scan_result.addresses = std::move(next_addresses);
  state.scan_result.count =
      static_cast<uint32_t>(state.scan_result.addresses.size());
  state.scan_result.truncated = false;
  state.scan_result.bytes_scanned = bytes_read;
  state.scan_result.elapsed_ns = elapsed_ns;
  state.scan_result.read_calls =
      static_cast<uint32_t>(current.size() + read_errors);
  state.scan_result.read_errors = read_errors;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s kept %zu values", mobile_refine_name(mode),
                state.scan_snapshot.size());
  set_status(state, state.scan_session_status);
  push_notification(state, state.scan_session_status);
}

static std::string mobile_scan_value_text(int type,
                                          const std::vector<uint8_t> &bytes) {
  char buf[96] = {};
  switch (type) {
  case MEMDBG_VALUE_U8:
    if (bytes.size() >= sizeof(uint8_t))
      std::snprintf(buf, sizeof(buf), "%u",
                    static_cast<unsigned>(read_scalar<uint8_t>(bytes)));
    break;
  case MEMDBG_VALUE_U16:
    if (bytes.size() >= sizeof(uint16_t))
      std::snprintf(buf, sizeof(buf), "%u",
                    static_cast<unsigned>(read_scalar<uint16_t>(bytes)));
    break;
  case MEMDBG_VALUE_U32:
    if (bytes.size() >= sizeof(uint32_t))
      std::snprintf(buf, sizeof(buf), "%u", read_scalar<uint32_t>(bytes));
    break;
  case MEMDBG_VALUE_U64:
    if (bytes.size() >= sizeof(uint64_t))
      std::snprintf(buf, sizeof(buf), "%llu",
                    static_cast<unsigned long long>(
                        read_scalar<uint64_t>(bytes)));
    break;
  case MEMDBG_VALUE_POINTER:
    if (bytes.size() >= sizeof(uint64_t))
      return hex_u64(read_scalar<uint64_t>(bytes));
    break;
  case MEMDBG_VALUE_F32:
    if (bytes.size() >= sizeof(float))
      std::snprintf(buf, sizeof(buf), "%.6g",
                    static_cast<double>(read_scalar<float>(bytes)));
    break;
  case MEMDBG_VALUE_F64:
    if (bytes.size() >= sizeof(double))
      std::snprintf(buf, sizeof(buf), "%.12g", read_scalar<double>(bytes));
    break;
  default:
    break;
  }
  if (buf[0] != '\0') return buf;
  return bytes_to_hex(bytes);
}

static const ScanSnapshotEntry *mobile_snapshot_for(const AppState &state,
                                                    uint64_t address) {
  for (const auto &entry : state.scan_snapshot)
    if (entry.address == address) return &entry;
  return nullptr;
}

static void mobile_value_type_combo(const char *label, int *value) {
  static const char *const type_names[] = {
      "Bytes", "u8", "u16", "u32", "u64", "float", "double", "pointer"};
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::Combo(label, value, type_names, IM_ARRAYSIZE(type_names));
}

static void draw_mobile_scanner(AppState &state, ImVec2 size) {
  mobile_poll_scanner_async(state);
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const bool has_pid = state.selected_pid > 0;

  ImGui::BeginChild("MobileScanner", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "Scanner");
  ImGui::SameLine();
  ui::status_dot(state.scan_async_pending ? palette.warning :
                 connected && has_pid ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(palette.muted, "%s", selected_process_name(state).c_str());

  ImGui::BeginChild("MobileScannerSummary", ImVec2(0, 128.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  has_pid ? palette.text : palette.dim);
  mobile_info_row("Results", std::to_string(state.scan_result.count) +
                                 (state.scan_result.truncated ? " truncated"
                                                              : ""),
                  state.scan_result.count != 0 ? palette.success
                                               : palette.muted);
  mobile_info_row("Speed",
                  bytes_per_second(state.scan_result.bytes_scanned,
                                   state.scan_result.elapsed_ns),
                  palette.muted);
  mobile_info_row("Session", state.scan_session_status, palette.dim);
  ImGui::EndChild();

  draw_mobile_section_label("Exact value");
  mobile_value_type_combo("Value type##MobileScanType", &state.scan_type);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Value##MobileScanValue", "0",
                           state.scan_value, sizeof(state.scan_value));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Alignment##MobileScanAlignment", &state.scan_alignment);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Max results##MobileScanMaxResults",
                  &state.scan_max_results);
  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  draw_mobile_section_label("Range");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Start##MobileScanStart", "0x0",
                           state.scan_start, sizeof(state.scan_start));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Length##MobileScanLength", "0x1000",
                           state.scan_length, sizeof(state.scan_length));

  const bool can_range = connected && has_pid && !client_async_busy(state) &&
                         payload_supports(state, MEMDBG_CAP_SCAN_EXACT);
  ImGui::BeginDisabled(!can_range);
  if (mobile_action_button(std::string(icons::kSearch) + "  Range scan",
                           true)) {
    mobile_start_range_scan(state);
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Process scan");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("End filter##MobileScanEnd", "0x0",
                           state.scan_end, sizeof(state.scan_end));
  ImGui::Checkbox("Readable maps only", &state.scan_readable_only);

  const bool can_process =
      connected && has_pid && !client_async_busy(state) &&
      payload_supports(state, MEMDBG_CAP_SCAN_PROCESS_EXACT);
  ImGui::BeginDisabled(!can_process);
  if (mobile_action_button(std::string(icons::kTarget) + "  Scan process",
                           false)) {
    mobile_start_process_scan(state, false);
  }
  ImGui::EndDisabled();

  const bool can_unknown =
      connected && has_pid && !client_async_busy(state) &&
      payload_supports(state, MEMDBG_CAP_SCAN_UNKNOWN);
  ImGui::BeginDisabled(!can_unknown);
  if (mobile_action_button(std::string(icons::kSearch) +
                               "  Unknown value baseline",
                           false)) {
    mobile_start_process_scan(state, true);
  }
  ImGui::EndDisabled();

  if (state.scan_async_pending) {
    ui::draw_scan_progress(state.scan_async_label, icons::kSearch,
                           ImGui::GetTime() - state.scan_async_start_time,
                           ImGui::GetContentRegionAvail().x);
  }

  draw_mobile_section_label("Refine");
  const bool can_refine =
      connected && has_pid && !client_async_busy(state) &&
      payload_supports(state, MEMDBG_CAP_MEMORY_READ) &&
      !state.scan_snapshot.empty();
  ImGui::BeginDisabled(!can_refine);
  if (mobile_action_button("Changed", false))
    mobile_refine_scan(state, RefineMode::Changed);
  if (mobile_action_button("Unchanged", false))
    mobile_refine_scan(state, RefineMode::Unchanged);
  if (mobile_action_button("Increased", false))
    mobile_refine_scan(state, RefineMode::Increased);
  if (mobile_action_button("Decreased", false))
    mobile_refine_scan(state, RefineMode::Decreased);
  if (mobile_action_button(std::string(icons::kRefresh) +
                               "  Refresh baseline",
                           false)) {
    mobile_refresh_scan_snapshot(state);
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Results");
  if (state.scan_result.addresses.empty()) {
    ImGui::TextColored(palette.dim, "%s", "No scan results");
  } else {
    if (mobile_action_button(std::string(icons::kCopy) + "  Copy all",
                             false)) {
      std::string all;
      all.reserve(state.scan_result.addresses.size() * 18U);
      for (uint64_t address : state.scan_result.addresses)
        all += hex_u64(address) + "\n";
      ImGui::SetClipboardText(all.c_str());
      set_status(state, "Copied scan results");
    }

    if (mobile_action_button(std::string(icons::kAdd) +
                                 "  First hit to trainer",
                             false)) {
      const std::string address = hex_u64(state.scan_result.addresses.front());
      std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                    address.c_str());
      state.cheat_type = state.scan_type;
      state.screen = Screen::Trainer;
    }

    const size_t limit =
        std::min<size_t>(state.scan_result.addresses.size(), 80U);
    for (size_t i = 0; i < limit; ++i) {
      const uint64_t address = state.scan_result.addresses[i];
      const ScanSnapshotEntry *snap = mobile_snapshot_for(state, address);
      const float card_h = 66.0f * scl;
      ImGui::PushID(static_cast<int>(i));
      ImGui::BeginChild("MobileScanHit", ImVec2(0, card_h), true,
                        ImGuiWindowFlags_NoScrollbar);
      const std::string addr = hex_u64(address);
      if (ImGui::Selectable(addr.c_str(), false,
                            ImGuiSelectableFlags_AllowDoubleClick)) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                      addr.c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s",
                      addr.c_str());
        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
          state.screen = Screen::Memory;
      }
      ImGui::TextColored(
          palette.dim, "%s",
          snap != nullptr
              ? mobile_scan_value_text(state.scan_snapshot_type, snap->bytes)
                    .c_str()
              : "value not captured");
      ImGui::SameLine(ImGui::GetWindowWidth() - 86.0f * scl);
      if (ImGui::SmallButton("Use")) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                      addr.c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s",
                      addr.c_str());
        std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                      addr.c_str());
      }
      ImGui::EndChild();
      ImGui::PopID();
    }
    if (state.scan_result.addresses.size() > limit) {
      ImGui::TextColored(palette.dim, "%zu more results hidden on mobile",
                         state.scan_result.addresses.size() - limit);
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static bool mobile_validate_writable_address(AppState &state, int32_t pid,
                                             uint64_t address, size_t length,
                                             std::string &error) {
  if (length == 0U) return true;
  const uint64_t byte_length = static_cast<uint64_t>(length);
  if (address > UINT64_MAX - byte_length) {
    error = "Trainer address range overflows";
    return false;
  }

  std::vector<MapEntry> fetched_maps;
  const std::vector<MapEntry> *maps = nullptr;
  if (pid == state.selected_pid && !state.maps.empty()) {
    maps = &state.maps;
  } else if (state.client.connected()) {
    if (state.client.process_maps(pid, fetched_maps)) maps = &fetched_maps;
  }
  if (maps == nullptr || maps->empty()) return true;

  const uint64_t end = address + byte_length;
  for (const auto &map : *maps) {
    if (address < map.start || end > map.end) continue;
    if ((map.protection & 2U) == 0U) {
      error = "Address " + hex_u64(address) + " is not writable";
      if (!map.name.empty()) error += ": " + map.name;
      return false;
    }
    return true;
  }

  error = "Address " + hex_u64(address) + " is outside known maps";
  return false;
}

static bool mobile_apply_cheat(AppState &state, CheatEntry &cheat) {
  if (!state.client.connected()) {
    cheat.status = "No console session";
    return false;
  }
  const int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0) {
    cheat.status = "No target PID";
    return false;
  }
  if (cheat.bytes.empty()) {
    cheat.status = "Empty value";
    return false;
  }

  std::string validation_error;
  if (!mobile_validate_writable_address(state, pid, cheat.address,
                                        cheat.bytes.size(),
                                        validation_error)) {
    cheat.status = validation_error;
    return false;
  }

  uint32_t written = 0;
  if (!state.client.memory_write(pid, cheat.address, cheat.bytes, written)) {
    cheat.status = state.client.last_error();
    return false;
  }
  cheat.active = true;
  cheat.status = "Wrote " + std::to_string(written) + " bytes";
  return true;
}

static bool mobile_deactivate_cheat(AppState &state, CheatEntry &cheat) {
  if (!cheat.has_off_bytes || cheat.off_bytes.empty()) {
    cheat.status = "No OFF value captured";
    return false;
  }
  if (!state.client.connected()) {
    cheat.status = "No console session";
    return false;
  }
  const int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0) {
    cheat.status = "No target PID";
    return false;
  }

  std::string validation_error;
  if (!mobile_validate_writable_address(state, pid, cheat.address,
                                        cheat.off_bytes.size(),
                                        validation_error)) {
    cheat.status = validation_error;
    return false;
  }

  uint32_t written = 0;
  if (!state.client.memory_write(pid, cheat.address, cheat.off_bytes,
                                 written)) {
    cheat.status = state.client.last_error();
    return false;
  }
  cheat.active = false;
  cheat.status = "Restored " + std::to_string(written) + " bytes";
  return true;
}

static void mobile_add_cheat_from_fields(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before adding a trainer entry");
    return;
  }
  if (client_async_busy(state)) {
    set_status(state, "Wait for the active operation to finish");
    return;
  }

  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  if (!parse_u64(state.cheat_address, address)) {
    set_status(state, "Invalid cheat address");
    return;
  }
  if (!build_value_bytes(state.cheat_type, state.cheat_value, bytes)) {
    set_status(state, "Invalid cheat value");
    return;
  }

  CheatEntry cheat;
  cheat.description =
      state.cheat_description[0] != '\0' ? state.cheat_description : "Cheat";
  cheat.pid = state.selected_pid;
  cheat.address = address;
  cheat.value_type = state.cheat_type;
  cheat.value_text = state.cheat_value;
  cheat.bytes = std::move(bytes);
  cheat.locked = state.cheat_lock;
  if (state.client.connected()) (void)capture_off_value(state, cheat);
  state.cheats.push_back(std::move(cheat));
  set_status(state, "Trainer entry added");
}

static void mobile_apply_enabled_cheats(AppState &state) {
  int applied = 0;
  for (auto &cheat : state.cheats)
    if (cheat.enabled && mobile_apply_cheat(state, cheat)) applied++;
  const std::string message =
      "Applied " + std::to_string(applied) + " trainer entries";
  set_status(state, message);
  push_notification(state, message);
}

static void mobile_import_batchcode(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before importing batchcode");
    return;
  }
  std::string error;
  std::vector<BatchcodeEntry> entries;
  const int imported = parse_batchcode(state.batchcode_text, entries, error);
  if (imported < 0) {
    set_status(state, "Batchcode error: " + error);
    return;
  }
  for (size_t i = 0; i < entries.size(); ++i) {
    CheatEntry cheat;
    cheat.description = "Batchcode " + std::to_string(i + 1U);
    cheat.pid = state.selected_pid;
    cheat.address = entries[i].offset;
    cheat.value_type = MEMDBG_VALUE_BYTES;
    cheat.value_text = bytes_to_hex(entries[i].bytes);
    cheat.bytes = std::move(entries[i].bytes);
    cheat.enabled = true;
    if (state.client.connected()) (void)capture_off_value(state, cheat);
    state.cheats.push_back(std::move(cheat));
  }
  set_status(state, "Imported " + std::to_string(imported) +
                        " batchcode entries");
}

static void draw_mobile_trainer(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const bool has_pid = state.selected_pid > 0;

  ImGui::BeginChild("MobileTrainer", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "Trainer");
  ImGui::SameLine();
  ui::status_dot(connected && has_pid ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(palette.muted, "%s", selected_process_name(state).c_str());

  ImGui::BeginChild("MobileTrainerSummary", ImVec2(0, 96.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  has_pid ? palette.text : palette.dim);
  mobile_info_row("Entries", std::to_string(state.cheats.size()),
                  state.cheats.empty() ? palette.muted : palette.success);
  mobile_info_row("File", state.trainer_file_path, palette.dim);
  ImGui::EndChild();

  draw_mobile_section_label("Cheat builder");
  ImGui::BeginDisabled(!has_pid);
  if (mobile_action_button("Use memory address", false)) {
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                  state.write_address);
  }
  ImGui::BeginDisabled(state.scan_result.addresses.empty());
  if (mobile_action_button("Use first scan hit", false)) {
    const std::string address = hex_u64(state.scan_result.addresses.front());
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                  address.c_str());
  }
  ImGui::EndDisabled();
  ImGui::EndDisabled();

  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Name##MobileCheatName", "Cheat name",
                           state.cheat_description,
                           sizeof(state.cheat_description));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Address##MobileCheatAddress", "0x0",
                           state.cheat_address, sizeof(state.cheat_address));
  mobile_value_type_combo("Value type##MobileCheatType", &state.cheat_type);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Value##MobileCheatValue", "0",
                           state.cheat_value, sizeof(state.cheat_value));
  ImGui::Checkbox("Lock on apply", &state.cheat_lock);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::SliderFloat("Lock interval##MobileCheatLockInterval",
                     &state.cheat_lock_interval, 0.10f, 5.0f, "%.2fs");

  ImGui::BeginDisabled(!connected || !has_pid || client_async_busy(state));
  if (mobile_action_button(std::string(icons::kAdd) + "  Add entry", true))
    mobile_add_cheat_from_fields(state);
  ImGui::EndDisabled();

  draw_mobile_section_label("Trainer file");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Path##MobileTrainerPath", "trainers/session.cht",
                           state.trainer_file_path,
                           sizeof(state.trainer_file_path));
  if (mobile_action_button(std::string(icons::kLoad) + "  Load", false)) {
    const int count = load_trainer_file(state, state.trainer_file_path);
    if (count >= 0)
      set_status(state, "Loaded " + std::to_string(count) +
                            " trainer entries");
  }
  if (mobile_action_button(std::string(icons::kSave) + "  Save", false))
    save_trainer_file(state, state.trainer_file_path);

  if (ImGui::CollapsingHeader("Batchcode import")) {
    ImGui::InputTextMultiline("##MobileBatchcode", state.batchcode_text,
                              sizeof(state.batchcode_text),
                              ImVec2(-1.0f, 112.0f * scl));
    ImGui::BeginDisabled(!has_pid);
    if (mobile_action_button(std::string(icons::kImport) + "  Import",
                             false)) {
      mobile_import_batchcode(state);
    }
    ImGui::EndDisabled();
  }

  draw_mobile_section_label("Runtime list");
  if (state.cheats.empty()) {
    ImGui::TextColored(palette.dim, "%s", "No trainer entries");
  } else {
    ImGui::BeginDisabled(!connected || client_async_busy(state));
    if (mobile_action_button(std::string(icons::kPlay) + "  Apply enabled",
                             true)) {
      mobile_apply_enabled_cheats(state);
    }
    ImGui::EndDisabled();
    if (mobile_action_button(std::string(icons::kTrash) +
                                 "  Clear disabled",
                             false)) {
      state.cheats.erase(
          std::remove_if(state.cheats.begin(), state.cheats.end(),
                         [](const CheatEntry &cheat) {
                           return !cheat.enabled;
                         }),
          state.cheats.end());
      set_status(state, "Disabled trainer entries cleared");
    }

    size_t remove_index = std::numeric_limits<size_t>::max();
    for (size_t i = 0; i < state.cheats.size(); ++i) {
      CheatEntry &cheat = state.cheats[i];
      ImGui::PushID(static_cast<int>(i));
      ImGui::BeginChild("MobileTrainerCheatCard", ImVec2(0, 152.0f * scl),
                        true, ImGuiWindowFlags_NoScrollbar);
      ImGui::Checkbox("##enabled", &cheat.enabled);
      ImGui::SameLine();
      text_ellipsis(cheat.description.c_str(),
                    ImGui::GetContentRegionAvail().x, palette.text);
      ImGui::TextColored(palette.dim, "%s | %s | PID %d",
                         hex_u64(cheat.address).c_str(),
                         value_type_name(cheat.value_type), cheat.pid);
      text_ellipsis(("Value " + cheat.value_text).c_str(),
                    ImGui::GetContentRegionAvail().x, palette.muted);
      ImGui::Checkbox("Lock", &cheat.locked);
      ImGui::SameLine();
      ImGui::TextColored(cheat.active ? palette.success : palette.dim, "%s",
                         cheat.active ? "Active" : "Idle");

      const float gap = 6.0f * scl;
      const float button_w =
          (ImGui::GetContentRegionAvail().x - gap * 3.0f) / 4.0f;
      ImGui::BeginDisabled(!connected || client_async_busy(state));
      if (ui::primary_button("ON", ImVec2(button_w, 34.0f * scl))) {
        if (mobile_apply_cheat(state, cheat)) set_status(state, cheat.status);
      }
      ImGui::SameLine(0, gap);
      ImGui::BeginDisabled(!cheat.has_off_bytes);
      if (ui::soft_button("OFF", ImVec2(button_w, 34.0f * scl))) {
        if (mobile_deactivate_cheat(state, cheat))
          set_status(state, cheat.status);
      }
      ImGui::EndDisabled();
      ImGui::SameLine(0, gap);
      if (ui::soft_button("CAP", ImVec2(button_w, 34.0f * scl))) {
        if (capture_off_value(state, cheat)) set_status(state, cheat.status);
      }
      ImGui::EndDisabled();
      ImGui::SameLine(0, gap);
      if (ui::danger_button("DEL", ImVec2(button_w, 34.0f * scl)))
        remove_index = i;

      if (!cheat.status.empty())
        text_ellipsis(cheat.status.c_str(), ImGui::GetContentRegionAvail().x,
                      palette.dim);
      ImGui::EndChild();
      ImGui::PopID();
    }
    if (remove_index != std::numeric_limits<size_t>::max() &&
        remove_index < state.cheats.size()) {
      state.cheats.erase(state.cheats.begin() +
                         static_cast<std::ptrdiff_t>(remove_index));
      set_status(state, "Trainer entry removed");
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static void draw_mobile_credits(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  ImGui::BeginChild("MobileCredits", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "MemDBG");
  ImGui::TextColored(palette.muted, "%s",
                     "PlayStation Memory Debugger");

  ImGui::BeginChild("MobileCreditsCard", ImVec2(0, 132.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Version", std::string("v") + MEMDBG_VERSION_STRING,
                  palette.text);
  mobile_info_row("Creator", "Seregon (@seregonwar)", palette.text);
  mobile_info_row("License", "GNU GPL v3.0 or later", palette.muted);
  mobile_info_row("Profile",
                  state.github_profile.error.empty()
                      ? state.github_profile.login
                      : state.github_profile.error,
                  state.github_profile.error.empty() ? palette.link
                                                     : palette.warning);
  ImGui::EndChild();

  if (mobile_action_button(std::string(icons::kLink) + "  GitHub", false))
    set_status(state, "GitHub profile: https://github.com/seregonwar");
  if (mobile_action_button(std::string(icons::kCredits) + "  Donations",
                           false))
    set_status(state, "Donations link is available in the desktop credits");
  if (mobile_action_button("X / SeregonWar", false))
    set_status(state, "X profile: SeregonWar");
  if (mobile_action_button("Bluesky", false))
    set_status(state, "Bluesky profile selected");

  draw_mobile_section_label("Project");
  ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                         ImGui::GetContentRegionAvail().x);
  ImGui::TextWrapped(
      "%s",
      "MemDBG combines memory scanning, remote debugging, trainer workflows, "
      "plugins, UDP logs, telemetry, and console session tools for PS4 and "
      "PS5 homebrew research.");
  ImGui::PopTextWrapPos();
  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static void draw_mobile_fallback(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  ImGui::BeginChild("MobileFallback", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", screen_title(state.screen));
  ImGui::TextWrapped("%s", screen_subtitle(state.screen));
  ImGui::Spacing();
  ImGui::BeginChild("MobileFallbackCard", ImVec2(0, 150.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Session",
                  state.client.connected() ? "Connected" : "Offline",
                  state.client.connected() ? palette.success : palette.dim);
  mobile_info_row("Process", selected_process_name(state),
                  state.selected_pid > 0 ? palette.text : palette.dim);
  mobile_info_row("Status", state.status, palette.muted);
  ImGui::EndChild();

  if (mobile_action_button(std::string(icons::kConsole) + "  Console",
                           false))
    state.screen = Screen::Consoles;
  if (mobile_action_button(std::string(icons::kScanner) + "  Scanner",
                           false))
    state.screen = Screen::Scanner;
  if (mobile_action_button(std::string(icons::kTrainer) + "  Trainer",
                           false))
    state.screen = Screen::Trainer;
  if (mobile_action_button(std::string(icons::kPlugins) + "  Plugins",
                           false))
    state.screen = Screen::Plugins;

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static void draw_mobile_processes(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const ImVec4 selected_bg(32.0f / 255.0f, 58.0f / 255.0f,
                           45.0f / 255.0f, 1.0f);

  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(12.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::BeginChild("MobileProcesses", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);

  ImGui::TextColored(palette.primary2, "%s", "Processes");
  ImGui::SameLine();
  ui::status_dot(connected ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(connected ? palette.muted : palette.danger, "%s",
                     connected ? "Select a target PID" : "Offline");

  ImGui::BeginChild("MobileProcessSummary", ImVec2(0, 154.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Session", connected ? "Connected" : "Offline",
                  connected ? palette.success : palette.dim);
  mobile_info_row("Process", selected_process_name(state),
                  state.selected_pid > 0 ? palette.text : palette.dim);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  state.selected_pid > 0 ? palette.text : palette.dim);
  mobile_info_row("Maps", std::to_string(state.maps.size()),
                  state.maps.empty() ? palette.dim : palette.text);
  ImGui::Separator();
  text_ellipsis(state.status, ImGui::GetContentRegionAvail().x, palette.muted);
  ImGui::EndChild();

  if (!connected) {
    if (mobile_action_button(std::string(icons::kConsole) +
                                 "  Configure console",
                             true))
      state.screen = Screen::Consoles;
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    return;
  }

  ImGui::BeginDisabled(client_async_busy(state));
  if (mobile_action_button(std::string(icons::kRefresh) +
                               "  Refresh processes",
                           state.processes.empty()))
    topbar_refresh_processes(state);
  ImGui::EndDisabled();

  ImGui::BeginDisabled(client_async_busy(state) || state.selected_pid <= 0);
  if (mobile_action_button(std::string(icons::kMemory) + "  Load maps",
                           state.maps.empty()))
    topbar_refresh_maps(state);
  ImGui::EndDisabled();

  if (state.selected_pid > 0) {
    ImGui::BeginChild("MobileProcessQuickActions", ImVec2(0, 96.0f * scl),
                      true, ImGuiWindowFlags_NoScrollbar);
    if (ImGui::BeginTable("MobileProcessQuickActionTable", 2,
                          ImGuiTableFlags_SizingStretchSame)) {
      ImGui::TableNextColumn();
      if (mobile_action_button(std::string(icons::kScanner) + "  Scanner",
                               false))
        state.screen = Screen::Scanner;
      ImGui::TableNextColumn();
      if (mobile_action_button(std::string(icons::kTrainer) + "  Trainer",
                               false))
        state.screen = Screen::Trainer;
      ImGui::EndTable();
    }
    ImGui::EndChild();
  }

  draw_mobile_section_label("Process list");
  if (state.processes.empty()) {
    ImGui::BeginChild("MobileNoProcesses", ImVec2(0, 92.0f * scl), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextColored(palette.muted, "%s", "No processes loaded");
    ImGui::TextWrapped("%s",
                       "Refresh the process list after connecting a console.");
    ImGui::EndChild();
  } else {
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const ProcessEntry &process = state.processes[i];
      const bool selected = process.pid == state.selected_pid;
      ImGui::PushID(i);
      ImGui::PushStyleColor(ImGuiCol_ChildBg,
                            selected ? selected_bg : palette.bg1);
      ImGui::BeginChild("MobileProcessCard", ImVec2(0, 66.0f * scl), true,
                        ImGuiWindowFlags_NoScrollbar);
      const ImVec2 text_pos = ImGui::GetCursorScreenPos();
      const ImVec2 hit_size(ImGui::GetContentRegionAvail().x, 48.0f * scl);
      ImGui::InvisibleButton("##select_process", hit_size);
      const bool clicked = ImGui::IsItemClicked();
      if (selected) {
        ImDrawList *dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(text_pos,
                          ImVec2(text_pos.x + 3.0f * scl,
                                 text_pos.y + hit_size.y),
                          ui::color_u32(palette.primary2), 2.0f * scl);
      }
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y));
      const std::string process_name =
          process.name.empty() ? "unnamed" : process.name;
      text_ellipsis(process_name.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.text);
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y + 24.0f * scl));
      ImGui::TextColored(selected ? palette.primary2 : palette.muted,
                         "PID %d", process.pid);
      ImGui::EndChild();
      ImGui::PopStyleColor();
      ImGui::PopID();
      if (clicked) topbar_select_process(state, i);
    }
  }

  draw_mobile_section_label("Memory maps");
  if (state.selected_pid <= 0) {
    ImGui::BeginChild("MobileMapsNoProcess", ImVec2(0, 86.0f * scl), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextColored(palette.muted, "%s", "Select a process first");
    ImGui::TextWrapped("%s",
                       "Maps become scan ranges and trainer safety checks.");
    ImGui::EndChild();
  } else if (state.maps.empty()) {
    ImGui::BeginChild("MobileNoMaps", ImVec2(0, 86.0f * scl), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextColored(palette.muted, "%s", "No maps loaded");
    ImGui::TextWrapped("%s",
                       "Load maps to pick a touch-friendly scan range.");
    ImGui::EndChild();
  } else {
    for (int i = 0; i < static_cast<int>(state.maps.size()); ++i) {
      const MapEntry &map = state.maps[i];
      const bool selected = i == state.selected_map_row;
      const uint64_t size_bytes = map.end > map.start ? map.end - map.start : 0;
      ImGui::PushID(10000 + i);
      ImGui::PushStyleColor(ImGuiCol_ChildBg,
                            selected ? selected_bg : palette.bg1);
      ImGui::BeginChild("MobileMapCard", ImVec2(0, 76.0f * scl), true,
                        ImGuiWindowFlags_NoScrollbar);
      const ImVec2 text_pos = ImGui::GetCursorScreenPos();
      const ImVec2 hit_size(ImGui::GetContentRegionAvail().x, 58.0f * scl);
      ImGui::InvisibleButton("##select_map", hit_size);
      const bool clicked = ImGui::IsItemClicked();
      if (selected) {
        ImDrawList *dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(text_pos,
                          ImVec2(text_pos.x + 3.0f * scl,
                                 text_pos.y + hit_size.y),
                          ui::color_u32(palette.primary2), 2.0f * scl);
      }
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y));
      const std::string title = hex_u64(map.start) + "  " +
                                prot_text(map.protection) + "  " +
                                mobile_format_bytes(size_bytes);
      text_ellipsis(title.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.text);
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y + 25.0f * scl));
      const std::string map_name =
          map.name.empty() ? "anonymous mapping" : map.name;
      text_ellipsis(map_name.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.muted);
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y + 47.0f * scl));
      const std::string map_end = hex_u64(map.end);
      text_ellipsis(map_end.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.dim);
      ImGui::EndChild();
      ImGui::PopStyleColor();
      ImGui::PopID();
      if (clicked) mobile_select_map(state, i);
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
  ImGui::PopStyleVar(2);
}

static void draw_mobile_session(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();

  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(12.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::BeginChild("MobileSession", size, false);

  ImGui::TextColored(palette.primary2, "%s", "Session");
  ImGui::SameLine();
  ui::status_dot(state.connect_pending ? palette.warning :
                 connected ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(state.connect_pending ? palette.warning :
                     connected ? palette.success : palette.danger,
                     "%s", state.connect_pending ? "Connecting" :
                          connected ? "Connected" : "Not connected");

  ImGui::Spacing();
  ImGui::BeginChild("MobileSessionCard", ImVec2(0, 154.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  char endpoint[96];
  std::snprintf(endpoint, sizeof(endpoint), "%s:%d", state.host,
                state.debug_port);
  mobile_info_row("Endpoint", endpoint,
                  connected ? palette.text : palette.muted);
  mobile_info_row("UDP", state.udp_listener.running() ? "Listening" : "Stopped",
                  state.udp_listener.running() ? palette.success : palette.dim);
  mobile_info_row("Process", selected_process_name(state),
                  state.selected_pid != 0 ? palette.text : palette.muted);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  state.selected_pid != 0 ? palette.text : palette.dim);
  ImGui::Separator();
  text_ellipsis(state.status, ImGui::GetContentRegionAvail().x, palette.muted);
  ImGui::EndChild();

  ImGui::BeginDisabled(client_async_busy(state) || state.connect_pending);
  if (connected) {
    if (ui::soft_button((std::string(icons::kGauge) + "  Ping").c_str(),
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               42.0f * scl))) {
      set_status(state, state.client.ping() ? "Ping OK"
                                            : state.client.last_error());
    }
    if (ui::danger_button((std::string(icons::kDisconnect) +
                           "  Disconnect").c_str(),
                          ImVec2(ImGui::GetContentRegionAvail().x,
                                 42.0f * scl))) {
      disconnect_console(state);
    }
  } else {
    if (ui::primary_button((std::string(icons::kConsole) +
                            "  Configure console").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  44.0f * scl))) {
      state.screen = Screen::Consoles;
    }
    if (ui::soft_button((std::string(icons::kConnect) +
                         "  Connect").c_str(),
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               42.0f * scl))) {
      connect_console(state);
    }
  }
  ImGui::EndDisabled();

  ImGui::Spacing();
  ImGui::TextColored(palette.muted, "%s", "Workflows");
  if (mobile_nav_button("MobileNavConsole", icons::kConsole, "Console", true))
    state.screen = Screen::Consoles;
  if (mobile_nav_button("MobileNavProcesses", icons::kProcess, "Processes",
                        connected))
    state.screen = Screen::Processes;
  if (mobile_nav_button("MobileNavScanner", icons::kScanner, "Scanner",
                        connected))
    state.screen = Screen::Scanner;
  if (mobile_nav_button("MobileNavTrainer", icons::kTrainer, "Trainer",
                        connected))
    state.screen = Screen::Trainer;
  if (mobile_nav_button("MobileNavPlugins", icons::kPlugins, "Plugins", true))
    state.screen = Screen::Plugins;
  if (mobile_nav_button("MobileNavLogs", icons::kLogs, "Logs", true))
    state.screen = Screen::Logs;

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
}

static void draw_mobile_top_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(10.0f * ui::dpi_scale(), 6.0f * ui::dpi_scale()));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(6.0f * ui::dpi_scale(), 0));
  ImGui::BeginChild("MobileTopBar", size, true, ImGuiWindowFlags_NoScrollbar);

  const float scl = ui::dpi_scale();
  const float topbar_w = ImGui::GetWindowWidth();
  const float bar_h = size.y;
  const bool connected = state.client.connected();

  ImGui::SetCursorPosY((bar_h - ImGui::GetFontSize()) * 0.5f);
  ImGui::TextColored(ui::colors().primary2, "%s", "MemDBG");
  ImGui::SameLine();
  ui::status_dot(state.connect_pending ? ui::colors().warning :
                 connected ? ui::colors().success : ui::colors().dim);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().muted, "%s",
                     connected ? "Online" : "Offline");

  const float btn_h = std::max(34.0f * scl, bar_h - 12.0f * scl);
  const float btn_w = connected ? btn_h : std::min(126.0f * scl,
                                                   topbar_w * 0.38f);
  ImGui::SetCursorPos(ImVec2(topbar_w - btn_w - 8.0f * scl,
                             (bar_h - btn_h) * 0.5f));
  ImGui::BeginDisabled(client_async_busy(state));
  if (connected) {
    if (ui::danger_button((std::string(icons::kDisconnect)).c_str(),
                          ImVec2(btn_w, btn_h))) {
      disconnect_console(state);
    }
  } else {
    if (ui::primary_button((std::string(icons::kConsole) +
                            "  Setup").c_str(),
                           ImVec2(btn_w, btn_h))) {
      state.screen = Screen::Consoles;
    }
  }
  ImGui::EndDisabled();

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

static void draw_mobile_tools_sheet(AppState &state, ImVec2 tab_pos,
                                    ImVec2 tab_size) {
  if (!s_mobile_tools_open) return;

  const float scl = ui::dpi_scale();
  ImGuiViewport *viewport = ImGui::GetMainViewport();
  const float safe_top = viewport->WorkPos.y + s_mobile_safe_area.top;
  const float max_h = std::max(220.0f * scl, tab_pos.y - safe_top - 12.0f * scl);
  const float sheet_h = std::min(430.0f * scl, max_h);
  const ImVec2 pos(tab_pos.x + 8.0f * scl,
                   std::max(safe_top + 8.0f * scl,
                            tab_pos.y - sheet_h - 8.0f * scl));
  const ImVec2 size(std::max(220.0f * scl, tab_size.x - 16.0f * scl),
                    sheet_h);

  ImGui::SetNextWindowPos(pos);
  ImGui::SetNextWindowSize(size);
  ImGui::PushStyleColor(ImGuiCol_WindowBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(10.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 6.0f * scl);
  ImGui::Begin("##MobileToolSheet", &s_mobile_tools_open,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                   ImGuiWindowFlags_NoSavedSettings |
                   ImGuiWindowFlags_NoResize);

  ImGui::TextColored(ui::colors().primary2, "%s  Tools", icons::kMore);
  ImGui::SameLine(ImGui::GetWindowWidth() - 72.0f * scl);
  if (ui::soft_button("Close", ImVec2(62.0f * scl, 30.0f * scl)))
    s_mobile_tools_open = false;
  ImGui::Separator();

  struct ToolEntry {
    Screen screen;
    const char *icon;
    const char *label;
  };
  const ToolEntry tools[] = {
      {Screen::Home, icons::kHome, "Home"},
      {Screen::Consoles, icons::kConsole, "Console"},
      {Screen::Processes, icons::kProcess, "Processes"},
      {Screen::Scanner, icons::kScanner, "Scanner"},
      {Screen::Trainer, icons::kTrainer, "Trainer"},
      {Screen::Plugins, icons::kPlugins, "Plugins"},
      {Screen::Logs, icons::kLogs, "Logs"},
      {Screen::Credits, icons::kCredits, "Credits"},
  };

  if (ImGui::BeginTable("MobileToolGrid", 2,
                        ImGuiTableFlags_SizingStretchSame |
                            ImGuiTableFlags_PadOuterX)) {
    for (const ToolEntry &tool : tools) {
      ImGui::TableNextColumn();
      const bool selected = state.screen == tool.screen;
      std::string label = std::string(tool.icon) + "  " + tool.label;
      const bool clicked =
          selected ? ui::primary_button(label.c_str(),
                                        ImVec2(-1.0f, 44.0f * scl))
                   : ui::soft_button(label.c_str(),
                                     ImVec2(-1.0f, 44.0f * scl));
      if (clicked) {
        state.screen = tool.screen;
        s_mobile_tools_open = false;
      }
    }
    ImGui::EndTable();
  }

  ImGui::End();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

static void draw_bottom_tab_bar(AppState &state, ImVec2 pos, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
  ImGui::SetNextWindowPos(pos);
  ImGui::SetNextWindowSize(size);
  ImGui::Begin("##MobileTabBar", nullptr,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
               ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar |
               ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

  const float tab_w = size.x / 6.0f;
  const float tab_h = size.y;

  struct TabEntry {
    Screen screen;
    const char *icon;
  };
  static const TabEntry tabs[] = {
    { Screen::Home,     icons::kHome },
    { Screen::Consoles, icons::kConsole },
    { Screen::Processes, icons::kProcess },
    { Screen::Scanner,  icons::kScanner },
    { Screen::Trainer,  icons::kTrainer },
  };

  ImDrawList *dl = ImGui::GetWindowDrawList();

  for (int i = 0; i < 5; ++i) {
    const ImVec2 tab_min(pos.x + tab_w * i, pos.y);
    const ImVec2 tab_max(pos.x + tab_w * (i + 1), pos.y + tab_h);
    const bool selected = state.screen == tabs[i].screen;

    /* Background for selected tab */
    if (selected) {
      ImVec4 bg(32.0f/255.0f, 58.0f/255.0f, 45.0f/255.0f, 1.0f);
      dl->AddRectFilled(tab_min, tab_max, ui::color_u32(bg));
      /* Top accent line */
      dl->AddRectFilled(ImVec2(tab_min.x + 8.0f, tab_min.y),
                        ImVec2(tab_max.x - 8.0f, tab_min.y + 2.0f),
                        ui::color_u32(ui::colors().primary2), 1.0f);
    }

    /* Icon centered */
    const ImVec4 icon_col = selected ? ui::colors().primary2 : ui::colors().muted;
    const ImVec2 icon_size = ImGui::CalcTextSize(tabs[i].icon);
    const float icon_x = tab_min.x + (tab_w - icon_size.x) * 0.5f;
    const float icon_y = tab_min.y + (tab_h - icon_size.y) * 0.5f;
    dl->AddText(ImVec2(icon_x, icon_y), ui::color_u32(icon_col), tabs[i].icon);

    /* Hit target */
    ImGui::SetCursorPos(ImVec2(tab_w * i, 0));
    ImGui::InvisibleButton(("##tab" + std::to_string(i)).c_str(), ImVec2(tab_w, tab_h));
    if (ImGui::IsItemClicked()) state.screen = tabs[i].screen;
  }

  /* 6th tab: overflow menu */
  {
    const ImVec2 tab_min(pos.x + tab_w * 5, pos.y);
    const ImVec2 tab_max(pos.x + tab_w * 6, pos.y + tab_h);
    const bool is_overflow_active =
        state.screen == Screen::Plugins || state.screen == Screen::Logs ||
        state.screen == Screen::Credits || state.screen == Screen::PluginGUI;

    if (is_overflow_active) {
      ImVec4 bg(32.0f/255.0f, 58.0f/255.0f, 45.0f/255.0f, 1.0f);
      dl->AddRectFilled(tab_min, tab_max, ui::color_u32(bg));
      dl->AddRectFilled(ImVec2(tab_min.x + 8.0f, tab_min.y),
                        ImVec2(tab_max.x - 8.0f, tab_min.y + 2.0f),
                        ui::color_u32(ui::colors().primary2), 1.0f);
    }

    const ImVec4 icon_col = is_overflow_active ? ui::colors().primary2 : ui::colors().muted;
    const ImVec2 icon_size = ImGui::CalcTextSize(icons::kMore);
    const float icon_x = tab_min.x + (tab_w - icon_size.x) * 0.5f;
    const float icon_y = tab_min.y + (tab_h - icon_size.y) * 0.5f;
    dl->AddText(ImVec2(icon_x, icon_y), ui::color_u32(icon_col), icons::kMore);

    ImGui::SetCursorPos(ImVec2(tab_w * 5, 0));
    if (ImGui::InvisibleButton("##tab_more", ImVec2(tab_w, tab_h))) {
      s_mobile_tools_open = !s_mobile_tools_open;
    }
  }

  ImGui::End();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
  draw_mobile_tools_sheet(state, pos, size);
}

static void draw_mobile_status_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(10.0f * ui::dpi_scale(), 3.0f * ui::dpi_scale()));
  ImGui::BeginChild("MobileStatusBar", size, true, ImGuiWindowFlags_NoScrollbar);

  const bool connected = state.client.connected();
  ui::status_dot(connected ? ui::colors().success : ui::colors().muted);
  ImGui::SameLine();

  float avail_w = ImGui::GetWindowWidth() - 28.0f * ui::dpi_scale();
  if (avail_w < 60.0f) avail_w = 60.0f;
  text_ellipsis(state.status, avail_w, ui::colors().text);

  ImGui::EndChild();
  ImGui::PopStyleVar();
  ImGui::PopStyleColor();
}

static void draw_mobile_content(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                      ImVec2(10.0f * scl, 8.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ScrollbarSize, 18.0f * scl);

  if (state.screen == Screen::Home) {
    draw_mobile_session(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Consoles) {
    draw_mobile_network(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Processes) {
    draw_mobile_processes(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Plugins || state.screen == Screen::PluginGUI) {
    draw_mobile_plugins(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Logs) {
    draw_mobile_logs(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Scanner) {
    draw_mobile_scanner(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Trainer) {
    draw_mobile_trainer(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Credits) {
    draw_mobile_credits(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  draw_mobile_fallback(state, size);
  ImGui::PopStyleVar(3);
}

void draw_mobile_app(AppState &state) {
  poll_locale_repository(state);
  poll_connect(state);
  poll_taskmgr_prefetch(state);
  poll_telemetry(state);
  poll_map_refresh(state);
  poll_tracer(state);
  poll_plugin_tasks(state);
  poll_session_health(state);

  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);

  ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                           ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
  ImGui::Begin("MemDBG Mobile", nullptr, flags);

  ImVec2 win_pos = ImGui::GetWindowPos(), win_size = ImGui::GetWindowSize();
  ui::draw_background(ImGui::GetWindowDrawList(), win_pos, win_size);

  const float scl = ui::dpi_scale();
  const float left = s_mobile_safe_area.left;
  const float top = s_mobile_safe_area.top;
  const float right = s_mobile_safe_area.right;
  const float bottom = s_mobile_safe_area.bottom;
  const float layout_x = left;
  const float layout_w = std::max(240.0f * scl, win_size.x - left - right);
  const float top_h = 48.0f * scl;
  const float status_h = 26.0f * scl;
  const float tab_h = 54.0f * scl;
  const float gap = 6.0f * scl;
  const float content_pad = 8.0f * scl;
  const float bottom_edge = win_size.y - bottom;
  const float tab_y = bottom_edge - tab_h;
  const float status_y = tab_y - status_h;
  const float content_y = top + top_h + gap;
  const float content_h = std::max(120.0f * scl, status_y - content_y - gap);

  ImGui::SetCursorPos(ImVec2(layout_x, top));
  draw_mobile_top_bar(state, ImVec2(layout_w, top_h));

  ImGui::SetCursorPos(ImVec2(layout_x + content_pad, content_y));
  draw_mobile_content(state,
                      ImVec2(std::max(120.0f * scl,
                                      layout_w - content_pad * 2.0f),
                             content_h));

  ImGui::SetCursorPos(ImVec2(layout_x, status_y));
  draw_mobile_status_bar(state, ImVec2(layout_w, status_h));

  draw_bottom_tab_bar(state,
     ImVec2(win_pos.x + layout_x, win_pos.y + tab_y),
     ImVec2(layout_w, tab_h));

  s_notification_bottom_reserved = bottom + tab_h + status_h + 8.0f * scl;
  draw_notifications(state);
  draw_connect_spinner(state);

  ImGui::End();
}

/* ---- Main app draw ---- */

void draw_app(AppState &state) {
  poll_locale_repository(state);
  poll_connect(state);
  poll_taskmgr_prefetch(state);
  poll_telemetry(state);
  poll_map_refresh(state);
  poll_tracer(state);
  poll_plugin_tasks(state);
  poll_session_health(state);
  handle_global_shortcuts(state);

  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);

  ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|
                           ImGuiWindowFlags_NoSavedSettings|ImGuiWindowFlags_NoBringToFrontOnFocus;
  ImGui::Begin("MemDBG Shell", nullptr, flags);

  ImVec2 win_pos = ImGui::GetWindowPos(), win_size = ImGui::GetWindowSize();
  ui::draw_background(ImGui::GetWindowDrawList(), win_pos, win_size);

  const float scl = ui::dpi_scale();
  const float sidebar_w = std::clamp(win_size.x * 0.15f, 160.0f * scl, 224.0f * scl);
  const float top_h = 46.0f * scl;
  const float status_h = 26.0f * scl;
  const float gap = 6.0f * scl;
  const float content_h = win_size.y - top_h - status_h;
  const float content_w = win_size.x - sidebar_w;

  ImGui::SetCursorPos(ImVec2(0,0));
  draw_top_bar(state, ImVec2(win_size.x, top_h));
  ImGui::SetCursorPos(ImVec2(0, top_h));
  draw_sidebar(state, ImVec2(sidebar_w, content_h));
  ImGui::SetCursorPos(ImVec2(sidebar_w+gap, top_h+gap));
  draw_screen(state, ImVec2(content_w-(gap*2.0f), content_h-(gap*2.0f)));
  ImGui::SetCursorPos(ImVec2(0, win_size.y-status_h));
  draw_status_bar(state, ImVec2(win_size.x, status_h));

  s_notification_bottom_reserved = 0.0f;
  draw_notifications(state);
  draw_connect_spinner(state);

  // Capture console-side UDP logs into the crash logger
  if (state.crash_logging_enabled && state.udp_listener.running()) {
    state.crash_logger.capture_console_lines(
        state.udp_listener.snapshot(),
        state.crash_udp_last_received,
        state.udp_listener.stats().received);
  }

  ImGui::End();
}

/* ---- Entry point ---- */

static bool readable_file(const char *path) {
  FILE *file = std::fopen(path, "rb");
  if (!file) return false;
  std::fclose(file);
  return true;
}

static void setup_fonts(ImGuiIO &io, float dpi_scale) {
  const float base_text_size = 16.0f;
  const float text_size = std::roundf(base_text_size * dpi_scale);

  // Build comprehensive glyph ranges: Default + Cyrillic
  ImFontGlyphRangesBuilder ranges_builder;
  ranges_builder.AddRanges(io.Fonts->GetGlyphRangesDefault());
  ranges_builder.AddRanges(io.Fonts->GetGlyphRangesCyrillic());
  ImVector<ImWchar> glyph_ranges;
  ranges_builder.BuildRanges(&glyph_ranges);

  ImFontConfig base_cfg;
  base_cfg.OversampleH = 3;
  base_cfg.OversampleV = 2;
  base_cfg.PixelSnapH = false;
  base_cfg.RasterizerMultiply = 1.08f;
  base_cfg.GlyphRanges = glyph_ranges.Data;

  bool loaded_base = false;
  static const char *font_candidates[] = {
#if defined(__APPLE__)
    "/System/Library/Fonts/SFNS.ttf",
    "/System/Library/Fonts/HelveticaNeue.ttc",
    "/System/Library/Fonts/Avenir Next.ttc",
#elif defined(_WIN32)
    "C:\\Windows\\Fonts\\segoeui.ttf",
    "C:\\Windows\\Fonts\\arial.ttf",
#else
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
#endif
  };

  for (const char *path : font_candidates) {
    if (!readable_file(path)) continue;
    if (io.Fonts->AddFontFromFileTTF(path, text_size, &base_cfg)) {
      loaded_base = true;
      break;
    }
  }

  if (!loaded_base) {
    ImFontConfig fallback_cfg;
    fallback_cfg.SizePixels = text_size;
    fallback_cfg.OversampleH = 3;
    fallback_cfg.OversampleV = 2;
    fallback_cfg.RasterizerMultiply = 1.08f;
    fallback_cfg.GlyphRanges = glyph_ranges.Data;
    io.Fonts->AddFontDefault(&fallback_cfg);
  }

  // CJK fallback font for Japanese (Hiragana, Katakana, common Kanji)
  {
    ImFontConfig cjk_cfg;
    cjk_cfg.MergeMode = true;
    cjk_cfg.OversampleH = 2;
    cjk_cfg.OversampleV = 1;
    cjk_cfg.PixelSnapH = true;
    cjk_cfg.GlyphRanges = io.Fonts->GetGlyphRangesJapanese();

    static const char *cjk_candidates[] = {
#if defined(__APPLE__)
      "/System/Library/Fonts/AppleSDGothicNeo.ttc",
      "/System/Library/Fonts/Hiragino Sans GB.ttc",
      "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
#elif defined(_WIN32)
      "C:\\Windows\\Fonts\\YuGothR.ttc",
      "C:\\Windows\\Fonts\\YuGothM.ttc",
      "C:\\Windows\\Fonts\\YuGothB.ttc",
      "C:\\Windows\\Fonts\\meiryo.ttc",
      "C:\\Windows\\Fonts\\meiryob.ttc",
      "C:\\Windows\\Fonts\\msgothic.ttc",
      "C:\\Windows\\Fonts\\msmincho.ttc",
      "C:\\Windows\\Fonts\\malgun.ttf",
      "C:\\Windows\\Fonts\\msyh.ttc",
      "C:\\Windows\\Fonts\\simsun.ttc",
      "C:\\Windows\\Fonts\\arialuni.ttf",
#else
      "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
      "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
      "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
#endif
    };

    bool loaded_cjk = false;
    for (const char *path : cjk_candidates) {
      if (!readable_file(path)) continue;
      if (io.Fonts->AddFontFromFileTTF(path, text_size, &cjk_cfg)) {
        loaded_cjk = true;
        break;
      }
    }
    (void)loaded_cjk;  // best-effort; UI degrades gracefully without CJK font
  }

  const float icon_size = std::roundf(15.0f * dpi_scale);
  ImFontConfig icon_cfg;
  icon_cfg.MergeMode = true;
  icon_cfg.FontDataOwnedByAtlas = false;
  icon_cfg.PixelSnapH = true;
  icon_cfg.GlyphMinAdvanceX = std::roundf(16.0f * dpi_scale);
  icon_cfg.GlyphOffset = ImVec2(0.0f, 1.0f * dpi_scale);
  static const ImWchar icon_ranges[] = { 0xF000, 0xF8FF, 0 };
  io.Fonts->AddFontFromMemoryTTF(
      fa_solid_900, (int)fa_solid_900_len,
      icon_size, &icon_cfg, icon_ranges);

  ImFontConfig brand_cfg;
  brand_cfg.MergeMode = true;
  brand_cfg.FontDataOwnedByAtlas = false;
  brand_cfg.PixelSnapH = true;
  brand_cfg.GlyphMinAdvanceX = std::roundf(16.0f * dpi_scale);
  brand_cfg.GlyphOffset = ImVec2(0.0f, 1.0f * dpi_scale);
  static const ImWchar brand_ranges[] = { 0xE000, 0xF8FF, 0 };
  io.Fonts->AddFontFromMemoryTTF(
      fa_brands_400, (int)fa_brands_400_len,
      icon_size, &brand_cfg, brand_ranges);
  io.Fonts->Build();
}

void init_app_shared(AppState &state, float dpi_scale) {
#if !defined(_WIN32)
  signal(SIGPIPE, SIG_IGN);
#endif
  ImGuiIO &io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.FontGlobalScale = 1.0f;
  io.FontAllowUserScaling = false;
  io.ConfigWindowsMoveFromTitleBarOnly = true;
  ui::set_dpi_scale(dpi_scale);
  ui::apply_theme();

  setup_fonts(io, dpi_scale);
  ImGui::GetStyle().ScaleAllSizes(dpi_scale);

  state.plugin_manager.set_bundle_root(s_executable_dir);
  {
    std::string plugin_error;
    if (!state.plugin_manager.load(&plugin_error) && !plugin_error.empty()) {
      set_status(state, plugin_error);
    }
  }

  // Open crash logger in the executable directory
  try {
    std::filesystem::path log_path = s_executable_dir.empty()
        ? std::filesystem::path("memdbg_crash.log")
        : s_executable_dir / "memdbg_crash.log";
    state.crash_logger.open(log_path.string().c_str());
  } catch (...) {
    // crash logger failure is non-fatal
  }

  bool settings_loaded = false;
  {
    std::string config_error;
    settings_loaded = load_frontend_settings(state, &config_error);
    if (settings_loaded && config_error.empty()) {
      set_status(state, "Settings loaded");
    } else if (!config_error.empty()) {
      if (state.crash_logging_enabled)
        state.crash_logger.log("error", ("Config load error: " + config_error).c_str());
      set_status(state, config_error);
    }
  }

  /* ---- ImGui ini from embedded data ---- */
  {
    using namespace memdbg::frontend::assets;
    if (kImGuiIniSize > 0) {
      io.IniFilename = nullptr;
      ImGui::LoadIniSettingsFromMemory(
          reinterpret_cast<const char *>(kImGuiIni),
          kImGuiIniSize);
    }
  }

  /* ---- Locale init ---- */
  locale::Manager &loc = locale::Manager::instance();
  locale::Repository &locale_repo = locale::Repository::instance();
  {
    using namespace memdbg::frontend::assets;
    for (size_t i = 0; i < kEmbeddedLocaleCount; ++i) {
      const auto &el = kEmbeddedLocales[i];
      (void)loc.load_mem(el.filename, el.data, el.size);
    }
  }
  locale_repo.preload_installed(loc);

  // Set language from saved preference, or auto-detect from OS.
  locale::Lang requested_lang = locale::Lang::EN;
  if (settings_loaded &&
      state.language >= 0 &&
      state.language < static_cast<int>(locale::Lang::COUNT)) {
    requested_lang = static_cast<locale::Lang>(state.language);
  } else {
    requested_lang = locale::detect_system_lang();
  }
  if (loc.set_active(requested_lang)) {
    state.language = static_cast<int>(requested_lang);
  } else {
    state.pending_language = static_cast<int>(requested_lang);
    state.language = static_cast<int>(locale::Lang::EN);
    (void)loc.set_active(locale::Lang::EN);
  }
  (void)locale_repo.start_startup_sync(requested_lang);
  github_profile_start(state.github_profile);
  release_check_start(state.release_check, MEMDBG_VERSION_STRING);
  {
    std::string udp_error;
    if (!ensure_udp_listener(state, udp_error))
      set_status(state, "UDP: " + udp_error);
  }

  if (state.crash_logging_enabled)
    state.crash_logger.log("startup", "MemDBG frontend started");

}

void shutdown_app_shared(AppState &state) {
  if (state.taskmgr_resource_future.valid()) state.taskmgr_resource_future.wait();
  state.taskmgr_resource_pending = false;
  if (state.taskmgr_prefetch_future.valid()) state.taskmgr_prefetch_future.wait();
  state.taskmgr_prefetch_pending = false;
  if (state.plugin_refresh_future.valid()) state.plugin_refresh_future.wait();
  state.plugin_refresh_pending = false;
  if (state.plugin_run_future.valid()) state.plugin_run_future.wait();
  state.plugin_run_pending = false;
  if (state.plugin_gui_bridge && state.plugin_gui_bridge->running())
    state.plugin_gui_bridge->stop();
  state.udp_listener.stop(); state.client.disconnect();
  release_check_shutdown(state.release_check);
  github_profile_shutdown(state.github_profile);
  locale::Repository::instance().shutdown();
  shutdown_texture(s_logo_texture);
  state.crash_logger.close();
}

#if !defined(MEMDBG_PLATFORM_IOS)
int run_frontend(int, char **argv) {
  init_executable_dir(argv != nullptr ? argv[0] : nullptr);
#if !defined(_WIN32)
  signal(SIGPIPE, SIG_IGN);
#endif
  if (!glfwInit()) return 1;

  glfwWindowHintString(GLFW_COCOA_FRAME_NAME, "MemDBG");

  float xscale = 1.0f, yscale = 1.0f;
  GLFWmonitor *monitor = glfwGetPrimaryMonitor();
  if (monitor) glfwGetMonitorContentScale(monitor, &xscale, &yscale);
  float raw_scale = std::max(xscale, yscale);
  if (raw_scale < 1.0f) raw_scale = 1.0f;

  // Keep the compact reference look by default (1.0x) and only nudge the
  // scale up gently for HiDPI monitors. Large high-res screens get a small
  // extra boost so the UI remains usable without becoming oversized.
  float dpi_scale = 1.0f + (raw_scale - 1.0f) * 0.15f;
  const GLFWvidmode *mode = monitor ? glfwGetVideoMode(monitor) : nullptr;
  if (mode) {
    float diag = std::sqrt(static_cast<float>(mode->width * mode->width +
                                              mode->height * mode->height));
    if (diag > 2200.0f) {
      dpi_scale *= 1.0f + (diag - 2200.0f) * 0.0001f;
    }
  }
  if (dpi_scale > 1.5f) dpi_scale = 1.5f;
#if defined(__APPLE__)
  const char *glsl_version = "#version 150";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3); glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
  const char *glsl_version = "#version 130";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3); glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif
  GLFWwindow *window = glfwCreateWindow(1400, 900, "MemDBG", nullptr, nullptr);
  if (!window) { glfwTerminate(); return 1; }
  set_window_icon(window);
  glfwMakeContextCurrent(window); glfwSwapInterval(1);

  auto state = std::make_unique<AppState>();
  IMGUI_CHECKVERSION(); ImGui::CreateContext();
  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init(glsl_version);
  init_app_shared(*state, dpi_scale);

  push_notification(*state, "MemDBG by seregonwar started", 6.0);

  /* Store pointers for the refresh callback (window-refresh fires during live resize on macOS).
   * Must be static so the non-capturing lambda below can access them. */
  static AppState *s_render_state = nullptr;
  static GLFWwindow *s_render_window = nullptr;
  s_render_state = state.get();
  s_render_window = window;

  /* Render a single frame. Callable from the main loop and from the window-refresh
   * callback (which fires during live resize on macOS).  The re-entrancy guard
   * wraps only glfwPollEvents() so the callback CAN produce a real frame — if the
   * callback fires while the main loop is inside PollEvents, it skips PollEvents
   * but still draws, matching the reference pattern for smooth live resize. */
  static const auto render_frame = []() {
    static bool in_poll = false;
    if (!in_poll) {
      in_poll = true;
      glfwPollEvents();
      in_poll = false;
    }
    poll_release_check(*s_render_state);

    if (glfwWindowShouldClose(s_render_window)) return;

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
    draw_app(*s_render_state);
    ImGui::Render();

    int dw, dh;
    glfwGetFramebufferSize(s_render_window, &dw, &dh);
    glViewport(0, 0, dw, dh);
    glClearColor(11.0f / 255.0f, 11.0f / 255.0f, 14.0f / 255.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(s_render_window);
  };

  glfwSetWindowRefreshCallback(window, [](GLFWwindow *) { render_frame(); });

  while (!glfwWindowShouldClose(window))
    render_frame();

  shutdown_app_shared(*state);
  ImGui_ImplOpenGL3_Shutdown(); ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext(); glfwDestroyWindow(window); glfwTerminate();
  s_render_state = nullptr;
  s_render_window = nullptr;
  return 0;
}
#endif // !MEMDBG_PLATFORM_IOS

} // namespace memdbg::frontend

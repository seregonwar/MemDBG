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
#include "platform.hpp"
#include "locale/locale.hpp"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <limits>
#include <string>
#include <vector>

#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif

#include "stb_image.h"

namespace memdbg::frontend {

namespace {

struct TextureAsset {
  GLuint texture = 0;
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

static ImTextureID texture_id(GLuint texture) {
  return reinterpret_cast<ImTextureID>(static_cast<intptr_t>(texture));
}

static void init_executable_dir(const char *argv0) {
  if (argv0 == nullptr || argv0[0] == '\0') return;

  std::error_code ec;
  std::filesystem::path path(argv0);
  if (path.is_relative()) {
    path = std::filesystem::current_path(ec) / path;
    ec.clear();
  }
  const std::filesystem::path canonical = std::filesystem::weakly_canonical(path, ec);
  if (!ec && !canonical.empty()) path = canonical;
  if (path.has_parent_path()) s_executable_dir = path.parent_path();
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
  if (asset.texture != 0U) return true;
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

  stbi_image_free(pixels);
  asset.texture = texture;
  return true;
}

static void shutdown_texture(TextureAsset &asset) {
  if (asset.texture != 0U) {
    GLuint texture = asset.texture;
    glDeleteTextures(1, &texture);
  }
  asset = TextureAsset{};
}

static void set_window_icon(GLFWwindow *window) {
#if defined(__APPLE__)
  (void)window;
#else
  if (window == nullptr) return;

  const std::filesystem::path path = find_asset_path("assets/app-icon.png");
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
#endif
}

} // namespace

/* ---- State helpers ---- */

void normalize_ports(AppState &state) {
  state.debug_port = std::clamp(state.debug_port, 1, 65535);
  state.udp_port    = std::clamp(state.udp_port, 1, 65535);
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
    } else    if (key == "dump_path" && !value.empty()) {
      std::snprintf(state.dump_path, sizeof(state.dump_path), "%s", value.c_str());
    } else if (key == "language") {
      state.language = static_cast<int>(locale::lang_from_code(value.c_str()));
    }
  }

  normalize_ports(state);
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
  out << "host=" << state.host << "\n";
  out << "debug_port=" << state.debug_port << "\n";
  out << "udp_port=" << state.udp_port << "\n";
  out << "dump_path=" << state.dump_path << "\n";
  out << "language=" << locale::lang_code(static_cast<locale::Lang>(state.language)) << "\n";
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
  std::string udp_error;
  std::string message = "Connected to console " + std::string(state.host) + ":" + std::to_string(state.debug_port);
  if (!ensure_udp_listener(state, udp_error)) message += " (UDP: " + udp_error + ")";

  if (state.crash_logging_enabled)
    state.crash_logger.log("connect", ("Connected to " + std::string(state.host) + ":" + std::to_string(state.debug_port)).c_str());

  set_status(state, message);
  push_notification(state, "Connected to " + std::string(state.host) + ":" + std::to_string(state.debug_port));
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

void disconnect_console(AppState &state) {
  state.connect_pending = false;  /* cancel any in-flight async connect */
  state.scan_async_pending = false;  /* cancel any in-flight async scan */
  state.telemetry_pending = false;  /* cancel any in-flight telemetry poll */
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

  if (state.crash_logging_enabled)
    state.crash_logger.log("connect", "Disconnected from console");

  set_status(state, "Console disconnected");
  push_notification(state, "Disconnected from console");
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
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("app.version"));

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

    ImGui::Dummy(ImVec2(0, 3));
    sidebar_section(locale::tr("sidebar.section.observe"));
    nav_item(state, Screen::TaskMgr, icons::kGauge, locale::tr("nav.taskmgr"));
    nav_item(state, Screen::Logs, icons::kLogs, locale::tr("nav.logs"));
    nav_item(state, Screen::Telemetry, icons::kTelemetry, locale::tr("nav.telemetry"));

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
  set_status(state, "Process list refreshed (" + std::to_string(state.processes.size()) + " entries)");
  if (state.crash_logging_enabled)
    state.crash_logger.log("refresh", ("Process list: " + std::to_string(state.processes.size()) + " entries").c_str());
}

static void topbar_refresh_maps(AppState &state) {
  if (!state.client.connected()) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", "Maps refresh failed: not connected");
    set_status(state, "Connect a console before refreshing maps");
    return;
  }
  if (state.selected_pid <= 0) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", "Maps refresh failed: no process selected");
    set_status(state, "Select a process first");
    return;
  }
  if (!state.client.process_maps(state.selected_pid, state.maps)) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Maps refresh failed: " + std::string(state.client.last_error())).c_str());
    set_status(state, state.client.last_error());
    return;
  }
  state.selected_map_row = -1;
  set_status(state, "Memory maps refreshed (" + std::to_string(state.maps.size()) + " maps)");
  if (state.crash_logging_enabled)
    state.crash_logger.log("refresh", ("Memory maps: " + std::to_string(state.maps.size()) + " maps").c_str());
}

static bool topbar_button(const char *id, const char *icon, const char *label,
                          float width, bool primary = false) {
  ImGui::PushID(id);
  topbar_align();
  std::string text = std::string(icon) + " " + label;
  const bool pressed = primary
      ? ui::primary_button(text.c_str(), ImVec2(width, topbar_control_h()))
      : ui::soft_button(text.c_str(), ImVec2(width, topbar_control_h()));
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

  if (s_logo_texture.texture != 0U) {
    topbar_align(logo_h);
    ImGui::Image(texture_id(s_logo_texture.texture), ImVec2(logo_w, logo_h),
                 s_logo_texture.uv0, s_logo_texture.uv1);
  } else {
    topbar_align(logo_h);
    ImGui::Dummy(ImVec2(logo_w, logo_h));
  }
  ImGui::SameLine(0.0f, 12.0f * scl);

  if (topbar_button("TopbarRefreshPids", icons::kRefresh, locale::tr("topbar.pids"), 76.0f * scl))
    topbar_refresh_processes(state);
  ImGui::SameLine();
  if (!state.client.connected()) ImGui::BeginDisabled();
  draw_process_combo(state, topbar_w > 1280.0f * scl ? 300.0f * scl : 230.0f * scl);
  if (!state.client.connected()) ImGui::EndDisabled();
  ImGui::SameLine();
  if (topbar_button("TopbarRefreshMaps", icons::kMemory, locale::tr("topbar.maps"), 82.0f * scl))
    topbar_refresh_maps(state);

  const bool connected = state.client.connected();
  const ImVec4 session_color = state.connect_pending ? ui::colors().warning :
                               connected ? ui::colors().success : ui::colors().danger;
  if (topbar_w > 1120.0f * scl) {
    ImGui::SameLine();
    topbar_chip("TopbarSession", locale::tr("topbar.chip_session"), connected ? locale::tr("topbar.online") : locale::tr("topbar.offline"), session_color, 136.0f * scl);
  }
  if (topbar_w > 1260.0f * scl) {
    ImGui::SameLine();
    topbar_chip("TopbarMaps", locale::tr("topbar.chip_maps"), std::to_string(state.maps.size()).c_str(), ui::colors().link, 104.0f * scl);
  }
  if (topbar_w > 1370.0f * scl) {
    ImGui::SameLine();
    topbar_chip("TopbarHits", locale::tr("topbar.chip_hits"), std::to_string(state.scan_result.count).c_str(), ui::colors().primary2, 104.0f * scl);
  }
  if (topbar_w > 1480.0f * scl) {
    ImGui::SameLine();
    topbar_chip("TopbarCheats", locale::tr("topbar.chip_cheats"), std::to_string(state.cheats.size()).c_str(), ui::colors().warning, 104.0f * scl);
  }

  const float right_w = connected ? 432.0f * scl : 376.0f * scl;
  ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX() + 8.0f * scl, topbar_w - right_w));
  if (connected) {
    if (topbar_button("TopbarPing", icons::kGauge, locale::tr("topbar.ping"), 74.0f * scl))
      set_status(state, state.client.ping() ? "Ping OK" : state.client.last_error());
    ImGui::SameLine();
    if (topbar_button("TopbarLogs", icons::kLogs, locale::tr("topbar.logs"), 96.0f * scl))
      state.screen = Screen::Logs;
    ImGui::SameLine();
    std::string label = std::string(locale::tr("topbar.drop"));
    if (topbar_button("TopbarDrop", icons::kDisconnect, label.c_str(), 120.0f * scl))
      disconnect_console(state);
  } else {
    if (topbar_button("TopbarConfigure", icons::kConsole, locale::tr("topbar.console"), 96.0f * scl))
      state.screen = Screen::Consoles;
    ImGui::SameLine();      if (topbar_button("TopbarSettings", icons::kSettings, locale::tr("topbar.settings"), 130.0f * scl))
      state.screen = Screen::Settings;
    ImGui::SameLine();
    if (state.connect_pending) {
      ImGui::SetCursorPosY(topbar_center_y(ImGui::GetFontSize()));
      ImGui::TextColored(ui::colors().warning, "%s  %s", icons::kConnect, locale::tr("topbar.connecting"));
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

static void draw_notifications(AppState &state) {
  const float scl = ui::dpi_scale();
  const double now = ImGui::GetTime();
  ImGuiViewport *viewport = ImGui::GetMainViewport();
  const float toast_w = 380.0f * scl, toast_h = 56.0f * scl;
  const float pad = 20.0f * scl, spacing = 8.0f * scl;
  float x = viewport->WorkPos.x + viewport->WorkSize.x - toast_w - pad;
  float y_base = viewport->WorkPos.y + viewport->WorkSize.y - pad;

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
  case Screen::Logs:      draw_logs(state, avail); break;
  case Screen::Telemetry: draw_telemetry(state, avail); break;
  case Screen::TaskMgr:   draw_taskmgr(state, avail); break;
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
  if (ImGui::IsKeyPressed(ImGuiKey_F5) && !state.connect_pending) {
    if (state.client.connected())
      disconnect_console(state);
    else
      connect_console(state);
  }
}

/* ---- Main app draw ---- */

static void draw_app(AppState &state) {
  poll_connect(state);
  poll_telemetry(state);
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
      "C:\\Windows\\Fonts\\msgothic.ttc",
      "C:\\Windows\\Fonts\\yugothib.ttf",
      "C:\\Windows\\Fonts\\malgun.ttf",
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
  io.Fonts->Build();
}

int run_frontend(int, char **argv) {
  init_executable_dir(argv != nullptr ? argv[0] : nullptr);
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
  ui::set_dpi_scale(dpi_scale);
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

  IMGUI_CHECKVERSION(); ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO(); io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  ui::apply_theme();

  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init(glsl_version);

  setup_fonts(io, dpi_scale);
  ImGui::GetStyle().ScaleAllSizes(dpi_scale);

  AppState state;

  // Open crash logger in the executable directory
  {
    std::filesystem::path log_path = s_executable_dir / "memdbg_crash.log";
    state.crash_logger.open(log_path.string().c_str());
  }

  {
    std::string config_error;
    if (load_frontend_settings(state, &config_error) && config_error.empty()) {
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
  {
    using namespace memdbg::frontend::assets;
    for (size_t i = 0; i < kEmbeddedLocaleCount; ++i) {
      const auto &el = kEmbeddedLocales[i];
      (void)loc.load_mem(el.filename, el.data, el.size);
    }
  }

  // Set language from saved preference, or auto-detect from OS.
  if (state.language >= 0 && state.language < static_cast<int>(locale::Lang::COUNT)) {
    loc.set_active(static_cast<locale::Lang>(state.language));
  } else {
    locale::Lang detected = locale::detect_system_lang();
    loc.set_active(detected);
    state.language = static_cast<int>(detected);
  }
  github_profile_start(state.github_profile);
  std::string udp_error;
  if (!ensure_udp_listener(state, udp_error)) set_status(state, "UDP: "+udp_error);

  if (state.crash_logging_enabled)
    state.crash_logger.log("startup", "MemDBG frontend started");

  push_notification(state, "MemDBG by seregonwar started", 6.0);

  /* Store pointers for the refresh callback (window-refresh fires during live resize on macOS).
   * Must be static so the non-capturing lambda below can access them. */
  static AppState *s_render_state = nullptr;
  static GLFWwindow *s_render_window = nullptr;
  s_render_state = &state;
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

  state.udp_listener.stop(); state.client.disconnect();
  github_profile_shutdown(state.github_profile);
  shutdown_texture(s_logo_texture);
  state.crash_logger.close();
  ImGui_ImplOpenGL3_Shutdown(); ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext(); glfwDestroyWindow(window); glfwTerminate();
  s_render_state = nullptr;
  s_render_window = nullptr;
  return 0;
}

} // namespace memdbg::frontend

/*
 * MemDBG - ImGui console frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "icon_font.hpp"
#include "github_profile.hpp"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <string>

namespace memdbg::frontend {

/* ---- State helpers ---- */

void set_status(AppState &state, const std::string &message) {
  std::snprintf(state.status, sizeof(state.status), "%s", message.c_str());
}

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
  if (const char *config_home = std::getenv("XDG_CONFIG_HOME");
      config_home != nullptr && config_home[0] != '\0') {
    return std::filesystem::path(config_home) / "MemDBG" / "frontend.conf";
  }
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
    return std::filesystem::path(home) / ".config" / "MemDBG" / "frontend.conf";
  }
  return std::filesystem::path("MemDBG_frontend.conf");
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
    } else if (key == "dump_path" && !value.empty()) {
      std::snprintf(state.dump_path, sizeof(state.dump_path), "%s", value.c_str());
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
  set_status(state, message);
  push_notification(state, "Connected to " + std::string(state.host) + ":" + std::to_string(state.debug_port));
}

/* Modal spinner drawn during async connect */
static void draw_connect_spinner(AppState &state) {
  if (!state.connect_pending) return;

  const ImVec2 center = ImGui::GetMainViewport()->GetCenter();
  ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
  ImGui::SetNextWindowSize(ImVec2(320, 120));

  ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(18, 24, 32, 245));
  ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(60, 120, 130, 100));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 14.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24, 20));

  ImGui::Begin("##ConnectSpinner", nullptr,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
               ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
               ImGuiWindowFlags_NoNav | ImGuiWindowFlags_AlwaysAutoResize);

  ImGui::TextColored(ui::colors().primary2, "%s  Connecting...", icons::kConnect);
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s:%d", state.host, state.debug_port);

  /* Animated spinner using time-based rotation */
  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec2 sp = ImVec2(center.x + 100, center.y + 4);
  float radius = 14.0f;
  float t = (float)ImGui::GetTime();
  const int segments = 8;
  for (int i = 0; i < segments; ++i) {
    float a = t * 4.0f + (float)i * 6.2831853f / (float)segments;
    float alpha = 0.15f + 0.85f * ((float)i / (float)segments);
    ImVec2 p(sp.x + radius * cosf(a), sp.y + radius * sinf(a));
    dl->AddCircleFilled(p, 2.5f, IM_COL32(118, 232, 224, (int)(200 * alpha)));
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
  set_status(state, "Console disconnected");
  push_notification(state, "Disconnected from console");
}

/* ---- Sidebar navigation ---- */

static ImVec4 alpha(ImVec4 color, float value) {
  color.w *= value;
  return color;
}

static void sidebar_section(const char *label) {
  ImGui::SetCursorPosX(24.0f);
  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::Dummy(ImVec2(0.0f, 1.0f));
}

static void nav_item(AppState &state, Screen screen, const char *icon, const char *label) {
  bool selected = state.screen == screen;
  ImGui::PushID(label);

  const float row_h = 34.0f;
  const float row_w = ImGui::GetContentRegionAvail().x;
  ImVec2 pos = ImGui::GetCursorScreenPos();
  ImGui::InvisibleButton("##nav", ImVec2(row_w, row_h));
  const bool hovered = ImGui::IsItemHovered();
  if (ImGui::IsItemClicked()) state.screen = screen;

  ImDrawList *dl = ImGui::GetWindowDrawList();
  const ImVec2 min(pos.x + 6.0f, pos.y + 2.0f);
  const ImVec2 max(pos.x + row_w - 4.0f, pos.y + row_h - 2.0f);

  if (selected || hovered) {
    const ImVec4 bg = selected ? ui::colors().bg3 : alpha(ui::colors().bg3, 0.58f);
    dl->AddRectFilled(min, max, ui::color_u32(bg), 8.0f);
    dl->AddRect(min, max,
                ui::color_u32(selected ? alpha(ui::colors().border_hot, 0.72f)
                                       : alpha(ui::colors().border, 0.45f)),
                8.0f);
  }

  if (selected) {
    dl->AddRectFilled(ImVec2(pos.x + 10.0f, pos.y + 9.0f),
                      ImVec2(pos.x + 14.0f, pos.y + row_h - 8.0f),
                      ui::color_u32(ui::colors().primary2), 3.0f);
  }

  const ImVec4 icon_col = selected ? ui::colors().primary2 :
                          hovered ? ui::colors().text : ui::colors().muted;
  const ImVec4 text_col = selected ? ui::colors().text :
                          hovered ? ui::colors().text : ui::colors().muted;
  const ImVec2 icon_size = ImGui::CalcTextSize(icon);
  const ImVec2 label_size = ImGui::CalcTextSize(label);
  const float icon_x = pos.x + 25.0f - icon_size.x * 0.5f;
  const float icon_y = pos.y + (row_h - icon_size.y) * 0.5f;
  const float text_y = pos.y + (row_h - label_size.y) * 0.5f;
  dl->AddText(ImVec2(icon_x, icon_y), ui::color_u32(icon_col), icon);
  dl->AddText(ImVec2(pos.x + 54.0f, text_y), ui::color_u32(text_col), label);

  if (hovered) ImGui::SetTooltip("%s", label);
  ImGui::PopID();
}

static void draw_sidebar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18,20));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8,2));
  ImGui::BeginChild("Sidebar", size, true, ImGuiWindowFlags_NoScrollbar);

  ImGui::TextColored(ui::colors().primary2, "%s", "MemDBG");
  ui::text_muted("Native v0.1.0");
  ImGui::Dummy(ImVec2(0, 6));
  ImGui::Separator();
  ImGui::Dummy(ImVec2(0, 6));

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14,10));
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
  ImGui::BeginChild("SidebarStatus", ImVec2(0,78), true, ImGuiWindowFlags_NoScrollbar);
  const bool connected = state.client.connected();
  const ImVec4 status_color = state.connect_pending ? ui::colors().warning :
                              connected ? ui::colors().success : ui::colors().dim;
  ui::status_dot(status_color);
  ImGui::SameLine();
  ImGui::BeginGroup();
  ImGui::TextColored(status_color, "%s", state.connect_pending ? "Connecting" :
                                          connected ? "Connected" : "Offline");
  ImGui::TextColored(ui::colors().dim, "%s:%d", state.host, state.debug_port);
  ImGui::EndGroup();
  ImGui::Dummy(ImVec2(0, 3));
  ImGui::TextColored(ui::colors().dim, "UDP");
  ImGui::SameLine(72.0f);
  ImGui::TextColored(state.udp_listener.running() ? ui::colors().success : ui::colors().dim,
                     "%s", state.udp_listener.running() ? "listening" : "stopped");
  ImGui::EndChild();
  ImGui::PopStyleVar(2); ImGui::PopStyleColor();

  ImGui::Dummy(ImVec2(0, 6));
  sidebar_section("MAIN");
  nav_item(state, Screen::Home, icons::kHome, "Command Center");
  nav_item(state, Screen::Consoles, icons::kConsole, "Consoles");

  ImGui::Dummy(ImVec2(0, 4));
  sidebar_section("TOOLS");
  nav_item(state, Screen::Processes, icons::kProcess, "Processes");
  nav_item(state, Screen::Memory, icons::kMemory, "Memory");
  nav_item(state, Screen::Scanner, icons::kScanner, "Scanner");
  nav_item(state, Screen::PointerScanner, icons::kPointer, "Pointer Scan");
  nav_item(state, Screen::AOBScanner, icons::kCode, "AOB Scan");
  nav_item(state, Screen::Trainer, icons::kTrainer, "Trainer");

  ImGui::Dummy(ImVec2(0, 4));
  sidebar_section("OBSERVE");
  nav_item(state, Screen::Logs, icons::kLogs, "UDP Logs");
  nav_item(state, Screen::Telemetry, icons::kTelemetry, "Telemetry");

  ImGui::Dummy(ImVec2(0, 4));
  sidebar_section("SYSTEM");
  nav_item(state, Screen::Settings, icons::kSettings, "Settings");
  nav_item(state, Screen::Credits, icons::kCredits, "Credits");

  float footer_y = ImGui::GetWindowHeight() - 84.0f;
  if (ImGui::GetCursorPosY() < footer_y) ImGui::SetCursorPosY(footer_y);
  ImGui::Separator();
  ImGui::Dummy(ImVec2(0, 4));
  ImGui::TextColored(ui::colors().dim, "TCP");
  ImGui::SameLine(70.0f);
  ImGui::TextColored(ui::colors().muted, "%d", state.debug_port);
  ImGui::TextColored(ui::colors().dim, "UDP");
  ImGui::SameLine(70.0f);
  ImGui::TextColored(ui::colors().muted, "%d", state.udp_port);
  ImGui::EndChild();
  ImGui::PopStyleVar(2); ImGui::PopStyleColor();
}

/* ---- Top bar ---- */

static void draw_top_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().panel);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24, 18));
  ImGui::BeginChild("TopBar", size, true, ImGuiWindowFlags_NoScrollbar);

  const float btn_w = state.client.connected() ? 150.0f : 178.0f;
  const float title_max_w = ImGui::GetWindowWidth() - btn_w - 64.0f;

  /* Title with ellipsis on overflow (single-pass truncation) */
  const char *title = screen_title(state.screen);
  const char *subtitle = screen_subtitle(state.screen);
  const float ellipsis_w = ImGui::CalcTextSize("...").x;

  auto draw_truncated = [&](const char *text, ImVec4 color) {
    if (ImGui::CalcTextSize(text).x <= title_max_w || title_max_w <= 40.0f) {
      ImGui::TextColored(color, "%s", text);
      return;
    }
    /* Estimate truncation point using average char width */
    size_t len = strlen(text);
    if (len == 0) return;
    float full_w = ImGui::CalcTextSize(text).x;
    float avg_w = full_w / (float)len;
    size_t keep = (size_t)((title_max_w - ellipsis_w) / avg_w);
    if (keep > len) keep = len;
    if (keep < 1) keep = 1;
    /* Walk back if overshoot */
    char buf[256];
    while (keep > 0) {
      size_t n = keep < sizeof(buf) - 4 ? keep : sizeof(buf) - 4;
      memcpy(buf, text, n);
      memcpy(buf + n, "...", 4);
      if (ImGui::CalcTextSize(buf).x <= title_max_w) break;
      --keep;
    }
    ImGui::TextColored(color, "%.*s...", (int)keep, text);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", text);
  };

  ImGui::BeginGroup();
  draw_truncated(title, ui::colors().primary2);
  draw_truncated(subtitle, ui::colors().muted);
  ImGui::EndGroup();

  ImGui::SameLine();
  ImGui::SetCursorPosX(ImGui::GetWindowWidth() - btn_w - 24.0f);
  ImGui::SetCursorPosY(22.0f);
  if (state.connect_pending) {
    ImGui::TextColored(ui::colors().warning, "%s  Connecting...", icons::kConnect);
  } else if (!state.client.connected()) {
    std::string label = std::string(icons::kConnect) + "  Connect";
    if (ui::primary_button(label.c_str(), ImVec2(btn_w, 42))) connect_console(state);
  } else {
    std::string label = std::string(icons::kDisconnect) + "  Disconnect";
    if (ui::danger_button(label.c_str(), ImVec2(btn_w, 42))) disconnect_console(state);
  }
  ImGui::EndChild();
  ImGui::PopStyleVar(); ImGui::PopStyleColor();
}

/* ---- Status bar ---- */

static void draw_status_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().panel);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(22, 10));
  ImGui::BeginChild("StatusBar", size, true, ImGuiWindowFlags_NoScrollbar);

  ui::status_dot(state.client.connected() ? ui::colors().success : ui::colors().muted);
  ImGui::SameLine();

  /* Status text with ellipsis on overflow */
  const float rhs_width = 440.0f;
  float avail_for_status = ImGui::GetWindowWidth() - rhs_width - 40.0f;
  if (avail_for_status < 80.0f) avail_for_status = 80.0f;
  ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + avail_for_status);
  ImGui::TextUnformatted(state.status);
  ImGui::PopTextWrapPos();

  const auto log_stats = state.udp_listener.stats();
  ImGui::SameLine();
  ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX(), ImGui::GetWindowWidth() - rhs_width));
  ImGui::TextColored(ui::colors().dim, "FPS %.0f", ImGui::GetIO().Framerate);
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);
  ImGui::TextColored(ui::colors().dim, "UDP %s", state.udp_listener.running() ? "on" : "off");
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);

  /* Compact stats: abbreviate when narrow */
  if (ImGui::GetWindowWidth() > 1100.0f) {
    ImGui::TextColored(ui::colors().dim, "%llu rx  %llu lost  %llu evicted",
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
  const double now = ImGui::GetTime();
  ImGuiViewport *viewport = ImGui::GetMainViewport();
  const float toast_w = 380.0f, toast_h = 56.0f;
  const float pad = 20.0f, spacing = 8.0f;
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
    if (y < viewport->WorkPos.y + 40.0f) { ++it; ++idx; continue; }

    ImGui::SetNextWindowPos(ImVec2(x, y));
    ImGui::SetNextWindowSize(ImVec2(toast_w, toast_h));

    ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(24, 28, 36, (int)(220 * alpha)));
    ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(60, 120, 130, (int)(120 * alpha)));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f);
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
    dl->AddRectFilled(ImVec2(wpos.x + 6, wpos.y + 10),
                      ImVec2(wpos.x + 10, wpos.y + wsz.y - 10),
                      IM_COL32(118, 232, 224, (int)(180 * alpha)), 3.0f);

    ImGui::TextColored(ImVec4(118.0f/255.0f, 232.0f/255.0f, 224.0f/255.0f, alpha),
                       "%s", icons::kNotify);
    ImGui::SameLine(34);

    /* Message text with wrapping */
    float text_w = toast_w - 100.0f;
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + text_w);
    ImGui::TextColored(ImVec4(0.92f, 0.93f, 0.94f, alpha), "%s", n.message.c_str());
    ImGui::PopTextWrapPos();

    /* Dismiss button */
    ImGui::SameLine();
    ImGui::SetCursorPosX(toast_w - 40.0f);
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
  case Screen::Settings:  draw_settings(state, avail); break;
  case Screen::Credits:   draw_credits(state, avail); break;
  }
}

/* ---- Main app draw ---- */

static void draw_app(AppState &state) {
  poll_connect(state);

  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);

  ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|
                           ImGuiWindowFlags_NoSavedSettings|ImGuiWindowFlags_NoBringToFrontOnFocus;
  ImGui::Begin("MemDBG Shell", nullptr, flags);

  ImVec2 win_pos = ImGui::GetWindowPos(), win_size = ImGui::GetWindowSize();
  ui::draw_background(ImGui::GetWindowDrawList(), win_pos, win_size);

  const float sidebar_w = std::clamp(win_size.x * 0.21f, 250.0f, 310.0f);
  const float top_h = 88.0f, status_h = 42.0f, gap = 16.0f;
  const float content_w = win_size.x - sidebar_w;

  ImGui::SetCursorPos(ImVec2(0,0));
  draw_sidebar(state, ImVec2(sidebar_w, win_size.y));
  ImGui::SetCursorPos(ImVec2(sidebar_w, 0));
  draw_top_bar(state, ImVec2(content_w, top_h));
  ImGui::SetCursorPos(ImVec2(sidebar_w+gap, top_h+gap));
  draw_screen(state, ImVec2(content_w-(gap*2.0f), win_size.y-top_h-status_h-(gap*2.0f)));
  ImGui::SetCursorPos(ImVec2(sidebar_w, win_size.y-status_h));
  draw_status_bar(state, ImVec2(content_w, status_h));

  draw_notifications(state);
  draw_connect_spinner(state);

  ImGui::End();
}

/* ---- Entry point ---- */

static bool readable_file(const char *path) {
  FILE *file = std::fopen(path, "rb");
  if (!file) return false;
  std::fclose(file);
  return true;
}

static void setup_fonts(ImGuiIO &io) {
  const float text_size = 17.0f;
  ImFontConfig base_cfg;
  base_cfg.OversampleH = 3;
  base_cfg.OversampleV = 2;
  base_cfg.PixelSnapH = false;

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
    io.Fonts->AddFontDefault(&fallback_cfg);
  }

  ImFontConfig icon_cfg;
  icon_cfg.MergeMode = true;
  icon_cfg.FontDataOwnedByAtlas = false;
  icon_cfg.PixelSnapH = true;
  icon_cfg.GlyphMinAdvanceX = 17.0f;
  icon_cfg.GlyphOffset = ImVec2(0.0f, 1.0f);
  static const ImWchar icon_ranges[] = { 0xF000, 0xF8FF, 0 };
  io.Fonts->AddFontFromMemoryTTF(
      fa_solid_900, (int)fa_solid_900_len,
      16.0f, &icon_cfg, icon_ranges);
  io.Fonts->Build();
}

int run_frontend(int, char **) {
  if (!glfwInit()) return 1;
#if defined(__APPLE__)
  const char *glsl_version = "#version 150";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3); glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
  const char *glsl_version = "#version 130";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3); glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif
  GLFWwindow *window = glfwCreateWindow(1400, 900, "MemDBG Native", nullptr, nullptr);
  if (!window) { glfwTerminate(); return 1; }
  glfwMakeContextCurrent(window); glfwSwapInterval(1);

  IMGUI_CHECKVERSION(); ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO(); io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  ui::apply_theme();

  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init(glsl_version);

  setup_fonts(io);

  AppState state;
  {
    std::string config_error;
    if (load_frontend_settings(state, &config_error) && config_error.empty()) {
      set_status(state, "Settings loaded");
    } else if (!config_error.empty()) {
      set_status(state, config_error);
    }
  }
  github_profile_start(state.github_profile);
  std::string udp_error;
  if (!ensure_udp_listener(state, udp_error)) set_status(state, "UDP: "+udp_error);
  push_notification(state, "MemDBG by seregonwar started", 6.0);

  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();
    ImGui_ImplOpenGL3_NewFrame(); ImGui_ImplGlfw_NewFrame(); ImGui::NewFrame();
    draw_app(state);
    ImGui::Render();
    int dw, dh; glfwGetFramebufferSize(window, &dw, &dh);
    glViewport(0,0,dw,dh);
    glClearColor(11.0f/255.0f,11.0f/255.0f,14.0f/255.0f,1.0f); glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(window);
  }

  state.udp_listener.stop(); state.client.disconnect();
  github_profile_shutdown(state.github_profile);
  ImGui_ImplOpenGL3_Shutdown(); ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext(); glfwDestroyWindow(window); glfwTerminate();
  return 0;
}

} // namespace memdbg::frontend

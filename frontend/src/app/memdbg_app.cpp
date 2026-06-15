/*
 * memDBG - ImGui console frontend.
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
#include <cstdio>
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

void connect_console(AppState &state) {
  normalize_ports(state);
  state.client.disconnect();
  state.has_hello = false;
  state.processes.clear(); state.maps.clear(); state.memory.clear();
  state.scan_result = ScanResult{};
  state.scan_snapshot.clear(); state.scan_snapshot_value_len = 0;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "No scan session");
  state.selected_pid = 0; state.selected_process_row = -1; state.selected_map_row = -1;
  state.has_process_info = false;
  if (!state.client.connect_to(state.host, static_cast<uint16_t>(state.debug_port))) {
    set_status(state, state.client.last_error());
    push_notification(state, "Connection failed: " + state.client.last_error(), 5.0);
    return;
  }
  if (!state.client.hello(state.hello)) {
    std::string error = state.client.last_error();
    state.client.disconnect();
    set_status(state, error.empty()?"HELLO failed":error);
    push_notification(state, "HELLO failed: " + (error.empty() ? "unknown error" : error), 5.0);
    return;
  }
  state.has_hello = true;
  std::string udp_error;
  std::string message = "Connected to console " + std::string(state.host) + ":" + std::to_string(state.debug_port);
  if (!ensure_udp_listener(state, udp_error)) message += " (UDP: " + udp_error + ")";
  set_status(state, message);
  push_notification(state, "Connected to " + std::string(state.host) + ":" + std::to_string(state.debug_port));
}

void disconnect_console(AppState &state) {
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

static void nav_item(AppState &state, Screen screen, const char *label) {
  bool selected = state.screen == screen;
  ImGui::PushID(label);

  /* Rounded selection highlight + left accent bar */
  if (selected) {
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 cursor = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float h = 42.0f;
    /* Subtle background pill */
    dl->AddRectFilled(ImVec2(cursor.x + 6.0f, cursor.y + 3.0f),
                      ImVec2(cursor.x + w - 4.0f, cursor.y + h - 3.0f),
                      ui::color_u32(ui::colors().bg3), 8.0f);
    /* Left accent glow bar */
    dl->AddRectFilled(ImVec2(cursor.x + 8.0f, cursor.y + 9.0f),
                      ImVec2(cursor.x + 12.0f, cursor.y + h - 9.0f),
                      ui::color_u32(ui::colors().primary2), 3.0f);
    /* Soft glow behind accent */
    dl->AddRectFilled(ImVec2(cursor.x + 7.0f, cursor.y + 7.0f),
                      ImVec2(cursor.x + 14.0f, cursor.y + h - 7.0f),
                      IM_COL32(118, 232, 224, 28), 4.0f);
  }

  ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0,0,0,0));
  ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(36.0f/255.0f,62.0f/255.0f,72.0f/255.0f,0.55f));
  ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(28.0f/255.0f,98.0f/255.0f,110.0f/255.0f,0.40f));

  /* Use Selectable with span-all-columns for full-width highlight */
  ImGuiSelectableFlags flags = ImGuiSelectableFlags_SpanAllColumns;
  if (ImGui::Selectable(label, selected, flags, ImVec2(0, 42))) state.screen = screen;

  /* Ellipsis tooltip for truncated labels */
  if (ImGui::IsItemHovered()) {
    ImVec2 label_size = ImGui::CalcTextSize(label);
    float avail_w = ImGui::GetContentRegionAvail().x - 20.0f;
    if (label_size.x > avail_w)
      ImGui::SetTooltip("%s", label);
  }

  ImGui::PopStyleColor(3);
  ImGui::PopID();
}

static void draw_sidebar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20,26));
  ImGui::BeginChild("Sidebar", size, true, ImGuiWindowFlags_NoScrollbar);
  ImGui::TextColored(ui::colors().text, "memDBG");
  ui::text_muted("Native v0.1.0");
  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14,14));
  ImGui::BeginChild("SidebarStatus", ImVec2(0,74), true, ImGuiWindowFlags_NoScrollbar);
  ui::status_dot(state.client.connected() ? ui::colors().success : ui::colors().dim);
  ImGui::SameLine(); ImGui::BeginGroup();
  ImGui::TextColored(state.client.connected()?ui::colors().success:ui::colors().muted, "%s", state.client.connected()?"Connected":"Offline");
  ImGui::TextColored(ui::colors().dim, "%s:%d", state.host, state.debug_port);
  ImGui::EndGroup();
  ImGui::EndChild();
  ImGui::PopStyleVar(); ImGui::PopStyleColor();

  ImGui::Spacing(); ImGui::Spacing();
  ui::text_dim("MAIN");
  nav_item(state, Screen::Home,
           (std::string("  ") + icons::kHome + "  Home").c_str());
  nav_item(state, Screen::Consoles,
           (std::string("  ") + icons::kConsole + "  Consoles").c_str());
  ImGui::Spacing();
  ui::text_dim("TOOLSET");
  nav_item(state, Screen::Processes,
           (std::string("  ") + icons::kProcess + "  Processes").c_str());
  nav_item(state, Screen::Memory,
           (std::string("  ") + icons::kMemory + "  Memory").c_str());
  nav_item(state, Screen::Scanner,
           (std::string("  ") + icons::kScanner + "  Scanner").c_str());
  nav_item(state, Screen::PointerScanner,
           (std::string("  ") + icons::kPointer + "  Pointer Scan").c_str());
  nav_item(state, Screen::AOBScanner,
           (std::string("  ") + icons::kCode + "  AOB Scan").c_str());
  nav_item(state, Screen::Trainer,
           (std::string("  ") + icons::kTrainer + "  Trainer").c_str());
  nav_item(state, Screen::Logs,
           (std::string("  ") + icons::kLogs + "  Logs").c_str());
  nav_item(state, Screen::Telemetry,
           (std::string("  ") + icons::kTelemetry + "  Telemetry").c_str());
  ImGui::Spacing();
  ui::text_dim("SYSTEM");
  nav_item(state, Screen::Settings,
           (std::string("  ") + icons::kSettings + "  Settings").c_str());
  nav_item(state, Screen::Credits,
           (std::string("  ") + icons::kCredits + "  Credits").c_str());

  float footer_y = ImGui::GetWindowHeight() - 100.0f;
  if (ImGui::GetCursorPosY() < footer_y) ImGui::SetCursorPosY(footer_y);
  ImGui::Separator();
  ImGui::TextColored(ui::colors().dim, "Debug TCP | %d", state.debug_port);
  ImGui::TextColored(ui::colors().dim, "UDP logs  | %d", state.udp_port);
  ImGui::TextColored(ui::colors().muted, "File log  | /data/memdbg/memdbg.log");
  ImGui::EndChild();
  ImGui::PopStyleVar(); ImGui::PopStyleColor();
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
  if (!state.client.connected()) {
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
  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);

  ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|
                           ImGuiWindowFlags_NoSavedSettings|ImGuiWindowFlags_NoBringToFrontOnFocus;
  ImGui::Begin("memDBG Shell", nullptr, flags);

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

  ImGui::End();
}

/* ---- Entry point ---- */

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
  GLFWwindow *window = glfwCreateWindow(1500, 920, "memDBG Native", nullptr, nullptr);
  if (!window) { glfwTerminate(); return 1; }
  glfwMakeContextCurrent(window); glfwSwapInterval(1);

  IMGUI_CHECKVERSION(); ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO(); io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  ui::apply_theme();

  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init(glsl_version);

  /* Add base font FIRST (required for MergeMode).
   * Use 18px for crisper rendering on HiDPI displays.
   * Then merge icon font: FontAwesome 6 Free Solid, PUA 0xF000-0xF8FF. */
  {
    ImFontConfig base_cfg;
    base_cfg.SizePixels = 18.0f;
    base_cfg.OversampleH = 2;
    base_cfg.OversampleV = 2;
    base_cfg.PixelSnapH = true;
    io.Fonts->AddFontDefault(&base_cfg);
  }
  {
    ImFontConfig cfg;
    cfg.FontDataOwnedByAtlas = false;
    cfg.MergeMode = true;
    cfg.GlyphMinAdvanceX = 18.0f;
    cfg.GlyphOffset = ImVec2(0.0f, 1.0f);
    cfg.PixelSnapH = true;
    cfg.OversampleH = 2;
    cfg.OversampleV = 2;
    static const ImWchar icon_ranges[] = { 0xF000, 0xF8FF, 0 };
    io.Fonts->AddFontFromMemoryTTF(
        fa_solid_900, (int)fa_solid_900_len,
        18.0f, &cfg, icon_ranges);
  }
  io.Fonts->Build();

  AppState state;
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

/*
 * MemDBG - Home screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <cstdio>
#include <string>

namespace memdbg::frontend {

namespace {

ImVec4 with_alpha(ImVec4 color, float alpha) {
  color.w *= alpha;
  return color;
}

void detail_row(const char *label, const char *value, ImVec4 value_color) {
  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::SameLine(124.0f);
  ImGui::TextColored(value_color, "%s", value);
}

bool action_tile(const char *id, const char *icon, const char *title,
                 const char *meta, bool available) {
  ImGui::PushID(id);
  const float h = 62.0f;
  const float w = ImGui::GetContentRegionAvail().x;
  ImVec2 pos = ImGui::GetCursorScreenPos();
  ImGui::InvisibleButton("##tile", ImVec2(w, h));
  const bool hovered = ImGui::IsItemHovered();
  const bool clicked = ImGui::IsItemClicked();

  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec4 bg = hovered ? ui::colors().bg3 : ui::colors().bg2;
  ImVec4 border = hovered ? ui::colors().border_hot : ui::colors().border;
  if (!available) {
    bg = with_alpha(bg, 0.62f);
    border = with_alpha(border, 0.45f);
  }

  dl->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + h), ui::color_u32(bg), 8.0f);
  dl->AddRect(pos, ImVec2(pos.x + w, pos.y + h), ui::color_u32(border), 8.0f);

  const ImVec4 icon_color = available ? ui::colors().primary2 : ui::colors().dim;
  const ImVec4 title_color = available ? ui::colors().text : ui::colors().muted;
  const ImVec4 meta_color = available ? ui::colors().muted : ui::colors().dim;
  dl->AddText(ImVec2(pos.x + 18.0f, pos.y + 20.0f), ui::color_u32(icon_color), icon);
  dl->AddText(ImVec2(pos.x + 54.0f, pos.y + 12.0f), ui::color_u32(title_color), title);
  dl->AddText(ImVec2(pos.x + 54.0f, pos.y + 35.0f), ui::color_u32(meta_color), meta);
  if (!available) {
    dl->AddText(ImVec2(pos.x + w - 34.0f, pos.y + 21.0f),
                ui::color_u32(ui::colors().dim), icons::kLock);
  }

  ImGui::PopID();
  return clicked;
}

} // namespace

void draw_home(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float col_w = (avail.x - gap) * 0.5f;
  const bool connected = state.client.connected();

  ui::begin_panel("HomeStatus", "Connection Status", ImVec2(col_w, avail.y));
  ImGui::BeginGroup();
  ui::status_dot(state.connect_pending ? ui::colors().warning :
                 connected ? ui::colors().success : ui::colors().dim);
  ImGui::SameLine();
  ImGui::TextColored(state.connect_pending ? ui::colors().warning :
                     connected ? ui::colors().success : ui::colors().danger,
                     "%s", state.connect_pending ? "CONNECTING" :
                          connected ? "CONNECTED TO CONSOLE" : "NOT CONNECTED");
  ImGui::EndGroup();

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  char endpoint[96];
  std::snprintf(endpoint, sizeof(endpoint), "%s:%d", state.host, state.debug_port);
  detail_row("Endpoint", endpoint, connected ? ui::colors().text : ui::colors().muted);
  detail_row("UDP logs", state.udp_listener.running() ? "listening" : "stopped",
             state.udp_listener.running() ? ui::colors().success : ui::colors().dim);
  detail_row("Process", selected_process_name(state).c_str(),
             state.selected_pid != 0 ? ui::colors().text : ui::colors().muted);

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  if (connected) {
    ui::draw_capabilities(state.hello);
    ImGui::Spacing();
    if (ui::soft_button((std::string(icons::kGauge) + "  Ping Payload").c_str(), ImVec2(170, 38))) {
      set_status(state, state.client.ping() ? "Ping OK" : state.client.last_error());
    }
    ImGui::SameLine();
    if (ui::danger_button((std::string(icons::kDisconnect) + "  Disconnect").c_str(), ImVec2(160, 38))) {
      disconnect_console(state);
    }
  } else {
    ImGui::TextWrapped("No active console session. Link the payload endpoint to unlock process, memory, scanner, and telemetry tools.");
    ImGui::Spacing();
    if (ui::primary_button((std::string(icons::kConnect) + "  Configure Connection").c_str(), ImVec2(240, 40))) {
      state.screen = Screen::Consoles;
    }
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("HomeActions", "Quick Actions", ImVec2(0, avail.y));
  if (action_tile("Consoles", icons::kConsole, "Consoles", "Console setup", true))
    state.screen = Screen::Consoles;
  if (action_tile("Processes", icons::kProcess, "Processes", connected ? "PID selection" : "Needs console", connected))
    { state.screen = Screen::Processes; if (!connected) set_status(state, "Connect a console before loading processes"); }
  if (action_tile("Memory", icons::kMemory, "Memory", connected ? "Read / patch" : "Needs console", connected))
    { state.screen = Screen::Memory; if (!connected) set_status(state, "Connect a console before reading memory"); }
  if (action_tile("Scanner", icons::kScanner, "Scanner", connected ? "Value search" : "Needs console", connected))
    { state.screen = Screen::Scanner; if (!connected) set_status(state, "Connect a console before scanning memory"); }
  if (action_tile("Trainer", icons::kTrainer, "Trainer", connected ? "Runtime cheats" : "Needs console", connected))
    { state.screen = Screen::Trainer; if (!connected) set_status(state, "Connect a console before using trainer locks"); }
  if (action_tile("Logs", icons::kLogs, "UDP Logs", state.udp_listener.running() ? "Listening" : "Stopped", true))
    state.screen = Screen::Logs;
  if (action_tile("Settings", icons::kSettings, "Settings", "Defaults", true))
    state.screen = Screen::Settings;
  ui::end_panel();
}

} // namespace memdbg::frontend

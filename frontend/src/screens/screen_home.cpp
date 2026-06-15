/*
 * memDBG - Home screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

namespace memdbg::frontend {

void draw_home(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float col_w = (avail.x - gap) * 0.5f;

  ui::begin_panel("HomeStatus", "Connection Status", ImVec2(col_w, avail.y));
  if (state.client.connected()) {
    ImGui::TextColored(ui::colors().success, "CONNECTED TO CONSOLE");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::Text("Endpoint: %s:%d", state.host, state.debug_port);
    ui::draw_capabilities(state.hello);
    ImGui::Spacing();
    ImGui::BeginDisabled(!state.client.connected());
    if (ui::soft_button("Ping Payload", ImVec2(160, 38))) {
      if (state.client.connected())
        set_status(state, state.client.ping() ? "Ping OK" : state.client.last_error());
      else
        set_status(state, "Not connected");
    }
    ImGui::SameLine();
    if (ui::danger_button("Disconnect", ImVec2(150, 38))) {
      if (state.client.connected())
        disconnect_console(state);
      else
        set_status(state, "Not connected");
    }
    ImGui::EndDisabled();
  } else {
    ImGui::TextColored(ui::colors().danger, "NOT CONNECTED");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextWrapped("No active console session. Link the payload endpoint to unlock process, memory, scanner, and telemetry tools.");
    ImGui::Spacing();
    if (ui::primary_button("Configure Connection", ImVec2(210, 40))) {
      state.screen = Screen::Consoles;
    }
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("HomeActions", "Quick Actions", ImVec2(0, avail.y));
  if (ui::soft_button((std::string(icons::kConsole) + "  Consoles").c_str(), ui::full_button(46)))
    { state.screen = Screen::Consoles; }
  if (ui::soft_button((std::string(icons::kProcess) + "  Processes").c_str(), ui::full_button(46)))
    { state.screen = Screen::Processes; }
  if (ui::soft_button((std::string(icons::kMemory) + "  Memory").c_str(), ui::full_button(46)))
    { state.screen = Screen::Memory; }
  if (ui::soft_button((std::string(icons::kScanner) + "  Scanner").c_str(), ui::full_button(46)))
    { state.screen = Screen::Scanner; }
  if (ui::soft_button((std::string(icons::kTrainer) + "  Trainer").c_str(), ui::full_button(46)))
    { state.screen = Screen::Trainer; }
  if (ui::soft_button((std::string(icons::kLogs) + "  UDP Logs").c_str(), ui::full_button(46)))
    { state.screen = Screen::Logs; }
  if (ui::soft_button((std::string(icons::kSettings) + "  Settings").c_str(), ui::full_button(46)))
    { state.screen = Screen::Settings; }
  ui::end_panel();
}

} // namespace memdbg::frontend

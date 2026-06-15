/*
 * memDBG - Settings screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"

#include <cstdio>

namespace memdbg::frontend {

void draw_settings(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float col_w = (avail.x - gap) * 0.5f;

  ui::begin_panel("SettingsConnection", "Connection Defaults", ImVec2(col_w, avail.y));
  ImGui::InputText("Console IPv4", state.host, sizeof(state.host));
  ImGui::InputInt("Debug TCP", &state.debug_port);
  ImGui::InputInt("UDP logs", &state.udp_port);
  normalize_ports(state);
  ImGui::Spacing();
  if (ui::soft_button("Apply UDP Port", ui::full_button(40))) {
    state.udp_listener.stop();
    std::string error;
    if (ensure_udp_listener(state, error)) set_status(state, "UDP port applied");
    else set_status(state, error);
  }
  if (ui::soft_button("Reset Console Defaults", ui::full_button(40))) {
    std::snprintf(state.host, sizeof(state.host), "%s", "192.168.1.100");
    state.debug_port = 9020;
    state.udp_port = 9023;
    set_status(state, "Console defaults restored");
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("SettingsRuntime", "Runtime Notes", ImVec2(0, avail.y));
  ImGui::TextWrapped("memDBG expects the payload to be running on the console. The app opens a TCP command session, while UDP logs can be received independently.");
  ImGui::Spacing();
  ImGui::Text("Protocol version: %u", MEMDBG_PROTOCOL_VERSION);
  ImGui::Text("Max read: %u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_READ));
  ImGui::Text("Max packet: %u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_PACKET));
  ImGui::TextWrapped("Console file log path: /data/memdbg/memdbg.log");
  ui::end_panel();
}

} // namespace memdbg::frontend

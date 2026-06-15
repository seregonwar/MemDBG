/*
 * MemDBG - Consoles screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"

namespace memdbg::frontend {

void draw_consoles(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float col_w = (avail.x - gap) * 0.5f;

  ui::begin_panel("ConsoleConnect", "Direct Console", ImVec2(col_w, avail.y));
  ImGui::InputText("Console IPv4", state.host, sizeof(state.host));
  ImGui::InputInt("Debug TCP", &state.debug_port);
  ImGui::InputInt("UDP logs", &state.udp_port);
  normalize_ports(state);
  ImGui::Spacing();

  if (!state.client.connected()) {
    if (ui::primary_button("Connect Console", ui::full_button(42))) {
      connect_console(state);
    }
  } else {
    if (ui::danger_button("Disconnect Console", ui::full_button(42))) {
      disconnect_console(state);
    }
  }

  if (state.client.connected()) {
    if (ui::soft_button("Ping Payload", ui::full_button(40))) {
      set_status(state, state.client.ping() ? "Ping OK" : state.client.last_error());
    }
    if (ui::danger_button("Shutdown Payload", ui::full_button(40))) {
      set_status(state, state.client.shutdown_payload() ? "Shutdown sent" : state.client.last_error());
    }
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ui::draw_capabilities(state.hello);
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("ConsoleRuntime", "Runtime", ImVec2(0, avail.y));
  ImGui::TextColored(state.client.connected() ? ui::colors().success : ui::colors().danger,
                     "%s", state.client.connected() ? "Session open" : "No session");
  ImGui::Spacing();
  ImGui::TextWrapped("The frontend talks to the payload over the debug TCP port and listens for telemetry on UDP.");
  ImGui::Spacing();
  ImGui::Text("Debug endpoint: %s:%d", state.host, state.debug_port);
  ImGui::Text("UDP listener: %s:%d", "0.0.0.0", state.udp_port);
  ImGui::TextWrapped("Console file log: /data/memdbg/memdbg.log");
  ImGui::Spacing();

  if (!state.udp_listener.running()) {
    if (ui::soft_button("Start UDP Log Listener", ui::full_button(40))) {
      std::string error;
      if (ensure_udp_listener(state, error)) {
        set_status(state, "UDP log listener started");
      } else {
        set_status(state, error);
      }
    }
  } else {
    if (ui::soft_button("Restart UDP Log Listener", ui::full_button(40))) {
      state.udp_listener.stop();
      std::string error;
      if (ensure_udp_listener(state, error)) {
        set_status(state, "UDP log listener restarted");
      } else {
        set_status(state, error);
      }
    }
    if (ui::soft_button("Stop UDP Log Listener", ui::full_button(40))) {
      state.udp_listener.stop();
      set_status(state, "UDP log listener stopped");
    }
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

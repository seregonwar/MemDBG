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

  ui::begin_panel("ConsoleConnect", locale::tr("consoles.direct_console"), ImVec2(col_w, avail.y));
  ImGui::InputText(locale::tr("consoles.console_ipv4"), state.host, sizeof(state.host));
  ImGui::InputInt(locale::tr("consoles.debug_tcp"), &state.debug_port);
  ImGui::InputInt(locale::tr("consoles.udp_logs"), &state.udp_port);
  normalize_ports(state);
  ImGui::Spacing();

  if (!state.client.connected()) {
    if (ui::primary_button(locale::tr("consoles.connect"), ui::full_button(42))) {
      connect_console(state);
    }
  } else {
    if (ui::danger_button(locale::tr("consoles.disconnect"), ui::full_button(42))) {
      disconnect_console(state);
    }
  }

  if (state.client.connected()) {
    if (ui::soft_button(locale::tr("consoles.ping_payload"), ui::full_button(40))) {
      set_status(state, state.client.ping() ? "Ping OK" : state.client.last_error());
    }
    if (ui::danger_button(locale::tr("consoles.shutdown_payload"), ui::full_button(40))) {
      set_status(state, state.client.shutdown_payload() ? "Shutdown sent" : state.client.last_error());
    }
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ui::draw_capabilities(state.hello);
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("ConsoleRuntime", locale::tr("consoles.runtime"), ImVec2(0, avail.y));
  ImGui::TextColored(state.client.connected() ? ui::colors().success : ui::colors().danger,
                     "%s", state.client.connected() ? locale::tr("consoles.session_open") : locale::tr("consoles.no_session"));
  ImGui::Spacing();
  ImGui::TextWrapped("%s", locale::tr("consoles.runtime_desc"));
  ImGui::Spacing();
  ImGui::Text(locale::tr("consoles.debug_endpoint"), state.host, state.debug_port);
  ImGui::Text(locale::tr("consoles.udp_listener"), "0.0.0.0", state.udp_port);
  ImGui::TextWrapped("%s", locale::tr("consoles.console_file_log"));
  ImGui::Spacing();

  if (!state.udp_listener.running()) {
    if (ui::soft_button(locale::tr("consoles.start_udp"), ui::full_button(40))) {
      std::string error;
      if (ensure_udp_listener(state, error)) {
        set_status(state, locale::tr("connect.udp_started"));
      } else {
        set_status(state, error);
      }
    }
  } else {
    if (ui::soft_button(locale::tr("consoles.restart_udp"), ui::full_button(40))) {
      state.udp_listener.stop();
      std::string error;
      if (ensure_udp_listener(state, error)) {
        set_status(state, locale::tr("connect.udp_restarted"));
      } else {
        set_status(state, error);
      }
    }
    if (ui::soft_button(locale::tr("consoles.stop_udp"), ui::full_button(40))) {
      state.udp_listener.stop();
      set_status(state, locale::tr("connect.udp_stopped"));
    }
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

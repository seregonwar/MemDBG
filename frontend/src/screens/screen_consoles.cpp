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

  /* Poll async discovery result. */
  if (state.discovery_pending && state.discovery_future.valid()) {
    auto fstatus = state.discovery_future.wait_for(std::chrono::milliseconds(0));
    if (fstatus == std::future_status::ready) {
      state.discovery_pending = false;
      bool ok = false;
      try {
        ok = state.discovery_future.get();
      } catch (...) {
        ok = false;
      }
      if (!ok && !state.discovery_error.empty()) {
        set_status(state, state.discovery_error);
      } else if (ok && state.discovered_consoles.empty()) {
        set_status(state, "No MemDBG payloads found on the local network.");
      } else if (ok) {
        set_status(state, "Found " + std::to_string(state.discovered_consoles.size()) + " payload(s).");
      }
    }
  }

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

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::Text("Auto-Discovery");
  ImGui::TextWrapped("Broadcast a UDP ping to find MemDBG payloads on the LAN.");
  ImGui::Spacing();

  if (state.discovery_pending) {
    ImGui::Text("Searching...");
  } else if (ui::soft_button("Discover Consoles", ui::full_button(40))) {
    state.discovery_pending = true;
    state.discovery_error.clear();
    state.discovered_consoles.clear();
    state.discovery_future = std::async(std::launch::async, [&state]() -> bool {
      return state.discovery_client.discover(
          MEMDBG_DEFAULT_DISCOVERY_PORT, 1.5, state.discovered_consoles,
          state.discovery_error);
    });
  }

  if (!state.discovered_consoles.empty()) {
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::Text("Discovered payloads");
    for (const auto &console : state.discovered_consoles) {
      std::string label = console.ip + ":" + std::to_string(console.debug_port);
      if (ImGui::Button(label.c_str(), ui::full_button(32))) {
        std::snprintf(state.host, sizeof(state.host), "%s", console.ip.c_str());
        state.debug_port = console.debug_port;
        state.udp_port = console.udp_log_port ? console.udp_log_port : state.udp_port;
        normalize_ports(state);
        set_status(state, "Selected " + console.ip);
      }
    }
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

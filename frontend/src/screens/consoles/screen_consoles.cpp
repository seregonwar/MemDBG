/*
 * MemDBG - Consoles screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "confirm_modal.hpp"

#include <cstdio>
#include <string>

namespace memdbg::frontend {

namespace {

static std::string target_endpoint(const ConsoleTarget &target) {
  return target.host + ":" + std::to_string(target.debug_port) +
         " / UDP " + std::to_string(target.udp_port);
}

static void persist_console_targets(AppState &state, const std::string &ok_message) {
  std::string error;
  if (save_frontend_settings(state, &error)) {
    set_status(state, ok_message);
    push_notification(state, ok_message, 3.0);
  } else {
    set_status(state, error);
    push_notification(state, std::string(locale::tr("consoles.cannot_save_targets")) + ": " + error, 5.0);
  }
}

static void use_discovered_console(AppState &state, const DiscoveryConsole &console) {
  const std::string name = !console.name.empty() ? console.name : console.ip;
  std::snprintf(state.target_name, sizeof(state.target_name), "%s", name.c_str());
  std::snprintf(state.host, sizeof(state.host), "%s", console.ip.c_str());
  state.debug_port = console.debug_port;
  state.udp_port = console.udp_log_port ? console.udp_log_port : state.udp_port;
  normalize_ports(state);
}

static void draw_saved_targets_table(AppState &state, bool locked) {
  ensure_console_targets(state);
  const float scl = ui::dpi_scale();
  const ImGuiTableFlags flags =
      ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_BordersOuter |
      ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY;

  if (ImGui::BeginTable("ConsoleTargetsTable", 3, flags, ImVec2(0, 150.0f * scl))) {
    ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 1.1f);
    ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Ports", ImGuiTableColumnFlags_WidthFixed, 100.0f * scl);
    ImGui::TableHeadersRow();

    for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
      const ConsoleTarget &target = state.console_targets[static_cast<size_t>(i)];
      const bool selected = i == state.selected_target_index;
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::BeginDisabled(locked);
      const std::string label = target.name + "##TargetRow" + std::to_string(i);
      if (ImGui::Selectable(label.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
        select_console_target(state, i);
      ImGui::EndDisabled();
      if (selected) ImGui::SetItemDefaultFocus();

      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(target.host.c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::Text("%d/%d", target.debug_port, target.udp_port);
    }
    ImGui::EndTable();
  }
}

} // namespace

void draw_consoles(AppState &state, ImVec2 avail) {
  ensure_console_targets(state);
  const bool connected = state.client.connected();
  const bool locked = connected || state.connect_pending;
  const float gap = 16.0f;
  const bool mobile = avail.x < 500.0f;
  const float col_w = mobile ? avail.x : (avail.x - gap) * 0.5f;

  ui::begin_panel("ConsoleTargets", "Console Targets", ImVec2(col_w, avail.y));
  ImGui::TextColored(ui::colors().primary2, "%s  Saved targets", icons::kTarget);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%zu profile(s)", state.console_targets.size());
  ImGui::Spacing();
  draw_saved_targets_table(state, locked);
  ImGui::Spacing();

  const ConsoleTarget current_target = {
      state.target_name, state.host, state.debug_port, state.udp_port
  };
  const std::string preview = current_target.name + "  " + target_endpoint(current_target);
  ImGui::BeginDisabled(locked);
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::BeginCombo("Target profile", preview.c_str())) {
    for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
      const ConsoleTarget &target = state.console_targets[static_cast<size_t>(i)];
      const bool selected = i == state.selected_target_index;
      const std::string label = target.name + "  " + target_endpoint(target);
      if (ImGui::Selectable(label.c_str(), selected)) select_console_target(state, i);
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }
  ImGui::InputText("Name", state.target_name, sizeof(state.target_name));
  ImGui::InputText(locale::tr("consoles.console_ipv4"), state.host, sizeof(state.host));
  ImGui::InputInt(locale::tr("consoles.debug_tcp"), &state.debug_port);
  ImGui::InputInt(locale::tr("consoles.udp_logs"), &state.udp_port);
  normalize_ports(state);
  ImGui::Spacing();

  const float action_gap = 6.0f;
  const float action_w = (ImGui::GetContentRegionAvail().x - action_gap * 2.0f) / 3.0f;
  if (ui::soft_button((std::string(icons::kSave) + "  Update").c_str(), ImVec2(action_w, 38.0f))) {
    save_current_console_target(state);
    persist_console_targets(state, locale::tr("consoles.console_target_updated"));
  }
  ImGui::SameLine(0, action_gap);
  if (ui::primary_button((std::string(icons::kAdd) + "  Add").c_str(), ImVec2(action_w, 38.0f))) {
    add_console_target(state);
    persist_console_targets(state, locale::tr("consoles.console_target_added"));
  }
  ImGui::SameLine(0, action_gap);
  if (ui::danger_button((std::string(icons::kTrash) + "  Remove").c_str(), ImVec2(action_w, 38.0f))) {
    remove_selected_console_target(state);
    persist_console_targets(state, locale::tr("consoles.console_target_removed"));
  }
  ImGui::EndDisabled();

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  if (!connected) {
    if (ui::primary_button((std::string(icons::kConnect) + "  " + locale::tr("consoles.connect")).c_str(),
                           ui::full_button(42))) {
      save_current_console_target(state);
      connect_console(state);
    }
  } else {
    ImGui::BeginDisabled(client_async_busy(state));
    if (ui::danger_button((std::string(icons::kDisconnect) + "  " + locale::tr("consoles.disconnect")).c_str(),
                          ui::full_button(42))) {
      ImGui::OpenPopup("ConfirmDisconnectConsoles");
    }
    static bool skip_disconnect_c = false;
    if (ui::confirm_modal("ConfirmDisconnectConsoles",
                          locale::tr("consoles.confirm_disconnect"), nullptr,
                          &skip_disconnect_c, true)) {
      disconnect_console(state);
    }
    ImGui::EndDisabled();
  }

  if (connected) {
    ImGui::BeginDisabled(client_async_busy(state));
    if (ui::soft_button((std::string(icons::kGauge) + "  " + locale::tr("consoles.ping_payload")).c_str(),
                        ui::full_button(40))) {
      set_status(state, state.client.ping() ? locale::tr("consoles.ping_ok") : state.client.last_error());
    }
    if (ui::danger_button((std::string(icons::kDisconnect) + "  " + locale::tr("consoles.shutdown_payload")).c_str(),
                          ui::full_button(40))) {
      ImGui::OpenPopup("ConfirmShutdownPayload");
    }
    static bool skip_shutdown = false;
    if (ui::confirm_modal("ConfirmShutdownPayload",
                          locale::tr("consoles.confirm_shutdown"), nullptr,
                          &skip_shutdown, true)) {
      set_status(state, state.client.shutdown_payload() ? locale::tr("consoles.shutdown_sent") : state.client.last_error());
    }
    ImGui::EndDisabled();
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
        set_status(state, locale::tr("consoles.no_payloads_found"));
      } else if (ok) {
        char disc_buf[128];
        std::snprintf(disc_buf, sizeof(disc_buf), locale::tr("consoles.found_n_payloads"), state.discovered_consoles.size());
        set_status(state, disc_buf);
      }
    }
  }

  if (!mobile) ImGui::SameLine(0, gap);
  if (mobile) ImGui::Spacing();
  ui::begin_panel("ConsoleRuntime", locale::tr("consoles.runtime"), ImVec2(mobile ? avail.x : 0, mobile ? 0 : avail.y));
  ImGui::TextColored(connected ? ui::colors().success : ui::colors().danger,
                     "%s", connected ? locale::tr("consoles.session_open") : locale::tr("consoles.no_session"));
  ImGui::Spacing();
  ImGui::TextWrapped("%s", locale::tr("consoles.runtime_desc"));
  ImGui::Spacing();
  ImGui::Text("Target: %s", state.target_name);
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
    const ImGuiTableFlags flags =
        ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_RowBg;
    if (ImGui::BeginTable("DiscoveredConsolesTable", 4, flags, ImVec2(0, 0))) {
      ImGui::TableSetupColumn("Name");
      ImGui::TableSetupColumn("Endpoint");
      ImGui::TableSetupColumn("Use", ImGuiTableColumnFlags_WidthFixed, 72.0f);
      ImGui::TableSetupColumn("Add", ImGuiTableColumnFlags_WidthFixed, 72.0f);
      ImGui::TableHeadersRow();
      for (int i = 0; i < static_cast<int>(state.discovered_consoles.size()); ++i) {
        const auto &console = state.discovered_consoles[static_cast<size_t>(i)];
        const std::string name = !console.name.empty() ? console.name : console.ip;
        const std::string endpoint = console.ip + ":" + std::to_string(console.debug_port) +
                                     " / UDP " + std::to_string(console.udp_log_port);
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::TextUnformatted(name.c_str());
        ImGui::TableSetColumnIndex(1);
        ImGui::TextUnformatted(endpoint.c_str());

        ImGui::TableSetColumnIndex(2);
        ImGui::BeginDisabled(locked);
        const std::string use_id = "Use##Discovered" + std::to_string(i);
        if (ui::soft_button(use_id.c_str(), ImVec2(-1, 30.0f))) {
          use_discovered_console(state, console);
          char sel_buf[128];
          std::snprintf(sel_buf, sizeof(sel_buf), locale::tr("consoles.selected_discovered"), console.ip.c_str());
          set_status(state, sel_buf);
        }
        ImGui::EndDisabled();

        ImGui::TableSetColumnIndex(3);
        ImGui::BeginDisabled(locked);
        const std::string add_id = "Add##Discovered" + std::to_string(i);
        if (ui::primary_button(add_id.c_str(), ImVec2(-1, 30.0f))) {
          use_discovered_console(state, console);
          add_console_target(state);
          persist_console_targets(state, locale::tr("consoles.discovered_target_saved"));
        }
        ImGui::EndDisabled();
      }
      ImGui::EndTable();
    }
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

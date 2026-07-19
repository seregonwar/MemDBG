/*
 * MemDBG - Home screen.
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

ImVec4 with_alpha(ImVec4 color, float alpha) {
  color.w *= alpha;
  return color;
}

void detail_row(const char *label, const char *value, ImVec4 value_color) {
  const bool mobile = ImGui::GetContentRegionAvail().x < 400.0f;
  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::SameLine(mobile ? 80.0f : 104.0f);
  ImGui::TextColored(value_color, "%s", value);
}

bool action_tile(const char *id, const char *icon, const char *title,
                 const char *meta, bool available) {
  const bool mobile = ImGui::GetContentRegionAvail().x < 400.0f;
  const float scl = mobile ? 1.0f : ui::dpi_scale();
  ImGui::PushID(id);
  const float h = 40.0f * scl;
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

  dl->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + h), ui::color_u32(bg), 1.0f * scl);
  dl->AddRect(pos, ImVec2(pos.x + w, pos.y + h), ui::color_u32(border), 1.0f * scl);

  const ImVec4 icon_color = available ? ui::colors().primary2 : ui::colors().dim;
  const ImVec4 title_color = available ? ui::colors().text : ui::colors().muted;
  const ImVec4 meta_color = available ? ui::colors().muted : ui::colors().dim;
  dl->AddText(ImVec2(pos.x + 12.0f * scl, pos.y + 10.0f * scl), ui::color_u32(icon_color), icon);
  dl->AddText(ImVec2(pos.x + 38.0f * scl, pos.y + 9.0f * scl), ui::color_u32(title_color), title);
  const ImVec2 meta_size = ImGui::CalcTextSize(meta);
  dl->AddText(ImVec2(pos.x + w - meta_size.x - 30.0f * scl, pos.y + 9.0f * scl),
              ui::color_u32(meta_color), meta);
  if (!available) {
    dl->AddText(ImVec2(pos.x + w - 20.0f * scl, pos.y + 9.0f * scl),
                ui::color_u32(ui::colors().dim), icons::kLock);
  }

  ImGui::PopID();
  return clicked;
}

} // namespace

void draw_home(AppState &state, ImVec2 avail) {
  const float scl = ui::dpi_scale();
  const bool connected = state.client.connected();
  const bool mobile = avail.x < 500.0f;

  const float col_w = mobile ? avail.x : avail.x * 0.40f;

  ui::begin_panel("HomeStatus", locale::tr("home.session"), ImVec2(col_w, mobile ? 0 : avail.y));
  ImGui::BeginGroup();
  ui::status_dot(state.connect_pending ? ui::colors().warning :
                 connected ? ui::colors().success : ui::colors().dim);
  ImGui::SameLine();
  ImGui::TextColored(state.connect_pending ? ui::colors().warning :
                     connected ? ui::colors().success : ui::colors().danger,
                     "%s", state.connect_pending ? locale::tr("home.connecting_status") :
                          connected ? locale::tr("home.connected_status") : locale::tr("home.not_connected"));
  ImGui::EndGroup();

  ImGui::Separator();

  char endpoint[96];
  std::snprintf(endpoint, sizeof(endpoint), "%s:%d", state.host, state.debug_port);
  detail_row(locale::tr("home.endpoint"), endpoint, connected ? ui::colors().text : ui::colors().muted);
  detail_row(locale::tr("home.udp_logs"), state.udp_listener.running() ? locale::tr("home.listening") : locale::tr("home.stopped"),
             state.udp_listener.running() ? ui::colors().success : ui::colors().dim);
  detail_row(locale::tr("home.process"), selected_process_name(state).c_str(),
             state.selected_pid != 0 ? ui::colors().text : ui::colors().muted);
  detail_row(locale::tr("home.pid"), std::to_string(state.selected_pid).c_str(),
             state.selected_pid != 0 ? ui::colors().text : ui::colors().dim);

  ImGui::Separator();

  if (connected) {
    ui::draw_capabilities(state.hello);
    ImGui::BeginDisabled(client_async_busy(state));
    const float btn_w = mobile ? ImGui::GetContentRegionAvail().x : 120.0f * scl;
    if (ui::soft_button((std::string(icons::kGauge) + "  " + locale::tr("home.ping")).c_str(), ImVec2(btn_w, 32.0f * scl))) {
      set_status(state, state.client.ping() ? locale::tr("home.ping_ok") : state.client.last_error());
    }
    if (!mobile) ImGui::SameLine();
    if (ui::danger_button((std::string(icons::kDisconnect) + "  " + locale::tr("home.drop")).c_str(), ImVec2(btn_w, 32.0f * scl))) {
      ImGui::OpenPopup("ConfirmDisconnectHome");
    }
    static bool skip_disconnect_h = false;
    if (ui::confirm_modal("ConfirmDisconnectHome",
                          locale::tr("consoles.confirm_disconnect"), nullptr,
                          &skip_disconnect_h, true)) {
      disconnect_console(state);
    }
    ImGui::EndDisabled();
  } else {
    ui::text_muted(locale::tr("home.no_active_session"));
    if (ui::primary_button((std::string(icons::kConnect) + "  " + locale::tr("home.configure")).c_str(), ImVec2(mobile ? ImGui::GetContentRegionAvail().x : 180.0f * scl, 32.0f * scl))) {
      state.screen = Screen::Consoles;
    }
  }
  ui::end_panel();

  if (!mobile) ImGui::SameLine();
  if (mobile) ImGui::Spacing();
  ui::begin_panel("HomeActions", locale::tr("home.command_palette"), ImVec2(mobile ? avail.x : 0, mobile ? 0 : avail.y));
  if (action_tile("Consoles", icons::kConsole, locale::tr("home.tile_consoles"), locale::tr("home.tile_consoles_meta"), true))
    state.screen = Screen::Consoles;
  if (action_tile("Processes", icons::kProcess, locale::tr("home.tile_processes"), connected ? locale::tr("home.tile_processes_meta_online") : locale::tr("home.tile_processes_meta_offline"), connected))
    { state.screen = Screen::Processes; if (!connected) set_status(state, locale::tr("home.connect_first_for_processes")); }
  if (action_tile("Memory", icons::kMemory, locale::tr("home.tile_memory"), connected ? locale::tr("home.tile_memory_meta_online") : locale::tr("home.tile_memory_meta_offline"), connected))
    { state.screen = Screen::Memory; if (!connected) set_status(state, locale::tr("home.connect_first_for_memory")); }
  if (action_tile("Scanner", icons::kScanner, locale::tr("home.tile_scanner"), connected ? locale::tr("home.tile_scanner_meta_online") : locale::tr("home.tile_scanner_meta_offline"), connected))
    { state.screen = Screen::Scanner; if (!connected) set_status(state, locale::tr("home.connect_first_for_scan")); }
  if (action_tile("Trainer", icons::kTrainer, locale::tr("home.tile_trainer"), connected ? locale::tr("home.tile_trainer_meta_online") : locale::tr("home.tile_trainer_meta_offline"), connected))
    { state.screen = Screen::Trainer; if (!connected) set_status(state, locale::tr("home.connect_first_for_trainer")); }
  if (action_tile("Logs", icons::kLogs, locale::tr("home.tile_logs"), state.udp_listener.running() ? locale::tr("home.tile_logs_meta_listening") : locale::tr("home.tile_logs_meta_stopped"), true))
    state.screen = Screen::Logs;
  if (action_tile("Settings", icons::kSettings, locale::tr("home.tile_settings"), locale::tr("home.tile_settings_meta"), true))
    state.screen = Screen::Settings;
  ImGui::Separator();
  detail_row(locale::tr("home.scan_hits"), std::to_string(state.scan_result.count).c_str(), ui::colors().muted);
  detail_row(locale::tr("home.maps"), std::to_string(state.maps.size()).c_str(), ui::colors().muted);
  detail_row(locale::tr("home.trainer_entries"), std::to_string(state.plugin.cheats.size()).c_str(), ui::colors().muted);
  ui::end_panel();
}

} // namespace memdbg::frontend

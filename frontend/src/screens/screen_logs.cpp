/*
 * MemDBG - Logs screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

namespace memdbg::frontend {

void draw_logs(AppState &state, ImVec2 avail) {
  ui::begin_panel("LogsPanel", locale::tr("logs.udp_telemetry"), avail);

  if (!state.udp_listener.running()) {
    if (ui::soft_button((std::string(icons::kPlay) + "  " + locale::tr("logs.start_listener")).c_str(), ImVec2(150, 38))) {
      std::string error;
      if (ensure_udp_listener(state, error)) set_status(state, locale::tr("logs.started"));
      else set_status(state, error);
    }
  } else {
    if (ui::soft_button((std::string(icons::kStop) + "  " + locale::tr("logs.stop_listener")).c_str(), ImVec2(150, 38))) { state.udp_listener.stop(); set_status(state, locale::tr("logs.stopped")); }
  }
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kTrash) + "  " + locale::tr("logs.clear")).c_str(), ImVec2(110, 38))) state.udp_listener.clear();
  ImGui::SameLine();
  auto logs = state.udp_listener.snapshot();
  if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("logs.copy")).c_str(), ImVec2(110, 38))) {
    if (!logs.empty()) {
      std::string all;
      for (const auto &line : logs) all += line + "\n";
      ImGui::SetClipboardText(all.c_str());
      set_status(state, locale::tr("logs.copied"));
    } else {
      set_status(state, locale::tr("logs.no_logs_to_copy"));
    }
  }
  ImGui::SameLine();
  const auto log_stats = state.udp_listener.stats();
  ImGui::TextColored(ui::colors().dim,
    "UDP %u | in %llu | lost %llu | evicted %llu | cap %d",
    static_cast<unsigned>(log_stats.port),
    static_cast<unsigned long long>(log_stats.received),
    static_cast<unsigned long long>(log_stats.dropped),
    static_cast<unsigned long long>(log_stats.evicted),
    log_stats.ring_capacity);
  if (log_stats.bind_attempts > 1) {
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().warning, "(bind took %d retries)", log_stats.bind_attempts);
  }

  std::string err = state.udp_listener.last_error();
  if (!err.empty()) ImGui::TextColored(ui::colors().warning, "%s: %s", locale::tr("logs.udp_error"), err.c_str());

  ImGui::Spacing();
  ImGui::BeginChild("LogLines", ImVec2(0,0), true);
  if (logs.empty()) {
    ui::draw_empty_state(locale::tr("logs.no_messages"), locale::tr("logs.no_messages_desc"));
  } else {
    const float wrap_x = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    for (const auto &line : logs) {
      ImGui::PushTextWrapPos(wrap_x);
      ImGui::TextUnformatted(line.c_str());
      ImGui::PopTextWrapPos();
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.0f) ImGui::SetScrollHereY(1.0f);
  }
  ImGui::EndChild();

  ui::end_panel();
}

} // namespace memdbg::frontend

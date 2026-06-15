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
  ui::begin_panel("LogsPanel", "UDP Telemetry", avail);

  if (!state.udp_listener.running()) {
    if (ui::soft_button((std::string(icons::kPlay) + "  Start Listener").c_str(), ImVec2(150, 38))) {
      std::string error;
      if (ensure_udp_listener(state, error)) set_status(state, "UDP log listener started");
      else set_status(state, error);
    }
  } else {
    if (ui::soft_button((std::string(icons::kStop) + "  Stop Listener").c_str(), ImVec2(150, 38))) { state.udp_listener.stop(); set_status(state, "UDP log listener stopped"); }
  }
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kTrash) + "  Clear").c_str(), ImVec2(110, 38))) state.udp_listener.clear();
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
  if (!err.empty()) ImGui::TextColored(ui::colors().warning, "UDP error: %s", err.c_str());

  ImGui::Spacing();
  auto logs = state.udp_listener.snapshot();
  ImGui::BeginChild("LogLines", ImVec2(0,0), false, ImGuiWindowFlags_HorizontalScrollbar);
  if (logs.empty()) {
    ui::draw_empty_state("No UDP messages yet", "Payload telemetry will appear here after the console sends datagrams.");
  } else {
    for (const auto &line : logs) ImGui::TextUnformatted(line.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.0f) ImGui::SetScrollHereY(1.0f);
  }
  ImGui::EndChild();

  ui::end_panel();
}

} // namespace memdbg::frontend

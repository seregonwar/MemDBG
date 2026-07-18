/*
 * MemDBG - Monitoring screen (unified UDP Logs, Kernel Log, Telemetry, Tracer).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "platform.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "confirm_modal.hpp"

namespace memdbg::frontend {

/* Local helper — keeps the action_journal module free of platform.hpp */
static std::filesystem::path journal_path() {
  return platform::app_data_dir() / "logs" / "memdbg_actions.log";
}

static void draw_actions_tab(AppState &state, ImVec2 avail);

/* ---- UDP Logs (original draw_logs content) ---- */
static void draw_logs_tab(AppState &state, ImVec2 avail) {
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
  static bool skip_clear_logs = false;
  if (ui::soft_button((std::string(icons::kTrash) + "  " + locale::tr("logs.clear")).c_str(), ImVec2(110, 38)))
    ImGui::OpenPopup("ConfirmClearLogs");
  if (ui::confirm_modal("ConfirmClearLogs",
                        locale::tr("logs.confirm_clear"), nullptr,
                        &skip_clear_logs, true))
    state.udp_listener.clear();
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

/* ---- Unified Monitoring screen ---- */
void draw_logs(AppState &state, ImVec2 avail) {
  static int mon_tab = 0; /* 0=UDP Logs, 1=Kernel Log, 2=Telemetry, 3=Tracer */

  if (ImGui::BeginTabBar("MonitoringTabs")) {
    if (ImGui::BeginTabItem(locale::tr("nav.logs"))) {
      mon_tab = 0;
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(locale::tr("nav.klog"))) {
      mon_tab = 1;
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(locale::tr("nav.telemetry"))) {
      mon_tab = 2;
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(locale::tr("nav.tracer"))) {
      mon_tab = 3;
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(locale::tr("logs.actions_tab"))) {
      mon_tab = 4;
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }

  switch (mon_tab) {
  case 0: draw_logs_tab(state, avail); break;
  case 1: draw_klog(state, avail); break;
  case 2: draw_telemetry(state, avail); break;
  case 3: draw_tracer(state, avail); break;
  case 4: draw_actions_tab(state, avail); break;
  }
}

/* ---- Actions Journal tab ---- */
static void draw_actions_tab(AppState &, ImVec2 avail) {
  ui::begin_panel("ActionsPanel", locale::tr("logs.actions_title"), avail);

  ImGui::TextWrapped("%s", locale::tr("logs.actions_desc"));
  ImGui::Spacing();

  // Reload actions from the journal file
  static std::vector<ActionJournalEntry> actions;
  static double last_reload = 0.0;
  if (ImGui::GetTime() - last_reload > 2.0 || actions.empty()) {
    ActionJournal::load_recent(journal_path(), actions, 200);
    last_reload = ImGui::GetTime();
  }

  if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("logs.actions_reload")).c_str(), ImVec2(140, 38))) {
    ActionJournal::load_recent(journal_path(), actions, 200);
    last_reload = ImGui::GetTime();
  }
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%zu %s", actions.size(), locale::tr("logs.actions_count"));

  ImGui::Spacing();
  ImGui::BeginChild("ActionsList", ImVec2(0, 0), true);
  if (actions.empty()) {
    ui::draw_empty_state(locale::tr("logs.no_actions"), locale::tr("logs.no_actions_desc"));
  } else {
    for (const auto &entry : actions) {
      char time_buf[24];
      std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S",
                    std::localtime(&entry.timestamp));
      ImGui::TextColored(ui::colors().dim, "[%s]", time_buf);
      ImGui::SameLine();
      ImGui::TextColored(ui::colors().primary, "%s", entry.action.c_str());
      if (!entry.detail.empty() && entry.detail != "{}") {
        ImGui::SameLine();
        ImGui::TextColored(ui::colors().muted, "%s", entry.detail.c_str());
      }
    }
  }
  ImGui::EndChild();

  ui::end_panel();
}

} // namespace memdbg::frontend

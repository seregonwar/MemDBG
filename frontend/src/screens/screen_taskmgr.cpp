/*
 * MemDBG - Task Manager screen (Windows-style process/resource monitor).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

namespace memdbg::frontend {

namespace {

/* ---- Formatting helpers ---- */

inline std::string format_bytes_tm(uint64_t bytes) {
  if (bytes < 1024ULL) return std::to_string(bytes) + " B";
  double v;
  const char *unit;
  if (bytes < 1024ULL * 1024ULL) {
    v = static_cast<double>(bytes) / 1024.0; unit = "KiB";
  } else if (bytes < 1024ULL * 1024ULL * 1024ULL) {
    v = static_cast<double>(bytes) / (1024.0 * 1024.0); unit = "MiB";
  } else {
    v = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0); unit = "GiB";
  }
  char buf[48];
  std::snprintf(buf, sizeof(buf), "%.2f %s", v, unit);
  return buf;
}

inline std::string format_count_tm(uint64_t count) {
  if (count < 1000ULL) return std::to_string(count);
  char buf[48];
  if (count < 1000000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fK", static_cast<double>(count) / 1000.0);
  } else if (count < 1000000000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fM", static_cast<double>(count) / 1000000.0);
  } else {
    std::snprintf(buf, sizeof(buf), "%.1fB", static_cast<double>(count) / 1000000000.0);
  }
  return buf;
}

inline std::string format_uptime_tm(uint64_t seconds) {
  uint64_t d = seconds / 86400U;
  uint64_t h = seconds / 3600U;
  uint64_t m = (seconds % 3600U) / 60U;
  uint64_t s = seconds % 60U;
  char buf[48];
  if (d > 0) {
    h = (seconds % 86400U) / 3600U;
    std::snprintf(buf, sizeof(buf), "%llud %lluh %llum",
                  static_cast<unsigned long long>(d),
                  static_cast<unsigned long long>(h),
                  static_cast<unsigned long long>(m));
  } else if (h > 0) {
    std::snprintf(buf, sizeof(buf), "%lluh %llum %llus",
                  static_cast<unsigned long long>(h),
                  static_cast<unsigned long long>(m),
                  static_cast<unsigned long long>(s));
  } else if (m > 0) {
    std::snprintf(buf, sizeof(buf), "%llum %llus",
                  static_cast<unsigned long long>(m),
                  static_cast<unsigned long long>(s));
  } else {
    std::snprintf(buf, sizeof(buf), "%llus", static_cast<unsigned long long>(s));
  }
  return buf;
}

/* ---- System overview tiles ---- */

struct SysTile {
  const char *icon;
  const char *label;
  std::string value;
  std::string subtitle;
  ImVec4 color;
};

static void draw_sys_tile(const SysTile &tile, ImVec2 size) {
  ImGui::PushID(tile.label);
  ImVec2 pos = ImGui::GetCursorScreenPos();
  ImGui::InvisibleButton("##systile", size);
  const bool hovered = ImGui::IsItemHovered();

  ImDrawList *dl = ImGui::GetWindowDrawList();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  const ImVec4 bg = hovered ? ui::colors().bg3 : ui::colors().bg2;
  dl->AddRectFilled(pos, max, ui::color_u32(bg), 6.0f);
  dl->AddRect(pos, max, ui::color_u32(hovered ? ui::colors().border_hot : ui::colors().border), 6.0f);

  const float pad = 12.0f;
  const float line_h = ImGui::GetTextLineHeight();
  dl->PushClipRect(pos, max, true);
  dl->AddText(ImVec2(pos.x + pad, pos.y + 11.0f), ui::color_u32(tile.color), tile.icon);
  dl->AddText(ImVec2(pos.x + pad + 28.0f, pos.y + 11.0f), ui::color_u32(ui::colors().muted), tile.label);
  dl->AddText(ImVec2(pos.x + pad, pos.y + 16.0f + line_h), ui::color_u32(ui::colors().text), tile.value.c_str());
  if (!tile.subtitle.empty())
    dl->AddText(ImVec2(pos.x + pad, pos.y + 19.0f + line_h * 2.0f), ui::color_u32(ui::colors().dim), tile.subtitle.c_str());
  dl->PopClipRect();

  ImGui::PopID();
}

/* ---- Process table + detail ---- */

static void select_taskmgr_process(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.processes.size())) return;
  state.taskmgr_selected_row = row;
  state.taskmgr_selected_pid = state.processes[row].pid;
  state.taskmgr_map_summary = ProcessMapSummary{};
  state.taskmgr_has_process_info = false;
}

static void refresh_selected_process_data(AppState &state) {
  if (state.taskmgr_selected_pid <= 0 || !state.client.connected()) return;

  /* Fetch process info if not already loaded */
  if (!state.taskmgr_has_process_info) {
    if (state.client.process_info(state.taskmgr_selected_pid, state.taskmgr_process_info)) {
      state.taskmgr_has_process_info = true;
    } else {
      state.taskmgr_has_process_info = true;  /* stop retrying on failure */
      if (!state.client.last_error().empty())
        set_status(state, state.client.last_error());
    }
  }

  /* Fetch maps and compute summary */
  std::vector<MapEntry> maps;
  if (state.client.process_maps(state.taskmgr_selected_pid, maps)) {
    ProcessMapSummary summary;
    summary.loaded = true;
    for (const auto &map : maps) {
      if (map.end <= map.start) continue;
      uint64_t size = map.end - map.start;
      summary.map_count++;
      summary.total_mapped += size;
      if (map.protection & 1U) summary.readable_bytes += size;
      if (map.protection & 2U) summary.writable_bytes += size;
      if (map.protection & 4U) summary.executable_bytes += size;
      if ((map.protection & 3U) == 3U && !(map.protection & 4U)) {
        /* RW, non-exec — heap-like */
        summary.rw_heap_bytes += size;
      }
    }
    state.taskmgr_map_summary = summary;
  } else {
    state.taskmgr_map_summary.loaded = true;  /* stop retrying on failure */
    if (!state.client.last_error().empty())
      set_status(state, state.client.last_error());
  }
}

/* ---- Draw functions ---- */

static void draw_system_overview(AppState &state, float width) {
  if (!state.client.connected()) {
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("taskmgr.no_session"));
    return;
  }

  const auto &t = state.telemetry_snap;
  const bool has_telemetry = state.telemetry_available;
  const bool uptime_ok = has_telemetry && t.uptime_seconds > 0U &&
                         t.uptime_seconds <= 366ULL * 24ULL * 60ULL * 60ULL;

  const float gap = 10.0f;
  const int cols = width >= 900.0f ? 6 : (width >= 600.0f ? 4 : (width >= 360.0f ? 3 : 2));
  const float tile_w = (width - gap * static_cast<float>(cols - 1)) / static_cast<float>(cols);
  const ImVec2 tile_sz(std::max(128.0f, tile_w), 68.0f);

  /* Platform info (always available from hello) */
  std::string platform_str = platform_name(state.hello.platform_id);
  draw_sys_tile(SysTile{icons::kConsole, locale::tr("taskmgr.platform"),
      platform_str, state.hello.name, ui::colors().primary2}, tile_sz);

  /* Uptime */
  if (cols > 1) ImGui::SameLine(0, gap);
  draw_sys_tile(SysTile{icons::kOnline, locale::tr("taskmgr.uptime"),
      uptime_ok ? format_uptime_tm(t.uptime_seconds) : (has_telemetry ? "---" : locale::tr("taskmgr.polling")),
      uptime_ok ? locale::tr("taskmgr.since_boot") : "",
      uptime_ok ? ui::colors().success : ui::colors().dim}, tile_sz);

  /* Connections */
  if (cols > 2) ImGui::SameLine(0, gap);
  draw_sys_tile(SysTile{icons::kTerminal, locale::tr("taskmgr.connections"),
      has_telemetry ? std::to_string(t.active_connections) : "-",
      has_telemetry ? std::string(locale::tr("taskmgr.thread_pool_tm")) + " " + std::to_string(t.thread_pool_size) : "",
      ui::colors().text}, tile_sz);

  /* I/O read */
  if (cols > 3) ImGui::SameLine(0, gap);
  draw_sys_tile(SysTile{icons::kImport, locale::tr("taskmgr.read"),
      has_telemetry ? format_bytes_tm(t.total_bytes_read) : "-",
      has_telemetry ? std::string(locale::tr("taskmgr.calls")) + " " + format_count_tm(t.total_read_calls) : "",
      ui::colors().success}, tile_sz);

  /* I/O write */
  if (cols > 4) ImGui::SameLine(0, gap);
  draw_sys_tile(SysTile{icons::kExport, locale::tr("taskmgr.written"),
      has_telemetry ? format_bytes_tm(t.total_bytes_written) : "-",
      has_telemetry ? std::string(locale::tr("taskmgr.calls")) + " " + format_count_tm(t.total_write_calls) : "",
      ui::colors().primary2}, tile_sz);

  /* Cache hits */
  if (cols > 5) ImGui::SameLine(0, gap);
  if (has_telemetry) {
    uint64_t total_cache = t.scan_cache_hits + t.scan_cache_misses;
    char cache_val[48];
    if (total_cache > 0U) {
      double hr = static_cast<double>(t.scan_cache_hits) / static_cast<double>(total_cache);
      std::snprintf(cache_val, sizeof(cache_val), "%.0f%%", hr * 100.0);
    } else {
      std::snprintf(cache_val, sizeof(cache_val), "n/a");
    }
    char cache_sub[64];
    std::snprintf(cache_sub, sizeof(cache_sub), "%s/%s",
                  format_count_tm(t.scan_cache_hits).c_str(),
                  format_count_tm(t.scan_cache_misses).c_str());
    draw_sys_tile(SysTile{icons::kGauge, locale::tr("taskmgr.cache_hitrate"),
        cache_val, cache_sub, ui::colors().warning}, tile_sz);
  } else {
    draw_sys_tile(SysTile{icons::kGauge, locale::tr("taskmgr.cache_hitrate"), "-", "", ui::colors().dim}, tile_sz);
  }
}

static void draw_process_table(AppState &state, float avail_w) {
  const float scl = ui::dpi_scale();
  if (!state.client.connected()) {
    ui::draw_empty_state(locale::tr("taskmgr.connect_first"), locale::tr("taskmgr.connect_first_desc"));
    return;
  }

  if (state.processes.empty()) {
    ImGui::Spacing(); ImGui::Spacing();
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("taskmgr.refresh_hint"));
    return;
  }

  const float row_h = ImGui::GetTextLineHeight() + ImGui::GetStyle().FramePadding.y * 2.0f;
  const float table_h = avail_w > 0.0f ? std::max(120.0f, avail_w * 0.55f) : 300.0f;
  const float tbl_h = std::min(table_h, row_h * static_cast<float>(state.processes.size() + 1) + 4.0f);

  if (ImGui::BeginTable("TaskMgrTable", 5,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable,
        ImVec2(0, tbl_h))) {
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_pid"), ImGuiTableColumnFlags_WidthFixed, 70.0f * scl);
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_name"));
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_titleid"), ImGuiTableColumnFlags_WidthFixed, 100.0f * scl);
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_maps"), ImGuiTableColumnFlags_WidthFixed, 80.0f * scl);
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_memory"), ImGuiTableColumnFlags_WidthFixed, 100.0f * scl);
    ImGui::TableHeadersRow();

    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const auto &proc = state.processes[i];
      ImGui::TableNextRow();
      const bool selected = i == state.taskmgr_selected_row;

      ImGui::TableSetColumnIndex(0);
      std::string pid_label = std::to_string(proc.pid) + "##tm" + std::to_string(i);
      if (ImGui::Selectable(pid_label.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
        select_taskmgr_process(state, i);

      ImGui::TableSetColumnIndex(1);
      const char *name = proc.name.c_str();
      ImGui::TextUnformatted(name[0] ? name : "?");
      if (ImGui::IsItemHovered() && name[0]) ImGui::SetTooltip("%s", name);

      ImGui::TableSetColumnIndex(2);
      if (selected && state.taskmgr_has_process_info)
        ImGui::TextColored(ui::colors().primary2, "%s", state.taskmgr_process_info.title_id.c_str());
      else
        ImGui::TextColored(ui::colors().dim, "%s", selected ? "..." : "-");

      ImGui::TableSetColumnIndex(3);
      if (selected && state.taskmgr_map_summary.loaded)
        ImGui::Text("%zu", state.taskmgr_map_summary.map_count);
      else
        ImGui::TextColored(ui::colors().dim, "%s", selected ? "..." : "-");

      ImGui::TableSetColumnIndex(4);
      if (selected && state.taskmgr_map_summary.loaded)
        ImGui::Text("%s", format_bytes_tm(state.taskmgr_map_summary.total_mapped).c_str());
      else
        ImGui::TextColored(ui::colors().dim, "%s", selected ? "..." : "-");
    }
    ImGui::EndTable();
  }
}

static void draw_detail_panel(AppState &state, float width) {
  if (state.taskmgr_selected_pid <= 0) {
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("taskmgr.select_pid_hint"));
    return;
  }

  if (!state.taskmgr_map_summary.loaded) {
    refresh_selected_process_data(state);
  }

  const float scl = ui::dpi_scale();

  /* Process info header */
  const char *proc_name = "?";
  for (const auto &p : state.processes)
    if (p.pid == state.taskmgr_selected_pid) { proc_name = p.name.c_str(); break; }

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg3);
  ImGui::BeginChild("TaskMgrDetail", ImVec2(width, 170.0f * scl), true);

  /* Row 1: PID badge + name */
  ImGui::TextColored(ui::colors().primary2, "PID %d", state.taskmgr_selected_pid);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().text, " — %s", proc_name);

  if (state.taskmgr_has_process_info) {
    const auto &info = state.taskmgr_process_info;
    if (!info.title_id.empty())
      ImGui::TextColored(ui::colors().dim, "%s: %s", locale::tr("taskmgr.title_id"), info.title_id.c_str());
    if (!info.content_id.empty())
      ImGui::TextColored(ui::colors().dim, "%s: %s", locale::tr("taskmgr.content_id"), info.content_id.c_str());
    if (!info.path.empty()) {
      ImGui::TextColored(ui::colors().dim, "%s:", locale::tr("taskmgr.path"));
      ImGui::SameLine();
      ImGui::TextWrapped("%s", info.path.c_str());
    }
  } else {
    ImGui::TextColored(ui::colors().dim, "%s", locale::tr("taskmgr.fetching_info"));
  }

  ImGui::EndChild();
  ImGui::PopStyleColor();

  ImGui::Spacing();

  /* Memory breakdown */
  if (state.taskmgr_map_summary.loaded) {
    const auto &ms = state.taskmgr_map_summary;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg3);
    ImGui::BeginChild("TaskMgrMemBreakdown", ImVec2(width, 0.0f), true);

    ImGui::TextColored(ui::colors().muted, "%s:", locale::tr("taskmgr.memory_breakdown"));
    ImGui::Spacing();

    /* Progress-style bars */
    const float bar_h = 16.0f * scl;
    const float label_w = 90.0f * scl;
    const float pad_x = 6.0f * scl;

    auto draw_bar = [&](const char *label, uint64_t bytes, ImVec4 color) {
      ImGui::TextColored(ui::colors().dim, "%s", label);
      ImGui::SameLine(label_w);
      float frac = ms.total_mapped > 0U ? static_cast<float>(static_cast<double>(bytes) / static_cast<double>(ms.total_mapped)) : 0.0f;
      char val_buf[64];
      std::snprintf(val_buf, sizeof(val_buf), "%s", format_bytes_tm(bytes).c_str());
      ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
      ImGui::PushStyleColor(ImGuiCol_FrameBg, ui::colors().bg2);
      ImGui::ProgressBar(frac, ImVec2(ImGui::GetContentRegionAvail().x - pad_x, bar_h), val_buf);
      ImGui::PopStyleColor(2);
    };

    draw_bar(locale::tr("taskmgr.total_mapped"), ms.total_mapped, ui::colors().text);
    draw_bar(locale::tr("taskmgr.readable"), ms.readable_bytes, ui::colors().success);
    draw_bar(locale::tr("taskmgr.writable"), ms.writable_bytes, ui::colors().primary2);
    draw_bar(locale::tr("taskmgr.executable"), ms.executable_bytes, ui::colors().warning);
    draw_bar(locale::tr("taskmgr.rw_heap"), ms.rw_heap_bytes, ui::colors().link);

    ImGui::Spacing();
    ImGui::TextColored(ui::colors().dim, locale::tr("taskmgr.total_maps"), ms.map_count);

    ImGui::EndChild();
    ImGui::PopStyleColor();
  }

  /* Action buttons */
  ImGui::Spacing();
  if (state.hello.capabilities & MEMDBG_CAP_PROCESS_CONTROL) {
    if (ui::soft_button((std::string(icons::kStop) + "  " + locale::tr("taskmgr.stop_process")).c_str(), ImVec2(130.0f * scl, 30.0f * scl))) {
      if (state.client.process_stop(state.taskmgr_selected_pid)) {
        set_status(state, std::string(locale::tr("taskmgr.process_stopped")) + " PID " + std::to_string(state.taskmgr_selected_pid));
      } else {
        set_status(state, state.client.last_error());
      }
    }
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kPlay) + "  " + locale::tr("taskmgr.continue_process")).c_str(), ImVec2(150.0f * scl, 30.0f * scl))) {
      if (state.client.process_continue(state.taskmgr_selected_pid)) {
        set_status(state, std::string(locale::tr("taskmgr.process_continued")) + " PID " + std::to_string(state.taskmgr_selected_pid));
      } else {
        set_status(state, state.client.last_error());
      }
    }
    ImGui::SameLine();
    if (ui::danger_button((std::string(icons::kTrash) + "  " + locale::tr("taskmgr.kill_process")).c_str(), ImVec2(130.0f * scl, 30.0f * scl))) {
      if (state.client.process_kill(state.taskmgr_selected_pid)) {
        set_status(state, std::string(locale::tr("taskmgr.process_killed")) + " PID " + std::to_string(state.taskmgr_selected_pid));
      } else {
        set_status(state, state.client.last_error());
      }
    }
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().warning, " ⚠ %s", locale::tr("taskmgr.caution"));
  }
}

} // namespace

/* ---- Main draw ---- */

void draw_taskmgr(AppState &state, ImVec2 avail) {
  const float scl = ui::dpi_scale();
  const double now = ImGui::GetTime();

  /* Auto-refresh telemetry (every 1s when this screen is active) */
  if (state.client.connected() &&
      (state.hello.capabilities & MEMDBG_CAP_PERF_TELEMETRY) &&
      now >= state.taskmgr_next_telemetry) {
    state.taskmgr_next_telemetry = now + 1.0;
    if (!state.telemetry_pending) {
      request_telemetry_async(state);
    }
  }

  ui::begin_panel("TaskMgrPanel", locale::tr("taskmgr.title"), avail);

  /* ---- Toolbar ---- */
  ImGui::TextColored(ui::colors().primary2, "%s", locale::tr("taskmgr.system_overview"));
  ImGui::SameLine();
  const float right_x = ImGui::GetWindowContentRegionMax().x - 180.0f * scl;
  if (right_x > ImGui::GetCursorPosX() + 24.0f * scl) {
    ImGui::SetCursorPosX(right_x);
  }
  if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("taskmgr.refresh_processes")).c_str(),
                      ImVec2(172.0f * scl, 30.0f * scl))) {
    if (state.client.connected()) {
      if (!state.client.process_list(state.processes)) {
        set_status(state, state.client.last_error());
      } else {
        state.taskmgr_selected_row = -1;
        state.taskmgr_selected_pid = 0;
        state.taskmgr_map_summary = ProcessMapSummary{};
        state.taskmgr_has_process_info = false;
        set_status(state, locale::tr("taskmgr.processes_refreshed"));
      }
    }
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  /* ---- System overview tiles ---- */
  draw_system_overview(state, avail.x - 36.0f * scl);

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  /* ---- Process table + detail (split layout) ---- */
  const float tbl_width = state.taskmgr_selected_pid > 0
      ? (avail.x - 36.0f * scl) * 0.58f
      : (avail.x - 36.0f * scl);

  ImGui::TextColored(ui::colors().primary2, "%s", locale::tr("taskmgr.process_table"));

  /* Show process count and selected info in toolbar row */
  ImGui::SameLine();
  if (state.client.connected()) {
    ImGui::TextColored(ui::colors().dim, "— %zu %s | %s PID %d",
                       state.processes.size(),
                       locale::tr("taskmgr.processes"),
                       locale::tr("taskmgr.selected"),
                       state.taskmgr_selected_pid);
  }

  ImGui::Spacing();

  if (state.taskmgr_selected_pid > 0) {
    /* Side-by-side: process table | detail panel */
    draw_process_table(state, tbl_width);

    ImGui::SameLine(0, 12.0f * scl);

    ImGui::BeginGroup();
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.0f * scl, 8.0f * scl));
    ImGui::BeginChild("TaskMgrDetailOuter", ImVec2(0, 0), true);

    ImGui::TextColored(ui::colors().primary2, "%s", locale::tr("taskmgr.process_detail"));
    ImGui::SameLine();
    if (ImGui::SmallButton((std::string(icons::kRefresh) + "##detail").c_str())) {
      state.taskmgr_map_summary = ProcessMapSummary{};
      state.taskmgr_has_process_info = false;
      refresh_selected_process_data(state);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("taskmgr.refresh_detail_tip"));

    ImGui::Separator();
    draw_detail_panel(state, ImGui::GetContentRegionAvail().x);
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::EndGroup();
  } else {
    draw_process_table(state, tbl_width);
  }

  ui::end_panel();
}

} // namespace memdbg::frontend

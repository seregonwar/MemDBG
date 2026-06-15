/*
 * MemDBG - Telemetry / performance screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace memdbg::frontend {

namespace {

struct MetricItem {
  const char *icon;
  std::string label;
  std::string value;
  std::string subtitle;
  ImVec4 value_color;
};

inline std::string format_bytes(uint64_t bytes) {
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
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%.2f %s", v, unit);
  return buf;
}

inline std::string format_count(uint64_t count) {
  if (count < 1000ULL) return std::to_string(count);
  char buf[48];
  double v;
  const char *suffix;
  if (count < 1000000ULL) {
    v = static_cast<double>(count) / 1000.0; suffix = "K";
  } else if (count < 1000000000ULL) {
    v = static_cast<double>(count) / 1000000.0; suffix = "M";
  } else {
    v = static_cast<double>(count) / 1000000000.0; suffix = "B";
  }
  std::snprintf(buf, sizeof(buf), "%.1f%s", v, suffix);
  return buf;
}

inline std::string format_uptime(uint64_t seconds) {
  uint64_t h = seconds / 3600U;
  uint64_t m = (seconds % 3600U) / 60U;
  uint64_t s = seconds % 60U;
  char buf[48];
  if (h > 0) {
    std::snprintf(buf, sizeof(buf), "%lluh %llum %llus",
                  (unsigned long long)h, (unsigned long long)m,
                  (unsigned long long)s);
  } else if (m > 0) {
    std::snprintf(buf, sizeof(buf), "%llum %llus",
                  (unsigned long long)m, (unsigned long long)s);
  } else {
    std::snprintf(buf, sizeof(buf), "%llus", (unsigned long long)s);
  }
  return buf;
}

static void section_header(const char *title) {
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", title);
  ImGui::Separator();
  ImGui::Spacing();
}

static void draw_metric_tile(const MetricItem &item, ImVec2 size) {
  ImGui::PushID(item.label.c_str());
  ImVec2 pos = ImGui::GetCursorScreenPos();
  ImGui::InvisibleButton("##metric", size);
  const bool hovered = ImGui::IsItemHovered();

  ImDrawList *dl = ImGui::GetWindowDrawList();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  const ImVec4 bg = hovered ? ui::colors().bg3 : ui::colors().bg2;
  const ImVec4 border = hovered ? ui::colors().border_hot : ui::colors().border;

  dl->AddRectFilled(pos, max, ui::color_u32(bg), 8.0f);
  dl->AddRect(pos, max, ui::color_u32(border), 8.0f);
  dl->PushClipRect(pos, max, true);

  const float pad = 14.0f;
  const float line_h = ImGui::GetTextLineHeight();
  dl->AddText(ImVec2(pos.x + pad, pos.y + 13.0f),
              ui::color_u32(ui::colors().primary2), item.icon);
  dl->AddText(ImVec2(pos.x + pad + 34.0f, pos.y + 13.0f),
              ui::color_u32(ui::colors().muted), item.label.c_str());
  dl->AddText(ImVec2(pos.x + pad, pos.y + 15.0f + line_h),
              ui::color_u32(item.value_color), item.value.c_str());
  if (!item.subtitle.empty()) {
    dl->AddText(ImVec2(pos.x + pad, pos.y + 18.0f + line_h * 2.0f),
                ui::color_u32(ui::colors().dim), item.subtitle.c_str());
  }

  dl->PopClipRect();
  ImGui::PopID();
}

static void draw_metric_grid(const std::vector<MetricItem> &items, float width) {
  const float gap = 12.0f;
  const int columns = width >= 900.0f ? 4 : (width >= 560.0f ? 2 : 1);
  const float tile_w = (width - gap * static_cast<float>(columns - 1)) /
                       static_cast<float>(columns);
  const ImVec2 tile_size(std::max(160.0f, tile_w), 82.0f);

  for (size_t i = 0; i < items.size(); ++i) {
    const int col = static_cast<int>(i % static_cast<size_t>(columns));
    draw_metric_tile(items[i], tile_size);
    if (col + 1 < columns && i + 1 < items.size()) ImGui::SameLine(0, gap);
  }
}

static void draw_progress_row(const char *label, double fraction, ImVec4 color) {
  fraction = std::clamp(fraction, 0.0, 1.0);
  char percent[32];
  std::snprintf(percent, sizeof(percent), "%.1f%%", fraction * 100.0);

  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::SameLine();
  ImGui::TextColored(color, "%s", percent);
  ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
  ImGui::PushStyleColor(ImGuiCol_FrameBg, ui::colors().bg2);
  ImGui::ProgressBar(static_cast<float>(fraction), ImVec2(-1, 18), "");
  ImGui::PopStyleColor(2);
}

} // namespace

void draw_telemetry(AppState &state, ImVec2 avail) {
  const double now = ImGui::GetTime();

  if (state.client.connected() &&
      (state.hello.capabilities & MEMDBG_CAP_PERF_TELEMETRY)) {
    if (now >= state.next_telemetry_poll) {
      state.next_telemetry_poll = now + 1.0;
      state.telemetry_available = state.client.telemetry(state.telemetry_snap);
      if (!state.telemetry_available) {
        set_status(state, "Telemetry: " + state.client.last_error());
      }
    }
  }

  if (!state.client.connected()) {
    ui::begin_panel("TelemetryEmpty", "Payload Telemetry", avail);
    ui::draw_empty_state("Payload Required",
                         "Connect to a console running the MemDBG payload to see runtime telemetry.");
    ui::end_panel();
    return;
  }

  if (!(state.hello.capabilities & MEMDBG_CAP_PERF_TELEMETRY)) {
    ui::begin_panel("TelemetryUnsupported", "Payload Telemetry", avail);
    ui::draw_empty_state("Not Supported",
                         "The connected payload does not advertise the PERF_TELEMETRY capability.\n"
                         "Update to a newer payload build to enable performance telemetry.");
    ui::end_panel();
    return;
  }

  if (!state.telemetry_available) {
    ui::begin_panel("TelemetryWaiting", "Payload Telemetry", avail);
    ui::draw_empty_state("Polling...",
                         "Waiting for the first telemetry response from the payload.\n"
                         "Check the status bar for errors if this persists.");
    ui::end_panel();
    return;
  }

  const auto &t = state.telemetry_snap;
  const float panel_w = std::max(240.0f, avail.x);

  ui::begin_panel("TelemetryPanel", "Payload Telemetry", avail);

  const float refresh_w = 172.0f;
  ImGui::TextColored(ui::colors().primary2, "%s", "Runtime metrics");
  const float right_x = ImGui::GetWindowContentRegionMax().x - refresh_w;
  if (right_x > ImGui::GetCursorPosX() + 24.0f) {
    ImGui::SameLine();
    ImGui::SetCursorPosX(right_x);
  }
  if (ui::soft_button((std::string(icons::kRefresh) + "  Refresh Now").c_str(),
                      ImVec2(refresh_w, 36))) {
    state.next_telemetry_poll = 0.0;
    set_status(state, "Telemetry refresh requested");
  }

  section_header("Runtime Overview");
  std::vector<MetricItem> runtime = {
      {icons::kOnline, "Uptime", format_uptime(t.uptime_seconds),
       "since payload start", ui::colors().text},
      {icons::kTerminal, "Active Conns", format_count(t.active_connections),
       "pool size " + format_count(t.thread_pool_size), ui::colors().text},
      {icons::kGauge, "Read Calls", format_count(t.total_read_calls),
       "total reads", ui::colors().text},
      {icons::kGauge, "Write Calls", format_count(t.total_write_calls),
       "total writes", ui::colors().text},
  };
  draw_metric_grid(runtime, panel_w - 36.0f);

  section_header("Data Throughput");
  const double avg_read = t.total_read_calls > 0
      ? static_cast<double>(t.total_bytes_read) / static_cast<double>(t.total_read_calls)
      : 0.0;
  const double avg_write = t.total_write_calls > 0
      ? static_cast<double>(t.total_bytes_written) / static_cast<double>(t.total_write_calls)
      : 0.0;
  std::vector<MetricItem> throughput = {
      {icons::kImport, "Bytes Read", format_bytes(t.total_bytes_read),
       "from target process", ui::colors().success},
      {icons::kExport, "Bytes Written", format_bytes(t.total_bytes_written),
       "to target process", ui::colors().primary2},
      {icons::kMemory, "Avg Read", format_bytes(static_cast<uint64_t>(avg_read)),
       "per read call", ui::colors().text},
      {icons::kMemory, "Avg Write", format_bytes(static_cast<uint64_t>(avg_write)),
       "per write call", ui::colors().text},
  };
  draw_metric_grid(throughput, panel_w - 36.0f);

  section_header("Map Cache");
  const uint64_t total_cache = t.scan_cache_hits + t.scan_cache_misses;
  const double hit_rate = total_cache > 0
      ? static_cast<double>(t.scan_cache_hits) / static_cast<double>(total_cache)
      : 0.0;
  draw_progress_row("Hit Rate", hit_rate, ui::colors().success);
  draw_progress_row("Miss Rate", 1.0 - hit_rate, ui::colors().warning);
  ImGui::TextColored(ui::colors().muted, "Hits %s    Misses %s",
                     format_count(t.scan_cache_hits).c_str(),
                     format_count(t.scan_cache_misses).c_str());
  ImGui::TextColored(ui::colors().dim, "LRU cache: 8 PID entries  |  TTL: 5 seconds");

  section_header("Aggregate Performance");
  const double read_mib_s = t.uptime_seconds > 0
      ? static_cast<double>(t.total_bytes_read) / static_cast<double>(t.uptime_seconds) /
            (1024.0 * 1024.0)
      : 0.0;
  const double write_mib_s = t.uptime_seconds > 0
      ? static_cast<double>(t.total_bytes_written) / static_cast<double>(t.uptime_seconds) /
            (1024.0 * 1024.0)
      : 0.0;
  ImGui::TextColored(ui::colors().success, "Read   %.2f MiB/s   (%s total)",
                     read_mib_s, format_bytes(t.total_bytes_read).c_str());
  ImGui::TextColored(ui::colors().primary2, "Write  %.2f MiB/s   (%s total)",
                     write_mib_s, format_bytes(t.total_bytes_written).c_str());
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Total call overhead: %s reads + %s writes",
                     format_count(t.total_read_calls).c_str(),
                     format_count(t.total_write_calls).c_str());
  ImGui::TextColored(ui::colors().dim, "Thread pool: %u workers",
                     t.thread_pool_size);
  ImGui::TextColored(ui::colors().dim, "Active sessions: %u client%s",
                     t.active_connections,
                     t.active_connections == 1 ? "" : "s");
  ImGui::TextColored(ui::colors().muted, "Last poll: %.0f seconds ago",
                     now - (state.next_telemetry_poll - 1.0));

  ui::end_panel();
}

} // namespace memdbg::frontend

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

constexpr uint64_t kMaxPlausibleUptimeSeconds = 366ULL * 24ULL * 60ULL * 60ULL;

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
  uint64_t d = seconds / 86400U;
  uint64_t h = seconds / 3600U;
  uint64_t m = (seconds % 3600U) / 60U;
  uint64_t s = seconds % 60U;
  char buf[48];
  if (d > 0) {
    h = (seconds % 86400U) / 3600U;
    std::snprintf(buf, sizeof(buf), "%llud %lluh %llum",
                  (unsigned long long)d, (unsigned long long)h,
                  (unsigned long long)m);
  } else if (h > 0) {
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
      (state.hello.capabilities & MEMDBG_CAP_PERF_TELEMETRY) &&
      !state.scan_async_pending) {
    if (now >= state.next_telemetry_poll) {
      state.next_telemetry_poll = now + 1.0;
      if (!state.telemetry_pending) {
        request_telemetry_async(state);
      }
    }
  }

  if (!state.client.connected()) {
    ui::begin_panel("TelemetryEmpty", locale::tr("telemetry.title"), avail);
    ui::draw_empty_state(locale::tr("telemetry.require_payload"),
                         locale::tr("telemetry.require_payload_desc"));
    ui::end_panel();
    return;
  }

  if (!(state.hello.capabilities & MEMDBG_CAP_PERF_TELEMETRY)) {
    ui::begin_panel("TelemetryUnsupported", locale::tr("telemetry.title"), avail);
    ui::draw_empty_state(locale::tr("telemetry.not_supported"),
                         locale::tr("telemetry.not_supported_desc"));
    ui::end_panel();
    return;
  }

  if (!state.telemetry_available) {
    ui::begin_panel("TelemetryWaiting", locale::tr("telemetry.title"), avail);
    ui::draw_empty_state(locale::tr("telemetry.polling"),
                         locale::tr("telemetry.polling_desc"));
    ui::end_panel();
    return;
  }

  const auto &t = state.telemetry_snap;
  const float panel_w = std::max(240.0f, avail.x);
  const bool uptime_valid =
      t.uptime_seconds > 0U && t.uptime_seconds <= kMaxPlausibleUptimeSeconds;

  ui::begin_panel("TelemetryPanel", locale::tr("telemetry.title"), avail);

  const float refresh_w = 172.0f;
  ImGui::TextColored(ui::colors().primary2, "%s", locale::tr("telemetry.runtime_metrics"));
  const float right_x = ImGui::GetWindowContentRegionMax().x - refresh_w;
  if (right_x > ImGui::GetCursorPosX() + 24.0f) {
    ImGui::SameLine();
    ImGui::SetCursorPosX(right_x);
  }
  ImGui::BeginDisabled(state.scan_async_pending);
  if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("telemetry.refresh_now")).c_str(),
                      ImVec2(refresh_w, 36))) {
    if (!state.telemetry_pending) {
      request_telemetry_async(state);
      set_status(state, locale::tr("telemetry.refresh_requested"));
    }
  }
  ImGui::EndDisabled();
  if (state.scan_async_pending) {
    ImGui::TextColored(ui::colors().warning,
                       "%s", locale::tr("telemetry.paused_scan"));
  }

  section_header(locale::tr("telemetry.runtime_overview"));
  std::vector<MetricItem> runtime = {
      {icons::kOnline, locale::tr("telemetry.uptime"),
       uptime_valid ? format_uptime(t.uptime_seconds) : locale::tr("telemetry.unavailable"),
       uptime_valid ? locale::tr("telemetry.since_start") : locale::tr("telemetry.invalid_clock"),
       uptime_valid ? ui::colors().text : ui::colors().warning},
      {icons::kTerminal, locale::tr("telemetry.active_conns"), format_count(t.active_connections),
       [&t]() { char b[64]; std::snprintf(b, sizeof(b), locale::tr("telemetry.pool_size"), format_count(t.thread_pool_size).c_str()); return std::string(b); }(), ui::colors().text},
      {icons::kGauge, locale::tr("telemetry.read_calls"), format_count(t.total_read_calls),
       locale::tr("telemetry.total_reads"), ui::colors().text},
      {icons::kGauge, locale::tr("telemetry.write_calls"), format_count(t.total_write_calls),
       locale::tr("telemetry.total_writes"), ui::colors().text},
  };
  draw_metric_grid(runtime, panel_w - 36.0f);

  section_header(locale::tr("telemetry.data_throughput"));
  const double avg_read = t.total_read_calls > 0
      ? static_cast<double>(t.total_bytes_read) / static_cast<double>(t.total_read_calls)
      : 0.0;
  const double avg_write = t.total_write_calls > 0
      ? static_cast<double>(t.total_bytes_written) / static_cast<double>(t.total_write_calls)
      : 0.0;
  std::vector<MetricItem> throughput = {
      {icons::kImport, locale::tr("telemetry.bytes_read"), format_bytes(t.total_bytes_read),
       locale::tr("telemetry.from_target"), ui::colors().success},
      {icons::kExport, locale::tr("telemetry.bytes_written"), format_bytes(t.total_bytes_written),
       locale::tr("telemetry.to_target"), ui::colors().primary2},
      {icons::kMemory, locale::tr("telemetry.avg_read"), format_bytes(static_cast<uint64_t>(avg_read)),
       locale::tr("telemetry.per_read_call"), ui::colors().text},
      {icons::kMemory, locale::tr("telemetry.avg_write"), format_bytes(static_cast<uint64_t>(avg_write)),
       locale::tr("telemetry.per_write_call"), ui::colors().text},
  };
  draw_metric_grid(throughput, panel_w - 36.0f);

  section_header(locale::tr("telemetry.map_cache"));
  const uint64_t total_cache = t.scan_cache_hits + t.scan_cache_misses;
  if (total_cache == 0U) {
    ImGui::TextColored(ui::colors().muted,
                       "%s", locale::tr("telemetry.no_cache_activity"));
    ImGui::TextColored(ui::colors().dim,
                       "%s", locale::tr("telemetry.cache_hint"));
  } else {
    const double hit_rate =
        static_cast<double>(t.scan_cache_hits) / static_cast<double>(total_cache);
    draw_progress_row(locale::tr("telemetry.hit_rate"), hit_rate, ui::colors().success);
    draw_progress_row(locale::tr("telemetry.miss_rate"), 1.0 - hit_rate, ui::colors().warning);
    ImGui::TextColored(ui::colors().muted, locale::tr("telemetry.hits_misses"),
                       format_count(t.scan_cache_hits).c_str(),
                       format_count(t.scan_cache_misses).c_str());
    ImGui::TextColored(ui::colors().dim, "%s", locale::tr("telemetry.lru_info"));
  }

  section_header(locale::tr("telemetry.aggregate_perf"));
  const double read_mib_s = uptime_valid
      ? static_cast<double>(t.total_bytes_read) / static_cast<double>(t.uptime_seconds) /
            (1024.0 * 1024.0)
      : 0.0;
  const double write_mib_s = uptime_valid
      ? static_cast<double>(t.total_bytes_written) / static_cast<double>(t.uptime_seconds) /
            (1024.0 * 1024.0)
      : 0.0;
  if (uptime_valid) {
    ImGui::TextColored(ui::colors().success, locale::tr("telemetry.read_mibs"),
                       read_mib_s, format_bytes(t.total_bytes_read).c_str());
    ImGui::TextColored(ui::colors().primary2, locale::tr("telemetry.write_mibs"),
                       write_mib_s, format_bytes(t.total_bytes_written).c_str());
  } else {
    ImGui::TextColored(ui::colors().warning,
                       "%s", locale::tr("telemetry.throughput_unavailable"));
    ImGui::TextColored(ui::colors().muted, locale::tr("telemetry.read_write_total"),
                       format_bytes(t.total_bytes_read).c_str(),
                       format_bytes(t.total_bytes_written).c_str());
  }
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, locale::tr("telemetry.total_overhead"),
                     format_count(t.total_read_calls).c_str(),
                     format_count(t.total_write_calls).c_str());
  ImGui::TextColored(ui::colors().dim, locale::tr("telemetry.thread_pool"),
                     t.thread_pool_size);
  ImGui::TextColored(ui::colors().dim, locale::tr("telemetry.active_sessions"),
                     t.active_connections,
                     t.active_connections == 1 ? "" : "s");
  ImGui::TextColored(ui::colors().muted, locale::tr("telemetry.last_poll"),
                     now - (state.next_telemetry_poll - 1.0));

  ui::end_panel();
}

} // namespace memdbg::frontend

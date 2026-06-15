/*
 * memDBG - Telemetry / performance screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <cstdio>

namespace memdbg::frontend {

namespace {

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
  if (h > 0) std::snprintf(buf, sizeof(buf), "%lluh %llum %llus", (unsigned long long)h, (unsigned long long)m, (unsigned long long)s);
  else if (m > 0) std::snprintf(buf, sizeof(buf), "%llum %llus", (unsigned long long)m, (unsigned long long)s);
  else std::snprintf(buf, sizeof(buf), "%llus", (unsigned long long)s);
  return buf;
}

inline void metric_card(const char *icon, const char *label, const char *value,
                        const char *subtitle, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 14));
  ImGui::BeginChild(label, size, true, ImGuiWindowFlags_NoScrollbar);

  ImGui::TextColored(ui::colors().primary, "%s", icon);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().muted, "%s", label);

  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 2));
  ImGui::TextColored(ui::colors().text, "%s", value);
  if (subtitle && *subtitle) {
    ImGui::TextColored(ui::colors().dim, "%s", subtitle);
  }
  ImGui::PopStyleVar();

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

inline void progress_bar_label(const char *label, double fraction, ImVec4 bar_color) {
  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::SameLine(128);
  ImGui::PushStyleColor(ImGuiCol_PlotHistogram, bar_color);
  ImGui::PushStyleColor(ImGuiCol_FrameBg, ui::colors().bg2);
  char overlay[32];
  std::snprintf(overlay, sizeof(overlay), "%.1f%%", fraction * 100.0);
  ImGui::ProgressBar(static_cast<float>(fraction), ImVec2(-1, 18), overlay);
  ImGui::PopStyleColor(2);
}

} // namespace

void draw_telemetry(AppState &state, ImVec2 avail) {
  const double now = ImGui::GetTime();

  /* Auto-poll every 1.0s while connected and on this screen */
  if (state.client.connected() && (state.hello.capabilities & MEMDBG_CAP_PERF_TELEMETRY)) {
    if (now >= state.next_telemetry_poll) {
      state.next_telemetry_poll = now + 1.0;
      state.telemetry_available = state.client.telemetry(state.telemetry_snap);
      if (!state.telemetry_available) {
        set_status(state, "Telemetry: " + state.client.last_error());
      }
    }
  }

  const float gap = 16.0f;

  if (!state.client.connected()) {
    /* Not connected — show empty state */
    ui::begin_panel("TelemetryEmpty", "Payload Telemetry", ImVec2(avail.x, avail.y));
    ui::draw_empty_state("Payload Required",
                         "Connect to a console running the memDBG payload to see runtime telemetry.");
    ui::end_panel();
    return;
  }

  if (!(state.hello.capabilities & MEMDBG_CAP_PERF_TELEMETRY)) {
    ui::begin_panel("TelemetryUnsupported", "Payload Telemetry", ImVec2(avail.x, avail.y));
    ui::draw_empty_state("Not Supported",
                         "The connected payload does not advertise the PERF_TELEMETRY capability.\n"
                         "Update to a newer payload build to enable performance telemetry.");
    ui::end_panel();
    return;
  }

  if (!state.telemetry_available) {
    ui::begin_panel("TelemetryWaiting", "Payload Telemetry", ImVec2(avail.x, avail.y));
    ui::draw_empty_state("Polling...",
                         "Waiting for the first telemetry response from the payload.\n"
                         "Check the status bar for errors if this persists.");
    ui::end_panel();
    return;
  }

  const auto &t = state.telemetry_snap;

  /* ---- Row 0: Connection & uptime ---- */
  char uptime_buf[128];
  std::snprintf(uptime_buf, sizeof(uptime_buf), "Up %s  |  %s workers",
                format_uptime(t.uptime_seconds).c_str(),
                format_count(t.thread_pool_size).c_str());

  ui::begin_panel("TelemetryHeader", "Runtime Overview", ImVec2(avail.x, gap + 82.0f));
  {
    ImVec2 card_sz((avail.x - gap * 3.0f) / 4.0f, 50.0f);

    metric_card(icons::kOnline, "Uptime",
                format_uptime(t.uptime_seconds).c_str(),
                "since payload start", card_sz);

    ImGui::SameLine(0, gap);
    metric_card(icons::kTerminal, "Active Conns",
                format_count(t.active_connections).c_str(),
                (std::string("pool size ") + format_count(t.thread_pool_size)).c_str(), card_sz);

    ImGui::SameLine(0, gap);
    metric_card(icons::kGauge, "Read Calls",
                format_count(t.total_read_calls).c_str(),
                "total synchronous reads", card_sz);

    ImGui::SameLine(0, gap);
    metric_card(icons::kGauge, "Write Calls",
                format_count(t.total_write_calls).c_str(),
                "total synchronous writes", card_sz);
  }
  ui::end_panel();

  ImGui::Spacing(); ImGui::Spacing();

  /* ---- Row 1: Throughput ---- */
  ui::begin_panel("TelemetryThroughput", "Data Throughput", ImVec2(avail.x, gap + 82.0f));
  {
    ImVec2 card_sz((avail.x - gap * 3.0f) / 4.0f, 50.0f);

    std::string rb_sub = "from target process";
    std::string wb_sub = "to target process";

    metric_card(icons::kImport, "Bytes Read",
                format_bytes(t.total_bytes_read).c_str(),
                rb_sub.c_str(), card_sz);

    ImGui::SameLine(0, gap);
    metric_card(icons::kExport, "Bytes Written",
                format_bytes(t.total_bytes_written).c_str(),
                wb_sub.c_str(), card_sz);

    /* Also show per-call averages */
    double avg_read = t.total_read_calls > 0
        ? static_cast<double>(t.total_bytes_read) / static_cast<double>(t.total_read_calls)
        : 0.0;
    double avg_write = t.total_write_calls > 0
        ? static_cast<double>(t.total_bytes_written) / static_cast<double>(t.total_write_calls)
        : 0.0;
    char avg_buf[64];
    std::snprintf(avg_buf, sizeof(avg_buf), "%s avg/call", format_bytes(static_cast<uint64_t>(avg_read)).c_str());

    ImGui::SameLine(0, gap);
    metric_card(icons::kMemory, "Avg Read",
                format_bytes(static_cast<uint64_t>(avg_read)).c_str(),
                "per read call", card_sz);

    ImGui::SameLine(0, gap);
    metric_card(icons::kMemory, "Avg Write",
                format_bytes(static_cast<uint64_t>(avg_write)).c_str(),
                "per write call", card_sz);
  }
  ui::end_panel();

  ImGui::Spacing(); ImGui::Spacing();

  /* ---- Row 2: Scan cache + summary ---- */
  const float half_w = (avail.x - gap) * 0.5f;

  /* Cache stats */
  ui::begin_panel("TelemetryCache", "Map Cache Performance", ImVec2(half_w, 0));
  {
    uint64_t total_cache = t.scan_cache_hits + t.scan_cache_misses;
    double hit_rate = total_cache > 0
        ? static_cast<double>(t.scan_cache_hits) / static_cast<double>(total_cache)
        : 0.0;

    char hit_text[64], miss_text[64];
    std::snprintf(hit_text, sizeof(hit_text), "Hits  %s", format_count(t.scan_cache_hits).c_str());
    std::snprintf(miss_text, sizeof(miss_text), "Misses  %s", format_count(t.scan_cache_misses).c_str());

    ImGui::Spacing();
    progress_bar_label("Hit Rate", hit_rate, ui::colors().success);
    ImGui::Spacing();
    progress_bar_label("Miss Rate", 1.0 - hit_rate, ui::colors().warning);
    ImGui::Spacing();

    ImGui::TextColored(ui::colors().muted, "%s    %s", hit_text, miss_text);

    if (total_cache > 0) {
      ImGui::Spacing();
      ImGui::Separator();
      ImGui::Spacing();

      char ratio_buf[64];
      std::snprintf(ratio_buf, sizeof(ratio_buf), "%.1f%% hit ratio  |  %s total cache lookups",
                    hit_rate * 100.0, format_count(total_cache).c_str());
      ImGui::TextColored(hit_rate > 0.7 ? ui::colors().success : ui::colors().warning,
                         "%s", ratio_buf);

      ImGui::TextColored(ui::colors().dim, "LRU cache: 8 PID entries  |  TTL: 5 seconds");
    }
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);

  /* Perf summary */
  ui::begin_panel("TelemetryPerf", "Aggregate Performance", ImVec2(half_w, 0));
  {
    /* Throughput in bytes/second */
    double read_mbps = t.uptime_seconds > 0
        ? static_cast<double>(t.total_bytes_read) / static_cast<double>(t.uptime_seconds)
            / (1024.0 * 1024.0)
        : 0.0;
    double write_mbps = t.uptime_seconds > 0
        ? static_cast<double>(t.total_bytes_written) / static_cast<double>(t.uptime_seconds)
            / (1024.0 * 1024.0)
        : 0.0;

    ImGui::Spacing();

    char line[128];
    std::snprintf(line, sizeof(line), "Read   %7.2f MiB/s   (%s total)",
                  read_mbps, format_bytes(t.total_bytes_read).c_str());
    ImGui::TextColored(ui::colors().success, "%s", line);

    std::snprintf(line, sizeof(line), "Write  %7.2f MiB/s   (%s total)",
                  write_mbps, format_bytes(t.total_bytes_written).c_str());
    ImGui::TextColored(ui::colors().primary2, "%s", line);

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    std::snprintf(line, sizeof(line), "Total call overhead: %s reads + %s writes",
                  format_count(t.total_read_calls).c_str(),
                  format_count(t.total_write_calls).c_str());
    ImGui::TextColored(ui::colors().muted, "%s", line);

    ImGui::Spacing();
    ImGui::TextColored(ui::colors().dim, "Thread pool:  %u workers (pre-spawned, multi-accept)",
                       t.thread_pool_size);
    ImGui::TextColored(ui::colors().dim, "Active sessions:  %u client%s",
                       t.active_connections,
                       t.active_connections == 1 ? "" : "s");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextColored(ui::colors().muted, "Last poll: %.0f seconds ago",
                       now - (state.next_telemetry_poll - 1.0));
  }
  ui::end_panel();

  /* ---- Manual refresh button ---- */
  ImGui::Spacing();
  ImGui::SetCursorPosX(avail.x - 190.0f);
  if (ui::soft_button((std::string(icons::kRefresh) + "  Refresh Now").c_str(), ImVec2(180, 38))) {
    state.next_telemetry_poll = 0.0;
    set_status(state, "Telemetry refresh requested");
  }
}

} // namespace memdbg::frontend

/*
 * MemDBG - Kernel Log (KLOG) streaming screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "core/platform.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <chrono>
#include <cstdio>

namespace memdbg::frontend {

static std::string klog_export_path(AppState &) {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  char buf[64];
  std::strftime(buf, sizeof(buf), "klog_%Y%m%d_%H%M%S.log", std::localtime(&t));
  return (platform::app_data_dir() / "logs" / buf).string();
}

static bool klog_export(AppState &state, std::string &error) {
  const std::string path = klog_export_path(state);
  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream ofs(path);
  if (!ofs.is_open()) {
    error = "Cannot open " + path;
    return false;
  }
  for (const auto &line : state.klog.lines)
    ofs << line << "\n";
  return true;
}

static bool line_matches(const std::string &line, const char *query) {
  if (!query || !*query) return true;
  return line.find(query) != std::string::npos;
}

void draw_klog(AppState &state, ImVec2 avail) {
  ui::begin_panel("KlogPanel", locale::tr("klog.title"), avail);

  const float scl = ui::dpi_scale();
  const float btn_h = 32.0f * scl;

  /* ---- Row 1: Connection controls ---- */
  if (!state.klog.connected) {
    if (ui::soft_button(
            (std::string(icons::kPlay) + "  " + locale::tr("klog.connect")).c_str(),
            ImVec2(140.0f * scl, btn_h))) {
      if (!state.client.connected()) {
        set_status(state, locale::tr("klog.connect_first"));
      } else {
        uint16_t port = 0;
        std::string host(state.host);
        if (state.client.klog_connect(host, port)) {
          state.klog.connected = true;
          state.klog.port = port;
          state.klog.paused = false;
          set_status(state, std::string(locale::tr("klog.connected_to")) + " :" +
                               std::to_string(port));
        } else {
          set_status(state, state.client.last_error());
        }
      }
    }
  } else {
    if (ui::soft_button(
            (std::string(icons::kStop) + "  " + locale::tr("klog.disconnect")).c_str(),
            ImVec2(140.0f * scl, btn_h))) {
      state.client.klog_disconnect();
      state.klog.connected = false;
      state.klog.paused = false;
      set_status(state, locale::tr("klog.disconnected"));
    }
  }

  ImGui::SameLine();
  if (ui::soft_button(
          (std::string(icons::kTrash) + "  " + locale::tr("klog.clear")).c_str(),
          ImVec2(90.0f * scl, btn_h))) {
    state.klog.lines.clear();
    state.klog.raw.clear();
    state.klog.total_received = 0;
    set_status(state, locale::tr("klog.cleared"));
  }

  ImGui::SameLine();
  if (ui::soft_button(
          (std::string(icons::kCopy) + "  " + locale::tr("klog.copy")).c_str(),
          ImVec2(90.0f * scl, btn_h))) {
    if (!state.klog.lines.empty()) {
      std::string all;
      for (const auto &line : state.klog.lines)
        all += line + "\n";
      ImGui::SetClipboardText(all.c_str());
      set_status(state, locale::tr("klog.copied"));
    } else {
      set_status(state, locale::tr("klog.none_to_copy"));
    }
  }

  ImGui::SameLine();
  if (ui::soft_button(
          (std::string(icons::kSave) + "  " + locale::tr("klog.export")).c_str(),
          ImVec2(100.0f * scl, btn_h))) {
    if (!state.klog.lines.empty()) {
      std::string error;
      if (klog_export(state, error)) {
        set_status(state, locale::tr("klog.exported"));
      } else {
        set_status(state, "Export failed: " + error);
      }
    } else {
      set_status(state, locale::tr("klog.none_to_export"));
    }
  }

  /* ---- Row 2: Search + Pause ---- */
  ImGui::SetNextItemWidth(220.0f * scl);
  ImGui::InputTextWithHint("##KlogSearch",
                           (std::string(icons::kSearch) + " " + locale::tr("klog.search_hint")).c_str(),
                           state.klog.search, sizeof(state.klog.search));

  ImGui::SameLine();
  if (state.klog.connected) {
    if (ui::soft_button(
            (std::string(state.klog.paused ? icons::kPlay : icons::kPause) + "  " +
             (state.klog.paused ? locale::tr("klog.resume") : locale::tr("klog.pause"))).c_str(),
            ImVec2(110.0f * scl, btn_h))) {
      state.klog.paused = !state.klog.paused;
    }
  }

  /* ---- Row 3: Status + Settings ---- */
  if (state.klog.connected) {
    const char *status_label = state.klog.paused ? locale::tr("klog.paused") : locale::tr("klog.streaming");
    ImGui::TextColored(state.klog.paused ? ui::colors().warning : ui::colors().dim,
                       "%s :%u  |  %zu / %zu %s",
                       status_label,
                       static_cast<unsigned>(state.klog.port),
                       state.klog.lines.size(),
                       state.klog.total_received,
                       locale::tr("klog.lines"));
  } else {
    ImGui::TextColored(
        ui::colors().dim, "%s",
        state.client.connected() ? locale::tr("klog.ready")
                                 : locale::tr("klog.need_console"));
  }

  ImGui::SameLine();
  ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 280.0f * scl);
  ImGui::SetNextItemWidth(60.0f * scl);
  int max_lines = state.klog.max_lines;
  if (ImGui::InputInt("##KlogMaxLines", &max_lines, 0, 0)) {
    if (max_lines < 100) max_lines = 100;
    if (max_lines > 50000) max_lines = 50000;
    state.klog.max_lines = max_lines;
  }
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%s", locale::tr("klog.max_lines"));

  ImGui::SameLine();
  ImGui::Checkbox(locale::tr("klog.auto_scroll"), &state.klog.auto_scroll);

  ImGui::Spacing();

  /* ---- Poll klog data (limited per frame to prevent UI blocking) ---- */
  if (state.klog.connected && !state.klog.paused) {
    double now = ImGui::GetTime();
    if (now - state.klog.last_poll >= 0.1) {
      state.klog.last_poll = now;

      /* Process at most 8 chunks per frame to prevent UI blocking */
      int chunks_processed = 0;
      const int max_chunks_per_frame = 8;
      std::vector<uint8_t> chunk;
      while (state.client.klog_read(chunk) && chunks_processed < max_chunks_per_frame) {
        if (chunk.empty()) break;
        state.klog.raw.insert(state.klog.raw.end(), chunk.begin(), chunk.end());
        while (true) {
          auto nl = std::find(state.klog.raw.begin(), state.klog.raw.end(),
                              static_cast<uint8_t>('\n'));
          if (nl == state.klog.raw.end()) break;
          std::string line(state.klog.raw.begin(), nl);
          if (!line.empty() && line.back() == '\r')
            line.pop_back();
          state.klog.lines.push_back(std::move(line));
          state.klog.raw.erase(state.klog.raw.begin(), nl + 1);
          state.klog.total_received++;
        }
        ++chunks_processed;
      }

      /* Enforce max line limit */
      while (state.klog.lines.size() >
             static_cast<size_t>(state.klog.max_lines)) {
        state.klog.lines.pop_front();
      }

      if (!state.client.klog_connected() && state.klog.connected) {
        state.klog.connected = false;
        std::string err = state.client.last_error();
        if (err.empty()) err = "klog stream closed";
        set_status(state, err);
      }
    }
  }

  /* ---- Log display with virtualization ---- */
  ImGui::BeginChild("KlogLines", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);

  if (state.klog.lines.empty() && state.klog.raw.empty()) {
    ui::draw_empty_state(locale::tr("klog.no_data"),
                         locale::tr("klog.no_data_desc"));
  } else {
    const bool has_search = state.klog.search[0] != '\0';

    std::vector<int> filtered;
    if (has_search) {
      filtered.reserve(state.klog.lines.size());
      for (int i = 0; i < static_cast<int>(state.klog.lines.size()); ++i) {
        if (line_matches(state.klog.lines[static_cast<size_t>(i)], state.klog.search))
          filtered.push_back(i);
      }
    }

    const int item_count = has_search ? static_cast<int>(filtered.size())
                                      : static_cast<int>(state.klog.lines.size());

    if (item_count == 0 && has_search) {
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("klog.no_matches"));
    } else {
      ImGuiListClipper clipper;
      clipper.Begin(item_count);
      while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
          const int line_idx = has_search ? filtered[static_cast<size_t>(i)] : i;
          const std::string &line = state.klog.lines[static_cast<size_t>(line_idx)];

          if (has_search) {
            const char *p = line.c_str();
            const char *q = state.klog.search;
            const size_t qlen = strlen(q);
            const char *found = nullptr;
            while ((found = strstr(p, q)) != nullptr) {
              if (found > p)
                ImGui::TextUnformatted(p, found);
              ImGui::PushStyleColor(ImGuiCol_Text, ui::colors().warning);
              ImGui::TextUnformatted(found, found + qlen);
              ImGui::PopStyleColor();
              p = found + qlen;
            }
            if (*p)
              ImGui::TextUnformatted(p);
          } else {
            ImGui::TextUnformatted(line.c_str());
          }
        }
      }
      clipper.End();
    }

    if (!state.klog.raw.empty()) {
      std::string partial(state.klog.raw.begin(), state.klog.raw.end());
      ImGui::TextUnformatted(partial.c_str());
    }

    if (state.klog.auto_scroll &&
        ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.0f) {
      ImGui::SetScrollHereY(1.0f);
    }
  }

  ImGui::EndChild();

  ui::end_panel();
}

} // namespace memdbg::frontend

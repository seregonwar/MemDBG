/*
 * MemDBG - Kernel Log (KLOG) streaming screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <algorithm>

namespace memdbg::frontend {

void draw_klog(AppState &state, ImVec2 avail) {
  ui::begin_panel("KlogPanel", locale::tr("klog.title"), avail);

  /* ---- Control bar ---- */
  if (!state.klog_connected) {
    if (ui::soft_button(
            (std::string(icons::kPlay) + "  " + locale::tr("klog.connect")).c_str(),
            ImVec2(150, 38))) {
      if (!state.client.connected()) {
        set_status(state, locale::tr("klog.connect_first"));
      } else {
        uint16_t port = 0;
        std::string host(state.host);
        if (state.client.klog_connect(host, port)) {
          state.klog_connected = true;
          state.klog_port = port;
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
            ImVec2(150, 38))) {
      state.client.klog_disconnect();
      state.klog_connected = false;
      set_status(state, locale::tr("klog.disconnected"));
    }
  }

  ImGui::SameLine();
  if (ui::soft_button(
          (std::string(icons::kTrash) + "  " + locale::tr("klog.clear")).c_str(),
          ImVec2(110, 38))) {
    state.klog_lines.clear();
    state.klog_raw.clear();
    set_status(state, locale::tr("klog.cleared"));
  }

  ImGui::SameLine();
  if (ui::soft_button(
          (std::string(icons::kCopy) + "  " + locale::tr("klog.copy")).c_str(),
          ImVec2(110, 38))) {
    if (!state.klog_lines.empty()) {
      std::string all;
      for (const auto &line : state.klog_lines)
        all += line + "\n";
      ImGui::SetClipboardText(all.c_str());
      set_status(state, locale::tr("klog.copied"));
    } else {
      set_status(state, locale::tr("klog.none_to_copy"));
    }
  }

  ImGui::SameLine();
  /* Status info */
  if (state.klog_connected) {
    ImGui::TextColored(ui::colors().dim, "%s :%u  |  %zu %s",
                       locale::tr("klog.streaming"),
                       static_cast<unsigned>(state.klog_port),
                       state.klog_lines.size(),
                       locale::tr("klog.lines"));
  } else {
    ImGui::TextColored(
        ui::colors().dim, "%s",
        state.client.connected() ? locale::tr("klog.ready")
                                 : locale::tr("klog.need_console"));
  }

  ImGui::SameLine();
  ImGui::SetCursorPosX(ImGui::GetCursorPosX() +
                       ImGui::GetContentRegionAvail().x - 200.0f);
  ImGui::SetNextItemWidth(60.0f);
  int max_lines = state.klog_max_lines;
  if (ImGui::InputInt("##KlogMaxLines", &max_lines, 0, 0)) {
    if (max_lines < 100)
      max_lines = 100;
    if (max_lines > 50000)
      max_lines = 50000;
    state.klog_max_lines = max_lines;
  }
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%s", locale::tr("klog.max_lines"));

  ImGui::SameLine();
  ImGui::Checkbox(locale::tr("klog.auto_scroll"), &state.klog_auto_scroll);

  ImGui::Spacing();

  /* ---- Poll klog data ---- */
  if (state.klog_connected) {
    double now = ImGui::GetTime();
    if (now - state.klog_last_poll >= 0.1) { /* poll every 100ms */
      state.klog_last_poll = now;
      std::vector<uint8_t> chunk;
      while (state.client.klog_read(chunk)) {
        if (chunk.empty()) break; /* no more data */
        state.klog_raw.insert(state.klog_raw.end(), chunk.begin(),
                             chunk.end());
        /* Split raw buffer into lines */
        while (true) {
          auto nl = std::find(state.klog_raw.begin(), state.klog_raw.end(),
                              static_cast<uint8_t>('\n'));
          if (nl == state.klog_raw.end()) break;
          std::string line(state.klog_raw.begin(), nl);
          /* Strip trailing \r */
          if (!line.empty() && line.back() == '\r')
            line.pop_back();
          state.klog_lines.push_back(std::move(line));
          state.klog_raw.erase(state.klog_raw.begin(), nl + 1);
        }
        /* Enforce max line limit */
        while (state.klog_lines.size() >
               static_cast<size_t>(state.klog_max_lines)) {
          state.klog_lines.erase(state.klog_lines.begin());
        }
      }
      /* Handle connection loss */
      if (!state.client.klog_connected() && state.klog_connected) {
        state.klog_connected = false;
        std::string err = state.client.last_error();
        if (err.empty()) err = "klog stream closed";
        set_status(state, err);
      }
    }
  }

  /* ---- Log display ---- */
  ImGui::BeginChild("KlogLines", ImVec2(0, 0), true);
  if (state.klog_lines.empty() && state.klog_raw.empty()) {
    ui::draw_empty_state(locale::tr("klog.no_data"),
                         locale::tr("klog.no_data_desc"));
  } else {
    /* Display partial line if any */
    if (!state.klog_raw.empty()) {
      std::string partial(state.klog_raw.begin(), state.klog_raw.end());
      ImGui::TextUnformatted(partial.c_str());
    }
    const float wrap_x =
        ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    for (const auto &line : state.klog_lines) {
      ImGui::PushTextWrapPos(wrap_x);
      ImGui::TextUnformatted(line.c_str());
      ImGui::PopTextWrapPos();
    }
    if (state.klog_auto_scroll &&
        ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.0f) {
      ImGui::SetScrollHereY(1.0f);
    }
  }
  ImGui::EndChild();

  ui::end_panel();
}

} // namespace memdbg::frontend

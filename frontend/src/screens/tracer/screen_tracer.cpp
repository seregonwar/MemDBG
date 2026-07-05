/*
 * memDBG - Tracer screen for frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Real-time syscall tracing and crash detection GUI.
 * Connects to the daemon's tracer service via protocol commands.
 */

#include "app_state.hpp"
#include "core/client/memdbg_client.hpp"
#include "locale/locale.hpp"
#include "memdbg/tracer/memdbg_tracer.h"
#include "ui/ui_icons.hpp"
#include "ui/ui_widgets.hpp"

#include "imgui.h"

#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace memdbg::frontend {

extern void request_tracer_attach_async(AppState &state);
extern void request_tracer_detach_async(AppState &state);

void draw_tracer(AppState &state, ImVec2 avail) {
  ui::begin_panel("TracerPanel", locale::tr("tracer.title"), avail);

  /* ── Status bar ── */
  {
    ImGui::BeginGroup();
    ImGui::Text("%s %s", icons::kOnline, locale::tr("tracer.status"));
    ImGui::SameLine();
    const char *status_icon = state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING ? u8"\uf04b"   /* play  */
                            : state.tracer_status.state == MEMDBG_TRACER_STATE_CRASHED ? u8"\uf071"   /* warning */
                            : state.tracer_status.state == MEMDBG_TRACER_STATE_IDLE   ? u8"\uf04d"   /* stop */
                            : u8"\uf023";                                                              /* lock */
    ImGui::TextColored(
        state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING ? ImVec4(0.2f, 0.9f, 0.2f, 1) :
        state.tracer_status.state == MEMDBG_TRACER_STATE_CRASHED ? ImVec4(1, 0.3f, 0.3f, 1) :
        ImVec4(0.7f, 0.7f, 0.7f, 1),
        "%s  %s", status_icon,
        state.tracer_status_text[0] ? state.tracer_status_text : "Idle");
    if (state.tracer_status.state != MEMDBG_TRACER_STATE_IDLE) {
      ImGui::SameLine();
      ImGui::TextDisabled("(%s)", locale::tr("tracer.events_total"));
      ImGui::SameLine();
      ImGui::Text("%u", state.tracer_status.events_total);
    }
    if (state.tracer_status.state == MEMDBG_TRACER_STATE_CRASHED && !state.tracer_crash_dump_path.empty()) {
      ImGui::SameLine();
      ImGui::TextColored(ImVec4(1, 0.5f, 0, 1), " %s %s: %s",
                         u8"\uf071", locale::tr("tracer.dump"), state.tracer_crash_dump_path.c_str());
    }
    ImGui::EndGroup();
  }

  ImGui::Spacing();
  ImGui::TextColored(ui::colors().warning, "%s",
                     "Tracer owns the target while active. Detach resumes it before using Debugger.");
  if (!state.tracer_error.empty())
    ImGui::TextColored(ui::colors().danger, "%s", state.tracer_error.c_str());

  /* ── Controls ── */
  {
    ImGui::AlignTextToFramePadding();
    ImGui::Text("%s", locale::tr("tracer.pid"));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120);
    ImGui::InputText("##pid_input", state.tracer_pid_input, sizeof(state.tracer_pid_input),
                     ImGuiInputTextFlags_CharsDecimal);

    ImGui::SameLine();
    bool is_idle  = (state.tracer_status.state == MEMDBG_TRACER_STATE_IDLE ||
                     state.tracer_status.state == MEMDBG_TRACER_STATE_STOPPED ||
                     state.tracer_status.state == MEMDBG_TRACER_STATE_EXITED);
    const bool attaching = state.tracer_pending && !state.tracer_detach_pending;
    const bool detaching = state.tracer_detach_pending;

    if (is_idle && !attaching && !detaching) {
      ImGui::BeginDisabled(client_async_busy(state));
      if (ui::primary_button(locale::tr("tracer.attach"), ImVec2(140, 0))) {
        int pid = atoi(state.tracer_pid_input);
        if (pid > 0) {
          state.tracer_target_pid = pid;
          request_tracer_attach_async(state);
        } else {
          set_status(state, locale::tr("tracer.select_pid"));
        }
      }
      ImGui::EndDisabled();
    } else {
      const char *detach_label = detaching ? "Detaching..." :
          (attaching ? "Cancel Attach" : "Detach & Resume");
      ImGui::BeginDisabled(detaching);
      if (ui::danger_button(detach_label, ImVec2(140, 0))) {
        request_tracer_detach_async(state);
      }
      ImGui::EndDisabled();
    }

    if (attaching || detaching) {
      ImGui::SameLine();
      ImGui::TextDisabled("%s", detaching ? "Releasing target..." :
                                           locale::tr("tracer.busy"));
    }
  }

  ImGui::Separator();

  /* ── Event log ── */
  {
    const ImVec2 table_size(avail.x - 16, avail.y - 160);
    if (ImGui::BeginTable("##tracer_events", 7,
                           ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders |
                           ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable,
                           table_size)) {
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableSetupColumn("#",        ImGuiTableColumnFlags_WidthFixed, 48);
      ImGui::TableSetupColumn(locale::tr("tracer.col_type"), ImGuiTableColumnFlags_WidthFixed, 80);
      ImGui::TableSetupColumn(locale::tr("tracer.col_syscall"), ImGuiTableColumnFlags_WidthStretch);
      ImGui::TableSetupColumn(locale::tr("tracer.col_args"),  ImGuiTableColumnFlags_WidthStretch);
      ImGui::TableSetupColumn(locale::tr("tracer.col_thread"),ImGuiTableColumnFlags_WidthFixed, 60);
      ImGui::TableSetupColumn(locale::tr("tracer.col_ret"),   ImGuiTableColumnFlags_WidthFixed, 80);
      ImGui::TableSetupColumn(locale::tr("tracer.col_signal"),ImGuiTableColumnFlags_WidthFixed, 60);
      ImGui::TableHeadersRow();

      /* Show most recent events at the bottom — scroll down. */
      size_t total = state.tracer_events.size();
      size_t start = (total > 500) ? total - 500 : 0;

      /* Track if we need to scroll to bottom. */
      bool at_bottom = false;
      if (total > 0 && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2)
        at_bottom = true;

      for (size_t i = start; i < total; i++) {
        const auto &ev = state.tracer_events[i];
        ImGui::TableNextRow();

        /* # */
        ImGui::TableNextColumn();
        ImGui::Text("%zu", i + 1);

        /* Type */
        ImGui::TableNextColumn();
        const char *type_str =
            ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_ENTRY ? u8"\uf054"  /* arrow-right (entry) */ :
            ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_EXIT  ? u8"\uf053"  /* arrow-left (exit)  */ :
            ev.event_type == MEMDBG_TRACER_EVENT_CRASH         ? u8"\uf071"  /* warning            */ :
            u8"\uf0a9";                                                         /* arrow (signal)    */
        ImVec4 type_col =
            ev.event_type == MEMDBG_TRACER_EVENT_CRASH         ? ImVec4(1, 0.3f, 0.3f, 1) :
            ev.event_type == MEMDBG_TRACER_EVENT_SIGNAL        ? ImVec4(1, 0.7f, 0, 1) :
            ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_ENTRY ? ImVec4(0.5f, 0.8f, 1, 1) :
            ImVec4(0.7f, 0.7f, 0.7f, 1);
        ImGui::TextColored(type_col, "%s", type_str);

        /* Syscall name */
        ImGui::TableNextColumn();
        if (ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_ENTRY ||
            ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_EXIT) {
          ImGui::Text("%s", memdbg_tracer_syscall_name((int)ev.syscall_no));
        } else {
          ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1), "—");
        }

        /* Args / ret */
        ImGui::TableNextColumn();
        if (ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_ENTRY) {
          char buf[128];
          int n = snprintf(buf, sizeof(buf), "%llx", (unsigned long long)ev.args[0]);
          for (int j = 1; j < 6 && ev.args[j] != 0; j++)
            n += snprintf(buf + n, sizeof(buf) - (size_t)n, ", %llx",
                         (unsigned long long)ev.args[j]);
          ImGui::Text("%s", buf);
        } else if (ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_EXIT) {
          ImGui::Text("%lld", (long long)ev.syscall_ret);
        } else if (ev.event_type == MEMDBG_TRACER_EVENT_CRASH) {
          ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "CRASH");
        } else {
          ImGui::Text("—");
        }

        /* Thread */
        ImGui::TableNextColumn();
        ImGui::Text("%u", ev.lwp);

        /* Return value (for exit events) */
        ImGui::TableNextColumn();
        if (ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_EXIT) {
          ImGui::Text("%lld", (long long)ev.syscall_ret);
        } else {
          ImGui::Text("—");
        }

        /* Signal */
        ImGui::TableNextColumn();
        if (ev.event_type == MEMDBG_TRACER_EVENT_SIGNAL ||
            ev.event_type == MEMDBG_TRACER_EVENT_CRASH) {
          ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1),
                             "SIG%d", ev.signal);
        } else {
          ImGui::Text("—");
        }
      }

      if (total > 0 && at_bottom)
        ImGui::SetScrollHereY(1.0f);

      ImGui::EndTable();
    }
  }

  /* ── Summary bar ── */
  {
    size_t entry_count = state.tracer_events.size();
    size_t crash_count = 0;
    for (size_t i = 0; i < entry_count; i++)
      if (state.tracer_events[i].event_type == MEMDBG_TRACER_EVENT_CRASH)
        crash_count++;
    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                       "%s %zu %s  |  %s %zu %s",
                       locale::tr("tracer.events_shown"), entry_count,
                       locale::tr("tracer.events"),
                       locale::tr("tracer.crashes"), crash_count,
                       crash_count == 1 ? "" : locale::tr("tracer.events"));
  }

  ui::end_panel();
}

} // namespace memdbg::frontend

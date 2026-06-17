/*
 * MemDBG - Native debugger screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "confirm_modal.hpp"

#include <algorithm>
#include <cinttypes>
#include <cstring>

namespace memdbg::frontend {

namespace {

struct DebuggerState {
  bool attached = false;
  bool stopped = false;
  int32_t pid = 0;
  int32_t selected_lwp = 0;
  double last_poll = 0.0;

  char pid_input[32] = {};
  char bp_input[32] = {};
  int bp_kind = 0; /* 0 = software, 1 = hardware */
  int bp_cond_reg = 0; /* 0 = none (MEMDBG_BP_COND_NONE) */
  int bp_cond_op = 0;  /* 0 = ==, 1 = !=, ... */
  char bp_cond_val[32] = {};

  char wp_input[32] = {};
  int wp_length = 4;
  int wp_type = 1; /* 0=exec, 1=write, 2=read, 3=rw */

  bool pause_on_attach = true;
  bool auto_refresh_on_stop = true;

  std::vector<Client::DebugThreadEntry> threads;
  Client::DebugRegs regs{};
  std::vector<Client::DebugBreakpointEntry> breakpoints;
  std::vector<Client::DebugWatchpointEntry> watchpoints;
};

static DebuggerState &dstate(AppState &state) {
  static DebuggerState s;
  (void)state;
  return s;
}

static bool parse_input_u64(const char *text, uint64_t &out) {
  if (text == nullptr || text[0] == '\0') return false;
  try {
    out = static_cast<uint64_t>(std::stoull(text, nullptr, 0));
    return true;
  } catch (...) {
    return false;
  }
}

static void poll_debugger_state(AppState &state);
static void refresh_threads(AppState &state);

static void refresh_regs(AppState &state) {
  auto &ds = dstate(state);
  if (!state.client.connected() || !ds.attached || ds.selected_lwp == 0) return;
  Client::DebugRegs r{};
  if (state.client.debug_get_regs(ds.selected_lwp, r)) {
    ds.regs = r;
  } else {
    set_status(state, "Regs: " + state.client.last_error());
  }
}

static void poll_debugger_state(AppState &state) {
  auto &ds = dstate(state);
  const double now = ImGui::GetTime();
  if (now - ds.last_poll < 0.5) return;
  ds.last_poll = now;

  if (!state.client.connected() || !ds.attached) return;

  bool stopped = false;
  int32_t stop_lwp = 0;
  if (state.client.debug_poll_events(stopped, stop_lwp)) {
    bool was_stopped = ds.stopped;
    ds.stopped = stopped;
    if (stopped && stop_lwp != 0) ds.selected_lwp = stop_lwp;
    /* Auto-refresh regs when the target just transitioned to stopped */
    if (ds.auto_refresh_on_stop && !was_stopped && stopped) {
      refresh_regs(state);
      refresh_threads(state);
    }
  }
}

static void refresh_threads(AppState &state) {
  auto &ds = dstate(state);
  ds.threads.clear();
  if (!state.client.connected() || !ds.attached) return;
  if (!state.client.debug_get_threads(ds.threads)) {
    set_status(state, "Threads: " + state.client.last_error());
    return;
  }
  if (!ds.threads.empty() && ds.selected_lwp == 0) {
    ds.selected_lwp = ds.threads[0].lwp;
  }
}

static void refresh_breakpoints(AppState &state) {
  auto &ds = dstate(state);
  ds.breakpoints.clear();
  if (!state.client.connected() || !ds.attached) return;
  state.client.debug_get_breakpoints(ds.breakpoints);
}

static void refresh_watchpoints(AppState &state) {
  auto &ds = dstate(state);
  ds.watchpoints.clear();
  if (!state.client.connected() || !ds.attached) return;
  state.client.debug_get_watchpoints(ds.watchpoints);
}

static void refresh_bpwp_lists(AppState &state) {
  refresh_breakpoints(state);
  refresh_watchpoints(state);
}

static void reg_input(AppState &state, const char *label, int64_t &value,
                      bool hex = true) {
  (void)state;
  char buf[32];
  if (hex)
    std::snprintf(buf, sizeof(buf), "%016" PRIX64, static_cast<uint64_t>(value));
  else
    std::snprintf(buf, sizeof(buf), "%" PRId64, value);
  ImGui::SetNextItemWidth(140);
  if (ImGui::InputText(label, buf, sizeof(buf),
                       ImGuiInputTextFlags_CharsHexadecimal |
                           ImGuiInputTextFlags_EnterReturnsTrue)) {
    try {
      value = static_cast<int64_t>(std::stoull(buf, nullptr, 16));
    } catch (...) {
    }
  }
}

} // namespace

void draw_debugger(AppState &state, ImVec2 avail) {
  auto &ds = dstate(state);
  poll_debugger_state(state);

  ui::begin_panel("Debugger", locale::tr("debugger.title"), avail);

  const bool has_cap = state.hello.capabilities & MEMDBG_CAP_DEBUGGER;
  if (!has_cap) {
    ImGui::TextColored(ui::colors().warning, "%s",
                       locale::tr("debugger.unsupported"));
    ui::end_panel();
    return;
  }

  if (!state.client.connected()) {
    ImGui::TextColored(ui::colors().dim, "%s",
                       locale::tr("debugger.connect_first"));
    ui::end_panel();
    return;
  }

  /* ---- Attach / control ---- */
  if (ImGui::BeginChild("DebuggerControl", ImVec2(0, 110), true)) {
    ImGui::Text("PID");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120);
    ImGui::InputText("##pid", ds.pid_input, sizeof(ds.pid_input),
                     ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();

    if (!ds.attached) {
      ImGui::Checkbox(locale::tr("debugger.pause_on_attach"), &ds.pause_on_attach);
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", locale::tr("debugger.pause_on_attach_tip"));
      if (ui::primary_button(locale::tr("debugger.attach"), ImVec2(100, 0))) {
        int32_t pid = 0;
        try {
          pid = static_cast<int32_t>(std::stoi(ds.pid_input));
        } catch (...) {
          pid = 0;
        }
        if (pid > 0) {
          if (state.client.debug_attach(pid)) {
            ds.attached = true;
            ds.pid = pid;
            ds.selected_lwp = 0;
            if (ds.pause_on_attach) {
              if (state.client.debug_stop()) {
                ds.stopped = true;
              } else {
                ds.stopped = false;
                set_status(state, "Stop: " + state.client.last_error());
              }
            }
            refresh_threads(state);
            refresh_regs(state);
            refresh_bpwp_lists(state);
            set_status(state, locale::tr("debugger.attached") +
                                    std::to_string(pid));
          } else {
            set_status(state, "Attach: " + state.client.last_error());
          }
        }
      }
    } else {
      static bool skip_detach = false;
      if (ui::danger_button(locale::tr("debugger.detach"), ImVec2(100, 0))) {
        ImGui::OpenPopup("ConfirmDetach");
      }
      if (ui::confirm_modal("ConfirmDetach",
                            locale::tr("debugger.confirm_detach"), nullptr,
                            &skip_detach, true)) {
        if (state.client.debug_detach()) {
          ds.attached = false;
          ds.stopped = false;
          ds.pid = 0;
          ds.selected_lwp = 0;
          ds.threads.clear();
          set_status(state, locale::tr("debugger.detached"));
        } else {
          set_status(state, "Detach: " + state.client.last_error());
        }
      }
      ImGui::SameLine();
      ImGui::TextColored(ui::colors().dim, "PID %d", ds.pid);

      ImGui::BeginDisabled(!ds.stopped);
      if (ui::soft_button(locale::tr("debugger.continue"), ImVec2(120, 0))) {
        if (state.client.debug_continue()) {
          ds.stopped = false;
        } else {
          set_status(state, "Continue: " + state.client.last_error());
        }
      }
      ImGui::EndDisabled();

      ImGui::SameLine();
      ImGui::BeginDisabled(ds.stopped);
      if (ui::soft_button(locale::tr("debugger.stop"), ImVec2(80, 0))) {
        if (state.client.debug_stop()) {
          ds.stopped = true;
        } else {
          set_status(state, "Stop: " + state.client.last_error());
        }
      }
      ImGui::EndDisabled();

      ImGui::SameLine();
      ImGui::BeginDisabled(!ds.stopped || ds.selected_lwp == 0);
      if (ui::soft_button(locale::tr("debugger.step"), ImVec2(70, 0))) {
        if (state.client.debug_step(ds.selected_lwp)) {
          refresh_regs(state);
        } else {
          set_status(state, "Step: " + state.client.last_error());
        }
      }
      ImGui::EndDisabled();

      ImGui::SameLine();
      ImGui::TextColored(ds.stopped ? ui::colors().warning : ui::colors().success,
                         "%s", ds.stopped ? "STOPPED" : "RUNNING");
    }
  }
  ImGui::EndChild();

  if (!ds.attached) {
    ui::end_panel();
    return;
  }

  /* ---- Threads ---- */
  if (ImGui::BeginChild("DebuggerThreads", ImVec2(220, -1), true)) {
    ImGui::Text("Threads");
    ImGui::Separator();
    if (ImGui::Button(locale::tr("debugger.refresh"))) refresh_threads(state);
    if (ImGui::BeginListBox("##threads", ImVec2(-1, -1))) {
      for (const auto &t : ds.threads) {
        bool sel = (t.lwp == ds.selected_lwp);
        char label[64];
        std::snprintf(label, sizeof(label), "%d %s", (int)t.lwp,
                      t.name.c_str());
        if (ImGui::Selectable(label, sel)) {
          ds.selected_lwp = t.lwp;
          refresh_regs(state);
        }
      }
      ImGui::EndListBox();
    }
  }
  ImGui::EndChild();

  ImGui::SameLine();

  /* ---- Registers ---- */
  if (ImGui::BeginChild("DebuggerRegs", ImVec2(0, -1), true)) {
    ImGui::Text("Registers (LWP %d)", (int)ds.selected_lwp);
    ImGui::Separator();
    if (ImGui::Button(locale::tr("debugger.refresh"))) refresh_regs(state);
    ImGui::SameLine();
    ImGui::BeginDisabled(ds.selected_lwp == 0);
    if (ui::primary_button(locale::tr("debugger.set_regs"), ImVec2(120, 0))) {
      if (state.client.debug_set_regs(ds.selected_lwp, ds.regs)) {
        set_status(state, locale::tr("debugger.regs_set"));
      } else {
        set_status(state, "Set regs: " + state.client.last_error());
      }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::Checkbox(locale::tr("debugger.auto_refresh_on_stop"), &ds.auto_refresh_on_stop);
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("debugger.auto_refresh_on_stop_tip"));

    auto &r = ds.regs.regs;
    reg_input(state, "RAX", r.r_rax);
    ImGui::SameLine();
    reg_input(state, "RBX", r.r_rbx);
    ImGui::SameLine();
    reg_input(state, "RCX", r.r_rcx);
    ImGui::SameLine();
    reg_input(state, "RDX", r.r_rdx);

    reg_input(state, "RSI", r.r_rsi);
    ImGui::SameLine();
    reg_input(state, "RDI", r.r_rdi);
    ImGui::SameLine();
    reg_input(state, "RBP", r.r_rbp);
    ImGui::SameLine();
    reg_input(state, "RSP", r.r_rsp);

    reg_input(state, "R8 ", r.r_r8);
    ImGui::SameLine();
    reg_input(state, "R9 ", r.r_r9);
    ImGui::SameLine();
    reg_input(state, "R10", r.r_r10);
    ImGui::SameLine();
    reg_input(state, "R11", r.r_r11);

    reg_input(state, "R12", r.r_r12);
    ImGui::SameLine();
    reg_input(state, "R13", r.r_r13);
    ImGui::SameLine();
    reg_input(state, "R14", r.r_r14);
    ImGui::SameLine();
    reg_input(state, "R15", r.r_r15);

    reg_input(state, "RIP", r.r_rip);
    ImGui::SameLine();
    reg_input(state, "RFLAGS", r.r_rflags);

    static const char *cond_reg_names[] = {
      "None", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
      "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"
    };
    static const char *cond_op_names[] = {"==", "!=", "<", "<=", ">", ">="};

    /* ---- Breakpoints ---- */
    ImGui::Separator();
    ImGui::Text("Breakpoints");
    ImGui::SetNextItemWidth(140);
    ImGui::InputText("##bpaddr", ds.bp_input, sizeof(ds.bp_input),
                     ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(110);
    const char *bp_kinds[] = {"Software", "Hardware"};
    ImGui::Combo("##bpkind", &ds.bp_kind, bp_kinds, IM_ARRAYSIZE(bp_kinds));
    ImGui::SameLine();
    /* Condition row */
    ImGui::SetNextItemWidth(80);
    ImGui::Combo("##bpcondreg", &ds.bp_cond_reg, cond_reg_names,
                 IM_ARRAYSIZE(cond_reg_names));
    ImGui::SameLine();
    if (ds.bp_cond_reg != 0) {
      ImGui::SetNextItemWidth(55);
      ImGui::Combo("##bpcondop", &ds.bp_cond_op, cond_op_names,
                   IM_ARRAYSIZE(cond_op_names));
      ImGui::SameLine();
      ImGui::SetNextItemWidth(120);
      ImGui::InputText("##bpcondval", ds.bp_cond_val, sizeof(ds.bp_cond_val),
                       ImGuiInputTextFlags_CharsHexadecimal);
      ImGui::SameLine();
    }
    if (ui::primary_button(locale::tr("debugger.add_bp"), ImVec2(90, 0))) {
      uint64_t addr = 0;
      if (parse_input_u64(ds.bp_input, addr)) {
        uint64_t cv = 0;
        if (ds.bp_cond_reg != 0) parse_input_u64(ds.bp_cond_val, cv);
        bool ok = (ds.bp_cond_reg != 0)
            ? state.client.debug_set_breakpoint_cond(
                  addr, static_cast<uint32_t>(ds.bp_kind),
                  static_cast<uint32_t>(ds.bp_cond_reg),
                  static_cast<uint32_t>(ds.bp_cond_op), cv)
            : state.client.debug_set_breakpoint(
                  addr, static_cast<uint32_t>(ds.bp_kind));
        if (ok) {
          set_status(state, "Breakpoint set");
          refresh_breakpoints(state);
        } else {
          set_status(state, "BP: " + state.client.last_error());
        }
      }
    }

    /* Existing breakpoints */
    if (!ds.breakpoints.empty()) {
      ImGui::Spacing();
      ImGui::TextColored(ui::colors().muted, "%s (%zu)",
                         locale::tr("debugger.bp_list"), ds.breakpoints.size());
      ImGui::SameLine();
      static bool skip_clear_bp = false;
      if (ui::danger_button(locale::tr("debugger.clear_all_bp"), ImVec2(80, 0))) {
        ImGui::OpenPopup("ConfirmClearBP");
      }
      if (ui::confirm_modal("ConfirmClearBP",
                            locale::tr("debugger.confirm_clear_bp"), nullptr,
                            &skip_clear_bp, true)) {
        uint32_t cleared = 0;
        if (state.client.debug_clear_all_breakpoints(cleared)) {
          refresh_breakpoints(state);
          set_status(state, "Cleared " + std::to_string(cleared) + " breakpoint(s)");
        } else {
          set_status(state, "Clear All BP: " + state.client.last_error());
        }
      }
      if (ImGui::BeginTable("##bptable", 4,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
            ImVec2(0, 70.0f * ImGui::GetIO().FontGlobalScale))) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("Cond");
        ImGui::TableSetupColumn("");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < ds.breakpoints.size(); ++i) {
          const auto &bp = ds.breakpoints[i];
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          ImGui::Text("0x%016" PRIX64, bp.address);
          ImGui::TableSetColumnIndex(1);
          ImGui::Text("%s", bp.kind == 0 ? "SW" : "HW");
          ImGui::TableSetColumnIndex(2);
          if (bp.cond_reg != 0 && bp.cond_reg <= (uint32_t)MEMDBG_BP_COND_RIP &&
              bp.cond_op <= (uint32_t)MEMDBG_BP_COND_GE) {
            ImGui::Text("%s %s 0x%" PRIX64,
                        cond_reg_names[bp.cond_reg],
                        cond_op_names[bp.cond_op], bp.cond_value);
          } else {
            ImGui::TextColored(ui::colors().dim, "-");
          }
          ImGui::TableSetColumnIndex(3);
          ImGui::PushID((int)i);
          static bool skip_remove_bp = false;
          if (ui::danger_button(locale::tr("debugger.remove_bp"), ImVec2(50, 0))) {
            ImGui::OpenPopup("ConfirmRemoveBP");
          }
          char bp_detail[64];
          std::snprintf(bp_detail, sizeof(bp_detail), "0x%016" PRIX64, bp.address);
          if (ui::confirm_modal("ConfirmRemoveBP",
                                locale::tr("debugger.confirm_remove_bp"),
                                bp_detail, &skip_remove_bp, true)) {
            if (state.client.debug_clear_breakpoint(bp.address)) {
              refresh_breakpoints(state);
            } else {
              set_status(state, "Clear BP: " + state.client.last_error());
            }
          }
          ImGui::PopID();
        }
        ImGui::EndTable();
      }
    }

    /* ---- Watchpoints ---- */
    ImGui::Separator();
    ImGui::Text("Watchpoints");
    ImGui::SetNextItemWidth(140);
    ImGui::InputText("##wpaddr", ds.wp_input, sizeof(ds.wp_input),
                     ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80);
    ImGui::InputInt("##wplen", &ds.wp_length);
    ds.wp_length = std::clamp(ds.wp_length, 1, 8);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120);
    const char *wp_types[] = {"Exec", "Write", "Read", "Read/Write"};
    ImGui::Combo("##wptype", &ds.wp_type, wp_types, IM_ARRAYSIZE(wp_types));
    ImGui::SameLine();
    if (ui::primary_button(locale::tr("debugger.add_wp"), ImVec2(130, 0))) {
      uint64_t addr = 0;
      if (parse_input_u64(ds.wp_input, addr)) {
        if (state.client.debug_set_watchpoint(
                addr, static_cast<uint32_t>(ds.wp_length),
                static_cast<uint32_t>(ds.wp_type))) {
          set_status(state, "Watchpoint set");
          refresh_watchpoints(state);
        } else {
          set_status(state, "WP: " + state.client.last_error());
        }
      }
    }

    /* Existing watchpoints */
    if (!ds.watchpoints.empty()) {
      ImGui::Spacing();
      ImGui::TextColored(ui::colors().muted, "%s (%zu)",
                         locale::tr("debugger.wp_list"), ds.watchpoints.size());
      ImGui::SameLine();
      static bool skip_clear_wp = false;
      if (ui::danger_button(locale::tr("debugger.clear_all_wp"), ImVec2(80, 0))) {
        ImGui::OpenPopup("ConfirmClearWP");
      }
      if (ui::confirm_modal("ConfirmClearWP",
                            locale::tr("debugger.confirm_clear_wp"), nullptr,
                            &skip_clear_wp, true)) {
        uint32_t cleared = 0;
        if (state.client.debug_clear_all_watchpoints(cleared)) {
          refresh_watchpoints(state);
          set_status(state, "Cleared " + std::to_string(cleared) + " watchpoint(s)");
        } else {
          set_status(state, "Clear All WP: " + state.client.last_error());
        }
      }
      if (ImGui::BeginTable("##wptable", 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
            ImVec2(0, 70.0f * ImGui::GetIO().FontGlobalScale))) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableSetupColumn("Len");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Slot");
        ImGui::TableSetupColumn("");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < ds.watchpoints.size(); ++i) {
          const auto &wp = ds.watchpoints[i];
          static const char *wp_type_names[] = {"Exec", "Write", "Read", "R/W"};
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          ImGui::Text("0x%016" PRIX64, wp.address);
          ImGui::TableSetColumnIndex(1);
          ImGui::Text("%u", wp.length);
          ImGui::TableSetColumnIndex(2);
          ImGui::Text("%s", wp.type < 4 ? wp_type_names[wp.type] : "?");
          ImGui::TableSetColumnIndex(3);
          ImGui::Text("%u", wp.slot);
          ImGui::TableSetColumnIndex(4);
          ImGui::PushID((int)i);
          static bool skip_remove_wp = false;
          if (ui::danger_button(locale::tr("debugger.remove_wp"), ImVec2(50, 0))) {
            ImGui::OpenPopup("ConfirmRemoveWP");
          }
          char wp_detail[64];
          std::snprintf(wp_detail, sizeof(wp_detail), "0x%016" PRIX64, wp.address);
          if (ui::confirm_modal("ConfirmRemoveWP",
                                locale::tr("debugger.confirm_remove_wp"),
                                wp_detail, &skip_remove_wp, true)) {
            if (state.client.debug_clear_watchpoint(wp.address)) {
              refresh_watchpoints(state);
            } else {
              set_status(state, "Clear WP: " + state.client.last_error());
            }
          }
          ImGui::PopID();
        }
        ImGui::EndTable();
      }
    }
  }
  ImGui::EndChild();

  ui::end_panel();
}

} // namespace memdbg::frontend

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
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>

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
  int32_t pid_input_source = 0;

  std::vector<Client::DebugThreadEntry> threads;
  Client::DebugRegs regs{};
  std::vector<Client::DebugBreakpointEntry> breakpoints;
  std::vector<Client::DebugWatchpointEntry> watchpoints;
};

static DebuggerState s_dbg_state;

static DebuggerState &dstate(AppState &state) {
  (void)state;
  return s_dbg_state;
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

static void set_debugger_pid_input(DebuggerState &ds, int32_t pid) {
  if (pid > 0) {
    std::snprintf(ds.pid_input, sizeof(ds.pid_input), "%d", pid);
    ds.pid_input_source = pid;
  }
}

static void select_debugger_process(AppState &state, DebuggerState &ds, int row) {
  if (row < 0 || row >= static_cast<int>(state.processes.size())) return;
  const auto &proc = state.processes[row];
  set_debugger_pid_input(ds, proc.pid);
  state.selected_process_row = row;
  state.selected_pid = proc.pid;
  state.maps.clear();
  state.selected_map_row = -1;
  state.memory.clear();
  state.has_process_info = false;
  set_status(state, "Selected PID " + std::to_string(proc.pid) + " (" + proc.name + ")");
}

static bool refresh_debugger_process_list(AppState &state) {
  if (!state.client.connected()) return false;
  if (!state.client.process_list(state.processes)) {
    set_status(state, state.client.last_error());
    return false;
  }
  set_status(state, "Process list refreshed (" + std::to_string(state.processes.size()) + " entries)");
  return true;
}

static void draw_debugger_pid_selector(AppState &state, DebuggerState &ds) {
  if (!ds.attached && state.selected_pid > 0 && state.selected_pid != ds.pid_input_source) {
    set_debugger_pid_input(ds, state.selected_pid);
  }
  if (ds.attached) ImGui::BeginDisabled();

  const char *preview = "Select target process";
  std::string selected_label;
  for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
    const auto &proc = state.processes[i];
    if (proc.pid == ds.pid_input_source) {
      selected_label = std::to_string(proc.pid) + "  " + proc.name;
      preview = selected_label.c_str();
      break;
    }
  }

  ImGui::SetNextItemWidth(310.0f * ui::dpi_scale());
  if (ImGui::BeginCombo("##debugger_pid_combo", preview)) {
    if (state.processes.empty()) {
      ImGui::TextColored(ui::colors().dim, "%s", "No process list loaded");
    }
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const auto &proc = state.processes[i];
      const bool selected = proc.pid == ds.pid_input_source;
      std::string label = std::to_string(proc.pid) + "  " + proc.name;
      if (ImGui::Selectable(label.c_str(), selected)) {
        select_debugger_process(state, ds, i);
      }
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", "Select a PID from the loaded process list");

  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kRefresh) + "  PIDs").c_str(),
                      ImVec2(82.0f * ui::dpi_scale(), 0.0f))) {
    (void)refresh_debugger_process_list(state);
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", "Refresh process list");

  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%s", "PID");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(90.0f * ui::dpi_scale());
  if (ImGui::InputText("##pid", ds.pid_input, sizeof(ds.pid_input),
                       ImGuiInputTextFlags_CharsDecimal)) {
    ds.pid_input_source = 0;
  }
  if (ds.attached) ImGui::EndDisabled();
}

static void refresh_regs(AppState &state) {
  auto &ds = dstate(state);
  if (!state.client.connected() || !ds.attached || ds.selected_lwp == 0) return;
  if (client_async_busy(state)) return;
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
  if (client_async_busy(state)) return;

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
  if (!state.client.connected() || !ds.attached) return;
  if (client_async_busy(state)) return;
  ds.threads.clear();
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
  if (!state.client.connected() || !ds.attached) return;
  if (client_async_busy(state)) return;
  ds.breakpoints.clear();
  state.client.debug_get_breakpoints(ds.breakpoints);
}

static void refresh_watchpoints(AppState &state) {
  auto &ds = dstate(state);
  if (!state.client.connected() || !ds.attached) return;
  if (client_async_busy(state)) return;
  ds.watchpoints.clear();
  state.client.debug_get_watchpoints(ds.watchpoints);
}

static void refresh_bpwp_lists(AppState &state) {
  refresh_breakpoints(state);
  refresh_watchpoints(state);
}

static int responsive_columns(float available_width, float min_cell_width,
                              int max_columns) {
  if (available_width <= min_cell_width) return 1;
  int columns = static_cast<int>(available_width / min_cell_width);
  return std::clamp(columns, 1, max_columns);
}

static void set_table_item_width(float fallback) {
  const float avail = ImGui::GetContentRegionAvail().x;
  ImGui::SetNextItemWidth(avail > 24.0f ? -1.0f : fallback);
}

static int64_t reg_input_cell(const char *label, int64_t value) {
  char buf[32];
  const float scl = ui::dpi_scale();

  std::snprintf(buf, sizeof(buf), "%016" PRIX64, static_cast<uint64_t>(value));
  ImGui::PushID(label);
  ImGui::AlignTextToFramePadding();
  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::SameLine(46.0f * scl);
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::InputText("##value", buf, sizeof(buf),
                       ImGuiInputTextFlags_CharsHexadecimal |
                           ImGuiInputTextFlags_EnterReturnsTrue)) {
    try {
      value = static_cast<int64_t>(std::stoull(buf, nullptr, 16));
    } catch (...) {
    }
  }
  ImGui::PopID();
  return value;
}

enum class RegField {
  RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP,
  R8, R9, R10, R11, R12, R13, R14, R15, RIP, RFLAGS,
};

static int64_t reg_field_value(const memdbg_debug_regs_t &regs, RegField field) {
  switch (field) {
  case RegField::RAX: return regs.r_rax;
  case RegField::RBX: return regs.r_rbx;
  case RegField::RCX: return regs.r_rcx;
  case RegField::RDX: return regs.r_rdx;
  case RegField::RSI: return regs.r_rsi;
  case RegField::RDI: return regs.r_rdi;
  case RegField::RBP: return regs.r_rbp;
  case RegField::RSP: return regs.r_rsp;
  case RegField::R8: return regs.r_r8;
  case RegField::R9: return regs.r_r9;
  case RegField::R10: return regs.r_r10;
  case RegField::R11: return regs.r_r11;
  case RegField::R12: return regs.r_r12;
  case RegField::R13: return regs.r_r13;
  case RegField::R14: return regs.r_r14;
  case RegField::R15: return regs.r_r15;
  case RegField::RIP: return regs.r_rip;
  case RegField::RFLAGS: return regs.r_rflags;
  }
  return 0;
}

static void set_reg_field_value(memdbg_debug_regs_t &regs, RegField field,
                                int64_t value) {
  switch (field) {
  case RegField::RAX: regs.r_rax = value; break;
  case RegField::RBX: regs.r_rbx = value; break;
  case RegField::RCX: regs.r_rcx = value; break;
  case RegField::RDX: regs.r_rdx = value; break;
  case RegField::RSI: regs.r_rsi = value; break;
  case RegField::RDI: regs.r_rdi = value; break;
  case RegField::RBP: regs.r_rbp = value; break;
  case RegField::RSP: regs.r_rsp = value; break;
  case RegField::R8: regs.r_r8 = value; break;
  case RegField::R9: regs.r_r9 = value; break;
  case RegField::R10: regs.r_r10 = value; break;
  case RegField::R11: regs.r_r11 = value; break;
  case RegField::R12: regs.r_r12 = value; break;
  case RegField::R13: regs.r_r13 = value; break;
  case RegField::R14: regs.r_r14 = value; break;
  case RegField::R15: regs.r_r15 = value; break;
  case RegField::RIP: regs.r_rip = value; break;
  case RegField::RFLAGS: regs.r_rflags = value; break;
  }
}

} // namespace

void reset_debugger_state() { s_dbg_state = DebuggerState{}; }

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

  const bool client_busy = client_async_busy(state);
  if (client_busy) {
    ImGui::TextColored(ui::colors().warning, "%s",
                       "Wait for the active operation to finish");
    ImGui::BeginDisabled();
  }

  /* ---- Attach / control ---- */
  if (ImGui::BeginChild("DebuggerControl", ImVec2(0, 122.0f * ui::dpi_scale()), true)) {
    draw_debugger_pid_selector(state, ds);

    if (!ds.attached) {
      ImGui::Spacing();
      ImGui::Checkbox(locale::tr("debugger.pause_on_attach"), &ds.pause_on_attach);
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", locale::tr("debugger.pause_on_attach_tip"));
      ImGui::SameLine();
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
    if (client_busy) ImGui::EndDisabled();
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
    const float scl = ui::dpi_scale();
    struct RegCell {
      const char *label;
      RegField field;
    };
    std::array<RegCell, 18> reg_cells{{
        {"RAX", RegField::RAX}, {"RBX", RegField::RBX},
        {"RCX", RegField::RCX}, {"RDX", RegField::RDX},
        {"RSI", RegField::RSI}, {"RDI", RegField::RDI},
        {"RBP", RegField::RBP}, {"RSP", RegField::RSP},
        {"R8", RegField::R8}, {"R9", RegField::R9},
        {"R10", RegField::R10}, {"R11", RegField::R11},
        {"R12", RegField::R12}, {"R13", RegField::R13},
        {"R14", RegField::R14}, {"R15", RegField::R15},
        {"RIP", RegField::RIP}, {"RFLAGS", RegField::RFLAGS},
    }};
    const int reg_columns =
        responsive_columns(ImGui::GetContentRegionAvail().x, 224.0f * scl, 4);
    if (ImGui::BeginTable("DebuggerRegGrid", reg_columns,
                          ImGuiTableFlags_SizingStretchSame |
                              ImGuiTableFlags_PadOuterX)) {
      for (auto &cell : reg_cells) {
        ImGui::TableNextColumn();
        const int64_t edited =
            reg_input_cell(cell.label, reg_field_value(r, cell.field));
        set_reg_field_value(r, cell.field, edited);
      }
      ImGui::EndTable();
    }

    static const char *cond_reg_names[] = {
      "None", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
      "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"
    };
    static const char *cond_op_names[] = {"==", "!=", "<", "<=", ">", ">="};

    /* ---- Breakpoints ---- */
    ImGui::Separator();
    ImGui::Text("Breakpoints");
    const char *bp_kinds[] = {"Software", "Hardware"};
    if (ImGui::BeginTable("BreakpointEditor", 5,
                          ImGuiTableFlags_SizingStretchProp |
                              ImGuiTableFlags_PadOuterX)) {
      ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.35f);
      ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 118.0f * scl);
      ImGui::TableSetupColumn("Condition", ImGuiTableColumnFlags_WidthFixed, 92.0f * scl);
      ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
      ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 112.0f * scl);
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      set_table_item_width(140.0f * scl);
      ImGui::InputText("##bpaddr", ds.bp_input, sizeof(ds.bp_input),
                       ImGuiInputTextFlags_CharsHexadecimal);
      ImGui::TableSetColumnIndex(1);
      set_table_item_width(110.0f * scl);
      ImGui::Combo("##bpkind", &ds.bp_kind, bp_kinds, IM_ARRAYSIZE(bp_kinds));
      ImGui::TableSetColumnIndex(2);
      set_table_item_width(80.0f * scl);
      ImGui::Combo("##bpcondreg", &ds.bp_cond_reg, cond_reg_names,
                   IM_ARRAYSIZE(cond_reg_names));
      ImGui::TableSetColumnIndex(3);
      if (ds.bp_cond_reg != 0) {
        if (ImGui::BeginTable("BreakpointConditionValue", 2,
                              ImGuiTableFlags_SizingStretchProp)) {
          ImGui::TableSetupColumn("Op", ImGuiTableColumnFlags_WidthFixed, 58.0f * scl);
          ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          set_table_item_width(55.0f * scl);
          ImGui::Combo("##bpcondop", &ds.bp_cond_op, cond_op_names,
                       IM_ARRAYSIZE(cond_op_names));
          ImGui::TableSetColumnIndex(1);
          set_table_item_width(120.0f * scl);
          ImGui::InputText("##bpcondval", ds.bp_cond_val, sizeof(ds.bp_cond_val),
                           ImGuiInputTextFlags_CharsHexadecimal);
          ImGui::EndTable();
        }
      } else {
        ImGui::TextColored(ui::colors().dim, "%s", "No condition");
      }
      ImGui::TableSetColumnIndex(4);
      if (ui::primary_button(locale::tr("debugger.add_bp"), ImVec2(-1, 0))) {
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
      ImGui::EndTable();
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
    const char *wp_types[] = {"Exec", "Write", "Read", "Read/Write"};
    if (ImGui::BeginTable("WatchpointEditor", 4,
                          ImGuiTableFlags_SizingStretchProp |
                              ImGuiTableFlags_PadOuterX)) {
      ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.3f);
      ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 82.0f * scl);
      ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 128.0f * scl);
      ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 136.0f * scl);
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      set_table_item_width(140.0f * scl);
      ImGui::InputText("##wpaddr", ds.wp_input, sizeof(ds.wp_input),
                       ImGuiInputTextFlags_CharsHexadecimal);
      ImGui::TableSetColumnIndex(1);
      set_table_item_width(80.0f * scl);
      ImGui::InputInt("##wplen", &ds.wp_length);
      ds.wp_length = std::clamp(ds.wp_length, 1, 8);
      ImGui::TableSetColumnIndex(2);
      set_table_item_width(120.0f * scl);
      ImGui::Combo("##wptype", &ds.wp_type, wp_types, IM_ARRAYSIZE(wp_types));
      ImGui::TableSetColumnIndex(3);
      if (ui::primary_button(locale::tr("debugger.add_wp"), ImVec2(-1, 0))) {
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
      ImGui::EndTable();
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

  if (client_busy) ImGui::EndDisabled();
  ui::end_panel();
}

} // namespace memdbg::frontend

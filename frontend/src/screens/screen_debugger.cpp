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
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <future>
#include <string>
#include <unordered_set>

namespace memdbg::frontend {

namespace {

struct DebuggerState {
  bool attached = false;
  bool stopped = false;
  bool attach_pending = false;
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
  bool follow_rip = true;
  int32_t pid_input_source = 0;

  std::vector<Client::DebugThreadEntry> threads;
  Client::DebugRegs regs{};
  std::vector<Client::DebugBreakpointEntry> breakpoints;
  std::vector<Client::DebugWatchpointEntry> watchpoints;

  struct DisasmLine {
    uint64_t address = 0;
    std::string bytes;
    std::string mnemonic;
  };
  std::vector<DisasmLine> disasm_lines;
  uint64_t disasm_base = 0;
  bool disasm_needs_refresh = true;
  bool disasm_follow_rip = true;   /* auto-center disasm on RIP after stops */
  uint64_t disasm_nav_addr = 0;    /* user-navigated address; 0 = use RIP */
  int disasm_reg_sel = 0;          /* 0 = RIP, 1-16 = RAX-R15 */
  bool disasm_cfg_view = false;     /* show only jump/call targets */
  char goto_addr_input[32] = {};    /* Go-to-address hex input */
  char bp_filename[256] = "breakpoints.mbp";
  char wp_filename[256] = "watchpoints.mwp";



  /* Stack view */
  std::vector<uint8_t> stack_bytes;
  uint64_t stack_base = 0;
  bool stack_needs_refresh = true;
};

static DebuggerState s_dbg_state;

struct DebuggerAttachResult {
  bool ok = false;
  bool stopped = false;
  bool has_regs = false;
  int32_t pid = 0;
  int32_t selected_lwp = 0;
  std::string error;
  std::vector<Client::DebugThreadEntry> threads;
  Client::DebugRegs regs{};
  std::vector<Client::DebugBreakpointEntry> breakpoints;
  std::vector<Client::DebugWatchpointEntry> watchpoints;
};

static std::future<DebuggerAttachResult> s_attach_future;

static DebuggerState &dstate(AppState &state) {
  (void)state;
  return s_dbg_state;
}

static bool parse_input_u64(const char *text, uint64_t &out) {
  if (text == nullptr || text[0] == '\0') return false;
  std::string value = trim_copy(text);
  if (value.empty()) return false;
  int base = 16;
  if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) {
    value = value.substr(2);
  }
  try {
    size_t consumed = 0;
    out = static_cast<uint64_t>(std::stoull(value, &consumed, base));
    return consumed == value.size();
  } catch (...) {
    return false;
  }
}

static bool parse_pid_input(const char *text, int32_t &out) {
  if (text == nullptr || text[0] == '\0') return false;
  try {
    size_t consumed = 0;
    int value = std::stoi(text, &consumed, 10);
    if (consumed != std::strlen(text) || value <= 0) return false;
    out = static_cast<int32_t>(value);
    return true;
  } catch (...) {
    return false;
  }
}

static void poll_debugger_state(AppState &state);
static void refresh_threads(AppState &state);
static void refresh_disasm(AppState &state);
static void refresh_stack(AppState &state);

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
    /* Auto-refresh regs/disasm when the target just transitioned to stopped */
    if (ds.auto_refresh_on_stop && !was_stopped && stopped) {
      refresh_regs(state);
      refresh_threads(state);          /* If Follow RIP is on, clear any user-navigated address */
          if (ds.disasm_follow_rip) {
            ds.disasm_nav_addr = 0;
            ds.disasm_reg_sel = 0;
          }
      ds.disasm_needs_refresh = true;
      ds.stack_needs_refresh = true;
      refresh_disasm(state);
      refresh_stack(state);
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

static void start_debugger_attach(AppState &state, DebuggerState &ds,
                                  int32_t pid) {
  if (pid <= 0 || ds.attach_pending) return;

  ds.attach_pending = true;
  ds.threads.clear();
  ds.breakpoints.clear();
  ds.watchpoints.clear();
  set_status(state, "Attaching to PID " + std::to_string(pid) + "...");

  const bool pause_on_attach = ds.pause_on_attach;
  auto &client = state.client;
  s_attach_future = std::async(std::launch::async,
      [&client, pid, pause_on_attach]() -> DebuggerAttachResult {
    DebuggerAttachResult result;
    result.pid = pid;

    if (!client.debug_attach(pid)) {
      result.error = client.last_error();
      return result;
    }

    result.ok = true;
    result.stopped = true;

    if (pause_on_attach) {
      if (!client.debug_stop()) {
        result.stopped = false;
        result.error = "Stop: " + client.last_error();
      }
    }

    /* Fetch threads and registers inside the async worker so they arrive
     * pre-populated in the result — no synchronous network calls needed
     * in poll_debugger_attach after the future completes. */
    if (result.stopped) {
      std::vector<Client::DebugThreadEntry> threads;
      if (client.debug_get_threads(threads) && !threads.empty()) {
        result.threads = std::move(threads);
        result.selected_lwp = result.threads[0].lwp;

        Client::DebugRegs regs{};
        if (client.debug_get_regs(result.selected_lwp, regs)) {
          result.regs = regs;
          result.has_regs = true;
        }
      }
    }

    return result;
  });
}

static void poll_debugger_attach(AppState &state, DebuggerState &ds) {
  if (!ds.attach_pending) return;
  if (!s_attach_future.valid()) {
    ds.attach_pending = false;
    set_status(state, "Attach: worker did not start");
    return;
  }

  auto status = s_attach_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  DebuggerAttachResult result;
  try {
    result = s_attach_future.get();
  } catch (const std::exception &ex) {
    result.error = ex.what();
  } catch (...) {
    result.error = "Unknown attach error";
  }

  ds.attach_pending = false;
  if (!result.ok) {
    set_status(state, "Attach: " + result.error);
    return;
  }

  ds.attached = true;
  ds.pid = result.pid;
  ds.stopped = result.stopped;
  ds.selected_lwp = result.selected_lwp;
  ds.threads = std::move(result.threads);
  ds.breakpoints = std::move(result.breakpoints);
  ds.watchpoints = std::move(result.watchpoints);
  if (result.has_regs) ds.regs = result.regs;

  set_status(state, locale::tr("debugger.attached") +
                    std::to_string(result.pid));
  if (!result.error.empty())
    push_notification(state, result.error, 5.0);
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

/* ---- x86-64 disassembler (compact, focused on common instructions) ---- */

static const char *kRegNames64[] = {
  "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
  "r8","r9","r10","r11","r12","r13","r14","r15"
};
static const char *kRegNames32[] = {
  "eax","ecx","edx","ebx","esp","ebp","esi","edi",
  "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};
static const char *kRegNames16[] = {
  "ax","cx","dx","bx","sp","bp","si","di",
  "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};
static const char *kRegNames8[] = {
  "al","cl","dl","bl","ah","ch","dh","bh",
  "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};

enum class OpSize { k8, k16, k32, k64 };

struct DecodedOp {
  enum Kind { kReg, kMem, kImm, kNone } kind = kNone;
  int reg = 0;       /* register index 0-15 */
  int base_reg = 0;
  int index_reg = -1;
  int scale = 1;
  int64_t disp = 0;
  uint64_t imm = 0;
  OpSize size = OpSize::k64;
};

struct DecodedInsn {
  const char *mnemonic = "???";
  DecodedOp dst, src;
  uint8_t length = 1;
  bool is_jump = false;
  bool is_call = false;
  bool is_ret = false;
};

static uint8_t modrm_mod(uint8_t b) { return (b >> 6) & 3; }
static uint8_t modrm_reg(uint8_t b) { return (b >> 3) & 7; }
static uint8_t modrm_rm(uint8_t b) { return b & 7; }

static int rex_b(uint8_t r) { return (r & 1) ? 8 : 0; }
static int rex_x(uint8_t r) { return (r & 2) ? 8 : 0; }
static int rex_r(uint8_t r) { return (r & 4) ? 8 : 0; }
static int rex_w(uint8_t r) { return (r & 8); }

static size_t decode_modrm_sib(const uint8_t *bytes, size_t pos, size_t len,
                                uint8_t rex, OpSize size, DecodedOp &op) {
  if (pos >= len) return pos;
  uint8_t modrm = bytes[pos++];
  uint8_t mod = modrm_mod(modrm);
  uint8_t rm  = modrm_rm(modrm);
  op.reg = modrm_reg(modrm) + rex_r(rex);

  if (mod == 3) {
    /* register direct */
    op.kind = DecodedOp::kReg;
    op.reg = rm + rex_b(rex);
    return pos;
  }

  /* memory operand */
  op.kind = DecodedOp::kMem;
  op.size = size;

  bool has_sib = (rm == 4);
  if (rm == 5 && mod == 0) {
    /* RIP-relative: disp32 follows */
    if (pos + 4 > len) return pos;
    memcpy(&op.disp, bytes + pos, 4);
    op.disp = (int32_t)op.disp;
    pos += 4;
    return pos;
  }

  if (has_sib) {
    if (pos >= len) return pos;
    uint8_t sib = bytes[pos++];
    op.scale = 1 << ((sib >> 6) & 3);
    op.index_reg = (int)((sib >> 3) & 7) + rex_x(rex);
    op.base_reg = (int)(sib & 7) + rex_b(rex);
    if (op.index_reg == 4 && ((sib >> 6) & 3) == 0) op.index_reg = -1;
    if (op.base_reg == 5 && mod == 0) {
      if (pos + 4 > len) return pos;
      memcpy(&op.disp, bytes + pos, 4);
      op.disp = (int32_t)op.disp;
      pos += 4;
      op.base_reg = -1;
      return pos;
    }
  } else {
    op.base_reg = (int)rm + rex_b(rex);
    op.index_reg = -1;
  }

  if (mod == 1) { if (pos < len) { op.disp = (int8_t)bytes[pos++]; } }
  else if (mod == 2) { if (pos + 4 <= len) { memcpy(&op.disp, bytes + pos, 4); op.disp = (int32_t)op.disp; pos += 4; } }
  return pos;
}

static void format_operand(const DecodedOp &op, std::string &out) {
  char buf[64];
  switch (op.kind) {
  case DecodedOp::kReg:
    switch (op.size) {
    case OpSize::k8:  snprintf(buf, sizeof(buf), "%s", kRegNames8[op.reg & 15]); break;
    case OpSize::k16: snprintf(buf, sizeof(buf), "%s", kRegNames16[op.reg & 15]); break;
    case OpSize::k32: snprintf(buf, sizeof(buf), "%s", kRegNames32[op.reg & 15]); break;
    default:          snprintf(buf, sizeof(buf), "%s", kRegNames64[op.reg & 15]); break;
    }
    out += buf;
    break;
  case DecodedOp::kMem: {
    bool need_plus = false;
    out += "[";
    if (op.base_reg >= 0) { out += kRegNames64[op.base_reg & 15]; need_plus = true; }
    if (op.index_reg >= 0) {
      if (need_plus) out += "+";
      out += kRegNames64[op.index_reg & 15];
      if (op.scale > 1) { snprintf(buf, sizeof(buf), "*%d", op.scale); out += buf; }
      need_plus = true;
    }
    if (op.disp != 0 || (!need_plus)) {
      if (need_plus && op.disp >= 0) out += "+";
      snprintf(buf, sizeof(buf), "0x%" PRIX64, (uint64_t)op.disp);
      out += buf;
    }
    out += "]";
    break;
  }
  case DecodedOp::kImm:
    snprintf(buf, sizeof(buf), "0x%" PRIX64, op.imm);
    out += buf;
    break;
  default: break;
  }
}

enum class InsnKind {
  /* opcode patterns */
  kRet, kCall, kJmp, kJcc, kSyscall, kInt3, kNop,
  kPush, kPop,
  kMovRR, kMovRM, kMovMR, kMovRI,
  kAdd, kSub, kCmp, kTest, kAnd, kOr, kXor,
  kLea, kXchg,
  kInc, kDec, kNot, kNeg,
  kShl, kShr, kSar,
  kMovsx, kMovzx,
  kUnknown
};

struct OpcodeEntry {
  uint16_t mask;   /* which bytes must match */
  uint16_t pattern; /* expected byte values */
  InsnKind kind;
  const char *mnemonic;
  OpSize size;
  uint8_t flags; /* bit0=swap operands, bit1=dst is rm, bit2=src is rm */
};

static const OpcodeEntry kOpcodeTable[] = {
  /* 1-byte opcodes */
  {0xFFFF, 0x00C3, InsnKind::kRet,     "ret",     OpSize::k64, 0},
  {0xFFFF, 0x00E8, InsnKind::kCall,    "call",    OpSize::k64, 0},
  {0xFFFF, 0x00E9, InsnKind::kJmp,     "jmp",     OpSize::k64, 0},
  {0xFFFF, 0x00EB, InsnKind::kJmp,     "jmp",     OpSize::k64, 0},
  {0xFFFF, 0x0005, InsnKind::kSyscall, "syscall", OpSize::k64, 0},
  {0xFFFF, 0x00CC, InsnKind::kInt3,    "int3",    OpSize::k64, 0},
  {0xFFFF, 0x0090, InsnKind::kNop,     "nop",     OpSize::k64, 0},
  {0xFF00, 0x7000, InsnKind::kJcc,     "j",       OpSize::k64, 0}, /* 70-7F */
  {0xFFF8, 0x0050, InsnKind::kPush,    "push",    OpSize::k64, 0}, /* 50-57 push */
  {0xFFF8, 0x0058, InsnKind::kPop,     "pop",     OpSize::k64, 0}, /* 58-5F pop */
  /* mov variants */
  {0xFFFE, 0x008A, InsnKind::kMovRR,   "mov",     OpSize::k8,  0},
  {0xFFFE, 0x008B, InsnKind::kMovRR,   "mov",     OpSize::k64, 0},
  {0xFFF0, 0xB000, InsnKind::kMovRI,   "mov",     OpSize::k8,  0}, /* B0-B7 */
  {0xFFF0, 0xB800, InsnKind::kMovRI,   "mov",     OpSize::k64, 0}, /* B8-BF */
  {0xFFFE, 0x00C6, InsnKind::kMovRM,   "mov",     OpSize::k8,  2}, /* C6 /0 ib */
  {0xFFFE, 0x00C7, InsnKind::kMovRM,   "mov",     OpSize::k64, 2}, /* C7 /0 id */
  /* ALU */
  {0xFFFE, 0x0001, InsnKind::kAdd,     "add",     OpSize::k64, 0},
  {0xFFFE, 0x0029, InsnKind::kSub,     "sub",     OpSize::k64, 0},
  {0xFFFE, 0x0039, InsnKind::kCmp,     "cmp",     OpSize::k64, 0},
  {0xFFFE, 0x0085, InsnKind::kTest,    "test",    OpSize::k64, 0},
  {0xFFFE, 0x0021, InsnKind::kAnd,     "and",     OpSize::k64, 0},
  {0xFFFE, 0x0009, InsnKind::kOr,      "or",      OpSize::k64, 0},
  {0xFFFE, 0x0031, InsnKind::kXor,     "xor",     OpSize::k64, 0},
  /* 0x83 group 1 (add/sub/cmp/and/or/xor with imm8) */
  {0xFFFF, 0x0083, InsnKind::kAdd,     "add",     OpSize::k64, 2}, /* /0 */
  {0xFFFF, 0x008D, InsnKind::kLea,     "lea",     OpSize::k64, 0},
  {0xFFFF, 0x0087, InsnKind::kXchg,    "xchg",    OpSize::k64, 0},
  /* 0F 2-byte opcodes */
  {0xFFFF, 0x0F84, InsnKind::kJcc,     "je",      OpSize::k64, 0},
  {0xFFFF, 0x0F85, InsnKind::kJcc,     "jne",     OpSize::k64, 0},
  {0xFFF0, 0x0F80, InsnKind::kJcc,     "j",       OpSize::k64, 0}, /* 0F80-0F8F */
  {0xFFFF, 0x0FB6, InsnKind::kMovzx,   "movzx",   OpSize::k64, 0},
  {0xFFFF, 0x0FBE, InsnKind::kMovsx,   "movsx",   OpSize::k64, 0},
  {0, 0, InsnKind::kUnknown, "???", OpSize::k64, 0}
};

static const char *kJccNames[16] = {
  "jo","jno","jb","jnb","jz","jnz","jbe","ja",
  "js","jns","jp","jnp","jl","jge","jle","jg"
};

static DecodedInsn decode_one(const uint8_t *bytes, size_t len) {
  DecodedInsn insn;
  if (len < 1) return insn;

  size_t pos = 0;
  uint8_t rex = 0;
  bool has_66 = false;

  /* prefixes */
  while (pos < len) {
    uint8_t b = bytes[pos];
    if (b >= 0x40 && b <= 0x4F) { rex = b; pos++; }
    else if (b == 0x66) { has_66 = true; pos++; }
    else if (b == 0x67) { pos++; }  /* addr-size override, ignore */
    else break;
  }
  if (pos >= len) { insn.length = (uint8_t)pos; return insn; }

  OpSize def_size = OpSize::k64;
  if (rex_w(rex)) def_size = OpSize::k64;
  else if (has_66) def_size = OpSize::k16;

  /* build 16-bit opcode key: if byte 0 is 0x0F, use 2-byte key */
  uint16_t opkey = bytes[pos];
  size_t op_pos = pos;
  if (bytes[pos] == 0x0F && pos + 1 < len) {
    opkey = (uint16_t)((0x0F00) | bytes[pos + 1]);
    pos++;
  }
  pos++;

  const OpcodeEntry *match = nullptr;
  for (const OpcodeEntry *e = kOpcodeTable; e->mask != 0; ++e) {
    if ((opkey & e->mask) == e->pattern) { match = e; break; }
  }
  if (match == nullptr) {
    insn.length = (uint8_t)pos;
    return insn;
  }

  insn.mnemonic = match->mnemonic;
  OpSize sz = match->size != OpSize::k64 ? match->size : def_size;

  switch (match->kind) {
  case InsnKind::kRet:
  case InsnKind::kNop:
    insn.is_ret = (match->kind == InsnKind::kRet);
    insn.length = (uint8_t)pos;
    return insn;

  case InsnKind::kInt3:
    insn.length = (uint8_t)pos;
    insn.is_ret = true;
    return insn;

  case InsnKind::kSyscall:
    insn.length = (uint8_t)pos;
    return insn;

  case InsnKind::kCall:
  case InsnKind::kJmp:
  case InsnKind::kJcc: {
    insn.is_call = (match->kind == InsnKind::kCall);
    insn.is_jump = (match->kind == InsnKind::kJmp || match->kind == InsnKind::kJcc);
    uint8_t op = bytes[op_pos];
    if (op == 0xEB && pos < len) {
      int8_t rel8 = (int8_t)bytes[pos];
      insn.dst.kind = DecodedOp::kImm;
      insn.dst.imm = (uint64_t)((int64_t)rel8);
      insn.length = (uint8_t)(pos + 1);
    } else if (pos + 4 <= len) {
      int32_t rel32;
      memcpy(&rel32, bytes + pos, 4);
      insn.dst.kind = DecodedOp::kImm;
      insn.dst.imm = (uint64_t)((int64_t)rel32);
      insn.length = (uint8_t)(pos + 4);
    } else {
      insn.length = (uint8_t)pos;
    }
    if (match->kind == InsnKind::kJcc) {
      uint8_t op_low = bytes[op_pos] & 0x0F;
      if (match->pattern == 0x0F80) {
        insn.mnemonic = kJccNames[op_low];
      } else if (match->pattern >= 0x7000 && match->pattern <= 0x7F00) {
        insn.mnemonic = kJccNames[op_low];
      }
    }
    return insn;
  }

  case InsnKind::kPush:
  case InsnKind::kPop: {
    uint8_t reg = (bytes[op_pos] & 7) + rex_b(rex);
    insn.dst.kind = DecodedOp::kReg;
    insn.dst.reg = (int)reg;
    insn.dst.size = OpSize::k64;
    insn.length = (uint8_t)pos;
    return insn;
  }

  case InsnKind::kMovRI: {
    uint8_t reg = (bytes[op_pos] & 7) + rex_b(rex);
    insn.dst.kind = DecodedOp::kReg;
    insn.dst.reg = (int)reg;
    insn.dst.size = (match->pattern >= 0xB800) ? OpSize::k64 : OpSize::k8;
    insn.src.kind = DecodedOp::kImm;
    int imm_len = (match->pattern >= 0xB800) ? 8 : 1;
    if (pos + imm_len <= len) {
      memcpy(&insn.src.imm, bytes + pos, imm_len);
      insn.length = (uint8_t)(pos + imm_len);
    } else {
      insn.length = (uint8_t)pos;
    }
    return insn;
  }

  case InsnKind::kMovRM:  /* mov [rm], imm */
  case InsnKind::kAdd:
  case InsnKind::kSub:
  case InsnKind::kCmp:
  case InsnKind::kTest:
  case InsnKind::kAnd:
  case InsnKind::kOr:
  case InsnKind::kXor:
  case InsnKind::kLea:
  case InsnKind::kXchg:
  case InsnKind::kMovRR:
  case InsnKind::kMovzx:
  case InsnKind::kMovsx: {
    /* Save ModR/M reg field before decode_modrm_sib advances pos */
    uint8_t saved_reg = (pos < len) ? modrm_reg(bytes[pos]) : 0;
    pos = decode_modrm_sib(bytes, pos, len, rex, sz, insn.dst);
    /* for most ALU, dst is reg from modrm.reg, src is modrm.rm */
    if (match->kind == InsnKind::kMovRM) {
      /* mov [rm], imm: dst = memory, src = imm */
      insn.src.kind = DecodedOp::kImm;
      insn.src.size = sz;
      int ilen = (sz == OpSize::k8) ? 1 : (sz == OpSize::k64 ? 4 : (sz == OpSize::k32 ? 4 : 2));
      uint32_t raw = 0;
      if (pos + ilen <= len) { memcpy(&raw, bytes + pos, ilen); pos += ilen; insn.src.imm = raw; }
      /* dst is the memory operand decoded by modrm; reg field is rm */
      insn.dst.kind = DecodedOp::kMem;
      insn.dst.size = sz;
    } else if (match->kind == InsnKind::kLea) {
      insn.src.kind = DecodedOp::kMem;
      insn.src = insn.dst;  /* lea dst, [mem] */
      insn.dst.kind = DecodedOp::kReg;
      insn.dst.reg = modrm_reg(bytes[pos - ((bytes[op_pos] == 0x8D || bytes[op_pos] == 0x48) ? 1 : 0)]) + rex_r(rex);
    } else if (match->kind == InsnKind::kMovzx || match->kind == InsnKind::kMovsx) {
      insn.src = insn.dst;
      insn.dst.kind = DecodedOp::kReg;
      insn.dst.reg = modrm_reg(bytes[pos - 1]) + rex_r(rex);
      insn.dst.size = OpSize::k64;
    } else {
      /* standard: dst = reg, src = rm */
      DecodedOp src_op;
      /* dst was populated by decode_modrm_sib as rm; swap: dst=reg */
      insn.dst.reg = (saved_reg & 7) + rex_r(rex);
      insn.dst.kind = DecodedOp::kReg;
      insn.dst.size = sz;
      /* 0x83 group 1: dispatch mnemonic from ModR/M reg field */
      if (opkey == 0x0083) {
        static const char *grp1[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
        int n = saved_reg & 7;
        insn.mnemonic = grp1[n];
      }
      /* src is the memory/register from modrm */
      size_t pos2 = op_pos + 1;
      src_op = {};
      decode_modrm_sib(bytes, pos2, len, rex, sz, src_op);
      insn.src = src_op;
      if (pos2 > pos) pos = pos2;
    }
    insn.length = (uint8_t)pos;
    return insn;
  }

  case InsnKind::kInc:
  case InsnKind::kDec: {
    uint8_t reg = (bytes[op_pos] & 7) + rex_b(rex);
    insn.dst.kind = DecodedOp::kReg;
    insn.dst.reg = (int)reg;
    insn.dst.size = OpSize::k64;
    insn.length = (uint8_t)pos;
    return insn;
  }

  default:
    insn.length = (uint8_t)pos;
    return insn;
  }
}

static void refresh_disasm(AppState &state) {
  auto &ds = dstate(state);
  if (!state.client.connected() || !ds.attached) return;
  if (client_async_busy(state)) return;
  if (!ds.stopped || ds.selected_lwp == 0) return;

  /* Determine base address: register selection (live) > user navigation > RIP */
  uint64_t start_addr;
  if (ds.disasm_reg_sel > 0) {
    /* Register selected: always use the current register value so it
     * live-tracks across steps/continues without manual refresh */
    start_addr = (uint64_t)reg_field_value(ds.regs.regs,
                                           (RegField)(ds.disasm_reg_sel - 1));
  } else if (ds.disasm_nav_addr != 0) {
    start_addr = ds.disasm_nav_addr;
  } else {
    start_addr = (uint64_t)ds.regs.regs.r_rip;
  }
  if (start_addr == ds.disasm_base && !ds.disasm_needs_refresh) return;

  ds.disasm_lines.clear();
  ds.disasm_base = start_addr;
  ds.disasm_needs_refresh = false;

  /* Read 256 bytes from RIP */
  std::vector<uint8_t> code;
  if (!state.client.memory_read(ds.pid, start_addr, 256, code) || code.empty()) {
    ds.disasm_needs_refresh = true;
    return;
  }

  size_t pos = 0;
  while (pos < code.size() && ds.disasm_lines.size() < 60) {
    DecodedInsn insn = decode_one(code.data() + pos, code.size() - pos);
    if (insn.length == 0) insn.length = 1;

    DebuggerState::DisasmLine line;
    line.address = start_addr + pos;

    /* format raw bytes */
    char byte_buf[32];
    int off = 0;
    for (uint8_t i = 0; i < insn.length && i < 8; ++i)
      off += snprintf(byte_buf + off, sizeof(byte_buf) - off, "%02X ", code[pos + i]);
    line.bytes = byte_buf;

    /* format instruction */
    std::string text = insn.mnemonic;
    if (insn.dst.kind != DecodedOp::kNone || insn.src.kind != DecodedOp::kNone) {
      text += " ";
      format_operand(insn.dst, text);
      if (insn.src.kind != DecodedOp::kNone) {
        text += ", ";
        format_operand(insn.src, text);
      }
    }
    line.mnemonic = text;

    ds.disasm_lines.push_back(std::move(line));
    pos += insn.length;
    if (insn.is_ret && pos < code.size()) break;  /* stop at ret */
  }

  /* CFG filter: keep only jump/call/ret instructions and their targets.
   * Second pass re-decodes to collect relative branch destinations;
   * unlike the first pass we do NOT break on ret — we want to collect
   * all branch targets across the full disasm_lines window. */
  if (ds.disasm_cfg_view && !ds.disasm_lines.empty()) {
    std::unordered_set<uint64_t> targets;
    size_t pos2 = 0;
    for (size_t k = 0; k < ds.disasm_lines.size() && pos2 < code.size(); ++k) {
      DecodedInsn insn2 = decode_one(code.data() + pos2, code.size() - pos2);
      if (insn2.length == 0) insn2.length = 1;
      uint64_t line_addr = ds.disasm_base + pos2;

      if (insn2.is_jump || insn2.is_call) {
        if (insn2.dst.kind == DecodedOp::kImm) {
          uint64_t target = line_addr + insn2.length + (int64_t)insn2.dst.imm;
          targets.insert(target);
        }
        targets.insert(line_addr);  /* keep the branch itself */
      }
      if (insn2.is_ret)
        targets.insert(line_addr);
      pos2 += insn2.length;
    }

    std::vector<DebuggerState::DisasmLine> filtered;
    for (auto &dl : ds.disasm_lines) {
      if (targets.count(dl.address))
        filtered.push_back(std::move(dl));
    }
    ds.disasm_lines = std::move(filtered);
  }
}

static void refresh_stack(AppState &state) {
  auto &ds = dstate(state);
  if (!state.client.connected() || !ds.attached) return;
  if (client_async_busy(state)) return;
  if (!ds.stopped || ds.selected_lwp == 0) return;

  uint64_t rsp = (uint64_t)ds.regs.regs.r_rsp;
  if (rsp == ds.stack_base && !ds.stack_needs_refresh) return;

  ds.stack_bytes.clear();
  ds.stack_base = rsp;
  ds.stack_needs_refresh = false;

  /* Read 64 quadwords (512 bytes) above RSP */
  if (!state.client.memory_read(ds.pid, rsp, 512, ds.stack_bytes) || ds.stack_bytes.empty()) {
    ds.stack_needs_refresh = true;
    return;
  }
}

} // namespace

/* ---- Save / Load breakpoints & watchpoints ---- */

static void save_breakpoints_to_file(AppState &state, const char *path) {
  const auto &ds = dstate(state);
  std::ofstream f(path);
  if (!f) {
    set_status(state, std::string("Cannot write: ") + path);
    return;
  }
  f << "# MemDBG Breakpoints\n";
  f << "# format: address kind cond_reg cond_op cond_value\n";
  for (const auto &bp : ds.breakpoints) {
    f << std::hex << "0x" << bp.address << std::dec
      << " " << bp.kind
      << " " << bp.cond_reg
      << " " << bp.cond_op
      << " " << std::hex << "0x" << bp.cond_value << std::dec << "\n";
  }
  set_status(state, std::string("Saved ") + std::to_string(ds.breakpoints.size()) +
                    " breakpoints to " + std::string(path));
}

static void load_breakpoints_from_file(AppState &state, const char *path) {
  std::ifstream f(path);
  if (!f) {
    set_status(state, std::string("Cannot read: ") + path);
    return;
  }
  uint32_t loaded = 0;
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') continue;
    uint64_t addr = 0, cond_val = 0;
    uint32_t kind = 0, cond_reg = 0, cond_op = 0;
    if (sscanf(line.c_str(), "0x%" SCNx64 " %" SCNu32 " %" SCNu32 " %" SCNu32 " 0x%" SCNx64,
               &addr, &kind, &cond_reg, &cond_op, &cond_val) >= 4) {
      bool ok = (cond_reg != 0)
          ? state.client.debug_set_breakpoint_cond(addr, kind, cond_reg, cond_op, cond_val)
          : state.client.debug_set_breakpoint(addr, kind);
      if (ok) loaded++;
    }
  }
  refresh_breakpoints(state);
  set_status(state, std::string("Loaded ") + std::to_string(loaded) +
                    " breakpoints from " + std::string(path));
}

static void save_watchpoints_to_file(AppState &state, const char *path) {
  const auto &ds = dstate(state);
  std::ofstream f(path);
  if (!f) {
    set_status(state, std::string("Cannot write: ") + path);
    return;
  }
  f << "# MemDBG Watchpoints\n";
  f << "# format: address length type\n";
  for (const auto &wp : ds.watchpoints) {
    f << std::hex << "0x" << wp.address << std::dec
      << " " << wp.length
      << " " << wp.type << "\n";
  }
  set_status(state, std::string("Saved ") + std::to_string(ds.watchpoints.size()) +
                    " watchpoints to " + std::string(path));
}

static void load_watchpoints_from_file(AppState &state, const char *path) {
  std::ifstream f(path);
  if (!f) {
    set_status(state, std::string("Cannot read: ") + path);
    return;
  }
  uint32_t loaded = 0;
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') continue;
    uint64_t addr = 0;
    uint32_t len = 0, type = 0;
    if (sscanf(line.c_str(), "0x%" SCNx64 " %" SCNu32 " %" SCNu32,
               &addr, &len, &type) == 3) {
      if (state.client.debug_set_watchpoint(addr, len, type)) loaded++;
    }
  }
  refresh_watchpoints(state);
  set_status(state, std::string("Loaded ") + std::to_string(loaded) +
                    " watchpoints from " + std::string(path));
}

void reset_debugger_state() { s_dbg_state = DebuggerState{}; }

void draw_debugger(AppState &state, ImVec2 avail) {
  auto &ds = dstate(state);
  poll_debugger_attach(state, ds);
  poll_debugger_state(state);

  const float scl = ui::dpi_scale();
  const float gap = 16.0f * scl;
  const bool has_cap = state.has_hello &&
                       (state.hello.capabilities & MEMDBG_CAP_DEBUGGER);

  if (!has_cap) {
    ui::begin_panel("DebuggerUnavailable", locale::tr("debugger.title"), avail);
    ui::draw_empty_state(locale::tr("debugger.title"),
                         locale::tr("debugger.unsupported"));
    ui::end_panel();
    return;
  }

  if (!state.client.connected()) {
    ui::begin_panel("DebuggerDisconnected", locale::tr("debugger.title"), avail);
    ui::draw_empty_state(locale::tr("debugger.title"),
                         locale::tr("debugger.connect_first"));
    ui::end_panel();
    return;
  }

  const bool client_busy = client_async_busy(state) || ds.attach_pending;

  /* Outer clipping child keeps all debugger panels within the screen area */
  ImGui::BeginChild("DebuggerOuter", avail, false);

  const float session_h = ds.attached ? 142.0f * scl : 128.0f * scl;
  ui::begin_panel("DebuggerSession", locale::tr("debugger.title"),
                  ImVec2(0, std::min(session_h, avail.y)));

  if (client_busy) {
    ImGui::TextColored(ui::colors().warning, "%s",
                       "Wait for the active operation to finish");
    ImGui::Spacing();
  }

  ImGui::BeginDisabled(client_busy);
  draw_debugger_pid_selector(state, ds);
  ImGui::EndDisabled();

  ImGui::Spacing();
  if (!ds.attached) {
    ImGui::Checkbox(locale::tr("debugger.pause_on_attach"), &ds.pause_on_attach);
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("debugger.pause_on_attach_tip"));

    ImGui::SameLine();
    const std::string attach_label = std::string(icons::kBug) + "  " +
        (ds.attach_pending ? "Attaching..." : locale::tr("debugger.attach"));
    ImGui::BeginDisabled(client_busy);
    if (ui::primary_button(attach_label.c_str(), ImVec2(150.0f * scl, 0))) {
      int32_t pid = 0;
      if (parse_pid_input(ds.pid_input, pid)) {
        start_debugger_attach(state, ds, pid);
      } else {
        set_status(state, "Select a valid PID before attaching");
      }
    }
    ImGui::EndDisabled();
  } else {
    static bool skip_detach = false;
    ImGui::BeginDisabled(client_busy);
    if (ui::danger_button((std::string(icons::kDisconnect) + "  " +
                           locale::tr("debugger.detach")).c_str(),
                          ImVec2(126.0f * scl, 0))) {
      ImGui::OpenPopup("ConfirmDetach");
    }
    ImGui::EndDisabled();
    if (ui::confirm_modal("ConfirmDetach",
                          locale::tr("debugger.confirm_detach"), nullptr,
                          &skip_detach, true)) {
      if (state.client.debug_detach()) {
        ds.attached = false;
        ds.stopped = false;
        ds.pid = 0;
        ds.selected_lwp = 0;
        ds.threads.clear();
        ds.breakpoints.clear();
        ds.watchpoints.clear();
        set_status(state, locale::tr("debugger.detached"));
      } else {
        set_status(state, "Detach: " + state.client.last_error());
      }
    }

    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, "PID %d", ds.pid);
    ImGui::SameLine();
    ImGui::TextColored(ds.stopped ? ui::colors().warning : ui::colors().success,
                       "%s", ds.stopped ? "STOPPED" : "RUNNING");
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, "LWP %d", ds.selected_lwp);

    ImGui::Spacing();
    ImGui::BeginDisabled(client_busy || !ds.stopped);
    if (ui::soft_button((std::string(icons::kPlay) + "  " +
                         locale::tr("debugger.continue")).c_str(),
                        ImVec2(132.0f * scl, 0))) {
      if (state.client.debug_continue()) {
        ds.stopped = false;
      } else {
        set_status(state, "Continue: " + state.client.last_error());
      }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(client_busy || ds.stopped);
    if (ui::soft_button((std::string(icons::kStop) + "  " +
                         locale::tr("debugger.stop")).c_str(),
                        ImVec2(108.0f * scl, 0))) {
      if (state.client.debug_stop()) {
        ds.stopped = true;
      } else {
        set_status(state, "Stop: " + state.client.last_error());
      }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(client_busy || !ds.stopped || ds.selected_lwp == 0);
    if (ui::soft_button((std::string(icons::kPointer) + "  " +
                         locale::tr("debugger.step")).c_str(),
                        ImVec2(104.0f * scl, 0))) {
      if (state.client.debug_step(ds.selected_lwp)) {
        refresh_regs(state);
        if (ds.disasm_follow_rip) {
          ds.disasm_nav_addr = 0;
          ds.disasm_reg_sel = 0;
        }
        ds.disasm_needs_refresh = true;
        ds.stack_needs_refresh = true;
        refresh_disasm(state);
        refresh_stack(state);
      } else {
        set_status(state, "Step: " + state.client.last_error());
      }
    }
    ImGui::EndDisabled();
  }
  ui::end_panel();

  ImGui::Spacing();
  if (!ds.attached) {
    ui::begin_panel("DebuggerNoSession", "Debugger Workspace",
                    ImVec2(0, ImGui::GetContentRegionAvail().y));
    ui::draw_empty_state("No debugger session",
                         "Select a process and attach to inspect threads, registers, breakpoints, and watchpoints.");
    ui::end_panel();
  } else {
    const float work_h = std::max(180.0f * scl, ImGui::GetContentRegionAvail().y);
    const float threads_w = std::min(320.0f * scl,
        std::max(240.0f * scl, avail.x * 0.22f));
    ui::begin_panel("DebuggerThreads", "Threads", ImVec2(threads_w, work_h));
    ImGui::BeginDisabled(client_busy);
    if (ui::soft_button((std::string(icons::kRefresh) + "  " +
                         locale::tr("debugger.refresh")).c_str(),
                        ui::full_button(34.0f))) {
      refresh_threads(state);
    }
    ImGui::EndDisabled();
    ImGui::Spacing();
    if (ds.threads.empty()) {
      ui::draw_empty_state("No threads", "Refresh after the target enters a stopped state.");
    } else if (ImGui::BeginTable("##threads", 2,
          ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
              ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
          ImVec2(0, -1))) {
      ImGui::TableSetupColumn("Thread", ImGuiTableColumnFlags_WidthStretch, 1.0f);
      ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 74.0f * scl);
      for (const auto &t : ds.threads) {
        bool sel = (t.lwp == ds.selected_lwp);
        ImGui::TableNextRow();
        /* Column 0: thread label */
        ImGui::TableSetColumnIndex(0);
        char label[96];
        std::snprintf(label, sizeof(label), "LWP %d  %s", (int)t.lwp,
                      t.name.c_str());
        if (ImGui::Selectable(label, sel, ImGuiSelectableFlags_SpanAllColumns)) {
          ds.selected_lwp = t.lwp;
          refresh_regs(state);
        }
        if (sel) ImGui::SetItemDefaultFocus();
        /* Right-click context menu: suspend/resume thread */
        if (ImGui::BeginPopupContextItem()) {
          ImGui::BeginDisabled(client_busy || t.lwp == 0);
          if (ImGui::MenuItem("Suspend Thread")) {
            if (state.client.debug_suspend_thread(t.lwp)) {
              refresh_threads(state);
              set_status(state, "Thread LWP " + std::to_string(t.lwp) + " suspended");
            } else {
              set_status(state, "Suspend: " + state.client.last_error());
            }
          }
          if (ImGui::MenuItem("Resume Thread")) {
            if (state.client.debug_resume_thread(t.lwp)) {
              refresh_threads(state);
              set_status(state, "Thread LWP " + std::to_string(t.lwp) + " resumed");
            } else {
              set_status(state, "Resume: " + state.client.last_error());
            }
          }
          ImGui::EndDisabled();
          ImGui::EndPopup();
        }
        /* Column 1: thread state */
        ImGui::TableSetColumnIndex(1);
        const char *state_text;
        ImVec4 state_color;
        const char *signal_name = nullptr;
        switch (t.state) {
        case MEMDBG_THREAD_SUSPENDED:
          state_text = "Suspended";
          state_color = ui::colors().warning;
          break;
        case MEMDBG_THREAD_STOPPED:
          state_text = "Stopped";
          state_color = ui::colors().muted;
          if (t.stop_info.stop_signal != 0) {
            switch (t.stop_info.stop_signal) {
            case 5:  signal_name = "SIGTRAP"; break;
            case 11: signal_name = "SIGSEGV"; break;
            case 17: signal_name = "SIGSTOP"; break;
            case 4:  signal_name = "SIGILL";  break;
            case 8:  signal_name = "SIGFPE";  break;
            case 10: signal_name = "SIGBUS";  break;
            default: break;
            }
          }
          break;
        case MEMDBG_THREAD_WAITING:
          state_text = "Waiting";
          state_color = ui::colors().muted;
          break;
        case MEMDBG_THREAD_UNKNOWN:
          state_text = "Unknown";
          state_color = ui::colors().dim;
          break;
        default:
          state_text = "Running";
          state_color = ui::colors().success;
          break;
        }
        ImGui::TextColored(state_color, "%s", state_text);
        if (signal_name != nullptr && ImGui::IsItemHovered())
          ImGui::SetTooltip("Stop signal: %s (%d)", signal_name,
                            (int)t.stop_info.stop_signal);
      }
      ImGui::EndTable();

      /* Mini info panel for the selected thread */
      if (ds.selected_lwp != 0) {
        const Client::DebugThreadEntry *sel = nullptr;
        for (const auto &t : ds.threads) {
          if (t.lwp == ds.selected_lwp) { sel = &t; break; }
        }
        if (sel != nullptr) {
          ImGui::Spacing();
          ImGui::Separator();
          ImGui::Spacing();

          ImGui::BeginChild("ThreadInfo", ImVec2(0, 170.0f * scl), true);
          ImGui::TextColored(ui::colors().primary2, "LWP %d  %s",
                             (int)sel->lwp, sel->name.c_str());
          ImGui::Spacing();

          if (ImGui::BeginTable("##thrinfo", 2,
                ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed,
                                    100.0f * scl);
            ImGui::TableSetupColumn("Value");

            auto row = [](const char *label, const char *value,
                          ImVec4 color = {}) {
              ImGui::TableNextRow();
              ImGui::TableSetColumnIndex(0);
              ImGui::TextColored(ui::colors().muted, "%s", label);
              ImGui::TableSetColumnIndex(1);
              if (color.w > 0.0f)
                ImGui::TextColored(color, "%s", value);
              else
                ImGui::Text("%s", value);
            };

            /* Build duration string from runtime_us */
            char cpu_buf[64];
            if (sel->runtime_us > 0) {
              uint64_t ms = sel->runtime_us / 1000;
              uint64_t s = ms / 1000;
              uint64_t m = s / 60;
              uint64_t h = m / 60;
              if (h > 0)
                std::snprintf(cpu_buf, sizeof(cpu_buf),
                              "%lluh %llum", (unsigned long long)h,
                              (unsigned long long)(m % 60));
              else if (m > 0)
                std::snprintf(cpu_buf, sizeof(cpu_buf),
                              "%llum %llus", (unsigned long long)m,
                              (unsigned long long)(s % 60));
              else if (s > 0)
                std::snprintf(cpu_buf, sizeof(cpu_buf), "%llus",
                              (unsigned long long)s);
              else
                std::snprintf(cpu_buf, sizeof(cpu_buf), "%llums",
                              (unsigned long long)ms);
            } else {
              std::snprintf(cpu_buf, sizeof(cpu_buf), "n/a");
            }

            const char *state_label;
            ImVec4 state_clr;
            switch (sel->state) {
            case MEMDBG_THREAD_SUSPENDED:
              state_label = "Suspended"; state_clr = ui::colors().warning; break;
            case MEMDBG_THREAD_STOPPED:
              state_label = "Stopped";   state_clr = ui::colors().muted; break;
            case MEMDBG_THREAD_WAITING:
              state_label = "Waiting";   state_clr = ui::colors().muted; break;
            case MEMDBG_THREAD_UNKNOWN:
              state_label = "Unknown";   state_clr = ui::colors().dim; break;
            default:
              state_label = "Running";   state_clr = ui::colors().success; break;
            }

            row("State", state_label, state_clr);

            /* Show stop signal if the thread is stopped by one */
            char sig_buf[64];
            if (sel->stop_info.stop_signal != 0) {
              const char *sn = nullptr;
              switch (sel->stop_info.stop_signal) {
              case 5:  sn = "SIGTRAP"; break;
              case 11: sn = "SIGSEGV"; break;
              case 17: sn = "SIGSTOP"; break;
              case 4:  sn = "SIGILL";  break;
              case 8:  sn = "SIGFPE";  break;
              case 10: sn = "SIGBUS";  break;
              case 6:  sn = "SIGABRT"; break;
              case 15: sn = "SIGTERM"; break;
              default: break;
              }
              if (sn != nullptr)
                std::snprintf(sig_buf, sizeof(sig_buf), "%s (%d)",
                              sn, (int)sel->stop_info.stop_signal);
              else
                std::snprintf(sig_buf, sizeof(sig_buf), "Signal %d",
                              (int)sel->stop_info.stop_signal);
              row("Stop signal", sig_buf, ui::colors().warning);
            }

            /* Show pl_event and pl_flags for debugging */
            char event_buf[32];
            std::snprintf(event_buf, sizeof(event_buf), "%s (%d)",
                          sel->stop_info.pl_event == 1 ? "SIGNAL" : "NONE",
                          (int)sel->stop_info.pl_event);
            row("pl_event", event_buf);

            char flags_buf[32];
            std::snprintf(flags_buf, sizeof(flags_buf), "0x%X",
                          (unsigned)sel->stop_info.pl_flags);
            row("pl_flags", flags_buf);

            /* Show signal masks (blocked / pending) for advanced debugging */
            char mask_buf[48];
            if (sel->stop_info.pl_sigmask_lo || sel->stop_info.pl_sigmask_hi) {
              std::snprintf(mask_buf, sizeof(mask_buf),
                            "0x%016llX %016llX",
                            (unsigned long long)sel->stop_info.pl_sigmask_hi,
                            (unsigned long long)sel->stop_info.pl_sigmask_lo);
              row("SigMask", mask_buf);
            }
            if (sel->stop_info.pl_siglist_lo || sel->stop_info.pl_siglist_hi) {
              std::snprintf(mask_buf, sizeof(mask_buf),
                            "0x%016llX %016llX",
                            (unsigned long long)sel->stop_info.pl_siglist_hi,
                            (unsigned long long)sel->stop_info.pl_siglist_lo);
              row("SigList", mask_buf);
            }

            char pri_buf[16];
            if (sel->priority != 0)
              std::snprintf(pri_buf, sizeof(pri_buf), "%d",
                            (int)sel->priority);
            else
              std::snprintf(pri_buf, sizeof(pri_buf), "n/a");
            row("Priority", pri_buf);

            char pct_buf[16];
            if (sel->pctcpu >= 0)
              std::snprintf(pct_buf, sizeof(pct_buf), "%d.%02d%%",
                            sel->pctcpu / 100, sel->pctcpu % 100);
            else
              std::snprintf(pct_buf, sizeof(pct_buf), "n/a");
            row("CPU %%", pct_buf);

            char core_buf[16];
            if (sel->cpu_id >= 0)
              std::snprintf(core_buf, sizeof(core_buf), "Core %d",
                            (int)sel->cpu_id);
            else
              std::snprintf(core_buf, sizeof(core_buf), "n/a");
            row("Core", core_buf);

            row("CPU time", cpu_buf);
            ImGui::EndTable();
          }
          ImGui::EndChild();
        }
      }
    }
    ui::end_panel();

    ImGui::SameLine(0, gap);
    ui::begin_panel("DebuggerWorkspace", "Debugger Workspace", ImVec2(0, work_h));
  if (ImGui::BeginTabBar("DebuggerWorkspaceTabs")) {
    if (ImGui::BeginTabItem("Registers")) {
      ImGui::TextColored(ui::colors().muted, "Registers (LWP %d)",
                         (int)ds.selected_lwp);
      ImGui::Spacing();
      ImGui::BeginDisabled(client_busy);
      if (ui::soft_button((std::string(icons::kRefresh) + "  " +
                           locale::tr("debugger.refresh")).c_str(),
                          ImVec2(118.0f * scl, 0))) {
        refresh_regs(state);
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::BeginDisabled(client_busy || ds.selected_lwp == 0);
      if (ui::primary_button((std::string(icons::kSave) + "  " +
                              locale::tr("debugger.set_regs")).c_str(),
                             ImVec2(132.0f * scl, 0))) {
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
      ImGui::SameLine();
      ImGui::Checkbox("Follow RIP", &ds.follow_rip);
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", "Highlight RIP first in the register grid when stopped");

      ImGui::Spacing();
      auto &r = ds.regs.regs;
      struct RegCell {
        const char *label;
        RegField field;
        bool is_rip = false;
      };
      const RegCell reg_cells_template[18] = {
          {"RAX", RegField::RAX}, {"RBX", RegField::RBX},
          {"RCX", RegField::RCX}, {"RDX", RegField::RDX},
          {"RSI", RegField::RSI}, {"RDI", RegField::RDI},
          {"RBP", RegField::RBP}, {"RSP", RegField::RSP},
          {"R8", RegField::R8}, {"R9", RegField::R9},
          {"R10", RegField::R10}, {"R11", RegField::R11},
          {"R12", RegField::R12}, {"R13", RegField::R13},
          {"R14", RegField::R14}, {"R15", RegField::R15},
          {"RIP", RegField::RIP, true}, {"RFLAGS", RegField::RFLAGS},
      };
      RegCell reg_cells[18];
      if (ds.follow_rip) {
        reg_cells[0] = reg_cells_template[16];  /* RIP */
        reg_cells[1] = reg_cells_template[17];  /* RFLAGS */
        reg_cells[2] = reg_cells_template[0];   /* RAX */
        reg_cells[3] = reg_cells_template[1];   /* RBX */
        reg_cells[4] = reg_cells_template[2];   /* RCX */
        reg_cells[5] = reg_cells_template[3];   /* RDX */
        reg_cells[6] = reg_cells_template[4];   /* RSI */
        reg_cells[7] = reg_cells_template[5];   /* RDI */
        reg_cells[8] = reg_cells_template[6];   /* RBP */
        reg_cells[9] = reg_cells_template[7];   /* RSP */
        reg_cells[10] = reg_cells_template[8];  /* R8 */
        reg_cells[11] = reg_cells_template[9];  /* R9 */
        reg_cells[12] = reg_cells_template[10]; /* R10 */
        reg_cells[13] = reg_cells_template[11]; /* R11 */
        reg_cells[14] = reg_cells_template[12]; /* R12 */
        reg_cells[15] = reg_cells_template[13]; /* R13 */
        reg_cells[16] = reg_cells_template[14]; /* R14 */
        reg_cells[17] = reg_cells_template[15]; /* R15 */
      } else {
        std::memcpy(reg_cells, reg_cells_template, sizeof(reg_cells));
      }
      const int reg_columns =
          responsive_columns(ImGui::GetContentRegionAvail().x, 224.0f * scl, 4);
      ImGui::BeginDisabled(client_busy || ds.selected_lwp == 0);
      if (ImGui::BeginTable("DebuggerRegGrid", reg_columns,
                            ImGuiTableFlags_SizingStretchSame |
                                ImGuiTableFlags_PadOuterX)) {
        for (auto &cell : reg_cells) {
          ImGui::TableNextColumn();
          const int64_t edited =
              reg_input_cell(cell.label, reg_field_value(r, cell.field));
          set_reg_field_value(r, cell.field, edited);
          /* Highlight RIP cell */
          if (cell.is_rip && ds.follow_rip) {
            ImVec2 rmin = ImGui::GetItemRectMin();
            ImVec2 rmax = ImGui::GetItemRectMax();
            rmin.x -= 4.0f * scl; rmax.x += 4.0f * scl;
            rmin.y -= 1.0f * scl; rmax.y += 1.0f * scl;
            ImVec4 hl = ui::colors().primary2; hl.w = 0.14f;
            ImGui::GetWindowDrawList()->AddRectFilled(rmin, rmax,
                ui::color_u32(hl), 2.0f * scl);
            ImGui::GetWindowDrawList()->AddRect(rmin, rmax,
                ui::color_u32(ui::colors().primary2), 2.0f * scl);
          }
        }
        ImGui::EndTable();
      }
      ImGui::EndDisabled();
      ImGui::EndTabItem();
    }

    static const char *cond_reg_names[] = {
      "None", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
      "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"
    };
    static const char *cond_op_names[] = {"==", "!=", "<", "<=", ">", ">="};

    if (ImGui::BeginTabItem("Breakpoints")) {
      ImGui::TextColored(ui::colors().muted, "%s", locale::tr("debugger.bp_list"));
      ImGui::Spacing();
      const char *bp_kinds[] = {"Software", "Hardware"};
      ImGui::BeginDisabled(client_busy);
      if (ImGui::BeginTable("BreakpointEditor", 5,
                            ImGuiTableFlags_SizingStretchProp |
                                ImGuiTableFlags_PadOuterX)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.35f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 118.0f * scl);
        ImGui::TableSetupColumn("Condition", ImGuiTableColumnFlags_WidthFixed, 92.0f * scl);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 124.0f * scl);
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
        if (ui::primary_button((std::string(icons::kAdd) + "  " +
                                locale::tr("debugger.add_bp")).c_str(),
                               ImVec2(-1, 0))) {
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
          } else {
            set_status(state, "Invalid breakpoint address");
          }
        }
        ImGui::EndTable();
      }
      ImGui::EndDisabled();

      ImGui::Spacing();
      /* Save / Load breakpoints */
      ImGui::BeginDisabled(client_busy);
      ImGui::SetNextItemWidth(200.0f * scl);
      ImGui::InputText("##bpfname", ds.bp_filename, sizeof(ds.bp_filename));
      ImGui::SameLine();
      if (ui::soft_button((std::string(icons::kSave) + "  Save BP").c_str(),
                          ImVec2(108.0f * scl, 0))) {
        save_breakpoints_to_file(state, ds.bp_filename);
      }
      ImGui::SameLine();
      if (ui::soft_button((std::string(icons::kLoad) + "  Load BP").c_str(),
                          ImVec2(110.0f * scl, 0))) {
        load_breakpoints_from_file(state, ds.bp_filename);
      }
      ImGui::EndDisabled();
      ImGui::Spacing();
      if (!ds.breakpoints.empty()) {
        ImGui::TextColored(ui::colors().muted, "%s (%zu)",
                           locale::tr("debugger.bp_list"), ds.breakpoints.size());
        ImGui::SameLine();
        static bool skip_clear_bp = false;
        ImGui::BeginDisabled(client_busy);
        if (ui::danger_button((std::string(icons::kTrash) + "  " +
                               locale::tr("debugger.clear_all_bp")).c_str(),
                              ImVec2(138.0f * scl, 0))) {
          ImGui::OpenPopup("ConfirmClearBP");
        }
        ImGui::EndDisabled();
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

        const float table_h = std::max(150.0f * scl, ImGui::GetContentRegionAvail().y - 8.0f * scl);
        if (ImGui::BeginTable("##bptable", 4,
              ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
              ImVec2(0, table_h))) {
          ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 154.0f * scl);
          ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 64.0f * scl);
          ImGui::TableSetupColumn("Condition");
          ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 88.0f * scl);
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
            ImGui::BeginDisabled(client_busy);
            if (ui::danger_button(locale::tr("debugger.remove_bp"), ImVec2(-1, 0))) {
              ImGui::OpenPopup("ConfirmRemoveBP");
            }
            ImGui::EndDisabled();
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
      } else {
        ui::draw_empty_state("No breakpoints", "Add a software or hardware breakpoint for the attached target.");
      }
      ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Disassembly")) {
      /* Auto-refresh disasm view when target stops */
      if (ds.stopped && ds.auto_refresh_on_stop)
        ds.disasm_needs_refresh = true;

      ImGui::TextColored(ui::colors().muted, "Disassembly  RIP = 0x%016" PRIX64,
                         (uint64_t)ds.regs.regs.r_rip);
      ImGui::Spacing();
      ImGui::BeginDisabled(client_busy || !ds.stopped || ds.selected_lwp == 0);
      if (ui::soft_button((std::string(icons::kRefresh) + "  Refresh").c_str(),
                          ImVec2(118.0f * scl, 0))) {
        ds.disasm_needs_refresh = true;
        refresh_disasm(state);
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::Checkbox(locale::tr("debugger.auto_refresh_on_stop"), &ds.auto_refresh_on_stop);
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", locale::tr("debugger.auto_refresh_on_stop_tip"));
      ImGui::SameLine();
      if (ImGui::Checkbox("Follow RIP", &ds.disasm_follow_rip)) {
        /* When user enables Follow RIP, reset to RIP immediately */
        if (ds.disasm_follow_rip && ds.disasm_nav_addr != 0) {
          ds.disasm_nav_addr = 0;
          ds.disasm_needs_refresh = true;
          refresh_disasm(state);
        }
      }
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", "Always center disassembly on RIP after each stop");
      /* Register selector: disassemble at any register's value */
      static const char *kDisasmRegNames[] = {
        "RIP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"
      };
      ImGui::SameLine();
      ImGui::SetNextItemWidth(68.0f * scl);
      if (ImGui::Combo("##disasmreg", &ds.disasm_reg_sel, kDisasmRegNames,
                       IM_ARRAYSIZE(kDisasmRegNames))) {
        /* When user selects a register, navigate to its value immediately */
        if (ds.disasm_reg_sel > 0) {
          /* Don't cache nav_addr — let refresh_disasm read live register */
          ds.disasm_nav_addr = 0;
          ds.disasm_follow_rip = false;
          ds.disasm_needs_refresh = true;
          refresh_disasm(state);
        } else {
          /* RIP selected — reset to default */
          ds.disasm_nav_addr = 0;
          ds.disasm_follow_rip = true;
          ds.disasm_needs_refresh = true;
          refresh_disasm(state);
        }
      }
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", "Disassemble starting at the selected register's value");
      /* Show selected register's value */
      if (ds.disasm_reg_sel > 0) {
        ImGui::SameLine();
        ImGui::TextColored(ui::colors().muted, "= 0x%016" PRIX64,
                           (uint64_t)reg_field_value(ds.regs.regs,
                               (RegField)(ds.disasm_reg_sel - 1)));
      }

      /* Show nav indicator when viewing a different address */
      if (ds.disasm_nav_addr != 0) {
        ImGui::SameLine();
        ImGui::TextColored(ui::colors().warning, "%s 0x%016" PRIX64,
                           "Navigated:", ds.disasm_nav_addr);
        ImGui::SameLine();
        if (ui::soft_button("Back to RIP", ImVec2(100.0f * scl, 0))) {
          ds.disasm_nav_addr = 0;
          ds.disasm_reg_sel = 0;
          ds.disasm_follow_rip = true;
          ds.disasm_needs_refresh = true;
          refresh_disasm(state);
        }
      }

      /* Go-to-address input */
      ImGui::TextColored(ui::colors().dim, "%s", "Go to:");
      ImGui::SameLine();
      ImGui::BeginDisabled(client_busy || !ds.stopped || ds.selected_lwp == 0);
      ImGui::SetNextItemWidth(156.0f * scl);
      if (ImGui::InputText("##goto_addr", ds.goto_addr_input,
                           sizeof(ds.goto_addr_input),
                           ImGuiInputTextFlags_CharsHexadecimal |
                               ImGuiInputTextFlags_EnterReturnsTrue)) {
        uint64_t addr = 0;
        if (parse_input_u64(ds.goto_addr_input, addr)) {
          ds.disasm_nav_addr = addr;
          ds.disasm_reg_sel = 0;
          ds.disasm_follow_rip = false;
          ds.disasm_needs_refresh = true;
          refresh_disasm(state);
        } else {
          set_status(state, "Invalid hex address");
        }
      }
      ImGui::EndDisabled();
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", "Type a hex address and press Enter to navigate");
      ImGui::SameLine();
      if (ImGui::Checkbox("Jump targets", &ds.disasm_cfg_view)) {
        ds.disasm_needs_refresh = true;
        refresh_disasm(state);
      }
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", "Show only jump/call instructions and their targets (CFG view)");

      ImGui::Spacing();
      if (ds.disasm_lines.empty() && ds.stopped && ds.selected_lwp != 0) {
        ImGui::TextColored(ui::colors().dim, "%s", "Refresh to disassemble at RIP");
      } else if (ds.disasm_lines.empty()) {
        ui::draw_empty_state("No disassembly",
                             "The target must be stopped to disassemble code at RIP.");
      } else {
        const float table_h = std::max(200.0f * scl, ImGui::GetContentRegionAvail().y - 8.0f * scl);
        if (ImGui::BeginTable("##disasmtable", 3,
              ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
              ImVec2(0, table_h))) {
          ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 154.0f * scl);
          ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 160.0f * scl);
          ImGui::TableSetupColumn("Instruction");
          ImGui::TableHeadersRow();
          uint64_t rip = (uint64_t)ds.regs.regs.r_rip;
          for (const auto &dl : ds.disasm_lines) {
            bool at_rip = (dl.address == rip);
            ImGui::TableNextRow();
            if (at_rip) {
              ImVec4 hl = ui::colors().primary2; hl.w = 0.18f;
              ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                     ui::color_u32(hl));
            }
            ImGui::TableSetColumnIndex(0);
            /* Red dot indicator for breakpoints */
            bool has_bp = false;
            for (const auto &bp : ds.breakpoints) {
              if (bp.address == dl.address) { has_bp = true; break; }
            }
            /* Also check for watchpoints at this address */
            bool has_wp = false;
            for (const auto &wp : ds.watchpoints) {
              if (wp.address == dl.address) { has_wp = true; break; }
            }
            if (has_bp) {
              ImVec2 cursor = ImGui::GetCursorScreenPos();
              float dot_r = 3.5f * scl;
              ImVec2 center(cursor.x + dot_r + 2.0f * scl,
                            cursor.y + ImGui::GetTextLineHeight() * 0.5f);
              ImGui::GetWindowDrawList()->AddCircleFilled(
                  center, dot_r, IM_COL32(220, 40, 40, 255));
              ImGui::SetCursorPosX(ImGui::GetCursorPosX() + dot_r * 2.0f + 4.0f * scl);
            }
            if (has_wp) {
              ImVec2 cursor = ImGui::GetCursorScreenPos();
              float dot_r = 3.5f * scl;
              ImVec2 center(cursor.x + dot_r + 2.0f * scl,
                            cursor.y + ImGui::GetTextLineHeight() * 0.5f);
              ImGui::GetWindowDrawList()->AddCircleFilled(
                  center, dot_r, IM_COL32(220, 180, 40, 255));
              ImGui::SetCursorPosX(ImGui::GetCursorPosX() + dot_r * 2.0f + 4.0f * scl);
            }
            /* Clickable address: navigate disassembly to this address */
            const bool can_navigate = ds.stopped && ds.selected_lwp != 0;
            ImGui::BeginDisabled(!can_navigate);
            ImGui::PushStyleColor(ImGuiCol_Text,
                at_rip ? ui::color_u32(ui::colors().primary2)
                       : ui::color_u32(ui::colors().dim));
            char addr_label[32];
            std::snprintf(addr_label, sizeof(addr_label),
                          "0x%016" PRIX64, dl.address);
            if (ImGui::Selectable(addr_label, false)) {
              ds.disasm_nav_addr = dl.address;
              ds.disasm_reg_sel = 0;
              ds.disasm_follow_rip = false;
              ds.disasm_needs_refresh = true;
              refresh_disasm(state);
            }
            ImGui::PopStyleColor();
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered())
              ImGui::SetTooltip("Click to disassemble at 0x%016" PRIX64, dl.address);
            /* Right-click context menu */
            if (ImGui::BeginPopupContextItem()) {
              char addr_copy[32];
              std::snprintf(addr_copy, sizeof(addr_copy),
                            "0x%016" PRIX64, dl.address);
              if (ImGui::MenuItem("Copy Address")) {
                ImGui::SetClipboardText(addr_copy);
                set_status(state, std::string("Copied ") + addr_copy);
              }
              ImGui::BeginDisabled(!can_navigate);
              if (ImGui::MenuItem("Disassemble here")) {
                ds.disasm_nav_addr = dl.address;
                ds.disasm_reg_sel = 0;
                ds.disasm_follow_rip = false;
                ds.disasm_needs_refresh = true;
                refresh_disasm(state);
              }
              ImGui::EndDisabled();
              ImGui::Separator();
              ImGui::BeginDisabled(client_busy);
              if (has_bp) {
                if (ImGui::MenuItem("Remove Breakpoint")) {
                  if (state.client.debug_clear_breakpoint(dl.address)) {
                    set_status(state, "Breakpoint removed");
                    refresh_breakpoints(state);
                  } else {
                    set_status(state, "Remove BP: " + state.client.last_error());
                  }
                }
              } else {
                if (ImGui::MenuItem("Set Breakpoint (Software)")) {
                  if (state.client.debug_set_breakpoint(dl.address, 0)) {
                    set_status(state, "Breakpoint set");
                    refresh_breakpoints(state);
                  } else {
                    set_status(state, "BP: " + state.client.last_error());
                  }
                }
                if (ImGui::MenuItem("Set Breakpoint (Hardware)")) {
                  if (state.client.debug_set_breakpoint(dl.address, 1)) {
                    set_status(state, "Breakpoint set");
                    refresh_breakpoints(state);
                  } else {
                    set_status(state, "BP: " + state.client.last_error());
                  }
                }
              }
              ImGui::Separator();
              if (has_wp) {
                if (ImGui::MenuItem("Remove Watchpoint")) {
                  if (state.client.debug_clear_watchpoint(dl.address)) {
                    set_status(state, "Watchpoint removed");
                    refresh_watchpoints(state);
                  } else {
                    set_status(state, "Remove WP: " + state.client.last_error());
                  }
                }
              } else {
                if (ImGui::MenuItem("Set Watchpoint (Write)")) {
                  if (state.client.debug_set_watchpoint(dl.address, 4, 1)) {
                    set_status(state, "Watchpoint set");
                    refresh_watchpoints(state);
                  } else {
                    set_status(state, "WP: " + state.client.last_error());
                  }
                }
                if (ImGui::MenuItem("Set Watchpoint (Read)")) {
                  if (state.client.debug_set_watchpoint(dl.address, 4, 2)) {
                    set_status(state, "Watchpoint set");
                    refresh_watchpoints(state);
                  } else {
                    set_status(state, "WP: " + state.client.last_error());
                  }
                }
                if (ImGui::MenuItem("Set Watchpoint (Read/Write)")) {
                  if (state.client.debug_set_watchpoint(dl.address, 4, 3)) {
                    set_status(state, "Watchpoint set");
                    refresh_watchpoints(state);
                  } else {
                    set_status(state, "WP: " + state.client.last_error());
                  }
                }
              }
              ImGui::EndDisabled();
              ImGui::EndPopup();
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(at_rip ? ui::colors().primary2 : ui::colors().muted,
                               "%s", dl.bytes.c_str());
            ImGui::TableSetColumnIndex(2);
            if (at_rip)
              ImGui::TextColored(ui::colors().primary2, "%s  %s", icons::kPointer, dl.mnemonic.c_str());
            else
              ImGui::TextUnformatted(dl.mnemonic.c_str());
          }
          ImGui::EndTable();
        }
      }
      ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Watchpoints")) {
      ImGui::TextColored(ui::colors().muted, "%s", locale::tr("debugger.wp_list"));
      ImGui::Spacing();
      const char *wp_types[] = {"Exec", "Write", "Read", "Read/Write"};
      ImGui::BeginDisabled(client_busy);
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
        if (ui::primary_button((std::string(icons::kAdd) + "  " +
                                locale::tr("debugger.add_wp")).c_str(),
                               ImVec2(-1, 0))) {
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
          } else {
            set_status(state, "Invalid watchpoint address");
          }
        }
        ImGui::EndTable();
      }
      ImGui::EndDisabled();

      ImGui::Spacing();
      /* Save / Load watchpoints */
      ImGui::BeginDisabled(client_busy);
      ImGui::SetNextItemWidth(200.0f * scl);
      ImGui::InputText("##wpfname", ds.wp_filename, sizeof(ds.wp_filename));
      ImGui::SameLine();
      if (ui::soft_button((std::string(icons::kSave) + "  Save WP").c_str(),
                          ImVec2(108.0f * scl, 0))) {
        save_watchpoints_to_file(state, ds.wp_filename);
      }
      ImGui::SameLine();
      if (ui::soft_button((std::string(icons::kLoad) + "  Load WP").c_str(),
                          ImVec2(110.0f * scl, 0))) {
        load_watchpoints_from_file(state, ds.wp_filename);
      }
      ImGui::EndDisabled();
      ImGui::Spacing();
      if (!ds.watchpoints.empty()) {
        ImGui::TextColored(ui::colors().muted, "%s (%zu)",
                           locale::tr("debugger.wp_list"), ds.watchpoints.size());
        ImGui::SameLine();
        static bool skip_clear_wp = false;
        ImGui::BeginDisabled(client_busy);
        if (ui::danger_button((std::string(icons::kTrash) + "  " +
                               locale::tr("debugger.clear_all_wp")).c_str(),
                              ImVec2(138.0f * scl, 0))) {
          ImGui::OpenPopup("ConfirmClearWP");
        }
        ImGui::EndDisabled();
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

        const float table_h = std::max(150.0f * scl, ImGui::GetContentRegionAvail().y - 8.0f * scl);
        if (ImGui::BeginTable("##wptable", 5,
              ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
              ImVec2(0, table_h))) {
          ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 154.0f * scl);
          ImGui::TableSetupColumn("Len", ImGuiTableColumnFlags_WidthFixed, 58.0f * scl);
          ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 78.0f * scl);
          ImGui::TableSetupColumn("Slot", ImGuiTableColumnFlags_WidthFixed, 58.0f * scl);
          ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 88.0f * scl);
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
            ImGui::BeginDisabled(client_busy);
            if (ui::danger_button(locale::tr("debugger.remove_wp"), ImVec2(-1, 0))) {
              ImGui::OpenPopup("ConfirmRemoveWP");
            }
            ImGui::EndDisabled();
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
      } else {
        ui::draw_empty_state("No watchpoints", "Add a hardware watchpoint for execute, write, read, or read/write access.");
      }
      ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Stack")) {
      uint64_t rsp = (uint64_t)ds.regs.regs.r_rsp;
      ImGui::TextColored(ui::colors().muted, "Stack  RSP = 0x%016" PRIX64, rsp);
      ImGui::Spacing();
      ImGui::BeginDisabled(client_busy || !ds.stopped || ds.selected_lwp == 0);
      if (ui::soft_button((std::string(icons::kRefresh) + "  Refresh").c_str(),
                          ImVec2(118.0f * scl, 0))) {
        ds.stack_needs_refresh = true;
        refresh_stack(state);
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::Checkbox(locale::tr("debugger.auto_refresh_on_stop"), &ds.auto_refresh_on_stop);
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", locale::tr("debugger.auto_refresh_on_stop_tip"));

      ImGui::Spacing();
      if (ds.stack_bytes.empty() && ds.stopped && ds.selected_lwp != 0) {
        ImGui::TextColored(ui::colors().dim, "%s", "Refresh to read the stack");
      } else if (ds.stack_bytes.empty()) {
        ui::draw_empty_state("No stack data",
                             "The target must be stopped to read the stack.");
      } else {
        const float table_h = std::max(200.0f * scl, ImGui::GetContentRegionAvail().y - 8.0f * scl);
        if (ImGui::BeginTable("##stacktable", 4,
              ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
              ImVec2(0, table_h))) {
          ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 60.0f * scl);
          ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 158.0f * scl);
          ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 160.0f * scl);
          ImGui::TableSetupColumn("ASCII");
          ImGui::TableHeadersRow();

          size_t num_qwords = ds.stack_bytes.size() / 8;
          for (size_t i = 0; i < num_qwords && i < 64; ++i) {
            uint64_t addr = ds.stack_base + i * 8;
            uint64_t val = 0;
            std::memcpy(&val, ds.stack_bytes.data() + i * 8, 8);

            /* Format ASCII representation */
            char ascii[9];
            for (int b = 0; b < 8; ++b) {
              uint8_t c = ds.stack_bytes[i * 8 + b];
              ascii[b] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
            }
            ascii[8] = '\0';

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextColored(ui::colors().dim, "+0x%02zX", i * 8);
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("0x%016" PRIX64, addr);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("0x%016" PRIX64, val);
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(ui::colors().muted, "%s", ascii);
          }
          ImGui::EndTable();
        }
      }
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
    }
    ui::end_panel();
  }

  ImGui::EndChild();
}

} // namespace memdbg::frontend

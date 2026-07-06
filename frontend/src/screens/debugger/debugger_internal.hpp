/*
 * MemDBG - Debugger module internal shared declarations.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "confirm_modal.hpp"
#include "debugger_disassembly.hpp"
#include "trainer_format.hpp"

#include <algorithm>
#include <cinttypes>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <future>
#include <sstream>
#include <string>

namespace memdbg::frontend {

/* ---- Debugger shared state ---- */

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

  std::vector<debugger::DisassemblyLine> disasm_lines;
  uint64_t disasm_base = 0;
  bool disasm_needs_refresh = true;
  bool disasm_follow_rip = true;
  uint64_t disasm_nav_addr = 0;
  int disasm_reg_sel = 0;
  bool disasm_cfg_view = false;
  char goto_addr_input[32] = {};
  char bp_filename[256] = "breakpoints.mbp";
  char wp_filename[256] = "watchpoints.mwp";

  /* Patch Studio */
  struct PatchEntry {
    uint64_t address = 0;
    uint32_t original_protection = 0;
    uint32_t applied_protection = 0;
    bool has_protection = false;
    bool applied = false;
    std::string label;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
    std::string status;
  };
  char patch_name[96] = "Code patch";
  char patch_addr_input[32] = "0x0";
  char patch_bytes_input[512] = "90";
  char patch_filename[256] = "patches.mpatch";
  int patch_mode = 0;
  int patch_length = 1;
  bool patch_use_mprotect = true;
  bool patch_restore_protection = true;
  std::vector<PatchEntry> patches;

  /* IDE analysis notebook */
  struct NotebookEntry {
    uint64_t id = 0;
    uint64_t address = 0;
    std::string kind;
    std::string label;
    std::string note;
    std::string bytes;
  };
  char notebook_label[96] = "Bookmark";
  char notebook_addr_input[32] = "0x0";
  char notebook_note[512] = "";
  char notebook_filename[256] = "debugger.workspace";
  char notebook_report_filename[256] = "debugger_report.md";
  int notebook_kind = 0;
  uint64_t notebook_next_id = 1;
  std::vector<NotebookEntry> notebook;

  /* Stack view */
  std::vector<uint8_t> stack_bytes;
  std::vector<Client::StackFrame> stack_frames;
  uint64_t stack_base = 0;
  uint64_t stack_refresh_sp = 0;
  bool stack_truncated = false;
  bool stack_walk_used = false;
  bool stack_needs_refresh = true;

  Client::DebugFpregs fpregs{};
  Client::DebugFsGsBase fsgsbase{};
  bool has_fpregs = false;
  bool has_fsgsbase = false;
};

/* Extern debugger singleton and async futures */
extern DebuggerState s_dbg_state;

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

extern std::future<DebuggerAttachResult> s_attach_future;

struct DebuggerThreadsResult {
  bool ok = false;
  int32_t pid = 0;
  std::string error;
  std::vector<Client::DebugThreadEntry> threads;
};

extern std::future<DebuggerThreadsResult> s_threads_future;

DebuggerState &dstate(AppState &state);

/* ---- Helpers ---- */
bool parse_input_u64(const char *text, uint64_t &out);
bool parse_pid_input(const char *text, int32_t &out);

/* ---- Attach / Detach ---- */
void set_debugger_pid_input(DebuggerState &ds, int32_t pid);
void select_debugger_process(AppState &state, DebuggerState &ds, int row);
bool refresh_debugger_process_list(AppState &state);
void draw_debugger_pid_selector(AppState &state, DebuggerState &ds);
void start_debugger_attach(AppState &state, DebuggerState &ds, int32_t pid);
void poll_debugger_attach(AppState &state, DebuggerState &ds);

/* ---- State polling ---- */
void poll_debugger_state(AppState &state);
void poll_debugger_threads(AppState &state, DebuggerState &ds);
void refresh_threads(AppState &state);
void refresh_breakpoints(AppState &state);
void refresh_watchpoints(AppState &state);

/* ---- Registers ---- */
void refresh_regs(AppState &state);
void refresh_extended_regs(AppState &state);

/* ---- UI utility types and functions ---- */
enum class RegField {
  RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP,
  R8, R9, R10, R11, R12, R13, R14, R15, RIP, RFLAGS,
};

int64_t reg_field_value(const memdbg_debug_regs_t &regs, RegField field);
void set_reg_field_value(memdbg_debug_regs_t &regs, RegField field, int64_t value);
int responsive_columns(float available_width, float min_cell_width, int max_columns);
void set_table_item_width(float fallback);
int64_t reg_input_cell(const char *label, int64_t value);
void draw_hex_blob_table(const char *id, const uint8_t *data, size_t length, float height);

/* ---- Memory / Disassembly / Stack ---- */
void refresh_disasm(AppState &state);
void refresh_stack(AppState &state);

/* ---- Patch Studio ---- */
constexpr size_t kPatchStudioMaxBytes = 256U;
size_t visible_disasm_byte_count(const std::string &bytes);
std::string disasm_bytes_compact(const std::string &bytes);
void set_patch_address(DebuggerState &ds, uint64_t address);
void set_patch_bytes(DebuggerState &ds, const std::vector<uint8_t> &bytes);
void stage_patch_from_disasm_line(AppState &state, DebuggerState &ds, const debugger::DisassemblyLine &line, bool nop_fill);
bool build_patch_bytes(const DebuggerState &ds, std::vector<uint8_t> &out, std::string &error);
bool read_patch_original(AppState &state, DebuggerState &ds, uint64_t address, size_t length, std::vector<uint8_t> &out, std::string &error);
bool write_patch_bytes(AppState &state, DebuggerState &ds, uint64_t address, const std::vector<uint8_t> &bytes, DebuggerState::PatchEntry *entry, std::string &error);
bool compose_patch_entry(AppState &state, DebuggerState &ds, DebuggerState::PatchEntry &entry, std::string &error);
void capture_patch(AppState &state, DebuggerState &ds);
void apply_composed_patch(AppState &state, DebuggerState &ds);
void reapply_patch(AppState &state, DebuggerState &ds, DebuggerState::PatchEntry &entry);
void restore_patch(AppState &state, DebuggerState &ds, DebuggerState::PatchEntry &entry);
void add_patch_to_trainer(AppState &state, DebuggerState &ds, const DebuggerState::PatchEntry &entry);
void save_patches_to_file(AppState &state, DebuggerState &ds, const char *path);
void load_patches_from_file(AppState &state, DebuggerState &ds, const char *path);
void draw_patch_studio(AppState &state, DebuggerState &ds, bool client_busy, float scl);

/* ---- Analysis Notebook ---- */
const char *notebook_kind_name(int kind);
std::string workspace_escape(const std::string &value);
std::string workspace_unescape(const std::string &value);
std::vector<std::string> split_tab_fields(const std::string &line);
std::string markdown_cell(std::string value);
bool parse_notebook_bytes(const std::string &text, std::vector<uint8_t> &out);
void add_notebook_entry(AppState &state, DebuggerState &ds, uint64_t address, const std::string &kind, const std::string &label, const std::string &bytes, const std::string &note);
void add_notebook_from_register(AppState &state, DebuggerState &ds, const char *reg_name, uint64_t address);
void save_notebook_to_file(AppState &state, DebuggerState &ds, const char *path);
void load_notebook_from_file(AppState &state, DebuggerState &ds, const char *path);
void export_notebook_report(AppState &state, DebuggerState &ds, const char *path);
void set_notebook_address(DebuggerState &ds, uint64_t address);
void draw_analysis_notebook(AppState &state, DebuggerState &ds, bool client_busy, float scl);

/* ---- BP / WP I/O ---- */
void save_breakpoints_to_file(AppState &state, const char *path);
void load_breakpoints_from_file(AppState &state, const char *path);
void save_watchpoints_to_file(AppState &state, const char *path);
void load_watchpoints_from_file(AppState &state, const char *path);

/* ---- Reset ---- */
void reset_debugger_state(AppState &state);

} // namespace memdbg::frontend

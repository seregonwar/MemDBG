/*
 * MemDBG - Pure helpers for the x64dbg plugin (testable without Plugin SDK).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_X64DBG_PLUGIN_UTIL_HPP
#define MEMDBG_X64DBG_PLUGIN_UTIL_HPP

#include "memdbg/core/memdbg_protocol.h"

#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::x64dbg_bridge {

bool parse_u64(const char *text, uint64_t &out);
bool parse_i32(const char *text, int32_t &out);
bool parse_hex_bytes(const char *text, std::vector<uint8_t> &out);

/* Case-insensitive GPR name → field write. Accepts eflags as alias of rflags. */
bool apply_gpr_name(memdbg_debug_regs_t &regs, const char *name, uint64_t value);

/* Plan for GuiDisasmAt / GuiDumpAt after a remote stop. */
struct ViewSyncPlan {
  uint64_t cip = 0;
  uint64_t dump_addr = 0;
  bool ok = false;
};

/* dump_override==0 → dump at RSP (or CIP if RSP is 0). */
ViewSyncPlan make_view_sync_plan(uint64_t rip, uint64_t rsp,
                                 uint64_t dump_override = 0);

} // namespace memdbg::x64dbg_bridge

#endif /* MEMDBG_X64DBG_PLUGIN_UTIL_HPP */

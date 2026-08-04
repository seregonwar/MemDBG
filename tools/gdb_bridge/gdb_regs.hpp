/*
 * MemDBG - GDB i386:x86-64 register mapping helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_GDB_BRIDGE_GDB_REGS_HPP
#define MEMDBG_GDB_BRIDGE_GDB_REGS_HPP

#include "memdbg/core/memdbg_protocol.h"

#include <cstdint>
#include <string>

namespace memdbg::gdb_bridge {

/* GDB org.gnu.gdb.i386.core + sse register numbers (amd64 layout). */
enum GdbReg : int {
  GDB_RAX = 0,
  GDB_RBX = 1,
  GDB_RCX = 2,
  GDB_RDX = 3,
  GDB_RSI = 4,
  GDB_RDI = 5,
  GDB_RBP = 6,
  GDB_RSP = 7,
  GDB_R8 = 8,
  GDB_R9 = 9,
  GDB_R10 = 10,
  GDB_R11 = 11,
  GDB_R12 = 12,
  GDB_R13 = 13,
  GDB_R14 = 14,
  GDB_R15 = 15,
  GDB_RIP = 16,
  GDB_EFLAGS = 17,
  GDB_CS = 18,
  GDB_SS = 19,
  GDB_DS = 20,
  GDB_ES = 21,
  GDB_FS = 22,
  GDB_GS = 23,
  GDB_CORE_COUNT = 24,

  GDB_XMM0 = 40,
  GDB_XMM7 = 47,
  GDB_XMM15 = 55,
  GDB_MXCSR = 56,
  GDB_REG_MAX = 57
};

/* FXSAVE offsets inside memdbg_debug_fpregs_t::data (AMD64). */
constexpr size_t kFxsaveMxcsrOff = 24U;
constexpr size_t kFxsaveXmm0Off = 160U;
constexpr size_t kFxsaveXmmBytes = 16U;
constexpr size_t kFxsaveMinLen = 416U; /* through xmm15 */

size_t gdb_reg_size(int regno);
bool gdb_reg_valid(int regno);
bool gdb_reg_is_core(int regno);
bool gdb_reg_is_sse(int regno);

/* Encode/decode little-endian hex used by RSP. */
std::string bytes_to_hex(const void *data, size_t size);
bool hex_to_bytes(const std::string &hex, void *out, size_t size);

/* ASCII→hex body for qThreadExtraInfo. Empty name → "LWP <tid>". */
std::string gdb_thread_extra_info_hex(int32_t tid, const std::string &name);

uint64_t gdb_get_reg_value(const memdbg_debug_regs_t &regs, int regno);
bool gdb_set_reg_value(memdbg_debug_regs_t &regs, int regno, uint64_t value);

/* Core-only helpers (legacy tests / partial G). */
std::string gdb_encode_g_core(const memdbg_debug_regs_t &regs);
bool gdb_decode_g_core(const std::string &hex, memdbg_debug_regs_t &regs);

/* Full g/G matching target.xml (core + SSE). Missing/short fpregs → zero SSE. */
std::string gdb_encode_g_packet(const memdbg_debug_regs_t &regs,
                                const memdbg_debug_fpregs_t *fpregs);
bool gdb_decode_g_packet(const std::string &hex, memdbg_debug_regs_t &regs,
                         memdbg_debug_fpregs_t *fpregs);

/* Read/write one SSE register into an FXSAVE-backed fpregs blob. */
bool gdb_get_sse_bytes(const memdbg_debug_fpregs_t &fpregs, int regno,
                       uint8_t *out, size_t out_size);
bool gdb_set_sse_bytes(memdbg_debug_fpregs_t &fpregs, int regno,
                       const uint8_t *data, size_t size);

} // namespace memdbg::gdb_bridge

#endif /* MEMDBG_GDB_BRIDGE_GDB_REGS_HPP */

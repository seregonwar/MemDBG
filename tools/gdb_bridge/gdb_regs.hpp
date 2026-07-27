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

/* GDB org.gnu.gdb.i386.core register numbers. */
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
  GDB_REG_COUNT = 24
};

size_t gdb_reg_size(int regno);
bool gdb_reg_valid(int regno);

/* Encode/decode little-endian hex used by RSP. */
std::string bytes_to_hex(const void *data, size_t size);
bool hex_to_bytes(const std::string &hex, void *out, size_t size);

uint64_t gdb_get_reg_value(const memdbg_debug_regs_t &regs, int regno);
bool gdb_set_reg_value(memdbg_debug_regs_t &regs, int regno, uint64_t value);

/* Full `g`/`G` blob matching target.xml sizes. */
std::string gdb_encode_g_packet(const memdbg_debug_regs_t &regs);
bool gdb_decode_g_packet(const std::string &hex, memdbg_debug_regs_t &regs);

} // namespace memdbg::gdb_bridge

#endif /* MEMDBG_GDB_BRIDGE_GDB_REGS_HPP */

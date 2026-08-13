/*
 * MemDBG - GDB i386:x86-64 register mapping helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_GDB_BRIDGE_GDB_REGS_HPP
#define MEMDBG_GDB_BRIDGE_GDB_REGS_HPP

#include "memdbg/pal/debug.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace memdbg::gdb_bridge {

/*
 * +-------------------------------------------------------------------+
 * | GDB AMD64 Register Enumeration                                    |
 * +-------------------------------------------------------------------+
 */
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

  /* x87 FPU Registers */
  GDB_ST0 = 24,
  GDB_ST1 = 25,
  GDB_ST2 = 26,
  GDB_ST3 = 27,
  GDB_ST4 = 28,
  GDB_ST5 = 29,
  GDB_ST6 = 30,
  GDB_ST7 = 31,
  GDB_FCTRL = 32,
  GDB_FSTAT = 33,
  GDB_FTAG = 34,
  GDB_FISEG = 35,
  GDB_FIOFF = 36,
  GDB_FOSEG = 37,
  GDB_FOOFF = 38,
  GDB_FOP = 39,
  GDB_X87_COUNT = 16,

  /* SSE Registers */
  GDB_XMM0 = 40,
  GDB_XMM1 = 41,
  GDB_XMM2 = 42,
  GDB_XMM3 = 43,
  GDB_XMM4 = 44,
  GDB_XMM5 = 45,
  GDB_XMM6 = 46,
  GDB_XMM7 = 47,
  GDB_XMM8 = 48,
  GDB_XMM9 = 49,
  GDB_XMM10 = 50,
  GDB_XMM11 = 51,
  GDB_XMM12 = 52,
  GDB_XMM13 = 53,
  GDB_XMM14 = 54,
  GDB_XMM15 = 55,
  GDB_MXCSR = 56,
  GDB_REG_MAX = 57
};

constexpr size_t kFxsaveMinLen = 512U;
constexpr size_t kFxsaveSt0Off = 32U;
constexpr size_t kFxsaveStStride = 16U;
constexpr size_t kFxsaveMxcsrOff = 24U;
constexpr size_t kFxsaveXmm0Off = 160U;
constexpr size_t kFxsaveXmmBytes = 16U;
constexpr size_t kX87PaddingBytes = 112U;
constexpr size_t kGdbCorePacketHexSize = 328U;
constexpr size_t kGdbPacketHexSize = 1072U;

/*
 * +-------------------------------------------------------------------+
 * | Register Properties and Wire Conversions                          |
 * +-------------------------------------------------------------------+
 */
size_t gdb_reg_size(int regno);
bool gdb_reg_is_core(int regno);
bool gdb_reg_is_x87(int regno);
bool gdb_reg_is_sse(int regno);
bool gdb_reg_valid(int regno);

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

/* Standard amd64 g/G packet (core + x87 + SSE). */
std::string gdb_encode_g_packet(const memdbg_debug_regs_t &regs,
                                const memdbg_debug_fpregs_t *fpregs);
bool gdb_decode_g_packet(const std::string &hex, memdbg_debug_regs_t &regs,
                         memdbg_debug_fpregs_t *fpregs);

/* Read/write one x87/SSE register in an FXSAVE-backed fpregs blob. */
bool gdb_get_sse_bytes(const memdbg_debug_fpregs_t &fpregs, int regno, uint8_t *out,
                       size_t out_size);
bool gdb_set_sse_bytes(memdbg_debug_fpregs_t &fpregs, int regno, const uint8_t *data, size_t size);
bool gdb_get_x87_bytes(const memdbg_debug_fpregs_t &fpregs, int regno, uint8_t *out,
                       size_t out_size);
bool gdb_set_x87_bytes(memdbg_debug_fpregs_t &fpregs, int regno, const uint8_t *data, size_t size);

} // namespace memdbg::gdb_bridge

#endif /* MEMDBG_GDB_BRIDGE_GDB_REGS_HPP */

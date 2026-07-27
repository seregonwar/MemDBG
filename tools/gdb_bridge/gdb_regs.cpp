/*
 * MemDBG - GDB i386:x86-64 register mapping helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "gdb_regs.hpp"

namespace memdbg::gdb_bridge {

namespace {

char hex_nibble(unsigned value) {
  return static_cast<char>(value < 10U ? ('0' + value) : ('a' + (value - 10U)));
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

} // namespace

size_t gdb_reg_size(int regno) {
  if (regno < 0 || regno >= GDB_REG_COUNT) return 0U;
  return regno <= GDB_RIP ? 8U : 4U;
}

bool gdb_reg_valid(int regno) {
  return regno >= 0 && regno < GDB_REG_COUNT;
}

std::string bytes_to_hex(const void *data, size_t size) {
  const auto *bytes = static_cast<const uint8_t *>(data);
  std::string out;
  out.resize(size * 2U);
  for (size_t i = 0; i < size; ++i) {
    out[i * 2U] = hex_nibble((bytes[i] >> 4U) & 0x0FU);
    out[i * 2U + 1U] = hex_nibble(bytes[i] & 0x0FU);
  }
  return out;
}

bool hex_to_bytes(const std::string &hex, void *out, size_t size) {
  if (hex.size() != size * 2U) return false;
  auto *bytes = static_cast<uint8_t *>(out);
  for (size_t i = 0; i < size; ++i) {
    const int hi = hex_value(hex[i * 2U]);
    const int lo = hex_value(hex[i * 2U + 1U]);
    if (hi < 0 || lo < 0) return false;
    bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

uint64_t gdb_get_reg_value(const memdbg_debug_regs_t &regs, int regno) {
  switch (regno) {
  case GDB_RAX: return static_cast<uint64_t>(regs.r_rax);
  case GDB_RBX: return static_cast<uint64_t>(regs.r_rbx);
  case GDB_RCX: return static_cast<uint64_t>(regs.r_rcx);
  case GDB_RDX: return static_cast<uint64_t>(regs.r_rdx);
  case GDB_RSI: return static_cast<uint64_t>(regs.r_rsi);
  case GDB_RDI: return static_cast<uint64_t>(regs.r_rdi);
  case GDB_RBP: return static_cast<uint64_t>(regs.r_rbp);
  case GDB_RSP: return static_cast<uint64_t>(regs.r_rsp);
  case GDB_R8: return static_cast<uint64_t>(regs.r_r8);
  case GDB_R9: return static_cast<uint64_t>(regs.r_r9);
  case GDB_R10: return static_cast<uint64_t>(regs.r_r10);
  case GDB_R11: return static_cast<uint64_t>(regs.r_r11);
  case GDB_R12: return static_cast<uint64_t>(regs.r_r12);
  case GDB_R13: return static_cast<uint64_t>(regs.r_r13);
  case GDB_R14: return static_cast<uint64_t>(regs.r_r14);
  case GDB_R15: return static_cast<uint64_t>(regs.r_r15);
  case GDB_RIP: return static_cast<uint64_t>(regs.r_rip);
  case GDB_EFLAGS: return static_cast<uint64_t>(regs.r_rflags) & 0xFFFFFFFFULL;
  case GDB_CS: return static_cast<uint64_t>(regs.r_cs) & 0xFFFFFFFFULL;
  case GDB_SS: return static_cast<uint64_t>(regs.r_ss) & 0xFFFFFFFFULL;
  case GDB_DS: return static_cast<uint64_t>(regs.r_ds);
  case GDB_ES: return static_cast<uint64_t>(regs.r_es);
  case GDB_FS: return static_cast<uint64_t>(regs.r_fs);
  case GDB_GS: return static_cast<uint64_t>(regs.r_gs);
  default: return 0U;
  }
}

bool gdb_set_reg_value(memdbg_debug_regs_t &regs, int regno, uint64_t value) {
  switch (regno) {
  case GDB_RAX: regs.r_rax = static_cast<int64_t>(value); return true;
  case GDB_RBX: regs.r_rbx = static_cast<int64_t>(value); return true;
  case GDB_RCX: regs.r_rcx = static_cast<int64_t>(value); return true;
  case GDB_RDX: regs.r_rdx = static_cast<int64_t>(value); return true;
  case GDB_RSI: regs.r_rsi = static_cast<int64_t>(value); return true;
  case GDB_RDI: regs.r_rdi = static_cast<int64_t>(value); return true;
  case GDB_RBP: regs.r_rbp = static_cast<int64_t>(value); return true;
  case GDB_RSP: regs.r_rsp = static_cast<int64_t>(value); return true;
  case GDB_R8: regs.r_r8 = static_cast<int64_t>(value); return true;
  case GDB_R9: regs.r_r9 = static_cast<int64_t>(value); return true;
  case GDB_R10: regs.r_r10 = static_cast<int64_t>(value); return true;
  case GDB_R11: regs.r_r11 = static_cast<int64_t>(value); return true;
  case GDB_R12: regs.r_r12 = static_cast<int64_t>(value); return true;
  case GDB_R13: regs.r_r13 = static_cast<int64_t>(value); return true;
  case GDB_R14: regs.r_r14 = static_cast<int64_t>(value); return true;
  case GDB_R15: regs.r_r15 = static_cast<int64_t>(value); return true;
  case GDB_RIP: regs.r_rip = static_cast<int64_t>(value); return true;
  case GDB_EFLAGS:
    regs.r_rflags = (regs.r_rflags & ~static_cast<int64_t>(0xFFFFFFFFLL)) |
                    static_cast<int64_t>(value & 0xFFFFFFFFULL);
    return true;
  case GDB_CS: regs.r_cs = static_cast<int64_t>(value & 0xFFFFFFFFULL); return true;
  case GDB_SS: regs.r_ss = static_cast<int64_t>(value & 0xFFFFFFFFULL); return true;
  case GDB_DS: regs.r_ds = static_cast<uint16_t>(value & 0xFFFFULL); return true;
  case GDB_ES: regs.r_es = static_cast<uint16_t>(value & 0xFFFFULL); return true;
  case GDB_FS: regs.r_fs = static_cast<uint16_t>(value & 0xFFFFULL); return true;
  case GDB_GS: regs.r_gs = static_cast<uint16_t>(value & 0xFFFFULL); return true;
  default: return false;
  }
}

std::string gdb_encode_g_packet(const memdbg_debug_regs_t &regs) {
  std::string out;
  out.reserve(GDB_REG_COUNT * 16U);
  for (int regno = 0; regno < GDB_REG_COUNT; ++regno) {
    const size_t size = gdb_reg_size(regno);
    uint64_t value = gdb_get_reg_value(regs, regno);
    if (size == 4U) value &= 0xFFFFFFFFULL;
    out += bytes_to_hex(&value, size);
  }
  return out;
}

bool gdb_decode_g_packet(const std::string &hex, memdbg_debug_regs_t &regs) {
  size_t offset = 0U;
  for (int regno = 0; regno < GDB_REG_COUNT; ++regno) {
    const size_t size = gdb_reg_size(regno);
    if (offset + size * 2U > hex.size()) return false;
    uint64_t value = 0U;
    if (!hex_to_bytes(hex.substr(offset, size * 2U), &value, size)) return false;
    if (!gdb_set_reg_value(regs, regno, value)) return false;
    offset += size * 2U;
  }
  return true;
}

} // namespace memdbg::gdb_bridge

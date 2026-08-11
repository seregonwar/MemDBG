/*
 * MemDBG - GDB i386:x86-64 register mapping helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "gdb_regs.hpp"

#include <cstdio>
#include <cstring>

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

bool fxsave_ready(const memdbg_debug_fpregs_t &fpregs) {
  return fpregs.length >= kFxsaveMinLen;
}

void ensure_fxsave(memdbg_debug_fpregs_t &fpregs) {
  if (fpregs.length < kFxsaveMinLen) {
    std::memset(fpregs.data + fpregs.length, 0,
                kFxsaveMinLen - fpregs.length);
    fpregs.length = static_cast<uint32_t>(kFxsaveMinLen);
  }
}

} // namespace

size_t gdb_reg_size(int regno) {
  if (gdb_reg_is_core(regno)) {
    return regno <= GDB_RIP ? 8U : 4U;
  }
  if (gdb_reg_is_x87(regno)) {
    return regno <= GDB_ST7 ? 10U : 4U;
  }
  if (regno >= GDB_XMM0 && regno <= GDB_XMM15) return kFxsaveXmmBytes;
  if (regno == GDB_MXCSR) return 4U;
  return 0U;
}

bool gdb_reg_is_core(int regno) {
  return regno >= 0 && regno < GDB_CORE_COUNT;
}

bool gdb_reg_is_x87(int regno) {
  return regno >= GDB_ST0 && regno <= GDB_FOP;
}

bool gdb_reg_is_sse(int regno) {
  return (regno >= GDB_XMM0 && regno <= GDB_XMM15) || regno == GDB_MXCSR;
}

bool gdb_reg_valid(int regno) {
  return gdb_reg_is_core(regno) || gdb_reg_is_x87(regno) || gdb_reg_is_sse(regno);
}

std::string gdb_thread_extra_info_hex(int32_t tid, const std::string &name) {
  std::string display = name;
  bool firmware_fill = display.size() >= 8U;
  for (unsigned char c : display) {
    if (c < 0x20U || c > 0x7EU) {
      display.clear();
      break;
    }
    if (c != 'F' && c != 'f') firmware_fill = false;
  }
  if (firmware_fill) display.clear();
  if (display.empty()) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "LWP %d", static_cast<int>(tid));
    display = buf;
  }
  return bytes_to_hex(display.data(), display.size());
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

/*
 * +-------------------------------------------------------------------+
 * | Register Access Routines                                          |
 * +-------------------------------------------------------------------+
 */
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

bool gdb_get_sse_bytes(const memdbg_debug_fpregs_t &fpregs, int regno,
                       uint8_t *out, size_t out_size) {
  if (!out || !gdb_reg_is_sse(regno)) return false;
  const size_t need = gdb_reg_size(regno);
  if (out_size < need) return false;
  std::memset(out, 0, need);
  if (!fxsave_ready(fpregs)) return true;
  if (regno == GDB_MXCSR) {
    std::memcpy(out, fpregs.data + kFxsaveMxcsrOff, 4U);
    return true;
  }
  const size_t off =
      kFxsaveXmm0Off +
      static_cast<size_t>(regno - GDB_XMM0) * kFxsaveXmmBytes;
  std::memcpy(out, fpregs.data + off, kFxsaveXmmBytes);
  return true;
}

bool gdb_set_sse_bytes(memdbg_debug_fpregs_t &fpregs, int regno,
                       const uint8_t *data, size_t size) {
  if (!data || !gdb_reg_is_sse(regno)) return false;
  if (size != gdb_reg_size(regno)) return false;
  ensure_fxsave(fpregs);
  if (regno == GDB_MXCSR) {
    std::memcpy(fpregs.data + kFxsaveMxcsrOff, data, 4U);
    return true;
  }
  const size_t off =
      kFxsaveXmm0Off +
      static_cast<size_t>(regno - GDB_XMM0) * kFxsaveXmmBytes;
  std::memcpy(fpregs.data + off, data, kFxsaveXmmBytes);
  return true;
}

/*
 * +-------------------------------------------------------------------+
 * | G-Packet Serialization                                            |
 * +-------------------------------------------------------------------+
 */
std::string gdb_encode_g_core(const memdbg_debug_regs_t &regs) {
  std::string out;
  out.reserve(GDB_CORE_COUNT * 16U);
  for (int regno = 0; regno < GDB_CORE_COUNT; ++regno) {
    const size_t size = gdb_reg_size(regno);
    uint64_t value = gdb_get_reg_value(regs, regno);
    if (size == 4U) value &= 0xFFFFFFFFULL;
    out += bytes_to_hex(&value, size);
  }
  return out;
}

bool gdb_decode_g_core(const std::string &hex, memdbg_debug_regs_t &regs) {
  size_t offset = 0U;
  for (int regno = 0; regno < GDB_CORE_COUNT; ++regno) {
    const size_t size = gdb_reg_size(regno);
    if (offset + size * 2U > hex.size()) return false;
    uint64_t value = 0U;
    if (!hex_to_bytes(hex.substr(offset, size * 2U), &value, size)) return false;
    if (!gdb_set_reg_value(regs, regno, value)) return false;
    offset += size * 2U;
  }
  return true;
}

std::string gdb_encode_g_packet(const memdbg_debug_regs_t &regs,
                                const memdbg_debug_fpregs_t *fpregs) {
  std::string out = gdb_encode_g_core(regs);
  /* Insert x87 112-byte zero padding (224 hex zeros) for standard amd64 layout. */
  out.append(kX87PaddingBytes * 2U, '0');

  /* Document order in target.xml: xmm0..xmm15 then mxcsr. */
  uint8_t tmp[16]{};
  for (int regno = GDB_XMM0; regno <= GDB_XMM15; ++regno) {
    if (fpregs) {
      (void)gdb_get_sse_bytes(*fpregs, regno, tmp, sizeof(tmp));
    } else {
      std::memset(tmp, 0, sizeof(tmp));
    }
    out += bytes_to_hex(tmp, kFxsaveXmmBytes);
  }
  uint8_t mxcsr[4]{};
  if (fpregs) {
    (void)gdb_get_sse_bytes(*fpregs, GDB_MXCSR, mxcsr, sizeof(mxcsr));
  }
  out += bytes_to_hex(mxcsr, sizeof(mxcsr));
  return out;
}

bool gdb_decode_g_packet(const std::string &hex, memdbg_debug_regs_t &regs,
                         memdbg_debug_fpregs_t *fpregs) {
  if (!gdb_decode_g_core(hex, regs)) return false;
  /* Core hex length: 328 chars. x87 padding: 224 chars. Total prefix: 552 chars. */
  size_t offset = 552U;
  if (hex.size() < offset) return false;
  if (!fpregs) {
    return true;
  }
  ensure_fxsave(*fpregs);
  uint8_t tmp[16]{};
  for (int regno = GDB_XMM0; regno <= GDB_XMM15; ++regno) {
    if (offset + kFxsaveXmmBytes * 2U > hex.size()) return false;
    if (!hex_to_bytes(hex.substr(offset, kFxsaveXmmBytes * 2U), tmp,
                      kFxsaveXmmBytes)) {
      return false;
    }
    if (!gdb_set_sse_bytes(*fpregs, regno, tmp, kFxsaveXmmBytes)) return false;
    offset += kFxsaveXmmBytes * 2U;
  }
  if (offset + 8U > hex.size()) return false;
  uint8_t mxcsr[4]{};
  if (!hex_to_bytes(hex.substr(offset, 8U), mxcsr, 4U)) return false;
  return gdb_set_sse_bytes(*fpregs, GDB_MXCSR, mxcsr, 4U);
}

} // namespace memdbg::gdb_bridge

/*
 * MemDBG - Unit tests for GDB bridge framing and register mapping.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "gdb_regs.hpp"
#include "rsp_server.hpp"
#include "target_xml.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace memdbg::gdb_bridge;

static int failures;

#define CHECK(name, expr)                                                       \
  do {                                                                          \
    if (!(expr)) {                                                              \
      std::fprintf(stderr, "FAIL: %s\n", name);                                 \
      failures++;                                                               \
    }                                                                           \
  } while (0)

int main() {
  CHECK("checksum empty", rsp_checksum("") == 0U);
  CHECK("checksum abc", rsp_checksum("abc") ==
                            static_cast<uint8_t>('a' + 'b' + 'c'));

  const std::string escaped = rsp_escape("a$#}b");
  CHECK("escape specials", escaped == "a}\x04}\x03}]b");
  CHECK("unescape round-trip", rsp_unescape(rsp_escape("hello$#}")) ==
                                   "hello$#}");

  memdbg_debug_regs_t regs{};
  regs.r_rax = 0x1122334455667788LL;
  regs.r_rbx = 0x1LL;
  regs.r_rcx = 0x2LL;
  regs.r_rdx = 0x3LL;
  regs.r_rsi = 0x4LL;
  regs.r_rdi = 0x5LL;
  regs.r_rbp = 0x6LL;
  regs.r_rsp = 0x7FFFFFFFFLL;
  regs.r_r8 = 0x8LL;
  regs.r_r9 = 0x9LL;
  regs.r_r10 = 0xALL;
  regs.r_r11 = 0xBLL;
  regs.r_r12 = 0xCLL;
  regs.r_r13 = 0xDLL;
  regs.r_r14 = 0xELL;
  regs.r_r15 = 0xFLL;
  regs.r_rip = 0x401000LL;
  regs.r_rflags = 0x246LL;
  regs.r_cs = 0x33LL;
  regs.r_ss = 0x2BLL;
  regs.r_ds = 0x2BU;
  regs.r_es = 0x2BU;
  regs.r_fs = 0x43U;
  regs.r_gs = 0x53U;

  CHECK("rax mapping", gdb_get_reg_value(regs, GDB_RAX) ==
                           0x1122334455667788ULL);
  CHECK("rip mapping", gdb_get_reg_value(regs, GDB_RIP) == 0x401000ULL);
  CHECK("eflags truncated",
        gdb_get_reg_value(regs, GDB_EFLAGS) == 0x246ULL);

  const std::string g = gdb_encode_g_packet(regs, nullptr);
  /* core 328 + xmm 512 + mxcsr 8 = 848 hex chars */
  CHECK("g packet size", g.size() == 848U);

  memdbg_debug_regs_t decoded{};
  CHECK("g decode succeeds", gdb_decode_g_packet(g, decoded, nullptr));
  CHECK("rax round-trip",
        static_cast<uint64_t>(decoded.r_rax) ==
            0x1122334455667788ULL);
  CHECK("rsp round-trip",
        static_cast<uint64_t>(decoded.r_rsp) == 0x7FFFFFFFFULL);
  CHECK("rip round-trip",
        static_cast<uint64_t>(decoded.r_rip) == 0x401000ULL);
  CHECK("rflags round-trip",
        (static_cast<uint64_t>(decoded.r_rflags) & 0xFFFFFFFFULL) == 0x246ULL);
  CHECK("ss round-trip",
        static_cast<uint64_t>(decoded.r_ss) == 0x2BULL);

  memdbg_debug_fpregs_t fpregs{};
  fpregs.length = 512U;
  std::memset(fpregs.data, 0, sizeof(fpregs.data));
  const uint8_t xmm7[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  CHECK("set xmm7", gdb_set_sse_bytes(fpregs, GDB_XMM7, xmm7, 16U));
  uint32_t mxcsr = 0x1F80U;
  CHECK("set mxcsr",
        gdb_set_sse_bytes(fpregs, GDB_MXCSR,
                          reinterpret_cast<const uint8_t *>(&mxcsr), 4U));
  const std::string g2 = gdb_encode_g_packet(regs, &fpregs);
  CHECK("g+sse size", g2.size() == 848U);
  memdbg_debug_fpregs_t fpregs2{};
  memdbg_debug_regs_t decoded2{};
  CHECK("g+sse decode", gdb_decode_g_packet(g2, decoded2, &fpregs2));
  uint8_t xmm7_out[16]{};
  CHECK("get xmm7", gdb_get_sse_bytes(fpregs2, GDB_XMM7, xmm7_out, 16U));
  CHECK("xmm7 round-trip", std::memcmp(xmm7, xmm7_out, 16U) == 0);

  uint32_t mxcsr_out = 0;
  CHECK("get mxcsr",
        gdb_get_sse_bytes(fpregs2, GDB_MXCSR,
                          reinterpret_cast<uint8_t *>(&mxcsr_out), 4U));
  CHECK("mxcsr round-trip", mxcsr_out == 0x1F80U);

  /* xmm0 and xmm15 extremes */
  const uint8_t xmm0[16] = {0xAA};
  const uint8_t xmm15[16] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                             0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
  CHECK("set xmm0", gdb_set_sse_bytes(fpregs, GDB_XMM0, xmm0, 16U));
  CHECK("set xmm15", gdb_set_sse_bytes(fpregs, GDB_XMM15, xmm15, 16U));
  uint8_t xmm0_out[16]{};
  uint8_t xmm15_out[16]{};
  CHECK("get xmm0", gdb_get_sse_bytes(fpregs, GDB_XMM0, xmm0_out, 16U));
  CHECK("get xmm15", gdb_get_sse_bytes(fpregs, GDB_XMM15, xmm15_out, 16U));
  CHECK("xmm0 round-trip", std::memcmp(xmm0, xmm0_out, 16U) == 0);
  CHECK("xmm15 round-trip", std::memcmp(xmm15, xmm15_out, 16U) == 0);

  /* Short FXSAVE still reports zeros for SSE reads. */
  memdbg_debug_fpregs_t short_fp{};
  short_fp.length = 32U;
  uint8_t zero16[16]{};
  CHECK("short fxsave get xmm0 zeros",
        gdb_get_sse_bytes(short_fp, GDB_XMM0, xmm0_out, 16U) &&
            std::memcmp(xmm0_out, zero16, 16U) == 0);
  CHECK("reject bad sse size",
        !gdb_set_sse_bytes(fpregs, GDB_XMM0, xmm0, 8U));
  CHECK("reject core as sse",
        !gdb_set_sse_bytes(fpregs, GDB_RAX, xmm0, 16U));

  /* target.xml must not claim X87 yet (documented gap). */
  CHECK("target xml no st0",
        std::strstr(kMemdbgGdbTargetXml, "name=\"st0\"") == nullptr);
  CHECK("target xml no fctrl",
        std::strstr(kMemdbgGdbTargetXml, "name=\"fctrl\"") == nullptr);

  uint64_t patched = 0xDEADBEEFCAFEULL;
  CHECK("set rbx", gdb_set_reg_value(regs, GDB_RBX, patched));
  CHECK("get rbx", gdb_get_reg_value(regs, GDB_RBX) == patched);

  const std::string hex = bytes_to_hex("\x01\x02\xff", 3U);
  CHECK("bytes_to_hex", hex == "0102ff");
  uint8_t back[3]{};
  CHECK("hex_to_bytes", hex_to_bytes(hex, back, 3U));
  CHECK("hex bytes match", back[0] == 0x01 && back[1] == 0x02 && back[2] == 0xFF);

  /* qThreadExtraInfo body: ASCII name hex-encoded for IDA/GDB. */
  CHECK("thread extra named",
        gdb_thread_extra_info_hex(88, "main") == "6d61696e");
  CHECK("thread extra empty fallback",
        gdb_thread_extra_info_hex(0x58, "") ==
            bytes_to_hex("LWP 88", 6U));

  CHECK("target xml non-empty", std::strlen(kMemdbgGdbTargetXml) > 100U);
  CHECK("target xml has architecture",
        std::strstr(kMemdbgGdbTargetXml, "i386:x86-64") != nullptr);
  CHECK("target xml has rax",
        std::strstr(kMemdbgGdbTargetXml, "name=\"rax\"") != nullptr);
  CHECK("target xml has xmm0",
        std::strstr(kMemdbgGdbTargetXml, "name=\"xmm0\"") != nullptr);
  CHECK("target xml has mxcsr",
        std::strstr(kMemdbgGdbTargetXml, "name=\"mxcsr\"") != nullptr);

  CHECK("reg size rax", gdb_reg_size(GDB_RAX) == 8U);
  CHECK("reg size eflags", gdb_reg_size(GDB_EFLAGS) == 4U);
  CHECK("invalid regno", !gdb_reg_valid(-1) && !gdb_reg_valid(GDB_REG_MAX));

  if (failures == 0) {
    std::fprintf(stdout, "All gdb_bridge tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d test(s) failed\n", failures);
  return 1;
}

/*
 * MemDBG - Unit tests for GDB bridge framing and register mapping.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "gdb_regs.hpp"
#include "rsp_handler.hpp"
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
  /* Multiprocess RSP thread ID parser tests */
  int32_t pid_out = 0, tid_out = 0;
  CHECK("parse_thread_id hex tid", parse_thread_id("4a", pid_out, tid_out) && pid_out == 0 && tid_out == 0x4A);
  CHECK("parse_thread_id p4a.4a", parse_thread_id("p4a.4a", pid_out, tid_out) && pid_out == 0x4A && tid_out == 0x4A);
  CHECK("parse_thread_id p4a.1001", parse_thread_id("p4a.1001", pid_out, tid_out) && pid_out == 0x4A && tid_out == 0x1001);
  CHECK("parse_thread_id p-1.-1", parse_thread_id("p-1.-1", pid_out, tid_out) && pid_out == -1 && tid_out == -1);
  CHECK("parse_thread_id -1", parse_thread_id("-1", pid_out, tid_out) && tid_out == -1);
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
  /* core 328 + x87 padding 224 + xmm 512 + mxcsr 8 = 1072 hex chars (536 bytes) */
  CHECK("g packet size", g.size() == 1072U);

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

  const std::string ida_core = gdb_encode_g_core(regs);
  CHECK("IDA core g-packet size", ida_core.size() == 328U);
  memdbg_debug_regs_t ida_decoded{};
  CHECK("IDA core g-packet decode",
        gdb_decode_g_core(ida_core, ida_decoded));
  CHECK("IDA core RIP round-trip",
        static_cast<uint64_t>(ida_decoded.r_rip) == 0x401000ULL);

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
  CHECK("g+sse size", g2.size() == 1072U);
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
  CHECK("thread extra rejects non-text firmware fill",
        gdb_thread_extra_info_hex(0x49, std::string(15U, '\xff')) ==
            bytes_to_hex("LWP 73", 6U));
  CHECK("thread extra rejects printable firmware fill",
        gdb_thread_extra_info_hex(0x4A, "FFFFFFFFFFFFFFF") ==
            bytes_to_hex("LWP 74", 6U));

  std::vector<memdbg::frontend::Client::DebugWatchpointEntry> watchpoints(3U);
  watchpoints[0] = {0x1000U, 4U, 1U, 0U, true};
  watchpoints[1] = {0x2000U, 4U, 2U, 1U, true};
  watchpoints[2] = {0x3000U, 8U, 3U, 2U, true};
  CHECK("write DR6 stop reason",
        gdb_watchpoint_stop_field(1ULL, watchpoints) == "watch:1000;");
  CHECK("read DR6 stop reason",
        gdb_watchpoint_stop_field(2ULL, watchpoints) == "rwatch:2000;");
  CHECK("access DR6 stop reason",
        gdb_watchpoint_stop_field(4ULL, watchpoints) == "awatch:3000;");
  CHECK("no DR6 hit has no stop reason",
        gdb_watchpoint_stop_field(0ULL, watchpoints).empty());

  CHECK("target xml non-empty", std::strlen(kMemdbgGdbTargetXml) > 100U);
  CHECK("target xml has architecture",
        std::strstr(kMemdbgGdbTargetXml, "i386:x86-64") != nullptr);
  CHECK("target xml uses IDA built-in register layout",
        std::strstr(kMemdbgGdbTargetXml, "<reg ") == nullptr);

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

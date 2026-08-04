/*
 * MemDBG - Unit tests for x64dbg plugin pure helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "plugin_util.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace memdbg::x64dbg_bridge;

static int failures;

#define CHECK(name, expr)                                                       \
  do {                                                                          \
    if (!(expr)) {                                                              \
      std::fprintf(stderr, "FAIL: %s\n", name);                                 \
      failures++;                                                               \
    }                                                                           \
  } while (0)

int main() {
  uint64_t u = 0;
  CHECK("parse_u64 hex", parse_u64("0x401000", u) && u == 0x401000ULL);
  CHECK("parse_u64 dec", parse_u64("1234", u) && u == 1234ULL);
  CHECK("parse_u64 rejects trailing", !parse_u64("0x10zz", u));
  CHECK("parse_u64 empty", !parse_u64("", u));
  CHECK("parse_u64 null", !parse_u64(nullptr, u));

  int32_t i = 0;
  CHECK("parse_i32", parse_i32("42", i) && i == 42);
  CHECK("parse_i32 rejects trailing", !parse_i32("42x", i));

  std::vector<uint8_t> bytes;
  CHECK("parse_hex spaces", parse_hex_bytes("90 90 C3", bytes) &&
                                bytes.size() == 3 && bytes[0] == 0x90 &&
                                bytes[2] == 0xC3);
  CHECK("parse_hex commas", parse_hex_bytes("DE,AD,BE,EF", bytes) &&
                                bytes.size() == 4 && bytes[0] == 0xDE);
  CHECK("parse_hex odd nibble", !parse_hex_bytes("ABC", bytes));
  CHECK("parse_hex empty", !parse_hex_bytes("", bytes));
  CHECK("parse_hex garbage", !parse_hex_bytes("ZZ", bytes));

  memdbg_debug_regs_t regs{};
  CHECK("apply rax", apply_gpr_name(regs, "RAX", 0x1111) &&
                         static_cast<uint64_t>(regs.r_rax) == 0x1111ULL);
  CHECK("apply rip", apply_gpr_name(regs, "rip", 0x2000) &&
                         static_cast<uint64_t>(regs.r_rip) == 0x2000ULL);
  CHECK("apply eflags alias",
        apply_gpr_name(regs, "EFLAGS", 0x246) &&
            static_cast<uint64_t>(regs.r_rflags) == 0x246ULL);
  CHECK("apply unknown", !apply_gpr_name(regs, "xmm0", 1));
  CHECK("apply null name", !apply_gpr_name(regs, nullptr, 1));

  const auto plan = make_view_sync_plan(0x401000, 0x7FFFFFFF0000ULL, 0);
  CHECK("sync plan cip", plan.ok && plan.cip == 0x401000ULL);
  CHECK("sync plan dump rsp", plan.dump_addr == 0x7FFFFFFF0000ULL);

  const auto plan2 = make_view_sync_plan(0x401000, 0x7FFFFFFF0000ULL, 0x5000);
  CHECK("sync plan dump override", plan2.dump_addr == 0x5000ULL);

  const auto plan3 = make_view_sync_plan(0x401000, 0, 0);
  CHECK("sync plan dump falls back to rip", plan3.dump_addr == 0x401000ULL);

  const auto plan4 = make_view_sync_plan(0, 0, 0);
  CHECK("sync plan empty", !plan4.ok);

  {
    std::string host;
    uint16_t port = 0;
    char *a0[] = {const_cast<char *>("MemDBGConnect")};
    CHECK("connect default",
          parse_connect_endpoint(1, a0, host, port) && host == "127.0.0.1" &&
              port == 9020);

    char *a1[] = {const_cast<char *>("MemDBGConnect"),
                  const_cast<char *>("192.168.1.50")};
    CHECK("connect host only",
          parse_connect_endpoint(2, a1, host, port) &&
              host == "192.168.1.50" && port == 9020);

    char *a2[] = {const_cast<char *>("MemDBGConnect"),
                  const_cast<char *>("192.168.1.50"),
                  const_cast<char *>("9021")};
    CHECK("connect host port",
          parse_connect_endpoint(3, a2, host, port) &&
              host == "192.168.1.50" && port == 9021);

    char *a3[] = {const_cast<char *>("MemDBGConnect"),
                  const_cast<char *>("192.168.1.50:9030")};
    CHECK("connect host:port",
          parse_connect_endpoint(2, a3, host, port) &&
              host == "192.168.1.50" && port == 9030);

    char *a4[] = {const_cast<char *>("MemDBGConnect"),
                  const_cast<char *>("\"192.168.1.50\""),
                  const_cast<char *>("9020")};
    CHECK("connect quoted host",
          parse_connect_endpoint(3, a4, host, port) &&
              host == "192.168.1.50" && port == 9020);

    char *a5[] = {const_cast<char *>("MemDBGConnect"),
                  const_cast<char *>("192.168.1.50,"),
                  const_cast<char *>("9020")};
    CHECK("connect comma host",
          parse_connect_endpoint(3, a5, host, port) &&
              host == "192.168.1.50" && port == 9020);

    char *a6[] = {const_cast<char *>("MemDBGConnect"),
                  const_cast<char *>("192.168.1.50 9020")};
    CHECK("connect jammed argv",
          parse_connect_endpoint(2, a6, host, port) &&
              host == "192.168.1.50" && port == 9020);

    char *a7[] = {const_cast<char *>("MemDBGConnect"),
                  const_cast<char *>("not-an-ip")};
    CHECK("connect reject host", !parse_connect_endpoint(2, a7, host, port));
  }

  if (failures == 0) {
    std::fprintf(stdout, "All x64dbg plugin util tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d test(s) failed\n", failures);
  return 1;
}

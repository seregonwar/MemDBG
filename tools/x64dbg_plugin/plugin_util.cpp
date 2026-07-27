/*
 * MemDBG - Pure helpers for the x64dbg plugin (testable without Plugin SDK).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "plugin_util.hpp"

#include <cctype>
#include <cstdlib>
#include <cstring>

namespace memdbg::x64dbg_bridge {

bool parse_u64(const char *text, uint64_t &out) {
  if (!text || !*text) return false;
  char *end = nullptr;
  const unsigned long long v = std::strtoull(text, &end, 0);
  if (end == text || (end && *end != '\0')) return false;
  out = static_cast<uint64_t>(v);
  return true;
}

bool parse_i32(const char *text, int32_t &out) {
  if (!text || !*text) return false;
  char *end = nullptr;
  const long v = std::strtol(text, &end, 0);
  if (end == text || (end && *end != '\0')) return false;
  out = static_cast<int32_t>(v);
  return true;
}

bool parse_hex_bytes(const char *text, std::vector<uint8_t> &out) {
  out.clear();
  if (!text) return false;
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  int hi = -1;
  for (const char *p = text; *p; ++p) {
    if (*p == ' ' || *p == '\t' || *p == ',') continue;
    const int n = nibble(*p);
    if (n < 0) return false;
    if (hi < 0) {
      hi = n;
    } else {
      out.push_back(static_cast<uint8_t>((hi << 4) | n));
      hi = -1;
    }
  }
  return hi < 0 && !out.empty();
}

namespace {

bool ieq(const char *a, const char *b) {
  if (!a || !b) return false;
  for (; *a && *b; ++a, ++b) {
    const unsigned char ca = static_cast<unsigned char>(*a);
    const unsigned char cb = static_cast<unsigned char>(*b);
    if (std::tolower(ca) != std::tolower(cb)) return false;
  }
  return *a == *b;
}

} // namespace

bool apply_gpr_name(memdbg_debug_regs_t &regs, const char *name, uint64_t value) {
  if (!name || !*name) return false;
  const int64_t v = static_cast<int64_t>(value);
  if (ieq(name, "rax")) regs.r_rax = v;
  else if (ieq(name, "rbx")) regs.r_rbx = v;
  else if (ieq(name, "rcx")) regs.r_rcx = v;
  else if (ieq(name, "rdx")) regs.r_rdx = v;
  else if (ieq(name, "rsi")) regs.r_rsi = v;
  else if (ieq(name, "rdi")) regs.r_rdi = v;
  else if (ieq(name, "rbp")) regs.r_rbp = v;
  else if (ieq(name, "rsp")) regs.r_rsp = v;
  else if (ieq(name, "r8")) regs.r_r8 = v;
  else if (ieq(name, "r9")) regs.r_r9 = v;
  else if (ieq(name, "r10")) regs.r_r10 = v;
  else if (ieq(name, "r11")) regs.r_r11 = v;
  else if (ieq(name, "r12")) regs.r_r12 = v;
  else if (ieq(name, "r13")) regs.r_r13 = v;
  else if (ieq(name, "r14")) regs.r_r14 = v;
  else if (ieq(name, "r15")) regs.r_r15 = v;
  else if (ieq(name, "rip")) regs.r_rip = v;
  else if (ieq(name, "rflags") || ieq(name, "eflags")) regs.r_rflags = v;
  else return false;
  return true;
}

ViewSyncPlan make_view_sync_plan(uint64_t rip, uint64_t rsp,
                                 uint64_t dump_override) {
  ViewSyncPlan plan;
  if (rip == 0 && rsp == 0 && dump_override == 0) {
    return plan;
  }
  plan.cip = rip;
  if (dump_override != 0) {
    plan.dump_addr = dump_override;
  } else if (rsp != 0) {
    plan.dump_addr = rsp;
  } else {
    plan.dump_addr = rip;
  }
  plan.ok = plan.cip != 0 || plan.dump_addr != 0;
  return plan;
}

} // namespace memdbg::x64dbg_bridge

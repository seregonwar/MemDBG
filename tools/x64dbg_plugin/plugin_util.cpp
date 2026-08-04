/*
 * MemDBG - Pure helpers for the x64dbg plugin (testable without Plugin SDK).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "plugin_util.hpp"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>

namespace memdbg::x64dbg_bridge {

namespace {

std::string strip_quotes_and_space(const char *text) {
  if (!text) return {};
  const char *begin = text;
  while (*begin == ' ' || *begin == '\t' || *begin == '"' || *begin == '\'') {
    ++begin;
  }
  const char *end = begin + std::strlen(begin);
  while (end > begin) {
    const char c = *(end - 1);
    if (c == ' ' || c == '\t' || c == '"' || c == '\'') {
      --end;
      continue;
    }
    break;
  }
  return std::string(begin, end);
}

bool looks_like_ipv4(const std::string &host) {
  int dots = 0;
  int group = -1;
  for (char c : host) {
    if (c == '.') {
      if (group < 0 || group > 255) return false;
      dots++;
      group = -1;
      continue;
    }
    if (c < '0' || c > '9') return false;
    if (group < 0) group = 0;
    group = group * 10 + (c - '0');
    if (group > 255) return false;
  }
  return dots == 3 && group >= 0 && group <= 255;
}

bool parse_port_token(const std::string &token, uint16_t &port) {
  if (token.empty()) return false;
  char *end = nullptr;
  const long v = std::strtol(token.c_str(), &end, 10);
  if (end == token.c_str() || (end && *end != '\0')) return false;
  if (v <= 0 || v > 65535) return false;
  port = static_cast<uint16_t>(v);
  return true;
}

} // namespace

bool parse_connect_endpoint(int argc, char **argv, std::string &host,
                            uint16_t &port) {
  host = "127.0.0.1";
  port = 9020;
  if (argc < 2 || argv == nullptr) return true;

  /* Join argv[1..] so Script-engine / odd splitters still work. */
  std::string joined;
  for (int i = 1; i < argc; ++i) {
    if (argv[i] == nullptr || argv[i][0] == '\0') continue;
    if (!joined.empty()) joined.push_back(' ');
    joined += argv[i];
  }
  joined = strip_quotes_and_space(joined.c_str());
  if (joined.empty()) return true;

  /* Normalize "host", port  /  host,port  (x64dbg often inserts commas). */
  for (char &c : joined) {
    if (c == ',') c = ' ';
  }
  /* Collapse runs of spaces. */
  {
    std::string norm;
    norm.reserve(joined.size());
    bool prev_space = false;
    for (char c : joined) {
      if (c == ' ' || c == '\t') {
        if (!prev_space && !norm.empty()) norm.push_back(' ');
        prev_space = true;
        continue;
      }
      prev_space = false;
      norm.push_back(c);
    }
    while (!norm.empty() && norm.back() == ' ') norm.pop_back();
    joined = std::move(norm);
  }
  if (joined.empty()) return true;

  /* host:port (prefer last colon so IPv4 stays intact). */
  const auto colon = joined.rfind(':');
  if (colon != std::string::npos && colon > 0 && colon + 1 < joined.size() &&
      joined.find(' ') == std::string::npos) {
    std::string maybe_host = strip_quotes_and_space(joined.substr(0, colon).c_str());
    std::string maybe_port = strip_quotes_and_space(joined.substr(colon + 1).c_str());
    uint16_t p = 9020;
    if (looks_like_ipv4(maybe_host) && parse_port_token(maybe_port, p)) {
      host = std::move(maybe_host);
      port = p;
      return true;
    }
  }

  /* host port */
  const auto space = joined.find(' ');
  if (space != std::string::npos) {
    std::string maybe_host =
        strip_quotes_and_space(joined.substr(0, space).c_str());
    std::string rest = strip_quotes_and_space(joined.substr(space + 1).c_str());
    /* drop any further tokens after port */
    const auto rest_space = rest.find(' ');
    if (rest_space != std::string::npos) rest = rest.substr(0, rest_space);
    uint16_t p = 9020;
    if (looks_like_ipv4(maybe_host) && parse_port_token(rest, p)) {
      host = std::move(maybe_host);
      port = p;
      return true;
    }
    if (looks_like_ipv4(maybe_host)) {
      host = std::move(maybe_host);
      return true;
    }
    return false;
  }

  if (!looks_like_ipv4(joined)) return false;
  host = std::move(joined);
  return true;
}

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

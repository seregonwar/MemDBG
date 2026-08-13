/*
 * MemDBG - Shared GDB Remote Serial Protocol primitives.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rsp_protocol.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>

namespace memdbg::gdb_bridge {
namespace detail {

bool parse_hex_u64(const std::string &s, size_t begin, size_t end, uint64_t &out) {
  if (begin >= end || end > s.size()) return false;
  uint64_t value = 0U;
  for (size_t i = begin; i < end; ++i) {
    const char c = s[i];
    int n = -1;
    if (c >= '0' && c <= '9')
      n = c - '0';
    else if (c >= 'a' && c <= 'f')
      n = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      n = c - 'A' + 10;
    else
      return false;
    if (value > (std::numeric_limits<uint64_t>::max() - static_cast<uint64_t>(n)) / 16U) {
      return false;
    }
    value = value * 16U + static_cast<uint64_t>(n);
  }
  out = value;
  return true;
}

bool parse_hex_u64(const char *s, uint64_t &out) {
  if (s == nullptr || *s == '\0') return false;
  const std::string text(s);
  return parse_hex_u64(text, 0U, text.size(), out);
}

std::string err_packet(int code) {
  char buf[8];
  std::snprintf(buf, sizeof(buf), "E%02x", code & 0xFF);
  return std::string(buf);
}

int watch_type_from_z(char kind) {
  /* MemDBG: 0=exec, 1=write, 2=read, 3=rw */
  switch (kind) {
  case '1': return 0; /* hardware exec -> exec watch / HW BP uses set_breakpoint */
  case '2': return 1;
  case '3': return 2;
  case '4': return 3;
  default: return -1;
  }
}

std::string xml_escape(const std::string &text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    switch (c) {
    case '&': out += "&amp;"; break;
    case '<': out += "&lt;"; break;
    case '>': out += "&gt;"; break;
    case '\"': out += "&quot;"; break;
    case '\'': out += "&apos;"; break;
    default: out.push_back(c); break;
    }
  }
  return out;
}

std::string qxfer_slice(const std::string &data, size_t offset, size_t length) {
  if (length == 0U) return err_packet(1);
  if (offset >= data.size()) return "l";
  const size_t n = std::min(length, data.size() - offset);
  std::string out(1U, offset + n >= data.size() ? 'l' : 'm');
  out.append(data, offset, n);
  return out;
}

bool parse_qxfer_request(const std::string &packet, const char *prefix, std::string &annex,
                         size_t &offset, size_t &length) {
  const size_t prefix_len = std::strlen(prefix);
  if (packet.rfind(prefix, 0U) != 0U) return false;
  const std::string rest = packet.substr(prefix_len);
  const size_t colon = rest.find(':');
  const size_t comma = colon == std::string::npos ? std::string::npos : rest.find(',', colon + 1U);
  if (colon == std::string::npos || comma == std::string::npos) return false;
  uint64_t parsed_offset = 0U;
  uint64_t parsed_length = 0U;
  if (!parse_hex_u64(rest, colon + 1U, comma, parsed_offset) ||
      !parse_hex_u64(rest, comma + 1U, rest.size(), parsed_length) ||
      parsed_offset > std::numeric_limits<size_t>::max() ||
      parsed_length > std::numeric_limits<size_t>::max() || parsed_length == 0U) {
    return false;
  }
  annex = rest.substr(0U, colon);
  offset = static_cast<size_t>(parsed_offset);
  length = static_cast<size_t>(parsed_length);
  return true;
}

} // namespace detail

using detail::parse_hex_u64;

bool parse_thread_id(const char *s, int32_t &pid_out, int32_t &tid_out) {
  if (s == nullptr || *s == '\0') return false;
  const std::string text(s);
  const bool multiprocess = text[0] == 'p';
  const size_t first = multiprocess ? 1U : 0U;
  if (first >= text.size()) return false;

  auto parse_component = [&](size_t begin, size_t end, int32_t &value) {
    if (begin >= end) return false;
    if (end - begin == 2U && text.compare(begin, 2U, "-1") == 0) {
      value = -1;
      return true;
    }
    uint64_t parsed = 0U;
    if (!parse_hex_u64(text, begin, end, parsed) ||
        parsed > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
      return false;
    }
    value = static_cast<int32_t>(parsed);
    return true;
  };

  if (!multiprocess) {
    pid_out = 0;
    return parse_component(0U, text.size(), tid_out);
  }

  const size_t dot = text.find('.', first);
  if (dot == std::string::npos || text.find('.', dot + 1U) != std::string::npos) return false;
  return parse_component(first, dot, pid_out) && parse_component(dot + 1U, text.size(), tid_out);
}

std::string gdb_watchpoint_stop_field(
  uint64_t dr6, const std::vector<memdbg::frontend::Client::DebugWatchpointEntry> &entries) {
  const uint64_t hits = dr6 & 0xFULL;
  for (const auto &entry : entries) {
    if (!entry.installed || entry.slot >= 4U || (hits & (1ULL << entry.slot)) == 0U) { continue; }
    if (entry.type == 0U) return "hwbreak:;";
    const char *reason = entry.type == 1U ? "watch" : entry.type == 2U ? "rwatch" : "awatch";
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s:%llx;", reason,
                  static_cast<unsigned long long>(entry.address));
    return std::string(buf);
  }
  return std::string();
}

bool gdb_memory_range_mapped(const std::vector<memdbg::frontend::MapEntry> &maps, uint64_t address,
                             uint64_t length) {
  if (length == 0U) return true;
  if (address > std::numeric_limits<uint64_t>::max() - length) return false;

  const uint64_t request_end = address + length;
  uint64_t cursor = address;
  while (cursor < request_end) {
    uint64_t covered_end = cursor;
    for (const auto &map : maps) {
      if (map.start <= cursor && cursor < map.end && map.end > covered_end) {
        covered_end = map.end < request_end ? map.end : request_end;
      }
    }
    if (covered_end == cursor) return false;
    cursor = covered_end;
  }
  return true;
}

} // namespace memdbg::gdb_bridge

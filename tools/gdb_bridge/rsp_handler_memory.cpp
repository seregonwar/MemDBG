/*
 * MemDBG - GDB RSP memory packet handling.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rsp_handler.hpp"

#include "gdb_regs.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace memdbg::gdb_bridge {

using namespace detail;

std::string RspHandler::handle_memory_read(const std::string &packet) {
  /* maddr,length */
  if (!ensure_attached()) return err_packet(1);
  const size_t comma = packet.find(',');
  if (comma == std::string::npos) return err_packet(1);
  uint64_t addr = 0U;
  uint64_t length = 0U;
  if (!parse_hex_u64(packet, 1U, comma, addr)) return err_packet(1);
  if (!parse_hex_u64(packet, comma + 1U, packet.size(), length)) return err_packet(1);
  if (length == 0U) return std::string();
  if (length > kRspMaxMemory || addr > std::numeric_limits<uint64_t>::max() - length) {
    return err_packet(0x22);
  }
  if (memory_maps_known_ && !gdb_memory_range_mapped(memory_maps_, addr, length)) {
    logf("rejecting unmapped memory read addr=0x%llx length=0x%llx",
         static_cast<unsigned long long>(addr), static_cast<unsigned long long>(length));
    return err_packet(1);
  }

  std::string hex;
  hex.reserve(static_cast<size_t>(length) * 2U);
  uint64_t done = 0U;
  while (done < length) {
    uint32_t chunk = static_cast<uint32_t>(length - done);
    if (chunk > kMemChunk) chunk = kMemChunk;
    std::vector<uint8_t> data;
    if (!backend_.memory_read(pid_, addr + done, chunk, data) || data.size() != chunk) {
      return err_packet(1);
    }
    /* Restore the original instruction bytes over any software breakpoints the
     * bridge inserted, so IDA disassembles real code instead of 'db 0CCh'. */
    const uint64_t chunk_begin = addr + done;
    for (const auto &entry : sw_breakpoints_) {
      const uint64_t bp_addr = entry.first;
      if (bp_addr >= chunk_begin && bp_addr < chunk_begin + chunk) {
        data[static_cast<size_t>(bp_addr - chunk_begin)] = entry.second;
      }
    }
    hex += bytes_to_hex(data.data(), data.size());
    done += chunk;
  }
  return hex;
}

std::string RspHandler::handle_memory_write(const std::string &packet) {
  /* Maddr,length:XX... */
  if (!ensure_attached()) return err_packet(1);
  const size_t comma = packet.find(',');
  const size_t colon = packet.find(':');
  if (comma == std::string::npos || colon == std::string::npos || colon < comma)
    return err_packet(1);
  uint64_t addr = 0U;
  uint64_t length = 0U;
  if (!parse_hex_u64(packet, 1U, comma, addr)) return err_packet(1);
  if (!parse_hex_u64(packet, comma + 1U, colon, length)) return err_packet(1);
  if (length > kRspMaxMemory || addr > std::numeric_limits<uint64_t>::max() - length ||
      length > std::numeric_limits<size_t>::max() / 2U) {
    return err_packet(0x22);
  }
  if (memory_maps_known_ && !gdb_memory_range_mapped(memory_maps_, addr, length)) {
    return err_packet(1);
  }
  const std::string hex = packet.substr(colon + 1U);
  if (hex.size() != static_cast<size_t>(length) * 2U) return err_packet(1);
  std::vector<uint8_t> data(static_cast<size_t>(length));
  if (length > 0U && !hex_to_bytes(hex, data.data(), static_cast<size_t>(length))) {
    return err_packet(1);
  }
  uint32_t written = 0U;
  if (!backend_.memory_write(pid_, addr, data, written) ||
      written != static_cast<uint32_t>(length)) {
    return err_packet(1);
  }
  return "OK";
}

std::string RspHandler::handle_binary_memory_write(const std::string &packet) {
  /* Xaddr,length:<binary data>; RspConnection already unescaped it. */
  if (!ensure_attached()) return err_packet(1);
  const size_t comma = packet.find(',');
  const size_t colon = packet.find(':');
  if (comma == std::string::npos || colon == std::string::npos || comma <= 1U ||
      colon <= comma + 1U) {
    return err_packet(1);
  }
  uint64_t addr = 0U;
  uint64_t length = 0U;
  if (!parse_hex_u64(packet, 1U, comma, addr) ||
      !parse_hex_u64(packet, comma + 1U, colon, length)) {
    return err_packet(1);
  }
  if (length > kRspMaxMemory || addr > std::numeric_limits<uint64_t>::max() - length ||
      length > std::numeric_limits<size_t>::max()) {
    return err_packet(0x22);
  }
  if (memory_maps_known_ && !gdb_memory_range_mapped(memory_maps_, addr, length)) {
    return err_packet(1);
  }
  const size_t byte_length = static_cast<size_t>(length);
  if (packet.size() - colon - 1U != byte_length) return err_packet(1);
  std::vector<uint8_t> data(byte_length);
  if (byte_length > 0U) { std::memcpy(data.data(), packet.data() + colon + 1U, byte_length); }
  uint32_t written = 0U;
  if (!backend_.memory_write(pid_, addr, data, written) || written != byte_length) {
    return err_packet(1);
  }
  return "OK";
}

std::string RspHandler::handle_search_memory(const std::string &packet) {
  static constexpr const char *kPrefix = "qSearch:memory:";
  if (!ensure_attached() || packet.rfind(kPrefix, 0U) != 0U) return err_packet(1);
  const size_t begin = std::strlen(kPrefix);
  const size_t semi1 = packet.find(';', begin);
  const size_t semi2 =
    semi1 == std::string::npos ? std::string::npos : packet.find(';', semi1 + 1U);
  if (semi1 == std::string::npos || semi2 == std::string::npos) return err_packet(1);
  uint64_t address = 0U;
  uint64_t length = 0U;
  if (!parse_hex_u64(packet, begin, semi1, address) ||
      !parse_hex_u64(packet, semi1 + 1U, semi2, length) || length > 0x4000000U ||
      address > std::numeric_limits<uint64_t>::max() - length) {
    return err_packet(0x22);
  }
  const std::string pattern_text = packet.substr(semi2 + 1U);
  const std::vector<uint8_t> pattern(pattern_text.begin(), pattern_text.end());
  if (pattern.empty() || pattern.size() > 0x1000U || pattern.size() > length ||
      (memory_maps_known_ && !gdb_memory_range_mapped(memory_maps_, address, length))) {
    return pattern.size() > length ? "0" : err_packet(1);
  }

  const size_t overlap = pattern.size() - 1U;
  uint64_t cursor = address;
  std::vector<uint8_t> carry;
  while (cursor < address + length) {
    const uint32_t amount =
      static_cast<uint32_t>(std::min<uint64_t>(kMemChunk, address + length - cursor));
    std::vector<uint8_t> data;
    if (!backend_.memory_read(pid_, cursor, amount, data) || data.size() != amount) {
      return err_packet(1);
    }
    std::vector<uint8_t> window;
    window.reserve(carry.size() + data.size());
    window.insert(window.end(), carry.begin(), carry.end());
    window.insert(window.end(), data.begin(), data.end());
    const auto hit = std::search(window.begin(), window.end(), pattern.begin(), pattern.end());
    if (hit != window.end()) {
      const uint64_t base = cursor - carry.size();
      const uint64_t found = base + static_cast<uint64_t>(std::distance(window.begin(), hit));
      char reply[40];
      std::snprintf(reply, sizeof(reply), "1,%llx", static_cast<unsigned long long>(found));
      return std::string(reply);
    }
    const size_t keep = std::min(overlap, window.size());
    carry.assign(window.end() - static_cast<std::ptrdiff_t>(keep), window.end());
    cursor += amount;
  }
  return "0";
}

} // namespace memdbg::gdb_bridge

/*
 * MemDBG - Process-list wire compatibility helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_PROCESS_LIST_PARSER_HPP
#define MEMDBG_FRONTEND_PROCESS_LIST_PARSER_HPP

#include "memdbg_client.hpp"

#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace memdbg::frontend::detail {

/* v0.2.0 and older did not include ppid in process-list records. */
constexpr size_t kLegacyProcessEntrySize = sizeof(int32_t) + 48U;
static_assert(kLegacyProcessEntrySize == 52U,
              "legacy process record wire size changed");
static_assert(sizeof(memdbg_process_entry_t) == 56U,
              "current process record wire size changed");

inline std::string process_wire_string(const char *data, size_t size) {
  size_t len = 0;
  while (len < size && data[len] != '\0') {
    ++len;
  }
  return std::string(data, len);
}

inline bool parse_process_list_response(const std::vector<uint8_t> &response,
                                        std::vector<ProcessEntry> &out,
                                        std::string &error) {
  if (response.size() < sizeof(uint32_t)) {
    error = "short process list response";
    return false;
  }

  uint32_t count = 0;
  std::memcpy(&count, response.data(), sizeof(count));
  constexpr uint32_t kMaxEntries =
      (MEMDBG_PROTOCOL_MAX_PACKET - sizeof(uint32_t)) /
      kLegacyProcessEntrySize;
  if (count > kMaxEntries) {
    error = "process list response has an invalid item count";
    return false;
  }

  const size_t payload_size = response.size() - sizeof(count);
  const size_t current_size = sizeof(memdbg_process_entry_t);
  const size_t current_expected = static_cast<size_t>(count) * current_size;
  const size_t legacy_expected =
      static_cast<size_t>(count) * kLegacyProcessEntrySize;

  enum class WireFormat { Current, Legacy };
  WireFormat format;
  size_t stride = 0;
  if (payload_size == current_expected) {
    format = WireFormat::Current;
    stride = current_size;
  } else if (payload_size == legacy_expected) {
    format = WireFormat::Legacy;
    stride = kLegacyProcessEntrySize;
  } else {
    error = payload_size < current_expected && payload_size < legacy_expected
                ? "truncated process list response"
                : "process list response has an unsupported record size";
    return false;
  }

  std::vector<ProcessEntry> decoded;
  decoded.reserve(count);
  const uint8_t *cursor = response.data() + sizeof(count);
  for (uint32_t i = 0; i < count; ++i, cursor += stride) {
    ProcessEntry entry;
    if (format == WireFormat::Current) {
      memdbg_process_entry_t wire{};
      std::memcpy(&wire, cursor, sizeof(wire));
      entry.pid = wire.pid;
      entry.ppid = wire.ppid;
      entry.name = process_wire_string(wire.name, sizeof(wire.name));
    } else {
      std::memcpy(&entry.pid, cursor, sizeof(entry.pid));
      entry.ppid = 0;
      entry.name = process_wire_string(
          reinterpret_cast<const char *>(cursor + sizeof(entry.pid)), 48U);
    }

    if (entry.pid <= 0) {
      continue;
    }
    if (entry.name.empty()) {
      entry.name = "pid " + std::to_string(entry.pid);
    }
    decoded.push_back(std::move(entry));
  }

  out = std::move(decoded);
  error.clear();
  return true;
}

} // namespace memdbg::frontend::detail

#endif /* MEMDBG_FRONTEND_PROCESS_LIST_PARSER_HPP */

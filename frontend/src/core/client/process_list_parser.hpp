/*
 * MemDBG - Process-list wire compatibility helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_PROCESS_LIST_PARSER_HPP
#define MEMDBG_FRONTEND_PROCESS_LIST_PARSER_HPP

#include "memdbg_client.hpp"

#include <cstring>
#include <limits>
#include <string>
#include <unordered_set>
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

struct ProcessListCandidate {
  std::vector<ProcessEntry> entries;
  int score = std::numeric_limits<int>::min();
  bool complete = false;
};

inline bool process_name_is_plausible(const std::string &name) {
  if (name.empty()) return false;
  for (unsigned char ch : name) {
    if (ch < 0x20U || ch == 0x7fU) return false;
  }
  return true;
}

inline ProcessListCandidate decode_process_candidate(
    const uint8_t *payload, size_t payload_size, uint32_t declared_count,
    size_t stride, bool current) {
  ProcessListCandidate candidate;
  const size_t available_count = payload_size / stride;
  const size_t decode_count =
      std::min(static_cast<size_t>(declared_count), available_count);
  candidate.complete = decode_count == declared_count &&
                       payload_size == decode_count * stride;
  candidate.entries.reserve(decode_count);

  std::unordered_set<int32_t> seen_pids;
  int score = 0;
  for (size_t i = 0; i < decode_count; ++i) {
    const uint8_t *cursor = payload + i * stride;
    ProcessEntry entry;
    if (current) {
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
      score -= 6;
      continue;
    }
    /* Console PIDs are small, while host PIDs still remain well below this
       boundary. Values made from four filename bytes ("elf\0", "SceV", ...)
       are much larger and are a strong signal that the record stride is
       wrong. */
    score += entry.pid <= 0x00ffffff ? 3 : -8;
    score += seen_pids.insert(entry.pid).second ? 1 : -3;
    if (process_name_is_plausible(entry.name)) {
      score += 4;
    } else {
      score -= 4;
      if (entry.name.empty()) entry.name = "pid " + std::to_string(entry.pid);
    }
    candidate.entries.push_back(std::move(entry));
  }

  if (candidate.complete) score += 4;
  score += static_cast<int>(candidate.entries.size());
  candidate.score = score;
  return candidate;
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

  if (payload_size != current_expected && payload_size != legacy_expected) {
    error = payload_size < current_expected && payload_size < legacy_expected
                ? "truncated process list response"
                : "process list response has an unsupported record size";
    return false;
  }

  const uint8_t *payload = response.data() + sizeof(count);
  ProcessListCandidate current = decode_process_candidate(
      payload, payload_size, count, current_size, true);
  ProcessListCandidate legacy = decode_process_candidate(
      payload, payload_size, count, kLegacyProcessEntrySize, false);

  /* Some PS5 payload/front-end combinations advertise the legacy byte count
     but contain current 56-byte records. This used to turn filename chunks
     into giant PIDs on Windows. Decode both known layouts and prefer the
     structurally plausible result; a genuinely truncated, unrecognised byte
     count was rejected above and remains an error. */
  ProcessListCandidate &best =
      current.score > legacy.score ? current : legacy;
  if (best.entries.empty() && count != 0U) {
    error = "process list response did not contain valid records";
    return false;
  }

  out = std::move(best.entries);
  error.clear();
  return true;
}

} // namespace memdbg::frontend::detail

#endif /* MEMDBG_FRONTEND_PROCESS_LIST_PARSER_HPP */

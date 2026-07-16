/*
 * MemDBG - Deterministic bounded unknown-scan request planning.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "core/client/memdbg_client.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::frontend {

struct UnknownScanUnit {
  uint64_t start = 0U;
  uint64_t end = 0U;
};

inline bool build_unknown_scan_units(
    std::vector<MapEntry> maps, uint64_t filter_start, uint64_t filter_end,
    uint32_t value_size, uint64_t unit_budget,
    std::vector<UnknownScanUnit> &out, std::string &error) {
  out.clear();
  error.clear();
  if (value_size == 0U || unit_budget < value_size ||
      unit_budget > MEMDBG_SCAN_UNKNOWN_MAX_UNIT_BYTES) {
    error = "invalid unknown-scan unit budget";
    return false;
  }
  if (filter_end != 0U && filter_end <= filter_start) {
    error = "invalid unknown-scan address window";
    return false;
  }

  std::sort(maps.begin(), maps.end(), [](const MapEntry &a, const MapEntry &b) {
    return a.start < b.start || (a.start == b.start && a.end < b.end);
  });
  const uint64_t overlap = static_cast<uint64_t>(value_size - 1U);
  for (const MapEntry &map : maps) {
    if ((map.protection & MEMDBG_MAP_PROT_READ) == 0U ||
        map.end <= map.start)
      continue;
    uint64_t start = std::max(map.start, filter_start);
    uint64_t end = map.end;
    if (filter_end != 0U) end = std::min(end, filter_end);
    if (end <= start || end - start < value_size) continue;

    uint64_t cursor = start;
    while (end - cursor >= value_size) {
      uint64_t unit_end = end;
      if (unit_budget < end - cursor)
        unit_end = cursor + unit_budget;
      out.push_back({cursor, unit_end});
      if (unit_end == end) break;
      uint64_t next = unit_end - overlap;
      if (next <= cursor) {
        error = "unknown-scan unit planning did not advance";
        out.clear();
        return false;
      }
      cursor = next;
    }
  }
  return true;
}

} // namespace memdbg::frontend

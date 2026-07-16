/*
 * MemDBG - Filter-aware memory-map selection helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_MAP_SELECTION_HPP
#define MEMDBG_FRONTEND_MAP_SELECTION_HPP

#include "core/client/memdbg_client.hpp"

#include <cstdint>
#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_set>
#include <vector>

namespace memdbg::frontend::detail {

inline bool map_matches_name_or_type(const MapEntry &map,
                                     std::string filter) {
  std::transform(filter.begin(), filter.end(), filter.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  std::string metadata = map.name + " " + map.type;
  std::transform(metadata.begin(), metadata.end(), metadata.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return metadata.find(filter) != std::string::npos;
}

template <typename Predicate>
void replace_map_selection_with_filtered(
    const std::vector<MapEntry> &maps,
    std::unordered_set<uint64_t> &selected_starts,
    Predicate passes_filter) {
  selected_starts.clear();
  for (const MapEntry &map : maps) {
    if (passes_filter(map)) selected_starts.insert(map.start);
  }
}

inline uint32_t complete_protection_mask(
    const std::vector<MapEntry> &maps,
    const std::unordered_set<uint64_t> &selected_starts) {
  if (selected_starts.empty()) return 0U;
  for (uint32_t mask = 7U; mask > 0U; --mask) {
    size_t matching = 0U;
    bool exact = true;
    for (const MapEntry &map : maps) {
      if (map.end <= map.start || (map.protection & mask) != mask) continue;
      matching++;
      if (selected_starts.count(map.start) == 0U) {
        exact = false;
        break;
      }
    }
    if (exact && matching == selected_starts.size()) return mask;
  }
  return 0U;
}

} // namespace memdbg::frontend::detail

#endif /* MEMDBG_FRONTEND_MAP_SELECTION_HPP */

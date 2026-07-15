/*
 * MemDBG - Platform utility helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared utilities for console platform identification.  All callers that
 * need to translate a platform index to a filter string should include this
 * header directly rather than pulling in the full PayloadFetcher class.
 */

#ifndef MEMDBG_FRONTEND_PLATFORM_UTILS_HPP
#define MEMDBG_FRONTEND_PLATFORM_UTILS_HPP

#include <algorithm>
#include <cctype>
#include <string>

namespace memdbg::frontend {

/* Convert a platform index (0=Auto, 1=PS4, 2=PS5) to the filter
 * string used by PayloadFetcher::set_platform().  Indices are clamped to [0,2]. */
inline const char *payload_platform_filter(int idx) {
  static const char *platforms[] = {"", "ps4", "ps5"};
  if (idx < 0) idx = 0;
  if (idx > 2) idx = 2;
  return platforms[idx];
}

/* Score a release asset for payload download.  Only the canonical executable
 * names are accepted, so libraries and frontend archives cannot be selected by
 * a broad substring match.  Auto mode prefers PS5 but falls back to PS4. */
inline int payload_asset_score(std::string name, std::string platform,
                               std::string asset_filter = {}) {
  auto lower = [](std::string &value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                     return static_cast<char>(std::tolower(c));
                   });
  };
  lower(name);
  lower(platform);
  lower(asset_filter);

  if (!asset_filter.empty() && name.find(asset_filter) == std::string::npos)
    return 0;
  if (name != "memdbg-ps4.elf" && name != "memdbg-ps5.elf") return 0;
  if (platform == "ps4") return name == "memdbg-ps4.elf" ? 100 : 0;
  if (platform == "ps5") return name == "memdbg-ps5.elf" ? 100 : 0;
  if (!platform.empty()) return 0;
  return name == "memdbg-ps5.elf" ? 20 : 10;
}

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_PLATFORM_UTILS_HPP */

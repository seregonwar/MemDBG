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

namespace memdbg::frontend {

/* Convert a platform index (0=Auto, 1=PS4, 2=PS5, 3=PS6) to the filter
 * string used by PayloadFetcher::set_platform().  Indices are clamped to [0,3]. */
inline const char *payload_platform_filter(int idx) {
  static const char *platforms[] = {"", "ps4", "ps5", "ps6"};
  if (idx < 0) idx = 0;
  if (idx > 3) idx = 3;
  return platforms[idx];
}

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_PLATFORM_UTILS_HPP */

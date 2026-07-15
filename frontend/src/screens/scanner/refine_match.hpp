/*
 * MemDBG - Pure scan refinement matching helper.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "app_state.hpp"

namespace memdbg::frontend {

inline bool scan_refine_match(
    int type, RefineMode mode, const std::vector<uint8_t> &old_bytes,
    const std::vector<uint8_t> &new_bytes,
    const std::vector<uint8_t> &target_bytes = {}) {
  const bool same = old_bytes == new_bytes;
  switch (mode) {
  case RefineMode::ExactValue:
    return new_bytes == target_bytes;
  case RefineMode::Changed:
    return !same;
  case RefineMode::Unchanged:
    return same;
  case RefineMode::Increased:
  case RefineMode::Decreased: {
    long double old_value = 0.0;
    long double new_value = 0.0;
    if (!bytes_to_number(type, old_bytes, old_value) ||
        !bytes_to_number(type, new_bytes, new_value)) {
      return false;
    }
    return mode == RefineMode::Increased ? new_value > old_value
                                         : new_value < old_value;
  }
  }
  return false;
}

} // namespace memdbg::frontend

/*
 * MemDBG - Scanner helpers (value length, refine matching, batch read check).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scanner_internal.hpp"

namespace memdbg::frontend {

uint32_t current_scan_value_len(const AppState &state) {
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!build_scan_value(state.scan_type, state.scan_value, value, value_len)) {
    switch (state.scan_type) {
    case MEMDBG_VALUE_U8:  return 1U;
    case MEMDBG_VALUE_U16: return 2U;
    case MEMDBG_VALUE_U32: case MEMDBG_VALUE_F32: return 4U;
    case MEMDBG_VALUE_U64: case MEMDBG_VALUE_F64: case MEMDBG_VALUE_POINTER: return 8U;
    default: return 1U;
    }
  }
  return value_len;
}

bool scan_refine_match(int type, RefineMode mode, const std::vector<uint8_t> &old_bytes, const std::vector<uint8_t> &new_bytes) {
  const bool same = old_bytes == new_bytes;
  switch (mode) {
  case RefineMode::Changed:   return !same;
  case RefineMode::Unchanged: return same;
  case RefineMode::Increased:
  case RefineMode::Decreased: {
    long double old_value=0.0, new_value=0.0;
    if (!bytes_to_number(type,old_bytes,old_value)||!bytes_to_number(type,new_bytes,new_value)) return false;
    return mode==RefineMode::Increased ? new_value>old_value : new_value<old_value;
  }}
  return false;
}

const char *refine_mode_name(RefineMode mode) {
  switch (mode) {
  case RefineMode::Changed: return "Changed";
  case RefineMode::Unchanged: return "Unchanged";
  case RefineMode::Increased: return "Increased";
  case RefineMode::Decreased: return "Decreased";
  }
  return "Refine";
}

bool has_batch_read(const AppState &state) {
  return (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;
}

} // namespace memdbg::frontend

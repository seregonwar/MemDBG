/*
 * MemDBG - Scanner module internal shared declarations.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "confirm_modal.hpp"
#include "scanner/heuristics/auto_search.hpp"
#include "scanner/structure_compare.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <future>
#include <limits>
#include <mutex>
#include <utility>

namespace memdbg::frontend {

/* ---- Scan helpers ---- */
uint32_t current_scan_value_len(const AppState &state);
bool scan_refine_match(int type, RefineMode mode, const std::vector<uint8_t> &old_bytes, const std::vector<uint8_t> &new_bytes);
const char *refine_mode_name(RefineMode mode);
bool has_batch_read(const AppState &state);

/* ---- Structure Compare ---- */
uint32_t structure_field_width(int value_type);
std::string structure_field_value(const std::vector<uint8_t> &bytes, int value_type);
const char *structure_relation_name(StructureFieldRelation relation);
ImVec4 structure_relation_color(StructureFieldRelation relation);
void poll_structure_compare(AppState &state);
void start_structure_compare(AppState &state);

/* ---- Scan session ---- */
void capture_scan_snapshot(AppState &state);
void refine_scan(AppState &state, RefineMode mode);

/* ---- Async scan poll + launchers ---- */
void poll_scanner_async(AppState &state);
void scan_range(AppState &state);
void scan_selected_maps(AppState &state);
void scan_process(AppState &state);
void scan_unknown_process(AppState &state);

} // namespace memdbg::frontend

/*
 * MemDBG - Structure comparison engine integration.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scanner_internal.hpp"

#include <chrono>
#include <exception>
#include <future>
#include <mutex>

namespace memdbg::frontend {

uint32_t structure_field_width(int value_type) {
  switch (value_type) {
  case MEMDBG_VALUE_U8:
    return 1U;
  case MEMDBG_VALUE_U16:
    return 2U;
  case MEMDBG_VALUE_U32:
  case MEMDBG_VALUE_F32:
    return 4U;
  case MEMDBG_VALUE_U64:
  case MEMDBG_VALUE_F64:
  case MEMDBG_VALUE_POINTER:
    return 8U;
  default:
    return 0U;
  }
}

std::string structure_field_value(const std::vector<uint8_t> &bytes,
                                   int value_type) {
  char value[64] = {};
  switch (value_type) {
  case MEMDBG_VALUE_U8:
    if (bytes.size() >= sizeof(uint8_t))
      std::snprintf(value, sizeof(value), "%u", static_cast<unsigned>(read_scalar<uint8_t>(bytes)));
    break;
  case MEMDBG_VALUE_U16:
    if (bytes.size() >= sizeof(uint16_t))
      std::snprintf(value, sizeof(value), "%u", static_cast<unsigned>(read_scalar<uint16_t>(bytes)));
    break;
  case MEMDBG_VALUE_U32:
    if (bytes.size() >= sizeof(uint32_t))
      std::snprintf(value, sizeof(value), "%u", read_scalar<uint32_t>(bytes));
    break;
  case MEMDBG_VALUE_U64:
    if (bytes.size() >= sizeof(uint64_t))
      std::snprintf(value, sizeof(value), "%llu",
                    static_cast<unsigned long long>(read_scalar<uint64_t>(bytes)));
    break;
  case MEMDBG_VALUE_POINTER:
    if (bytes.size() >= sizeof(uint64_t))
      return hex_u64(read_scalar<uint64_t>(bytes));
    break;
  case MEMDBG_VALUE_F32:
    if (bytes.size() >= sizeof(float))
      std::snprintf(value, sizeof(value), "%.6g", static_cast<double>(read_scalar<float>(bytes)));
    break;
  case MEMDBG_VALUE_F64:
    if (bytes.size() >= sizeof(double))
      std::snprintf(value, sizeof(value), "%.12g", read_scalar<double>(bytes));
    break;
  default:
    break;
  }
  return value[0] == '\0' ? "?" : std::string(value);
}

const char *structure_relation_name(StructureFieldRelation relation) {
  switch (relation) {
  case StructureFieldRelation::Common:
    return "Common";
  case StructureFieldRelation::PlayerVsEnemies:
    return "Player vs enemies";
  case StructureFieldRelation::EnemyAOutlier:
    return "Enemy A outlier";
  case StructureFieldRelation::EnemyBOutlier:
    return "Enemy B outlier";
  case StructureFieldRelation::AllDifferent:
    return "All different";
  case StructureFieldRelation::Different:
    return "Different";
  }
  return "Unknown";
}

ImVec4 structure_relation_color(StructureFieldRelation relation) {
  switch (relation) {
  case StructureFieldRelation::PlayerVsEnemies:
    return ui::colors().success;
  case StructureFieldRelation::Common:
    return ui::colors().dim;
  case StructureFieldRelation::EnemyAOutlier:
  case StructureFieldRelation::EnemyBOutlier:
    return ui::colors().warning;
  case StructureFieldRelation::AllDifferent:
  case StructureFieldRelation::Different:
    return ui::colors().muted;
  }
  return ui::colors().muted;
}

void poll_structure_compare(AppState &state) {
  if (!state.structure_compare_pending || !state.structure_compare_future.valid()) return;
  if (state.structure_compare_future.wait_for(std::chrono::milliseconds(0)) !=
      std::future_status::ready) return;

  state.structure_compare_pending = false;
  bool ok = false;
  try {
    ok = state.structure_compare_future.get();
  } catch (const std::exception &ex) {
    state.structure_compare_error = ex.what();
  } catch (...) {
    state.structure_compare_error = "Unknown structure comparison error";
  }

  std::lock_guard<std::mutex> lock(state.structure_compare_mtx);
  if (!ok) {
    const std::string error = state.structure_compare_error.empty()
        ? "Structure comparison failed" : state.structure_compare_error;
    std::snprintf(state.structure_compare_status, sizeof(state.structure_compare_status),
                  "%s", error.c_str());
    set_status(state, error);
    push_notification(state, error, 5.0);
    state.structure_compare_error.clear();
    return;
  }

  state.structure_compare_fields = std::move(state.structure_compare_temp_fields);
  std::snprintf(state.structure_compare_status, sizeof(state.structure_compare_status),
                "Compared %zu fields", state.structure_compare_fields.size());
  set_status(state, state.structure_compare_status);
  char sc_buf[256]; std::snprintf(sc_buf, sizeof(sc_buf), locale::tr("scanner.structure_compare_complete"), state.structure_compare_fields.size()); push_notification(state, sc_buf);
}

void start_structure_compare(AppState &state) {
  constexpr int kMaxStructureBytes = 64 * 1024;
  if (state.structure_compare_pending) return;
  if (!state.client.connected()) {
    set_status(state, locale::tr("scanner.structure_compare.connect_first"));
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, locale::tr("scanner.structure_compare.select_process_first"));
    return;
  }
  if (!payload_supports(state, MEMDBG_CAP_MEMORY_READ)) {
    set_status(state, locale::tr("scanner.structure_compare.no_mem_reads"));
    return;
  }

  uint64_t player_base = 0U;
  uint64_t enemy_a_base = 0U;
  uint64_t enemy_b_base = 0U;
  if (!parse_u64(state.structure_player_base, player_base) || player_base == 0U ||
      !parse_u64(state.structure_enemy_a_base, enemy_a_base) || enemy_a_base == 0U ||
      (state.structure_compare_has_enemy_b &&
       (!parse_u64(state.structure_enemy_b_base, enemy_b_base) || enemy_b_base == 0U))) {
    set_status(state, locale::tr("scanner.structure_compare.invalid_addresses"));
    return;
  }

  const uint32_t field_width = structure_field_width(state.structure_compare_type);
  if (field_width == 0U || state.structure_compare_size < static_cast<int>(field_width) ||
      state.structure_compare_size > kMaxStructureBytes ||
      static_cast<uint32_t>(state.structure_compare_size) % field_width != 0U) {
    set_status(state, locale::tr("scanner.structure_compare.invalid_size"));
    return;
  }

  const int32_t pid = state.selected_pid;
  const uint32_t read_size = static_cast<uint32_t>(state.structure_compare_size);
  const bool has_enemy_b = state.structure_compare_has_enemy_b;
  auto &client = state.client;
  auto &temp_fields = state.structure_compare_temp_fields;
  auto &error_out = state.structure_compare_error;
  state.structure_compare_pending = true;
  state.structure_compare_start_time = ImGui::GetTime();
  std::snprintf(state.structure_compare_status, sizeof(state.structure_compare_status),
                "Reading player and enemy structures...");

  state.structure_compare_future = std::async(
      std::launch::async,
      [&client, pid, player_base, enemy_a_base, enemy_b_base, read_size,
       field_width, has_enemy_b, &temp_fields, &error_out,
       &mtx = state.structure_compare_mtx]() -> bool {
        std::vector<uint8_t> player;
        std::vector<uint8_t> enemy_a;
        std::vector<uint8_t> enemy_b;
        if (!client.memory_read(pid, player_base, read_size, player) ||
            player.size() != read_size) {
          error_out = "Could not read player structure: " + client.last_error();
          return false;
        }
        if (!client.memory_read(pid, enemy_a_base, read_size, enemy_a) ||
            enemy_a.size() != read_size) {
          error_out = "Could not read enemy A structure: " + client.last_error();
          return false;
        }
        if (has_enemy_b &&
            (!client.memory_read(pid, enemy_b_base, read_size, enemy_b) ||
             enemy_b.size() != read_size)) {
          error_out = "Could not read enemy B structure: " + client.last_error();
          return false;
        }

        auto fields = StructureCompareEngine::compare(player, enemy_a, enemy_b, field_width);
        if (fields.empty()) {
          error_out = "Could not split the captured structures into fields";
          return false;
        }

        std::lock_guard<std::mutex> lock(mtx);
        temp_fields = std::move(fields);
        return true;
      });
}

} // namespace memdbg::frontend

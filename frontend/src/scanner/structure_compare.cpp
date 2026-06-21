/*
 * MemDBG - Structure comparison engine.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "structure_compare.hpp"

namespace memdbg::frontend {

std::vector<StructureCompareField> StructureCompareEngine::compare(
    const std::vector<uint8_t> &player,
    const std::vector<uint8_t> &enemy_a,
    const std::vector<uint8_t> &enemy_b,
    uint32_t field_width) {
  std::vector<StructureCompareField> fields;
  const bool has_enemy_b = !enemy_b.empty();

  if (field_width == 0U || player.empty() || player.size() != enemy_a.size() ||
      (has_enemy_b && player.size() != enemy_b.size()) ||
      player.size() % field_width != 0U) {
    return fields;
  }

  fields.reserve(player.size() / field_width);
  for (size_t offset = 0U; offset + field_width <= player.size();
       offset += field_width) {
    StructureCompareField field;
    field.offset = static_cast<uint32_t>(offset);
    field.player.assign(player.begin() + static_cast<std::ptrdiff_t>(offset),
                        player.begin() + static_cast<std::ptrdiff_t>(offset + field_width));
    field.enemy_a.assign(enemy_a.begin() + static_cast<std::ptrdiff_t>(offset),
                         enemy_a.begin() + static_cast<std::ptrdiff_t>(offset + field_width));

    const bool player_eq_a = field.player == field.enemy_a;
    if (!has_enemy_b) {
      field.relation = player_eq_a ? StructureFieldRelation::Common
                                   : StructureFieldRelation::Different;
      fields.push_back(std::move(field));
      continue;
    }

    field.enemy_b.assign(enemy_b.begin() + static_cast<std::ptrdiff_t>(offset),
                         enemy_b.begin() + static_cast<std::ptrdiff_t>(offset + field_width));
    const bool player_eq_b = field.player == field.enemy_b;
    const bool enemies_match = field.enemy_a == field.enemy_b;
    if (player_eq_a && enemies_match) {
      field.relation = StructureFieldRelation::Common;
    } else if (enemies_match) {
      field.relation = StructureFieldRelation::PlayerVsEnemies;
    } else if (player_eq_a) {
      field.relation = StructureFieldRelation::EnemyBOutlier;
    } else if (player_eq_b) {
      field.relation = StructureFieldRelation::EnemyAOutlier;
    } else {
      field.relation = StructureFieldRelation::AllDifferent;
    }
    fields.push_back(std::move(field));
  }

  return fields;
}

} // namespace memdbg::frontend

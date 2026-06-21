/*
 * MemDBG - Structure comparison engine.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_SCANNER_STRUCTURE_COMPARE_HPP
#define MEMDBG_FRONTEND_SCANNER_STRUCTURE_COMPARE_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace memdbg::frontend {

/*
 * A three-way comparison is deliberately used when possible.  A field where
 * both enemy samples match but the player sample differs is much less likely
 * to be a per-instance value such as health or position.
 */
enum class StructureFieldRelation {
  Common,
  PlayerVsEnemies,
  EnemyAOutlier,
  EnemyBOutlier,
  AllDifferent,
  Different,
};

struct StructureCompareField {
  uint32_t offset = 0U;
  std::vector<uint8_t> player;
  std::vector<uint8_t> enemy_a;
  std::vector<uint8_t> enemy_b;
  StructureFieldRelation relation = StructureFieldRelation::Common;
};

class StructureCompareEngine {
public:
  /* Split equally-sized snapshots into fields of field_width bytes and label
   * the relationship at each offset.  An empty enemy_b makes this a two-way
   * comparison.  Invalid inputs return no fields. */
  static std::vector<StructureCompareField> compare(
      const std::vector<uint8_t> &player,
      const std::vector<uint8_t> &enemy_a,
      const std::vector<uint8_t> &enemy_b,
      uint32_t field_width);
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_SCANNER_STRUCTURE_COMPARE_HPP */

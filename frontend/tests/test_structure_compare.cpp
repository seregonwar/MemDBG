/*
 * MemDBG - Structure comparison engine tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scanner/structure_compare.hpp"

#include <cstdio>
#include <vector>

namespace memdbg::frontend {
namespace {

int g_failed = 0;

#define TEST(name, expression)                                                \
  do {                                                                         \
    if (expression) {                                                          \
      std::printf("  PASS  %s\n", name);                                      \
    } else {                                                                   \
      ++g_failed;                                                              \
      std::printf("  FAIL  %s\n", name);                                      \
    }                                                                          \
  } while (0)

void test_three_way_classification() {
  std::printf("\n--- Three-way structure comparison ---\n");
  const std::vector<uint8_t> player = {1U, 9U, 4U, 7U, 8U};
  const std::vector<uint8_t> enemy_a = {1U, 2U, 4U, 6U, 5U};
  const std::vector<uint8_t> enemy_b = {1U, 2U, 3U, 7U, 0U};

  const auto fields = StructureCompareEngine::compare(player, enemy_a, enemy_b, 1U);
  TEST("one field per byte", fields.size() == 5U);
  if (fields.size() != 5U) return;
  TEST("common field is recognised", fields[0].relation == StructureFieldRelation::Common);
  TEST("player differs while enemies agree", fields[1].relation == StructureFieldRelation::PlayerVsEnemies);
  TEST("enemy B outlier is recognised", fields[2].relation == StructureFieldRelation::EnemyBOutlier);
  TEST("enemy A outlier is recognised", fields[3].relation == StructureFieldRelation::EnemyAOutlier);
  TEST("all different field is recognised", fields[4].relation == StructureFieldRelation::AllDifferent);
}

void test_two_way_and_invalid_inputs() {
  std::printf("\n--- Two-way and input validation ---\n");
  const std::vector<uint8_t> player = {1U, 2U, 3U, 4U};
  const std::vector<uint8_t> enemy = {1U, 8U, 3U, 5U};
  const std::vector<uint8_t> empty;

  const auto fields = StructureCompareEngine::compare(player, enemy, empty, 2U);
  TEST("two fields at u16 width", fields.size() == 2U);
  if (fields.size() == 2U) {
    TEST("different two-way field", fields[0].relation == StructureFieldRelation::Different);
    TEST("different second two-way field", fields[1].relation == StructureFieldRelation::Different);
  }

  const std::vector<uint8_t> short_enemy = {1U, 2U};
  TEST("mismatched snapshots are rejected",
       StructureCompareEngine::compare(player, short_enemy, empty, 1U).empty());
  TEST("zero field width is rejected",
       StructureCompareEngine::compare(player, enemy, empty, 0U).empty());
  TEST("partial trailing field is rejected",
       StructureCompareEngine::compare(player, enemy, empty, 3U).empty());
}

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;
  test_three_way_classification();
  test_two_way_and_invalid_inputs();
  std::printf("\n%d failure(s)\n", g_failed);
  return g_failed == 0 ? 0 : 1;
}

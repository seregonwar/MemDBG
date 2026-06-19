/*
 * MemDBG - Auto-search engine tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scanner/heuristics/auto_search.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace memdbg::frontend {
namespace {

/* ---- Test helpers ---- */

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                      \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s\n", name);                                      \
    }                                                                          \
  } while (0)

#define TEST_EQ(name, actual, expected)                                        \
  do {                                                                         \
    auto _a = (actual);                                                        \
    auto _e = (expected);                                                      \
    if (_a == _e) {                                                            \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                      \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s  (got %g, expected %g)\n", name,               \
                  (double)_a, (double)_e);                                     \
    }                                                                          \
  } while (0)

#define TEST_GT(name, actual, threshold)                                       \
  do {                                                                         \
    auto _a = (actual);                                                        \
    if (_a > (threshold)) {                                                    \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                      \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s  (got %g, expected > %g)\n", name,             \
                  (double)_a, (double)(threshold));                            \
    }                                                                          \
  } while (0)

#define TEST_LT(name, actual, threshold)                                       \
  do {                                                                         \
    auto _a = (actual);                                                        \
    if (_a < (threshold)) {                                                    \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                      \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s  (got %g, expected < %g)\n", name,             \
                  (double)_a, (double)(threshold));                            \
    }                                                                          \
  } while (0)

#define TEST_FLAG(name, flags, flag_bit)                                       \
  do {                                                                         \
    if ((flags) & (flag_bit)) {                                                \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                      \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s  (flag 0x%X not set in 0x%X)\n", name,         \
                  (unsigned)(flag_bit), (unsigned)(flags));                    \
    }                                                                          \
  } while (0)

#define TEST_NOFLAG(name, flags, flag_bit)                                     \
  do {                                                                         \
    if (!((flags) & (flag_bit))) {                                             \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                      \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s  (flag 0x%X unexpectedly set)\n", name,         \
                  (unsigned)(flag_bit));                                       \
    }                                                                          \
  } while (0)

/* Build a ScanSnapshotEntry from a known uint32_t value at an aligned address. */
static ScanSnapshotEntry make_u32(uint64_t address, uint32_t value) {
  ScanSnapshotEntry e;
  e.address = address;
  e.bytes.resize(sizeof(value));
  std::memcpy(e.bytes.data(), &value, sizeof(value));
  return e;
}

static ScanSnapshotEntry make_f32(uint64_t address, float value) {
  ScanSnapshotEntry e;
  e.address = address;
  e.bytes.resize(sizeof(value));
  std::memcpy(e.bytes.data(), &value, sizeof(value));
  return e;
}

static ScanSnapshotEntry make_u8(uint64_t address, uint8_t value) {
  ScanSnapshotEntry e;
  e.address = address;
  e.bytes.resize(sizeof(value));
  std::memcpy(e.bytes.data(), &value, sizeof(value));
  return e;
}

/* ---- Health scoring tests ---- */

static void test_health_decreased() {
  std::printf("\n--- Health: decreased (took damage) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x1000, 100));  /* u32 health */

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x1000, 85));  /* took 15 damage */

  auto results = engine.score_candidates(current, 10);
  TEST("decreased health yields at least one candidate", results.size() >= 1U);

  if (!results.empty()) {
    const auto &c = results[0];
    TEST_EQ("address preserved", c.address, 0x1000ULL);
    TEST_GT("score positive", c.score, 0.0f);
    TEST_GT("score >= 0.5 for clear decrease", c.score, 0.5f);
    TEST_EQ("old value correct", c.old_value, 100.0);
    TEST_EQ("new value correct", c.new_value, 85.0);
    TEST_FLAG("decreased flag set", c.matched_flags, kFlagDecreased);
    TEST_FLAG("non-zero flag", c.matched_flags, kFlagNonZero);
    TEST_FLAG("integer type flag", c.matched_flags, kFlagIntegerType);
  }
}

static void test_health_unchanged_zero_score() {
  std::printf("\n--- Health: unchanged (zero score) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x1000, 100));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x1000, 100));  /* unchanged */

  auto results = engine.score_candidates(current, 10);
  TEST_EQ("unchanged health yields no candidates", results.size(), 0U);
}

static void test_health_zero_value() {
  std::printf("\n--- Health: zero value (dead) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x2000, 50));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x2000, 0));  /* dead — new health is 0 */

  auto results = engine.score_candidates(current, 10);
  /* 50→0: decreased yes, but new_val > 0 is false, so NonZero flag absent.
   * Range check for u32 is 1–9999, 0 is out of range.
   * Still gets Decreased + IntegerType.
   * Score = (1.0 + 0.4) / 2 = 0.7 */
  TEST("zero health yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    TEST("zero health still scores (decreased)", c.score > 0.0f);
    TEST_EQ("old = 50", c.old_value, 50.0);
    TEST_EQ("new = 0", c.new_value, 0.0);
    TEST_FLAG("decreased", c.matched_flags, kFlagDecreased);
    TEST_NOFLAG("not non-zero", c.matched_flags, kFlagNonZero);
  }
}

static void test_health_huge_decrease_skips_small_delta() {
  std::printf("\n--- Health: huge decrease (>50%%) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x3000, 100));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x3000, 10));  /* -90% */

  auto results = engine.score_candidates(current, 10);
  TEST("huge decrease yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    TEST_GT("huge decrease still scores", c.score, 0.0f);
    TEST_FLAG("decreased", c.matched_flags, kFlagDecreased);
    /* delta/old = 0.9 > 0.5, so SmallDelta NOT set */
    TEST_NOFLAG("no small delta for >50%", c.matched_flags, kFlagSmallDelta);
  }
}

static void test_health_float_format() {
  std::printf("\n--- Health: float value decreased ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_f32(0x4000, 100.0f));

  engine.set_baseline(baseline, MEMDBG_VALUE_F32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_f32(0x4000, 85.5f));

  auto results = engine.score_candidates(current, 10);
  TEST("float health yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    TEST_GT("float health scores", c.score, 0.0f);
    TEST_FLAG("decreased", c.matched_flags, kFlagDecreased);
  }
}

/* ---- Ammo scoring tests ---- */

static void test_ammo_one_shot() {
  std::printf("\n--- Ammo: fired one shot (30→29) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Ammo);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x5000, 30));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x5000, 29));  /* -1 shot */

  auto results = engine.score_candidates(current, 10);
  TEST("ammo one shot yields candidate", results.size() >= 1U);

  if (!results.empty()) {
    const auto &c = results[0];
    TEST_GT("high score for 1-shot decrease", c.score, 0.6f);
    TEST_FLAG("decreased", c.matched_flags, kFlagDecreased);
    TEST_FLAG("small delta", c.matched_flags, kFlagSmallDelta);
    TEST_FLAG("integer type", c.matched_flags, kFlagIntegerType);
  }
}

static void test_ammo_unchanged_zero_score() {
  std::printf("\n--- Ammo: unchanged ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Ammo);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x5000, 30));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x5000, 30));  /* unchanged */

  auto results = engine.score_candidates(current, 10);
  TEST_EQ("unchanged ammo yields no candidates", results.size(), 0U);
}

static void test_ammo_burst_fire() {
  std::printf("\n--- Ammo: burst fire (-5) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Ammo);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x5000, 100));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x5000, 95));  /* -5 (in range 1–30) */

  auto results = engine.score_candidates(current, 10);
  TEST("burst fire yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    TEST_GT("burst fire scores", c.score, 0.4f);
    TEST_FLAG("decreased", c.matched_flags, kFlagDecreased);
    TEST_FLAG("small delta", c.matched_flags, kFlagSmallDelta);
  }
}

static void test_ammo_huge_drop_no_decrease_bonus() {
  std::printf("\n--- Ammo: huge drop (delta=35 > 30) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Ammo);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x5000, 100));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x5000, 65));  /* -35, exceeds 30 limit */

  auto results = engine.score_candidates(current, 10);
  TEST("huge drop yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    /* Still scores via small range + integer + non-zero, but no decrease+smalldelta bonus */
    TEST_GT("still scores", c.score, 0.0f);
    TEST_NOFLAG("no decreased flag (delta>30)", c.matched_flags, kFlagDecreased);
    TEST_FLAG("small range", c.matched_flags, kFlagReasonableRange);
  }
}

static void test_ammo_u8_format() {
  std::printf("\n--- Ammo: u8 value (200→199) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Ammo);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u8(0x6000, 200));

  engine.set_baseline(baseline, MEMDBG_VALUE_U8, 1U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u8(0x6000, 199));  /* -1, within u8 range (<=200) */

  auto results = engine.score_candidates(current, 10);
  TEST("u8 ammo yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    TEST_GT("u8 ammo scores", c.score, 0.4f);
    TEST_FLAG("decreased", c.matched_flags, kFlagDecreased);
  }
}

/* ---- Resources scoring tests ---- */

static void test_resources_increased() {
  std::printf("\n--- Resources: increased (collected) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Resources);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x7000, 10));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x7000, 25));

  auto results = engine.score_candidates(current, 10);
  TEST("resources increase yields candidate", results.size() >= 1U);

  if (!results.empty()) {
    const auto &c = results[0];
    TEST_GT("score positive", c.score, 0.0f);
    TEST_GT("good score for clear increase", c.score, 0.5f);
    TEST_EQ("old value", c.old_value, 10.0);
    TEST_EQ("new value", c.new_value, 25.0);
    TEST_FLAG("increased", c.matched_flags, kFlagIncreased);
    TEST_FLAG("small delta (ratio 1.5 < 50)", c.matched_flags, kFlagSmallDelta);
    TEST_FLAG("reasonable range", c.matched_flags, kFlagReasonableRange);
    TEST_FLAG("non-zero", c.matched_flags, kFlagNonZero);
  }
}

static void test_resources_decreased() {
  std::printf("\n--- Resources: decreased (spent) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Resources);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x7000, 100));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x7000, 80));

  auto results = engine.score_candidates(current, 10);
  TEST("resources decrease yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    TEST_GT("resources decrease scores", c.score, 0.4f);
    TEST_FLAG("decreased flag", c.matched_flags, kFlagDecreased);
    TEST_NOFLAG("no increased flag", c.matched_flags, kFlagIncreased);
  }
}

static void test_resources_unchanged_zero_score() {
  std::printf("\n--- Resources: unchanged ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Resources);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x7000, 50));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x7000, 50));

  auto results = engine.score_candidates(current, 10);
  TEST_EQ("unchanged resources yields no candidates", results.size(), 0U);
}

/* ---- Score candidates pipeline tests ---- */

static void test_candidates_ranking() {
  std::printf("\n--- Candidates: ranking by score ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x1000, 100));  /* will decrease → high score */
  baseline.push_back(make_u32(0x2000, 50));   /* will decrease → high score */
  baseline.push_back(make_u32(0x3000, 30));   /* unchanged → zero score, excluded */

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x1000, 70));  /* -30, significant */
  current.push_back(make_u32(0x2000, 48));  /* -2, small */
  current.push_back(make_u32(0x3000, 30));  /* unchanged */

  auto results = engine.score_candidates(current, 50);
  TEST_EQ("only changed entries returned", results.size(), 2U);

  if (results.size() >= 2U) {
    /* 0x1000 (100→70) should score higher than 0x2000 (50→48) */
    TEST("first candidate highest score",
         results[0].score >= results[1].score);
  }
}

static void test_max_results_limit() {
  std::printf("\n--- Candidates: max_results limit ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Ammo);

  std::vector<ScanSnapshotEntry> baseline;
  std::vector<ScanSnapshotEntry> current;
  for (uint64_t i = 0; i < 10; ++i) {
    baseline.push_back(make_u32(0x1000 + i * 4, 30U));
    current.push_back(make_u32(0x1000 + i * 4, 29U));  /* all decreased by 1 */
  }

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  auto results = engine.score_candidates(current, 3);
  TEST_EQ("limited to 3 results", results.size(), 3U);
}

static void test_empty_baseline_returns_empty() {
  std::printf("\n--- Edge: empty baseline ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x1000, 42));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);
  auto results = engine.score_candidates(current, 10);
  TEST_EQ("empty baseline → empty results", results.size(), 0U);
}

static void test_mismatched_sizes_returns_empty() {
  std::printf("\n--- Edge: mismatched baseline/current sizes ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x1000, 100));
  baseline.push_back(make_u32(0x1004, 200));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x1000, 90));  /* only 1 entry, baseline has 2 */

  auto results = engine.score_candidates(current, 10);
  TEST_EQ("mismatched sizes → empty", results.size(), 0U);
}

static void test_health_float_with_fraction() {
  std::printf("\n--- Health: float with fraction (85.5) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_f32(0x4000, 100.0f));

  engine.set_baseline(baseline, MEMDBG_VALUE_F32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_f32(0x4000, 85.5f));

  auto results = engine.score_candidates(current, 10);
  TEST("fractional float yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    /* 85.5 has fmod(85.5, 1.0) = 0.5, which is between 0.001 and 0.999.
     * kFlagFloatRepr should NOT be set. */
    TEST_NOFLAG("float repr not set for fractional", c.matched_flags,
                kFlagFloatRepr);
  }
}

static void test_health_float_integer_like() {
  std::printf("\n--- Health: float integer-like (100.0 -> 85.0) ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_f32(0x4000, 100.0f));

  engine.set_baseline(baseline, MEMDBG_VALUE_F32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_f32(0x4000, 85.0f));

  auto results = engine.score_candidates(current, 10);
  TEST("integer-like float yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    /* 85.0f >= 0.01 → magnitude gate doesn't kill it.  Engine should
     * correctly pick f32 with kFlagFloatRepr set. */
    TEST_EQ("picked f32 for plausible float", c.value_type, MEMDBG_VALUE_F32);
    TEST_EQ("old = 100", c.old_value, 100.0);
    TEST_EQ("new = 85", c.new_value, 85.0);
    TEST_FLAG("float repr set", c.matched_flags, kFlagFloatRepr);
    TEST_GT("score positive", c.score, 0.0f);
  }
}

static void test_multi_type_evaluation() {
  std::printf("\n--- Multi-type: engine picks best type ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  /* Value that looks like u32 health but also fits u8 range */
  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x1000, 100));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);

  std::vector<ScanSnapshotEntry> current;
  current.push_back(make_u32(0x1000, 85));

  auto results = engine.score_candidates(current, 10);
  TEST("multi-type yields candidate", results.size() >= 1U);
  if (!results.empty()) {
    const auto &c = results[0];
    /* Engine evaluates u32, f32, u16, u8 and picks the best.
     * For health 100→85, the integer types (u32/u16/u8) should score well.
     * f32 should also match but might get lower score due to float repr check. */
    TEST("candidate has a type assigned", c.value_type == MEMDBG_VALUE_U32 ||
         c.value_type == MEMDBG_VALUE_U8 || c.value_type == MEMDBG_VALUE_U16 ||
         c.value_type == MEMDBG_VALUE_F32);
    TEST_GT("score positive", c.score, 0.0f);
  }
}

static void test_reset_clears_baseline() {
  std::printf("\n--- Engine: reset clears baseline ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x1000, 100));

  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);
  TEST("has baseline after set_baseline", engine.has_baseline());
  TEST_EQ("baseline size 1", engine.baseline_size(), 1U);

  engine.reset();
  TEST("no baseline after reset", !engine.has_baseline());
  TEST_EQ("baseline size 0 after reset", engine.baseline_size(), 0U);
}

static void test_set_target_resets() {
  std::printf("\n--- Engine: set_target clears baseline ---\n");

  AutoSearchEngine engine;
  engine.set_target(AutoSearchTarget::Health);

  std::vector<ScanSnapshotEntry> baseline;
  baseline.push_back(make_u32(0x1000, 100));
  engine.set_baseline(baseline, MEMDBG_VALUE_U32, 4U);
  TEST("has baseline", engine.has_baseline());

  engine.set_target(AutoSearchTarget::Ammo);
  TEST("set_target resets baseline", !engine.has_baseline());
  TEST("target changed to Ammo",
       engine.target() == AutoSearchTarget::Ammo);
}

} // namespace

} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::printf("=== Auto-Search Engine Tests ===\n");
  std::printf("Testing heuristic scoring for Health, Ammo, Resources\n\n");

  test_health_decreased();
  test_health_unchanged_zero_score();
  test_health_zero_value();
  test_health_huge_decrease_skips_small_delta();
  test_health_float_format();
  test_health_float_with_fraction();
  test_health_float_integer_like();

  test_ammo_one_shot();
  test_ammo_unchanged_zero_score();
  test_ammo_burst_fire();
  test_ammo_huge_drop_no_decrease_bonus();
  test_ammo_u8_format();

  test_resources_increased();
  test_resources_decreased();
  test_resources_unchanged_zero_score();

  test_candidates_ranking();
  test_max_results_limit();
  test_empty_baseline_returns_empty();
  test_mismatched_sizes_returns_empty();
  test_multi_type_evaluation();

  test_reset_clears_baseline();
  test_set_target_resets();

  std::printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  std::printf("Total:  %d\n", total);
  std::printf("Passed: %d\n", g_passed);
  std::printf("Failed: %d\n", g_failed);
  std::printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}

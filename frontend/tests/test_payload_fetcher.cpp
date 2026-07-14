/*
 * MemDBG - PayloadFetcher platform filter tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "platform_utils.hpp"

#include <cstdio>
#include <cstring>

namespace memdbg::frontend {
namespace {

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                        \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s\n", name);                                        \
    }                                                                          \
  } while (0)

#define TEST_STR(name, actual, expected)                                       \
  TEST(name, std::strcmp((actual), (expected)) == 0)

static void test_payload_platform_filter() {
  std::printf("\n--- payload_platform_filter ---\n");

  /* Valid indices */
  TEST_STR("index 0 (Auto)",  payload_platform_filter(0), "");
  TEST_STR("index 1 (PS4)",   payload_platform_filter(1), "ps4");
  TEST_STR("index 2 (PS5)",   payload_platform_filter(2), "ps5");
  TEST_STR("index 3 (PS6)",   payload_platform_filter(3), "ps6");

  /* Bounds clamping — negative */
  TEST_STR("index -1  clamps to 0", payload_platform_filter(-1), "");
  TEST_STR("index -10 clamps to 0", payload_platform_filter(-10), "");

  /* Bounds clamping — above max */
  TEST_STR("index 4  clamps to 3",  payload_platform_filter(4),  "ps6");
  TEST_STR("index 99 clamps to 3",  payload_platform_filter(99), "ps6");
}

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::printf("=== PayloadFetcher Platform Filter Tests ===\n");
  test_payload_platform_filter();

  std::printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  std::printf("Total:  %d\n", total);
  std::printf("Passed: %d\n", g_passed);
  std::printf("Failed: %d\n", g_failed);
  std::printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}

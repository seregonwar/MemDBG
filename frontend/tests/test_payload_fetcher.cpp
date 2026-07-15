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

  /* Bounds clamping — negative */
  TEST_STR("index -1  clamps to 0", payload_platform_filter(-1), "");
  TEST_STR("index -10 clamps to 0", payload_platform_filter(-10), "");

  /* Bounds clamping — above max */
  TEST_STR("index 3  clamps to 2",  payload_platform_filter(3),  "ps5");
  TEST_STR("index 99 clamps to 2",  payload_platform_filter(99), "ps5");
}

static void test_payload_asset_score() {
  std::printf("\n--- payload_asset_score ---\n");

  TEST("PS4 exact ELF",
       payload_asset_score("MemDBG-ps4.elf", "ps4", "MemDBG-") == 100);
  TEST("PS5 exact ELF",
       payload_asset_score("MemDBG-ps5.elf", "ps5", "MemDBG-") == 100);
  TEST("platform mismatch rejected",
       payload_asset_score("MemDBG-ps4.elf", "ps5", "MemDBG-") == 0);
  TEST("library rejected",
       payload_asset_score("libmemdbg-ps5.a", "ps5", "MemDBG-") == 0);
  TEST("frontend archive rejected",
       payload_asset_score("MemDBG-frontend-windows.zip", "", "MemDBG-") == 0);
  TEST("legacy filter mismatch rejected",
       payload_asset_score("MemDBG-ps5.elf", "", "memdbg_payload") == 0);
  TEST("Auto prefers PS5",
       payload_asset_score("MemDBG-ps5.elf", "", "MemDBG-") >
           payload_asset_score("MemDBG-ps4.elf", "", "MemDBG-"));
}

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::printf("=== PayloadFetcher Platform Filter Tests ===\n");
  test_payload_platform_filter();
  test_payload_asset_score();

  std::printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  std::printf("Total:  %d\n", total);
  std::printf("Passed: %d\n", g_passed);
  std::printf("Failed: %d\n", g_failed);
  std::printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}

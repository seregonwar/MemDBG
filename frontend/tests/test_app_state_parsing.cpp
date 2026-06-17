/*
 * MemDBG - Frontend parsing helpers tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"

#include <array>
#include <cstdint>
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
      std::printf("  PASS  %s\n", name);                                       \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s\n", name);                                       \
    }                                                                          \
  } while (0)

#define TEST_EQ(name, actual, expected)                                        \
  do {                                                                         \
    auto _a = (actual);                                                        \
    auto _e = (expected);                                                      \
    if (_a == _e) {                                                            \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                       \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s  (got %llu, expected %llu)\n", name,            \
                  (unsigned long long)_a, (unsigned long long)_e);             \
    }                                                                          \
  } while (0)

static void test_parse_u64() {
  std::printf("\n--- parse_u64 ---\n");
  uint64_t value = 0;

  TEST("decimal", parse_u64("12345", value) && value == 12345ULL);
  TEST("hex lowercase", parse_u64("0x1a2b", value) && value == 0x1a2bULL);
  TEST("hex uppercase", parse_u64("0X1A2B", value) && value == 0x1A2BULL);
  TEST("no octal interpretation", parse_u64("0123", value) && value == 123ULL);
  TEST("whitespace tolerated", parse_u64("  0xABC  ", value) && value == 0xABCULL);
  TEST("max u64", parse_u64("18446744073709551615", value) && value == UINT64_MAX);

  TEST("empty rejected", !parse_u64("", value));
  TEST("invalid rejected", !parse_u64("xyz", value));
  TEST("mixed rejected", !parse_u64("12abc", value));
}

static void test_build_scan_value() {
  std::printf("\n--- build_scan_value ---\n");
  std::array<uint8_t, 16> value{};
  uint32_t len = 0;

  TEST("u32 decimal", build_scan_value(MEMDBG_VALUE_U32, "123456789", value, len) &&
                         len == 4 && read_scalar<uint32_t>(value) == 123456789U);
  value.fill(0); len = 0;
  TEST("u32 hex", build_scan_value(MEMDBG_VALUE_U32, "0xDEADBEEF", value, len) &&
                      len == 4 && read_scalar<uint32_t>(value) == 0xDEADBEEFU);
  value.fill(0); len = 0;
  TEST("u32 no octal", build_scan_value(MEMDBG_VALUE_U32, "0100", value, len) &&
                           len == 4 && read_scalar<uint32_t>(value) == 100U);
  value.fill(0); len = 0;
  TEST("u64 pointer", build_scan_value(MEMDBG_VALUE_POINTER, "0x7FFF12340000", value, len) &&
                          len == 8 && read_scalar<uint64_t>(value) == 0x7FFF12340000ULL);
  value.fill(0); len = 0;
  TEST("bytes", build_scan_value(MEMDBG_VALUE_BYTES, "48 8B 05 00 00", value, len) &&
                     len == 5 && value[0] == 0x48 && value[1] == 0x8B &&
                     value[2] == 0x05 && value[3] == 0x00 && value[4] == 0x00);
  value.fill(0); len = 0;
  TEST("float", build_scan_value(MEMDBG_VALUE_F32, "3.14", value, len) && len == 4);
  value.fill(0); len = 0;
  TEST("double", build_scan_value(MEMDBG_VALUE_F64, "2.718281828", value, len) && len == 8);

  TEST("invalid u32 rejected", !build_scan_value(MEMDBG_VALUE_U32, "abc", value, len));
  TEST("oversized bytes rejected",
       !build_scan_value(MEMDBG_VALUE_BYTES,
                         "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                         value, len));
}

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::printf("=== Frontend Parsing Tests ===\n");
  test_parse_u64();
  test_build_scan_value();

  std::printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  std::printf("Total:  %d\n", total);
  std::printf("Passed: %d\n", g_passed);
  std::printf("Failed: %d\n", g_failed);
  std::printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}

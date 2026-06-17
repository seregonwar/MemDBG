/*
 * MemDBG - Trainer format and batchcode parser tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "batchcode_parser.hpp"
#include "trainer_format.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>

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

static void test_bytes_to_hex() {
  std::printf("\n--- bytes_to_hex ---\n");
  TEST("empty", bytes_to_hex({}).empty());
  TEST("single", bytes_to_hex({0xab}) == "AB");
  TEST("multi", bytes_to_hex({0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}) ==
                   "0123456789ABCDEF");
}

static void test_batchcode_parser() {
  std::printf("\n--- batchcode parser ---\n");
  std::string error;
  std::vector<BatchcodeEntry> out;

  TEST("semicolon separated",
       parse_batchcode("offset:0x123456;value:90 90 90 90;size:4", out, error) == 1 &&
           out.size() == 1 && out[0].offset == 0x123456 && out[0].bytes.size() == 4);

  TEST("equals separated",
       parse_batchcode("offset=0xABCDEF value=01 02 03 size=3", out, error) == 1 &&
           out[0].offset == 0xABCDEF && out[0].bytes == std::vector<uint8_t>({1, 2, 3}));

  TEST("bare numbers",
       parse_batchcode("0x1000 : DE AD BE EF", out, error) == 1 &&
           out[0].offset == 0x1000 && out[0].bytes == std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));

  TEST("newline records",
       parse_batchcode("offset:0x0;value:00\noffset:0x10;value:FF", out, error) == 2 &&
           out[1].offset == 0x10 && out[1].bytes == std::vector<uint8_t>({0xFF}));

  TEST("comments ignored",
       parse_batchcode("# header\noffset:0x0;value:00 // comment\n", out, error) == 1);

  TEST("wildcard bytes",
       parse_batchcode("offset:0x0 value:48 8B ?? 00", out, error) == 1 &&
           out[0].bytes == std::vector<uint8_t>({0x48, 0x8B, 0x00, 0x00}));

  TEST("hex number value",
       parse_batchcode("offset:0x0 value:0x12345678", out, error) == 1 &&
           out[0].bytes == std::vector<uint8_t>({0x12, 0x34, 0x56, 0x78}));

  TEST("size truncates",
       parse_batchcode("offset:0x0 value:11 22 33 44 size:2", out, error) == 1 &&
           out[0].bytes == std::vector<uint8_t>({0x11, 0x22}));

  TEST("size pads",
       parse_batchcode("offset:0x0 value:11 size:3", out, error) == 1 &&
           out[0].bytes == std::vector<uint8_t>({0x11, 0x00, 0x00}));

  TEST("empty input",
       parse_batchcode("", out, error) == 0 && out.empty());

  TEST("garbage ignored",
       parse_batchcode("hello world", out, error) == 0 && out.empty());

  int bad = parse_batchcode("offset:", out, error);
  TEST("missing offset number errors", bad < 0 && !error.empty());
}

static void test_goldhen_json_roundtrip() {
  std::printf("\n--- GoldHEN JSON roundtrip ---\n");

  AppState state;
  state.selected_pid = 1234;
  CheatEntry cheat;
  cheat.description = "Godmode";
  cheat.pid = 1234;
  cheat.address = 0x668DA3;
  cheat.value_type = MEMDBG_VALUE_BYTES;
  cheat.value_text = "90909090";
  cheat.bytes = {0x90, 0x90, 0x90, 0x90};
  cheat.off_bytes = {0xC5, 0xFA, 0x11, 0x00};
  cheat.has_off_bytes = true;
  cheat.enabled = true;
  state.cheats.push_back(cheat);

  const auto tmp = std::filesystem::temp_directory_path() / "memdbg_test_goldhen.json";
  (void)std::filesystem::remove(tmp);

  TEST("save succeeds", save_trainer_file(state, tmp.string()));

  AppState loaded;
  loaded.selected_pid = 1234;
  TEST("load succeeds", load_trainer_file(loaded, tmp.string()) == 1);
  if (!loaded.cheats.empty()) {
    const auto &c = loaded.cheats[0];
    TEST_EQ("address preserved", c.address, 0x668DA3ULL);
    TEST("description preserved", c.description == "Godmode");
    TEST("bytes preserved", c.bytes == std::vector<uint8_t>({0x90, 0x90, 0x90, 0x90}));
    TEST("off bytes preserved", c.has_off_bytes &&
                                    c.off_bytes == std::vector<uint8_t>({0xC5, 0xFA, 0x11, 0x00}));
  }

  /* Verify the saved file is valid JSON and has the expected top-level keys. */
  {
    std::ifstream in(tmp, std::ios::binary);
    nlohmann::json json;
    in >> json;
    TEST("saved JSON has top-level object", json.is_object());
    TEST("saved JSON has mods", json.contains("mods") && json["mods"].is_array());
    TEST("saved JSON has process", json.contains("process"));
  }

  (void)std::filesystem::remove(tmp);
}

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::setvbuf(stdout, nullptr, _IONBF, 0);
  std::printf("=== Trainer Format Tests ===\n");
  test_bytes_to_hex();
  test_batchcode_parser();
  test_goldhen_json_roundtrip();

  std::printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  std::printf("Total:  %d\n", total);
  std::printf("Passed: %d\n", g_passed);
  std::printf("Failed: %d\n", g_failed);
  std::printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}

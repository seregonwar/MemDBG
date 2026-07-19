/*
 * MemDBG - Trainer format and batchcode parser tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "batchcode_parser.hpp"
#include "trainer_format.hpp"

#include <nlohmann/json.hpp>
#include "simdjson.h"

extern "C" {
#include "sJson.c"
}

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#if !defined(_WIN32)
#include <sys/resource.h>
#endif

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
  state.plugin.cheats.push_back(cheat);

  const auto tmp = std::filesystem::temp_directory_path() / "memdbg_test_goldhen.json";
  (void)std::filesystem::remove(tmp);

  TEST("save succeeds", save_trainer_file(state, tmp.string()));

  AppState loaded;
  loaded.selected_pid = 1234;
  TEST("load succeeds", load_trainer_file(loaded, tmp.string()) == 1);
  if (!loaded.plugin.cheats.empty()) {
    const auto &c = loaded.plugin.cheats[0];
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

static void test_goldhen_json_roundtrip_extended() {
  std::printf("\n--- GoldHEN JSON roundtrip extended (enabled/locked) ---\n");

  AppState state;
  state.selected_pid = 1234;
  state.has_process_info = true;
  state.selected_process_info.title_id = "CUSA12345";

  /* Entry 1: enabled + locked, with off_bytes */
  CheatEntry cheat1;
  cheat1.description = "Infinite Health";
  cheat1.pid = 1234;
  cheat1.address = 0x668DA3;
  cheat1.value_type = MEMDBG_VALUE_U32;
  cheat1.value_text = "90909090";
  cheat1.bytes = {0x90, 0x90, 0x90, 0x90};
  cheat1.off_bytes = {0xC5, 0xFA, 0x11, 0x00};
  cheat1.has_off_bytes = true;
  cheat1.enabled = true;
  cheat1.locked = true;
  state.plugin.cheats.push_back(cheat1);

  /* Entry 2: disabled, unlocked, no off_bytes */
  CheatEntry cheat2;
  cheat2.description = "Infinite Ammo";
  cheat2.pid = 1234;
  cheat2.address = 0xAABBCC;
  cheat2.value_type = MEMDBG_VALUE_U16;
  cheat2.value_text = "FFFF";
  cheat2.bytes = {0xFF, 0xFF};
  cheat2.enabled = false;
  cheat2.locked = false;
  state.plugin.cheats.push_back(cheat2);

  const auto tmp = std::filesystem::temp_directory_path() / "memdbg_test_goldhen_ext.json";
  (void)std::filesystem::remove(tmp);

  TEST("save extended succeeds", save_trainer_file(state, tmp.string()));

  AppState loaded;
  loaded.selected_pid = 1234;
  int load_count = load_trainer_file(loaded, tmp.string());
  TEST("load extended count", load_count == 2);

  if (loaded.plugin.cheats.size() >= 2) {
    const auto &c1 = loaded.plugin.cheats[0];
    TEST("entry1 description", c1.description == "Infinite Health");
    TEST_EQ("entry1 address", c1.address, 0x668DA3ULL);
    TEST("entry1 enabled", c1.enabled == true);
    TEST("entry1 locked", c1.locked == true);
    TEST("entry1 has off", c1.has_off_bytes == true);

    const auto &c2 = loaded.plugin.cheats[1];
    TEST("entry2 description", c2.description == "Infinite Ammo");
    TEST_EQ("entry2 address", c2.address, 0xAABBCCULL);
    TEST("entry2 disabled", c2.enabled == false);
    TEST("entry2 unlocked", c2.locked == false);
    TEST("entry2 no off", c2.has_off_bytes == false);
  }

  /* Verify saved JSON has enabled/locked fields */
  {
    std::ifstream in(tmp, std::ios::binary);
    nlohmann::json json;
    in >> json;
    TEST("saved JSON has mods", json.contains("mods") && json["mods"].is_array());
    if (json["mods"].size() >= 2) {
      auto &mod1 = json["mods"][0];
      auto &mod2 = json["mods"][1];
      TEST("mod1 has enabled", mod1.contains("enabled") && mod1["enabled"] == true);
      TEST("mod1 has locked", mod1.contains("locked") && mod1["locked"] == true);
      TEST("mod2 has enabled", mod2.contains("enabled") && mod2["enabled"] == false);
      TEST("mod2 has locked", mod2.contains("locked") && mod2["locked"] == false);
    }
  }

  (void)std::filesystem::remove(tmp);
}

static void test_goldhen_json_schema() {
  std::printf("\n--- GoldHEN JSON schema validation ---\n");

  AppState state;
  state.selected_pid = 1234;
  state.has_process_info = true;
  state.selected_process_info.title_id = "CUSA12345";
  state.selected_process_info.name = "MyGame";

  CheatEntry cheat;
  cheat.description = "Infinite Health";
  cheat.pid = 1234;
  cheat.address = 0x668DA3;
  cheat.value_type = MEMDBG_VALUE_U32;
  cheat.value_text = "90909090";
  cheat.bytes = {0x90, 0x90, 0x90, 0x90};
  cheat.off_bytes = {0xC5, 0xFA, 0x11, 0x00};
  cheat.has_off_bytes = true;
  cheat.enabled = true;
  cheat.locked = true;
  state.plugin.cheats.push_back(cheat);

  const auto tmp = std::filesystem::temp_directory_path() / "memdbg_test_schema.json";
  (void)std::filesystem::remove(tmp);

  TEST("schema save succeeds", save_trainer_file(state, tmp.string()));

  /* Read back as JSON and validate structure */
  std::ifstream in(tmp, std::ios::binary);
  TEST("schema file is readable", in.good());

  nlohmann::json json;
  try {
    in >> json;
    TEST("schema file is valid JSON", true);
  } catch (...) {
    TEST("schema file is valid JSON", false);
    in.close();
    (void)std::filesystem::remove(tmp);
    return;
  }

  /* Top-level keys */
  TEST("top-level is object", json.is_object());

  TEST("has 'name'", json.contains("name") && json["name"].is_string() &&
                        !json["name"].get<std::string>().empty());
  TEST("has 'id'", json.contains("id") && json["id"].is_string() &&
                      json["id"].get<std::string>() == "CUSA12345");
  TEST("has 'version'", json.contains("version") && json["version"].is_string() &&
                            json["version"].get<std::string>() == "01.00");
  TEST("has 'process'", json.contains("process") && json["process"].is_string() &&
                            json["process"].get<std::string>() == "eboot.bin");
  TEST("has 'credits'", json.contains("credits") && json["credits"].is_array());
  TEST("has 'mods'", json.contains("mods") && json["mods"].is_array() &&
                         json["mods"].size() == 1);

  /* Mod sub-keys */
  if (json.contains("mods") && json["mods"].is_array() && json["mods"].size() >= 1) {
    auto &mod = json["mods"][0];
    TEST("mod is object", mod.is_object());
    TEST("mod has name", mod.contains("name") && mod["name"].is_string());
    TEST("mod has type", mod.contains("type") && mod["type"].is_string() &&
                            mod["type"].get<std::string>() == "checkbox");
    TEST("mod has enabled", mod.contains("enabled") && mod["enabled"].is_boolean());
    TEST("mod has locked", mod.contains("locked") && mod["locked"].is_boolean());
    TEST("mod has memory", mod.contains("memory") && mod["memory"].is_array() &&
                               mod["memory"].size() == 1);

    /* Memory entry sub-keys */
    if (mod.contains("memory") && mod["memory"].is_array() &&
        mod["memory"].size() >= 1) {
      auto &mem = mod["memory"][0];
      TEST("memory has offset", mem.contains("offset") && mem["offset"].is_string());
      TEST("memory has on", mem.contains("on") && mem["on"].is_string());
      TEST("memory has type", mem.contains("type") && mem["type"].is_string());
      TEST("memory has off", mem.contains("off") && mem["off"].is_string());
    }
  }

  /* Verify credits is empty array (no credits configured) */
  TEST("credits is empty", json["credits"].is_array() && json["credits"].empty());

  /* Windows does not allow removing a file while this stream still owns a
     handle to it.  Close it explicitly before deleting the test fixture. */
  in.close();
  (void)std::filesystem::remove(tmp);
}

static void test_pipe_delimited_roundtrip() {
  std::printf("\n--- Pipe-delimited .cht roundtrip ---\n");

  /* Set up state with memory maps so some entries resolve via section+offset. */
  AppState state;
  state.selected_pid = 1234;
  state.has_process_info = true;
  state.selected_process_info.title_id = "CUSA12345";
  state.selected_process_info.name = "TestGame";
  state.maps = {
      {0x200000, 0x300000, 7, 0, "code"},
      {0x400000, 0x500000, 5, 0, "data"},
  };

  /* Entry 1: section-based (map 0), with off_bytes, locked, U32 */
  CheatEntry cheat1;
  cheat1.description = "Infinite Health";
  cheat1.pid = 1234;
  cheat1.address = 0x268DA3; /* map[0].start(0x200000) + offset 0x68DA3 */
  cheat1.value_type = MEMDBG_VALUE_U32;
  cheat1.value_text = "90909090";
  cheat1.bytes = {0x90, 0x90, 0x90, 0x90};
  cheat1.off_bytes = {0xC5, 0xFA, 0x11, 0x00};
  cheat1.has_off_bytes = true;
  cheat1.enabled = true;
  cheat1.locked = true;
  state.plugin.cheats.push_back(cheat1);

  /* Entry 2: absolute (outside all maps), no off_bytes, unlocked, U16 */
  CheatEntry cheat2;
  cheat2.description = "Infinite Ammo";
  cheat2.pid = 1234;
  cheat2.address = 0x500001; /* outside both maps */
  cheat2.value_type = MEMDBG_VALUE_U16;
  cheat2.value_text = "FFFF";
  cheat2.bytes = {0xFF, 0xFF};
  cheat2.enabled = true;
  cheat2.locked = false;
  state.plugin.cheats.push_back(cheat2);

  /* Entry 3: section-based (map 1), no off_bytes, locked, BYTES */
  CheatEntry cheat3;
  cheat3.description = "Max Score";
  cheat3.pid = 1234;
  cheat3.address = 0x401000; /* map[1].start(0x400000) + offset 0x1000 */
  cheat3.value_type = MEMDBG_VALUE_BYTES;
  cheat3.value_text = "01020304";
  cheat3.bytes = {0x01, 0x02, 0x03, 0x04};
  cheat3.enabled = true;
  cheat3.locked = true;
  state.plugin.cheats.push_back(cheat3);

  const auto tmp = std::filesystem::temp_directory_path() / "memdbg_test_pipe_roundtrip.cht";
  (void)std::filesystem::remove(tmp);

  TEST("pipe save succeeds", save_trainer_file(state, tmp.string()));

  /* Verify the saved file has the expected header and structure */
  {
    std::ifstream in(tmp);
    std::string first_line;
    std::getline(in, first_line);
    TEST("pipe header starts with version", first_line.rfind("1.4|", 0) == 0);

    /* Check each data line has the core pipe tokens */
    std::string data_line;
    int data_lines = 0;
    while (std::getline(in, data_line)) {
      if (!data_line.empty() && data_line.rfind("data|", 0) == 0) {
        data_lines++;
        auto tokens = [&]() {
          std::vector<std::string> t;
          size_t start = 0;
          while (start <= data_line.size()) {
            size_t pos = data_line.find('|', start);
            if (pos == std::string::npos) { t.push_back(data_line.substr(start)); break; }
            t.push_back(data_line.substr(start, pos - start));
            start = pos + 1;
          }
          return t;
        }();
        TEST("pipe data line has enough tokens", tokens.size() >= 7);
      }
    }
    TEST("pipe saved 3 data lines", data_lines == 3);
  }

  /* Load back and compare every field */
  AppState loaded;
  loaded.selected_pid = 1234;
  loaded.maps = state.maps;
  int load_count = load_trainer_file(loaded, tmp.string());
  TEST("pipe load count", load_count == 3);

  if (loaded.plugin.cheats.size() >= 3) {
    /* Entry 1: section-based, off_bytes, locked, U32 */
    const auto &c1 = loaded.plugin.cheats[0];
    TEST("c1 description", c1.description == "Infinite Health");
    TEST_EQ("c1 address", c1.address, 0x268DA3ULL);
    TEST("c1 value_type U32", c1.value_type == MEMDBG_VALUE_U32);
    TEST("c1 value_text", c1.value_text == "90909090");
    TEST("c1 bytes", c1.bytes == std::vector<uint8_t>({0x90, 0x90, 0x90, 0x90}));
    TEST("c1 off_bytes", c1.has_off_bytes &&
                             c1.off_bytes == std::vector<uint8_t>({0xC5, 0xFA, 0x11, 0x00}));
    TEST("c1 locked", c1.locked == true);
    TEST("c1 enabled", c1.enabled == true);

    /* Entry 2: absolute, no off_bytes, unlocked, U16 */
    const auto &c2 = loaded.plugin.cheats[1];
    TEST("c2 description", c2.description == "Infinite Ammo");
    TEST_EQ("c2 address", c2.address, 0x500001ULL);
    TEST("c2 value_type U16", c2.value_type == MEMDBG_VALUE_U16);
    TEST("c2 value_text", c2.value_text == "FFFF");
    TEST("c2 bytes", c2.bytes == std::vector<uint8_t>({0xFF, 0xFF}));
    TEST("c2 no off_bytes", c2.has_off_bytes == false);
    TEST("c2 unlocked", c2.locked == false);

    /* Entry 3: section-based (map 1), no off_bytes, locked, BYTES */
    const auto &c3 = loaded.plugin.cheats[2];
    TEST("c3 description", c3.description == "Max Score");
    TEST_EQ("c3 address", c3.address, 0x401000ULL);
    TEST("c3 value_type BYTES", c3.value_type == MEMDBG_VALUE_BYTES);
    TEST("c3 value_text", c3.value_text == "01020304");
    TEST("c3 bytes", c3.bytes == std::vector<uint8_t>({0x01, 0x02, 0x03, 0x04}));
    TEST("c3 no off_bytes", c3.has_off_bytes == false);
    TEST("c3 locked", c3.locked == true);
  }

  (void)std::filesystem::remove(tmp);
}

static void test_pipe_delimited_no_maps_roundtrip() {
  std::printf("\n--- Pipe-delimited .cht roundtrip (no maps → @absolute) ---\n");

  /* Set up state WITH memory maps so entries resolve via section+offset on save. */
  AppState state;
  state.selected_pid = 1234;
  state.has_process_info = true;
  state.selected_process_info.title_id = "CUSA12345";
  state.selected_process_info.name = "TestGame";
  state.maps = {
      {0x200000, 0x300000, 7, 0, "code"},
      {0x400000, 0x500000, 5, 0, "data"},
  };

  /* Entry 1: section-based (map 0), absolute address 0x268DA3 */
  CheatEntry cheat1;
  cheat1.description = "Infinite Health";
  cheat1.pid = 1234;
  cheat1.address = 0x268DA3;
  cheat1.value_type = MEMDBG_VALUE_U32;
  cheat1.value_text = "90909090";
  cheat1.bytes = {0x90, 0x90, 0x90, 0x90};
  cheat1.locked = true;
  cheat1.enabled = true;
  state.plugin.cheats.push_back(cheat1);

  /* Entry 2: section-based (map 1), absolute address 0x401000 */
  CheatEntry cheat2;
  cheat2.description = "Max Score";
  cheat2.pid = 1234;
  cheat2.address = 0x401000;
  cheat2.value_type = MEMDBG_VALUE_BYTES;
  cheat2.value_text = "01020304";
  cheat2.bytes = {0x01, 0x02, 0x03, 0x04};
  cheat2.locked = true;
  cheat2.enabled = true;
  state.plugin.cheats.push_back(cheat2);

  /* Entry 3: absolute (outside maps), address 0x500001 */
  CheatEntry cheat3;
  cheat3.description = "Infinite Ammo";
  cheat3.pid = 1234;
  cheat3.address = 0x500001;
  cheat3.value_type = MEMDBG_VALUE_U16;
  cheat3.value_text = "FFFF";
  cheat3.bytes = {0xFF, 0xFF};
  cheat3.locked = false;
  cheat3.enabled = true;
  state.plugin.cheats.push_back(cheat3);

  const auto tmp = std::filesystem::temp_directory_path() / "memdbg_test_pipe_nomaps.cht";
  (void)std::filesystem::remove(tmp);

  /* Save with maps → section-based entries written as section|offset format. */
  TEST("nomaps save succeeds", save_trainer_file(state, tmp.string()));

  /* Load WITHOUT maps — all entries must resolve to @absolute addresses. */
  AppState loaded;
  loaded.selected_pid = 1234;
  /* Intentionally leave loaded.maps EMPTY to simulate no memory layout. */
  int load_count = load_trainer_file(loaded, tmp.string());
  TEST("nomaps load count", load_count == 3);

  if (loaded.plugin.cheats.size() >= 3) {
    const auto &c1 = loaded.plugin.cheats[0];
    TEST("nomaps c1 description", c1.description == "Infinite Health");
    TEST_EQ("nomaps c1 address resolved via @absolute", c1.address, 0x268DA3ULL);
    TEST("nomaps c1 value_type", c1.value_type == MEMDBG_VALUE_U32);
    TEST("nomaps c1 bytes", c1.bytes == std::vector<uint8_t>({0x90, 0x90, 0x90, 0x90}));

    const auto &c2 = loaded.plugin.cheats[1];
    TEST("nomaps c2 description", c2.description == "Max Score");
    TEST_EQ("nomaps c2 address resolved via @absolute", c2.address, 0x401000ULL);
    TEST("nomaps c2 value_type", c2.value_type == MEMDBG_VALUE_BYTES);
    TEST("nomaps c2 bytes", c2.bytes == std::vector<uint8_t>({0x01, 0x02, 0x03, 0x04}));

    const auto &c3 = loaded.plugin.cheats[2];
    /* Entry 3 was already @absolute even when maps were present.
       Maps don't matter here — it was already saved as @absolute. */
    TEST("nomaps c3 description", c3.description == "Infinite Ammo");
    TEST_EQ("nomaps c3 address (already absolute)", c3.address, 0x500001ULL);
    TEST("nomaps c3 value_type", c3.value_type == MEMDBG_VALUE_U16);
    TEST("nomaps c3 bytes", c3.bytes == std::vector<uint8_t>({0xFF, 0xFF}));
  }

  (void)std::filesystem::remove(tmp);
}

static void test_parse_goldhen_mods_variants() {
  std::printf("\n--- parse_goldhen_mods variant formats ---\n");

  std::string error;

  /* Test 1: mod with "title" instead of "name" */
  {
    const char *json = R"({
      "mods": [
        {
          "title": "Title Fallback",
          "type": "checkbox",
          "memory": [
            {"offset": "0x1000", "on": "90909090", "type": "4 bytes"}
          ]
        }
      ]
    })";
    auto entries = parse_goldhen_mods(json, 0, &error);
    TEST("title fallback parsed", entries.size() == 1);
    if (!entries.empty())
      TEST("title fallback name", entries[0].description == "Title Fallback");
  }

  /* Test 2: array-format on values */
  {
    const char *json = R"({
      "mods": [
        {
          "name": "Array Test",
          "type": "checkbox",
          "memory": [
            {"offset": "0x2000", "on": [144, 144, 144, 144], "type": "bytes"}
          ]
        }
      ]
    })";
    auto entries = parse_goldhen_mods(json, 0, &error);
    TEST("array on parsed", entries.size() == 1);
    if (!entries.empty())
      TEST("array on bytes", entries[0].bytes == std::vector<uint8_t>({0x90, 0x90, 0x90, 0x90}));
  }

  /* Test 3: root-level {memory: [...]} without mods wrapper */
  {
    const char *json = R"({
      "name": "RootMod",
      "memory": [
        {"offset": "0x3000", "on": "01020304", "type": "4 bytes"}
      ]
    })";
    auto entries = parse_goldhen_mods(json, 0, &error);
    TEST("root memory parsed", entries.size() == 1);
    if (!entries.empty())
      TEST("root memory name", entries[0].description == "RootMod");
  }

  /* Test 4: bare root array */
  {
    const char *json = R"([
      {"name": "Bare1", "type": "checkbox", "memory": [{"offset": "0x4000", "on": "FF", "type": "byte"}]},
      {"name": "Bare2", "type": "checkbox", "memory": [{"offset": "0x5000", "on": "EE", "type": "byte"}]}
    ])";
    auto entries = parse_goldhen_mods(json, 0, &error);
    TEST("bare array parsed", entries.size() == 2);
    if (entries.size() >= 2) {
      TEST("bare array name1", entries[0].description == "Bare1");
      TEST("bare array name2", entries[1].description == "Bare2");
    }
  }

  /* Test 5: section-based addressing with maps */
  {
    const char *json = R"({
      "mods": [
        {
          "name": "Section Test",
          "type": "checkbox",
          "memory": [
            {"offset": "0x1000", "section": 0, "on": "90909090", "type": "4 bytes"}
          ]
        }
      ]
    })";
    std::vector<MapEntry> maps = {{0x800000, 0x900000, 7, 0, "code"}};
    auto entries = parse_goldhen_mods(json, 0, &error, &maps);
    TEST("section parsed", entries.size() == 1);
    if (!entries.empty())
      TEST_EQ("section resolved address", entries[0].address, 0x801000ULL);
  }

  /* Test 6: OFF-note entry attaches to previous */
  {
    const char *json = R"({
      "mods": [
        {
          "name": "NoteTest",
          "type": "checkbox",
          "memory": [
            {"offset": "0x6000", "on": "90909090", "type": "bytes"},
            {"offset": "0x6000", "value": "C5FA1100", "note": "off"}
          ]
        }
      ]
    })";
    auto entries = parse_goldhen_mods(json, 0, &error);
    TEST("off note parsed", entries.size() == 1);
    if (!entries.empty()) {
      TEST("off note has off_bytes", entries[0].has_off_bytes == true);
      TEST("off note bytes", entries[0].off_bytes == std::vector<uint8_t>({0xC5, 0xFA, 0x11, 0x00}));
    }
  }
}

/* Sample the current peak RSS (resident set size) via getrusage.
   On macOS ru_maxrss is bytes; on Linux it is KiB. Normalise to KiB. */
static long sample_peak_rss_kb() {
#if defined(_WIN32)
  return -1;
#else
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) != 0) return -1;
#ifdef __APPLE__
  return usage.ru_maxrss / 1024L;
#else
  return usage.ru_maxrss;
#endif
#endif
}

static void test_malformed_cht() {
  std::printf("\n--- Malformed .cht files ---\n");

  auto write_and_load = [](const char *name, const std::string &content,
                            int expected_max) {
    const auto tmp = std::filesystem::temp_directory_path() / name;
    (void)std::filesystem::remove(tmp);
    {
      std::ofstream out(tmp, std::ios::binary);
      out << content;
    }
    AppState state;
    state.selected_pid = 100;
    int loaded = load_trainer_file(state, tmp.string());
    (void)std::filesystem::remove(tmp);
    TEST((std::string(name) + " returns <= " + std::to_string(expected_max)).c_str(),
         loaded >= -1 && loaded <= expected_max);
  };

  /* Empty file */
  write_and_load("malformed_empty.cht", "", 0);

  /* Garbage — no pipe separator in header, no valid data */
  write_and_load("malformed_garbage.cht", "this is not a cht file\nmore garbage\n", 0);

  /* Header with pipe but no data lines */
  write_and_load("malformed_header_only.cht", "1.4|CUSA00000|ID:CUSA00000|VER:unknown|FM:MemDBG\n", 0);

  /* Data line with too few tokens (< 6) */
  write_and_load("malformed_short.cht",
                 "1.4|CUSA00000|ID:CUSA00000|VER:unknown|FM:MemDBG\n"
                 "data|0|1000|4 bytes\n",
                 0);

  /* Data line with non-hex value ("ZZZZ" cannot be parsed as bytes) */
  write_and_load("malformed_bad_value.cht",
                 "1.4|CUSA00000|ID:CUSA00000|VER:unknown|FM:MemDBG\n"
                 "data|0|1000|4 bytes|ZZZZ|0|Test cheat|268DA3\n",
                 0);

  /* Data line with non-hex offset */
  write_and_load("malformed_bad_offset.cht",
                 "1.4|CUSA00000|ID:CUSA00000|VER:unknown|FM:MemDBG\n"
                 "data|0|GGGG|4 bytes|90909090|0|Test cheat|268DA3\n",
                 0);

  /* Mixed: one valid entry, one bad — should load only the good one */
  {
    const auto tmp = std::filesystem::temp_directory_path() / "malformed_mixed.cht";
    (void)std::filesystem::remove(tmp);
    {
      std::ofstream out(tmp, std::ios::binary);
      out << "1.4|CUSA00000|ID:CUSA00000|VER:unknown|FM:MemDBG\n"
             "data|0|1000|4 bytes|90909090|0|Good cheat|268DA3\n"
             "data|0|1001|4 bytes|ZZZZ|0|Bad cheat|268DA4\n"
             "data|0|1002|4 bytes|01020304|0|Also good cheat|268DA5\n";
    }
    AppState state;
    state.selected_pid = 100;
    state.maps = {{0x200000, 0x300000, 7, 0, "code"}};
    int loaded = load_trainer_file(state, tmp.string());
    TEST("malformed mixed cht count", loaded == 2);
    if (loaded >= 2) {
      TEST("malformed mixed first good",
           state.plugin.cheats[0].description == "Good cheat");
      TEST("malformed mixed second good",
           state.plugin.cheats[1].description == "Also good cheat");
    }
    (void)std::filesystem::remove(tmp);
  }

  /* Missing header entirely: first line is "data|" (should still parse) */
  {
    const auto tmp = std::filesystem::temp_directory_path() / "malformed_no_header.cht";
    (void)std::filesystem::remove(tmp);
    {
      std::ofstream out(tmp, std::ios::binary);
      out << "data|0|1000|4 bytes|90909090|0|No header cheat|268DA3\n";
    }
    AppState state;
    state.selected_pid = 100;
    state.maps = {{0x200000, 0x300000, 7, 0, "code"}};
    int loaded = load_trainer_file(state, tmp.string());
    /* load_pipe_delimited detects "data|" on the first line and does NOT
       skip it as a header — it parses it directly. */
    TEST("malformed no-header count", loaded == 1);
    (void)std::filesystem::remove(tmp);
  }

  /* Non-hex section number: "ABC" is valid hex but out-of-range, falls back
     to absolute address. Should not crash. */
  {
    const auto tmp = std::filesystem::temp_directory_path() / "malformed_bad_section.cht";
    (void)std::filesystem::remove(tmp);
    {
      std::ofstream out(tmp, std::ios::binary);
      out << "1.4|CUSA00000|ID:CUSA00000|VER:unknown|FM:MemDBG\n"
             "data|ABC|1000|4 bytes|90909090|0|Bad section cheat|268DA3\n";
    }
    AppState state;
    state.selected_pid = 100;
    /* No maps — section ABC (0xABC) is out of range, tokens.back() fallback kicks in. */
    int loaded = load_trainer_file(state, tmp.string());
    TEST("malformed bad-section count", loaded == 1);
    if (loaded >= 1)
      TEST_EQ("malformed bad-section address", state.plugin.cheats[0].address, 0x268DA3ULL);
    (void)std::filesystem::remove(tmp);
  }

  /* File does not exist */
  {
    AppState state;
    state.selected_pid = 100;
    int loaded = load_trainer_file(state, "/tmp/memdbg_test_nonexistent_xyz.cht");
    TEST("malformed nonexistent returns -1", loaded == -1);
  }
}

static void bench_trainer_formats() {
  constexpr int N = 10000;
  std::printf("\n--- Bench: trainer format load/save (%d entries) ---\n", N);

  long rss_before_data = sample_peak_rss_kb();

  /* Build 10000 synthetic cheats with varied characteristics. */
  AppState state;
  state.selected_pid = 100;
  state.has_process_info = true;
  state.selected_process_info.title_id = "CUSA00000";
  state.maps = {
      {0x100000, 0x500000, 7, 0, "code"},    /* 4 MiB */
      {0x500000, 0x900000, 5, 0, "data"},    /* 4 MiB */
      {0x900000, 0xD00000, 3, 0, "rodata"},  /* 4 MiB */
  };

  /* Pipe format uses hex value_text — avoid F32/F64 which require decimal float parsing. */
  const int value_types[] = {MEMDBG_VALUE_U8, MEMDBG_VALUE_U16, MEMDBG_VALUE_U32,
                             MEMDBG_VALUE_U64, MEMDBG_VALUE_BYTES};

  for (int i = 0; i < N; ++i) {
    CheatEntry cheat;
    cheat.description = "Bench cheat #" + std::to_string(i);
    cheat.pid = 100;
    /* Mix of section-based and absolute addresses. */
    if (i % 3 == 0)
      cheat.address = state.maps[0].start + (i * 0x100) % (state.maps[0].end - state.maps[0].start);
    else if (i % 3 == 1)
      cheat.address = state.maps[1].start + (i * 0x80) % (state.maps[1].end - state.maps[1].start);
    else
      cheat.address = 0xD00000 + i * 4; /* absolute, outside maps */
    cheat.value_type = value_types[i % 5];
    cheat.locked = (i % 4 == 0);
    cheat.enabled = true;

    /* Deterministic bytes based on index. */
    unsigned seed = static_cast<unsigned>(i * 0x9E3779B9ULL);
    int len = 1 + (i % 8); /* 1-8 bytes */
    cheat.bytes.resize(static_cast<size_t>(len));
    for (int b = 0; b < len; ++b)
      cheat.bytes[static_cast<size_t>(b)] = static_cast<uint8_t>((seed >> (b * 8)) & 0xFF);
    cheat.value_text = bytes_to_hex(cheat.bytes);

    /* Every 3rd entry gets off_bytes. */
    if (i % 3 == 0) {
      cheat.off_bytes = cheat.bytes;
      cheat.off_bytes[0] ^= 0xFF; /* make it different */
      cheat.has_off_bytes = true;
    }

    state.plugin.cheats.push_back(std::move(cheat));
  }

  long rss_after_data = sample_peak_rss_kb();

  using clock = std::chrono::high_resolution_clock;
  using ns = std::chrono::nanoseconds;
  const double ns_to_ms = 1.0 / 1000000.0;

  /* ----- .cht save ----- */
  const auto tmp_cht = std::filesystem::temp_directory_path() / "memdbg_bench_cht.cht";
  (void)std::filesystem::remove(tmp_cht);
  long rss_before_cht_save = sample_peak_rss_kb();
  auto t0 = clock::now();
  bool ok_cht_save = save_trainer_file(state, tmp_cht.string());
  auto t1 = clock::now();
  long rss_after_cht_save = sample_peak_rss_kb();
  double cht_save_ms = static_cast<double>(std::chrono::duration_cast<ns>(t1 - t0).count()) * ns_to_ms;

  /* ----- .cht load ----- */
  long rss_after_cht_load;
  long rss_cht_load_delta;
  double cht_load_ms;
  int cht_loaded;
  {
    long rss_before_cht_load = sample_peak_rss_kb();
    AppState loaded_cht;
    loaded_cht.selected_pid = 100;
    loaded_cht.maps = state.maps;
    t0 = clock::now();
    cht_loaded = load_trainer_file(loaded_cht, tmp_cht.string());
    t1 = clock::now();
    rss_after_cht_load = sample_peak_rss_kb();
    cht_load_ms = static_cast<double>(std::chrono::duration_cast<ns>(t1 - t0).count()) * ns_to_ms;
    rss_cht_load_delta = (rss_after_cht_load >= 0 && rss_before_cht_load >= 0)
                             ? rss_after_cht_load - rss_before_cht_load : -1;
  }
  /* loaded_cht destroyed here. ru_maxrss is a peak metric so it won't go down,
     but freeing this memory before the JSON phase is still correct practice. */

  /* ----- .json save ----- */
  const auto tmp_json = std::filesystem::temp_directory_path() / "memdbg_bench_json.json";
  (void)std::filesystem::remove(tmp_json);
  long rss_before_json_save = sample_peak_rss_kb();
  t0 = clock::now();
  bool ok_json_save = save_trainer_file(state, tmp_json.string());
  t1 = clock::now();
  long rss_after_json_save = sample_peak_rss_kb();
  double json_save_ms = static_cast<double>(std::chrono::duration_cast<ns>(t1 - t0).count()) * ns_to_ms;

  /* ----- .json load ----- */
  long rss_before_json_load = sample_peak_rss_kb();
  AppState loaded_json;
  loaded_json.selected_pid = 100;
  loaded_json.maps = state.maps;
  t0 = clock::now();
  int json_loaded = load_trainer_file(loaded_json, tmp_json.string());
  t1 = clock::now();
  long rss_after_json_load = sample_peak_rss_kb();
  double json_load_ms = static_cast<double>(std::chrono::duration_cast<ns>(t1 - t0).count()) * ns_to_ms;

  /* Report */
  long rss_data_delta = (rss_after_data >= 0 && rss_before_data >= 0)
                            ? rss_after_data - rss_before_data : -1;
  std::printf("  %d cheats generated (%zu bytes in memory)\n", N,
              state.plugin.cheats.size() * sizeof(CheatEntry) + state.plugin.cheats.size() * 32);
  if (rss_data_delta >= 0)
    std::printf("  RSS delta (data gen):   %+7ld KiB  (peak: %ld KiB)\n", rss_data_delta, rss_after_data);

  std::printf("\n  --- .cht (pipe-delimited) ---\n");
  TEST("bench cht save", ok_cht_save);
  TEST("bench cht load count", cht_loaded == N);
  std::printf("        cht save: %8.2f ms  (%6.1f us/entry)\n", cht_save_ms,
              (cht_save_ms * 1000.0) / N);
  long rss_cht_save_delta = (rss_after_cht_save >= 0 && rss_before_cht_save >= 0)
                                ? rss_after_cht_save - rss_before_cht_save : -1;
  if (rss_cht_save_delta >= 0)
    std::printf("        RSS delta:    %+7ld KiB  (peak: %ld KiB)\n", rss_cht_save_delta, rss_after_cht_save);
  std::printf("        cht load: %8.2f ms  (%6.1f us/entry)\n", cht_load_ms,
              (cht_load_ms * 1000.0) / N);
  if (rss_cht_load_delta >= 0)
    std::printf("        RSS delta:    %+7ld KiB  (peak: %ld KiB)\n", rss_cht_load_delta, rss_after_cht_load);
  std::printf("        cht file: %8zu bytes\n",
              std::filesystem::file_size(tmp_cht));

  std::printf("\n  --- .json (GoldHEN) ---\n");
  TEST("bench json save", ok_json_save);
  TEST("bench json load count", json_loaded == N);
  std::printf("        json save: %8.2f ms  (%6.1f us/entry)\n", json_save_ms,
              (json_save_ms * 1000.0) / N);
  long rss_json_save_delta = (rss_after_json_save >= 0 && rss_before_json_save >= 0)
                                 ? rss_after_json_save - rss_before_json_save : -1;
  if (rss_json_save_delta >= 0)
    std::printf("        RSS delta:    %+7ld KiB  (peak: %ld KiB)\n", rss_json_save_delta, rss_after_json_save);
  std::printf("        json load: %8.2f ms  (%6.1f us/entry)\n", json_load_ms,
              (json_load_ms * 1000.0) / N);
  long rss_json_load_delta = (rss_after_json_load >= 0 && rss_before_json_load >= 0)
                                 ? rss_after_json_load - rss_before_json_load : -1;
  if (rss_json_load_delta >= 0)
    std::printf("        RSS delta:    %+7ld KiB  (peak: %ld KiB)\n", rss_json_load_delta, rss_after_json_load);
  std::printf("        json file: %8zu bytes\n",
              std::filesystem::file_size(tmp_json));

  std::printf("\n  --- Comparison ---\n");
  std::printf("        cht  total: %8.2f ms  (peak RSS: %ld KiB)\n", cht_save_ms + cht_load_ms, rss_after_cht_load);
  std::printf("        json total: %8.2f ms  (peak RSS: %ld KiB)\n", json_save_ms + json_load_ms, rss_after_json_load);
  std::printf("        json/cht speed ratio (total): %.2fx\n",
              (cht_save_ms + cht_load_ms) / (json_save_ms + json_load_ms + 0.001));

  /* Summary memory table */
  std::printf("\n  --- Memory Summary ---\n");
  std::printf("        %-20s %8s %8s %8s\n", "Phase", "Delta KiB", "Peak KiB", "File bytes");
  auto mem_row = [](const char *label, long delta, long peak, size_t file_sz) {
    std::printf("        %-20s %+8ld %8ld %8zu\n", label, delta, peak, file_sz);
  };
  mem_row("Data generation", rss_data_delta, rss_after_data, 0UL);
  mem_row("CHT save",         rss_cht_save_delta, rss_after_cht_save, std::filesystem::file_size(tmp_cht));
  mem_row("CHT load",         rss_cht_load_delta, rss_after_cht_load, 0UL);
  mem_row("JSON save",        rss_json_save_delta, rss_after_json_save, std::filesystem::file_size(tmp_json));
  mem_row("JSON load",        rss_json_load_delta, rss_after_json_load, 0UL);

  /* Cleanup */
  (void)std::filesystem::remove(tmp_cht);
  (void)std::filesystem::remove(tmp_json);
}

/* Compare nlohmann/json vs simdjson on the same GoldHEN JSON payload.
   Generates N entries, writes them as .json, then parses + iterates
   the file with each library, measuring wall-clock time and peak RSS. */
static void bench_json_libraries() {
  constexpr int N = 10000;
  std::printf("\n--- Bench: nlohmann/json vs simdjson (%d entries) ---\n", N);

  /* Generate GoldHEN JSON with N entries (reuse existing save pipeline). */
  AppState state;
  state.selected_pid = 100;
  state.has_process_info = true;
  state.selected_process_info.title_id = "CUSA00000";
  state.selected_process_info.name = "BenchGame";
  state.maps = {
      {0x100000, 0x500000, 7, 0, "code"},
      {0x500000, 0x900000, 5, 0, "data"},
  };

  const int value_types[] = {MEMDBG_VALUE_U8, MEMDBG_VALUE_U16, MEMDBG_VALUE_U32,
                             MEMDBG_VALUE_U64, MEMDBG_VALUE_BYTES};

  for (int i = 0; i < N; ++i) {
    CheatEntry cheat;
    cheat.description = "Bench cheat #" + std::to_string(i);
    cheat.pid = 100;
    cheat.address = 0x200000 + static_cast<uint64_t>(i) * 4;
    cheat.value_type = value_types[i % 5];
    cheat.locked = (i % 4 == 0);
    cheat.enabled = true;
    unsigned seed = static_cast<unsigned>(i * 0x9E3779B9ULL);
    int len = 1 + (i % 8);
    cheat.bytes.resize(static_cast<size_t>(len));
    for (int b = 0; b < len; ++b)
      cheat.bytes[static_cast<size_t>(b)] = static_cast<uint8_t>((seed >> (b * 8)) & 0xFF);
    cheat.value_text = bytes_to_hex(cheat.bytes);
    if (i % 3 == 0) {
      cheat.off_bytes = cheat.bytes;
      cheat.off_bytes[0] ^= 0xFF;
      cheat.has_off_bytes = true;
    }
    state.plugin.cheats.push_back(std::move(cheat));
  }

  const auto tmp =
      std::filesystem::temp_directory_path() / "memdbg_bench_libs.json";
  (void)std::filesystem::remove(tmp);
  TEST("lib bench generate JSON", save_trainer_file(state, tmp.string()));

  /* Read the file into a single std::string */
  std::ifstream in(tmp, std::ios::binary);
  std::string raw((std::istreambuf_iterator<char>(in)),
                   std::istreambuf_iterator<char>());
  in.close();

  using clock = std::chrono::high_resolution_clock;
  using ns = std::chrono::nanoseconds;
  const double ns_to_ms = 1.0 / 1000000.0;

  /* ===== nlohmann/json ===== */
  {
    long rss_before = sample_peak_rss_kb();
    auto t0 = clock::now();

    nlohmann::json json = nlohmann::json::parse(raw);
    int nlo_count = 0;
    if (json.contains("mods") && json["mods"].is_array()) {
      for (const auto &mod : json["mods"]) {
        if (!mod.contains("memory") || !mod["memory"].is_array()) continue;
        for (const auto &mem : mod["memory"]) {
          if (!mem.contains("on")) continue;
          std::string on_str;
          if (mem["on"].is_string())
            on_str = mem["on"].get<std::string>();
          else if (mem["on"].is_number_unsigned())
            on_str = std::to_string(mem["on"].get<uint64_t>());
          else
            continue;
          if (on_str.empty()) continue;
          nlo_count++;

          /* Same work as sJson path: hex→binary decode. */
          std::vector<uint8_t> bytes;
          parse_hex_bytes(on_str.c_str(), bytes);

          /* Also parse off bytes where present. */
          if (mem.contains("off")) {
            std::string off_str;
            if (mem["off"].is_string())
              off_str = mem["off"].get<std::string>();
            std::vector<uint8_t> off_bytes;
            parse_hex_bytes(off_str.c_str(), off_bytes);
          }
        }
      }
    }

    auto t1 = clock::now();
    long rss_after = sample_peak_rss_kb();
    double ms = static_cast<double>(std::chrono::duration_cast<ns>(t1 - t0).count()) * ns_to_ms;
    long rss_delta = (rss_after >= 0 && rss_before >= 0)
                         ? rss_after - rss_before : -1;

    std::printf("\n  --- nlohmann/json v3.11.3 ---\n");
    TEST("nlo parse+iterate count", nlo_count == N);
    std::printf("        parse+iterate: %8.2f ms  (%6.1f us/entry)\n", ms,
                (ms * 1000.0) / N);
    if (rss_delta >= 0)
      std::printf("        RSS delta:     %+7ld KiB  (peak: %ld KiB)\n",
                  rss_delta, rss_after);
  }

  /* ===== sJson v1.1.0 (C99, optimized) ===== */
  {
    long rss_before = sample_peak_rss_kb();

    /* Larger arena block (256 KiB) reduces allocator churn for 2.6 MB input.
       Created outside the timer — same treatment as simdjson padded_string. */
    JsonArena* arena = json_arena_create(nullptr, 256 * 1024);

    auto t0 = clock::now();

    JsonError s_err = JSON_OK;
    JsonValue* root = json_parse(arena, raw.data(), raw.size(), &s_err);

    int sjson_count = 0;
    std::vector<CheatEntry> sjson_entries;
    sjson_entries.reserve(static_cast<size_t>(N));

    /* Stack buffer for null-terminating sJson strings.
       Avoids 20,000+ heap allocations from std::string(on_str, on_len).
       Hex values are 2-16 chars (1-8 bytes) in our bench — 128 is ample. */
    char hex_buf[128];

    if (root && s_err == JSON_OK && json_is_object(root)) {
      JsonValue* mods = nullptr;
      if (json_obj_get(root, "mods", &mods) == JSON_OK &&
          json_is_array(mods)) {
        uint32_t mod_count = 0;
        json_get_arr_len(mods, &mod_count);

        for (uint32_t mi = 0; mi < mod_count; mi++) {
          JsonValue* mod = nullptr;
          if (json_arr_get(mods, mi, &mod) != JSON_OK ||
              !json_is_object(mod))
            continue;

          /* Use json_obj_iter to avoid 2× json_obj_get hash recomputation.
             Iterate once and match keys by first character + length. */
          const char* mod_name = nullptr;
          uint32_t mod_name_len = 0;
          JsonValue* memory = nullptr;
          uint32_t mod_pairs = 0;
          json_get_obj_len(mod, &mod_pairs);

          for (uint32_t ki = 0; ki < mod_pairs; ki++) {
            const char* key = nullptr;
            uint32_t klen = 0;
            JsonValue* val = nullptr;
            json_obj_iter(mod, ki, &key, &klen, &val);
            if (klen == 4 && key[0] == 'n') { /* "name" */
              json_get_string(val, &mod_name, &mod_name_len);
            } else if (klen == 6 && key[0] == 'm') { /* "memory" */
              memory = val;
            }
          }

          if (!memory || !json_is_array(memory)) continue;

          uint32_t mem_count = 0;
          json_get_arr_len(memory, &mem_count);

          for (uint32_t mei = 0; mei < mem_count; mei++) {
            JsonValue* mem = nullptr;
            if (json_arr_get(memory, mei, &mem) != JSON_OK ||
                !json_is_object(mem))
              continue;

            /* Iterate memory keys once instead of 3 separate json_obj_get
               calls (each recomputes FNV-1a hash + linear scan).
               Match by first letter + length for fast dispatch. */
            const char* on_str = nullptr;
            uint32_t on_len = 0;
            const char* off_str = nullptr;
            uint32_t off_len = 0;
            bool has_on = false, has_off = false;
            uint32_t mem_pairs = 0;
            json_get_obj_len(mem, &mem_pairs);

            for (uint32_t ki = 0; ki < mem_pairs; ki++) {
              const char* key = nullptr;
              uint32_t klen = 0;
              JsonValue* val = nullptr;
              json_obj_iter(mem, ki, &key, &klen, &val);
              if (klen == 2 && key[0] == 'o') { /* "on" */
                json_get_string(val, &on_str, &on_len);
                has_on = true;
              } else if (klen == 3 && key[0] == 'o') { /* "off" */
                json_get_string(val, &off_str, &off_len);
                has_off = true;
              }
            }

            if (!has_on) continue;
            sjson_count++;

            /* Stack buffer: avoid std::string heap allocation. */
            if (on_len < sizeof(hex_buf)) {
              memcpy(hex_buf, on_str, on_len);
              hex_buf[on_len] = '\0';
            }
            std::vector<uint8_t> bytes;
            if (parse_hex_bytes(
                    on_len < sizeof(hex_buf) ? hex_buf
                                             : std::string(on_str, on_len).c_str(),
                    bytes)) {
              CheatEntry cheat;
              if (mod_name && mod_name_len > 0) {
                memcpy(hex_buf, mod_name,
                       mod_name_len < sizeof(hex_buf) ? mod_name_len
                                                      : sizeof(hex_buf) - 1);
                hex_buf[mod_name_len < sizeof(hex_buf)
                            ? mod_name_len
                            : sizeof(hex_buf) - 1] = '\0';
                cheat.description = hex_buf;
              }
              cheat.pid = 100;
              cheat.bytes = std::move(bytes);
              cheat.value_text =
                  on_len < sizeof(hex_buf)
                      ? std::string(hex_buf)
                      : std::string(on_str, on_len);
              sjson_entries.push_back(std::move(cheat));
            }

            /* Off bytes (optional). */
            if (has_off) {
              if (off_len < sizeof(hex_buf)) {
                memcpy(hex_buf, off_str, off_len);
                hex_buf[off_len] = '\0';
              }
              std::vector<uint8_t> off_bytes;
              parse_hex_bytes(off_len < sizeof(hex_buf)
                                  ? hex_buf
                                  : std::string(off_str, off_len).c_str(),
                              off_bytes);
            }
          }
        }
      }
    }

    json_arena_destroy(arena);

    auto t1 = clock::now();
    long rss_after = sample_peak_rss_kb();
    double ms = static_cast<double>(std::chrono::duration_cast<ns>(t1 - t0).count()) * ns_to_ms;
    long rss_delta = (rss_after >= 0 && rss_before >= 0)
                         ? rss_after - rss_before : -1;

    std::printf("\n  --- sJson v1.1.0 (C99, optimized) ---\n");
    TEST("sjson parse+iterate count", sjson_count == N);
    std::printf("        parse+iterate: %8.2f ms  (%6.1f us/entry)\n", ms,
                (ms * 1000.0) / N);
    if (rss_delta >= 0)
      std::printf("        RSS delta:     %+7ld KiB  (peak: %ld KiB)\n",
                  rss_delta, rss_after);
  }

  /* ===== simdjson (ondemand) ===== */
  {
    long rss_before = sample_peak_rss_kb();
    auto t0 = clock::now();

    simdjson::ondemand::parser parser;
    /* Pre-pad outside the timer: nlohmann parses the raw std::string directly. */
    simdjson::padded_string padded(raw);
    simdjson::ondemand::document doc;
    int simd_count = 0;
    std::vector<CheatEntry> simd_entries;
    simd_entries.reserve(static_cast<size_t>(N));

    if (!parser.iterate(padded).get(doc)) {
      simdjson::ondemand::array mods;
      if (!doc["mods"].get_array().get(mods)) {
        for (auto mod : mods) {
          simdjson::ondemand::object mod_obj;
          if (mod.get_object().get(mod_obj)) continue;

          std::string_view name;
          if (mod_obj["name"].get_string().get(name)) continue;

          simdjson::ondemand::array memory;
          if (mod_obj["memory"].get_array().get(memory)) continue;

          for (auto mem : memory) {
            std::string_view offset_str, on_str, type_str;
            if (mem["offset"].get_string().get(offset_str)) continue;
            if (mem["on"].get_string().get(on_str)) continue;
            simd_count++;

            /* Do the same work that parse_goldhen_mods does:
               hex→binary decode of on_str and optional off_str.
               string_view::data() is not \0-terminated in simdjson's
               ondemand API; wrap in std::string for parse_hex_bytes. */
            std::vector<uint8_t> bytes;
            std::string on_copy(on_str);
            if (parse_hex_bytes(on_copy.c_str(), bytes)) {
              CheatEntry cheat;
              cheat.description = std::string(name);
              cheat.pid = 100;
              cheat.bytes = std::move(bytes);
              cheat.value_text = std::move(on_copy);
              simd_entries.push_back(std::move(cheat));
            }

            std::string_view off_str;
            if (!mem["off"].get_string().get(off_str)) {
              std::string off_copy(off_str);
              std::vector<uint8_t> off_bytes;
              parse_hex_bytes(off_copy.c_str(), off_bytes);
            }
            (void)mem["type"].get_string().get(type_str);
          }
        }
      }
    }

    auto t1 = clock::now();
    long rss_after = sample_peak_rss_kb();
    double ms = static_cast<double>(std::chrono::duration_cast<ns>(t1 - t0).count()) * ns_to_ms;
    long rss_delta = (rss_after >= 0 && rss_before >= 0)
                         ? rss_after - rss_before : -1;

    std::printf("\n  --- simdjson v3.11.4 (ondemand) ---\n");
    TEST("simdjson parse+iterate count", simd_count == N);
    std::printf("        parse+iterate: %8.2f ms  (%6.1f us/entry)\n", ms,
                (ms * 1000.0) / N);
    if (rss_delta >= 0)
      std::printf("        RSS delta:     %+7ld KiB  (peak: %ld KiB)\n",
                  rss_delta, rss_after);
  }

  /* Summary */
  std::printf("\n  --- File ---\n");
  std::printf("        JSON file size:  %8zu bytes\n",
              std::filesystem::file_size(tmp));

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
  test_goldhen_json_roundtrip_extended();
  test_goldhen_json_schema();
  test_pipe_delimited_roundtrip();
  test_pipe_delimited_no_maps_roundtrip();
  test_parse_goldhen_mods_variants();
  test_malformed_cht();
  bench_trainer_formats();
  bench_json_libraries();

  std::printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  std::printf("Total:  %d\n", total);
  std::printf("Passed: %d\n", g_passed);
  std::printf("Failed: %d\n", g_failed);
  std::printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}

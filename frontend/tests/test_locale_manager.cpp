/*
 * MemDBG - Locale manager tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "locale/locale.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace memdbg::frontend::locale {
namespace {

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

#define TEST_STR(name, actual, expected)                                       \
  TEST(name, std::strcmp((actual), (expected)) == 0)

static void write_file(const std::filesystem::path &path, const char *text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << text;
}

static void test_memory_loading() {
  std::printf("\n--- memory locale loading ---\n");
  auto &mgr = Manager::instance();

  static constexpr const char kEnglish[] =
      R"({"_meta":{"code":"en"},"hello":"Hello","same":"Same","only_en":"English fallback"})";
  static constexpr const char kItalian[] =
      R"({"_meta":{"code":"it"},"hello":"Ciao","same":"Same"})";
  static constexpr const char kInvalid[] =
      R"({"_meta":{"code":"fr"},"hello":42})";

  TEST("load embedded English",
       mgr.load_mem("en.json", reinterpret_cast<const unsigned char *>(kEnglish),
                    sizeof(kEnglish) - 1U));
  TEST("load downloaded Italian",
       mgr.load_mem("it.json", reinterpret_cast<const unsigned char *>(kItalian),
                    sizeof(kItalian) - 1U));
  TEST("reject non-string locale value",
       !mgr.load_mem("fr.json", reinterpret_cast<const unsigned char *>(kInvalid),
                     sizeof(kInvalid) - 1U));

  TEST("set Italian active", mgr.set_active(Lang::IT));
  TEST_STR("translated key", mgr.get("hello"), "Ciao");
  TEST_STR("English fallback key", mgr.get("only_en"), "English fallback");
  TEST_STR("unknown key fallback", mgr.get("missing"), "missing");
  TEST("English progress", mgr.translation_progress(Lang::EN) == 100);
  TEST("Italian progress counts changed strings",
       mgr.translation_progress(Lang::IT) == 33);
}

static void test_file_loading() {
  std::printf("\n--- file locale loading ---\n");
  auto &mgr = Manager::instance();
  const auto path = std::filesystem::temp_directory_path() / "es.json";
  write_file(path, R"({"_meta":{"code":"es"},"hello":"Hola","same":"Igual","only_en":"Fallback ES"})");

  TEST("load locale from file", mgr.load(path.string().c_str()));
  TEST("set Spanish active", mgr.set_active(Lang::ES));
  TEST_STR("file locale key", mgr.get("hello"), "Hola");

  std::error_code ec;
  std::filesystem::remove(path, ec);
}

} // namespace

int run_tests() {
  std::printf("MemDBG Locale Manager Tests\n");
  test_memory_loading();
  test_file_loading();

  std::printf("\nSummary: %d passed, %d failed\n", g_passed, g_failed);
  return g_failed == 0 ? 0 : 1;
}

} // namespace memdbg::frontend::locale

int main() {
  return memdbg::frontend::locale::run_tests();
}

/*
 * MemDBG - Action journal unit tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests: open/close, record, load_recent, json_escape, crash_report_url.
 */

#include "action_journal.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

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
      std::printf("  FAIL  %s  (got \"%s\", expected \"%s\")\n", name,        \
                  std::string(_a).c_str(), std::string(_e).c_str());           \
    }                                                                          \
  } while (0)

static std::filesystem::path temp_journal_path() {
  auto tmp = std::filesystem::temp_directory_path() /
             "memdbg_test_journal.log";
  std::error_code ec;
  std::filesystem::remove(tmp, ec);
  return tmp;
}

/* ── open / close ─────────────────────────────────────────────────────── */

static void test_open_close() {
  std::printf("\n--- open / close ---\n");
  auto path = temp_journal_path();
  ActionJournal journal;

  /* Open with valid path */
  bool opened = journal.open(path.string().c_str());
  TEST("open succeeds with valid path", opened);
  TEST("is_open after open", journal.is_open());
  TEST("enabled after open", journal.enabled());

  /* Close */
  journal.close();
  TEST("is_open false after close", !journal.is_open());
  TEST("enabled false after close", !journal.enabled());

  /* File should exist and contain session markers */
  std::error_code ec;
  bool exists = std::filesystem::exists(path, ec);
  TEST("journal file exists after open/close", exists);

  if (exists) {
    std::ifstream in(path);
    std::string first_line, last_line;
    std::getline(in, first_line);
    std::string line;
    while (std::getline(in, line))
      last_line = line;
    TEST("first line is session_start",
         first_line.find("\"session_start\"") != std::string::npos);
    TEST("last line is clean_shutdown",
         last_line.find("\"clean_shutdown\"") != std::string::npos);
  }

  /* Open with null/empty path should fail */
  ActionJournal j2;
  TEST("open with nullptr fails", !j2.open(nullptr));
  TEST("open with empty string fails", !j2.open(""));

  /* Clean up */
  std::filesystem::remove(path, ec);
}

/* ── record ───────────────────────────────────────────────────────────── */

static void test_record() {
  std::printf("\n--- record ---\n");
  auto path = temp_journal_path();
  ActionJournal journal;

  journal.open(path.string().c_str());

  /* Record a simple action */
  journal.record("test_action", "{\"key\":\"value\"}");
  journal.record("another_action", "{\"num\":42}");

  /* Record with null detail -> should default to {} */
  journal.record("null_detail", nullptr);

  /* record when disabled should silently skip */
  journal.set_enabled(false);
  journal.record("should_not_appear", "{}");
  journal.set_enabled(true);
  journal.record("after_reenable", "{}");

  journal.close();

  /* Load back and verify */
  std::vector<ActionJournalEntry> entries;
  ActionJournal::load_recent(path, entries, 100);

  TEST("4 user entries recorded", entries.size() == 4U);

  if (entries.size() >= 4U) {
    TEST("first action name", entries[0].action == "test_action");
    TEST("first action detail", entries[0].detail.find("\"key\"") != std::string::npos);

    TEST("second action name", entries[1].action == "another_action");
    TEST("second action detail", entries[1].detail.find("\"num\"") != std::string::npos);

    TEST("null detail defaults to empty",
         entries[2].action == "null_detail" &&
             (entries[2].detail == "{}" || entries[2].detail.empty()));

    TEST("skip disabled entry", entries[3].action == "after_reenable");
  }

  /* Clean up */
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

/* ── load_recent ──────────────────────────────────────────────────────── */

static void test_load_recent() {
  std::printf("\n--- load_recent ---\n");
  auto path = temp_journal_path();

  /* Manually write 10 entries to the journal file */
  {
    ActionJournal journal;
    journal.open(path.string().c_str());
    for (int i = 0; i < 10; ++i) {
      std::string detail = "{\"idx\":" + std::to_string(i) + "}";
      journal.record("step", detail.c_str());
    }
    journal.close();
  }

  /* Load last 5 entries */
  {
    std::vector<ActionJournalEntry> entries;
    bool clean = false;
    bool loaded = ActionJournal::load_recent(path, entries, 5, &clean);

    TEST("load_recent succeeds", loaded);
    TEST("clean_shutdown detected", clean);
    TEST("only last 5 entries", entries.size() == 5U);

    if (entries.size() == 5U) {
      TEST("first loaded entry has idx=5",
           entries[0].detail.find("\"idx\":5") != std::string::npos);
      TEST("last loaded entry has idx=9",
           entries[4].detail.find("\"idx\":9") != std::string::npos);
    }
  }

  /* Load with max_entries larger than actual -> should get all 10 */
  {
    std::vector<ActionJournalEntry> entries;
    ActionJournal::load_recent(path, entries, 500);
    TEST("load all entries with large max", entries.size() == 10U);
  }

  /* Load nonexistent file -> should return false */
  {
    std::vector<ActionJournalEntry> entries;
    bool loaded = ActionJournal::load_recent("/nonexistent/path/xyz.log",
                                             entries, 100);
    TEST("load_recent fails on nonexistent file", !loaded);
    TEST("entries empty on failure", entries.empty());
  }

  /* Detect unclean shutdown: write entries without clean_shutdown marker */
  {
    auto unclean_path =
        std::filesystem::temp_directory_path() / "memdbg_test_unclean.log";
    std::error_code ec;
    std::filesystem::remove(unclean_path, ec);

    /* Craft a file with session_start but no clean_shutdown */
    std::ofstream out(unclean_path);
    out << R"({"ts":1000,"action":"session_start","detail":{}})" << "\n";
    out << R"({"ts":1001,"action":"user_action","detail":{"key":"val"}})" << "\n";
    out.close();

    std::vector<ActionJournalEntry> entries;
    bool clean = true;
    ActionJournal::load_recent(unclean_path, entries, 100, &clean);
    TEST("unclean shutdown detected", !clean);
    TEST("entry loaded from unclean file", entries.size() == 1U);
    if (entries.size() >= 1U)
      TEST("entry is user_action", entries[0].action == "user_action");

    std::filesystem::remove(unclean_path, ec);
  }

  /* Clean up */
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

/* ── json_escape ──────────────────────────────────────────────────────── */

static void test_json_escape() {
  std::printf("\n--- json_escape ---\n");

  /* Normal strings pass through */
  std::string normal = ActionJournal::json_escape("hello world");
  TEST("normal string unchanged", normal == "hello world");

  /* Double quotes escaped */
  std::string quotes = ActionJournal::json_escape("say \"hi\"");
  TEST("double quotes escaped", quotes == "say \\\"hi\\\"");

  /* Backslash escaped */
  std::string bs = ActionJournal::json_escape("C:\\path\\to");
  TEST("backslashes escaped", bs == "C:\\\\path\\\\to");

  /* Control characters escaped */
  std::string ctrl = ActionJournal::json_escape("line1\nline2\tend");
  TEST("newline escaped", ctrl.find("\\n") != std::string::npos);
  TEST("tab escaped", ctrl.find("\\t") != std::string::npos);

  /* Empty string */
  std::string empty = ActionJournal::json_escape("");
  TEST("empty string stays empty", empty.empty());

  /* Mixed: quotes, backslashes, newlines */
  std::string mixed = ActionJournal::json_escape("a\"b\\c\nd");
  TEST("mixed escaping", mixed == "a\\\"b\\\\c\\nd");

  /* Low byte (< 0x20) gets \\uXXXX */
  std::string bell = ActionJournal::json_escape("\x07"); /* BEL char */
  TEST("BEL escaped to \\u0007", bell == "\\u0007");

  /* All printable ASCII passes through */
  std::string printable;
  for (char c = ' '; c <= '~'; ++c)
    printable.push_back(c);
  std::string escaped = ActionJournal::json_escape(printable);
  /* Only backslash and double-quote among printable ASCII need escaping */
  TEST("printable length preserved", escaped.size() >= printable.size());
  /* Verify that 'A', 'z', '0' passed through unchanged */
  TEST("A passes through", escaped.find('A') != std::string::npos);
  TEST("space passes through", escaped.find(' ') != std::string::npos);
}

/* ── crash_report_url ─────────────────────────────────────────────────── */

static void test_crash_report_url() {
  std::printf("\n--- crash_report_url ---\n");

  std::vector<ActionJournalEntry> actions;

  /* Empty actions -> should still return a valid URL */
  {
    std::string url = ActionJournal::build_crash_report_url(
        actions, "1.0.0", "macOS 14", true, true);
    TEST("empty actions still produces URL",
         url.find("github.com/seregonwar/MemDBG/issues/new") !=
             std::string::npos);
    TEST("template is console_crash.yml",
         url.find("template=console_crash.yml") != std::string::npos);
    TEST("title is URL-encoded",
         url.find("title=") != std::string::npos);
    TEST("body contains version",
         url.find("1.0.0") != std::string::npos || url.find("1%2E0%2E0") != std::string::npos);
  }

  /* Build actions for crash scenario */
  {
    ActionJournalEntry e1;
    e1.timestamp = 1000;
    e1.action = "connect";
    e1.detail = R"({"host":"192.168.1.100","port":9020})";
    actions.push_back(e1);

    ActionJournalEntry e2;
    e2.timestamp = 1001;
    e2.action = "process_select";
    e2.detail = R"({"pid":1234,"name":"eboot.bin"})";
    actions.push_back(e2);

    ActionJournalEntry e3;
    e3.timestamp = 1002;
    e3.action = "scan_exact";
    e3.detail = R"({"type":"u32","op":"eq","value":"42"})";
    actions.push_back(e3);
  }

  /* With anonymize=true (default) */
  {
    std::string url = ActionJournal::build_crash_report_url(
        actions, "2.0.0", "Windows 11", true, true);
    TEST("anonymized URL contains build info",
         url.find("2.0.0") != std::string::npos || url.find("2%2E0%2E0") != std::string::npos);
    TEST("anonymized host is redacted",
         url.find("192.168") == std::string::npos);
    TEST("anonymized PID is replaced",
         url.find("1234") == std::string::npos);
    TEST("anonymized process name is redacted",
         url.find("eboot.bin") == std::string::npos);
    TEST("anonymized scan type is preserved (not sensitive)",
         url.find("u32") != std::string::npos);
    TEST("scan op preserved", url.find("eq") != std::string::npos);
  }

  /* With anonymize=false (raw) */
  {
    std::string url = ActionJournal::build_crash_report_url(
        actions, "3.0.0", "Linux", false, true);
    TEST("raw URL contains host",
         url.find("192.x.x.x") == std::string::npos &&
         url.find("192.168.1.100") != std::string::npos);
    TEST("raw URL contains PID",
         url.find("1234") != std::string::npos);
  }

  /* With include_telemetry=false */
  {
    std::string url = ActionJournal::build_crash_report_url(
        actions, "1.0.0", "macOS", false, false);
    TEST("no-telemetry URL still contains action names",
         url.find("connect") != std::string::npos);
    /* Detail params should not appear in reproduction steps */
    TEST("no-telemetry hides host in steps",
         url.find("host=192") == std::string::npos);
  }
}

/* ── record_marker ────────────────────────────────────────────────────── */

static void test_record_marker() {
  std::printf("\n--- record_marker ---\n");
  auto path = temp_journal_path();
  ActionJournal journal;

  journal.open(path.string().c_str());
  journal.record_marker("custom_marker");
  journal.close();

  std::vector<ActionJournalEntry> entries;
  ActionJournal::load_recent(path, entries, 100);

  /* session_start and clean_shutdown are excluded from load_recent,
     so only custom_marker remains */
  TEST("custom marker recorded", entries.size() == 1U);
  if (entries.size() >= 1U)
    TEST("custom marker name", entries[0].action == "custom_marker");

  std::error_code ec;
  std::filesystem::remove(path, ec);
}

static void test_clear_active_journal() {
  std::printf("\n--- clear_active_journal ---\n");
  auto path = temp_journal_path();
  ActionJournal journal;
  TEST("open before clear", journal.open(path.string().c_str()));
  journal.record("old_entry", "{}");
  TEST("clear active journal", journal.clear());
  journal.record("new_entry", "{}");
  journal.close();

  std::vector<ActionJournalEntry> entries;
  bool clean = false;
  ActionJournal::load_recent(path, entries, 100, &clean);
  TEST("clear removes old entries",
       entries.size() == 1U && entries[0].action == "new_entry");
  TEST("cleared journal closes cleanly", clean);
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

/* ── set_enabled toggle ───────────────────────────────────────────────── */

static void test_set_enabled() {
  std::printf("\n--- set_enabled ---\n");
  auto path = temp_journal_path();
  ActionJournal journal;

  /* enabled() should be false before open */
  TEST("enabled false before open", !journal.enabled());

  journal.open(path.string().c_str());
  TEST("enabled true after open", journal.enabled());

  journal.set_enabled(false);
  TEST("enabled false after set_enabled(false)", !journal.enabled());
  TEST("is_open still true when disabled", journal.is_open());

  journal.set_enabled(true);
  TEST("enabled true after re-enable", journal.enabled());

  journal.close();

  std::error_code ec;
  std::filesystem::remove(path, ec);
}

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::printf("=== Action Journal Unit Tests ===\n");
  test_open_close();
  test_record();
  test_load_recent();
  test_json_escape();
  test_crash_report_url();
  test_record_marker();
  test_clear_active_journal();
  test_set_enabled();

  std::printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  std::printf("Total:  %d\n", total);
  std::printf("Passed: %d\n", g_passed);
  std::printf("Failed: %d\n", g_failed);
  std::printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}

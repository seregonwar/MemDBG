/*
 * MemDBG - Action journal implementation (uses sjson for all JSON operations).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "action_journal.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

#include "core/platform.hpp"

/* ── sjson (single-header C99 JSON, already compiled once by CMake) ─── */
extern "C" {
#include "sJson.c"
}

namespace memdbg::frontend {

/* ── Helpers: build a simple JSON object for a journal entry ───────────── */

/*
 * Write a JSON line to `fp` of the form:
 *   {"ts":<epoch>,"action":"<action>","detail":<detail_json>}
 *
 * `detail_json` must be a valid JSON object string, e.g. `{"host":"192.168.1.1"}`.
 * We parse it into a JsonValue so sjson handles all escaping on serialisation.
 */
static void write_json_line(std::FILE *fp, std::time_t ts,
                            const char *action, const char *detail_json) {
  JsonArena *arena = json_arena_create(nullptr, 4096);
  if (!arena) return;

  JsonValue *root = json_make_object(arena);
  if (!root) { json_arena_destroy(arena); return; }

  json_obj_setz(root, arena, "ts", json_make_int(arena, static_cast<int64_t>(ts)));
  json_obj_setz(root, arena, "action", json_make_stringz(arena, action));

  /* Parse detail_json so sjson handles escaping on write */
  JsonError err;
  JsonValue *detail_val = json_parse_cstr(arena, detail_json, &err);
  if (!detail_val || err != JSON_OK) {
    detail_val = json_make_object(arena);  // fallback to empty object
  }
  json_obj_setz(root, arena, "detail", detail_val);

  /* Serialize to buffer; fall back to truncated detail on overflow */
  size_t written = 0;
  char buf[4096];
  JsonWriteOpts opts{};
  err = json_write(root, buf, sizeof(buf) - 2, &written, &opts);
  if (err == JSON_ERR_BUFFER_TOO_SMALL) {
    /* Detail too large — retry with an empty detail object */
    json_obj_setz(root, arena, "detail", json_make_object(arena));
    err = json_write(root, buf, sizeof(buf) - 2, &written, &opts);
  }
  if (err == JSON_OK) {
    buf[written] = '\n';
    buf[written + 1] = '\0';
    std::fwrite(buf, 1, written + 1, fp);
  }

  json_arena_destroy(arena);
}

/* ── Construction / destruction ─────────────────────────────────────────── */

ActionJournal::ActionJournal() = default;

ActionJournal::~ActionJournal() {
  close();
}

/* ── Public API ────────────────────────────────────────────────────────── */

std::filesystem::path ActionJournal::default_path() {
  return platform::app_data_dir() / "logs" / "memdbg_actions.log";
}

bool ActionJournal::open(const char *journal_path) {
  close();

  if (!journal_path || journal_path[0] == '\0') return false;

  try {
    std::filesystem::path p(journal_path);
    if (p.has_parent_path()) {
      std::error_code ec;
      std::filesystem::create_directories(p.parent_path(), ec);
    }
  } catch (...) { return false; }

  std::FILE *fp = std::fopen(journal_path, "a");
  if (!fp) return false;

  std::lock_guard<std::mutex> lock(mutex_);
  file_      = static_cast<void *>(fp);
  file_open_ = true;
  path_ = std::filesystem::path(journal_path);
  enabled_.store(true);

  write_json_line(fp, std::time(nullptr), "session_start", "{}");
  std::fflush(fp);

  return true;
}

void ActionJournal::close() {
  std::lock_guard<std::mutex> lock(mutex_);

  if (file_open_ && file_ != nullptr) {
    auto *fp = static_cast<std::FILE *>(file_);
    write_json_line(fp, std::time(nullptr), "clean_shutdown", "{}");
    std::fflush(fp);
    std::fclose(fp);
    file_      = nullptr;
    file_open_ = false;
  }
  enabled_.store(false);
}

void ActionJournal::record(const char *action, const char *detail) {
  if (!enabled_.load()) return;
  if (!action || action[0] == '\0') return;

  std::lock_guard<std::mutex> lock(mutex_);
  if (!file_open_ || file_ == nullptr) return;

  auto *fp = static_cast<std::FILE *>(file_);

  const char *safe_detail = (detail && detail[0] != '\0') ? detail : "{}";
  write_json_line(fp, std::time(nullptr), action, safe_detail);
  std::fflush(fp);
}

void ActionJournal::record_marker(const char *marker) {
  if (!marker || marker[0] == '\0') return;
  record(marker, "{}");
}

bool ActionJournal::is_open() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return file_open_ && file_ != nullptr;
}

bool ActionJournal::clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!file_open_ || file_ == nullptr || path_.empty()) return false;

  auto *old = static_cast<std::FILE *>(file_);
  std::fflush(old);
  std::fclose(old);
  file_ = nullptr;
  file_open_ = false;

  std::FILE *fresh = std::fopen(path_.string().c_str(), "w");
  if (fresh == nullptr) {
    enabled_.store(false);
    return false;
  }
  file_ = static_cast<void *>(fresh);
  file_open_ = true;
  enabled_.store(true);
  write_json_line(fresh, std::time(nullptr), "session_start", "{}");
  std::fflush(fresh);
  return true;
}

/* ── Static helpers ────────────────────────────────────────────────────── */

/*
 * Parse a single JSON journal line and populate an ActionJournalEntry.
 * Returns true on success.
 */
static bool parse_journal_line(const std::string &line, ActionJournalEntry &entry) {
  JsonArena *arena = json_arena_create(nullptr, 4096);
  if (!arena) return false;

  JsonError err;
  JsonValue *root = json_parse(arena, line.c_str(), line.size(), &err);
  if (!root || err != JSON_OK) {
    json_arena_destroy(arena);
    return false;
  }

  /* Extract "ts" (integer) */
  JsonValue *ts_val = nullptr;
  if (json_obj_get(root, "ts", &ts_val) == JSON_OK && ts_val) {
    int64_t ts = 0;
    if (json_get_int(ts_val, &ts) == JSON_OK) {
      entry.timestamp = static_cast<std::time_t>(ts);
    }
  }

  /* Extract "action" (string) */
  JsonValue *act_val = nullptr;
  if (json_obj_get(root, "action", &act_val) == JSON_OK && act_val) {
    const char *s = nullptr;
    uint32_t slen = 0;
    if (json_get_string(act_val, &s, &slen) == JSON_OK && s && slen > 0) {
      entry.action.assign(s, slen);
    }
  }

  /* Extract "detail" (object) — reserialize to compact JSON string */
  JsonValue *det_val = nullptr;
  if (json_obj_get(root, "detail", &det_val) == JSON_OK && det_val &&
      json_is_object(det_val)) {
    char buf[2048];
    size_t written = 0;
    if (json_write(det_val, buf, sizeof(buf) - 1, &written, nullptr) == JSON_OK) {
      buf[written] = '\0';
      entry.detail = buf;
    }
  }

  json_arena_destroy(arena);
  return !entry.action.empty();
}

bool ActionJournal::load_recent(const std::filesystem::path &path,
                                std::vector<ActionJournalEntry> &out_entries,
                                size_t max_entries,
                                bool *out_clean_shutdown) {
  out_entries.clear();
  if (out_clean_shutdown) *out_clean_shutdown = false;

  std::ifstream in(path);
  if (!in) return false;

  std::string line;
  std::deque<ActionJournalEntry> recent_entries;

  while (std::getline(in, line)) {
    if (line.empty()) continue;

    ActionJournalEntry entry;
    if (parse_journal_line(line, entry)) {
      if (entry.action == "session_start") {
        if (out_clean_shutdown) *out_clean_shutdown = false;
        continue;
      }
      if (entry.action == "clean_shutdown") {
        if (out_clean_shutdown) *out_clean_shutdown = true;
        continue;
      }
      if (max_entries == 0U) continue;
      recent_entries.push_back(std::move(entry));
      if (recent_entries.size() > max_entries) recent_entries.pop_front();
    }
  }

  out_entries.assign(recent_entries.begin(), recent_entries.end());

  return true;
}

/* ── JSON string escaping ──────────────────────────────────────────────── */

std::string ActionJournal::json_escape(const std::string &value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (unsigned char c : value) {
    switch (c) {
    case '"':  out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\b': out += "\\b";  break;
    case '\f': out += "\\f";  break;
    case '\n': out += "\\n";  break;
    case '\r': out += "\\r";  break;
    case '\t': out += "\\t";  break;
    default:
      if (c < 0x20U) {
        char hex[8];
        std::snprintf(hex, sizeof(hex), "\\u%04X", static_cast<unsigned>(c));
        out += hex;
      } else {
        out.push_back(static_cast<char>(c));
      }
      break;
    }
  }
  return out;
}

/* ── URL encoding ──────────────────────────────────────────────────────── */

static std::string url_encode(const std::string &value) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (char c : value) {
    if (std::isalnum(static_cast<unsigned char>(c)) ||
        c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    } else if (c == ' ') {
      escaped << '+';
    } else {
      escaped << '%' << std::setw(2)
              << static_cast<int>(static_cast<unsigned char>(c));
    }
  }
  return escaped.str();
}

/*
 * Parse the `detail` JSON string and extract a string field by key.
 * Returns empty string if not found or not a string.
 */
static std::string detail_field(const std::string &detail, const char *key) {
  if (detail.empty() || detail == "{}") return {};

  JsonArena *arena = json_arena_create(nullptr, 2048);
  if (!arena) return {};

  JsonError err;
  JsonValue *root = json_parse_cstr(arena, detail.c_str(), &err);
  if (!root || err != JSON_OK) {
    json_arena_destroy(arena);
    return {};
  }

  std::string result;
  JsonValue *val = nullptr;
  if (json_obj_get(root, key, &val) == JSON_OK && val && json_is_string(val)) {
    const char *s = nullptr;
    uint32_t slen = 0;
    if (json_get_string(val, &s, &slen) == JSON_OK && s && slen > 0) {
      result.assign(s, slen);
    }
  } else if (val != nullptr && json_is_integer(val)) {
    int64_t number = 0;
    if (json_get_int(val, &number) == JSON_OK)
      result = std::to_string(number);
  }

  json_arena_destroy(arena);
  return result;
}

/* ── Anonymization ─────────────────────────────────────────────────────── */

/* Sensitive keys whose values should be redacted when anonymize=true. */
static bool is_sensitive_key(const char *key) {
  return std::strcmp(key, "host") == 0 ||
         std::strcmp(key, "pid") == 0 ||
         std::strcmp(key, "name") == 0 ||
         std::strcmp(key, "path") == 0;
}

/* Redact IP addresses: replace each octet beyond the first with "x" */
static std::string redact_ip(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  int dots = 0;
  for (char c : value) {
    if (c == '.') {
      dots++;
      out.push_back('.');
    } else if (dots >= 1 && c >= '0' && c <= '9') {
      out.push_back('x');
    } else {
      out.push_back(c);
    }
  }
  return out;
}

/* Redact filesystem paths: keep only the last component */
static std::string redact_path(const std::string &value) {
  auto pos = value.find_last_of("/\\");
  if (pos != std::string::npos && pos + 1 < value.size())
    return "[REDACTED]/" + value.substr(pos + 1);
  return "[REDACTED]";
}

static std::string anonymize_value(const char *key, const std::string &value) {
  if (!is_sensitive_key(key)) return value;
  if (std::strcmp(key, "host") == 0) return redact_ip(value);
  if (std::strcmp(key, "pid") == 0) return "[PID]";
  if (std::strcmp(key, "name") == 0) return "[PROCESS]";
  if (std::strcmp(key, "path") == 0) return redact_path(value);
  if (std::strcmp(key, "version") == 0) return value;  // keep version
  return value;
}

std::string ActionJournal::build_crash_report_url(
    const std::vector<ActionJournalEntry> &actions,
    const char *version_string,
    const char *platform_name,
    bool anonymize,
    bool include_telemetry) {

  /* Build reproduction steps from actions */
  std::string steps;
  {
    int step_num = 1;
    for (const auto &entry : actions) {
      steps += std::to_string(step_num) + ". " + entry.action;

      if (include_telemetry && !entry.detail.empty() && entry.detail != "{}") {
        steps += " — ";
        auto add = [&](const char *key, const char *label) {
          std::string val = detail_field(entry.detail, key);
          if (!val.empty()) {
            if (anonymize) val = anonymize_value(key, val);
            if (!steps.empty() && steps.back() != '\n') steps += ", ";
            steps += std::string(label) + "=" + val;
          }
        };
        add("host", "host");
        add("pid", "pid");
        add("name", "name");
        add("type", "type");
        add("op", "op");
      }
      steps += "\n";
      step_num++;
    }
  }

  /* Figure out which operation triggered the crash */
  std::string last_op = "Other";
  if (!actions.empty()) {
    const auto &last = actions.back().action;
    if (last.find("scan") != std::string::npos || last == "scan_exact" ||
        last == "scan_aob" || last == "scan_pointer" || last == "scan_unknown") {
      if (last.find("aob") != std::string::npos) last_op = "AOB scan";
      else if (last.find("pointer") != std::string::npos) last_op = "Pointer scan";
      else if (last.find("unknown") != std::string::npos) last_op = "Unknown initial value scan";
      else last_op = "Exact scan";
    } else if (last == "connect") last_op = "Connect / HELLO";
    else if (last == "disconnect") last_op = "Shutdown";
    else if (last.find("process") != std::string::npos) last_op = "Process list";
    else if (last.find("memory_read") != std::string::npos) last_op = "Memory read";
    else if (last.find("memory_write") != std::string::npos) last_op = "Memory write";
    else if (last.find("debugger") != std::string::npos) last_op = "Debugger attach / stop / continue";
    else if (last.find("telemetry") != std::string::npos) last_op = "Telemetry / discovery";
  }

  /* Determine platform */
  std::string platform = "PS5";
  for (const auto &e : actions) {
    std::string p = detail_field(e.detail, "platform");
    if (p == "PS4") { platform = "PS4"; break; }
  }

  std::string title = "[Crash]: " + last_op + " caused frontend crash";

  std::string body;
  body += "### Platform\n\n" + platform + "\n\n";
  body += "### Firmware / environment\n\n<!-- Please fill in -->\n\n";
  body += "### MemDBG build\n\n" + std::string(version_string) + " on " + platform_name + "\n\n";
  body += "### Operation that triggered the crash\n\n" + last_op + "\n\n";
  body += "### Target process and range\n\n<!-- Please fill in -->\n\n";
  body += "### Exact reproduction path\n\n" + steps + "\n";
  body += "### Crash behavior\n\n"
          "Frontend crashed unexpectedly. The action journal recorded the steps above.\n"
          "Crash log: `memdbg_crash.log`\n"
          "Action log: `memdbg_actions.log`\n\n";
  body += "### Diagnostics\n\n"
          "```\n<!-- Paste crash log contents here -->\n```\n\n";

  std::string url = "https://github.com/seregonwar/MemDBG/issues/new"
                    "?template=console_crash.yml"
                    "&title=" + url_encode(title) +
                    "&body=" + url_encode(body);

  return url;
}

} // namespace memdbg::frontend

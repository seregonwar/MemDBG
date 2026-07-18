/*
 * MemDBG - protocol probe using the frontend client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Exercises every protocol command against a running payload.
 * Usage: memdbg_probe [host] [port]
 */

#include "core/client/memdbg_client.hpp"
#include "memdbg/core/memdbg.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

/* ---- Test runner ---- */

static int g_passed = 0;
static int g_failed = 0;
static int g_skipped = 0;

struct TestResult {
  const char *name;
  bool ok;
  bool skipped;
  std::string detail;
};

static std::vector<TestResult> g_results;

static void record(const char *name, bool ok, bool skipped,
                   const std::string &detail) {
  g_results.push_back({name, ok, skipped, detail});
  if (skipped) {
    ++g_skipped;
    std::cout << "  SKIP  " << name << " — " << detail << "\n";
  } else if (ok) {
    ++g_passed;
    std::cout << "  PASS  " << name;
    if (!detail.empty()) std::cout << "  (" << detail << ")";
    std::cout << "\n";
  } else {
    ++g_failed;
    std::cout << "  FAIL  " << name;
    if (!detail.empty()) std::cout << " — " << detail;
    std::cout << "\n";
  }
}

#define TEST(name, expr)                                                       \
  do {                                                                         \
    bool _ok = (expr);                                                         \
    std::string _detail;                                                       \
    if (!_ok)                                                                  \
      _detail = client.last_error();                                           \
    record(name, _ok, false, _detail);                                         \
  } while (0)

#define TEST_SKIP(name, reason) record(name, false, true, reason)

/* ---- Helpers ---- */

static std::string fmt_hex(uint64_t a) {
  char b[32];
  std::snprintf(b, sizeof(b), "%llx", (unsigned long long)a);
  return std::string(b);
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  std::string host = argc > 1 ? argv[1] : "127.0.0.1";
  uint16_t port = argc > 2
                      ? static_cast<uint16_t>(std::strtoul(argv[2], nullptr, 10))
                      : 9020;

  memdbg::frontend::Client client;

  std::cout << "=== memDBG Protocol Probe ===\n";
  std::cout << "Target: " << host << ":" << port << "\n\n";

  /* ----------------------------------------------------------------
   *  1. CONNECT  (precondition)
   * ---------------------------------------------------------------- */
  if (!client.connect_to(host, port)) {
    std::cerr << "FATAL: connect failed: " << client.last_error() << "\n";
    return 1;
  }
  record("CONNECT", true, false, "");

  /* ----------------------------------------------------------------
   *  2. HELLO
   * ---------------------------------------------------------------- */
  memdbg::frontend::HelloInfo hello;
  {
    bool hello_ok = client.hello(hello);
    record("HELLO", hello_ok, false, hello_ok ? "" : client.last_error());
    if (hello_ok) {
      std::cout << "        payload=" << hello.name << " v" << hello.version
                << "  platform="
                << memdbg::frontend::platform_name(hello.platform_id)
                << "  protocol=feature-v" << hello.feature_level
                << " (wire-v" << hello.protocol_version << ")\n";
      std::cout << "        caps="
                << memdbg::frontend::capability_text(hello.capabilities) << "\n";
      std::cout << "        debug_port=" << hello.debug_port
                << "  udp_log_port=" << hello.udp_log_port << "\n";
    }
  }

  /* ----------------------------------------------------------------
   *  3. PING
   * ---------------------------------------------------------------- */
  TEST("PING", client.ping());

  /* ----------------------------------------------------------------
   *  4. PROCESS_LIST
   * ---------------------------------------------------------------- */
  std::vector<memdbg::frontend::ProcessEntry> processes;
  TEST("PROCESS_LIST", client.process_list(processes));
  if (!processes.empty())
    std::cout << "        found " << processes.size() << " processes\n";

  /* ----------------------------------------------------------------
   *  5. PROCESS_INFO  (first + last process)
   * ---------------------------------------------------------------- */
  if (!processes.empty()) {
    memdbg::frontend::ProcessInfo info_first;
    if (client.process_info(processes.front().pid, info_first)) {
      record("PROCESS_INFO(first)", true, false,
             std::string("pid=") + std::to_string(info_first.pid) +
                 " name=" + info_first.name +
                 " title_id=" + info_first.title_id);
    } else {
      record("PROCESS_INFO(first)", false, false, client.last_error());
    }

    if (processes.size() > 1) {
      memdbg::frontend::ProcessInfo info_last;
      if (client.process_info(processes.back().pid, info_last)) {
        record("PROCESS_INFO(last)", true, false,
               std::string("pid=") + std::to_string(info_last.pid) +
                   " name=" + info_last.name);
      } else {
        record("PROCESS_INFO(last)", false, false, client.last_error());
      }
    } else {
      TEST_SKIP("PROCESS_INFO(last)", "only 1 process available");
    }
  } else {
    TEST_SKIP("PROCESS_INFO(first)", "no processes available");
    TEST_SKIP("PROCESS_INFO(last)", "no processes available");
  }

  /* ----------------------------------------------------------------
   *  6. PROCESS_MAPS  (first process with valid PID)
   * ---------------------------------------------------------------- */
  if (!processes.empty()) {
    std::vector<memdbg::frontend::MapEntry> maps;
    if (client.process_maps(processes.front().pid, maps)) {
      size_t readable = 0;
      for (const auto &m : maps)
        if (m.protection & 1U) ++readable;
      record("PROCESS_MAPS", true, false,
             std::string("pid=") + std::to_string(processes.front().pid) +
                 " total=" + std::to_string(maps.size()) +
                 " readable=" + std::to_string(readable));
    } else {
      record("PROCESS_MAPS", false, false, client.last_error());
    }
  } else {
    TEST_SKIP("PROCESS_MAPS", "no processes available");
  }

  /* ----------------------------------------------------------------
   *  7. FOREGROUND_APP
   * ---------------------------------------------------------------- */
  {
    char title_id[32] = {}, content_id[128] = {}, name[96] = {}, app_ver[32] = {};
    if (client.foreground_app(0, title_id, sizeof(title_id),
                              content_id, sizeof(content_id),
                              name, sizeof(name),
                              app_ver, sizeof(app_ver))) {
      record("FOREGROUND_APP", true, false,
             std::string("name=") + name + " title_id=" + title_id);
    } else {
      record("FOREGROUND_APP", false, false, client.last_error());
    }
  }

  /* ----------------------------------------------------------------
   *  8. TELEMETRY
   * ---------------------------------------------------------------- */
  {
    memdbg::frontend::Client::TelemetrySnapshot tele;
    if (client.telemetry(tele)) {
      record("TELEMETRY", true, false,
             std::string("uptime=") + std::to_string(tele.uptime_seconds) +
                 "s  read=" + std::to_string(tele.total_bytes_read) +
                 "B/" + std::to_string(tele.total_read_calls) + "calls" +
                 "  write=" + std::to_string(tele.total_bytes_written) +
                 "B/" + std::to_string(tele.total_write_calls) + "calls" +
                 "  conns=" + std::to_string(tele.active_connections) +
                 "  pool=" + std::to_string(tele.thread_pool_size) +
                 "  cache_hits=" + std::to_string(tele.scan_cache_hits) +
                 "  cache_misses=" + std::to_string(tele.scan_cache_misses));
    } else {
      record("TELEMETRY", false, false, client.last_error());
    }
  }

  /* ----------------------------------------------------------------
   *  9. MEMORY_READ  (first readable map of first process)
   * ---------------------------------------------------------------- */
  {
    bool tested = false;
    if (!processes.empty()) {
      std::vector<memdbg::frontend::MapEntry> maps;
      if (client.process_maps(processes.front().pid, maps)) {
        for (const auto &m : maps) {
          if (!(m.protection & 1U)) continue; /* not readable */
          uint64_t len = m.end - m.start;
          if (len < 4U) continue;
          uint32_t read_len = len > 256U ? 256U : static_cast<uint32_t>(len);
          std::vector<uint8_t> data;
          if (client.memory_read(processes.front().pid, m.start, read_len,
                                 data)) {
            record("MEMORY_READ", true, false,
                   std::string("pid=") +
                       std::to_string(processes.front().pid) +
                       " addr=0x" + fmt_hex(m.start) +
                       " len=" + std::to_string(data.size()));
          } else {
            record("MEMORY_READ", false, false, client.last_error());
          }
          tested = true;
          break;
        }
      }
    }
    if (!tested)
      TEST_SKIP("MEMORY_READ", "no readable memory map found");
  }

  /* ----------------------------------------------------------------
   * 10. MEMORY_WRITE  (read-then-write-back, non-destructive)
   * ---------------------------------------------------------------- */
  {
    bool tested = false;
    if (!processes.empty()) {
      std::vector<memdbg::frontend::MapEntry> maps;
      if (client.process_maps(processes.front().pid, maps)) {
        for (const auto &m : maps) {
          if (!(m.protection & 3U)) continue; /* need read+write */
          if (m.end - m.start < 8U) continue;
          std::vector<uint8_t> orig;
          uint64_t addr = m.start;
          if (!client.memory_read(processes.front().pid, addr, 8, orig) ||
              orig.size() < 8U)
            continue;
          uint32_t written = 0;
          if (client.memory_write(processes.front().pid, addr, orig, written)) {
            record("MEMORY_WRITE", true, false,
                   std::string("pid=") +
                       std::to_string(processes.front().pid) +
                       " addr=0x" + fmt_hex(addr) +
                       " written=" + std::to_string(written));
          } else {
            record("MEMORY_WRITE", false, false, client.last_error());
          }
          tested = true;
          break;
        }
      }
    }
    if (!tested)
      TEST_SKIP("MEMORY_WRITE", "no writable memory map found");
  }

  /* ----------------------------------------------------------------
   * 11. BATCH_READ
   * ---------------------------------------------------------------- */
  {
    bool tested = false;
    if (!processes.empty()) {
      std::vector<memdbg::frontend::MapEntry> maps;
      if (client.process_maps(processes.front().pid, maps)) {
        std::vector<memdbg_batch_read_item_t> items;
        for (const auto &m : maps) {
          if (!(m.protection & 1U)) continue;
          if (m.end - m.start < 4U) continue;
          memdbg_batch_read_item_t item{};
          item.address = m.start;
          item.length = 4U;
          items.push_back(item);
          if (items.size() >= 2U) break;
          if (m.end - m.start >= 8U) {
            memdbg_batch_read_item_t item2{};
            item2.address = m.start + 4U;
            item2.length = 4U;
            items.push_back(item2);
            break;
          }
        }
        if (!items.empty()) {
          memdbg::frontend::Client::BatchReadResult br;
          if (client.batch_read(processes.front().pid, items, br)) {
            size_t ok_count = 0;
            for (const auto &e : br.entries)
              if (e.status == (uint32_t)MEMDBG_OK) ++ok_count;
            record("BATCH_READ", true, false,
                   std::string("pid=") +
                       std::to_string(processes.front().pid) +
                       " items=" + std::to_string(items.size()) +
                       " ok=" + std::to_string(ok_count) +
                       " data=" + std::to_string(br.data.size()) + "B");
            tested = true;
          } else {
            record("BATCH_READ", false, false, client.last_error());
            tested = true;
          }
        }
      }
    }
    if (!tested)
      TEST_SKIP("BATCH_READ", "no readable memory maps found");
  }

  /* ----------------------------------------------------------------
   * 12. BATCH_WRITE  (read-then-write-back, non-destructive)
   * ---------------------------------------------------------------- */
  {
    bool tested = false;
    if (!processes.empty()) {
      std::vector<memdbg::frontend::MapEntry> maps;
      if (client.process_maps(processes.front().pid, maps)) {
        for (const auto &m : maps) {
          if (!(m.protection & 3U)) continue;
          if (m.end - m.start < 8U) continue;
          std::vector<uint8_t> orig;
          if (!client.memory_read(processes.front().pid, m.start, 4, orig) ||
              orig.size() < 4U)
            continue;
          std::vector<std::pair<uint64_t, std::vector<uint8_t>>> witems;
          witems.push_back({m.start, orig});
          memdbg::frontend::Client::BatchWriteResult bw;
          if (client.batch_write(processes.front().pid, witems, bw)) {
            size_t ok_count = 0;
            for (const auto &e : bw.entries)
              if (e.status == (uint32_t)MEMDBG_OK) ++ok_count;
            record("BATCH_WRITE", true, false,
                   std::string("pid=") +
                       std::to_string(processes.front().pid) +
                       " items=" + std::to_string(witems.size()) +
                       " ok=" + std::to_string(ok_count));
          } else {
            record("BATCH_WRITE", false, false, client.last_error());
          }
          tested = true;
          break;
        }
      }
    }
    if (!tested)
      TEST_SKIP("BATCH_WRITE", "no writable memory map found");
  }

  /* ----------------------------------------------------------------
   * 13. SCAN_EXACT  (scan for a known value in a readable map)
   * ---------------------------------------------------------------- */
  {
    bool tested = false;
    if (!processes.empty()) {
      std::vector<memdbg::frontend::MapEntry> maps;
      if (client.process_maps(processes.front().pid, maps)) {
        for (const auto &m : maps) {
          if (!(m.protection & 1U)) continue;
          if (m.end - m.start < 256U) continue;
          /* Read first 16 bytes to get a known value to scan for */
          std::vector<uint8_t> probe_data;
          if (!client.memory_read(processes.front().pid, m.start, 16,
                                  probe_data) ||
              probe_data.size() < 4U)
            continue;
          /* Scan for the first 4 bytes as a U32 */
          memdbg_scan_exact_request_t req{};
          req.pid = processes.front().pid;
          req.start = m.start;
          req.length =
              (m.end - m.start) > (1024U * 1024U) ? (1024U * 1024U) : static_cast<uint32_t>(m.end - m.start);
          req.value_type = MEMDBG_VALUE_U32;
          req.value_length = 4U;
          req.alignment = 4U;
          req.max_results = 100U;
          std::memcpy(req.value, probe_data.data(), 4U);
          memdbg::frontend::ScanResult sr;
          if (client.scan_exact(req, sr)) {
            record("SCAN_EXACT", true, false,
                   std::string("pid=") +
                       std::to_string(processes.front().pid) +
                       " hits=" + std::to_string(sr.count) +
                       " scanned=" + std::to_string(sr.bytes_scanned) +
                       "B regions=" + std::to_string(sr.regions_scanned));
          } else {
            record("SCAN_EXACT", false, false, client.last_error());
          }
          tested = true;
          break;
        }
      }
    }
    if (!tested)
      TEST_SKIP("SCAN_EXACT", "no suitable memory map found");
  }

  /* ----------------------------------------------------------------
   * 14. SCAN_PROCESS_EXACT
   * ---------------------------------------------------------------- */
  if (!processes.empty()) {
    std::vector<memdbg::frontend::MapEntry> maps;
    bool found = false;
    uint8_t search_val[4] = {0, 0, 0, 0};
    if (client.process_maps(processes.front().pid, maps)) {
      for (const auto &m : maps) {
        if (!(m.protection & 1U)) continue;
        if (m.end - m.start < 256U) continue;
        std::vector<uint8_t> probe_data;
        if (!client.memory_read(processes.front().pid, m.start, 4, probe_data) ||
            probe_data.size() < 4U)
          continue;
        std::memcpy(search_val, probe_data.data(), 4U);
        found = true;
        break;
      }
    }
    if (found) {
      memdbg_scan_process_exact_request_t req{};
      req.pid = processes.front().pid;
      req.value_type = MEMDBG_VALUE_U32;
      req.value_length = 4U;
      req.alignment = 4U;
      req.max_results = 100U;
      req.protection_mask = 0U;
      req.start = 0U;
      req.end = 0U;
      std::memcpy(req.value, search_val, 4U);
      memdbg::frontend::ScanResult sr;
      if (client.scan_process_exact(req, sr)) {
        record("SCAN_PROCESS_EXACT", true, false,
               std::string("pid=") + std::to_string(processes.front().pid) +
                   " hits=" + std::to_string(sr.count) +
                   " scanned=" + std::to_string(sr.bytes_scanned) +
                   "B regions=" + std::to_string(sr.regions_scanned) +
                   " errors=" + std::to_string(sr.read_errors));
      } else {
        record("SCAN_PROCESS_EXACT", false, false, client.last_error());
      }
    } else {
      TEST_SKIP("SCAN_PROCESS_EXACT", "no readable map to extract probe value");
    }
  } else {
    TEST_SKIP("SCAN_PROCESS_EXACT", "no processes available");
  }

  /* ----------------------------------------------------------------
   * 15. SCAN_AOB  (scan for a known byte sequence)
   * ---------------------------------------------------------------- */
  {
    bool tested = false;
    if (!processes.empty()) {
      std::vector<memdbg::frontend::MapEntry> maps;
      if (client.process_maps(processes.front().pid, maps)) {
        for (const auto &m : maps) {
          if (!(m.protection & 1U)) continue;
          if (m.end - m.start < 256U) continue;
          std::vector<uint8_t> probe_data;
          if (!client.memory_read(processes.front().pid, m.start, 8, probe_data) ||
              probe_data.size() < 4U)
            continue;
          std::vector<uint8_t> pattern(probe_data.begin(),
                                       probe_data.begin() + 4);
          std::vector<uint8_t> mask(4, 0xFFU);
          memdbg_scan_aob_request_t req{};
          req.pid = processes.front().pid;
          req.start = m.start;
          req.length =
              (m.end - m.start) > (1024U * 1024U) ? (1024U * 1024U) : static_cast<uint32_t>(m.end - m.start);
          req.max_results = 100U;
          req.pattern_length = 4U;
          memdbg::frontend::ScanResult sr;
          if (client.scan_aob(req, pattern, mask, sr)) {
            record("SCAN_AOB", true, false,
                   std::string("pid=") +
                       std::to_string(processes.front().pid) +
                       " hits=" + std::to_string(sr.count) +
                       " scanned=" + std::to_string(sr.bytes_scanned) + "B");
          } else {
            record("SCAN_AOB", false, false, client.last_error());
          }
          tested = true;
          break;
        }
      }
    }
    if (!tested)
      TEST_SKIP("SCAN_AOB", "no suitable memory map found");
  }

  /* ----------------------------------------------------------------
   * 16. SCAN_PROCESS_AOB
   * ---------------------------------------------------------------- */
  if (!processes.empty()) {
    std::vector<memdbg::frontend::MapEntry> maps;
    bool found = false;
    std::vector<uint8_t> pattern(4, 0);
    if (client.process_maps(processes.front().pid, maps)) {
      for (const auto &m : maps) {
        if (!(m.protection & 1U)) continue;
        if (m.end - m.start < 256U) continue;
        std::vector<uint8_t> probe_data;
        if (!client.memory_read(processes.front().pid, m.start, 4, probe_data) ||
            probe_data.size() < 4U)
          continue;
        pattern.assign(probe_data.begin(), probe_data.begin() + 4);
        found = true;
        break;
      }
    }
    if (found) {
      memdbg_scan_process_aob_request_t req{};
      req.pid = processes.front().pid;
      req.protection_mask = 0U;
      req.max_results = 100U;
      req.pattern_length = 4U;
      req.start = 0U;
      req.end = 0U;
      std::vector<uint8_t> mask(4, 0xFFU);
      memdbg::frontend::ScanResult sr;
      if (client.scan_process_aob(req, pattern, mask, sr)) {
        record("SCAN_PROCESS_AOB", true, false,
               std::string("pid=") + std::to_string(processes.front().pid) +
                   " hits=" + std::to_string(sr.count) +
                   " scanned=" + std::to_string(sr.bytes_scanned) +
                   "B regions=" + std::to_string(sr.regions_scanned));
      } else {
        record("SCAN_PROCESS_AOB", false, false, client.last_error());
      }
    } else {
      TEST_SKIP("SCAN_PROCESS_AOB", "no readable map to extract probe pattern");
    }
  } else {
    TEST_SKIP("SCAN_PROCESS_AOB", "no processes available");
  }

  /* ----------------------------------------------------------------
   * 17. SCAN_POINTER  (scan for a pointer to a known address)
   * ---------------------------------------------------------------- */
  {
    bool tested = false;
    if (!processes.empty()) {
      std::vector<memdbg::frontend::MapEntry> maps;
      if (client.process_maps(processes.front().pid, maps)) {
        for (const auto &m : maps) {
          if (!(m.protection & 1U)) continue;
          if (m.end - m.start < 256U) continue;
          /* Use the map start as a plausible target address */
          uint64_t target = m.start;
          memdbg_scan_pointer_request_t req{};
          req.pid = processes.front().pid;
          req.start = m.start;
          req.length =
              (m.end - m.start) > (1024U * 1024U) ? (1024U * 1024U) : static_cast<uint32_t>(m.end - m.start);
          req.target_address = target;
          req.max_depth = 1U;
          req.max_results = 100U;
          req.alignment = 8U;
          memdbg::frontend::ScanResult sr;
          if (client.scan_pointer(req, sr)) {
            record("SCAN_POINTER", true, false,
                   std::string("pid=") +
                       std::to_string(processes.front().pid) +
                       " target=0x" + fmt_hex(target) +
                       " hits=" + std::to_string(sr.count) +
                       " scanned=" + std::to_string(sr.bytes_scanned) + "B");
          } else {
            record("SCAN_POINTER", false, false, client.last_error());
          }
          tested = true;
          break;
        }
      }
    }
    if (!tested)
      TEST_SKIP("SCAN_POINTER", "no suitable memory map found");
  }

  /* ----------------------------------------------------------------
   * 18. SCAN_UNKNOWN
   * ---------------------------------------------------------------- */
  if (!processes.empty()) {
    memdbg_scan_unknown_request_t req{};
    req.abi_magic = MEMDBG_SCAN_UNKNOWN_ABI_MAGIC;
    req.abi_version = MEMDBG_SCAN_UNKNOWN_ABI_VERSION;
    req.struct_size = static_cast<uint16_t>(sizeof(req));
    req.pid = processes.front().pid;
    req.value_type = MEMDBG_VALUE_U32;
    req.value_length = 4U;
    req.alignment = 4U;
    req.max_results = 100U;
    req.protection_mask = 0U;
    req.start = 0U;
    req.end = 0U;
    req.max_bytes = MEMDBG_SCAN_UNKNOWN_MAX_UNIT_BYTES;
    memdbg::frontend::ScanResult sr;
    if (client.scan_unknown(req, sr)) {
      record("SCAN_UNKNOWN", true, false,
             std::string("pid=") + std::to_string(processes.front().pid) +
                 " hits=" + std::to_string(sr.count) +
                 " scanned=" + std::to_string(sr.bytes_scanned) +
                 "B regions=" + std::to_string(sr.regions_scanned));
    } else {
      record("SCAN_UNKNOWN", false, false, client.last_error());
    }
  } else {
    TEST_SKIP("SCAN_UNKNOWN", "no processes available");
  }

  /* ----------------------------------------------------------------
   * 19. PROCESS_STOP / PROCESS_CONTINUE  (destructive — skip)
   * ---------------------------------------------------------------- */
  TEST_SKIP("PROCESS_STOP",
            "destructive — use --test-stop <pid> to exercise");
  TEST_SKIP("PROCESS_CONTINUE",
            "destructive — use --test-continue <pid> to exercise");

  /* ----------------------------------------------------------------
   * 20. SHUTDOWN  (destructive — skip)
   * ---------------------------------------------------------------- */
  TEST_SKIP("SHUTDOWN",
            "destructive — use --shutdown to stop the payload");

  /* ----------------------------------------------------------------
   * 21. DISCOVERY  (UDP-based — skip)
   * ---------------------------------------------------------------- */
  TEST_SKIP("DISCOVERY",
            "UDP broadcast — tested by the frontend discovery dialog");

  /* ---- Summary ---- */

  std::cout << "\n=== Results ======================================\n";
  int total = g_passed + g_failed + g_skipped;
  std::cout << "Total:  " << total << "\n";
  std::cout << "Passed: " << g_passed << "\n";
  std::cout << "Failed: " << g_failed << "\n";
  std::cout << "Skipped:" << g_skipped << "\n";

  if (g_failed > 0) {
    std::cout << "\nFailures:\n";
    for (const auto &r : g_results) {
      if (!r.ok && !r.skipped)
        std::cout << "  " << r.name << " — " << r.detail << "\n";
    }
  }

  std::cout << "================================================\n";

  client.disconnect();
  return g_failed > 0 ? 1 : 0;
}

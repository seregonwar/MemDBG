/*
 * MemDBG - Read-only performance probe for a live PS4/PS5 payload.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Usage: memdbg_performance_probe [host] [port] [process-name]
 *        [--stress|--scan-only|--cancel-scan|--write-test]
 */

#include "core/client/memdbg_client.hpp"
#include "memdbg/core/memdbg.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

using memdbg::frontend::Client;
using memdbg::frontend::HelloInfo;
using memdbg::frontend::MapEntry;
using memdbg::frontend::ProcessEntry;

namespace {

using Clock = std::chrono::steady_clock;

double elapsed_ms(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

std::string lowercase(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return value;
}

double percentile(std::vector<double> samples, double fraction) {
  if (samples.empty()) return 0.0;
  std::sort(samples.begin(), samples.end());
  const size_t index = static_cast<size_t>(fraction * (samples.size() - 1U));
  return samples[index];
}

void print_latency(const char *name, const std::vector<double> &samples) {
  const double mean = samples.empty()
      ? 0.0
      : std::accumulate(samples.begin(), samples.end(), 0.0) /
            static_cast<double>(samples.size());
  std::cout << std::left << std::setw(31) << name << std::right
            << " avg=" << std::fixed << std::setprecision(3) << mean
            << " ms  p50=" << percentile(samples, 0.50)
            << " ms  p95=" << percentile(samples, 0.95) << " ms\n";
}

bool connect_client(Client &client, const std::string &host, uint16_t port,
                    HelloInfo &hello, std::string &error) {
  client.set_socket_timeout_ms(30000U);
  if (!client.connect_to(host, port, 5000U) || !client.hello(hello)) {
    error = client.last_error();
    return false;
  }
  return true;
}

const MapEntry *select_readable_map(Client &client, int32_t pid,
                                    const std::vector<MapEntry> &maps) {
  std::vector<const MapEntry *> candidates;
  for (const auto &map : maps) {
    const std::string name = lowercase(map.name);
    const std::string type = lowercase(map.type);
    if ((map.protection & MEMDBG_MAP_PROT_READ) == 0U ||
        map.end <= map.start || map.end - map.start < (1ULL << 20) ||
        map.end - map.start > (512ULL << 20) ||
        name.find("device") != std::string::npos ||
        type.find("device") != std::string::npos)
      continue;
    candidates.push_back(&map);
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const MapEntry *a, const MapEntry *b) {
              const bool a_exec = (a->protection & MEMDBG_MAP_PROT_EXEC) != 0U;
              const bool b_exec = (b->protection & MEMDBG_MAP_PROT_EXEC) != 0U;
              if (a_exec != b_exec) return a_exec;
              return a->end - a->start > b->end - b->start;
            });
  for (const MapEntry *map : candidates) {
    std::vector<uint8_t> probe;
    if (client.memory_read(pid, map->start, 4096U, probe) &&
        probe.size() == 4096U)
      return map;
  }
  return nullptr;
}

bool read_workload(Client &client, int32_t pid, const MapEntry &map,
                   uint32_t chunk_size, uint64_t total_bytes,
                   uint64_t lane_offset, double &seconds,
                   uint64_t &completed) {
  completed = 0U;
  const uint64_t span = map.end - map.start;
  if (span < chunk_size) return false;
  uint64_t cursor = lane_offset % (span - chunk_size + 1U);
  const auto start = Clock::now();
  while (completed < total_bytes) {
    const uint32_t amount = static_cast<uint32_t>(
        std::min<uint64_t>(chunk_size, total_bytes - completed));
    if (cursor + amount > span) cursor = 0U;
    std::vector<uint8_t> data;
    if (!client.memory_read(pid, map.start + cursor, amount, data) ||
        data.size() != amount) {
      seconds = std::chrono::duration<double>(Clock::now() - start).count();
      return false;
    }
    completed += amount;
    cursor += amount;
  }
  seconds = std::chrono::duration<double>(Clock::now() - start).count();
  return true;
}

void print_throughput(const std::string &name, uint64_t bytes, double seconds) {
  const double mib = static_cast<double>(bytes) / (1024.0 * 1024.0);
  std::cout << std::left << std::setw(31) << name << std::right
            << " " << std::fixed << std::setprecision(2)
            << (seconds > 0.0 ? mib / seconds : 0.0) << " MiB/s"
            << "  (" << mib << " MiB, " << seconds << " s)\n";
}

} // namespace

int main(int argc, char **argv) {
  std::cout << std::unitbuf;
  const std::string host = argc > 1 ? argv[1] : "192.168.1.10";
  const uint16_t port = argc > 2
      ? static_cast<uint16_t>(std::strtoul(argv[2], nullptr, 10))
      : 9020U;
  const std::string target = lowercase(argc > 3 ? argv[3] : "eboot.bin");
  const bool stress = argc > 4 && std::strcmp(argv[4], "--stress") == 0;
  const bool scan_only =
      argc > 4 && std::strcmp(argv[4], "--scan-only") == 0;
  const bool cancel_scan =
      argc > 4 && std::strcmp(argv[4], "--cancel-scan") == 0;
  const bool write_test =
      argc > 4 && std::strcmp(argv[4], "--write-test") == 0;

  std::cout << "MemDBG live read-only performance probe\n"
            << "Target: " << host << ':' << port
            << "  process: " << target
            << (stress ? "  mode: stress"
                       : (scan_only ? "  mode: scan-only"
                                    : (cancel_scan ? "  mode: cancel-scan"
                                                   : (write_test ? "  mode: write-test" : ""))))
            << "\n\n";

  std::array<std::unique_ptr<Client>, 4> clients;
  std::array<HelloInfo, 4> hellos;
  std::array<std::string, 4> errors;
  for (auto &client : clients) client = std::make_unique<Client>();

  if (!connect_client(*clients[0], host, port, hellos[0], errors[0])) {
    std::cerr << "Connection failed: " << errors[0] << '\n';
    return 1;
  }
  std::cout << "Payload: " << hellos[0].name << " v" << hellos[0].version
            << "  platform="
            << memdbg::frontend::platform_name(hellos[0].platform_id)
            << "  protocol=feature-v" << hellos[0].feature_level
            << " (wire-v" << hellos[0].protocol_version << ")\n";

  std::vector<ProcessEntry> processes;
  std::vector<double> list_latency;
  for (unsigned i = 0; i < 10U; ++i) {
    const auto start = Clock::now();
    if (!clients[0]->process_list(processes)) {
      std::cerr << "PROCESS_LIST failed: " << clients[0]->last_error() << '\n';
      return 1;
    }
    list_latency.push_back(elapsed_ms(start));
  }
  print_latency("PROCESS_LIST (10x)", list_latency);

  const ProcessEntry *selected_process = nullptr;
  for (const auto &entry : processes) {
    const std::string name = lowercase(entry.name);
    if (name != target && name.find(target) == std::string::npos) continue;
    /* A freshly injected payload can briefly inherit the loader's eboot.bin
     * name before becoming payload.elf. The long-running game has the older
     * (lower) PID, so prefer it deterministically. */
    if (selected_process == nullptr || entry.pid < selected_process->pid)
      selected_process = &entry;
  }
  if (selected_process == nullptr) {
    std::cerr << "Process not found. Available process names:\n";
    for (const auto &entry : processes)
      std::cerr << "  " << entry.pid << "  " << entry.name << '\n';
    return 2;
  }
  const int32_t pid = selected_process->pid;
  std::cout << "Selected PID " << pid << " (" << selected_process->name
            << ")\n";

  std::vector<MapEntry> maps;
  const auto first_maps_start = Clock::now();
  if (!clients[0]->process_maps(pid, maps)) {
    std::cerr << "PROCESS_MAPS failed: " << clients[0]->last_error() << '\n';
    return 1;
  }
  const double first_maps_ms = elapsed_ms(first_maps_start);
  std::cout << std::left << std::setw(31) << "PROCESS_MAPS first"
            << std::right << " " << std::fixed << std::setprecision(3)
            << first_maps_ms << " ms  (" << maps.size() << " maps)\n";

  std::vector<double> maps_latency;
  for (unsigned i = 0; i < 20U; ++i) {
    std::vector<MapEntry> refreshed;
    const auto start = Clock::now();
    if (!clients[0]->process_maps(pid, refreshed)) {
      std::cerr << "PROCESS_MAPS repeat failed: "
                << clients[0]->last_error() << '\n';
      return 1;
    }
    maps_latency.push_back(elapsed_ms(start));
  }
  print_latency("PROCESS_MAPS warm (20x)", maps_latency);

  std::array<bool, 3> connected = {false, false, false};
  std::array<std::thread, 3> connector_threads;
  for (size_t i = 0; i < connector_threads.size(); ++i) {
    connector_threads[i] = std::thread([&, i]() {
      connected[i] = connect_client(*clients[i + 1U], host, port,
                                    hellos[i + 1U], errors[i + 1U]);
    });
  }
  for (auto &thread : connector_threads) thread.join();
  for (size_t i = 0; i < connected.size(); ++i) {
    if (!connected[i]) {
      std::cerr << "Role connection " << (i + 1U)
                << " failed: " << errors[i + 1U] << '\n';
      return 1;
    }
  }
  std::cout << "Four protocol connections active\n";

  std::array<double, 4> parallel_maps_ms{};
  std::array<bool, 4> parallel_maps_ok{};
  std::array<std::thread, 4> map_threads;
  const auto map_burst_start = Clock::now();
  for (size_t i = 0; i < map_threads.size(); ++i) {
    map_threads[i] = std::thread([&, i]() {
      std::vector<MapEntry> local_maps;
      const auto start = Clock::now();
      parallel_maps_ok[i] = clients[i]->process_maps(pid, local_maps);
      parallel_maps_ms[i] = elapsed_ms(start);
    });
  }
  for (auto &thread : map_threads) thread.join();
  if (!std::all_of(parallel_maps_ok.begin(), parallel_maps_ok.end(),
                   [](bool ok) { return ok; })) {
    std::cerr << "Concurrent PROCESS_MAPS failed\n";
    return 1;
  }
  std::vector<double> parallel_map_samples(parallel_maps_ms.begin(),
                                           parallel_maps_ms.end());
  print_latency("PROCESS_MAPS per socket (4x)", parallel_map_samples);
  std::cout << std::left << std::setw(31) << "PROCESS_MAPS burst wall time"
            << std::right << " " << elapsed_ms(map_burst_start) << " ms\n";

  const MapEntry *read_map = select_readable_map(*clients[0], pid, maps);
  if (read_map == nullptr) {
    std::cerr << "No stable readable map found for throughput tests\n";
    return 2;
  }
  std::cout << "Read map: 0x" << std::hex << read_map->start << "-0x"
            << read_map->end << std::dec << "  " << read_map->name << '\n';

  if (write_test) {
    constexpr uint64_t kAllocationSize = 16U * 1024U;
    Client::ProcessAllocResult allocation;
    if (!clients[0]->process_alloc(
            pid, 0U, kAllocationSize,
            MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE, 0U, allocation)) {
      std::cout << "PROCESS_ALLOC unavailable (" << clients[0]->last_error()
                << "); using a stopped-process reversible write\n";
      uint64_t test_address = 0U;
      std::vector<uint8_t> original;
      for (const MapEntry &map : maps) {
        if ((map.protection & (MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE)) !=
                (MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE) ||
            (map.protection & MEMDBG_MAP_PROT_EXEC) != 0U ||
            map.end <= map.start || map.end - map.start < 4096U)
          continue;
        const uint64_t page = map.end - 4096U;
        std::vector<uint8_t> bytes;
        if (!clients[0]->memory_read(pid, page, 4096U, bytes) ||
            bytes.size() != 4096U)
          continue;
        for (size_t offset = 0U; offset + 32U <= bytes.size(); offset += 16U) {
          if (std::all_of(bytes.begin() + static_cast<ptrdiff_t>(offset),
                          bytes.begin() + static_cast<ptrdiff_t>(offset + 32U),
                          [](uint8_t byte) { return byte == 0U; })) {
            test_address = page + offset;
            original.assign(bytes.begin() + static_cast<ptrdiff_t>(offset),
                            bytes.begin() + static_cast<ptrdiff_t>(offset + 16U));
            break;
          }
        }
        if (test_address != 0U) break;
      }
      if (test_address == 0U) {
        std::cerr << "No conservative writable zero run found\n";
        return 1;
      }
      if (!clients[0]->process_stop(pid)) {
        std::cerr << "PROCESS_STOP failed: " << clients[0]->last_error() << '\n';
        return 1;
      }
      bool ok = true;
      bool changed = false;
      std::vector<uint8_t> stopped_original;
      if (!clients[0]->memory_read(pid, test_address, 16U, stopped_original) ||
          stopped_original.size() != 16U) {
        std::cerr << "Stopped read failed: " << clients[0]->last_error() << '\n';
        ok = false;
      }
      original = stopped_original;
      const std::vector<uint8_t> pattern = {
          0x4d, 0x65, 0x6d, 0x44, 0x42, 0x47, 0xa5, 0x5a,
          0x13, 0x37, 0xc0, 0xde, 0x26, 0x07, 0x18, 0x01};
      uint32_t written = 0U;
      std::vector<uint8_t> readback;
      if (ok && (!clients[0]->memory_write(pid, test_address, pattern, written) ||
                 written != pattern.size())) {
        std::cerr << "MEMORY_WRITE failed: " << clients[0]->last_error() << '\n';
        ok = false;
      } else if (ok) {
        changed = true;
      }
      if (ok && (!clients[0]->memory_read(pid, test_address, 16U, readback) ||
                 readback != pattern)) {
        std::cerr << "Changed-value read-back failed\n";
        ok = false;
      }
      if (changed) {
        uint32_t restored = 0U;
        if (!clients[0]->memory_write(pid, test_address, original, restored) ||
            restored != original.size()) {
          std::cerr << "Restore write failed: " << clients[0]->last_error() << '\n';
          ok = false;
        } else {
          readback.clear();
          if (!clients[0]->memory_read(pid, test_address, 16U, readback) ||
              readback != original) {
            std::cerr << "Restore verification failed\n";
            ok = false;
          }
        }
      }
      if (!clients[0]->process_continue(pid)) {
        std::cerr << "PROCESS_CONTINUE failed: " << clients[0]->last_error() << '\n';
        return 1;
      }
      if (ok)
        std::cout << "Reversible write verified and restored at 0x" << std::hex
                  << test_address << std::dec << " while PID was stopped\n";
      return ok ? 0 : 1;
    }
    bool test_ok = true;
    auto finish = [&]() {
      if (!clients[0]->process_free(pid, allocation.address,
                                    allocation.length)) {
        std::cerr << "PROCESS_FREE failed: " << clients[0]->last_error() << '\n';
        test_ok = false;
      }
    };
    std::vector<uint8_t> pattern_a(256U);
    std::vector<uint8_t> pattern_b(256U);
    for (size_t i = 0U; i < pattern_a.size(); ++i) {
      pattern_a[i] = static_cast<uint8_t>((i * 37U + 0x5AU) & 0xFFU);
      pattern_b[i] = static_cast<uint8_t>((i * 73U + 0xA5U) & 0xFFU);
    }
    uint32_t written = 0U;
    std::vector<uint8_t> readback;
    if (!clients[0]->memory_write(pid, allocation.address, pattern_a, written) ||
        written != pattern_a.size() ||
        !clients[0]->memory_read(pid, allocation.address,
                                 static_cast<uint32_t>(pattern_a.size()),
                                 readback) || readback != pattern_a) {
      std::cerr << "First write/read-back verification failed: "
                << clients[0]->last_error() << '\n';
      test_ok = false;
    } else {
      std::cout << "WRITE A verified: 256 bytes at 0x" << std::hex
                << allocation.address << std::dec << '\n';
    }
    written = 0U;
    readback.clear();
    if (test_ok &&
        (!clients[0]->memory_write(pid, allocation.address, pattern_b, written) ||
         written != pattern_b.size() ||
         !clients[0]->memory_read(pid, allocation.address,
                                  static_cast<uint32_t>(pattern_b.size()),
                                  readback) || readback != pattern_b)) {
      std::cerr << "Second write/read-back verification failed: "
                << clients[0]->last_error() << '\n';
      test_ok = false;
    } else if (test_ok) {
      std::cout << "WRITE B verified: value changed and read back exactly\n";
    }
    finish();
    std::cout << (test_ok ? "Temporary process allocation released cleanly\n"
                          : "Write test failed\n");
    return test_ok ? 0 : 1;
  }

  if (!scan_only && !cancel_scan) {
  const std::array<uint32_t, 3> chunks = {4096U, 65536U, 1048576U};
  const std::array<uint64_t, 3> totals = stress
      ? std::array<uint64_t, 3>{8ULL << 20, 32ULL << 20, 64ULL << 20}
      : std::array<uint64_t, 3>{1ULL << 20, 16ULL << 20, 32ULL << 20};
  for (size_t i = 0; i < chunks.size(); ++i) {
    double seconds = 0.0;
    uint64_t completed = 0U;
    if (!read_workload(*clients[0], pid, *read_map, chunks[i], totals[i],
                       0U, seconds, completed)) {
      std::cerr << "Read workload failed after " << completed << " bytes: "
                << clients[0]->last_error() << '\n';
      return 1;
    }
    print_throughput("MEMORY_READ " + std::to_string(chunks[i] / 1024U) +
                         " KiB",
                     completed, seconds);
  }

  /* The deliberately long sequential 4 KiB workload may exceed the daemon's
   * idle timeout on the three unused role sockets. Refresh only those roles
   * immediately before measuring parallel throughput. */
  for (size_t i = 1U; i < clients.size(); ++i) clients[i]->disconnect();
  std::array<std::thread, 3> role_refresh_threads;
  std::fill(connected.begin(), connected.end(), false);
  for (size_t i = 0U; i < role_refresh_threads.size(); ++i) {
    role_refresh_threads[i] = std::thread([&, i]() {
      errors[i + 1U].clear();
      connected[i] = connect_client(*clients[i + 1U], host, port,
                                    hellos[i + 1U], errors[i + 1U]);
    });
  }
  for (auto &thread : role_refresh_threads) thread.join();
  if (!std::all_of(connected.begin(), connected.end(),
                   [](bool ok) { return ok; })) {
    std::cerr << "Could not refresh role sockets before parallel read\n";
    return 1;
  }

  std::array<double, 4> lane_seconds{};
  std::array<uint64_t, 4> lane_bytes{};
  std::array<bool, 4> lane_ok{};
  std::array<std::thread, 4> read_threads;
  const uint64_t per_lane = stress ? 32ULL << 20 : 16ULL << 20;
  const auto aggregate_start = Clock::now();
  for (size_t i = 0; i < read_threads.size(); ++i) {
    read_threads[i] = std::thread([&, i]() {
      lane_ok[i] = read_workload(*clients[i], pid, *read_map, 1048576U,
                                 per_lane, i * (4ULL << 20), lane_seconds[i],
                                 lane_bytes[i]);
    });
  }
  for (auto &thread : read_threads) thread.join();
  const double aggregate_seconds =
      std::chrono::duration<double>(Clock::now() - aggregate_start).count();
  const uint64_t aggregate_bytes =
      std::accumulate(lane_bytes.begin(), lane_bytes.end(), uint64_t{0});
  if (!std::all_of(lane_ok.begin(), lane_ok.end(), [](bool ok) { return ok; })) {
    std::cerr << "Parallel read workload failed:\n";
    for (size_t i = 0U; i < lane_ok.size(); ++i) {
      if (!lane_ok[i])
        std::cerr << "  lane " << i << " after " << lane_bytes[i]
                  << " bytes: " << clients[i]->last_error() << '\n';
    }
    return 1;
  }
  print_throughput("MEMORY_READ 4-socket aggregate", aggregate_bytes,
                   aggregate_seconds);
  }

  const uint64_t scan_length =
      std::min<uint64_t>(read_map->end - read_map->start, 16ULL << 20);
  std::vector<uint8_t> needle;
  if ((hellos[0].capabilities & MEMDBG_CAP_SCAN_EXACT) != 0U &&
      scan_length >= sizeof(uint32_t) &&
      clients[0]->memory_read(pid, read_map->start, sizeof(uint32_t), needle)) {
    memdbg_scan_exact_request_t request{};
    request.pid = pid;
    request.start = read_map->start;
    request.length = scan_length;
    request.value_type = MEMDBG_VALUE_U32;
    request.value_length = sizeof(uint32_t);
    request.alignment = sizeof(uint32_t);
    request.max_results = 1024U;
    std::memcpy(request.value, needle.data(), sizeof(uint32_t));
    memdbg::frontend::ScanResult result;
    const auto start = Clock::now();
    if (!clients[0]->scan_exact(request, result)) {
      std::cerr << "SCAN_EXACT failed: " << clients[0]->last_error() << '\n';
      return 1;
    }
    const double scan_seconds =
        std::chrono::duration<double>(Clock::now() - start).count();
    print_throughput("SCAN_EXACT bounded range", result.bytes_scanned,
                     scan_seconds);
    std::cout << "                               payload elapsed="
              << std::fixed << std::setprecision(3)
              << static_cast<double>(result.elapsed_ns) / 1000000.0
              << " ms  reads=" << result.read_calls
              << "  matches=" << result.count << '\n';

    /* Exercise the payload's map partitioner separately from a single-range
       scan.  Bound the window to a useful multi-map sample so this remains a
       non-destructive benchmark rather than an unbounded whole-title scan. */
    uint64_t process_start = 0U;
    uint64_t process_end = 0U;
    uint64_t estimated_bytes = 0U;
    size_t process_maps = 0U;
    for (const MapEntry &map : maps) {
      if ((map.protection & MEMDBG_MAP_PROT_READ) == 0U ||
          map.end <= map.start)
        continue;
      if (process_start == 0U) process_start = map.start;
      process_end = map.end;
      estimated_bytes += map.end - map.start;
      ++process_maps;
      if (process_maps >= 4U && estimated_bytes >= (16ULL << 20)) break;
      if (process_maps >= 8U || estimated_bytes >= (64ULL << 20)) break;
    }
    if (process_maps >= 4U && process_end > process_start) {
      if (scan_only) clients[0]->set_socket_timeout_ms(120000U);
      std::cout << "Multi-map scan window: " << process_maps
                << " maps, estimated " << std::fixed << std::setprecision(2)
                << static_cast<double>(estimated_bytes) / (1024.0 * 1024.0)
                << " MiB\n";
      memdbg_scan_process_exact_request_t process_request{};
      process_request.pid = pid;
      process_request.value_type = MEMDBG_VALUE_U32;
      process_request.value_length = sizeof(uint32_t);
      process_request.alignment = sizeof(uint32_t);
      process_request.max_results = 1024U;
      process_request.protection_mask = MEMDBG_MAP_PROT_READ;
      process_request.start = process_start;
      process_request.end = process_end;
      std::memcpy(process_request.value, needle.data(), sizeof(uint32_t));
      memdbg::frontend::ScanResult process_result;
      const uint64_t job_id = static_cast<uint64_t>(
          Clock::now().time_since_epoch().count()) | 1ULL;
      bool tracked_ok = false;
      std::atomic<bool> tracked_finished{false};
      double scan_transport_seconds = 0.0;
      const auto process_scan_start = Clock::now();
      std::thread tracked_thread([&]() {
        const auto transport_start = Clock::now();
        tracked_ok = clients[0]->scan_process_exact_tracked(
            job_id, process_request, process_result);
        scan_transport_seconds = std::chrono::duration<double>(
            Clock::now() - transport_start).count();
        tracked_finished.store(true, std::memory_order_release);
      });
      bool cancel_sent = false;
      unsigned progress_samples = 0U;
      while (!tracked_finished.load(std::memory_order_acquire)) {
        const double running_ms = elapsed_ms(process_scan_start);
        Client::ScanJobStatus status;
        const bool status_ok = cancel_scan && !cancel_sent && running_ms >= 20.0
            ? clients[1]->scan_job_cancel(job_id, status)
            : clients[1]->scan_job_status(job_id, status);
        if (status_ok) {
          ++progress_samples;
          if (cancel_scan && !cancel_sent && running_ms >= 20.0)
            cancel_sent = true;
          std::cout << "  progress bytes=" << status.bytes_done << '/'
                    << status.bytes_total << " maps=" << status.maps_done
                    << '/' << status.maps_total << " found="
                    << status.results_found << " workers="
                    << status.workers_active << '/' << status.workers_total
                    << (cancel_sent ? " cancel=sent" : "") << '\n';
        }
        if (status_ok && status.state != MEMDBG_SCAN_JOB_RUNNING) break;
        if (running_ms > 120000.0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        /* Completion is observed through the job state. The scan thread is
           joined below after the payload publishes its terminal state. */
      }
      tracked_thread.join();
      if (!tracked_ok) {
        std::cerr << "SCAN_PROCESS_EXACT failed: "
                  << clients[0]->last_error() << '\n';
        return 1;
      }
      print_throughput("SCAN_PROCESS_EXACT multi-map",
                       process_result.bytes_scanned, scan_transport_seconds);
      std::cout << "                               payload elapsed="
                << std::fixed << std::setprecision(3)
                << static_cast<double>(process_result.elapsed_ns) / 1000000.0
                << " ms  maps=" << process_result.regions_scanned
                << "  reads=" << process_result.read_calls
                << "  matches=" << process_result.count
                << "  progress-samples=" << progress_samples
                << "  cancelled=" << (process_result.cancelled ? "yes" : "no")
                << '\n';
    }
  }

  std::cout << "\nCompleted without memory writes.\n";
  return 0;
}

/*
 * MemDBG - ImGui frontend client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_CLIENT_HPP
#define MEMDBG_FRONTEND_CLIENT_HPP

#include "memdbg/core/memdbg_protocol.h"

#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::frontend {

struct ProcessEntry {
  int32_t pid = 0;
  std::string name;
};

struct MapEntry {
  uint64_t start = 0;
  uint64_t end = 0;
  uint32_t protection = 0;
  uint32_t flags = 0;
  std::string name;
};

struct ProcessInfo {
  int32_t pid = 0;
  std::string name;
  std::string title_id;
  std::string content_id;
  std::string path;
};

struct HelloInfo {
  uint16_t protocol_version = 0;
  uint16_t platform_id = 0;
  uint32_t capabilities = 0;
  uint16_t debug_port = 0;
  uint16_t udp_log_port = 0;
  std::string version;
  std::string name;
};

struct ScanResult {
  uint32_t count = 0;
  bool truncated = false;
  uint64_t bytes_scanned = 0;
  uint64_t elapsed_ns = 0;
  uint32_t read_calls = 0;
  uint32_t regions_scanned = 0;
  uint32_t read_errors = 0;
  std::vector<uint64_t> addresses;
};

class Client {
public:
  Client();
  ~Client();

  Client(const Client &) = delete;
  Client &operator=(const Client &) = delete;

  bool connect_to(const std::string &host, uint16_t port);
  void disconnect();
  int  release_fd();      /* Release fd ownership for async transfer */
  void take_fd(int fd);   /* Adopt a connected fd from async transfer */
  bool connected() const;
  const std::string &last_error() const;

  bool hello(HelloInfo &out);
  bool ping();
  bool shutdown_payload();
  bool process_list(std::vector<ProcessEntry> &out);
  bool process_maps(int32_t pid, std::vector<MapEntry> &out);
  bool process_info(int32_t pid, ProcessInfo &out);
  bool memory_read(int32_t pid, uint64_t address, uint32_t length,
                   std::vector<uint8_t> &out);
  bool memory_write(int32_t pid, uint64_t address,
                    const std::vector<uint8_t> &data, uint32_t &written);
  bool scan_exact(const memdbg_scan_exact_request_t &request, ScanResult &out);
  bool scan_process_exact(const memdbg_scan_process_exact_request_t &request,
                          ScanResult &out);
  bool scan_aob(const memdbg_scan_aob_request_t &request,
                const std::vector<uint8_t> &pattern,
                const std::vector<uint8_t> &mask, ScanResult &out);
  bool scan_process_aob(const memdbg_scan_process_aob_request_t &request,
                        const std::vector<uint8_t> &pattern,
                        const std::vector<uint8_t> &mask, ScanResult &out);
  bool scan_pointer(const memdbg_scan_pointer_request_t &request,
                    ScanResult &out);
  bool scan_unknown(const memdbg_scan_process_exact_request_t &request,
                    ScanResult &out);

  /* Batch read — up to 64 addresses in one request.
     Items: array of (address, length).
     Response: results[i] = (address, length, status), data = concatenated bytes.
     Caller parses data using results[i].length offsets. */
  struct BatchReadResult {
    std::vector<memdbg_batch_read_result_entry_t> entries;
    std::vector<uint8_t> data;
  };
  bool batch_read(int32_t pid,
                  const std::vector<memdbg_batch_read_item_t> &items,
                  BatchReadResult &out);

  /* Batch write — up to 64 (address, data) pairs in one request.
     Items: vector of {address, data_bytes}.
     Response: results[i] = {address, written, status} for each item. */
  struct BatchWriteResult {
    std::vector<memdbg_batch_write_result_entry_t> entries;
  };
  bool batch_write(int32_t pid,
                   const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> &items,
                   BatchWriteResult &out);

  struct TelemetrySnapshot {
    uint64_t total_bytes_read = 0;
    uint64_t total_bytes_written = 0;
    uint64_t total_read_calls = 0;
    uint64_t total_write_calls = 0;
    uint64_t uptime_seconds = 0;
    uint32_t active_connections = 0;
    uint32_t thread_pool_size = 0;
    uint32_t scan_cache_hits = 0;
    uint32_t scan_cache_misses = 0;
  };
  bool telemetry(TelemetrySnapshot &out);

  bool foreground_app(int32_t pid, char *title_id, size_t title_id_size,
                      char *content_id, size_t content_id_size,
                      char *name, size_t name_size, char *app_ver,
                      size_t app_ver_size);
  bool process_stop(int32_t pid);
  bool process_continue(int32_t pid);

private:
  bool request(uint16_t command, const void *payload, uint32_t payload_len,
               std::vector<uint8_t> &response);
  bool read_exact(void *data, size_t size);
  bool write_all(const void *data, size_t size);
  void set_error_from_errno(const std::string &prefix);
  void set_error(const std::string &message);

  int fd_ = -1;
  uint32_t next_request_id_ = 1;
  std::string last_error_;
};

std::string platform_name(uint16_t platform_id);
std::string capability_text(uint32_t capabilities);

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_CLIENT_HPP */

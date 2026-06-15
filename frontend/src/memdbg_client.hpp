/*
 * memDBG - ImGui frontend client.
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

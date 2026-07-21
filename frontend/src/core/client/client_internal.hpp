/*
 * MemDBG - Shared utilities for the Client class implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef MEMDBG_FRONTEND_CLIENT_INTERNAL_HPP
#define MEMDBG_FRONTEND_CLIENT_INTERNAL_HPP

#include "memdbg_client.hpp"
#include "memdbg/core/memdbg.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <sstream>

#if !defined(_WIN32)
#include <netinet/tcp.h>
#endif

extern "C" {
int lz4_decompress_safe(const char *src, char *dst, int compressed_size,
                        int dst_capacity);
}

namespace memdbg::frontend {

/* ---- LZ4 decompression ---- */

inline bool maybe_decompress(const std::vector<uint8_t> &response,
                             std::vector<uint8_t> &out) {
  if (response.empty()) {
    out.clear();
    return true;
  }
  if (response[0] == 0x00U) {
    out.assign(response.begin() + 1, response.end());
    return true;
  }
  if (response[0] == 0x01U && response.size() >= 5U) {
    uint32_t uncomp_len = (uint32_t)response[1] |
                          ((uint32_t)response[2] << 8U) |
                          ((uint32_t)response[3] << 16U) |
                          ((uint32_t)response[4] << 24U);
    out.resize(uncomp_len);
    int dec = lz4_decompress_safe((const char *)(response.data() + 5),
                                  (char *)out.data(),
                                  (int)(response.size() - 5U),
                                  (int)uncomp_len);
    if (dec != (int)uncomp_len) {
      out.clear();
      return false;
    }
    return true;
  }
  out = response;
  return true;
}

/* ---- TCP keepalive ---- */

inline void socket_set_keepalive(platform::socket_handle_t fd) {
  int keepalive = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                     reinterpret_cast<const char *>(&keepalive),
                     sizeof(keepalive));
#if !defined(_WIN32)
#if defined(TCP_KEEPIDLE)
  int idle = 30;
  int intvl = 10;
  int cnt = 3;
  (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
                     reinterpret_cast<const char *>(&idle), sizeof(idle));
  (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
                     reinterpret_cast<const char *>(&intvl), sizeof(intvl));
  (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
                     reinterpret_cast<const char *>(&cnt), sizeof(cnt));
#elif defined(TCP_KEEPALIVE)
  int idle = 30;
  (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
                     reinterpret_cast<const char *>(&idle), sizeof(idle));
#endif
#endif
}

/* ---- Legacy compat ---- */

constexpr size_t kLegacyThreadEntryV1Size = sizeof(int32_t) + 24U;
constexpr size_t kLegacyThreadEntryV2Size =
    sizeof(int32_t) + sizeof(uint32_t) + 24U;

/* ---- Session ID ---- */

inline uint64_t frontend_session_id() {
  static int anchor = 0;
  static const uint64_t value = []() {
    uint64_t x = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());
    x ^= static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    x ^= static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&anchor));
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27U)) * 0x94d049bb133111ebULL;
    x ^= x >> 31U;
    return x != 0U ? x : 1U;
  }();
  return value;
}

/* ---- Protocol helpers ---- */

inline uint32_t max_response_for_command(uint16_t command) {
  return command == MEMDBG_CMD_PROCESS_MAPS ||
                 command == MEMDBG_CMD_PROCESS_MAPS_V2
             ? MEMDBG_PROTOCOL_MAX_MAP_RESPONSE
             : MEMDBG_PROTOCOL_MAX_PACKET + 1024U * 1024U;
}

template <typename T>
inline bool read_object(const std::vector<uint8_t> &data, T &out) {
  if (data.size() < sizeof(T)) return false;
  std::memcpy(&out, data.data(), sizeof(T));
  return true;
}

inline std::string fixed_string(const char *data, size_t size) {
  size_t len = 0;
  while (len < size && data[len] != '\0') ++len;
  return std::string(data, len);
}

inline const char *payload_status_name(int32_t status) {
  switch (static_cast<memdbg_status_t>(status)) {
  case MEMDBG_OK:           return "ok";
  case MEMDBG_ERR_PARAM:    return "invalid parameter";
  case MEMDBG_ERR_NOMEM:    return "out of memory";
  case MEMDBG_ERR_IO:       return "i/o error";
  case MEMDBG_ERR_NET:      return "network error";
  case MEMDBG_ERR_PROTOCOL: return "protocol error";
  case MEMDBG_ERR_UNSUPPORTED: return "unsupported";
  case MEMDBG_ERR_NOT_FOUND:   return "not found";
  case MEMDBG_ERR_PERMISSION:  return "permission denied";
  case MEMDBG_ERR_OVERFLOW:    return "overflow";
  case MEMDBG_ERR_STATE:       return "invalid state";
  default:                  return "unknown error";
  }
}

inline const char *payload_status_hint(uint16_t command, int32_t status) {
  if (command == MEMDBG_CMD_DEBUG_ATTACH) {
    switch (static_cast<memdbg_status_t>(status)) {
    case MEMDBG_ERR_PERMISSION:
      return "ptrace attach was denied; try a user process/game process and "
             "check payload privileges";
    case MEMDBG_ERR_NOT_FOUND:
      return "the target process no longer exists; refresh PIDs";
    case MEMDBG_ERR_STATE:
      return "the debugger is already attached or the target did not enter a "
             "traceable stop state";
    case MEMDBG_ERR_IO:
      return "ptrace attach failed on the payload; check "
             "/data/memdbg/memdbg.log for the errno line";
    default: break;
    }
  }
  if (command == MEMDBG_CMD_SCAN_EXACT ||
      command == MEMDBG_CMD_SCAN_PROCESS_EXACT ||
      command == MEMDBG_CMD_SCAN_AOB ||
      command == MEMDBG_CMD_SCAN_PROCESS_AOB ||
      command == MEMDBG_CMD_SCAN_UNKNOWN ||
      command == MEMDBG_CMD_SCAN_UNKNOWN_V2 ||
      command == MEMDBG_CMD_SCAN_POINTER) {
    switch (static_cast<memdbg_status_t>(status)) {
    case MEMDBG_ERR_STATE:
      return "another process-wide scan is already running; wait for it to "
             "finish before starting a new one";
    case MEMDBG_ERR_NOT_FOUND:
      return "the target process no longer exists; refresh PIDs";
    case MEMDBG_ERR_PROTOCOL:
      return (command == MEMDBG_CMD_SCAN_UNKNOWN ||
              command == MEMDBG_CMD_SCAN_UNKNOWN_V2)
          ? "unknown-scan request ABI mismatch; update the payload and "
            "frontend together"
          : "scan request size mismatch; the frontend and payload protocol "
            "versions may be out of sync";
    case MEMDBG_ERR_UNSUPPORTED:
      return (command == MEMDBG_CMD_SCAN_UNKNOWN ||
              command == MEMDBG_CMD_SCAN_UNKNOWN_V2)
          ? "the payload does not support this unknown-scan request ABI version"
          : "this scan request is not supported by the payload";
    default: break;
    }
  }
  switch (static_cast<memdbg_status_t>(status)) {
  case MEMDBG_ERR_IO:          return "verify the target process, selected map/range, and payload privileges";
  case MEMDBG_ERR_PERMISSION:  return "the payload could not access the target process memory";
  case MEMDBG_ERR_PARAM:       return "check that a process and a valid address/range are selected";
  case MEMDBG_ERR_UNSUPPORTED: return "this payload/platform does not expose the requested operation";
  default:                     return "";
  }
}

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_CLIENT_INTERNAL_HPP */

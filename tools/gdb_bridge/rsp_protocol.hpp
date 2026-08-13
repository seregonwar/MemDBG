/*
 * MemDBG - Shared GDB Remote Serial Protocol primitives.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_GDB_BRIDGE_RSP_PROTOCOL_HPP
#define MEMDBG_GDB_BRIDGE_RSP_PROTOCOL_HPP

#include "memdbg_client.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::gdb_bridge {

bool parse_thread_id(const char *s, int32_t &pid_out, int32_t &tid_out);

std::string gdb_watchpoint_stop_field(
  uint64_t dr6, const std::vector<memdbg::frontend::Client::DebugWatchpointEntry> &entries);

bool gdb_memory_range_mapped(const std::vector<memdbg::frontend::MapEntry> &maps, uint64_t address,
                             uint64_t length);

namespace detail {

inline constexpr uint32_t kMemChunk = 0x10000U;
inline constexpr uint64_t kRspMaxMemory = 0x100000U;

bool parse_hex_u64(const std::string &s, size_t begin, size_t end, uint64_t &out);
bool parse_hex_u64(const char *s, uint64_t &out);
std::string err_packet(int code);
int watch_type_from_z(char kind);
std::string xml_escape(const std::string &text);
std::string qxfer_slice(const std::string &data, size_t offset, size_t length);
bool parse_qxfer_request(const std::string &packet, const char *prefix, std::string &annex,
                         size_t &offset, size_t &length);

} // namespace detail
} // namespace memdbg::gdb_bridge

#endif /* MEMDBG_GDB_BRIDGE_RSP_PROTOCOL_HPP */

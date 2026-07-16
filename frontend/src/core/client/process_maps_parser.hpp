/*
 * MemDBG - Process-map wire parsing and metadata helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_PROCESS_MAPS_PARSER_HPP
#define MEMDBG_FRONTEND_PROCESS_MAPS_PARSER_HPP

#include "memdbg_client.hpp"

#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace memdbg::frontend::detail {

inline std::string map_type_name(uint32_t flags) {
  const uint32_t type =
      (flags & MEMDBG_MAP_FLAG_TYPE_MASK) >> MEMDBG_MAP_FLAG_TYPE_SHIFT;
  switch (type) {
  case MEMDBG_MAP_TYPE_NONE: return "untyped";
  case MEMDBG_MAP_TYPE_DEFAULT: return "default";
  case MEMDBG_MAP_TYPE_VNODE: return "file";
  case MEMDBG_MAP_TYPE_SWAP: return "swap";
  case MEMDBG_MAP_TYPE_DEVICE: return "device";
  case MEMDBG_MAP_TYPE_PHYSICAL: return "physical";
  case MEMDBG_MAP_TYPE_DEAD: return "dead";
  case MEMDBG_MAP_TYPE_SCATTER_GATHER: return "scatter/gather";
  case MEMDBG_MAP_TYPE_MANAGED_DEVICE: return "managed device";
  default: return "unknown";
  }
}

inline std::string map_wire_string(const char *data, size_t size) {
  size_t len = 0U;
  while (len < size && data[len] != '\0') ++len;
  return std::string(data, len);
}

inline bool parse_process_maps_response(const std::vector<uint8_t> &response,
                                        std::vector<MapEntry> &out,
                                        std::string &error) {
  if (response.size() < sizeof(uint32_t)) {
    error = "short map response";
    return false;
  }

  uint32_t count = 0U;
  std::memcpy(&count, response.data(), sizeof(count));
  constexpr uint32_t kMaxMapEntries =
      (MEMDBG_PROTOCOL_MAX_MAP_RESPONSE - sizeof(uint32_t)) /
      sizeof(memdbg_map_entry_t);
  if (count > kMaxMapEntries) {
    error = "map response has an invalid item count";
    return false;
  }

  const size_t expected =
      sizeof(count) + static_cast<size_t>(count) * sizeof(memdbg_map_entry_t);
  if (response.size() != expected) {
    error = response.size() < expected ? "truncated map response"
                                       : "map response has trailing data";
    return false;
  }

  out.clear();
  out.reserve(count);
  for (uint32_t i = 0U; i < count; ++i) {
    memdbg_map_entry_t wire{};
    std::memcpy(&wire,
                response.data() + sizeof(count) +
                    static_cast<size_t>(i) * sizeof(wire),
                sizeof(wire));
    if (wire.end <= wire.start) continue;

    MapEntry entry;
    entry.start = wire.start;
    entry.end = wire.end;
    entry.protection = wire.protection & 0x7U;
    entry.flags = wire.flags;
    entry.type = map_type_name(wire.flags);
    entry.name = map_wire_string(wire.name, sizeof(wire.name));
    if (entry.name.empty()) entry.name = "[" + entry.type + "]";
    out.push_back(std::move(entry));
  }

  error.clear();
  return true;
}

} // namespace memdbg::frontend::detail

#endif /* MEMDBG_FRONTEND_PROCESS_MAPS_PARSER_HPP */

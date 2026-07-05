/*
 * MemDBG - Multi-format trainer file support.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "trainer_format.hpp"
#include "app_state.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <vector>

namespace memdbg::frontend {

/* ---- format detection ---- */

TrainerFormat detect_trainer_format(const std::string &path) {
  std::filesystem::path p(path);
  std::string ext = p.extension().string();
  std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (ext == ".cht" || ext == ".trainer") return TrainerFormat::CHT;
  if (ext == ".shn")    return TrainerFormat::SHN;
  if (ext == ".json")   return TrainerFormat::JSON;
  if (ext == ".mc4")    return TrainerFormat::MC4;
  if (ext == ".shnext") return TrainerFormat::SHNEXT;
  return TrainerFormat::Unknown;
}

const char *trainer_format_name(TrainerFormat fmt) {
  switch (fmt) {
  case TrainerFormat::CHT:   return "MemDBG .cht";
  case TrainerFormat::SHN:   return "Reaper .shn";
  case TrainerFormat::JSON:  return "GoldHEN .json";
  case TrainerFormat::MC4:   return "Reaper .mc4 (encrypted)";
  case TrainerFormat::SHNEXT:return "Reaper .shnext (proprietary)";
  default:                   return "Unknown";
  }
}

const char *trainer_format_ext(TrainerFormat fmt) {
  switch (fmt) {
  case TrainerFormat::CHT:   return ".cht";
  case TrainerFormat::SHN:   return ".shn";
  case TrainerFormat::JSON:  return ".json";
  case TrainerFormat::MC4:   return ".mc4";
  case TrainerFormat::SHNEXT:return ".shnext";
  default:                   return ".cht";
  }
}

bool trainer_format_supports_save(TrainerFormat fmt) {
  return fmt == TrainerFormat::CHT || fmt == TrainerFormat::SHN || fmt == TrainerFormat::JSON;
}

/* ---- shared helpers ---- */

std::string bytes_to_hex(const std::vector<uint8_t> &bytes) {
  std::ostringstream out;
  out << std::hex << std::uppercase << std::setfill('0');
  for (uint8_t b : bytes) out << std::setw(2) << static_cast<unsigned>(b);
  return out.str();
}

static int map_index_for_address(const AppState &state, uint64_t addr) {
  for (int i = 0; i < static_cast<int>(state.maps.size()); ++i)
    if (addr >= state.maps[i].start && addr < state.maps[i].end) return i;
  return -1;
}

static std::string process_label(const AppState &state) {
  if (state.has_process_info && !state.selected_process_info.title_id.empty())
    return state.selected_process_info.title_id;
  std::string n = selected_process_name(state);
  return n == "No process selected" ? "unknown" : n;
}

static const char *cht_type_name(int type) {
  switch (type) {
  case MEMDBG_VALUE_U8:  return "byte";
  case MEMDBG_VALUE_U16: return "2 bytes";
  case MEMDBG_VALUE_U32: return "4 bytes";
  case MEMDBG_VALUE_U64: return "8 bytes";
  case MEMDBG_VALUE_F32: return "float";
  case MEMDBG_VALUE_F64: return "double";
  case MEMDBG_VALUE_POINTER: return "pointer";
  default: return "hex";
  }
}

static int cht_type_from_string(std::string value) {
  value = lower_copy(trim_copy(std::move(value)));
  if (value == "byte" || value == "1 byte" || value == "u8") return MEMDBG_VALUE_U8;
  if (value == "2 bytes" || value == "u16") return MEMDBG_VALUE_U16;
  if (value == "4 bytes" || value == "u32" || value == "uint") return MEMDBG_VALUE_U32;
  if (value == "8 bytes" || value == "u64" || value == "ulong") return MEMDBG_VALUE_U64;
  if (value == "float") return MEMDBG_VALUE_F32;
  if (value == "double") return MEMDBG_VALUE_F64;
  if (value == "pointer") return MEMDBG_VALUE_POINTER;
  return MEMDBG_VALUE_BYTES;
}

static bool parse_hex_or_int(const std::string &text, uint64_t &out) {
  if (parse_u64(text.c_str(), out)) return true;
  std::string value = trim_copy(text);
  if (!value.empty() && value[0] == '@') value.erase(value.begin());
  size_t us = value.find('_');
  if (us != std::string::npos) value = value.substr(0, us);
  if (value.empty() || !is_hex_digit_string(value)) return false;
  char *end = nullptr; errno = 0;
  unsigned long long parsed = std::strtoull(value.c_str(), &end, 16);
  if (errno != 0 || end == value.c_str() || *end != '\0') return false;
  out = static_cast<uint64_t>(parsed);
  return true;
}

static std::vector<std::string> split_pipe(const std::string &line) {
  std::vector<std::string> tokens;
  size_t start = 0;
  while (start <= line.size()) {
    size_t pos = line.find('|', start);
    if (pos == std::string::npos) { tokens.push_back(line.substr(start)); break; }
    tokens.push_back(line.substr(start, pos - start));
    start = pos + 1;
  }
  return tokens;
}

bool capture_off_value(AppState &state, CheatEntry &cheat) {
  if (!state.client.connected()) { cheat.status = "No console session"; return false; }
  if (client_async_busy(state)) { cheat.status = "Client busy"; return false; }
  int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0 || cheat.bytes.empty()) { cheat.status = "No target value"; return false; }
  std::vector<uint8_t> current;
  if (!state.client.memory_read(pid, cheat.address, static_cast<uint32_t>(cheat.bytes.size()), current) ||
      current.size() != cheat.bytes.size()) {
    cheat.status = state.client.last_error().empty() ? "OFF capture failed" : state.client.last_error();
    return false;
  }
  cheat.off_bytes = std::move(current);
  cheat.has_off_bytes = true;
  cheat.status = "OFF value captured";
  return true;
}

/* ================================================================
   PIPE-DELIMITED: .cht / .shn  (same format, different extensions)
   ================================================================ */

static bool parse_pipe_data_line(AppState &state, const std::vector<std::string> &tokens,
                                 CheatEntry &cheat) {
  if (tokens.size() < 6 || tokens[0] != "data") return false;
  uint64_t address = 0;
  size_t type_idx = 3;
  if (!tokens[1].empty() && tokens[1][0] == '@') {
    if (!parse_hex_or_int(tokens[1], address)) return false;
    type_idx = 2;
  } else {
    uint64_t section = 0, offset = 0;
    if (!parse_hex_or_int(tokens[1], section) || !parse_hex_or_int(tokens[2], offset)) return false;
    if (section < state.maps.size())
      address = state.maps[static_cast<size_t>(section)].start + offset;
    else if (tokens.size() > 7 && parse_hex_or_int(tokens.back(), address))
      type_idx = 3;
    else
      address = offset;
  }
  if (tokens.size() <= type_idx + 2U) return false;
  int type = cht_type_from_string(tokens[type_idx]);
  std::vector<uint8_t> bytes;
  if (!build_value_bytes(type, tokens[type_idx + 1U].c_str(), bytes)) return false;
  cheat.description = tokens.size() > type_idx + 3U && !tokens[type_idx + 3U].empty()
                          ? tokens[type_idx + 3U] : "Imported cheat";
  cheat.pid = state.selected_pid;
  cheat.address = address;
  cheat.value_type = type;
  cheat.value_text = tokens[type_idx + 1U];
  cheat.bytes = std::move(bytes);
  cheat.locked = tokens.size() > type_idx + 2U && tokens[type_idx + 2U] == "1";
  cheat.enabled = true;
  for (size_t i = type_idx + 4U; i < tokens.size(); ++i) {
    if (tokens[i].rfind("off:", 0) == 0 && parse_hex_bytes(tokens[i].c_str() + 4, cheat.off_bytes))
      cheat.has_off_bytes = true;
  }
  return true;
}

static int load_pipe_delimited(AppState &state, const std::string &path) {
  std::ifstream in(path);
  if (!in) return -1;
  std::string line;
  int imported = 0;
  bool first = true;
  while (std::getline(in, line)) {
    line = trim_copy(line);
    if (line.empty()) continue;
    if (first) {
      first = false;
      if (line.find('|') != std::string::npos && line.rfind("data|", 0) != 0) continue;
    }
    CheatEntry cheat;
    if (parse_pipe_data_line(state, split_pipe(line), cheat)) {
      if (state.client.connected()) (void)capture_off_value(state, cheat);
      state.cheats.push_back(std::move(cheat));
      imported++;
    }
  }
  return imported;
}

static bool save_pipe_delimited(AppState &state, const std::string &path) {
  std::filesystem::path p(path);
  std::error_code ec;
  if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path(), ec);
  if (ec) return false;
  std::ofstream out(p, std::ios::binary);
  if (!out) return false;
  out << "1.4|" << process_label(state);
  if (state.has_process_info && !state.selected_process_info.title_id.empty())
    out << "|ID:" << state.selected_process_info.title_id;
  else out << "|ID:unknown";
  out << "|VER:unknown|FM:MemDBG\n";
  for (const auto &cheat : state.cheats) {
    int section = map_index_for_address(state, cheat.address);
    uint64_t offset = cheat.address;
    if (section >= 0) offset = cheat.address - state.maps[static_cast<size_t>(section)].start;
    out << "data|" << (section >= 0 ? section : 0) << "|" << std::hex << std::uppercase << offset << std::dec
        << "|" << cht_type_name(cheat.value_type) << "|" << cheat.value_text << "|"
        << (cheat.locked ? "1" : "0") << "|" << cheat.description << "|"
        << std::hex << std::uppercase << cheat.address << std::dec;
    if (cheat.has_off_bytes) out << "|off:" << bytes_to_hex(cheat.off_bytes);
    out << "\n";
  }
  return true;
}

/* ================================================================
   GoldHEN JSON (formal nlohmann/json parser)
   ================================================================ */

static std::string json_string_or_number(const nlohmann::json &node) {
  if (node.is_string()) return node.get<std::string>();
  if (node.is_number_unsigned()) return std::to_string(node.get<uint64_t>());
  if (node.is_number_integer()) return std::to_string(node.get<int64_t>());
  if (node.is_number_float()) return std::to_string(node.get<double>());
  return {};
}

static bool memory_entry_is_off_note(const nlohmann::json &mem) {
  if (!mem.is_object() || !mem.contains("note")) return false;
  std::string note = lower_copy(json_string_or_number(mem["note"]));
  return note.find("off") != std::string::npos;
}

static int load_goldhen_json(AppState &state, const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return -1;

  nlohmann::json json;
  try {
    in >> json;
  } catch (const std::exception &) {
    return -1;
  }

  std::vector<nlohmann::json> mods;
  if (json.is_object()) {
    if (json.contains("mods") && json["mods"].is_array()) {
      for (const auto &mod : json["mods"])
        mods.push_back(mod);
    } else if (json.contains("memory") && json["memory"].is_array()) {
      mods.push_back(json); /* single-mod object */
    }
  } else if (json.is_array()) {
    for (const auto &mod : json)
      mods.push_back(mod);
  }

  int imported = 0;
  for (const auto &mod : mods) {
    if (!mod.is_object() || !mod.contains("name") || !mod["name"].is_string())
      continue;
    const std::string mod_name = mod["name"].get<std::string>();

    if (!mod.contains("memory") || !mod["memory"].is_array()) continue;
    for (const auto &mem : mod["memory"]) {
      if (!mem.is_object()) continue;
      if (!mem.contains("offset")) continue;

      std::string offset_str = json_string_or_number(mem["offset"]);
      std::string on_str;
      if (mem.contains("on")) on_str = json_string_or_number(mem["on"]);
      else if (mem.contains("value")) on_str = json_string_or_number(mem["value"]);

      std::string off_str;
      if (mem.contains("off")) off_str = json_string_or_number(mem["off"]);

      uint64_t address = 0;
      if (offset_str.empty() || !parse_hex_or_int(offset_str, address)) continue;

      /* OFF-only entry with a note attaches to the previous cheat. */
      if (on_str.empty() && mem.contains("value") && memory_entry_is_off_note(mem)) {
        std::vector<uint8_t> off_bytes;
        if (!state.cheats.empty() && parse_hex_bytes(mem["value"].get<std::string>().c_str(), off_bytes)) {
          state.cheats.back().off_bytes = std::move(off_bytes);
          state.cheats.back().has_off_bytes = true;
        }
        continue;
      }

      std::vector<uint8_t> bytes;
      if (on_str.empty() || !parse_hex_bytes(on_str.c_str(), bytes) || bytes.empty()) continue;

      CheatEntry cheat;
      cheat.description = mod_name.empty()
                              ? ("JSON cheat " + std::to_string(imported + 1))
                              : mod_name;
      cheat.pid = state.selected_pid;
      cheat.address = address;
      cheat.value_text = on_str;
      cheat.bytes = std::move(bytes);
      cheat.locked = false;
      cheat.enabled = true;

      if (mem.contains("type") && mem["type"].is_string()) {
        cheat.value_type = cht_type_from_string(mem["type"].get<std::string>());
      } else {
        cheat.value_type = MEMDBG_VALUE_BYTES;
      }

      if (!off_str.empty()) {
        std::vector<uint8_t> off_bytes;
        if (parse_hex_bytes(off_str.c_str(), off_bytes) && !off_bytes.empty()) {
          cheat.off_bytes = std::move(off_bytes);
          cheat.has_off_bytes = true;
        }
      }

      if (state.client.connected()) (void)capture_off_value(state, cheat);
      state.cheats.push_back(std::move(cheat));
      imported++;
    }
  }
  return imported;
}

static bool save_goldhen_json(const AppState &state, const std::string &path) {
  std::filesystem::path p(path);
  std::error_code ec;
  if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path(), ec);
  if (ec) return false;

  nlohmann::json root = nlohmann::json::object();
  root["name"] = state.has_process_info && !state.selected_process_info.title_id.empty()
                     ? state.selected_process_info.title_id
                     : selected_process_name(state);
  root["id"] = state.has_process_info ? state.selected_process_info.title_id : "unknown";
  root["version"] = "01.00";
  root["process"] = "eboot.bin";
  root["credits"] = nlohmann::json::array();

  nlohmann::json mods = nlohmann::json::array();
  for (const auto &cheat : state.cheats) {
    nlohmann::json mem_entry = nlohmann::json::object();
    mem_entry["offset"] = hex_u64(cheat.address);
    mem_entry["on"] = bytes_to_hex(cheat.bytes);
    mem_entry["type"] = cht_type_name(cheat.value_type);
    if (cheat.has_off_bytes && !cheat.off_bytes.empty())
      mem_entry["off"] = bytes_to_hex(cheat.off_bytes);

    nlohmann::json mod = nlohmann::json::object();
    mod["name"] = cheat.description;
    mod["type"] = "checkbox";
    mod["memory"] = nlohmann::json::array({ mem_entry });
    mods.push_back(mod);
  }
  root["mods"] = mods;

  std::ofstream out(p, std::ios::binary);
  if (!out) return false;
  out << root.dump(2);
  return !out.fail();
}

/* ================================================================
   MC4 / SHNEXT — proprietary/encrypted, detection only
   ================================================================ */

static int load_unsupported(AppState &state, const std::string &path,
                            TrainerFormat fmt) {
  (void)state;
  (void)path;
  (void)fmt;
  /* MC4 is encrypted with a key known only to Reaper Studio.
     SHNEXT is a proprietary binary format.
     We detect these formats but cannot parse them without the official tools. */
  return -2; /* special code: unsupported format */
}

/* ================================================================
   Public API
   ================================================================ */

int load_trainer_file(AppState &state, const std::string &path) {
  TrainerFormat fmt = detect_trainer_format(path);
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before loading trainer entries");
    return -1;
  }
  int result = 0;
  switch (fmt) {
  case TrainerFormat::CHT:
  case TrainerFormat::SHN:
    result = load_pipe_delimited(state, path);
    break;
  case TrainerFormat::JSON:
    result = load_goldhen_json(state, path);
    break;
  case TrainerFormat::MC4:
  case TrainerFormat::SHNEXT:
    result = load_unsupported(state, path, fmt);
    break;
  default:
    /* try pipe-delimited as fallback */
    result = load_pipe_delimited(state, path);
    break;
  }
  if (result == -2) {
    set_status(state, std::string(trainer_format_name(fmt)) +
                          " format requires Reaper Studio — cannot parse proprietary file");
    return -1;
  }
  if (result < 0) {
    set_status(state, "Trainer file not found or unreadable");
    return -1;
  }
  set_status(state, "Loaded " + std::to_string(result) + " trainer entries (" +
                        std::string(trainer_format_name(fmt)) + ")");
  return result;
}

bool save_trainer_file(AppState &state, const std::string &path) {
  TrainerFormat fmt = detect_trainer_format(path);
  if (!trainer_format_supports_save(fmt)) {
    set_status(state, std::string(trainer_format_name(fmt)) + " format is read-only — use .cht, .shn, or .json");
    return false;
  }
  bool ok = false;
  switch (fmt) {
  case TrainerFormat::CHT:
  case TrainerFormat::SHN:
    ok = save_pipe_delimited(state, path);
    break;
  case TrainerFormat::JSON:
    ok = save_goldhen_json(state, path);
    break;
  default:
    ok = save_pipe_delimited(state, path);
    break;
  }
  if (!ok) {
    set_status(state, "Failed to save trainer file");
    return false;
  }
  set_status(state, "Saved " + std::to_string(state.cheats.size()) + " trainer entries (" +
                        std::string(trainer_format_name(fmt)) + ")");
  return true;
}

} // namespace memdbg::frontend

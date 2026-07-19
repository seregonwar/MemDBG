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
extern "C" {
#include "sJson.c"
}

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
  return state.selected_pid > 0 ? selected_process_name(state) : "unknown";
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

/* Parse a number that may be decimal, hex (0x prefix), or bare hex.
   When hex_only is true, decimal parsing is skipped — the input is
   assumed to be hex (e.g. pipe-delimited .cht offsets and absolute
   addresses written with std::hex by save_pipe_delimited). */
static bool parse_hex_or_int(const std::string &text, uint64_t &out,
                             bool hex_only = false) {
  if (!hex_only && parse_u64(text.c_str(), out)) return true;
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

/* Handle the PS4Cheater/Reaper "simple pointer|" variant format:
 *   simple pointer|pointer|4 bytes|@ADDR_CHAIN|data|4 bytes|VALUE|LOCKED|DESC|
 * Unlike the standard format, the "data" keyword appears at index 4.
 * Pointer chains with + offsets (e.g. @ADDR+448+58) require live memory
 * resolution and are skipped — only base addresses without + are imported. */
static bool parse_pointer_chain_line(AppState &state,
                                     const std::vector<std::string> &tokens,
                                     CheatEntry &cheat) {
  /* Find the "data" token */
  size_t data_idx = 0;
  for (; data_idx < tokens.size(); ++data_idx)
    if (tokens[data_idx] == "data") break;
  if (data_idx == 0 || data_idx >= tokens.size())
    return false; /* "data" at index 0 is standard format; missing is invalid */
  if (tokens.size() <= data_idx + 3U) return false;

  /* Address at tokens[data_idx - 1] (e.g. @BASE_2_OFFSET+448+58...)
   * Pointer chains with + offsets require live memory resolution — skip them. */
  const std::string &addr_token = tokens[data_idx - 1];
  if (addr_token.find('+') != std::string::npos) return false;

  uint64_t address = 0;
  if (!parse_hex_or_int(addr_token, address, /*hex_only=*/true)) return false;

  size_t type_idx = data_idx + 1U;
  if (tokens.size() <= type_idx + 2U) return false;
  int type = cht_type_from_string(tokens[type_idx]);
  std::vector<uint8_t> bytes;
  if (!build_value_bytes(type, tokens[type_idx + 1U].c_str(), bytes, true)) return false;
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

static bool parse_pipe_data_line(AppState &state, const std::vector<std::string> &tokens,
                                 CheatEntry &cheat) {
  if (tokens.size() < 6 || tokens[0] != "data") return false;
  uint64_t address = 0;
  size_t type_idx = 3;
  if (!tokens[1].empty() && tokens[1][0] == '@') {
    if (!parse_hex_or_int(tokens[1], address, /*hex_only=*/true)) return false;
    type_idx = 2;
  } else {
    uint64_t section = 0, offset = 0;
    if (!parse_hex_or_int(tokens[1], section)) return false;
    /* Offsets are written in hex by save_pipe_delimited. */
    if (!parse_hex_or_int(tokens[2], offset, /*hex_only=*/true)) return false;
    if (section < state.maps.size())
      address = state.maps[static_cast<size_t>(section)].start + offset;
    else if (tokens.size() > 7 && parse_hex_or_int(tokens.back(), address, /*hex_only=*/true))
      type_idx = 3;
    else
      address = offset;
  }
  if (tokens.size() <= type_idx + 2U) return false;
  int type = cht_type_from_string(tokens[type_idx]);
  std::vector<uint8_t> bytes;
  if (!build_value_bytes(type, tokens[type_idx + 1U].c_str(), bytes, true)) return false;
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
      /* Skip header line unless it starts with a known data format */
      if (line.find('|') != std::string::npos &&
          line.rfind("data|", 0) != 0 &&
          line.rfind("simple pointer|", 0) != 0)
        continue;
    }
    CheatEntry cheat;
    auto tokens = split_pipe(line);
    bool ok = tokens[0] == "data"
                  ? parse_pipe_data_line(state, tokens, cheat)
                  : parse_pointer_chain_line(state, tokens, cheat);
    if (ok) {
      if (state.client.connected()) (void)capture_off_value(state, cheat);
      state.plugin.cheats.push_back(std::move(cheat));
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
  for (const auto &cheat : state.plugin.cheats) {
    int section = map_index_for_address(state, cheat.address);
    if (section >= 0) {
      uint64_t offset = cheat.address - state.maps[static_cast<size_t>(section)].start;
      out << "data|" << section << "|" << std::hex << std::uppercase << offset << std::dec
          << "|" << cht_type_name(cheat.value_type) << "|" << cheat.value_text << "|"
          << (cheat.locked ? "1" : "0") << "|" << cheat.description << "|"
          << std::hex << std::uppercase << cheat.address << std::dec;
    } else {
      out << "data|@" << std::hex << std::uppercase << cheat.address << std::dec
          << "|" << cht_type_name(cheat.value_type) << "|" << cheat.value_text << "|"
          << (cheat.locked ? "1" : "0") << "|" << cheat.description << "|"
          << std::hex << std::uppercase << cheat.address << std::dec;
    }
    if (cheat.has_off_bytes) out << "|off:" << bytes_to_hex(cheat.off_bytes);
    out << "\n";
  }
  return true;
}

/* ================================================================
   GoldHEN JSON (formal nlohmann/json parser)
   ================================================================ */

static int load_goldhen_json(AppState &state, const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return -1;
  std::string content((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());

  std::string parse_error;
  std::vector<CheatEntry> parsed = parse_goldhen_mods(content, state.selected_pid, &parse_error, &state.maps);
  if (parsed.empty() && !parse_error.empty()) {
    set_status(state, parse_error);
    return -1;
  }

  int imported = static_cast<int>(parsed.size());
  for (auto &cheat : parsed) {
    if (state.client.connected()) (void)capture_off_value(state, cheat);
    state.plugin.cheats.push_back(std::move(cheat));
  }
  return imported;
}

/* ================================================================
   GoldHEN JSON — unified parser (shared with cheat sources)
   ================================================================ */

/* ---- sJson helpers (replace nlohmann json_string_or_number / json_field_contains) ---- */

static std::string sjson_value_to_string(const JsonValue *v) {
  if (!v) return {};
  if (json_is_string(v)) {
    const char *s = nullptr; uint32_t len = 0;
    json_get_string(v, &s, &len);
    return std::string(s, len);
  }
  if (json_is_integer(v))   { int64_t i; json_get_int(v, &i); return std::to_string(i); }
  if (json_is_float(v))     { double f; json_get_float(v, &f); return std::to_string(f); }
  if (json_is_bool(v))      { bool b; json_get_bool(v, &b); return b ? "true" : "false"; }
  if (json_is_array(v)) {
    uint32_t alen = 0; json_get_arr_len(v, &alen);
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (uint32_t i = 0; i < alen; i++) {
      JsonValue *elem = nullptr; json_arr_get(v, i, &elem);
      if (!elem || !json_is_number(elem)) continue;
      int64_t val = 0;
      if (json_is_integer(elem)) json_get_int(elem, &val);
      else { double d; json_get_float(elem, &d); val = static_cast<int64_t>(d); }
      if (i > 0) oss << ' ';
      oss << std::setw(2) << (val & 0xFF);
    }
    return oss.str();
  }
  return {};
}

static bool sjson_field_contains(const JsonValue *obj, const char *field,
                                  const std::string &needle) {
  if (!obj || !json_is_object(obj)) return false;
  JsonValue *val = nullptr;
  if (json_obj_get(obj, field, &val) != JSON_OK) return false;
  std::string value = lower_copy(sjson_value_to_string(val));
  std::string lower_n = lower_copy(needle);
  return value.find(lower_n) != std::string::npos;
}

/* ---- GoldHEN JSON parser (sJson backend) ---- */

std::vector<CheatEntry> parse_goldhen_mods(const std::string &json_content,
                                            int32_t selected_pid,
                                            std::string *error,
                                            const std::vector<MapEntry> *maps) {
  std::vector<CheatEntry> result;

  JsonArena *arena = json_arena_create(nullptr, 0);
  if (!arena) {
    if (error) *error = "Failed to create JSON arena";
    return result;
  }

  JsonError s_err = JSON_OK;
  JsonValue *root = json_parse(arena, json_content.data(),
                               json_content.size(), &s_err);
  if (!root || s_err != JSON_OK) {
    if (error) *error = std::string("JSON parse error: ") + json_error_str(s_err);
    json_arena_destroy(arena);
    return result;
  }

  /* Normalise into a flat list of mod objects (JsonValue*). */
  std::vector<JsonValue *> mods;
  if (json_is_object(root)) {
    JsonValue *mods_arr = nullptr;
    if (json_obj_get(root, "mods", &mods_arr) == JSON_OK && json_is_array(mods_arr)) {
      uint32_t mc = 0; json_get_arr_len(mods_arr, &mc);
      for (uint32_t i = 0; i < mc; i++) {
        JsonValue *m = nullptr;
        if (json_arr_get(mods_arr, i, &m) == JSON_OK) mods.push_back(m);
      }
    } else {
      JsonValue *mem_arr = nullptr;
      if (json_obj_get(root, "memory", &mem_arr) == JSON_OK &&
          json_is_array(mem_arr))
        mods.push_back(root); /* single-mod object */
    }
  } else if (json_is_array(root)) {
    uint32_t rc = 0; json_get_arr_len(root, &rc);
    for (uint32_t i = 0; i < rc; i++) {
      JsonValue *m = nullptr;
      if (json_arr_get(root, i, &m) == JSON_OK) mods.push_back(m);
    }
  }

  for (JsonValue *mod : mods) {
    if (!mod || !json_is_object(mod)) continue;

    std::string mod_name = "Unnamed";
    {
      JsonValue *name_v = nullptr;
      if (json_obj_get(mod, "name", &name_v) == JSON_OK && json_is_string(name_v)) {
        const char *s = nullptr; uint32_t l = 0;
        json_get_string(name_v, &s, &l);
        mod_name = std::string(s, l);
      } else {
        JsonValue *title_v = nullptr;
        if (json_obj_get(mod, "title", &title_v) == JSON_OK && json_is_string(title_v)) {
          const char *s = nullptr; uint32_t l = 0;
          json_get_string(title_v, &s, &l);
          mod_name = std::string(s, l);
        }
      }
    }

    JsonValue *memory = nullptr;
    if (json_obj_get(mod, "memory", &memory) != JSON_OK || !json_is_array(memory))
      continue;

    uint32_t mem_count = 0; json_get_arr_len(memory, &mem_count);

    for (uint32_t mei = 0; mei < mem_count; mei++) {
      JsonValue *mem = nullptr;
      if (json_arr_get(memory, mei, &mem) != JSON_OK || !json_is_object(mem))
        continue;

      /* offset field is mandatory. */
      JsonValue *off_v = nullptr;
      if (json_obj_get(mem, "offset", &off_v) != JSON_OK) continue;
      std::string offset_str = sjson_value_to_string(off_v);
      uint64_t address = 0;
      if (offset_str.empty() || !parse_hex_or_int(offset_str, address)) continue;

      /* Resolve section-based addressing. */
      JsonValue *sec = nullptr;
      if (maps && json_obj_get(mem, "section", &sec) == JSON_OK && json_is_number(sec)) {
        int64_t si = 0;
        if (json_is_integer(sec)) json_get_int(sec, &si);
        else { double d; json_get_float(sec, &d); si = static_cast<int64_t>(d); }
        if (si >= 0 && static_cast<size_t>(si) < maps->size())
          address = (*maps)[static_cast<size_t>(si)].start + address;
      }

      /* "on" or "value" field. */
      JsonValue *on_v = nullptr;
      bool has_on_key = (json_obj_get(mem, "on", &on_v) == JSON_OK);
      std::string on_str;
      if (has_on_key)
        on_str = sjson_value_to_string(on_v);
      else {
        JsonValue *val_v = nullptr;
        if (json_obj_get(mem, "value", &val_v) == JSON_OK)
          on_str = sjson_value_to_string(val_v);
      }

      /* OFF-only note entry attaches to the previous cheat. */
      if (!has_on_key && !on_str.empty() &&
          sjson_field_contains(mem, "note", "off")) {
        JsonValue *val_v = nullptr;
        if (json_obj_get(mem, "value", &val_v) == JSON_OK) {
          std::string val_str = sjson_value_to_string(val_v);
          std::vector<uint8_t> off_bytes;
          if (!result.empty() && parse_hex_bytes(val_str.c_str(), off_bytes)) {
            result.back().off_bytes = std::move(off_bytes);
            result.back().has_off_bytes = true;
          }
        }
        continue;
      }

      /* Decode the ON bytes. */
      std::vector<uint8_t> bytes;
      if (on_str.empty() || !parse_hex_bytes(on_str.c_str(), bytes) || bytes.empty())
        continue;

      CheatEntry cheat;
      cheat.description = mod_name.empty()
                              ? ("JSON cheat " + std::to_string(result.size() + 1))
                              : mod_name;
      cheat.pid = selected_pid;
      cheat.address = address;
      cheat.value_text = on_str;
      cheat.bytes = std::move(bytes);
      cheat.locked = false;
      cheat.enabled = true;

      /* Locked / enabled from mod-level keys. */
      JsonValue *lv = nullptr;
      if (json_obj_get(mod, "locked", &lv) == JSON_OK) {
        if (json_is_bool(lv)) json_get_bool(lv, &cheat.locked);
        else if (json_is_string(lv)) {
          const char *s = nullptr; uint32_t l = 0;
          json_get_string(lv, &s, &l);
          std::string lvs(s, l);
          cheat.locked = (lvs == "1" || lvs == "true");
        }
      }
      JsonValue *ev = nullptr;
      if (json_obj_get(mod, "enabled", &ev) == JSON_OK) {
        if (json_is_bool(ev)) json_get_bool(ev, &cheat.enabled);
        else if (json_is_string(ev)) {
          const char *s = nullptr; uint32_t l = 0;
          json_get_string(ev, &s, &l);
          std::string evs(s, l);
          cheat.enabled = !(evs == "0" || evs == "false");
        }
      }

      /* Value type. */
      JsonValue *tv = nullptr;
      if (json_obj_get(mem, "type", &tv) == JSON_OK && json_is_string(tv)) {
        const char *s = nullptr; uint32_t l = 0;
        json_get_string(tv, &s, &l);
        cheat.value_type = cht_type_from_string(std::string(s, l));
      } else {
        cheat.value_type = MEMDBG_VALUE_BYTES;
      }

      /* Off bytes. */
      JsonValue *offb = nullptr;
      if (json_obj_get(mem, "off", &offb) == JSON_OK) {
        std::string off_str = sjson_value_to_string(offb);
        if (!off_str.empty()) {
          std::vector<uint8_t> off_bytes;
          if (parse_hex_bytes(off_str.c_str(), off_bytes) && !off_bytes.empty()) {
            cheat.off_bytes = std::move(off_bytes);
            cheat.has_off_bytes = true;
          }
        }
      }

      result.push_back(std::move(cheat));
    }
  }

  json_arena_destroy(arena);

  if (result.empty() && error && error->empty())
    *error = "No valid cheat entries found in JSON";

  return result;
}

static bool save_goldhen_json(const AppState &state, const std::string &path) {
  std::filesystem::path p(path);
  std::error_code ec;
  if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path(), ec);
  if (ec) return false;

  JsonArena *arena = json_arena_create(nullptr, 0);
  if (!arena) return false;

  JsonValue *root = json_make_object(arena);
  if (!root) { json_arena_destroy(arena); return false; }

  /* Top-level metadata. */
  std::string name = state.has_process_info &&
                             !state.selected_process_info.title_id.empty()
                         ? state.selected_process_info.title_id
                         : (state.selected_pid > 0
                                ? selected_process_name(state)
                                : "unknown");
  json_obj_setz(root, arena, "name", json_make_stringz(arena, name.c_str()));

  std::string tid = state.has_process_info
                        ? state.selected_process_info.title_id
                        : "unknown";
  json_obj_setz(root, arena, "id", json_make_stringz(arena, tid.c_str()));
  json_obj_setz(root, arena, "version", json_make_stringz(arena, "01.00"));
  json_obj_setz(root, arena, "process", json_make_stringz(arena, "eboot.bin"));
  json_obj_setz(root, arena, "credits", json_make_array(arena));

  /* Build the mods array. */
  JsonValue *mods = json_make_array(arena);
  for (const auto &cheat : state.plugin.cheats) {
    JsonValue *mem_entry = json_make_object(arena);
    std::string offset = hex_u64(cheat.address);
    json_obj_setz(mem_entry, arena, "offset",
                  json_make_stringz(arena, offset.c_str()));
    std::string on = bytes_to_hex(cheat.bytes);
    json_obj_setz(mem_entry, arena, "on",
                  json_make_stringz(arena, on.c_str()));
    json_obj_setz(mem_entry, arena, "type",
                  json_make_stringz(arena, cht_type_name(cheat.value_type)));
    if (cheat.has_off_bytes && !cheat.off_bytes.empty()) {
      std::string off = bytes_to_hex(cheat.off_bytes);
      json_obj_setz(mem_entry, arena, "off",
                    json_make_stringz(arena, off.c_str()));
    }

    JsonValue *mem_arr = json_make_array(arena);
    json_arr_push(mem_arr, arena, mem_entry);

    JsonValue *mod = json_make_object(arena);
    json_obj_setz(mod, arena, "name",
                  json_make_stringz(arena, cheat.description.c_str()));
    json_obj_setz(mod, arena, "type", json_make_stringz(arena, "checkbox"));
    json_obj_setz(mod, arena, "enabled", json_make_bool(arena, cheat.enabled));
    json_obj_setz(mod, arena, "locked", json_make_bool(arena, cheat.locked));
    json_obj_setz(mod, arena, "memory", mem_arr);

    json_arr_push(mods, arena, mod);
  }
  json_obj_setz(root, arena, "mods", mods);

  /* Serialize with indentation matching nlohmann dump(2). */
  JsonWriteOpts opts = {true, 2U, false, false, false};
  char *output = nullptr;
  size_t out_len = 0;
  bool ok = false;
  if (json_write_arena(root, arena, &output, &out_len, &opts) == JSON_OK &&
      output) {
    std::ofstream out(p, std::ios::binary);
    if (out) {
      out.write(output, static_cast<std::streamsize>(out_len));
      ok = !out.fail();
    }
  }

  json_arena_destroy(arena);
  return ok;
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
  set_status(state, "Saved " + std::to_string(state.plugin.cheats.size()) + " trainer entries (" +
                        std::string(trainer_format_name(fmt)) + ")");
  return true;
}

} // namespace memdbg::frontend

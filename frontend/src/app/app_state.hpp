/*
 * MemDBG - Frontend application state and shared types.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_APP_STATE_HPP
#define MEMDBG_FRONTEND_APP_STATE_HPP

#include "memdbg_client.hpp"
#include "udp_log_listener.hpp"
#include "github_profile.hpp"
#include "memdbg/core/memdbg_protocol.h"

#include "imgui.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <future>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace memdbg::frontend {

using memdbg::frontend::Client;
using memdbg::frontend::HelloInfo;
using memdbg::frontend::MapEntry;
using memdbg::frontend::ProcessEntry;
using memdbg::frontend::ProcessInfo;
using memdbg::frontend::ScanResult;
using memdbg::frontend::UdpLogListener;
using memdbg::frontend::GitHubProfile;

enum class Screen {
  Home, Consoles, Processes, Memory, Scanner, PointerScanner, AOBScanner,
  Trainer, Logs, Settings, Telemetry, Credits,
};

struct CheatEntry {
  std::string description;
  int32_t pid = 0;
  uint64_t address = 0;
  int value_type = MEMDBG_VALUE_U32;
  std::string value_text;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> off_bytes;
  bool has_off_bytes = false;
  bool enabled = true;
  bool locked = false;
  bool active = false;
  std::string status;
};

struct ScanSnapshotEntry {
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
};

enum class RefineMode { Changed, Unchanged, Increased, Decreased };

struct Notification {
  std::string message;
  double created_at = 0.0;
  double duration = 4.0;
  bool dismissed = false;
};

struct AppState {
  Client client;
  UdpLogListener udp_listener;
  GitHubProfile github_profile;

  char host[64] = "192.168.1.100";
  int debug_port = 9020;
  int udp_port = 9023;
  char status[512] = "Ready";

  Screen screen = Screen::Home;
  HelloInfo hello;
  bool has_hello = false;

  std::vector<ProcessEntry> processes;
  std::vector<MapEntry> maps;
  ProcessInfo selected_process_info;
  bool has_process_info = false;
  int32_t selected_pid = 0;
  int selected_process_row = -1;
  int selected_map_row = -1;

  char read_address[32] = "0x0";
  int read_length = 256;
  std::vector<uint8_t> memory;

  char write_address[32] = "0x0";
  char write_bytes[512] = "";
  char dump_path[512] = "dumps";

  int scan_type = MEMDBG_VALUE_U32;
  char scan_value[128] = "0";
  char scan_start[32] = "0x0";
  char scan_length[32] = "0x1000";
  char scan_end[32] = "0x0";
  int scan_alignment = 4;
  int scan_max_results = 4096;
  bool scan_readable_only = true;
  ScanResult scan_result;
  std::vector<ScanSnapshotEntry> scan_snapshot;
  uint32_t scan_snapshot_value_len = 0;
  int scan_snapshot_type = MEMDBG_VALUE_U32;
  char scan_session_status[256] = "No scan session";
  bool scan_is_unknown_session = false;

  char map_filter[96] = "";
  bool map_filter_readable = true;
  bool map_filter_writable = false;
  bool map_filter_executable = false;
  bool map_filter_hide_system = true;
  int map_filter_min_kb = 0;

  std::vector<CheatEntry> cheats;
  char cheat_description[96] = "New cheat";
  char cheat_address[32] = "0x0";
  char cheat_value[256] = "0";
  int cheat_type = MEMDBG_VALUE_U32;
  bool cheat_lock = false;
  float cheat_lock_interval = 0.50f;
  double next_cheat_lock_time = 0.0;
  char trainer_file_path[256] = "trainers/session.cht";
  char batchcode_text[4096] = "";

  /* ---- Telemetry ---- */
  Client::TelemetrySnapshot telemetry_snap;
  double next_telemetry_poll = 0.0;
  bool telemetry_available = false;

  /* ---- AOB Scanner ---- */
  char aob_pattern[512] = "";
  ScanResult aob_result;
  bool aob_process_wide = false;  /* Scan across all process maps */

  /* ---- Pointer Scanner ---- */
  char pointer_target_address[32] = "0x0";
  int pointer_max_depth = 3;
  int pointer_max_results = 256;
  int pointer_alignment = 4;
  ScanResult pointer_result;

  /* ---- Async connect ---- */
  bool connect_pending = false;

  /* ---- Async scan (shared by Scanner, AOB Scanner, Pointer Scanner) ---- */
  bool scan_async_pending = false;
  std::future<bool> scan_async_future;
  std::string scan_async_label;
  double scan_async_start_time = 0.0;
  Screen scan_async_owner = Screen::Home;  /* prevents cross-screen result contamination */
  /* Temp storage populated by async worker, consumed by poll on UI thread */
  ScanResult scan_async_temp_result;
  std::vector<ScanSnapshotEntry> scan_async_temp_snapshot;
  uint32_t scan_async_temp_snapshot_value_len = 0U;
  int scan_async_temp_snapshot_type = MEMDBG_VALUE_U32;
  bool scan_async_temp_is_unknown = false;
  char scan_async_temp_session_status[256] = {};
  std::string scan_async_error;

  /* ---- Notifications ---- */
  static constexpr size_t kMaxNotifications = 8;
  std::deque<Notification> notifications;
};

/* ---- utility functions ---- */

inline std::string hex_u64(uint64_t value, int width = 0) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::uppercase;
  if (width > 0) oss << std::setw(width) << std::setfill('0');
  oss << value;
  return oss.str();
}

inline bool parse_u64(const char *text, uint64_t &out) {
  if (!text) return false;
  char *end = nullptr; errno = 0;
  unsigned long long value = std::strtoull(text, &end, 0);
  if (errno != 0 || end == text) return false;
  while (*end != '\0') { if (!std::isspace(static_cast<unsigned char>(*end))) return false; ++end; }
  out = static_cast<uint64_t>(value);
  return true;
}

inline std::string trim_copy(std::string value) {
  auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](char c) { return !is_space(static_cast<unsigned char>(c)); }));
  value.erase(std::find_if(value.rbegin(), value.rend(), [&](char c) { return !is_space(static_cast<unsigned char>(c)); }).base(), value.end());
  return value;
}

inline bool is_hex_digit_string(const std::string &value) {
  return std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

inline bool parse_hex_bytes(const char *text, std::vector<uint8_t> &out) {
  out.clear();
  std::string value = trim_copy(text ? text : "");
  if (value.empty()) return false;
  bool has_separator = value.find_first_of(" ,;\t\n\r") != std::string::npos;
  if (!has_separator) {
    if (value.rfind("0x",0)==0||value.rfind("0X",0)==0) value = value.substr(2);
    if (value.size()%2U!=0U||!is_hex_digit_string(value)) return false;
    for (size_t i=0; i<value.size(); i+=2U)
      out.push_back(static_cast<uint8_t>(std::strtoul(value.substr(i,2).c_str(),nullptr,16)));
    return !out.empty();
  }
  std::istringstream iss(value);
  std::string token;
  while (iss >> token) {
    while (!token.empty()&&(token.back()==','||token.back()==';')) token.pop_back();
    if (token.rfind("0x",0)==0||token.rfind("0X",0)==0) token = token.substr(2);
    if (token.empty()||token.size()>2U||!is_hex_digit_string(token)) return false;
    out.push_back(static_cast<uint8_t>(std::strtoul(token.c_str(),nullptr,16)));
  }
  return !out.empty();
}

template <typename T> inline void append_value(std::vector<uint8_t> &out, T value) {
  const auto *p = reinterpret_cast<const uint8_t*>(&value);
  out.insert(out.end(), p, p + sizeof(T));
}

inline bool build_scan_value(int type, const char *text, std::array<uint8_t, 16> &value, uint32_t &value_len) {
  std::vector<uint8_t> bytes;
  value.fill(0);
  try {
    switch (type) {
    case MEMDBG_VALUE_BYTES: if (!parse_hex_bytes(text, bytes) || bytes.size() > value.size()) return false; break;
    case MEMDBG_VALUE_U8:  append_value<uint8_t>(bytes, static_cast<uint8_t>(std::stoull(text,nullptr,0))); break;
    case MEMDBG_VALUE_U16: append_value<uint16_t>(bytes, static_cast<uint16_t>(std::stoull(text,nullptr,0))); break;
    case MEMDBG_VALUE_U32: append_value<uint32_t>(bytes, static_cast<uint32_t>(std::stoull(text,nullptr,0))); break;
    case MEMDBG_VALUE_U64: case MEMDBG_VALUE_POINTER: append_value<uint64_t>(bytes, static_cast<uint64_t>(std::stoull(text,nullptr,0))); break;
    case MEMDBG_VALUE_F32: append_value<float>(bytes, std::stof(text)); break;
    case MEMDBG_VALUE_F64: append_value<double>(bytes, std::stod(text)); break;
    default: return false;
    }
  } catch (...) { return false; }
  if (bytes.empty()||bytes.size()>value.size()) return false;
  std::copy(bytes.begin(), bytes.end(), value.begin());
  value_len = static_cast<uint32_t>(bytes.size());
  return true;
}

inline bool build_value_bytes(int type, const char *text, std::vector<uint8_t> &out) {
  out.clear();
  if (type == MEMDBG_VALUE_BYTES) return parse_hex_bytes(text, out);
  std::array<uint8_t,16> value{};
  uint32_t value_len=0;
  if (!build_scan_value(type, text, value, value_len)) return false;
  out.assign(value.begin(), value.begin()+value_len);
  return true;
}

inline const char *value_type_name(int type) {
  switch (type) {
  case MEMDBG_VALUE_BYTES: return "Bytes"; case MEMDBG_VALUE_U8: return "u8";
  case MEMDBG_VALUE_U16: return "u16"; case MEMDBG_VALUE_U32: return "u32";
  case MEMDBG_VALUE_U64: return "u64"; case MEMDBG_VALUE_F32: return "float";
  case MEMDBG_VALUE_F64: return "double"; case MEMDBG_VALUE_POINTER: return "pointer";
  default: return "unknown";
  }
}

inline std::string prot_text(uint32_t prot) { std::string t; t+=(prot&1U)?'r':'-'; t+=(prot&2U)?'w':'-'; t+=(prot&4U)?'x':'-'; return t; }

inline std::string lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

inline bool map_is_system_like(const MapEntry &map) {
  const std::string name = lower_copy(map.name);
  static const char *patterns[] = {"libsce","libkernel","libc.prx","scefios","scenp","scevoice","scevdec","system","kernel"};
  for (const char *p : patterns) if (name.find(p)!=std::string::npos) return true;
  return false;
}

inline std::string bytes_per_second(uint64_t bytes, uint64_t elapsed_ns) {
  if (elapsed_ns==0U) return "n/a";
  double s=static_cast<double>(elapsed_ns)/1000000000.0;
  double m=static_cast<double>(bytes)/(1024.0*1024.0);
  std::ostringstream oss; oss<<std::fixed<<std::setprecision(2)<<(m/s)<<" MiB/s";
  return oss.str();
}

inline std::string selected_process_name(const AppState &state) {
  for (const auto &p : state.processes) if (p.pid==state.selected_pid) return p.name;
  return "No process selected";
}

inline const char *screen_title(Screen s) {
  switch (s) {
  case Screen::Home: return "Command Center"; case Screen::Consoles: return "Consoles";
  case Screen::Processes: return "Processes"; case Screen::Memory: return "Memory";
  case Screen::Scanner: return "Scanner";
  case Screen::PointerScanner: return "Pointer Scanner";
  case Screen::AOBScanner: return "AOB Scanner";
  case Screen::Trainer: return "Trainer";
  case Screen::Logs: return "Logs"; case Screen::Settings: return "Settings";
  case Screen::Telemetry: return "Telemetry";
  case Screen::Credits: return "Credits";
  } return "MemDBG";
}

inline const char *screen_subtitle(Screen s) {
  switch (s) {
  case Screen::Home: return "Connect a console to begin";
  case Screen::Consoles: return "Open a direct payload session";
  case Screen::Processes: return "Select a target process and inspect maps";
  case Screen::Memory: return "Read and patch memory on the selected process";
  case Screen::Scanner: return "Run exact value scans through the payload";
  case Screen::PointerScanner: return "Find pointer chains to a target address";
  case Screen::AOBScanner: return "Search memory with array-of-bytes patterns";
  case Screen::Trainer: return "Build and lock runtime cheats for the selected game";
  case Screen::Logs: return "Watch UDP telemetry and on-console file logging";
  case Screen::Settings: return "Configure frontend connection defaults";
  case Screen::Telemetry: return "Payload performance and runtime metrics";
  case Screen::Credits: return "Project information";
  } return "";
}

inline void push_notification(AppState &state, const std::string &message, double duration = 4.0) {
  Notification n;
  n.message = message;
  n.created_at = ImGui::GetTime();
  n.duration = duration;
  state.notifications.push_back(std::move(n));
  while (state.notifications.size() > AppState::kMaxNotifications)
    state.notifications.pop_front();
}

/* ---- shared state helpers ---- */
void set_status(AppState &state, const std::string &message);
void normalize_ports(AppState &state);
bool ensure_udp_listener(AppState &state, std::string &error);
void connect_console(AppState &state);
void disconnect_console(AppState &state);
bool load_frontend_settings(AppState &state, std::string *error = nullptr);
bool save_frontend_settings(const AppState &state, std::string *error = nullptr);

/* ---- screen drawing declarations ---- */
void draw_home(AppState &state, struct ImVec2 avail);
void draw_consoles(AppState &state, struct ImVec2 avail);
void draw_processes(AppState &state, struct ImVec2 avail);
void draw_memory(AppState &state, struct ImVec2 avail);
void draw_scanner(AppState &state, struct ImVec2 avail);
void draw_pointer_scanner(AppState &state, struct ImVec2 avail);
void draw_aob_scanner(AppState &state, struct ImVec2 avail);
void draw_trainer(AppState &state, struct ImVec2 avail);
void draw_logs(AppState &state, struct ImVec2 avail);
void draw_settings(AppState &state, struct ImVec2 avail);
void draw_credits(AppState &state, struct ImVec2 avail);
void draw_telemetry(AppState &state, struct ImVec2 avail);
void draw_screen(AppState &state, struct ImVec2 avail);

} // namespace memdbg::frontend

#endif

/*
 * memDBG - ImGui console frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_app.hpp"

#include "github_profile.hpp"
#include "memdbg_client.hpp"
#include "udp_log_listener.hpp"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <GLFW/glfw3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cfloat>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace {

using memdbg::frontend::Client;
using memdbg::frontend::HelloInfo;
using memdbg::frontend::MapEntry;
using memdbg::frontend::ProcessEntry;
using memdbg::frontend::ProcessInfo;
using memdbg::frontend::ScanResult;
using memdbg::frontend::UdpLogListener;
using memdbg::frontend::GitHubProfile;

enum class Screen {
  Home,
  Consoles,
  Processes,
  Memory,
  Scanner,
  Trainer,
  Logs,
  Settings,
  Credits,
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

enum class RefineMode {
  Changed,
  Unchanged,
  Increased,
  Decreased,
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
};

namespace ui {

struct Palette {
  ImVec4 bg0 = ImVec4(7.0f / 255.0f, 10.0f / 255.0f, 14.0f / 255.0f, 1.0f);
  ImVec4 bg1 = ImVec4(13.0f / 255.0f, 18.0f / 255.0f, 24.0f / 255.0f, 1.0f);
  ImVec4 bg2 = ImVec4(22.0f / 255.0f, 29.0f / 255.0f, 36.0f / 255.0f, 1.0f);
  ImVec4 bg3 = ImVec4(32.0f / 255.0f, 42.0f / 255.0f, 52.0f / 255.0f, 1.0f);
  ImVec4 panel = ImVec4(12.0f / 255.0f, 16.0f / 255.0f, 22.0f / 255.0f, 0.93f);
  ImVec4 panel2 = ImVec4(18.0f / 255.0f, 24.0f / 255.0f, 31.0f / 255.0f, 0.96f);
  ImVec4 border = ImVec4(45.0f / 255.0f, 57.0f / 255.0f, 68.0f / 255.0f, 0.78f);
  ImVec4 border_hot = ImVec4(45.0f / 255.0f, 154.0f / 255.0f, 170.0f / 255.0f, 0.82f);
  ImVec4 text = ImVec4(238.0f / 255.0f, 244.0f / 255.0f, 246.0f / 255.0f, 1.0f);
  ImVec4 muted = ImVec4(158.0f / 255.0f, 174.0f / 255.0f, 184.0f / 255.0f, 1.0f);
  ImVec4 dim = ImVec4(91.0f / 255.0f, 108.0f / 255.0f, 121.0f / 255.0f, 1.0f);
  ImVec4 primary = ImVec4(28.0f / 255.0f, 184.0f / 255.0f, 196.0f / 255.0f, 1.0f);
  ImVec4 primary2 = ImVec4(118.0f / 255.0f, 232.0f / 255.0f, 224.0f / 255.0f, 1.0f);
  ImVec4 link = ImVec4(95.0f / 255.0f, 172.0f / 255.0f, 255.0f / 255.0f, 1.0f);
  ImVec4 success = ImVec4(68.0f / 255.0f, 207.0f / 255.0f, 127.0f / 255.0f, 1.0f);
  ImVec4 warning = ImVec4(244.0f / 255.0f, 171.0f / 255.0f, 75.0f / 255.0f, 1.0f);
  ImVec4 danger = ImVec4(239.0f / 255.0f, 82.0f / 255.0f, 97.0f / 255.0f, 1.0f);
};

const Palette &colors() {
  static Palette palette;
  return palette;
}

ImU32 color_u32(const ImVec4 &color) {
  return ImGui::ColorConvertFloat4ToU32(color);
}

void apply_theme() {
  const auto &p = colors();
  ImGui::StyleColorsDark();
  ImGuiStyle &style = ImGui::GetStyle();
  ImVec4 *c = style.Colors;

  c[ImGuiCol_Text] = p.text;
  c[ImGuiCol_TextDisabled] = p.dim;
  c[ImGuiCol_WindowBg] = p.bg0;
  c[ImGuiCol_ChildBg] = p.panel;
  c[ImGuiCol_PopupBg] = ImVec4(9.0f / 255.0f, 13.0f / 255.0f, 18.0f / 255.0f, 0.98f);
  c[ImGuiCol_Border] = p.border;
  c[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
  c[ImGuiCol_FrameBg] = p.bg2;
  c[ImGuiCol_FrameBgHovered] = ImVec4(29.0f / 255.0f, 42.0f / 255.0f, 52.0f / 255.0f, 1.0f);
  c[ImGuiCol_FrameBgActive] = ImVec4(36.0f / 255.0f, 55.0f / 255.0f, 66.0f / 255.0f, 1.0f);
  c[ImGuiCol_ScrollbarBg] = ImVec4(7.0f / 255.0f, 10.0f / 255.0f, 14.0f / 255.0f, 0.65f);
  c[ImGuiCol_ScrollbarGrab] = ImVec4(44.0f / 255.0f, 58.0f / 255.0f, 69.0f / 255.0f, 1.0f);
  c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(58.0f / 255.0f, 78.0f / 255.0f, 91.0f / 255.0f, 1.0f);
  c[ImGuiCol_ScrollbarGrabActive] = p.primary;
  c[ImGuiCol_CheckMark] = p.primary2;
  c[ImGuiCol_SliderGrab] = p.primary;
  c[ImGuiCol_SliderGrabActive] = p.primary2;
  c[ImGuiCol_Button] = ImVec4(26.0f / 255.0f, 36.0f / 255.0f, 44.0f / 255.0f, 1.0f);
  c[ImGuiCol_ButtonHovered] = ImVec4(36.0f / 255.0f, 63.0f / 255.0f, 74.0f / 255.0f, 1.0f);
  c[ImGuiCol_ButtonActive] = ImVec4(22.0f / 255.0f, 111.0f / 255.0f, 124.0f / 255.0f, 1.0f);
  c[ImGuiCol_Header] = ImVec4(25.0f / 255.0f, 36.0f / 255.0f, 44.0f / 255.0f, 1.0f);
  c[ImGuiCol_HeaderHovered] = ImVec4(36.0f / 255.0f, 65.0f / 255.0f, 76.0f / 255.0f, 1.0f);
  c[ImGuiCol_HeaderActive] = ImVec4(24.0f / 255.0f, 104.0f / 255.0f, 118.0f / 255.0f, 1.0f);
  c[ImGuiCol_Separator] = p.border;
  c[ImGuiCol_SeparatorHovered] = p.primary;
  c[ImGuiCol_SeparatorActive] = p.primary2;
  c[ImGuiCol_ResizeGrip] = ImVec4(45.0f / 255.0f, 91.0f / 255.0f, 101.0f / 255.0f, 0.47f);
  c[ImGuiCol_ResizeGripHovered] = ImVec4(28.0f / 255.0f, 184.0f / 255.0f, 196.0f / 255.0f, 0.70f);
  c[ImGuiCol_ResizeGripActive] = p.primary;
  c[ImGuiCol_Tab] = p.bg1;
  c[ImGuiCol_TabHovered] = ImVec4(36.0f / 255.0f, 63.0f / 255.0f, 74.0f / 255.0f, 1.0f);
  c[ImGuiCol_TabActive] = ImVec4(26.0f / 255.0f, 47.0f / 255.0f, 57.0f / 255.0f, 1.0f);
  c[ImGuiCol_TableHeaderBg] = ImVec4(24.0f / 255.0f, 34.0f / 255.0f, 42.0f / 255.0f, 1.0f);
  c[ImGuiCol_TableBorderStrong] = p.border_hot;
  c[ImGuiCol_TableBorderLight] = p.border;
  c[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
  c[ImGuiCol_TableRowBgAlt] = ImVec4(1, 1, 1, 0.025f);
  c[ImGuiCol_TextSelectedBg] = ImVec4(28.0f / 255.0f, 184.0f / 255.0f, 196.0f / 255.0f, 0.30f);

  style.WindowPadding = ImVec2(0, 0);
  style.FramePadding = ImVec2(12, 8);
  style.CellPadding = ImVec2(10, 8);
  style.ItemSpacing = ImVec2(10, 9);
  style.ItemInnerSpacing = ImVec2(8, 7);
  style.ScrollbarSize = 12.0f;
  style.WindowBorderSize = 0.0f;
  style.ChildBorderSize = 1.0f;
  style.PopupBorderSize = 1.0f;
  style.FrameBorderSize = 1.0f;
  style.WindowRounding = 0.0f;
  style.ChildRounding = 10.0f;
  style.FrameRounding = 8.0f;
  style.PopupRounding = 10.0f;
  style.ScrollbarRounding = 10.0f;
  style.GrabRounding = 10.0f;
  style.TabRounding = 8.0f;
}

void draw_background(ImDrawList *draw_list, ImVec2 pos, ImVec2 size) {
  const auto &p = colors();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  draw_list->AddRectFilled(pos, max, color_u32(p.bg0));
  draw_list->AddRectFilledMultiColor(
      pos, max,
      IM_COL32(10, 28, 34, 245),
      IM_COL32(7, 10, 14, 255),
      IM_COL32(7, 10, 14, 255),
      IM_COL32(7, 10, 14, 255));

  const float grid = 52.0f;
  const ImU32 grid_color = IM_COL32(28, 184, 196, 10);
  for (float x = pos.x; x < max.x; x += grid) {
    draw_list->AddLine(ImVec2(x, pos.y), ImVec2(x, max.y), grid_color);
  }
  for (float y = pos.y; y < max.y; y += grid) {
    draw_list->AddLine(ImVec2(pos.x, y), ImVec2(max.x, y), grid_color);
  }
}

void text_muted(const char *text) {
  ImGui::TextColored(colors().muted, "%s", text);
}

void text_dim(const char *text) {
  ImGui::TextColored(colors().dim, "%s", text);
}

void section_label(const char *title) {
  ImGui::TextColored(colors().muted, "%s", title);
  ImGui::Separator();
  ImGui::Spacing();
}

void begin_panel(const char *id, const char *title, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, colors().panel2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 18));
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
  ImGui::BeginChild(id, size, true);
  section_label(title);
}

void end_panel() {
  ImGui::EndChild();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

void status_dot(ImVec4 color) {
  ImDrawList *draw_list = ImGui::GetWindowDrawList();
  ImVec2 cursor = ImGui::GetCursorScreenPos();
  draw_list->AddCircleFilled(ImVec2(cursor.x + 6.0f, cursor.y + 8.0f), 5.0f,
                             color_u32(color));
  ImGui::Dummy(ImVec2(16.0f, 16.0f));
}

bool styled_button(const char *label, ImVec2 size, ImVec4 base, ImVec4 hover,
                   ImVec4 active) {
  ImGui::PushStyleColor(ImGuiCol_Button, base);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hover);
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, active);
  bool pressed = ImGui::Button(label, size);
  ImGui::PopStyleColor(3);
  return pressed;
}

bool primary_button(const char *label, ImVec2 size) {
  const auto &p = colors();
  return styled_button(label, size, p.primary, p.primary2,
                       ImVec4(16.0f / 255.0f, 128.0f / 255.0f, 142.0f / 255.0f,
                              1.0f));
}

bool soft_button(const char *label, ImVec2 size) {
  return styled_button(label, size,
                       ImVec4(26.0f / 255.0f, 36.0f / 255.0f, 44.0f / 255.0f,
                              1.0f),
                       ImVec4(38.0f / 255.0f, 62.0f / 255.0f, 72.0f / 255.0f,
                              1.0f),
                       ImVec4(28.0f / 255.0f, 98.0f / 255.0f, 110.0f / 255.0f,
                              1.0f));
}

bool danger_button(const char *label, ImVec2 size) {
  const auto &p = colors();
  return styled_button(label, size,
                       ImVec4(78.0f / 255.0f, 28.0f / 255.0f, 40.0f / 255.0f,
                              1.0f),
                       p.danger,
                       ImVec4(140.0f / 255.0f, 42.0f / 255.0f, 55.0f / 255.0f,
                              1.0f));
}

ImVec2 full_button(float height) {
  return ImVec2(ImGui::GetContentRegionAvail().x, height);
}

} // namespace ui

void set_status(AppState &state, const std::string &message) {
  std::snprintf(state.status, sizeof(state.status), "%s", message.c_str());
}

void normalize_ports(AppState &state) {
  state.debug_port = std::clamp(state.debug_port, 1, 65535);
  state.udp_port = std::clamp(state.udp_port, 1, 65535);
}

std::string hex_u64(uint64_t value, int width = 0) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::uppercase;
  if (width > 0) {
    oss << std::setw(width) << std::setfill('0');
  }
  oss << value;
  return oss.str();
}

bool parse_u64(const char *text, uint64_t &out) {
  if (text == nullptr) {
    return false;
  }
  char *end = nullptr;
  errno = 0;
  unsigned long long value = std::strtoull(text, &end, 0);
  if (errno != 0 || end == text) {
    return false;
  }
  while (*end != '\0') {
    if (!std::isspace(static_cast<unsigned char>(*end))) {
      return false;
    }
    ++end;
  }
  out = static_cast<uint64_t>(value);
  return true;
}

std::string trim_copy(std::string value) {
  auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
  value.erase(value.begin(),
              std::find_if(value.begin(), value.end(), [&](char c) {
                return !is_space(static_cast<unsigned char>(c));
              }));
  value.erase(std::find_if(value.rbegin(), value.rend(), [&](char c) {
                return !is_space(static_cast<unsigned char>(c));
              }).base(),
              value.end());
  return value;
}

bool is_hex_digit_string(const std::string &value) {
  return std::all_of(value.begin(), value.end(), [](unsigned char c) {
    return std::isxdigit(c) != 0;
  });
}

bool parse_hex_bytes(const char *text, std::vector<uint8_t> &out) {
  out.clear();
  std::string value = trim_copy(text != nullptr ? text : "");
  if (value.empty()) {
    return false;
  }

  bool has_separator =
      value.find_first_of(" ,;\t\n\r") != std::string::npos;
  if (!has_separator) {
    if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) {
      value = value.substr(2);
    }
    if (value.size() % 2U != 0U || !is_hex_digit_string(value)) {
      return false;
    }
    for (size_t i = 0; i < value.size(); i += 2U) {
      out.push_back(static_cast<uint8_t>(
          std::strtoul(value.substr(i, 2).c_str(), nullptr, 16)));
    }
    return !out.empty();
  }

  std::istringstream iss(value);
  std::string token;
  while (iss >> token) {
    while (!token.empty() && (token.back() == ',' || token.back() == ';')) {
      token.pop_back();
    }
    if (token.rfind("0x", 0) == 0 || token.rfind("0X", 0) == 0) {
      token = token.substr(2);
    }
    if (token.empty() || token.size() > 2U || !is_hex_digit_string(token)) {
      return false;
    }
    out.push_back(static_cast<uint8_t>(std::strtoul(token.c_str(), nullptr, 16)));
  }
  return !out.empty();
}

template <typename T> void append_value(std::vector<uint8_t> &out, T value) {
  const auto *p = reinterpret_cast<const uint8_t *>(&value);
  out.insert(out.end(), p, p + sizeof(T));
}

bool build_scan_value(int type, const char *text, std::array<uint8_t, 16> &value,
                      uint32_t &value_len) {
  std::vector<uint8_t> bytes;
  value.fill(0);

  try {
    switch (type) {
    case MEMDBG_VALUE_BYTES:
      if (!parse_hex_bytes(text, bytes) || bytes.size() > value.size()) {
        return false;
      }
      break;
    case MEMDBG_VALUE_U8:
      append_value<uint8_t>(bytes,
                            static_cast<uint8_t>(std::stoull(text, nullptr, 0)));
      break;
    case MEMDBG_VALUE_U16:
      append_value<uint16_t>(
          bytes, static_cast<uint16_t>(std::stoull(text, nullptr, 0)));
      break;
    case MEMDBG_VALUE_U32:
      append_value<uint32_t>(
          bytes, static_cast<uint32_t>(std::stoull(text, nullptr, 0)));
      break;
    case MEMDBG_VALUE_U64:
    case MEMDBG_VALUE_POINTER:
      append_value<uint64_t>(
          bytes, static_cast<uint64_t>(std::stoull(text, nullptr, 0)));
      break;
    case MEMDBG_VALUE_F32:
      append_value<float>(bytes, std::stof(text));
      break;
    case MEMDBG_VALUE_F64:
      append_value<double>(bytes, std::stod(text));
      break;
    default:
      return false;
    }
  } catch (...) {
    return false;
  }

  if (bytes.empty() || bytes.size() > value.size()) {
    return false;
  }
  std::copy(bytes.begin(), bytes.end(), value.begin());
  value_len = static_cast<uint32_t>(bytes.size());
  return true;
}

const char *value_type_name(int type) {
  switch (type) {
  case MEMDBG_VALUE_BYTES:
    return "Bytes";
  case MEMDBG_VALUE_U8:
    return "u8";
  case MEMDBG_VALUE_U16:
    return "u16";
  case MEMDBG_VALUE_U32:
    return "u32";
  case MEMDBG_VALUE_U64:
    return "u64";
  case MEMDBG_VALUE_F32:
    return "float";
  case MEMDBG_VALUE_F64:
    return "double";
  case MEMDBG_VALUE_POINTER:
    return "pointer";
  default:
    return "unknown";
  }
}

std::string prot_text(uint32_t prot) {
  std::string text;
  text += (prot & 1U) ? 'r' : '-';
  text += (prot & 2U) ? 'w' : '-';
  text += (prot & 4U) ? 'x' : '-';
  return text;
}

std::string lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool map_is_system_like(const MapEntry &map) {
  const std::string name = lower_copy(map.name);
  static const char *patterns[] = {
      "libsce", "libkernel", "libc.prx", "scefios", "scenp",
      "scevoice", "scevdec", "system",  "kernel",
  };
  for (const char *pattern : patterns) {
    if (name.find(pattern) != std::string::npos) {
      return true;
    }
  }
  return false;
}

bool map_passes_filters(const AppState &state, const MapEntry &map) {
  if (map.end <= map.start) {
    return false;
  }
  if (state.map_filter_readable && (map.protection & 1U) == 0U) {
    return false;
  }
  if (state.map_filter_writable && (map.protection & 2U) == 0U) {
    return false;
  }
  if (state.map_filter_executable && (map.protection & 4U) == 0U) {
    return false;
  }
  if (state.map_filter_hide_system && map_is_system_like(map)) {
    return false;
  }
  if (state.map_filter_min_kb > 0 &&
      ((map.end - map.start) / 1024U) <
          static_cast<uint64_t>(state.map_filter_min_kb)) {
    return false;
  }
  std::string filter = lower_copy(trim_copy(state.map_filter));
  if (!filter.empty() && lower_copy(map.name).find(filter) == std::string::npos) {
    return false;
  }
  return true;
}

size_t filtered_map_count(const AppState &state) {
  size_t count = 0;
  for (const auto &map : state.maps) {
    if (map_passes_filters(state, map)) {
      count++;
    }
  }
  return count;
}

void set_scan_window_from_filtered_maps(AppState &state) {
  uint64_t start = UINT64_MAX;
  uint64_t end = 0;
  for (const auto &map : state.maps) {
    if (!map_passes_filters(state, map)) {
      continue;
    }
    start = std::min(start, map.start);
    end = std::max(end, map.end);
  }
  if (start == UINT64_MAX || end <= start) {
    set_status(state, "No filtered maps available");
    return;
  }
  std::snprintf(state.scan_start, sizeof(state.scan_start), "%s",
                hex_u64(start).c_str());
  std::snprintf(state.scan_end, sizeof(state.scan_end), "%s",
                hex_u64(end).c_str());
  set_status(state, "Process scan window set from filtered maps");
}

void dump_selected_map(AppState &state) {
  if (!state.client.connected()) {
    set_status(state, "Connect a console first");
    return;
  }
  if (state.selected_pid <= 0 || state.selected_map_row < 0 ||
      state.selected_map_row >= static_cast<int>(state.maps.size())) {
    set_status(state, "Select a process map first");
    return;
  }

  const MapEntry &map = state.maps[state.selected_map_row];
  if (map.end <= map.start) {
    set_status(state, "Selected map is empty");
    return;
  }

  std::filesystem::path dump_dir = "dumps";
  std::error_code ec;
  std::filesystem::create_directories(dump_dir, ec);
  if (ec) {
    set_status(state, "Failed to create dumps directory");
    return;
  }

  std::filesystem::path out_path =
      dump_dir / ("pid_" + std::to_string(state.selected_pid) + "_" +
                  hex_u64(map.start).substr(2) + ".bin");
  std::ofstream out(out_path, std::ios::binary);
  if (!out) {
    set_status(state, "Failed to open dump file");
    return;
  }

  uint64_t address = map.start;
  uint64_t remaining = map.end - map.start;
  uint64_t written_total = 0;
  while (remaining != 0U) {
    uint32_t chunk = remaining > MEMDBG_PROTOCOL_MAX_READ
                         ? MEMDBG_PROTOCOL_MAX_READ
                         : static_cast<uint32_t>(remaining);
    std::vector<uint8_t> bytes;
    if (!state.client.memory_read(state.selected_pid, address, chunk, bytes)) {
      set_status(state, "Dump failed: " + state.client.last_error());
      return;
    }
    if (bytes.empty()) {
      break;
    }
    out.write(reinterpret_cast<const char *>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    if (!out) {
      set_status(state, "Dump file write failed");
      return;
    }
    address += bytes.size();
    remaining -= bytes.size();
    written_total += bytes.size();
  }

  set_status(state, "Dumped " + std::to_string(written_total) + " bytes to " +
                        out_path.string());
}

std::string bytes_per_second(uint64_t bytes, uint64_t elapsed_ns) {
  if (elapsed_ns == 0U) {
    return "n/a";
  }
  double seconds = static_cast<double>(elapsed_ns) / 1000000000.0;
  double mib = static_cast<double>(bytes) / (1024.0 * 1024.0);
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(2) << (mib / seconds) << " MiB/s";
  return oss.str();
}

std::string selected_process_name(const AppState &state) {
  for (const auto &process : state.processes) {
    if (process.pid == state.selected_pid) {
      return process.name;
    }
  }
  return "No process selected";
}

const char *screen_title(Screen screen) {
  switch (screen) {
  case Screen::Home:
    return "Command Center";
  case Screen::Consoles:
    return "Consoles";
  case Screen::Processes:
    return "Processes";
  case Screen::Memory:
    return "Memory";
  case Screen::Scanner:
    return "Scanner";
  case Screen::Trainer:
    return "Trainer";
  case Screen::Logs:
    return "Logs";
  case Screen::Settings:
    return "Settings";
  case Screen::Credits:
    return "Credits";
  }
  return "memDBG";
}

const char *screen_subtitle(Screen screen) {
  switch (screen) {
  case Screen::Home:
    return "Connect a console to begin";
  case Screen::Consoles:
    return "Open a direct payload session";
  case Screen::Processes:
    return "Select a target process and inspect maps";
  case Screen::Memory:
    return "Read and patch memory on the selected process";
  case Screen::Scanner:
    return "Run exact value scans through the payload";
  case Screen::Trainer:
    return "Build and lock runtime cheats for the selected game";
  case Screen::Logs:
    return "Watch UDP telemetry and on-console file logging";
  case Screen::Settings:
    return "Configure frontend connection defaults";
  case Screen::Credits:
    return "Project information";
  }
  return "";
}

bool ensure_udp_listener(AppState &state, std::string &error) {
  normalize_ports(state);
  if (state.udp_listener.running()) {
    return true;
  }
  if (state.udp_listener.start(static_cast<uint16_t>(state.udp_port))) {
    return true;
  }
  error = state.udp_listener.last_error();
  if (error.empty()) {
    error = "UDP listener failed";
  }
  return false;
}

void clear_scan_session(AppState &state, const char *reason);

void refresh_processes(AppState &state) {
  if (!state.client.connected()) {
    set_status(state, "Connect a console before refreshing processes");
    return;
  }
  if (!state.client.process_list(state.processes)) {
    set_status(state, state.client.last_error());
    return;
  }
  if (state.processes.empty()) {
    state.selected_pid = 0;
    state.selected_process_row = -1;
    state.has_process_info = false;
    state.maps.clear();
  }
  set_status(state, "Process list refreshed");
}

void refresh_maps(AppState &state) {
  if (!state.client.connected()) {
    set_status(state, "Connect a console before refreshing maps");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process first");
    return;
  }
  if (!state.client.process_maps(state.selected_pid, state.maps)) {
    set_status(state, state.client.last_error());
    return;
  }
  state.selected_map_row = -1;
  set_status(state, "Memory maps refreshed");
}

void connect_console(AppState &state) {
  normalize_ports(state);
  state.client.disconnect();
  state.has_hello = false;
  state.processes.clear();
  state.maps.clear();
  state.memory.clear();
  state.scan_result = ScanResult{};
  clear_scan_session(state, "No scan session");
  state.selected_pid = 0;
  state.selected_process_row = -1;
  state.selected_map_row = -1;
  state.has_process_info = false;

  if (!state.client.connect_to(state.host, static_cast<uint16_t>(state.debug_port))) {
    set_status(state, state.client.last_error());
    return;
  }
  if (!state.client.hello(state.hello)) {
    std::string error = state.client.last_error();
    state.client.disconnect();
    set_status(state, error.empty() ? "HELLO failed" : error);
    return;
  }

  state.has_hello = true;
  std::string udp_error;
  std::string message = "Connected to console ";
  message += state.host;
  message += ":";
  message += std::to_string(state.debug_port);
  if (!ensure_udp_listener(state, udp_error)) {
    message += " (UDP log listener: ";
    message += udp_error;
    message += ")";
  }
  set_status(state, message);
}

void disconnect_console(AppState &state) {
  state.client.disconnect();
  state.has_hello = false;
  state.processes.clear();
  state.maps.clear();
  state.memory.clear();
  state.scan_result = ScanResult{};
  clear_scan_session(state, "No scan session");
  state.selected_pid = 0;
  state.selected_process_row = -1;
  state.selected_map_row = -1;
  state.has_process_info = false;
  set_status(state, "Console disconnected");
}

void select_process(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.processes.size())) {
    return;
  }
  state.selected_process_row = row;
  state.selected_pid = state.processes[row].pid;
  state.maps.clear();
  state.selected_map_row = -1;
  state.memory.clear();
  state.scan_result = ScanResult{};
  clear_scan_session(state, "Process changed");
  state.has_process_info = false;
  if (state.client.connected() &&
      state.client.process_info(state.selected_pid, state.selected_process_info)) {
    state.has_process_info = true;
  }
  set_status(state, "Selected PID " + std::to_string(state.selected_pid));
}

void select_map(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.maps.size())) {
    return;
  }
  const auto &map = state.maps[row];
  state.selected_map_row = row;
  std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                hex_u64(map.start).c_str());
  std::snprintf(state.write_address, sizeof(state.write_address), "%s",
                hex_u64(map.start).c_str());
  std::snprintf(state.scan_start, sizeof(state.scan_start), "%s",
                hex_u64(map.start).c_str());
  std::snprintf(state.scan_length, sizeof(state.scan_length), "%s",
                hex_u64(map.end - map.start).c_str());
  set_status(state, "Selected map " + hex_u64(map.start) + " - " +
                        hex_u64(map.end));
}

void draw_empty_state(const char *title, const char *message) {
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", title);
  ImGui::TextWrapped("%s", message);
}

void draw_capabilities(const AppState &state) {
  if (!state.has_hello) {
    ui::text_dim("Payload details will appear after HELLO.");
    return;
  }

  ImGui::Text("Payload: %s %s", state.hello.name.c_str(),
              state.hello.version.c_str());
  ImGui::Text("Platform: %s",
              memdbg::frontend::platform_name(state.hello.platform_id).c_str());
  ImGui::Text("Debug port: %u", static_cast<unsigned>(state.hello.debug_port));
  ImGui::Text("UDP log port: %u",
              static_cast<unsigned>(state.hello.udp_log_port));
  ImGui::Spacing();
  ImGui::TextWrapped("Capabilities: %s",
                     memdbg::frontend::capability_text(state.hello.capabilities)
                         .c_str());
}

void draw_hex_view(const std::vector<uint8_t> &data, uint64_t base) {
  if (data.empty()) {
    draw_empty_state("No memory buffer",
                     "Read memory from the selected process to populate this view.");
    return;
  }

  if (ImGui::BeginTable("hex_view", 3,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                        ImVec2(0, 0))) {
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 130);
    ImGui::TableSetupColumn("Hex");
    ImGui::TableSetupColumn("ASCII", ImGuiTableColumnFlags_WidthFixed, 150);
    ImGui::TableHeadersRow();
    for (size_t row = 0; row < data.size(); row += 16U) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextUnformatted(hex_u64(base + row).c_str());
      ImGui::TableSetColumnIndex(1);
      std::ostringstream hex;
      for (size_t i = 0; i < 16U; ++i) {
        if (row + i < data.size()) {
          hex << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
              << static_cast<unsigned>(data[row + i]) << ' ';
        } else {
          hex << "   ";
        }
      }
      ImGui::TextUnformatted(hex.str().c_str());
      ImGui::TableSetColumnIndex(2);
      char ascii[17]{};
      for (size_t i = 0; i < 16U && row + i < data.size(); ++i) {
        unsigned char c = data[row + i];
        ascii[i] = std::isprint(c) != 0 ? static_cast<char>(c) : '.';
      }
      ImGui::TextUnformatted(ascii);
    }
    ImGui::EndTable();
  }
}

void read_memory(AppState &state) {
  if (!state.client.connected()) {
    set_status(state, "Connect a console first");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process first");
    return;
  }
  uint64_t address = 0;
  if (!parse_u64(state.read_address, address)) {
    set_status(state, "Invalid read address");
    return;
  }
  state.read_length = std::clamp(state.read_length, 1,
                                 static_cast<int>(MEMDBG_PROTOCOL_MAX_READ));
  if (!state.client.memory_read(state.selected_pid, address,
                                static_cast<uint32_t>(state.read_length),
                                state.memory)) {
    set_status(state, state.client.last_error());
    return;
  }
  set_status(state, "Read " + std::to_string(state.memory.size()) + " bytes");
}

void write_memory(AppState &state) {
  if (!state.client.connected()) {
    set_status(state, "Connect a console first");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process first");
    return;
  }
  uint64_t address = 0;
  std::vector<uint8_t> data;
  if (!parse_u64(state.write_address, address)) {
    set_status(state, "Invalid write address");
    return;
  }
  if (!parse_hex_bytes(state.write_bytes, data)) {
    set_status(state, "Invalid byte list");
    return;
  }

  uint32_t written = 0;
  if (!state.client.memory_write(state.selected_pid, address, data, written)) {
    set_status(state, state.client.last_error());
    return;
  }
  set_status(state, "Wrote " + std::to_string(written) + " bytes");
}

bool build_value_bytes(int type, const char *text, std::vector<uint8_t> &out) {
  out.clear();
  if (type == MEMDBG_VALUE_BYTES) {
    return parse_hex_bytes(text, out);
  }

  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!build_scan_value(type, text, value, value_len)) {
    return false;
  }
  out.assign(value.begin(), value.begin() + value_len);
  return true;
}

std::string bytes_to_hex(const std::vector<uint8_t> &bytes) {
  std::ostringstream out;
  out << std::hex << std::uppercase << std::setfill('0');
  for (uint8_t byte : bytes) {
    out << std::setw(2) << static_cast<unsigned>(byte);
  }
  return out.str();
}

const char *cht_type_name(int type) {
  switch (type) {
  case MEMDBG_VALUE_U8:
    return "byte";
  case MEMDBG_VALUE_U16:
    return "2 bytes";
  case MEMDBG_VALUE_U32:
    return "4 bytes";
  case MEMDBG_VALUE_U64:
    return "8 bytes";
  case MEMDBG_VALUE_F32:
    return "float";
  case MEMDBG_VALUE_F64:
    return "double";
  case MEMDBG_VALUE_POINTER:
    return "pointer";
  case MEMDBG_VALUE_BYTES:
  default:
    return "hex";
  }
}

int cht_type_from_string(std::string value) {
  value = lower_copy(trim_copy(std::move(value)));
  if (value == "byte" || value == "1 byte" || value == "u8") {
    return MEMDBG_VALUE_U8;
  }
  if (value == "2 bytes" || value == "u16") {
    return MEMDBG_VALUE_U16;
  }
  if (value == "4 bytes" || value == "u32" || value == "uint") {
    return MEMDBG_VALUE_U32;
  }
  if (value == "8 bytes" || value == "u64" || value == "ulong") {
    return MEMDBG_VALUE_U64;
  }
  if (value == "float") {
    return MEMDBG_VALUE_F32;
  }
  if (value == "double") {
    return MEMDBG_VALUE_F64;
  }
  if (value == "pointer") {
    return MEMDBG_VALUE_POINTER;
  }
  return MEMDBG_VALUE_BYTES;
}

bool parse_hex_or_int(const std::string &text, uint64_t &out) {
  if (parse_u64(text.c_str(), out)) {
    return true;
  }
  std::string value = trim_copy(text);
  if (!value.empty() && value[0] == '@') {
    value.erase(value.begin());
  }
  size_t underscore = value.find('_');
  if (underscore != std::string::npos) {
    value = value.substr(0, underscore);
  }
  if (value.empty() || !is_hex_digit_string(value)) {
    return false;
  }
  char *end = nullptr;
  errno = 0;
  unsigned long long parsed = std::strtoull(value.c_str(), &end, 16);
  if (errno != 0 || end == value.c_str() || *end != '\0') {
    return false;
  }
  out = static_cast<uint64_t>(parsed);
  return true;
}

std::vector<std::string> split_pipe(const std::string &line) {
  std::vector<std::string> tokens;
  size_t start = 0;
  while (start <= line.size()) {
    size_t pos = line.find('|', start);
    if (pos == std::string::npos) {
      tokens.push_back(line.substr(start));
      break;
    }
    tokens.push_back(line.substr(start, pos - start));
    start = pos + 1;
  }
  return tokens;
}

int map_index_for_address(const AppState &state, uint64_t address) {
  for (int i = 0; i < static_cast<int>(state.maps.size()); ++i) {
    const auto &map = state.maps[i];
    if (address >= map.start && address < map.end) {
      return i;
    }
  }
  return -1;
}

uint32_t current_scan_value_len(const AppState &state) {
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!build_scan_value(state.scan_type, state.scan_value, value, value_len)) {
    switch (state.scan_type) {
    case MEMDBG_VALUE_U8:
      return 1U;
    case MEMDBG_VALUE_U16:
      return 2U;
    case MEMDBG_VALUE_U32:
    case MEMDBG_VALUE_F32:
      return 4U;
    case MEMDBG_VALUE_U64:
    case MEMDBG_VALUE_F64:
    case MEMDBG_VALUE_POINTER:
      return 8U;
    default:
      return 1U;
    }
  }
  return value_len;
}

template <typename T> T read_scalar(const std::vector<uint8_t> &bytes) {
  T value{};
  if (bytes.size() >= sizeof(T)) {
    std::memcpy(&value, bytes.data(), sizeof(T));
  }
  return value;
}

bool bytes_to_number(int type, const std::vector<uint8_t> &bytes,
                     long double &out) {
  switch (type) {
  case MEMDBG_VALUE_U8:
    out = read_scalar<uint8_t>(bytes);
    return bytes.size() >= sizeof(uint8_t);
  case MEMDBG_VALUE_U16:
    out = read_scalar<uint16_t>(bytes);
    return bytes.size() >= sizeof(uint16_t);
  case MEMDBG_VALUE_U32:
    out = read_scalar<uint32_t>(bytes);
    return bytes.size() >= sizeof(uint32_t);
  case MEMDBG_VALUE_U64:
  case MEMDBG_VALUE_POINTER:
    out = static_cast<long double>(read_scalar<uint64_t>(bytes));
    return bytes.size() >= sizeof(uint64_t);
  case MEMDBG_VALUE_F32:
    out = read_scalar<float>(bytes);
    return bytes.size() >= sizeof(float);
  case MEMDBG_VALUE_F64:
    out = read_scalar<double>(bytes);
    return bytes.size() >= sizeof(double);
  default:
    return false;
  }
}

bool scan_refine_match(int type, RefineMode mode,
                       const std::vector<uint8_t> &old_bytes,
                       const std::vector<uint8_t> &new_bytes) {
  const bool same = old_bytes == new_bytes;
  switch (mode) {
  case RefineMode::Changed:
    return !same;
  case RefineMode::Unchanged:
    return same;
  case RefineMode::Increased:
  case RefineMode::Decreased: {
    long double old_value = 0.0;
    long double new_value = 0.0;
    if (!bytes_to_number(type, old_bytes, old_value) ||
        !bytes_to_number(type, new_bytes, new_value)) {
      return false;
    }
    return mode == RefineMode::Increased ? new_value > old_value
                                         : new_value < old_value;
  }
  }
  return false;
}

const char *refine_mode_name(RefineMode mode) {
  switch (mode) {
  case RefineMode::Changed:
    return "Changed";
  case RefineMode::Unchanged:
    return "Unchanged";
  case RefineMode::Increased:
    return "Increased";
  case RefineMode::Decreased:
    return "Decreased";
  }
  return "Refine";
}

void clear_scan_session(AppState &state, const char *reason) {
  state.scan_snapshot.clear();
  state.scan_snapshot_value_len = 0;
  state.scan_snapshot_type = state.scan_type;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s", reason != nullptr ? reason : "No scan session");
}

void capture_scan_snapshot(AppState &state) {
  state.scan_snapshot.clear();
  state.scan_snapshot_type = state.scan_type;
  state.scan_snapshot_value_len = current_scan_value_len(state);
  if (!state.client.connected() || state.selected_pid <= 0 ||
      state.scan_result.addresses.empty() || state.scan_snapshot_value_len == 0U) {
    std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                  "%s", "No scan values captured");
    return;
  }

  state.scan_snapshot.reserve(state.scan_result.addresses.size());
  uint32_t read_errors = 0;
  const auto start = std::chrono::steady_clock::now();
  for (uint64_t address : state.scan_result.addresses) {
    std::vector<uint8_t> bytes;
    if (!state.client.memory_read(state.selected_pid, address,
                                  state.scan_snapshot_value_len, bytes) ||
        bytes.size() != state.scan_snapshot_value_len) {
      read_errors++;
      continue;
    }
    ScanSnapshotEntry entry;
    entry.address = address;
    entry.bytes = std::move(bytes);
    state.scan_snapshot.push_back(std::move(entry));
  }
  const auto end = std::chrono::steady_clock::now();
  const uint64_t elapsed_ns =
      static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                end - start)
                                .count());

  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "Captured %zu values (%u read errors)", state.scan_snapshot.size(),
                read_errors);
  state.scan_result.read_calls +=
      static_cast<uint32_t>(state.scan_result.addresses.size());
  state.scan_result.read_errors += read_errors;
  state.scan_result.elapsed_ns += elapsed_ns;
}

void refine_scan(AppState &state, RefineMode mode) {
  if (!state.client.connected()) {
    set_status(state, "Connect a console first");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process first");
    return;
  }
  if (state.scan_snapshot.empty() || state.scan_snapshot_value_len == 0U) {
    set_status(state, "Run a scan before refining");
    return;
  }

  std::vector<ScanSnapshotEntry> next_snapshot;
  next_snapshot.reserve(state.scan_snapshot.size());
  std::vector<uint64_t> next_addresses;
  next_addresses.reserve(state.scan_snapshot.size());
  uint32_t read_errors = 0;
  uint64_t bytes_read = 0;
  const auto start = std::chrono::steady_clock::now();

  for (const auto &entry : state.scan_snapshot) {
    std::vector<uint8_t> current;
    if (!state.client.memory_read(state.selected_pid, entry.address,
                                  state.scan_snapshot_value_len, current) ||
        current.size() != state.scan_snapshot_value_len) {
      read_errors++;
      continue;
    }
    bytes_read += current.size();
    if (!scan_refine_match(state.scan_snapshot_type, mode, entry.bytes,
                           current)) {
      continue;
    }
    ScanSnapshotEntry next;
    next.address = entry.address;
    next.bytes = std::move(current);
    next_addresses.push_back(next.address);
    next_snapshot.push_back(std::move(next));
  }

  const auto end = std::chrono::steady_clock::now();
  const uint64_t elapsed_ns =
      static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                end - start)
                                .count());

  state.scan_snapshot = std::move(next_snapshot);
  state.scan_result.addresses = std::move(next_addresses);
  state.scan_result.count = static_cast<uint32_t>(state.scan_result.addresses.size());
  state.scan_result.truncated = false;
  state.scan_result.bytes_scanned = bytes_read;
  state.scan_result.elapsed_ns = elapsed_ns;
  state.scan_result.read_calls =
      static_cast<uint32_t>(state.scan_snapshot.size() + read_errors);
  state.scan_result.regions_scanned = 0;
  state.scan_result.read_errors = read_errors;

  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s refine kept %zu values", refine_mode_name(mode),
                state.scan_snapshot.size());
  set_status(state, state.scan_session_status);
}

bool capture_cheat_off_value(AppState &state, CheatEntry &cheat) {
  if (!state.client.connected()) {
    cheat.status = "No console session";
    return false;
  }
  int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0 || cheat.bytes.empty()) {
    cheat.status = "No target value";
    return false;
  }
  std::vector<uint8_t> current;
  if (!state.client.memory_read(pid, cheat.address,
                                static_cast<uint32_t>(cheat.bytes.size()),
                                current) ||
      current.size() != cheat.bytes.size()) {
    cheat.status = state.client.last_error().empty() ? "OFF capture failed"
                                                     : state.client.last_error();
    return false;
  }
  cheat.off_bytes = std::move(current);
  cheat.has_off_bytes = true;
  cheat.status = "OFF value captured";
  return true;
}

bool apply_cheat(AppState &state, CheatEntry &cheat) {
  if (!state.client.connected()) {
    cheat.status = "No console session";
    return false;
  }
  int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0) {
    cheat.status = "No target PID";
    return false;
  }
  if (cheat.bytes.empty()) {
    cheat.status = "Empty value";
    return false;
  }

  uint32_t written = 0;
  if (!state.client.memory_write(pid, cheat.address, cheat.bytes, written)) {
    cheat.status = state.client.last_error();
    return false;
  }
  cheat.active = true;
  cheat.status = "Wrote " + std::to_string(written) + " bytes";
  return true;
}

bool deactivate_cheat(AppState &state, CheatEntry &cheat) {
  if (!cheat.has_off_bytes || cheat.off_bytes.empty()) {
    cheat.status = "No OFF value captured";
    return false;
  }
  if (!state.client.connected()) {
    cheat.status = "No console session";
    return false;
  }
  int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0) {
    cheat.status = "No target PID";
    return false;
  }
  uint32_t written = 0;
  if (!state.client.memory_write(pid, cheat.address, cheat.off_bytes, written)) {
    cheat.status = state.client.last_error();
    return false;
  }
  cheat.active = false;
  cheat.status = "Restored " + std::to_string(written) + " bytes";
  return true;
}

void add_cheat_from_fields(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before adding a trainer entry");
    return;
  }

  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  if (!parse_u64(state.cheat_address, address)) {
    set_status(state, "Invalid cheat address");
    return;
  }
  if (!build_value_bytes(state.cheat_type, state.cheat_value, bytes)) {
    set_status(state, "Invalid cheat value");
    return;
  }

  CheatEntry cheat;
  cheat.description =
      state.cheat_description[0] != '\0' ? state.cheat_description : "Cheat";
  cheat.pid = state.selected_pid;
  cheat.address = address;
  cheat.value_type = state.cheat_type;
  cheat.value_text = state.cheat_value;
  cheat.bytes = std::move(bytes);
  cheat.locked = state.cheat_lock;
  if (state.client.connected()) {
    (void)capture_cheat_off_value(state, cheat);
  }
  state.cheats.push_back(std::move(cheat));
  set_status(state, "Trainer entry added");
}

std::string batch_value_after(const std::string &text, const char *key,
                              size_t start_pos) {
  size_t pos = text.find(key, start_pos);
  if (pos == std::string::npos) {
    return {};
  }
  pos += std::strlen(key);
  while (pos < text.size() &&
         std::isspace(static_cast<unsigned char>(text[pos])) != 0) {
    ++pos;
  }
  size_t end = pos;
  while (end < text.size() && text[end] != ';' && text[end] != '|' &&
         std::isspace(static_cast<unsigned char>(text[end])) == 0) {
    ++end;
  }
  return text.substr(pos, end - pos);
}

void import_batchcode(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before importing batchcode");
    return;
  }

  std::string text = state.batchcode_text;
  size_t pos = 0;
  int imported = 0;
  while ((pos = text.find("offset:", pos)) != std::string::npos) {
    std::string offset_text = batch_value_after(text, "offset:", pos);
    std::string value_text = batch_value_after(text, "value:", pos);
    std::string size_text = batch_value_after(text, "size:", pos);
    pos += 7;

    uint64_t address = 0;
    uint64_t size = 0;
    std::vector<uint8_t> bytes;
    if (!parse_u64(offset_text.c_str(), address) ||
        !parse_hex_bytes(value_text.c_str(), bytes)) {
      continue;
    }
    if (!size_text.empty() && parse_u64(size_text.c_str(), size) && size > 0) {
      if (bytes.size() > size) {
        bytes.resize(static_cast<size_t>(size));
      } else {
        bytes.resize(static_cast<size_t>(size), 0);
      }
    }

    CheatEntry cheat;
    cheat.description = "Batchcode " + std::to_string(imported + 1);
    cheat.pid = state.selected_pid;
    cheat.address = address;
    cheat.value_type = MEMDBG_VALUE_BYTES;
    cheat.value_text = value_text;
    cheat.bytes = std::move(bytes);
    state.cheats.push_back(std::move(cheat));
    imported++;
  }

  set_status(state, imported > 0 ? "Imported " + std::to_string(imported) +
                                      " batchcode entries"
                                  : "No batchcode entries imported");
}

std::string process_label_for_trainer(const AppState &state) {
  if (state.has_process_info && !state.selected_process_info.title_id.empty()) {
    return state.selected_process_info.title_id;
  }
  std::string name = selected_process_name(state);
  return name == "No process selected" ? "unknown" : name;
}

bool parse_cht_data_line(AppState &state, const std::vector<std::string> &tokens,
                         CheatEntry &cheat) {
  if (tokens.size() < 6 || tokens[0] != "data") {
    return false;
  }

  uint64_t address = 0;
  size_t type_idx = 3;
  if (!tokens[1].empty() && tokens[1][0] == '@') {
    if (!parse_hex_or_int(tokens[1], address)) {
      return false;
    }
    type_idx = 2;
  } else {
    uint64_t section = 0;
    uint64_t offset = 0;
    if (!parse_hex_or_int(tokens[1], section) ||
        !parse_hex_or_int(tokens[2], offset)) {
      return false;
    }
    if (section < state.maps.size()) {
      address = state.maps[static_cast<size_t>(section)].start + offset;
    } else if (tokens.size() > 7 && parse_hex_or_int(tokens.back(), address)) {
      type_idx = 3;
    } else {
      address = offset;
    }
  }

  if (tokens.size() <= type_idx + 2U) {
    return false;
  }
  int type = cht_type_from_string(tokens[type_idx]);
  std::vector<uint8_t> bytes;
  if (!build_value_bytes(type, tokens[type_idx + 1U].c_str(), bytes)) {
    return false;
  }

  cheat.description =
      tokens.size() > type_idx + 3U && !tokens[type_idx + 3U].empty()
          ? tokens[type_idx + 3U]
          : "Imported cheat";
  cheat.pid = state.selected_pid;
  cheat.address = address;
  cheat.value_type = type;
  cheat.value_text = tokens[type_idx + 1U];
  cheat.bytes = std::move(bytes);
  cheat.locked = tokens.size() > type_idx + 2U && tokens[type_idx + 2U] == "1";
  cheat.enabled = true;
  for (size_t i = type_idx + 4U; i < tokens.size(); ++i) {
    if (tokens[i].rfind("off:", 0) == 0 &&
        parse_hex_bytes(tokens[i].c_str() + 4, cheat.off_bytes)) {
      cheat.has_off_bytes = true;
    }
  }
  return true;
}

void load_trainer_file(AppState &state) {
  std::ifstream in(state.trainer_file_path);
  if (!in) {
    set_status(state, "Trainer file not found");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before loading trainer entries");
    return;
  }

  std::string line;
  int imported = 0;
  int skipped = 0;
  bool first = true;
  while (std::getline(in, line)) {
    line = trim_copy(line);
    if (line.empty()) {
      continue;
    }
    if (first) {
      first = false;
      if (line.find('|') != std::string::npos && line.rfind("data|", 0) != 0 &&
          line.rfind("@batchcode", 0) != 0) {
        continue;
      }
    }
    if (line.rfind("@batchcode", 0) == 0) {
      std::snprintf(state.batchcode_text, sizeof(state.batchcode_text), "%s",
                    line.c_str());
      import_batchcode(state);
      imported++;
      continue;
    }

    CheatEntry cheat;
    if (parse_cht_data_line(state, split_pipe(line), cheat)) {
      if (state.client.connected()) {
        (void)capture_cheat_off_value(state, cheat);
      }
      state.cheats.push_back(std::move(cheat));
      imported++;
    } else {
      skipped++;
    }
  }

  set_status(state, "Loaded " + std::to_string(imported) +
                        " trainer entries (" + std::to_string(skipped) +
                        " skipped)");
}

void save_trainer_file(AppState &state) {
  std::filesystem::path path(state.trainer_file_path);
  std::error_code ec;
  if (path.has_parent_path()) {
    std::filesystem::create_directories(path.parent_path(), ec);
  }
  if (ec) {
    set_status(state, "Failed to create trainer directory");
    return;
  }

  std::ofstream out(path, std::ios::binary);
  if (!out) {
    set_status(state, "Failed to open trainer file");
    return;
  }

  out << "1.4|" << process_label_for_trainer(state);
  if (state.has_process_info && !state.selected_process_info.title_id.empty()) {
    out << "|ID:" << state.selected_process_info.title_id;
  } else {
    out << "|ID:unknown";
  }
  out << "|VER:unknown|FM:memDBG\n";

  for (const auto &cheat : state.cheats) {
    int section = map_index_for_address(state, cheat.address);
    uint64_t offset = cheat.address;
    if (section >= 0) {
      offset = cheat.address - state.maps[static_cast<size_t>(section)].start;
    }
    out << "data|" << (section >= 0 ? section : 0) << "|" << std::hex
        << std::uppercase << offset << std::dec << "|"
        << cht_type_name(cheat.value_type) << "|" << cheat.value_text << "|"
        << (cheat.locked ? "1" : "0") << "|" << cheat.description << "|"
        << std::hex << std::uppercase << cheat.address << std::dec;
    if (cheat.has_off_bytes) {
      out << "|off:" << bytes_to_hex(cheat.off_bytes);
    }
    out << "\n";
  }

  set_status(state, "Saved " + std::to_string(state.cheats.size()) +
                        " trainer entries");
}

void apply_locked_cheats(AppState &state) {
  if (!state.client.connected() || state.cheats.empty()) {
    return;
  }
  const double now = ImGui::GetTime();
  const double interval = std::max(0.10f, state.cheat_lock_interval);
  if (now < state.next_cheat_lock_time) {
    return;
  }
  state.next_cheat_lock_time = now + interval;

  for (auto &cheat : state.cheats) {
    if (cheat.enabled && cheat.locked) {
      (void)apply_cheat(state, cheat);
    }
  }
}

void scan_range(AppState &state) {
  if (!state.client.connected()) {
    set_status(state, "Connect a console first");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process first");
    return;
  }

  uint64_t start = 0;
  uint64_t length = 0;
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!parse_u64(state.scan_start, start) ||
      !parse_u64(state.scan_length, length)) {
    set_status(state, "Invalid scan range");
    return;
  }
  if (!build_scan_value(state.scan_type, state.scan_value, value, value_len)) {
    set_status(state, "Invalid scan value");
    return;
  }
  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  memdbg_scan_exact_request_t request{};
  request.pid = state.selected_pid;
  request.start = start;
  request.length = length;
  request.value_type = static_cast<uint32_t>(state.scan_type);
  request.value_length = value_len;
  request.alignment = static_cast<uint32_t>(state.scan_alignment);
  request.max_results = static_cast<uint32_t>(state.scan_max_results);
  std::copy(value.begin(), value.end(), request.value);

  if (!state.client.scan_exact(request, state.scan_result)) {
    set_status(state, state.client.last_error());
    return;
  }
  capture_scan_snapshot(state);
  set_status(state, "Range scan complete");
}

void scan_process(AppState &state) {
  if (!state.client.connected()) {
    set_status(state, "Connect a console first");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process first");
    return;
  }

  uint64_t start = 0;
  uint64_t end = 0;
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!parse_u64(state.scan_start, start) || !parse_u64(state.scan_end, end)) {
    set_status(state, "Invalid process scan window");
    return;
  }
  if (!build_scan_value(state.scan_type, state.scan_value, value, value_len)) {
    set_status(state, "Invalid scan value");
    return;
  }
  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  memdbg_scan_process_exact_request_t request{};
  request.pid = state.selected_pid;
  request.value_type = static_cast<uint32_t>(state.scan_type);
  request.value_length = value_len;
  request.alignment = static_cast<uint32_t>(state.scan_alignment);
  request.max_results = static_cast<uint32_t>(state.scan_max_results);
  request.protection_mask = state.scan_readable_only ? 1U : 0U;
  request.start = start;
  request.end = end;
  std::copy(value.begin(), value.end(), request.value);

  if (!state.client.scan_process_exact(request, state.scan_result)) {
    set_status(state, state.client.last_error());
    return;
  }
  capture_scan_snapshot(state);
  set_status(state, "Process scan complete");
}

void nav_item(AppState &state, Screen screen, const char *label) {
  bool selected = state.screen == screen;
  ImGui::PushID(label);
  ImGui::PushStyleColor(ImGuiCol_Header,
                        selected ? ui::colors().bg3 : ImVec4(0, 0, 0, 0));
  ImGui::PushStyleColor(ImGuiCol_HeaderHovered,
                        ImVec4(36.0f / 255.0f, 62.0f / 255.0f,
                               72.0f / 255.0f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_HeaderActive,
                        ImVec4(28.0f / 255.0f, 98.0f / 255.0f,
                               110.0f / 255.0f, 1.0f));
  if (ImGui::Selectable(label, selected, 0, ImVec2(0, 42))) {
    state.screen = screen;
  }
  ImGui::PopStyleColor(3);
  if (selected) {
    ImDrawList *draw_list = ImGui::GetWindowDrawList();
    ImVec2 min = ImGui::GetItemRectMin();
    ImVec2 max = ImGui::GetItemRectMax();
    draw_list->AddRectFilled(ImVec2(min.x, min.y + 7.0f),
                             ImVec2(min.x + 4.0f, max.y - 7.0f),
                             ui::color_u32(ui::colors().primary2), 2.0f);
  }
  ImGui::PopID();
}

void draw_sidebar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 26));
  ImGui::BeginChild("Sidebar", size, true, ImGuiWindowFlags_NoScrollbar);

  ImGui::TextColored(ui::colors().text, "memDBG");
  ui::text_muted("Native v0.1.0");
  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14, 14));
  ImGui::BeginChild("SidebarStatus", ImVec2(0, 74), true,
                    ImGuiWindowFlags_NoScrollbar);
  ui::status_dot(state.client.connected() ? ui::colors().success
                                          : ui::colors().dim);
  ImGui::SameLine();
  ImGui::BeginGroup();
  ImGui::TextColored(state.client.connected() ? ui::colors().success
                                              : ui::colors().muted,
                     "%s", state.client.connected() ? "Connected" : "Offline");
  ImGui::TextColored(ui::colors().dim, "%s:%d", state.host, state.debug_port);
  ImGui::EndGroup();
  ImGui::EndChild();
  ImGui::PopStyleVar();
  ImGui::PopStyleColor();

  ImGui::Spacing();
  ImGui::Spacing();
  ui::text_dim("MAIN");
  nav_item(state, Screen::Home, "  Home");
  nav_item(state, Screen::Consoles, "  Consoles");

  ImGui::Spacing();
  ui::text_dim("TOOLSET");
  nav_item(state, Screen::Processes, "  Processes");
  nav_item(state, Screen::Memory, "  Memory");
  nav_item(state, Screen::Scanner, "  Scanner");
  nav_item(state, Screen::Trainer, "  Trainer");
  nav_item(state, Screen::Logs, "  Logs");

  ImGui::Spacing();
  ui::text_dim("SYSTEM");
  nav_item(state, Screen::Settings, "  Settings");
  nav_item(state, Screen::Credits, "  Credits");

  float footer_y = ImGui::GetWindowHeight() - 100.0f;
  if (ImGui::GetCursorPosY() < footer_y) {
    ImGui::SetCursorPosY(footer_y);
  }
  ImGui::Separator();
  ImGui::TextColored(ui::colors().dim, "Debug TCP | %d", state.debug_port);
  ImGui::TextColored(ui::colors().dim, "UDP logs  | %d", state.udp_port);
  ImGui::TextColored(ui::colors().muted, "File log  | /data/memdbg/memdbg.log");

  ImGui::EndChild();
  ImGui::PopStyleVar();
  ImGui::PopStyleColor();
}

void draw_top_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().panel);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24, 18));
  ImGui::BeginChild("TopBar", size, true, ImGuiWindowFlags_NoScrollbar);

  ImGui::BeginGroup();
  ImGui::TextColored(ui::colors().primary2, "%s", screen_title(state.screen));
  ImGui::TextColored(ui::colors().muted, "%s", screen_subtitle(state.screen));
  ImGui::EndGroup();

  const float button_w = state.client.connected() ? 150.0f : 178.0f;
  ImGui::SameLine();
  ImGui::SetCursorPosX(ImGui::GetWindowWidth() - button_w - 24.0f);
  ImGui::SetCursorPosY(24.0f);
  if (!state.client.connected()) {
    if (ui::primary_button("Connect Console", ImVec2(button_w, 42))) {
      connect_console(state);
    }
  } else {
    if (ui::danger_button("Disconnect", ImVec2(button_w, 42))) {
      disconnect_console(state);
    }
  }

  ImGui::EndChild();
  ImGui::PopStyleVar();
  ImGui::PopStyleColor();
}

void draw_status_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().panel);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(22, 10));
  ImGui::BeginChild("StatusBar", size, true, ImGuiWindowFlags_NoScrollbar);

  ui::status_dot(state.client.connected() ? ui::colors().success
                                          : ui::colors().muted);
  ImGui::SameLine();
  ImGui::TextUnformatted(state.status);

  const auto log_stats = state.udp_listener.stats();
  ImGui::SameLine();
  ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX(),
                                ImGui::GetWindowWidth() - 430.0f));
  ImGui::TextColored(ui::colors().dim, "FPS %.0f", ImGui::GetIO().Framerate);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "UDP %s",
                     state.udp_listener.running() ? "listening" : "stopped");
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%llu notices",
                     static_cast<unsigned long long>(log_stats.received));

  ImGui::EndChild();
  ImGui::PopStyleVar();
  ImGui::PopStyleColor();
}

void draw_home(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float col_w = (avail.x - gap) * 0.5f;

  ui::begin_panel("HomeStatus", "Connection Status", ImVec2(col_w, avail.y));
  if (state.client.connected()) {
    ImGui::TextColored(ui::colors().success, "CONNECTED TO CONSOLE");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::Text("Endpoint: %s:%d", state.host, state.debug_port);
    draw_capabilities(state);
    ImGui::Spacing();
    if (ui::soft_button("Ping Payload", ImVec2(160, 38))) {
      set_status(state,
                 state.client.ping() ? "Ping OK" : state.client.last_error());
    }
    ImGui::SameLine();
    if (ui::danger_button("Disconnect", ImVec2(150, 38))) {
      disconnect_console(state);
    }
  } else {
    ImGui::TextColored(ui::colors().danger, "NOT CONNECTED");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextWrapped("No active console session. Link the payload endpoint to unlock process, memory, scanner, and telemetry tools.");
    ImGui::Spacing();
    if (ui::primary_button("Configure Connection", ImVec2(210, 40))) {
      state.screen = Screen::Consoles;
    }
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("HomeActions", "Quick Actions", ImVec2(0, avail.y));
  if (ui::soft_button("Consoles", ui::full_button(46))) {
    state.screen = Screen::Consoles;
  }
  if (ui::soft_button("Processes", ui::full_button(46))) {
    state.screen = Screen::Processes;
  }
  if (ui::soft_button("Memory", ui::full_button(46))) {
    state.screen = Screen::Memory;
  }
  if (ui::soft_button("Scanner", ui::full_button(46))) {
    state.screen = Screen::Scanner;
  }
  if (ui::soft_button("Trainer", ui::full_button(46))) {
    state.screen = Screen::Trainer;
  }
  if (ui::soft_button("UDP Logs", ui::full_button(46))) {
    state.screen = Screen::Logs;
  }
  if (ui::soft_button("Settings", ui::full_button(46))) {
    state.screen = Screen::Settings;
  }
  ui::end_panel();
}

void draw_consoles(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float col_w = (avail.x - gap) * 0.5f;

  ui::begin_panel("ConsoleConnect", "Direct Console", ImVec2(col_w, avail.y));
  ImGui::InputText("Console IPv4", state.host, sizeof(state.host));
  ImGui::InputInt("Debug TCP", &state.debug_port);
  ImGui::InputInt("UDP logs", &state.udp_port);
  normalize_ports(state);
  ImGui::Spacing();

  if (!state.client.connected()) {
    if (ui::primary_button("Connect Console", ui::full_button(42))) {
      connect_console(state);
    }
  } else {
    if (ui::danger_button("Disconnect Console", ui::full_button(42))) {
      disconnect_console(state);
    }
  }

  if (state.client.connected()) {
    if (ui::soft_button("Ping Payload", ui::full_button(40))) {
      set_status(state,
                 state.client.ping() ? "Ping OK" : state.client.last_error());
    }
    if (ui::danger_button("Shutdown Payload", ui::full_button(40))) {
      set_status(state, state.client.shutdown_payload() ? "Shutdown sent"
                                                        : state.client.last_error());
    }
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  draw_capabilities(state);
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("ConsoleRuntime", "Runtime", ImVec2(0, avail.y));
  ImGui::TextColored(state.client.connected() ? ui::colors().success
                                              : ui::colors().danger,
                     "%s", state.client.connected() ? "Session open" : "No session");
  ImGui::Spacing();
  ImGui::TextWrapped("The frontend talks to the payload over the debug TCP port and listens for telemetry on UDP.");
  ImGui::Spacing();
  ImGui::Text("Debug endpoint: %s:%d", state.host, state.debug_port);
  ImGui::Text("UDP listener: %s:%d", "0.0.0.0", state.udp_port);
  ImGui::TextWrapped("Console file log: /data/memdbg/memdbg.log");
  ImGui::Spacing();

  if (!state.udp_listener.running()) {
    if (ui::soft_button("Start UDP Log Listener", ui::full_button(40))) {
      std::string error;
      if (ensure_udp_listener(state, error)) {
        set_status(state, "UDP log listener started");
      } else {
        set_status(state, error);
      }
    }
  } else {
    if (ui::soft_button("Restart UDP Log Listener", ui::full_button(40))) {
      state.udp_listener.stop();
      std::string error;
      if (ensure_udp_listener(state, error)) {
        set_status(state, "UDP log listener restarted");
      } else {
        set_status(state, error);
      }
    }
    if (ui::soft_button("Stop UDP Log Listener", ui::full_button(40))) {
      state.udp_listener.stop();
      set_status(state, "UDP log listener stopped");
    }
  }
  ui::end_panel();
}

void draw_process_table(AppState &state) {
  if (ImGui::BeginTable("ProcessTable", 3,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                        ImVec2(0, 0))) {
    ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 82);
    ImGui::TableSetupColumn("Name");
    ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 78);
    ImGui::TableHeadersRow();
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const auto &process = state.processes[i];
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      bool selected = i == state.selected_process_row;
      std::string label = std::to_string(process.pid) + "##pid" +
                          std::to_string(i);
      if (ImGui::Selectable(label.c_str(), selected,
                            ImGuiSelectableFlags_SpanAllColumns)) {
        select_process(state, i);
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(process.name.c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::TextColored(selected ? ui::colors().primary2 : ui::colors().dim,
                         "%s", selected ? "Active" : "-");
    }
    ImGui::EndTable();
  }
}

void draw_maps_table(AppState &state) {
  if (state.selected_pid <= 0) {
    draw_empty_state("No process selected",
                     "Select a process, then refresh maps to inspect memory ranges.");
    return;
  }

  if (ImGui::BeginTable("MapsTable", 5,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                        ImVec2(0, 0))) {
    ImGui::TableSetupColumn("Start");
    ImGui::TableSetupColumn("End");
    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90);
    ImGui::TableSetupColumn("Prot", ImGuiTableColumnFlags_WidthFixed, 58);
    ImGui::TableSetupColumn("Name");
    ImGui::TableHeadersRow();
    for (int i = 0; i < static_cast<int>(state.maps.size()); ++i) {
      const auto &map = state.maps[i];
      if (!map_passes_filters(state, map)) {
        continue;
      }
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      bool selected = state.selected_map_row == i;
      std::string start = hex_u64(map.start);
      if (ImGui::Selectable((start + "##map" + std::to_string(i)).c_str(),
                            selected, ImGuiSelectableFlags_SpanAllColumns)) {
        select_map(state, i);
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(hex_u64(map.end).c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::Text("%llu KB",
                  static_cast<unsigned long long>((map.end - map.start) / 1024U));
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(prot_text(map.protection).c_str());
      ImGui::TableSetColumnIndex(4);
      ImGui::TextUnformatted(map.name.c_str());
    }
    ImGui::EndTable();
  }
}

void draw_processes(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float left_w = std::max(360.0f, (avail.x - gap) * 0.42f);

  ui::begin_panel("ProcessesPanel", "Console Processes", ImVec2(left_w, avail.y));
  if (!state.client.connected()) {
    draw_empty_state("Connect a console",
                     "Process enumeration is available after a payload session is open.");
  } else {
    if (ui::soft_button("Refresh Processes", ImVec2(180, 38))) {
      refresh_processes(state);
    }
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, "%zu entries", state.processes.size());
    ImGui::Spacing();
    draw_process_table(state);
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("MapsPanel", "Memory Maps", ImVec2(0, avail.y));
  if (!state.client.connected()) {
    draw_empty_state("Waiting for session",
                     "Connect first, then choose a process to request maps.");
  } else {
    ImGui::Text("Active PID: %d", state.selected_pid);
    ImGui::TextColored(ui::colors().muted, "%s",
                       selected_process_name(state).c_str());
    if (state.has_process_info) {
      if (!state.selected_process_info.title_id.empty()) {
        ImGui::TextColored(ui::colors().primary2, "Title ID: %s",
                           state.selected_process_info.title_id.c_str());
      }
      if (!state.selected_process_info.content_id.empty()) {
        ImGui::TextWrapped("Content ID: %s",
                           state.selected_process_info.content_id.c_str());
      }
      if (!state.selected_process_info.path.empty()) {
        ImGui::TextWrapped("Path: %s", state.selected_process_info.path.c_str());
      }
    }
    if (ui::soft_button("Refresh Maps", ImVec2(150, 38))) {
      refresh_maps(state);
    }
    ImGui::SameLine();
    if (ui::soft_button("Use Filtered Window", ImVec2(185, 38))) {
      set_scan_window_from_filtered_maps(state);
    }
    ImGui::SameLine();
    if (ui::soft_button("Dump Selected Map", ImVec2(170, 38))) {
      dump_selected_map(state);
    }
    ImGui::Spacing();
    ImGui::InputText("Filter", state.map_filter, sizeof(state.map_filter));
    ImGui::Checkbox("Readable", &state.map_filter_readable);
    ImGui::SameLine();
    ImGui::Checkbox("Writable", &state.map_filter_writable);
    ImGui::SameLine();
    ImGui::Checkbox("Executable", &state.map_filter_executable);
    ImGui::Checkbox("Hide system maps", &state.map_filter_hide_system);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputInt("Min KB", &state.map_filter_min_kb);
    state.map_filter_min_kb = std::max(state.map_filter_min_kb, 0);
    ImGui::TextColored(ui::colors().dim, "%zu / %zu maps shown",
                       filtered_map_count(state), state.maps.size());
    ImGui::Spacing();
    draw_maps_table(state);
  }
  ui::end_panel();
}

void draw_memory(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float left_w = std::max(380.0f, (avail.x - gap) * 0.35f);

  ui::begin_panel("MemoryTools", "Memory Tools", ImVec2(left_w, avail.y));
  ImGui::Text("Active PID: %d", state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s",
                     selected_process_name(state).c_str());
  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  ImGui::InputText("Read address", state.read_address, sizeof(state.read_address));
  ImGui::InputInt("Read length", &state.read_length);
  state.read_length =
      std::clamp(state.read_length, 1, static_cast<int>(MEMDBG_PROTOCOL_MAX_READ));
  if (ui::primary_button("Read Memory", ui::full_button(40))) {
    read_memory(state);
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::InputText("Write address", state.write_address,
                   sizeof(state.write_address));
  ImGui::InputText("Bytes", state.write_bytes, sizeof(state.write_bytes));
  if (ui::danger_button("Write Memory", ui::full_button(40))) {
    write_memory(state);
  }

  ImGui::Spacing();
  ui::text_dim("Accepted byte formats: DEADBEEF or DE AD BE EF");
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("MemoryHex", "Hex View", ImVec2(0, avail.y));
  uint64_t base = 0;
  (void)parse_u64(state.read_address, base);
  draw_hex_view(state.memory, base);
  ui::end_panel();
}

void draw_scanner(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float left_w = std::max(420.0f, (avail.x - gap) * 0.38f);
  const char *type_names[] = {"Bytes", "u8", "u16", "u32",
                              "u64",   "float", "double", "pointer"};

  ui::begin_panel("ScannerControl", "Exact Scan", ImVec2(left_w, avail.y));
  ImGui::Text("Active PID: %d", state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s",
                     selected_process_name(state).c_str());
  ImGui::Spacing();

  ImGui::Combo("Value type", &state.scan_type, type_names,
               IM_ARRAYSIZE(type_names));
  ImGui::InputText("Value", state.scan_value, sizeof(state.scan_value));
  ImGui::InputInt("Alignment", &state.scan_alignment);
  ImGui::InputInt("Max results", &state.scan_max_results);
  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::InputText("Start", state.scan_start, sizeof(state.scan_start));
  ImGui::InputText("Length", state.scan_length, sizeof(state.scan_length));
  if (ui::primary_button("Scan Range", ui::full_button(40))) {
    scan_range(state);
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::InputText("End filter", state.scan_end, sizeof(state.scan_end));
  ImGui::Checkbox("Readable maps only", &state.scan_readable_only);
  if (ui::soft_button("Scan Process", ui::full_button(40))) {
    scan_process(state);
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Next Scan");
  ImGui::TextWrapped("%s", state.scan_session_status);
  if (ui::soft_button("Changed", ImVec2((ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f, 38))) {
    refine_scan(state, RefineMode::Changed);
  }
  ImGui::SameLine();
  if (ui::soft_button("Unchanged", ImVec2(0, 38))) {
    refine_scan(state, RefineMode::Unchanged);
  }
  if (ui::soft_button("Increased", ImVec2((ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f, 38))) {
    refine_scan(state, RefineMode::Increased);
  }
  ImGui::SameLine();
  if (ui::soft_button("Decreased", ImVec2(0, 38))) {
    refine_scan(state, RefineMode::Decreased);
  }
  if (ui::soft_button("Refresh Baseline", ui::full_button(38))) {
    capture_scan_snapshot(state);
    set_status(state, state.scan_session_status);
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("ScannerResults", "Results", ImVec2(0, avail.y));
  ImGui::Text("Results: %u%s  Type: %s", state.scan_result.count,
              state.scan_result.truncated ? " (truncated)" : "",
              value_type_name(state.scan_type));
  ImGui::Text("Scanned: %.2f MiB",
              static_cast<double>(state.scan_result.bytes_scanned) /
                  (1024.0 * 1024.0));
  ImGui::Text("Speed: %s",
              bytes_per_second(state.scan_result.bytes_scanned,
                               state.scan_result.elapsed_ns)
                  .c_str());
  ImGui::Text("Reads: %u  Regions: %u  Errors: %u",
              state.scan_result.read_calls, state.scan_result.regions_scanned,
              state.scan_result.read_errors);
  ImGui::Text("Session: %zu captured values",
              state.scan_snapshot.size());
  ImGui::Spacing();

  if (ImGui::BeginTable("ScanResultsTable", 1,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                            ImGuiTableFlags_ScrollY,
                        ImVec2(0, 0))) {
    ImGui::TableSetupColumn("Address");
    ImGui::TableHeadersRow();
    for (int i = 0; i < static_cast<int>(state.scan_result.addresses.size());
         ++i) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      std::string label = hex_u64(state.scan_result.addresses[i]) + "##scan" +
                          std::to_string(i);
      if (ImGui::Selectable(label.c_str())) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                      hex_u64(state.scan_result.addresses[i]).c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s",
                      hex_u64(state.scan_result.addresses[i]).c_str());
        state.screen = Screen::Memory;
      }
    }
    ImGui::EndTable();
  }
  ui::end_panel();
}

void draw_trainer(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float left_w = std::max(420.0f, (avail.x - gap) * 0.36f);
  const char *type_names[] = {"Bytes", "u8", "u16", "u32",
                              "u64",   "float", "double", "pointer"};

  ui::begin_panel("TrainerBuilder", "Cheat Builder", ImVec2(left_w, avail.y));
  ImGui::Text("Active PID: %d", state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s",
                     selected_process_name(state).c_str());
  ImGui::Spacing();

  if (ui::soft_button("Use Memory Address", ImVec2(185, 36))) {
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                  state.write_address);
  }
  ImGui::SameLine();
  if (!state.scan_result.addresses.empty() &&
      ui::soft_button("Use First Scan Hit", ImVec2(190, 36))) {
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                  hex_u64(state.scan_result.addresses.front()).c_str());
  }

  ImGui::InputText("Name", state.cheat_description,
                   sizeof(state.cheat_description));
  ImGui::InputText("Address", state.cheat_address, sizeof(state.cheat_address));
  ImGui::Combo("Value type", &state.cheat_type, type_names,
               IM_ARRAYSIZE(type_names));
  ImGui::InputText("Value", state.cheat_value, sizeof(state.cheat_value));
  ImGui::Checkbox("Lock value", &state.cheat_lock);
  ImGui::SliderFloat("Lock interval", &state.cheat_lock_interval, 0.10f, 5.0f,
                     "%.2fs");
  if (ui::primary_button("Add To Trainer", ui::full_button(40))) {
    add_cheat_from_fields(state);
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Trainer File");
  ImGui::InputText("Path", state.trainer_file_path,
                   sizeof(state.trainer_file_path));
  if (ui::soft_button("Load .cht", ImVec2((ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f, 38))) {
    load_trainer_file(state);
  }
  ImGui::SameLine();
  if (ui::soft_button("Save .cht", ImVec2(0, 38))) {
    save_trainer_file(state);
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Batchcode Import");
  ImGui::InputTextMultiline("##Batchcode", state.batchcode_text,
                            sizeof(state.batchcode_text),
                            ImVec2(0, 120));
  if (ui::soft_button("Import Batchcode", ui::full_button(38))) {
    import_batchcode(state);
  }
  ui::text_dim("Supported tokens: offset:0x..., value:0x..., size:n");
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("TrainerList", "Runtime Cheat List", ImVec2(0, avail.y));
  if (ui::soft_button("Apply Enabled", ImVec2(150, 38))) {
    int applied = 0;
    for (auto &cheat : state.cheats) {
      if (cheat.enabled && apply_cheat(state, cheat)) {
        applied++;
      }
    }
    set_status(state, "Applied " + std::to_string(applied) + " trainer entries");
  }
  ImGui::SameLine();
  if (ui::soft_button("Clear Disabled", ImVec2(150, 38))) {
    state.cheats.erase(
        std::remove_if(state.cheats.begin(), state.cheats.end(),
                       [](const CheatEntry &cheat) { return !cheat.enabled; }),
        state.cheats.end());
  }
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%zu entries", state.cheats.size());
  ImGui::Spacing();

  if (state.cheats.empty()) {
    draw_empty_state("No trainer entries",
                     "Add scan hits or manual addresses to build a runtime cheat list.");
  } else if (ImGui::BeginTable("TrainerTable", 10,
                               ImGuiTableFlags_RowBg |
                                   ImGuiTableFlags_Borders |
                                   ImGuiTableFlags_ScrollY |
                                   ImGuiTableFlags_Resizable,
                               ImVec2(0, 0))) {
    ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 44);
    ImGui::TableSetupColumn("Lock", ImGuiTableColumnFlags_WidthFixed, 54);
    ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 74);
    ImGui::TableSetupColumn("Name");
    ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70);
    ImGui::TableSetupColumn("Address");
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 70);
    ImGui::TableSetupColumn("Value");
    ImGui::TableSetupColumn("OFF", ImGuiTableColumnFlags_WidthFixed, 54);
    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 190);
    ImGui::TableHeadersRow();

    for (int i = 0; i < static_cast<int>(state.cheats.size()); ++i) {
      CheatEntry &cheat = state.cheats[i];
      ImGui::PushID(i);
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::Checkbox("##enabled", &cheat.enabled);
      ImGui::TableSetColumnIndex(1);
      ImGui::Checkbox("##locked", &cheat.locked);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextColored(cheat.active ? ui::colors().success : ui::colors().dim,
                         "%s", cheat.active ? "Active" : "Idle");
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(cheat.description.c_str());
      if (!cheat.status.empty() && ImGui::IsItemHovered()) {
        ImGui::SetTooltip("%s", cheat.status.c_str());
      }
      ImGui::TableSetColumnIndex(4);
      ImGui::Text("%d", cheat.pid);
      ImGui::TableSetColumnIndex(5);
      ImGui::TextUnformatted(hex_u64(cheat.address).c_str());
      ImGui::TableSetColumnIndex(6);
      ImGui::TextUnformatted(value_type_name(cheat.value_type));
      ImGui::TableSetColumnIndex(7);
      ImGui::TextUnformatted(cheat.value_text.c_str());
      ImGui::TableSetColumnIndex(8);
      ImGui::TextColored(cheat.has_off_bytes ? ui::colors().success
                                             : ui::colors().warning,
                         "%s", cheat.has_off_bytes ? "Yes" : "No");
      ImGui::TableSetColumnIndex(9);
      if (ImGui::SmallButton("On")) {
        if (apply_cheat(state, cheat)) {
          set_status(state, cheat.description + " applied");
        } else {
          set_status(state, cheat.status);
        }
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Off")) {
        if (deactivate_cheat(state, cheat)) {
          set_status(state, cheat.description + " restored");
        } else {
          set_status(state, cheat.status);
        }
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Cap")) {
        if (capture_cheat_off_value(state, cheat)) {
          set_status(state, cheat.description + " OFF captured");
        } else {
          set_status(state, cheat.status);
        }
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ui::end_panel();
}

void draw_logs(AppState &state, ImVec2 avail) {
  ui::begin_panel("LogsPanel", "UDP Telemetry", avail);

  if (!state.udp_listener.running()) {
    if (ui::soft_button("Start Listener", ImVec2(150, 38))) {
      std::string error;
      if (ensure_udp_listener(state, error)) {
        set_status(state, "UDP log listener started");
      } else {
        set_status(state, error);
      }
    }
  } else {
    if (ui::soft_button("Stop Listener", ImVec2(150, 38))) {
      state.udp_listener.stop();
      set_status(state, "UDP log listener stopped");
    }
  }
  ImGui::SameLine();
  if (ui::soft_button("Clear", ImVec2(110, 38))) {
    state.udp_listener.clear();
  }
  ImGui::SameLine();
  const auto log_stats = state.udp_listener.stats();
  ImGui::TextColored(ui::colors().dim,
                     "UDP %u | received %llu | dropped %llu | file mirror /data/memdbg/memdbg.log",
                     static_cast<unsigned>(log_stats.port),
                     static_cast<unsigned long long>(log_stats.received),
                     static_cast<unsigned long long>(log_stats.dropped));

  std::string err = state.udp_listener.last_error();
  if (!err.empty()) {
    ImGui::TextColored(ui::colors().warning, "UDP error: %s", err.c_str());
  }

  ImGui::Spacing();
  auto logs = state.udp_listener.snapshot();
  ImGui::BeginChild("LogLines", ImVec2(0, 0), false,
                    ImGuiWindowFlags_HorizontalScrollbar);
  if (logs.empty()) {
    draw_empty_state("No UDP messages yet",
                     "Payload telemetry will appear here after the console sends datagrams.");
  } else {
    for (const auto &line : logs) {
      ImGui::TextUnformatted(line.c_str());
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.0f) {
      ImGui::SetScrollHereY(1.0f);
    }
  }
  ImGui::EndChild();

  ui::end_panel();
}

void draw_settings(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float col_w = (avail.x - gap) * 0.5f;

  ui::begin_panel("SettingsConnection", "Connection Defaults", ImVec2(col_w, avail.y));
  ImGui::InputText("Console IPv4", state.host, sizeof(state.host));
  ImGui::InputInt("Debug TCP", &state.debug_port);
  ImGui::InputInt("UDP logs", &state.udp_port);
  normalize_ports(state);
  ImGui::Spacing();
  if (ui::soft_button("Apply UDP Port", ui::full_button(40))) {
    state.udp_listener.stop();
    std::string error;
    if (ensure_udp_listener(state, error)) {
      set_status(state, "UDP port applied");
    } else {
      set_status(state, error);
    }
  }
  if (ui::soft_button("Reset Console Defaults", ui::full_button(40))) {
    std::snprintf(state.host, sizeof(state.host), "%s", "192.168.1.100");
    state.debug_port = 9020;
    state.udp_port = 9023;
    set_status(state, "Console defaults restored");
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("SettingsRuntime", "Runtime Notes", ImVec2(0, avail.y));
  ImGui::TextWrapped("memDBG expects the payload to be running on the console. The app opens a TCP command session, while UDP logs can be received independently.");
  ImGui::Spacing();
  ImGui::Text("Protocol version: %u", MEMDBG_PROTOCOL_VERSION);
  ImGui::Text("Max read: %u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_READ));
  ImGui::Text("Max packet: %u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_PACKET));
  ImGui::TextWrapped("Console file log path: /data/memdbg/memdbg.log");
  ui::end_panel();
}

void draw_credits(AppState &state, ImVec2 avail) {
  memdbg::frontend::github_profile_start(state.github_profile);
  memdbg::frontend::github_profile_pump_texture(state.github_profile);

  std::string profile_name;
  std::string profile_login;
  std::string profile_bio;
  std::string profile_error;
  {
    std::lock_guard<std::mutex> lock(state.github_profile.mutex);
    profile_name = state.github_profile.name;
    profile_login = state.github_profile.login;
    profile_bio = state.github_profile.bio;
    profile_error = state.github_profile.error;
  }

  ui::begin_panel("CreditsPanel", "memDBG", avail);
  ImGui::BeginGroup();
  if (state.github_profile.texture != 0U) {
    ImGui::Image(memdbg::frontend::github_profile_texture_id(
                     state.github_profile),
                 ImVec2(96, 96));
  } else {
    ImDrawList *draw_list = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetCursorScreenPos();
    draw_list->AddRectFilled(pos, ImVec2(pos.x + 96.0f, pos.y + 96.0f),
                             ui::color_u32(ui::colors().bg3), 12.0f);
    draw_list->AddText(ImVec2(pos.x + 24.0f, pos.y + 38.0f),
                       ui::color_u32(ui::colors().muted), "SW");
    ImGui::Dummy(ImVec2(96, 96));
  }
  ImGui::EndGroup();

  ImGui::SameLine(0, 18);
  ImGui::BeginGroup();
  ImGui::TextColored(ui::colors().primary2, "memDBG Native");
  ImGui::Text("Version 0.1.0");
  ImGui::Text("Creator: %s (@%s)", profile_name.c_str(),
              profile_login.c_str());
  if (!profile_bio.empty()) {
    ImGui::TextWrapped("%s", profile_bio.c_str());
  }
  if (!profile_error.empty()) {
    ImGui::TextColored(ui::colors().warning, "GitHub profile: %s",
                       profile_error.c_str());
  }
  ImGui::EndGroup();

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::TextWrapped("Console-first frontend for connecting to the memDBG payload, browsing processes, reading and writing memory, scanning exact values, and watching telemetry.");
  ImGui::Spacing();
  ImGui::TextWrapped("License: GNU General Public License v3.0 or later");
  ImGui::Spacing();
  ImGui::Text("Current endpoint: %s:%d", state.host, state.debug_port);
  ui::end_panel();
}

void draw_screen(AppState &state, ImVec2 avail) {
  switch (state.screen) {
  case Screen::Home:
    draw_home(state, avail);
    break;
  case Screen::Consoles:
    draw_consoles(state, avail);
    break;
  case Screen::Processes:
    draw_processes(state, avail);
    break;
  case Screen::Memory:
    draw_memory(state, avail);
    break;
  case Screen::Scanner:
    draw_scanner(state, avail);
    break;
  case Screen::Trainer:
    draw_trainer(state, avail);
    break;
  case Screen::Logs:
    draw_logs(state, avail);
    break;
  case Screen::Settings:
    draw_settings(state, avail);
    break;
  case Screen::Credits:
    draw_credits(state, avail);
    break;
  }
}

void draw_app(AppState &state) {
  apply_locked_cheats(state);

  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);

  ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration |
                           ImGuiWindowFlags_NoMove |
                           ImGuiWindowFlags_NoSavedSettings |
                           ImGuiWindowFlags_NoBringToFrontOnFocus;
  ImGui::Begin("memDBG Shell", nullptr, flags);

  ImVec2 win_pos = ImGui::GetWindowPos();
  ImVec2 win_size = ImGui::GetWindowSize();
  ui::draw_background(ImGui::GetWindowDrawList(), win_pos, win_size);

  const float sidebar_w = std::clamp(win_size.x * 0.21f, 250.0f, 310.0f);
  const float top_h = 88.0f;
  const float status_h = 42.0f;
  const float gap = 16.0f;
  const float content_w = win_size.x - sidebar_w;

  ImGui::SetCursorPos(ImVec2(0, 0));
  draw_sidebar(state, ImVec2(sidebar_w, win_size.y));

  ImGui::SetCursorPos(ImVec2(sidebar_w, 0));
  draw_top_bar(state, ImVec2(content_w, top_h));

  ImGui::SetCursorPos(ImVec2(sidebar_w + gap, top_h + gap));
  draw_screen(state, ImVec2(content_w - (gap * 2.0f),
                            win_size.y - top_h - status_h - (gap * 2.0f)));

  ImGui::SetCursorPos(ImVec2(sidebar_w, win_size.y - status_h));
  draw_status_bar(state, ImVec2(content_w, status_h));

  ImGui::End();
}

} // namespace

namespace memdbg::frontend {

int run_frontend(int, char **) {
  if (!glfwInit()) {
    return 1;
  }

#if defined(__APPLE__)
  const char *glsl_version = "#version 150";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
  glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
  const char *glsl_version = "#version 130";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif

  GLFWwindow *window =
      glfwCreateWindow(1500, 920, "memDBG Native", nullptr, nullptr);
  if (window == nullptr) {
    glfwTerminate();
    return 1;
  }
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  ui::apply_theme();

  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init(glsl_version);

  AppState state;
  memdbg::frontend::github_profile_start(state.github_profile);
  std::string udp_error;
  if (!ensure_udp_listener(state, udp_error)) {
    set_status(state, "UDP log listener: " + udp_error);
  }

  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    draw_app(state);

    ImGui::Render();
    int display_w = 0;
    int display_h = 0;
    glfwGetFramebufferSize(window, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    glClearColor(11.0f / 255.0f, 11.0f / 255.0f, 14.0f / 255.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    glfwSwapBuffers(window);
  }

  state.udp_listener.stop();
  state.client.disconnect();
  memdbg::frontend::github_profile_shutdown(state.github_profile);

  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();
  glfwDestroyWindow(window);
  glfwTerminate();
  return 0;
}

} // namespace memdbg::frontend

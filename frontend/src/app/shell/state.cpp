/*
 * MemDBG - Console targets, port normalization, and persistent frontend settings.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "internal.hpp"
#include "platform.hpp"
#include <fstream>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
namespace memdbg::frontend {

void normalize_ports(AppState &state) {
  state.debug_port = std::clamp(state.debug_port, 1, 65535);
  state.udp_port    = std::clamp(state.udp_port, 1, 65535);
}

void normalize_console_target(ConsoleTarget &target) {
  target.name = trim_copy(target.name);
  if (target.name.empty()) target.name = "Default";
  target.host = trim_copy(target.host);
  if (target.host.empty()) target.host = "192.168.1.100";
  target.debug_port = target.debug_port <= 0 ? 9020 : std::clamp(target.debug_port, 1, 65535);
  target.udp_port = target.udp_port <= 0 ? 9023 : std::clamp(target.udp_port, 1, 65535);
}

ConsoleTarget current_console_target_from_fields(const AppState &state) {
  ConsoleTarget target;
  target.name = state.target_name;
  target.host = state.host;
  target.debug_port = state.debug_port;
  target.udp_port = state.udp_port;
  normalize_console_target(target);
  return target;
}

static void apply_console_target(AppState &state, const ConsoleTarget &target) {
  ConsoleTarget normalized = target;
  normalize_console_target(normalized);
  std::snprintf(state.target_name, sizeof(state.target_name), "%s", normalized.name.c_str());
  std::snprintf(state.host, sizeof(state.host), "%s", normalized.host.c_str());
  state.debug_port = normalized.debug_port;
  state.udp_port = normalized.udp_port;
}

static bool console_target_name_exists(const AppState &state, const std::string &name, int ignore_index) {
  for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
    if (i == ignore_index) continue;
    if (state.console_targets[i].name == name) return true;
  }
  return false;
}

static std::string unique_console_target_name(const AppState &state, std::string base, int ignore_index = -1) {
  base = trim_copy(base);
  if (base.empty()) base = "Target";
  if (!console_target_name_exists(state, base, ignore_index)) return base;

  for (int i = 2; i < 1000; ++i) {
    const std::string candidate = base + " " + std::to_string(i);
    if (!console_target_name_exists(state, candidate, ignore_index)) return candidate;
  }
  return base + " copy";
}

void ensure_console_targets(AppState &state) {
  normalize_ports(state);
  if (state.console_targets.empty()) {
    state.console_targets.push_back(current_console_target_from_fields(state));
  }
  for (auto &target : state.console_targets) normalize_console_target(target);
  if (state.selected_target_index < 0 ||
      state.selected_target_index >= static_cast<int>(state.console_targets.size())) {
    state.selected_target_index = 0;
  }
}

void select_console_target(AppState &state, int index) {
  ensure_console_targets(state);
  if (state.console_targets.empty()) return;
  index = std::clamp(index, 0, static_cast<int>(state.console_targets.size()) - 1);
  state.selected_target_index = index;
  apply_console_target(state, state.console_targets[static_cast<size_t>(index)]);
}

void save_current_console_target(AppState &state) {
  ensure_console_targets(state);
  if (state.console_targets.empty()) return;
  ConsoleTarget target = current_console_target_from_fields(state);
  target.name = unique_console_target_name(state, target.name, state.selected_target_index);
  state.console_targets[static_cast<size_t>(state.selected_target_index)] = target;
  apply_console_target(state, target);
}

void add_console_target(AppState &state) {
  ensure_console_targets(state);
  ConsoleTarget target = current_console_target_from_fields(state);
  target.name = unique_console_target_name(state, target.name);
  state.console_targets.push_back(target);
  state.selected_target_index = static_cast<int>(state.console_targets.size()) - 1;
  apply_console_target(state, target);
}

void remove_selected_console_target(AppState &state) {
  ensure_console_targets(state);
  if (state.console_targets.size() <= 1U) {
    state.console_targets.clear();
    state.selected_target_index = 0;
    ConsoleTarget target;
    state.console_targets.push_back(target);
    apply_console_target(state, target);
    return;
  }

  const int index = std::clamp(state.selected_target_index, 0,
                              static_cast<int>(state.console_targets.size()) - 1);
  state.console_targets.erase(state.console_targets.begin() + index);
  state.selected_target_index = std::min(index, static_cast<int>(state.console_targets.size()) - 1);
  apply_console_target(state, state.console_targets[static_cast<size_t>(state.selected_target_index)]);
}

bool ensure_udp_listener(AppState &state, std::string &error) {
  normalize_ports(state);
  if (state.udp_listener.running()) return true;
  if (state.udp_listener.start(static_cast<uint16_t>(state.udp_port))) return true;
  error = state.udp_listener.last_error();
  if (error.empty()) error = "UDP listener failed";
  return false;
}

/* ---- Persistent frontend settings ---- */

static std::filesystem::path frontend_settings_path() {
  return platform::app_config_dir() / "frontend.conf";
}

bool load_frontend_settings(AppState &state, std::string *error) {
  const std::filesystem::path path = frontend_settings_path();
  std::ifstream in(path);
  if (!in) return false;

  state.console_targets.clear();
  int saved_selected_target = 0;
  std::string line;
  while (std::getline(in, line)) {
    const size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    const std::string key = trim_copy(line.substr(0, eq));
    const std::string value = trim_copy(line.substr(eq + 1));
    if (key == "host" && !value.empty()) {
      std::snprintf(state.host, sizeof(state.host), "%s", value.c_str());
    } else if (key == "debug_port") {
      state.debug_port = std::atoi(value.c_str());
    } else if (key == "udp_port") {
      state.udp_port = std::atoi(value.c_str());
    } else if (key == "dump_path" && !value.empty()) {
      std::snprintf(state.dump_path, sizeof(state.dump_path), "%s", value.c_str());
    } else if (key == "language") {
      state.language = static_cast<int>(locale::lang_from_code(value.c_str()));
    } else if (key == "last_debugger_pid") {
      state.last_debugger_pid = static_cast<int32_t>(std::atoi(value.c_str()));
    } else if (key == "taskmgr_prefetch_on_connect") {
      state.taskmgr_prefetch_on_connect =
          value == "1" || value == "true" || value == "on" || value == "yes";
    } else if (key == "payload_auto_fetch") {
      state.payload_auto_fetch =
          value == "1" || value == "true" || value == "on" || value == "yes";
    } else if (key == "payload_platform") {
      state.payload_platform = std::atoi(value.c_str());
      if (state.payload_platform < 0 || state.payload_platform > 2)
        state.payload_platform = 0;
    } else if (key == "selected_target") {
      saved_selected_target = std::atoi(value.c_str());
    } else if (key == "sidebar_section_0") {
      state.sidebar_sections_expanded[0] = value == "1" || value == "true";
    } else if (key == "sidebar_section_1") {
      state.sidebar_sections_expanded[1] = value == "1" || value == "true";
    } else if (key == "sidebar_section_2") {
      state.sidebar_sections_expanded[2] = value == "1" || value == "true";
    } else if (key == "sidebar_section_3") {
      state.sidebar_sections_expanded[3] = value == "1" || value == "true";
    } else if (key == "sidebar_width") {
      state.sidebar_width = static_cast<float>(std::atof(value.c_str()));
    } else if (key.rfind("target.", 0) == 0) {
      const std::string rest = key.substr(7);
      const size_t dot = rest.find('.');
      if (dot == std::string::npos) continue;

      const std::string index_text = rest.substr(0, dot);
      char *end = nullptr;
      const long index = std::strtol(index_text.c_str(), &end, 10);
      if (end == index_text.c_str() || *end != '\0' || index < 0 || index >= 64) continue;

      const size_t target_index = static_cast<size_t>(index);
      if (state.console_targets.size() <= target_index)
        state.console_targets.resize(target_index + 1U);

      const std::string field = rest.substr(dot + 1);
      ConsoleTarget &target = state.console_targets[target_index];
      if (field == "name") {
        target.name = value;
      } else if (field == "host") {
        target.host = value;
      } else if (field == "debug_port") {
        target.debug_port = std::atoi(value.c_str());
      } else if (field == "udp_port") {
        target.udp_port = std::atoi(value.c_str());
      }
    }
  }

  normalize_ports(state);
  ensure_console_targets(state);
  state.selected_target_index = std::clamp(saved_selected_target, 0,
      static_cast<int>(state.console_targets.size()) - 1);
  select_console_target(state, state.selected_target_index);
  if (!in.eof() && error != nullptr) {
    *error = "Failed while reading " + path.string();
    return false;
  }
  return true;
}

bool save_frontend_settings(const AppState &state, std::string *error) {
  const std::filesystem::path path = frontend_settings_path();
  std::error_code ec;
  if (!path.parent_path().empty())
    std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (error != nullptr) *error = "Cannot create settings directory: " + ec.message();
    return false;
  }

  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    if (error != nullptr) *error = "Cannot write " + path.string();
    return false;
  }
  std::vector<ConsoleTarget> targets = state.console_targets;
  if (targets.empty()) targets.push_back(current_console_target_from_fields(state));
  for (auto &target : targets) normalize_console_target(target);

  int selected_target = state.selected_target_index;
  if (selected_target < 0 || selected_target >= static_cast<int>(targets.size()))
    selected_target = 0;
  targets[static_cast<size_t>(selected_target)] = current_console_target_from_fields(state);

  out << "host=" << state.host << "\n";
  out << "debug_port=" << state.debug_port << "\n";
  out << "udp_port=" << state.udp_port << "\n";
  out << "dump_path=" << state.dump_path << "\n";
  out << "last_debugger_pid=" << state.last_debugger_pid << "\n";
  out << "language=" << locale::lang_code(static_cast<locale::Lang>(state.language)) << "\n";
  out << "taskmgr_prefetch_on_connect=" << (state.taskmgr_prefetch_on_connect ? 1 : 0) << "\n";
  out << "payload_auto_fetch=" << (state.payload_auto_fetch ? 1 : 0) << "\n";
  out << "payload_platform=" << state.payload_platform << "\n";
  out << "selected_target=" << selected_target << "\n";
  for (int i = 0; i < 4; ++i)
    out << "sidebar_section_" << i << "=" << (state.sidebar_sections_expanded[i] ? 1 : 0) << "\n";
  if (state.sidebar_width > 0.0f)
    out << "sidebar_width=" << state.sidebar_width << "\n";
  out << "target_count=" << targets.size() << "\n";
  for (size_t i = 0; i < targets.size(); ++i) {
    const ConsoleTarget &target = targets[i];
    out << "target." << i << ".name=" << target.name << "\n";
    out << "target." << i << ".host=" << target.host << "\n";
    out << "target." << i << ".debug_port=" << target.debug_port << "\n";
    out << "target." << i << ".udp_port=" << target.udp_port << "\n";
  }
  if (!out) {
    if (error != nullptr) *error = "Failed while writing " + path.string();
    return false;
  }
  return true;
}
} // namespace

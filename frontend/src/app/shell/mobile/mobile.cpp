/*
 * MemDBG - Mobile (iOS/Android) layout and screens: network, logs, processes, scanner,
 *          trainer, plugins, credits, session, and fallback UI.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "../internal.hpp"
#include "trainer/trainer_format.hpp"
#include "trainer/batchcode_parser.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <cctype>
namespace memdbg::frontend {

struct MobileSafeArea { float left=0,top=0,right=0,bottom=0; };
static MobileSafeArea s_mobile_safe_area;
static bool s_mobile_tools_open = false;
void set_mobile_safe_area(float l,float t,float r,float b) { s_mobile_safe_area.left=std::max(0.0f,l); s_mobile_safe_area.top=std::max(0.0f,t); s_mobile_safe_area.right=std::max(0.0f,r); s_mobile_safe_area.bottom=std::max(0.0f,b); }
static void mobile_info_row(const char *label, const std::string &value,
                            ImVec4 value_color) {
  const float scl = ui::dpi_scale();
  const float label_w = 92.0f * scl;
  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::SameLine(label_w);
  text_ellipsis(value.c_str(), ImGui::GetContentRegionAvail().x, value_color);
}

static bool mobile_nav_button(const char *id, const char *icon,
                              const char *label, bool enabled) {
  const float scl = ui::dpi_scale();
  const ImVec2 size(ImGui::GetContentRegionAvail().x, 42.0f * scl);
  const std::string text = std::string(icon) + "  " + label;
  ImGui::PushID(id);
  ImGui::BeginDisabled(!enabled);
  const bool clicked = ui::soft_button(text.c_str(), size);
  ImGui::EndDisabled();
  ImGui::PopID();
  return clicked && enabled;
}

static std::string mobile_target_endpoint(const ConsoleTarget &target) {
  return target.host + ":" + std::to_string(target.debug_port) +
         " / UDP " + std::to_string(target.udp_port);
}

static void mobile_persist_console_targets(AppState &state,
                                           const std::string &ok_message) {
  std::string error;
  if (save_frontend_settings(state, &error)) {
    set_status(state, ok_message);
    push_notification(state, ok_message, 3.0);
  } else {
    const std::string message = "Cannot save console targets: " + error;
    set_status(state, message);
    push_notification(state, message, 5.0);
  }
}

static void mobile_use_discovered_console(AppState &state,
                                          const DiscoveryConsole &console) {
  const std::string name = !console.name.empty() ? console.name : console.ip;
  std::snprintf(state.target_name, sizeof(state.target_name), "%s",
                name.c_str());
  std::snprintf(state.host, sizeof(state.host), "%s", console.ip.c_str());
  state.debug_port = console.debug_port;
  if (console.udp_log_port != 0U) state.udp_port = console.udp_log_port;
  normalize_ports(state);
}

static void poll_mobile_discovery(AppState &state) {
  if (!state.discovery_pending || !state.discovery_future.valid()) return;
  auto status = state.discovery_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  bool ok = false;
  try {
    ok = state.discovery_future.get();
  } catch (const std::exception &ex) {
    state.discovery_error = ex.what();
  } catch (...) {
    state.discovery_error = "Unknown discovery error";
  }
  state.discovery_pending = false;

  if (!ok && !state.discovery_error.empty()) {
    set_status(state, state.discovery_error);
    push_notification(state, state.discovery_error, 5.0);
  } else if (state.discovered_consoles.empty()) {
    set_status(state, "No MemDBG payloads found on the local network.");
  } else {
    set_status(state, "Found " +
                      std::to_string(state.discovered_consoles.size()) +
                      " payload(s).");
  }
}

static void start_mobile_discovery(AppState &state) {
  if (state.discovery_pending) return;
  if (state.discovery_future.valid()) state.discovery_future.wait();
  state.discovery_pending = true;
  state.discovery_error.clear();
  state.discovered_consoles.clear();
  set_status(state, "Searching local network...");
  state.discovery_future = std::async(std::launch::async, [&state]() -> bool {
    return state.discovery_client.discover(
        MEMDBG_DEFAULT_DISCOVERY_PORT, 1.5, state.discovered_consoles,
        state.discovery_error);
  });
}

static void draw_mobile_section_label(const char *label) {
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", label);
}

static bool mobile_action_button(const std::string &label, bool primary,
                                 bool danger = false) {
  const float scl = ui::dpi_scale();
  const ImVec2 size(ImGui::GetContentRegionAvail().x, 42.0f * scl);
  if (danger) return ui::danger_button(label.c_str(), size);
  if (primary) return ui::primary_button(label.c_str(), size);
  return ui::soft_button(label.c_str(), size);
}

static std::string mobile_format_bytes(uint64_t bytes) {
  const char *units[] = {"B", "KiB", "MiB", "GiB"};
  double value = static_cast<double>(bytes);
  int unit = 0;
  while (value >= 1024.0 && unit < 3) {
    value /= 1024.0;
    ++unit;
  }
  char buffer[64];
  if (unit == 0)
    std::snprintf(buffer, sizeof(buffer), "%llu %s",
                  static_cast<unsigned long long>(bytes), units[unit]);
  else
    std::snprintf(buffer, sizeof(buffer), "%.2f %s", value, units[unit]);
  return buffer;
}

static void mobile_select_map(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.maps.size())) return;
  const MapEntry &map = state.maps[row];
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

static plugins::PluginRunContext mobile_build_plugin_context(
    const AppState &state) {
  plugins::PluginRunContext context;
  context.host = state.host;
  context.debug_port = state.debug_port;
  context.udp_port = state.udp_port;
  context.connected = state.client.connected();
  context.selected_pid = state.selected_pid;
  context.selected_process_name = selected_process_name(state);
  context.dump_path = state.dump_path;
  context.trainer_file_path = state.trainer_file_path;
  context.protocol_version = state.has_hello ? state.hello.protocol_version : 0U;
  context.capabilities = state.has_hello ? state.hello.capabilities : 0U;
  context.map_count = state.maps.size();
  context.scan_hit_count = state.scan_result.addresses.size();
  context.trainer_entry_count = state.cheats.size();
  return context;
}

static void mobile_start_plugin_refresh(AppState &state) {
  if (state.plugin_refresh_pending || state.plugin_run_pending) return;
  if (state.plugin_refresh_future.valid()) state.plugin_refresh_future.wait();
  state.plugin_refresh_error.clear();
  state.plugin_refresh_pending = true;
  set_status(state, "Refreshing plugin sources...");
  state.plugin_refresh_future = std::async(std::launch::async,
      [&state]() -> bool {
        std::string error;
        const bool ok = state.plugin_manager.refresh_all(&error);
        state.plugin_refresh_error = error;
        return ok;
      });
}

static void mobile_start_plugin_run(AppState &state,
                                    const plugins::PluginPackage &package) {
  if (!package.installed || state.plugin_refresh_pending ||
      state.plugin_run_pending) {
    return;
  }
  if (state.plugin_run_future.valid()) state.plugin_run_future.wait();
  const auto context = mobile_build_plugin_context(state);
  const std::string package_id = package.id;
  state.plugin_last_output.clear();
  state.plugin_last_error.clear();
  state.plugin_last_command.clear();
  state.plugin_last_id = package_id;
  state.plugin_run_pending = true;
  state.plugin_run_start_time = ImGui::GetTime();
  set_status(state, "Running plugin " + package.name + "...");
  state.plugin_run_future = std::async(std::launch::async,
      [&state, package_id, context]() {
        return state.plugin_manager.run_plugin(package_id, context);
      });
}

static std::string mobile_plugin_tags_text(
    const std::vector<std::string> &tags) {
  std::string out;
  for (const auto &tag : tags) {
    if (!out.empty()) out += ", ";
    out += tag;
  }
  return out;
}

static bool mobile_contains_ci(const std::string &haystack,
                               const std::string &needle) {
  if (needle.empty()) return true;
  auto lower = [](std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                     return static_cast<char>(std::tolower(c));
                   });
    return value;
  };
  return lower(haystack).find(lower(needle)) != std::string::npos;
}

static std::vector<plugins::PluginPackage> mobile_filtered_plugins(
    AppState &state, const std::vector<plugins::PluginSource> &sources) {
  if (state.plugin_source_filter < 0 ||
      state.plugin_source_filter > static_cast<int>(sources.size())) {
    state.plugin_source_filter = 0;
  }

  std::vector<plugins::PluginPackage> catalog = state.plugin_manager.catalog();
  if (state.plugin_source_filter > 0) {
    const auto &source = sources[static_cast<size_t>(
        state.plugin_source_filter - 1)];
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const plugins::PluginPackage &pkg) {
          return pkg.source_id != source.id;
        }), catalog.end());
  }

  const std::string filter = state.plugin_filter;
  if (!filter.empty()) {
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const plugins::PluginPackage &pkg) {
          return !mobile_contains_ci(pkg.name, filter) &&
                 !mobile_contains_ci(pkg.author, filter) &&
                 !mobile_contains_ci(pkg.id, filter) &&
                 !mobile_contains_ci(pkg.source_name, filter) &&
                 !mobile_contains_ci(pkg.short_description, filter) &&
                 !mobile_contains_ci(pkg.description, filter) &&
                 !mobile_contains_ci(mobile_plugin_tags_text(pkg.tags), filter);
        }), catalog.end());
  }

  std::sort(catalog.begin(), catalog.end(),
      [](const plugins::PluginPackage &a,
         const plugins::PluginPackage &b) {
        if (a.installed != b.installed) return a.installed > b.installed;
        if (a.enabled != b.enabled) return a.enabled > b.enabled;
        if (a.language != b.language)
          return static_cast<int>(a.language) > static_cast<int>(b.language);
        return a.name < b.name;
      });
  return catalog;
}

static std::string mobile_plugin_description(
    const plugins::PluginPackage &package) {
  if (!package.short_description.empty()) return package.short_description;
  if (!package.description.empty()) return package.description;
  return "No description provided.";
}

static void draw_mobile_network(AppState &state, ImVec2 size) {
  ensure_console_targets(state);
  poll_mobile_discovery(state);

  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const bool locked = connected || state.connect_pending;

  ImGui::BeginChild("MobileNetwork", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "Console");
  ImGui::SameLine();
  ui::status_dot(state.connect_pending ? palette.warning :
                 connected ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(connected ? palette.success :
                     state.connect_pending ? palette.warning : palette.danger,
                     "%s", state.connect_pending ? "Connecting" :
                          connected ? "Connected" : "Offline");

  ImGui::Spacing();
  ImGui::BeginChild("MobileNetworkSummary", ImVec2(0, 112.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  const ConsoleTarget current_target = {
      state.target_name, state.host, state.debug_port, state.udp_port
  };
  mobile_info_row("Target", state.target_name, palette.text);
  mobile_info_row("Endpoint", mobile_target_endpoint(current_target),
                  connected ? palette.text : palette.muted);
  mobile_info_row("UDP", state.udp_listener.running() ? "Listening" : "Stopped",
                  state.udp_listener.running() ? palette.success : palette.dim);
  mobile_info_row("Payload", state.has_hello ? "Handshake OK" : "No hello",
                  state.has_hello ? palette.success : palette.dim);
  ImGui::EndChild();

  ImGui::BeginDisabled(client_async_busy(state));
  if (connected) {
    if (mobile_action_button(std::string(icons::kGauge) + "  Ping payload",
                             false)) {
      set_status(state, state.client.ping() ? "Ping OK"
                                            : state.client.last_error());
    }
    if (mobile_action_button(std::string(icons::kDisconnect) +
                             "  Disconnect", false, true)) {
      disconnect_console(state);
    }
  } else {
    if (mobile_action_button(std::string(icons::kConnect) + "  Connect",
                             true)) {
      save_current_console_target(state);
      connect_console(state);
    }
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Target");
  ImGui::BeginDisabled(locked);
  std::string preview = state.console_targets.empty()
      ? "No saved targets"
      : state.console_targets[static_cast<size_t>(
            std::clamp(state.selected_target_index, 0,
                       static_cast<int>(state.console_targets.size()) - 1))].name;
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::BeginCombo("##MobileTargetProfile", preview.c_str())) {
    for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
      const ConsoleTarget &target = state.console_targets[static_cast<size_t>(i)];
      const bool selected = i == state.selected_target_index;
      const std::string label = target.name + "  " +
                                mobile_target_endpoint(target);
      if (ImGui::Selectable(label.c_str(), selected))
        select_console_target(state, i);
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }

  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText("Name##MobileTargetName", state.target_name,
                   sizeof(state.target_name));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText("IPv4##MobileTargetHost", state.host, sizeof(state.host));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Debug TCP##MobileDebugPort", &state.debug_port);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("UDP logs##MobileUdpPort", &state.udp_port);
  normalize_ports(state);

  const float gap = 6.0f * scl;
  const float button_w = (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f;
  if (ui::soft_button((std::string(icons::kSave) + " Save").c_str(),
                      ImVec2(button_w, 40.0f * scl))) {
    save_current_console_target(state);
    mobile_persist_console_targets(state, "Console target updated");
  }
  ImGui::SameLine(0, gap);
  if (ui::primary_button((std::string(icons::kAdd) + " Add").c_str(),
                         ImVec2(button_w, 40.0f * scl))) {
    add_console_target(state);
    mobile_persist_console_targets(state, "Console target added");
  }
  ImGui::SameLine(0, gap);
  if (ui::danger_button((std::string(icons::kTrash) + " Del").c_str(),
                        ImVec2(button_w, 40.0f * scl))) {
    remove_selected_console_target(state);
    mobile_persist_console_targets(state, "Console target removed");
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Saved");
  for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
    const ConsoleTarget &target = state.console_targets[static_cast<size_t>(i)];
    const bool selected = i == state.selected_target_index;
    ImGui::PushID(i);
    ImGui::BeginDisabled(locked);
    const std::string label =
        std::string(icons::kTarget) + "  " + (selected ? "* " : "") +
        target.name + "\n" + mobile_target_endpoint(target);
    if (ui::soft_button(label.c_str(),
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               52.0f * scl))) {
      select_console_target(state, i);
    }
    ImGui::EndDisabled();
    ImGui::PopID();
  }

  draw_mobile_section_label("Runtime");
  if (!state.udp_listener.running()) {
    if (mobile_action_button("Start UDP log listener", false)) {
      std::string error;
      if (ensure_udp_listener(state, error)) set_status(state, "UDP started");
      else set_status(state, error);
    }
  } else {
    if (mobile_action_button("Restart UDP log listener", false)) {
      state.udp_listener.stop();
      std::string error;
      if (ensure_udp_listener(state, error)) set_status(state, "UDP restarted");
      else set_status(state, error);
    }
    if (mobile_action_button("Stop UDP log listener", false)) {
      state.udp_listener.stop();
      set_status(state, "UDP stopped");
    }
  }

  draw_mobile_section_label("Discovery");
  ImGui::BeginDisabled(state.discovery_pending);
  if (mobile_action_button(std::string(icons::kRefresh) +
                           (state.discovery_pending ? "  Searching" :
                            "  Discover payloads"), false)) {
    start_mobile_discovery(state);
  }
  ImGui::EndDisabled();

  if (!state.discovered_consoles.empty()) {
    for (int i = 0; i < static_cast<int>(state.discovered_consoles.size()); ++i) {
      const DiscoveryConsole &console =
          state.discovered_consoles[static_cast<size_t>(i)];
      const std::string name = !console.name.empty() ? console.name : console.ip;
      const std::string endpoint =
          console.ip + ":" + std::to_string(console.debug_port) +
          " / UDP " + std::to_string(console.udp_log_port);
      ImGui::PushID(1000 + i);
      ImGui::BeginChild("MobileDiscoveredPayload", ImVec2(0, 86.0f * scl),
                        true, ImGuiWindowFlags_NoScrollbar);
      text_ellipsis(name.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.text);
      text_ellipsis(endpoint.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.muted);
      const float half = (ImGui::GetContentRegionAvail().x - gap) * 0.5f;
      ImGui::BeginDisabled(locked);
      if (ui::soft_button("Use", ImVec2(half, 32.0f * scl))) {
        mobile_use_discovered_console(state, console);
        set_status(state, "Selected discovered target " + console.ip);
      }
      ImGui::SameLine(0, gap);
      if (ui::primary_button("Save", ImVec2(half, 32.0f * scl))) {
        mobile_use_discovered_console(state, console);
        add_console_target(state);
        mobile_persist_console_targets(state, "Discovered target saved");
      }
      ImGui::EndDisabled();
      ImGui::EndChild();
      ImGui::PopID();
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static void draw_mobile_logs(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const auto stats = state.udp_listener.stats();
  auto logs = state.udp_listener.snapshot();

  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(12.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::BeginChild("MobileLogs", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);

  ImGui::TextColored(palette.primary2, "%s", "UDP Logs");
  ImGui::SameLine();
  ui::status_dot(state.udp_listener.running() ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(state.udp_listener.running() ? palette.success
                                                  : palette.muted,
                     "%s", state.udp_listener.running() ? "Listening"
                                                         : "Stopped");

  ImGui::BeginChild("MobileLogSummary", ImVec2(0, 138.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Port", std::to_string(stats.port),
                  state.udp_listener.running() ? palette.text : palette.dim);
  mobile_info_row("Received", std::to_string(stats.received), palette.text);
  mobile_info_row("Lost", std::to_string(stats.dropped), palette.muted);
  mobile_info_row("Buffered", std::to_string(logs.size()), palette.text);
  ImGui::Separator();
  const std::string error = state.udp_listener.last_error();
  text_ellipsis(error.empty() ? state.status : error.c_str(),
                ImGui::GetContentRegionAvail().x,
                error.empty() ? palette.muted : palette.warning);
  ImGui::EndChild();

  if (!state.udp_listener.running()) {
    if (mobile_action_button(std::string(icons::kPlay) +
                                 "  Start listener",
                             true)) {
      std::string start_error;
      if (ensure_udp_listener(state, start_error))
        set_status(state, "UDP listener started");
      else
        set_status(state, start_error);
    }
  } else if (mobile_action_button(std::string(icons::kStop) +
                                      "  Stop listener",
                                  false)) {
    state.udp_listener.stop();
    set_status(state, "UDP listener stopped");
  }

  if (ImGui::BeginTable("MobileLogActions", 2,
                        ImGuiTableFlags_SizingStretchSame)) {
    ImGui::TableNextColumn();
    if (mobile_action_button(std::string(icons::kCopy) + "  Copy", false)) {
      if (!logs.empty()) {
        std::string all;
        for (const auto &line : logs) all += line + "\n";
        ImGui::SetClipboardText(all.c_str());
        set_status(state, "Logs copied");
      } else {
        set_status(state, "No logs to copy");
      }
    }
    ImGui::TableNextColumn();
    if (mobile_action_button(std::string(icons::kTrash) + "  Clear", false)) {
      state.udp_listener.clear();
      logs.clear();
      set_status(state, "Logs cleared");
    }
    ImGui::EndTable();
  }

  draw_mobile_section_label("Messages");
  ImGui::BeginChild("MobileLogLines", ImVec2(0, 0), true);
  if (logs.empty()) {
    ImGui::TextColored(palette.muted, "%s", "No UDP messages yet");
    ImGui::TextWrapped("%s",
                       "Start the listener and keep this screen open while "
                       "the payload forwards runtime output.");
  } else {
    const float wrap_x = ImGui::GetCursorPosX() +
                         ImGui::GetContentRegionAvail().x;
    for (const auto &line : logs) {
      ImGui::PushTextWrapPos(wrap_x);
      ImGui::TextUnformatted(line.c_str());
      ImGui::PopTextWrapPos();
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.0f)
      ImGui::SetScrollHereY(1.0f);
  }
  ImGui::EndChild();

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
}

static void draw_mobile_plugin_source_popup(AppState &state) {
  const float scl = ui::dpi_scale();
  if (state.plugin_add_source_modal_open)
    ImGui::OpenPopup("MobileAddPluginSource");

  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowSize(
      ImVec2(std::min(430.0f * scl, viewport->WorkSize.x - 24.0f * scl), 0),
      ImGuiCond_Appearing);
  bool open = state.plugin_add_source_modal_open;
  if (ImGui::BeginPopupModal("MobileAddPluginSource", &open,
                             ImGuiWindowFlags_NoResize)) {
    ImGui::TextColored(ui::colors().primary2, "%s", "Add Plugin Source");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("Name##MobilePluginSourceName",
                     state.plugin_source_name,
                     sizeof(state.plugin_source_name));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("Manifest URL##MobilePluginSourceUrl",
                     state.plugin_source_url,
                     sizeof(state.plugin_source_url));
    ImGui::BeginDisabled(state.plugin_refresh_pending ||
                         state.plugin_run_pending);
    if (ui::primary_button((std::string(icons::kAdd) + "  Add").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  40.0f * scl))) {
      std::string error;
      if (state.plugin_manager.add_source(state.plugin_source_name,
                                          state.plugin_source_url, &error)) {
        std::snprintf(state.plugin_source_name,
                      sizeof(state.plugin_source_name), "%s",
                      "Community Repository");
        state.plugin_source_url[0] = '\0';
        state.plugin_add_source_modal_open = false;
        mobile_start_plugin_refresh(state);
        ImGui::CloseCurrentPopup();
      } else {
        set_status(state, error);
      }
    }
    ImGui::EndDisabled();
    if (ui::soft_button("Cancel",
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               38.0f * scl))) {
      state.plugin_add_source_modal_open = false;
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }
  if (!open) state.plugin_add_source_modal_open = false;
}

static void draw_mobile_plugin_output(AppState &state) {
  const bool has_output = state.plugin_run_pending ||
                          !state.plugin_last_error.empty() ||
                          !state.plugin_last_id.empty() ||
                          !state.plugin_last_command.empty() ||
                          !state.plugin_last_output.empty();
  if (!has_output) return;

  const float scl = ui::dpi_scale();
  draw_mobile_section_label("Runtime output");
  if (state.plugin_run_pending) {
    ui::draw_scan_progress("Plugin script", icons::kTerminal,
                           ImGui::GetTime() - state.plugin_run_start_time,
                           ImGui::GetContentRegionAvail().x);
    return;
  }

  if (!state.plugin_last_error.empty()) {
    ImGui::TextColored(ui::colors().danger, "%s",
                       state.plugin_last_error.c_str());
  } else {
    ImGui::TextColored(ui::colors().success, "Last run: %s",
                       state.plugin_last_id.c_str());
  }
  if (!state.plugin_last_command.empty()) {
    text_ellipsis(state.plugin_last_command.c_str(),
                  ImGui::GetContentRegionAvail().x, ui::colors().dim);
  }

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::BeginChild("MobilePluginOutputText", ImVec2(0, 150.0f * scl),
                    true);
  if (state.plugin_last_output.empty())
    ImGui::TextColored(ui::colors().dim, "%s", "Output will appear here.");
  else
    ImGui::TextUnformatted(state.plugin_last_output.c_str());
  ImGui::EndChild();
  ImGui::PopStyleColor();
}

static void draw_mobile_plugin_details(AppState &state,
                                       const plugins::PluginPackage &package) {
  const float scl = ui::dpi_scale();
  const bool ios_python =
#if defined(MEMDBG_PLATFORM_IOS)
      package.language == plugins::PluginLanguage::Python;
#else
      false;
#endif
  const bool runnable = package.installed && package.enabled && !ios_python;
  const float gap = 6.0f * scl;
  const float two_col = (ImGui::GetContentRegionAvail().x - gap) * 0.5f;

  ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                         ImGui::GetContentRegionAvail().x);
  ImGui::TextWrapped("%s", mobile_plugin_description(package).c_str());
  ImGui::PopTextWrapPos();
  ImGui::TextColored(ui::colors().dim, "%s  %s  %s",
                     plugins::language_name(package.language),
                     package.version.c_str(), package.source_name.c_str());

  ImGui::BeginDisabled(state.plugin_refresh_pending ||
                       state.plugin_run_pending);
  if (!package.installed) {
    if (ui::primary_button((std::string(icons::kDump) + "  Install").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  40.0f * scl))) {
      std::string error;
      if (state.plugin_manager.install_package(package.id,
                                               package.source_id, &error)) {
        set_status(state, "Plugin installed: " + package.name);
        push_notification(state, "Plugin installed: " + package.name);
      } else {
        set_status(state, error);
      }
    }
  } else {
    ImGui::BeginDisabled(!runnable);
    if (ui::primary_button((std::string(icons::kPlay) + "  Run").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  40.0f * scl))) {
      mobile_start_plugin_run(state, package);
    }
    ImGui::EndDisabled();
    if (ios_python) {
      ImGui::TextColored(ui::colors().warning, "%s",
                         "Python plugins are desktop-only on iOS.");
    }

    if (ui::soft_button((std::string(icons::kRefresh) + "  Update").c_str(),
                        ImVec2(two_col, 38.0f * scl))) {
      std::string error;
      if (state.plugin_manager.install_package(package.id,
                                               package.source_id, &error)) {
        set_status(state, "Plugin updated: " + package.name);
      } else {
        set_status(state, error);
      }
    }
    ImGui::SameLine(0, gap);
    if (ui::danger_button((std::string(icons::kTrash) + "  Remove").c_str(),
                          ImVec2(two_col, 38.0f * scl))) {
      std::string error;
      if (state.plugin_manager.uninstall_package(package.id, &error))
        set_status(state, "Plugin removed: " + package.name);
      else
        set_status(state, error);
    }

    bool enabled = package.enabled;
    if (ImGui::Checkbox("Enabled##MobilePluginEnabled", &enabled)) {
      std::string error;
      if (!state.plugin_manager.set_package_enabled(package.id, enabled,
                                                    &error)) {
        set_status(state, error);
      }
    }
  }
  ImGui::EndDisabled();

  if (!package.tags.empty()) {
    const std::string tags = mobile_plugin_tags_text(package.tags);
    text_ellipsis(tags.c_str(),
                  ImGui::GetContentRegionAvail().x, ui::colors().dim);
  }
}

static void draw_mobile_plugin_card(AppState &state,
                                    const plugins::PluginPackage &package,
                                    int index) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool selected = state.plugin_selected_row == index;
  const ImVec2 pos = ImGui::GetCursorScreenPos();
  const ImVec2 size(ImGui::GetContentRegionAvail().x, 76.0f * scl);
  ImGui::PushID(package.id.c_str());
  ImGui::InvisibleButton("##MobilePluginCard", size);
  if (ImGui::IsItemClicked()) {
    state.plugin_selected_row = selected ? -1 : index;
    state.plugin_description_expanded = false;
  }

  ImDrawList *draw = ImGui::GetWindowDrawList();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  const ImVec4 bg = selected ? ImVec4(0.06f, 0.22f, 0.17f, 1.0f)
      : ImGui::IsItemHovered() ? ImVec4(0.12f, 0.16f, 0.15f, 1.0f)
                               : palette.bg1;
  draw->AddRectFilled(pos, max, ui::color_u32(bg), 7.0f * scl);
  draw->AddRect(pos, max,
                ui::color_u32(selected ? palette.primary2 : palette.border),
                7.0f * scl, 0, 1.0f * scl);

  const char *language = plugins::language_name(package.language);
  const char *state_text = package.installed
      ? (package.enabled ? "Installed" : "Disabled")
      : "Available";
  const ImVec2 badge_min(pos.x + 10.0f * scl, pos.y + 12.0f * scl);
  const ImVec2 badge_max(badge_min.x + 46.0f * scl,
                         badge_min.y + 28.0f * scl);
  draw->AddRectFilled(badge_min, badge_max,
                      ui::color_u32(package.language == plugins::PluginLanguage::Lua
                                        ? ImVec4(0.16f, 0.18f, 0.34f, 1.0f)
                                        : ImVec4(0.14f, 0.24f, 0.32f, 1.0f)),
                      5.0f * scl);
  draw->AddText(ImVec2(badge_min.x + 7.0f * scl, badge_min.y + 6.0f * scl),
                ui::color_u32(palette.text), language);

  const float text_x = pos.x + 66.0f * scl;
  draw->PushClipRect(ImVec2(text_x, pos.y + 8.0f * scl),
                     ImVec2(max.x - 10.0f * scl, max.y - 8.0f * scl), true);
  draw->AddText(ImVec2(text_x, pos.y + 10.0f * scl),
                ui::color_u32(palette.text), package.name.c_str());
  const std::string meta = std::string(state_text) + "  |  " +
      (package.author.empty() ? "Unknown creator" : package.author);
  draw->AddText(ImVec2(text_x, pos.y + 31.0f * scl),
                ui::color_u32(package.installed ? palette.success :
                              palette.muted), meta.c_str());
  const std::string desc = mobile_plugin_description(package);
  draw->AddText(ImVec2(text_x, pos.y + 52.0f * scl),
                ui::color_u32(palette.dim), desc.c_str());
  draw->PopClipRect();

  ImGui::PopID();

  if (selected) {
    ImGui::Indent(8.0f * scl);
    draw_mobile_plugin_details(state, package);
    ImGui::Unindent(8.0f * scl);
  }
  ImGui::Spacing();
}

static void draw_mobile_plugins(AppState &state, ImVec2 size) {
  poll_plugin_tasks(state);
  const float scl = ui::dpi_scale();

  draw_mobile_plugin_source_popup(state);
  ImGui::BeginChild("MobilePlugins", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(ui::colors().primary2, "%s", "Plugins");
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%s",
                     state.plugin_run_pending ? "Running" :
                     state.plugin_refresh_pending ? "Refreshing" :
                     "Ready");

  std::vector<plugins::PluginSource> sources = state.plugin_manager.sources();
  std::vector<plugins::PluginPackage> catalog =
      mobile_filtered_plugins(state, sources);
  if (state.plugin_selected_row >= static_cast<int>(catalog.size()))
    state.plugin_selected_row = catalog.empty() ? -1 : 0;

  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("##MobilePluginSearch", "Search plugins...",
                           state.plugin_filter, sizeof(state.plugin_filter));

  const float gap = 6.0f * scl;
  const float button_w = (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f;
  ImGui::BeginDisabled(state.plugin_refresh_pending ||
                       state.plugin_run_pending);
  if (ui::soft_button((std::string(icons::kRefresh) + " Sync").c_str(),
                      ImVec2(button_w, 38.0f * scl))) {
    mobile_start_plugin_refresh(state);
  }
  ImGui::SameLine(0, gap);
  if (ui::primary_button((std::string(icons::kAdd) + " Source").c_str(),
                         ImVec2(button_w, 38.0f * scl))) {
    state.plugin_add_source_modal_open = true;
  }
  ImGui::SameLine(0, gap);
  if (ui::soft_button((std::string(icons::kSettings) + " GUI").c_str(),
                      ImVec2(button_w, 38.0f * scl))) {
    state.screen = Screen::PluginGUI;
    set_status(state, "GUI plugins use the desktop bridge on this build.");
  }
  ImGui::EndDisabled();

  if (!sources.empty()) {
    const char *preview = "All sources";
    std::string preview_label;
    if (state.plugin_source_filter > 0) {
      preview_label = sources[static_cast<size_t>(
          state.plugin_source_filter - 1)].name;
      preview = preview_label.c_str();
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("Source##MobilePluginSourceFilter", preview)) {
      if (ImGui::Selectable("All sources", state.plugin_source_filter == 0))
        state.plugin_source_filter = 0;
      for (size_t i = 0; i < sources.size(); ++i) {
        const bool selected =
            state.plugin_source_filter == static_cast<int>(i + 1U);
        if (ImGui::Selectable(sources[i].name.c_str(), selected))
          state.plugin_source_filter = static_cast<int>(i + 1U);
        if (selected) ImGui::SetItemDefaultFocus();
      }
      ImGui::EndCombo();
    }
  }

  draw_mobile_plugin_output(state);
  draw_mobile_section_label("Catalog");
  if (catalog.empty()) {
    ui::draw_empty_state("No plugins found",
                         "Refresh sources or change the search.");
  } else {
    for (size_t i = 0; i < catalog.size(); ++i) {
      draw_mobile_plugin_card(state, catalog[i], static_cast<int>(i));
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static uint32_t mobile_scan_value_len(const AppState &state) {
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (build_scan_value(state.scan_type, state.scan_value, value, value_len))
    return value_len;

  switch (state.scan_type) {
  case MEMDBG_VALUE_U8: return 1U;
  case MEMDBG_VALUE_U16: return 2U;
  case MEMDBG_VALUE_U32:
  case MEMDBG_VALUE_F32: return 4U;
  case MEMDBG_VALUE_U64:
  case MEMDBG_VALUE_F64:
  case MEMDBG_VALUE_POINTER: return 8U;
  default: return 1U;
  }
}

static bool mobile_scan_refine_match(int type, RefineMode mode,
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

static const char *mobile_refine_name(RefineMode mode) {
  switch (mode) {
  case RefineMode::Changed: return "Changed";
  case RefineMode::Unchanged: return "Unchanged";
  case RefineMode::Increased: return "Increased";
  case RefineMode::Decreased: return "Decreased";
  }
  return "Refine";
}

static bool mobile_has_batch_read(const AppState &state) {
  return (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;
}

static bool mobile_capture_snapshot_worker(Client &client, int32_t pid,
                                           const std::vector<uint64_t> &addrs,
                                           uint32_t value_len,
                                           bool has_batch_read,
                                           std::vector<ScanSnapshotEntry> &out,
                                           uint32_t &read_errors,
                                           uint64_t &elapsed_ns) {
  out.clear();
  read_errors = 0;
  elapsed_ns = 0;
  if (pid <= 0 || addrs.empty() || value_len == 0U) return true;

  const auto start = std::chrono::steady_clock::now();
  out.reserve(addrs.size());

  if (has_batch_read) {
    std::vector<memdbg_batch_read_item_t> batch_items;
    batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
    for (size_t base = 0U; base < addrs.size();
         base += MEMDBG_BATCH_READ_MAX_ITEMS) {
      batch_items.clear();
      const size_t chunk_end =
          std::min(base + MEMDBG_BATCH_READ_MAX_ITEMS, addrs.size());
      for (size_t i = base; i < chunk_end; ++i) {
        memdbg_batch_read_item_t item{};
        item.address = addrs[i];
        item.length = value_len;
        batch_items.push_back(item);
      }

      Client::BatchReadResult batch;
      if (!client.batch_read(pid, batch_items, batch)) {
        read_errors += static_cast<uint32_t>(chunk_end - base);
        continue;
      }

      uint32_t data_offset = 0U;
      for (const auto &entry : batch.entries) {
        if (data_offset > batch.data.size() ||
            entry.length > batch.data.size() - data_offset ||
            entry.status != 0U || entry.length != value_len) {
          read_errors++;
          data_offset += std::min<uint32_t>(
              entry.length,
              data_offset <= batch.data.size()
                  ? static_cast<uint32_t>(batch.data.size() - data_offset)
                  : 0U);
          continue;
        }

        ScanSnapshotEntry snap;
        snap.address = entry.address;
        snap.bytes.assign(batch.data.begin() + data_offset,
                          batch.data.begin() + data_offset + entry.length);
        out.push_back(std::move(snap));
        data_offset += entry.length;
      }
    }
  } else {
    for (uint64_t address : addrs) {
      std::vector<uint8_t> data;
      if (!client.memory_read(pid, address, value_len, data) ||
          data.size() != value_len) {
        read_errors++;
        continue;
      }
      ScanSnapshotEntry snap;
      snap.address = address;
      snap.bytes = std::move(data);
      out.push_back(std::move(snap));
    }
  }

  const auto end = std::chrono::steady_clock::now();
  elapsed_ns = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
          .count());
  return true;
}

static void mobile_prepare_scan_async(AppState &state,
                                      const std::string &label) {
  if (state.scan_async_future.valid()) state.scan_async_future.wait();
  {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    state.scan_async_temp_result = ScanResult{};
    state.scan_async_temp_snapshot.clear();
    state.scan_async_temp_snapshot_value_len = 0U;
    state.scan_async_temp_snapshot_type = state.scan_type;
    state.scan_async_temp_is_unknown = false;
    state.scan_async_temp_session_status[0] = '\0';
    state.scan_async_error.clear();
    state.auto_search_temp_candidates.clear();
  }
  state.scan_async_label = label;
  state.scan_async_start_time = ImGui::GetTime();
  state.scan_async_pending = true;
  state.scan_async_owner = Screen::Scanner;
}

static void mobile_start_range_scan(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) {
    set_status(state, "Connect a console before scanning");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before scanning");
    return;
  }
  if (!payload_supports(state, MEMDBG_CAP_SCAN_EXACT)) {
    set_status(state, "Payload does not support exact range scans");
    return;
  }

  uint64_t start = 0;
  uint64_t length = 0;
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!parse_u64(state.scan_start, start) ||
      !parse_u64(state.scan_length, length) || length == 0U) {
    set_status(state, "Enter a valid start and non-zero length");
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

  mobile_prepare_scan_async(state, "Range scan");
  const int32_t pid = state.selected_pid;
  const int scan_type = state.scan_type;
  Client &client = state.client;
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_value_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_type = state.scan_async_temp_snapshot_type;
  auto &temp_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = mobile_has_batch_read(state);

  state.scan_async_future = std::async(
      std::launch::async,
      [&client, request, pid, scan_type, value_len, has_batch, &temp_result,
       &temp_snapshot, &temp_value_len, &temp_type, &temp_unknown,
       &temp_status, &error_out, &mtx = state.scan_async_mtx]() -> bool {
        std::lock_guard<std::mutex> lock(mtx);
        ScanResult result;
        if (!client.scan_exact(request, result)) {
          error_out = client.last_error();
          return false;
        }

        uint32_t read_errors = 0;
        uint64_t snapshot_ns = 0;
        std::vector<ScanSnapshotEntry> snapshot;
        mobile_capture_snapshot_worker(client, pid, result.addresses,
                                       value_len, has_batch, snapshot,
                                       read_errors, snapshot_ns);

        const uint64_t capture_bytes =
            static_cast<uint64_t>(snapshot.size()) * value_len;
        result.read_calls += static_cast<uint32_t>(result.addresses.size());
        result.read_errors += read_errors;
        result.elapsed_ns += snapshot_ns;
        temp_result = std::move(result);
        temp_snapshot = std::move(snapshot);
        temp_value_len = value_len;
        temp_type = scan_type;
        temp_unknown = false;
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu values, %u read errors, %s",
                      has_batch ? "BATCH_READ" : "individual reads",
                      temp_snapshot.size(), read_errors,
                      bytes_per_second(capture_bytes, snapshot_ns).c_str());
        return true;
      });
}

static void mobile_start_process_scan(AppState &state, bool unknown) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) {
    set_status(state, "Connect a console before scanning");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before scanning");
    return;
  }
  const uint32_t required_cap =
      unknown ? MEMDBG_CAP_SCAN_UNKNOWN : MEMDBG_CAP_SCAN_PROCESS_EXACT;
  if (!payload_supports(state, required_cap)) {
    set_status(state, unknown ? "Payload does not support unknown scans"
                              : "Payload does not support process scans");
    return;
  }

  uint64_t start = 0;
  uint64_t end = 0;
  if (!parse_u64(state.scan_start, start) ||
      !parse_u64(state.scan_end, end) || (end != 0U && end <= start)) {
    set_status(state, "Enter a valid scan window");
    return;
  }

  std::array<uint8_t, 16> value{};
  uint32_t value_len = mobile_scan_value_len(state);
  if (!unknown &&
      !build_scan_value(state.scan_type, state.scan_value, value, value_len)) {
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
  if (!unknown) std::copy(value.begin(), value.end(), request.value);

  mobile_prepare_scan_async(state, unknown ? "Unknown value scan"
                                           : "Process scan");
  const int32_t pid = state.selected_pid;
  const int scan_type = state.scan_type;
  Client &client = state.client;
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_value_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_type = state.scan_async_temp_snapshot_type;
  auto &temp_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = mobile_has_batch_read(state);

  state.scan_async_future = std::async(
      std::launch::async,
      [&client, request, pid, scan_type, value_len, has_batch, unknown,
       &temp_result, &temp_snapshot, &temp_value_len, &temp_type,
       &temp_unknown, &temp_status, &error_out,
       &mtx = state.scan_async_mtx]() -> bool {
        std::lock_guard<std::mutex> lock(mtx);
        ScanResult result;
        const bool ok = unknown ? client.scan_unknown(request, result)
                                : client.scan_process_exact(request, result);
        if (!ok) {
          error_out = client.last_error();
          return false;
        }

        uint32_t read_errors = 0;
        uint64_t snapshot_ns = 0;
        std::vector<ScanSnapshotEntry> snapshot;
        mobile_capture_snapshot_worker(client, pid, result.addresses,
                                       value_len, has_batch, snapshot,
                                       read_errors, snapshot_ns);

        const uint64_t capture_bytes =
            static_cast<uint64_t>(snapshot.size()) * value_len;
        result.read_calls += static_cast<uint32_t>(result.addresses.size());
        result.read_errors += read_errors;
        result.elapsed_ns += snapshot_ns;
        temp_result = std::move(result);
        temp_snapshot = std::move(snapshot);
        temp_value_len = value_len;
        temp_type = scan_type;
        temp_unknown = unknown;
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu values, %u read errors, %s",
                      has_batch ? "BATCH_READ" : "individual reads",
                      temp_snapshot.size(), read_errors,
                      bytes_per_second(capture_bytes, snapshot_ns).c_str());
        return true;
      });
}

static void mobile_poll_scanner_async(AppState &state) {
  if (!state.scan_async_pending || !state.scan_async_future.valid()) return;
  if (state.scan_async_future.wait_for(std::chrono::milliseconds(0)) !=
      std::future_status::ready) {
    return;
  }

  state.scan_async_pending = false;
  bool ok = false;
  try {
    ok = state.scan_async_future.get();
  } catch (const std::exception &ex) {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    state.scan_async_error = ex.what();
  } catch (...) {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    state.scan_async_error = "Unknown scanner error";
  }

  if (state.scan_async_owner != Screen::Scanner) return;

  if (!ok) {
    std::string error;
    {
      std::lock_guard<std::mutex> lock(state.scan_async_mtx);
      error = state.scan_async_error.empty() ? "Scanner request failed"
                                             : state.scan_async_error;
      state.scan_async_error.clear();
    }
    set_status(state, error);
    push_notification(state, error, 5.0);
    return;
  }

  ScanResult result;
  std::vector<ScanSnapshotEntry> snapshot;
  uint32_t value_len = 0U;
  int type = MEMDBG_VALUE_U32;
  bool unknown = false;
  char status[256] = {};
  {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    result = std::move(state.scan_async_temp_result);
    snapshot = std::move(state.scan_async_temp_snapshot);
    value_len = state.scan_async_temp_snapshot_value_len;
    type = state.scan_async_temp_snapshot_type;
    unknown = state.scan_async_temp_is_unknown;
    std::memcpy(status, state.scan_async_temp_session_status, sizeof(status));
  }

  state.scan_result = std::move(result);
  state.scan_snapshot = std::move(snapshot);
  state.scan_snapshot_value_len = value_len;
  state.scan_snapshot_type = type;
  state.scan_is_unknown_session = unknown;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s", status[0] != '\0' ? status : "Scan complete");
  set_status(state, state.scan_session_status);
  push_notification(state, state.scan_async_label + ": " +
                               std::to_string(state.scan_result.count) +
                               " results");
}

static void mobile_refresh_scan_snapshot(AppState &state) {
  if (!state.client.connected() || state.selected_pid <= 0 ||
      state.scan_result.addresses.empty()) {
    set_status(state, "Run a scan before refreshing the baseline");
    return;
  }
  if (client_async_busy(state)) {
    set_status(state, "Wait for the active operation to finish");
    return;
  }

  const uint32_t value_len = mobile_scan_value_len(state);
  uint32_t read_errors = 0;
  uint64_t elapsed_ns = 0;
  std::vector<ScanSnapshotEntry> snapshot;
  mobile_capture_snapshot_worker(state.client, state.selected_pid,
                                 state.scan_result.addresses, value_len,
                                 mobile_has_batch_read(state), snapshot,
                                 read_errors, elapsed_ns);

  state.scan_snapshot = std::move(snapshot);
  state.scan_snapshot_value_len = value_len;
  state.scan_snapshot_type = state.scan_type;
  state.scan_is_unknown_session = false;
  state.scan_result.read_calls +=
      static_cast<uint32_t>(state.scan_result.addresses.size());
  state.scan_result.read_errors += read_errors;
  state.scan_result.elapsed_ns += elapsed_ns;
  const uint64_t capture_bytes =
      static_cast<uint64_t>(state.scan_snapshot.size()) * value_len;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s: %zu values, %u read errors, %s",
                mobile_has_batch_read(state) ? "BATCH_READ"
                                             : "individual reads",
                state.scan_snapshot.size(), read_errors,
                bytes_per_second(capture_bytes, elapsed_ns).c_str());
  set_status(state, state.scan_session_status);
}

static void mobile_refine_scan(AppState &state, RefineMode mode) {
  if (!state.client.connected() || state.selected_pid <= 0 ||
      state.scan_snapshot.empty() || state.scan_snapshot_value_len == 0U) {
    set_status(state, "Run a scan before refining");
    return;
  }
  if (client_async_busy(state)) {
    set_status(state, "Wait for the active operation to finish");
    return;
  }

  const uint32_t value_len = state.scan_snapshot_value_len;
  const auto old_snapshot = state.scan_snapshot;
  std::vector<uint64_t> addrs;
  addrs.reserve(old_snapshot.size());
  for (const auto &entry : old_snapshot) addrs.push_back(entry.address);

  uint32_t read_errors = 0;
  uint64_t elapsed_ns = 0;
  std::vector<ScanSnapshotEntry> current;
  mobile_capture_snapshot_worker(state.client, state.selected_pid, addrs,
                                 value_len, mobile_has_batch_read(state),
                                 current, read_errors, elapsed_ns);

  std::unordered_map<uint64_t, std::vector<uint8_t>> old_by_address;
  old_by_address.reserve(old_snapshot.size());
  for (const auto &entry : old_snapshot)
    old_by_address.emplace(entry.address, entry.bytes);

  std::vector<ScanSnapshotEntry> next_snapshot;
  std::vector<uint64_t> next_addresses;
  next_snapshot.reserve(current.size());
  next_addresses.reserve(current.size());
  uint64_t bytes_read = 0U;
  for (auto &entry : current) {
    auto it = old_by_address.find(entry.address);
    if (it == old_by_address.end()) continue;
    bytes_read += entry.bytes.size();
    if (!mobile_scan_refine_match(state.scan_snapshot_type, mode, it->second,
                                  entry.bytes)) {
      continue;
    }
    next_addresses.push_back(entry.address);
    next_snapshot.push_back(std::move(entry));
  }

  state.scan_snapshot = std::move(next_snapshot);
  state.scan_result.addresses = std::move(next_addresses);
  state.scan_result.count =
      static_cast<uint32_t>(state.scan_result.addresses.size());
  state.scan_result.truncated = false;
  state.scan_result.bytes_scanned = bytes_read;
  state.scan_result.elapsed_ns = elapsed_ns;
  state.scan_result.read_calls =
      static_cast<uint32_t>(current.size() + read_errors);
  state.scan_result.read_errors = read_errors;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s kept %zu values", mobile_refine_name(mode),
                state.scan_snapshot.size());
  set_status(state, state.scan_session_status);
  push_notification(state, state.scan_session_status);
}

static std::string mobile_scan_value_text(int type,
                                          const std::vector<uint8_t> &bytes) {
  char buf[96] = {};
  switch (type) {
  case MEMDBG_VALUE_U8:
    if (bytes.size() >= sizeof(uint8_t))
      std::snprintf(buf, sizeof(buf), "%u",
                    static_cast<unsigned>(read_scalar<uint8_t>(bytes)));
    break;
  case MEMDBG_VALUE_U16:
    if (bytes.size() >= sizeof(uint16_t))
      std::snprintf(buf, sizeof(buf), "%u",
                    static_cast<unsigned>(read_scalar<uint16_t>(bytes)));
    break;
  case MEMDBG_VALUE_U32:
    if (bytes.size() >= sizeof(uint32_t))
      std::snprintf(buf, sizeof(buf), "%u", read_scalar<uint32_t>(bytes));
    break;
  case MEMDBG_VALUE_U64:
    if (bytes.size() >= sizeof(uint64_t))
      std::snprintf(buf, sizeof(buf), "%llu",
                    static_cast<unsigned long long>(
                        read_scalar<uint64_t>(bytes)));
    break;
  case MEMDBG_VALUE_POINTER:
    if (bytes.size() >= sizeof(uint64_t))
      return hex_u64(read_scalar<uint64_t>(bytes));
    break;
  case MEMDBG_VALUE_F32:
    if (bytes.size() >= sizeof(float))
      std::snprintf(buf, sizeof(buf), "%.6g",
                    static_cast<double>(read_scalar<float>(bytes)));
    break;
  case MEMDBG_VALUE_F64:
    if (bytes.size() >= sizeof(double))
      std::snprintf(buf, sizeof(buf), "%.12g", read_scalar<double>(bytes));
    break;
  default:
    break;
  }
  if (buf[0] != '\0') return buf;
  return bytes_to_hex(bytes);
}

static const ScanSnapshotEntry *mobile_snapshot_for(const AppState &state,
                                                    uint64_t address) {
  for (const auto &entry : state.scan_snapshot)
    if (entry.address == address) return &entry;
  return nullptr;
}

static void mobile_value_type_combo(const char *label, int *value) {
  static const char *const type_names[] = {
      "Bytes", "u8", "u16", "u32", "u64", "float", "double", "pointer"};
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::Combo(label, value, type_names, IM_ARRAYSIZE(type_names));
}

static void draw_mobile_scanner(AppState &state, ImVec2 size) {
  mobile_poll_scanner_async(state);
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const bool has_pid = state.selected_pid > 0;

  ImGui::BeginChild("MobileScanner", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "Scanner");
  ImGui::SameLine();
  ui::status_dot(state.scan_async_pending ? palette.warning :
                 connected && has_pid ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(palette.muted, "%s", selected_process_name(state).c_str());

  ImGui::BeginChild("MobileScannerSummary", ImVec2(0, 128.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  has_pid ? palette.text : palette.dim);
  mobile_info_row("Results", std::to_string(state.scan_result.count) +
                                 (state.scan_result.truncated ? " truncated"
                                                              : ""),
                  state.scan_result.count != 0 ? palette.success
                                               : palette.muted);
  mobile_info_row("Speed",
                  bytes_per_second(state.scan_result.bytes_scanned,
                                   state.scan_result.elapsed_ns),
                  palette.muted);
  mobile_info_row("Session", state.scan_session_status, palette.dim);
  ImGui::EndChild();

  draw_mobile_section_label("Exact value");
  mobile_value_type_combo("Value type##MobileScanType", &state.scan_type);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Value##MobileScanValue", "0",
                           state.scan_value, sizeof(state.scan_value));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Alignment##MobileScanAlignment", &state.scan_alignment);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Max results##MobileScanMaxResults",
                  &state.scan_max_results);
  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  draw_mobile_section_label("Range");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Start##MobileScanStart", "0x0",
                           state.scan_start, sizeof(state.scan_start));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Length##MobileScanLength", "0x1000",
                           state.scan_length, sizeof(state.scan_length));

  const bool can_range = connected && has_pid && !client_async_busy(state) &&
                         payload_supports(state, MEMDBG_CAP_SCAN_EXACT);
  ImGui::BeginDisabled(!can_range);
  if (mobile_action_button(std::string(icons::kSearch) + "  Range scan",
                           true)) {
    mobile_start_range_scan(state);
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Process scan");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("End filter##MobileScanEnd", "0x0",
                           state.scan_end, sizeof(state.scan_end));
  ImGui::Checkbox("Readable maps only", &state.scan_readable_only);

  const bool can_process =
      connected && has_pid && !client_async_busy(state) &&
      payload_supports(state, MEMDBG_CAP_SCAN_PROCESS_EXACT);
  ImGui::BeginDisabled(!can_process);
  if (mobile_action_button(std::string(icons::kTarget) + "  Scan process",
                           false)) {
    mobile_start_process_scan(state, false);
  }
  ImGui::EndDisabled();

  const bool can_unknown =
      connected && has_pid && !client_async_busy(state) &&
      payload_supports(state, MEMDBG_CAP_SCAN_UNKNOWN);
  ImGui::BeginDisabled(!can_unknown);
  if (mobile_action_button(std::string(icons::kSearch) +
                               "  Unknown value baseline",
                           false)) {
    mobile_start_process_scan(state, true);
  }
  ImGui::EndDisabled();

  if (state.scan_async_pending) {
    ui::draw_scan_progress(state.scan_async_label, icons::kSearch,
                           ImGui::GetTime() - state.scan_async_start_time,
                           ImGui::GetContentRegionAvail().x);
  }

  draw_mobile_section_label("Refine");
  const bool can_refine =
      connected && has_pid && !client_async_busy(state) &&
      payload_supports(state, MEMDBG_CAP_MEMORY_READ) &&
      !state.scan_snapshot.empty();
  ImGui::BeginDisabled(!can_refine);
  if (mobile_action_button("Changed", false))
    mobile_refine_scan(state, RefineMode::Changed);
  if (mobile_action_button("Unchanged", false))
    mobile_refine_scan(state, RefineMode::Unchanged);
  if (mobile_action_button("Increased", false))
    mobile_refine_scan(state, RefineMode::Increased);
  if (mobile_action_button("Decreased", false))
    mobile_refine_scan(state, RefineMode::Decreased);
  if (mobile_action_button(std::string(icons::kRefresh) +
                               "  Refresh baseline",
                           false)) {
    mobile_refresh_scan_snapshot(state);
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Results");
  if (state.scan_result.addresses.empty()) {
    ImGui::TextColored(palette.dim, "%s", "No scan results");
  } else {
    if (mobile_action_button(std::string(icons::kCopy) + "  Copy all",
                             false)) {
      std::string all;
      all.reserve(state.scan_result.addresses.size() * 18U);
      for (uint64_t address : state.scan_result.addresses)
        all += hex_u64(address) + "\n";
      ImGui::SetClipboardText(all.c_str());
      set_status(state, "Copied scan results");
    }

    if (mobile_action_button(std::string(icons::kAdd) +
                                 "  First hit to trainer",
                             false)) {
      const std::string address = hex_u64(state.scan_result.addresses.front());
      std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                    address.c_str());
      state.cheat_type = state.scan_type;
      state.screen = Screen::Trainer;
    }

    const size_t limit =
        std::min<size_t>(state.scan_result.addresses.size(), 80U);
    for (size_t i = 0; i < limit; ++i) {
      const uint64_t address = state.scan_result.addresses[i];
      const ScanSnapshotEntry *snap = mobile_snapshot_for(state, address);
      const float card_h = 66.0f * scl;
      ImGui::PushID(static_cast<int>(i));
      ImGui::BeginChild("MobileScanHit", ImVec2(0, card_h), true,
                        ImGuiWindowFlags_NoScrollbar);
      const std::string addr = hex_u64(address);
      if (ImGui::Selectable(addr.c_str(), false,
                            ImGuiSelectableFlags_AllowDoubleClick)) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                      addr.c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s",
                      addr.c_str());
        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
          state.screen = Screen::Memory;
      }
      ImGui::TextColored(
          palette.dim, "%s",
          snap != nullptr
              ? mobile_scan_value_text(state.scan_snapshot_type, snap->bytes)
                    .c_str()
              : "value not captured");
      ImGui::SameLine(ImGui::GetWindowWidth() - 86.0f * scl);
      if (ImGui::SmallButton("Use")) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                      addr.c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s",
                      addr.c_str());
        std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                      addr.c_str());
      }
      ImGui::EndChild();
      ImGui::PopID();
    }
    if (state.scan_result.addresses.size() > limit) {
      ImGui::TextColored(palette.dim, "%zu more results hidden on mobile",
                         state.scan_result.addresses.size() - limit);
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static bool mobile_validate_writable_address(AppState &state, int32_t pid,
                                             uint64_t address, size_t length,
                                             std::string &error) {
  if (length == 0U) return true;
  const uint64_t byte_length = static_cast<uint64_t>(length);
  if (address > UINT64_MAX - byte_length) {
    error = "Trainer address range overflows";
    return false;
  }

  std::vector<MapEntry> fetched_maps;
  const std::vector<MapEntry> *maps = nullptr;
  if (pid == state.selected_pid && !state.maps.empty()) {
    maps = &state.maps;
  } else if (state.client.connected()) {
    if (state.client.process_maps(pid, fetched_maps)) maps = &fetched_maps;
  }
  if (maps == nullptr || maps->empty()) return true;

  const uint64_t end = address + byte_length;
  for (const auto &map : *maps) {
    if (address < map.start || end > map.end) continue;
    if ((map.protection & 2U) == 0U) {
      error = "Address " + hex_u64(address) + " is not writable";
      if (!map.name.empty()) error += ": " + map.name;
      return false;
    }
    return true;
  }

  error = "Address " + hex_u64(address) + " is outside known maps";
  return false;
}

static bool mobile_apply_cheat(AppState &state, CheatEntry &cheat) {
  if (!state.client.connected()) {
    cheat.status = "No console session";
    return false;
  }
  const int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0) {
    cheat.status = "No target PID";
    return false;
  }
  if (cheat.bytes.empty()) {
    cheat.status = "Empty value";
    return false;
  }

  std::string validation_error;
  if (!mobile_validate_writable_address(state, pid, cheat.address,
                                        cheat.bytes.size(),
                                        validation_error)) {
    cheat.status = validation_error;
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

static bool mobile_deactivate_cheat(AppState &state, CheatEntry &cheat) {
  if (!cheat.has_off_bytes || cheat.off_bytes.empty()) {
    cheat.status = "No OFF value captured";
    return false;
  }
  if (!state.client.connected()) {
    cheat.status = "No console session";
    return false;
  }
  const int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0) {
    cheat.status = "No target PID";
    return false;
  }

  std::string validation_error;
  if (!mobile_validate_writable_address(state, pid, cheat.address,
                                        cheat.off_bytes.size(),
                                        validation_error)) {
    cheat.status = validation_error;
    return false;
  }

  uint32_t written = 0;
  if (!state.client.memory_write(pid, cheat.address, cheat.off_bytes,
                                 written)) {
    cheat.status = state.client.last_error();
    return false;
  }
  cheat.active = false;
  cheat.status = "Restored " + std::to_string(written) + " bytes";
  return true;
}

static void mobile_add_cheat_from_fields(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before adding a trainer entry");
    return;
  }
  if (client_async_busy(state)) {
    set_status(state, "Wait for the active operation to finish");
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
  if (state.client.connected()) (void)capture_off_value(state, cheat);
  state.cheats.push_back(std::move(cheat));
  set_status(state, "Trainer entry added");
}

static void mobile_apply_enabled_cheats(AppState &state) {
  int applied = 0;
  for (auto &cheat : state.cheats)
    if (cheat.enabled && mobile_apply_cheat(state, cheat)) applied++;
  const std::string message =
      "Applied " + std::to_string(applied) + " trainer entries";
  set_status(state, message);
  push_notification(state, message);
}

static void mobile_import_batchcode(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before importing batchcode");
    return;
  }
  std::string error;
  std::vector<BatchcodeEntry> entries;
  const int imported = parse_batchcode(state.batchcode_text, entries, error);
  if (imported < 0) {
    set_status(state, "Batchcode error: " + error);
    return;
  }
  for (size_t i = 0; i < entries.size(); ++i) {
    CheatEntry cheat;
    cheat.description = "Batchcode " + std::to_string(i + 1U);
    cheat.pid = state.selected_pid;
    cheat.address = entries[i].offset;
    cheat.value_type = MEMDBG_VALUE_BYTES;
    cheat.value_text = bytes_to_hex(entries[i].bytes);
    cheat.bytes = std::move(entries[i].bytes);
    cheat.enabled = true;
    if (state.client.connected()) (void)capture_off_value(state, cheat);
    state.cheats.push_back(std::move(cheat));
  }
  set_status(state, "Imported " + std::to_string(imported) +
                        " batchcode entries");
}

static void draw_mobile_trainer(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const bool has_pid = state.selected_pid > 0;

  ImGui::BeginChild("MobileTrainer", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "Trainer");
  ImGui::SameLine();
  ui::status_dot(connected && has_pid ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(palette.muted, "%s", selected_process_name(state).c_str());

  ImGui::BeginChild("MobileTrainerSummary", ImVec2(0, 96.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  has_pid ? palette.text : palette.dim);
  mobile_info_row("Entries", std::to_string(state.cheats.size()),
                  state.cheats.empty() ? palette.muted : palette.success);
  mobile_info_row("File", state.trainer_file_path, palette.dim);
  ImGui::EndChild();

  draw_mobile_section_label("Cheat builder");
  ImGui::BeginDisabled(!has_pid);
  if (mobile_action_button("Use memory address", false)) {
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                  state.write_address);
  }
  ImGui::BeginDisabled(state.scan_result.addresses.empty());
  if (mobile_action_button("Use first scan hit", false)) {
    const std::string address = hex_u64(state.scan_result.addresses.front());
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s",
                  address.c_str());
  }
  ImGui::EndDisabled();
  ImGui::EndDisabled();

  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Name##MobileCheatName", "Cheat name",
                           state.cheat_description,
                           sizeof(state.cheat_description));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Address##MobileCheatAddress", "0x0",
                           state.cheat_address, sizeof(state.cheat_address));
  mobile_value_type_combo("Value type##MobileCheatType", &state.cheat_type);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Value##MobileCheatValue", "0",
                           state.cheat_value, sizeof(state.cheat_value));
  ImGui::Checkbox("Lock on apply", &state.cheat_lock);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::SliderFloat("Lock interval##MobileCheatLockInterval",
                     &state.cheat_lock_interval, 0.10f, 5.0f, "%.2fs");

  ImGui::BeginDisabled(!connected || !has_pid || client_async_busy(state));
  if (mobile_action_button(std::string(icons::kAdd) + "  Add entry", true))
    mobile_add_cheat_from_fields(state);
  ImGui::EndDisabled();

  draw_mobile_section_label("Trainer file");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Path##MobileTrainerPath", "trainers/session.cht",
                           state.trainer_file_path,
                           sizeof(state.trainer_file_path));
  if (mobile_action_button(std::string(icons::kLoad) + "  Load", false)) {
    const int count = load_trainer_file(state, state.trainer_file_path);
    if (count >= 0)
      set_status(state, "Loaded " + std::to_string(count) +
                            " trainer entries");
  }
  if (mobile_action_button(std::string(icons::kSave) + "  Save", false))
    save_trainer_file(state, state.trainer_file_path);

  if (ImGui::CollapsingHeader("Batchcode import")) {
    ImGui::InputTextMultiline("##MobileBatchcode", state.batchcode_text,
                              sizeof(state.batchcode_text),
                              ImVec2(-1.0f, 112.0f * scl));
    ImGui::BeginDisabled(!has_pid);
    if (mobile_action_button(std::string(icons::kImport) + "  Import",
                             false)) {
      mobile_import_batchcode(state);
    }
    ImGui::EndDisabled();
  }

  draw_mobile_section_label("Runtime list");
  if (state.cheats.empty()) {
    ImGui::TextColored(palette.dim, "%s", "No trainer entries");
  } else {
    ImGui::BeginDisabled(!connected || client_async_busy(state));
    if (mobile_action_button(std::string(icons::kPlay) + "  Apply enabled",
                             true)) {
      mobile_apply_enabled_cheats(state);
    }
    ImGui::EndDisabled();
    if (mobile_action_button(std::string(icons::kTrash) +
                                 "  Clear disabled",
                             false)) {
      state.cheats.erase(
          std::remove_if(state.cheats.begin(), state.cheats.end(),
                         [](const CheatEntry &cheat) {
                           return !cheat.enabled;
                         }),
          state.cheats.end());
      set_status(state, "Disabled trainer entries cleared");
    }

    size_t remove_index = std::numeric_limits<size_t>::max();
    for (size_t i = 0; i < state.cheats.size(); ++i) {
      CheatEntry &cheat = state.cheats[i];
      ImGui::PushID(static_cast<int>(i));
      ImGui::BeginChild("MobileTrainerCheatCard", ImVec2(0, 152.0f * scl),
                        true, ImGuiWindowFlags_NoScrollbar);
      ImGui::Checkbox("##enabled", &cheat.enabled);
      ImGui::SameLine();
      text_ellipsis(cheat.description.c_str(),
                    ImGui::GetContentRegionAvail().x, palette.text);
      ImGui::TextColored(palette.dim, "%s | %s | PID %d",
                         hex_u64(cheat.address).c_str(),
                         value_type_name(cheat.value_type), cheat.pid);
      text_ellipsis(("Value " + cheat.value_text).c_str(),
                    ImGui::GetContentRegionAvail().x, palette.muted);
      ImGui::Checkbox("Lock", &cheat.locked);
      ImGui::SameLine();
      ImGui::TextColored(cheat.active ? palette.success : palette.dim, "%s",
                         cheat.active ? "Active" : "Idle");

      const float gap = 6.0f * scl;
      const float button_w =
          (ImGui::GetContentRegionAvail().x - gap * 3.0f) / 4.0f;
      ImGui::BeginDisabled(!connected || client_async_busy(state));
      if (ui::primary_button("ON", ImVec2(button_w, 34.0f * scl))) {
        if (mobile_apply_cheat(state, cheat)) set_status(state, cheat.status);
      }
      ImGui::SameLine(0, gap);
      ImGui::BeginDisabled(!cheat.has_off_bytes);
      if (ui::soft_button("OFF", ImVec2(button_w, 34.0f * scl))) {
        if (mobile_deactivate_cheat(state, cheat))
          set_status(state, cheat.status);
      }
      ImGui::EndDisabled();
      ImGui::SameLine(0, gap);
      if (ui::soft_button("CAP", ImVec2(button_w, 34.0f * scl))) {
        if (capture_off_value(state, cheat)) set_status(state, cheat.status);
      }
      ImGui::EndDisabled();
      ImGui::SameLine(0, gap);
      if (ui::danger_button("DEL", ImVec2(button_w, 34.0f * scl)))
        remove_index = i;

      if (!cheat.status.empty())
        text_ellipsis(cheat.status.c_str(), ImGui::GetContentRegionAvail().x,
                      palette.dim);
      ImGui::EndChild();
      ImGui::PopID();
    }
    if (remove_index != std::numeric_limits<size_t>::max() &&
        remove_index < state.cheats.size()) {
      state.cheats.erase(state.cheats.begin() +
                         static_cast<std::ptrdiff_t>(remove_index));
      set_status(state, "Trainer entry removed");
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static void draw_mobile_credits(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  ImGui::BeginChild("MobileCredits", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "MemDBG");
  ImGui::TextColored(palette.muted, "%s",
                     "PlayStation Memory Debugger");

  ImGui::BeginChild("MobileCreditsCard", ImVec2(0, 132.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Version", std::string("v") + MEMDBG_VERSION_STRING,
                  palette.text);
  mobile_info_row("Creator", "Seregon (@seregonwar)", palette.text);
  mobile_info_row("License", "GNU GPL v3.0 or later", palette.muted);
  mobile_info_row("Profile",
                  state.github_profile.error.empty()
                      ? state.github_profile.login
                      : state.github_profile.error,
                  state.github_profile.error.empty() ? palette.link
                                                     : palette.warning);
  ImGui::EndChild();

  if (mobile_action_button(std::string(icons::kLink) + "  GitHub", false))
    set_status(state, "GitHub profile: https://github.com/seregonwar");
  if (mobile_action_button(std::string(icons::kCredits) + "  Donations",
                           false))
    set_status(state, "Donations link is available in the desktop credits");
  if (mobile_action_button("X / SeregonWar", false))
    set_status(state, "X profile: SeregonWar");
  if (mobile_action_button("Bluesky", false))
    set_status(state, "Bluesky profile selected");

  draw_mobile_section_label("Project");
  ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                         ImGui::GetContentRegionAvail().x);
  ImGui::TextWrapped(
      "%s",
      "MemDBG combines memory scanning, remote debugging, trainer workflows, "
      "plugins, UDP logs, telemetry, and console session tools for PS4 and "
      "PS5 homebrew research.");
  ImGui::PopTextWrapPos();
  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static void draw_mobile_fallback(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  ImGui::BeginChild("MobileFallback", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", screen_title(state.screen));
  ImGui::TextWrapped("%s", screen_subtitle(state.screen));
  ImGui::Spacing();
  ImGui::BeginChild("MobileFallbackCard", ImVec2(0, 150.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Session",
                  state.client.connected() ? "Connected" : "Offline",
                  state.client.connected() ? palette.success : palette.dim);
  mobile_info_row("Process", selected_process_name(state),
                  state.selected_pid > 0 ? palette.text : palette.dim);
  mobile_info_row("Status", state.status, palette.muted);
  ImGui::EndChild();

  if (mobile_action_button(std::string(icons::kConsole) + "  Console",
                           false))
    state.screen = Screen::Consoles;
  if (mobile_action_button(std::string(icons::kScanner) + "  Scanner",
                           false))
    state.screen = Screen::Scanner;
  if (mobile_action_button(std::string(icons::kTrainer) + "  Trainer",
                           false))
    state.screen = Screen::Trainer;
  if (mobile_action_button(std::string(icons::kPlugins) + "  Plugins",
                           false))
    state.screen = Screen::Plugins;

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

static void draw_mobile_processes(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const ImVec4 selected_bg(32.0f / 255.0f, 58.0f / 255.0f,
                           45.0f / 255.0f, 1.0f);

  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(12.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::BeginChild("MobileProcesses", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);

  ImGui::TextColored(palette.primary2, "%s", "Processes");
  ImGui::SameLine();
  ui::status_dot(connected ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(connected ? palette.muted : palette.danger, "%s",
                     connected ? "Select a target PID" : "Offline");

  ImGui::BeginChild("MobileProcessSummary", ImVec2(0, 154.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Session", connected ? "Connected" : "Offline",
                  connected ? palette.success : palette.dim);
  mobile_info_row("Process", selected_process_name(state),
                  state.selected_pid > 0 ? palette.text : palette.dim);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  state.selected_pid > 0 ? palette.text : palette.dim);
  mobile_info_row("Maps", std::to_string(state.maps.size()),
                  state.maps.empty() ? palette.dim : palette.text);
  ImGui::Separator();
  text_ellipsis(state.status, ImGui::GetContentRegionAvail().x, palette.muted);
  ImGui::EndChild();

  if (!connected) {
    if (mobile_action_button(std::string(icons::kConsole) +
                                 "  Configure console",
                             true))
      state.screen = Screen::Consoles;
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    return;
  }

  ImGui::BeginDisabled(client_async_busy(state));
  if (mobile_action_button(std::string(icons::kRefresh) +
                               "  Refresh processes",
                           state.processes.empty()))
    topbar_refresh_processes(state);
  ImGui::EndDisabled();

  ImGui::BeginDisabled(client_async_busy(state) || state.selected_pid <= 0);
  if (mobile_action_button(std::string(icons::kMemory) + "  Load maps",
                           state.maps.empty()))
    topbar_refresh_maps(state);
  ImGui::EndDisabled();

  if (state.selected_pid > 0) {
    ImGui::BeginChild("MobileProcessQuickActions", ImVec2(0, 96.0f * scl),
                      true, ImGuiWindowFlags_NoScrollbar);
    if (ImGui::BeginTable("MobileProcessQuickActionTable", 2,
                          ImGuiTableFlags_SizingStretchSame)) {
      ImGui::TableNextColumn();
      if (mobile_action_button(std::string(icons::kScanner) + "  Scanner",
                               false))
        state.screen = Screen::Scanner;
      ImGui::TableNextColumn();
      if (mobile_action_button(std::string(icons::kTrainer) + "  Trainer",
                               false))
        state.screen = Screen::Trainer;
      ImGui::EndTable();
    }
    ImGui::EndChild();
  }

  draw_mobile_section_label("Process list");
  if (state.processes.empty()) {
    ImGui::BeginChild("MobileNoProcesses", ImVec2(0, 92.0f * scl), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextColored(palette.muted, "%s", "No processes loaded");
    ImGui::TextWrapped("%s",
                       "Refresh the process list after connecting a console.");
    ImGui::EndChild();
  } else {
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const ProcessEntry &process = state.processes[i];
      const bool selected = process.pid == state.selected_pid;
      ImGui::PushID(i);
      ImGui::PushStyleColor(ImGuiCol_ChildBg,
                            selected ? selected_bg : palette.bg1);
      ImGui::BeginChild("MobileProcessCard", ImVec2(0, 66.0f * scl), true,
                        ImGuiWindowFlags_NoScrollbar);
      const ImVec2 text_pos = ImGui::GetCursorScreenPos();
      const ImVec2 hit_size(ImGui::GetContentRegionAvail().x, 48.0f * scl);
      ImGui::InvisibleButton("##select_process", hit_size);
      const bool clicked = ImGui::IsItemClicked();
      if (selected) {
        ImDrawList *dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(text_pos,
                          ImVec2(text_pos.x + 3.0f * scl,
                                 text_pos.y + hit_size.y),
                          ui::color_u32(palette.primary2), 2.0f * scl);
      }
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y));
      const std::string process_name =
          process.name.empty() ? "unnamed" : process.name;
      text_ellipsis(process_name.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.text);
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y + 24.0f * scl));
      ImGui::TextColored(selected ? palette.primary2 : palette.muted,
                         "PID %d", process.pid);
      ImGui::EndChild();
      ImGui::PopStyleColor();
      ImGui::PopID();
      if (clicked) topbar_select_process(state, i);
    }
  }

  draw_mobile_section_label("Memory maps");
  if (state.selected_pid <= 0) {
    ImGui::BeginChild("MobileMapsNoProcess", ImVec2(0, 86.0f * scl), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextColored(palette.muted, "%s", "Select a process first");
    ImGui::TextWrapped("%s",
                       "Maps become scan ranges and trainer safety checks.");
    ImGui::EndChild();
  } else if (state.maps.empty()) {
    ImGui::BeginChild("MobileNoMaps", ImVec2(0, 86.0f * scl), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextColored(palette.muted, "%s", "No maps loaded");
    ImGui::TextWrapped("%s",
                       "Load maps to pick a touch-friendly scan range.");
    ImGui::EndChild();
  } else {
    for (int i = 0; i < static_cast<int>(state.maps.size()); ++i) {
      const MapEntry &map = state.maps[i];
      const bool selected = i == state.selected_map_row;
      const uint64_t size_bytes = map.end > map.start ? map.end - map.start : 0;
      ImGui::PushID(10000 + i);
      ImGui::PushStyleColor(ImGuiCol_ChildBg,
                            selected ? selected_bg : palette.bg1);
      ImGui::BeginChild("MobileMapCard", ImVec2(0, 76.0f * scl), true,
                        ImGuiWindowFlags_NoScrollbar);
      const ImVec2 text_pos = ImGui::GetCursorScreenPos();
      const ImVec2 hit_size(ImGui::GetContentRegionAvail().x, 58.0f * scl);
      ImGui::InvisibleButton("##select_map", hit_size);
      const bool clicked = ImGui::IsItemClicked();
      if (selected) {
        ImDrawList *dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(text_pos,
                          ImVec2(text_pos.x + 3.0f * scl,
                                 text_pos.y + hit_size.y),
                          ui::color_u32(palette.primary2), 2.0f * scl);
      }
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y));
      const std::string title = hex_u64(map.start) + "  " +
                                prot_text(map.protection) + "  " +
                                mobile_format_bytes(size_bytes);
      text_ellipsis(title.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.text);
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y + 25.0f * scl));
      const std::string map_name =
          map.name.empty() ? "anonymous mapping" : map.name;
      text_ellipsis(map_name.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.muted);
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y + 47.0f * scl));
      const std::string map_end = hex_u64(map.end);
      text_ellipsis(map_end.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.dim);
      ImGui::EndChild();
      ImGui::PopStyleColor();
      ImGui::PopID();
      if (clicked) mobile_select_map(state, i);
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
  ImGui::PopStyleVar(2);
}

static void draw_mobile_session(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();

  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(12.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::BeginChild("MobileSession", size, false);

  ImGui::TextColored(palette.primary2, "%s", "Session");
  ImGui::SameLine();
  ui::status_dot(state.connect_pending ? palette.warning :
                 connected ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(state.connect_pending ? palette.warning :
                     connected ? palette.success : palette.danger,
                     "%s", state.connect_pending ? "Connecting" :
                          connected ? "Connected" : "Not connected");

  ImGui::Spacing();
  ImGui::BeginChild("MobileSessionCard", ImVec2(0, 154.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  char endpoint[96];
  std::snprintf(endpoint, sizeof(endpoint), "%s:%d", state.host,
                state.debug_port);
  mobile_info_row("Endpoint", endpoint,
                  connected ? palette.text : palette.muted);
  mobile_info_row("UDP", state.udp_listener.running() ? "Listening" : "Stopped",
                  state.udp_listener.running() ? palette.success : palette.dim);
  mobile_info_row("Process", selected_process_name(state),
                  state.selected_pid != 0 ? palette.text : palette.muted);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  state.selected_pid != 0 ? palette.text : palette.dim);
  ImGui::Separator();
  text_ellipsis(state.status, ImGui::GetContentRegionAvail().x, palette.muted);
  ImGui::EndChild();

  ImGui::BeginDisabled(client_async_busy(state) || state.connect_pending);
  if (connected) {
    if (ui::soft_button((std::string(icons::kGauge) + "  Ping").c_str(),
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               42.0f * scl))) {
      set_status(state, state.client.ping() ? "Ping OK"
                                            : state.client.last_error());
    }
    if (ui::danger_button((std::string(icons::kDisconnect) +
                           "  Disconnect").c_str(),
                          ImVec2(ImGui::GetContentRegionAvail().x,
                                 42.0f * scl))) {
      disconnect_console(state);
    }
  } else {
    if (ui::primary_button((std::string(icons::kConsole) +
                            "  Configure console").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  44.0f * scl))) {
      state.screen = Screen::Consoles;
    }
    if (ui::soft_button((std::string(icons::kConnect) +
                         "  Connect").c_str(),
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               42.0f * scl))) {
      connect_console(state);
    }
  }
  ImGui::EndDisabled();

  ImGui::Spacing();
  ImGui::TextColored(palette.muted, "%s", "Workflows");
  if (mobile_nav_button("MobileNavConsole", icons::kConsole, "Console", true))
    state.screen = Screen::Consoles;
  if (mobile_nav_button("MobileNavProcesses", icons::kProcess, "Processes",
                        connected))
    state.screen = Screen::Processes;
  if (mobile_nav_button("MobileNavScanner", icons::kScanner, "Scanner",
                        connected))
    state.screen = Screen::Scanner;
  if (mobile_nav_button("MobileNavTrainer", icons::kTrainer, "Trainer",
                        connected))
    state.screen = Screen::Trainer;
  if (mobile_nav_button("MobileNavPlugins", icons::kPlugins, "Plugins", true))
    state.screen = Screen::Plugins;
  if (mobile_nav_button("MobileNavLogs", icons::kLogs, "Logs", true))
    state.screen = Screen::Logs;

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
}

static void draw_mobile_top_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(10.0f * ui::dpi_scale(), 6.0f * ui::dpi_scale()));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(6.0f * ui::dpi_scale(), 0));
  ImGui::BeginChild("MobileTopBar", size, true, ImGuiWindowFlags_NoScrollbar);

  const float scl = ui::dpi_scale();
  const float topbar_w = ImGui::GetWindowWidth();
  const float bar_h = size.y;
  const bool connected = state.client.connected();

  ImGui::SetCursorPosY((bar_h - ImGui::GetFontSize()) * 0.5f);
  ImGui::TextColored(ui::colors().primary2, "%s", "MemDBG");
  ImGui::SameLine();
  ui::status_dot(state.connect_pending ? ui::colors().warning :
                 connected ? ui::colors().success : ui::colors().dim);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().muted, "%s",
                     connected ? "Online" : "Offline");

  const float btn_h = std::max(34.0f * scl, bar_h - 12.0f * scl);
  const float btn_w = connected ? btn_h : std::min(126.0f * scl,
                                                   topbar_w * 0.38f);
  ImGui::SetCursorPos(ImVec2(topbar_w - btn_w - 8.0f * scl,
                             (bar_h - btn_h) * 0.5f));
  ImGui::BeginDisabled(client_async_busy(state));
  if (connected) {
    if (ui::danger_button((std::string(icons::kDisconnect)).c_str(),
                          ImVec2(btn_w, btn_h))) {
      disconnect_console(state);
    }
  } else {
    if (ui::primary_button((std::string(icons::kConsole) +
                            "  Setup").c_str(),
                           ImVec2(btn_w, btn_h))) {
      state.screen = Screen::Consoles;
    }
  }
  ImGui::EndDisabled();

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

static void draw_mobile_tools_sheet(AppState &state, ImVec2 tab_pos,
                                    ImVec2 tab_size) {
  if (!s_mobile_tools_open) return;

  const float scl = ui::dpi_scale();
  ImGuiViewport *viewport = ImGui::GetMainViewport();
  const float safe_top = viewport->WorkPos.y + s_mobile_safe_area.top;
  const float max_h = std::max(220.0f * scl, tab_pos.y - safe_top - 12.0f * scl);
  const float sheet_h = std::min(430.0f * scl, max_h);
  const ImVec2 pos(tab_pos.x + 8.0f * scl,
                   std::max(safe_top + 8.0f * scl,
                            tab_pos.y - sheet_h - 8.0f * scl));
  const ImVec2 size(std::max(220.0f * scl, tab_size.x - 16.0f * scl),
                    sheet_h);

  ImGui::SetNextWindowPos(pos);
  ImGui::SetNextWindowSize(size);
  ImGui::PushStyleColor(ImGuiCol_WindowBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(10.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 6.0f * scl);
  ImGui::Begin("##MobileToolSheet", &s_mobile_tools_open,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                   ImGuiWindowFlags_NoSavedSettings |
                   ImGuiWindowFlags_NoResize);

  ImGui::TextColored(ui::colors().primary2, "%s  Tools", icons::kMore);
  ImGui::SameLine(ImGui::GetWindowWidth() - 72.0f * scl);
  if (ui::soft_button("Close", ImVec2(62.0f * scl, 30.0f * scl)))
    s_mobile_tools_open = false;
  ImGui::Separator();

  struct ToolEntry {
    Screen screen;
    const char *icon;
    const char *label;
  };
  const ToolEntry tools[] = {
      {Screen::Home, icons::kHome, "Home"},
      {Screen::Consoles, icons::kConsole, "Console"},
      {Screen::Processes, icons::kProcess, "Processes"},
      {Screen::Scanner, icons::kScanner, "Scanner"},
      {Screen::Trainer, icons::kTrainer, "Trainer"},
      {Screen::Plugins, icons::kPlugins, "Plugins"},
      {Screen::Logs, icons::kLogs, "Logs"},
      {Screen::Credits, icons::kCredits, "Credits"},
  };

  if (ImGui::BeginTable("MobileToolGrid", 2,
                        ImGuiTableFlags_SizingStretchSame |
                            ImGuiTableFlags_PadOuterX)) {
    for (const ToolEntry &tool : tools) {
      ImGui::TableNextColumn();
      const bool selected = state.screen == tool.screen;
      std::string label = std::string(tool.icon) + "  " + tool.label;
      const bool clicked =
          selected ? ui::primary_button(label.c_str(),
                                        ImVec2(-1.0f, 44.0f * scl))
                   : ui::soft_button(label.c_str(),
                                     ImVec2(-1.0f, 44.0f * scl));
      if (clicked) {
        state.screen = tool.screen;
        s_mobile_tools_open = false;
      }
    }
    ImGui::EndTable();
  }

  ImGui::End();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

static void draw_bottom_tab_bar(AppState &state, ImVec2 pos, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
  ImGui::SetNextWindowPos(pos);
  ImGui::SetNextWindowSize(size);
  ImGui::Begin("##MobileTabBar", nullptr,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
               ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar |
               ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

  const float tab_w = size.x / 6.0f;
  const float tab_h = size.y;

  struct TabEntry {
    Screen screen;
    const char *icon;
  };
  static const TabEntry tabs[] = {
    { Screen::Home,     icons::kHome },
    { Screen::Consoles, icons::kConsole },
    { Screen::Processes, icons::kProcess },
    { Screen::Scanner,  icons::kScanner },
    { Screen::Trainer,  icons::kTrainer },
  };

  ImDrawList *dl = ImGui::GetWindowDrawList();

  for (int i = 0; i < 5; ++i) {
    const ImVec2 tab_min(pos.x + tab_w * i, pos.y);
    const ImVec2 tab_max(pos.x + tab_w * (i + 1), pos.y + tab_h);
    const bool selected = state.screen == tabs[i].screen;

    /* Background for selected tab */
    if (selected) {
      ImVec4 bg(32.0f/255.0f, 58.0f/255.0f, 45.0f/255.0f, 1.0f);
      dl->AddRectFilled(tab_min, tab_max, ui::color_u32(bg));
      /* Top accent line */
      dl->AddRectFilled(ImVec2(tab_min.x + 8.0f, tab_min.y),
                        ImVec2(tab_max.x - 8.0f, tab_min.y + 2.0f),
                        ui::color_u32(ui::colors().primary2), 1.0f);
    }

    /* Icon centered */
    const ImVec4 icon_col = selected ? ui::colors().primary2 : ui::colors().muted;
    const ImVec2 icon_size = ImGui::CalcTextSize(tabs[i].icon);
    const float icon_x = tab_min.x + (tab_w - icon_size.x) * 0.5f;
    const float icon_y = tab_min.y + (tab_h - icon_size.y) * 0.5f;
    dl->AddText(ImVec2(icon_x, icon_y), ui::color_u32(icon_col), tabs[i].icon);

    /* Hit target */
    ImGui::SetCursorPos(ImVec2(tab_w * i, 0));
    ImGui::InvisibleButton(("##tab" + std::to_string(i)).c_str(), ImVec2(tab_w, tab_h));
    if (ImGui::IsItemClicked()) state.screen = tabs[i].screen;
  }

  /* 6th tab: overflow menu */
  {
    const ImVec2 tab_min(pos.x + tab_w * 5, pos.y);
    const ImVec2 tab_max(pos.x + tab_w * 6, pos.y + tab_h);
    const bool is_overflow_active =
        state.screen == Screen::Plugins || state.screen == Screen::Logs ||
        state.screen == Screen::Credits || state.screen == Screen::PluginGUI ||
        state.screen == Screen::Klog;

    if (is_overflow_active) {
      ImVec4 bg(32.0f/255.0f, 58.0f/255.0f, 45.0f/255.0f, 1.0f);
      dl->AddRectFilled(tab_min, tab_max, ui::color_u32(bg));
      dl->AddRectFilled(ImVec2(tab_min.x + 8.0f, tab_min.y),
                        ImVec2(tab_max.x - 8.0f, tab_min.y + 2.0f),
                        ui::color_u32(ui::colors().primary2), 1.0f);
    }

    const ImVec4 icon_col = is_overflow_active ? ui::colors().primary2 : ui::colors().muted;
    const ImVec2 icon_size = ImGui::CalcTextSize(icons::kMore);
    const float icon_x = tab_min.x + (tab_w - icon_size.x) * 0.5f;
    const float icon_y = tab_min.y + (tab_h - icon_size.y) * 0.5f;
    dl->AddText(ImVec2(icon_x, icon_y), ui::color_u32(icon_col), icons::kMore);

    ImGui::SetCursorPos(ImVec2(tab_w * 5, 0));
    if (ImGui::InvisibleButton("##tab_more", ImVec2(tab_w, tab_h))) {
      s_mobile_tools_open = !s_mobile_tools_open;
    }
  }

  ImGui::End();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
  draw_mobile_tools_sheet(state, pos, size);
}

static void draw_mobile_status_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(10.0f * ui::dpi_scale(), 3.0f * ui::dpi_scale()));
  ImGui::BeginChild("MobileStatusBar", size, true, ImGuiWindowFlags_NoScrollbar);

  const bool connected = state.client.connected();
  ui::status_dot(connected ? ui::colors().success : ui::colors().muted);
  ImGui::SameLine();

  float avail_w = ImGui::GetWindowWidth() - 28.0f * ui::dpi_scale();
  if (avail_w < 60.0f) avail_w = 60.0f;
  text_ellipsis(state.status, avail_w, ui::colors().text);

  ImGui::EndChild();
  ImGui::PopStyleVar();
  ImGui::PopStyleColor();
}

static void draw_mobile_content(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                      ImVec2(10.0f * scl, 8.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ScrollbarSize, 18.0f * scl);

  if (state.screen == Screen::Home) {
    draw_mobile_session(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Consoles) {
    draw_mobile_network(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Processes) {
    draw_mobile_processes(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Plugins || state.screen == Screen::PluginGUI) {
    draw_mobile_plugins(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Logs) {
    draw_mobile_logs(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Scanner) {
    draw_mobile_scanner(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Trainer) {
    draw_mobile_trainer(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Credits) {
    draw_mobile_credits(state, size);
    ImGui::PopStyleVar(3);
    return;
  }
  if (state.screen == Screen::Klog) {
    draw_klog(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  draw_mobile_fallback(state, size);
  ImGui::PopStyleVar(3);
}

} // namespace

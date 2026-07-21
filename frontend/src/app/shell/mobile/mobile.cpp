/*
 * MemDBG - Mobile (iOS/Android) layout and screens: network, logs, processes, scanner,
 *          trainer, plugins, credits, session, and fallback UI.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "../internal.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <cctype>
namespace memdbg::frontend {

MobileSafeArea s_mobile_safe_area;
bool s_mobile_tools_open = false;
void set_mobile_safe_area(float l,float t,float r,float b) { s_mobile_safe_area.left=std::max(0.0f,l); s_mobile_safe_area.top=std::max(0.0f,t); s_mobile_safe_area.right=std::max(0.0f,r); s_mobile_safe_area.bottom=std::max(0.0f,b); }
void mobile_info_row(const char *label, const std::string &value,
                     ImVec4 value_color) {
  const float scl = ui::dpi_scale();
  const float label_w = 92.0f * scl;
  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::SameLine(label_w);
  text_ellipsis(value.c_str(), ImGui::GetContentRegionAvail().x, value_color);
}

bool mobile_nav_button(const char *id, const char *icon,
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

std::string mobile_target_endpoint(const ConsoleTarget &target) {
  return target.host + ":" + std::to_string(target.debug_port) +
         " / UDP " + std::to_string(target.udp_port) +
         " / ELF " + std::to_string(target.payload_port);
}

void mobile_persist_console_targets(AppState &state,
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

void mobile_use_discovered_console(AppState &state,
                                   const DiscoveryConsole &console) {
  const std::string name = !console.name.empty() ? console.name : console.ip;
  std::snprintf(state.target_name, sizeof(state.target_name), "%s",
                name.c_str());
  std::snprintf(state.host, sizeof(state.host), "%s", console.ip.c_str());
  state.debug_port = console.debug_port;
  if (console.udp_log_port != 0U) state.udp_port = console.udp_log_port;
  normalize_ports(state);
}

void poll_mobile_discovery(AppState &state) {
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

void start_mobile_discovery(AppState &state) {
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

void draw_mobile_section_label(const char *label) {
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", label);
}

bool mobile_action_button(const std::string &label, bool primary,
                          bool danger) {
  const float scl = ui::dpi_scale();
  const ImVec2 size(ImGui::GetContentRegionAvail().x, 42.0f * scl);
  if (danger) return ui::danger_button(label.c_str(), size);
  if (primary) return ui::primary_button(label.c_str(), size);
  return ui::soft_button(label.c_str(), size);
}

std::string mobile_format_bytes(uint64_t bytes) {
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

void mobile_select_map(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.maps.size())) return;
  const MapEntry &map = state.maps[row];
  state.selected_map_row = row;
  std::snprintf(state.mem.read_address, sizeof(state.mem.read_address), "%s",
                hex_u64(map.start).c_str());
  std::snprintf(state.mem.write_address, sizeof(state.mem.write_address), "%s",
                hex_u64(map.start).c_str());
  std::snprintf(state.scan.start, sizeof(state.scan.start), "%s",
                hex_u64(map.start).c_str());
  std::snprintf(state.scan.length, sizeof(state.scan.length), "%s",
                hex_u64(map.end - map.start).c_str());
  set_status(state, "Selected map " + hex_u64(map.start) + " - " +
                        hex_u64(map.end));
}


void draw_mobile_logs(AppState &state, ImVec2 size) {
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


void draw_mobile_app(AppState &state) {
  poll_locale_repository(state);
  poll_connect(state);
  poll_payload_lifecycle(state);
  poll_taskmgr_prefetch(state);
  poll_telemetry(state);
  poll_map_refresh(state);
  poll_tracer(state);
  poll_plugin_tasks(state);
  poll_session_health(state);

  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);

  const ImGuiWindowFlags flags =
      ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoSavedSettings |
      ImGuiWindowFlags_NoBringToFrontOnFocus;
  ImGui::Begin("MemDBG Mobile", nullptr, flags);

  const ImVec2 win_pos = ImGui::GetWindowPos();
  const ImVec2 win_size = ImGui::GetWindowSize();
  ui::draw_background(ImGui::GetWindowDrawList(), win_pos, win_size);

  const float scl = ui::dpi_scale();
  const float left = s_mobile_safe_area.left;
  const float top = s_mobile_safe_area.top;
  const float right = s_mobile_safe_area.right;
  const float bottom = s_mobile_safe_area.bottom;
  const float layout_x = left;
  const float layout_w = std::max(240.0f * scl, win_size.x - left - right);
  const float top_h = 48.0f * scl;
  const float status_h = 26.0f * scl;
  const float tab_h = 54.0f * scl;
  const float gap = 6.0f * scl;
  const float content_pad = 8.0f * scl;
  const float bottom_edge = win_size.y - bottom;
  const float tab_y = bottom_edge - tab_h;
  const float status_y = tab_y - status_h;
  const float content_y = top + top_h + gap;
  const float content_h =
      std::max(120.0f * scl, status_y - content_y - gap);

  ImGui::SetCursorPos(ImVec2(layout_x, top));
  draw_mobile_top_bar(state, ImVec2(layout_w, top_h));

  ImGui::SetCursorPos(ImVec2(layout_x + content_pad, content_y));
  draw_mobile_content(
      state,
      ImVec2(std::max(120.0f * scl, layout_w - content_pad * 2.0f),
             content_h));

  ImGui::SetCursorPos(ImVec2(layout_x, status_y));
  draw_mobile_status_bar(state, ImVec2(layout_w, status_h));

  draw_bottom_tab_bar(state, ImVec2(win_pos.x + layout_x, win_pos.y + tab_y),
                      ImVec2(layout_w, tab_h));

  set_notification_bottom_reserved(bottom + tab_h + status_h + 8.0f * scl);
  draw_notifications(state);
  draw_connect_spinner(state);

  ImGui::End();
}

} // namespace

/*
 * MemDBG - Processes screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>

namespace memdbg::frontend {

/* ---- Map filter helpers ---- */
static bool map_passes_filters(const AppState &state, const MapEntry &map) {
  if (map.end <= map.start) return false;
  if (state.map_filter_readable && (map.protection & 1U) == 0U) return false;
  if (state.map_filter_writable && (map.protection & 2U) == 0U) return false;
  if (state.map_filter_executable && (map.protection & 4U) == 0U) return false;
  if (state.map_filter_hide_system && map_is_system_like(map)) return false;
  if (state.map_filter_min_kb > 0 && ((map.end - map.start)/1024U) < static_cast<uint64_t>(state.map_filter_min_kb))
    return false;
  std::string filter = lower_copy(trim_copy(state.map_filter));
  if (!filter.empty() && lower_copy(map.name).find(filter) == std::string::npos) return false;
  return true;
}

static size_t filtered_map_count(const AppState &state) {
  size_t count = 0;
  for (const auto &map : state.maps)
    if (map_passes_filters(state, map)) count++;
  return count;
}

static void set_scan_window_from_filtered_maps(AppState &state) {
  uint64_t start = UINT64_MAX;
  uint64_t end = 0;
  for (const auto &map : state.maps) {
    if (!map_passes_filters(state, map)) continue;
    start = std::min(start, map.start);
    end = std::max(end, map.end);
  }
  if (start == UINT64_MAX || end <= start) {
    set_status(state, "No filtered maps available");
    return;
  }
  std::snprintf(state.scan_start, sizeof(state.scan_start), "%s", hex_u64(start).c_str());
  std::snprintf(state.scan_end, sizeof(state.scan_end), "%s", hex_u64(end).c_str());
  set_status(state, "Process scan window set from filtered maps");
}

/* ---- Dump ---- */
static void dump_selected_map(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0 || state.selected_map_row < 0 ||
      state.selected_map_row >= static_cast<int>(state.maps.size())) {
    set_status(state, "Select a process map first"); return;
  }
  const MapEntry &map = state.maps[state.selected_map_row];
  if (map.end <= map.start) { set_status(state, "Selected map is empty"); return; }
  std::string default_name = "pid_" + std::to_string(state.selected_pid) + "_" +
                             hex_u64(map.start).substr(2) + ".bin";
  std::filesystem::path configured = trim_copy(state.dump_path);
  if (configured.empty()) configured = "dumps";

  std::filesystem::path out_path;
  const bool looks_like_file = configured.has_extension();
  if (looks_like_file) out_path = configured;
  else                 out_path = configured / default_name;

  std::filesystem::path dump_dir = out_path.parent_path();
  if (dump_dir.empty()) dump_dir = ".";
  std::error_code ec;
  std::filesystem::create_directories(dump_dir, ec);
  if (ec) { set_status(state, "Failed to create dumps directory"); return; }
  std::ofstream out(out_path, std::ios::binary);
  if (!out) { set_status(state, "Failed to open dump file"); return; }
  uint64_t address = map.start;
  uint64_t remaining = map.end - map.start;
  uint64_t written_total = 0;
  while (remaining != 0U) {
    uint32_t chunk = remaining > MEMDBG_PROTOCOL_MAX_READ ? MEMDBG_PROTOCOL_MAX_READ : static_cast<uint32_t>(remaining);
    std::vector<uint8_t> bytes;
    if (!state.client.memory_read(state.selected_pid, address, chunk, bytes)) {
      set_status(state, "Dump failed: " + state.client.last_error()); return;
    }
    if (bytes.empty()) break;
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out) { set_status(state, "Dump file write failed"); return; }
    address += bytes.size();
    remaining -= bytes.size();
    written_total += bytes.size();
  }
  set_status(state, "Dumped " + std::to_string(written_total) + " bytes to " + out_path.string());
  push_notification(state, "Map dumped to " + out_path.string(), 5.0);
}

/* ---- Process selection ---- */
static void select_process(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.processes.size())) return;
  state.selected_process_row = row;
  state.selected_pid = state.processes[row].pid;
  state.maps.clear();
  state.selected_map_row = -1;
  state.memory.clear();
  state.scan_result = ScanResult{};
  state.scan_snapshot.clear();
  state.scan_snapshot_value_len = 0;
  state.scan_is_unknown_session = false;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "Process changed");
  state.has_process_info = false;
  if (state.client.connected() && state.client.process_info(state.selected_pid, state.selected_process_info))
    state.has_process_info = true;
  set_status(state, "Selected PID " + std::to_string(state.selected_pid));
}

static void select_map(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.maps.size())) return;
  const auto &map = state.maps[row];
  state.selected_map_row = row;
  std::snprintf(state.read_address, sizeof(state.read_address), "%s", hex_u64(map.start).c_str());
  std::snprintf(state.write_address, sizeof(state.write_address), "%s", hex_u64(map.start).c_str());
  std::snprintf(state.scan_start, sizeof(state.scan_start), "%s", hex_u64(map.start).c_str());
  std::snprintf(state.scan_length, sizeof(state.scan_length), "%s", hex_u64(map.end - map.start).c_str());
  set_status(state, "Selected map " + hex_u64(map.start) + " - " + hex_u64(map.end));
}

static void refresh_processes(AppState &state) {
  if (!state.client.connected()) {
    set_status(state, "Connect a console before refreshing processes");
    push_notification(state, "Connect a console before loading processes", 4.0);
    return;
  }
  if (!state.client.process_list(state.processes)) {
    std::string error = state.client.last_error();
    if (error.empty()) error = "Process refresh failed";
    set_status(state, error);
    push_notification(state, "Process refresh failed: " + error, 5.0);
    return;
  }
  if (state.processes.empty()) {
    state.selected_pid = 0; state.selected_process_row = -1;
    state.has_process_info = false; state.maps.clear();
  }
  set_status(state, "Process list refreshed");
}

static void refresh_maps(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console before refreshing maps"); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); return; }
  if (!state.client.process_maps(state.selected_pid, state.maps)) { set_status(state, state.client.last_error()); return; }
  state.selected_map_row = -1;
  set_status(state, "Memory maps refreshed");
}

/* ---- Tables ---- */
static void draw_process_table(AppState &state) {
  if (ImGui::BeginTable("ProcessTable", 4,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable,
        ImVec2(0,0))) {
    ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 82);
    ImGui::TableSetupColumn("Name");
    ImGui::TableSetupColumn("Title ID", ImGuiTableColumnFlags_WidthFixed, 100);
    ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 78);
    ImGui::TableHeadersRow();
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const auto &process = state.processes[i];
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      bool selected = i == state.selected_process_row;
      std::string label = std::to_string(process.pid) + "##pid" + std::to_string(i);
      if (ImGui::Selectable(label.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
        select_process(state, i);
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(process.name.c_str());
      ImGui::TableSetColumnIndex(2);
      if (state.has_process_info && state.selected_pid == process.pid)
        ImGui::TextColored(ui::colors().primary2, "%s", state.selected_process_info.title_id.c_str());
      else
        ImGui::TextUnformatted("");
      ImGui::TableSetColumnIndex(3);
      ImGui::TextColored(selected ? ui::colors().primary2 : ui::colors().dim,
                         "%s", selected ? "Active" : "-");
    }
    ImGui::EndTable();
  }
}

static void draw_maps_table(AppState &state) {
  if (state.selected_pid <= 0) {
    ui::draw_empty_state("No process selected", "Select a process, then refresh maps to inspect memory ranges.");
    return;
  }
  if (ImGui::BeginTable("MapsTable", 5,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable,
        ImVec2(0,0))) {
    ImGui::TableSetupColumn("Start");
    ImGui::TableSetupColumn("End");
    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90);
    ImGui::TableSetupColumn("Prot", ImGuiTableColumnFlags_WidthFixed, 58);
    ImGui::TableSetupColumn("Name");
    ImGui::TableHeadersRow();
    for (int i = 0; i < static_cast<int>(state.maps.size()); ++i) {
      const auto &map = state.maps[i];
      if (!map_passes_filters(state, map)) continue;
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      bool selected = state.selected_map_row == i;
      std::string start = hex_u64(map.start);
      if (ImGui::Selectable((start + "##map" + std::to_string(i)).c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
        select_map(state, i);
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(hex_u64(map.end).c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::Text("%llu KB", static_cast<unsigned long long>((map.end - map.start) / 1024U));
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(prot_text(map.protection).c_str());
      ImGui::TableSetColumnIndex(4);
      ImGui::TextUnformatted(map.name.c_str());
    }
    ImGui::EndTable();
  }
}

/* ---- Main draw ---- */
void draw_processes(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float left_w = std::max(360.0f, (avail.x - gap) * 0.42f);

  ui::begin_panel("ProcessesPanel", "Console Processes", ImVec2(left_w, avail.y));
  if (!state.client.connected()) {
    if (ui::soft_button((std::string(icons::kRefresh) + "  Refresh Processes").c_str(), ImVec2(190, 38)))
      refresh_processes(state);
    ImGui::Spacing();
    ui::draw_empty_state("Connect a console", "Process enumeration is available after a payload session is open.");
  } else {
    if (ui::soft_button((std::string(icons::kRefresh) + "  Refresh Processes").c_str(), ImVec2(180, 38))) refresh_processes(state);
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, "%zu entries", state.processes.size());
    ImGui::Spacing();
    draw_process_table(state);
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("MapsPanel", "Memory Maps", ImVec2(0, avail.y));
  if (!state.client.connected()) {
    ui::draw_empty_state("Waiting for session", "Connect first, then choose a process to request maps.");
  } else {
    ImGui::Text("Active PID: %d", state.selected_pid);
    ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
    if (state.has_process_info) {
      if (!state.selected_process_info.title_id.empty())
        ImGui::TextColored(ui::colors().primary2, "Title ID: %s", state.selected_process_info.title_id.c_str());
      if (!state.selected_process_info.content_id.empty())
        ImGui::TextWrapped("Content ID: %s", state.selected_process_info.content_id.c_str());
      if (!state.selected_process_info.path.empty())
        ImGui::TextWrapped("Path: %s", state.selected_process_info.path.c_str());
    }
    ImGui::BeginDisabled(!state.client.connected() || state.selected_pid <= 0);
    if (ui::soft_button((std::string(icons::kRefresh) + "  Refresh Maps").c_str(), ImVec2(150, 38))) refresh_maps(state);
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kFilter) + "  Use Filtered Window").c_str(), ImVec2(185, 38))) set_scan_window_from_filtered_maps(state);
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kDump) + "  Dump Selected Map").c_str(), ImVec2(170, 38))) dump_selected_map(state);
    ImGui::EndDisabled();
    ImGui::Spacing();
    ImGui::InputText("Dump output", state.dump_path, sizeof(state.dump_path));
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("Directory or full .bin file path for Dump Selected Map");
    ImGui::Spacing();
    ImGui::InputText("Filter", state.map_filter, sizeof(state.map_filter));
    ImGui::Checkbox("Readable", &state.map_filter_readable);
    ImGui::SameLine(); ImGui::Checkbox("Writable", &state.map_filter_writable);
    ImGui::SameLine(); ImGui::Checkbox("Executable", &state.map_filter_executable);
    ImGui::Checkbox("Hide system maps", &state.map_filter_hide_system);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputInt("Min KB", &state.map_filter_min_kb);
    state.map_filter_min_kb = std::max(state.map_filter_min_kb, 0);
    ImGui::TextColored(ui::colors().dim, "%zu / %zu maps shown", filtered_map_count(state), state.maps.size());
    ImGui::Spacing();
    draw_maps_table(state);
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

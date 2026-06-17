/*
 * MemDBG - Processes screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "file_picker.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

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

static std::string format_bytes(uint64_t bytes) {
  const char *units[] = {"B", "KiB", "MiB", "GiB"};
  double value = static_cast<double>(bytes);
  size_t unit = 0;
  while (value >= 1024.0 && unit + 1U < std::size(units)) {
    value /= 1024.0;
    unit++;
  }
  std::ostringstream out;
  out << std::fixed << std::setprecision(unit == 0U ? 0 : 2) << value
      << ' ' << units[unit];
  return out.str();
}

static std::string sanitize_component(std::string value) {
  for (char &c : value) {
    unsigned char ch = static_cast<unsigned char>(c);
    if (std::isalnum(ch) == 0 && c != '_' && c != '-' && c != '.')
      c = '_';
  }
  while (!value.empty() && value.front() == '_') value.erase(value.begin());
  while (!value.empty() && value.back() == '_') value.pop_back();
  if (value.empty()) value = "process";
  if (value.size() > 64U) value.resize(64U);
  return value;
}

static bool add_saturating(uint64_t &total, uint64_t value) {
  if (std::numeric_limits<uint64_t>::max() - total < value) {
    total = std::numeric_limits<uint64_t>::max();
    return false;
  }
  total += value;
  return true;
}

static void analyze_process(AppState &state) {
  if (state.selected_pid <= 0) {    set_status(state, locale::tr("processes.select_pid_first")); return; }
  if (state.maps.empty()) { set_status(state, "Refresh process maps first"); return; }

  uint64_t total_bytes = 0;
  uint64_t readable_bytes = 0;
  uint64_t writable_bytes = 0;
  uint64_t executable_bytes = 0;
  uint64_t heap_candidate_bytes = 0;
  uint64_t filtered_bytes = 0;
  uint64_t largest_size = 0;
  const MapEntry *largest = nullptr;
  size_t valid_maps = 0;
  size_t readable_maps = 0;
  size_t writable_maps = 0;
  size_t executable_maps = 0;
  size_t heap_candidates = 0;
  size_t system_maps = 0;
  size_t filtered_maps = 0;

  for (const auto &map : state.maps) {
    if (map.end <= map.start) continue;
    const uint64_t size = map.end - map.start;
    valid_maps++;
    add_saturating(total_bytes, size);
    if (size > largest_size) {
      largest_size = size;
      largest = &map;
    }
    const bool readable = (map.protection & 1U) != 0U;
    const bool writable = (map.protection & 2U) != 0U;
    const bool executable = (map.protection & 4U) != 0U;
    const bool system = map_is_system_like(map);
    if (readable) { readable_maps++; add_saturating(readable_bytes, size); }
    if (writable) { writable_maps++; add_saturating(writable_bytes, size); }
    if (executable) { executable_maps++; add_saturating(executable_bytes, size); }
    if (system) system_maps++;
    if (readable && writable && !executable && !system) {
      heap_candidates++;
      add_saturating(heap_candidate_bytes, size);
    }
    if (map_passes_filters(state, map)) {
      filtered_maps++;
      add_saturating(filtered_bytes, size);
    }
  }

  std::ostringstream out;
  out << "PID " << state.selected_pid << " - " << selected_process_name(state) << '\n';
  if (state.has_process_info) {
    if (!state.selected_process_info.title_id.empty())
      out << "Title ID: " << state.selected_process_info.title_id << '\n';
    if (!state.selected_process_info.path.empty())
      out << "Path: " << state.selected_process_info.path << '\n';
  }
  out << "Maps: " << valid_maps << " total, " << filtered_maps << " currently filtered\n";
  out << "Address space in maps: " << format_bytes(total_bytes) << '\n';
  out << "Readable: " << readable_maps << " maps / " << format_bytes(readable_bytes) << '\n';
  out << "Writable: " << writable_maps << " maps / " << format_bytes(writable_bytes) << '\n';
  out << "Executable: " << executable_maps << " maps / " << format_bytes(executable_bytes) << '\n';
  out << "Non-system RW heap candidates: " << heap_candidates << " maps / "
      << format_bytes(heap_candidate_bytes) << '\n';
  out << "System-like maps hidden by default: " << system_maps << '\n';
  out << "Filtered dump size before cap: " << format_bytes(filtered_bytes) << '\n';
  if (largest) {
    out << "Largest map: " << hex_u64(largest->start) << " - " << hex_u64(largest->end)
        << " (" << format_bytes(largest_size) << ", " << prot_text(largest->protection)
        << ") " << largest->name << '\n';
  }
  state.process_analysis_report = out.str();
  set_status(state, locale::tr("processes.process_analysis_updated"));
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
    set_status(state, locale::tr("processes.no_filtered_maps"));
    return;
  }
  std::snprintf(state.scan_start, sizeof(state.scan_start), "%s", hex_u64(start).c_str());
  std::snprintf(state.scan_end, sizeof(state.scan_end), "%s", hex_u64(end).c_str());
  set_status(state, locale::tr("processes.scan_window_set"));
}

/* ---- Dump ---- */
static void dump_selected_map(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0 || state.selected_map_row < 0 ||
      state.selected_map_row >= static_cast<int>(state.maps.size())) {
    set_status(state, locale::tr("processes.select_map_first")); return;
  }
  const MapEntry &map = state.maps[state.selected_map_row];
  if (map.end <= map.start) { set_status(state, locale::tr("processes.map_empty")); return; }
  std::string default_name = "pid_" + std::to_string(state.selected_pid) + "_" +
                             hex_u64(map.start).substr(2) + ".bin";

  /* Try native save dialog first; fall back to configured dump_path */
  std::string picked = memdbg::frontend::ui::pickSaveFile(
      locale::tr("file_picker.save_memory_dump"), default_name, locale::tr("file_picker.binary_files"), "*.bin");

  std::filesystem::path out_path;
  if (!picked.empty()) {
    out_path = picked;
    /* Update dump_path so subsequent dumps default here */
    std::filesystem::path parent = out_path.parent_path();
    if (!parent.empty())
      std::snprintf(state.dump_path, sizeof(state.dump_path), "%s",
                    parent.string().c_str());
  } else {
    /* No native picker (console) or user cancelled — use configured path */
    std::filesystem::path configured = trim_copy(state.dump_path);
    if (configured.empty()) configured = "dumps";
    const bool looks_like_file = configured.has_extension();
    if (looks_like_file) out_path = configured;
    else                 out_path = configured / default_name;
  }

  std::filesystem::path dump_dir = out_path.parent_path();
  if (dump_dir.empty()) dump_dir = ".";
  std::error_code ec;
  std::filesystem::create_directories(dump_dir, ec);
  if (ec) { set_status(state, locale::tr("processes.create_dump_dir_failed")); return; }
  std::ofstream out(out_path, std::ios::binary);
  if (!out) { if (state.crash_logging_enabled) state.crash_logger.log("error", "Dump failed: cannot open output file"); set_status(state, locale::tr("processes.open_dump_failed")); return; }
  uint64_t address = map.start;
  uint64_t remaining = map.end - map.start;
  uint64_t written_total = 0;
  while (remaining != 0U) {
    uint32_t chunk = remaining > MEMDBG_PROTOCOL_MAX_READ ? MEMDBG_PROTOCOL_MAX_READ : static_cast<uint32_t>(remaining);
    std::vector<uint8_t> bytes;
    if (!state.client.memory_read(state.selected_pid, address, chunk, bytes)) {
      if (state.crash_logging_enabled) state.crash_logger.log("error", ("Dump failed: " + std::string(state.client.last_error())).c_str());
      char df_buf[512]; std::snprintf(df_buf, sizeof(df_buf), locale::tr("processes.dump_failed"), state.client.last_error().c_str()); set_status(state, df_buf); return;
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

static void dump_filtered_maps(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) {    set_status(state, locale::tr("processes.select_pid_first")); return; }
  if (state.maps.empty()) { set_status(state, "Refresh process maps first"); return; }

  state.process_dump_max_mb = std::clamp(state.process_dump_max_mb, 1, 4096);
  std::filesystem::path base_dir = trim_copy(state.dump_path);
  if (base_dir.empty()) base_dir = "dumps";
  if (base_dir.has_extension()) base_dir = base_dir.parent_path();
  if (base_dir.empty()) base_dir = ".";

  std::string process_name = sanitize_component(selected_process_name(state));
  std::filesystem::path out_dir = base_dir /
      ("pid_" + std::to_string(state.selected_pid) + "_" + process_name + "_maps");
  std::error_code ec;
  std::filesystem::create_directories(out_dir, ec);
  if (ec) { set_status(state, "Failed to create process dump directory"); return; }

  std::ofstream manifest(out_dir / "manifest.txt", std::ios::binary);
  if (!manifest) { set_status(state, "Failed to create dump manifest"); return; }
  manifest << "MemDBG process dump\n";
  manifest << "pid=" << state.selected_pid << "\n";
  manifest << "process=" << selected_process_name(state) << "\n";
  manifest << "filter=" << trim_copy(state.map_filter) << "\n";
  manifest << "readable=" << state.map_filter_readable
           << " writable=" << state.map_filter_writable
           << " executable=" << state.map_filter_executable
           << " hide_system=" << state.map_filter_hide_system
           << " min_kb=" << state.map_filter_min_kb << "\n\n";
  manifest << "file,start,end,prot,dumped_bytes,name\n";

  const uint64_t budget =
      static_cast<uint64_t>(state.process_dump_max_mb) * 1024ULL * 1024ULL;
  uint64_t dumped_total = 0;
  size_t dumped_maps = 0;
  size_t skipped_maps = 0;

  for (size_t i = 0; i < state.maps.size(); ++i) {
    const auto &map = state.maps[i];
    if (!map_passes_filters(state, map) || (map.protection & 1U) == 0U ||
        map.end <= map.start) {
      continue;
    }
    if (dumped_total >= budget) break;

    const uint64_t map_size = map.end - map.start;
    const uint64_t budget_left = budget - dumped_total;
    const uint64_t target_size = std::min(map_size, budget_left);
    std::string file_name = "map_" + std::to_string(i) + "_" +
        hex_u64(map.start).substr(2) + "_" + hex_u64(map.end).substr(2) +
        "_" + prot_text(map.protection) + ".bin";
    file_name = sanitize_component(file_name);
    std::filesystem::path file_path = out_dir / file_name;
    std::ofstream out(file_path, std::ios::binary);
    if (!out) {
      skipped_maps++;
      manifest << "# open_failed," << hex_u64(map.start) << ',' << hex_u64(map.end)
               << ',' << prot_text(map.protection) << ',' << map.name << "\n";
      continue;
    }

    uint64_t address = map.start;
    uint64_t remaining = target_size;
    uint64_t written = 0;
    while (remaining != 0U) {
      uint32_t chunk = remaining > MEMDBG_PROTOCOL_MAX_READ
                           ? MEMDBG_PROTOCOL_MAX_READ
                           : static_cast<uint32_t>(remaining);
      std::vector<uint8_t> bytes;
      if (!state.client.memory_read(state.selected_pid, address, chunk, bytes)) {
        manifest << "# read_failed," << file_name << ',' << hex_u64(address)
                 << ',' << state.client.last_error() << "\n";
        break;
      }
      if (bytes.empty()) break;
      out.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
      if (!out) {
        manifest << "# write_failed," << file_name << ',' << hex_u64(address) << "\n";
        break;
      }
      address += bytes.size();
      remaining -= bytes.size();
      written += bytes.size();
      dumped_total += bytes.size();
      if (dumped_total >= budget) break;
    }

    if (written == 0U) {
      skipped_maps++;
      std::filesystem::remove(file_path, ec);
      continue;
    }
    dumped_maps++;
    manifest << file_name << ',' << hex_u64(map.start) << ',' << hex_u64(map.end)
             << ',' << prot_text(map.protection) << ',' << written << ','
             << map.name << "\n";
  }

  manifest << "\nsummary_maps=" << dumped_maps
           << "\nskipped_maps=" << skipped_maps
           << "\ndumped_bytes=" << dumped_total << "\n";
  set_status(state, "Dumped " + std::to_string(dumped_maps) + " filtered map(s) to " +
                    out_dir.string());
  push_notification(state, "Process dump written to " + out_dir.string(), 5.0);
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
  char pid_buf[128];
  std::snprintf(pid_buf, sizeof(pid_buf), locale::tr("processes.selected_pid"), state.selected_pid);
  set_status(state, pid_buf);
}

static void ensure_process_info(AppState &state) {
  if (state.has_process_info) return;
  if (!state.client.connected() || state.selected_pid <= 0) return;
  /* Skip if payload is busy with an async operation */
  if (state.telemetry_pending || state.scan_async_pending) return;
  if (state.client.process_info(state.selected_pid, state.selected_process_info))
    state.has_process_info = true;
}

static void select_map(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.maps.size())) return;
  const auto &map = state.maps[row];
  state.selected_map_row = row;
  std::snprintf(state.read_address, sizeof(state.read_address), "%s", hex_u64(map.start).c_str());
  std::snprintf(state.write_address, sizeof(state.write_address), "%s", hex_u64(map.start).c_str());
  std::snprintf(state.scan_start, sizeof(state.scan_start), "%s", hex_u64(map.start).c_str());
  std::snprintf(state.scan_length, sizeof(state.scan_length), "%s", hex_u64(map.end - map.start).c_str());
  char map_buf[128];
  std::snprintf(map_buf, sizeof(map_buf), locale::tr("processes.selected_map"), hex_u64(map.start).c_str(), hex_u64(map.end).c_str());
  set_status(state, map_buf);
}

static void refresh_processes(AppState &state) {
  if (!state.client.connected()) {
    set_status(state, locale::tr("connect.no_console_before_processes"));
    push_notification(state, locale::tr("connect.no_console_before_processes"), 4.0);
    return;
  }
  if (!state.client.process_list(state.processes)) {
    std::string error = state.client.last_error();
    if (error.empty()) error = locale::tr("processes.process_refreshed");
    set_status(state, error);
    char refr_buf[512];
    std::snprintf(refr_buf, sizeof(refr_buf), locale::tr("connect.process_refresh_failed"), error.c_str());
    push_notification(state, refr_buf, 5.0);
    return;
  }
  /* Reconcile selection: find previously selected PID in new list */
  int new_row = -1;
  if (state.selected_pid > 0) {
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      if (state.processes[i].pid == state.selected_pid) { new_row = i; break; }
    }
  }
  if (new_row >= 0) {
    state.selected_process_row = new_row;
  } else {
    state.selected_pid = 0;
    state.selected_process_row = -1;
    state.has_process_info = false;
    state.maps.clear();
  }
  set_status(state, locale::tr("processes.process_refreshed"));
}

static void refresh_maps(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console before refreshing maps"); return; }
  if (state.selected_pid <= 0) {    set_status(state, locale::tr("processes.select_pid_first")); return; }
  if (!state.client.process_maps(state.selected_pid, state.maps)) { set_status(state, state.client.last_error()); return; }
  state.selected_map_row = -1;
  set_status(state, "Memory maps refreshed");
}

/* ---- Tables ---- */
static void draw_process_table(AppState &state) {
  if (ImGui::BeginTable("ProcessTable", 4,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable,
        ImVec2(0,0))) {
    ImGui::TableSetupColumn(locale::tr("processes.pid_col"), ImGuiTableColumnFlags_WidthFixed, 82);
    ImGui::TableSetupColumn(locale::tr("processes.name_col"));
    ImGui::TableSetupColumn(locale::tr("processes.title_id_col"), ImGuiTableColumnFlags_WidthFixed, 100);
    ImGui::TableSetupColumn(locale::tr("processes.state_col"), ImGuiTableColumnFlags_WidthFixed, 78);
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
      if (ImGui::IsItemHovered() && !process.name.empty()) ImGui::SetTooltip("%s", process.name.c_str());
      ImGui::TableSetColumnIndex(2);
      if (state.has_process_info && state.selected_pid == process.pid)
        ImGui::TextColored(ui::colors().primary2, "%s", state.selected_process_info.title_id.c_str());
      else if (ImGui::IsItemVisible() && i == state.selected_process_row && state.client.connected())
        ensure_process_info(state);
      ImGui::TableSetColumnIndex(3);
      ImGui::TextColored(selected ? ui::colors().primary2 : ui::colors().dim,
                         "%s", selected ? locale::tr("processes.active") : "-");
    }
    ImGui::EndTable();
  }
}

static void draw_maps_table(AppState &state) {
  if (state.selected_pid <= 0) {
    ui::draw_empty_state(locale::tr("processes.no_process_selected"), locale::tr("processes.no_process_desc"));
    return;
  }
  if (ImGui::BeginTable("MapsTable", 5,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable,
        ImVec2(0,0))) {
    ImGui::TableSetupColumn(locale::tr("processes.start_col"));
    ImGui::TableSetupColumn(locale::tr("processes.end_col"));
    ImGui::TableSetupColumn(locale::tr("processes.size_col"), ImGuiTableColumnFlags_WidthFixed, 90);
    ImGui::TableSetupColumn(locale::tr("processes.prot_col"), ImGuiTableColumnFlags_WidthFixed, 58);
    ImGui::TableSetupColumn(locale::tr("processes.name_col"));
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
      if (ImGui::IsItemHovered() && !map.name.empty()) ImGui::SetTooltip("%s", map.name.c_str());
    }
    ImGui::EndTable();
  }
}

/* ---- Main draw ---- */
void draw_processes(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float left_w = std::max(360.0f, (avail.x - gap) * 0.42f);

  ui::begin_panel("ProcessesPanel", locale::tr("processes.console_processes"), ImVec2(left_w, avail.y));
  if (!state.client.connected()) {
    if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("processes.refresh_processes")).c_str(), ImVec2(190, 38)))
      refresh_processes(state);
    ImGui::Spacing();
    ui::draw_empty_state(locale::tr("processes.connect_first"), locale::tr("processes.connect_first_desc"));
  } else {
    if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("processes.refresh_processes")).c_str(), ImVec2(180, 38))) refresh_processes(state);
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, locale::tr("processes.entries"), state.processes.size());
    ImGui::Spacing();
    draw_process_table(state);
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("MapsPanel", locale::tr("processes.memory_maps"), ImVec2(0, avail.y));
  if (!state.client.connected()) {
    ui::draw_empty_state(locale::tr("processes.waiting_session"), locale::tr("processes.waiting_desc"));
  } else {
    ImGui::Text(locale::tr("processes.active_pid"), state.selected_pid);
    ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
    if (state.has_process_info) {
      if (!state.selected_process_info.title_id.empty())
        ImGui::TextColored(ui::colors().primary2, locale::tr("processes.title_id"), state.selected_process_info.title_id.c_str());
      if (!state.selected_process_info.content_id.empty())
        ImGui::TextWrapped(locale::tr("processes.content_id"), state.selected_process_info.content_id.c_str());
      if (!state.selected_process_info.path.empty())
        ImGui::TextWrapped(locale::tr("processes.path"), state.selected_process_info.path.c_str());
    }
    ImGui::BeginDisabled(!state.client.connected() || state.selected_pid <= 0);
    if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("processes.refresh_maps")).c_str(), ImVec2(150, 38))) refresh_maps(state);
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kFilter) + "  " + locale::tr("processes.use_filtered_window")).c_str(), ImVec2(185, 38))) set_scan_window_from_filtered_maps(state);
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kDump) + "  " + locale::tr("processes.dump_selected_map")).c_str(), ImVec2(170, 38))) dump_selected_map(state);
    if (ui::soft_button((std::string(icons::kSearch) + "  " + locale::tr("processes.analyze_process")).c_str(), ImVec2(170, 38))) analyze_process(state);
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kDump) + "  " + locale::tr("processes.dump_filtered_maps")).c_str(), ImVec2(190, 38))) dump_filtered_maps(state);
    ImGui::EndDisabled();
    ImGui::Spacing();
    ImGui::InputText(locale::tr("processes.dump_output"), state.dump_path, sizeof(state.dump_path));
    ImGui::SameLine();
    if (ImGui::SmallButton((std::string(icons::kLoad) + "##dumppath").c_str())) {
      std::string picked = memdbg::frontend::ui::pickFile(locale::tr("file_picker.select_dump_dir"));
      if (!picked.empty())
        std::snprintf(state.dump_path, sizeof(state.dump_path), "%s", picked.c_str());
    }
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("processes.dump_dir_tooltip"));
    ImGui::Spacing();
    ImGui::InputText(locale::tr("processes.filter"), state.map_filter, sizeof(state.map_filter));
    ImGui::Checkbox(locale::tr("processes.readable"), &state.map_filter_readable);
    ImGui::SameLine(); ImGui::Checkbox(locale::tr("processes.writable"), &state.map_filter_writable);
    ImGui::SameLine(); ImGui::Checkbox(locale::tr("processes.executable"), &state.map_filter_executable);
    ImGui::Checkbox(locale::tr("processes.hide_system"), &state.map_filter_hide_system);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputInt(locale::tr("processes.min_kb"), &state.map_filter_min_kb);
    state.map_filter_min_kb = std::max(state.map_filter_min_kb, 0);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(130.0f);
    ImGui::InputInt(locale::tr("processes.dump_cap_mb"), &state.process_dump_max_mb);
    state.process_dump_max_mb = std::clamp(state.process_dump_max_mb, 1, 4096);
    ImGui::TextColored(ui::colors().dim, locale::tr("processes.maps_shown"), filtered_map_count(state), state.maps.size());
    if (!state.process_analysis_report.empty()) {
      ImGui::Spacing();
      if (ImGui::BeginChild("ProcessAnalysisReport", ImVec2(0, 118), true,
                            ImGuiWindowFlags_AlwaysVerticalScrollbar)) {
        ImGui::TextWrapped("%s", state.process_analysis_report.c_str());
      }
      ImGui::EndChild();
    }
    ImGui::Spacing();
    draw_maps_table(state);
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

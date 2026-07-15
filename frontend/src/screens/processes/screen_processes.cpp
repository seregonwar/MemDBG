/*
 * MemDBG - Processes screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "core/client/memdbg_client.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "file_picker.hpp"
#include "confirm_modal.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <tuple>
#include <unordered_map>

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
  if (state.maps.empty()) { set_status(state, locale::tr("processes.refresh_maps_first")); return; }

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
    if (!out) { set_status(state, locale::tr("processes.dump_failed")); return; }
    address += bytes.size();
    remaining -= bytes.size();
    written_total += bytes.size();
  }
  char dp_buf[512]; std::snprintf(dp_buf, sizeof(dp_buf), locale::tr("processes.dumped_bytes"), written_total, out_path.string().c_str()); set_status(state, dp_buf);
  char md_buf[512]; std::snprintf(md_buf, sizeof(md_buf), locale::tr("processes.map_dumped"), out_path.string().c_str()); push_notification(state, md_buf, 5.0);
}

static void dump_filtered_maps(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) {    set_status(state, locale::tr("processes.select_pid_first")); return; }
  if (state.maps.empty()) { set_status(state, locale::tr("processes.refresh_maps_first")); return; }

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
  if (ec) { set_status(state, locale::tr("processes.dump_dir_failed")); return; }

  std::ofstream manifest(out_dir / "manifest.txt", std::ios::binary);
  if (!manifest) { set_status(state, locale::tr("processes.dump_manifest_failed")); return; }
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
  char pdw_buf[512]; std::snprintf(pdw_buf, sizeof(pdw_buf), locale::tr("processes.dump_written"), out_dir.string().c_str()); push_notification(state, pdw_buf, 5.0);
}

/* ---- Process selection ---- */
static void select_process(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.processes.size())) return;
  state.selected_process_row = row;
  state.selected_pid = state.processes[row].pid;
  state.maps.clear();
  state.selected_map_row = -1;
  state.selected_map_starts.clear();
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
  if (client_async_busy(state)) return;
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
    state.selected_map_starts.clear();
  }
  set_status(state, locale::tr("processes.process_refreshed"));
}

static void refresh_maps(AppState &state) {
  request_maps_refresh_async(state);
}

/* ---- Process Tree ---- */

struct ProcessTreeNode {
  int32_t pid = 0;
  int32_t ppid = 0;
  std::string name;
  std::vector<int> children;  // indices into the flat list
};

static void build_process_tree(const std::vector<ProcessEntry> &processes,
                               std::vector<ProcessTreeNode> &nodes,
                               std::vector<int> &roots) {
  nodes.clear();
  roots.clear();
  if (processes.empty()) return;

  std::unordered_map<int32_t, int> pid_to_index;
  nodes.reserve(processes.size());

  for (size_t i = 0; i < processes.size(); ++i) {
    const auto &p = processes[i];
    if (p.pid <= 0) continue;
    ProcessTreeNode node;
    node.pid = p.pid;
    node.ppid = p.ppid;
    node.name = p.name;
    nodes.push_back(node);
    pid_to_index[p.pid] = static_cast<int>(nodes.size()) - 1;
  }

  for (int i = 0; i < static_cast<int>(nodes.size()); ++i) {
    int32_t ppid = nodes[i].ppid;
    if (ppid <= 0 || ppid == nodes[i].pid) {
      roots.push_back(i);
      continue;
    }
    auto it = pid_to_index.find(ppid);
    if (it != pid_to_index.end()) {
      nodes[it->second].children.push_back(i);
    } else {
      roots.push_back(i);
    }
  }
}

static void draw_tree_node(AppState &state, const std::vector<ProcessTreeNode> &nodes,
                           int node_idx, int depth) {
  const auto &node = nodes[node_idx];
  const float scl = ui::dpi_scale();
  const float indent = static_cast<float>(depth) * 20.0f * scl;

  ImGui::TableNextRow();

  ImGui::TableSetColumnIndex(0);
  ImGui::SetCursorPosX(ImGui::GetCursorPosX() + indent);

  bool has_children = !node.children.empty();
  bool selected = node.pid == state.selected_pid;

  std::string label;
  if (has_children) {
    label = std::string(icons::kLoad) + "  " + std::to_string(node.pid);
  } else {
    label = std::string(icons::kCode) + "  " + std::to_string(node.pid);
  }
  label += "##ptree" + std::to_string(node.pid);

  ImGuiSelectableFlags flags = ImGuiSelectableFlags_SpanAllColumns;
  if (ImGui::Selectable(label.c_str(), selected, flags)) {
    int row = -1;
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      if (state.processes[i].pid == node.pid) { row = i; break; }
    }
    if (row >= 0) select_process(state, row);
  }

  ImGui::TableSetColumnIndex(1);
  ImGui::SetCursorPosX(ImGui::GetCursorPosX() + indent);
  ImGui::TextUnformatted(node.name.c_str());
  if (ImGui::IsItemHovered() && !node.name.empty())
    ImGui::SetTooltip("%s", node.name.c_str());

  ImGui::TableSetColumnIndex(2);
  ImGui::Text("%d", node.ppid);

  ImGui::TableSetColumnIndex(3);
  ImGui::TextColored(selected ? ui::colors().primary2 : ui::colors().dim,
                     "%s", selected ? locale::tr("processes.active") : "-");

  for (int child : node.children)
    draw_tree_node(state, nodes, child, depth + 1);
}

static void draw_process_tree(AppState &state) {
  std::vector<ProcessTreeNode> nodes;
  std::vector<int> roots;
  build_process_tree(state.processes, nodes, roots);

  if (nodes.empty()) {
    ui::draw_empty_state(locale::tr("processes.no_process_selected"),
                         locale::tr("processes.no_process_desc"));
    return;
  }

  const ImGuiTableFlags table_flags =
      ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
      ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

  if (ImGui::BeginTable("ProcessTreeTable", 4, table_flags, ImVec2(0, 0))) {
    ImGui::TableSetupColumn(locale::tr("processes.pid_col"),
                            ImGuiTableColumnFlags_WidthFixed, 100);
    ImGui::TableSetupColumn(locale::tr("processes.name_col"));
    ImGui::TableSetupColumn(locale::tr("processes.ppid_col"),
                            ImGuiTableColumnFlags_WidthFixed, 70);
    ImGui::TableSetupColumn(locale::tr("processes.state_col"),
                            ImGuiTableColumnFlags_WidthFixed, 78);
    ImGui::TableHeadersRow();

    for (int root : roots)
      draw_tree_node(state, nodes, root, 0);

    ImGui::EndTable();
  }
}

/* ---- JSON Dump Dialog ---- */

static void request_json_dump_async(AppState &state) {
  if (!state.client.connected() || state.selected_pid <= 0) return;
  if (client_async_busy(state)) return;

  state.json_dump_pending = true;
  state.json_dump_error.clear();
  state.json_dump_output.clear();
  state.json_dump_start_time = ImGui::GetTime();

  uint32_t flags = 0U;
  if (state.json_dump_include_regs) flags |= 1U;
  if (state.json_dump_include_stack) flags |= 2U;
  if (state.json_dump_include_preview) flags |= 4U;

  int32_t pid = state.selected_pid;
  std::string host = state.host;
  uint16_t port = static_cast<uint16_t>(state.debug_port);

  state.json_dump_future = std::async(std::launch::async,
      [host, port, pid, flags]() -> std::tuple<bool, std::string, std::string> {
        try {
          Client local_client;
          if (!local_client.connect_to(host, port)) {
            return {false, "", "JSON dump connect failed: " + local_client.last_error()};
          }
          std::string json;
          if (!local_client.process_dump(pid, flags, json)) {
            return {false, "", "JSON dump request failed: " + local_client.last_error()};
          }
          return {true, std::move(json), ""};
        } catch (const std::exception &e) {
          return {false, "", std::string("JSON dump exception: ") + e.what()};
        }
      });
}

static void poll_json_dump(AppState &state) {
  if (!state.json_dump_pending) return;
  if (!state.json_dump_future.valid()) {
    state.json_dump_pending = false;
    return;
  }
  auto status = state.json_dump_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) {
    double elapsed = ImGui::GetTime() - state.json_dump_start_time;
    if (elapsed > 60.0) {
      state.json_dump_pending = false;
      state.json_dump_error = "JSON dump timed out after 60s";
      set_status(state, state.json_dump_error);
    }
    return;
  }
  state.json_dump_pending = false;
  auto [ok, output, error] = state.json_dump_future.get();
  if (ok) {
    state.json_dump_output = std::move(output);
    state.json_dump_error.clear();
    set_status(state, "JSON dump complete (" + std::to_string(state.json_dump_output.size()) + " bytes)");
    push_notification(state, "Process dump JSON received", 4.0);
  } else {
    state.json_dump_output.clear();
    state.json_dump_error = std::move(error);
    set_status(state, state.json_dump_error);
  }
}

static void draw_json_dump_dialog(AppState &state) {
  if (!ImGui::IsPopupOpen("JSONDumpDialog")) return;

  ImGui::SetNextWindowSize(ImVec2(620, 580), ImGuiCond_Appearing);
  if (!ImGui::BeginPopupModal("JSONDumpDialog", nullptr,
                              ImGuiWindowFlags_NoSavedSettings)) return;

  ImGui::TextColored(ui::colors().primary2, "%s %s", icons::kDump,
                     locale::tr("processes.json_dump_title"));
  ImGui::Separator();

  ImGui::Text("PID: %d  |  %s", state.selected_pid,
              selected_process_name(state).c_str());
  ImGui::Spacing();

  ImGui::Checkbox(locale::tr("processes.json_dump_include_regs"),
                  &state.json_dump_include_regs);
  ImGui::SameLine();
  ImGui::Checkbox(locale::tr("processes.json_dump_include_stack"),
                  &state.json_dump_include_stack);
  ImGui::SameLine();
  ImGui::Checkbox(locale::tr("processes.json_dump_include_preview"),
                  &state.json_dump_include_preview);

  ImGui::Spacing();
  ImGui::Separator();

  /* Dump button */
  const bool connected = state.client.connected();
  const bool has_pid = state.selected_pid > 0;
  const bool busy = client_async_busy(state);
  const bool can_dump = connected && has_pid && !state.json_dump_pending && !busy;

  if (!connected) {
    ImGui::TextColored(ui::colors().danger, "%s",
                       "Connect to a console before requesting a JSON dump.");
  } else if (!has_pid) {
    ImGui::TextColored(ui::colors().danger, "%s",
                       "Select a process from the list before requesting a JSON dump.");
  } else if (busy && !state.json_dump_pending) {
    ImGui::TextColored(ui::colors().warning, "%s",
                       "Another operation is in progress; wait for it to finish.");
  }

  ImGui::BeginDisabled(!can_dump);
  if (ui::primary_button(locale::tr("processes.json_dump_request"),
                          ImVec2(180, 0))) {
    request_json_dump_async(state);
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  if (state.json_dump_pending)
    ImGui::TextColored(ui::colors().warning, "%s %.1fs",
                       locale::tr("processes.json_dump_waiting"),
                       ImGui::GetTime() - state.json_dump_start_time);

  ImGui::SameLine();
  if (ui::soft_button(locale::tr("common.close"), ImVec2(80, 0)))
    ImGui::CloseCurrentPopup();

  /* Copy to clipboard and save buttons */
  if (!state.json_dump_output.empty()) {
    ImGui::SameLine();
    if (ImGui::SmallButton(locale::tr("common.copy"))) {
      ImGui::SetClipboardText(state.json_dump_output.c_str());
      set_status(state, locale::tr("processes.json_dump_copied"));
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(locale::tr("processes.json_dump_save"))) {
      std::string default_name = "pid_" + std::to_string(state.selected_pid) + "_" +
                                 selected_process_name(state) + ".json";
      std::string picked = memdbg::frontend::ui::pickSaveFile(
          locale::tr("processes.json_dump_save_title"), default_name,
          "JSON files", "*.json");
      if (!picked.empty()) {
        std::ofstream out(picked);
        if (out) {
          out << state.json_dump_output;
          set_status(state, "JSON dump saved to " + picked);
          push_notification(state, "JSON dump saved", 4.0);
        } else {
          set_status(state, "Failed to save JSON dump");
        }
      }
    }
  }

  if (!state.json_dump_error.empty())
    ImGui::TextColored(ui::colors().danger, "%s %s",
                       locale::tr("common.error"),
                       state.json_dump_error.c_str());

  ImGui::Spacing();
  ImGui::Separator();

  /* JSON output area */
  if (state.json_dump_output.empty()) {
    ImGui::TextColored(ui::colors().dim, "%s",
                       locale::tr("processes.json_dump_placeholder"));
  } else {
    ImGui::TextColored(ui::colors().muted, "%s (%zu bytes):",
                       locale::tr("processes.json_dump_output"),
                       state.json_dump_output.size());
    ImVec2 json_size(ImGui::GetContentRegionAvail().x,
                     ImGui::GetContentRegionAvail().y - 10);
    if (ImGui::BeginChild("JSONDumpOutput", json_size, true,
                          ImGuiWindowFlags_HorizontalScrollbar)) {
      std::istringstream stream(state.json_dump_output);
      std::string line;
      int line_no = 0;
      while (std::getline(stream, line)) {
        line_no++;
        /* Line number */
        char num_buf[16];
        snprintf(num_buf, sizeof(num_buf), "%4d ", line_no);
        ImGui::TextColored(ui::colors().dim, "%s", num_buf);
        ImGui::SameLine(42.0f);

        /* Simple syntax highlighting */
        for (size_t ci = 0; ci < line.size();) {
          /* Strings */
          if (line[ci] == '"') {
            size_t end = line.find('"', ci + 1);
            if (end == std::string::npos) end = line.size();
            else end++;
            ImGui::SameLine(0, 0);
            ImGui::TextColored(ImVec4(0.86f, 0.60f, 0.26f, 1), "%.*s",
                               static_cast<int>(end - ci), line.c_str() + ci);
            ci = end;
            continue;
          }
          /* Numbers */
          if ((line[ci] >= '0' && line[ci] <= '9') || line[ci] == '-') {
            size_t end = ci;
            while (end < line.size() &&
                   ((static_cast<unsigned char>(line[end]) >= '0' &&
                     static_cast<unsigned char>(line[end]) <= '9') ||
                    line[end] == 'x' || line[end] == '.' || line[end] == '-' ||
                    (static_cast<unsigned char>(line[end]) >= 'a' &&
                     static_cast<unsigned char>(line[end]) <= 'f') ||
                    (static_cast<unsigned char>(line[end]) >= 'A' &&
                     static_cast<unsigned char>(line[end]) <= 'F')))
              end++;
            ImGui::SameLine(0, 0);
            ImGui::TextColored(ImVec4(0.39f, 0.76f, 0.62f, 1), "%.*s",
                               static_cast<int>(end - ci), line.c_str() + ci);
            ci = end;
            continue;
          }
          /* Keywords: true, false, null */
          const char *kw = nullptr;
          if (line.compare(ci, 4, "true") == 0) {
            kw = "true"; ci += 4;
          } else if (line.compare(ci, 5, "false") == 0) {
            kw = "false"; ci += 5;
          } else if (line.compare(ci, 4, "null") == 0) {
            kw = "null"; ci += 4;
          }
          if (kw) {
            ImGui::SameLine(0, 0);
            ImGui::TextColored(ImVec4(0.49f, 0.65f, 1.0f, 1), "%s", kw);
          } else {
            /* Default char */
            ImGui::SameLine(0, 0);
            ImGui::Text("%.*s", 1, line.c_str() + ci);
            ci++;
          }
        }
      }
    }
    ImGui::EndChild();
  }

  ImGui::EndPopup();
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
  if (ImGui::BeginTable("MapsTable", 6,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable,
        ImVec2(0,0))) {
    ImGui::TableSetupColumn("##selected", ImGuiTableColumnFlags_WidthFixed, 30);
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
      bool checked = state.selected_map_starts.count(map.start) != 0U;
      if (ImGui::Checkbox(("##mapcheck" + std::to_string(i)).c_str(), &checked)) {
        if (checked)
          state.selected_map_starts.insert(map.start);
        else
          state.selected_map_starts.erase(map.start);
      }
      ImGui::TableSetColumnIndex(1);
      bool selected = state.selected_map_row == i;
      std::string start = hex_u64(map.start);
      if (ImGui::Selectable((start + "##map" + std::to_string(i)).c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
        select_map(state, i);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(hex_u64(map.end).c_str());
      ImGui::TableSetColumnIndex(3);
      ImGui::Text("%llu KB", static_cast<unsigned long long>((map.end - map.start) / 1024U));
      ImGui::TableSetColumnIndex(4);
      ImGui::TextUnformatted(prot_text(map.protection).c_str());
      ImGui::TableSetColumnIndex(5);
      ImGui::TextUnformatted(map.name.c_str());
      if (ImGui::IsItemHovered() && !map.name.empty()) ImGui::SetTooltip("%s", map.name.c_str());
    }
    ImGui::EndTable();
  }
}

/* ---- Main draw ---- */
void draw_processes(AppState &state, ImVec2 avail) {
  static int proc_tab = 0; /* 0=Process Explorer, 1=Task Manager */

  if (ImGui::BeginTabBar("ProcessesTabs")) {
    if (ImGui::BeginTabItem(locale::tr("nav.processes"))) {
      proc_tab = 0;
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(locale::tr("nav.taskmgr"))) {
      proc_tab = 1;
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }

  if (proc_tab == 1) {
    draw_taskmgr(state, avail);
    return;
  }

  poll_json_dump(state);

  const float left_w = std::max(360.0f, avail.x * 0.42f);

  ui::begin_panel("ProcessesPanel", locale::tr("processes.console_processes"), ImVec2(left_w, avail.y));
  if (!state.client.connected()) {
    if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("processes.refresh_processes")).c_str(), ImVec2(190, 34)))
      refresh_processes(state);
    ImGui::Spacing();
    ui::draw_empty_state(locale::tr("processes.connect_first"), locale::tr("processes.connect_first_desc"));
  } else {
    /* Button row: Refresh + Tree toggle + JSON Dump */
    ImGui::BeginDisabled(client_async_busy(state));
    if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("processes.refresh_processes")).c_str(), ImVec2(150, 34))) refresh_processes(state);
    ImGui::EndDisabled();
    ImGui::SameLine();
    /* Tree/List toggle */
    static int process_view_mode = 0; // 0=list, 1=tree
    if (ImGui::RadioButton("List", &process_view_mode, 0)) {}
    ImGui::SameLine();
    if (ImGui::RadioButton("Tree", &process_view_mode, 1)) {}
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, locale::tr("processes.entries"), state.processes.size());
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kDump) + "  " + locale::tr("processes.json_dump")).c_str(), ImVec2(130, 34)))
      ImGui::OpenPopup("JSONDumpDialog");
    ImGui::Spacing();
    if (process_view_mode == 1)
      draw_process_tree(state);
    else
      draw_process_table(state);
  }
  ui::end_panel();

  ImGui::SameLine();
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
    ImGui::BeginDisabled(!state.client.connected() || state.selected_pid <= 0 ||
                         client_async_busy(state));
    if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("processes.refresh_maps")).c_str(), ImVec2(150, 34))) refresh_maps(state);
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kFilter) + "  " + locale::tr("processes.use_filtered_window")).c_str(), ImVec2(185, 34))) set_scan_window_from_filtered_maps(state);
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kDump) + "  " + locale::tr("processes.dump_selected_map")).c_str(), ImVec2(170, 34))) ImGui::OpenPopup("ConfirmDumpSelectedMap");
    if (ui::soft_button((std::string(icons::kSearch) + "  " + locale::tr("processes.analyze_process")).c_str(), ImVec2(170, 34))) analyze_process(state);
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kDump) + "  " + locale::tr("processes.dump_filtered_maps")).c_str(), ImVec2(190, 34))) ImGui::OpenPopup("ConfirmDumpFilteredMaps");
    ImGui::EndDisabled();
    static bool skip_dump_selected_confirm = false;
    static bool skip_dump_filtered_confirm = false;
    if (ui::confirm_modal("ConfirmDumpSelectedMap",
                          "Dump selected memory map?",
                          "This reads the selected map from the console. Large or unstable regions can stall or crash weak payload sessions.",
                          &skip_dump_selected_confirm, true)) {
      dump_selected_map(state);
    }
    if (ui::confirm_modal("ConfirmDumpFilteredMaps",
                          "Dump all filtered readable maps?",
                          "This can read a large portion of the process address space. Tighten filters and keep the cap low on unstable consoles.",
                          &skip_dump_filtered_confirm, true)) {
      dump_filtered_maps(state);
    }
    ImGui::Spacing();
    {
      ui::FilePathOptions dump_opts;
      dump_opts.label = locale::tr("processes.dump_output");
      dump_opts.id = "##DumpPathProcesses";
      dump_opts.dialog_title = locale::tr("file_picker.select_dump_dir");
      dump_opts.folder_mode = true;
      dump_opts.placeholder = "dumps";
      if (ui::file_path_input(state.dump_path, sizeof(state.dump_path), dump_opts)) {
        std::string err;
        (void)save_frontend_settings(state, &err);
      }
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
    if (ui::soft_button(locale::tr("processes.select_all_maps"), ImVec2(120, 32))) {
      for (const auto &map : state.maps)
        if (map_passes_filters(state, map)) state.selected_map_starts.insert(map.start);
    }
    ImGui::SameLine();
    if (ui::soft_button(locale::tr("processes.select_no_maps"), ImVec2(120, 32)))
      state.selected_map_starts.clear();
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().primary2, locale::tr("processes.maps_selected"),
                       state.selected_map_starts.size());
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

  /* JSON Dump dialog */
  draw_json_dump_dialog(state);
}

} // namespace memdbg::frontend

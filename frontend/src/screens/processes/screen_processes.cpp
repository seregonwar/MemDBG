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
#include "map_selection.hpp"

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
  if (!filter.empty() && !detail::map_matches_name_or_type(map, filter))
    return false;
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
  state.action_journal.record("memory_dump", ("{\"pid\":" + std::to_string(state.selected_pid) + ",\"bytes\":" + std::to_string(written_total) + "}").c_str());
}

struct MapDumpPlanEntry {
  MapEntry map;
  size_t source_index = 0U;
  uint64_t target_size = 0U;
};

static void dump_filtered_maps(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) {    set_status(state, locale::tr("processes.select_pid_first")); return; }
  if (state.maps.empty()) { set_status(state, locale::tr("processes.refresh_maps_first")); return; }
  if (state.map_dump_pending) return;

  state.process_dump_max_mb = std::clamp(state.process_dump_max_mb, 1, 4096);
  std::filesystem::path base_dir = trim_copy(state.dump_path);
  if (base_dir.empty()) base_dir = "dumps";
  if (base_dir.has_extension()) base_dir = base_dir.parent_path();
  if (base_dir.empty()) base_dir = ".";

  std::string process_name = sanitize_component(selected_process_name(state));
  std::filesystem::path out_dir = base_dir /
      ("pid_" + std::to_string(state.selected_pid) + "_" + process_name + "_maps");
  const uint64_t budget =
      static_cast<uint64_t>(state.process_dump_max_mb) * 1024ULL * 1024ULL;
  uint64_t planned_bytes = 0U;
  std::vector<MapDumpPlanEntry> plan;
  for (size_t i = 0; i < state.maps.size(); ++i) {
    const auto &map = state.maps[i];
    if (!map_passes_filters(state, map) || (map.protection & 1U) == 0U ||
        map.end <= map.start)
      continue;
    if (planned_bytes >= budget) break;
    const uint64_t map_size = map.end - map.start;
    const uint64_t target_size = std::min(map_size, budget - planned_bytes);
    plan.push_back({map, i, target_size});
    planned_bytes += target_size;
  }
  if (plan.empty()) {
    set_status(state, locale::tr("processes.no_filtered_maps"));
    return;
  }

  const int32_t pid = state.selected_pid;
  const std::string process = selected_process_name(state);
  const std::string filter = trim_copy(state.map_filter);
  const bool readable = state.map_filter_readable;
  const bool writable = state.map_filter_writable;
  const bool executable = state.map_filter_executable;
  const bool hide_system = state.map_filter_hide_system;
  const int min_kb = state.map_filter_min_kb;
  state.map_dump_pending = true;
  state.map_dump_cancel_requested.store(false);
  state.map_dump_maps_done.store(0U);
  state.map_dump_maps_total.store(plan.size());
  state.map_dump_bytes_done.store(0U);
  state.map_dump_bytes_total.store(planned_bytes);
  state.map_dump_pid = pid;
  state.map_dump_start_time = ImGui::GetTime();
  state.map_dump_client = state.pool.memory_lease();
  auto client = state.map_dump_client;

  state.map_dump_future = std::async(std::launch::async,
      [client, plan = std::move(plan), out_dir, pid, process, filter,
       readable, writable, executable, hide_system, min_kb,
       &cancel = state.map_dump_cancel_requested,
       &maps_done = state.map_dump_maps_done,
       &bytes_done = state.map_dump_bytes_done]()
          -> std::tuple<bool, size_t, size_t, uint64_t, std::string,
                        std::string> {
        std::error_code ec;
        std::filesystem::create_directories(out_dir, ec);
        if (ec)
          return {false, 0U, 0U, 0U, out_dir.string(),
                  "Could not create dump directory: " + ec.message()};
        std::ofstream manifest(out_dir / "manifest.txt", std::ios::binary);
        if (!manifest)
          return {false, 0U, 0U, 0U, out_dir.string(),
                  "Could not create dump manifest"};
        manifest << "MemDBG process dump\n"
                 << "pid=" << pid << "\nprocess=" << process
                 << "\nfilter=" << filter << "\nreadable=" << readable
                 << " writable=" << writable << " executable=" << executable
                 << " hide_system=" << hide_system << " min_kb=" << min_kb
                 << "\n\nfile,start,end,prot,dumped_bytes,name\n";

        uint64_t dumped_total = 0U;
        size_t dumped_maps = 0U;
        size_t skipped_maps = 0U;
        for (const MapDumpPlanEntry &item : plan) {
          if (cancel.load()) break;
          const MapEntry &map = item.map;
          std::string file_name = sanitize_component(
              "map_" + std::to_string(item.source_index) + "_" +
              hex_u64(map.start).substr(2) + "_" +
              hex_u64(map.end).substr(2) + "_" +
              prot_text(map.protection) + ".bin");
          const std::filesystem::path file_path = out_dir / file_name;
          std::ofstream out(file_path, std::ios::binary);
          uint64_t written = 0U;
          if (!out) {
            ++skipped_maps;
            manifest << "# open_failed," << hex_u64(map.start) << ','
                     << hex_u64(map.end) << ',' << prot_text(map.protection)
                     << ',' << map.name << "\n";
          } else {
            uint64_t address = map.start;
            uint64_t remaining = item.target_size;
            while (remaining != 0U && !cancel.load()) {
              const uint32_t chunk = remaining > MEMDBG_PROTOCOL_MAX_READ
                  ? MEMDBG_PROTOCOL_MAX_READ
                  : static_cast<uint32_t>(remaining);
              std::vector<uint8_t> bytes;
              if (!client->memory_read(pid, address, chunk, bytes)) {
                manifest << "# read_failed," << file_name << ','
                         << hex_u64(address) << ',' << client->last_error()
                         << "\n";
                break;
              }
              if (bytes.empty()) break;
              out.write(reinterpret_cast<const char *>(bytes.data()),
                        static_cast<std::streamsize>(bytes.size()));
              if (!out) {
                manifest << "# write_failed," << file_name << ','
                         << hex_u64(address) << "\n";
                break;
              }
              address += bytes.size();
              remaining -= bytes.size();
              written += bytes.size();
              dumped_total += bytes.size();
              bytes_done.store(dumped_total);
            }
            if (written == 0U) {
              ++skipped_maps;
              out.close();
              std::filesystem::remove(file_path, ec);
            } else {
              ++dumped_maps;
              manifest << file_name << ',' << hex_u64(map.start) << ','
                       << hex_u64(map.end) << ',' << prot_text(map.protection)
                       << ',' << written << ',' << map.name << "\n";
            }
          }
          maps_done.fetch_add(1U);
        }
        manifest << "\nsummary_maps=" << dumped_maps
                 << "\nskipped_maps=" << skipped_maps
                 << "\ndumped_bytes=" << dumped_total
                 << "\ncancelled=" << (cancel.load() ? 1 : 0) << "\n";
        return {true, dumped_maps, skipped_maps, dumped_total,
                out_dir.string(), ""};
      });
}

static void poll_filtered_map_dump(AppState &state) {
  if (!state.map_dump_pending || !state.map_dump_future.valid()) return;
  if (state.map_dump_future.wait_for(std::chrono::milliseconds(0)) !=
      std::future_status::ready)
    return;
  state.map_dump_pending = false;
  state.map_dump_client.reset();
  const bool cancelled = state.map_dump_cancel_requested.exchange(false);
  auto [ok, dumped_maps, skipped_maps, dumped_total, out_dir, error] =
      state.map_dump_future.get();
  if (!ok) {
    set_status(state, error);
    push_notification(state, error, 5.0);
    return;
  }
  const std::string summary = (cancelled ? "Stopped after " : "Dumped ") +
      std::to_string(dumped_maps) + " map(s), " +
      format_bytes(dumped_total) + " to " + out_dir;
  set_status(state, summary);
  push_notification(state, summary, 5.0);
  state.action_journal.record(
      "memory_dump_filtered",
      ("{\"pid\":" + std::to_string(state.map_dump_pid) +
       ",\"maps\":" + std::to_string(dumped_maps) +
       ",\"skipped\":" + std::to_string(skipped_maps) +
       ",\"bytes\":" + std::to_string(dumped_total) +
       ",\"cancelled\":" + (cancelled ? "true" : "false") + "}").c_str());
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
  state.action_journal.record("process_select", ("{\"pid\":" + std::to_string(state.selected_pid) + ",\"name\":\"" + ActionJournal::json_escape(state.processes[row].name) + "\"}").c_str());
}

static void ensure_process_info(AppState &state) {
  if (state.has_process_info) return;
  if (!state.client.connected() || state.selected_pid <= 0) return;
  auto cached = state.taskmgr_resources.find(state.selected_pid);
  if (cached != state.taskmgr_resources.end() && cached->second.has_info) {
    state.selected_process_info = cached->second.info;
    state.has_process_info = true;
    return;
  }
  /* Process metadata shares the read-oriented memory lane.  Unrelated scan,
   * telemetry, and plugin work can continue on their own role connections. */
  if (state.connect_pending || state.map_refresh_pending ||
      state.json_dump_pending)
    return;
  auto client = state.pool.memory_lease();
  if (client->process_info(state.selected_pid, state.selected_process_info))
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
  if (state.json_dump_pending || state.map_refresh_pending) return;

  state.json_dump_pending = true;
  state.json_dump_error.clear();
  state.json_dump_output.clear();
  state.json_dump_cancel_requested = false;
  state.json_dump_start_time = ImGui::GetTime();

  uint32_t flags = 0U;
  if (state.json_dump_include_regs) flags |= 1U;
  if (state.json_dump_include_stack) flags |= 2U;
  if (state.json_dump_include_preview) flags |= 4U;

  int32_t pid = state.selected_pid;
  state.json_dump_client = state.pool.memory_lease();
  auto client = state.json_dump_client;

  state.json_dump_future = std::async(std::launch::async,
      [client = std::move(client), pid, flags]() -> std::tuple<bool, std::string, std::string> {
        try {
          std::string json;
          if (!client->process_dump(pid, flags, json)) {
            return {false, "", "JSON dump request failed: " + client->last_error()};
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
    if (elapsed > 60.0 && !state.json_dump_cancel_requested) {
      state.json_dump_cancel_requested = true;
      if (state.json_dump_client)
        state.json_dump_client->cancel_pending_io();
      state.json_dump_error = "JSON dump timed out after 60s";
      set_status(state, state.json_dump_error);
    }
    return;
  }
  state.json_dump_pending = false;
  state.json_dump_client.reset();
  auto [ok, output, error] = state.json_dump_future.get();
  if (ok) {
    state.json_dump_output = std::move(output);
    state.json_dump_error.clear();
    set_status(state, "JSON dump complete (" + std::to_string(state.json_dump_output.size()) + " bytes)");
    push_notification(state, "Process dump JSON received", 4.0);
  } else {
    state.json_dump_output.clear();
    if (!state.json_dump_cancel_requested)
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
  const bool busy = state.connect_pending || state.map_refresh_pending;
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

/* ---- ELF Load / Hijack ---- */

#pragma pack(push, 1)
struct Elf64_Ehdr {
  uint8_t  e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};
struct Elf32_Ehdr {
  uint8_t  e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint32_t e_entry;
  uint32_t e_phoff;
  uint32_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};
struct Elf64_Phdr {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};
struct Elf32_Phdr {
  uint32_t p_type;
  uint32_t p_offset;
  uint32_t p_vaddr;
  uint32_t p_paddr;
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint32_t p_flags;
  uint32_t p_align;
};
#pragma pack(pop)

#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_PHDR    6
#define PT_TLS     7
#define PT_GNU_EH_FRAME 0x6474e550
#define PT_GNU_STACK    0x6474e551
#define PT_GNU_RELRO    0x6474e552

static const char *elf_phdr_type_name(uint32_t p_type) {
  switch (p_type) {
  case PT_NULL:    return "NULL";
  case PT_LOAD:    return "LOAD";
  case PT_DYNAMIC: return "DYNAMIC";
  case PT_INTERP:  return "INTERP";
  case PT_NOTE:    return "NOTE";
  case PT_PHDR:    return "PHDR";
  case PT_TLS:     return "TLS";
  case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
  case PT_GNU_STACK:    return "GNU_STACK";
  case PT_GNU_RELRO:    return "GNU_RELRO";
  default:         return "???";
  }
}

static bool parse_elf_header(const std::vector<uint8_t> &data, ElfState::Meta &meta) {
  meta = {};
  if (data.size() < 52U) return false;

  /* Check ELF magic */
  if (data[0] != 0x7fU || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
    meta.elf_class = 0;
    return false;
  }

  const uint8_t elf_class = data[4]; /* 1=32-bit, 2=64-bit */
  meta.elf_class = elf_class;

  if (elf_class == 2) {
    /* 64-bit ELF */
    if (data.size() < sizeof(Elf64_Ehdr)) return false;
    Elf64_Ehdr ehdr;
    std::memcpy(&ehdr, data.data(), sizeof(ehdr));
    meta.elf_type    = ehdr.e_type;
    meta.elf_machine = ehdr.e_machine;
    meta.entry_point = ehdr.e_entry;

    if (ehdr.e_phoff == 0U || ehdr.e_phnum == 0U) return true;
    if (ehdr.e_phentsize < sizeof(Elf64_Phdr)) return false;

    for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
      uint64_t offset = ehdr.e_phoff + static_cast<uint64_t>(i) * ehdr.e_phentsize;
      if (offset + sizeof(Elf64_Phdr) > data.size()) break;
      Elf64_Phdr phdr;
      std::memcpy(&phdr, data.data() + offset, sizeof(phdr));
      if (phdr.p_type == PT_NULL) continue;
      ElfState::Segment seg;
      seg.name    = elf_phdr_type_name(phdr.p_type);
      seg.vaddr   = phdr.p_vaddr;
      seg.memsz   = phdr.p_memsz;
      seg.filesz  = phdr.p_filesz;
      seg.p_offset = phdr.p_offset;
      seg.p_type  = phdr.p_type;
      seg.flags   = phdr.p_flags;
      meta.segments.push_back(seg);
    }
  } else if (elf_class == 1) {
    /* 32-bit ELF */
    if (data.size() < sizeof(Elf32_Ehdr)) return false;
    Elf32_Ehdr ehdr;
    std::memcpy(&ehdr, data.data(), sizeof(ehdr));
    meta.elf_type    = ehdr.e_type;
    meta.elf_machine = ehdr.e_machine;
    meta.entry_point = static_cast<uint64_t>(ehdr.e_entry);

    if (ehdr.e_phoff == 0U || ehdr.e_phnum == 0U) return true;
    if (ehdr.e_phentsize < sizeof(Elf32_Phdr)) return false;

    for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
      uint64_t offset = static_cast<uint64_t>(ehdr.e_phoff) + static_cast<uint64_t>(i) * ehdr.e_phentsize;
      if (offset + sizeof(Elf32_Phdr) > data.size()) break;
      Elf32_Phdr phdr;
      std::memcpy(&phdr, data.data() + offset, sizeof(phdr));
      if (phdr.p_type == PT_NULL) continue;
      ElfState::Segment seg;
      seg.name    = elf_phdr_type_name(phdr.p_type);
      seg.vaddr   = phdr.p_vaddr;
      seg.memsz   = phdr.p_memsz;
      seg.filesz  = phdr.p_filesz;
      seg.p_offset = phdr.p_offset;
      seg.p_type  = phdr.p_type;
      seg.flags   = phdr.p_flags;
      meta.segments.push_back(seg);
    }
  } else {
    return false;
  }
  return true;
}

static void load_elf_file(AppState &state, const std::string &path) {
  std::snprintf(state.elf.load_path, sizeof(state.elf.load_path), "%s", path.c_str());
  state.elf.meta_valid = false;
  state.elf.meta = {};

  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file) {
    set_status(state, locale::tr("processes.elf_cannot_open"));
    return;
  }
  std::streamsize sz = file.tellg();
  if (sz <= 0 || static_cast<uint64_t>(sz) > (64ULL << 20)) {
    set_status(state, locale::tr("processes.elf_too_large"));
    return;
  }
  file.seekg(0, std::ios::beg);
  std::vector<uint8_t> data(static_cast<size_t>(sz));
  if (!file.read(reinterpret_cast<char *>(data.data()), sz)) {
    set_status(state, locale::tr("processes.elf_cannot_open"));
    return;
  }

  if (!parse_elf_header(data, state.elf.meta)) {
    char magic_buf[64];
    if (data.size() >= 4U)
      std::snprintf(magic_buf, sizeof(magic_buf),
                    locale::tr("processes.elf_invalid_magic"),
                    data[0], data[1], data[2], data[3]);
    else
      std::snprintf(magic_buf, sizeof(magic_buf), "%s", locale::tr("processes.elf_cannot_open"));
    set_status(state, magic_buf);
    return;
  }
  state.elf.meta_valid = true;

  /* Add to recent files (deduplicate, keep most recent 5) */
  auto &recent = state.elf.recent_files;
  recent.erase(std::remove(recent.begin(), recent.end(), path), recent.end());
  recent.insert(recent.begin(), path);
  if (recent.size() > ElfState::kMaxRecent) recent.resize(ElfState::kMaxRecent);

  char elf_buf[256];
  std::snprintf(elf_buf, sizeof(elf_buf), locale::tr("processes.elf_dropped"),
                std::filesystem::path(path).filename().string().c_str());
  set_status(state, elf_buf);
}

static void request_elf_load(AppState &state) {
  if (!state.client.connected() || state.selected_pid <= 0) return;
  if (state.elf.load_pending || state.connect_pending) return;

  const char *fpath = state.elf.load_path;
  if (fpath[0] == '\0') {
    set_status(state, locale::tr("processes.elf_select"));
    return;
  }

  std::ifstream file(fpath, std::ios::binary | std::ios::ate);
  if (!file) { set_status(state, locale::tr("processes.elf_cannot_open")); return; }
  std::streamsize sz = file.tellg();
  if (sz <= 0 || static_cast<uint64_t>(sz) > (64ULL << 20)) {
    set_status(state, locale::tr("processes.elf_too_large")); return;
  }
  file.seekg(0, std::ios::beg);
  std::vector<uint8_t> elf_data(static_cast<size_t>(sz));
  if (!file.read(reinterpret_cast<char *>(elf_data.data()), sz)) {
    set_status(state, locale::tr("processes.elf_cannot_open")); return;
  }

  state.elf.load_pending = true;
  state.elf.load_error.clear();
  state.elf.load_op = "Load ELF";
  state.elf.load_start_time = ImGui::GetTime();
  state.elf.hijack_accepted = false;
  state.elf.load_result = {};
  state.elf.load_cancel_requested = false;

  const int32_t pid = state.selected_pid;
  const uint32_t flags = state.elf.jump_entry ? 1U : 0U;
  const uint32_t match_flags = state.elf.match_flags;
  const std::string target_region = state.elf.target_region;
  state.elf.load_client = state.pool.control_lease();
  auto client = state.elf.load_client;

  state.action_journal.record("elf_load", ("{\"pid\":" + std::to_string(pid) + ",\"path\":\"" + ActionJournal::json_escape(fpath) + "\"}").c_str());

  state.elf.load_future = std::async(std::launch::async,
      [client = std::move(client), pid, flags, match_flags, target_region,
       elf_data = std::move(elf_data)]() -> ElfState::Outcome {
        try {
          Client::ProcessElfLoadResult result;
          if (!client->process_elf_load(pid, elf_data, flags, target_region,
                                        match_flags, result)) {
            return {false, false, {}, client->last_error()};
          }
          return {true, false, result, {}};
        } catch (const std::exception &ex) {
          return {false, false, {}, ex.what()};
        }
      });
}

static void request_elf_hijack(AppState &state) {
  if (!state.client.connected() || state.selected_pid <= 0) return;
  if (state.elf.load_pending || state.connect_pending) return;

  const char *fpath = state.elf.load_path;
  if (fpath[0] == '\0') {
    set_status(state, locale::tr("processes.elf_select"));
    return;
  }

  std::ifstream file(fpath, std::ios::binary | std::ios::ate);
  if (!file) { set_status(state, locale::tr("processes.elf_cannot_open")); return; }
  std::streamsize sz = file.tellg();
  if (sz <= 0 || static_cast<uint64_t>(sz) > (64ULL << 20)) {
    set_status(state, locale::tr("processes.elf_too_large")); return;
  }
  file.seekg(0, std::ios::beg);
  std::vector<uint8_t> elf_data(static_cast<size_t>(sz));
  if (!file.read(reinterpret_cast<char *>(elf_data.data()), sz)) {
    set_status(state, locale::tr("processes.elf_cannot_open")); return;
  }

  state.elf.load_pending = true;
  state.elf.load_error.clear();
  state.elf.load_op = "Hijack";
  state.elf.load_start_time = ImGui::GetTime();
  state.elf.hijack_accepted = false;
  state.elf.load_result = {};
  state.elf.load_cancel_requested = false;

  const int32_t pid = state.selected_pid;
  const uint32_t match_flags = state.elf.match_flags;
  const std::string target_region = state.elf.target_region;
  state.elf.load_client = state.pool.control_lease();
  auto client = state.elf.load_client;

  state.action_journal.record("elf_hijack", ("{\"pid\":" + std::to_string(pid) + ",\"path\":\"" + ActionJournal::json_escape(fpath) + "\"}").c_str());

  state.elf.load_future = std::async(std::launch::async,
      [client = std::move(client), pid, match_flags, target_region,
       elf_data = std::move(elf_data)]() -> ElfState::Outcome {
        try {
          bool accepted = false;
          constexpr uint32_t flags = 3U; /* spawn thread + resume target */
          if (!client->process_hijack(pid, elf_data, flags, target_region,
                                      match_flags, accepted)) {
            return {false, false, {}, client->last_error()};
          }
          return {true, accepted, {}, {}};
        } catch (const std::exception &ex) {
          return {false, false, {}, ex.what()};
        }
      });
}

static void poll_elf_load(AppState &state) {
  if (!state.elf.load_pending) return;
  if (!state.elf.load_future.valid()) {
    state.elf.load_pending = false;
    return;
  }
  auto status = state.elf.load_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) {
    double elapsed = ImGui::GetTime() - state.elf.load_start_time;
    if (elapsed > 120.0 && !state.elf.load_cancel_requested) {
      state.elf.load_cancel_requested = true;
      if (state.elf.load_client)
        state.elf.load_client->cancel_pending_io();
      state.elf.load_error = "ELF operation timed out after 120s";
      set_status(state, state.elf.load_error);
    }
    return;
  }
  state.elf.load_pending = false;
  state.elf.load_client.reset();
  ElfState::Outcome outcome;
  try {
    outcome = state.elf.load_future.get();
  } catch (const std::exception &ex) {
    outcome.error = ex.what();
  } catch (...) {
    outcome.error = locale::tr("processes.elf_unknown_error");
  }
  const bool ok = outcome.ok;
  if (!outcome.error.empty() && !state.elf.load_cancel_requested)
    state.elf.load_error = std::move(outcome.error);
  state.elf.load_result = outcome.load_result;

  if (!ok && !state.elf.load_error.empty()) {
    char ef_buf[512];
    std::snprintf(ef_buf, sizeof(ef_buf), locale::tr("processes.elf_failed"),
                  state.elf.load_op.c_str(), state.elf.load_error.c_str());
    set_status(state, ef_buf);
    return;
  }

  if (state.elf.load_op == "Hijack") {
    if (ok && outcome.accepted) {
      state.elf.hijack_accepted = true;
      set_status(state, locale::tr("processes.elf_hijack_started"));
      push_notification(state, locale::tr("processes.elf_hijack_started"), 4.0);
    } else {
      state.elf.hijack_accepted = false;
      state.elf.load_error = state.elf.load_error.empty()
          ? locale::tr("processes.elf_hijack_rejected")
          : state.elf.load_error;
      set_status(state, state.elf.load_error);
    }
  } else {
    if (ok) {
      char el_buf[256];
      std::snprintf(el_buf, sizeof(el_buf), locale::tr("processes.elf_loaded_at"),
                    hex_u64(state.elf.load_result.load_base).c_str(),
                    hex_u64(state.elf.load_result.entry_address).c_str());
      set_status(state, el_buf);
      push_notification(state, el_buf, 5.0);
    } else {
      if (state.elf.load_error.empty())
        state.elf.load_error = locale::tr("processes.elf_unknown_error");
      char ef_buf[512];
      std::snprintf(ef_buf, sizeof(ef_buf), locale::tr("processes.elf_failed"),
                    state.elf.load_op.c_str(), state.elf.load_error.c_str());
      set_status(state, ef_buf);
    }
  }
}

static void draw_elf_section(AppState &state) {
  const float scl = ui::dpi_scale();
  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  /* Collapsible header */
  const char *header_label = locale::tr("processes.elf_header");
  if (ImGui::TreeNodeEx(header_label, ImGuiTreeNodeFlags_DefaultOpen | ImGuiTreeNodeFlags_Framed)) {
    /* File selection row */
    if (!state.elf.recent_files.empty()) {
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("processes.elf_recent"));
      ImGui::SameLine();
      ImGui::SetNextItemWidth(200.0f * scl);
      static int recent_sel = -1;
      if (ImGui::BeginCombo("##ElfRecent", recent_sel >= 0 && recent_sel < static_cast<int>(state.elf.recent_files.size())
          ? std::filesystem::path(state.elf.recent_files[recent_sel]).filename().string().c_str()
          : locale::tr("processes.elf_select"))) {
        for (int i = 0; i < static_cast<int>(state.elf.recent_files.size()); ++i) {
          bool is_sel = (recent_sel == i);
          if (ImGui::Selectable(state.elf.recent_files[i].c_str(), is_sel)) {
            recent_sel = i;
            load_elf_file(state, state.elf.recent_files[i]);
          }
          if (is_sel) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
      }
      ImGui::SameLine();
    }

    if (ui::soft_button(locale::tr("processes.elf_select"), ImVec2(120.0f * scl, 28.0f * scl))) {
      std::string picked = ui::pickFile(locale::tr("processes.elf_select"), "ELF files", "*.elf;*.bin;*.so;*.prx;*.sprx");
      if (!picked.empty()) load_elf_file(state, picked);
    }

    if (state.elf.load_path[0] != '\0') {
      ImGui::SameLine();
      ImGui::TextColored(ui::colors().primary2, "%s",
                         std::filesystem::path(state.elf.load_path).filename().string().c_str());
    } else {
      ImGui::SameLine();
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("processes.elf_no_file"));
    }

    /* ELF metadata */
    if (state.elf.meta_valid) {
      ImGui::Spacing();
      const auto &meta = state.elf.meta;
      const char *elf_type_str = meta.elf_type == 2 ? "ET_EXEC" : meta.elf_type == 3 ? "ET_DYN" : "??";
      const char *machine_str = "??";
      switch (meta.elf_machine) {
      case 3:   machine_str = locale::tr("processes.elf_machine_386"); break;
      case 62:  machine_str = locale::tr("processes.elf_machine_x86_64"); break;
      case 183: machine_str = locale::tr("processes.elf_machine_aarch64"); break;
      case 40:  machine_str = locale::tr("processes.elf_machine_arm"); break;
      }

      ImGui::TextColored(ui::colors().muted, locale::tr("processes.elf_metadata_line"),
                         meta.elf_class == 2 ? 64 : 32, elf_type_str, machine_str);
      ImGui::TextColored(ui::colors().dim, locale::tr("processes.elf_entry"),
                         hex_u64(meta.entry_point).c_str());

      /* Architecture mismatch warning */
      if (state.has_hello) {
        bool mismatch = false;
        const char *elf_arch = "";
        const char *payload_arch = "";
        if (meta.elf_machine == 62) {
          elf_arch = locale::tr("processes.elf_arch_x86_64");
          mismatch = (state.hello.platform_id == MEMDBG_PLATFORM_PS5);
        } else if (meta.elf_machine == 183) {
          elf_arch = locale::tr("processes.elf_arch_aarch64");
          mismatch = (state.hello.platform_id == MEMDBG_PLATFORM_PS4);
        }
        switch (state.hello.platform_id) {
        case MEMDBG_PLATFORM_PS4: payload_arch = locale::tr("processes.elf_arch_x86_64"); break;
        case MEMDBG_PLATFORM_PS5: payload_arch = locale::tr("processes.elf_arch_aarch64"); break;
        default: payload_arch = locale::tr("processes.elf_unknown"); break;
        }
        if (mismatch) {
          ImGui::TextColored(ui::colors().danger, locale::tr("processes.elf_arch_mismatch"),
                             elf_arch, payload_arch);
          ImGui::TextWrapped("%s", locale::tr("processes.elf_arch_mismatch_tip"));
        }
      }

      /* Segments table */
      if (!meta.segments.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ui::colors().primary2, "%s (%zu)", locale::tr("processes.elf_segments"), meta.segments.size());
        if (ImGui::BeginTable("ElfSegments", 7,
              ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
              ImVec2(0, std::min<float>(static_cast<float>(meta.segments.size() + 1) * ImGui::GetTextLineHeightWithSpacing() + 4.0f, 180.0f * scl)))) {
          ImGui::TableSetupColumn(locale::tr("processes.elf_segments_type_col"), ImGuiTableColumnFlags_WidthFixed, 100);
          ImGui::TableSetupColumn(locale::tr("processes.elf_segments_offset_col"), ImGuiTableColumnFlags_WidthFixed, 80);
          ImGui::TableSetupColumn(locale::tr("processes.elf_segments_vaddr_col"), ImGuiTableColumnFlags_WidthFixed, 110);
          ImGui::TableSetupColumn(locale::tr("processes.elf_segments_memsz_col"), ImGuiTableColumnFlags_WidthFixed, 80);
          ImGui::TableSetupColumn(locale::tr("processes.elf_segments_filesz_col"), ImGuiTableColumnFlags_WidthFixed, 80);
          ImGui::TableSetupColumn(locale::tr("processes.elf_segments_flags_col"), ImGuiTableColumnFlags_WidthFixed, 55);
          ImGui::TableSetupColumn("##SegName");
          ImGui::TableHeadersRow();
          for (const auto &seg : meta.segments) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(seg.name.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("0x%llX", static_cast<unsigned long long>(seg.p_offset));
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", hex_u64(seg.vaddr).c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("0x%llX", static_cast<unsigned long long>(seg.memsz));
            ImGui::TableSetColumnIndex(4);
            ImGui::Text("0x%llX", static_cast<unsigned long long>(seg.filesz));
            ImGui::TableSetColumnIndex(5);
            ImGui::Text("%c%c%c",
                        (seg.flags & 4U) ? 'R' : '-',
                        (seg.flags & 2U) ? 'W' : '-',
                        (seg.flags & 1U) ? 'X' : '-');
            ImGui::TableSetColumnIndex(6);
            ImGui::TextColored(ui::colors().dim, "%s",
                               seg.name == "LOAD" ? "Segment" : "");
          }
          ImGui::EndTable();
        }
      }
    }

    ImGui::Spacing();

    /* Target region input */
    ImGui::SetNextItemWidth(300.0f * scl);
    ImGui::InputTextWithHint("##ElfTargetRegion", locale::tr("processes.elf_target_region_tip"),
                             state.elf.target_region, sizeof(state.elf.target_region));
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("processes.elf_target_region_tip"));
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, "%s", locale::tr("processes.elf_target_region"));

    /* Jump to entry */
    ImGui::Checkbox(locale::tr("processes.elf_jump_entry"), &state.elf.jump_entry);

    /* Match flags */
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, "%s", locale::tr("processes.elf_match_flags"));
    ImGui::SameLine();
    bool exact = (state.elf.match_flags & MEMDBG_MATCH_EXACT) != 0U;
    if (ImGui::Checkbox(locale::tr("processes.elf_match_exact"), &exact)) {
      if (exact) state.elf.match_flags |= MEMDBG_MATCH_EXACT;
      else       state.elf.match_flags &= ~MEMDBG_MATCH_EXACT;
    }
    ImGui::SameLine();
    bool case_sens = (state.elf.match_flags & MEMDBG_MATCH_CASE_SENSITIVE) != 0U;
    if (ImGui::Checkbox(locale::tr("processes.elf_match_case_sensitive"), &case_sens)) {
      if (case_sens) state.elf.match_flags |= MEMDBG_MATCH_CASE_SENSITIVE;
      else           state.elf.match_flags &= ~MEMDBG_MATCH_CASE_SENSITIVE;
    }
    ImGui::SameLine();
    bool regex = (state.elf.match_flags & MEMDBG_MATCH_REGEX) != 0U;
    if (ImGui::Checkbox(locale::tr("processes.elf_match_regex"), &regex)) {
      if (regex) state.elf.match_flags |= MEMDBG_MATCH_REGEX;
      else       state.elf.match_flags &= ~MEMDBG_MATCH_REGEX;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("processes.elf_match_regex_tip"));
    ImGui::SameLine();
    bool fullpath = (state.elf.match_flags & MEMDBG_MATCH_FULLPATH) != 0U;
    if (ImGui::Checkbox(locale::tr("processes.elf_match_fullpath"), &fullpath)) {
      if (fullpath) state.elf.match_flags |= MEMDBG_MATCH_FULLPATH;
      else          state.elf.match_flags &= ~MEMDBG_MATCH_FULLPATH;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("processes.elf_match_fullpath_tip"));

    /* Action buttons */
    ImGui::Spacing();
    const bool connected = state.client.connected();
    const bool has_pid = state.selected_pid > 0;
    const bool busy = state.connect_pending || state.elf.load_pending;
    const bool can_act = connected && has_pid && !busy && state.elf.load_path[0] != '\0';

    ImGui::BeginDisabled(!can_act);
    if (ui::primary_button(locale::tr("processes.elf_load"), ImVec2(130.0f * scl, 32.0f * scl)))
      request_elf_load(state);
    ImGui::SameLine();
    if (ui::soft_button(locale::tr("processes.elf_hijack"), ImVec2(100.0f * scl, 32.0f * scl)))
      ImGui::OpenPopup("ConfirmElfHijack");
    ImGui::EndDisabled();

    if (state.elf.load_pending)
      ImGui::TextColored(ui::colors().warning, locale::tr("processes.elf_load_progress"),
                         state.elf.load_op.c_str(), ImGui::GetTime() - state.elf.load_start_time);

    /* Hijack confirmation modal */
    static bool skip_elf_hijack_confirm = false;
    if (ui::confirm_modal("ConfirmElfHijack",
                          locale::tr("processes.elf_hijack_confirm_title"),
                          locale::tr("processes.elf_hijack_confirm_desc"),
                          &skip_elf_hijack_confirm, true)) {
      request_elf_hijack(state);
    }

    ImGui::TreePop();
  }
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
      const auto cached = state.taskmgr_resources.find(process.pid);
      if (cached != state.taskmgr_resources.end() && cached->second.has_info)
        ImGui::TextColored(ui::colors().primary2, "%s",
                           cached->second.info.title_id.c_str());
      else if (state.has_process_info && state.selected_pid == process.pid)
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

static void draw_maps_table(AppState &state, float height) {
  if (state.selected_pid <= 0) {
    ui::draw_empty_state(locale::tr("processes.no_process_selected"), locale::tr("processes.no_process_desc"));
    return;
  }
  if (ImGui::BeginTable("MapsTable", 7,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|
        ImGuiTableFlags_Resizable|ImGuiTableFlags_SizingStretchProp,
        ImVec2(0, height))) {
    ImGui::TableSetupColumn("##selected", ImGuiTableColumnFlags_WidthFixed, 30);
    ImGui::TableSetupColumn(locale::tr("processes.start_col"),
                            ImGuiTableColumnFlags_WidthFixed, 140);
    ImGui::TableSetupColumn(locale::tr("processes.end_col"),
                            ImGuiTableColumnFlags_WidthFixed, 140);
    ImGui::TableSetupColumn(locale::tr("processes.size_col"), ImGuiTableColumnFlags_WidthFixed, 90);
    ImGui::TableSetupColumn(locale::tr("processes.prot_col"), ImGuiTableColumnFlags_WidthFixed, 58);
    ImGui::TableSetupColumn(locale::tr("processes.elf_segments_type_col"),
                            ImGuiTableColumnFlags_WidthFixed, 105);
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
      ImGui::TextUnformatted(map.type.c_str());
      ImGui::TableSetColumnIndex(6);
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

  poll_filtered_map_dump(state);
  poll_json_dump(state);
  poll_elf_load(state);

  const float left_w = std::max(360.0f, avail.x * 0.42f);

  ui::begin_panel("ProcessesPanel", locale::tr("processes.console_processes"), ImVec2(left_w, avail.y));
  if (!state.client.connected()) {
    if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("processes.refresh_processes")).c_str(), ImVec2(190, 34)))
      refresh_processes(state);
    ImGui::Spacing();
    ui::draw_empty_state(locale::tr("processes.connect_first"), locale::tr("processes.connect_first_desc"));
  } else {
    /* Button row: Refresh + Tree toggle + JSON Dump */
    ImGui::BeginDisabled(state.connect_pending || state.elf.load_pending);
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
                         state.connect_pending || state.map_refresh_pending ||
                         state.json_dump_pending || state.map_dump_pending);
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
    if (state.map_dump_pending) {
      ImGui::Spacing();
      ui::draw_scan_progress(locale::tr("processes.dump_filtered_maps"),
                             icons::kDump,
                             ImGui::GetTime() - state.map_dump_start_time,
                             ImGui::GetContentRegionAvail().x);
      const uint64_t maps_done = state.map_dump_maps_done.load();
      const uint64_t maps_total = state.map_dump_maps_total.load();
      const float map_fraction = maps_total == 0U ? 0.0f : std::min(
          1.0f, static_cast<float>(maps_done) /
                    static_cast<float>(maps_total));
      ImGui::ProgressBar(map_fraction,
                         ImVec2(ImGui::GetContentRegionAvail().x, 12.0f), "");
      ImGui::Text(locale::tr("scanner.maps_progress"),
                  static_cast<unsigned long long>(maps_done),
                  static_cast<unsigned long long>(maps_total));
      ImGui::TextColored(
          ui::colors().dim, "%s / %s",
          format_bytes(state.map_dump_bytes_done.load()).c_str(),
          format_bytes(state.map_dump_bytes_total.load()).c_str());
      ImGui::BeginDisabled(state.map_dump_cancel_requested.load());
      if (ui::danger_button(locale::tr("scanner.stop"), ImVec2(140, 34))) {
        state.map_dump_cancel_requested.store(true);
        set_status(state, locale::tr("scanner.stopping"));
      }
      ImGui::EndDisabled();
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
      detail::replace_map_selection_with_filtered(
          state.maps, state.selected_map_starts,
          [&state](const MapEntry &map) { return map_passes_filters(state, map); });
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
    /* A zero-height scrolling table consumes all remaining panel space and
       makes every section below it unreachable. Reserve a responsive, bounded
       viewport so ELF controls and diagnostics remain visible; the panel can
       still scroll as a whole on smaller windows. */
    const float remaining_y = ImGui::GetContentRegionAvail().y;
    const float maps_height = std::clamp(remaining_y * 0.58f, 220.0f, 520.0f);
    draw_maps_table(state, maps_height);

    /* ELF Load / Hijack section */
    draw_elf_section(state);
  }
  ui::end_panel();

  /* JSON Dump dialog */
  draw_json_dump_dialog(state);
}

} // namespace memdbg::frontend

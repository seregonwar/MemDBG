/*
 * MemDBG - Task Manager screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "confirm_modal.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <sstream>
#include <string>
#include <vector>

namespace memdbg::frontend {

namespace {

constexpr size_t kTaskMgrBatchInfoMax = 128U;

inline std::string format_bytes_tm(uint64_t bytes) {
  if (bytes < 1024ULL) return std::to_string(bytes) + " B";
  double v;
  const char *unit;
  if (bytes < 1024ULL * 1024ULL) {
    v = static_cast<double>(bytes) / 1024.0; unit = "KiB";
  } else if (bytes < 1024ULL * 1024ULL * 1024ULL) {
    v = static_cast<double>(bytes) / (1024.0 * 1024.0); unit = "MiB";
  } else {
    v = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0); unit = "GiB";
  }
  char buf[48];
  std::snprintf(buf, sizeof(buf), "%.2f %s", v, unit);
  return buf;
}

static uint64_t mib_to_bytes(double mib) {
  if (mib <= 0.0) return 0U;
  return static_cast<uint64_t>(mib * 1024.0 * 1024.0);
}

static std::string trim_copy(const char *text) {
  if (text == nullptr) return {};
  std::string out(text);
  while (!out.empty() && (out.front() == ' ' || out.front() == '\t')) out.erase(out.begin());
  while (!out.empty() && (out.back() == ' ' || out.back() == '\t' ||
                          out.back() == '\r' || out.back() == '\n')) {
    out.pop_back();
  }
  return out;
}

static bool parse_fmem_line(const std::string &line, TaskFmemSample &out) {
  const char *p = std::strstr(line.c_str(), "FMEM");
  if (p == nullptr) return false;

  double used = 0.0;
  double budget = 0.0;
  double gpu_used = 0.0;
  double gpu_budget = 0.0;
  char title_id[32] = {};
  char name[128] = {};
  int matched = std::sscanf(p, "FMEM %lf/ %lf %lf/ %lf %31s %127[^\n]",
                            &used, &budget, &gpu_used, &gpu_budget,
                            title_id, name);
  if (matched < 6) return false;

  out.title_id = title_id;
  out.name = trim_copy(name);
  out.used_bytes = mib_to_bytes(used);
  out.budget_bytes = mib_to_bytes(budget);
  out.loaded = !out.name.empty();
  return out.loaded;
}

static void update_fmem_from_udp_logs(AppState &state) {
  const auto stats = state.udp_listener.stats();
  if (stats.received == state.taskmgr_last_log_received) return;
  state.taskmgr_last_log_received = stats.received;

  const auto logs = state.udp_listener.snapshot();
  for (const auto &line : logs) {
    TaskFmemSample sample;
    if (!parse_fmem_line(line, sample)) continue;
    state.taskmgr_fmem_by_name[sample.name] = sample;
  }
}

static const ProcessEntry *find_process(const AppState &state, int32_t pid) {
  for (const auto &proc : state.processes)
    if (proc.pid == pid) return &proc;
  return nullptr;
}

static const TaskFmemSample *find_fmem_sample(const AppState &state,
                                              const ProcessEntry &proc) {
  if (proc.name.empty()) return nullptr;
  auto it = state.taskmgr_fmem_by_name.find(proc.name);
  return it != state.taskmgr_fmem_by_name.end() && it->second.loaded
      ? &it->second
      : nullptr;
}

static ProcessMapSummary summarize_maps(const std::vector<MapEntry> &maps) {
  ProcessMapSummary summary;
  summary.loaded = true;
  for (const auto &map : maps) {
    if (map.end <= map.start) continue;
    uint64_t size = map.end - map.start;
    summary.map_count++;
    summary.total_mapped += size;
    if (map.protection & 1U) summary.readable_bytes += size;
    if (map.protection & 2U) summary.writable_bytes += size;
    if (map.protection & 4U) summary.executable_bytes += size;
    if ((map.protection & 3U) == 3U && !(map.protection & 4U))
      summary.rw_heap_bytes += size;
  }
  return summary;
}

static void start_resource_fetch(AppState &state, int32_t pid) {
  if (pid <= 0 || !state.client.connected()) return;
  if (state.taskmgr_resource_pending || state.connect_pending ||
      state.telemetry_pending || state.scan_async_pending ||
      state.map_refresh_pending || state.taskmgr_prefetch_pending) {
    return;
  }
  if (state.taskmgr_resource_future.valid()) {
    state.taskmgr_resource_future.wait();
  }

  state.taskmgr_resource_pending = true;
  state.taskmgr_resource_pid = pid;
  state.taskmgr_resource_error.clear();
  state.taskmgr_resource_temp = TaskProcessResource{};
  state.taskmgr_resource_temp.pid = pid;

  ProcessInfo existing_info;
  bool existing_has_info = false;
  bool existing_info_failed = false;
  auto existing = state.taskmgr_resources.find(pid);
  if (existing != state.taskmgr_resources.end()) {
    existing_info = existing->second.info;
    existing_has_info = existing->second.has_info;
    existing_info_failed = existing->second.info_failed;
  }

  state.taskmgr_resource_future = std::async(std::launch::async,
      [pid, existing_info = std::move(existing_info), existing_has_info,
       existing_info_failed, &client = state.client,
       &temp = state.taskmgr_resource_temp]() -> bool {
        TaskProcessResource local;
        local.pid = pid;
        local.info = existing_info;
        local.has_info = existing_has_info;
        local.info_failed = existing_info_failed;

        std::vector<MapEntry> maps;
        if (client.process_maps(pid, maps)) {
          local.maps = summarize_maps(maps);
        } else {
          local.maps.loaded = true;
          local.maps_failed = true;
          local.error = client.last_error();
        }

        temp = std::move(local);
        return true;
      });
}

static void poll_resource_fetch(AppState &state) {
  if (!state.taskmgr_resource_pending || !state.taskmgr_resource_future.valid()) return;
  auto status = state.taskmgr_resource_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.taskmgr_resource_pending = false;
  try {
    (void)state.taskmgr_resource_future.get();
  } catch (const std::exception &ex) {
    state.taskmgr_resource_error = ex.what();
    state.taskmgr_resource_temp.maps.loaded = true;
    state.taskmgr_resource_temp.maps_failed = true;
    state.taskmgr_batch_temp_infos.clear();
    state.taskmgr_batch_temp_failed_pids.clear();
  } catch (...) {
    state.taskmgr_resource_error = "Unknown task manager resource error";
    state.taskmgr_resource_temp.maps.loaded = true;
    state.taskmgr_resource_temp.maps_failed = true;
    state.taskmgr_batch_temp_infos.clear();
    state.taskmgr_batch_temp_failed_pids.clear();
  }

  /* Merge batch process_info results into resources (UI thread only). */
  double now = ImGui::GetTime();
  if (!state.taskmgr_batch_temp_infos.empty()) {
    for (auto &info : state.taskmgr_batch_temp_infos) {
      if (info.pid <= 0) continue;
      TaskProcessResource &res = state.taskmgr_resources[info.pid];
      res.pid = info.pid;
      res.info = std::move(info);
      res.has_info = true;
      res.info_failed = false;
      res.updated_at = now;
    }
    state.taskmgr_batch_temp_infos.clear();
  }
  if (!state.taskmgr_batch_temp_failed_pids.empty()) {
    for (int32_t pid : state.taskmgr_batch_temp_failed_pids) {
      if (pid <= 0) continue;
      TaskProcessResource &res = state.taskmgr_resources[pid];
      res.pid = pid;
      res.info_failed = true;
      if (!state.taskmgr_resource_error.empty())
        res.error = state.taskmgr_resource_error;
      res.updated_at = now;
    }
    state.taskmgr_batch_temp_failed_pids.clear();
  }

  /* Merge per-pid resource fetch result (maps only, info already populated). */
  if (state.taskmgr_resource_temp.pid > 0) {
    state.taskmgr_resource_temp.updated_at = ImGui::GetTime();
    TaskProcessResource &res =
        state.taskmgr_resources[state.taskmgr_resource_temp.pid];
    res.pid = state.taskmgr_resource_temp.pid;
    if (state.taskmgr_resource_temp.has_info) {
      res.info = std::move(state.taskmgr_resource_temp.info);
      res.has_info = true;
      res.info_failed = false;
    } else if (state.taskmgr_resource_temp.info_failed) {
      res.info_failed = true;
    }
    res.maps = state.taskmgr_resource_temp.maps;
    res.maps_failed = state.taskmgr_resource_temp.maps_failed;
    res.error = std::move(state.taskmgr_resource_temp.error);
    res.updated_at = state.taskmgr_resource_temp.updated_at;
    if (!res.error.empty())
      state.taskmgr_resource_error = res.error;
    state.taskmgr_resource_temp = TaskProcessResource{};
  }
}

static bool resource_needs_fetch(const AppState &state, int32_t pid) {
  auto it = state.taskmgr_resources.find(pid);
  if (it == state.taskmgr_resources.end()) return true;
  const TaskProcessResource &res = it->second;
  return !res.maps.loaded && !res.maps_failed;
}

static void start_batch_info_fetch(AppState &state) {
  if (!state.client.connected() || state.processes.empty()) return;
  if (state.taskmgr_resource_pending || state.connect_pending ||
      state.telemetry_pending || state.scan_async_pending ||
      state.map_refresh_pending || state.taskmgr_prefetch_pending) {
    return;
  }
  if (state.taskmgr_resource_future.valid()) {
    state.taskmgr_resource_future.wait();
  }

  /* Collect the next protocol-sized batch of PIDs that don't yet have info. */
  std::vector<int32_t> pids;
  pids.reserve(kTaskMgrBatchInfoMax);
  for (const auto &proc : state.processes) {
    auto it = state.taskmgr_resources.find(proc.pid);
    if (it == state.taskmgr_resources.end() ||
        (!it->second.has_info && !it->second.info_failed)) {
      pids.push_back(proc.pid);
      if (pids.size() >= kTaskMgrBatchInfoMax) break;
    }
  }
  if (pids.empty()) return;

  state.taskmgr_resource_pending = true;
  state.taskmgr_resource_pid = 0;
  state.taskmgr_resource_error.clear();
  state.taskmgr_batch_temp_infos.clear();
  state.taskmgr_batch_temp_failed_pids.clear();

  state.taskmgr_resource_future = std::async(std::launch::async,
      [pids = std::move(pids), &client = state.client,
       &temp_infos = state.taskmgr_batch_temp_infos,
       &failed_pids = state.taskmgr_batch_temp_failed_pids,
       &error = state.taskmgr_resource_error]() -> bool {
        if (!client.batch_process_info(pids, temp_infos)) {
          error = client.last_error();
          temp_infos.clear();
          failed_pids = pids;
          return false;
        }
        return true;
      });
}

static void schedule_resource_fetch(AppState &state, double now) {
  if (!state.client.connected() || state.processes.empty()) return;
  if (state.taskmgr_resource_pending || state.taskmgr_prefetch_pending ||
      now < state.taskmgr_next_resource_fetch) return;

  /* First, check if we need a batch process_info fetch for all new PIDs */
  bool need_batch = false;
  for (const auto &proc : state.processes) {
    auto it = state.taskmgr_resources.find(proc.pid);
    if (it == state.taskmgr_resources.end() ||
        (!it->second.has_info && !it->second.info_failed)) {
      need_batch = true;
      break;
    }
  }
  if (need_batch) {
    state.taskmgr_next_resource_fetch = now + 0.08;
    start_batch_info_fetch(state);
    return;
  }

  /* Then, schedule per-pid map fetches */
  int32_t pid = 0;
  if (state.taskmgr_selected_pid > 0 &&
      resource_needs_fetch(state, state.taskmgr_selected_pid)) {
    pid = state.taskmgr_selected_pid;
  } else {
    for (const auto &proc : state.processes) {
      if (resource_needs_fetch(state, proc.pid)) {
        pid = proc.pid;
        break;
      }
    }
  }

  if (pid > 0) {
    state.taskmgr_next_resource_fetch = now + 0.04;
    start_resource_fetch(state, pid);
  }
}

static const TaskProcessResource *resource_for_pid(const AppState &state,
                                                   int32_t pid) {
  auto it = state.taskmgr_resources.find(pid);
  return it != state.taskmgr_resources.end() ? &it->second : nullptr;
}

static void select_taskmgr_process(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.processes.size())) return;
  state.taskmgr_selected_row = row;
  state.taskmgr_selected_pid = state.processes[row].pid;
  state.taskmgr_detail_open = true;
}

static void reset_taskmgr_cache(AppState &state) {
  if (state.taskmgr_resource_future.valid()) state.taskmgr_resource_future.wait();
  state.taskmgr_resource_pending = false;
  state.taskmgr_resources.clear();
  state.taskmgr_selected_row = -1;
  state.taskmgr_selected_pid = 0;
  state.taskmgr_detail_open = false;
  state.taskmgr_map_summary = ProcessMapSummary{};
  state.taskmgr_has_process_info = false;
}

static void draw_detail_title_bar(AppState &state) {
  const float scl = ui::dpi_scale();
  ImGui::TextColored(ui::colors().primary2, "%s",
                     locale::tr("taskmgr.process_detail"));
  ImGui::SameLine();
  const float close_w = 28.0f * scl;
  const float right_x = ImGui::GetWindowContentRegionMax().x - close_w;
  if (right_x > ImGui::GetCursorPosX())
    ImGui::SetCursorPosX(right_x);
  if (ui::soft_button("X##TaskMgrCloseDetail", ImVec2(close_w, 26.0f * scl))) {
    state.taskmgr_detail_open = false;
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", "Close process details");
  ImGui::Separator();
}

static std::string resource_title_text(const TaskProcessResource *res,
                                       const TaskFmemSample *fmem) {
  if (res != nullptr && res->has_info && !res->info.title_id.empty())
    return res->info.title_id;
  if (fmem != nullptr && !fmem->title_id.empty())
    return fmem->title_id;
  return "-";
}

static std::string resource_memory_text(const TaskProcessResource *res,
                                        const TaskFmemSample *fmem,
                                        bool pending) {
  if (fmem != nullptr && fmem->used_bytes > 0U) {
    if (fmem->budget_bytes > 0U)
      return format_bytes_tm(fmem->used_bytes) + " / " +
             format_bytes_tm(fmem->budget_bytes);
    return format_bytes_tm(fmem->used_bytes);
  }
  if (res != nullptr && res->maps.loaded && !res->maps_failed &&
      res->maps.total_mapped > 0U) {
    return format_bytes_tm(res->maps.total_mapped);
  }
  return pending ? "..." : "-";
}

static void draw_process_table(AppState &state, float height) {
  const float scl = ui::dpi_scale();
  if (!state.client.connected()) {
    ui::draw_empty_state(locale::tr("taskmgr.connect_first"),
                         locale::tr("taskmgr.connect_first_desc"));
    return;
  }
  if (state.processes.empty()) {
    ui::draw_empty_state(locale::tr("taskmgr.refresh_hint"),
                         "No process data available.");
    return;
  }

  if (ImGui::BeginTable("TaskMgrTable", 5,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable,
        ImVec2(0, std::max(140.0f * scl, height)))) {
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_pid"),
                            ImGuiTableColumnFlags_WidthFixed, 70.0f * scl);
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_name"),
                            ImGuiTableColumnFlags_WidthStretch, 1.5f);
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_titleid"),
                            ImGuiTableColumnFlags_WidthFixed, 112.0f * scl);
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_maps"),
                            ImGuiTableColumnFlags_WidthFixed, 72.0f * scl);
    ImGui::TableSetupColumn(locale::tr("taskmgr.col_memory"),
                            ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableHeadersRow();

    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const auto &proc = state.processes[i];
      const TaskProcessResource *res = resource_for_pid(state, proc.pid);
      const TaskFmemSample *fmem = find_fmem_sample(state, proc);
      const bool pending = state.taskmgr_resource_pending &&
                           state.taskmgr_resource_pid == proc.pid;
      const bool selected = i == state.taskmgr_selected_row;

      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      std::string pid_label = std::to_string(proc.pid) + "##tm_pid_" + std::to_string(i);
      if (ImGui::Selectable(pid_label.c_str(), selected,
                            ImGuiSelectableFlags_SpanAllColumns)) {
        select_taskmgr_process(state, i);
      }

      ImGui::TableSetColumnIndex(1);
      const char *name = proc.name.empty() ? "?" : proc.name.c_str();
      ImGui::TextUnformatted(name);
      if (ImGui::IsItemHovered() && !proc.name.empty()) ImGui::SetTooltip("%s", name);

      ImGui::TableSetColumnIndex(2);
      std::string title = resource_title_text(res, fmem);
      ImGui::TextColored(title == "-" ? ui::colors().dim : ui::colors().text,
                         "%s", title.c_str());

      ImGui::TableSetColumnIndex(3);
      if (res != nullptr && res->maps.loaded && !res->maps_failed) {
        ImGui::Text("%zu", res->maps.map_count);
      } else {
        ImGui::TextColored(ui::colors().dim, "%s", pending ? "..." : "-");
      }

      ImGui::TableSetColumnIndex(4);
      std::string memory = resource_memory_text(res, fmem, pending);
      ImGui::TextColored(memory == "-" ? ui::colors().dim : ui::colors().text,
                         "%s", memory.c_str());
    }
    ImGui::EndTable();
  }
}

static void draw_usage_bar(const char *label, uint64_t bytes, uint64_t total,
                           ImVec4 color) {
  const float scl = ui::dpi_scale();
  const float label_w = 96.0f * scl;
  float frac = total > 0U
      ? static_cast<float>(static_cast<double>(bytes) / static_cast<double>(total))
      : 0.0f;
  frac = std::clamp(frac, 0.0f, 1.0f);

  ImGui::TextColored(ui::colors().dim, "%s", label);
  ImGui::SameLine(label_w);
  std::string value = format_bytes_tm(bytes);
  ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
  ImGui::PushStyleColor(ImGuiCol_FrameBg, ui::colors().bg2);
  ImGui::ProgressBar(frac, ImVec2(ImGui::GetContentRegionAvail().x, 16.0f * scl),
                     value.c_str());
  ImGui::PopStyleColor(2);
}

static void draw_process_actions(AppState &state) {
  if (!(state.hello.capabilities & MEMDBG_CAP_PROCESS_CONTROL)) return;

  const float scl = ui::dpi_scale();
  const float avail = ImGui::GetContentRegionAvail().x;
  const bool compact = avail < 520.0f * scl;
  const float gap = 8.0f * scl;
  const float button_h = 34.0f * scl;
  const float button_w = compact
      ? avail
      : std::max(128.0f * scl, (avail - 2.0f * gap) / 3.0f);

  ImGui::BeginDisabled(client_async_busy(state));
  if (ui::soft_button((std::string(icons::kStop) + "  " +
                       locale::tr("taskmgr.stop_process")).c_str(),
                      ImVec2(button_w, button_h))) {
    if (state.client.process_stop(state.taskmgr_selected_pid))
      set_status(state, std::string(locale::tr("taskmgr.process_stopped")) +
                         " PID " + std::to_string(state.taskmgr_selected_pid));
    else
      set_status(state, state.client.last_error());
  }
  if (!compact) ImGui::SameLine(0.0f, gap);

  if (ui::soft_button((std::string(icons::kPlay) + "  " +
                       locale::tr("taskmgr.continue_process")).c_str(),
                      ImVec2(button_w, button_h))) {
    if (state.client.process_continue(state.taskmgr_selected_pid))
      set_status(state, std::string(locale::tr("taskmgr.process_continued")) +
                         " PID " + std::to_string(state.taskmgr_selected_pid));
    else
      set_status(state, state.client.last_error());
  }
  if (!compact) ImGui::SameLine(0.0f, gap);

  static bool skip_kill = false;
  if (ui::danger_button((std::string(icons::kTrash) + "  " +
                         locale::tr("taskmgr.kill_process")).c_str(),
                        ImVec2(button_w, button_h))) {
    ImGui::OpenPopup("ConfirmKill");
  }
  char kill_detail[80];
  std::snprintf(kill_detail, sizeof(kill_detail), "PID %d - %s",
                state.taskmgr_selected_pid, locale::tr("taskmgr.caution"));
  if (ui::confirm_modal("ConfirmKill", locale::tr("taskmgr.confirm_kill"),
                        kill_detail, &skip_kill, true)) {
    if (state.client.process_kill(state.taskmgr_selected_pid))
      set_status(state, std::string(locale::tr("taskmgr.process_killed")) +
                         " PID " + std::to_string(state.taskmgr_selected_pid));
    else
      set_status(state, state.client.last_error());
  }
  ImGui::EndDisabled();

  ImGui::Spacing();
  ImGui::TextColored(ui::colors().warning, "%s  %s",
                     icons::kWarning, locale::tr("taskmgr.caution"));
}

static void draw_detail_panel(AppState &state) {
  if (state.taskmgr_selected_pid <= 0) {
    ImGui::TextColored(ui::colors().muted, "%s",
                       locale::tr("taskmgr.select_pid_hint"));
    return;
  }

  const ProcessEntry *proc = find_process(state, state.taskmgr_selected_pid);
  if (proc == nullptr) {
    ImGui::TextColored(ui::colors().muted, "%s",
                       locale::tr("taskmgr.select_pid_hint"));
    return;
  }

  const TaskProcessResource *res = resource_for_pid(state, proc->pid);
  const TaskFmemSample *fmem = find_fmem_sample(state, *proc);
  const bool pending = state.taskmgr_resource_pending &&
                       state.taskmgr_resource_pid == proc->pid;
  const float scl = ui::dpi_scale();

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg3);
  ImGui::BeginChild("TaskMgrDetailHeader", ImVec2(0, 118.0f * scl), true);
  ImGui::TextColored(ui::colors().primary2, "PID %d", proc->pid);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().text, "%s", proc->name.empty() ? "?" : proc->name.c_str());

  std::string title = resource_title_text(res, fmem);
  if (title != "-")
    ImGui::TextColored(ui::colors().dim, "%s: %s",
                       locale::tr("taskmgr.title_id"), title.c_str());

  if (res != nullptr && res->has_info) {
    if (!res->info.content_id.empty())
      ImGui::TextColored(ui::colors().dim, "%s: %s",
                         locale::tr("taskmgr.content_id"), res->info.content_id.c_str());
    if (!res->info.path.empty()) {
      ImGui::TextColored(ui::colors().dim, "%s:", locale::tr("taskmgr.path"));
      ImGui::SameLine();
      ImGui::TextWrapped("%s", res->info.path.c_str());
    }
  } else if (pending) {
    ImGui::TextColored(ui::colors().dim, "%s", locale::tr("taskmgr.fetching_info"));
  }
  ImGui::EndChild();
  ImGui::PopStyleColor();

  ImGui::Spacing();

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg3);
  ImGui::BeginChild("TaskMgrResources", ImVec2(0, 172.0f * scl), true);
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("taskmgr.memory_breakdown"));
  ImGui::Separator();

  if (res != nullptr && res->maps.loaded && !res->maps_failed &&
      res->maps.total_mapped > 0U) {
    const auto &ms = res->maps;
    draw_usage_bar(locale::tr("taskmgr.total_mapped"),
                   ms.total_mapped, ms.total_mapped, ui::colors().text);
    draw_usage_bar(locale::tr("taskmgr.readable"),
                   ms.readable_bytes, ms.total_mapped, ui::colors().success);
    draw_usage_bar(locale::tr("taskmgr.writable"),
                   ms.writable_bytes, ms.total_mapped, ui::colors().primary2);
    draw_usage_bar(locale::tr("taskmgr.executable"),
                   ms.executable_bytes, ms.total_mapped, ui::colors().warning);
    draw_usage_bar(locale::tr("taskmgr.rw_heap"),
                   ms.rw_heap_bytes, ms.total_mapped, ui::colors().link);
    ImGui::TextColored(ui::colors().dim, locale::tr("taskmgr.total_maps"), ms.map_count);
  } else if (fmem != nullptr && fmem->used_bytes > 0U) {
    draw_usage_bar("FMEM", fmem->used_bytes,
                   fmem->budget_bytes > 0U ? fmem->budget_bytes : fmem->used_bytes,
                   ui::colors().primary2);
    ImGui::TextColored(ui::colors().dim, "%s",
                       "Memory sample from SceShellCore UDP logs");
  } else {
    ImGui::TextColored(ui::colors().dim, "%s",
                       pending ? locale::tr("taskmgr.fetching_info")
                               : "No resource data for this process yet");
  }
  ImGui::EndChild();
  ImGui::PopStyleColor();

  ImGui::Spacing();
  draw_process_actions(state);
}

} // namespace

void draw_taskmgr(AppState &state, ImVec2 avail) {
  const float scl = ui::dpi_scale();
  const double now = ImGui::GetTime();

  update_fmem_from_udp_logs(state);
  poll_resource_fetch(state);
  schedule_resource_fetch(state, now);

  ui::begin_panel("TaskMgrPanel", locale::tr("taskmgr.title"), avail);

  ImGui::TextColored(ui::colors().primary2, "%s", locale::tr("taskmgr.process_table"));
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%zu %s", state.processes.size(),
                     locale::tr("taskmgr.processes"));

  ImGui::SameLine();
  const float refresh_w = 172.0f * scl;
  const float right_x = ImGui::GetWindowContentRegionMax().x - refresh_w;
  if (right_x > ImGui::GetCursorPosX() + 16.0f * scl)
    ImGui::SetCursorPosX(right_x);

  ImGui::BeginDisabled(client_async_busy(state));
  if (ui::soft_button((std::string(icons::kRefresh) + "  " +
                       locale::tr("taskmgr.refresh_processes")).c_str(),
                      ImVec2(refresh_w, 30.0f * scl))) {
    if (state.client.connected()) {
      if (state.client.process_list(state.processes)) {
        reset_taskmgr_cache(state);
        set_status(state, locale::tr("taskmgr.processes_refreshed"));
      } else {
        set_status(state, state.client.last_error());
      }
    }
  }
  ImGui::EndDisabled();

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  const float content_h = std::max(180.0f * scl, ImGui::GetContentRegionAvail().y);
  const bool show_detail = state.taskmgr_detail_open &&
                           state.taskmgr_selected_pid > 0;
  const bool side_by_side = show_detail && ImGui::GetContentRegionAvail().x >= 880.0f * scl;

  if (side_by_side) {
    const float gap = 12.0f * scl;
    const float table_w = std::max(420.0f * scl,
        (ImGui::GetContentRegionAvail().x - gap) * 0.46f);
    ImGui::BeginChild("TaskMgrTablePane", ImVec2(table_w, content_h), false);
    draw_process_table(state, ImGui::GetContentRegionAvail().y);
    ImGui::EndChild();

    ImGui::SameLine(0.0f, gap);
    ImGui::BeginChild("TaskMgrDetailPane", ImVec2(0, content_h), true);
    draw_detail_title_bar(state);
    draw_detail_panel(state);
    ImGui::EndChild();
  } else {
    const float detail_h = show_detail ? 390.0f * scl : 0.0f;
    draw_process_table(state, content_h - detail_h - (show_detail ? 12.0f * scl : 0.0f));
    if (show_detail) {
      ImGui::Spacing();
      ImGui::BeginChild("TaskMgrDetailPaneStacked", ImVec2(0, detail_h), true);
      draw_detail_title_bar(state);
      draw_detail_panel(state);
      ImGui::EndChild();
    }
  }

  ui::end_panel();
}

} // namespace memdbg::frontend

/*
 * MemDBG - Scanner screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scanner_internal.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>

namespace memdbg::frontend {

/* ---- Main draw ---- */

void draw_scanner(AppState &state, ImVec2 avail) {
  poll_scanner_async(state);
  poll_structure_compare(state);

  const float gap = 16.0f;
  const float left_w = std::max(420.0f, (avail.x - gap) * 0.38f);
  const char *type_names[] = {"Bytes","u8","u16","u32","u64","float","double","pointer"};

  ui::begin_panel("ScannerControl", locale::tr("scanner.exact_scan"), ImVec2(left_w, avail.y));
  ImGui::Text(locale::tr("scanner.active_pid"), state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  ImGui::Combo(locale::tr("scanner.value_type"), &state.scan_type, type_names, IM_ARRAYSIZE(type_names));
  ImGui::InputText(locale::tr("scanner.value"), state.scan_value, sizeof(state.scan_value));
  ImGui::InputInt(locale::tr("scanner.alignment"), &state.scan_alignment);
  ImGui::InputInt(locale::tr("scanner.max_results"), &state.scan_max_results);
  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::InputText(locale::tr("scanner.start"), state.scan_start, sizeof(state.scan_start));
  ImGui::InputText(locale::tr("scanner.length"), state.scan_length, sizeof(state.scan_length));
  bool can_launch_range = !client_async_busy(state) && state.client.connected() &&
                          state.selected_pid > 0 &&
                          payload_supports(state, MEMDBG_CAP_SCAN_EXACT);
  ImGui::BeginDisabled(!can_launch_range);
  if (ui::primary_button((std::string(icons::kSearch) + "  " + locale::tr("scanner.scan_range")).c_str(), ui::full_button(40))) scan_range(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::InputText(locale::tr("scanner.end_filter"), state.scan_end, sizeof(state.scan_end));
  ImGui::Checkbox(locale::tr("scanner.readable_only"), &state.scan_readable_only);
  bool can_launch_process = !client_async_busy(state) && state.client.connected() &&
                            state.selected_pid > 0 &&
                            payload_supports(state, MEMDBG_CAP_SCAN_PROCESS_EXACT);
  ImGui::BeginDisabled(!can_launch_process);
  if (ui::soft_button((std::string(icons::kTarget) + "  " + locale::tr("scanner.scan_process")).c_str(), ui::full_button(40))) ImGui::OpenPopup("ConfirmProcessScan");
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().warning, "%s", locale::tr("scanner.unknown_value"));
  ImGui::TextWrapped("%s", locale::tr("scanner.unknown_desc"));
  bool can_launch_unknown = !client_async_busy(state) && state.client.connected() &&
                            state.selected_pid > 0 &&
                            payload_supports(state, MEMDBG_CAP_SCAN_UNKNOWN);
  ImGui::BeginDisabled(!can_launch_unknown);
  if (ui::primary_button((std::string(icons::kSearch) + "  " + locale::tr("scanner.unknown_scan")).c_str(), ui::full_button(40))) ImGui::OpenPopup("ConfirmUnknownScan");
  ImGui::EndDisabled();

  /* Progress bar for async scans */
  if (state.scan_async_pending)
    ui::draw_scan_progress(state.scan_async_label, icons::kSearch,
                           ImGui::GetTime() - state.scan_async_start_time,
                           ImGui::GetContentRegionAvail().x);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  const char *session_label = state.scan_is_unknown_session ? locale::tr("scanner.unknown_session") : locale::tr("scanner.next_scan");
  ImGui::TextColored(state.scan_is_unknown_session ? ui::colors().warning : ui::colors().muted, "%s", session_label);
  ImGui::TextWrapped("%s", state.scan_session_status);
  if (state.scan_is_unknown_session && !state.scan_snapshot.empty())
    ImGui::TextColored(ui::colors().dim, locale::tr("scanner.tracking_n"),
                       state.scan_snapshot.size(), state.scan_snapshot_value_len);
  ImGui::Spacing();

  bool can_refine = state.client.connected() && state.selected_pid > 0 &&
                    payload_supports(state, MEMDBG_CAP_MEMORY_READ) &&
                    !state.scan_snapshot.empty() && !client_async_busy(state);
  const float half_w = (ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f;
  ImGui::BeginDisabled(!can_refine);
  if (ui::soft_button(locale::tr("scanner.changed"), ImVec2(half_w, 38))) refine_scan(state, RefineMode::Changed);
  ImGui::SameLine();
  if (ui::soft_button(locale::tr("scanner.unchanged"), ImVec2(0, 38))) refine_scan(state, RefineMode::Unchanged);
  if (ui::soft_button(locale::tr("scanner.increased"), ImVec2(half_w, 38))) refine_scan(state, RefineMode::Increased);
  ImGui::SameLine();
  if (ui::soft_button(locale::tr("scanner.decreased"), ImVec2(0, 38))) refine_scan(state, RefineMode::Decreased);
  ImGui::EndDisabled();
  bool can_refresh = state.client.connected() &&
                     payload_supports(state, MEMDBG_CAP_MEMORY_READ) &&
                     !state.scan_snapshot.empty() && !client_async_busy(state);
  ImGui::BeginDisabled(!can_refresh);
  std::string next_label = std::string(icons::kRefresh) + "  " +
      std::string(state.scan_is_unknown_session ? locale::tr("scanner.next_scan_refresh_all") : locale::tr("scanner.refresh_baseline"));
  if (ui::soft_button(next_label.c_str(), ui::full_button(38))) {
    capture_scan_snapshot(state);
    set_status(state, state.scan_session_status);
  }
  ImGui::EndDisabled();

  /* ---- Smart Auto-Search ---- */
  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::Checkbox(locale::tr("scanner.smart_auto"), &state.auto_search_enabled);
  if (state.auto_search_enabled) {
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.0f);
    const char *target_names[] = {locale::tr("scanner.target_health"), locale::tr("scanner.target_ammo"), locale::tr("scanner.target_resources")};
    if (ImGui::Combo("##autotarget", &state.auto_search_target,
                     target_names, IM_ARRAYSIZE(target_names)))
      state.auto_search_has_baseline = false;

    /* Hint text — warn about critical instructions like "don't reload" */
    AutoSearchTarget hint_tgt =
        static_cast<AutoSearchTarget>(state.auto_search_target);
    ImVec4 hint_color = hint_tgt == AutoSearchTarget::Ammo
                            ? ui::colors().warning
                            : ui::colors().dim;
    ImGui::TextColored(hint_color, "%s",
                       auto_search_target_hint(hint_tgt));

    /* Baseline capture: auto-search piggybacks on the Unknown Value Scan */
    bool can_baseline = can_launch_unknown;
    ImGui::BeginDisabled(!can_baseline);
    if (ui::soft_button((std::string(icons::kTarget) + "  " + locale::tr("scanner.capture_baseline")).c_str(),
                        ui::full_button(38))) {
      ImGui::OpenPopup("ConfirmAutoBaselineScan");
    }
    ImGui::EndDisabled();

    /* Next Scan: re-read and score candidates */
    bool can_next = state.auto_search_has_baseline && can_launch_unknown &&
                    !state.scan_snapshot.empty();
    ImGui::BeginDisabled(!can_next);    char ns_buf[128];
    std::snprintf(ns_buf, sizeof(ns_buf), locale::tr("scanner.next_scan_pass"), state.auto_search_pass + 1);
    std::string auto_next_label = std::string(icons::kRefresh) + "  " + ns_buf;
    if (ui::primary_button(auto_next_label.c_str(), ui::full_button(38))) {
      /* Re-read baseline addresses and score them on the async worker.
       * We reuse the refine_scan Changed path but with scoring layered on top. */
      AutoSearchTarget tgt = static_cast<AutoSearchTarget>(state.auto_search_target);
      state.scan_async_label = "Auto-search pass " +
                               std::to_string(state.auto_search_pass + 1);
      state.scan_async_start_time = ImGui::GetTime();
      state.scan_async_pending = true;
      state.scan_async_owner = Screen::Scanner;

      const int32_t pid = state.selected_pid;
      const uint32_t val_len = state.scan_snapshot_value_len;
      const int snap_type = state.scan_snapshot_type;
      auto &client = state.client;
      auto &snap = state.scan_snapshot;
      const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;
      auto &temp_result = state.scan_async_temp_result;
      auto &temp_snapshot = state.scan_async_temp_snapshot;
      auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
      auto &temp_snap_type = state.scan_async_temp_snapshot_type;
      auto &temp_is_unknown = state.scan_async_temp_is_unknown;
      auto &temp_status = state.scan_async_temp_session_status;
      auto &temp_candidates = state.auto_search_temp_candidates;

      state.scan_async_future = std::async(std::launch::async,
        [&client, pid, val_len, snap_type, tgt, has_batch,
         &snap, &temp_result, &temp_snapshot, &temp_snap_val_len,
         &temp_snap_type, &temp_is_unknown, &temp_status,
         &temp_candidates, &mtx = state.scan_async_mtx]() -> bool {
          /* Re-read all baseline addresses */
          const auto &old_snap = snap;
          std::vector<ScanSnapshotEntry> current_snap;
          std::vector<uint64_t> current_addrs;
          current_snap.reserve(old_snap.size());
          current_addrs.reserve(old_snap.size());
          uint32_t read_errors = 0;
          uint64_t bytes_read = 0;
          const auto t_start = std::chrono::steady_clock::now();
          std::vector<memdbg_batch_read_item_t> batch_items;

          if (has_batch) {
            batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
            for (size_t base = 0U; base < old_snap.size();
                 base += MEMDBG_BATCH_READ_MAX_ITEMS) {
              batch_items.clear();
              size_t chunk_end = std::min(
                  base + MEMDBG_BATCH_READ_MAX_ITEMS, old_snap.size());
              for (size_t i = base; i < chunk_end; ++i) {
                memdbg_batch_read_item_t item{};
                item.address = old_snap[i].address;
                item.length  = val_len;
                batch_items.push_back(item);
              }
              Client::BatchReadResult batch;
              if (!client.batch_read(pid, batch_items, batch)) {
                read_errors += static_cast<uint32_t>(chunk_end - base);
                continue;
              }
              uint32_t data_offset = 0U;
              for (size_t j = 0U; j < batch.entries.size(); ++j) {
                const auto &entry = batch.entries[j];
                if (entry.status != 0U || entry.length != val_len) {
                  read_errors++;
                  data_offset += entry.length;
                  continue;
                }
                ScanSnapshotEntry cur;
                cur.address = entry.address;
                cur.bytes.assign(batch.data.begin() + data_offset,
                                 batch.data.begin() + data_offset + entry.length);
                current_snap.push_back(std::move(cur));
                current_addrs.push_back(entry.address);
                bytes_read += entry.length;
                data_offset += entry.length;
              }
            }
          } else {
            for (size_t i = 0U; i < old_snap.size(); ++i) {
              std::vector<uint8_t> data;
              if (!client.memory_read(pid, old_snap[i].address, val_len, data) ||
                  data.size() != val_len) {
                read_errors++;
                continue;
              }
              ScanSnapshotEntry cur;
              cur.address = old_snap[i].address;
              cur.bytes   = std::move(data);
              current_snap.push_back(std::move(cur));
              current_addrs.push_back(old_snap[i].address);
              bytes_read += val_len;
            }
          }

          /* Run auto-search engine */
          AutoSearchEngine engine;
          engine.set_target(tgt);
          engine.set_baseline(old_snap, snap_type, val_len);
          auto candidates = engine.score_candidates(current_snap, 100);

          /* Store scored candidates and build new snapshot under lock */
          {
            std::lock_guard<std::mutex> lock(mtx);
            temp_candidates = std::move(candidates);

            /* Build new snapshot from the top candidates (keep them for next pass) */
            temp_snapshot.clear();
          temp_snapshot.reserve(candidates.size());
          temp_result.addresses.clear();
          temp_result.addresses.reserve(candidates.size());
          for (auto &c : candidates) {
            /* Map candidate back to current snapshot bytes */
            for (const auto &cs : current_snap) {
              if (cs.address == c.address) {
                ScanSnapshotEntry se;
                se.address = c.address;
                se.bytes   = cs.bytes;
                temp_snapshot.push_back(std::move(se));
                break;
              }
            }
            temp_result.addresses.push_back(c.address);
          }
          temp_result.count = static_cast<uint32_t>(temp_result.addresses.size());
          temp_result.bytes_scanned = bytes_read;
          temp_result.read_calls = static_cast<uint32_t>(current_snap.size() + read_errors);
          temp_snap_val_len = val_len;
          temp_snap_type = snap_type;
          temp_is_unknown = false;

          const auto t_end = std::chrono::steady_clock::now();
          const uint64_t elapsed_ns = static_cast<uint64_t>(
              std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count());
          temp_result.elapsed_ns = elapsed_ns;
          temp_result.read_errors = read_errors;
          std::snprintf(temp_status, sizeof(temp_status),
                        "Auto-search: %u candidates scored (%s)",
                        temp_result.count,
                        bytes_per_second(bytes_read, elapsed_ns).c_str());
          }
          return true;
        });
    }
    ImGui::EndDisabled();

    if (state.auto_search_has_baseline && !state.scan_snapshot.empty())
      ImGui::TextColored(ui::colors().dim, locale::tr("scanner.baseline_n_values"),
                         state.scan_snapshot.size());
    if (state.auto_search_pass > 0)
      ImGui::TextColored(ui::colors().success, locale::tr("scanner.pass_n_complete"),
                         state.auto_search_pass);

    /* Reset button */
    if (state.auto_search_has_baseline) {
      ImGui::SameLine();
      if (ImGui::SmallButton(locale::tr("scanner.reset"))) {
        state.auto_search_has_baseline = false;
        state.auto_search_pass = 0;
        state.auto_search_candidates.clear();
        set_status(state, locale::tr("scanner.auto_search_reset"));
      }
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", locale::tr("scanner.reset_tooltip"));
    }

    /* Display scored candidates if available */
    if (!state.auto_search_candidates.empty()) {
      ImGui::Spacing();
      ImGui::TextColored(ui::colors().primary2, "%s", locale::tr("scanner.top_candidates"));
      ImGui::Spacing();
      if (ImGui::BeginTable("AutoSearchResults", 4,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
            ImVec2(0, 200.0f))) {
        ImGui::TableSetupColumn(locale::tr("scanner.score_col"), ImGuiTableColumnFlags_WidthFixed, 55);
        ImGui::TableSetupColumn(locale::tr("scanner.address_col"), ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn(locale::tr("scanner.old_new_col"));
        ImGui::TableSetupColumn(locale::tr("scanner.reason_col"));
        ImGui::TableHeadersRow();
        for (size_t i = 0U;
             i < state.auto_search_candidates.size() && i < 20U; ++i) {
          const auto &c = state.auto_search_candidates[i];
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          /* Color-code score: green > 0.7, yellow > 0.4, dim otherwise */
          ImVec4 sc = c.score > 0.7f ? ui::colors().success :
                      c.score > 0.4f ? ui::colors().warning : ui::colors().dim;
          ImGui::TextColored(sc, "%.2f", c.score);
          ImGui::TableSetColumnIndex(1);
          std::string addr_label = hex_u64(c.address) + "##ac" +
                                   std::to_string(i);
          if (ImGui::Selectable(addr_label.c_str())) {
            std::snprintf(state.read_address, sizeof(state.read_address),
                          "%s", hex_u64(c.address).c_str());
            std::snprintf(state.write_address, sizeof(state.write_address),
                          "%s", hex_u64(c.address).c_str());
            state.screen = Screen::Memory;
          }
          ImGui::TableSetColumnIndex(2);
          ImGui::Text("%s \xe2\x86\x92 %s",
                      c.old_value_str().c_str(), c.new_value_str().c_str());
          ImGui::TableSetColumnIndex(3);
          ImGui::TextColored(ui::colors().muted, "%s", c.reason().c_str());
          if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s: %s", locale::tr("scanner.value_type"), value_type_name(c.value_type));
        }
        ImGui::EndTable();
      }
    }
  }

  static bool skip_process_scan_confirm = false;
  static bool skip_unknown_scan_confirm = false;
  static bool skip_auto_baseline_confirm = false;
  if (ui::confirm_modal("ConfirmProcessScan",
                        "Scan the selected process maps?",
                        "Process-wide scans walk the target map list and can stress unstable console sessions. Prefer a selected map or tight start/end filter first.",
                        &skip_process_scan_confirm, true)) {
    scan_process(state);
  }
  if (ui::confirm_modal("ConfirmUnknownScan",
                        "Start an unknown-value process scan?",
                        "Unknown-value scans snapshot many addresses for later refinement. Keep filters readable-only and narrow on fragile targets.",
                        &skip_unknown_scan_confirm, true)) {
    scan_unknown_process(state);
  }
  if (ui::confirm_modal("ConfirmAutoBaselineScan",
                        "Capture an auto-search baseline?",
                        "This runs an unknown-value scan and keeps a baseline snapshot. Use a narrow window if the target has caused read faults before.",
                        &skip_auto_baseline_confirm, true)) {
    state.auto_search_has_baseline = false;
    state.auto_search_pass = 0;
    scan_unknown_process(state);
  }

  /* ---- Structure Compare ---- */
  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  if (ImGui::CollapsingHeader(locale::tr("scanner.structure_compare"),
                              ImGuiTreeNodeFlags_DefaultOpen)) {
    ImGui::TextWrapped("%s", locale::tr("scanner.structure_compare_desc"));
    ImGui::Spacing();
    ImGui::InputText("Player base", state.structure_player_base,
                     sizeof(state.structure_player_base));
    ImGui::InputText("Enemy A base", state.structure_enemy_a_base,
                     sizeof(state.structure_enemy_a_base));
    ImGui::Checkbox("Compare a second enemy", &state.structure_compare_has_enemy_b);
    if (state.structure_compare_has_enemy_b) {
      ImGui::InputText("Enemy B base", state.structure_enemy_b_base,
                       sizeof(state.structure_enemy_b_base));
    }
    ImGui::InputInt("Structure size (bytes)", &state.structure_compare_size);
    state.structure_compare_size = std::clamp(state.structure_compare_size, 1, 64 * 1024);

    static const int structure_types[] = {
        MEMDBG_VALUE_U8, MEMDBG_VALUE_U16, MEMDBG_VALUE_U32, MEMDBG_VALUE_U64,
        MEMDBG_VALUE_F32, MEMDBG_VALUE_F64, MEMDBG_VALUE_POINTER,
    };
    static const char *structure_type_names[] = {
        "u8", "u16", "u32", "u64", "float", "double", "pointer",
    };
    int type_index = 0;
    for (int i = 0; i < IM_ARRAYSIZE(structure_types); ++i) {
      if (state.structure_compare_type == structure_types[i]) {
        type_index = i;
        break;
      }
    }
    if (ImGui::Combo("Field type", &type_index, structure_type_names,
                     IM_ARRAYSIZE(structure_type_names))) {
      state.structure_compare_type = structure_types[type_index];
    }

    const bool can_compare = state.client.connected() && state.selected_pid > 0 &&
                             payload_supports(state, MEMDBG_CAP_MEMORY_READ) &&
                             !client_async_busy(state);
    ImGui::BeginDisabled(!can_compare);
    if (ui::primary_button((std::string(icons::kTarget) +
                            "  Compare player vs enemies").c_str(),
                           ui::full_button(38))) {
      start_structure_compare(state);
    }
    ImGui::EndDisabled();

    if (state.structure_compare_pending) {
      ui::draw_scan_progress("Comparing structures", icons::kTarget,
                             ImGui::GetTime() - state.structure_compare_start_time,
                             ImGui::GetContentRegionAvail().x);
    }
    ImGui::TextColored(ui::colors().dim, "%s", state.structure_compare_status);

    if (!state.structure_compare_fields.empty()) {
      const size_t player_vs_enemies = static_cast<size_t>(std::count_if(
          state.structure_compare_fields.begin(), state.structure_compare_fields.end(),
          [](const StructureCompareField &field) {
            return field.relation == StructureFieldRelation::PlayerVsEnemies;
          }));
      const bool has_second_enemy = std::any_of(
          state.structure_compare_fields.begin(), state.structure_compare_fields.end(),
          [](const StructureCompareField &field) { return !field.enemy_b.empty(); });
      if (has_second_enemy) {
        ImGui::TextColored(ui::colors().success,
                           "%zu high-confidence player-vs-enemies fields", player_vs_enemies);
      } else {
        ImGui::TextColored(ui::colors().warning,
                           "Two-way comparison: add a second enemy to isolate player-only fields");
      }
      ImGui::Checkbox("Show all fields", &state.structure_compare_show_all);

      std::vector<size_t> visible_fields;
      visible_fields.reserve(state.structure_compare_fields.size());
      for (size_t i = 0U; i < state.structure_compare_fields.size(); ++i) {
        const auto &field = state.structure_compare_fields[i];
        const bool focus = field.relation == StructureFieldRelation::PlayerVsEnemies ||
                           (field.enemy_b.empty() &&
                            field.relation == StructureFieldRelation::Different);
        if (state.structure_compare_show_all || focus) visible_fields.push_back(i);
      }

      if (visible_fields.empty()) {
        ImGui::TextColored(ui::colors().warning,
                           "No player-vs-enemies fields. Try two enemies of the same type or show all fields.");
      } else if (ImGui::BeginTable("StructureCompareResults", 5,
                                   ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                                   ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                                   ImVec2(0, 220.0f))) {
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 82.0f);
        ImGui::TableSetupColumn("Player");
        ImGui::TableSetupColumn("Enemy A");
        ImGui::TableSetupColumn("Enemy B");
        ImGui::TableSetupColumn("Relation");
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(visible_fields.size()));
        while (clipper.Step()) {
          for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto &field = state.structure_compare_fields[
                visible_fields[static_cast<size_t>(row)]];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            const std::string offset = "+" + hex_u64(field.offset, 4) + "##struct" +
                                       std::to_string(visible_fields[static_cast<size_t>(row)]);
            if (ImGui::Selectable(offset.c_str(), false,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
              uint64_t player_base = 0U;
              if (parse_u64(state.structure_player_base, player_base) &&
                  player_base <= std::numeric_limits<uint64_t>::max() - field.offset) {
                const std::string address = hex_u64(player_base + field.offset);
                std::snprintf(state.read_address, sizeof(state.read_address), "%s", address.c_str());
                std::snprintf(state.write_address, sizeof(state.write_address), "%s", address.c_str());
                state.screen = Screen::Memory;
              }
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(structure_field_value(field.player,
                                                          state.structure_compare_type).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(structure_field_value(field.enemy_a,
                                                          state.structure_compare_type).c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(field.enemy_b.empty() ? "-" :
                structure_field_value(field.enemy_b, state.structure_compare_type).c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::TextColored(structure_relation_color(field.relation), "%s",
                               structure_relation_name(field.relation));
          }
        }
        ImGui::EndTable();
      }
    }
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("ScannerResults", locale::tr("scanner.results_title"), ImVec2(0, avail.y));
  ImGui::Text(locale::tr("scanner.results_count"), state.scan_result.count,
              state.scan_result.truncated ? locale::tr("scanner.truncated") : "");
  ImGui::Text("%s %s", locale::tr("scanner.results_type"), value_type_name(state.scan_type));
  ImGui::Text(locale::tr("scanner.scanned_mib"), static_cast<double>(state.scan_result.bytes_scanned)/(1024.0*1024.0));
  ImGui::Text(locale::tr("scanner.speed"), bytes_per_second(state.scan_result.bytes_scanned, state.scan_result.elapsed_ns).c_str());
  ImGui::Text(locale::tr("scanner.reads_regions_errors"),
              state.scan_result.read_calls, state.scan_result.regions_scanned, state.scan_result.read_errors);
  ImGui::Text(locale::tr("scanner.session_captured"), state.scan_snapshot.size());
  /* BATCH_READ status badge */
  if (!state.scan_snapshot.empty()) {
    ImGui::SameLine();
    if (has_batch_read(state)) {
      ImGui::TextColored(ui::colors().success, "  %s", icons::kGauge);
      if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("scanner.batch_active"));
    } else {
      ImGui::TextColored(ui::colors().warning, "  %s", icons::kWarning);
      if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("scanner.batch_unavailable"));
    }
  }
  ImGui::Spacing();

  /* Copy All logic shared between button and keyboard shortcut */
  auto copy_all = [&](const char *suffix = nullptr) {
    std::string all;
    all.reserve(state.scan_result.addresses.size() * 18U);
    for (uint64_t addr : state.scan_result.addresses)
      all += hex_u64(addr) + "\n";
    ImGui::SetClipboardText(all.c_str());
    char copy_buf[128];
    std::snprintf(copy_buf, sizeof(copy_buf), locale::tr("notify.copied_n_addresses"), state.scan_result.addresses.size());
    set_status(state, copy_buf);
    push_notification(state, copy_buf + (suffix ? std::string(suffix) : std::string("")));
  };

  if (!state.scan_result.addresses.empty()) {
    if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("scanner.copy_all")).c_str(),
                        ImVec2(200, 30)))
      copy_all();
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip(locale::tr("scanner.copy_all_tooltip"),
                        state.scan_result.count);
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_C))
      copy_all(" (Ctrl+C)");
  }

  if (ImGui::BeginTable("ScanResultsTable", 2,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY, ImVec2(0,0))) {
    ImGui::TableSetupColumn(locale::tr("scanner.address_col"));
    ImGui::TableSetupColumn(locale::tr("scanner.current_value_col"));
    ImGui::TableHeadersRow();
    /* Two-pointer lookup: both scan_result.addresses and scan_snapshot are sorted
       and built in the same order (snapshot may skip read errors). */
    size_t snap_idx = 0U;
    for (int i = 0; i < static_cast<int>(state.scan_result.addresses.size()); ++i) {
      uint64_t addr = state.scan_result.addresses[i];
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      std::string label = hex_u64(addr) + "##scan" + std::to_string(i);
      if (ImGui::Selectable(label.c_str())) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s", hex_u64(addr).c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s", hex_u64(addr).c_str());
        state.screen = Screen::Memory;
      }
      ImGui::TableSetColumnIndex(1);
      /* Advance snapshot pointer to match current address (both arrays sorted) */
      while (snap_idx < state.scan_snapshot.size() &&
             state.scan_snapshot[snap_idx].address < addr) snap_idx++;
      if (snap_idx < state.scan_snapshot.size() &&
          state.scan_snapshot[snap_idx].address == addr) {
        const auto &snap = state.scan_snapshot[snap_idx];
        switch (state.scan_snapshot_type) {
        case MEMDBG_VALUE_U8:
          if (snap.bytes.size() >= 1) ImGui::Text("%u", (unsigned)snap.bytes[0]);
          break;
        case MEMDBG_VALUE_U16:
          if (snap.bytes.size() >= 2) ImGui::Text("%u", read_scalar<uint16_t>(snap.bytes));
          break;
        case MEMDBG_VALUE_U32:
          if (snap.bytes.size() >= 4) ImGui::Text("%u", read_scalar<uint32_t>(snap.bytes));
          break;
        case MEMDBG_VALUE_U64: case MEMDBG_VALUE_POINTER:
          if (snap.bytes.size() >= 8) ImGui::Text("%s", hex_u64(read_scalar<uint64_t>(snap.bytes)).c_str());
          break;
        case MEMDBG_VALUE_F32:
          if (snap.bytes.size() >= 4) ImGui::Text("%.6g", (double)read_scalar<float>(snap.bytes));
          break;
        case MEMDBG_VALUE_F64:
          if (snap.bytes.size() >= 8) ImGui::Text("%.12g", read_scalar<double>(snap.bytes));
          break;
        case MEMDBG_VALUE_BYTES: {
          std::string hex;
          for (size_t b = 0; b < snap.bytes.size() && b < 8; ++b) {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%02X ", snap.bytes[b]);
            hex += buf;
          }
          if (snap.bytes.size() > 8) hex += "...";
          ImGui::TextUnformatted(hex.c_str());
          break;
        }
        default: ImGui::TextUnformatted("?"); break;
        }
      } else {
        ImGui::TextColored(ui::colors().dim, "%s", locale::tr("scanner.n_a"));
      }
    }
    ImGui::EndTable();
  }

  ui::end_panel();
}

} // namespace memdbg::frontend

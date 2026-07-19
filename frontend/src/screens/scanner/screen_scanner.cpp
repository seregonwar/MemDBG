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

static std::string scanner_value_text(int type,
                                      const std::vector<uint8_t> &bytes) {
  char text[128] = {};
  switch (type) {
  case MEMDBG_VALUE_U8:
    if (bytes.size() >= 1U)
      std::snprintf(text, sizeof(text), "%u", unsigned(bytes[0]));
    break;
  case MEMDBG_VALUE_U16:
    if (bytes.size() >= 2U)
      std::snprintf(text, sizeof(text), "%u", read_scalar<uint16_t>(bytes));
    break;
  case MEMDBG_VALUE_U32:
    if (bytes.size() >= 4U)
      std::snprintf(text, sizeof(text), "%u", read_scalar<uint32_t>(bytes));
    break;
  case MEMDBG_VALUE_U64:
    if (bytes.size() >= 8U)
      std::snprintf(text, sizeof(text), "%llu",
                    static_cast<unsigned long long>(read_scalar<uint64_t>(bytes)));
    break;
  case MEMDBG_VALUE_POINTER:
    if (bytes.size() >= 8U)
      return hex_u64(read_scalar<uint64_t>(bytes));
    break;
  case MEMDBG_VALUE_F32:
    if (bytes.size() >= 4U)
      std::snprintf(text, sizeof(text), "%.9g",
                    static_cast<double>(read_scalar<float>(bytes)));
    break;
  case MEMDBG_VALUE_F64:
    if (bytes.size() >= 8U)
      std::snprintf(text, sizeof(text), "%.17g", read_scalar<double>(bytes));
    break;
  case MEMDBG_VALUE_BYTES: {
    std::string hex;
    char byte_text[4];
    for (uint8_t byte : bytes) {
      std::snprintf(byte_text, sizeof(byte_text), "%02X ", byte);
      hex += byte_text;
    }
    if (!hex.empty()) hex.pop_back();
    return hex;
  }
  default:
    break;
  }
  return text[0] != '\0' ? std::string(text) : std::string("0");
}

static CheatEntry &upsert_scanner_cheat(AppState &state, uint64_t address,
                                        int type,
                                        const std::vector<uint8_t> &bytes,
                                        const std::string &value_text,
                                        bool locked,
                                        const std::vector<uint8_t> *off_bytes) {
  auto found = std::find_if(state.plugin.cheats.begin(), state.plugin.cheats.end(),
      [&](const CheatEntry &entry) {
        return entry.pid == state.selected_pid && entry.address == address;
      });
  if (found == state.plugin.cheats.end()) {
    state.plugin.cheats.emplace_back();
    found = std::prev(state.plugin.cheats.end());
  }
  CheatEntry &cheat = *found;
  cheat.description = "Scanner runtime " + hex_u64(address);
  cheat.pid = state.selected_pid;
  cheat.address = address;
  cheat.value_type = type;
  cheat.value_text = value_text;
  cheat.bytes = bytes;
  cheat.enabled = true;
  cheat.locked = locked;
  cheat.active = true;
  cheat.active_known = true;
  if (off_bytes != nullptr && off_bytes->size() == bytes.size() &&
      *off_bytes != bytes) {
    cheat.off_bytes = *off_bytes;
    cheat.has_off_bytes = true;
  }
  cheat.status = locale::tr("scanner.runtime_address_warning");
  return cheat;
}

static void request_scanner_value_editor(AppState &state, uint64_t address,
                                         int type,
                                         const std::vector<uint8_t> &current) {
  state.scanner_value_editor_address = address;
  state.scanner_value_editor_type = type;
  state.scanner_value_editor_original = current;
  const std::string value = scanner_value_text(type, current);
  std::snprintf(state.scanner_value_editor_text,
                sizeof(state.scanner_value_editor_text), "%s", value.c_str());
  state.scanner_value_editor_lock = false;
  state.scanner_value_editor_add_trainer = true;
  state.scanner_value_editor_request_open = true;
}

static void draw_scanner_value_editor(AppState &state) {
  if (state.scanner_value_editor_request_open) {
    ImGui::OpenPopup("##ScannerValueEditor");
    state.scanner_value_editor_request_open = false;
    state.scanner_value_editor_open = true;
  }
  bool open = state.scanner_value_editor_open;
  if (!ImGui::BeginPopupModal("##ScannerValueEditor", &open,
                              ImGuiWindowFlags_AlwaysAutoResize)) {
    state.scanner_value_editor_open = open;
    return;
  }

  ImGui::TextColored(ui::colors().primary2, "%s",
                     locale::tr("scanner.edit_result"));
  ImGui::Text("%s: %s", locale::tr("scanner.address_col"),
              hex_u64(state.scanner_value_editor_address).c_str());
  ImGui::Text("%s: %s", locale::tr("scanner.results_type"),
              value_type_name(state.scanner_value_editor_type));
  ImGui::SetNextItemWidth(380.0f * ui::dpi_scale());
  ImGui::InputText(locale::tr("scanner.value"),
                   state.scanner_value_editor_text,
                   sizeof(state.scanner_value_editor_text));
  ImGui::Checkbox(locale::tr("scanner.add_runtime_trainer"),
                  &state.scanner_value_editor_add_trainer);
  ImGui::Checkbox(locale::tr("scanner.lock_written_value"),
                  &state.scanner_value_editor_lock);
  if (state.scanner_value_editor_lock)
    state.scanner_value_editor_add_trainer = true;
  ImGui::TextColored(ui::colors().warning, "%s",
                     locale::tr("scanner.runtime_address_warning"));
  ImGui::Spacing();

  ImGui::BeginDisabled(!state.client.connected() ||
                       state.selected_pid <= 0 || client_async_busy(state));
  if (ui::primary_button(locale::tr("memory.write_memory"),
                         ImVec2(150.0f * ui::dpi_scale(), 34.0f))) {
    std::vector<uint8_t> bytes;
    if (!build_value_bytes(state.scanner_value_editor_type,
                           state.scanner_value_editor_text, bytes)) {
      set_status(state, locale::tr("scanner.invalid_value"));
    } else {
      auto client = state.pool.memory_lease();
      uint32_t written = 0U;
      if (!client || !client->memory_write(
              state.selected_pid, state.scanner_value_editor_address,
              bytes, written) || written != bytes.size()) {
        set_status(state, client ? client->last_error()
                                 : locale::tr("scanner.write_failed"));
      } else {
        if (state.scanner_value_editor_add_trainer) {
          (void)upsert_scanner_cheat(
              state, state.scanner_value_editor_address,
              state.scanner_value_editor_type, bytes,
              state.scanner_value_editor_text,
              state.scanner_value_editor_lock,
              &state.scanner_value_editor_original);
        }
        char message[256];
        std::snprintf(message, sizeof(message),
                      locale::tr("scanner.wrote_result"), written,
                      hex_u64(state.scanner_value_editor_address).c_str());
        set_status(state, message);
        push_notification(state, message);
        state.scanner_value_editor_open = false;
        ImGui::CloseCurrentPopup();
      }
    }
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  if (ui::soft_button(locale::tr("common.cancel"),
                      ImVec2(120.0f * ui::dpi_scale(), 34.0f))) {
    state.scanner_value_editor_open = false;
    ImGui::CloseCurrentPopup();
  }
  ImGui::EndPopup();
  state.scanner_value_editor_open = open && state.scanner_value_editor_open;
}

/* ---- Structure Compare helper (shared between Exact scan panel and standalone tab) ---- */
static void draw_structure_compare_section(AppState &state) {
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

/* ---- Main draw ---- */

void draw_scanner(AppState &state, ImVec2 avail) {

  static int scanner_tab = 0; /* 0=Exact, 1=Pointer, 2=AOB */

  /* ---- Tab bar (shared across all scanner modes) ---- */
  if (ImGui::BeginTabBar("ScannerTabs")) {
    if (ImGui::BeginTabItem(locale::tr("scanner.exact_scan"))) {
      scanner_tab = 0;
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(locale::tr("pointer_scanner.title"))) {
      scanner_tab = 1;
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(locale::tr("aob_scanner.title"))) {
      scanner_tab = 2;
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(locale::tr("scanner.structure_compare"))) {
      scanner_tab = 3;
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }

  if (scanner_tab == 1) {
    draw_pointer_scanner(state, avail);
    return;
  }
  if (scanner_tab == 2) {
    draw_aob_scanner(state, avail);
    return;
  }
  if (scanner_tab == 3) {
    poll_structure_compare(state);
    /* Structure Compare as standalone tab */
    const float left_w = std::max(420.0f, avail.x * 0.38f);
    ui::begin_panel("ScannerStruct", locale::tr("scanner.structure_compare"), ImVec2(left_w, avail.y));
    ImGui::Text(locale::tr("scanner.active_pid"), state.selected_pid);
    ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
    ImGui::Spacing();
    draw_structure_compare_section(state);
    ui::end_panel();
    return;
  }

  poll_scanner_async(state);
  poll_structure_compare(state);

  const float left_w = std::max(420.0f, avail.x * 0.38f);
  const char *type_names[] = {"Bytes","u8","u16","u32","u64","float","double","pointer"};

  ui::begin_panel("ScannerControl", locale::tr("scanner.exact_scan"), ImVec2(left_w, avail.y));
  ImGui::Text(locale::tr("scanner.active_pid"), state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  ImGui::Combo(locale::tr("scanner.value_type"), &state.scan_type, type_names, IM_ARRAYSIZE(type_names));
  ImGui::InputText(locale::tr("scanner.value"), state.scan_value, sizeof(state.scan_value));
  ImGui::InputInt(locale::tr("scanner.alignment"), &state.scan_alignment);
  ImGui::InputInt(locale::tr("scanner.max_results"), &state.scan_max_results, 100, 1000);
  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::clamp(state.scan_max_results, 1,
      static_cast<int>(MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE));

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::InputText(locale::tr("scanner.start"), state.scan_start, sizeof(state.scan_start));
  ImGui::InputText(locale::tr("scanner.length"), state.scan_length, sizeof(state.scan_length));
  bool can_launch_range = !client_async_busy(state) && state.client.connected() &&
                          state.selected_pid > 0 &&
                          payload_supports(state, MEMDBG_CAP_SCAN_EXACT);
  ImGui::BeginDisabled(!can_launch_range);
  if (ui::primary_button((std::string(icons::kSearch) + "  " + locale::tr("scanner.scan_range")).c_str(), ui::full_button(40))) scan_range(state);
  ImGui::EndDisabled();

  const bool can_launch_selected = can_launch_range &&
      !state.selected_map_starts.empty();
  ImGui::BeginDisabled(!can_launch_selected);
  if (ui::soft_button((std::string(icons::kTarget) + "  " +
                       locale::tr("scanner.scan_selected_maps")).c_str(),
                      ui::full_button(40)))
    scan_selected_maps(state);
  ImGui::EndDisabled();
  ImGui::TextColored(ui::colors().dim, locale::tr("scanner.selected_maps_count"),
                     state.selected_map_starts.size());

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
  ImGui::Checkbox("Exclude zero values (prefilter)",
                  &state.scan_unknown_nonzero_prefilter);
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
  if (state.scan_async_pending &&
      state.scan_async_units_total.load() != 0U) {
    const uint64_t done = state.scan_async_units_done.load();
    const uint64_t total = state.scan_async_units_total.load();
    const float fraction = std::min(
        1.0f, static_cast<float>(done) / static_cast<float>(total));
    ImGui::ProgressBar(fraction,
                       ImVec2(ImGui::GetContentRegionAvail().x, 12.0f), "");
    const char *progress_format = state.scan_async_units_are_maps.load()
        ? locale::tr("scanner.maps_progress")
        : locale::tr("scanner.units_progress");
    ImGui::TextColored(ui::colors().dim, progress_format,
        static_cast<unsigned long long>(done),
        static_cast<unsigned long long>(total));
  }
  if (state.scan_async_pending) {
    const uint32_t maps_total = state.scan_async_maps_total.load();
    if (maps_total != 0U)
      ImGui::TextColored(ui::colors().dim, locale::tr("scanner.maps_progress"),
          static_cast<unsigned long long>(state.scan_async_maps_done.load()),
          static_cast<unsigned long long>(maps_total));
    ImGui::TextColored(ui::colors().dim, locale::tr("scanner.results_found"),
        static_cast<unsigned long long>(state.scan_async_results_found.load()));
    const uint32_t workers_total = state.scan_async_workers_total.load();
    if (workers_total != 0U)
      ImGui::SameLine(), ImGui::TextColored(
          ui::colors().dim, locale::tr("scanner.workers_active"),
          state.scan_async_workers_active.load(), workers_total);
  }
  if (state.scan_async_pending && state.scan_async_cancellable) {
    ImGui::BeginDisabled(state.scan_async_cancel_requested.load());
    if (ui::danger_button(locale::tr("scanner.stop"), ui::full_button(36))) {
      state.scan_async_cancel_requested.store(true);
      set_status(state, locale::tr("scanner.stopping"));
    }
    ImGui::EndDisabled();
  }

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
  if (ui::soft_button(locale::tr("scanner.exact_value"), ui::full_button(38))) refine_scan(state, RefineMode::ExactValue);
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
      state.scan_async_cancellable = true;
      state.scan_async_cancel_requested.store(false);
      state.scan_async_owner = Screen::Scanner;

      const int32_t pid = state.selected_pid;
      const uint32_t val_len = state.scan_snapshot_value_len;
      const int snap_type = state.scan_snapshot_type;
      auto client = state.pool.scan_lease();
      const auto snap = state.scan_snapshot;
      const ScanResult original_result = state.scan_result;
      const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;
      state.scan_async_units_done.store(0U);
      state.scan_async_units_total.store(has_batch
          ? (snap.size() + MEMDBG_BATCH_READ_MAX_ITEMS - 1U) /
                MEMDBG_BATCH_READ_MAX_ITEMS
          : snap.size());
      auto &temp_result = state.scan_async_temp_result;
      auto &temp_snapshot = state.scan_async_temp_snapshot;
      auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
      auto &temp_snap_type = state.scan_async_temp_snapshot_type;
      auto &temp_is_unknown = state.scan_async_temp_is_unknown;
      auto &temp_status = state.scan_async_temp_session_status;
      auto &temp_candidates = state.auto_search_temp_candidates;

      state.scan_async_future = std::async(std::launch::async,
        [client, pid, val_len, snap_type, tgt, has_batch,
         snap, &temp_result, &temp_snapshot, &temp_snap_val_len,
         &temp_snap_type, &temp_is_unknown, &temp_status,
         &temp_candidates, original_result,
         &cancel_requested = state.scan_async_cancel_requested,
         &units_done = state.scan_async_units_done,
         &mtx = state.scan_async_mtx]() -> bool {
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
              if (cancel_requested.load()) break;
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
              if (!client->batch_read(pid, batch_items, batch)) {
                if (cancel_requested.load()) break;
                read_errors += static_cast<uint32_t>(chunk_end - base);
                units_done.fetch_add(1U);
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
              units_done.fetch_add(1U);
            }
          } else {
            for (size_t i = 0U; i < old_snap.size(); ++i) {
              if (cancel_requested.load()) break;
              std::vector<uint8_t> data;
              if (!client->memory_read(pid, old_snap[i].address, val_len, data) ||
                  data.size() != val_len) {
                read_errors++;
                units_done.fetch_add(1U);
                continue;
              }
              ScanSnapshotEntry cur;
              cur.address = old_snap[i].address;
              cur.bytes   = std::move(data);
              current_snap.push_back(std::move(cur));
              current_addrs.push_back(old_snap[i].address);
              bytes_read += val_len;
              units_done.fetch_add(1U);
            }
          }

          if (cancel_requested.load()) {
            std::lock_guard<std::mutex> lock(mtx);
            temp_candidates.clear();
            temp_snapshot = old_snap;
            temp_result = original_result;
            temp_snap_val_len = val_len;
            temp_snap_type = snap_type;
            temp_is_unknown = true;
            std::snprintf(temp_status, sizeof(temp_status),
                          "Stopped: auto-search baseline preserved");
            return true;
          }

          /* Run auto-search engine */
          AutoSearchEngine engine;
          engine.set_target(tgt);
          engine.set_baseline(old_snap, snap_type, val_len);
          auto candidates = engine.score_candidates(current_snap, 100);

          /* Store scored candidates and build new snapshot under lock */
          {
            std::lock_guard<std::mutex> lock(mtx);
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
            temp_candidates = std::move(candidates);
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
    draw_structure_compare_section(state);
  }
  ui::end_panel();

  ImGui::SameLine();
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

  if (ImGui::BeginTable("ScanResultsTable", 3,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|
            ImGuiTableFlags_ScrollX|ImGuiTableFlags_Resizable, ImVec2(0,0))) {
    ImGui::TableSetupColumn(locale::tr("scanner.address_col"),
                            ImGuiTableColumnFlags_WidthFixed, 190.0f);
    ImGui::TableSetupColumn(locale::tr("scanner.current_value_col"),
                            ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn(locale::tr("scanner.actions_col"),
                            ImGuiTableColumnFlags_WidthFixed, 270.0f);
    ImGui::TableHeadersRow();
    /* Two-pointer lookup: both scan_result.addresses and scan_snapshot are sorted
       and built in the same order (snapshot may skip read errors). */
    size_t snap_idx = 0U;
    for (int i = 0; i < static_cast<int>(state.scan_result.addresses.size()); ++i) {
      uint64_t addr = state.scan_result.addresses[i];
      while (snap_idx < state.scan_snapshot.size() &&
             state.scan_snapshot[snap_idx].address < addr) snap_idx++;
      const ScanSnapshotEntry *snap =
          snap_idx < state.scan_snapshot.size() &&
                  state.scan_snapshot[snap_idx].address == addr
              ? &state.scan_snapshot[snap_idx]
              : nullptr;
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      std::string label = hex_u64(addr) + "##scan" + std::to_string(i);
      if (ImGui::Selectable(label.c_str())) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s", hex_u64(addr).c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s", hex_u64(addr).c_str());
        state.screen = Screen::Memory;
      }
      ImGui::TableSetColumnIndex(1);
      if (snap != nullptr) {
        ImGui::TextUnformatted(
            scanner_value_text(state.scan_snapshot_type, snap->bytes).c_str());
      } else {
        ImGui::TextColored(ui::colors().dim, "%s", locale::tr("scanner.n_a"));
      }

      ImGui::TableSetColumnIndex(2);
      ImGui::PushID(i);
      if (ImGui::SmallButton(locale::tr("common.copy"))) {
        const std::string address = hex_u64(addr);
        ImGui::SetClipboardText(address.c_str());
        set_status(state, locale::tr("scanner.address_copied"));
      }
      ImGui::SameLine();
      ImGui::BeginDisabled(snap == nullptr || client_async_busy(state));
      if (ImGui::SmallButton(locale::tr("scanner.edit")) && snap != nullptr)
        request_scanner_value_editor(state, addr, state.scan_snapshot_type,
                                     snap->bytes);
      ImGui::SameLine();
      if (ImGui::SmallButton(locale::tr("scanner.lock")) && snap != nullptr) {
        (void)upsert_scanner_cheat(
            state, addr, state.scan_snapshot_type, snap->bytes,
            scanner_value_text(state.scan_snapshot_type, snap->bytes), true,
            nullptr);
        set_status(state, locale::tr("scanner.runtime_lock_added"));
        push_notification(state, locale::tr("scanner.runtime_lock_added"));
      }
      ImGui::SameLine();
      if (ImGui::SmallButton(locale::tr("scanner.trainer")) && snap != nullptr) {
        (void)upsert_scanner_cheat(
            state, addr, state.scan_snapshot_type, snap->bytes,
            scanner_value_text(state.scan_snapshot_type, snap->bytes), false,
            nullptr);
        set_status(state, locale::tr("scanner.runtime_trainer_added"));
        push_notification(state, locale::tr("scanner.runtime_trainer_added"));
      }
      ImGui::EndDisabled();
      ImGui::PopID();
    }
    ImGui::EndTable();
  }

  draw_scanner_value_editor(state);

  ui::end_panel();
}

} // namespace memdbg::frontend

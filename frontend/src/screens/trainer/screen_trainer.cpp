/*
 * MemDBG - Trainer screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "trainer_format.hpp"
#include "batchcode_parser.hpp"
#include "file_picker.hpp"
#include "confirm_modal.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace memdbg::frontend {

/* build_value_bytes and build_scan_value are in app_state.hpp */
/* trainer load/save now in trainer_format.cpp */

static bool validate_writable_address(AppState &state, int32_t pid,
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
      error = "Address " + hex_u64(address) + " is in a non-writable map";
      if (!map.name.empty()) error += ": " + map.name;
      return false;
    }
    return true;
  }

  error = "Address " + hex_u64(address) + " is outside the known process maps";
  return false;
}

static void labeled_input_text(const char *label, const char *id, char *buffer,
                               size_t buffer_size,
                               ImGuiInputTextFlags flags = 0) {
  ImGui::TextColored(ui::colors().muted, "%s", label);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText(id, buffer, buffer_size, flags);
}

static void labeled_combo(const char *label, const char *id, int *value,
                          const char *const items[], int item_count) {
  ImGui::TextColored(ui::colors().muted, "%s", label);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::Combo(id, value, items, item_count);
}

static bool apply_cheat(AppState &state, CheatEntry &cheat) {
  if (!state.client.connected()) { cheat.status="No console session"; return false; }
  int32_t pid = cheat.pid>0 ? cheat.pid : state.selected_pid;
  if (pid<=0) { cheat.status="No target PID"; return false; }
  if (cheat.bytes.empty()) { cheat.status="Empty value"; return false; }
  std::string validation_error;
  if (!validate_writable_address(state, pid, cheat.address, cheat.bytes.size(),
                                 validation_error)) {
    cheat.status = validation_error;
    return false;
  }
  uint32_t written=0;
  if (!state.client.memory_write(pid, cheat.address, cheat.bytes, written)) { cheat.status=state.client.last_error(); return false; }
  cheat.active = true;
  cheat.status = "Wrote "+std::to_string(written)+" bytes";
  return true;
}

static bool deactivate_cheat(AppState &state, CheatEntry &cheat) {
  if (!cheat.has_off_bytes||cheat.off_bytes.empty()) { cheat.status="No OFF value captured"; return false; }
  if (!state.client.connected()) { cheat.status="No console session"; return false; }
  int32_t pid = cheat.pid>0 ? cheat.pid : state.selected_pid;
  if (pid<=0) { cheat.status="No target PID"; return false; }
  std::string validation_error;
  if (!validate_writable_address(state, pid, cheat.address, cheat.off_bytes.size(),
                                 validation_error)) {
    cheat.status = validation_error;
    return false;
  }
  uint32_t written=0;
  if (!state.client.memory_write(pid, cheat.address, cheat.off_bytes, written)) { cheat.status=state.client.last_error(); return false; }
  cheat.active = false;
  cheat.status = "Restored "+std::to_string(written)+" bytes";
  return true;
}

static void add_cheat_from_fields(AppState &state) {
  if (state.selected_pid<=0) { set_status(state, locale::tr("trainer.select_process_first")); return; }
  if (client_async_busy(state)) { set_status(state, locale::tr("trainer.wait_active")); return; }
  uint64_t address=0;
  std::vector<uint8_t> bytes;
  if (!parse_u64(state.cheat_address, address)) { set_status(state, locale::tr("trainer.invalid_cheat_addr")); return; }
  if (!build_value_bytes(state.cheat_type, state.cheat_value, bytes)) { set_status(state, locale::tr("trainer.invalid_cheat_value")); return; }
  CheatEntry cheat;
  cheat.description = state.cheat_description[0]!='\0'?state.cheat_description:"Cheat";
  cheat.pid=state.selected_pid; cheat.address=address; cheat.value_type=state.cheat_type;
  cheat.value_text=state.cheat_value; cheat.bytes=std::move(bytes); cheat.locked=state.cheat_lock;
  if (state.client.connected()) (void)capture_off_value(state, cheat);
  state.cheats.push_back(std::move(cheat));
  set_status(state, locale::tr("trainer.entry_added"));
  char notify_buf[512];
  std::snprintf(notify_buf, sizeof(notify_buf), locale::tr("trainer.entry_added_notify"), state.cheat_description);
  push_notification(state, notify_buf);
}

/* ---- load/save now in trainer_format.cpp ---- */

/* ---- Batchcode ---- */
static void import_batchcode(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, locale::tr("trainer.select_process_for_batch"));
    return;
  }
  std::string error;
  std::vector<BatchcodeEntry> entries;
  int imported = parse_batchcode(state.batchcode_text, entries, error);
  if (imported < 0) {
    char bce_buf[256]; std::snprintf(bce_buf, sizeof(bce_buf), locale::tr("trainer.batchcode_error"), error.c_str()); set_status(state, bce_buf);
    return;
  }
  for (size_t i = 0; i < entries.size(); ++i) {
    CheatEntry cheat;
    cheat.description = "Batchcode " + std::to_string(i + 1);
    cheat.pid = state.selected_pid;
    cheat.address = entries[i].offset;
    cheat.value_type = MEMDBG_VALUE_BYTES;
    cheat.value_text = bytes_to_hex(entries[i].bytes);
    cheat.bytes = std::move(entries[i].bytes);
    cheat.enabled = true;
    state.cheats.push_back(std::move(cheat));
  }
    char import_buf[256];
    if (imported > 0) {
      std::snprintf(import_buf, sizeof(import_buf), locale::tr("trainer.imported_n"), imported);
    } else {
      std::snprintf(import_buf, sizeof(import_buf), "%s", locale::tr("trainer.no_batchcode"));
    }
    set_status(state, import_buf);
}

/* ---- Locked cheats timer ---- */
static bool has_batch_write(const AppState &state) {
  return (state.hello.capabilities & MEMDBG_CAP_BATCH_WRITE) != 0U;
}

static void apply_locked_cheats(AppState &state) {
  if (!state.client.connected()||state.cheats.empty()) return;
  if (client_async_busy(state)) return;
  const double now = ImGui::GetTime();
  const double interval = std::max(0.10f, state.cheat_lock_interval);
  if (now < state.next_cheat_lock_time) return;
  state.next_cheat_lock_time = now + interval;

  /* Collect locked cheats with valid PID and non-empty bytes */
  std::vector<CheatEntry *> locked;
  for (auto &cheat : state.cheats)
    if (cheat.enabled && cheat.locked && !cheat.bytes.empty())
      locked.push_back(&cheat);

  if (locked.empty()) return;

  /* Compute effective PID for each locked cheat */
  int32_t effective_pid = state.selected_pid;
  if (effective_pid <= 0) return;

  if (has_batch_write(state)) {
    /* Batch write: group into chunks of up to 64 items */
    for (size_t base = 0U; base < locked.size(); base += MEMDBG_BATCH_WRITE_MAX_ITEMS) {
      size_t chunk_end = std::min(base + MEMDBG_BATCH_WRITE_MAX_ITEMS, locked.size());
      std::vector<std::pair<uint64_t, std::vector<uint8_t>>> items;
      items.reserve(chunk_end - base);
      for (size_t i = base; i < chunk_end; ++i)
        items.emplace_back(locked[i]->address, std::vector<uint8_t>(locked[i]->bytes));

      Client::BatchWriteResult result;
      if (state.client.batch_write(effective_pid, items, result)) {
        for (size_t j = 0U; j < items.size() && j < (chunk_end - base); ++j) {
          CheatEntry *cheat = locked[base + j];
          if (result.entries[j].status == 0U) {
            cheat->active = true;
            cheat->status = "Locked (batch)";
          } else {
            cheat->status = "Batch write status " + std::to_string(result.entries[j].status);
          }
        }
      }
    }
  } else {
    /* Fallback: individual writes (slower, but universal) */
    for (auto *cheat : locked)
      (void)apply_cheat(state, *cheat);
  }
}

static void apply_enabled_cheats(AppState &state) {
  int applied = 0;
  for (auto &cheat : state.cheats) {
    if (cheat.enabled && apply_cheat(state, cheat)) applied++;
  }
  char applied_buf[256];
  std::snprintf(applied_buf, sizeof(applied_buf), locale::tr("trainer.applied"), applied);
  set_status(state, applied_buf);
  push_notification(state, applied_buf);
}

/* ---- Main draw ---- */
void draw_trainer(AppState &state, ImVec2 avail) {
  /* Process trainer files dropped from the OS onto the window */
  if (!state.dropped_files.empty()) {
    for (const auto &path : state.dropped_files) {
      std::string lower = path;
      std::transform(lower.begin(), lower.end(), lower.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      const bool is_trainer_ext =
          (lower.size() >= 4U && (lower.compare(lower.size() - 4U, 4U, ".cht") == 0 ||
                                  lower.compare(lower.size() - 4U, 4U, ".shn") == 0)) ||
          (lower.size() >= 5U && lower.compare(lower.size() - 5U, 5U, ".json") == 0) ||
          (lower.size() >= 8U && lower.compare(lower.size() - 8U, 8U, ".trainer") == 0);
      if (is_trainer_ext) {
        std::snprintf(state.trainer_file_path, sizeof(state.trainer_file_path),
                      "%s", path.c_str());
        const int loaded = load_trainer_file(state, path);
        if (loaded >= 0) {
          char buf[512];
          std::snprintf(buf, sizeof(buf),
                        locale::tr("trainer.drop_loaded"), loaded,
                        path.c_str());
          set_status(state, buf);
          push_notification(state, buf, 5.0);
        }
        /* On error, load_trainer_file already sets the status */
        break;  /* only consume the first matching file */
      }
    }
    state.dropped_files.clear();
  }

  const float scl = ui::dpi_scale();
  const float gap = 12.0f * scl;
  const bool stacked = avail.x < 900.0f * scl;
  const float left_w = stacked
      ? avail.x
      : std::clamp((avail.x - gap) * 0.40f, 360.0f * scl,
                   std::max(360.0f * scl, (avail.x - gap) * 0.54f));
  const float left_h = stacked ? std::max(330.0f * scl, avail.y * 0.48f)
                               : avail.y;
  const char *type_names[] = {"Bytes","u8","u16","u32","u64","float","double","pointer"};

  ui::begin_panel("TrainerBuilder", locale::tr("trainer.cheat_builder"), ImVec2(left_w, left_h));
  ImGui::SetScrollX(0.0f);
  ImGui::Text(locale::tr("trainer.active_pid"), state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  if (ImGui::BeginTable("TrainerAddressSources", 2,
                        ImGuiTableFlags_SizingStretchSame |
                            ImGuiTableFlags_PadOuterX)) {
    ImGui::TableNextColumn();
    if (ui::soft_button(locale::tr("trainer.use_memory_addr"), ImVec2(-1, 36.0f * scl)))
      std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s", state.write_address);
    ImGui::TableNextColumn();
    ImGui::BeginDisabled(state.scan_result.addresses.empty());
    if (ui::soft_button(locale::tr("trainer.use_first_hit"), ImVec2(-1, 36.0f * scl)))
      std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s", hex_u64(state.scan_result.addresses.front()).c_str());
    ImGui::EndDisabled();
    ImGui::EndTable();
  }

  labeled_input_text(locale::tr("trainer.name_label"), "##TrainerName",
                     state.cheat_description, sizeof(state.cheat_description));
  labeled_input_text(locale::tr("trainer.address"), "##TrainerAddress",
                     state.cheat_address, sizeof(state.cheat_address));
  labeled_combo(locale::tr("trainer.value_type"), "##TrainerValueType",
                &state.cheat_type, type_names, IM_ARRAYSIZE(type_names));
  labeled_input_text(locale::tr("trainer.value"), "##TrainerValue",
                     state.cheat_value, sizeof(state.cheat_value));
  ImGui::Checkbox(locale::tr("trainer.lock_value"), &state.cheat_lock);
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.lock_interval"));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::SliderFloat("##TrainerLockInterval", &state.cheat_lock_interval, 0.10f, 5.0f, "%.2fs");
  bool can_train = state.client.connected() && state.selected_pid > 0 &&
                   !client_async_busy(state) &&
                   payload_supports(state, MEMDBG_CAP_MEMORY_WRITE);
  ImGui::BeginDisabled(!can_train);
  if (ui::primary_button((std::string(icons::kAdd) + "  " + locale::tr("trainer.add_to_trainer")).c_str(), ui::full_button(40))) add_cheat_from_fields(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.trainer_file"));
  if (ImGui::BeginTable("TrainerFilePathRow", 2,
                        ImGuiTableFlags_SizingStretchProp |
                            ImGuiTableFlags_PadOuterX)) {
    ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Browse", ImGuiTableColumnFlags_WidthFixed, 42.0f * scl);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##TrainerPath", state.trainer_file_path, sizeof(state.trainer_file_path));
    ImGui::TableSetColumnIndex(1);
    if (ImGui::SmallButton((std::string(icons::kLoad) + "##trainerpath").c_str())) {
      std::string picked = memdbg::frontend::ui::pickFile(locale::tr("file_picker.open_trainer"), locale::tr("file_picker.trainer_files"), "*.cht;*.shn;*.json;*.trainer");
      if (!picked.empty())
        std::snprintf(state.trainer_file_path, sizeof(state.trainer_file_path), "%s", picked.c_str());
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("file_picker.open_trainer"));
    ImGui::EndTable();
  }
  ImGui::BeginDisabled(client_async_busy(state));
  if (ImGui::BeginTable("TrainerFileActions", 2,
                        ImGuiTableFlags_SizingStretchSame |
                            ImGuiTableFlags_PadOuterX)) {
    ImGui::TableNextColumn();
    if (ui::soft_button((std::string(icons::kLoad) + "  " + locale::tr("trainer.load")).c_str(),
        ImVec2(-1, 38.0f * scl))) {
      if (load_trainer_file(state, state.trainer_file_path) < 0) {
        /* error already set by load_trainer_file */
      }
    }
    ImGui::TableNextColumn();
    if (ui::soft_button((std::string(icons::kSave) + "  " + locale::tr("trainer.save")).c_str(),
        ImVec2(-1, 38.0f * scl))) {
      save_trainer_file(state, state.trainer_file_path);
    }
    ImGui::EndTable();
  }
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.batchcode_import"));
  ImGui::InputTextMultiline("##Batchcode", state.batchcode_text, sizeof(state.batchcode_text),
                            ImVec2(0, 112.0f * scl));
  if (ui::soft_button((std::string(icons::kImport) + "  " + locale::tr("trainer.import_batchcode")).c_str(), ui::full_button(38.0f))) import_batchcode(state);
  ui::text_dim(locale::tr("trainer.batchcode_hint"));
  ui::end_panel();

  if (stacked) {
    ImGui::Spacing();
  } else {
    ImGui::SameLine(0, gap);
  }
  const float list_h = stacked ? std::max(220.0f * scl, avail.y - left_h - gap)
                               : avail.y;
  ui::begin_panel("TrainerList", locale::tr("trainer.runtime_cheat_list"),
                  ImVec2(0, list_h));

  /* Apply locked cheats automatically */
  apply_locked_cheats(state);

  static bool skip_apply_enabled = false;
  static bool skip_clear_disabled = false;
  ImGui::BeginDisabled(!state.client.connected() || client_async_busy(state));
  if (ImGui::BeginTable("TrainerListActions", 3,
                        ImGuiTableFlags_SizingStretchProp |
                            ImGuiTableFlags_PadOuterX)) {
    ImGui::TableSetupColumn("Apply", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Clear", ImGuiTableColumnFlags_WidthFixed, 176.0f * scl);
    ImGui::TableSetupColumn("Count", ImGuiTableColumnFlags_WidthFixed, 86.0f * scl);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    if (ui::soft_button((std::string(icons::kPlay) + "  " + locale::tr("trainer.apply_enabled")).c_str(), ImVec2(-1, 38.0f * scl))) {
      ImGui::OpenPopup("ConfirmApplyEnabledTrainer");
    }
    ImGui::EndDisabled();
    ImGui::TableSetColumnIndex(1);
    if (ui::soft_button((std::string(icons::kTrash) + "  " + locale::tr("trainer.clear_disabled")).c_str(), ImVec2(-1, 38.0f * scl))) {
      ImGui::OpenPopup("ConfirmClearDisabled");
    }
    ImGui::TableSetColumnIndex(2);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ui::colors().dim, locale::tr("trainer.n_entries"), state.cheats.size());
    ImGui::EndTable();
  } else {
    ImGui::EndDisabled();
  }
  if (ui::confirm_modal("ConfirmApplyEnabledTrainer",
                        "Apply all enabled trainer entries?",
                        "This can write several process addresses in one action. Validate the PID and loaded trainer before continuing.",
                        &skip_apply_enabled, true)) {
    apply_enabled_cheats(state);
  }
  if (ui::confirm_modal("ConfirmClearDisabled",
                        locale::tr("trainer.confirm_clear_disabled"), nullptr,
                        &skip_clear_disabled, true)) {
    state.cheats.erase(std::remove_if(state.cheats.begin(), state.cheats.end(),
      [](const CheatEntry &c){ return !c.enabled; }), state.cheats.end());
  }
  ImGui::Spacing();

  /* Copy All logic shared between button and keyboard shortcut */
  auto copy_all = [&](const char *suffix = nullptr) {
    std::string all;
    all.reserve(state.cheats.size() * 18U);
    for (const auto &cheat : state.cheats)
      all += hex_u64(cheat.address) + "\n";
    ImGui::SetClipboardText(all.c_str());
    char cp_buf[256];
    std::snprintf(cp_buf, sizeof(cp_buf), locale::tr("trainer.copied_n"), state.cheats.size());
    set_status(state, cp_buf);
    push_notification(state, cp_buf + std::string(suffix ? suffix : ""));
  };

  if (!state.cheats.empty()) {
    if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("trainer.copy_all")).c_str(),
                        ImVec2(200, 30)))
      copy_all();
    if (ImGui::IsItemHovered()) {
      char tip_buf[128];
      std::snprintf(tip_buf, sizeof(tip_buf), locale::tr("trainer.copy_all_tooltip"), state.cheats.size());
      ImGui::SetTooltip("%s", tip_buf);
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_C))
      copy_all(" (Ctrl+C)");
  }

  if (state.cheats.empty()) {
    ui::draw_empty_state(locale::tr("trainer.no_entries"), locale::tr("trainer.no_entries_desc"));
  } else if (ImGui::BeginTable("TrainerTable", 10,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|
            ImGuiTableFlags_ScrollX|ImGuiTableFlags_Resizable,
        ImVec2(0,0))) {
    ImGui::TableSetupColumn(locale::tr("trainer.col_on"), ImGuiTableColumnFlags_WidthFixed,44);
    ImGui::TableSetupColumn(locale::tr("trainer.col_lock"), ImGuiTableColumnFlags_WidthFixed,54);
    ImGui::TableSetupColumn(locale::tr("trainer.col_state"), ImGuiTableColumnFlags_WidthFixed,74);
    ImGui::TableSetupColumn(locale::tr("trainer.col_name"));
    ImGui::TableSetupColumn(locale::tr("trainer.col_pid"), ImGuiTableColumnFlags_WidthFixed,70);
    ImGui::TableSetupColumn(locale::tr("trainer.col_address"));
    ImGui::TableSetupColumn(locale::tr("trainer.col_type"), ImGuiTableColumnFlags_WidthFixed,70);
    ImGui::TableSetupColumn(locale::tr("trainer.col_value"));
    ImGui::TableSetupColumn(locale::tr("trainer.col_off"), ImGuiTableColumnFlags_WidthFixed,54);
    ImGui::TableSetupColumn(locale::tr("trainer.col_action"), ImGuiTableColumnFlags_WidthFixed,215);
    ImGui::TableHeadersRow();
    for (int i=0; i<static_cast<int>(state.cheats.size()); ++i) {
      CheatEntry &cheat = state.cheats[i];
      ImGui::PushID(i);
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0); ImGui::Checkbox("##enabled", &cheat.enabled);
      ImGui::TableSetColumnIndex(1); ImGui::Checkbox("##locked", &cheat.locked);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextColored(cheat.active?ui::colors().success:ui::colors().dim, "%s", cheat.active?locale::tr("trainer.state_active"):locale::tr("trainer.state_idle"));
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(cheat.description.c_str());
      if (ImGui::IsItemHovered()) {
        if (!cheat.status.empty())
          ImGui::SetTooltip("%s \xe2\x80\x94 %s", cheat.description.c_str(), cheat.status.c_str());
        else if (!cheat.description.empty())
          ImGui::SetTooltip("%s", cheat.description.c_str());
      }
      ImGui::TableSetColumnIndex(4); ImGui::Text("%d", cheat.pid);
      ImGui::TableSetColumnIndex(5); ImGui::TextUnformatted(hex_u64(cheat.address).c_str());
      ImGui::TableSetColumnIndex(6); ImGui::TextUnformatted(value_type_name(cheat.value_type));
      ImGui::TableSetColumnIndex(7); ImGui::TextUnformatted(cheat.value_text.c_str());
      if (ImGui::IsItemHovered() && !cheat.value_text.empty()) ImGui::SetTooltip("%s", cheat.value_text.c_str());
      ImGui::TableSetColumnIndex(8);
      ImGui::TextColored(cheat.has_off_bytes?ui::colors().success:ui::colors().warning, "%s", cheat.has_off_bytes?locale::tr("trainer.off_yes"):locale::tr("trainer.off_no"));
      ImGui::TableSetColumnIndex(9);
      ImGui::BeginDisabled(client_async_busy(state));
      if (ImGui::SmallButton(locale::tr("trainer.btn_on"))) {
        if (apply_cheat(state,cheat)) { char ca_buf[256]; std::snprintf(ca_buf, sizeof(ca_buf), locale::tr("trainer.cheat_applied"), cheat.description.c_str()); set_status(state, ca_buf); push_notification(state, ca_buf); }
        else set_status(state, cheat.status);
      }
      ImGui::SameLine();
      if (ImGui::SmallButton(locale::tr("trainer.btn_off"))) {
        if (deactivate_cheat(state,cheat)) { char cr_buf[256]; std::snprintf(cr_buf, sizeof(cr_buf), locale::tr("trainer.cheat_restored"), cheat.description.c_str()); set_status(state, cr_buf); push_notification(state, cr_buf); }
        else set_status(state, cheat.status);
      }
      ImGui::SameLine();
      if (ImGui::SmallButton(locale::tr("trainer.btn_cap"))) {
        if (capture_off_value(state,cheat)) { char coc_buf[256]; std::snprintf(coc_buf, sizeof(coc_buf), locale::tr("trainer.off_captured"), cheat.description.c_str()); set_status(state, coc_buf); }
        else set_status(state, cheat.status);
      }
      ImGui::EndDisabled();
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

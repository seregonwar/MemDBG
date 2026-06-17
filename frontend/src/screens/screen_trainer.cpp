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

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace memdbg::frontend {

/* build_value_bytes and build_scan_value are in app_state.hpp */
/* trainer load/save now in trainer_format.cpp */

static bool apply_cheat(AppState &state, CheatEntry &cheat) {
  if (!state.client.connected()) { cheat.status="No console session"; return false; }
  int32_t pid = cheat.pid>0 ? cheat.pid : state.selected_pid;
  if (pid<=0) { cheat.status="No target PID"; return false; }
  if (cheat.bytes.empty()) { cheat.status="Empty value"; return false; }
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
  uint32_t written=0;
  if (!state.client.memory_write(pid, cheat.address, cheat.off_bytes, written)) { cheat.status=state.client.last_error(); return false; }
  cheat.active = false;
  cheat.status = "Restored "+std::to_string(written)+" bytes";
  return true;
}

static void add_cheat_from_fields(AppState &state) {
  if (state.selected_pid<=0) { set_status(state,"Select a process before adding a trainer entry"); return; }
  uint64_t address=0;
  std::vector<uint8_t> bytes;
  if (!parse_u64(state.cheat_address, address)) { set_status(state,"Invalid cheat address"); return; }
  if (!build_value_bytes(state.cheat_type, state.cheat_value, bytes)) { set_status(state,"Invalid cheat value"); return; }
  CheatEntry cheat;
  cheat.description = state.cheat_description[0]!='\0'?state.cheat_description:"Cheat";
  cheat.pid=state.selected_pid; cheat.address=address; cheat.value_type=state.cheat_type;
  cheat.value_text=state.cheat_value; cheat.bytes=std::move(bytes); cheat.locked=state.cheat_lock;
  if (state.client.connected()) (void)capture_off_value(state, cheat);
  state.cheats.push_back(std::move(cheat));
  set_status(state, "Trainer entry added");
  push_notification(state, "Trainer entry added: " + std::string(state.cheat_description));
}

/* ---- load/save now in trainer_format.cpp ---- */

/* ---- Batchcode ---- */
static void import_batchcode(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before importing batchcode");
    return;
  }
  std::string error;
  std::vector<BatchcodeEntry> entries;
  int imported = parse_batchcode(state.batchcode_text, entries, error);
  if (imported < 0) {
    set_status(state, "Batchcode error: " + error);
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
  set_status(state, imported > 0
                        ? "Imported " + std::to_string(imported) + " batchcode entries"
                        : "No batchcode entries imported");
}

/* ---- Locked cheats timer ---- */
static bool has_batch_write(const AppState &state) {
  return (state.hello.capabilities & MEMDBG_CAP_BATCH_WRITE) != 0U;
}

static void apply_locked_cheats(AppState &state) {
  if (!state.client.connected()||state.cheats.empty()) return;
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

/* ---- Main draw ---- */
void draw_trainer(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float left_w = std::max(440.0f, (avail.x - gap) * 0.40f);
  const char *type_names[] = {"Bytes","u8","u16","u32","u64","float","double","pointer"};

  ui::begin_panel("TrainerBuilder", locale::tr("trainer.cheat_builder"), ImVec2(left_w, avail.y));
  ImGui::Text(locale::tr("trainer.active_pid"), state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  const float addr_btn_w = (ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f;
  if (ui::soft_button(locale::tr("trainer.use_memory_addr"), ImVec2(addr_btn_w, 36)))
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s", state.write_address);
  ImGui::SameLine();
  if (!state.scan_result.addresses.empty() && ui::soft_button(locale::tr("trainer.use_first_hit"), ImVec2(0, 36)))
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s", hex_u64(state.scan_result.addresses.front()).c_str());

  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.name_label"));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText(locale::tr("trainer.name_input"), state.cheat_description, sizeof(state.cheat_description));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText(locale::tr("trainer.address"), state.cheat_address, sizeof(state.cheat_address));
  ImGui::Combo(locale::tr("trainer.value_type"), &state.cheat_type, type_names, IM_ARRAYSIZE(type_names));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText(locale::tr("trainer.value"), state.cheat_value, sizeof(state.cheat_value));
  ImGui::Checkbox(locale::tr("trainer.lock_value"), &state.cheat_lock);
  ImGui::SliderFloat(locale::tr("trainer.lock_interval"), &state.cheat_lock_interval, 0.10f, 5.0f, "%.2fs");
  bool can_train = state.client.connected() && state.selected_pid > 0 &&
                   payload_supports(state, MEMDBG_CAP_MEMORY_WRITE);
  ImGui::BeginDisabled(!can_train);
  if (ui::primary_button((std::string(icons::kAdd) + "  " + locale::tr("trainer.add_to_trainer")).c_str(), ui::full_button(40))) add_cheat_from_fields(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.trainer_file"));
  ImGui::InputText(locale::tr("trainer.path"), state.trainer_file_path, sizeof(state.trainer_file_path));
  ImGui::SameLine();
  if (ImGui::SmallButton((std::string(icons::kLoad) + "##trainerpath").c_str())) {
    std::string picked = memdbg::frontend::ui::pickFile(locale::tr("file_picker.open_trainer"), locale::tr("file_picker.trainer_files"), "*.cht;*.shn;*.json");
    if (!picked.empty())
      std::snprintf(state.trainer_file_path, sizeof(state.trainer_file_path), "%s", picked.c_str());
  }
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("file_picker.open_trainer"));
  if (ui::soft_button((std::string(icons::kLoad) + "  " + locale::tr("trainer.load")).c_str(),
      ImVec2((ImGui::GetContentRegionAvail().x-8.0f)*0.5f,38))) {
    if (load_trainer_file(state, state.trainer_file_path) < 0) {
      /* error already set by load_trainer_file */
    }
  }
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kSave) + "  " + locale::tr("trainer.save")).c_str(), ImVec2(0,38))) {
    save_trainer_file(state, state.trainer_file_path);
  }

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.batchcode_import"));
  ImGui::InputTextMultiline("##Batchcode", state.batchcode_text, sizeof(state.batchcode_text), ImVec2(0,120));
  if (ui::soft_button((std::string(icons::kImport) + "  " + locale::tr("trainer.import_batchcode")).c_str(), ui::full_button(38))) import_batchcode(state);
  ui::text_dim(locale::tr("trainer.batchcode_hint"));
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("TrainerList", locale::tr("trainer.runtime_cheat_list"), ImVec2(0, avail.y));

  /* Apply locked cheats automatically */
  apply_locked_cheats(state);

  ImGui::BeginDisabled(!state.client.connected());
  const float action_btn_w = (ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f;
  if (ui::soft_button((std::string(icons::kPlay) + "  " + locale::tr("trainer.apply_enabled")).c_str(), ImVec2(action_btn_w, 38))) {
    int applied=0;
    for (auto &cheat : state.cheats) if (cheat.enabled && apply_cheat(state,cheat)) applied++;
    set_status(state, "Applied "+std::to_string(applied)+" trainer entries");
    push_notification(state, "Applied " + std::to_string(applied) + " trainer entries");
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kTrash) + "  " + locale::tr("trainer.clear_disabled")).c_str(), ImVec2(0, 38))) {
    state.cheats.erase(std::remove_if(state.cheats.begin(), state.cheats.end(),
      [](const CheatEntry &c){ return !c.enabled; }), state.cheats.end());
  }
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, locale::tr("trainer.n_entries"), state.cheats.size());
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
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0,0))) {
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
      if (ImGui::SmallButton(locale::tr("trainer.btn_on"))) {
        if (apply_cheat(state,cheat)) { set_status(state, cheat.description+" applied"); push_notification(state, cheat.description + " applied"); }
        else set_status(state, cheat.status);
      }
      ImGui::SameLine();
      if (ImGui::SmallButton(locale::tr("trainer.btn_off"))) {
        if (deactivate_cheat(state,cheat)) { set_status(state, cheat.description+" restored"); push_notification(state, cheat.description + " restored"); }
        else set_status(state, cheat.status);
      }
      ImGui::SameLine();
      if (ImGui::SmallButton(locale::tr("trainer.btn_cap"))) {
        if (capture_off_value(state,cheat)) set_status(state, cheat.description+" OFF captured");
        else set_status(state, cheat.status);
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

/*
 * MemDBG - Trainer screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "trainer_format.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace memdbg::frontend {

/* build_value_bytes and build_scan_value are in app_state.hpp */
/* trainer load/save now in trainer_format.cpp */

/* ---- Cheat operations ---- */
static bool capture_cheat_off_value(AppState &state, CheatEntry &cheat) {
  if (!state.client.connected()) { cheat.status="No console session"; return false; }
  int32_t pid = cheat.pid>0 ? cheat.pid : state.selected_pid;
  if (pid<=0||cheat.bytes.empty()) { cheat.status="No target value"; return false; }
  std::vector<uint8_t> current;
  if (!state.client.memory_read(pid, cheat.address, static_cast<uint32_t>(cheat.bytes.size()), current) ||
      current.size()!=cheat.bytes.size()) {
    cheat.status = state.client.last_error().empty()?"OFF capture failed":state.client.last_error();
    return false;
  }
  cheat.off_bytes = std::move(current);
  cheat.has_off_bytes = true;
  cheat.status = "OFF value captured";
  return true;
}

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
  if (state.client.connected()) (void)capture_cheat_off_value(state, cheat);
  state.cheats.push_back(std::move(cheat));
  set_status(state, "Trainer entry added");
  push_notification(state, "Trainer entry added: " + std::string(state.cheat_description));
}

/* ---- load/save now in trainer_format.cpp ---- */

/* ---- Batchcode ---- */
static std::string batch_value_after(const std::string &text, const char *key, size_t start_pos) {
  size_t pos=text.find(key, start_pos);
  if (pos==std::string::npos) return {};
  pos+=std::strlen(key);
  while (pos<text.size()&&std::isspace(static_cast<unsigned char>(text[pos]))!=0) ++pos;
  size_t end=pos;
  while (end<text.size()&&text[end]!=';'&&text[end]!='|'&&std::isspace(static_cast<unsigned char>(text[end]))==0) ++end;
  return text.substr(pos, end-pos);
}

static void import_batchcode(AppState &state) {
  if (state.selected_pid<=0) { set_status(state,"Select a process before importing batchcode"); return; }
  std::string text = state.batchcode_text;
  size_t pos=0;
  int imported=0;
  while ((pos=text.find("offset:", pos))!=std::string::npos) {
    std::string offset_text=batch_value_after(text,"offset:",pos);
    std::string value_text=batch_value_after(text,"value:",pos);
    std::string size_text=batch_value_after(text,"size:",pos);
    pos+=7;
    uint64_t address=0, size=0;
    std::vector<uint8_t> bytes;
    if (!parse_u64(offset_text.c_str(),address)||!parse_hex_bytes(value_text.c_str(),bytes)) continue;
    if (!size_text.empty()&&parse_u64(size_text.c_str(),size)&&size>0) {
      if (bytes.size()>size) bytes.resize(static_cast<size_t>(size));
      else bytes.resize(static_cast<size_t>(size), 0);
    }
    CheatEntry cheat;
    cheat.description="Batchcode "+std::to_string(imported+1);
    cheat.pid=state.selected_pid; cheat.address=address; cheat.value_type=MEMDBG_VALUE_BYTES;
    cheat.value_text=value_text; cheat.bytes=std::move(bytes);
    state.cheats.push_back(std::move(cheat)); imported++;
  }
  set_status(state, imported>0?"Imported "+std::to_string(imported)+" batchcode entries":"No batchcode entries imported");
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
  const float left_w = std::max(420.0f, (avail.x - gap) * 0.36f);
  const char *type_names[] = {"Bytes","u8","u16","u32","u64","float","double","pointer"};

  ui::begin_panel("TrainerBuilder", "Cheat Builder", ImVec2(left_w, avail.y));
  ImGui::Text("Active PID: %d", state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  if (ui::soft_button("Use Memory Address", ImVec2(185,36)))
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s", state.write_address);
  ImGui::SameLine();
  if (!state.scan_result.addresses.empty() && ui::soft_button("Use First Scan Hit", ImVec2(190,36)))
    std::snprintf(state.cheat_address, sizeof(state.cheat_address), "%s", hex_u64(state.scan_result.addresses.front()).c_str());

  ImGui::TextColored(ui::colors().muted, "Name");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText("##CheatName", state.cheat_description, sizeof(state.cheat_description));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText("Address", state.cheat_address, sizeof(state.cheat_address));
  ImGui::Combo("Value type", &state.cheat_type, type_names, IM_ARRAYSIZE(type_names));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText("Value", state.cheat_value, sizeof(state.cheat_value));
  ImGui::Checkbox("Lock value", &state.cheat_lock);
  ImGui::SliderFloat("Lock interval", &state.cheat_lock_interval, 0.10f, 5.0f, "%.2fs");
  bool can_train = state.client.connected() && state.selected_pid > 0;
  ImGui::BeginDisabled(!can_train);
  if (ui::primary_button((std::string(icons::kAdd) + "  Add To Trainer").c_str(), ui::full_button(40))) add_cheat_from_fields(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Trainer File");
  ImGui::InputText("Path", state.trainer_file_path, sizeof(state.trainer_file_path));
  if (ui::soft_button((std::string(icons::kLoad) + "  Load").c_str(),
      ImVec2((ImGui::GetContentRegionAvail().x-8.0f)*0.5f,38))) {
    if (load_trainer_file(state, state.trainer_file_path) < 0) {
      /* error already set by load_trainer_file */
    }
  }
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kSave) + "  Save").c_str(), ImVec2(0,38))) {
    save_trainer_file(state, state.trainer_file_path);
  }

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Batchcode Import");
  ImGui::InputTextMultiline("##Batchcode", state.batchcode_text, sizeof(state.batchcode_text), ImVec2(0,120));
  if (ui::soft_button((std::string(icons::kImport) + "  Import Batchcode").c_str(), ui::full_button(38))) import_batchcode(state);
  ui::text_dim("Tokens: offset:0x... value:0x... size:n, also AOB: pattern:??...");
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("TrainerList", "Runtime Cheat List", ImVec2(0, avail.y));

  /* Apply locked cheats automatically */
  apply_locked_cheats(state);

  ImGui::BeginDisabled(!state.client.connected());
  if (ui::soft_button((std::string(icons::kPlay) + "  Apply Enabled").c_str(), ImVec2(150,38))) {
    int applied=0;
    for (auto &cheat : state.cheats) if (cheat.enabled && apply_cheat(state,cheat)) applied++;
    set_status(state, "Applied "+std::to_string(applied)+" trainer entries");
    push_notification(state, "Applied " + std::to_string(applied) + " trainer entries");
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kTrash) + "  Clear Disabled").c_str(), ImVec2(150,38))) {
    state.cheats.erase(std::remove_if(state.cheats.begin(), state.cheats.end(),
      [](const CheatEntry &c){ return !c.enabled; }), state.cheats.end());
  }
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%zu entries", state.cheats.size());
  ImGui::Spacing();

  if (state.cheats.empty()) {
    ui::draw_empty_state("No trainer entries", "Add scan hits or manual addresses to build a runtime cheat list.");
  } else if (ImGui::BeginTable("TrainerTable", 10,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0,0))) {
    ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed,44);
    ImGui::TableSetupColumn("Lock", ImGuiTableColumnFlags_WidthFixed,54);
    ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed,74);
    ImGui::TableSetupColumn("Name");
    ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed,70);
    ImGui::TableSetupColumn("Address");
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed,70);
    ImGui::TableSetupColumn("Value");
    ImGui::TableSetupColumn("OFF", ImGuiTableColumnFlags_WidthFixed,54);
    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed,190);
    ImGui::TableHeadersRow();
    for (int i=0; i<static_cast<int>(state.cheats.size()); ++i) {
      CheatEntry &cheat = state.cheats[i];
      ImGui::PushID(i);
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0); ImGui::Checkbox("##enabled", &cheat.enabled);
      ImGui::TableSetColumnIndex(1); ImGui::Checkbox("##locked", &cheat.locked);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextColored(cheat.active?ui::colors().success:ui::colors().dim, "%s", cheat.active?"Active":"Idle");
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(cheat.description.c_str());
      if (!cheat.status.empty()&&ImGui::IsItemHovered()) ImGui::SetTooltip("%s", cheat.status.c_str());
      ImGui::TableSetColumnIndex(4); ImGui::Text("%d", cheat.pid);
      ImGui::TableSetColumnIndex(5); ImGui::TextUnformatted(hex_u64(cheat.address).c_str());
      ImGui::TableSetColumnIndex(6); ImGui::TextUnformatted(value_type_name(cheat.value_type));
      ImGui::TableSetColumnIndex(7); ImGui::TextUnformatted(cheat.value_text.c_str());
      ImGui::TableSetColumnIndex(8);
      ImGui::TextColored(cheat.has_off_bytes?ui::colors().success:ui::colors().warning, "%s", cheat.has_off_bytes?"Yes":"No");
      ImGui::TableSetColumnIndex(9);
      if (ImGui::SmallButton("On")) {
        if (apply_cheat(state,cheat)) { set_status(state, cheat.description+" applied"); push_notification(state, cheat.description + " applied"); }
        else set_status(state, cheat.status);
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Off")) {
        if (deactivate_cheat(state,cheat)) { set_status(state, cheat.description+" restored"); push_notification(state, cheat.description + " restored"); }
        else set_status(state, cheat.status);
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Cap")) {
        if (capture_cheat_off_value(state,cheat)) set_status(state, cheat.description+" OFF captured");
        else set_status(state, cheat.status);
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

/*
 * MemDBG - Memory screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <algorithm>
#include <cstdio>

namespace memdbg::frontend {

static void read_memory(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); return; }
  uint64_t address = 0;
  if (!parse_u64(state.read_address, address)) { set_status(state, "Invalid read address"); return; }
  state.read_length = std::clamp(state.read_length, 1, static_cast<int>(MEMDBG_PROTOCOL_MAX_READ));
  if (!state.client.memory_read(state.selected_pid, address, static_cast<uint32_t>(state.read_length), state.memory)) {
    set_status(state, state.client.last_error()); return;
  }
  set_status(state, "Read " + std::to_string(state.memory.size()) + " bytes");
}

static void write_memory(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); return; }
  uint64_t address = 0;
  std::vector<uint8_t> data;
  if (!parse_u64(state.write_address, address)) { set_status(state, "Invalid write address"); return; }
  if (!parse_hex_bytes(state.write_bytes, data)) { set_status(state, "Invalid byte list"); return; }
  uint32_t written = 0;
  if (!state.client.memory_write(state.selected_pid, address, data, written)) {
    set_status(state, state.client.last_error()); return;
  }
  set_status(state, "Wrote " + std::to_string(written) + " bytes");
}

void draw_memory(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float left_w = std::max(380.0f, (avail.x - gap) * 0.35f);

  ui::begin_panel("MemoryTools", "Memory Tools", ImVec2(left_w, avail.y));
  ImGui::Text("Active PID: %d", state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

  ImGui::InputText("Read address", state.read_address, sizeof(state.read_address));
  ImGui::InputInt("Read length", &state.read_length);
  state.read_length = std::clamp(state.read_length, 1, static_cast<int>(MEMDBG_PROTOCOL_MAX_READ));
  bool can_read = state.client.connected() && state.selected_pid > 0;
  ImGui::BeginDisabled(!can_read);
  if (ui::primary_button((std::string(icons::kPlay) + "  Read Memory").c_str(), ui::full_button(40))) read_memory(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::InputText("Write address", state.write_address, sizeof(state.write_address));
  ImGui::InputText("Bytes", state.write_bytes, sizeof(state.write_bytes));
  bool can_write = state.client.connected() && state.selected_pid > 0;
  ImGui::BeginDisabled(!can_write);
  if (ui::danger_button((std::string(icons::kEdit) + "  Write Memory").c_str(), ui::full_button(40))) write_memory(state);
  ImGui::EndDisabled();

  ImGui::Spacing();
  ui::text_dim("Accepted byte formats: DEADBEEF or DE AD BE EF");
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("MemoryHex", "Hex View", ImVec2(0, avail.y));
  uint64_t base = 0;
  (void)parse_u64(state.read_address, base);
  ui::draw_hex_view(state.memory, base);
  ui::end_panel();
}

} // namespace memdbg::frontend

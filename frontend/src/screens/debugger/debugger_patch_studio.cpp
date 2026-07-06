/*
 * MemDBG - Patch Studio (compose, apply, restore patches).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "debugger_internal.hpp"

namespace memdbg::frontend {

size_t visible_disasm_byte_count(const std::string &bytes) {
  std::istringstream in(bytes);
  std::string token;
  size_t count = 0U;
  while (in >> token) {
    while (!token.empty() && (token.back() == ',' || token.back() == ';'))
      token.pop_back();
    if (token.size() != 2U || !is_hex_digit_string(token)) break;
    ++count;
  }
  return count;
}

std::string disasm_bytes_compact(const std::string &bytes) {
  std::istringstream in(bytes);
  std::string token;
  std::string out;
  while (in >> token) {
    while (!token.empty() && (token.back() == ',' || token.back() == ';'))
      token.pop_back();
    if (token.size() != 2U || !is_hex_digit_string(token)) break;
    out += token;
  }
  return out;
}

void set_patch_address(DebuggerState &ds, uint64_t address) {
  std::snprintf(ds.patch_addr_input, sizeof(ds.patch_addr_input),
                "0x%016" PRIX64, address);
}

void set_patch_bytes(DebuggerState &ds, const std::vector<uint8_t> &bytes) {
  const std::string hex = bytes_to_hex(bytes);
  std::snprintf(ds.patch_bytes_input, sizeof(ds.patch_bytes_input), "%s",
                hex.c_str());
}

void stage_patch_from_disasm_line(AppState &state, DebuggerState &ds,
                                   const debugger::DisassemblyLine &line,
                                   bool nop_fill) {
  const size_t byte_count = std::clamp(visible_disasm_byte_count(line.bytes),
                                       size_t{1U}, kPatchStudioMaxBytes);
  set_patch_address(ds, line.address);
  std::snprintf(ds.patch_name, sizeof(ds.patch_name), "%s",
                line.mnemonic.empty() ? "Code patch" : line.mnemonic.c_str());
  ds.patch_length = static_cast<int>(byte_count);
  if (nop_fill) {
    ds.patch_mode = 1;
    std::vector<uint8_t> nop(byte_count, 0x90U);
    set_patch_bytes(ds, nop);
    set_status(state, "Patch Studio staged NOP at " + hex_u64(line.address));
  } else {
    ds.patch_mode = 0;
    const std::string compact = disasm_bytes_compact(line.bytes);
    std::snprintf(ds.patch_bytes_input, sizeof(ds.patch_bytes_input), "%s",
                  compact.empty() ? "90" : compact.c_str());
    set_status(state, "Patch Studio staged " + hex_u64(line.address));
  }
}

bool build_patch_bytes(const DebuggerState &ds,
                        std::vector<uint8_t> &out,
                        std::string &error) {
  out.clear();
  const int length = std::clamp(ds.patch_length, 1,
                                static_cast<int>(kPatchStudioMaxBytes));
  switch (ds.patch_mode) {
  case 0:
    if (!parse_hex_bytes(ds.patch_bytes_input, out)) {
      error = "Invalid patch bytes";
      return false;
    }
    if (out.size() > kPatchStudioMaxBytes) {
      error = "Patch is larger than 256 bytes";
      return false;
    }
    return true;
  case 1:
    out.assign(static_cast<size_t>(length), 0x90U);
    return true;
  case 2:
    out.assign(static_cast<size_t>(length), 0xCCU);
    return true;
  default:
    error = "Unknown patch mode";
    return false;
  }
}

bool read_patch_original(AppState &state, DebuggerState &ds,
                          uint64_t address, size_t length,
                          std::vector<uint8_t> &out,
                          std::string &error) {
  out.clear();
  if (length == 0U || length > kPatchStudioMaxBytes) {
    error = "Invalid patch length";
    return false;
  }
  if (!state.client.memory_read(ds.pid, address, static_cast<uint32_t>(length),
                                out) ||
      out.size() != length) {
    error = "Read original bytes: " + state.client.last_error();
    return false;
  }
  return true;
}

bool write_patch_bytes(AppState &state, DebuggerState &ds,
                        uint64_t address,
                        const std::vector<uint8_t> &bytes,
                        DebuggerState::PatchEntry *entry,
                        std::string &error) {
  if (bytes.empty()) {
    error = "Patch is empty";
    return false;
  }

  bool protected_write = false;
  uint32_t old_protection = 0U;
  uint32_t new_protection = 0U;
  if (ds.patch_use_mprotect &&
      payload_supports(state, MEMDBG_CAP_MEMORY_PROTECT)) {
    Client::ProcessProtectResult protection{};
    if (state.client.process_protect(
            ds.pid, address, static_cast<uint64_t>(bytes.size()),
            MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE |
                MEMDBG_MAP_PROT_EXEC,
            protection)) {
      protected_write = true;
      old_protection = protection.old_protection;
      new_protection = protection.new_protection;
      if (entry != nullptr) {
        entry->original_protection = old_protection;
        entry->applied_protection = new_protection;
        entry->has_protection = true;
      }
    }
  }

  uint32_t written = 0U;
  if (!state.client.memory_write(ds.pid, address, bytes, written) ||
      written != bytes.size()) {
    error = "Write patch: " + state.client.last_error();
    if (protected_write && ds.patch_restore_protection &&
        old_protection != 0U) {
      Client::ProcessProtectResult ignored{};
      (void)state.client.process_protect(
          ds.pid, address, static_cast<uint64_t>(bytes.size()),
          old_protection, ignored);
    }
    return false;
  }

  if (protected_write && ds.patch_restore_protection &&
      old_protection != 0U) {
    Client::ProcessProtectResult restored{};
    if (!state.client.process_protect(
            ds.pid, address, static_cast<uint64_t>(bytes.size()),
            old_protection, restored)) {
      error = "Patch written, protection restore failed: " +
              state.client.last_error();
      if (entry != nullptr) entry->status = error;
      return true;
    }
  }

  if (entry != nullptr) {
    entry->status = "Wrote " + std::to_string(written) + " bytes";
  }
  return true;
}

bool compose_patch_entry(AppState &state, DebuggerState &ds,
                          DebuggerState::PatchEntry &entry,
                          std::string &error) {
  uint64_t address = 0;
  if (!parse_input_u64(ds.patch_addr_input, address)) {
    error = "Invalid patch address";
    return false;
  }
  std::vector<uint8_t> patched;
  if (!build_patch_bytes(ds, patched, error)) return false;

  entry = DebuggerState::PatchEntry{};
  entry.address = address;
  entry.label = ds.patch_name[0] != '\0' ? ds.patch_name : "Code patch";
  entry.patched = std::move(patched);
  if (!read_patch_original(state, ds, entry.address, entry.patched.size(),
                           entry.original, error)) {
    return false;
  }
  entry.status = "Captured " + std::to_string(entry.original.size()) +
                 " original bytes";
  return true;
}

void capture_patch(AppState &state, DebuggerState &ds) {
  DebuggerState::PatchEntry entry;
  std::string error;
  if (!compose_patch_entry(state, ds, entry, error)) {
    set_status(state, "Patch capture: " + error);
    return;
  }
  ds.patches.push_back(std::move(entry));
  set_status(state, "Patch captured");
}

void apply_composed_patch(AppState &state, DebuggerState &ds) {
  DebuggerState::PatchEntry entry;
  std::string error;
  if (!compose_patch_entry(state, ds, entry, error)) {
    set_status(state, "Patch apply: " + error);
    return;
  }
  if (!write_patch_bytes(state, ds, entry.address, entry.patched, &entry,
                         error)) {
    set_status(state, "Patch apply: " + error);
    return;
  }
  entry.applied = true;
  ds.patches.push_back(std::move(entry));
  ds.disasm_needs_refresh = true;
  refresh_disasm(state);
  set_status(state, "Patch applied");
  push_notification(state, "Patch applied at " + hex_u64(ds.patches.back().address));
}

void reapply_patch(AppState &state, DebuggerState &ds,
                    DebuggerState::PatchEntry &entry) {
  std::string error;
  if (!write_patch_bytes(state, ds, entry.address, entry.patched, &entry,
                         error)) {
    entry.status = error;
    set_status(state, "Patch reapply: " + error);
    return;
  }
  entry.applied = true;
  ds.disasm_needs_refresh = true;
  refresh_disasm(state);
  set_status(state, "Patch reapplied");
}

void restore_patch(AppState &state, DebuggerState &ds,
                    DebuggerState::PatchEntry &entry) {
  if (entry.original.empty()) {
    entry.status = "No original bytes captured";
    set_status(state, entry.status);
    return;
  }
  std::string error;
  if (!write_patch_bytes(state, ds, entry.address, entry.original, &entry,
                         error)) {
    entry.status = error;
    set_status(state, "Patch restore: " + error);
    return;
  }
  entry.applied = false;
  entry.status = "Original bytes restored";
  ds.disasm_needs_refresh = true;
  refresh_disasm(state);
  set_status(state, "Patch restored");
}

void add_patch_to_trainer(AppState &state, DebuggerState &ds,
                           const DebuggerState::PatchEntry &entry) {
  if (entry.patched.empty() || entry.original.empty()) {
    set_status(state, "Patch must have ON and OFF bytes before trainer export");
    return;
  }
  CheatEntry cheat;
  cheat.description = entry.label.empty() ? "Patch Studio" : entry.label;
  cheat.pid = ds.pid;
  cheat.address = entry.address;
  cheat.value_type = MEMDBG_VALUE_BYTES;
  cheat.value_text = bytes_to_hex(entry.patched);
  cheat.bytes = entry.patched;
  cheat.off_bytes = entry.original;
  cheat.has_off_bytes = true;
  cheat.enabled = true;
  cheat.locked = false;
  cheat.status = "Created from Patch Studio";
  state.cheats.push_back(std::move(cheat));
  set_status(state, "Patch exported to Trainer");
  push_notification(state, "Trainer entry added from Patch Studio");
}

void save_patches_to_file(AppState &state, DebuggerState &ds,
                           const char *path) {
  std::ofstream out(path);
  if (!out) {
    set_status(state, std::string("Cannot write: ") + path);
    return;
  }
  out << "# MemDBG Patch Studio\n";
  out << "# format: address applied original_hex patched_hex label\n";
  for (const auto &patch : ds.patches) {
    std::string label = patch.label;
    std::replace(label.begin(), label.end(), '\t', ' ');
    out << hex_u64(patch.address) << "\t"
        << (patch.applied ? 1 : 0) << "\t"
        << bytes_to_hex(patch.original) << "\t"
        << bytes_to_hex(patch.patched) << "\t"
        << label << "\n";
  }
  set_status(state, "Saved " + std::to_string(ds.patches.size()) +
                    " patch(es) to " + path);
}

void load_patches_from_file(AppState &state, DebuggerState &ds,
                             const char *path) {
  std::ifstream in(path);
  if (!in) {
    set_status(state, std::string("Cannot read: ") + path);
    return;
  }

  size_t loaded = 0U;
  std::string line;
  while (std::getline(in, line)) {
    line = trim_copy(std::move(line));
    if (line.empty() || line[0] == '#') continue;

    std::istringstream row(line);
    std::string addr_text;
    std::string applied_text;
    std::string original_text;
    std::string patched_text;
    if (!(row >> addr_text >> applied_text >> original_text >> patched_text))
      continue;
    std::string label;
    std::getline(row, label);
    label = trim_copy(std::move(label));

    uint64_t address = 0;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
    if (!parse_input_u64(addr_text.c_str(), address) ||
        !parse_hex_bytes(original_text.c_str(), original) ||
        !parse_hex_bytes(patched_text.c_str(), patched) ||
        original.empty() || patched.empty()) {
      continue;
    }

    DebuggerState::PatchEntry entry;
    entry.address = address;
    entry.label = label.empty() ? "Loaded patch" : label;
    entry.original = std::move(original);
    entry.patched = std::move(patched);
    entry.applied = applied_text == "1" || applied_text == "true";
    entry.status = "Loaded from patch manifest";
    ds.patches.push_back(std::move(entry));
    ++loaded;
  }

  set_status(state, "Loaded " + std::to_string(loaded) +
                    " patch(es) from " + path);
}

void draw_patch_studio(AppState &state, DebuggerState &ds,
                        bool client_busy, float scl) {
  ImGui::TextColored(ui::colors().muted, "Patch Studio  PID %d", ds.pid);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%s",
                     payload_supports(state, MEMDBG_CAP_MEMORY_PROTECT)
                         ? "mprotect available"
                         : "write-only protection path");
  ImGui::Spacing();

  const char *modes[] = {"Bytes", "NOP fill", "INT3 fill"};
  ImGui::BeginDisabled(client_busy || !ds.stopped || ds.selected_lwp == 0);
  if (ImGui::BeginTable("PatchStudioEditor", 5,
                        ImGuiTableFlags_SizingStretchProp |
                            ImGuiTableFlags_PadOuterX)) {
    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed,
                            170.0f * scl);
    ImGui::TableSetupColumn("Mode", ImGuiTableColumnFlags_WidthFixed,
                            112.0f * scl);
    ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed,
                            74.0f * scl);
    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed,
                            188.0f * scl);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    set_table_item_width(150.0f * scl);
    ImGui::InputText("##patchname", ds.patch_name, sizeof(ds.patch_name));
    ImGui::TableSetColumnIndex(1);
    set_table_item_width(150.0f * scl);
    ImGui::InputText("##patchaddr", ds.patch_addr_input,
                     sizeof(ds.patch_addr_input),
                     ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::TableSetColumnIndex(2);
    set_table_item_width(104.0f * scl);
    ImGui::Combo("##patchmode", &ds.patch_mode, modes, IM_ARRAYSIZE(modes));
    ImGui::TableSetColumnIndex(3);
    set_table_item_width(62.0f * scl);
    ImGui::InputInt("##patchlength", &ds.patch_length);
    ds.patch_length = std::clamp(ds.patch_length, 1,
                                 static_cast<int>(kPatchStudioMaxBytes));
    ImGui::TableSetColumnIndex(4);
    if (ui::soft_button((std::string(icons::kSave) + "  Capture").c_str(),
                        ImVec2(88.0f * scl, 0))) {
      capture_patch(state, ds);
    }
    ImGui::SameLine();
    if (ui::primary_button((std::string(icons::kEdit) + "  Apply").c_str(),
                           ImVec2(90.0f * scl, 0))) {
      apply_composed_patch(state, ds);
    }
    ImGui::EndTable();
  }

  ImGui::Spacing();
  if (ds.patch_mode == 0) {
    ImGui::TextColored(ui::colors().muted, "%s", "Patch bytes");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##patchbytes", ds.patch_bytes_input,
                     sizeof(ds.patch_bytes_input));
  } else {
    std::vector<uint8_t> preview(static_cast<size_t>(ds.patch_length),
                                 ds.patch_mode == 1 ? 0x90U : 0xCCU);
    set_patch_bytes(ds, preview);
    ImGui::TextColored(ui::colors().dim, "Generated bytes: %s",
                       ds.patch_bytes_input);
  }

  ImGui::Checkbox("Use mprotect when available", &ds.patch_use_mprotect);
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", "Temporarily adds write permission for code maps when the payload supports PROCESS_PROTECT");
  ImGui::SameLine();
  ImGui::Checkbox("Restore protection", &ds.patch_restore_protection);
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", "Restore the previous map protection after writing the patch");
  ImGui::EndDisabled();

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  ImGui::BeginDisabled(client_busy);
  ImGui::SetNextItemWidth(220.0f * scl);
  ImGui::InputText("##patchfile", ds.patch_filename,
                   sizeof(ds.patch_filename));
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kSave) + "  Save").c_str(),
                      ImVec2(88.0f * scl, 0))) {
    save_patches_to_file(state, ds, ds.patch_filename);
  }
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kLoad) + "  Load").c_str(),
                      ImVec2(88.0f * scl, 0))) {
    load_patches_from_file(state, ds, ds.patch_filename);
  }
  ImGui::EndDisabled();

  ImGui::Spacing();
  if (ds.patches.empty()) {
    ui::draw_empty_state("No patches staged",
                         "Right-click disassembly rows to stage code patches, then capture or apply them here.");
    return;
  }

  const float table_h =
      std::max(200.0f * scl, ImGui::GetContentRegionAvail().y - 8.0f * scl);
  if (ImGui::BeginTable("PatchStudioTable", 8,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                            ImGuiTableFlags_ScrollY |
                            ImGuiTableFlags_ScrollX |
                            ImGuiTableFlags_Resizable,
                        ImVec2(0, table_h))) {
    ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed,
                            44.0f * scl);
    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.1f);
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed,
                            158.0f * scl);
    ImGui::TableSetupColumn("Original", ImGuiTableColumnFlags_WidthFixed,
                            170.0f * scl);
    ImGui::TableSetupColumn("Patch", ImGuiTableColumnFlags_WidthFixed,
                            170.0f * scl);
    ImGui::TableSetupColumn("Prot", ImGuiTableColumnFlags_WidthFixed,
                            80.0f * scl);
    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed,
                            330.0f * scl);
    ImGui::TableHeadersRow();
    for (size_t i = 0; i < ds.patches.size(); ++i) {
      auto &patch = ds.patches[i];
      ImGui::PushID(static_cast<int>(i));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextColored(patch.applied ? ui::colors().success
                                       : ui::colors().dim,
                         "%s", patch.applied ? "ON" : "OFF");
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(patch.label.c_str());
      if (ImGui::IsItemHovered() && !patch.label.empty())
        ImGui::SetTooltip("%s", patch.label.c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(hex_u64(patch.address).c_str());
      ImGui::TableSetColumnIndex(3);
      const std::string original = bytes_to_hex(patch.original);
      ImGui::TextUnformatted(original.c_str());
      if (ImGui::IsItemHovered() && !original.empty())
        ImGui::SetTooltip("%s", original.c_str());
      ImGui::TableSetColumnIndex(4);
      const std::string patched = bytes_to_hex(patch.patched);
      ImGui::TextUnformatted(patched.c_str());
      if (ImGui::IsItemHovered() && !patched.empty())
        ImGui::SetTooltip("%s", patched.c_str());
      ImGui::TableSetColumnIndex(5);
      if (patch.has_protection)
        ImGui::Text("%s>%s", prot_text(patch.original_protection).c_str(),
                    prot_text(patch.applied_protection).c_str());
      else
        ImGui::TextColored(ui::colors().dim, "%s", "-");
      ImGui::TableSetColumnIndex(6);
      ImGui::TextColored(patch.status.find("failed") != std::string::npos
                             ? ui::colors().warning
                             : ui::colors().muted,
                         "%s", patch.status.c_str());
      ImGui::TableSetColumnIndex(7);
      ImGui::BeginDisabled(client_busy || !ds.stopped);
      if (ImGui::SmallButton("Apply"))
        reapply_patch(state, ds, patch);
      ImGui::SameLine();
      if (ImGui::SmallButton("Restore"))
        restore_patch(state, ds, patch);
      ImGui::EndDisabled();
      ImGui::SameLine();
      if (ImGui::SmallButton("Trainer"))
        add_patch_to_trainer(state, ds, patch);
      ImGui::SameLine();
      if (ImGui::SmallButton("Notebook")) {
        add_notebook_entry(state, ds, patch.address, "patch",
                           patch.label, bytes_to_hex(patch.patched),
                           "Original " + bytes_to_hex(patch.original) +
                               "; " + patch.status);
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Stage")) {
        set_patch_address(ds, patch.address);
        std::snprintf(ds.patch_name, sizeof(ds.patch_name), "%s",
                      patch.label.c_str());
        ds.patch_mode = 0;
        ds.patch_length = static_cast<int>(patch.patched.size());
        set_patch_bytes(ds, patch.patched);
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Forget")) {
        ds.patches.erase(ds.patches.begin() + static_cast<std::ptrdiff_t>(i));
        ImGui::PopID();
        break;
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
}

} // namespace memdbg::frontend

/*
 * MemDBG - Analysis Notebook (bookmarks, workspace persistence, reporting).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "debugger_internal.hpp"

namespace memdbg::frontend {

const char *notebook_kind_name(int kind) {
  switch (kind) {
  case 0: return "code";
  case 1: return "data";
  case 2: return "stack";
  case 3: return "patch";
  case 4: return "note";
  default: return "note";
  }
}

std::string workspace_escape(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  for (char ch : value) {
    switch (ch) {
    case '\\': out += "\\\\"; break;
    case '\t': out += "\\t"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    default: out.push_back(ch); break;
    }
  }
  return out;
}

std::string workspace_unescape(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  for (size_t i = 0; i < value.size(); ++i) {
    if (value[i] != '\\' || i + 1U >= value.size()) {
      out.push_back(value[i]);
      continue;
    }
    const char next = value[++i];
    switch (next) {
    case '\\': out.push_back('\\'); break;
    case 't': out.push_back('\t'); break;
    case 'n': out.push_back('\n'); break;
    case 'r': out.push_back('\r'); break;
    default:
      out.push_back('\\');
      out.push_back(next);
      break;
    }
  }
  return out;
}

std::vector<std::string> split_tab_fields(const std::string &line) {
  std::vector<std::string> fields;
  size_t start = 0U;
  while (start <= line.size()) {
    const size_t pos = line.find('\t', start);
    if (pos == std::string::npos) {
      fields.push_back(line.substr(start));
      break;
    }
    fields.push_back(line.substr(start, pos - start));
    start = pos + 1U;
  }
  return fields;
}

std::string markdown_cell(std::string value) {
  value = trim_copy(std::move(value));
  for (char &ch : value) {
    if (ch == '|') ch = '/';
    else if (ch == '\n' || ch == '\r' || ch == '\t') ch = ' ';
  }
  return value.empty() ? "-" : value;
}

bool parse_notebook_bytes(const std::string &text,
                           std::vector<uint8_t> &out) {
  if (parse_hex_bytes(text.c_str(), out)) return true;
  const std::string compact = disasm_bytes_compact(text);
  return !compact.empty() && parse_hex_bytes(compact.c_str(), out);
}

void add_notebook_entry(AppState &state, DebuggerState &ds,
                         uint64_t address, const std::string &kind,
                         const std::string &label,
                         const std::string &bytes,
                         const std::string &note) {
  DebuggerState::NotebookEntry entry;
  entry.id = ds.notebook_next_id++;
  entry.address = address;
  entry.kind = kind.empty() ? "note" : kind;
  entry.label = label.empty() ? "Bookmark" : label;
  entry.bytes = bytes;
  entry.note = note;
  ds.notebook.push_back(std::move(entry));
  set_status(state, "Notebook bookmark added at " + hex_u64(address));
}

void add_notebook_from_register(AppState &state, DebuggerState &ds,
                                 const char *reg_name,
                                 uint64_t address) {
  char note[128];
  std::snprintf(note, sizeof(note), "Captured from %s while LWP %d was selected",
                reg_name, static_cast<int>(ds.selected_lwp));
  add_notebook_entry(state, ds, address,
                     std::strcmp(reg_name, "RSP") == 0 ||
                             std::strcmp(reg_name, "RBP") == 0
                         ? "stack"
                         : "code",
                     reg_name, "", note);
}

void save_notebook_to_file(AppState &state, DebuggerState &ds,
                            const char *path) {
  std::ofstream out(path);
  if (!out) {
    set_status(state, std::string("Cannot write: ") + path);
    return;
  }
  out << "# MemDBG Debugger Notebook\n";
  out << "# format: address kind label bytes note\n";
  for (const auto &entry : ds.notebook) {
    out << hex_u64(entry.address) << "\t"
        << workspace_escape(entry.kind) << "\t"
        << workspace_escape(entry.label) << "\t"
        << workspace_escape(entry.bytes) << "\t"
        << workspace_escape(entry.note) << "\n";
  }
  set_status(state, "Saved " + std::to_string(ds.notebook.size()) +
                    " notebook item(s) to " + path);
}

void load_notebook_from_file(AppState &state, DebuggerState &ds,
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
    const auto fields = split_tab_fields(line);
    if (fields.size() < 5U) continue;
    uint64_t address = 0;
    if (!parse_input_u64(fields[0].c_str(), address)) continue;
    DebuggerState::NotebookEntry entry;
    entry.id = ds.notebook_next_id++;
    entry.address = address;
    entry.kind = workspace_unescape(fields[1]);
    entry.label = workspace_unescape(fields[2]);
    entry.bytes = workspace_unescape(fields[3]);
    entry.note = workspace_unescape(fields[4]);
    ds.notebook.push_back(std::move(entry));
    ++loaded;
  }
  set_status(state, "Loaded " + std::to_string(loaded) +
                    " notebook item(s) from " + path);
}

void export_notebook_report(AppState &state, DebuggerState &ds,
                             const char *path) {
  std::ofstream out(path);
  if (!out) {
    set_status(state, std::string("Cannot write report: ") + path);
    return;
  }
  out << "# MemDBG Debugger Report\n\n";
  out << "- PID: " << ds.pid << "\n";
  out << "- Selected LWP: " << ds.selected_lwp << "\n";
  out << "- State: " << (ds.stopped ? "stopped" : "running") << "\n";
  out << "- RIP: " << hex_u64(static_cast<uint64_t>(ds.regs.regs.r_rip)) << "\n";
  out << "- RSP: " << hex_u64(static_cast<uint64_t>(ds.regs.regs.r_rsp)) << "\n";
  out << "- RBP: " << hex_u64(static_cast<uint64_t>(ds.regs.regs.r_rbp)) << "\n";
  out << "- Threads: " << ds.threads.size() << "\n";
  out << "- Breakpoints: " << ds.breakpoints.size() << "\n";
  out << "- Watchpoints: " << ds.watchpoints.size() << "\n";
  out << "- Patches: " << ds.patches.size() << "\n";
  out << "- Notebook items: " << ds.notebook.size() << "\n\n";

  out << "## Notebook\n\n";
  out << "| Kind | Address | Label | Bytes | Note |\n";
  out << "|---|---:|---|---|---|\n";
  for (const auto &entry : ds.notebook) {
    out << "| " << markdown_cell(entry.kind)
        << " | `" << hex_u64(entry.address) << "`"
        << " | " << markdown_cell(entry.label)
        << " | `" << markdown_cell(entry.bytes) << "`"
        << " | " << markdown_cell(entry.note) << " |\n";
  }

  out << "\n## Patches\n\n";
  out << "| State | Address | Label | Original | Patch | Status |\n";
  out << "|---|---:|---|---|---|---|\n";
  for (const auto &patch : ds.patches) {
    out << "| " << (patch.applied ? "applied" : "captured")
        << " | `" << hex_u64(patch.address) << "`"
        << " | " << markdown_cell(patch.label)
        << " | `" << bytes_to_hex(patch.original) << "`"
        << " | `" << bytes_to_hex(patch.patched) << "`"
        << " | " << markdown_cell(patch.status) << " |\n";
  }

  set_status(state, std::string("Notebook report exported to ") + path);
}

void set_notebook_address(DebuggerState &ds, uint64_t address) {
  std::snprintf(ds.notebook_addr_input, sizeof(ds.notebook_addr_input),
                "0x%016" PRIX64, address);
}

void draw_analysis_notebook(AppState &state, DebuggerState &ds,
                             bool client_busy, float scl) {
  static const char *kind_names[] = {"code", "data", "stack", "patch", "note"};

  ImGui::TextColored(ui::colors().muted, "Analysis Notebook  PID %d",
                     ds.pid);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%zu item(s)", ds.notebook.size());
  ImGui::Spacing();

  ImGui::BeginDisabled(client_busy);
  if (ImGui::BeginTable("NotebookEditor", 5,
                        ImGuiTableFlags_SizingStretchProp |
                            ImGuiTableFlags_PadOuterX)) {
    ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed,
                            96.0f * scl);
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed,
                            170.0f * scl);
    ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthStretch,
                            1.0f);
    ImGui::TableSetupColumn("Note", ImGuiTableColumnFlags_WidthStretch,
                            1.4f);
    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed,
                            116.0f * scl);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    set_table_item_width(88.0f * scl);
    ImGui::Combo("##notekind", &ds.notebook_kind, kind_names,
                 IM_ARRAYSIZE(kind_names));
    ImGui::TableSetColumnIndex(1);
    set_table_item_width(150.0f * scl);
    ImGui::InputText("##noteaddr", ds.notebook_addr_input,
                     sizeof(ds.notebook_addr_input),
                     ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::TableSetColumnIndex(2);
    set_table_item_width(140.0f * scl);
    ImGui::InputText("##notelabel", ds.notebook_label,
                     sizeof(ds.notebook_label));
    ImGui::TableSetColumnIndex(3);
    set_table_item_width(180.0f * scl);
    ImGui::InputText("##notenote", ds.notebook_note,
                     sizeof(ds.notebook_note));
    ImGui::TableSetColumnIndex(4);
    if (ui::primary_button((std::string(icons::kAdd) + "  Add").c_str(),
                           ImVec2(-1, 0))) {
      uint64_t address = 0;
      if (parse_input_u64(ds.notebook_addr_input, address)) {
        add_notebook_entry(state, ds, address,
                           notebook_kind_name(ds.notebook_kind),
                           ds.notebook_label, "", ds.notebook_note);
      } else {
        set_status(state, "Notebook: invalid address");
      }
    }
    ImGui::EndTable();
  }

  ImGui::Spacing();
  ImGui::BeginDisabled(!ds.stopped || ds.selected_lwp == 0);
  if (ui::soft_button("RIP", ImVec2(58.0f * scl, 0))) {
    const uint64_t value = static_cast<uint64_t>(ds.regs.regs.r_rip);
    set_notebook_address(ds, value);
    add_notebook_from_register(state, ds, "RIP", value);
  }
  ImGui::SameLine();
  if (ui::soft_button("RSP", ImVec2(58.0f * scl, 0))) {
    const uint64_t value = static_cast<uint64_t>(ds.regs.regs.r_rsp);
    set_notebook_address(ds, value);
    add_notebook_from_register(state, ds, "RSP", value);
  }
  ImGui::SameLine();
  if (ui::soft_button("RBP", ImVec2(58.0f * scl, 0))) {
    const uint64_t value = static_cast<uint64_t>(ds.regs.regs.r_rbp);
    set_notebook_address(ds, value);
    add_notebook_from_register(state, ds, "RBP", value);
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::SetNextItemWidth(190.0f * scl);
  ImGui::InputText("##notebookfile", ds.notebook_filename,
                   sizeof(ds.notebook_filename));
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kSave) + "  Save").c_str(),
                      ImVec2(86.0f * scl, 0))) {
    save_notebook_to_file(state, ds, ds.notebook_filename);
  }
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kLoad) + "  Load").c_str(),
                      ImVec2(86.0f * scl, 0))) {
    load_notebook_from_file(state, ds, ds.notebook_filename);
  }

  ImGui::Spacing();
  ImGui::SetNextItemWidth(190.0f * scl);
  ImGui::InputText("##notebookreport", ds.notebook_report_filename,
                   sizeof(ds.notebook_report_filename));
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kExport) + "  Report").c_str(),
                      ImVec2(106.0f * scl, 0))) {
    export_notebook_report(state, ds, ds.notebook_report_filename);
  }
  ImGui::SameLine();
  static bool skip_clear_notebook = false;
  if (ui::danger_button((std::string(icons::kTrash) + "  Clear").c_str(),
                        ImVec2(94.0f * scl, 0))) {
    ImGui::OpenPopup("ConfirmClearNotebook");
  }
  if (ui::confirm_modal("ConfirmClearNotebook",
                        "Clear the debugger notebook?",
                        "This removes the in-memory notebook items. Save first if you want to keep the workspace.",
                        &skip_clear_notebook, true)) {
    ds.notebook.clear();
    set_status(state, "Notebook cleared");
  }
  ImGui::EndDisabled();

  ImGui::Spacing();
  if (ds.notebook.empty()) {
    ui::draw_empty_state("No notebook items",
                         "Use the quick register buttons, manual address field, or right-click disassembly and stack rows.");
    return;
  }

  const float table_h =
      std::max(210.0f * scl, ImGui::GetContentRegionAvail().y - 8.0f * scl);
  if (ImGui::BeginTable("NotebookTable", 7,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                            ImGuiTableFlags_ScrollY |
                            ImGuiTableFlags_ScrollX |
                            ImGuiTableFlags_Resizable,
                        ImVec2(0, table_h))) {
    ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed,
                            78.0f * scl);
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed,
                            158.0f * scl);
    ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthStretch,
                            1.0f);
    ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed,
                            170.0f * scl);
    ImGui::TableSetupColumn("Note", ImGuiTableColumnFlags_WidthStretch,
                            1.2f);
    ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed,
                            58.0f * scl);
    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed,
                            256.0f * scl);
    ImGui::TableHeadersRow();

    for (size_t i = 0; i < ds.notebook.size(); ++i) {
      auto &entry = ds.notebook[i];
      ImGui::PushID(static_cast<int>(entry.id));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextColored(entry.kind == "patch" ? ui::colors().warning
                                               : ui::colors().muted,
                         "%s", entry.kind.c_str());
      ImGui::TableSetColumnIndex(1);
      const std::string addr = hex_u64(entry.address);
      if (ImGui::Selectable(addr.c_str(), false,
                            ImGuiSelectableFlags_SpanAllColumns)) {
        ds.disasm_nav_addr = entry.address;
        ds.disasm_reg_sel = 0;
        ds.disasm_follow_rip = false;
        ds.disasm_needs_refresh = true;
        refresh_disasm(state);
      }
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", "Click to navigate disassembly");
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(entry.label.c_str());
      if (ImGui::IsItemHovered() && !entry.label.empty())
        ImGui::SetTooltip("%s", entry.label.c_str());
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(entry.bytes.empty() ? "-" : entry.bytes.c_str());
      if (ImGui::IsItemHovered() && !entry.bytes.empty())
        ImGui::SetTooltip("%s", entry.bytes.c_str());
      ImGui::TableSetColumnIndex(4);
      ImGui::TextUnformatted(entry.note.empty() ? "-" : entry.note.c_str());
      if (ImGui::IsItemHovered() && !entry.note.empty())
        ImGui::SetTooltip("%s", entry.note.c_str());
      ImGui::TableSetColumnIndex(5);
      ImGui::Text("%" PRIu64, entry.id);
      ImGui::TableSetColumnIndex(6);
      ImGui::BeginDisabled(client_busy);
      if (ImGui::SmallButton("Disasm")) {
        ds.disasm_nav_addr = entry.address;
        ds.disasm_reg_sel = 0;
        ds.disasm_follow_rip = false;
        ds.disasm_needs_refresh = true;
        refresh_disasm(state);
      }
      ImGui::SameLine();
      std::vector<uint8_t> parsed_bytes;
      const bool has_bytes = parse_notebook_bytes(entry.bytes, parsed_bytes);
      ImGui::BeginDisabled(!has_bytes);
      if (ImGui::SmallButton("Patch")) {
        set_patch_address(ds, entry.address);
        std::snprintf(ds.patch_name, sizeof(ds.patch_name), "%s",
                      entry.label.empty() ? "Notebook patch"
                                          : entry.label.c_str());
        ds.patch_mode = 0;
        ds.patch_length = static_cast<int>(parsed_bytes.size());
        set_patch_bytes(ds, parsed_bytes);
        set_status(state, "Patch Studio staged from notebook");
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      if (ImGui::SmallButton("Copy")) {
        std::string text = entry.kind + " " + hex_u64(entry.address) +
                           " " + entry.label;
        if (!entry.note.empty()) text += " - " + entry.note;
        ImGui::SetClipboardText(text.c_str());
        set_status(state, "Notebook item copied");
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Delete")) {
        ds.notebook.erase(ds.notebook.begin() +
                          static_cast<std::ptrdiff_t>(i));
        ImGui::EndDisabled();
        ImGui::PopID();
        break;
      }
      ImGui::EndDisabled();
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
}

} // namespace memdbg::frontend

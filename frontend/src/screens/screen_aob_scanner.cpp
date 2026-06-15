/*
 * memDBG - AOB Scanner screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <vector>

namespace memdbg::frontend {

/* ---- AOB pattern parser ---- */
static bool parse_aob_pattern(const char *text,
                              std::vector<uint8_t> &pattern,
                              std::vector<uint8_t> &mask,
                              std::string &error) {
  pattern.clear();
  mask.clear();
  if (!text || text[0] == '\0') { error = "Empty pattern"; return false; }

  std::istringstream iss(text);
  std::string token;
  while (iss >> token) {
    // Trim trailing comma/semicolon
    while (!token.empty() && (token.back() == ',' || token.back() == ';'))
      token.pop_back();
    if (token.empty()) continue;

    if (token == "??" || token == "?" || token == "???" || token == "**") {
      // Wildcard byte
      pattern.push_back(0x00);
      mask.push_back(0x00);
    } else {
      // Hex byte (with optional 0x prefix)
      if (token.rfind("0x", 0) == 0 || token.rfind("0X", 0) == 0)
        token = token.substr(2);
      if (token.size() > 2) { error = "Invalid token: " + token; return false; }
      char *end = nullptr;
      unsigned long val = std::strtoul(token.c_str(), &end, 16);
      if (end != token.c_str() + token.size()) {
        error = "Invalid hex: " + token;
        return false;
      }
      pattern.push_back(static_cast<uint8_t>(val));
      mask.push_back(0xFF);
    }
  }

  if (pattern.empty()) { error = "Empty pattern"; return false; }
  if (pattern.size() > 256) { error = "Pattern too long (max 256 bytes)"; return false; }
  return true;
}

/* ---- AOB scan execution ---- */
static void run_aob_scan(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); return; }

  uint64_t start = 0, length = 0;
  if (!parse_u64(state.scan_start, start) || !parse_u64(state.scan_length, length)) {
    set_status(state, "Invalid scan range"); return;
  }

  std::vector<uint8_t> pattern, mask;
  std::string error;
  if (!parse_aob_pattern(state.aob_pattern, pattern, mask, error)) {
    set_status(state, "AOB: " + error); return;
  }

  state.scan_max_results = std::max(state.scan_max_results, 1);

  memdbg_scan_aob_request_t request{};
  request.pid = state.selected_pid;
  request.start = start;
  request.length = length;
  request.max_results = static_cast<uint32_t>(state.scan_max_results);
  request.pattern_length = static_cast<uint32_t>(pattern.size());

  if (!state.client.scan_aob(request, pattern, mask, state.aob_result)) {
    set_status(state, state.client.last_error()); return;
  }

  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "AOB scan: %u hits (%.2f MiB scanned)",
                state.aob_result.count,
                static_cast<double>(state.aob_result.bytes_scanned) / (1024.0 * 1024.0));
  set_status(state, state.scan_session_status);
}

/* ---- Main draw ---- */
void draw_aob_scanner(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float left_w = std::max(420.0f, (avail.x - gap) * 0.38f);

  ui::begin_panel("AOBControl", "AOB Pattern Scan", ImVec2(left_w, avail.y));
  ImGui::Text("Active PID: %d", state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  // Alias for readability
  static const char *aob_aliases[] = {
    "mov rax, [rdi+8]; ret  =  48 8B 47 08 C3",
    "xor eax, eax; ret        =  31 C0 C3",
    "push rbp; mov rbp, rsp   =  55 48 89 E5",
    "nop; nop; ret            =  90 90 C3",
  };
  ImGui::InputTextMultiline("Pattern", state.aob_pattern, sizeof(state.aob_pattern),
                            ImVec2(0, 80));
  if (ImGui::BeginCombo("##AOBExamples", "Example patterns...")) {
    for (const char *alias : aob_aliases) {
      if (ImGui::Selectable(alias)) {
        // Extract the part after "= "
        const char *eq = std::strstr(alias, "=  ");
        if (eq) std::snprintf(state.aob_pattern, sizeof(state.aob_pattern), "%s", eq + 3);
      }
    }
    ImGui::EndCombo();
  }

  ImGui::Spacing();
  ui::text_dim("Use ?? for wildcard bytes (e.g. 48 8B ?? ?? C3)");
  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

  ImGui::InputText("Start", state.scan_start, sizeof(state.scan_start));
  ImGui::InputText("Length", state.scan_length, sizeof(state.scan_length));
  ImGui::InputInt("Max results", &state.scan_max_results);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  ImGui::Spacing();
  if (ui::primary_button((std::string(icons::kSearch) + "  Scan AOB").c_str(),
                         ui::full_button(42)))
    run_aob_scan(state);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ui::text_dim("AOB Tips");
  ImGui::TextWrapped("Patterns like 48 8B ?? ?? are efficient — the payload uses "
                     "the first known byte to skip regions quickly.");
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("AOBResults", "AOB Results", ImVec2(0, avail.y));

  auto &result = state.aob_result;
  ImGui::Text("Hits: %u%s  |  Scanned: %.2f MiB",
              result.count, result.truncated ? " (truncated)" : "",
              static_cast<double>(result.bytes_scanned) / (1024.0 * 1024.0));
  ImGui::Text("Speed: %s  |  Regions: %u  |  Errors: %u",
              bytes_per_second(result.bytes_scanned, result.elapsed_ns).c_str(),
              result.regions_scanned, result.read_errors);
  ImGui::Spacing();

  if (result.addresses.empty()) {
    if (result.count == 0 && result.bytes_scanned > 0)
      ui::draw_empty_state("No hits", "The pattern was not found in the selected range.");
    else
      ui::draw_empty_state("Ready", "Enter an AOB pattern and scan range, then press Scan.");
  } else if (ImGui::BeginTable("AOBResultsTable", 2,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
        ImVec2(0, 0))) {
    ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 50);
    ImGui::TableSetupColumn("Address");
    ImGui::TableHeadersRow();
    for (int i = 0; i < static_cast<int>(result.addresses.size()); ++i) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::Text("%d", i + 1);
      ImGui::TableSetColumnIndex(1);
      std::string label = hex_u64(result.addresses[i]) + "##aob" + std::to_string(i);
      if (ImGui::Selectable(label.c_str())) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                      hex_u64(result.addresses[i]).c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s",
                      hex_u64(result.addresses[i]).c_str());
        state.screen = Screen::Memory;
      }
    }
    ImGui::EndTable();
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

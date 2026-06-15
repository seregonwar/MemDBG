/*
 * MemDBG - Pointer Scanner screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <algorithm>
#include <cstdio>
#include <exception>
#include <future>

namespace memdbg::frontend {

/* ---- Async scan poll ---- */
static void poll_pointer_async(AppState &state) {
  if (!state.scan_async_pending) return;
  if (!state.scan_async_future.valid()) return;

  auto status = state.scan_async_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;
  if (state.scan_async_owner != Screen::PointerScanner) return;

  state.scan_async_pending = false;
  bool ok = false;
  try {
    ok = state.scan_async_future.get();
  } catch (const std::exception &ex) {
    state.scan_async_error = ex.what();
  } catch (...) {
    state.scan_async_error = "Unknown pointer scanner error";
  }

  if (!ok) {
    if (state.scan_async_error.empty()) state.scan_async_error = "Pointer scanner request failed";
    set_status(state, state.scan_async_error);
    push_notification(state, "Pointer scan failed: " + state.scan_async_error, 5.0);
    return;
  }

  /* Apply results from temp storage */
  state.pointer_result = std::move(state.scan_async_temp_result);
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s", state.scan_async_temp_session_status);
  set_status(state, state.scan_session_status);
}

/* ---- Pointer scan execution ---- */
static void run_pointer_scan(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); return; }

  uint64_t start = 0, length = 0, target = 0;
  if (!parse_u64(state.scan_start, start) || !parse_u64(state.scan_length, length)) {
    set_status(state, "Invalid scan range"); return;
  }
  if (length == 0U) { set_status(state, "Scan length must be greater than zero"); return; }
  if (!parse_u64(state.pointer_target_address, target)) {
    set_status(state, "Invalid target address"); return;
  }

  state.pointer_max_depth   = std::max(state.pointer_max_depth, 1);
  state.pointer_max_results = std::max(state.pointer_max_results, 1);
  state.pointer_alignment   = std::max(state.pointer_alignment, 1);

  memdbg_scan_pointer_request_t request{};
  request.pid            = state.selected_pid;
  request.start          = start;
  request.length         = length;
  request.target_address = target;
  request.max_depth      = static_cast<uint32_t>(state.pointer_max_depth);
  request.max_results    = static_cast<uint32_t>(state.pointer_max_results);
  request.alignment      = static_cast<uint32_t>(state.pointer_alignment);

  state.scan_async_label = "Pointer scan";
  state.scan_async_start_time = ImGui::GetTime();
  state.scan_async_pending = true;
  state.scan_async_owner = Screen::PointerScanner;

  auto &client = state.client;
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;

  state.scan_async_future = std::async(std::launch::async,
    [&client, request, &temp_result, &temp_status, &error_out]() -> bool {
      ScanResult res;
      if (!client.scan_pointer(request, res)) {
        error_out = client.last_error();
        return false;
      }
      temp_result = std::move(res);
      std::snprintf(temp_status, sizeof(temp_status),
                    "Pointer scan: %u candidates (%.2f MiB scanned)",
                    temp_result.count,
                    static_cast<double>(temp_result.bytes_scanned) / (1024.0 * 1024.0));
      return true;
    });
}

/* ---- Main draw ---- */
void draw_pointer_scanner(AppState &state, ImVec2 avail) {
  poll_pointer_async(state);

  const float gap = 16.0f;
  const float left_w = std::max(420.0f, (avail.x - gap) * 0.38f);

  ui::begin_panel("PointerControl", "Pointer Scanner", ImVec2(left_w, avail.y));
  ImGui::Text("Active PID: %d", state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  ImGui::InputText("Target address", state.pointer_target_address,
                   sizeof(state.pointer_target_address));
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("The address you want to find pointers to (e.g. a scan hit)");

  if (ui::soft_button((std::string(icons::kCopy) + "  Use Last Scan Hit").c_str(),
                      ImVec2(210, 32))) {
    if (!state.scan_result.addresses.empty())
      std::snprintf(state.pointer_target_address, sizeof(state.pointer_target_address),
                    "%s", hex_u64(state.scan_result.addresses.front()).c_str());
  }

  ImGui::Spacing();
  ImGui::InputInt("Max depth", &state.pointer_max_depth);
  ImGui::InputInt("Max results", &state.pointer_max_results);
  ImGui::InputInt("Alignment", &state.pointer_alignment);
  state.pointer_max_depth   = std::max(state.pointer_max_depth, 1);
  state.pointer_max_results = std::max(state.pointer_max_results, 1);
  state.pointer_alignment   = std::max(state.pointer_alignment, 1);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

  ImGui::InputText("Start", state.scan_start, sizeof(state.scan_start));
  ImGui::InputText("Length", state.scan_length, sizeof(state.scan_length));
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("Memory range to search for pointer candidates");

  ImGui::Spacing();
  bool can_scan = state.client.connected() && state.selected_pid > 0 && !state.scan_async_pending;
  ImGui::BeginDisabled(!can_scan);
  if (ui::primary_button((std::string(icons::kPointer) + "  Scan Pointers").c_str(),
                         ui::full_button(42)))
    run_pointer_scan(state);
  ImGui::EndDisabled();

  /* Progress bar for async pointer scans */
  if (state.scan_async_pending)
    ui::draw_scan_progress(state.scan_async_label, icons::kPointer,
                           ImGui::GetTime() - state.scan_async_start_time,
                           ImGui::GetContentRegionAvail().x);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ui::text_dim("How it works");
  ImGui::TextWrapped("The scanner finds values in the search range that, when "
                     "dereferenced, point to the target address. Useful for "
                     "finding stable base pointers.");
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("PointerResults", "Pointer Candidates", ImVec2(0, avail.y));

  auto &result = state.pointer_result;
  ImGui::Text("Candidates: %u%s  |  Scanned: %.2f MiB",
              result.count, result.truncated ? " (truncated)" : "",
              static_cast<double>(result.bytes_scanned) / (1024.0 * 1024.0));
  ImGui::Text("Speed: %s  |  Regions: %u  |  Errors: %u",
              bytes_per_second(result.bytes_scanned, result.elapsed_ns).c_str(),
              result.regions_scanned, result.read_errors);
  ImGui::Text("Target: %s  |  Max depth: %d",
              state.pointer_target_address, state.pointer_max_depth);
  ImGui::Spacing();

  if (result.addresses.empty()) {
    if (result.count == 0 && result.bytes_scanned > 0)
      ui::draw_empty_state("No pointers found",
                           "No values in the search range point to the target address.");
    else
      ui::draw_empty_state("Ready",
                           "Enter a target address and scan range, then press Scan.");
  } else if (ImGui::BeginTable("PointerResultsTable", 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
        ImVec2(0, 0))) {
    ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 44);
    ImGui::TableSetupColumn("Base Address");
    ImGui::TableSetupColumn("Offset to Target");
    ImGui::TableHeadersRow();
    uint64_t target = 0;
    (void)parse_u64(state.pointer_target_address, target);
    for (int i = 0; i < static_cast<int>(result.addresses.size()); ++i) {
      uint64_t addr = result.addresses[i];
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::Text("%d", i + 1);
      ImGui::TableSetColumnIndex(1);
      std::string label = hex_u64(addr) + "##ptr" + std::to_string(i);
      if (ImGui::Selectable(label.c_str())) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                      hex_u64(addr).c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s",
                      hex_u64(addr).c_str());
        state.screen = Screen::Memory;
      }
      ImGui::TableSetColumnIndex(2);
      if (target > 0 && addr < target)
        ImGui::TextColored(ui::colors().dim, "+0x%llX",
                           static_cast<unsigned long long>(target - addr));
      else
        ImGui::TextUnformatted("-");
    }
    ImGui::EndTable();
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

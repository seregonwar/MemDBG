/*
 * MemDBG - AOB Scanner screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "confirm_modal.hpp"

#include <algorithm>
#include <cstdio>
#include <exception>
#include <future>
#include <mutex>
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

static bool build_aob_pattern(const char *text, bool text_mode,
                              std::vector<uint8_t> &pattern,
                              std::vector<uint8_t> &mask,
                              std::string &error) {
  if (!text_mode) return parse_aob_pattern(text, pattern, mask, error);
  if (!parse_text_bytes(text, pattern, 256U)) {
    error = "Text must contain 1 to 256 UTF-8 bytes";
    return false;
  }
  mask.assign(pattern.size(), 0xFFU);
  return true;
}

/* ---- Async scan poll ---- */
static void poll_aob_async(AppState &state) {
  if (!state.scan_async_pending) return;
  if (!state.scan_async_future.valid()) return;

  auto status = state.scan_async_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.scan_async_pending = false;
  bool ok = false;
  try {
    ok = state.scan_async_future.get();
  } catch (const std::exception &ex) {
    state.scan_async_error = ex.what();
  } catch (...) {
    state.scan_async_error = "Unknown AOB scanner error";
  }

  if (state.scan_async_owner != Screen::AOBScanner) return;


  if (!ok) {
    std::string error_local;
    {
      std::lock_guard<std::mutex> lock(state.scan_async_mtx);
      error_local = state.scan_async_error.empty() ? "AOB scanner request failed" : state.scan_async_error;
      state.scan_async_error.clear();
    }
    set_status(state, error_local);
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("AOB scan failed: " + error_local).c_str());
    char aobn_buf[256]; std::snprintf(aobn_buf, sizeof(aobn_buf), locale::tr("aob.scan_failed"), error_local.c_str()); push_notification(state, aobn_buf, 5.0);
    return;
  }

  /* Apply results from temp storage under lock */
  ScanResult result_local;
  char status_local[256] = {};
  {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    result_local = std::move(state.scan_async_temp_result);
    std::memcpy(status_local, state.scan_async_temp_session_status, sizeof(status_local));
  }
  state.aob_result = std::move(result_local);
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s", status_local);
  set_status(state, state.scan_session_status);
}

/* ---- AOB scan execution ---- */
static void run_aob_scan(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) { set_status(state, locale::tr("aob_scanner.connect_first")); return; }
  if (state.selected_pid <= 0) { set_status(state, locale::tr("aob_scanner.select_process_first")); return; }

  std::vector<uint8_t> pattern, mask;
  std::string error;
  const bool text_mode = state.aob_text_mode;
  if (!build_aob_pattern(state.aob_pattern, text_mode, pattern, mask, error)) {
    char aobs_buf[256]; std::snprintf(aobs_buf, sizeof(aobs_buf), locale::tr("aob.scan_error"), text_mode ? "Text search" : "AOB", error.c_str()); set_status(state, aobs_buf);
    return;
  }

  state.scan_max_results = std::max(state.scan_max_results, 1);

  if (state.aob_process_wide) {
    state.scan_async_label = text_mode ? "Process text search" : "Process AOB";
    uint64_t start = 0, end = 0;
    if (!parse_u64(state.scan_start, start) || !parse_u64(state.scan_end, end)) {
      set_status(state, locale::tr("scanner.invalid_window")); return;
    }
    if (end != 0U && end <= start) {
      set_status(state, locale::tr("scanner.end_filter_error")); return;
    }

    state.scan_async_start_time = ImGui::GetTime();
    state.scan_async_pending = true;
    state.scan_async_owner = Screen::AOBScanner;

    memdbg_scan_process_aob_request_t request{};
    request.pid = state.selected_pid;
    request.protection_mask = state.scan_readable_only ? 1U : 0U;
    request.max_results = static_cast<uint32_t>(state.scan_max_results);
    request.pattern_length = static_cast<uint32_t>(pattern.size());
    request.start = start;
    request.end = end;

    auto &client = state.client;
    auto &temp_result = state.scan_async_temp_result;
    auto &temp_status = state.scan_async_temp_session_status;
    auto &error_out = state.scan_async_error;

    state.scan_async_future = std::async(std::launch::async,
      [&client, request, pattern, mask, text_mode, &temp_result, &temp_status, &error_out,
       &mtx = state.scan_async_mtx]() -> bool {
        std::lock_guard<std::mutex> lock(mtx);
        ScanResult res;
        if (!client.scan_process_aob(request, pattern, mask, res)) {
          error_out = client.last_error();
          return false;
        }
        temp_result = std::move(res);
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %u hits in %u regions (%.2f MiB)",
                      text_mode ? "Process text" : "Process AOB",
                      temp_result.count, temp_result.regions_scanned,
                      static_cast<double>(temp_result.bytes_scanned) / (1024.0 * 1024.0));
        return true;
      });
  } else {
    state.scan_async_label = text_mode ? "Text search" : "AOB scan";
    uint64_t start = 0, length = 0;
    if (!parse_u64(state.scan_start, start) || !parse_u64(state.scan_length, length)) {
      set_status(state, locale::tr("scanner.invalid_range")); return;
    }
    if (length == 0U) { set_status(state, locale::tr("scanner.length_zero")); return; }

    state.scan_async_start_time = ImGui::GetTime();
    state.scan_async_pending = true;
    state.scan_async_owner = Screen::AOBScanner;

    auto &client = state.client;
    auto &temp_result = state.scan_async_temp_result;
    auto &temp_status = state.scan_async_temp_session_status;
    auto &error_out = state.scan_async_error;

    memdbg_scan_aob_request_t request{};
    request.pid = state.selected_pid;
    request.start = start;
    request.length = length;
    request.max_results = static_cast<uint32_t>(state.scan_max_results);
    request.pattern_length = static_cast<uint32_t>(pattern.size());

    state.scan_async_future = std::async(std::launch::async,
      [&client, request, pattern, mask, text_mode, &temp_result, &temp_status, &error_out,
       &mtx = state.scan_async_mtx]() -> bool {
        std::lock_guard<std::mutex> lock(mtx);
        ScanResult res;
        if (!client.scan_aob(request, pattern, mask, res)) {
          error_out = client.last_error();
          return false;
        }
        temp_result = std::move(res);
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %u hits (%.2f MiB scanned)",
                      text_mode ? "Text search" : "AOB scan",
                      temp_result.count,
                      static_cast<double>(temp_result.bytes_scanned) / (1024.0 * 1024.0));
        return true;
      });
  }
}

/* ---- Main draw ---- */
void draw_aob_scanner(AppState &state, ImVec2 avail) {
  poll_aob_async(state);

  const float gap = 16.0f;
  const float left_w = std::max(420.0f, (avail.x - gap) * 0.38f);

  ui::begin_panel("AOBControl", locale::tr("aob_scanner.title"), ImVec2(left_w, avail.y));
  ImGui::Text(locale::tr("aob_scanner.active_pid"), state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  // Alias for readability
  static const char *aob_aliases[] = {
    "mov rax, [rdi+8]; ret  =  48 8B 47 08 C3",
    "xor eax, eax; ret        =  31 C0 C3",
    "push rbp; mov rbp, rsp   =  55 48 89 E5",
    "nop; nop; ret            =  90 90 C3",
  };
  ImGui::Checkbox("Search text (UTF-8)", &state.aob_text_mode);
  const char *pattern_label = state.aob_text_mode
      ? "Text to find" : locale::tr("aob_scanner.pattern");
  ImGui::InputTextMultiline(pattern_label, state.aob_pattern, sizeof(state.aob_pattern),
                            ImVec2(0, 80));
  if (!state.aob_text_mode &&
      ImGui::BeginCombo("##AOBExamples", locale::tr("aob_scanner.examples"))) {
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
  ui::text_dim(state.aob_text_mode
                   ? "Matches an exact UTF-8 string (including spaces), up to 256 bytes."
                   : locale::tr("aob_scanner.wildcard_hint"));
  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

  /* Process-wide toggle */
  ImGui::Checkbox(locale::tr("aob_scanner.process_wide"), &state.aob_process_wide);
  ImGui::Spacing();

  if (state.aob_process_wide) {
    /* Process-wide mode: uses protection_mask + start/end range filter.
       The payload iterates cached maps, skipping non-readable regions
       when protection_mask != 0. */
    ui::text_dim(locale::tr("aob_scanner.process_wide_desc"));
    ImGui::Checkbox(locale::tr("aob_scanner.readable_only"), &state.scan_readable_only);
    ImGui::InputText(locale::tr("aob_scanner.start_filter"), state.scan_start, sizeof(state.scan_start));
    ImGui::InputText(locale::tr("aob_scanner.end_filter"), state.scan_end, sizeof(state.scan_end));
    ui::text_dim(locale::tr("aob_scanner.leave_zero"));
  } else {
    /* Single-range mode: explicit start + length. */
    ImGui::InputText(locale::tr("aob_scanner.start"), state.scan_start, sizeof(state.scan_start));
    ImGui::InputText(locale::tr("aob_scanner.length"), state.scan_length, sizeof(state.scan_length));
  }

  ImGui::InputInt(locale::tr("aob_scanner.max_results"), &state.scan_max_results);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  ImGui::Spacing();
  const char *scan_action = state.aob_text_mode
      ? (state.aob_process_wide ? "Search Process Text" : "Search Text")
      : (state.aob_process_wide ? locale::tr("aob_scanner.scan_process_aob")
                                : locale::tr("aob_scanner.scan_aob"));
  std::string scan_label = std::string(icons::kSearch) + "  " + scan_action;
  bool can_scan = state.client.connected() && state.selected_pid > 0 &&
                  !client_async_busy(state) &&
                  payload_supports(state, state.aob_process_wide
                                          ? MEMDBG_CAP_SCAN_PROCESS_AOB
                                          : MEMDBG_CAP_SCAN_AOB);
  ImGui::BeginDisabled(!can_scan);
  if (ui::primary_button(scan_label.c_str(), ui::full_button(42))) {
    if (state.aob_process_wide)
      ImGui::OpenPopup("ConfirmProcessAOBScan");
    else
      run_aob_scan(state);
  }
  ImGui::EndDisabled();
  static bool skip_process_aob_confirm = false;
  if (ui::confirm_modal("ConfirmProcessAOBScan",
                        state.aob_text_mode ? "Search text across the process?"
                                            : "Scan AOB across the process?",
                        "Process-wide pattern scans read many memory maps. Prefer a selected range first when a title or payload session is unstable.",
                        &skip_process_aob_confirm, true)) {
    run_aob_scan(state);
  }

  /* Progress bar for async AOB scans */
  if (state.scan_async_pending)
    ui::draw_scan_progress(state.scan_async_label, icons::kSearch,
                           ImGui::GetTime() - state.scan_async_start_time,
                           ImGui::GetContentRegionAvail().x);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ui::text_dim(locale::tr("aob_scanner.aob_tips"));
  ImGui::TextWrapped("%s", locale::tr("aob_scanner.tips_desc"));
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("AOBResults", locale::tr("aob_scanner.results"), ImVec2(0, avail.y));

  auto &result = state.aob_result;
  ImGui::Text(locale::tr("aob_scanner.hits"),
              result.count, result.truncated ? locale::tr("aob_scanner.truncated") : "",
              static_cast<double>(result.bytes_scanned) / (1024.0 * 1024.0));
  ImGui::Text(locale::tr("aob_scanner.speed"),
              bytes_per_second(result.bytes_scanned, result.elapsed_ns).c_str(),
              result.regions_scanned, result.read_errors);
  ImGui::Spacing();

  /* Copy All logic shared between button and keyboard shortcut */
  auto copy_all = [&](const char *suffix = nullptr) {
    std::string all;
    all.reserve(result.addresses.size() * 18U);
    for (uint64_t addr : result.addresses)
      all += hex_u64(addr) + "\n";
    ImGui::SetClipboardText(all.c_str());
    char copy_buf[128];
    std::snprintf(copy_buf, sizeof(copy_buf), locale::tr("notify.copied_n_addresses"), result.addresses.size());
    set_status(state, copy_buf);
    push_notification(state, copy_buf + (suffix ? std::string(suffix) : std::string("")));
  };

  if (!result.addresses.empty()) {
    if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("aob_scanner.copy_all")).c_str(),
                        ImVec2(200, 30)))
      copy_all();
    if (ImGui::IsItemHovered()) {
      char tip_buf[128];
      std::snprintf(tip_buf, sizeof(tip_buf), locale::tr("aob_scanner.copy_all_tooltip"), result.count);
      ImGui::SetTooltip("%s", tip_buf);
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_C))
      copy_all(" (Ctrl+C)");
  }

  if (result.addresses.empty()) {
    if (result.count == 0 && result.bytes_scanned > 0)
      ui::draw_empty_state(locale::tr("aob_scanner.no_hits"), locale::tr("aob_scanner.no_hits_desc"));
    else
      ui::draw_empty_state(locale::tr("aob_scanner.ready"), locale::tr("aob_scanner.ready_desc"));
  } else if (ImGui::BeginTable("AOBResultsTable", 2,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
        ImVec2(0, 0))) {
    ImGui::TableSetupColumn(locale::tr("aob_scanner.col_num"), ImGuiTableColumnFlags_WidthFixed, 50);
    ImGui::TableSetupColumn(locale::tr("aob_scanner.col_address"));
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
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s %s", locale::tr("memory.selected"),
                          hex_u64(result.addresses[i]).c_str());
    }
    ImGui::EndTable();
  }

  ui::end_panel();
}

} // namespace memdbg::frontend

/*
 * MemDBG - Memory screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "confirm_modal.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace memdbg::frontend {

namespace {

struct GadgetPattern {
  const char *name;
  std::vector<uint8_t> bytes;
};

static const std::array<GadgetPattern, 13> kGadgetPatterns = {{
    {"ret", {0xC3}},
    {"pop rdi; ret", {0x5F, 0xC3}},
    {"pop rsi; ret", {0x5E, 0xC3}},
    {"pop rdx; ret", {0x5A, 0xC3}},
    {"pop rcx; ret", {0x59, 0xC3}},
    {"pop rax; ret", {0x58, 0xC3}},
    {"pop rbx; ret", {0x5B, 0xC3}},
    {"pop rbp; ret", {0x5D, 0xC3}},
    {"leave; ret", {0xC9, 0xC3}},
    {"syscall; ret", {0x0F, 0x05, 0xC3}},
    {"jmp rax", {0xFF, 0xE0}},
    {"call rax", {0xFF, 0xD0}},
    {"mov [rdi], rsi; ret", {0x48, 0x89, 0x37, 0xC3}},
}};

static std::string bytes_hex(const std::vector<uint8_t> &bytes) {
  std::ostringstream out;
  out << std::hex << std::uppercase << std::setfill('0');
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i != 0U) out << ' ';
    out << std::setw(2) << static_cast<unsigned>(bytes[i]);
  }
  return out.str();
}

static bool range_overlaps(uint64_t a_start, uint64_t a_len,
                           uint64_t b_start, uint64_t b_len) {
  if (a_len == 0U || b_len == 0U) return false;
  uint64_t a_end = a_start + a_len;
  uint64_t b_end = b_start + b_len;
  if (a_end < a_start) a_end = UINT64_MAX;
  if (b_end < b_start) b_end = UINT64_MAX;
  return a_start < b_end && b_start < a_end;
}

static const AllocationRecord *allocation_at(const AppState &state,
                                             uint64_t address,
                                             bool freed_only) {
  for (const auto &alloc : state.allocations) {
    if (freed_only && !alloc.freed) continue;
    if (!freed_only && alloc.freed) continue;
    if (alloc.size == 0U) continue;
    if (address >= alloc.address && address < alloc.address + alloc.size)
      return &alloc;
  }
  return nullptr;
}

static bool watchpoint_at(const AppState &state, uint64_t address) {
  for (const auto &watch : state.watchpoints) {
    if (!watch.enabled || watch.length == 0U) continue;
    if (address >= watch.address && address < watch.address + watch.length)
      return true;
  }
  return false;
}

static bool byte_changed(const AppState &state, uint64_t address,
                         uint8_t value) {
  if (!state.memory_overlay_changes) return false;
  if (state.memory_previous.empty()) return false;
  if (state.memory_previous_base != state.memory_base) return false;
  if (address < state.memory_previous_base) return false;
  uint64_t offset = address - state.memory_previous_base;
  if (offset >= state.memory_previous.size()) return false;
  return state.memory_previous[static_cast<size_t>(offset)] != value;
}

static ImVec4 byte_color(const AppState &state, uint64_t address,
                         uint8_t value) {
  if (state.memory_overlay_freed_allocs &&
      allocation_at(state, address, true) != nullptr) {
    return ui::colors().danger;
  }
  if (state.memory_overlay_watchpoints && watchpoint_at(state, address)) {
    return ui::colors().primary2;
  }
  if (byte_changed(state, address, value)) {
    return ui::colors().warning;
  }
  return ui::colors().text;
}

static void draw_overlay_hex_view(AppState &state) {
  if (state.memory.empty()) {
    ui::draw_empty_state(locale::tr("memory.no_memory_buffer"),
                         locale::tr("memory.no_memory_desc"));
    return;
  }

  ImGui::Checkbox(locale::tr("memory.changes"), &state.memory_overlay_changes);
  ImGui::SameLine();
  ImGui::Checkbox(locale::tr("memory.watchpoints_overlay"), &state.memory_overlay_watchpoints);
  ImGui::SameLine();
  ImGui::Checkbox(locale::tr("memory.freed_allocs"), &state.memory_overlay_freed_allocs);
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("memory.copy_hex")).c_str(),
                      ImVec2(130, 30))) {
    ImGui::SetClipboardText(bytes_hex(state.memory).c_str());
  }
  ImGui::Spacing();

  if (ImGui::BeginTable("memory_overlay_hex", 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
        ImVec2(0, 0))) {
    ImGui::TableSetupColumn(locale::tr("memory.address_col"), ImGuiTableColumnFlags_WidthFixed, 132);
    ImGui::TableSetupColumn(locale::tr("memory.hex_col"));
    ImGui::TableSetupColumn(locale::tr("memory.ascii_col"), ImGuiTableColumnFlags_WidthFixed, 150);
    ImGui::TableHeadersRow();

    for (size_t row = 0; row < state.memory.size(); row += 16U) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      const uint64_t row_addr = state.memory_base + row;
      std::string addr = hex_u64(row_addr);
      if (ImGui::Selectable((addr + "##memrow" + std::to_string(row)).c_str(),
                            false, ImGuiSelectableFlags_SpanAllColumns)) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s",
                      addr.c_str());
        std::snprintf(state.watch_address, sizeof(state.watch_address), "%s",
                      addr.c_str());
        char sel_buf[128];
        std::snprintf(sel_buf, sizeof(sel_buf), locale::tr("memory.selected"), addr.c_str());
        set_status(state, sel_buf);
      }

      ImGui::TableSetColumnIndex(1);
      for (size_t i = 0; i < 16U; ++i) {
        if (row + i >= state.memory.size()) {
          ImGui::TextUnformatted("  ");
        } else {
          uint64_t address = state.memory_base + row + i;
          uint8_t value = state.memory[row + i];
          char byte_text[4];
          std::snprintf(byte_text, sizeof(byte_text), "%02X",
                        static_cast<unsigned>(value));
          ImGui::TextColored(byte_color(state, address, value), "%s", byte_text);
          if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("%s = 0x%02X", hex_u64(address).c_str(),
                              static_cast<unsigned>(value));
          }
        }
        if (i + 1U < 16U) ImGui::SameLine(0, 5.0f);
      }

      ImGui::TableSetColumnIndex(2);
      char ascii[17]{};
      for (size_t i = 0; i < 16U && row + i < state.memory.size(); ++i) {
        unsigned char c = state.memory[row + i];
        ascii[i] = std::isprint(c) != 0 ? static_cast<char>(c) : '.';
      }
      ImGui::TextUnformatted(ascii);
    }
    ImGui::EndTable();
  }
}

static void read_memory(AppState &state, bool quiet = false) {
  if (!state.client.connected()) {    if (!quiet) set_status(state, locale::tr("memory.connect_first")); return; }
  if (state.selected_pid <= 0) { if (!quiet) set_status(state, locale::tr("memory.select_process_first")); return; }
  uint64_t address = 0;
  if (!parse_u64(state.read_address, address)) { if (!quiet) set_status(state, locale::tr("memory.invalid_read_addr")); return; }
  state.read_length = std::clamp(state.read_length, 1, static_cast<int>(MEMDBG_PROTOCOL_MAX_READ));

  std::vector<uint8_t> next;
  if (!state.client.memory_read(state.selected_pid, address,
                                static_cast<uint32_t>(state.read_length),
                                next)) {
    if (!quiet) set_status(state, state.client.last_error());
    return;
  }

  state.memory_previous = state.memory;
  state.memory_previous_base = state.memory_base;
  state.memory = std::move(next);
  state.memory_base = address;
  if (!quiet) {
    char read_buf[64];
    std::snprintf(read_buf, sizeof(read_buf), locale::tr("memory.read_n_bytes"), state.memory.size());
    set_status(state, read_buf);
  }
}

static void write_memory(AppState &state) {
  if (!state.client.connected()) {    set_status(state, locale::tr("memory.connect_first")); return; }
  if (state.selected_pid <= 0) { set_status(state, locale::tr("memory.select_process_first")); return; }
  uint64_t address = 0;
  std::vector<uint8_t> data;
  if (!parse_u64(state.write_address, address)) { set_status(state, locale::tr("memory.invalid_write_addr")); return; }
  if (!parse_hex_bytes(state.write_bytes, data)) { set_status(state, locale::tr("memory.invalid_byte_list")); return; }
  uint32_t written = 0;
  if (!state.client.memory_write(state.selected_pid, address, data, written)) {
    set_status(state, state.client.last_error()); return;
  }
  char wrote_buf[64];
  std::snprintf(wrote_buf, sizeof(wrote_buf), locale::tr("memory.wrote_n_bytes"), written);
  set_status(state, wrote_buf);
}

static void add_watchpoint(AppState &state) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); return; }
  uint64_t address = 0;
  if (!parse_u64(state.watch_address, address)) { set_status(state, "Invalid watch address"); return; }
  state.watch_length = std::clamp(state.watch_length, 1, 256);

  MemoryWatchpoint watch;
  watch.address = address;
  watch.length = static_cast<uint32_t>(state.watch_length);
  watch.label = hex_u64(address);
  if (!state.client.memory_read(state.selected_pid, watch.address, watch.length,
                                watch.last_bytes)) {
    set_status(state, "Watchpoint read failed: " + state.client.last_error());
    return;
  }
  watch.current_bytes = watch.last_bytes;
  watch.status = "armed";
  state.watchpoints.push_back(std::move(watch));    char wp_buf[128];
    std::snprintf(wp_buf, sizeof(wp_buf), locale::tr("memory.watchpoints.armed_at"), hex_u64(address).c_str());
    set_status(state, wp_buf);
}

static void poll_watchpoints(AppState &state, bool force) {
  if (!state.watchpoints_polling && !force) return;
  if (!state.client.connected() || state.selected_pid <= 0) return;
  if (state.scan_async_pending || state.telemetry_pending) return;

  const double now = ImGui::GetTime();
  if (!force && now < state.next_watchpoint_poll) return;
  state.next_watchpoint_poll = now + std::max(0.1f, state.watchpoint_interval);

  for (auto &watch : state.watchpoints) {
    if (!watch.enabled || watch.length == 0U) continue;
    std::vector<uint8_t> bytes;
    if (!state.client.memory_read(state.selected_pid, watch.address,
                                  watch.length, bytes)) {
      watch.status = state.client.last_error();
      continue;
    }
    watch.current_bytes = bytes;
    watch.changed = bytes != watch.last_bytes;
    if (watch.changed) {
      watch.status = "changed";
      push_notification(state, "Watchpoint changed at " + hex_u64(watch.address), 5.0);
      watch.last_bytes = bytes;
    } else {
      watch.status = "stable";
    }
  }
}

static void draw_watchpoints(AppState &state) {
  ImGui::InputText(locale::tr("memory.watchpoints.address"), state.watch_address, sizeof(state.watch_address));
  ImGui::InputInt(locale::tr("memory.watchpoints.length"), &state.watch_length);
  state.watch_length = std::clamp(state.watch_length, 1, 256);
  ImGui::SliderFloat(locale::tr("memory.watchpoints.poll_interval"), &state.watchpoint_interval, 0.1f, 5.0f, "%.2fs");
  ImGui::Checkbox(locale::tr("memory.watchpoints.polling"), &state.watchpoints_polling);
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("memory.watchpoints.poll_now")).c_str(),
                      ImVec2(118, 34))) {
    poll_watchpoints(state, true);
  }
  if (ui::primary_button((std::string(icons::kAdd) + "  " + locale::tr("memory.watchpoints.add")).c_str(),
                         ui::full_button(38))) {
    add_watchpoint(state);
  }

  ImGui::Spacing();
  if (ImGui::BeginTable("Watchpoints", 5,
      ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
      ImVec2(0, 190))) {
    ImGui::TableSetupColumn(locale::tr("memory.watchpoints.on_col"), ImGuiTableColumnFlags_WidthFixed, 42);
    ImGui::TableSetupColumn(locale::tr("memory.watchpoints.addr_col"));
    ImGui::TableSetupColumn(locale::tr("memory.watchpoints.len_col"), ImGuiTableColumnFlags_WidthFixed, 54);
    ImGui::TableSetupColumn(locale::tr("memory.watchpoints.value_col"));
    ImGui::TableSetupColumn(locale::tr("memory.watchpoints.state_col"), ImGuiTableColumnFlags_WidthFixed, 86);
    ImGui::TableHeadersRow();
    for (size_t i = 0; i < state.watchpoints.size(); ++i) {
      auto &watch = state.watchpoints[i];
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::PushID(static_cast<int>(i));
      ImGui::Checkbox("##enabled", &watch.enabled);
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(hex_u64(watch.address).c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::Text("%u", watch.length);
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(bytes_hex(watch.current_bytes).c_str());
      ImGui::TableSetColumnIndex(4);
      ImGui::TextColored(watch.changed ? ui::colors().warning : ui::colors().muted,
                         "%s", watch.status.c_str());
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  static bool skip_clear_wp = false;
  if (ui::danger_button((std::string(icons::kTrash) + "  " + locale::tr("memory.watchpoints.clear")).c_str(),
                        ui::full_button(34))) {
    ImGui::OpenPopup("ConfirmClearMemWP");
  }
  if (ui::confirm_modal("ConfirmClearMemWP",
                        locale::tr("memory.watchpoints.confirm_clear"), nullptr,
                        &skip_clear_wp, true)) {
    state.watchpoints.clear();
  }
}

static void refresh_allocation_findings(AppState &state) {
  /* Skip recomputation when allocations haven't changed since last frame.
   * Use allocation_event_counter (incremented on every alloc/free) to catch
   * freed-flag flips that don't change vector sizes. */
  static size_t cached_alloc_count = 0;
  static size_t cached_alert_count = 0;
  static uint64_t cached_event_counter = 0;
  static uint64_t cached_memory_base = 0;
  static size_t cached_memory_size = 0;
  if (state.allocations.size() == cached_alloc_count &&
      state.allocation_alerts.size() == cached_alert_count &&
      state.allocation_event_counter == cached_event_counter &&
      state.memory_base == cached_memory_base &&
      state.memory.size() == cached_memory_size)
    return;
  cached_alloc_count = state.allocations.size();
  cached_alert_count = state.allocation_alerts.size();
  cached_event_counter = state.allocation_event_counter;
  cached_memory_base = state.memory_base;
  cached_memory_size = state.memory.size();

  state.allocation_findings.clear();
  uint64_t live_bytes = 0;
  size_t live_count = 0;
  size_t freed_count = 0;
  for (const auto &alloc : state.allocations) {
    if (alloc.freed) {
      freed_count++;
    } else {
      live_count++;
      live_bytes += alloc.size;
    }
  }

  std::ostringstream summary;
  summary << live_count << " live allocation(s), " << freed_count
          << " freed, " << live_bytes << " live byte(s)";
  state.allocation_findings.push_back(summary.str());
  for (const auto &alert : state.allocation_alerts)
    state.allocation_findings.push_back(alert);

  if (!state.memory.empty()) {
    for (const auto &alloc : state.allocations) {
      if (!alloc.freed) continue;
      if (range_overlaps(state.memory_base, state.memory.size(),
                         alloc.address, alloc.size)) {
        state.allocation_findings.push_back(
            "current memory view overlaps freed allocation " + hex_u64(alloc.address));
      }
    }
  }
}

static AllocationRecord *find_allocation(AppState &state, uint64_t address) {
  for (auto &alloc : state.allocations) {
    if (alloc.address == address) return &alloc;
  }
  return nullptr;
}

static void track_alloc(AppState &state, uint64_t address, uint64_t size,
                        const std::string &note) {
  if (address == 0U || size == 0U) return;
  if (auto *existing = find_allocation(state, address)) {
    existing->size = size;
    existing->freed = false;
    existing->alloc_event = ++state.allocation_event_counter;
    existing->note = note;
  } else {
    AllocationRecord alloc;
    alloc.address = address;
    alloc.size = size;
    alloc.alloc_event = ++state.allocation_event_counter;
    alloc.note = note;
    state.allocations.push_back(std::move(alloc));
  }
}

static void track_free(AppState &state, uint64_t address) {
  if (auto *alloc = find_allocation(state, address)) {
    if (alloc->freed) {
      state.allocation_alerts.push_back("double free candidate at " + hex_u64(address));
    }
    alloc->freed = true;
    alloc->free_event = ++state.allocation_event_counter;
  } else {
    state.allocation_alerts.push_back("free without known allocation at " + hex_u64(address));
  }
}

static void parse_allocation_events(AppState &state) {
  std::istringstream in(state.alloc_events_text);
  std::string line;
  size_t parsed = 0;
  while (std::getline(in, line)) {
    std::istringstream row(line);
    std::string op, a, b;
    row >> op >> a >> b;
    op = lower_copy(op);
    uint64_t address = 0, size = 0;
    if ((op == "malloc" || op == "alloc") && parse_u64(a.c_str(), address) &&
        parse_u64(b.c_str(), size)) {
      track_alloc(state, address, size, "event import");
      parsed++;
    } else if (op == "free" && parse_u64(a.c_str(), address)) {
      track_free(state, address);
      parsed++;
    } else if (op == "realloc") {
      std::string c;
      row >> c;
      uint64_t old_addr = 0, new_addr = 0, new_size = 0;
      if (parse_u64(a.c_str(), old_addr) && parse_u64(b.c_str(), new_addr) &&
          parse_u64(c.c_str(), new_size)) {
        track_free(state, old_addr);
        track_alloc(state, new_addr, new_size, "realloc import");
        parsed++;
      }
    }
  }
  refresh_allocation_findings(state);
  char alloc_buf[128];
  std::snprintf(alloc_buf, sizeof(alloc_buf), locale::tr("memory.allocations.imported_n"), parsed);
  set_status(state, alloc_buf);
}

static void draw_allocations(AppState &state) {
  ImGui::InputText(locale::tr("memory.allocations.alloc_addr"), state.alloc_address, sizeof(state.alloc_address));
  ImGui::InputText(locale::tr("memory.allocations.alloc_size"), state.alloc_size, sizeof(state.alloc_size));
  if (ui::primary_button((std::string(icons::kAdd) + "  " + locale::tr("memory.allocations.track_malloc")).c_str(),
                         ui::full_button(36))) {
    uint64_t address = 0, size = 0;
    if (parse_u64(state.alloc_address, address) &&
        parse_u64(state.alloc_size, size)) {
      track_alloc(state, address, size, "manual");
      refresh_allocation_findings(state);
    } else {
      set_status(state, locale::tr("memory.allocations.invalid_alloc"));
    }
  }
  if (ui::soft_button((std::string(icons::kUnlock) + "  " + locale::tr("memory.allocations.track_free")).c_str(),
                      ui::full_button(34))) {
    uint64_t address = 0;
    if (parse_u64(state.alloc_address, address)) {
      track_free(state, address);
      refresh_allocation_findings(state);
    } else {
      set_status(state, locale::tr("memory.allocations.invalid_free"));
    }
  }

  ImGui::InputTextMultiline(locale::tr("memory.allocations.events"), state.alloc_events_text,
                            sizeof(state.alloc_events_text),
                            ImVec2(0, 92));
  if (ui::soft_button((std::string(icons::kImport) + "  " + locale::tr("memory.allocations.import_events")).c_str(),
                      ui::full_button(34))) {
    parse_allocation_events(state);
  }

  for (const auto &finding : state.allocation_findings)
    ImGui::TextColored(ui::colors().muted, "%s", finding.c_str());

  if (ImGui::BeginTable("Allocations", 5,
      ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
      ImVec2(0, 190))) {
    ImGui::TableSetupColumn(locale::tr("memory.allocations.addr_col"));
    ImGui::TableSetupColumn(locale::tr("memory.allocations.size_col"), ImGuiTableColumnFlags_WidthFixed, 82);
    ImGui::TableSetupColumn(locale::tr("memory.allocations.state_col"), ImGuiTableColumnFlags_WidthFixed, 72);
    ImGui::TableSetupColumn(locale::tr("memory.allocations.events_col"), ImGuiTableColumnFlags_WidthFixed, 92);
    ImGui::TableSetupColumn(locale::tr("memory.allocations.note_col"));
    ImGui::TableHeadersRow();
    for (const auto &alloc : state.allocations) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextUnformatted(hex_u64(alloc.address).c_str());
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("%llu", static_cast<unsigned long long>(alloc.size));
      ImGui::TableSetColumnIndex(2);
      ImGui::TextColored(alloc.freed ? ui::colors().danger : ui::colors().success,
                         "%s", alloc.freed ? locale::tr("memory.allocations.freed") : locale::tr("memory.allocations.live"));
      ImGui::TableSetColumnIndex(3);
      ImGui::Text("%llu/%llu",
                  static_cast<unsigned long long>(alloc.alloc_event),
                  static_cast<unsigned long long>(alloc.free_event));
      ImGui::TableSetColumnIndex(4);
      ImGui::TextUnformatted(alloc.note.c_str());
    }
    ImGui::EndTable();
  }
  static bool skip_clear_alloc = false;
  if (ui::danger_button((std::string(icons::kTrash) + "  " + locale::tr("memory.allocations.clear")).c_str(),
                        ui::full_button(34))) {
    ImGui::OpenPopup("ConfirmClearAlloc");
  }
  if (ui::confirm_modal("ConfirmClearAlloc",
                        locale::tr("memory.allocations.confirm_clear"), nullptr,
                        &skip_clear_alloc, true)) {
    state.allocations.clear();
    state.allocation_findings.clear();
    state.allocation_alerts.clear();
  }
}

static bool should_scan_map_for_gadgets(const AppState &state, int map_index) {
  if (map_index < 0 || map_index >= static_cast<int>(state.maps.size()))
    return false;
  const auto &map = state.maps[map_index];
  if (map.end <= map.start) return false;
  if (state.gadget_exec_only && (map.protection & 4U) == 0U) return false;
  return (map.protection & 1U) != 0U;
}

static void scan_map_for_gadgets(AppState &state, int map_index) {
  const auto &map = state.maps[map_index];
  constexpr uint64_t kChunk = 64U * 1024U;
  constexpr size_t kOverlap = 8U;
  uint64_t cursor = map.start;
  std::vector<uint8_t> tail;

  while (cursor < map.end &&
         state.gadget_results.size() <
             static_cast<size_t>(std::max(1, state.gadget_max_results))) {
    uint64_t remaining = map.end - cursor;
    uint32_t length = remaining > kChunk ? static_cast<uint32_t>(kChunk)
                                         : static_cast<uint32_t>(remaining);
    std::vector<uint8_t> chunk;
    if (!state.client.memory_read(state.selected_pid, cursor, length, chunk)) {
      cursor += length;
      tail.clear();
      continue;
    }

    std::vector<uint8_t> scan = tail;
    scan.insert(scan.end(), chunk.begin(), chunk.end());
    uint64_t scan_base = cursor - tail.size();
    for (size_t i = 0; i < scan.size(); ++i) {
      for (const auto &pattern : kGadgetPatterns) {
        if (pattern.bytes.empty() || i + pattern.bytes.size() > scan.size())
          continue;
        if (!std::equal(pattern.bytes.begin(), pattern.bytes.end(),
                        scan.begin() + static_cast<std::ptrdiff_t>(i)))
          continue;
        GadgetMatch match;
        match.address = scan_base + i;
        match.name = pattern.name;
        match.bytes = bytes_hex(pattern.bytes);
        match.map_name = map.name;
        state.gadget_results.push_back(std::move(match));
        if (state.gadget_results.size() >=
            static_cast<size_t>(std::max(1, state.gadget_max_results)))
          return;
      }
    }

    tail.clear();
    if (scan.size() > kOverlap)
      tail.assign(scan.end() - static_cast<std::ptrdiff_t>(kOverlap),
                  scan.end());
    cursor += length;
  }
}

static void find_gadgets(AppState &state) {
  state.gadget_results.clear();
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); return; }
  state.gadget_max_results = std::clamp(state.gadget_max_results, 1, 4096);

  if (state.gadget_selected_map_only) {
    if (state.selected_map_row < 0) { set_status(state, "Select a map first"); return; }
    if (should_scan_map_for_gadgets(state, state.selected_map_row))
      scan_map_for_gadgets(state, state.selected_map_row);
  } else {
    for (int i = 0; i < static_cast<int>(state.maps.size()); ++i) {
      if (!should_scan_map_for_gadgets(state, i)) continue;
      scan_map_for_gadgets(state, i);
      if (state.gadget_results.size() >= static_cast<size_t>(state.gadget_max_results))
        break;
    }
  }
  char gb_buf[128];
  std::snprintf(gb_buf, sizeof(gb_buf), locale::tr("memory.exploit.found_n_gadgets"), state.gadget_results.size());
  set_status(state, gb_buf);
}

static double shannon_entropy(const std::vector<uint8_t> &bytes,
                              double &dominant_ratio,
                              uint32_t &longest_run) {
  if (bytes.empty()) {
    dominant_ratio = 0.0;
    longest_run = 0;
    return 0.0;
  }
  std::array<uint32_t, 256> counts{};
  uint32_t run = 1, best_run = 1;
  for (size_t i = 0; i < bytes.size(); ++i) {
    counts[bytes[i]]++;
    if (i > 0 && bytes[i] == bytes[i - 1]) {
      run++;
      best_run = std::max(best_run, run);
    } else {
      run = 1;
    }
  }
  uint32_t dominant = *std::max_element(counts.begin(), counts.end());
  dominant_ratio = static_cast<double>(dominant) / static_cast<double>(bytes.size());
  longest_run = best_run;

  double entropy = 0.0;
  for (uint32_t count : counts) {
    if (count == 0U) continue;
    double p = static_cast<double>(count) / static_cast<double>(bytes.size());
    entropy -= p * std::log2(p);
  }
  return entropy;
}

static void analyze_heap_spray(AppState &state) {
  state.heap_findings.clear();
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); return; }
  state.heap_sample_kb = std::clamp(state.heap_sample_kb, 4, 4096);
  state.heap_max_maps = std::clamp(state.heap_max_maps, 1, 256);

  int scanned = 0;
  uint32_t sample_len = static_cast<uint32_t>(state.heap_sample_kb) * 1024U;
  for (const auto &map : state.maps) {
    if (scanned >= state.heap_max_maps) break;
    if (map.end <= map.start) continue;
    if ((map.protection & 3U) != 3U || (map.protection & 4U) != 0U) continue;
    if (map_is_system_like(map)) continue;

    uint64_t available = map.end - map.start;
    uint32_t read_len = available > sample_len ? sample_len
                                               : static_cast<uint32_t>(available);
    std::vector<uint8_t> bytes;
    scanned++;
    if (!state.client.memory_read(state.selected_pid, map.start, read_len, bytes))
      continue;

    double dominant_ratio = 0.0;
    uint32_t longest_run = 0;
    double entropy = shannon_entropy(bytes, dominant_ratio, longest_run);
    if (entropy < 2.5 || dominant_ratio > 0.60 || longest_run >= 256U) {
      HeapSprayFinding finding;
      finding.start = map.start;
      finding.end = map.end;
      finding.entropy = entropy;
      finding.dominant_ratio = dominant_ratio;
      finding.longest_run = longest_run;
      std::ostringstream detail;
      if (entropy < 2.5) detail << "low entropy ";
      if (dominant_ratio > 0.60) detail << "dominant byte ";
      if (longest_run >= 256U) detail << "long run ";
      finding.detail = detail.str();
      state.heap_findings.push_back(std::move(finding));
    }
  }
  set_status(state, "Heap analysis: " + std::to_string(state.heap_findings.size()) +
                    " suspicious region(s)");
}

static const GadgetMatch *find_gadget(const AppState &state, const char *name) {
  for (const auto &gadget : state.gadget_results)
    if (gadget.name == name) return &gadget;
  return nullptr;
}

static void draw_exploit_tools(AppState &state) {
  ImGui::Checkbox(locale::tr("memory.exploit.selected_map"), &state.gadget_selected_map_only);
  ImGui::SameLine();
  ImGui::Checkbox(locale::tr("memory.exploit.exec_only"), &state.gadget_exec_only);
  ImGui::InputInt(locale::tr("memory.exploit.max_gadgets"), &state.gadget_max_results);
  state.gadget_max_results = std::clamp(state.gadget_max_results, 1, 4096);
  if (ui::primary_button((std::string(icons::kSearch) + "  " + locale::tr("memory.exploit.find_gadgets")).c_str(),
                         ui::full_button(36))) {
    find_gadgets(state);
  }

  const GadgetMatch *pop_rdi = find_gadget(state, "pop rdi; ret");
  const GadgetMatch *pop_rsi = find_gadget(state, "pop rsi; ret");
  const GadgetMatch *pop_rdx = find_gadget(state, "pop rdx; ret");
  const GadgetMatch *pop_rax = find_gadget(state, "pop rax; ret");
  const GadgetMatch *syscall = find_gadget(state, "syscall; ret");
  ImGui::TextColored(ui::colors().muted, locale::tr("memory.exploit.rop_skeleton"),
                     pop_rdi ? hex_u64(pop_rdi->address).c_str() : "-",
                     pop_rsi ? hex_u64(pop_rsi->address).c_str() : "-",
                     pop_rdx ? hex_u64(pop_rdx->address).c_str() : "-",
                     pop_rax ? hex_u64(pop_rax->address).c_str() : "-",
                     syscall ? hex_u64(syscall->address).c_str() : "-");

  if (ImGui::BeginTable("Gadgets", 4,
      ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
      ImVec2(0, 170))) {
    ImGui::TableSetupColumn(locale::tr("memory.exploit.gadget_addr_col"));
    ImGui::TableSetupColumn(locale::tr("memory.exploit.gadget_col"));
    ImGui::TableSetupColumn(locale::tr("memory.exploit.gadget_bytes_col"), ImGuiTableColumnFlags_WidthFixed, 120);
    ImGui::TableSetupColumn(locale::tr("memory.exploit.gadget_map_col"));
    ImGui::TableHeadersRow();
    for (const auto &gadget : state.gadget_results) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextUnformatted(hex_u64(gadget.address).c_str());
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(gadget.name.c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(gadget.bytes.c_str());
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(gadget.map_name.c_str());
    }
    ImGui::EndTable();
  }

  ImGui::Separator();
  ImGui::InputInt(locale::tr("memory.exploit.sample_kb"), &state.heap_sample_kb);
  ImGui::InputInt(locale::tr("memory.exploit.max_maps"), &state.heap_max_maps);
  if (ui::soft_button((std::string(icons::kBug) + "  " + locale::tr("memory.exploit.analyze_heap")).c_str(),
                      ui::full_button(36))) {
    analyze_heap_spray(state);
  }
  if (ImGui::BeginTable("HeapFindings", 5,
      ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
      ImVec2(0, 150))) {
    ImGui::TableSetupColumn(locale::tr("memory.exploit.heap_start_col"));
    ImGui::TableSetupColumn(locale::tr("memory.exploit.heap_end_col"));
    ImGui::TableSetupColumn(locale::tr("memory.exploit.heap_entropy_col"), ImGuiTableColumnFlags_WidthFixed, 72);
    ImGui::TableSetupColumn(locale::tr("memory.exploit.heap_dominant_col"), ImGuiTableColumnFlags_WidthFixed, 82);
    ImGui::TableSetupColumn(locale::tr("memory.exploit.heap_finding_col"));
    ImGui::TableHeadersRow();
    for (const auto &finding : state.heap_findings) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextUnformatted(hex_u64(finding.start).c_str());
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(hex_u64(finding.end).c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::Text("%.2f", finding.entropy);
      ImGui::TableSetColumnIndex(3);
      ImGui::Text("%.0f%%", finding.dominant_ratio * 100.0);
      ImGui::TableSetColumnIndex(4);
      ImGui::TextUnformatted(finding.detail.c_str());
    }
    ImGui::EndTable();
  }
}

} // namespace

void draw_memory(AppState &state, ImVec2 avail) {
  poll_watchpoints(state, false);

  /* Auto-refresh memory at the configured interval */
  if (state.memory_auto_refresh && state.client.connected() &&
      state.selected_pid > 0 &&
      payload_supports(state, MEMDBG_CAP_MEMORY_READ)) {
    const double now = ImGui::GetTime();
    if (now >= state.next_memory_auto_refresh) {
      state.next_memory_auto_refresh = now + std::max(0.1f, state.memory_auto_refresh_interval);
      read_memory(state, /*quiet=*/true);
    }
  }

  const float gap = 16.0f;
  const float left_w = std::max(420.0f, (avail.x - gap) * 0.38f);

  ui::begin_panel("MemoryTools", locale::tr("memory.memory_tools"), ImVec2(left_w, avail.y));
  ImGui::Text(locale::tr("memory.active_pid"), state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  if (ImGui::BeginTabBar("MemoryToolTabs")) {
    if (ImGui::BeginTabItem(locale::tr("memory.tab_io"))) {
      ImGui::InputText(locale::tr("memory.read_address"), state.read_address, sizeof(state.read_address));
      ImGui::InputInt(locale::tr("memory.read_length"), &state.read_length);
      state.read_length = std::clamp(state.read_length, 1, static_cast<int>(MEMDBG_PROTOCOL_MAX_READ));
      bool can_read = state.client.connected() && state.selected_pid > 0 &&
                      payload_supports(state, MEMDBG_CAP_MEMORY_READ);
      ImGui::BeginDisabled(!can_read);
      if (ui::primary_button((std::string(icons::kPlay) + "  " + locale::tr("memory.read_memory")).c_str(),
                             ui::full_button(40))) read_memory(state);
      ImGui::EndDisabled();

      ImGui::Spacing();
      ImGui::Checkbox(locale::tr("memory.auto_refresh"), &state.memory_auto_refresh);
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", locale::tr("memory.auto_refresh_tip"));
      ImGui::SameLine();
      ImGui::SetNextItemWidth(160);
      ImGui::SliderFloat("##mem_interval", &state.memory_auto_refresh_interval, 0.1f, 5.0f, "%.2f s");

      ImGui::Separator(); ImGui::Spacing();
      ImGui::InputText(locale::tr("memory.write_address"), state.write_address, sizeof(state.write_address));
      ImGui::InputText(locale::tr("memory.bytes"), state.write_bytes, sizeof(state.write_bytes));
      bool can_write = state.client.connected() && state.selected_pid > 0 &&
                       payload_supports(state, MEMDBG_CAP_MEMORY_WRITE);
      ImGui::BeginDisabled(!can_write);
      if (ui::danger_button((std::string(icons::kEdit) + "  " + locale::tr("memory.write_memory")).c_str(),
                            ui::full_button(40))) write_memory(state);
      ImGui::EndDisabled();

      ImGui::Spacing();
      ui::text_dim(locale::tr("memory.byte_format_hint"));
      ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem(locale::tr("memory.tab_watchpoints"))) {
      draw_watchpoints(state);
      ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem(locale::tr("memory.tab_allocations"))) {
      draw_allocations(state);
      ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem(locale::tr("memory.tab_exploit"))) {
      draw_exploit_tools(state);
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("MemoryHex", locale::tr("memory.hex_view"), ImVec2(0, avail.y));
  refresh_allocation_findings(state);
  draw_overlay_hex_view(state);
  ui::end_panel();
}

} // namespace memdbg::frontend

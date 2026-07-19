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
  cheat.active_known = true;
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
  cheat.active_known = true;
  cheat.status = "Restored "+std::to_string(written)+" bytes";
  return true;
}

static void draw_cheat_runtime_state(const CheatEntry &cheat) {
  if (!cheat.active_known) {
    ImGui::TextColored(ui::colors().warning, "%s",
                       locale::tr("trainer.state_unknown"));
    return;
  }
  ImGui::TextColored(cheat.active ? ui::colors().success : ui::colors().dim,
                     "%s", cheat.active
                         ? locale::tr("trainer.state_active")
                         : locale::tr("trainer.state_idle"));
}

static void draw_cheat_address(const CheatEntry &cheat, int row_id) {
  const std::string address = hex_u64(cheat.address);
  const std::string label = address + "##trainer_address_" +
                            std::to_string(row_id);
  if (ImGui::Selectable(label.c_str(), false,
                        ImGuiSelectableFlags_AllowDoubleClick)) {
    ImGui::SetClipboardText(address.c_str());
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("trainer.copy_address_tooltip"));
}

/* ---- Cheat Sources UI ---- */

namespace {

bool contains_ci_src(const std::string &haystack, const std::string &needle) {
  if (needle.empty()) return true;
  auto lower = [](std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
  };
  return lower(haystack).find(lower(needle)) != std::string::npos;
}

void start_cheat_refresh(AppState &state) {
  if (state.plugin.cheat_refresh_pending) return;
  if (state.plugin.cheat_refresh_future.valid()) state.plugin.cheat_refresh_future.wait();
  state.plugin.cheat_refresh_error.clear();
  state.plugin.cheat_refresh_pending = true;
  set_status(state, locale::tr("trainer.refreshing_sources"));
  state.plugin.cheat_refresh_future = std::async(std::launch::async, [&state]() -> bool {
    std::string error;
    const bool ok = state.cheat_repository.refresh_all(&error);
    state.plugin.cheat_refresh_error = error;
    return ok;
  });
}

bool load_cheat_into_trainer(AppState &state, const cheats::CheatCatalogEntry &entry) {
  std::string content;
  std::string error;
  if (!state.cheat_repository.fetch_cheat_content(entry, content, &error)) {
    set_status(state, error);
    return false;
  }

  if (cheats::cheat_format_from_string(entry.format) != cheats::CheatFormat::JSON) {
    set_status(state, "Only JSON format cheats can be loaded into the trainer currently");
    return false;
  }

  /* Parse GoldHEN JSON via the shared parser. */
  std::string parse_error;
  std::vector<CheatEntry> parsed = parse_goldhen_mods(content, state.selected_pid, &parse_error, &state.maps);
  if (parsed.empty()) {
    set_status(state, parse_error.empty() ? "No valid cheat entries in JSON" : parse_error);
    return false;
  }

  int loaded = 0;
  for (auto &cheat : parsed) {
    if (state.client.connected()) (void)capture_off_value(state, cheat);
    state.plugin.cheats.push_back(std::move(cheat));
    loaded++;
  }

  if (loaded > 0) {
    char buf[256];
    std::snprintf(buf, sizeof(buf), locale::tr("trainer.loaded_into_trainer"), loaded, entry.title.c_str());
    set_status(state, buf);
    push_notification(state, buf);
  }
  return loaded > 0;
}

void draw_cheat_source_modal(AppState &state) {
  const float scl = ui::dpi_scale();
  if (state.plugin.cheat_add_source_modal_open)
    ImGui::OpenPopup("Add Cheat Source");

  const ImGuiViewport *viewport = ImGui::GetMainViewport();
  const ImVec2 modal_size(
      std::min(550.0f * scl, viewport->WorkSize.x - 48.0f * scl),
      std::min(400.0f * scl, viewport->WorkSize.y - 48.0f * scl));
  ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
  ImGui::SetNextWindowSize(modal_size, ImGuiCond_Appearing);

  bool open = state.plugin.cheat_add_source_modal_open;
  ImGui::PushStyleColor(ImGuiCol_PopupBg, ui::colors().panel2);
  ImGui::PushStyleColor(ImGuiCol_TitleBg, ui::colors().bg3);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f * scl, 10.0f * scl));
  if (ImGui::BeginPopupModal("Add Cheat Source", &open, ImGuiWindowFlags_NoResize)) {
    state.plugin.cheat_add_source_modal_open = true;

    ImGui::TextColored(ui::colors().primary2, "%s", "Add Cheat Repository");
    ImGui::TextWrapped("%s", "Enter the URL to a cheat index file (e.g. json.txt from a HEN cheats collection) or a structured manifest.json.");
    ImGui::Spacing();

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.source_name"));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##CheatSourceNameModal", state.plugin.cheat_source_name, sizeof(state.plugin.cheat_source_name));
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.source_url"));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##CheatSourceUrlModal", state.plugin.cheat_source_url, sizeof(state.plugin.cheat_source_url));

    ImGui::Spacing();
    if (ui::primary_button((std::string(icons::kAdd) + "  " + locale::tr("trainer.add_source")).c_str(),
                           ImVec2(150.0f * scl, 34.0f * scl))) {
      /* Auto-detect format from URL */
      std::string url = state.plugin.cheat_source_url;
      std::string base_url;
      std::string fmt = "json";
      std::string index_fmt = "flat_txt";

      /* Derive base URL: strip the filename part */
      size_t last_slash = url.find_last_of('/');
      if (last_slash != std::string::npos)
        base_url = url.substr(0, last_slash + 1);
      else
        base_url = url + "/";

      /* Derive format from path */
      std::string lower_url = url;
      std::transform(lower_url.begin(), lower_url.end(), lower_url.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (lower_url.find("shn") != std::string::npos) fmt = "shn";
      else if (lower_url.find("mc4") != std::string::npos) fmt = "mc4";

      std::string error;
      if (state.cheat_repository.add_source(state.plugin.cheat_source_name, url, base_url, index_fmt, fmt, "", &error)) {
        std::snprintf(state.plugin.cheat_source_name, sizeof(state.plugin.cheat_source_name), "%s", "HEN Cheats Collection");
        state.plugin.cheat_source_url[0] = '\0';
        state.plugin.cheat_source_filter = 0;
        state.plugin.cheat_add_source_modal_open = false;
        set_status(state, locale::tr("trainer.source_added"));
        push_notification(state, locale::tr("trainer.source_added"));
        start_cheat_refresh(state);
        ImGui::CloseCurrentPopup();
      } else {
        set_status(state, error);
      }
    }
    ImGui::SameLine();
    if (ui::soft_button("Cancel", ImVec2(100.0f * scl, 34.0f * scl))) {
      state.plugin.cheat_add_source_modal_open = false;
      ImGui::CloseCurrentPopup();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextColored(ui::colors().muted, "%s", "Configured sources");
    std::vector<cheats::CheatSource> sources = state.cheat_repository.sources();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
    ImGui::BeginChild("CheatSourceModalListFrame", ImVec2(0, 0), true);
    if (ImGui::BeginTable("CheatSourceModalList", 4,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
                          ImVec2(0, 0))) {
      ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 42.0f * scl);
      ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.34f);
      ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch, 0.40f);
      ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 72.0f * scl);
      ImGui::TableHeadersRow();
      for (size_t i = 0; i < sources.size(); ++i) {
        cheats::CheatSource source = sources[i];
        ImGui::PushID(static_cast<int>(i));
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        bool enabled = source.enabled;
        if (ImGui::Checkbox("##cheat_source_enabled", &enabled)) {
          std::string error;
          state.cheat_repository.set_source_enabled(i, enabled, &error);
          state.plugin.cheat_source_filter = 0;
        }
        ImGui::TableSetColumnIndex(1);
        ImGui::TextUnformatted(source.name.c_str());
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", source.url.c_str());
        ImGui::TableSetColumnIndex(2);
        ImGui::TextColored(source.last_ok ? ui::colors().success : ui::colors().muted,
                           "%s", source.status.c_str());
        ImGui::TableSetColumnIndex(3);
        if (ImGui::SmallButton((std::string(icons::kTrash) + "##removeCheat").c_str())) {
          std::string error;
          state.cheat_repository.remove_source(i, &error);
          state.plugin.cheat_source_filter = 0;
        }
        ImGui::PopID();
      }
      ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::EndPopup();
  }
  ImGui::PopStyleVar();
  ImGui::PopStyleColor(2);
  if (!open) state.plugin.cheat_add_source_modal_open = false;
}

void draw_cheat_sources(AppState &state, ImVec2 content_avail) {
  const float scl = ui::dpi_scale();
  const float min_left_w = 480.0f * scl;
  const float min_right_w = 380.0f * scl;
  const bool stacked = content_avail.x < (min_left_w + min_right_w);
  const float left_w = stacked ? content_avail.x
      : std::clamp(content_avail.x * 0.58f, min_left_w, content_avail.x - min_right_w);
  const float right_w = stacked ? content_avail.x : std::max(min_right_w, content_avail.x - left_w);
  const float left_h = stacked ? std::max(280.0f * scl, content_avail.y * 0.52f) : content_avail.y;
  const float right_h = stacked ? std::max(200.0f * scl, content_avail.y - left_h) : content_avail.y;

  std::vector<cheats::CheatSource> sources = state.cheat_repository.sources();
  std::vector<cheats::CheatCatalogEntry> catalog = state.cheat_repository.catalog();

  /* Filter by source */
  if (state.plugin.cheat_source_filter < 0 ||
      state.plugin.cheat_source_filter > static_cast<int>(sources.size()))
    state.plugin.cheat_source_filter = 0;

  if (state.plugin.cheat_source_filter > 0) {
    const auto &source = sources[static_cast<size_t>(state.plugin.cheat_source_filter - 1)];
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const cheats::CheatCatalogEntry &e) { return e.source_id != source.id; }),
        catalog.end());
  }

  /* Search filter */
  const std::string filter = state.plugin.cheat_repo_filter;
  if (!filter.empty()) {
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const cheats::CheatCatalogEntry &e) {
          return !contains_ci_src(e.title, filter) &&
                 !contains_ci_src(e.game_id, filter) &&
                 !contains_ci_src(e.credits, filter) &&
                 !contains_ci_src(e.version, filter);
        }), catalog.end());
  }

  /* Sort: installed first, then by title */
  std::sort(catalog.begin(), catalog.end(),
      [](const cheats::CheatCatalogEntry &a, const cheats::CheatCatalogEntry &b) {
        if (a.installed != b.installed) return a.installed > b.installed;
        return a.title < b.title;
      });

  draw_cheat_source_modal(state);

  /* ---- Left panel: catalog ---- */
  ui::begin_panel("CheatSourcesCatalog", locale::tr("trainer.cheat_sources"), ImVec2(left_w, left_h));

  /* Toolbar */
  const float control_h = 34.0f * scl;
  const float btn_w = 38.0f * scl;
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9.0f * scl, 7.0f * scl));
  if (ImGui::BeginTable("CheatSourcesToolbar", 4,
                        ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_PadOuterX)) {
    ImGui::TableSetupColumn("Search", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 190.0f * scl);
    ImGui::TableSetupColumn("Refresh", ImGuiTableColumnFlags_WidthFixed, btn_w);
    ImGui::TableSetupColumn("Add", ImGuiTableColumnFlags_WidthFixed, btn_w);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##CheatRepoSearch", locale::tr("trainer.search_cheats"),
                             state.plugin.cheat_repo_filter, sizeof(state.plugin.cheat_repo_filter));
    ImGui::TableSetColumnIndex(1);
    const char *preview = "All sources";
    std::string preview_label;
    if (state.plugin.cheat_source_filter > 0) {
      preview_label = sources[static_cast<size_t>(state.plugin.cheat_source_filter - 1)].name;
      preview = preview_label.c_str();
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##CheatSourceFilter", preview)) {
      if (ImGui::Selectable("All sources", state.plugin.cheat_source_filter == 0))
        state.plugin.cheat_source_filter = 0;
      for (size_t i = 0; i < sources.size(); ++i) {
        const bool selected = state.plugin.cheat_source_filter == static_cast<int>(i + 1U);
        if (ImGui::Selectable(sources[i].name.c_str(), selected))
          state.plugin.cheat_source_filter = static_cast<int>(i + 1U);
        if (selected) ImGui::SetItemDefaultFocus();
      }
      ImGui::EndCombo();
    }
    ImGui::TableSetColumnIndex(2);
    if (ui::soft_button(icons::kRefresh, ImVec2(btn_w, control_h))) start_cheat_refresh(state);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", "Refresh sources");
    ImGui::TableSetColumnIndex(3);
    if (ui::primary_button(icons::kAdd, ImVec2(btn_w, control_h)))
      state.plugin.cheat_add_source_modal_open = true;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", "Add cheat source");
    ImGui::EndTable();
  }
  ImGui::PopStyleVar();

  /* Catalog list */
  if (state.plugin.cheat_selected_row >= static_cast<int>(catalog.size()))
    state.plugin.cheat_selected_row = catalog.empty() ? -1 : 0;

  ImGui::BeginChild("CheatCatalogList", ImVec2(0, 0), false);
  if (catalog.empty()) {
    ui::draw_empty_state(locale::tr("trainer.no_cheats"), locale::tr("trainer.no_cheats_desc"));
  } else {
    for (size_t i = 0; i < catalog.size(); ++i) {
      const auto &entry = catalog[i];
      const bool selected = state.plugin.cheat_selected_row == static_cast<int>(i);
      ImGui::PushID(static_cast<int>(i));

      const ImVec2 pos = ImGui::GetCursorScreenPos();
      const ImVec2 size(ImGui::GetContentRegionAvail().x, 58.0f * scl);
      ImGui::InvisibleButton("##cheat_card", size);
      const bool hovered = ImGui::IsItemHovered();
      if (ImGui::IsItemClicked()) state.plugin.cheat_selected_row = static_cast<int>(i);

      ImDrawList *draw = ImGui::GetWindowDrawList();
      const ImVec2 max(pos.x + size.x, pos.y + size.y);
      const ImVec4 bg = selected ? ImVec4(0.06f, 0.22f, 0.17f, 1.0f)
          : hovered ? ImVec4(0.12f, 0.16f, 0.15f, 1.0f) : ui::colors().bg1;
      draw->AddRectFilled(pos, max, ui::color_u32(bg), 6.0f * scl);
      draw->AddRect(pos, max, ui::color_u32(selected ? ui::colors().primary2 : ui::colors().border),
                    6.0f * scl, 0, 1.0f * scl);

      draw->AddText(ImGui::GetFont(), ImGui::GetFontSize() * 1.05f,
                    ImVec2(pos.x + 10.0f * scl, pos.y + 7.0f * scl),
                    ui::color_u32(ui::colors().text), entry.title.c_str());
      draw->AddText(ImVec2(pos.x + 10.0f * scl, pos.y + 25.0f * scl),
                    ui::color_u32(ui::colors().muted),
                    (entry.game_id + "  ·  v" + entry.version + "  ·  " + entry.format).c_str());

      const char *state_text = entry.installed ? "Installed" : "Available";
      const ImVec2 chip_size = ImGui::CalcTextSize(state_text);
      const ImVec2 chip_min(max.x - chip_size.x - 16.0f * scl, max.y - 22.0f * scl);
      const ImVec2 chip_max(max.x - 6.0f * scl, max.y - 6.0f * scl);
      draw->AddRectFilled(chip_min, chip_max,
                          ui::color_u32(entry.installed ? ui::colors().bg3 : ui::colors().bg0), 4.0f * scl);
      draw->AddText(ImVec2(chip_min.x + 5.0f * scl, chip_min.y + 2.0f * scl),
                    ui::color_u32(entry.installed ? ui::colors().success : ui::colors().muted), state_text);

      if (hovered) {
        ImGui::SetTooltip("%s\n%s v%s", entry.title.c_str(), entry.game_id.c_str(), entry.version.c_str());
      }
      ImGui::PopID();
    }
  }
  ImGui::EndChild();
  ui::end_panel();

  /* ---- Right panel: details ---- */
  if (!stacked) ImGui::SameLine(0, 0);
  ui::begin_panel("CheatSourcesDetail", "Details", ImVec2(right_w, right_h));

  const cheats::CheatCatalogEntry *selected_cheat = nullptr;
  if (state.plugin.cheat_selected_row >= 0 && state.plugin.cheat_selected_row < static_cast<int>(catalog.size()))
    selected_cheat = &catalog[static_cast<size_t>(state.plugin.cheat_selected_row)];

  if (selected_cheat == nullptr) {
    ui::draw_empty_state("No cheat selected", "Select a cheat from the catalog to see details and load into the trainer.");
  } else {
    ImGui::PushStyleColor(ImGuiCol_Text, ui::colors().primary2);
    ImGui::TextWrapped("%s", selected_cheat->title.c_str());
    ImGui::PopStyleColor();

    ImGui::TextColored(ui::colors().muted, "%s", selected_cheat->game_id.c_str());
    ImGui::TextColored(ui::colors().dim, "Version %s  ·  %s",
                       selected_cheat->version.c_str(),
                       selected_cheat->format.c_str());
    if (!selected_cheat->credits.empty())
      ImGui::TextColored(ui::colors().dim, "Credits: %s", selected_cheat->credits.c_str());
    ImGui::TextColored(ui::colors().dim, "Source: %s", selected_cheat->source_name.c_str());

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    /* Action buttons */
    if (!selected_cheat->installed) {
      if (ui::primary_button((std::string(icons::kDump) + "  " + locale::tr("trainer.install")).c_str(),
                             ImVec2(std::min(150.0f * scl, ImGui::GetContentRegionAvail().x), 34.0f * scl))) {
        std::string error;
        if (state.cheat_repository.install_cheat(selected_cheat->game_id, selected_cheat->version,
                                                  selected_cheat->source_id, &error)) {
          char buf[256];
          std::snprintf(buf, sizeof(buf), locale::tr("trainer.cheat_installed"), selected_cheat->title.c_str());
          set_status(state, buf);
          push_notification(state, buf);
        } else {
          set_status(state, error);
        }
      }
    } else {
      if (ui::danger_button((std::string(icons::kTrash) + "  " + locale::tr("trainer.remove")).c_str(),
                            ImVec2(std::min(150.0f * scl, ImGui::GetContentRegionAvail().x), 34.0f * scl))) {
        std::string error;
        if (state.cheat_repository.uninstall_cheat(selected_cheat->game_id, selected_cheat->version, &error)) {
          char buf[256];
          std::snprintf(buf, sizeof(buf), locale::tr("trainer.cheat_removed"), selected_cheat->title.c_str());
          set_status(state, buf);
        } else {
          set_status(state, error);
        }
      }
    }

    ImGui::Spacing();
    if (ui::primary_button((std::string(icons::kPlay) + "  " + locale::tr("trainer.load_into_trainer")).c_str(),
                           ImVec2(std::min(200.0f * scl, ImGui::GetContentRegionAvail().x), 34.0f * scl))) {
      load_cheat_into_trainer(state, *selected_cheat);
    }
  }

  ui::end_panel();
}

} // namespace

/* poll_cheat_tasks: called every frame to check async refresh completion */
void poll_cheat_tasks(AppState &state) {
  if (state.plugin.cheat_refresh_pending && state.plugin.cheat_refresh_future.valid()) {
    auto status = state.plugin.cheat_refresh_future.wait_for(std::chrono::milliseconds(0));
    if (status == std::future_status::ready) {
      bool ok = false;
      try {
        ok = state.plugin.cheat_refresh_future.get();
      } catch (const std::exception &ex) {
        state.plugin.cheat_refresh_error = ex.what();
      } catch (...) {
        state.plugin.cheat_refresh_error = "Unknown cheat refresh error";
      }
      state.plugin.cheat_refresh_pending = false;
      if (ok) {
        set_status(state, locale::tr("trainer.sources_refreshed"));
        push_notification(state, locale::tr("trainer.sources_refreshed"));
      } else {
        const std::string error = state.plugin.cheat_refresh_error.empty()
            ? "Cheat source refresh failed" : state.plugin.cheat_refresh_error;
        set_status(state, error);
        push_notification(state, error, 5.0);
      }
    }
  }
}

static void add_cheat_from_fields(AppState &state) {
  if (state.selected_pid<=0) { set_status(state, locale::tr("trainer.select_process_first")); return; }
  if (client_async_busy(state)) { set_status(state, locale::tr("trainer.wait_active")); return; }
  uint64_t address=0;
  std::vector<uint8_t> bytes;
  if (!parse_u64(state.plugin.cheat_address, address)) { set_status(state, locale::tr("trainer.invalid_cheat_addr")); return; }
  if (!build_value_bytes(state.plugin.cheat_type, state.plugin.cheat_value, bytes)) { set_status(state, locale::tr("trainer.invalid_cheat_value")); return; }
  CheatEntry cheat;
  cheat.description = state.plugin.cheat_description[0]!='\0'?state.plugin.cheat_description:"Cheat";
  cheat.pid=state.selected_pid; cheat.address=address; cheat.value_type=state.plugin.cheat_type;
  cheat.value_text=state.plugin.cheat_value; cheat.bytes=std::move(bytes); cheat.locked=state.plugin.cheat_lock;
  if (state.client.connected()) (void)capture_off_value(state, cheat);
  state.plugin.cheats.push_back(std::move(cheat));
  set_status(state, locale::tr("trainer.entry_added"));
  char notify_buf[512];
  std::snprintf(notify_buf, sizeof(notify_buf), locale::tr("trainer.entry_added_notify"), state.plugin.cheat_description);
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
  int imported = parse_batchcode(state.plugin.batchcode_text, entries, error);
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
    state.plugin.cheats.push_back(std::move(cheat));
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

void apply_locked_cheats(AppState &state) {
  if (!state.client.connected()||state.plugin.cheats.empty()) return;
  /* Suspend trainer writes after reconnect until session is fully verified.
   * Writing to old PIDs or addresses after rest mode can corrupt memory. */
  if (state.conn.reconnect.phase != ConnectionPhase::Online ||
      state.conn.reconnect.stale)
    return;
  if (client_async_busy(state)) return;
  const double now = ImGui::GetTime();
  const double interval = std::max(0.10f, state.plugin.cheat_lock_interval);
  if (now < state.plugin.next_cheat_lock_time) return;
  state.plugin.next_cheat_lock_time = now + interval;

  /* Collect locked cheats with valid PID and non-empty bytes */
  std::vector<CheatEntry *> locked;
  for (auto &cheat : state.plugin.cheats)
    if (cheat.enabled && cheat.locked && !cheat.bytes.empty())
      locked.push_back(&cheat);

  if (locked.empty()) return;

  if (has_batch_write(state)) {
    /* Batch writes are PID-scoped.  Keep entries attached to the process they
       came from even when the user selects another process later. */
    std::vector<int32_t> pids;
    for (const CheatEntry *cheat : locked) {
      const int32_t pid = cheat->pid > 0 ? cheat->pid : state.selected_pid;
      if (pid > 0 && std::find(pids.begin(), pids.end(), pid) == pids.end())
        pids.push_back(pid);
    }
    for (int32_t pid : pids) {
      std::vector<CheatEntry *> group;
      for (CheatEntry *cheat : locked) {
        const int32_t entry_pid = cheat->pid > 0 ? cheat->pid : state.selected_pid;
        if (entry_pid == pid) group.push_back(cheat);
      }
      for (size_t base = 0U; base < group.size();
           base += MEMDBG_BATCH_WRITE_MAX_ITEMS) {
        const size_t chunk_end =
            std::min(base + MEMDBG_BATCH_WRITE_MAX_ITEMS, group.size());
        std::vector<std::pair<uint64_t, std::vector<uint8_t>>> items;
        items.reserve(chunk_end - base);
        for (size_t i = base; i < chunk_end; ++i)
          items.emplace_back(group[i]->address, group[i]->bytes);

        Client::BatchWriteResult result;
        if (state.client.batch_write(pid, items, result)) {
          for (size_t j = 0U; j < items.size(); ++j) {
            CheatEntry *cheat = group[base + j];
            if (j < result.entries.size() && result.entries[j].status == 0U) {
              cheat->active = true;
              cheat->active_known = true;
              cheat->status = "Locked (batch)";
            } else {
              cheat->status = "Batch write failed";
            }
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
  for (auto &cheat : state.plugin.cheats) {
    if (cheat.enabled && apply_cheat(state, cheat)) applied++;
  }
  char applied_buf[256];
  std::snprintf(applied_buf, sizeof(applied_buf), locale::tr("trainer.applied"), applied);
  set_status(state, applied_buf);
  push_notification(state, applied_buf);
}

/* ---- Main draw ---- */
void draw_trainer(AppState &state, ImVec2 avail) {
  const float scl = ui::dpi_scale();
  static int trainer_tab = 0;

  /* Tab bar */
  const float tab_h = 36.0f * scl;
  const float content_avail_y = avail.y - tab_h - 8.0f * scl;
  ImGui::PushStyleColor(ImGuiCol_Tab, ui::colors().bg1);
  ImGui::PushStyleColor(ImGuiCol_TabSelected, ui::colors().bg2);
  ImGui::PushStyleColor(ImGuiCol_TabHovered, ui::colors().bg3);
  if (ImGui::BeginTabBar("TrainerTabBar")) {
    if (ImGui::BeginTabItem(locale::tr("trainer.tab_builder"))) { trainer_tab = 0; ImGui::EndTabItem(); }
    if (ImGui::BeginTabItem(locale::tr("trainer.tab_list"))) { trainer_tab = 1; ImGui::EndTabItem(); }
    if (ImGui::BeginTabItem(locale::tr("trainer.tab_sources"))) { trainer_tab = 2; ImGui::EndTabItem(); }
    ImGui::EndTabBar();
  }
  ImGui::PopStyleColor(3);

  /* Global keyboard shortcuts — work in any trainer tab */
  if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_O)) {
    std::string picked = memdbg::frontend::ui::pickFile(
        locale::tr("file_picker.open_trainer"),
        locale::tr("file_picker.trainer_files"),
        "*.cht;*.shn;*.json;*.trainer");
    if (!picked.empty()) {
      std::snprintf(state.plugin.trainer_file_path, sizeof(state.plugin.trainer_file_path),
                    "%s", picked.c_str());
      load_trainer_file(state, state.plugin.trainer_file_path);
    }
  }
  if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_S)) {
    if (state.plugin.trainer_file_path[0] != '\0') {
      save_trainer_file(state, state.plugin.trainer_file_path);
    } else {
      std::string picked = memdbg::frontend::ui::pickSaveFile(
          locale::tr("file_picker.save_trainer"),
          "trainer.cht",
          locale::tr("file_picker.trainer_files"),
          "*.cht;*.shn;*.json;*.trainer");
      if (!picked.empty()) {
        std::snprintf(state.plugin.trainer_file_path, sizeof(state.plugin.trainer_file_path),
                      "%s", picked.c_str());
        save_trainer_file(state, state.plugin.trainer_file_path);
      }
    }
  }

  ImVec2 content_avail(avail.x, content_avail_y);

  if (trainer_tab == 2) {
    /* Sources tab */
    draw_cheat_sources(state, content_avail);
    return;
  }

  if (trainer_tab == 1) {
    /* List-only tab */
    ui::begin_panel("TrainerList", locale::tr("trainer.runtime_cheat_list"), ImVec2(0, content_avail.y));
    static bool skip_apply_enabled2 = false;
    static bool skip_clear_disabled2 = false;
    ImGui::BeginDisabled(!state.client.connected() || client_async_busy(state));
    if (ImGui::BeginTable("TrainerListActions2", 3,
                          ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_PadOuterX)) {
      ImGui::TableSetupColumn("Apply", ImGuiTableColumnFlags_WidthStretch, 1.0f);
      ImGui::TableSetupColumn("Clear", ImGuiTableColumnFlags_WidthFixed, 176.0f * scl);
      ImGui::TableSetupColumn("Count", ImGuiTableColumnFlags_WidthFixed, 86.0f * scl);
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      if (ui::soft_button((std::string(icons::kPlay) + "  " + locale::tr("trainer.apply_enabled")).c_str(), ImVec2(-1, 38.0f * scl)))
        ImGui::OpenPopup("ConfirmApplyEnabledTrainer2");
      ImGui::TableSetColumnIndex(1);
      if (ui::soft_button((std::string(icons::kTrash) + "  " + locale::tr("trainer.clear_disabled")).c_str(), ImVec2(-1, 38.0f * scl)))
        ImGui::OpenPopup("ConfirmClearDisabled2");
      ImGui::TableSetColumnIndex(2);
      ImGui::AlignTextToFramePadding();
      ImGui::TextColored(ui::colors().dim, locale::tr("trainer.n_entries"), state.plugin.cheats.size());
      ImGui::EndTable();
    }
    ImGui::EndDisabled();
    if (ui::confirm_modal("ConfirmApplyEnabledTrainer2",
                          "Apply all enabled trainer entries?",
                          "This can write several process addresses in one action. Validate the PID and loaded trainer before continuing.",
                          &skip_apply_enabled2, true))
      apply_enabled_cheats(state);
    if (ui::confirm_modal("ConfirmClearDisabled2", locale::tr("trainer.confirm_clear_disabled"), nullptr,
                          &skip_clear_disabled2, true)) {
      state.plugin.cheats.erase(std::remove_if(state.plugin.cheats.begin(), state.plugin.cheats.end(),
          [](const CheatEntry &c){ return !c.enabled; }), state.plugin.cheats.end());
    }

    /* Copy All */
    if (!state.plugin.cheats.empty()) {
      if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("trainer.copy_all")).c_str(), ImVec2(200, 30))) {
        std::string all;
        all.reserve(state.plugin.cheats.size() * 18U);
        for (const auto &cheat : state.plugin.cheats) all += hex_u64(cheat.address) + "\n";
        ImGui::SetClipboardText(all.c_str());
        char cp_buf[256];
        std::snprintf(cp_buf, sizeof(cp_buf), locale::tr("trainer.copied_n"), state.plugin.cheats.size());
        set_status(state, cp_buf);
        push_notification(state, cp_buf);
      }
    }

    ImGui::Spacing();
    if (state.plugin.cheats.empty()) {
      ui::draw_empty_state(locale::tr("trainer.no_entries"), locale::tr("trainer.no_entries_desc"));
    } else if (ImGui::BeginTable("TrainerTable2", 10,
          ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|
              ImGuiTableFlags_ScrollX|ImGuiTableFlags_Resizable, ImVec2(0,0))) {
      ImGui::TableSetupColumn(locale::tr("trainer.col_on"), ImGuiTableColumnFlags_WidthFixed,76);
      ImGui::TableSetupColumn(locale::tr("trainer.col_lock"), ImGuiTableColumnFlags_WidthFixed,54);
      ImGui::TableSetupColumn(locale::tr("trainer.col_state"), ImGuiTableColumnFlags_WidthFixed,92);
      ImGui::TableSetupColumn(locale::tr("trainer.col_name"));
      ImGui::TableSetupColumn(locale::tr("trainer.col_pid"), ImGuiTableColumnFlags_WidthFixed,70);
      ImGui::TableSetupColumn(locale::tr("trainer.col_address"));
      ImGui::TableSetupColumn(locale::tr("trainer.col_type"), ImGuiTableColumnFlags_WidthFixed,70);
      ImGui::TableSetupColumn(locale::tr("trainer.col_value"));
      ImGui::TableSetupColumn(locale::tr("trainer.col_off"), ImGuiTableColumnFlags_WidthFixed,136);
      ImGui::TableSetupColumn(locale::tr("trainer.col_action"), ImGuiTableColumnFlags_WidthFixed,350);
      ImGui::TableHeadersRow();
      for (int i=0; i<static_cast<int>(state.plugin.cheats.size()); ++i) {
        CheatEntry &cheat = state.plugin.cheats[i];
        ImGui::PushID(i+1000);
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0); ImGui::Checkbox("##enabled2", &cheat.enabled);
        ImGui::TableSetColumnIndex(1); ImGui::Checkbox("##locked2", &cheat.locked);
        ImGui::TableSetColumnIndex(2); draw_cheat_runtime_state(cheat);
        ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(cheat.description.c_str());
        ImGui::TableSetColumnIndex(4); ImGui::Text("%d", cheat.pid);
        ImGui::TableSetColumnIndex(5); draw_cheat_address(cheat, i + 1000);
        ImGui::TableSetColumnIndex(6); ImGui::TextUnformatted(value_type_name(cheat.value_type));
        ImGui::TableSetColumnIndex(7); ImGui::TextUnformatted(cheat.value_text.c_str());
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
    return;
  }

  /* Builder tab (tab 0) - original layout */
  /* Process trainer files dropped from the OS onto the window */
  if (!state.elf.dropped_files.empty()) {
    for (const auto &path : state.elf.dropped_files) {
      std::string lower = path;
      std::transform(lower.begin(), lower.end(), lower.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      const bool is_trainer_ext =
          (lower.size() >= 4U && (lower.compare(lower.size() - 4U, 4U, ".cht") == 0 ||
                                  lower.compare(lower.size() - 4U, 4U, ".shn") == 0)) ||
          (lower.size() >= 5U && lower.compare(lower.size() - 5U, 5U, ".json") == 0) ||
          (lower.size() >= 8U && lower.compare(lower.size() - 8U, 8U, ".trainer") == 0);
      if (is_trainer_ext) {
        std::snprintf(state.plugin.trainer_file_path, sizeof(state.plugin.trainer_file_path),
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
    state.elf.dropped_files.clear();
  }

  const bool stacked = content_avail.x < 900.0f * scl;
  const float left_w = stacked
      ? content_avail.x
      : std::clamp(content_avail.x * 0.40f, 360.0f * scl,
                   std::max(360.0f * scl, content_avail.x * 0.54f));
  const float left_h = stacked ? std::max(330.0f * scl, content_avail.y * 0.48f)
                               : content_avail.y;
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
      std::snprintf(state.plugin.cheat_address, sizeof(state.plugin.cheat_address), "%s", state.mem.write_address);
    ImGui::TableNextColumn();
    ImGui::BeginDisabled(state.scan.result.addresses.empty());
    if (ui::soft_button(locale::tr("trainer.use_first_hit"), ImVec2(-1, 36.0f * scl)))
      std::snprintf(state.plugin.cheat_address, sizeof(state.plugin.cheat_address), "%s", hex_u64(state.scan.result.addresses.front()).c_str());
    ImGui::EndDisabled();
    ImGui::EndTable();
  }

  labeled_input_text(locale::tr("trainer.name_label"), "##TrainerName",
                     state.plugin.cheat_description, sizeof(state.plugin.cheat_description));
  labeled_input_text(locale::tr("trainer.address"), "##TrainerAddress",
                     state.plugin.cheat_address, sizeof(state.plugin.cheat_address));
  labeled_combo(locale::tr("trainer.value_type"), "##TrainerValueType",
                &state.plugin.cheat_type, type_names, IM_ARRAYSIZE(type_names));
  labeled_input_text(locale::tr("trainer.value"), "##TrainerValue",
                     state.plugin.cheat_value, sizeof(state.plugin.cheat_value));
  ImGui::Checkbox(locale::tr("trainer.lock_value"), &state.plugin.cheat_lock);
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.lock_interval"));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::SliderFloat("##TrainerLockInterval", &state.plugin.cheat_lock_interval, 0.10f, 5.0f, "%.2fs");
  bool can_train = state.client.connected() && state.selected_pid > 0 &&
                   !client_async_busy(state) &&
                   payload_supports(state, MEMDBG_CAP_MEMORY_WRITE);
  ImGui::BeginDisabled(!can_train);
  if (ui::primary_button((std::string(icons::kAdd) + "  " + locale::tr("trainer.add_to_trainer")).c_str(), ui::full_button(40))) add_cheat_from_fields(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.trainer_file"));
  {
    ui::FilePathOptions trainer_opts;
    trainer_opts.id = "##TrainerPath";
    trainer_opts.dialog_title = locale::tr("file_picker.open_trainer");
    trainer_opts.filter_desc = locale::tr("file_picker.trainer_files");
    trainer_opts.filter_ext = "*.cht;*.shn;*.json;*.trainer";
    ui::file_path_input(state.plugin.trainer_file_path, sizeof(state.plugin.trainer_file_path), trainer_opts);
  }
  ImGui::BeginDisabled(client_async_busy(state));
  if (ImGui::BeginTable("TrainerFileActions", 4,
                        ImGuiTableFlags_SizingStretchSame |
                            ImGuiTableFlags_PadOuterX)) {
    ImGui::TableNextColumn();
    if (ui::soft_button((std::string(icons::kLoad) + "  " + locale::tr("trainer.load")).c_str(),
        ImVec2(-1, 38.0f * scl))) {
      if (load_trainer_file(state, state.plugin.trainer_file_path) < 0) {
        /* error already set by load_trainer_file */
      }
    }
    ImGui::TableNextColumn();
    {
      ui::FilePathOptions open_opts;
      open_opts.id = "##TrainerLoadPicker";
      open_opts.dialog_title = locale::tr("file_picker.open_trainer");
      open_opts.filter_desc = locale::tr("file_picker.trainer_files");
      open_opts.filter_ext = "*.cht;*.shn;*.json;*.trainer";
      open_opts.button_size = ImVec2(-1, 38.0f * scl);
      std::string picked = ui::file_open_button(
          (std::string(icons::kLoad) + "  ...").c_str(), open_opts);
      if (!picked.empty()) {
        std::snprintf(state.plugin.trainer_file_path, sizeof(state.plugin.trainer_file_path),
                      "%s", picked.c_str());
        load_trainer_file(state, state.plugin.trainer_file_path);
      }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("file_picker.open_trainer"));
    ImGui::TableNextColumn();
    if (ui::soft_button((std::string(icons::kSave) + "  " + locale::tr("trainer.save")).c_str(),
        ImVec2(-1, 38.0f * scl))) {
      save_trainer_file(state, state.plugin.trainer_file_path);
    }
    ImGui::TableNextColumn();
    {
      ui::FilePathOptions save_opts;
      save_opts.id = "##TrainerSavePicker";
      save_opts.dialog_title = locale::tr("file_picker.save_trainer");
      save_opts.filter_desc = locale::tr("file_picker.trainer_files");
      save_opts.filter_ext = "*.cht;*.shn;*.json;*.trainer";
      save_opts.default_name = "trainer.cht";
      save_opts.button_size = ImVec2(-1, 38.0f * scl);
      std::string picked = ui::file_save_button(
          (std::string(icons::kSave) + "  ...").c_str(), save_opts);
      if (!picked.empty()) {
        std::snprintf(state.plugin.trainer_file_path, sizeof(state.plugin.trainer_file_path),
                      "%s", picked.c_str());
        save_trainer_file(state, state.plugin.trainer_file_path);
      }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("file_picker.save_trainer"));
    ImGui::EndTable();
  }
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("trainer.batchcode_import"));
  ImGui::InputTextMultiline("##Batchcode", state.plugin.batchcode_text, sizeof(state.plugin.batchcode_text),
                            ImVec2(0, 112.0f * scl));
  if (ui::soft_button((std::string(icons::kImport) + "  " + locale::tr("trainer.import_batchcode")).c_str(), ui::full_button(38.0f))) import_batchcode(state);
  ui::text_dim(locale::tr("trainer.batchcode_hint"));
  ui::end_panel();

  if (stacked) {
    ImGui::Spacing();
  } else {
    ImGui::SameLine(0, 0);
  }
  const float list_h = stacked ? std::max(220.0f * scl, content_avail.y - left_h)
                               : content_avail.y;
  ui::begin_panel("TrainerList", locale::tr("trainer.runtime_cheat_list"),
                  ImVec2(0, list_h));

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
    ImGui::TextColored(ui::colors().dim, locale::tr("trainer.n_entries"), state.plugin.cheats.size());
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
    state.plugin.cheats.erase(std::remove_if(state.plugin.cheats.begin(), state.plugin.cheats.end(),
      [](const CheatEntry &c){ return !c.enabled; }), state.plugin.cheats.end());
  }
  ImGui::Spacing();

  /* Copy All logic shared between button and keyboard shortcut */
  auto copy_all = [&](const char *suffix = nullptr) {
    std::string all;
    all.reserve(state.plugin.cheats.size() * 18U);
    for (const auto &cheat : state.plugin.cheats)
      all += hex_u64(cheat.address) + "\n";
    ImGui::SetClipboardText(all.c_str());
    char cp_buf[256];
    std::snprintf(cp_buf, sizeof(cp_buf), locale::tr("trainer.copied_n"), state.plugin.cheats.size());
    set_status(state, cp_buf);
    push_notification(state, cp_buf + std::string(suffix ? suffix : ""));
  };

  if (!state.plugin.cheats.empty()) {
    if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("trainer.copy_all")).c_str(),
                        ImVec2(200, 30)))
      copy_all();
    if (ImGui::IsItemHovered()) {
      char tip_buf[128];
      std::snprintf(tip_buf, sizeof(tip_buf), locale::tr("trainer.copy_all_tooltip"), state.plugin.cheats.size());
      ImGui::SetTooltip("%s", tip_buf);
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_C))
      copy_all(" (Ctrl+C)");
  }

  if (state.plugin.cheats.empty()) {
    ui::draw_empty_state(locale::tr("trainer.no_entries"), locale::tr("trainer.no_entries_desc"));
  } else if (ImGui::BeginTable("TrainerTable", 10,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|
            ImGuiTableFlags_ScrollX|ImGuiTableFlags_Resizable,
        ImVec2(0,0))) {
    ImGui::TableSetupColumn(locale::tr("trainer.col_on"), ImGuiTableColumnFlags_WidthFixed,76);
    ImGui::TableSetupColumn(locale::tr("trainer.col_lock"), ImGuiTableColumnFlags_WidthFixed,54);
    ImGui::TableSetupColumn(locale::tr("trainer.col_state"), ImGuiTableColumnFlags_WidthFixed,92);
    ImGui::TableSetupColumn(locale::tr("trainer.col_name"));
    ImGui::TableSetupColumn(locale::tr("trainer.col_pid"), ImGuiTableColumnFlags_WidthFixed,70);
    ImGui::TableSetupColumn(locale::tr("trainer.col_address"));
    ImGui::TableSetupColumn(locale::tr("trainer.col_type"), ImGuiTableColumnFlags_WidthFixed,70);
    ImGui::TableSetupColumn(locale::tr("trainer.col_value"));
    ImGui::TableSetupColumn(locale::tr("trainer.col_off"), ImGuiTableColumnFlags_WidthFixed,136);
    ImGui::TableSetupColumn(locale::tr("trainer.col_action"), ImGuiTableColumnFlags_WidthFixed,350);
    ImGui::TableHeadersRow();
    for (int i=0; i<static_cast<int>(state.plugin.cheats.size()); ++i) {
      CheatEntry &cheat = state.plugin.cheats[i];
      ImGui::PushID(i);
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0); ImGui::Checkbox("##enabled", &cheat.enabled);
      ImGui::TableSetColumnIndex(1); ImGui::Checkbox("##locked", &cheat.locked);
      ImGui::TableSetColumnIndex(2); draw_cheat_runtime_state(cheat);
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(cheat.description.c_str());
      if (ImGui::IsItemHovered()) {
        if (!cheat.status.empty())
          ImGui::SetTooltip("%s \xe2\x80\x94 %s", cheat.description.c_str(), cheat.status.c_str());
        else if (!cheat.description.empty())
          ImGui::SetTooltip("%s", cheat.description.c_str());
      }
      ImGui::TableSetColumnIndex(4); ImGui::Text("%d", cheat.pid);
      ImGui::TableSetColumnIndex(5); draw_cheat_address(cheat, i);
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

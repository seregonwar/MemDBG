/*
 * MemDBG - Plugin community catalog screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "platform.hpp"

#if !defined(MEMDBG_PLATFORM_IOS)
#include <GLFW/glfw3.h>
#endif
#include "stb_image.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <future>
#include <string>
#include <unordered_map>
#include <vector>

#if !defined(MEMDBG_PLATFORM_IOS)
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif
#endif

namespace memdbg::frontend {

namespace {

using plugins::PluginPackage;
using plugins::PluginSource;

struct PluginIconTexture {
  uint32_t texture = 0;
  int width = 0;
  int height = 0;
  bool attempted = false;
};

static std::unordered_map<std::string, PluginIconTexture> s_icon_cache;
constexpr size_t kCardDescriptionLimit = 118;
constexpr size_t kDetailDescriptionLimit = 210;

bool contains_ci(const std::string &haystack, const std::string &needle) {
  if (needle.empty()) return true;
  auto lower = [](std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
  };
  return lower(haystack).find(lower(needle)) != std::string::npos;
}

std::string lower_ascii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

bool starts_with(const std::string &value, const char *prefix) {
  const std::string p(prefix);
  return value.size() >= p.size() && value.compare(0, p.size(), p) == 0;
}

bool is_remote_asset(const std::string &value) {
  const std::string lower = lower_ascii(value);
  return starts_with(lower, "http://") || starts_with(lower, "https://");
}

std::filesystem::path icon_path_from_url(const std::string &value) {
  if (starts_with(lower_ascii(value), "file://")) {
    std::string path = value.substr(7);
#if defined(_WIN32)
    if (starts_with(path, "/") && path.size() > 2U && path[2] == ':')
      path.erase(path.begin());
#endif
    return std::filesystem::path(path);
  }
  return std::filesystem::path(value);
}

ImTextureID texture_id(uint32_t texture) {
  return reinterpret_cast<ImTextureID>(static_cast<intptr_t>(texture));
}

PluginIconTexture *plugin_icon_texture(const PluginPackage &pkg) {
  if (pkg.icon_url.empty() || is_remote_asset(pkg.icon_url)) return nullptr;

  PluginIconTexture &asset = s_icon_cache[pkg.icon_url];
  if (asset.texture != 0U) return &asset;
  if (asset.attempted) return nullptr;
  asset.attempted = true;

  int width = 0;
  int height = 0;
  int channels = 0;
  const std::filesystem::path path = icon_path_from_url(pkg.icon_url);
  unsigned char *pixels = stbi_load(path.string().c_str(), &width, &height, &channels, 4);
  if (pixels == nullptr || width <= 0 || height <= 0) {
    stbi_image_free(pixels);
    return nullptr;
  }

  #if !defined(MEMDBG_PLATFORM_IOS)
  GLuint tex = 0;
  glGenTextures(1, &tex);
  glBindTexture(GL_TEXTURE_2D, tex);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA,
               GL_UNSIGNED_BYTE, pixels);
  glBindTexture(GL_TEXTURE_2D, 0);
  asset.texture = static_cast<uint32_t>(tex);
#endif
  stbi_image_free(pixels);

  asset.width = width;
  asset.height = height;
  return &asset;
}

std::string tags_text(const std::vector<std::string> &tags) {
  std::string out;
  for (const auto &tag : tags) {
    if (!out.empty()) out += ", ";
    out += tag;
  }
  return out.empty() ? "general" : out;
}

std::string permissions_text(const std::vector<std::string> &permissions) {
  std::string out;
  for (const auto &permission : permissions) {
    if (!out.empty()) out += ", ";
    out += permission;
  }
  return out.empty() ? "none declared" : out;
}

std::string format_downloads(uint64_t value) {
  char buf[64];
  if (value >= 1000000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fM", static_cast<double>(value) / 1000000.0);
  } else if (value >= 1000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fk", static_cast<double>(value) / 1000.0);
  } else {
    std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(value));
  }
  return buf;
}

std::string download_label(uint64_t value) {
  return value == 0U ? "stats unavailable" : format_downloads(value) + " downloads";
}

std::string shorten_text(const std::string &value, size_t limit) {
  if (value.size() <= limit) return value;
  if (limit <= 4U) return value.substr(0, limit);

  size_t cut = std::min(limit, value.size());
  const size_t soft_floor = limit > 24U ? limit - 24U : limit / 2U;
  while (cut > soft_floor &&
         std::isspace(static_cast<unsigned char>(value[cut])) == 0) {
    --cut;
  }
  if (cut <= soft_floor) cut = limit;
  while (cut > 0U &&
         std::isspace(static_cast<unsigned char>(value[cut - 1U])) != 0) {
    --cut;
  }
  return value.substr(0, cut) + "...";
}

std::string compact_middle(const std::string &value, size_t limit) {
  if (value.size() <= limit || limit < 12U) return value;
  const size_t keep = limit - 3U;
  const size_t front = keep / 2U;
  const size_t back = keep - front;
  return value.substr(0, front) + "..." + value.substr(value.size() - back);
}

std::string plugin_full_description(const PluginPackage &pkg) {
  if (!pkg.description.empty()) return pkg.description;
  if (!pkg.short_description.empty()) return pkg.short_description;
  return "No description provided.";
}

std::string plugin_card_description(const PluginPackage &pkg) {
  const std::string source = !pkg.short_description.empty()
      ? pkg.short_description
      : plugin_full_description(pkg);
  return shorten_text(source, kCardDescriptionLimit);
}

std::string plugin_detail_preview(const PluginPackage &pkg) {
  return shorten_text(plugin_full_description(pkg), kDetailDescriptionLimit);
}

bool is_default_source(const PluginSource &source) {
  return source.url == plugins::kDefaultSourceUrl ||
         plugins::normalize_source_url(source.url) == plugins::kDefaultSourceUrl;
}

float clamp_layout(float value, float min_value, float max_value) {
  if (max_value < min_value) return std::max(0.0f, max_value);
  return std::clamp(value, min_value, max_value);
}

plugins::PluginRunContext build_run_context(const AppState &state) {
  plugins::PluginRunContext context;
  context.host = state.host;
  context.debug_port = state.debug_port;
  context.udp_port = state.udp_port;
  context.connected = state.client.connected();
  context.selected_pid = state.selected_pid;
  context.selected_process_name = selected_process_name(state);
  context.dump_path = state.dump_path;
  context.trainer_file_path = state.trainer_file_path;
  context.protocol_version = state.has_hello ? state.hello.protocol_version : 0U;
  context.capabilities = state.has_hello ? state.hello.capabilities : 0U;
  context.map_count = state.maps.size();
  context.scan_hit_count = state.scan_result.addresses.size();
  context.trainer_entry_count = state.cheats.size();
  return context;
}

void start_refresh(AppState &state) {
  if (state.plugin_refresh_pending || state.plugin_run_pending) return;
  if (state.plugin_refresh_future.valid()) state.plugin_refresh_future.wait();
  state.plugin_refresh_error.clear();
  state.plugin_refresh_pending = true;
  set_status(state, locale::tr("plugins.refreshing_sources"));
  state.plugin_refresh_future = std::async(std::launch::async, [&state]() -> bool {
    std::string error;
    const bool ok = state.plugin_manager.refresh_all(&error);
    state.plugin_refresh_error = error;
    return ok;
  });
}

void start_run(AppState &state, const PluginPackage &package) {
  if (!package.installed || state.plugin_refresh_pending || state.plugin_run_pending) return;
  if (state.plugin_run_future.valid()) state.plugin_run_future.wait();
  const auto context = build_run_context(state);
  const std::string package_id = package.id;
  state.plugin_last_output.clear();
  state.plugin_last_error.clear();
  state.plugin_last_command.clear();
  state.plugin_last_id = package_id;
  state.plugin_run_pending = true;
  state.plugin_run_start_time = ImGui::GetTime();
  char run_buf[256];
  std::snprintf(run_buf, sizeof(run_buf), locale::tr("plugins.running_plugin"), package.name.c_str());
  set_status(state, run_buf);
  state.plugin_run_future = std::async(std::launch::async, [&state, package_id, context]() {
    return state.plugin_manager.run_plugin(package_id, context);
  });
}

std::vector<PluginPackage> filtered_catalog(AppState &state,
                                            const std::vector<PluginSource> &sources) {
  if (state.plugin_source_filter < 0 ||
      state.plugin_source_filter > static_cast<int>(sources.size())) {
    state.plugin_source_filter = 0;
  }

  std::vector<PluginPackage> catalog = state.plugin_manager.catalog();
  if (state.plugin_source_filter > 0) {
    const auto &source = sources[static_cast<size_t>(state.plugin_source_filter - 1)];
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const PluginPackage &pkg) { return pkg.source_id != source.id; }),
        catalog.end());
  }

  const std::string filter = state.plugin_filter;
  if (!filter.empty()) {
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const PluginPackage &pkg) {
          return !contains_ci(pkg.name, filter) &&
                 !contains_ci(pkg.author, filter) &&
                 !contains_ci(pkg.source_name, filter) &&
                 !contains_ci(pkg.id, filter) &&
                 !contains_ci(pkg.short_description, filter) &&
                 !contains_ci(pkg.description, filter) &&
                 !contains_ci(tags_text(pkg.tags), filter);
        }), catalog.end());
  }

  std::sort(catalog.begin(), catalog.end(),
      [](const PluginPackage &a, const PluginPackage &b) {
        if (a.installed != b.installed) return a.installed > b.installed;
        if (a.download_count != b.download_count) return a.download_count > b.download_count;
        if (a.source_name != b.source_name) return a.source_name < b.source_name;
        return a.name < b.name;
      });
  return catalog;
}

void draw_plugin_thumbnail(const PluginPackage &pkg, ImVec2 pos, float size) {
  const float scl = ui::dpi_scale();
  ImDrawList *draw = ImGui::GetWindowDrawList();
  const ImVec2 max(pos.x + size, pos.y + size);
  if (PluginIconTexture *icon = plugin_icon_texture(pkg); icon != nullptr) {
    draw->AddRectFilled(pos, max, ui::color_u32(ui::colors().bg1), 6.0f * scl);
    draw->AddImage(texture_id(icon->texture), pos, max);
    draw->AddRect(pos, max, ui::color_u32(ui::colors().border), 6.0f * scl, 0, 1.0f * scl);
    return;
  }

  const bool python = pkg.language == plugins::PluginLanguage::Python;
  const bool lua = pkg.language == plugins::PluginLanguage::Lua;
  const ImVec4 base = python ? ImVec4(0.14f, 0.24f, 0.32f, 1.0f)
      : lua ? ImVec4(0.16f, 0.18f, 0.34f, 1.0f)
            : ImVec4(0.16f, 0.22f, 0.20f, 1.0f);
  const ImVec4 accent = python ? ImVec4(0.33f, 0.70f, 0.95f, 1.0f)
      : lua ? ImVec4(0.47f, 0.57f, 0.98f, 1.0f)
            : ui::colors().primary2;

  draw->AddRectFilled(pos, max, ui::color_u32(base), 6.0f * scl);
  draw->AddRect(pos, max, ui::color_u32(accent), 6.0f * scl, 0, 1.0f * scl);

  const char *mark = python ? "PY" : lua ? "LUA" : icons::kPlugins;
  const ImVec2 text_size = ImGui::CalcTextSize(mark);
  draw->AddText(ImVec2(pos.x + (size - text_size.x) * 0.5f,
                       pos.y + (size - text_size.y) * 0.5f),
                ui::color_u32(ui::colors().text), mark);

  if (!pkg.icon_url.empty()) {
    const ImVec2 tag_min(pos.x + size - 18.0f * scl,
                         pos.y + size - 18.0f * scl);
    const ImVec2 tag_max(pos.x + size - 4.0f * scl,
                         pos.y + size - 4.0f * scl);
    const ImU32 accent_u32 = ui::color_u32(accent);
    draw->AddRectFilled(tag_min, tag_max, ui::color_u32(ui::colors().bg0),
                        3.0f * scl);
    draw->AddRect(tag_min, tag_max, accent_u32, 3.0f * scl, 0, 1.0f * scl);
    draw->AddCircleFilled(ImVec2(tag_min.x + 4.5f * scl, tag_min.y + 4.5f * scl),
                          1.5f * scl, accent_u32);
    draw->AddLine(ImVec2(tag_min.x + 3.0f * scl, tag_max.y - 4.0f * scl),
                  ImVec2(tag_min.x + 7.0f * scl, tag_min.y + 9.0f * scl),
                  accent_u32, 1.0f * scl);
    draw->AddLine(ImVec2(tag_min.x + 7.0f * scl, tag_min.y + 9.0f * scl),
                  ImVec2(tag_max.x - 3.0f * scl, tag_max.y - 4.0f * scl),
                  accent_u32, 1.0f * scl);
  }
}

void draw_info_row(const char *label, const std::string &value,
                   bool compact = false) {
  if (value.empty()) return;
  const std::string display = compact ? compact_middle(value, 54U) : value;
  ImGui::TableNextRow();
  ImGui::TableSetColumnIndex(0);
  ImGui::TextColored(ui::colors().muted, "%s", label);
  ImGui::TableSetColumnIndex(1);
  ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
  ImGui::TextWrapped("%s", display.c_str());
  ImGui::PopTextWrapPos();
  if (display != value && ImGui::IsItemHovered()) {
    ImGui::SetTooltip("%s", value.c_str());
  }
}

void draw_add_source_modal(AppState &state) {
  const float scl = ui::dpi_scale();
  if (state.plugin_add_source_modal_open) {
    ImGui::OpenPopup("Add Plugin Source");
  }

  const ImGuiViewport *viewport = ImGui::GetMainViewport();
  const ImVec2 modal_size(
      std::min(620.0f * scl, viewport->WorkSize.x - 48.0f * scl),
      std::min(470.0f * scl, viewport->WorkSize.y - 48.0f * scl));
  ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_Appearing,
                          ImVec2(0.5f, 0.5f));
  ImGui::SetNextWindowSize(modal_size, ImGuiCond_Appearing);

  bool open = state.plugin_add_source_modal_open;
  ImGui::PushStyleColor(ImGuiCol_PopupBg, ui::colors().panel2);
  ImGui::PushStyleColor(ImGuiCol_TitleBg, ui::colors().bg3);
  ImGui::PushStyleColor(ImGuiCol_TitleBgActive, ui::colors().bg3);
  ImGui::PushStyleColor(ImGuiCol_TitleBgCollapsed, ui::colors().bg3);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f * scl, 10.0f * scl));
  if (ImGui::BeginPopupModal("Add Plugin Source", &open,
                             ImGuiWindowFlags_NoResize)) {
    state.plugin_add_source_modal_open = true;

    ImGui::TextColored(ui::colors().primary2, "%s", "Community repository");
    ImGui::TextWrapped("%s", "Add a forkable source with a manifest.json catalog. GitHub repository URLs, raw manifest URLs, and local folders are accepted.");
    ImGui::Spacing();

    const float control_h = 34.0f * scl;
    ImGui::TextColored(ui::colors().muted, "%s", "Name");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##PluginSourceNameModal", state.plugin_source_name,
                     sizeof(state.plugin_source_name));
    ImGui::TextColored(ui::colors().muted, "%s", "Manifest / repository URL");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##PluginSourceUrlModal", state.plugin_source_url,
                     sizeof(state.plugin_source_url));

    ImGui::Spacing();
    ImGui::BeginDisabled(state.plugin_refresh_pending || state.plugin_run_pending);
    if (ui::primary_button((std::string(icons::kAdd) + "  Add Source").c_str(),
                           ImVec2(168.0f * scl, control_h))) {
      std::string error;
      if (state.plugin_manager.add_source(state.plugin_source_name,
                                          state.plugin_source_url, &error)) {
        std::snprintf(state.plugin_source_name, sizeof(state.plugin_source_name),
                      "%s", "Community Repository");
        state.plugin_source_url[0] = '\0';
        state.plugin_source_filter = 0;
        state.plugin_add_source_modal_open = false;
        set_status(state, locale::tr("plugins.source_added"));
        push_notification(state, locale::tr("plugins.source_added"));
        start_refresh(state);
        ImGui::CloseCurrentPopup();
      } else {
        set_status(state, error);
      }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ui::soft_button("Cancel", ImVec2(120.0f * scl, control_h))) {
      state.plugin_add_source_modal_open = false;
      ImGui::CloseCurrentPopup();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextColored(ui::colors().muted, "%s", "Configured sources");
    std::vector<PluginSource> sources = state.plugin_manager.sources();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
    ImGui::BeginChild("PluginSourceModalListFrame", ImVec2(0, 0), true);
    if (ImGui::BeginTable("PluginSourceModalList", 4,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
                          ImVec2(0, 0))) {
      ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 42.0f * scl);
      ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.34f);
      ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch, 0.40f);
      ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 72.0f * scl);
      ImGui::TableHeadersRow();
      for (size_t i = 0; i < sources.size(); ++i) {
        PluginSource source = sources[i];
        ImGui::PushID(static_cast<int>(i));
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        bool enabled = source.enabled;
        if (ImGui::Checkbox("##source_enabled", &enabled)) {
          std::string error;
          if (!state.plugin_manager.set_source_enabled(i, enabled, &error))
            set_status(state, error);
          state.plugin_source_filter = 0;
        }
        ImGui::TableSetColumnIndex(1);
        ImGui::TextUnformatted(source.name.c_str());
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", source.url.c_str());
        ImGui::TableSetColumnIndex(2);
        ImGui::TextColored(source.last_ok ? ui::colors().success : ui::colors().muted,
                           "%s", source.status.c_str());
        ImGui::TableSetColumnIndex(3);
        ImGui::BeginDisabled(is_default_source(source));
        if (ImGui::SmallButton((std::string(icons::kTrash) + "##remove").c_str())) {
          std::string error;
          if (!state.plugin_manager.remove_source(i, &error)) set_status(state, error);
          else {
            state.plugin_source_filter = 0;
            set_status(state, locale::tr("plugins.source_removed"));
          }
        }
        ImGui::EndDisabled();
        ImGui::PopID();
      }
      ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::EndPopup();
  }
  ImGui::PopStyleVar();
  ImGui::PopStyleColor(4);
  if (!open) state.plugin_add_source_modal_open = false;
}

void draw_catalog_toolbar(AppState &state, const std::vector<PluginSource> &sources) {
  const float scl = ui::dpi_scale();
  const float control_h = 34.0f * scl;
  const float button_w = 38.0f * scl;
  const float avail_w = ImGui::GetContentRegionAvail().x;
  const float source_w = std::clamp(avail_w * 0.34f, 190.0f * scl, 300.0f * scl);
  if (state.plugin_source_filter < 0 ||
      state.plugin_source_filter > static_cast<int>(sources.size())) {
    state.plugin_source_filter = 0;
  }

  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9.0f * scl, 7.0f * scl));
  if (ImGui::BeginTable("PluginCatalogToolbar", 4,
                        ImGuiTableFlags_SizingStretchProp |
                            ImGuiTableFlags_PadOuterX)) {
    ImGui::TableSetupColumn("Search", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, source_w);
    ImGui::TableSetupColumn("Refresh", ImGuiTableColumnFlags_WidthFixed, button_w);
    ImGui::TableSetupColumn("Add", ImGuiTableColumnFlags_WidthFixed, button_w);
    ImGui::TableNextRow();

    ImGui::TableSetColumnIndex(0);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##PluginSearch", "Search plugins, creators, tags...",
                             state.plugin_filter, sizeof(state.plugin_filter));

    ImGui::TableSetColumnIndex(1);
    const char *preview = "All sources";
    std::string preview_label;
    if (state.plugin_source_filter > 0) {
      preview_label = sources[static_cast<size_t>(state.plugin_source_filter - 1)].name;
      preview = preview_label.c_str();
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##PluginSourceFilter", preview)) {
      if (ImGui::Selectable("All sources", state.plugin_source_filter == 0))
        state.plugin_source_filter = 0;
      for (size_t i = 0; i < sources.size(); ++i) {
        const bool selected = state.plugin_source_filter == static_cast<int>(i + 1U);
        if (ImGui::Selectable(sources[i].name.c_str(), selected))
          state.plugin_source_filter = static_cast<int>(i + 1U);
        if (selected) ImGui::SetItemDefaultFocus();
      }
      ImGui::EndCombo();
    }

    ImGui::TableSetColumnIndex(2);
    ImGui::BeginDisabled(state.plugin_refresh_pending || state.plugin_run_pending);
    if (ui::soft_button(icons::kRefresh, ImVec2(button_w, control_h))) {
      start_refresh(state);
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", "Refresh sources");

    ImGui::TableSetColumnIndex(3);
    if (ui::primary_button(icons::kAdd, ImVec2(button_w, control_h))) {
      state.plugin_add_source_modal_open = true;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", "Add plugin source");
    ImGui::EndTable();
  }
  ImGui::PopStyleVar();
}

void draw_plugin_card(AppState &state, const PluginPackage &pkg,
                      int row, float width) {
  const float scl = ui::dpi_scale();
  const float row_h = 78.0f * scl;
  const float pad = 8.0f * scl;
  const float thumb = 54.0f * scl;
  const bool selected = state.plugin_selected_row == row;

  ImGui::PushID(pkg.id.c_str());
  const ImVec2 pos = ImGui::GetCursorScreenPos();
  const ImVec2 size(std::max(width, 220.0f * scl), row_h);
  ImGui::InvisibleButton("##plugin_card", size);
  const bool hovered = ImGui::IsItemHovered();
  if (ImGui::IsItemClicked()) {
    if (state.plugin_selected_row != row) state.plugin_description_expanded = false;
    state.plugin_selected_row = row;
  }

  ImDrawList *draw = ImGui::GetWindowDrawList();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  const ImVec4 bg = selected ? ImVec4(0.06f, 0.22f, 0.17f, 1.0f)
      : hovered ? ImVec4(0.12f, 0.16f, 0.15f, 1.0f)
                : ui::colors().bg1;
  draw->AddRectFilled(pos, max, ui::color_u32(bg), 6.0f * scl);
  draw->AddRect(pos, max,
                ui::color_u32(selected ? ui::colors().primary2 : ui::colors().border),
                6.0f * scl, 0, 1.0f * scl);

  const ImVec2 thumb_pos(pos.x + pad, pos.y + (row_h - thumb) * 0.5f);
  draw_plugin_thumbnail(pkg, thumb_pos, thumb);

  const float text_x = thumb_pos.x + thumb + 12.0f * scl;
  draw->PushClipRect(ImVec2(pos.x + pad, pos.y + pad),
                     ImVec2(max.x - pad, max.y - pad), true);
  draw->AddText(ImGui::GetFont(), ImGui::GetFontSize() * 1.08f,
                ImVec2(text_x, pos.y + 9.0f * scl),
                ui::color_u32(ui::colors().text), pkg.name.c_str());

  const std::string meta = (pkg.author.empty() ? "Unknown creator" : pkg.author) +
      std::string("  |  ") + plugins::language_name(pkg.language) +
      "  |  " + pkg.source_name;
  draw->AddText(ImVec2(text_x, pos.y + 29.0f * scl),
                ui::color_u32(ui::colors().muted), meta.c_str());

  const std::string desc = plugin_card_description(pkg);
  draw->AddText(ImVec2(text_x, pos.y + 49.0f * scl),
                ui::color_u32(ui::colors().dim), desc.c_str());

  if (pkg.download_count != 0U) {
    const std::string downloads = format_downloads(pkg.download_count) + " downloads";
    const ImVec2 dl_size = ImGui::CalcTextSize(downloads.c_str());
    draw->AddText(ImVec2(max.x - dl_size.x - pad, pos.y + 10.0f * scl),
                  ui::color_u32(ui::colors().primary2), downloads.c_str());
  }

  const char *state_text = pkg.installed ? (pkg.enabled ? "Installed" : "Disabled") : "Available";
  const ImVec2 chip_size = ImGui::CalcTextSize(state_text);
  const ImVec2 chip_min(max.x - chip_size.x - 18.0f * scl, max.y - 28.0f * scl);
  const ImVec2 chip_max(max.x - pad, max.y - 8.0f * scl);
  draw->AddRectFilled(chip_min, chip_max,
                      ui::color_u32(pkg.installed ? ui::colors().bg3 : ui::colors().bg0),
                      4.0f * scl);
  draw->AddText(ImVec2(chip_min.x + 6.0f * scl, chip_min.y + 3.0f * scl),
                ui::color_u32(pkg.installed ? ui::colors().success : ui::colors().muted),
                state_text);
  draw->PopClipRect();

  if (hovered) ImGui::SetTooltip("%s", plugin_full_description(pkg).c_str());
  ImGui::PopID();
  ImGui::Spacing();
}

void draw_catalog(AppState &state, const std::vector<PluginPackage> &catalog) {
  const float scl = ui::dpi_scale();
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Community Catalog");
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%zu plugins", catalog.size());

  if (state.plugin_selected_row >= static_cast<int>(catalog.size()))
    state.plugin_selected_row = catalog.empty() ? -1 : 0;

  ImGui::BeginChild("PluginCatalogList", ImVec2(0, 0), false);
  if (catalog.empty()) {
    ui::draw_empty_state("No plugins found",
                         "Try another search term or switch plugin source.");
  } else {
    const float width = ImGui::GetContentRegionAvail().x;
    for (size_t i = 0; i < catalog.size(); ++i) {
      draw_plugin_card(state, catalog[i], static_cast<int>(i), width);
    }
  }
  ImGui::Dummy(ImVec2(1.0f, 4.0f * scl));
  ImGui::EndChild();
}

void draw_package_details(AppState &state, const PluginPackage *pkg) {
  const float scl = ui::dpi_scale();
  if (pkg == nullptr) {
    ui::draw_empty_state("No plugin selected",
                         "Select a plugin from the catalog to inspect it.");
    return;
  }

  const float thumb = 62.0f * scl;
  if (ImGui::BeginTable("PluginDetailsHeaderTable", 2,
                        ImGuiTableFlags_SizingStretchProp)) {
    ImGui::TableSetupColumn("Icon", ImGuiTableColumnFlags_WidthFixed,
                            thumb + 12.0f * scl);
    ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    const ImVec2 thumb_pos = ImGui::GetCursorScreenPos();
    draw_plugin_thumbnail(*pkg, thumb_pos, thumb);
    ImGui::Dummy(ImVec2(thumb, thumb));

    ImGui::TableSetColumnIndex(1);
    ImGui::PushStyleColor(ImGuiCol_Text, ui::colors().primary2);
    ImGui::TextWrapped("%s", pkg->name.c_str());
    ImGui::PopStyleColor();
    ImGui::TextColored(ui::colors().muted, "%s",
                       pkg->author.empty() ? "Unknown creator" : pkg->author.c_str());
    const std::string meta = std::string(plugins::language_name(pkg->language)) +
        " " + pkg->version + "  |  " + pkg->source_name;
    ImGui::TextColored(ui::colors().dim, "%s", meta.c_str());
    ImGui::TextColored(pkg->download_count == 0U ? ui::colors().dim : ui::colors().primary2,
                       "%s", download_label(pkg->download_count).c_str());
    ImGui::EndTable();
  }

  ImGui::Spacing();
  const std::string full_description = plugin_full_description(*pkg);
  const bool can_expand = full_description.size() > kDetailDescriptionLimit;
  const std::string visible_description =
      state.plugin_description_expanded || !can_expand
          ? full_description
          : plugin_detail_preview(*pkg);
  ImGui::TextWrapped("%s", visible_description.c_str());
  if (can_expand) {
    const char *label = state.plugin_description_expanded ? "Collapse" : "Expand";
    if (ui::soft_button(label, ImVec2(92.0f * scl, 28.0f * scl))) {
      state.plugin_description_expanded = !state.plugin_description_expanded;
    }
    if (ImGui::IsItemHovered()) {
      ImGui::SetTooltip("%s", state.plugin_description_expanded
                                ? "Show a compact description"
                                : "Show the full plugin description");
    }
  }

  ImGui::Spacing();
  ImGui::BeginDisabled(state.plugin_refresh_pending || state.plugin_run_pending);
  if (!pkg->installed) {
    if (ui::primary_button((std::string(icons::kDump) + "  Install").c_str(),
                           ImVec2(std::min(160.0f * scl, ImGui::GetContentRegionAvail().x),
                                  34.0f * scl))) {
      std::string error;
      if (state.plugin_manager.install_package(pkg->id, pkg->source_id, &error)) {
        char inst_buf[256];
        std::snprintf(inst_buf, sizeof(inst_buf), locale::tr("plugins.installed"), pkg->name.c_str());
        set_status(state, inst_buf);
        push_notification(state, inst_buf);
      } else {
        set_status(state, error);
      }
    }
  } else {
    const float action_w = ImGui::GetContentRegionAvail().x;
    const bool inline_actions = action_w >= 370.0f * scl;
    const float button_w = inline_actions
        ? (action_w - 12.0f * scl) / 3.0f
        : action_w;
    if (ui::primary_button((std::string(icons::kPlay) + "  Run").c_str(),
                           ImVec2(button_w, 34.0f * scl))) {
      start_run(state, *pkg);
    }
    if (inline_actions) ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kRefresh) + "  Update").c_str(),
                        ImVec2(button_w, 34.0f * scl))) {
      std::string error;
      if (state.plugin_manager.install_package(pkg->id, pkg->source_id, &error)) {
        char upd_buf[256];
        std::snprintf(upd_buf, sizeof(upd_buf), locale::tr("plugins.updated"), pkg->name.c_str());
        set_status(state, upd_buf);
        push_notification(state, upd_buf);
      } else {
        set_status(state, error);
      }
    }
    if (inline_actions) ImGui::SameLine();
    if (ui::danger_button((std::string(icons::kTrash) + "  Remove").c_str(),
                          ImVec2(button_w, 34.0f * scl))) {
      std::string error;
      if (state.plugin_manager.uninstall_package(pkg->id, &error)) {
        char rem_buf[256];
        std::snprintf(rem_buf, sizeof(rem_buf), locale::tr("plugins.removed"), pkg->name.c_str());
        set_status(state, rem_buf);
      } else {
        set_status(state, error);
      }
    }

    bool enabled = pkg->enabled;
    if (ImGui::Checkbox("Enabled", &enabled)) {
      std::string error;
      if (!state.plugin_manager.set_package_enabled(pkg->id, enabled, &error))
        set_status(state, error);
    }
  }
  ImGui::EndDisabled();

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", "Full information");
  if (ImGui::BeginTable("PluginInfoTable", 2,
                        ImGuiTableFlags_SizingStretchProp |
                            ImGuiTableFlags_RowBg)) {
    ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 96.0f * scl);
    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    draw_info_row("ID", pkg->id);
    draw_info_row("Source", pkg->source_name);
    draw_info_row("Entry", pkg->entry);
    draw_info_row("Tags", tags_text(pkg->tags));
    draw_info_row("Permissions", permissions_text(pkg->permissions));
    draw_info_row("License", pkg->license);
    draw_info_row("Min MemDBG", pkg->min_memdbg_version);
    draw_info_row("Image", pkg->icon_url, true);
    draw_info_row("Homepage", pkg->homepage, true);
    draw_info_row("Repository", pkg->repository, true);
    if (pkg->installed) draw_info_row("Installed at", pkg->installed_path.string(), true);
    ImGui::EndTable();
  }

  if (!pkg->homepage.empty() || !pkg->repository.empty()) {
    ImGui::Spacing();
    const std::string link = !pkg->homepage.empty() ? pkg->homepage : pkg->repository;
    if (ui::soft_button((std::string(icons::kLink) + "  Open project").c_str(),
                        ImVec2(std::min(170.0f * scl, ImGui::GetContentRegionAvail().x),
                               30.0f * scl))) {
      if (!platform::open_url(link)) set_status(state, locale::tr("plugins.cannot_open_url"));
    }
  }
}

void draw_output(AppState &state) {
  const bool has_output = state.plugin_run_pending ||
                          !state.plugin_last_error.empty() ||
                          !state.plugin_last_id.empty() ||
                          !state.plugin_last_command.empty() ||
                          !state.plugin_last_output.empty();
  if (!has_output) return;

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Runtime output");
  if (state.plugin_run_pending) {
    ui::draw_scan_progress("Plugin script", icons::kTerminal,
                           ImGui::GetTime() - state.plugin_run_start_time,
                           ImGui::GetContentRegionAvail().x);
    return;
  }

  if (!state.plugin_last_error.empty()) {
    ImGui::TextColored(ui::colors().danger, "%s", state.plugin_last_error.c_str());
  } else if (!state.plugin_last_id.empty()) {
    ImGui::TextColored(ui::colors().success, "Last run: %s", state.plugin_last_id.c_str());
  } else {
    ImGui::TextColored(ui::colors().dim, "No plugin has run in this session.");
  }

  if (!state.plugin_last_command.empty()) {
    ImGui::TextColored(ui::colors().dim, "%s", state.plugin_last_command.c_str());
  }

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::BeginChild("PluginOutputText", ImVec2(0, 150.0f * ui::dpi_scale()), true);
  if (state.plugin_last_output.empty()) {
    ImGui::TextColored(ui::colors().dim, "Output will appear here.");
  } else {
    ImGui::TextUnformatted(state.plugin_last_output.c_str());
  }
  ImGui::EndChild();
  ImGui::PopStyleColor();
}

} // namespace

void poll_plugin_tasks(AppState &state) {
  if (state.plugin_refresh_pending && state.plugin_refresh_future.valid()) {
    auto status = state.plugin_refresh_future.wait_for(std::chrono::milliseconds(0));
    if (status == std::future_status::ready) {
      bool ok = false;
      try {
        ok = state.plugin_refresh_future.get();
      } catch (const std::exception &ex) {
        state.plugin_refresh_error = ex.what();
      } catch (...) {
        state.plugin_refresh_error = "Unknown plugin refresh error";
      }
      state.plugin_refresh_pending = false;
      if (ok) {
        set_status(state, locale::tr("plugins.sources_refreshed"));
        push_notification(state, locale::tr("plugins.sources_refreshed"));
      } else {
        const std::string error = state.plugin_refresh_error.empty()
            ? "Plugin source refresh failed"
            : state.plugin_refresh_error;
        set_status(state, error);
        push_notification(state, error, 5.0);
      }
    }
  }

  if (state.plugin_run_pending && state.plugin_run_future.valid()) {
    auto status = state.plugin_run_future.wait_for(std::chrono::milliseconds(0));
    if (status == std::future_status::ready) {
      plugins::PluginRunResult result;
      try {
        result = state.plugin_run_future.get();
      } catch (const std::exception &ex) {
        result.error = ex.what();
      } catch (...) {
        result.error = "Unknown plugin runtime error";
      }
      state.plugin_run_pending = false;
      state.plugin_last_id = result.plugin_id;
      state.plugin_last_output = result.output;
      state.plugin_last_error = result.error;
      state.plugin_last_command = result.command;
      if (result.ok) {
        char comp_buf[256];
        std::snprintf(comp_buf, sizeof(comp_buf), locale::tr("plugins.completed"), result.plugin_id.c_str());
        set_status(state, comp_buf);
        push_notification(state, comp_buf);
      } else {
        const std::string error = result.error.empty()
            ? "Plugin failed: " + result.plugin_id
            : result.error;
        set_status(state, error);
        push_notification(state, error, 5.0);
      }
    }
  }
}

void draw_plugins(AppState &state, ImVec2 avail) {
  poll_plugin_tasks(state);
  if (avail.x <= 0.0f || avail.y <= 0.0f) return;

  const float scl = ui::dpi_scale();
  const float gap = 12.0f * scl;
  const float layout_scl = 1.0f;
  const float min_left_w = 500.0f * layout_scl;
  const float min_right_w = 420.0f * layout_scl;
  const bool stacked = avail.x < (min_left_w + min_right_w + gap);
  const float max_left_w = std::max(260.0f * layout_scl, avail.x - min_right_w - gap);
  const float left_w = stacked ? avail.x
      : clamp_layout((avail.x - gap) * 0.60f, min_left_w, max_left_w);
  const float right_w = stacked ? avail.x : std::max(260.0f * layout_scl, avail.x - left_w - gap);
  const float left_h = stacked
      ? clamp_layout(avail.y * 0.58f, 340.0f * layout_scl,
                     std::max(340.0f * layout_scl, avail.y - 250.0f * layout_scl - gap))
      : avail.y;
  const float right_h = stacked ? std::max(230.0f * layout_scl, avail.y - left_h - gap)
                                : avail.y;

  std::vector<PluginSource> sources = state.plugin_manager.sources();
  std::vector<PluginPackage> catalog = filtered_catalog(state, sources);
  const PluginPackage *selected = nullptr;
  if (state.plugin_selected_row >= 0 &&
      state.plugin_selected_row < static_cast<int>(catalog.size())) {
    selected = &catalog[static_cast<size_t>(state.plugin_selected_row)];
  }

  draw_add_source_modal(state);
  ImGui::BeginChild("PluginManagerPage", avail, false);

  ui::begin_panel("PluginCommunityCatalog", "Plugins", ImVec2(left_w, left_h));
  draw_catalog_toolbar(state, sources);
  draw_catalog(state, catalog);
  ui::end_panel();

  if (!stacked) ImGui::SameLine(0, gap);
  ui::begin_panel("PluginDetailsPanel", "Plugin Details", ImVec2(right_w, right_h));
  ImGui::BeginChild("PluginDetailsScroll", ImVec2(0, 0), false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  draw_package_details(state, selected);
  draw_output(state);
  ImGui::EndChild();
  ui::end_panel();

  ImGui::EndChild();
}

} // namespace memdbg::frontend

/*
 * MemDBG - Mobile plugin management UI.
 */
#include "../internal.hpp"
namespace memdbg::frontend {

plugins::PluginRunContext mobile_build_plugin_context(
    const AppState &state) {
  plugins::PluginRunContext context;
  context.host = state.host;
  context.debug_port = state.debug_port;
  context.udp_port = state.udp_port;
  context.connected = state.client.connected();
  context.selected_pid = state.selected_pid;
  context.selected_process_name = selected_process_name(state);
  context.dump_path = state.mem.dump_path;
  context.trainer_file_path = state.plugin.trainer_file_path;
  context.protocol_version = state.has_hello ? state.hello.protocol_version : 0U;
  context.capabilities = state.has_hello ? state.hello.capabilities : 0U;
  context.map_count = state.maps.size();
  context.scan_hit_count = state.scan.result.addresses.size();
  context.trainer_entry_count = state.plugin.cheats.size();
  // Sandbox settings
  context.sandbox_enabled = state.sandbox_enabled;
  context.sandbox_filesystem = state.sandbox_filesystem;
  context.sandbox_subprocess = state.sandbox_subprocess;
  context.sandbox_network = state.sandbox_network;
  context.sandbox_native_modules = state.sandbox_native_modules;
  std::snprintf(context.sandbox_require_whitelist, sizeof(context.sandbox_require_whitelist),
                "%s", state.sandbox_require_whitelist);
  return context;
}

void mobile_start_plugin_refresh(AppState &state) {
  if (state.plugin.refresh_pending || state.plugin.run_pending) return;
  if (state.plugin.refresh_future.valid()) state.plugin.refresh_future.wait();
  state.plugin.refresh_error.clear();
  state.plugin.refresh_pending = true;
  set_status(state, "Refreshing plugin sources...");
  state.plugin.refresh_future = std::async(std::launch::async,
      [&state]() -> bool {
        std::string error;
        const bool ok = state.plugin_manager.refresh_all(&error);
        state.plugin.refresh_error = error;
        return ok;
      });
}

void mobile_start_plugin_run(AppState &state,
                                    const plugins::PluginPackage &package) {
  if (!package.installed || state.plugin.refresh_pending ||
      state.plugin.run_pending) {
    return;
  }
  if (state.plugin.run_future.valid()) state.plugin.run_future.wait();
  const auto context = mobile_build_plugin_context(state);
  const std::string package_id = package.id;
  state.plugin.last_output.clear();
  state.plugin.last_error.clear();
  state.plugin.last_command.clear();
  state.plugin.last_id = package_id;
  state.plugin.run_pending = true;
  state.plugin.run_start_time = ImGui::GetTime();
  set_status(state, "Running plugin " + package.name + "...");
  state.plugin.run_future = std::async(std::launch::async,
      [&state, package_id, context]() {
        return state.plugin_manager.run_plugin(package_id, context);
      });
}

std::string mobile_plugin_tags_text(
    const std::vector<std::string> &tags) {
  std::string out;
  for (const auto &tag : tags) {
    if (!out.empty()) out += ", ";
    out += tag;
  }
  return out;
}

bool mobile_contains_ci(const std::string &haystack,
                               const std::string &needle) {
  if (needle.empty()) return true;
  auto lower = [](std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                     return static_cast<char>(std::tolower(c));
                   });
    return value;
  };
  return lower(haystack).find(lower(needle)) != std::string::npos;
}

std::vector<plugins::PluginPackage> mobile_filtered_plugins(
    AppState &state, const std::vector<plugins::PluginSource> &sources) {
  if (state.plugin.source_filter < 0 ||
      state.plugin.source_filter > static_cast<int>(sources.size())) {
    state.plugin.source_filter = 0;
  }

  std::vector<plugins::PluginPackage> catalog = state.plugin_manager.catalog();
  if (state.plugin.source_filter > 0) {
    const auto &source = sources[static_cast<size_t>(
        state.plugin.source_filter - 1)];
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const plugins::PluginPackage &pkg) {
          return pkg.source_id != source.id;
        }), catalog.end());
  }

  const std::string filter = state.plugin.filter;
  if (!filter.empty()) {
    catalog.erase(std::remove_if(catalog.begin(), catalog.end(),
        [&](const plugins::PluginPackage &pkg) {
          return !mobile_contains_ci(pkg.name, filter) &&
                 !mobile_contains_ci(pkg.author, filter) &&
                 !mobile_contains_ci(pkg.id, filter) &&
                 !mobile_contains_ci(pkg.source_name, filter) &&
                 !mobile_contains_ci(pkg.short_description, filter) &&
                 !mobile_contains_ci(pkg.description, filter) &&
                 !mobile_contains_ci(mobile_plugin_tags_text(pkg.tags), filter);
        }), catalog.end());
  }

  std::sort(catalog.begin(), catalog.end(),
      [](const plugins::PluginPackage &a,
         const plugins::PluginPackage &b) {
        if (a.installed != b.installed) return a.installed > b.installed;
        if (a.enabled != b.enabled) return a.enabled > b.enabled;
        if (a.language != b.language)
          return static_cast<int>(a.language) > static_cast<int>(b.language);
        return a.name < b.name;
      });
  return catalog;
}

std::string mobile_plugin_description(
    const plugins::PluginPackage &package) {
  if (!package.short_description.empty()) return package.short_description;
  if (!package.description.empty()) return package.description;
  return "No description provided.";
}

void draw_mobile_plugin_source_popup(AppState &state) {
  const float scl = ui::dpi_scale();
  if (state.plugin.add_source_modal_open)
    ImGui::OpenPopup("MobileAddPluginSource");

  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowSize(
      ImVec2(std::min(430.0f * scl, viewport->WorkSize.x - 24.0f * scl), 0),
      ImGuiCond_Appearing);
  bool open = state.plugin.add_source_modal_open;
  if (ImGui::BeginPopupModal("MobileAddPluginSource", &open,
                             ImGuiWindowFlags_NoResize)) {
    ImGui::TextColored(ui::colors().primary2, "%s", "Add Plugin Source");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("Name##MobilePluginSourceName",
                     state.plugin.source_name,
                     sizeof(state.plugin.source_name));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("Manifest URL##MobilePluginSourceUrl",
                     state.plugin.source_url,
                     sizeof(state.plugin.source_url));
    ImGui::BeginDisabled(state.plugin.refresh_pending ||
                         state.plugin.run_pending);
    if (ui::primary_button((std::string(icons::kAdd) + "  Add").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  40.0f * scl))) {
      std::string error;
      if (state.plugin_manager.add_source(state.plugin.source_name,
                                          state.plugin.source_url, &error)) {
        std::snprintf(state.plugin.source_name,
                      sizeof(state.plugin.source_name), "%s",
                      "Community Repository");
        state.plugin.source_url[0] = '\0';
        state.plugin.add_source_modal_open = false;
        mobile_start_plugin_refresh(state);
        ImGui::CloseCurrentPopup();
      } else {
        set_status(state, error);
      }
    }
    ImGui::EndDisabled();
    if (ui::soft_button("Cancel",
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               38.0f * scl))) {
      state.plugin.add_source_modal_open = false;
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }
  if (!open) state.plugin.add_source_modal_open = false;
}

void draw_mobile_plugin_output(AppState &state) {
  const bool has_output = state.plugin.run_pending ||
                          !state.plugin.last_error.empty() ||
                          !state.plugin.last_id.empty() ||
                          !state.plugin.last_command.empty() ||
                          !state.plugin.last_output.empty();
  if (!has_output) return;

  const float scl = ui::dpi_scale();
  draw_mobile_section_label("Runtime output");
  if (state.plugin.run_pending) {
    ui::draw_scan_progress("Plugin script", icons::kTerminal,
                           ImGui::GetTime() - state.plugin.run_start_time,
                           ImGui::GetContentRegionAvail().x);
    return;
  }

  if (!state.plugin.last_error.empty()) {
    ImGui::TextColored(ui::colors().danger, "%s",
                       state.plugin.last_error.c_str());
  } else {
    ImGui::TextColored(ui::colors().success, "Last run: %s",
                       state.plugin.last_id.c_str());
  }
  if (!state.plugin.last_command.empty()) {
    text_ellipsis(state.plugin.last_command.c_str(),
                  ImGui::GetContentRegionAvail().x, ui::colors().dim);
  }

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::BeginChild("MobilePluginOutputText", ImVec2(0, 150.0f * scl),
                    true);
  if (state.plugin.last_output.empty())
    ImGui::TextColored(ui::colors().dim, "%s", "Output will appear here.");
  else
    ImGui::TextUnformatted(state.plugin.last_output.c_str());
  ImGui::EndChild();
  ImGui::PopStyleColor();
}

void draw_mobile_plugin_details(AppState &state,
                                       const plugins::PluginPackage &package) {
  const float scl = ui::dpi_scale();
  const bool ios_python =
#if defined(MEMDBG_PLATFORM_IOS)
      package.language == plugins::PluginLanguage::Python;
#else
      false;
#endif
  const bool runnable = package.installed && package.enabled && !ios_python;
  const float gap = 6.0f * scl;
  const float two_col = (ImGui::GetContentRegionAvail().x - gap) * 0.5f;

  ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                         ImGui::GetContentRegionAvail().x);
  ImGui::TextWrapped("%s", mobile_plugin_description(package).c_str());
  ImGui::PopTextWrapPos();
  ImGui::TextColored(ui::colors().dim, "%s  %s  %s",
                     plugins::language_name(package.language),
                     package.version.c_str(), package.source_name.c_str());

  ImGui::BeginDisabled(state.plugin.refresh_pending ||
                       state.plugin.run_pending);
  if (!package.installed) {
    if (ui::primary_button((std::string(icons::kDump) + "  Install").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  40.0f * scl))) {
      std::string error;
      if (state.plugin_manager.install_package(package.id,
                                               package.source_id, &error)) {
        set_status(state, "Plugin installed: " + package.name);
        push_notification(state, "Plugin installed: " + package.name);
      } else {
        set_status(state, error);
      }
    }
  } else {
    ImGui::BeginDisabled(!runnable);
    if (ui::primary_button((std::string(icons::kPlay) + "  Run").c_str(),
                           ImVec2(ImGui::GetContentRegionAvail().x,
                                  40.0f * scl))) {
      mobile_start_plugin_run(state, package);
    }
    ImGui::EndDisabled();
    if (ios_python) {
      ImGui::TextColored(ui::colors().warning, "%s",
                         "Python plugins are desktop-only on iOS.");
    }

    if (ui::soft_button((std::string(icons::kRefresh) + "  Update").c_str(),
                        ImVec2(two_col, 38.0f * scl))) {
      std::string error;
      if (state.plugin_manager.install_package(package.id,
                                               package.source_id, &error)) {
        set_status(state, "Plugin updated: " + package.name);
      } else {
        set_status(state, error);
      }
    }
    ImGui::SameLine(0, gap);
    if (ui::danger_button((std::string(icons::kTrash) + "  Remove").c_str(),
                          ImVec2(two_col, 38.0f * scl))) {
      std::string error;
      if (state.plugin_manager.uninstall_package(package.id, &error))
        set_status(state, "Plugin removed: " + package.name);
      else
        set_status(state, error);
    }

    bool enabled = package.enabled;
    if (ImGui::Checkbox("Enabled##MobilePluginEnabled", &enabled)) {
      std::string error;
      if (!state.plugin_manager.set_package_enabled(package.id, enabled,
                                                    &error)) {
        set_status(state, error);
      }
    }
  }
  ImGui::EndDisabled();

  if (!package.tags.empty()) {
    const std::string tags = mobile_plugin_tags_text(package.tags);
    text_ellipsis(tags.c_str(),
                  ImGui::GetContentRegionAvail().x, ui::colors().dim);
  }
}

void draw_mobile_plugin_card(AppState &state,
                                    const plugins::PluginPackage &package,
                                    int index) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool selected = state.plugin.selected_row == index;
  const ImVec2 pos = ImGui::GetCursorScreenPos();
  const ImVec2 size(ImGui::GetContentRegionAvail().x, 76.0f * scl);
  ImGui::PushID(package.id.c_str());
  ImGui::InvisibleButton("##MobilePluginCard", size);
  if (ImGui::IsItemClicked()) {
    state.plugin.selected_row = selected ? -1 : index;
    state.plugin.description_expanded = false;
  }

  ImDrawList *draw = ImGui::GetWindowDrawList();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  const ImVec4 bg = selected ? ImVec4(0.06f, 0.22f, 0.17f, 1.0f)
      : ImGui::IsItemHovered() ? ImVec4(0.12f, 0.16f, 0.15f, 1.0f)
                               : palette.bg1;
  draw->AddRectFilled(pos, max, ui::color_u32(bg), 7.0f * scl);
  draw->AddRect(pos, max,
                ui::color_u32(selected ? palette.primary2 : palette.border),
                7.0f * scl, 0, 1.0f * scl);

  const char *language = plugins::language_name(package.language);
  const char *state_text = package.installed
      ? (package.enabled ? "Installed" : "Disabled")
      : "Available";
  const ImVec2 badge_min(pos.x + 10.0f * scl, pos.y + 12.0f * scl);
  const ImVec2 badge_max(badge_min.x + 46.0f * scl,
                         badge_min.y + 28.0f * scl);
  draw->AddRectFilled(badge_min, badge_max,
                      ui::color_u32(package.language == plugins::PluginLanguage::Lua
                                        ? ImVec4(0.16f, 0.18f, 0.34f, 1.0f)
                                        : ImVec4(0.14f, 0.24f, 0.32f, 1.0f)),
                      5.0f * scl);
  draw->AddText(ImVec2(badge_min.x + 7.0f * scl, badge_min.y + 6.0f * scl),
                ui::color_u32(palette.text), language);

  const float text_x = pos.x + 66.0f * scl;
  draw->PushClipRect(ImVec2(text_x, pos.y + 8.0f * scl),
                     ImVec2(max.x - 10.0f * scl, max.y - 8.0f * scl), true);
  draw->AddText(ImVec2(text_x, pos.y + 10.0f * scl),
                ui::color_u32(palette.text), package.name.c_str());
  const std::string meta = std::string(state_text) + "  |  " +
      (package.author.empty() ? "Unknown creator" : package.author);
  draw->AddText(ImVec2(text_x, pos.y + 31.0f * scl),
                ui::color_u32(package.installed ? palette.success :
                              palette.muted), meta.c_str());
  const std::string desc = mobile_plugin_description(package);
  draw->AddText(ImVec2(text_x, pos.y + 52.0f * scl),
                ui::color_u32(palette.dim), desc.c_str());
  draw->PopClipRect();

  ImGui::PopID();

  if (selected) {
    ImGui::Indent(8.0f * scl);
    draw_mobile_plugin_details(state, package);
    ImGui::Unindent(8.0f * scl);
  }
  ImGui::Spacing();
}

void draw_mobile_plugins(AppState &state, ImVec2 size) {
  poll_plugin_tasks(state);
  const float scl = ui::dpi_scale();

  draw_mobile_plugin_source_popup(state);
  ImGui::BeginChild("MobilePlugins", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(ui::colors().primary2, "%s", "Plugins");
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%s",
                     state.plugin.run_pending ? "Running" :
                     state.plugin.refresh_pending ? "Refreshing" :
                     "Ready");

  std::vector<plugins::PluginSource> sources = state.plugin_manager.sources();
  std::vector<plugins::PluginPackage> catalog =
      mobile_filtered_plugins(state, sources);
  if (state.plugin.selected_row >= static_cast<int>(catalog.size()))
    state.plugin.selected_row = catalog.empty() ? -1 : 0;

  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("##MobilePluginSearch", "Search plugins...",
                           state.plugin.filter, sizeof(state.plugin.filter));

  const float gap = 6.0f * scl;
  const float button_w = (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f;
  ImGui::BeginDisabled(state.plugin.refresh_pending ||
                       state.plugin.run_pending);
  if (ui::soft_button((std::string(icons::kRefresh) + " Sync").c_str(),
                      ImVec2(button_w, 38.0f * scl))) {
    mobile_start_plugin_refresh(state);
  }
  ImGui::SameLine(0, gap);
  if (ui::primary_button((std::string(icons::kAdd) + " Source").c_str(),
                         ImVec2(button_w, 38.0f * scl))) {
    state.plugin.add_source_modal_open = true;
  }
  ImGui::SameLine(0, gap);
  if (ui::soft_button((std::string(icons::kSettings) + " GUI").c_str(),
                      ImVec2(button_w, 38.0f * scl))) {
    state.screen = Screen::PluginGUI;
    set_status(state, "GUI plugins use the desktop bridge on this build.");
  }
  ImGui::EndDisabled();

  if (!sources.empty()) {
    const char *preview = "All sources";
    std::string preview_label;
    if (state.plugin.source_filter > 0) {
      preview_label = sources[static_cast<size_t>(
          state.plugin.source_filter - 1)].name;
      preview = preview_label.c_str();
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("Source##MobilePluginSourceFilter", preview)) {
      if (ImGui::Selectable("All sources", state.plugin.source_filter == 0))
        state.plugin.source_filter = 0;
      for (size_t i = 0; i < sources.size(); ++i) {
        const bool selected =
            state.plugin.source_filter == static_cast<int>(i + 1U);
        if (ImGui::Selectable(sources[i].name.c_str(), selected))
          state.plugin.source_filter = static_cast<int>(i + 1U);
        if (selected) ImGui::SetItemDefaultFocus();
      }
      ImGui::EndCombo();
    }
  }

  draw_mobile_plugin_output(state);
  draw_mobile_section_label("Catalog");
  if (catalog.empty()) {
    ui::draw_empty_state("No plugins found",
                         "Refresh sources or change the search.");
  } else {
    for (size_t i = 0; i < catalog.size(); ++i) {
      draw_mobile_plugin_card(state, catalog[i], static_cast<int>(i));
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}


} // namespace memdbg::frontend

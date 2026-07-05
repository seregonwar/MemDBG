/*
 * MemDBG - Plugin GUI screen (renders Python plugin ImGui UIs).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "plugins/repository/gui_bridge.hpp"
#include "plugins/repository/plugin_manager.hpp"

#include <filesystem>
#include <fstream>
#include <string>

namespace memdbg::frontend {

namespace {

std::string find_python_interpreter() {
#if defined(_WIN32)
  const std::string check = "where python3 >NUL 2>NUL || where python >NUL 2>NUL";
#else
  const std::string check = "command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1";
#endif
  /* Try common candidates */
  static const char *candidates[] = {"python3", "python", "/usr/bin/python3", "/usr/local/bin/python3"};
  for (const auto *cand : candidates) {
    std::filesystem::path path(cand);
    if (std::filesystem::exists(path)) return cand;
  }
  return "python3";
}

} // namespace


void draw_plugin_gui(AppState &state, ImVec2 avail) {
  if (state.plugin_gui_active_id.empty()) {
    ImGui::BeginChild("PluginGUIPlaceholder", avail, false);
    ui::draw_empty_state("No Plugin Selected",
                         "Choose a GUI plugin from the sidebar Plugin Apps launcher.");
    ImGui::EndChild();
    return;
  }

  /* Start the GUI bridge if not already running */
  if ((!state.plugin_gui_bridge || !state.plugin_gui_bridge->running()) && !state.plugin_gui_starting) {
    state.plugin_gui_starting = true;
    state.plugin_gui_error.clear();

    /* Find the installed plugin */
    auto installed = state.plugin_manager.catalog();
    std::string entry_path;
    std::string plugin_name;
    for (const auto &pkg : installed) {
      if (pkg.id == state.plugin_gui_active_id && pkg.installed) {
        entry_path = (pkg.installed_path / pkg.entry).string();
        plugin_name = pkg.name;
        break;
      }
    }

    if (entry_path.empty()) {
      state.plugin_gui_error = "Plugin not found or not installed: " + state.plugin_gui_active_id;
      state.plugin_gui_starting = false;
      state.plugin_gui_active_id.clear();
      return;
    }

    /* Build context file */
    std::filesystem::path runtime_dir =
        state.plugin_manager.plugin_data_dir() / "runtime";
    std::error_code ec;
    std::filesystem::create_directories(runtime_dir, ec);

    std::string context_path = (runtime_dir /
        (state.plugin_gui_active_id + "-context.json")).string();

    /* Write the context JSON */
    {
      nlohmann::json doc;
      doc["memdbg"]["frontend"] = "MemDBG";
      doc["memdbg"]["protocol_version"] = state.has_hello ? state.hello.protocol_version : 0U;
      doc["memdbg"]["capabilities"] = state.has_hello ? state.hello.capabilities : 0U;
      doc["console"]["host"] = state.host;
      doc["console"]["debug_port"] = state.debug_port;
      doc["console"]["udp_port"] = state.udp_port;
      doc["console"]["connected"] = state.client.connected();
      doc["process"]["pid"] = state.selected_pid;
      doc["process"]["name"] = selected_process_name(state);
      doc["paths"]["dump"] = state.dump_path;
      doc["paths"]["trainer"] = state.trainer_file_path;
      doc["paths"]["plugin"] = std::filesystem::path(entry_path).parent_path().string();

      /* Plugin config directory */
      std::filesystem::path config_dir =
          std::filesystem::path(entry_path).parent_path() / "config";
      std::filesystem::create_directories(config_dir, ec);
      doc["paths"]["config"] = config_dir.string();

      doc["state"]["map_count"] = state.maps.size();
      doc["state"]["scan_hit_count"] = state.scan_result.addresses.size();
      doc["state"]["trainer_entry_count"] = state.cheats.size();

      std::ofstream out(context_path, std::ios::binary | std::ios::trunc);
      if (!out) {
        state.plugin_gui_error = "Cannot write context file for GUI plugin";
        state.plugin_gui_starting = false;
        return;
      }
      out << doc.dump(2) << "\n";
    }

    /* Find Python interpreter */
    std::string python_exe = find_python_interpreter();

    /* Start the bridge */
    state.plugin_gui_bridge = std::make_shared<plugins::GuiBridge>();
    if (!state.plugin_gui_bridge->start(python_exe, entry_path, context_path)) {
      state.plugin_gui_error = "Failed to start GUI plugin process for " + plugin_name;
      state.plugin_gui_starting = false;
      state.plugin_gui_active_id.clear();
      set_status(state, state.plugin_gui_error);
      return;
    }

    state.plugin_gui_starting = false;
    char gui_buf[256];
    std::snprintf(gui_buf, sizeof(gui_buf), locale::tr("plugins.gui_started"), plugin_name.c_str());
    set_status(state, gui_buf);
    push_notification(state, gui_buf);
  }

  /* Render the plugin UI */
  if (state.plugin_gui_bridge) {
    state.plugin_gui_bridge->begin_frame();

    if (state.plugin_gui_bridge->running()) {
      ImGui::BeginChild("PluginGUIContent", avail, false);
      if (state.plugin_gui_bridge->has_active_tree()) {
        state.plugin_gui_bridge->render_widgets();
      } else {
        ui::draw_empty_state("Loading plugin UI...",
                             "Waiting for the Python plugin to send its widget tree.");
      }

      /* Always show stderr diagnostics if present (debug footer) */
      std::string err = state.plugin_gui_bridge->stderr_text();
      if (!err.empty()) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::PushStyleColor(ImGuiCol_Text, ui::colors().warning);
        ImGui::TextWrapped("Python stderr:\n%s", err.c_str());
        if (ImGui::IsItemClicked()) {
          ImGui::SetClipboardText(err.c_str());
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("Click to copy to clipboard");
        }
        ImGui::PopStyleColor();
      }

      /* Always show C++ bridge diagnostics if non-trivial */
      std::string diag = state.plugin_gui_bridge->debug_info();
      if (!diag.empty() && diag.find("Active tree widgets: 0") == std::string::npos) {
        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Text, ui::colors().dim);
        ImGui::TextWrapped("%s", diag.c_str());
        if (ImGui::IsItemClicked()) {
          ImGui::SetClipboardText(diag.c_str());
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("Click to copy diagnostics to clipboard");
        }
        ImGui::PopStyleColor();
      }

      ImGui::EndChild();
      state.plugin_gui_bridge->end_frame();
    }
  }

  /* Show error if present */
  if (!state.plugin_gui_error.empty()) {
    ImGui::TextColored(ui::colors().danger, "%s", state.plugin_gui_error.c_str());
  }
}

} // namespace memdbg::frontend

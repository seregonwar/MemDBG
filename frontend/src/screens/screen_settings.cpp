/*
 * MemDBG - Settings screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "file_picker.hpp"
#include "confirm_modal.hpp"
#include "locale/locale_repository.hpp"

#include <algorithm>
#include <cstdio>
#include <string>

namespace memdbg::frontend {

void draw_settings(AppState &state, ImVec2 avail) {
  ensure_console_targets(state);
  const float gap = 16.0f;
  const float col_w = (avail.x - gap) * 0.5f;

  ui::begin_panel("SettingsConnection", locale::tr("settings.connection_defaults"), ImVec2(col_w, avail.y));
  ImGui::InputText("Target name", state.target_name, sizeof(state.target_name));
  ImGui::InputText(locale::tr("settings.console_ipv4"), state.host, sizeof(state.host));
  ImGui::InputInt(locale::tr("settings.debug_tcp"), &state.debug_port);
  ImGui::InputInt(locale::tr("settings.udp_logs"), &state.udp_port);
  ImGui::InputText(locale::tr("settings.dump_path"), state.dump_path, sizeof(state.dump_path));
  ImGui::SameLine();
  if (ImGui::SmallButton((std::string(icons::kLoad) + "##dumppath").c_str())) {
    std::string picked = memdbg::frontend::ui::pickFile(locale::tr("file_picker.select_dump_dir"));
    if (!picked.empty())
      std::snprintf(state.dump_path, sizeof(state.dump_path), "%s", picked.c_str());
  }
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("settings.browse_dump_dir"));
  normalize_ports(state);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

  // Crash logging toggle
  if (ImGui::Checkbox(locale::tr("settings.crash_logging"), &state.crash_logging_enabled)) {
    state.crash_logger.set_enabled(state.crash_logging_enabled);
    set_status(state, state.crash_logging_enabled
        ? locale::tr("settings.crash_logging_on")
        : locale::tr("settings.crash_logging_off"));
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.crash_logging_hint"));

  ImGui::Spacing();

  if (ImGui::Checkbox(locale::tr("settings.taskmgr_prefetch_on_connect"),
                      &state.taskmgr_prefetch_on_connect)) {
    set_status(state, state.taskmgr_prefetch_on_connect
        ? locale::tr("settings.taskmgr_prefetch_on")
        : locale::tr("settings.taskmgr_prefetch_off"));
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.taskmgr_prefetch_hint"));

  ImGui::Spacing();

  // Language selector
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.language"));
  ImGui::Spacing();
  {
    auto &mgr = locale::Manager::instance();
    auto &repo = locale::Repository::instance();
    locale::Lang active_lang = mgr.active();
    if (state.pending_language >= 0 &&
        state.pending_language < static_cast<int>(locale::Lang::COUNT)) {
      active_lang = static_cast<locale::Lang>(state.pending_language);
    }
    const auto languages = repo.languages();
    auto active_info = std::find_if(languages.begin(), languages.end(),
                                    [active_lang](const locale::RepositoryLanguage &info) {
                                      return info.lang == active_lang;
                                    });
    const char *active_name = active_info != languages.end()
                                  ? active_info->name.c_str()
                                  : locale::lang_name(active_lang);
    int active_pct = mgr.translation_progress(active_lang);
    char preview_buf[128];
    if (state.pending_language >= 0) {
      std::snprintf(preview_buf, sizeof(preview_buf), "%s - %s",
                    active_name, locale::tr("settings.language_downloading"));
    } else {
      std::snprintf(preview_buf, sizeof(preview_buf), "%s (%d%%)",
                    active_name, active_pct);
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##LangCombo", preview_buf)) {
      (void)repo.request_manifest();
      for (const auto &info : languages) {
        locale::Lang lang = info.lang;
        const int lang_index = static_cast<int>(lang);
        const bool loaded = mgr.is_loaded(lang);
        const bool selected = state.language == lang_index ||
                              state.pending_language == lang_index;
        const int pct = mgr.translation_progress(lang);
        char label[128];
        if (loaded) {
          std::snprintf(label, sizeof(label), "%s (%d%%)", info.name.c_str(), pct);
        } else if (state.pending_language == lang_index) {
          std::snprintf(label, sizeof(label), "%s - %s", info.name.c_str(),
                        locale::tr("settings.language_downloading"));
        } else {
          std::snprintf(label, sizeof(label), "%s - %s", info.name.c_str(),
                        locale::tr("settings.language_download"));
        }
        if (ImGui::Selectable(label, selected)) {
          if (loaded) {
            state.language = lang_index;
            state.pending_language = -1;
            mgr.set_active(lang);
            set_status(state, std::string(locale::tr("settings.language")) + ": " + label);
          } else if (repo.request_download(lang)) {
            state.pending_language = lang_index;
            set_status(state, std::string(locale::tr("settings.language_downloading")) +
                              ": " + info.name);
          } else {
            const std::string status = repo.status();
            set_status(state, status.empty()
                                  ? locale::tr("settings.language_busy")
                                  : status);
          }
        }
        if (selected) ImGui::SetItemDefaultFocus();
      }
      ImGui::EndCombo();
    }
    if (repo.busy()) {
      ImGui::TextColored(ui::colors().muted, "%s",
                         locale::tr("settings.language_checking"));
    } else if (!repo.error().empty()) {
      ImGui::TextColored(ui::colors().warning, "%s", repo.error().c_str());
    } else if (repo.manifest_ready()) {
      ImGui::TextColored(ui::colors().muted, "%s",
                         locale::tr("settings.language_repository_ready"));
    }
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.language_hint"));

  ImGui::Spacing();
  if (ui::primary_button((std::string(icons::kSave) + "  " + locale::tr("settings.save_defaults")).c_str(), ui::full_button(40))) {
    save_current_console_target(state);
    std::string error;
    if (save_frontend_settings(state, &error)) {
      set_status(state, locale::tr("settings.saved"));
      push_notification(state, std::string(locale::tr("notify.settings_saved")));
    } else {
      set_status(state, error);
      char buf[512];
      std::snprintf(buf, sizeof(buf), locale::tr("notify.settings_save_failed"), error.c_str());
      push_notification(state, buf, 5.0);
    }
  }
  if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("settings.apply_udp")).c_str(), ui::full_button(40))) {
    state.udp_listener.stop();
    std::string error;
    if (ensure_udp_listener(state, error)) set_status(state, locale::tr("settings.udp_applied"));
    else set_status(state, error);
  }
  static bool skip_reset_defaults = false;
  if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("settings.reset_defaults")).c_str(), ui::full_button(40))) {
    ImGui::OpenPopup("ConfirmResetDefaults");
  }
  if (ui::confirm_modal("ConfirmResetDefaults",
                        locale::tr("settings.confirm_reset"), nullptr,
                        &skip_reset_defaults, true)) {
    std::snprintf(state.target_name, sizeof(state.target_name), "%s", "Default");
    std::snprintf(state.host, sizeof(state.host), "%s", "192.168.1.100");
    state.debug_port = 9020;
    state.udp_port = 9023;
    std::snprintf(state.dump_path, sizeof(state.dump_path), "%s", "dumps");
    state.console_targets.clear();
    state.selected_target_index = 0;
    ensure_console_targets(state);
    save_current_console_target(state);
    set_status(state, locale::tr("settings.restored"));
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("SettingsRuntime", locale::tr("settings.runtime_notes"), ImVec2(0, avail.y));
  ImGui::TextWrapped("%s", locale::tr("settings.runtime_desc"));
  ImGui::Spacing();
  ImGui::Text(locale::tr("settings.protocol_version"), MEMDBG_PROTOCOL_VERSION);
  ImGui::Text(locale::tr("settings.max_read"), static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_READ));
  ImGui::Text(locale::tr("settings.max_packet"), static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_PACKET));
  ImGui::TextWrapped("%s", locale::tr("settings.console_log_path"));
  ui::end_panel();
}

} // namespace memdbg::frontend

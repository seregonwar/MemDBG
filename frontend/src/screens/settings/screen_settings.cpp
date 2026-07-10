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
  const float col_w = avail.x / 3.0f;

  /* ---- Column 1: Connection Defaults ---- */
  ui::begin_panel("SettingsConnection", locale::tr("settings.connection_defaults"), ImVec2(col_w, avail.y));
  ImGui::TextColored(ui::colors().muted, "Console");
  ImGui::Spacing();
  ImGui::InputText("Target name", state.target_name, sizeof(state.target_name));
  ImGui::InputText(locale::tr("settings.console_ipv4"), state.host, sizeof(state.host));
  ImGui::InputInt(locale::tr("settings.debug_tcp"), &state.debug_port);
  ImGui::InputInt(locale::tr("settings.udp_logs"), &state.udp_port);
  normalize_ports(state);

  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Paths");
  ImGui::Spacing();
  ImGui::Spacing();
  {
    ui::FilePathOptions dump_opts;
    dump_opts.label = locale::tr("settings.dump_path");
    dump_opts.id = "##DumpPathSettings";
    dump_opts.dialog_title = locale::tr("file_picker.select_dump_dir");
    dump_opts.folder_mode = true;
    dump_opts.placeholder = "dumps";
    ui::file_path_input(state.dump_path, sizeof(state.dump_path), dump_opts);
  }
  ui::end_panel();

  /* ---- Column 2: Preferences ---- */
  ImGui::SameLine();
  ui::begin_panel("SettingsPreferences", "Preferences", ImVec2(col_w, avail.y));
  ImGui::TextColored(ui::colors().muted, "Options");
  ImGui::Spacing();

  if (ImGui::Checkbox(locale::tr("settings.crash_logging"), &state.crash_logging_enabled)) {
    state.crash_logger.set_enabled(state.crash_logging_enabled);
    set_status(state, state.crash_logging_enabled
        ? locale::tr("settings.crash_logging_on")
        : locale::tr("settings.crash_logging_off"));
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.crash_logging_hint"));

  if (ImGui::Checkbox(locale::tr("settings.taskmgr_prefetch_on_connect"),
                      &state.taskmgr_prefetch_on_connect)) {
    set_status(state, state.taskmgr_prefetch_on_connect
        ? locale::tr("settings.taskmgr_prefetch_on")
        : locale::tr("settings.taskmgr_prefetch_off"));
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.taskmgr_prefetch_hint"));

  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "Language");
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
  ImGui::TextColored(ui::colors().muted, "Theme");
  ImGui::Spacing();
  {
    auto &theme_mgr = state.theme_manager;
    const auto theme_list = theme_mgr.themes();
    const std::string active_id = theme_mgr.active_theme_id();
    const themes::ThemeDefinition *active_def = theme_mgr.active_theme();
    const char *preview = active_def ? active_def->name.c_str() : "Default";

    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##ThemeCombo", preview)) {
      for (const auto &theme : theme_list) {
        const bool selected = theme.id == active_id;
        if (ImGui::Selectable(theme.name.c_str(), selected)) {
          std::string error;
          if (theme_mgr.set_active_theme(theme.id, &error)) {
            theme_mgr.apply_active_theme();
            set_status(state, std::string("Theme: ") + theme.name);
          } else {
            set_status(state, error);
          }
        }
        if (selected) ImGui::SetItemDefaultFocus();
      }
      ImGui::EndCombo();
    }
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("Select the UI color theme");
  }

  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.sandbox_title"));
  ImGui::Spacing();
  {
    static bool skip_sandbox_confirm = false;
    if (ImGui::Checkbox(locale::tr("settings.sandbox_enabled"), &state.sandbox_enabled)) {
      if (!state.sandbox_enabled) {
        // User is trying to disable sandbox — show confirmation
        ImGui::OpenPopup("ConfirmDisableSandbox");
        state.sandbox_enabled = true;  // revert until confirmed
      } else {
        set_status(state, locale::tr("settings.sandbox_on"));
      }
    }
    if (ui::confirm_modal("ConfirmDisableSandbox",
                          locale::tr("settings.sandbox_confirm_disable"),
                          locale::tr("settings.sandbox_confirm_disable_desc"),
                          &skip_sandbox_confirm, true)) {
      state.sandbox_enabled = false;
      set_status(state, locale::tr("settings.sandbox_off"));
    }
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("settings.sandbox_enabled_tip"));

    ImGui::BeginDisabled(!state.sandbox_enabled);
    ImGui::Indent(12.0f);
    if (ImGui::Checkbox(locale::tr("settings.sandbox_filesystem"), &state.sandbox_filesystem)) {
      set_status(state, state.sandbox_filesystem
          ? locale::tr("settings.sandbox_fs_on")
          : locale::tr("settings.sandbox_fs_off"));
    }
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("settings.sandbox_filesystem_tip"));

    if (ImGui::Checkbox(locale::tr("settings.sandbox_subprocess"), &state.sandbox_subprocess)) {
      set_status(state, state.sandbox_subprocess
          ? locale::tr("settings.sandbox_sp_on")
          : locale::tr("settings.sandbox_sp_off"));
    }
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("settings.sandbox_subprocess_tip"));

    if (ImGui::Checkbox(locale::tr("settings.sandbox_network"), &state.sandbox_network)) {
      set_status(state, state.sandbox_network
          ? locale::tr("settings.sandbox_net_on")
          : locale::tr("settings.sandbox_net_off"));
    }
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("settings.sandbox_network_tip"));

    if (ImGui::Checkbox(locale::tr("settings.sandbox_native_modules"), &state.sandbox_native_modules)) {
      set_status(state, state.sandbox_native_modules
          ? locale::tr("settings.sandbox_native_on")
          : locale::tr("settings.sandbox_native_off"));
    }
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("settings.sandbox_native_modules_tip"));

    ImGui::Spacing();
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.sandbox_whitelist"));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##SandboxRequireWhitelist", locale::tr("settings.sandbox_whitelist_hint"),
                             state.sandbox_require_whitelist, sizeof(state.sandbox_require_whitelist));
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", locale::tr("settings.sandbox_whitelist_tip"));

    ImGui::Unindent(12.0f);
    ImGui::EndDisabled();
  }

  ui::end_panel();

  /* ---- Column 3: Actions + Runtime Info ---- */
  ImGui::SameLine();
  ui::begin_panel("SettingsActions", "Actions", ImVec2(0, avail.y));

  /* Action buttons in 2x2 grid */
  const float btn_w = (ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f;
  const float btn_h = 36.0f;

  if (ui::primary_button((std::string(icons::kSave) + "  " + locale::tr("settings.save_defaults")).c_str(), ImVec2(btn_w, btn_h))) {
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
  ImGui::SameLine();
  if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("settings.apply_udp")).c_str(), ImVec2(btn_w, btn_h))) {
    state.udp_listener.stop();
    std::string error;
    if (ensure_udp_listener(state, error)) set_status(state, locale::tr("settings.udp_applied"));
    else set_status(state, error);
  }

  if (ui::soft_button((std::string(icons::kRefresh) + "  Refresh Themes").c_str(), ImVec2(btn_w, btn_h))) {
    std::string error;
    if (state.theme_manager.reload(&error)) {
      state.theme_manager.apply_active_theme();
      set_status(state, "Themes reloaded");
    } else {
      set_status(state, error);
    }
  }
  ImGui::SameLine();
  static bool skip_reset_defaults = false;
  if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("settings.reset_defaults")).c_str(), ImVec2(btn_w, btn_h))) {
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

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  /* Runtime info section */
  ImGui::TextColored(ui::colors().muted, "Runtime Info");
  ImGui::Spacing();
  ImGui::TextWrapped("%s", locale::tr("settings.runtime_desc"));
  ImGui::Spacing();
  ImGui::Text("Protocol: v%d", MEMDBG_PROTOCOL_VERSION);
  ImGui::Text("Max read: %u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_READ));
  ImGui::Text("Max packet: %u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_PACKET));
  ImGui::TextWrapped("%s", locale::tr("settings.console_log_path"));

  ui::end_panel();
}

} // namespace memdbg::frontend

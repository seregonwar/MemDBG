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

namespace {

enum class SettingsSection { Connection = 0, Preferences = 1, Actions = 2, COUNT = 3 };

struct SettingsSectionDef {
  SettingsSection id;
  const char *icon;
  const char *label_key;
};

const SettingsSectionDef kSettingsSections[] = {
  { SettingsSection::Connection,  icons::kConnect,  "settings.section.connection"  },
  { SettingsSection::Preferences, icons::kSettings, "settings.section.preferences"  },
  { SettingsSection::Actions,     icons::kSave,     "settings.section.actions"      },
};

static void draw_settings_sidebar(AppState &state, float sidebar_w, float avail_y) {
  const float scl = ui::dpi_scale();
  const float item_h = 36.0f * scl;
  const float pad = 8.0f * scl;

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6, 6));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 2));
  ImGui::BeginChild("##SettingsSidebar", ImVec2(sidebar_w, avail_y), true, ImGuiWindowFlags_NoScrollbar);

  for (int i = 0; i < static_cast<int>(SettingsSection::COUNT); ++i) {
    const auto &def = kSettingsSections[i];
    const bool active = state.settings_active_section == i;

    ImGui::PushStyleColor(ImGuiCol_Button, active ? ui::colors().bg3 : ui::colors().bg2);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, active ? ui::colors().bg3 : ui::colors().bg1);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ui::colors().bg1);
    ImGui::PushStyleColor(ImGuiCol_Text, active ? ui::colors().primary2 : ui::colors().muted);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(pad, 6.0f * scl));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f * scl);

    const std::string label = std::string(def.icon) + "  " + locale::tr(def.label_key);
    if (ImGui::Button(label.c_str(), ImVec2(-1.0f, item_h)))
      state.settings_active_section = i;

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(4);
  }

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

static void draw_connection_section(AppState &state) {
  ui::begin_panel("SettingsConnection", locale::tr("settings.connection_defaults"), ImVec2(0, 0));

  ImGui::TextColored(ui::colors().muted, "Console");
  ImGui::Spacing();
  ImGui::InputText("Target name", state.target_name, sizeof(state.target_name));
  ImGui::InputText(locale::tr("settings.console_ipv4"), state.host, sizeof(state.host));
  ImGui::InputInt(locale::tr("settings.debug_tcp"), &state.debug_port);
  ImGui::InputInt(locale::tr("settings.udp_logs"), &state.udp_port);
  ImGui::InputInt(locale::tr("settings.payload_port"), &state.payload_port);
  ImGui::InputInt(locale::tr("settings.socket_timeout"), &state.socket_timeout_ms);
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
}

static void draw_preferences_section(AppState &state) {
  ui::begin_panel("SettingsPreferences", locale::tr("settings.section.preferences"), ImVec2(0, 0));

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

  if (ImGui::Checkbox(locale::tr("settings.payload_auto_fetch"),
                      &state.payload_auto_fetch)) {
    state.payload_fetcher.set_auto_fetch(state.payload_auto_fetch);
    set_status(state, state.payload_auto_fetch
        ? locale::tr("settings.payload_auto_fetch_on")
        : locale::tr("settings.payload_auto_fetch_off"));
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.payload_auto_fetch_hint"));

  if (ImGui::Checkbox(locale::tr("settings.payload_auto_inject"),
                      &state.payload_auto_inject)) {
    set_status(state, state.payload_auto_inject
        ? locale::tr("settings.payload_auto_inject_on")
        : locale::tr("settings.payload_auto_inject_off"));
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.payload_auto_inject_hint"));

  if (ImGui::Checkbox(locale::tr("settings.payload_auto_shutdown"),
                      &state.payload_auto_shutdown)) {
    set_status(state, state.payload_auto_shutdown
        ? locale::tr("settings.payload_auto_shutdown_on")
        : locale::tr("settings.payload_auto_shutdown_off"));
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.payload_auto_shutdown_hint"));

  const char *platform_opts[] = {
    locale::tr("settings.payload_platform_auto"),
    locale::tr("settings.payload_platform_ps4"),
    locale::tr("settings.payload_platform_ps5")
  };
  state.payload_platform = std::clamp(state.payload_platform, 0, 2);
  if (ImGui::Combo(locale::tr("settings.payload_platform"), &state.payload_platform, platform_opts, 3)) {
    state.payload_fetcher.set_platform(payload_platform_filter(state.payload_platform));
    int idx = std::clamp(state.payload_platform, 0, 2);
    set_status(state, std::string(locale::tr("settings.payload_platform_changed")) + ": " + platform_opts[idx]);
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.payload_platform_hint"));

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
        ImGui::OpenPopup("ConfirmDisableSandbox");
        state.sandbox_enabled = true;
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
}

static void draw_actions_section(AppState &state) {
  ui::begin_panel("SettingsActions", locale::tr("settings.section.actions"), ImVec2(0, 0));

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
    state.payload_port = 9021;
    state.payload_platform = 0;
    state.payload_auto_inject = false;
    state.payload_auto_shutdown = false;
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

} // namespace

void draw_settings(AppState &state, ImVec2 avail) {
  ensure_console_targets(state);
  const float scl = ui::dpi_scale();
  const float sidebar_w = 190.0f * scl;

  /* Sidebar */
  draw_settings_sidebar(state, sidebar_w, avail.y);

  /* Content area */
  ImGui::SameLine();
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::BeginChild("##SettingsContent", ImVec2(avail.x - sidebar_w - 8.0f * scl, avail.y), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

  state.settings_active_section = std::clamp(state.settings_active_section, 0,
      static_cast<int>(SettingsSection::COUNT) - 1);

  switch (static_cast<SettingsSection>(state.settings_active_section)) {
    case SettingsSection::Connection:  draw_connection_section(state);  break;
    case SettingsSection::Preferences: draw_preferences_section(state); break;
    case SettingsSection::Actions:     draw_actions_section(state);     break;
  }

  ImGui::EndChild();
  ImGui::PopStyleVar();
}

} // namespace memdbg::frontend

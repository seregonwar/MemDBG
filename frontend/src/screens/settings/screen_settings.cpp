/*
 * MemDBG - Settings screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "platform.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "file_picker.hpp"
#include "confirm_modal.hpp"
#include "locale/locale_repository.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>

namespace memdbg::frontend {

namespace {

/* Local helper: compute the action journal path without depending on
   ActionJournal::default_path(), keeping the action_journal module
   free of platform.hpp */
static std::filesystem::path journal_default_path() {
  return platform::app_data_dir() / "logs" / "memdbg_actions.log";
}

enum class SettingsSection { Connection = 0, Preferences = 1, Actions = 2, Diagnostics = 3, COUNT = 4 };

struct SettingsSectionDef {
  SettingsSection id;
  const char *icon;
  const char *label_key;
};

const SettingsSectionDef kSettingsSections[] = {
  { SettingsSection::Connection,  icons::kConnect,     "settings.section.connection"  },
  { SettingsSection::Preferences, icons::kSettings,    "settings.section.preferences"  },
  { SettingsSection::Actions,     icons::kSave,        "settings.section.actions"      },
  { SettingsSection::Diagnostics, icons::kInfo,        "settings.section.diagnostics"  },
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
  const float scl = ui::dpi_scale();
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

  if (ImGui::Checkbox(locale::tr("settings.report_telemetry"), &state.report_telemetry_enabled)) {
    set_status(state, state.report_telemetry_enabled
        ? locale::tr("settings.report_telemetry_on")
        : locale::tr("settings.report_telemetry_off"));
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.report_telemetry_hint"));

  if (ImGui::Checkbox(locale::tr("settings.report_anonymize"), &state.report_anonymize)) {
    set_status(state, state.report_anonymize
        ? locale::tr("settings.report_anonymize_on")
        : locale::tr("settings.report_anonymize_off"));
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.report_anonymize_hint"));

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
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("scanner.max_results"));
  ImGui::Spacing();
  ImGui::SetNextItemWidth(200.0f * scl);
  ImGui::InputInt("##SettingsScanMaxResults", &state.scan_max_results, 100, 1000);
  state.scan_max_results = std::clamp(state.scan_max_results, 1,
      static_cast<int>(MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE));
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "(1 – %u)",
      static_cast<unsigned>(MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE));
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", "Maximum scan results returned per request (1 – 50 000).");

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
  ImGui::Text(locale::tr("settings.protocol_feature"),
              MEMDBG_PROTOCOL_FEATURE_LEVEL, MEMDBG_PROTOCOL_VERSION);
  ImGui::Text("Max read: %u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_READ));
  ImGui::Text("Max packet: %u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_PACKET));
  ImGui::TextWrapped("%s", locale::tr("settings.console_log_path"));

  ui::end_panel();
}

} // namespace

/* ========================================================================
 * Diagnostics section
 * ======================================================================== */

namespace {

struct ReplayState {
  std::vector<ActionJournalEntry> entries;
  int current_step = 0;        /* 0-based index */
  bool auto_advance = false;
  float auto_interval = 2.0f;  /* seconds */
  double next_advance_at = 0.0;
  std::string file_path;
  bool show_step_list = true;
  bool loaded = false;
};

static ReplayState g_replay;

static void export_diagnostics_bundle(AppState &state) {
  std::string path = ui::pickSaveFile(
      locale::tr("settings.diagnostics.export_bundle"),
      "memdbg_diagnostics.md", "Markdown", "*.md");
  if (path.empty()) return;

  std::ofstream out(path);
  if (!out) {
    set_status(state, locale::tr("settings.diagnostics.export_failed"));
    return;
  }

  /* ---- Header ---- */
  out << "# MemDBG Diagnostics Bundle\n\n";
  {
    char time_buf[32];
    std::time_t now = std::time(nullptr);
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    out << "**Generated:** " << time_buf << "\n\n";
  }

  /* ---- System Information ---- */
  out << "## System Information\n\n";
  out << "- **MemDBG version:** " << MEMDBG_VERSION_STRING << "\n";
  out << "- **Protocol feature level:** v" << MEMDBG_PROTOCOL_FEATURE_LEVEL
      << " (wire v" << MEMDBG_PROTOCOL_VERSION << ")\n";
#if defined(_WIN32)
  out << "- **Platform:** Windows";
#elif defined(__APPLE__)
  out << "- **Platform:** macOS";
#elif defined(__linux__)
  out << "- **Platform:** Linux";
#else
  out << "- **Platform:** Unknown";
#endif
#ifdef __x86_64__
  out << " (x86_64)\n";
#elif defined(__aarch64__)
  out << " (ARM64)\n";
#else
  out << "\n";
#endif
  out << "- **Max read:** " << MEMDBG_PROTOCOL_MAX_READ << " bytes\n";
  out << "- **Max packet:** " << MEMDBG_PROTOCOL_MAX_PACKET << " bytes\n";
  out << "- **Socket timeout:** " << state.socket_timeout_ms << " ms\n";
  out << "- **Connected:** " << (state.client.connected() ? "yes" : "no") << "\n";
  if (state.has_hello) {
    out << "- **Payload version:** " << state.hello.version << "\n";
    out << "- **Payload protocol:** feature level v"
        << state.hello.feature_level << " (wire v"
        << state.hello.protocol_version << ")\n";
  }
  out << "- **Crash logging:** " << (state.crash_logging_enabled ? "enabled" : "disabled") << "\n";
  out << "- **Telemetry in reports:** " << (state.report_telemetry_enabled ? "enabled" : "disabled");
  if (state.report_telemetry_enabled)
    out << " (" << (state.report_anonymize ? "anonymized" : "raw") << ")";
  out << "\n\n";

  /* ---- Action Journal ---- */
  out << "## Action Journal\n\n";
  const auto journal_path = journal_default_path();
  out << "**Path:** `" << journal_path.string() << "`\n\n";

  std::vector<ActionJournalEntry> entries;
  bool clean = false;
  ActionJournal::load_recent(journal_path, entries, 500, &clean);

  out << "**Entries:** " << entries.size() << "\n";
  out << "**Last shutdown:** " << (clean ? "clean" : "unclean (possible crash)") << "\n\n";

  if (entries.empty()) {
    out << "_(no entries)_\n\n";
  } else {
    out << "| # | Timestamp | Action | Details |\n";
    out << "|---|-----------|--------|----------|\n";
    int idx = 1;
    for (const auto &e : entries) {
      char time_buf[24];
      std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", std::localtime(&e.timestamp));

      // Anonymize details for export
      std::string detail = e.detail;
      if (state.report_anonymize && !detail.empty() && detail != "{}") {
        // Simple redaction of host/PID/path from the JSON detail string
        auto redact = [&detail](const std::string &key, const std::string &replacement) {
          auto pos = detail.find("\"" + key + "\":\"");
          if (pos != std::string::npos) {
            auto val_start = pos + key.length() + 4;
            auto val_end = detail.find("\"", val_start);
            if (val_end != std::string::npos) {
              detail.replace(val_start, val_end - val_start, replacement);
            }
          }
        };
        redact("host", "[HOST]");
        redact("name", "[PROCESS]");
        redact("path", "[PATH]");
        // Redact PID by replacing numeric value
        auto pid_pos = detail.find("\"pid\":");
        if (pid_pos != std::string::npos) {
          auto val_start = pid_pos + 6;
          auto val_end = detail.find_first_of(",}", val_start);
          if (val_end != std::string::npos) {
            detail.replace(val_start, val_end - val_start, "[PID]");
          }
        }
      }

      // Escape pipes in detail for Markdown table formatting
      std::string escaped = detail;
      if (!escaped.empty() && escaped != "{}") {
        for (size_t p = 0; (p = escaped.find('|', p)) != std::string::npos; p += 2)
          escaped.insert(p, "\\");
      }

      out << "| " << idx << " | " << time_buf << " | `" << e.action << "` | "
          << (escaped.empty() || escaped == "{}" ? "—" : escaped) << " |\n";
      idx++;
    }
    out << "\n";
  }

  /* ---- Crash Log ---- */
  out << "## Crash Log\n\n";
  const auto crash_log_path = journal_default_path().parent_path() / "memdbg_crash.log";
  out << "**Path:** `" << crash_log_path.string() << "`\n\n";

  std::error_code ec;
  if (std::filesystem::exists(crash_log_path, ec)) {
    std::ifstream crash_in(crash_log_path);
    if (crash_in) {
      out << "```\n";
      std::string line;
      int crash_lines = 0;
      while (std::getline(crash_in, line) && crash_lines < 500) {
        out << line << "\n";
        crash_lines++;
      }
      if (crash_lines >= 500)
        out << "... (truncated)\n";
      out << "```\n";
    } else {
      out << "_(could not read crash log)_\n";
    }
  } else {
    out << "_(no crash log found)_\n";
  }

  char msg_buf[512];
  std::snprintf(msg_buf, sizeof(msg_buf),
                locale::tr("settings.diagnostics.export_saved"), path.c_str());
  set_status(state, msg_buf);
  push_notification(state, msg_buf, 5.0);
}

static void draw_diagnostics_section(AppState &state) {
  const float scl = ui::dpi_scale();

  /* ---- Row 1: System Info + Journal Info side by side ---- */
  const float panel_w = (ImGui::GetContentRegionAvail().x - 8.0f * scl) * 0.5f;

  /* System Information */
  ui::begin_panel("DiagSystem", locale::tr("settings.diagnostics.system_info"), ImVec2(panel_w, 0));
  {
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.version"));
    ImGui::SameLine();
    ImGui::Text("%s", MEMDBG_VERSION_STRING);

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.protocol"));
    ImGui::SameLine();
    ImGui::Text(locale::tr("settings.diagnostics.protocol_feature"),
                MEMDBG_PROTOCOL_FEATURE_LEVEL, MEMDBG_PROTOCOL_VERSION);

    ImGui::Spacing();
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.platform"));
    ImGui::SameLine();
#if defined(_WIN32)
    ImGui::Text("Windows");
#elif defined(__APPLE__)
    ImGui::Text("macOS");
#elif defined(__linux__)
    ImGui::Text("Linux");
#else
    ImGui::Text("Unknown");
#endif

#ifdef __x86_64__
    ImGui::SameLine(); ImGui::Text(" (x86_64)");
#elif defined(__aarch64__)
    ImGui::SameLine(); ImGui::Text(" (ARM64)");
#endif

    ImGui::Spacing();
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.console_status"));
    ImGui::SameLine();
    if (state.client.connected()) {
      ImGui::TextColored(ui::colors().success, "%s", locale::tr("settings.diagnostics.connected"));
      ImGui::SameLine();
      ImGui::Text("- %s:%d", state.host, state.debug_port);
      if (state.has_hello) {
        ImGui::TextColored(ui::colors().muted, "  Payload:");
        ImGui::SameLine();
        ImGui::Text(locale::tr("settings.diagnostics.payload_feature"),
                    state.hello.version.c_str(), state.hello.feature_level,
                    state.hello.protocol_version);
      }
    } else {
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("settings.diagnostics.not_connected"));
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.crash_logging_status"));
    ImGui::SameLine();
    if (state.crash_logging_enabled) {
      ImGui::TextColored(ui::colors().success, "%s", locale::tr("settings.diagnostics.enabled"));
    } else {
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("settings.diagnostics.disabled"));
    }

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.telemetry"));
    ImGui::SameLine();
    if (state.report_telemetry_enabled) {
      ImGui::TextColored(ui::colors().success, "%s", locale::tr("settings.diagnostics.enabled"));
      ImGui::SameLine();
      ImGui::TextColored(ui::colors().muted, " (%s)",
        state.report_anonymize ? locale::tr("settings.diagnostics.anonymized") : locale::tr("settings.diagnostics.raw"));
    } else {
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("settings.diagnostics.disabled"));
    }

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.max_read"));
    ImGui::SameLine();
    ImGui::Text("%u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_READ));

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.max_packet"));
    ImGui::SameLine();
    ImGui::Text("%u bytes", static_cast<unsigned>(MEMDBG_PROTOCOL_MAX_PACKET));

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.socket_timeout"));
    ImGui::SameLine();
    ImGui::Text("%d ms", state.socket_timeout_ms);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("settings.diagnostics.copy_sysinfo")).c_str(), ImVec2(-1.0f, 32.0f * scl))) {
      std::string info;
      info += "MemDBG " MEMDBG_VERSION_STRING "\n";
      info += "Protocol feature level v" +
              std::to_string(MEMDBG_PROTOCOL_FEATURE_LEVEL) + " (wire v" +
              std::to_string(MEMDBG_PROTOCOL_VERSION) + ")\n";
#if defined(_WIN32)
      info += "Platform: Windows\n";
#elif defined(__APPLE__)
      info += "Platform: macOS\n";
#elif defined(__linux__)
      info += "Platform: Linux\n";
#endif
      info += "Connected: " + std::string(state.client.connected() ? "yes" : "no") + "\n";
      if (state.has_hello) {
        info += "Payload: " + state.hello.version + " (feature v" +
                std::to_string(state.hello.feature_level) + ", wire v" +
                std::to_string(state.hello.protocol_version) + ")\n";
      }
      ImGui::SetClipboardText(info.c_str());
      set_status(state, locale::tr("settings.diagnostics.sysinfo_copied"));
    }

    ImGui::Spacing();
    if (ui::soft_button((std::string(icons::kLoad) + "  " +
                         locale::tr("settings.diagnostics.open_config_folder")).c_str(),
                        ImVec2(-1.0f, 32.0f * scl))) {
      const auto config_dir = platform::app_config_dir();
      if (platform::open_directory(config_dir)) {
        set_status(state, std::string(locale::tr(
                              "settings.diagnostics.config_folder_opened")) +
                              ": " + config_dir.string());
      } else {
        set_status(state, std::string(locale::tr(
                              "settings.diagnostics.config_folder_failed")) +
                              ": " + config_dir.string());
      }
    }

    ImGui::Spacing();
    if (ui::primary_button((std::string(icons::kSave) + "  " + locale::tr("settings.diagnostics.export_bundle")).c_str(), ImVec2(-1.0f, 36.0f * scl))) {
      export_diagnostics_bundle(state);
    }
  }
  ui::end_panel();

  ImGui::SameLine();

  /* Journal Information */
  ui::begin_panel("DiagJournal", locale::tr("settings.diagnostics.journal_title"), ImVec2(panel_w, 0));
  {
    const auto journal_path = journal_default_path();

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.journal_path"));
    ImGui::SameLine();
    ImGui::TextWrapped("%s", journal_path.string().c_str());

    /* File size & entry count — throttled reload */
    static double journal_last_reload = 0.0;
    static bool journal_loaded = false;
    static std::vector<ActionJournalEntry> journal_cached_entries;
    static bool journal_cached_clean = false;
    static uintmax_t journal_cached_size = 0;

    if (ImGui::GetTime() - journal_last_reload > 2.0 || !journal_loaded) {
      std::error_code ec;
      journal_cached_size = 0;
      if (std::filesystem::exists(journal_path, ec)) {
        journal_cached_size = std::filesystem::file_size(journal_path, ec);
      }
      journal_cached_entries.clear();
      ActionJournal::load_recent(journal_path, journal_cached_entries, 200, &journal_cached_clean);
      journal_loaded = true;
      journal_last_reload = ImGui::GetTime();
    }

    /* File size */
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.journal_size"));
    ImGui::SameLine();
    if (journal_cached_size < 1024)
      ImGui::Text("%llu B", static_cast<unsigned long long>(journal_cached_size));
    else if (journal_cached_size < 1024 * 1024)
      ImGui::Text("%.1f KB", journal_cached_size / 1024.0);
    else
      ImGui::Text("%.1f MB", journal_cached_size / (1024.0 * 1024.0));

    /* Entry count & clean shutdown */
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.journal_entries"));
    ImGui::SameLine();
    ImGui::Text("%zu", journal_cached_entries.size());

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.last_shutdown"));
    ImGui::SameLine();
    if (journal_cached_clean) {
      ImGui::TextColored(ui::colors().success, "%s", locale::tr("settings.diagnostics.clean"));
    } else {
      ImGui::TextColored(ui::colors().warning, "%s", locale::tr("settings.diagnostics.unclean"));
    }

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.journal_status"));
    ImGui::SameLine();
    if (state.action_journal.is_open()) {
      ImGui::TextColored(ui::colors().success, "%s", locale::tr("settings.diagnostics.active"));
    } else {
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("settings.diagnostics.inactive"));
    }

    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.journal_enabled"));
    ImGui::SameLine();
    if (state.action_journal.enabled()) {
      ImGui::TextColored(ui::colors().success, "%s", locale::tr("settings.diagnostics.enabled"));
    } else {
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("settings.diagnostics.disabled"));
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    /* Inline journal viewer */
    ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.recent_actions"));
    ImGui::Spacing();

    const float list_h = ImGui::GetContentRegionAvail().y - 36.0f * scl;
    if (ImGui::BeginChild("##DiagJournalList", ImVec2(0, list_h), true)) {
      if (journal_cached_entries.empty()) {
        ImGui::TextColored(ui::colors().dim, "%s", locale::tr("settings.diagnostics.no_entries"));
      } else {
        for (auto it = journal_cached_entries.rbegin();
             it != journal_cached_entries.rend(); ++it) {
          const auto &entry = *it;
          char time_buf[24];
          std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", std::localtime(&entry.timestamp));
          ImGui::TextColored(ui::colors().dim, "[%s]", time_buf);
          ImGui::SameLine();
          ImGui::TextColored(ui::colors().primary2, "%s", entry.action.c_str());
          if (!entry.detail.empty() && entry.detail != "{}") {
            ImGui::SameLine();
            ImGui::TextColored(ui::colors().muted, "%s", entry.detail.c_str());
          }
        }
      }
    }
    ImGui::EndChild();

    const float journal_button_w =
        (ImGui::GetContentRegionAvail().x -
         ImGui::GetStyle().ItemSpacing.x * 2.0f) / 3.0f;
    if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("settings.diagnostics.copy_journal")).c_str(), ImVec2(journal_button_w, 28.0f * scl))) {
      std::string all;
      for (const auto &entry : journal_cached_entries) {
        char time_buf[24];
        std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&entry.timestamp));
        all += std::string("[") + time_buf + "] " + entry.action;
        if (!entry.detail.empty() && entry.detail != "{}")
          all += " " + entry.detail;
        all += "\n";
      }
      ImGui::SetClipboardText(all.c_str());
      set_status(state, locale::tr("settings.diagnostics.journal_copied"));
    }
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kExternalLink) + "  " +
                         locale::tr("settings.diagnostics.open_journal")).c_str(),
                        ImVec2(journal_button_w, 28.0f * scl))) {
      if (platform::open_path(journal_path))
        set_status(state, locale::tr("settings.diagnostics.journal_opened"));
      else
        set_status(state, locale::tr("settings.diagnostics.journal_open_failed"));
    }
    ImGui::SameLine();
    static bool skip_clear_journal = false;
    if (ui::soft_button((std::string(icons::kTrash) + "  " +
                         locale::tr("settings.diagnostics.clear_journal")).c_str(),
                        ImVec2(journal_button_w, 28.0f * scl)))
      ImGui::OpenPopup("ConfirmClearJournal");
    if (ui::confirm_modal("ConfirmClearJournal",
                          locale::tr("settings.diagnostics.clear_journal_confirm"),
                          nullptr,
                          &skip_clear_journal, true)) {
      if (state.action_journal.clear()) {
        journal_cached_entries.clear();
        journal_cached_size = 0U;
        journal_cached_clean = false;
        journal_loaded = false;
        set_status(state, locale::tr("settings.diagnostics.journal_cleared"));
      } else {
        set_status(state,
                   locale::tr("settings.diagnostics.journal_clear_failed"));
      }
    }
  }
  ui::end_panel();

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  /* ---- Row 2: Action Replay (full width) ---- */
  ui::begin_panel("DiagReplay", locale::tr("settings.diagnostics.replay_title"), ImVec2(0, 0));
  {
    ImGui::TextWrapped("%s", locale::tr("settings.diagnostics.replay_desc"));
    ImGui::Spacing();

    /* ---- Controls bar ---- */
    const float btn_w = 150.0f * scl;
    const float btn_h = 32.0f * scl;

    /* Load button */
    if (ui::soft_button((std::string(icons::kLoad) + "  " + locale::tr("settings.diagnostics.load_journal")).c_str(), ImVec2(btn_w, btn_h))) {
      std::string picked = ui::pickFile("Load Action Journal", "Log Files", "*.log");
      if (!picked.empty()) {
        g_replay.entries.clear();
        bool clean = false;
        ActionJournal::load_recent(std::filesystem::path(picked), g_replay.entries, 500, &clean);
        g_replay.current_step = 0;
        g_replay.loaded = true;
        g_replay.file_path = picked;
        g_replay.auto_advance = false;
        set_status(state, std::string(locale::tr("settings.diagnostics.loaded")) + ": " +
                   std::to_string(g_replay.entries.size()) + " " + locale::tr("settings.diagnostics.entries_loaded"));
      }
    }

    /* Also allow loading the current journal */
    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("settings.diagnostics.load_current")).c_str(), ImVec2(btn_w, btn_h))) {
      const auto jpath = journal_default_path();
      g_replay.entries.clear();
      ActionJournal::load_recent(jpath, g_replay.entries, 500);
      g_replay.current_step = 0;
      g_replay.loaded = true;
      g_replay.file_path = jpath.string();
      g_replay.auto_advance = false;
      set_status(state, std::string(locale::tr("settings.diagnostics.loaded")) + ": " +
                 std::to_string(g_replay.entries.size()) + " " + locale::tr("settings.diagnostics.entries_loaded"));
    }

    ImGui::SameLine();
    if (!g_replay.file_path.empty()) {
      ImGui::TextColored(ui::colors().dim, "%s", g_replay.file_path.c_str());
    }

    if (!g_replay.loaded || g_replay.entries.empty()) {
      ImGui::Spacing();
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("settings.diagnostics.replay_empty"));
      ui::end_panel();
      return;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    /* ---- Progress bar ---- */
    const int total = static_cast<int>(g_replay.entries.size());
    const int current = g_replay.current_step;
    float progress = total > 0 ? static_cast<float>(current + 1) / static_cast<float>(total) : 0.0f;
    ImGui::ProgressBar(progress, ImVec2(-1.0f, 12.0f * scl), "");
    ImGui::Spacing();

    /* ---- Two-column: step list + step details ---- */
    const float left_w = (g_replay.show_step_list && total > 1) ? 220.0f * scl : 0.0f;
    const float right_w = ImGui::GetContentRegionAvail().x - left_w - 8.0f * scl;

    /* Step list (left column) */
    if (left_w > 0) {
      if (ImGui::BeginChild("##ReplayStepList", ImVec2(left_w, 0), true)) {
        for (int i = 0; i < total; ++i) {
          const bool is_current = (i == current);
          const bool is_done = (i < current);

          ImGui::PushStyleColor(ImGuiCol_Text, is_current ? ui::colors().primary2 :
                                                (is_done ? ui::colors().dim : ui::colors().muted));

          char label[64];
          std::snprintf(label, sizeof(label), "%d. %s", i + 1, g_replay.entries[i].action.c_str());
          if (ImGui::Selectable(label, is_current)) {
            g_replay.current_step = i;
            g_replay.auto_advance = false;
          }
          ImGui::PopStyleColor();

          if (is_current) ImGui::SetItemDefaultFocus();
        }
      }
      ImGui::EndChild();
      ImGui::SameLine();
    }

    /* Step details (right column) */
    if (ImGui::BeginChild("##ReplayDetail", ImVec2(right_w, 0), true)) {
      const auto &step = g_replay.entries[current];

      /* Step counter */
      char step_label[64];
      std::snprintf(step_label, sizeof(step_label), locale::tr("settings.diagnostics.step_of"),
                    current + 1, total);
      ImGui::TextColored(ui::colors().primary2, "%s", step_label);
      ImGui::Spacing();

      /* Action card */
      ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
      ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.0f * scl, 12.0f * scl));
      ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f * scl);
      ImGui::BeginChild("##ReplayActionCard", ImVec2(0, 0), true);

      /* Timestamp */
      char time_buf[32];
      std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&step.timestamp));
      ImGui::TextColored(ui::colors().dim, "%s", time_buf);

      /* Action name */
      ImGui::TextColored(ui::colors().primary2, "%s: %s",
                         locale::tr("settings.diagnostics.action"), step.action.c_str());

      /* Detail params */
      if (!step.detail.empty() && step.detail != "{}") {
        ImGui::Spacing();
        ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.diagnostics.params"));
        ImGui::SameLine();
        ImGui::TextWrapped("%s", step.detail.c_str());
      }

      /* Instruction */
      ImGui::Spacing();
      ImGui::Separator();
      ImGui::Spacing();
      ImGui::TextWrapped("%s %s", icons::kInfo,
                         locale::tr("settings.diagnostics.replay_instruction"));

      ImGui::EndChild();
      ImGui::PopStyleVar(2);
      ImGui::PopStyleColor();
    }
    ImGui::EndChild();

    /* ---- Navigation buttons ---- */
    ImGui::Spacing();

    ImGui::BeginDisabled(current <= 0);
    if (ui::soft_button((std::string("\xe2\x86\x90  ") + locale::tr("settings.diagnostics.prev")).c_str(), ImVec2(btn_w, btn_h))) {
      g_replay.current_step = std::max(0, current - 1);
      g_replay.auto_advance = false;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(current >= total - 1);
    if (ui::soft_button((std::string("\xe2\x86\x92  ") + locale::tr("settings.diagnostics.next")).c_str(), ImVec2(btn_w, btn_h))) {
      g_replay.current_step = std::min(total - 1, current + 1);
      g_replay.auto_advance = false;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ui::soft_button((std::string(g_replay.auto_advance ? icons::kPause : icons::kPlay) + "  " +
                         locale::tr(g_replay.auto_advance ? "settings.diagnostics.pause" : "settings.diagnostics.auto")).c_str(), ImVec2(btn_w, btn_h))) {
      g_replay.auto_advance = !g_replay.auto_advance;
      if (g_replay.auto_advance) {
        g_replay.next_advance_at = ImGui::GetTime() + g_replay.auto_interval;
      }
    }

    /* Auto-advance interval slider */
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f * scl);
    ImGui::SliderFloat(locale::tr("settings.diagnostics.interval"), &g_replay.auto_interval, 0.5f, 10.0f, "%.1fs");

    ImGui::SameLine();
    if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("settings.diagnostics.reset")).c_str(), ImVec2(btn_w, btn_h))) {
      g_replay.current_step = 0;
      g_replay.auto_advance = false;
    }

    /* Step list toggle */
    ImGui::SameLine();
    ImGui::Checkbox(locale::tr("settings.diagnostics.show_list"), &g_replay.show_step_list);

    /* Auto-advance logic */
    if (g_replay.auto_advance && ImGui::GetTime() >= g_replay.next_advance_at) {
      if (current < total - 1) {
        g_replay.current_step++;
        g_replay.next_advance_at = ImGui::GetTime() + g_replay.auto_interval;
      } else {
        g_replay.auto_advance = false;
      }
    }
  }
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
    case SettingsSection::Diagnostics: draw_diagnostics_section(state); break;
    case SettingsSection::COUNT:       break;
  }

  ImGui::EndChild();
  ImGui::PopStyleVar();
}

} // namespace memdbg::frontend

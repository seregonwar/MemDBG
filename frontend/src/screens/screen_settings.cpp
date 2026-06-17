/*
 * MemDBG - Settings screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "file_picker.hpp"

#include <cstdio>
#include <string>

namespace memdbg::frontend {

void draw_settings(AppState &state, ImVec2 avail) {
  const float gap = 16.0f;
  const float col_w = (avail.x - gap) * 0.5f;

  ui::begin_panel("SettingsConnection", locale::tr("settings.connection_defaults"), ImVec2(col_w, avail.y));
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

  // Language selector
  ImGui::TextColored(ui::colors().muted, "%s", locale::tr("settings.language"));
  ImGui::Spacing();
  {
    auto &mgr = locale::Manager::instance();
    locale::Lang active_lang = static_cast<locale::Lang>(state.language);
    int active_pct = mgr.translation_progress(active_lang);
    char preview_buf[128];
    std::snprintf(preview_buf, sizeof(preview_buf), "%s (%d%%)",
                  locale::lang_name(active_lang), active_pct);
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##LangCombo", preview_buf)) {
      for (int i = 0; i < static_cast<int>(locale::Lang::COUNT); ++i) {
        locale::Lang lang = static_cast<locale::Lang>(i);
        if (!mgr.is_loaded(lang)) continue;
        const bool selected = state.language == i;
        int pct = mgr.translation_progress(lang);
        char label[128];
        std::snprintf(label, sizeof(label), "%s (%d%%)",
                      locale::lang_name(lang), pct);
        if (ImGui::Selectable(label, selected)) {
          state.language = i;
          mgr.set_active(lang);
          set_status(state, std::string(locale::tr("settings.language")) + ": " + label);
        }
        if (selected) ImGui::SetItemDefaultFocus();
      }
      ImGui::EndCombo();
    }
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", locale::tr("settings.language_hint"));

  ImGui::Spacing();
  if (ui::primary_button((std::string(icons::kSave) + "  " + locale::tr("settings.save_defaults")).c_str(), ui::full_button(40))) {
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
  if (ui::soft_button((std::string(icons::kRefresh) + "  " + locale::tr("settings.reset_defaults")).c_str(), ui::full_button(40))) {
    std::snprintf(state.host, sizeof(state.host), "%s", "192.168.1.100");
    state.debug_port = 9020;
    state.udp_port = 9023;
    std::snprintf(state.dump_path, sizeof(state.dump_path), "%s", "dumps");
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

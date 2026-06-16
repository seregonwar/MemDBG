/*
 * MemDBG - Credits screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "github_profile.hpp"
#include "platform.hpp"

#include <mutex>
#include <string>

namespace memdbg::frontend {

namespace {

void link_button(const char *id, const char *icon, const char *label, const char *url) {
  ImGui::PushID(id);
  if (ui::soft_button((std::string(icon) + "  " + label).c_str(), ImVec2(260, 38))) {
    (void)platform::open_url(url);
  }
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", url);
  ImGui::PopID();
}

} // namespace

void draw_credits(AppState &state, ImVec2 avail) {
  github_profile_pump_texture(state.github_profile);

  std::string profile_name;
  std::string profile_login;
  std::string profile_bio;
  std::string profile_error;
  {
    std::lock_guard<std::mutex> lock(state.github_profile.mutex);
    profile_name  = state.github_profile.name;
    profile_login = state.github_profile.login;
    profile_bio   = state.github_profile.bio;
    profile_error = state.github_profile.error;
  }

  ui::begin_panel("CreditsPanel", locale::tr("app.title"), avail);
  ImGui::BeginGroup();
  if (state.github_profile.texture != 0U) {
    ImGui::Image(github_profile_texture_id(state.github_profile), ImVec2(96, 96));
  } else {
    ImDrawList *draw_list = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetCursorScreenPos();
    draw_list->AddRectFilled(pos, ImVec2(pos.x+96.0f, pos.y+96.0f), ui::color_u32(ui::colors().bg3), 12.0f);
    draw_list->AddText(ImVec2(pos.x+24.0f, pos.y+38.0f), ui::color_u32(ui::colors().muted), "SW");
    ImGui::Dummy(ImVec2(96, 96));
  }
  ImGui::EndGroup();

  ImGui::SameLine(0, 18);
  ImGui::BeginGroup();
  ImGui::TextColored(ui::colors().primary2, "%s", locale::tr("app.title"));
  ImGui::Text("%s", locale::tr("credits.version"));
  if (!profile_name.empty())
    ImGui::Text(locale::tr("credits.creator"), profile_name.c_str(), profile_login.c_str());
  else
    ImGui::Text("%s", locale::tr("credits.creator_default"));
  if (!profile_bio.empty()) ImGui::TextWrapped("%s", profile_bio.c_str());
  if (!profile_error.empty()) ImGui::TextColored(ui::colors().warning, locale::tr("credits.github_profile"), profile_error.c_str());
  ImGui::EndGroup();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextWrapped("%s", locale::tr("credits.description"));
  ImGui::Spacing();
  const bool inline_links = ImGui::GetContentRegionAvail().x >= 830.0f;
  link_button("github", icons::kCode, locale::tr("credits.github"), "https://github.com/seregonwar/");
  if (inline_links) ImGui::SameLine();
  link_button("donations", icons::kSuccess, locale::tr("credits.donations"), "https://www.seregonwar.com/donations");
  if (inline_links) ImGui::SameLine();
  link_button("x", icons::kInfo, "X / SeregonWar", "https://x.com/SeregonWar");
  ImGui::Spacing();
  ImGui::TextWrapped("%s", locale::tr("credits.license"));
  ImGui::Spacing();
  ImGui::Text(locale::tr("credits.current_endpoint"), state.host, state.debug_port);
  ui::end_panel();
}

} // namespace memdbg::frontend

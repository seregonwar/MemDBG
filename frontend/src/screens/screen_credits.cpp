/*
 * MemDBG - Credits screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "github_profile.hpp"

#include <cstdlib>
#include <mutex>
#include <string>

namespace memdbg::frontend {

namespace {

void open_url(const char *url) {
#if defined(__APPLE__)
  std::string command = "open '" + std::string(url) + "'";
#elif defined(_WIN32)
  std::string command = "start \"\" \"" + std::string(url) + "\"";
#else
  std::string command = "xdg-open '" + std::string(url) + "'";
#endif
  (void)std::system(command.c_str());
}

void link_button(const char *id, const char *icon, const char *label, const char *url) {
  ImGui::PushID(id);
  if (ui::soft_button((std::string(icon) + "  " + label).c_str(), ImVec2(260, 38))) {
    open_url(url);
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

  ui::begin_panel("CreditsPanel", "MemDBG", avail);
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
  ImGui::TextColored(ui::colors().primary2, "MemDBG Native");
  ImGui::Text("Version 0.1.0");
  if (!profile_name.empty())
    ImGui::Text("Creator: %s (@%s)", profile_name.c_str(), profile_login.c_str());
  else
    ImGui::Text("Creator: SeregonWar (@seregonwar)");
  if (!profile_bio.empty()) ImGui::TextWrapped("%s", profile_bio.c_str());
  if (!profile_error.empty()) ImGui::TextColored(ui::colors().warning, "GitHub profile: %s", profile_error.c_str());
  ImGui::EndGroup();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextWrapped("Console-first frontend for connecting to the MemDBG payload, browsing processes, reading and writing memory, scanning values (exact, AOB, pointer), building trainers (.cht, SHN, SHNEXT, MC4, JSON), and watching UDP telemetry.");
  ImGui::Spacing();
  const bool inline_links = ImGui::GetContentRegionAvail().x >= 830.0f;
  link_button("github", icons::kCode, "GitHub", "https://github.com/seregonwar/");
  if (inline_links) ImGui::SameLine();
  link_button("donations", icons::kSuccess, "Donations", "https://www.seregonwar.com/donations");
  if (inline_links) ImGui::SameLine();
  link_button("x", icons::kInfo, "X / SeregonWar", "https://x.com/SeregonWar");
  ImGui::Spacing();
  ImGui::TextWrapped("License: GNU General Public License v3.0 or later");
  ImGui::Spacing();
  ImGui::Text("Current endpoint: %s:%d", state.host, state.debug_port);
  ui::end_panel();
}

} // namespace memdbg::frontend

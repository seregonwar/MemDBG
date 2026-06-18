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

#include <algorithm>
#include <cstdio>
#include <mutex>
#include <string>

namespace memdbg::frontend {

namespace {

static ImVec4 alpha(ImVec4 color, float value) {
  color.w *= value;
  return color;
}

enum class BrandLogo {
  GitHub,
  Donations,
  X,
  Bluesky,
};

const char *brand_icon(BrandLogo logo) {
  switch (logo) {
  case BrandLogo::GitHub: return u8"\uf09b";
  case BrandLogo::Donations: return icons::kSuccess;
  case BrandLogo::X: return u8"\ue61b";
  case BrandLogo::Bluesky: return u8"\ue671";
  }
  return icons::kInfo;
}

void link_button(const char *id, BrandLogo logo, const char *label,
                 const char *url, float width) {
  ImGui::PushID(id);
  std::string text = std::string(brand_icon(logo)) + "  " + label;
  if (ui::soft_button(text.c_str(), ImVec2(width, 38.0f * ui::dpi_scale()))) {
    (void)platform::open_url(url);
  }
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", url);
  ImGui::PopID();
}

void section_header(const char *label, const char *icon) {
  ImGui::TextColored(ui::colors().primary2, "%s  %s", icon, label);
  ImGui::Separator();
}

void draw_avatar(const GitHubProfile &profile, float size) {
  if (profile.texture != 0U) {
    ImGui::Image(github_profile_texture_id(profile), ImVec2(size, size));
    return;
  }

  ImDrawList *draw_list = ImGui::GetWindowDrawList();
  ImVec2 pos = ImGui::GetCursorScreenPos();
  ImVec2 max(pos.x + size, pos.y + size);
  draw_list->AddRectFilled(pos, max, ui::color_u32(ui::colors().bg3), 4.0f * ui::dpi_scale());
  draw_list->AddRect(pos, max, ui::color_u32(alpha(ui::colors().border_hot, 0.65f)),
                     4.0f * ui::dpi_scale());

  const char *initials = "SW";
  ImVec2 text_size = ImGui::CalcTextSize(initials);
  draw_list->AddText(ImVec2(pos.x + (size - text_size.x) * 0.5f,
                            pos.y + (size - text_size.y) * 0.5f),
                     ui::color_u32(ui::colors().muted), initials);
  ImGui::Dummy(ImVec2(size, size));
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

  if (profile_login.empty()) profile_login = "seregonwar";

  char creator_buf[256];
  if (!profile_name.empty()) {
    std::snprintf(creator_buf, sizeof(creator_buf), locale::tr("credits.creator"),
                  profile_name.c_str(), profile_login.c_str());
  } else {
    std::snprintf(creator_buf, sizeof(creator_buf), "%s",
                  locale::tr("credits.creator_default"));
  }

  const float scl = ui::dpi_scale();
  const float panel_w = std::max(240.0f * scl, avail.x - 20.0f * scl);
  const float avatar_size = 112.0f * scl;

  ui::begin_panel("CreditsPanel", locale::tr("app.title"), avail);

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().panel);
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 4.0f * scl);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f * scl, 12.0f * scl));
  ImGui::BeginChild("CreditsHeader", ImVec2(0, 152.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  {
    ImDrawList *draw_list = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetWindowPos();
    ImVec2 size = ImGui::GetWindowSize();
    draw_list->AddRectFilled(pos, ImVec2(pos.x + 4.0f * scl, pos.y + size.y),
                             ui::color_u32(ui::colors().primary2), 2.0f * scl);

    draw_avatar(state.github_profile, avatar_size);
    ImGui::SameLine(0, 16.0f * scl);
    ImGui::BeginGroup();
    ImGui::TextColored(ui::colors().primary2, "%s", locale::tr("app.title"));
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, "%s", locale::tr("app.tagline"));
    ImGui::Spacing();
    ImGui::TextColored(ui::colors().text, "%s", locale::tr("credits.version"));
    ImGui::TextColored(ui::colors().muted, "%s", creator_buf);
    const char *bio_text = !profile_bio.empty() ? profile_bio.c_str()
                                                : locale::tr("app.tagline");
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + panel_w - avatar_size - 80.0f * scl);
    ImGui::TextColored(ui::colors().dim, "%s", bio_text);
    ImGui::PopTextWrapPos();
    if (!profile_error.empty()) {
      ImGui::TextColored(ui::colors().warning, locale::tr("credits.github_profile"),
                         profile_error.c_str());
    }
    ImGui::EndGroup();
  }
  ImGui::EndChild();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();

  ImGui::Spacing();

  const float link_gap = 8.0f * scl;
  const float link_wide_threshold = 900.0f * scl;
  if (ImGui::GetContentRegionAvail().x >= link_wide_threshold &&
      ImGui::BeginTable("CreditsLinks", 4, ImGuiTableFlags_SizingStretchSame)) {
    ImGui::TableNextColumn();
    link_button("github", BrandLogo::GitHub, locale::tr("credits.github"),
                "https://github.com/seregonwar/", -1.0f);
    ImGui::TableNextColumn();
    link_button("donations", BrandLogo::Donations, locale::tr("credits.donations"),
                "https://www.seregonwar.com/donations", -1.0f);
    ImGui::TableNextColumn();
    link_button("x", BrandLogo::X, "X / SeregonWar", "https://x.com/SeregonWar",
                -1.0f);
    ImGui::TableNextColumn();
    link_button("bluesky", BrandLogo::Bluesky, "Bluesky",
                "https://bsky.app/profile/seregonwar.bsky.social",
                -1.0f);
    ImGui::EndTable();
  } else {
    const float link_width = ImGui::GetContentRegionAvail().x;
    link_button("github", BrandLogo::GitHub, locale::tr("credits.github"),
                "https://github.com/seregonwar/", link_width);
    ImGui::Dummy(ImVec2(0, link_gap));
    link_button("donations", BrandLogo::Donations, locale::tr("credits.donations"),
                "https://www.seregonwar.com/donations", link_width);
    ImGui::Dummy(ImVec2(0, link_gap));
    link_button("x", BrandLogo::X, "X / SeregonWar", "https://x.com/SeregonWar",
                link_width);
    ImGui::Dummy(ImVec2(0, link_gap));
    link_button("bluesky", BrandLogo::Bluesky, "Bluesky",
                "https://bsky.app/profile/seregonwar.bsky.social",
                link_width);
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  section_header(locale::tr("app.title"), icons::kShield);
  ImGui::TextWrapped("%s", locale::tr("credits.description"));
  ImGui::Spacing();
  ImGui::TextWrapped("%s", locale::tr("credits.license"));

  ui::end_panel();
}

} // namespace memdbg::frontend

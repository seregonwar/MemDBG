/*
 * MemDBG - Shared ImGui widgets and theme.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_UI_WIDGETS_HPP
#define MEMDBG_FRONTEND_UI_WIDGETS_HPP

#include "imgui.h"
#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::frontend { struct HelloInfo; }

namespace memdbg::frontend::ui {

struct Palette {
  ImVec4 bg0 = ImVec4(7.0f / 255.0f, 10.0f / 255.0f, 14.0f / 255.0f, 1.0f);
  ImVec4 bg1 = ImVec4(13.0f / 255.0f, 18.0f / 255.0f, 24.0f / 255.0f, 1.0f);
  ImVec4 bg2 = ImVec4(22.0f / 255.0f, 29.0f / 255.0f, 36.0f / 255.0f, 1.0f);
  ImVec4 bg3 = ImVec4(32.0f / 255.0f, 42.0f / 255.0f, 52.0f / 255.0f, 1.0f);
  ImVec4 panel = ImVec4(12.0f / 255.0f, 16.0f / 255.0f, 22.0f / 255.0f, 0.93f);
  ImVec4 panel2 = ImVec4(18.0f / 255.0f, 24.0f / 255.0f, 31.0f / 255.0f, 0.96f);
  ImVec4 border = ImVec4(45.0f / 255.0f, 57.0f / 255.0f, 68.0f / 255.0f, 0.78f);
  ImVec4 border_hot = ImVec4(45.0f / 255.0f, 154.0f / 255.0f, 170.0f / 255.0f, 0.82f);
  ImVec4 text = ImVec4(238.0f / 255.0f, 244.0f / 255.0f, 246.0f / 255.0f, 1.0f);
  ImVec4 muted = ImVec4(158.0f / 255.0f, 174.0f / 255.0f, 184.0f / 255.0f, 1.0f);
  ImVec4 dim = ImVec4(91.0f / 255.0f, 108.0f / 255.0f, 121.0f / 255.0f, 1.0f);
  ImVec4 primary = ImVec4(28.0f / 255.0f, 184.0f / 255.0f, 196.0f / 255.0f, 1.0f);
  ImVec4 primary2 = ImVec4(118.0f / 255.0f, 232.0f / 255.0f, 224.0f / 255.0f, 1.0f);
  ImVec4 link = ImVec4(95.0f / 255.0f, 172.0f / 255.0f, 255.0f / 255.0f, 1.0f);
  ImVec4 success = ImVec4(68.0f / 255.0f, 207.0f / 255.0f, 127.0f / 255.0f, 1.0f);
  ImVec4 warning = ImVec4(244.0f / 255.0f, 171.0f / 255.0f, 75.0f / 255.0f, 1.0f);
  ImVec4 danger = ImVec4(239.0f / 255.0f, 82.0f / 255.0f, 97.0f / 255.0f, 1.0f);
};

const Palette &colors();
ImU32 color_u32(const ImVec4 &color);
void apply_theme();

void draw_background(ImDrawList *draw_list, ImVec2 pos, ImVec2 size);

void text_muted(const char *text);
void text_dim(const char *text);
void section_label(const char *title);

void begin_panel(const char *id, const char *title, ImVec2 size);
void end_panel();

void status_dot(ImVec4 color);

bool styled_button(const char *label, ImVec2 size, ImVec4 base, ImVec4 hover, ImVec4 active);
bool primary_button(const char *label, ImVec2 size);
bool soft_button(const char *label, ImVec2 size);
bool danger_button(const char *label, ImVec2 size);
ImVec2 full_button(float height);

void draw_empty_state(const char *title, const char *message);
void draw_hex_view(const std::vector<uint8_t> &data, uint64_t base);
void draw_capabilities(const ::memdbg::frontend::HelloInfo &hello);
void draw_scan_progress(const std::string &label, const char *icon, double elapsed, float bar_width);

} // namespace memdbg::frontend::ui

#endif /* MEMDBG_FRONTEND_UI_WIDGETS_HPP */

/*
 * MemDBG - Shared ImGui widgets and theme.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_UI_WIDGETS_HPP
#define MEMDBG_FRONTEND_UI_WIDGETS_HPP

#include "imgui.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace memdbg::frontend { struct HelloInfo; }

namespace memdbg::frontend::ui {

struct Palette {
  ImVec4 bg0 = ImVec4(14.0f / 255.0f, 15.0f / 255.0f, 16.0f / 255.0f, 1.0f);
  ImVec4 bg1 = ImVec4(22.0f / 255.0f, 23.0f / 255.0f, 25.0f / 255.0f, 1.0f);
  ImVec4 bg2 = ImVec4(31.0f / 255.0f, 33.0f / 255.0f, 35.0f / 255.0f, 1.0f);
  ImVec4 bg3 = ImVec4(43.0f / 255.0f, 46.0f / 255.0f, 49.0f / 255.0f, 1.0f);
  ImVec4 panel = ImVec4(20.0f / 255.0f, 21.0f / 255.0f, 23.0f / 255.0f, 1.0f);
  ImVec4 panel2 = ImVec4(25.0f / 255.0f, 27.0f / 255.0f, 29.0f / 255.0f, 1.0f);
  ImVec4 border = ImVec4(62.0f / 255.0f, 66.0f / 255.0f, 70.0f / 255.0f, 0.95f);
  ImVec4 border_hot = ImVec4(52.0f / 255.0f, 151.0f / 255.0f, 112.0f / 255.0f, 0.95f);
  ImVec4 text = ImVec4(226.0f / 255.0f, 229.0f / 255.0f, 232.0f / 255.0f, 1.0f);
  ImVec4 muted = ImVec4(166.0f / 255.0f, 172.0f / 255.0f, 177.0f / 255.0f, 1.0f);
  ImVec4 dim = ImVec4(105.0f / 255.0f, 111.0f / 255.0f, 116.0f / 255.0f, 1.0f);
  ImVec4 primary = ImVec4(38.0f / 255.0f, 139.0f / 255.0f, 96.0f / 255.0f, 1.0f);
  ImVec4 primary2 = ImVec4(113.0f / 255.0f, 221.0f / 255.0f, 150.0f / 255.0f, 1.0f);
  ImVec4 link = ImVec4(102.0f / 255.0f, 163.0f / 255.0f, 255.0f / 255.0f, 1.0f);
  ImVec4 success = ImVec4(91.0f / 255.0f, 207.0f / 255.0f, 122.0f / 255.0f, 1.0f);
  ImVec4 warning = ImVec4(230.0f / 255.0f, 178.0f / 255.0f, 77.0f / 255.0f, 1.0f);
  ImVec4 danger = ImVec4(225.0f / 255.0f, 87.0f / 255.0f, 93.0f / 255.0f, 1.0f);
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
void draw_hex_view(const std::vector<uint8_t> &data, uint64_t base,
                    const std::function<void(uint64_t)> &on_address_clicked = {});
void draw_capabilities(const ::memdbg::frontend::HelloInfo &hello);
void draw_scan_progress(const std::string &label, const char *icon, double elapsed, float bar_width);

} // namespace memdbg::frontend::ui

#endif /* MEMDBG_FRONTEND_UI_WIDGETS_HPP */

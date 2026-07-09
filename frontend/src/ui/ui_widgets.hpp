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
  ImVec4 bg0 = ImVec4(16.0f / 255.0f, 17.0f / 255.0f, 18.0f / 255.0f, 1.0f);
  ImVec4 bg1 = ImVec4(24.0f / 255.0f, 26.0f / 255.0f, 27.0f / 255.0f, 1.0f);
  ImVec4 bg2 = ImVec4(32.0f / 255.0f, 35.0f / 255.0f, 36.0f / 255.0f, 1.0f);
  ImVec4 bg3 = ImVec4(45.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f);
  ImVec4 panel = ImVec4(22.0f / 255.0f, 24.0f / 255.0f, 25.0f / 255.0f, 1.0f);
  ImVec4 panel2 = ImVec4(28.0f / 255.0f, 31.0f / 255.0f, 32.0f / 255.0f, 1.0f);
  ImVec4 border = ImVec4(73.0f / 255.0f, 80.0f / 255.0f, 81.0f / 255.0f, 0.95f);
  ImVec4 border_hot = ImVec4(79.0f / 255.0f, 220.0f / 255.0f, 145.0f / 255.0f, 0.95f);
  ImVec4 text = ImVec4(252.0f / 255.0f, 254.0f / 255.0f, 253.0f / 255.0f, 1.0f);
  ImVec4 muted = ImVec4(214.0f / 255.0f, 222.0f / 255.0f, 220.0f / 255.0f, 1.0f);
  ImVec4 dim = ImVec4(156.0f / 255.0f, 168.0f / 255.0f, 166.0f / 255.0f, 1.0f);
  ImVec4 primary = ImVec4(39.0f / 255.0f, 164.0f / 255.0f, 103.0f / 255.0f, 1.0f);
  ImVec4 primary2 = ImVec4(119.0f / 255.0f, 244.0f / 255.0f, 166.0f / 255.0f, 1.0f);
  ImVec4 link = ImVec4(154.0f / 255.0f, 202.0f / 255.0f, 255.0f / 255.0f, 1.0f);
  ImVec4 success = ImVec4(104.0f / 255.0f, 238.0f / 255.0f, 148.0f / 255.0f, 1.0f);
  ImVec4 warning = ImVec4(239.0f / 255.0f, 192.0f / 255.0f, 86.0f / 255.0f, 1.0f);
  ImVec4 danger = ImVec4(241.0f / 255.0f, 95.0f / 255.0f, 100.0f / 255.0f, 1.0f);
};

Palette &mutable_colors();
const Palette &colors();
void set_palette(const Palette &palette);
ImU32 color_u32(const ImVec4 &color);
void apply_theme();
float dpi_scale();
void set_dpi_scale(float scale);

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

/* ---- Reusable file/folder picker widgets ---- */

struct FilePathOptions {
  const char *label = nullptr;      /* label text (null = no label) */
  const char *id = "##FilePath";   /* ImGui ID */
  const char *dialog_title = "Select File";
  const char *filter_desc = "All Files";
  const char *filter_ext = "*.*";
  const char *default_name = nullptr; /* for save dialogs */
  const char *placeholder = nullptr;  /* input hint text */
  ImVec2 button_size = {};          /* {} = default 42x0 (auto height) */
  bool save_mode = false;           /* use Save dialog instead of Open */
  bool folder_mode = false;         /* pick folder instead of file */
};

/// Reusable labeled file/folder path input with browse button.
/// Returns true if a file/folder was picked this frame.
bool file_path_input(char *buffer, size_t buffer_size,
                     const FilePathOptions &opts = {});

/// Standalone button that opens a file-open dialog.
/// Returns the selected path (empty if cancelled).
std::string file_open_button(const char *label, const FilePathOptions &opts = {});

/// Standalone button that opens a file-save dialog.
/// Returns the selected path (empty if cancelled).
std::string file_save_button(const char *label, const FilePathOptions &opts = {});

} // namespace memdbg::frontend::ui

#endif /* MEMDBG_FRONTEND_UI_WIDGETS_HPP */

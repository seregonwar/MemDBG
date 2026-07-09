/*
 * MemDBG - Shared ImGui widgets and theme implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "file_picker.hpp"
#include "locale/locale.hpp"

#include "core/client/memdbg_client.hpp"
#include "memdbg/core/memdbg_protocol.h"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace memdbg::frontend::ui {

static float s_dpi_scale = 1.0f;
static Palette s_active_palette;

Palette &mutable_colors() {
  return s_active_palette;
}

const Palette &colors() {
  return s_active_palette;
}

void set_palette(const Palette &palette) {
  s_active_palette = palette;
}

ImU32 color_u32(const ImVec4 &color) {
  return ImGui::ColorConvertFloat4ToU32(color);
}

float dpi_scale() {
  return s_dpi_scale;
}

void set_dpi_scale(float scale) {
  if (scale < 0.25f) scale = 0.25f;
  if (scale > 4.0f) scale = 4.0f;
  s_dpi_scale = scale;
}

void apply_theme() {
  const auto &p = colors();
  ImGui::StyleColorsDark();
  ImGuiStyle &style = ImGui::GetStyle();
  ImVec4 *c = style.Colors;

  c[ImGuiCol_Text] = p.text;
  c[ImGuiCol_TextDisabled] = p.dim;
  c[ImGuiCol_WindowBg] = p.bg0;
  c[ImGuiCol_ChildBg] = p.panel;
  c[ImGuiCol_PopupBg] = p.bg1;
  c[ImGuiCol_Border] = p.border;
  c[ImGuiCol_BorderShadow] = ImVec4(0,0,0,0);
  c[ImGuiCol_FrameBg] = p.bg2;
  c[ImGuiCol_FrameBgHovered] = p.bg3;
  c[ImGuiCol_FrameBgActive] = p.primary;
  c[ImGuiCol_ScrollbarBg] = p.bg0;
  c[ImGuiCol_ScrollbarGrab] = p.bg3;
  c[ImGuiCol_ScrollbarGrabHovered] = p.dim;
  c[ImGuiCol_ScrollbarGrabActive] = p.primary;
  c[ImGuiCol_CheckMark] = p.primary2;
  c[ImGuiCol_SliderGrab] = p.primary;
  c[ImGuiCol_SliderGrabActive] = p.primary2;
  c[ImGuiCol_Button] = p.bg2;
  c[ImGuiCol_ButtonHovered] = p.primary;
  c[ImGuiCol_ButtonActive] = p.primary2;
  c[ImGuiCol_Header] = p.bg2;
  c[ImGuiCol_HeaderHovered] = p.primary;
  c[ImGuiCol_HeaderActive] = p.primary2;
  c[ImGuiCol_Separator] = p.border;
  c[ImGuiCol_SeparatorHovered] = p.primary;
  c[ImGuiCol_SeparatorActive] = p.primary2;
  c[ImGuiCol_ResizeGrip] = p.bg3;
  c[ImGuiCol_ResizeGripHovered] = p.primary2;
  c[ImGuiCol_ResizeGripActive] = p.primary;
  c[ImGuiCol_Tab] = p.bg1;
  c[ImGuiCol_TabHovered] = p.primary;
  c[ImGuiCol_TabActive] = p.bg2;
  c[ImGuiCol_TableHeaderBg] = p.bg1;
  c[ImGuiCol_TableBorderStrong] = p.border_hot;
  c[ImGuiCol_TableBorderLight] = p.border;
  c[ImGuiCol_TableRowBg] = ImVec4(0,0,0,0);
  c[ImGuiCol_TableRowBgAlt] = ImVec4(1,1,1,0.045f);
  c[ImGuiCol_TextSelectedBg] = ImVec4(p.primary2.x, p.primary2.y, p.primary2.z, 0.34f);

  style.WindowPadding = ImVec2(0, 0);
  style.FramePadding = ImVec2(7, 4);
  style.CellPadding = ImVec2(6, 3);
  style.ItemSpacing = ImVec2(6, 4);
  style.ItemInnerSpacing = ImVec2(6, 4);
  style.ScrollbarSize = 11.0f;
  style.WindowBorderSize = 0.0f;
  style.ChildBorderSize = 1.0f;
  style.PopupBorderSize = 1.0f;
  style.FrameBorderSize = 1.0f;
  style.WindowRounding = 0.0f;
  style.ChildRounding = 2.0f;
  style.FrameRounding = 2.0f;
  style.PopupRounding = 2.0f;
  style.ScrollbarRounding = 2.0f;
  style.GrabRounding = 2.0f;
  style.TabRounding = 2.0f;
  style.AntiAliasedLines = true;
  style.AntiAliasedLinesUseTex = true;
  style.AntiAliasedFill = true;
  style.CurveTessellationTol = 1.05f;
  style.CircleTessellationMaxError = 0.20f;
}

void draw_background(ImDrawList *draw_list, ImVec2 pos, ImVec2 size) {
  const auto &p = colors();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  draw_list->AddRectFilled(pos, max, color_u32(p.bg0));
  draw_list->AddRectFilled(ImVec2(pos.x, pos.y), ImVec2(max.x, pos.y + 1.0f * dpi_scale()),
                           color_u32(p.border_hot));
}

void text_muted(const char *text) { ImGui::TextColored(colors().muted, "%s", text); }
void text_dim(const char *text)   { ImGui::TextColored(colors().dim, "%s", text); }

void section_label(const char *title) {
  ImGui::TextColored(colors().muted, "%s", title);
  ImGui::Separator();
}

void begin_panel(const char *id, const char *title, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, colors().panel2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8,7));
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 2.0f);
  ImGui::BeginChild(id, size, true);
  section_label(title);
}

void end_panel() {
  ImGui::EndChild();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

void status_dot(ImVec4 color) {
  const float scl = dpi_scale();
  ImDrawList *draw_list = ImGui::GetWindowDrawList();
  ImVec2 cursor = ImGui::GetCursorScreenPos();
  draw_list->AddCircleFilled(ImVec2(cursor.x + 6.0f * scl, cursor.y + 8.0f * scl), 5.0f * scl, color_u32(color));
  ImGui::Dummy(ImVec2(16.0f * scl, 16.0f * scl));
}

bool styled_button(const char *label, ImVec2 size, ImVec4 base, ImVec4 hover, ImVec4 active) {
  ImGui::PushStyleColor(ImGuiCol_Button, base);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hover);
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, active);
  bool pressed = ImGui::Button(label, size);
  ImGui::PopStyleColor(3);
  return pressed;
}

bool primary_button(const char *label, ImVec2 size) {
  const auto &p = colors();
  return styled_button(label, size, p.primary, p.primary2, p.primary);
}

bool soft_button(const char *label, ImVec2 size) {
  const auto &p = colors();
  return styled_button(label, size, p.bg2, p.bg3, p.primary);
}

bool danger_button(const char *label, ImVec2 size) {
  const auto &p = colors();
  return styled_button(label, size,
    ImVec4(p.danger.x * 0.5f, p.danger.y * 0.5f, p.danger.z * 0.5f, 1.0f),
    p.danger,
    ImVec4(p.danger.x * 0.8f, p.danger.y * 0.8f, p.danger.z * 0.8f, 1.0f));
}

ImVec2 full_button(float height) {
  return ImVec2(ImGui::GetContentRegionAvail().x, height * dpi_scale());
}

void draw_empty_state(const char *title, const char *message) {
  ImGui::Spacing();
  ImGui::TextColored(colors().muted, "%s", locale::tr(title));
  ImGui::TextWrapped("%s", locale::tr(message));
}

void draw_hex_view(const std::vector<uint8_t> &data, uint64_t base,
                    const std::function<void(uint64_t)> &on_address_clicked) {
  if (data.empty()) {
    draw_empty_state("common.no_memory_buffer", "common.no_memory_desc");
    return;
  }

  /* Copy entire buffer as pure hex */
  if (soft_button((std::string(icons::kCopy) + "  Copy Hex").c_str(),
                      ImVec2(140.0f * dpi_scale(), 30.0f * dpi_scale()))) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < data.size(); ++i) {
      if (i > 0) oss << ' ';
      oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    ImGui::SetClipboardText(oss.str().c_str());
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("Copy %zu bytes as space-separated hex", data.size());
  ImGui::Spacing();

  if (ImGui::BeginTable("hex_view", 3,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable,
        ImVec2(0,0))) {
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 130);
    ImGui::TableSetupColumn("Hex");
    ImGui::TableSetupColumn("ASCII", ImGuiTableColumnFlags_WidthFixed, 150);
    ImGui::TableHeadersRow();
    for (size_t row = 0; row < data.size(); row += 16U) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase << std::setw(0) << (base+row);
        const std::string addr_str = oss.str();
        ImGui::TextUnformatted(addr_str.c_str());
        if (ImGui::IsItemHovered()) {
          if (on_address_clicked)
            ImGui::SetTooltip("Click to jump to %s", addr_str.c_str());
          else
            ImGui::SetTooltip("Click to copy: %s", addr_str.c_str());
        }
        if (ImGui::IsItemClicked()) {
          const uint64_t row_addr = base + row;
          if (on_address_clicked)
            on_address_clicked(row_addr);
          else
            ImGui::SetClipboardText(addr_str.c_str());
        }
      }
      ImGui::TableSetColumnIndex(1);
      {
        std::ostringstream hex;
        for (size_t i = 0; i < 16U; ++i) {
          if (row + i < data.size())
            hex << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned>(data[row+i]) << ' ';
          else hex << "   ";
        }
        ImGui::TextUnformatted(hex.str().c_str());
        if (ImGui::IsItemHovered()) {
          size_t end = std::min(row + 15U, data.size() - 1U);
          ImGui::SetTooltip("+0x%zX \xe2\x80\x93 +0x%zX  (%zu bytes)",
                            row, end, end - row + 1U);
        }
      }
      ImGui::TableSetColumnIndex(2);
      {
        char ascii[17]{};
        for (size_t i = 0; i < 16U && row+i < data.size(); ++i) {
          unsigned char c = data[row+i];
          ascii[i] = std::isprint(c)!=0 ? static_cast<char>(c) : '.';
        }
        ImGui::TextUnformatted(ascii);
        if (ImGui::IsItemHovered()) {
          std::ostringstream tip;
          tip << "0x" << std::hex << std::uppercase << (base + row);
          ImGui::SetTooltip("%s +%zu", tip.str().c_str(), row);
        }
      }
    }
    ImGui::EndTable();
  }
}

void draw_capabilities(const memdbg::frontend::HelloInfo &hello) {
  if (hello.protocol_version == 0) {
    text_dim(locale::tr("common.payload_details_after_hello"));
    return;
  }
  ImGui::Text("%s %s %s", locale::tr("common.payload"), hello.name.c_str(), hello.version.c_str());
  ImGui::Text("%s: %s", locale::tr("common.platform"), memdbg::frontend::platform_name(hello.platform_id).c_str());
  ImGui::Text("Debug port: %u", static_cast<unsigned>(hello.debug_port));
  ImGui::Text("UDP log port: %u", static_cast<unsigned>(hello.udp_log_port));
  ImGui::Spacing();
  ImGui::TextWrapped("Capabilities: %s", memdbg::frontend::capability_text(hello.capabilities).c_str());
}

void draw_scan_progress(const std::string &label, const char *icon, double elapsed, float bar_width) {
  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  ImGui::TextColored(colors().primary2, "%s  %s...", icon, label.c_str());

  const float bar_h = 8.0f;
  ImVec2 cursor = ImGui::GetCursorScreenPos();
  ImDrawList *dl = ImGui::GetWindowDrawList();

  /* Track background */
  dl->AddRectFilled(cursor, ImVec2(cursor.x + bar_width, cursor.y + bar_h),
                    color_u32(colors().bg3), bar_h * 0.5f);

  /* Animated fill segment — ping-pong between 0 and 1 */
  float t = static_cast<float>(std::fmod(elapsed * 2.2, 2.0));
  if (t > 1.0f) t = 2.0f - t;  /* ping-pong */
  float seg_w = bar_width * 0.28f;
  float seg_x = (bar_width - seg_w) * t;

  dl->AddRectFilled(ImVec2(cursor.x + seg_x, cursor.y),
                    ImVec2(cursor.x + seg_x + seg_w, cursor.y + bar_h),
                    color_u32(colors().primary2), bar_h * 0.5f);

  ImGui::SetCursorScreenPos(ImVec2(cursor.x, cursor.y + bar_h + 8.0f));

  /* Elapsed time */
  if (elapsed < 60.0)
    ImGui::TextColored(colors().muted, "Elapsed: %.1fs", elapsed);
  else {
    int mins = static_cast<int>(elapsed) / 60;
    int secs = static_cast<int>(elapsed) % 60;
    ImGui::TextColored(colors().muted, "Elapsed: %dm %ds", mins, secs);
  }
}

/* ---- Reusable file/folder picker widgets ---- */

bool file_path_input(char *buffer, size_t buffer_size,
                     const FilePathOptions &opts) {
  const float scl = dpi_scale();
  const float btn_w = opts.button_size.x > 0 ? opts.button_size.x : 42.0f * scl;
  const float btn_h = opts.button_size.y > 0 ? opts.button_size.y : 0.0f;
  bool picked = false;

  if (opts.label != nullptr)
    ImGui::TextColored(colors().muted, "%s", opts.label);

  if (ImGui::BeginTable(opts.id, 2,
        ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_PadOuterX)) {
    ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Btn", ImGuiTableColumnFlags_WidthFixed, btn_w + 8.0f * scl);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::SetNextItemWidth(-1.0f);
    const char *hint = opts.placeholder ? opts.placeholder : "";
    ImGui::InputTextWithHint(opts.id, hint, buffer, buffer_size);
    ImGui::TableSetColumnIndex(1);

    const char *icon = icons::kLoad;
    if (ImGui::Button((std::string(icon) + "##" + opts.id + "_btn").c_str(),
                      ImVec2(btn_w, btn_h))) {
      std::string result;
      if (opts.folder_mode)
        result = pickFolder(opts.dialog_title);
      else if (opts.save_mode)
        result = pickSaveFile(opts.dialog_title, opts.default_name ? opts.default_name : "",
                              opts.filter_desc, opts.filter_ext);
      else
        result = pickFile(opts.dialog_title, opts.filter_desc, opts.filter_ext);
      if (!result.empty()) {
        std::snprintf(buffer, buffer_size, "%s", result.c_str());
        picked = true;
      }
    }
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", opts.dialog_title);
    ImGui::EndTable();
  }
  return picked;
}

std::string file_open_button(const char *label, const FilePathOptions &opts) {
  const float scl = dpi_scale();
  const float btn_w = opts.button_size.x > 0 ? opts.button_size.x : 0;
  const float btn_h = opts.button_size.y > 0 ? opts.button_size.y : 0;
  ImVec2 size(btn_w, btn_h);
  if (btn_w <= 0) size.x = ImGui::CalcTextSize(label).x + 24.0f * scl;

  std::string result;
  if (soft_button(label, size)) {
    if (opts.folder_mode)
      result = pickFolder(opts.dialog_title);
    else if (opts.save_mode)
      result = pickSaveFile(opts.dialog_title, opts.default_name ? opts.default_name : "",
                            opts.filter_desc, opts.filter_ext);
    else
      result = pickFile(opts.dialog_title, opts.filter_desc, opts.filter_ext);
  }
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", opts.dialog_title);
  return result;
}

std::string file_save_button(const char *label, const FilePathOptions &opts) {
  FilePathOptions save_opts = opts;
  save_opts.save_mode = true;
  return file_open_button(label, save_opts);
}

} // namespace memdbg::frontend::ui

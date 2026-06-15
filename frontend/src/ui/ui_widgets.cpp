/*
 * MemDBG - Shared ImGui widgets and theme implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ui_widgets.hpp"

#include "memdbg_client.hpp"
#include "memdbg/core/memdbg_protocol.h"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace memdbg::frontend::ui {

const Palette &colors() {
  static Palette palette;
  return palette;
}

ImU32 color_u32(const ImVec4 &color) {
  return ImGui::ColorConvertFloat4ToU32(color);
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
  c[ImGuiCol_PopupBg] = ImVec4(9.0f/255.0f,13.0f/255.0f,18.0f/255.0f,0.98f);
  c[ImGuiCol_Border] = p.border;
  c[ImGuiCol_BorderShadow] = ImVec4(0,0,0,0);
  c[ImGuiCol_FrameBg] = ImVec4(24.0f/255.0f, 34.0f/255.0f, 42.0f/255.0f, 1.0f);
  c[ImGuiCol_FrameBgHovered] = ImVec4(32.0f/255.0f, 46.0f/255.0f, 56.0f/255.0f, 1.0f);
  c[ImGuiCol_FrameBgActive] = ImVec4(38.0f/255.0f, 58.0f/255.0f, 70.0f/255.0f, 1.0f);
  c[ImGuiCol_ScrollbarBg] = ImVec4(7.0f/255.0f,10.0f/255.0f,14.0f/255.0f,0.65f);
  c[ImGuiCol_ScrollbarGrab] = ImVec4(44.0f/255.0f,58.0f/255.0f,69.0f/255.0f,1.0f);
  c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(58.0f/255.0f,78.0f/255.0f,91.0f/255.0f,1.0f);
  c[ImGuiCol_ScrollbarGrabActive] = p.primary;
  c[ImGuiCol_CheckMark] = p.primary2;
  c[ImGuiCol_SliderGrab] = p.primary;
  c[ImGuiCol_SliderGrabActive] = p.primary2;
  c[ImGuiCol_Button] = ImVec4(30.0f/255.0f, 42.0f/255.0f, 52.0f/255.0f, 1.0f);
  c[ImGuiCol_ButtonHovered] = ImVec4(40.0f/255.0f, 68.0f/255.0f, 80.0f/255.0f, 1.0f);
  c[ImGuiCol_ButtonActive] = ImVec4(24.0f/255.0f, 120.0f/255.0f, 134.0f/255.0f, 1.0f);
  c[ImGuiCol_Header] = ImVec4(30.0f/255.0f, 42.0f/255.0f, 52.0f/255.0f, 1.0f);
  c[ImGuiCol_HeaderHovered] = ImVec4(40.0f/255.0f, 68.0f/255.0f, 80.0f/255.0f, 1.0f);
  c[ImGuiCol_HeaderActive] = ImVec4(26.0f/255.0f, 112.0f/255.0f, 126.0f/255.0f, 1.0f);
  c[ImGuiCol_Separator] = p.border;
  c[ImGuiCol_SeparatorHovered] = p.primary;
  c[ImGuiCol_SeparatorActive] = p.primary2;
  c[ImGuiCol_ResizeGrip] = ImVec4(45.0f/255.0f,91.0f/255.0f,101.0f/255.0f,0.47f);
  c[ImGuiCol_ResizeGripHovered] = ImVec4(28.0f/255.0f,184.0f/255.0f,196.0f/255.0f,0.70f);
  c[ImGuiCol_ResizeGripActive] = p.primary;
  c[ImGuiCol_Tab] = p.bg1;
  c[ImGuiCol_TabHovered] = ImVec4(36.0f/255.0f,63.0f/255.0f,74.0f/255.0f,1.0f);
  c[ImGuiCol_TabActive] = ImVec4(26.0f/255.0f,47.0f/255.0f,57.0f/255.0f,1.0f);
  c[ImGuiCol_TableHeaderBg] = ImVec4(24.0f/255.0f,34.0f/255.0f,42.0f/255.0f,1.0f);
  c[ImGuiCol_TableBorderStrong] = p.border_hot;
  c[ImGuiCol_TableBorderLight] = p.border;
  c[ImGuiCol_TableRowBg] = ImVec4(0,0,0,0);
  c[ImGuiCol_TableRowBgAlt] = ImVec4(1,1,1,0.025f);
  c[ImGuiCol_TextSelectedBg] = ImVec4(28.0f/255.0f,184.0f/255.0f,196.0f/255.0f,0.30f);

  style.WindowPadding = ImVec2(0, 0);
  style.FramePadding = ImVec2(14, 9);
  style.CellPadding = ImVec2(10, 9);
  style.ItemSpacing = ImVec2(10, 9);
  style.ItemInnerSpacing = ImVec2(8, 7);
  style.ScrollbarSize = 12.0f;
  style.WindowBorderSize = 0.0f;
  style.ChildBorderSize = 1.0f;
  style.PopupBorderSize = 1.0f;
  style.FrameBorderSize = 1.0f;
  style.WindowRounding = 0.0f;
  style.ChildRounding = 10.0f;
  style.FrameRounding = 8.0f;
  style.PopupRounding = 10.0f;
  style.ScrollbarRounding = 10.0f;
  style.GrabRounding = 10.0f;
  style.TabRounding = 8.0f;
}

void draw_background(ImDrawList *draw_list, ImVec2 pos, ImVec2 size) {
  const auto &p = colors();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  draw_list->AddRectFilled(pos, max, color_u32(p.bg0));
  draw_list->AddRectFilledMultiColor(
      pos, max,
      IM_COL32(10,28,34,245),
      IM_COL32(7,10,14,255),
      IM_COL32(7,10,14,255),
      IM_COL32(7,10,14,255));
  const float grid = 52.0f;
  const ImU32 grid_color = IM_COL32(28,184,196,10);
  for (float x = pos.x; x < max.x; x += grid)
    draw_list->AddLine(ImVec2(x, pos.y), ImVec2(x, max.y), grid_color);
  for (float y = pos.y; y < max.y; y += grid)
    draw_list->AddLine(ImVec2(pos.x, y), ImVec2(max.x, y), grid_color);
}

void text_muted(const char *text) { ImGui::TextColored(colors().muted, "%s", text); }
void text_dim(const char *text)   { ImGui::TextColored(colors().dim, "%s", text); }

void section_label(const char *title) {
  ImGui::TextColored(colors().muted, "%s", title);
  ImGui::Separator();
  ImGui::Spacing();
}

void begin_panel(const char *id, const char *title, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, colors().panel2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18,18));
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
  ImGui::BeginChild(id, size, true);
  section_label(title);
}

void end_panel() {
  ImGui::EndChild();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

void status_dot(ImVec4 color) {
  ImDrawList *draw_list = ImGui::GetWindowDrawList();
  ImVec2 cursor = ImGui::GetCursorScreenPos();
  draw_list->AddCircleFilled(ImVec2(cursor.x+6.0f, cursor.y+8.0f), 5.0f, color_u32(color));
  ImGui::Dummy(ImVec2(16.0f, 16.0f));
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
  return styled_button(label, size, p.primary, p.primary2,
                       ImVec4(16.0f/255.0f,128.0f/255.0f,142.0f/255.0f,1.0f));
}

bool soft_button(const char *label, ImVec2 size) {
  return styled_button(label, size,
    ImVec4(26.0f/255.0f,36.0f/255.0f,44.0f/255.0f,1.0f),
    ImVec4(38.0f/255.0f,62.0f/255.0f,72.0f/255.0f,1.0f),
    ImVec4(28.0f/255.0f,98.0f/255.0f,110.0f/255.0f,1.0f));
}

bool danger_button(const char *label, ImVec2 size) {
  return styled_button(label, size,
    ImVec4(78.0f/255.0f,28.0f/255.0f,40.0f/255.0f,1.0f),
    colors().danger,
    ImVec4(140.0f/255.0f,42.0f/255.0f,55.0f/255.0f,1.0f));
}

ImVec2 full_button(float height) {
  return ImVec2(ImGui::GetContentRegionAvail().x, height);
}

void draw_empty_state(const char *title, const char *message) {
  ImGui::Spacing();
  ImGui::TextColored(colors().muted, "%s", title);
  ImGui::TextWrapped("%s", message);
}

void draw_hex_view(const std::vector<uint8_t> &data, uint64_t base) {
  if (data.empty()) {
    draw_empty_state("No memory buffer", "Read memory from the selected process to populate this view.");
    return;
  }
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
        ImGui::TextUnformatted(oss.str().c_str());
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
      }
      ImGui::TableSetColumnIndex(2);
      {
        char ascii[17]{};
        for (size_t i = 0; i < 16U && row+i < data.size(); ++i) {
          unsigned char c = data[row+i];
          ascii[i] = std::isprint(c)!=0 ? static_cast<char>(c) : '.';
        }
        ImGui::TextUnformatted(ascii);
      }
    }
    ImGui::EndTable();
  }
}

void draw_capabilities(const memdbg::frontend::HelloInfo &hello) {
  if (hello.protocol_version == 0) {
    text_dim("Payload details will appear after HELLO.");
    return;
  }
  ImGui::Text("Payload: %s %s", hello.name.c_str(), hello.version.c_str());
  ImGui::Text("Platform: %s", memdbg::frontend::platform_name(hello.platform_id).c_str());
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

} // namespace memdbg::frontend::ui

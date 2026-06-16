/*
 * MemDBG - Shared ImGui widgets and theme implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "locale/locale.hpp"

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
  c[ImGuiCol_PopupBg] = ImVec4(24.0f/255.0f,26.0f/255.0f,27.0f/255.0f,0.99f);
  c[ImGuiCol_Border] = p.border;
  c[ImGuiCol_BorderShadow] = ImVec4(0,0,0,0);
  c[ImGuiCol_FrameBg] = ImVec4(43.0f/255.0f, 47.0f/255.0f, 48.0f/255.0f, 1.0f);
  c[ImGuiCol_FrameBgHovered] = ImVec4(58.0f/255.0f, 70.0f/255.0f, 64.0f/255.0f, 1.0f);
  c[ImGuiCol_FrameBgActive] = ImVec4(46.0f/255.0f, 119.0f/255.0f, 76.0f/255.0f, 1.0f);
  c[ImGuiCol_ScrollbarBg] = ImVec4(17.0f/255.0f,18.0f/255.0f,19.0f/255.0f,0.92f);
  c[ImGuiCol_ScrollbarGrab] = ImVec4(67.0f/255.0f,73.0f/255.0f,74.0f/255.0f,1.0f);
  c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(91.0f/255.0f,101.0f/255.0f,98.0f/255.0f,1.0f);
  c[ImGuiCol_ScrollbarGrabActive] = p.primary;
  c[ImGuiCol_CheckMark] = p.primary2;
  c[ImGuiCol_SliderGrab] = p.primary;
  c[ImGuiCol_SliderGrabActive] = p.primary2;
  c[ImGuiCol_Button] = ImVec4(45.0f/255.0f, 50.0f/255.0f, 51.0f/255.0f, 1.0f);
  c[ImGuiCol_ButtonHovered] = ImVec4(62.0f/255.0f, 82.0f/255.0f, 71.0f/255.0f, 1.0f);
  c[ImGuiCol_ButtonActive] = ImVec4(42.0f/255.0f, 136.0f/255.0f, 84.0f/255.0f, 1.0f);
  c[ImGuiCol_Header] = ImVec4(45.0f/255.0f, 49.0f/255.0f, 50.0f/255.0f, 1.0f);
  c[ImGuiCol_HeaderHovered] = ImVec4(61.0f/255.0f, 83.0f/255.0f, 70.0f/255.0f, 1.0f);
  c[ImGuiCol_HeaderActive] = ImVec4(38.0f/255.0f, 121.0f/255.0f, 76.0f/255.0f, 1.0f);
  c[ImGuiCol_Separator] = p.border;
  c[ImGuiCol_SeparatorHovered] = p.primary;
  c[ImGuiCol_SeparatorActive] = p.primary2;
  c[ImGuiCol_ResizeGrip] = ImVec4(83.0f/255.0f,92.0f/255.0f,88.0f/255.0f,0.54f);
  c[ImGuiCol_ResizeGripHovered] = ImVec4(79.0f/255.0f,220.0f/255.0f,145.0f/255.0f,0.70f);
  c[ImGuiCol_ResizeGripActive] = p.primary;
  c[ImGuiCol_Tab] = p.bg1;
  c[ImGuiCol_TabHovered] = ImVec4(49.0f/255.0f,70.0f/255.0f,59.0f/255.0f,1.0f);
  c[ImGuiCol_TabActive] = ImVec4(38.0f/255.0f,55.0f/255.0f,46.0f/255.0f,1.0f);
  c[ImGuiCol_TableHeaderBg] = ImVec4(34.0f/255.0f,37.0f/255.0f,38.0f/255.0f,1.0f);
  c[ImGuiCol_TableBorderStrong] = p.border_hot;
  c[ImGuiCol_TableBorderLight] = p.border;
  c[ImGuiCol_TableRowBg] = ImVec4(0,0,0,0);
  c[ImGuiCol_TableRowBgAlt] = ImVec4(1,1,1,0.045f);
  c[ImGuiCol_TextSelectedBg] = ImVec4(79.0f/255.0f,220.0f/255.0f,145.0f/255.0f,0.34f);

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
}

void draw_background(ImDrawList *draw_list, ImVec2 pos, ImVec2 size) {
  const auto &p = colors();
  const ImVec2 max(pos.x + size.x, pos.y + size.y);
  draw_list->AddRectFilled(pos, max, color_u32(p.bg0));
  draw_list->AddRectFilled(ImVec2(pos.x, pos.y), ImVec2(max.x, pos.y + 1.0f),
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
                       ImVec4(31.0f/255.0f,125.0f/255.0f,78.0f/255.0f,1.0f));
}

bool soft_button(const char *label, ImVec2 size) {
  return styled_button(label, size,
    ImVec4(40.0f/255.0f,44.0f/255.0f,45.0f/255.0f,1.0f),
    ImVec4(55.0f/255.0f,73.0f/255.0f,64.0f/255.0f,1.0f),
    ImVec4(40.0f/255.0f,105.0f/255.0f,70.0f/255.0f,1.0f));
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
                      ImVec2(140, 30))) {
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

} // namespace memdbg::frontend::ui

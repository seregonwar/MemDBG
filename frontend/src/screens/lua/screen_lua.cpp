/*
 * MemDBG - Lua Console: interactive REPL + script editor with syntax-aware
 *          output, history, and save/load.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_icons.hpp"
#include "ui_widgets.hpp"
#include "locale/locale.hpp"

#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace memdbg::frontend {

// ── helpers ──────────────────────────────────────────────────────────────

static void lua_append_line(std::string &buf, const std::string &line) {
  if (!buf.empty() && buf.back() != '\n') buf.push_back('\n');
  buf += line;
  if (buf.size() > 128U * 1024U) {
    buf.erase(0, buf.size() - 96U * 1024U);
    const size_t nl = buf.find('\n');
    if (nl != std::string::npos && nl < buf.size())
      buf.erase(0, nl + 1U);
  }
}

// ── Lua syntax highlighter ───────────────────────────────────────────────

struct LuaToken {
  const char *start = nullptr;
  const char *end = nullptr;
  ImVec4 color;
};

static bool is_lua_keyword(const char *word, size_t len) {
  static const char *kws[] = {
    "and", "break", "do", "else", "elseif", "end", "false", "for",
    "function", "goto", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while", nullptr
  };
  for (int i = 0; kws[i]; ++i) {
    size_t kwlen = std::strlen(kws[i]);
    if (len == kwlen && std::strncmp(word, kws[i], len) == 0) return true;
  }
  return false;
}

static bool is_ident_start(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static bool is_ident_continue(char c) {
  return is_ident_start(c) || (c >= '0' && c <= '9');
}

// Tokenize a single line of Lua into coloured segments.
// Returns number of tokens written (clamped to max_tokens).
static int tokenize_lua_line(const char *line, LuaToken *tokens, int max_tokens,
                             ImVec4 kw, ImVec4 str_c, ImVec4 cmt, ImVec4 num,
                             ImVec4 def) {
  int count = 0;
  const char *p = line;
  while (*p && count < max_tokens) {
    // Skip whitespace (emit as default colour)
    if (*p == ' ' || *p == '\t') {
      const char *start = p;
      while (*p == ' ' || *p == '\t') ++p;
      tokens[count++] = {start, p, def};
      continue;
    }
    // Single-line comment
    if (p[0] == '-' && p[1] == '-') {
      if (p[2] == '[' && p[3] == '[') {
        // Multi-line comment --[[...]]  (no nesting in Lua)
        const char *start = p;
        p += 4; // skip --[[
        while (*p) {
          if (p[0] == ']' && p[1] == ']') { p += 2; break; }
          ++p;
        }
        tokens[count++] = {start, p, cmt};
      } else {
        const char *start = p;
        while (*p && *p != '\n') ++p;
        tokens[count++] = {start, p, cmt};
      }
      continue;
    }
    // String
    if (*p == '"' || *p == '\'') {
      char quote = *p;
      const char *start = p;
      ++p;
      while (*p && *p != quote) {
        if (*p == '\\') ++p; // skip escaped char
        if (*p) ++p;
      }
      if (*p == quote) ++p;
      tokens[count++] = {start, p, str_c};
      continue;
    }
    // Long string [[...]] or [=[...]=]  (no nesting in Lua)
    if (*p == '[' && (p[1] == '[' || p[1] == '=')) {
      const char *start = p;
      int eq = 0;
      while (p[1 + eq] == '=') ++eq;
      if (p[1 + eq] == '[') {
        p += 2 + eq; // skip opening delimiter
        // Find matching ]=...=]
        while (*p) {
          if (*p == ']') {
            int closing_eq = 0;
            while (p[1 + closing_eq] == '=') ++closing_eq;
            if (p[1 + closing_eq] == ']' && closing_eq == eq) {
              p += 2 + closing_eq;
              break;
            }
          }
          ++p;
        }
        tokens[count++] = {start, p, str_c};
        continue;
      }
      p = start; // not a long string, fall through
    }
    // Number
    if ((*p >= '0' && *p <= '9') || (*p == '.' && p[1] >= '0' && p[1] <= '9')) {
      const char *start = p;
      if (*p == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
               (*p >= 'A' && *p <= 'F')) ++p;
      } else {
        while (*p >= '0' && *p <= '9') ++p;
        if (*p == '.' && (p[1] >= '0' && p[1] <= '9')) { ++p; while (*p >= '0' && *p <= '9') ++p; }
        if (*p == 'e' || *p == 'E') {
          ++p;
          if (*p == '+' || *p == '-') ++p;
          while (*p >= '0' && *p <= '9') ++p;
        }
      }
      tokens[count++] = {start, p, num};
      continue;
    }
    // Identifier / keyword
    if (is_ident_start(*p)) {
      const char *start = p;
      while (is_ident_continue(*p)) ++p;
      size_t len = static_cast<size_t>(p - start);
      tokens[count++] = {start, p,
                         is_lua_keyword(start, len) ? kw : def};
      continue;
    }
    // Operator / punctuation (single char)
    const char *start = p;
    ++p;
    tokens[count++] = {start, p, def};
  }
  return count;
}

// Draw syntax-highlighted Lua text at position pos inside a clip rect of size.
static void draw_lua_highlighted(const char *text, ImVec2 pos, ImVec2 size,
                                 ImVec4 kw, ImVec4 str_c, ImVec4 cmt, ImVec4 num,
                                 ImVec4 def, const ImFont *font, float font_size,
                                 float scroll_x, float scroll_y) {
  if (!text || !*text || !font) return;
  ImDrawList *dl = ImGui::GetWindowDrawList();
  dl->PushClipRect(pos, ImVec2(pos.x + size.x, pos.y + size.y), true);

  float line_h = font_size * 1.4f;
  float x0 = pos.x - scroll_x;
  float y = pos.y - scroll_y;

  // Process line by line
  const char *p = text;
  while (*p) {
    // Find end of line
    const char *line_end = p;
    while (*line_end && *line_end != '\n') ++line_end;

    // Only draw lines visible in the clip rect
    if (y + line_h >= pos.y && y <= pos.y + size.y) {
      float x = x0;
      LuaToken tokens[128];
      int n = tokenize_lua_line(p, tokens, 128, kw, str_c, cmt, num, def);
      for (int i = 0; i < n; ++i) {
        if (tokens[i].start >= line_end) break;
        const char *seg_end =
            tokens[i].end < line_end ? tokens[i].end : line_end;
        int len = static_cast<int>(seg_end - tokens[i].start);
        if (len <= 0) continue;
        // Measure this segment
        std::string seg(tokens[i].start, static_cast<size_t>(len));
        ImVec2 text_size = font->CalcTextSizeA(font_size, FLT_MAX, 0.0f,
                                                seg.c_str(), seg.c_str() + len);
        dl->AddText(font, font_size, ImVec2(x, y),
                    ImGui::ColorConvertFloat4ToU32(tokens[i].color),
                    seg.c_str(), seg.c_str() + len);
        x += text_size.x;
      }
    }

    y += line_h;
    p = line_end;
    if (*p == '\n') ++p;
  }
  dl->PopClipRect();
}

// ── main draw ────────────────────────────────────────────────────────────

void draw_lua(AppState &state, ImVec2 avail) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();

  /* Wrap the entire Lua screen in a scrollable child window so content
   * never overflows and clips against the AppContent boundary. */
  ImGui::BeginChild("LuaScreen", avail, false,
                    ImGuiWindowFlags_HorizontalScrollbar);
  const ImVec2 inner_avail(ImGui::GetContentRegionAvail().x,
                           ImGui::GetContentRegionAvail().y);

  ImGui::Dummy(ImVec2(0, 4.0f * scl));

  /* ── Ensure LuaEngine is initialized ── */
  plugins::LuaEngine &lua = state.lua_engine;
  static bool lua_init_attempted = false;
  if (!lua.is_initialized() && !lua_init_attempted) {
    std::string err;
    if (!lua.init(&err)) {
      lua_append_line(state.lua_output, "Failed to initialize Lua: " + err);
    }
    lua.bind_api(state);
    lua_init_attempted = true;
    // Restore script from last session path
    if (state.lua_editor_text[0] == '\0' && !state.lua_last_script_path.empty()) {
      std::ifstream in(state.lua_last_script_path, std::ios::binary);
      if (in) {
        std::string content((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
        if (content.size() < sizeof(state.lua_editor_text))
          std::strncpy(state.lua_editor_text, content.c_str(),
                       sizeof(state.lua_editor_text) - 1);
      }
    }
  }

  /* ── Tab bar ── */
  static int lua_tab = 0; // 0 = REPL, 1 = Script Editor
  ImGui::BeginGroup();
  const char *tabs[] = {"REPL", "Script Editor"};
  for (int i = 0; i < 2; ++i) {
    if (i > 0) ImGui::SameLine();
    if (lua_tab == i) {
      ImGui::PushStyleColor(ImGuiCol_Button, palette.primary);
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1,1,1,1));
    }
    if (ImGui::Button(tabs[i], ImVec2(120.0f * scl, 28.0f * scl)))
      lua_tab = i;
    if (lua_tab == i) ImGui::PopStyleColor(2);
  }
  ImGui::EndGroup();

  ImGui::Dummy(ImVec2(0, 6.0f * scl));

  /* ── Shared output console (bottom half) ── */
  /* Chrome: 4(top pad) + 28(tab bar) + 6(spacer) + 26(buttons) + 2(spacer)
             + 2(pre-status spacer) = 68px fixed, plus 2 text lines. */
  const float line_h = ImGui::GetTextLineHeightWithSpacing();
  const float chrome_h = 68.0f * scl + 2.0f * line_h;
  const float output_h = std::max(100.0f * scl, inner_avail.y * 0.38f);
  const float input_h = inner_avail.y - output_h - chrome_h;

  /* ── REPL tab ── */
  if (lua_tab == 0) {
    static char repl_buf[8192] = "";
    static std::string repl_draft;  // saved current text while browsing history

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6, 6));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, palette.bg3);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.46f, 0.82f, 0.55f, 1.0f));
    ImGui::SetNextItemWidth(inner_avail.x - 4.0f * scl);
    const ImGuiInputTextFlags repl_flags =
        ImGuiInputTextFlags_AllowTabInput |
        ImGuiInputTextFlags_CtrlEnterForNewLine;
    ImGui::InputTextMultiline("##LuaReplInput", repl_buf, sizeof(repl_buf),
                              ImVec2(inner_avail.x - 4.0f * scl, input_h), repl_flags);
    const bool repl_focused = ImGui::IsItemActive();

    /* ── History navigation (up/down arrows) ── */
    if (repl_focused && !state.lua_repl_history.empty()) {
      if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
        if (state.lua_repl_history_index == -1) {
          repl_draft = repl_buf;
          state.lua_repl_history_index =
              static_cast<int>(state.lua_repl_history.size()) - 1;
        } else if (state.lua_repl_history_index > 0) {
          --state.lua_repl_history_index;
        }
        if (state.lua_repl_history_index >= 0 &&
            state.lua_repl_history_index <
                static_cast<int>(state.lua_repl_history.size())) {
          const auto &entry =
              state.lua_repl_history[static_cast<size_t>(
                  state.lua_repl_history_index)];
          std::strncpy(repl_buf, entry.c_str(), sizeof(repl_buf) - 1);
          repl_buf[sizeof(repl_buf) - 1] = '\0';
        }
      } else if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
        if (state.lua_repl_history_index >= 0 &&
            state.lua_repl_history_index <
                static_cast<int>(state.lua_repl_history.size()) - 1) {
          ++state.lua_repl_history_index;
          const auto &entry =
              state.lua_repl_history[static_cast<size_t>(
                  state.lua_repl_history_index)];
          std::strncpy(repl_buf, entry.c_str(), sizeof(repl_buf) - 1);
          repl_buf[sizeof(repl_buf) - 1] = '\0';
        } else {
          // Past the last entry: restore the draft
          state.lua_repl_history_index = -1;
          std::strncpy(repl_buf, repl_draft.c_str(), sizeof(repl_buf) - 1);
          repl_buf[sizeof(repl_buf) - 1] = '\0';
          repl_draft.clear();
        }
      }
    }

    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();

    ImGui::BeginGroup();
    const bool shift_enter = ImGui::IsKeyPressed(ImGuiKey_Enter) &&
                             (ImGui::IsKeyDown(ImGuiKey_LeftShift) ||
                              ImGui::IsKeyDown(ImGuiKey_RightShift));
    const bool enter_no_mod = ImGui::IsKeyPressed(ImGuiKey_Enter) &&
                              !ImGui::IsKeyDown(ImGuiKey_LeftCtrl) &&
                              !ImGui::IsKeyDown(ImGuiKey_RightCtrl) &&
                              !ImGui::IsKeyDown(ImGuiKey_LeftShift) &&
                              !ImGui::IsKeyDown(ImGuiKey_RightShift);

    bool execute = false;
    if (ImGui::Button((std::string(icons::kTerminal) + " Execute (Shift+Enter)").c_str(),
                      ImVec2(180.0f * scl, 26.0f * scl)))
      execute = true;
    ImGui::SameLine();
    if (ImGui::Button((std::string(icons::kTrash) + " Clear").c_str(), ImVec2(100.0f * scl, 26.0f * scl))) {
      state.lua_output.clear();
      repl_buf[0] = '\0';
      state.lua_repl_history_index = -1;
      repl_draft.clear();
    }
    ImGui::EndGroup();

    if ((enter_no_mod || shift_enter) && repl_focused && !execute)
      execute = true;

    if (execute && repl_buf[0] != '\0') {
      std::string code(repl_buf);
      lua_append_line(state.lua_output, "> " + code);

      auto result = lua.exec(code);
      if (!result.output.empty())
        lua_append_line(state.lua_output, result.output);
      if (!result.error.empty())
        lua_append_line(state.lua_output, "[error] " + result.error);

      // Save to history (dedup adjacent entries, cap at 50)
      if (state.lua_repl_history.empty() ||
          state.lua_repl_history.back() != code) {
        state.lua_repl_history.push_back(code);
        while (state.lua_repl_history.size() > AppState::kLuaReplHistoryMax)
          state.lua_repl_history.pop_front();
      }
      state.lua_repl_history_index = -1;
      repl_draft.clear();
      repl_buf[0] = '\0';
      ImGui::SetKeyboardFocusHere(-1);
    }
  }

  /* ── Script Editor tab ── */
  if (lua_tab == 1) {
    const ImVec4 kw_color(0.40f, 0.60f, 0.90f, 1.0f);  // blue (keywords)
    const ImVec4 str_color(0.40f, 0.78f, 0.40f, 1.0f); // green (strings)
    const ImVec4 cmt_color(0.50f, 0.50f, 0.50f, 1.0f); // grey (comments)
    const ImVec4 num_color(0.90f, 0.70f, 0.40f, 1.0f); // amber (numbers)
    const ImVec4 def_color(0.85f, 0.85f, 0.88f, 1.0f); // light grey (default)

    const float editor_w = inner_avail.x - 4.0f * scl;
    const float editor_h = input_h;

    // Layout: background → highlighted text → transparent InputTextMultiline
    // The input widget draws on top so cursor/selection remain visible.
    ImVec2 bg_pos = ImGui::GetCursorScreenPos();

    // ── 1. Background ──
    ImGui::GetWindowDrawList()->AddRectFilled(
        bg_pos, ImVec2(bg_pos.x + editor_w, bg_pos.y + editor_h),
        ImGui::ColorConvertFloat4ToU32(palette.bg3));

    // ── 2. Syntax-highlighted text ──
    const ImFont *font = ImGui::GetFont();
    const float font_size = ImGui::GetFontSize();
    const ImVec2 frame_pad = ImGui::GetStyle().FramePadding;
    float text_x = bg_pos.x + frame_pad.x;
    float text_y = bg_pos.y + frame_pad.y;
    ImVec2 text_area(editor_w - frame_pad.x * 2.0f,
                     editor_h - frame_pad.y * 2.0f);

    static float editor_scroll_x = 0.0f, editor_scroll_y = 0.0f;
    draw_lua_highlighted(state.lua_editor_text,
                         ImVec2(text_x, text_y), text_area,
                         kw_color, str_color, cmt_color, num_color, def_color,
                         font, font_size, editor_scroll_x, editor_scroll_y);

    // ── 3. Transparent InputTextMultiline for editing (on top) ──
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6, 6));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));       // transparent bg
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 0.06f));      // faint text for visible cursor
    ImGui::SetNextItemWidth(editor_w);
    ImGui::InputTextMultiline("##LuaScriptEditor", state.lua_editor_text,
                              sizeof(state.lua_editor_text),
                              ImVec2(editor_w, editor_h),
                              ImGuiInputTextFlags_AllowTabInput);
    editor_scroll_x = ImGui::GetScrollX();
    editor_scroll_y = ImGui::GetScrollY();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();

    // Toolbar
    ImGui::BeginGroup();
    if (ImGui::Button((std::string(icons::kTerminal) + " Run (F5)").c_str(),
                      ImVec2(130.0f * scl, 26.0f * scl))) {
      lua_append_line(state.lua_output, "-- Running script...");
      auto result = lua.exec(state.lua_editor_text, /*capture_returns=*/false);
      if (!result.output.empty())
        lua_append_line(state.lua_output, result.output);
      if (!result.error.empty())
        lua_append_line(state.lua_output, "[error] " + result.error);
      else
        lua_append_line(state.lua_output, "-- Script finished.");
    }
    ImGui::SameLine();

    if (ImGui::Button((std::string(icons::kSave) + " Save").c_str(),
                      ImVec2(90.0f * scl, 26.0f * scl)))
      state.lua_save_modal_open = true;
    ImGui::SameLine();

    if (ImGui::Button((std::string(icons::kLoad) + " Load").c_str(),
                      ImVec2(90.0f * scl, 26.0f * scl)))
      state.lua_load_modal_open = true;
    ImGui::SameLine();

    if (ImGui::Button((std::string(icons::kTrash) + " New").c_str(),
                      ImVec2(80.0f * scl, 26.0f * scl))) {
      state.lua_editor_text[0] = '\0';
      state.lua_last_script_path.clear();
      lua_append_line(state.lua_output, "-- New script");
    }
    ImGui::EndGroup();

    // F5 shortcut — works even when editor is focused (F-keys bypass WantTextInput)
    if (ImGui::IsKeyPressed(ImGuiKey_F5)) {
      lua_append_line(state.lua_output, "-- Running script (F5)...");
      auto result = lua.exec(state.lua_editor_text, /*capture_returns=*/false);
      if (!result.output.empty())
        lua_append_line(state.lua_output, result.output);
      if (!result.error.empty())
        lua_append_line(state.lua_output, "[error] " + result.error);
      else
        lua_append_line(state.lua_output, "-- Script finished.");
    }
  }

  /* ── Output panel ── */
  ImGui::Dummy(ImVec2(0, 2.0f * scl));
  ImGui::TextColored(palette.muted, "%s", "Output");
  ImGui::SameLine();
  if (ImGui::SmallButton("Clear##LuaOutClear")) state.lua_output.clear();

  // Use a temporary buffer to avoid const_cast on string internals
  static char output_buf[65536] = "";
  size_t copy_len = std::min(state.lua_output.size(), sizeof(output_buf) - 1);
  std::memcpy(output_buf, state.lua_output.data(), copy_len);
  output_buf[copy_len] = '\0';

  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4, 4));
  ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.06f, 0.08f, 0.10f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.78f, 0.82f, 0.88f, 1.0f));
  ImGui::InputTextMultiline("##LuaOutput", output_buf, copy_len,
                            ImVec2(inner_avail.x - 4.0f * scl, output_h),
                            ImGuiInputTextFlags_ReadOnly);
  ImGui::PopStyleColor(2);
  ImGui::PopStyleVar();

  // Auto-scroll to bottom
  if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 10.0f)
    ImGui::SetScrollHereY(1.0f);

  /* ── Save-as modal ── */
  if (state.lua_save_modal_open) {
    ImGui::OpenPopup("Save Lua Script##LuaSaveModal");
    state.lua_save_modal_open = false;
  }
  ImVec2 center = ImGui::GetMainViewport()->GetCenter();
  ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
  if (ImGui::BeginPopupModal("Save Lua Script##LuaSaveModal", nullptr,
                             ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextColored(palette.primary2, "Save Lua Script");
    ImGui::Dummy(ImVec2(0, 6.0f * scl));
    ImGui::SetNextItemWidth(340.0f * scl);
    ImGui::InputTextWithHint("##LuaSavePath", "Path (e.g. myscript.lua)",
                             state.lua_save_path, sizeof(state.lua_save_path));
    ImGui::Dummy(ImVec2(0, 6.0f * scl));
    if (ImGui::Button("Save", ImVec2(90.0f * scl, 0))) {
      std::ofstream out(state.lua_save_path, std::ios::binary | std::ios::trunc);
      if (out) {
        out << state.lua_editor_text;
        if (!out) {
          lua_append_line(state.lua_output,
                          "-- Failed to write: " + std::string(state.lua_save_path));
        } else {
          state.lua_last_script_path = state.lua_save_path;
          lua_append_line(state.lua_output,
                          "-- Saved: " + std::string(state.lua_save_path));
          ImGui::CloseCurrentPopup();
        }
      } else {
        lua_append_line(state.lua_output,
                        "-- Cannot open: " + std::string(state.lua_save_path));
      }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(90.0f * scl, 0)))
      ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
  }

  /* ── Load modal ── */
  if (state.lua_load_modal_open) {
    ImGui::OpenPopup("Load Lua Script##LuaLoadModal");
    state.lua_load_modal_open = false;
  }
  if (ImGui::BeginPopupModal("Load Lua Script##LuaLoadModal", nullptr,
                             ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextColored(palette.primary2, "Load Lua Script");
    ImGui::Dummy(ImVec2(0, 6.0f * scl));
    ImGui::SetNextItemWidth(340.0f * scl);
    ImGui::InputTextWithHint("##LuaLoadPath", "Path to .lua file",
                             state.lua_save_path, sizeof(state.lua_save_path));
    ImGui::Dummy(ImVec2(0, 6.0f * scl));
    if (ImGui::Button("Load", ImVec2(90.0f * scl, 0))) {
      std::ifstream in(state.lua_save_path, std::ios::binary);
      if (in) {
        std::string content((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
        if (content.size() < sizeof(state.lua_editor_text)) {
          std::strncpy(state.lua_editor_text, content.c_str(),
                       sizeof(state.lua_editor_text) - 1);
          state.lua_editor_text[sizeof(state.lua_editor_text) - 1] = '\0';
        }
        state.lua_last_script_path = state.lua_save_path;
        lua_append_line(state.lua_output,
                        "-- Loaded: " + std::string(state.lua_save_path) +
                        " (" + std::to_string(content.size()) + " bytes)");
        ImGui::CloseCurrentPopup();
      } else {
        lua_append_line(state.lua_output,
                        "-- Failed to load: " + std::string(state.lua_save_path));
      }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(90.0f * scl, 0)))
      ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
  }

  /* ── Status bar ── */
  ImGui::Dummy(ImVec2(0, 2.0f * scl));
  ImGui::TextColored(lua.is_initialized() ? palette.success : palette.dim,
                     "%s Lua 5.4 %s",
                     icons::kCode,
                     lua.is_initialized() ? "ready" : "not initialized");
  ImGui::SameLine();
  ImGui::TextColored(palette.muted, "|  timeout: %d ms  |  sandboxed (no io/os)",
                     state.lua_timeout_ms);

  ImGui::EndChild();
}

} // namespace memdbg::frontend

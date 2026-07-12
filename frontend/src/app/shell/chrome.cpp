/*
 * MemDBG - Desktop chrome: sidebar navigation, top bar (logo, process picker, connect/disconnect),
 *          status bar, and toast notifications.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "internal.hpp"
#include "platform.hpp"
#include <cstring>
#include <cstdio>
#include <cctype>
namespace memdbg::frontend {

static float s_notification_bottom_reserved = 0.0f;
void set_notification_bottom_reserved(float value) {
  s_notification_bottom_reserved = value;
}
static ImVec4 alpha(ImVec4 color, float value) {
  color.w *= value;
  return color;
}

void text_ellipsis(const char *text, float max_width, ImVec4 color) {
  if (text == nullptr || text[0] == '\0') return;
  if (ImGui::CalcTextSize(text).x <= max_width || max_width <= 24.0f) {
    ImGui::TextColored(color, "%s", text);
    return;
  }

  const float ellipsis_w = ImGui::CalcTextSize("...").x;
  const size_t len = strlen(text);
  const float avg_w = ImGui::CalcTextSize(text).x / static_cast<float>(len);
  size_t keep = static_cast<size_t>((max_width - ellipsis_w) / avg_w);
  if (keep > len) keep = len;
  if (keep < 1U) keep = 1U;

  char buf[512];
  while (keep > 0U) {
    const size_t n = std::min(keep, sizeof(buf) - 4U);
    std::memcpy(buf, text, n);
    std::memcpy(buf + n, "...", 4U);
    if (ImGui::CalcTextSize(buf).x <= max_width) break;
    --keep;
  }
  ImGui::TextColored(color, "%s", buf);
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", text);
}

static bool sidebar_section_header(AppState &state, int section_index, const char *label) {
  const float scl = ui::dpi_scale();
  ImGui::SetCursorPosX(10.0f * scl);

  bool &expanded = state.sidebar_sections_expanded[section_index];

  std::string header = (expanded ? icons::kCaretDown : icons::kCaretRight) + std::string("  ") + std::string(label);

  const ImVec4 col = alpha(ui::colors().primary2, 0.70f);
  ImGui::PushStyleColor(ImGuiCol_Text, col);
  const bool clicked = ImGui::Selectable(header.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick, ImVec2(ImGui::GetContentRegionAvail().x, 0));
  ImGui::PopStyleColor();

  if (clicked) expanded = !expanded;
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", expanded ? "Click to collapse" : "Click to expand");

  return expanded;
}

static void stop_gui_plugin_if_idle(AppState &state) {
  if (state.screen != Screen::PluginGUI &&
      state.plugin_gui_bridge && state.plugin_gui_bridge->running()) {
    state.plugin_gui_bridge->stop();
    state.plugin_gui_starting = false;
    state.plugin_gui_error.clear();
  }
}

static void draw_gui_plugin_launcher(AppState &state) {
  /* Stop GUI plugin when navigating away */
  stop_gui_plugin_if_idle(state);

  /* Collect installed GUI plugins (tagged with "gui" in the manifest) */
  std::vector<plugins::PluginPackage> catalog = state.plugin_manager.catalog();
  std::vector<plugins::PluginPackage> gui_plugins;
  for (const auto &pkg : catalog) {
    if (!pkg.installed || !pkg.enabled) continue;
    bool has_gui = false;
    for (const auto &tag : pkg.tags) {
      std::string lower = tag;
      std::transform(lower.begin(), lower.end(), lower.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (lower == "gui") { has_gui = true; break; }
    }
    if (has_gui) gui_plugins.push_back(pkg);
  }

  if (gui_plugins.empty()) return;

  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const float width =
      std::max(96.0f * scl, ImGui::GetContentRegionAvail().x - 8.0f * scl);

  std::string active_name;
  for (const auto &pkg : gui_plugins) {
    if (state.plugin_gui_active_id == pkg.id &&
        state.screen == Screen::PluginGUI) {
      active_name = pkg.name;
      break;
    }
  }
  const bool bridge_running =
      state.plugin_gui_bridge && state.plugin_gui_bridge->running();

  ImGui::Dummy(ImVec2(0, 2.0f * scl));
  ImGui::SetCursorPosX(10.0f * scl);
  ImGui::TextColored(alpha(palette.primary2, 0.70f), "PLUGIN APPS");

  ImGui::SetCursorPosX(10.0f * scl);
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(11.0f * scl, 5.0f * scl));
  ImGui::PushStyleColor(ImGuiCol_Button, active_name.empty()
                                           ? palette.bg3
                                           : alpha(palette.primary, 0.58f));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, alpha(palette.primary2, 0.34f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, alpha(palette.primary, 0.82f));
  const std::string launcher_label =
      std::string(icons::kPlugins) + " Open plugin UI##GuiPluginLauncher";
  if (ImGui::Button(launcher_label.c_str(), ImVec2(width, 34.0f * scl))) {
    ImGui::OpenPopup("GuiPluginLauncherPopup");
  }
  if (ImGui::IsItemHovered()) {
    ImGui::SetTooltip("%s", "Open an installed GUI plugin without leaving the sidebar");
  }
  ImGui::PopStyleColor(3);
  ImGui::PopStyleVar();

  if (!active_name.empty()) {
    std::string status = bridge_running ? "Running: " : "Selected: ";
    status += active_name;
    ImGui::SetCursorPosX(14.0f * scl);
    text_ellipsis(status.c_str(), width - 8.0f * scl, palette.muted);
  } else {
    ImGui::SetCursorPosX(14.0f * scl);
    ImGui::TextColored(palette.dim, "%zu installed", gui_plugins.size());
  }

  if (ImGui::BeginPopup("GuiPluginLauncherPopup")) {
    ImGui::TextColored(palette.primary2, "%s Plugin apps", icons::kPlugins);
    ImGui::Separator();
    for (const auto &pkg : gui_plugins) {
      bool is_selected = (state.plugin_gui_active_id == pkg.id &&
                          state.screen == Screen::PluginGUI);
      std::string label = pkg.name + "##gui-plugin-" + pkg.id;
      if (ImGui::Selectable(label.c_str(), is_selected)) {
        /* Stop previous GUI plugin if running */
        if (state.plugin_gui_bridge && state.plugin_gui_bridge->running()) {
          state.plugin_gui_bridge->stop();
        }
        state.plugin_gui_active_id = pkg.id;
        state.plugin_gui_error.clear();
        state.screen = Screen::PluginGUI;
        set_status(state, "Opening GUI plugin: " + pkg.name);
      }
      if (is_selected) ImGui::SetItemDefaultFocus();
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("%s", pkg.short_description.c_str());
      }
      if (!pkg.version.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(palette.dim, "%s", pkg.version.c_str());
      }
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Manage plugins")) {
      state.screen = Screen::Plugins;
    }
    if (bridge_running && ImGui::MenuItem("Stop active plugin")) {
      state.plugin_gui_bridge->stop();
      state.plugin_gui_starting = false;
      state.plugin_gui_error.clear();
      set_status(state, "GUI plugin stopped");
    }
    ImGui::EndPopup();
  }

  ImGui::Dummy(ImVec2(0, 2));
}

static bool label_matches(const char *label, const char *query) {
  if (query == nullptr || query[0] == '\0') return true;
  const char *l = label, *q = query;
  while (*l) {
    const char *ls = l, *qs = q;
    while (*ls && *qs && std::tolower(static_cast<unsigned char>(*ls)) == std::tolower(static_cast<unsigned char>(*qs))) {
      ++ls; ++qs;
    }
    if (*qs == '\0') return true;
    ++l;
  }
  return false;
}

static bool nav_item_visible(const char *query, const char *label) {
  if (query == nullptr || query[0] == '\0') return true;
  return label_matches(label, query);
}

static void nav_item(AppState &state, Screen screen, const char *icon, const char *label) {
  bool selected = state.screen == screen;
  ImGui::PushID(label);

  const float scl = ui::dpi_scale();
  const float row_h = 32.0f * scl;
  const float row_w = ImGui::GetContentRegionAvail().x;
  ImVec2 pos = ImGui::GetCursorScreenPos();
  ImGui::InvisibleButton("##nav", ImVec2(row_w, row_h));
  const bool hovered = ImGui::IsItemHovered();
  if (ImGui::IsItemClicked()) state.screen = screen;

  ImDrawList *dl = ImGui::GetWindowDrawList();
  const ImVec2 min(pos.x + 2.0f * scl, pos.y);
  const ImVec2 max(pos.x + row_w - 2.0f * scl, pos.y + row_h);

  if (selected || hovered) {
    const ImVec4 bg = selected
        ? ImVec4(ui::colors().primary.x * 0.3f, ui::colors().primary.y * 0.3f, ui::colors().primary.z * 0.3f, 1.0f)
        : alpha(ui::colors().bg3, 0.70f);
    dl->AddRectFilled(min, max, ui::color_u32(bg), 1.0f * scl);
    dl->AddRect(min, max,
                ui::color_u32(selected ? alpha(ui::colors().border_hot, 0.92f)
                                       : alpha(ui::colors().border, 0.62f)),
                1.0f * scl);
  }

  if (selected) {
    dl->AddRectFilled(ImVec2(pos.x + 3.0f * scl, pos.y + 3.0f * scl),
                      ImVec2(pos.x + 6.0f * scl, pos.y + row_h - 3.0f * scl),
                      ui::color_u32(ui::colors().primary2), 1.0f * scl);
  }

  const ImVec4 icon_col = selected ? ui::colors().primary2 :
                          hovered ? ui::colors().primary2 : ui::colors().muted;
  const ImVec4 text_col = selected ? ui::colors().text :
                          hovered ? ui::colors().text : ui::colors().muted;
  const ImVec2 icon_size = ImGui::CalcTextSize(icon);
  const ImVec2 label_size = ImGui::CalcTextSize(label);
  const float icon_x = pos.x + 23.0f * scl - icon_size.x * 0.5f;
  const float icon_y = pos.y + (row_h - icon_size.y) * 0.5f;
  const float text_y = pos.y + (row_h - label_size.y) * 0.5f;
  dl->AddText(ImVec2(icon_x, icon_y), ui::color_u32(icon_col), icon);

  /* Ellipsis label if it exceeds available width */
  const float text_x = pos.x + 45.0f * scl;
  const float max_label_w = row_w - 45.0f * scl - 12.0f * scl;
  if (label_size.x <= max_label_w) {
    dl->AddText(ImVec2(text_x, text_y), ui::color_u32(text_col), label);
  } else {
    char buf[128];
    size_t len = std::strlen(label);
    size_t keep = len;
    if (keep < 1U) keep = 1U;
    while (keep > 0U) {
      size_t n = std::min(keep, sizeof(buf) - 4U);
      std::memcpy(buf, label, n);
      std::memcpy(buf + n, "...", 4U);
      if (ImGui::CalcTextSize(buf).x <= max_label_w) break;
      --keep;
    }
    dl->AddText(ImVec2(text_x, text_y), ui::color_u32(text_col), buf);
  }

  if (hovered) ImGui::SetTooltip("%s", label);
  ImGui::PopID();
}

void draw_sidebar(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6,6));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4,2));
  ImGui::BeginChild("Sidebar", size, true, ImGuiWindowFlags_NoScrollbar);

  ImGui::TextColored(ui::colors().text, "%s", locale::tr("sidebar.brand"));
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().muted, "v%s", MEMDBG_VERSION_STRING);

  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg3);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8,6));
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 3.0f);
  ImGui::BeginChild("SidebarStatus", ImVec2(0, 72.0f * scl), true, ImGuiWindowFlags_NoScrollbar);

  const bool connected = state.client.connected();
  const ImVec4 status_color = state.connect_pending ? ui::colors().warning :
                              connected ? ui::colors().success : ui::colors().dim;
  const ImVec4 udp_color = state.udp_listener.running() ? ui::colors().success : ui::colors().dim;

  if (ImGui::BeginTable("SidebarStatusTable", 2, ImGuiTableFlags_NoBordersInBody, ImVec2(0, 0))) {
    ImGui::TableSetupColumn("Left", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("Right", ImGuiTableColumnFlags_WidthFixed, 80.0f * scl);

    /* Row 1: Connection + UDP */
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ui::status_dot(status_color);
    ImGui::SameLine();
    ImGui::TextColored(status_color, "%s", state.connect_pending ? locale::tr("status.connecting") :
                                            connected ? locale::tr("status.connected") : locale::tr("status.offline"));

    ImGui::TableSetColumnIndex(1);
    ui::status_dot(udp_color);
    ImGui::SameLine();
    ImGui::TextColored(udp_color, "%s", state.udp_listener.running() ? locale::tr("sidebar.udp_on") : locale::tr("sidebar.udp_off"));

    /* Row 2: Host:Port + PID */
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextColored(ui::colors().muted, "%s:%d", state.host, state.debug_port);

    ImGui::TableSetColumnIndex(1);
    ImGui::TextColored(ui::colors().muted, "PID %d", state.selected_pid);

    ImGui::EndTable();
  }

  ImGui::EndChild();
  ImGui::PopStyleVar(2); ImGui::PopStyleColor();

  /* Footer: fixed height, drawn first so scrollable area gets remaining space */
  const float footer_h = 38.0f * scl;
  const float avail_y = ImGui::GetContentRegionAvail().y;
  const float nav_h = std::max(40.0f * scl, avail_y - footer_h - 4.0f * scl);

  /* Scrollable nav area */
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(3, 1));
  ImGui::BeginChild("SidebarNavList", ImVec2(0, nav_h), true);

  /* ── Quick search ── */
  static char nav_search[64] = "";
  const bool searching = nav_search[0] != '\0';
  ImGui::Dummy(ImVec2(0, 4.0f * scl));
  ImGui::SetCursorPosX(6.0f * scl);
  ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 10.0f * scl);
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f * scl, 4.0f * scl));
  if (ImGui::InputTextWithHint("##NavSearch",
        (std::string(icons::kSearch) + "  " + "Filter pages...").c_str(),
        nav_search, sizeof(nav_search)))
    ImGui::SetKeyboardFocusHere(-1);
  ImGui::PopStyleVar();
  ImGui::Dummy(ImVec2(0, 3.0f * scl));

  /* When searching, auto-expand all sections so results are visible */
  const bool main_vis = searching || sidebar_section_header(state, 0, locale::tr("sidebar.section.main"));
  if (main_vis) {
    if (nav_item_visible(nav_search, locale::tr("nav.home")))
      nav_item(state, Screen::Home, icons::kHome, locale::tr("nav.home"));
    if (nav_item_visible(nav_search, locale::tr("nav.consoles")))
      nav_item(state, Screen::Consoles, icons::kConsole, locale::tr("nav.consoles"));
  }

  ImGui::Dummy(ImVec2(0, 3));
  const bool tools_vis = searching || sidebar_section_header(state, 1, locale::tr("sidebar.section.tools"));
  if (tools_vis) {
    if (nav_item_visible(nav_search, locale::tr("nav.processes")))
      nav_item(state, Screen::Processes, icons::kProcess, locale::tr("nav.processes"));
    if (nav_item_visible(nav_search, locale::tr("nav.memory")))
      nav_item(state, Screen::Memory, icons::kMemory, locale::tr("nav.memory"));
    if (nav_item_visible(nav_search, locale::tr("nav.scanner")))
      nav_item(state, Screen::Scanner, icons::kScanner, locale::tr("nav.scanner"));
    if (nav_item_visible(nav_search, locale::tr("nav.trainer")))
      nav_item(state, Screen::Trainer, icons::kTrainer, locale::tr("nav.trainer"));
    if (nav_item_visible(nav_search, locale::tr("nav.lua")))
      nav_item(state, Screen::Lua, icons::kTerminal, locale::tr("nav.lua"));
    if (nav_item_visible(nav_search, locale::tr("nav.plugins")))
      nav_item(state, Screen::Plugins, icons::kPlugins, locale::tr("nav.plugins"));

    /* GUI plugin launcher — hide when searching */
    if (!searching) draw_gui_plugin_launcher(state);

    if (!state.client.connected() || payload_supports(state, MEMDBG_CAP_DEBUGGER)) {
      if (nav_item_visible(nav_search, locale::tr("nav.debugger")))
        nav_item(state, Screen::Debugger, icons::kBug, locale::tr("nav.debugger"));
    }
  }

  ImGui::Dummy(ImVec2(0, 3));
  const bool mon_vis = searching || sidebar_section_header(state, 2, locale::tr("sidebar.section.monitoring"));
  if (mon_vis) {
    if (nav_item_visible(nav_search, locale::tr("nav.monitoring")))
      nav_item(state, Screen::Logs, icons::kLogs, locale::tr("nav.monitoring"));
  }

  ImGui::Dummy(ImVec2(0, 3));
  const bool sys_vis = searching || sidebar_section_header(state, 3, locale::tr("sidebar.section.system"));
  if (sys_vis) {
    if (nav_item_visible(nav_search, locale::tr("nav.settings")))
      nav_item(state, Screen::Settings, icons::kSettings, locale::tr("nav.settings"));
    if (nav_item_visible(nav_search, locale::tr("nav.credits")))
      nav_item(state, Screen::Credits, icons::kCredits, locale::tr("nav.credits"));
  }

  /* ── Enter to navigate when only one item matches ── */
  if (searching && ImGui::IsKeyPressed(ImGuiKey_Enter)) {
    struct Candidate { Screen screen; const char *label; };
    std::vector<Candidate> matches;
    auto try_add = [&](Screen s, const char *lbl) {
      if (nav_item_visible(nav_search, lbl)) matches.push_back({s, lbl});
    };
    try_add(Screen::Home, locale::tr("nav.home"));
    try_add(Screen::Consoles, locale::tr("nav.consoles"));
    try_add(Screen::Processes, locale::tr("nav.processes"));
    try_add(Screen::Memory, locale::tr("nav.memory"));
    try_add(Screen::Scanner, locale::tr("nav.scanner"));
    try_add(Screen::Trainer, locale::tr("nav.trainer"));
    try_add(Screen::Lua, locale::tr("nav.lua"));
    try_add(Screen::Plugins, locale::tr("nav.plugins"));
    try_add(Screen::Debugger, locale::tr("nav.debugger"));
    try_add(Screen::Logs, locale::tr("nav.monitoring"));
    try_add(Screen::Settings, locale::tr("nav.settings"));
    try_add(Screen::Credits, locale::tr("nav.credits"));
    if (matches.size() == 1U) {
      state.screen = matches[0].screen;
      nav_search[0] = '\0';
    }
  }

  /* ── No results hint ── */
  if (searching) {
    bool any = false;
    auto check = [&](const char *lbl) { if (nav_item_visible(nav_search, lbl)) any = true; };
    check(locale::tr("nav.home")); check(locale::tr("nav.consoles"));
    check(locale::tr("nav.processes")); check(locale::tr("nav.memory"));
    check(locale::tr("nav.scanner")); check(locale::tr("nav.trainer"));
    check(locale::tr("nav.lua"));
    check(locale::tr("nav.plugins")); check(locale::tr("nav.debugger"));
    check(locale::tr("nav.monitoring"));
    check(locale::tr("nav.settings")); check(locale::tr("nav.credits"));
    if (!any) {
      ImGui::SetCursorPosX(14.0f * scl);
      ImGui::TextColored(ui::colors().dim, "%s", "No matching pages");
    }
  }

  ImGui::EndChild();
  ImGui::PopStyleVar(2);

  /* Fixed footer */
  ImGui::SetCursorPosY(size.y - footer_h - ImGui::GetStyle().WindowPadding.y);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8, 5));
  ImGui::BeginChild("SidebarFooter", ImVec2(0, footer_h), true, ImGuiWindowFlags_NoScrollbar);
  const auto *active_theme = state.theme_manager.active_theme();
  ImGui::TextColored(ui::colors().dim, "Theme: %s", active_theme ? active_theme->name.c_str() : "Default");
  ImGui::EndChild();
  ImGui::PopStyleVar();

  ImGui::EndChild();
  ImGui::PopStyleVar(2); ImGui::PopStyleColor();
}

/* ---- Top bar ---- */

static float topbar_control_h() { return 34.0f * ui::dpi_scale(); }
static float topbar_logo_h() { return 34.0f * ui::dpi_scale(); }

static float topbar_center_y(float item_h) {
  return std::max(0.0f, (ImGui::GetWindowHeight() - item_h) * 0.5f);
}

static void topbar_align(float item_h = 0.0f) {
  if (item_h == 0.0f) item_h = topbar_control_h();
  ImGui::SetCursorPosY(topbar_center_y(item_h));
}

void topbar_select_process(AppState &state, int row) {
  if (row < 0 || row >= static_cast<int>(state.processes.size())) return;
  state.selected_process_row = row;
  state.selected_pid = state.processes[row].pid;
  state.maps.clear();
  state.selected_map_row = -1;
  state.memory.clear();
  state.scan_result = ScanResult{};
  state.scan_snapshot.clear();
  state.scan_snapshot_value_len = 0;
  state.scan_is_unknown_session = false;
  state.has_process_info = false;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "Process changed");
  set_status(state, "Selected PID " + std::to_string(state.selected_pid) + " (" + state.processes[row].name + ")");
}

void topbar_refresh_processes(AppState &state) {
  if (!state.client.connected()) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", "Process refresh failed: not connected");
    set_status(state, "Connect a console before refreshing processes");
    push_notification(state, "Connect a console before loading processes", 4.0);
    return;
  }
  if (!state.client.process_list(state.processes)) {
    std::string error = state.client.last_error();
    if (error.empty()) error = "Process refresh failed";
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Process refresh failed: " + error).c_str());
    set_status(state, error);
    push_notification(state, "Process refresh failed: " + error, 5.0);
    return;
  }

  int new_row = -1;
  if (state.selected_pid > 0) {
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      if (state.processes[i].pid == state.selected_pid) { new_row = i; break; }
    }
  }
  if (new_row >= 0) {
    state.selected_process_row = new_row;
  } else {
    state.selected_pid = 0;
    state.selected_process_row = -1;
    state.has_process_info = false;
    state.maps.clear();
    state.selected_map_row = -1;
  }
  state.taskmgr_resources.clear();
  state.taskmgr_selected_row = -1;
  state.taskmgr_selected_pid = 0;
  state.taskmgr_detail_open = false;
  state.taskmgr_map_summary = ProcessMapSummary{};
  state.taskmgr_has_process_info = false;
  set_status(state, "Process list refreshed (" + std::to_string(state.processes.size()) + " entries)");
  if (state.crash_logging_enabled)
    state.crash_logger.log("refresh", ("Process list: " + std::to_string(state.processes.size()) + " entries").c_str());
}

void topbar_refresh_maps(AppState &state) {
  request_maps_refresh_async(state);
}

static bool topbar_button(const char *id, const char *icon, const char *label,
                          float width, bool primary = false,
                          bool danger = false) {
  ImGui::PushID(id);
  topbar_align();
  std::string text = std::string(icon) + " " + label;
  bool pressed = false;
  if (danger)
    pressed = ui::danger_button(text.c_str(), ImVec2(width, topbar_control_h()));
  else if (primary)
    pressed = ui::primary_button(text.c_str(), ImVec2(width, topbar_control_h()));
  else
    pressed = ui::soft_button(text.c_str(), ImVec2(width, topbar_control_h()));
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", label);
  ImGui::PopID();
  return pressed;
}

static void draw_process_combo(AppState &state, float width) {
  std::string preview = state.selected_pid > 0
      ? (std::to_string(state.selected_pid) + "  " + selected_process_name(state))
      : locale::tr("topbar.select_process");
  topbar_align();
  const float frame_pad_y = std::max(0.0f, (topbar_control_h() - ImGui::GetFontSize()) * 0.5f);
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9.0f, frame_pad_y));
  ImGui::SetNextItemWidth(width);
  if (ImGui::BeginCombo("##TopbarProcessCombo", preview.c_str())) {
    if (state.processes.empty()) {
      ImGui::TextColored(ui::colors().dim, "%s", locale::tr("topbar.no_process_list"));
    }
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const auto &process = state.processes[i];
      const bool selected = i == state.selected_process_row;
      std::string label = std::to_string(process.pid) + "  " + process.name;
      if (ImGui::Selectable(label.c_str(), selected)) topbar_select_process(state, i);
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }
  ImGui::PopStyleVar();
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("Select target process for all tools");
}

static std::string console_target_label(const ConsoleTarget &target) {
  ConsoleTarget normalized = target;
  normalize_console_target(normalized);
  return normalized.name + "  " + normalized.host + ":" + std::to_string(normalized.debug_port);
}

[[maybe_unused]] static void draw_console_target_combo(AppState &state,
                                                       float width) {
  ensure_console_targets(state);
  const ConsoleTarget preview_target = current_console_target_from_fields(state);
  const std::string preview = console_target_label(preview_target);
  const bool locked = state.client.connected() || state.connect_pending;

  topbar_align();
  const float frame_pad_y = std::max(0.0f, (topbar_control_h() - ImGui::GetFontSize()) * 0.5f);
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9.0f, frame_pad_y));
  ImGui::BeginDisabled(locked);
  ImGui::SetNextItemWidth(width);
  if (ImGui::BeginCombo("##TopbarConsoleTarget", preview.c_str())) {
    for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
      const bool selected = i == state.selected_target_index;
      const std::string label = console_target_label(state.console_targets[static_cast<size_t>(i)]);
      if (ImGui::Selectable(label.c_str(), selected)) select_console_target(state, i);
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }
  ImGui::EndDisabled();
  ImGui::PopStyleVar();
  if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
    ImGui::SetTooltip("%s", locked ? "Disconnect before switching console target"
                                   : "Select the console target used by Connect");
  }
}

void draw_top_bar(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8, 6));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(5, 0));
  ImGui::BeginChild("TopBar", size, true, ImGuiWindowFlags_NoScrollbar);
  const float topbar_w = ImGui::GetWindowWidth();

  /* Logo centered above the sidebar */
  const float logo_h = topbar_logo_h();
  const float sidebar_w = std::clamp(topbar_w * 0.15f, 160.0f * scl, 224.0f * scl);
  const float logo_w = topbar_logo_w(logo_h);
  const float logo_x = (sidebar_w - logo_w) * 0.5f;
  ImGui::SetCursorPos(ImVec2(std::max(logo_x, 0.0f), topbar_center_y(logo_h)));
  draw_topbar_logo(logo_h);

  /* Left toolbar: PIDs + Select target process + Maps — starts at sidebar_w */
  const bool show_target_combo = topbar_w > 1780.0f * scl;
  const float left_tb_x = sidebar_w + 8.0f * scl;
  ImGui::SetCursorPos(ImVec2(left_tb_x, topbar_center_y(topbar_control_h())));

  ImGui::BeginDisabled(client_async_busy(state));
  if (topbar_button("TopbarRefreshPids", icons::kRefresh, locale::tr("topbar.pids"), 95.0f * scl))
    topbar_refresh_processes(state);
  ImGui::EndDisabled();
  ImGui::SameLine();
  if (!state.client.connected()) ImGui::BeginDisabled();
  draw_process_combo(state, show_target_combo ? 240.0f * scl :
                     (topbar_w > 1280.0f * scl ? 300.0f * scl : 230.0f * scl));
  if (!state.client.connected()) ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::BeginDisabled(client_async_busy(state));
  if (topbar_button("TopbarRefreshMaps", icons::kMemory, locale::tr("topbar.maps"), 95.0f * scl))
    topbar_refresh_maps(state);
  ImGui::EndDisabled();

  /* Right toolbar: Console/Settings/Connect */
  std::string update_tag;
  std::string update_url;
  {
    std::lock_guard<std::mutex> lock(state.release_check.mutex);
    if (state.release_check.update_available) {
      update_tag = state.release_check.latest_tag;
      update_url = state.release_check.release_url;
    }
  }

  const bool has_update = !update_tag.empty();
  const bool connected = state.client.connected();
  const float btn_w = 130.0f * scl;
  const float right_group_w = 3.0f * btn_w + 2.0f * 5.0f * scl;
  const float right_w = right_group_w + (has_update ? btn_w + 5.0f * scl : 0.0f);
  ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX() + 8.0f * scl, topbar_w - right_w));
  if (has_update) {
    std::string label = "Update " + update_tag;
    if (topbar_button("TopbarUpdate", icons::kNotify, label.c_str(), btn_w)) {
      if (!update_url.empty()) {
        (void)platform::open_url(update_url);
      }
    }
    if (ImGui::IsItemHovered()) {
      ImGui::SetTooltip("New MemDBG release available: %s", update_tag.c_str());
    }
    ImGui::SameLine();
  }
  if (connected) {
    ImGui::BeginDisabled(client_async_busy(state));
    if (topbar_button("TopbarPing", icons::kGauge, locale::tr("topbar.ping"), btn_w))
      const bool ping_ok = state.client.ping();
      set_status(state, ping_ok ? "Ping OK" : state.client.last_error());
      if (state.crash_logging_enabled)
        state.crash_logger.log("ping", ping_ok ? "Ping OK" : state.client.last_error().c_str());
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (topbar_button("TopbarLogs", icons::kLogs, locale::tr("topbar.logs"), btn_w))
      state.screen = Screen::Logs;
    ImGui::SameLine();
    ImGui::BeginDisabled(client_async_busy(state));
    std::string label = std::string(locale::tr("topbar.drop"));
    if (topbar_button("TopbarDrop", icons::kDisconnect, label.c_str(), btn_w, false, true))
      disconnect_console(state);
    ImGui::EndDisabled();
  } else {
    if (topbar_button("TopbarConfigure", icons::kConsole, locale::tr("topbar.console"), btn_w))
      state.screen = Screen::Consoles;
    ImGui::SameLine();
    if (topbar_button("TopbarSettings", icons::kSettings, locale::tr("topbar.settings"), btn_w))
      state.screen = Screen::Settings;
    ImGui::SameLine();
    if (state.connect_pending) {
      ImGui::BeginDisabled();
      (void)topbar_button("TopbarConnecting", icons::kConnect, locale::tr("topbar.connecting"), btn_w, true);
      ImGui::EndDisabled();
    } else {
      if (topbar_button("TopbarConnect", icons::kConnect, locale::tr("topbar.connect"), btn_w, true))
        connect_console(state);
    }
  }
  ImGui::EndChild();
  ImGui::PopStyleVar(2); ImGui::PopStyleColor();
}

/* ---- Status bar ---- */

void draw_status_bar(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8, 4));
  ImGui::BeginChild("StatusBar", size, true, ImGuiWindowFlags_NoScrollbar);

  ui::status_dot(state.client.connected() ? ui::colors().success : ui::colors().muted);
  ImGui::SameLine();

  /* Status text with ellipsis on overflow */
  const float rhs_width = 580.0f * scl;
  float avail_for_status = ImGui::GetWindowWidth() - rhs_width - 32.0f * scl;
  if (avail_for_status < 80.0f * scl) avail_for_status = 80.0f * scl;
  text_ellipsis(state.status, avail_for_status, ui::colors().text);

  const auto log_stats = state.udp_listener.stats();
  ImGui::SameLine();
  ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX(), ImGui::GetWindowWidth() - rhs_width));
  ImGui::TextColored(ui::colors().dim, "%s", state.client.connected() ? locale::tr("status.session_open") : locale::tr("status.session_idle"));
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);
  ImGui::TextColored(ui::colors().dim, "TARGET pid=%d", state.selected_pid);
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);
  ImGui::TextColored(ui::colors().dim, "FPS %.0f", ImGui::GetIO().Framerate);
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);
  ImGui::TextColored(ui::colors().dim, "UDP %s", state.udp_listener.running() ? locale::tr("status.udp_on") : locale::tr("status.udp_off"));
  ImGui::SameLine(0, 6); ImGui::TextColored(ui::colors().dim, "|");
  ImGui::SameLine(0, 6);

  /* Compact stats: abbreviate when narrow */
  if (ImGui::GetWindowWidth() > 1100.0f * scl) {
    ImGui::TextColored(ui::colors().dim, "rx=%llu lost=%llu evict=%llu",
                        static_cast<unsigned long long>(log_stats.received),
                        static_cast<unsigned long long>(log_stats.dropped),
                        static_cast<unsigned long long>(log_stats.evicted));
  } else {
    ImGui::TextColored(ui::colors().dim, "rx %llu",
                        static_cast<unsigned long long>(log_stats.received));
  }
  ImGui::EndChild();
  ImGui::PopStyleVar(); ImGui::PopStyleColor();
}

/* ---- Toast notifications ---- */


void draw_notifications(AppState &state) {
  const float scl = ui::dpi_scale();
  const double now = ImGui::GetTime();
  ImGuiViewport *viewport = ImGui::GetMainViewport();
  const float toast_w = 380.0f * scl, toast_h = 56.0f * scl;
  const float pad = 20.0f * scl, spacing = 8.0f * scl;
  float x = viewport->WorkPos.x + viewport->WorkSize.x - toast_w - pad;
  float y_base = viewport->WorkPos.y + viewport->WorkSize.y - pad -
                 s_notification_bottom_reserved;

  int idx = 0;
  for (auto it = state.notifications.begin(); it != state.notifications.end(); ) {
    Notification &n = *it;
    double age = now - n.created_at;

    /* Remove expired or dismissed notifications */
    if (n.dismissed || (n.duration > 0.0 && age >= n.duration)) {
      it = state.notifications.erase(it);
      continue;
    }

    /* Fade-out over last 0.6s */
    float alpha = 1.0f;
    if (n.duration > 0.0 && age > n.duration - 0.6)
      alpha = static_cast<float>((n.duration - age) / 0.6);
    if (alpha < 0.05f) { ++it; ++idx; continue; }

    float y = y_base - (toast_h + spacing) * static_cast<float>(idx + 1);
    if (y < viewport->WorkPos.y + 40.0f * scl) { ++it; ++idx; continue; }

    ImGui::SetNextWindowPos(ImVec2(x, y));
    ImGui::SetNextWindowSize(ImVec2(toast_w, toast_h));

    ImVec4 toast_bg = ui::colors().bg2;
    toast_bg.w = 0.94f * alpha;
    ImVec4 toast_border = ui::colors().border_hot;
    toast_border.w = 0.72f * alpha;
    ImVec4 toast_accent = ui::colors().primary2;
    toast_accent.w = alpha;

    ImGui::PushStyleColor(ImGuiCol_WindowBg, toast_bg);
    ImGui::PushStyleColor(ImGuiCol_Border, toast_border);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f * scl);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 14));

    char window_id[64];
    std::snprintf(window_id, sizeof(window_id), "##Toast%d", idx);
    ImGui::Begin(window_id, nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                 ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                 ImGuiWindowFlags_NoNav);

    /* Accent bar + icon */
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 wpos = ImGui::GetWindowPos(), wsz = ImGui::GetWindowSize();
    dl->AddRectFilled(ImVec2(wpos.x + 6.0f * scl, wpos.y + 10.0f * scl),
                      ImVec2(wpos.x + 10.0f * scl, wpos.y + wsz.y - 10.0f * scl),
                      ui::color_u32(toast_accent), 3.0f * scl);

    ImGui::TextColored(toast_accent, "%s", icons::kNotify);
    ImGui::SameLine(34.0f * scl);

    /* Message text with wrapping */
    float text_w = toast_w - 100.0f * scl;
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + text_w);
    ImGui::TextColored(ImVec4(0.92f, 0.93f, 0.94f, alpha), "%s", n.message.c_str());
    ImGui::PopTextWrapPos();

    /* Dismiss button */
    ImGui::SameLine();
    ImGui::SetCursorPosX(toast_w - 40.0f * scl);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.65f, alpha));
    if (ImGui::SmallButton("x")) n.dismissed = true;
    ImGui::PopStyleColor();

    ImGui::End();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);

    ++it; ++idx;
  }
}

} // namespace

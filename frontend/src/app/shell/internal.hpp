/*
 * MemDBG - Internal shared declarations for the shell module.
 *          Bridges state, connection, chrome, session, and mobile units.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef MEMDBG_FRONTEND_SHELL_INTERNAL_HPP
#define MEMDBG_FRONTEND_SHELL_INTERNAL_HPP

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "locale/locale.hpp"
#include "locale/locale_repository.hpp"
#include "plugins/repository/gui_bridge.hpp"
#include "memdbg/core/memdbg_version.h"
#include "imgui.h"
#include <string>
#include <vector>

namespace memdbg::frontend {

// state.cpp
void normalize_ports(AppState &state);
void normalize_console_target(ConsoleTarget &target);
ConsoleTarget current_console_target_from_fields(const AppState &state);
void ensure_console_targets(AppState &state);
void select_console_target(AppState &state, int index);
void save_current_console_target(AppState &state);
void add_console_target(AppState &state);
void remove_selected_console_target(AppState &state);
bool ensure_udp_listener(AppState &state, std::string &error);
bool load_frontend_settings(AppState &state, std::string *error);
bool save_frontend_settings(const AppState &state, std::string *error);

// connection.cpp
void connect_console(AppState &state);
void disconnect_console(AppState &state, const char *reason);
void request_telemetry_async(AppState &state);
void request_maps_refresh_async(AppState &state);
void request_tracer_attach_async(AppState &state);
void request_tracer_detach_async(AppState &state);
void poll_connect(AppState &state);
void poll_telemetry(AppState &state);
void poll_map_refresh(AppState &state);
void poll_tracer(AppState &state);
void poll_taskmgr_prefetch(AppState &state);
void draw_connect_spinner(AppState &state);

// chrome.cpp
void text_ellipsis(const char *text, float max_width, ImVec4 color);
void draw_sidebar(AppState &state, ImVec2 size);
void set_notification_bottom_reserved(float value);
void draw_top_bar(AppState &state, ImVec2 size);
void draw_status_bar(AppState &state, ImVec2 size);
void draw_notifications(AppState &state);
void topbar_refresh_processes(AppState &state);
void topbar_refresh_maps(AppState &state);
void topbar_select_process(AppState &state, int row);

// session.cpp
void poll_release_check(AppState &state);
void poll_locale_repository(AppState &state);
void poll_session_health(AppState &state);
void draw_screen(AppState &state, ImVec2 avail);
void handle_global_shortcuts(AppState &state);

// mobile.cpp
void set_mobile_safe_area(float left, float top, float right, float bottom);
void draw_mobile_app(AppState &state);

// memdbg_app.cpp
void draw_topbar_logo(float logo_h);
float topbar_logo_w(float logo_h);

} // namespace memdbg::frontend
#endif

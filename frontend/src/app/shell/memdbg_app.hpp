/*
 * MemDBG - ImGui console frontend app entry.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_APP_HPP
#define MEMDBG_FRONTEND_APP_HPP

struct AppState;

namespace memdbg::frontend {

int run_frontend(int argc, char **argv);

/* ---- Shared app lifecycle, usable from desktop (GLFW) and mobile shells ----
 *   init_app_shared() expects the ImGui context to already be created and
 *   current (ImGui::CreateContext() / ImGui::GetIO() valid).  It applies the
 *   theme, fonts, dpi scaling, locale, settings and plugin/catalog bootstrap.
 *   draw_app() renders one full frame of the MemDBG UI (sidebar + screen).
 *   shutdown_app_shared() drains async futures and shuts background services.
 *   The render backend (OpenGL/Metal) is owned by the calling shell. */
void init_app_shared(AppState &state, float dpi_scale);
void draw_app(AppState &state);
void shutdown_app_shared(AppState &state);

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_APP_HPP */

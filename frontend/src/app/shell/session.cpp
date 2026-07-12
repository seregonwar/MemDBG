/*
 * MemDBG - Release check, locale repository polling, session health (heartbeat),
 *          screen dispatch, and global keyboard shortcuts.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "internal.hpp"
#include <mutex>
namespace memdbg::frontend {

void poll_release_check(AppState &state) {
  if (!state.release_check.worker_done.load()) return;
  {
    std::lock_guard<std::mutex> lock(state.release_check.mutex);
    if (!state.release_check.checked || state.release_check.notification_shown)
      return;
  }
  std::lock_guard<std::mutex> lock(state.release_check.mutex);
  if (state.release_check.update_available) {
    set_status(state, "New MemDBG release available: " + state.release_check.latest_tag);
    push_notification(state, "New MemDBG release " + state.release_check.latest_tag + " available!", 12.0);
    state.release_check.notification_shown = true;
  }
  state.release_check.notification_shown = true;
}

void poll_locale_repository(AppState &state) {
  locale::Manager &loc = locale::Manager::instance();
  locale::Repository &repo = locale::Repository::instance();
  (void)repo.poll_completed(loc);

  if (state.pending_language < 0 ||
      state.pending_language >= static_cast<int>(locale::Lang::COUNT)) {
    return;
  }

  locale::Lang pending = static_cast<locale::Lang>(state.pending_language);
  if (loc.is_loaded(pending) && loc.set_active(pending)) {
    state.language = state.pending_language;
    state.pending_language = -1;
    set_status(state, std::string(locale::tr("settings.language")) + ": " +
                     locale::lang_name(pending));
    return;
  }

  if (!repo.busy()) {
    const std::string error = repo.error();
    state.pending_language = -1;
    if (!error.empty()) set_status(state, error);
  }
}

void poll_session_health(AppState &state) {
  if (state.has_hello && !state.client.connected() && !state.connect_pending) {
    const std::string error = state.client.last_error();
    const std::string message = error.empty()
                                    ? "Payload connection lost"
                                    : "Payload connection lost: " + error;
    disconnect_console(state, message.c_str());
    return;
  }

  if (state.heartbeat_pending) {
    if (!state.heartbeat_future.valid()) {
      state.heartbeat_pending = false;
      return;
    }

    auto status = state.heartbeat_future.wait_for(std::chrono::milliseconds(0));
    if (status != std::future_status::ready) {
      return;
    }

    bool ok = false;
    try {
      ok = state.heartbeat_future.get();
    } catch (const std::exception &ex) {
      state.heartbeat_error = ex.what();
    } catch (...) {
      state.heartbeat_error = "Unknown heartbeat error";
    }
    state.heartbeat_pending = false;

    if (!ok) {
      const std::string error = state.heartbeat_error.empty()
                                    ? state.client.last_error()
                                    : state.heartbeat_error;
      const std::string message = error.empty()
                                      ? "Payload connection lost"
                                      : "Payload connection lost: " + error;
      disconnect_console(state, message.c_str());
      return;
    }

    state.next_heartbeat = ImGui::GetTime() + 2.5;
    return;
  }

  if (!state.client.connected() || state.connect_pending ||
      state.telemetry_pending || state.scan_async_pending ||
      state.map_refresh_pending || state.taskmgr_resource_pending ||
      state.taskmgr_prefetch_pending || state.plugin_refresh_pending ||
      state.plugin_run_pending) {
    return;
  }

  const double now = ImGui::GetTime();
  if (now < state.next_heartbeat) {
    return;
  }

  if (state.heartbeat_future.valid()) {
    state.heartbeat_future.wait();
  }
  state.heartbeat_pending = true;
  state.heartbeat_error.clear();
  state.heartbeat_future = std::async(std::launch::async, [&state]() -> bool {
    if (state.client.ping()) {
      return true;
    }
    state.heartbeat_error = state.client.last_error();
    return false;
  });
}

/* ---- Screen dispatch ---- */

void draw_screen(AppState &state, ImVec2 avail) {
  switch (state.screen) {
  case Screen::Home:      draw_home(state, avail); break;
  case Screen::Consoles:  draw_consoles(state, avail); break;
  case Screen::Processes: draw_processes(state, avail); break;
  case Screen::Memory:    draw_memory(state, avail); break;
  case Screen::Scanner:        draw_scanner(state, avail); break;
  case Screen::PointerScanner: draw_pointer_scanner(state, avail); break;
  case Screen::AOBScanner:     draw_aob_scanner(state, avail); break;
  case Screen::Trainer:        draw_trainer(state, avail); break;
  case Screen::Plugins:        draw_plugins(state, avail); break;
  case Screen::PluginGUI:      draw_plugin_gui(state, avail); break;
  case Screen::Logs:      draw_logs(state, avail); break;
  case Screen::Telemetry: draw_telemetry(state, avail); break;
  case Screen::TaskMgr:   draw_taskmgr(state, avail); break;
  case Screen::Debugger:  draw_debugger(state, avail); break;
  case Screen::Tracer:    draw_tracer(state, avail); break;
  case Screen::Settings:  draw_settings(state, avail); break;
  case Screen::Credits:   draw_credits(state, avail); break;
  case Screen::Klog:     draw_klog(state, avail); break;
  case Screen::Lua:      draw_lua(state, avail); break;
  }
}

void handle_global_shortcuts(AppState &state) {
  ImGuiIO &io = ImGui::GetIO();
  if (io.WantTextInput) return;

  if (ImGui::IsKeyPressed(ImGuiKey_F1)) state.screen = Screen::Home;
  if (ImGui::IsKeyPressed(ImGuiKey_F4)) {
    if (state.screen == Screen::Lua) {
      state.screen = state.previous_screen;
    } else {
      state.previous_screen = state.screen;
      state.screen = Screen::Lua;
    }
  }
  if (ImGui::IsKeyPressed(ImGuiKey_F6)) state.screen = Screen::Processes;
  if (ImGui::IsKeyPressed(ImGuiKey_F7)) state.screen = Screen::Scanner;
  if (ImGui::IsKeyPressed(ImGuiKey_F8)) state.screen = Screen::Memory;
  if (ImGui::IsKeyPressed(ImGuiKey_F9)) state.screen = Screen::Trainer;
  if (ImGui::IsKeyPressed(ImGuiKey_F10)) state.screen = Screen::Logs;
  if (ImGui::IsKeyPressed(ImGuiKey_F11)) state.screen = Screen::Plugins;
  if (ImGui::IsKeyPressed(ImGuiKey_F5) && !state.connect_pending && state.screen != Screen::Lua) {
    if (client_async_busy(state)) {
      set_status(state, "Wait for the active operation to finish");
    } else if (state.client.connected()) {
      disconnect_console(state);
    } else {
      connect_console(state);
    }
  }
}

} // namespace

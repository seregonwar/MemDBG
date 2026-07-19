/*
 * MemDBG - Release check, locale repository polling, session health (heartbeat),
 *          screen dispatch, and global keyboard shortcuts.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "internal.hpp"
#include "payload_fetcher.hpp"
#include <mutex>
namespace memdbg::frontend {

void update_payload_version_check(AppState &state) {
  if (!state.has_hello || state.hello.version.empty()) {
    state.payload_outdated = false;
    state.payload_outdated_remote_tag.clear();
    return;
  }

  PayloadInfo info = state.payload_fetcher.info();
  if (!info.available || info.tag_name.empty()) return;

  const PayloadVersionCompatibility compatibility =
      compare_payload_versions(state.hello.version, info.tag_name);
  state.payload_outdated =
      compatibility.status == PayloadVersionStatus::Outdated;
  state.payload_outdated_remote_tag =
      state.payload_outdated ? info.tag_name : std::string{};
  if ((compatibility.status == PayloadVersionStatus::Invalid ||
       compatibility.status == PayloadVersionStatus::ChannelMismatch) &&
      state.crash_logging_enabled &&
      state.payload_version_diagnostic != compatibility.error) {
    state.crash_logger.log(
        "version",
        ("Payload version comparison skipped: " + compatibility.error).c_str());
    state.payload_version_diagnostic = compatibility.error;
  }
}

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

/* ---- Reconnect helpers (rest mode resilience) ---- */

void begin_reconnect(AppState &state, const std::string &reason) {
  if (state.conn.reconnect.manual_disconnect) return;
  if (!state.conn.reconnect.enabled) return;

  using namespace std::chrono;

  /* Save the logical identity of the currently selected process so we
   * can rematch it after reconnect (PID is ephemeral across rest mode). */
  auto &tid = state.conn.reconnect.target_identity;
  tid.clear();
  if (state.selected_pid > 0) {
    for (const auto &p : state.processes) {
      if (p.pid == state.selected_pid) { tid.name = p.name; break; }
    }
    if (state.has_process_info) {
      tid.title_id = state.selected_process_info.title_id;
      tid.content_id = state.selected_process_info.content_id;
      tid.executable_path = state.selected_process_info.path;
    }
  }

  /* Immediately cancel all in-flight I/O so stale futures don't block
   * the UI and don't produce results from the dead connection. */
  state.pool.cancel_all_pending_io();

  /* Disconnect the control socket and invalidate ALL role sockets.
   * Invalidate immediately — don't wait for quiesce_transport later. */
  state.pool.control().disconnect();
  state.pool.invalidate_roles();

  /* Bump the epoch so any in-flight async results from the old connection
   * are silently rejected when they eventually complete. */
  ++state.conn.reconnect.epoch;

  state.conn.reconnect.attempt = 0;
  state.conn.reconnect.started_at = steady_clock::now();
  state.conn.reconnect.next_attempt_at = steady_clock::now() + milliseconds(500);
  state.conn.reconnect.reason = reason;
  state.conn.reconnect.stale = true;
  state.conn.reconnect.phase = ConnectionPhase::WaitingForWake;

  set_status(state, reason + " — reconnecting automatically...");
}

void poll_reconnect(AppState &state) {
  if (!state.conn.reconnect.enabled) return;
  if (state.conn.reconnect.manual_disconnect) return;
  if (state.conn.connect_pending) return;  /* already attempting */
  if (state.client.connected()) return;     /* already online */

  using namespace std::chrono;
  const auto now = steady_clock::now();
  if (now < state.conn.reconnect.next_attempt_at) return;

  /* Only attempt reconnect if we're in a reconnectable phase. */
  if (state.conn.reconnect.phase != ConnectionPhase::WaitingForWake &&
      state.conn.reconnect.phase != ConnectionPhase::Reconnecting)
    return;

  state.conn.reconnect.phase = ConnectionPhase::Reconnecting;
  connect_console(state, ConnectIntent::AutomaticReconnect);
}

void poll_session_health(AppState &state) {
  /* Transport-level failure (socket died unexpectedly).
   * Only transition from Online — once we're already in a reconnect
   * phase (WaitingForWake, Reconnecting, etc.), skip this check to
   * avoid resetting the backoff timer every frame. */
  if (state.has_hello && !state.client.connected() && !state.conn.connect_pending &&
      state.conn.reconnect.phase == ConnectionPhase::Online) {
    const std::string error = state.client.last_error();
    begin_reconnect(state, error.empty() ? "Payload connection lost"
                                         : "Payload connection lost: " + error);
    return;
  }

  if (state.conn.heartbeat_pending) {
    if (!state.conn.heartbeat_future.valid()) {
      state.conn.heartbeat_pending = false;
      return;
    }

    auto status = state.conn.heartbeat_future.wait_for(std::chrono::milliseconds(0));
    if (status != std::future_status::ready) {
      return;
    }

    bool ok = false;
    try {
      ok = state.conn.heartbeat_future.get();
    } catch (const std::exception &ex) {
      state.conn.heartbeat_error = ex.what();
    } catch (...) {
      state.conn.heartbeat_error = "Unknown heartbeat error";
    }
    state.conn.heartbeat_pending = false;

    if (!ok) {
      ++state.conn.heartbeat_failures;
      /* Require 2 consecutive failures before triggering reconnect. */
      if (state.conn.heartbeat_failures >= 2) {
        const std::string error = state.conn.heartbeat_error.empty()
                                      ? state.client.last_error()
                                      : state.conn.heartbeat_error;
        begin_reconnect(state, error.empty() ? "Heartbeat lost"
                                             : "Heartbeat lost: " + error);
        return;
      }
    } else {
      state.conn.heartbeat_failures = 0;
    }

    state.conn.next_heartbeat = ImGui::GetTime() + 2.5;
    return;
  }

  if (!state.client.connected() || state.conn.connect_pending ||
      state.telemetry_pending || state.scan.async_pending ||
      state.map_refresh_pending || state.taskmgr.resource_pending ||
      state.taskmgr.prefetch_pending || state.plugin.refresh_pending ||
      state.plugin.run_pending) {
    return;
  }

  const double now = ImGui::GetTime();
  if (now < state.conn.next_heartbeat) {
    return;
  }

  if (state.conn.heartbeat_future.valid()) {
    state.conn.heartbeat_future.wait();
  }
  state.conn.heartbeat_pending = true;
  state.conn.heartbeat_error.clear();
  state.conn.heartbeat_future = std::async(std::launch::async, [&state]() -> bool {
    if (state.client.ping()) {
      return true;
    }
    state.conn.heartbeat_error = state.client.last_error();
    return false;
  });
}

/* ---- Restore session after reconnect ---- */

void poll_restore_session(AppState &state) {
  if (state.conn.reconnect.phase != ConnectionPhase::Restoring) return;
  if (!state.client.connected() || !state.has_hello) return;

  /* Force a fresh process list on first Restoring frame.
   * Don't rely on taskmgr prefetch (gated by prefetch_on_connect setting)
   * or the old list (PIDs may have changed across rest mode). */
  if (!state.restore_list_requested) {
    state.restore_list_requested = true;
    /* Blocking call, but process_list is fast and this runs once per reconnect. */
    if (!state.client.process_list(state.processes)) {
      set_status(state, "Failed to refresh process list after reconnect");
      state.conn.reconnect.phase = ConnectionPhase::Online;
      state.conn.reconnect.stale = true;  /* keep stale — user must reselect */
      return;
    }
  }

  /* Wait for the taskmgr prefetch (process list refresh) to complete
   * if it was started by start_taskmgr_prefetch() after connect success. */
  if (state.taskmgr.prefetch_pending) return;

  /* Process list is now available. Try to rematch the target process
   * by logical identity (name / title_id) rather than by old PID. */
  const auto &tid = state.conn.reconnect.target_identity;
  if (tid.valid() && !state.processes.empty()) {
    int matched_row = -1;

    /* Best match: title_id (most stable across rest mode) */
    if (!tid.title_id.empty()) {
      for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
        /* title_id is available via ProcessInfo — check cached resources */
        auto it = state.taskmgr.resources.find(state.processes[i].pid);
        if (it != state.taskmgr.resources.end() && it->second.has_info &&
            it->second.info.title_id == tid.title_id) {
          matched_row = i;
          break;
        }
      }
    }

    /* Fallback: match by process name */
    if (matched_row < 0 && !tid.name.empty()) {
      for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
        if (state.processes[i].name == tid.name) {
          matched_row = i;
          break;
        }
      }
    }

    if (matched_row >= 0) {
      state.selected_process_row = matched_row;
      state.selected_pid = state.processes[matched_row].pid;
      state.has_process_info = false;

      /* Trigger async maps refresh for the new PID */
      request_maps_refresh_async(state);

      char buf[128];
      std::snprintf(buf, sizeof(buf),
                    "Session restored — rematched process %s (PID %d)",
                    state.processes[matched_row].name.c_str(),
                    state.selected_pid);
      set_status(state, buf);
      push_notification(state, buf, 4.0);
    } else {
      /* Target not found — keep stale flag, notify user */
      state.selected_pid = 0;
      state.selected_process_row = -1;
      set_status(state, "Reconnected but target process not found — reselect manually");
      push_notification(state,
          "Target process '" + (tid.name.empty() ? tid.title_id : tid.name) +
          "' no longer running", 6.0);
    }
  }

  /* Restore complete — mark session as live. */
  state.restore_list_requested = false;
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = false;
  state.conn.reconnect.attempt = 0;
  state.conn.reconnect.reason.clear();
}

/* ---- Screen dispatch ---- */

void draw_screen(AppState &state, ImVec2 avail) {
  /* Locks are a session-wide behavior, not a Trainer-screen animation. */
  apply_locked_cheats(state);
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
  if (ImGui::IsKeyPressed(ImGuiKey_F5) && !state.conn.connect_pending && state.screen != Screen::Lua) {
    if (client_async_busy(state)) {
      set_status(state, "Wait for the active operation to finish");
    } else if (state.client.connected()) {
      disconnect_console(state);
    } else {
      connect_console(state, ConnectIntent::ManualFreshConnection);
    }
  }
}

} // namespace

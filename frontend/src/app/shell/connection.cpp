/*
 * MemDBG - Console connection lifecycle, async telemetry, memory maps, tracer, and TaskMgr prefetch.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "internal.hpp"
#include "payload_sender.hpp"
#include <future>
#include <chrono>
#include <exception>
#include <filesystem>
#include <unordered_map>

namespace memdbg::frontend {

static std::future<bool> s_connect_future;
static Client s_temp_client;
static HelloInfo s_temp_hello;
static std::string s_temp_error;
static uint64_t s_connect_generation = 0;
static std::future<bool> s_payload_inject_future;
static std::string s_payload_inject_error;

static std::filesystem::path selected_cached_payload(const AppState &state) {
  const auto cache = PayloadFetcher::cache_dir();
  const auto ps4 = cache / "MemDBG-ps4.elf";
  const auto ps5 = cache / "MemDBG-ps5.elf";
  std::error_code ec;
  if (state.payload_platform == 1)
    return std::filesystem::is_regular_file(ps4, ec) ? ps4 : std::filesystem::path{};
  if (state.payload_platform == 2)
    return std::filesystem::is_regular_file(ps5, ec) ? ps5 : std::filesystem::path{};

  const PayloadInfo info = state.payload_fetcher.info();
  if (!info.local_path.empty()) {
    const std::filesystem::path reported = info.local_path;
    if (std::filesystem::is_regular_file(reported, ec)) return reported;
  }
  ec.clear();
  if (std::filesystem::is_regular_file(ps5, ec)) return ps5;
  ec.clear();
  return std::filesystem::is_regular_file(ps4, ec) ? ps4 : std::filesystem::path{};
}

void request_payload_inject(AppState &state, bool connect_after) {
  if (state.payload_inject_pending || state.connect_pending) return;
  normalize_ports(state);
  state.payload_fetcher.set_platform(payload_platform_filter(state.payload_platform));
  const std::filesystem::path payload_path = selected_cached_payload(state);
  if (payload_path.empty()) {
    const std::string platform = state.payload_platform == 1 ? "PS4" :
                                 state.payload_platform == 2 ? "PS5" : "selected";
    const std::string message = "No cached " + platform +
        " payload is available; enable payload auto-fetch first";
    set_status(state, message);
    push_notification(state, message, 6.0);
    return;
  }
  if (s_payload_inject_future.valid()) s_payload_inject_future.wait();

  const std::string host = state.host;
  const uint16_t port = static_cast<uint16_t>(state.payload_port);
  state.payload_inject_pending = true;
  state.payload_connect_after_inject = connect_after;
  set_status(state, "Injecting " + payload_path.filename().string() + " to " +
                    host + ":" + std::to_string(port) + "...");
  s_payload_inject_future = std::async(std::launch::async,
      [host, port, payload_path]() -> bool {
        return send_payload_elf(host, port, payload_path,
                                s_payload_inject_error);
      });
}

void poll_payload_lifecycle(AppState &state) {
  if (state.payload_auto_inject_waiting &&
      state.payload_fetcher.checked() && !state.payload_fetcher.busy()) {
    state.payload_auto_inject_waiting = false;
    request_payload_inject(state, true);
  }

  if (state.payload_inject_pending && s_payload_inject_future.valid() &&
      s_payload_inject_future.wait_for(std::chrono::milliseconds(0)) ==
          std::future_status::ready) {
    state.payload_inject_pending = false;
    bool ok = false;
    try {
      ok = s_payload_inject_future.get();
    } catch (const std::exception &ex) {
      s_payload_inject_error = ex.what();
    } catch (...) {
      s_payload_inject_error = "Unknown payload injection error";
    }
    if (ok) {
      const std::string message = "Payload injected on " +
          std::string(state.host) + ":" + std::to_string(state.payload_port);
      set_status(state, message);
      push_notification(state, message, 5.0);
      if (state.payload_connect_after_inject) {
        state.payload_post_inject_connect = true;
        state.payload_connect_retry_at = ImGui::GetTime() + 1.0;
        state.payload_connect_retry_deadline = ImGui::GetTime() + 12.0;
      }
    } else {
      const std::string message = "Payload injection failed: " +
          (s_payload_inject_error.empty() ? std::string("unknown error")
                                          : s_payload_inject_error);
      set_status(state, message);
      push_notification(state, message, 7.0);
    }
    state.payload_connect_after_inject = false;
  }

  if (state.payload_connect_retry_at > 0.0 &&
      ImGui::GetTime() >= state.payload_connect_retry_at &&
      !state.connect_pending && !state.client.connected()) {
    state.payload_connect_retry_at = 0.0;
    connect_console(state);
  }
}

void connect_console(AppState &state) {
  if (state.connect_pending) return;  /* already connecting */
  if (s_connect_future.valid()) {
    set_status(state, "Previous connection attempt is still completing");
    return;
  }
  ensure_console_targets(state);
  save_current_console_target(state);
  normalize_ports(state);
  state.pool.disconnect();
  state.pool_active = false;
  state.has_hello = false;
  state.klog_connected = false;
  state.klog_paused = false;
  state.processes.clear(); state.maps.clear(); state.selected_map_starts.clear(); state.memory.clear();
  state.scan_result = ScanResult{};
  state.scan_snapshot.clear(); state.scan_snapshot_value_len = 0;
  state.scan_is_unknown_session = false;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "No scan session");
  state.selected_pid = 0; state.selected_process_row = -1; state.selected_map_row = -1;
  state.has_process_info = false;
  s_temp_client.set_socket_timeout_ms(static_cast<uint32_t>(std::max(1000, state.socket_timeout_ms)));
  s_temp_client.disconnect();
  s_temp_hello = {};
  s_temp_error.clear();
  state.connect_pending = true;
  state.connect_cancel_requested = false;
  s_connect_generation = ++state.connect_generation;

  if (state.crash_logging_enabled) {
    state.crash_logger.log("connect", ("Connecting to " + std::string(state.host) + ":" + std::to_string(state.debug_port)).c_str());
  }
  state.action_journal.record("connect", ("{\"host\":\"" + ActionJournal::json_escape(state.host) + "\",\"port\":" + std::to_string(state.debug_port) + "}").c_str());

  set_status(state, "Connecting to " + std::string(state.host) + "...");

  std::string host = state.host;
  uint16_t port = static_cast<uint16_t>(state.debug_port);
  s_connect_future = std::async(std::launch::async, [host, port]() -> bool {
    if (!s_temp_client.connect_to(host, port)) {
      s_temp_error = s_temp_client.last_error();
      return false;
    }
    if (!s_temp_client.hello(s_temp_hello)) {
      s_temp_error = s_temp_client.last_error();
      s_temp_client.disconnect();
      return false;
    }
    s_temp_error.clear();
    return true;
  });
}

void cancel_connect(AppState &state) {
  if (!connect_sequence_pending(state)) return;
  if (state.connect_pending && !state.connect_cancel_requested) {
    state.connect_cancel_requested = true;
    ++state.connect_generation;
    s_temp_client.cancel_pending_io();
  }
  state.payload_auto_inject_probe = false;
  state.payload_auto_inject_waiting = false;
  state.payload_post_inject_connect = false;
  state.payload_connect_after_inject = false;
  state.payload_connect_retry_at = 0.0;
  state.payload_connect_retry_deadline = 0.0;
  set_status(state, state.connect_pending ? "Cancelling connection..."
                                          : "Automatic connection cancelled");
  if (state.crash_logging_enabled)
    state.crash_logger.log("connect", "Connection cancellation requested");
}

/* ---- Async telemetry ---- */

void request_telemetry_async(AppState &state) {
  if (state.telemetry_pending) return;
  if (state.map_refresh_pending) return;
  if (!state.client.connected()) return;
  if (!(state.hello.capabilities & MEMDBG_CAP_PERF_TELEMETRY)) return;

  state.telemetry_pending = true;
  state.telemetry_future = std::async(std::launch::async, [&state]() -> bool {
    Client::TelemetrySnapshot snap;
    if (!state.client.telemetry(snap)) {
      state.telemetry_temp_error = state.client.last_error();
      return false;
    }
    state.telemetry_temp_snap = snap;
    state.telemetry_temp_error.clear();
    return true;
  });
}

void poll_telemetry(AppState &state) {
  if (!state.telemetry_pending) return;
  if (!state.telemetry_future.valid()) return;

  auto status = state.telemetry_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.telemetry_pending = false;
  bool ok = false;
  try {
    ok = state.telemetry_future.get();
  } catch (const std::exception &ex) {
    state.telemetry_temp_error = ex.what();
  } catch (...) {
    state.telemetry_temp_error = "Unknown telemetry error";
  }

  if (!ok) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Telemetry failed: " + state.telemetry_temp_error).c_str());
    set_status(state, "Telemetry: " + state.telemetry_temp_error);
    state.telemetry_available = false;
    return;
  }

  state.telemetry_snap = state.telemetry_temp_snap;
  state.telemetry_available = true;
}

void request_maps_refresh_async(AppState &state) {
  if (state.map_refresh_pending) {
    set_status(state, "Memory maps refresh already in progress");
    return;
  }
  if (state.connect_pending || state.telemetry_pending || state.scan_async_pending) {
    set_status(state, "Wait for the active operation to finish");
    return;
  }
  if (!state.client.connected()) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", "Maps refresh failed: not connected");
    set_status(state, locale::tr("connect.no_console_before_maps"));
    push_notification(state, locale::tr("connect.no_console_before_maps"), 4.0);
    return;
  }
  if (state.selected_pid <= 0) {
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", "Maps refresh failed: no process selected");
    set_status(state, locale::tr("processes.select_pid_first"));
    return;
  }

  if (state.map_refresh_future.valid()) {
    state.map_refresh_future.wait();
  }

  state.map_refresh_pid = state.selected_pid;
  state.map_refresh_start_time = ImGui::GetTime();
  state.map_refresh_pending = true;
  state.map_refresh_temp_maps.clear();
  state.map_refresh_error.clear();
  set_status(state, "Refreshing memory maps...");

  int32_t pid = state.map_refresh_pid;
  state.map_refresh_future = std::async(std::launch::async,
      [pid, &client = state.client,
       &temp_maps = state.map_refresh_temp_maps,
       &error = state.map_refresh_error]() -> bool {
        std::vector<MapEntry> maps;
        if (!client.process_maps(pid, maps)) {
          error = client.last_error();
          if (error.empty()) error = "Memory maps refresh failed";
          return false;
        }
        temp_maps = std::move(maps);
        error.clear();
        return true;
      });
}

void poll_map_refresh(AppState &state) {
  if (!state.map_refresh_pending) return;
  if (!state.map_refresh_future.valid()) return;

  auto status = state.map_refresh_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.map_refresh_pending = false;
  bool ok = false;
  try {
    ok = state.map_refresh_future.get();
  } catch (const std::exception &ex) {
    state.map_refresh_error = ex.what();
  } catch (...) {
    state.map_refresh_error = "Unknown maps refresh error";
  }

  if (state.map_refresh_pid != state.selected_pid) {
    state.map_refresh_temp_maps.clear();
    set_status(state, "Memory maps refresh discarded: selected process changed");
    return;
  }

  if (!ok) {
    std::string error = state.map_refresh_error.empty()
        ? "Memory maps refresh failed"
        : state.map_refresh_error;
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Maps refresh failed: " + error).c_str());
    set_status(state, error);
    push_notification(state, "Maps refresh failed: " + error, 5.0);
    return;
  }

  state.maps = std::move(state.map_refresh_temp_maps);
  state.selected_map_row = -1;
  state.selected_map_starts.clear();
  std::string message =
      std::string(locale::tr("processes.maps_refreshed")) +
      " (" + std::to_string(state.maps.size()) + " maps)";
  set_status(state, message);
  if (state.crash_logging_enabled)
    state.crash_logger.log("refresh",
        ("Memory maps: " + std::to_string(state.maps.size()) + " maps").c_str());
  state.action_journal.record("maps_refresh", ("{\"pid\":" + std::to_string(state.selected_pid) + ",\"maps\":" + std::to_string(state.maps.size()) + "}").c_str());
}

/* ---- Tracer ---- */

void request_tracer_attach_async(AppState &state) {
  if (state.tracer_pending || state.tracer_detach_pending) return;
  if (!state.client.connected()) return;
  if (!(state.hello.capabilities & MEMDBG_CAP_TRACER)) return;
  if (client_async_busy(state)) return;

  int32_t pid = state.tracer_target_pid;
  if (pid <= 0) return;

  state.tracer_pending = true;
  state.tracer_detach_requested = false;
  state.tracer_status = {};
  state.tracer_events.clear();
  state.tracer_was_crashed = false;
  state.tracer_crash_dump_path.clear();
  state.tracer_error.clear();
  state.tracer_temp_error.clear();
  state.tracer_status_text[0] = '\0';

  state.tracer_future = std::async(std::launch::async, [&state, pid]() -> bool {
    const bool ok = state.client.tracer_attach(pid);
    if (!ok) state.tracer_temp_error = state.client.last_error();
    return ok;
  });
}

void request_tracer_detach_async(AppState &state) {
  if (state.tracer_detach_pending) return;
  if (state.tracer_pending) {
    /* The attach request owns the Client socket.  Send detach immediately
     * after it has completed rather than replacing its future (which would
     * synchronously wait and freeze the UI). */
    state.tracer_detach_requested = true;
    set_status(state, "Cancelling tracer attach...");
    return;
  }
  if (!state.client.connected()) {
    state.tracer_status = {};
    state.tracer_status_text[0] = '\0';
    state.tracer_target_pid = 0;
    return;
  }

  state.tracer_pending = true;
  state.tracer_detach_pending = true;
  state.tracer_detach_requested = false;
  state.tracer_error.clear();
  state.tracer_temp_error.clear();
  set_status(state, "Detaching tracer and resuming target...");
  state.tracer_future = std::async(std::launch::async, [&state]() -> bool {
    const bool ok = state.client.tracer_detach();
    if (!ok) state.tracer_temp_error = state.client.last_error();
    return ok;
  });
}

void poll_tracer(AppState &state) {
  /* Complete an attach or detach without blocking the render thread. */
  if (state.tracer_pending && state.tracer_future.valid()) {
    const auto future_status =
        state.tracer_future.wait_for(std::chrono::milliseconds(0));
    if (future_status == std::future_status::ready) {
      const bool was_detach = state.tracer_detach_pending;
      bool ok = false;
      state.tracer_pending = false;
      state.tracer_detach_pending = false;
      try {
        ok = state.tracer_future.get();
      } catch (const std::exception &ex) {
        state.tracer_temp_error = ex.what();
      } catch (...) {
        state.tracer_temp_error = "Unknown tracer operation error";
      }

      if (!ok) {
        state.tracer_error = state.tracer_temp_error.empty()
            ? "Tracer operation failed"
            : state.tracer_temp_error;
        set_status(state, "Tracer: " + state.tracer_error);
        push_notification(state, "Tracer: " + state.tracer_error, 6.0);
      } else if (was_detach) {
        state.tracer_status = {};
        state.tracer_status.state = MEMDBG_TRACER_STATE_STOPPED;
        std::snprintf(state.tracer_status_text,
                      sizeof(state.tracer_status_text), "%s", "Stopped");
        state.tracer_target_pid = 0;
        state.tracer_next_poll = 0.0;
    state.tracer_next_event_poll = 0.0;
    set_status(state, "Tracer detached; target resumed");
    state.action_journal.record("tracer_detach", ("{\"pid\":" + std::to_string(state.tracer_target_pid) + "}").c_str());
      } else {
        std::snprintf(state.tracer_status_text,
                      sizeof(state.tracer_status_text), "%s", "Starting...");
        state.tracer_next_poll = 0.0;
        state.tracer_next_event_poll = 0.0;
        state.action_journal.record("tracer_attach", ("{\"pid\":" + std::to_string(state.tracer_target_pid) + "}").c_str());

      if (!was_detach && state.tracer_detach_requested) {
        state.tracer_detach_requested = false;
        request_tracer_detach_async(state);
      }
      }
    }
  }

  /* The attach/detach request owns the shared protocol client. */
  if (state.tracer_pending) return;
  if (!state.client.connected()) return;
  if (!(state.hello.capabilities & MEMDBG_CAP_TRACER)) return;

  if (state.tracer_status_pending && state.tracer_status_future.valid() &&
      state.tracer_status_future.wait_for(std::chrono::milliseconds(0)) ==
          std::future_status::ready) {
    bool ok = false;
    try {
      ok = state.tracer_status_future.get();
    } catch (const std::exception &ex) {
      state.tracer_status_error = ex.what();
    } catch (...) {
      state.tracer_status_error = "Unknown tracer status error";
    }
    state.tracer_status_pending = false;
    if (ok) {
      Client::TracerStatus new_st = state.tracer_temp_status;
      /* Check for state transition to crashed. */
      if (state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING &&
          new_st.state == MEMDBG_TRACER_STATE_CRASHED) {
        state.tracer_was_crashed = true;
        state.tracer_crash_dump_path = new_st.dump_path;
        state.tracer_crash_notification_time = ImGui::GetTime();
        push_notification(state,
            "Process crashed! Signal " + std::to_string(new_st.crash_signal) +
            ". Dump: " + new_st.dump_path, 10.0);
      }
      state.tracer_status = std::move(new_st);
      std::snprintf(state.tracer_status_text,
                    sizeof(state.tracer_status_text), "%s",
                    state.tracer_status.state == MEMDBG_TRACER_STATE_IDLE     ? "Idle" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING  ? "Running" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_CRASHED  ? "Crashed" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_EXITED   ? "Exited" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_STOPPED  ? "Stopped" :
                    state.tracer_status.state == MEMDBG_TRACER_STATE_STARTING ? "Starting..." : "?");
    } else if (!state.tracer_status_error.empty()) {
      state.tracer_error = state.tracer_status_error;
    }
  }

  if (state.tracer_events_pending && state.tracer_events_future.valid() &&
      state.tracer_events_future.wait_for(std::chrono::milliseconds(0)) ==
          std::future_status::ready) {
    bool ok = false;
    try {
      ok = state.tracer_events_future.get();
    } catch (const std::exception &ex) {
      state.tracer_events_error = ex.what();
    } catch (...) {
      state.tracer_events_error = "Unknown tracer event poll error";
    }
    state.tracer_events_pending = false;
    if (ok) {
      state.tracer_events.insert(state.tracer_events.end(),
                                  state.tracer_temp_events.begin(),
                                  state.tracer_temp_events.end());
      /* Keep max ~5000 events in memory. */
      if (state.tracer_events.size() > 5000)
        state.tracer_events.erase(state.tracer_events.begin(),
                                  state.tracer_events.begin() + (state.tracer_events.size() - 5000));
    } else if (!state.tracer_events_error.empty()) {
      state.tracer_error = state.tracer_events_error;
    }
  }

  /* Skip polling when no tracer session was ever started. */
  if (state.tracer_target_pid <= 0) return;

  const double now = ImGui::GetTime();
  if (!state.tracer_status_pending && !state.tracer_events_pending &&
      now >= state.tracer_next_poll) {
    state.tracer_next_poll = now + 0.5;
    state.tracer_status_pending = true;
    state.tracer_status_error.clear();
    state.tracer_status_future = std::async(std::launch::async, [&state]() -> bool {
      Client::TracerStatus status;
      const bool ok = state.client.tracer_status(status);
      if (ok)
        state.tracer_temp_status = std::move(status);
      else
        state.tracer_status_error = state.client.last_error();
      return ok;
    });
    return;
  }

  if (state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING &&
      !state.tracer_status_pending && !state.tracer_events_pending &&
      now >= state.tracer_next_event_poll) {
    state.tracer_next_event_poll = now + 0.1;
    state.tracer_events_pending = true;
    state.tracer_events_error.clear();
    state.tracer_events_future = std::async(std::launch::async, [&state]() -> bool {
      std::vector<Client::TracerEvent> events;
      const bool ok = state.client.tracer_poll(events);
      if (ok)
        state.tracer_temp_events = std::move(events);
      else
        state.tracer_events_error = state.client.last_error();
      return ok;
    });
  }
}

static ProcessMapSummary summarize_taskmgr_prefetch_maps(const std::vector<MapEntry> &maps) {
  ProcessMapSummary summary;
  summary.loaded = true;
  for (const auto &map : maps) {
    if (map.end <= map.start) continue;
    const uint64_t size = map.end - map.start;
    summary.map_count++;
    summary.total_mapped += size;
    if (map.protection & 1U) summary.readable_bytes += size;
    if (map.protection & 2U) summary.writable_bytes += size;
    if (map.protection & 4U) summary.executable_bytes += size;
    if ((map.protection & 3U) == 3U && !(map.protection & 4U))
      summary.rw_heap_bytes += size;
  }
  return summary;
}

static void merge_taskmgr_resource(AppState &state, TaskProcessResource &&incoming) {
  if (incoming.pid <= 0) return;
  TaskProcessResource &resource = state.taskmgr_resources[incoming.pid];
  resource.pid = incoming.pid;
  if (incoming.has_info) {
    resource.info = std::move(incoming.info);
    resource.has_info = true;
    resource.info_failed = false;
  } else if (incoming.info_failed) {
    resource.info_failed = true;
  }
  if (incoming.maps.loaded || incoming.maps_failed) {
    resource.maps = incoming.maps;
    resource.maps_failed = incoming.maps_failed;
  }
  if (!incoming.error.empty()) resource.error = std::move(incoming.error);
  resource.updated_at = ImGui::GetTime();
}

static void start_taskmgr_prefetch(AppState &state) {
  if (!state.taskmgr_prefetch_on_connect || state.taskmgr_prefetch_pending) return;
  if (!state.client.connected() || !state.has_hello) return;
  if (!(state.hello.capabilities & MEMDBG_CAP_PROCESS_LIST)) return;
  if (state.taskmgr_prefetch_future.valid()) state.taskmgr_prefetch_future.wait();

  state.taskmgr_prefetch_pending = true;
  state.taskmgr_prefetch_processes.clear();
  state.taskmgr_prefetch_resources.clear();
  state.taskmgr_prefetch_error.clear();

  const uint32_t capabilities = state.hello.capabilities;
  state.taskmgr_prefetch_future = std::async(std::launch::async,
      [&client = state.client,
       &processes_out = state.taskmgr_prefetch_processes,
       &resources_out = state.taskmgr_prefetch_resources,
       &error = state.taskmgr_prefetch_error,
       capabilities]() -> bool {
        std::vector<ProcessEntry> processes;
        if (!client.process_list(processes)) {
          error = client.last_error();
          return false;
        }

        std::unordered_map<int32_t, TaskProcessResource> resources;
        resources.reserve(processes.size());
        for (const auto &process : processes) {
          if (process.pid <= 0) continue;
          TaskProcessResource &resource = resources[process.pid];
          resource.pid = process.pid;
        }

        if (capabilities & MEMDBG_CAP_PROCESS_INFO) {
          constexpr size_t kBatchInfoMax = 128U;
          for (size_t base = 0; base < processes.size(); base += kBatchInfoMax) {
            const size_t end = std::min(base + kBatchInfoMax, processes.size());
            std::vector<int32_t> pids;
            pids.reserve(end - base);
            for (size_t i = base; i < end; ++i) {
              if (processes[i].pid > 0) pids.push_back(processes[i].pid);
            }
            if (pids.empty()) continue;

            std::vector<ProcessInfo> infos;
            if (client.batch_process_info(pids, infos)) {
              for (auto &info : infos) {
                if (info.pid <= 0) continue;
                TaskProcessResource &resource = resources[info.pid];
                resource.pid = info.pid;
                resource.info = std::move(info);
                resource.has_info = true;
              }
              continue;
            }

            const std::string batch_error = client.last_error();
            if (error.empty()) error = batch_error;
            for (int32_t pid : pids) {
              ProcessInfo info;
              TaskProcessResource &resource = resources[pid];
              resource.pid = pid;
              if (client.process_info(pid, info)) {
                resource.info = std::move(info);
                resource.has_info = true;
                resource.info_failed = false;
              } else {
                resource.info_failed = true;
                if (resource.error.empty()) resource.error = client.last_error();
              }
            }
          }
        }

        if (capabilities & MEMDBG_CAP_PROCESS_MAPS) {
          for (const auto &process : processes) {
            if (process.pid <= 0) continue;
            std::vector<MapEntry> maps;
            TaskProcessResource &resource = resources[process.pid];
            resource.pid = process.pid;
            if (client.process_maps(process.pid, maps)) {
              resource.maps = summarize_taskmgr_prefetch_maps(maps);
              resource.maps_failed = false;
            } else {
              resource.maps.loaded = true;
              resource.maps_failed = true;
              resource.error = client.last_error();
              if (error.empty()) error = resource.error;
            }
          }
        }

        processes_out = std::move(processes);
        resources_out = std::move(resources);
        return true;
      });
}

void poll_taskmgr_prefetch(AppState &state) {
  if (!state.taskmgr_prefetch_pending || !state.taskmgr_prefetch_future.valid()) return;

  auto status = state.taskmgr_prefetch_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.taskmgr_prefetch_pending = false;
  bool ok = false;
  try {
    ok = state.taskmgr_prefetch_future.get();
  } catch (const std::exception &ex) {
    state.taskmgr_prefetch_error = ex.what();
  } catch (...) {
    state.taskmgr_prefetch_error = "Unknown task manager prefetch error";
  }

  if (ok) {
    if (!state.taskmgr_prefetch_processes.empty()) {
      state.processes = std::move(state.taskmgr_prefetch_processes);
    }
    for (auto &entry : state.taskmgr_prefetch_resources) {
      merge_taskmgr_resource(state, std::move(entry.second));
    }
    state.taskmgr_next_resource_fetch = ImGui::GetTime() + 1.0;
  }

  state.taskmgr_prefetch_processes.clear();
  state.taskmgr_prefetch_resources.clear();
}

/* Poll async connect result. Called at start of every frame. */
void poll_connect(AppState &state) {
  if (!state.connect_pending) return;
  if (!s_connect_future.valid()) return;

  auto status = s_connect_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.connect_pending = false;
  bool ok = false;
  try {
    ok = s_connect_future.get();
  } catch (const std::exception &ex) {
    s_temp_error = ex.what();
  } catch (...) {
    s_temp_error = "Unknown connection error";
  }

  const bool cancelled = state.connect_cancel_requested ||
                         s_connect_generation != state.connect_generation;
  state.connect_pending = false;
  state.connect_cancel_requested = false;
  if (cancelled) {
    s_temp_client.disconnect();
    set_status(state, "Connection cancelled");
    if (state.crash_logging_enabled)
      state.crash_logger.log("connect", "Connection cancelled");
    return;
  }

  if (!ok) {
    if (state.payload_auto_inject_probe) {
      state.payload_auto_inject_probe = false;
      state.payload_auto_inject_waiting = true;
      set_status(state, "Payload is offline; waiting for the selected ELF...");
      return;
    }
    if (state.payload_post_inject_connect &&
        ImGui::GetTime() < state.payload_connect_retry_deadline) {
      state.payload_connect_retry_at = ImGui::GetTime() + 1.0;
      set_status(state, "Payload is starting; retrying connection...");
      return;
    }
    state.payload_post_inject_connect = false;
    state.payload_connect_retry_at = 0.0;
    state.payload_connect_retry_deadline = 0.0;
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Connection failed: " + s_temp_error).c_str());
    set_status(state, s_temp_error);
    push_notification(state, "Connection failed: " + s_temp_error, 5.0);
    return;
  }

  /* Success: transfer connected fd from temp client to main client */
  /* Transfer control fd to pool, then connect additional roles in background. */
  {
    platform::socket_handle_t cfd = s_temp_client.release_fd();
    state.pool.control().take_fd(cfd);
  }
  state.pool_active = true;
  /* Kick off Memory / Scan / Poll role connections asynchronously.
   * These are non-blocking — roles that fail to connect fall back to Control. */
  state.pool.connect_additional_roles_async(
      std::string(state.host),
      static_cast<uint16_t>(state.debug_port),
      static_cast<uint32_t>(state.socket_timeout_ms));
  state.payload_auto_inject_probe = false;
  state.payload_auto_inject_waiting = false;
  state.payload_post_inject_connect = false;
  state.payload_connect_retry_at = 0.0;
  state.payload_connect_retry_deadline = 0.0;
  state.hello = s_temp_hello;
  state.has_hello = true;
  update_payload_version_check(state);
  state.taskmgr_resources.clear();
  state.taskmgr_fmem_by_name.clear();
  state.taskmgr_last_log_received = 0U;
  state.taskmgr_prefetch_processes.clear();
  state.taskmgr_prefetch_resources.clear();
  state.taskmgr_prefetch_error.clear();
  std::string udp_error;
  std::string message = "Connected to console " + std::string(state.host) + ":" + std::to_string(state.debug_port);
  if (!ensure_udp_listener(state, udp_error)) message += " (UDP: " + udp_error + ")";

  if (state.crash_logging_enabled)
    state.crash_logger.log("connect", ("Connected to " + std::string(state.host) + ":" + std::to_string(state.debug_port)).c_str());

  state.action_journal.record("connected", ("{\"host\":\"" + ActionJournal::json_escape(state.host) + "\",\"port\":" + std::to_string(state.debug_port) + ",\"version\":\"" + ActionJournal::json_escape(state.hello.version) + "\"}").c_str());

  set_status(state, message);
  push_notification(state, "Connected to " + std::string(state.host) + ":" + std::to_string(state.debug_port));
  start_taskmgr_prefetch(state);
}

/* Modal spinner drawn during async connect */
void draw_connect_spinner(AppState &state) {
  if (!state.connect_pending) return;

  const float scl = ui::dpi_scale();
  const ImVec2 center = ImGui::GetMainViewport()->GetCenter();
  ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
  ImGui::SetNextWindowSize(ImVec2(320.0f * scl, 155.0f * scl));

  ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(18, 24, 32, 245));
  ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(60, 120, 130, 100));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 14.0f * scl);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24, 20));

  ImGui::Begin("##ConnectSpinner", nullptr,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
               ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
               ImGuiWindowFlags_NoNav | ImGuiWindowFlags_AlwaysAutoResize);

  ImGui::TextColored(
      ui::colors().primary2, "%s  %s", icons::kConnect,
      state.connect_cancel_requested ? "Cancelling..." : locale::tr("connect.spinner"));
  ImGui::Spacing();
  ImGui::TextColored(ui::colors().muted, "%s:%d", state.host, state.debug_port);

  /* Animated spinner using time-based rotation */
  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec2 sp = ImVec2(center.x + 100.0f * scl, center.y + 4.0f * scl);
  float radius = 14.0f * scl;
  float t = (float)ImGui::GetTime();
  const int segments = 8;
  for (int i = 0; i < segments; ++i) {
    float a = t * 4.0f + (float)i * 6.2831853f / (float)segments;
    float alpha = 0.15f + 0.85f * ((float)i / (float)segments);
    ImVec2 p(sp.x + radius * cosf(a), sp.y + radius * sinf(a));
    dl->AddCircleFilled(p, 2.5f * scl, IM_COL32(118, 232, 224, (int)(200 * alpha)));
  }

  ImGui::Spacing();
  ImGui::SetCursorPosX(24.0f * scl);
  ImGui::BeginDisabled(state.connect_cancel_requested);
  if (ui::soft_button(locale::tr("common.cancel"), ImVec2(272.0f * scl, 32.0f * scl)))
    cancel_connect(state);
  ImGui::EndDisabled();

  ImGui::End();
  ImGui::PopStyleVar(3);
  ImGui::PopStyleColor(2);

  /* Dim background overlay */
  ImVec2 vp_pos = ImGui::GetMainViewport()->Pos;
  ImVec2 vp_size = ImGui::GetMainViewport()->Size;
  ImGui::GetBackgroundDrawList()->AddRectFilled(
      vp_pos, ImVec2(vp_pos.x + vp_size.x, vp_pos.y + vp_size.y),
      IM_COL32(0, 0, 0, 80));
}

void disconnect_console(AppState &state, const char *reason) {
  if (state.connect_pending) cancel_connect(state);

  /* Drain async futures before clearing flags (std::future blocks on destructor). */
  state.connect_pending = false;  /* cancel any in-flight async connect */

  /* Interrupt scanner I/O before draining its future. */
  if (state.scan_async_future.valid()) {
    state.scan_async_cancel_requested.store(true);
    state.pool.cancel_all_pending_io();
  }
  if (state.scan_async_future.valid()) state.scan_async_future.wait();
  if (state.telemetry_future.valid()) state.telemetry_future.wait();
  if (state.map_refresh_future.valid()) state.map_refresh_future.wait();
  if (state.taskmgr_resource_future.valid()) state.taskmgr_resource_future.wait();
  if (state.taskmgr_prefetch_future.valid()) state.taskmgr_prefetch_future.wait();
  if (state.heartbeat_future.valid()) state.heartbeat_future.wait();
  if (state.tracer_future.valid()) state.tracer_future.wait();
  if (state.tracer_status_future.valid()) state.tracer_status_future.wait();
  if (state.tracer_events_future.valid()) state.tracer_events_future.wait();
  if (s_connect_future.valid()) {
    s_connect_future.wait();
    try {
      (void)s_connect_future.get();
    } catch (const std::exception &ex) {
      if (state.crash_logging_enabled)
        state.crash_logger.log(
            "error", ("Connection worker shutdown failed: " +
                      std::string(ex.what())).c_str());
    }
    s_temp_client.disconnect();
  }

  state.connect_pending = false;
  state.connect_cancel_requested = false;
  state.scan_async_pending = false;  /* cancel any in-flight async scan */
  state.telemetry_pending = false;  /* cancel any in-flight telemetry poll */
  state.map_refresh_pending = false;  /* cancel any in-flight map refresh */
  state.taskmgr_resource_pending = false;  /* cancel any in-flight task manager fetch */
  state.taskmgr_prefetch_pending = false;
  state.heartbeat_pending = false;
  state.heartbeat_error.clear();
  state.next_heartbeat = 0.0;
  const bool tracer_may_own_target = state.tracer_pending ||
      state.tracer_target_pid > 0 ||
      state.tracer_status.state == MEMDBG_TRACER_STATE_RUNNING;
  if (state.client.connected() && state.has_hello && tracer_may_own_target &&
      (state.hello.capabilities & MEMDBG_CAP_TRACER)) {
    /* Do not leave a traced process stopped when the frontend disconnects. */
    (void)state.client.tracer_detach();
  }
  state.tracer_pending = false;
  state.tracer_detach_pending = false;
  state.tracer_detach_requested = false;
  state.tracer_status_pending = false;
  state.tracer_events_pending = false;
  state.tracer_target_pid = 0;
  state.tracer_status = {};
  state.tracer_status_text[0] = '\0';
  state.tracer_error.clear();
  state.tracer_temp_events.clear();
  state.pool.disconnect();
  state.pool_active = false;
  state.has_hello = false;
  state.klog_connected = false;
  state.klog_paused = false;
  state.processes.clear(); state.maps.clear(); state.selected_map_starts.clear(); state.memory.clear();
  state.scan_result = ScanResult{};
  state.scan_snapshot.clear(); state.scan_snapshot_value_len = 0;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "No scan session");
  state.selected_pid = 0; state.selected_process_row = -1; state.selected_map_row = -1;
  state.has_process_info = false;
  state.telemetry_available = false;
  state.next_telemetry_poll = 0.0;
  state.taskmgr_resources.clear();
  state.taskmgr_fmem_by_name.clear();
  state.taskmgr_prefetch_processes.clear();
  state.taskmgr_prefetch_resources.clear();
  state.taskmgr_prefetch_error.clear();
  state.taskmgr_last_log_received = 0U;
  state.taskmgr_selected_row = -1;
  state.taskmgr_selected_pid = 0;
  state.taskmgr_detail_open = false;
  state.taskmgr_map_summary = ProcessMapSummary{};
  state.taskmgr_has_process_info = false;
  reset_debugger_state(state);

  /* Stop any running GUI plugin bridge */
  if (state.plugin_gui_bridge && state.plugin_gui_bridge->running()) {
    state.plugin_gui_bridge->stop();
    state.plugin_gui_starting = false;
    state.plugin_gui_error.clear();
  }

  if (state.crash_logging_enabled)
    state.crash_logger.log("connect", "Disconnected from console");

  const std::string disconnect_reason = reason != nullptr && reason[0] != '\0'
                                  ? std::string(reason)
                                  : "Console disconnected";
  state.action_journal.record("disconnect", ("{\"reason\":\"" + ActionJournal::json_escape(disconnect_reason) + "\"}").c_str());

  set_status(state, disconnect_reason);
  push_notification(state, disconnect_reason);
}

} // namespace

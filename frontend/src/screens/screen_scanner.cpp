/*
 * MemDBG - Scanner screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "auto_search.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <future>
#include <mutex>

namespace memdbg::frontend {

/* ---- Scan helpers ---- */
/* build_scan_value and append_value are in app_state.hpp */

static uint32_t current_scan_value_len(const AppState &state) {
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!build_scan_value(state.scan_type, state.scan_value, value, value_len)) {
    switch (state.scan_type) {
    case MEMDBG_VALUE_U8:  return 1U;
    case MEMDBG_VALUE_U16: return 2U;
    case MEMDBG_VALUE_U32: case MEMDBG_VALUE_F32: return 4U;
    case MEMDBG_VALUE_U64: case MEMDBG_VALUE_F64: case MEMDBG_VALUE_POINTER: return 8U;
    default: return 1U;
    }
  }
  return value_len;
}

static bool scan_refine_match(int type, RefineMode mode, const std::vector<uint8_t> &old_bytes, const std::vector<uint8_t> &new_bytes) {
  const bool same = old_bytes == new_bytes;
  switch (mode) {
  case RefineMode::Changed:   return !same;
  case RefineMode::Unchanged: return same;
  case RefineMode::Increased:
  case RefineMode::Decreased: {
    long double old_value=0.0, new_value=0.0;
    if (!bytes_to_number(type,old_bytes,old_value)||!bytes_to_number(type,new_bytes,new_value)) return false;
    return mode==RefineMode::Increased ? new_value>old_value : new_value<old_value;
  }}
  return false;
}

static const char *refine_mode_name(RefineMode mode) {
  switch (mode) {
  case RefineMode::Changed: return "Changed";
  case RefineMode::Unchanged: return "Unchanged";
  case RefineMode::Increased: return "Increased";
  case RefineMode::Decreased: return "Decreased";
  }
  return "Refine";
}

static bool has_batch_read(const AppState &state) {
  return (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;
}

/* ---- Scan session ---- */
static void capture_scan_snapshot(AppState &state) {
  state.scan_snapshot.clear();
  state.scan_snapshot_type = state.scan_type;
  state.scan_snapshot_value_len = current_scan_value_len(state);
  const uint32_t val_len = state.scan_snapshot_value_len;

  if (!state.client.connected() || state.selected_pid <= 0 ||
      state.scan_result.addresses.empty() || val_len == 0U) {
    std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "%s", locale::tr("scanner.no_scan_values"));
    return;
  }

  const auto &addrs = state.scan_result.addresses;
  state.scan_snapshot.reserve(addrs.size());
  uint32_t read_errors = 0;
  const auto start = std::chrono::steady_clock::now();

  if (has_batch_read(state)) {
    /* Fast path: batch read up to 64 addresses per request. */
    std::vector<memdbg_batch_read_item_t> batch_items;
    batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);

    for (size_t base = 0U; base < addrs.size(); base += MEMDBG_BATCH_READ_MAX_ITEMS) {
      batch_items.clear();
      size_t chunk_end = std::min(base + MEMDBG_BATCH_READ_MAX_ITEMS, addrs.size());
      for (size_t i = base; i < chunk_end; ++i) {
        memdbg_batch_read_item_t item{};
        item.address = addrs[i];
        item.length  = val_len;
        batch_items.push_back(item);
      }

      Client::BatchReadResult batch;
      if (!state.client.batch_read(state.selected_pid, batch_items, batch)) {
        read_errors += static_cast<uint32_t>(chunk_end - base);
        continue;
      }

      uint32_t data_offset = 0U;
      for (size_t j = 0U; j < batch.entries.size(); ++j) {
        const auto &entry = batch.entries[j];
        if (entry.status != 0U || entry.length != val_len) {
          read_errors++;
          data_offset += entry.length;
          continue;
        }
        ScanSnapshotEntry snap;
        snap.address = entry.address;
        snap.bytes.assign(batch.data.begin() + data_offset,
                          batch.data.begin() + data_offset + entry.length);
        state.scan_snapshot.push_back(std::move(snap));
        data_offset += entry.length;
      }
    }
  } else {
    /* Fallback: individual memory_read per address (slower, but universal). */
    for (size_t i = 0U; i < addrs.size(); ++i) {
      std::vector<uint8_t> data;
      if (!state.client.memory_read(state.selected_pid, addrs[i], val_len, data) ||
          data.size() != val_len) {
        read_errors++;
        continue;
      }
      ScanSnapshotEntry snap;
      snap.address = addrs[i];
      snap.bytes   = std::move(data);
      state.scan_snapshot.push_back(std::move(snap));
    }
  }

  const auto end = std::chrono::steady_clock::now();
  const uint64_t elapsed_ns = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count());
  const uint64_t capture_bytes = (uint64_t)state.scan_snapshot.size() * val_len;
  const char *mode = has_batch_read(state) ? "BATCH_READ" : "individual reads";
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s: %zu values (%u read errors, %s)",
                mode, state.scan_snapshot.size(), read_errors,
                bytes_per_second(capture_bytes, elapsed_ns).c_str());
  if (!has_batch_read(state) && !addrs.empty())      set_status(state, locale::tr("scanner.individual_reads"));
  state.scan_result.read_calls += static_cast<uint32_t>(addrs.size());
  state.scan_result.read_errors += read_errors;
  state.scan_result.elapsed_ns += elapsed_ns;
}

static void refine_scan(AppState &state, RefineMode mode) {
  if (!state.client.connected()) { set_status(state, locale::tr("scanner.connect_first")); return; }
  if (state.selected_pid <= 0) { set_status(state, locale::tr("scanner.select_process_first")); return; }
  if (state.scan_snapshot.empty() || state.scan_snapshot_value_len == 0U) {
    set_status(state, locale::tr("scanner.run_scan_before_refine")); return;
  }

  const uint32_t val_len = state.scan_snapshot_value_len;
  std::vector<ScanSnapshotEntry> next_snapshot;
  next_snapshot.reserve(state.scan_snapshot.size());
  std::vector<uint64_t> next_addresses;
  next_addresses.reserve(state.scan_snapshot.size());
  uint32_t read_errors = 0;
  uint64_t bytes_read = 0;
  const auto start = std::chrono::steady_clock::now();

  const auto &old_snap = state.scan_snapshot;
  std::vector<memdbg_batch_read_item_t> batch_items;

  if (has_batch_read(state)) {
    /* Fast path: batch read up to 64 addresses per request. */
    batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);

    for (size_t base = 0U; base < old_snap.size(); base += MEMDBG_BATCH_READ_MAX_ITEMS) {
      batch_items.clear();
      size_t chunk_end = std::min(base + MEMDBG_BATCH_READ_MAX_ITEMS, old_snap.size());
      for (size_t i = base; i < chunk_end; ++i) {
        memdbg_batch_read_item_t item{};
        item.address = old_snap[i].address;
        item.length  = val_len;
        batch_items.push_back(item);
      }

      Client::BatchReadResult batch;
      if (!state.client.batch_read(state.selected_pid, batch_items, batch)) {
        read_errors += static_cast<uint32_t>(chunk_end - base);
        continue;
      }

      uint32_t data_offset = 0U;
      for (size_t j = 0U; j < batch.entries.size(); ++j) {
        const auto &entry = batch.entries[j];
        const auto &old_entry = old_snap[base + j];

        if (entry.status != 0U || entry.length != val_len) {
          read_errors++;
          data_offset += entry.length;
          continue;
        }

        std::vector<uint8_t> current(
            batch.data.begin() + data_offset,
            batch.data.begin() + data_offset + entry.length);
        bytes_read += entry.length;
        data_offset += entry.length;

        if (!scan_refine_match(state.scan_snapshot_type, mode, old_entry.bytes, current))
          continue;

        ScanSnapshotEntry next;
        next.address = old_entry.address;
        next.bytes   = std::move(current);
        next_addresses.push_back(next.address);
        next_snapshot.push_back(std::move(next));
      }
    }
  } else {
    /* Fallback: individual memory_read per address. */
    for (size_t i = 0U; i < old_snap.size(); ++i) {
      std::vector<uint8_t> current;
      if (!state.client.memory_read(state.selected_pid, old_snap[i].address,
                                    val_len, current) || current.size() != val_len) {
        read_errors++;
        continue;
      }
      bytes_read += (uint64_t)current.size();

      if (!scan_refine_match(state.scan_snapshot_type, mode, old_snap[i].bytes, current))
        continue;

      ScanSnapshotEntry next;
      next.address = old_snap[i].address;
      next.bytes   = std::move(current);
      next_addresses.push_back(next.address);
      next_snapshot.push_back(std::move(next));
    }
  }

  const auto end = std::chrono::steady_clock::now();
  const uint64_t elapsed_ns = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count());
  state.scan_snapshot = std::move(next_snapshot);
  state.scan_result.addresses = std::move(next_addresses);
  state.scan_result.count = static_cast<uint32_t>(state.scan_result.addresses.size());
  state.scan_result.truncated = false;
  state.scan_result.bytes_scanned = bytes_read;
  state.scan_result.elapsed_ns = elapsed_ns;
  state.scan_result.read_calls = static_cast<uint32_t>(state.scan_snapshot.size() + read_errors);
  state.scan_result.regions_scanned = 0;
  state.scan_result.read_errors = read_errors;
  std::snprintf(state.scan_session_status, sizeof(state.scan_session_status),
                "%s refine kept %zu values", refine_mode_name(mode), state.scan_snapshot.size());
  set_status(state, state.scan_session_status);
  push_notification(state, std::string(refine_mode_name(mode)) + " refine: " + std::to_string(state.scan_snapshot.size()) + " values kept");
}

/* ---- Async scan poll ---- */
static void poll_scanner_async(AppState &state) {
  if (!state.scan_async_pending) return;
  if (!state.scan_async_future.valid()) return;

  auto status = state.scan_async_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;
  if (state.scan_async_owner != Screen::Scanner) return;

  state.scan_async_pending = false;
  bool ok = false;
  try {
    ok = state.scan_async_future.get();
  } catch (const std::exception &ex) {
    state.scan_async_error = ex.what();
  } catch (...) {
    state.scan_async_error = "Unknown scanner error";
  }

  if (!ok) {
    std::string error_local;
    {
      std::lock_guard<std::mutex> lock(state.scan_async_mtx);
      error_local = state.scan_async_error.empty() ? "Scanner request failed" : state.scan_async_error;
      state.scan_async_error.clear();
    }
    if (state.crash_logging_enabled)
      state.crash_logger.log("error", ("Scan failed: " + error_local).c_str());
    set_status(state, error_local);
    char sf_buf[512];
    std::snprintf(sf_buf, sizeof(sf_buf), locale::tr("scanner.scan_failed"), error_local.c_str());
    push_notification(state, sf_buf, 5.0);
    return;
  }

  /* Apply scan results from temp storage under lock */
  ScanResult result_local;
  std::vector<ScanSnapshotEntry> snapshot_local;
  uint32_t snap_val_len = 0;
  int snap_type = MEMDBG_VALUE_U32;
  bool is_unknown = false;
  char status_local[256] = {};
  std::vector<AutoSearchCandidate> auto_search_local;
  {
    std::lock_guard<std::mutex> lock(state.scan_async_mtx);
    result_local = std::move(state.scan_async_temp_result);
    snapshot_local = std::move(state.scan_async_temp_snapshot);
    snap_val_len = state.scan_async_temp_snapshot_value_len;
    snap_type = state.scan_async_temp_snapshot_type;
    is_unknown = state.scan_async_temp_is_unknown;
    auto_search_local = std::move(state.auto_search_temp_candidates);
    std::memcpy(status_local, state.scan_async_temp_session_status, sizeof(status_local));
  }
  state.scan_result = std::move(result_local);
  state.scan_snapshot = std::move(snapshot_local);
  state.scan_snapshot_value_len = snap_val_len;
  state.scan_snapshot_type = snap_type;
  state.scan_is_unknown_session = is_unknown;

  /* Post-scan: capture snapshot on the UI thread */
  // snapshot was already captured by the async worker via temp storage
  set_status(state, status_local);
  push_notification(state, std::string(state.scan_async_label) + " complete: " +
                    std::to_string(state.scan_result.count) + " results");  /* If auto-search is enabled and this was a scan, track pass progression.
   * Only the auto-search Next Scan lambda populates temp_candidates;
   * regular scans don't, so we gate on the temp vector being non-empty. */
  if (state.auto_search_enabled && !state.scan_snapshot.empty()) {
    if (!state.auto_search_has_baseline) {
      /* Baseline just captured — only set the flag, don't touch candidates */
      state.auto_search_has_baseline = true;
      state.auto_search_pass = 0;
      state.auto_search_candidates.clear();
      char auto_buf[256];
      std::snprintf(auto_buf, sizeof(auto_buf), locale::tr("notify.auto_baseline"), state.scan_snapshot.size());
      push_notification(state, auto_buf);
    } else if (!auto_search_local.empty()) {
      /* Next Scan just completed (only these populate temp_candidates) */
      state.auto_search_pass++;
      state.auto_search_candidates = std::move(auto_search_local);
      char pass_buf[256];
      std::snprintf(pass_buf, sizeof(pass_buf), locale::tr("notify.auto_pass"), state.auto_search_pass, state.scan_result.count);
      push_notification(state, pass_buf);
    }
  }
}

/* ---- Async scan launchers (validation on UI thread, blocking I/O on worker) ---- */

static void scan_range(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) { set_status(state, locale::tr("scanner.connect_first")); push_notification(state, locale::tr("scanner.connect_first"), 4.0); return; }
  if (state.selected_pid <= 0) { set_status(state, locale::tr("scanner.select_process_first")); push_notification(state, locale::tr("scanner.select_process_first"), 4.0); return; }
  uint64_t start=0, length=0;
  std::array<uint8_t,16> value{};
  uint32_t value_len=0;
  if (!parse_u64(state.scan_start,start)||!parse_u64(state.scan_length,length)) { set_status(state,locale::tr("scanner.invalid_range")); return; }
  if (length == 0U) { set_status(state, locale::tr("scanner.length_zero")); return; }
  if (!build_scan_value(state.scan_type,state.scan_value,value,value_len)) { set_status(state,locale::tr("scanner.invalid_value")); return; }
  state.scan_alignment=std::max(state.scan_alignment,1);
  state.scan_max_results=std::max(state.scan_max_results,1);
  memdbg_scan_exact_request_t request{};
  request.pid=state.selected_pid; request.start=start; request.length=length;
  request.value_type=static_cast<uint32_t>(state.scan_type); request.value_length=value_len;
  request.alignment=static_cast<uint32_t>(state.scan_alignment);
  request.max_results=static_cast<uint32_t>(state.scan_max_results);
  std::copy(value.begin(),value.end(),request.value);

  state.scan_async_label = "Range scan";
  state.scan_async_start_time = ImGui::GetTime();
  state.scan_async_pending = true;
  state.scan_async_owner = Screen::Scanner;

  const int32_t pid = state.selected_pid;
  const int scan_type_snap = state.scan_type;
  const auto snapshot_val_len = value_len;
  auto &client = state.client;
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_snap_type = state.scan_async_temp_snapshot_type;
  auto &temp_is_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;

  state.scan_async_future = std::async(std::launch::async,
    [&client, request, pid, scan_type_snap, snapshot_val_len,
     has_batch, &temp_result, &temp_snapshot, &temp_snap_val_len,
     &temp_snap_type, &temp_is_unknown, &temp_status, &error_out,
     &mtx = state.scan_async_mtx]() -> bool {
      std::lock_guard<std::mutex> lock(mtx);
      ScanResult scan_res;
      if (!client.scan_exact(request, scan_res)) {
        error_out = client.last_error();
        return false;
      }
      temp_result = std::move(scan_res);

      /* Capture snapshot on worker thread (network I/O, not UI) */
      temp_snapshot.clear();
      temp_snap_val_len = snapshot_val_len;
      temp_snap_type = scan_type_snap;
      temp_is_unknown = false;

      const auto &addrs = temp_result.addresses;
      if (!addrs.empty() && snapshot_val_len > 0U) {
        temp_snapshot.reserve(addrs.size());
        uint32_t read_errors = 0;
        const auto t_start = std::chrono::steady_clock::now();

        if (has_batch) {
          std::vector<memdbg_batch_read_item_t> batch_items;
          batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
          for (size_t base = 0U; base < addrs.size(); base += MEMDBG_BATCH_READ_MAX_ITEMS) {
            batch_items.clear();
            size_t chunk_end = std::min(base + MEMDBG_BATCH_READ_MAX_ITEMS, addrs.size());
            for (size_t i = base; i < chunk_end; ++i) {
              memdbg_batch_read_item_t item{};
              item.address = addrs[i];
              item.length  = snapshot_val_len;
              batch_items.push_back(item);
            }
            Client::BatchReadResult batch;
            if (!client.batch_read(pid, batch_items, batch)) {
              read_errors += static_cast<uint32_t>(chunk_end - base);
              continue;
            }
            uint32_t data_offset = 0U;
            for (size_t j = 0U; j < batch.entries.size(); ++j) {
              const auto &entry = batch.entries[j];
              if (entry.status != 0U || entry.length != snapshot_val_len) {
                read_errors++;
                data_offset += entry.length;
                continue;
              }
              ScanSnapshotEntry snap;
              snap.address = entry.address;
              snap.bytes.assign(batch.data.begin() + data_offset,
                                batch.data.begin() + data_offset + entry.length);
              temp_snapshot.push_back(std::move(snap));
              data_offset += entry.length;
            }
          }
        } else {
          for (size_t i = 0U; i < addrs.size(); ++i) {
            std::vector<uint8_t> data;
            if (!client.memory_read(pid, addrs[i], snapshot_val_len, data) ||
                data.size() != snapshot_val_len) {
              read_errors++;
              continue;
            }
            ScanSnapshotEntry snap;
            snap.address = addrs[i];
            snap.bytes   = std::move(data);
            temp_snapshot.push_back(std::move(snap));
          }
        }

        const auto t_end = std::chrono::steady_clock::now();
        const uint64_t elapsed_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count());
        const uint64_t capture_bytes = static_cast<uint64_t>(temp_snapshot.size()) * snapshot_val_len;
        const char *mode = has_batch ? "BATCH_READ" : "individual reads";
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu values (%u read errors, %s)",
                      mode, temp_snapshot.size(), read_errors,
                      bytes_per_second(capture_bytes, elapsed_ns).c_str());
        temp_result.read_calls += static_cast<uint32_t>(addrs.size());
        temp_result.read_errors += read_errors;
        temp_result.elapsed_ns += elapsed_ns;
      } else {
        std::snprintf(temp_status, sizeof(temp_status), "Range scan: %u hits", temp_result.count);
      }
      return true;
    });
}

static void scan_process(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) { set_status(state,"Connect a console first"); push_notification(state, "Connect a console before scanning processes", 4.0); return; }
  if (state.selected_pid <= 0) { set_status(state,"Select a process first"); push_notification(state, "Select a process before scanning", 4.0); return; }
  uint64_t start=0, end=0;
  std::array<uint8_t,16> value{};
  uint32_t value_len=0;
  if (!parse_u64(state.scan_start,start)||!parse_u64(state.scan_end,end)) { set_status(state,locale::tr("scanner.invalid_window")); return; }
  if (end != 0U && end <= start) { set_status(state, locale::tr("scanner.end_filter_error")); return; }
  if (!build_scan_value(state.scan_type,state.scan_value,value,value_len)) { set_status(state,"Invalid scan value"); return; }
  state.scan_alignment=std::max(state.scan_alignment,1);
  state.scan_max_results=std::max(state.scan_max_results,1);
  memdbg_scan_process_exact_request_t request{};
  request.pid=state.selected_pid; request.value_type=static_cast<uint32_t>(state.scan_type);
  request.value_length=value_len; request.alignment=static_cast<uint32_t>(state.scan_alignment);
  request.max_results=static_cast<uint32_t>(state.scan_max_results);
  request.protection_mask=state.scan_readable_only?1U:0U;
  request.start=start; request.end=end;
  std::copy(value.begin(),value.end(),request.value);

  state.scan_async_label = "Process scan";
  state.scan_async_start_time = ImGui::GetTime();
  state.scan_async_pending = true;
  state.scan_async_owner = Screen::Scanner;

  const int32_t pid = state.selected_pid;
  const int scan_type_snap = state.scan_type;
  const auto snapshot_val_len = value_len;
  auto &client = state.client;
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_snap_type = state.scan_async_temp_snapshot_type;
  auto &temp_is_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;

  state.scan_async_future = std::async(std::launch::async,
    [&client, request, pid, scan_type_snap, snapshot_val_len,
     has_batch, &temp_result, &temp_snapshot, &temp_snap_val_len,
     &temp_snap_type, &temp_is_unknown, &temp_status, &error_out,
     &mtx = state.scan_async_mtx]() -> bool {
      std::lock_guard<std::mutex> lock(mtx);
      ScanResult scan_res;
      if (!client.scan_process_exact(request, scan_res)) {
        error_out = client.last_error();
        return false;
      }
      temp_result = std::move(scan_res);
      temp_snapshot.clear();
      temp_snap_val_len = snapshot_val_len;
      temp_snap_type = scan_type_snap;
      temp_is_unknown = false;

      const auto &addrs = temp_result.addresses;
      if (!addrs.empty() && snapshot_val_len > 0U) {
        temp_snapshot.reserve(addrs.size());
        uint32_t read_errors = 0;
        const auto t_start = std::chrono::steady_clock::now();

        if (has_batch) {
          std::vector<memdbg_batch_read_item_t> batch_items;
          batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
          for (size_t base = 0U; base < addrs.size(); base += MEMDBG_BATCH_READ_MAX_ITEMS) {
            batch_items.clear();
            size_t chunk_end = std::min(base + MEMDBG_BATCH_READ_MAX_ITEMS, addrs.size());
            for (size_t i = base; i < chunk_end; ++i) {
              memdbg_batch_read_item_t item{};
              item.address = addrs[i];
              item.length  = snapshot_val_len;
              batch_items.push_back(item);
            }
            Client::BatchReadResult batch;
            if (!client.batch_read(pid, batch_items, batch)) {
              read_errors += static_cast<uint32_t>(chunk_end - base);
              continue;
            }
            uint32_t data_offset = 0U;
            for (size_t j = 0U; j < batch.entries.size(); ++j) {
              const auto &entry = batch.entries[j];
              if (entry.status != 0U || entry.length != snapshot_val_len) {
                read_errors++;
                data_offset += entry.length;
                continue;
              }
              ScanSnapshotEntry snap;
              snap.address = entry.address;
              snap.bytes.assign(batch.data.begin() + data_offset,
                                batch.data.begin() + data_offset + entry.length);
              temp_snapshot.push_back(std::move(snap));
              data_offset += entry.length;
            }
          }
        } else {
          for (size_t i = 0U; i < addrs.size(); ++i) {
            std::vector<uint8_t> data;
            if (!client.memory_read(pid, addrs[i], snapshot_val_len, data) ||
                data.size() != snapshot_val_len) {
              read_errors++;
              continue;
            }
            ScanSnapshotEntry snap;
            snap.address = addrs[i];
            snap.bytes   = std::move(data);
            temp_snapshot.push_back(std::move(snap));
          }
        }

        const auto t_end = std::chrono::steady_clock::now();
        const uint64_t elapsed_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count());
        const uint64_t capture_bytes = static_cast<uint64_t>(temp_snapshot.size()) * snapshot_val_len;
        const char *mode = has_batch ? "BATCH_READ" : "individual reads";
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu values (%u read errors, %s)",
                      mode, temp_snapshot.size(), read_errors,
                      bytes_per_second(capture_bytes, elapsed_ns).c_str());
        temp_result.read_calls += static_cast<uint32_t>(addrs.size());
        temp_result.read_errors += read_errors;
        temp_result.elapsed_ns += elapsed_ns;
      } else {
        std::snprintf(temp_status, sizeof(temp_status), "Process scan: %u hits", temp_result.count);
      }
      return true;
    });
}

static void scan_unknown_process(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) { set_status(state,"Connect a console first"); push_notification(state, "Connect a console before scanning", 4.0); return; }
  if (state.selected_pid <= 0) { set_status(state,"Select a process first"); push_notification(state, "Select a process before scanning", 4.0); return; }
  if (!(state.hello.capabilities & MEMDBG_CAP_SCAN_UNKNOWN)) {
    set_status(state,locale::tr("scanner.no_unknown_cap")); return;
  }
  uint64_t start=0, end=0;
  if (!parse_u64(state.scan_start,start)||!parse_u64(state.scan_end,end)) { set_status(state,"Invalid scan window"); return; }
  if (end != 0U && end <= start) { set_status(state, "End filter must be greater than start, or 0x0"); return; }
  state.scan_alignment=std::max(state.scan_alignment,1);
  state.scan_max_results=std::max(state.scan_max_results,1);
  memdbg_scan_process_exact_request_t request{};
  memset(&request,0,sizeof(request));
  request.pid=state.selected_pid;
  request.value_type=static_cast<uint32_t>(state.scan_type);
  request.value_length=current_scan_value_len(state);
  request.alignment=static_cast<uint32_t>(state.scan_alignment);
  request.max_results=static_cast<uint32_t>(state.scan_max_results);
  request.protection_mask=state.scan_readable_only?1U:0U;
  request.start=start; request.end=end;

  state.scan_async_label = "Unknown value scan";
  state.scan_async_start_time = ImGui::GetTime();
  state.scan_async_pending = true;
  state.scan_async_owner = Screen::Scanner;

  const int32_t pid = state.selected_pid;
  const int scan_type_snap = state.scan_type;
  const auto snapshot_val_len = current_scan_value_len(state);
  auto &client = state.client;
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_snap_type = state.scan_async_temp_snapshot_type;
  auto &temp_is_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;

  state.scan_async_future = std::async(std::launch::async,
    [&client, request, pid, scan_type_snap, snapshot_val_len,
     has_batch, &temp_result, &temp_snapshot, &temp_snap_val_len,
     &temp_snap_type, &temp_is_unknown, &temp_status, &error_out,
     &mtx = state.scan_async_mtx]() -> bool {
      std::lock_guard<std::mutex> lock(mtx);
      ScanResult scan_res;
      if (!client.scan_unknown(request, scan_res)) {
        error_out = client.last_error();
        return false;
      }
      temp_result = std::move(scan_res);
      temp_snapshot.clear();
      temp_snap_val_len = snapshot_val_len;
      temp_snap_type = scan_type_snap;
      temp_is_unknown = true;

      const auto &addrs = temp_result.addresses;
      if (!addrs.empty() && snapshot_val_len > 0U) {
        temp_snapshot.reserve(addrs.size());
        uint32_t read_errors = 0;
        const auto t_start = std::chrono::steady_clock::now();

        if (has_batch) {
          std::vector<memdbg_batch_read_item_t> batch_items;
          batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
          for (size_t base = 0U; base < addrs.size(); base += MEMDBG_BATCH_READ_MAX_ITEMS) {
            batch_items.clear();
            size_t chunk_end = std::min(base + MEMDBG_BATCH_READ_MAX_ITEMS, addrs.size());
            for (size_t i = base; i < chunk_end; ++i) {
              memdbg_batch_read_item_t item{};
              item.address = addrs[i];
              item.length  = snapshot_val_len;
              batch_items.push_back(item);
            }
            Client::BatchReadResult batch;
            if (!client.batch_read(pid, batch_items, batch)) {
              read_errors += static_cast<uint32_t>(chunk_end - base);
              continue;
            }
            uint32_t data_offset = 0U;
            for (size_t j = 0U; j < batch.entries.size(); ++j) {
              const auto &entry = batch.entries[j];
              if (entry.status != 0U || entry.length != snapshot_val_len) {
                read_errors++;
                data_offset += entry.length;
                continue;
              }
              ScanSnapshotEntry snap;
              snap.address = entry.address;
              snap.bytes.assign(batch.data.begin() + data_offset,
                                batch.data.begin() + data_offset + entry.length);
              temp_snapshot.push_back(std::move(snap));
              data_offset += entry.length;
            }
          }
        } else {
          for (size_t i = 0U; i < addrs.size(); ++i) {
            std::vector<uint8_t> data;
            if (!client.memory_read(pid, addrs[i], snapshot_val_len, data) ||
                data.size() != snapshot_val_len) {
              read_errors++;
              continue;
            }
            ScanSnapshotEntry snap;
            snap.address = addrs[i];
            snap.bytes   = std::move(data);
            temp_snapshot.push_back(std::move(snap));
          }
        }

        const auto t_end = std::chrono::steady_clock::now();
        const uint64_t elapsed_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count());
        const uint64_t capture_bytes = static_cast<uint64_t>(temp_snapshot.size()) * snapshot_val_len;
        const char *mode = has_batch ? "BATCH_READ" : "individual reads";
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu values (%u read errors, %s)",
                      mode, temp_snapshot.size(), read_errors,
                      bytes_per_second(capture_bytes, elapsed_ns).c_str());
        temp_result.read_calls += static_cast<uint32_t>(addrs.size());
        temp_result.read_errors += read_errors;
        temp_result.elapsed_ns += elapsed_ns;
      } else {
        std::snprintf(temp_status, sizeof(temp_status), "Unknown scan: %u addresses", temp_result.count);
      }
      return true;
    });
}

/* ---- Main draw ---- */

void draw_scanner(AppState &state, ImVec2 avail) {
  poll_scanner_async(state);

  const float gap = 16.0f;
  const float left_w = std::max(420.0f, (avail.x - gap) * 0.38f);
  const char *type_names[] = {"Bytes","u8","u16","u32","u64","float","double","pointer"};

  ui::begin_panel("ScannerControl", locale::tr("scanner.exact_scan"), ImVec2(left_w, avail.y));
  ImGui::Text(locale::tr("scanner.active_pid"), state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  ImGui::Combo(locale::tr("scanner.value_type"), &state.scan_type, type_names, IM_ARRAYSIZE(type_names));
  ImGui::InputText(locale::tr("scanner.value"), state.scan_value, sizeof(state.scan_value));
  ImGui::InputInt(locale::tr("scanner.alignment"), &state.scan_alignment);
  ImGui::InputInt(locale::tr("scanner.max_results"), &state.scan_max_results);
  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::InputText(locale::tr("scanner.start"), state.scan_start, sizeof(state.scan_start));
  ImGui::InputText(locale::tr("scanner.length"), state.scan_length, sizeof(state.scan_length));
  bool can_launch_range = !state.scan_async_pending && state.client.connected() &&
                          state.selected_pid > 0 &&
                          payload_supports(state, MEMDBG_CAP_SCAN_EXACT);
  ImGui::BeginDisabled(!can_launch_range);
  if (ui::primary_button((std::string(icons::kSearch) + "  " + locale::tr("scanner.scan_range")).c_str(), ui::full_button(40))) scan_range(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::InputText(locale::tr("scanner.end_filter"), state.scan_end, sizeof(state.scan_end));
  ImGui::Checkbox(locale::tr("scanner.readable_only"), &state.scan_readable_only);
  bool can_launch_process = !state.scan_async_pending && state.client.connected() &&
                            state.selected_pid > 0 &&
                            payload_supports(state, MEMDBG_CAP_SCAN_PROCESS_EXACT);
  ImGui::BeginDisabled(!can_launch_process);
  if (ui::soft_button((std::string(icons::kTarget) + "  " + locale::tr("scanner.scan_process")).c_str(), ui::full_button(40))) scan_process(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().warning, "%s", locale::tr("scanner.unknown_value"));
  ImGui::TextWrapped("%s", locale::tr("scanner.unknown_desc"));
  bool can_launch_unknown = !state.scan_async_pending && state.client.connected() &&
                            state.selected_pid > 0 &&
                            payload_supports(state, MEMDBG_CAP_SCAN_UNKNOWN);
  ImGui::BeginDisabled(!can_launch_unknown);
  if (ui::primary_button((std::string(icons::kSearch) + "  " + locale::tr("scanner.unknown_scan")).c_str(), ui::full_button(40))) scan_unknown_process(state);
  ImGui::EndDisabled();

  /* Progress bar for async scans */
  if (state.scan_async_pending)
    ui::draw_scan_progress(state.scan_async_label, icons::kSearch,
                           ImGui::GetTime() - state.scan_async_start_time,
                           ImGui::GetContentRegionAvail().x);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  const char *session_label = state.scan_is_unknown_session ? locale::tr("scanner.unknown_session") : locale::tr("scanner.next_scan");
  ImGui::TextColored(state.scan_is_unknown_session ? ui::colors().warning : ui::colors().muted, "%s", session_label);
  ImGui::TextWrapped("%s", state.scan_session_status);
  if (state.scan_is_unknown_session && !state.scan_snapshot.empty())
    ImGui::TextColored(ui::colors().dim, locale::tr("scanner.tracking_n"),
                       state.scan_snapshot.size(), state.scan_snapshot_value_len);
  ImGui::Spacing();

  bool can_refine = state.client.connected() && state.selected_pid > 0 &&
                    payload_supports(state, MEMDBG_CAP_MEMORY_READ) &&
                    !state.scan_snapshot.empty() && !state.scan_async_pending;
  const float half_w = (ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f;
  ImGui::BeginDisabled(!can_refine);
  if (ui::soft_button(locale::tr("scanner.changed"), ImVec2(half_w, 38))) refine_scan(state, RefineMode::Changed);
  ImGui::SameLine();
  if (ui::soft_button(locale::tr("scanner.unchanged"), ImVec2(0, 38))) refine_scan(state, RefineMode::Unchanged);
  if (ui::soft_button(locale::tr("scanner.increased"), ImVec2(half_w, 38))) refine_scan(state, RefineMode::Increased);
  ImGui::SameLine();
  if (ui::soft_button(locale::tr("scanner.decreased"), ImVec2(0, 38))) refine_scan(state, RefineMode::Decreased);
  ImGui::EndDisabled();
  bool can_refresh = state.client.connected() &&
                     payload_supports(state, MEMDBG_CAP_MEMORY_READ) &&
                     !state.scan_snapshot.empty() && !state.scan_async_pending;
  ImGui::BeginDisabled(!can_refresh);
  std::string next_label = std::string(icons::kRefresh) + "  " +
      std::string(state.scan_is_unknown_session ? locale::tr("scanner.next_scan_refresh_all") : locale::tr("scanner.refresh_baseline"));
  if (ui::soft_button(next_label.c_str(), ui::full_button(38))) {
    capture_scan_snapshot(state);
    set_status(state, state.scan_session_status);
  }
  ImGui::EndDisabled();

  /* ---- Smart Auto-Search ---- */
  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();
  ImGui::Checkbox(locale::tr("scanner.smart_auto"), &state.auto_search_enabled);
  if (state.auto_search_enabled) {
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.0f);
    const char *target_names[] = {locale::tr("scanner.target_health"), locale::tr("scanner.target_ammo"), locale::tr("scanner.target_resources")};
    if (ImGui::Combo("##autotarget", &state.auto_search_target,
                     target_names, IM_ARRAYSIZE(target_names)))
      state.auto_search_has_baseline = false;

    /* Hint text — warn about critical instructions like "don't reload" */
    AutoSearchTarget hint_tgt =
        static_cast<AutoSearchTarget>(state.auto_search_target);
    ImVec4 hint_color = hint_tgt == AutoSearchTarget::Ammo
                            ? ui::colors().warning
                            : ui::colors().dim;
    ImGui::TextColored(hint_color, "%s",
                       auto_search_target_hint(hint_tgt));

    /* Baseline capture: auto-search piggybacks on the Unknown Value Scan */
    bool can_baseline = can_launch_unknown;
    ImGui::BeginDisabled(!can_baseline);
    if (ui::soft_button((std::string(icons::kTarget) + "  " + locale::tr("scanner.capture_baseline")).c_str(),
                        ui::full_button(38))) {
      state.auto_search_has_baseline = false;
      state.auto_search_pass = 0;
      /* Run an Unknown Value Scan — the async worker will store the snapshot
       * as the baseline via the auto_search_has_baseline flag */
      scan_unknown_process(state);
    }
    ImGui::EndDisabled();

    /* Next Scan: re-read and score candidates */
    bool can_next = state.auto_search_has_baseline && can_launch_unknown &&
                    !state.scan_snapshot.empty();
    ImGui::BeginDisabled(!can_next);    char ns_buf[128];
    std::snprintf(ns_buf, sizeof(ns_buf), locale::tr("scanner.next_scan_pass"), state.auto_search_pass + 1);
    std::string next_label = std::string(icons::kRefresh) + "  " + ns_buf;
    if (ui::primary_button(next_label.c_str(), ui::full_button(38))) {
      /* Re-read baseline addresses and score them on the async worker.
       * We reuse the refine_scan Changed path but with scoring layered on top. */
      AutoSearchTarget tgt = static_cast<AutoSearchTarget>(state.auto_search_target);
      state.scan_async_label = "Auto-search pass " +
                               std::to_string(state.auto_search_pass + 1);
      state.scan_async_start_time = ImGui::GetTime();
      state.scan_async_pending = true;
      state.scan_async_owner = Screen::Scanner;

      const int32_t pid = state.selected_pid;
      const uint32_t val_len = state.scan_snapshot_value_len;
      const int snap_type = state.scan_snapshot_type;
      auto &client = state.client;
      auto &snap = state.scan_snapshot;
      const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;
      auto &temp_result = state.scan_async_temp_result;
      auto &temp_snapshot = state.scan_async_temp_snapshot;
      auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
      auto &temp_snap_type = state.scan_async_temp_snapshot_type;
      auto &temp_is_unknown = state.scan_async_temp_is_unknown;
      auto &temp_status = state.scan_async_temp_session_status;
      auto &temp_candidates = state.auto_search_temp_candidates;

      state.scan_async_future = std::async(std::launch::async,
        [&client, pid, val_len, snap_type, tgt, has_batch,
         &snap, &temp_result, &temp_snapshot, &temp_snap_val_len,
         &temp_snap_type, &temp_is_unknown, &temp_status,
         &temp_candidates, &mtx = state.scan_async_mtx]() -> bool {
          /* Re-read all baseline addresses */
          const auto &old_snap = snap;
          std::vector<ScanSnapshotEntry> current_snap;
          std::vector<uint64_t> current_addrs;
          current_snap.reserve(old_snap.size());
          current_addrs.reserve(old_snap.size());
          uint32_t read_errors = 0;
          uint64_t bytes_read = 0;
          const auto t_start = std::chrono::steady_clock::now();
          std::vector<memdbg_batch_read_item_t> batch_items;

          if (has_batch) {
            batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
            for (size_t base = 0U; base < old_snap.size();
                 base += MEMDBG_BATCH_READ_MAX_ITEMS) {
              batch_items.clear();
              size_t chunk_end = std::min(
                  base + MEMDBG_BATCH_READ_MAX_ITEMS, old_snap.size());
              for (size_t i = base; i < chunk_end; ++i) {
                memdbg_batch_read_item_t item{};
                item.address = old_snap[i].address;
                item.length  = val_len;
                batch_items.push_back(item);
              }
              Client::BatchReadResult batch;
              if (!client.batch_read(pid, batch_items, batch)) {
                read_errors += static_cast<uint32_t>(chunk_end - base);
                continue;
              }
              uint32_t data_offset = 0U;
              for (size_t j = 0U; j < batch.entries.size(); ++j) {
                const auto &entry = batch.entries[j];
                if (entry.status != 0U || entry.length != val_len) {
                  read_errors++;
                  data_offset += entry.length;
                  continue;
                }
                ScanSnapshotEntry cur;
                cur.address = entry.address;
                cur.bytes.assign(batch.data.begin() + data_offset,
                                 batch.data.begin() + data_offset + entry.length);
                current_snap.push_back(std::move(cur));
                current_addrs.push_back(entry.address);
                bytes_read += entry.length;
                data_offset += entry.length;
              }
            }
          } else {
            for (size_t i = 0U; i < old_snap.size(); ++i) {
              std::vector<uint8_t> data;
              if (!client.memory_read(pid, old_snap[i].address, val_len, data) ||
                  data.size() != val_len) {
                read_errors++;
                continue;
              }
              ScanSnapshotEntry cur;
              cur.address = old_snap[i].address;
              cur.bytes   = std::move(data);
              current_snap.push_back(std::move(cur));
              current_addrs.push_back(old_snap[i].address);
              bytes_read += val_len;
            }
          }

          /* Run auto-search engine */
          AutoSearchEngine engine;
          engine.set_target(tgt);
          engine.set_baseline(old_snap, snap_type, val_len);
          auto candidates = engine.score_candidates(current_snap, 100);

          /* Store scored candidates and build new snapshot under lock */
          {
            std::lock_guard<std::mutex> lock(mtx);
            temp_candidates = std::move(candidates);

            /* Build new snapshot from the top candidates (keep them for next pass) */
            temp_snapshot.clear();
          temp_snapshot.reserve(candidates.size());
          temp_result.addresses.clear();
          temp_result.addresses.reserve(candidates.size());
          for (auto &c : candidates) {
            /* Map candidate back to current snapshot bytes */
            for (const auto &cs : current_snap) {
              if (cs.address == c.address) {
                ScanSnapshotEntry se;
                se.address = c.address;
                se.bytes   = cs.bytes;
                temp_snapshot.push_back(std::move(se));
                break;
              }
            }
            temp_result.addresses.push_back(c.address);
          }
          temp_result.count = static_cast<uint32_t>(temp_result.addresses.size());
          temp_result.bytes_scanned = bytes_read;
          temp_result.read_calls = static_cast<uint32_t>(current_snap.size() + read_errors);
          temp_snap_val_len = val_len;
          temp_snap_type = snap_type;
          temp_is_unknown = false;

          const auto t_end = std::chrono::steady_clock::now();
          const uint64_t elapsed_ns = static_cast<uint64_t>(
              std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count());
          temp_result.elapsed_ns = elapsed_ns;
          temp_result.read_errors = read_errors;
          std::snprintf(temp_status, sizeof(temp_status),
                        "Auto-search: %u candidates scored (%s)",
                        temp_result.count,
                        bytes_per_second(bytes_read, elapsed_ns).c_str());
          }
          return true;
        });
    }
    ImGui::EndDisabled();

    if (state.auto_search_has_baseline && !state.scan_snapshot.empty())
      ImGui::TextColored(ui::colors().dim, locale::tr("scanner.baseline_n_values"),
                         state.scan_snapshot.size());
    if (state.auto_search_pass > 0)
      ImGui::TextColored(ui::colors().success, locale::tr("scanner.pass_n_complete"),
                         state.auto_search_pass);

    /* Reset button */
    if (state.auto_search_has_baseline) {
      ImGui::SameLine();
      if (ImGui::SmallButton(locale::tr("scanner.reset"))) {
        state.auto_search_has_baseline = false;
        state.auto_search_pass = 0;
        state.auto_search_candidates.clear();
        set_status(state, locale::tr("scanner.auto_search_reset"));
      }
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", locale::tr("scanner.reset_tooltip"));
    }

    /* Display scored candidates if available */
    if (!state.auto_search_candidates.empty()) {
      ImGui::Spacing();
      ImGui::TextColored(ui::colors().primary2, "%s", locale::tr("scanner.top_candidates"));
      ImGui::Spacing();
      if (ImGui::BeginTable("AutoSearchResults", 4,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
            ImVec2(0, 200.0f))) {
        ImGui::TableSetupColumn(locale::tr("scanner.score_col"), ImGuiTableColumnFlags_WidthFixed, 55);
        ImGui::TableSetupColumn(locale::tr("scanner.address_col"), ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn(locale::tr("scanner.old_new_col"));
        ImGui::TableSetupColumn(locale::tr("scanner.reason_col"));
        ImGui::TableHeadersRow();
        for (size_t i = 0U;
             i < state.auto_search_candidates.size() && i < 20U; ++i) {
          const auto &c = state.auto_search_candidates[i];
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          /* Color-code score: green > 0.7, yellow > 0.4, dim otherwise */
          ImVec4 sc = c.score > 0.7f ? ui::colors().success :
                      c.score > 0.4f ? ui::colors().warning : ui::colors().dim;
          ImGui::TextColored(sc, "%.2f", c.score);
          ImGui::TableSetColumnIndex(1);
          std::string addr_label = hex_u64(c.address) + "##ac" +
                                   std::to_string(i);
          if (ImGui::Selectable(addr_label.c_str())) {
            std::snprintf(state.read_address, sizeof(state.read_address),
                          "%s", hex_u64(c.address).c_str());
            std::snprintf(state.write_address, sizeof(state.write_address),
                          "%s", hex_u64(c.address).c_str());
            state.screen = Screen::Memory;
          }
          ImGui::TableSetColumnIndex(2);
          ImGui::Text("%s \xe2\x86\x92 %s",
                      c.old_value_str().c_str(), c.new_value_str().c_str());
          ImGui::TableSetColumnIndex(3);
          ImGui::TextColored(ui::colors().muted, "%s", c.reason().c_str());
          if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s: %s", locale::tr("scanner.value_type"), value_type_name(c.value_type));
        }
        ImGui::EndTable();
      }
    }
  }
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("ScannerResults", locale::tr("scanner.results_title"), ImVec2(0, avail.y));
  ImGui::Text(locale::tr("scanner.results_count"), state.scan_result.count,
              state.scan_result.truncated ? locale::tr("scanner.truncated") : "");
  ImGui::Text("%s %s", locale::tr("scanner.results_type"), value_type_name(state.scan_type));
  ImGui::Text(locale::tr("scanner.scanned_mib"), static_cast<double>(state.scan_result.bytes_scanned)/(1024.0*1024.0));
  ImGui::Text(locale::tr("scanner.speed"), bytes_per_second(state.scan_result.bytes_scanned, state.scan_result.elapsed_ns).c_str());
  ImGui::Text(locale::tr("scanner.reads_regions_errors"),
              state.scan_result.read_calls, state.scan_result.regions_scanned, state.scan_result.read_errors);
  ImGui::Text(locale::tr("scanner.session_captured"), state.scan_snapshot.size());
  /* BATCH_READ status badge */
  if (!state.scan_snapshot.empty()) {
    ImGui::SameLine();
    if (has_batch_read(state)) {
      ImGui::TextColored(ui::colors().success, "  %s", icons::kGauge);
      if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("scanner.batch_active"));
    } else {
      ImGui::TextColored(ui::colors().warning, "  %s", icons::kWarning);
      if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", locale::tr("scanner.batch_unavailable"));
    }
  }
  ImGui::Spacing();

  /* Copy All logic shared between button and keyboard shortcut */
  auto copy_all = [&](const char *suffix = nullptr) {
    std::string all;
    all.reserve(state.scan_result.addresses.size() * 18U);
    for (uint64_t addr : state.scan_result.addresses)
      all += hex_u64(addr) + "\n";
    ImGui::SetClipboardText(all.c_str());
    set_status(state, "Copied " + std::to_string(state.scan_result.addresses.size()) + " addresses");
    push_notification(state, "Copied " + std::to_string(state.scan_result.addresses.size()) + " addresses to clipboard" + (suffix ? suffix : ""));
  };

  if (!state.scan_result.addresses.empty()) {
    if (ui::soft_button((std::string(icons::kCopy) + "  " + locale::tr("scanner.copy_all")).c_str(),
                        ImVec2(200, 30)))
      copy_all();
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip(locale::tr("scanner.copy_all_tooltip"),
                        state.scan_result.count);
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_C))
      copy_all(" (Ctrl+C)");
  }

  if (ImGui::BeginTable("ScanResultsTable", 2,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY, ImVec2(0,0))) {
    ImGui::TableSetupColumn(locale::tr("scanner.address_col"));
    ImGui::TableSetupColumn(locale::tr("scanner.current_value_col"));
    ImGui::TableHeadersRow();
    /* Two-pointer lookup: both scan_result.addresses and scan_snapshot are sorted
       and built in the same order (snapshot may skip read errors). */
    size_t snap_idx = 0U;
    for (int i = 0; i < static_cast<int>(state.scan_result.addresses.size()); ++i) {
      uint64_t addr = state.scan_result.addresses[i];
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      std::string label = hex_u64(addr) + "##scan" + std::to_string(i);
      if (ImGui::Selectable(label.c_str())) {
        std::snprintf(state.read_address, sizeof(state.read_address), "%s", hex_u64(addr).c_str());
        std::snprintf(state.write_address, sizeof(state.write_address), "%s", hex_u64(addr).c_str());
        state.screen = Screen::Memory;
      }
      ImGui::TableSetColumnIndex(1);
      /* Advance snapshot pointer to match current address (both arrays sorted) */
      while (snap_idx < state.scan_snapshot.size() &&
             state.scan_snapshot[snap_idx].address < addr) snap_idx++;
      if (snap_idx < state.scan_snapshot.size() &&
          state.scan_snapshot[snap_idx].address == addr) {
        const auto &snap = state.scan_snapshot[snap_idx];
        switch (state.scan_snapshot_type) {
        case MEMDBG_VALUE_U8:
          if (snap.bytes.size() >= 1) ImGui::Text("%u", (unsigned)snap.bytes[0]);
          break;
        case MEMDBG_VALUE_U16:
          if (snap.bytes.size() >= 2) ImGui::Text("%u", read_scalar<uint16_t>(snap.bytes));
          break;
        case MEMDBG_VALUE_U32:
          if (snap.bytes.size() >= 4) ImGui::Text("%u", read_scalar<uint32_t>(snap.bytes));
          break;
        case MEMDBG_VALUE_U64: case MEMDBG_VALUE_POINTER:
          if (snap.bytes.size() >= 8) ImGui::Text("%s", hex_u64(read_scalar<uint64_t>(snap.bytes)).c_str());
          break;
        case MEMDBG_VALUE_F32:
          if (snap.bytes.size() >= 4) ImGui::Text("%.6g", (double)read_scalar<float>(snap.bytes));
          break;
        case MEMDBG_VALUE_F64:
          if (snap.bytes.size() >= 8) ImGui::Text("%.12g", read_scalar<double>(snap.bytes));
          break;
        case MEMDBG_VALUE_BYTES: {
          std::string hex;
          for (size_t b = 0; b < snap.bytes.size() && b < 8; ++b) {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%02X ", snap.bytes[b]);
            hex += buf;
          }
          if (snap.bytes.size() > 8) hex += "...";
          ImGui::TextUnformatted(hex.c_str());
          break;
        }
        default: ImGui::TextUnformatted("?"); break;
        }
      } else {
        ImGui::TextColored(ui::colors().dim, "%s", locale::tr("scanner.n_a"));
      }
    }
    ImGui::EndTable();
  }

  ui::end_panel();
}

} // namespace memdbg::frontend

/*
 * MemDBG - Async scan launchers: range, process, unknown, and poll.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scanner_internal.hpp"

#include <chrono>
#include <exception>
#include <future>
#include <mutex>

namespace memdbg::frontend {

void poll_scanner_async(AppState &state) {
  if (!state.scan_async_pending) return;
  if (!state.scan_async_future.valid()) return;

  auto status = state.scan_async_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.scan_async_pending = false;
  bool ok = false;
  try {
    ok = state.scan_async_future.get();
  } catch (const std::exception &ex) {
    state.scan_async_error = ex.what();
  } catch (...) {
    state.scan_async_error = "Unknown scanner error";
  }

  if (state.scan_async_owner != Screen::Scanner) return;


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

void scan_range(AppState &state) {
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

void scan_process(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) { set_status(state,locale::tr("scanner.connect_first")); push_notification(state, locale::tr("scanner.scan_connect_first_notify"), 4.0); return; }
  if (state.selected_pid <= 0) { set_status(state,locale::tr("scanner.select_process_first")); push_notification(state, locale::tr("scanner.scan_select_process_notify"), 4.0); return; }
  uint64_t start=0, end=0;
  std::array<uint8_t,16> value{};
  uint32_t value_len=0;
  if (!parse_u64(state.scan_start,start)||!parse_u64(state.scan_end,end)) { set_status(state,locale::tr("scanner.invalid_window")); return; }
  if (end != 0U && end <= start) { set_status(state, locale::tr("scanner.end_filter_error")); return; }
  if (!build_scan_value(state.scan_type,state.scan_value,value,value_len)) { set_status(state,locale::tr("scanner.invalid_value")); return; }
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

void scan_unknown_process(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) { set_status(state,locale::tr("scanner.connect_first")); push_notification(state, locale::tr("scanner.scan_select_process_notify"), 4.0); return; }
  if (state.selected_pid <= 0) { set_status(state,locale::tr("scanner.select_process_first")); push_notification(state, locale::tr("scanner.scan_select_process_notify"), 4.0); return; }
  if (!(state.hello.capabilities & MEMDBG_CAP_SCAN_UNKNOWN)) {
    set_status(state,locale::tr("scanner.no_unknown_cap")); return;
  }
  uint64_t start=0, end=0;
  if (!parse_u64(state.scan_start,start)||!parse_u64(state.scan_end,end)) { set_status(state,locale::tr("scanner.invalid_window")); return; }
  if (end != 0U && end <= start) { set_status(state, locale::tr("scanner.end_filter_error")); return; }
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

} // namespace memdbg::frontend

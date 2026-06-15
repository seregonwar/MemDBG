/*
 * MemDBG - Scanner screen.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_state.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <future>

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

template <typename T> static T read_scalar(const std::vector<uint8_t> &bytes) {
  T value{};
  if (bytes.size() >= sizeof(T)) std::memcpy(&value, bytes.data(), sizeof(T));
  return value;
}

static bool bytes_to_number(int type, const std::vector<uint8_t> &bytes, long double &out) {
  switch (type) {
  case MEMDBG_VALUE_U8:  out = read_scalar<uint8_t>(bytes); return bytes.size() >= sizeof(uint8_t);
  case MEMDBG_VALUE_U16: out = read_scalar<uint16_t>(bytes); return bytes.size() >= sizeof(uint16_t);
  case MEMDBG_VALUE_U32: out = read_scalar<uint32_t>(bytes); return bytes.size() >= sizeof(uint32_t);
  case MEMDBG_VALUE_U64: case MEMDBG_VALUE_POINTER: out = static_cast<long double>(read_scalar<uint64_t>(bytes)); return bytes.size() >= sizeof(uint64_t);
  case MEMDBG_VALUE_F32: out = read_scalar<float>(bytes); return bytes.size() >= sizeof(float);
  case MEMDBG_VALUE_F64: out = read_scalar<double>(bytes); return bytes.size() >= sizeof(double);
  default: return false;
  }
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
    std::snprintf(state.scan_session_status, sizeof(state.scan_session_status), "No scan values captured");
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
  if (!has_batch_read(state) && !addrs.empty())
    set_status(state, "Using individual memory_read \xe2\x80\x94 payload lacks BATCH_READ support");
  state.scan_result.read_calls += static_cast<uint32_t>(addrs.size());
  state.scan_result.read_errors += read_errors;
  state.scan_result.elapsed_ns += elapsed_ns;
}

static void refine_scan(AppState &state, RefineMode mode) {
  if (!state.client.connected()) { set_status(state, "Connect a console first"); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); return; }
  if (state.scan_snapshot.empty() || state.scan_snapshot_value_len == 0U) {
    set_status(state, "Run a scan before refining"); return;
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
    if (state.scan_async_error.empty()) state.scan_async_error = "Scanner request failed";
    set_status(state, state.scan_async_error);
    push_notification(state, "Scan failed: " + state.scan_async_error, 5.0);
    return;
  }

  /* Apply scan results from temp storage */
  state.scan_result = std::move(state.scan_async_temp_result);
  state.scan_snapshot = std::move(state.scan_async_temp_snapshot);
  state.scan_snapshot_value_len = state.scan_async_temp_snapshot_value_len;
  state.scan_snapshot_type = state.scan_async_temp_snapshot_type;
  state.scan_is_unknown_session = state.scan_async_temp_is_unknown;

  /* Post-scan: capture snapshot on the UI thread */
  // snapshot was already captured by the async worker via temp storage
  set_status(state, state.scan_async_temp_session_status);
  push_notification(state, std::string(state.scan_async_label) + " complete: " +
                    std::to_string(state.scan_result.count) + " results");
}

/* ---- Async scan launchers (validation on UI thread, blocking I/O on worker) ---- */

static void scan_range(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) { set_status(state, "Connect a console first"); push_notification(state, "Connect a console before scanning", 4.0); return; }
  if (state.selected_pid <= 0) { set_status(state, "Select a process first"); push_notification(state, "Select a process before scanning", 4.0); return; }
  uint64_t start=0, length=0;
  std::array<uint8_t,16> value{};
  uint32_t value_len=0;
  if (!parse_u64(state.scan_start,start)||!parse_u64(state.scan_length,length)) { set_status(state,"Invalid scan range"); return; }
  if (length == 0U) { set_status(state, "Scan length must be greater than zero"); return; }
  if (!build_scan_value(state.scan_type,state.scan_value,value,value_len)) { set_status(state,"Invalid scan value"); return; }
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
     &temp_snap_type, &temp_is_unknown, &temp_status, &error_out]() -> bool {
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
  if (!parse_u64(state.scan_start,start)||!parse_u64(state.scan_end,end)) { set_status(state,"Invalid process scan window"); return; }
  if (end != 0U && end <= start) { set_status(state, "End filter must be greater than start, or 0x0"); return; }
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
     &temp_snap_type, &temp_is_unknown, &temp_status, &error_out]() -> bool {
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
    set_status(state,"Payload does not support unknown value scan"); return;
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
     &temp_snap_type, &temp_is_unknown, &temp_status, &error_out]() -> bool {
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

  ui::begin_panel("ScannerControl", "Exact Scan", ImVec2(left_w, avail.y));
  ImGui::Text("Active PID: %d", state.selected_pid);
  ImGui::TextColored(ui::colors().muted, "%s", selected_process_name(state).c_str());
  ImGui::Spacing();

  ImGui::Combo("Value type", &state.scan_type, type_names, IM_ARRAYSIZE(type_names));
  ImGui::InputText("Value", state.scan_value, sizeof(state.scan_value));
  ImGui::InputInt("Alignment", &state.scan_alignment);
  ImGui::InputInt("Max results", &state.scan_max_results);
  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::InputText("Start", state.scan_start, sizeof(state.scan_start));
  ImGui::InputText("Length", state.scan_length, sizeof(state.scan_length));
  bool can_launch_scan = !state.scan_async_pending;
  ImGui::BeginDisabled(!can_launch_scan);
  if (ui::primary_button((std::string(icons::kSearch) + "  Scan Range").c_str(), ui::full_button(40))) scan_range(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::InputText("End filter", state.scan_end, sizeof(state.scan_end));
  ImGui::Checkbox("Readable maps only", &state.scan_readable_only);
  ImGui::BeginDisabled(!can_launch_scan);
  if (ui::soft_button((std::string(icons::kTarget) + "  Scan Process").c_str(), ui::full_button(40))) scan_process(state);
  ImGui::EndDisabled();

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  ImGui::TextColored(ui::colors().warning, "Unknown Initial Value");
  ImGui::TextWrapped("Saves every aligned value in process memory as a baseline. Refine with Changed/Unchanged afterwards.");
  ImGui::BeginDisabled(!can_launch_scan);
  if (ui::primary_button((std::string(icons::kSearch) + "  Unknown Value Scan").c_str(), ui::full_button(40))) scan_unknown_process(state);
  ImGui::EndDisabled();

  /* Progress bar for async scans */
  if (state.scan_async_pending)
    ui::draw_scan_progress(state.scan_async_label, icons::kSearch,
                           ImGui::GetTime() - state.scan_async_start_time,
                           ImGui::GetContentRegionAvail().x);

  ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
  const char *session_label = state.scan_is_unknown_session ? "Unknown Scan Session" : "Next Scan";
  ImGui::TextColored(state.scan_is_unknown_session ? ui::colors().warning : ui::colors().muted, "%s", session_label);
  ImGui::TextWrapped("%s", state.scan_session_status);
  if (state.scan_is_unknown_session && !state.scan_snapshot.empty())
    ImGui::TextColored(ui::colors().dim, "Tracking %zu addresses (%u bytes each)",
                       state.scan_snapshot.size(), state.scan_snapshot_value_len);
  ImGui::Spacing();

  bool can_refine = state.client.connected() && state.selected_pid > 0 && !state.scan_snapshot.empty() && !state.scan_async_pending;
  const float half_w = (ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f;
  ImGui::BeginDisabled(!can_refine);
  if (ui::soft_button("Changed", ImVec2(half_w, 38))) refine_scan(state, RefineMode::Changed);
  ImGui::SameLine();
  if (ui::soft_button("Unchanged", ImVec2(0, 38))) refine_scan(state, RefineMode::Unchanged);
  if (ui::soft_button("Increased", ImVec2(half_w, 38))) refine_scan(state, RefineMode::Increased);
  ImGui::SameLine();
  if (ui::soft_button("Decreased", ImVec2(0, 38))) refine_scan(state, RefineMode::Decreased);
  ImGui::EndDisabled();
  bool can_refresh = state.client.connected() && !state.scan_snapshot.empty() && !state.scan_async_pending;
  ImGui::BeginDisabled(!can_refresh);
  std::string next_label = std::string(icons::kRefresh) +
      (state.scan_is_unknown_session ? "  Next Scan (Refresh All)" : "  Refresh Baseline");
  if (ui::soft_button(next_label.c_str(), ui::full_button(38))) {
    capture_scan_snapshot(state);
    set_status(state, state.scan_session_status);
  }
  ImGui::EndDisabled();
  ui::end_panel();

  ImGui::SameLine(0, gap);
  ui::begin_panel("ScannerResults", "Results", ImVec2(0, avail.y));
  ImGui::Text("Results: %u%s  Type: %s", state.scan_result.count,
              state.scan_result.truncated ? " (truncated)" : "", value_type_name(state.scan_type));
  ImGui::Text("Scanned: %.2f MiB", static_cast<double>(state.scan_result.bytes_scanned)/(1024.0*1024.0));
  ImGui::Text("Speed: %s", bytes_per_second(state.scan_result.bytes_scanned, state.scan_result.elapsed_ns).c_str());
  ImGui::Text("Reads: %u  Regions: %u  Errors: %u",
              state.scan_result.read_calls, state.scan_result.regions_scanned, state.scan_result.read_errors);
  ImGui::Text("Session: %zu captured values", state.scan_snapshot.size());
  /* BATCH_READ status badge */
  if (!state.scan_snapshot.empty()) {
    ImGui::SameLine();
    if (has_batch_read(state)) {
      ImGui::TextColored(ui::colors().success, "  %s", icons::kGauge);
      if (ImGui::IsItemHovered()) ImGui::SetTooltip("BATCH_READ active \xe2\x80\x94 fast multi-address reads");
    } else {
      ImGui::TextColored(ui::colors().warning, "  %s", icons::kWarning);
      if (ImGui::IsItemHovered()) ImGui::SetTooltip("BATCH_READ unavailable \xe2\x80\x94 using individual reads (slower)");
    }
  }
  ImGui::Spacing();

  if (ImGui::BeginTable("ScanResultsTable", 2,
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Borders|ImGuiTableFlags_ScrollY, ImVec2(0,0))) {
    ImGui::TableSetupColumn("Address");
    ImGui::TableSetupColumn("Current Value");
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
        ImGui::TextColored(ui::colors().dim, "n/a");
      }
    }
    ImGui::EndTable();
  }
  ui::end_panel();
}

} // namespace memdbg::frontend

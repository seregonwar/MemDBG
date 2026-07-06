/*
 * MemDBG - Scan session: snapshot capture and refine operations.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scanner_internal.hpp"

#include <chrono>

namespace memdbg::frontend {

void capture_scan_snapshot(AppState &state) {
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

void refine_scan(AppState &state, RefineMode mode) {
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

} // namespace memdbg::frontend

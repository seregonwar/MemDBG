/*
 * MemDBG - Scan session: snapshot capture and refine operations.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scanner_internal.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <unordered_map>

namespace memdbg::frontend {

namespace {

void start_snapshot_worker(AppState &state, bool refine, RefineMode mode,
                           std::vector<uint8_t> target_bytes) {
  const int32_t pid = state.selected_pid;
  const uint32_t value_len = state.scan_snapshot_value_len != 0U
      ? state.scan_snapshot_value_len
      : current_scan_value_len(state);
  const int value_type = state.scan_snapshot_value_len != 0U
      ? state.scan_snapshot_type
      : state.scan_type;
  const bool has_batch = has_batch_read(state);
  const bool is_unknown = state.scan_is_unknown_session;
  const ScanResult original_result = state.scan_result;
  const std::vector<ScanSnapshotEntry> old_snapshot = state.scan_snapshot;
  std::vector<uint64_t> addresses;
  addresses.reserve(old_snapshot.empty() ? original_result.addresses.size()
                                         : old_snapshot.size());
  if (old_snapshot.empty()) {
    addresses = original_result.addresses;
  } else {
    for (const auto &entry : old_snapshot) addresses.push_back(entry.address);
  }

  state.scan_async_label = refine
      ? std::string(refine_mode_name(mode)) + " refinement"
      : "Refresh scan baseline";
  state.scan_async_start_time = ImGui::GetTime();
  state.scan_async_pending = true;
  state.scan_async_cancellable = true;
  state.scan_async_cancel_requested.store(false);
  state.scan_async_units_done.store(0U);
  const uint64_t unit_count = has_batch
      ? (addresses.size() + MEMDBG_BATCH_READ_MAX_ITEMS - 1U) /
            MEMDBG_BATCH_READ_MAX_ITEMS
      : addresses.size();
  state.scan_async_units_total.store(unit_count);
  state.scan_async_owner = Screen::Scanner;
  state.scan_async_error.clear();

  auto client = state.pool.scan_lease();
  ScanResult &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_value_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_type = state.scan_async_temp_snapshot_type;
  auto &temp_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  std::string &error_out = state.scan_async_error;

  state.scan_async_future = std::async(
      std::launch::async,
      [client, pid, value_len, value_type, has_batch, is_unknown, refine,
       mode, target_bytes = std::move(target_bytes),
       addresses = std::move(addresses), old_snapshot, original_result,
       &temp_result, &temp_snapshot, &temp_value_len, &temp_type,
       &temp_unknown, &temp_status, &error_out,
       &cancel_requested = state.scan_async_cancel_requested,
       &units_done = state.scan_async_units_done,
       &mtx = state.scan_async_mtx]() mutable -> bool {
        const auto start = std::chrono::steady_clock::now();
        std::unordered_map<uint64_t, const ScanSnapshotEntry *> old_by_address;
        old_by_address.reserve(old_snapshot.size());
        for (const auto &entry : old_snapshot)
          old_by_address.emplace(entry.address, &entry);

        std::vector<ScanSnapshotEntry> next_snapshot;
        std::vector<uint64_t> next_addresses;
        next_snapshot.reserve(addresses.size());
        next_addresses.reserve(addresses.size());
        uint64_t bytes_read = 0U;
        uint64_t attempted_reads = 0U;
        uint32_t read_errors = 0U;

        auto accept_value = [&](uint64_t address,
                                std::vector<uint8_t> current) {
          if (refine) {
            auto old_it = old_by_address.find(address);
            if (old_it == old_by_address.end() ||
                !scan_refine_match(value_type, mode, old_it->second->bytes,
                                   current, target_bytes))
              return;
          }
          next_addresses.push_back(address);
          next_snapshot.push_back({address, std::move(current)});
        };

        if (has_batch) {
          std::vector<memdbg_batch_read_item_t> items;
          items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
          for (size_t base = 0U; base < addresses.size();
               base += MEMDBG_BATCH_READ_MAX_ITEMS) {
            if (cancel_requested.load()) break;
            const size_t end = std::min(
                base + MEMDBG_BATCH_READ_MAX_ITEMS, addresses.size());
            items.clear();
            for (size_t i = base; i < end; ++i) {
              memdbg_batch_read_item_t item{};
              item.address = addresses[i];
              item.length = value_len;
              items.push_back(item);
            }
            attempted_reads += items.size();
            Client::BatchReadResult batch;
            if (!client->batch_read(pid, items, batch)) {
              if (cancel_requested.load()) break;
              read_errors += static_cast<uint32_t>(items.size());
              units_done.fetch_add(1U);
              continue;
            }
            size_t data_offset = 0U;
            for (const auto &entry : batch.entries) {
              if (entry.status != 0U || entry.length != value_len ||
                  data_offset > batch.data.size() ||
                  entry.length > batch.data.size() - data_offset) {
                read_errors++;
                if (data_offset <= batch.data.size() &&
                    entry.length <= batch.data.size() - data_offset)
                  data_offset += entry.length;
                continue;
              }
              std::vector<uint8_t> current(
                  batch.data.begin() + static_cast<ptrdiff_t>(data_offset),
                  batch.data.begin() + static_cast<ptrdiff_t>(
                      data_offset + entry.length));
              data_offset += entry.length;
              bytes_read += entry.length;
              accept_value(entry.address, std::move(current));
            }
            units_done.fetch_add(1U);
          }
        } else {
          for (uint64_t address : addresses) {
            if (cancel_requested.load()) break;
            attempted_reads++;
            std::vector<uint8_t> current;
            if (!client->memory_read(pid, address, value_len, current) ||
                current.size() != value_len) {
              if (cancel_requested.load()) break;
              read_errors++;
            } else {
              bytes_read += current.size();
              accept_value(address, std::move(current));
            }
            units_done.fetch_add(1U);
          }
        }

        const bool cancelled = cancel_requested.load();
        const auto end = std::chrono::steady_clock::now();
        const uint64_t elapsed_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                end - start).count());

        std::lock_guard<std::mutex> lock(mtx);
        if (cancelled) {
          temp_result = original_result;
          temp_snapshot = old_snapshot;
          temp_value_len = value_len;
          temp_type = value_type;
          temp_unknown = is_unknown;
          std::snprintf(temp_status, sizeof(temp_status),
                        "Stopped: previous %zu candidates preserved",
                        old_snapshot.size());
          error_out.clear();
          return true;
        }
        if (!addresses.empty() && bytes_read == 0U) {
          error_out = "Refinement failed: no candidate values could be read";
          return false;
        }

        ScanResult result;
        result.addresses = std::move(next_addresses);
        result.count = static_cast<uint32_t>(result.addresses.size());
        result.bytes_scanned = bytes_read;
        result.elapsed_ns = elapsed_ns;
        result.read_calls = attempted_reads > UINT32_MAX
            ? UINT32_MAX
            : static_cast<uint32_t>(attempted_reads);
        result.read_errors = read_errors;
        temp_result = std::move(result);
        temp_snapshot = std::move(next_snapshot);
        temp_value_len = value_len;
        temp_type = value_type;
        temp_unknown = is_unknown;
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s kept %zu values (%u read errors, %s)",
                      refine ? refine_mode_name(mode) : "Baseline refresh",
                      temp_snapshot.size(), read_errors,
                      bytes_per_second(bytes_read, elapsed_ns).c_str());
        error_out.clear();
        return true;
      });
}

} // namespace

void capture_scan_snapshot(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) {
    set_status(state, locale::tr("scanner.connect_first"));
    return;
  }
  if (state.selected_pid <= 0 || state.scan_result.addresses.empty()) {
    set_status(state, locale::tr("scanner.no_scan_values"));
    return;
  }
  start_snapshot_worker(state, false, RefineMode::Unchanged, {});
}

void refine_scan(AppState &state, RefineMode mode) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) {
    set_status(state, locale::tr("scanner.connect_first"));
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, locale::tr("scanner.select_process_first"));
    return;
  }
  if (state.scan_snapshot.empty() || state.scan_snapshot_value_len == 0U) {
    set_status(state, locale::tr("scanner.run_scan_before_refine"));
    return;
  }

  std::vector<uint8_t> target_bytes;
  if (mode == RefineMode::ExactValue) {
    std::array<uint8_t, 16> target{};
    uint32_t target_len = 0U;
    if (!build_scan_value(state.scan_snapshot_type, state.scan_value,
                          target, target_len) ||
        target_len != state.scan_snapshot_value_len) {
      set_status(state, locale::tr("scanner.invalid_value"));
      return;
    }
    target_bytes.assign(target.begin(), target.begin() + target_len);
  }
  start_snapshot_worker(state, true, mode, std::move(target_bytes));
}

} // namespace memdbg::frontend

/*
 * MemDBG - Async scan launchers: range, process, unknown, and poll.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scanner_internal.hpp"
#include "unknown_scan_plan.hpp"
#include "screens/processes/map_selection.hpp"

#include <chrono>
#include <exception>
#include <future>
#include <mutex>
#include <unordered_set>

namespace memdbg::frontend {

void poll_scanner_async(AppState &state) {
  if (!state.scan_async_pending) return;
  if (!state.scan_async_future.valid()) return;

  auto status = state.scan_async_future.wait_for(std::chrono::milliseconds(0));
  if (status != std::future_status::ready) return;

  state.scan_async_pending = false;
  state.scan_async_cancellable = false;
  const bool was_cancelled = state.scan_async_cancel_requested.exchange(false);
  state.scan_async_units_done.store(0U);
  state.scan_async_units_total.store(0U);
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
  push_notification(state, was_cancelled
      ? std::string(locale::tr("scanner.scan_stopped"))
      : std::string(state.scan_async_label) + " complete: " +
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
  auto client = state.pool.scan_lease();
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_snap_type = state.scan_async_temp_snapshot_type;
  auto &temp_is_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;

  state.scan_async_future = std::async(std::launch::async,
    [client, request, pid, scan_type_snap, snapshot_val_len,
     has_batch, &temp_result, &temp_snapshot, &temp_snap_val_len,
     &temp_snap_type, &temp_is_unknown, &temp_status, &error_out,
     &mtx = state.scan_async_mtx]() -> bool {
      std::lock_guard<std::mutex> lock(mtx);
      ScanResult scan_res;
      if (!client->scan_exact(request, scan_res)) {
        error_out = client->last_error();
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
            if (!client->batch_read(pid, batch_items, batch)) {
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
            if (!client->memory_read(pid, addrs[i], snapshot_val_len, data) ||
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

void scan_selected_maps(AppState &state) {
  if (state.scan_async_pending) return;
  if (!state.client.connected()) {
    set_status(state, locale::tr("scanner.connect_first"));
    push_notification(state, locale::tr("scanner.connect_first"), 4.0);
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, locale::tr("scanner.select_process_first"));
    push_notification(state, locale::tr("scanner.select_process_first"), 4.0);
    return;
  }

  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!build_scan_value(state.scan_type, state.scan_value, value, value_len)) {
    set_status(state, locale::tr("scanner.invalid_value"));
    return;
  }

  std::vector<MapEntry> selected_maps;
  selected_maps.reserve(state.selected_map_starts.size());
  for (const MapEntry &map : state.maps) {
    if (map.end <= map.start ||
        state.selected_map_starts.count(map.start) == 0U)
      continue;
    if (state.scan_readable_only && (map.protection & MEMDBG_MAP_PROT_READ) == 0U)
      continue;
    selected_maps.push_back(map);
  }
  if (selected_maps.empty()) {
    set_status(state, locale::tr("scanner.no_selected_maps"));
    push_notification(state, locale::tr("scanner.no_selected_maps"), 4.0);
    return;
  }
  std::sort(selected_maps.begin(), selected_maps.end(),
            [](const MapEntry &a, const MapEntry &b) {
              return a.start < b.start;
            });

  state.scan_alignment = std::max(state.scan_alignment, 1);
  state.scan_max_results = std::max(state.scan_max_results, 1);
  const int32_t pid = state.selected_pid;
  const uint32_t alignment = static_cast<uint32_t>(state.scan_alignment);
  const uint32_t max_results = static_cast<uint32_t>(state.scan_max_results);
  const int scan_type_snap = state.scan_type;
  const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;
  std::unordered_set<uint64_t> effective_selection;
  effective_selection.reserve(selected_maps.size());
  for (const MapEntry &map : selected_maps)
    effective_selection.insert(map.start);
  const uint32_t parallel_protection_mask =
      detail::complete_protection_mask(state.maps, effective_selection);

  state.scan_async_label = locale::tr("scanner.selected_maps_scan");
  state.scan_async_start_time = ImGui::GetTime();
  state.scan_async_pending = true;
  state.scan_async_cancellable = true;
  state.scan_async_cancel_requested.store(false);
  state.scan_async_owner = Screen::Scanner;

  auto client = state.pool.scan_lease();
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_snap_type = state.scan_async_temp_snapshot_type;
  auto &temp_is_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;

  state.scan_async_future = std::async(std::launch::async,
      [client, selected_maps = std::move(selected_maps), pid, value,
       value_len, alignment, max_results, scan_type_snap, has_batch,
       parallel_protection_mask,
       &temp_result, &temp_snapshot, &temp_snap_val_len, &temp_snap_type,
       &temp_is_unknown, &temp_status, &error_out,
       &mtx = state.scan_async_mtx,
       &cancel_requested = state.scan_async_cancel_requested]() -> bool {
        std::lock_guard<std::mutex> lock(mtx);
        ScanResult aggregate;
        aggregate.addresses.reserve(max_results);

        auto add_u32 = [](uint32_t &dst, uint32_t value_to_add) {
          const uint64_t sum = static_cast<uint64_t>(dst) + value_to_add;
          dst = sum > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(sum);
        };
        auto add_u64 = [](uint64_t &dst, uint64_t value_to_add) {
          dst = value_to_add > UINT64_MAX - dst ? UINT64_MAX
                                                : dst + value_to_add;
        };

        size_t scanned_maps = 0U;
        auto merge_part = [&](ScanResult &part, size_t maps_in_part) {
          const size_t remaining_results =
              aggregate.addresses.size() < max_results
                  ? max_results - aggregate.addresses.size()
                  : 0U;
          const size_t retained = std::min(remaining_results,
                                           part.addresses.size());
          aggregate.addresses.insert(aggregate.addresses.end(),
                                     part.addresses.begin(),
                                     part.addresses.begin() + retained);
          aggregate.truncated = aggregate.truncated || part.truncated ||
                                part.addresses.size() > retained;
          add_u64(aggregate.bytes_scanned, part.bytes_scanned);
          add_u64(aggregate.elapsed_ns, part.elapsed_ns);
          add_u32(aggregate.read_calls, part.read_calls);
          add_u32(aggregate.regions_scanned, part.regions_scanned);
          add_u32(aggregate.read_errors, part.read_errors);
          scanned_maps += maps_in_part;
        };

        if (parallel_protection_mask != 0U) {
          constexpr size_t kMapsPerParallelBatch = 1024U;
          for (size_t base = 0U; base < selected_maps.size();
               base += kMapsPerParallelBatch) {
            if (cancel_requested.load()) break;
            const size_t end = std::min(base + kMapsPerParallelBatch,
                                        selected_maps.size());
            const size_t remaining_results =
                aggregate.addresses.size() < max_results
                    ? max_results - aggregate.addresses.size()
                    : 0U;
            memdbg_scan_process_exact_request_t request{};
            request.pid = pid;
            request.value_type = static_cast<uint32_t>(scan_type_snap);
            request.value_length = value_len;
            request.alignment = alignment;
            request.max_results = static_cast<uint32_t>(
                remaining_results == 0U ? 1U : remaining_results);
            request.protection_mask = parallel_protection_mask;
            request.start = selected_maps[base].start;
            request.end = end < selected_maps.size()
                ? selected_maps[end].start
                : selected_maps.back().end;
            std::copy(value.begin(), value.end(), request.value);

            ScanResult part;
            if (!client->scan_process_exact(request, part)) {
              error_out = "Selected map batch " + hex_u64(request.start) +
                          ": " + client->last_error();
              return false;
            }
            merge_part(part, end - base);
          }
        } else {
          for (const MapEntry &map : selected_maps) {
            if (cancel_requested.load()) break;
            const size_t remaining_results =
                aggregate.addresses.size() < max_results
                    ? max_results - aggregate.addresses.size()
                    : 0U;
            memdbg_scan_exact_request_t request{};
            request.pid = pid;
            request.start = map.start;
            request.length = map.end - map.start;
            request.value_type = static_cast<uint32_t>(scan_type_snap);
            request.value_length = value_len;
            request.alignment = alignment;
            request.max_results = static_cast<uint32_t>(
                remaining_results == 0U ? 1U : remaining_results);
            std::copy(value.begin(), value.end(), request.value);

            ScanResult part;
            if (!client->scan_exact(request, part)) {
              error_out = "Selected map " + hex_u64(map.start) + ": " +
                          client->last_error();
              return false;
            }
            merge_part(part, 1U);
          }
        }
        aggregate.count = static_cast<uint32_t>(aggregate.addresses.size());
        temp_result = std::move(aggregate);
        temp_snapshot.clear();
        temp_snap_val_len = value_len;
        temp_snap_type = scan_type_snap;
        temp_is_unknown = false;

        const auto snapshot_start = std::chrono::steady_clock::now();
        uint32_t snapshot_errors = 0U;
        if (!temp_result.addresses.empty() && value_len > 0U) {
          temp_snapshot.reserve(temp_result.addresses.size());
          if (has_batch) {
            std::vector<memdbg_batch_read_item_t> items;
            items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
            for (size_t base = 0U; base < temp_result.addresses.size();
                 base += MEMDBG_BATCH_READ_MAX_ITEMS) {
              items.clear();
              const size_t end = std::min(
                  base + MEMDBG_BATCH_READ_MAX_ITEMS,
                  temp_result.addresses.size());
              for (size_t i = base; i < end; ++i) {
                memdbg_batch_read_item_t item{};
                item.address = temp_result.addresses[i];
                item.length = value_len;
                items.push_back(item);
              }
              Client::BatchReadResult batch;
              if (!client->batch_read(pid, items, batch)) {
                snapshot_errors += static_cast<uint32_t>(end - base);
                continue;
              }
              uint32_t data_offset = 0U;
              for (const auto &entry : batch.entries) {
                if (entry.status != 0U || entry.length != value_len ||
                    data_offset > batch.data.size() ||
                    entry.length > batch.data.size() - data_offset) {
                  snapshot_errors++;
                  if (entry.length <= batch.data.size() -
                                          std::min<size_t>(data_offset,
                                                           batch.data.size()))
                    data_offset += entry.length;
                  continue;
                }
                ScanSnapshotEntry snapshot;
                snapshot.address = entry.address;
                snapshot.bytes.assign(batch.data.begin() + data_offset,
                                      batch.data.begin() + data_offset +
                                          entry.length);
                temp_snapshot.push_back(std::move(snapshot));
                data_offset += entry.length;
              }
            }
          } else {
            for (uint64_t address : temp_result.addresses) {
              std::vector<uint8_t> data;
              if (!client->memory_read(pid, address, value_len, data) ||
                  data.size() != value_len) {
                snapshot_errors++;
                continue;
              }
              ScanSnapshotEntry snapshot;
              snapshot.address = address;
              snapshot.bytes = std::move(data);
              temp_snapshot.push_back(std::move(snapshot));
            }
          }
        }
        const auto snapshot_end = std::chrono::steady_clock::now();
        add_u32(temp_result.read_errors, snapshot_errors);
        add_u64(temp_result.elapsed_ns, static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                snapshot_end - snapshot_start).count()));
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu/%zu maps scanned, %u hits, %u snapshot errors",
                      cancel_requested.load() ? "Stopped" : "Complete",
                      scanned_maps, selected_maps.size(), temp_result.count,
                      snapshot_errors);
        error_out.clear();
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
  auto client = state.pool.scan_lease();
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_snap_type = state.scan_async_temp_snapshot_type;
  auto &temp_is_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;

  state.scan_async_future = std::async(std::launch::async,
    [client, request, pid, scan_type_snap, snapshot_val_len,
     has_batch, &temp_result, &temp_snapshot, &temp_snap_val_len,
     &temp_snap_type, &temp_is_unknown, &temp_status, &error_out,
     &mtx = state.scan_async_mtx]() -> bool {
      std::lock_guard<std::mutex> lock(mtx);
      ScanResult scan_res;
      if (!client->scan_process_exact(request, scan_res)) {
        error_out = client->last_error();
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
            if (!client->batch_read(pid, batch_items, batch)) {
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
            if (!client->memory_read(pid, addrs[i], snapshot_val_len, data) ||
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
  const uint32_t max_results = static_cast<uint32_t>(
      std::min<int>(state.scan_max_results,
                    static_cast<int>(
                        MEMDBG_SCAN_UNKNOWN_RESULT_BUDGET /
                        sizeof(memdbg_scan_result_entry_t))));
  memdbg_scan_unknown_request_t request{};
  request.abi_magic = MEMDBG_SCAN_UNKNOWN_ABI_MAGIC;
  request.abi_version = MEMDBG_SCAN_UNKNOWN_ABI_VERSION;
  request.struct_size = static_cast<uint16_t>(sizeof(request));
  request.flags = state.scan_unknown_nonzero_prefilter
      ? MEMDBG_SCAN_UNKNOWN_FLAG_NONZERO
      : 0U;
  request.pid=state.selected_pid;
  request.value_type=static_cast<uint32_t>(state.scan_type);
  request.value_length=current_scan_value_len(state);
  request.alignment=static_cast<uint32_t>(state.scan_alignment);
  request.max_results=max_results;
  request.protection_mask=MEMDBG_MAP_PROT_READ;
  request.start=start;
  request.end=end;
  request.max_bytes=MEMDBG_SCAN_UNKNOWN_MAX_UNIT_BYTES;

  state.scan_async_label = "Unknown value scan";
  state.scan_async_start_time = ImGui::GetTime();
  state.scan_async_pending = true;
  state.scan_async_cancellable = true;
  state.scan_async_cancel_requested.store(false);
  state.scan_async_units_done.store(0U);
  state.scan_async_units_total.store(0U);
  state.scan_async_owner = Screen::Scanner;

  const int32_t pid = state.selected_pid;
  const int scan_type_snap = state.scan_type;
  const auto snapshot_val_len = current_scan_value_len(state);
  const ScanResult original_result = state.scan_result;
  const auto original_snapshot = state.scan_snapshot;
  const uint32_t original_value_len = state.scan_snapshot_value_len;
  const int original_type = state.scan_snapshot_type;
  const bool original_unknown = state.scan_is_unknown_session;
  auto client = state.pool.scan_lease();
  auto &temp_result = state.scan_async_temp_result;
  auto &temp_snapshot = state.scan_async_temp_snapshot;
  auto &temp_snap_val_len = state.scan_async_temp_snapshot_value_len;
  auto &temp_snap_type = state.scan_async_temp_snapshot_type;
  auto &temp_is_unknown = state.scan_async_temp_is_unknown;
  auto &temp_status = state.scan_async_temp_session_status;
  auto &error_out = state.scan_async_error;
  const bool has_batch = (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;

  state.scan_async_future = std::async(std::launch::async,
    [client, request, pid, scan_type_snap, snapshot_val_len, max_results,
     has_batch, &temp_result, &temp_snapshot, &temp_snap_val_len,
     &temp_snap_type, &temp_is_unknown, &temp_status, &error_out,
     original_result, original_snapshot, original_value_len, original_type,
     original_unknown, &cancel_requested = state.scan_async_cancel_requested,
     &units_done = state.scan_async_units_done,
     &units_total = state.scan_async_units_total,
     &mtx = state.scan_async_mtx]() mutable -> bool {
     auto preserve_cancelled = [&]() {
       std::lock_guard<std::mutex> lock(mtx);
       temp_result = original_result;
       temp_snapshot = original_snapshot;
       temp_snap_val_len = original_value_len;
       temp_snap_type = original_type;
       temp_is_unknown = original_unknown;
       std::snprintf(temp_status, sizeof(temp_status),
                     "Stopped: previous scan session preserved");
       error_out.clear();
     };
     auto fail = [&](const std::string &message) {
       std::lock_guard<std::mutex> lock(mtx);
       error_out = message;
       return false;
     };
     auto add_u32 = [](uint32_t &dst, uint32_t value) {
       const uint64_t sum = static_cast<uint64_t>(dst) + value;
       dst = sum > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(sum);
     };
     auto add_u64 = [](uint64_t &dst, uint64_t value) {
       dst = value > UINT64_MAX - dst ? UINT64_MAX : dst + value;
     };

     std::vector<MapEntry> maps;
     if (!client->process_maps(pid, maps)) {
       if (cancel_requested.load()) {
         preserve_cancelled();
         return true;
       }
       return fail("Unknown scan map refresh failed: " + client->last_error());
     }

     std::vector<UnknownScanUnit> units;
     std::string plan_error;
     if (!build_unknown_scan_units(
             std::move(maps), request.start, request.end,
             snapshot_val_len, MEMDBG_SCAN_UNKNOWN_MAX_UNIT_BYTES,
             units, plan_error))
       return fail(plan_error);
     units_total.store(units.size());

     ScanResult aggregate;
     aggregate.addresses.reserve(max_results);
     std::unordered_set<uint64_t> seen;
     seen.reserve(max_results);
     for (const UnknownScanUnit &unit : units) {
       if (cancel_requested.load()) {
         preserve_cancelled();
         return true;
       }
       const size_t remaining = aggregate.addresses.size() < max_results
           ? max_results - aggregate.addresses.size()
           : 0U;
       if (remaining == 0U) {
         aggregate.truncated = true;
         break;
       }

       memdbg_scan_unknown_request_t unit_request = request;
       unit_request.start = unit.start;
       unit_request.end = unit.end;
       unit_request.max_bytes = unit.end - unit.start;
       unit_request.max_results = static_cast<uint32_t>(remaining);
       ScanResult part;
       if (!client->scan_unknown(unit_request, part)) {
         if (cancel_requested.load()) {
           preserve_cancelled();
           return true;
         }
         return fail("Unknown scan unit " + hex_u64(unit.start) + ": " +
                     client->last_error());
       }
       add_u64(aggregate.bytes_scanned, part.bytes_scanned);
       add_u64(aggregate.elapsed_ns, part.elapsed_ns);
       add_u32(aggregate.read_calls, part.read_calls);
       add_u32(aggregate.regions_scanned, part.regions_scanned);
       add_u32(aggregate.read_errors, part.read_errors);
       for (uint64_t address : part.addresses) {
         if (seen.insert(address).second)
           aggregate.addresses.push_back(address);
       }
       if (aggregate.addresses.size() >= max_results) {
         aggregate.truncated = true;
         break;
       }
       units_done.fetch_add(1U);
     }

     std::sort(aggregate.addresses.begin(), aggregate.addresses.end());
     aggregate.addresses.erase(
         std::unique(aggregate.addresses.begin(), aggregate.addresses.end()),
         aggregate.addresses.end());
     aggregate.count = static_cast<uint32_t>(aggregate.addresses.size());

     const uint64_t snapshot_units = has_batch
         ? (aggregate.addresses.size() + MEMDBG_BATCH_READ_MAX_ITEMS - 1U) /
               MEMDBG_BATCH_READ_MAX_ITEMS
         : aggregate.addresses.size();
     units_total.fetch_add(snapshot_units);
     std::vector<ScanSnapshotEntry> snapshot;
     snapshot.reserve(aggregate.addresses.size());
     uint32_t snapshot_errors = 0U;
     uint64_t snapshot_reads = 0U;
     const auto snapshot_start = std::chrono::steady_clock::now();

     if (has_batch) {
       std::vector<memdbg_batch_read_item_t> items;
       items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
       for (size_t base = 0U; base < aggregate.addresses.size();
            base += MEMDBG_BATCH_READ_MAX_ITEMS) {
         if (cancel_requested.load()) {
           preserve_cancelled();
           return true;
         }
         const size_t end_index = std::min(
             base + MEMDBG_BATCH_READ_MAX_ITEMS, aggregate.addresses.size());
         items.clear();
         for (size_t i = base; i < end_index; ++i)
           items.push_back({aggregate.addresses[i], snapshot_val_len, 0U});
         snapshot_reads += items.size();
         Client::BatchReadResult batch;
         if (!client->batch_read(pid, items, batch)) {
           if (cancel_requested.load()) {
             preserve_cancelled();
             return true;
           }
           snapshot_errors += static_cast<uint32_t>(items.size());
           units_done.fetch_add(1U);
           continue;
         }
         size_t offset = 0U;
         for (const auto &entry : batch.entries) {
           if (entry.status != 0U || entry.length != snapshot_val_len ||
               offset > batch.data.size() ||
               entry.length > batch.data.size() - offset) {
             snapshot_errors++;
             if (offset <= batch.data.size() &&
                 entry.length <= batch.data.size() - offset)
               offset += entry.length;
             continue;
           }
           ScanSnapshotEntry value;
           value.address = entry.address;
           value.bytes.assign(
               batch.data.begin() + static_cast<ptrdiff_t>(offset),
               batch.data.begin() + static_cast<ptrdiff_t>(
                   offset + entry.length));
           snapshot.push_back(std::move(value));
           offset += entry.length;
         }
         units_done.fetch_add(1U);
       }
     } else {
       for (uint64_t address : aggregate.addresses) {
         if (cancel_requested.load()) {
           preserve_cancelled();
           return true;
         }
         snapshot_reads++;
         std::vector<uint8_t> data;
         if (!client->memory_read(pid, address, snapshot_val_len, data) ||
             data.size() != snapshot_val_len) {
           if (cancel_requested.load()) {
             preserve_cancelled();
             return true;
           }
           snapshot_errors++;
         } else {
           snapshot.push_back({address, std::move(data)});
         }
         units_done.fetch_add(1U);
       }
     }

     if (!aggregate.addresses.empty() && snapshot.empty())
       return fail("Unknown scan failed: candidate snapshots were unreadable");
     const auto snapshot_end = std::chrono::steady_clock::now();
     const uint64_t snapshot_ns = static_cast<uint64_t>(
         std::chrono::duration_cast<std::chrono::nanoseconds>(
             snapshot_end - snapshot_start).count());
     add_u64(aggregate.elapsed_ns, snapshot_ns);
     add_u32(aggregate.read_calls, snapshot_reads > UINT32_MAX
         ? UINT32_MAX
         : static_cast<uint32_t>(snapshot_reads));
     add_u32(aggregate.read_errors, snapshot_errors);
     aggregate.addresses.clear();
     aggregate.addresses.reserve(snapshot.size());
     for (const auto &entry : snapshot)
       aggregate.addresses.push_back(entry.address);
     aggregate.count = static_cast<uint32_t>(aggregate.addresses.size());

     std::lock_guard<std::mutex> lock(mtx);
     temp_result = std::move(aggregate);
     temp_snapshot = std::move(snapshot);
     temp_snap_val_len = snapshot_val_len;
     temp_snap_type = scan_type_snap;
     temp_is_unknown = true;
     std::snprintf(temp_status, sizeof(temp_status),
                   "Unknown scan: %u candidates, %u read errors%s",
                   temp_result.count, temp_result.read_errors,
                   temp_result.truncated ? " (capped)" : "");
     error_out.clear();
     return true;
    });
}

} // namespace memdbg::frontend

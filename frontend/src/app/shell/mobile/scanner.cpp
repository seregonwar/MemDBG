/*
 * MemDBG - Mobile scanner UI and async logic.
 */
#include "../internal.hpp"
#include "trainer/trainer_format.hpp"
#include "trainer/batchcode_parser.hpp"
#include "file_picker.hpp"

namespace memdbg::frontend {

uint32_t mobile_scan_value_len(const AppState &state) {
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (build_scan_value(state.scan.type, state.scan.value, value, value_len))
    return value_len;

  switch (state.scan.type) {
  case MEMDBG_VALUE_U8: return 1U;
  case MEMDBG_VALUE_U16: return 2U;
  case MEMDBG_VALUE_U32:
  case MEMDBG_VALUE_F32: return 4U;
  case MEMDBG_VALUE_U64:
  case MEMDBG_VALUE_F64:
  case MEMDBG_VALUE_POINTER: return 8U;
  default: return 1U;
  }
}

bool mobile_has_batch_read(const AppState &state) {
  return (state.hello.capabilities & MEMDBG_CAP_BATCH_READ) != 0U;
}

bool mobile_capture_snapshot_worker(Client &client, int32_t pid,
                                           const std::vector<uint64_t> &addrs,
                                           uint32_t value_len,
                                           bool has_batch_read,
                                           std::vector<ScanSnapshotEntry> &out,
                                           uint32_t &read_errors,
                                           uint64_t &elapsed_ns) {
  out.clear();
  read_errors = 0;
  elapsed_ns = 0;
  if (pid <= 0 || addrs.empty() || value_len == 0U) return true;

  const auto start = std::chrono::steady_clock::now();
  out.reserve(addrs.size());

  if (has_batch_read) {
    std::vector<memdbg_batch_read_item_t> batch_items;
    batch_items.reserve(MEMDBG_BATCH_READ_MAX_ITEMS);
    for (size_t base = 0U; base < addrs.size();
         base += MEMDBG_BATCH_READ_MAX_ITEMS) {
      batch_items.clear();
      const size_t chunk_end =
          std::min(base + MEMDBG_BATCH_READ_MAX_ITEMS, addrs.size());
      for (size_t i = base; i < chunk_end; ++i) {
        memdbg_batch_read_item_t item{};
        item.address = addrs[i];
        item.length = value_len;
        batch_items.push_back(item);
      }

      Client::BatchReadResult batch;
      if (!client.batch_read(pid, batch_items, batch)) {
        read_errors += static_cast<uint32_t>(chunk_end - base);
        continue;
      }

      uint32_t data_offset = 0U;
      for (const auto &entry : batch.entries) {
        if (data_offset > batch.data.size() ||
            entry.length > batch.data.size() - data_offset ||
            entry.status != 0U || entry.length != value_len) {
          read_errors++;
          data_offset += std::min<uint32_t>(
              entry.length,
              data_offset <= batch.data.size()
                  ? static_cast<uint32_t>(batch.data.size() - data_offset)
                  : 0U);
          continue;
        }

        ScanSnapshotEntry snap;
        snap.address = entry.address;
        snap.bytes.assign(batch.data.begin() + data_offset,
                          batch.data.begin() + data_offset + entry.length);
        out.push_back(std::move(snap));
        data_offset += entry.length;
      }
    }
  } else {
    for (uint64_t address : addrs) {
      std::vector<uint8_t> data;
      if (!client.memory_read(pid, address, value_len, data) ||
          data.size() != value_len) {
        read_errors++;
        continue;
      }
      ScanSnapshotEntry snap;
      snap.address = address;
      snap.bytes = std::move(data);
      out.push_back(std::move(snap));
    }
  }

  const auto end = std::chrono::steady_clock::now();
  elapsed_ns = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
          .count());
  return true;
}

void mobile_prepare_scan_async(AppState &state,
                                      const std::string &label) {
  if (state.scan.async_future.valid()) state.scan.async_future.wait();
  {
    std::lock_guard<std::mutex> lock(state.scan.async_mtx);
    state.scan.async_temp_result = ScanResult{};
    state.scan.async_temp_snapshot.clear();
    state.scan.async_temp_snapshot_value_len = 0U;
    state.scan.async_temp_snapshot_type = state.scan.type;
    state.scan.async_temp_is_unknown = false;
    state.scan.async_temp_session_status[0] = '\0';
    state.scan.async_error.clear();
    state.scan.auto_search_temp_candidates.clear();
  }
  state.scan.async_label = label;
  state.scan.async_start_time = ImGui::GetTime();
  state.scan.async_pending = true;
  state.scan.async_owner = Screen::Scanner;
}

void mobile_start_range_scan(AppState &state) {
  if (state.scan.async_pending) return;
  if (!state.client.connected()) {
    set_status(state, "Connect a console before scanning");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before scanning");
    return;
  }
  if (!payload_supports(state, MEMDBG_CAP_SCAN_EXACT)) {
    set_status(state, "Payload does not support exact range scans");
    return;
  }

  uint64_t start = 0;
  uint64_t length = 0;
  std::array<uint8_t, 16> value{};
  uint32_t value_len = 0;
  if (!parse_u64(state.scan.start, start) ||
      !parse_u64(state.scan.length, length) || length == 0U) {
    set_status(state, "Enter a valid start and non-zero length");
    return;
  }
  if (!build_scan_value(state.scan.type, state.scan.value, value, value_len)) {
    set_status(state, "Invalid scan value");
    return;
  }

  state.scan.alignment = std::max(state.scan.alignment, 1);
  state.scan.max_results = std::clamp(state.scan.max_results, 1,
      static_cast<int>(MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE));

  memdbg_scan_exact_request_t request{};
  request.pid = state.selected_pid;
  request.start = start;
  request.length = length;
  request.value_type = static_cast<uint32_t>(state.scan.type);
  request.value_length = value_len;
  request.alignment = static_cast<uint32_t>(state.scan.alignment);
  request.max_results = static_cast<uint32_t>(state.scan.max_results);
  std::copy(value.begin(), value.end(), request.value);

  mobile_prepare_scan_async(state, "Range scan");
  const int32_t pid = state.selected_pid;
  const int scan_type = state.scan.type;
  Client &client = state.client;
  auto &temp_result = state.scan.async_temp_result;
  auto &temp_snapshot = state.scan.async_temp_snapshot;
  auto &temp_value_len = state.scan.async_temp_snapshot_value_len;
  auto &temp_type = state.scan.async_temp_snapshot_type;
  auto &temp_unknown = state.scan.async_temp_is_unknown;
  auto &temp_status = state.scan.async_temp_session_status;
  auto &error_out = state.scan.async_error;
  const bool has_batch = mobile_has_batch_read(state);

  state.scan.async_future = std::async(
      std::launch::async,
      [&client, request, pid, scan_type, value_len, has_batch, &temp_result,
       &temp_snapshot, &temp_value_len, &temp_type, &temp_unknown,
       &temp_status, &error_out, &mtx = state.scan.async_mtx]() -> bool {
        std::lock_guard<std::mutex> lock(mtx);
        ScanResult result;
        if (!client.scan_exact(request, result)) {
          error_out = client.last_error();
          return false;
        }

        uint32_t read_errors = 0;
        uint64_t snapshot_ns = 0;
        std::vector<ScanSnapshotEntry> snapshot;
        mobile_capture_snapshot_worker(client, pid, result.addresses,
                                       value_len, has_batch, snapshot,
                                       read_errors, snapshot_ns);

        const uint64_t capture_bytes =
            static_cast<uint64_t>(snapshot.size()) * value_len;
        result.read_calls += static_cast<uint32_t>(result.addresses.size());
        result.read_errors += read_errors;
        result.elapsed_ns += snapshot_ns;
        temp_result = std::move(result);
        temp_snapshot = std::move(snapshot);
        temp_value_len = value_len;
        temp_type = scan_type;
        temp_unknown = false;
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu values, %u read errors, %s",
                      has_batch ? "BATCH_READ" : "individual reads",
                      temp_snapshot.size(), read_errors,
                      bytes_per_second(capture_bytes, snapshot_ns).c_str());
        return true;
      });
}

void mobile_start_process_scan(AppState &state, bool unknown) {
  if (unknown) {
    scan_unknown_process(state);
    return;
  }
  if (state.scan.async_pending) return;
  if (!state.client.connected()) {
    set_status(state, "Connect a console before scanning");
    return;
  }
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before scanning");
    return;
  }
  if (!payload_supports(state, MEMDBG_CAP_SCAN_PROCESS_EXACT)) {
    set_status(state, "Payload does not support process scans");
    return;
  }

  uint64_t start = 0;
  uint64_t end = 0;
  if (!parse_u64(state.scan.start, start) ||
      !parse_u64(state.scan.end, end) || (end != 0U && end <= start)) {
    set_status(state, "Enter a valid scan window");
    return;
  }

  std::array<uint8_t, 16> value{};
  uint32_t value_len = mobile_scan_value_len(state);
  if (!build_scan_value(
          state.scan.type, state.scan.value, value, value_len)) {
    set_status(state, "Invalid scan value");
    return;
  }

  state.scan.alignment = std::max(state.scan.alignment, 1);
  state.scan.max_results = std::clamp(state.scan.max_results, 1,
      static_cast<int>(MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE));

  memdbg_scan_process_exact_request_t request{};
  request.pid = state.selected_pid;
  request.value_type = static_cast<uint32_t>(state.scan.type);
  request.value_length = value_len;
  request.alignment = static_cast<uint32_t>(state.scan.alignment);
  request.max_results = static_cast<uint32_t>(state.scan.max_results);
  request.protection_mask = state.scan.readable_only ? 1U : 0U;
  request.start = start;
  request.end = end;
  std::copy(value.begin(), value.end(), request.value);

  mobile_prepare_scan_async(state, "Process scan");
  const int32_t pid = state.selected_pid;
  const int scan_type = state.scan.type;
  Client &client = state.client;
  auto &temp_result = state.scan.async_temp_result;
  auto &temp_snapshot = state.scan.async_temp_snapshot;
  auto &temp_value_len = state.scan.async_temp_snapshot_value_len;
  auto &temp_type = state.scan.async_temp_snapshot_type;
  auto &temp_unknown = state.scan.async_temp_is_unknown;
  auto &temp_status = state.scan.async_temp_session_status;
  auto &error_out = state.scan.async_error;
  const bool has_batch = mobile_has_batch_read(state);

  state.scan.async_future = std::async(
      std::launch::async,
      [&client, request, pid, scan_type, value_len, has_batch,
       &temp_result, &temp_snapshot, &temp_value_len, &temp_type,
       &temp_unknown, &temp_status, &error_out,
       &mtx = state.scan.async_mtx]() -> bool {
        std::lock_guard<std::mutex> lock(mtx);
        ScanResult result;
        const bool ok = client.scan_process_exact(request, result);
        if (!ok) {
          error_out = client.last_error();
          return false;
        }

        uint32_t read_errors = 0;
        uint64_t snapshot_ns = 0;
        std::vector<ScanSnapshotEntry> snapshot;
        mobile_capture_snapshot_worker(client, pid, result.addresses,
                                       value_len, has_batch, snapshot,
                                       read_errors, snapshot_ns);

        const uint64_t capture_bytes =
            static_cast<uint64_t>(snapshot.size()) * value_len;
        result.read_calls += static_cast<uint32_t>(result.addresses.size());
        result.read_errors += read_errors;
        result.elapsed_ns += snapshot_ns;
        temp_result = std::move(result);
        temp_snapshot = std::move(snapshot);
        temp_value_len = value_len;
        temp_type = scan_type;
        temp_unknown = false;
        std::snprintf(temp_status, sizeof(temp_status),
                      "%s: %zu values, %u read errors, %s",
                      has_batch ? "BATCH_READ" : "individual reads",
                      temp_snapshot.size(), read_errors,
                      bytes_per_second(capture_bytes, snapshot_ns).c_str());
        return true;
      });
}

void mobile_poll_scanner_async(AppState &state) {
  if (!state.scan.async_pending || !state.scan.async_future.valid()) return;
  if (state.scan.async_future.wait_for(std::chrono::milliseconds(0)) !=
      std::future_status::ready) {
    return;
  }

  state.scan.async_pending = false;
  state.scan.async_cancellable = false;
  const bool cancelled = state.scan.async_cancel_requested.exchange(false);
  state.scan.async_units_done.store(0U);
  state.scan.async_units_total.store(0U);
  bool ok = false;
  try {
    ok = state.scan.async_future.get();
  } catch (const std::exception &ex) {
    std::lock_guard<std::mutex> lock(state.scan.async_mtx);
    state.scan.async_error = ex.what();
  } catch (...) {
    std::lock_guard<std::mutex> lock(state.scan.async_mtx);
    state.scan.async_error = "Unknown scanner error";
  }

  if (state.scan.async_owner != Screen::Scanner) return;

  if (!ok) {
    std::string error;
    {
      std::lock_guard<std::mutex> lock(state.scan.async_mtx);
      error = state.scan.async_error.empty() ? "Scanner request failed"
                                             : state.scan.async_error;
      state.scan.async_error.clear();
    }
    set_status(state, error);
    push_notification(state, error, 5.0);
    return;
  }

  ScanResult result;
  std::vector<ScanSnapshotEntry> snapshot;
  uint32_t value_len = 0U;
  int type = MEMDBG_VALUE_U32;
  bool unknown = false;
  char status[256] = {};
  {
    std::lock_guard<std::mutex> lock(state.scan.async_mtx);
    result = std::move(state.scan.async_temp_result);
    snapshot = std::move(state.scan.async_temp_snapshot);
    value_len = state.scan.async_temp_snapshot_value_len;
    type = state.scan.async_temp_snapshot_type;
    unknown = state.scan.async_temp_is_unknown;
    std::memcpy(status, state.scan.async_temp_session_status, sizeof(status));
  }

  state.scan.result = std::move(result);
  state.scan.snapshot = std::move(snapshot);
  state.scan.snapshot_value_len = value_len;
  state.scan.snapshot_type = type;
  state.scan.is_unknown_session = unknown;
  std::snprintf(state.scan.session_status, sizeof(state.scan.session_status),
                "%s", status[0] != '\0' ? status : "Scan complete");
  set_status(state, state.scan.session_status);
  push_notification(state, cancelled
      ? "Scan stopped"
      : state.scan.async_label + ": " +
            std::to_string(state.scan.result.count) + " results");
}

void mobile_refresh_scan_snapshot(AppState &state) {
  capture_scan_snapshot(state);
}

void mobile_refine_scan(AppState &state, RefineMode mode) {
  refine_scan(state, mode);
}

std::string mobile_scan_value_text(int type,
                                          const std::vector<uint8_t> &bytes) {
  char buf[96] = {};
  switch (type) {
  case MEMDBG_VALUE_U8:
    if (bytes.size() >= sizeof(uint8_t))
      std::snprintf(buf, sizeof(buf), "%u",
                    static_cast<unsigned>(read_scalar<uint8_t>(bytes)));
    break;
  case MEMDBG_VALUE_U16:
    if (bytes.size() >= sizeof(uint16_t))
      std::snprintf(buf, sizeof(buf), "%u",
                    static_cast<unsigned>(read_scalar<uint16_t>(bytes)));
    break;
  case MEMDBG_VALUE_U32:
    if (bytes.size() >= sizeof(uint32_t))
      std::snprintf(buf, sizeof(buf), "%u", read_scalar<uint32_t>(bytes));
    break;
  case MEMDBG_VALUE_U64:
    if (bytes.size() >= sizeof(uint64_t))
      std::snprintf(buf, sizeof(buf), "%llu",
                    static_cast<unsigned long long>(
                        read_scalar<uint64_t>(bytes)));
    break;
  case MEMDBG_VALUE_POINTER:
    if (bytes.size() >= sizeof(uint64_t))
      return hex_u64(read_scalar<uint64_t>(bytes));
    break;
  case MEMDBG_VALUE_F32:
    if (bytes.size() >= sizeof(float))
      std::snprintf(buf, sizeof(buf), "%.6g",
                    static_cast<double>(read_scalar<float>(bytes)));
    break;
  case MEMDBG_VALUE_F64:
    if (bytes.size() >= sizeof(double))
      std::snprintf(buf, sizeof(buf), "%.12g", read_scalar<double>(bytes));
    break;
  default:
    break;
  }
  if (buf[0] != '\0') return buf;
  return bytes_to_hex(bytes);
}

const ScanSnapshotEntry *mobile_snapshot_for(const AppState &state,
                                                    uint64_t address) {
  for (const auto &entry : state.scan.snapshot)
    if (entry.address == address) return &entry;
  return nullptr;
}

void mobile_value_type_combo(const char *label, int *value) {
  static const char *const type_names[] = {
      "Bytes", "u8", "u16", "u32", "u64", "float", "double", "pointer"};
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::Combo(label, value, type_names, IM_ARRAYSIZE(type_names));
}

void draw_mobile_scanner(AppState &state, ImVec2 size) {
  mobile_poll_scanner_async(state);
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const bool has_pid = state.selected_pid > 0;

  ImGui::BeginChild("MobileScanner", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "Scanner");
  ImGui::SameLine();
  ui::status_dot(state.scan.async_pending ? palette.warning :
                 connected && has_pid ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(palette.muted, "%s", selected_process_name(state).c_str());

  ImGui::BeginChild("MobileScannerSummary", ImVec2(0, 128.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  has_pid ? palette.text : palette.dim);
  mobile_info_row("Results", std::to_string(state.scan.result.count) +
                                 (state.scan.result.truncated ? " truncated"
                                                              : ""),
                  state.scan.result.count != 0 ? palette.success
                                               : palette.muted);
  mobile_info_row("Speed",
                  bytes_per_second(state.scan.result.bytes_scanned,
                                   state.scan.result.elapsed_ns),
                  palette.muted);
  mobile_info_row("Session", state.scan.session_status, palette.dim);
  ImGui::EndChild();

  draw_mobile_section_label("Exact value");
  mobile_value_type_combo("Value type##MobileScanType", &state.scan.type);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Value##MobileScanValue", "0",
                           state.scan.value, sizeof(state.scan.value));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Alignment##MobileScanAlignment", &state.scan.alignment);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Max results##MobileScanMaxResults",
                  &state.scan.max_results, 100, 1000);
  state.scan.alignment = std::max(state.scan.alignment, 1);
  state.scan.max_results = std::clamp(state.scan.max_results, 1,
      static_cast<int>(MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE));

  draw_mobile_section_label("Range");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Start##MobileScanStart", "0x0",
                           state.scan.start, sizeof(state.scan.start));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Length##MobileScanLength", "0x1000",
                           state.scan.length, sizeof(state.scan.length));

  const bool can_range = connected && has_pid && !client_async_busy(state) &&
                         payload_supports(state, MEMDBG_CAP_SCAN_EXACT);
  ImGui::BeginDisabled(!can_range);
  if (mobile_action_button(std::string(icons::kSearch) + "  Range scan",
                           true)) {
    mobile_start_range_scan(state);
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Process scan");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("End filter##MobileScanEnd", "0x0",
                           state.scan.end, sizeof(state.scan.end));
  ImGui::Checkbox("Readable maps only", &state.scan.readable_only);

  const bool can_process =
      connected && has_pid && !client_async_busy(state) &&
      payload_supports(state, MEMDBG_CAP_SCAN_PROCESS_EXACT);
  ImGui::BeginDisabled(!can_process);
  if (mobile_action_button(std::string(icons::kTarget) + "  Scan process",
                           false)) {
    mobile_start_process_scan(state, false);
  }
  ImGui::EndDisabled();

  const bool can_unknown =
      connected && has_pid && !client_async_busy(state) &&
      payload_supports(state, MEMDBG_CAP_SCAN_UNKNOWN);
  ImGui::BeginDisabled(!can_unknown);
  ImGui::Checkbox("Exclude zero values (prefilter)",
                  &state.scan.unknown_nonzero_prefilter);
  if (mobile_action_button(std::string(icons::kSearch) +
                               "  Unknown value baseline",
                           false)) {
    mobile_start_process_scan(state, true);
  }
  ImGui::EndDisabled();

  if (state.scan.async_pending) {
    ui::draw_scan_progress(state.scan.async_label, icons::kSearch,
                           ImGui::GetTime() - state.scan.async_start_time,
                           ImGui::GetContentRegionAvail().x);
    const uint64_t total = state.scan.async_units_total.load();
    if (total != 0U) {
      const uint64_t done = state.scan.async_units_done.load();
      const float fraction = std::min(
          1.0f, static_cast<float>(done) / static_cast<float>(total));
      ImGui::ProgressBar(fraction,
                         ImVec2(ImGui::GetContentRegionAvail().x, 12.0f), "");
      const char *progress_format = state.scan.async_units_are_maps.load()
          ? locale::tr("scanner.maps_progress")
          : locale::tr("scanner.units_progress");
      ImGui::Text(progress_format,
                  static_cast<unsigned long long>(done),
                  static_cast<unsigned long long>(total));
    }
    const uint32_t maps_total = state.scan.async_maps_total.load();
    if (maps_total != 0U) {
      ImGui::Text(locale::tr("scanner.maps_progress"),
                  static_cast<unsigned long long>(
                      state.scan.async_maps_done.load()),
                  static_cast<unsigned long long>(maps_total));
    }
    ImGui::Text(locale::tr("scanner.results_found"),
                static_cast<unsigned long long>(
                    state.scan.async_results_found.load()));
    const uint32_t workers_total = state.scan.async_workers_total.load();
    if (workers_total != 0U) {
      ImGui::Text(locale::tr("scanner.workers_active"),
                  state.scan.async_workers_active.load(), workers_total);
    }
    if (state.scan.async_cancellable &&
        mobile_action_button("Stop active scan", true)) {
      state.scan.async_cancel_requested.store(true);
      set_status(state, "Stopping scan...");
    }
  }

  draw_mobile_section_label("Refine");
  const bool can_refine =
      connected && has_pid && !client_async_busy(state) &&
      payload_supports(state, MEMDBG_CAP_MEMORY_READ) &&
      !state.scan.snapshot.empty();
  ImGui::BeginDisabled(!can_refine);
  if (mobile_action_button("Exact value", false))
    mobile_refine_scan(state, RefineMode::ExactValue);
  if (mobile_action_button("Changed", false))
    mobile_refine_scan(state, RefineMode::Changed);
  if (mobile_action_button("Unchanged", false))
    mobile_refine_scan(state, RefineMode::Unchanged);
  if (mobile_action_button("Increased", false))
    mobile_refine_scan(state, RefineMode::Increased);
  if (mobile_action_button("Decreased", false))
    mobile_refine_scan(state, RefineMode::Decreased);
  if (mobile_action_button(std::string(icons::kRefresh) +
                               "  Refresh baseline",
                           false)) {
    mobile_refresh_scan_snapshot(state);
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Results");
  if (state.scan.result.addresses.empty()) {
    ImGui::TextColored(palette.dim, "%s", "No scan results");
  } else {
    if (mobile_action_button(std::string(icons::kCopy) + "  Copy all",
                             false)) {
      std::string all;
      all.reserve(state.scan.result.addresses.size() * 18U);
      for (uint64_t address : state.scan.result.addresses)
        all += hex_u64(address) + "\n";
      ImGui::SetClipboardText(all.c_str());
      set_status(state, "Copied scan results");
    }

    if (mobile_action_button(std::string(icons::kAdd) +
                                 "  First hit to trainer",
                             false)) {
      const std::string address = hex_u64(state.scan.result.addresses.front());
      std::snprintf(state.plugin.cheat_address, sizeof(state.plugin.cheat_address), "%s",
                    address.c_str());
      state.plugin.cheat_type = state.scan.type;
      state.screen = Screen::Trainer;
    }

    const size_t limit =
        std::min<size_t>(state.scan.result.addresses.size(), 80U);
    for (size_t i = 0; i < limit; ++i) {
      const uint64_t address = state.scan.result.addresses[i];
      const ScanSnapshotEntry *snap = mobile_snapshot_for(state, address);
      const float card_h = 66.0f * scl;
      ImGui::PushID(static_cast<int>(i));
      ImGui::BeginChild("MobileScanHit", ImVec2(0, card_h), true,
                        ImGuiWindowFlags_NoScrollbar);
      const std::string addr = hex_u64(address);
      if (ImGui::Selectable(addr.c_str(), false,
                            ImGuiSelectableFlags_AllowDoubleClick)) {
        std::snprintf(state.mem.read_address, sizeof(state.mem.read_address), "%s",
                      addr.c_str());
        std::snprintf(state.mem.write_address, sizeof(state.mem.write_address), "%s",
                      addr.c_str());
        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
          state.screen = Screen::Memory;
      }
      ImGui::TextColored(
          palette.dim, "%s",
          snap != nullptr
              ? mobile_scan_value_text(state.scan.snapshot_type, snap->bytes)
                    .c_str()
              : "value not captured");
      ImGui::SameLine(ImGui::GetWindowWidth() - 86.0f * scl);
      if (ImGui::SmallButton("Use")) {
        std::snprintf(state.mem.read_address, sizeof(state.mem.read_address), "%s",
                      addr.c_str());
        std::snprintf(state.mem.write_address, sizeof(state.mem.write_address), "%s",
                      addr.c_str());
        std::snprintf(state.plugin.cheat_address, sizeof(state.plugin.cheat_address), "%s",
                      addr.c_str());
      }
      ImGui::EndChild();
      ImGui::PopID();
    }
    if (state.scan.result.addresses.size() > limit) {
      ImGui::TextColored(palette.dim, "%zu more results hidden on mobile",
                         state.scan.result.addresses.size() - limit);
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

bool mobile_validate_writable_address(AppState &state, int32_t pid,
                                             uint64_t address, size_t length,
                                             std::string &error) {
  if (length == 0U) return true;
  const uint64_t byte_length = static_cast<uint64_t>(length);
  if (address > UINT64_MAX - byte_length) {
    error = "Trainer address range overflows";
    return false;
  }

  std::vector<MapEntry> fetched_maps;
  const std::vector<MapEntry> *maps = nullptr;
  if (pid == state.selected_pid && !state.maps.empty()) {
    maps = &state.maps;
  } else if (state.client.connected()) {
    if (state.client.process_maps(pid, fetched_maps)) maps = &fetched_maps;
  }
  if (maps == nullptr || maps->empty()) return true;

  const uint64_t end = address + byte_length;
  for (const auto &map : *maps) {
    if (address < map.start || end > map.end) continue;
    if ((map.protection & 2U) == 0U) {
      error = "Address " + hex_u64(address) + " is not writable";
      if (!map.name.empty()) error += ": " + map.name;
      return false;
    }
    return true;
  }

  error = "Address " + hex_u64(address) + " is outside known maps";
  return false;
}

bool mobile_apply_cheat(AppState &state, CheatEntry &cheat) {
  if (!state.client.connected()) {
    cheat.status = "No console session";
    return false;
  }
  const int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0) {
    cheat.status = "No target PID";
    return false;
  }
  if (cheat.bytes.empty()) {
    cheat.status = "Empty value";
    return false;
  }

  std::string validation_error;
  if (!mobile_validate_writable_address(state, pid, cheat.address,
                                        cheat.bytes.size(),
                                        validation_error)) {
    cheat.status = validation_error;
    return false;
  }

  uint32_t written = 0;
  if (!state.client.memory_write(pid, cheat.address, cheat.bytes, written)) {
    cheat.status = state.client.last_error();
    return false;
  }
  cheat.active = true;
  cheat.active_known = true;
  cheat.status = "Wrote " + std::to_string(written) + " bytes";
  return true;
}

bool mobile_deactivate_cheat(AppState &state, CheatEntry &cheat) {
  if (!cheat.has_off_bytes || cheat.off_bytes.empty()) {
    cheat.status = "No OFF value captured";
    return false;
  }
  if (!state.client.connected()) {
    cheat.status = "No console session";
    return false;
  }
  const int32_t pid = cheat.pid > 0 ? cheat.pid : state.selected_pid;
  if (pid <= 0) {
    cheat.status = "No target PID";
    return false;
  }

  std::string validation_error;
  if (!mobile_validate_writable_address(state, pid, cheat.address,
                                        cheat.off_bytes.size(),
                                        validation_error)) {
    cheat.status = validation_error;
    return false;
  }

  uint32_t written = 0;
  if (!state.client.memory_write(pid, cheat.address, cheat.off_bytes,
                                 written)) {
    cheat.status = state.client.last_error();
    return false;
  }
  cheat.active = false;
  cheat.active_known = true;
  cheat.status = "Restored " + std::to_string(written) + " bytes";
  return true;
}

void mobile_add_cheat_from_fields(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, "Select a process before adding a trainer entry");
    return;
  }
  if (client_async_busy(state)) {
    set_status(state, "Wait for the active operation to finish");
    return;
  }

  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  if (!parse_u64(state.plugin.cheat_address, address)) {
    set_status(state, "Invalid cheat address");
    return;
  }
  if (!build_value_bytes(state.plugin.cheat_type, state.plugin.cheat_value, bytes)) {
    set_status(state, "Invalid cheat value");
    return;
  }

  CheatEntry cheat;
  cheat.description =
      state.plugin.cheat_description[0] != '\0' ? state.plugin.cheat_description : "Cheat";
  cheat.pid = state.selected_pid;
  cheat.address = address;
  cheat.value_type = state.plugin.cheat_type;
  cheat.value_text = state.plugin.cheat_value;
  cheat.bytes = std::move(bytes);
  cheat.locked = state.plugin.cheat_lock;
  if (state.client.connected()) (void)capture_off_value(state, cheat);
  state.plugin.cheats.push_back(std::move(cheat));
  set_status(state, "Trainer entry added");
}

void mobile_apply_enabled_cheats(AppState &state) {
  int applied = 0;
  for (auto &cheat : state.plugin.cheats)
    if (cheat.enabled && mobile_apply_cheat(state, cheat)) applied++;
  const std::string message =
      "Applied " + std::to_string(applied) + " trainer entries";
  set_status(state, message);
  push_notification(state, message);
}

void mobile_import_batchcode(AppState &state) {
  if (state.selected_pid <= 0) {
    set_status(state, locale::tr("trainer.select_process_for_batch"));
    return;
  }
  std::string error;
  std::vector<BatchcodeEntry> entries;
  const int imported = parse_batchcode(state.plugin.batchcode_text, entries, error);
  if (imported < 0) {
    char error_buffer[512];
    std::snprintf(error_buffer, sizeof(error_buffer),
                  locale::tr("trainer.batchcode_error"), error.c_str());
    set_status(state, error_buffer);
    return;
  }
  for (size_t i = 0; i < entries.size(); ++i) {
    CheatEntry cheat;
    char name_buffer[128];
    std::snprintf(name_buffer, sizeof(name_buffer),
                  locale::tr("trainer.batchcode_name"),
                  static_cast<int>(i + 1U));
    cheat.description = name_buffer;
    cheat.pid = state.selected_pid;
    cheat.address = entries[i].offset;
    cheat.value_type = MEMDBG_VALUE_BYTES;
    cheat.value_text = bytes_to_hex(entries[i].bytes);
    cheat.bytes = std::move(entries[i].bytes);
    cheat.enabled = true;
    if (state.client.connected()) (void)capture_off_value(state, cheat);
    state.plugin.cheats.push_back(std::move(cheat));
  }
  char import_buffer[256];
  if (imported > 0) {
    std::snprintf(import_buffer, sizeof(import_buffer),
                  locale::tr("trainer.imported_n"),
                  static_cast<unsigned>(imported));
  } else {
    std::snprintf(import_buffer, sizeof(import_buffer), "%s",
                  locale::tr("trainer.no_batchcode"));
  }
  set_status(state, import_buffer);
}

void draw_mobile_trainer(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const bool has_pid = state.selected_pid > 0;

  ImGui::BeginChild("MobileTrainer", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "Trainer");
  ImGui::SameLine();
  ui::status_dot(connected && has_pid ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(palette.muted, "%s", selected_process_name(state).c_str());

  ImGui::BeginChild("MobileTrainerSummary", ImVec2(0, 96.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  has_pid ? palette.text : palette.dim);
  mobile_info_row("Entries", std::to_string(state.plugin.cheats.size()),
                  state.plugin.cheats.empty() ? palette.muted : palette.success);
  mobile_info_row("File", state.plugin.trainer_file_path, palette.dim);
  ImGui::EndChild();

  draw_mobile_section_label("Cheat builder");
  ImGui::BeginDisabled(!has_pid);
  if (mobile_action_button("Use memory address", false)) {
    std::snprintf(state.plugin.cheat_address, sizeof(state.plugin.cheat_address), "%s",
                  state.mem.write_address);
  }
  ImGui::BeginDisabled(state.scan.result.addresses.empty());
  if (mobile_action_button("Use first scan hit", false)) {
    const std::string address = hex_u64(state.scan.result.addresses.front());
    std::snprintf(state.plugin.cheat_address, sizeof(state.plugin.cheat_address), "%s",
                  address.c_str());
  }
  ImGui::EndDisabled();
  ImGui::EndDisabled();

  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Name##MobileCheatName", "Cheat name",
                           state.plugin.cheat_description,
                           sizeof(state.plugin.cheat_description));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Address##MobileCheatAddress", "0x0",
                           state.plugin.cheat_address, sizeof(state.plugin.cheat_address));
  mobile_value_type_combo("Value type##MobileCheatType", &state.plugin.cheat_type);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Value##MobileCheatValue", "0",
                           state.plugin.cheat_value, sizeof(state.plugin.cheat_value));
  ImGui::Checkbox("Lock on apply", &state.plugin.cheat_lock);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::SliderFloat("Lock interval##MobileCheatLockInterval",
                     &state.plugin.cheat_lock_interval, 0.10f, 5.0f, "%.2fs");

  ImGui::BeginDisabled(!connected || !has_pid || client_async_busy(state));
  if (mobile_action_button(std::string(icons::kAdd) + "  Add entry", true))
    mobile_add_cheat_from_fields(state);
  ImGui::EndDisabled();

  draw_mobile_section_label("Trainer file");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputTextWithHint("Path##MobileTrainerPath", "trainers/session.cht",
                           state.plugin.trainer_file_path,
                           sizeof(state.plugin.trainer_file_path));
  /* Browse button using native OS file picker */
  if (mobile_action_button(std::string(icons::kLoad) + "  Browse...", false)) {
    std::string picked = ui::pickFile("Open Trainer File", "Trainer Files", "*.cht");
    if (!picked.empty()) {
      std::snprintf(state.plugin.trainer_file_path, sizeof(state.plugin.trainer_file_path),
                    "%s", picked.c_str());
      const int count = load_trainer_file(state, state.plugin.trainer_file_path);
      if (count >= 0)
        set_status(state, "Loaded " + std::to_string(count) +
                              " trainer entries");
    }
  }
  if (mobile_action_button(std::string(icons::kSave) + "  Save", false))
    save_trainer_file(state, state.plugin.trainer_file_path);

  if (ImGui::CollapsingHeader("Batchcode import")) {
    ImGui::InputTextMultiline("##MobileBatchcode", state.plugin.batchcode_text,
                              sizeof(state.plugin.batchcode_text),
                              ImVec2(-1.0f, 112.0f * scl));
    ImGui::BeginDisabled(!has_pid);
    if (mobile_action_button(std::string(icons::kImport) + "  Import",
                             false)) {
      mobile_import_batchcode(state);
    }
    ImGui::EndDisabled();
  }

  draw_mobile_section_label("Runtime list");
  if (state.plugin.cheats.empty()) {
    ImGui::TextColored(palette.dim, "%s", "No trainer entries");
  } else {
    ImGui::BeginDisabled(!connected || client_async_busy(state));
    if (mobile_action_button(std::string(icons::kPlay) + "  Apply enabled",
                             true)) {
      mobile_apply_enabled_cheats(state);
    }
    ImGui::EndDisabled();
    if (mobile_action_button(std::string(icons::kTrash) +
                                 "  Clear disabled",
                             false)) {
      state.plugin.cheats.erase(
          std::remove_if(state.plugin.cheats.begin(), state.plugin.cheats.end(),
                         [](const CheatEntry &cheat) {
                           return !cheat.enabled;
                         }),
          state.plugin.cheats.end());
      set_status(state, "Disabled trainer entries cleared");
    }

    size_t remove_index = std::numeric_limits<size_t>::max();
    for (size_t i = 0; i < state.plugin.cheats.size(); ++i) {
      CheatEntry &cheat = state.plugin.cheats[i];
      ImGui::PushID(static_cast<int>(i));
      ImGui::BeginChild("MobileTrainerCheatCard", ImVec2(0, 170.0f * scl),
                        true, ImGuiWindowFlags_NoScrollbar);
      ImGui::Checkbox("##enabled", &cheat.enabled);
      ImGui::SameLine();
      text_ellipsis(cheat.description.c_str(),
                    ImGui::GetContentRegionAvail().x, palette.text);
      ImGui::TextColored(palette.dim, "%s | %s | PID %d",
                         hex_u64(cheat.address).c_str(),
                         value_type_name(cheat.value_type), cheat.pid);
      text_ellipsis(("Value " + cheat.value_text).c_str(),
                    ImGui::GetContentRegionAvail().x, palette.muted);
      ImGui::Checkbox("Lock", &cheat.locked);
      ImGui::SameLine();
      if (!cheat.active_known) {
        ImGui::TextColored(palette.warning, "%s",
                           locale::tr("trainer.state_unknown"));
      } else {
        ImGui::TextColored(cheat.active ? palette.success : palette.dim, "%s",
                           cheat.active ? locale::tr("trainer.state_active")
                                        : locale::tr("trainer.state_idle"));
      }
      ImGui::TextColored(
          cheat.has_off_bytes ? palette.success : palette.warning,
          "%s: %s", locale::tr("trainer.col_off"),
          cheat.has_off_bytes ? locale::tr("trainer.off_yes")
                              : locale::tr("trainer.off_no"));

      const float gap = 6.0f * scl;
      const float button_w =
          (ImGui::GetContentRegionAvail().x - gap * 3.0f) / 4.0f;
      ImGui::BeginDisabled(!connected || client_async_busy(state));
      if (ui::primary_button("ON", ImVec2(button_w, 34.0f * scl))) {
        if (mobile_apply_cheat(state, cheat)) set_status(state, cheat.status);
      }
      ImGui::SameLine(0, gap);
      ImGui::BeginDisabled(!cheat.has_off_bytes);
      if (ui::soft_button("Restore", ImVec2(button_w, 34.0f * scl))) {
        if (mobile_deactivate_cheat(state, cheat))
          set_status(state, cheat.status);
      }
      ImGui::EndDisabled();
      ImGui::SameLine(0, gap);
      if (ui::soft_button("Capture", ImVec2(button_w, 34.0f * scl))) {
        if (capture_off_value(state, cheat)) set_status(state, cheat.status);
      }
      ImGui::EndDisabled();
      ImGui::SameLine(0, gap);
      if (ui::danger_button("DEL", ImVec2(button_w, 34.0f * scl)))
        remove_index = i;

      if (!cheat.status.empty())
        text_ellipsis(cheat.status.c_str(), ImGui::GetContentRegionAvail().x,
                      palette.dim);
      ImGui::EndChild();
      ImGui::PopID();
    }
    if (remove_index != std::numeric_limits<size_t>::max() &&
        remove_index < state.plugin.cheats.size()) {
      state.plugin.cheats.erase(state.plugin.cheats.begin() +
                         static_cast<std::ptrdiff_t>(remove_index));
      set_status(state, "Trainer entry removed");
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

void draw_mobile_credits(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  ImGui::BeginChild("MobileCredits", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "MemDBG");
  ImGui::TextColored(palette.muted, "%s",
                     "PlayStation Memory Debugger");

  ImGui::BeginChild("MobileCreditsCard", ImVec2(0, 132.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Version", std::string("v") + MEMDBG_VERSION_STRING,
                  palette.text);
  mobile_info_row("Creator", "Seregon (@seregonwar)", palette.text);
  mobile_info_row("License", "GNU GPL v3.0 or later", palette.muted);
  mobile_info_row("Profile",
                  state.github_profile.error.empty()
                      ? state.github_profile.login
                      : state.github_profile.error,
                  state.github_profile.error.empty() ? palette.link
                                                     : palette.warning);
  ImGui::EndChild();

  if (mobile_action_button(std::string(icons::kLink) + "  GitHub", false))
    set_status(state, "GitHub profile: https://github.com/seregonwar");
  if (mobile_action_button(std::string(icons::kCredits) + "  Donations",
                           false))
    set_status(state, "Donations link is available in the desktop credits");
  if (mobile_action_button("X / SeregonWar", false))
    set_status(state, "X profile: SeregonWar");
  if (mobile_action_button("Bluesky", false))
    set_status(state, "Bluesky profile selected");

  draw_mobile_section_label("Project");
  ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                         ImGui::GetContentRegionAvail().x);
  ImGui::TextWrapped(
      "%s",
      "MemDBG combines memory scanning, remote debugging, trainer workflows, "
      "plugins, UDP logs, telemetry, and console session tools for PS4 and "
      "PS5 homebrew research.");
  ImGui::PopTextWrapPos();
  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

void draw_mobile_fallback(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  ImGui::BeginChild("MobileFallback", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", screen_title(state.screen));
  ImGui::TextWrapped("%s", screen_subtitle(state.screen));
  ImGui::Spacing();
  ImGui::BeginChild("MobileFallbackCard", ImVec2(0, 150.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Session",
                  state.client.connected() ? "Connected" : "Offline",
                  state.client.connected() ? palette.success : palette.dim);
  mobile_info_row("Process", selected_process_name(state),
                  state.selected_pid > 0 ? palette.text : palette.dim);
  mobile_info_row("Status", state.status, palette.muted);
  ImGui::EndChild();

  if (mobile_action_button(std::string(icons::kConsole) + "  Console",
                           false))
    state.screen = Screen::Consoles;
  if (mobile_action_button(std::string(icons::kScanner) + "  Scanner",
                           false))
    state.screen = Screen::Scanner;
  if (mobile_action_button(std::string(icons::kTrainer) + "  Trainer",
                           false))
    state.screen = Screen::Trainer;
  if (mobile_action_button(std::string(icons::kPlugins) + "  Plugins",
                           false))
    state.screen = Screen::Plugins;

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}

void draw_mobile_processes(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const ImVec4 selected_bg(32.0f / 255.0f, 58.0f / 255.0f,
                           45.0f / 255.0f, 1.0f);

  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(12.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::BeginChild("MobileProcesses", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);

  ImGui::TextColored(palette.primary2, "%s", "Processes");
  ImGui::SameLine();
  ui::status_dot(connected ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(connected ? palette.muted : palette.danger, "%s",
                     connected ? "Select a target PID" : "Offline");

  ImGui::BeginChild("MobileProcessSummary", ImVec2(0, 154.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  mobile_info_row("Session", connected ? "Connected" : "Offline",
                  connected ? palette.success : palette.dim);
  mobile_info_row("Process", selected_process_name(state),
                  state.selected_pid > 0 ? palette.text : palette.dim);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  state.selected_pid > 0 ? palette.text : palette.dim);
  mobile_info_row("Maps", std::to_string(state.maps.size()),
                  state.maps.empty() ? palette.dim : palette.text);
  ImGui::Separator();
  text_ellipsis(state.status, ImGui::GetContentRegionAvail().x, palette.muted);
  ImGui::EndChild();

  if (!connected) {
    if (mobile_action_button(std::string(icons::kConsole) +
                                 "  Configure console",
                             true))
      state.screen = Screen::Consoles;
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    return;
  }

  ImGui::BeginDisabled(client_async_busy(state));
  if (mobile_action_button(std::string(icons::kRefresh) +
                               "  Refresh processes",
                           state.processes.empty()))
    topbar_refresh_processes(state);
  ImGui::EndDisabled();

  ImGui::BeginDisabled(client_async_busy(state) || state.selected_pid <= 0);
  if (mobile_action_button(std::string(icons::kMemory) + "  Load maps",
                           state.maps.empty()))
    topbar_refresh_maps(state);
  ImGui::EndDisabled();

  if (state.selected_pid > 0) {
    ImGui::BeginChild("MobileProcessQuickActions", ImVec2(0, 96.0f * scl),
                      true, ImGuiWindowFlags_NoScrollbar);
    if (ImGui::BeginTable("MobileProcessQuickActionTable", 2,
                          ImGuiTableFlags_SizingStretchSame)) {
      ImGui::TableNextColumn();
      if (mobile_action_button(std::string(icons::kScanner) + "  Scanner",
                               false))
        state.screen = Screen::Scanner;
      ImGui::TableNextColumn();
      if (mobile_action_button(std::string(icons::kTrainer) + "  Trainer",
                               false))
        state.screen = Screen::Trainer;
      ImGui::EndTable();
    }
    ImGui::EndChild();
  }

  draw_mobile_section_label("Process list");
  if (state.processes.empty()) {
    ImGui::BeginChild("MobileNoProcesses", ImVec2(0, 92.0f * scl), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextColored(palette.muted, "%s", "No processes loaded");
    ImGui::TextWrapped("%s",
                       "Refresh the process list after connecting a console.");
    ImGui::EndChild();
  } else {
    for (int i = 0; i < static_cast<int>(state.processes.size()); ++i) {
      const ProcessEntry &process = state.processes[i];
      const bool selected = process.pid == state.selected_pid;
      ImGui::PushID(i);
      ImGui::PushStyleColor(ImGuiCol_ChildBg,
                            selected ? selected_bg : palette.bg1);
      ImGui::BeginChild("MobileProcessCard", ImVec2(0, 66.0f * scl), true,
                        ImGuiWindowFlags_NoScrollbar);
      const ImVec2 text_pos = ImGui::GetCursorScreenPos();
      const ImVec2 hit_size(ImGui::GetContentRegionAvail().x, 48.0f * scl);
      ImGui::InvisibleButton("##select_process", hit_size);
      const bool clicked = ImGui::IsItemClicked();
      if (selected) {
        ImDrawList *dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(text_pos,
                          ImVec2(text_pos.x + 3.0f * scl,
                                 text_pos.y + hit_size.y),
                          ui::color_u32(palette.primary2), 2.0f * scl);
      }
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y));
      const std::string process_name =
          process.name.empty() ? "unnamed" : process.name;
      text_ellipsis(process_name.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.text);
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y + 24.0f * scl));
      ImGui::TextColored(selected ? palette.primary2 : palette.muted,
                         "PID %d", process.pid);
      ImGui::EndChild();
      ImGui::PopStyleColor();
      ImGui::PopID();
      if (clicked) topbar_select_process(state, i);
    }
  }

  draw_mobile_section_label("Memory maps");
  if (state.selected_pid <= 0) {
    ImGui::BeginChild("MobileMapsNoProcess", ImVec2(0, 86.0f * scl), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextColored(palette.muted, "%s", "Select a process first");
    ImGui::TextWrapped("%s",
                       "Maps become scan ranges and trainer safety checks.");
    ImGui::EndChild();
  } else if (state.maps.empty()) {
    ImGui::BeginChild("MobileNoMaps", ImVec2(0, 86.0f * scl), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextColored(palette.muted, "%s", "No maps loaded");
    ImGui::TextWrapped("%s",
                       "Load maps to pick a touch-friendly scan range.");
    ImGui::EndChild();
  } else {
    for (int i = 0; i < static_cast<int>(state.maps.size()); ++i) {
      const MapEntry &map = state.maps[i];
      const bool selected = i == state.selected_map_row;
      const uint64_t size_bytes = map.end > map.start ? map.end - map.start : 0;
      ImGui::PushID(10000 + i);
      ImGui::PushStyleColor(ImGuiCol_ChildBg,
                            selected ? selected_bg : palette.bg1);
      ImGui::BeginChild("MobileMapCard", ImVec2(0, 76.0f * scl), true,
                        ImGuiWindowFlags_NoScrollbar);
      const ImVec2 text_pos = ImGui::GetCursorScreenPos();
      const ImVec2 hit_size(ImGui::GetContentRegionAvail().x, 58.0f * scl);
      ImGui::InvisibleButton("##select_map", hit_size);
      const bool clicked = ImGui::IsItemClicked();
      if (selected) {
        ImDrawList *dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(text_pos,
                          ImVec2(text_pos.x + 3.0f * scl,
                                 text_pos.y + hit_size.y),
                          ui::color_u32(palette.primary2), 2.0f * scl);
      }
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y));
      const std::string title = hex_u64(map.start) + "  " +
                                prot_text(map.protection) + "  " +
                                mobile_format_bytes(size_bytes);
      text_ellipsis(title.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.text);
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y + 25.0f * scl));
      const std::string map_name =
          map.name.empty() ? "anonymous mapping" : map.name;
      text_ellipsis(map_name.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.muted);
      ImGui::SetCursorScreenPos(ImVec2(text_pos.x + 10.0f * scl,
                                       text_pos.y + 47.0f * scl));
      const std::string map_end = hex_u64(map.end);
      text_ellipsis(map_end.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.dim);
      ImGui::EndChild();
      ImGui::PopStyleColor();
      ImGui::PopID();
      if (clicked) mobile_select_map(state, i);
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
  ImGui::PopStyleVar(2);
}

void draw_mobile_session(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();

  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(12.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::BeginChild("MobileSession", size, false);

  ImGui::TextColored(palette.primary2, "%s", "Session");
  ImGui::SameLine();
  ui::status_dot(state.conn.connect_pending ? palette.warning :
                 connected ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(state.conn.connect_pending ? palette.warning :
                     connected ? palette.success : palette.danger,
                     "%s", state.conn.connect_pending ? "Connecting" :
                          connected ? "Connected" : "Not connected");

  ImGui::Spacing();
  ImGui::BeginChild("MobileSessionCard", ImVec2(0, 154.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  char endpoint[96];
  std::snprintf(endpoint, sizeof(endpoint), "%s:%d", state.host,
                state.debug_port);
  mobile_info_row("Endpoint", endpoint,
                  connected ? palette.text : palette.muted);
  mobile_info_row("UDP", state.udp_listener.running() ? "Listening" : "Stopped",
                  state.udp_listener.running() ? palette.success : palette.dim);
  mobile_info_row("Process", selected_process_name(state),
                  state.selected_pid != 0 ? palette.text : palette.muted);
  mobile_info_row("PID", std::to_string(state.selected_pid),
                  state.selected_pid != 0 ? palette.text : palette.dim);
  ImGui::Separator();
  text_ellipsis(state.status, ImGui::GetContentRegionAvail().x, palette.muted);
  ImGui::EndChild();

  if (connect_sequence_pending(state)) {
    if (ui::danger_button((std::string(icons::kDisconnect) +
                           "  Cancel connection").c_str(),
                          ImVec2(ImGui::GetContentRegionAvail().x,
                                 42.0f * scl))) {
      cancel_connect(state);
    }
  } else {
    ImGui::BeginDisabled(client_async_busy(state));
    if (connected) {
      if (ui::soft_button((std::string(icons::kGauge) + "  Ping").c_str(),
                          ImVec2(ImGui::GetContentRegionAvail().x,
                                 42.0f * scl))) {
        set_status(state, state.client.ping() ? "Ping OK"
                                              : state.client.last_error());
      }
      if (ui::danger_button((std::string(icons::kDisconnect) +
                             "  Disconnect").c_str(),
                            ImVec2(ImGui::GetContentRegionAvail().x,
                                   42.0f * scl))) {
        disconnect_console(state);
      }
    } else {
      if (ui::primary_button((std::string(icons::kConsole) +
                              "  Configure console").c_str(),
                             ImVec2(ImGui::GetContentRegionAvail().x,
                                    44.0f * scl))) {
        state.screen = Screen::Consoles;
      }
      if (ui::soft_button((std::string(icons::kConnect) +
                           "  Connect").c_str(),
                          ImVec2(ImGui::GetContentRegionAvail().x,
                                 42.0f * scl))) {
        connect_console(state, ConnectIntent::ManualFreshConnection);
      }
    }
    ImGui::EndDisabled();
  }

  ImGui::Spacing();
  ImGui::TextColored(palette.muted, "%s", "Workflows");
  if (mobile_nav_button("MobileNavConsole", icons::kConsole, "Console", true))
    state.screen = Screen::Consoles;
  if (mobile_nav_button("MobileNavProcesses", icons::kProcess, "Processes",
                        connected))
    state.screen = Screen::Processes;
  if (mobile_nav_button("MobileNavScanner", icons::kScanner, "Scanner",
                        connected))
    state.screen = Screen::Scanner;
  if (mobile_nav_button("MobileNavTrainer", icons::kTrainer, "Trainer",
                        connected))
    state.screen = Screen::Trainer;
  if (mobile_nav_button("MobileNavPlugins", icons::kPlugins, "Plugins", true))
    state.screen = Screen::Plugins;
  if (mobile_nav_button("MobileNavLogs", icons::kLogs, "Logs", true))
    state.screen = Screen::Logs;

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
}

void draw_mobile_top_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(10.0f * ui::dpi_scale(), 6.0f * ui::dpi_scale()));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(6.0f * ui::dpi_scale(), 0));
  ImGui::BeginChild("MobileTopBar", size, true, ImGuiWindowFlags_NoScrollbar);

  const float scl = ui::dpi_scale();
  const float topbar_w = ImGui::GetWindowWidth();
  const float bar_h = size.y;
  const bool connected = state.client.connected();

  ImGui::SetCursorPosY((bar_h - ImGui::GetFontSize()) * 0.5f);
  ImGui::TextColored(ui::colors().primary2, "%s", "MemDBG");
  ImGui::SameLine();
  ui::status_dot(state.conn.connect_pending ? ui::colors().warning :
                 connected ? ui::colors().success : ui::colors().dim);
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().muted, "%s",
                     state.conn.connect_pending ? "Connecting" :
                     connected ? "Online" : "Offline");

  const float btn_h = std::max(34.0f * scl, bar_h - 12.0f * scl);
  const float btn_w = connected ? btn_h : std::min(126.0f * scl,
                                                   topbar_w * 0.38f);
  ImGui::SetCursorPos(ImVec2(topbar_w - btn_w - 8.0f * scl,
                             (bar_h - btn_h) * 0.5f));
  if (connect_sequence_pending(state)) {
    if (ui::danger_button((std::string(icons::kDisconnect) +
                           "  " + locale::tr("common.cancel")).c_str(),
                          ImVec2(btn_w, btn_h))) {
      cancel_connect(state);
    }
  } else {
    ImGui::BeginDisabled(client_async_busy(state));
    if (connected) {
      if (ui::danger_button((std::string(icons::kDisconnect)).c_str(),
                            ImVec2(btn_w, btn_h))) {
        disconnect_console(state);
      }
    } else {
      if (ui::primary_button((std::string(icons::kConsole) +
                              "  Setup").c_str(),
                             ImVec2(btn_w, btn_h))) {
        state.screen = Screen::Consoles;
      }
    }
    ImGui::EndDisabled();
  }

  ImGui::EndChild();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

void draw_mobile_tools_sheet(AppState &state, ImVec2 tab_pos,
                                    ImVec2 tab_size) {
  if (!s_mobile_tools_open) return;

  const float scl = ui::dpi_scale();
  ImGuiViewport *viewport = ImGui::GetMainViewport();
  const float safe_top = viewport->WorkPos.y + s_mobile_safe_area.top;
  const float max_h = std::max(220.0f * scl, tab_pos.y - safe_top - 12.0f * scl);
  const float sheet_h = std::min(430.0f * scl, max_h);
  const ImVec2 pos(tab_pos.x + 8.0f * scl,
                   std::max(safe_top + 8.0f * scl,
                            tab_pos.y - sheet_h - 8.0f * scl));
  const ImVec2 size(std::max(220.0f * scl, tab_size.x - 16.0f * scl),
                    sheet_h);

  ImGui::SetNextWindowPos(pos);
  ImGui::SetNextWindowSize(size);
  ImGui::PushStyleColor(ImGuiCol_WindowBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(10.0f * scl, 10.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 6.0f * scl);
  ImGui::Begin("##MobileToolSheet", &s_mobile_tools_open,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                   ImGuiWindowFlags_NoSavedSettings |
                   ImGuiWindowFlags_NoResize);

  ImGui::TextColored(ui::colors().primary2, "%s  Tools", icons::kMore);
  ImGui::SameLine(ImGui::GetWindowWidth() - 72.0f * scl);
  if (ui::soft_button("Close", ImVec2(62.0f * scl, 30.0f * scl)))
    s_mobile_tools_open = false;
  ImGui::Separator();

  struct ToolEntry {
    Screen screen;
    const char *icon;
    const char *label;
  };
  const ToolEntry tools[] = {
      {Screen::Home, icons::kHome, "Home"},
      {Screen::Consoles, icons::kConsole, "Console"},
      {Screen::Processes, icons::kProcess, "Processes"},
      {Screen::Scanner, icons::kScanner, "Scanner"},
      {Screen::Trainer, icons::kTrainer, "Trainer"},
      {Screen::Plugins, icons::kPlugins, "Plugins"},
      {Screen::Logs, icons::kLogs, "Logs"},
      {Screen::Credits, icons::kCredits, "Credits"},
  };

  if (ImGui::BeginTable("MobileToolGrid", 2,
                        ImGuiTableFlags_SizingStretchSame |
                            ImGuiTableFlags_PadOuterX)) {
    for (const ToolEntry &tool : tools) {
      ImGui::TableNextColumn();
      const bool selected = state.screen == tool.screen;
      std::string label = std::string(tool.icon) + "  " + tool.label;
      const bool clicked =
          selected ? ui::primary_button(label.c_str(),
                                        ImVec2(-1.0f, 44.0f * scl))
                   : ui::soft_button(label.c_str(),
                                     ImVec2(-1.0f, 44.0f * scl));
      if (clicked) {
        state.screen = tool.screen;
        s_mobile_tools_open = false;
      }
    }
    ImGui::EndTable();
  }

  ImGui::End();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
}

void draw_bottom_tab_bar(AppState &state, ImVec2 pos, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg2);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
  ImGui::SetNextWindowPos(pos);
  ImGui::SetNextWindowSize(size);
  ImGui::Begin("##MobileTabBar", nullptr,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
               ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar |
               ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

  const float tab_w = size.x / 6.0f;
  const float tab_h = size.y;

  struct TabEntry {
    Screen screen;
    const char *icon;
  };
  static const TabEntry tabs[] = {
    { Screen::Home,     icons::kHome },
    { Screen::Consoles, icons::kConsole },
    { Screen::Processes, icons::kProcess },
    { Screen::Scanner,  icons::kScanner },
    { Screen::Trainer,  icons::kTrainer },
  };

  ImDrawList *dl = ImGui::GetWindowDrawList();

  for (int i = 0; i < 5; ++i) {
    const ImVec2 tab_min(pos.x + tab_w * i, pos.y);
    const ImVec2 tab_max(pos.x + tab_w * (i + 1), pos.y + tab_h);
    const bool selected = state.screen == tabs[i].screen;

    /* Background for selected tab */
    if (selected) {
      ImVec4 bg(32.0f/255.0f, 58.0f/255.0f, 45.0f/255.0f, 1.0f);
      dl->AddRectFilled(tab_min, tab_max, ui::color_u32(bg));
      /* Top accent line */
      dl->AddRectFilled(ImVec2(tab_min.x + 8.0f, tab_min.y),
                        ImVec2(tab_max.x - 8.0f, tab_min.y + 2.0f),
                        ui::color_u32(ui::colors().primary2), 1.0f);
    }

    /* Icon centered */
    const ImVec4 icon_col = selected ? ui::colors().primary2 : ui::colors().muted;
    const ImVec2 icon_size = ImGui::CalcTextSize(tabs[i].icon);
    const float icon_x = tab_min.x + (tab_w - icon_size.x) * 0.5f;
    const float icon_y = tab_min.y + (tab_h - icon_size.y) * 0.5f;
    dl->AddText(ImVec2(icon_x, icon_y), ui::color_u32(icon_col), tabs[i].icon);

    /* Hit target */
    ImGui::SetCursorPos(ImVec2(tab_w * i, 0));
    ImGui::InvisibleButton(("##tab" + std::to_string(i)).c_str(), ImVec2(tab_w, tab_h));
    if (ImGui::IsItemClicked()) state.screen = tabs[i].screen;
  }

  /* 6th tab: overflow menu */
  {
    const ImVec2 tab_min(pos.x + tab_w * 5, pos.y);
    const ImVec2 tab_max(pos.x + tab_w * 6, pos.y + tab_h);
    const bool is_overflow_active =
        state.screen == Screen::Plugins || state.screen == Screen::Logs ||
        state.screen == Screen::Credits || state.screen == Screen::PluginGUI ||
        state.screen == Screen::Klog;

    if (is_overflow_active) {
      ImVec4 bg(32.0f/255.0f, 58.0f/255.0f, 45.0f/255.0f, 1.0f);
      dl->AddRectFilled(tab_min, tab_max, ui::color_u32(bg));
      dl->AddRectFilled(ImVec2(tab_min.x + 8.0f, tab_min.y),
                        ImVec2(tab_max.x - 8.0f, tab_min.y + 2.0f),
                        ui::color_u32(ui::colors().primary2), 1.0f);
    }

    const ImVec4 icon_col = is_overflow_active ? ui::colors().primary2 : ui::colors().muted;
    const ImVec2 icon_size = ImGui::CalcTextSize(icons::kMore);
    const float icon_x = tab_min.x + (tab_w - icon_size.x) * 0.5f;
    const float icon_y = tab_min.y + (tab_h - icon_size.y) * 0.5f;
    dl->AddText(ImVec2(icon_x, icon_y), ui::color_u32(icon_col), icons::kMore);

    ImGui::SetCursorPos(ImVec2(tab_w * 5, 0));
    if (ImGui::InvisibleButton("##tab_more", ImVec2(tab_w, tab_h))) {
      s_mobile_tools_open = !s_mobile_tools_open;
    }
  }

  ImGui::End();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor();
  draw_mobile_tools_sheet(state, pos, size);
}

void draw_mobile_status_bar(AppState &state, ImVec2 size) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ui::colors().bg1);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                      ImVec2(10.0f * ui::dpi_scale(), 3.0f * ui::dpi_scale()));
  ImGui::BeginChild("MobileStatusBar", size, true, ImGuiWindowFlags_NoScrollbar);

  const bool connected = state.client.connected();
  ui::status_dot(connected ? ui::colors().success : ui::colors().muted);
  ImGui::SameLine();

  float avail_w = ImGui::GetWindowWidth() - 28.0f * ui::dpi_scale();
  if (avail_w < 60.0f) avail_w = 60.0f;
  text_ellipsis(state.status, avail_w, ui::colors().text);

  ImGui::EndChild();
  ImGui::PopStyleVar();
  ImGui::PopStyleColor();
}

void draw_mobile_content(AppState &state, ImVec2 size) {
  const float scl = ui::dpi_scale();
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                      ImVec2(10.0f * scl, 8.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(8.0f * scl, 8.0f * scl));
  ImGui::PushStyleVar(ImGuiStyleVar_ScrollbarSize, 18.0f * scl);

  if (state.screen == Screen::Home) {
    draw_mobile_session(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Consoles) {
    draw_mobile_network(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Processes) {
    draw_mobile_processes(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Plugins || state.screen == Screen::PluginGUI) {
    draw_mobile_plugins(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Logs) {
    draw_mobile_logs(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Scanner) {
    draw_mobile_scanner(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Trainer) {
    draw_mobile_trainer(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  if (state.screen == Screen::Credits) {
    draw_mobile_credits(state, size);
    ImGui::PopStyleVar(3);
    return;
  }
  if (state.screen == Screen::Klog) {
    draw_klog(state, size);
    ImGui::PopStyleVar(3);
    return;
  }

  draw_mobile_fallback(state, size);
  ImGui::PopStyleVar(3);
}


} // namespace memdbg::frontend

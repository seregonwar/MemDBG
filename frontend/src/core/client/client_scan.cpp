/*
 * MemDBG - Client scan operations.
 */
#include "client_internal.hpp"

namespace memdbg::frontend {

template <typename EntryT>
static bool parse_scan_response(const std::vector<uint8_t> &response,
                                ScanResult &out,
                                std::string &error,
                                size_t entry_addr_offset = offsetof(EntryT, address)) {
  memdbg_scan_response_prefix_t prefix{};
  if (response.size() < sizeof(prefix)) {
    error = "short scan response";
    return false;
  }
  std::memcpy(&prefix, response.data(), sizeof(prefix));
  size_t expected = sizeof(prefix) + static_cast<size_t>(prefix.count) *
                                        sizeof(EntryT);
  if (response.size() < expected) {
    error = "truncated scan response";
    return false;
  }
  out.count = prefix.count;
  out.truncated = prefix.truncated != 0;
  out.cancelled =
      (prefix.reserved & MEMDBG_SCAN_RESULT_FLAG_CANCELLED) != 0U;
  out.bytes_scanned = prefix.bytes_scanned;
  out.elapsed_ns = prefix.elapsed_ns;
  out.read_calls = prefix.read_calls;
  out.regions_scanned = prefix.regions_scanned;
  out.read_errors = prefix.read_errors;
  out.addresses.clear();
  out.addresses.reserve(prefix.count);
  const auto *entries = reinterpret_cast<const EntryT *>(
      response.data() + sizeof(prefix));
  for (uint32_t i = 0; i < prefix.count; ++i) {
    uint64_t addr = 0;
    std::memcpy(&addr,
                reinterpret_cast<const uint8_t *>(&entries[i]) + entry_addr_offset,
                sizeof(uint64_t));
    out.addresses.push_back(addr);
  }
  return true;
}

bool Client::scan_exact(const memdbg_scan_exact_request_t &request_body,
                        ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_EXACT, &request_body, sizeof(request_body),
               response)) {
    return false;
  }
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
}

bool Client::scan_process_exact(
    const memdbg_scan_process_exact_request_t &request_body, ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_PROCESS_EXACT, &request_body,
               sizeof(request_body), response)) {
    return false;
  }
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
}

bool Client::scan_process_exact_tracked(
    uint64_t job_id,
    const memdbg_scan_process_exact_request_t &request_body,
    ScanResult &out) {
  if (job_id == 0U) {
    set_error("scan job id must be non-zero");
    return false;
  }
  memdbg_scan_process_exact_tracked_request_t tracked{};
  tracked.job_id = job_id;
  tracked.scan = request_body;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_PROCESS_EXACT_TRACKED, &tracked,
               sizeof(tracked), response))
    return false;
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(
      response, out, error);
  if (!ok) set_error(error);
  return ok;
}

static bool scan_job_request(Client &client, uint16_t command,
                             uint64_t job_id, Client::ScanJobStatus &out) {
  memdbg_scan_job_request_t query{};
  query.job_id = job_id;
  std::vector<uint8_t> response;
  int32_t payload_status = MEMDBG_OK;
  if (!client.raw_request(command, &query, sizeof(query), response,
                          payload_status) || payload_status != MEMDBG_OK)
    return false;
  memdbg_scan_job_status_response_t wire{};
  if (!read_object(response, wire) || wire.job_id != job_id)
    return false;
  out.bytes_done = wire.bytes_done;
  out.bytes_total = wire.bytes_total;
  out.results_found = wire.results_found;
  out.maps_done = wire.maps_done;
  out.maps_total = wire.maps_total;
  out.workers_active = wire.workers_active;
  out.workers_total = wire.workers_total;
  out.read_errors = wire.read_errors;
  out.state = wire.state;
  return true;
}

bool Client::scan_job_status(uint64_t job_id, ScanJobStatus &out) {
  return scan_job_request(*this, MEMDBG_CMD_SCAN_JOB_STATUS, job_id, out);
}

bool Client::scan_job_cancel(uint64_t job_id, ScanJobStatus &out) {
  return scan_job_request(*this, MEMDBG_CMD_SCAN_JOB_CANCEL, job_id, out);
}

bool Client::scan_aob(const memdbg_scan_aob_request_t &request_body,
                      const std::vector<uint8_t> &pattern,
                      const std::vector<uint8_t> &mask, ScanResult &out) {
  size_t pat_len = pattern.size();
  if (pat_len != mask.size() || pat_len > 256U) {
    set_error("invalid AOB pattern/mask");
    return false;
  }
  std::vector<uint8_t> body;
  body.resize(sizeof(request_body) + pat_len + pat_len);
  memcpy(body.data(), &request_body, sizeof(request_body));
  memcpy(body.data() + sizeof(request_body), pattern.data(), pat_len);
  memcpy(body.data() + sizeof(request_body) + pat_len, mask.data(), pat_len);
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_AOB, body.data(),
               static_cast<uint32_t>(body.size()), response)) {
    return false;
  }
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
}

bool Client::scan_process_aob(
    const memdbg_scan_process_aob_request_t &request_body,
    const std::vector<uint8_t> &pattern,
    const std::vector<uint8_t> &mask, ScanResult &out) {
  size_t pat_len = pattern.size();
  if (pat_len != mask.size() || pat_len > 256U) {
    set_error("invalid AOB pattern/mask");
    return false;
  }
  std::vector<uint8_t> body;
  body.resize(sizeof(request_body) + pat_len + pat_len);
  memcpy(body.data(), &request_body, sizeof(request_body));
  memcpy(body.data() + sizeof(request_body), pattern.data(), pat_len);
  memcpy(body.data() + sizeof(request_body) + pat_len, mask.data(), pat_len);
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_PROCESS_AOB, body.data(),
               static_cast<uint32_t>(body.size()), response)) {
    return false;
  }
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
}

bool Client::scan_pointer(const memdbg_scan_pointer_request_t &request_body,
                          ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_POINTER, &request_body, sizeof(request_body),
               response)) {
    return false;
  }
  /* Pointer scan returns memdbg_pointer_chain_entry_t (16 bytes),
   * extracting base_address at offset 0. */
  std::string error;
  const bool ok = parse_scan_response<memdbg_pointer_chain_entry_t>(
      response, out, error, offsetof(memdbg_pointer_chain_entry_t, base_address));
  if (!ok) set_error(error);
  return ok;
}

bool Client::telemetry(TelemetrySnapshot &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_TELEMETRY, nullptr, 0, response)) {
    return false;
  }

  memdbg_telemetry_response_t wire{};
  if (response.size() < sizeof(wire)) {
    set_error("short telemetry response");
    return false;
  }
  std::memcpy(&wire, response.data(), sizeof(wire));

  out.total_bytes_read    = wire.total_bytes_read;
  out.total_bytes_written = wire.total_bytes_written;
  out.total_read_calls    = wire.total_read_calls;
  out.total_write_calls   = wire.total_write_calls;
  out.uptime_seconds      = wire.uptime_seconds;
  out.active_connections  = wire.active_connections;
  out.thread_pool_size    = wire.thread_pool_size;
  out.scan_cache_hits     = wire.scan_cache_hits;
  out.scan_cache_misses   = wire.scan_cache_misses;
  return true;
}

bool Client::batch_read(int32_t pid,
                        const std::vector<memdbg_batch_read_item_t> &items,
                        BatchReadResult &out) {
  if (items.empty() || items.size() > MEMDBG_BATCH_READ_MAX_ITEMS) {
    set_error("batch_read: invalid item count");
    return false;
  }

  uint32_t count = static_cast<uint32_t>(items.size());
  memdbg_batch_read_request_t header{};
  header.pid   = pid;
  header.count = count;

  size_t body_len = sizeof(header) + count * sizeof(memdbg_batch_read_item_t);
  std::vector<uint8_t> body(body_len);
  memcpy(body.data(), &header, sizeof(header));
  memcpy(body.data() + sizeof(header), items.data(),
         count * sizeof(memdbg_batch_read_item_t));

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_BATCH_READ, body.data(),
               static_cast<uint32_t>(body_len), response)) {
    return false;
  }

  size_t results_size = count * sizeof(memdbg_batch_read_result_entry_t);
  if (response.size() < results_size) {
    set_error("batch_read: short response");
    return false;
  }

  out.entries.resize(count);
  memcpy(out.entries.data(), response.data(), results_size);

  /* Decompress data portion */
  std::vector<uint8_t> compressed_data(
      response.begin() + (ptrdiff_t)results_size, response.end());
  if (!maybe_decompress(compressed_data, out.data)) {
    set_error("batch_read: LZ4 decompression failed");
    return false;
  }

  return true;
}

bool Client::batch_write(int32_t pid,
                         const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> &items,
                         BatchWriteResult &out) {
  if (items.empty() || items.size() > MEMDBG_BATCH_WRITE_MAX_ITEMS) {
    set_error("batch_write: invalid item count");
    return false;
  }

  uint32_t count = static_cast<uint32_t>(items.size());

  /* Calculate total body size: header + items (with inline data) */
  size_t body_len = sizeof(memdbg_batch_write_request_t);
  for (const auto &item : items)
    body_len += sizeof(memdbg_batch_write_item_t) + item.second.size();

  std::vector<uint8_t> body(body_len);

  memdbg_batch_write_request_t header{};
  header.pid   = pid;
  header.count = count;
  memcpy(body.data(), &header, sizeof(header));

  uint8_t *cursor = body.data() + sizeof(header);
  for (const auto &item : items) {
    memdbg_batch_write_item_t witem{};
    witem.address = item.first;
    witem.length  = static_cast<uint32_t>(item.second.size());
    memcpy(cursor, &witem, sizeof(witem));
    cursor += sizeof(witem);
    if (!item.second.empty()) {
      memcpy(cursor, item.second.data(), item.second.size());
      cursor += item.second.size();
    }
  }

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_BATCH_WRITE, body.data(),
               static_cast<uint32_t>(body_len), response)) {
    return false;
  }

  size_t results_size = count * sizeof(memdbg_batch_write_result_entry_t);
  if (response.size() < results_size) {
    set_error("batch_write: short response");
    return false;
  }

  out.entries.resize(count);
  memcpy(out.entries.data(), response.data(), results_size);

  return true;
}

bool Client::scan_unknown(const memdbg_scan_unknown_request_t &request_body,
                          ScanResult &out) {
  std::vector<uint8_t> response;
  int32_t payload_status = MEMDBG_OK;
  if (!request(MEMDBG_CMD_SCAN_UNKNOWN_V2, &request_body,
               sizeof(request_body), response, &payload_status)) {
    if (payload_status != MEMDBG_ERR_UNSUPPORTED) return false;
    if (request_body.flags != 0U) {
      set_error("the payload does not support versioned unknown-scan filters");
      return false;
    }

    memdbg_scan_process_exact_request_t legacy{};
    legacy.pid = request_body.pid;
    legacy.value_type = request_body.value_type;
    legacy.value_length = request_body.value_length;
    legacy.alignment = request_body.alignment;
    legacy.max_results = request_body.max_results;
    legacy.protection_mask = request_body.protection_mask;
    legacy.start = request_body.start;
    legacy.end = request_body.end;
    if (!request(MEMDBG_CMD_SCAN_UNKNOWN, &legacy, sizeof(legacy), response))
      return false;
  }
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
}

bool Client::foreground_app(int32_t pid, char *title_id, size_t title_id_size,
                            char *content_id, size_t content_id_size,
                            char *name, size_t name_size, char *app_ver,
                            size_t app_ver_size) {
  (void)pid;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_FOREGROUND_APP, nullptr, 0, response))
    return false;
  memdbg_foreground_app_response_t app;
  if (response.size() < sizeof(app)) {
    set_error("short foreground app response");
    return false;
  }
  std::memcpy(&app, response.data(), sizeof(app));
  if (title_id) std::snprintf(title_id, title_id_size, "%s", app.title_id);
  if (content_id)
    std::snprintf(content_id, content_id_size, "%s", app.content_id);
  if (name) std::snprintf(name, name_size, "%s", app.name);
  if (app_ver) std::snprintf(app_ver, app_ver_size, "%s", app.app_ver);
  return true;
}

} // namespace memdbg::frontend

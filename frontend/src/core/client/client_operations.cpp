/*
 * MemDBG - Client operations (process, memory, kernel, console, klog).
 */
#include "client_internal.hpp"
#include "process_list_parser.hpp"
#include "process_maps_parser.hpp"

namespace memdbg::frontend {

bool Client::process_list(std::vector<ProcessEntry> &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_LIST, nullptr, 0, response)) {
    return false;
  }
  std::string parse_error;
  if (!detail::parse_process_list_response(response, out, parse_error)) {
    set_error(parse_error);
    return false;
  }
  return true;
}

bool Client::process_maps(int32_t pid, std::vector<MapEntry> &out) {
  memdbg_process_maps_request_t body{};
  body.pid = pid;

  std::vector<uint8_t> response;
  if (compressed_maps_support_.load() != 0) {
    int32_t payload_status = MEMDBG_OK;
    std::vector<uint8_t> framed;
    if (request(MEMDBG_CMD_PROCESS_MAPS_V2, &body, sizeof(body), framed,
                &payload_status)) {
      compressed_maps_support_.store(1);
      if (!maybe_decompress(framed, response)) {
        set_error("compressed map response could not be decompressed");
        return false;
      }
    } else if (payload_status == MEMDBG_ERR_UNSUPPORTED ||
               payload_status == MEMDBG_ERR_PROTOCOL) {
      /* Payloads predating the common unsupported-command response used
         ERR_PROTOCOL for unknown opcodes. Treat both as a V1 capability miss
         so a new desktop client remains compatible with deployed consoles. */
      compressed_maps_support_.store(0);
    } else {
      return false;
    }
  }
  if (compressed_maps_support_.load() == 0 &&
      !request(MEMDBG_CMD_PROCESS_MAPS, &body, sizeof(body), response)) {
    return false;
  }
  std::string parse_error;
  if (!detail::parse_process_maps_response(response, out, parse_error)) {
    set_error(parse_error);
    return false;
  }
  return true;
}

bool Client::process_info(int32_t pid, ProcessInfo &out) {
  memdbg_process_info_request_t body{};
  body.pid = pid;

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_INFO, &body, sizeof(body), response)) {
    return false;
  }

  memdbg_process_info_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short process info response");
    return false;
  }

  out.pid = wire.pid;
  out.name = fixed_string(wire.name, sizeof(wire.name));
  out.title_id = fixed_string(wire.title_id, sizeof(wire.title_id));
  out.content_id = fixed_string(wire.content_id, sizeof(wire.content_id));
  out.path = fixed_string(wire.path, sizeof(wire.path));
  return true;
}

bool Client::batch_process_info(const std::vector<int32_t> &pids,
                                std::vector<ProcessInfo> &out) {
  out.clear();
  if (pids.empty()) return true;
  if (pids.size() > 128U) {
    set_error("batch_process_info: too many PIDs (max 128)");
    return false;
  }

  uint32_t count = static_cast<uint32_t>(pids.size());
  size_t body_len = sizeof(memdbg_batch_process_info_request_t) +
                    count * sizeof(int32_t);
  std::vector<uint8_t> body(body_len);

  auto *hdr = reinterpret_cast<memdbg_batch_process_info_request_t *>(body.data());
  hdr->count = count;
  hdr->reserved = 0;
  auto *pid_buf = reinterpret_cast<int32_t *>(body.data() + sizeof(*hdr));
  for (uint32_t i = 0; i < count; ++i)
    pid_buf[i] = pids[i];

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_BATCH_PROCESS_INFO, body.data(),
               static_cast<uint32_t>(body_len), response))
    return false;

  if (response.size() < sizeof(memdbg_batch_process_info_response_t)) {
    set_error("batch_process_info: short response");
    return false;
  }

  auto *prefix = reinterpret_cast<const memdbg_batch_process_info_response_t *>(
      response.data());
  if (prefix->count != count) {
    set_error("batch_process_info: count mismatch");
    return false;
  }

  size_t expected = sizeof(*prefix) +
                    count * sizeof(memdbg_process_info_response_t);
  if (response.size() < expected) {
    set_error("batch_process_info: truncated response");
    return false;
  }

  auto *entries = reinterpret_cast<const memdbg_process_info_response_t *>(
      response.data() + sizeof(*prefix));
  out.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    ProcessInfo info;
    info.pid = entries[i].pid;
    info.name = fixed_string(entries[i].name, sizeof(entries[i].name));
    info.title_id = fixed_string(entries[i].title_id, sizeof(entries[i].title_id));
    info.content_id = fixed_string(entries[i].content_id, sizeof(entries[i].content_id));
    info.path = fixed_string(entries[i].path, sizeof(entries[i].path));
    out.push_back(std::move(info));
  }
  return true;
}

bool Client::memory_read(int32_t pid, uint64_t address, uint32_t length,
                         std::vector<uint8_t> &out) {
  memdbg_memory_request_t body{};
  body.pid = pid;
  body.address = address;
  body.length = length;
  std::vector<uint8_t> raw;
  if (!request(MEMDBG_CMD_MEMORY_READ, &body, sizeof(body), raw))
    return false;
  if (!maybe_decompress(raw, out)) {
    set_error("LZ4 decompression failed");
    return false;
  }
  return true;
}

bool Client::memory_write(int32_t pid, uint64_t address,
                          const std::vector<uint8_t> &data, uint32_t &written) {
  memdbg_memory_request_t header{};
  header.pid = pid;
  header.address = address;
  header.length = static_cast<uint32_t>(data.size());

  std::vector<uint8_t> body(sizeof(header) + data.size());
  std::memcpy(body.data(), &header, sizeof(header));
  if (!data.empty()) {
    std::memcpy(body.data() + sizeof(header), data.data(), data.size());
  }

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_MEMORY_WRITE, body.data(),
               static_cast<uint32_t>(body.size()), response)) {
    return false;
  }

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
  memcpy(&app, response.data(), sizeof(app));
  if (title_id)    std::snprintf(title_id, title_id_size, "%s", app.title_id);
  if (content_id)  std::snprintf(content_id, content_id_size, "%s", app.content_id);
  if (name)        std::snprintf(name, name_size, "%s", app.name);
  if (app_ver)     std::snprintf(app_ver, app_ver_size, "%s", app.app_ver);
  return true;
}

bool Client::process_stop(int32_t pid) {
  memdbg_process_control_request_t body;
  body.pid = pid;
  body.action = 1U;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_PROCESS_STOP, &body, sizeof(body), response);
}

bool Client::process_continue(int32_t pid) {
  memdbg_process_control_request_t body;
  body.pid = pid;
  body.action = 2U;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_PROCESS_CONTINUE, &body, sizeof(body), response);
}

bool Client::process_kill(int32_t pid) {
  memdbg_process_control_request_t body;
  body.pid = pid;
  body.action = 3U;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_PROCESS_KILL, &body, sizeof(body), response);
}

bool Client::process_protect(int32_t pid, uint64_t address, uint64_t length,
                             uint32_t protection,
                             ProcessProtectResult &out) {
  memdbg_process_protect_request_t body{};
  body.pid = pid;
  body.address = address;
  body.length = length;
  body.protection = protection;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_PROTECT, &body, sizeof(body), response))
    return false;
  memdbg_process_protect_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short process protect response");
    return false;
  }
  out.old_protection = wire.old_protection;
  out.new_protection = wire.new_protection;
  return true;
}

bool Client::process_alloc(int32_t pid, uint64_t hint, uint64_t length,
                           uint32_t protection, uint32_t flags,
                           ProcessAllocResult &out) {
  memdbg_process_alloc_request_t body{};
  body.pid = pid;
  body.hint = hint;
  body.length = length;
  body.protection = protection;
  body.flags = flags;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_ALLOC, &body, sizeof(body), response))
    return false;
  memdbg_process_alloc_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short process alloc response");
    return false;
  }
  out.address = wire.address;
  out.length = wire.length;
  return true;
}

bool Client::process_free(int32_t pid, uint64_t address, uint64_t length) {
  memdbg_process_free_request_t body{};
  body.pid = pid;
  body.address = address;
  body.length = length;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_PROCESS_FREE, &body, sizeof(body), response);
}

bool Client::process_elf_load(int32_t pid, const std::vector<uint8_t> &elf_data,
                              uint32_t flags, const std::string &target_region,
                              uint32_t match_flags,
                              ProcessElfLoadResult &out) {
  if (elf_data.empty() || elf_data.size() > (64ULL << 20)) {
    set_error("ELF data too large (max 64MB)");
    return false;
  }

  memdbg_process_elf_load_request_t req{};
  req.pid        = pid;
  req.flags      = flags;
  req.image_size = static_cast<uint64_t>(elf_data.size());
  req.match_flags = match_flags;
  if (!target_region.empty()) {
    size_t len = target_region.size();
    if (len >= sizeof(req.target_region)) len = sizeof(req.target_region) - 1;
    memcpy(req.target_region, target_region.c_str(), len);
    req.target_region[len] = '\0';
  }

  std::vector<uint8_t> body(sizeof(req) + elf_data.size());
  memcpy(body.data(), &req, sizeof(req));
  memcpy(body.data() + sizeof(req), elf_data.data(), elf_data.size());

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_ELF_LOAD, body.data(),
               static_cast<uint32_t>(body.size()), response))
    return false;

  memdbg_process_elf_load_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short ELF load response");
    return false;
  }
  out.entry_address = wire.entry_address;
  out.load_base     = wire.load_base;
  return true;
}

bool Client::process_hijack(int32_t pid, const std::vector<uint8_t> &elf_data,
                            uint32_t flags, const std::string &target_region,
                            uint32_t match_flags, bool &accepted) {
  accepted = false;
  if (elf_data.empty() || elf_data.size() > (64ULL << 20)) {
    set_error("ELF data too large (max 64MB)");
    return false;
  }

  memdbg_process_hijack_request_t req{};
  req.pid          = pid;
  req.flags        = flags;
  req.payload_size = static_cast<uint64_t>(elf_data.size());
  req.match_flags  = match_flags;
  if (!target_region.empty()) {
    size_t len = target_region.size();
    if (len >= sizeof(req.target_region)) len = sizeof(req.target_region) - 1;
    memcpy(req.target_region, target_region.c_str(), len);
    req.target_region[len] = '\0';
  }

  std::vector<uint8_t> body(sizeof(req) + elf_data.size());
  memcpy(body.data(), &req, sizeof(req));
  memcpy(body.data() + sizeof(req), elf_data.data(), elf_data.size());

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_HIJACK, body.data(),
               static_cast<uint32_t>(body.size()), response))
    return false;

  memdbg_process_hijack_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short hijack response");
    return false;
  }
  accepted = wire.accepted != 0U;
  return true;
}

bool Client::process_stack(const memdbg_process_stack_request_t &request_body,
                           std::vector<StackFrame> &out, bool &truncated) {
  out.clear();
  truncated = false;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_STACK, &request_body,
               sizeof(request_body), response)) {
    return false;
  }
  if (response.size() < sizeof(memdbg_process_stack_response_prefix_t)) {
    set_error("short stack response");
    return false;
  }
  const auto *prefix =
      reinterpret_cast<const memdbg_process_stack_response_prefix_t *>(
          response.data());
  if (prefix->entry_size != sizeof(memdbg_process_stack_frame_t)) {
    set_error("unsupported stack frame entry size");
    return false;
  }
  const size_t entries_size =
      static_cast<size_t>(prefix->count) * sizeof(memdbg_process_stack_frame_t);
  const size_t header_size = sizeof(*prefix);
  if (response.size() < header_size + entries_size ||
      response.size() < header_size + entries_size + prefix->data_size) {
    set_error("truncated stack response");
    return false;
  }
  const auto *entries =
      reinterpret_cast<const memdbg_process_stack_frame_t *>(
          response.data() + header_size);
  const uint8_t *blob = response.data() + header_size + entries_size;
  const size_t blob_size = prefix->data_size;
  out.reserve(prefix->count);
  for (uint32_t i = 0; i < prefix->count; ++i) {
    const auto &wire = entries[i];
    StackFrame frame;
    frame.frame_pointer = wire.frame_pointer;
    frame.saved_frame_pointer = wire.saved_frame_pointer;
    frame.return_address = wire.return_address;
    frame.stack_address = wire.stack_address;
    frame.code_address = wire.code_address;
    if (wire.stack_data_offset <= blob_size &&
        wire.stack_size <= blob_size - wire.stack_data_offset) {
      frame.stack_bytes.assign(blob + wire.stack_data_offset,
                               blob + wire.stack_data_offset + wire.stack_size);
    }
    if (wire.code_data_offset <= blob_size &&
        wire.code_size <= blob_size - wire.code_data_offset) {
      frame.code_bytes.assign(blob + wire.code_data_offset,
                              blob + wire.code_data_offset + wire.code_size);
    }
    out.push_back(std::move(frame));
  }
  truncated = prefix->truncated != 0U;
  return true;
}

bool Client::process_call(const memdbg_process_call_request_t &request_body,
                          memdbg_process_call_response_t &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_CALL, &request_body,
               sizeof(request_body), response))
    return false;
  return read_object(response, out);
}

/* ---- Klog streaming ---- */

bool Client::klog_connect(const std::string &host, uint16_t &klog_port) {
  std::lock_guard<std::mutex> lock(io_mutex_);

  /* Close any existing klog socket */
  if (platform::socket_valid(klog_fd_)) {
    platform::socket_close(klog_fd_);
    klog_fd_ = platform::invalid_socket();
  }

  if (!platform::socket_valid(fd_)) {
    set_error("not connected to payload");
    return false;
  }

  /* Send KLOG_CONNECT command on the main protocol socket */
  memdbg_klog_connect_request_t body{};
  body.reserved = 0;

  memdbg_packet_header_t header{};
  header.magic = MEMDBG_PACKET_MAGIC;
  header.version = MEMDBG_PROTOCOL_VERSION;
  header.command = MEMDBG_CMD_KLOG_CONNECT;
  header.request_id = next_request_id_++;
  header.length = sizeof(body);

  std::array<uint8_t, sizeof(header) + sizeof(body)> frame{};
  std::memcpy(frame.data(), &header, sizeof(header));
  std::memcpy(frame.data() + sizeof(header), &body, sizeof(body));
  if (!write_all(frame.data(), frame.size())) {
    return false;
  }

  memdbg_response_header_t response_header{};
  if (!read_exact(&response_header, sizeof(response_header))) {
    return false;
  }
  if (response_header.magic != MEMDBG_PACKET_MAGIC ||
      response_header.version != MEMDBG_PROTOCOL_VERSION ||
      response_header.command != MEMDBG_CMD_KLOG_CONNECT ||
      response_header.request_id != header.request_id) {
    set_error("invalid klog connect response header");
    return false;
  }
  if (response_header.status != 0) {
    std::ostringstream oss;
    oss << "klog connect: payload status " << response_header.status
        << " (" << payload_status_name(response_header.status) << ")";
    set_error(oss.str());
    return false;
  }
  if (response_header.length != sizeof(uint32_t)) {
    set_error("short klog connect response");
    return false;
  }

  uint32_t port = 0;
  if (!read_exact(&port, sizeof(port))) {
    return false;
  }
  klog_port = static_cast<uint16_t>(port);

  /* Open a secondary raw TCP connection for the klog stream */
  klog_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!platform::socket_valid(klog_fd_)) {
    set_error_from_errno("klog socket");
    klog_fd_ = platform::invalid_socket();
    return false;
  }

  (void)platform::socket_set_recv_timeout(klog_fd_, 100U); /* 100ms for background thread */
  (void)platform::socket_set_nosigpipe(klog_fd_);
  socket_set_keepalive(klog_fd_);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(klog_port);
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    set_error("invalid klog IPv4 address");
    platform::socket_close(klog_fd_);
    klog_fd_ = platform::invalid_socket();
    return false;
  }

  if (::connect(klog_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    set_error_from_errno("klog connect");
    platform::socket_close(klog_fd_);
    klog_fd_ = platform::invalid_socket();
    return false;
  }

  clear_error();

  /* Start background reader thread */
  klog_reader_closed_ = false;
  klog_reader_running_ = true;
  klog_reader_thread_ = std::thread(&Client::klog_reader_loop, this);

  return true;
}

void Client::klog_reader_loop() {
  uint8_t buf[4096];
  while (klog_reader_running_.load()) {
    int n = platform::socket_recv(klog_fd_, buf, sizeof(buf));
    if (n > 0) {
      std::vector<uint8_t> chunk(buf, buf + static_cast<size_t>(n));
      {
        std::lock_guard<std::mutex> lock(klog_buf_mutex_);
        klog_buf_.push_back(std::move(chunk));
      }
      klog_buf_cv_.notify_one();
    } else if (n == 0) {
      /* Connection closed */
      break;
    } else {
      int err = platform::socket_last_error_code();
      if (platform::socket_error_interrupted(err) ||
          platform::socket_error_would_block(err)) {
        /* No data yet, continue looping */
        continue;
      }
      /* Real error */
      break;
    }
  }
  klog_reader_closed_ = true;
  klog_buf_cv_.notify_all();
}

bool Client::klog_read(std::vector<uint8_t> &out) {
  out.clear();
  std::lock_guard<std::mutex> lock(klog_buf_mutex_);
  if (klog_buf_.empty()) {
    return !klog_reader_closed_.load();
  }
  out = std::move(klog_buf_.front());
  klog_buf_.pop_front();
  return true;
}

void Client::klog_disconnect() {
  klog_stop_reader();
  if (platform::socket_valid(klog_fd_)) {
    platform::socket_close(klog_fd_);
    klog_fd_ = platform::invalid_socket();
  }
}

void Client::klog_stop_reader() {
  klog_reader_running_ = false;
  if (klog_reader_thread_.joinable()) {
    klog_reader_thread_.join();
  }
  /* Drain remaining buffered data */
  {
    std::lock_guard<std::mutex> lock(klog_buf_mutex_);
    klog_buf_.clear();
  }
}

bool Client::klog_connected() const {
  return platform::socket_valid(klog_fd_) && !klog_reader_closed_.load();
}

bool Client::kernel_base(KernelBase &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_KERNEL_BASE, nullptr, 0, response))
    return false;
  memdbg_kernel_base_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short kernel base response");
    return false;
  }
  out.text_base = wire.text_base;
  out.data_base = wire.data_base;
  return true;
}

bool Client::kernel_read(uint64_t address, uint32_t length,
                         std::vector<uint8_t> &out) {
  memdbg_kernel_memory_request_t body{};
  body.address = address;
  body.length = length;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_KERNEL_READ, &body, sizeof(body), response))
    return false;
  out = std::move(response);
  return true;
}

bool Client::kernel_write(uint64_t address, const std::vector<uint8_t> &data) {
  if (data.size() > MEMDBG_PROTOCOL_MAX_READ) {
    set_error("kernel write payload too large");
    return false;
  }
  std::vector<uint8_t> payload(sizeof(memdbg_kernel_memory_request_t) +
                               data.size());
  auto *body = reinterpret_cast<memdbg_kernel_memory_request_t *>(payload.data());
  body->address = address;
  body->length = static_cast<uint32_t>(data.size());
  if (!data.empty())
    std::memcpy(payload.data() + sizeof(*body), data.data(), data.size());
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_KERNEL_WRITE, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::console_notify(const std::string &text) {
  if (text.size() > 4096U) {
    set_error("console notification text too long");
    return false;
  }
  std::vector<uint8_t> payload(sizeof(memdbg_console_text_request_t) +
                               text.size());
  auto *body = reinterpret_cast<memdbg_console_text_request_t *>(payload.data());
  body->length = static_cast<uint32_t>(text.size());
  body->reserved = 0;
  if (!text.empty())
    std::memcpy(payload.data() + sizeof(*body), text.data(), text.size());
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_CONSOLE_NOTIFY, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::console_print(const std::string &text) {
  if (text.size() > 4096U) {
    set_error("console print text too long");
    return false;
  }
  std::vector<uint8_t> payload(sizeof(memdbg_console_text_request_t) +
                               text.size());
  auto *body = reinterpret_cast<memdbg_console_text_request_t *>(payload.data());
  body->length = static_cast<uint32_t>(text.size());
  body->reserved = 0;
  if (!text.empty())
    std::memcpy(payload.data() + sizeof(*body), text.data(), text.size());
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_CONSOLE_PRINT, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::console_reboot() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_CONSOLE_REBOOT, nullptr, 0, response);
}

bool Client::process_dump(int32_t pid, uint32_t flags, std::string &json_out) {
  memdbg_process_dump_request_t body{};
  body.pid = pid;
  body.flags = flags;

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_DUMP, &body, sizeof(body), response))
    return false;

  json_out.assign(reinterpret_cast<const char *>(response.data()), response.size());
  return true;
}


} // namespace memdbg::frontend

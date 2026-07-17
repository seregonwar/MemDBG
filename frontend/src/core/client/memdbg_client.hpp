/*
 * MemDBG - ImGui frontend client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_CLIENT_HPP
#define MEMDBG_FRONTEND_CLIENT_HPP

#include "memdbg/core/memdbg_protocol.h"
#include "platform.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace memdbg::frontend {

struct ProcessEntry {
  int32_t pid = 0;
  int32_t ppid = 0;
  std::string name;
};

struct MapEntry {
  uint64_t start = 0;
  uint64_t end = 0;
  uint32_t protection = 0;
  uint32_t flags = 0;
  std::string name;
  std::string type;
};

struct ProcessInfo {
  int32_t pid = 0;
  std::string name;
  std::string title_id;
  std::string content_id;
  std::string path;
};

struct HelloInfo {
  uint16_t protocol_version = 0;
  uint16_t platform_id = 0;
  uint32_t capabilities = 0;
  uint16_t debug_port = 0;
  uint16_t udp_log_port = 0;
  std::string version;
  std::string name;
};

struct ScanResult {
  uint32_t count = 0;
  bool truncated = false;
  uint64_t bytes_scanned = 0;
  uint64_t elapsed_ns = 0;
  uint32_t read_calls = 0;
  uint32_t regions_scanned = 0;
  uint32_t read_errors = 0;
  std::vector<uint64_t> addresses;
};

class Client {
public:
  Client();
  ~Client();

  Client(const Client &) = delete;
  Client &operator=(const Client &) = delete;

  bool connect_to(const std::string &host, uint16_t port,
                  uint32_t timeout_ms = 5000U);
  void set_socket_timeout_ms(uint32_t ms);
  void cancel_pending_io();
  void disconnect();
  platform::socket_handle_t release_fd();      /* Release fd ownership for async transfer */
  void take_fd(platform::socket_handle_t fd);  /* Adopt a connected fd from async transfer */
  bool connected() const;
  const std::string &last_error() const;

  bool hello(HelloInfo &out);
  bool ping();
  bool shutdown_payload();
  bool process_list(std::vector<ProcessEntry> &out);
  bool process_maps(int32_t pid, std::vector<MapEntry> &out);
  bool process_info(int32_t pid, ProcessInfo &out);
  bool batch_process_info(const std::vector<int32_t> &pids,
                          std::vector<ProcessInfo> &out);
  bool memory_read(int32_t pid, uint64_t address, uint32_t length,
                   std::vector<uint8_t> &out);
  bool memory_write(int32_t pid, uint64_t address,
                    const std::vector<uint8_t> &data, uint32_t &written);
  bool scan_exact(const memdbg_scan_exact_request_t &request, ScanResult &out);
  bool scan_process_exact(const memdbg_scan_process_exact_request_t &request,
                          ScanResult &out);
  bool scan_aob(const memdbg_scan_aob_request_t &request,
                const std::vector<uint8_t> &pattern,
                const std::vector<uint8_t> &mask, ScanResult &out);
  bool scan_process_aob(const memdbg_scan_process_aob_request_t &request,
                        const std::vector<uint8_t> &pattern,
                        const std::vector<uint8_t> &mask, ScanResult &out);
  bool scan_pointer(const memdbg_scan_pointer_request_t &request,
                    ScanResult &out);
  bool scan_unknown(const memdbg_scan_unknown_request_t &request,
                    ScanResult &out);

  /* Batch read — up to 64 addresses in one request.
     Items: array of (address, length).
     Response: results[i] = (address, length, status), data = concatenated bytes.
     Caller parses data using results[i].length offsets. */
  struct BatchReadResult {
    std::vector<memdbg_batch_read_result_entry_t> entries;
    std::vector<uint8_t> data;
  };
  bool batch_read(int32_t pid,
                  const std::vector<memdbg_batch_read_item_t> &items,
                  BatchReadResult &out);

  /* Batch write — up to 64 (address, data) pairs in one request.
     Items: vector of {address, data_bytes}.
     Response: results[i] = {address, written, status} for each item. */
  struct BatchWriteResult {
    std::vector<memdbg_batch_write_result_entry_t> entries;
  };
  bool batch_write(int32_t pid,
                   const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> &items,
                   BatchWriteResult &out);

  struct TelemetrySnapshot {
    uint64_t total_bytes_read = 0;
    uint64_t total_bytes_written = 0;
    uint64_t total_read_calls = 0;
    uint64_t total_write_calls = 0;
    uint64_t uptime_seconds = 0;
    uint32_t active_connections = 0;
    uint32_t thread_pool_size = 0;
    uint32_t scan_cache_hits = 0;
    uint32_t scan_cache_misses = 0;
  };
  bool telemetry(TelemetrySnapshot &out);

  bool foreground_app(int32_t pid, char *title_id, size_t title_id_size,
                      char *content_id, size_t content_id_size,
                      char *name, size_t name_size, char *app_ver,
                      size_t app_ver_size);
  bool process_stop(int32_t pid);
  bool process_continue(int32_t pid);
  bool process_kill(int32_t pid);
  struct ProcessProtectResult {
    uint32_t old_protection = 0;
    uint32_t new_protection = 0;
  };
  struct ProcessAllocResult {
    uint64_t address = 0;
    uint64_t length = 0;
  };
  struct StackFrame {
    uint64_t frame_pointer = 0;
    uint64_t saved_frame_pointer = 0;
    uint64_t return_address = 0;
    uint64_t stack_address = 0;
    uint64_t code_address = 0;
    std::vector<uint8_t> stack_bytes;
    std::vector<uint8_t> code_bytes;
  };
  struct KernelBase {
    uint64_t text_base = 0;
    uint64_t data_base = 0;
  };
  bool process_protect(int32_t pid, uint64_t address, uint64_t length,
                       uint32_t protection, ProcessProtectResult &out);
  bool process_alloc(int32_t pid, uint64_t hint, uint64_t length,
                     uint32_t protection, uint32_t flags,
                     ProcessAllocResult &out);
  bool process_free(int32_t pid, uint64_t address, uint64_t length);
  struct ProcessElfLoadResult {
    uint64_t entry_address = 0;
    uint64_t load_base = 0;
  };
  bool process_elf_load(int32_t pid, const std::vector<uint8_t> &elf_data,
                        uint32_t flags, const std::string &target_region,
                        uint32_t match_flags, ProcessElfLoadResult &out);
  bool process_hijack(int32_t pid, const std::vector<uint8_t> &elf_data,
                      uint32_t flags, const std::string &target_region,
                      uint32_t match_flags, bool &accepted);
  bool process_stack(const memdbg_process_stack_request_t &request,
                     std::vector<StackFrame> &out, bool &truncated);
  bool process_call(const memdbg_process_call_request_t &request,
                    memdbg_process_call_response_t &out);
  bool process_dump(int32_t pid, uint32_t flags, std::string &json_out);

  /* ---- Klog streaming (secondary raw TCP connection) ---- */
  bool klog_connect(const std::string &host, uint16_t &klog_port);
  /* Non-blocking: drains buffered data from the background reader thread.
     Returns true if the klog connection is still alive, false if closed/error.
     out is filled with available bytes (may be empty if none ready). */
  bool klog_read(std::vector<uint8_t> &out);
  void klog_disconnect();
  bool klog_connected() const;
  void klog_stop_reader();

  bool kernel_base(KernelBase &out);
  bool kernel_read(uint64_t address, uint32_t length,
                   std::vector<uint8_t> &out);
  bool kernel_write(uint64_t address, const std::vector<uint8_t> &data);
  bool console_notify(const std::string &text);
  bool console_print(const std::string &text);
  bool console_reboot();

  /* ---- Debugger ---- */
  struct DebugThreadEntry {
    int32_t lwp = 0;
    uint32_t state = 0; /* memdbg_thread_state_t */
    memdbg_thread_stop_info_t stop_info{}; /* granular PT_LWPINFO data */
    int32_t priority = 0;     /* scheduling priority */
    uint64_t runtime_us = 0;  /* accumulated CPU time in microseconds */
    int32_t pctcpu = 0;       /* recent CPU utilisation 0..10000 */
    int32_t cpu_id = -1;      /* last CPU core index, -1 = n/a */
    std::string name;
  };
  struct DebugRegs {
    memdbg_debug_regs_t regs{};
  };
  struct DebugDbregs {
    memdbg_debug_dbregs_t dbregs{};
  };
  struct DebugFpregs {
    memdbg_debug_fpregs_t fpregs{};
  };
  struct DebugFsGsBase {
    memdbg_debug_fsgsbase_t base{};
  };
  struct DebugBreakpointEntry {
    uint64_t address = 0;
    uint32_t kind = 0;          /* 0 = sw, 1 = hw */
    bool installed = false;
    bool active = false;
    uint32_t cond_reg = 0;      /* memdbg_bp_cond_reg_t, 0 = none */
    uint32_t cond_op = 0;       /* memdbg_bp_cond_op_t */
    uint64_t cond_value = 0;
  };
  struct DebugWatchpointEntry {
    uint64_t address = 0;
    uint32_t length = 0;
    uint32_t type = 0;    /* 0=exec, 1=write, 2=read, 3=rw */
    uint32_t slot = 0;
    bool installed = false;
  };

  bool debug_attach(int32_t pid);
  bool debug_detach();
  bool debug_stop();
  bool debug_continue();
  bool debug_step(int32_t lwp);
  bool debug_get_threads(std::vector<DebugThreadEntry> &out);
  bool debug_get_regs(int32_t lwp, DebugRegs &out);
  bool debug_set_regs(int32_t lwp, const DebugRegs &in);
  bool debug_get_dbregs(int32_t lwp, DebugDbregs &out);
  bool debug_set_dbregs(int32_t lwp, const DebugDbregs &in);
  bool debug_get_fpregs(int32_t lwp, DebugFpregs &out);
  bool debug_set_fpregs(int32_t lwp, const DebugFpregs &in);
  bool debug_get_fsgsbase(int32_t lwp, DebugFsGsBase &out);
  bool debug_set_fsgsbase(int32_t lwp, const DebugFsGsBase &in);
  bool debug_set_breakpoint(uint64_t address, uint32_t kind);
  bool debug_set_breakpoint_cond(uint64_t address, uint32_t kind,
                                 uint32_t cond_reg, uint32_t cond_op,
                                 uint64_t cond_value);
  bool debug_clear_breakpoint(uint64_t address);
  bool debug_set_watchpoint(uint64_t address, uint32_t length, uint32_t type);
  bool debug_clear_watchpoint(uint64_t address);
  bool debug_suspend_thread(int32_t lwp);
  bool debug_resume_thread(int32_t lwp);
  bool debug_clear_all_breakpoints(uint32_t &cleared);
  bool debug_clear_all_watchpoints(uint32_t &cleared);
  bool debug_get_breakpoints(std::vector<DebugBreakpointEntry> &out);
  bool debug_get_watchpoints(std::vector<DebugWatchpointEntry> &out);
  bool debug_poll_events(bool &stopped, int32_t &stop_lwp);

  /* ---- Tracer ---- */
  struct TracerEvent {
    uint64_t timestamp_ns = 0;
    uint32_t event_type = 0;
    uint32_t lwp = 0;
    uint32_t syscall_no = 0;
    int32_t  syscall_ret = 0;
    uint64_t args[6]{};
    int32_t  signal = 0;
    uint64_t fault_addr = 0;
  };
  struct TracerStatus {
    int32_t  state = 0;          /* MEMDBG_TRACER_STATE_* */
    uint32_t events_total = 0;
    int32_t  crash_signal = 0;
    uint64_t start_time_ns = 0;
    uint64_t elapsed_ns = 0;
    std::string dump_path;
  };

  bool tracer_attach(int32_t pid);
  bool tracer_detach();
  bool tracer_poll(std::vector<TracerEvent> &out);
  bool tracer_status(TracerStatus &out);

  /* ---- Protocol pipelining ----
   *
   * Pipeline mode lets the client send N requests back-to-back without
   * waiting for responses, then read all N responses in one batch.
   * This eliminates N-1 round-trip delays when issuing multiple
   * independent operations (e.g. reading several memory regions).
   *
   * Usage:
   *   uint32_t r1 = client.pipeline_send(MEMDBG_CMD_MEMORY_READ, &req1, sizeof(req1));
   *   uint32_t r2 = client.pipeline_send(MEMDBG_CMD_MEMORY_READ, &req2, sizeof(req2));
   *   uint32_t r3 = client.pipeline_send(MEMDBG_CMD_TELEMETRY, nullptr, 0);
   *   if (!client.pipeline_flush()) { ... error ... }
   *   // Now call read_pipeline_response(r1), read_pipeline_response(r2), etc.
   *
   * The daemon processes requests sequentially on the same connection;
   * responses arrive in the same order they were sent.  request_id is
   * used to verify correct correlation. */

  /* Send a request without waiting for a response.
   * Returns the request_id for later correlation with pipeline_flush(). */
  uint32_t pipeline_send(uint16_t command, const void *payload,
                         uint32_t payload_len);

  /* Read all pending responses from pipelined requests.
   * Must be called exactly once for each batch of pipeline_send() calls.
   * Returns true if all responses were received and validated.
   * After flush(), use read_pipeline_response() to retrieve each result. */
  bool pipeline_flush();

  /* After a successful pipeline_flush(), retrieve the response body
   * for a specific request_id (as returned by pipeline_send()).
   * The response body includes the full raw bytes after the header.
   * Returns false if the request_id is not found or the request failed. */
  bool read_pipeline_response(uint32_t request_id,
                              std::vector<uint8_t> &response_body,
                              int32_t *out_status = nullptr);

  /* Number of requests sent via pipeline_send() that haven't been flushed yet. */
  size_t pipeline_pending() const { return pipeline_ids_.size(); }

  /* Discard all accumulated pipeline state without sending. */
  void pipeline_reset();

private:
  bool request(uint16_t command, const void *payload, uint32_t payload_len,
               std::vector<uint8_t> &response,
               int32_t *payload_status = nullptr);
  bool read_exact(void *data, size_t size);
  bool write_all(const void *data, size_t size);
  void disconnect_unlocked();
  void close_after_connection_loss();
  void set_error_from_errno(const std::string &prefix);
  void set_error(const std::string &message);

  std::atomic<platform::socket_handle_t> fd_{platform::invalid_socket()};
  platform::socket_handle_t klog_fd_ = platform::invalid_socket();
  bool socket_runtime_active_ = false;
  uint32_t next_request_id_ = 1;
  uint32_t socket_timeout_ms_ = 60000U;
  std::string last_error_;
  mutable std::mutex io_mutex_;
  std::atomic<bool> cancel_requested_{false};

  /* Pipeline state */
  static constexpr size_t kPipelineMaxBuffer = 1024U * 1024U; /* 1 MB auto-flush threshold */
  std::vector<uint8_t> pipeline_buffer_;
  std::vector<uint32_t> pipeline_ids_;
  std::unordered_map<uint32_t, std::vector<uint8_t>> pipeline_responses_;
  std::unordered_map<uint32_t, int32_t> pipeline_statuses_;

  /* Klog background reader */
  std::thread klog_reader_thread_;
  std::atomic<bool> klog_reader_running_{false};
  std::mutex klog_buf_mutex_;
  std::condition_variable klog_buf_cv_;
  std::deque<std::vector<uint8_t>> klog_buf_;
  std::atomic<bool> klog_reader_closed_{false};
  void klog_reader_loop();
};

std::string platform_name(uint16_t platform_id);
std::string capability_text(uint32_t capabilities);

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_CLIENT_HPP */

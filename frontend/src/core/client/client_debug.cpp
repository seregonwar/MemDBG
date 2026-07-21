/*
 * MemDBG - Client debugger and tracer operations.
 */
#include "client_internal.hpp"

namespace memdbg::frontend {

bool Client::debug_attach(int32_t pid) {
  memdbg_debug_attach_request_t body{pid, 0};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_ATTACH, &body, sizeof(body), response);
}

bool Client::debug_detach() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_DETACH, nullptr, 0, response);
}

bool Client::debug_stop() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_STOP, nullptr, 0, response);
}

bool Client::debug_continue() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_CONTINUE, nullptr, 0, response);
}

bool Client::debug_step(int32_t lwp) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_STEP, &body, sizeof(body), response);
}

bool Client::debug_get_threads(std::vector<DebugThreadEntry> &out) {
  out.clear();
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_THREADS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_threads_response_prefix_t)) {
    set_error("short thread list response");
    return false;
  }
  auto *prefix = reinterpret_cast<const memdbg_debug_threads_response_prefix_t *>(
      response.data());
  if (prefix->count == 0U) return true;

  const size_t body_size = response.size() - sizeof(*prefix);
  size_t entry_size = prefix->reserved;
  if (entry_size != sizeof(memdbg_debug_thread_entry_t) &&
      entry_size != kLegacyThreadEntryV1Size &&
      entry_size != kLegacyThreadEntryV2Size) {
    const size_t full_size = sizeof(memdbg_debug_thread_entry_t);
    if (prefix->count > 0U && body_size >= prefix->count * full_size) {
      entry_size = full_size;
    } else if (prefix->count > 0U &&
               body_size >= prefix->count * kLegacyThreadEntryV2Size) {
      entry_size = kLegacyThreadEntryV2Size;
    } else {
      entry_size = kLegacyThreadEntryV1Size;
    }
  }

  if (entry_size == 0U || body_size < entry_size) {
    set_error("empty thread list response");
    return false;
  }

  const size_t available_count = body_size / entry_size;
  const uint32_t count = static_cast<uint32_t>(
      available_count < prefix->count ? available_count : prefix->count);
  if (count == 0U && prefix->count != 0U) {
    set_error("truncated thread list response");
    return false;
  }

  const uint8_t *entries = response.data() + sizeof(*prefix);
  out.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    const uint8_t *entry = entries + static_cast<size_t>(i) * entry_size;
    DebugThreadEntry e;
    std::memcpy(&e.lwp, entry, sizeof(e.lwp));
    if (entry_size == sizeof(memdbg_debug_thread_entry_t)) {
      auto *full = reinterpret_cast<const memdbg_debug_thread_entry_t *>(entry);
      e.state = full->state;
      e.stop_info.pl_event = full->stop_info.pl_event;
      e.stop_info.stop_signal = full->stop_info.stop_signal;
      e.stop_info.pl_flags = full->stop_info.pl_flags;
      e.stop_info._pad = full->stop_info._pad;
      e.stop_info.pl_sigmask_lo = full->stop_info.pl_sigmask_lo;
      e.stop_info.pl_sigmask_hi = full->stop_info.pl_sigmask_hi;
      e.stop_info.pl_siglist_lo = full->stop_info.pl_siglist_lo;
      e.stop_info.pl_siglist_hi = full->stop_info.pl_siglist_hi;
      e.priority = full->priority;
      e.runtime_us = full->runtime_us;
      e.pctcpu = full->pctcpu;
      e.cpu_id = full->cpu_id;
      e.name.assign(full->name, strnlen(full->name, sizeof(full->name)));
    } else if (entry_size == kLegacyThreadEntryV2Size) {
      std::memcpy(&e.state, entry + sizeof(int32_t), sizeof(e.state));
      const char *name = reinterpret_cast<const char *>(entry + sizeof(int32_t) + sizeof(uint32_t));
      e.name.assign(name, strnlen(name, 24U));
    } else {
      const char *name = reinterpret_cast<const char *>(entry + sizeof(int32_t));
      e.name.assign(name, strnlen(name, 24U));
    }
    out.push_back(std::move(e));
  }
  return true;
}

bool Client::debug_get_regs(int32_t lwp, DebugRegs &out) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_REGS, &body, sizeof(body), response))
    return false;
  if (response.size() < sizeof(memdbg_debug_regs_t)) {
    set_error("short regs response");
    return false;
  }
  std::memcpy(&out.regs, response.data(), sizeof(out.regs));
  return true;
}

bool Client::debug_set_regs(int32_t lwp, const DebugRegs &in) {
  std::vector<uint8_t> payload(sizeof(memdbg_debug_thread_request_t) +
                               sizeof(memdbg_debug_regs_t));
  auto *body = reinterpret_cast<memdbg_debug_thread_request_t *>(payload.data());
  body->pid = 0;
  body->lwp = lwp;
  std::memcpy(payload.data() + sizeof(*body), &in.regs, sizeof(in.regs));
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_REGS, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::debug_get_dbregs(int32_t lwp, DebugDbregs &out) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_DBREGS, &body, sizeof(body), response))
    return false;
  if (response.size() < sizeof(memdbg_debug_dbregs_t)) {
    set_error("short dbregs response");
    return false;
  }
  std::memcpy(&out.dbregs, response.data(), sizeof(out.dbregs));
  return true;
}

bool Client::debug_set_dbregs(int32_t lwp, const DebugDbregs &in) {
  std::vector<uint8_t> payload(sizeof(memdbg_debug_thread_request_t) +
                               sizeof(memdbg_debug_dbregs_t));
  auto *body = reinterpret_cast<memdbg_debug_thread_request_t *>(payload.data());
  body->pid = 0;
  body->lwp = lwp;
  std::memcpy(payload.data() + sizeof(*body), &in.dbregs, sizeof(in.dbregs));
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_DBREGS, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::debug_get_fpregs(int32_t lwp, DebugFpregs &out) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_FPREGS, &body, sizeof(body), response))
    return false;
  if (response.size() < sizeof(memdbg_debug_fpregs_t)) {
    set_error("short fpregs response");
    return false;
  }
  std::memcpy(&out.fpregs, response.data(), sizeof(out.fpregs));
  return true;
}

bool Client::debug_set_fpregs(int32_t lwp, const DebugFpregs &in) {
  std::vector<uint8_t> payload(sizeof(memdbg_debug_thread_request_t) +
                               sizeof(memdbg_debug_fpregs_t));
  auto *body = reinterpret_cast<memdbg_debug_thread_request_t *>(payload.data());
  body->pid = 0;
  body->lwp = lwp;
  std::memcpy(payload.data() + sizeof(*body), &in.fpregs, sizeof(in.fpregs));
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_FPREGS, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::debug_get_fsgsbase(int32_t lwp, DebugFsGsBase &out) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_FSGSBASE, &body, sizeof(body), response))
    return false;
  if (response.size() < sizeof(memdbg_debug_fsgsbase_t)) {
    set_error("short fs/gs base response");
    return false;
  }
  std::memcpy(&out.base, response.data(), sizeof(out.base));
  return true;
}

bool Client::debug_set_fsgsbase(int32_t lwp, const DebugFsGsBase &in) {
  std::vector<uint8_t> payload(sizeof(memdbg_debug_thread_request_t) +
                               sizeof(memdbg_debug_fsgsbase_t));
  auto *body = reinterpret_cast<memdbg_debug_thread_request_t *>(payload.data());
  body->pid = 0;
  body->lwp = lwp;
  std::memcpy(payload.data() + sizeof(*body), &in.base, sizeof(in.base));
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_FSGSBASE, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::debug_set_breakpoint(uint64_t address, uint32_t kind) {
  memdbg_debug_breakpoint_request_t body{address, kind, 0};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_BREAKPOINT, &body, sizeof(body), response);
}

bool Client::debug_set_breakpoint_cond(uint64_t address, uint32_t kind,
                                       uint32_t cond_reg, uint32_t cond_op,
                                       uint64_t cond_value) {
  memdbg_debug_breakpoint_cond_request_t body{address, kind, cond_reg,
                                               cond_op, 0, cond_value};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_BREAKPOINT_COND, &body, sizeof(body),
                 response);
}

bool Client::debug_clear_breakpoint(uint64_t address) {
  memdbg_debug_breakpoint_request_t body{address, 0, 0};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_CLEAR_BREAKPOINT, &body, sizeof(body), response);
}

bool Client::debug_set_watchpoint(uint64_t address, uint32_t length,
                                  uint32_t type) {
  memdbg_debug_watchpoint_request_t body{address, length, type};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_WATCHPOINT, &body, sizeof(body), response);
}

bool Client::debug_clear_watchpoint(uint64_t address) {
  memdbg_debug_watchpoint_request_t body{address, 0, 0};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_CLEAR_WATCHPOINT, &body, sizeof(body), response);
}

bool Client::debug_clear_all_breakpoints(uint32_t &cleared) {
  cleared = 0;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_CLEAR_ALL_BREAKPOINTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_clear_all_response_t)) {
    set_error("short clear-all-bp response");
    return false;
  }
  auto *resp = reinterpret_cast<const memdbg_debug_clear_all_response_t *>(
      response.data());
  cleared = resp->cleared;
  return true;
}

bool Client::debug_clear_all_watchpoints(uint32_t &cleared) {
  cleared = 0;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_CLEAR_ALL_WATCHPOINTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_clear_all_response_t)) {
    set_error("short clear-all-wp response");
    return false;
  }
  auto *resp = reinterpret_cast<const memdbg_debug_clear_all_response_t *>(
      response.data());
  cleared = resp->cleared;
  return true;
}

bool Client::debug_suspend_thread(int32_t lwp) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SUSPEND_THREAD, &body, sizeof(body), response);
}

bool Client::debug_resume_thread(int32_t lwp) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_RESUME_THREAD, &body, sizeof(body), response);
}

bool Client::debug_get_breakpoints(std::vector<DebugBreakpointEntry> &out) {
  out.clear();
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_BREAKPOINTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_breakpoint_list_prefix_t)) {
    set_error("short breakpoint list response");
    return false;
  }
  auto *prefix = reinterpret_cast<const memdbg_debug_breakpoint_list_prefix_t *>(
      response.data());
  size_t expected = sizeof(*prefix) +
                    prefix->count * sizeof(memdbg_debug_breakpoint_list_entry_t);
  if (response.size() < expected) {
    set_error("truncated breakpoint list response");
    return false;
  }
  auto *entries = reinterpret_cast<const memdbg_debug_breakpoint_list_entry_t *>(
      response.data() + sizeof(*prefix));
  out.reserve(prefix->count);
  for (uint32_t i = 0; i < prefix->count; ++i) {
    DebugBreakpointEntry e;
    e.address    = entries[i].address;
    e.kind       = entries[i].kind;
    e.installed  = (entries[i].flags & 1U) != 0;
    e.active     = (entries[i].flags & 2U) != 0;
    e.cond_reg   = entries[i].cond_reg;
    e.cond_op    = entries[i].cond_op;
    e.cond_value = entries[i].cond_value;
    out.push_back(e);
  }
  return true;
}

bool Client::debug_get_watchpoints(std::vector<DebugWatchpointEntry> &out) {
  out.clear();
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_WATCHPOINTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_watchpoint_list_prefix_t)) {
    set_error("short watchpoint list response");
    return false;
  }
  auto *prefix = reinterpret_cast<const memdbg_debug_watchpoint_list_prefix_t *>(
      response.data());
  size_t expected = sizeof(*prefix) +
                    prefix->count * sizeof(memdbg_debug_watchpoint_list_entry_t);
  if (response.size() < expected) {
    set_error("truncated watchpoint list response");
    return false;
  }
  auto *entries = reinterpret_cast<const memdbg_debug_watchpoint_list_entry_t *>(
      response.data() + sizeof(*prefix));
  out.reserve(prefix->count);
  for (uint32_t i = 0; i < prefix->count; ++i) {
    DebugWatchpointEntry e;
    e.address   = entries[i].address;
    e.length    = entries[i].length;
    e.type      = entries[i].type;
    e.slot      = entries[i].slot;
    e.installed = (entries[i].flags != 0);
    out.push_back(e);
  }
  return true;
}

bool Client::debug_poll_events(bool &stopped, int32_t &stop_lwp) {
  stopped = false;
  stop_lwp = 0;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_POLL_EVENTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_poll_response_t)) {
    set_error("short poll response");
    return false;
  }
  auto *resp = reinterpret_cast<const memdbg_debug_poll_response_t *>(response.data());
  stopped = resp->stopped != 0;
  stop_lwp = resp->stop_lwp;
  return true;
}

/* ---- Tracer ---- */

bool Client::tracer_attach(int32_t pid) {
  memdbg_tracer_attach_request_t req;
  req.pid = pid;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_TRACER_ATTACH, &req, sizeof(req), response);
}

bool Client::tracer_detach() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_TRACER_DETACH, nullptr, 0, response);
}

bool Client::tracer_poll(std::vector<TracerEvent> &out) {
  out.clear();
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_TRACER_POLL, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_tracer_poll_response_prefix_t))
    return true; /* no events, not an error */
  auto *pfx = reinterpret_cast<const memdbg_tracer_poll_response_prefix_t *>(response.data());
  uint32_t count = pfx->count;
  if (count == 0) return true;
  const auto *evs = reinterpret_cast<const memdbg_tracer_event_t *>(
      response.data() + sizeof(memdbg_tracer_poll_response_prefix_t));
  out.reserve(count);
  for (uint32_t i = 0; i < count; i++) {
    TracerEvent e;
    e.timestamp_ns = evs[i].timestamp_ns;
    e.event_type    = evs[i].event_type;
    e.lwp           = evs[i].lwp;
    e.syscall_no    = evs[i].syscall_no;
    e.syscall_ret   = evs[i].syscall_ret;
    e.signal        = evs[i].signal;
    e.fault_addr    = evs[i].fault_addr;
    for (int j = 0; j < 6; j++) e.args[j] = evs[i].args[j];
    out.push_back(e);
  }
  return true;
}

bool Client::tracer_status(TracerStatus &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_TRACER_STATUS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_tracer_status_response_t)) {
    set_error("short tracer status response");
    return false;
  }
  auto *st = reinterpret_cast<const memdbg_tracer_status_response_t *>(response.data());
  out.state        = st->state;
  out.events_total = st->events_total;
  out.crash_signal = st->crash_signal;
  out.start_time_ns = st->start_time_ns;
  out.elapsed_ns    = st->elapsed_ns;
  out.dump_path     = st->dump_path;
  return true;
}

} // namespace memdbg::frontend

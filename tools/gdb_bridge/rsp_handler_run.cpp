/*
 * MemDBG - GDB RSP execution and breakpoint handling.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rsp_handler.hpp"

#include "gdb_regs.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <thread>

namespace memdbg::gdb_bridge {

using namespace detail;

std::string RspHandler::handle_continue_or_step(bool step, RspConnection &conn, int32_t lwp) {
  if (!ensure_attached()) return err_packet(1);

  bool ok = false;
  if (step) {
    const int32_t tid = lwp != 0 ? lwp : current_thread();
    logf("debug_step lwp=%d", static_cast<int>(tid));
    ok = backend_.debug_step(tid);
  } else {
    logf("debug_continue");
    ok = backend_.debug_continue();
  }
  if (!ok) {
    logf("%s failed: %s", step ? "debug_step" : "debug_continue", backend_.last_error().c_str());
    return err_packet(1);
  }
  stop_reason_.clear();

  for (;;) {
    if (conn.poll_interrupt(50U)) {
      (void)backend_.debug_stop();
      bool stopped = false;
      int32_t stop_lwp = 0;
      (void)backend_.debug_poll_events(stopped, stop_lwp);
      if (stop_lwp != 0) stop_lwp_ = stop_lwp;
      stop_signal_ = 2U;
      (void)refresh_memory_maps();
      return stop_reply();
    }

    bool stopped = false;
    int32_t stop_lwp = 0;
    if (!backend_.debug_poll_events(stopped, stop_lwp)) { return err_packet(1); }
    if (stopped) {
      if (stop_lwp != 0) stop_lwp_ = stop_lwp;
      stop_signal_ = 5U;
      refresh_threads();
      for (const auto &thread : threads_) {
        if (thread.lwp == stop_lwp_ && thread.stop_info.stop_signal > 0 &&
            thread.stop_info.stop_signal <= 0xFF) {
          stop_signal_ = static_cast<uint8_t>(thread.stop_info.stop_signal);
          break;
        }
      }
      capture_stop_reason(stop_lwp_);
      general_thread_ = stop_lwp_;
      /* The target may have loaded or unloaded modules while it was running.
       * Keep range validation aligned with the new stopped state. */
      (void)refresh_memory_maps();
      return stop_reply();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

bool RspHandler::set_program_counter(uint64_t address) {
  memdbg::frontend::Client::DebugRegs regs;
  if (!backend_.debug_get_regs(current_thread(), regs)) return false;
  regs.regs.r_rip = static_cast<int64_t>(address);
  return backend_.debug_set_regs(current_thread(), regs);
}

bool RspHandler::kill_process(int32_t target_pid) {
  if (target_pid <= 1) return false;
  if (attached_) {
    if (target_pid != pid_ || !safe_detach()) return false;
  }
  if (!backend_.process_kill(target_pid)) {
    logf("process_kill failed for pid=%d: %s", static_cast<int>(target_pid),
         backend_.last_error().c_str());
    return false;
  }
  return true;
}

std::string RspHandler::handle_resume_packet(const std::string &packet, bool step,
                                             RspConnection &conn) {
  if (packet.empty()) return err_packet(1);
  const bool with_signal = packet[0] == 'C' || packet[0] == 'S';
  size_t address_begin = 1U;
  if (with_signal) {
    const size_t semi = packet.find(';', 1U);
    const size_t signal_end = semi == std::string::npos ? packet.size() : semi;
    uint64_t signal = 0U;
    if (!parse_hex_u64(packet, 1U, signal_end, signal) || signal > 0xFFU) return err_packet(1);
    if (semi == std::string::npos) return handle_continue_or_step(step, conn, continue_thread_);
    address_begin = semi + 1U;
  }

  if (address_begin < packet.size()) {
    uint64_t address = 0U;
    if (!parse_hex_u64(packet, address_begin, packet.size(), address) || !ensure_attached() ||
        !set_program_counter(address)) {
      return err_packet(1);
    }
  }
  return handle_continue_or_step(step, conn, continue_thread_);
}

std::string RspHandler::handle_breakpoint(const std::string &packet, bool enable) {
  /* Ztype,addr,kind  / ztype,addr,kind */
  if (!ensure_attached()) return err_packet(1);
  if (packet.size() < 5U) return err_packet(1);
  const char type = packet[1];
  const size_t comma1 = packet.find(',', 2U);
  if (comma1 == std::string::npos) return err_packet(1);
  size_t comma2 = packet.find(',', comma1 + 1U);
  if (comma2 == std::string::npos) comma2 = packet.size();
  uint64_t addr = 0U;
  uint64_t kind = 1U;
  if (!parse_hex_u64(packet, comma1 + 1U, comma2, addr)) return err_packet(1);
  if (comma2 < packet.size()) {
    if (!parse_hex_u64(packet, comma2 + 1U, packet.size(), kind)) return err_packet(1);
  }

  if (type == '0') {
    if (kind != 1U) return err_packet(0x22);
    if (enable) {
      if (!backend_.debug_set_breakpoint(addr, 0U)) return err_packet(1);
    } else {
      if (!backend_.debug_clear_breakpoint(addr)) return err_packet(1);
    }
    return "OK";
  }
  if (type == '1') {
    if (kind != 1U) return err_packet(0x22);
    if (enable) {
      if (!backend_.debug_set_breakpoint(addr, 1U)) return err_packet(1);
    } else {
      if (!backend_.debug_clear_breakpoint(addr)) return err_packet(1);
    }
    return "OK";
  }
  const int wtype = watch_type_from_z(type);
  if (wtype < 0) return std::string(); /* unsupported */
  if (kind > std::numeric_limits<uint32_t>::max()) return err_packet(0x22);
  const uint32_t length = kind == 0U ? 1U : static_cast<uint32_t>(kind);
  if (length != 1U && length != 2U && length != 4U && length != 8U) return err_packet(0x22);
  if (enable) {
    if (!backend_.debug_set_watchpoint(addr, length, static_cast<uint32_t>(wtype))) {
      return err_packet(1);
    }
  } else {
    if (!backend_.debug_clear_watchpoint(addr)) return err_packet(1);
  }
  return "OK";
}

std::string RspHandler::handle_v(const std::string &packet, RspConnection &conn) {
  if (packet.rfind("vAttach;", 0) == 0) {
    int32_t req_pid = 0, req_tid = 0;
    if (!parse_thread_id(packet.c_str() + 8, req_pid, req_tid)) {
      logf("vAttach: bad pid hex in '%s'", packet.c_str());
      return err_packet(1);
    }
    const int32_t attach_pid = req_pid > 0 ? req_pid : req_tid;
    if (attach_pid <= 1) return err_packet(1);
    logf("vAttach pid=0x%x (%d decimal)", static_cast<unsigned>(attach_pid),
         static_cast<int>(attach_pid));
    if (attached_ && pid_ == attach_pid) {
      logf("vAttach: reusing session for pid=%d", static_cast<int>(pid_));
      return stop_reply();
    }
    if (attached_) {
      logf("vAttach: switching from pid=%d", static_cast<int>(pid_));
      if (!safe_detach()) return err_packet(1);
    }
    pid_ = attach_pid;
    if (!backend_.debug_attach(pid_)) {
      logf("vAttach debug_attach failed: %s", backend_.last_error().c_str());
      return err_packet(1);
    }
    attached_ = true;
    refresh_threads();
    if (!threads_.empty()) {
      stop_lwp_ = threads_[0].lwp;
      general_thread_ = stop_lwp_;
    }
    (void)refresh_memory_maps();
    return stop_reply();
  }
  if (packet == "vCont?") { return "vCont;c;C;s;S"; }
  if (packet.rfind("vKill;", 0U) == 0U) {
    uint64_t requested_pid = 0U;
    if (!parse_hex_u64(packet, 6U, packet.size(), requested_pid) ||
        requested_pid > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
      return err_packet(1);
    }
    return kill_process(static_cast<int32_t>(requested_pid)) ? "OK" : err_packet(1);
  }
  if (packet.rfind("vCont;", 0) == 0) {
    /* MemDBG is all-stop: execute the first action, but validate every action
     * so malformed per-thread tails cannot be silently ignored. */
    char action = '\0';
    int32_t lwp = 0;
    size_t begin = 6U;
    while (begin < packet.size()) {
      const size_t end = packet.find(';', begin);
      const std::string spec =
        packet.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
      if (spec.empty()) return err_packet(1);
      const char candidate = spec[0];
      if (candidate != 'c' && candidate != 'C' && candidate != 's' && candidate != 'S') {
        return err_packet(1);
      }
      int32_t candidate_lwp = 0;
      const size_t colon = spec.find(':');
      const size_t action_arg_end = colon == std::string::npos ? spec.size() : colon;
      if (candidate == 'C' || candidate == 'S') {
        uint64_t signal = 0U;
        if (!parse_hex_u64(spec, 1U, action_arg_end, signal) || signal > 0xFFU) {
          return err_packet(1);
        }
      } else if (action_arg_end != 1U) {
        return err_packet(1);
      }
      if (colon != std::string::npos) {
        int32_t p_out = 0, t_out = 0;
        if (!parse_thread_id(spec.c_str() + colon + 1U, p_out, t_out) ||
            (p_out > 0 && p_out != pid_)) {
          return err_packet(1);
        }
        candidate_lwp = t_out > 0 ? t_out : 0;
      }
      if (action == '\0') {
        action = candidate;
        lwp = candidate_lwp;
      } else if (lwp == 0 && candidate_lwp > 0) {
        /* A thread-specific action overrides the all-thread default. */
        action = candidate;
        lwp = candidate_lwp;
      }
      if (end == std::string::npos) break;
      if (end + 1U == packet.size()) return err_packet(1);
      begin = end + 1U;
    }
    if (action == '\0') return err_packet(1);
    if (action == 'c' || action == 'C') { return handle_continue_or_step(false, conn, lwp); }
    if (action == 's' || action == 'S') { return handle_continue_or_step(true, conn, lwp); }
    return err_packet(1);
  }
  if (packet == "vMustReplyEmpty") return std::string();
  return std::string();
}

} // namespace memdbg::gdb_bridge

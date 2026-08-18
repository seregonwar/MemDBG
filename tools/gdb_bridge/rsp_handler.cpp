#include "rsp_handler.hpp"

#include "gdb_regs.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <utility>
namespace memdbg::gdb_bridge {

using namespace detail;

RspHandler::RspHandler(memdbg::frontend::Client &client, int32_t initial_pid,
                       bool fpregs_supported, bool verbose)
  : owned_backend_(make_client_rsp_backend(client, fpregs_supported)), backend_(*owned_backend_),
    pid_(initial_pid), verbose_(verbose) {}

RspHandler::RspHandler(RspBackend &backend, int32_t initial_pid, bool verbose)
  : backend_(backend), pid_(initial_pid), verbose_(verbose) {}

void RspHandler::logf(const char *fmt, ...) const {
  if (!verbose_ || fmt == nullptr) return;
  std::fputs("[gdb_bridge] ", stderr);
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(stderr, fmt, ap);
  va_end(ap);
  std::fputc('\n', stderr);
}

void RspHandler::log_rsp_command(const std::string &packet) const {
  if (!verbose_) return;
  const size_t limit = packet.size() < 96U ? packet.size() : 96U;
  std::string display;
  display.reserve(limit);
  for (size_t i = 0; i < limit; ++i) {
    const unsigned char c = static_cast<unsigned char>(packet[i]);
    if (c >= 0x20U && c <= 0x7EU) {
      display.push_back(static_cast<char>(c));
    } else {
      char escaped[5];
      std::snprintf(escaped, sizeof(escaped), "\\x%02x", c);
      display += escaped;
    }
  }
  logf("rsp <- %s%s (%zu bytes)", display.c_str(), packet.size() > limit ? "..." : "",
       packet.size());
}

bool RspHandler::safe_detach() {
  if (!attached_) return true;
  /* Stop before the payload restores software breakpoints.  PT_DETACH resumes
   * the process; continuing first races live code against INT3 removal. */
  if (!backend_.debug_stop()) { logf("pre-detach stop failed: %s", backend_.last_error().c_str()); }
  if (!backend_.debug_detach()) {
    logf("debug_detach failed: %s", backend_.last_error().c_str());
    return false;
  } else {
    logf("detached pid=%d", static_cast<int>(pid_));
  }
  attached_ = false;
  stop_lwp_ = 0;
  stop_signal_ = 5U;
  stop_reason_.clear();
  general_thread_ = 0;
  continue_thread_ = 0;
  threads_.clear();
  memory_maps_.clear();
  memory_maps_known_ = false;
  sw_breakpoints_.clear();
  return true;
}

void RspHandler::cleanup() { (void)safe_detach(); }

bool RspHandler::ensure_attached() {
  if (attached_) return true;
  if (pid_ <= 0) {
    logf("ensure_attached: no pid");
    return false;
  }
  logf("debug_attach pid=%d", static_cast<int>(pid_));
  if (!backend_.debug_attach(pid_)) {
    logf("debug_attach failed: %s", backend_.last_error().c_str());
    return false;
  }
  attached_ = true;
  refresh_threads();
  if (!threads_.empty()) {
    stop_lwp_ = threads_[0].lwp;
    general_thread_ = stop_lwp_;
  }
  (void)refresh_memory_maps();
  return true;
}

void RspHandler::refresh_threads() {
  threads_.clear();
  if (!attached_) return;
  (void)backend_.debug_get_threads(threads_);
}

bool RspHandler::refresh_memory_maps() {
  std::vector<memdbg::frontend::MapEntry> maps;
  if (!backend_.process_maps(pid_, maps)) {
    memory_maps_.clear();
    memory_maps_known_ = false;
    logf("process map refresh failed: %s", backend_.last_error().c_str());
    return false;
  }
  memory_maps_ = std::move(maps);
  memory_maps_known_ = true;
  return true;
}

int32_t RspHandler::current_thread() const {
  if (general_thread_ > 0) return general_thread_;
  if (stop_lwp_ > 0) return stop_lwp_;
  if (!threads_.empty() && threads_[0].lwp > 0) return threads_[0].lwp;
  return pid_ > 0 ? pid_ : 0;
}

std::string RspHandler::stop_reply() const {
  const int32_t tid = stop_lwp_ > 0 ? stop_lwp_ : current_thread();
  char signal[4];
  std::snprintf(signal, sizeof(signal), "T%02x", stop_signal_);
  std::string reply(signal);
  reply += stop_reason_;
  if (tid > 0) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "thread:%x;", static_cast<unsigned>(tid));
    reply += buf;
  }
  return reply;
}

void RspHandler::capture_stop_reason(int32_t lwp) {
  stop_reason_.clear();
  if (lwp <= 0) return;

  memdbg::frontend::Client::DebugDbregs dbregs;
  std::vector<memdbg::frontend::Client::DebugWatchpointEntry> entries;
  if (backend_.debug_get_dbregs(lwp, dbregs) && backend_.debug_get_watchpoints(entries)) {
    stop_reason_ = gdb_watchpoint_stop_field(dbregs.dbregs.dr[6], entries);
    if (!stop_reason_.empty()) return;
  }

  /* A software breakpoint traps with RIP one byte past the INT3.  Report the
   * standard 'swbreak' stop reason so IDA recognizes its own breakpoint hit
   * instead of surfacing a bare SIGTRAP. */
  memdbg::frontend::Client::DebugRegs regs;
  if (backend_.debug_get_regs(lwp, regs)) {
    const uint64_t rip = static_cast<uint64_t>(regs.regs.r_rip);
    if (rip != 0U && sw_breakpoints_.find(rip - 1U) != sw_breakpoints_.end()) {
      stop_reason_ = "swbreak:;";
    }
  }
}

std::string RspHandler::handle(const std::string &packet, RspConnection &conn) {
  if (packet.empty()) return std::string();
  log_rsp_command(packet);

  std::string reply;
  if (packet[0] == 'q' || packet[0] == 'Q') {
    reply = handle_query(packet, conn);
  } else if (packet[0] == 'v') {
    reply = handle_v(packet, conn);
  } else if (packet == "?") {
    if (!attached_ && pid_ > 0) {
      if (!ensure_attached())
        reply = "W00";
      else
        reply = stop_reply();
    } else {
      reply = attached_ ? stop_reply() : "W00";
    }
  } else {
    if (packet == "!") {
      /* extended mode — acknowledge */
      reply = "OK";
    } else if (packet[0] == 'H') {
      /* Hg / Hc */
      if (packet.size() < 3U) {
        reply = err_packet(1);
      } else {
        const char which = packet[1];
        int32_t req_pid = 0, req_tid = 0;
        if (!parse_thread_id(packet.c_str() + 2, req_pid, req_tid)) {
          reply = err_packet(1);
        } else {
          if (req_pid > 0 && pid_ > 0 && req_pid != pid_) {
            reply = err_packet(1);
          } else if (attached_ && req_tid > 0) {
            refresh_threads();
            const bool exists = req_tid == pid_ || std::any_of(threads_.begin(), threads_.end(),
                                                               [&](const auto &thread) {
                                                                 return thread.lwp == req_tid;
                                                               });
            if (!exists) {
              reply = err_packet(1);
            } else if (which == 'g') {
              general_thread_ = req_tid;
              reply = "OK";
            } else if (which == 'c') {
              continue_thread_ = req_tid;
              reply = "OK";
            } else {
              reply = std::string();
            }
          } else if (which == 'g') {
            general_thread_ = req_tid;
            reply = "OK";
          } else if (which == 'c') {
            continue_thread_ = req_tid;
            reply = "OK";
          } else {
            reply = std::string();
          }
        }
      }
    } else if (packet == "g") {
      reply = handle_read_all_registers();
    } else if (packet[0] == 'G') {
      reply = handle_write_all_registers(packet);
    } else if (packet[0] == 'p') {
      reply = handle_read_register(packet);
    } else if (packet[0] == 'P') {
      reply = handle_write_register(packet);
    } else if (packet[0] == 'm') {
      reply = handle_memory_read(packet);
    } else if (packet[0] == 'M') {
      reply = handle_memory_write(packet);
    } else if (packet[0] == 'X') {
      reply = handle_binary_memory_write(packet);
    } else if (packet[0] == 'c' || packet[0] == 'C') {
      reply = handle_resume_packet(packet, false, conn);
    } else if (packet[0] == 's' || packet[0] == 'S') {
      reply = handle_resume_packet(packet, true, conn);
    } else if (packet[0] == 'Z') {
      reply = handle_breakpoint(packet, true);
    } else if (packet[0] == 'z') {
      reply = handle_breakpoint(packet, false);
    } else if (packet[0] == 'D') {
      bool valid_detach = packet == "D";
      if (!valid_detach && packet.rfind("D;", 0U) == 0U) {
        uint64_t detach_pid = 0U;
        valid_detach = detail::parse_hex_u64(packet, 2U, packet.size(), detach_pid) &&
                       detach_pid == static_cast<uint64_t>(pid_);
      }
      reply = valid_detach && safe_detach() ? "OK" : err_packet(1);
    } else if (packet == "k") {
      reply = attached_ && kill_process(pid_) ? "OK" : err_packet(1);
    } else if (packet[0] == 'T') {
      refresh_threads();
      int32_t req_pid = 0, req_tid = 0;
      if (!parse_thread_id(packet.c_str() + 1, req_pid, req_tid)) {
        reply = err_packet(1);
      } else if (req_pid > 0 && req_pid != pid_) {
        reply = err_packet(1);
      } else {
        reply = err_packet(1);
        if (req_tid <= 0 && attached_) {
          reply = "OK";
        } else {
          for (const auto &t : threads_) {
            if (t.lwp == req_tid) {
              reply = "OK";
              break;
            }
          }
        }
      }
    } else {
      reply = std::string(); /* unsupported */
    }
  }

  if (verbose_) {
    if (reply.size() > 96U) {
      logf("rsp -> %.64s... (%zu bytes)", reply.c_str(), reply.size());
    } else {
      logf("rsp -> %s", reply.empty() ? "(empty)" : reply.c_str());
    }
  }
  return reply;
}

} // namespace memdbg::gdb_bridge

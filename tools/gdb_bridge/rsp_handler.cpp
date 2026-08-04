/*
 * MemDBG - RSP command dispatch onto MDBG Client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rsp_handler.hpp"

#include "gdb_regs.hpp"
#include "target_xml.h"

#include <cctype>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace memdbg::gdb_bridge {

namespace {

constexpr uint32_t kMemChunk = 0x10000U; /* 64 KiB per MEMORY_READ */

bool parse_hex_u64(const std::string &s, size_t begin, size_t end,
                   uint64_t &out) {
  if (begin >= end) return false;
  uint64_t value = 0U;
  for (size_t i = begin; i < end; ++i) {
    const char c = s[i];
    int n = -1;
    if (c >= '0' && c <= '9') n = c - '0';
    else if (c >= 'a' && c <= 'f') n = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') n = c - 'A' + 10;
    else return false;
    value = (value << 4U) | static_cast<uint64_t>(n);
  }
  out = value;
  return true;
}

bool parse_hex_u64(const char *s, uint64_t &out) {
  if (s == nullptr || *s == '\0') return false;
  char *end = nullptr;
  out = std::strtoull(s, &end, 16);
  return end != s;
}

std::string err_packet(int code) {
  char buf[8];
  std::snprintf(buf, sizeof(buf), "E%02x", code & 0xFF);
  return std::string(buf);
}

int watch_type_from_z(char kind) {
  /* MemDBG: 0=exec, 1=write, 2=read, 3=rw */
  switch (kind) {
  case '1': return 0; /* hardware exec -> exec watch / HW BP uses set_breakpoint */
  case '2': return 1;
  case '3': return 2;
  case '4': return 3;
  default: return -1;
  }
}

} // namespace

RspHandler::RspHandler(memdbg::frontend::Client &client, int32_t initial_pid,
                       bool verbose)
    : client_(client), pid_(initial_pid), verbose_(verbose) {}

void RspHandler::logf(const char *fmt, ...) const {
  if (!verbose_ || fmt == nullptr) return;
  std::fputs("[gdb_bridge] ", stderr);
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(stderr, fmt, ap);
  va_end(ap);
  std::fputc('\n', stderr);
}

void RspHandler::safe_detach() {
  if (!attached_) return;
  /* Resume before detach so the console process is not left stopped. */
  if (!client_.debug_continue()) {
    logf("pre-detach continue failed: %s", client_.last_error().c_str());
  }
  if (!client_.debug_detach()) {
    logf("debug_detach failed: %s", client_.last_error().c_str());
  } else {
    logf("detached pid=%d", static_cast<int>(pid_));
  }
  attached_ = false;
  stop_lwp_ = 0;
  general_thread_ = 0;
  continue_thread_ = 0;
  threads_.clear();
}

void RspHandler::cleanup() { safe_detach(); }

bool RspHandler::ensure_attached() {
  if (attached_) return true;
  if (pid_ <= 0) {
    logf("ensure_attached: no pid");
    return false;
  }
  logf("debug_attach pid=%d", static_cast<int>(pid_));
  if (!client_.debug_attach(pid_)) {
    logf("debug_attach failed: %s", client_.last_error().c_str());
    return false;
  }
  attached_ = true;
  refresh_threads();
  if (!threads_.empty()) {
    stop_lwp_ = threads_[0].lwp;
    general_thread_ = stop_lwp_;
  }
  return true;
}

void RspHandler::refresh_threads() {
  threads_.clear();
  if (!attached_) return;
  (void)client_.debug_get_threads(threads_);
}

int32_t RspHandler::current_thread() const {
  if (general_thread_ != 0) return general_thread_;
  if (stop_lwp_ != 0) return stop_lwp_;
  if (!threads_.empty()) return threads_[0].lwp;
  return 0;
}

std::string RspHandler::stop_reply() const {
  const int32_t tid = stop_lwp_ != 0 ? stop_lwp_ : current_thread();
  char buf[64];
  if (tid != 0) {
    std::snprintf(buf, sizeof(buf), "T05thread:%x;",
                  static_cast<unsigned>(tid));
  } else {
    std::snprintf(buf, sizeof(buf), "S05");
  }
  return std::string(buf);
}

std::string RspHandler::qxfer_features(const std::string &annex, size_t offset,
                                       size_t length) const {
  if (annex != "target.xml") return err_packet(1);
  const std::string xml(kMemdbgGdbTargetXml);
  if (offset >= xml.size()) return "l";
  const size_t avail = xml.size() - offset;
  const size_t n = length < avail ? length : avail;
  const bool last = offset + n >= xml.size();
  std::string out;
  out.push_back(last ? 'l' : 'm');
  out.append(xml, offset, n);
  return out;
}

std::string RspHandler::qxfer_memory_map(size_t offset, size_t length) {
  if (!ensure_attached()) return err_packet(1);
  std::vector<memdbg::frontend::MapEntry> maps;
  if (!client_.process_maps(pid_, maps)) return err_packet(1);

  std::string xml = "<?xml version=\"1.0\"?>"
                    "<!DOCTYPE memory-map PUBLIC "
                    "\"+//IDN gnu.org/DTD GDB Memory Map V1.0//EN\" "
                    "\"http://sourceware.org/gdb/gdb-memory-map.dtd\">"
                    "<memory-map>";
  for (const auto &m : maps) {
    if (m.end <= m.start) continue;
    const uint64_t len = m.end - m.start;
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "<memory type=\"ram\" start=\"0x%llx\" length=\"0x%llx\"/>",
                  static_cast<unsigned long long>(m.start),
                  static_cast<unsigned long long>(len));
    xml += buf;
  }
  xml += "</memory-map>";

  if (offset >= xml.size()) return "l";
  const size_t avail = xml.size() - offset;
  const size_t n = length < avail ? length : avail;
  const bool last = offset + n >= xml.size();
  std::string out;
  out.push_back(last ? 'l' : 'm');
  out.append(xml, offset, n);
  return out;
}

std::string RspHandler::handle_continue_or_step(bool step, RspConnection &conn,
                                                 int32_t lwp) {
  if (!ensure_attached()) return err_packet(1);

  bool ok = false;
  if (step) {
    const int32_t tid = lwp != 0 ? lwp : current_thread();
    logf("debug_step lwp=%d", static_cast<int>(tid));
    ok = client_.debug_step(tid);
  } else {
    logf("debug_continue");
    ok = client_.debug_continue();
  }
  if (!ok) {
    logf("%s failed: %s", step ? "debug_step" : "debug_continue",
         client_.last_error().c_str());
    return err_packet(1);
  }

  for (;;) {
    if (conn.poll_interrupt(50U)) {
      (void)client_.debug_stop();
      bool stopped = false;
      int32_t stop_lwp = 0;
      (void)client_.debug_poll_events(stopped, stop_lwp);
      if (stop_lwp != 0) stop_lwp_ = stop_lwp;
      return "T02"; /* SIGINT */
    }

    bool stopped = false;
    int32_t stop_lwp = 0;
    if (!client_.debug_poll_events(stopped, stop_lwp)) {
      return err_packet(1);
    }
    if (stopped) {
      if (stop_lwp != 0) stop_lwp_ = stop_lwp;
      general_thread_ = stop_lwp_;
      return stop_reply();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

std::string RspHandler::handle_memory_read(const std::string &packet) {
  /* maddr,length */
  if (!ensure_attached()) return err_packet(1);
  const size_t comma = packet.find(',');
  if (comma == std::string::npos) return err_packet(1);
  uint64_t addr = 0U;
  uint64_t length = 0U;
  if (!parse_hex_u64(packet, 1U, comma, addr)) return err_packet(1);
  if (!parse_hex_u64(packet, comma + 1U, packet.size(), length))
    return err_packet(1);
  if (length == 0U) return std::string();
  if (length > 0x100000U) length = 0x100000U;

  std::string hex;
  hex.reserve(static_cast<size_t>(length) * 2U);
  uint64_t done = 0U;
  while (done < length) {
    uint32_t chunk = static_cast<uint32_t>(length - done);
    if (chunk > kMemChunk) chunk = kMemChunk;
    std::vector<uint8_t> data;
    if (!client_.memory_read(pid_, addr + done, chunk, data) ||
        data.size() != chunk) {
      return err_packet(1);
    }
    hex += bytes_to_hex(data.data(), data.size());
    done += chunk;
  }
  return hex;
}

std::string RspHandler::handle_memory_write(const std::string &packet) {
  /* Maddr,length:XX... */
  if (!ensure_attached()) return err_packet(1);
  const size_t comma = packet.find(',');
  const size_t colon = packet.find(':');
  if (comma == std::string::npos || colon == std::string::npos || colon < comma)
    return err_packet(1);
  uint64_t addr = 0U;
  uint64_t length = 0U;
  if (!parse_hex_u64(packet, 1U, comma, addr)) return err_packet(1);
  if (!parse_hex_u64(packet, comma + 1U, colon, length)) return err_packet(1);
  const std::string hex = packet.substr(colon + 1U);
  if (hex.size() != length * 2U) return err_packet(1);
  std::vector<uint8_t> data(static_cast<size_t>(length));
  if (length > 0U &&
      !hex_to_bytes(hex, data.data(), static_cast<size_t>(length))) {
    return err_packet(1);
  }
  uint32_t written = 0U;
  if (!client_.memory_write(pid_, addr, data, written) ||
      written != static_cast<uint32_t>(length)) {
    return err_packet(1);
  }
  return "OK";
}

std::string RspHandler::handle_breakpoint(const std::string &packet,
                                          bool enable) {
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
    (void)parse_hex_u64(packet, comma2 + 1U, packet.size(), kind);
  }
  (void)kind;

  if (type == '0') {
    if (enable) {
      if (!client_.debug_set_breakpoint(addr, 0U)) return err_packet(1);
    } else {
      if (!client_.debug_clear_breakpoint(addr)) return err_packet(1);
    }
    return "OK";
  }
  if (type == '1') {
    if (enable) {
      if (!client_.debug_set_breakpoint(addr, 1U)) return err_packet(1);
    } else {
      if (!client_.debug_clear_breakpoint(addr)) return err_packet(1);
    }
    return "OK";
  }
  const int wtype = watch_type_from_z(type);
  if (wtype < 0) return std::string(); /* unsupported */
  const uint32_t length = kind == 0U ? 1U : static_cast<uint32_t>(kind);
  if (enable) {
    if (!client_.debug_set_watchpoint(addr, length,
                                      static_cast<uint32_t>(wtype))) {
      return err_packet(1);
    }
  } else {
    if (!client_.debug_clear_watchpoint(addr)) return err_packet(1);
  }
  return "OK";
}

std::string RspHandler::handle_query(const std::string &packet,
                                     RspConnection &conn) {
  if (packet.rfind("qSupported", 0) == 0) {
    return "PacketSize=1048576;qXfer:features:read+;qXfer:memory-map:read+;"
           "swbreak+;hwbreak+;vContSupported+;QStartNoAckMode+";
  }
  if (packet == "QStartNoAckMode") {
    conn.set_no_ack(true);
    return "OK";
  }
  if (packet == "qAttached") return attached_ ? "1" : "0";
  if (packet.rfind("qAttached:", 0) == 0) return attached_ ? "1" : "0";
  if (packet == "qC") {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "QC%x",
                  static_cast<unsigned>(current_thread()));
    return std::string(buf);
  }
  if (packet == "qfThreadInfo") {
    refresh_threads();
    thread_info_started_ = true;
    if (threads_.empty()) return "l";
    std::string out = "m";
    for (size_t i = 0; i < threads_.size(); ++i) {
      if (i > 0U) out.push_back(',');
      char buf[16];
      std::snprintf(buf, sizeof(buf), "%x",
                    static_cast<unsigned>(threads_[i].lwp));
      out += buf;
    }
    return out;
  }
  if (packet == "qsThreadInfo") return "l";
  if (packet.rfind("qThreadExtraInfo,", 0) == 0) {
    uint64_t tid = 0U;
    if (!parse_hex_u64(packet.c_str() + std::strlen("qThreadExtraInfo,"), tid)) {
      return err_packet(1);
    }
    refresh_threads();
    for (const auto &t : threads_) {
      if (static_cast<uint64_t>(t.lwp) == tid) {
        return gdb_thread_extra_info_hex(t.lwp, t.name);
      }
    }
    logf("qThreadExtraInfo: unknown tid=0x%llx",
         static_cast<unsigned long long>(tid));
    return err_packet(1);
  }
  if (packet.rfind("qXfer:features:read:", 0) == 0) {
    /* qXfer:features:read:annex:offset,length */
    const std::string rest = packet.substr(std::strlen("qXfer:features:read:"));
    const size_t colon = rest.find(':');
    if (colon == std::string::npos) return err_packet(1);
    const std::string annex = rest.substr(0U, colon);
    const size_t comma = rest.find(',', colon + 1U);
    if (comma == std::string::npos) return err_packet(1);
    uint64_t offset = 0U;
    uint64_t length = 0U;
    if (!parse_hex_u64(rest, colon + 1U, comma, offset)) return err_packet(1);
    if (!parse_hex_u64(rest, comma + 1U, rest.size(), length))
      return err_packet(1);
    return qxfer_features(annex, static_cast<size_t>(offset),
                          static_cast<size_t>(length));
  }
  if (packet.rfind("qXfer:memory-map:read:", 0) == 0) {
    /* qXfer:memory-map:read::offset,length  (empty annex) */
    const std::string rest =
        packet.substr(std::strlen("qXfer:memory-map:read:"));
    const size_t colon = rest.find(':');
    if (colon == std::string::npos) return err_packet(1);
    const size_t comma = rest.find(',', colon + 1U);
    if (comma == std::string::npos) return err_packet(1);
    uint64_t offset = 0U;
    uint64_t length = 0U;
    if (!parse_hex_u64(rest, colon + 1U, comma, offset)) return err_packet(1);
    if (!parse_hex_u64(rest, comma + 1U, rest.size(), length))
      return err_packet(1);
    return qxfer_memory_map(static_cast<size_t>(offset),
                            static_cast<size_t>(length));
  }
  if (packet.rfind("qRcmd,", 0) == 0) {
    return "OK";
  }
  return std::string(); /* unsupported query */
}

std::string RspHandler::handle_v(const std::string &packet,
                                 RspConnection &conn) {
  if (packet.rfind("vAttach;", 0) == 0) {
    uint64_t pid = 0U;
    if (!parse_hex_u64(packet.c_str() + 8, pid) || pid == 0U) {
      logf("vAttach: bad pid hex in '%s'", packet.c_str());
      return err_packet(1);
    }
    const auto attach_pid = static_cast<int32_t>(pid);
    /* RSP vAttach pid is hexadecimal. IDA's PID field is hex too: decimal 88
     * typed as "88" becomes pid 0x88 = 136. */
    logf("vAttach pid=0x%x (%d decimal)", static_cast<unsigned>(attach_pid),
         static_cast<int>(attach_pid));
    if (attached_ && pid_ == attach_pid) {
      logf("vAttach: already attached to pid=%d", static_cast<int>(pid_));
      return stop_reply();
    }
    if (attached_) {
      logf("vAttach: switching from pid=%d", static_cast<int>(pid_));
      safe_detach();
    }
    pid_ = attach_pid;
    if (!client_.debug_attach(pid_)) {
      logf("vAttach debug_attach failed: %s", client_.last_error().c_str());
      return err_packet(1);
    }
    attached_ = true;
    refresh_threads();
    if (!threads_.empty()) {
      stop_lwp_ = threads_[0].lwp;
      general_thread_ = stop_lwp_;
    }
    return stop_reply();
  }
  if (packet == "vCont?") {
    return "vCont;c;C;s;S";
  }
  if (packet.rfind("vCont;", 0) == 0) {
    /* Support first action only (all-stop MVP). */
    const char action = packet.size() > 6U ? packet[6] : '\0';
    int32_t lwp = 0;
    const size_t colon = packet.find(':', 6U);
    if (colon != std::string::npos) {
      uint64_t tid = 0U;
      if (parse_hex_u64(packet, colon + 1U, packet.size(), tid)) {
        lwp = static_cast<int32_t>(tid);
      }
    }
    if (action == 'c' || action == 'C') {
      return handle_continue_or_step(false, conn, lwp);
    }
    if (action == 's' || action == 'S') {
      return handle_continue_or_step(true, conn, lwp);
    }
    return err_packet(1);
  }
  if (packet == "vMustReplyEmpty") return std::string();
  return std::string();
}

std::string RspHandler::handle(const std::string &packet, RspConnection &conn) {
  if (packet.empty()) return std::string();
  if (verbose_) {
    /* Truncate huge memory payloads in logs. */
    if (packet.size() > 96U &&
        (packet[0] == 'M' || packet[0] == 'X' || packet[0] == 'G')) {
      logf("rsp <- %.64s... (%zu bytes)", packet.c_str(), packet.size());
    } else {
      logf("rsp <- %s", packet.c_str());
    }
  }

  std::string reply;
  if (packet[0] == 'q' || packet[0] == 'Q') {
    reply = handle_query(packet, conn);
  } else if (packet[0] == 'v') {
    reply = handle_v(packet, conn);
  } else if (packet == "?") {
    if (!attached_ && pid_ > 0) {
      if (!ensure_attached()) reply = "W00";
      else reply = stop_reply();
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
        int32_t tid = 0;
        bool tid_ok = true;
        if (packet[2] == '-') {
          tid = -1;
        } else {
          uint64_t value = 0U;
          if (!parse_hex_u64(packet.c_str() + 2, value)) {
            tid_ok = false;
            reply = err_packet(1);
          } else {
            tid = static_cast<int32_t>(value);
          }
        }
        if (tid_ok) {
          if (which == 'g') {
            if (tid > 0) general_thread_ = tid;
            reply = "OK";
          } else if (which == 'c') {
            continue_thread_ = tid > 0 ? tid : 0;
            reply = "OK";
          } else {
            reply = std::string();
          }
        }
      }
    } else if (packet[0] == 'g') {
      if (!ensure_attached()) {
        reply = err_packet(1);
      } else {
        memdbg::frontend::Client::DebugRegs regs;
        if (!client_.debug_get_regs(current_thread(), regs)) {
          reply = err_packet(1);
        } else {
          memdbg::frontend::Client::DebugFpregs fpregs;
          const memdbg_debug_fpregs_t *fp = nullptr;
          if (client_.debug_get_fpregs(current_thread(), fpregs)) {
            fp = &fpregs.fpregs;
          }
          reply = gdb_encode_g_packet(regs.regs, fp);
        }
      }
    } else if (packet[0] == 'G') {
      if (!ensure_attached()) {
        reply = err_packet(1);
      } else {
        memdbg::frontend::Client::DebugRegs regs;
        if (!client_.debug_get_regs(current_thread(), regs)) {
          reply = err_packet(1);
        } else {
          memdbg::frontend::Client::DebugFpregs fpregs;
          (void)client_.debug_get_fpregs(current_thread(), fpregs);
          if (!gdb_decode_g_packet(packet.substr(1U), regs.regs, &fpregs.fpregs))
            reply = err_packet(1);
          else if (!client_.debug_set_regs(current_thread(), regs))
            reply = err_packet(1);
          else {
            if (fpregs.fpregs.length > 0U) {
              (void)client_.debug_set_fpregs(current_thread(), fpregs);
            }
            reply = "OK";
          }
        }
      }
    } else if (packet[0] == 'p') {
      if (!ensure_attached()) {
        reply = err_packet(1);
      } else {
        uint64_t regno = 0U;
        if (!parse_hex_u64(packet.c_str() + 1, regno) ||
            !gdb_reg_valid(static_cast<int>(regno))) {
          reply = err_packet(1);
        } else {
          const int ir = static_cast<int>(regno);
          const size_t size = gdb_reg_size(ir);
          if (gdb_reg_is_sse(ir)) {
            memdbg::frontend::Client::DebugFpregs fpregs;
            if (!client_.debug_get_fpregs(current_thread(), fpregs))
              reply = err_packet(1);
            else {
              uint8_t buf[16]{};
              if (!gdb_get_sse_bytes(fpregs.fpregs, ir, buf, sizeof(buf)))
                reply = err_packet(1);
              else
                reply = bytes_to_hex(buf, size);
            }
          } else {
            memdbg::frontend::Client::DebugRegs regs;
            if (!client_.debug_get_regs(current_thread(), regs)) {
              reply = err_packet(1);
            } else {
              uint64_t value = gdb_get_reg_value(regs.regs, ir);
              if (size == 4U) value &= 0xFFFFFFFFULL;
              reply = bytes_to_hex(&value, size);
            }
          }
        }
      }
    } else if (packet[0] == 'P') {
      if (!ensure_attached()) {
        reply = err_packet(1);
      } else {
        const size_t eq = packet.find('=');
        if (eq == std::string::npos) {
          reply = err_packet(1);
        } else {
          uint64_t regno = 0U;
          if (!parse_hex_u64(packet, 1U, eq, regno) ||
              !gdb_reg_valid(static_cast<int>(regno))) {
            reply = err_packet(1);
          } else {
            const int ir = static_cast<int>(regno);
            const size_t size = gdb_reg_size(ir);
            if (gdb_reg_is_sse(ir)) {
              uint8_t buf[16]{};
              if (!hex_to_bytes(packet.substr(eq + 1U), buf, size))
                reply = err_packet(1);
              else {
                memdbg::frontend::Client::DebugFpregs fpregs;
                (void)client_.debug_get_fpregs(current_thread(), fpregs);
                if (!gdb_set_sse_bytes(fpregs.fpregs, ir, buf, size))
                  reply = err_packet(1);
                else if (!client_.debug_set_fpregs(current_thread(), fpregs))
                  reply = err_packet(1);
                else
                  reply = "OK";
              }
            } else {
              uint64_t value = 0U;
              if (!hex_to_bytes(packet.substr(eq + 1U), &value, size))
                reply = err_packet(1);
              else {
                memdbg::frontend::Client::DebugRegs regs;
                if (!client_.debug_get_regs(current_thread(), regs))
                  reply = err_packet(1);
                else if (!gdb_set_reg_value(regs.regs, ir, value))
                  reply = err_packet(1);
                else if (!client_.debug_set_regs(current_thread(), regs))
                  reply = err_packet(1);
                else
                  reply = "OK";
              }
            }
          }
        }
      }
    } else if (packet[0] == 'm') {
      reply = handle_memory_read(packet);
    } else if (packet[0] == 'M') {
      reply = handle_memory_write(packet);
    } else if (packet[0] == 'c' || packet[0] == 'C') {
      reply = handle_continue_or_step(false, conn, continue_thread_);
    } else if (packet[0] == 's' || packet[0] == 'S') {
      reply = handle_continue_or_step(true, conn, continue_thread_);
    } else if (packet[0] == 'Z') {
      reply = handle_breakpoint(packet, true);
    } else if (packet[0] == 'z') {
      reply = handle_breakpoint(packet, false);
    } else if (packet[0] == 'D' || packet == "k") {
      safe_detach();
      reply = "OK";
    } else if (packet[0] == 'T') {
      refresh_threads();
      uint64_t tid = 0U;
      if (!parse_hex_u64(packet.c_str() + 1, tid)) {
        reply = err_packet(1);
      } else {
        reply = err_packet(1);
        for (const auto &t : threads_) {
          if (static_cast<uint64_t>(t.lwp) == tid) {
            reply = "OK";
            break;
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

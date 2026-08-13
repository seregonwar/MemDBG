/*
 * MemDBG - GDB RSP query and XML transfer handling.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rsp_handler.hpp"

#include "gdb_regs.hpp"
#include "target_xml.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace memdbg::gdb_bridge {

using namespace detail;

std::string RspHandler::qxfer_features(const std::string &annex, size_t offset,
                                       size_t length) const {
  if (annex != "target.xml") return err_packet(1);
  return qxfer_slice(kMemdbgGdbTargetXml, offset, length);
}

std::string RspHandler::qxfer_memory_map(size_t offset, size_t length) {
  if (!ensure_attached()) return err_packet(1);
  if ((offset == 0U || !memory_maps_known_) && !refresh_memory_maps()) return err_packet(1);

  std::string xml = "<?xml version=\"1.0\"?>"
                    "<!DOCTYPE memory-map PUBLIC "
                    "\"+//IDN gnu.org/DTD GDB Memory Map V1.0//EN\" "
                    "\"http://sourceware.org/gdb/gdb-memory-map.dtd\">"
                    "<memory-map>";
  for (const auto &m : memory_maps_) {
    if (m.end <= m.start) continue;
    const uint64_t len = m.end - m.start;
    char buf[128];
    std::snprintf(buf, sizeof(buf), "<memory type=\"ram\" start=\"0x%llx\" length=\"0x%llx\"/>",
                  static_cast<unsigned long long>(m.start), static_cast<unsigned long long>(len));
    xml += buf;
  }
  xml += "</memory-map>";

  return qxfer_slice(xml, offset, length);
}

std::string RspHandler::qxfer_threads(size_t offset, size_t length) {
  if (!ensure_attached()) return err_packet(1);
  if (offset == 0U) refresh_threads();
  std::string xml = "<?xml version=\"1.0\"?><threads>";
  if (threads_.empty() && pid_ > 0) {
    char buf[96];
    std::snprintf(buf, sizeof(buf), "<thread id=\"%x\" name=\"main (fallback)\"/>",
                  static_cast<unsigned>(pid_));
    xml += buf;
  } else {
    for (const auto &thread : threads_) {
      if (thread.lwp <= 0) continue;
      char buf[48];
      std::snprintf(buf, sizeof(buf), "<thread id=\"%x\" name=\"",
                    static_cast<unsigned>(thread.lwp));
      xml += buf;
      xml += xml_escape(thread.name.empty() ? "LWP " + std::to_string(thread.lwp) : thread.name);
      xml += "\"/>";
    }
  }
  xml += "</threads>";
  return qxfer_slice(xml, offset, length);
}

std::string RspHandler::qxfer_libraries(size_t offset, size_t length) {
  if (!ensure_attached()) return err_packet(1);
  if ((offset == 0U || !memory_maps_known_) && !refresh_memory_maps()) return err_packet(1);

  std::string xml = "<?xml version=\"1.0\"?><library-list>";
  std::vector<std::string> emitted;
  for (const auto &map : memory_maps_) {
    if (map.end <= map.start || map.name.empty() ||
        std::find(emitted.begin(), emitted.end(), map.name) != emitted.end()) {
      continue;
    }
    emitted.push_back(map.name);
    xml += "<library name=\"" + xml_escape(map.name) + "\">";
    for (const auto &segment : memory_maps_) {
      if (segment.name != map.name || segment.end <= segment.start) continue;
      char buf[64];
      std::snprintf(buf, sizeof(buf), "<segment address=\"0x%llx\"/>",
                    static_cast<unsigned long long>(segment.start));
      xml += buf;
    }
    xml += "</library>";
  }
  xml += "</library-list>";
  return qxfer_slice(xml, offset, length);
}

std::string RspHandler::qxfer_exec_file(size_t offset, size_t length) {
  if (!ensure_attached()) return err_packet(1);
  memdbg::frontend::ProcessInfo info;
  if (!backend_.process_info(pid_, info)) return err_packet(1);
  const std::string path = !info.path.empty() ? info.path : info.name;
  return qxfer_slice(path, offset, length);
}

std::string RspHandler::qxfer_osdata(const std::string &annex, size_t offset, size_t length) {
  if (annex != "processes") return err_packet(1);
  std::vector<memdbg::frontend::ProcessEntry> processes;
  if (!backend_.process_list(processes)) return err_packet(1);
  std::string xml = "<?xml version=\"1.0\"?><osdata type=\"processes\">";
  for (const auto &process : processes) {
    xml += "<item><column name=\"pid\">" + std::to_string(process.pid) +
           "</column><column name=\"ppid\">" + std::to_string(process.ppid) +
           "</column><column name=\"command\">" + xml_escape(process.name) + "</column></item>";
  }
  xml += "</osdata>";
  return qxfer_slice(xml, offset, length);
}

std::string RspHandler::memory_region_info(const std::string &packet) {
  static constexpr const char *kPrefix = "qMemoryRegionInfo:";
  if (!ensure_attached() || packet.rfind(kPrefix, 0U) != 0U) return err_packet(1);
  uint64_t address = 0U;
  if (!parse_hex_u64(packet.c_str() + std::strlen(kPrefix), address)) return err_packet(1);
  if (!memory_maps_known_ && !refresh_memory_maps()) return err_packet(1);

  for (const auto &map : memory_maps_) {
    if (map.start <= address && address < map.end) {
      std::string permissions;
      if ((map.protection & MEMDBG_MAP_PROT_READ) != 0U) permissions += 'r';
      if ((map.protection & MEMDBG_MAP_PROT_WRITE) != 0U) permissions += 'w';
      if ((map.protection & MEMDBG_MAP_PROT_EXEC) != 0U) permissions += 'x';
      char reply[128];
      std::snprintf(reply, sizeof(reply), "start:%llx;size:%llx;permissions:%s;",
                    static_cast<unsigned long long>(map.start),
                    static_cast<unsigned long long>(map.end - map.start), permissions.c_str());
      std::string out(reply);
      if (!map.name.empty()) out += "name:" + bytes_to_hex(map.name.data(), map.name.size()) + ";";
      return out;
    }
  }

  uint64_t next = std::numeric_limits<uint64_t>::max();
  for (const auto &map : memory_maps_) {
    if (map.start > address && map.start < next) next = map.start;
  }
  const uint64_t size = next == std::numeric_limits<uint64_t>::max()
                          ? std::numeric_limits<uint64_t>::max() - address
                          : next - address;
  char reply[96];
  std::snprintf(reply, sizeof(reply), "start:%llx;size:%llx;permissions:;",
                static_cast<unsigned long long>(address), static_cast<unsigned long long>(size));
  return std::string(reply);
}

std::string RspHandler::handle_query(const std::string &packet, RspConnection &conn) {
  if (packet.rfind("qSupported", 0) == 0) {
    return "PacketSize=200000;qXfer:features:read+;"
           "qXfer:memory-map:read+;qXfer:threads:read+;"
           "qXfer:libraries:read+;qXfer:exec-file:read+;"
           "qXfer:osdata:read+;swbreak+;hwbreak+;"
           "QStartNoAckMode+;vContSupported+";
  }
  if (packet == "QStartNoAckMode") {
    conn.set_no_ack(true);
    return "OK";
  }
  if (packet == "QNonStop:0" || packet == "QThreadEvents:0" || packet == "QThreadEvents:1")
    return "OK";
  if (packet == "QNonStop:1") return err_packet(1);
  if (packet == "qAttached") return attached_ ? "1" : "0";
  if (packet.rfind("qAttached:", 0) == 0) {
    uint64_t requested_pid = 0U;
    if (!parse_hex_u64(packet, std::strlen("qAttached:"), packet.size(), requested_pid)) {
      return err_packet(1);
    }
    return attached_ && requested_pid == static_cast<uint64_t>(pid_) ? "1" : "0";
  }
  if (packet == "qProcessInfo" || packet.rfind("qProcessInfo:", 0) == 0) {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "pid:%x;triple:x86_64-unknown-freebsd;endian:little;",
                  static_cast<unsigned>(pid_ > 0 ? pid_ : 1));
    return std::string(buf);
  }
  if (packet == "qC") {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "QC%x", static_cast<unsigned>(current_thread()));
    return std::string(buf);
  }
  if (packet == "qHostInfo") {
    return "triple:7838365f36342d756e6b6e6f776e2d66726565627364;"
           "endian:little;ptrsize:8;";
  }
  if (packet == "qOffsets") return "Text=0;Data=0;Bss=0";
  if (packet == "qSymbol::" || packet.rfind("qSymbol:", 0U) == 0U) return "OK";
  if (packet == "qTStatus" || packet == "qTfV" || packet == "qTsV") return std::string();
  if (packet.rfind("qMemoryRegionInfo:", 0U) == 0U) return memory_region_info(packet);
  if (packet.rfind("qSearch:memory:", 0U) == 0U) return handle_search_memory(packet);
  if (packet.rfind("qThreadStopInfo", 0U) == 0U) {
    if (!ensure_attached()) return err_packet(1);
    size_t id_begin = std::strlen("qThreadStopInfo");
    if (id_begin < packet.size() && packet[id_begin] == ',') ++id_begin;
    if (id_begin >= packet.size()) return err_packet(1);
    int32_t req_pid = 0, req_tid = 0;
    if (!parse_thread_id(packet.c_str() + id_begin, req_pid, req_tid)) return err_packet(1);
    if (req_pid > 0 && req_pid != pid_) return err_packet(1);
    refresh_threads();
    if (req_tid != pid_) {
      const auto found = std::find_if(threads_.begin(), threads_.end(),
                                      [&](const auto &thread) { return thread.lwp == req_tid; });
      if (found == threads_.end()) return err_packet(1);
    }
    const int32_t saved = stop_lwp_;
    stop_lwp_ = req_tid;
    const std::string reply = stop_reply();
    stop_lwp_ = saved;
    return reply;
  }
  if (packet == "qfThreadInfo") {
    refresh_threads();
    thread_info_started_ = true;
    if (threads_.empty()) {
      if (pid_ > 0) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "m%x", static_cast<unsigned>(pid_));
        return std::string(buf);
      }
      return "l";
    }
    std::string out = "m";
    for (size_t i = 0; i < threads_.size(); ++i) {
      if (i > 0U) out.push_back(',');
      char buf[16];
      std::snprintf(buf, sizeof(buf), "%x",
                    static_cast<unsigned>(threads_[i].lwp > 0 ? threads_[i].lwp : pid_));
      out += buf;
    }
    return out;
  }
  if (packet == "qsThreadInfo") return "l";
  if (packet.rfind("qThreadExtraInfo,", 0) == 0) {
    int32_t req_pid = 0, req_tid = 0;
    if (!parse_thread_id(packet.c_str() + std::strlen("qThreadExtraInfo,"), req_pid, req_tid)) {
      return err_packet(1);
    }
    refresh_threads();
    for (const auto &t : threads_) {
      if (t.lwp == req_tid || (req_tid <= 0 && t.lwp > 0)) {
        return gdb_thread_extra_info_hex(t.lwp, t.name);
      }
    }
    const int32_t fallback_tid = req_tid > 0 ? req_tid : (pid_ > 0 ? pid_ : 1);
    return gdb_thread_extra_info_hex(fallback_tid, "");
  }
  std::string annex;
  size_t offset = 0U, length = 0U;
  if (packet.rfind("qXfer:features:read:", 0U) == 0U) {
    if (!parse_qxfer_request(packet, "qXfer:features:read:", annex, offset, length))
      return err_packet(1);
    return qxfer_features(annex, offset, length);
  }
  if (packet.rfind("qXfer:memory-map:read:", 0U) == 0U) {
    if (!parse_qxfer_request(packet, "qXfer:memory-map:read:", annex, offset, length) ||
        !annex.empty())
      return err_packet(1);
    return qxfer_memory_map(offset, length);
  }
  if (packet.rfind("qXfer:threads:read:", 0U) == 0U) {
    if (!parse_qxfer_request(packet, "qXfer:threads:read:", annex, offset, length) ||
        !annex.empty())
      return err_packet(1);
    return qxfer_threads(offset, length);
  }
  if (packet.rfind("qXfer:libraries:read:", 0U) == 0U) {
    if (!parse_qxfer_request(packet, "qXfer:libraries:read:", annex, offset, length) ||
        !annex.empty())
      return err_packet(1);
    return qxfer_libraries(offset, length);
  }
  if (packet.rfind("qXfer:exec-file:read:", 0U) == 0U) {
    if (!parse_qxfer_request(packet, "qXfer:exec-file:read:", annex, offset, length))
      return err_packet(1);
    if (!annex.empty()) {
      uint64_t requested_pid = 0U;
      if (!parse_hex_u64(annex, 0U, annex.size(), requested_pid) ||
          requested_pid != static_cast<uint64_t>(pid_))
        return err_packet(1);
    }
    return qxfer_exec_file(offset, length);
  }
  if (packet.rfind("qXfer:osdata:read:", 0U) == 0U) {
    if (!parse_qxfer_request(packet, "qXfer:osdata:read:", annex, offset, length))
      return err_packet(1);
    return qxfer_osdata(annex, offset, length);
  }
  if (packet.rfind("qRcmd,", 0) == 0) {
    /* Do not claim that an arbitrary monitor command ran when this target has
     * no monitor-command channel.  An empty response is the RSP spelling for
     * an unsupported query and lets GDB/IDA report it accurately. */
    return std::string();
  }
  return std::string(); /* unsupported query */
}

} // namespace memdbg::gdb_bridge

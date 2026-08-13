/*
 * MemDBG - Unit tests for GDB bridge framing and register mapping.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "gdb_regs.hpp"
#include "rsp_handler.hpp"
#include "rsp_server.hpp"
#include "target_xml.h"

#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

using namespace memdbg::gdb_bridge;

static int failures;

#define CHECK(name, expr)                       \
  do {                                          \
    if (!(expr)) {                              \
      std::fprintf(stderr, "FAIL: %s\n", name); \
      failures++;                               \
    }                                           \
  } while (0)

class FakeRspBackend final : public RspBackend {
public:
  FakeRspBackend() : memory(0x2000U) {
    for (size_t i = 0; i < memory.size(); ++i)
      memory[i] = static_cast<uint8_t>(i & 0xFFU);
    maps.push_back({0x1000U, 0x2000U, MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_EXEC, 0U,
                    "/app0/eboot.bin", "image"});
    maps.push_back({0x2000U, 0x3000U, MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE, 0U,
                    "/app0/eboot.bin", "image"});
    processes.push_back({0x49, 0x27, "eboot.bin"});
    process_info_value.pid = 0x49;
    process_info_value.name = "eboot.bin";
    process_info_value.path = "/app0/eboot.bin";

    memdbg::frontend::Client::DebugThreadEntry main_thread;
    main_thread.lwp = 0x49;
    main_thread.name = "main";
    threads.push_back(main_thread);
    memdbg::frontend::Client::DebugThreadEntry worker_thread;
    worker_thread.lwp = 0x50;
    worker_thread.name = "worker<&";
    threads.push_back(worker_thread);

    regs.regs.r_rip = 0x1010;
    regs.regs.r_rsp = 0x2FF0;
    regs.regs.r_rflags = 0x202;
    fpregs.fpregs.length = 512U;
    for (size_t i = 0; i < 10U; ++i)
      fpregs.fpregs.data[kFxsaveSt0Off + i] = static_cast<uint8_t>(0xA0U + i);
  }

  std::string last_error() const override { return error; }
  bool process_list(std::vector<memdbg::frontend::ProcessEntry> &out) override {
    out = processes;
    return true;
  }
  bool process_maps(int32_t, std::vector<memdbg::frontend::MapEntry> &out) override {
    out = maps;
    return maps_ok;
  }
  bool process_info(int32_t, memdbg::frontend::ProcessInfo &out) override {
    out = process_info_value;
    return true;
  }
  bool process_kill(int32_t pid) override {
    killed_pid = pid;
    attached = false;
    return pid == 0x49;
  }
  bool memory_read(int32_t, uint64_t address, uint32_t length, std::vector<uint8_t> &out) override {
    if (address < 0x1000U || address + length > 0x3000U) return false;
    const size_t off = static_cast<size_t>(address - 0x1000U);
    out.assign(memory.begin() + static_cast<std::ptrdiff_t>(off),
               memory.begin() + static_cast<std::ptrdiff_t>(off + length));
    return true;
  }
  bool memory_write(int32_t, uint64_t address, const std::vector<uint8_t> &data,
                    uint32_t &written) override {
    if (address < 0x1000U || address + data.size() > 0x3000U) return false;
    const size_t off = static_cast<size_t>(address - 0x1000U);
    std::copy(data.begin(), data.end(), memory.begin() + static_cast<std::ptrdiff_t>(off));
    written = static_cast<uint32_t>(data.size());
    return true;
  }
  bool debug_attach(int32_t pid) override {
    attached = pid == 0x49;
    return attached;
  }
  bool debug_detach() override {
    attached = false;
    detached = true;
    return true;
  }
  bool debug_stop() override { return attached; }
  bool debug_continue() override {
    continued++;
    return attached;
  }
  bool debug_step(int32_t lwp) override {
    stepped_lwp = lwp;
    return attached;
  }
  bool debug_get_threads(std::vector<memdbg::frontend::Client::DebugThreadEntry> &out) override {
    out = threads;
    return attached;
  }
  bool debug_get_regs(int32_t, memdbg::frontend::Client::DebugRegs &out) override {
    out = regs;
    return attached;
  }
  bool debug_set_regs(int32_t, const memdbg::frontend::Client::DebugRegs &in) override {
    regs = in;
    return attached;
  }
  bool debug_get_dbregs(int32_t, memdbg::frontend::Client::DebugDbregs &out) override {
    out = dbregs;
    return attached;
  }
  bool debug_get_fpregs(int32_t, memdbg::frontend::Client::DebugFpregs &out) override {
    out = fpregs;
    return attached;
  }
  bool debug_set_fpregs(int32_t, const memdbg::frontend::Client::DebugFpregs &in) override {
    fpregs = in;
    return attached;
  }
  bool debug_set_breakpoint(uint64_t address, uint32_t kind) override {
    breakpoint_address = address;
    breakpoint_kind = kind;
    return attached;
  }
  bool debug_clear_breakpoint(uint64_t address) override {
    breakpoint_address = address;
    return attached;
  }
  bool debug_set_watchpoint(uint64_t address, uint32_t length, uint32_t type) override {
    watchpoint = {address, length, type, 0U, true};
    return attached;
  }
  bool debug_clear_watchpoint(uint64_t address) override {
    watchpoint.address = address;
    watchpoint.installed = false;
    return attached;
  }
  bool
  debug_get_watchpoints(std::vector<memdbg::frontend::Client::DebugWatchpointEntry> &out) override {
    out.clear();
    if (watchpoint.installed) out.push_back(watchpoint);
    return attached;
  }
  bool debug_poll_events(bool &stopped, int32_t &stop_lwp) override {
    stopped = true;
    stop_lwp = 0x49;
    return attached;
  }

  std::string error;
  bool attached = false;
  bool detached = false;
  bool maps_ok = true;
  int continued = 0;
  int32_t stepped_lwp = 0;
  int32_t killed_pid = 0;
  uint64_t breakpoint_address = 0U;
  uint32_t breakpoint_kind = 0U;
  memdbg::frontend::Client::DebugWatchpointEntry watchpoint{};
  memdbg::frontend::Client::DebugRegs regs{};
  memdbg::frontend::Client::DebugDbregs dbregs{};
  memdbg::frontend::Client::DebugFpregs fpregs{};
  memdbg::frontend::ProcessInfo process_info_value;
  std::vector<memdbg::frontend::ProcessEntry> processes;
  std::vector<memdbg::frontend::MapEntry> maps;
  std::vector<memdbg::frontend::Client::DebugThreadEntry> threads;
  std::vector<uint8_t> memory;
};

int main() {
  /* Multiprocess RSP thread ID parser tests */
  int32_t pid_out = 0, tid_out = 0;
  CHECK("parse_thread_id hex tid",
        parse_thread_id("4a", pid_out, tid_out) && pid_out == 0 && tid_out == 0x4A);
  CHECK("parse_thread_id p4a.4a",
        parse_thread_id("p4a.4a", pid_out, tid_out) && pid_out == 0x4A && tid_out == 0x4A);
  CHECK("parse_thread_id p4a.1001",
        parse_thread_id("p4a.1001", pid_out, tid_out) && pid_out == 0x4A && tid_out == 0x1001);
  CHECK("parse_thread_id p-1.-1",
        parse_thread_id("p-1.-1", pid_out, tid_out) && pid_out == -1 && tid_out == -1);
  CHECK("parse_thread_id -1", parse_thread_id("-1", pid_out, tid_out) && tid_out == -1);
  CHECK("reject thread id trailing garbage", !parse_thread_id("49xyz", pid_out, tid_out));
  CHECK("reject incomplete multiprocess thread id", !parse_thread_id("p49", pid_out, tid_out));
  CHECK("reject overflowing thread id", !parse_thread_id("80000000", pid_out, tid_out));
  CHECK("checksum empty", rsp_checksum("") == 0U);
  CHECK("checksum abc", rsp_checksum("abc") == static_cast<uint8_t>('a' + 'b' + 'c'));

  const std::string escaped = rsp_escape("a$#}b");
  CHECK("escape specials", escaped == "a}\x04}\x03}]b");
  CHECK("unescape round-trip", rsp_unescape(rsp_escape("hello$#}")) == "hello$#}");
  std::string decoded_rsp;
  CHECK("decode RSP run-length encoding", rsp_decode("0* ", decoded_rsp) && decoded_rsp == "0000");
  CHECK("reject dangling RSP escape", !rsp_decode("abc}", decoded_rsp));
  CHECK("reject RSP repeat without prefix", !rsp_decode("* ", decoded_rsp));

  memdbg_debug_regs_t regs{};
  regs.r_rax = 0x1122334455667788LL;
  regs.r_rbx = 0x1LL;
  regs.r_rcx = 0x2LL;
  regs.r_rdx = 0x3LL;
  regs.r_rsi = 0x4LL;
  regs.r_rdi = 0x5LL;
  regs.r_rbp = 0x6LL;
  regs.r_rsp = 0x7FFFFFFFFLL;
  regs.r_r8 = 0x8LL;
  regs.r_r9 = 0x9LL;
  regs.r_r10 = 0xALL;
  regs.r_r11 = 0xBLL;
  regs.r_r12 = 0xCLL;
  regs.r_r13 = 0xDLL;
  regs.r_r14 = 0xELL;
  regs.r_r15 = 0xFLL;
  regs.r_rip = 0x401000LL;
  regs.r_rflags = 0x246LL;
  regs.r_cs = 0x33LL;
  regs.r_ss = 0x2BLL;
  regs.r_ds = 0x2BU;
  regs.r_es = 0x2BU;
  regs.r_fs = 0x43U;
  regs.r_gs = 0x53U;

  CHECK("rax mapping", gdb_get_reg_value(regs, GDB_RAX) == 0x1122334455667788ULL);
  CHECK("rip mapping", gdb_get_reg_value(regs, GDB_RIP) == 0x401000ULL);
  CHECK("eflags truncated", gdb_get_reg_value(regs, GDB_EFLAGS) == 0x246ULL);

  const std::string g = gdb_encode_g_packet(regs, nullptr);
  /* core 328 + x87 padding 224 + xmm 512 + mxcsr 8 = 1072 hex chars (536 bytes) */
  CHECK("g packet size", g.size() == kGdbPacketHexSize);

  memdbg_debug_regs_t decoded{};
  CHECK("g decode succeeds", gdb_decode_g_packet(g, decoded, nullptr));
  CHECK("g decode rejects trailing bytes", !gdb_decode_g_packet(g + "00", decoded, nullptr));
  CHECK("rax round-trip", static_cast<uint64_t>(decoded.r_rax) == 0x1122334455667788ULL);
  CHECK("rsp round-trip", static_cast<uint64_t>(decoded.r_rsp) == 0x7FFFFFFFFULL);
  CHECK("rip round-trip", static_cast<uint64_t>(decoded.r_rip) == 0x401000ULL);
  CHECK("rflags round-trip", (static_cast<uint64_t>(decoded.r_rflags) & 0xFFFFFFFFULL) == 0x246ULL);
  CHECK("ss round-trip", static_cast<uint64_t>(decoded.r_ss) == 0x2BULL);

  const std::string ida_core = gdb_encode_g_core(regs);
  CHECK("IDA core g-packet size", ida_core.size() == kGdbCorePacketHexSize);
  memdbg_debug_regs_t ida_decoded{};
  CHECK("IDA core g-packet decode", gdb_decode_g_core(ida_core, ida_decoded));
  CHECK("IDA core RIP round-trip", static_cast<uint64_t>(ida_decoded.r_rip) == 0x401000ULL);

  memdbg_debug_fpregs_t fpregs{};
  fpregs.length = 512U;
  std::memset(fpregs.data, 0, sizeof(fpregs.data));
  const uint8_t xmm7[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  CHECK("set xmm7", gdb_set_sse_bytes(fpregs, GDB_XMM7, xmm7, 16U));
  uint32_t mxcsr = 0x1F80U;
  CHECK("set mxcsr",
        gdb_set_sse_bytes(fpregs, GDB_MXCSR, reinterpret_cast<const uint8_t *>(&mxcsr), 4U));
  const std::string g2 = gdb_encode_g_packet(regs, &fpregs);
  CHECK("g+sse size", g2.size() == kGdbPacketHexSize);
  memdbg_debug_fpregs_t fpregs2{};
  memdbg_debug_regs_t decoded2{};
  CHECK("g+sse decode", gdb_decode_g_packet(g2, decoded2, &fpregs2));
  uint8_t xmm7_out[16]{};
  CHECK("get xmm7", gdb_get_sse_bytes(fpregs2, GDB_XMM7, xmm7_out, 16U));
  CHECK("xmm7 round-trip", std::memcmp(xmm7, xmm7_out, 16U) == 0);

  uint32_t mxcsr_out = 0;
  CHECK("get mxcsr",
        gdb_get_sse_bytes(fpregs2, GDB_MXCSR, reinterpret_cast<uint8_t *>(&mxcsr_out), 4U));
  CHECK("mxcsr round-trip", mxcsr_out == 0x1F80U);

  /* xmm0 and xmm15 extremes */
  const uint8_t xmm0[16] = {0xAA};
  const uint8_t xmm15[16] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                             0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
  CHECK("set xmm0", gdb_set_sse_bytes(fpregs, GDB_XMM0, xmm0, 16U));
  CHECK("set xmm15", gdb_set_sse_bytes(fpregs, GDB_XMM15, xmm15, 16U));
  uint8_t xmm0_out[16]{};
  uint8_t xmm15_out[16]{};
  CHECK("get xmm0", gdb_get_sse_bytes(fpregs, GDB_XMM0, xmm0_out, 16U));
  CHECK("get xmm15", gdb_get_sse_bytes(fpregs, GDB_XMM15, xmm15_out, 16U));
  CHECK("xmm0 round-trip", std::memcmp(xmm0, xmm0_out, 16U) == 0);
  CHECK("xmm15 round-trip", std::memcmp(xmm15, xmm15_out, 16U) == 0);

  /* Short FXSAVE still reports zeros for SSE reads. */
  memdbg_debug_fpregs_t short_fp{};
  short_fp.length = 32U;
  uint8_t zero16[16]{};
  CHECK("short fxsave get xmm0 zeros", gdb_get_sse_bytes(short_fp, GDB_XMM0, xmm0_out, 16U) &&
                                         std::memcmp(xmm0_out, zero16, 16U) == 0);
  CHECK("reject bad sse size", !gdb_set_sse_bytes(fpregs, GDB_XMM0, xmm0, 8U));
  CHECK("reject core as sse", !gdb_set_sse_bytes(fpregs, GDB_RAX, xmm0, 16U));

  const uint8_t st0[10] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
  CHECK("set x87 st0", gdb_set_x87_bytes(fpregs, GDB_ST0, st0, 10U));
  uint8_t st0_out[10]{};
  CHECK("get x87 st0", gdb_get_x87_bytes(fpregs, GDB_ST0, st0_out, sizeof(st0_out)) &&
                         std::memcmp(st0, st0_out, sizeof(st0)) == 0);
  CHECK("reject core as x87", !gdb_get_x87_bytes(fpregs, GDB_RAX, st0_out, sizeof(st0_out)));

  uint64_t patched = 0xDEADBEEFCAFEULL;
  CHECK("set rbx", gdb_set_reg_value(regs, GDB_RBX, patched));
  CHECK("get rbx", gdb_get_reg_value(regs, GDB_RBX) == patched);

  const std::string hex = bytes_to_hex("\x01\x02\xff", 3U);
  CHECK("bytes_to_hex", hex == "0102ff");
  uint8_t back[3]{};
  CHECK("hex_to_bytes", hex_to_bytes(hex, back, 3U));
  CHECK("hex bytes match", back[0] == 0x01 && back[1] == 0x02 && back[2] == 0xFF);

  /* qThreadExtraInfo body: ASCII name hex-encoded for IDA/GDB. */
  CHECK("thread extra named", gdb_thread_extra_info_hex(88, "main") == "6d61696e");
  CHECK("thread extra empty fallback",
        gdb_thread_extra_info_hex(0x58, "") == bytes_to_hex("LWP 88", 6U));
  CHECK("thread extra rejects non-text firmware fill",
        gdb_thread_extra_info_hex(0x49, std::string(15U, '\xff')) == bytes_to_hex("LWP 73", 6U));
  CHECK("thread extra rejects printable firmware fill",
        gdb_thread_extra_info_hex(0x4A, "FFFFFFFFFFFFFFF") == bytes_to_hex("LWP 74", 6U));

  std::vector<memdbg::frontend::Client::DebugWatchpointEntry> watchpoints(3U);
  watchpoints[0] = {0x1000U, 4U, 1U, 0U, true};
  watchpoints[1] = {0x2000U, 4U, 2U, 1U, true};
  watchpoints[2] = {0x3000U, 8U, 3U, 2U, true};
  CHECK("write DR6 stop reason", gdb_watchpoint_stop_field(1ULL, watchpoints) == "watch:1000;");
  CHECK("read DR6 stop reason", gdb_watchpoint_stop_field(2ULL, watchpoints) == "rwatch:2000;");
  CHECK("access DR6 stop reason", gdb_watchpoint_stop_field(4ULL, watchpoints) == "awatch:3000;");
  CHECK("no DR6 hit has no stop reason", gdb_watchpoint_stop_field(0ULL, watchpoints).empty());

  std::vector<memdbg::frontend::MapEntry> maps;
  maps.push_back({0x1000U, 0x1800U, 0U, 0U, "first", ""});
  maps.push_back({0x1800U, 0x2000U, 0U, 0U, "second", ""});
  maps.push_back({0x3000U, 0x4000U, 0U, 0U, "third", ""});
  CHECK("mapped range within one mapping", gdb_memory_range_mapped(maps, 0x1100U, 0x100U));
  CHECK("mapped range crosses adjacent mappings", gdb_memory_range_mapped(maps, 0x1700U, 0x200U));
  CHECK("mapped zero-length range", gdb_memory_range_mapped(maps, 0x2500U, 0U));
  CHECK("reject mapping gap", !gdb_memory_range_mapped(maps, 0x1F00U, 0x1200U));
  CHECK("reject unmapped range", !gdb_memory_range_mapped(maps, 0x5000U, 0x100U));
  CHECK("reject wrapping range",
        !gdb_memory_range_mapped(maps, std::numeric_limits<uint64_t>::max() - 0x10U, 0x20U));

  /* Full RSP command integration through a deterministic backend. */
  FakeRspBackend fake;
  RspHandler handler(fake, 0, false);
  RspConnection conn(memdbg::frontend::platform::invalid_socket());

  const std::string supported = handler.handle("qSupported:multiprocess+", conn);
  CHECK("qSupported packet size is hexadecimal",
        supported.find("PacketSize=200000") != std::string::npos);
  CHECK("qSupported advertises thread XML",
        supported.find("qXfer:threads:read+") != std::string::npos);
  CHECK("qSupported advertises binary-safe features",
        supported.find("vContSupported+") != std::string::npos);
  CHECK("reject invalid attach pid", handler.handle("vAttach;1", conn) == "E01");
  CHECK("attach by hexadecimal pid",
        handler.handle("vAttach;49", conn) == "T05thread:49;" && fake.attached);
  CHECK("attached query", handler.handle("qAttached", conn) == "1");
  CHECK("current thread query", handler.handle("qC", conn) == "QC49");
  CHECK("thread enumeration", handler.handle("qfThreadInfo", conn) == "m49,50");
  CHECK("thread selection", handler.handle("Hg50", conn) == "OK");
  CHECK("reject unknown thread", handler.handle("Hg999", conn) == "E01");
  CHECK("thread name encoding",
        handler.handle("qThreadExtraInfo,50", conn) == bytes_to_hex("worker<&", 8U));
  CHECK("thread stop info", handler.handle("qThreadStopInfo50", conn) == "T05thread:50;");

  const std::string thread_xml = handler.handle("qXfer:threads:read::0,1000", conn);
  CHECK("thread XML final chunk", !thread_xml.empty() && thread_xml[0] == 'l');
  CHECK("thread XML escapes names", thread_xml.find("worker&lt;&amp;") != std::string::npos);
  const std::string library_xml = handler.handle("qXfer:libraries:read::0,1000", conn);
  CHECK("library XML contains image", library_xml.find("/app0/eboot.bin") != std::string::npos);
  CHECK("exec-file qXfer",
        handler.handle("qXfer:exec-file:read:49:0,100", conn) == "l/app0/eboot.bin");
  const std::string process_xml = handler.handle("qXfer:osdata:read:processes:0,1000", conn);
  CHECK("process XML contains eboot", process_xml.find("eboot.bin") != std::string::npos);
  const std::string target_description =
    handler.handle("qXfer:features:read:target.xml:0,10000", conn);
  CHECK("target XML is returned as a final qXfer chunk",
        !target_description.empty() && target_description[0] == 'l');
  CHECK("served target XML contains the amd64 core feature",
        target_description.find("org.gnu.gdb.i386.core") != std::string::npos);
  CHECK("reject zero qXfer chunk",
        handler.handle("qXfer:features:read:target.xml:0,0", conn) == "E01");

  CHECK(
    "mapped memory region info",
    handler.handle("qMemoryRegionInfo:1000", conn).find("start:1000;size:1000;permissions:rx;") ==
      0U);
  CHECK("unmapped memory region info",
        handler.handle("qMemoryRegionInfo:3000", conn).find("permissions:;") != std::string::npos);
  CHECK("valid memory read", handler.handle("m1000,4", conn) == "00010203");
  CHECK("reject unmapped memory read", handler.handle("m4000,4", conn) == "E01");
  CHECK("reject oversized memory read", handler.handle("m1000,100001", conn) == "E22");
  CHECK("reject wrapping memory read", handler.handle("mffffffffffffffff,2", conn) == "E22");
  CHECK("hex memory write", handler.handle("M2004,4:aabbccdd", conn) == "OK" &&
                              handler.handle("m2004,4", conn) == "aabbccdd");
  CHECK("reject unmapped hex memory write", handler.handle("M4000,1:aa", conn) == "E01");
  std::string binary_write = "X2008,4:";
  binary_write.append("\x00\x23\x7d\xff", 4U);
  CHECK("binary memory write", handler.handle(binary_write, conn) == "OK" &&
                                 handler.handle("m2008,4", conn) == "00237dff");
  CHECK("reject short binary write", handler.handle("X2008,4:abc", conn) == "E01");
  CHECK("reject unmapped binary memory write", handler.handle("X4000,1:a", conn) == "E01");
  CHECK("memory search found",
        handler.handle(std::string("qSearch:memory:1000;100;") + std::string("\x20\x21\x22", 3U),
                       conn) == "1,1020");
  CHECK("memory search miss", handler.handle("qSearch:memory:1000;10;missing", conn) == "0");

  CHECK("read RIP register", handler.handle("p10", conn) == "1010000000000000");
  const std::string all_registers = handler.handle("g", conn);
  CHECK("handler g returns complete target layout", all_registers.size() == kGdbPacketHexSize);
  CHECK("handler g contains exact ST0 bytes",
        all_registers.substr(kGdbCorePacketHexSize, 20U) == "a0a1a2a3a4a5a6a7a8a9");

  memdbg_debug_regs_t written_regs = fake.regs.regs;
  memdbg_debug_fpregs_t written_fpregs = fake.fpregs.fpregs;
  written_regs.r_rax = static_cast<int64_t>(0x1122334455667788ULL);
  const uint8_t written_xmm15[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  CHECK("prepare full G xmm15",
        gdb_set_sse_bytes(written_fpregs, GDB_XMM15, written_xmm15, sizeof(written_xmm15)));
  CHECK("handler accepts complete G packet",
        handler.handle("G" + gdb_encode_g_packet(written_regs, &written_fpregs), conn) == "OK" &&
          static_cast<uint64_t>(fake.regs.regs.r_rax) == 0x1122334455667788ULL);
  uint8_t stored_xmm15[16]{};
  CHECK("handler G writes SSE state",
        gdb_get_sse_bytes(fake.fpregs.fpregs, GDB_XMM15, stored_xmm15, sizeof(stored_xmm15)) &&
          std::memcmp(stored_xmm15, written_xmm15, sizeof(written_xmm15)) == 0);
  CHECK("handler keeps legacy core-only G compatibility",
        handler.handle("G" + gdb_encode_g_core(written_regs), conn) == "OK");
  CHECK("handler rejects truncated G packet",
        handler.handle("G" + std::string(kGdbCorePacketHexSize + 2U, '0'), conn) == "E01");
  CHECK("read x87 register without stack overread",
        handler.handle("p18", conn) == "a0a1a2a3a4a5a6a7a8a9");
  CHECK("write x87 register", handler.handle("P18=10111213141516171819", conn) == "OK" &&
                                handler.handle("p18", conn) == "10111213141516171819");
  CHECK("write RIP register", handler.handle("P10=3412000000000000", conn) == "OK" &&
                                static_cast<uint64_t>(fake.regs.regs.r_rip) == 0x1234U);
  CHECK("reject malformed register number", handler.handle("p10junk", conn) == "E01");
  CHECK("software breakpoint", handler.handle("Z0,1010,1", conn) == "OK" &&
                                 fake.breakpoint_address == 0x1010U && fake.breakpoint_kind == 0U);
  CHECK("reject invalid software breakpoint kind", handler.handle("Z0,1010,2", conn) == "E22");
  CHECK("write watchpoint", handler.handle("Z2,2000,4", conn) == "OK" &&
                              fake.watchpoint.installed && fake.watchpoint.type == 1U);
  CHECK("reject invalid watchpoint length", handler.handle("Z2,2000,3", conn) == "E22");

  CHECK("continue from explicit address", handler.handle("c1020", conn) == "T05thread:49;" &&
                                            fake.continued == 1 &&
                                            static_cast<uint64_t>(fake.regs.regs.r_rip) == 0x1020U);
  CHECK("single step selected thread",
        handler.handle("vCont;s:50", conn) == "T05thread:49;" && fake.stepped_lwp == 0x50);
  CHECK("thread action overrides vCont default",
        handler.handle("vCont;c;s:50", conn) == "T05thread:49;" && fake.stepped_lwp == 0x50);
  CHECK("reject malformed vCont", handler.handle("vCont;Czz:49", conn) == "E01");
  CHECK("reject malformed secondary vCont action",
        handler.handle("vCont;c;invalid", conn) == "E01");
  CHECK("reject trailing empty vCont action", handler.handle("vCont;c;", conn) == "E01");
  CHECK("reject mismatched qAttached pid", handler.handle("qAttached:50", conn) == "0");
  CHECK("unsupported monitor command is not reported as executed",
        handler.handle("qRcmd,68656c70", conn).empty());
  CHECK("reject malformed detach", handler.handle("Dgarbage", conn) == "E01" && handler.attached());
  CHECK("detach", handler.handle("D", conn) == "OK" && fake.detached);
  CHECK("detached query", handler.handle("qAttached", conn) == "0");
  CHECK("reattach before vKill", handler.handle("vAttach;49", conn).find("T05thread:49;") == 0U);
  CHECK("vKill process",
        handler.handle("vKill;49", conn) == "OK" && fake.killed_pid == 0x49 && !handler.attached());
  CHECK("reattach before legacy kill",
        handler.handle("vAttach;49", conn).find("T05thread:49;") == 0U);
  CHECK("legacy kill packet",
        handler.handle("k", conn) == "OK" && fake.killed_pid == 0x49 && !handler.attached());

  CHECK("target xml non-empty", std::strlen(kMemdbgGdbTargetXml) > 100U);
  CHECK("target xml has architecture", std::strstr(kMemdbgGdbTargetXml, "i386:x86-64") != nullptr);
  CHECK("target xml declares required amd64 core feature",
        std::strstr(kMemdbgGdbTargetXml, "org.gnu.gdb.i386.core") != nullptr);
  CHECK("target xml declares SSE feature",
        std::strstr(kMemdbgGdbTargetXml, "org.gnu.gdb.i386.sse") != nullptr);
  CHECK("target xml core register order starts at rax",
        std::strstr(kMemdbgGdbTargetXml,
                    "<reg name=\"rax\" bitsize=\"64\" type=\"int64\" regnum=\"0\"") != nullptr);
  CHECK("target xml x87 register declared",
        std::strstr(kMemdbgGdbTargetXml, "<reg name=\"st0\" bitsize=\"80\"") != nullptr);
  CHECK("target xml SSE register order starts at 40",
        std::strstr(kMemdbgGdbTargetXml,
                    "<reg name=\"xmm0\" bitsize=\"128\" type=\"vec128\" regnum=\"40\"") != nullptr);
  CHECK("target xml register layout ends at mxcsr",
        std::strstr(kMemdbgGdbTargetXml, "<reg name=\"mxcsr\" bitsize=\"32\"") != nullptr);
  const std::string target_xml(kMemdbgGdbTargetXml);
  size_t xml_register_count = 0U;
  for (size_t offset = 0U; (offset = target_xml.find("<reg name=", offset)) != std::string::npos;
       offset += std::strlen("<reg name=")) {
    ++xml_register_count;
  }
  CHECK("target xml and serializer expose the same register count",
        xml_register_count == static_cast<size_t>(GDB_REG_MAX));

  CHECK("reg size rax", gdb_reg_size(GDB_RAX) == 8U);
  CHECK("reg size eflags", gdb_reg_size(GDB_EFLAGS) == 4U);
  CHECK("invalid regno", !gdb_reg_valid(-1) && !gdb_reg_valid(GDB_REG_MAX));

  if (failures == 0) {
    std::fprintf(stdout, "All gdb_bridge tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d test(s) failed\n", failures);
  return 1;
}

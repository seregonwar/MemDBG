/*
 * MemDBG - x64dbg plugin entry (issue #39).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Speaks native MDBG to a MemDBG payload. Links the official x64dbg Plugin SDK
 * (FetchContent or MEMDBG_X64DBG_SDK) to produce MemDBG.dp64.
 */

#include "memdbg_session.hpp"
#include "plugin_util.hpp"

#include "pluginsdk/bridgemain.h"
#include "pluginsdk/_plugins.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr int kPluginVersion = 1;
constexpr const char *kPluginName = "MemDBG";

int g_plugin_handle = 0;
int g_menu = 0;

enum MenuId : int {
  kMenuConnect = 1,
  kMenuDisconnect = 2,
  kMenuAttach = 3,
  kMenuDetach = 4,
  kMenuStop = 5,
  kMenuContinue = 6,
  kMenuStep = 7,
  kMenuDumpRegs = 8,
  kMenuReadMem = 9,
  kMenuSetBp = 10,
  kMenuClearBp = 11,
  kMenuWriteMem = 12,
  kMenuWatch = 13,
  kMenuUnwatch = 14,
  kMenuPoll = 15,
  kMenuSync = 20,
};

using memdbg::x64dbg_bridge::parse_connect_endpoint;
using memdbg::x64dbg_bridge::parse_hex_bytes;
using memdbg::x64dbg_bridge::parse_i32;
using memdbg::x64dbg_bridge::parse_u64;
using memdbg::x64dbg_bridge::make_view_sync_plan;

void log_ok(const char *msg) {
  _plugin_logprintf("[MemDBG] %s\n", msg);
}

void log_err(const char *msg) {
  _plugin_logprintf("[MemDBG] ERROR: %s\n", msg);
}

/* Navigate x64dbg CPU/Dump views to remote RIP/RSP (or override). Native views
 * still read the local TitanEngine debuggee; this anchors CIP/VA for workflow. */
bool sync_views_from_regs(const memdbg::frontend::Client::DebugRegs &regs,
                          uint64_t dump_override) {
  const auto plan = make_view_sync_plan(
      static_cast<uint64_t>(regs.regs.r_rip),
      static_cast<uint64_t>(regs.regs.r_rsp), dump_override);
  if (!plan.ok) {
    log_err("sync: empty RIP/RSP");
    return false;
  }
  if (plan.cip != 0) {
    GuiDisasmAt(static_cast<duint>(plan.cip), static_cast<duint>(plan.cip));
  }
  if (plan.dump_addr != 0) {
    GuiDumpAt(static_cast<duint>(plan.dump_addr));
  }
  GuiUpdateDisassemblyView();
  GuiUpdateDumpView();
  GuiUpdateAllViews();
  _plugin_logprintf("[MemDBG] synced CPU@%016llX dump@%016llX\n",
                    static_cast<unsigned long long>(plan.cip),
                    static_cast<unsigned long long>(plan.dump_addr));
  return true;
}

bool cmd_connect(int argc, char **argv) {
  /* x64dbg's default command engine expression-evaluates bare args, so
   * 192.168.1.50 9020 often mangles the IP. Prefer quotes or host:port:
   *   MemDBGConnect "192.168.1.50", 9020
   *   MemDBGConnect "192.168.1.50:9020"
   * Also switch the command bar from Script DLL to the default engine. */
  std::string host;
  uint16_t port = 9020;
  if (!parse_connect_endpoint(argc, argv, host, port)) {
    log_err("usage: MemDBGConnect \"<ipv4>\" [port] | MemDBGConnect "
            "\"<ipv4>:<port>\" (quote the IP; x64dbg evaluates bare dots)");
    return false;
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.connect(host, port)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] connected to %s:%u\n", host.c_str(),
                    static_cast<unsigned>(port));
  return true;
}

bool cmd_ps(int, char **) {
  auto &session = memdbg::x64dbg_bridge::global_session();
  std::vector<memdbg::frontend::ProcessEntry> procs;
  if (!session.list_processes(procs)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] %zu processes:\n", procs.size());
  for (const auto &p : procs) {
    _plugin_logprintf("  pid=%d ppid=%d %s\n", static_cast<int>(p.pid),
                      static_cast<int>(p.ppid), p.name.c_str());
  }
  return true;
}

bool cmd_disconnect(int, char **) {
  memdbg::x64dbg_bridge::global_session().disconnect();
  log_ok("disconnected");
  return true;
}

bool cmd_attach(int argc, char **argv) {
  if (argc < 2) {
    log_err("usage: MemDBGAttach <pid>");
    return false;
  }
  int32_t pid = 0;
  if (!parse_i32(argv[1], pid)) {
    log_err("invalid pid");
    return false;
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.attach(pid)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] attached pid=%d\n", static_cast<int>(pid));
  return true;
}

bool cmd_detach(int, char **) {
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.detach()) {
    log_err(session.last_error().c_str());
    return false;
  }
  log_ok("detached");
  return true;
}

bool cmd_stop(int, char **) {
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.stop()) {
    log_err(session.last_error().c_str());
    return false;
  }
  log_ok("stopped");
  memdbg::frontend::Client::DebugRegs regs;
  if (session.get_regs(regs)) {
    (void)sync_views_from_regs(regs, 0);
  }
  return true;
}

bool cmd_continue(int, char **) {
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.cont()) {
    log_err(session.last_error().c_str());
    return false;
  }
  log_ok("continued");
  return true;
}

bool cmd_step(int, char **) {
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.step()) {
    log_err(session.last_error().c_str());
    return false;
  }
  log_ok("stepped");
  return true;
}

bool cmd_regs(int, char **) {
  auto &session = memdbg::x64dbg_bridge::global_session();
  memdbg::frontend::Client::DebugRegs regs;
  if (!session.get_regs(regs)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf(
      "[MemDBG] rax=%016llX rbx=%016llX rcx=%016llX rdx=%016llX\n",
      static_cast<unsigned long long>(regs.regs.r_rax),
      static_cast<unsigned long long>(regs.regs.r_rbx),
      static_cast<unsigned long long>(regs.regs.r_rcx),
      static_cast<unsigned long long>(regs.regs.r_rdx));
  _plugin_logprintf(
      "[MemDBG] rsi=%016llX rdi=%016llX rbp=%016llX rsp=%016llX\n",
      static_cast<unsigned long long>(regs.regs.r_rsi),
      static_cast<unsigned long long>(regs.regs.r_rdi),
      static_cast<unsigned long long>(regs.regs.r_rbp),
      static_cast<unsigned long long>(regs.regs.r_rsp));
  _plugin_logprintf("[MemDBG] rip=%016llX rflags=%016llX\n",
                    static_cast<unsigned long long>(regs.regs.r_rip),
                    static_cast<unsigned long long>(regs.regs.r_rflags));
  return true;
}

bool cmd_read(int argc, char **argv) {
  if (argc < 2) {
    log_err("usage: MemDBGRead <addr> [length]");
    return false;
  }
  uint64_t addr = 0;
  if (!parse_u64(argv[1], addr)) {
    log_err("invalid address");
    return false;
  }
  uint32_t length = 64;
  if (argc >= 3) {
    uint64_t tmp = 0;
    if (!parse_u64(argv[2], tmp) || tmp == 0 || tmp > (1U << 20)) {
      log_err("invalid length");
      return false;
    }
    length = static_cast<uint32_t>(tmp);
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  std::vector<uint8_t> data;
  if (!session.read_memory(addr, length, data)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] %zu bytes @ %016llX:\n", data.size(),
                    static_cast<unsigned long long>(addr));
  for (size_t i = 0; i < data.size(); i += 16) {
    char line[128];
    size_t used = static_cast<size_t>(std::snprintf(
        line, sizeof(line), "  %016llX:",
        static_cast<unsigned long long>(addr + i)));
    for (size_t j = 0; j < 16 && i + j < data.size() && used + 4 < sizeof(line);
         ++j) {
      used += static_cast<size_t>(
          std::snprintf(line + used, sizeof(line) - used, " %02X", data[i + j]));
    }
    _plugin_logputs(line);
  }
  return true;
}

bool cmd_bp(int argc, char **argv) {
  if (argc < 2) {
    log_err("usage: MemDBGBp <addr>  (software)");
    return false;
  }
  uint64_t addr = 0;
  if (!parse_u64(argv[1], addr)) {
    log_err("invalid address");
    return false;
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.set_soft_bp(addr)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] soft BP @ %016llX\n",
                    static_cast<unsigned long long>(addr));
  return true;
}

bool cmd_hwbp(int argc, char **argv) {
  if (argc < 2) {
    log_err("usage: MemDBGHwBp <addr>");
    return false;
  }
  uint64_t addr = 0;
  if (!parse_u64(argv[1], addr)) {
    log_err("invalid address");
    return false;
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.set_hw_bp(addr)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] hardware BP @ %016llX\n",
                    static_cast<unsigned long long>(addr));
  return true;
}

bool cmd_bc(int argc, char **argv) {
  if (argc < 2) {
    log_err("usage: MemDBGBc <addr>");
    return false;
  }
  uint64_t addr = 0;
  if (!parse_u64(argv[1], addr)) {
    log_err("invalid address");
    return false;
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.clear_bp(addr)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] cleared BP @ %016llX\n",
                    static_cast<unsigned long long>(addr));
  return true;
}

bool cmd_write(int argc, char **argv) {
  if (argc < 3) {
    log_err("usage: MemDBGWrite <addr> <hex-bytes>");
    return false;
  }
  uint64_t addr = 0;
  if (!parse_u64(argv[1], addr)) {
    log_err("invalid address");
    return false;
  }
  std::vector<uint8_t> data;
  if (!parse_hex_bytes(argv[2], data)) {
    log_err("invalid hex bytes");
    return false;
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.write_memory(addr, data)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] wrote %zu bytes @ %016llX\n", data.size(),
                    static_cast<unsigned long long>(addr));
  return true;
}

bool cmd_watch(int argc, char **argv) {
  if (argc < 2) {
    log_err("usage: MemDBGWatch <addr> [length] [r|w|rw]  (default length=8 type=w)");
    return false;
  }
  uint64_t addr = 0;
  if (!parse_u64(argv[1], addr)) {
    log_err("invalid address");
    return false;
  }
  uint32_t length = 8;
  if (argc >= 3) {
    uint64_t tmp = 0;
    if (!parse_u64(argv[2], tmp) || tmp == 0 || tmp > 8) {
      log_err("invalid length (1..8)");
      return false;
    }
    length = static_cast<uint32_t>(tmp);
  }
  /* MemDBG watch types: 0=exec, 1=write, 2=read, 3=rw */
  uint32_t type = 1;
  if (argc >= 4) {
    if (std::strcmp(argv[3], "w") == 0 || std::strcmp(argv[3], "write") == 0) {
      type = 1;
    } else if (std::strcmp(argv[3], "r") == 0 || std::strcmp(argv[3], "read") == 0) {
      type = 2;
    } else if (std::strcmp(argv[3], "rw") == 0) {
      type = 3;
    } else if (std::strcmp(argv[3], "x") == 0 || std::strcmp(argv[3], "exec") == 0) {
      type = 0;
    } else {
      log_err("type must be r|w|rw|x");
      return false;
    }
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.set_watchpoint(addr, length, type)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] watchpoint @ %016llX len=%u type=%u\n",
                    static_cast<unsigned long long>(addr),
                    static_cast<unsigned>(length),
                    static_cast<unsigned>(type));
  return true;
}

bool cmd_unwatch(int argc, char **argv) {
  if (argc < 2) {
    log_err("usage: MemDBGUnwatch <addr>");
    return false;
  }
  uint64_t addr = 0;
  if (!parse_u64(argv[1], addr)) {
    log_err("invalid address");
    return false;
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.clear_watchpoint(addr)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] cleared watchpoint @ %016llX\n",
                    static_cast<unsigned long long>(addr));
  return true;
}

bool cmd_sync(int argc, char **argv) {
  uint64_t dump_override = 0;
  if (argc >= 2) {
    if (!parse_u64(argv[1], dump_override)) {
      log_err("usage: MemDBGSync [dump_addr]");
      return false;
    }
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  memdbg::frontend::Client::DebugRegs regs;
  if (!session.get_regs(regs)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] rip=%016llX rsp=%016llX\n",
                    static_cast<unsigned long long>(regs.regs.r_rip),
                    static_cast<unsigned long long>(regs.regs.r_rsp));
  return sync_views_from_regs(regs, dump_override);
}

bool cmd_poll(int, char **) {
  auto &session = memdbg::x64dbg_bridge::global_session();
  bool stopped = false;
  int32_t stop_lwp = 0;
  if (!session.poll_events(stopped, stop_lwp)) {
    log_err(session.last_error().c_str());
    return false;
  }
  if (stopped) {
    _plugin_logprintf("[MemDBG] stopped lwp=%d\n", static_cast<int>(stop_lwp));
    memdbg::frontend::Client::DebugRegs regs;
    if (session.get_regs(regs)) {
      (void)sync_views_from_regs(regs, 0);
    }
  } else {
    log_ok("running (no stop event)");
  }
  return true;
}

bool cmd_setreg(int argc, char **argv) {
  if (argc < 3) {
    log_err("usage: MemDBGSetReg <name> <value>");
    return false;
  }
  uint64_t value = 0;
  if (!parse_u64(argv[2], value)) {
    log_err("invalid value");
    return false;
  }
  auto &session = memdbg::x64dbg_bridge::global_session();
  if (!session.set_gpr(argv[1], value)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] %s = %016llX\n", argv[1],
                    static_cast<unsigned long long>(value));
  return true;
}

bool cmd_maps(int, char **) {
  auto &session = memdbg::x64dbg_bridge::global_session();
  std::vector<memdbg::frontend::MapEntry> maps;
  if (!session.list_maps(maps)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] %zu map entries:\n", maps.size());
  const size_t show = maps.size() < 64 ? maps.size() : 64;
  for (size_t i = 0; i < show; ++i) {
    const auto &m = maps[i];
    _plugin_logprintf("  %016llX-%016llX prot=%08X %s\n",
                      static_cast<unsigned long long>(m.start),
                      static_cast<unsigned long long>(m.end),
                      static_cast<unsigned>(m.protection),
                      m.name.empty() ? m.type.c_str() : m.name.c_str());
  }
  if (maps.size() > show) {
    _plugin_logprintf("  ... (%zu more)\n", maps.size() - show);
  }
  return true;
}

bool cmd_fpregs(int, char **) {
  auto &session = memdbg::x64dbg_bridge::global_session();
  memdbg::frontend::Client::DebugFpregs fpregs;
  if (!session.get_fpregs(fpregs)) {
    log_err(session.last_error().c_str());
    return false;
  }
  _plugin_logprintf("[MemDBG] fpregs length=%u flags=%08X\n",
                    static_cast<unsigned>(fpregs.fpregs.length),
                    static_cast<unsigned>(fpregs.fpregs.flags));
  if (fpregs.fpregs.length >= 416U) {
    uint32_t mxcsr = 0;
    std::memcpy(&mxcsr, fpregs.fpregs.data + 24, 4);
    _plugin_logprintf("[MemDBG] mxcsr=%08X\n", static_cast<unsigned>(mxcsr));
    for (int i = 0; i < 16; ++i) {
      const uint8_t *xmm = fpregs.fpregs.data + 160 + i * 16;
      _plugin_logprintf(
          "[MemDBG] xmm%-2d %02X%02X%02X%02X %02X%02X%02X%02X "
          "%02X%02X%02X%02X %02X%02X%02X%02X\n",
          i, xmm[15], xmm[14], xmm[13], xmm[12], xmm[11], xmm[10], xmm[9],
          xmm[8], xmm[7], xmm[6], xmm[5], xmm[4], xmm[3], xmm[2], xmm[1],
          xmm[0]);
    }
  }
  return true;
}

void handle_menu(int entry) {
  switch (entry) {
  case kMenuConnect:
    _plugin_logputs(
        "[MemDBG] Use: MemDBGConnect \"192.168.1.50\", 9020  (or "
        "\"192.168.1.50:9020\"; quote IP; default engine not Script DLL)");
    break;
  case 21:
    cmd_ps(0, nullptr);
    break;
  case kMenuDisconnect:
    cmd_disconnect(0, nullptr);
    break;
  case kMenuAttach:
    _plugin_logputs("[MemDBG] Use command: MemDBGAttach <pid>");
    break;
  case kMenuDetach:
    cmd_detach(0, nullptr);
    break;
  case kMenuStop:
    cmd_stop(0, nullptr);
    break;
  case kMenuContinue:
    cmd_continue(0, nullptr);
    break;
  case kMenuStep:
    cmd_step(0, nullptr);
    break;
  case kMenuDumpRegs:
    cmd_regs(0, nullptr);
    break;
  case kMenuReadMem:
    _plugin_logputs("[MemDBG] Use command: MemDBGRead <addr> [length]");
    break;
  case kMenuSetBp:
    _plugin_logputs("[MemDBG] Use command: MemDBGBp <addr>");
    break;
  case kMenuClearBp:
    _plugin_logputs("[MemDBG] Use command: MemDBGBc <addr>");
    break;
  case kMenuWriteMem:
    _plugin_logputs("[MemDBG] Use command: MemDBGWrite <addr> <hex-bytes>");
    break;
  case kMenuWatch:
    _plugin_logputs("[MemDBG] Use command: MemDBGWatch <addr> [len] [r|w|rw|x]");
    break;
  case kMenuUnwatch:
    _plugin_logputs("[MemDBG] Use command: MemDBGUnwatch <addr>");
    break;
  case kMenuPoll:
    cmd_poll(0, nullptr);
    break;
  case 16:
    _plugin_logputs("[MemDBG] Use command: MemDBGHwBp <addr>");
    break;
  case 17:
    _plugin_logputs("[MemDBG] Use command: MemDBGSetReg <name> <value>");
    break;
  case 18:
    cmd_maps(0, nullptr);
    break;
  case 19:
    cmd_fpregs(0, nullptr);
    break;
  case kMenuSync:
    cmd_sync(0, nullptr);
    break;
  default:
    break;
  }
}

} // namespace

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT *initStruct) {
  initStruct->pluginVersion = kPluginVersion;
  initStruct->sdkVersion = PLUG_SDKVERSION;
  std::strncpy(initStruct->pluginName, kPluginName, sizeof(initStruct->pluginName) - 1);
  initStruct->pluginName[sizeof(initStruct->pluginName) - 1] = '\0';
  g_plugin_handle = initStruct->pluginHandle;

  _plugin_registercommand(g_plugin_handle, "MemDBGConnect", cmd_connect, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGDisconnect", cmd_disconnect, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGPs", cmd_ps, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGAttach", cmd_attach, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGDetach", cmd_detach, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGStop", cmd_stop, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGContinue", cmd_continue, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGStep", cmd_step, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGRegs", cmd_regs, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGRead", cmd_read, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGWrite", cmd_write, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGBp", cmd_bp, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGHwBp", cmd_hwbp, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGBc", cmd_bc, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGWatch", cmd_watch, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGUnwatch", cmd_unwatch, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGPoll", cmd_poll, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGSetReg", cmd_setreg, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGMaps", cmd_maps, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGFpRegs", cmd_fpregs, false);
  _plugin_registercommand(g_plugin_handle, "MemDBGSync", cmd_sync, false);

  log_ok("plugin loaded (MDBG remote bridge)");
  return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT *setupStruct) {
  g_menu = setupStruct->hMenu;
  _plugin_menuaddentry(g_menu, kMenuConnect, "Connect (see MemDBGConnect)...");
  _plugin_menuaddentry(g_menu, kMenuDisconnect, "Disconnect");
  _plugin_menuaddentry(g_menu, 21, "Process list (MemDBGPs)");
  _plugin_menuaddseparator(g_menu);
  _plugin_menuaddentry(g_menu, kMenuAttach, "Attach (see MemDBGAttach)...");
  _plugin_menuaddentry(g_menu, kMenuDetach, "Detach");
  _plugin_menuaddseparator(g_menu);
  _plugin_menuaddentry(g_menu, kMenuStop, "Stop");
  _plugin_menuaddentry(g_menu, kMenuContinue, "Continue");
  _plugin_menuaddentry(g_menu, kMenuStep, "Step");
  _plugin_menuaddentry(g_menu, kMenuPoll, "Poll stop events");
  _plugin_menuaddseparator(g_menu);
  _plugin_menuaddentry(g_menu, kMenuDumpRegs, "Dump registers");
  _plugin_menuaddentry(g_menu, kMenuReadMem, "Read memory (see MemDBGRead)...");
  _plugin_menuaddentry(g_menu, kMenuWriteMem, "Write memory (see MemDBGWrite)...");
  _plugin_menuaddentry(g_menu, kMenuSetBp, "Set soft BP (see MemDBGBp)...");
  _plugin_menuaddentry(g_menu, kMenuClearBp, "Clear BP (see MemDBGBc)...");
  _plugin_menuaddentry(g_menu, kMenuWatch, "Watchpoint (see MemDBGWatch)...");
  _plugin_menuaddentry(g_menu, kMenuUnwatch, "Clear watch (see MemDBGUnwatch)...");
  _plugin_menuaddseparator(g_menu);
  _plugin_menuaddentry(g_menu, 16, "Hardware BP (see MemDBGHwBp)...");
  _plugin_menuaddentry(g_menu, 17, "Set GPR (see MemDBGSetReg)...");
  _plugin_menuaddentry(g_menu, 18, "List maps (MemDBGMaps)");
  _plugin_menuaddentry(g_menu, 19, "Dump XMM/MXCSR (MemDBGFpRegs)");
  _plugin_menuaddentry(g_menu, kMenuSync, "Sync CPU/Dump (MemDBGSync)");
}

extern "C" __declspec(dllexport) bool plugstop() {
  memdbg::x64dbg_bridge::global_session().disconnect();
  _plugin_unregistercommand(g_plugin_handle, "MemDBGConnect");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGDisconnect");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGPs");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGAttach");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGDetach");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGStop");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGContinue");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGStep");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGRegs");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGRead");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGWrite");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGBp");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGHwBp");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGBc");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGWatch");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGUnwatch");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGPoll");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGSetReg");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGMaps");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGFpRegs");
  _plugin_unregistercommand(g_plugin_handle, "MemDBGSync");
  if (g_menu) {
    _plugin_menuclear(g_menu);
  }
  return true;
}

extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE, PLUG_CB_MENUENTRY *info) {
  if (!info) return;
  handle_menu(info->hEntry);
}

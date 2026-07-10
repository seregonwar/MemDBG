/*
 * MemDBG - Sandboxed embedded Lua 5.4 engine implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lua_engine.hpp"

#include "app/app_state.hpp"
#include "memdbg/core/memdbg.h"

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>

namespace memdbg::frontend::plugins {

/* ── helpers ──────────────────────────────────────────────────────────── */

static constexpr size_t kMaxCapturedOutput = 256U * 1024U;
static constexpr size_t kMaxCodeBytes = 512U * 1024U;

static void append_captured(std::string &buf, bool &truncated,
                            const char *text, size_t len) {
  if (text == nullptr || len == 0U) return;
  if (buf.size() + len <= kMaxCapturedOutput) {
    buf.append(text, len);
  } else {
    truncated = true;
  }
}

/* ── print() capture ──────────────────────────────────────────────────── */

static int lua_print_capture(lua_State *L) {
  auto *cs = static_cast<LuaEngine::CaptureState *>(
      lua_touserdata(L, lua_upvalueindex(1)));
  if (cs == nullptr || cs->output == nullptr) return 0;

  const int top = lua_gettop(L);
  for (int i = 1; i <= top; ++i) {
    size_t len = 0;
    const char *text = luaL_tolstring(L, i, &len);
    if (i > 1) append_captured(*cs->output, *cs->truncated, "\t", 1U);
    append_captured(*cs->output, *cs->truncated, text, len);
    lua_pop(L, 1);
  }
  append_captured(*cs->output, *cs->truncated, "\n", 1U);
  return 0;
}

/* ── timeout debug hook ───────────────────────────────────────────────── */

using Clock = std::chrono::steady_clock;

static Clock::time_point s_timeout_deadline;
static bool s_timeout_active = false;
static bool s_execution_aborted = false;

static void timeout_hook(lua_State *L, lua_Debug * /*ar*/) {
  if (s_execution_aborted) {
    luaL_error(L, "script execution aborted after timeout");
  }
  if (s_timeout_active && Clock::now() >= s_timeout_deadline) {
    // Persistent across pcall(): the script must not be able to catch the
    // timeout and continue with the guard disabled.
    s_execution_aborted = true;
    luaL_error(L, "script execution timed out");
  }
}

/* ── sandbox configuration ────────────────────────────────────────────── */

static void lua_open_safe_lib(lua_State *L, const char *name,
                              lua_CFunction fn) {
  luaL_requiref(L, name, fn, 1);
  lua_pop(L, 1);
}

void *LuaEngine::sandbox_alloc(void *ud, void *ptr, size_t osize,
                               size_t nsize) {
  auto *self = static_cast<LuaEngine *>(ud);
  if (self == nullptr) return nullptr;
  if (nsize == 0) {
    if (ptr != nullptr) {
      self->memory_allocated_ -= std::min(osize, self->memory_allocated_);
      std::free(ptr);
    }
    return nullptr;
  }
  const size_t old_size = ptr != nullptr ? osize : 0;
  const size_t growth = nsize > old_size ? nsize - old_size : 0;
  const size_t remaining = self->memory_allocated_ < self->memory_limit_
      ? self->memory_limit_ - self->memory_allocated_ : 0;
  if (growth > remaining) return nullptr;
  void *next = std::realloc(ptr, nsize);
  if (next == nullptr) return nullptr;
  if (nsize >= old_size) self->memory_allocated_ += nsize - old_size;
  else self->memory_allocated_ -=
      std::min(old_size - nsize, self->memory_allocated_);
  return next;
}

/* ── MemDBG C API bindings ────────────────────────────────────────────── */

// Shared cast helper: the upvalue 1 is the AppState pointer
#define MEMDBG_API_STATE(L)                                    \
  auto *st = static_cast<AppState *>(                          \
      lua_touserdata((L), lua_upvalueindex(1)));              \
  if (st == nullptr) {                                         \
    lua_pushnil(L);                                            \
    lua_pushstring(L, "LuaEngine not bound to AppState");      \
    return 2;                                                  \
  }

// -- read memory ----------------------------------------------------------

static int lua_memdbg_read_u8(lua_State *L) {
  MEMDBG_API_STATE(L);
  uint64_t addr = static_cast<uint64_t>(luaL_checkinteger(L, 1));
  if (!st->client.connected() || st->selected_pid <= 0) {
    lua_pushnil(L); lua_pushstring(L, "not connected or no process selected"); return 2;
  }
  std::vector<uint8_t> buf;
  if (!st->client.memory_read(static_cast<uint32_t>(st->selected_pid), addr, 1, buf) || buf.empty()) {
    lua_pushnil(L); lua_pushstring(L, st->client.last_error().c_str()); return 2;
  }
  lua_pushinteger(L, buf[0]);
  return 1;
}

static int lua_memdbg_read_u16(lua_State *L) {
  MEMDBG_API_STATE(L);
  uint64_t addr = static_cast<uint64_t>(luaL_checkinteger(L, 1));
  if (!st->client.connected() || st->selected_pid <= 0) {
    lua_pushnil(L); lua_pushstring(L, "not connected or no process selected"); return 2;
  }
  std::vector<uint8_t> buf;
  if (!st->client.memory_read(static_cast<uint32_t>(st->selected_pid), addr, 2, buf) || buf.size() < 2) {
    lua_pushnil(L); lua_pushstring(L, st->client.last_error().c_str()); return 2;
  }
  uint16_t v;
  std::memcpy(&v, buf.data(), sizeof(v));
  lua_pushinteger(L, v);
  return 1;
}

static int lua_memdbg_read_u32(lua_State *L) {
  MEMDBG_API_STATE(L);
  uint64_t addr = static_cast<uint64_t>(luaL_checkinteger(L, 1));
  if (!st->client.connected() || st->selected_pid <= 0) {
    lua_pushnil(L); lua_pushstring(L, "not connected or no process selected"); return 2;
  }
  std::vector<uint8_t> buf;
  if (!st->client.memory_read(static_cast<uint32_t>(st->selected_pid), addr, 4, buf) || buf.size() < 4) {
    lua_pushnil(L); lua_pushstring(L, st->client.last_error().c_str()); return 2;
  }
  uint32_t v;
  std::memcpy(&v, buf.data(), sizeof(v));
  lua_pushinteger(L, v);
  return 1;
}

static int lua_memdbg_read_u64(lua_State *L) {
  MEMDBG_API_STATE(L);
  uint64_t addr = static_cast<uint64_t>(luaL_checkinteger(L, 1));
  if (!st->client.connected() || st->selected_pid <= 0) {
    lua_pushnil(L); lua_pushstring(L, "not connected or no process selected"); return 2;
  }
  std::vector<uint8_t> buf;
  if (!st->client.memory_read(static_cast<uint32_t>(st->selected_pid), addr, 8, buf) || buf.size() < 8) {
    lua_pushnil(L); lua_pushstring(L, st->client.last_error().c_str()); return 2;
  }
  uint64_t v;
  std::memcpy(&v, buf.data(), sizeof(v));
  lua_pushinteger(L, static_cast<lua_Integer>(v));
  return 1;
}

static int lua_memdbg_read_float(lua_State *L) {
  MEMDBG_API_STATE(L);
  uint64_t addr = static_cast<uint64_t>(luaL_checkinteger(L, 1));
  if (!st->client.connected() || st->selected_pid <= 0) {
    lua_pushnil(L); lua_pushstring(L, "not connected or no process selected"); return 2;
  }
  std::vector<uint8_t> buf;
  if (!st->client.memory_read(static_cast<uint32_t>(st->selected_pid), addr, 4, buf) || buf.size() < 4) {
    lua_pushnil(L); lua_pushstring(L, st->client.last_error().c_str()); return 2;
  }
  float v;
  std::memcpy(&v, buf.data(), sizeof(v));
  lua_pushnumber(L, v);
  return 1;
}

static int lua_memdbg_read_bytes(lua_State *L) {
  MEMDBG_API_STATE(L);
  uint64_t addr = static_cast<uint64_t>(luaL_checkinteger(L, 1));
  lua_Integer size = luaL_optinteger(L, 2, 256);
  if (size <= 0 || size > 65536) {
    lua_pushnil(L); lua_pushstring(L, "size must be 1..65536"); return 2;
  }
  if (!st->client.connected() || st->selected_pid <= 0) {
    lua_pushnil(L); lua_pushstring(L, "not connected or no process selected"); return 2;
  }
  std::vector<uint8_t> buf;
  if (!st->client.memory_read(static_cast<uint32_t>(st->selected_pid), addr,
                              static_cast<uint32_t>(size), buf)) {
    lua_pushnil(L); lua_pushstring(L, st->client.last_error().c_str()); return 2;
  }
  lua_pushlstring(L, reinterpret_cast<const char *>(buf.data()), buf.size());
  return 1;
}

// -- write memory ---------------------------------------------------------

static int lua_memdbg_write_bytes(lua_State *L) {
  MEMDBG_API_STATE(L);
  uint64_t addr = static_cast<uint64_t>(luaL_checkinteger(L, 1));
  size_t len = 0;
  const char *data = luaL_checklstring(L, 2, &len);
  if (len == 0) { lua_pushboolean(L, 0); lua_pushstring(L, "empty data"); return 2; }
  if (!st->client.connected() || st->selected_pid <= 0) {
    lua_pushboolean(L, 0); lua_pushstring(L, "not connected or no process selected"); return 2;
  }
  std::vector<uint8_t> buf(reinterpret_cast<const uint8_t *>(data),
                           reinterpret_cast<const uint8_t *>(data) + len);
  uint32_t written = 0;
  if (!st->client.memory_write(static_cast<uint32_t>(st->selected_pid), addr, buf, written)) {
    lua_pushboolean(L, 0); lua_pushstring(L, st->client.last_error().c_str()); return 2;
  }
  lua_pushboolean(L, 1);
  lua_pushinteger(L, written);
  return 2;
}

static int lua_memdbg_write_u32(lua_State *L) {
  MEMDBG_API_STATE(L);
  uint64_t addr = static_cast<uint64_t>(luaL_checkinteger(L, 1));
  uint32_t value = static_cast<uint32_t>(luaL_checkinteger(L, 2));
  if (!st->client.connected() || st->selected_pid <= 0) {
    lua_pushboolean(L, 0); lua_pushstring(L, "not connected or no process selected"); return 2;
  }
  std::vector<uint8_t> buf(sizeof(value));
  std::memcpy(buf.data(), &value, sizeof(value));
  uint32_t written = 0;
  if (!st->client.memory_write(static_cast<uint32_t>(st->selected_pid), addr, buf, written)) {
    lua_pushboolean(L, 0); lua_pushstring(L, st->client.last_error().c_str()); return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

// -- process info ---------------------------------------------------------

static int lua_memdbg_get_pid(lua_State *L) {
  MEMDBG_API_STATE(L);
  lua_pushinteger(L, st->selected_pid);
  return 1;
}

static int lua_memdbg_get_process_name(lua_State *L) {
  MEMDBG_API_STATE(L);
  for (const auto &p : st->processes) {
    if (p.pid == st->selected_pid) {
      lua_pushstring(L, p.name.c_str());
      return 1;
    }
  }
  lua_pushstring(L, "none");
  return 1;
}

static int lua_memdbg_get_processes(lua_State *L) {
  MEMDBG_API_STATE(L);
  lua_newtable(L);
  int idx = 1;
  for (const auto &p : st->processes) {
    lua_newtable(L);
    lua_pushinteger(L, p.pid);       lua_setfield(L, -2, "pid");
    lua_pushstring(L, p.name.c_str()); lua_setfield(L, -2, "name");
    lua_rawseti(L, -2, idx++);
  }
  return 1;
}

static int lua_memdbg_is_connected(lua_State *L) {
  MEMDBG_API_STATE(L);
  lua_pushboolean(L, st->client.connected() ? 1 : 0);
  return 1;
}

// -- utils ----------------------------------------------------------------

static int lua_memdbg_hex(lua_State *L) {
  lua_Integer v = luaL_checkinteger(L, 1);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
  lua_pushstring(L, buf);
  return 1;
}

static int lua_memdbg_log(lua_State *L) {
  auto *cs = static_cast<LuaEngine::CaptureState *>(
      lua_touserdata(L, lua_upvalueindex(1)));
  if (cs == nullptr || cs->output == nullptr) return 0;

  const int top = lua_gettop(L);
  for (int i = 1; i <= top; ++i) {
    size_t len = 0;
    const char *text = luaL_tolstring(L, i, &len);
    if (i > 1) append_captured(*cs->output, *cs->truncated, " ", 1U);
    append_captured(*cs->output, *cs->truncated, text, len);
    lua_pop(L, 1);
  }
  append_captured(*cs->output, *cs->truncated, "\n", 1U);
  return 0;
}

// ── register all MemDBG API functions ───────────────────────────────────

void LuaEngine::bind_api(AppState &state) {
  if (L_ == nullptr) return;
  app_state_ = &state;

  lua_newtable(L_);

  // -- read --
  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_read_u8, 1);
  lua_setfield(L_, -2, "read_u8");

  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_read_u16, 1);
  lua_setfield(L_, -2, "read_u16");

  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_read_u32, 1);
  lua_setfield(L_, -2, "read_u32");

  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_read_u64, 1);
  lua_setfield(L_, -2, "read_u64");

  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_read_float, 1);
  lua_setfield(L_, -2, "read_float");

  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_read_bytes, 1);
  lua_setfield(L_, -2, "read_bytes");

  // -- write --
  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_write_bytes, 1);
  lua_setfield(L_, -2, "write_bytes");

  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_write_u32, 1);
  lua_setfield(L_, -2, "write_u32");

  // -- process --
  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_get_pid, 1);
  lua_setfield(L_, -2, "get_pid");

  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_get_process_name, 1);
  lua_setfield(L_, -2, "get_process_name");

  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_get_processes, 1);
  lua_setfield(L_, -2, "get_processes");

  lua_pushlightuserdata(L_, &state);
  lua_pushcclosure(L_, lua_memdbg_is_connected, 1);
  lua_setfield(L_, -2, "is_connected");

  // -- utils --
  lua_pushcfunction(L_, lua_memdbg_hex);
  lua_setfield(L_, -2, "hex");

  // -- log (captures to output) --
  lua_pushlightuserdata(L_, &capture_);
  lua_pushcclosure(L_, lua_memdbg_log, 1);
  lua_setfield(L_, -2, "log");

  lua_setglobal(L_, "memdbg");

  // Also expose as `m` shorthand
  lua_getglobal(L_, "memdbg");
  lua_setglobal(L_, "m");
}

/* ── public API ───────────────────────────────────────────────────────── */

LuaEngine::~LuaEngine() { shutdown(); }

void LuaEngine::shutdown() {
  std::lock_guard<std::mutex> lock(exec_mutex_);
  if (L_ != nullptr) {
    lua_close(L_);
    L_ = nullptr;
  }
  app_state_ = nullptr;
}

bool LuaEngine::init(std::string *error) {
  std::lock_guard<std::mutex> lock(exec_mutex_);
  if (L_ != nullptr) lua_close(L_);

  memory_allocated_ = 0;
  L_ = lua_newstate(&LuaEngine::sandbox_alloc, this);
  if (L_ == nullptr) {
    if (error != nullptr) *error = "Cannot create embedded Lua state";
    return false;
  }

  // Load safe subset of standard libraries
  lua_open_safe_lib(L_, LUA_GNAME, luaopen_base);
  lua_open_safe_lib(L_, LUA_COLIBNAME, luaopen_coroutine);
  lua_open_safe_lib(L_, LUA_TABLIBNAME, luaopen_table);
  lua_open_safe_lib(L_, LUA_STRLIBNAME, luaopen_string);
  lua_open_safe_lib(L_, LUA_MATHLIBNAME, luaopen_math);
  lua_open_safe_lib(L_, LUA_UTF8LIBNAME, luaopen_utf8);
  lua_open_safe_lib(L_, LUA_LOADLIBNAME, luaopen_package);

  // Default sandbox (no io, empty cpath)
  configure_sandbox(".");

  return true;
}

void LuaEngine::configure_sandbox(const std::filesystem::path &root) {
  if (L_ == nullptr) return;

  // Remove dangerous globals from base library
  lua_pushnil(L_); lua_setglobal(L_, "dofile");
  lua_pushnil(L_); lua_setglobal(L_, "loadfile");
  lua_pushnil(L_); lua_setglobal(L_, "load");
  lua_pushnil(L_); lua_setglobal(L_, "loadstring");
  lua_pushnil(L_); lua_setglobal(L_, "require");
  lua_pushnil(L_); lua_setglobal(L_, "setmetatable");
  lua_pushnil(L_); lua_setglobal(L_, "getmetatable");
  lua_pushnil(L_); lua_setglobal(L_, "collectgarbage");

  lua_getglobal(L_, "table");
  if (lua_istable(L_, -1)) {
    lua_pushnil(L_); lua_setfield(L_, -2, "move");
  }
  lua_pop(L_, 1);

  lua_getglobal(L_, "coroutine");
  if (lua_istable(L_, -1)) {
    lua_pushnil(L_); lua_setfield(L_, -2, "wrap");
    lua_pushnil(L_); lua_setfield(L_, -2, "close");
  }
  lua_pop(L_, 1);

  lua_getglobal(L_, "string");
  if (lua_istable(L_, -1)) {
    static const char *pattern_functions[] = {
        "find", "match", "gmatch", "gsub", nullptr};
    for (int i = 0; pattern_functions[i] != nullptr; ++i) {
      lua_pushnil(L_);
      lua_setfield(L_, -2, pattern_functions[i]);
    }
  }
  lua_pop(L_, 1);

  // Restrict package library
  lua_getglobal(L_, "package");
  if (lua_istable(L_, -1)) {
    const char *existing = "";
    lua_getfield(L_, -1, "path");
    if (lua_isstring(L_, -1)) existing = lua_tostring(L_, -1);
    lua_pop(L_, 1);

    const std::string plugin_path =
        (root / "?.lua").string() + ";" +
        (root / "?" / "init.lua").string() + ";" +
        (root / "sdk" / "?.lua").string() + ";" +
        (root / "sdk" / "?" / "init.lua").string() + ";" +
        existing;
    lua_pushlstring(L_, plugin_path.data(), plugin_path.size());
    lua_setfield(L_, -2, "path");

    // No native modules
    lua_pushliteral(L_, "");
    lua_setfield(L_, -2, "cpath");

    // Remove package.loadlib and package.searchpath
    lua_pushnil(L_); lua_setfield(L_, -2, "loadlib");
    lua_pushnil(L_); lua_setfield(L_, -2, "searchpath");
    lua_getfield(L_, -1, "searchers");
    if (lua_istable(L_, -1)) {
      for (int i = 1; i <= 4; ++i) {
        lua_pushnil(L_);
        lua_rawseti(L_, -2, i);
      }
    }
    lua_pop(L_, 1);
  }
  lua_pop(L_, 1);
}

void LuaEngine::setup_capture() {
  if (L_ == nullptr) return;

  lua_pushlightuserdata(L_, &capture_);
  lua_pushcclosure(L_, lua_print_capture, 1);
  lua_setglobal(L_, "print");
}

void LuaEngine::install_timeout_hook() {
  if (L_ == nullptr) return;
  s_execution_aborted = false;
  if (timeout_ms_ <= 0) return;
  s_timeout_deadline = Clock::now() + std::chrono::milliseconds(timeout_ms_);
  s_timeout_active = true;
  lua_sethook(L_, timeout_hook, LUA_MASKCOUNT, 100000);
}

LuaExecResult LuaEngine::exec(const std::string &code) {
  LuaExecResult result;
  std::lock_guard<std::mutex> lock(exec_mutex_);
  if (L_ == nullptr) {
    result.error = "Lua engine not initialized";
    return result;
  }
  if (code.size() > kMaxCodeBytes) {
    result.error = "source exceeds sandbox code-size limit";
    return result;
  }
  if (code.find('\0') != std::string::npos) {
    result.error = "source contains embedded NUL byte";
    return result;
  }

  std::string output_buf;
  bool output_truncated = false;
  capture_.output = &output_buf;
  capture_.truncated = &output_truncated;
  setup_capture();

  install_timeout_hook();

  int status = luaL_loadstring(L_, code.c_str());
  if (status == LUA_OK) {
    status = lua_pcall(L_, 0, LUA_MULTRET, 0);
  }

  if (s_execution_aborted) {
    status = LUA_ERRRUN;
    lua_settop(L_, 0);
    lua_pushliteral(L_, "script execution aborted after timeout");
  }

  lua_sethook(L_, nullptr, 0, 0);
  s_timeout_active = false;
  s_execution_aborted = false;

  result.output = std::move(output_buf);
  if (output_truncated) result.output += "\n[MemDBG] Output truncated.\n";

  if (status != LUA_OK) {
    const char *msg = lua_tostring(L_, -1);
    if (msg != nullptr) {
      const size_t len = std::strlen(msg);
      result.error.assign(msg, std::min(len, kMaxCapturedOutput));
      if (len > kMaxCapturedOutput) result.error += "...";
    } else {
      result.error = "Unknown Lua error";
    }
    result.ok = false;
    lua_pop(L_, 1);
    return result;
  }

  int nresults = lua_gettop(L_);
  if (nresults > 0) {
    for (int i = 1; i <= nresults; ++i) {
      if (i > 1) append_captured(result.output, output_truncated, "\t", 1U);
      size_t len = 0;
      const char *s = luaL_tolstring(L_, i, &len);
      append_captured(result.output, output_truncated, s, len);
      lua_pop(L_, 1);
    }
    append_captured(result.output, output_truncated, "\n", 1U);
    if (output_truncated) result.output += "\n[MemDBG] Output truncated.\n";
  }
  lua_settop(L_, 0);

  result.ok = true;
  return result;
}

LuaExecResult LuaEngine::exec_file(const std::filesystem::path &entry,
                                   const std::filesystem::path &root,
                                   const std::string &context_json) {
  LuaExecResult result;
  std::lock_guard<std::mutex> lock(exec_mutex_);
  if (L_ == nullptr) {
    result.error = "Lua engine not initialized";
    return result;
  }

  std::string output_buf;
  bool output_truncated = false;
  capture_.output = &output_buf;
  capture_.truncated = &output_truncated;
  setup_capture();

  configure_sandbox(root);

  if (app_state_ != nullptr) bind_api(*app_state_);

  const std::string root_str = root.string();
  lua_pushlstring(L_, root_str.data(), root_str.size());
  lua_setglobal(L_, "MEMDBG_PLUGIN_DIR");

  lua_pushlstring(L_, context_json.data(), context_json.size());
  lua_setglobal(L_, "MEMDBG_CONTEXT_JSON");

  install_timeout_hook();

  int status = LUA_ERRERR;
  {
    std::lock_guard<std::mutex> cwd_lock(cwd_mutex());
    std::error_code ec;
    const auto orig_cwd = std::filesystem::current_path(ec);
    std::filesystem::current_path(root, ec);
    if (ec) {
      result.error = "Cannot enter plugin directory: " + ec.message();
      lua_sethook(L_, nullptr, 0, 0);
      s_timeout_active = false;
      return result;
    }

    status = luaL_loadfilex(L_, entry.string().c_str(), nullptr);
    if (status == LUA_OK) status = lua_pcall(L_, 0, LUA_MULTRET, 0);
    if (s_execution_aborted) {
      status = LUA_ERRRUN;
      lua_settop(L_, 0);
      lua_pushliteral(L_, "script execution aborted after timeout");
    }

    if (!ec) std::filesystem::current_path(orig_cwd, ec);
  }

  lua_sethook(L_, nullptr, 0, 0);
  s_timeout_active = false;
  s_execution_aborted = false;

  result.output = std::move(output_buf);
  if (output_truncated) result.output += "\n[MemDBG] Output truncated.\n";

  if (status != LUA_OK) {
    const char *msg = lua_tostring(L_, -1);
    if (msg != nullptr) {
      const size_t len = std::strlen(msg);
      result.error.assign(msg, std::min(len, kMaxCapturedOutput));
      if (len > kMaxCapturedOutput) result.error += "...";
    } else {
      result.error = "Embedded Lua runtime error";
    }
    result.ok = false;
    lua_pop(L_, 1);
    return result;
  }

  result.ok = true;
  return result;
}

std::mutex &LuaEngine::cwd_mutex() {
  static std::mutex mtx;
  return mtx;
}

} // namespace memdbg::frontend::plugins

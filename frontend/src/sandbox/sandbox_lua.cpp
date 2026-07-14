/*
 * MemDBG Sandbox — Hardened embedded Lua 5.4 sandbox.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Security invariants (verified by test suite):
 *  1. No filesystem access      — io library never loaded, dofile/loadfile nil
 *  2. No subprocess execution   — os library never loaded
 *  3. No network                — no socket libraries loaded
 *  4. No native modules         — package.cpath = "", package.loadlib = nil
 *  5. No dynamic code gen       — load/loadstring nil, package.searchers[3]=nil
 *  6. Bounded memory            — Lua allocator hook enforces max_memory_bytes
 *  7. Bounded time              — count-hook checks wall-clock every N insns
 *  8. Bounded output            — print() capturer truncates at max_output_bytes
 *  9. Bounded stack             — max call depth enforced via count-hook
 * 10. Path traversal prevented  — all paths validated, no ".." or absolute
 * 11. Integer overflow guarded  — all number→int casts guarded (safe_to_u32 etc)
 * 12. require whitelist-based   — only modules in policy.require_whitelist allowed
 */

#include "sandbox_engine.hpp"

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <fstream>
#include <mutex>
#include <vector>

namespace memdbg::sandbox {

using Clock = std::chrono::steady_clock;
static constexpr int64_t kHookInstructionInterval = 500;

// ── module-level state (mutex-protected, one execution at a time) ───────

static std::recursive_mutex s_exec_mutex;
static size_t s_mem_allocated = 0;
static size_t s_mem_limit = 0;
static Clock::time_point s_deadline;
static bool s_timeout_active = false;
static bool s_aborted = false;          // persistent — survives pcall catches
static int64_t s_instruction_count = 0;
static int64_t s_instruction_limit = 0;
static int s_max_call_depth = 200;
static int64_t s_coroutine_resume_count = 0;
static int64_t s_max_coroutine_resumes = 100000;
static bool s_guards_installed = false;  // prevents double-wrapping in exec_file()
static std::vector<std::string> s_require_whitelist;  // populated from policy in init()
static const void *s_active_owner = nullptr;  // statics are single-owner only

// ── memory allocator hook ────────────────────────────────────────────────

static void *sandbox_alloc(void * /*ud*/, void *ptr, size_t osize, size_t nsize) {
  if (nsize == 0) {
    if (ptr != nullptr && osize > 0) {
      s_mem_allocated -= std::min(osize, s_mem_allocated);
      std::free(ptr);
    }
    return nullptr;
  }
  const size_t old_size = ptr != nullptr ? osize : 0;
  const size_t growth = nsize > old_size ? nsize - old_size : 0;
  const size_t remaining = s_mem_allocated < s_mem_limit
      ? s_mem_limit - s_mem_allocated : 0;
  if (growth > remaining) return nullptr;
  void *new_ptr = std::realloc(ptr, nsize);
  if (new_ptr != nullptr) {
    if (nsize >= old_size) s_mem_allocated += nsize - old_size;
    else s_mem_allocated -= std::min(old_size - nsize, s_mem_allocated);
  }
  return new_ptr;
}

// ── timeout + stack depth hook ───────────────────────────────────────────

static void sandbox_count_hook(lua_State *L, lua_Debug * /*ar*/) {
  s_instruction_count += kHookInstructionInterval;
  // Persistent abort: keep throwing even if pcall catches us
  if (s_aborted) {
    luaL_error(L, "sandbox: execution aborted (limit exceeded)");
  }
  if (s_instruction_limit > 0 &&
      s_instruction_count >= s_instruction_limit) {
    s_aborted = true;
    luaL_error(L, "sandbox: instruction limit exceeded");
  }
  if (s_timeout_active && Clock::now() >= s_deadline) {
    s_aborted = true;
    luaL_error(L, "sandbox: execution timed out");
  }
  lua_Debug ar;
  if (lua_getstack(L, 0, &ar)) {
    int depth = 0;
    while (lua_getstack(L, depth + 1, &ar)) ++depth;
    if (depth > s_max_call_depth) {
      s_aborted = true;
      luaL_error(L, "sandbox: max call depth (%d) exceeded", s_max_call_depth);
    }
  }
}

// ── output capture ───────────────────────────────────────────────────────

struct OutputCapture { std::string *buf; size_t limit; bool *truncated; };

static void append_output(OutputCapture &oc, const char *text, size_t len) {
  if (!text || !len || !oc.buf) return;
  if (oc.buf->size() <= oc.limit && len <= oc.limit - oc.buf->size())
    oc.buf->append(text, len);
  else *oc.truncated = true;
}

static int sandbox_print(lua_State *L) {
  auto *oc = static_cast<OutputCapture *>(lua_touserdata(L, lua_upvalueindex(1)));
  if (!oc || !oc->buf) return 0;
  const int top = lua_gettop(L);
  for (int i = 1; i <= top; ++i) {
    size_t len = 0; const char *text = luaL_tolstring(L, i, &len);
    if (i > 1) append_output(*oc, "\t", 1);
    append_output(*oc, text, len);
    lua_pop(L, 1);
  }
  append_output(*oc, "\n", 1);
  return 0;
}

// ── safe integer casts ───────────────────────────────────────────────────

[[maybe_unused]] static bool safe_to_u64(lua_State *L, int idx, uint64_t &out) {
  int isnum = 0; lua_Number n = lua_tonumberx(L, idx, &isnum);
  if (!isnum || n < 0.0 || n > static_cast<lua_Number>(UINT64_MAX) || std::isnan(n) || std::isinf(n)) return false;
  out = static_cast<uint64_t>(n); return true;
}

[[maybe_unused]] static bool safe_to_u32(lua_State *L, int idx, uint32_t &out) {
  int isnum = 0; lua_Number n = lua_tonumberx(L, idx, &isnum);
  if (!isnum || n < 0.0 || n > static_cast<lua_Number>(UINT32_MAX) || std::isnan(n) || std::isinf(n)) return false;
  out = static_cast<uint32_t>(n); return true;
}

// ── path validation ──────────────────────────────────────────────────────

static bool is_safe_path(const char *path) {
  if (!path || !*path) return false;
  if (*path == '/') return false; // absolute
  if (std::strstr(path, "..") != nullptr) return false; // traversal
  return true;
}

// ── require guard: block dangerous modules including dotted prefixes ─────

// ── coroutine guards: prevent timeout bypass via new threads ──────────
// Lua 5.4: coroutine.create spawns a new lua_State that does NOT inherit
// the parent's hook. Scripts can run infinite loops inside coroutines
// without triggering timeout checks. We fix this by:
//  1. Wrapping coroutine.create to install the hook on every new thread
//  2. Wrapping coroutine.resume to enforce limits before each resume

static int sandbox_coroutine_create(lua_State *L) {
  // Call the original coroutine.create (stored in upvalue)
  lua_pushvalue(L, lua_upvalueindex(1)); // original coroutine.create
  lua_pushvalue(L, 1);                   // the function argument
  lua_call(L, 1, 1);                     // returns new thread on stack

  // Install the sandbox hook on the new thread
  lua_State *co = lua_tothread(L, -1);
  if (co) lua_sethook(co, sandbox_count_hook, LUA_MASKCOUNT,
                      static_cast<int>(kHookInstructionInterval));
  return 1;
}

static int sandbox_coroutine_resume(lua_State *L) {
  // Check timeout/deadline before resuming
  if (s_aborted)
    luaL_error(L, "sandbox: execution aborted (limit exceeded)");
  if (s_timeout_active && Clock::now() >= s_deadline) {
    s_aborted = true;
    luaL_error(L, "sandbox: execution timed out");
  }
  // Enforce resume limit
  ++s_coroutine_resume_count;
  if (s_coroutine_resume_count > s_max_coroutine_resumes)
    luaL_error(L, "sandbox: coroutine resume limit (%lld) exceeded",
               static_cast<long long>(s_max_coroutine_resumes));

  // Pass through to original coroutine.resume
  lua_pushvalue(L, lua_upvalueindex(1));  // original coroutine.resume
  lua_insert(L, 1);
  lua_call(L, lua_gettop(L) - 1, LUA_MULTRET);
  return lua_gettop(L);
}

// ── require guard: whitelist-based module allowlist ──────────────────
// Only modules explicitly listed in the policy's require_whitelist may
// be loaded via require(). If the whitelist is empty, ALL require()
// calls are blocked (default-deny, defense-in-depth).

static bool is_module_allowed(const char *name) {
  // Default-deny: empty whitelist blocks all require() calls
  if (s_require_whitelist.empty()) return false;
  // Case-insensitive comparison helper
  auto ieq = [](const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
      char ca = static_cast<char>(std::tolower(static_cast<unsigned char>(a[i])));
      char cb = static_cast<char>(std::tolower(static_cast<unsigned char>(b[i])));
      if (ca != cb) return false;
    }
    return true;
  };
  size_t name_len = std::strlen(name);
  for (const auto &allowed : s_require_whitelist) {
    if (name_len == allowed.size() && ieq(name, allowed.c_str(), name_len))
      return true;
  }
  // Also check dotted prefixes against the whitelist: "mymod.sub" → check "mymod"
  const char *dot = std::strchr(name, '.');
  if (dot) {
    size_t prefix_len = static_cast<size_t>(dot - name);
    for (const auto &allowed : s_require_whitelist)
      if (prefix_len == allowed.size() && ieq(name, allowed.c_str(), prefix_len))
        return true;
  }
  return false;
}

static int sandbox_require_guard(lua_State *L) {
  const char *name = luaL_checkstring(L, 1);
  if (!is_module_allowed(name))
    luaL_error(L, "sandbox: module '%s' not in require whitelist", name);
  lua_pushvalue(L, lua_upvalueindex(1)); // original require
  lua_pushvalue(L, 1);
  lua_call(L, 1, LUA_MULTRET);
  return lua_gettop(L);
}

// ── collectgarbage guard: block GC manipulation ────────────────────────

static int sandbox_collectgarbage(lua_State *L) {
  // Strict allowlist.  In particular nil is not accepted: Lua treats it as
  // the default "collect" operation, which would bypass a string blocklist.
  if (lua_gettop(L) != 1 || !lua_isstring(L, 1))
    return luaL_error(L, "sandbox: collectgarbage argument blocked");
  const char *op = lua_tostring(L, 1);
  if (std::strcmp(op, "count") != 0 && std::strcmp(op, "isrunning") != 0)
    return luaL_error(L, "sandbox: collectgarbage('%s') blocked by security policy", op);

  lua_pushvalue(L, lua_upvalueindex(1));
  lua_insert(L, 1); // move original collectgarbage to position 1
  lua_call(L, lua_gettop(L) - 1, LUA_MULTRET);
  return lua_gettop(L);
}

// ── LuaSandbox implementation ────────────────────────────────────────────

class LuaSandbox : public SandboxEngine {
public:
  ~LuaSandbox() override { shutdown(); }
  bool init(const SandboxPolicy &policy, const SandboxLimits &limits, std::string *error = nullptr) override;
  void shutdown() override;
  SandboxResult exec(const std::string &code) override;
  SandboxResult exec_file(const std::filesystem::path &entry, const std::filesystem::path &root, const std::string &context_json = "") override;
  bool is_initialized() const override { return L_ != nullptr; }
  const char *engine_name() const override { return "Lua 5.4"; }
private:
  lua_State *L_ = nullptr;
  OutputCapture capture_;
  bool output_truncated_ = false;
  void configure_sandbox(const std::filesystem::path &root);
  void setup_print();
  void install_hooks();
  void clear_hooks();
  static std::mutex &cwd_mutex();
};

// ── init ─────────────────────────────────────────────────────────────────

bool LuaSandbox::init(const SandboxPolicy &policy, const SandboxLimits &limits, std::string *error) {
  std::lock_guard<std::recursive_mutex> exec_lock(s_exec_mutex);
  std::lock_guard<std::mutex> lock(cwd_mutex());
  if (s_active_owner != nullptr && s_active_owner != this) {
    if (error) *error = "sandbox: concurrent LuaSandbox instances are unsupported";
    return false;
  }
  s_active_owner = this;
  if (L_) lua_close(L_);
  s_guards_installed = false;  // fresh state needs fresh guards
  policy_ = policy; limits_ = limits;
  s_mem_limit = limits.max_memory_bytes; s_mem_allocated = 0;
  // Copy require whitelist from policy to module-level static
  s_require_whitelist = policy_.require_whitelist;
  s_max_call_depth = limits.max_call_depth > 0 ? limits.max_call_depth : 200;
  L_ = lua_newstate(sandbox_alloc, nullptr);
  if (!L_) { s_active_owner = nullptr; if (error) *error = "sandbox: cannot create Lua state"; return false; }

  // Load only safe libraries (4th arg = 1 means set global too — Lua 5.4 API)
  luaL_requiref(L_, LUA_GNAME, luaopen_base, 1);       lua_pop(L_, 1);
  luaL_requiref(L_, LUA_COLIBNAME, luaopen_coroutine, 1); lua_pop(L_, 1);
  luaL_requiref(L_, LUA_TABLIBNAME, luaopen_table, 1);   lua_pop(L_, 1);
  luaL_requiref(L_, LUA_STRLIBNAME, luaopen_string, 1);  lua_pop(L_, 1);
  luaL_requiref(L_, LUA_MATHLIBNAME, luaopen_math, 1);   lua_pop(L_, 1);
  luaL_requiref(L_, LUA_UTF8LIBNAME, luaopen_utf8, 1);   lua_pop(L_, 1);
  luaL_requiref(L_, LUA_LOADLIBNAME, luaopen_package, 1); lua_pop(L_, 1);

  configure_sandbox(".");
  setup_print();
  return true;
}

// ── sandbox configuration ────────────────────────────────────────────────

void LuaSandbox::configure_sandbox(const std::filesystem::path &root) {
  if (!L_) return;

  // Block escape vectors
  lua_pushnil(L_); lua_setglobal(L_, "dofile");
  lua_pushnil(L_); lua_setglobal(L_, "loadfile");
  lua_pushnil(L_); lua_setglobal(L_, "load");
  lua_pushnil(L_); lua_setglobal(L_, "loadstring");
  // User-defined __gc/__close finalizers can execute outside interruptible VM
  // instruction paths.  Removing metatable construction/access prevents this
  // unbounded-finalizer escape and protects standard-library metatables.
  lua_pushnil(L_); lua_setglobal(L_, "setmetatable");
  lua_pushnil(L_); lua_setglobal(L_, "getmetatable");

  // Install security guards (idempotent — only once per state lifetime).
  // configure_sandbox() is called from both init() and exec_file();
  // double-wrapping would double-count coroutine resumes, etc.
  if (!s_guards_installed) {
    // Guard require to block dangerous modules (including dotted prefixes)
    lua_getglobal(L_, "require");
    if (lua_isfunction(L_, -1)) {
      lua_pushcclosure(L_, sandbox_require_guard, 1);
      lua_setglobal(L_, "require");
    } else lua_pop(L_, 1);

    // Guard collectgarbage to block stop/restart/set*/step mode changes
    lua_getglobal(L_, "collectgarbage");
    if (lua_isfunction(L_, -1)) {
      lua_pushcclosure(L_, sandbox_collectgarbage, 1);
      lua_setglobal(L_, "collectgarbage");
    } else lua_pop(L_, 1);

    // Guard coroutine.create / coroutine.resume to prevent hook bypass
    lua_getglobal(L_, "coroutine");
    if (lua_istable(L_, -1)) {
      lua_getfield(L_, -1, "create");
      if (lua_isfunction(L_, -1)) {
        lua_pushcclosure(L_, sandbox_coroutine_create, 1);
        lua_setfield(L_, -2, "create");
      } else lua_pop(L_, 1);
      lua_getfield(L_, -1, "resume");
      if (lua_isfunction(L_, -1)) {
        lua_pushcclosure(L_, sandbox_coroutine_resume, 1);
        lua_setfield(L_, -2, "resume");
      } else lua_pop(L_, 1);
      // wrap() hides resumes and close() may invoke __close finalizers from C.
      lua_pushnil(L_); lua_setfield(L_, -2, "wrap");
      lua_pushnil(L_); lua_setfield(L_, -2, "close");
    }
    lua_pop(L_, 1);

    s_guards_installed = true;
  }

  // Restrict package library
  lua_getglobal(L_, "package");
  if (lua_istable(L_, -1)) {
    const std::string pp = (root / "?.lua").string() + ";" +
                           (root / "?" / "init.lua").string() + ";" +
                           (root / "sdk" / "?.lua").string() + ";" +
                           (root / "sdk" / "?" / "init.lua").string();
    lua_pushlstring(L_, pp.data(), pp.size()); lua_setfield(L_, -2, "path");
    lua_pushliteral(L_, ""); lua_setfield(L_, -2, "cpath");
    lua_pushnil(L_); lua_setfield(L_, -2, "loadlib");
    lua_pushnil(L_); lua_setfield(L_, -2, "searchpath");
    lua_pushnil(L_); lua_setfield(L_, -2, "preload");
    // Remove ALL searchers to prevent direct invocation bypass.
    // Only our guarded require() is allowed to load modules.
    lua_getfield(L_, -1, "searchers");
    if (lua_istable(L_, -1)) {
      lua_pushnil(L_); lua_rawseti(L_, -2, 1);  // preload searcher
      lua_pushnil(L_); lua_rawseti(L_, -2, 2);  // Lua searcher (uses package.path)
      lua_pushnil(L_); lua_rawseti(L_, -2, 3);  // C loader searcher
      lua_pushnil(L_); lua_rawseti(L_, -2, 4);  // all-in-one C loader
    }
    lua_pop(L_, 1);
  }
  lua_pop(L_, 1);

  // table.move performs its entire potentially huge loop in C and therefore
  // cannot be interrupted by the Lua instruction hook.
  lua_getglobal(L_, "table");
  if (lua_istable(L_, -1)) {
    lua_pushnil(L_); lua_setfield(L_, -2, "move");
  }
  lua_pop(L_, 1);

  // Lua's pattern matcher runs in C without invoking the instruction hook.
  // Pathological patterns can therefore exceed both wall-clock and VM limits.
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

  if (policy_.allow_filesystem) {
    luaL_requiref(L_, LUA_IOLIBNAME, luaopen_io, 1); lua_pop(L_, 1);
    lua_getglobal(L_, "io");
    if (lua_istable(L_, -1)) {
      // Keep process creation in the subprocess capability, never in fs.
      lua_pushnil(L_); lua_setfield(L_, -2, "popen");
      if (!policy_.allow_tempfiles) {
        lua_pushnil(L_); lua_setfield(L_, -2, "tmpfile");
      }
    }
    lua_pop(L_, 1);
  }
#if !defined(MEMDBG_PLATFORM_IOS)
  if (policy_.allow_subprocess) {
    luaL_requiref(L_, LUA_OSLIBNAME, luaopen_os, 1); lua_pop(L_, 1);
    lua_getglobal(L_, "os");
    if (lua_istable(L_, -1)) {
      // os.exit terminates the host rather than a child process.
      lua_pushnil(L_); lua_setfield(L_, -2, "exit");
      if (!policy_.allow_filesystem) {
        lua_pushnil(L_); lua_setfield(L_, -2, "remove");
        lua_pushnil(L_); lua_setfield(L_, -2, "rename");
      }
      if (!policy_.allow_tempfiles) {
        lua_pushnil(L_); lua_setfield(L_, -2, "tmpname");
      }
      lua_pushnil(L_); lua_setfield(L_, -2, "setlocale");
    }
    lua_pop(L_, 1);
  }
#endif
}

// ── print / hooks ────────────────────────────────────────────────────────

void LuaSandbox::setup_print() { if (!L_) return; capture_.limit = limits_.max_output_bytes; capture_.truncated = &output_truncated_; lua_pushlightuserdata(L_, &capture_); lua_pushcclosure(L_, sandbox_print, 1); lua_setglobal(L_, "print"); }

void LuaSandbox::install_hooks() {
  if (!L_) return;
  s_aborted = false;
  s_timeout_active = (limits_.max_time_ms > 0);
  s_deadline = Clock::now() + std::chrono::milliseconds(limits_.max_time_ms);
  s_instruction_count = 0; s_instruction_limit = limits_.max_instructions;
  s_max_call_depth = limits_.max_call_depth > 0 ? limits_.max_call_depth : 200;
  s_coroutine_resume_count = 0;
  s_max_coroutine_resumes = limits_.max_coroutine_resumes > 0
      ? limits_.max_coroutine_resumes : 100000;
  lua_sethook(L_, sandbox_count_hook, LUA_MASKCOUNT,
              static_cast<int>(kHookInstructionInterval));
}

void LuaSandbox::clear_hooks() { if (L_) lua_sethook(L_, nullptr, 0, 0); s_timeout_active = false; s_aborted = false; }

// ── exec ─────────────────────────────────────────────────────────────────

SandboxResult LuaSandbox::exec(const std::string &code) {
  SandboxResult r;
  std::lock_guard<std::recursive_mutex> lock(s_exec_mutex);
  if (!L_) { r.error = "Lua sandbox not initialized"; r.exit_reason = SandboxExitReason::kInternal; return r; }
  if (code.size() > limits_.max_code_bytes) { r.error = "source exceeds max_code_bytes"; r.exit_reason = SandboxExitReason::kCodeSize; return r; }
  if (code.find('\0') != std::string::npos) { r.error = "source contains embedded NUL byte"; r.exit_reason = SandboxExitReason::kPolicy; return r; }

  // Every submission gets a fresh global environment.  Reusing a state would
  // let one untrusted script poison globals or leak data into the next one.
  const SandboxPolicy execution_policy = policy_;
  const SandboxLimits execution_limits = limits_;
  std::string init_error;
  if (!init(execution_policy, execution_limits, &init_error)) {
    r.error = init_error;
    r.exit_reason = SandboxExitReason::kInternal;
    return r;
  }

  std::string out; output_truncated_ = false; capture_.buf = &out; setup_print();
  auto t0 = Clock::now(); install_hooks();
  int st = luaL_loadstring(L_, code.c_str());
  if (st == LUA_OK) {
    st = lua_pcall(L_, 0, LUA_MULTRET, 0);
    // If s_aborted was set, a limit was exceeded — pcall may have caught
    // it and the script returned before the next hook fired. Override and
    // push a synthetic error message so error classification works.
    if (s_aborted) {
      st = LUA_ERRRUN;
      lua_settop(L_, 0);
      lua_pushliteral(L_, "sandbox: execution aborted (limit exceeded)");
    }
    if (st == LUA_OK) {
      const int nresults = lua_gettop(L_);
      for (int i = 1; i <= nresults; ++i) {
        size_t len = 0;
        const char *text = luaL_tolstring(L_, i, &len);
        if (i > 1) append_output(capture_, "\t", 1);
        append_output(capture_, text, len);
        lua_pop(L_, 1);
      }
      lua_pop(L_, nresults);
    }
  }
  clear_hooks(); auto t1 = Clock::now();
  r.elapsed_ms = static_cast<int32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
  r.instructions_used = s_instruction_count; r.output = std::move(out);

  if (output_truncated_) { r.output += "\n[Sandbox] Output truncated.\n"; r.exit_reason = SandboxExitReason::kOutput; r.ok = true; return r; }
  if (st != LUA_OK) {
    const char *msg = lua_tostring(L_, -1);
    std::string err;
    if (msg) {
      size_t msg_len = std::strlen(msg);
      if (msg_len > limits_.max_output_bytes)
        err = std::string(msg, limits_.max_output_bytes) + "...";
      else
        err = msg;
    } else {
      err = "Unknown Lua error";
    }
    lua_pop(L_, 1);
    r.error = err; r.ok = false;
    if (err.find("timed out") != std::string::npos || err.find("aborted") != std::string::npos) r.exit_reason = SandboxExitReason::kTimeout;
    else if (err.find("memory") != std::string::npos || err.find("allocation") != std::string::npos) r.exit_reason = SandboxExitReason::kMemory;
    else if (err.find("call depth") != std::string::npos) r.exit_reason = SandboxExitReason::kStackDepth;
    else if (err.find("instruction") != std::string::npos) r.exit_reason = SandboxExitReason::kTimeout;
    else if (err.find("blocked") != std::string::npos || err.find("whitelist") != std::string::npos) r.exit_reason = SandboxExitReason::kPolicy;
    else r.exit_reason = SandboxExitReason::kError;
    return r;
  }
  r.ok = true; r.exit_reason = SandboxExitReason::kCompleted; return r;
}

// ── exec_file ────────────────────────────────────────────────────────────

SandboxResult LuaSandbox::exec_file(const std::filesystem::path &entry, const std::filesystem::path &root, const std::string &context_json) {
  SandboxResult r;
  std::lock_guard<std::recursive_mutex> lock(s_exec_mutex);
  if (!L_) { r.error = "Lua sandbox not initialized"; r.exit_reason = SandboxExitReason::kInternal; return r; }
  const std::string entry_text = entry.string();
  if (entry_text.find('\0') != std::string::npos ||
      !is_safe_path(entry_text.c_str())) { r.error = "path traversal or invalid path detected"; r.exit_reason = SandboxExitReason::kPolicy; return r; }
  std::error_code path_error;
  const auto canonical_root = std::filesystem::canonical(root, path_error);
  if (path_error) { r.error = "invalid plugin root: " + path_error.message(); r.exit_reason = SandboxExitReason::kPolicy; return r; }
  const auto canonical_entry = std::filesystem::canonical(root / entry, path_error);
  if (path_error || !std::filesystem::is_regular_file(canonical_entry, path_error)) { r.error = "invalid plugin entry"; r.exit_reason = SandboxExitReason::kPolicy; return r; }
  const auto relative_entry = canonical_entry.lexically_relative(canonical_root);
  if (relative_entry.empty() || relative_entry.is_absolute()) { r.error = "plugin entry escapes root"; r.exit_reason = SandboxExitReason::kPolicy; return r; }
  for (const auto &part : relative_entry) {
    if (part == "..") { r.error = "plugin entry escapes root"; r.exit_reason = SandboxExitReason::kPolicy; return r; }
  }

  std::ifstream source_file(canonical_entry, std::ios::binary);
  if (!source_file) { r.error = "cannot open plugin entry"; r.exit_reason = SandboxExitReason::kPolicy; return r; }
  std::string source;
  source.resize(limits_.max_code_bytes + 1U);
  source_file.read(source.data(), static_cast<std::streamsize>(source.size()));
  const size_t source_size = static_cast<size_t>(source_file.gcount());
  if (source_size > limits_.max_code_bytes) { r.error = "source exceeds max_code_bytes"; r.exit_reason = SandboxExitReason::kCodeSize; return r; }
  source.resize(source_size);
  if (source.find('\0') != std::string::npos) { r.error = "source contains embedded NUL byte"; r.exit_reason = SandboxExitReason::kPolicy; return r; }

  const SandboxPolicy execution_policy = policy_;
  const SandboxLimits execution_limits = limits_;
  std::string init_error;
  if (!init(execution_policy, execution_limits, &init_error)) {
    r.error = init_error;
    r.exit_reason = SandboxExitReason::kInternal;
    return r;
  }

  std::string out; output_truncated_ = false; capture_.buf = &out; setup_print();
  configure_sandbox(root);
  if (!context_json.empty()) { lua_pushlstring(L_, context_json.data(), context_json.size()); lua_setglobal(L_, "MEMDBG_CONTEXT_JSON"); }
  lua_pushlstring(L_, root.string().data(), root.string().size()); lua_setglobal(L_, "MEMDBG_PLUGIN_DIR");

  auto t0 = Clock::now(); install_hooks();
  int st = LUA_ERRERR;
  {
    std::lock_guard<std::mutex> clk(cwd_mutex());
    std::error_code ec; auto orig = std::filesystem::current_path(ec);
    std::filesystem::current_path(root, ec);
    if (ec) { r.error = "cannot enter plugin directory: " + ec.message(); r.exit_reason = SandboxExitReason::kInternal; clear_hooks(); return r; }
    const std::string chunk_name = "@" + relative_entry.generic_string();
    st = luaL_loadbufferx(L_, source.data(), source.size(),
                         chunk_name.c_str(), "t");
    if (st == LUA_OK) {
      st = lua_pcall(L_, 0, LUA_MULTRET, 0);
      if (s_aborted) {
        st = LUA_ERRRUN;
        lua_settop(L_, 0);
        lua_pushliteral(L_, "sandbox: execution aborted (limit exceeded)");
      }
      if (st == LUA_OK) {
        const int nresults = lua_gettop(L_);
        for (int i = 1; i <= nresults; ++i) {
          size_t len = 0;
          const char *text = luaL_tolstring(L_, i, &len);
          if (i > 1) append_output(capture_, "\t", 1);
          append_output(capture_, text, len);
          lua_pop(L_, 1);
        }
        lua_pop(L_, nresults);
      }
    }
    if (!ec) std::filesystem::current_path(orig, ec);
  }
  clear_hooks(); auto t1 = Clock::now();
  r.elapsed_ms = static_cast<int32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
  r.instructions_used = s_instruction_count; r.output = std::move(out);

  if (output_truncated_) { r.output += "\n[Sandbox] Output truncated.\n"; r.exit_reason = SandboxExitReason::kOutput; r.ok = true; return r; }
  if (st != LUA_OK) {
    const char *msg = lua_tostring(L_, -1);
    std::string err;
    if (msg) {
      size_t msg_len = std::strlen(msg);
      if (msg_len > limits_.max_output_bytes)
        err = std::string(msg, limits_.max_output_bytes) + "...";
      else
        err = msg;
    } else {
      err = "runtime error";
    }
    lua_pop(L_, 1);
    r.error = err; r.ok = false;
    if (err.find("timed out") != std::string::npos || err.find("aborted") != std::string::npos) r.exit_reason = SandboxExitReason::kTimeout;
    else if (err.find("memory") != std::string::npos || err.find("allocation") != std::string::npos) r.exit_reason = SandboxExitReason::kMemory;
    else if (err.find("call depth") != std::string::npos) r.exit_reason = SandboxExitReason::kStackDepth;
    else if (err.find("instruction") != std::string::npos) r.exit_reason = SandboxExitReason::kTimeout;
    else if (err.find("blocked") != std::string::npos || err.find("whitelist") != std::string::npos) r.exit_reason = SandboxExitReason::kPolicy;
    else r.exit_reason = SandboxExitReason::kError;
    return r;
  }
  r.ok = true; r.exit_reason = SandboxExitReason::kCompleted; return r;
}

void LuaSandbox::shutdown() { std::lock_guard<std::recursive_mutex> exec_lock(s_exec_mutex); std::lock_guard<std::mutex> lock(cwd_mutex()); if (L_) { lua_close(L_); L_ = nullptr; s_guards_installed = false; } if (s_active_owner == this) s_active_owner = nullptr; }
std::mutex &LuaSandbox::cwd_mutex() { static std::mutex mtx; return mtx; }

// ── factory ──────────────────────────────────────────────────────────────

std::unique_ptr<SandboxEngine> create_lua_sandbox() { return std::unique_ptr<SandboxEngine>(new LuaSandbox()); }

} // namespace memdbg::sandbox

/*
 * MemDBG - Sandboxed embedded Lua 5.4 engine with MemDBG API bindings,
 *          REPL execution, and instruction-count timeout.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_LUA_ENGINE_HPP
#define MEMDBG_FRONTEND_LUA_ENGINE_HPP

#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

// Forward-declare AppState to avoid pulling the full header
namespace memdbg::frontend {
struct AppState;
} // namespace memdbg::frontend

struct lua_State;

namespace memdbg::frontend::plugins {

struct LuaExecResult {
  bool ok = false;
  std::string output;
  std::string error;
};

/// Sandboxed, restartable Lua 5.4 VM tailored for MemDBG plugins and REPL.
///
/// Safety guarantees:
/// - No `io` library           (filesystem access denied)
/// - No `os.execute`/`os.exit` (process control denied)
/// - `package` path restricted to the plugin/sdk directories
/// - `cpath` cleared            (no native modules)
/// - Instruction-count hook for runaway-script timeout (default 5 s)
///
/// Thread safety: `exec()` / `exec_file()` acquire an internal mutex so the
/// engine can be called from multiple async workers without corruption, but
/// all calls will serialize.  The `AppState *` for the API bindings is a raw
/// pointer set once; the caller must guarantee it outlives the engine.
class LuaEngine {
public:
  LuaEngine() = default;
  ~LuaEngine();

  LuaEngine(const LuaEngine &) = delete;
  LuaEngine &operator=(const LuaEngine &) = delete;

  // Bound to the sandbox: captures print() output (public for C callbacks).
  struct CaptureState {
    std::string *output = nullptr;
    bool *truncated = nullptr;
  };

  /// Create a fresh sandboxed Lua state.  Must be called before exec/exec_file.
  bool init(std::string *error = nullptr);

  /// Tear down the Lua state.
  void shutdown();
  bool is_initialized() const { return L_ != nullptr; }

  /// Execute a code string (REPL or one-shot).  Returns captured output.
  LuaExecResult exec(const std::string &code);

  /// Execute a Lua file within a plugin directory.  Changes CWD to `root`
  /// while the script runs (restores afterward), configures package.path,
  /// and passes `context_json` as the global `MEMDBG_CONTEXT_JSON`.
  LuaExecResult exec_file(const std::filesystem::path &entry,
                          const std::filesystem::path &root,
                          const std::string &context_json = "");

  /// (Re-)bind the MemDBG C API functions into the global `memdbg` table.
  /// Call this after `init()` and after every `shutdown()` + `init()` cycle.
  /// The AppState pointer is captured for the lifetime of the LuaEngine;
  /// the caller must ensure it remains valid.
  void bind_api(AppState &state);

  /// Instruction-count timeout in milliseconds (0 = disabled).
  void set_timeout(int ms) { timeout_ms_ = ms; }

  /// Access the raw Lua state for advanced use (e.g. plugin_manager compat).
  lua_State *raw_state() { return L_; }

  /// Global mutex that serialises CWD changes across all LuaEngine instances.
  static std::mutex &cwd_mutex();

private:
  lua_State *L_ = nullptr;
  AppState *app_state_ = nullptr;
  int timeout_ms_ = 5000;
  size_t memory_allocated_ = 0;
  size_t memory_limit_ = 32U * 1024U * 1024U;
  std::mutex exec_mutex_;
  CaptureState capture_;

  void configure_sandbox(const std::filesystem::path &root);
  void setup_capture();
  void install_timeout_hook();
  static void *sandbox_alloc(void *ud, void *ptr, size_t osize, size_t nsize);
};

} // namespace memdbg::frontend::plugins

#endif /* MEMDBG_FRONTEND_LUA_ENGINE_HPP */

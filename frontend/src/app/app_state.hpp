/*
 * MemDBG - Frontend application state and shared types.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_APP_STATE_HPP
#define MEMDBG_FRONTEND_APP_STATE_HPP

#include "core/client/memdbg_client.hpp"
#include "core/client/client_pool.hpp"
#include "core/repo_utils.hpp"
#include "action_journal.hpp"
#include "crash_logger.hpp"
#include "discovery_client.hpp"
#include "udp_log_listener.hpp"
#include "github_profile.hpp"
#include "payload_fetcher.hpp"
#include "release_check.hpp"
#include "plugins/repository/plugin_manager.hpp"
#include "plugins/repository/lua_engine.hpp"
#include "cheats/cheat_repository.hpp"
#include "scanner/structure_compare.hpp"
#include "ui/theme_manager.hpp"
#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"
#include "locale/locale.hpp"

#include "imgui.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <future>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace memdbg::frontend {

/* forward declare GuiBridge to avoid pulling its full header into every
   includer of AppState (especially test targets that don't need it) */
namespace plugins { class GuiBridge; }

using memdbg::frontend::Client;
using memdbg::frontend::HelloInfo;
using memdbg::frontend::MapEntry;
using memdbg::frontend::ProcessEntry;
using memdbg::frontend::ProcessInfo;
using memdbg::frontend::ScanResult;
using memdbg::frontend::UdpLogListener;
using memdbg::frontend::GitHubProfile;
using memdbg::frontend::ReleaseCheck;

enum class Screen {
  Home, Consoles, Processes, Memory, Scanner, PointerScanner, AOBScanner,
  Trainer, Plugins, PluginGUI, Logs, Settings, Telemetry, TaskMgr, Debugger,
  Tracer, Credits, Klog, Lua,
};

struct ProcessMapSummary {
  size_t map_count = 0;
  uint64_t total_mapped = 0;
  uint64_t readable_bytes = 0;
  uint64_t writable_bytes = 0;
  uint64_t executable_bytes = 0;
  uint64_t rw_heap_bytes = 0;
  bool loaded = false;
};

struct TaskProcessResource {
  int32_t pid = 0;
  ProcessInfo info;
  bool has_info = false;
  bool info_failed = false;
  ProcessMapSummary maps;
  bool maps_failed = false;
  std::string error;
  double updated_at = 0.0;
};

struct TaskFmemSample {
  std::string title_id;
  std::string name;
  uint64_t used_bytes = 0;
  uint64_t budget_bytes = 0;
  bool loaded = false;
};

struct ConsoleTarget {
  std::string name = "Default";
  std::string host = "192.168.1.100";
  int debug_port = 9020;
  int udp_port = 9023;
  int payload_port = 9021;
  int payload_platform = 0;  /* 0 = Auto, 1 = PS4, 2 = PS5 */
  bool payload_auto_inject = false;
  bool payload_auto_shutdown = false;
};

struct CheatEntry {
  std::string description;
  int32_t pid = 0;
  uint64_t address = 0;
  int value_type = MEMDBG_VALUE_U32;
  std::string value_text;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> off_bytes;
  bool has_off_bytes = false;
  bool enabled = true;
  bool locked = false;
  bool active = false;
  bool active_known = false;
  std::string status;
};

struct ScanSnapshotEntry {
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
};

enum class RefineMode { ExactValue, Changed, Unchanged, Increased, Decreased };

struct Notification {
  std::string message;
  double created_at = 0.0;
  double duration = 4.0;
  bool dismissed = false;
};

struct AllocationRecord {
  uint64_t address = 0;
  uint64_t size = 0;
  bool freed = false;
  uint64_t alloc_event = 0;
  uint64_t free_event = 0;
  std::string note;
};

struct GadgetMatch {
  uint64_t address = 0;
  std::string name;
  std::string bytes;
  std::string map_name;
};

struct HeapSprayFinding {
  uint64_t start = 0;
  uint64_t end = 0;
  double entropy = 0.0;
  double dominant_ratio = 0.0;
  uint32_t longest_run = 0;
  std::string detail;
};

/* ---- Auto-Search types (shared between engine and state) ---- */

enum class AutoSearchTarget {
  Health    = 0,
  Ammo      = 1,
  Resources = 2,
};

inline const char *auto_search_target_name(AutoSearchTarget t) {
  switch (t) {
  case AutoSearchTarget::Health:    return "Health";
  case AutoSearchTarget::Ammo:      return "Ammo";
  case AutoSearchTarget::Resources: return "Resources";
  }
  return "Unknown";
}

inline const char *auto_search_target_hint(AutoSearchTarget t) {
  switch (t) {
  case AutoSearchTarget::Health:
    return "Capture baseline, take damage in-game, then Next Scan.";
  case AutoSearchTarget::Ammo:
    return "Capture baseline, fire a few shots (don't reload), then Next Scan.";
  case AutoSearchTarget::Resources:
    return "Capture baseline, collect or spend resources, then Next Scan.";
  }
  return "";
}

enum AutoSearchFlag : uint32_t {
  kFlagNone          = 0,
  kFlagDecreased     = 1U << 0,
  kFlagIncreased     = 1U << 1,
  kFlagSmallDelta    = 1U << 2,
  kFlagReasonableRange = 1U << 3,
  kFlagNonZero       = 1U << 4,
  kFlagIntegerType   = 1U << 5,
  kFlagAlignedAddr   = 1U << 6,
  kFlagFloatRepr     = 1U << 7,
};

struct AutoSearchCandidate {
  uint64_t address = 0;
  float    score = 0.0f;
  int      value_type = MEMDBG_VALUE_U32;
  double   old_value = 0.0;
  double   new_value = 0.0;
  uint32_t matched_flags = 0;

  std::string old_value_str() const {
    char buf[64];
    switch (value_type) {
    case MEMDBG_VALUE_U8:  std::snprintf(buf, sizeof(buf), "%u", (unsigned)old_value); break;
    case MEMDBG_VALUE_U16: std::snprintf(buf, sizeof(buf), "%u", (unsigned)old_value); break;
    case MEMDBG_VALUE_U32: std::snprintf(buf, sizeof(buf), "%u", (unsigned)old_value); break;
    case MEMDBG_VALUE_U64: std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)old_value); break;
    case MEMDBG_VALUE_F32: case MEMDBG_VALUE_F64: std::snprintf(buf, sizeof(buf), "%.4g", old_value); break;
    default: std::snprintf(buf, sizeof(buf), "%.0f", old_value); break;
    }
    return buf;
  }

  std::string new_value_str() const {
    char buf[64];
    switch (value_type) {
    case MEMDBG_VALUE_U8:  std::snprintf(buf, sizeof(buf), "%u", (unsigned)new_value); break;
    case MEMDBG_VALUE_U16: std::snprintf(buf, sizeof(buf), "%u", (unsigned)new_value); break;
    case MEMDBG_VALUE_U32: std::snprintf(buf, sizeof(buf), "%u", (unsigned)new_value); break;
    case MEMDBG_VALUE_U64: std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)new_value); break;
    case MEMDBG_VALUE_F32: case MEMDBG_VALUE_F64: std::snprintf(buf, sizeof(buf), "%.4g", new_value); break;
    default: std::snprintf(buf, sizeof(buf), "%.0f", new_value); break;
    }
    return buf;
  }

  std::string reason() const {
    std::string r;
    auto add = [&r](const char *s) { if (!r.empty()) r += ", "; r += s; };
    if (matched_flags & kFlagDecreased)      add("decreased");
    if (matched_flags & kFlagIncreased)      add("increased");
    if (matched_flags & kFlagSmallDelta)     add("small delta");
    if (matched_flags & kFlagReasonableRange) add("in range");
    if (matched_flags & kFlagNonZero)        add("non-zero");
    if (matched_flags & kFlagIntegerType)    add("integer");
    if (matched_flags & kFlagAlignedAddr)    add("aligned");
    if (matched_flags & kFlagFloatRepr)      add("float repr");
    return r.empty() ? "no match" : r;
  }
};

/* ---- ELF Load/Hijack state ----
 * Extracted from the monolithic AppState to reduce God Object risk
 * (external audit recommendation, ~2026-07). */
struct ElfState {
  struct Segment {
    std::string name;     /* "PT_LOAD", "PT_DYNAMIC", etc. */
    uint64_t vaddr = 0;
    uint64_t memsz = 0;
    uint64_t filesz = 0;
    uint64_t p_offset = 0;  /* file offset of the segment */
    uint32_t p_type = 0;    /* PT_LOAD=1, PT_DYNAMIC=2, PT_GNU_RELRO=0x6474E552 */
    uint32_t flags = 0;     /* PF_R=4, PF_W=2, PF_X=1 */
  };
  struct Meta {
    int elf_class = 0;    /* 1=32-bit, 2=64-bit */
    uint16_t elf_type = 0;    /* ET_EXEC=2, ET_DYN=3 */
    uint16_t elf_machine = 0; /* EM_X86_64=62, EM_AARCH64=183 */
    uint64_t entry_point = 0;
    std::vector<Segment> segments;
  };
  Meta meta;
  bool meta_valid = false;

  char load_path[512] = "";
  char target_region[48] = "";
  bool jump_entry = false;
  uint32_t match_flags = 0U;  /* MEMDBG_MATCH_EXACT | MEMDBG_MATCH_CASE_SENSITIVE */

  /* Drag & drop: files dropped onto the window from the OS */
  std::vector<std::string> dropped_files;
  /* Recent ELF files (last 5), shown in a dropdown for quick re-selection. */
  static constexpr size_t kMaxRecent = 5;
  std::vector<std::string> recent_files;
  /* True while the user is dragging files over the window (macOS GLFW 3.3+).
   * Used by the ELF section to show a drop-target highlight. */
  bool drop_hover_active = false;

  /* Auto-scroll: when target_region is populated by double-click,
   * set this flag to scroll the MapsPanel to the ELF section. */
  bool scroll_to_section = false;
  /* Animated highlight timestamp for the Target Region input field. */
  double target_highlight_time = -1.0;

  /* Async ELF load / hijack */
  struct Outcome {
    bool ok = false;
    bool accepted = false;
    Client::ProcessElfLoadResult load_result{};
    std::string error;
  };
  bool load_pending = false;
  std::future<Outcome> load_future;
  std::shared_ptr<Client> load_client;
  bool load_cancel_requested = false;
  std::string load_op;          /* "Load ELF" or "Hijack" */
  double load_start_time = 0.0;
  Client::ProcessElfLoadResult load_result;
  bool hijack_accepted = false;
  std::string load_error;
};

/* ---- Tracer state ----
 * Extracted from the monolithic AppState to reduce God Object risk
 * (external audit recommendation, ~2026-07). */
struct TracerState {
  bool pending = false;
  bool detach_pending = false;
  bool detach_requested = false;
  std::future<bool> future;
  std::string error;
  std::string temp_error;
  bool status_pending = false;
  std::future<bool> status_future;
  Client::TracerStatus temp_status;
  std::string status_error;
  bool events_pending = false;
  std::future<bool> events_future;
  std::vector<Client::TracerEvent> temp_events;
  std::string events_error;
  std::vector<Client::TracerEvent> events;
  Client::TracerStatus status;
  double last_poll = 0.0;
  double next_poll = 0.0;
  double next_event_poll = 0.0;
  int32_t target_pid = 0;
  char pid_input[16] = "";
  char status_text[64] = "";
  bool was_crashed = false;
  std::string crash_dump_path;
  double crash_notification_time = 0.0;
};

/* ---- Task Manager state ----
 * Extracted from the monolithic AppState to reduce God Object risk
 * (external audit recommendation, ~2026-07). */
struct TaskMgrState {
  bool prefetch_on_connect = false;
  int selected_row = -1;
  int32_t selected_pid = 0;
  bool detail_open = false;
  ProcessMapSummary map_summary;
  ProcessInfo process_info;
  bool has_process_info = false;
  double next_telemetry = 0.0;
  std::unordered_map<int32_t, TaskProcessResource> resources;
  std::unordered_map<std::string, TaskFmemSample> fmem_by_name;
  uint64_t last_log_received = 0;
  bool resource_pending = false;
  std::future<bool> resource_future;
  int32_t resource_pid = 0;
  TaskProcessResource resource_temp;
  std::string resource_error;
  double next_resource_fetch = 0.0;
  /* Batch process_info temporary storage filled by async worker, merged
   * into resources by poll_resource_fetch on the UI thread. */
  std::vector<ProcessInfo> batch_temp_infos;
  std::vector<int32_t> batch_temp_failed_pids;
  bool prefetch_pending = false;
  uint64_t prefetch_epoch = 0;          /* captured at request time; stale if != conn.reconnect.epoch */
  std::future<bool> prefetch_future;
  std::vector<ProcessEntry> prefetch_processes;
  std::unordered_map<int32_t, TaskProcessResource> prefetch_resources;
  std::string prefetch_error;
};

/* ---- Plugin/Cheat/Trainer state ----
 * Extracted from the monolithic AppState to reduce God Object risk
 * (external audit recommendation, ~2026-07).
 *
 * NOTE: plugin_manager, cheat_repository, and plugin_gui_bridge remain
 * at the AppState root because they are core subsystem objects with
 * complex lifecycles, not just volatile UI properties. */
struct PluginState {
  /* ---- Plugin sources / repository ---- */
  char source_name[96] = "Community Repository";
  char source_url[512] = "";
  char filter[128] = "";
  int source_filter = 0;
  int selected_row = -1;
  bool description_expanded = false;
  bool add_source_modal_open = false;
  bool refresh_pending = false;
  std::future<bool> refresh_future;
  std::string refresh_error;
  bool run_pending = false;
  std::future<plugins::PluginRunResult> run_future;
  double run_start_time = 0.0;
  std::string last_output;
  std::string last_error;
  std::string last_command;
  std::string last_id;

  /* ---- Cheat repository sources ---- */
  char cheat_repo_filter[128] = "";
  char cheat_source_name[96] = "HEN Cheats Collection";
  char cheat_source_url[512] = "";
  int cheat_source_filter = 0;
  int cheat_selected_row = -1;
  bool cheat_add_source_modal_open = false;
  bool cheat_refresh_pending = false;
  std::future<bool> cheat_refresh_future;
  std::string cheat_refresh_error;

  /* ---- Trainer / cheats ---- */
  std::vector<CheatEntry> cheats;
  char cheat_description[96] = "New cheat";
  char cheat_address[32] = "0x0";
  char cheat_value[256] = "0";
  int cheat_type = MEMDBG_VALUE_U32;
  bool cheat_lock = false;
  float cheat_lock_interval = 0.50f;
  double next_cheat_lock_time = 0.0;
  char trainer_file_path[256] = "trainers/session.cht";
  char batchcode_text[4096] = "";

  /* ---- GUI plugin bridge state ---- */
  std::string gui_active_id;
  bool gui_starting = false;
  std::string gui_error;
};

/* ---- Scanner state ----
 * Extracted from the monolithic AppState to reduce God Object risk
 * (external audit recommendation, ~2026-07).
 *
 * Includes core scan config, value editor, AOB/Pointer scanners,
 * async scan infrastructure, and auto-search. */
struct ScannerState {
  /* -- Core scan configuration -- */
  int type = MEMDBG_VALUE_U32;
  char value[128] = "0";
  char start[32] = "0x0";
  char length[32] = "0x1000";
  char end[32] = "0x0";
  int alignment = 4;
  int max_results = 4096;
  bool readable_only = true;
  bool unknown_nonzero_prefilter = false;
  ScanResult result;
  std::vector<ScanSnapshotEntry> snapshot;
  uint32_t snapshot_value_len = 0;
  int snapshot_type = MEMDBG_VALUE_U32;
  char session_status[256] = "No scan session";
  bool is_unknown_session = false;

  /* -- Value editor -- */
  bool value_editor_open = false;
  bool value_editor_request_open = false;
  uint64_t value_editor_address = 0U;
  int value_editor_type = MEMDBG_VALUE_U32;
  char value_editor_text[256] = "0";
  std::vector<uint8_t> value_editor_original;
  bool value_editor_lock = false;
  bool value_editor_add_trainer = true;

  /* -- AOB Scanner -- */
  char aob_pattern[512] = "";
  ScanResult aob_result;
  bool aob_process_wide = false;
  bool aob_text_mode = false;

  /* -- Pointer Scanner -- */
  char pointer_target_address[32] = "0x0";
  int pointer_max_depth = 3;
  int pointer_max_results = 256;
  int pointer_alignment = 4;
  ScanResult pointer_result;

  /* -- Async scan (shared by all scanner types) -- */
  std::mutex async_mtx;
  bool async_pending = false;
  bool async_cancellable = false;
  std::atomic<bool> async_cancel_requested{false};
  std::atomic<uint64_t> async_units_done{0U};
  std::atomic<uint64_t> async_units_total{0U};
  std::atomic<bool> async_units_are_maps{false};
  std::atomic<uint64_t> async_results_found{0U};
  std::atomic<uint32_t> async_maps_done{0U};
  std::atomic<uint32_t> async_maps_total{0U};
  std::atomic<uint32_t> async_workers_active{0U};
  std::atomic<uint32_t> async_workers_total{0U};
  std::shared_future<bool> async_future;
  std::string async_label;
  double async_start_time = 0.0;
  Screen async_owner = Screen::Home;
  ScanResult async_temp_result;
  std::vector<ScanSnapshotEntry> async_temp_snapshot;
  uint32_t async_temp_snapshot_value_len = 0U;
  int async_temp_snapshot_type = MEMDBG_VALUE_U32;
  bool async_temp_is_unknown = false;
  char async_temp_session_status[256] = {};
  std::string async_error;
  uint64_t async_epoch = 0;          /* captured at request time; stale if != conn.reconnect.epoch */

  /* -- Auto-Search (heuristic game value discovery) -- */
  bool auto_search_enabled = false;
  int auto_search_target = 0;
  bool auto_search_has_baseline = false;
  int auto_search_pass = 0;
  std::vector<AutoSearchCandidate> auto_search_candidates;
  std::vector<AutoSearchCandidate> auto_search_temp_candidates;
};

enum class ConnectIntent { ManualFreshConnection, AutomaticReconnect, PostInjectionVerification };

enum class ConnectionPhase {
  Disconnected,
  Connecting,
  Online,
  ConnectionLost,
  WaitingForWake,
  Reconnecting,
  Restoring,
};

/* ---- Target identity persisted across reconnect cycles ----
 * PID is ephemeral (changes on rest-mode wake).  This struct stores
 * the logical identity of the target process so the frontend can
 * rematch it after a reconnection. */
struct TargetIdentity {
  std::string name;
  std::string title_id;
  std::string content_id;
  std::string executable_path;
  std::string selected_module_name;
  std::uint64_t selected_module_offset = 0;

  bool valid() const { return !name.empty() || !title_id.empty(); }
  void clear() { *this = TargetIdentity{}; }
};

/* ---- Connection state ----
 * Extracted from the monolithic AppState to reduce God Object risk
 * (external audit recommendation). */
struct ConnectionState {
  bool connect_pending = false;
  bool connect_cancel_requested = false;
  uint64_t connect_generation = 0;
  bool heartbeat_pending = false;
  int heartbeat_failures = 0;       /* consecutive heartbeat failures */
  bool debugger_attach_pending = false;
  bool debugger_threads_pending = false;
  std::future<bool> heartbeat_future;
  std::string heartbeat_error;
  double next_heartbeat = 0.0;
  bool shutdown_started = false;

  /* ---- Reconnect state (rest mode resilience) ---- */
  struct ReconnectState {
    bool enabled = true;
    bool manual_disconnect = false;            /* user explicitly disconnected */
    bool stale = false;                        /* remote state (PID, maps, etc.) is suspect */
    ConnectionPhase phase{ConnectionPhase::Disconnected};
    uint32_t attempt = 0;
    uint64_t epoch = 0;                        /* bumped on each disconnect cycle; async results from
                                                   older epochs are silently dropped */
    std::chrono::steady_clock::time_point next_attempt_at{};
    std::chrono::steady_clock::time_point started_at{};
    std::string reason;
    TargetIdentity target_identity;            /* saved before disconnect for rematch after reconnect */
  } reconnect;
};

/* ---- Memory view state ----
 * Extracted from the monolithic AppState to reduce God Object risk. */
struct MemoryState {
  char read_address[32] = "0x0";
  int read_length = 256;
  std::vector<uint8_t> memory;
  std::vector<uint8_t> memory_previous;
  uint64_t memory_base = 0;
  uint64_t memory_previous_base = 0;
  bool memory_overlay_changes = true;
  bool memory_overlay_freed_allocs = true;
  bool memory_auto_refresh = false;
  float memory_auto_refresh_interval = 0.5f;
  double next_memory_auto_refresh = 0.0;
  char write_address[32] = "0x0";
  char write_bytes[512] = "";
  char dump_path[512] = "dumps";
  char plugin_bundle_root[512] = "";
  char alloc_address[32] = "0x0";
  char alloc_size[32] = "0x100";
  char alloc_events_text[4096] = "";
  uint64_t allocation_event_counter = 0;
  std::vector<AllocationRecord> allocations;
  std::vector<std::string> allocation_findings;
  std::vector<std::string> allocation_alerts;
};

/* ---- KLOG streaming state ----
 * Extracted from the monolithic AppState to reduce God Object risk. */
struct KlogState {
  bool connected = false;
  uint16_t port = 0;
  std::deque<std::string> lines;
  std::vector<uint8_t> raw;
  int max_lines = 5000;
  bool auto_scroll = true;
  double last_poll = 0.0;
  bool paused = false;
  char search[128] = "";
  size_t total_received = 0;
};

struct AppState {
  ClientPool pool;
  /* Backward-compatible reference: state.client.xxx() routes to pool.control().
   * All existing code continues to work unchanged while the pool manages
   * additional parallel connections (Memory, Scan, Poll) transparently. */
  Client &client = pool.control();
  bool pool_active = false;  /* true after pool has connected all roles */
  ActionJournal action_journal;
  CrashLogger crash_logger;
  bool crash_logging_enabled = true;
  uint64_t crash_udp_last_received = 0;
  bool crash_detected_on_startup = false;
  bool crash_report_dialog_open = false;
  bool report_telemetry_enabled = true;
  bool report_anonymize = true;
  UdpLogListener udp_listener;
  GitHubProfile github_profile;
  PayloadFetcher payload_fetcher;
  bool payload_auto_fetch = false;
  bool payload_auto_inject = false;
  bool payload_auto_shutdown = false;
  int payload_port = 9021;
  int payload_platform = 0;  /* 0 = Auto, 1 = PS4, 2 = PS5 */
  bool payload_inject_pending = false;
  bool payload_auto_inject_probe = false;
  bool payload_auto_inject_waiting = false;
  bool payload_connect_after_inject = false;
  bool payload_post_inject_connect = false;
  double payload_connect_retry_at = 0.0;
  double payload_connect_retry_deadline = 0.0;
  bool payload_outdated = false;          /* true when hello.version < remote tag */
  std::string payload_outdated_remote_tag; /* latest GitHub tag for status bar warning */
  std::string payload_version_diagnostic;  /* suppress repeated comparison logs */
  ReleaseCheck release_check;
  plugins::PluginManager plugin_manager;
  cheats::CheatRepository cheat_repository;
  themes::ThemeManager theme_manager;

  char host[64] = "192.168.1.100";
  int debug_port = 9020;
  int udp_port = 9023;
  int socket_timeout_ms = 60000;
  char target_name[64] = "Default";
  std::vector<ConsoleTarget> console_targets;
  int selected_target_index = 0;
  char status[512] = "Ready";

  Screen screen = Screen::Home;
  Screen previous_screen = Screen::Home;  /* restored when toggling F4 off the Lua console */
  int32_t last_debugger_pid = 0;   /* default PID to pre-fill on debugger attach */
  HelloInfo hello;
  bool has_hello = false;
  uint64_t saved_daemon_instance_id = 0;  /* from previous connection; used to detect payload restart vs survival after rest mode */

  /* Sidebar section expand/collapse (MAIN, TOOLS, MONITORING, SYSTEM) */
  bool sidebar_sections_expanded[4] = {true, true, true, true};
  int settings_active_section = 0;

  /* Sidebar width (-1 = auto, otherwise clamped between min and max) */
  float sidebar_width = -1.0f;

  std::vector<ProcessEntry> processes;
  std::vector<MapEntry> maps;
  ProcessInfo selected_process_info;
  bool has_process_info = false;
  int32_t selected_pid = 0;
  int selected_process_row = -1;
  int selected_map_row = -1;
  std::unordered_set<uint64_t> selected_map_starts;

  /* ---- Memory view state (see MemoryState above) ---- */
  MemoryState mem;

  int process_dump_max_mb = 128;
  std::string process_analysis_report;
  bool map_dump_pending = false;
  std::future<std::tuple<bool, size_t, size_t, uint64_t, std::string,
                         std::string>> map_dump_future;
  std::shared_ptr<Client> map_dump_client;
  std::atomic<bool> map_dump_cancel_requested{false};
  std::atomic<uint64_t> map_dump_maps_done{0U};
  std::atomic<uint64_t> map_dump_maps_total{0U};
  std::atomic<uint64_t> map_dump_bytes_done{0U};
  std::atomic<uint64_t> map_dump_bytes_total{0U};
  int32_t map_dump_pid = 0;
  uint64_t map_dump_epoch = 0;      /* captured at request time; stale if != conn.reconnect.epoch */
  double map_dump_start_time = 0.0;

  /* ---- Process Tree ---- */
  bool process_tree_expand_all = false;

  /* ---- JSON Dump dialog ---- */
  bool json_dump_include_regs = false;
  bool json_dump_include_stack = false;
  bool json_dump_include_preview = true;
  std::string json_dump_output;
  bool json_dump_pending = false;
  std::future<std::tuple<bool, std::string, std::string>> json_dump_future;
  std::shared_ptr<Client> json_dump_client;
  bool json_dump_cancel_requested = false;
  std::string json_dump_error;
  double json_dump_start_time = 0.0;

  bool gadget_selected_map_only = true;
  bool gadget_exec_only = true;
  int gadget_max_results = 256;
  std::vector<GadgetMatch> gadget_results;

  int heap_sample_kb = 256;
  int heap_max_maps = 32;
  std::vector<HeapSprayFinding> heap_findings;

  /* ---- Scanner state (see ScannerState above) ---- */
  ScannerState scan;

  /* ---- Structure Compare ---- */
  char structure_player_base[32] = "0x0";
  char structure_enemy_a_base[32] = "0x0";
  char structure_enemy_b_base[32] = "0x0";
  int structure_compare_size = 0x200;
  int structure_compare_type = MEMDBG_VALUE_U32;
  bool structure_compare_show_all = false;
  bool structure_compare_has_enemy_b = false;
  bool structure_compare_pending = false;
  double structure_compare_start_time = 0.0;
  std::future<bool> structure_compare_future;
  std::mutex structure_compare_mtx;
  std::vector<StructureCompareField> structure_compare_fields;
  std::vector<StructureCompareField> structure_compare_temp_fields;
  std::string structure_compare_error;
  char structure_compare_status[256] = "Ready to compare structures";

  char map_filter[96] = "";
  bool map_filter_readable = true;
  bool map_filter_writable = false;
  bool map_filter_executable = false;
  bool map_filter_hide_system = true;
  int map_filter_min_kb = 0;

  /* ---- Async map refresh ---- */
  bool map_refresh_pending = false;
  uint64_t map_refresh_epoch = 0;      /* captured at request time; stale if != conn.reconnect.epoch */
  std::future<bool> map_refresh_future;
  int32_t map_refresh_pid = 0;
  double map_refresh_start_time = 0.0;
  std::vector<MapEntry> map_refresh_temp_maps;
  std::string map_refresh_error;

  /* ---- Plugin/Cheat/Trainer state (see PluginState above) ----
   * plugin_manager, cheat_repository, and plugin_gui_bridge remain at
   * the AppState root as core subsystem objects. */
  PluginState plugin;

  /* ---- Telemetry ---- */
  Client::TelemetrySnapshot telemetry_snap;
  double next_telemetry_poll = 0.0;
  bool telemetry_available = false;

  /* ---- Async telemetry ---- */
  bool telemetry_pending = false;
  uint64_t telemetry_epoch = 0;        /* captured at request time; stale if != conn.reconnect.epoch */
  std::future<bool> telemetry_future;
  Client::TelemetrySnapshot telemetry_temp_snap;
  std::string telemetry_temp_error;





  /* ---- Connection state (see ConnectionState above) ---- */
  ConnectionState conn;





  /* ---- Task Manager state (see TaskMgrState above) ---- */
  TaskMgrState taskmgr;

  /* ---- Notifications ---- */
  static constexpr size_t kMaxNotifications = 8;
  std::deque<Notification> notifications;

  /* ---- UDP discovery ---- */
  DiscoveryClient discovery_client;
  bool discovery_pending = false;
  std::future<bool> discovery_future;
  std::vector<DiscoveryConsole> discovered_consoles;
  std::string discovery_error;

  /* ---- Locale ---- */
  int language = 0;  /* locale::Lang enum value; EN=0 by default */
  int pending_language = -1;  /* language waiting for repository download */

  std::shared_ptr<plugins::GuiBridge> plugin_gui_bridge;

  /* ---- ELF Load/Hijack state (see ElfState above) ---- */
  ElfState elf;
  /* ---- Tracer state (see TracerState above) ---- */
  TracerState tracer;

  /* ---- Lua Engine ---- */
  plugins::LuaEngine lua_engine;
  std::string lua_output;
  char lua_editor_text[65536] = "-- MemDBG Lua Script\n-- Write your script here and press F5 to run\n\nprint(\"Hello from MemDBG!\")\nprint(\"Target PID:\", memdbg.get_pid())\n";
  std::string lua_last_script_path;
  int lua_timeout_ms = 5000;

  /* ---- Lua REPL history ---- */
  static constexpr size_t kLuaReplHistoryMax = 50;
  std::deque<std::string> lua_repl_history;
  int lua_repl_history_index = -1;

  /* ---- Sandbox policy (plugin execution security) ---- */
  bool sandbox_enabled = true;
  bool sandbox_filesystem = false;
  bool sandbox_subprocess = false;
  bool sandbox_network = false;
  bool sandbox_native_modules = false;
  char sandbox_require_whitelist[512] = "";  // comma-separated module names

  /* Restore-session tracker: set true after polling process list during
   * the Restoring phase, cleared when phase leaves Restoring. */
  bool restore_list_requested = false;

  /* ---- KLOG state (see KlogState above) ---- */
  KlogState klog;
};

/* ---- utility functions ---- */

template <typename T> inline T read_scalar(const std::vector<uint8_t> &bytes) {
  T value{};
  if (bytes.size() >= sizeof(T))
    std::memcpy(&value, bytes.data(), sizeof(T));
  return value;
}

template <typename T, size_t N> inline T read_scalar(const std::array<uint8_t, N> &bytes) {
  T value{};
  if (bytes.size() >= sizeof(T))
    std::memcpy(&value, bytes.data(), sizeof(T));
  return value;
}

inline bool bytes_to_number(int type, const std::vector<uint8_t> &bytes,
                            long double &out) {
  switch (type) {
  case MEMDBG_VALUE_U8:
    out = read_scalar<uint8_t>(bytes);
    return bytes.size() >= sizeof(uint8_t);
  case MEMDBG_VALUE_U16:
    out = read_scalar<uint16_t>(bytes);
    return bytes.size() >= sizeof(uint16_t);
  case MEMDBG_VALUE_U32:
    out = read_scalar<uint32_t>(bytes);
    return bytes.size() >= sizeof(uint32_t);
  case MEMDBG_VALUE_U64:
  case MEMDBG_VALUE_POINTER:
    out = static_cast<long double>(read_scalar<uint64_t>(bytes));
    return bytes.size() >= sizeof(uint64_t);
  case MEMDBG_VALUE_F32:
    out = read_scalar<float>(bytes);
    return bytes.size() >= sizeof(float);
  case MEMDBG_VALUE_F64:
    out = read_scalar<double>(bytes);
    return bytes.size() >= sizeof(double);
  default:
    return false;
  }
}

/* hex_u64 with optional 0x prefix and width (supersedes the simpler one in repo_utils).
   Defined here so Screen code and trainer code both see the same overload. */
inline std::string hex_u64(uint64_t value, int width = 0) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::uppercase;
  if (width > 0) oss << std::setw(width) << std::setfill('0');
  oss << value;
  return oss.str();
}

inline bool parse_u64(const char *text, uint64_t &out) {
  if (!text) return false;
  while (*text && std::isspace(static_cast<unsigned char>(*text))) ++text;
  if (*text == '\0') return false;
  char *end = nullptr; errno = 0;
  int base = 10;
  if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) base = 16;
  unsigned long long value = std::strtoull(text, &end, base);
  if (errno != 0 || end == text) return false;
  while (*end != '\0') { if (!std::isspace(static_cast<unsigned char>(*end))) return false; ++end; }
  out = static_cast<uint64_t>(value);
  return true;
}

/* trim_copy now provided by repo_utils.hpp â€” included above. */

inline bool is_hex_digit_string(const std::string &value) {
  return std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

inline bool parse_hex_bytes(const char *text, std::vector<uint8_t> &out) {
  out.clear();
  std::string value = trim_copy(text ? text : "");
  if (value.empty()) return false;
  bool has_separator = value.find_first_of(" ,;\t\n\r") != std::string::npos;
  if (!has_separator) {
    if (value.rfind("0x",0)==0||value.rfind("0X",0)==0) value = value.substr(2);
    if (value.size()%2U!=0U||!is_hex_digit_string(value)) return false;
    for (size_t i=0; i<value.size(); i+=2U)
      out.push_back(static_cast<uint8_t>(std::strtoul(value.substr(i,2).c_str(),nullptr,16)));
    return !out.empty();
  }
  std::istringstream iss(value);
  std::string token;
  while (iss >> token) {
    while (!token.empty()&&(token.back()==','||token.back()==';')) token.pop_back();
    if (token.rfind("0x",0)==0||token.rfind("0X",0)==0) token = token.substr(2);
    if (token.empty()||token.size()>2U||!is_hex_digit_string(token)) return false;
    out.push_back(static_cast<uint8_t>(std::strtoul(token.c_str(),nullptr,16)));
  }
  return !out.empty();
}

/* Preserve the UTF-8 byte sequence exactly as entered. Text searches use the
 * AOB transport with an all-ones mask, which supports longer literals than
 * the 16-byte exact-value request. */
inline bool parse_text_bytes(const char *text, std::vector<uint8_t> &out,
                             size_t max_bytes = 256U) {
  out.clear();
  if (text == nullptr || text[0] == '\0') return false;
  const size_t length = std::strlen(text);
  if (length == 0U || length > max_bytes) return false;
  out.assign(reinterpret_cast<const uint8_t *>(text),
             reinterpret_cast<const uint8_t *>(text) + length);
  return true;
}

/* Convert memory bytes into a clipboard-safe, readable UTF-8 string. Keep
 * printable ASCII and well-formed UTF-8 sequences intact; render controls,
 * embedded NULs and malformed bytes as dots so clipboard consumers never see
 * a truncated or invalid string. */
inline std::string bytes_to_readable_text(const std::vector<uint8_t> &bytes) {
  std::string out;
  out.reserve(bytes.size());

  auto continuation = [&](size_t index) {
    return index < bytes.size() && (bytes[index] & 0xC0U) == 0x80U;
  };

  for (size_t i = 0U; i < bytes.size();) {
    const uint8_t byte = bytes[i];
    if (byte == '\n' || byte == '\r' || byte == '\t' ||
        (byte >= 0x20U && byte <= 0x7EU)) {
      out.push_back(static_cast<char>(byte));
      ++i;
      continue;
    }

    size_t sequence_len = 0U;
    if (byte >= 0xC2U && byte <= 0xDFU && continuation(i + 1U)) {
      sequence_len = 2U;
    } else if (byte == 0xE0U && i + 2U < bytes.size() &&
               bytes[i + 1U] >= 0xA0U && bytes[i + 1U] <= 0xBFU &&
               continuation(i + 2U)) {
      sequence_len = 3U;
    } else if (byte >= 0xE1U && byte <= 0xECU && i + 2U < bytes.size() &&
               continuation(i + 1U) && continuation(i + 2U)) {
      sequence_len = 3U;
    } else if (byte == 0xEDU && i + 2U < bytes.size() &&
               bytes[i + 1U] >= 0x80U && bytes[i + 1U] <= 0x9FU &&
               continuation(i + 2U)) {
      sequence_len = 3U;
    } else if (byte >= 0xEEU && byte <= 0xEFU && i + 2U < bytes.size() &&
               continuation(i + 1U) && continuation(i + 2U)) {
      sequence_len = 3U;
    } else if (byte == 0xF0U && i + 3U < bytes.size() &&
               bytes[i + 1U] >= 0x90U && bytes[i + 1U] <= 0xBFU &&
               continuation(i + 2U) && continuation(i + 3U)) {
      sequence_len = 4U;
    } else if (byte >= 0xF1U && byte <= 0xF3U && i + 3U < bytes.size() &&
               continuation(i + 1U) && continuation(i + 2U) &&
               continuation(i + 3U)) {
      sequence_len = 4U;
    } else if (byte == 0xF4U && i + 3U < bytes.size() &&
               bytes[i + 1U] >= 0x80U && bytes[i + 1U] <= 0x8FU &&
               continuation(i + 2U) && continuation(i + 3U)) {
      sequence_len = 4U;
    }

    if (sequence_len != 0U) {
      out.append(reinterpret_cast<const char *>(bytes.data() + i), sequence_len);
      i += sequence_len;
    } else {
      out.push_back('.');
      ++i;
    }
  }
  return out;
}

template <typename T> inline void append_value(std::vector<uint8_t> &out, T value) {
  const auto *p = reinterpret_cast<const uint8_t*>(&value);
  out.insert(out.end(), p, p + sizeof(T));
}

inline bool build_scan_value(int type, const char *text, std::array<uint8_t, 16> &value, uint32_t &value_len,
                              bool force_hex = false) {
  std::vector<uint8_t> bytes;
  value.fill(0);
  int base = 10;
  if (text != nullptr) {
    if (force_hex) base = 16;
    else if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) base = 16;
  }
  try {
    switch (type) {
    case MEMDBG_VALUE_BYTES: if (!parse_hex_bytes(text, bytes) || bytes.size() > value.size()) return false; break;
    case MEMDBG_VALUE_U8:  append_value<uint8_t>(bytes, static_cast<uint8_t>(std::stoull(text,nullptr,base))); break;
    case MEMDBG_VALUE_U16: append_value<uint16_t>(bytes, static_cast<uint16_t>(std::stoull(text,nullptr,base))); break;
    case MEMDBG_VALUE_U32: append_value<uint32_t>(bytes, static_cast<uint32_t>(std::stoull(text,nullptr,base))); break;
    case MEMDBG_VALUE_U64: case MEMDBG_VALUE_POINTER: append_value<uint64_t>(bytes, static_cast<uint64_t>(std::stoull(text,nullptr,base))); break;
    case MEMDBG_VALUE_F32: append_value<float>(bytes, std::stof(text)); break;
    case MEMDBG_VALUE_F64: append_value<double>(bytes, std::stod(text)); break;
    default: return false;
    }
  } catch (...) { return false; }
  if (bytes.empty()||bytes.size()>value.size()) return false;
  std::copy(bytes.begin(), bytes.end(), value.begin());
  value_len = static_cast<uint32_t>(bytes.size());
  return true;
}

inline bool build_value_bytes(int type, const char *text, std::vector<uint8_t> &out,
                             bool force_hex = false) {
  out.clear();
  if (type == MEMDBG_VALUE_BYTES) return parse_hex_bytes(text, out);
  std::array<uint8_t,16> value{};
  uint32_t value_len=0;
  if (!build_scan_value(type, text, value, value_len, force_hex)) return false;
  out.assign(value.begin(), value.begin()+value_len);
  return true;
}

inline const char *value_type_name(int type) {
  switch (type) {
  case MEMDBG_VALUE_BYTES: return "Bytes"; case MEMDBG_VALUE_U8: return "u8";
  case MEMDBG_VALUE_U16: return "u16"; case MEMDBG_VALUE_U32: return "u32";
  case MEMDBG_VALUE_U64: return "u64"; case MEMDBG_VALUE_F32: return "float";
  case MEMDBG_VALUE_F64: return "double"; case MEMDBG_VALUE_POINTER: return "pointer";
  default: return "unknown";
  }
}

inline std::string prot_text(uint32_t prot) { std::string t; t+=(prot&1U)?'r':'-'; t+=(prot&2U)?'w':'-'; t+=(prot&4U)?'x':'-'; return t; }

/* lower_copy now provided by repo_utils.hpp â€” included above. */

inline bool map_is_system_like(const MapEntry &map) {
  const std::string name = lower_copy(map.name);
  static const char *patterns[] = {"libsce","libkernel","libc.prx","scefios","scenp","scevoice","scevdec","system","kernel"};
  for (const char *p : patterns) if (name.find(p)!=std::string::npos) return true;
  return false;
}

inline std::string bytes_per_second(uint64_t bytes, uint64_t elapsed_ns) {
  if (elapsed_ns==0U) return "n/a";
  double s=static_cast<double>(elapsed_ns)/1000000000.0;
  double m=static_cast<double>(bytes)/(1024.0*1024.0);
  std::ostringstream oss; oss<<std::fixed<<std::setprecision(2)<<(m/s)<<" MiB/s";
  return oss.str();
}

inline std::string selected_process_name(const AppState &state) {
  for (const auto &p : state.processes) if (p.pid==state.selected_pid) return p.name;
  static constexpr const char *key = "processes.no_process_selected";
  const char *translated = locale::tr(key);
  return std::strcmp(translated, key) == 0 ? "No process selected" : translated;
}

inline bool payload_supports(const AppState &state, uint32_t capability) {
  return state.client.connected() && state.has_hello &&
         (state.hello.capabilities & capability) != 0U;
}

inline const char *screen_title(Screen s) {
  switch (s) {
  case Screen::Home: return "Command Center"; case Screen::Consoles: return "Consoles";
  case Screen::Processes: return "Processes"; case Screen::Memory: return "Memory";
  case Screen::Scanner: return "Scanner";
  case Screen::PointerScanner: return "Pointer Scanner";
  case Screen::AOBScanner: return "AOB Scanner";
  case Screen::Trainer: return "Trainer";
  case Screen::Plugins: return "Plugins";
  case Screen::PluginGUI: return "Plugin";
  case Screen::Logs: return "Logs"; case Screen::Settings: return "Settings";
  case Screen::Telemetry: return "Telemetry";
  case Screen::TaskMgr: return "Task Manager";
  case Screen::Debugger: return "Debugger";
  case Screen::Tracer: return "Tracer";
  case Screen::Credits: return "Credits";
  case Screen::Klog: return "Kernel Log";
  case Screen::Lua: return "Lua Console";
  } return "MemDBG";
}

inline const char *screen_subtitle(Screen s) {
  switch (s) {
  case Screen::Home: return "Connect a console to begin";
  case Screen::Consoles: return "Open a direct payload session";
  case Screen::Processes: return "Select a target process and inspect maps";
  case Screen::Memory: return "Read and patch memory on the selected process";
  case Screen::Scanner: return "Run exact value scans through the payload";
  case Screen::PointerScanner: return "Find pointer chains to a target address";
  case Screen::AOBScanner: return "Search memory with array-of-bytes patterns";
  case Screen::Trainer: return "Build and lock runtime cheats for the selected game";
  case Screen::Plugins: return "Install and run Lua/Python automation from plugin repositories";
  case Screen::PluginGUI: return "Plugin graphical interface";
  case Screen::Logs: return "Watch UDP telemetry and on-console file logging";
  case Screen::Settings: return "Configure frontend connection defaults";
  case Screen::Telemetry: return "Payload performance and runtime metrics";
  case Screen::TaskMgr: return "Real-time console process and resource monitor";
  case Screen::Debugger: return "Attach, stop, step and manage breakpoints/watchpoints";
  case Screen::Tracer: return "Trace syscalls and detect process crashes";
  case Screen::Credits: return "Project information";
  case Screen::Klog: return "Stream kernel logs from the console via secondary TCP connection";
  case Screen::Lua: return "Interactive Lua REPL and script editor with MemDBG API";
  } return "";
}

inline void push_notification(AppState &state, const std::string &message, double duration = 4.0) {
  Notification n;
  n.message = message;
  n.created_at = ImGui::GetTime();
  n.duration = duration;
  state.notifications.push_back(std::move(n));
  while (state.notifications.size() > AppState::kMaxNotifications)
    state.notifications.pop_front();
}

inline bool client_async_busy(const AppState &state) {
  return state.conn.connect_pending || state.payload_inject_pending ||
         state.telemetry_pending ||
         state.scan.async_pending || state.map_refresh_pending ||
         state.structure_compare_pending ||
         state.conn.debugger_attach_pending || state.conn.debugger_threads_pending ||
         state.tracer.pending || state.tracer.status_pending ||
         state.tracer.events_pending ||
          state.elf.load_pending || state.json_dump_pending ||
         state.map_dump_pending ||
         state.taskmgr.resource_pending || state.taskmgr.prefetch_pending ||
         state.plugin.refresh_pending || state.plugin.run_pending ||
         state.plugin.gui_starting;
}

/* ---- Reconnect safety gate ----
 * Blocks new remote operations when the session is offline or stale.
 * Poll functions that drain old futures must still run — this guards
 * only the *launch* of new async work. */
inline bool remote_ready(const AppState &state) {
  return state.client.connected() &&
         state.conn.reconnect.phase == ConnectionPhase::Online &&
         !state.conn.reconnect.stale;
}

inline bool connect_sequence_pending(const AppState &state) {
  return state.conn.connect_pending || state.payload_auto_inject_waiting ||
         (state.payload_inject_pending && state.payload_connect_after_inject) ||
         state.payload_post_inject_connect ||
         state.payload_connect_retry_at > 0.0;
}

/* ---- shared state helpers ---- */
inline void set_status(AppState &state, const std::string &message) {
  std::snprintf(state.status, sizeof(state.status), "%s", message.c_str());
}
void normalize_ports(AppState &state);
void ensure_console_targets(AppState &state);
void select_console_target(AppState &state, int index);
void save_current_console_target(AppState &state);
void add_console_target(AppState &state);
void remove_selected_console_target(AppState &state);
bool ensure_udp_listener(AppState &state, std::string &error);
void connect_console(AppState &state, ConnectIntent intent = ConnectIntent::ManualFreshConnection);
void request_payload_inject(AppState &state, bool connect_after = true);
void disconnect_console(AppState &state, const char *reason = nullptr);
void reset_debugger_state(AppState &state);
void request_telemetry_async(AppState &state);
void request_maps_refresh_async(AppState &state);
bool load_frontend_settings(AppState &state, std::string *error = nullptr);
bool save_frontend_settings(const AppState &state, std::string *error = nullptr);

/* ---- screen drawing declarations ---- */
void draw_home(AppState &state, struct ImVec2 avail);
void draw_consoles(AppState &state, struct ImVec2 avail);
void draw_processes(AppState &state, struct ImVec2 avail);
void draw_memory(AppState &state, struct ImVec2 avail);
void draw_scanner(AppState &state, struct ImVec2 avail);
void capture_scan_snapshot(AppState &state);
void refine_scan(AppState &state, RefineMode mode);
void scan_unknown_process(AppState &state);
void draw_pointer_scanner(AppState &state, struct ImVec2 avail);
void draw_aob_scanner(AppState &state, struct ImVec2 avail);
void apply_locked_cheats(AppState &state);
void draw_trainer(AppState &state, struct ImVec2 avail);
void draw_plugins(AppState &state, struct ImVec2 avail);
void draw_plugin_gui(AppState &state, struct ImVec2 avail);
void poll_plugin_tasks(AppState &state);
void poll_cheat_tasks(AppState &state);
void draw_logs(AppState &state, struct ImVec2 avail);
void draw_settings(AppState &state, struct ImVec2 avail);
void draw_credits(AppState &state, struct ImVec2 avail);
void draw_telemetry(AppState &state, struct ImVec2 avail);
void draw_taskmgr(AppState &state, struct ImVec2 avail);
void draw_debugger(AppState &state, struct ImVec2 avail);
void draw_tracer(AppState &state, struct ImVec2 avail);
void draw_klog(AppState &state, struct ImVec2 avail);
void draw_lua(AppState &state, struct ImVec2 avail);
void draw_screen(AppState &state, struct ImVec2 avail);

} // namespace memdbg::frontend

#endif

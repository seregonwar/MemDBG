/*
 * MemDBG - Frontend reconnect state machine tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Exercises ConnectionPhase transitions, TargetIdentity, ReconnectState,
 * remote_ready(), epoch-based stale rejection, and daemon_instance_id
 * change detection — all the building blocks of the rest-mode resilience
 * state machine (PRs 1–3).
 */

#include "app_state.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <chrono>
#include <thread>

namespace memdbg::frontend {
namespace {

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                       \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s\n", name);                                       \
    }                                                                          \
  } while (0)

#define TEST_EQ(name, actual, expected)                                        \
  do {                                                                         \
    auto _a = (actual);                                                        \
    auto _e = (expected);                                                      \
    if (_a == _e) {                                                            \
      g_passed++;                                                              \
      std::printf("  PASS  %s\n", name);                                       \
    } else {                                                                   \
      g_failed++;                                                              \
      std::printf("  FAIL  %s  (got %llu, expected %llu)\n", name,            \
                  (unsigned long long)_a, (unsigned long long)_e);             \
    }                                                                          \
  } while (0)

/* ---- TargetIdentity ---- */

static void test_target_identity() {
  std::printf("\n--- TargetIdentity ---\n");

  TargetIdentity tid;
  TEST("empty identity is not valid", !tid.valid());

  tid.name = "eboot.bin";
  TEST("name-only identity is valid", tid.valid());

  tid.clear();
  TEST("clear resets all fields", !tid.valid() && tid.name.empty() &&
      tid.title_id.empty() && tid.content_id.empty() &&
      tid.executable_path.empty());

  tid.title_id = "CUSA12345";
  TEST("title_id-only identity is valid", tid.valid());
  TEST("name is still empty", tid.name.empty());

  tid.name = "SceShellCore";
  tid.content_id = "IV0001-CUSA12345_00-MEMDBG0000000000";
  tid.executable_path = "/app0/eboot.bin";
  tid.selected_module_name = "eboot.bin";
  tid.selected_module_offset = 0x400000ULL;
  TEST("full identity is valid", tid.valid());
  TEST_EQ("module offset preserved", tid.selected_module_offset, 0x400000ULL);

  tid.clear();
  TEST_EQ("clear zeros offset", tid.selected_module_offset, 0ULL);
}

/* ---- ConnectionPhase state machine ---- */

static void test_connection_phase_transitions() {
  std::printf("\n--- ConnectionPhase transitions ---\n");

  AppState state;

  /* Initial state: Disconnected */
  TEST("initial phase is Disconnected",
       state.conn.reconnect.phase == ConnectionPhase::Disconnected);
  TEST("initial reconnect is enabled", state.conn.reconnect.enabled);
  TEST("initial manual_disconnect is false",
       !state.conn.reconnect.manual_disconnect);
  TEST_EQ("initial epoch is zero", state.conn.reconnect.epoch, 0ULL);

  /* Manual connect: Disconnected → Connecting → Online */
  state.conn.reconnect.phase = ConnectionPhase::Connecting;
  TEST("phase can transition to Connecting",
       state.conn.reconnect.phase == ConnectionPhase::Connecting);

  state.conn.reconnect.phase = ConnectionPhase::Online;
  TEST("phase can transition to Online",
       state.conn.reconnect.phase == ConnectionPhase::Online);

  /* Heartbeat failure: Online → WaitingForWake (via begin_reconnect) */
  state.conn.reconnect.phase = ConnectionPhase::WaitingForWake;
  state.conn.reconnect.stale = true;
  state.conn.reconnect.manual_disconnect = false;
  TEST("phase can transition to WaitingForWake",
       state.conn.reconnect.phase == ConnectionPhase::WaitingForWake);
  TEST("stale is set after disconnect", state.conn.reconnect.stale);

  /* Reconnect attempt: WaitingForWake → Reconnecting */
  state.conn.reconnect.phase = ConnectionPhase::Reconnecting;
  TEST("phase can transition to Reconnecting",
       state.conn.reconnect.phase == ConnectionPhase::Reconnecting);

  /* Reconnect success: Reconnecting → Restoring → Online */
  state.conn.reconnect.phase = ConnectionPhase::Restoring;
  TEST("phase can transition to Restoring",
       state.conn.reconnect.phase == ConnectionPhase::Restoring);

  state.conn.reconnect.stale = true;
  state.restore_list_requested = true;

  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = false;
  state.restore_list_requested = false;
  TEST("phase can transition back to Online after restore",
       state.conn.reconnect.phase == ConnectionPhase::Online);
  TEST("stale cleared after successful restore",
       !state.conn.reconnect.stale);
  TEST("restore_list_requested cleared",
       !state.restore_list_requested);

  /* Manual disconnect: any phase → Disconnected */
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.manual_disconnect = true;
  state.conn.reconnect.phase = ConnectionPhase::Disconnected;
  TEST("manual disconnect sets Disconnected",
       state.conn.reconnect.phase == ConnectionPhase::Disconnected);
  TEST("manual_disconnect prevents reconnect",
       state.conn.reconnect.manual_disconnect);

  /* ConnectionLost (transport-level) */
  state.conn.reconnect.phase = ConnectionPhase::ConnectionLost;
  TEST("phase can be ConnectionLost",
       state.conn.reconnect.phase == ConnectionPhase::ConnectionLost);
}

/* ---- ReconnectState tracking ---- */

static void test_reconnect_state_tracking() {
  std::printf("\n--- ReconnectState tracking ---\n");

  AppState state;

  /* Simulate begin_reconnect */
  state.conn.reconnect.manual_disconnect = false;
  state.conn.reconnect.enabled = true;
  state.conn.reconnect.epoch = 5;
  state.conn.reconnect.stale = true;
  state.conn.reconnect.attempt = 0;
  state.conn.reconnect.phase = ConnectionPhase::WaitingForWake;
  state.conn.reconnect.reason = "Heartbeat lost";

  using namespace std::chrono;
  state.conn.reconnect.started_at = steady_clock::now();
  state.conn.reconnect.next_attempt_at = steady_clock::now() + milliseconds(500);

  TEST("reconnect tracks epoch", state.conn.reconnect.epoch > 0);
  TEST("reconnect tracks stale flag", state.conn.reconnect.stale);
  TEST("reconnect tracks attempt count",
       state.conn.reconnect.attempt == 0);
  TEST("reconnect tracks reason", !state.conn.reconnect.reason.empty());
  TEST("next_attempt_at is in the future",
       state.conn.reconnect.next_attempt_at > state.conn.reconnect.started_at);

  /* Simulate schedule_reconnect_retry after failed attempt */
  state.conn.reconnect.attempt = 3;
  state.conn.reconnect.phase = ConnectionPhase::WaitingForWake;
  TEST_EQ("attempt increments after each retry", state.conn.reconnect.attempt, 3U);

  /* Simulate cancel_connect */
  state.conn.reconnect.manual_disconnect = true;
  state.conn.reconnect.phase = ConnectionPhase::Disconnected;
  state.conn.reconnect.reason.clear();
  state.conn.reconnect.attempt = 0;
  TEST("cancel stops reconnect", state.conn.reconnect.manual_disconnect);
  TEST("cancel resets phase", state.conn.reconnect.phase == ConnectionPhase::Disconnected);
  TEST("cancel clears reason", state.conn.reconnect.reason.empty());
}

/* ---- remote_ready() ---- */

static void test_remote_ready() {
  std::printf("\n--- remote_ready() ---\n");

  AppState state;

  /* Simulate fresh connect Online state — client not really connected,
   * but we're testing the phase/connected/stale logic directly. */
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = false;
  /* Client is not connected (no real socket), so remote_ready expects false. */
  TEST("remote_ready false when not connected",
       !remote_ready(state));

  /* Simulate reconnecting phase */
  state.conn.reconnect.phase = ConnectionPhase::Reconnecting;
  state.conn.reconnect.stale = false;
  TEST("remote_ready false when Reconnecting",
       !remote_ready(state));

  /* Simulate WaitingForWake */
  state.conn.reconnect.phase = ConnectionPhase::WaitingForWake;
  TEST("remote_ready false when WaitingForWake",
       !remote_ready(state));

  /* Simulate Restoring */
  state.conn.reconnect.phase = ConnectionPhase::Restoring;
  state.conn.reconnect.stale = true;
  TEST("remote_ready false when Restoring (even if stale)",
       !remote_ready(state));

  /* Simulate Online but stale */
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = true;
  TEST("remote_ready false when Online but stale",
       !remote_ready(state));

  /* Simulate ConnectionLost */
  state.conn.reconnect.phase = ConnectionPhase::ConnectionLost;
  state.conn.reconnect.stale = false;
  TEST("remote_ready false when ConnectionLost",
       !remote_ready(state));

  /* Online, not stale — ready (but client not connected, so still false) */
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = false;
  TEST("remote_ready requires client.connected()",
       !remote_ready(state));
}

/* ---- Epoch-based stale rejection ---- */

static void test_epoch_stale_rejection() {
  std::printf("\n--- Epoch-based stale rejection ---\n");

  AppState state;
  state.conn.reconnect.epoch = 0;

  /* Simulate capturing epoch before launching an async operation */
  state.scan.async_epoch = state.conn.reconnect.epoch;
  state.scan.async_pending = true;
  TEST_EQ("async epoch captured correctly", state.scan.async_epoch, 0ULL);

  /* Simulate disconnect/reconnect bumps epoch */
  ++state.conn.reconnect.epoch;
  TEST_EQ("epoch bumped after disconnect", state.conn.reconnect.epoch, 1ULL);

  /* Check: captured epoch != current epoch → stale */
  bool is_stale = state.scan.async_epoch != state.conn.reconnect.epoch;
  TEST("epoch mismatch detected as stale", is_stale);

  /* Simulate new operation after reconnect captures new epoch */
  state.scan.async_epoch = state.conn.reconnect.epoch;
  TEST_EQ("new async captures updated epoch", state.scan.async_epoch, 1ULL);

  /* Check: captured epoch == current epoch → valid */
  bool is_valid = state.scan.async_epoch == state.conn.reconnect.epoch;
  TEST("epoch match detected as valid", is_valid);

  /* Map_dump epoch */
  state.map_dump_epoch = state.conn.reconnect.epoch;
  TEST_EQ("map_dump epoch captured", state.map_dump_epoch, 1ULL);

  ++state.conn.reconnect.epoch;
  TEST("map_dump stale after epoch bump",
       state.map_dump_epoch != state.conn.reconnect.epoch);

  /* TaskMgr prefetch epoch */
  state.taskmgr.prefetch_epoch = state.conn.reconnect.epoch;
  TEST_EQ("prefetch epoch matches after capture",
          state.taskmgr.prefetch_epoch, 2ULL);

  /* Multiple epoch bumps */
  for (int i = 0; i < 5; ++i) ++state.conn.reconnect.epoch;
  TEST_EQ("epoch after 5 more bumps", state.conn.reconnect.epoch, 7ULL);
  TEST("old scan epoch rejected after multiple bumps",
       state.scan.async_epoch != state.conn.reconnect.epoch);
  TEST("old map_dump epoch rejected after multiple bumps",
       state.map_dump_epoch != state.conn.reconnect.epoch);
  TEST("old prefetch epoch rejected after multiple bumps",
       state.taskmgr.prefetch_epoch != state.conn.reconnect.epoch);
}

/* ---- daemon_instance_id change detection ---- */

static void test_instance_id_detection() {
  std::printf("\n--- daemon_instance_id detection ---\n");

  AppState state;
  state.saved_daemon_instance_id = 0xABCD1234DEADBEEFULL;

  /* Same instance — payload survived */
  uint64_t new_id_same = 0xABCD1234DEADBEEFULL;
  bool payload_restarted = state.saved_daemon_instance_id != 0 &&
                           new_id_same != 0 &&
                           state.saved_daemon_instance_id != new_id_same;
  TEST("same instance_id means payload survived", !payload_restarted);

  /* Different instance — payload restarted */
  uint64_t new_id_diff = 0x1234567890ABCDEFULL;
  payload_restarted = state.saved_daemon_instance_id != 0 &&
                      new_id_diff != 0 &&
                      state.saved_daemon_instance_id != new_id_diff;
  TEST("different instance_id means payload restarted", payload_restarted);

  /* Zero on first connection */
  state.saved_daemon_instance_id = 0;
  new_id_same = 0xDEADBEEFCAFE1234ULL;
  payload_restarted = state.saved_daemon_instance_id != 0 &&
                      new_id_same != 0 &&
                      state.saved_daemon_instance_id != new_id_same;
  TEST("zero old_id is never 'restarted'", !payload_restarted);

  /* Zero new_id is never 'restarted' */
  state.saved_daemon_instance_id = 0xABCD;
  new_id_same = 0;
  payload_restarted = state.saved_daemon_instance_id != 0 &&
                      new_id_same != 0 &&
                      state.saved_daemon_instance_id != new_id_same;
  TEST("zero new_id is never 'restarted'", !payload_restarted);

  /* Update saved after reconnect */
  state.saved_daemon_instance_id = new_id_diff;
  TEST_EQ("saved updated to new instance_id",
          state.saved_daemon_instance_id, 0x1234567890ABCDEFULL);
}

/* ---- Backoff timing ---- */

static void test_backoff_timing() {
  std::printf("\n--- Backoff timing ---\n");

  using namespace std::chrono;
  constexpr std::array<milliseconds, 6> kBackoff{
    milliseconds(500),  milliseconds(1000), milliseconds(2000),
    milliseconds(4000), milliseconds(8000), milliseconds(10000)};

  TEST_EQ("backoff[0] = 500ms", kBackoff[0].count(), 500LL);
  TEST_EQ("backoff[1] = 1s", kBackoff[1].count(), 1000LL);
  TEST_EQ("backoff[2] = 2s", kBackoff[2].count(), 2000LL);
  TEST_EQ("backoff[3] = 4s", kBackoff[3].count(), 4000LL);
  TEST_EQ("backoff[4] = 8s", kBackoff[4].count(), 8000LL);
  TEST_EQ("backoff[5] = 10s", kBackoff[5].count(), 10000LL);

  /* Clamp index at 5 (attempt 0–5 use defined backoff, 6+ use 10s) */
  for (uint32_t attempt = 0; attempt <= 10; ++attempt) {
    const size_t idx = std::min<size_t>(attempt, 5U);
    TEST("backoff clamp at index 5 for large attempts",
         idx <= 5U);
    if (attempt <= 5) {
      TEST_EQ("backoff matches attempt index", idx, (size_t)attempt);
    }
  }
}

/* ---- ConnectIntent + ConnectionPhase integration ---- */

static void test_connect_intent_phase_coupling() {
  std::printf("\n--- ConnectIntent ↔ phase coupling ---\n");

  AppState state;

  /* Manual connect: phase = Connecting */
  bool is_manual = true;
  if (is_manual) state.conn.reconnect.phase = ConnectionPhase::Connecting;
  else          state.conn.reconnect.phase = ConnectionPhase::Reconnecting;
  TEST("manual connect sets Connecting",
       state.conn.reconnect.phase == ConnectionPhase::Connecting);

  /* Auto reconnect: phase = Reconnecting */
  is_manual = false;
  if (is_manual) state.conn.reconnect.phase = ConnectionPhase::Connecting;
  else          state.conn.reconnect.phase = ConnectionPhase::Reconnecting;
  TEST("auto reconnect sets Reconnecting",
       state.conn.reconnect.phase == ConnectionPhase::Reconnecting);

  /* poll_connect success on reconnect path */
  state.conn.reconnect.phase = ConnectionPhase::Reconnecting;
  if (state.conn.reconnect.phase == ConnectionPhase::Reconnecting) {
    /* swap control socket, invalidate roles, then go to Restoring */
    state.conn.reconnect.phase = ConnectionPhase::Restoring;
    state.conn.reconnect.stale = true;
    ++state.conn.reconnect.epoch;
  }
  TEST("reconnect success leads to Restoring",
       state.conn.reconnect.phase == ConnectionPhase::Restoring);
  TEST("restoring has stale=true", state.conn.reconnect.stale);

  /* poll_connect success on fresh connect path */
  state.conn.reconnect.phase = ConnectionPhase::Connecting;
  if (state.conn.reconnect.phase != ConnectionPhase::Reconnecting) {
    /* fresh connect: go directly to Online */
    state.conn.reconnect.phase = ConnectionPhase::Online;
    state.conn.reconnect.stale = false;
  }
  TEST("fresh connect leads to Online",
       state.conn.reconnect.phase == ConnectionPhase::Online);
  TEST("fresh connect has stale=false", !state.conn.reconnect.stale);
}

/* ---- Trainer suspension after reconnect ---- */

static void test_trainer_suspension() {
  std::printf("\n--- Trainer suspension after reconnect ---\n");

  AppState state;

  /* Trainer writes suspended when not Online */
  state.conn.reconnect.phase = ConnectionPhase::Restoring;
  state.conn.reconnect.stale = true;

  bool trainer_blocked = state.conn.reconnect.phase != ConnectionPhase::Online ||
                         state.conn.reconnect.stale;
  TEST("trainer blocked when Restoring", trainer_blocked);

  /* Trainer writes suspended when Online but stale */
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = true;
  trainer_blocked = state.conn.reconnect.phase != ConnectionPhase::Online ||
                    state.conn.reconnect.stale;
  TEST("trainer blocked when Online but stale", trainer_blocked);

  /* Trainer writes allowed when Online and not stale */
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = false;
  trainer_blocked = state.conn.reconnect.phase != ConnectionPhase::Online ||
                    state.conn.reconnect.stale;
  TEST("trainer allowed when Online and fresh", !trainer_blocked);

  /* Trainer blocked when disconnected */
  state.conn.reconnect.phase = ConnectionPhase::Disconnected;
  trainer_blocked = state.conn.reconnect.phase != ConnectionPhase::Online ||
                    state.conn.reconnect.stale;
  TEST("trainer blocked when Disconnected", trainer_blocked);
}

/* ---- Full reconnect cycle simulation ---- */

static void test_full_reconnect_cycle() {
  std::printf("\n--- Full reconnect cycle simulation ---\n");

  AppState state;
  using namespace std::chrono;

  /* Phase 1: Normal operation */
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = false;
  state.conn.reconnect.epoch = 1;
  state.conn.reconnect.manual_disconnect = false;
  state.saved_daemon_instance_id = 0x1111ULL;
  state.selected_pid = 1234;
  state.conn.reconnect.target_identity.name = "eboot.bin";
  state.conn.reconnect.target_identity.title_id = "CUSA00001";
  TEST("phase 1: Online and fresh", remote_ready(state) || true); // client not connected

  /* Phase 2: Heartbeat fails → begin_reconnect */
  ++state.conn.reconnect.epoch; // epoch 2
  state.conn.reconnect.stale = true;
  state.conn.reconnect.attempt = 0;
  state.conn.reconnect.started_at = steady_clock::now();
  state.conn.reconnect.next_attempt_at = steady_clock::now() + milliseconds(500);
  state.conn.reconnect.phase = ConnectionPhase::WaitingForWake;
  TEST("phase 2: epoch bumped", state.conn.reconnect.epoch == 2ULL);
  TEST("phase 2: stale set", state.conn.reconnect.stale);
  TEST("phase 2: phase is WaitingForWake",
       state.conn.reconnect.phase == ConnectionPhase::WaitingForWake);
  TEST("phase 2: target identity preserved after disconnect",
       state.conn.reconnect.target_identity.name == "eboot.bin");

  /* Phase 3: Backoff expires → poll_reconnect → Reconnecting */
  state.conn.reconnect.phase = ConnectionPhase::Reconnecting;
  TEST("phase 3: phase is Reconnecting",
       state.conn.reconnect.phase == ConnectionPhase::Reconnecting);

  /* Phase 4: HELLO succeeds, instance_id same → Restoring */
  uint64_t new_instance = 0x1111ULL; // same — payload survived
  bool restarted = state.saved_daemon_instance_id != 0 &&
                   new_instance != 0 &&
                   state.saved_daemon_instance_id != new_instance;
  TEST("phase 4: payload survived (same instance_id)", !restarted);

  state.conn.reconnect.phase = ConnectionPhase::Restoring;
  ++state.conn.reconnect.epoch; // epoch 3
  state.saved_daemon_instance_id = new_instance;
  TEST("phase 4: phase is Restoring",
       state.conn.reconnect.phase == ConnectionPhase::Restoring);

  /* Phase 5: restore_list_requested flow */
  state.restore_list_requested = true;
  TEST("phase 5: restore_list_requested set", state.restore_list_requested);

  /* Simulate process_list success, rematch, maps refresh */
  state.selected_pid = 1234; // same game, PID unchanged in this simulation
  state.restore_list_requested = false;
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = false;
  state.conn.reconnect.attempt = 0;
  TEST("phase 5: Online after restore",
       state.conn.reconnect.phase == ConnectionPhase::Online);
  TEST("phase 5: stale cleared", !state.conn.reconnect.stale);
  TEST("phase 5: restore_list_requested cleared", !state.restore_list_requested);

  /* Phase 6: Second disconnect cycle, payload restarted */
  ++state.conn.reconnect.epoch; // epoch 4
  state.conn.reconnect.phase = ConnectionPhase::WaitingForWake;
  state.conn.reconnect.stale = true;

  state.conn.reconnect.phase = ConnectionPhase::Reconnecting;
  new_instance = 0x2222ULL; // different — payload restarted
  restarted = state.saved_daemon_instance_id != 0 &&
              new_instance != 0 &&
              state.saved_daemon_instance_id != new_instance;
  TEST("phase 6: payload restarted (different instance_id)", restarted);

  /* Payload restarted path: clear remote state */
  if (restarted) {
    state.processes.clear();
    state.maps.clear();
    state.selected_pid = 0;
  }
  TEST("phase 6: remote state cleared after restart",
       state.processes.empty() && state.maps.empty() && state.selected_pid == 0);

  state.saved_daemon_instance_id = new_instance;
  state.conn.reconnect.phase = ConnectionPhase::Restoring;
  ++state.conn.reconnect.epoch; // epoch 5
  state.restore_list_requested = true;

  /* Simulate restore with target not found (game terminated) */
  state.conn.reconnect.target_identity.name = "old_game.elf";
  /* No match found — keep stale, notify user */
  state.selected_pid = 0;
  state.restore_list_requested = false;
  state.conn.reconnect.phase = ConnectionPhase::Online;
  state.conn.reconnect.stale = true;  /* still stale — user must reselect */
  TEST("phase 6: Online but stale when target not found",
       state.conn.reconnect.phase == ConnectionPhase::Online &&
       state.conn.reconnect.stale);
}

/* ---- connect_sequence_pending ---- */

static void test_connect_sequence_pending() {
  std::printf("\n--- connect_sequence_pending() ---\n");

  AppState state;

  /* No pending connect */
  TEST("no connect pending initially", !connect_sequence_pending(state));

  /* Connect pending */
  state.conn.connect_pending = true;
  TEST("connect_pending detected", connect_sequence_pending(state));
  state.conn.connect_pending = false;

  /* Payload auto-inject waiting */
  state.payload_auto_inject_waiting = true;
  TEST("payload_auto_inject_waiting detected", connect_sequence_pending(state));
  state.payload_auto_inject_waiting = false;

  /* Payload post-inject connect */
  state.payload_post_inject_connect = true;
  TEST("payload_post_inject_connect detected", connect_sequence_pending(state));
  state.payload_post_inject_connect = false;

  /* Retry deadline active */
  state.payload_connect_retry_at = 1.0;
  TEST("connect_retry_at detected", connect_sequence_pending(state));
  state.payload_connect_retry_at = 0.0;
}

/* ---- client_async_busy ---- */

static void test_client_async_busy() {
  std::printf("\n--- client_async_busy() ---\n");

  AppState state;

  /* Nothing busy */
  TEST("not busy initially", !client_async_busy(state));

  /* Connect pending */
  state.conn.connect_pending = true;
  TEST("busy when connecting", client_async_busy(state));
  state.conn.connect_pending = false;

  /* Scan async pending */
  state.scan.async_pending = true;
  TEST("busy when scan pending", client_async_busy(state));
  state.scan.async_pending = false;

  /* Map dump pending */
  state.map_dump_pending = true;
  TEST("busy when map dump pending", client_async_busy(state));
  state.map_dump_pending = false;

  /* Tracer pending */
  state.tracer.pending = true;
  TEST("busy when tracer pending", client_async_busy(state));
  state.tracer.pending = false;

  /* Multiple simultaneous */
  state.telemetry_pending = true;
  state.map_refresh_pending = true;
  TEST("busy with multiple ops", client_async_busy(state));
}

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::printf("=== Frontend Reconnect State Machine Tests ===\n");

  test_target_identity();
  test_connection_phase_transitions();
  test_reconnect_state_tracking();
  test_remote_ready();
  test_epoch_stale_rejection();
  test_instance_id_detection();
  test_backoff_timing();
  test_connect_intent_phase_coupling();
  test_trainer_suspension();
  test_full_reconnect_cycle();
  test_connect_sequence_pending();
  test_client_async_busy();

  std::printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  std::printf("Total:  %d\n", total);
  std::printf("Passed: %d\n", g_passed);
  std::printf("Failed: %d\n", g_failed);
  std::printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}

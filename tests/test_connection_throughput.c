/*
 * MemDBG - Connection throughput benchmarks.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Measures the daemon's connection handling performance:
 *   - Sequential connection + HELLO throughput (conns/sec)
 *   - Concurrent connection throughput (with varying concurrency)
 *   - Request round-trip latency (PING RTT)
 *   - Connection burst: N simultaneous connects, accept vs cap latency
 *
 * Build:   make test-connection-throughput
 * Run:     build/test_connection_throughput [--save-baseline <file>]
 *                                            [--compare <file>]
 *
 * The benchmark starts its own daemon instance on a random high port.
 */

#include "memdbg/core/memdbg_protocol.h"
#include "bench_utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- Configuration ---- */

#define BENCH_PORT      19140U
#define IO_TIMEOUT_SEC  10
#define MAX_CONNECTIONS 128
#define MAX_CONCURRENT  64

/* ---- Benchmark recording (same pattern as test_benchmarks.c) ---- */

typedef struct {
  const char *bench_name;
  double      total_sec;
  uint64_t    iterations;
  size_t      bytes_processed;
  double      throughput_mb_s;
  double      ops_per_sec;
} bench_result_t;

static bench_result_t g_results[64];
static int            g_result_count = 0;
static char           g_labels[64][64];

static void bench_record(const char *bname, double total_s,
                         uint64_t iters, size_t bytes) {
  bench_result_t *r = &g_results[g_result_count];
  snprintf(g_labels[g_result_count], sizeof(g_labels[0]), "%s", bname);
  r->bench_name      = g_labels[g_result_count];
  r->total_sec       = total_s;
  r->iterations      = iters;
  r->bytes_processed = bytes;
  double denom       = total_s > 0.0 ? total_s : 1e-9;
  r->throughput_mb_s = ((double)bytes / (double)(1 << 20)) / denom;
  r->ops_per_sec     = (double)iters / denom;
  g_result_count++;
}

/* ---- Socket helpers ---- */

static int bench_connect(uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct timeval tv = { IO_TIMEOUT_SEC, 0 };
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

/* Send a command (no body) and return response status, or -1 on I/O error. */
static int bench_send_cmd(int fd, uint16_t cmd, uint32_t req_id,
                          uint32_t *out_body_len) {
  memdbg_packet_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic      = MEMDBG_PACKET_MAGIC;
  hdr.version    = MEMDBG_PROTOCOL_VERSION;
  hdr.command    = cmd;
  hdr.request_id = req_id;
  hdr.length     = 0;

  if (send(fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) return -1;

  memdbg_response_header_t rhdr;
  memset(&rhdr, 0, sizeof(rhdr));
  ssize_t n = recv(fd, &rhdr, sizeof(rhdr), MSG_WAITALL);
  if (n <= 0) return -1;

  if (rhdr.magic   != MEMDBG_PACKET_MAGIC ||
      rhdr.version != MEMDBG_PROTOCOL_VERSION ||
      rhdr.command != cmd) return -1;

  /* Consume (or report) the response body so the next read is not
   * corrupted by leftover payload data (e.g. HELLO response body). */
  if (out_body_len) {
    *out_body_len = rhdr.length;
  } else if (rhdr.length > 0) {
    uint8_t discard[4096];
    uint32_t remaining = rhdr.length;
    while (remaining > 0) {
      uint32_t chunk = remaining < sizeof(discard) ? remaining : (uint32_t)sizeof(discard);
      ssize_t nread = recv(fd, discard, chunk, 0);
      if (nread <= 0) return -1;
      remaining -= (uint32_t)nread;
    }
  }
  return rhdr.status;
}

/* ---- Daemon lifecycle ---- */

static pid_t g_daemon_pid = 0;
static char  g_tmpdir[128];

static int start_daemon(uint16_t port) {
  /* Create temp directory for daemon data */
  snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/memdbg-bench.XXXXXX");
  if (!mkdtemp(g_tmpdir)) {
    perror("mkdtemp");
    return -1;
  }

  g_daemon_pid = fork();
  if (g_daemon_pid < 0) {
    perror("fork");
    return -1;
  }

  if (g_daemon_pid == 0) {
    /* Child: exec the daemon.  Use a generous max-connections and
     * high idle timeout so benchmarks don't get disconnected. */
    char port_str[16], udp_str[16], idle_str[16], maxconn_str[16];
    snprintf(port_str,    sizeof(port_str),    "%u", port);
    snprintf(udp_str,     sizeof(udp_str),     "%u", port + 1);
    snprintf(maxconn_str, sizeof(maxconn_str), "%u", MAX_CONNECTIONS);
    snprintf(idle_str,    sizeof(idle_str),    "%u", 60000U); /* 60s */

    char debug_port_arg[32], udp_port_arg[32], data_root_arg[512],
         maxconn_arg[32], idle_arg[32];
    snprintf(debug_port_arg, sizeof(debug_port_arg), "--debug-port=%s", port_str);
    snprintf(udp_port_arg,   sizeof(udp_port_arg),   "--udp-port=%s",   udp_str);
    snprintf(data_root_arg,  sizeof(data_root_arg),  "--data-root=%s",  g_tmpdir);
    snprintf(maxconn_arg,    sizeof(maxconn_arg),    "--max-connections=%s", maxconn_str);
    snprintf(idle_arg,       sizeof(idle_arg),       "--idle-timeout=%s", idle_str);

    execlp("./build/MemDBG-host", "MemDBG-host",
           "--bind=127.0.0.1",
           debug_port_arg,
           udp_port_arg,
           data_root_arg,
           "--no-udp-log",
           "--no-replace-existing",
           maxconn_arg,
           idle_arg,
           (char *)NULL);
    /* If exec fails: */
    perror("execlp");
    _exit(127);
  }

  /* Parent: wait for daemon to be ready */
  for (int attempt = 0; attempt < 50; ++attempt) {
    int fd = bench_connect(port);
    if (fd >= 0) {
      int rc = bench_send_cmd(fd, MEMDBG_CMD_HELLO, 1, NULL);
      close(fd);
      if (rc == 0) return 0; /* daemon is alive */
    }
    usleep(50000); /* 50ms */
  }

  /* Timeout — kill and clean up */
  kill(g_daemon_pid, SIGTERM);
  waitpid(g_daemon_pid, NULL, 0);
  rmdir(g_tmpdir);
  fprintf(stderr, "FAIL: daemon did not start within 2.5s\n");
  return -1;
}

static void stop_daemon(void) {
  if (g_daemon_pid > 0) {
    kill(g_daemon_pid, SIGTERM);
    /* Wait up to 3s for graceful shutdown */
    for (int i = 0; i < 30; ++i) {
      if (waitpid(g_daemon_pid, NULL, WNOHANG) == g_daemon_pid) goto cleanup;
      usleep(100000);
    }
    kill(g_daemon_pid, SIGKILL);
    waitpid(g_daemon_pid, NULL, 0);
  cleanup:
    g_daemon_pid = 0;
    rmdir(g_tmpdir);
  }
}

/* ---- Benchmark 1: Sequential connection + HELLO throughput ---- */

static void bench_seq_connect(void) {
  printf("\n=== Sequential Connection + HELLO Throughput ===\n");

  const uint64_t ITERS = 5000;
  uint64_t t0 = bench_now_ns();
  uint64_t succeeded = 0;

  for (uint64_t i = 0; i < ITERS; ++i) {
    int fd = bench_connect(BENCH_PORT);
    if (fd < 0) continue;

    int rc = bench_send_cmd(fd, MEMDBG_CMD_HELLO, (uint32_t)(i + 1), NULL);
    close(fd);
    if (rc == 0) succeeded++;
  }

  uint64_t t1 = bench_now_ns();
  double sec = (double)(t1 - t0) / 1e9;

  printf("  Sequential connect+HELLO: %" PRIu64 "/%" PRIu64 " succeeded\n",
         succeeded, ITERS);
  printf("  Elapsed: %.4f s  (%.0f conns/sec)\n", sec, (double)succeeded / sec);

  bench_record("Sequential connect+HELLO", sec, succeeded,
               succeeded * (sizeof(memdbg_packet_header_t) +
                            sizeof(memdbg_response_header_t)));
}

/* ---- Benchmark 2: Concurrent connection throughput ---- */

typedef struct {
  uint16_t    port;
  uint64_t    iters;
  atomic_uint_fast64_t succeeded;
  atomic_uint_fast64_t elapsed_ns; /* sum of per-connection RTT */
} bench_conc_ctx_t;

static void *bench_conc_worker(void *arg) {
  bench_conc_ctx_t *ctx = (bench_conc_ctx_t *)arg;
  uint64_t ok = 0;

  for (uint64_t i = 0; i < ctx->iters; ++i) {
    uint64_t t0 = bench_now_ns();
    int fd = bench_connect(ctx->port);
    if (fd < 0) continue;

    int rc = bench_send_cmd(fd, MEMDBG_CMD_HELLO, (uint32_t)(i + 1), NULL);
    if (rc == 0) {
      ok++;
      uint64_t t1 = bench_now_ns();
      atomic_fetch_add(&ctx->elapsed_ns, t1 - t0);
    }
    close(fd);
  }

  atomic_fetch_add(&ctx->succeeded, ok);
  return NULL;
}

static void bench_concurrent_connect(const char *label, uint64_t total_iters,
                                     unsigned concurrency) {
  printf("\n--- Concurrent: %u workers, %" PRIu64 " total iters ---\n",
         concurrency, total_iters);

  bench_conc_ctx_t ctx;
  ctx.port      = BENCH_PORT;
  ctx.iters     = total_iters / concurrency;
  atomic_store(&ctx.succeeded, 0);
  atomic_store(&ctx.elapsed_ns, 0);

  uint64_t t0 = bench_now_ns();

  pthread_t *threads = (pthread_t *)malloc(concurrency * sizeof(pthread_t));
  if (!threads) { printf("  SKIP: malloc\n"); return; }

  memset(threads, 0, concurrency * sizeof(pthread_t));
  for (unsigned i = 0; i < concurrency; ++i)
    (void)pthread_create(&threads[i], NULL, bench_conc_worker, &ctx);

  for (unsigned i = 0; i < concurrency; ++i) {
    if (threads[i] != (pthread_t)0)
      pthread_join(threads[i], NULL);
  }

  uint64_t t1 = bench_now_ns();
  double sec = (double)(t1 - t0) / 1e9;
  uint64_t ok = atomic_load(&ctx.succeeded);
  double avg_rtt_ns = ok > 0 ? (double)atomic_load(&ctx.elapsed_ns) / (double)ok : 0.0;

  printf("  %-40s %" PRIu64 "/%" PRIu64 "\n", "succeeded", ok, total_iters);
  printf("  %-40s %.4f s\n", "elapsed", sec);
  printf("  %-40s %.0f conns/sec\n", "throughput", (double)ok / sec);
  printf("  %-40s %.3f us/RTT\n", "avg per-connection RTT", avg_rtt_ns / 1000.0);

  bench_record(label, sec, ok,
               ok * (sizeof(memdbg_packet_header_t) +
                     sizeof(memdbg_response_header_t)));
  free(threads);
}

static void bench_conc_connect_all(void) {
  printf("\n=== Concurrent Connection + HELLO Throughput ===\n");

  bench_concurrent_connect("Concurrent 1 worker",     2000, 1);
  bench_concurrent_connect("Concurrent 4 workers",    2000, 4);
  bench_concurrent_connect("Concurrent 8 workers",    2000, 8);
  bench_concurrent_connect("Concurrent 16 workers",   2000, 16);
  bench_concurrent_connect("Concurrent 32 workers",   2000, 32);
}

/* ---- Benchmark 3: Request round-trip latency ---- */

static void bench_request_latency(void) {
  printf("\n=== Request Round-Trip Latency (single connection) ===\n");

  int fd = bench_connect(BENCH_PORT);
  if (fd < 0) {
    printf("  SKIP: connect failed\n");
    return;
  }

  const uint64_t ITERS = 10000;
  uint64_t min_ns = UINT64_MAX;
  uint64_t max_ns = 0;
  uint64_t sum_ns = 0;
  uint64_t ok = 0;

  /* Warm-up: send one HELLO to establish the connection */
  (void)bench_send_cmd(fd, MEMDBG_CMD_HELLO, 0, NULL);

  for (uint64_t i = 0; i < ITERS; ++i) {
    uint64_t t0 = bench_now_ns();
    int rc = bench_send_cmd(fd, MEMDBG_CMD_PING, (uint32_t)(i + 1), NULL);
    uint64_t t1 = bench_now_ns();

    if (rc == 0) {
      uint64_t rtt = t1 - t0;
      sum_ns += rtt;
      if (rtt < min_ns) min_ns = rtt;
      if (rtt > max_ns) max_ns = rtt;
      ok++;
    }
  }

  close(fd);

  double avg = ok > 0 ? (double)sum_ns / (double)ok : 0.0;
  printf("  %-40s %" PRIu64 "/%" PRIu64 "\n", "succeeded", ok, ITERS);
  printf("  %-40s %.3f us\n", "avg RTT", avg / 1000.0);
  printf("  %-40s %.3f us\n", "min RTT", (double)min_ns / 1000.0);
  printf("  %-40s %.3f us\n", "max RTT", (double)max_ns / 1000.0);
  printf("  %-40s %.0f reqs/sec\n", "throughput", ok / (sum_ns / 1e9));

  double sec = sum_ns > 0 ? (double)sum_ns / 1e9 : 1e-9;
  bench_record("PING RTT (single connection)", sec, ok,
               ok * (sizeof(memdbg_packet_header_t) +
                     sizeof(memdbg_response_header_t)));
}

/* ---- Benchmark 4: Connection burst ---- */

typedef struct {
  uint16_t port;
  uint64_t *connect_times_ns;  /* array, indexed by worker id */
  int       worker_id;
  uint64_t  accepted;
} burst_ctx_t;

static void *burst_worker(void *arg) {
  burst_ctx_t *ctx = (burst_ctx_t *)arg;
  uint64_t t0 = bench_now_ns();
  int fd = bench_connect(ctx->port);
  uint64_t t1 = bench_now_ns();

  if (fd >= 0) {
    ctx->connect_times_ns[ctx->worker_id] = t1 - t0;
    /* Send HELLO to be counted as an accepted connection */
    int rc = bench_send_cmd(fd, MEMDBG_CMD_HELLO, (uint32_t)ctx->worker_id, NULL);
    if (rc == 0)
      ctx->accepted = 1;
    close(fd);
  } else {
    ctx->connect_times_ns[ctx->worker_id] = UINT64_MAX;
    ctx->accepted = 0;
  }
  return NULL;
}

static void bench_connection_burst(void) {
  printf("\n=== Connection Burst (%d simultaneous, max_conn=%d) ===\n",
         MAX_CONNECTIONS, MAX_CONNECTIONS);

  const int N = MAX_CONNECTIONS;

  uint64_t *times = (uint64_t *)calloc((size_t)N, sizeof(uint64_t));
  if (!times) { printf("  SKIP: calloc\n"); return; }

  pthread_t *threads = (pthread_t *)malloc((size_t)N * sizeof(pthread_t));
  if (!threads) { free(times); printf("  SKIP: malloc\n"); return; }

  burst_ctx_t *ctxs = (burst_ctx_t *)calloc((size_t)N, sizeof(burst_ctx_t));
  if (!ctxs) { free(times); free(threads); printf("  SKIP: calloc\n"); return; }

  uint64_t t0 = bench_now_ns();

  memset(threads, 0, (size_t)N * sizeof(pthread_t));
  for (int i = 0; i < N; ++i) {
    ctxs[i].port              = BENCH_PORT;
    ctxs[i].connect_times_ns  = times;
    ctxs[i].worker_id         = i;
    ctxs[i].accepted          = 0;
    (void)pthread_create(&threads[i], NULL, burst_worker, &ctxs[i]);
  }

  for (int i = 0; i < N; ++i) {
    if (threads[i] != (pthread_t)0)
      pthread_join(threads[i], NULL);
  }

  uint64_t t1 = bench_now_ns();
  double total_sec = (double)(t1 - t0) / 1e9;

  /* Compute stats on accepted connections */
  uint64_t accepted = 0;
  uint64_t sum_rtt = 0;
  uint64_t min_rtt = UINT64_MAX;
  uint64_t max_rtt = 0;

  for (int i = 0; i < N; ++i) {
    if (ctxs[i].accepted && times[i] != UINT64_MAX) {
      accepted++;
      sum_rtt += times[i];
      if (times[i] < min_rtt) min_rtt = times[i];
      if (times[i] > max_rtt) max_rtt = times[i];
    }
  }

  double avg_rtt = accepted > 0 ? (double)sum_rtt / (double)accepted : 0.0;

  printf("  %-40s %" PRIu64 "/%d\n", "accepted", accepted, N);
  printf("  %-40s %.4f s  (%.0f connects/sec burst)\n",
         "total burst time", total_sec, (double)N / total_sec);
  printf("  %-40s %.3f us\n", "avg connect RTT", avg_rtt / 1000.0);
  printf("  %-40s %.3f us\n", "min connect RTT", (double)min_rtt / 1000.0);
  printf("  %-40s %.3f us\n", "max connect RTT", (double)max_rtt / 1000.0);

  bench_record("Connection burst (%d simultaneous)", total_sec, accepted,
               accepted * sizeof(memdbg_packet_header_t));

  free(ctxs);
  free(threads);
  free(times);
}

/* ---- Baseline save / compare ---- */

static void bench_save_baseline(const char *path) {
  FILE *f = fopen(path, "w");
  if (!f) { fprintf(stderr, "Cannot write baseline: %s\n", path); return; }
  for (int i = 0; i < g_result_count; ++i) {
    bench_result_t *r = &g_results[i];
    fprintf(f, "%s\t%.6f\t%" PRIu64 "\t%zu\t%.2f\t%.0f\n",
            r->bench_name, r->total_sec, r->iterations,
            r->bytes_processed, r->throughput_mb_s, r->ops_per_sec);
  }
  fclose(f);
  printf("\nBaseline saved to %s (%d benchmarks)\n", path, g_result_count);
}

static void bench_compare_baseline(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) { fprintf(stderr, "Cannot read baseline: %s\n", path); return; }

  printf("\n=================================================================\n");
  printf("  BASELINE COMPARISON (vs %s)\n", path);
  printf("=================================================================\n");
  printf("  %-48s %10s  %14s\n", "Benchmark", "Before(ops/s)", "After(ops/s)");
  printf("  -----------------------------------------------------------------\n");

  char line[256]; int b_idx = 0;
  while (fgets(line, sizeof(line), f) && b_idx < g_result_count) {
    char name[128]; double before_ops;
    if (sscanf(line, "%127[^\t]\t%*lf\t%*" SCNu64 "\t%*zu\t%*lf\t%lf",
               name, &before_ops) < 2) continue;

    bench_result_t *r = &g_results[b_idx];
    if (strcmp(name, r->bench_name) != 0) continue;

    /* before_ops is ops_per_sec from the saved baseline */
    double pct = ((r->ops_per_sec - before_ops) / before_ops) * 100.0;
    const char *mark = pct > 1.0  ? "FASTER" :
                       pct < -1.0 ? "SLOWER" : "~same";
    printf("  %-48s %10.0f  %14.2f  %+.1f%% %s\n",
           r->bench_name, before_ops, r->ops_per_sec, pct, mark);
    b_idx++;
  }
  fclose(f);
  printf("=================================================================\n");
}

/* ---- Summary ---- */

static void bench_print_summary(void) {
  printf("\n=================================================================\n");
  printf("  CONNECTION THROUGHPUT SUMMARY\n");
  printf("=================================================================\n");
  printf("  %-48s %10s  %12s  %12s\n",
         "Benchmark", "Time(s)", "Ops/s", "MB/s");
  printf("  -----------------------------------------------------------------\n");
  for (int i = 0; i < g_result_count; ++i) {
    bench_result_t *r = &g_results[i];
    printf("  %-48s %10.4f  %12.0f  %12.2f\n",
           r->bench_name, r->total_sec, r->ops_per_sec, r->throughput_mb_s);
  }
  printf("=================================================================\n");
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  const char *save_path    = NULL;
  const char *compare_path = NULL;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--save-baseline") == 0 && i + 1 < argc)
      save_path = argv[++i];
    else if (strcmp(argv[i], "--compare") == 0 && i + 1 < argc)
      compare_path = argv[++i];
    else if (strcmp(argv[i], "--help") == 0) {
      printf("Usage: test_connection_throughput [--save-baseline <file>]\n");
      printf("                                  [--compare <file>]\n");
      return 0;
    }
  }

  printf("MemDBG Connection Throughput Benchmarks\n");
  printf("========================================\n\n");

  /* Start daemon */
  printf("Starting daemon on port %u...\n", BENCH_PORT);
  if (start_daemon(BENCH_PORT) != 0) {
    fprintf(stderr, "FATAL: could not start daemon\n");
    return 1;
  }
  printf("Daemon ready.\n");

  /* Register cleanup so we don't leave orphan daemons */
  atexit(stop_daemon);

  /* Run benchmarks */
  bench_seq_connect();
  bench_conc_connect_all();
  bench_request_latency();
  bench_connection_burst();

  /* Report */
  bench_print_summary();

  if (save_path)    bench_save_baseline(save_path);
  if (compare_path) bench_compare_baseline(compare_path);

  printf("\nTotal benchmarks: %d\n", g_result_count);

  stop_daemon();
  return 0;
}

/* MemDBG - process-map cache concurrency and invalidation tests. */

#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_process.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static atomic_int g_map_calls;
static atomic_int g_active_fetches;
static atomic_int g_max_active_fetches;
static atomic_int g_failures;

static void update_max_active(int active) {
  int observed = atomic_load(&g_max_active_fetches);
  while (active > observed &&
         !atomic_compare_exchange_weak(&g_max_active_fetches, &observed,
                                       active)) {}
}

memdbg_status_t pal_process_maps(int pid, pal_map_list_t *out) {
  atomic_fetch_add(&g_map_calls, 1);
  int active = atomic_fetch_add(&g_active_fetches, 1) + 1;
  update_max_active(active);
  struct timespec delay = {0, 50000000L};
  (void)nanosleep(&delay, NULL);

  memset(out, 0, sizeof(*out));
  out->entries = (pal_map_entry_t *)calloc(2U, sizeof(*out->entries));
  if (out->entries == NULL) {
    atomic_fetch_sub(&g_active_fetches, 1);
    return MEMDBG_ERR_NOMEM;
  }
  out->count = 2U;
  out->capacity = 2U;
  out->entries[0].start = (uint64_t)(unsigned int)pid << 20U;
  out->entries[0].end = out->entries[0].start + 0x1000U;
  out->entries[0].protection = MEMDBG_MAP_PROT_READ;
  out->entries[1].start = out->entries[0].end;
  out->entries[1].end = out->entries[1].start + 0x2000U;
  out->entries[1].protection = MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE;
  atomic_fetch_sub(&g_active_fetches, 1);
  return MEMDBG_OK;
}

void pal_process_maps_free(pal_map_list_t *list) {
  if (list == NULL) return;
  free(list->entries);
  memset(list, 0, sizeof(*list));
}

memdbg_status_t pal_process_list(pal_process_list_t *out) {
  memset(out, 0, sizeof(*out));
  return MEMDBG_OK;
}

void pal_process_list_free(pal_process_list_t *list) {
  if (list == NULL) return;
  free(list->entries);
  memset(list, 0, sizeof(*list));
}

memdbg_status_t pal_process_path(int pid, char *out, size_t out_size) {
  (void)pid;
  if (out != NULL && out_size != 0U) out[0] = '\0';
  return MEMDBG_OK;
}

static void check(const char *name, int condition) {
  printf("  %s %s\n", condition ? "PASS" : "FAIL", name);
  if (!condition) atomic_fetch_add(&g_failures, 1);
}

static void *read_maps(void *arg) {
  int pid = *(const int *)arg;
  memdbg_map_list_t maps;
  memdbg_status_t status = memdbg_process_maps_cached(pid, &maps);
  if (status != MEMDBG_OK || maps.count != 2U)
    atomic_fetch_add(&g_failures, 1);
  memdbg_process_maps_free(&maps);
  return NULL;
}

int main(void) {
  printf("=== Process Map Cache Tests ===\n");
  memdbg_process_maps_cache_flush(0);

  enum { THREADS = 8 };
  pthread_t threads[THREADS];
  int shared_pid = 42;
  for (int i = 0; i < THREADS; ++i)
    (void)pthread_create(&threads[i], NULL, read_maps, &shared_pid);
  for (int i = 0; i < THREADS; ++i)
    (void)pthread_join(threads[i], NULL);
  check("same-PID misses are coalesced", atomic_load(&g_map_calls) == 1);

  memdbg_map_list_t cached;
  check("cache hit succeeds",
        memdbg_process_maps_cached(shared_pid, &cached) == MEMDBG_OK);
  memdbg_process_maps_free(&cached);
  check("cache hit avoids PAL", atomic_load(&g_map_calls) == 1);

  memdbg_process_maps_cache_flush(shared_pid);
  check("refetch after invalidation succeeds",
        memdbg_process_maps_cached(shared_pid, &cached) == MEMDBG_OK);
  memdbg_process_maps_free(&cached);
  check("invalidation refetches PAL", atomic_load(&g_map_calls) == 2);

  memdbg_process_maps_cache_flush(0);
  atomic_store(&g_max_active_fetches, 0);
  int pids[2] = {101, 102};
  (void)pthread_create(&threads[0], NULL, read_maps, &pids[0]);
  (void)pthread_create(&threads[1], NULL, read_maps, &pids[1]);
  (void)pthread_join(threads[0], NULL);
  (void)pthread_join(threads[1], NULL);
  check("different PIDs fetch concurrently",
        atomic_load(&g_max_active_fetches) >= 2);

  uint32_t hits = 0U, misses = 0U;
  memdbg_process_cache_stats(&hits, &misses);
  check("cache telemetry records hits", hits >= THREADS);
  check("cache telemetry records misses", misses >= 4U);
  return atomic_load(&g_failures) == 0 ? 0 : 1;
}

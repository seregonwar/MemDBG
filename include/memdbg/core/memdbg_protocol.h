/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_CORE_MEMDBG_PROTOCOL_H
#define MEMDBG_CORE_MEMDBG_PROTOCOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define MEMDBG_PACKED __attribute__((packed))
#else
#define MEMDBG_PACKED
#endif

#define MEMDBG_PACKET_MAGIC 0x4742444dU /* "MDBG", little-endian */
#define MEMDBG_PROTOCOL_VERSION 1U
#define MEMDBG_PROTOCOL_MAX_PACKET (1024U * 1024U)
#define MEMDBG_PROTOCOL_MAX_MAP_RESPONSE (8U * 1024U * 1024U)
#define MEMDBG_PROTOCOL_MAX_READ (1024U * 1024U)
#define MEMDBG_BATCH_READ_MAX_ITEMS 64U
/* Per-item byte cap for batch reads. Kept well below 1 GiB so the running
 * offset + item length arithmetic in memdbg_memory_batch_read() cannot
 * overflow a uint32_t, while still covering any practical single read. */
#define MEMDBG_BATCH_READ_MAX_ITEM_BYTES (64U * 1024U * 1024U)
#define MEMDBG_BATCH_WRITE_MAX_ITEMS 64U
#define MEMDBG_SCAN_VALUE_MAX 16U
#define MEMDBG_MAP_PROT_READ 1U
#define MEMDBG_MAP_PROT_WRITE 2U
#define MEMDBG_MAP_PROT_EXEC 4U

/* Region matching flags for ELF load / hijack target_region */
#define MEMDBG_MATCH_EXACT          0x00000001U  /* exact basename only, skip substring fallback */
#define MEMDBG_MATCH_CASE_SENSITIVE 0x00000002U  /* case-sensitive comparison */
#define MEMDBG_MATCH_REGEX          0x00000004U  /* treat target as POSIX ERE instead of glob */
#define MEMDBG_MATCH_FULLPATH       0x00000008U  /* match against full path instead of basename */

typedef enum memdbg_command {
  MEMDBG_CMD_HELLO = 0x0001U,
  MEMDBG_CMD_PING = 0x0002U,
  MEMDBG_CMD_PROCESS_LIST = 0x0100U,
  MEMDBG_CMD_PROCESS_MAPS = 0x0101U,
  MEMDBG_CMD_PROCESS_INFO = 0x0102U,
  MEMDBG_CMD_MEMORY_READ = 0x0200U,
  MEMDBG_CMD_MEMORY_WRITE = 0x0201U,
  MEMDBG_CMD_SCAN_EXACT = 0x0300U,
  MEMDBG_CMD_SCAN_PROCESS_EXACT = 0x0301U,
  MEMDBG_CMD_SCAN_AOB = 0x0302U,
  MEMDBG_CMD_SCAN_POINTER = 0x0303U,
  MEMDBG_CMD_SCAN_UNKNOWN = 0x0304U,
  MEMDBG_CMD_SCAN_PROCESS_AOB = 0x0305U,
  MEMDBG_CMD_FOREGROUND_APP = 0x0103U,
  MEMDBG_CMD_PROCESS_STOP = 0x0104U,
  MEMDBG_CMD_PROCESS_CONTINUE = 0x0105U,
  MEMDBG_CMD_PROCESS_KILL = 0x0106U,

  /* Debugger (attach, breakpoints, watchpoints, registers, threads) */
  MEMDBG_CMD_DEBUG_ATTACH = 0x0600U,
  MEMDBG_CMD_DEBUG_DETACH = 0x0601U,
  MEMDBG_CMD_DEBUG_STOP = 0x0602U,
  MEMDBG_CMD_DEBUG_CONTINUE = 0x0603U,
  MEMDBG_CMD_DEBUG_STEP = 0x0604U,
  MEMDBG_CMD_DEBUG_GET_THREADS = 0x0605U,
  MEMDBG_CMD_DEBUG_GET_REGS = 0x0606U,
  MEMDBG_CMD_DEBUG_SET_REGS = 0x0607U,
  MEMDBG_CMD_DEBUG_GET_DBREGS = 0x0608U,
  MEMDBG_CMD_DEBUG_SET_DBREGS = 0x0609U,
  MEMDBG_CMD_DEBUG_SET_BREAKPOINT = 0x060AU,
  MEMDBG_CMD_DEBUG_CLEAR_BREAKPOINT = 0x060BU,
  MEMDBG_CMD_DEBUG_SET_WATCHPOINT = 0x060CU,
  MEMDBG_CMD_DEBUG_CLEAR_WATCHPOINT = 0x060DU,
  MEMDBG_CMD_DEBUG_SUSPEND_THREAD = 0x060EU,
  MEMDBG_CMD_DEBUG_RESUME_THREAD = 0x060FU,
  MEMDBG_CMD_DEBUG_POLL_EVENTS = 0x0610U,
  MEMDBG_CMD_DEBUG_GET_BREAKPOINTS = 0x0611U,
  MEMDBG_CMD_DEBUG_GET_WATCHPOINTS = 0x0612U,
  MEMDBG_CMD_DEBUG_SET_BREAKPOINT_COND = 0x0613U,
  MEMDBG_CMD_DEBUG_CLEAR_ALL_BREAKPOINTS = 0x0614U,
  MEMDBG_CMD_DEBUG_CLEAR_ALL_WATCHPOINTS = 0x0615U,
  MEMDBG_CMD_DEBUG_GET_FPREGS = 0x0616U,
  MEMDBG_CMD_DEBUG_SET_FPREGS = 0x0617U,
  MEMDBG_CMD_DEBUG_GET_FSGSBASE = 0x0618U,
  MEMDBG_CMD_DEBUG_SET_FSGSBASE = 0x0619U,

  /* Tracer (syscall tracing, crash dump) */
  MEMDBG_CMD_TRACER_ATTACH = 0x0700U,
  MEMDBG_CMD_TRACER_DETACH = 0x0701U,
  MEMDBG_CMD_TRACER_POLL   = 0x0702U,
  MEMDBG_CMD_TRACER_STATUS = 0x0703U,

  MEMDBG_CMD_BATCH_READ = 0x0202U,
  MEMDBG_CMD_BATCH_WRITE = 0x0203U,
  MEMDBG_CMD_BATCH_PROCESS_INFO = 0x0107U,
  MEMDBG_CMD_PROCESS_PROTECT = 0x0108U,
  MEMDBG_CMD_PROCESS_ALLOC = 0x0109U,
  MEMDBG_CMD_PROCESS_FREE = 0x010AU,
  MEMDBG_CMD_PROCESS_STACK = 0x010BU,
  MEMDBG_CMD_PROCESS_CALL = 0x010CU,
  MEMDBG_CMD_PROCESS_ELF_LOAD = 0x010DU,
  MEMDBG_CMD_PROCESS_HIJACK  = 0x010EU,
  MEMDBG_CMD_PROCESS_DUMP    = 0x010FU,
  MEMDBG_CMD_TELEMETRY = 0x0400U,
  MEMDBG_CMD_DISCOVERY = 0x0500U,
  MEMDBG_CMD_KERNEL_BASE = 0x0800U,
  MEMDBG_CMD_KERNEL_READ = 0x0801U,
  MEMDBG_CMD_KERNEL_WRITE = 0x0802U,
  MEMDBG_CMD_CONSOLE_NOTIFY = 0x0900U,
  MEMDBG_CMD_CONSOLE_PRINT = 0x0901U,
  MEMDBG_CMD_CONSOLE_REBOOT = 0x0902U,
  /* Assembler / disassembler */
  MEMDBG_CMD_ASM_ENCODE = 0x0A00U,
  MEMDBG_CMD_DISASM      = 0x0A01U,
  MEMDBG_CMD_XREFS_TO    = 0x0A02U,

  /* FlashScan engine (server-resident scan with snapshots) */
  MEMDBG_CMD_QUICKSCAN_CAPS     = 0x0B00U,
  MEMDBG_CMD_QUICKSCAN_START    = 0x0B01U,
  MEMDBG_CMD_QUICKSCAN_COUNT    = 0x0B02U,
  MEMDBG_CMD_QUICKSCAN_FETCH    = 0x0B03U,
  MEMDBG_CMD_QUICKSCAN_END      = 0x0B04U,
  MEMDBG_CMD_QUICKSCAN_CONFIG   = 0x0B05U,
  MEMDBG_CMD_QUICKSCAN_REGIONS  = 0x0B06U,

  /* Page-table introspection */
  MEMDBG_CMD_PTWALK_DISCOVER = 0x0C00U,
  MEMDBG_CMD_PTWALK_AUGMENT  = 0x0C01U,
  MEMDBG_CMD_PTWALK_READ     = 0x0C02U,
  MEMDBG_CMD_PTWALK_WRITE    = 0x0C03U,
  MEMDBG_CMD_PTWALK_PROBE    = 0x0C04U,

  /* Bulk write with per-entry status */
  MEMDBG_CMD_BATCH_WRITE_ADV  = 0x0204U,

  /* Auth / privilege escalation ceremony */
  MEMDBG_CMD_AUTH_KEY = 0x0D00U,

  /* Arena allocator toggle */
  MEMDBG_CMD_ARENA_CONFIG = 0x0D01U,

  /* Klog streaming */
  MEMDBG_CMD_KLOG_CONNECT = 0x0D02U,

  MEMDBG_CMD_SHUTDOWN = 0x7f00U
} memdbg_command_t;

typedef enum memdbg_platform_id {
  MEMDBG_PLATFORM_UNKNOWN = 0U,
  MEMDBG_PLATFORM_PS4 = 4U,
  MEMDBG_PLATFORM_PS5 = 5U,
  MEMDBG_PLATFORM_HOST = 100U
} memdbg_platform_id_t;

typedef enum memdbg_capability {
  MEMDBG_CAP_PROCESS_LIST = 1U << 0,
  MEMDBG_CAP_PROCESS_MAPS = 1U << 1,
  MEMDBG_CAP_MEMORY_READ = 1U << 2,
  MEMDBG_CAP_MEMORY_WRITE = 1U << 3,
  MEMDBG_CAP_SCAN_EXACT = 1U << 4,
  MEMDBG_CAP_UDP_LOG = 1U << 5,
  MEMDBG_CAP_SCAN_PROCESS_EXACT = 1U << 6,
  MEMDBG_CAP_SCAN_TELEMETRY = 1U << 7,
  MEMDBG_CAP_PROCESS_INFO = 1U << 8,
  MEMDBG_CAP_SCAN_AOB = 1U << 9,
  MEMDBG_CAP_SCAN_POINTER = 1U << 10,
  MEMDBG_CAP_FOREGROUND_APP = 1U << 11,
  MEMDBG_CAP_PROCESS_CONTROL = 1U << 12,
  MEMDBG_CAP_BATCH_READ = 1U << 13,
  MEMDBG_CAP_PERF_TELEMETRY = 1U << 14,
  MEMDBG_CAP_SCAN_UNKNOWN = 1U << 15,
  MEMDBG_CAP_BATCH_WRITE = 1U << 16,
  MEMDBG_CAP_LZ4 = 1U << 17,
  MEMDBG_CAP_SCAN_PROCESS_AOB = 1U << 18,
  MEMDBG_CAP_DISCOVERY = 1U << 19,
  MEMDBG_CAP_DEBUGGER = 1U << 20,
  MEMDBG_CAP_TRACER = 1U << 21,
  MEMDBG_CAP_MEMORY_PROTECT = 1U << 22,
  MEMDBG_CAP_MEMORY_ALLOC = 1U << 23,
  MEMDBG_CAP_STACK_WALK = 1U << 24,
  MEMDBG_CAP_REMOTE_CALL = 1U << 25,
  MEMDBG_CAP_KERNEL_ACCESS = 1U << 26,
  MEMDBG_CAP_CONSOLE_UI = 1U << 27,
  MEMDBG_CAP_DEBUG_FPREGS = 1U << 28,
  MEMDBG_CAP_DEBUG_FSGS = 1U << 29,
  MEMDBG_CAP_DISASSEMBLY = 1U << 30
} memdbg_capability_t;

#define MEMDBG_CAP_KLOG_FORWARD (1U << 31)
#define MEMDBG_CAP_HIJACK_MASK   (1U << 31)

/* Extended capabilities (report at runtime via HELLO caps field;
 * these overlap bit positions with the main caps but are advertised
 * as a second 32-bit word in the quick-scan capabilities response).
 * For HELLO, we stuff the high 16 bits of the protocol's caps field. */
#define MEMDBG_EXT_CAP_QUICKSCAN     0x00000001U
#define MEMDBG_EXT_CAP_PTWALK         0x00000002U
#define MEMDBG_EXT_CAP_ALIAS          0x00000004U
#define MEMDBG_EXT_CAP_SIMD           0x00000008U
#define MEMDBG_EXT_CAP_KLOG_SERVER    0x00000010U
#define MEMDBG_EXT_CAP_AUTH           0x00000020U
#define MEMDBG_EXT_CAP_ARENA          0x00000040U
#define MEMDBG_EXT_CAP_BATCH_WRITE_ADV 0x00000080U
#define MEMDBG_EXT_CAP_HIJACK           0x00000100U

typedef enum memdbg_value_type {
  MEMDBG_VALUE_BYTES = 0U,
  MEMDBG_VALUE_U8 = 1U,
  MEMDBG_VALUE_U16 = 2U,
  MEMDBG_VALUE_U32 = 3U,
  MEMDBG_VALUE_U64 = 4U,
  MEMDBG_VALUE_F32 = 5U,
  MEMDBG_VALUE_F64 = 6U,
  MEMDBG_VALUE_POINTER = 7U
} memdbg_value_type_t;

typedef struct MEMDBG_PACKED memdbg_packet_header {
  uint32_t magic;
  uint16_t version;
  uint16_t command;
  uint32_t request_id;
  uint32_t length;
} memdbg_packet_header_t;

typedef struct MEMDBG_PACKED memdbg_response_header {
  uint32_t magic;
  uint16_t version;
  uint16_t command;
  uint32_t request_id;
  int32_t status;
  uint32_t length;
} memdbg_response_header_t;

typedef struct MEMDBG_PACKED memdbg_hello_response {
  uint16_t protocol_version;
  uint16_t platform_id;
  uint32_t capabilities;
  uint16_t debug_port;
  uint16_t udp_log_port;
  char version[16];
  char name[16];
} memdbg_hello_response_t;

typedef struct MEMDBG_PACKED memdbg_process_entry {
  int32_t pid;
  int32_t ppid;
  char name[48];
} memdbg_process_entry_t;

typedef struct MEMDBG_PACKED memdbg_process_maps_request {
  int32_t pid;
} memdbg_process_maps_request_t;

typedef struct MEMDBG_PACKED memdbg_process_info_request {
  int32_t pid;
} memdbg_process_info_request_t;

typedef struct MEMDBG_PACKED memdbg_process_info_response {
  int32_t pid;
  char name[48];
  char title_id[16];
  char content_id[64];
  char path[128];
} memdbg_process_info_response_t;

typedef struct MEMDBG_PACKED memdbg_map_entry {
  uint64_t start;
  uint64_t end;
  uint32_t protection;
  uint32_t flags;
  char name[64];
} memdbg_map_entry_t;

typedef struct MEMDBG_PACKED memdbg_memory_request {
  int32_t pid;
  uint64_t address;
  uint32_t length;
} memdbg_memory_request_t;

typedef struct MEMDBG_PACKED memdbg_scan_exact_request {
  int32_t pid;
  uint64_t start;
  uint64_t length;
  uint32_t value_type;
  uint32_t value_length;
  uint32_t alignment;
  uint32_t max_results;
  uint8_t value[MEMDBG_SCAN_VALUE_MAX];
} memdbg_scan_exact_request_t;

typedef struct MEMDBG_PACKED memdbg_scan_process_exact_request {
  int32_t pid;
  uint32_t value_type;
  uint32_t value_length;
  uint32_t alignment;
  uint32_t max_results;
  uint32_t protection_mask;
  uint64_t start;
  uint64_t end;
  uint8_t value[MEMDBG_SCAN_VALUE_MAX];
} memdbg_scan_process_exact_request_t;

typedef struct MEMDBG_PACKED memdbg_scan_response_prefix {
  uint32_t count;
  uint32_t truncated;
  uint64_t bytes_scanned;
  uint64_t elapsed_ns;
  uint32_t read_calls;
  uint32_t regions_scanned;
  uint32_t read_errors;
  uint32_t reserved;
} memdbg_scan_response_prefix_t;

typedef struct MEMDBG_PACKED memdbg_scan_result_entry {
  uint64_t address;
} memdbg_scan_result_entry_t;

typedef struct MEMDBG_PACKED memdbg_scan_aob_request {
  int32_t pid;
  uint64_t start;
  uint64_t length;
  uint32_t max_results;
  uint32_t pattern_length;
  uint8_t reserved[4];
} memdbg_scan_aob_request_t;

typedef struct MEMDBG_PACKED memdbg_scan_process_aob_request {
  int32_t pid;
  uint32_t protection_mask;
  uint32_t max_results;
  uint32_t pattern_length;
  uint64_t start;
  uint64_t end;
  uint32_t reserved[2];
} memdbg_scan_process_aob_request_t;

typedef struct MEMDBG_PACKED memdbg_scan_aob_response_prefix {
  uint32_t count;
  uint32_t truncated;
  uint64_t bytes_scanned;
  uint64_t elapsed_ns;
  uint32_t regions_scanned;
  uint32_t reserved;
} memdbg_scan_aob_response_prefix_t;

typedef struct MEMDBG_PACKED memdbg_scan_pointer_request {
  int32_t pid;
  uint64_t start;
  uint64_t length;
  uint64_t target_address;
  uint32_t max_depth;
  uint32_t max_results;
  uint32_t alignment;
  uint32_t reserved;
} memdbg_scan_pointer_request_t;

typedef struct MEMDBG_PACKED memdbg_pointer_chain_entry {
  uint64_t base_address;
  uint32_t depth;
  uint32_t reserved;
} memdbg_pointer_chain_entry_t;

typedef struct MEMDBG_PACKED memdbg_foreground_app_response {
  int32_t pid;
  char title_id[16];
  char content_id[64];
  char name[48];
  char app_ver[16];
} memdbg_foreground_app_response_t;

typedef struct MEMDBG_PACKED memdbg_process_control_request {
  int32_t pid;
  uint32_t action;
} memdbg_process_control_request_t;

typedef struct MEMDBG_PACKED memdbg_process_protect_request {
  int32_t pid;
  uint32_t protection; /* MEMDBG_MAP_PROT_* bitmask: 1=R, 2=W, 4=X */
  uint64_t address;
  uint64_t length;
} memdbg_process_protect_request_t;

typedef struct MEMDBG_PACKED memdbg_process_protect_response {
  uint32_t old_protection;
  uint32_t new_protection;
} memdbg_process_protect_response_t;

typedef struct MEMDBG_PACKED memdbg_process_alloc_request {
  int32_t pid;
  uint32_t protection; /* MEMDBG_MAP_PROT_* bitmask */
  uint64_t hint;
  uint64_t length;
  uint32_t flags; /* bit 0 = honor hint when platform supports it */
  uint32_t reserved;
} memdbg_process_alloc_request_t;

typedef struct MEMDBG_PACKED memdbg_process_alloc_response {
  uint64_t address;
  uint64_t length;
} memdbg_process_alloc_response_t;

typedef struct MEMDBG_PACKED memdbg_process_free_request {
  int32_t pid;
  uint32_t reserved;
  uint64_t address;
  uint64_t length;
} memdbg_process_free_request_t;

typedef struct MEMDBG_PACKED memdbg_process_call_request {
  int32_t pid;
  uint32_t reserved;
  uint64_t function_address;
  uint64_t args[6];
} memdbg_process_call_request_t;

typedef struct MEMDBG_PACKED memdbg_process_call_response {
  uint64_t rax;
} memdbg_process_call_response_t;

typedef struct MEMDBG_PACKED memdbg_process_elf_load_request {
  int32_t pid;
  uint32_t flags;             /* bit 0 = jump to entry immediately */
  uint64_t image_size;
  uint32_t match_flags;       /* MEMDBG_MATCH_*; 0 = default (case-insensitive, substring) */
  char     target_region[44]; /* VM region name to load into, empty = allocate new */
} memdbg_process_elf_load_request_t;

typedef struct MEMDBG_PACKED memdbg_process_elf_load_response {
  uint64_t entry_address;
  uint64_t load_base;
} memdbg_process_elf_load_response_t;

#define MEMDBG_STACK_MAX_FRAMES 64U
#define MEMDBG_STACK_DEFAULT_CODE_WINDOW 200U
#define MEMDBG_STACK_MAX_FRAME_BYTES 4096U

typedef struct MEMDBG_PACKED memdbg_process_stack_request {
  int32_t pid;
  int32_t lwp;
  uint64_t frame_pointer; /* 0 = use selected thread RBP when attached */
  uint64_t stack_pointer; /* optional; used for frame 0 locals when RBP is 0 */
  uint32_t max_frames;
  uint32_t max_bytes_per_frame;
  uint32_t code_window;
  uint32_t flags;
} memdbg_process_stack_request_t;

typedef struct MEMDBG_PACKED memdbg_process_stack_response_prefix {
  uint32_t count;
  uint32_t truncated;
  uint32_t entry_size;
  uint32_t data_size;
} memdbg_process_stack_response_prefix_t;

typedef struct MEMDBG_PACKED memdbg_process_stack_frame {
  uint64_t frame_pointer;
  uint64_t saved_frame_pointer;
  uint64_t return_address;
  uint64_t stack_address;
  uint64_t code_address;
  uint32_t stack_size;
  uint32_t code_size;
  uint32_t stack_data_offset;
  uint32_t code_data_offset;
} memdbg_process_stack_frame_t;

typedef struct MEMDBG_PACKED memdbg_kernel_base_response {
  uint64_t text_base;
  uint64_t data_base;
} memdbg_kernel_base_response_t;

typedef struct MEMDBG_PACKED memdbg_kernel_memory_request {
  uint64_t address;
  uint32_t length;
  uint32_t reserved;
} memdbg_kernel_memory_request_t;

typedef struct MEMDBG_PACKED memdbg_console_text_request {
  uint32_t length;
  uint32_t reserved;
  /* followed by 'length' bytes of UTF-8 text, NUL not required */
} memdbg_console_text_request_t;

/* ---- Batch process info (fetch title_id/path/name for many PIDs) ---- */

typedef struct MEMDBG_PACKED memdbg_batch_process_info_request {
  uint32_t count;
  uint32_t reserved;
  /* followed by 'count' int32_t pid values */
} memdbg_batch_process_info_request_t;

typedef struct MEMDBG_PACKED memdbg_batch_process_info_response {
  uint32_t count;
  uint32_t reserved;
  /* followed by 'count' memdbg_process_info_response_t entries */
} memdbg_batch_process_info_response_t;

typedef struct MEMDBG_PACKED memdbg_batch_read_item {
  uint64_t address;
  uint32_t length;
  uint32_t reserved;
} memdbg_batch_read_item_t;

typedef struct MEMDBG_PACKED memdbg_batch_read_request {
  int32_t pid;
  uint32_t count;
  uint32_t reserved;
} memdbg_batch_read_request_t;

typedef struct MEMDBG_PACKED memdbg_batch_read_result_entry {
  uint64_t address;
  uint32_t length;
  uint32_t status;
} memdbg_batch_read_result_entry_t;

typedef struct MEMDBG_PACKED memdbg_batch_write_item {
  uint64_t address;
  uint32_t length;
  uint32_t reserved;
  /* inline data of 'length' bytes follows in the request body */
} memdbg_batch_write_item_t;

typedef struct MEMDBG_PACKED memdbg_batch_write_request {
  int32_t pid;
  uint32_t count;
  uint32_t reserved;
  /* followed by 'count' memdbg_batch_write_item_t + inline data */
} memdbg_batch_write_request_t;

typedef struct MEMDBG_PACKED memdbg_batch_write_result_entry {
  uint64_t address;
  uint32_t written;
  uint32_t status;
} memdbg_batch_write_result_entry_t;

typedef struct MEMDBG_PACKED memdbg_telemetry_response {
  uint64_t total_bytes_read;
  uint64_t total_bytes_written;
  uint64_t total_read_calls;
  uint64_t total_write_calls;
  uint64_t uptime_seconds;
  uint32_t active_connections;
  uint32_t thread_pool_size;
  uint32_t scan_cache_hits;
  uint32_t scan_cache_misses;
  uint32_t reserved;
} memdbg_telemetry_response_t;

/* ---- Debugger ---- */

typedef enum memdbg_thread_state {
  MEMDBG_THREAD_RUNNING = 0,
  MEMDBG_THREAD_STOPPED = 1,
  MEMDBG_THREAD_SUSPENDED = 2,
  MEMDBG_THREAD_WAITING = 3,
  MEMDBG_THREAD_UNKNOWN = 4
} memdbg_thread_state_t;

/* Granular stop information from PT_LWPINFO — why a thread stopped. */
typedef struct MEMDBG_PACKED memdbg_thread_stop_info {
  int32_t pl_event;      /* PL_EVENT_NONE=0, PL_EVENT_SIGNAL=1 */
  int32_t stop_signal;   /* signal number (SIGTRAP=5, SIGSTOP=17, etc.), 0=none */
  int32_t pl_flags;      /* PL_FLAG_* bits (SCE, SCX, EXEC, FORKED, SI, etc.) */
  uint32_t _pad;
  uint64_t pl_sigmask_lo; /* blocked signal mask, bits 0..63 */
  uint64_t pl_sigmask_hi; /* blocked signal mask, bits 64..127 */
  uint64_t pl_siglist_lo; /* pending signals, bits 0..63 */
  uint64_t pl_siglist_hi; /* pending signals, bits 64..127 */
} memdbg_thread_stop_info_t;

typedef struct MEMDBG_PACKED memdbg_debug_attach_request {
  int32_t pid;
  uint32_t reserved;
} memdbg_debug_attach_request_t;

typedef struct MEMDBG_PACKED memdbg_debug_thread_request {
  int32_t pid;
  int32_t lwp;
} memdbg_debug_thread_request_t;

typedef struct MEMDBG_PACKED memdbg_debug_thread_entry {
  int32_t lwp;
  uint32_t state; /* memdbg_thread_state_t */
  memdbg_thread_stop_info_t stop_info; /* granular PT_LWPINFO data */
  int32_t priority;   /* scheduling priority (ki_pri), 0 if unavailable */
  uint64_t runtime_us; /* accumulated CPU time in microseconds */
  int32_t pctcpu;      /* recent CPU utilisation 0..10000 (0.00% .. 100.00%) */
  int32_t cpu_id;      /* last CPU core index, -1 if unavailable */
  char name[24];
} memdbg_debug_thread_entry_t;

typedef struct MEMDBG_PACKED memdbg_debug_threads_response_prefix {
  uint32_t count;
  uint32_t reserved;
} memdbg_debug_threads_response_prefix_t;

typedef struct MEMDBG_PACKED memdbg_debug_regs {
  int64_t r_r15;
  int64_t r_r14;
  int64_t r_r13;
  int64_t r_r12;
  int64_t r_r11;
  int64_t r_r10;
  int64_t r_r9;
  int64_t r_r8;
  int64_t r_rdi;
  int64_t r_rsi;
  int64_t r_rbp;
  int64_t r_rbx;
  int64_t r_rdx;
  int64_t r_rcx;
  int64_t r_rax;
  uint32_t r_trapno;
  uint16_t r_fs;
  uint16_t r_gs;
  uint32_t r_err;
  uint16_t r_es;
  uint16_t r_ds;
  int64_t r_rip;
  int64_t r_cs;
  int64_t r_rflags;
  int64_t r_rsp;
  int64_t r_ss;
} memdbg_debug_regs_t;

typedef struct MEMDBG_PACKED memdbg_debug_dbregs {
  uint64_t dr[16];
} memdbg_debug_dbregs_t;

#define MEMDBG_DEBUG_FPREGS_MAX 1024U
#define MEMDBG_DEBUG_FPREGS_FLAG_XSTATE 0x00000001U

typedef struct MEMDBG_PACKED memdbg_debug_fpregs {
  uint32_t length;
  uint32_t flags;
  uint8_t data[MEMDBG_DEBUG_FPREGS_MAX];
} memdbg_debug_fpregs_t;

typedef struct MEMDBG_PACKED memdbg_debug_fsgsbase {
  uint64_t fs_base;
  uint64_t gs_base;
} memdbg_debug_fsgsbase_t;

typedef struct MEMDBG_PACKED memdbg_debug_breakpoint_request {
  uint64_t address;
  uint32_t kind; /* 0 = software (INT3), 1 = hardware */
  uint32_t reserved;
} memdbg_debug_breakpoint_request_t;

/* Breakpoint condition enums.  cond_reg=0 means unconditional. */
typedef enum memdbg_bp_cond_reg {
  MEMDBG_BP_COND_NONE = 0,
  MEMDBG_BP_COND_RAX,   /* 1 */
  MEMDBG_BP_COND_RBX,   /* 2 */
  MEMDBG_BP_COND_RCX,   /* 3 */
  MEMDBG_BP_COND_RDX,   /* 4 */
  MEMDBG_BP_COND_RSI,   /* 5 */
  MEMDBG_BP_COND_RDI,   /* 6 */
  MEMDBG_BP_COND_RBP,   /* 7 */
  MEMDBG_BP_COND_RSP,   /* 8 */
  MEMDBG_BP_COND_R8,    /* 9 */
  MEMDBG_BP_COND_R9,    /* 10 */
  MEMDBG_BP_COND_R10,   /* 11 */
  MEMDBG_BP_COND_R11,   /* 12 */
  MEMDBG_BP_COND_R12,   /* 13 */
  MEMDBG_BP_COND_R13,   /* 14 */
  MEMDBG_BP_COND_R14,   /* 15 */
  MEMDBG_BP_COND_R15,   /* 16 */
  MEMDBG_BP_COND_RIP     /* 17 */
} memdbg_bp_cond_reg_t;

typedef enum memdbg_bp_cond_op {
  MEMDBG_BP_COND_EQ = 0,  /* == */
  MEMDBG_BP_COND_NE,      /* != */
  MEMDBG_BP_COND_LT,      /* <  */
  MEMDBG_BP_COND_LE,      /* <= */
  MEMDBG_BP_COND_GT,      /* >  */
  MEMDBG_BP_COND_GE       /* >= */
} memdbg_bp_cond_op_t;

/* Breakpoint request with optional condition.  cond_reg=0 means unconditional;
 * the original MEMDBG_CMD_DEBUG_SET_BREAKPOINT is still accepted and is
 * equivalent to cond_reg=0. */
typedef struct MEMDBG_PACKED memdbg_debug_breakpoint_cond_request {
  uint64_t address;
  uint32_t kind;        /* 0 = software, 1 = hardware */
  uint32_t cond_reg;    /* memdbg_bp_cond_reg_t, 0 = no condition */
  uint32_t cond_op;     /* memdbg_bp_cond_op_t */
  uint32_t reserved;
  uint64_t cond_value;
} memdbg_debug_breakpoint_cond_request_t;

typedef struct MEMDBG_PACKED memdbg_debug_watchpoint_request {
  uint64_t address;
  uint32_t length; /* 1, 2, 4, 8 */
  uint32_t type;   /* 0 = exec, 1 = write, 2 = read, 3 = read-write */
} memdbg_debug_watchpoint_request_t;

typedef struct MEMDBG_PACKED memdbg_debug_poll_response {
  int32_t stopped;
  int32_t stop_lwp;
} memdbg_debug_poll_response_t;

/* Response prefix + entries for breakpoint list.
 * Transmitted as: prefix | entry[0] | entry[1] | ... | entry[count-1] */
typedef struct MEMDBG_PACKED memdbg_debug_breakpoint_list_entry {
  uint64_t address;
  uint32_t kind;       /* 0 = software, 1 = hardware */
  uint32_t flags;      /* bit 0 = installed, bit 1 = active */
  uint32_t cond_reg;   /* memdbg_bp_cond_reg_t, 0 = none */
  uint32_t cond_op;    /* memdbg_bp_cond_op_t */
  uint64_t cond_value;
} memdbg_debug_breakpoint_list_entry_t;

typedef struct MEMDBG_PACKED memdbg_debug_breakpoint_list_prefix {
  uint32_t count;
  uint32_t reserved;
} memdbg_debug_breakpoint_list_prefix_t;

/* Response prefix + entries for watchpoint list. */
typedef struct MEMDBG_PACKED memdbg_debug_watchpoint_list_entry {
  uint64_t address;
  uint32_t length;  /* 1, 2, 4, 8 */
  uint32_t type;    /* 0 = exec, 1 = write, 2 = read, 3 = read-write */
  uint32_t slot;    /* 0..3 */
  uint32_t flags;   /* bit 0 = installed */
} memdbg_debug_watchpoint_list_entry_t;

typedef struct MEMDBG_PACKED memdbg_debug_watchpoint_list_prefix {
  uint32_t count;
  uint32_t reserved;
} memdbg_debug_watchpoint_list_prefix_t;

/* Response for batch clear-all commands. */
typedef struct MEMDBG_PACKED memdbg_debug_clear_all_response {
  uint32_t cleared;
  uint32_t reserved;
} memdbg_debug_clear_all_response_t;

/* ---- Discovery (UDP broadcast) ----
 *
 * Frontends send a discovery ping to the broadcast address on the
 * discovery port.  Every payload that receives it replies with a
 * discovery response so the frontend can auto-populate the connection
 * dialog without knowing the debug port ahead of time.
 *
 * Ping:    memdbg_discovery_ping_t   (sent by frontend)
 * Pong:    memdbg_discovery_response_t (unicast reply from payload)
 *
 * Both use the same MEMDBG_PACKET_MAGIC for quick filtering. */

typedef struct MEMDBG_PACKED memdbg_discovery_ping {
  uint32_t magic;
  uint16_t version;
  uint16_t reserved;
} memdbg_discovery_ping_t;

typedef struct MEMDBG_PACKED memdbg_discovery_response {
  uint32_t magic;
  uint16_t protocol_version;
  uint16_t platform_id;
  uint32_t capabilities;
  uint16_t debug_port;
  uint16_t udp_log_port;
  char version[16];
  char name[16];
} memdbg_discovery_response_t;

/* ---- Tracer (syscall tracing, crash dump) ---- */

typedef struct MEMDBG_PACKED memdbg_tracer_attach_request {
  int32_t pid;
} memdbg_tracer_attach_request_t;

/* Tracer event — one entry in the poll ring buffer. */
typedef struct MEMDBG_PACKED memdbg_tracer_event {
  uint64_t timestamp_ns;
  uint32_t event_type;   /* 1=entry, 2=exit, 3=signal, 4=crash */
  uint32_t lwp;
  uint32_t syscall_no;
  int32_t  syscall_ret;
  uint64_t args[6];
  int32_t  signal;
  uint32_t reserved;
  uint64_t fault_addr;
} memdbg_tracer_event_t;

typedef struct MEMDBG_PACKED memdbg_tracer_poll_response_prefix {
  uint32_t count;
  uint32_t reserved;
} memdbg_tracer_poll_response_prefix_t;

/* Tracer daemon states. */
#define MEMDBG_TRACER_STATE_IDLE     0
#define MEMDBG_TRACER_STATE_RUNNING  1
#define MEMDBG_TRACER_STATE_CRASHED  2
#define MEMDBG_TRACER_STATE_EXITED   3
#define MEMDBG_TRACER_STATE_STOPPED  4
#define MEMDBG_TRACER_STATE_STARTING 5

/* Tracer event types. */
#define MEMDBG_TRACER_EVENT_SYSCALL_ENTRY  1U
#define MEMDBG_TRACER_EVENT_SYSCALL_EXIT   2U
#define MEMDBG_TRACER_EVENT_SIGNAL         3U
#define MEMDBG_TRACER_EVENT_CRASH          4U

typedef struct MEMDBG_PACKED memdbg_tracer_status_response {
  int32_t  state;           /* MEMDBG_TRACER_STATE_* */
  uint32_t events_total;    /* total events captured */
  int32_t  crash_signal;    /* 0 if no crash */
  uint32_t reserved;
  uint64_t start_time_ns;
  uint64_t elapsed_ns;
  char     dump_path[256];  /* path to crash dump, empty if none */
} memdbg_tracer_status_response_t;

/* ---- Klog streaming ---- */

typedef struct MEMDBG_PACKED memdbg_klog_connect_request {
  uint32_t reserved;
} memdbg_klog_connect_request_t;

// Assembler / disassembler / xrefs

typedef struct MEMDBG_PACKED memdbg_asm_encode_request {
  uint64_t origin;        /* base address for relative operands */
  uint32_t syntax;        /* 0 = Intel, 1 = AT&T */
  uint32_t reserved;
  /* followed by 'length' bytes of assembly source text */
} memdbg_asm_encode_request_t;

typedef struct MEMDBG_PACKED memdbg_asm_encode_ok {
  uint32_t byte_count;
  uint32_t insn_count;
  /* followed by byte_count bytes of machine code */
} memdbg_asm_encode_ok_t;

typedef struct MEMDBG_PACKED memdbg_asm_encode_err {
  uint32_t err_code;
  uint32_t msg_len;
  /* followed by msg_len bytes of error message (UTF-8, not NUL-terminated) */
} memdbg_asm_encode_err_t;

typedef struct MEMDBG_PACKED memdbg_disasm_request {
  int32_t pid;
  uint32_t count_max;    /* max instructions to emit */
  uint64_t address;
  uint32_t length;       /* max bytes to disassemble */
  uint32_t reserved;
} memdbg_disasm_request_t;

typedef struct MEMDBG_PACKED memdbg_disasm_entry {
  uint64_t address;           /* instruction address */
  uint64_t rip_rel_target;    /* effective target if RIP-relative, else 0 */
  int64_t  mem_displacement;  /* memory operand displacement, 0 if none */
  uint8_t  byte_length;       /* instruction length in bytes */
  uint8_t  opcode_kind;       /* 0=normal, 1=jump, 2=call, 3=ret, 4=conditional */
  uint8_t  mem_base_reg;      /* memory base register (0=none, 1=RAX..16=R15) */
  uint8_t  mem_index_reg;     /* memory index register (0=none) */
  uint8_t  mem_scale;         /* index scale (1,2,4,8; 0=none) */
  uint8_t  mnemonic_id;       /* compact mnemonic identifier */
  uint16_t padding;
} memdbg_disasm_entry_t;

typedef struct MEMDBG_PACKED memdbg_xrefs_to_request {
  int32_t pid;
  uint32_t reserved;
  uint64_t scan_address;
  uint64_t scan_length;
  uint64_t target_address;
} memdbg_xrefs_to_request_t;

// FlashScan: server-resident, snapshot-capable scanning

#define MEMDBG_QUICKSCAN_MAX_CLIENTS 12U
#define MEMDBG_QUICKSCAN_RESIDENT_CAP (256ULL << 20)
#define MEMDBG_QUICKSCAN_RAM_DEFAULT  (512ULL << 20)
#define MEMDBG_QUICKSCAN_MATERIALIZE_MAX (1ULL << 20)

/* Engine capability flags (advertised in caps response) */
#define MEMDBG_QS_F_SIMD          0x00000001U
#define MEMDBG_QS_F_RESIDENT      0x00000004U
#define MEMDBG_QS_F_SNAPSHOT      0x00000008U
#define MEMDBG_QS_F_SNAP_SEGMENTS 0x00000010U
#define MEMDBG_QS_F_SNAP_CONFIG   0x00000020U
#define MEMDBG_QS_F_SNAP_FIRST    0x00000040U
#define MEMDBG_QS_F_SNAP_PREVIOUS 0x00000080U
#define MEMDBG_QS_F_PARALLEL      0x00000100U
#define MEMDBG_QS_F_ALIAS_RESCAN  0x00000200U

/* Per-request flags */
#define MEMDBG_QS_FL_ALIAS_READ    0x00000001U
#define MEMDBG_QS_FL_SERVER_KEEP   0x00000002U
#define MEMDBG_QS_FL_SNAPSHOT      0x00000004U
#define MEMDBG_QS_FL_SNAP_NOZERO   0x00000008U
#define MEMDBG_QS_FL_SNAP_SEGMENTS 0x00000010U
#define MEMDBG_QS_FL_SNAP_FIRST    0x00000020U
#define MEMDBG_QS_FL_SNAP_PREVIOUS 0x00000040U
#define MEMDBG_QS_FL_PARALLEL      0x00000080U
#define MEMDBG_QS_FL_ALIAS_RESCAN  0x00000100U

typedef struct MEMDBG_PACKED memdbg_quickscan_caps_response {
  uint32_t protocol_vers;  /* 1 */
  uint32_t engine_flags;   /* MEMDBG_QS_F_* */
  uint32_t max_workers;    /* parallel compare threads */
  uint32_t reserved;
} memdbg_quickscan_caps_response_t;

typedef struct MEMDBG_PACKED memdbg_quickscan_start_request {
  int32_t pid;
  uint32_t value_type;
  uint32_t compare_type;
  uint32_t alignment;
  uint32_t value_length;
  uint32_t request_flags;  /* MEMDBG_QS_FL_* */
  uint64_t address;
  uint64_t length;
  /* followed by value_length + (between ? value_length : 0) bytes of compare data */
  /* if AOB/array-of-bytes: followed by value_length bytes of mask */
} memdbg_quickscan_start_request_t;

typedef struct MEMDBG_PACKED memdbg_quickscan_count_request {
  int32_t pid;
  uint32_t value_type;
  uint32_t compare_type;
  uint32_t value_length;
  uint32_t request_flags;
  uint64_t base_address;
  /* followed by value_length + optional extra bytes of compare data + optional mask */
} memdbg_quickscan_count_request_t;

typedef struct MEMDBG_PACKED memdbg_quickscan_fetch_request {
  uint32_t start_index;
  uint32_t count;
  uint32_t flags;
} memdbg_quickscan_fetch_request_t;

typedef struct MEMDBG_PACKED memdbg_quickscan_config_request {
  uint32_t ram_limit_mb;     /* 0 = default 512MB */
  uint32_t spill_path_len;   /* length of spill directory path that follows */
  /* followed by spill_path_len bytes */
} memdbg_quickscan_config_request_t;

typedef struct MEMDBG_PACKED memdbg_quickscan_regions_request {
  int32_t pid;
  uint32_t region_max;
  uint32_t probe_bytes;
  uint32_t reserved;
} memdbg_quickscan_regions_request_t;

typedef struct MEMDBG_PACKED memdbg_quickscan_region_info {
  uint64_t start;
  uint64_t end;
  uint32_t protection;
  uint32_t flags;      /* bit 0 = uncached (PCD set) */
  uint32_t read_mbps;  /* measured read MB/s */
  uint32_t reserved;
} memdbg_quickscan_region_info_t;

/* Resident result header sent after a server-kept START */
typedef struct MEMDBG_PACKED memdbg_quickscan_resident_header {
  uint32_t stored;    /* 1 = kept server-side, 0 = results streamed */
  uint64_t hit_count; /* valid iff stored==1 */
} memdbg_quickscan_resident_header_t;

/* Snapshot creation progress sentinel: a uint64 with value 0xFFFFFFFFFFFFFFFF
 * marks end of progress stream. */

/* Snapshot result header */
typedef struct MEMDBG_PACKED memdbg_quickscan_snapshot_summary {
  uint32_t ok;             /* 1 = success */
  uint64_t survivor_count; /* initial survivor slots */
} memdbg_quickscan_snapshot_summary_t;

/* Snapshot plan: sent before scanning begins so client can show progress */
typedef struct MEMDBG_PACKED memdbg_quickscan_snapshot_plan {
  uint64_t slot_count;
  uint64_t total_bytes;
} memdbg_quickscan_snapshot_plan_t;

/* ---- Disjoint segment descriptor for multi-segment snapshot/resident ---- */
typedef struct MEMDBG_PACKED memdbg_quickscan_segment {
  uint64_t address;
  uint32_t length;
  uint32_t reserved;
} memdbg_quickscan_segment_t;

#define MEMDBG_QUICKSCAN_MAX_SEGMENTS (1U << 20)

// Page-table walk / DMAP introspection

typedef struct MEMDBG_PACKED memdbg_ptwalk_discover_response {
  uint32_t status;        /* 0 = found, non-zero = not available */
  uint64_t dmap_base;     /* kernel identity-mapping base */
  uint64_t pmap_offset;   /* offset of pmap within vmspace */
} memdbg_ptwalk_discover_response_t;

typedef struct MEMDBG_PACKED memdbg_ptwalk_augment_request {
  int32_t pid;
  uint32_t reserved;
} memdbg_ptwalk_augment_request_t;

typedef struct MEMDBG_PACKED memdbg_ptwalk_io_request {
  int32_t pid;
  uint32_t reserved;
  uint64_t address;
  uint64_t length;
  /* for write: followed by length bytes of data */
} memdbg_ptwalk_io_request_t;

typedef struct MEMDBG_PACKED memdbg_ptwalk_probe_request {
  int32_t pid;
  uint32_t reserved;
  uint64_t address;
} memdbg_ptwalk_probe_request_t;

typedef struct MEMDBG_PACKED memdbg_ptwalk_probe_response {
  uint64_t phys_address;
  uint64_t page_size;    /* 4096, 2MB, or 1GB */
  uint64_t pte_value;    /* raw page table entry */
  int32_t  page_level;   /* 1=1GB, 2=2MB, 3=4KB */
  uint32_t cached;       /* non-zero if PCD bit is set (uncached memory) */
} memdbg_ptwalk_probe_response_t;

// Batch write with per-entry status

typedef struct MEMDBG_PACKED memdbg_batch_write_adv_request {
  int32_t pid;
  uint32_t count;
  uint32_t flags;      /* bit 0 = include per-entry status array in response */
  uint32_t reserved;
  /* followed by count streamed entries: { uint64 address; uint32 length; <length> bytes } */
} memdbg_batch_write_adv_request_t;

#define MEMDBG_BATCH_WRITE_ADV_MAX_ENTRIES 0xFFFFU
#define MEMDBG_BATCH_WRITE_ADV_MAX_ENTRY   0x100000U

// Auth ceremony

typedef struct MEMDBG_PACKED memdbg_auth_key_request {
  uint32_t magic;       /* must match MEMDBG_AUTH_KEY_MAGIC */
  uint32_t flags;
} memdbg_auth_key_request_t;

#define MEMDBG_AUTH_KEY_MAGIC 0x4DE640BBU

// Arena memory sub-allocator toggle

typedef struct MEMDBG_PACKED memdbg_arena_config_request {
  uint32_t enabled;  /* 0 = disable, 1 = enable */
  uint32_t reserved;
} memdbg_arena_config_request_t;

// Hijack mode: inject payload without blocking the caller

typedef struct MEMDBG_PACKED memdbg_process_hijack_request {
  int32_t pid;
  uint32_t flags;             /* bit 0 = spawn thread, bit 1 = resume target after injection */
  uint64_t payload_size;      /* size of payload ELF that follows */
  uint32_t match_flags;       /* MEMDBG_MATCH_*; 0 = default (case-insensitive, substring) */
  char     target_region[44]; /* VM region name to load into, empty = allocate new */
  /* followed by payload_size bytes of ELF data */
} memdbg_process_hijack_request_t;

typedef struct MEMDBG_PACKED memdbg_process_hijack_response {
  uint32_t accepted;  /* 1 = hijack thread started, 0 = rejected */
  uint32_t reserved;
} memdbg_process_hijack_response_t;

/* ---- Process dump (full JSON snapshot) ---- */

typedef struct MEMDBG_PACKED memdbg_process_dump_request {
  int32_t pid;
  uint32_t flags;  /* bit 0 = include register values
                       bit 1 = include stack traces
                       bit 2 = include region preview (first 256B) */
} memdbg_process_dump_request_t;

/* The dump response is a JSON string sent as a plain payload (no struct).
   The payload length is variable; the JSON follows the schema:
   {
     "pid": int,
     "name": string,
     "path": string,
     "title_id": string,
     "content_id": string,
     "maps": [{ "start": hex, "end": hex, "prot": int, "flags": int,
                "name": string, "preview": hex ... }],
     "threads": [{ "lwp": int, "state": int, "name": string,
                    "regs": { "rax": hex, ... },
                    "stack": [{ "fp": hex, "ret": hex, "code": hex ... }] }]
   }
 */

#undef MEMDBG_PACKED

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_PROTOCOL_H */

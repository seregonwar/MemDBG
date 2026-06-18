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
#define MEMDBG_PROTOCOL_MAX_READ (1024U * 1024U)
#define MEMDBG_BATCH_READ_MAX_ITEMS 64U
#define MEMDBG_BATCH_WRITE_MAX_ITEMS 64U
#define MEMDBG_SCAN_VALUE_MAX 16U

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

  MEMDBG_CMD_BATCH_READ = 0x0202U,
  MEMDBG_CMD_BATCH_WRITE = 0x0203U,
  MEMDBG_CMD_BATCH_PROCESS_INFO = 0x0107U,
  MEMDBG_CMD_TELEMETRY = 0x0400U,
  MEMDBG_CMD_DISCOVERY = 0x0500U,
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
  MEMDBG_CAP_DEBUGGER = 1U << 20
} memdbg_capability_t;

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

#undef MEMDBG_PACKED

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_PROTOCOL_H */

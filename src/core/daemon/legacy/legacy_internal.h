/*
 * memDBG - ps5debug wire-compatibility layer (internal header).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared types, macros, globals, and function declarations for all
 * compat source files.
 */

#ifndef MEMDBG_DAEMON_LEGACY_INTERNAL_H
#define MEMDBG_DAEMON_LEGACY_INTERNAL_H

#include "../daemon_internal.h"

#include "memdbg/core/memdbg_log.h"
#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_memory.h"
#include "memdbg/pal/pal_network.h"
#include "memdbg/privilege/privilege.h"
#include "memdbg/scanner/memdbg_scan.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Wire protocol constants ---- */

#define LEGACY_PACKET_MAGIC 0xFFAABBCCU

#define LEGACY_CMD_SUCCESS   0x40000000U
#define LEGACY_CMD_DATA_NULL 0xF0000003U
#define LEGACY_CMD_ERROR     0xF0000002U

/* ---- Command IDs ---- */

#define LEGACY_CMD_VERSION       0xBD000001U
#define LEGACY_CMD_FW_VERSION    0xBD000500U
#define LEGACY_CMD_BRANDING      0xBD000501U
#define LEGACY_CMD_PLATFORM_ID   0xBD000502U
#define LEGACY_CMD_PROC_NOP      0xBDAACC06U

#define LEGACY_CMD_PROC_LIST         0xBDAA0001U
#define LEGACY_CMD_PROC_READ         0xBDAA0002U
#define LEGACY_CMD_PROC_WRITE        0xBDAA0003U
#define LEGACY_CMD_PROC_MAPS         0xBDAA0004U
#define LEGACY_CMD_PROC_INSTALL      0xBDAA0005U
#define LEGACY_CMD_PROC_PROTECT      0xBDAA0008U
#define LEGACY_CMD_PROC_INFO         0xBDAA000AU
#define LEGACY_CMD_PROC_ALLOC        0xBDAA000BU
#define LEGACY_CMD_PROC_FREE         0xBDAA000CU
#define LEGACY_CMD_PROC_FIRST_MAP    0xBDAA000DU
#define LEGACY_CMD_PROC_ALLOC_HINTED 0xBDAA000EU
#define LEGACY_CMD_PROC_WRITE_MULTI  0xBDAACC04U
#define LEGACY_CMD_PROC_AUTH         0xBDAACCFFU

#define LEGACY_CMD_SCAN       0xBDAA0009U
#define LEGACY_CMD_SCAN_AOB   0xBDAACC01U
#define LEGACY_CMD_SCAN_CONT  0xBDAACC02U
#define LEGACY_CMD_SCAN_FETCH 0xBDAACC03U

#define LEGACY_CMD_DEBUG_ATTACH       0xBDAA0006U
#define LEGACY_CMD_DEBUG_DETACH       0xBDAA0007U
#define LEGACY_CMD_DEBUG_STOP         0xBDAA0010U
#define LEGACY_CMD_DEBUG_CONTINUE     0xBDAA0011U
#define LEGACY_CMD_DEBUG_STEP         0xBDAA0012U
#define LEGACY_CMD_DEBUG_GET_REGS     0xBDAA0013U
#define LEGACY_CMD_DEBUG_SET_REGS     0xBDAA0014U
#define LEGACY_CMD_DEBUG_SET_BP       0xBDAA0015U
#define LEGACY_CMD_DEBUG_CLEAR_BP     0xBDAA0016U
#define LEGACY_CMD_DEBUG_SET_WP       0xBDAA0017U
#define LEGACY_CMD_DEBUG_CLEAR_WP     0xBDAA0018U
#define LEGACY_CMD_DEBUG_GET_THREADS  0xBDAA0019U
#define LEGACY_CMD_DEBUG_SUSPEND_TID  0xBDAA001AU
#define LEGACY_CMD_DEBUG_RESUME_TID   0xBDAA001BU

#define LEGACY_CMD_INTERRUPT      0xBDAACC07U
#define LEGACY_DEBUGGER_INT_PORT  755U

#define LEGACY_CMD_KERN_BASE  0xBDAA001CU
#define LEGACY_CMD_KERN_READ  0xBDAA001DU
#define LEGACY_CMD_KERN_WRITE 0xBDAA001EU

#define LEGACY_CMD_DISASM        0xBDAA001FU
#define LEGACY_CMD_XREFS         0xBDAA0020U
#define LEGACY_CMD_PROC_CALL     0xBDAA0021U
#define LEGACY_CMD_PROC_ELF_LOAD 0xBDAA0022U

#define LEGACY_CMD_QUICKSCAN_CAPS    0xBDAACC08U
#define LEGACY_CMD_QUICKSCAN_START   0xBDAACC09U
#define LEGACY_CMD_QUICKSCAN_COUNT   0xBDAACC0AU
#define LEGACY_CMD_QUICKSCAN_FETCH   0xBDAACC0BU
#define LEGACY_CMD_QUICKSCAN_END     0xBDAACC0CU
#define LEGACY_CMD_QUICKSCAN_CONFIG  0xBDAACC0DU
#define LEGACY_CMD_QUICKSCAN_REGIONS 0xBDAACC0EU

#define LEGACY_RW_CHUNK               0x10000U
#define LEGACY_WRITE_MULTI_STATUS     0x1U
#define LEGACY_WRITE_MULTI_MAX_COUNT  0xFFFFU
#define LEGACY_WRITE_MULTI_MAX_ENTRY  0x100000U
#define LEGACY_SCAN_CHUNK_MAX         4096U

#if defined(__GNUC__) || defined(__clang__)
#define LEGACY_PACKED __attribute__((packed))
#else
#define LEGACY_PACKED
#endif

/* ---- Packet types ---- */

typedef struct legacy_packet_header {
  uint32_t magic;
  uint32_t command;
  uint32_t data_len;
} LEGACY_PACKED legacy_packet_header_t;

typedef struct legacy_proc_list_entry {
  char name[32];
  int32_t pid;
} LEGACY_PACKED legacy_proc_list_entry_t;

typedef struct legacy_proc_maps_entry {
  char name[32];
  uint64_t start;
  uint64_t end;
  uint64_t offset;
  uint16_t protection;
} LEGACY_PACKED legacy_proc_maps_entry_t;

typedef struct legacy_memory_packet {
  uint32_t pid;
  uint64_t address;
  uint32_t length;
} LEGACY_PACKED legacy_memory_packet_t;

typedef struct legacy_proc_info_packet {
  uint32_t pid;
} LEGACY_PACKED legacy_proc_info_packet_t;

typedef struct legacy_proc_info_response {
  uint32_t pid;
  char name[40];
  char path[64];
  char title_id[16];
  char content_id[64];
} LEGACY_PACKED legacy_proc_info_response_t;

typedef struct legacy_proc_alloc_packet {
  uint32_t pid;
  uint32_t length;
} LEGACY_PACKED legacy_proc_alloc_packet_t;

typedef struct legacy_proc_alloc_hinted_packet {
  uint32_t pid;
  uint64_t hint;
  uint32_t length;
} LEGACY_PACKED legacy_proc_alloc_hinted_packet_t;

typedef struct legacy_proc_alloc_response {
  uint64_t address;
} LEGACY_PACKED legacy_proc_alloc_response_t;

typedef struct legacy_proc_free_packet {
  uint32_t pid;
  uint64_t address;
  uint32_t length;
} LEGACY_PACKED legacy_proc_free_packet_t;

typedef struct legacy_proc_protect_packet {
  uint32_t pid;
  uint64_t address;
  uint32_t length;
  uint32_t protection;
} LEGACY_PACKED legacy_proc_protect_packet_t;

typedef struct legacy_proc_write_multi_packet {
  uint32_t pid;
  uint32_t count;
  uint32_t flags;
} LEGACY_PACKED legacy_proc_write_multi_packet_t;

typedef struct legacy_proc_write_multi_entry {
  uint64_t address;
  uint32_t length;
} LEGACY_PACKED legacy_proc_write_multi_entry_t;

/* Scanner packet types */

typedef struct legacy_scan_request {
  uint8_t  value_type;
  uint8_t  value_length;
  uint8_t  alignment;
  uint8_t  reserved[5];
  uint64_t start;
  uint64_t end;
  uint32_t max_results;
} LEGACY_PACKED legacy_scan_request_t;

typedef struct legacy_scan_aob_request {
  uint64_t start;
  uint64_t end;
  uint32_t pattern_length;
} LEGACY_PACKED legacy_scan_aob_request_t;

_Static_assert(sizeof(legacy_packet_header_t) == 12U,
               "legacy packet header must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_list_entry_t) == 36U,
               "legacy process entries must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_maps_entry_t) == 58U,
               "legacy map entries must stay wire-compatible");
_Static_assert(sizeof(legacy_memory_packet_t) == 16U,
               "legacy memory packet must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_info_response_t) == 188U,
               "legacy process info response must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_protect_packet_t) == 20U,
               "legacy protect packet must stay wire-compatible");

typedef struct legacy_scan_session {
  bool     active;
  uint64_t *addresses;
  uint32_t total;
  uint32_t cursor;
} legacy_scan_session_t;

/* Debugger packet types */

typedef struct legacy_debug_attach_request {
  uint32_t pid;
} LEGACY_PACKED legacy_debug_attach_request_t;

typedef struct legacy_debug_step_request {
  int32_t lwp;
} LEGACY_PACKED legacy_debug_step_request_t;

typedef struct legacy_debug_thread_request {
  int32_t lwp;
} LEGACY_PACKED legacy_debug_thread_request_t;

typedef struct legacy_debug_regs {
  uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
  uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax;
  uint64_t rip, rflags, rsp;
  uint32_t trapno;
  uint16_t fs, gs;
  uint32_t err;
  uint16_t es, ds;
  uint64_t cs, ss;
} LEGACY_PACKED legacy_debug_regs_t;

typedef struct legacy_debug_bp_request {
  uint64_t address;
  uint32_t kind;
} LEGACY_PACKED legacy_debug_bp_request_t;

typedef struct legacy_debug_wp_request {
  uint64_t address;
  uint32_t length;
  uint32_t type;
} LEGACY_PACKED legacy_debug_wp_request_t;

typedef struct legacy_debug_thread_entry {
  int32_t lwp;
  uint32_t state;
  char    name[24];
} LEGACY_PACKED legacy_debug_thread_entry_t;

typedef struct legacy_client_args {
  socket_t fd;
  memdbg_config_t cfg;
} legacy_client_args_t;

typedef struct legacy_debugger_session {
  bool     attached;
  int32_t  pid;
  socket_t intr_fd;
  pthread_t intr_thread;
  bool     intr_thread_running;
  char     peer_host[INET_ADDRSTRLEN];
  atomic_bool stop_requested;
} legacy_debugger_session_t;

/* Kernel packet types */

typedef struct legacy_kernel_memory_request {
  uint64_t address;
  uint32_t length;
} LEGACY_PACKED legacy_kernel_memory_request_t;

typedef struct legacy_kernel_base_response {
  uint64_t text_base;
  uint64_t data_base;
} LEGACY_PACKED legacy_kernel_base_response_t;

/* Disasm/xref/remote-call/elf-load packet types */

typedef struct legacy_disasm_request {
  int32_t  pid;
  uint64_t address;
  uint32_t max_count;
} LEGACY_PACKED legacy_disasm_request_t;

/* Mirrors memdbg_disasm_entry_t — wire-compatible translation. */
typedef struct legacy_disasm_entry {
  uint64_t address;
  uint64_t rip_rel_target;
  int64_t  mem_displacement;
  uint8_t  byte_length;
  uint8_t  opcode_kind;
  uint8_t  mem_base_reg;
  uint8_t  mem_index_reg;
  uint8_t  mem_scale;
  uint8_t  mnemonic_id;
  uint16_t padding;
} LEGACY_PACKED legacy_disasm_entry_t;

typedef struct legacy_xrefs_request {
  int32_t  pid;
  uint64_t scan_address;
  uint64_t scan_length;
  uint64_t target_address;
} LEGACY_PACKED legacy_xrefs_request_t;

typedef struct legacy_proc_call_request {
  int32_t  pid;
  uint64_t function_address;
  uint64_t args[6];
} LEGACY_PACKED legacy_proc_call_request_t;

typedef struct legacy_proc_elf_load_request {
  int32_t  pid;
  uint32_t flags;
  uint64_t image_size;
  /* followed by image_size bytes of ELF data */
} LEGACY_PACKED legacy_proc_elf_load_request_t;

_Static_assert(sizeof(legacy_disasm_entry_t) == 32U,
               "legacy disasm entry must stay wire-compatible");
_Static_assert(sizeof(legacy_disasm_request_t) == 16U,
               "legacy disasm request must stay wire-compatible");
_Static_assert(sizeof(legacy_xrefs_request_t) == 28U,
               "legacy xrefs request must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_call_request_t) == 60U,
               "legacy proc call request must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_elf_load_request_t) == 16U,
               "legacy elf load request must stay wire-compatible");

/* ---- Shared globals ---- */

extern atomic_bool g_legacy_running;
extern socket_t    g_legacy_listen_fd;
extern pthread_t   g_legacy_thread;
extern bool        g_legacy_thread_started;
extern memdbg_config_t g_legacy_cfg;

extern legacy_scan_session_t    g_scan_session;
extern legacy_debugger_session_t g_debugger;
extern pthread_mutex_t          g_debugger_mutex;

/* ---- Shared helpers (defined in legacy_common.c) ---- */

uint32_t        legacy_bitswap32(uint32_t value);
uint32_t        legacy_status_from_memdbg(memdbg_status_t status);
int             legacy_send_status(socket_t fd, uint32_t status);
int             legacy_send_memdbg_status(socket_t fd, memdbg_status_t status);
int             legacy_send_blob(socket_t fd, const void *data, size_t length);
int             legacy_send_sized_string(socket_t fd, const char *data, uint32_t length);
void            legacy_copy_fixed(char *dst, size_t dst_len, const char *src);
bool            legacy_is_valid_command(uint32_t command);
bool            legacy_has_body(const void *body, uint32_t body_len, size_t expected);
uint32_t        legacy_platform_id(void);
int             legacy_wait_for_fd(socket_t fd);
bool            legacy_sockaddr_ipv4_host(const struct sockaddr_storage *ss, char *host, size_t host_len);
bool            legacy_peer_allowed(const memdbg_config_t *cfg, const struct sockaddr_storage *ss);
bool            legacy_rw_allowed(const memdbg_config_t *cfg, uint32_t length);

/* ---- Scanner bridge (defined in legacy_scanner.c) ---- */

void            scan_session_reset(void);
bool            scan_session_send_chunk(socket_t fd);
memdbg_status_t scan_session_from_result(memdbg_scan_result_t *result);
memdbg_status_t legacy_handle_scan_exact(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_scan_aob_start(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_scan_cont(socket_t fd);

/* ---- Debugger bridge (defined in legacy_debugger.c) ---- */

void            debugger_session_init(void);
void            debugger_intr_disconnect(void);
void            debugger_session_cleanup(void);
int             legacy_debugger_send_intr(int32_t lwp);
memdbg_status_t legacy_handle_debug_attach(socket_t fd, const void *body, uint32_t body_len, const struct sockaddr_storage *peer_ss);
memdbg_status_t legacy_handle_debug_detach(socket_t fd);
memdbg_status_t legacy_handle_debug_stop_cmd(socket_t fd);
memdbg_status_t legacy_handle_debug_continue_cmd(socket_t fd);
memdbg_status_t legacy_handle_debug_step_cmd(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_debug_get_regs(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_debug_set_regs(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_debug_set_bp(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_debug_clear_bp(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_debug_set_wp(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_debug_clear_wp(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_debug_get_threads(socket_t fd);
memdbg_status_t legacy_handle_debug_suspend_thread(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_debug_resume_thread(socket_t fd, const void *body, uint32_t body_len);

/* ---- Kernel bridge (defined in legacy_kernel.c) ---- */

memdbg_status_t legacy_handle_kern_base(socket_t fd);
memdbg_status_t legacy_handle_kern_read(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_kern_write(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len);

/* ---- Analysis bridge: disasm/xref/remote-call/elf-load (defined in legacy_analysis.c) ---- */

memdbg_status_t legacy_handle_disasm(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_xrefs(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_proc_call(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_proc_elf_load(socket_t fd, const void *body, uint32_t body_len);

/* ---- FlashScan bridge (defined in legacy_flashscan.c) ---- */

memdbg_status_t legacy_handle_quickscan_caps(socket_t fd);
memdbg_status_t legacy_handle_quickscan_start(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_quickscan_count(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_quickscan_fetch(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_quickscan_end(socket_t fd);
memdbg_status_t legacy_handle_quickscan_config(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_quickscan_regions(socket_t fd, const void *body, uint32_t body_len);

/* ---- Process/memory/metadata handlers (defined in legacy_process.c) ---- */

memdbg_status_t legacy_handle_version(socket_t fd);
memdbg_status_t legacy_handle_branding(socket_t fd);
memdbg_status_t legacy_handle_platform_id_cmd(socket_t fd);
memdbg_status_t legacy_handle_fw_version(socket_t fd);
memdbg_status_t legacy_handle_process_list(socket_t fd);
memdbg_status_t legacy_handle_process_maps(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_process_info(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_memory_read(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_memory_write(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_write_multi(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_process_alloc(socket_t fd, const void *body, uint32_t body_len, bool hinted);
memdbg_status_t legacy_handle_process_free(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_process_protect(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_first_map(socket_t fd, const void *body, uint32_t body_len);
memdbg_status_t legacy_handle_install(socket_t fd);

/* ---- Dispatch + server (defined in legacy_server.c) ---- */

memdbg_status_t legacy_dispatch(socket_t fd, const memdbg_config_t *cfg, const legacy_packet_header_t *header, const void *body);

memdbg_status_t memdbg_legacy_start(const memdbg_config_t *cfg);
void            memdbg_legacy_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DAEMON_LEGACY_INTERNAL_H */

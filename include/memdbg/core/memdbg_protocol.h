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
  MEMDBG_CAP_PROCESS_INFO = 1U << 8
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

#undef MEMDBG_PACKED

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_PROTOCOL_H */

/*
 * memDBG - Scan protocol ABI compatibility tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/scanner/scan_request.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(name, expr)                                                       \
  do {                                                                          \
    if (!(expr)) {                                                              \
      fprintf(stderr, "FAIL: %s\n", name);                                     \
      failures++;                                                               \
    }                                                                           \
  } while (0)

int main(void) {
  CHECK("packet header size", sizeof(memdbg_packet_header_t) == 16U);
  CHECK("exact request size", sizeof(memdbg_scan_exact_request_t) == 52U);
  CHECK("legacy unknown request size",
        sizeof(memdbg_scan_process_exact_request_t) == 56U);
  CHECK("versioned unknown request size",
        sizeof(memdbg_scan_unknown_request_t) == 64U);
  CHECK("versioned unknown scan has a distinct command",
        MEMDBG_CMD_SCAN_UNKNOWN_V2 != MEMDBG_CMD_SCAN_UNKNOWN);
  CHECK("goodbye command ABI", MEMDBG_CMD_GOODBYE == 0x0003U);
  CHECK("tracked scan command ABI",
        MEMDBG_CMD_SCAN_PROCESS_EXACT_TRACKED == 0x0307U &&
        MEMDBG_CMD_SCAN_JOB_STATUS == 0x0308U &&
        MEMDBG_CMD_SCAN_JOB_CANCEL == 0x0309U);
  CHECK("tracked scan request size",
        sizeof(memdbg_scan_process_exact_tracked_request_t) == 64U);
  CHECK("scan job request size", sizeof(memdbg_scan_job_request_t) == 8U);
  CHECK("scan job status size",
        sizeof(memdbg_scan_job_status_response_t) == 56U);
  CHECK("scan jobs extended capability",
        MEMDBG_EXT_CAP_SCAN_JOBS == 0x00000200U);
  CHECK("cancelled result flag ABI",
        MEMDBG_SCAN_RESULT_FLAG_CANCELLED == 0x00000001U);

  memdbg_scan_process_exact_request_t legacy;
  memset(&legacy, 0, sizeof(legacy));
  legacy.pid = 42;
  legacy.value_type = MEMDBG_VALUE_U32;
  legacy.value_length = 4U;
  legacy.alignment = 4U;
  legacy.max_results = 123U;
  legacy.protection_mask = MEMDBG_MAP_PROT_READ;
  legacy.start = 0x1000U;
  legacy.end = 0x9000U;

  memdbg_scan_unknown_request_t decoded;
  CHECK("legacy request accepted",
        memdbg_scan_unknown_request_decode(
            &legacy, (uint32_t)sizeof(legacy), &decoded) == MEMDBG_OK);
  CHECK("legacy fields preserved",
        decoded.pid == legacy.pid && decoded.start == legacy.start &&
        decoded.end == legacy.end && decoded.max_results == legacy.max_results);
  CHECK("legacy request gets bounded budget",
        decoded.max_bytes == MEMDBG_SCAN_UNKNOWN_MAX_UNIT_BYTES);

  memdbg_scan_unknown_request_t current;
  memset(&current, 0, sizeof(current));
  current.abi_magic = MEMDBG_SCAN_UNKNOWN_ABI_MAGIC;
  current.abi_version = MEMDBG_SCAN_UNKNOWN_ABI_VERSION;
  current.struct_size = (uint16_t)sizeof(current);
  current.pid = 7;
  current.value_type = MEMDBG_VALUE_U64;
  current.value_length = 8U;
  current.max_bytes = 4096U;
  CHECK("current request accepted",
        memdbg_scan_unknown_request_decode(
            &current, (uint32_t)sizeof(current), &decoded) == MEMDBG_OK);

  current.abi_version++;
  CHECK("newer ABI rejected explicitly",
        memdbg_scan_unknown_request_decode(
            &current, (uint32_t)sizeof(current), &decoded) ==
        MEMDBG_ERR_UNSUPPORTED);
  current.abi_version = MEMDBG_SCAN_UNKNOWN_ABI_VERSION;
  current.flags = MEMDBG_SCAN_UNKNOWN_KNOWN_FLAGS << 1U;
  CHECK("unknown flags rejected explicitly",
        memdbg_scan_unknown_request_decode(
            &current, (uint32_t)sizeof(current), &decoded) ==
        MEMDBG_ERR_UNSUPPORTED);
  current.flags = 0U;
  current.struct_size--;
  CHECK("declared size mismatch rejected",
        memdbg_scan_unknown_request_decode(
            &current, (uint32_t)sizeof(current), &decoded) ==
        MEMDBG_ERR_PROTOCOL);
  CHECK("truncated request rejected",
        memdbg_scan_unknown_request_decode(
            &current, 12U, &decoded) == MEMDBG_ERR_PROTOCOL);

  if (failures == 0) printf("scan protocol ABI tests passed\n");
  return failures == 0 ? 0 : 1;
}

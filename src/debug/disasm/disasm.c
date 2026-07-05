/*
 * memDBG - Disassembler and cross-reference engine.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Uses Zydis for x86-64 disassembly. Provides detailed per-instruction
 * metadata including RIP-relative targets, memory operand breakdown,
 * and opcode classification. Also provides a cross-reference scanner
 * that finds all pointers to a given target address.
 */

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/pal/pal_network.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(MEMDBG_HAS_ZYDIS)
#include "Zydis.h"
#endif

// Public helpers

int memdbg_disasm(int fd, const memdbg_disasm_request_t *req,
                  const uint8_t *code, uint32_t code_len) {
  if (!req || !code || code_len == 0) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }

  uint32_t max_entries = req->count_max ? req->count_max : 200u;

#if defined(MEMDBG_HAS_ZYDIS)
  memdbg_disasm_entry_t *entries =
      (memdbg_disasm_entry_t *)malloc((size_t)max_entries * sizeof(*entries));
  if (!entries) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000003u}, 4);
    return 1;
  }

  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

  ZydisFormatter formatter;
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

  size_t offset = 0;
  uint32_t count = 0;

  while (offset < code_len && count < max_entries) {
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, code + offset,
        code_len - offset, &insn, operands);
    if (!ZYAN_SUCCESS(status)) break;

    memdbg_disasm_entry_t *e = &entries[count];
    memset(e, 0, sizeof(*e));

    e->address     = req->address + offset;
    e->byte_length = insn.length;
    e->opcode_kind = 0;

    switch (insn.meta.category) {
    case ZYDIS_CATEGORY_UNCOND_BRANCH:
      e->opcode_kind = (insn.mnemonic == ZYDIS_MNEMONIC_CALL) ? 2 : 1;
      break;
    case ZYDIS_CATEGORY_COND_BRANCH: e->opcode_kind = 4; break;
    case ZYDIS_CATEGORY_RET:         e->opcode_kind = 3; break;
    }

    e->mnemonic_id = (uint8_t)(insn.mnemonic & 0xFF);

    for (ZyanU8 i = 0; i < insn.operand_count_visible; i++) {
      if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
          operands[i].mem.base == ZYDIS_REGISTER_RIP) {
        e->rip_rel_target = (uint64_t)(
            (int64_t)(e->address + insn.length) +
            operands[i].mem.disp.value);
      }
    }

    for (ZyanU8 i = 0; i < insn.operand_count_visible; i++) {
      if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (operands[i].mem.base != ZYDIS_REGISTER_NONE)
          e->mem_base_reg = (uint8_t)(operands[i].mem.base & 0xFF);
        if (operands[i].mem.index != ZYDIS_REGISTER_NONE)
          e->mem_index_reg = (uint8_t)(operands[i].mem.index & 0xFF);
        if (operands[i].mem.scale > 0)
          e->mem_scale = (uint8_t)operands[i].mem.scale;
        if (operands[i].mem.disp.has_displacement)
          e->mem_displacement = operands[i].mem.disp.value;
        break;
      }
    }

    offset += insn.length;
    count++;
  }

  pal_socket_write_all(fd, &(uint32_t){0}, 4);  /* CMD_SUCCESS */
  pal_socket_write_all(fd, &count, 4);

  if (count > 0)
    pal_socket_write_all(fd, entries, count * sizeof(*entries));

  free(entries);
#else
  pal_socket_write_all(fd, &(uint32_t){0}, 4);  /* CMD_SUCCESS */
  uint32_t zero = 0;
  pal_socket_write_all(fd, &zero, 4);
#endif

  return 0;
}

int memdbg_xrefs(int fd, const memdbg_xrefs_to_request_t *req) {
  if (!req || req->scan_length == 0 || req->scan_length > (64ULL << 20)) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }

  uint64_t chunk = 0x100000ULL;
  uint64_t target = req->target_address;
  uint64_t max_results = 32768ULL;
  uint8_t *buf = (uint8_t *)malloc(chunk);
  uint64_t *results = (uint64_t *)malloc((size_t)(max_results * 8));

  if (!buf || !results) {
    free(buf); free(results);
    pal_socket_write_all(fd, &(uint32_t){0xF0000003u}, 4);
    return 1;
  }

  uint64_t addr = req->scan_address;
  uint64_t remaining = req->scan_length;
  uint64_t count = 0;

  while (remaining > 0 && count < max_results) {
    uint64_t n = (remaining > chunk) ? chunk : remaining;
    size_t ro = 0;
    memdbg_memory_read(req->pid, addr, buf, n, &ro);
    if (ro < 8) { addr += (ro > 0) ? ro : 0x1000ULL; remaining -= (ro > 0) ? ro : 0x1000ULL; continue; }

    for (uint64_t i = 0; i <= ro - 8; i += 8) {
      uint64_t val;
      memcpy(&val, buf + i, 8);
      if (val == target && count < max_results)
        results[count++] = addr + i;
      /* Also check misaligned if alignment doesn't match */
      else if (i + 1 <= ro - 8) {
        uint64_t v2;
        memcpy(&v2, buf + i + 1, 8);
        if (v2 == target && count < max_results)
          results[count++] = addr + i + 1;
      }
      /* And offset by 2, 3, 4 */
      for (int off = 2; off <= 4 && count < max_results; off += 2) {
        if (i + (uint64_t)off <= ro - 8) {
          uint64_t vo;
          memcpy(&vo, buf + i + off, 8);
          if (vo == target && count < max_results)
            results[count++] = addr + i + (uint64_t)off;
        }
      }
    }

    addr += ro;
    remaining -= ro;
  }

  pal_socket_write_all(fd, &(uint32_t){0}, 4);  /* CMD_SUCCESS */
  pal_socket_write_all(fd, &(uint64_t){count}, 8);
  if (count > 0)
    pal_socket_write_all(fd, results, count * 8);

  free(buf); free(results);
  return 0;
}

// Wrapper for daemon dispatch

int memdbg_disasm_multiple(int fd, const uint8_t *body, uint32_t body_len) {
  if (body_len < sizeof(memdbg_disasm_request_t)) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }
  const memdbg_disasm_request_t *req = (const memdbg_disasm_request_t *)body;
  uint32_t code_len = body_len - (uint32_t)sizeof(*req);
  return memdbg_disasm(fd, req, body + sizeof(*req), code_len);
}

int memdbg_xrefs_multiple(int fd, const uint8_t *body, uint32_t body_len) {
  if (body_len < sizeof(memdbg_xrefs_to_request_t)) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }
  const memdbg_xrefs_to_request_t *req = (const memdbg_xrefs_to_request_t *)body;
  return memdbg_xrefs(fd, req);
}

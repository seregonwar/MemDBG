/*
 * MemDBG - Debugger disassembly helpers (Zydis-backed).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "debugger_disassembly.hpp"

#include <Zydis/Zydis.h>

#include <cstdio>
#include <cstring>
#include <unordered_set>
#include <utility>

namespace memdbg::frontend::debugger {
namespace {

bool is_cfg_anchor(const ZydisDecodedInstruction &insn) {
  switch (insn.meta.category) {
  case ZYDIS_CATEGORY_CALL:
  case ZYDIS_CATEGORY_RET:
  case ZYDIS_CATEGORY_UNCOND_BR:
  case ZYDIS_CATEGORY_COND_BR:
    return true;
  default:
    return false;
  }
}

void collect_branch_targets(const ZydisDecodedInstruction &insn,
                            const ZydisDecodedOperand *operands,
                            uint64_t runtime_address,
                            std::unordered_set<uint64_t> &targets) {
  targets.insert(runtime_address);
  if (insn.meta.category == ZYDIS_CATEGORY_RET) {
    return;
  }
  for (ZyanU8 i = 0; i < insn.operand_count_visible; ++i) {
    if (operands[i].type != ZYDIS_OPERAND_TYPE_IMMEDIATE &&
        operands[i].type != ZYDIS_OPERAND_TYPE_MEMORY) {
      continue;
    }
    ZyanU64 abs_addr = 0;
    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &operands[i], runtime_address,
                                              &abs_addr))) {
      targets.insert(static_cast<uint64_t>(abs_addr));
    }
  }
}

} // namespace

std::vector<DisassemblyLine> decode_x86_64_window(const std::vector<uint8_t> &code,
                                                  uint64_t base_address,
                                                  bool cfg_view,
                                                  size_t max_lines) {
  std::vector<DisassemblyLine> lines;
  if (code.empty() || max_lines == 0) {
    return lines;
  }

  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

  ZydisFormatter formatter;
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

  std::unordered_set<uint64_t> cfg_targets;
  size_t pos = 0;

  while (pos < code.size() && lines.size() < max_lines) {
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    const ZyanStatus status = ZydisDecoderDecodeFull(
        &decoder, code.data() + pos, code.size() - pos, &insn, operands);

    char bytes[64];
    bytes[0] = '\0';
    std::string mnemonic;

    if (!ZYAN_SUCCESS(status) || insn.length == 0) {
      std::snprintf(bytes, sizeof(bytes), "%02X", code[pos]);
      char db_text[32];
      std::snprintf(db_text, sizeof(db_text), "db 0x%02X", code[pos]);
      mnemonic = db_text;
      lines.push_back({base_address + pos, bytes, std::move(mnemonic)});
      ++pos;
      continue;
    }

    size_t used = 0;
    const size_t count = insn.length < 8U ? insn.length : 8U;
    for (size_t i = 0; i < count && used + 4U < sizeof(bytes); ++i) {
      used += static_cast<size_t>(std::snprintf(
          bytes + used, sizeof(bytes) - used, "%02X ", code[pos + i]));
    }
    if (insn.length > count && used + 4U < sizeof(bytes)) {
      std::snprintf(bytes + used, sizeof(bytes) - used, "...");
    }

    char text[256];
    if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
            &formatter, &insn, operands, insn.operand_count_visible, text,
            sizeof(text), base_address + pos, ZYAN_NULL))) {
      mnemonic = text;
    } else {
      mnemonic = "???";
    }

    const uint64_t line_addr = base_address + pos;
    if (cfg_view && is_cfg_anchor(insn)) {
      collect_branch_targets(insn, operands, line_addr, cfg_targets);
    }

    lines.push_back({line_addr, bytes, std::move(mnemonic)});
    pos += insn.length;
  }

  if (cfg_view && !lines.empty()) {
    std::vector<DisassemblyLine> filtered;
    filtered.reserve(lines.size());
    for (auto &line : lines) {
      if (cfg_targets.count(line.address) != 0) {
        filtered.push_back(std::move(line));
      }
    }
    lines = std::move(filtered);
  }

  return lines;
}

uint64_t realign_x86_64_address(const std::vector<uint8_t> &code,
                                uint64_t code_base,
                                uint64_t preferred_addr,
                                size_t lookback) {
  if (code.empty() || preferred_addr < code_base) {
    return preferred_addr;
  }
  const uint64_t preferred_off = preferred_addr - code_base;
  if (preferred_off >= code.size()) {
    return preferred_addr;
  }

  const size_t max_back =
      lookback < preferred_off ? lookback : static_cast<size_t>(preferred_off);

  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

  auto try_stream = [&](size_t start, uint64_t &inside_insn_start,
                        bool &hit_boundary) -> bool {
    inside_insn_start = preferred_addr;
    hit_boundary = false;
    size_t pos = start;
    while (pos <= preferred_off && pos < code.size()) {
      ZydisDecodedInstruction insn;
      ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
      const ZyanStatus status = ZydisDecoderDecodeFull(
          &decoder, code.data() + pos, code.size() - pos, &insn, operands);
      if (!ZYAN_SUCCESS(status) || insn.length == 0) {
        return false;
      }
      const size_t next = pos + insn.length;
      if (pos == preferred_off) {
        hit_boundary = true;
        return true;
      }
      if (pos < preferred_off && next > preferred_off) {
        inside_insn_start = code_base + pos;
        return true;
      }
      pos = next;
    }
    return false;
  };

  /* Prefer a lookback stream where preferred falls inside an instruction. */
  for (size_t back = max_back; back >= 1; --back) {
    uint64_t inside = preferred_addr;
    bool boundary = false;
    if (try_stream(preferred_off - back, inside, boundary) && !boundary) {
      return inside;
    }
  }

  /* Otherwise keep preferred if any stream treats it as an insn boundary. */
  for (size_t back = 0; back <= max_back; ++back) {
    uint64_t inside = preferred_addr;
    bool boundary = false;
    if (try_stream(preferred_off - back, inside, boundary) && boundary) {
      return preferred_addr;
    }
  }

  return preferred_addr;
}

} // namespace memdbg::frontend::debugger

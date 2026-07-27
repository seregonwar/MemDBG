/*
 * MemDBG - Debugger disassembly helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_DEBUGGER_DISASSEMBLY_HPP
#define MEMDBG_FRONTEND_DEBUGGER_DISASSEMBLY_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::frontend::debugger {

struct DisassemblyLine {
  uint64_t address = 0;
  std::string bytes;
  std::string mnemonic;
};

std::vector<DisassemblyLine> decode_x86_64_window(const std::vector<uint8_t> &code,
                                                  uint64_t start_addr,
                                                  bool cfg_view,
                                                  size_t max_lines);

/* Scan back up to lookback bytes and pick a start that lands on preferred_addr
 * after linear Zydis decode. Returns preferred_addr unchanged if no better
 * candidate exists. code must cover [preferred_addr - lookback, preferred_addr]. */
uint64_t realign_x86_64_address(const std::vector<uint8_t> &code,
                                uint64_t code_base,
                                uint64_t preferred_addr,
                                size_t lookback = 15);

} // namespace memdbg::frontend::debugger

#endif /* MEMDBG_FRONTEND_DEBUGGER_DISASSEMBLY_HPP */

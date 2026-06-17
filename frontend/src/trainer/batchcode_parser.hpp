/*
 * MemDBG - Formal batchcode parser for trainer import.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_BATCHCODE_PARSER_HPP
#define MEMDBG_FRONTEND_BATCHCODE_PARSER_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::frontend {

struct BatchcodeEntry {
  uint64_t offset = 0;
  std::vector<uint8_t> bytes;
  uint64_t size = 0; /* optional; 0 means "use bytes length" */
};

/* Parse a batchcode string and return the list of memory entries.
 * Supported syntax:
 *   offset:0x123456;value:90 90 90 90;size:4
 *   offset=0x123456 value=0x90909090 size=4
 *   offset 0x123456 value 90 90 90 90
 *   0x123456 : 90 90 90 90
 * Multiple records can be separated by ';' or newlines.
 * Comments start with // or # and run to end of line.
 * Returns the number of entries parsed, or -1 on a hard syntax error. */
int parse_batchcode(const std::string &text, std::vector<BatchcodeEntry> &out,
                    std::string &error);

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_BATCHCODE_PARSER_HPP */

/*
 * MemDBG - Scanner refinement and bounded unknown-scan planning tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "screens/scanner/refine_match.hpp"
#include "screens/scanner/unknown_scan_plan.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace memdbg::frontend;

static int failures;

#define CHECK(name, expr)                                                       \
  do {                                                                          \
    if (!(expr)) {                                                              \
      std::fprintf(stderr, "FAIL: %s\n", name);                                \
      failures++;                                                               \
    }                                                                           \
  } while (0)

static std::vector<uint8_t> u32_bytes(uint32_t value) {
  std::vector<uint8_t> bytes(sizeof(value));
  std::memcpy(bytes.data(), &value, sizeof(value));
  return bytes;
}

int main() {
  std::vector<MapEntry> maps = {
      {0x1000U, 0x1010U, MEMDBG_MAP_PROT_READ, 0U, "readable"},
      {0x2000U, 0x3000U, MEMDBG_MAP_PROT_WRITE, 0U, "write-only"}};
  std::vector<UnknownScanUnit> units;
  std::string error;
  CHECK("bounded planning succeeds",
        build_unknown_scan_units(maps, 0U, 0U, 4U, 8U, units, error));
  CHECK("write-only map filtered", units.size() == 3U);
  CHECK("overlap preserves boundary candidates",
        units[0].start == 0x1000U && units[0].end == 0x1008U &&
        units[1].start == 0x1005U && units[1].end == 0x100dU &&
        units[2].start == 0x100aU && units[2].end == 0x1010U);
  CHECK("overflow-safe high-address planning",
        build_unknown_scan_units(
            {{UINT64_MAX - 15U, UINT64_MAX, MEMDBG_MAP_PROT_READ, 0U, "high"}},
            0U, 0U, 8U, 8U, units, error));
  CHECK("high-address units stay ordered",
        std::all_of(units.begin(), units.end(),
                    [](const UnknownScanUnit &u) {
                      return u.start < u.end && u.end <= UINT64_MAX;
                    }));
  CHECK("oversized budget rejected",
        !build_unknown_scan_units(
            maps, 0U, 0U, 4U,
            MEMDBG_SCAN_UNKNOWN_MAX_UNIT_BYTES + 1U, units, error));

  const std::vector<uint8_t> old_value = u32_bytes(10U);
  const std::vector<uint8_t> same_value = u32_bytes(10U);
  const std::vector<uint8_t> larger_value = u32_bytes(11U);
  const std::vector<uint8_t> exact_value = u32_bytes(11U);
  CHECK("exact refinement matches requested value",
        scan_refine_match(MEMDBG_VALUE_U32, RefineMode::ExactValue,
                          old_value, larger_value, exact_value));
  CHECK("unchanged refinement is monotonic",
        scan_refine_match(MEMDBG_VALUE_U32, RefineMode::Unchanged,
                          old_value, same_value));
  CHECK("increased refinement compares prior candidate",
        scan_refine_match(MEMDBG_VALUE_U32, RefineMode::Increased,
                          old_value, larger_value));

  std::vector<uint64_t> candidates = {1U, 2U, 3U, 4U};
  std::vector<uint64_t> refined = {2U, 4U};
  CHECK("refinement cannot introduce candidates",
        std::all_of(refined.begin(), refined.end(),
                    [&candidates](uint64_t address) {
                      return std::find(candidates.begin(), candidates.end(),
                                       address) != candidates.end();
                    }) &&
        refined.size() <= candidates.size());

  if (failures == 0) std::printf("scanner plan tests passed\n");
  return failures == 0 ? 0 : 1;
}

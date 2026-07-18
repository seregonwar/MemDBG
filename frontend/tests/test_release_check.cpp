/*
 * MemDBG - Payload release compatibility tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "release_check.hpp"

#include <cstdio>
#include <string>

namespace memdbg::frontend {
namespace {

int g_passed = 0;
int g_failed = 0;

void expect_status(const char *name, const std::string &local,
                   const std::string &remote,
                   PayloadVersionStatus expected) {
  const PayloadVersionCompatibility result =
      compare_payload_versions(local, remote);
  if (result.status == expected) {
    ++g_passed;
    std::printf("  PASS  %s\n", name);
  } else {
    ++g_failed;
    std::printf("  FAIL  %s (%s)\n", name, result.error.c_str());
  }
}

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::printf("=== Payload Release Compatibility Tests ===\n");
  expect_status("rolling nightly accepts numbered nightly",
                "0.2.0-nightly.32.gf00fe03", "nightly",
                PayloadVersionStatus::Compatible);
  expect_status("dated rolling nightly accepts numbered nightly",
                "0.2.0-nightly.32.gf00fe03",
                "nightly-20260718-g4c09468",
                PayloadVersionStatus::Compatible);
  expect_status("newer nightly sequence is outdated",
                "0.2.0-nightly.32.gf00fe03", "0.2.0-nightly.33.gabcdef",
                PayloadVersionStatus::Outdated);
  expect_status("older nightly sequence remains compatible",
                "0.2.0-nightly.32.gf00fe03", "0.2.0-nightly.3",
                PayloadVersionStatus::Compatible);
  expect_status("stable patch update is outdated", "0.2.0", "v0.2.1",
                PayloadVersionStatus::Outdated);
  expect_status("stable equal version is compatible", "0.2.0", "V0.2.0",
                PayloadVersionStatus::Compatible);
  expect_status("newer local stable remains compatible", "0.3.0", "v0.2.9",
                PayloadVersionStatus::Compatible);
  expect_status("stable supersedes same-core nightly",
                "0.2.0-nightly.99.gabcdef", "v0.2.0",
                PayloadVersionStatus::Outdated);
  expect_status("stable does not follow rolling nightly", "0.2.0", "nightly",
                PayloadVersionStatus::ChannelMismatch);
  expect_status("invalid local version is explicit", "development", "nightly",
                PayloadVersionStatus::Invalid);
  expect_status("invalid remote tag is explicit", "0.2.0", "latest",
                PayloadVersionStatus::Invalid);

  std::printf("Passed: %d\nFailed: %d\n", g_passed, g_failed);
  return g_failed == 0 ? 0 : 1;
}

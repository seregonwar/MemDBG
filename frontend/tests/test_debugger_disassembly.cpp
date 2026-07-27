/*
 * MemDBG - Unit tests for Zydis-backed debugger disassembly (issue #39).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "screens/debugger/debugger_disassembly.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using memdbg::frontend::debugger::decode_x86_64_window;
using memdbg::frontend::debugger::DisassemblyLine;

namespace {

int g_failures = 0;

void expect_true(bool cond, const char *msg) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", msg);
    ++g_failures;
  }
}

bool mnemonic_contains(const DisassemblyLine &line, const char *needle) {
  return line.mnemonic.find(needle) != std::string::npos;
}

void test_basic_prologue() {
  /* push rbp ; mov rbp, rsp ; sub rsp, 0x20 ; ret */
  const std::vector<uint8_t> code = {
      0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xC3};
  const auto lines = decode_x86_64_window(code, 0x1000, false, 64);
  expect_true(lines.size() >= 4, "prologue yields >= 4 instructions");
  expect_true(mnemonic_contains(lines[0], "push"), "first is push");
  expect_true(mnemonic_contains(lines[1], "mov"), "second is mov");
  expect_true(mnemonic_contains(lines.back(), "ret"), "last is ret");
  /* Must continue past nothing — only one ret at end, full window decoded. */
  expect_true(lines.size() == 4, "exact 4 insn for prologue blob");
}

void test_continues_after_ret() {
  /* ret ; nop ; nop — old decoder stopped at ret */
  const std::vector<uint8_t> code = {0xC3, 0x90, 0x90};
  const auto lines = decode_x86_64_window(code, 0x2000, false, 64);
  expect_true(lines.size() == 3, "decode continues after ret");
  expect_true(mnemonic_contains(lines[0], "ret"), "first ret");
  expect_true(mnemonic_contains(lines[1], "nop"), "second nop");
  expect_true(mnemonic_contains(lines[2], "nop"), "third nop");
}

void test_continues_after_int3() {
  /* int3 ; mov eax, 1 */
  const std::vector<uint8_t> code = {0xCC, 0xB8, 0x01, 0x00, 0x00, 0x00};
  const auto lines = decode_x86_64_window(code, 0x3000, false, 64);
  expect_true(lines.size() >= 2, "decode continues after int3");
  expect_true(mnemonic_contains(lines[0], "int3") ||
                  mnemonic_contains(lines[0], "int"),
              "first is int3");
  expect_true(mnemonic_contains(lines[1], "mov"), "second is mov");
}

void test_rip_relative() {
  /* lea rax, [rip+0] */
  const std::vector<uint8_t> code = {0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00};
  const auto lines = decode_x86_64_window(code, 0x4000, false, 8);
  expect_true(lines.size() == 1, "one lea");
  expect_true(mnemonic_contains(lines[0], "lea"), "lea mnemonic");
  expect_true(lines[0].address == 0x4000, "address preserved");
}

void test_avx_vmovaps() {
  /* vmovaps xmm0, xmm1 */
  const std::vector<uint8_t> code = {0xC5, 0xF8, 0x28, 0xC1};
  const auto lines = decode_x86_64_window(code, 0x5000, false, 8);
  expect_true(lines.size() == 1, "one avx insn");
  expect_true(mnemonic_contains(lines[0], "vmovaps"), "vmovaps (not ???)");
}

void test_cfg_filters_to_control_flow() {
  /* nop ; call rel32(+0) ; nop ; ret */
  const std::vector<uint8_t> code = {
      0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x90, 0xC3};
  const auto full = decode_x86_64_window(code, 0x6000, false, 64);
  const auto cfg = decode_x86_64_window(code, 0x6000, true, 64);
  expect_true(full.size() >= 3, "full view has nop/call/nop/ret");
  expect_true(cfg.size() < full.size(), "cfg view filters anchors");
  bool saw_call = false;
  bool saw_ret = false;
  for (const auto &line : cfg) {
    if (mnemonic_contains(line, "call")) saw_call = true;
    if (mnemonic_contains(line, "ret")) saw_ret = true;
  }
  expect_true(saw_call, "cfg keeps call");
  expect_true(saw_ret, "cfg keeps ret");
}

void test_max_lines_cap() {
  std::vector<uint8_t> code(64, 0x90);
  const auto lines = decode_x86_64_window(code, 0x7000, false, 8);
  expect_true(lines.size() == 8, "respects max_lines");
}

void test_realign_mid_instruction() {
  /* nop ; mov rax, rbx ; ret  — prefer address inside mov (second byte) */
  const std::vector<uint8_t> code = {0x90, 0x48, 0x89, 0xD8, 0xC3};
  const uint64_t base = 0x8000;
  const uint64_t mid_mov = base + 2; /* inside 48 89 D8 */
  const uint64_t aligned =
      memdbg::frontend::debugger::realign_x86_64_address(code, base, mid_mov, 15);
  expect_true(aligned == base + 1, "realign lands on mov start");
}

void test_goto_window_slice_after_realign() {
  /* Simulate refresh_disasm nav path: lookback read then decode from aligned. */
  const std::vector<uint8_t> code = {0x90, 0x48, 0x89, 0xD8, 0xC3, 0x90};
  const uint64_t read_base = 0x9000;
  const uint64_t preferred = read_base + 2; /* mid-mov */
  const uint64_t aligned = memdbg::frontend::debugger::realign_x86_64_address(
      code, read_base, preferred, 15);
  expect_true(aligned == read_base + 1, "goto path realigns");
  const size_t offset = static_cast<size_t>(aligned - read_base);
  std::vector<uint8_t> window(code.begin() + static_cast<std::ptrdiff_t>(offset),
                              code.end());
  const auto lines = decode_x86_64_window(window, aligned, false, 64);
  expect_true(!lines.empty(), "window non-empty");
  expect_true(lines[0].address == aligned, "first line at aligned addr");
  expect_true(mnemonic_contains(lines[0], "mov"), "first insn is mov");
}

} // namespace

int main() {
  test_basic_prologue();
  test_continues_after_ret();
  test_continues_after_int3();
  test_rip_relative();
  test_avx_vmovaps();
  test_cfg_filters_to_control_flow();
  test_max_lines_cap();
  test_realign_mid_instruction();
  test_goto_window_slice_after_realign();

  if (g_failures != 0) {
    std::fprintf(stderr, "%d assertion(s) failed\n", g_failures);
    return 1;
  }
  std::fprintf(stdout, "All debugger_disassembly tests passed\n");
  return 0;
}

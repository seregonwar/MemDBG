/*
 * MemDBG - ImGui console frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_app.hpp"

int main(int argc, char **argv) {
  return memdbg::frontend::run_frontend(argc, argv);
}

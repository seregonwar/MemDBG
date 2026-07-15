/*
 * MemDBG - Raw ELF sender for PS4/PS5 payload loaders.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_PAYLOAD_SENDER_HPP
#define MEMDBG_FRONTEND_PAYLOAD_SENDER_HPP

#include <cstdint>
#include <filesystem>
#include <string>

namespace memdbg::frontend {

bool send_payload_elf(const std::string &host, uint16_t port,
                      const std::filesystem::path &path,
                      std::string &error);

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_PAYLOAD_SENDER_HPP */

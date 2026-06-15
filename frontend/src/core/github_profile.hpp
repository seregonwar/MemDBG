/*
 * MemDBG - GitHub profile loader for frontend credits.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_GITHUB_PROFILE_HPP
#define MEMDBG_FRONTEND_GITHUB_PROFILE_HPP

#include "imgui.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace memdbg::frontend {

struct GitHubProfile {
  std::string login = "seregonwar";
  std::string name = "Seregon";
  std::string bio;
  std::string avatar_url;
  std::string error;

  std::atomic_bool started{false};
  std::atomic_bool worker_done{false};
  std::thread worker;
  mutable std::mutex mutex;

  std::vector<unsigned char> pixels;
  int image_width = 0;
  int image_height = 0;
  uint32_t texture = 0;
};

void github_profile_start(GitHubProfile &profile);
void github_profile_pump_texture(GitHubProfile &profile);
void github_profile_shutdown(GitHubProfile &profile);
ImTextureID github_profile_texture_id(const GitHubProfile &profile);

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_GITHUB_PROFILE_HPP */

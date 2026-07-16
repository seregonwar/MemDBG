/*
 * MemDBG - GitHub release update checker.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_RELEASE_CHECK_HPP
#define MEMDBG_FRONTEND_RELEASE_CHECK_HPP

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

#include "memdbg/core/memdbg_version.h"

namespace memdbg::frontend {

enum class PayloadVersionStatus {
  Compatible,
  Outdated,
  ChannelMismatch,
  Invalid,
};

struct PayloadVersionCompatibility {
  PayloadVersionStatus status = PayloadVersionStatus::Invalid;
  std::string error;
};

struct ReleaseCheck {
  std::string current_version = MEMDBG_VERSION_STRING;
  std::string latest_tag;
  std::string latest_name;
  std::string release_url;
  std::string error;

  bool checked = false;
  bool update_available = false;
  bool notification_shown = false;

  std::atomic_bool started{false};
  std::atomic_bool worker_done{false};
  std::thread worker;
  mutable std::mutex mutex;
};

void release_check_start(ReleaseCheck &check, const char *current_version);
void release_check_shutdown(ReleaseCheck &check);
PayloadVersionCompatibility compare_payload_versions(
    const std::string &local_version, const std::string &remote_tag);

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_RELEASE_CHECK_HPP */

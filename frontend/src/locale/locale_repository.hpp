/*
 * MemDBG - Remote locale repository/cache.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_LOCALE_REPOSITORY_HPP
#define MEMDBG_FRONTEND_LOCALE_REPOSITORY_HPP

#include "locale.hpp"

#include <atomic>
#include <filesystem>
#include <future>
#include <mutex>
#include <string>
#include <vector>

namespace memdbg::frontend::locale {

struct RepositoryLanguage {
  Lang lang = Lang::EN;
  std::string code;
  std::string name;
  std::string filename;
  std::string url;
  bool embedded = false;
  bool remote_available = false;
  bool installed = false;
  bool loaded = false;
  std::string error;
};

class Repository {
public:
  static Repository &instance();

  std::filesystem::path locales_dir() const;

  void preload_installed(Manager &manager);
  bool start_startup_sync(Lang preferred_lang);
  bool request_manifest();
  bool request_download(Lang lang);
  int poll_completed(Manager &manager);
  void shutdown();

  std::vector<RepositoryLanguage> languages() const;
  bool busy() const { return busy_.load(); }
  bool manifest_ready() const;
  std::string status() const;
  std::string error() const;

private:
  enum class Operation { StartupSync, ManifestOnly, Download };

  Repository() = default;

  bool start_worker(Operation op, Lang lang);
  void worker_main(Operation op, Lang lang);

  mutable std::mutex mutex_;
  std::future<void> worker_;
  std::atomic_bool busy_{false};

  std::vector<RepositoryLanguage> languages_;
  std::vector<std::filesystem::path> pending_loads_;
  bool manifest_ready_ = false;
  std::string status_;
  std::string error_;
};

} // namespace memdbg::frontend::locale

#endif /* MEMDBG_FRONTEND_LOCALE_REPOSITORY_HPP */

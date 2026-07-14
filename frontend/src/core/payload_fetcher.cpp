/*
 * MemDBG - Payload fetcher: auto-download latest payload from GitHub releases.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Fingerprint-based comparison: the remote file is considered up-to-date
 * when the cached metadata tag_name matches the latest release tag AND the
 * local file size matches the remote asset size.  No cryptographic hash is
 * computed over the binary payload.
 */

#include "payload_fetcher.hpp"

#include "platform.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>

namespace memdbg::frontend {

/* ========================================================================
 *  PayloadFetcher
 * ======================================================================== */

namespace {

constexpr const char *kReleaseUrl =
    "https://api.github.com/repos/seregonwar/memDBG/releases/latest";

/* Read entire file into a string. */
std::string read_text_file(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

/* Write string to file atomically (write to temp + rename). */
bool write_text_file(const std::filesystem::path &path, const std::string &content) {
  std::error_code ec;
  if (!path.parent_path().empty())
    std::filesystem::create_directories(path.parent_path(), ec);
  auto tmp = path;
  tmp += ".tmp";
  {
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) return false;
    out << content;
  }
  std::filesystem::rename(tmp, path, ec);
  return !ec;
}

/* Return the size of a file on disk, or 0 if absent / unreadable. */
int64_t local_file_size(const std::filesystem::path &path) {
  std::error_code ec;
  auto sz = std::filesystem::file_size(path, ec);
  return ec ? 0 : static_cast<int64_t>(sz);
}

} // anonymous namespace

std::filesystem::path PayloadFetcher::cache_dir() {
  return platform::app_cache_dir() / "payloads";
}

PayloadFetcher::PayloadFetcher() = default;

PayloadFetcher::~PayloadFetcher() {
  stop();
}

void PayloadFetcher::start(const std::string &asset_filter) {
  asset_filter_ = asset_filter;
  bool expected = false;
  if (!started_.compare_exchange_strong(expected, true)) return;
  stop_requested_.store(false);
  worker_ = std::thread(&PayloadFetcher::worker_loop, this);
}

void PayloadFetcher::stop() {
  stop_requested_.store(true);
  if (worker_.joinable()) worker_.join();
}

void PayloadFetcher::refresh() {
  refresh_requested_.store(true);
}

void PayloadFetcher::set_platform(const std::string &p) {
  std::lock_guard<std::mutex> lock(platform_mutex_);
  platform_ = p;
  /* Trigger a re-check so the new platform filter takes effect immediately. */
  refresh_requested_.store(true);
}

PayloadInfo PayloadFetcher::info() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return info_;
}

/* ---- Worker ---- */

void PayloadFetcher::worker_loop() {
  /* Do a first check immediately, then poll every 30 minutes. */
  constexpr auto kPollInterval = std::chrono::minutes(30);
  auto next_check = std::chrono::steady_clock::now(); /* immediate */

  while (!stop_requested_.load()) {
    /* Sleep until next scheduled check or refresh request. */
    while (!stop_requested_.load() && !refresh_requested_.load()) {
      auto now = std::chrono::steady_clock::now();
      if (now >= next_check) break;
      auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          next_check - now);
      if (remaining > std::chrono::milliseconds(500))
        remaining = std::chrono::milliseconds(500);
      std::this_thread::sleep_for(remaining);
    }
    if (stop_requested_.load()) break;

    refresh_requested_.store(false);

    if (!auto_fetch_.load() && checked_.load()) {
      next_check = std::chrono::steady_clock::now() + kPollInterval;
      continue;
    }

    busy_.store(true);
    try {
      PayloadInfo result = check_now();

      {
        std::lock_guard<std::mutex> lock(mutex_);
        info_ = result;
      }

      if (!checked_.load()) checked_.store(true);

      /* Notify the UI of a new version (regardless of auto-fetch).
       * Write tag first, then set flag so take_notify() sees consistent data. */
      if (result.available && !result.up_to_date && !result.tag_name.empty()) {
        {
          std::lock_guard<std::mutex> lock(mutex_);
          notify_tag_ = result.tag_name;
        }
        notify_available_.store(true);
      }

      /* If we found a new version and auto-fetch is on, download it. */
      if (auto_fetch_.load() && result.available && !result.up_to_date &&
          !result.download_url.empty()) {
        std::filesystem::path dest = cache_dir() / result.asset_name;
        std::error_code ec;
        std::filesystem::create_directories(cache_dir(), ec);

        if (platform::download_file(result.download_url, dest)) {
          result.local_path = dest.string();
          result.local_size = local_file_size(dest);
          result.downloaded = true;
          result.up_to_date = (result.local_size == result.asset_size);
          result.error.clear();

          /* Persist metadata (tag + size fingerprint). */
          nlohmann::json meta;
          meta["tag_name"] = result.tag_name;
          meta["asset_name"] = result.asset_name;
          meta["size"] = result.asset_size;
          write_text_file(cache_dir() / "payload_meta.json", meta.dump(2));
        } else {
          result.error = "Download failed";
          result.downloaded = false;
        }

        {
          std::lock_guard<std::mutex> lock(mutex_);
          info_ = result;
        }
      }
    } catch (const std::exception &ex) {
      std::lock_guard<std::mutex> lock(mutex_);
      info_.error = std::string("Worker exception: ") + ex.what();
    } catch (...) {
      std::lock_guard<std::mutex> lock(mutex_);
      info_.error = "Worker unknown exception";
    }

    busy_.store(false);
    next_check = std::chrono::steady_clock::now() + kPollInterval;
  }
}

PayloadInfo PayloadFetcher::check_now() {
  PayloadInfo result;

  /* 1. Fetch release JSON from GitHub API. */
  const auto json_path = cache_dir() / "latest-release.json";
  std::error_code ec;
  std::filesystem::create_directories(cache_dir(), ec);

  if (!platform::download_file(kReleaseUrl, json_path)) {
    result.error = "Failed to fetch GitHub release info";
    return result;
  }

  auto json = nlohmann::json::parse(read_text_file(json_path), nullptr, false);
  if (json.is_discarded()) {
    result.error = "Failed to parse release JSON";
    return result;
  }

  if (json.contains("tag_name") && json["tag_name"].is_string())
    result.tag_name = json["tag_name"].get<std::string>();

  /* 2. Find a matching asset. */
  if (!json.contains("assets") || !json["assets"].is_array()) {
    result.error = "No assets in release";
    return result;
  }

  for (const auto &asset : json["assets"]) {
    if (!asset.contains("name") || !asset["name"].is_string()) continue;
    std::string name = asset["name"].get<std::string>();

    /* Match against the filter (substring, case-insensitive). */
    std::string lower_name = name;
    std::string lower_filter = asset_filter_;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    if (lower_name.find(lower_filter) == std::string::npos) continue;

    /* Apply platform filter if set. */
    {
      std::lock_guard<std::mutex> lock(platform_mutex_);
      if (!platform_.empty()) {
        std::string lower_platform = platform_;
        std::transform(lower_platform.begin(), lower_platform.end(),
                       lower_platform.begin(),
                       [](unsigned char c) { return (char)std::tolower(c); });
        if (lower_name.find(lower_platform) == std::string::npos) continue;
      }
    }

    result.asset_name = name;
    if (asset.contains("browser_download_url") && asset["browser_download_url"].is_string())
      result.download_url = asset["browser_download_url"].get<std::string>();
    if (asset.contains("size") && asset["size"].is_number())
      result.asset_size = asset["size"].get<int64_t>();
    result.available = true;
    break;
  }

  if (!result.available) {
    result.error = "No matching payload asset found in release " + result.tag_name;
    return result;
  }

  /* 3. Compare fingerprint with local cache (tag + size). */
  std::filesystem::path local_path = cache_dir() / result.asset_name;
  result.local_path = local_path.string();
  result.local_size = local_file_size(local_path);

  /* Read persisted metadata. */
  auto meta_path = cache_dir() / "payload_meta.json";
  if (std::filesystem::exists(meta_path)) {
    auto meta = nlohmann::json::parse(read_text_file(meta_path), nullptr, false);
    if (!meta.is_discarded() && meta.contains("tag_name") &&
        meta["tag_name"].get<std::string>() == result.tag_name &&
        meta.contains("size") &&
        meta["size"].get<int64_t>() == result.asset_size &&
        result.local_size == result.asset_size) {
      result.up_to_date = true;
    }
  }

  return result;
}

} // namespace memdbg::frontend

/*
 * MemDBG - GitHub release update checker.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "release_check.hpp"

#include "platform.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <vector>

namespace memdbg::frontend {

namespace {

constexpr const char *kLatestReleaseUrl =
    "https://api.github.com/repos/seregonwar/memDBG/releases/latest";

std::string read_text_file(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

std::string normalize_tag(std::string value) {
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
    value.erase(value.begin());
  }
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
    value.pop_back();
  }
  if (!value.empty() && (value.front() == 'v' || value.front() == 'V')) {
    value.erase(value.begin());
  }
  return value;
}

std::vector<int> version_parts(const std::string &version) {
  std::vector<int> parts;
  std::string number;
  for (char ch : normalize_tag(version)) {
    if (std::isdigit(static_cast<unsigned char>(ch))) {
      number.push_back(ch);
      continue;
    }
    if (!number.empty()) {
      parts.push_back(std::stoi(number));
      number.clear();
    }
    if (ch != '.') break;
  }
  if (!number.empty()) parts.push_back(std::stoi(number));
  return parts;
}

bool version_newer(const std::string &latest, const std::string &current) {
  std::vector<int> lhs = version_parts(latest);
  std::vector<int> rhs = version_parts(current);
  const size_t count = std::max(lhs.size(), rhs.size());
  lhs.resize(count, 0);
  rhs.resize(count, 0);
  return lhs > rhs;
}

void worker_main(ReleaseCheck *check) {
  std::string latest_tag;
  std::string latest_name;
  std::string release_url;
  std::string error;
  bool update_available = false;

  std::string current_version;
  {
    std::lock_guard<std::mutex> lock(check->mutex);
    current_version = check->current_version;
  }

  try {
    const auto cache = platform::app_cache_dir();
    std::filesystem::create_directories(cache);
    const auto json_path = cache / "latest-release.json";

    if (!platform::download_file(kLatestReleaseUrl, json_path)) {
      error = "GitHub release check failed";
    } else {
      const auto json = nlohmann::json::parse(read_text_file(json_path), nullptr, false);
      if (json.is_discarded()) {
        error = "GitHub release JSON parse failed";
      } else {
        if (json.contains("tag_name") && json["tag_name"].is_string())
          latest_tag = json["tag_name"].get<std::string>();
        if (json.contains("name") && json["name"].is_string())
          latest_name = json["name"].get<std::string>();
        if (json.contains("html_url") && json["html_url"].is_string())
          release_url = json["html_url"].get<std::string>();
        if (latest_tag.empty()) {
          error = "GitHub release tag not found";
        } else {
          update_available = version_newer(latest_tag, current_version);
        }
      }
    }
  } catch (const std::exception &ex) {
    error = ex.what();
  }

  {
    std::lock_guard<std::mutex> lock(check->mutex);
    check->latest_tag = latest_tag;
    check->latest_name = latest_name;
    check->release_url = release_url;
    check->error = error;
    check->checked = true;
    check->update_available = update_available;
  }
  check->worker_done.store(true);
}

} // namespace

void release_check_start(ReleaseCheck &check, const char *current_version) {
  {
    std::lock_guard<std::mutex> lock(check.mutex);
    check.current_version = current_version != nullptr ? current_version : MEMDBG_VERSION_STRING;
  }

  bool expected = false;
  if (!check.started.compare_exchange_strong(expected, true)) {
    return;
  }
  check.worker_done.store(false);
  check.worker = std::thread(worker_main, &check);
}

void release_check_shutdown(ReleaseCheck &check) {
  if (check.worker.joinable()) {
    check.worker.join();
  }
}

} // namespace memdbg::frontend

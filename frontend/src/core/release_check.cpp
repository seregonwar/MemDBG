/*
 * MemDBG - GitHub release update checker.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "release_check.hpp"

#include "platform.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
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

enum class VersionChannel {
  Stable,
  Nightly,
};

struct ParsedVersion {
  VersionChannel channel = VersionChannel::Stable;
  bool has_core = false;
  std::array<uint32_t, 3> core{};
  bool has_nightly_sequence = false;
  uint32_t nightly_sequence = 0;
};

bool parse_number(const std::string &text, size_t &offset, uint32_t &out) {
  if (offset >= text.size() ||
      !std::isdigit(static_cast<unsigned char>(text[offset]))) {
    return false;
  }
  uint64_t value = 0;
  while (offset < text.size() &&
         std::isdigit(static_cast<unsigned char>(text[offset]))) {
    value = value * 10U + static_cast<uint32_t>(text[offset] - '0');
    if (value > std::numeric_limits<uint32_t>::max()) return false;
    ++offset;
  }
  out = static_cast<uint32_t>(value);
  return true;
}

bool parse_payload_version(const std::string &input, ParsedVersion &out,
                           std::string &error) {
  const std::string normalized = normalize_tag(input);
  std::string lowered = normalized;
  std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  if (lowered == "nightly") {
    out.channel = VersionChannel::Nightly;
    return true;
  }
  if (lowered.rfind("nightly-", 0U) == 0U) {
    size_t offset = 8U;
    uint32_t build_date = 0U;
    const size_t date_start = offset;
    if (!parse_number(lowered, offset, build_date) ||
        offset - date_start != 8U || offset + 2U >= lowered.size() ||
        lowered[offset] != '-' || lowered[offset + 1U] != 'g') {
      error = "invalid rolling nightly tag";
      return false;
    }
    offset += 2U;
    const size_t hash_start = offset;
    while (offset < lowered.size() &&
           std::isxdigit(static_cast<unsigned char>(lowered[offset])))
      ++offset;
    if (offset != lowered.size() || offset - hash_start < 7U) {
      error = "invalid rolling nightly commit hash";
      return false;
    }
    out.channel = VersionChannel::Nightly;
    return true;
  }

  size_t offset = 0;
  for (size_t i = 0; i < out.core.size(); ++i) {
    if (!parse_number(lowered, offset, out.core[i])) {
      error = "expected semantic version major.minor.patch";
      return false;
    }
    if (i + 1U < out.core.size()) {
      if (offset >= lowered.size() || lowered[offset] != '.') {
        error = "expected semantic version major.minor.patch";
        return false;
      }
      ++offset;
    }
  }
  out.has_core = true;
  if (offset == lowered.size()) {
    out.channel = VersionChannel::Stable;
    return true;
  }

  constexpr const char *kNightlySuffix = "-nightly";
  constexpr size_t kNightlySuffixLength = 8U;
  if (lowered.compare(offset, kNightlySuffixLength, kNightlySuffix) != 0) {
    error = "unsupported release channel";
    return false;
  }
  offset += kNightlySuffixLength;
  out.channel = VersionChannel::Nightly;
  if (offset == lowered.size()) return true;
  if (lowered[offset] != '.') {
    error = "invalid nightly suffix";
    return false;
  }
  ++offset;
  if (!parse_number(lowered, offset, out.nightly_sequence)) {
    error = "invalid nightly build sequence";
    return false;
  }
  out.has_nightly_sequence = true;
  if (offset < lowered.size() && lowered[offset] != '.') {
    error = "invalid nightly build metadata";
    return false;
  }
  return true;
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

PayloadVersionCompatibility compare_payload_versions(
    const std::string &local_version, const std::string &remote_tag) {
  ParsedVersion local;
  ParsedVersion remote;
  std::string error;
  if (!parse_payload_version(local_version, local, error)) {
    return {PayloadVersionStatus::Invalid,
            "invalid local payload version '" + local_version + "': " + error};
  }
  if (!parse_payload_version(remote_tag, remote, error)) {
    return {PayloadVersionStatus::Invalid,
            "invalid remote payload tag '" + remote_tag + "': " + error};
  }

  if (!remote.has_core) {
    if (remote.channel == VersionChannel::Nightly &&
        local.channel == VersionChannel::Nightly) {
      return {PayloadVersionStatus::Compatible, {}};
    }
    return {PayloadVersionStatus::ChannelMismatch,
            "local payload and remote release use different channels"};
  }
  if (!local.has_core) {
    return {PayloadVersionStatus::Invalid,
            "local payload version does not contain a semantic version"};
  }

  if (remote.core > local.core) {
    return {PayloadVersionStatus::Outdated, {}};
  }
  if (remote.core < local.core) {
    return {PayloadVersionStatus::Compatible, {}};
  }

  if (remote.channel == VersionChannel::Stable) {
    return {local.channel == VersionChannel::Nightly
                ? PayloadVersionStatus::Outdated
                : PayloadVersionStatus::Compatible,
            {}};
  }
  if (local.channel == VersionChannel::Stable) {
    return {PayloadVersionStatus::Compatible, {}};
  }
  if (remote.has_nightly_sequence &&
      (!local.has_nightly_sequence ||
       remote.nightly_sequence > local.nightly_sequence)) {
    return {PayloadVersionStatus::Outdated, {}};
  }
  return {PayloadVersionStatus::Compatible, {}};
}

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

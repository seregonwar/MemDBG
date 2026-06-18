/*
 * MemDBG - Remote locale repository/cache.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "locale_repository.hpp"

#include "platform.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <sstream>

#ifndef MEMDBG_LOCALE_MANIFEST_URL
#define MEMDBG_LOCALE_MANIFEST_URL "https://raw.githubusercontent.com/seregonwar/memDBG/main/frontend/locales/manifest.json"
#endif

#ifndef MEMDBG_LOCALE_RAW_BASE_URL
#define MEMDBG_LOCALE_RAW_BASE_URL "https://raw.githubusercontent.com/seregonwar/memDBG/main/frontend/locales"
#endif

namespace memdbg::frontend::locale {

namespace {

constexpr size_t kMinimumLocaleKeys = 32;

bool parse_known_lang(const std::string &code, Lang &out) {
  for (int i = 0; i < static_cast<int>(Lang::COUNT); ++i) {
    Lang lang = static_cast<Lang>(i);
    if (code == lang_code(lang)) {
      out = lang;
      return true;
    }
  }
  return false;
}

std::string filename_for_lang(Lang lang) {
  return std::string(lang_code(lang)) + ".json";
}

std::string default_url_for_lang(Lang lang) {
  return std::string(MEMDBG_LOCALE_RAW_BASE_URL) + "/" + filename_for_lang(lang);
}

RepositoryLanguage default_language(Lang lang) {
  RepositoryLanguage info;
  info.lang = lang;
  info.code = lang_code(lang);
  info.name = lang_name(lang);
  info.filename = filename_for_lang(lang);
  info.url = default_url_for_lang(lang);
  info.embedded = lang == Lang::EN;
  info.remote_available = lang != Lang::EN;
  info.loaded = lang == Lang::EN;
  return info;
}

void sort_languages(std::vector<RepositoryLanguage> &langs) {
  std::sort(langs.begin(), langs.end(),
            [](const RepositoryLanguage &a, const RepositoryLanguage &b) {
              return static_cast<int>(a.lang) < static_cast<int>(b.lang);
            });
}

std::vector<RepositoryLanguage> default_languages(
    const std::filesystem::path &locales_dir) {
  std::vector<RepositoryLanguage> out;
  for (int i = 0; i < static_cast<int>(Lang::COUNT); ++i) {
    RepositoryLanguage info = default_language(static_cast<Lang>(i));
    std::error_code ec;
    info.installed =
        std::filesystem::exists(locales_dir / info.filename, ec) && !ec;
    out.push_back(std::move(info));
  }
  sort_languages(out);
  return out;
}

std::string read_text_file(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

bool files_equal(const std::filesystem::path &lhs,
                 const std::filesystem::path &rhs) {
  std::error_code ec;
  const auto lhs_size = std::filesystem::file_size(lhs, ec);
  if (ec) return false;
  const auto rhs_size = std::filesystem::file_size(rhs, ec);
  if (ec || lhs_size != rhs_size) return false;

  std::ifstream a(lhs, std::ios::binary);
  std::ifstream b(rhs, std::ios::binary);
  if (!a || !b) return false;

  std::array<char, 8192> abuf{};
  std::array<char, 8192> bbuf{};
  while (a && b) {
    a.read(abuf.data(), static_cast<std::streamsize>(abuf.size()));
    b.read(bbuf.data(), static_cast<std::streamsize>(bbuf.size()));
    if (a.gcount() != b.gcount()) return false;
    if (!std::equal(abuf.begin(), abuf.begin() + a.gcount(), bbuf.begin())) {
      return false;
    }
  }
  return true;
}

bool validate_locale_file(const std::filesystem::path &path, Lang expected,
                          std::string &error) {
  nlohmann::json doc = nlohmann::json::parse(read_text_file(path), nullptr, false);
  if (doc.is_discarded()) {
    error = path.filename().string() + ": JSON parse failed";
    return false;
  }
  if (!doc.is_object()) {
    error = path.filename().string() + ": top-level value is not an object";
    return false;
  }

  if (doc.contains("_meta") && doc["_meta"].is_object()) {
    const auto &meta = doc["_meta"];
    if (meta.contains("code") && meta["code"].is_string()) {
      Lang meta_lang = Lang::EN;
      const std::string meta_code = meta["code"].get<std::string>();
      if (!parse_known_lang(meta_code, meta_lang) || meta_lang != expected) {
        error = path.filename().string() + ": locale metadata code mismatch";
        return false;
      }
    }
  }

  size_t string_keys = 0;
  for (auto it = doc.begin(); it != doc.end(); ++it) {
    if (it.key() == "_meta") continue;
    if (!it.value().is_string()) {
      error = path.filename().string() + ": non-string value for key " + it.key();
      return false;
    }
    ++string_keys;
  }

  if (string_keys < kMinimumLocaleKeys || !doc.contains("app.title")) {
    error = path.filename().string() + ": incomplete locale file";
    return false;
  }
  return true;
}

std::vector<RepositoryLanguage> parse_manifest(
    const std::filesystem::path &path,
    const std::filesystem::path &locales_dir,
    std::string &error) {
  nlohmann::json doc = nlohmann::json::parse(read_text_file(path), nullptr, false);
  if (doc.is_discarded() || !doc.is_object()) {
    error = "Locale manifest JSON parse failed";
    return {};
  }
  if (!doc.contains("languages") || !doc["languages"].is_array()) {
    error = "Locale manifest has no languages list";
    return {};
  }

  std::vector<RepositoryLanguage> out;
  for (const auto &item : doc["languages"]) {
    if (!item.is_object() || !item.contains("code") || !item["code"].is_string()) {
      continue;
    }
    Lang lang = Lang::EN;
    const std::string code = item["code"].get<std::string>();
    if (!parse_known_lang(code, lang)) {
      continue;
    }

    RepositoryLanguage info = default_language(lang);
    if (item.contains("name") && item["name"].is_string()) {
      info.name = item["name"].get<std::string>();
    }
    if (item.contains("filename") && item["filename"].is_string()) {
      info.filename = item["filename"].get<std::string>();
    }
    if (item.contains("url") && item["url"].is_string()) {
      info.url = item["url"].get<std::string>();
    }
    if (info.url.empty()) {
      info.url = default_url_for_lang(lang);
    }
    if (item.contains("embedded") && item["embedded"].is_boolean()) {
      info.embedded = item["embedded"].get<bool>();
    }
    info.remote_available = !info.embedded || lang != Lang::EN;

    std::error_code ec;
    info.installed = std::filesystem::exists(locales_dir / info.filename, ec) && !ec;
    out.push_back(std::move(info));
  }

  auto has_en = std::any_of(out.begin(), out.end(), [](const RepositoryLanguage &info) {
    return info.lang == Lang::EN;
  });
  if (!has_en) out.push_back(default_language(Lang::EN));
  sort_languages(out);
  return out;
}

bool download_entry(const RepositoryLanguage &info,
                    const std::filesystem::path &tmp_path,
                    std::string &error) {
  if (info.url.empty()) {
    error = "No repository URL for " + info.code;
    return false;
  }
  std::error_code ec;
  std::filesystem::create_directories(tmp_path.parent_path(), ec);
  if (ec) {
    error = "Cannot create locale cache directory: " + ec.message();
    return false;
  }
  std::filesystem::remove(tmp_path, ec);
  if (!platform::download_file(info.url, tmp_path)) {
    error = "Download failed for " + info.code;
    return false;
  }
  if (!validate_locale_file(tmp_path, info.lang, error)) {
    std::filesystem::remove(tmp_path, ec);
    return false;
  }
  return true;
}

} // namespace

Repository &Repository::instance() {
  static Repository repo;
  return repo;
}

std::filesystem::path Repository::locales_dir() const {
  return platform::app_data_dir() / "locales";
}

void Repository::preload_installed(Manager &manager) {
  std::error_code ec;
  const std::filesystem::path dir = locales_dir();
  if (!std::filesystem::exists(dir, ec) || ec) {
    std::lock_guard<std::mutex> lock(mutex_);
    languages_.push_back(default_language(Lang::EN));
    return;
  }

  std::vector<RepositoryLanguage> loaded;
  loaded.push_back(default_language(Lang::EN));
  for (int i = 1; i < static_cast<int>(Lang::COUNT); ++i) {
    Lang lang = static_cast<Lang>(i);
    RepositoryLanguage info = default_language(lang);
    const std::filesystem::path path = dir / info.filename;
    ec.clear();
    info.installed = std::filesystem::exists(path, ec) && !ec;
    if (!info.installed) continue;

    std::string validate_error;
    if (validate_locale_file(path, lang, validate_error) &&
        manager.load(path.string().c_str())) {
      info.loaded = true;
    } else {
      info.error = validate_error.empty() ? "Locale load failed" : validate_error;
    }
    loaded.push_back(std::move(info));
  }
  sort_languages(loaded);

  std::lock_guard<std::mutex> lock(mutex_);
  languages_ = std::move(loaded);
}

bool Repository::start_startup_sync(Lang preferred_lang) {
  return start_worker(Operation::StartupSync, preferred_lang);
}

bool Repository::request_manifest() {
  if (manifest_ready()) return true;
  return start_worker(Operation::ManifestOnly, Lang::EN);
}

bool Repository::request_download(Lang lang) {
  if (lang == Lang::EN) return true;
  return start_worker(Operation::Download, lang);
}

int Repository::poll_completed(Manager &manager) {
  if (worker_.valid() &&
      worker_.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
    try {
      worker_.get();
    } catch (const std::exception &ex) {
      std::lock_guard<std::mutex> lock(mutex_);
      error_ = ex.what();
      status_ = "Language repository error";
      busy_.store(false);
    }
  }

  std::vector<std::filesystem::path> loads;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    loads.swap(pending_loads_);
  }

  int loaded_count = 0;
  for (const auto &path : loads) {
    if (manager.load(path.string().c_str())) {
      ++loaded_count;
      const std::string code = path.stem().string();
      Lang lang = Lang::EN;
      if (parse_known_lang(code, lang)) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto &info : languages_) {
          if (info.lang == lang) {
            info.installed = true;
            info.loaded = true;
            info.error.clear();
            break;
          }
        }
      }
    }
  }
  return loaded_count;
}

void Repository::shutdown() {
  if (worker_.valid()) {
    worker_.wait();
    try {
      worker_.get();
    } catch (...) {
      /* Best-effort shutdown; the UI has already surfaced worker errors. */
    }
  }
}

std::vector<RepositoryLanguage> Repository::languages() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!languages_.empty()) return languages_;
  return {default_language(Lang::EN)};
}

bool Repository::manifest_ready() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return manifest_ready_;
}

std::string Repository::status() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return status_;
}

std::string Repository::error() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return error_;
}

bool Repository::start_worker(Operation op, Lang lang) {
  if (busy_.load()) return false;
  if (worker_.valid() &&
      worker_.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
    try {
      worker_.get();
    } catch (...) {
      /* A previous worker error is already captured in repository state. */
    }
  }

  busy_.store(true);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    error_.clear();
    status_ = op == Operation::Download ? "Downloading language"
                                        : "Checking language repository";
  }
  worker_ = std::async(std::launch::async, [this, op, lang]() {
    worker_main(op, lang);
  });
  return true;
}

void Repository::worker_main(Operation op, Lang requested_lang) {
  const std::filesystem::path cache_dir = platform::app_cache_dir() / "locales";
  const std::filesystem::path manifest_path = cache_dir / "manifest.json";
  const std::filesystem::path manifest_tmp = cache_dir / "manifest.json.download";
  const std::filesystem::path dir = locales_dir();

  std::string worker_error;
  std::vector<RepositoryLanguage> manifest_languages;

  try {
    std::error_code ec;
    std::filesystem::create_directories(cache_dir, ec);
    if (ec) {
      worker_error = "Cannot create locale cache directory: " + ec.message();
    }

    bool downloaded_manifest = false;
    std::vector<RepositoryLanguage> downloaded_languages;
    if (worker_error.empty()) {
      std::filesystem::remove(manifest_tmp, ec);
      downloaded_manifest =
          platform::download_file(MEMDBG_LOCALE_MANIFEST_URL, manifest_tmp);
      if (downloaded_manifest) {
        std::string parse_error;
        downloaded_languages = parse_manifest(manifest_tmp, dir, parse_error);
        if (!downloaded_languages.empty()) {
          std::filesystem::copy_file(manifest_tmp, manifest_path,
                                     std::filesystem::copy_options::overwrite_existing,
                                     ec);
          std::filesystem::remove(manifest_tmp, ec);
        } else {
          downloaded_manifest = false;
          if (worker_error.empty()) worker_error = parse_error;
        }
      }
    }

    if (!downloaded_manifest && !worker_error.empty()) {
      ec.clear();
      if (std::filesystem::exists(manifest_path, ec) && !ec) {
        worker_error.clear();
      }
    }

    if (worker_error.empty() && downloaded_languages.empty()) {
      ec.clear();
      if (!downloaded_manifest && !std::filesystem::exists(manifest_path, ec)) {
        worker_error = "Locale repository unavailable";
      }
    }

    if (!downloaded_languages.empty()) {
      manifest_languages = std::move(downloaded_languages);
    } else if (worker_error.empty()) {
      manifest_languages = parse_manifest(manifest_path, dir, worker_error);
    }
    if (manifest_languages.empty()) {
      manifest_languages = default_languages(dir);
      if (worker_error == "Locale repository unavailable" ||
          worker_error == "Locale manifest JSON parse failed") {
        worker_error.clear();
      }
    }

    if (!manifest_languages.empty()) {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto &fresh : manifest_languages) {
        for (const auto &old : languages_) {
          if (old.lang == fresh.lang) {
            fresh.loaded = old.loaded;
            if (!old.error.empty()) fresh.error = old.error;
            break;
          }
        }
      }
      languages_ = manifest_languages;
      manifest_ready_ = true;
      status_ = "Language repository ready";
    }

    auto find_entry = [&](Lang lang) -> RepositoryLanguage {
      auto it = std::find_if(manifest_languages.begin(), manifest_languages.end(),
                             [lang](const RepositoryLanguage &info) {
                               return info.lang == lang;
                             });
      return it != manifest_languages.end() ? *it : default_language(lang);
    };

    auto install_tmp = [&](const RepositoryLanguage &info,
                           const std::filesystem::path &tmp_path) {
      std::error_code ec2;
      std::filesystem::create_directories(dir, ec2);
      if (ec2) {
        worker_error = "Cannot create locale directory: " + ec2.message();
        return;
      }
      const std::filesystem::path target = dir / info.filename;
      std::filesystem::copy_file(tmp_path, target,
                                 std::filesystem::copy_options::overwrite_existing,
                                 ec2);
      if (ec2) {
        worker_error = "Cannot install " + info.filename + ": " + ec2.message();
        return;
      }
      std::lock_guard<std::mutex> lock(mutex_);
      pending_loads_.push_back(target);
      for (auto &lang : languages_) {
        if (lang.lang == info.lang) {
          lang.installed = true;
          lang.error.clear();
          break;
        }
      }
    };

    auto sync_entry = [&](const RepositoryLanguage &info, bool install_if_missing) {
      if (info.lang == Lang::EN || info.url.empty()) return;

      const std::filesystem::path target = dir / info.filename;
      std::error_code ec2;
      const bool local_exists = std::filesystem::exists(target, ec2) && !ec2;
      if (!local_exists && !install_if_missing) return;

      std::string local_error;
      const bool local_valid =
          local_exists && validate_locale_file(target, info.lang, local_error);

      const std::filesystem::path tmp_path = cache_dir / (info.filename + ".download");
      std::string download_error;
      if (!download_entry(info, tmp_path, download_error)) {
        if (!local_valid) {
          std::lock_guard<std::mutex> lock(mutex_);
          for (auto &lang : languages_) {
            if (lang.lang == info.lang) {
              lang.error = local_error.empty() ? download_error : local_error;
              break;
            }
          }
        }
        if (worker_error.empty() && !local_valid) worker_error = download_error;
        return;
      }

      if (!local_valid || !files_equal(target, tmp_path)) {
        install_tmp(info, tmp_path);
      } else if (install_if_missing) {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_loads_.push_back(target);
      }
      std::filesystem::remove(tmp_path, ec2);
    };

    if (worker_error.empty() || !manifest_languages.empty()) {
      if (op == Operation::Download) {
        sync_entry(find_entry(requested_lang), true);
      } else if (op == Operation::StartupSync) {
        for (const auto &info : manifest_languages) {
          sync_entry(info, info.lang == requested_lang && info.lang != Lang::EN);
        }
      }
    }
  } catch (const std::exception &ex) {
    worker_error = ex.what();
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!worker_error.empty()) {
      error_ = worker_error;
      status_ = worker_error;
    } else if (op == Operation::Download) {
      status_ = "Language downloaded";
    } else {
      status_ = "Languages checked";
    }
  }
  busy_.store(false);
}

} // namespace memdbg::frontend::locale

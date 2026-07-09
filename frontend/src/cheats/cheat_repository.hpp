/*
 * MemDBG - Cheat repository and source management.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_CHEAT_REPOSITORY_HPP
#define MEMDBG_FRONTEND_CHEAT_REPOSITORY_HPP

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace memdbg::frontend::cheats {

constexpr const char *kDefaultCheatSourceName = "HEN Cheats Collection";

enum class CheatFormat {
  Unknown,
  JSON,   /* GoldHEN JSON format */
  SHN,    /* Reaper pipe-delimited format */
  MC4,    /* Reaper encrypted format */
};

struct CheatSource {
  std::string id;
  std::string name;
  std::string url;             /* manifest URL or flat .txt index URL */
  std::string cheats_base_url; /* base URL for individual cheat file downloads */
  std::string index_format;    /* "manifest_json" or "flat_txt" */
  std::string format;          /* "json", "shn", "mc4" */
  std::string homepage;
  bool enabled = true;
  bool last_ok = false;
  std::string status;
  int cheat_count = 0;
};

struct CheatCatalogEntry {
  std::string source_id;
  std::string source_name;
  std::string game_id;         /* "CUSA28863" or "PPSA04609" */
  std::string title;           /* "Elden Ring" */
  std::string version;         /* "01.13" */
  std::string format;          /* "json", "shn" */
  std::string path;            /* relative path in repo */
  std::string url;             /* direct download URL */
  std::string credits;         /* cheat author(s) */
  uint64_t size = 0;
  bool installed = false;
  std::filesystem::path installed_path;
};

const char *cheat_format_name(CheatFormat fmt);
CheatFormat cheat_format_from_string(const std::string &value);
std::string cheat_format_ext(CheatFormat fmt);

class CheatRepository {
public:
  void set_bundle_root(std::filesystem::path root);

  bool load(std::string *error = nullptr);
  bool save(std::string *error = nullptr) const;

  std::vector<CheatSource> sources() const;
  std::vector<CheatCatalogEntry> catalog() const;

  bool add_source(const std::string &name, const std::string &url,
                  const std::string &cheats_base_url,
                  const std::string &index_format,
                  const std::string &format,
                  const std::string &homepage,
                  std::string *error = nullptr);
  bool remove_source(size_t index, std::string *error = nullptr);
  bool set_source_enabled(size_t index, bool enabled,
                          std::string *error = nullptr);

  bool refresh_all(std::string *error = nullptr);
  bool refresh_source(size_t index, std::string *error = nullptr);

  bool install_cheat(const std::string &game_id,
                     const std::string &version,
                     const std::string &source_id,
                     std::string *error = nullptr);
  bool uninstall_cheat(const std::string &game_id,
                       const std::string &version,
                       std::string *error = nullptr);

  /* Load a cheat file's content into memory (downloads if not cached). */
  bool fetch_cheat_content(const CheatCatalogEntry &entry,
                           std::string &content,
                           std::string *error = nullptr);

  std::filesystem::path bundled_manifest_path() const;
  std::filesystem::path config_path() const;
  std::filesystem::path cheat_data_dir() const;

  struct InstalledRecord {
    std::string source_id;
    std::string game_id;
    std::string version;
    std::string format;
    std::filesystem::path path;
  };

private:
  bool load_unlocked(std::string *error);
  bool save_unlocked(std::string *error) const;
  void ensure_defaults_unlocked();
  void load_cached_catalog_unlocked();

  bool refresh_sources(const std::vector<CheatSource> &sources,
                       std::vector<CheatSource> &out_sources,
                       std::vector<CheatCatalogEntry> &out_catalog,
                       std::string *error);
  bool refresh_one(const CheatSource &source,
                   CheatSource &out_source,
                   std::vector<CheatCatalogEntry> &out_packages,
                   std::string *error);

  bool parse_flat_txt_index(const std::string &content,
                            const CheatSource &source,
                            std::vector<CheatCatalogEntry> &entries,
                            std::string *error);
  bool parse_manifest_json(const std::string &content,
                           const CheatSource &source,
                           std::vector<CheatCatalogEntry> &entries,
                           std::string *error);

  bool install_cheat_unlocked(const CheatCatalogEntry &entry,
                              std::string *error);
  bool find_entry_unlocked(const std::string &game_id,
                           const std::string &version,
                           const std::string &source_id,
                           CheatCatalogEntry &out) const;
  bool find_installed_unlocked(const std::string &game_id,
                               const std::string &version,
                               InstalledRecord &out) const;

  std::filesystem::path source_cache_manifest_path(const CheatSource &source) const;

  mutable std::mutex mutex_;
  std::filesystem::path bundle_root_;
  std::filesystem::path bundled_manifest_path_;
  std::vector<CheatSource> sources_;
  std::vector<CheatCatalogEntry> catalog_;
  std::unordered_map<std::string, InstalledRecord> installed_;
};

} // namespace memdbg::frontend::cheats

#endif /* MEMDBG_FRONTEND_CHEAT_REPOSITORY_HPP */

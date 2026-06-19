/*
 * MemDBG - Plugin manager tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "plugins/repository/plugin_manager.hpp"

#include <cassert>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

#ifndef MEMDBG_TEST_SOURCE_DIR
#define MEMDBG_TEST_SOURCE_DIR "."
#endif

namespace {

void set_test_home(const std::filesystem::path &path) {
#if defined(_WIN32)
  _putenv_s("USERPROFILE", path.string().c_str());
  _putenv_s("LOCALAPPDATA", (path / "LocalAppData").string().c_str());
  _putenv_s("APPDATA", (path / "AppData").string().c_str());
#else
  setenv("HOME", path.string().c_str(), 1);
  unsetenv("XDG_CONFIG_HOME");
  unsetenv("XDG_CACHE_HOME");
  unsetenv("XDG_DATA_HOME");
#endif
}

std::filesystem::path unique_temp_dir() {
  const auto ticks = std::chrono::high_resolution_clock::now()
                         .time_since_epoch()
                         .count();
#if defined(_WIN32)
  const int pid = _getpid();
#else
  const int pid = getpid();
#endif
  return std::filesystem::temp_directory_path() /
         ("memdbg-plugin-test-" + std::to_string(pid) + "-" +
          std::to_string(ticks));
}

} // namespace

int main() {
  namespace fs = std::filesystem;
  namespace plugins = memdbg::frontend::plugins;

  const fs::path temp = unique_temp_dir();
  fs::create_directories(temp);
  set_test_home(temp);

  plugins::PluginManager manager;
  manager.set_bundle_root(fs::path(MEMDBG_TEST_SOURCE_DIR));

  std::string error;
  assert(manager.load(&error));

  const std::string normalized =
      plugins::normalize_source_url("https://github.com/seregonwar/MemDBG-Plugin");
  assert(normalized == plugins::kDefaultSourceUrl);

  const auto catalog = manager.catalog();
  assert(!catalog.empty());

  auto it = std::find_if(catalog.begin(), catalog.end(), [](const auto &pkg) {
    return pkg.id == "io.github.seregonwar.memdbg.context-dump";
  });
  assert(it != catalog.end());
  assert(it->language == plugins::PluginLanguage::Python);
  assert(it->download_count == 0);
  assert(it->icon_url.find("context-dump.png") != std::string::npos);
  assert(it->short_description.find("runtime context") != std::string::npos);
  assert(it->description.find("automation plugins") != std::string::npos);

  assert(manager.install_package(it->id, it->source_id, &error));
  const auto installed_catalog = manager.catalog();
  auto installed = std::find_if(installed_catalog.begin(), installed_catalog.end(),
      [](const auto &pkg) {
        return pkg.id == "io.github.seregonwar.memdbg.context-dump";
      });
  assert(installed != installed_catalog.end());
  assert(installed->installed);
  assert(fs::exists(installed->installed_path / "context_dump.py"));

  plugins::PluginRunContext context;
  context.host = "127.0.0.1";
  context.debug_port = 9020;
  context.udp_port = 9023;
  context.connected = false;
  context.selected_pid = 1234;
  context.selected_process_name = "test-process";
  context.dump_path = "dumps";
  context.trainer_file_path = "trainers/session.cht";
  context.map_count = 2;
  context.scan_hit_count = 3;
  context.trainer_entry_count = 4;

  const plugins::PluginRunResult run = manager.run_plugin(installed->id, context);
  if (run.error.find("interpreter not found") == std::string::npos) {
    assert(run.ok);
    assert(run.output.find("MemDBG Python plugin context") != std::string::npos);
    assert(run.output.find("pid=1234") != std::string::npos);
  }

  assert(manager.uninstall_package(installed->id, &error));

  fs::remove_all(temp);
  std::cout << "plugin_manager tests passed\n";
  return 0;
}

/*
 * MemDBG - protocol probe using the frontend client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_client.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char **argv) {
  std::string host = argc > 1 ? argv[1] : "127.0.0.1";
  uint16_t port =
      argc > 2 ? static_cast<uint16_t>(std::strtoul(argv[2], nullptr, 10))
               : 9020;

  memdbg::frontend::Client client;
  if (!client.connect_to(host, port)) {
    std::cerr << "connect failed: " << client.last_error() << "\n";
    return 1;
  }

  memdbg::frontend::HelloInfo hello;
  if (!client.hello(hello)) {
    std::cerr << "hello failed: " << client.last_error() << "\n";
    return 1;
  }

  if (!client.ping()) {
    std::cerr << "ping failed: " << client.last_error() << "\n";
    return 1;
  }

  std::vector<memdbg::frontend::ProcessEntry> processes;
  if (!client.process_list(processes)) {
    std::cerr << "process list failed: " << client.last_error() << "\n";
    return 1;
  }

  memdbg::frontend::ProcessInfo info;
  if (!processes.empty() && !client.process_info(processes.front().pid, info)) {
    std::cerr << "process info failed: " << client.last_error() << "\n";
    return 1;
  }

  std::cout << "payload=" << hello.name << " " << hello.version
            << " platform=" << memdbg::frontend::platform_name(hello.platform_id)
            << " caps=" << memdbg::frontend::capability_text(hello.capabilities)
            << " processes=" << processes.size();
  if (!processes.empty()) {
    std::cout << " first_pid=" << info.pid << " first_name=" << info.name;
  }
  std::cout << "\n";
  return 0;
}

/*
 * MemDBG - payload loader/upload and daemon-start verification probe.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "core/client/memdbg_client.hpp"
#include "core/payload_sender.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

int main(int argc, char **argv) {
  if (argc != 5) {
    std::cerr << "Usage: memdbg_payload_injection_probe <host> <loader-port> "
                 "<debug-port> <payload.elf>\n";
    return 64;
  }

  const std::string host = argv[1];
  const auto loader_port = static_cast<uint16_t>(
      std::strtoul(argv[2], nullptr, 10));
  const auto debug_port = static_cast<uint16_t>(
      std::strtoul(argv[3], nullptr, 10));
  const std::string payload_path = argv[4];

  /* Do not let the verification loop mistake the old listener for the newly
     uploaded payload. A cooperative stop also drains pooled handlers before
     the loader starts the replacement image. */
  {
    memdbg::frontend::Client previous;
    previous.set_socket_timeout_ms(1500U);
    memdbg::frontend::HelloInfo previous_hello;
    if (previous.connect_to(host, debug_port, 1000U) &&
        previous.hello(previous_hello)) {
      if (!previous.shutdown_payload()) {
        std::cerr << "PREVIOUS PAYLOAD SHUTDOWN FAILED: "
                  << previous.last_error() << "\n";
        return 3;
      }
      previous.disconnect();
      const auto stop_deadline = std::chrono::steady_clock::now() +
                                 std::chrono::seconds(5);
      bool stopped = false;
      while (std::chrono::steady_clock::now() < stop_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        memdbg::frontend::Client probe;
        if (!probe.connect_to(host, debug_port, 250U)) {
          stopped = true;
          break;
        }
      }
      if (!stopped) {
        std::cerr << "PREVIOUS PAYLOAD DID NOT RELEASE PORT " << debug_port
                  << "\n";
        return 3;
      }
      std::cout << "PREVIOUS PAYLOAD STOPPED: port released before upload\n";
    }
  }

  std::string error;
  if (!memdbg::frontend::send_payload_elf(host, loader_port, payload_path,
                                          error)) {
    std::cerr << "UPLOAD FAILED: " << error << "\n";
    return 1;
  }
  std::cout << "UPLOAD COMPLETE: loader accepted the ELF; startup is not yet "
               "verified\n";

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(20);
  unsigned attempt = 0U;
  std::string last_error;
  do {
    ++attempt;
    std::this_thread::sleep_for(std::chrono::seconds(1));
    memdbg::frontend::Client client;
    client.set_socket_timeout_ms(2000U);
    memdbg::frontend::HelloInfo hello;
    if (client.connect_to(host, debug_port, 1500U) && client.hello(hello)) {
      std::cout << "STARTUP VERIFIED: HELLO from " << hello.name << " v"
                << hello.version << " on " << host << ':' << debug_port
                << " after " << attempt << " attempt(s)\n";
      return 0;
    }
    last_error = client.last_error();
  } while (std::chrono::steady_clock::now() < deadline);

  std::cerr << "STARTUP NOT VERIFIED: upload completed, but no valid HELLO was "
               "received from "
            << host << ':' << debug_port << " (last error: " << last_error
            << ")\n";
  return 2;
}

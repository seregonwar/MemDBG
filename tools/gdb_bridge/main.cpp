/*
 * MemDBG - Host-side GDB RSP ↔ MDBG bridge for IDA Pro.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Usage:
 *   memdbg_gdb_bridge --host 192.168.1.50 --port 9020 \
 *                     --listen 127.0.0.1:23946 --pid 123
 */

#include "memdbg_client.hpp"
#include "platform.hpp"
#include "rsp_handler.hpp"
#include "rsp_server.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

struct Options {
  std::string console_host = "127.0.0.1";
  uint16_t console_port = 9020;
  std::string listen_host = "127.0.0.1";
  uint16_t listen_port = 23946;
  int32_t pid = 0;
  bool once = false;
};

void print_usage(const char *prog) {
  std::fprintf(stderr,
               "Usage: %s --host HOST [--port 9020] [--listen [HOST:]PORT] "
               "[--pid PID] [--once]\n"
               "\n"
               "Proxy GDB Remote Serial Protocol to a MemDBG console payload.\n"
               "Point IDA Pro Remote GDB Debugger at the --listen address.\n"
               "\n"
               "Options:\n"
               "  --host HOST          Console IP / hostname (required)\n"
               "  --port N             MDBG debug port (default 9020)\n"
               "  --listen [HOST:]N    RSP listen address (default 127.0.0.1:23946)\n"
               "  --pid PID            Optional pre-attach PID (or use vAttach)\n"
               "  --once               Exit after the first GDB client disconnects\n"
               "  --help               Show this help\n",
               prog);
}

bool parse_listen(const std::string &value, std::string &host, uint16_t &port) {
  const size_t colon = value.rfind(':');
  if (colon == std::string::npos) {
    const int n = std::atoi(value.c_str());
    if (n <= 0 || n > 65535) return false;
    host = "127.0.0.1";
    port = static_cast<uint16_t>(n);
    return true;
  }
  host = value.substr(0U, colon);
  const int n = std::atoi(value.c_str() + colon + 1U);
  if (n <= 0 || n > 65535) return false;
  if (host.empty()) host = "127.0.0.1";
  port = static_cast<uint16_t>(n);
  return true;
}

bool parse_args(int argc, char **argv, Options &opt) {
  bool have_host = false;
  for (int i = 1; i < argc; ++i) {
    const char *arg = argv[i];
    auto need_value = [&](const char *name) -> const char * {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "Missing value for %s\n", name);
        return nullptr;
      }
      return argv[++i];
    };

    if (std::strcmp(arg, "--help") == 0 || std::strcmp(arg, "-h") == 0) {
      print_usage(argv[0]);
      std::exit(0);
    }
    if (std::strcmp(arg, "--host") == 0) {
      const char *v = need_value("--host");
      if (!v) return false;
      opt.console_host = v;
      have_host = true;
      continue;
    }
    if (std::strcmp(arg, "--port") == 0) {
      const char *v = need_value("--port");
      if (!v) return false;
      const int n = std::atoi(v);
      if (n <= 0 || n > 65535) return false;
      opt.console_port = static_cast<uint16_t>(n);
      continue;
    }
    if (std::strcmp(arg, "--listen") == 0) {
      const char *v = need_value("--listen");
      if (!v) return false;
      if (!parse_listen(v, opt.listen_host, opt.listen_port)) {
        std::fprintf(stderr, "Invalid --listen value: %s\n", v);
        return false;
      }
      continue;
    }
    if (std::strcmp(arg, "--pid") == 0) {
      const char *v = need_value("--pid");
      if (!v) return false;
      opt.pid = static_cast<int32_t>(std::atoi(v));
      continue;
    }
    if (std::strcmp(arg, "--once") == 0) {
      opt.once = true;
      continue;
    }
    std::fprintf(stderr, "Unknown option: %s\n", arg);
    return false;
  }
  if (!have_host) {
    std::fprintf(stderr, "--host is required\n");
    return false;
  }
  return true;
}

} // namespace

int main(int argc, char **argv) {
  Options opt;
  if (!parse_args(argc, argv, opt)) {
    print_usage(argv[0]);
    return 1;
  }

  std::string sock_error;
  if (!memdbg::frontend::platform::socket_startup(&sock_error)) {
    std::fprintf(stderr, "Socket startup failed: %s\n", sock_error.c_str());
    return 1;
  }

  memdbg::frontend::Client client;
  std::fprintf(stderr, "[gdb_bridge] Connecting to MDBG %s:%u...\n",
               opt.console_host.c_str(),
               static_cast<unsigned>(opt.console_port));
  if (!client.connect_to(opt.console_host, opt.console_port)) {
    std::fprintf(stderr, "[gdb_bridge] Connect failed: %s\n",
                 client.last_error().c_str());
    memdbg::frontend::platform::socket_cleanup();
    return 1;
  }

  memdbg::frontend::HelloInfo hello;
  if (!client.hello(hello)) {
    std::fprintf(stderr, "[gdb_bridge] HELLO failed: %s\n",
                 client.last_error().c_str());
    client.disconnect();
    memdbg::frontend::platform::socket_cleanup();
    return 1;
  }
  std::fprintf(stderr,
               "[gdb_bridge] Connected to %s (protocol %u, caps 0x%08x)\n",
               hello.name.c_str(),
               static_cast<unsigned>(hello.protocol_version),
               hello.capabilities);

  if ((hello.capabilities & MEMDBG_CAP_DEBUGGER) == 0U) {
    std::fprintf(stderr,
                 "[gdb_bridge] Warning: payload did not advertise "
                 "MEMDBG_CAP_DEBUGGER\n");
  }

  memdbg::gdb_bridge::RspServer server;
  std::string listen_error;
  if (!server.listen_on(opt.listen_host, opt.listen_port, listen_error)) {
    std::fprintf(stderr, "[gdb_bridge] Listen failed: %s\n",
                 listen_error.c_str());
    client.disconnect();
    memdbg::frontend::platform::socket_cleanup();
    return 1;
  }
  std::fprintf(stderr,
               "[gdb_bridge] Listening for IDA/GDB on %s:%u (pid=%d)\n",
               opt.listen_host.c_str(),
               static_cast<unsigned>(server.listen_port()), opt.pid);

  int exit_code = 0;
  for (;;) {
    std::string accept_error;
    auto client_fd = server.accept_client(accept_error);
    if (!memdbg::frontend::platform::socket_valid(client_fd)) {
      std::fprintf(stderr, "[gdb_bridge] Accept failed: %s\n",
                   accept_error.c_str());
      exit_code = 1;
      break;
    }
    std::fprintf(stderr, "[gdb_bridge] GDB client connected\n");

    memdbg::gdb_bridge::RspHandler handler(client, opt.pid);
    server.serve(client_fd, [&](const std::string &packet,
                                memdbg::gdb_bridge::RspConnection &conn) {
      return handler.handle(packet, conn);
    });

    std::fprintf(stderr, "[gdb_bridge] GDB client disconnected\n");
    if (opt.once) break;
  }

  client.disconnect();
  server.close_listen();
  memdbg::frontend::platform::socket_cleanup();
  return exit_code;
}

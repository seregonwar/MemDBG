#ifndef MEMDBG_FRONTEND_DISCOVERY_CLIENT_HPP
#define MEMDBG_FRONTEND_DISCOVERY_CLIENT_HPP

#include "platform.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::frontend {

struct DiscoveryConsole {
  std::string ip;
  uint16_t debug_port = 9020;
  uint16_t udp_log_port = 9023;
  uint32_t capabilities = 0;
  uint16_t platform_id = 0;
  std::string version;
  std::string name;
};

class DiscoveryClient {
public:
  DiscoveryClient() = default;
  ~DiscoveryClient();

  DiscoveryClient(const DiscoveryClient &) = delete;
  DiscoveryClient &operator=(const DiscoveryClient &) = delete;

  bool discover(uint16_t discovery_port, double timeout_seconds,
                std::vector<DiscoveryConsole> &out, std::string &error);
  void cancel();

private:
  platform::socket_handle_t fd_ = platform::invalid_socket();
  std::atomic<bool> cancelled_{false};
};

} // namespace memdbg::frontend

#endif

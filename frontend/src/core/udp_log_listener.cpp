/*
 * MemDBG - UDP log listener for the ImGui frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "udp_log_listener.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <iomanip>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>

namespace memdbg::frontend {

/* ---- Construction / destruction ---- */

UdpLogListener::UdpLogListener() { ring_clear(); }

UdpLogListener::~UdpLogListener() { stop(); }

/* ---- Ring buffer ---- */

void UdpLogListener::ring_push(std::string line) {
  ring_[ring_head_] = std::move(line);
  ring_head_ = (ring_head_ + 1U) % kRingCapacity;
  if (ring_count_ < kRingCapacity) {
    ring_count_++;
  } else {
    evicted_++;
  }
}

std::vector<std::string> UdpLogListener::ring_snapshot() const {
  std::vector<std::string> out;
  out.reserve(ring_count_);
  if (ring_count_ == 0U) return out;

  size_t oldest = (ring_head_ + kRingCapacity - ring_count_) % kRingCapacity;
  for (size_t i = 0; i < ring_count_; ++i) {
    out.push_back(ring_[(oldest + i) % kRingCapacity]);
  }
  return out;
}

void UdpLogListener::ring_clear() {
  ring_head_  = 0;
  ring_count_ = 0;
}

/* ---- Public API ---- */

bool UdpLogListener::start(uint16_t port) {
  stop();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    last_error_.clear();
    startup_done_ = false;
    startup_ok_   = false;
    port_         = port;
    bind_attempts_ = 0;
  }
  stop_requested_.store(false);
  thread_ = std::thread(&UdpLogListener::thread_main, this, port);

  // Wait for startup with a generous timeout (bind retry may take a few secs).
  std::unique_lock<std::mutex> lock(mutex_);
  bool signaled = startup_cv_.wait_for(lock, std::chrono::seconds(5), [this] {
    return startup_done_;
  });
  if (!signaled || !startup_ok_) {
    if (!signaled) {
      last_error_ = "UDP listener startup timed out (tried " +
                    std::to_string(bind_attempts_) + " bind(s))";
    }
    lock.unlock();
    stop();  // join the thread
    return false;
  }
  return true;
}

void UdpLogListener::stop() {
  stop_requested_.store(true);
  if (thread_.joinable()) {
    thread_.join();
  }
  running_.store(false);
}

bool UdpLogListener::running() const { return running_.load(); }

std::string UdpLogListener::last_error() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return last_error_;
}

UdpLogStats UdpLogListener::stats() const {
  std::lock_guard<std::mutex> lock(mutex_);
  UdpLogStats out;
  out.received      = received_;
  out.dropped       = dropped_;
  out.evicted       = evicted_;
  out.port          = port_;
  out.bind_attempts = bind_attempts_;
  out.ring_capacity = static_cast<int>(kRingCapacity);
  return out;
}

std::vector<std::string> UdpLogListener::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return ring_snapshot();
}

void UdpLogListener::clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  ring_clear();
}

/* ---- Helpers (thread-safe only from thread_main) ---- */

static std::string current_time_text() {
  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  char buffer[32];
  if (std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &tm) == 0) {
    return "00:00:00";
  }
  return buffer;
}

static std::string endpoint_text(const sockaddr_in &addr) {
  char host[INET_ADDRSTRLEN] = "";
  if (::inet_ntop(AF_INET, &addr.sin_addr, host, sizeof(host)) == nullptr) {
    std::snprintf(host, sizeof(host), "unknown");
  }
  std::ostringstream out;
  out << host << ":" << ntohs(addr.sin_port);
  return out.str();
}

/* ---- Thread main ---- */

void UdpLogListener::thread_main(uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_error_ = std::string("socket: ") + std::strerror(errno);
    startup_done_ = true;
    startup_ok_   = false;
    startup_cv_.notify_all();
    return;
  }

  // Allow immediate reuse of the port after a crash / quick restart.
  int one = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  // Increase receive buffer to reduce UDP packet loss under load.
  {
    int rcvbuf = 256 * 1024;  // 256 KiB
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  }

  // Short recv timeout so we can check stop_requested_ frequently.
  timeval timeout{};
  timeout.tv_sec  = 0;
  timeout.tv_usec = 250000;  // 250 ms
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  // ---- Bind with exponential-backoff retry (up to 5 attempts) ----
  sockaddr_in addr{};
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port        = htons(port);

  bool bound = false;
  for (int attempt = 1; attempt <= 5; ++attempt) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      bind_attempts_ = attempt;
    }
    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0) {
      bound = true;
      break;
    }
    // Don't retry on permission errors (EACCES = privileged port).
    if (errno == EACCES) break;

    // Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms.
    int delay_ms = 50 * (1 << attempt);  // 100, 200, 400, 800, 1600
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
  }

  if (!bound) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_error_ = std::string("bind port ") + std::to_string(port) +
                  " failed after " + std::to_string(bind_attempts_) +
                  " attempt(s): " + std::strerror(errno);
    startup_done_ = true;
    startup_ok_   = false;
    startup_cv_.notify_all();
    (void)::close(fd);
    return;
  }

  // ---- Startup complete ----
  {
    std::lock_guard<std::mutex> lock(mutex_);
    startup_done_ = true;
    startup_ok_   = true;
    port_         = port;
    startup_cv_.notify_all();
  }
  running_.store(true);

  // ---- Receive loop ----
  int consecutive_recv_errors = 0;

  while (!stop_requested_.load()) {
    char buffer[1500];
    sockaddr_in source{};
    socklen_t source_len = sizeof(source);
    ssize_t n = ::recvfrom(fd, buffer, sizeof(buffer) - 1U, 0,
                           reinterpret_cast<sockaddr *>(&source),
                           &source_len);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Timeout — normal, just check stop_requested_.
        consecutive_recv_errors = 0;
        continue;
      }
      if (errno == EINTR) {
        continue;
      }
      // Real error — count as dropped, don't break the loop.
      consecutive_recv_errors++;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        dropped_++;
        last_error_ = std::string("recv: ") + std::strerror(errno);
      }
      // If we get many consecutive errors the socket is probably dead.
      if (consecutive_recv_errors > 10) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      continue;
    }

    consecutive_recv_errors = 0;

    // Clear any stale error on successful recv.
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!last_error_.empty() && last_error_.rfind("recv:", 0) == 0)
        last_error_.clear();
    }

    if (n == 0) {
      // Zero-length datagram — legal but useless.
      continue;
    }

    buffer[n] = '\0';
    std::string message(buffer);
    // Trim trailing newlines / carriage returns.
    while (!message.empty() &&
           (message.back() == '\n' || message.back() == '\r')) {
      message.pop_back();
    }

    std::ostringstream line;
    line << "[" << current_time_text() << "] " << endpoint_text(source)
         << " " << message;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      received_++;
      ring_push(line.str());
    }
  }

  (void)::close(fd);
  running_.store(false);
}

} // namespace memdbg::frontend

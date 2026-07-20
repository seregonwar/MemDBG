/*
 * memDBG - Reusable test fixture for memdbg_instance tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "fixture_memdbg_instance.h"

#include "memdbg/pal/pal_network.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int g_fixture_passed = 0;
int g_fixture_failed = 0;

int fixture_make_temp_dir(char *out, size_t out_size) {
  int n = snprintf(out, out_size, "/tmp/memdbg_instance_test.XXXXXX");
  if (n < 0 || (size_t)n >= out_size) return -1;
  if (mkdtemp(out) == NULL) return -1;
  return 0;
}

int fixture_pid_file_path(const char *data_root, char *out, size_t out_size) {
  int n = snprintf(out, out_size, "%s/memdbg.pid", data_root);
  if (n < 0 || (size_t)n >= out_size) return -1;
  return 0;
}

int fixture_write_pid_file(const char *data_root, int pid) {
  return fixture_write_pid_file_with_token(data_root, pid, 0U);
}

int fixture_write_pid_file_with_token(const char *data_root, int pid,
                                      uint64_t token) {
  char path[1024];
  FILE *fp;
  if (fixture_pid_file_path(data_root, path, sizeof(path)) != 0) return -1;
  fp = fopen(path, "w");
  if (fp == NULL) return -1;
  if (token != 0U) {
    fprintf(fp, "%d %016llx\n", pid, (unsigned long long)token);
  } else {
    fprintf(fp, "%d\n", pid);
  }
  fclose(fp);
  return 0;
}

void fixture_remove_pid_file(const char *data_root) {
  char path[1024];
  if (fixture_pid_file_path(data_root, path, sizeof(path)) != 0) return;
  (void)unlink(path);
}

int fixture_pid_file_exists(const char *data_root) {
  char path[1024];
  struct stat st;
  if (fixture_pid_file_path(data_root, path, sizeof(path)) != 0) return 0;
  return stat(path, &st) == 0;
}

void fixture_cleanup_dir(const char *data_root) {
  fixture_remove_pid_file(data_root);
  (void)rmdir(data_root);
}

uint16_t fixture_get_free_port(void) {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  if (fd < 0) return 0;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  uint16_t port = 0;
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
      getsockname(fd, (struct sockaddr *)&addr, &len) == 0) {
    port = ntohs(addr.sin_port);
  }
  (void)pal_socket_close(fd);
  return port;
}

/* ---- Shared listener plumbing ---- */

typedef struct {
  int listen_fd;
  uint16_t port;
} fixture_listener_args_t;

static int bind_loopback_listener(int *out_fd, uint16_t *out_port) {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  int one = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(fd, 16) != 0 ||
      getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
    (void)close(fd);
    return -1;
  }

  *out_fd = fd;
  *out_port = ntohs(addr.sin_port);
  return 0;
}

static int start_listener(void *(*thread_fn)(void *), fixture_listener_t *out) {
  fixture_listener_args_t *args =
      (fixture_listener_args_t *)calloc(1, sizeof(*args));
  if (args == NULL) return -1;

  if (bind_loopback_listener(&args->listen_fd, &args->port) != 0) {
    free(args);
    return -1;
  }

  if (pthread_create(&out->thread, NULL, thread_fn, args) != 0) {
    (void)close(args->listen_fd);
    free(args);
    return -1;
  }

  out->listen_fd = args->listen_fd;
  out->port = args->port;
  out->thread_args = args;
  return 0;
}

/* ---- Plain TCP listener that accepts and closes (non-MemDBG service) ---- */

static void *plain_listener_thread(void *arg) {
  fixture_listener_args_t *args = (fixture_listener_args_t *)arg;
  int listen_fd = args->listen_fd;
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
  if (client_fd >= 0) {
    (void)close(client_fd);
  }
  return NULL;
}

int fixture_start_plain_listener(fixture_listener_t *out) {
  return start_listener(plain_listener_thread, out);
}

/* ---- Fake MemDBG listener that replies to HELLO ---- */

static void *fake_memdbg_listener_thread(void *arg) {
  fixture_listener_args_t *args = (fixture_listener_args_t *)arg;
  int listen_fd = args->listen_fd;

  for (;;) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
      break;
    }

    char buf[256];
    ssize_t n = recv(client_fd, buf, sizeof(buf), 0);

    memdbg_response_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = MEMDBG_PACKET_MAGIC;
    hdr.version = MEMDBG_PROTOCOL_VERSION;
    hdr.command = MEMDBG_CMD_HELLO;
    hdr.request_id = 0;
    hdr.status = (int32_t)MEMDBG_OK;
    hdr.length = sizeof(memdbg_hello_response_t);

    bool valid_request = false;
    if (n >= (ssize_t)sizeof(memdbg_packet_header_t)) {
      const memdbg_packet_header_t *req = (const memdbg_packet_header_t *)buf;
      if (req->magic == MEMDBG_PACKET_MAGIC &&
          req->command == MEMDBG_CMD_HELLO) {
        hdr.request_id = req->request_id;
        valid_request = true;
      }
    }

    if (!valid_request) {
      (void)close(client_fd);
      continue;
    }

    memdbg_hello_response_t hello;
    memset(&hello, 0, sizeof(hello));
    hello.protocol_version = MEMDBG_PROTOCOL_VERSION;
    hello.platform_id = MEMDBG_PLATFORM_HOST;
    hello.capabilities = 0;
    hello.debug_port = args->port;
    hello.udp_log_port = 0;
    hello.feature_level = MEMDBG_PROTOCOL_FEATURE_LEVEL;
    hello.daemon_instance_id = FIXTURE_INSTANCE_ID;
    (void)snprintf(hello.version, sizeof(hello.version), "test");
    (void)snprintf(hello.name, sizeof(hello.name), "MemDBG");

    (void)send(client_fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    (void)send(client_fd, &hello, sizeof(hello), MSG_NOSIGNAL);
    (void)close(client_fd);
  }

  return NULL;
}

int fixture_start_memdbg_listener(fixture_listener_t *out) {
  return start_listener(fake_memdbg_listener_thread, out);
}

void fixture_stop_listener(fixture_listener_t *listener) {
  if (listener == NULL || listener->listen_fd < 0) return;
  /* shutdown() guarantees accept() unblocks on Linux (POSIX leaves close()
   * behavior on an accept()-blocked socket undefined; Linux does NOT unblock,
   * while macOS/BSD do).  pthread_join would hang forever without this. */
  (void)shutdown(listener->listen_fd, SHUT_RDWR);
  (void)close(listener->listen_fd);
  listener->listen_fd = -1;
  (void)pthread_join(listener->thread, NULL);
  if (listener->thread_args != NULL) {
    free(listener->thread_args);
    listener->thread_args = NULL;
  }
}

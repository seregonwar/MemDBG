/*
 * memDBG - ps5debug wire compatibility: console commands.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "internal.h"

#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_notification.h"

#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#include <ps4/klog.h>
#elif defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#include <ps5/klog.h>
#include <sys/reboot.h>
#ifndef RB_AUTOBOOT
#define RB_AUTOBOOT 0
#endif
extern int reboot(int);
#define LEGACY_HAS_REBOOT 1
#endif

typedef struct legacy_console_print_request {
  uint32_t length;
} LEGACY_PACKED legacy_console_print_request_t;

typedef struct legacy_console_notify_request {
  uint32_t message_type;
  uint32_t length;
} LEGACY_PACKED legacy_console_notify_request_t;

typedef struct legacy_console_foreground_response {
  uint32_t pid;
  char title_id[16];
  char content_id[64];
  char name[40];
  char app_ver[16];
} LEGACY_PACKED legacy_console_foreground_response_t;

static memdbg_status_t legacy_console_read_text(socket_t fd, uint32_t length,
                                                 char **out) {
  if (out == NULL || length > 4096U) return MEMDBG_ERR_PARAM;
  *out = (char *)malloc((size_t)length + 1U);
  if (*out == NULL) return MEMDBG_ERR_NOMEM;
  if (length != 0U && pal_socket_read_exact(fd, *out, length) < 0) {
    free(*out);
    *out = NULL;
    return MEMDBG_ERR_NET;
  }
  (*out)[length] = '\0';
  return MEMDBG_OK;
}

static memdbg_status_t legacy_console_foreground(socket_t fd) {
  legacy_console_foreground_response_t out;
  memdbg_process_list_t list;
  memset(&out, 0, sizeof(out));
  memset(&list, 0, sizeof(list));
  memdbg_status_t st = memdbg_process_list(&list);
  if (st == MEMDBG_OK) {
    for (size_t i = 0U; i < list.count; ++i) {
      if (strcmp(list.entries[i].name, "eboot.bin") != 0 &&
          strcmp(list.entries[i].name, "eboot") != 0)
        continue;
      memdbg_process_info_response_t info;
      memset(&info, 0, sizeof(info));
      if (memdbg_process_info(list.entries[i].pid, &info) == MEMDBG_OK) {
        out.pid = (uint32_t)info.pid;
        legacy_copy_fixed(out.title_id, sizeof(out.title_id), info.title_id);
        legacy_copy_fixed(out.content_id, sizeof(out.content_id), info.content_id);
        legacy_copy_fixed(out.name, sizeof(out.name), info.name);
      }
      break;
    }
    memdbg_process_list_free(&list);
  }
  if (st != MEMDBG_OK)
    return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
                 legacy_send_blob(fd, &out, sizeof(out)) == 0
             ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_console_command(socket_t fd, uint32_t command,
                                              const void *body,
                                              uint32_t body_len) {
  if (command == LEGACY_CMD_CONSOLE_END) {
    const int rc = legacy_send_status(fd, LEGACY_CMD_SUCCESS);
    if (rc == 0) memdbg_daemon_request_stop();
    return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }
  if (command == LEGACY_CMD_CONSOLE_INFO)
    return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (command == LEGACY_CMD_CONSOLE_FOREGROUND)
    return legacy_console_foreground(fd);
  if (command == LEGACY_CMD_CONSOLE_REBOOT) {
#if defined(LEGACY_HAS_REBOOT)
    (void)reboot(RB_AUTOBOOT);
    return MEMDBG_OK;
#else
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
#endif
  }

  uint32_t length = 0U;
  if (command == LEGACY_CMD_CONSOLE_PRINT) {
    if (!legacy_has_body(body, body_len, sizeof(legacy_console_print_request_t)))
      return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0
                 ? MEMDBG_OK : MEMDBG_ERR_NET;
    length = ((const legacy_console_print_request_t *)body)->length;
  } else if (command == LEGACY_CMD_CONSOLE_NOTIFY) {
    if (!legacy_has_body(body, body_len, sizeof(legacy_console_notify_request_t)))
      return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0
                 ? MEMDBG_OK : MEMDBG_ERR_NET;
    length = ((const legacy_console_notify_request_t *)body)->length;
  } else {
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  char *text = NULL;
  memdbg_status_t st = legacy_console_read_text(fd, length, &text);
  if (st == MEMDBG_OK) {
    if (command == LEGACY_CMD_CONSOLE_NOTIFY) {
      pal_notification_send(text);
    } else {
#if defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || defined(PS4) ||          \
    defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)
      (void)klog_puts(text);
#else
      memdbg_log_write(MEMDBG_LOG_INFO, "console: %s", text);
#endif
    }
  }
  free(text);
  return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file pal_notification.c
 * @brief Platform Abstraction Layer — System notification implementation
 *
 * PS4: sceKernelSendNotificationRequest
 * PS5: sceNotificationSend (rich interactive toast) with fallback
 * Host: memdbg_log
 */

#include "memdbg/pal/pal_notification.h"
#include "memdbg/core/memdbg_log.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__ORBIS__) || defined(PS4)

/* ---- PS4 ---- */

typedef struct notify_request {
  char padding[45];
  char message[3075];
} notify_request_t;

__attribute__((weak)) int
sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

static int g_notify_available = 0;

int pal_notification_init(void) {
  g_notify_available = (sceKernelSendNotificationRequest != NULL) ? 1 : 0;
  return g_notify_available ? 0 : -1;
}

void pal_notification_shutdown(void) { g_notify_available = 0; }

void pal_notification_send(const char *message) {
  if (!g_notify_available || message == NULL) return;

  notify_request_t req;
  memset(&req, 0, sizeof(req));
  (void)snprintf(req.message, sizeof(req.message), "%s", message);
  if (sceKernelSendNotificationRequest != NULL)
    (void)sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

#elif defined(__PROSPERO__) || defined(PS5)

/* ---- PS5 ---- */

#include <time.h>
#include <unistd.h>

typedef struct notify_request {
  char padding[45];
  char message[3075];
} notify_request_t;

__attribute__((weak)) int
sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

__attribute__((weak)) int
sceNotificationSend(int userId, int isLogged, const char *payload);

static int g_notify_available = 0;

static void append_json_escaped(char *dst, size_t dst_size, const char *src) {
  size_t used = strlen(dst);
  if (used >= dst_size) return;

  for (; *src != '\0' && used + 1U < dst_size; ++src) {
    const char *esc = NULL;
    char one[2]      = {0, 0};
    switch (*src) {
    case '\\': esc = "\\\\"; break;
    case '"':  esc = "\\\""; break;
    case '\n': esc = "\\n";  break;
    case '\r': esc = "\\r";  break;
    case '\t': esc = "\\t";  break;
    default:   one[0] = *src; esc = one; break;
    }

    size_t n = strlen(esc);
    if (used + n >= dst_size) break;
    memcpy(dst + used, esc, n);
    used += n;
    dst[used] = '\0';
  }
}

static int send_rich_notification(const char *message) {
  if (sceNotificationSend == NULL || message == NULL || message[0] == '\0')
    return -1;

  char escaped_message[3072];
  char payload[6144];
  char created_at[32];
  char notification_id[32];
  time_t now = time(NULL);
  struct tm tm_utc;

  escaped_message[0] = '\0';
  append_json_escaped(escaped_message, sizeof(escaped_message), message);

  if (gmtime_r(&now, &tm_utc) == NULL) return -1;
  if (strftime(created_at, sizeof(created_at), "%Y-%m-%dT%H:%M:%S.000Z",
               &tm_utc) == 0)
    return -1;

  (void)snprintf(notification_id, sizeof(notification_id), "%u",
                 (unsigned)((uint32_t)now ^ (uint32_t)getpid()));

  int len = snprintf(
      payload, sizeof(payload),
      "{"
      "\"rawData\":{"
      "\"viewTemplateType\":\"InteractiveToastTemplateB\","
      "\"channelType\":\"ServiceFeedback\","
      "\"bundleName\":\"MemDBG\","
      "\"useCaseId\":\"IDC\","
      "\"soundEffect\":\"none\","
      "\"toastOverwriteType\":\"InQueue\","
      "\"isImmediate\":true,"
      "\"priority\":100,"
      "\"viewData\":{"
      "\"icon\":{\"type\":\"Predefined\",\"parameters\":{\"icon\":\"notice_info\"}},"
      "\"message\":{\"body\":\"%s\"},"
      "\"subMessage\":{\"body\":\"MemDBG\"}"
      "},"
      "\"platformViews\":{"
      "\"previewDisabled\":{\"viewData\":{"
      "\"icon\":{\"type\":\"Predefined\",\"parameters\":{\"icon\":\"community\"}},"
      "\"message\":{\"body\":\"%s\"}"
      "}}"
      "}"
      "},"
      "\"createdDateTime\":\"%s\","
      "\"localNotificationId\":\"%s\""
      "}",
      escaped_message, escaped_message, created_at, notification_id);
  if (len < 0 || (size_t)len >= sizeof(payload)) return -1;

  return sceNotificationSend(0xFE, 1, payload);
}

int pal_notification_init(void) {
  if (sceNotificationSend != NULL || sceKernelSendNotificationRequest != NULL) {
    g_notify_available = 1;
    return 0;
  }
  g_notify_available = 0;
  return -1;
}

void pal_notification_shutdown(void) { g_notify_available = 0; }

void pal_notification_send(const char *message) {
  if (!g_notify_available || message == NULL) return;

  /* Try rich notification first (PS5 5.00+), fall back to legacy */
  if (send_rich_notification(message) == 0) return;

  notify_request_t req;
  memset(&req, 0, sizeof(req));
  (void)snprintf(req.message, sizeof(req.message), "%s", message);
  if (sceKernelSendNotificationRequest != NULL)
    (void)sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

#else

/* ---- Host (Linux / macOS / FreeBSD) ---- */

int pal_notification_init(void) {
  memdbg_log_write(MEMDBG_LOG_INFO, "notification system initialized");
  return 0;
}

void pal_notification_shutdown(void) { /* no-op */ }

void pal_notification_send(const char *message) {
  if (message == NULL) return;
  memdbg_log_write(MEMDBG_LOG_INFO, "notify: %s", message);
}

#endif

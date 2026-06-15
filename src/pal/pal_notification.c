/*
MIT License

Copyright (c) 2026 seregonwar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
 * @file pal_notification.c
 * @brief Platform Abstraction Layer - Notification Implementation (PS4/PS5)
 *
 * @author SeregonWar
 * @version 1.0.0
 * @date 2026-02-13
 *
 */
#include "netmount/pal/pal_notification.h"

#ifndef NETMOUNT_SECURE_LOGS
#define NETMOUNT_SECURE_LOGS 0
#endif

#if NETMOUNT_SECURE_LOGS
#include "netmount/core/nm_log.h"
#define PAL_NOTIFY_SECURE_LOG(message_)                                        \
  do {                                                                         \
    if ((message_) != NULL)                                                    \
      nm_log_important("notify:%s", (message_));                               \
  } while (0)
#else
#define PAL_NOTIFY_SECURE_LOG(message_)                                        \
  do {                                                                         \
    (void)(message_);                                                          \
  } while (0)
#endif

#if defined(PLATFORM_PS4)

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct notify_request {
  char padding[45];
  char message[3075];
} notify_request_t;

__attribute__((weak)) int
sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

static int g_notify_available = 0;

int pal_notification_init(void) {
  if (sceKernelSendNotificationRequest == NULL) {
    g_notify_available = 0;
    return -1;
  }
  g_notify_available = 1;
  return 0;
}

void pal_notification_shutdown(void) { g_notify_available = 0; }

void pal_notification_send(const char *message) {
  if ((g_notify_available == 0) || (message == NULL)) {
    return;
  }

  PAL_NOTIFY_SECURE_LOG(message);

  notify_request_t req;
  memset(&req, 0, sizeof(req));
  (void)snprintf(req.message, sizeof(req.message), "%s", message);
  if (sceKernelSendNotificationRequest != NULL) {
    (void)sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
  }
}

#elif defined(PLATFORM_PS5)

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct notify_request {
  char padding[45];
  char message[3075];
} notify_request_t;

__attribute__((weak)) int
sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

__attribute__((weak)) int sceNotificationSend(int userId, int isLogged,
                                              const char *payload);

static int g_notify_available = 0;

static void append_json_escaped(char *dst, size_t dst_size, const char *src) {
  size_t used = strlen(dst);
  if (used >= dst_size)
    return;

  for (; *src != '\0' && used + 1U < dst_size; ++src) {
    const char *esc = NULL;
    char one[2] = {0, 0};
    switch (*src) {
    case '\\':
      esc = "\\\\";
      break;
    case '"':
      esc = "\\\"";
      break;
    case '\n':
      esc = "\\n";
      break;
    case '\r':
      esc = "\\r";
      break;
    case '\t':
      esc = "\\t";
      break;
    default:
      one[0] = *src;
      esc = one;
      break;
    }

    size_t n = strlen(esc);
    if (used + n >= dst_size)
      break;
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

  if (gmtime_r(&now, &tm_utc) == NULL)
    return -1;
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
      "\"bundleName\":\"NetMount\","
      "\"useCaseId\":\"IDC\","
      "\"soundEffect\":\"none\","
      "\"toastOverwriteType\":\"InQueue\","
      "\"isImmediate\":true,"
      "\"priority\":100,"
      "\"viewData\":{"
      "\"icon\":{\"type\":\"Predefined\",\"parameters\":{\"icon\":\"notice_info\"}},"
      "\"message\":{\"body\":\"%s\"},"
      "\"subMessage\":{\"body\":\"NetMount\"}"
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
  if (len < 0 || (size_t)len >= sizeof(payload))
    return -1;

  return sceNotificationSend(0xFE, 1, payload);
}

int pal_notification_init(void) {
  if (sceNotificationSend != NULL) {
    g_notify_available = 1;
    return 0;
  }
  if (sceKernelSendNotificationRequest != NULL) {
    g_notify_available = 1;
    return 0;
  }
  g_notify_available = 0;
  return -1;
}

void pal_notification_shutdown(void) { g_notify_available = 0; }

void pal_notification_send(const char *message) {
  if ((g_notify_available == 0) || (message == NULL)) {
    return;
  }

  PAL_NOTIFY_SECURE_LOG(message);

  if (send_rich_notification(message) == 0) {
    return;
  }

  notify_request_t req;
  memset(&req, 0, sizeof(req));
  (void)snprintf(req.message, sizeof(req.message), "%s", message);
  if (sceKernelSendNotificationRequest != NULL) {
    (void)sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
  }
}

#else

#include <stddef.h>
#include <syslog.h>

static int g_syslog_open = 0;

int pal_notification_init(void) {
  if (g_syslog_open == 0) {
    openlog("zftpd", LOG_PID | LOG_CONS, LOG_DAEMON);
    g_syslog_open = 1;
  }
  return 0;
}

void pal_notification_shutdown(void) {
  if (g_syslog_open != 0) {
    closelog();
    g_syslog_open = 0;
  }
}

void pal_notification_send(const char *message) {
  if (message == NULL) {
    return;
  }

  PAL_NOTIFY_SECURE_LOG(message);

  if (g_syslog_open == 0) {
    openlog("zftpd", LOG_PID | LOG_CONS, LOG_DAEMON);
    g_syslog_open = 1;
  }

  syslog(LOG_INFO, "%s", message);
}

#endif

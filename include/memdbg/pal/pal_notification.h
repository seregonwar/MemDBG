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
 * @file pal_notification.h
 * @brief Platform Abstraction Layer — System notification (PS4/PS5/host)
 *
 * Sends system-level notifications visible on the console's UI.
 * PS4: sceKernelSendNotificationRequest
 * PS5: sceNotificationSend (rich interactive toast) with fallback to
 *      sceKernelSendNotificationRequest
 * Host: memdbg_log (file + UDP)
 */

#ifndef MEMDBG_PAL_NOTIFICATION_H
#define MEMDBG_PAL_NOTIFICATION_H

#ifdef __cplusplus
extern "C" {
#endif

int  pal_notification_init(void);
void pal_notification_shutdown(void);
void pal_notification_send(const char *message);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_NOTIFICATION_H */

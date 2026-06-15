/*
 * memDBG — UDP discovery listener.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Binds a UDP socket on the discovery port and replies to broadcast
 * discovery pings with the payload's connection details.  Runs in a
 * dedicated thread; the daemon stops it during shutdown.
 */

#ifndef MEMDBG_TELEMETRY_DISCOVERY_H
#define MEMDBG_TELEMETRY_DISCOVERY_H

#include "memdbg/core/memdbg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Start the UDP discovery listener on cfg->discovery_port.
   Returns MEMDBG_OK on success. */
memdbg_status_t memdbg_discovery_start(const memdbg_config_t *cfg);

/* Stop the listener and join the thread.  Safe to call even if
   discovery was never started. */
void memdbg_discovery_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_TELEMETRY_DISCOVERY_H */

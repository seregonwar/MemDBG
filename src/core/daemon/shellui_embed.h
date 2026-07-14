/*
 * MemDBG - ShellUI SPRX embedding (extract to filesystem at daemon startup).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef MEMDBG_SHELLUI_EMBED_H
#define MEMDBG_SHELLUI_EMBED_H

#ifdef __cplusplus
extern "C" {
#endif

/* Write the embedded SPRX to /user/data/memdbg/memdbg_shellui.sprx.
 * Skips if the file already exists and has the correct size.
 * Returns 0 on success, negative on error. */
int shellui_embed_extract(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SHELLUI_EMBED_H */

/*
 * memDBG - Page alias engine: map foreign physical pages via PTE manipulation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_SCANNER_PAGE_ALIAS_H
#define MEMDBG_SCANNER_PAGE_ALIAS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct page_alias_ctx page_alias_ctx_t;

/* Create an alias context for the given target PID.
 * arena_cap_bytes: size of the virtual arena (0 = use 64MB default). */
page_alias_ctx_t *page_alias_begin(uint32_t pid, uint64_t arena_cap_bytes);

/* Bind (or rebind) the context to a different PID. */
void page_alias_rebind(page_alias_ctx_t *ctx, uint32_t pid);

/* Map `length` bytes starting at `target_va` into the payload's address space
 * so that the returned pointer is directly readable. The mapping stays live
 * until the next page_alias_release() call (single-map context).
 *
 * Use page_alias_release() when done with the mapped window.
 * Returns NULL on failure. *mapped_len_out receives the actual mapped length
 * (which may equal 'length'). */
const void *page_alias_map(page_alias_ctx_t *ctx,
                           uint64_t target_va, uint64_t length,
                           uint64_t *mapped_len_out);

/* Release the currently active mapping so the arena span can be reused. */
void page_alias_release(page_alias_ctx_t *ctx);

/* Free all resources associated with the alias context. */
void page_alias_end(page_alias_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SCANNER_PAGE_ALIAS_H */

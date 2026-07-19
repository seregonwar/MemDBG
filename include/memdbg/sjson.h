/*
 * memDBG - sJson wrapper for payload-side JSON building.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-only OR MIT
 *
 * sJson is a high-performance, arena-allocated, single-header JSON library.
 * https://github.com/seregonwar/sJson
 */

#ifndef MEMDBG_SJSON_H
#define MEMDBG_SJSON_H

/* Configure sJson for the payload environment. */
#define JSON_MAX_DEPTH         32U
#define JSON_MAX_STRING_LEN    (256U * 1024U)
#define JSON_MAX_NODES         (256U * 1024U)
#define JSON_MAX_ARRAY_LEN     (128U * 1024U)
#define JSON_INTROSORT_THRESH  16U
#define JSON_ARENA_ALIGN       8U
#define JSON_FAST_FLOAT        0   /* Don't need float parsing in the payload */

/*
 * Implementation: include the single-header source.
 * This file is included ONCE in src/sjson_impl.c (the JSON_IMPLEMENTATION
 * anchor). Other translation units only see declarations.
 *
 * sJson has some variables/functions that are only used when JSON_FAST_FLOAT
 * is enabled; suppress related warnings since we ship with it disabled.
 */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-but-set-variable"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunreachable-code-generic-assoc"
#endif
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include "../../external/sjson/sJson.c"

#ifdef __clang__
#pragma clang diagnostic pop
#endif
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#endif /* MEMDBG_SJSON_H */

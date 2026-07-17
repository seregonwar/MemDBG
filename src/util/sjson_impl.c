/*
 * memDBG - sJson single-header implementation anchor.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-only OR MIT
 *
 * Defines JSON_IMPLEMENTATION once so the sJson source is compiled
 * into exactly one object file.  Every other translation unit that
 * includes memdbg/sjson.h will only see the public declarations.
 */

#define JSON_IMPLEMENTATION
#include "memdbg/sjson.h"

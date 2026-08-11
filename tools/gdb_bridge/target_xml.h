/*
 * MemDBG - GDB target description for i386:x86-64.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_GDB_BRIDGE_TARGET_XML_H
#define MEMDBG_GDB_BRIDGE_TARGET_XML_H

/*
 * +-------------------------------------------------------------------+
 * | Target XML Description                                            |
 * +-------------------------------------------------------------------+
 */
/* Keep the description intentionally minimal.  IDA then uses its built-in
 * amd64 core layout, matching the known-good ps4-payload-dev/gdbsrv contract. */
static const char kMemdbgGdbTargetXml[] =
    "<?xml version=\"1.0\"?>\n"
    "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
    "<target>\n"
    "<architecture>i386:x86-64</architecture>\n"
    "<osabi>none</osabi>\n"
    "</target>\n";

#endif /* MEMDBG_GDB_BRIDGE_TARGET_XML_H */

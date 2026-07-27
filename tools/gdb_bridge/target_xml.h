/*
 * MemDBG - Minimal GDB target description for i386:x86-64.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_GDB_BRIDGE_TARGET_XML_H
#define MEMDBG_GDB_BRIDGE_TARGET_XML_H

/* Core GPRs only (MVP). FPU/XMM intentionally omitted. */
static const char kMemdbgGdbTargetXml[] =
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
    "<target version=\"1.0\">"
    "<architecture>i386:x86-64</architecture>"
    "<feature name=\"org.gnu.gdb.i386.core\">"
    "<reg name=\"rax\" bitsize=\"64\" type=\"int64\" regnum=\"0\"/>"
    "<reg name=\"rbx\" bitsize=\"64\" type=\"int64\" regnum=\"1\"/>"
    "<reg name=\"rcx\" bitsize=\"64\" type=\"int64\" regnum=\"2\"/>"
    "<reg name=\"rdx\" bitsize=\"64\" type=\"int64\" regnum=\"3\"/>"
    "<reg name=\"rsi\" bitsize=\"64\" type=\"int64\" regnum=\"4\"/>"
    "<reg name=\"rdi\" bitsize=\"64\" type=\"int64\" regnum=\"5\"/>"
    "<reg name=\"rbp\" bitsize=\"64\" type=\"int64\" regnum=\"6\"/>"
    "<reg name=\"rsp\" bitsize=\"64\" type=\"int64\" regnum=\"7\"/>"
    "<reg name=\"r8\" bitsize=\"64\" type=\"int64\" regnum=\"8\"/>"
    "<reg name=\"r9\" bitsize=\"64\" type=\"int64\" regnum=\"9\"/>"
    "<reg name=\"r10\" bitsize=\"64\" type=\"int64\" regnum=\"10\"/>"
    "<reg name=\"r11\" bitsize=\"64\" type=\"int64\" regnum=\"11\"/>"
    "<reg name=\"r12\" bitsize=\"64\" type=\"int64\" regnum=\"12\"/>"
    "<reg name=\"r13\" bitsize=\"64\" type=\"int64\" regnum=\"13\"/>"
    "<reg name=\"r14\" bitsize=\"64\" type=\"int64\" regnum=\"14\"/>"
    "<reg name=\"r15\" bitsize=\"64\" type=\"int64\" regnum=\"15\"/>"
    "<reg name=\"rip\" bitsize=\"64\" type=\"code_ptr\" regnum=\"16\"/>"
    "<reg name=\"eflags\" bitsize=\"32\" type=\"int32\" regnum=\"17\"/>"
    "<reg name=\"cs\" bitsize=\"32\" type=\"int32\" regnum=\"18\"/>"
    "<reg name=\"ss\" bitsize=\"32\" type=\"int32\" regnum=\"19\"/>"
    "<reg name=\"ds\" bitsize=\"32\" type=\"int32\" regnum=\"20\"/>"
    "<reg name=\"es\" bitsize=\"32\" type=\"int32\" regnum=\"21\"/>"
    "<reg name=\"fs\" bitsize=\"32\" type=\"int32\" regnum=\"22\"/>"
    "<reg name=\"gs\" bitsize=\"32\" type=\"int32\" regnum=\"23\"/>"
    "</feature>"
    "</target>";

#endif /* MEMDBG_GDB_BRIDGE_TARGET_XML_H */

#!/usr/bin/env python3
"""Test script for remaining untested/uncertain MemDBG payload commands.
   All struct.pack formats verified against memdbg_protocol.h."""

import socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.10"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9020
MAGIC = 0x4742444D

s = socket.socket()
s.settimeout(15)
s.connect((HOST, PORT))

def cmd(cmd_id, rid, body=b""):
    hdr = struct.pack("<IHHII", MAGIC, 1, cmd_id, rid, len(body))
    s.sendall(hdr + body)
    r = b""
    while len(r) < 20:
        r += s.recv(20 - len(r))
    _, _, _, _, status, length = struct.unpack("<IHHIiI", r)
    data = b""
    if length > 0:
        while len(data) < length:
            data += s.recv(length - len(data))
    return status, data

def test(name, status, extra=""):
    mark = "[OK]" if status == 0 else "[FAIL]"
    print(f"  {mark} {name}: status={status} {extra}")

# --- HELLO + find eboot ---
status, data = cmd(0x0001, 1)
pv, pid, caps = struct.unpack("<HHI", data[:8])
ver = data[12:28].split(b"\x00")[0].decode()
print(f"HELLO: {ver} caps=0x{caps:08X}")

status, data = cmd(0x0100, 2)
count = struct.unpack("<I", data[:4])[0]
eboot_pid = None
off = 4
for i in range(count):
    p, pp = struct.unpack("<ii", data[off:off+8])
    name = data[off+8:off+56].split(b"\x00")[0].decode("utf-8", "replace")
    off += 56
    if "eboot" in name.lower():
        eboot_pid = p
        break
print(f"eboot PID={eboot_pid}  (total procs={count})")

# ====================== SCANNING ======================
print("\n=== SCANNING ===")

# SCAN_POINTER (0x0303)
# memdbg_scan_pointer_request_t: i Q Q Q I I I I = 44 bytes
body = struct.pack("<iQQQIIII", eboot_pid, 0x400000, 0x100000, 0x400000, 3, 100, 8, 0)
status, data = cmd(0x0303, 10, body)
if status == 0 and len(data) >= 40:
    pref = struct.unpack("<IIQQIIII", data[:40])
    test("SCAN_POINTER", status, f"count={pref[0]} scanned={pref[2]}")
else:
    test("SCAN_POINTER", status)

# SCAN_EXACT legacy (0x0300)
# memdbg_scan_exact_request_t: i Q Q I I I I + 16B value = 52 bytes
body = struct.pack("<iQQIIII", eboot_pid, 0x400000, 0x10000, 0, 4, 1, 100)
body += b"\x00" * 16
status, data = cmd(0x0300, 11, body)
if status == 0 and len(data) >= 40:
    pref = struct.unpack("<IIQQIIII", data[:40])
    test("SCAN_EXACT", status, f"count={pref[0]}")
else:
    test("SCAN_EXACT", status)

# SCAN_UNKNOWN_V2 (0x0306)
# memdbg_scan_unknown_request_t: I H H I i I I I I I I Q Q Q = 64 bytes
body = struct.pack("<IHHIIIIIIIIQQQ",
    0x314E4B55, 1, 64, 1,         # abi, version, struct_size, flags
    eboot_pid, 0, 8, 8, 100, 0x5, 0,  # pid..reserved
    0x400000, 0xD1C000, 8*1024*1024)    # start, end, max_bytes
status, data = cmd(0x0306, 12, body)
if status == 0 and len(data) >= 40:
    pref = struct.unpack("<IIQQIIII", data[:40])
    test("SCAN_UNKNOWN_V2", status, f"count={pref[0]} scanned={pref[2]}")
else:
    test("SCAN_UNKNOWN_V2", status)

# ====================== DEBUGGER ======================
print("\n=== DEBUGGER ===")

body = struct.pack("<iI", eboot_pid, 0)
status, _ = cmd(0x0600, 20, body)
test("ATTACH", status)
if status != 0:
    s.close()
    sys.exit(1)

status, data = cmd(0x0605, 21)
tcount = struct.unpack("<I", data[:4])[0]
lwp = struct.unpack("<i", data[8:12])[0]
print(f"  threads={tcount}  LWP={lwp}")

# GET_REGS
body = struct.pack("<ii", eboot_pid, lwp)
status, regs = cmd(0x0606, 22, body)
test("GET_REGS", status, f"{len(regs)}B")

rip = None
if status == 0 and len(regs) >= 192:
    rip = struct.unpack("<q", regs[184:192])[0]
    print(f"  RIP=0x{rip:016X}")

# GET/SET DBREGS
body = struct.pack("<ii", eboot_pid, lwp)
status, data = cmd(0x0608, 23, body)
test("GET_DBREGS", status, f"{len(data)}B")

if status == 0 and len(data) >= 128:
    # Set DR0 = test addr, DR7 = enable
    ndr = bytearray(data[:128])
    struct.pack_into("<Q", ndr, 0, 0x400100)
    struct.pack_into("<Q", ndr, 56, 0x1)
    body = struct.pack("<ii", eboot_pid, lwp) + bytes(ndr)
    status, _ = cmd(0x0609, 24, body)
    test("SET_DBREGS", status)

# SET_BP HW + SW
body = struct.pack("<QII", 0x400100, 1, 0)  # kind=1=HW
status, _ = cmd(0x060A, 25, body)
test("SET_BP_HW", status)
body = struct.pack("<QII", 0x400110, 0, 0)  # kind=0=SW
status, _ = cmd(0x060A, 26, body)
test("SET_BP_SW", status)

# SET_BP_COND
body = struct.pack("<QIIIIQ", 0x400120, 1, 1, 0, 0, 0xDEAD)
status, _ = cmd(0x0613, 27, body)
test("SET_BP_COND", status)

# GET_BREAKPOINTS
status, data = cmd(0x0611, 28)
if status == 0 and len(data) >= 8:
    bc = struct.unpack("<I", data[:4])[0]
    test("GET_BREAKPOINTS", status, f"{bc} BPs")
else:
    test("GET_BREAKPOINTS", status)

# SET_WP
body = struct.pack("<QII", 0xD1C000, 4, 1)  # write watchpoint
status, _ = cmd(0x060C, 29, body)
test("SET_WATCHPOINT", status)

# GET_WATCHPOINTS
status, data = cmd(0x0612, 30)
if status == 0 and len(data) >= 8:
    wc = struct.unpack("<I", data[:4])[0]
    test("GET_WATCHPOINTS", status, f"{wc} WPs")
else:
    test("GET_WATCHPOINTS", status)

# STEP
body = struct.pack("<ii", eboot_pid, lwp)
status, _ = cmd(0x0604, 31, body)
test("STEP", status)

# POLL
status, data = cmd(0x0610, 32)
if status == 0 and len(data) >= 8:
    stopped, slwp = struct.unpack("<ii", data[:8])
    test("POLL", status, f"stopped={stopped}")
else:
    test("POLL", status)

# GET_FPREGS / GET_FSGSBASE
body = struct.pack("<ii", eboot_pid, lwp)
status, data = cmd(0x0616, 33, body)
test("GET_FPREGS", status, f"{len(data)}B")
body = struct.pack("<ii", eboot_pid, lwp)
status, data = cmd(0x0618, 34, body)
test("GET_FSGSBASE", status, f"{len(data)}B")

# SUSPEND / RESUME
body = struct.pack("<ii", eboot_pid, lwp)
status, _ = cmd(0x060E, 35, body)
test("SUSPEND", status)
status, _ = cmd(0x060F, 36, body)
test("RESUME", status)

# CLEANUP
cmd(0x060B, 37, struct.pack("<QII", 0x400110, 0, 0))
cmd(0x060D, 38, struct.pack("<QII", 0xD1C000, 4, 1))
cmd(0x0614, 39)  # CLEAR_ALL_BP
cmd(0x0615, 40)  # CLEAR_ALL_WP
status, _ = cmd(0x0601, 41)  # DETACH
test("DETACH", status)

# ====================== XREFS_TO ======================
print("\n=== XREFS_TO (may hang — test last) ===")
# memdbg_xrefs_to_request_t: i I Q Q Q = 32 bytes
body = struct.pack("<iIQQQ", eboot_pid, 0, 0x400000, 0x10000, 0x400000)
s.settimeout(5)
try:
    t0 = time.time()
    status, data = cmd(0x0A02, 50, body)
    dt = time.time() - t0
    test("XREFS_TO", status, f"{dt:.2f}s  {len(data)}B")
except socket.timeout:
    test("XREFS_TO", -1, "TIMEOUT (likely rwpipe hang)")
except Exception as e:
    test("XREFS_TO", -99, str(e))

s.settimeout(10)
# ====================== MISC ======================
print("\n=== MISC ===")

# PROCESS_DUMP
body = struct.pack("<iI", eboot_pid, 7)
status, data = cmd(0x010F, 60, body)
test("PROCESS_DUMP", status, f"{len(data)}B" if status == 0 else "")

# TELEMETRY
status, data = cmd(0x0400, 61)
if status == 0 and len(data) >= 56:
    total_r = struct.unpack("<Q", data[:8])[0]
    total_w = struct.unpack("<Q", data[8:16])[0]
    uptime = struct.unpack("<Q", data[32:40])[0]
    conns = struct.unpack("<I", data[40:44])[0]
    test("TELEMETRY", status, f"up={uptime}s r={total_r} w={total_w} conns={conns}")
else:
    test("TELEMETRY", status)

# EXTENDED_CAPS
status, data = cmd(0x0D03, 62)
if status == 0 and len(data) >= 8:
    ec_val = struct.unpack("<I", data[4:8])[0] if len(data) >= 8 else 0
    test("EXTENDED_CAPS", status, f"0x{ec_val:08X}")
else:
    test("EXTENDED_CAPS", status)

# CONSOLE_NOTIFY
body = struct.pack("<II", 5, 0) + b"Test!"
status, _ = cmd(0x0900, 63, body)
test("CONSOLE_NOTIFY", status)

# CONSOLE_PRINT
body = struct.pack("<II", 6, 0) + b"Hello!"
status, _ = cmd(0x0901, 64, body)
test("CONSOLE_PRINT", status)

# PING
status, _ = cmd(0x0002, 65)
test("PING", status)

# KERNEL_BASE (safe)
status, data = cmd(0x0800, 66)
if status == 0:
    tb, db = struct.unpack("<QQ", data[:16])
    test("KERNEL_BASE", status, f"text=0x{tb:X} data=0x{db:X}")

# KERNEL_READ (safe path only — kernel_copyout, no rwpipe)
print("\n=== KERNEL_READ (safe path) ===")
body = struct.pack("<QII", tb, 16, 0)
s.settimeout(3)
try:
    t0 = time.time()
    status, data = cmd(0x0801, 70, body)
    dt = time.time() - t0
    test("KERNEL_READ", status, f"{dt:.2f}s  {len(data)}B")
    if status == 0:
        print(f"  data: {data[:16].hex()}")
except socket.timeout:
    test("KERNEL_READ", -1, "TIMEOUT")
    print("  WARNING: kernel_copyout also hangs — KERNEL_READ broken on this firmware")
except Exception as e:
    test("KERNEL_READ", -99, str(e))

s.close()
print("\n=== ALL TESTS COMPLETE ===")

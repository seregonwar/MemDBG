# Code Cave

Code caves let you inject and execute custom shellcode inside a target process.
MemDBG provides the full pipeline — remote allocation, shellcode writing, memory
protection, and an optional detour mechanism — all through the MDBG wire protocol
and the desktop frontend's **Code Cave** panel.

## Quick Start

1. Open the **Debugger** screen and select a target process.
2. Switch to the **Code Cave** tab.
3. Click **Allocate Cave** to reserve 4 KB of RW memory inside the target.
4. Enter your shellcode as hex bytes and click **Write & Protect RX**.
5. (Optional) Enter a target address and click **Install Detour** to redirect
   execution from the target address into your cave.

## Frontend Workflow

### 1. Allocate

The **Allocate Cave** button sends `PROCESS_ALLOC` (`0x0109`) with
`protection = READ | WRITE`. The payload allocates virtual memory inside the
target process using the platform's remote-syscall bridge and returns the
allocated address and size. The default size is 4 KB; you can adjust it
before allocating.

### 2. Shellcode

Enter raw hex bytes in the shellcode input field (e.g. `B8 EF BE 00 00 CC` for
`mov eax, 0xBEEF; int3`). Click **Write & Protect RX** to:

1. Send `MEMORY_WRITE` (`0x0201`) with your bytes to the cave address.
2. Send `PROCESS_PROTECT` (`0x0108`) to change the cave from RW to RX
   (read + execute), making it executable.

> **Tip:** You can compose shellcode with the **Patch Studio** tab and copy the
> hex bytes into the Code Cave panel.

### 3. Detour (Optional)

If you want execution to *automatically* reach your cave, enter the target
address where you want to install the jump. Click **Install Detour**:

1. Reads 12 original bytes at the target address.
2. Changes the target page to RW via `PROCESS_PROTECT`.
3. Writes a 12-byte absolute jump (`mov rax, cave; jmp rax`) via `MEMORY_WRITE`.
4. Restores the target page to RX via `PROCESS_PROTECT`.

Your shellcode should include the original bytes and a jump back to
`target + 12` to preserve the original program flow.

Click **Remove Detour** to restore the original bytes and clean up.

## Protocol Reference

| Step | Command | Notes |
|------|---------|-------|
| Allocate | `PROCESS_ALLOC` (`0x0109`) | Gated by `MEMDBG_CAP_MEMORY_ALLOC`. Returns `{address, length}`. |
| Write | `MEMORY_WRITE` (`0x0201`) | Gated by `MEMDBG_CAP_MEMORY_WRITE`. Request: `pid + addr + len + data`. |
| Protect | `PROCESS_PROTECT` (`0x0108`) | Gated by `MEMDBG_CAP_MEMORY_PROTECT`. Changes RW → RX (or back). |
| Assemble | `ASM_ENCODE` (`0x0A00`) | Gated by `MEMDBG_CAP_DISASSEMBLY`. Server-side Keystone assembler. Raw response: `ok(4) + byte_count(4) + insn_count(4) + code(N)`. |

See [`protocol.md`](protocol.md) for the full wire format and
[`feature_research.md`](feature_research.md) for platform capability status.

## Shellcode Patterns

### Marker + Breakpoint

```
B8 EF BE 00 00    mov eax, 0xBEEF
CC                int3
```

Useful for testing: attach the debugger, set RIP to the cave, continue, and
verify that RAX equals `0xBEEF` when the breakpoint hits.

### Detour Stub (12-byte patch)

```
48 B8 EF BE 00 00 00 00 00 00    mov rax, 0xBEEF   ; marker
<original 12 bytes>                                    ; execute replaced code
48 B8 <return_addr>               mov rax, retaddr
FF E0                             jmp rax            ; return to target+12
CC                                int3               ; safety
```

Build the return address as `target + 12` and assemble the full stub manually
or with `ASM_ENCODE`.

### NOP Sled + Payload

```
90 90 90 90 90    nop × 5
B8 14 00 00 00    mov eax, 20     ; SYS_getpid
0F 05             syscall
CC                int3
```

For syscall-based payloads, note that `syscall` clobbers `rcx` and `r11` on
x86-64. Save and restore any registers your shellcode depends on.

## Platform Notes

### PS5

- **W^X enforcement**: The PS5 hypervisor may prevent changing a page from RW
  to RX. If `PROCESS_PROTECT` fails with `MEMDBG_ERR_IO`, the cave cannot be
  made executable. In that case, use the debugger's `SET_REGS(RIP=cave)`
  approach instead of a detour.
- **PTWALK bypass**: `MEMORY_WRITE` to RX pages via the page-table walk path
  (`PTWALK_WRITE`) can trigger a hypervisor security violation and kernel panic.
  Always use `PROCESS_PROTECT` to change protection to RW before writing, then
  back to RX — especially when installing detours into `.text` pages.
- **ALLOC works** via the remote `mmap` syscall bridge (`PROCESS_ALLOC`).
- **ASM_ENCODE** uses Keystone cross-compiled with `prospero-clang`
  (`-DMEMDBG_HAS_KEYSTONE=1` in the PS5 Makefile).

### PS4

- Remote allocation is not currently supported. Use `PROCESS_HIJACK` or
  `PROCESS_ELF_LOAD` for code injection instead.
- `MEMDBG_CAP_MEMORY_ALLOC` is not advertised.

### Host (macOS/Linux)

- `PROCESS_ALLOC` and `PROCESS_FREE` return `MEMDBG_ERR_UNSUPPORTED`.
- Use the debugger and `SET_REGS` for testing shellcode execution.
- ASM_ENCODE and DISASM are fully functional on host builds (Zydis + Keystone).

## See Also

- [Debugger / Patch Studio](frontend/src/screens/debugger/debugger_patch_studio.cpp)
- [Protocol specification](protocol.md)
- [Feature research](feature_research.md)
- [PS5 validation notes](ps5_validation_2026-07-18.md)

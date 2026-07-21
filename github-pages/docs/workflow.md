This guide walks through a complete memory hacking session — from connecting to the console to building a working trainer. Follow it in order the first time, then adapt the steps to your own workflow.

## 1. Connect and verify

1. Launch MemDBG on your console (see [Setup](#setup)).
2. Open the frontend, enter the console IP, and press **Connect**.
3. Verify the connection in the sidebar — you should see a green status indicator, platform info, and protocol version.
4. Open **Logs** to confirm UDP messages are arriving. If not, check your UDP port configuration.

> **Pro tip:** Save your console in **Settings → Console Targets** so you don't retype the IP every session.

## 2. Select the target process

1. Open the **Processes** screen.
2. Click **Refresh** to fetch the process list from the console.
3. Find your game or application in the list. Use the **Filter** box to narrow results (e.g. type `eboot` for PS4 games).
4. Click on the process to select it. The PID and process name appear in the status bar.
5. Click **Load Maps** to enumerate the process's virtual memory regions.

> **No processes?** Verify the payload has sufficient privileges. On PS4, ensure GoldHEN is active. On PS5, check ps5debug status. See [Troubleshooting](#troubleshooting).

## 3. Understand the memory maps

Each map entry shows:

| Column | Meaning |
|---|---|
| **Start** – **End** | Virtual address range. |
| **Size** | Total bytes in the region. |
| **Prot** | Protection flags: `r` (read), `w` (write), `x` (execute). |
| **Name** | Region name (e.g. `[heap]`, `libc.so`, `eboot.bin`). |
| **Offset** | File offset (for mapped files). |

**Key insights:**
- **`rw-` regions** are your primary scan targets — they contain variables, game state, and writable data.
- **`r-x` regions** contain code — useful for AOB signatures and breakpoints.
- **`[heap]` and `[stack]`** regions are often where dynamic values live.
- **Named regions** (`eboot.bin`, `libc.so`) map to specific binaries — useful for version-specific offsets.

> **Too many maps?** Use the map filter (e.g. `rw-` to show only writable regions) or sort by size to identify large data segments.

## 4. Find values with scanning

This is the core loop of memory hacking. The [Scanner](#scanner) section has full details on each scan type, but here's the essential workflow:

### Narrowing scan (exact value)

1. Note the current value in-game (e.g. health = 100, ammo = 30).
2. Go to **Scanner**, choose **Exact Scan**, select the value type, and enter the value.
3. Use **Range Scan** if you know the region, or **Process Scan** to search everywhere.
4. Click **Start Scan**.
5. Change the value in-game (take damage, spend ammo).
6. Enter the new value and click **Next Scan**.
7. Repeat until only a few candidates remain (ideally 1–10).
8. Test each candidate by writing a controlled value and checking the game.

### Unknown value scan

Use when you don't know the exact value (e.g. a health bar, position, or timer):

1. Start with **Unknown Scan** → **Initial**.
2. Change the value in-game (move, take damage).
3. Scan for **Increased** or **Decreased**.
4. Repeat until you isolate the address.

### AOB (Array of Bytes) scan

Best for finding code or data patterns that survive game updates:

1. Identify a unique byte pattern around your target address (use the **Memory** screen hex view).
2. Enter the pattern in hex with `??` as wildcards (e.g. `48 8B 05 ?? ?? ?? ?? 89 45 FC`).
3. Scan the code region (`r-x` maps) or the whole process.
4. Results show the matched address — use this in trainers for version-independent cheats.

> **Pattern too short?** You'll get thousands of matches. Make your AOB pattern at least 8–12 bytes with specific bytes for uniqueness.

## 5. Read and verify memory

Once you have candidate addresses from scanning:

1. Double-click a scan result to jump to the **Memory** screen.
2. The hex view shows the memory at that address.
3. Use **Auto-Refresh** (0.5s interval) to watch the value change in real time as you play.
4. Write a test value to confirm you control the right address:
   - Enter a value in the **Write** field.
   - Press **Write** and check the game.
   - If nothing happens, it's the wrong address — try the next candidate.

> **Always capture the original value** before writing! You'll need it for the trainer's OFF state.

## 6. Handle address changes (ASLR)

Game addresses change on every restart due to Address Space Layout Randomization (ASLR). For permanent cheats, use one of these strategies:

### Pointer chains
1. Find a **static pointer** — an address that consistently points to your target value.
2. Use the **Pointer Scanner** to trace the chain of pointers.
3. Save the chain (base address + offsets) in your trainer.

### AOB signatures
1. Find a unique byte pattern near your target address.
2. Use the **AOB Scanner** to find the pattern at runtime.
3. Calculate the offset from the pattern to your target value.
4. The trainer resolves the AOB match at runtime, adding the offset to get the final address.

### Code caves
Inject a small trampoline that writes your desired value directly, bypassing the need to find the address.

See the [Trainer](#trainer) section for implementation details.

## 7. Build the trainer

1. Go to the **Trainer** screen.
2. Click **Add Cheat** for each cheat you want to include.
3. For each cheat:
   - **Name**: Descriptive label (e.g. "Infinite Health").
   - **Address**: Absolute address, AOB result, or pointer chain.
   - **Type**: Value type (u8, u16, u32, u64, f32, f64, bytes).
   - **ON value**: The value to write when enabled.
   - **OFF value**: The original value to restore when disabled.
   - **Lock**: Periodically rewrites the ON value (useful for values the game overwrites).
4. Test each cheat individually — enable it, verify in-game, disable it, verify restoration.
5. Save as a `.cht` file.

> **Lock frequency matters:** Some games rewrite values every frame. If lock doesn't work, the value might be computed from something else — try finding the source.

## 8. Advanced: ELF injection

MemDBG can load custom ELF binaries into a target process:

1. Go to **Processes**, select your target process.
2. In the **ELF Load / Hijack** section, drag an `.elf` file or click **Select ELF...**.
3. The frontend validates the ELF header and shows architecture, segments, and entry point.
4. Optionally specify a **Target Region** to map into a specific memory area.
5. Click **Load ELF** to inject, or **Hijack** to spawn a new thread running your payload.

> **Architecture mismatch:** Loading an AArch64 ELF on PS4 (x86-64) will fail. The frontend warns you with a ⚠ indicator.

## 9. Use the debugger (advanced)

For reverse engineering and precise control:

1. Go to the **Debugger** screen.
2. Click **Attach** to take control of the target process.
3. The process pauses — you can now:
   - View and edit **registers** and **threads**.
   - Set **breakpoints** at specific addresses (the game pauses when hit).
   - Set **watchpoints** on memory ranges (pauses when the value changes).
   - **Step** through code one instruction at a time.
   - View **disassembly** with xrefs and control flow.
4. Click **Continue** to resume, or **Detach** to release control.

> **Warning:** Attaching the debugger pauses the game. This is normal — use Continue to resume. Some games have anti-debugging protections.

## Quick reference

| Task | Screen | Key action |
|---|---|---|
| Connect to console | Connection bar | Enter IP, press Connect |
| See process list | Processes | Refresh |
| View memory maps | Processes | Select process → Load Maps |
| Search for a value | Scanner | Exact Scan → Start |
| Narrow results | Scanner | Next Scan with new value |
| Read/write memory | Memory | Enter address, read/write |
| Watch live values | Memory | Auto-Refresh |
| Create cheat | Trainer | Add Cheat → configure |
| Save trainer | Trainer | Save as .cht |
| Debug process | Debugger | Attach → set breakpoints |
| View console logs | Logs | (automatic if UDP configured) |
| Inject code | Processes | ELF Load / Hijack |

Real-world advice from experienced MemDBG users. These practices help you avoid common mistakes, build reliable trainers, and work efficiently.

## Before you start hacking

### Use disposable saves
Never test trainers or memory writes on your main save file. Create a backup save, or use a secondary account. A single bad write can corrupt hours of progress.

### Record everything
For each trainer you build, record:
- Game title, version, and region
- Platform (PS4, PS5)
- Payload build version
- Frontend version
- The exact addresses, AOB patterns, and pointer chains used

This information is invaluable when you revisit the trainer months later or when someone reports it's broken after a game update.

### Understand the game first
Before scanning, spend 5 minutes understanding how the game handles your target value:
- Is it displayed as a whole number or a decimal?
- Does it have a maximum?
- Does it increase or decrease?
- Does it change smoothly (position) or in steps (score)?
- Is it visible on screen or hidden in menus?

This knowledge helps you choose the right scan type and value type.

## Scanning

### Change one thing at a time
When narrowing scan results, modify only ONE variable between scans. If you take damage AND move AND pick up an item, you won't know which address corresponds to which change.

### Start broad, narrow fast
- First scan: Process Scan with a loose type. Expect thousands of results.
- Second scan: Next Scan on existing results. Expect hundreds.
- Third scan: Now you're down to dozens. Start verifying.
- Never scan the entire process more than once per session. "Next Scan" is much faster.

### Prefer Range Scans
Once you know which memory region contains your value (usually `[heap]` or a named data region), switch to Range Scan. It's 10–50× faster than scanning the whole process.

### The "f32 trap"
Many values that look like integers are actually stored as floats. If `u32` returns zero results for a value like "100", try `f32 = 100.0`. Games often use floats for health, position, and physics even when the UI displays integers.

### AOB: length matters
| Pattern length | Typical matches |
|---|---|
| 4–7 bytes | Hundreds to thousands — too short |
| 8–11 bytes | Dozens — borderine |
| 12–19 bytes | 1–5 — ideal |
| 20+ bytes | 0–1 — fragile across versions |

Aim for 12–16 bytes with 2–4 wildcards. This balances uniqueness with version resilience.

### Verify AOB patterns across versions
A pattern that works perfectly on v1.0 might fail on v1.01 because the compiler reordered instructions. Dump the code region from both versions and compare the bytes around your target. Adjust wildcards until the pattern matches both.

## Trainers

### Always capture OFF before ON
Before writing a cheat value, read and save the original. You'll need it for the trainer's toggle-off behavior. Without a valid OFF value, disabling the cheat leaves the game in an unknown state.

### Lock sparingly
Lock rewrites a value continuously. It's useful when the game overwrites your value, but it wastes CPU and network bandwidth when applied unnecessarily:

- **Lock needed**: Health that the game resets every frame, position coordinates, countdown timers
- **Lock NOT needed**: Score that only changes on events, money that accumulates, flags that are set once

Monitor the Telemetry screen — if "writes/sec" exceeds 100, you're locking too aggressively.

### Test on clean state
After building a trainer, test it on a fresh game session:
1. Close the game completely.
2. Restart and load your save.
3. Connect MemDBG.
4. Load the trainer.
5. Enable each cheat one at a time, verifying it works.
6. Disable each cheat one at a time, verifying restoration.

### Version your trainer files
Name your `.cht` files descriptively:
```
MyGame_v1.0.3_PS4_InfiniteHealth.cht        ← Good
trainer.cht                                   ← Bad (which game? which version?)
```

### Share responsibly
When sharing trainers online:
- Include version and platform info
- Use AOB signatures or pointer chains (never absolute addresses)
- Test before sharing
- Add notes about any special requirements (e.g. "enable before entering combat")

## Memory operations

### Read first, write second
Never write to an address without reading it first. Without reading, you don't know what's there. You might overwrite critical game data, code, or pointers.

### Respect page boundaries
Memory is organized in 4 KB pages. Writing across a page boundary is fine, but reading from an unmapped page returns an error. If you get `status -3`, check if your read range crosses into an unmapped region.

### Use batch writes for multi-cheat activation
If your trainer has 5 cheats that all activate at once, use a batch write instead of 5 separate writes. It's one TCP round-trip instead of five, and it feels instant.

### Monitor changes with auto-refresh
Auto-refresh at 0.5s is fast enough to see real-time changes without saturating the connection. Use the Changes overlay (teal highlights) to instantly see what bytes changed since the last read.

## Debugger

### Attach after scanning, detach before disconnecting
- Scan and find your address BEFORE attaching the debugger. Scanning with the debugger attached is slower and can cause issues.
- Detach the debugger BEFORE disconnecting or closing the frontend. Leaving a process paused causes console instability.

### Use the right breakpoint type
- **Software breakpoint**: Normal case. Use when you know the exact instruction address.
- **Conditional breakpoint**: High-frequency breakpoints. Filter by register value to isolate specific cases.
- **Hardware watchpoint**: Finding "what writes to X". Only 4 available — use them wisely.

### NOP length alignment
When NOP-ing instructions, fill the EXACT instruction length with `0x90`. x86 instructions are 1–15 bytes:
```
48 89 45 FC              mov [rbp-4], rax    ; 4 bytes
→ 90 90 90 90            ; Correct: 4 NOPs

48 8B 05 10 20 30 00     mov rax, [rip+...]  ; 7 bytes
→ 90 90 90 90 90 90 90  ; Correct: 7 NOPs
```
Partial NOPs (e.g., 5 NOPs on a 7-byte instruction) leave garbage bytes that crash the process.

## Network and performance

### Use wired Ethernet for heavy scanning
WiFi adds 2–20ms of latency per operation. For scans that make hundreds of reads, this adds seconds to minutes. Wired Ethernet cuts latency to <1ms.

### Keep TCP and UDP on different ports
The default ports (9020 TCP, 9023 UDP) don't conflict. If you customize them, make sure they're different — binding TCP and UDP to the same port causes issues on some platforms.

### Monitor Telemetry
The Telemetry screen shows:
- **Connections**: Active TCP sessions. Usually 1.
- **Reads/writes**: Total operations since payload start.
- **Scan cache**: Hits vs misses. High miss rate = scans are repeating work.
- **Memory usage**: Payload-side memory pressure.

Watch Telemetry during heavy sessions to catch performance problems early.

### Restart the payload periodically
Console payloads run in limited memory. After hours of heavy scanning, the payload may fragment its memory. A fresh restart clears caches and restores peak performance.

## Plugins

### Start from the official repository
The [MemDBG Plugin repository](https://github.com/seregonwar/MemDBG-Plugin) contains working examples. Fork it, add your scripts, and test before publishing.

### Keep plugins small and focused
A plugin should do ONE thing well. If your Lua script is 2000 lines, it's probably multiple plugins in one. Split it — smaller plugins are easier to debug and share.

### Use the context file
Plugins receive a JSON context file with the active console, PID, dump path, and scan results. Use this instead of hardcoding values. The context file is the stable integration point.

## Security

### Only connect to consoles you own
MemDBG gives you full memory access. Never connect to a console you don't own or have explicit permission to access.

### Be careful with shared trainers
A `.cht` file can contain Batchcode scripts. Only load trainers from trusted sources. Malicious scripts can write to arbitrary addresses and crash or corrupt the game (or, on host builds, the test process).

### Don't use online with cheats
Most online games detect memory modifications. Using MemDBG cheats online WILL get you banned. MemDBG is designed for offline/single-player use.

## General workflow efficiency

### Save your scan state
If you're taking a break, save your scan results as a CSV. You can reload them later instead of re-scanning.

### Build incrementally
Don't try to build a 20-cheat trainer in one session. Start with one cheat, test it thoroughly, save it. Add the next cheat. This isolates issues — if something breaks, you know which cheat caused it.

### Keep notes
Use the Trainer screen's description field to document your findings: how you found the address, what the value does, any quirks. Future you will thank present you.

### Learn from others
Examine existing trainers and plugins to see how others solve problems. The MemDBG community shares techniques, AOB patterns, and pointer chain strategies.

## Scanning overview

The scanner is the heart of memory hacking. You search the game's memory for values you know (or suspect), narrow down results by comparing changes, and isolate the exact address that controls what you want to modify.

MemDBG supports six scan types, each suited to different situations.

## Scan types at a glance

| Scan type | When to use | Speed | Precision |
|---|---|---|---|
| **Exact Scan** | You know the exact value (health=100, ammo=30) | Fast | Highest |
| **Unknown Scan** | You don't know the value (progress bar, position) | Medium | High |
| **AOB Scan** | You have a byte signature (code pattern, magic bytes) | Medium | Very high |
| **Pointer Scan** | Address changes every restart (ASLR-proof) | Slow | Highest |
| **Process Scan** | You don't know which memory region to target | Slow | High |
| **Range Scan** | You know the approximate region (`[heap]`, `eboot.bin`) | Fast | High |

## Exact scan

Searches for an exact value across memory. This is your primary tool.

### Value types

Choose the right type — using the wrong one guarantees zero results:

| Type | C type | Size | Example |
|---|---|---|---|
| `u8` | `uint8_t` | 1 byte | Health bars (0–255), flags, small counters |
| `u16` | `uint16_t` | 2 bytes | Ammo counters, item quantities |
| `u32` | `uint32_t` | 4 bytes | Most game values (health, score, money) |
| `u64` | `uint64_t` | 8 bytes | Large counters, timestamps, pointers |
| `f32` | `float` | 4 bytes | Position coordinates (x, y, z), physics values |
| `f64` | `double` | 8 bytes | High-precision timers, accumulated values |

> **Unsure which type?** Start with `u32` for integer counters, `f32` for things that move smoothly (position, speed). If you get zero results, try the next size up or down.

### Range scan vs. Process scan

- **Range Scan**: Faster. You specify the memory region (start–end address). Use when you've identified the likely region from the maps table (e.g. `[heap]` for dynamic allocations).
- **Process Scan**: Scans all readable maps of the selected process. Slower but comprehensive. Use when you have no idea where the value lives.

### Narrowing strategy

The key to efficient scanning is narrowing:

1. **First scan**: Cast a wide net — Process Scan with the initial known value. Expect hundreds or thousands of results.
2. **Next Scan**: Change the value in-game (take damage, spend money). Enter the NEW value and scan again on the existing results.
3. **Repeat**: Each "Next Scan" filters the previous results. After 3–5 iterations, you should have fewer than 20 candidates.
4. **Verify**: Write a test value to each candidate and observe the game. The correct address will visibly change the value.

> **Value didn't change as expected?** Some games store values in non-obvious ways (e.g. `max - current` instead of `current`, or in a scaled fixed-point format). Try an Unknown Scan instead.

### Tracked process scans

When scanning the entire process, you can use **tracked scans** for live progress:

1. Enable **Tracked** mode in the scan options.
2. The scan runs asynchronously — you can watch progress (bytes scanned, maps done, results found).
3. Cancel at any time if the scan is taking too long.
4. Results are merged and delivered as a single batch when complete.

> Tracked scans require the payload to support `MEMDBG_EXT_CAP_SCAN_JOBS`. Older payloads fall back to synchronous scanning.

## Unknown value scan

Use when you can't express the value as a simple number:

| Operation | Meaning | Example |
|---|---|---|
| **Initial** | Capture all values as a baseline | First pass — takes a snapshot |
| **Increased** | Value went up since last scan | Health restored, score increased |
| **Decreased** | Value went down since last scan | Damage taken, timer counting down |
| **Changed** | Value is different (up or down) | Any change at all |
| **Unchanged** | Value stayed the same | Items that didn't change |
| **Increased by** | Value increased by a specific amount | Gained exactly 50 gold |
| **Decreased by** | Value decreased by a specific amount | Lost exactly 10 HP |

### Strategy for unknown scans

1. **Initial** scan captures everything.
2. Change ONE thing in the game (move slightly, take one hit).
3. Scan for **Changed** (if you expect the value to change) or **Unchanged** (if you expect it to stay the same while other things change).
4. Repeat, changing only one variable at a time.
5. The address that consistently matches your expectations is your target.

> **Golden rule:** Change only ONE thing at a time. If you move AND take damage between scans, you won't know which address corresponds to which change.

## AOB (Array of Bytes) scan

Searches for a raw byte pattern — essential for version-independent trainers.

### Writing an AOB pattern

1. Open the **Memory** screen and navigate to your target address.
2. Look at the surrounding bytes in the hex view. Identify ~12–24 bytes that look unique.
3. Replace bytes that vary between versions with `??` (wildcard).
4. Test the pattern on the current game version — it should return exactly one result.
5. If it returns too many, make the pattern longer or more specific.

### Example

```
Pattern: 48 8B 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC
```

This matches:
- `48 8B 05` — `mov rax, [rip+...]` (common instruction start)
- `?? ?? ?? ??` — the displacement varies per version (wildcards)
- `89 45 FC` — `mov [rbp-4], eax`
- `8B 45 FC` — `mov eax, [rbp-4]`

### Best practices

- Place wildcards on relative offsets and addresses — these change between builds.
- Keep specific bytes on opcodes and immediate values — these are stable.
- Test your pattern on at least two different game versions before relying on it.
- Patterns under 8 bytes usually produce too many false positives.
- Patterns over 32 bytes are fragile — minor code changes can break them.

## Pointer scan

Addresses change due to ASLR, but pointer chains often remain stable. A pointer chain is a series of hops: read address at base, add offset, read address at result, add offset, ...

### When to use

- Your cheat address changes every game restart.
- AOB scanning the surrounding code is impractical (too many matches, obfuscated code).
- You've found a static pointer (or base address) that consistently leads to your value.

### How it works

1. Find a **base address** — this is a static pointer that doesn't change between restarts. Multiplayer games often store globals in a static table.
2. Run a **Pointer Scan** from that base, specifying the maximum depth (usually 2–5 levels).
3. The scanner traces all pointer paths and returns chains that end at (or near) your target address.
4. Verify the chain by restarting the game — the final address should still point to your value.

### Verifying pointer chains

1. Save the chain in your trainer.
2. Restart the game or reload the save.
3. The trainer resolves the chain at runtime and shows the final address.
4. Read the address and confirm the value matches expectations.
5. If it doesn't, the chain is broken — try a different base or shallower depth.

> **Pointer chains are fragile.** Game updates, different game modes, or even loading a different save can invalidate a chain. Always test across multiple sessions.

## Scan results

All scans return a results table with:

| Column | Description |
|---|---|
| **Address** | Absolute virtual address of the match. |
| **Value** | Current value at that address (decoded by type). |
| **Previous** | Value from the previous scan (for comparison). |
| **Map** | Memory region name (e.g. `[heap]`, `eboot.bin`). |

### Working with results

- **Double-click** a result to jump to the Memory screen at that address.
- **Right-click** to copy the address or add it to a trainer cheat.
- **Filter** results by map name to focus on specific regions.
- **Export** results as CSV for external analysis.

### What if I get zero results?

| Problem | Solution |
|---|---|
| Wrong value type | Try `f32` instead of `u32`, or vice versa |
| Value not stored directly | Use Unknown Scan instead of Exact |
| Value is encrypted/obfuscated | Look for the decryption routine with AOB |
| Address is in kernel space | Make sure your process has `r/w` permissions |
| The game recalculates every frame | Find the source formula, not the display value |

## Scan performance tips

- **Pre-filter maps**: Only scan `rw-` regions unless you need code (`r-x`).
- **Use range scans** when you've identified the likely region — they're 10–50× faster than process scans.
- **Avoid scanning huge maps**: The `[heap]` can be gigabytes. Use the map filter to exclude it or narrow it by sub-region.
- **Use the right type**: Scanning as `u64` is slower than `u32` (twice the bytes). Match the type to the actual data size.
- **Narrow aggressively**: Each "Next Scan" on existing results is much faster than a fresh scan.
- **Parallel workers**: On supported payloads, process scans use multiple threads — the Telemetry screen shows worker activity.

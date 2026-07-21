Memory dumps save a region of process memory to a file on your PC. They're essential for offline analysis, version comparison, and creating AOB signatures that survive game updates.

## When to dump memory

| Use case | What to dump | Why |
|---|---|---|
| **AOB signature creation** | Code region (`r-x` maps) | Find unique byte patterns for version-independent trainers |
| **Version comparison** | Same region from two game versions | Identify what changed between updates |
| **Reverse engineering** | Code or data region | Analyze in IDA, Ghidra, or a hex editor |
| **Save state backup** | Game data regions (`rw-` maps) | Backup game state before risky modifications |
| **Crash analysis** | Stack and heap regions | Diagnose what caused a game crash |
| **Trainer validation** | The target region | Verify your cheat is writing to the right address |

## Dumping a memory region

### From the Maps table

1. Open the **Processes** screen.
2. Select your target process and click **Load Maps**.
3. Find the region you want to dump.
4. Right-click the map row and choose **Dump selected map**.
5. Choose a file path and click **Save**.

### From the Memory screen

1. Navigate to the address you want to dump.
2. Select the byte range (click and drag in the hex view, or enter start/end manually).
3. Click **Dump** in the toolbar.
4. Choose a file path and format.

### Dump formats

| Format | Extension | Description |
|---|---|---|
| **Raw binary** | `.bin` | Exact bytes as they appear in memory. Universal format. |
| **Hex dump** | `.hex` | Text format with address, hex, and ASCII columns. Human-readable. |
| **ELF core** | `.core` | Standard ELF core dump. Can be loaded in GDB, IDA, Ghidra. |

> **Raw binary is best for AOB work.** Hex dumps are for visual inspection. ELF core dumps are for debugger analysis.

## Size considerations

Some memory regions are enormous:

| Region | Typical size | Dump time |
|---|---|---|
| `[heap]` | 50 MB – 2 GB | Minutes to hours |
| `eboot.bin` (code) | 10–100 MB | Seconds to minutes |
| `[stack]` | 1–8 MB | Under a second |
| `libc.so` | 1–5 MB | Under a second |

> **Watch the size!** Dumping a 2 GB heap region will fill your disk and may timeout the TCP connection. If you need a large dump, use a range scan to identify the exact sub-region first.

### Partial dumps

If a region is too large:

1. Use the Memory screen to identify the sub-range you actually need.
2. Dump only that range by specifying custom start/end addresses.
3. For the heap, use the Scanner to find the address range containing your target value, then dump ±4 KB around it.

## Dump failure troubleshooting

| Symptom | Likely cause | Solution |
|---|---|---|
| Dump hangs forever | Region too large, TCP timeout | Dump a smaller range |
| `payload status -3` | Page not readable in that range | Skip the unreadable page; use smaller chunks |
| Empty dump file | Address range has zero length | Verify start < end |
| Garbage data in dump | Region was unmapped mid-dump | Retry; the game may be deallocating memory |
| `MEMDBG_ERR_IO` | Permission denied on some pages | Dump with read-only protection filter |

## Using dumps for AOB creation

This is the most common use case for dumps:

1. **Dump the code region** containing your target address (usually `eboot.bin`).
2. **Open in a hex editor** (HxD, Hex Fiend, `xxd`).
3. **Locate your target address** in the dump.
4. **Extract 16–32 bytes** around it — include unique instructions and constants.
5. **Test the pattern** in MemDBG's AOB scanner.
6. **Verify on a different game version** by dumping the same region from the updated binary.
7. **Adjust wildcards** where bytes differ between versions.

### Example workflow

```
1. Target address: 0x4000A4 (health write instruction)
2. Dump eboot.bin (code region)
3. Open in hex editor, go to offset matching 0x4000A4
4. See: 48 8B 05 10 20 30 00 89 45 FC 8B 45 FC 85 C0
5. Pattern: 48 8B 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC
6. Scan AOB on current version → 1 match ✓
7. Dump eboot.bin from updated version
8. Scan AOB on updated version → 1 match ✓ (same pattern, different displacement bytes)
9. Add to trainer with aob(48 8B 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC)+0x0
```

## Dump analysis tools

| Tool | Platform | Use |
|---|---|---|
| **HxD** | Windows | Fast hex editor with pattern search |
| **Hex Fiend** | macOS | Lightweight hex editor, handles large files |
| **Ghidra** | Cross-platform | Full reverse engineering suite |
| **IDA Pro** | Cross-platform | Professional disassembler/decompiler |
| **xxd / hexdump** | CLI | Quick inspection in terminal |
| **diff** | CLI | Compare two dumps for changes |
| **BinDiff** | Cross-platform | Structural binary diffing |

## Saving to a specific path

By default, dumps go to the frontend's working directory. You can configure the default dump path in **Settings → Paths → Memory Dumps**. The path supports these variables:

| Variable | Expands to |
|---|---|
| `{pid}` | Target process ID |
| `{name}` | Process name |
| `{map}` | Memory region name |
| `{date}` | Current date (YYYY-MM-DD) |
| `{time}` | Current time (HH-MM-SS) |

Example: `dumps/{name}/{map}_{date}_{time}.bin` creates organized, timestamped dumps.

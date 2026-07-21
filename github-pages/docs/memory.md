The Memory screen is your direct window into the target process. You can read, write, monitor, and manipulate memory at any valid address.

## Reading memory

### Basic read

1. Enter an **absolute address** (hex or decimal) in the address field.
2. Specify the **length** in bytes.
3. Click **Read**.

The hex view displays the memory contents. The left column shows the address, the center shows hex bytes, and the right column shows an ASCII representation.

### Auto-refresh

Enable **Auto-refresh** in the Memory I/O tab to re-read the buffer at a configurable interval:

| Interval | Use case |
|---|---|
| 0.1s | Fast-changing values (position, velocity) |
| 0.5s | Game state (health, ammo, score) |
| 2.0s | Slow-changing values (level, XP, inventory) |
| 5.0s | Background monitoring, watchpoints |

Auto-refresh runs in the background while you play. The hex view updates live, and changes are highlighted.

> **Performance note:** Auto-refresh reads the full buffer each interval. Keep the read length reasonable (under 4 KB) to avoid saturating the TCP connection.

### Hex view overlays

The hex view supports three visual overlays that make changes and relationships obvious:

| Overlay | Color | Meaning |
|---|---|---|
| **Changes** | Teal highlight | Bytes that differ from the previous read — shows what changed since last refresh. |
| **Watchpoints** | Amber highlight | Bytes under active watchpoints. |
| **Freed allocs** | Red highlight | Bytes in freed heap allocations (debugging use-after-free). |

Enable overlays from the Memory toolbar. Multiple overlays can be active simultaneously — overlapping regions use priority coloring.

## Writing memory

### Basic write

1. Navigate to the target address.
2. Enter the new value in the **Write** field:
   - **Integers**: Decimal (e.g. `9999`) or hex (`0x270F`).
   - **Floats**: Decimal with optional decimal point (e.g. `100.0`, `3.14159`).
   - **Bytes**: Hex string with spaces (e.g. `90 90 90 90` for NOP).
3. Select the value type matching what you want to write.
4. Click **Write**.

> **Always capture the OFF value first!** Before writing, note the original bytes. You'll need them to restore the game state when the cheat is disabled.

### Writing different types

| Type | Example input | Bytes written |
|---|---|---|
| `u8` | `255` | `FF` |
| `u16` | `9999` | `0F 27` |
| `u32` | `999999` | `3F 42 0F 00` |
| `u64` | `9999999999` | `FF 64 D9 52 02 00 00 00` |
| `f32` | `100.0` | `00 00 C8 42` |
| `f64` | `100.0` | `00 00 00 00 00 00 59 40` |
| `bytes` | `90 90 90 90` | `90 90 90 90` (raw, no conversion) |

### NOP-ing code

A common technique for disabling game logic:

1. Find the instruction you want to disable (e.g. damage calculation, collision check).
2. Write `90` bytes (x86 NOP) over the instruction.
3. The instruction is now a no-op — the game skips that logic.

> **NOP length matters:** x86 instructions vary in length (1–15 bytes). Fill the exact instruction length with `90`s. Leaving partial instructions causes crashes.

## Batch operations

Batch operations read or write multiple addresses in a single request, reducing TCP overhead compared to individual requests.

### Batch read

1. Add addresses to the batch list (right-click a scan result → **Add to Batch Read**).
2. Configure each entry with an address and length.
3. Click **Execute Batch Read**.
4. Results appear as a table, each row showing the address, bytes read, and decoded value.

Maximum 64 items per batch. Ideal for trainers that need to check multiple addresses at once.

### Batch write

1. Add entries to the batch write list.
2. Configure each entry with address, value, and type.
3. Click **Execute Batch Write**.
4. All writes happen in a single TCP round-trip.

Maximum 64 items per batch. Use this for trainers that activate multiple cheats simultaneously.

> **Atomicity:** Batch operations are NOT atomic. If the connection drops mid-batch, some writes may have completed and others not. For critical operations, verify each address after the batch completes.

## Watchpoints

Watchpoints monitor memory regions and notify you when values change. Unlike the debugger's hardware watchpoints, these are software-based and work on any memory region.

### Setting up a watchpoint

1. In the Memory screen, click **Add Watchpoint**.
2. Enter the address and length.
3. Set the **polling interval** (how often to check, in seconds).
4. Enable the watchpoint.

When the value changes:
- The hex view highlights changed bytes (amber overlay).
- The watchpoint logs the old and new values.
- The notification area shows a brief alert.

### Use cases

- **Monitor a cheat**: Verify your written value isn't being overwritten by the game.
- **Find related addresses**: Watch one value, change another — if the watched value changes, they're connected.
- **Detect anti-cheat**: Watch critical values for unexpected modifications.

## Advanced: allocation tracking

On supported platforms, MemDBG can track heap allocations in the target process:

1. Enable **Allocation Tracking** in the Memory settings.
2. The hex view overlay marks freed allocations in red.
3. Use this to diagnose use-after-free bugs, memory leaks, or understand the game's memory management.

This feature requires the payload's `MEMDBG_CAP_MEMORY_ALLOC` capability.

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+G` | Go to address |
| `Ctrl+R` | Read memory at current address |
| `Ctrl+W` | Write value (opens write dialog) |
| `F5` | Toggle auto-refresh |
| `Ctrl+Up/Down` | Scroll memory view by one row |
| `Page Up/Down` | Scroll memory view by one page |
| `Ctrl+Shift+C` | Copy hex bytes to clipboard |
| `Ctrl+Shift+V` | Paste hex bytes from clipboard |

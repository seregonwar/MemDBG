Trainers are reusable cheat files (`.cht`) that bundle multiple cheats with their logic, addresses, and activation states. A well-built trainer survives game restarts, works across versions, and can be shared with others.

## Anatomy of a trainer

A trainer file is a JSON document containing:

- **Metadata**: Name, game, version, author, description.
- **Cheats**: Individual cheat entries with addresses, values, and options.
- **Scripts**: Optional Batchcode scripts for complex logic.
- **Signatures**: AOB patterns and pointer chains for version-independent addressing.

## Creating a cheat

### Step 1: Find the address

Use the [Scanner](#scanner) to locate the address controlling your value. Confirm it by writing a test value.

### Step 2: Add the cheat

1. Go to the **Trainer** screen.
2. Click **Add Cheat**.
3. Fill in the cheat details:

| Field | Description | Example |
|---|---|---|
| **Name** | Human-readable label | "Infinite Health" |
| **Address** | Absolute address, pointer chain, or AOB result | `0x1A2B3C4D` or `[[base]+0x10]+0x8` |
| **Type** | Value type | `u32`, `f32`, `bytes` |
| **ON value** | Value to write when cheat is active | `9999` |
| **OFF value** | Original value to restore | `100` |
| **Lock** | Continuously rewrite ON value | Enable for values the game overwrites |
| **Lock interval (ms)** | How often to rewrite | `100` (10 times/sec) — lower = more CPU |

### Step 3: Capture the OFF value

Before enabling the cheat for the first time:

1. Read the current value at the address.
2. Click **Capture OFF** to save it.
3. If the OFF value is dynamic (changes during gameplay), consider using a pointer or AOB instead.

### Step 4: Test

1. Enable only this cheat — verify the game changes as expected.
2. Disable — verify the original value is restored.
3. Enable/disable multiple times — the game should handle it gracefully.
4. Test on a **disposable save** — some games detect modified values and corrupt saves.

> **Testing tip:** Create a save file specifically for trainer testing. Never test on your main save.

## Address types

Trainers support three address modes:

### Absolute address
The simplest: a fixed memory address. Works only for the current game session (ASLR changes it on restart).

```
0x1A2B3C4D0
```

### Pointer chain
A chain of reads from a base address through offsets. Survives ASLR.

```
Syntax:  [[base]+offset1]+offset2

Example: [[eboot.bin+0x2A0000]+0x10]+0x8

Reads:   Read pointer at (eboot.bin base + 0x2A0000) → 0x500000
         Read pointer at (0x500000 + 0x10) → 0x600000
         Final address = 0x600000 + 0x8 = 0x600008
```

The pointer scanner generates these chains automatically.

> **Base options:** Use a named map base (e.g. `eboot.bin`, `libc.so`) or a fixed address. Map bases are resolved at runtime and survive ASLR.

### AOB result
Resolves an AOB pattern at runtime, then adds an offset.

```
Syntax:  aob(<pattern>)+<offset>

Example: aob(48 8B 05 ?? ?? ?? ?? 89 45 FC)+0x4

Resolves: Find the AOB match address → 0x400000
          Final address = 0x400000 + 0x4 = 0x400004
```

> **Verification:** The trainer shows the resolved address in the UI. If it's `0x0` or looks wrong, the AOB didn't match — check your pattern.

## Lock (freeze)

Lock continuously rewrites the ON value at the configured interval. Use when the game overwrites your value every frame.

### When to lock

| Scenario | Lock? |
|---|---|
| Health, ammo (game writes on change) | No — write once is enough until it changes |
| Health, ammo (game validates every frame) | Yes — game resets it otherwise |
| Position (game updates every frame) | Yes — without lock you teleport for one frame |
| Score, money (accumulates) | No — you want it to increase naturally |
| Timer (counts down every frame) | Yes — freeze to stop the timer |

### Lock interval

- **100ms**: Standard — 10 writes/sec, low CPU impact.
- **50ms**: Fast — 20 writes/sec for rapidly-changing values.
- **16ms**: Per-frame — 60 writes/sec, significant CPU. Only for values the game writes every frame.

> **Watch the Telemetry screen.** If "writes/sec" is high (>1000), reduce your lock interval or disable unnecessary locked cheats.

## Batchcode scripts

For cheats that need logic beyond simple write/lock, use Batchcode scripts. Scripts are embedded in the trainer file and run when the cheat is enabled.

### When to use Batchcode

- Conditional logic (if health < 50, heal to 100)
- Multi-address coordination (if ammo = 0, also restore clip)
- Timed sequences (wait 5s, then write)
- Reading and comparing values

See the [Batchcode Reference](#batchcode) for the full command set.

### Embedding scripts

1. In the cheat editor, click **Add Script**.
2. Write your Batchcode in the editor.
3. The script runs when the cheat is toggled ON.
4. When toggled OFF, locked values are unlocked and the OFF value is restored.

## Organizing cheats

### Categories
Group related cheats with section headers. In the trainer editor, add a **Section** entry (no address, just a name) to create visual separators:

```
── Player ──
  Infinite Health
  Infinite Ammo
  Super Speed
── World ──
  No Collision
  Brightness Override
── Enemies ──
  One-Hit Kill
  Freeze Enemies
```

### Activation groups
Assign cheats to activation groups (A, B, C, D). Activate/deactivate entire groups at once with a single click. Useful for:

- **Group A**: Safe cheats (always on)
- **Group B**: Combat cheats (toggle before fights)
- **Group C**: Exploration cheats (toggle for traversal)
- **Group D**: Experimental cheats (test carefully)

## Sharing trainers

### What to include

A shareable trainer should contain:

1. **AOB signatures** or **pointer chains** — never absolute addresses.
2. **Game version info** — which update/patch it works with.
3. **Tested platform** — PS4, PS5, or both.
4. **README notes** — any special instructions (enable before loading save, disable during cutscenes, etc.).

### What to avoid

- Absolute addresses (won't work for anyone else)
- Unofficial game modifications (stick to memory values)
- Copyrighted game data (hex dumps of game assets)

### File format

`.cht` files are JSON. They're human-readable and version-control-friendly:

```json
{
  "name": "My Trainer",
  "game": "Game Title",
  "version": "1.0.3",
  "author": "YourName",
  "cheats": [
    {
      "name": "Infinite Health",
      "type": "aob",
      "pattern": "48 8B 05 ?? ?? ?? ?? 89 45 FC",
      "offset": 4,
      "value_type": "u32",
      "on_value": 9999,
      "off_value": 100,
      "locked": false
    }
  ]
}
```

## Trainer file management

- **Save**: Saves the current trainer as a `.cht` file. Choose a descriptive name including the game and version.
- **Load**: Opens a `.cht` file, replacing the current trainer.
- **Import Cheat**: Adds a single cheat from another `.cht` file without replacing your current cheats.
- **Export as Batchcode**: Converts all cheats to a Batchcode script for advanced customization.

Trainer files are portable — copy them between PCs, share them online, and version them with git.

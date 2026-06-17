## Example: infinite health

1. Select the game process.
2. With health at 100, run an exact scan for `u32 = 100`.
3. Take damage (e.g. health 83) and scan for `u32 = 83`.
4. Repeat until only a few results remain.
5. Read the candidate and verify it changes with the in-game value.
6. Add the cheat in the Trainer section.
7. Capture the original OFF value.
8. Set the ON value (e.g. `999`) and enable lock if needed.

## Cheat fields

| Field | Description |
|---|---|
| Name | Readable label, e.g. Infinite Health. |
| Address | Absolute address or result from AOB/pointer data. |
| Type | Value type: byte, integer, float, or raw bytes. |
| ON value | Value written when the cheat is enabled. |
| OFF value | Original value restored when disabled. |
| Lock | Periodically rewrites the ON value. |

## Stable trainers

Absolute addresses can change on every launch because of ASLR, updates, or version differences. For trainers you want to share, prefer AOB signatures or pointer chains verified across multiple sessions.

## OFF value

Capture OFF before enabling the cheat. If the original value is dynamic, disabling may not be enough — test restoration on an unimportant save.

## Trainer files (.cht)

Trainers are saved as `.cht` files containing JSON with cheat entries, AOB signatures, and pointer chains. Load and save via the Trainer screen. Files are portable across sessions.

## Batchcode

The Trainer screen supports batchcode scripts — a simple domain language for writing trainer logic. See the Batchcode reference section below for syntax and examples.

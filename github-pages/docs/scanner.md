## Exact scan

Searches for an exact value in a range or across the whole process. Choose `u8`, `u16`, `u32`, `u64`, `f32`, or `f64`. If unsure, start with `u32` for integer counters or `f32` for decimal values.

## Process scan

Scans all readable maps of the selected process. Useful when you don't know the correct region, but can be slower and produce more errors on protected maps.

## AOB scan

Searches for a byte signature. Use wildcards for variable bytes. Build patterns long enough to avoid too many matches. A strong base for trainers that survive address changes.

## Pointer scan

Use pointer chains when an address changes after a restart or level change. Always verify the chain by restarting the game or reloading the save.

> **Recommended method:** scan a known value, change that value in-game, narrow results with a new scan, then verify candidates by reading and writing controlled values.

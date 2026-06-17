## Read Memory

Reads bytes from an absolute address in the selected process. Use small lengths while validating an address, then increase only when the range is stable.

## Write Memory

Writes bytes into the target process. Always capture the original value before writing — you'll need it to restore state or build a safe trainer toggle.

## Batch operations

Batch operations read or write multiple addresses in a single request. Ideal for trainers with several active cheats; they reduce TCP traffic compared to many separate requests.

## Hex view overlays

The hex view supports three overlays:
- **Changes** — highlights bytes that differ from the previous read.
- **Watchpoints** — highlights bytes under active watchpoints.
- **Freed allocs** — highlights freed heap allocations.

## Auto-refresh

Enable **Auto-refresh** in the Memory I/O tab to re-read the memory buffer at a configurable interval (0.1–5.0s). Ideal for monitoring live values.

## Watchpoints

Set watchpoints on memory regions to detect changes. Configure the polling interval and enable polling to receive notifications when values change.

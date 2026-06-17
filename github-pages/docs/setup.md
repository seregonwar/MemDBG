MemDBG exposes a TCP server for commands and a UDP channel for logs. The payload must be running before using processes, maps, memory reads, scanners, or trainers.

## Useful arguments

| Argument | Purpose |
|---|---|
| `--bind=0.0.0.0` | Address the payload listens on. |
| `--debug-port=9020` | TCP port used by the frontend. |
| `--udp-host=255.255.255.255` | UDP host or broadcast address for logs. |
| `--udp-port=9023` | UDP port for live console logs. |
| `--data-root=/data/memdbg` | Payload data and log directory. |
| `--no-udp-log` | Disable UDP log delivery. |

> **Console permissions:** On supported platforms the privilege module tries to elevate the payload at startup and temporarily elevate the target process during read/write/batch operations. Look for a log line similar to `privilege: payload escaped sandbox`. If that line is missing, many operations return `payload status -3` or `payload status -8`.

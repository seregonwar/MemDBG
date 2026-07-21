## Connection errors

| Error | Meaning | What to check |
|---|---|---|
| `Connection refused` | No payload listening on that IP/port. | Verify the payload is running. Re-send the ELF to the console. |
| `Connection timed out` | Network unreachable. | Check console IP. Verify both devices are on the same network. Check firewall. |
| `not connected` | No active TCP session. | Connect to the console first; verify IP/port in Settings. |
| `HELLO timeout` | Payload accepted TCP but didn't respond. | Payload may be hung. Restart it. Check console logs. |
| `Protocol mismatch` | Frontend protocol version doesn't match payload. | Update both frontend and payload to the same version. |
| `Session rejected` | Payload has an active session and doesn't allow multiple connections. | Disconnect the other frontend, or restart the payload. |

## Operation errors

| Error | Code | Meaning | What to check |
|---|---|---|---|
| `payload status -1` | `MEMDBG_ERR_PARAM` | Invalid request parameters. | Check address, length, value type — something is out of range. |
| `payload status -2` | `MEMDBG_ERR_NOMEM` | Payload ran out of memory. | Reduce scan size, batch size, or dump range. |
| `payload status -3` | `MEMDBG_ERR_IO` | I/O error (memory read/write failed). | Valid process, readable range, payload privileges, process alive. |
| `payload status -4` | `MEMDBG_ERR_NET` | Network error during operation. | Check network stability. Retry. |
| `payload status -5` | `MEMDBG_ERR_PROTOCOL` | Malformed packet. | Usually a bug — report it with steps to reproduce. |
| `payload status -6` | `MEMDBG_ERR_UNSUPPORTED` | Feature not available on this platform. | Check capabilities in Telemetry. |
| `payload status -7` | `MEMDBG_ERR_NOT_FOUND` | Target process/map/thread not found. | Refresh process list. Verify PID. |
| `payload status -8` | `MEMDBG_ERR_PERMISSION` | Permission denied. | Check privilege module, jailbreak status, target permissions. |
| `payload status -9` | `MEMDBG_ERR_OVERFLOW` | Size/count/address overflow. | Reduce scan size or batch count. |
| `payload status -10` | `MEMDBG_ERR_STATE` | Invalid state for this operation. | E.g., debugger not attached, scanner already running. |

## Scanner issues

| Symptom | Likely cause | Solution |
|---|---|---|
| Zero results on exact scan | Wrong value type or endianness | Try `f32` if `u32` fails. Verify the value with a memory read. |
| Zero results on Next Scan | Value changed in unexpected way | Use Unknown Scan instead. The game may store `max - current`. |
| Scan takes forever | Region too large, too many maps | Use Range Scan on a specific map. Exclude huge maps like `[heap]`. |
| "No readable maps" | Process has no accessible memory regions | Check process is alive. Try a different process. |
| Scan results don't change after narrowing | The game stores the value differently than displayed | Try Unknown Scan. The value may be encrypted or normalized. |
| AOB scan returns no matches | Pattern too specific, different game version | Shorten pattern, add more wildcards, verify on current version first. |
| AOB scan returns too many matches | Pattern too generic | Make pattern longer. Add more specific bytes. Avoid common byte sequences. |
| Pointer scan takes too long | Too many maps, max depth too high | Reduce max depth to 2–3. Use range scan on specific maps. |
| Tracked scan not available | Payload doesn't support `SCAN_JOBS` | Update payload. Fall back to synchronous scanning. |

## Memory issues

| Symptom | Likely cause | Solution |
|---|---|---|
| Read returns all zeros | Address not mapped or not readable | Check memory maps — the address may be unmapped. |
| Read returns garbage | Wrong endianness, encrypted data | Try reading as bytes and inspecting the hex. |
| Write doesn't take effect | Game overwrites immediately, or value is display-only | Enable Lock. Find the source value the game reads from. |
| Auto-refresh causes disconnect | Buffer too large, saturating connection | Reduce read length. Increase refresh interval. |
| Hex view shows wrong values | Wrong type interpretation | Toggle between u8/u16/u32/f32 views. |

## Console-specific issues

| Symptom | Likely cause | Solution |
|---|---|---|
| Empty process list | Insufficient privileges | PS4: Check GoldHEN is active. PS5: Check ps5debug status. |
| `MemDBG is already running` | Stale PID file or live daemon on PS4/GoldHEN. | See [PS4 / GoldHEN launch notes](https://github.com/seregonwar/MemDBG/blob/main/docs/ps4_goldhen_launch.md). |
| No UDP logs | UDP channel broken. | Verify port 9023. Check firewall. Ensure same network segment. |
| Console crashes during scan | Memory pressure, kernel panic. | Reduce parallel workers. Scan smaller regions. |
| PS5 KLOG not working | Unsupported firmware. | Check [PS5 validation notes](https://github.com/seregonwar/MemDBG/blob/main/docs/ps5_validation_2026-07-18.md). |
| Payload disappears after rest mode | Rest mode kills the payload. | Enable auto-inject in Settings. The reconnect system handles this. |
| PS4 crashes on ELF load | ELF architecture mismatch. | Verify you're loading a PS4 ELF (x86-64), not PS5 (AArch64). |

## Frontend issues

| Symptom | Likely cause | Solution |
|---|---|---|
| Frontend crashes on start | OpenGL or font issue. | Check `memdbg_crash.log`. Verify GPU drivers are up to date. |
| UI is slow/laggy | Too many auto-refresh operations. | Disable unnecessary auto-refresh. Reduce refresh rates. |
| Settings not saved | Write permission on config directory. | Check the frontend's working directory permissions. |
| Plugins don't load | Lua/Python not found. | Verify Lua JIT or Python is installed. Check plugin logs. |
| Crash on disconnect | Pending I/O not cancelled. | Check `memdbg_crash.log`. Update frontend. |

## Performance issues

| Symptom | Likely cause | Solution |
|---|---|---|
| Slow scans (< 50 MB/s) | WiFi connection, many small maps | Use wired Ethernet. Pre-filter maps. |
| High memory usage in frontend | Large scan results cached | Clear scan results when done. Restart frontend periodically. |
| Frontend uses 100% CPU | Excessive auto-refresh or lock intervals | Increase refresh/lock intervals. Reduce batch sizes. |
| Payload uses high CPU | Heavy lock loops, many parallel workers | Reduce lock frequency. Limit parallel scan workers. |

## "I still can't fix it"

1. **Save your work** (trainer files, AOB patterns, scan results).
2. **Restart everything**: Console, payload, frontend.
3. **Check the logs**: Frontend `memdbg_crash.log`, console UDP logs, payload `data-root` logs.
4. **Update**: Download the latest payload and frontend from [releases](https://github.com/seregonwar/MemDBG/releases).
5. **Report a bug**: Include platform, firmware, frontend version, payload version, and steps to reproduce. See the [issue templates](https://github.com/seregonwar/MemDBG/issues/new/choose).

| Error | Meaning | What to check |
|---|---|---|
| `payload status -3` | I/O error during operation. | Valid process, readable range, payload privileges, process alive. |
| `payload status -8` | Permission denied. | Privilege module, active jailbreak, payload logs, target permissions. |
| `not connected` | No active TCP session. | Connect to the console first; verify IP/port in Settings. |
| Empty process list | Cannot enumerate processes. | Ping, payload logs, supported platform, process privileges. |
| Scan has no results | Value, type, or range mismatch. | Try another type, narrow maps, use AOB or unknown scan. |
| No UDP logs | UDP channel broken. | Port 9023, firewall, broadcast, same network segment. |
| Frontend crashes on start | OpenGL or font issue. | Check `memdbg_crash.log`, verify GPU drivers. |

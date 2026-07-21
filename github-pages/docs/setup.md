MemDBG exposes a TCP command channel and an optional UDP log channel. The payload must be running on your console before you can use processes, maps, memory reads, scanners, or trainers.

## Platform-specific setup

### PS4 (GoldHEN)

1. Ensure GoldHEN 2.3 or later is running on your PS4.
2. Send `MemDBG-ps4.elf` using GoldHEN's **Payload Sender** (port `9021`).
3. Check the PS4 notification area — you should see a MemDBG notification confirming the payload started.
4. The payload binds to `0.0.0.0:9020` (TCP) and broadcasts logs on `255.255.255.255:9023` (UDP).

> **Permission issues?** Look for the log line `privilege: payload escaped sandbox` in the console output. If it's missing, many operations will fail with status `-3` (I/O error) or `-8` (permission denied). See [PS4 / GoldHEN launch notes](https://github.com/seregonwar/MemDBG/blob/main/docs/ps4_goldhen_launch.md) for full details.

### PS5 (ps5debug / etaHEN)

1. Ensure ps5debug or etaHEN is active on your PS5.
2. Send `MemDBG-ps5.elf` via the ps5debug payload loader on port `9021`.
3. The payload binds to `0.0.0.0:9020` (TCP) and broadcasts logs on `255.255.255.255:9023` (UDP).
4. KLOG forwarding is available via a separate TCP stream — negotiate with the frontend after connection.

> **Validation:** See the [PS5 validation notes](https://github.com/seregonwar/MemDBG/blob/main/docs/ps5_validation_2026-07-18.md) for tested firmware versions and known limitations.

### Host (PC testing)

The host build is useful for development, testing, and learning the tool without a console:

```bash
./build/MemDBG-host --bind=127.0.0.1 --debug-port=9020 --udp-port=9023
```

You can attach to any local process for memory reading, scanning, and debugging practice.

## Command-line arguments

| Argument | Default | Description |
|---|---|---|
| `--bind=127.0.0.1` | `127.0.0.1` (host) / `0.0.0.0` (console) | Address the payload listens on. |
| `--allow=192.168.1.50` | _(none)_ | Optional single IPv4 client allowlist for LAN sessions. |
| `--debug-port=9020` | `9020` | TCP port for frontend command channel. |
| `--udp-host=255.255.255.255` | `255.255.255.255` | UDP broadcast address for logs. |
| `--udp-port=9023` | `9023` | UDP port for live console log delivery. |
| `--data-root=/data/memdbg` | platform-dependent | Payload data and log directory. |
| `--no-udp-log` | _(disabled)_ | Disable UDP log delivery entirely. |
| `--discovery-port=9022` | `9022` | UDP port for console discovery broadcasts. |

## Privilege escalation

On supported console platforms, MemDBG's privilege module attempts to:

1. **Elevate the payload** at startup — escaping the sandbox to gain full memory access.
2. **Temporarily elevate the target process** during read/write/batch operations.

After a successful elevation, you'll see a log line similar to:
```
privilege: payload escaped sandbox
```

If this line is missing:
- Verify your jailbreak is active and up to date.
- Check console logs for privilege-related errors.
- Some operations (memory read, scan) may still work on accessible regions.
- Operations requiring full access (kernel, debugger) will fail.

## Network configuration

### Firewall considerations

The frontend needs outbound TCP access to your console's IP on the debug port (`9020`). If using UDP logs, the frontend also needs to listen on the UDP log port (`9023`).

### Discovery

MemDBG supports UDP broadcast discovery on port `9022`. The frontend sends a discovery ping to `255.255.255.255:9022` and listening payloads respond with their IP, port, and platform. This is useful when you don't know the console's IP — just make sure both devices are on the same subnet.

### Multiple consoles

Each console runs its own MemDBG instance. Use different TCP ports or connect to different IPs. The frontend's saved targets make switching between consoles quick.

## Verifying the setup

After launching the payload and connecting from the frontend:

1. The sidebar should show **green** connection status.
2. Go to **Processes** → **Refresh** — you should see the console's process list.
3. Open the **Logs** screen — you should see live console output if UDP is configured.
4. Go to **Telemetry** — you should see uptime, connection count, and operational stats.

> **Nothing works?** See the [Troubleshooting](#troubleshooting) section for common errors and solutions.

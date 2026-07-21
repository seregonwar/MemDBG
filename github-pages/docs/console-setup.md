Platform-specific instructions for setting up MemDBG on PS4 and PS5 consoles.

## PS4 (GoldHEN)

### Requirements

- **PS4 firmware**: 9.00, 11.00, or compatible jailbreakable firmware
- **GoldHEN**: Version 2.3 or later
- **Payload sender**: GoldHEN's built-in BinLoader (port `9021`) or an external sender like NetCat GUI
- **Network**: PS4 and PC on the same local network (wired recommended for scan performance)

### Installation

1. Jailbreak your PS4 and load GoldHEN.
2. Download or [build from source](#setup) `MemDBG-ps4.elf`.
3. Send the ELF to your PS4:
   - **GoldHEN BinLoader**: Navigate to your PS4's IP on port `9021` from a browser, or use GoldHEN's built-in sender.
   - **NetCat GUI**: Enter your PS4's IP and port `9021`, select the ELF, and send.
4. You should see a notification: "MemDBG: payload started".
5. The payload listens on `0.0.0.0:9020`. Connect from the frontend using your PS4's IP.

### GoldHEN-specific notes

- GoldHEN must be running BEFORE sending the payload. The payload uses GoldHEN's privilege escalation hooks.
- If you see `privilege: payload escaped sandbox` in the logs, the payload has full access.
- If this line is missing, try: restart GoldHEN, re-send the payload, or check your GoldHEN version.
- Some firmware versions require specific GoldHEN builds. See the [PS4 GoldHEN notes](https://github.com/seregonwar/MemDBG/blob/main/docs/ps4_goldhen_launch.md) for compatibility details.

### "MemDBG is already running" error

This error occurs when a previous MemDBG instance left a stale PID file. Solutions:

1. **Restart the PS4** — this clears all running processes and PID files.
2. **Use GoldHEN's process manager** to kill the old MemDBG process, then restart.
3. See the [GoldHEN launch notes](https://github.com/seregonwar/MemDBG/blob/main/docs/ps4_goldhen_launch.md) for workarounds.

### PS4 limitations

- **4 watchpoint limit** (x86-64 hardware limit)
- **Memory read speed**: ~50–200 MB/s depending on region and PS4 model (vs ~500+ MB/s on PS5)
- **No KLOG forwarding** (PS4 kernel doesn't expose the same log interface)
- **PT walk** (page-table introspection) is available on supported firmware

## PS5 (ps5debug / etaHEN)

### Requirements

- **PS5 firmware**: 3.xx–5.xx (see [validation notes](https://github.com/seregonwar/MemDBG/blob/main/docs/ps5_validation_2026-07-18.md) for tested versions)
- **ps5debug** or **etaHEN**: Active and running
- **Payload loader**: ps5debug payload sender (port `9021`) or equivalent
- **Network**: PS5 and PC on the same local network

### Installation

1. Load ps5debug or etaHEN on your PS5.
2. Download or [build from source](#setup) `MemDBG-ps5.elf`.
3. Send the ELF via the payload loader on port `9021`.
4. The payload binds to `0.0.0.0:9020`. Connect from the frontend using your PS5's IP.

### PS5-specific features

The PS5 payload has several features not available on PS4:

| Feature | PS5 | PS4 |
|---|---|---|
| **KLOG forwarding** | Yes (separate TCP stream via `KLOG_CONNECT`) | No |
| **DMAP introspection** | Yes (direct memory access via DMAP) | Limited |
| **PT walk** | Yes (page-table introspection) | Yes |
| **Memory read speed** | Up to 1 GB/s (DMAP path) | ~50–200 MB/s |
| **Scan performance** | Faster (more cores, higher memory bandwidth) | Slower |
| **SIMD scan** | Yes (SIMD-accelerated compare) | Limited |

### KLOG setup

1. Connect to the PS5 payload.
2. Go to **Settings → KLOG** and enable KLOG forwarding.
3. The frontend opens a second TCP connection for kernel log streaming.
4. Kernel messages appear in the **KLOG** screen in real time.

> **KLOG is read-only.** It's a diagnostic tool — you can't send commands through it. Use the main TCP connection for all operations.

### DMAP access

On supported firmware, the PS5 payload can access process memory through the Direct Memory Access Path (DMAP):

- **Faster reads**: DMAP bypasses `ptrace` overhead, achieving near line-rate memory reads.
- **Kernel memory access**: DMAP enables `KERNEL_READ` and `KERNEL_WRITE` commands.
- **PT walk augmentation**: DMAP-backed PT walk provides physical address resolution.

If DMAP is unavailable, the payload falls back to standard process memory access.

### PS5 limitations

- **Firmware compatibility**: Not all firmware versions support all features. Check the [validation notes](https://github.com/seregonwar/MemDBG/blob/main/docs/ps5_validation_2026-07-18.md).
- **4 watchpoint limit** (AArch64 hardware limit, same as x86-64)
- **Anti-debug**: Some PS5 games have kernel-level anti-debugging. The debugger may not work with all titles.
- **Rest mode**: The [reconnect system](https://github.com/seregonwar/MemDBG/blob/main/docs/reconnect.md) handles rest-mode cycles, but some payloads may need re-injection.

## Network configuration for consoles

### Finding your console's IP

1. On PS4: **Settings → System → System Information**.
2. On PS5: **Settings → Network → Connection Status → View Connection Status**.

### Wired vs. WiFi

| | Wired (Ethernet) | WiFi |
|---|---|---|
| **Scan speed** | Faster (lower latency, more stable) | Slower (variable latency) |
| **Connection stability** | Very stable | Subject to interference |
| **UDP log reliability** | Near zero packet loss | Possible packet loss |

> **Strong recommendation:** Use wired Ethernet for both the console and PC when doing heavy scanning or memory dumps. WiFi adds latency that directly impacts scan throughput.

### Firewall and router settings

- The frontend initiates the TCP connection, so the PC needs outbound access to the console's IP on port `9020`.
- The console needs to accept inbound TCP on port `9020` (most home routers allow this by default for LAN traffic).
- UDP logs (port `9023`) are broadcast, so both devices must be on the same subnet.
- If you're connecting across subnets, use `--udp-host=<pc-ip>` on the payload to send logs directly instead of broadcasting.

## Updating the payload

1. Download the latest `MemDBG-ps4.elf` or `MemDBG-ps5.elf` from the [releases page](https://github.com/seregonwar/MemDBG/releases).
2. If the old payload is running, send `SHUTDOWN` from the frontend or restart the console.
3. Send the new ELF via the payload sender.
4. Reconnect from the frontend.
5. The HELLO response shows the new payload version — verify it matches the expected version.

## Troubleshooting console issues

| Problem | Likely cause | Solution |
|---|---|---|
| "Connection refused" | Payload not running | Re-send the payload ELF |
| "Connection timed out" | Wrong IP or firewall | Verify console IP, check firewall |
| Empty process list | Insufficient privileges | Check GoldHEN / ps5debug status |
| `status -8` on all operations | Payload not escaped sandbox | Check `privilege: payload escaped sandbox` in logs |
| Frontend can't discover console | Different subnet | Use direct IP connection instead of discovery |
| Scan crashes the console | Too many parallel workers or oversized buffer | Reduce `MEMDBG_SCAN_PARALLEL_THREADS` or scan a smaller region |
| KLOG not working (PS5) | Firmware doesn't support KLOG | Check validation notes for your firmware version |

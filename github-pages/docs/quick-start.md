## Prerequisites

Before you start, make sure you have:

- A **jailbroken PS4** (GoldHEN 2.3+) or **PS5** (ps5debug/etaHEN) on the same network as your PC
- The **MemDBG payload** built for your console (`MemDBG-ps4.elf` or `MemDBG-ps5.elf`)
- The **MemDBG frontend** built and running on your PC (Windows, macOS, or Linux)

If you're just testing locally, a host build is sufficient — see the [Setup](#setup) section.

## 1. Build the payload

```bash
# Host build (local testing on PC)
make host

# PS4 payload
make payload-ps4 PS4_PAYLOAD_SDK=/path/to/ps4-payload-sdk

# PS5 payload
make payload-ps5 PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
```

The binaries land in `build/` (host) or `build/ps4/` / `build/ps5/` (console).

## 2. Launch the payload on your console

### PS4 (GoldHEN)
Send `MemDBG-ps4.elf` to your PS4 using a payload sender (e.g. GoldHEN's built-in sender on port `9021`, or NetCat GUI). The payload listens on `0.0.0.0:9020` by default.

### PS5 (ps5debug / etaHEN)
Send `MemDBG-ps5.elf` via the ps5debug payload loader. The payload binds to `0.0.0.0:9020` on the console's IP.

### Host (local PC testing)
```bash
./build/MemDBG-host --bind=127.0.0.1 --debug-port=9020 --udp-port=9023
```

Use `--bind=0.0.0.0 --allow=<frontend-ip>` only when another machine on the LAN must connect.

## 3. Open the frontend

```bash
make frontend
./build/frontend/memdbg_frontend
```

Or build with CMake directly:

```bash
cmake -S frontend -B build/frontend -DCMAKE_BUILD_TYPE=Release
cmake --build build/frontend --config Release
```

## 4. Connect to the console

1. In the frontend, enter your console's **IP address** in the connection bar.
2. Confirm the **TCP port** (default: `9020`).
3. Press **Connect**.

After a successful HELLO handshake, the sidebar shows:
- Connection state (green = online)
- Console IP and port
- Platform (PS4 / PS5 / Host)
- UDP log status (if configured)

> **First connection?** Go to **Settings → Console Targets** and save your console as a target. You can store the IP, ports, platform, and auto-inject preferences for quick reconnection later.

## 5. Your first memory scan

Here's a practical walkthrough — let's find a health value in a game:

1. Open the **Processes** screen and click **Refresh**.
2. Select your game from the process list.
3. Click **Load Maps** to see the game's memory regions.
4. Go to the **Scanner** screen.
5. Choose **Exact Scan**, type `u32`, and enter your current health value (e.g. `100`).
6. Select **Process Scan** to scan all readable memory.
7. Click **Start Scan**. Wait for results.
8. In the game, change your health (take damage or heal).
9. Enter the new value and click **Next Scan** to narrow results.
10. Repeat until only a few candidates remain.
11. Double-click a result to jump to the **Memory** screen and verify it.
12. Write a test value to confirm you found the right address.

> **Tip:** If the scan returns too many results, try filtering by map type (e.g. only scan `rw-` regions) or use a narrower value type like `f32` for float values.

## 6. Create a trainer

Once you've confirmed the address:

1. Go to the **Trainer** screen.
2. Click **Add Cheat**.
3. Name it (e.g. "Infinite Health").
4. Paste the address and choose the value type.
5. Set the **ON value** (e.g. `9999`) and capture the **OFF value** (the original).
6. Optionally enable **Lock** to freeze the value.
7. Save as a `.cht` file for reuse.

> **Important:** Absolute addresses change on every game restart (ASLR). For permanent trainers, convert your cheat to use an **AOB signature** or **pointer chain** — see the [Trainer](#trainer) section.

## 7. Next steps

- Learn the [full workflow](#workflow) for efficient memory hacking
- Master [scanning techniques](#scanner) (AOB, pointer, unknown value)
- Set up [UDP logging](#frontend) for real-time console output
- Explore the [debugger](#debugger) for advanced reverse engineering
- Automate with [Batchcode scripts](#batchcode)

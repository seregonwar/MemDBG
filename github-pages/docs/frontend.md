## Connection

Enter the console or host IP address, confirm the TCP port, and press **Connect**. After the HELLO response the sidebar shows connection state, IP, port, and UDP status.

## Saved IP

In **Settings** you can save the IP address you use most often. Useful when the console has a static address or a DHCP reservation.

## Console log

The **Logs** screen shows UDP messages from the payload. If messages don't arrive, verify that the frontend is listening on the same UDP port configured in the payload.

## Telemetry

The **Telemetry** screen summarizes uptime, active connections, total reads/writes, and scanner cache performance. Use it to understand whether a trainer is writing too often.

## Crash logger

The frontend writes a `memdbg_crash.log` file next to the executable. It captures connection events, errors, and console-side log lines for offline diagnosis.

## ELF Load / Hijack

The **Processes** screen includes an ELF Load / Hijack section for injecting custom binaries into a target process.

### File selection

- **File picker**: click *Select ELF…* to open a native file dialog.
- **Drag & drop**: drag `.elf`, `.so`, `.prx`, `.sprx`, or `.bin` files directly onto the window — they are captured and loaded automatically.
- **Raw binaries** (`.bin`): stripped payloads without an ELF header are accepted as raw machine code. No metadata is displayed — just a *Raw binary* label.

### ELF validation & metadata

When a valid ELF file is selected, the frontend parses the ELF header client-side and displays:

- **Basic metadata**: ELF class (32-bit or 64-bit), type (`ET_EXEC`, `ET_DYN`, `ET_REL`, `ET_CORE`), machine architecture (`EM_X86_64`, `EM_AARCH64`, `EM_386`, `EM_ARM`), and entry point address.
- **PT_LOAD segments**: a scrollable table showing each loadable segment with virtual address, memory size, file size, and permissions (`r`, `w`, `x`).
- **Architecture mismatch warning**: if the ELF architecture doesn't match the connected console (e.g., an AArch64 ELF on a PS4), a colored warning `⚠` appears with a tooltip explaining that loading will fail or crash the process.
- Invalid ELF files (bad magic or incomplete headers) are rejected immediately with a status message showing the raw magic bytes.

### Target region

- **Load ELF**: loads an ELF binary into the selected process (async, non-blocking), optionally matching a VM region by name. Supports wildcards (`*`), substring fallback, and configurable match flags (Exact, Case-Sensitive, Regex, Full Path).
- **Hijack**: spawns a thread inside the target process to run the injected payload, with the same region matching controls.
- **Double-click** any map row in the maps table to populate the *Target Region* field automatically — the UI auto-scrolls to the ELF section and highlights the input field with a fading teal animation for immediate visual feedback.
- ELF magic (`0x7F E L F`) is validated client-side before sending the file to the payload, with immediate feedback on invalid files.

## Multi-language

The frontend supports 8 languages (English, Italian, German, French, Spanish, Portuguese, Russian, Japanese). Change the language in Settings or via the saved configuration.

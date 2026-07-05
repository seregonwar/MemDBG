# Feature Research

This note tracks the native debugger parity work against ps5debug-NG without
copying its protocol or implementation. The intent is to keep MemDBG's MDBG
wire protocol capability-aware while filling the low-level gaps that matter for
serious runtime inspection.

## Current parity pass

| Area | Status | Notes |
|---|---|---|
| Debug attach / detach / stop / continue / step | Implemented | Existing debugger lifecycle remains the base. |
| Software breakpoints | Implemented | INT3 breakpoints are managed by the debugger backend and covered by tests. |
| Hardware watchpoints / hardware breakpoints | Implemented | Uses debug-register slots through the debugger backend; the Memory screen still has polling watch overlays for non-attached workflows. |
| Thread list and control | Implemented | Thread enumeration, suspend, resume, and single-step are exposed through debugger commands and UI controls. |
| GPR and debug registers | Implemented | Read/write GPR and DBREG paths are exposed in the debugger UI and tests. |
| FPU / YMM register blob | Implemented where PAL supports XSTATE or FPREGS | The backend prefers `PT_GETXSTATE`/`PT_SETXSTATE` for XSAVE/YMM coverage and falls back to `PT_GETFPREGS`/`PT_SETFPREGS`. The frontend exposes a raw hex view and shows the wire flags. |
| FS/GS base | Implemented where PAL supports FS/GS ptrace requests | PS5 SDK builds expose `PT_GETFSBASE`/`PT_SETFSBASE` and `PT_GETGSBASE`/`PT_SETGSBASE`; PS4 does not advertise this capability. |
| Process memory protection | Implemented on PS5 | `PROCESS_PROTECT` maps MDBG R/W/X flags to native protection flags and reports old protection when available. |
| Kernel base/read/write | Implemented on PS4/PS5 | Uses payload kernel copy helpers and is capability-gated. Host builds return `UNSUPPORTED`. |
| Server-side stack walk | Implemented | `PROCESS_STACK` walks up to 64 RBP-linked frames and returns per-frame stack/code windows. The debugger UI can jump from return addresses to disassembly. |
| Patch Studio / Analysis Notebook | Implemented in the desktop frontend | The debugger exposes these workspace tools as regular tabs. Patch Studio stages instructions from disassembly, captures original bytes, applies reversible byte/NOP/INT3 patches, uses `PROCESS_PROTECT` when available, saves patch manifests, bookmarks evidence into an Analysis Notebook, exports Markdown reports, and exports trainer entries with OFF bytes. |
| Console notification / kernel print | Implemented on consoles | `CONSOLE_NOTIFY` uses the PAL notification path; `CONSOLE_PRINT` writes to klog on console payloads. |
| Console reboot | PS5 implemented, PS4 unsupported | PS4 SDK used here does not export a linkable `reboot`, so PS4 returns `UNSUPPORTED`. |
| Remote allocation/free | Protocol endpoint only | Kept disabled until MemDBG has a safe remote syscall bridge. |
| Remote function call | Protocol endpoint only | Request validation exists; execution returns `UNSUPPORTED`. |
| ELF load into target process | Implemented with region matching | Supports `target_region` with wildcards, substring fallback, and `match_flags` (Exact, Case-Sensitive, Regex, Full Path). Hijack mode spawns a thread inside the target. Frontend provides async dispatch, ELF magic validation, and double-click map→target_region. |
| Process hijack (thread injection) | Implemented | Spawns a thread in the target with the same `match_flags` region matching; frontend provides confirmation modal and async dispatch. |

## Still open

| Area | Direction |
|---|---|
| Turbo SIMD scanner paths | Add AVX2/NEON-style fast paths behind runtime feature checks while keeping resilient page handling. |
| Parallel alias compare engine | Build on the existing batch and partition infrastructure instead of importing a ps5debug wire model. |
| Assembler integration | Add an optional assembler backend only after the disassembler/edit workflow is stable. |
| Klog forwarder stream | Add a capability-gated stream or UDP channel; keep it separate from the existing user-facing UDP log feed. |
| Old ps5debug wire compatibility | Not a default goal. A bridge/proxy can be considered later if it does not weaken the MDBG protocol. |

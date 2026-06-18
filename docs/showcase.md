# MemDBG Showcase
> The photos below may not be completely up to date because the program is constantly being updated; try the latest build to see the updated interface.

This page gives a quick tour of the MemDBG frontend. Each section shows the main workflow exposed by the screen and the kind of console-side payload feature it drives.

## Main

### Command Center

The command center is the first operational view after launch. It summarizes the current console session, selected process, payload status, recent activity, and shortcuts to the workflows used most often during a debugging session.

<img width="920" alt="MemDBG command center" src="https://github.com/user-attachments/assets/55524e43-1e18-4bcf-b613-b8c6d27d9879" />

### Consoles

The consoles screen manages direct payload sessions and discovery data. Use it to connect, ping, drop, or switch the active console endpoint without leaving the main interface.

<img width="920" alt="MemDBG console connection screen" src="https://github.com/user-attachments/assets/36a2b24c-8717-4eb1-8dd8-604011a3cea7" />

## Tools

### Processes

The processes screen lists running targets and exposes their memory maps. It is the main place to select a PID, inspect mapped regions, filter maps, and prepare dump or scan ranges.

<img width="920" alt="MemDBG process and map inspector" src="https://github.com/user-attachments/assets/e5c3597f-eea0-44c8-8d8e-4db04d0d0044" />

### Memory

The memory screen provides direct read and write access for the selected process. It can inspect addresses, patch bytes, watch values, manage allocations, and scan selected maps for useful gadgets.

<img width="920" alt="MemDBG memory editor" src="https://github.com/user-attachments/assets/7d963935-438c-4b02-9e54-a21e122f7112" />

### Scanner

The scanner searches process memory for exact values and supports process-wide scans, explicit range scans, unknown-value sessions, and refinement passes such as changed, unchanged, increased, or decreased.

<img width="920" alt="MemDBG exact value scanner" src="https://github.com/user-attachments/assets/e9fdaee0-a6b4-4340-8ede-0485e82dc133" />

### Pointer Scan

Pointer scan searches memory for addresses that reference a target address. It is useful when values move between launches or when building stable trainer entries from dynamic locations.

<img width="920" alt="MemDBG pointer scanner" src="https://github.com/user-attachments/assets/06f24b19-a1b4-4196-8a90-f4fafacdcf61" />

### AOB Scan

AOB scan searches for byte patterns with masks and wildcards. It is designed for signatures that survive address relocation and can be used to locate code or data patterns across a target process.

<img width="920" alt="MemDBG array of bytes scanner" src="https://github.com/user-attachments/assets/5b2e5f2d-d662-468c-ab93-422c03322794" />

### Trainer

The trainer screen turns scan results or manual addresses into runtime cheat entries. Entries can be applied, restored, locked at an interval, imported from supported formats, and saved for later sessions.

<img width="920" alt="MemDBG trainer builder" src="https://github.com/user-attachments/assets/cbf5abae-4fc8-4fdb-9bc0-97c6a708d19f" />

### Debugger

The debugger attaches to a selected process and exposes thread control, register viewing/editing, breakpoints, watchpoints, step, stop, continue, and event polling for low-level runtime debugging.

<img width="920" alt="MemDBG debugger screen" src="https://github.com/user-attachments/assets/29949047-c448-4d22-95c4-5e64d8900a85" />

## Observe

### Task Manager

Task Manager shows process state and per-process resource details. It helps compare memory maps, mapped memory totals, readable/writable/executable regions, and process control actions from one operational view.

<img width="920" alt="MemDBG task manager process list" src="https://github.com/user-attachments/assets/be6c44a6-e3c2-48cb-97b5-ee652f776439" />

<img width="920" alt="MemDBG task manager process details" src="https://github.com/user-attachments/assets/9e3f220c-b016-42f6-9101-60df432eca62" />

### UDP Logs

UDP Logs displays payload log messages received over the UDP telemetry channel. It is useful for watching runtime errors, payload diagnostics, and console-side messages without interrupting the TCP command session.

<img width="920" alt="MemDBG UDP log viewer" src="https://github.com/user-attachments/assets/a2a44c4e-d8a1-4f79-aa9c-a9a4fa510a7d" />

### Telemetry

Telemetry focuses on payload runtime counters: memory I/O, scan performance, packet sizes, cache behavior, and other metrics that help diagnose slow or unstable sessions.

<img width="920" alt="MemDBG telemetry dashboard" src="https://github.com/user-attachments/assets/6356a51e-b2f3-45ce-a234-ac29a1fd6a20" />

## System

### Settings

Settings controls frontend defaults such as console IP, TCP/UDP ports, dump path, crash logging, language, and persistence. It is also where local configuration can be saved or restored.

<img width="920" alt="MemDBG settings screen" src="https://github.com/user-attachments/assets/f6fbe42e-7b28-4fb2-8d3e-86eb8cffc71e" />

### Credits

Credits contains project information, license details, author links, and support links.

<img width="920" alt="MemDBG credits screen" src="https://github.com/user-attachments/assets/2727f78a-0d65-4606-9447-c87254c564af" />

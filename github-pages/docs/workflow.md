1. Connect to the payload and open the **Processes** screen.
2. Refresh the process list and select the game or application.
3. Load the memory maps for the selected process.
4. Prefer maps with read permission for scans and memory reads.
5. Use **Dump selected map** to save a region to disk.
6. Use **ELF Load** to inject a custom binary into the target process, or **Hijack** to spawn a thread running the payload. Double-click any map row to populate the target region field.

> **Rule of thumb:** Before reading or scanning you need a valid process and, for range scans, a range that matches the process maps. Bad ranges, terminated processes, or unreadable pages can produce I/O errors even when the TCP connection is alive.

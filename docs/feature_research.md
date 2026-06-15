# memDBG feature research

This note tracks external feature targets and how they map into memDBG.

## Sources

- ScriptSK/Reaper-Software-Suite repository: resources for MultiTrainer2 and Reaper Studio on PlayStation 4 and 5.
- Reaper Studio public beta notes: debugger, converter, trainer engine, assisted cheat creator.
- Reaper Studio v1.0.4.2 notes: multi-threaded debugging, high-address code caves, breakpoint/watchpoint grouping, kstuff compatibility, 64-bit ranges.
- PS4_Cheater and PS4CheaterNeo notes: memory search/edit, cheat lists, pointer finder, batchcode, console scanner, scan progress, unknown initial scans, section filters, dump/import section blocks.
- psdevwiki Content ID and PS5 Param.json pages: Content ID, Title ID, `contentId`, `titleId`, localized title metadata.

## Implemented foundation

- Console-first ImGui app shell with connection as the primary workflow.
- Modular frontend entrypoint: `main.cpp` delegates to `memdbg_app.cpp`.
- UDP receiver now waits for bind success, tracks received/dropped counters, timestamps lines, and shows sender endpoint.
- Dynamic GitHub credits fetch for `seregonwar`, including avatar download and runtime texture upload.
- Trainer page with manual entries, lock/freeze, apply-enabled, and basic batchcode import (`offset`, `value`, `size` tokens).
- Trainer entries capture OFF values from runtime memory, can activate/deactivate cheats, and can load/save base `.cht` data entries.
- Payload/client `PROCESS_INFO` command for process name, executable path, Title ID, and Content ID discovery.
- Scan session baseline capture after exact scans, with next-scan refine for changed, unchanged, increased, and decreased values.
- Section filters by name/protection/size, filtered scan window setup, and selected-map binary dump.

## Next feature blocks

- Scan refinement: unknown initial, bigger/smaller, between, compare-to-first, undo history.
- Section UX: check all/uncheck all/invert presets, import selected map, diff selected map against a dump.
- Trainer formats: relative `.chtr`, full pointer `.cht`, GoldHEN JSON/SHN read support, richer ON/OFF groups.
- Pointer tooling: pointer scan, pointer validation, pointer-chain trainer entries.
- Debugger tooling: attach/detach, pause/resume, breakpoints, watchpoints, call stack, disassembler, code cave helper.
- Converter tooling: bytes to typed values, typed values to bytes, assembly to bytes once an assembler backend is selected.

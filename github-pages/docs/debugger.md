The debugger gives you low-level control over the target process. You can pause execution, inspect registers, set breakpoints and watchpoints, step through code, and disassemble instructions — all from the frontend.

## When to use the debugger

| Scenario | Debugger feature |
|---|---|
| Find what writes to an address | Set a **write watchpoint** on the address |
| Find what reads from an address | Set a **read watchpoint** on the address |
| Trace code execution flow | Set **breakpoints** at function boundaries |
| Inspect function arguments | Break at function entry, read registers |
| Understand a crash | Attach after crash, inspect registers and stack |
| Bypass a check | NOP the check instruction, set breakpoint to verify |
| Find a static pointer | Break in initialization code, trace pointer writes |

## Attaching and detaching

### Attach

1. Select your target process in the **Processes** screen.
2. Go to the **Debugger** screen.
3. Click **Attach**.

The process pauses immediately. The debugger takes control and the status shows "Attached" with the stop reason.

> **Warning:** Attaching pauses the ENTIRE process, not just one thread. The game freezes, audio stops, and network connections may time out. This is normal.

### Detach

Click **Detach** to release control and let the process run normally. Any breakpoints you set are removed. The process resumes from where it was paused.

> **Tip:** Always detach before closing the frontend or disconnecting. Leaving a process in debug-stop can cause console instability.

## Threads

The **Threads** panel shows all threads in the target process:

| Column | Description |
|---|---|
| **TID** | Thread ID |
| **State** | Running, Stopped, Suspended, or Dead |
| **Stop info** | Signal or reason the thread stopped (e.g. `SIGTRAP` for breakpoint hit) |
| **Name** | Thread name if available |

### Thread control

- **Suspend**: Pause a specific thread without affecting others.
- **Resume**: Let a suspended thread run again.
- **Freeze on breakpoint**: When checked, only the thread that hit the breakpoint stops — other threads keep running.

> **Suspend vs. Stop:** Stop applies to the whole process (via attach). Suspend targets individual threads. Most debugging workflows use stop-all mode.

## Registers

The **Registers** panel shows the CPU register state. Select a thread to view its registers.

### General-purpose registers (x86-64)

| Register | Typical purpose |
|---|---|
| `RAX` | Return value, accumulator |
| `RBX` | Callee-saved |
| `RCX` | 4th argument |
| `RDX` | 3rd argument |
| `RSI` | 2nd argument |
| `RDI` | 1st argument |
| `RBP` | Frame pointer |
| `RSP` | Stack pointer |
| `R8–R15` | Additional arguments / general purpose |
| `RIP` | Instruction pointer (current code address) |

### Editing registers

Double-click a register value to edit it. Press Enter to apply. Common uses:

- **Change RIP** to jump to a different code path.
- **Modify RAX** to change a function's return value.
- **Set RSP** to manipulate the stack.

> **Editing RIP is dangerous.** If you jump to an invalid address, the process will crash. Stick to valid code addresses you've verified via disassembly.

### Floating-point / vector registers

If the payload supports `MEMDBG_CAP_DEBUG_FPREGS`, you can also view and edit:
- **XMM0–XMM15**: SSE/SSE2 128-bit registers (common for float/double math)
- **XSTATE**: Extended state (AVX, AVX-512) up to 1024 bytes

## Breakpoints

Software breakpoints pause execution when the instruction pointer reaches a specific address.

### Setting a breakpoint

1. Navigate to the target address (use the Memory screen or disassembly).
2. Click **Set Breakpoint**.
3. The address appears in the breakpoint list with a unique ID.
4. When the game reaches that instruction, execution pauses.

### Conditional breakpoints

Add a condition to break only when a register matches:

1. Set a breakpoint normally.
2. Click **Add Condition**.
3. Choose a register (e.g. `RAX`), operator (`==`, `!=`, `<`, `>`, etc.), and value.
4. The breakpoint now only triggers when `RAX == <value>`.

> **Use conditions to filter noise.** A breakpoint in a frequently-called function (e.g. the game loop) triggers hundreds of times per second. Add a condition to isolate the specific case you're investigating.

### Managing breakpoints

| Action | What it does |
|---|---|
| **Enable/Disable** | Toggle breakpoint without removing it |
| **Clear** | Remove a single breakpoint |
| **Clear All** | Remove all breakpoints |
| **Edit** | Change the address or condition |

> **Breakpoint persistence:** Breakpoints survive Continue/Stop cycles but are removed on Detach. If you detach and re-attach, re-set your breakpoints.

## Watchpoints

Hardware watchpoints pause execution when a memory address is read from or written to. Unlike software watchpoints (in the Memory screen), these use CPU debug registers for zero-overhead monitoring.

### Hardware limitations

| Platform | Max watchpoints | Max size per watchpoint |
|---|---|---|
| x86-64 (PS4, Host) | 4 | 1, 2, 4, or 8 bytes |
| AArch64 (PS5) | 4 | 1, 2, 4, or 8 bytes |

> **4 watchpoints total.** If you exceed this, you must clear an existing watchpoint first.

### Setting a watchpoint

1. In the Memory screen, find the address you want to watch.
2. Click **Set Watchpoint**.
3. Choose **Write** (break when value changes), **Read** (break when value is read), or **Read/Write** (both).
4. Choose the size (1, 2, 4, or 8 bytes).

When the game reads or writes that address, execution pauses and the debugger shows which instruction triggered it.

### Finding what writes to an address

This is the most common watchpoint use case:

1. You've found the health address via scanning.
2. You want to find the CODE that writes to it.
3. Set a **write watchpoint** on the health address.
4. Take damage in-game — the debugger pauses at the exact instruction that modifies health.
5. The RIP register points to the write instruction.
6. NOP that instruction to prevent damage, or trace back to find the damage calculation.

## Stepping

When execution is paused, you can advance one instruction at a time:

| Step type | Action |
|---|---|
| **Step Into (F7)** | Execute one instruction. If it's a `call`, enter the function. |
| **Step Over (F8)** | Execute one instruction. If it's a `call`, run the whole function and stop after. |
| **Step Out (Shift+F8)** | Run until the current function returns. |

### Stepping strategy

1. Set a breakpoint at a function of interest.
2. When it hits, **Step Into** to follow the logic.
3. Use **Step Over** for calls you don't care about (e.g. `printf`, logging).
4. Use **Step Out** if you've seen enough of the current function.

## Disassembly

The **Disassembly** panel shows the code at the current RIP or any address you enter:

- Instructions are disassembled in real time via Zydis (x86-64) or the target's disassembler.
- **Control flow arrows** show jumps, calls, and branches.
- **Xrefs** (cross-references) show what other code references this address — click **Find Xrefs To** to see all callers.
- **Patch Studio** lets you assemble and inject custom instructions (requires `MEMDBG_CAP_DISASSEMBLY`).

### Patch Studio

The built-in assembler lets you write and inject custom code:

1. Enter assembly instructions in the editor (e.g. `mov eax, 9999; ret`).
2. Click **Assemble** — the frontend sends the assembly to the payload's Keystone engine.
3. If assembly succeeds, the machine code appears as hex bytes.
4. Click **Inject** to write the bytes into the target process at the current address.

> **Keep patches small.** The assembler handles standard x86-64/AArch64 instructions but doesn't resolve external symbols. For complex patches, assemble offline and paste the hex bytes.

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `F5` | Continue (resume execution) |
| `F7` | Step Into |
| `F8` | Step Over |
| `Shift+F8` | Step Out |
| `F9` | Toggle breakpoint at current address |
| `Ctrl+B` | Set breakpoint dialog |
| `Ctrl+W` | Set watchpoint dialog |
| `Ctrl+G` | Go to address (disassembly) |

## Common debugger workflows

### "What writes to my health?"

1. Scan for your health value and find the address.
2. Attach the debugger.
3. Set a **write watchpoint** on the health address (size = 4 for `u32`).
4. Continue execution.
5. Take damage in-game.
6. Debugger pauses at the write instruction.
7. RIP shows the code that modifies health — now you can NOP it, redirect it, or understand the damage formula.

### "What calls this function?"

1. Find the function address (via AOB scan, disassembly, or dump analysis).
2. Attach the debugger.
3. In the Disassembly panel, go to the function address.
4. Click **Find Xrefs To**.
5. Set breakpoints on each caller.
6. Continue execution — see which caller triggers when you perform specific actions.

### "Bypass an anti-debug check"

1. Attach to the process. If the game crashes, it may have anti-debug protection.
2. Look for common anti-debug patterns in the disassembly (e.g. `ptrace` calls, `isDebuggerPresent`).
3. Set a breakpoint before the check.
4. When it hits, skip the check by modifying RIP to jump past it, or modify the return value in RAX.
5. Continue execution — the game thinks no debugger is attached.

> **Persistent bypass:** Instead of manually skipping every time, write an AOB signature for the check and add trailing NOPs to your trainer. The trainer patches the anti-debug code before you even attach.

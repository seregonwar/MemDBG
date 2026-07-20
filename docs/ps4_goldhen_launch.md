# PS4 / GoldHEN Launch Notes

When you launch MemDBG from the GoldHEN menu, the payload may be injected into
a loader process that already ran MemDBG during an earlier attempt.  If the
previous payload crashed or was killed without cleaning up, a `memdbg.pid` file
may be left behind in the data root.  Because the PS4 kernel reuses PIDs
quickly, that stale file can accidentally match the new loader process and make
MemDBG think it is already running.

## What MemDBG does at launch

1. **Reads the existing PID file** (`${data_root}/memdbg.pid`).
2. **Compares the stored PID with `getpid()`**.
3. **If the PIDs match, it does not assume the daemon is alive.**  Instead it
   sends a `HELLO` probe to the configured debug port and waits for a valid
   MemDBG `HELLO` response.
   - If a real daemon answers with the correct magic, version, and feature
     level, MemDBG exits with the notification *"MemDBG is already running"*.
   - If nothing answers, the PID file is treated as **stale**, is removed, and
     startup continues normally.

This means a stale PID file after a crash is recovered automatically; you do not
need to delete it manually.

## Why you might still see "MemDBG is already running"

That message appears only when **another live MemDBG daemon responds to the
HELLO probe on the debug port**.  Common causes are:

- MemDBG was already running and you launched a second copy.
- A previous payload survived but its PID file was overwritten or lost.
- A different homebrew or service is bound to the same debug port and is
   replying with a valid MemDBG-compatible HELLO response (very unlikely).

## Logs

When MemDBG exits early because a live daemon was detected, it intentionally
**does not initialize its own log file**.  Opening the log sink would disturb
sockets or files owned by the running daemon.  The only feedback is the OS
notification.

If you suspect a stale PID issue, check the data root for `memdbg.pid`.  If the
file contains a PID that no longer exists, the next launch will remove it and
start normally.

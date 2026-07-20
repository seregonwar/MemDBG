# PS4 / GoldHEN Launch Notes

*Available in: [English](ps4_goldhen_launch.en.md) · [Deutsch](ps4_goldhen_launch.de.md) · [Español](ps4_goldhen_launch.es.md) · [Français](ps4_goldhen_launch.fr.md) · [Italiano](ps4_goldhen_launch.it.md) · [日本語](ps4_goldhen_launch.ja.md) · [한국어](ps4_goldhen_launch.ko.md) · [Português](ps4_goldhen_launch.pt.md) · [Русский](ps4_goldhen_launch.ru.md)*

When you launch MemDBG from the GoldHEN menu, the payload may be injected into
a loader process that already ran MemDBG during an earlier attempt.  If the
previous payload crashed or was killed without cleaning up, a `memdbg.pid` file
may be left behind in the data root.  Because the PS4 kernel reuses PIDs
quickly, that stale file can accidentally match the new loader process and make
MemDBG think it is already running.

On GoldHEN builds the default data root is `/data/memdbg`, so the PID file is
`/data/memdbg/memdbg.pid`.

## What MemDBG does at launch

1. **Reads the existing PID file** (`/data/memdbg/memdbg.pid`).
2. **Compares the stored PID with `getpid()`**.
3. **If the PIDs match, it does not assume the daemon is alive.**  Instead it
   sends a `HELLO` probe to the configured debug port and waits for a valid
   MemDBG `HELLO` response.
   - If a real daemon answers with the correct magic, version, and feature
     level **and** its `daemon_instance_id` matches the token stored in the PID
     file, MemDBG exits with the notification *"MemDBG is already running"*.
   - If nothing answers, or the daemon reports a different instance token, the
     PID file is treated as **stale**, is removed, and startup continues normally.

This means a stale PID file after a crash is recovered automatically; you do not
need to delete it manually.

## Instance token and PID-file locking

The PID file format is:

```
<pid> <instance_id_hex>
```

For example:

```
1234 deadbeefcafebabe
```

- `<instance_id_hex>` is the daemon's unique instance token, generated at
  payload startup and written alongside the PID.
- When MemDBG checks whether the stored PID is still alive, it sends a `HELLO`
  probe and verifies that the daemon's `daemon_instance_id` matches the token in
  the PID file.
  - If the tokens match, the daemon is genuinely the same instance and MemDBG
    exits with *"MemDBG is already running"*.
  - If the tokens do not match, the PID was reused by a different process after
    a crash; the PID file is treated as stale and removed.
- Old `memdbg.pid` files that contain only a PID are still supported. They are
  treated as having no token, so the HELLO probe is used without token
  verification.
- On platforms that support `flock`, MemDBG takes a best-effort advisory lock on
  the PID file while reading, writing, or removing it. This prevents two nearly
  simultaneous payload launches from corrupting the file. If `flock` is not
  available, the operation continues without locking.

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

If you suspect a stale PID issue, check `/data/memdbg/memdbg.pid`.  If the
file contains a PID that no longer exists, the next launch will remove it and
start normally.

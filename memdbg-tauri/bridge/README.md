# MDBG WebSocket-to-TCP Bridge

The browser cannot open raw TCP sockets, so the web UI talks to the MemDBG
payload through a tiny local proxy. This directory contains a reference
Node.js implementation.

## Wire contract

- Client opens `ws://<bridge>/mdbg?host=<CONSOLE_IP>&port=<PORT>`.
- The bridge opens a TCP socket to that host/port and becomes a
  transparent byte-pipe:
  - Binary WebSocket frames from the client are forwarded verbatim into
    the TCP socket.
  - Bytes read from the TCP socket are sent back as binary WebSocket
    frames. Framing does not need to preserve packet boundaries; the
    browser reassembles MDBG frames using the 20-byte response header.
- When either side closes, the bridge closes the other side.

**No auth by default.** Bind to `127.0.0.1` and treat this like a local
debug tool. If you need to run it on a remote host, put it behind an
authenticated reverse proxy.

## Running

```bash
node bridge/mdbg-bridge.mjs        # listens on 127.0.0.1:9021
PORT=9021 HOST=127.0.0.1 node bridge/mdbg-bridge.mjs
```

Dependencies: `ws` (`npm i ws` inside `bridge/`).

## Optional: LZ4 decompression

MDBG can compress large memory reads with LZ4. This reference bridge
forwards them untouched; the browser will surface an error until you
enable decompression. When you need it, decompress the payload in the
bridge (using `lz4-napi` or similar) before re-framing.

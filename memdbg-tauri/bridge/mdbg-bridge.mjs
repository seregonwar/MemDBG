#!/usr/bin/env node
/**
 * MDBG WebSocket-to-TCP bridge (reference implementation).
 *
 * Usage:
 *   npm i ws
 *   node bridge/mdbg-bridge.mjs           # 127.0.0.1:9021
 *   HOST=0.0.0.0 PORT=9021 node bridge/mdbg-bridge.mjs
 */
import { createServer } from "node:http";
import { connect } from "node:net";
import { URL } from "node:url";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 9021);
const HOST = process.env.HOST || "127.0.0.1";

const httpServer = createServer((_req, res) => {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("MDBG bridge — connect via ws://.../mdbg?host=<ip>&port=<port>\n");
});

const wss = new WebSocketServer({ noServer: true });

httpServer.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname !== "/mdbg") {
    socket.destroy();
    return;
  }
  const host = url.searchParams.get("host");
  const port = Number(url.searchParams.get("port"));
  if (!host || !port) {
    socket.write("HTTP/1.1 400 Bad Request\r\n\r\nmissing host/port\n");
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => bridge(ws, host, port));
});

function bridge(ws, host, port) {
  console.log(`[mdbg-bridge] → ${host}:${port}`);
  const tcp = connect({ host, port });
  let closed = false;

  const close = (reason) => {
    if (closed) return;
    closed = true;
    console.log(`[mdbg-bridge] close (${reason})`);
    try { tcp.destroy(); } catch {}
    try { ws.close(); } catch {}
  };

  tcp.on("connect", () => console.log(`[mdbg-bridge] tcp open ${host}:${port}`));
  tcp.on("data", (buf) => {
    if (ws.readyState === ws.OPEN) ws.send(buf, { binary: true });
  });
  tcp.on("error", (err) => close(`tcp error: ${err.message}`));
  tcp.on("close", () => close("tcp closed"));

  ws.on("message", (data, isBinary) => {
    if (!isBinary) return;
    tcp.write(data);
  });
  ws.on("close", () => close("ws closed"));
  ws.on("error", (err) => close(`ws error: ${err.message}`));
}

httpServer.listen(PORT, HOST, () =>
  console.log(`[mdbg-bridge] listening ws://${HOST}:${PORT}/mdbg`),
);

import logo from "@/assets/memdbg-logo.png";
import { useSession } from "@/store/session";
import { platformName } from "@/lib/protocol";
import { Activity, Plug, Settings, Wifi, Zap } from "lucide-react";
import { useState } from "react";
import { ConnectDialog } from "./ConnectDialog";
import { SettingsDialog } from "./SettingsDialog";


export function TopBar() {
  const conn = useSession((s) => s.conn);
  const hello = useSession((s) => s.hello);
  const attachedName = useSession((s) => s.attachedName);
  const attachedPid = useSession((s) => s.attachedPid);
  const logs = useSession((s) => s.logs);
  const disconnect = useSession((s) => s.disconnect);

  const [dialog, setDialog] = useState(false);
  const [settings, setSettings] = useState(false);


  const online = conn.kind === "online";
  const statusLabel =
    conn.kind === "online"
      ? "CONNECTED"
      : conn.kind === "handshaking"
      ? "HELLO…"
      : conn.kind === "connecting"
      ? "CONNECTING"
      : conn.kind === "closed"
      ? "OFFLINE"
      : conn.kind === "error"
      ? "ERROR"
      : "IDLE";

  const host = conn.kind === "online" || conn.kind === "handshaking" || conn.kind === "connecting"
    ? `${conn.host}:${conn.port}`
    : "—";

  const packetsPerSec = logs.length;

  return (
    <>
      <header className="flex h-16 shrink-0 items-center gap-4 border-b border-mem-line bg-mem-panel px-5">
        <div className="flex items-center">
          <img src={logo} alt="MemDBG" className="h-12 w-auto object-contain" />
        </div>

        <div className="mx-2 h-6 w-px bg-mem-line" />

        <button
          type="button"
          onClick={() => (online ? disconnect() : setDialog(true))}
          className="flex items-center gap-2 rounded-sm border border-mem-line bg-mem-bg px-2.5 py-1 hover:border-mem-accent"
        >
          <span className="relative flex h-2 w-2">
            <span
              className={`absolute inline-flex h-full w-full rounded-full ${
                online ? "mem-live-dot bg-mem-accent" : "bg-mem-muted"
              }`}
            />
            <span
              className={`relative inline-flex h-2 w-2 rounded-full ${
                online ? "bg-mem-accent" : "bg-mem-muted"
              }`}
            />
          </span>
          <span className="font-mono text-xs text-mem-text">{host}</span>
          <span className="font-mono text-[10px] text-mem-muted">{statusLabel}</span>
          {!online && <Plug className="h-3 w-3 text-mem-muted" />}
        </button>

        {hello && (
          <div className="flex items-center gap-2 rounded-sm border border-mem-line bg-mem-bg px-2.5 py-1">
            <Zap className="h-3 w-3 text-mem-accent" />
            <span className="font-mono text-xs text-mem-text">
              {hello.name || "console"} {hello.version}
            </span>
            <span className="font-mono text-[10px] text-mem-muted">
              {platformName(hello.platformId)}
            </span>
          </div>
        )}

        {attachedPid != null && (
          <div className="flex items-center gap-2 rounded-sm border border-mem-line bg-mem-bg px-2.5 py-1">
            <Zap className="h-3 w-3 text-mem-accent" />
            <span className="font-mono text-xs text-mem-text">{attachedName || "process"}</span>
            <span className="font-mono text-[10px] text-mem-muted">
              PID {attachedPid} · 0x{attachedPid.toString(16).toUpperCase()}
            </span>
          </div>
        )}

        <div className="ml-auto flex items-center gap-4 font-mono text-[11px] text-mem-muted">
          <div className="flex items-center gap-1.5">
            <Wifi className="h-3 w-3" />
            <span>{packetsPerSec} events</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Activity className="h-3 w-3" />
            <span>{online ? "live" : "idle"}</span>
          </div>
          <button
            type="button"
            onClick={() => setSettings(true)}
            className="flex h-7 w-7 items-center justify-center rounded-sm border border-mem-line hover:border-mem-accent hover:text-mem-accent"
            aria-label="Settings"
          >
            <Settings className="h-3.5 w-3.5" />
          </button>
        </div>
      </header>
      {dialog && <ConnectDialog onClose={() => setDialog(false)} />}
      {settings && <SettingsDialog onClose={() => setSettings(false)} />}
    </>
  );
}


import { useSession, mapId } from "@/store/session";
import { addrToHex } from "@/lib/protocol";
import { Boxes, Cpu, HardDrive, RefreshCw } from "lucide-react";
import { ExpandableSection } from "./ExpandableSection";


export function LeftRail() {
  const conn = useSession((s) => s.conn);
  const processes = useSession((s) => s.processes);
  const attachedPid = useSession((s) => s.attachedPid);
  const maps = useSession((s) => s.maps);
  const activeMapId = useSession((s) => s.activeMapId);
  const setActiveMap = useSession((s) => s.setActiveMap);
  const attach = useSession((s) => s.attach);
  const refresh = useSession((s) => s.refreshProcesses);
  const loadingProcesses = useSession((s) => s.loadingProcesses);
  const online = conn.kind === "online";

  return (
    <aside className="flex h-full w-72 shrink-0 flex-col border-r border-mem-line bg-mem-panel">
      <ExpandableSection title="Processes" className="max-h-[40%] border-b border-mem-line">
        <SectionHeader
          icon={<Cpu className="h-3 w-3" />}
          label="PROCESSES"
          right={
            <button
              type="button"
              onClick={() => refresh()}
              disabled={!online || loadingProcesses}
              aria-label="Refresh processes"
              className="text-mem-muted hover:text-mem-accent disabled:opacity-40"
            >
              <RefreshCw className={`h-3 w-3 ${loadingProcesses ? "animate-spin" : ""}`} />
            </button>
          }
        />
        <div className="min-h-0 flex-1 overflow-y-auto">
          {!online && (
            <div className="px-3 py-4 text-center font-mono text-[11px] text-mem-muted">
              Not connected. Open <span className="text-mem-accent">Connect</span> in the top bar.
            </div>
          )}
          {online && processes.length === 0 && !loadingProcesses && (
            <div className="px-3 py-4 text-center font-mono text-[11px] text-mem-muted">
              No processes yet — click refresh.
            </div>
          )}
          {processes.map((p) => {
            const active = p.pid === attachedPid;
            return (
              <button
                key={p.pid}
                type="button"
                onClick={() => attach(p.pid, p.name)}
                className={`flex w-full items-center gap-2 border-b border-mem-line/60 px-3 py-1.5 text-left transition-colors ${
                  active ? "bg-mem-accent/10" : "hover:bg-mem-bg"
                }`}
              >
                <div className={`h-1.5 w-1.5 rounded-full ${active ? "bg-mem-accent" : "bg-mem-line"}`} />
                <div className="min-w-0 flex-1">
                  <div className={`truncate font-mono text-xs ${active ? "text-mem-accent" : "text-mem-text"}`}>
                    {p.name}
                  </div>
                  <div className="font-mono text-[10px] text-mem-muted">
                    PID {p.pid} · {p.titleId || "—"}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </ExpandableSection>

      <ExpandableSection title="Memory maps" className="flex-1">
        <SectionHeader
          icon={<HardDrive className="h-3 w-3" />}
          label="MEMORY MAPS"
          right={<span className="font-mono text-[10px] text-mem-muted">{maps.length}</span>}
        />
        <div className="min-h-0 flex-1 overflow-y-auto px-2 py-2">
          {maps.length === 0 && (
            <div className="px-2 py-3 text-center font-mono text-[10px] text-mem-muted">
              {attachedPid == null ? "Attach to a process to load maps." : "no maps"}
            </div>
          )}
          {maps.map((m) => {
            const id = mapId(m);
            const active = id === activeMapId;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setActiveMap(id)}
                className={`mb-1 w-full rounded-sm border px-2 py-1.5 text-left transition-colors ${
                  active
                    ? "border-mem-accent/60 bg-mem-accent/10"
                    : "border-transparent hover:border-mem-line hover:bg-mem-bg"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className={`truncate font-mono text-xs ${active ? "text-mem-accent" : "text-mem-text"}`}>
                    {m.name || "anon"}
                  </span>
                  <ProtBadge prot={m.protStr} />
                </div>
                <div className="mt-0.5 flex items-center justify-between font-mono text-[10px] text-mem-muted">
                  <span>{addrToHex(m.base)}</span>
                  <span>{formatSize(m.size)}</span>
                </div>
              </button>
            );
          })}
        </div>
      </ExpandableSection>


      <SectionHeader icon={<Boxes className="h-3 w-3" />} label="TOOLS" />
      <div className="grid grid-cols-2 gap-1 border-t border-mem-line px-2 py-2">
        {["Scanner", "Memory", "AOB", "Pointer", "Debugger", "Trainer", "Patch", "K-Log"].map((t) => (
          <button
            key={t}
            type="button"
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1.5 text-left font-mono text-[10px] text-mem-muted hover:border-mem-accent/60 hover:text-mem-accent"
          >
            {t}
          </button>
        ))}
      </div>
    </aside>
  );
}

function formatSize(bytes: bigint): string {
  const n = Number(bytes);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function SectionHeader({
  icon,
  label,
  right,
}: {
  icon: React.ReactNode;
  label: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-1.5 border-b border-mem-line bg-mem-bg/60 px-3 py-2">
      <span className="text-mem-muted">{icon}</span>
      <span className="font-mono text-[10px] font-semibold tracking-widest text-mem-muted">
        {label}
      </span>
      <div className="ml-auto">{right}</div>
    </div>
  );
}

function ProtBadge({ prot }: { prot: string }) {
  return (
    <span className="ml-2 font-mono text-[9px] tracking-wider">
      {prot.split("").map((c, i) => {
        const on = c !== "-";
        const color = !on
          ? "text-mem-line"
          : c === "r"
          ? "text-mem-accent"
          : c === "w"
          ? "text-mem-warn"
          : "text-mem-danger";
        return (
          <span key={i} className={color}>
            {on ? c.toUpperCase() : "·"}
          </span>
        );
      })}
    </span>
  );
}

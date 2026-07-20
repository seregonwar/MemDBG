import { useSession, type TrainerEntry, type WatchEntry } from "@/store/session";
import { valueTypeLabel } from "@/lib/protocol";
import { Lock, LockOpen, Pencil, Trash2 } from "lucide-react";
import { useState } from "react";
import { ExpandableSection } from "./ExpandableSection";


export function RightPanel() {
  const trainer = useSession((s) => s.trainer);
  const watch = useSession((s) => s.watch);
  const conn = useSession((s) => s.conn);
  const hello = useSession((s) => s.hello);
  const toggleLock = useSession((s) => s.toggleTrainerLock);
  const removeTrainer = useSession((s) => s.removeTrainer);
  const editTrainer = useSession((s) => s.editTrainer);

  const linkLabel = conn.kind === "online" ? "ONLINE" : "OFFLINE";

  return (
    <aside className="flex h-full w-[340px] shrink-0 flex-col border-l border-mem-line bg-mem-panel">
      <ExpandableSection title="Trainer" className="max-h-[45%] border-b border-mem-line">
        <Header title="TRAINER" count={trainer.length} />
        <div className="min-h-0 flex-1 overflow-y-auto">
          {trainer.length === 0 && (
            <div className="px-3 py-6 text-center font-mono text-[11px] text-mem-muted">
              No entries. Use <span className="text-mem-accent">+</span> on any result.
            </div>
          )}
          {trainer.map((t) => (
            <TrainerRow
              key={t.id}
              entry={t}
              onLock={() => toggleLock(t.id)}
              onRemove={() => removeTrainer(t.id)}
              onEdit={(patch) => editTrainer(t.id, patch)}
            />
          ))}
        </div>
      </ExpandableSection>

      <ExpandableSection title="Monitor" className="flex-1">
        <Header title="MONITOR" count={watch.length} />
        <div className="min-h-0 flex-1 overflow-y-auto">
          {watch.length === 0 && (
            <div className="px-3 py-4 text-center font-mono text-[11px] text-mem-muted">
              No watches yet — click the eye icon on a result.
            </div>
          )}
          {watch.map((w) => (
            <WatchRow key={w.id} entry={w} />
          ))}
        </div>
      </ExpandableSection>

      <div className="shrink-0">
        <Header title="TELEMETRY" />
        <div className="grid grid-cols-2 gap-2 border-b border-mem-line p-3 font-mono text-[10px]">
          <Stat label="Link" value={linkLabel} />
          <Stat label="Console" value={hello?.name || "—"} />
          <Stat label="Version" value={hello?.version || "—"} />
          <Stat label="Debug port" value={hello ? String(hello.debugPort) : "—"} />
        </div>
      </div>

      <UdpTail />
    </aside>
  );
}


function Header({ title, count }: { title: string; count?: number }) {
  return (
    <div className="flex items-center justify-between border-b border-mem-line bg-mem-bg/60 px-3 py-1.5">
      <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-mem-muted">
        {title}
      </span>
      {count !== undefined && (
        <span className="font-mono text-[10px] text-mem-muted">{count}</span>
      )}
    </div>
  );
}

function TrainerRow({
  entry,
  onLock,
  onRemove,
  onEdit,
}: {
  entry: TrainerEntry;
  onLock: () => void;
  onRemove: () => void;
  onEdit: (patch: Partial<TrainerEntry>) => void;
}) {
  const [editing, setEditing] = useState(false);
  return (
    <div className={`border-b border-mem-line/70 px-3 py-2 ${entry.locked ? "bg-mem-accent/[0.04]" : ""}`}>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onLock}
          aria-label={entry.locked ? "Unlock" : "Lock"}
          className={`flex h-6 w-6 items-center justify-center rounded-sm border ${
            entry.locked
              ? "border-mem-accent bg-mem-accent/10 text-mem-accent"
              : "border-mem-line text-mem-muted hover:border-mem-accent hover:text-mem-accent"
          }`}
        >
          {entry.locked ? <Lock className="h-3 w-3" /> : <LockOpen className="h-3 w-3" />}
        </button>
        {editing ? (
          <input
            autoFocus
            defaultValue={entry.label}
            onBlur={(e) => {
              onEdit({ label: e.target.value });
              setEditing(false);
            }}
            onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
            className="min-w-0 flex-1 rounded-sm border border-mem-accent bg-mem-bg px-1.5 py-0.5 font-mono text-xs text-mem-text outline-none"
          />
        ) : (
          <button
            type="button"
            onClick={() => setEditing(true)}
            className="min-w-0 flex-1 truncate text-left font-mono text-xs text-mem-text hover:text-mem-accent"
          >
            {entry.label}
          </button>
        )}
        <button
          type="button"
          aria-label="Rename"
          onClick={() => setEditing(true)}
          className="flex h-6 w-6 items-center justify-center rounded-sm border border-mem-line text-mem-muted hover:border-mem-accent hover:text-mem-accent"
        >
          <Pencil className="h-3 w-3" />
        </button>
        <button
          type="button"
          aria-label="Remove"
          onClick={onRemove}
          className="flex h-6 w-6 items-center justify-center rounded-sm border border-mem-line text-mem-muted hover:border-mem-danger hover:text-mem-danger"
        >
          <Trash2 className="h-3 w-3" />
        </button>
      </div>
      <div className="mt-1.5 flex items-center gap-3 font-mono text-[10px] text-mem-muted">
        <span>{entry.addressHex}</span>
        <span>{valueTypeLabel(entry.type)}</span>
        <span className="ml-auto">
          val{" "}
          <input
            defaultValue={entry.value}
            onBlur={(e) => onEdit({ value: e.target.value })}
            className="w-16 rounded-sm border border-mem-line bg-mem-bg px-1 py-0.5 text-right font-mono text-[10px] text-mem-text outline-none focus:border-mem-accent"
          />
        </span>
        <span>{entry.intervalMs}ms</span>
      </div>
    </div>
  );
}

function WatchRow({ entry }: { entry: WatchEntry }) {
  const latest = entry.samples[entry.samples.length - 1];
  return (
    <div className="border-b border-mem-line/70 px-3 py-2">
      <div className="flex items-center justify-between font-mono text-[11px]">
        <span className="text-mem-text">{entry.addressHex}</span>
        <span className="text-mem-accent">
          {typeof latest === "number" ? latest.toFixed(0) : String(latest)}
        </span>
      </div>
      <Sparkline values={entry.samples} />
    </div>
  );
}

function Sparkline({ values }: { values: number[] }) {
  const w = 300;
  const h = 32;
  if (values.length < 2) return <div className="mt-1 h-8 w-full" />;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const step = w / (values.length - 1);
  const path = values
    .map((v, i) => {
      const x = i * step;
      const y = h - ((v - min) / range) * (h - 4) - 2;
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const areaPath = `${path} L${w},${h} L0,${h} Z`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="mt-1 h-8 w-full" preserveAspectRatio="none">
      <path d={areaPath} fill="var(--color-mem-accent)" fillOpacity="0.08" />
      <path d={path} fill="none" stroke="var(--color-mem-accent)" strokeWidth="1.2" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1.5">
      <div className="text-[9px] uppercase tracking-widest text-mem-muted">{label}</div>
      <div className="mt-0.5 truncate text-mem-text">{value}</div>
    </div>
  );
}

function UdpTail() {
  const logs = useSession((s) => s.logs);
  const tail = logs.slice(-200).reverse();
  return (
    <ExpandableSection title="Event log" className="shrink-0 border-t border-mem-line">
      <Header title="EVENT LOG" />
      <div className="max-h-[140px] overflow-y-auto px-3 py-2 font-mono text-[10px] leading-5">
        {tail.slice(0, 6).map((l) => (
          <div key={l.id} className="flex gap-2">
            <span className="text-mem-muted">
              {new Date(l.t).toLocaleTimeString(undefined, { hour12: false })}
            </span>
            <span
              className={
                l.level === "error"
                  ? "text-mem-danger"
                  : l.level === "warn"
                  ? "text-mem-warn"
                  : l.level === "debug"
                  ? "text-mem-muted"
                  : "text-mem-accent"
              }
            >
              {l.level.toUpperCase()}
            </span>
            <span className="truncate text-mem-text">{l.msg}</span>
          </div>
        ))}
      </div>
    </ExpandableSection>
  );
}

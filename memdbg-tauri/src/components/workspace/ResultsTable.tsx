import { useSession, type ScanResultRow } from "@/store/session";
import { valueTypeLabel } from "@/lib/protocol";
import { Eye, Lock, LockOpen, Pencil, Plus, Target } from "lucide-react";
import { useState } from "react";

export function ResultsTable() {
  const results = useSession((s) => s.results);
  const toggleFreeze = useSession((s) => s.toggleFreeze);
  const editResultValue = useSession((s) => s.editResultValue);
  const addToTrainer = useSession((s) => s.addToTrainer);
  const addToWatch = useSession((s) => s.addToWatch);
  const setActiveAddress = useSession((s) => s.setActiveAddress);
  const activeAddress = useSession((s) => s.activeAddress);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center justify-between border-b border-mem-line bg-mem-bg/60 px-3 py-1.5">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-mem-muted">
          Results · {results.length}
        </span>
        <span className="font-mono text-[10px] text-mem-muted">
          click row → inspect · pencil → write · + → trainer · eye → watch
        </span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {results.length === 0 ? (
          <div className="flex h-full items-center justify-center px-6 py-10 text-center font-mono text-[11px] text-mem-muted">
            No results. Attach to a process, choose a mode + type, and run a scan.
          </div>
        ) : (
          <table className="w-full font-mono text-xs">
            <thead className="sticky top-0 z-10 bg-mem-panel text-mem-muted">
              <tr className="border-b border-mem-line">
                <Th className="w-8"> </Th>
                <Th>Address</Th>
                <Th>Region</Th>
                <Th className="w-14">Type</Th>
                <Th>Value</Th>
                <Th>Previous</Th>
                <Th className="w-32 text-right pr-3">Actions</Th>
              </tr>
            </thead>
            <tbody>
              {results.map((r) => (
                <Row
                  key={r.id}
                  r={r}
                  active={activeAddress === r.address}
                  onSelect={() => setActiveAddress(r.address)}
                  onFreeze={() => toggleFreeze(r.id)}
                  onWrite={(v) => editResultValue(r.id, v)}
                  onTrainer={() => addToTrainer(r.id)}
                  onWatch={() => addToWatch(r.id)}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <th className={`px-3 py-1.5 text-left text-[10px] font-semibold uppercase tracking-widest ${className}`}>
      {children}
    </th>
  );
}

function Row({
  r,
  active,
  onSelect,
  onFreeze,
  onWrite,
  onTrainer,
  onWatch,
}: {
  r: ScanResultRow;
  active: boolean;
  onSelect: () => void;
  onFreeze: () => void;
  onWrite: (v: string) => void;
  onTrainer: () => void;
  onWatch: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<string>(r.value);
  const changed = r.value !== r.previous;

  return (
    <tr
      onClick={onSelect}
      className={`cursor-pointer border-b border-mem-line/60 transition-colors ${
        active ? "bg-mem-accent/5" : "hover:bg-mem-bg/60"
      }`}
    >
      <td className="pl-3">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onFreeze();
          }}
          className={`flex h-6 w-6 items-center justify-center rounded-sm border ${
            r.frozen
              ? "border-mem-danger/60 bg-mem-danger/10 text-mem-danger"
              : "border-mem-line text-mem-muted hover:border-mem-accent hover:text-mem-accent"
          }`}
          aria-label={r.frozen ? "Unfreeze" : "Freeze"}
        >
          {r.frozen ? <Lock className="h-3 w-3" /> : <LockOpen className="h-3 w-3" />}
        </button>
      </td>
      <td className="px-3 py-1.5 text-mem-text">{r.addressHex}</td>
      <td className="px-3 py-1.5 text-mem-muted">{r.region}</td>
      <td className="px-3 py-1.5 text-mem-muted">{valueTypeLabel(r.type)}</td>
      <td className="px-3 py-1.5">
        {editing ? (
          <input
            autoFocus
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onBlur={() => {
              setEditing(false);
              onWrite(draft);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") (e.target as HTMLInputElement).blur();
              if (e.key === "Escape") setEditing(false);
            }}
            className="w-28 rounded-sm border border-mem-accent bg-mem-bg px-1.5 py-0.5 font-mono text-xs text-mem-text outline-none"
          />
        ) : (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setDraft(r.value);
              setEditing(true);
            }}
            className={`rounded-sm px-1 ${changed ? "text-mem-accent" : "text-mem-text"} hover:bg-mem-bg`}
          >
            {r.value}
          </button>
        )}
      </td>
      <td className="px-3 py-1.5 text-mem-muted">{r.previous}</td>
      <td className="px-3 py-1.5 pr-3">
        <div className="flex justify-end gap-1">
          <IconBtn label="Edit" onClick={() => { setDraft(r.value); setEditing(true); }}>
            <Pencil className="h-3 w-3" />
          </IconBtn>
          <IconBtn label="Watch" onClick={onWatch}>
            <Eye className="h-3 w-3" />
          </IconBtn>
          <IconBtn label="Inspect" onClick={onSelect}>
            <Target className="h-3 w-3" />
          </IconBtn>
          <IconBtn label="Add to trainer" onClick={onTrainer} accent>
            <Plus className="h-3 w-3" />
          </IconBtn>
        </div>
      </td>
    </tr>
  );
}

function IconBtn({
  children,
  onClick,
  label,
  accent,
}: {
  children: React.ReactNode;
  onClick: () => void;
  label: string;
  accent?: boolean;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      className={`flex h-6 w-6 items-center justify-center rounded-sm border ${
        accent
          ? "border-mem-accent/60 text-mem-accent hover:bg-mem-accent/15"
          : "border-mem-line text-mem-muted hover:border-mem-accent hover:text-mem-accent"
      }`}
    >
      {children}
    </button>
  );
}

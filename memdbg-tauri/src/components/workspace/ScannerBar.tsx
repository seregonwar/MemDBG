import { useSession, type Refinement, type ScanMode } from "@/store/session";
import { ValueType, type ValueTypeId, valueTypeLabel } from "@/lib/protocol";
import { Play, RefreshCw, Search } from "lucide-react";

const MODES: { id: ScanMode; label: string }[] = [
  { id: "exact", label: "Exact" },
  { id: "unknown", label: "Unknown" },
  { id: "range", label: "Range" },
  { id: "aob", label: "AOB" },
  { id: "pointer", label: "Pointer" },
];

const TYPES: ValueTypeId[] = [
  ValueType.U8,
  ValueType.U16,
  ValueType.U32,
  ValueType.U64,
  ValueType.F32,
  ValueType.F64,
  ValueType.POINTER,
  ValueType.BYTES,
];

const REFINE: { id: Refinement; label: string }[] = [
  { id: "changed", label: "Changed" },
  { id: "unchanged", label: "Unchanged" },
  { id: "increased", label: "Increased" },
  { id: "decreased", label: "Decreased" },
];

export function ScannerBar() {
  const scanMode = useSession((s) => s.scanMode);
  const scanValue = useSession((s) => s.scanValue);
  const scanType = useSession((s) => s.scanType);
  const aobPattern = useSession((s) => s.aobPattern);
  const pointerTarget = useSession((s) => s.pointerTarget);
  const scanning = useSession((s) => s.scanning);
  const attached = useSession((s) => s.attachedPid) != null;
  const setScanMode = useSession((s) => s.setScanMode);
  const setScanValue = useSession((s) => s.setScanValue);
  const setScanType = useSession((s) => s.setScanType);
  const setAobPattern = useSession((s) => s.setAobPattern);
  const setPointerTarget = useSession((s) => s.setPointerTarget);
  const runScan = useSession((s) => s.runScan);
  const refine = useSession((s) => s.refine);

  return (
    <div className="border-b border-mem-line bg-mem-panel">
      <div className="flex items-center gap-1 border-b border-mem-line px-3 py-1.5">
        {MODES.map((m) => (
          <button
            key={m.id}
            type="button"
            onClick={() => setScanMode(m.id)}
            className={`rounded-sm border px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors ${
              scanMode === m.id
                ? "border-mem-accent bg-mem-accent/10 text-mem-accent"
                : "border-transparent text-mem-muted hover:text-mem-text"
            }`}
          >
            {m.label}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <span className="font-mono text-[10px] text-mem-muted">TYPE</span>
          <select
            value={scanType}
            onChange={(e) => setScanType(Number(e.target.value) as ValueTypeId)}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[11px] text-mem-text outline-none focus:border-mem-accent"
          >
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {valueTypeLabel(t)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="flex items-center gap-2 px-3 py-2">
        <Search className="h-3.5 w-3.5 text-mem-muted" />
        {scanMode === "aob" ? (
          <input
            value={aobPattern}
            onChange={(e) => setAobPattern(e.target.value)}
            placeholder="48 8B 05 ?? ?? ?? ?? 48 89 44 24"
            className="flex-1 rounded-sm border border-mem-line bg-mem-bg px-2.5 py-1.5 font-mono text-xs text-mem-text placeholder:text-mem-muted/60 outline-none focus:border-mem-accent"
          />
        ) : scanMode === "pointer" ? (
          <input
            value={pointerTarget}
            onChange={(e) => setPointerTarget(e.target.value)}
            placeholder="target address, e.g. 0x40C138A0"
            className="flex-1 rounded-sm border border-mem-line bg-mem-bg px-2.5 py-1.5 font-mono text-xs text-mem-text placeholder:text-mem-muted/60 outline-none focus:border-mem-accent"
          />
        ) : scanMode === "unknown" ? (
          <div className="flex-1 rounded-sm border border-dashed border-mem-line bg-mem-bg/40 px-2.5 py-1.5 font-mono text-[11px] text-mem-muted">
            Unknown initial value — capture snapshot, then refine
          </div>
        ) : (
          <input
            value={scanValue}
            onChange={(e) => setScanValue(e.target.value)}
            placeholder={scanMode === "range" ? "min .. max" : "value"}
            className="flex-1 rounded-sm border border-mem-line bg-mem-bg px-2.5 py-1.5 font-mono text-xs text-mem-text placeholder:text-mem-muted/60 outline-none focus:border-mem-accent"
          />
        )}

        <button
          type="button"
          disabled={!attached || scanning}
          onClick={() => runScan()}
          className="flex items-center gap-1.5 rounded-sm border border-mem-accent bg-mem-accent/15 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-mem-accent hover:bg-mem-accent/25 disabled:opacity-50"
        >
          <Play className="h-3 w-3" />
          {scanning ? "scanning…" : "Scan"}
        </button>
      </div>

      <div className="flex items-center gap-1 border-t border-mem-line px-3 py-1.5">
        <RefreshCw className="mr-1 h-3 w-3 text-mem-muted" />
        <span className="mr-2 font-mono text-[10px] uppercase tracking-widest text-mem-muted">
          Refine
        </span>
        {REFINE.map((r) => (
          <button
            key={r.id}
            type="button"
            disabled={!attached}
            onClick={() => refine(r.id)}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] text-mem-muted hover:border-mem-accent/60 hover:text-mem-accent disabled:opacity-50"
          >
            {r.label}
          </button>
        ))}
      </div>
    </div>
  );
}

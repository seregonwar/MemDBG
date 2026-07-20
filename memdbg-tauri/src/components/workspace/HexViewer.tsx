import { useSession } from "@/store/session";
import { addrToHex } from "@/lib/protocol";
import { useState } from "react";

export function HexViewer() {
  const bytes = useSession((s) => s.hexBytes);
  const base = useSession((s) => s.hexBase);
  const activeAddress = useSession((s) => s.activeAddress);
  const hexLoading = useSession((s) => s.hexLoading);
  const attached = useSession((s) => s.attachedPid) != null;
  const setActiveAddress = useSession((s) => s.setActiveAddress);
  const patchByte = useSession((s) => s.patchByte);
  const refreshHex = useSession((s) => s.refreshHex);

  const [selected, setSelected] = useState<number | null>(null);
  const [editing, setEditing] = useState<number | null>(null);

  const rows: number[][] = [];
  for (let i = 0; i < bytes.length; i += 16) rows.push(Array.from(bytes.slice(i, i + 16)));

  const step = (delta: bigint) => {
    if (activeAddress == null) return;
    setActiveAddress(activeAddress + delta);
  };

  return (
    <div className="flex min-h-0 flex-col border-t border-mem-line bg-mem-panel">
      <div className="flex items-center justify-between border-b border-mem-line bg-mem-bg/60 px-3 py-1.5">
        <div className="flex items-center gap-3">
          <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-mem-muted">
            Hex Viewer
          </span>
          <span className="font-mono text-xs text-mem-text">
            {activeAddress != null ? addrToHex(activeAddress) : "—"}
          </span>
          <span className="font-mono text-[10px] text-mem-muted">
            {bytes.length} B · double-click a byte to patch
          </span>
          {hexLoading && <span className="font-mono text-[10px] text-mem-accent">reading…</span>}
        </div>
        <div className="flex gap-1 font-mono text-[10px]">
          <button
            type="button"
            onClick={() => step(-0x100n)}
            disabled={!attached}
            className="rounded-sm border border-mem-line px-2 py-0.5 text-mem-muted hover:text-mem-accent disabled:opacity-40"
          >
            − 0x100
          </button>
          <button
            type="button"
            onClick={() => step(0x100n)}
            disabled={!attached}
            className="rounded-sm border border-mem-line px-2 py-0.5 text-mem-muted hover:text-mem-accent disabled:opacity-40"
          >
            + 0x100
          </button>
          <button
            type="button"
            onClick={() => refreshHex()}
            disabled={!attached}
            className="rounded-sm border border-mem-line px-2 py-0.5 text-mem-muted hover:text-mem-accent disabled:opacity-40"
          >
            reload
          </button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto px-3 py-2 font-mono text-[11px] leading-5">
        {bytes.length === 0 ? (
          <div className="flex h-full items-center justify-center text-center text-mem-muted">
            {attached ? "Select a map or address to view memory." : "Not attached."}
          </div>
        ) : (
          rows.map((row, ri) => {
            const rowAddr = base + BigInt(ri * 16);
            return (
              <div key={ri} className="flex gap-4">
                <span className="w-32 shrink-0 text-mem-muted">{addrToHex(rowAddr)}</span>
                <div className="flex gap-1">
                  {row.map((b, bi) => {
                    const idx = ri * 16 + bi;
                    const isSel = selected === idx;
                    if (editing === idx) {
                      return (
                        <input
                          key={bi}
                          autoFocus
                          maxLength={2}
                          defaultValue={b.toString(16).toUpperCase().padStart(2, "0")}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value, 16);
                            if (!Number.isNaN(n)) void patchByte(idx, n & 0xff);
                            setEditing(null);
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") (e.target as HTMLInputElement).blur();
                            if (e.key === "Escape") setEditing(null);
                          }}
                          className="w-6 rounded-sm border border-mem-accent bg-mem-bg px-0.5 text-center font-mono text-[11px] text-mem-text outline-none"
                        />
                      );
                    }
                    return (
                      <button
                        key={bi}
                        type="button"
                        onClick={() => setSelected(idx)}
                        onDoubleClick={() => setEditing(idx)}
                        className={`w-6 text-center transition-colors ${
                          isSel ? "bg-mem-accent/25 text-mem-accent" : "text-mem-text hover:bg-mem-bg"
                        }`}
                      >
                        {b.toString(16).toUpperCase().padStart(2, "0")}
                      </button>
                    );
                  })}
                </div>
                <div className="ml-2 text-mem-muted">
                  {row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·")).join("")}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

import { useMemo } from "react";
import { useSession } from "@/store/session";
import { severityName } from "@/lib/protocol";

const SEV_COLOR: Record<number, string> = {
  0: "text-mem-danger",
  1: "text-mem-danger",
  2: "text-mem-danger",
  3: "text-mem-danger",
  4: "text-yellow-300",
  5: "text-mem-accent",
  6: "text-mem-text",
  7: "text-mem-muted",
};

export function KernelLogPanel() {
  const klog = useSession((s) => s.klog);
  const clear = useSession((s) => s.klogClear);
  const setFilter = useSession((s) => s.klogSetFilter);

  const filtered = useMemo(() => {
    const q = klog.filter.trim().toLowerCase();
    return klog.lines.filter((l) => {
      if (l.severity > klog.minSeverity) return false;
      if (q && !l.message.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [klog.lines, klog.filter, klog.minSeverity]);

  return (
    <section className="flex min-h-0 flex-1 flex-col">
      <header className="flex flex-wrap items-center gap-2 border-b border-mem-line bg-mem-panel px-3 py-2">
        <span className="font-mono text-[10px] uppercase tracking-widest text-mem-muted">
          Kernel Log
        </span>
        <span className="font-mono text-[11px] text-mem-text">
          {klog.streaming ? (
            <span className="text-mem-accent">● streaming</span>
          ) : (
            <span className="text-mem-muted">idle</span>
          )}
        </span>
        <span className="font-mono text-[10px] text-mem-muted">{filtered.length} lines</span>

        <div className="ml-auto flex items-center gap-2">
          <input
            placeholder="filter…"
            value={klog.filter}
            onChange={(e) => setFilter({ filter: e.target.value })}
            className="w-48 rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] text-mem-text"
          />
          <select
            value={klog.minSeverity}
            onChange={(e) => setFilter({ minSeverity: Number(e.target.value) })}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] text-mem-text"
          >
            {[0, 1, 2, 3, 4, 5, 6, 7].map((s) => (
              <option key={s} value={s}>
                ≤ {severityName(s)}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => setFilter({ paused: !klog.paused })}
            className={`rounded-sm border px-2 py-1 font-mono text-[10px] uppercase tracking-wider ${
              klog.paused
                ? "border-yellow-400/60 bg-yellow-400/10 text-yellow-300"
                : "border-mem-line bg-mem-bg text-mem-muted hover:text-mem-text"
            }`}
          >
            {klog.paused ? "paused" : "pause"}
          </button>
          <button
            type="button"
            onClick={clear}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] text-mem-muted hover:text-mem-text"
          >
            clear
          </button>
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-auto bg-mem-bg">
        {filtered.length === 0 ? (
          <div className="p-8 text-center font-mono text-[11px] text-mem-muted">
            no kernel messages
          </div>
        ) : (
          <ul className="divide-y divide-mem-line/30 font-mono text-[11px] leading-relaxed">
            {filtered
              .slice()
              .reverse()
              .slice(0, 1000)
              .map((l, i) => (
                <li key={i} className="flex gap-3 px-3 py-0.5 hover:bg-mem-line/20">
                  <span className="w-24 shrink-0 text-mem-muted">
                    {(Number(l.timestamp) / 1_000_000).toFixed(3)}
                  </span>
                  <span className={`w-14 shrink-0 uppercase ${SEV_COLOR[l.severity] ?? ""}`}>
                    {severityName(l.severity)}
                  </span>
                  <span className="w-10 shrink-0 text-mem-muted">c{l.cpu}</span>
                  <span className="min-w-0 flex-1 whitespace-pre-wrap break-words text-mem-text">
                    {l.message}
                  </span>
                </li>
              ))}
          </ul>
        )}
      </div>
    </section>
  );
}

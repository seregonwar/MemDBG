import { useEffect, useMemo } from "react";
import { useSession } from "@/store/session";
import { tracerEventKindName } from "@/lib/protocol";

export function TracerPanel() {
  const tracer = useSession((s) => s.tracer);
  const attachedPid = useSession((s) => s.attachedPid);
  const tracerAttach = useSession((s) => s.tracerAttach);
  const tracerDetach = useSession((s) => s.tracerDetach);
  const tracerClear = useSession((s) => s.tracerClear);
  const tracerRefreshStatus = useSession((s) => s.tracerRefreshStatus);
  const tracerSetFilter = useSession((s) => s.tracerSetFilter);

  useEffect(() => {
    if (!tracer.attached) return;
    const t = setInterval(() => void tracerRefreshStatus(), 2000);
    return () => clearInterval(t);
  }, [tracer.attached, tracerRefreshStatus]);

  const filtered = useMemo(() => {
    return tracer.events.filter((e) => {
      if (tracer.filterKind !== null && e.kind !== tracer.filterKind) return false;
      if (tracer.filterTid !== null && e.tid !== tracer.filterTid) return false;
      return true;
    });
  }, [tracer.events, tracer.filterKind, tracer.filterTid]);

  return (
    <section className="flex min-h-0 flex-1 flex-col">
      <header className="flex flex-wrap items-center gap-2 border-b border-mem-line bg-mem-panel px-3 py-2">
        <span className="font-mono text-[10px] uppercase tracking-widest text-mem-muted">
          Tracer
        </span>
        <span className="font-mono text-[11px] text-mem-text">
          {tracer.attached ? (
            <>
              <span className="text-mem-accent">● attached</span>{" "}
              <span className="text-mem-muted">pid {tracer.pid}</span>
            </>
          ) : (
            <span className="text-mem-muted">not attached</span>
          )}
        </span>
        <span className="font-mono text-[10px] text-mem-muted">
          seen {tracer.eventsSeen} · dropped {tracer.dropped}
        </span>

        <div className="ml-auto flex items-center gap-2">
          <select
            value={tracer.filterKind ?? ""}
            onChange={(e) =>
              tracerSetFilter({ kind: e.target.value === "" ? null : Number(e.target.value) })
            }
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] text-mem-text"
          >
            <option value="">all kinds</option>
            {[0, 1, 2, 3, 4, 5, 6].map((k) => (
              <option key={k} value={k}>
                {tracerEventKindName(k)}
              </option>
            ))}
          </select>
          <input
            placeholder="tid"
            value={tracer.filterTid ?? ""}
            onChange={(e) =>
              tracerSetFilter({
                tid: e.target.value === "" ? null : Number(e.target.value) || null,
              })
            }
            className="w-16 rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] text-mem-text"
          />
          <button
            type="button"
            onClick={tracerClear}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] text-mem-muted hover:text-mem-text"
          >
            clear
          </button>
          {tracer.attached ? (
            <button
              type="button"
              onClick={() => void tracerDetach()}
              className="rounded-sm border border-mem-danger/50 bg-mem-danger/10 px-2 py-1 font-mono text-[10px] text-mem-danger hover:bg-mem-danger/20"
            >
              detach
            </button>
          ) : (
            <button
              type="button"
              disabled={attachedPid == null}
              onClick={() => void tracerAttach()}
              className="rounded-sm border border-mem-accent bg-mem-accent/15 px-2 py-1 font-mono text-[10px] font-semibold uppercase tracking-wider text-mem-accent hover:bg-mem-accent/25 disabled:opacity-40"
            >
              attach
            </button>
          )}
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full font-mono text-[11px]">
          <thead className="sticky top-0 bg-mem-panel">
            <tr className="text-left text-[10px] uppercase tracking-widest text-mem-muted">
              <th className="px-3 py-1.5">t</th>
              <th className="px-3 py-1.5">tid</th>
              <th className="px-3 py-1.5">kind</th>
              <th className="px-3 py-1.5">rip</th>
              <th className="px-3 py-1.5">target</th>
              <th className="px-3 py-1.5">extra</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-8 text-center text-mem-muted">
                  {tracer.attached ? "waiting for events…" : "tracer detached"}
                </td>
              </tr>
            )}
            {filtered
              .slice()
              .reverse()
              .slice(0, 500)
              .map((e, i) => (
                <tr
                  key={`${e.timestamp}-${i}`}
                  className="border-t border-mem-line/40 hover:bg-mem-line/20"
                >
                  <td className="px-3 py-1 text-mem-muted">
                    {(Number(e.timestamp) / 1_000_000).toFixed(3)}
                  </td>
                  <td className="px-3 py-1 text-mem-text">{e.tid}</td>
                  <td className="px-3 py-1 text-mem-accent">{tracerEventKindName(e.kind)}</td>
                  <td className="px-3 py-1 text-mem-text">{e.ripHex}</td>
                  <td className="px-3 py-1 text-mem-text">{e.targetHex}</td>
                  <td className="px-3 py-1 text-mem-muted">{e.extra.toString(16)}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

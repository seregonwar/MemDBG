import { useEffect, useMemo, useState } from "react";
import { useSession } from "@/store/session";
import { formatBytes, processStateName } from "@/lib/protocol";

export function TaskManagerPanel() {
  const taskmgr = useSession((s) => s.taskmgr);
  const attachedPid = useSession((s) => s.attachedPid);
  const attach = useSession((s) => s.attach);
  const refresh = useSession((s) => s.tmRefresh);
  const select = useSession((s) => s.tmSelect);
  const stop = useSession((s) => s.tmStop);
  const cont = useSession((s) => s.tmContinue);
  const kill = useSession((s) => s.tmKill);
  const foreground = useSession((s) => s.tmForeground);

  const [query, setQuery] = useState("");

  useEffect(() => {
    void refresh();
    void foreground();
    const t = setInterval(() => {
      void refresh();
      void foreground();
    }, 3000);
    return () => clearInterval(t);
  }, [refresh, foreground]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return taskmgr.infos.filter((p) => {
      if (!q) return true;
      return (
        p.name.toLowerCase().includes(q) ||
        String(p.pid).includes(q) ||
        p.titleId.toLowerCase().includes(q)
      );
    });
  }, [taskmgr.infos, query]);

  return (
    <section className="flex min-h-0 flex-1 flex-col">
      <header className="flex flex-wrap items-center gap-2 border-b border-mem-line bg-mem-panel px-3 py-2">
        <span className="font-mono text-[10px] uppercase tracking-widest text-mem-muted">
          Task Manager
        </span>
        <span className="font-mono text-[10px] text-mem-muted">
          {taskmgr.infos.length} processes
        </span>
        {taskmgr.foreground && (
          <span className="font-mono text-[10px] text-mem-accent">
            foreground: {taskmgr.foreground.name} ({taskmgr.foreground.pid})
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          <input
            placeholder="filter…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-48 rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] text-mem-text"
          />
          <button
            type="button"
            disabled={taskmgr.loading}
            onClick={() => void refresh()}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] text-mem-muted hover:text-mem-text disabled:opacity-40"
          >
            {taskmgr.loading ? "…" : "refresh"}
          </button>
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full font-mono text-[11px]">
          <thead className="sticky top-0 bg-mem-panel">
            <tr className="text-left text-[10px] uppercase tracking-widest text-mem-muted">
              <th className="px-3 py-1.5">pid</th>
              <th className="px-3 py-1.5">name</th>
              <th className="px-3 py-1.5">title id</th>
              <th className="px-3 py-1.5">state</th>
              <th className="px-3 py-1.5 text-right">thr</th>
              <th className="px-3 py-1.5 text-right">rss</th>
              <th className="px-3 py-1.5 text-right">vm</th>
              <th className="px-3 py-1.5 text-right">cpu%</th>
              <th className="px-3 py-1.5 text-right">actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => {
              const active = taskmgr.selectedPid === p.pid;
              return (
                <tr
                  key={p.pid}
                  onClick={() => select(p.pid)}
                  className={`cursor-pointer border-t border-mem-line/40 ${
                    active ? "bg-mem-accent/10" : "hover:bg-mem-line/20"
                  }`}
                >
                  <td className="px-3 py-1 text-mem-text">{p.pid}</td>
                  <td className="px-3 py-1 text-mem-text">
                    {p.name}
                    {attachedPid === p.pid && (
                      <span className="ml-2 rounded-sm border border-mem-accent/50 bg-mem-accent/10 px-1 text-[9px] uppercase tracking-widest text-mem-accent">
                        attached
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-1 text-mem-muted">{p.titleId || "—"}</td>
                  <td className="px-3 py-1 text-mem-muted">{processStateName(p.state)}</td>
                  <td className="px-3 py-1 text-right text-mem-text">{p.threadCount}</td>
                  <td className="px-3 py-1 text-right text-mem-text">{formatBytes(p.vmRss)}</td>
                  <td className="px-3 py-1 text-right text-mem-muted">{formatBytes(p.vmSize)}</td>
                  <td className="px-3 py-1 text-right text-mem-text">{p.cpuPercent.toFixed(1)}</td>
                  <td className="px-3 py-1 text-right">
                    <div className="inline-flex gap-1">
                      <ActBtn onClick={(e) => { e.stopPropagation(); void attach(p.pid, p.name); }}>
                        attach
                      </ActBtn>
                      {p.state === 0 ? (
                        <ActBtn onClick={(e) => { e.stopPropagation(); void stop(p.pid); }}>
                          stop
                        </ActBtn>
                      ) : (
                        <ActBtn onClick={(e) => { e.stopPropagation(); void cont(p.pid); }}>
                          cont
                        </ActBtn>
                      )}
                      <ActBtn
                        danger
                        onClick={(e) => {
                          e.stopPropagation();
                          if (confirm(`Kill pid ${p.pid} (${p.name})?`)) void kill(p.pid);
                        }}
                      >
                        kill
                      </ActBtn>
                    </div>
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={9} className="px-3 py-8 text-center text-mem-muted">
                  {taskmgr.loading ? "loading…" : "no processes"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ActBtn({
  onClick,
  children,
  danger,
}: {
  onClick: (e: React.MouseEvent) => void;
  children: React.ReactNode;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
        danger
          ? "border-mem-danger/50 bg-mem-danger/10 text-mem-danger hover:bg-mem-danger/20"
          : "border-mem-line bg-mem-bg text-mem-muted hover:text-mem-text"
      }`}
    >
      {children}
    </button>
  );
}

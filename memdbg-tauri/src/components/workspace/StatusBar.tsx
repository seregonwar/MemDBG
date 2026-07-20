import { useSession } from "@/store/session";

export function StatusBar() {
  const logs = useSession((s) => s.logs);
  const last = logs[logs.length - 1];
  const conn = useSession((s) => s.conn);
  const results = useSession((s) => s.results);
  const trainer = useSession((s) => s.trainer);
  const scanning = useSession((s) => s.scanning);

  const online = conn.kind === "online";

  return (
    <footer className="flex h-7 shrink-0 items-center gap-4 border-t border-mem-line bg-mem-panel px-3 font-mono text-[10px] text-mem-muted">
      <span className="flex items-center gap-1.5">
        <span className={`h-1.5 w-1.5 rounded-full ${online ? "bg-mem-accent" : "bg-mem-muted"}`} />
        <span>{online ? "Ready" : conn.kind}</span>
      </span>
      <span>results <span className="text-mem-text">{results.length}</span></span>
      <span>trainer <span className="text-mem-text">{trainer.length}</span></span>
      {scanning && <span className="text-mem-accent">scanning…</span>}
      <span className="ml-auto truncate">
        {last && (
          <>
            <span className="text-mem-accent">
              {new Date(last.t).toLocaleTimeString(undefined, { hour12: false })}
            </span>{" "}
            {last.msg}
          </>
        )}
      </span>
    </footer>
  );
}

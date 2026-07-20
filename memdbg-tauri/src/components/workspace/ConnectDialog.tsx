import { useSession } from "@/store/session";
import { useConsoles } from "@/store/consoles";
import { useState } from "react";
import { Star } from "lucide-react";

export function ConnectDialog({ onClose }: { onClose: () => void }) {
  const config = useSession((s) => s.config);
  const setConfig = useSession((s) => s.setConfig);
  const connect = useSession((s) => s.connect);
  const conn = useSession((s) => s.conn);
  const { consoles, add, touch, setActive } = useConsoles();

  const [host, setHost] = useState(config.host);
  const [port, setPort] = useState(String(config.port));
  const [name, setName] = useState("");
  const [save, setSave] = useState(true);

  const busy = conn.kind === "connecting" || conn.kind === "handshaking";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="w-[440px] rounded-sm border border-mem-line bg-mem-panel shadow-2xl">
        <div className="flex items-center justify-between border-b border-mem-line px-4 py-2.5">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-mem-accent">
            Connect
          </span>
          <button
            type="button"
            onClick={onClose}
            className="font-mono text-[10px] text-mem-muted hover:text-mem-text"
          >
            ESC
          </button>
        </div>

        <div className="space-y-3 px-4 py-4">
          {consoles.length > 0 && (
            <div>
              <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-mem-muted">
                Saved consoles
              </div>
              <div className="max-h-32 overflow-auto rounded-sm border border-mem-line">
                {consoles
                  .slice()
                  .sort((a, b) => Number(!!b.favorite) - Number(!!a.favorite))
                  .map((c) => (
                    <button
                      key={c.id}
                      type="button"
                      onClick={() => {
                        setHost(c.host);
                        setPort(String(c.port));
                        setName(c.name);
                        setActive(c.id);
                      }}
                      className="flex w-full items-center gap-2 px-2 py-1 text-left font-mono text-[11px] hover:bg-mem-line/30"
                    >
                      {c.favorite && <Star className="h-3 w-3 text-yellow-300" />}
                      <span className="text-mem-text">{c.name}</span>
                      <span className="text-mem-muted">
                        {c.host}:{c.port}
                      </span>
                      <span className="ml-auto text-[10px] uppercase text-mem-muted">{c.kind}</span>
                    </button>
                  ))}
              </div>
            </div>
          )}

          <div className="rounded-sm border border-mem-accent/40 bg-mem-accent/5 px-2.5 py-1.5 font-mono text-[10px] text-mem-muted">
            <span className="text-mem-accent">native transport</span> · TCP diretto via backend Rust
          </div>

          <div className="grid grid-cols-[1fr_120px] gap-2">
            <Field label="Console host" hint="IP of the target (PS4/PS5/host)">
              <input
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="192.168.1.42"
                className="w-full rounded-sm border border-mem-line bg-mem-bg px-2.5 py-1.5 font-mono text-xs text-mem-text outline-none focus:border-mem-accent"
              />
            </Field>
            <Field label="Port" hint="default 9020">
              <input
                value={port}
                onChange={(e) => setPort(e.target.value)}
                inputMode="numeric"
                className="w-full rounded-sm border border-mem-line bg-mem-bg px-2.5 py-1.5 font-mono text-xs text-mem-text outline-none focus:border-mem-accent"
              />
            </Field>
          </div>

          {conn.kind === "error" && (
            <div className="rounded-sm border border-mem-danger/50 bg-mem-danger/10 px-2 py-1.5 font-mono text-[11px] text-mem-danger">
              {conn.message}
            </div>
          )}
          {conn.kind === "closed" && (
            <div className="rounded-sm border border-mem-line bg-mem-bg/50 px-2 py-1.5 font-mono text-[11px] text-mem-muted">
              closed: {conn.reason}
            </div>
          )}

          <label className="flex items-center gap-2 pt-1 font-mono text-[10px] text-mem-muted">
            <input
              type="checkbox"
              checked={save}
              onChange={(e) => setSave(e.target.checked)}
              className="accent-mem-accent"
            />
            save as
            <input
              placeholder="console name (optional)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="flex-1 rounded-sm border border-mem-line bg-mem-bg px-2 py-1 text-mem-text"
            />
          </label>
        </div>

        <div className="flex justify-end gap-2 border-t border-mem-line px-4 py-2.5">
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm border border-mem-line bg-mem-bg px-3 py-1.5 font-mono text-[11px] text-mem-muted hover:text-mem-text"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={async () => {
              const portNum = Number(port) || 9020;
              setConfig({ host, port: portNum });
              if (save) {
                const existing = consoles.find((c) => c.host === host && c.port === portNum);
                if (existing) {
                  touch(existing.id);
                  setActive(existing.id);
                } else {
                  const entry = add({
                    name: name || `${host}:${portNum}`,
                    host,
                    port: portNum,
                    kind: "unknown",
                    lastUsedAt: Date.now(),
                  });
                  setActive(entry.id);
                }
              }
              await connect();
              onClose();
            }}
            className="rounded-sm border border-mem-accent bg-mem-accent/15 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-mem-accent hover:bg-mem-accent/25 disabled:opacity-50"
          >
            {busy ? "connecting…" : "connect"}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <div className="mb-1 flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-widest text-mem-muted">
          {label}
        </span>
        {hint && <span className="font-mono text-[10px] text-mem-muted/70">{hint}</span>}
      </div>
      {children}
    </label>
  );
}

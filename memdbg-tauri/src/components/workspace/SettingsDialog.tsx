import { usePrefs, DEFAULT_PREFS, type Preferences } from "@/store/prefs";
import { useConsoles, type ConsoleEntry } from "@/store/consoles";
import { useSession } from "@/store/session";
import { isTauriRuntime } from "@/lib/protocol/transport";
import { useState } from "react";
import { Trash2, Star, Plus } from "lucide-react";

type Tab = "consoles" | "appearance" | "behaviour" | "scanner" | "logging" | "about";

const TABS: { id: Tab; label: string }[] = [
  { id: "consoles", label: "Consoles" },
  { id: "appearance", label: "Appearance" },
  { id: "behaviour", label: "Behaviour" },
  { id: "scanner", label: "Scanner" },
  { id: "logging", label: "Logging" },
  { id: "about", label: "About" },
];

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const [tab, setTab] = useState<Tab>("consoles");
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="flex h-[560px] w-[820px] max-w-[95vw] flex-col rounded-sm border border-mem-line bg-mem-panel shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-mem-line px-4 py-2.5">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-mem-accent">
            Settings
          </span>
          <button
            type="button"
            onClick={onClose}
            className="font-mono text-[10px] text-mem-muted hover:text-mem-text"
          >
            ESC
          </button>
        </header>

        <div className="flex min-h-0 flex-1">
          <aside className="w-40 shrink-0 border-r border-mem-line bg-mem-bg/40 py-2">
            {TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className={`block w-full px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider ${
                  tab === t.id
                    ? "border-l-2 border-mem-accent bg-mem-accent/5 text-mem-accent"
                    : "border-l-2 border-transparent text-mem-muted hover:text-mem-text"
                }`}
              >
                {t.label}
              </button>
            ))}
          </aside>
          <main className="min-h-0 flex-1 overflow-auto p-4">
            {tab === "consoles" && <ConsolesTab />}
            {tab === "appearance" && <AppearanceTab />}
            {tab === "behaviour" && <BehaviourTab />}
            {tab === "scanner" && <ScannerTab />}
            {tab === "logging" && <LoggingTab />}
            {tab === "about" && <AboutTab />}
          </main>
        </div>
      </div>
    </div>
  );
}

// ─── Consoles ────────────────────────────────────────────────────────────

function ConsolesTab() {
  const { consoles, add, remove, update, toggleFavorite } = useConsoles();
  const setConfig = useSession((s) => s.setConfig);
  const connect = useSession((s) => s.connect);
  const [draft, setDraft] = useState<Omit<ConsoleEntry, "id">>({
    name: "",
    host: "",
    port: 9020,
    kind: "ps4",
  });

  return (
    <div className="space-y-4 font-mono text-[11px]">
      <div>
        <div className="mb-2 flex items-center justify-between">
          <span className="text-[10px] uppercase tracking-widest text-mem-muted">
            Registered consoles
          </span>
          <span className="text-[10px] text-mem-muted">{consoles.length}</span>
        </div>
        {consoles.length === 0 ? (
          <div className="rounded-sm border border-dashed border-mem-line px-3 py-4 text-center text-mem-muted">
            no consoles yet — register your first target below
          </div>
        ) : (
          <ul className="divide-y divide-mem-line/40 rounded-sm border border-mem-line">
            {consoles.map((c) => (
              <li key={c.id} className="flex items-center gap-2 px-3 py-2">
                <button
                  type="button"
                  onClick={() => toggleFavorite(c.id)}
                  className={c.favorite ? "text-yellow-300" : "text-mem-muted hover:text-mem-text"}
                  aria-label="favorite"
                >
                  <Star className="h-3.5 w-3.5" />
                </button>
                <div className="min-w-0 flex-1">
                  <input
                    value={c.name}
                    onChange={(e) => update(c.id, { name: e.target.value })}
                    className="w-full bg-transparent text-mem-text outline-none"
                  />
                  <div className="text-[10px] text-mem-muted">
                    {c.host}:{c.port} · {c.kind}
                  </div>
                </div>
                <select
                  value={c.kind}
                  onChange={(e) => update(c.id, { kind: e.target.value as ConsoleEntry["kind"] })}
                  className="rounded-sm border border-mem-line bg-mem-bg px-1.5 py-0.5 text-[10px]"
                >
                  <option value="ps4">ps4</option>
                  <option value="ps5">ps5</option>
                  <option value="unknown">other</option>
                </select>
                <input
                  value={c.host}
                  onChange={(e) => update(c.id, { host: e.target.value })}
                  className="w-32 rounded-sm border border-mem-line bg-mem-bg px-1.5 py-0.5 text-[10px]"
                />
                <input
                  value={c.port}
                  onChange={(e) => update(c.id, { port: Number(e.target.value) || 9020 })}
                  className="w-16 rounded-sm border border-mem-line bg-mem-bg px-1.5 py-0.5 text-[10px]"
                />
                <button
                  type="button"
                  onClick={async () => {
                    setConfig({ host: c.host, port: c.port });
                    await connect();
                  }}
                  className="rounded-sm border border-mem-accent bg-mem-accent/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-mem-accent hover:bg-mem-accent/25"
                >
                  connect
                </button>
                <button
                  type="button"
                  onClick={() => remove(c.id)}
                  className="rounded-sm border border-mem-danger/50 bg-mem-danger/10 px-1.5 py-0.5 text-mem-danger hover:bg-mem-danger/20"
                  aria-label="delete"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="rounded-sm border border-mem-line p-3">
        <div className="mb-2 text-[10px] uppercase tracking-widest text-mem-muted">
          Register new console
        </div>
        <div className="grid grid-cols-[1fr_1fr_80px_100px_auto] gap-2">
          <input
            placeholder="name"
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 text-mem-text"
          />
          <input
            placeholder="192.168.1.42"
            value={draft.host}
            onChange={(e) => setDraft({ ...draft, host: e.target.value })}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 text-mem-text"
          />
          <input
            placeholder="port"
            value={draft.port}
            onChange={(e) => setDraft({ ...draft, port: Number(e.target.value) || 9020 })}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 text-mem-text"
          />
          <select
            value={draft.kind}
            onChange={(e) => setDraft({ ...draft, kind: e.target.value as ConsoleEntry["kind"] })}
            className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 text-mem-text"
          >
            <option value="ps4">ps4</option>
            <option value="ps5">ps5</option>
            <option value="unknown">other</option>
          </select>
          <button
            type="button"
            disabled={!draft.host || !draft.name}
            onClick={() => {
              add(draft);
              setDraft({ name: "", host: "", port: 9020, kind: draft.kind });
            }}
            className="flex items-center gap-1 rounded-sm border border-mem-accent bg-mem-accent/15 px-2 py-1 font-semibold uppercase tracking-wider text-mem-accent hover:bg-mem-accent/25 disabled:opacity-40"
          >
            <Plus className="h-3 w-3" /> add
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Appearance ──────────────────────────────────────────────────────────

function AppearanceTab() {
  return (
    <div className="space-y-3">
      <Toggle prefKey="compactRails" label="Force-compact side rails" />
      <Toggle prefKey="showDebuggerStrip" label="Show debugger strip on Scanner tab" />
      <SelectPref
        prefKey="hexBytesPerRow"
        label="Hex bytes per row"
        options={[
          { value: 16, label: "16" },
          { value: 32, label: "32" },
        ]}
      />
      <SelectPref
        prefKey="fontSize"
        label="Font size"
        options={[
          { value: "sm", label: "Small" },
          { value: "md", label: "Medium" },
          { value: "lg", label: "Large" },
        ]}
      />
    </div>
  );
}

// ─── Behaviour ───────────────────────────────────────────────────────────

function BehaviourTab() {
  return (
    <div className="space-y-3">
      <Toggle prefKey="autoReconnect" label="Auto-reconnect on link drop" />
      <NumberPref prefKey="reconnectDelayMs" label="Reconnect delay (ms)" min={250} max={30000} />
      <NumberPref prefKey="telemetryPollMs" label="Telemetry poll (ms)" min={100} max={10000} />
      <NumberPref prefKey="regsPollMs" label="Registers poll (ms)" min={200} max={10000} />
      <NumberPref prefKey="klogPollMs" label="Kernel log poll (ms)" min={100} max={5000} />
      <NumberPref prefKey="tracerPollMs" label="Tracer poll (ms)" min={100} max={5000} />
    </div>
  );
}

// ─── Scanner ─────────────────────────────────────────────────────────────

function ScannerTab() {
  return (
    <div className="space-y-3">
      <SelectPref
        prefKey="defaultScanType"
        label="Default scan type"
        options={[
          { value: "u8", label: "u8" },
          { value: "u16", label: "u16" },
          { value: "u32", label: "u32" },
          { value: "u64", label: "u64" },
          { value: "f32", label: "f32" },
          { value: "f64", label: "f64" },
        ]}
      />
      <NumberPref prefKey="scanMaxHits" label="Max hits per scan" min={100} max={200000} />
    </div>
  );
}

// ─── Logging ─────────────────────────────────────────────────────────────

function LoggingTab() {
  const reset = usePrefs((s) => s.reset);
  return (
    <div className="space-y-3">
      <SelectPref
        prefKey="logLevel"
        label="Log level"
        options={[
          { value: "debug", label: "debug" },
          { value: "info", label: "info" },
          { value: "warn", label: "warn" },
          { value: "error", label: "error" },
        ]}
      />
      <NumberPref prefKey="logRetain" label="Retain last N lines" min={50} max={2000} />
      <button
        type="button"
        onClick={reset}
        className="rounded-sm border border-mem-danger/50 bg-mem-danger/10 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-mem-danger hover:bg-mem-danger/20"
      >
        Reset all preferences
      </button>
    </div>
  );
}

// ─── About ───────────────────────────────────────────────────────────────

function AboutTab() {
  return (
    <div className="space-y-3 font-mono text-[11px] text-mem-muted">
      <div>
        <span className="text-mem-text">MemDBG</span> — memory debugger workspace
      </div>
      <div>runtime: {isTauriRuntime() ? "native (Tauri)" : "web (dev)"}</div>
      <div>protocol: MDBG v2.0-web</div>
      <div>defaults: {JSON.stringify(DEFAULT_PREFS.telemetryPollMs)} ms telemetry</div>
    </div>
  );
}

// ─── Building blocks ─────────────────────────────────────────────────────

function Toggle({ prefKey, label }: { prefKey: keyof Preferences; label: string }) {
  const value = usePrefs((s) => s.prefs[prefKey]) as boolean;
  const setPref = usePrefs((s) => s.set);
  return (
    <label className="flex items-center justify-between gap-3 rounded-sm border border-mem-line bg-mem-bg/50 px-3 py-2">
      <span className="font-mono text-[11px] text-mem-text">{label}</span>
      <button
        type="button"
        onClick={() => setPref(prefKey, !value as never)}
        className={`h-4 w-8 rounded-full border transition-colors ${
          value
            ? "border-mem-accent bg-mem-accent/40"
            : "border-mem-line bg-mem-bg"
        }`}
      >
        <span
          className={`block h-3 w-3 rounded-full bg-mem-text transition-transform ${
            value ? "translate-x-4" : "translate-x-0.5"
          }`}
        />
      </button>
    </label>
  );
}

function NumberPref({
  prefKey,
  label,
  min,
  max,
}: {
  prefKey: keyof Preferences;
  label: string;
  min?: number;
  max?: number;
}) {
  const value = usePrefs((s) => s.prefs[prefKey]) as number;
  const setPref = usePrefs((s) => s.set);
  return (
    <label className="flex items-center justify-between gap-3 rounded-sm border border-mem-line bg-mem-bg/50 px-3 py-2">
      <span className="font-mono text-[11px] text-mem-text">{label}</span>
      <input
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(e) => setPref(prefKey, (Number(e.target.value) || 0) as never)}
        className="w-28 rounded-sm border border-mem-line bg-mem-bg px-2 py-1 text-right font-mono text-[11px] text-mem-text"
      />
    </label>
  );
}

function SelectPref<T extends string | number>({
  prefKey,
  label,
  options,
}: {
  prefKey: keyof Preferences;
  label: string;
  options: { value: T; label: string }[];
}) {
  const value = usePrefs((s) => s.prefs[prefKey]) as T;
  const setPref = usePrefs((s) => s.set);
  return (
    <label className="flex items-center justify-between gap-3 rounded-sm border border-mem-line bg-mem-bg/50 px-3 py-2">
      <span className="font-mono text-[11px] text-mem-text">{label}</span>
      <select
        value={String(value)}
        onChange={(e) => {
          const raw = e.target.value;
          const opt = options.find((o) => String(o.value) === raw);
          if (opt) setPref(prefKey, opt.value as never);
        }}
        className="rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[11px] text-mem-text"
      >
        {options.map((o) => (
          <option key={String(o.value)} value={String(o.value)}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

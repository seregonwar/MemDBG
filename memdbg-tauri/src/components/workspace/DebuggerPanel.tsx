import { useEffect, useState } from "react";
import { useSession } from "@/store/session";
import { addrToHex, hexToAddr, GP_REG_ORDER, type DebugRegs } from "@/lib/protocol";
import { Trash2, Plus, RefreshCw } from "lucide-react";

export function DebuggerPanel() {
  const dbg = useSession((s) => s.dbg);
  const refreshThreads = useSession((s) => s.dbgRefreshThreads);
  const refreshRegs = useSession((s) => s.dbgRefreshRegs);
  const refreshBps = useSession((s) => s.dbgRefreshBreakpoints);
  const refreshWps = useSession((s) => s.dbgRefreshWatchpoints);
  const refreshDisasm = useSession((s) => s.dbgRefreshDisasm);
  const selectThread = useSession((s) => s.dbgSelectThread);
  const suspend = useSession((s) => s.dbgSuspendThread);
  const resume = useSession((s) => s.dbgResumeThread);
  const writeReg = useSession((s) => s.dbgWriteReg);
  const addBp = useSession((s) => s.dbgAddBreakpoint);
  const clearBp = useSession((s) => s.dbgClearBreakpoint);
  const clearAllBps = useSession((s) => s.dbgClearAllBreakpoints);
  const addWp = useSession((s) => s.dbgAddWatchpoint);
  const clearWp = useSession((s) => s.dbgClearWatchpoint);
  const setAsm = useSession((s) => s.dbgSetAsmSource);
  const assemble = useSession((s) => s.dbgAssemble);
  const applyAsm = useSession((s) => s.dbgApplyAssembled);

  useEffect(() => {
    if (!dbg.attached) return;
    refreshThreads();
    const t = setInterval(() => {
      if (!useSession.getState().dbg.running) refreshRegs();
    }, 2000);
    return () => clearInterval(t);
  }, [dbg.attached, refreshThreads, refreshRegs]);

  if (!dbg.attached) {
    return (
      <div className="flex flex-1 items-center justify-center bg-mem-bg font-mono text-xs text-mem-muted">
        Debugger detached — click <span className="mx-1 text-mem-accent">attach</span> in the debug strip.
      </div>
    );
  }

  return (
    <div className="grid flex-1 grid-cols-[240px_1fr_320px] overflow-hidden bg-mem-bg font-mono text-xs">
      {/* Threads */}
      <div className="flex min-h-0 flex-col border-r border-mem-line">
        <PanelHeader label="THREADS" onRefresh={refreshThreads} count={dbg.threads.length} />
        <div className="min-h-0 flex-1 overflow-y-auto">
          {dbg.threads.map((t) => {
            const active = t.tid === dbg.selectedTid;
            return (
              <button
                key={t.tid}
                type="button"
                onClick={() => selectThread(t.tid)}
                className={`flex w-full items-center gap-2 border-b border-mem-line/60 px-2 py-1.5 text-left ${
                  active ? "bg-mem-accent/10" : "hover:bg-mem-panel"
                }`}
              >
                <div className="min-w-0 flex-1">
                  <div className={`truncate text-[11px] ${active ? "text-mem-accent" : "text-mem-text"}`}>
                    {t.name || `tid ${t.tid}`}
                  </div>
                  <div className="text-[10px] text-mem-muted">
                    TID {t.tid} · cpu {t.cpu} · prio {t.priority}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    t.state === 0 ? resume(t.tid) : suspend(t.tid);
                  }}
                  className="text-[9px] uppercase tracking-widest text-mem-muted hover:text-mem-accent"
                >
                  {t.state === 0 ? "run" : "hold"}
                </button>
              </button>
            );
          })}
          {dbg.threads.length === 0 && (
            <div className="p-4 text-center text-mem-muted">no threads</div>
          )}
        </div>
      </div>

      {/* Center: Disasm + Assembler */}
      <div className="flex min-h-0 flex-col">
        <PanelHeader
          label="DISASM"
          onRefresh={() => refreshDisasm(dbg.regs?.rip)}
          count={dbg.disasm.length}
        />
        <div className="min-h-0 flex-1 overflow-y-auto">
          {dbg.disasmLoading && <div className="p-2 text-mem-muted">disassembling…</div>}
          {!dbg.disasmLoading && dbg.disasm.length === 0 && (
            <div className="p-3 text-mem-muted">
              Enter an address in the hex viewer or click refresh to disassemble around RIP.
            </div>
          )}
          {dbg.disasm.map((ins) => {
            const isRip = dbg.regs && ins.address === dbg.regs.rip;
            return (
              <div
                key={ins.address.toString()}
                className={`grid grid-cols-[140px_180px_1fr] items-center gap-2 border-b border-mem-line/40 px-2 py-0.5 text-[11px] ${
                  isRip ? "bg-mem-accent/10 text-mem-accent" : ""
                }`}
              >
                <span className="text-mem-muted">{addrToHex(ins.address)}</span>
                <span className="truncate text-mem-muted/80">
                  {Array.from(ins.bytes).map((b) => b.toString(16).padStart(2, "0")).join(" ")}
                </span>
                <span>
                  <span className="text-mem-accent">{ins.mnemonic}</span>{" "}
                  <span className="text-mem-text">{ins.operands}</span>
                </span>
              </div>
            );
          })}
        </div>
        {/* Inline assembler */}
        <div className="border-t border-mem-line bg-mem-panel p-2">
          <div className="mb-1 flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-widest text-mem-muted">Assemble</span>
            <span className="text-[10px] text-mem-muted">
              @ {dbg.disasmBase !== 0n ? addrToHex(dbg.disasmBase) : "—"}
            </span>
            <div className="ml-auto flex gap-1">
              <button
                type="button"
                onClick={() => assemble(dbg.disasmBase)}
                className="rounded-sm border border-mem-line px-2 py-0.5 text-[10px] uppercase text-mem-muted hover:border-mem-accent hover:text-mem-accent"
              >
                encode
              </button>
              <button
                type="button"
                disabled={!dbg.asmEncoded}
                onClick={() => applyAsm(dbg.disasmBase)}
                className="rounded-sm border border-mem-accent/40 bg-mem-accent/10 px-2 py-0.5 text-[10px] uppercase text-mem-accent hover:bg-mem-accent/20 disabled:opacity-40"
              >
                write
              </button>
            </div>
          </div>
          <textarea
            value={dbg.asmSource}
            onChange={(e) => setAsm(e.target.value)}
            placeholder="mov rax, 1&#10;ret"
            className="h-16 w-full resize-none rounded-sm border border-mem-line bg-mem-bg p-1.5 text-[11px] text-mem-text outline-none focus:border-mem-accent"
          />
          {dbg.asmError && <div className="mt-1 text-mem-danger">{dbg.asmError}</div>}
          {dbg.asmEncoded && (
            <div className="mt-1 text-mem-accent">
              {Array.from(dbg.asmEncoded).map((b) => b.toString(16).padStart(2, "0")).join(" ")}
            </div>
          )}
        </div>
      </div>

      {/* Right: Regs / BPs / WPs */}
      <div className="flex min-h-0 flex-col border-l border-mem-line">
        <RegistersPanel regs={dbg.regs} onEdit={writeReg} onRefresh={refreshRegs} />
        <BreakpointsPanel
          count={dbg.breakpoints.length}
          items={dbg.breakpoints}
          onAdd={addBp}
          onClear={clearBp}
          onClearAll={clearAllBps}
          onRefresh={refreshBps}
        />
        <WatchpointsPanel
          items={dbg.watchpoints}
          onAdd={addWp}
          onClear={clearWp}
          onRefresh={refreshWps}
        />
      </div>
    </div>
  );
}

function PanelHeader({
  label,
  onRefresh,
  count,
  right,
}: {
  label: string;
  onRefresh?: () => void;
  count?: number;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-2 border-b border-mem-line bg-mem-panel px-2 py-1.5">
      <span className="text-[10px] font-semibold uppercase tracking-widest text-mem-muted">
        {label}
      </span>
      {typeof count === "number" && (
        <span className="text-[10px] text-mem-muted">· {count}</span>
      )}
      <div className="ml-auto flex items-center gap-1">
        {right}
        {onRefresh && (
          <button
            type="button"
            onClick={onRefresh}
            className="text-mem-muted hover:text-mem-accent"
            aria-label="Refresh"
          >
            <RefreshCw className="h-3 w-3" />
          </button>
        )}
      </div>
    </div>
  );
}

function RegistersPanel({
  regs,
  onEdit,
  onRefresh,
}: {
  regs: DebugRegs | null;
  onEdit: (reg: keyof DebugRegs, value: bigint) => void;
  onRefresh: () => void;
}) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <PanelHeader label="REGISTERS" onRefresh={onRefresh} />
      <div className="min-h-0 flex-1 overflow-y-auto">
        {!regs && <div className="p-3 text-mem-muted">no regs — select a thread</div>}
        {regs &&
          GP_REG_ORDER.map((r) => (
            <RegRow key={r} name={r} value={regs[r]} onCommit={(v) => onEdit(r, v)} />
          ))}
      </div>
    </div>
  );
}

function RegRow({
  name,
  value,
  onCommit,
}: {
  name: string;
  value: bigint;
  onCommit: (v: bigint) => void;
}) {
  const [text, setText] = useState(addrToHex(value));
  useEffect(() => {
    setText(addrToHex(value));
  }, [value]);
  return (
    <div className="grid grid-cols-[60px_1fr] items-center gap-2 border-b border-mem-line/40 px-2 py-1">
      <span className="text-[10px] uppercase text-mem-muted">{name}</span>
      <input
        value={text}
        onChange={(e) => setText(e.target.value)}
        onBlur={() => {            try {
              const v = hexToAddr(text);
              if (v !== value) onCommit(v as bigint);
          } catch {
            setText(addrToHex(value));
          }
        }}
        className="w-full bg-transparent text-[11px] text-mem-text outline-none focus:text-mem-accent"
      />
    </div>
  );
}

function BreakpointsPanel({
  items,
  onAdd,
  onClear,
  onClearAll,
  onRefresh,
  count,
}: {
  items: { address: bigint; addressHex: string; type: number; enabled: boolean }[];
  onAdd: (addr: bigint, hw?: boolean) => void;
  onClear: (addr: bigint, hw?: boolean) => void;
  onClearAll: () => void;
  onRefresh: () => void;
  count: number;
}) {
  const [addr, setAddr] = useState("");
  const [hw, setHw] = useState(false);
  return (
    <div className="flex min-h-0 flex-1 flex-col border-t border-mem-line">
      <PanelHeader
        label="BREAKPOINTS"
        count={count}
        onRefresh={onRefresh}
        right={
          <button
            type="button"
            onClick={onClearAll}
            className="text-[9px] uppercase text-mem-muted hover:text-mem-danger"
          >
            clear all
          </button>
        }
      />
      <div className="flex items-center gap-1 border-b border-mem-line bg-mem-panel px-2 py-1">
        <input
          value={addr}
          onChange={(e) => setAddr(e.target.value)}
          placeholder="0x..."
          className="min-w-0 flex-1 rounded-sm border border-mem-line bg-mem-bg px-1.5 py-0.5 text-[11px] outline-none focus:border-mem-accent"
        />
        <label className="flex items-center gap-1 text-[10px] text-mem-muted">
          <input type="checkbox" checked={hw} onChange={(e) => setHw(e.target.checked)} />
          hw
        </label>
        <button
          type="button"
          onClick={() => {
            try {
              onAdd(hexToAddr(addr), hw);
              setAddr("");
            } catch {
              /* noop */
            }
          }}
          className="rounded-sm border border-mem-accent/40 px-2 py-0.5 text-[10px] uppercase text-mem-accent hover:bg-mem-accent/10"
        >
          <Plus className="inline h-3 w-3" />
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {items.map((b) => (
          <div
            key={`${b.type}-${b.addressHex}`}
            className="flex items-center gap-2 border-b border-mem-line/40 px-2 py-1"
          >
            <span
              className={`text-[9px] uppercase ${b.type === 1 ? "text-mem-accent" : "text-mem-muted"}`}
            >
              {b.type === 1 ? "hw" : "sw"}
            </span>
            <span className="flex-1 text-[11px]">{b.addressHex}</span>
            <button
              type="button"
              onClick={() => onClear(b.address, b.type === 1)}
              className="text-mem-muted hover:text-mem-danger"
              aria-label="Remove"
            >
              <Trash2 className="h-3 w-3" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function WatchpointsPanel({
  items,
  onAdd,
  onClear,
  onRefresh,
}: {
  items: { address: bigint; addressHex: string; size: number; type: number; hwIndex: number }[];
  onAdd: (addr: bigint, size: number, type: number) => void;
  onClear: (addr: bigint, hwIndex: number) => void;
  onRefresh: () => void;
}) {
  const [addr, setAddr] = useState("");
  const [size, setSize] = useState(4);
  const [type, setType] = useState(1); // 1=write, 3=r/w
  return (
    <div className="flex min-h-0 flex-1 flex-col border-t border-mem-line">
      <PanelHeader label="WATCHPOINTS" count={items.length} onRefresh={onRefresh} />
      <div className="flex items-center gap-1 border-b border-mem-line bg-mem-panel px-2 py-1">
        <input
          value={addr}
          onChange={(e) => setAddr(e.target.value)}
          placeholder="0x..."
          className="min-w-0 flex-1 rounded-sm border border-mem-line bg-mem-bg px-1.5 py-0.5 text-[11px] outline-none focus:border-mem-accent"
        />
        <select
          value={size}
          onChange={(e) => setSize(Number(e.target.value))}
          className="rounded-sm border border-mem-line bg-mem-bg px-1 py-0.5 text-[10px]"
        >
          {[1, 2, 4, 8].map((s) => (
            <option key={s} value={s}>
              {s}B
            </option>
          ))}
        </select>
        <select
          value={type}
          onChange={(e) => setType(Number(e.target.value))}
          className="rounded-sm border border-mem-line bg-mem-bg px-1 py-0.5 text-[10px]"
        >
          <option value={1}>W</option>
          <option value={3}>R/W</option>
        </select>
        <button
          type="button"
          onClick={() => {
            try {
              onAdd(hexToAddr(addr), size, type);
              setAddr("");
            } catch {
              /* noop */
            }
          }}
          className="rounded-sm border border-mem-accent/40 px-2 py-0.5 text-[10px] uppercase text-mem-accent hover:bg-mem-accent/10"
        >
          <Plus className="inline h-3 w-3" />
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {items.map((w) => (
          <div
            key={`${w.hwIndex}-${w.addressHex}`}
            className="flex items-center gap-2 border-b border-mem-line/40 px-2 py-1"
          >
            <span className="text-[9px] uppercase text-mem-accent">dr{w.hwIndex}</span>
            <span className="flex-1 text-[11px]">{w.addressHex}</span>
            <span className="text-[10px] text-mem-muted">
              {w.size}B · {w.type === 3 ? "r/w" : w.type === 1 ? "w" : "x"}
            </span>
            <button
              type="button"
              onClick={() => onClear(w.address, w.hwIndex)}
              className="text-mem-muted hover:text-mem-danger"
              aria-label="Remove"
            >
              <Trash2 className="h-3 w-3" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

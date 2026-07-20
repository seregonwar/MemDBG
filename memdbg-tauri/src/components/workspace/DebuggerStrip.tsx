import { ChevronsRight, Circle, Pause, Play, Square, StepForward } from "lucide-react";
import { useSession } from "@/store/session";
import { addrToHex } from "@/lib/protocol";

export function DebuggerStrip() {
  const dbg = useSession((s) => s.dbg);
  const attached = dbg.attached;
  const running = dbg.running;
  const attach = useSession((s) => s.dbgAttach);
  const detach = useSession((s) => s.dbgDetach);
  const cont = useSession((s) => s.dbgContinue);
  const stop = useSession((s) => s.dbgStop);
  const step = useSession((s) => s.dbgStep);
  const attachedPid = useSession((s) => s.attachedPid);

  return (
    <div className="flex items-center gap-2 border-b border-mem-line bg-mem-panel px-3 py-1.5">
      <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-mem-muted">
        Debugger
      </span>
      <div className="flex items-center gap-1">
        {!attached ? (
          <button
            type="button"
            onClick={attach}
            disabled={attachedPid == null || dbg.attaching}
            className="flex h-6 items-center gap-1 rounded-sm border border-mem-line px-2 font-mono text-[10px] uppercase text-mem-muted hover:border-mem-accent hover:text-mem-accent disabled:opacity-40"
          >
            {dbg.attaching ? "attaching…" : "attach"}
          </button>
        ) : (
          <>
            <IconBtn label="Continue" disabled={running} onClick={cont}>
              <Play className="h-3 w-3" />
            </IconBtn>
            <IconBtn label="Pause" disabled={!running} onClick={stop}>
              <Pause className="h-3 w-3" />
            </IconBtn>
            <IconBtn label="Step" disabled={running} onClick={step}>
              <StepForward className="h-3 w-3" />
            </IconBtn>
            <IconBtn label="Step Into" disabled={running} onClick={step}>
              <ChevronsRight className="h-3 w-3" />
            </IconBtn>
            <IconBtn label="Detach" onClick={detach}>
              <Square className="h-3 w-3" />
            </IconBtn>
          </>
        )}
      </div>
      <div className="mx-2 h-4 w-px bg-mem-line" />
      <div className="flex items-center gap-1.5 font-mono text-[10px] text-mem-muted">
        <Circle
          className={`h-2 w-2 ${
            !attached
              ? "fill-mem-line text-mem-line"
              : running
              ? "fill-mem-accent text-mem-accent"
              : "fill-mem-warn text-mem-warn"
          }`}
        />
        <span>{!attached ? "DETACHED" : running ? "RUNNING" : "STOPPED"}</span>
      </div>
      <div className="ml-4 flex items-center gap-4 font-mono text-[10px] text-mem-muted">
        <span>RIP <span className="text-mem-text">{dbg.regs ? addrToHex(dbg.regs.rip) : "—"}</span></span>
        <span>RSP <span className="text-mem-text">{dbg.regs ? addrToHex(dbg.regs.rsp) : "—"}</span></span>
        <span>RAX <span className="text-mem-text">{dbg.regs ? addrToHex(dbg.regs.rax) : "—"}</span></span>
        <span>threads <span className="text-mem-text">{dbg.threads.length}</span></span>
        <span>bps <span className="text-mem-text">{dbg.breakpoints.length}</span></span>
        <span>wps <span className="text-mem-text">{dbg.watchpoints.length}</span></span>
      </div>
    </div>
  );
}

function IconBtn({
  label,
  onClick,
  disabled,
  children,
}: {
  label: string;
  onClick?: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      onClick={onClick}
      disabled={disabled}
      className="flex h-6 w-6 items-center justify-center rounded-sm border border-mem-line text-mem-muted hover:border-mem-accent hover:text-mem-accent disabled:opacity-30"
    >
      {children}
    </button>
  );
}

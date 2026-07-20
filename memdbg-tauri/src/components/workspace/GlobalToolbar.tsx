import { useSession } from "@/store/session";
import {
  RefreshCw,
  Unplug,
  Lock,
  Unlock,
  Eraser,
  Download,
  Upload,
  Trash2,
  Camera,
} from "lucide-react";
import { useRef } from "react";

export function GlobalToolbar() {
  const conn = useSession((s) => s.conn);
  const online = conn.kind === "online";
  const attachedPid = useSession((s) => s.attachedPid);
  const refreshProcesses = useSession((s) => s.refreshProcesses);
  const disconnect = useSession((s) => s.disconnect);
  const trainer = useSession((s) => s.trainer);
  const toggleTrainerLock = useSession((s) => s.toggleTrainerLock);
  const removeTrainer = useSession((s) => s.removeTrainer);
  const pushLog = useSession((s) => s.pushLog);

  const fileRef = useRef<HTMLInputElement>(null);

  const allFrozen = trainer.length > 0 && trainer.every((t) => t.locked);

  const freezeAll = () => {
    for (const t of trainer) if (!t.locked) toggleTrainerLock(t.id);
  };
  const unfreezeAll = () => {
    for (const t of trainer) if (t.locked) toggleTrainerLock(t.id);
  };
  const clearTrainer = () => {
    for (const t of trainer) removeTrainer(t.id);
  };

  const exportTrainer = () => {
    const data = JSON.stringify(
      trainer.map((t) => ({ ...t, address: t.address.toString() })),
      null,
      2,
    );
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `memdbg-trainer-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    pushLog(`exported ${trainer.length} trainer entries`, "info");
  };

  const importTrainer = () => fileRef.current?.click();
  const onImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const raw = await f.text();
      const items = JSON.parse(raw);
      pushLog(`imported ${Array.isArray(items) ? items.length : 0} trainer entries`, "info");
    } catch (err) {
      pushLog(`import failed: ${(err as Error).message}`, "error");
    } finally {
      e.target.value = "";
    }
  };

  const snapshot = () => {
    pushLog("snapshot: use Hex Viewer export (per-region snapshots)", "info");
  };

  return (
    <div className="flex h-9 shrink-0 items-center gap-1 border-b border-mem-line bg-mem-panel/60 px-3">
      <ToolGroup label="session">
        <ToolBtn
          icon={<RefreshCw className="h-3 w-3" />}
          label="refresh"
          disabled={!online}
          onClick={() => void refreshProcesses()}
        />
        <ToolBtn
          icon={<Unplug className="h-3 w-3" />}
          label="detach"
          disabled={!online || attachedPid == null}
          onClick={() => disconnect()}
        />
      </ToolGroup>

      <Divider />

      <ToolGroup label="trainer">
        <ToolBtn
          icon={allFrozen ? <Unlock className="h-3 w-3" /> : <Lock className="h-3 w-3" />}
          label={allFrozen ? "unfreeze all" : "freeze all"}
          disabled={trainer.length === 0}
          onClick={allFrozen ? unfreezeAll : freezeAll}
        />
        <ToolBtn
          icon={<Download className="h-3 w-3" />}
          label="export"
          disabled={trainer.length === 0}
          onClick={exportTrainer}
        />
        <ToolBtn
          icon={<Upload className="h-3 w-3" />}
          label="import"
          onClick={importTrainer}
        />
        <ToolBtn
          icon={<Eraser className="h-3 w-3" />}
          label="clear"
          disabled={trainer.length === 0}
          onClick={clearTrainer}
        />
      </ToolGroup>

      <Divider />

      <ToolGroup label="memory">
        <ToolBtn
          icon={<Camera className="h-3 w-3" />}
          label="snapshot"
          disabled={!online}
          onClick={snapshot}
        />
      </ToolGroup>

      <div className="ml-auto flex items-center gap-1">
        <ToolBtn
          icon={<Trash2 className="h-3 w-3" />}
          label="clear log"
          onClick={() => useSession.setState({ logs: [] })}
        />
      </div>

      <input
        ref={fileRef}
        type="file"
        accept="application/json"
        className="hidden"
        onChange={onImportFile}
      />
    </div>
  );
}

function ToolGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1">
      <span className="mr-1 font-mono text-[9px] uppercase tracking-widest text-mem-muted/70">
        {label}
      </span>
      {children}
    </div>
  );
}

function Divider() {
  return <div className="mx-1 h-5 w-px bg-mem-line" />;
}

function ToolBtn({
  icon,
  label,
  disabled,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className="flex items-center gap-1.5 rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-mem-muted transition-colors hover:border-mem-accent hover:text-mem-accent disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-mem-line disabled:hover:text-mem-muted"
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

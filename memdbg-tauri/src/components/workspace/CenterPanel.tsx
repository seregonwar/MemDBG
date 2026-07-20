import { useState } from "react";
import { DebuggerPanel } from "./DebuggerPanel";
import { DebuggerStrip } from "./DebuggerStrip";
import { ExpandableSection } from "./ExpandableSection";
import { HexViewer } from "./HexViewer";
import { KernelLogPanel } from "./KernelLogPanel";
import { ResultsTable } from "./ResultsTable";
import { ScannerBar } from "./ScannerBar";
import { TaskManagerPanel } from "./TaskManagerPanel";
import { TracerPanel } from "./TracerPanel";
import { usePrefs } from "@/store/prefs";

type Tab = "scanner" | "debugger" | "tracer" | "klog" | "taskmgr";

const TABS: { id: Tab; label: string }[] = [
  { id: "scanner", label: "Scanner" },
  { id: "debugger", label: "Debugger" },
  { id: "tracer", label: "Tracer" },
  { id: "klog", label: "Kernel Log" },
  { id: "taskmgr", label: "Task Manager" },
];

export function CenterPanel() {
  const [tab, setTab] = useState<Tab>("scanner");
  const showStrip = usePrefs((s) => s.prefs.showDebuggerStrip);
  return (
    <section className="flex min-w-0 min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-1 overflow-x-auto border-b border-mem-line bg-mem-panel px-2 pt-1.5">
        {TABS.map((t) => (
          <TabBtn key={t.id} active={tab === t.id} onClick={() => setTab(t.id)}>
            {t.label}
          </TabBtn>
        ))}
      </div>
      {tab === "scanner" && (
        <div className="flex min-h-0 flex-1 flex-col">
          <ScannerBar />
          <ExpandableSection title="Scan results" className="flex-1">
            <ResultsTable />
          </ExpandableSection>
          {showStrip && <DebuggerStrip />}
          <ExpandableSection title="Hex viewer" className="h-[300px] shrink-0 border-t border-mem-line">
            <HexViewer />
          </ExpandableSection>
        </div>
      )}
      {tab === "debugger" && (
        <>
          {showStrip && <DebuggerStrip />}
          <ExpandableSection title="Debugger" className="flex-1">
            <DebuggerPanel />
          </ExpandableSection>
        </>
      )}
      {tab === "tracer" && (
        <ExpandableSection title="Tracer" className="flex-1">
          <TracerPanel />
        </ExpandableSection>
      )}
      {tab === "klog" && (
        <ExpandableSection title="Kernel Log" className="flex-1">
          <KernelLogPanel />
        </ExpandableSection>
      )}
      {tab === "taskmgr" && (
        <ExpandableSection title="Task Manager" className="flex-1">
          <TaskManagerPanel />
        </ExpandableSection>
      )}
    </section>
  );
}


function TabBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`shrink-0 rounded-t-sm border-b-2 px-3 py-1.5 font-mono text-[11px] uppercase tracking-widest transition-colors ${
        active
          ? "border-mem-accent text-mem-accent"
          : "border-transparent text-mem-muted hover:text-mem-text"
      }`}
    >
      {children}
    </button>
  );
}

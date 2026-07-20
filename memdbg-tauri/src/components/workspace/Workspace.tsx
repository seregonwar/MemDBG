import { LeftRail } from "./LeftRail";
import { CenterPanel } from "./CenterPanel";
import { RightPanel } from "./RightPanel";
import { StatusBar } from "./StatusBar";
import { TopBar } from "./TopBar";
import { GlobalToolbar } from "./GlobalToolbar";
import { useViewport, MIN_USABLE_WIDTH, MIN_USABLE_HEIGHT } from "@/hooks/useViewport";
import { usePrefs } from "@/store/prefs";
import { useConsoles } from "@/store/consoles";
import { useEffect, useState } from "react";
import { X, PanelLeft, PanelRight } from "lucide-react";

export function Workspace() {
  const vp = useViewport();
  const compactPref = usePrefs((s) => s.prefs.compactRails);
  const loadPrefs = usePrefs((s) => s.load);
  const loadConsoles = useConsoles((s) => s.load);

  useEffect(() => {
    void loadPrefs();
    void loadConsoles();
  }, [loadPrefs, loadConsoles]);

  const compact = vp.compact || compactPref;
  const [leftOpen, setLeftOpen] = useState(false);
  const [rightOpen, setRightOpen] = useState(false);

  if (vp.unusable) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-mem-bg p-8 text-center font-mono text-mem-text">
        <div>
          <div className="mb-2 text-lg font-semibold text-mem-accent">Window too small</div>
          <div className="text-xs text-mem-muted">
            MemDBG needs at least {MIN_USABLE_WIDTH}×{MIN_USABLE_HEIGHT}. Current:{" "}
            {vp.width}×{vp.height}.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen w-screen min-w-[900px] flex-col overflow-hidden bg-mem-bg text-mem-text">
      <TopBar />
      <GlobalToolbar />
      {compact && (
        <div className="flex shrink-0 items-center gap-1 border-b border-mem-line bg-mem-panel px-2 py-1">
          <button
            type="button"
            onClick={() => setLeftOpen((v) => !v)}
            className="flex items-center gap-1 rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-mem-muted hover:text-mem-text"
          >
            <PanelLeft className="h-3 w-3" /> processes
          </button>
          <button
            type="button"
            onClick={() => setRightOpen((v) => !v)}
            className="ml-auto flex items-center gap-1 rounded-sm border border-mem-line bg-mem-bg px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-mem-muted hover:text-mem-text"
          >
            <PanelRight className="h-3 w-3" /> trainer / log
          </button>
        </div>
      )}
      <div className="relative flex min-h-0 flex-1">
        {!compact && <LeftRail />}
        <CenterPanel />
        {!compact && <RightPanel />}

        {compact && leftOpen && (
          <Drawer side="left" onClose={() => setLeftOpen(false)}>
            <LeftRail />
          </Drawer>
        )}
        {compact && rightOpen && (
          <Drawer side="right" onClose={() => setRightOpen(false)}>
            <RightPanel />
          </Drawer>
        )}
      </div>
      <StatusBar />
    </div>
  );
}

function Drawer({
  side,
  onClose,
  children,
}: {
  side: "left" | "right";
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="absolute inset-0 z-30 flex">
      <div className="flex-1 bg-black/50" onClick={onClose} />
      <div
        className={`absolute top-0 h-full ${side === "left" ? "left-0" : "right-0"} flex w-[320px] max-w-[90vw] flex-col bg-mem-panel shadow-2xl`}
      >
        <div className="flex items-center justify-between border-b border-mem-line px-3 py-2">
          <span className="font-mono text-[10px] uppercase tracking-widest text-mem-muted">
            {side === "left" ? "Processes / Maps" : "Trainer / Log"}
          </span>
          <button
            type="button"
            onClick={onClose}
            className="text-mem-muted hover:text-mem-text"
            aria-label="close drawer"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-auto">{children}</div>
      </div>
    </div>
  );
}

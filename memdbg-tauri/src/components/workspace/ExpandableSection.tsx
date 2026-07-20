import { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Maximize2, Minimize2, X } from "lucide-react";

/**
 * ExpandableSection
 * Wraps any panel and provides an "expand" affordance that pops the
 * children into a large centered modal overlay. State (zustand) is
 * shared so the modal view stays live.
 *
 * Layout: the wrapper is a flex column that fills its parent. When
 * expanded, an inline placeholder is shown and the real content moves
 * to a portal.
 */
export function ExpandableSection({
  title,
  children,
  className = "",
  buttonPlacement = "corner",
}: {
  title: string;
  children: ReactNode;
  className?: string;
  /** "corner" floats the button in the top-right; "inline" leaves you to place your own */
  buttonPlacement?: "corner" | "inline";
}) {
  const [expanded, setExpanded] = useState(false);

  // ESC closes
  useEffect(() => {
    if (!expanded) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setExpanded(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [expanded]);

  const cornerBtn =
    buttonPlacement === "corner" ? (
      <button
        type="button"
        onClick={() => setExpanded(true)}
        aria-label={`Expand ${title}`}
        title="Expand"
        className="absolute right-1.5 top-1.5 z-20 flex h-6 w-6 items-center justify-center rounded-sm border border-mem-line bg-mem-panel/85 text-mem-muted backdrop-blur transition-colors hover:border-mem-accent hover:text-mem-accent"
      >
        <Maximize2 className="h-3 w-3" />
      </button>
    ) : null;

  return (
    <div className={`relative flex min-h-0 flex-col ${className || "flex-1"}`}>
      {!expanded && cornerBtn}
      {!expanded && children}
      {expanded && (
        <div className="flex flex-1 items-center justify-center gap-2 bg-mem-bg font-mono text-[10px] uppercase tracking-widest text-mem-muted">
          <span>{title} — expanded</span>
          <button
            type="button"
            onClick={() => setExpanded(false)}
            className="rounded-sm border border-mem-line bg-mem-panel px-2 py-1 text-mem-text hover:border-mem-accent hover:text-mem-accent"
          >
            restore
          </button>
        </div>
      )}
      {expanded &&
        createPortal(
          <div
            className="fixed inset-0 z-[70] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm animate-in fade-in"
            role="dialog"
            aria-modal="true"
            aria-label={title}
            onClick={() => setExpanded(false)}
          >
            <div
              className="flex h-[92vh] w-[94vw] max-w-[1600px] flex-col overflow-hidden rounded-md border border-mem-line bg-mem-panel shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex shrink-0 items-center justify-between border-b border-mem-line bg-mem-bg/60 px-3 py-2">
                <span className="font-mono text-[10px] uppercase tracking-widest text-mem-muted">
                  {title}
                </span>
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => setExpanded(false)}
                    aria-label="Restore"
                    title="Restore"
                    className="flex h-6 w-6 items-center justify-center rounded-sm border border-mem-line text-mem-muted hover:border-mem-accent hover:text-mem-accent"
                  >
                    <Minimize2 className="h-3 w-3" />
                  </button>
                  <button
                    type="button"
                    onClick={() => setExpanded(false)}
                    aria-label="Close"
                    title="Close (Esc)"
                    className="flex h-6 w-6 items-center justify-center rounded-sm border border-mem-line text-mem-muted hover:border-mem-danger hover:text-mem-danger"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
              <div className="relative flex min-h-0 flex-1 flex-col">{children}</div>
            </div>
          </div>,
          document.body,
        )}
    </div>
  );
}

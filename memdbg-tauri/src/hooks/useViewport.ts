/**
 * Responsive viewport hook. Tracks window width and exposes named
 * breakpoints suitable for a desktop-tool layout.
 *
 *   width < MIN_USABLE (900)   → app is unusable, show overlay
 *   width < COMPACT (1200)     → collapse LeftRail/RightPanel into drawers
 *   width >= COMPACT           → full 3-column layout
 */
import { useEffect, useState } from "react";

export const MIN_USABLE_WIDTH = 900;
export const MIN_USABLE_HEIGHT = 640;
export const COMPACT_WIDTH = 1200;

export interface Viewport {
  width: number;
  height: number;
  compact: boolean;
  unusable: boolean;
}

function read(): Viewport {
  if (typeof window === "undefined") {
    return { width: 1600, height: 1000, compact: false, unusable: false };
  }
  const w = window.innerWidth;
  const h = window.innerHeight;
  return {
    width: w,
    height: h,
    compact: w < COMPACT_WIDTH,
    unusable: w < MIN_USABLE_WIDTH || h < MIN_USABLE_HEIGHT,
  };
}

export function useViewport(): Viewport {
  const [vp, setVp] = useState<Viewport>(read);
  useEffect(() => {
    let raf = 0;
    const handler = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => setVp(read()));
    };
    window.addEventListener("resize", handler);
    return () => {
      window.removeEventListener("resize", handler);
      cancelAnimationFrame(raf);
    };
  }, []);
  return vp;
}

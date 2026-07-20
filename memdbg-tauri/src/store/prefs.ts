/**
 * User preferences — persisted to disk.
 */
import { create } from "zustand";
import { debouncedWriter, readJson } from "@/lib/storage";

export interface Preferences {
  // UI
  compactRails: boolean;      // force-collapse left/right rails
  showDebuggerStrip: boolean;
  hexBytesPerRow: 16 | 32;
  fontSize: "sm" | "md" | "lg";

  // Behaviour
  autoReconnect: boolean;
  reconnectDelayMs: number;
  telemetryPollMs: number;
  regsPollMs: number;
  klogPollMs: number;
  tracerPollMs: number;

  // Scanner defaults
  defaultScanType: "u8" | "u16" | "u32" | "u64" | "f32" | "f64";
  scanMaxHits: number;

  // Logging
  logLevel: "debug" | "info" | "warn" | "error";
  logRetain: number;
}

export const DEFAULT_PREFS: Preferences = {
  compactRails: false,
  showDebuggerStrip: true,
  hexBytesPerRow: 16,
  fontSize: "md",

  autoReconnect: true,
  reconnectDelayMs: 2000,
  telemetryPollMs: 1000,
  regsPollMs: 2000,
  klogPollMs: 750,
  tracerPollMs: 500,

  defaultScanType: "u32",
  scanMaxHits: 5000,

  logLevel: "info",
  logRetain: 200,
};

interface State {
  prefs: Preferences;
  loaded: boolean;
  load: () => Promise<void>;
  set: <K extends keyof Preferences>(key: K, value: Preferences[K]) => void;
  reset: () => void;
}

const persist = debouncedWriter<Preferences>("preferences");

export const usePrefs = create<State>((set) => ({
  prefs: DEFAULT_PREFS,
  loaded: false,

  load: async () => {
    const data = await readJson<Preferences>("preferences", DEFAULT_PREFS);
    set({ prefs: { ...DEFAULT_PREFS, ...data }, loaded: true });
  },

  set: (key, value) =>
    set((st) => {
      const next = { ...st.prefs, [key]: value };
      persist(next);
      return { prefs: next };
    }),

  reset: () =>
    set(() => {
      persist(DEFAULT_PREFS);
      return { prefs: DEFAULT_PREFS };
    }),
}));

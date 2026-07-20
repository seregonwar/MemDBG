/**
 * Console registry — persistent list of known target consoles.
 * Backed by JSON on disk via `src/lib/storage.ts`.
 */
import { create } from "zustand";
import { debouncedWriter, readJson } from "@/lib/storage";

export type ConsoleKind = "ps4" | "ps5" | "unknown";

export interface ConsoleEntry {
  id: string;
  name: string;
  host: string;
  port: number;
  kind: ConsoleKind;
  bridgeUrl?: string;
  notes?: string;
  lastUsedAt?: number;
  favorite?: boolean;
}

interface State {
  consoles: ConsoleEntry[];
  activeId: string | null;
  loaded: boolean;

  load: () => Promise<void>;
  add: (entry: Omit<ConsoleEntry, "id">) => ConsoleEntry;
  update: (id: string, patch: Partial<ConsoleEntry>) => void;
  remove: (id: string) => void;
  setActive: (id: string | null) => void;
  touch: (id: string) => void;
  toggleFavorite: (id: string) => void;
}

const persist = debouncedWriter<{ consoles: ConsoleEntry[]; activeId: string | null }>("consoles");

const uid = () => Math.random().toString(36).slice(2, 10);

function persistState(s: Pick<State, "consoles" | "activeId">) {
  persist({ consoles: s.consoles, activeId: s.activeId });
}

export const useConsoles = create<State>((set, get) => ({
  consoles: [],
  activeId: null,
  loaded: false,

  load: async () => {
    const data = await readJson<{ consoles: ConsoleEntry[]; activeId: string | null }>(
      "consoles",
      { consoles: [], activeId: null },
    );
    set({ consoles: data.consoles ?? [], activeId: data.activeId ?? null, loaded: true });
  },

  add: (entry) => {
    const full: ConsoleEntry = { id: uid(), ...entry };
    set((st) => {
      const next = { consoles: [...st.consoles, full], activeId: st.activeId ?? full.id };
      persistState(next);
      return next;
    });
    return full;
  },

  update: (id, patch) =>
    set((st) => {
      const consoles = st.consoles.map((c) => (c.id === id ? { ...c, ...patch } : c));
      persistState({ consoles, activeId: st.activeId });
      return { consoles };
    }),

  remove: (id) =>
    set((st) => {
      const consoles = st.consoles.filter((c) => c.id !== id);
      const activeId = st.activeId === id ? consoles[0]?.id ?? null : st.activeId;
      persistState({ consoles, activeId });
      return { consoles, activeId };
    }),

  setActive: (id) =>
    set((st) => {
      persistState({ consoles: st.consoles, activeId: id });
      return { activeId: id };
    }),

  touch: (id) =>
    set((st) => {
      const consoles = st.consoles.map((c) =>
        c.id === id ? { ...c, lastUsedAt: Date.now() } : c,
      );
      persistState({ consoles, activeId: st.activeId });
      return { consoles };
    }),

  toggleFavorite: (id) => {
    const cur = get().consoles.find((c) => c.id === id);
    if (!cur) return;
    get().update(id, { favorite: !cur.favorite });
  },
}));

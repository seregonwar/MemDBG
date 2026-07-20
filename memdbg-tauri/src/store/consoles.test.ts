import { describe, it, expect, beforeEach } from "vitest";
import { useConsoles, type ConsoleEntry } from "./consoles";

describe("useConsoles store", () => {
  beforeEach(() => {
    useConsoles.setState({ consoles: [], activeId: null, loaded: true });
  });

  it("starts empty", () => {
    const state = useConsoles.getState();
    expect(state.consoles).toEqual([]);
    expect(state.activeId).toBeNull();
  });

  it("add creates an entry with an id", () => {
    const entry = useConsoles.getState().add({ name: "Test PS5", host: "192.168.1.100", port: 9020, kind: "ps5" });
    expect(entry.id).toBeTruthy();
    expect(entry.name).toBe("Test PS5");
    expect(useConsoles.getState().consoles).toHaveLength(1);
    expect(useConsoles.getState().activeId).toBe(entry.id);
  });

  it("remove deletes the entry and updates activeId", () => {
    const a = useConsoles.getState().add({ name: "A", host: "a", port: 9020, kind: "ps4" });
    const b = useConsoles.getState().add({ name: "B", host: "b", port: 9020, kind: "ps5" });

    useConsoles.getState().remove(a.id);
    const state = useConsoles.getState();
    expect(state.consoles).toHaveLength(1);
    expect(state.consoles[0].id).toBe(b.id);
    expect(state.activeId).toBe(b.id);
  });

  it("update patches an entry", () => {
    const entry = useConsoles.getState().add({ name: "Old", host: "old", port: 9020, kind: "ps4" });
    useConsoles.getState().update(entry.id, { name: "New", notes: "updated" });
    const updated = useConsoles.getState().consoles.find((c) => c.id === entry.id);
    expect(updated?.name).toBe("New");
    expect(updated?.notes).toBe("updated");
    expect(updated?.host).toBe("old"); // unchanged
  });

  it("toggleFavorite toggles the flag", () => {
    const entry = useConsoles.getState().add({ name: "Fav", host: "fav", port: 9020, kind: "ps4" });
    expect(useConsoles.getState().consoles[0].favorite).toBeFalsy();

    useConsoles.getState().toggleFavorite(entry.id);
    expect(useConsoles.getState().consoles[0].favorite).toBe(true);

    useConsoles.getState().toggleFavorite(entry.id);
    expect(useConsoles.getState().consoles[0].favorite).toBe(false);
  });
});

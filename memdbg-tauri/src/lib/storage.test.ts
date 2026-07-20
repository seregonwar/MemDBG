import { describe, it, expect, beforeEach, vi } from "vitest";
import { readJson, writeJson } from "./storage";

describe("storage (localStorage fallback)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("readJson returns fallback when no data exists", async () => {
    const result = await readJson("test-key", { default: true });
    expect(result).toEqual({ default: true });
  });

  it("writeJson + readJson round-trip", async () => {
    await writeJson("test-key", { value: 42, name: "test" });
    const result = await readJson("test-key", {});
    expect(result).toEqual({ value: 42, name: "test" });
  });

  it("readJson returns fallback on corrupt JSON", async () => {
    localStorage.setItem("mdbg.store.test-key", "{not json");
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const result = await readJson("test-key", { fallback: true });
    expect(result).toEqual({ fallback: true });
    spy.mockRestore();
  });

  it("debouncedWriter coalesces writes", async () => {
    const { debouncedWriter } = await import("./storage");

    const writer = debouncedWriter<{ count: number }>("debounce-test", 50);

    // Write multiple times rapidly
    writer({ count: 1 });
    writer({ count: 2 });
    writer({ count: 3 });

    // Should not have written yet
    expect(localStorage.getItem("mdbg.store.debounce-test")).toBeNull();

    // Wait for the debounce
    await new Promise((r) => setTimeout(r, 100));

    const stored = localStorage.getItem("mdbg.store.debounce-test");
    expect(stored).not.toBeNull();
    expect(JSON.parse(stored!)).toEqual({ count: 3 });
  });
});

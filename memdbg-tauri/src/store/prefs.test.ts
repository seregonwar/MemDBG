import { describe, it, expect, beforeEach } from "vitest";
import { usePrefs, DEFAULT_PREFS } from "./prefs";

describe("usePrefs store", () => {
  beforeEach(() => {
    usePrefs.setState({ prefs: DEFAULT_PREFS, loaded: true });
  });

  it("initializes with defaults", () => {
    const state = usePrefs.getState();
    expect(state.prefs).toEqual(DEFAULT_PREFS);
    expect(state.loaded).toBe(true);
  });

  it("set updates a single preference", () => {
    usePrefs.getState().set("autoReconnect", false);
    expect(usePrefs.getState().prefs.autoReconnect).toBe(false);
    // Other prefs unchanged
    expect(usePrefs.getState().prefs.hexBytesPerRow).toBe(DEFAULT_PREFS.hexBytesPerRow);
  });

  it("reset restores defaults", () => {
    usePrefs.getState().set("autoReconnect", false);
    usePrefs.getState().set("fontSize", "lg");
    usePrefs.getState().reset();
    expect(usePrefs.getState().prefs).toEqual(DEFAULT_PREFS);
  });
});

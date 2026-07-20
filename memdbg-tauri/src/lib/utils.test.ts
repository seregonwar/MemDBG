import { describe, it, expect } from "vitest";
import { cn } from "./utils";

describe("cn", () => {
  it("merges class names", () => {
    expect(cn("a", "b")).toBe("a b");
    expect(cn("a", undefined, "b")).toBe("a b");
    expect(cn("a", false, "b")).toBe("a b");
    expect(cn("a", null, "b")).toBe("a b");
    expect(cn("")).toBe("");
  });

  it("resolves tailwind conflicts via twMerge", () => {
    expect(cn("px-2 py-1", "px-4")).toBe("py-1 px-4");
  });
});

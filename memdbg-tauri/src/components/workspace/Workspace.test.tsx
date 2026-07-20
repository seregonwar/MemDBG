import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Workspace } from "./Workspace";

function withProviders(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

describe("Workspace", () => {
  it("renders the MemDBG logo", () => {
    withProviders(<Workspace />);
    expect(screen.getByAltText("MemDBG")).toBeInTheDocument();
  });

  it("renders the toolbar with session controls", () => {
    withProviders(<Workspace />);
    expect(screen.getByText("session")).toBeInTheDocument();
    const trainerEls = screen.getAllByText("trainer");
    expect(trainerEls.length).toBeGreaterThan(0);
  });

  it("renders the status bar showing idle state", () => {
    withProviders(<Workspace />);
    const idleEls = screen.getAllByText("idle");
    expect(idleEls.length).toBeGreaterThan(0);
  });
});

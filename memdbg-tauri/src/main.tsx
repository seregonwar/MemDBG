/**
 * main.tsx — SPA entry point for MemDBG Tauri app.
 * Mounts the TanStack Router into #root.
 */
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "@tanstack/react-router";
import { getRouter } from "./router";

// Import Tailwind CSS — Vite processes and bundles this
import "./styles.css";

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Root element #root not found in the DOM.");
}

const router = getRouter();

// Register the router type so routeTree and loaders can infer it
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

createRoot(rootElement).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [
    tsconfigPaths(),
    tailwindcss(),
    react(),
  ],
  resolve: {
    tsconfigPaths: true,
  },
  build: {
    // Target modern WebKit (Tauri) — smaller output, less polyfill bloat
    target: "es2020",
    // CSS minification with lightningcss (faster + better than default)
    cssMinify: "lightningcss",
    // Report compressed sizes during build
    reportCompressedSize: true,
    // Smaller chunk size for better caching
    chunkSizeWarningLimit: 200,
    rollupOptions: {
      output: {
        // Group vendor chunks for better caching
        manualChunks(id: string) {
          if (id.includes("node_modules/react-dom") || id.includes("node_modules/react/")) {
            return "react";
          }
          if (id.includes("node_modules/lucide-react/")) {
            return "icons";
          }
        },
      },
    },
  },
});

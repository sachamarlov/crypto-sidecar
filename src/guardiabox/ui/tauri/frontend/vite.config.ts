import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import { TanStackRouterVite } from "@tanstack/router-vite-plugin";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const TAURI_DEV_HOST = process.env.TAURI_DEV_HOST;

// https://vitejs.dev/config/
// Vite 7 strict types reject the legacy `defineConfig(async () => (...))`
// signature; we never awaited anything in the body anyway, so the
// function form is enough.
export default defineConfig(() => ({
  plugins: [
    TanStackRouterVite({ autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Vite options tailored for Tauri development
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: TAURI_DEV_HOST || false,
    hmr: TAURI_DEV_HOST
      ? { protocol: "ws", host: TAURI_DEV_HOST, port: 1421 }
      : undefined,
    watch: {
      // Tell Vite to ignore watching the Rust src
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    target: "es2022",
    sourcemap: true,
    minify: "esbuild" as const,
    // cssMinify "lightningcss" requires the optional lightningcss
    // dep + `css.transformer: "lightningcss"`; under Vite 7 strict
    // typings the literal is rejected when the dep is not installed.
    // "esbuild" is the default and adequate -- CSS payload is tiny.
    cssMinify: "esbuild" as const,
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks: {
          "react-vendor": ["react", "react-dom"],
          "tanstack": [
            "@tanstack/react-query",
            "@tanstack/react-router",
            "@tanstack/react-table",
          ],
          "three": ["three", "@react-three/fiber", "@react-three/drei"],
        },
      },
    },
  },
  envPrefix: ["VITE_", "TAURI_"],
  test: {
    globals: true,
    environment: "happy-dom",
    setupFiles: ["./src/test/setup.ts"],
    // Playwright E2E tests live under tests-e2e/ and use a different
    // runtime; vitest must skip them.
    exclude: ["**/node_modules/**", "**/dist/**", "tests-e2e/**"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "json"],
    },
  },
}));

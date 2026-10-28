import { defineConfig } from "vite";
import { tanstackStart } from "@tanstack/solid-start/plugin/vite";
import solid from "@solidjs/vite-plugin";

export default defineConfig({
  // The dashboard is for the operator only: never listen beyond loopback
  // (CLAUDE.md guardrail 4).
  server: { host: "127.0.0.1", port: 3100, strictPort: true },
  preview: { host: "127.0.0.1", port: 3100, strictPort: true },
  plugins: [tanstackStart(), solid({ ssr: true })],
});

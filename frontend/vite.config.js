import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // The string shorthand sets changeOrigin: true, which rewrites Host to
      // 127.0.0.1:5055 while the browser still sends Origin 127.0.0.1:5173.
      // The backend compares Origin against Host, so login/signup returned 403.
      // Keeping the original Host makes the dev proxy same-origin for CSRF checks.
      // AVA_PROXY_TARGET lets the end-to-end auth test point a throwaway Vite
      // instance at its own temporary backend; development defaults are unchanged.
      "/api": {
        target: process.env.AVA_PROXY_TARGET || "http://127.0.0.1:5055",
        changeOrigin: false,
      },
    },
  },
  test: { environment: "jsdom", setupFiles: ["./src/test-setup.js"] },
});

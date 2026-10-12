import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "API_");
  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      proxy: {
        "/api": env.API_PROXY_TARGET || "http://localhost:8000",
        "/health": env.API_PROXY_TARGET || "http://localhost:8000",
      },
    },
  };
});

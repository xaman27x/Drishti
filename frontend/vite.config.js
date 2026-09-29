import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/v1": "http://localhost:8080",
      "/docs": "http://localhost:8080",
      "/openapi.json": "http://localhost:8080",
      "/health": "http://localhost:8080",
      "/api": "http://localhost:8080",
    },
  },
});
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Set SERVER_URL=https://localhost:3001 if the relay is running with TLS.
const target = process.env.SERVER_URL || 'http://localhost:3001';
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target, secure: false },
      '/ws': { target, ws: true, secure: false },
    },
  },
});

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Rename Vite's static asset directory so 'public/' can hold React source
  publicDir: 'static',
  // Relative base so the built SPA works from file:// URLs or subdirectories
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    // Allow LAN access in dev mode
    host: true,
  },
});

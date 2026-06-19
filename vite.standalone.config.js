import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Standalone build configuration.
 *
 * Produces a single-bundle SPA in dist-standalone/ that works from file://
 * with no server, no build step, and no dependencies for the end-user.
 *
 * Usage:  npm run build:standalone
 */
export default defineConfig({
  plugins: [react()],
  // Static assets (logo, etc.) — same source dir as the main build
  publicDir: 'static',
  // Relative base so assets resolve from file:// or any subdirectory
  base: './',
  build: {
    outDir: 'dist-standalone',
    emptyOutDir: true,
    rollupOptions: {
      input: 'standalone/index.html',
      output: {
        // Disable code splitting so everything collapses into a single JS file.
        // This is required for file:// — browsers block ES module
        // import() across file:// origins due to CORS.
        // (Vite 8 / Rolldown replacement for the deprecated inlineDynamicImports.)
        codeSplitting: false,
      },
    },
  },
});

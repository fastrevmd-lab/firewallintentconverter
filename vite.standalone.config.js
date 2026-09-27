import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const stubPath = (name) => fileURLToPath(new URL(`./standalone/stubs/${name}`, import.meta.url));

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
  resolve: {
    alias: [
      // The standalone build has no LLM provider and no PyEZ bridge to talk
      // to; standalone/main.jsx forces deterministic mode so the real
      // modules are never called, but that's a runtime toggle, not proof the
      // networking/API-key code isn't shipped. Aliasing to inert stubs keeps
      // that code out of dist-standalone/ entirely — verified by a CI grep
      // over the built assets (see .github/workflows/ci.yml).
      // The regex must match the whole import specifier (not just a suffix)
      // since alias replacement substitutes only the matched substring —
      // an unanchored suffix match would splice the absolute stub path onto
      // the tail of the original relative specifier instead of replacing it.
      { find: /^.*llm-client\.js$/, replacement: stubPath('llm-client.stub.js') },
      { find: /^.*bridge-client\.js$/, replacement: stubPath('bridge-client.stub.js') },
    ],
  },
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

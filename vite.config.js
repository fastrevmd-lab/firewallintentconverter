import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { configDefaults } from 'vitest/config';

const SELF_RUNNING_NODE_TESTS = [
  'tests/app-mappings.test.js',
  'tests/bridge-client.test.js',
  'tests/day2-ops.test.js',
  'tests/llm-translate.test.js',
  'tests/srx-converter-apps.test.js',
  'tests/validation-engine.test.js',
];

/** Inject strict Content-Security-Policy meta tag in production builds only. */
function cspPlugin() {
  return {
    name: 'csp-meta-tag',
    transformIndexHtml(html, ctx) {
      if (ctx.server) return html; // Skip in dev — HMR needs inline scripts
      const csp = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self' https://api.anthropic.com https://api.openai.com https://generativelanguage.googleapis.com",
        "img-src 'self' data:",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ].join('; ');
      return html.replace(
        '<head>',
        `<head>\n  <meta http-equiv="Content-Security-Policy" content="${csp}" />`
      );
    },
  };
}

export default defineConfig({
  plugins: [react(), cspPlugin()],
  test: {
    exclude: [...configDefaults.exclude, ...SELF_RUNNING_NODE_TESTS],
    setupFiles: ['./tests/setup.js'],
  },
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

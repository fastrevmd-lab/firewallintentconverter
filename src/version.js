// Import attribute is required for native Node ESM (the CI self-contained suites
// run these modules under `node` directly); Vite/vitest also accept it.
import pkg from '../package.json' with { type: 'json' };

/**
 * Application version — single source of truth is package.json.
 * Stamped into the UI footer, every generated output file (set + XML), and the
 * PDF report so a given artifact can be tied back to the tool version that
 * produced it.
 * @type {string}
 */
export const APP_VERSION = pkg.version;

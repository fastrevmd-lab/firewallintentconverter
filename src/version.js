import { version } from '../package.json';

/**
 * Application version — single source of truth is package.json.
 * Stamped into the UI footer, every generated output file (set + XML), and the
 * PDF report so a given artifact can be tied back to the tool version that
 * produced it.
 * @type {string}
 */
export const APP_VERSION = version;

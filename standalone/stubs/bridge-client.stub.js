/**
 * Standalone-build stand-in for public/utils/bridge-client.js.
 *
 * The standalone bundle has no PyEZ bridge to talk to; vite.standalone.config.js
 * aliases every import of bridge-client.js to this file so the real
 * fetch/auth-header code never ships in dist-standalone/.
 */

export const BRIDGE_SETTINGS_STORAGE_KEY = 'pyez-bridge-settings';
export const OLD_BRIDGE_SETTINGS_STORAGE_KEY = 'mcp-settings';
export const BRIDGE_TOKEN_SESSION_KEY = 'pyez-bridge-token';
export const DEFAULT_BRIDGE_TIMEOUT = 30000;

function unavailable() {
  throw new Error('The PyEZ bridge is not available in the standalone build.');
}

export function normalizeBridgeUrl() {
  return '';
}

export function loadBridgeSettings() {
  return { url: '', token: '' };
}

export function saveBridgeSettings() {
  return { url: '', token: '' };
}

export function bridgeFetch() {
  return unavailable();
}

export function bridgeResponseError() {
  return new Error('The PyEZ bridge is not available in the standalone build.');
}

export function bridgeResponseJson() {
  return unavailable();
}

export function bridgeErrorMessage(error, fallback = 'Bridge operation failed.') {
  return fallback;
}

export function isBridgeResponseStatus() {
  return false;
}

export function safeBridgeLoadWarnings() {
  return [];
}

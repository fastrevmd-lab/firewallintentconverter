/** Shared, authenticated client for the local PyEZ bridge. */

import { safeJsonParse } from './safe-json.js';


export const BRIDGE_SETTINGS_STORAGE_KEY = 'pyez-bridge-settings';
export const OLD_BRIDGE_SETTINGS_STORAGE_KEY = 'mcp-settings';
export const BRIDGE_TOKEN_SESSION_KEY = 'pyez-bridge-token';
export const DEFAULT_BRIDGE_TIMEOUT = 30000;

const BRIDGE_CODE_MESSAGES = new Map([
  ['INVENTORY_UNSAFE', 'Device inventory is unsafe or invalid.'],
  ['DEVICE_IDENTITY_FAILED', 'NETCONF device identity verification failed.'],
  ['DEVICE_AUTHENTICATION_FAILED', 'NETCONF device authentication failed.'],
  ['DEVICE_CREDENTIAL_UNAVAILABLE', 'The configured device credential is unavailable.'],
  ['DEVICE_UNREACHABLE', 'The NETCONF device is unreachable.'],
  ['DEVICE_OPERATION_FAILED', 'The NETCONF device operation failed.'],
  ['UNEXPECTED_ERROR', 'An unexpected bridge error occurred.'],
]);

const BRIDGE_STATUS_MESSAGES = new Map([
  [400, 'Bridge rejected the request.'],
  [401, 'Bridge access token is missing or invalid.'],
  [403, 'This browser origin is not allowed by the bridge.'],
  [404, 'The requested bridge resource was not found.'],
  [409, 'Bridge request conflicts with the current device state.'],
  [413, 'Bridge request is too large.'],
  [429, 'Bridge request limit reached. Wait and try again.'],
  [500, 'Bridge encountered an internal error.'],
  [502, 'The bridge could not complete the device request.'],
  [503, 'The bridge service is temporarily unavailable.'],
]);

class BridgeClientError extends Error {
  constructor(message, { code = null, status = null } = {}) {
    super(message);
    this.name = 'BridgeClientError';
    this.code = code;
    this.status = status;
  }
}


/** Normalize a bridge base URL to a credential-free HTTP(S) origin. */
export function normalizeBridgeUrl(raw) {
  let value = String(raw || '').trim().replace(/\/+$/, '');
  if (!value) return '';
  if (/^https?:\/[^/]/i.test(value)) {
    value = value.replace(/^(https?:\/)/i, '$1/');
  }
  if (!/^https?:\/\//i.test(value)) value = `http://${value}`;

  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol)) return '';
    if (parsed.username || parsed.password) return '';
    if (parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
    return parsed.origin;
  } catch {
    return '';
  }
}


function readJsonStorage(storage, key) {
  try {
    const raw = storage?.getItem(key);
    return raw ? safeJsonParse(raw) : null;
  } catch {
    return null;
  }
}


/** Load the persistent bridge URL and session-scoped access token. */
export function loadBridgeSettings() {
  const persistent = typeof localStorage === 'undefined' ? null : localStorage;
  const session = typeof sessionStorage === 'undefined' ? null : sessionStorage;
  let url = '';

  const saved = readJsonStorage(persistent, BRIDGE_SETTINGS_STORAGE_KEY);
  if (saved) url = normalizeBridgeUrl(saved.url || '');

  if (!url) {
    const old = readJsonStorage(persistent, OLD_BRIDGE_SETTINGS_STORAGE_KEY);
    url = normalizeBridgeUrl(old?.url || '');
    if (url) {
      try {
        persistent?.setItem(
          BRIDGE_SETTINGS_STORAGE_KEY,
          JSON.stringify({ url }),
        );
      } catch {
        // Storage is optional; callers still receive the in-memory value.
      }
    }
  }

  let token = '';
  try {
    token = session?.getItem(BRIDGE_TOKEN_SESSION_KEY) || '';
  } catch {
    // A disabled session store behaves like a missing token.
  }
  return { url, token };
}


/** Persist the URL and retain the access token only for this browser session. */
export function saveBridgeSettings({ url, token }) {
  const normalizedUrl = normalizeBridgeUrl(url);
  const sessionToken = String(token || '');

  try {
    if (typeof localStorage !== 'undefined') {
      if (normalizedUrl) {
        localStorage.setItem(
          BRIDGE_SETTINGS_STORAGE_KEY,
          JSON.stringify({ url: normalizedUrl }),
        );
      } else {
        localStorage.removeItem(BRIDGE_SETTINGS_STORAGE_KEY);
      }
    }
  } catch {
    // The settings remain usable until the current page is closed.
  }

  try {
    if (typeof sessionStorage !== 'undefined') {
      if (sessionToken) {
        sessionStorage.setItem(BRIDGE_TOKEN_SESSION_KEY, sessionToken);
      } else {
        sessionStorage.removeItem(BRIDGE_TOKEN_SESSION_KEY);
      }
    }
  } catch {
    // Protected requests will report the unavailable token clearly.
  }

  return { url: normalizedUrl, token: sessionToken };
}


/** Fetch from the bridge with timeout and bearer authentication by default. */
export async function bridgeFetch(url, options = {}, requestOptions = {}) {
  const {
    authenticated = true,
    timeout = DEFAULT_BRIDGE_TIMEOUT,
  } = requestOptions;
  const headers = new Headers(options.headers || {});

  if (authenticated && !headers.has('Authorization')) {
    const { token } = loadBridgeSettings();
    if (!token) {
      throw new Error('Bridge access token is required. Enter it in Settings.');
    }
    headers.set('Authorization', `Bearer ${token}`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, {
      ...options,
      headers,
      signal: controller.signal,
      mode: 'cors',
    });
  } finally {
    clearTimeout(timer);
  }
}


/** Convert an unsuccessful bridge response into a locally defined Error. */
export async function bridgeResponseError(response) {
  let code = null;
  try {
    const data = await response.clone().json();
    if (
      data
      && typeof data === 'object'
      && typeof data.code === 'string'
      && BRIDGE_CODE_MESSAGES.has(data.code)
    ) {
      code = data.code;
    }
  } catch {
    // Malformed bodies fall through to a fixed status-based message.
  }
  const message = (
    (code && BRIDGE_CODE_MESSAGES.get(code))
    || BRIDGE_STATUS_MESSAGES.get(response.status)
    || 'Bridge request failed.'
  );
  return new BridgeClientError(message, { code, status: response.status });
}


/** Parse one bridge response through the shared diagnostic trust boundary. */
export async function bridgeResponseJson(response) {
  if (!response.ok) throw await bridgeResponseError(response);
  try {
    return await response.json();
  } catch {
    throw new BridgeClientError('Bridge returned an invalid JSON response.', {
      code: 'INVALID_JSON_RESPONSE',
      status: response.status,
    });
  }
}


/** Return a mapped bridge message, never an arbitrary caught Error message. */
export function bridgeErrorMessage(error, fallback = 'Bridge operation failed.') {
  return error instanceof BridgeClientError ? error.message : fallback;
}


/** Test a mapped bridge response status without trusting arbitrary errors. */
export function isBridgeResponseStatus(error, status) {
  return error instanceof BridgeClientError && error.status === status;
}


/** Keep only actionable, closed-category line-load warnings. */
export function safeBridgeLoadWarnings(warnings) {
  if (!Array.isArray(warnings)) return [];
  return warnings.flatMap((warning) => {
    if (
      !warning
      || typeof warning !== 'object'
      || !Number.isSafeInteger(warning.line)
      || warning.line < 1
      || typeof warning.code !== 'string'
      || !BRIDGE_CODE_MESSAGES.has(warning.code)
    ) {
      return [];
    }
    return [{
      line: warning.line,
      code: warning.code,
      category: BRIDGE_CODE_MESSAGES.get(warning.code),
    }];
  });
}

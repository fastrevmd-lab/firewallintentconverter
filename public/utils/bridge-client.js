/** Shared, authenticated client for the local PyEZ bridge. */

import { safeJsonParse } from './safe-json.js';


export const BRIDGE_SETTINGS_STORAGE_KEY = 'pyez-bridge-settings';
export const OLD_BRIDGE_SETTINGS_STORAGE_KEY = 'mcp-settings';
export const BRIDGE_TOKEN_SESSION_KEY = 'pyez-bridge-token';
export const DEFAULT_BRIDGE_TIMEOUT = 30000;


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


/** Convert an unsuccessful bridge response into an actionable Error. */
export async function bridgeResponseError(response) {
  const messages = {
    401: 'Bridge access token is missing or invalid.',
    403: 'This browser origin is not allowed by the bridge.',
    429: 'Bridge request limit reached. Wait and try again.',
  };
  if (messages[response.status]) {
    const error = new Error(messages[response.status]);
    error.status = response.status;
    return error;
  }

  let message = '';
  try {
    const data = await response.clone().json();
    message = typeof data?.error === 'string' ? data.error : '';
  } catch {
    // Fall through to the status-based generic message.
  }
  const error = new Error(
    message || `Bridge request failed with HTTP ${response.status}.`,
  );
  error.status = response.status;
  return error;
}

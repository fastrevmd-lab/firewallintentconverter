/** Security tests for the shared browser-to-bridge client. */

import { readFile } from 'node:fs/promises';

import {
  bridgeFetch,
  bridgeResponseError,
  loadBridgeSettings,
  normalizeBridgeUrl,
  saveBridgeSettings,
} from '../public/utils/bridge-client.js';


function makeStorage() {
  const values = new Map();
  return {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
    clear: () => values.clear(),
    snapshot: () => Object.fromEntries(values.entries()),
  };
}

global.localStorage = makeStorage();
global.sessionStorage = makeStorage();

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ✔ ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  ✘ ${name}: ${error.message}`);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function equal(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

const TOKEN = 'session-token-value-with-at-least-32-characters';

await test('normalizes only credential-free HTTP(S) bridge URLs', () => {
  equal(normalizeBridgeUrl('localhost:8830/'), 'http://localhost:8830', 'adds HTTP');
  equal(normalizeBridgeUrl('http:/localhost:8830'), 'http://localhost:8830', 'repairs slash');
  equal(normalizeBridgeUrl('https://bridge.example.test///'), 'https://bridge.example.test', 'trims slashes');
  for (const value of ['file:///tmp/bridge', 'javascript:alert(1)', 'http://user:pass@localhost:8830', 'not a url']) {
    equal(normalizeBridgeUrl(value), '', `rejects ${value}`);
  }
});

await test('stores URL persistently and token only for the browser session', () => {
  localStorage.clear();
  sessionStorage.clear();
  const saved = saveBridgeSettings({ url: 'localhost:8830/', token: TOKEN });
  equal(saved.url, 'http://localhost:8830', 'normalized return URL');
  equal(saved.token, TOKEN, 'returned token');
  equal(
    localStorage.getItem('pyez-bridge-settings'),
    JSON.stringify({ url: 'http://localhost:8830' }),
    'persistent settings contain URL only',
  );
  equal(sessionStorage.getItem('pyez-bridge-token'), TOKEN, 'session token saved');
  assert(!localStorage.getItem('pyez-bridge-settings').includes(TOKEN), 'token absent from local storage');
});

await test('loads and migrates the old bridge URL without persisting a token', () => {
  localStorage.clear();
  sessionStorage.clear();
  localStorage.setItem('mcp-settings', JSON.stringify({ url: 'http://127.0.0.1:9000' }));
  sessionStorage.setItem('pyez-bridge-token', TOKEN);
  const settings = loadBridgeSettings();
  equal(settings.url, 'http://127.0.0.1:9000', 'migrated URL');
  equal(settings.token, TOKEN, 'session token loaded');
  equal(
    localStorage.getItem('pyez-bridge-settings'),
    JSON.stringify({ url: 'http://127.0.0.1:9000' }),
    'new URL-only settings written',
  );
});

await test('adds the session bearer token and preserves caller headers', async () => {
  sessionStorage.setItem('pyez-bridge-token', TOKEN);
  let captured;
  global.fetch = async (url, options) => {
    captured = { url, options };
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  await bridgeFetch(
    'http://localhost:8830/devices',
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
  );
  equal(captured.url, 'http://localhost:8830/devices', 'request URL');
  equal(captured.options.mode, 'cors', 'CORS mode');
  equal(captured.options.headers.get('Authorization'), `Bearer ${TOKEN}`, 'bearer header');
  equal(captured.options.headers.get('Content-Type'), 'application/json', 'content header');
  assert(captured.options.signal instanceof AbortSignal, 'abort signal supplied');
});

await test('does not overwrite an explicit authorization header', async () => {
  sessionStorage.setItem('pyez-bridge-token', TOKEN);
  let authorization;
  global.fetch = async (_url, options) => {
    authorization = options.headers.get('Authorization');
    return new Response('{}', { status: 200 });
  };
  await bridgeFetch('/devices', { headers: { Authorization: 'Bearer explicit-token' } });
  equal(authorization, 'Bearer explicit-token', 'explicit header preserved');
});

await test('omits authentication only when explicitly requested', async () => {
  sessionStorage.setItem('pyez-bridge-token', TOKEN);
  let authorization;
  global.fetch = async (_url, options) => {
    authorization = options.headers.get('Authorization');
    return new Response('{}', { status: 200 });
  };
  await bridgeFetch('http://localhost:8830/health', {}, { authenticated: false });
  equal(authorization, null, 'health request has no token');
});

await test('rejects a protected request before fetch when the token is missing', async () => {
  sessionStorage.removeItem('pyez-bridge-token');
  let called = false;
  global.fetch = async () => {
    called = true;
    return new Response('{}', { status: 200 });
  };
  let message = '';
  try {
    await bridgeFetch('http://localhost:8830/devices');
  } catch (error) {
    message = error.message;
  }
  assert(message.includes('access token'), 'missing-token error is actionable');
  assert(!called, 'fetch was not called');
});

await test('maps authentication, origin, and rate-limit responses', async () => {
  const cases = [
    [401, 'Bridge access token is missing or invalid.'],
    [403, 'This browser origin is not allowed by the bridge.'],
    [429, 'Bridge request limit reached. Wait and try again.'],
  ];
  for (const [status, expected] of cases) {
    const error = await bridgeResponseError(new Response('', { status }));
    equal(error.message, expected, `status ${status}`);
  }
});

await test('uses a server JSON error for other unsuccessful responses', async () => {
  const response = new Response(JSON.stringify({ error: 'Device was not found.' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' },
  });
  const error = await bridgeResponseError(response);
  equal(error.message, 'Device was not found.', 'server error message');
});

await test('aborts a request after its configured timeout', async () => {
  sessionStorage.setItem('pyez-bridge-token', TOKEN);
  global.fetch = async (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => {
      reject(new DOMException('aborted', 'AbortError'));
    });
  });
  let name = '';
  try {
    await bridgeFetch('/devices', {}, { timeout: 5 });
  } catch (error) {
    name = error.name;
  }
  equal(name, 'AbortError', 'timeout abort error');
});

await test('all browser bridge callers use the shared authenticated client', async () => {
  const callers = {
    'public/hooks/usePush.js': 'bridgeFetch',
    'public/hooks/useDay2Ops.js': 'bridgeFetch',
    'public/components/LLMSettings.jsx': 'bridgeFetch',
    'public/components/PullModal.jsx': 'bridgeFetch',
    'public/components/SRXOutput.jsx': 'loadBridgeSettings',
    'public/components/layout/WorkflowStepper.jsx': 'loadBridgeSettings',
  };
  for (const [file, sharedHelper] of Object.entries(callers)) {
    const source = await readFile(new URL(`../${file}`, import.meta.url), 'utf8');
    assert(!/\bfetch\s*\(/.test(source), `${file} still calls raw fetch`);
    assert(source.includes(sharedHelper), `${file} does not use ${sharedHelper}`);
  }
});

console.log(`\n✔ ${passed} passed  ${failed} failed\n`);
if (failed > 0) process.exit(1);

/** Security tests for the shared browser-to-bridge client. */

import { readFile } from 'node:fs/promises';

import {
  bridgeFetch,
  bridgeResponseError,
  loadBridgeSettings,
  normalizeBridgeUrl,
  saveBridgeSettings,
} from '../public/utils/bridge-client.js';
import * as bridgeClient from '../public/utils/bridge-client.js';


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

await test('maps only recognized response codes and never remote diagnostics', async () => {
  const sentinel = 'SENTINEL_REMOTE_DIAGNOSTIC';
  const cases = [
    [400, 'INVENTORY_UNSAFE', 'Device inventory is unsafe or invalid.'],
    [502, 'DEVICE_IDENTITY_FAILED', 'NETCONF device identity verification failed.'],
    [502, 'DEVICE_AUTHENTICATION_FAILED', 'NETCONF device authentication failed.'],
    [503, 'DEVICE_CREDENTIAL_UNAVAILABLE', 'The configured device credential is unavailable.'],
    [502, 'DEVICE_UNREACHABLE', 'The NETCONF device is unreachable.'],
    [502, 'DEVICE_OPERATION_FAILED', 'The NETCONF device operation failed.'],
    [500, 'UNEXPECTED_ERROR', 'An unexpected bridge error occurred.'],
  ];
  for (const [status, code, expected] of cases) {
    const response = new Response(JSON.stringify({
      code,
      error: sentinel,
      details: [{ message: sentinel, command: sentinel }],
      fingerprint: sentinel,
      message: { nested: sentinel },
    }), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
    const error = await bridgeResponseError(response);
    equal(error.message, expected, code);
    assert(!error.message.includes(sentinel), `${code} reflected diagnostics`);
  }
});

await test('uses fixed local fallbacks for unknown codes and malformed bodies', async () => {
  const unknown = await bridgeResponseError(new Response(JSON.stringify({
    code: 'SENTINEL_UNKNOWN_CODE',
    error: 'SENTINEL_REMOTE_ERROR',
  }), { status: 418 }));
  equal(unknown.message, 'Bridge request failed.', 'unknown response fallback');

  const malformed = await bridgeResponseError(new Response(
    '{"code":"UNEXPECTED_ERROR","error":"SENTINEL_PARSER',
    { status: 500, headers: { 'Content-Type': 'application/json' } },
  ));
  equal(malformed.message, 'Bridge encountered an internal error.', 'malformed response fallback');
  assert(!malformed.message.includes('SENTINEL'), 'parser input was reflected');
});

await test('shared response helper rejects failures and malformed success JSON safely', async () => {
  const failures = [
    new Response(JSON.stringify({
      code: 'DEVICE_OPERATION_FAILED',
      error: 'SENTINEL_ERROR',
      details: 'SENTINEL_DETAILS',
      command: 'SENTINEL_COMMAND',
      fingerprint: 'SENTINEL_FINGERPRINT',
    }), { status: 502 }),
    new Response('SENTINEL_PARSER_ERROR', { status: 200 }),
  ];
  const expected = [
    'The NETCONF device operation failed.',
    'Bridge returned an invalid JSON response.',
  ];
  for (let index = 0; index < failures.length; index += 1) {
    let caught;
    try {
      await bridgeClient.bridgeResponseJson(failures[index]);
    } catch (error) {
      caught = error;
    }
    equal(caught?.message, expected[index], `failure ${index}`);
    assert(!caught?.message.includes('SENTINEL'), `failure ${index} reflected input`);
  }
});

await test('shared response helper preserves successful operational payloads', async () => {
  const operational = {
    ok: true,
    config: 'set system host-name edge',
    diff: '+ system host-name edge',
    devices: [{ name: 'edge', host: '192.0.2.10' }],
    policies: [{ name: 'allow-web', hit_count: 7 }],
    app_sessions: [{ application: 'junos-https', sessions: 2 }],
  };
  const parsed = await bridgeClient.bridgeResponseJson(new Response(
    JSON.stringify(operational),
    { status: 200 },
  ));
  equal(JSON.stringify(parsed), JSON.stringify(operational), 'operational payload');
});

await test('arbitrary network Error messages are replaced with local copy', () => {
  const message = bridgeClient.bridgeErrorMessage(
    new Error('SENTINEL_NETWORK_ERROR password fingerprint command'),
    'Connection failed. Check the bridge service and try again.',
  );
  equal(
    message,
    'Connection failed. Check the bridge service and try again.',
    'network failure fallback',
  );
  assert(!message.includes('SENTINEL'), 'network error was reflected');
});

await test('line-load warnings expose only numeric lines and recognized categories', () => {
  const warnings = bridgeClient.safeBridgeLoadWarnings([
    {
      line: 17,
      code: 'DEVICE_OPERATION_FAILED',
      error: 'SENTINEL_ERROR',
      details: 'SENTINEL_DETAILS',
      command: 'SENTINEL_COMMAND',
      message: 'SENTINEL_MESSAGE',
      fingerprint: 'SENTINEL_FINGERPRINT',
    },
    { line: '18', code: 'DEVICE_OPERATION_FAILED' },
    { line: 19, code: 'SENTINEL_UNKNOWN_CODE' },
  ]);
  equal(JSON.stringify(warnings), JSON.stringify([{
    line: 17,
    code: 'DEVICE_OPERATION_FAILED',
    category: 'The NETCONF device operation failed.',
  }]), 'safe warnings');
  assert(!JSON.stringify(warnings).includes('SENTINEL'), 'warning diagnostics were reflected');
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

await test('all response-reading bridge callers use the shared JSON boundary', async () => {
  const callers = {
    'public/hooks/usePush.js': 'bridgeResponseJson',
    'public/hooks/useDay2Ops.js': 'bridgeResponseJson',
    'public/components/LLMSettings.jsx': 'bridgeResponseJson',
    'public/components/PullModal.jsx': 'bridgeResponseJson',
  };
  for (const [file, sharedHelper] of Object.entries(callers)) {
    const source = await readFile(new URL(`../${file}`, import.meta.url), 'utf8');
    assert(!/\bfetch\s*\(/.test(source), `${file} still calls raw fetch`);
    assert(source.includes(sharedHelper), `${file} does not use ${sharedHelper}`);
    assert(!/\bresponse\.json\(\)|\bresp\.json\(\)|\bdevResp\.json\(\)|\bdeviceResponse\.json\(\)|\bhealthResponse\.json\(\)|\bprobeResponse\.json\(\)/.test(source), `${file} parses bridge JSON directly`);
  }
});

await test('push, pull, and Day 2 UI paths never render remote diagnostics', async () => {
  const files = [
    'public/hooks/usePush.js',
    'public/components/PushModal.jsx',
    'public/hooks/useDay2Ops.js',
    'public/components/PullModal.jsx',
  ];
  for (const file of files) {
    const source = await readFile(new URL(`../${file}`, import.meta.url), 'utf8');
    assert(!/\b(?:err|error|reason|data|w)\?*\.(?:error|details|command|fingerprint|message)\b/.test(source), `${file} reads a remote diagnostic field`);
  }
});

console.log(`\n✔ ${passed} passed  ${failed} failed\n`);
if (failed > 0) process.exit(1);

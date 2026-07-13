import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { getLLMChatResponse, getLLMSuggestion } from '../public/utils/llm-client.js';
import { saveLLMSettings } from '../public/utils/llm-settings.js';
import { bridgeResponseError } from '../public/utils/bridge-client.js';
import {
  EMPTY_DEVICE_REGISTRATION,
  DeviceRegistrationError,
  buildDeviceRegistration,
} from '../public/utils/device-registration.js';
import {
  bridgeDisplayError,
  confirmedHostKeyVerification,
  createExclusiveBridgeMutationLock,
  createLatestBridgeAttemptGuard,
  isHostKeyVerificationDisabledForUrl,
  retainHostKeyVerificationForUrl,
} from '../public/utils/bridge-ui-security.js';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

function memoryStorage() {
  const values = new Map();
  return {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
  };
}

beforeEach(() => {
  globalThis.localStorage = memoryStorage();
  globalThis.sessionStorage = memoryStorage();
});

describe('credential source invariants', () => {
  it('runs credential security suites through complete Vitest discovery in CI', () => {
    const ci = read('.github/workflows/ci.yml');
    const start = ci.indexOf('      - name: Run Vitest suites\n');
    const end = ci.indexOf('\n      - name:', start + 1);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    const step = ci.slice(start, end);
    expect(step).toMatch(/\n        run: npx vitest run\s*$/);
    expect(step).not.toMatch(/tests\/[\w-]+\.test\.(?:js|jsx)/);
  });

  it('has no tracked runtime device inventory', () => {
    expect(read('tools/pyez-bridge/devices.example.yaml')).toContain('192.0.2.10');
    expect(read('.gitignore')).toContain('tools/pyez-bridge/devices.yaml');
  });

  it('does not track the runtime inventory', () => {
    expect(() => execFileSync(
      'git',
      ['ls-files', '--error-unmatch', 'tools/pyez-bridge/devices.yaml'],
      { stdio: 'pipe' },
    )).toThrow();
  });

  it('effectively ignores the runtime inventory', () => {
    expect(() => execFileSync(
      'git',
      ['check-ignore', '--quiet', 'tools/pyez-bridge/devices.yaml'],
      { stdio: 'pipe' },
    )).not.toThrow();
  });

  it('documents the split LLM settings storage boundary', () => {
    const readme = read('README.md');
    expect(readme).toContain("nonsecret preferences are stored in `localStorage['llm-settings']`");
    expect(readme).toContain("API key is stored only in `sessionStorage['llm-api-key']` for the current tab session");
    expect(readme).not.toContain('All LLM configuration is stored in `localStorage`');
  });

  it('contains no raw bridge exception reflection', () => {
    const source = read('tools/pyez-bridge/app.py');
    expect(source).not.toMatch(/details\s*=\s*str\s*\(/);
    expect(source).not.toMatch(/f["'][^"'\n]*\{(?:e|exc|error)\}/);
    expect(source).not.toMatch(/print\([^\n]*(?:line\[|str\()/);
  });

  it('exposes no inventory password or private-key fields', () => {
    const example = read('tools/pyez-bridge/devices.example.yaml');
    expect(example).not.toMatch(/^\s+(?:password|passwd|ssh_key|ssh_private_key_file):/m);
    const ui = read('public/components/LLMSettings.jsx');
    expect(ui).not.toMatch(/newDevice\.(?:password|ssh_key)\b/);
  });

  it('builds agent registrations without secret fields', () => {
    expect(buildDeviceRegistration({
      ...EMPTY_DEVICE_REGISTRATION,
      name: ' edge ', host: ' 192.0.2.10 ', username: ' netops ',
    })).toEqual({
      name: 'edge', host: '192.0.2.10', port: 830,
      username: 'netops', auth_method: 'agent',
    });
  });

  it('includes only the password environment reference for password-env', () => {
    expect(buildDeviceRegistration({
      name: 'edge', host: '192.0.2.10', port: 830, username: 'netops',
      auth_method: 'password-env', password_env: 'FIC_EDGE_PASSWORD',
    })).toMatchObject({ auth_method: 'password-env', password_env: 'FIC_EDGE_PASSWORD' });
  });

  it('rejects invalid password environment names without echoing input', () => {
    expect(() => buildDeviceRegistration({
      name: 'edge', host: '192.0.2.10', port: 830, username: 'netops',
      auth_method: 'password-env', password_env: 'bad-SENTINEL',
    })).toThrow('Password environment variable name is invalid.');
    try {
      buildDeviceRegistration({
        name: 'edge', host: '192.0.2.10', port: 830, username: 'netops',
        auth_method: 'password-env', password_env: 'bad-SENTINEL',
      });
    } catch (error) {
      expect(error.message).not.toContain('SENTINEL');
    }
  });

  it('removes password and private-key controls from the bridge UI', () => {
    const source = read('public/components/LLMSettings.jsx');
    expect(source).not.toMatch(/newDevice\.(?:password|ssh_key)\b/);
    expect(source).not.toContain('SSH Key Path');
    expect(source).toContain('Password Environment Variable');
    expect(read('public/utils/bridge-ui-security.js')).toContain('disabled-development');
  });

  it('maps hostile bridge and parser errors to fixed display messages', async () => {
    const hostileResponse = new Response(JSON.stringify({
      error: 'SENTINEL_REMOTE_BODY FIC_EDGE_PASSWORD http://host.invalid',
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
    const hostileError = await bridgeResponseError(hostileResponse);
    expect(hostileError.message).toBe('Bridge encountered an internal error.');
    expect(hostileError.message).not.toContain('SENTINEL_REMOTE_BODY');

    const connectionMessage = bridgeDisplayError('connection', hostileError);
    expect(connectionMessage).toBe('Bridge encountered an internal error.');
    expect(connectionMessage).not.toContain('SENTINEL');
    expect(connectionMessage).not.toContain('FIC_EDGE_PASSWORD');
    expect(connectionMessage).not.toContain('http://');

    for (const [operation, expected] of [
      ['connection', 'Connection failed. Check the bridge service and try again.'],
      ['add-device', 'Failed to add device.'],
      ['remove-device', 'Failed to remove device.'],
    ]) {
      const parserError = new SyntaxError(`Malformed JSON SENTINEL_PARSER for ${operation}`);
      const message = bridgeDisplayError(operation, parserError);
      expect(message).toBe(expected);
      expect(message).not.toContain('SENTINEL_PARSER');
    }
  });

  it('preserves only enumerated bridge and registration messages', async () => {
    const registrationError = new DeviceRegistrationError('Device port is invalid.');
    expect(bridgeDisplayError('add-device', registrationError)).toBe('Device port is invalid.');
    const hostileRegistrationError = new DeviceRegistrationError('SENTINEL_REGISTRATION');
    expect(bridgeDisplayError('add-device', hostileRegistrationError)).toBe('Failed to add device.');

    for (const [status, expected] of [
      [401, 'Bridge access token is missing or invalid.'],
      [403, 'This browser origin is not allowed by the bridge.'],
      [429, 'Bridge request limit reached. Wait and try again.'],
    ]) {
      const error = await bridgeResponseError(new Response(
        JSON.stringify({ error: `SENTINEL_STATUS_${status}` }),
        { status },
      ));
      expect(bridgeDisplayError('connection', error)).toBe(expected);
    }

    for (const inheritedStatus of ['toString', 'constructor', '__proto__']) {
      const error = new Error(`SENTINEL_${inheritedStatus}`);
      error.status = inheritedStatus;
      expect(bridgeDisplayError('connection', error)).toBe(
        'Connection failed. Check the bridge service and try again.',
      );
    }
  });

  it('prevents an older deferred bridge attempt from committing state', async () => {
    const deferred = () => {
      let resolve;
      const promise = new Promise(done => { resolve = done; });
      return { promise, resolve };
    };
    const guard = createLatestBridgeAttemptGuard();
    const olderHealth = deferred();
    const newerHealth = deferred();
    const state = { mode: 'strict', commits: [] };
    const run = async (attempt, response) => {
      const health = await response.promise;
      attempt.commit(() => {
        state.mode = health.host_key_verification;
        state.commits.push(health.host_key_verification);
      });
    };

    const olderRun = run(guard.begin(), olderHealth);
    const newerRun = run(guard.begin(), newerHealth);
    newerHealth.resolve({ host_key_verification: 'disabled-development' });
    await newerRun;
    olderHealth.resolve({ host_key_verification: 'strict' });
    await olderRun;

    expect(state).toEqual({
      mode: 'disabled-development',
      commits: ['disabled-development'],
    });
  });

  it('serializes device mutations without letting an old owner release a new lock', () => {
    const lock = createExclusiveBridgeMutationLock();
    const first = lock.acquire();
    expect(first).not.toBeNull();
    expect(lock.acquire()).toBeNull();

    lock.reset();
    const second = lock.acquire();
    expect(second).not.toBeNull();
    expect(first.release()).toBe(false);
    expect(lock.acquire()).toBeNull();
    expect(second.release()).toBe(true);
    expect(lock.acquire()).not.toBeNull();
  });

  it('preserves a confirmed disabled warning until that endpoint reports strict', () => {
    const bridgeUrl = 'http://localhost:8830';
    const disabled = confirmedHostKeyVerification(
      bridgeUrl,
      'disabled-development',
    );

    const afterTokenEdit = retainHostKeyVerificationForUrl(disabled, bridgeUrl);
    const afterFailedRetestStart = retainHostKeyVerificationForUrl(
      afterTokenEdit,
      bridgeUrl,
    );
    expect(isHostKeyVerificationDisabledForUrl(afterFailedRetestStart, bridgeUrl)).toBe(true);

    const unknownMode = confirmedHostKeyVerification(
      bridgeUrl,
      'SENTINEL_UNKNOWN_MODE',
      disabled,
    );
    expect(isHostKeyVerificationDisabledForUrl(unknownMode, bridgeUrl)).toBe(true);

    const strict = confirmedHostKeyVerification(bridgeUrl, 'strict');
    expect(isHostKeyVerificationDisabledForUrl(strict, bridgeUrl)).toBe(false);

    const changedEndpoint = retainHostKeyVerificationForUrl(
      disabled,
      'http://localhost:9930',
    );
    expect(isHostKeyVerificationDisabledForUrl(changedEndpoint, bridgeUrl)).toBe(false);
    expect(changedEndpoint).toEqual({ url: '', mode: 'strict' });
  });

  it('wires safe display errors and latest-attempt guards into the bridge UI', () => {
    const source = read('public/components/LLMSettings.jsx');
    expect(source).not.toMatch(/(?:err|error)\.message/);
    expect(source).toContain("bridgeDisplayError('connection'");
    expect(source).toContain("bridgeDisplayError('add-device'");
    expect(source).toContain("bridgeDisplayError('remove-device'");
    expect(source.match(/bridgeAttemptGuard\.begin\(\)/g)).toHaveLength(4);
    expect(source).toContain('bridgeAttemptGuard.invalidate()');
    expect(source).toContain('attempt.commit(');
    const addHandler = source.slice(
      source.indexOf('const handleAddDevice'),
      source.indexOf('const handleRemoveDevice'),
    );
    expect(addHandler.indexOf('bridgeAttemptGuard.begin()')).toBeLessThan(
      addHandler.indexOf('buildDeviceRegistration(newDevice)'),
    );
    expect(source.match(/bridgeMutationLock\.acquire\(\)/g)).toHaveLength(2);
    expect(source).toContain('bridgeTesting || bridgeMutationPending');
    expect(source).toContain('disabled={bridgeMutationPending}');
    expect(source.match(/confirmedHostKeyVerification\(/g)).toHaveLength(2);
    expect(source).toContain('retainHostKeyVerificationForUrl(');
    expect(source).toContain('isHostKeyVerificationDisabledForUrl(');
    expect(source).not.toContain("setHostKeyVerification('strict')");
  });

  it('centralizes LLM storage access', () => {
    for (const path of [
      'public/components/LLMSettings.jsx',
      'public/utils/llm-client.js',
      'public/components/ExportPdfButton.jsx',
    ]) {
      const source = read(path);
      expect(source).not.toMatch(/localStorage\.(?:getItem|setItem)\(['"]llm-settings/);
      expect(source).not.toMatch(/sessionStorage\.(?:getItem|setItem)\(['"]llm-api-key/);
    }
  });

  it('does not serialize apiKey into persistent settings', () => {
    const source = read('public/utils/llm-settings.js');
    expect(source).toContain("const { apiKey = '', ...nonsecret } = settings");
    expect(source).toContain('JSON.stringify(nonsecret)');
  });

  it('keeps cloud keys in auth headers and redacts remote error bodies', async () => {
    const cases = [
      { provider: 'claude', header: 'x-api-key', value: 'SENTINEL_KEY', label: 'Claude' },
      { provider: 'openai', header: 'Authorization', value: 'Bearer SENTINEL_KEY', label: 'OpenAI' },
      { provider: 'gemini', header: 'x-goog-api-key', value: 'SENTINEL_KEY', label: 'Gemini' },
    ];

    for (const testCase of cases) {
      for (const call of [
        () => getLLMSuggestion('user prompt', 'system prompt'),
        () => getLLMChatResponse([{ role: 'user', content: 'user prompt' }], 'system prompt'),
      ]) {
        saveLLMSettings({ provider: testCase.provider, apiKey: 'SENTINEL_KEY' });
        const responseJson = vi.fn(async () => ({ error: { message: 'SENTINEL_REMOTE_ERROR' } }));
        globalThis.fetch = vi.fn(async () => ({ ok: false, status: 401, json: responseJson }));

        let caught;
        try { await call(); } catch (error) { caught = error; }

        expect(caught?.message).toBe(`${testCase.label} API error: 401`);
        expect(caught?.message).not.toContain('SENTINEL_REMOTE_ERROR');
        expect(responseJson).not.toHaveBeenCalled();
        const [url, options] = fetch.mock.calls[0];
        expect(url).not.toContain('SENTINEL_KEY');
        expect(options.body).not.toContain('SENTINEL_KEY');
        expect(options.headers[testCase.header]).toBe(testCase.value);
      }
    }
  });
});

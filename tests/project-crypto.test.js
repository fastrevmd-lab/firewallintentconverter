import { describe, expect, it, vi } from 'vitest';
import {
  ProjectCryptoError,
  decryptReversibleEnvelope,
  encryptReversiblePayload,
  inspectEncryptedEnvelope,
  isProjectCryptoAvailable,
  validateProjectPassphrase,
} from '../public/utils/project-crypto.js';
import {
  MAX_PROJECT_FILE_BYTES,
} from '../public/utils/project-security.js';

const payload = {
  payloadSchema: 1,
  name: 'UNIQUE-PROJECT-NAME',
  savedAt: '2026-07-12T00:00:00.000Z',
  sourceMode: 'sanitized',
  state: {
    configText: 'set system login password SANITIZED_KEY_0',
    sanitizationTable: [{
      type: 'key', placeholder: 'SANITIZED_KEY_0', original: 'UNIQUE-ORIGINAL-SECRET',
    }],
  },
};
const passphrase = 'correct horse battery staple';
const encoder = new TextEncoder();

function toBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function aadObject(security) {
  return {
    fpic_version: 5,
    security: {
      schema: 1,
      mode: 'reversible-encrypted',
      containsOriginals: true,
      reversible: true,
      cipher: 'AES-256-GCM',
      tagBits: 128,
      kdf: 'PBKDF2-HMAC-SHA-256',
      iterations: 600_000,
      salt: security.salt,
      nonce: security.nonce,
      aadVersion: 1,
    },
  };
}

function validEnvelopeFixture() {
  const salt = toBase64(new Uint8Array(16));
  const nonce = toBase64(new Uint8Array(12));
  return {
    fpic_version: 5,
    security: aadObject({ salt, nonce }).security,
    ciphertext: toBase64(new Uint8Array(16)),
  };
}

async function encryptArbitraryBytes(bytes) {
  const salt = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const security = {
    ...aadObject({ salt: '', nonce: '' }).security,
    salt: toBase64(salt),
    nonce: toBase64(nonce),
  };
  const material = await globalThis.crypto.subtle.importKey(
    'raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey'],
  );
  const key = await globalThis.crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const ciphertext = await globalThis.crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: nonce,
    additionalData: encoder.encode(JSON.stringify(aadObject(security))),
    tagLength: 128,
  }, key, bytes);
  return { fpic_version: 5, security, ciphertext: toBase64(new Uint8Array(ciphertext)) };
}

function expectCryptoError(operation, code, message) {
  let thrown;
  try {
    operation();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(ProjectCryptoError);
  expect(thrown).toMatchObject({ code, message });
}

function expectFreshFixedError(error, hostile, code, message) {
  expect(error).toBeInstanceOf(ProjectCryptoError);
  expect(error).not.toBe(hostile);
  expect(error).toMatchObject({ name: 'ProjectCryptoError', code, message });
  expect(Reflect.ownKeys(error).filter(key => ![
    'stack', 'message', 'name', 'code',
  ].includes(key))).toEqual([]);
  expect('cause' in error).toBe(false);
  expect('custom' in error).toBe(false);
}

function hostileCryptoError(code) {
  const error = new ProjectCryptoError(code);
  error.custom = 'REVIEW-SENSITIVE-CUSTOM-DATA';
  error.cause = new Error('REVIEW-SENSITIVE-CAUSE');
  error[Symbol('review-sensitive')] = true;
  return error;
}

describe('reversible project crypto', () => {
  it('round-trips a strict payload without exposing plaintext', async () => {
    expect(isProjectCryptoAvailable()).toBe(true);
    const envelope = await encryptReversiblePayload(payload, passphrase);
    const serialized = JSON.stringify(envelope);
    expect(Object.keys(envelope)).toEqual(['fpic_version', 'security', 'ciphertext']);
    expect(serialized).not.toContain('UNIQUE-PROJECT-NAME');
    expect(serialized).not.toContain('UNIQUE-ORIGINAL-SECRET');
    await expect(decryptReversibleEnvelope(envelope, passphrase)).resolves.toEqual(payload);
  });

  it('uses fresh salt, nonce, and ciphertext', async () => {
    const first = await encryptReversiblePayload(payload, passphrase);
    const second = await encryptReversiblePayload(payload, passphrase);
    expect(first.security.salt).not.toBe(second.security.salt);
    expect(first.security.nonce).not.toBe(second.security.nonce);
    expect(first.ciphertext).not.toBe(second.ciphertext);
  });

  it.each(['wrong passphrase value', 'another wrong value'])('uses one error for wrong passphrase', async wrong => {
    const envelope = await encryptReversiblePayload(payload, passphrase);
    await expect(decryptReversibleEnvelope(envelope, wrong)).rejects.toMatchObject({
      name: 'ProjectCryptoError',
      code: 'decryption_failed',
      message: 'Encrypted project could not be opened.',
    });
  });

  it.each(['ciphertext', 'nonce', 'salt', 'iterations'])('rejects tampered %s', async field => {
    const envelope = structuredClone(await encryptReversiblePayload(payload, passphrase));
    if (field === 'ciphertext') {
      envelope.ciphertext = (envelope.ciphertext[0] === 'A' ? 'B' : 'A')
        + envelope.ciphertext.slice(1);
    } else if (field === 'iterations') envelope.security.iterations += 1;
    else {
      envelope.security[field] = (envelope.security[field][0] === 'A' ? 'B' : 'A')
        + envelope.security[field].slice(1);
    }
    await expect(decryptReversibleEnvelope(envelope, passphrase)).rejects.toMatchObject({
      name: 'ProjectCryptoError',
      code: 'decryption_failed',
      message: 'Encrypted project could not be opened.',
    });
  });

  it('validates passphrase bounds without returning the value', () => {
    expect(() => validateProjectPassphrase('short')).toThrow(ProjectCryptoError);
    expect(() => validateProjectPassphrase('sixteen-characters')).not.toThrow();
    expect(validateProjectPassphrase('🔐'.repeat(16))).toBeUndefined();
    expect(() => validateProjectPassphrase('x'.repeat(1025))).toThrow(ProjectCryptoError);
  });

  it('uses the exact algorithms and derives a non-extractable AES-256-GCM key', async () => {
    const calls = {};
    const subtle = globalThis.crypto.subtle;
    const cryptoImpl = {
      getRandomValues: array => globalThis.crypto.getRandomValues(array),
      subtle: {
        importKey: (...args) => subtle.importKey(...args),
        deriveKey: async (...args) => {
          calls.deriveAlgorithm = args[0];
          calls.derivedType = args[2];
          calls.extractable = args[3];
          calls.usages = args[4];
          const key = await subtle.deriveKey(...args);
          calls.key = key;
          return key;
        },
        encrypt: (...args) => {
          calls.encryptAlgorithm = args[0];
          return subtle.encrypt(...args);
        },
      },
    };
    const envelope = await encryptReversiblePayload(payload, passphrase, cryptoImpl);
    expect(calls.deriveAlgorithm).toMatchObject({
      name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000,
    });
    expect(calls.deriveAlgorithm.salt).toHaveLength(16);
    expect(calls.derivedType).toEqual({ name: 'AES-GCM', length: 256 });
    expect(calls.extractable).toBe(false);
    expect(calls.usages).toEqual(['encrypt', 'decrypt']);
    expect(calls.key).toMatchObject({ algorithm: { name: 'AES-GCM', length: 256 }, extractable: false });
    expect(calls.encryptAlgorithm).toMatchObject({ name: 'AES-GCM', tagLength: 128 });
    expect(calls.encryptAlgorithm.iv).toHaveLength(12);
    expect(new TextDecoder().decode(calls.encryptAlgorithm.additionalData))
      .toBe(JSON.stringify(aadObject(envelope.security)));
  });

  it('returns a frozen, canonical inspection copy', async () => {
    const envelope = await encryptReversiblePayload(payload, passphrase);
    const inspected = inspectEncryptedEnvelope(envelope);
    expect(inspected).toEqual(envelope);
    expect(inspected).not.toBe(envelope);
    expect(inspected.security).not.toBe(envelope.security);
    expect(Object.isFrozen(inspected)).toBe(true);
    expect(Object.isFrozen(inspected.security)).toBe(true);
    expect(Object.keys(inspected.security)).toEqual([
      'schema', 'mode', 'containsOriginals', 'reversible', 'cipher', 'tagBits', 'kdf',
      'iterations', 'salt', 'nonce', 'aadVersion',
    ]);
  });

  it.each([
    ['unknown outer field', envelope => { envelope.extra = true; }],
    ['unknown security field', envelope => { envelope.security.extra = true; }],
    ['non-canonical base64 padding', envelope => { envelope.security.salt += '='; }],
    ['base64 whitespace', envelope => { envelope.security.nonce += '\n'; }],
    ['wrong salt length', envelope => { envelope.security.salt = toBase64(new Uint8Array(15)); }],
    ['wrong nonce length', envelope => { envelope.security.nonce = toBase64(new Uint8Array(13)); }],
    ['impossible ciphertext length', envelope => { envelope.ciphertext = toBase64(new Uint8Array(15)); }],
    ['wrong version', envelope => { envelope.fpic_version = 6; }],
    ['wrong mode', envelope => { envelope.security.mode = 'sanitized'; }],
    ['wrong cipher', envelope => { envelope.security.cipher = 'AES-128-GCM'; }],
    ['wrong tag size', envelope => { envelope.security.tagBits = 96; }],
    ['wrong KDF', envelope => { envelope.security.kdf = 'scrypt'; }],
    ['wrong iteration count', envelope => { envelope.security.iterations = 600_001; }],
    ['wrong AAD version', envelope => { envelope.security.aadVersion = 2; }],
  ])('inspection rejects malformed envelopes: %s', async (_label, mutate) => {
    const envelope = structuredClone(await encryptReversiblePayload(payload, passphrase));
    mutate(envelope);
    expectCryptoError(
      () => inspectEncryptedEnvelope(envelope),
      'invalid_envelope',
      'Encrypted project file is invalid.',
    );
  });

  it.each(['salt', 'nonce'])('rejects object %s before invoking toJSON', async field => {
    const envelope = await encryptReversiblePayload(payload, passphrase);
    const original = envelope.security[field];
    let invoked = 0;
    envelope.security[field] = {
      toJSON() {
        invoked += 1;
        return original;
      },
    };
    expectCryptoError(
      () => inspectEncryptedEnvelope(envelope),
      'invalid_envelope',
      'Encrypted project file is invalid.',
    );
    expect(invoked).toBe(0);
  });

  it.each([
    ['salt', 25],
    ['nonce', 17],
  ])('rejects oversized %s before envelope serialization', async (field, length) => {
    const envelope = await encryptReversiblePayload(payload, passphrase);
    envelope.security[field] = 'A'.repeat(length);
    const stringifySpy = vi.spyOn(JSON, 'stringify');
    expectCryptoError(
      () => inspectEncryptedEnvelope(envelope),
      'invalid_envelope',
      'Encrypted project file is invalid.',
    );
    const stringifyCalls = stringifySpy.mock.calls.length;
    stringifySpy.mockRestore();
    expect(stringifyCalls).toBe(0);
  });

  it.each(['mode', 'cipher', 'kdf'])(
    'rejects oversized fixed %s before serialization at envelope boundaries',
    async field => {
      const envelope = validEnvelopeFixture();
      envelope.security[field] = 'A'.repeat(MAX_PROJECT_FILE_BYTES + 1);
      const observations = [];
      for (const [boundary, operation] of [
        ['inspection', () => inspectEncryptedEnvelope(envelope)],
        ['decryption', () => decryptReversibleEnvelope(envelope, passphrase)],
      ]) {
        const stringifySpy = vi.spyOn(JSON, 'stringify');
        let thrown;
        try {
          await operation();
        } catch (error) {
          thrown = error;
        }
        observations.push({ boundary, stringifyCalls: stringifySpy.mock.calls.length, thrown });
        stringifySpy.mockRestore();
      }
      expect(observations.map(({ boundary, stringifyCalls, thrown }) => ({
        boundary,
        stringifyCalls,
        code: thrown?.code,
        message: thrown?.message,
      }))).toEqual([
        {
          boundary: 'inspection',
          stringifyCalls: 0,
          code: 'invalid_envelope',
          message: 'Encrypted project file is invalid.',
        },
        {
          boundary: 'decryption',
          stringifyCalls: 0,
          code: 'decryption_failed',
          message: 'Encrypted project could not be opened.',
        },
      ]);
    },
  );

  it.each([
    ['fpic_version', envelope => { envelope.fpic_version = 6; }],
    ['schema', envelope => { envelope.security.schema = 2; }],
    ['mode', envelope => { envelope.security.mode = 'sanitized'; }],
    ['containsOriginals', envelope => { envelope.security.containsOriginals = false; }],
    ['reversible', envelope => { envelope.security.reversible = false; }],
    ['cipher', envelope => { envelope.security.cipher = 'AES-128-GCM'; }],
    ['tagBits', envelope => { envelope.security.tagBits = 96; }],
    ['kdf', envelope => { envelope.security.kdf = 'PBKDF2-HMAC-SHA-1'; }],
    ['iterations', envelope => { envelope.security.iterations = 600_001; }],
    ['aadVersion', envelope => { envelope.security.aadVersion = 2; }],
  ])('rejects invalid fixed identifier %s before serialization', (field, mutate) => {
    const envelope = validEnvelopeFixture();
    mutate(envelope);
    const stringifySpy = vi.spyOn(JSON, 'stringify');
    expectCryptoError(
      () => inspectEncryptedEnvelope(envelope),
      'invalid_envelope',
      'Encrypted project file is invalid.',
    );
    const stringifyCalls = stringifySpy.mock.calls.length;
    stringifySpy.mockRestore();
    expect(stringifyCalls, field).toBe(0);
  });

  it.each([
    ['inspection', 'invalid_envelope', proxy => inspectEncryptedEnvelope(proxy)],
    ['encryption', 'invalid_envelope', proxy => encryptReversiblePayload(proxy, passphrase)],
    ['decryption', 'decryption_failed', proxy => decryptReversibleEnvelope(proxy, passphrase)],
  ])('replaces a hostile ProjectCryptoError from an input proxy during %s', async (
    _label,
    code,
    operation,
  ) => {
    const hostile = hostileCryptoError('invalid_envelope');
    const proxy = new Proxy({}, {
      getPrototypeOf() {
        throw hostile;
      },
    });
    let thrown;
    try {
      await operation(proxy);
    } catch (error) {
      thrown = error;
    }
    expectFreshFixedError(
      thrown,
      hostile,
      code,
      code === 'decryption_failed'
        ? 'Encrypted project could not be opened.'
        : 'Encrypted project file is invalid.',
    );
  });

  it('replaces a hostile ProjectCryptoError from an injected crypto operation', async () => {
    const hostile = hostileCryptoError('invalid_envelope');
    const cryptoImpl = {
      getRandomValues: array => globalThis.crypto.getRandomValues(array),
      subtle: {
        importKey() {
          throw hostile;
        },
      },
    };
    let thrown;
    try {
      await encryptReversiblePayload(payload, passphrase, cryptoImpl);
    } catch (error) {
      thrown = error;
    }
    expectFreshFixedError(
      thrown,
      hostile,
      'invalid_envelope',
      'Encrypted project file is invalid.',
    );
  });

  it.each([
    ['schema', 2],
    ['containsOriginals', false],
    ['reversible', false],
    ['cipher', 'AES-128-GCM'],
    ['tagBits', 96],
    ['kdf', 'PBKDF2-HMAC-SHA-1'],
    ['aadVersion', 2],
  ])('normalizes authenticated metadata tampering for %s', async (field, value) => {
    const envelope = structuredClone(await encryptReversiblePayload(payload, passphrase));
    envelope.security[field] = value;
    await expect(decryptReversibleEnvelope(envelope, passphrase)).rejects.toEqual(
      new ProjectCryptoError('decryption_failed'),
    );
  });

  it('rejects changed iterations before PBKDF2', async () => {
    const envelope = structuredClone(await encryptReversiblePayload(payload, passphrase));
    envelope.security.iterations = 1_000_000_000;
    let derivationStarted = false;
    const cryptoImpl = {
      getRandomValues: array => globalThis.crypto.getRandomValues(array),
      subtle: {
        importKey() {
          derivationStarted = true;
          throw new Error('must not be reflected');
        },
      },
    };
    await expect(decryptReversibleEnvelope(envelope, passphrase, cryptoImpl)).rejects.toEqual(
      new ProjectCryptoError('decryption_failed'),
    );
    expect(derivationStarted).toBe(false);
  });

  it('rejects oversized encrypted metadata before PBKDF2', async () => {
    const envelope = structuredClone(await encryptReversiblePayload(payload, passphrase));
    envelope.ciphertext = 'A'.repeat(MAX_PROJECT_FILE_BYTES + 1);
    let derivationStarted = false;
    const cryptoImpl = {
      getRandomValues: array => globalThis.crypto.getRandomValues(array),
      subtle: {
        importKey() {
          derivationStarted = true;
          throw new Error('must not be reflected');
        },
      },
    };
    await expect(decryptReversibleEnvelope(envelope, passphrase, cryptoImpl)).rejects.toEqual(
      new ProjectCryptoError('decryption_failed'),
    );
    expect(derivationStarted).toBe(false);
  });

  it.each([
    ['invalid UTF-8', Uint8Array.of(0xc3, 0x28)],
    ['invalid JSON', encoder.encode('{not json')],
    ['invalid inner payload schema', encoder.encode(JSON.stringify({ ...payload, payloadSchema: 2 }))],
    ['unknown inner payload key', encoder.encode(JSON.stringify({ ...payload, unexpected: true }))],
  ])('normalizes authenticated plaintext failure: %s', async (_label, plaintext) => {
    const envelope = await encryptArbitraryBytes(plaintext);
    await expect(decryptReversibleEnvelope(envelope, passphrase)).rejects.toEqual(
      new ProjectCryptoError('decryption_failed'),
    );
  });

  it('rejects truncated ciphertext with the same decryption error', async () => {
    const envelope = structuredClone(await encryptReversiblePayload(payload, passphrase));
    envelope.ciphertext = envelope.ciphertext.slice(0, -4);
    await expect(decryptReversibleEnvelope(envelope, passphrase)).rejects.toEqual(
      new ProjectCryptoError('decryption_failed'),
    );
  });

  it('rejects unavailable Web Crypto without a plaintext fallback', async () => {
    const absent = {};
    expect(isProjectCryptoAvailable(absent)).toBe(false);
    await expect(encryptReversiblePayload(payload, passphrase, absent)).rejects.toEqual(
      new ProjectCryptoError('unsupported_crypto'),
    );
    const envelope = await encryptReversiblePayload(payload, passphrase);
    await expect(decryptReversibleEnvelope(envelope, passphrase, absent)).rejects.toEqual(
      new ProjectCryptoError('unsupported_crypto'),
    );
  });

  it.each([
    ['unknown payload field', { ...payload, extra: true }],
    ['wrong source mode', { ...payload, sourceMode: 'unsanitized' }],
    ['invalid timestamp', { ...payload, savedAt: 'yesterday' }],
    ['empty name', { ...payload, name: '' }],
  ])('rejects invalid encryption payloads: %s', async (_label, invalidPayload) => {
    await expect(encryptReversiblePayload(invalidPayload, passphrase)).rejects.toEqual(
      new ProjectCryptoError('invalid_envelope'),
    );
  });

  it('rejects unsafe nested payloads without invoking getters or leaking native errors', async () => {
    let invoked = false;
    const unsafe = structuredClone(payload);
    Object.defineProperty(unsafe.state, 'secret', {
      enumerable: true,
      get() {
        invoked = true;
        throw new Error('native getter detail');
      },
    });
    await expect(encryptReversiblePayload(unsafe, passphrase)).rejects.toEqual(
      new ProjectCryptoError('invalid_envelope'),
    );
    expect(invoked).toBe(false);
  });
});

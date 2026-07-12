import {
  MAX_PROJECT_FILE_BYTES,
  MAX_PROJECT_PLAINTEXT_BYTES,
  boundedProjectStringify,
} from './project-security.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const ITERATIONS = 600_000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MAX_PASSPHRASE_BYTES = 1024;
const MAX_PROJECT_NAME_BYTES = 1024;
const BASE64_CHUNK_BYTES = 0x8000;
const PAYLOAD_KEYS = Object.freeze([
  'payloadSchema', 'name', 'savedAt', 'sourceMode', 'state',
]);
const OUTER_KEYS = Object.freeze(['fpic_version', 'security', 'ciphertext']);
const SECURITY_KEYS = Object.freeze([
  'schema', 'mode', 'containsOriginals', 'reversible', 'cipher', 'tagBits', 'kdf',
  'iterations', 'salt', 'nonce', 'aadVersion',
]);
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const CRYPTO_MESSAGES = Object.freeze({
  invalid_passphrase: 'Passphrase must contain at least 16 characters.',
  unsupported_crypto: 'Encrypted project export is unavailable in this browser.',
  invalid_envelope: 'Encrypted project file is invalid.',
  decryption_failed: 'Encrypted project could not be opened.',
});

export class ProjectCryptoError extends Error {
  constructor(code) {
    super(CRYPTO_MESSAGES[code] || CRYPTO_MESSAGES.invalid_envelope);
    this.name = 'ProjectCryptoError';
    this.code = Object.hasOwn(CRYPTO_MESSAGES, code) ? code : 'invalid_envelope';
  }
}

export function isProjectCryptoAvailable(cryptoImpl = globalThis.crypto) {
  try {
    return Boolean(cryptoImpl?.getRandomValues && cryptoImpl?.subtle);
  } catch {
    return false;
  }
}

export function validateProjectPassphrase(passphrase) {
  if (typeof passphrase !== 'string'
      || passphrase.length > MAX_PASSPHRASE_BYTES
      || Array.from(passphrase).length < 16
      || encoder.encode(passphrase).length > MAX_PASSPHRASE_BYTES) {
    throw new ProjectCryptoError('invalid_passphrase');
  }
}

function invalidEnvelope() {
  throw new ProjectCryptoError('invalid_envelope');
}

function exactOwnDataObject(value, expectedKeys) {
  try {
    if (value === null
        || typeof value !== 'object'
        || Array.isArray(value)
        || Object.getPrototypeOf(value) !== Object.prototype
        || Object.getOwnPropertySymbols(value).length > 0) {
      invalidEnvelope();
    }
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== expectedKeys.length
        || !names.every(name => expectedKeys.includes(name))) {
      invalidEnvelope();
    }
    const result = {};
    for (const key of expectedKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
        invalidEnvelope();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error instanceof ProjectCryptoError) throw error;
    invalidEnvelope();
  }
}

function hasExactKeys(value, expectedKeys) {
  const record = exactOwnDataObject(value, expectedKeys);
  return record;
}

function canonicalBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += BASE64_CHUNK_BYTES) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + BASE64_CHUNK_BYTES));
  }
  return btoa(binary);
}

function decodeCanonicalBase64(value, { exactBytes, minimumBytes, maximumBytes } = {}) {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length > MAX_PROJECT_FILE_BYTES
      || !BASE64_PATTERN.test(value)) {
    invalidEnvelope();
  }
  let binary;
  try {
    binary = atob(value);
  } catch {
    invalidEnvelope();
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  if (canonicalBase64(bytes) !== value
      || exactBytes !== undefined && bytes.length !== exactBytes
      || minimumBytes !== undefined && bytes.length < minimumBytes
      || maximumBytes !== undefined && bytes.length > maximumBytes) {
    invalidEnvelope();
  }
  return bytes;
}

function assertExactEnvelopeIdentifiers(envelope) {
  const { security } = envelope;
  if (envelope.fpic_version !== 5
      || security.schema !== 1
      || security.mode !== 'reversible-encrypted'
      || security.containsOriginals !== true
      || security.reversible !== true
      || security.cipher !== 'AES-256-GCM'
      || security.tagBits !== 128
      || security.kdf !== 'PBKDF2-HMAC-SHA-256'
      || security.iterations !== ITERATIONS
      || security.aadVersion !== 1) {
    invalidEnvelope();
  }
}

function parseEnvelopeShape(envelope) {
  const outer = exactOwnDataObject(envelope, OUTER_KEYS);
  const security = exactOwnDataObject(outer.security, SECURITY_KEYS);
  if (!Number.isSafeInteger(outer.fpic_version)
      || !Number.isSafeInteger(security.schema)
      || typeof security.mode !== 'string'
      || typeof security.containsOriginals !== 'boolean'
      || typeof security.reversible !== 'boolean'
      || typeof security.cipher !== 'string'
      || !Number.isSafeInteger(security.tagBits)
      || typeof security.kdf !== 'string'
      || !Number.isSafeInteger(security.iterations)
      || !Number.isSafeInteger(security.aadVersion)
      || typeof outer.ciphertext !== 'string'
      || outer.ciphertext.length > MAX_PROJECT_FILE_BYTES) {
    invalidEnvelope();
  }
  const clone = {
    fpic_version: outer.fpic_version,
    security: {
      schema: security.schema,
      mode: security.mode,
      containsOriginals: security.containsOriginals,
      reversible: security.reversible,
      cipher: security.cipher,
      tagBits: security.tagBits,
      kdf: security.kdf,
      iterations: security.iterations,
      salt: security.salt,
      nonce: security.nonce,
      aadVersion: security.aadVersion,
    },
    ciphertext: outer.ciphertext,
  };
  let serializedBytes;
  try {
    serializedBytes = encoder.encode(JSON.stringify(clone)).length;
  } catch {
    invalidEnvelope();
  }
  if (serializedBytes > MAX_PROJECT_FILE_BYTES) invalidEnvelope();
  const saltBytes = decodeCanonicalBase64(security.salt, { exactBytes: SALT_BYTES });
  const nonceBytes = decodeCanonicalBase64(security.nonce, { exactBytes: NONCE_BYTES });
  const ciphertextBytes = decodeCanonicalBase64(outer.ciphertext, {
    minimumBytes: TAG_BYTES,
    maximumBytes: MAX_PROJECT_PLAINTEXT_BYTES + TAG_BYTES,
  });
  return { clone, saltBytes, nonceBytes, ciphertextBytes };
}

function assertCanonicalTimestamp(value) {
  if (typeof value !== 'string') invalidEnvelope();
  let canonical;
  try {
    canonical = new Date(value).toISOString();
  } catch {
    invalidEnvelope();
  }
  if (canonical !== value) invalidEnvelope();
}

function validatePayload(payload) {
  hasExactKeys(payload, PAYLOAD_KEYS);
  let serialized;
  try {
    serialized = boundedProjectStringify(payload);
  } catch {
    invalidEnvelope();
  }
  let clone;
  try {
    clone = JSON.parse(serialized);
  } catch {
    invalidEnvelope();
  }
  if (clone.payloadSchema !== 1
      || clone.sourceMode !== 'sanitized'
      || typeof clone.name !== 'string'
      || clone.name.length === 0
      || encoder.encode(clone.name).length > MAX_PROJECT_NAME_BYTES
      || clone.state === null
      || typeof clone.state !== 'object'
      || Array.isArray(clone.state)) {
    invalidEnvelope();
  }
  assertCanonicalTimestamp(clone.savedAt);
  return { clone, serialized };
}

async function deriveKey(passphrase, salt, cryptoImpl) {
  const material = await cryptoImpl.subtle.importKey(
    'raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey'],
  );
  return cryptoImpl.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
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
      iterations: ITERATIONS,
      salt: security.salt,
      nonce: security.nonce,
      aadVersion: 1,
    },
  };
}

function aadBytes(security) {
  return encoder.encode(JSON.stringify(aadObject(security)));
}

export function inspectEncryptedEnvelope(envelope) {
  const parsed = parseEnvelopeShape(envelope);
  assertExactEnvelopeIdentifiers(parsed.clone);
  Object.freeze(parsed.clone.security);
  return Object.freeze(parsed.clone);
}

export async function encryptReversiblePayload(
  payload,
  passphrase,
  cryptoImpl = globalThis.crypto,
) {
  validateProjectPassphrase(passphrase);
  if (!isProjectCryptoAvailable(cryptoImpl)) {
    throw new ProjectCryptoError('unsupported_crypto');
  }
  const { serialized } = validatePayload(payload);
  try {
    const salt = cryptoImpl.getRandomValues(new Uint8Array(SALT_BYTES));
    const nonce = cryptoImpl.getRandomValues(new Uint8Array(NONCE_BYTES));
    const security = {
      schema: 1,
      mode: 'reversible-encrypted',
      containsOriginals: true,
      reversible: true,
      cipher: 'AES-256-GCM',
      tagBits: 128,
      kdf: 'PBKDF2-HMAC-SHA-256',
      iterations: ITERATIONS,
      salt: canonicalBase64(salt),
      nonce: canonicalBase64(nonce),
      aadVersion: 1,
    };
    const key = await deriveKey(passphrase, salt, cryptoImpl);
    const ciphertext = await cryptoImpl.subtle.encrypt({
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aadBytes(security),
      tagLength: 128,
    }, key, encoder.encode(serialized));
    return {
      fpic_version: 5,
      security,
      ciphertext: canonicalBase64(new Uint8Array(ciphertext)),
    };
  } catch (error) {
    if (error instanceof ProjectCryptoError) throw error;
    throw new ProjectCryptoError('invalid_envelope');
  }
}

export async function decryptReversibleEnvelope(
  envelope,
  passphrase,
  cryptoImpl = globalThis.crypto,
) {
  validateProjectPassphrase(passphrase);
  if (!isProjectCryptoAvailable(cryptoImpl)) {
    throw new ProjectCryptoError('unsupported_crypto');
  }
  try {
    const parsed = parseEnvelopeShape(envelope);
    assertExactEnvelopeIdentifiers(parsed.clone);
    const key = await deriveKey(passphrase, parsed.saltBytes, cryptoImpl);
    const plaintext = await cryptoImpl.subtle.decrypt({
      name: 'AES-GCM',
      iv: parsed.nonceBytes,
      additionalData: aadBytes(parsed.clone.security),
      tagLength: 128,
    }, key, parsed.ciphertextBytes);
    const bytes = new Uint8Array(plaintext);
    if (bytes.length > MAX_PROJECT_PLAINTEXT_BYTES) invalidEnvelope();
    const decoded = decoder.decode(bytes);
    const payload = JSON.parse(decoded);
    return validatePayload(payload).clone;
  } catch {
    throw new ProjectCryptoError('decryption_failed');
  }
}

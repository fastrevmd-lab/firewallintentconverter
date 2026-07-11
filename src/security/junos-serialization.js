import { sanitizeJunosName } from '../parsers/parser-utils.js';

const UNSAFE_CONTROL = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/u;
const JUNOS_IDENTIFIER = /^[A-Za-z][A-Za-z0-9._-]{0,62}$/;
const UNSAFE_UNQUOTED = /[\s;`$#"'\\]/u;

/**
 * A safe, field-addressable conversion error. Rejected values are never
 * retained on the error so callers cannot accidentally reflect them.
 */
export class JunosSerializationError extends Error {
  constructor(fieldPath, valueKind, reason) {
    super(`Invalid ${valueKind} at ${fieldPath}: ${reason}`);
    this.name = 'JunosSerializationError';
    this.fieldPath = fieldPath;
    this.valueKind = valueKind;
    this.reason = reason;
  }
}

function fail(fieldPath, valueKind, reason) {
  throw new JunosSerializationError(fieldPath, valueKind, reason);
}

export function assertSafeScalar(value, fieldPath) {
  const valueType = typeof value;
  if (!['string', 'number', 'boolean'].includes(valueType)) {
    fail(fieldPath, 'scalar', 'expected a string, finite number, or boolean');
  }
  if (valueType === 'number' && !Number.isFinite(value)) {
    fail(fieldPath, 'scalar', 'expected a string, finite number, or boolean');
  }

  const text = String(value);
  if (UNSAFE_CONTROL.test(text)) {
    fail(fieldPath, 'scalar', 'control or line-separator characters are not allowed');
  }
  return text;
}

export function setToken(value, fieldPath, pattern = JUNOS_IDENTIFIER) {
  const text = assertSafeScalar(value, fieldPath);
  pattern.lastIndex = 0;
  if (!text || !pattern.test(text) || UNSAFE_UNQUOTED.test(text)) {
    fail(fieldPath, 'token', 'value is outside the allowed token domain');
  }
  return text;
}

export function setIdentifier(value, fieldPath) {
  const normalized = sanitizeJunosName(assertSafeScalar(value, fieldPath));
  if (!JUNOS_IDENTIFIER.test(normalized)) {
    fail(fieldPath, 'identifier', 'value cannot form a Junos identifier');
  }
  return normalized;
}

export function setQuoted(value, fieldPath) {
  const text = assertSafeScalar(value, fieldPath);
  return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

export function setEnum(value, allowed, fieldPath) {
  const text = assertSafeScalar(value, fieldPath);
  if (!Array.isArray(allowed) || !allowed.includes(text)) {
    fail(fieldPath, 'enum', `expected one of: ${(allowed || []).join(', ')}`);
  }
  return text;
}

export function setInteger(
  value,
  { min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER } = {},
  fieldPath,
) {
  const text = assertSafeScalar(value, fieldPath);
  if (!/^-?\d+$/.test(text)) {
    fail(fieldPath, 'integer', 'expected a base-10 integer');
  }

  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    fail(fieldPath, 'integer', `expected ${min} through ${max}`);
  }
  return text;
}

export function setPort(value, fieldPath) {
  return setInteger(value, { min: 0, max: 65535 }, fieldPath);
}

function isIpv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(part => (
    /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255
  ));
}

function isIpv6(value) {
  if (!/^[0-9A-Fa-f:.]+$/.test(value) || !value.includes(':')) return false;
  if ((value.match(/::/g) || []).length > 1) return false;

  const halves = value.split('::');
  if (halves.length > 2) return false;

  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = [...left, ...right];
  const ipv4Tail = groups.length > 0 && groups.at(-1).includes('.');
  const hexGroups = ipv4Tail ? groups.slice(0, -1) : groups;

  if (!hexGroups.every(group => /^[0-9A-Fa-f]{1,4}$/.test(group))) return false;
  if (ipv4Tail && !isIpv4(groups.at(-1))) return false;

  const width = hexGroups.length + (ipv4Tail ? 2 : 0);
  return halves.length === 2 ? width < 8 : width === 8;
}

export function setAddressOrPrefix(value, fieldPath) {
  const text = assertSafeScalar(value, fieldPath);
  const pieces = text.split('/');
  if (pieces.length > 2) {
    fail(fieldPath, 'address', 'expected an IPv4/IPv6 address or prefix');
  }

  const [address, prefix] = pieces;
  const family = isIpv4(address) ? 4 : isIpv6(address) ? 6 : 0;
  if (!family) {
    fail(fieldPath, 'address', 'expected an IPv4/IPv6 address or prefix');
  }
  if (prefix !== undefined) {
    const maxPrefix = family === 4 ? 32 : 128;
    if (!/^\d+$/.test(prefix) || Number(prefix) > maxPrefix) {
      fail(fieldPath, 'prefix', 'prefix length is outside the address-family range');
    }
  }
  return text;
}

function assertSerializedCommandPiece(piece) {
  const text = assertSafeScalar(piece, 'output');
  if (!text) fail('output', 'command', 'hierarchy contains an empty token');

  if (!text.startsWith('"')) {
    if (UNSAFE_UNQUOTED.test(text)) {
      fail('output', 'command', 'hierarchy contains an unserialized token');
    }
    return text;
  }

  let escaped = false;
  for (let index = 1; index < text.length; index += 1) {
    const char = text[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '"' && index !== text.length - 1) {
      fail('output', 'command', 'quoted token terminates before its end');
    }
  }
  if (escaped || text.length < 2 || !text.endsWith('"')) {
    fail('output', 'command', 'quoted token is incomplete');
  }
  return text;
}

export function setCommand(verb, hierarchy) {
  if (!['set', 'deactivate'].includes(verb)) {
    fail('output', 'command', 'unsupported command verb');
  }
  if (!Array.isArray(hierarchy) || hierarchy.length === 0) {
    fail('output', 'command', 'hierarchy must contain serialized tokens');
  }
  return `${verb} ${hierarchy.map(assertSerializedCommandPiece).join(' ')}`;
}

export function setComment(value, fieldPath) {
  return `# ${assertSafeScalar(value, fieldPath)}`;
}

function escapeXml(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function xmlText(value, fieldPath) {
  return escapeXml(assertSafeScalar(value, fieldPath));
}

export function xmlAttribute(value, fieldPath) {
  return escapeXml(assertSafeScalar(value, fieldPath));
}

export function xmlElementName(value, allowed, fieldPath) {
  return setEnum(value, allowed, fieldPath);
}

export function xmlComment(value, fieldPath) {
  let text = assertSafeScalar(value, fieldPath).replace(/--/g, '- -');
  if (text.endsWith('-')) text += ' ';
  return `<!-- ${text} -->`;
}

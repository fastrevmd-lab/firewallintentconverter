import {
  findSecretsInText,
  isSanitizedSecretValue,
  isSecretBearingKey,
} from './secret-detection.js';

export const PROJECT_SECURITY_MODES = Object.freeze({
  SANITIZED: 'sanitized',
  REVERSIBLE: 'reversible-encrypted',
  UNSANITIZED: 'unsanitized',
  LEGACY: 'legacy-secret-bearing',
});
export const MAX_PROJECT_PLAINTEXT_BYTES = 48 * 1024 * 1024;
export const MAX_PROJECT_FILE_BYTES = 65 * 1024 * 1024;
export const MAX_PROJECT_DEPTH = 128;
export const MAX_PROJECT_NODES = 1_000_000;

const MAX_RESTORATION_TYPE_BYTES = 64;
const MAX_RESTORATION_PLACEHOLDER_BYTES = 1024;
const MAX_RESTORATION_ORIGINAL_BYTES = 1024 * 1024;
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const RESTORATION_KEYS = new Set(['type', 'placeholder', 'original', 'restore']);
const NON_RESTORABLE_TYPES = new Set([
  'password', 'hash', 'key', 'community', 'certificate', 'cert',
]);
const TEXT_ENCODER = new TextEncoder();

const ERROR_MESSAGES = Object.freeze({
  unsafe_state: 'Project state contains an unsupported value.',
  invalid_restoration: 'Project restoration data is invalid.',
  unsanitized_source: 'Sanitized export requires every populated source to be sanitized.',
  original_leak: 'Sanitized export was blocked because an original value remains.',
  secret_leak: 'Sanitized export was blocked because secret-bearing content remains.',
  oversized_project: 'Project data exceeds the supported size limit.',
});

export class ProjectSecurityError extends Error {
  constructor(code) {
    const knownCode = typeof code === 'string' && Object.hasOwn(ERROR_MESSAGES, code);
    super(knownCode ? ERROR_MESSAGES[code] : 'Project security validation failed.');
    this.name = 'ProjectSecurityError';
    this.code = knownCode ? code : 'unsafe_state';
  }
}

function fixedBoundary(operation, fallbackCode = 'unsafe_state') {
  try {
    return operation();
  } catch (error) {
    if (error instanceof ProjectSecurityError) throw error;
    throw new ProjectSecurityError(fallbackCode);
  }
}

function utf8Length(value) {
  return TEXT_ENCODER.encode(value).length;
}

function ownPropertyNames(value) {
  try {
    return Object.getOwnPropertyNames(value);
  } catch {
    throw new ProjectSecurityError('unsafe_state');
  }
}

function ownPropertySymbols(value) {
  try {
    return Object.getOwnPropertySymbols(value);
  } catch {
    throw new ProjectSecurityError('unsafe_state');
  }
}

function ownDescriptor(value, key) {
  try {
    return Object.getOwnPropertyDescriptor(value, key);
  } catch {
    throw new ProjectSecurityError('unsafe_state');
  }
}

function prototypeOf(value) {
  try {
    return Object.getPrototypeOf(value);
  } catch {
    throw new ProjectSecurityError('unsafe_state');
  }
}

function assertPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && prototypeOf(value) === Object.prototype;
}

function requiredDataDescriptor(value, key) {
  const descriptor = ownDescriptor(value, key);
  if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
    throw new ProjectSecurityError('unsafe_state');
  }
  return descriptor;
}

function optionalDataValue(value, key) {
  const descriptor = ownDescriptor(value, key);
  if (!descriptor) return undefined;
  if (descriptor.get || descriptor.set || !descriptor.enumerable) {
    throw new ProjectSecurityError('unsafe_state');
  }
  return descriptor.value;
}

function assertSafePrimitive(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  throw new ProjectSecurityError('unsafe_state');
}

function walk(
  value,
  visitor,
  path = [],
  state = { depth: 0, nodes: 0, seen: new WeakSet() },
  parent = null,
) {
  state.nodes += 1;
  if (state.nodes > MAX_PROJECT_NODES || state.depth > MAX_PROJECT_DEPTH) {
    throw new ProjectSecurityError('unsafe_state');
  }

  if (value === null || typeof value !== 'object') {
    assertSafePrimitive(value);
    visitor(value, path, parent);
    return;
  }

  const isArray = Array.isArray(value);
  const expectedPrototype = isArray ? Array.prototype : Object.prototype;
  if (prototypeOf(value) !== expectedPrototype || state.seen.has(value)) {
    throw new ProjectSecurityError('unsafe_state');
  }
  state.seen.add(value);

  if (ownPropertySymbols(value).length > 0) {
    throw new ProjectSecurityError('unsafe_state');
  }

  let names;
  if (isArray) {
    const lengthDescriptor = ownDescriptor(value, 'length');
    const length = lengthDescriptor?.value;
    if (!lengthDescriptor || lengthDescriptor.get || lengthDescriptor.set
        || !Number.isSafeInteger(length) || length < 0
        || state.nodes + (length * 2) > MAX_PROJECT_NODES) {
      throw new ProjectSecurityError('unsafe_state');
    }
    names = ownPropertyNames(value);
    if (names.length !== length + 1 || !names.includes('length')) {
      throw new ProjectSecurityError('unsafe_state');
    }
  } else {
    names = ownPropertyNames(value);
    if (state.nodes + (names.length * 2) > MAX_PROJECT_NODES) {
      throw new ProjectSecurityError('unsafe_state');
    }
  }

  visitor(value, path, parent);
  state.depth += 1;

  if (isArray) {
    const length = ownDescriptor(value, 'length').value;
    for (let index = 0; index < length; index += 1) {
      const key = String(index);
      const descriptor = requiredDataDescriptor(value, key);
      state.nodes += 1;
      if (state.nodes > MAX_PROJECT_NODES) throw new ProjectSecurityError('unsafe_state');
      walk(descriptor.value, visitor, [...path, key], state, value);
    }
  } else {
    for (const key of names) {
      if (DANGEROUS_KEYS.has(key)) throw new ProjectSecurityError('unsafe_state');
      const descriptor = requiredDataDescriptor(value, key);
      state.nodes += 1;
      if (state.nodes > MAX_PROJECT_NODES) throw new ProjectSecurityError('unsafe_state');
      walk(descriptor.value, visitor, [...path, key], state, value);
    }
  }

  state.depth -= 1;
}

function cloneValidated(value, omitRestorationTables = false) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    const length = ownDescriptor(value, 'length').value;
    const clone = new Array(length);
    for (let index = 0; index < length; index += 1) {
      clone[index] = cloneValidated(requiredDataDescriptor(value, String(index)).value, omitRestorationTables);
    }
    return clone;
  }

  const clone = {};
  for (const key of ownPropertyNames(value)) {
    if (omitRestorationTables && key === 'sanitizationTable') continue;
    clone[key] = cloneValidated(requiredDataDescriptor(value, key).value, omitRestorationTables);
  }
  return clone;
}

function normalizedType(value) {
  return value.replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function validatedTable(value) {
  if (!Array.isArray(value)) throw new ProjectSecurityError('invalid_restoration');
  const length = ownDescriptor(value, 'length')?.value;
  const entries = [];
  for (let index = 0; index < length; index += 1) {
    const entry = ownDescriptor(value, String(index))?.value;
    if (!assertPlainObject(entry)) throw new ProjectSecurityError('invalid_restoration');
    const keys = ownPropertyNames(entry);
    if (!keys.every(key => RESTORATION_KEYS.has(key))) {
      throw new ProjectSecurityError('invalid_restoration');
    }
    const type = optionalDataValue(entry, 'type');
    const placeholder = optionalDataValue(entry, 'placeholder');
    const original = optionalDataValue(entry, 'original');
    const restore = optionalDataValue(entry, 'restore');
    if (typeof type !== 'string'
        || typeof placeholder !== 'string'
        || typeof original !== 'string'
        || original.length === 0
        || restore !== undefined && typeof restore !== 'boolean'
        || utf8Length(type) > MAX_RESTORATION_TYPE_BYTES
        || utf8Length(placeholder) > MAX_RESTORATION_PLACEHOLDER_BYTES
        || utf8Length(original) > MAX_RESTORATION_ORIGINAL_BYTES
        || restore === true && NON_RESTORABLE_TYPES.has(normalizedType(type))) {
      throw new ProjectSecurityError('invalid_restoration');
    }
    entries.push(entry);
  }
  return entries;
}

function scanRestorationData(stateBag) {
  let restorationAvailable = false;
  const originals = new Set();
  walk(stateBag, (value, path) => {
    if (path.at(-1) !== 'sanitizationTable' || value === null) return;
    const entries = validatedTable(value);
    restorationAvailable ||= entries.length > 0;
    for (const entry of entries) {
      originals.add(optionalDataValue(entry, 'original'));
    }
  });
  return { restorationAvailable, originals };
}

function isPopulatedSource(source) {
  if (!assertPlainObject(source)) return false;
  const configText = optionalDataValue(source, 'configText');
  const intermediateConfig = optionalDataValue(source, 'intermediateConfig');
  const srxOutput = optionalDataValue(source, 'srxOutput');
  const translatedPolicies = optionalDataValue(source, 'srxTranslatedPolicies');
  const ruleGroups = optionalDataValue(source, 'ruleGroups');
  const interfaceMappings = optionalDataValue(source, 'interfaceMappings');
  const greenfieldMode = optionalDataValue(source, 'greenfieldMode');
  const greenfieldTemplate = optionalDataValue(source, 'greenfieldTemplate');
  return Boolean(
    typeof configText === 'string' && configText.trim()
    || intermediateConfig !== null && intermediateConfig !== undefined
    || srxOutput !== null && srxOutput !== undefined
    || Array.isArray(translatedPolicies) && translatedPolicies.length > 0
    || Array.isArray(ruleGroups) && ruleGroups.length > 0
    || assertPlainObject(interfaceMappings) && ownPropertyNames(interfaceMappings).length > 0
    || greenfieldMode === true
    || greenfieldTemplate !== null && greenfieldTemplate !== undefined
  );
}

function classifyProjectSecurityInternal(stateBag) {
  walk(stateBag, () => {});
  if (!assertPlainObject(stateBag)) throw new ProjectSecurityError('unsafe_state');

  const configuredSlots = optionalDataValue(stateBag, 'configSlots');
  if (configuredSlots !== undefined && !Array.isArray(configuredSlots)) {
    throw new ProjectSecurityError('unsafe_state');
  }
  const slots = configuredSlots || [];
  const sources = [stateBag];
  const slotLength = ownDescriptor(slots, 'length').value;
  for (let index = 0; index < slotLength; index += 1) {
    const slot = requiredDataDescriptor(slots, String(index)).value;
    if (!assertPlainObject(slot)) throw new ProjectSecurityError('unsafe_state');
    if (isPopulatedSource(slot)) sources.push(slot);
  }
  const populated = sources.filter(isPopulatedSource);
  const sanitizedEligible = populated.length > 0 && populated.every(source => (
    optionalDataValue(source, 'isSanitized') === true
    && optionalDataValue(source, 'greenfieldMode') !== true
  ));
  const { restorationAvailable } = scanRestorationData(stateBag);

  return Object.freeze({
    mode: sanitizedEligible
      ? PROJECT_SECURITY_MODES.SANITIZED
      : PROJECT_SECURITY_MODES.UNSANITIZED,
    sanitizedEligible,
    reversibleAvailable: sanitizedEligible && restorationAvailable,
    restorationAvailable,
  });
}

export function classifyProjectSecurity(stateBag) {
  return fixedBoundary(() => classifyProjectSecurityInternal(stateBag));
}

export function prepareSanitizedProjectState(stateBag) {
  return fixedBoundary(() => {
    const classification = classifyProjectSecurityInternal(stateBag);
    if (!classification.sanitizedEligible) {
      throw new ProjectSecurityError('unsanitized_source');
    }
    const { originals } = scanRestorationData(stateBag);
    return {
      state: cloneValidated(stateBag, true),
      originals: [...originals].sort(),
    };
  });
}

export function prepareUnsanitizedProjectState(stateBag) {
  return fixedBoundary(() => {
    walk(stateBag, () => {});
    if (!assertPlainObject(stateBag)) throw new ProjectSecurityError('unsafe_state');
    const { restorationAvailable } = scanRestorationData(stateBag);
    return {
      state: cloneValidated(stateBag),
      restorationAvailable,
    };
  });
}

function validateOriginals(originals) {
  if (!Array.isArray(originals)) throw new ProjectSecurityError('invalid_restoration');
  const length = ownDescriptor(originals, 'length')?.value;
  if (!Number.isSafeInteger(length) || ownPropertyNames(originals).length !== length + 1) {
    throw new ProjectSecurityError('invalid_restoration');
  }
  const validated = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = ownDescriptor(originals, String(index));
    const original = descriptor?.value;
    if (!descriptor || descriptor.get || descriptor.set
        || typeof original !== 'string' || original.length === 0
        || utf8Length(original) > MAX_RESTORATION_ORIGINAL_BYTES) {
      throw new ProjectSecurityError('invalid_restoration');
    }
    validated.push(original);
  }
  return validated;
}

function isSnmpCommunityName(path, parent) {
  if (path.at(-1) !== 'name'
      || !path.some(segment => String(segment).replace(/[^a-z0-9]/gi, '').toLowerCase() === 'snmpconfig')
      || !assertPlainObject(parent)) {
    return false;
  }
  const type = optionalDataValue(parent, 'type');
  return typeof type === 'string' && normalizedType(type) === 'community';
}

function isStructuredSecretPath(path, parent) {
  const key = path.at(-1) || '';
  if (isSecretBearingKey(key) || path.slice(0, -1).some(isSecretBearingKey)) return true;
  return isSnmpCommunityName(path, parent);
}

function assertPlainRoot(value) {
  if (!assertPlainObject(value)) throw new ProjectSecurityError('unsafe_state');
}

export function assertSanitizedProjectSafe(project, originals) {
  return fixedBoundary(() => {
    const validatedOriginals = validateOriginals(originals);
    assertPlainRoot(project);
    walk(project, (value, path, parent) => {
      if (path.includes('sanitizationTable')) {
        throw new ProjectSecurityError('original_leak');
      }
      if (typeof value !== 'string') return;
      if (findSecretsInText(value).length > 0) {
        throw new ProjectSecurityError('secret_leak');
      }
      if (isStructuredSecretPath(path, parent)
          && value
          && !isSanitizedSecretValue(value)) {
        throw new ProjectSecurityError('secret_leak');
      }
      if (validatedOriginals.some(original => value.includes(original))) {
        throw new ProjectSecurityError('original_leak');
      }
    });

    let serialized;
    try {
      serialized = JSON.stringify(project, null, 2);
    } catch {
      throw new ProjectSecurityError('unsafe_state');
    }
    if (utf8Length(serialized) > MAX_PROJECT_PLAINTEXT_BYTES) {
      throw new ProjectSecurityError('oversized_project');
    }
    for (const original of validatedOriginals) {
      const escaped = JSON.stringify(original).slice(1, -1);
      if (serialized.includes(original) || serialized.includes(escaped)) {
        throw new ProjectSecurityError('original_leak');
      }
    }
    if (serialized.includes('"sanitizationTable"')) {
      throw new ProjectSecurityError('original_leak');
    }
    if (findSecretsInText(serialized).length > 0) {
      throw new ProjectSecurityError('secret_leak');
    }
    return serialized;
  });
}

export function boundedProjectStringify(project) {
  return fixedBoundary(() => {
    assertPlainRoot(project);
    walk(project, () => {});
    let serialized;
    try {
      serialized = JSON.stringify(project, null, 2);
    } catch {
      throw new ProjectSecurityError('unsafe_state');
    }
    if (utf8Length(serialized) > MAX_PROJECT_PLAINTEXT_BYTES) {
      throw new ProjectSecurityError('oversized_project');
    }
    return serialized;
  });
}

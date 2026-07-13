import {
  findSecretsInText,
  isSanitizedSecretValue,
  isSecretBearingKey,
} from './secret-detection.js';
import {
  CURRENT_VERSION,
  buildProjectCore,
  validateProjectStateCore,
} from './project-io.js';
import {
  ProjectCryptoError,
  decryptReversibleEnvelope,
  encryptReversiblePayload,
  inspectEncryptedEnvelope,
} from './project-crypto.js';

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
const BARE_KEY_SECRET_CONTEXTS = new Set([
  'aaa', 'aaaconfig', 'aaaserver', 'aaaservers',
  'radius', 'radiusserver', 'radiusservers',
  'tacacs', 'tacacsserver', 'tacacsservers',
  'tacplus', 'tacplusserver', 'tacplusservers',
  'vpn', 'vpntunnel', 'vpntunnels',
  'ike', 'ikegateway', 'ikegateways', 'ikepolicy', 'ikepolicies',
  'ikeproposal', 'ikeproposals',
  'cert', 'certificate', 'certificates',
  'certificatecontainer', 'certificatecontainers',
]);
const TEXT_ENCODER = new TextEncoder();
const PROJECT_DOWNLOAD_SNAPSHOTS = new WeakMap();

const ERROR_MESSAGES = Object.freeze({
  unsafe_state: 'Project state contains an unsupported value.',
  invalid_restoration: 'Project restoration data is invalid.',
  unsanitized_source: 'Sanitized export requires every populated source to be sanitized.',
  original_leak: 'Sanitized export was blocked because an original value remains.',
  secret_leak: 'Sanitized export was blocked because secret-bearing content remains.',
  oversized_project: 'Project data exceeds the supported size limit.',
  invalid_confirmation: 'Project export confirmation is invalid.',
  unsupported_mode: 'Project security mode is not supported.',
  unsupported_version: 'Project file version is not supported.',
  invalid_project: 'Project file is invalid.',
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
  if (normalizedType(key) === 'key') {
    const pathHasContext = path.slice(0, -1)
      .some(segment => BARE_KEY_SECRET_CONTEXTS.has(normalizedType(segment)));
    const siblingType = assertPlainObject(parent) ? optionalDataValue(parent, 'type') : undefined;
    const typeHasContext = typeof siblingType === 'string'
      && BARE_KEY_SECRET_CONTEXTS.has(normalizedType(siblingType));
    if (pathHasContext || typeHasContext) {
      return true;
    }
  }
  return isSnmpCommunityName(path, parent);
}

function isNonEmptyScalar(value) {
  return value !== null
    && typeof value !== 'object'
    && (typeof value !== 'string' || value.length > 0);
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
      if (isStructuredSecretPath(path, parent)
          && isNonEmptyScalar(value)
          && (typeof value !== 'string' || !isSanitizedSecretValue(value))) {
        throw new ProjectSecurityError('secret_leak');
      }
      if (typeof value !== 'string') return;
      if (findSecretsInText(value).length > 0) {
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

const SANITIZED_METADATA = Object.freeze({
  schema: 1,
  mode: PROJECT_SECURITY_MODES.SANITIZED,
  containsOriginals: false,
  reversible: false,
  restorationAvailable: false,
});
const PLAINTEXT_OUTER_KEYS = Object.freeze([
  'fpic_version', 'name', 'savedAt', 'security', 'state',
]);
const PLAINTEXT_SECURITY_KEYS = Object.freeze([
  'schema', 'mode', 'containsOriginals', 'reversible', 'restorationAvailable',
]);

function unsanitizedMetadata(restorationAvailable) {
  return Object.freeze({
    schema: 1,
    mode: PROJECT_SECURITY_MODES.UNSANITIZED,
    containsOriginals: true,
    reversible: false,
    restorationAvailable: restorationAvailable === true,
  });
}

function legacyMetadata(mode, restorationAvailable) {
  if (mode === PROJECT_SECURITY_MODES.SANITIZED) return SANITIZED_METADATA;
  return Object.freeze({
    schema: 1,
    mode,
    containsOriginals: true,
    reversible: false,
    restorationAvailable: restorationAvailable === true,
  });
}

function buildReversiblePayload(stateBag, name) {
  const prepared = prepareUnsanitizedProjectState(stateBag);
  return {
    payloadSchema: 1,
    name,
    savedAt: new Date().toISOString(),
    sourceMode: PROJECT_SECURITY_MODES.SANITIZED,
    state: { ...prepared.state, projectSecurityMode: PROJECT_SECURITY_MODES.REVERSIBLE },
  };
}

function projectFilename(name, mode) {
  const base = String(name).replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^[-_.]+|[-_.]+$/g, '').slice(0, 100) || 'project';
  const suffix = mode === PROJECT_SECURITY_MODES.SANITIZED
    ? 'sanitized.fpic.json'
    : mode === PROJECT_SECURITY_MODES.REVERSIBLE
      ? 'reversible.fpic.enc.json'
      : 'unsanitized.fpic.json';
  return `${base}.${suffix}`;
}

async function serializeProjectExportInternal(stateBag, name, options) {
  const classification = classifyProjectSecurity(stateBag);
  if (options.mode === PROJECT_SECURITY_MODES.SANITIZED) {
    const prepared = prepareSanitizedProjectState(stateBag);
    const project = buildProjectCore(
      { ...prepared.state, projectSecurityMode: PROJECT_SECURITY_MODES.SANITIZED },
      name,
      SANITIZED_METADATA,
    );
    return {
      serialized: assertSanitizedProjectSafe(project, prepared.originals),
      filename: projectFilename(name, PROJECT_SECURITY_MODES.SANITIZED),
      security: project.security,
    };
  }
  if (options.mode === PROJECT_SECURITY_MODES.REVERSIBLE) {
    if (!classification.reversibleAvailable) {
      throw new ProjectSecurityError('invalid_restoration');
    }
    if (options.acknowledgement !== true
        || options.passphrase !== options.confirmationPassphrase) {
      throw new ProjectSecurityError('invalid_confirmation');
    }
    const payload = buildReversiblePayload(stateBag, name);
    const envelope = await encryptReversiblePayload(payload, options.passphrase);
    return {
      serialized: JSON.stringify(envelope, null, 2),
      filename: projectFilename(name, PROJECT_SECURITY_MODES.REVERSIBLE),
      security: envelope.security,
    };
  }
  if (options.mode === PROJECT_SECURITY_MODES.UNSANITIZED) {
    if (options.confirmation !== 'EXPORT UNSANITIZED') {
      throw new ProjectSecurityError('invalid_confirmation');
    }
    const prepared = prepareUnsanitizedProjectState(stateBag);
    const project = buildProjectCore(
      { ...prepared.state, projectSecurityMode: PROJECT_SECURITY_MODES.UNSANITIZED },
      name,
      unsanitizedMetadata(false),
    );
    const finalState = prepareUnsanitizedProjectState(project.state);
    project.state = finalState.state;
    project.security = unsanitizedMetadata(finalState.restorationAvailable);
    return {
      serialized: boundedProjectStringify(project),
      filename: projectFilename(name, PROJECT_SECURITY_MODES.UNSANITIZED),
      security: project.security,
    };
  }
  throw new ProjectSecurityError('unsupported_mode');
}

export async function serializeProjectExport(stateBag, name, options = {}) {
  try {
    const result = await serializeProjectExportInternal(stateBag, name, options);
    const snapshot = Object.freeze({
      serialized: result.serialized,
      filename: result.filename,
      security: Object.freeze({ mode: result.security.mode }),
    });
    PROJECT_DOWNLOAD_SNAPSHOTS.set(result, snapshot);
    return result;
  } catch (error) {
    if (error instanceof ProjectSecurityError) {
      throw new ProjectSecurityError(error.code);
    }
    if (error instanceof ProjectCryptoError) {
      throw new ProjectCryptoError(error.code);
    }
    throw new ProjectSecurityError('invalid_project');
  }
}

export function consumeValidatedProjectDownload(result) {
  try {
    if (result === null || typeof result !== 'object') {
      throw new ProjectSecurityError('invalid_project');
    }
    const snapshot = PROJECT_DOWNLOAD_SNAPSHOTS.get(result);
    if (!snapshot) throw new ProjectSecurityError('invalid_project');
    return snapshot;
  } catch {
    throw new ProjectSecurityError('invalid_project');
  }
}

function hasExactKeys(value, expectedKeys) {
  if (!assertPlainObject(value) || ownPropertySymbols(value).length > 0) return false;
  const names = ownPropertyNames(value);
  return names.length === expectedKeys.length
    && names.every(key => expectedKeys.includes(key))
    && expectedKeys.every(key => {
      const descriptor = ownDescriptor(value, key);
      return descriptor && !descriptor.get && !descriptor.set && descriptor.enumerable;
    });
}

function assertCanonicalTimestamp(value) {
  if (typeof value !== 'string') throw new ProjectSecurityError('invalid_project');
  let canonical;
  try {
    canonical = new Date(value).toISOString();
  } catch {
    throw new ProjectSecurityError('invalid_project');
  }
  if (canonical !== value) throw new ProjectSecurityError('invalid_project');
}

function assertPlaintextOuter(project) {
  if (!hasExactKeys(project, PLAINTEXT_OUTER_KEYS)
      || project.fpic_version !== CURRENT_VERSION
      || typeof project.name !== 'string'
      || project.name.length === 0
      || utf8Length(project.name) > 1024
      || !assertPlainObject(project.state)
      || !hasExactKeys(project.security, PLAINTEXT_SECURITY_KEYS)) {
    throw new ProjectSecurityError('invalid_project');
  }
  assertCanonicalTimestamp(project.savedAt);
}

function assertPlaintextMetadata(security, mode) {
  const valid = security.schema === 1
    && security.mode === mode
    && security.reversible === false
    && typeof security.restorationAvailable === 'boolean'
    && (mode === PROJECT_SECURITY_MODES.SANITIZED
      ? security.containsOriginals === false && security.restorationAvailable === false
      : security.containsOriginals === true);
  if (!valid) throw new ProjectSecurityError('invalid_project');
}

function parseProjectText(serialized) {
  if (typeof serialized !== 'string') throw new ProjectSecurityError('invalid_project');
  if (serialized.length > MAX_PROJECT_FILE_BYTES) {
    throw new ProjectSecurityError('oversized_project');
  }
  let byteLength;
  try {
    byteLength = utf8Length(serialized);
  } catch {
    throw new ProjectSecurityError('invalid_project');
  }
  if (byteLength > MAX_PROJECT_FILE_BYTES) {
    throw new ProjectSecurityError('oversized_project');
  }
  let parsed;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new ProjectSecurityError('invalid_project');
  }
  if (!assertPlainObject(parsed)) throw new ProjectSecurityError('invalid_project');
  return { parsed, byteLength };
}

function isRecognizedEncryptedProject(parsed) {
  return parsed.fpic_version === CURRENT_VERSION
    && assertPlainObject(parsed.security)
    && optionalDataValue(parsed.security, 'mode') === PROJECT_SECURITY_MODES.REVERSIBLE;
}

function normalizeSanitizedRestorationState(state) {
  const clone = cloneValidated(state);
  clone.sanitizationTable = null;
  if (Array.isArray(clone.configSlots)) {
    clone.configSlots = clone.configSlots.map(slot => {
      if (!assertPlainObject(slot)) throw new ProjectSecurityError('invalid_project');
      return { ...slot, sanitizationTable: null };
    });
  }
  return clone;
}

function validateStateCoreForImport(project) {
  try {
    return validateProjectStateCore(project);
  } catch {
    throw new ProjectSecurityError('invalid_project');
  }
}

function validateSanitizedPlaintext(project) {
  assertPlaintextOuter(project);
  assertPlaintextMetadata(project.security, PROJECT_SECURITY_MODES.SANITIZED);
  const classification = classifyProjectSecurity(project.state);
  if (!classification.sanitizedEligible || classification.restorationAvailable) {
    throw new ProjectSecurityError('invalid_project');
  }
  assertSanitizedProjectSafe(project, []);
  const result = validateStateCoreForImport(project);
  result.project.state = normalizeSanitizedRestorationState(result.project.state);
  result.project.security = SANITIZED_METADATA;
  return result;
}

function validateUnsanitizedPlaintext(project) {
  assertPlaintextOuter(project);
  assertPlaintextMetadata(project.security, PROJECT_SECURITY_MODES.UNSANITIZED);
  const prepared = prepareUnsanitizedProjectState(project.state);
  if (prepared.restorationAvailable !== project.security.restorationAvailable) {
    throw new ProjectSecurityError('invalid_project');
  }
  const result = validateStateCoreForImport({ ...project, state: prepared.state });
  result.project.security = unsanitizedMetadata(prepared.restorationAvailable);
  return result;
}

function classifyLegacyProject(project) {
  const prepared = prepareUnsanitizedProjectState(project.state);
  const unsanitized = () => ({
    mode: PROJECT_SECURITY_MODES.UNSANITIZED,
    requiresConfirmation: true,
    restorationAvailable: prepared.restorationAvailable,
    state: prepared.state,
  });
  if (project.state.isSanitized === true && prepared.restorationAvailable) {
    return {
      mode: PROJECT_SECURITY_MODES.LEGACY,
      requiresConfirmation: true,
      restorationAvailable: true,
      state: prepared.state,
    };
  }
  if (project.state.isSanitized === true) {
    const classification = classifyProjectSecurity(prepared.state);
    if (!classification.sanitizedEligible) return unsanitized();
    const sanitized = prepareSanitizedProjectState(project.state);
    const candidate = {
      fpic_version: CURRENT_VERSION,
      name: typeof project.name === 'string' ? project.name : 'project',
      savedAt: typeof project.savedAt === 'string'
        ? project.savedAt
        : new Date(0).toISOString(),
      security: SANITIZED_METADATA,
      state: sanitized.state,
    };
    try {
      assertSanitizedProjectSafe(candidate, sanitized.originals);
    } catch (error) {
      if (error instanceof ProjectSecurityError
          && ['secret_leak', 'original_leak', 'unsanitized_source'].includes(error.code)) {
        return unsanitized();
      }
      throw error;
    }
    return {
      mode: PROJECT_SECURITY_MODES.SANITIZED,
      requiresConfirmation: false,
      restorationAvailable: false,
      state: sanitized.state,
    };
  }
  return unsanitized();
}

function inspectLegacyProject(project) {
  const classification = classifyLegacyProject(project);
  const security = legacyMetadata(
    classification.mode,
    classification.restorationAvailable,
  );
  const result = validateStateCoreForImport({
    ...project,
    security,
    state: classification.state,
  });
  result.project.security = security;
  if (classification.mode === PROJECT_SECURITY_MODES.SANITIZED) {
    result.project.state = normalizeSanitizedRestorationState(result.project.state);
  }
  return {
    kind: classification.mode,
    security,
    envelope: result.project,
    warnings: result.warnings,
    requiresConfirmation: classification.requiresConfirmation,
  };
}

function inspectParsedProject(parsed) {
  if (!Number.isSafeInteger(parsed.fpic_version) || parsed.fpic_version < 1) {
    throw new ProjectSecurityError('invalid_project');
  }
  if (parsed.fpic_version > CURRENT_VERSION) {
    throw new ProjectSecurityError('unsupported_version');
  }
  if (parsed.fpic_version < CURRENT_VERSION) return inspectLegacyProject(parsed);

  const mode = parsed.security?.mode;
  if (mode === PROJECT_SECURITY_MODES.REVERSIBLE) {
    const envelope = inspectEncryptedEnvelope(parsed);
    return {
      kind: PROJECT_SECURITY_MODES.REVERSIBLE,
      security: envelope.security,
      envelope,
      warnings: [],
      requiresConfirmation: true,
    };
  }
  if (mode === PROJECT_SECURITY_MODES.SANITIZED) {
    const result = validateSanitizedPlaintext(parsed);
    return {
      kind: mode,
      security: SANITIZED_METADATA,
      envelope: result.project,
      warnings: result.warnings,
      requiresConfirmation: false,
    };
  }
  if (mode === PROJECT_SECURITY_MODES.UNSANITIZED) {
    const result = validateUnsanitizedPlaintext(parsed);
    return {
      kind: mode,
      security: result.project.security,
      envelope: result.project,
      warnings: result.warnings,
      requiresConfirmation: true,
    };
  }
  throw new ProjectSecurityError('invalid_project');
}

function inspectProjectSource(source) {
  if (source.byteLength > MAX_PROJECT_PLAINTEXT_BYTES
      && !isRecognizedEncryptedProject(source.parsed)) {
    throw new ProjectSecurityError('oversized_project');
  }
  return inspectParsedProject(source.parsed);
}

export function inspectProjectImport(serialized) {
  let source;
  try {
    source = parseProjectText(serialized);
  } catch (error) {
    if (error instanceof ProjectSecurityError
        && ['unsupported_version', 'oversized_project'].includes(error.code)) {
      throw new ProjectSecurityError(error.code);
    }
    throw new ProjectSecurityError('invalid_project');
  }
  const recognizedEncrypted = isRecognizedEncryptedProject(source.parsed);
  try {
    return inspectProjectSource(source);
  } catch (error) {
    if (recognizedEncrypted) throw new ProjectCryptoError('decryption_failed');
    if (error instanceof ProjectSecurityError
        && ['unsupported_version', 'oversized_project'].includes(error.code)) {
      throw new ProjectSecurityError(error.code);
    }
    throw new ProjectSecurityError('invalid_project');
  }
}

function extractImportPassphrase(options) {
  try {
    if (!assertPlainObject(options) || ownPropertySymbols(options).length > 0) {
      throw new ProjectSecurityError('invalid_project');
    }
    const names = ownPropertyNames(options);
    if (names.length > 1 || names.some(key => key !== 'passphrase')) {
      throw new ProjectSecurityError('invalid_project');
    }
    if (names.length === 0) return undefined;
    const descriptor = ownDescriptor(options, 'passphrase');
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
      throw new ProjectSecurityError('invalid_project');
    }
    return descriptor.value;
  } catch {
    throw new ProjectSecurityError('invalid_project');
  }
}

async function openProjectImportInternal(serialized, options) {
  const source = parseProjectText(serialized);
  const recognizedEncrypted = isRecognizedEncryptedProject(source.parsed);
  try {
    const passphrase = extractImportPassphrase(options);
    const inspected = inspectProjectSource(source);
    if (inspected.kind !== PROJECT_SECURITY_MODES.REVERSIBLE) {
      return {
        project: inspected.envelope,
        security: inspected.security,
        warnings: inspected.warnings,
        requiresConfirmation: inspected.requiresConfirmation,
      };
    }

    const payload = await decryptReversibleEnvelope(inspected.envelope, passphrase);
    const classification = classifyProjectSecurity(payload.state);
    if (!classification.sanitizedEligible || !classification.reversibleAvailable) {
      throw new ProjectSecurityError('invalid_project');
    }
    const sanitized = prepareSanitizedProjectState(payload.state);
    const candidate = {
      fpic_version: CURRENT_VERSION,
      name: payload.name,
      savedAt: payload.savedAt,
      security: SANITIZED_METADATA,
      state: {
        ...sanitized.state,
        projectSecurityMode: PROJECT_SECURITY_MODES.SANITIZED,
      },
    };
    assertSanitizedProjectSafe(candidate, sanitized.originals);

    const prepared = prepareUnsanitizedProjectState(payload.state);
    const result = validateStateCoreForImport({
      fpic_version: CURRENT_VERSION,
      name: payload.name,
      savedAt: payload.savedAt,
      security: inspected.security,
      state: prepared.state,
    });
    result.project.security = inspected.security;
    return {
      project: result.project,
      security: inspected.security,
      warnings: result.warnings,
      requiresConfirmation: true,
    };
  } catch (error) {
    if (recognizedEncrypted) throw new ProjectCryptoError('decryption_failed');
    throw error;
  }
}

export async function openProjectImport(serialized, options = {}) {
  try {
    return await openProjectImportInternal(serialized, options);
  } catch (error) {
    if (error instanceof ProjectSecurityError) {
      throw new ProjectSecurityError(error.code);
    }
    if (error instanceof ProjectCryptoError) {
      throw new ProjectCryptoError(error.code);
    }
    throw new ProjectSecurityError('invalid_project');
  }
}

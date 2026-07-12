import { sanitizeJunosName } from '../parsers/parser-utils.js';

export const JUNOS_IDENTIFIER_MAPPING_VERSION = 1;

const FNV_OFFSET = 14695981039346656037n;
const FNV_PRIME = 1099511628211n;
const FNV_MASK = 0xffffffffffffffffn;
const MAX_CONFLICT_ROUNDS = 32;
const UNSAFE_CONTROL = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/u;
const JUNOS_IDENTIFIER = /^[A-Za-z][A-Za-z0-9._-]{0,62}$/;

const ENTRY_FIELDS = [
  'context', 'namespace', 'kind', 'sourceName', 'outputName',
  'definitionPath', 'referencePaths', 'resolution',
];
const MAPPING_FIELDS = ['entries', 'version'];
const RESOLUTIONS = new Set([
  'unchanged', 'collision-renamed', 'generated',
  'generated-collision-renamed', 'unresolved-reference',
  'unresolved-collision-renamed',
]);

const ERROR_DETAIL_FIELDS = [
  'namespace', 'context', 'sourceName', 'definitionPaths',
  'referencePaths', 'reason',
];

function safeErrorScalar(value) {
  if (!['string', 'number', 'boolean'].includes(typeof value)) return undefined;
  if (typeof value === 'number' && !Number.isFinite(value)) return undefined;
  const text = String(value);
  return UNSAFE_CONTROL.test(text) ? undefined : text;
}

/** A blocking identifier-planning error that never retains configuration artifacts. */
export class JunosIdentifierPlanningError extends Error {
  constructor(code, details = {}) {
    const safeCode = safeErrorScalar(code) || 'identifier_planning_failed';
    super(`Junos identifier planning failed (${safeCode}).`);
    this.name = 'JunosIdentifierPlanningError';
    this.code = safeCode;

    for (const field of ERROR_DETAIL_FIELDS) {
      const value = details?.[field];
      if (field.endsWith('Paths')) {
        this[field] = Array.isArray(value)
          ? value.map(safeErrorScalar).filter(item => item !== undefined)
          : undefined;
      } else {
        this[field] = safeErrorScalar(value);
      }
    }
  }
}

function fail(code, details = {}) {
  throw new JunosIdentifierPlanningError(code, details);
}

function invalidMapping(reason) {
  fail('invalid_identifier_mapping', { reason });
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortedUnique(values) {
  return [...new Set(values)].sort(compareStrings);
}

function semanticKey(...parts) {
  return parts.join('\0');
}

function safeScalar(value, field, { allowEmpty = false } = {}) {
  const valueType = typeof value;
  if (!['string', 'number', 'boolean'].includes(valueType)) {
    fail('missing_catalog_coverage', { reason: `invalid ${field} metadata` });
  }
  if (valueType === 'number' && !Number.isFinite(value)) {
    fail('missing_catalog_coverage', { reason: `invalid ${field} metadata` });
  }
  const text = String(value);
  if (UNSAFE_CONTROL.test(text) || (!allowEmpty && text.length === 0)) {
    fail('missing_catalog_coverage', { reason: `invalid ${field} metadata` });
  }
  return text;
}

function mappingScalar(value, field, { allowEmpty = false } = {}) {
  if (typeof value !== 'string'
      || UNSAFE_CONTROL.test(value)
      || (!allowEmpty && value.length === 0)) {
    invalidMapping(`invalid ${field}`);
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function fnv1a64(value) {
  let hash = FNV_OFFSET;
  for (const byte of new TextEncoder().encode(value)) {
    hash ^= BigInt(byte);
    hash = (hash * FNV_PRIME) & FNV_MASK;
  }
  return hash;
}

function suffixFor(identity, retry, hash64 = fnv1a64) {
  const input = ['junos-id-v1', identity.context, identity.namespace,
    identity.kind, identity.stableKey, String(retry)].join('\0');
  const hash = hash64(input);
  if (typeof hash !== 'bigint' || hash < 0n || hash > FNV_MASK) {
    fail('allocation_failed', {
      context: identity.context,
      namespace: identity.namespace,
      reason: 'hash function returned an invalid value',
    });
  }
  return hash.toString(36).padStart(13, '0');
}

function collisionName(base, suffix) {
  const prefix = base.slice(0, 63 - suffix.length - 1);
  return `${prefix}-${suffix}`;
}

function normalizeDefinition(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    fail('missing_catalog_coverage', { reason: 'invalid definition metadata' });
  }

  const generated = record.generated === true;
  if (record.generated !== true && record.generated !== false) {
    fail('missing_catalog_coverage', { reason: 'invalid generated metadata' });
  }

  const normalized = {
    catalogKey: safeScalar(record.catalogKey, 'catalog key'),
    context: safeScalar(record.context, 'context'),
    namespace: safeScalar(record.namespace, 'namespace'),
    kind: safeScalar(record.kind, 'kind'),
    sourceName: safeScalar(record.sourceName, 'source name', { allowEmpty: true }),
    definitionPath: safeScalar(record.definitionPath, 'definition path'),
    generated,
    role: generated ? safeScalar(record.role, 'generated role') : null,
    stableParentKey: generated
      ? safeScalar(record.stableParentKey, 'stable parent key')
      : null,
  };
  normalized.stableKey = generated
    ? semanticKey(normalized.stableParentKey, normalized.role)
    : normalized.sourceName;
  normalized.auditablePath = generated
    ? `${normalized.definitionPath}#generated:${normalized.role}`
    : normalized.definitionPath;
  return normalized;
}

function normalizeReference(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    fail('missing_catalog_coverage', { reason: 'invalid reference metadata' });
  }
  if (!Array.isArray(record.compatibleKinds) || record.compatibleKinds.length === 0) {
    fail('missing_catalog_coverage', { reason: 'invalid compatible kinds metadata' });
  }
  if (!Array.isArray(record.literals)) {
    fail('missing_catalog_coverage', { reason: 'invalid literal metadata' });
  }

  const compatibleKinds = record.compatibleKinds
    .map(kind => safeScalar(kind, 'compatible kind'));
  if (new Set(compatibleKinds).size !== compatibleKinds.length) {
    fail('missing_catalog_coverage', { reason: 'duplicate compatible kind metadata' });
  }

  const literals = record.literals
    .map(literal => safeScalar(literal, 'literal', { allowEmpty: true }));
  if (new Set(literals).size !== literals.length) {
    fail('missing_catalog_coverage', { reason: 'duplicate literal metadata' });
  }

  return {
    catalogKey: safeScalar(record.catalogKey, 'catalog key'),
    context: safeScalar(record.context, 'context'),
    namespace: safeScalar(record.namespace, 'namespace'),
    compatibleKinds: [...compatibleKinds].sort(compareStrings),
    sourceName: safeScalar(record.sourceName, 'source name', { allowEmpty: true }),
    referencePath: safeScalar(record.referencePath, 'reference path'),
    literals,
  };
}

function symbolSortKey(symbol) {
  return semanticKey(
    symbol.context,
    symbol.namespace,
    symbol.kind,
    symbol.stableKey,
    symbol.type,
  );
}

function mappingEntrySort(left, right) {
  return compareStrings(semanticKey(
    left.context,
    left.namespace,
    left.kind,
    left.sourceName,
    left.definitionPath ?? '',
  ), semanticKey(
    right.context,
    right.namespace,
    right.kind,
    right.sourceName,
    right.definitionPath ?? '',
  ));
}

function allocationFailure(group, reason = 'identifier uniqueness could not be proven') {
  fail('allocation_failed', {
    context: group[0]?.context,
    namespace: group[0]?.namespace,
    reason,
  });
}

function allocateNamespace(group, hash64) {
  const ordered = [...group].sort((left, right) => (
    compareStrings(symbolSortKey(left), symbolSortKey(right))
  ));
  const definitionsByBase = new Map();
  const unresolvedByBase = new Map();

  for (const symbol of ordered) {
    const target = symbol.type === 'unresolved' ? unresolvedByBase : definitionsByBase;
    const members = target.get(symbol.base) || [];
    members.push(symbol);
    target.set(symbol.base, members);
  }

  const fixed = new Map();
  const candidates = [];
  for (const members of definitionsByBase.values()) {
    if (members.length === 1) fixed.set(members[0].base, members[0]);
    else candidates.push(...members);
  }
  for (const members of unresolvedByBase.values()) {
    if (members.length === 1 && !fixed.has(members[0].base)) {
      fixed.set(members[0].base, members[0]);
    } else {
      candidates.push(...members);
    }
  }

  for (const [outputName, symbol] of fixed) symbol.outputName = outputName;
  const retryBySymbol = new Map(candidates.map(symbol => [symbol, 0]));

  for (let round = 0; candidates.length > 0 && round < MAX_CONFLICT_ROUNDS; round += 1) {
    const byCandidate = new Map();
    for (const symbol of candidates) {
      const suffix = suffixFor(symbol, retryBySymbol.get(symbol), hash64);
      const outputName = collisionName(symbol.base, suffix);
      const members = byCandidate.get(outputName) || [];
      members.push(symbol);
      byCandidate.set(outputName, members);
    }

    const conflicted = new Set();
    for (const [outputName, members] of byCandidate) {
      if (fixed.has(outputName) || members.length > 1) {
        for (const symbol of members) conflicted.add(symbol);
      }
    }

    if (conflicted.size === 0) {
      for (const [outputName, members] of byCandidate) members[0].outputName = outputName;
      break;
    }
    if (round === MAX_CONFLICT_ROUNDS - 1) allocationFailure(group);
    for (const symbol of conflicted) {
      retryBySymbol.set(symbol, retryBySymbol.get(symbol) + 1);
    }
  }

  const outputs = new Set();
  for (const symbol of ordered) {
    if (!symbol.outputName || outputs.has(symbol.outputName)) allocationFailure(group);
    outputs.add(symbol.outputName);
  }
}

function resolutionFor(symbol) {
  const renamed = symbol.outputName !== symbol.base;
  if (symbol.type === 'unresolved') {
    return renamed ? 'unresolved-collision-renamed' : 'unresolved-reference';
  }
  if (symbol.definition.generated) {
    return renamed ? 'generated-collision-renamed' : 'generated';
  }
  return renamed ? 'collision-renamed' : 'unchanged';
}

function missingLookup(kind, path) {
  const detailField = kind === 'reference' ? 'referencePaths' : 'definitionPaths';
  fail('missing_catalog_coverage', {
    [detailField]: [path],
    reason: `missing ${kind} lookup coverage`,
  });
}

/**
 * Build an immutable deterministic allocation plan from catalog records.
 */
export function createJunosIdentifierPlan({ definitions, references } = {}, options = {}) {
  if (!Array.isArray(definitions) || !Array.isArray(references)) {
    fail('missing_catalog_coverage', { reason: 'definitions and references must be arrays' });
  }
  const hash64 = options.hash64 || fnv1a64;
  if (typeof hash64 !== 'function') {
    fail('allocation_failed', { reason: 'hash function is unavailable' });
  }

  const normalizedDefinitions = definitions.map(normalizeDefinition);
  const normalizedReferences = references.map(normalizeReference);
  const definitionPaths = new Set();
  const generatedKeys = new Set();
  const semanticDefinitions = new Map();
  const definitionIndex = new Map();
  const symbols = [];

  for (const item of normalizedDefinitions) {
    const lookupKey = semanticKey(item.definitionPath, item.role ?? '');
    if (item.generated ? generatedKeys.has(lookupKey) : definitionPaths.has(item.definitionPath)) {
      fail('missing_catalog_coverage', {
        definitionPaths: [item.definitionPath],
        reason: 'duplicate definition lookup path',
      });
    }
    if (item.generated) generatedKeys.add(lookupKey);
    else definitionPaths.add(item.definitionPath);

    const duplicateKey = semanticKey(
      item.context, item.namespace, item.kind, item.stableKey,
    );
    const duplicate = semanticDefinitions.get(duplicateKey);
    if (duplicate) {
      fail('duplicate_definition', {
        context: item.context,
        namespace: item.namespace,
        sourceName: item.sourceName,
        definitionPaths: sortedUnique([duplicate.auditablePath, item.auditablePath]),
        reason: 'multiple definitions have the same stable identity',
      });
    }
    semanticDefinitions.set(duplicateKey, item);

    const sourceKey = semanticKey(item.context, item.namespace, item.sourceName);
    const sourceMatches = definitionIndex.get(sourceKey) || [];
    sourceMatches.push(item);
    definitionIndex.set(sourceKey, sourceMatches);

    symbols.push({
      type: 'definition',
      definition: item,
      context: item.context,
      namespace: item.namespace,
      kind: item.kind,
      sourceName: item.sourceName,
      stableKey: item.stableKey,
      base: sanitizeJunosName(item.sourceName),
      referencePaths: [],
      outputName: null,
    });
  }

  const symbolByDefinition = new Map(symbols.map(symbol => [symbol.definition, symbol]));
  const referenceBindings = new Map();
  const referencePaths = new Set();
  const unresolvedSymbols = new Map();

  for (const item of normalizedReferences) {
    if (referencePaths.has(item.referencePath)) {
      fail('missing_catalog_coverage', {
        referencePaths: [item.referencePath],
        reason: 'duplicate reference lookup path',
      });
    }
    referencePaths.add(item.referencePath);

    if (item.literals.includes(item.sourceName)) {
      referenceBindings.set(item.referencePath, item.sourceName);
      continue;
    }

    const sourceKey = semanticKey(item.context, item.namespace, item.sourceName);
    const matches = (definitionIndex.get(sourceKey) || [])
      .filter(match => item.compatibleKinds.includes(match.kind));
    if (matches.length > 1) {
      fail('ambiguous_reference', {
        context: item.context,
        namespace: item.namespace,
        sourceName: item.sourceName,
        definitionPaths: matches.map(match => match.auditablePath).sort(compareStrings),
        referencePaths: [item.referencePath],
        reason: 'reference matches more than one compatible definition',
      });
    }
    if (matches.length === 1) {
      const symbol = symbolByDefinition.get(matches[0]);
      symbol.referencePaths.push(item.referencePath);
      referenceBindings.set(item.referencePath, symbol);
      continue;
    }

    const compatibleKey = item.compatibleKinds.join('\0');
    const unresolvedKey = semanticKey(
      item.context, item.namespace, compatibleKey, item.sourceName,
    );
    let symbol = unresolvedSymbols.get(unresolvedKey);
    if (!symbol) {
      symbol = {
        type: 'unresolved',
        context: item.context,
        namespace: item.namespace,
        kind: item.compatibleKinds.join('|'),
        sourceName: item.sourceName,
        stableKey: semanticKey('unresolved', compatibleKey, item.sourceName),
        base: sanitizeJunosName(item.sourceName),
        referencePaths: [],
        outputName: null,
      };
      unresolvedSymbols.set(unresolvedKey, symbol);
      symbols.push(symbol);
    }
    symbol.referencePaths.push(item.referencePath);
    referenceBindings.set(item.referencePath, symbol);
  }

  const namespaces = new Map();
  for (const symbol of symbols) {
    const key = semanticKey(symbol.context, symbol.namespace);
    const group = namespaces.get(key) || [];
    group.push(symbol);
    namespaces.set(key, group);
  }
  for (const group of namespaces.values()) allocateNamespace(group, hash64);

  const definitionLookup = new Map();
  const generatedLookup = new Map();
  for (const symbol of symbols) {
    if (symbol.type !== 'definition') continue;
    if (symbol.definition.generated) {
      generatedLookup.set(
        semanticKey(symbol.definition.definitionPath, symbol.definition.role),
        symbol.outputName,
      );
    } else {
      definitionLookup.set(symbol.definition.definitionPath, symbol.outputName);
    }
  }
  const referenceLookup = new Map();
  for (const [path, binding] of referenceBindings) {
    referenceLookup.set(path, typeof binding === 'string' ? binding : binding.outputName);
  }

  const entries = symbols.map(symbol => ({
    context: symbol.context,
    namespace: symbol.namespace,
    kind: symbol.kind,
    sourceName: symbol.sourceName,
    outputName: symbol.outputName,
    definitionPath: symbol.type === 'unresolved'
      ? null
      : symbol.definition.auditablePath,
    referencePaths: sortedUnique(symbol.referencePaths),
    resolution: resolutionFor(symbol),
  })).sort(mappingEntrySort);
  const mapping = validateIdentifierMappings({
    version: JUNOS_IDENTIFIER_MAPPING_VERSION,
    entries,
  });

  const renamedDefinitions = symbols
    .filter(symbol => symbol.type === 'definition' && symbol.outputName !== symbol.base)
    .sort((left, right) => mappingEntrySort({
      ...left,
      definitionPath: left.definition.auditablePath,
    }, {
      ...right,
      definitionPath: right.definition.auditablePath,
    }));
  const warnings = renamedDefinitions.map(symbol => {
    const definitionPath = symbol.definition.auditablePath;
    return {
      type: 'warning',
      category: 'identifier',
      subType: 'identifier_collision',
      element: definitionPath,
      message: `Resolved ${symbol.namespace} identifier collision for "${symbol.sourceName}" as "${symbol.outputName}".`,
      suggestion: 'Review the identifier mapping before deployment.',
      context: symbol.context,
      namespace: symbol.namespace,
      sourceName: symbol.sourceName,
      normalizedBase: symbol.base,
      outputName: symbol.outputName,
      definitionPath,
      referenceCount: symbol.referencePaths.length,
    };
  });

  const plan = {
    mapping,
    warnings: deepFreeze(warnings),
    collisionCount: renamedDefinitions.length,
    nameForDefinition(path) {
      const safePath = safeErrorScalar(path);
      if (safePath === undefined || !definitionLookup.has(safePath)) {
        missingLookup('definition', safePath || 'unknown');
      }
      return definitionLookup.get(safePath);
    },
    nameForReference(path) {
      const safePath = safeErrorScalar(path);
      if (safePath === undefined || !referenceLookup.has(safePath)) {
        missingLookup('reference', safePath || 'unknown');
      }
      return referenceLookup.get(safePath);
    },
    nameForGenerated(path, role) {
      const safePath = safeErrorScalar(path);
      const safeRole = safeErrorScalar(role);
      const key = safePath !== undefined && safeRole !== undefined
        ? semanticKey(safePath, safeRole)
        : null;
      if (key === null || !generatedLookup.has(key)) {
        missingLookup('generated', safePath || 'unknown');
      }
      return generatedLookup.get(key);
    },
  };
  return Object.freeze(plan);
}

/** Validate, defensively copy, and deeply freeze persisted mapping metadata. */
export function validateIdentifierMappings(mapping) {
  if (!mapping || typeof mapping !== 'object' || Array.isArray(mapping)) {
    invalidMapping('mapping must be an object');
  }
  const mappingFields = Object.keys(mapping).sort(compareStrings);
  if (mappingFields.length !== MAPPING_FIELDS.length
      || mappingFields.some((field, index) => field !== MAPPING_FIELDS[index])) {
    invalidMapping('mapping fields are invalid');
  }
  if (mapping.version !== JUNOS_IDENTIFIER_MAPPING_VERSION) {
    invalidMapping('mapping version is unsupported');
  }
  if (!Array.isArray(mapping.entries)) invalidMapping('entries must be an array');

  const semanticDefinitions = new Set();
  const namespaceOutputs = new Set();
  const entries = mapping.entries.map(entry => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      invalidMapping('entry must be an object');
    }
    const fields = Object.keys(entry).sort(compareStrings);
    const allowedFields = [...ENTRY_FIELDS].sort(compareStrings);
    if (fields.length !== allowedFields.length
        || fields.some((field, index) => field !== allowedFields[index])) {
      invalidMapping('entry fields are invalid');
    }

    const context = mappingScalar(entry.context, 'context');
    const namespace = mappingScalar(entry.namespace, 'namespace');
    const kind = mappingScalar(entry.kind, 'kind');
    const sourceName = mappingScalar(entry.sourceName, 'source name', { allowEmpty: true });
    const outputName = mappingScalar(entry.outputName, 'output name');
    if (!JUNOS_IDENTIFIER.test(outputName)) invalidMapping('output name is invalid');
    if (!RESOLUTIONS.has(entry.resolution)) invalidMapping('resolution is invalid');

    const unresolved = entry.resolution.startsWith('unresolved-');
    let definitionPath = null;
    if (unresolved) {
      if (entry.definitionPath !== null) invalidMapping('unresolved definition path must be null');
    } else {
      definitionPath = mappingScalar(entry.definitionPath, 'definition path');
    }

    if (!Array.isArray(entry.referencePaths)) {
      invalidMapping('reference paths must be an array');
    }
    const referencePaths = entry.referencePaths.map(path => (
      mappingScalar(path, 'reference path')
    ));
    for (let index = 1; index < referencePaths.length; index += 1) {
      if (compareStrings(referencePaths[index - 1], referencePaths[index]) >= 0) {
        invalidMapping('reference paths must be sorted and unique');
      }
    }

    const base = sanitizeJunosName(sourceName);
    const renamed = outputName !== base;
    const shouldBeRenamed = new Set([
      'collision-renamed',
      'generated-collision-renamed',
      'unresolved-collision-renamed',
    ]).has(entry.resolution);
    if (renamed !== shouldBeRenamed) invalidMapping('resolution contradicts output name');

    const semanticDefinition = semanticKey(context, namespace, kind, sourceName);
    if (semanticDefinitions.has(semanticDefinition)) {
      invalidMapping('semantic definition is duplicated');
    }
    semanticDefinitions.add(semanticDefinition);

    const namespaceOutput = semanticKey(context, namespace, outputName);
    if (namespaceOutputs.has(namespaceOutput)) invalidMapping('output name is duplicated');
    namespaceOutputs.add(namespaceOutput);

    return {
      context,
      namespace,
      kind,
      sourceName,
      outputName,
      definitionPath,
      referencePaths,
      resolution: entry.resolution,
    };
  });

  return deepFreeze({
    version: JUNOS_IDENTIFIER_MAPPING_VERSION,
    entries,
  });
}

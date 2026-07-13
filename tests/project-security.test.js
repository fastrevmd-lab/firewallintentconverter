import { describe, expect, it } from 'vitest';
import {
  MAX_PROJECT_DEPTH,
  MAX_PROJECT_FILE_BYTES,
  MAX_PROJECT_NODES,
  MAX_PROJECT_PLAINTEXT_BYTES,
  PROJECT_SECURITY_MODES,
  ProjectSecurityError,
  assertSanitizedProjectSafe,
  boundedProjectStringify,
  classifyProjectSecurity,
  inspectProjectImport,
  openProjectImport,
  prepareSanitizedProjectState,
  prepareUnsanitizedProjectState,
  serializeProjectExport,
} from '../public/utils/project-security.js';
import { ProjectCryptoError } from '../public/utils/project-crypto.js';

const table = original => [{
  type: 'key',
  placeholder: 'SANITIZED_KEY_0',
  original,
}];

const sanitizedState = {
  configText: 'set system login password SANITIZED_KEY_0',
  intermediateConfig: { metadata: { note: 'safe' } },
  isSanitized: true,
  sanitizationTable: table('TOP-LEVEL-ORIGINAL'),
  mergeMode: true,
  configSlots: [{
    configText: 'set snmp community SANITIZED_COMMUNITY_0',
    intermediateConfig: { metadata: {} },
    isSanitized: true,
    sanitizationTable: table('NESTED-ORIGINAL'),
  }],
};

const projectFrom = (state, overrides = {}) => ({
  fpic_version: 5,
  name: 'safe',
  savedAt: '2026-07-12T00:00:00.000Z',
  security: {
    schema: 1,
    mode: 'sanitized',
    containsOriginals: false,
    reversible: false,
    restorationAvailable: false,
  },
  state,
  ...overrides,
});

function expectSecurityError(operation, code, message) {
  let thrown;
  try {
    operation();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(ProjectSecurityError);
  expect(thrown).toMatchObject({ code, message });
}

function seededRandom(seed) {
  let value = seed >>> 0;
  return () => {
    value = (value + 0x6D2B79F5) >>> 0;
    let mixed = value;
    mixed = Math.imul(mixed ^ (mixed >>> 15), mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 0x1_0000_0000;
  };
}

function nestedLeak(seed, marker) {
  const random = seededRandom(seed);
  let value = seed % 2 === 0
    ? { credentials: { radius_secret: marker } }
    : marker;
  const depth = 1 + Math.floor(random() * 5);
  for (let level = 0; level < depth; level += 1) {
    value = random() < 0.5
      ? [{ slot: level }, value]
      : { [`level_${level}_${Math.floor(random() * 10_000)}`]: value };
  }
  return value;
}

function randomizedNestedState(seed, marker) {
  const state = structuredClone(sanitizedState);
  state.sanitizationTable = table(marker);
  return { seed, state };
}

function injectFinalCandidateLeak(project, seed, marker) {
  const leak = nestedLeak(seed, marker);
  switch (seed % 6) {
    case 0:
      project.state.futureObjects = { [`seed_${seed}`]: leak };
      break;
    case 1:
      project.state.parseWarnings = [{ code: `seed-${seed}`, details: leak }];
      break;
    case 2:
      project.state.configSlots[0].future = { leak };
      break;
    case 3:
      project.state.interfaceMappings = { [`mapping_${seed}`]: { history: leak } };
      break;
    case 4:
      project.state.warningStatuses = { [`warning_${seed}`]: [leak] };
      break;
    default:
      project.state.intermediateConfig.metadata[`seed_${seed}`] = leak;
      break;
  }
}

function exportSanitizedFixture(fixture, marker) {
  const prepared = prepareSanitizedProjectState(fixture.state);
  const project = projectFrom(prepared.state);
  expect(JSON.stringify(project)).not.toContain('sanitizationTable');
  injectFinalCandidateLeak(project, fixture.seed, marker);
  return assertSanitizedProjectSafe(project, prepared.originals);
}

describe('project security boundary', () => {
  it('acceptance: merge slots cannot bypass sanitized eligibility', () => {
    expect(classifyProjectSecurity(sanitizedState)).toMatchObject({
      mode: 'sanitized',
      sanitizedEligible: true,
      reversibleAvailable: true,
      restorationAvailable: true,
    });
    expect(classifyProjectSecurity({
      ...sanitizedState,
      configSlots: [{ ...sanitizedState.configSlots[0], isSanitized: false }],
    })).toMatchObject({
      mode: 'unsanitized',
      sanitizedEligible: false,
    });
    expect(classifyProjectSecurity({
      ...sanitizedState,
      greenfieldMode: true,
      isSanitized: false,
    }).sanitizedEligible).toBe(false);
  });

  it('removes all restoration tables without mutating live state', () => {
    const before = structuredClone(sanitizedState);
    const prepared = prepareSanitizedProjectState(sanitizedState);
    expect(prepared.originals).toEqual(['NESTED-ORIGINAL', 'TOP-LEVEL-ORIGINAL']);
    expect(JSON.stringify(prepared.state)).not.toContain('sanitizationTable');
    expect(sanitizedState).toEqual(before);
  });

  it.each([
    ['metadata', project => { project.state.intermediateConfig.metadata.note = 'TOP-LEVEL-ORIGINAL'; }],
    ['warning', project => { project.state.parseWarnings = [{ message: 'NESTED-ORIGINAL' }]; }],
    ['raw secret syntax', project => { project.state.future = 'set password "RAW-SECRET"'; }],
    ['structured secret', project => { project.state.future = { radius_secret: 'RAW-SECRET' }; }],
  ])('rejects a leak injected into %s', (_label, mutate) => {
    const prepared = prepareSanitizedProjectState(sanitizedState);
    const project = {
      fpic_version: 5,
      name: 'safe',
      savedAt: '2026-07-12T00:00:00.000Z',
      security: {
        schema: 1, mode: 'sanitized', containsOriginals: false,
        reversible: false, restorationAvailable: false,
      },
      state: prepared.state,
    };
    mutate(project);
    expect(() => assertSanitizedProjectSafe(project, prepared.originals))
      .toThrow(ProjectSecurityError);
  });

  it('rejects originals and secret-bearing objects at deterministic nested paths for 200 seeds', () => {
    for (let seed = 1; seed <= 200; seed += 1) {
      const marker = 'ORIGINAL-MARKER-' + seed;
      const state = randomizedNestedState(seed, marker);
      expect(() => exportSanitizedFixture(state, marker), 'seed ' + seed)
        .toThrow(ProjectSecurityError);
    }
  });

  it.each([
    ['quote', 'ORIGINAL-"QUOTE"-MARKER'],
    ['backslash', 'ORIGINAL\\SLASH\\MARKER'],
    ['newline', 'ORIGINAL\nNEWLINE\nMARKER'],
    ['tab', 'ORIGINAL\tTAB\tMARKER'],
    ['control character', 'ORIGINAL-\u0001-MARKER'],
    ['lone surrogate', 'ORIGINAL-' + String.fromCharCode(0xD800) + '-MARKER'],
  ])('rejects raw and canonical JSON-escaped %s originals', (_label, marker) => {
    const prepared = prepareSanitizedProjectState({
      ...structuredClone(sanitizedState),
      sanitizationTable: table(marker),
    });
    const rawCandidate = projectFrom(prepared.state);
    rawCandidate.state.intermediateConfig.metadata.raw = `prefix:${marker}:suffix`;
    expect(() => assertSanitizedProjectSafe(rawCandidate, prepared.originals))
      .toThrow(ProjectSecurityError);

    const escapedCandidate = projectFrom(prepared.state);
    escapedCandidate.state.intermediateConfig.metadata[`prefix:${marker}:suffix`] = 'safe';
    const escaped = JSON.stringify(marker).slice(1, -1);
    expect(escaped).not.toBe(marker);
    expect(JSON.stringify(escapedCandidate)).toContain(escaped);
    expect(() => assertSanitizedProjectSafe(escapedCandidate, prepared.originals))
      .toThrow(ProjectSecurityError);
  });

  it.each([
    ['forward slash', 'ORIGINAL/SLASH/MARKER'],
    ['non-ASCII Unicode', 'ORIGINAL-秘密-🔐-MARKER'],
  ])('rejects raw UTF-8 %s originals without calling them escaped', (_label, marker) => {
    const prepared = prepareSanitizedProjectState({
      ...structuredClone(sanitizedState),
      sanitizationTable: table(marker),
    });
    expect(JSON.stringify(marker).slice(1, -1)).toBe(marker);
    const candidate = projectFrom(prepared.state);
    candidate.state.intermediateConfig.metadata.raw = `prefix:${marker}:suffix`;
    expect(() => assertSanitizedProjectSafe(candidate, prepared.originals))
      .toThrow(ProjectSecurityError);
  });

  it('acceptance: searches the complete file including outer metadata and nested objects', () => {
    const marker = 'COMPLETE-FILE-ORIGINAL';
    const prepared = prepareSanitizedProjectState({
      ...structuredClone(sanitizedState),
      sanitizationTable: table(marker),
    });
    const candidate = projectFrom(prepared.state, {
      metadata: { audit: [{ nested: { original: marker } }] },
    });
    expect(() => assertSanitizedProjectSafe(candidate, prepared.originals))
      .toThrow(expect.objectContaining({ code: 'original_leak' }));
  });

  it('exports the fixed modes and resource limits', () => {
    expect(PROJECT_SECURITY_MODES).toEqual({
      SANITIZED: 'sanitized',
      REVERSIBLE: 'reversible-encrypted',
      UNSANITIZED: 'unsanitized',
      LEGACY: 'legacy-secret-bearing',
    });
    expect(Object.isFrozen(PROJECT_SECURITY_MODES)).toBe(true);
    expect(MAX_PROJECT_PLAINTEXT_BYTES).toBe(48 * 1024 * 1024);
    expect(MAX_PROJECT_FILE_BYTES).toBe(65 * 1024 * 1024);
    expect(MAX_PROJECT_DEPTH).toBe(128);
    expect(MAX_PROJECT_NODES).toBe(1_000_000);
  });

  it('uses only fixed error codes and messages', () => {
    const expected = {
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
    };
    for (const [code, message] of Object.entries(expected)) {
      expect(new ProjectSecurityError(code)).toMatchObject({
        name: 'ProjectSecurityError', code, message,
      });
    }
    expect(new ProjectSecurityError('caller-controlled')).toMatchObject({
      name: 'ProjectSecurityError',
      code: 'unsafe_state',
      message: 'Project security validation failed.',
    });
  });

  it('ignores empty merge slots but requires at least one populated source', () => {
    expect(classifyProjectSecurity({
      ...sanitizedState,
      configSlots: [{
        configText: '  ', intermediateConfig: null, interfaceMappings: {}, isSanitized: false,
      }],
    })).toMatchObject({ mode: 'sanitized', sanitizedEligible: true });
    expect(classifyProjectSecurity({
      configText: '', intermediateConfig: null, interfaceMappings: {}, configSlots: [],
    })).toEqual({
      mode: 'unsanitized',
      sanitizedEligible: false,
      reversibleAvailable: false,
      restorationAvailable: false,
    });
  });

  it('deduplicates and code-unit sorts originals collected at any depth', () => {
    const state = structuredClone(sanitizedState);
    state.sanitizationTable = [
      ...table('z-original'),
      ...table('NESTED-ORIGINAL'),
      ...table('A-original'),
    ];
    state.future = { nested: { sanitizationTable: table('b-original') } };
    expect(prepareSanitizedProjectState(state).originals).toEqual([
      'A-original', 'NESTED-ORIGINAL', 'b-original', 'z-original',
    ]);
  });

  it('rejects sanitized preparation for raw or mixed populated sources', () => {
    expectSecurityError(
      () => prepareSanitizedProjectState({ ...sanitizedState, isSanitized: false }),
      'unsanitized_source',
      'Sanitized export requires every populated source to be sanitized.',
    );
  });

  it('prepares an unsanitized clone while preserving valid restoration data', () => {
    const state = structuredClone(sanitizedState);
    state.isSanitized = false;
    const prepared = prepareUnsanitizedProjectState(state);
    expect(prepared).toMatchObject({ restorationAvailable: true });
    expect(prepared.state).toEqual(state);
    expect(prepared.state).not.toBe(state);
    expect(prepared.state.sanitizationTable).not.toBe(state.sanitizationTable);
  });

  it.each([
    ['missing type', [{ placeholder: 'SANITIZED_KEY_0', original: 'original' }]],
    ['unknown field', [{ ...table('original')[0], extra: true }]],
    ['non-array table', {}],
    ['empty original', [{ ...table('original')[0], original: '' }]],
    ['non-boolean restore', [{ ...table('original')[0], restore: 'yes' }]],
    ['overlong type', [{ ...table('original')[0], type: 'x'.repeat(65) }]],
    ['overlong placeholder', [{ ...table('original')[0], placeholder: 'x'.repeat(1025) }]],
    ['overlong original', [{ ...table('original')[0], original: 'x'.repeat(1024 * 1024 + 1) }]],
  ])('rejects invalid restoration data: %s', (_label, sanitizationTable) => {
    expectSecurityError(
      () => classifyProjectSecurity({ ...sanitizedState, sanitizationTable }),
      'invalid_restoration',
      'Project restoration data is invalid.',
    );
  });

  it('measures restoration field limits in UTF-8 bytes', () => {
    expectSecurityError(
      () => classifyProjectSecurity({
        ...sanitizedState,
        sanitizationTable: [{ ...table('original')[0], type: '🔐'.repeat(17) }],
      }),
      'invalid_restoration',
      'Project restoration data is invalid.',
    );
  });

  it.each(['password', 'hash', 'key', 'community', 'certificate', 'cert'])
    ('never permits restore: true for secret type %s', type => {
      expectSecurityError(
        () => prepareUnsanitizedProjectState({
          value: 'populated',
          sanitizationTable: [{
            type: type.toUpperCase(),
            placeholder: 'SANITIZED_KEY_0',
            original: 'original',
            restore: true,
          }],
        }),
        'invalid_restoration',
        'Project restoration data is invalid.',
      );
    });

  it('allows explicitly restorable non-secret entries and non-restorable secret entries', () => {
    expect(prepareUnsanitizedProjectState({
      sanitizationTable: [
        { ...table('secret')[0], restore: false },
        { type: 'hostname', placeholder: 'SANITIZED_HOST_0', original: 'router', restore: true },
      ],
    }).restorationAvailable).toBe(true);
  });

  it.each([
    ['null root', null],
    ['undefined value', { value: undefined }],
    ['function value', { value: () => {} }],
    ['symbol value', { value: Symbol('unsafe') }],
    ['bigint value', { value: 1n }],
    ['NaN value', { value: Number.NaN }],
    ['positive infinity', { value: Number.POSITIVE_INFINITY }],
    ['negative infinity', { value: Number.NEGATIVE_INFINITY }],
    ['non-plain object', { value: new Date('2026-07-12T00:00:00.000Z') }],
    ['sparse array', { value: new Array(2) }],
    ['prototype key', JSON.parse('{"prototype":null}')],
    ['constructor key', JSON.parse('{"constructor":null}')],
    ['__proto__ key', JSON.parse('{"__proto__":null}')],
  ])('rejects unsupported shape: %s', (_label, value) => {
    expectSecurityError(
      () => boundedProjectStringify(value),
      'unsafe_state',
      'Project state contains an unsupported value.',
    );
  });

  it('rejects cycles', () => {
    const cycle = {};
    cycle.self = cycle;
    expectSecurityError(
      () => prepareUnsanitizedProjectState(cycle),
      'unsafe_state',
      'Project state contains an unsupported value.',
    );
  });

  it('rejects getters without invoking them', () => {
    let invoked = false;
    const value = {};
    Object.defineProperty(value, 'secret', {
      enumerable: true,
      get() {
        invoked = true;
        throw new Error('native getter detail');
      },
    });
    expectSecurityError(
      () => prepareUnsanitizedProjectState(value),
      'unsafe_state',
      'Project state contains an unsupported value.',
    );
    expect(invoked).toBe(false);
  });

  it('rejects depth 129', () => {
    const root = {};
    let cursor = root;
    for (let index = 0; index < MAX_PROJECT_DEPTH + 1; index += 1) {
      cursor.child = {};
      cursor = cursor.child;
    }
    expectSecurityError(
      () => boundedProjectStringify(root),
      'unsafe_state',
      'Project state contains an unsupported value.',
    );
  });

  it('enforces the real one-million-node ceiling without a test-only limit', () => {
    expectSecurityError(
      () => boundedProjectStringify({ values: new Array(MAX_PROJECT_NODES).fill(null) }),
      'unsafe_state',
      'Project state contains an unsupported value.',
    );
  });

  it.each([
    ['classification', () => classifyProjectSecurity('not-an-object')],
    ['sanitized preparation', () => prepareSanitizedProjectState(undefined)],
    ['unsanitized preparation', () => prepareUnsanitizedProjectState(() => {})],
    ['sanitized gate', () => assertSanitizedProjectSafe(null, [])],
    ['bounded serialization', () => boundedProjectStringify(Symbol('unsafe'))],
  ])('maps malformed caller input at %s to a fixed public error', (_label, operation) => {
    expectSecurityError(
      operation,
      'unsafe_state',
      'Project state contains an unsupported value.',
    );
  });

  it('rejects malformed known-original input with a fixed restoration error', () => {
    expectSecurityError(
      () => assertSanitizedProjectSafe(projectFrom({ safe: true }), 'not-an-array'),
      'invalid_restoration',
      'Project restoration data is invalid.',
    );
  });

  it('serializes safe unsanitized projects and enforces the UTF-8 byte limit', () => {
    expect(boundedProjectStringify({ name: 'safe' })).toBe(JSON.stringify({ name: 'safe' }, null, 2));
    expectSecurityError(
      () => boundedProjectStringify({ value: 'x'.repeat(MAX_PROJECT_PLAINTEXT_BYTES) }),
      'oversized_project',
      'Project data exceeds the supported size limit.',
    );
  });

  it('rejects restoration keys even when the table value is null', () => {
    expectSecurityError(
      () => assertSanitizedProjectSafe(projectFrom({ nested: { sanitizationTable: null } }), []),
      'original_leak',
      'Sanitized export was blocked because an original value remains.',
    );
  });

  it('rejects an original found only as a JSON-escaped property name', () => {
    const original = 'line one\n"quoted"';
    expectSecurityError(
      () => assertSanitizedProjectSafe(projectFrom({ [`prefix-${original}`]: 'safe' }), [original]),
      'original_leak',
      'Sanitized export was blocked because an original value remains.',
    );
  });

  it.each([
    ['SNMP community name', { snmp_config: [{ type: 'community', name: 'RAW-COMMUNITY' }] }],
    ['AAA server secret', { aaa_config: [{ type: 'radius', server: '192.0.2.1', secret: 'RAW-AAA' }] }],
    ['AAA server bare key', { aaa_config: [{ type: 'radius', key: 'RAW-AAA' }] }],
    ['VPN pre-shared key', { vpn_tunnels: [{ ike_gateway: { pre_shared_key: 'RAW-PSK' } }] }],
    ['VPN/IKE bare key', { vpn_tunnels: [{ ike_gateway: { key: 'RAW-VPN' } }] }],
    ['certificate private value', { certificates: [{ private_key: { value: 'RAW-PRIVATE' } }] }],
    ['certificate bare key', { certificates: [{ key: 'RAW-CERT' }] }],
  ])('rejects path-aware structured secret: %s', (_label, intermediateConfig) => {
    expectSecurityError(
      () => assertSanitizedProjectSafe(projectFrom({ intermediateConfig }), []),
      'secret_leak',
      'Sanitized export was blocked because secret-bearing content remains.',
    );
  });

  it.each([
    ['radius', { radius: { key: 'RAW-RADIUS' } }],
    ['tacacs', { tacacs: { key: 'RAW-TACACS' } }],
    ['tacplus', { tacplus: { key: 'RAW-TACPLUS' } }],
    ['vpn', { vpn: { key: 'RAW-VPN' } }],
    ['cert', { cert: { key: 'RAW-CERT' } }],
    ['certificates', { certificates: { key: 'RAW-CERTIFICATES' } }],
  ])('rejects a bare key in direct %s context', (_label, state) => {
    expectSecurityError(
      () => assertSanitizedProjectSafe(projectFrom(state), []),
      'secret_leak',
      'Sanitized export was blocked because secret-bearing content remains.',
    );
  });

  it.each(['radius', 'tacacs'])
    ('rejects a bare key when sibling type is %s', type => {
      expectSecurityError(
        () => assertSanitizedProjectSafe(projectFrom({
          servers: [{ type, key: 'RAW-SIBLING-KEY' }],
        }), []),
        'secret_leak',
        'Sanitized export was blocked because secret-bearing content remains.',
      );
    });

  it('allows a bare key in unrelated metadata', () => {
    const project = projectFrom({ metadata: { key: 'display-order' } });
    expect(assertSanitizedProjectSafe(project, [])).toBe(JSON.stringify(project, null, 2));
  });

  it.each([123456, 0, true, false])
    ('rejects non-string scalar %s under a secret-bearing path', value => {
      expectSecurityError(
        () => assertSanitizedProjectSafe(projectFrom({ password: value }), []),
        'secret_leak',
        'Sanitized export was blocked because secret-bearing content remains.',
      );
    });

  it.each(['', null])('allows empty secret field value %s', value => {
    const project = projectFrom({ password: value });
    expect(assertSanitizedProjectSafe(project, [])).toBe(JSON.stringify(project, null, 2));
  });

  it('accepts placeholders in secret fields and algorithm descriptors', () => {
    const project = projectFrom({
      intermediateConfig: {
        snmp_config: [{ type: 'community', name: 'SANITIZED_COMMUNITY_0' }],
        aaa_config: [{
          type: 'radius', secret: 'SANITIZED_KEY_0', key: 'SANITIZED_KEY_1',
        }],
        vpn_tunnels: [{
          ike_gateway: {
            pre_shared_key: 'SANITIZED_KEY_2', key: 'SANITIZED_KEY_3',
          },
          ike_proposal: { auth_method: 'pre-shared-keys' },
        }],
        certificates: [{
          private_key: { value: 'SANITIZED_CERT_0' }, key: 'SANITIZED_CERT_1',
        }],
        radius: { key: 'SANITIZED_KEY_4' },
        servers: [{ type: 'tacacs', key: 'SANITIZED_KEY_5' }],
      },
    });
    expect(assertSanitizedProjectSafe(project, [])).toBe(JSON.stringify(project, null, 2));
  });

  it('rejects unsupported export modes with a fixed non-reflective failure', async () => {
    await expect(serializeProjectExport(sanitizedState, 'safe', {
      mode: 'CALLER-CONTROLLED-MODE',
    })).rejects.toMatchObject({
      code: 'unsupported_mode',
      message: 'Project security mode is not supported.',
    });
  });

  it.each([
    ['null options', null],
    ['throwing mode getter', Object.defineProperty({}, 'mode', {
      enumerable: true,
      get() { throw new Error('SENSITIVE-GETTER-DETAIL'); },
    })],
  ])('maps malformed export options to a fixed failure: %s', async (_label, options) => {
    let error;
    try {
      await serializeProjectExport(sanitizedState, 'safe', options);
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({
      code: 'invalid_project',
      message: 'Project file is invalid.',
    });
    expect(error.message).not.toContain('SENSITIVE-GETTER-DETAIL');
  });

  it.each([
    ['non-string input', null],
    ['invalid JSON', '{"caller":"SENSITIVE-DETAIL"'],
    ['missing version', '{"state":{}}'],
    ['invalid version', '{"fpic_version":0,"state":{}}'],
  ])('rejects malformed import input without reflecting it: %s', (_label, serialized) => {
    let error;
    try {
      inspectProjectImport(serialized);
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({
      code: 'invalid_project',
      message: 'Project file is invalid.',
    });
    expect(error.message).not.toContain('SENSITIVE-DETAIL');
  });

  it('does not accept a decrypted reversible payload as plaintext v5', async () => {
    const plaintextPayload = JSON.stringify({
      payloadSchema: 1,
      name: 'private',
      savedAt: '2026-07-12T00:00:00.000Z',
      sourceMode: 'sanitized',
      state: sanitizedState,
    });
    expect(() => inspectProjectImport(plaintextPayload)).toThrow(expect.objectContaining({
      code: 'invalid_project',
    }));
    await expect(openProjectImport(plaintextPayload, {})).rejects.toMatchObject({
      code: 'invalid_project',
    });
  });

  it('safely rejects null import options and a throwing passphrase getter', async () => {
    const passphrase = 'correct horse battery staple';
    const exported = await serializeProjectExport(sanitizedState, 'backup', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase,
      confirmationPassphrase: passphrase,
      acknowledgement: true,
    });
    let getterCalls = 0;
    const throwingOptions = Object.defineProperty({}, 'passphrase', {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error('SENSITIVE-PASSPHRASE-GETTER');
      },
    });
    for (const options of [null, throwingOptions]) {
      let error;
      try {
        await openProjectImport(exported.serialized, options);
      } catch (caught) {
        error = caught;
      }
      expect(error).toBeInstanceOf(ProjectCryptoError);
      expect(error).toMatchObject({
        code: 'decryption_failed',
        message: 'Encrypted project could not be opened.',
      });
      expect(error.message).not.toContain('SENSITIVE-PASSPHRASE-GETTER');
    }
    expect(getterCalls).toBe(0);
  });

  it('acceptance: wrong passphrases fail with the uniform decryption error', async () => {
    const passphrase = 'correct horse battery staple';
    const exported = await serializeProjectExport(sanitizedState, 'backup', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase,
      confirmationPassphrase: passphrase,
      acknowledgement: true,
    });
    await expect(openProjectImport(exported.serialized, {
      passphrase: 'wrong passphrase value',
    })).rejects.toMatchObject({
      code: 'decryption_failed',
      message: 'Encrypted project could not be opened.',
    });
  });
});

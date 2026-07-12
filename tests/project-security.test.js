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
  prepareSanitizedProjectState,
  prepareUnsanitizedProjectState,
} from '../public/utils/project-security.js';

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

describe('project security boundary', () => {
  it('classifies every populated source, including merge slots', () => {
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
    ['VPN pre-shared key', { vpn_tunnels: [{ ike_gateway: { pre_shared_key: 'RAW-PSK' } }] }],
    ['certificate private value', { certificates: [{ private_key: { value: 'RAW-PRIVATE' } }] }],
  ])('rejects path-aware structured secret: %s', (_label, intermediateConfig) => {
    expectSecurityError(
      () => assertSanitizedProjectSafe(projectFrom({ intermediateConfig }), []),
      'secret_leak',
      'Sanitized export was blocked because secret-bearing content remains.',
    );
  });

  it('accepts placeholders in secret fields and algorithm descriptors', () => {
    const project = projectFrom({
      intermediateConfig: {
        snmp_config: [{ type: 'community', name: 'SANITIZED_COMMUNITY_0' }],
        aaa_config: [{ type: 'radius', secret: 'SANITIZED_KEY_0' }],
        vpn_tunnels: [{
          ike_gateway: { pre_shared_key: 'SANITIZED_KEY_1' },
          ike_proposal: { auth_method: 'pre-shared-keys' },
        }],
        certificates: [{ private_key: { value: 'SANITIZED_CERT_0' } }],
      },
    });
    expect(assertSanitizedProjectSafe(project, [])).toBe(JSON.stringify(project, null, 2));
  });
});

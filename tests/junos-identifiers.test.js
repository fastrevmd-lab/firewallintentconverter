import { describe, expect, it } from 'vitest';

import {
  JUNOS_IDENTIFIER_MAPPING_VERSION,
  JunosIdentifierPlanningError,
  createJunosIdentifierPlan,
  validateIdentifierMappings,
} from '../src/security/junos-identifiers.js';

const definition = (sourceName, definitionPath, overrides = {}) => ({
  catalogKey: 'address-book',
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  kind: 'address',
  sourceName,
  definitionPath,
  generated: false,
  role: null,
  stableParentKey: null,
  ...overrides,
});

const reference = (sourceName, referencePath, overrides = {}) => ({
  catalogKey: 'address-book',
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  compatibleKinds: ['address', 'address-set'],
  sourceName,
  referencePath,
  literals: [],
  ...overrides,
});

const validEntry = (overrides = {}) => ({
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  kind: 'address',
  sourceName: 'Web Server',
  outputName: 'Web-Server',
  definitionPath: 'address_objects[0].name',
  referencePaths: ['security_policies[0].src_addresses[0]'],
  resolution: 'unchanged',
  ...overrides,
});

const mapping = (...entries) => ({
  version: JUNOS_IDENTIFIER_MAPPING_VERSION,
  entries,
});

function capturePlanningError(callback) {
  try {
    callback();
  } catch (error) {
    expect(error).toBeInstanceOf(JunosIdentifierPlanningError);
    return error;
  }
  throw new Error('Expected JunosIdentifierPlanningError');
}

describe('Junos identifier allocation', () => {
  it.each([
    ['Web Server', 'Web@Server'],
    ['Web  Server', 'Web--Server'],
    ['!!!', '???'],
    ['1 edge', 'n-1-edge'],
    [`${'a'.repeat(63)}x`, `${'a'.repeat(63)}y`],
  ])('renames both definitions for %s and %s', (left, right) => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition(left, 'defs[0]'), definition(right, 'defs[1]')],
      references: [],
    });

    expect(plan.nameForDefinition('defs[0]')).not.toBe(plan.nameForDefinition('defs[1]'));
    expect(plan.mapping.entries.every(entry => entry.resolution === 'collision-renamed'))
      .toBe(true);
    expect(plan.collisionCount).toBe(2);
    expect(plan.warnings).toHaveLength(2);
    expect(plan.warnings[0]).toMatchObject({
      type: 'warning',
      category: 'identifier',
      subType: 'identifier_collision',
      suggestion: 'Review the identifier mapping before deployment.',
    });
  });

  it('preserves case-only and other non-colliding names', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition('Web', 'defs[0]'), definition('web', 'defs[1]')],
      references: [],
    });

    expect(plan.nameForDefinition('defs[0]')).toBe('Web');
    expect(plan.nameForDefinition('defs[1]')).toBe('web');
    expect(plan.mapping.entries.map(entry => entry.resolution)).toEqual([
      'unchanged',
      'unchanged',
    ]);
  });

  it('is stable when definitions and references are reordered', () => {
    const definitions = [
      definition('Web Server', 'defs.web-space'),
      definition('Web@Server', 'defs.web-at'),
      definition('Database', 'defs.database'),
    ];
    const references = [
      reference('Web Server', 'refs.web-space'),
      reference('Web@Server', 'refs.web-at'),
      reference('Outside Name', 'refs.external'),
    ];

    const forward = createJunosIdentifierPlan({ definitions, references });
    const reversed = createJunosIdentifierPlan({
      definitions: [...definitions].reverse(),
      references: [...references].reverse(),
    });

    expect(reversed.mapping).toEqual(forward.mapping);
    expect(reversed.warnings).toEqual(forward.warnings);
    for (const path of definitions.map(item => item.definitionPath)) {
      expect(reversed.nameForDefinition(path)).toBe(forward.nameForDefinition(path));
    }
    for (const path of references.map(item => item.referencePath)) {
      expect(reversed.nameForReference(path)).toBe(forward.nameForReference(path));
    }
  });

  it('keeps a singleton unchanged when it matches a first collision candidate', () => {
    const colliding = [
      definition('Web Server', 'defs.web-space'),
      definition('Web@Server', 'defs.web-at'),
    ];
    const firstPlan = createJunosIdentifierPlan({ definitions: colliding, references: [] });
    const firstCandidate = firstPlan.nameForDefinition('defs.web-space');

    const plan = createJunosIdentifierPlan({
      definitions: [...colliding, definition(firstCandidate, 'defs.singleton')],
      references: [],
    });

    expect(plan.nameForDefinition('defs.singleton')).toBe(firstCandidate);
    expect(plan.nameForDefinition('defs.web-space')).not.toBe(firstCandidate);
    expect(plan.nameForDefinition('defs.web-at')).not.toBe(firstCandidate);
  });

  it('rejects exact duplicate semantic definitions', () => {
    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Server', 'defs[0]'),
        definition('Web Server', 'defs[1]'),
      ],
      references: [],
    }));

    expect(error).toMatchObject({
      code: 'duplicate_definition',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      sourceName: 'Web Server',
      definitionPaths: ['defs[0]', 'defs[1]'],
    });
  });

  it('rejects duplicate generated stable identities before allocation', () => {
    let hashCalls = 0;
    const generated = {
      kind: 'source-nat-pool',
      generated: true,
      role: 'source-nat-pool',
      stableParentKey: 'source-rule:Web Rule',
    };

    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Pool', 'nat.rules[0]', generated),
        definition('Web@Pool', 'nat.rules[1]', generated),
      ],
      references: [],
    }, {
      hash64: () => {
        hashCalls += 1;
        return 0n;
      },
    }));

    expect(error).toMatchObject({
      code: 'duplicate_definition',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      definitionPaths: [
        'nat.rules[0]#generated:source-nat-pool',
        'nat.rules[1]#generated:source-nat-pool',
      ],
    });
    expect(hashCalls).toBe(0);
  });

  it('rejects exact source duplicates for generated definitions before allocation', () => {
    let hashCalls = 0;
    const generated = {
      kind: 'source-nat-pool',
      generated: true,
      role: 'source-nat-pool',
    };

    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Pool', 'nat.rules[0]', {
          ...generated,
          stableParentKey: 'source-rule:Web Rule',
        }),
        definition('Web Pool', 'nat.rules[1]', {
          ...generated,
          stableParentKey: 'source-rule:Other Rule',
        }),
      ],
      references: [],
    }, {
      hash64: () => {
        hashCalls += 1;
        return 0n;
      },
    }));

    expect(error).toMatchObject({
      code: 'duplicate_definition',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      sourceName: 'Web Pool',
      definitionPaths: [
        'nat.rules[0]#generated:source-nat-pool',
        'nat.rules[1]#generated:source-nat-pool',
      ],
    });
    expect(hashCalls).toBe(0);
  });

  it('rejects a reference that can bind to both an address and address set', () => {
    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Shared', 'addresses[0]'),
        definition('Shared', 'address_sets[0]', { kind: 'address-set' }),
      ],
      references: [reference('Shared', 'policies[0].src_addresses[0]')],
    }));

    expect(error).toMatchObject({
      code: 'ambiguous_reference',
      namespace: 'address-book-entry',
      sourceName: 'Shared',
      definitionPaths: ['address_sets[0]', 'addresses[0]'],
      referencePaths: ['policies[0].src_addresses[0]'],
    });
  });

  it('reserves an unresolved external reference without binding by normalized spelling', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition('Web Server', 'defs[0]')],
      references: [reference('Web@Server', 'refs[0]')],
    });

    expect(plan.nameForDefinition('defs[0]')).toBe('Web-Server');
    expect(plan.nameForReference('refs[0]')).not.toBe('Web-Server');
    expect(plan.mapping.entries).toContainEqual(expect.objectContaining({
      sourceName: 'Web@Server',
      definitionPath: null,
      referencePaths: ['refs[0]'],
      resolution: 'unresolved-collision-renamed',
    }));
    expect(plan.collisionCount).toBe(0);
  });

  it('returns explicit literals without adding mapping entries', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [],
      references: [reference('any', 'refs.any', { literals: ['any'] })],
    });

    expect(plan.nameForReference('refs.any')).toBe('any');
    expect(plan.mapping.entries).toEqual([]);
  });

  it('catalogs generated names by owner and role with auditable paths', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition('Web Pool', 'nat.rules[0]', {
        kind: 'source-nat-pool',
        generated: true,
        role: 'source-nat-pool',
        stableParentKey: 'source-rule:Web Rule',
      })],
      references: [],
    });

    expect(plan.nameForGenerated('nat.rules[0]', 'source-nat-pool')).toBe('Web-Pool');
    expect(plan.mapping.entries).toEqual([expect.objectContaining({
      definitionPath: 'nat.rules[0]#generated:source-nat-pool',
      resolution: 'generated',
    })]);
  });

  it('fails closed for every missing lookup type', () => {
    const plan = createJunosIdentifierPlan({ definitions: [], references: [] });

    for (const lookup of [
      () => plan.nameForDefinition('missing.definition'),
      () => plan.nameForReference('missing.reference'),
      () => plan.nameForGenerated('missing.owner', 'missing-role'),
    ]) {
      expect(capturePlanningError(lookup)).toMatchObject({
        code: 'missing_catalog_coverage',
      });
    }
  });

  it('retries all candidates involved in a one-round injected hash conflict', () => {
    const calls = [];
    const hash64 = input => {
      calls.push(input);
      const retry = input.split('\0').at(-1);
      if (retry === '0') return 0n;
      return input.includes('Web Server') ? 1n : 2n;
    };

    const plan = createJunosIdentifierPlan({
      definitions: [
        definition('Web Server', 'defs[0]'),
        definition('Web@Server', 'defs[1]'),
      ],
      references: [],
    }, { hash64 });

    expect(plan.nameForDefinition('defs[0]')).not.toBe(plan.nameForDefinition('defs[1]'));
    expect(calls.some(input => input.endsWith('\0' + '1'))).toBe(true);
  });

  it('throws allocation_failed after 32 complete conflict rounds', () => {
    let calls = 0;
    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Server', 'defs[0]'),
        definition('Web@Server', 'defs[1]'),
      ],
      references: [],
    }, {
      hash64: () => {
        calls += 1;
        return 0n;
      },
    }));

    expect(error).toMatchObject({
      code: 'allocation_failed',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
    });
    expect(calls).toBe(64);
  });
});

describe('Junos identifier mapping validation', () => {
  it('returns a deeply frozen defensive copy', () => {
    const original = mapping(validEntry());
    const validated = validateIdentifierMappings(original);

    expect(validated).toEqual(original);
    expect(validated).not.toBe(original);
    expect(validated.entries[0]).not.toBe(original.entries[0]);
    expect(Object.isFrozen(validated)).toBe(true);
    expect(Object.isFrozen(validated.entries)).toBe(true);
    expect(Object.isFrozen(validated.entries[0])).toBe(true);
    expect(Object.isFrozen(validated.entries[0].referencePaths)).toBe(true);

    original.entries[0].sourceName = 'Changed';
    original.entries[0].referencePaths.push('security_policies[1].src_addresses[0]');
    expect(validated.entries[0].sourceName).toBe('Web Server');
    expect(validated.entries[0].referencePaths).toEqual([
      'security_policies[0].src_addresses[0]',
    ]);
  });

  it.each([
    ['unknown version', { version: 2, entries: [] }],
    ['unknown mapping field', { version: 1, entries: [], artifact: 'secret' }],
    ['unknown entry field', mapping(validEntry({ artifact: 'secret' }))],
    ['unknown resolution', mapping(validEntry({ resolution: 'renamed' }))],
    ['unsafe scalar', mapping(validEntry({ sourceName: 'Web\nServer' }))],
    ['invalid output name', mapping(validEntry({ outputName: '1-invalid' }))],
    ['null definition path', mapping(validEntry({ definitionPath: null }))],
    ['unresolved definition path', mapping(validEntry({
      definitionPath: 'defs[0]',
      resolution: 'unresolved-reference',
    }))],
    ['unsorted reference paths', mapping(validEntry({
      referencePaths: ['refs[1]', 'refs[0]'],
    }))],
    ['duplicate reference paths', mapping(validEntry({
      referencePaths: ['refs[0]', 'refs[0]'],
    }))],
    ['unchanged output mismatch', mapping(validEntry({ outputName: 'Other' }))],
    ['collision output unchanged', mapping(validEntry({
      outputName: 'Web-Server',
      resolution: 'collision-renamed',
    }))],
  ])('rejects %s', (_label, invalidMapping) => {
    const error = capturePlanningError(() => validateIdentifierMappings(invalidMapping));
    expect(error).toMatchObject({ code: 'invalid_identifier_mapping' });
    expect(error.message).not.toContain('secret');
  });

  it('rejects duplicate semantic definitions', () => {
    const error = capturePlanningError(() => validateIdentifierMappings(mapping(
      validEntry({ definitionPath: 'defs[0]', referencePaths: [] }),
      validEntry({ definitionPath: 'defs[1]', referencePaths: [] }),
    )));

    expect(error.code).toBe('invalid_identifier_mapping');
  });

  it('rejects duplicate output names across kinds and unresolved entries', () => {
    const error = capturePlanningError(() => validateIdentifierMappings(mapping(
      validEntry({ definitionPath: 'defs[0]', referencePaths: [] }),
      validEntry({
        kind: 'address-set',
        sourceName: 'Web-Server',
        definitionPath: null,
        referencePaths: ['refs[0]'],
        resolution: 'unresolved-reference',
      }),
    )));

    expect(error.code).toBe('invalid_identifier_mapping');
  });
});

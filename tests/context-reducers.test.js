import { describe, it, expect } from 'vitest';
import { conversionReducer, initialState as conversionInitial } from '../public/contexts/ConversionContext.jsx';
import { mergeReducer, initialState as mergeInitial } from '../public/contexts/MergeContext.jsx';
import { configReducer, initialState as configInitial } from '../public/contexts/ConfigContext.jsx';

const IDENTIFIER_MAPPINGS = { version: 1, entries: [] };

const sanitizedConfigState = {
  ...configInitial,
  configText: 'set system host-name SANITIZED_HOST_0',
  intermediateConfig: { security_policies: [{ name: 'allow', _rule_index: 1 }] },
  interfaceMappings: { ethernet1: 'ge-0/0/0' },
  isSanitized: true,
  sanitizationTable: [{
    type: 'hostname', placeholder: 'SANITIZED_HOST_0', original: 'edge.example',
  }],
  projectSecurityMode: 'sanitized',
};

describe('configReducer sanitization provenance', () => {
  it.each([
    ['generic config text edit', { type: 'SET_FIELD', field: 'configText', value: 'set password RAW' }],
    ['generic source edit', { type: 'SET_FIELD', field: 'sourceVendor', value: 'fortigate' }],
    ['mapping edit', { type: 'SET_FIELD', field: 'interfaceMappings', value: { port1: 'ge-0/0/1' } }],
    ['structured config edit', { type: 'UPDATE_CONFIG', updater: value => ({ ...value, zones: [] }) }],
    ['rule update', { type: 'UPDATE_RULE', index: 0, rule: { name: 'changed', _rule_index: 1 } }],
    ['rule deletion', { type: 'DELETE_RULE', index: 0 }],
    ['rule addition', { type: 'ADD_RULE', rule: { name: 'new', _rule_index: 2 } }],
    ['translated rule edit', { type: 'SET_TRANSLATED_POLICIES', policies: [{ name: 'translated' }] }],
    ['rule grouping edit', { type: 'SET_RULE_GROUPS', groups: [{ name: 'group' }] }],
  ])('invalidates safe classification after %s while retaining sensitive table data', (_label, action) => {
    const next = configReducer(sanitizedConfigState, action);
    expect(next.isSanitized).toBe(false);
    expect(next.projectSecurityMode).toBe('unsanitized');
    expect(next.sanitizationTable).toBe(sanitizedConfigState.sanitizationTable);
  });

  it('does not invalidate provenance for non-source UI bookkeeping', () => {
    const next = configReducer(sanitizedConfigState, {
      type: 'SET_FIELD', field: 'warningStatuses', value: { 0: 'acknowledged' },
    });
    expect(next.isSanitized).toBe(true);
    expect(next.projectSecurityMode).toBe('sanitized');
  });

  it('uses one trusted sanitization completion action and preserves it through trusted parse', () => {
    const sanitized = configReducer(configInitial, {
      type: 'SET_SANITIZATION_RESULT',
      configText: 'set system host-name SANITIZED_HOST_0',
      sanitizationTable: sanitizedConfigState.sanitizationTable,
    });
    expect(sanitized).toMatchObject({
      isSanitized: true,
      projectSecurityMode: 'sanitized',
      sanitizationTable: sanitizedConfigState.sanitizationTable,
    });

    const parsed = configReducer(sanitized, {
      type: 'SET_PARSE_RESULT',
      intermediateConfig: { security_policies: [] },
      warnings: [],
      parseStats: {},
      sourceVendor: 'panos',
      preserveSanitization: true,
    });
    expect(parsed.isSanitized).toBe(true);
    expect(parsed.projectSecurityMode).toBe('sanitized');

    const resetTranslation = configReducer(parsed, {
      type: 'SET_FIELD', field: 'srxTranslatedPolicies', value: null,
    });
    const resetGroups = configReducer(resetTranslation, {
      type: 'SET_FIELD', field: 'ruleGroups', value: [],
    });
    expect(resetGroups.isSanitized).toBe(true);
    expect(resetGroups.projectSecurityMode).toBe('sanitized');
  });

  it('invalidates an untrusted parse result but trusts LOAD_PROJECT and RESET', () => {
    const parsed = configReducer(sanitizedConfigState, {
      type: 'SET_PARSE_RESULT', intermediateConfig: { security_policies: [] },
    });
    expect(parsed).toMatchObject({ isSanitized: false, projectSecurityMode: 'unsanitized' });

    const loaded = configReducer(configInitial, {
      type: 'LOAD_PROJECT', state: sanitizedConfigState,
    });
    expect(loaded).toMatchObject({ isSanitized: true, projectSecurityMode: 'sanitized' });
    expect(configReducer(sanitizedConfigState, { type: 'RESET' })).toEqual(configInitial);
  });
});

describe('conversionReducer RESET', () => {
  it('returns a clean initial state, discarding all output', () => {
    const dirty = {
      srxOutput: 'set security ...',
      convertWarnings: [{ msg: 'x' }],
      conversionSummary: { total: 5 },
      outputFormat: 'xml',
      targetContext: { type: 'logical-system', name: 'LS1' },
      validationFindings: [{ id: 1 }],
    };
    const next = conversionReducer(dirty, { type: 'RESET' });
    expect(next).toEqual(conversionInitial);
    expect(next).not.toBe(conversionInitial); // fresh object, not the shared ref
  });
});

describe('conversionReducer canonical output', () => {
  it('derives outputFormat from canonical output and ignores a stale action format', () => {
    const output = {
      format: 'set',
      commands: ['set system host-name edge-1'],
      warnings: [],
      identifierMappings: IDENTIFIER_MAPPINGS,
    };
    const next = conversionReducer(conversionInitial, {
      type: 'SET_CONVERSION_RESULT',
      output,
      format: 'xml',
      warnings: [],
    });

    expect(next.srxOutput).toEqual(output);
    expect(next.outputFormat).toBe('set');
  });

  it('rejects malformed output instead of storing it', () => {
    expect(() => conversionReducer(conversionInitial, {
      type: 'SET_CONVERSION_RESULT',
      output: { commands: [] },
    })).toThrow(/Canonical conversion output/);
  });

  it('validates canonical output assigned through SET_FIELD and corrects stale format', () => {
    const output = {
      format: 'set',
      commands: ['set system host-name edge-1'],
      identifierMappings: IDENTIFIER_MAPPINGS,
    };
    const next = conversionReducer(
      { ...conversionInitial, outputFormat: 'xml' },
      { type: 'SET_FIELD', field: 'srxOutput', value: output },
    );

    expect(next.srxOutput).toEqual(output);
    expect(next.outputFormat).toBe('set');
    expect(() => conversionReducer(conversionInitial, {
      type: 'SET_FIELD',
      field: 'srxOutput',
      value: { commands: ['set system host-name bypass'] },
    })).toThrow(/Canonical conversion output/);
  });

  it('allows SET_FIELD to clear output without changing the selected format', () => {
    const next = conversionReducer(
      {
        ...conversionInitial,
        srxOutput: { format: 'xml', xml: '<configuration />' },
        outputFormat: 'xml',
      },
      { type: 'SET_FIELD', field: 'srxOutput', value: null },
    );

    expect(next.srxOutput).toBeNull();
    expect(next.outputFormat).toBe('xml');
  });

  it('validates LOAD_PROJECT output and derives format from canonical output', () => {
    const output = {
      format: 'set',
      commands: ['set system host-name loaded-edge'],
      identifierMappings: IDENTIFIER_MAPPINGS,
    };
    const next = conversionReducer(conversionInitial, {
      type: 'LOAD_PROJECT',
      state: { srxOutput: output, outputFormat: 'xml' },
    });

    expect(next.srxOutput).toEqual(output);
    expect(next.outputFormat).toBe('set');
    expect(() => conversionReducer(conversionInitial, {
      type: 'LOAD_PROJECT',
      state: {
        srxOutput: { format: 'set', commands: [] },
        outputFormat: 'set',
      },
    })).toThrow(/at least one command/);
  });

  it('preserves null LOAD_PROJECT output and its selected format', () => {
    const next = conversionReducer(conversionInitial, {
      type: 'LOAD_PROJECT',
      state: { srxOutput: null, outputFormat: 'xml' },
    });

    expect(next.srxOutput).toBeNull();
    expect(next.outputFormat).toBe('xml');
  });
});

describe('mergeReducer RESET', () => {
  it('returns a clean initial state, discarding all merge slots', () => {
    const dirty = {
      mergeMode: true,
      configSlots: [{ id: 'a' }, { id: 'b' }],
      activeSlotIndex: 1,
      crossLsLinks: [{ from: 'a', to: 'b' }],
    };
    const next = mergeReducer(dirty, { type: 'RESET' });
    expect(next).toEqual(mergeInitial);
    expect(next).not.toBe(mergeInitial);
  });
});

describe('mergeReducer sanitization provenance', () => {
  const sanitizedMerge = {
    ...mergeInitial,
    mergeMode: true,
    configSlots: [{
      configText: 'set system host-name SANITIZED_HOST_0',
      intermediateConfig: { security_policies: [] },
      isSanitized: true,
      projectSecurityMode: 'sanitized',
      sanitizationTable: sanitizedConfigState.sanitizationTable,
    }],
  };

  it.each([
    ['raw text', { configText: 'set password RAW' }],
    ['structured config', { intermediateConfig: { security_policies: [{ name: 'new' }] } }],
    ['mapping', { interfaceMappings: { ethernet1: 'ge-0/0/1' } }],
  ])('invalidates the edited slot after %s changes and retains its table', (_label, slot) => {
    const next = mergeReducer(sanitizedMerge, {
      type: 'UPDATE_SLOT', index: 0, slot,
    });
    expect(next.configSlots[0]).toMatchObject({
      isSanitized: false,
      projectSecurityMode: 'unsanitized',
    });
    expect(next.configSlots[0].sanitizationTable)
      .toBe(sanitizedMerge.configSlots[0].sanitizationTable);
  });

  it('preserves trusted slot sanitization completion, LOAD_PROJECT, and RESET', () => {
    const completed = mergeReducer(sanitizedMerge, {
      type: 'UPDATE_SLOT',
      index: 0,
      preserveSanitization: true,
      slot: {
        configText: 'set system host-name SANITIZED_HOST_1',
        intermediateConfig: { security_policies: [] },
        isSanitized: true,
        projectSecurityMode: 'sanitized',
        sanitizationTable: sanitizedConfigState.sanitizationTable,
      },
    });
    expect(completed.configSlots[0].isSanitized).toBe(true);
    expect(completed.configSlots[0].projectSecurityMode).toBe('sanitized');

    expect(mergeReducer(mergeInitial, {
      type: 'LOAD_PROJECT', state: sanitizedMerge,
    }).configSlots[0].isSanitized).toBe(true);
    expect(mergeReducer(sanitizedMerge, { type: 'RESET' })).toEqual(mergeInitial);
  });
});

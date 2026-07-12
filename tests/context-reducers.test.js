import { describe, it, expect } from 'vitest';
import { conversionReducer, initialState as conversionInitial } from '../public/contexts/ConversionContext.jsx';
import { mergeReducer, initialState as mergeInitial } from '../public/contexts/MergeContext.jsx';

const IDENTIFIER_MAPPINGS = { version: 1, entries: [] };

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

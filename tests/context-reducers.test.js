import { describe, it, expect } from 'vitest';
import { conversionReducer, initialState as conversionInitial } from '../public/contexts/ConversionContext.jsx';
import { mergeReducer, initialState as mergeInitial } from '../public/contexts/MergeContext.jsx';

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

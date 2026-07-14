import { describe, it, expect } from 'vitest';
import { uiReducer, initialState } from '../public/contexts/UIContext.jsx';

describe('UI policy structure state', () => {
  it('defaults to global', () => {
    expect(initialState.policyStructure).toBe('global');
  });

  it('SET_FIELD updates policyStructure', () => {
    const next = uiReducer(initialState, { type: 'SET_FIELD', field: 'policyStructure', value: 'zone-pair' });
    expect(next.policyStructure).toBe('zone-pair');
  });
});

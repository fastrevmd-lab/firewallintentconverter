import { describe, it, expect } from 'vitest';
import { uiReducer, initialState } from '../public/contexts/UIContext.jsx';

describe('UI deployment mode state', () => {
  it('defaults to standalone', () => {
    expect(initialState.deploymentMode).toBe('standalone');
  });

  it('SET_FIELD updates deploymentMode', () => {
    const next = uiReducer(initialState, { type: 'SET_FIELD', field: 'deploymentMode', value: 'mnha' });
    expect(next.deploymentMode).toBe('mnha');
  });

  it('SET_FIELD updates to chassis-cluster', () => {
    const next = uiReducer(initialState, { type: 'SET_FIELD', field: 'deploymentMode', value: 'chassis-cluster' });
    expect(next.deploymentMode).toBe('chassis-cluster');
  });
});

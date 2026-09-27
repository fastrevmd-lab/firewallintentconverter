import { describe, it, expect, vi, beforeEach } from 'vitest';
import { uiReducer, initialState } from '../public/contexts/UIContext.jsx';
import { LLM_RISK_ACCEPTANCE_STORAGE_KEY } from '../public/utils/llm-risk-acceptance.js';

describe('LLM risk acceptance persistence (M8)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('persists a chosen mode with setItem', () => {
    const setItemSpy = vi.spyOn(globalThis.localStorage, 'setItem');
    const next = uiReducer(initialState, { type: 'SET_LLM_RISK_ACCEPTANCE', value: 'local-only' });
    expect(next.llmRiskAcceptance).toBe('local-only');
    expect(setItemSpy).toHaveBeenCalledWith(LLM_RISK_ACCEPTANCE_STORAGE_KEY, 'local-only');
  });

  it('"Change mode" (value: null) clears storage instead of writing the string "null"', () => {
    // Regression test: the old reducer called localStorage.setItem(key, null),
    // which coerces to the string "null". On the next load, getItem() returns
    // that truthy string and the app skips the disclaimer instead of asking
    // for consent again.
    const setItemSpy = vi.spyOn(globalThis.localStorage, 'setItem');
    const removeItemSpy = vi.spyOn(globalThis.localStorage, 'removeItem');

    const next = uiReducer(initialState, { type: 'SET_LLM_RISK_ACCEPTANCE', value: null });

    expect(next.llmRiskAcceptance).toBeNull();
    expect(removeItemSpy).toHaveBeenCalledWith(LLM_RISK_ACCEPTANCE_STORAGE_KEY);
    expect(setItemSpy).not.toHaveBeenCalled();
  });

  it('a stale "null" string from a pre-1.2.3 install is treated as undecided and cleared (MEC-134 F2)', async () => {
    // Regression test: users who clicked "Change mode" on 1.2.2 or earlier
    // have the literal string "null" stored. initialState used to read it
    // with a raw localStorage.getItem(), which is truthy, so the app skipped
    // the disclaimer and never asked those installs to re-consent.
    vi.spyOn(globalThis.localStorage, 'getItem').mockImplementation((key) =>
      key === LLM_RISK_ACCEPTANCE_STORAGE_KEY ? 'null' : null,
    );
    const removeItemSpy = vi.spyOn(globalThis.localStorage, 'removeItem');

    vi.resetModules();
    const fresh = await import('../public/contexts/UIContext.jsx');

    expect(fresh.initialState.llmRiskAcceptance).toBeNull();
    expect(removeItemSpy).toHaveBeenCalledWith(LLM_RISK_ACCEPTANCE_STORAGE_KEY);
  });
});

/**
 * resolveConversionOptions — override precedence.
 *
 * Regression for the stale-closure bug: changing the "Policy structure" (or
 * "Target architecture") selector dispatches the new value to uiState
 * asynchronously, so a reconvert fired in the same handler still sees the OLD
 * uiState. The reconvert must use an explicit override that wins over uiState,
 * so the freshly-selected value takes effect immediately (preview + download).
 */

import { describe, it, expect } from 'vitest';
import { resolveConversionOptions } from '../public/utils/conversion-options.js';

describe('resolveConversionOptions', () => {
  it('falls back to defaults when nothing is set', () => {
    expect(resolveConversionOptions(undefined)).toEqual({
      policyStructure: 'global',
      deploymentMode: 'standalone',
    });
  });

  it('uses uiState when no overrides are given', () => {
    const uiState = { policyStructure: 'zone-pair', deploymentMode: 'mnha' };
    expect(resolveConversionOptions(uiState)).toEqual({
      policyStructure: 'zone-pair',
      deploymentMode: 'mnha',
    });
  });

  it('lets an explicit override win over a STALE uiState value (the bug)', () => {
    // uiState still holds the pre-change value; the selector just changed to zone-pair.
    const staleUiState = { policyStructure: 'global', deploymentMode: 'standalone' };
    expect(resolveConversionOptions(staleUiState, { policyStructure: 'zone-pair' })).toEqual({
      policyStructure: 'zone-pair',
      deploymentMode: 'standalone',
    });
  });

  it('overrides deploymentMode independently', () => {
    const staleUiState = { policyStructure: 'zone-pair', deploymentMode: 'standalone' };
    expect(resolveConversionOptions(staleUiState, { deploymentMode: 'chassis-cluster' })).toEqual({
      policyStructure: 'zone-pair',
      deploymentMode: 'chassis-cluster',
    });
  });
});

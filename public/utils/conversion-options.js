/**
 * Resolve conversion options for a convert run, letting explicit per-call
 * overrides win over UI state.
 *
 * This exists to defeat a React stale-closure bug: when the "Policy structure"
 * or "Target architecture" selector changes, the new value is dispatched to
 * uiState asynchronously, so a reconvert fired in the same event handler still
 * captures the OLD uiState. Passing the freshly-selected value as an override
 * makes the reconvert deterministic — the preview and download reflect the new
 * selection immediately.
 *
 * @param {object} [uiState] - current UI state (may be undefined)
 * @param {{policyStructure?: string, deploymentMode?: string}} [overrides]
 * @returns {{policyStructure: string, deploymentMode: string}}
 */
export function resolveConversionOptions(uiState, overrides = {}) {
  return {
    policyStructure: overrides.policyStructure ?? uiState?.policyStructure ?? 'global',
    deploymentMode: overrides.deploymentMode ?? uiState?.deploymentMode ?? 'standalone',
  };
}

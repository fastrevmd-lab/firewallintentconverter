/**
 * Shared LLM risk-acceptance mode storage.
 *
 * Single source of truth for the localStorage key that records whether the
 * user has accepted sending firewall configs to an LLM: null (undecided),
 * 'all' (any provider), 'local-only' (local providers only), 'deterministic'
 * (no AI), or 'rejected'.
 *
 * llm-client.js reads this directly so local-only mode is enforced at the
 * point of call, not just by filtering the Settings UI dropdown.
 */
export const LLM_RISK_ACCEPTANCE_STORAGE_KEY = 'llm-risk-acceptance';

export function getLLMRiskAcceptance() {
  try {
    return typeof localStorage === 'undefined'
      ? null
      : localStorage.getItem(LLM_RISK_ACCEPTANCE_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function isLocalOnlyLLMMode() {
  return getLLMRiskAcceptance() === 'local-only';
}

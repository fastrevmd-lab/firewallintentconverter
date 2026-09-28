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

const VALID_LLM_RISK_ACCEPTANCE_VALUES = new Set(['all', 'local-only', 'deterministic', 'rejected']);

/**
 * Reads the stored risk-acceptance mode, treating anything that isn't one of
 * the known values (missing key, the literal string "null" left behind by
 * pre-1.2.3 builds, or any other corrupt/unrecognized value) as undecided.
 *
 * A stale/invalid value is actively cleared rather than left in place, so a
 * fresh load re-asks for consent instead of silently trusting old state.
 *
 * @returns {'all' | 'local-only' | 'deterministic' | 'rejected' | null}
 */
export function getLLMRiskAcceptance() {
  let value;
  try {
    value = typeof localStorage === 'undefined'
      ? null
      : localStorage.getItem(LLM_RISK_ACCEPTANCE_STORAGE_KEY);
  } catch {
    return null;
  }

  if (value === null || VALID_LLM_RISK_ACCEPTANCE_VALUES.has(value)) {
    return value;
  }

  try {
    localStorage.removeItem(LLM_RISK_ACCEPTANCE_STORAGE_KEY);
  } catch {
    // best-effort cleanup — fall through and treat as undecided regardless
  }
  return null;
}

/**
 * Fail-closed gate on whether the current risk-acceptance mode permits any
 * LLM call at all. Does not trust the caller (or the Settings UI) to have
 * kept itself in sync with the stored mode.
 *
 * - 'all' → every provider is allowed.
 * - 'local-only' → allowed, but the caller must still run its own
 *   cloud-provider/loopback checks before allowing the call.
 * - anything else — undecided (null), 'deterministic', 'rejected', or an
 *   unrecognized value — AI features are disabled entirely.
 *
 * @returns {'all' | 'local-only'} the mode, for callers that branch on it
 * @throws {Error} if the current mode does not allow LLM calls
 */
export function assertLLMModeAllowsCalls() {
  const mode = getLLMRiskAcceptance();
  if (mode === 'all' || mode === 'local-only') return mode;
  throw new Error('AI features are disabled in the current mode');
}

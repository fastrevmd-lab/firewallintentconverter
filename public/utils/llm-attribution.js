import { sanitizeModelLabel } from '../../src/version.js';

/**
 * Resolve the LLM model that assisted this conversion, for provenance stamps.
 *
 * A model is credited only when at least one policy was actually LLM-reviewed
 * (`_review_status === 'llm_reviewed'`); a purely deterministic run stamps
 * nothing. The value comes from the current LLM settings and is sanitized for
 * embedding in output comments.
 *
 * @param {Array<object>} [policies] - security policies (may be undefined)
 * @param {{model?: string}} [settings] - current LLM settings
 * @returns {string} model label (e.g. 'ornith:35b', 'claude-opus-4-8') or ''
 */
export function resolveAssistModel(policies, settings) {
  const usedLlm = Array.isArray(policies)
    && policies.some(p => p && p._review_status === 'llm_reviewed');
  if (!usedLlm) return '';
  return sanitizeModelLabel(settings?.model);
}

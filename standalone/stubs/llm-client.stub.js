/**
 * Standalone-build stand-in for public/utils/llm-client.js.
 *
 * The standalone bundle ships with no server and forces deterministic mode
 * (see standalone/main.jsx), so the real module's networking/API-key code is
 * never exercised from the UI. vite.standalone.config.js aliases every import
 * of llm-client.js to this file so that code never reaches dist-standalone/
 * at all — a runtime toggle isn't enough, since the code would still be
 * present in the bundle to inspect or invoke directly.
 */

export const DEFAULT_FULL_REVIEW_SYSTEM_PROMPT = '';
export const DEFAULT_GREENFIELD_SYSTEM_PROMPT = '';
export const DEFAULT_TRANSLATE_SYSTEM_PROMPT = '';
export const VENDOR_PROMPT_KEYS = [];

function unavailable() {
  throw new Error('LLM features are not available in the standalone build.');
}

export function loadSystemPrompt() {
  return '';
}

export function loadVendorTranslatePrompt() {
  return null;
}

export function getLLMSuggestion() {
  return unavailable();
}

export function getLLMChatResponse() {
  return unavailable();
}

export function getLLMStatus() {
  return { configured: false, provider: 'none', model: 'none' };
}

export function testLLMConnection() {
  return unavailable();
}

export function describeLLMError(error) {
  return (error && error.message) || 'LLM features are not available in the standalone build.';
}

export function buildFullReviewPrompt() {
  return { system: '', user: '' };
}

export function buildTranslationPrompt() {
  return { system: '', user: '' };
}

export function parseTranslationResponse() {
  return [];
}

export function translatePolicies() {
  return unavailable();
}

export function groupPolicies() {
  return unavailable();
}

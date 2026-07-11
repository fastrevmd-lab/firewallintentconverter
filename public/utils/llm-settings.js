import { safeJsonParse } from './safe-json.js';

export const LLM_SETTINGS_STORAGE_KEY = 'llm-settings';
export const LLM_API_KEY_SESSION_KEY = 'llm-api-key';

export class LLMSettingsStorageError extends Error {
  constructor(message = 'LLM settings storage is unavailable.') {
    super(message);
    this.name = 'LLMSettingsStorageError';
    this.code = 'LLM_SETTINGS_STORAGE_UNAVAILABLE';
  }
}

function stores() {
  return {
    persistent: typeof localStorage === 'undefined' ? null : localStorage,
    session: typeof sessionStorage === 'undefined' ? null : sessionStorage,
  };
}

function readPersistent(persistent) {
  const raw = persistent?.getItem(LLM_SETTINGS_STORAGE_KEY);
  const parsed = raw ? safeJsonParse(raw) : {};
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
}

export function migrateLegacyLLMSettings() {
  const { persistent, session } = stores();
  let settings;
  try { settings = readPersistent(persistent); }
  catch { throw new LLMSettingsStorageError(); }
  if (!Object.prototype.hasOwnProperty.call(settings, 'apiKey')) return settings;

  const legacyKey = typeof settings.apiKey === 'string' ? settings.apiKey : '';
  const { apiKey: removed, ...nonsecret } = settings;
  let sessionFailed = false;
  try {
    if (legacyKey && !session?.getItem(LLM_API_KEY_SESSION_KEY)) {
      session?.setItem(LLM_API_KEY_SESSION_KEY, legacyKey);
    }
  } catch { sessionFailed = true; }
  try { persistent?.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify(nonsecret)); }
  catch { throw new LLMSettingsStorageError(); }
  if (sessionFailed) throw new LLMSettingsStorageError();
  return nonsecret;
}

export function loadLLMSettings() {
  const persistentSettings = migrateLegacyLLMSettings();
  try {
    const { session } = stores();
    return { ...persistentSettings, apiKey: session?.getItem(LLM_API_KEY_SESSION_KEY) || '' };
  } catch { throw new LLMSettingsStorageError(); }
}

export function saveLLMSettings(settings = {}) {
  const { apiKey = '', ...nonsecret } = settings;
  const { persistent, session } = stores();
  try {
    persistent?.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify(nonsecret));
    if (apiKey) session?.setItem(LLM_API_KEY_SESSION_KEY, String(apiKey));
    else session?.removeItem(LLM_API_KEY_SESSION_KEY);
  } catch { throw new LLMSettingsStorageError(); }
  return { ...nonsecret, apiKey: String(apiKey || '') };
}

export function clearLLMApiKey() {
  try { stores().session?.removeItem(LLM_API_KEY_SESSION_KEY); }
  catch { throw new LLMSettingsStorageError(); }
}

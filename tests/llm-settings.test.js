import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  LLM_API_KEY_SESSION_KEY,
  LLM_SETTINGS_STORAGE_KEY,
  LLMSettingsStorageError,
  clearLLMApiKey,
  loadLLMSettings,
  migrateLegacyLLMSettings,
  saveLLMSettings,
} from '../public/utils/llm-settings.js';

function memoryStorage() {
  const values = new Map();
  return {
    getItem: vi.fn(key => values.get(key) ?? null),
    setItem: vi.fn((key, value) => values.set(key, String(value))),
    removeItem: vi.fn(key => values.delete(key)),
    clear: () => values.clear(),
  };
}

beforeEach(() => {
  globalThis.localStorage = memoryStorage();
  globalThis.sessionStorage = memoryStorage();
});

describe('LLM settings storage boundary', () => {
  it('persists nonsecret preferences and keeps the key in the tab session', () => {
    saveLLMSettings({ provider: 'openai', model: 'gpt-4o', apiKey: 'SENTINEL_KEY' });
    expect(JSON.parse(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY))).toEqual({
      provider: 'openai', model: 'gpt-4o',
    });
    expect(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY)).not.toContain('SENTINEL_KEY');
    expect(sessionStorage.getItem(LLM_API_KEY_SESSION_KEY)).toBe('SENTINEL_KEY');
    expect(loadLLMSettings()).toMatchObject({ provider: 'openai', apiKey: 'SENTINEL_KEY' });
  });

  it('clears only the tab-session key', () => {
    saveLLMSettings({ provider: 'openai', apiKey: 'SENTINEL_KEY' });
    clearLLMApiKey();
    expect(loadLLMSettings()).toEqual({ provider: 'openai', apiKey: '' });
  });

  it('moves a legacy key once while preserving preferences', () => {
    localStorage.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify({
      provider: 'claude', apiKey: 'LEGACY_SENTINEL', translateSystemPrompt_panos: 'prompt',
    }));
    migrateLegacyLLMSettings();
    expect(sessionStorage.getItem(LLM_API_KEY_SESSION_KEY)).toBe('LEGACY_SENTINEL');
    expect(JSON.parse(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY))).toEqual({
      provider: 'claude', translateSystemPrompt_panos: 'prompt',
    });
  });

  it('does not replace a current session key during migration', () => {
    sessionStorage.setItem(LLM_API_KEY_SESSION_KEY, 'CURRENT_SENTINEL');
    localStorage.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify({ apiKey: 'LEGACY_SENTINEL' }));
    migrateLegacyLLMSettings();
    expect(sessionStorage.getItem(LLM_API_KEY_SESSION_KEY)).toBe('CURRENT_SENTINEL');
    expect(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY)).not.toContain('LEGACY_SENTINEL');
  });

  it('removes a legacy persistent key even if session storage rejects it', () => {
    localStorage.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify({ provider: 'openai', apiKey: 'LEGACY_SENTINEL' }));
    sessionStorage.setItem.mockImplementation(() => { throw new Error('LEGACY_SENTINEL'); });
    let caught;
    try { migrateLegacyLLMSettings(); } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(LLMSettingsStorageError);
    expect(caught.message).not.toContain('LEGACY_SENTINEL');
    expect(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY)).toBe('{"provider":"openai"}');
  });
});

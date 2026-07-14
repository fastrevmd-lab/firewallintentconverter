/**
 * Vitest setup file — runs before all tests
 * Provides minimal localStorage/sessionStorage shims for React components
 * that access them at module load time (e.g., UIContext initialState).
 */

globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
  clear: () => {},
};

globalThis.sessionStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
  clear: () => {},
};

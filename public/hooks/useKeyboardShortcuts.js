/**
 * useKeyboardShortcuts — Global keyboard shortcut system
 *
 * Registers a single keydown listener on window and dispatches
 * to registered action handlers. Supports mod+key combos
 * (ctrl on non-Mac, cmd on Mac) and single-key shortcuts
 * (only active when focus is not in an input field).
 *
 * Usage:
 *   const { registerHandler, unregisterHandler } = useKeyboardShortcuts();
 *   useEffect(() => {
 *     registerHandler('save-project', () => { ... });
 *     return () => unregisterHandler('save-project');
 *   }, []);
 */
import { useEffect, useRef, useCallback } from 'react';

// ---------------------------------------------------------------------------
// Default shortcut maps
// ---------------------------------------------------------------------------
const DEFAULT_SHORTCUTS = {
  'mod+p': 'command-palette',
  'mod+s': 'save-project',
  'mod+o': 'load-project',
  'mod+z': 'undo',
  'mod+shift+z': 'redo',
  'mod+y': 'redo',
  'mod+enter': 'parse',
  'mod+shift+c': 'convert',
  'mod+shift+t': 'translate-llm',
  'mod+k': 'search',
  'mod+b': 'toggle-sidebar',
  'mod+shift+b': 'toggle-inspector',
  'mod+1': 'nav-import',
  'mod+2': 'nav-policies',
  'mod+3': 'nav-objects',
  'mod+4': 'nav-output',
  'escape': 'close-modal',
};

// Single-key shortcuts (only active when not in an input field)
const SINGLE_KEY_SHORTCUTS = {
  'j': 'next-rule',
  'k': 'prev-rule',
  'a': 'accept-rule',
  'n': 'add-rule',
  'delete': 'delete-rule',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Detect if the current platform is macOS */
const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent);

/**
 * Build a normalized key string from a KeyboardEvent.
 * Returns strings like 'mod+shift+z', 'mod+s', 'escape', etc.
 */
function buildKeyString(e) {
  const parts = [];

  // 'mod' maps to metaKey on Mac, ctrlKey elsewhere
  if (isMac ? e.metaKey : e.ctrlKey) {
    parts.push('mod');
  }

  if (e.shiftKey) {
    parts.push('shift');
  }

  if (e.altKey) {
    parts.push('alt');
  }

  // Normalize the key name
  let key = e.key.toLowerCase();

  // Map special keys
  if (key === ' ') key = 'space';
  if (key === 'backspace') key = 'backspace';
  if (key === 'enter') key = 'enter';

  // Skip modifier-only key presses
  if (['control', 'meta', 'shift', 'alt'].includes(key)) {
    return '';
  }

  parts.push(key);
  return parts.join('+');
}

/**
 * Check if the currently focused element is an input field,
 * textarea, select, or contentEditable element.
 */
function isInputFocused() {
  const el = document.activeElement;
  if (!el) return false;

  const tagName = el.tagName?.toUpperCase();
  if (tagName === 'INPUT' || tagName === 'TEXTAREA' || tagName === 'SELECT') {
    return true;
  }
  if (el.isContentEditable) {
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
export default function useKeyboardShortcuts() {
  // Map of action name -> handler function
  const handlersRef = useRef(new Map());

  // -----------------------------------------------------------------------
  // registerHandler — register a callback for an action name
  // -----------------------------------------------------------------------
  const registerHandler = useCallback((actionName, fn) => {
    handlersRef.current.set(actionName, fn);
  }, []);

  // -----------------------------------------------------------------------
  // unregisterHandler — remove callback for an action name
  // -----------------------------------------------------------------------
  const unregisterHandler = useCallback((actionName) => {
    handlersRef.current.delete(actionName);
  }, []);

  // -----------------------------------------------------------------------
  // Main keydown listener
  // -----------------------------------------------------------------------
  useEffect(() => {
    function handleKeyDown(e) {
      const keyString = buildKeyString(e);
      if (!keyString) return;

      // Check mod+ shortcuts first (always fire regardless of focus)
      const modAction = DEFAULT_SHORTCUTS[keyString];
      if (modAction) {
        const handler = handlersRef.current.get(modAction);
        if (handler) {
          e.preventDefault();
          e.stopPropagation();
          handler(e);
          return;
        }
      }

      // Check single-key shortcuts (only when not focused in an input)
      if (!isInputFocused()) {
        const singleAction = SINGLE_KEY_SHORTCUTS[keyString];
        if (singleAction) {
          const handler = handlersRef.current.get(singleAction);
          if (handler) {
            e.preventDefault();
            handler(e);
            return;
          }
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    registerHandler,
    unregisterHandler,
    shortcuts: { ...DEFAULT_SHORTCUTS, ...SINGLE_KEY_SHORTCUTS },
  };
}

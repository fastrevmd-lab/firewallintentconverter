/**
 * UndoContext — History stack for undo/redo
 *
 * Maintains past/future stacks of intermediateConfig snapshots
 * (max 50 entries in `past`). Exposes a `restoreTarget` value
 * that other contexts can watch to know when to apply a restored snapshot.
 */
import React, { createContext, useContext, useReducer, useCallback } from 'react';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const MAX_HISTORY = 50;

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------
const initialState = {
  past: [],
  future: [],
  restoreTarget: null,
};

// ---------------------------------------------------------------------------
// Deep clone helper (structured clone with JSON fallback)
// ---------------------------------------------------------------------------
function deepClone(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof structuredClone === 'function') {
    return structuredClone(obj);
  }
  return JSON.parse(JSON.stringify(obj));
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------
function undoReducer(state, action) {
  switch (action.type) {
    // Push current config snapshot onto the past stack, clear future
    case 'PUSH': {
      const snapshot = deepClone(action.snapshot);
      const nextPast = [...state.past, snapshot];
      // Enforce max history length
      if (nextPast.length > MAX_HISTORY) {
        nextPast.shift();
      }
      return {
        ...state,
        past: nextPast,
        future: [],
        restoreTarget: null,
      };
    }

    // Undo: pop from past, push currentConfig to future, set restoreTarget
    case 'UNDO': {
      if (state.past.length === 0) return state;
      const nextPast = state.past.slice();
      const restored = nextPast.pop();
      const currentSnapshot = deepClone(action.currentConfig);
      return {
        ...state,
        past: nextPast,
        future: [...state.future, currentSnapshot],
        restoreTarget: restored,
      };
    }

    // Redo: pop from future, push currentConfig to past, set restoreTarget
    case 'REDO': {
      if (state.future.length === 0) return state;
      const nextFuture = state.future.slice();
      const restored = nextFuture.pop();
      const currentSnapshot = deepClone(action.currentConfig);
      const nextPast = [...state.past, currentSnapshot];
      if (nextPast.length > MAX_HISTORY) {
        nextPast.shift();
      }
      return {
        ...state,
        past: nextPast,
        future: nextFuture,
        restoreTarget: restored,
      };
    }

    // Clear: consumed after restoreTarget has been applied, or full reset
    case 'CLEAR':
      return { ...initialState };

    // Clear restoreTarget after it has been consumed
    case 'CONSUME_RESTORE':
      return { ...state, restoreTarget: null };

    default:
      console.warn(`UndoContext: unhandled action "${action.type}"`);
      return state;
  }
}

// ---------------------------------------------------------------------------
// Context + Provider
// ---------------------------------------------------------------------------
const UndoContext = createContext(null);

function UndoProvider({ children }) {
  const [state, dispatch] = useReducer(undoReducer, initialState);

  const value = React.useMemo(
    () => ({
      state,
      dispatch,
      canUndo: state.past.length > 0,
      canRedo: state.future.length > 0,
    }),
    [state],
  );

  return (
    <UndoContext.Provider value={value}>
      {children}
    </UndoContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
function useUndoContext() {
  const ctx = useContext(UndoContext);
  if (!ctx) {
    throw new Error('useUndoContext must be used within an <UndoProvider>');
  }
  return ctx;
}

export { UndoContext, UndoProvider, useUndoContext };

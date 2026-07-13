/**
 * MergeContext — Multi-firewall merge mode state
 *
 * Owns merge mode toggle, config slot management,
 * active slot tracking, and cross-logical-system links.
 */
import React, { createContext, useContext, useReducer } from 'react';

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------
export const initialState = {
  mergeMode: false,
  configSlots: [],
  activeSlotIndex: 0,
  crossLsLinks: [],
};

const SLOT_PROVENANCE_FIELDS = new Set([
  'configText', 'intermediateConfig', 'sourceVendor', 'sourceModel',
  'interfaceMappings', 'srxTranslatedPolicies', 'ruleGroups',
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function replaceAt(arr, index, item) {
  const next = arr.slice();
  next[index] = item;
  return next;
}

function removeAt(arr, index) {
  const next = arr.slice();
  next.splice(index, 1);
  return next;
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------
export function mergeReducer(state, action) {
  switch (action.type) {
    // Generic single-field setter
    case 'SET_FIELD':
      return { ...state, [action.field]: action.value };

    // Toggle or explicitly set merge mode
    case 'SET_MERGE_MODE':
      return { ...state, mergeMode: action.enabled };

    // Add a new config slot
    case 'ADD_SLOT':
      return {
        ...state,
        configSlots: [...state.configSlots, action.slot],
      };

    // Remove a slot by index, adjusting activeSlotIndex if needed
    case 'REMOVE_SLOT': {
      const nextSlots = removeAt(state.configSlots, action.index);
      let nextActive = state.activeSlotIndex;
      if (nextActive >= nextSlots.length) {
        nextActive = Math.max(0, nextSlots.length - 1);
      }
      return {
        ...state,
        configSlots: nextSlots,
        activeSlotIndex: nextActive,
      };
    }

    // Update a slot at a given index (shallow merge with existing slot)
    case 'UPDATE_SLOT': {
      const invalidates = action.preserveSanitization !== true
        && Object.keys(action.slot).some(key => SLOT_PROVENANCE_FIELDS.has(key));
      const updatedSlot = {
        ...state.configSlots[action.index],
        ...action.slot,
        ...(invalidates ? {
          isSanitized: false,
          projectSecurityMode: 'unsanitized',
        } : {}),
      };
      return {
        ...state,
        configSlots: replaceAt(
          state.configSlots,
          action.index,
          updatedSlot,
        ),
      };
    }

    // Set the active slot index
    case 'SET_ACTIVE_SLOT':
      return { ...state, activeSlotIndex: action.index };

    // Set cross-logical-system links
    case 'SET_CROSS_LS_LINKS':
      return { ...state, crossLsLinks: action.links };

    // Full reset to initial state (workspace reset)
    case 'RESET':
      return { ...initialState };

    // Restore from a project file
    case 'LOAD_PROJECT': {
      const s = action.state;
      return {
        ...initialState,
        ...s,
      };
    }

    default:
      console.warn(`MergeContext: unhandled action "${action.type}"`);
      return state;
  }
}

// ---------------------------------------------------------------------------
// Context + Provider
// ---------------------------------------------------------------------------
const MergeContext = createContext(null);

function MergeProvider({ children }) {
  const [state, dispatch] = useReducer(mergeReducer, initialState);

  const value = React.useMemo(() => ({ state, dispatch }), [state]);

  return (
    <MergeContext.Provider value={value}>
      {children}
    </MergeContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
function useMergeContext() {
  const ctx = useContext(MergeContext);
  if (!ctx) {
    throw new Error('useMergeContext must be used within a <MergeProvider>');
  }
  return ctx;
}

export { MergeContext, MergeProvider, useMergeContext };

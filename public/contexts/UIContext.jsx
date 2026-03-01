/**
 * UIContext — Visual / UI state only
 *
 * Owns modal visibility, loading indicators, panel dimensions,
 * tab selection, and other transient UI state.
 * No data dependencies — purely presentational concerns.
 */
import React, { createContext, useContext, useReducer } from 'react';

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------
const initialState = {
  editTab: 'import',
  bottomTab: 'output',
  platformView: 'panos',
  selectedRule: null,
  isLoading: false,
  loadingMessage: '',
  error: null,

  // Modals / dialogs
  showModelSelector: false,
  showInterfaceMapper: false,
  showSettings: false,
  showFeedback: false,
  showConvertConfirm: false,
  showSaveModal: false,
  showReportModal: false,
  showLoadConfirm: null,
  showLLMWarning: false,
  showAutoSplitPrompt: null,
  showPushToast: '',
  showTour: localStorage.getItem('tour-completed') !== 'true',

  llmWarningDismissed: false,

  // LLM translation progress
  isTranslating: false,
  translationError: null,
  translationProgress: null,

  // Grouping
  groupingInProgress: false,

  // Layout
  leftSidebarCollapsed: false,
  leftSidebarWidth: 260,
  rightPanelCollapsed: false,
  rightPanelWidth: 320,

  // Command palette
  commandPaletteOpen: false,
};

// ---------------------------------------------------------------------------
// Modal name mapping — maps a short name to the state key
// ---------------------------------------------------------------------------
const MODAL_KEYS = {
  modelSelector: 'showModelSelector',
  interfaceMapper: 'showInterfaceMapper',
  settings: 'showSettings',
  feedback: 'showFeedback',
  convertConfirm: 'showConvertConfirm',
  saveModal: 'showSaveModal',
  reportModal: 'showReportModal',
  loadConfirm: 'showLoadConfirm',
  llmWarning: 'showLLMWarning',
  autoSplitPrompt: 'showAutoSplitPrompt',
  tour: 'showTour',
};

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------
function uiReducer(state, action) {
  switch (action.type) {
    // Generic single-field setter
    case 'SET_FIELD':
      return { ...state, [action.field]: action.value };

    // Combined loading setter
    case 'SET_LOADING':
      return {
        ...state,
        isLoading: action.isLoading,
        loadingMessage: action.message ?? '',
      };

    // Clear error
    case 'CLEAR_ERROR':
      return { ...state, error: null };

    // Show a named modal (value defaults to true, but can be an object for loadConfirm etc.)
    case 'SHOW_MODAL': {
      const key = MODAL_KEYS[action.name] || action.name;
      return { ...state, [key]: action.value !== undefined ? action.value : true };
    }

    // Hide a named modal
    case 'HIDE_MODAL': {
      const key = MODAL_KEYS[action.name] || action.name;
      // Reset to the "closed" value — null for object-typed modals, false for booleans
      const closed = typeof state[key] === 'boolean' ? false : null;
      return { ...state, [key]: closed };
    }

    // Toggle left sidebar collapsed state
    case 'TOGGLE_SIDEBAR':
      return { ...state, leftSidebarCollapsed: !state.leftSidebarCollapsed };

    // Toggle right inspector/panel collapsed state
    case 'TOGGLE_INSPECTOR':
      return { ...state, rightPanelCollapsed: !state.rightPanelCollapsed };

    // Set panel width by name
    case 'SET_PANEL_WIDTH': {
      if (action.panel === 'left') {
        return { ...state, leftSidebarWidth: action.width };
      }
      if (action.panel === 'right') {
        return { ...state, rightPanelWidth: action.width };
      }
      return state;
    }

    default:
      console.warn(`UIContext: unhandled action "${action.type}"`);
      return state;
  }
}

// ---------------------------------------------------------------------------
// Context + Provider
// ---------------------------------------------------------------------------
const UIContext = createContext(null);

function UIProvider({ children }) {
  const [state, dispatch] = useReducer(uiReducer, initialState);

  const value = React.useMemo(() => ({ state, dispatch }), [state]);

  return (
    <UIContext.Provider value={value}>
      {children}
    </UIContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
function useUIContext() {
  const ctx = useContext(UIContext);
  if (!ctx) {
    throw new Error('useUIContext must be used within a <UIProvider>');
  }
  return ctx;
}

export { UIContext, UIProvider, useUIContext };

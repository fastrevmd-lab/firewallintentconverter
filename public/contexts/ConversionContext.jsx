/**
 * ConversionContext — Output / conversion state
 *
 * Owns the SRX output text, conversion warnings, summary,
 * output format selection, and target routing context.
 */
import React, { createContext, useContext, useReducer } from 'react';

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------
const initialState = {
  srxOutput: null,
  convertWarnings: [],
  conversionSummary: null,
  outputFormat: 'set',
  targetContext: { type: 'none', name: '' },
};

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------
function conversionReducer(state, action) {
  switch (action.type) {
    // Generic single-field setter
    case 'SET_FIELD':
      return { ...state, [action.field]: action.value };

    // Bulk set after a successful conversion
    case 'SET_CONVERSION_RESULT':
      return {
        ...state,
        srxOutput: action.output ?? null,
        convertWarnings: action.warnings ?? [],
        conversionSummary: action.summary ?? null,
        outputFormat: action.format ?? state.outputFormat,
      };

    // Clear all output state
    case 'CLEAR_OUTPUT':
      return {
        ...state,
        srxOutput: null,
        convertWarnings: [],
        conversionSummary: null,
      };

    // Restore from a project file
    case 'LOAD_PROJECT': {
      const s = action.state;
      return {
        ...initialState,
        ...s,
      };
    }

    default:
      console.warn(`ConversionContext: unhandled action "${action.type}"`);
      return state;
  }
}

// ---------------------------------------------------------------------------
// Context + Provider
// ---------------------------------------------------------------------------
const ConversionContext = createContext(null);

function ConversionProvider({ children }) {
  const [state, dispatch] = useReducer(conversionReducer, initialState);

  const value = React.useMemo(() => ({ state, dispatch }), [state]);

  return (
    <ConversionContext.Provider value={value}>
      {children}
    </ConversionContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
function useConversionContext() {
  const ctx = useContext(ConversionContext);
  if (!ctx) {
    throw new Error(
      'useConversionContext must be used within a <ConversionProvider>',
    );
  }
  return ctx;
}

export { ConversionContext, ConversionProvider, useConversionContext };

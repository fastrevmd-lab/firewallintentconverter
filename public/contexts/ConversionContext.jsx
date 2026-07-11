/**
 * ConversionContext — Output / conversion state
 *
 * Owns the SRX output text, conversion warnings, summary,
 * output format selection, and target routing context.
 */
import React, { createContext, useContext, useReducer } from 'react';
import { assertConversionOutput } from '../../src/conversion/conversion-output.js';

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------
export const initialState = {
  srxOutput: null,
  convertWarnings: [],
  conversionSummary: null,
  outputFormat: 'set',
  targetContext: { type: 'none', name: '' },
  validationFindings: [],
};

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------
export function conversionReducer(state, action) {
  switch (action.type) {
    // Generic single-field setter
    case 'SET_FIELD':
      return { ...state, [action.field]: action.value };

    // Bulk set after a successful conversion
    case 'SET_CONVERSION_RESULT': {
      const output = assertConversionOutput(action.output);
      return {
        ...state,
        srxOutput: output,
        convertWarnings: action.warnings ?? [],
        conversionSummary: action.summary ?? output.summary ?? null,
        outputFormat: output.format,
        validationFindings: action.validationFindings ?? state.validationFindings,
      };
    }

    // Clear all output state
    case 'CLEAR_OUTPUT':
      return {
        ...state,
        srxOutput: null,
        convertWarnings: [],
        conversionSummary: null,
        validationFindings: [],
      };

    // Full reset to initial state (workspace reset — keeps no output)
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

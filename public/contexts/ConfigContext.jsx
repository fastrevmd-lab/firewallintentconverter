/**
 * ConfigContext — Core data model context
 *
 * Owns all parsed configuration state, rule management,
 * vendor/model selection, sanitization, and greenfield state.
 * Replaces ~20 useState calls from the monolithic app.jsx.
 */
import React, { createContext, useContext, useReducer, useCallback } from 'react';

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------
const initialState = {
  configText: '',
  intermediateConfig: null,
  parseWarnings: [],
  parseStats: null,
  sourceVendor: 'panos',
  sourceModel: '',
  targetModel: '',
  srxLicense: '',
  portProfile: null,
  siteName: '',
  siteGroup: '',
  interfaceMappings: {},
  isSanitized: false,
  sanitizationTable: null,
  projectSecurityMode: 'unsanitized',
  greenfieldMode: false,
  greenfieldTemplate: null,
  srxTranslatedPolicies: null,
  ruleGroups: [],
  selectedRuleKeys: new Set(),
  lastClickedKey: null,
  warningStatuses: {},
  sectionAcceptance: {},
};

const PROVENANCE_FIELDS = new Set([
  'configText', 'intermediateConfig', 'sourceVendor', 'interfaceMappings',
  'greenfieldMode', 'greenfieldTemplate',
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Immutably update an array element at `index`. */
function replaceAt(arr, index, item) {
  const next = arr.slice();
  next[index] = item;
  return next;
}

/** Immutably remove an array element at `index`. */
function removeAt(arr, index) {
  const next = arr.slice();
  next.splice(index, 1);
  return next;
}

function invalidateSanitization(state) {
  return {
    ...state,
    isSanitized: false,
    projectSecurityMode: 'unsanitized',
  };
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------
function configReducer(state, action) {
  switch (action.type) {
    // Generic single-field setter
    case 'SET_FIELD': {
      const next = { ...state, [action.field]: action.value };
      return PROVENANCE_FIELDS.has(action.field) || action.field === 'isSanitized'
        ? invalidateSanitization(next)
        : next;
    }

    case 'SET_SANITIZATION_RESULT':
      return {
        ...state,
        configText: action.configText,
        sanitizationTable: action.sanitizationTable,
        isSanitized: true,
        projectSecurityMode: 'sanitized',
      };

    // Bulk set after a successful parse
    case 'SET_PARSE_RESULT': {
      const next = {
        ...state,
        intermediateConfig: action.intermediateConfig,
        parseWarnings: action.warnings ?? [],
        parseStats: action.parseStats ?? null,
        sourceVendor: action.sourceVendor ?? state.sourceVendor,
      };
      return action.preserveSanitization === true
        ? next
        : invalidateSanitization(next);
    }

    // Functional update on intermediateConfig (updater receives prev, returns next)
    case 'UPDATE_CONFIG': {
      const updated = action.updater(state.intermediateConfig);
      return invalidateSanitization({ ...state, intermediateConfig: updated });
    }

    // --- Security policy CRUD (source/intermediate rules) ---
    case 'UPDATE_RULE': {
      if (!state.intermediateConfig?.security_policies) return state;
      const policies = replaceAt(
        state.intermediateConfig.security_policies,
        action.index,
        action.rule,
      );
      return invalidateSanitization({
        ...state,
        intermediateConfig: {
          ...state.intermediateConfig,
          security_policies: policies,
        },
      });
    }

    case 'DELETE_RULE': {
      if (!state.intermediateConfig?.security_policies) return state;
      const policies = removeAt(
        state.intermediateConfig.security_policies,
        action.index,
      );
      return invalidateSanitization({
        ...state,
        intermediateConfig: {
          ...state.intermediateConfig,
          security_policies: policies,
        },
      });
    }

    case 'ADD_RULE': {
      const existing = state.intermediateConfig?.security_policies ?? [];
      return invalidateSanitization({
        ...state,
        intermediateConfig: {
          ...state.intermediateConfig,
          security_policies: [...existing, action.rule],
        },
      });
    }

    // --- Translated (SRX) policy CRUD ---
    case 'SET_TRANSLATED_POLICIES':
      return invalidateSanitization({ ...state, srxTranslatedPolicies: action.policies });

    case 'UPDATE_TRANSLATED_RULE': {
      if (!state.srxTranslatedPolicies) return state;
      return invalidateSanitization({
        ...state,
        srxTranslatedPolicies: replaceAt(
          state.srxTranslatedPolicies,
          action.index,
          action.rule,
        ),
      });
    }

    case 'DELETE_TRANSLATED_RULE': {
      if (!state.srxTranslatedPolicies) return state;
      return invalidateSanitization({
        ...state,
        srxTranslatedPolicies: removeAt(
          state.srxTranslatedPolicies,
          action.index,
        ),
      });
    }

    case 'ADD_TRANSLATED_RULE': {
      const existing = state.srxTranslatedPolicies ?? [];
      return invalidateSanitization({
        ...state,
        srxTranslatedPolicies: [...existing, action.rule],
      });
    }

    // --- Rule grouping ---
    case 'SET_RULE_GROUPS':
      return invalidateSanitization({ ...state, ruleGroups: action.groups });

    // --- Bulk selection (Set stored immutably) ---
    case 'SET_SELECTED_KEYS':
      return { ...state, selectedRuleKeys: new Set(action.keys) };

    // --- Warning status tracking ---
    case 'SET_WARNING_STATUS':
      return {
        ...state,
        warningStatuses: {
          ...state.warningStatuses,
          [action.index]: action.status,
        },
      };

    // --- Section acceptance workflow ---
    case 'ACCEPT_SECTION':
      return {
        ...state,
        sectionAcceptance: { ...state.sectionAcceptance, [action.sectionId]: true },
      };

    case 'ACCEPT_SECTIONS':
      return {
        ...state,
        sectionAcceptance: {
          ...state.sectionAcceptance,
          ...Object.fromEntries(action.sectionIds.map(id => [id, true])),
        },
      };

    case 'REVOKE_SECTION':
      return {
        ...state,
        sectionAcceptance: { ...state.sectionAcceptance, [action.sectionId]: false },
      };

    // --- Full reset ---
    case 'RESET':
      return { ...initialState };

    // --- Project file restore ---
    case 'LOAD_PROJECT': {
      const s = action.state;
      return {
        ...initialState,
        ...s,
        // Ensure selectedRuleKeys is always a Set
        selectedRuleKeys: s.selectedRuleKeys
          ? new Set(s.selectedRuleKeys)
          : new Set(),
        sectionAcceptance: s.sectionAcceptance || {},
      };
    }

    default:
      console.warn(`ConfigContext: unhandled action "${action.type}"`);
      return state;
  }
}

// ---------------------------------------------------------------------------
// Context + Provider
// ---------------------------------------------------------------------------
const ConfigContext = createContext(null);

function ConfigProvider({ children }) {
  const [state, dispatch] = useReducer(configReducer, initialState);

  // Convenience: stable dispatch reference (useReducer dispatch is already stable)
  const value = React.useMemo(() => ({ state, dispatch }), [state]);

  return (
    <ConfigContext.Provider value={value}>
      {children}
    </ConfigContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
function useConfigContext() {
  const ctx = useContext(ConfigContext);
  if (!ctx) {
    throw new Error('useConfigContext must be used within a <ConfigProvider>');
  }
  return ctx;
}

export { ConfigContext, ConfigProvider, configReducer, initialState, useConfigContext };

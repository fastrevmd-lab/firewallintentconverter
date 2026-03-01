/**
 * useLLM — LLM translation and grouping hook
 *
 * Provides handlers for translating policies with an LLM,
 * grouping rules with AI, and managing translated policy CRUD
 * and bulk operations.
 * Uses ConfigContext and UIContext.
 */
import { useCallback, useState, useRef } from 'react';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import { useUIContext } from '../contexts/UIContext.jsx';
import { useMergeContext } from '../contexts/MergeContext.jsx';
import { translatePolicies, getLLMStatus, groupPolicies } from '../utils/llm-client.js';

// ---------------------------------------------------------------------------
// Helper: stable rule identity key
// ---------------------------------------------------------------------------
function makeRuleKey(policy) {
  return `${policy.name}::${policy._rule_index}`;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
export default function useLLM() {
  const { state: configState, dispatch: configDispatch } = useConfigContext();
  const { state: uiState, dispatch: uiDispatch } = useUIContext();
  const { state: mergeState } = useMergeContext();

  const {
    intermediateConfig,
    srxTranslatedPolicies,
    ruleGroups,
    selectedRuleKeys,
    lastClickedKey,
    isSanitized,
    sourceVendor,
  } = configState;

  const isHealthCheckMode = sourceVendor === 'srx_healthcheck';

  // Ref for shift-click tracking
  const lastClickedKeyRef = useRef(lastClickedKey);
  lastClickedKeyRef.current = lastClickedKey;

  // -----------------------------------------------------------------------
  // getCurrentPolicies — resolve which policy list is active
  // -----------------------------------------------------------------------
  const getCurrentPolicies = useCallback(() => {
    if (uiState.platformView === 'srx' && srxTranslatedPolicies) return srxTranslatedPolicies;
    const activeConfig = mergeState.mergeMode
      ? mergeState.configSlots[mergeState.activeSlotIndex]?.intermediateConfig
      : intermediateConfig;
    return activeConfig?.security_policies || [];
  }, [uiState.platformView, srxTranslatedPolicies, mergeState, intermediateConfig]);

  // -----------------------------------------------------------------------
  // handleTranslateWithLLM — translate policies via LLM, auto-switch to SRX
  // -----------------------------------------------------------------------
  const handleTranslateWithLLM = useCallback(async () => {
    if (!intermediateConfig?.security_policies?.length) return;

    // Check sanitization
    if (!isSanitized && !uiState.llmWarningDismissed) {
      uiDispatch({ type: 'SHOW_MODAL', name: 'llmWarning' });
      return;
    }

    // Check LLM is configured
    const status = getLLMStatus();
    if (!status.configured) {
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: 'No LLM provider configured. Open Settings to configure one.' });
      return;
    }

    uiDispatch({ type: 'SET_FIELD', field: 'isTranslating', value: true });
    uiDispatch({ type: 'SET_FIELD', field: 'translationError', value: null });
    uiDispatch({ type: 'SET_FIELD', field: 'translationProgress', value: null });
    uiDispatch({ type: 'CLEAR_ERROR' });
    uiDispatch({
      type: 'SET_LOADING',
      isLoading: true,
      message: isHealthCheckMode ? 'Running best practice audit...' : 'Translating policies with LLM...',
    });

    try {
      const translated = await translatePolicies(
        intermediateConfig,
        configState.targetModel || '',
        configState.srxLicense || '',
        (progress) => {
          uiDispatch({ type: 'SET_FIELD', field: 'translationProgress', value: progress });
        },
      );
      configDispatch({ type: 'SET_TRANSLATED_POLICIES', policies: translated });

      // Auto-switch to SRX view and rules tab
      uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: 'srx' });
      uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'rules' });
      uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
    } catch (err) {
      uiDispatch({ type: 'SET_FIELD', field: 'translationError', value: err.message });
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Translation error: ${err.message}` });
    } finally {
      uiDispatch({ type: 'SET_FIELD', field: 'isTranslating', value: false });
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [intermediateConfig, configState.targetModel, configState.srxLicense, isSanitized, uiState.llmWarningDismissed, isHealthCheckMode, configDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // handleGroupWithAI — group policies using LLM
  // -----------------------------------------------------------------------
  const handleGroupWithAI = useCallback(async () => {
    const policies = uiState.platformView === 'srx' && srxTranslatedPolicies
      ? srxTranslatedPolicies
      : (intermediateConfig?.security_policies || []);
    if (policies.length === 0) return;

    const llmStatus = getLLMStatus();
    if (!llmStatus.configured) {
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: 'LLM provider not configured. Open Settings to configure one.' });
      return;
    }

    uiDispatch({ type: 'SET_FIELD', field: 'groupingInProgress', value: true });
    try {
      const groups = await groupPolicies(policies, (progress) => {
        console.log('[group]', progress.phase, progress.detail);
      });
      configDispatch({ type: 'SET_RULE_GROUPS', groups });
    } catch (err) {
      console.error('[group] Error:', err);
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Grouping failed: ${err.message}` });
    } finally {
      uiDispatch({ type: 'SET_FIELD', field: 'groupingInProgress', value: false });
    }
  }, [uiState.platformView, srxTranslatedPolicies, intermediateConfig, configDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // Review handlers (source policies)
  // -----------------------------------------------------------------------

  const handleAcceptRule = useCallback((index) => {
    configDispatch({
      type: 'UPDATE_RULE',
      index,
      rule: {
        ...(intermediateConfig?.security_policies?.[index]),
        _review_status: 'accepted',
      },
    });
    uiDispatch({
      type: 'SET_FIELD',
      field: 'selectedRule',
      value: uiState.selectedRule
        ? { ...uiState.selectedRule, _review_status: 'accepted' }
        : null,
    });
  }, [intermediateConfig, uiState.selectedRule, configDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // Translated policy CRUD
  // -----------------------------------------------------------------------

  const handleUpdateTranslatedRule = useCallback((index, updatedRule) => {
    configDispatch({ type: 'UPDATE_TRANSLATED_RULE', index, rule: updatedRule });
  }, [configDispatch]);

  const handleAcceptTranslatedRule = useCallback((index) => {
    if (!srxTranslatedPolicies) return;
    configDispatch({
      type: 'UPDATE_TRANSLATED_RULE',
      index,
      rule: { ...srxTranslatedPolicies[index], _review_status: 'accepted' },
    });
    uiDispatch({
      type: 'SET_FIELD',
      field: 'selectedRule',
      value: uiState.selectedRule
        ? { ...uiState.selectedRule, _review_status: 'accepted' }
        : null,
    });
  }, [srxTranslatedPolicies, uiState.selectedRule, configDispatch, uiDispatch]);

  const handleDeleteTranslatedRule = useCallback((index) => {
    configDispatch({ type: 'DELETE_TRANSLATED_RULE', index });
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
  }, [configDispatch, uiDispatch]);

  const handleAddTranslatedRule = useCallback(() => {
    const arr = srxTranslatedPolicies || [];
    const newIndex = arr.length;
    configDispatch({
      type: 'ADD_TRANSLATED_RULE',
      rule: {
        name: `new-rule-${newIndex + 1}`,
        _rule_index: newIndex,
        action: 'deny',
        src_zones: [],
        dst_zones: [],
        src_addresses: [],
        dst_addresses: [],
        negate_source: false,
        negate_destination: false,
        applications: [],
        services: [],
        log_start: false,
        log_end: true,
        disabled: false,
        description: '',
        tags: [],
        profile_group: '',
        security_profiles: {},
        _review_status: 'accepted',
        _translation_notes: 'Manually added rule',
      },
    });
  }, [srxTranslatedPolicies, configDispatch]);

  // -----------------------------------------------------------------------
  // Bulk selection operations
  // -----------------------------------------------------------------------

  const handleToggleRuleSelect = useCallback((policy, event) => {
    const key = makeRuleKey(policy);
    const newKeys = new Set(selectedRuleKeys);

    if (event?.shiftKey && lastClickedKeyRef.current) {
      const policies = getCurrentPolicies();
      const lastIdx = policies.findIndex(p => makeRuleKey(p) === lastClickedKeyRef.current);
      const curIdx = policies.findIndex(p => makeRuleKey(p) === key);
      if (lastIdx >= 0 && curIdx >= 0) {
        const [start, end] = [Math.min(lastIdx, curIdx), Math.max(lastIdx, curIdx)];
        for (let i = start; i <= end; i++) newKeys.add(makeRuleKey(policies[i]));
      }
    } else if (newKeys.has(key)) {
      newKeys.delete(key);
    } else {
      newKeys.add(key);
    }

    configDispatch({ type: 'SET_SELECTED_KEYS', keys: [...newKeys] });
    configDispatch({ type: 'SET_FIELD', field: 'lastClickedKey', value: key });
  }, [selectedRuleKeys, getCurrentPolicies, configDispatch]);

  const handleSelectAllRules = useCallback((selectAll) => {
    if (selectAll) {
      configDispatch({ type: 'SET_SELECTED_KEYS', keys: getCurrentPolicies().map(makeRuleKey) });
    } else {
      configDispatch({ type: 'SET_SELECTED_KEYS', keys: [] });
    }
  }, [getCurrentPolicies, configDispatch]);

  const handleBulkAccept = useCallback(() => {
    const isTranslated = uiState.platformView === 'srx' && srxTranslatedPolicies;
    if (isTranslated) {
      const updated = srxTranslatedPolicies.map(p =>
        selectedRuleKeys.has(makeRuleKey(p)) ? { ...p, _review_status: 'accepted' } : p,
      );
      configDispatch({ type: 'SET_TRANSLATED_POLICIES', policies: updated });
    } else {
      configDispatch({
        type: 'UPDATE_CONFIG',
        updater: prev => ({
          ...prev,
          security_policies: prev.security_policies.map(p =>
            selectedRuleKeys.has(makeRuleKey(p)) ? { ...p, _review_status: 'accepted' } : p,
          ),
        }),
      });
    }
    configDispatch({ type: 'SET_SELECTED_KEYS', keys: [] });
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
  }, [selectedRuleKeys, uiState.platformView, srxTranslatedPolicies, configDispatch, uiDispatch]);

  const handleBulkDelete = useCallback(() => {
    const isTranslated = uiState.platformView === 'srx' && srxTranslatedPolicies;
    if (isTranslated) {
      const filtered = srxTranslatedPolicies
        .filter(p => !selectedRuleKeys.has(makeRuleKey(p)))
        .map((p, i) => ({ ...p, _rule_index: i }));
      configDispatch({ type: 'SET_TRANSLATED_POLICIES', policies: filtered });
    } else {
      configDispatch({
        type: 'UPDATE_CONFIG',
        updater: prev => ({
          ...prev,
          security_policies: prev.security_policies.filter(p => !selectedRuleKeys.has(makeRuleKey(p))),
        }),
      });
    }
    configDispatch({ type: 'SET_SELECTED_KEYS', keys: [] });
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
  }, [selectedRuleKeys, uiState.platformView, srxTranslatedPolicies, configDispatch, uiDispatch]);

  const handleBulkToggleDisable = useCallback(() => {
    const isTranslated = uiState.platformView === 'srx' && srxTranslatedPolicies;
    if (isTranslated) {
      const updated = srxTranslatedPolicies.map(p =>
        selectedRuleKeys.has(makeRuleKey(p)) ? { ...p, disabled: !p.disabled } : p,
      );
      configDispatch({ type: 'SET_TRANSLATED_POLICIES', policies: updated });
    } else {
      configDispatch({
        type: 'UPDATE_CONFIG',
        updater: prev => ({
          ...prev,
          security_policies: prev.security_policies.map(p =>
            selectedRuleKeys.has(makeRuleKey(p)) ? { ...p, disabled: !p.disabled } : p,
          ),
        }),
      });
    }
    configDispatch({ type: 'SET_SELECTED_KEYS', keys: [] });
  }, [selectedRuleKeys, uiState.platformView, srxTranslatedPolicies, configDispatch]);

  const handleBulkMove = useCallback((direction) => {
    const mutate = (policies) => {
      const result = [...policies];
      const selectedIndices = result
        .map((p, i) => selectedRuleKeys.has(makeRuleKey(p)) ? i : -1)
        .filter(i => i >= 0);

      if (direction === 'up') {
        for (const idx of selectedIndices) {
          if (idx === 0) return result;
          if (selectedRuleKeys.has(makeRuleKey(result[idx - 1]))) continue;
          [result[idx - 1], result[idx]] = [result[idx], result[idx - 1]];
        }
      } else {
        for (let j = selectedIndices.length - 1; j >= 0; j--) {
          const idx = selectedIndices[j];
          if (idx >= result.length - 1) return result;
          if (selectedRuleKeys.has(makeRuleKey(result[idx + 1]))) continue;
          [result[idx], result[idx + 1]] = [result[idx + 1], result[idx]];
        }
      }
      return result.map((p, i) => ({ ...p, _rule_index: i }));
    };

    const isTranslated = uiState.platformView === 'srx' && srxTranslatedPolicies;
    if (isTranslated) {
      configDispatch({
        type: 'SET_TRANSLATED_POLICIES',
        policies: srxTranslatedPolicies ? mutate(srxTranslatedPolicies) : null,
      });
    } else {
      configDispatch({
        type: 'UPDATE_CONFIG',
        updater: prev => ({ ...prev, security_policies: mutate(prev.security_policies) }),
      });
    }
  }, [selectedRuleKeys, uiState.platformView, srxTranslatedPolicies, configDispatch]);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    // LLM state
    isTranslating: uiState.isTranslating,
    translationProgress: uiState.translationProgress,
    translationError: uiState.translationError,
    srxTranslatedPolicies,
    ruleGroups,
    groupingInProgress: uiState.groupingInProgress,
    selectedRuleKeys,

    // Translation / grouping
    handleTranslateWithLLM,
    handleGroupWithAI,

    // Review handlers
    handleAcceptRule,

    // Translated policy CRUD
    handleUpdateTranslatedRule,
    handleAcceptTranslatedRule,
    handleDeleteTranslatedRule,
    handleAddTranslatedRule,

    // Bulk selection
    handleToggleRuleSelect,
    handleSelectAllRules,
    handleBulkAccept,
    handleBulkDelete,
    handleBulkToggleDisable,
    handleBulkMove,
  };
}

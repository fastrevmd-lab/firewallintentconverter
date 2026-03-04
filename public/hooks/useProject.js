/**
 * useProject — Project save/load hook
 *
 * Provides handlers for saving/loading .fpic.json project files
 * and restoring all application state from a loaded project.
 * Uses ConfigContext, UIContext, ConversionContext, and MergeContext.
 */
import { useCallback } from 'react';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import { useUIContext } from '../contexts/UIContext.jsx';
import { useConversionContext } from '../contexts/ConversionContext.jsx';
import { useMergeContext } from '../contexts/MergeContext.jsx';
import { buildProjectPayload, validateProjectFile, generateProjectName } from '../utils/project-io.js';
import { safeJsonParse } from '../utils/safe-json.js';

export default function useProject() {
  const { state: configState, dispatch: configDispatch } = useConfigContext();
  const { state: uiState, dispatch: uiDispatch } = useUIContext();
  const { state: conversionState, dispatch: conversionDispatch } = useConversionContext();
  const { state: mergeState, dispatch: mergeDispatch } = useMergeContext();

  // -----------------------------------------------------------------------
  // handleSaveProject — build payload from all state, download as .fpic.json
  // -----------------------------------------------------------------------
  const handleSaveProject = useCallback((projectName) => {
    // Assemble the full state bag from all contexts
    const stateBag = {
      // ConfigContext
      configText: configState.configText,
      intermediateConfig: configState.intermediateConfig,
      sourceVendor: configState.sourceVendor,
      sourceModel: configState.sourceModel,
      targetModel: configState.targetModel,
      srxLicense: configState.srxLicense,
      portProfile: configState.portProfile,
      siteName: configState.siteName,
      siteGroup: configState.siteGroup,
      interfaceMappings: configState.interfaceMappings,
      isSanitized: configState.isSanitized,
      sanitizationTable: configState.sanitizationTable,
      parseWarnings: configState.parseWarnings,
      parseStats: configState.parseStats,
      warningStatuses: configState.warningStatuses,
      srxTranslatedPolicies: configState.srxTranslatedPolicies,
      ruleGroups: configState.ruleGroups,
      sectionAcceptance: configState.sectionAcceptance,
      greenfieldMode: configState.greenfieldMode,
      greenfieldTemplate: configState.greenfieldTemplate,

      // ConversionContext
      srxOutput: conversionState.srxOutput,
      convertWarnings: conversionState.convertWarnings,
      conversionSummary: conversionState.conversionSummary,
      outputFormat: conversionState.outputFormat,
      targetContext: conversionState.targetContext,

      // UIContext
      editTab: uiState.editTab,
      platformView: uiState.platformView,
      bottomTab: uiState.bottomTab,

      // MergeContext
      mergeMode: mergeState.mergeMode,
      configSlots: mergeState.configSlots,
      activeSlotIndex: mergeState.activeSlotIndex,
      crossLsLinks: mergeState.crossLsLinks,
    };

    const payload = buildProjectPayload(stateBag, projectName);
    const jsonStr = JSON.stringify(payload, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${projectName}.fpic.json`;
    a.click();
    URL.revokeObjectURL(url);

    uiDispatch({ type: 'HIDE_MODAL', name: 'saveModal' });
  }, [configState, conversionState, uiState, mergeState, uiDispatch]);

  // -----------------------------------------------------------------------
  // handleLoadProjectFile — read file, validate, show load confirm dialog
  // -----------------------------------------------------------------------
  const handleLoadProjectFile = useCallback((e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const json = safeJsonParse(event.target.result);
        const result = validateProjectFile(json);
        if (!result.valid) {
          uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Load project failed: ${result.error}` });
          return;
        }
        uiDispatch({
          type: 'SHOW_MODAL',
          name: 'loadConfirm',
          value: { project: result.project, warnings: result.warnings },
        });
      } catch (err) {
        uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Load project failed: Invalid JSON file. ${err.message}` });
      }
    };
    reader.readAsText(file);
  }, [uiDispatch]);

  // -----------------------------------------------------------------------
  // applyLoadedProject — restore all state from a project, dispatch
  //                       LOAD_PROJECT to all contexts
  // -----------------------------------------------------------------------
  const applyLoadedProject = useCallback((project) => {
    const s = project.state;

    // Dispatch LOAD_PROJECT to each context with its relevant state subset
    configDispatch({
      type: 'LOAD_PROJECT',
      state: {
        configText: s.configText ?? '',
        intermediateConfig: s.intermediateConfig ?? null,
        sourceVendor: s.sourceVendor ?? 'panos',
        sourceModel: s.sourceModel ?? '',
        targetModel: s.targetModel ?? '',
        srxLicense: s.srxLicense ?? '',
        portProfile: s.portProfile ?? null,
        siteName: s.siteName ?? '',
        siteGroup: s.siteGroup ?? '',
        interfaceMappings: s.interfaceMappings ?? {},
        isSanitized: s.isSanitized ?? false,
        sanitizationTable: s.sanitizationTable ?? null,
        parseWarnings: s.parseWarnings ?? [],
        parseStats: s.parseStats ?? null,
        warningStatuses: s.warningStatuses ?? {},
        srxTranslatedPolicies: s.srxTranslatedPolicies ?? null,
        ruleGroups: s.ruleGroups ?? [],
        sectionAcceptance: s.sectionAcceptance ?? {},
        greenfieldMode: s.greenfieldMode ?? false,
        greenfieldTemplate: s.greenfieldTemplate ?? null,
        selectedRuleKeys: [],
        lastClickedKey: null,
      },
    });

    conversionDispatch({
      type: 'LOAD_PROJECT',
      state: {
        srxOutput: s.srxOutput ?? null,
        convertWarnings: s.convertWarnings ?? [],
        conversionSummary: s.conversionSummary ?? null,
        outputFormat: s.outputFormat ?? 'set',
        targetContext: s.targetContext ?? { type: 'none', name: '' },
      },
    });

    mergeDispatch({
      type: 'LOAD_PROJECT',
      state: {
        mergeMode: s.mergeMode ?? false,
        configSlots: s.configSlots ?? [],
        activeSlotIndex: s.activeSlotIndex ?? 0,
        crossLsLinks: s.crossLsLinks ?? [],
      },
    });

    // Reset transient UI state
    uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: s.editTab ?? 'rules' });
    uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: s.platformView ?? 'panos' });
    uiDispatch({ type: 'SET_FIELD', field: 'bottomTab', value: s.bottomTab ?? 'output' });
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
    uiDispatch({ type: 'CLEAR_ERROR' });
    uiDispatch({ type: 'SET_LOADING', isLoading: false });
    uiDispatch({ type: 'HIDE_MODAL', name: 'modelSelector' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'interfaceMapper' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'llmWarning' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'loadConfirm' });
    uiDispatch({
      type: 'SET_FIELD',
      field: 'llmWarningDismissed',
      value: s.isSanitized || s.greenfieldMode || false,
    });
  }, [configDispatch, conversionDispatch, mergeDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // generateName — convenience wrapper around generateProjectName
  // -----------------------------------------------------------------------
  const generateName = useCallback(() => {
    return generateProjectName(
      configState.sourceVendor,
      configState.sourceModel,
      configState.siteName,
    );
  }, [configState.sourceVendor, configState.sourceModel, configState.siteName]);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    handleSaveProject,
    handleLoadProjectFile,
    applyLoadedProject,
    generateName,
  };
}

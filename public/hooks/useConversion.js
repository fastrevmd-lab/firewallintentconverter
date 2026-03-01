/**
 * useConversion — Conversion handler hook
 *
 * Provides handlers for converting parsed intermediate configs
 * (single or merged) to SRX set/XML output format.
 * Uses ConfigContext, ConversionContext, UIContext, and MergeContext.
 */
import { useCallback } from 'react';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import { useConversionContext } from '../contexts/ConversionContext.jsx';
import { useUIContext } from '../contexts/UIContext.jsx';
import { useMergeContext } from '../contexts/MergeContext.jsx';
import { convertConfig, mergeConvert } from '../utils/engine.js';

export default function useConversion() {
  const { state: configState } = useConfigContext();
  const { state: conversionState, dispatch: conversionDispatch } = useConversionContext();
  const { state: uiState, dispatch: uiDispatch } = useUIContext();
  const { state: mergeState } = useMergeContext();

  const {
    intermediateConfig,
    srxTranslatedPolicies,
    ruleGroups,
    interfaceMappings,
    siteName,
    siteGroup,
  } = configState;

  const { targetContext } = conversionState;

  // -----------------------------------------------------------------------
  // handleConvert — convert a single parsed config to SRX output
  // -----------------------------------------------------------------------
  const handleConvert = useCallback((format = 'set') => {
    if (!intermediateConfig) return;

    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Converting to SRX format...' });
    uiDispatch({ type: 'CLEAR_ERROR' });

    try {
      // Merge translated policies into the config for conversion
      let configForConversion = srxTranslatedPolicies
        ? { ...intermediateConfig, security_policies: srxTranslatedPolicies }
        : { ...intermediateConfig };

      // Attach rule groups for group comment output
      if (ruleGroups && ruleGroups.length > 0) {
        configForConversion._rule_groups = ruleGroups;
      }

      // Inject site identification metadata for output headers
      if (siteName || siteGroup) {
        configForConversion.metadata = {
          ...configForConversion.metadata,
          siteName: siteName || undefined,
          siteGroup: siteGroup || undefined,
        };
      }

      const data = convertConfig(
        configForConversion,
        format,
        interfaceMappings,
        targetContext.type !== 'none' ? targetContext : null,
      );

      conversionDispatch({
        type: 'SET_CONVERSION_RESULT',
        output: data.output,
        warnings: data.output.warnings || [],
        summary: data.output.summary || null,
        format,
      });

      // Reset warning statuses and switch to output tab
      uiDispatch({ type: 'SET_FIELD', field: 'bottomTab', value: 'output' });
    } catch (err) {
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Conversion error: ${err.message}` });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [intermediateConfig, interfaceMappings, srxTranslatedPolicies, ruleGroups, siteName, siteGroup, targetContext, conversionDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // handleConvertClick — warn if not all rules accepted, else convert
  // -----------------------------------------------------------------------
  const handleConvertClick = useCallback((format = 'set') => {
    // Check if all rules are accepted
    const policies = (uiState.platformView === 'srx' && srxTranslatedPolicies)
      ? srxTranslatedPolicies
      : (intermediateConfig?.security_policies || []);
    const accepted = policies.filter(r => r._review_status === 'accepted' || r.disabled).length;
    const allAccepted = policies.length > 0 && accepted === policies.length;

    if (!allAccepted) {
      uiDispatch({ type: 'SHOW_MODAL', name: 'convertConfirm' });
      return;
    }
    handleConvert(format);
  }, [uiState.platformView, srxTranslatedPolicies, intermediateConfig, handleConvert, uiDispatch]);

  // -----------------------------------------------------------------------
  // handleMergeConvert — convert all parsed merge-mode slots to SRX output
  // -----------------------------------------------------------------------
  const handleMergeConvert = useCallback((format = 'set') => {
    const { configSlots, crossLsLinks } = mergeState;
    const parsedSlots = configSlots.filter(s => s.intermediateConfig);
    if (parsedSlots.length === 0) return;

    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Merging and converting to SRX format...' });
    uiDispatch({ type: 'CLEAR_ERROR' });

    try {
      const slotsPayload = parsedSlots.map(slot => ({
        lsName: slot.lsName,
        intermediateConfig: slot.srxTranslatedPolicies
          ? { ...slot.intermediateConfig, security_policies: slot.srxTranslatedPolicies }
          : slot.intermediateConfig,
        interfaceMappings: slot.interfaceMappings,
      }));

      // Extract global config (HA from first slot that has it, syslog aggregated)
      const globalConfig = {
        ha_config: parsedSlots.find(s => s.intermediateConfig.ha_config?.enabled)?.intermediateConfig.ha_config || { enabled: false },
        syslog_config: parsedSlots.flatMap(s => s.intermediateConfig.syslog_config || []),
      };

      const data = mergeConvert(slotsPayload, crossLsLinks, format, globalConfig);

      conversionDispatch({
        type: 'SET_CONVERSION_RESULT',
        output: data.output,
        warnings: data.output.warnings || [],
        summary: data.output.summary || null,
        format,
      });

      uiDispatch({ type: 'SET_FIELD', field: 'bottomTab', value: 'output' });
    } catch (err) {
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Merge conversion error: ${err.message}` });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [mergeState, conversionDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    // Conversion state (read-only)
    ...conversionState,

    // Handlers
    handleConvertClick,
    handleConvert,
    handleMergeConvert,
  };
}

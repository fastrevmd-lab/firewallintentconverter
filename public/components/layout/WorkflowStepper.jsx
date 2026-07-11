import React, { useState } from 'react';
import { useConfigContext } from '../../contexts/ConfigContext.jsx';
import { useConversionContext } from '../../contexts/ConversionContext.jsx';
import { useUIContext, isDeterministicMode } from '../../contexts/UIContext.jsx';
import { useMergeContext } from '../../contexts/MergeContext.jsx';
import useConfig from '../../hooks/useConfig.js';
import useConversion from '../../hooks/useConversion.js';
import { loadBridgeSettings } from '../../utils/bridge-client.js';
import { computeWorkflowSteps } from '../../utils/workflow-steps.js';

const VENDOR_DISPLAY = {
  panos: 'PAN-OS', srx: 'SRX', fortigate: 'FortiGate', cisco_asa: 'Cisco ASA',
  checkpoint: 'Check Point', sonicwall: 'SonicWall', huawei_usg: 'Huawei USG',
};

/**
 * WorkflowStepper — the promoted, numbered chevron rail for the migration workflow.
 * Renders the six step segments plus the contextual SRX action cluster (output
 * context select, Push to SRX, Validate, Enforce license). Hidden on the import
 * and batch tabs and before any config is loaded.
 * @returns {JSX.Element|null}
 */
export default function WorkflowStepper() {
  const { state: cfg } = useConfigContext();
  const { state: conv, dispatch: convDispatch } = useConversionContext();
  const { state: ui, dispatch: uiDispatch } = useUIContext();
  const { state: merge } = useMergeContext();

  const config = useConfig();
  const conversion = useConversion();

  const {
    sourceVendor, sourceModel, targetModel, greenfieldMode,
    intermediateConfig, srxTranslatedPolicies,
  } = cfg;
  const { editTab, platformView, isLoading } = ui;
  const { mergeMode, configSlots, activeSlotIndex } = merge;
  const { srxOutput, validationFindings, targetContext } = conv;

  const [enforceLicense, setEnforceLicense] = useState(false);

  const isHealthCheck = sourceVendor === 'srx_healthcheck';
  const activeConfig = mergeMode
    ? configSlots[activeSlotIndex]?.intermediateConfig
    : intermediateConfig;

  // Visibility: same situations the old platform bar appeared in.
  if (!activeConfig && !greenfieldMode) return null;
  if (editTab === 'import' || editTab === 'batch') return null;

  const deterministic = isDeterministicMode(ui.llmRiskAcceptance);
  const analysisCount = activeConfig?._analysisFindings?.reduce((s, f) => s + f.count, 0) || 0;
  const policies = activeConfig?.security_policies || [];
  const llmReviewedCount = policies.filter(p => p._review_status === 'llm_reviewed').length;

  const sourceLabel = greenfieldMode ? 'From LLM Interview'
    : isHealthCheck ? 'Original Config'
    : `From ${sourceModel || VENDOR_DISPLAY[sourceVendor] || 'PAN-OS'}`;
  const targetLabel = isHealthCheck ? 'Best Practice Status' : `to ${targetModel || 'SRX'}`;

  const steps = computeWorkflowSteps({
    editTab, platformView, analysisCount,
    hasTranslated: !!srxTranslatedPolicies, hasOutput: !!srxOutput,
    llmReviewedCount, mergeMode, sourceLabel, targetLabel,
  });

  const hasPolicies = !!activeConfig?.security_policies?.length;

  const goSource = () => {
    uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: 'panos' });
    uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'rules' });
  };
  const goAnalysis = () => {
    if (analysisCount > 0) uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'analysis' });
    else config.handleRunAnalysis();
  };
  const goReview = () => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'review' });
  const goSrx = () => {
    uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: 'srx' });
    uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'rules' });
  };
  const goConvert = () => (mergeMode ? conversion.handleMergeConvert('set') : conversion.handleConvertClick('set'));
  const goDay2 = () => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'day2ops' });

  const HANDLERS = { source: goSource, analysis: goAnalysis, review: goReview, srx: goSrx, convert: goConvert, day2: goDay2 };
  const DISABLED = {
    analysis: isLoading || !hasPolicies,
    convert: isLoading || !hasPolicies,
    day2: !hasPolicies,
  };

  const segClass = (step) => {
    const cls = ['wf-seg'];
    if (step.status === 'done') cls.push('wf-done');
    else if (step.status === 'current') cls.push(step.llm && !deterministic ? 'wf-cur-llm' : 'wf-cur');
    else if (step.status === 'available') cls.push(step.llm && !deterministic ? 'wf-avail-llm' : 'wf-avail');
    else cls.push('wf-upnext');
    return cls.join(' ');
  };

  return (
    <div className="workflow-stepper">
      <div className="wf-rail">
        {steps.map((step) => (
          <button
            key={step.id}
            className={segClass(step)}
            onClick={HANDLERS[step.id]}
            disabled={!!DISABLED[step.id]}
            title={step.optional ? `${step.label} (optional)` : step.label}
          >
            <span className="wf-num">{step.status === 'done' ? '\u2713' : step.num}</span>
            <span className="wf-text">
              <span className="wf-lbl">{step.label}</span>
              {step.optional
                ? <span className="wf-opt">Optional</span>
                : step.sub && <span className="wf-sub">{step.sub}</span>}
            </span>
          </button>
        ))}
      </div>

      {platformView === 'srx' && (
        <div className="wf-actions">
          <select
            className="btn btn-secondary btn-sm"
            value={targetContext.type}
            onChange={(e) => convDispatch({ type: 'SET_FIELD', field: 'targetContext', value: { ...targetContext, type: e.target.value, name: e.target.value === 'none' ? '' : targetContext.name } })}
            style={{ maxWidth: 130 }}
          >
            <option value="none">Flat Config</option>
            <option value="logical-system">Logical System</option>
            <option value="tenant">Tenant</option>
          </select>
          {targetContext.type !== 'none' && (
            <input
              type="text"
              className="btn btn-secondary btn-sm"
              placeholder="Name..."
              value={targetContext.name}
              onChange={(e) => convDispatch({ type: 'SET_FIELD', field: 'targetContext', value: { ...targetContext, name: e.target.value } })}
              style={{ maxWidth: 100, textAlign: 'left' }}
            />
          )}
          {srxOutput && (
            <>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => conversion.handleValidate(enforceLicense)}
                disabled={isLoading}
                title="Run post-conversion validation checks"
                style={{ color: 'var(--caution)' }}
              >
                Validate{validationFindings?.length > 0 ? ` (${validationFindings.length})` : ''}
              </button>
              <label
                style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--text-muted)', cursor: 'pointer' }}
                title="When enabled, commands requiring a higher license tier are removed from the SRX output"
              >
                <input type="checkbox" checked={enforceLicense} onChange={(e) => setEnforceLicense(e.target.checked)} style={{ margin: 0 }} />
                Enforce license
              </label>
            </>
          )}
          <button
            className="btn btn-secondary btn-sm push-btn"
            onClick={() => {
              const bridgeSettings = loadBridgeSettings();
              if (bridgeSettings.url && bridgeSettings.token) {
                uiDispatch({ type: 'SHOW_MODAL', name: 'pushModal' });
              } else {
                uiDispatch({ type: 'SHOW_MODAL', name: 'settings', value: 'mcp' });
              }
            }}
            title="Push config to SRX device via PyEZ"
            disabled={!srxOutput}
          >Push to SRX</button>
        </div>
      )}
    </div>
  );
}

import React from 'react';
import { useConfigContext } from '../../contexts/ConfigContext.jsx';
import { useConversionContext } from '../../contexts/ConversionContext.jsx';
import { useUIContext, isDeterministicMode } from '../../contexts/UIContext.jsx';

/**
 * TopBar — Top navigation bar.
 *
 * Displays brand, stats badges (after parsing), and action buttons.
 * Reads from context instead of props — mirrors the current navbar in app.jsx.
 */

const VENDOR_NAMES = {
  panos: 'PAN-OS',
  srx: 'SRX',
  fortigate: 'FortiGate',
  cisco_asa: 'Cisco ASA',
  checkpoint: 'Check Point',
  sonicwall: 'SonicWall',
  huawei_usg: 'Huawei USG',
};

export default function TopBar() {
  const { state: cfg, dispatch: cfgDispatch } = useConfigContext();
  const { state: conv } = useConversionContext();
  const { state: ui, dispatch: uiDispatch } = useUIContext();

  const {
    sourceVendor, sourceModel, targetModel, srxLicense,
    siteName, intermediateConfig, greenfieldMode, warningStatuses,
    configText,
  } = cfg;
  const { convertWarnings } = conv;
  const { isLoading, isTranslating, editTab } = ui;

  // Compute stats
  const displayStats = !!(intermediateConfig || greenfieldMode);
  const policyCount = intermediateConfig?.security_policies?.length || 0;
  const accepted = policyCount > 0
    ? intermediateConfig.security_policies.filter(p => p._review_status === 'accepted').length
    : 0;
  const llmReviewed = policyCount > 0
    ? intermediateConfig.security_policies.filter(p => p._review_status === 'llm_reviewed').length
    : 0;

  // Warning counts
  const allWarnings = convertWarnings || [];
  const unresolvedWarningCount = allWarnings.length -
    Object.values(warningStatuses).filter(s => s === 'acknowledged' || s === 'resolved').length;

  // Helpers
  const showModal = (name) => uiDispatch({ type: 'SHOW_MODAL', name });
  const setTab = (tab) => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: tab });

  return (
    <div className="app-topbar">
      {/* Left: Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '0 16px', flexShrink: 0 }}>
        <img src="/logo.png" alt="Intent Converter" style={{ width: 28, height: 28 }} />
        <h1 style={{ fontSize: 14, fontWeight: 600, whiteSpace: 'nowrap' }}>
          Firewall Policy to <span style={{ color: 'var(--accent)' }}>Intent Converter</span>
        </h1>
      </div>

      {/* Center: Stats badges */}
      {displayStats && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, justifyContent: 'center', flexWrap: 'wrap' }}>
          {(sourceModel || greenfieldMode) && (
            <span
              className="stat-badge model-badge"
              onClick={() => showModal('modelSelector')}
              style={{ cursor: 'pointer' }}
            >
              {greenfieldMode ? 'Greenfield' : sourceModel}
              <span style={{ color: 'var(--accent)', margin: '0 4px' }}>&rarr;</span>
              {targetModel || '?'}
            </span>
          )}
          {srxLicense && (
            <span
              className="stat-badge license-badge"
              onClick={() => showModal('modelSelector')}
              style={{ cursor: 'pointer' }}
            >
              License <span className="stat-value">{srxLicense}</span>
            </span>
          )}
          {siteName && (
            <span
              className="stat-badge"
              onClick={() => showModal('modelSelector')}
              style={{ cursor: 'pointer' }}
            >
              Site <span className="stat-value">{siteName}</span>
            </span>
          )}
          {allWarnings.length > 0 && (
            <span
              className="stat-badge"
              style={{ cursor: 'pointer' }}
              onClick={() => setTab('warnings')}
            >
              Warnings{' '}
              <span
                className="stat-value"
                style={{ color: unresolvedWarningCount > 0 ? 'var(--warning)' : 'var(--success)' }}
              >
                {unresolvedWarningCount}/{allWarnings.length}
              </span>
            </span>
          )}
          {intermediateConfig && (
            <span className="review-progress">
              Policies: {accepted}/{policyCount} accepted
              {llmReviewed > 0 && (
                <span style={{ color: 'var(--accent)', marginLeft: 6 }}>
                  ({llmReviewed} LLM reviewed)
                </span>
              )}
            </span>
          )}
        </div>
      )}

      {/* Spacer when no stats */}
      {!displayStats && <div style={{ flex: 1 }} />}

      {/* Right: Actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '0 12px', flexShrink: 0 }}>
        {intermediateConfig && (
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => showModal('modelSelector')}
            title="Change hardware models"
          >
            Models
          </button>
        )}
        {intermediateConfig && targetModel && (
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => showModal('interfaceMapper')}
            title="Edit interface mappings"
          >
            Interfaces
          </button>
        )}
        {intermediateConfig && targetModel && (
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => showModal('reportModal')}
            title="Generate migration report"
          >
            Report
          </button>
        )}

        {/* Save */}
        <button
          className="settings-btn"
          onClick={() => {
            if (!intermediateConfig && !configText) {
              uiDispatch({ type: 'SET_FIELD', field: 'error', value: 'Nothing to save. Parse a config or start a Greenfield interview first.' });
              return;
            }
            showModal('saveModal');
          }}
          title="Save project to file"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z" />
            <polyline points="17 21 17 13 7 13 7 21" />
            <polyline points="7 3 7 8 15 8" />
          </svg>
        </button>

        {/* Load */}
        <button
          className="settings-btn"
          onClick={() => {
            // Trigger file input — the actual file input lives in the parent shell
            const input = document.getElementById('topbar-project-file-input');
            if (input) input.click();
          }}
          title="Load project from file"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
            <line x1="12" y1="11" x2="12" y2="17" />
            <polyline points="9 14 12 11 15 14" />
          </svg>
        </button>

        {/* Tour */}
        <button
          className="settings-btn"
          onClick={() => showModal('tour')}
          title="Start guided tour"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        </button>

        {/* Feedback */}
        <button
          className="settings-btn"
          onClick={() => showModal('feedback')}
          title="Send feedback or suggest a feature"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </svg>
        </button>

        {isDeterministicMode(ui.llmRiskAcceptance) && (
          <button
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 4,
              padding: '2px 8px', borderRadius: 10, fontSize: 11, fontWeight: 600,
              background: 'var(--success)', color: '#fff',
              border: 'none', cursor: 'pointer',
            }}
            title="Click to change AI mode"
            onClick={() => uiDispatch({ type: 'SET_LLM_RISK_ACCEPTANCE', value: null })}
          >
            No AI
          </button>
        )}

        {/* Settings — hidden in deterministic mode (no LLM to configure) */}
        {!isDeterministicMode(ui.llmRiskAcceptance) && (
          <button
            className="settings-btn"
            onClick={() => showModal('settings')}
            title="Settings"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="3" />
              <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
}

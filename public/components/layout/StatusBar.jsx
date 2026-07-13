import React from 'react';
import { useConfigContext } from '../../contexts/ConfigContext.jsx';
import { useConversionContext } from '../../contexts/ConversionContext.jsx';
import { useUIContext } from '../../contexts/UIContext.jsx';
import { useUndoContext } from '../../contexts/UndoContext.jsx';
import ProjectSecurityBadge from '../ProjectSecurityBadge.jsx';

/**
 * StatusBar — Bottom bar showing conversion stats and quick indicators.
 */
export default function StatusBar({ projectSecurityDescriptor }) {
  const { state: cfg } = useConfigContext();
  const { state: conv } = useConversionContext();
  const { state: ui, dispatch: uiDispatch } = useUIContext();
  const { state: undo } = useUndoContext();

  const {
    sourceVendor, sourceModel, targetModel, intermediateConfig, warningStatuses,
    projectSecurityMode,
  } = cfg;
  const { conversionSummary, convertWarnings } = conv;

  // Policy counts
  const policyCount = intermediateConfig?.security_policies?.length || 0;
  const accepted = policyCount > 0
    ? intermediateConfig.security_policies.filter(p => p._review_status === 'accepted').length
    : 0;
  const reviewPct = policyCount > 0 ? Math.round((accepted / policyCount) * 100) : 0;

  // Warning counts
  const totalWarnings = convertWarnings?.length || 0;
  const resolvedWarnings = totalWarnings > 0
    ? Object.values(warningStatuses).filter(s => s === 'acknowledged' || s === 'resolved').length
    : 0;
  const unresolvedWarnings = totalWarnings - resolvedWarnings;

  // Undo depth
  const undoDepth = undo.past?.length || 0;

  // OS-aware modifier key
  const modKey = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform) ? 'Cmd' : 'Ctrl';

  // Vendor display name
  const VENDOR_NAMES = {
    panos: 'PAN-OS',
    srx: 'SRX',
    fortigate: 'FortiGate',
    cisco_asa: 'Cisco ASA',
    checkpoint: 'Check Point',
    sonicwall: 'SonicWall',
    huawei_usg: 'Huawei USG',
  };
  const vendorLabel = VENDOR_NAMES[sourceVendor] || sourceVendor;

  return (
    <div className="app-statusbar">
      {/* Source -> Target */}
      {sourceModel ? (
        <div
          className="status-item clickable"
          onClick={() => uiDispatch({ type: 'SHOW_MODAL', name: 'modelSelector' })}
          title="Change hardware models"
        >
          <span className="status-dot success" />
          <span>{sourceModel}</span>
          <span style={{ color: 'var(--accent)', margin: '0 2px' }}>&rarr;</span>
          <span style={{ color: 'var(--juniper-green)' }}>{targetModel || '?'}</span>
        </div>
      ) : (
        <div className="status-item">
          <span className="status-dot" style={{ background: 'var(--text-muted)' }} />
          <span>{vendorLabel}</span>
        </div>
      )}

      <div className="status-separator" />

      {/* Policies */}
      {policyCount > 0 && (
        <>
          <div
            className="status-item clickable"
            onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'rules' })}
            title="View policies"
          >
            <span>Policies: {accepted}/{policyCount}</span>
            <div className="status-progress">
              <div className="status-progress-fill" style={{ width: `${reviewPct}%` }} />
            </div>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', minWidth: 28, textAlign: 'right' }}>{reviewPct}%</span>
          </div>
          <div className="status-separator" />
        </>
      )}

      {/* Warnings */}
      {totalWarnings > 0 && (
        <>
          <div
            className="status-item clickable"
            onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'warnings' })}
            title="View warnings"
          >
            <span className={`status-dot ${unresolvedWarnings > 0 ? 'warning' : 'success'}`} />
            <span>Warnings: {unresolvedWarnings}/{totalWarnings}</span>
          </div>
          <div className="status-separator" />
        </>
      )}

      {/* Undo depth */}
      {undoDepth > 0 && (
        <>
          <div className="status-item" title="Undo history depth">
            <span>Undo: {undoDepth}</span>
          </div>
          <div className="status-separator" />
        </>
      )}

      {/* Spacer */}
      <div style={{ flex: 1 }} />

      <ProjectSecurityBadge
        mode={projectSecurityMode}
        descriptor={projectSecurityDescriptor}
      />

      {/* Keyboard hint */}
      <div
        className="status-item clickable"
        onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'commandPaletteOpen', value: true })}
        title="Open command palette"
        style={{ fontFamily: 'var(--font-mono)' }}
      >
        {modKey}+P Commands
      </div>
    </div>
  );
}

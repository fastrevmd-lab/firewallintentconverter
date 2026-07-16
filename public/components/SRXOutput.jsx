/**
 * SRXOutput Component
 *
 * Bottom panel displaying the generated SRX configuration.
 * Supports:
 *   - Set commands view (syntax-highlighted)
 *   - XML view
 *   - Download as .txt or .xml
 *   - Copy to clipboard
 *   - Conversion summary stats
 */
import React, { useState, useCallback } from 'react';
import { useUIContext } from '../contexts/UIContext.jsx';
import { exportToTerraform, exportToAnsible } from '../utils/iac-export.js';
import { loadBridgeSettings } from '../utils/bridge-client.js';
import {
  getConversionOutputPresentation,
  getSetExportCommands,
} from '../utils/conversion-output-consumer.js';

/** Download a text string as a file */
function downloadText(text, filename, mimeType = 'text/plain') {
  const blob = new Blob([text], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function SRXOutput({ output, summary, isParsed, sanitizationTable, onReconvert }) {
  const { state: uiState, dispatch: uiDispatch } = useUIContext();
  const [copied, setCopied] = useState(false);

  /** Get validated output text and every format-sensitive presentation property. */
  const getPresentation = useCallback(() => getConversionOutputPresentation(output), [output]);

  /**
   * Restore sanitized values that should be put back on export.
   * Currently restores public IPs (marked with restore: true).
   * Hashes, keys, usernames stay redacted.
   */
  const restoreForExport = useCallback((text) => {
    if (!sanitizationTable || sanitizationTable.length === 0) return text;
    let result = text;
    for (const entry of sanitizationTable) {
      if (entry.restore) {
        result = result.replaceAll(entry.placeholder, entry.original);
      }
    }
    return result;
  }, [sanitizationTable]);

  /** Copy output to clipboard — restores public IPs */
  const handleCopy = useCallback(async () => {
    const text = restoreForExport(getPresentation().text);
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [getPresentation, restoreForExport]);

  /** Download output as file — restores public IPs */
  const handleDownload = useCallback(() => {
    const presentation = getPresentation();
    const text = restoreForExport(presentation.text);
    const now = new Date();
    const ts = now.toISOString().slice(0, 10) + '_' + now.toTimeString().slice(0, 8).replace(/:/g, '');
    const filename = `srx-config-${ts}.${presentation.extension}`;

    const blob = new Blob([text], { type: presentation.mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }, [getPresentation, restoreForExport]);

  // --- Not yet parsed ---
  if (!isParsed) {
    return (
      <div className="empty-state">
        <p>Load a config (PAN-OS, Junos SRX, FortiGate, or Cisco ASA/FTD) or start a Greenfield interview, then click "Convert to SRX" to see the generated output here.</p>
      </div>
    );
  }

  // --- Parsed but not yet converted ---
  if (!output) {
    return (
      <div className="empty-state">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
          <polyline points="16 18 22 12 16 6" />
          <polyline points="8 6 2 12 8 18" />
        </svg>
        <h3>Ready to generate</h3>
        <p>Click "Convert to SRX" in the policy table to generate the SRX configuration.</p>
      </div>
    );
  }

  const presentation = getPresentation();
  const outputText = presentation.text;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, padding: '0 12px 12px' }}>
      {/* Conversion summary */}
      {summary && (
        <div className="conversion-summary">
          <SummaryCard label="Zones" value={summary.zones_converted} />
          <SummaryCard label="Addresses" value={summary.addresses_converted} />
          <SummaryCard label="Groups" value={summary.address_groups_converted} />
          <SummaryCard label="Services" value={summary.services_converted} />
          <SummaryCard label="Policies" value={summary.policies_converted} />
          <SummaryCard label="NAT Rules" value={summary.nat_rules_converted} />
          <SummaryCard label="Warnings" value={summary.total_warnings} color="var(--caution)" />
        </div>
      )}

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '8px', flexShrink: 0, alignItems: 'center' }}>
        <label className="policy-structure-select" style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', color: 'var(--text-secondary)' }}>
          Policy structure:
          <select
            value={uiState?.policyStructure || 'global'}
            onChange={(e) => {
              uiDispatch({ type: 'SET_FIELD', field: 'policyStructure', value: e.target.value });
              // Pass the fresh value as an override — uiState hasn't updated yet.
              if (typeof onReconvert === 'function') onReconvert({ policyStructure: e.target.value });
            }}
            style={{ fontSize: '13px', padding: '4px 8px', border: '1px solid var(--border-color)', borderRadius: '4px', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
          >
            <option value="global">Global (security policies global)</option>
            <option value="zone-pair">Zone-pair (from-zone / to-zone)</option>
          </select>
        </label>
        <label className="deployment-mode-select" style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', color: 'var(--text-secondary)' }}>
          Target architecture:
          <select
            value={uiState?.deploymentMode || 'standalone'}
            onChange={(e) => {
              uiDispatch({ type: 'SET_FIELD', field: 'deploymentMode', value: e.target.value });
              // Pass the fresh value as an override — uiState hasn't updated yet.
              if (typeof onReconvert === 'function') onReconvert({ deploymentMode: e.target.value });
            }}
            style={{ fontSize: '13px', padding: '4px 8px', border: '1px solid var(--border-color)', borderRadius: '4px', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
          >
            <option value="standalone">Standalone</option>
            <option value="chassis-cluster">Chassis Cluster</option>
            <option value="mnha">MNHA</option>
          </select>
        </label>
        <span style={{ width: 1, height: 20, background: 'var(--border-color)', flexShrink: 0 }} />
        <button className="btn btn-secondary btn-sm" onClick={handleDownload}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
            <polyline points="7 10 12 15 17 10" />
            <line x1="12" y1="15" x2="12" y2="3" />
          </svg>
          Download .{presentation.extension}
        </button>
        <button
          className="btn btn-secondary btn-sm"
          onClick={handleCopy}
          style={copied ? { borderColor: 'var(--juniper-green)', color: 'var(--juniper-green)', transition: 'all 0.15s' } : { transition: 'all 0.15s' }}
        >
          {copied ? '\u2713 Copied!' : 'Copy to Clipboard'}
        </button>
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
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 2L11 13" /><path d="M22 2L15 22 11 13 2 9z" />
          </svg>
          Push to SRX
        </button>
        <span style={{ width: 1, height: 20, background: 'var(--border-color)', flexShrink: 0 }} />
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => {
            const commands = getSetExportCommands(output);
            const text = exportToTerraform(commands);
            downloadText(text, 'srx-config.tf', 'text/plain');
          }}
          title="Export as Terraform HCL (Junos provider)"
          disabled={!presentation.setExportEligible}
        >
          Terraform
        </button>
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => {
            const commands = getSetExportCommands(output);
            const text = exportToAnsible(commands);
            downloadText(text, 'srx-playbook.yml', 'text/yaml');
          }}
          title="Export as Ansible playbook (junos_config)"
          disabled={!presentation.setExportEligible}
        >
          Ansible
        </button>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', alignSelf: 'center', marginLeft: 'auto' }}>
          {outputText.split('\n').length} lines
        </span>
      </div>

      {/* Output code block — fills remaining space */}
      <pre className="output-code" style={{ flex: 1, minHeight: 0, overflow: 'auto', margin: 0 }}>
        {presentation.renderMode === 'xml' ? (
          outputText
        ) : (
          // Syntax highlighting for set commands
          outputText.split('\n').map((line, i) => {
            if (line.startsWith('#')) {
              return <span key={i} className="comment-line">{line}{'\n'}</span>;
            }
            if (line.startsWith('set ') || line.startsWith('deactivate ')) {
              // Highlight the 'set' or 'deactivate' keyword
              const firstSpace = line.indexOf(' ');
              return (
                <span key={i} className="set-command">
                  <span className="keyword">{line.substring(0, firstSpace)}</span>
                  {line.substring(firstSpace)}
                  {'\n'}
                </span>
              );
            }
            return <span key={i}>{line}{'\n'}</span>;
          })
        )}
      </pre>
    </div>
  );
}

/** Small summary statistic card */
function SummaryCard({ label, value, color }) {
  return (
    <div className="summary-card">
      <div className="summary-value" style={color ? { color } : undefined}>
        {value}
      </div>
      <div className="summary-label">{label}</div>
    </div>
  );
}

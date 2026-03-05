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

export default function SRXOutput({ output, format, summary, isParsed, sanitizationTable }) {
  const { dispatch: uiDispatch } = useUIContext();
  const [copied, setCopied] = useState(false);

  /** Get the raw output text based on format */
  const getOutputText = useCallback(() => {
    if (!output) return '';
    if (format === 'xml') {
      return output.xml || '';
    }
    // Set commands format
    return (output.commands || []).join('\n');
  }, [output, format]);

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
    const text = restoreForExport(getOutputText());
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
  }, [getOutputText, restoreForExport]);

  /** Download output as file — restores public IPs */
  const handleDownload = useCallback(() => {
    const text = restoreForExport(getOutputText());
    const extension = format === 'xml' ? 'xml' : 'txt';
    const mimeType = format === 'xml' ? 'application/xml' : 'text/plain';
    const now = new Date();
    const ts = now.toISOString().slice(0, 10) + '_' + now.toTimeString().slice(0, 8).replace(/:/g, '');
    const filename = `srx-config-${ts}.${extension}`;

    const blob = new Blob([text], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }, [getOutputText, restoreForExport, format]);

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
        <p>Click "Convert to SRX" in the policy table to generate the SRX configuration.</p>
      </div>
    );
  }

  const outputText = getOutputText();

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
      <div style={{ display: 'flex', gap: '8px', marginBottom: '8px', flexShrink: 0 }}>
        <button className="btn btn-secondary btn-sm" onClick={handleDownload}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
            <polyline points="7 10 12 15 17 10" />
            <line x1="12" y1="15" x2="12" y2="3" />
          </svg>
          Download .{format === 'xml' ? 'xml' : 'txt'}
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
            const bridgeSettings = localStorage.getItem('pyez-bridge-settings') || localStorage.getItem('mcp-settings');
            if (bridgeSettings) {
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
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', alignSelf: 'center', marginLeft: 'auto' }}>
          {outputText.split('\n').length} lines
        </span>
      </div>

      {/* Output code block — fills remaining space */}
      <pre className="output-code" style={{ flex: 1, minHeight: 0, overflow: 'auto', margin: 0 }}>
        {format === 'xml' ? (
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

/**
 * AnalysisPanel — Pre-conversion analysis results and actions.
 *
 * Displays 7 finding categories from the analysis engine.
 * Each finding is a collapsible card with count badge, bulk action selector,
 * per-item override toggles, and an "Apply Analysis" button.
 *
 * Analysis engine logic adapted from fatcat/converter.
 */
import React, { useState, useEffect, useCallback } from 'react';

const FINDING_LABELS = {
  unused_objects: 'Unused Objects',
  shadowed: 'Shadowed Policies',
  duplicates: 'Duplicate Objects',
  disabled: 'Disabled Policies',
  logging_off: 'Logging Disabled',
  permissive: 'Overly Permissive',
  empty_groups: 'Empty Groups',
};

const FINDING_SEVERITY = {
  unused_objects: 'info',
  shadowed: 'warning',
  duplicates: 'info',
  disabled: 'info',
  logging_off: 'warning',
  permissive: 'warning',
  empty_groups: 'info',
};

const FINDING_ACTIONS = {
  unused_objects: [
    { value: 'include', label: 'Keep All' },
    { value: 'exclude', label: 'Remove Unused' },
  ],
  shadowed: [
    { value: 'include', label: 'Keep All' },
    { value: 'exclude', label: 'Remove Shadowed' },
  ],
  duplicates: [
    { value: 'keep_all', label: 'Keep All (Annotate)' },
    { value: 'consolidate', label: 'Consolidate' },
  ],
  disabled: [
    { value: 'include_disabled', label: 'Keep Disabled' },
    { value: 'include_enabled', label: 'Re-enable' },
    { value: 'exclude', label: 'Remove' },
  ],
  logging_off: [
    { value: 'report_only', label: 'Report Only' },
    { value: 'enable_all', label: 'Enable Logging' },
  ],
  permissive: [
    { value: 'include', label: 'Keep (Report Only)' },
    { value: 'remove_all', label: 'Remove All' },
  ],
  empty_groups: [
    { value: 'include', label: 'Keep' },
    { value: 'exclude', label: 'Remove Empty' },
  ],
};

export default function AnalysisPanel({ findings, onApply, onRunAnalysis, isLoading, progressLabel, hasConfig, onNavigate }) {
  const [localFindings, setLocalFindings] = useState(findings || []);
  const [expanded, setExpanded] = useState(new Set());

  useEffect(() => { setLocalFindings(findings || []); }, [findings]);

  const toggleExpand = useCallback((id) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }, []);

  const handleBulkAction = useCallback((findingId, value) => {
    setLocalFindings(prev => prev.map(f =>
      f.id === findingId ? { ...f, selected: value } : f
    ));
  }, []);

  const handleItemOverride = useCallback((findingId, itemKey, value) => {
    setLocalFindings(prev => prev.map(f => {
      if (f.id !== findingId) return f;
      const overrides = { ...(f.itemOverrides || {}) };
      if (value === null) {
        delete overrides[itemKey];
      } else {
        overrides[itemKey] = value;
      }
      return { ...f, itemOverrides: overrides };
    }));
  }, []);

  const totalFindings = localFindings.reduce((sum, f) => sum + f.count, 0);
  const hasFindings = localFindings.length > 0 && totalFindings > 0;

  return (
    <div style={{ padding: '16px', maxWidth: 900 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <h3 style={{ margin: 0 }}>Configuration Analysis</h3>
          {hasFindings && (
            <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>
              {totalFindings} finding{totalFindings !== 1 ? 's' : ''} across {localFindings.filter(f => f.count > 0).length} categories
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {hasConfig && (
            <button
              className="btn btn-sm"
              onClick={onRunAnalysis}
              disabled={isLoading}
              style={{ fontSize: 13 }}
            >
              {isLoading ? progressLabel || 'Analyzing...' : (hasFindings ? 'Re-run Analysis' : 'Run Analysis')}
            </button>
          )}
          {hasFindings && (
            <button
              className="btn btn-sm btn-primary"
              onClick={() => onApply(localFindings)}
              style={{ fontSize: 13 }}
            >
              Apply Analysis
            </button>
          )}
        </div>
      </div>

      {!hasFindings && !isLoading && (
        <div style={{
          textAlign: 'center', padding: '40px 20px',
          color: 'var(--text-muted)', border: '1px dashed var(--border-color)',
          borderRadius: 8,
        }}>
          {hasConfig
            ? 'Click "Run Analysis" to check for unused objects, shadowed policies, duplicates, and more.'
            : 'Parse a firewall configuration first, then run analysis.'
          }
        </div>
      )}

      {isLoading && (
        <div style={{
          textAlign: 'center', padding: '40px 20px',
          color: 'var(--text-muted)',
        }}>
          <div style={{ marginBottom: 8, fontSize: 14 }}>{progressLabel || 'Analyzing...'}</div>
          <div style={{
            width: 200, height: 4, background: 'var(--border-color)',
            borderRadius: 2, margin: '0 auto', overflow: 'hidden',
          }}>
            <div style={{
              width: '60%', height: '100%', background: 'var(--accent-color)',
              borderRadius: 2, animation: 'pulse 1.5s ease-in-out infinite',
            }} />
          </div>
        </div>
      )}

      {/* Summary badges */}
      {hasFindings && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
          {localFindings.filter(f => f.count > 0).map(f => {
            const sev = FINDING_SEVERITY[f.id] || 'info';
            return (
              <span
                key={f.id}
                onClick={() => toggleExpand(f.id)}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  padding: '4px 10px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                  cursor: 'pointer',
                  background: sev === 'warning' ? 'rgba(167,139,250,0.12)' : 'var(--surface-2, rgba(128,128,128,0.1))',
                  color: sev === 'warning' ? '#a78bfa' : 'var(--text-secondary)',
                  border: `1px solid ${sev === 'warning' ? 'rgba(167,139,250,0.3)' : 'var(--border-color)'}`,
                }}
              >
                {FINDING_LABELS[f.id] || f.id}
                <span style={{
                  display: 'inline-block', minWidth: 18, padding: '0 5px',
                  borderRadius: 8, fontSize: 11, textAlign: 'center',
                  background: sev === 'warning' ? '#a78bfa' : '#6b7280', color: '#fff',
                }}>
                  {f.count}
                </span>
              </span>
            );
          })}
        </div>
      )}

      {hasFindings && localFindings.map(finding => {
        if (finding.count === 0) return null;
        const isExpanded = expanded.has(finding.id);
        const severity = FINDING_SEVERITY[finding.id] || 'info';
        const actions = FINDING_ACTIONS[finding.id] || [];
        const badgeColor = severity === 'warning' ? '#a78bfa' : '#6b7280';

        return (
          <div key={finding.id} style={{
            border: '1px solid var(--border-color)',
            borderRadius: 8,
            marginBottom: 12,
            background: 'var(--bg-primary)',
          }}>
            {/* Header */}
            <div
              onClick={() => toggleExpand(finding.id)}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '12px 16px', cursor: 'pointer', userSelect: 'none',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 12, transform: isExpanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s' }}>
                  &#9654;
                </span>
                <span style={{ fontWeight: 600, fontSize: 14 }}>
                  {FINDING_LABELS[finding.id] || finding.id}
                </span>
                <span style={{
                  display: 'inline-block', minWidth: 22, padding: '2px 8px',
                  borderRadius: 10, fontSize: 12, fontWeight: 600,
                  background: badgeColor, color: '#fff', textAlign: 'center',
                }}>
                  {finding.count}
                </span>
              </div>
              {actions.length > 0 && (
                <select
                  value={finding.selected || actions[0].value}
                  onChange={(e) => { e.stopPropagation(); handleBulkAction(finding.id, e.target.value); }}
                  onClick={(e) => e.stopPropagation()}
                  style={{ fontSize: 12, padding: '4px 8px', borderRadius: 4, border: '1px solid var(--border-color)', background: 'var(--bg-secondary)', color: 'var(--caution)' }}
                >
                  {actions.map(a => (
                    <option key={a.value} value={a.value}>{a.label}</option>
                  ))}
                </select>
              )}
            </div>

            {/* Description */}
            <div style={{ padding: '0 16px 8px 42px', fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.4 }}>
              {finding.description}
            </div>

            {/* Expanded items */}
            {isExpanded && finding.items.length > 0 && (
              <div style={{ padding: '0 16px 12px 42px', maxHeight: 300, overflowY: 'auto' }}>
                {finding.items.map((item, idx) => {
                  const override = finding.itemOverrides?.[item.key];
                  return (
                    <div key={item.key || idx} style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '4px 0', fontSize: 13,
                      borderTop: idx === 0 ? '1px solid var(--border-color)' : 'none',
                      borderBottom: '1px solid var(--border-color)',
                    }}>
                      <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.label}
                        {item.kind && <span style={{ color: 'var(--text-muted)', marginLeft: 6, fontSize: 11 }}>({item.kind})</span>}
                      </span>
                      <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                        <button
                          className={`btn btn-xs ${override === 'include' ? 'btn-active' : ''}`}
                          onClick={() => handleItemOverride(finding.id, item.key, override === 'include' ? null : 'include')}
                          style={{ fontSize: 11, padding: '2px 6px', opacity: override === 'include' ? 1 : 0.5 }}
                          title="Keep this item"
                        >
                          Keep
                        </button>
                        <button
                          className={`btn btn-xs ${override === 'exclude' ? 'btn-active' : ''}`}
                          onClick={() => handleItemOverride(finding.id, item.key, override === 'exclude' ? null : 'exclude')}
                          style={{ fontSize: 11, padding: '2px 6px', opacity: override === 'exclude' ? 1 : 0.5 }}
                          title="Remove this item"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}

      {/* Next Steps guide */}
      {hasFindings && !isLoading && (
        <div style={{
          marginTop: 20, padding: '16px 20px', borderRadius: 8,
          background: 'var(--surface-2, rgba(128,128,128,0.06))',
          border: '1px solid var(--border-color)',
        }}>
          <h4 style={{ margin: '0 0 10px', fontSize: 14 }}>Next Steps</h4>
          <ol style={{ margin: 0, paddingLeft: 20, lineHeight: 1.8, fontSize: 13, color: 'var(--text-secondary)' }}>
            <li><strong>Review findings above</strong> — expand each category and choose a bulk action (Keep, Remove, Consolidate, etc.)</li>
            <li><strong>Override individual items</strong> if needed — click Keep/Remove per item within a category</li>
            <li>Click <strong>"Apply Analysis"</strong> above to clean up the config based on your selections</li>
            <li>
              Switch to the <strong>SRX view</strong> and click{' '}
              <strong
                style={{ cursor: 'pointer', color: 'var(--accent)' }}
                onClick={() => onNavigate?.('rules')}
              >
                "Convert to SRX"
              </strong>
              {' '}to generate the final output
            </li>
          </ol>
        </div>
      )}
    </div>
  );
}

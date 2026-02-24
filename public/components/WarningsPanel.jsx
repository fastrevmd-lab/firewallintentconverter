/**
 * WarningsPanel Component
 *
 * Displays all conversion warnings, filterable by severity level.
 * Each warning shows:
 *   - Severity icon (clean / warning / unsupported / interview required)
 *   - The specific config element involved
 *   - Description of the issue
 *   - Suggestion for resolution
 */
import React, { useState, useMemo } from 'react';

const SEVERITY_META = {
  clean:              { icon: '\u2705', label: 'Clean',              cssClass: 'clean' },
  warning:            { icon: '\u26A0\uFE0F', label: 'Warning',      cssClass: 'warning' },
  unsupported:        { icon: '\u274C', label: 'Unsupported',        cssClass: 'unsupported' },
  interview_required: { icon: '\uD83D\uDCAC', label: 'Interview Req.', cssClass: 'interview' },
  info:               { icon: '\uD83D\uDCA1', label: 'Optimization',  cssClass: 'info' },
};

export default function WarningsPanel({ warnings }) {
  const [severityFilter, setSeverityFilter] = useState('all');

  // Count by severity
  const counts = useMemo(() => {
    const c = { all: 0, warning: 0, unsupported: 0, interview_required: 0, info: 0 };
    for (const w of (warnings || [])) {
      c.all++;
      if (c[w.severity] !== undefined) c[w.severity]++;
    }
    return c;
  }, [warnings]);

  // Filtered list
  const filtered = useMemo(() => {
    if (severityFilter === 'all') return warnings || [];
    return (warnings || []).filter(w => w.severity === severityFilter);
  }, [warnings, severityFilter]);

  if (!warnings || warnings.length === 0) {
    return (
      <div className="empty-state">
        <p>No warnings. All conversion items processed cleanly.</p>
      </div>
    );
  }

  return (
    <div className="warnings-panel">
      {/* Filter buttons */}
      <div style={{
        display: 'flex',
        gap: '6px',
        padding: '8px 16px',
        borderBottom: '1px solid var(--border-color)',
      }}>
        <FilterButton
          label={`All (${counts.all})`}
          active={severityFilter === 'all'}
          onClick={() => setSeverityFilter('all')}
        />
        <FilterButton
          label={`Warnings (${counts.warning})`}
          active={severityFilter === 'warning'}
          onClick={() => setSeverityFilter('warning')}
          color="var(--warning)"
        />
        <FilterButton
          label={`Unsupported (${counts.unsupported})`}
          active={severityFilter === 'unsupported'}
          onClick={() => setSeverityFilter('unsupported')}
          color="var(--error)"
        />
        <FilterButton
          label={`Interview (${counts.interview_required})`}
          active={severityFilter === 'interview_required'}
          onClick={() => setSeverityFilter('interview_required')}
          color="var(--status-interview)"
        />
        {counts.info > 0 && (
          <FilterButton
            label={`Optimization (${counts.info})`}
            active={severityFilter === 'info'}
            onClick={() => setSeverityFilter('info')}
            color="#38bdf8"
          />
        )}
      </div>

      {/* Warning list */}
      {filtered.map((w, i) => {
        const meta = SEVERITY_META[w.severity] || SEVERITY_META.warning;
        return (
          <div key={i} className="warning-item">
            <span className={`warning-icon ${meta.cssClass}`}>
              {meta.icon}
            </span>
            <div className="warning-body">
              <div className="warning-element">{w.element}</div>
              <div className="warning-message">{w.message}</div>
              {w.suggestion && (
                <div className="warning-suggestion">{w.suggestion}</div>
              )}
            </div>
          </div>
        );
      })}

      {filtered.length === 0 && (
        <div className="empty-state" style={{ padding: '20px' }}>
          <p>No warnings match this filter.</p>
        </div>
      )}
    </div>
  );
}

function FilterButton({ label, active, onClick, color }) {
  return (
    <button
      className={`btn btn-sm ${active ? 'btn-primary' : 'btn-secondary'}`}
      onClick={onClick}
      style={active && color ? { background: color } : undefined}
    >
      {label}
    </button>
  );
}

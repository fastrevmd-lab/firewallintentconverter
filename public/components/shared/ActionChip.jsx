import React from 'react';

/**
 * ActionChip — Color-coded chip for permit/deny/reject actions.
 *
 * @param {string}  action — The firewall action (permit, deny, reject, etc.)
 * @param {boolean} small  — Slightly smaller variant
 */

const ACTION_COLORS = {
  allow:        { bg: 'var(--success)', fg: '#000' },
  permit:       { bg: 'var(--success)', fg: '#000' },
  deny:         { bg: 'var(--error)',   fg: '#fff' },
  drop:         { bg: 'var(--error)',   fg: '#fff' },
  block:        { bg: 'var(--error)',   fg: '#fff' },
  reject:       { bg: 'var(--warning)', fg: '#000' },
  'reset-both':   { bg: 'var(--warning)', fg: '#000' },
  'reset-client': { bg: 'var(--warning)', fg: '#000' },
  'reset-server': { bg: 'var(--warning)', fg: '#000' },
};

const DEFAULT_COLOR = { bg: 'var(--bg-tertiary)', fg: 'var(--text-muted)' };

export default function ActionChip({ action, small }) {
  const normalized = (action || '').toLowerCase().trim();
  const colors = ACTION_COLORS[normalized] || DEFAULT_COLOR;

  return (
    <span
      className="action-chip"
      style={{
        background: colors.bg,
        color: colors.fg,
        ...(small ? { fontSize: 10, padding: '1px 6px' } : {}),
      }}
    >
      {action}
    </span>
  );
}

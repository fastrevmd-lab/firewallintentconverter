import React, { useEffect, useRef } from 'react';

/**
 * ConfirmModal — Reusable confirmation dialog.
 *
 * @param {string}   title          — Modal heading
 * @param {string}   message        — Body text
 * @param {'danger'|'warning'|'info'} severity — Affects confirm button color
 * @param {() => void} onConfirm    — Called when confirmed
 * @param {() => void} onCancel     — Called when cancelled or overlay clicked
 * @param {string}   confirmLabel   — Confirm button text (default: "Confirm")
 * @param {string}   cancelLabel    — Cancel button text (default: "Cancel")
 */
export default function ConfirmModal({
  title = 'Confirm',
  message = 'Are you sure?',
  severity = 'info',
  onConfirm,
  onCancel,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
}) {
  const confirmRef = useRef(null);

  // Focus the confirm button on mount
  useEffect(() => {
    confirmRef.current?.focus();
  }, []);

  // Escape key to cancel
  useEffect(() => {
    const handleKey = (e) => {
      if (e.key === 'Escape' && onCancel) onCancel();
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [onCancel]);

  // Severity-based confirm button styles
  const SEVERITY_COLORS = {
    danger:  { background: 'var(--error)',   color: '#fff' },
    warning: { background: 'var(--warning)', color: '#000' },
    info:    { background: 'var(--accent)',   color: '#000' },
  };
  const btnStyle = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;

  return (
    <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget && onCancel) onCancel(); }}>
      <div className="modal-content" style={{ width: 420 }}>
        <div className="modal-header">
          <h2>{title}</h2>
          <button className="modal-close" onClick={onCancel}>&times;</button>
        </div>
        <div className="modal-body">
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{message}</p>
        </div>
        <div className="modal-footer" style={{ justifyContent: 'flex-end', gap: 8 }}>
          <button className="btn btn-secondary btn-sm" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            ref={confirmRef}
            className="btn btn-sm"
            style={{ ...btnStyle, border: 'none', cursor: 'pointer', padding: '6px 16px', borderRadius: 'var(--radius)', fontWeight: 600, fontSize: 13 }}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

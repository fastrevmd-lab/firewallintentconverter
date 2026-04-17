/**
 * AppMappingsEditor — Settings modal for viewing and editing the
 * vendor → Junos application mapping table.
 *
 * Built-in mappings ship in src/data/app-mappings.json (read-only here).
 * User edits layer on top via localStorage, consumed by
 * src/utils/app-mappings.js at lookup time.
 */
import React, { useMemo, useState, useEffect } from 'react';
import appMappingsData from '../../src/data/app-mappings.json' with { type: 'json' };
import {
  readOverrides,
  setOverride,
  removeOverride,
  resetAllOverrides,
  exportOverridesAsJson,
  importOverridesFromJson,
  countOverrides,
} from '../utils/app-mapping-overrides.js';

// Mirrors VENDOR_KEY_MAP in src/utils/app-mappings.js
const VENDOR_OPTIONS = [
  { id: 'panos',       label: 'PAN-OS',      fatcatKey: 'panos' },
  { id: 'fortigate',   label: 'FortiGate',   fatcatKey: 'fortios' },
  { id: 'cisco_asa',   label: 'Cisco ASA/FTD', fatcatKey: 'ftd' },
  { id: 'checkpoint',  label: 'Check Point', fatcatKey: 'checkpoint' },
  { id: 'sonicwall',   label: 'SonicWall',   fatcatKey: 'sonicwall' },
  { id: 'huawei_usg',  label: 'Huawei USG',  fatcatKey: 'huawei' },
  { id: 'srx',         label: 'Junos (SRX)', fatcatKey: 'junos' },
];

/**
 * Produces the denormalised row list: one row per (app, vendor-name-or-alias).
 * Each row carries source='builtin' or 'override'.
 */
function buildRows(vendorId) {
  const vendorOption = VENDOR_OPTIONS.find(v => v.id === vendorId);
  if (!vendorOption) return [];
  const fatcatKey = vendorOption.fatcatKey;
  const rows = [];
  for (const app of appMappingsData.apps) {
    const vendorEntry = app.vendors[fatcatKey];
    if (!vendorEntry || !vendorEntry.name) continue;
    const names = [vendorEntry.name, ...(Array.isArray(vendorEntry.aliases) ? vendorEntry.aliases : [])];
    for (const vendorName of names) {
      rows.push({
        vendorName,
        canonical: app.canonical,
        category: app.category,
        junosName: app.vendors.junos?.name ?? null,
        confidence: vendorEntry.confidence,
        protocols: app.protocols,
        ports: app.ports,
        source: 'builtin',
        isAlias: vendorName !== vendorEntry.name,
      });
    }
  }
  return rows;
}

function mergeOverrides(rows, vendorId, overrides) {
  const vendorMap = overrides[vendorId] || {};
  // Mark matching built-ins as 'override' (user replaced them) or filter if _deleted.
  const out = rows.map(r => {
    const rec = vendorMap[r.vendorName.toLowerCase()];
    if (!rec) return r;
    if (rec._deleted) return { ...r, source: 'deleted' };
    return { ...r, source: 'override', override: rec };
  });
  // Append user-added overrides not matching any built-in.
  const existingNames = new Set(rows.map(r => r.vendorName.toLowerCase()));
  for (const [name, rec] of Object.entries(vendorMap)) {
    if (existingNames.has(name.toLowerCase())) continue;
    if (rec._deleted) continue;
    out.push({
      vendorName: name,
      canonical: rec.canonical ?? name,
      category: rec.category ?? 'user-override',
      junosName: rec.kind === 'predefined' ? rec.name : rec.junosApp,
      confidence: rec.confidence ?? 1,
      protocols: rec.protocol ? [rec.protocol.toUpperCase()] : [],
      ports: rec.ports ?? [],
      source: 'override',
      override: rec,
    });
  }
  return out;
}

function formatEmission(row) {
  if (row.source === 'deleted') return '— (hidden)';
  if (row.source === 'override' && row.override?.kind === 'predefined' && row.override.name) {
    return row.override.name;
  }
  if (row.source === 'override' && row.override?.kind === 'custom') {
    return `${row.override.protocol}/${(row.override.ports || []).join(',')}`;
  }
  if (row.junosName) return row.junosName.replace(/^junos:/, 'junos-').toLowerCase();
  if (row.protocols?.length && row.ports?.length) {
    return `${row.protocols[0].toLowerCase()}/${row.ports.join(',')}`;
  }
  return '—';
}

export default function AppMappingsEditor({ onClose }) {
  const [vendorId, setVendorId] = useState('panos');
  const [query, setQuery] = useState('');
  const [overrides, setOverrides] = useState(() => readOverrides());
  const [editing, setEditing] = useState(null); // row being edited, or { isNew: true } for add
  const [importText, setImportText] = useState('');
  const [showImport, setShowImport] = useState(false);
  const [feedback, setFeedback] = useState(null);

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const rows = useMemo(() => {
    const base = buildRows(vendorId);
    const merged = mergeOverrides(base, vendorId, overrides);
    if (!query.trim()) return merged;
    const q = query.trim().toLowerCase();
    return merged.filter(r =>
      r.vendorName.toLowerCase().includes(q) ||
      r.canonical.toLowerCase().includes(q) ||
      (r.junosName || '').toLowerCase().includes(q) ||
      (r.category || '').toLowerCase().includes(q)
    );
  }, [vendorId, query, overrides]);

  const refresh = () => setOverrides(readOverrides());

  const handleDeleteOverride = (row) => {
    // If it's purely a user-added override with no built-in twin → full remove.
    // If it's shadowing a built-in → offer to fully remove (restore built-in) or tombstone (hide built-in).
    const builtinExists = buildRows(vendorId).some(
      r => r.vendorName.toLowerCase() === row.vendorName.toLowerCase()
    );
    if (!builtinExists) {
      removeOverride(vendorId, row.vendorName);
    } else {
      // Default: restore built-in (remove override without tombstoning).
      if (!window.confirm(`Remove override for "${row.vendorName}" and restore the built-in mapping?`)) return;
      removeOverride(vendorId, row.vendorName);
    }
    refresh();
  };

  const handleSuppressBuiltin = (row) => {
    if (!window.confirm(`Hide the built-in mapping for "${row.vendorName}"? It will be treated as UNMAPPED.`)) return;
    removeOverride(vendorId, row.vendorName, { suppressBundled: true });
    refresh();
  };

  const handleRestoreTombstone = (row) => {
    removeOverride(vendorId, row.vendorName);
    refresh();
  };

  const handleResetAll = () => {
    if (!window.confirm('Remove ALL application-mapping overrides? This cannot be undone.')) return;
    resetAllOverrides();
    refresh();
  };

  const handleExport = () => {
    const json = exportOverridesAsJson();
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'app-mappings-overrides.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImport = () => {
    const result = importOverridesFromJson(importText);
    if (!result.ok) {
      setFeedback({ kind: 'error', message: result.error });
      return;
    }
    setFeedback({ kind: 'success', message: 'Overrides imported.' });
    setShowImport(false);
    setImportText('');
    refresh();
  };

  const total = rows.length;
  const visibleOverrideCount = rows.filter(r => r.source === 'override').length;

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--bg-secondary)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-color)',
          padding: '24px',
          width: '960px',
          maxWidth: '95vw',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div>
            <h2 style={{ fontSize: 16, margin: 0 }}>Application Mappings</h2>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
              Vendor app name → Junos emission. Overrides persist in this browser only.
              {countOverrides() > 0 && (
                <>
                  {' '}<span style={{ color: 'var(--caution, #f59e0b)' }}>●</span>{' '}
                  {countOverrides()} override{countOverrides() === 1 ? '' : 's'} active
                </>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 18 }}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {/* Toolbar */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' }}>
          <select
            value={vendorId}
            onChange={(e) => setVendorId(e.target.value)}
            style={selectStyle}
          >
            {VENDOR_OPTIONS.map(v => (
              <option key={v.id} value={v.id}>{v.label}</option>
            ))}
          </select>
          <input
            type="search"
            placeholder="Search (vendor name, canonical, junos, category)…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ ...inputStyle, flex: 1, minWidth: 220 }}
          />
          <button onClick={() => setEditing({ isNew: true })} style={primaryBtn}>+ Add mapping</button>
          <button onClick={handleExport} style={secondaryBtn}>Export JSON</button>
          <button onClick={() => setShowImport(true)} style={secondaryBtn}>Import JSON</button>
          <button onClick={handleResetAll} style={dangerBtn} disabled={countOverrides() === 0}>Reset all</button>
        </div>

        {feedback && (
          <div
            role="status"
            style={{
              padding: '8px 12px',
              marginBottom: 8,
              borderRadius: 4,
              fontSize: 12,
              background: feedback.kind === 'error' ? 'rgba(220,38,38,0.1)' : 'rgba(16,185,129,0.1)',
              color: feedback.kind === 'error' ? '#dc2626' : '#10b981',
            }}
          >
            {feedback.message}
            <button
              onClick={() => setFeedback(null)}
              style={{ background: 'none', border: 'none', float: 'right', cursor: 'pointer', color: 'inherit' }}
            >×</button>
          </div>
        )}

        {/* Stats */}
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6 }}>
          {total} entr{total === 1 ? 'y' : 'ies'}
          {visibleOverrideCount > 0 && `, ${visibleOverrideCount} override${visibleOverrideCount === 1 ? '' : 's'}`}
          {query && ` (filtered)`}
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflow: 'auto', border: '1px solid var(--border-color)', borderRadius: 4 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>
              <tr>
                <th style={thStyle}>Vendor name</th>
                <th style={thStyle}>Canonical</th>
                <th style={thStyle}>Category</th>
                <th style={thStyle}>Junos emission</th>
                <th style={thStyle}>Source</th>
                <th style={thStyle}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr><td colSpan={6} style={{ padding: 16, textAlign: 'center', color: 'var(--text-secondary)' }}>
                  No mappings match the current filter.
                </td></tr>
              )}
              {rows.map((row, idx) => (
                <tr
                  key={`${row.vendorName}-${idx}`}
                  style={{
                    borderTop: '1px solid var(--border-color)',
                    background: row.source === 'override'
                      ? 'rgba(245,158,11,0.06)'
                      : row.source === 'deleted'
                      ? 'rgba(220,38,38,0.06)'
                      : 'transparent',
                  }}
                >
                  <td style={tdStyle}>
                    <code>{row.vendorName}</code>
                    {row.isAlias && <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--text-secondary)' }}>(alias)</span>}
                  </td>
                  <td style={tdStyle}><code>{row.canonical}</code></td>
                  <td style={tdStyle}>{row.category || '—'}</td>
                  <td style={tdStyle}><code>{formatEmission(row)}</code></td>
                  <td style={tdStyle}>
                    {row.source === 'override' && <span style={{ color: 'var(--caution, #f59e0b)' }}>Override</span>}
                    {row.source === 'builtin' && <span style={{ color: 'var(--text-secondary)' }}>Built-in</span>}
                    {row.source === 'deleted' && <span style={{ color: '#dc2626' }}>Hidden</span>}
                  </td>
                  <td style={tdStyle}>
                    <button style={linkBtn} onClick={() => setEditing(row)}>Edit</button>
                    {' | '}
                    {row.source === 'override' && (
                      <button style={linkBtn} onClick={() => handleDeleteOverride(row)}>Reset</button>
                    )}
                    {row.source === 'builtin' && (
                      <button style={linkBtn} onClick={() => handleSuppressBuiltin(row)}>Hide</button>
                    )}
                    {row.source === 'deleted' && (
                      <button style={linkBtn} onClick={() => handleRestoreTombstone(row)}>Restore</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Edit / Add modal */}
      {editing && (
        <EditModal
          row={editing}
          vendorId={vendorId}
          onSave={(vendorName, record) => {
            setOverride(vendorId, vendorName, record);
            setEditing(null);
            refresh();
            setFeedback({ kind: 'success', message: `Saved override for ${vendorName}` });
          }}
          onCancel={() => setEditing(null)}
        />
      )}

      {/* Import modal */}
      {showImport && (
        <ImportModal
          text={importText}
          setText={setImportText}
          onCommit={handleImport}
          onCancel={() => { setShowImport(false); setImportText(''); }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// EditModal — inline form for add/edit
// ---------------------------------------------------------------------------
function EditModal({ row, vendorId, onSave, onCancel }) {
  const isNew = row?.isNew;
  const initial = isNew
    ? { vendorName: '', kind: 'predefined', name: '', protocol: 'tcp', ports: '', canonical: '' }
    : {
        vendorName: row.vendorName,
        kind: row.override?.kind ?? (row.protocols?.length && row.ports?.length ? 'custom' : 'predefined'),
        name: row.override?.name ?? (row.junosName ? row.junosName.replace(/^junos:/, 'junos-').toLowerCase() : ''),
        protocol: row.override?.protocol ?? (row.protocols?.[0]?.toLowerCase() ?? 'tcp'),
        ports: (row.override?.ports ?? row.ports ?? []).join(','),
        canonical: row.override?.canonical ?? row.canonical ?? '',
      };
  const [form, setForm] = useState(initial);
  const [err, setErr] = useState(null);

  const submit = () => {
    if (!form.vendorName.trim()) { setErr('Vendor app name is required'); return; }
    const record = {
      kind: form.kind,
      canonical: form.canonical.trim() || form.vendorName.trim().toLowerCase(),
    };
    if (form.kind === 'predefined') {
      if (!form.name.trim()) { setErr('Junos app name (e.g. junos-https) is required for predefined kind'); return; }
      record.name = form.name.trim();
      record.junosApp = form.name.trim();
    } else {
      const ports = form.ports.split(',').map(s => s.trim()).filter(Boolean);
      if (ports.length === 0) { setErr('At least one port is required for custom kind'); return; }
      record.protocol = form.protocol;
      record.ports = ports;
    }
    onSave(form.vendorName.trim(), record);
  };

  return (
    <div
      onClick={onCancel}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--bg-secondary)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-color)',
          padding: 20,
          width: 480,
          maxWidth: '92vw',
        }}
      >
        <h3 style={{ fontSize: 14, margin: '0 0 12px' }}>
          {isNew ? 'Add mapping' : `Edit "${row.vendorName}"`}
          <span style={{ fontWeight: 400, color: 'var(--text-secondary)', marginLeft: 8, fontSize: 11 }}>
            ({vendorId})
          </span>
        </h3>

        <Field label="Vendor app name">
          <input
            style={inputStyle}
            value={form.vendorName}
            onChange={(e) => setForm({ ...form, vendorName: e.target.value })}
            disabled={!isNew}
            placeholder="e.g. facebook, zoom, custom-internal-app"
          />
        </Field>

        <Field label="Canonical (optional)">
          <input
            style={inputStyle}
            value={form.canonical}
            onChange={(e) => setForm({ ...form, canonical: e.target.value })}
            placeholder="facebook"
          />
        </Field>

        <Field label="Emission kind">
          <select style={selectStyle} value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
            <option value="predefined">Predefined Junos app (e.g. junos-https)</option>
            <option value="custom">Custom application (protocol + ports)</option>
          </select>
        </Field>

        {form.kind === 'predefined' ? (
          <Field label="Junos app name">
            <input
              style={inputStyle}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="junos-https"
            />
          </Field>
        ) : (
          <>
            <Field label="Protocol">
              <select style={selectStyle} value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
              </select>
            </Field>
            <Field label="Ports (comma-separated)">
              <input
                style={inputStyle}
                value={form.ports}
                onChange={(e) => setForm({ ...form, ports: e.target.value })}
                placeholder="443, 8443"
              />
            </Field>
          </>
        )}

        {err && <div style={{ color: '#dc2626', fontSize: 11, marginTop: 8 }}>{err}</div>}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button onClick={onCancel} style={secondaryBtn}>Cancel</button>
          <button onClick={submit} style={primaryBtn}>Save</button>
        </div>
      </div>
    </div>
  );
}

function ImportModal({ text, setText, onCommit, onCancel }) {
  return (
    <div
      onClick={onCancel}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--bg-secondary)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-color)',
          padding: 20,
          width: 560,
          maxWidth: '92vw',
        }}
      >
        <h3 style={{ fontSize: 14, margin: '0 0 8px' }}>Import overrides</h3>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8 }}>
          Paste a previously-exported <code>app-mappings-overrides.json</code> payload. This REPLACES all current overrides.
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          style={{ ...inputStyle, width: '100%', height: 220, fontFamily: 'monospace', fontSize: 11 }}
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
          <button onClick={onCancel} style={secondaryBtn}>Cancel</button>
          <button onClick={onCommit} style={primaryBtn} disabled={!text.trim()}>Import</button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label style={{ display: 'block', marginBottom: 10, fontSize: 11, color: 'var(--text-secondary)' }}>
      <div style={{ marginBottom: 4 }}>{label}</div>
      {children}
    </label>
  );
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------
const inputStyle = {
  padding: '6px 8px',
  fontSize: 12,
  background: 'var(--bg-primary)',
  color: 'var(--text-primary)',
  border: '1px solid var(--border-color)',
  borderRadius: 4,
  boxSizing: 'border-box',
};
const selectStyle = { ...inputStyle };
const primaryBtn = {
  padding: '6px 14px',
  fontSize: 12,
  background: 'var(--accent)',
  color: 'var(--bg-primary)',
  border: 'none',
  borderRadius: 4,
  cursor: 'pointer',
  fontWeight: 500,
};
const secondaryBtn = {
  padding: '6px 12px',
  fontSize: 12,
  background: 'transparent',
  color: 'var(--text-primary)',
  border: '1px solid var(--border-color)',
  borderRadius: 4,
  cursor: 'pointer',
};
const dangerBtn = {
  ...secondaryBtn,
  color: '#dc2626',
  borderColor: '#dc2626',
};
const linkBtn = {
  background: 'none',
  border: 'none',
  color: 'var(--accent)',
  cursor: 'pointer',
  fontSize: 12,
  padding: 0,
};
const thStyle = {
  padding: '8px 10px',
  textAlign: 'left',
  fontWeight: 600,
  fontSize: 11,
  color: 'var(--text-secondary)',
  borderBottom: '1px solid var(--border-color)',
  whiteSpace: 'nowrap',
};
const tdStyle = {
  padding: '6px 10px',
  verticalAlign: 'middle',
};

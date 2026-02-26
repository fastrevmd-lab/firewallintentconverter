/**
 * DiffPanel Component
 *
 * Compares source policies vs LLM-translated policies rule-by-rule.
 * Shows field-level diffs with color coding and expandable detail rows.
 */
import React, { useState, useMemo } from 'react';

const DIFF_FIELDS = [
  { key: 'name', label: 'Name' },
  { key: 'action', label: 'Action' },
  { key: 'src_zones', label: 'Source Zones', isArray: true },
  { key: 'dst_zones', label: 'Dest Zones', isArray: true },
  { key: 'src_addresses', label: 'Source Addr', isArray: true },
  { key: 'dst_addresses', label: 'Dest Addr', isArray: true },
  { key: 'applications', label: 'Applications', isArray: true },
  { key: 'services', label: 'Services', isArray: true },
  { key: 'log_start', label: 'Log Start' },
  { key: 'log_end', label: 'Log End' },
  { key: 'disabled', label: 'Disabled' },
  { key: 'description', label: 'Description' },
];

function normalizeValue(val, isArray) {
  if (val == null) return isArray ? '[]' : '';
  if (isArray && Array.isArray(val)) return JSON.stringify([...val].sort());
  if (typeof val === 'boolean') return String(val);
  if (typeof val === 'object') return JSON.stringify(val);
  return String(val);
}

function displayValue(val, isArray) {
  if (val == null || (Array.isArray(val) && val.length === 0)) return 'any';
  if (Array.isArray(val)) return val.join(', ');
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  return String(val);
}

function diffFields(sourceRule, translatedRule) {
  const changes = [];
  for (const field of DIFF_FIELDS) {
    const srcVal = normalizeValue(sourceRule[field.key], field.isArray);
    const tgtVal = normalizeValue(translatedRule[field.key], field.isArray);
    if (srcVal !== tgtVal) {
      changes.push({
        label: field.label,
        sourceValue: displayValue(sourceRule[field.key], field.isArray),
        translatedValue: displayValue(translatedRule[field.key], field.isArray),
      });
    }
  }
  return changes;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function nameSimilarity(a, b) {
  if (!a || !b) return 0;
  const la = a.toLowerCase(), lb = b.toLowerCase();
  if (la === lb) return 1;
  const maxLen = Math.max(la.length, lb.length);
  if (maxLen === 0) return 1;
  return 1 - levenshtein(la, lb) / maxLen;
}

/**
 * Match source rules to translated rules.
 * Pass 1: Match by _rule_index
 * Pass 2: Match by exact name (case-insensitive)
 * Pass 3: Match by fuzzy name similarity (threshold > 0.5)
 * Remainder: unmatched source = removed, unmatched translated = added
 */
function matchRules(sourcePolicies, translatedPolicies) {
  const pairs = [];
  const unmatchedSource = new Set(sourcePolicies.map((_, i) => i));
  const unmatchedTranslated = new Set(translatedPolicies.map((_, i) => i));

  // Pass 1: _rule_index
  for (const si of [...unmatchedSource]) {
    const src = sourcePolicies[si];
    if (src._rule_index == null) continue;
    for (const ti of [...unmatchedTranslated]) {
      const tgt = translatedPolicies[ti];
      if (tgt._rule_index != null && tgt._rule_index === src._rule_index) {
        unmatchedSource.delete(si);
        unmatchedTranslated.delete(ti);
        const changes = diffFields(src, tgt);
        pairs.push({ source: src, translated: tgt, status: changes.length > 0 ? 'modified' : 'unchanged', changes, sourceIndex: si, translatedIndex: ti });
        break;
      }
    }
  }

  // Pass 2: exact name
  for (const si of [...unmatchedSource]) {
    const src = sourcePolicies[si];
    for (const ti of [...unmatchedTranslated]) {
      const tgt = translatedPolicies[ti];
      if (src.name && tgt.name && src.name.toLowerCase() === tgt.name.toLowerCase()) {
        unmatchedSource.delete(si);
        unmatchedTranslated.delete(ti);
        const changes = diffFields(src, tgt);
        pairs.push({ source: src, translated: tgt, status: changes.length > 0 ? 'modified' : 'unchanged', changes, sourceIndex: si, translatedIndex: ti });
        break;
      }
    }
  }

  // Pass 3: fuzzy name (skip if too many unmatched to avoid slowdown)
  if (unmatchedSource.size <= 100 && unmatchedTranslated.size <= 100) {
    for (const si of [...unmatchedSource]) {
      const src = sourcePolicies[si];
      let bestTi = -1, bestScore = 0;
      for (const ti of unmatchedTranslated) {
        const score = nameSimilarity(src.name, translatedPolicies[ti].name);
        if (score > bestScore) { bestScore = score; bestTi = ti; }
      }
      if (bestTi >= 0 && bestScore > 0.5) {
        unmatchedSource.delete(si);
        unmatchedTranslated.delete(bestTi);
        const tgt = translatedPolicies[bestTi];
        const changes = diffFields(src, tgt);
        pairs.push({ source: src, translated: tgt, status: 'modified', changes, renamed: true, sourceIndex: si, translatedIndex: bestTi });
      }
    }
  }

  // Remaining: removed / added
  for (const si of unmatchedSource) {
    pairs.push({ source: sourcePolicies[si], translated: null, status: 'removed', changes: [], sourceIndex: si, translatedIndex: null });
  }
  for (const ti of unmatchedTranslated) {
    pairs.push({ source: null, translated: translatedPolicies[ti], status: 'added', changes: [], sourceIndex: null, translatedIndex: ti });
  }

  pairs.sort((a, b) => (a.sourceIndex ?? a.translatedIndex ?? 9999) - (b.sourceIndex ?? b.translatedIndex ?? 9999));
  return pairs;
}

const STATUS_META = {
  added:     { label: 'Added',     css: 'diff-added',     icon: '+' },
  removed:   { label: 'Removed',   css: 'diff-removed',   icon: '\u2212' },
  modified:  { label: 'Modified',  css: 'diff-modified',  icon: '\u0394' },
  unchanged: { label: 'Unchanged', css: 'diff-unchanged', icon: '=' },
};

export default function DiffPanel({ sourcePolicies, translatedPolicies }) {
  const [statusFilter, setStatusFilter] = useState('all');
  const [expandedRows, setExpandedRows] = useState({});

  const diffResult = useMemo(() => {
    if (!sourcePolicies || !translatedPolicies) return { pairs: [], counts: {} };
    const pairs = matchRules(sourcePolicies, translatedPolicies);
    const counts = { added: 0, removed: 0, modified: 0, unchanged: 0 };
    for (const p of pairs) counts[p.status]++;
    return { pairs, counts };
  }, [sourcePolicies, translatedPolicies]);

  const filteredPairs = useMemo(() => {
    if (statusFilter === 'all') return diffResult.pairs;
    return diffResult.pairs.filter(p => p.status === statusFilter);
  }, [diffResult.pairs, statusFilter]);

  const toggleRow = (index) => setExpandedRows(prev => ({ ...prev, [index]: !prev[index] }));

  if (!translatedPolicies) {
    return (
      <div className="empty-state" style={{ padding: 40 }}>
        <p>Run <strong>Translate with LLM</strong> to compare source policies against LLM-translated SRX policies.</p>
      </div>
    );
  }

  if (!sourcePolicies || sourcePolicies.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 40 }}>
        <p>No source policies to compare. Parse a configuration first.</p>
      </div>
    );
  }

  const { counts } = diffResult;

  return (
    <div className="diff-panel">
      <div className="diff-summary-bar">
        <span className="diff-stat diff-stat-modified">{counts.modified} modified</span>
        <span className="diff-stat diff-stat-added">{counts.added} added</span>
        <span className="diff-stat diff-stat-removed">{counts.removed} removed</span>
        <span className="diff-stat diff-stat-unchanged">{counts.unchanged} unchanged</span>
      </div>

      <div className="diff-filter-bar">
        {[
          { key: 'all', label: `All (${diffResult.pairs.length})` },
          { key: 'modified', label: `Modified (${counts.modified})`, color: 'var(--warning)' },
          { key: 'added', label: `Added (${counts.added})`, color: 'var(--success)' },
          { key: 'removed', label: `Removed (${counts.removed})`, color: 'var(--error)' },
          { key: 'unchanged', label: `Unchanged (${counts.unchanged})` },
        ].map(f => (
          <button
            key={f.key}
            className={`btn btn-sm ${statusFilter === f.key ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setStatusFilter(f.key)}
            style={statusFilter === f.key && f.color ? { background: f.color } : undefined}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="diff-list">
        {filteredPairs.map((pair, i) => {
          const meta = STATUS_META[pair.status];
          const isExpanded = expandedRows[i];
          const ruleName = pair.source?.name || pair.translated?.name || 'Unknown';
          const isExpandable = pair.status !== 'unchanged';

          return (
            <div key={i} className={`diff-item ${meta.css}`}>
              <div
                className="diff-item-header"
                onClick={() => isExpandable && toggleRow(i)}
                style={{ cursor: isExpandable ? 'pointer' : 'default' }}
              >
                <span className={`diff-status-icon ${meta.css}`}>{meta.icon}</span>
                <span className="diff-rule-name">{ruleName}</span>
                {pair.renamed && (
                  <span className="diff-renamed-badge" title={`Renamed: "${pair.source?.name}" \u2192 "${pair.translated?.name}"`}>renamed</span>
                )}
                {pair.status === 'modified' && (
                  <span className="diff-change-count">{pair.changes.length} field{pair.changes.length !== 1 ? 's' : ''}</span>
                )}
                {pair.translated?._translation_notes && (
                  <span className="diff-notes-indicator" title={pair.translated._translation_notes}>LLM Note</span>
                )}
                <span className={`diff-status-badge ${meta.css}`}>{meta.label}</span>
                {isExpandable && (
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                    style={{ marginLeft: 4, transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}>
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                )}
              </div>

              {isExpanded && pair.status === 'modified' && (
                <div className="diff-field-details">
                  {pair.translated?._translation_notes && (
                    <div className="diff-translation-note"><strong>LLM Notes:</strong> {pair.translated._translation_notes}</div>
                  )}
                  <table className="diff-field-table">
                    <thead><tr><th>Field</th><th>Source</th><th>Translated</th></tr></thead>
                    <tbody>
                      {pair.changes.map((c, ci) => (
                        <tr key={ci}>
                          <td className="diff-field-name">{c.label}</td>
                          <td className="diff-field-source">{c.sourceValue}</td>
                          <td className="diff-field-translated">{c.translatedValue}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {isExpanded && pair.status === 'added' && pair.translated && (
                <div className="diff-field-details">
                  {pair.translated._translation_notes && (
                    <div className="diff-translation-note"><strong>LLM Notes:</strong> {pair.translated._translation_notes}</div>
                  )}
                  <div className="diff-added-summary">
                    <div><strong>Action:</strong> {pair.translated.action}</div>
                    <div><strong>Src Zones:</strong> {(pair.translated.src_zones || []).join(', ') || 'any'}</div>
                    <div><strong>Dst Zones:</strong> {(pair.translated.dst_zones || []).join(', ') || 'any'}</div>
                    <div><strong>Applications:</strong> {(pair.translated.applications || []).join(', ') || 'any'}</div>
                    {pair.translated.description && <div><strong>Description:</strong> {pair.translated.description}</div>}
                  </div>
                </div>
              )}

              {isExpanded && pair.status === 'removed' && pair.source && (
                <div className="diff-field-details">
                  <div className="diff-removed-summary">
                    <div><strong>Action:</strong> {pair.source.action}</div>
                    <div><strong>Src Zones:</strong> {(pair.source.src_zones || []).join(', ') || 'any'}</div>
                    <div><strong>Dst Zones:</strong> {(pair.source.dst_zones || []).join(', ') || 'any'}</div>
                    <div><strong>Applications:</strong> {(pair.source.applications || []).join(', ') || 'any'}</div>
                    {pair.source.description && <div><strong>Description:</strong> {pair.source.description}</div>}
                  </div>
                </div>
              )}
            </div>
          );
        })}

        {filteredPairs.length === 0 && (
          <div className="empty-state" style={{ padding: 20 }}><p>No rules match this filter.</p></div>
        )}
      </div>
    </div>
  );
}

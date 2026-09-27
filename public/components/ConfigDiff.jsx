/**
 * ConfigDiff Component
 *
 * Side-by-side or unified diff of two SRX config outputs.
 * Supports comparing: (a) current vs previous conversion, or (b) pasting
 * two configs for comparison.
 *
 * Uses simple line-by-line diff with green/red highlighting.
 */
import React, { useState, useMemo, useCallback } from 'react';
import { getConversionOutputText } from '../../src/conversion/conversion-output.js';
import { safeJsonParse } from '../utils/safe-json.js';

/**
 * Simple line-by-line diff algorithm (longest common subsequence based).
 * Returns array of { type: 'same'|'added'|'removed', line: string }.
 */
function computeLineDiff(linesA, linesB) {
  const result = [];
  const setA = new Set(linesA);
  const setB = new Set(linesB);

  // Build LCS for ordering
  const m = linesA.length;
  const n = linesB.length;

  // For performance, use a simpler approach for large configs:
  // track which lines exist in both, then walk through in order
  if (m + n > 10000) {
    return fastLineDiff(linesA, linesB);
  }

  // Standard LCS DP (works well for configs up to ~5000 lines)
  const dp = Array.from({ length: m + 1 }, () => new Uint16Array(n + 1));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (linesA[i - 1] === linesB[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  // Backtrack
  let i = m, j = n;
  const ops = [];
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && linesA[i - 1] === linesB[j - 1]) {
      ops.push({ type: 'same', line: linesA[i - 1] });
      i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      ops.push({ type: 'added', line: linesB[j - 1] });
      j--;
    } else {
      ops.push({ type: 'removed', line: linesA[i - 1] });
      i--;
    }
  }
  ops.reverse();
  return ops;
}

/** Fast diff for large configs — line set comparison */
function fastLineDiff(linesA, linesB) {
  const result = [];
  const mapA = new Map();
  const mapB = new Map();
  linesA.forEach((line, i) => {
    if (!mapA.has(line)) mapA.set(line, []);
    mapA.get(line).push(i);
  });
  linesB.forEach((line, i) => {
    if (!mapB.has(line)) mapB.set(line, []);
    mapB.get(line).push(i);
  });

  // Walk through A: if line exists in B, it's same; else removed
  for (const line of linesA) {
    if (mapB.has(line)) {
      result.push({ type: 'same', line });
      // Consume one instance
      const arr = mapB.get(line);
      arr.shift();
      if (arr.length === 0) mapB.delete(line);
    } else {
      result.push({ type: 'removed', line });
    }
  }

  // Anything left in B is added
  for (const line of linesB) {
    if (mapA.has(line)) {
      const arr = mapA.get(line);
      arr.shift();
      if (arr.length === 0) mapA.delete(line);
    } else {
      result.push({ type: 'added', line });
    }
  }

  return result;
}

const DIFF_COLORS = {
  added: { bg: 'rgba(52, 211, 153, 0.12)', color: 'var(--success)', prefix: '+' },
  removed: { bg: 'rgba(248, 113, 113, 0.12)', color: 'var(--error)', prefix: '-' },
  same: { bg: 'transparent', color: 'var(--text-primary)', prefix: ' ' },
};

const STORAGE_KEY = 'config-diff-previous';
// An unconverted SRX baseline is unsanitized device config; don't let it sit
// in localStorage indefinitely — expire it like a short-lived cache entry.
const BASELINE_TTL_MS = 24 * 60 * 60 * 1000;

/** Reads the saved baseline, discarding it once it's past its expiry. */
function readSavedBaseline() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return '';
    const parsed = safeJsonParse(raw);
    if (!parsed || typeof parsed.text !== 'string' || typeof parsed.savedAt !== 'number') {
      localStorage.removeItem(STORAGE_KEY);
      return '';
    }
    if (Date.now() - parsed.savedAt > BASELINE_TTL_MS) {
      localStorage.removeItem(STORAGE_KEY);
      return '';
    }
    return parsed.text;
  } catch { return ''; }
}

export default function ConfigDiff({ currentOutput }) {
  const [mode, setMode] = useState('previous'); // 'previous' or 'paste'
  const [pasteText, setPasteText] = useState('');
  const [showOnlyChanges, setShowOnlyChanges] = useState(false);

  const currentText = useMemo(
    () => currentOutput ? getConversionOutputText(currentOutput) : '',
    [currentOutput],
  );

  // Load previous output from localStorage (expires after BASELINE_TTL_MS)
  const previousText = useMemo(() => readSavedBaseline(), []);

  // Save current as "previous" for next comparison, timestamped for expiry
  const handleSaveAsPrevious = useCallback(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ text: currentText, savedAt: Date.now() }));
    } catch { /* ignore */ }
  }, [currentText]);

  const compareText = mode === 'previous' ? previousText : pasteText;

  const diffResult = useMemo(() => {
    if (!currentText || !compareText) return [];
    const linesA = compareText.split('\n');
    const linesB = currentText.split('\n');
    return computeLineDiff(linesA, linesB);
  }, [currentText, compareText]);

  const stats = useMemo(() => {
    const added = diffResult.filter(d => d.type === 'added').length;
    const removed = diffResult.filter(d => d.type === 'removed').length;
    const same = diffResult.filter(d => d.type === 'same').length;
    return { added, removed, same, total: diffResult.length };
  }, [diffResult]);

  const displayDiff = showOnlyChanges ? diffResult.filter(d => d.type !== 'same') : diffResult;

  if (!currentOutput) {
    return (
      <div className="panel-body">
        <div className="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
            <path d="M16 3H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2V8z" />
            <polyline points="16 3 16 8 21 8" />
          </svg>
          <h3>No configuration output</h3>
          <p>Convert a config to SRX format first, then use Config Diff to compare versions.</p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, padding: 12 }}>
      {/* Controls */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <select
          className="btn btn-secondary btn-sm"
          value={mode}
          onChange={(e) => setMode(e.target.value)}
        >
          <option value="previous">vs Previous Conversion</option>
          <option value="paste">vs Pasted Config</option>
        </select>

        {mode === 'previous' && (
          <button className="btn btn-secondary btn-sm" onClick={handleSaveAsPrevious}>
            Save Current as Baseline
          </button>
        )}

        <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={showOnlyChanges}
            onChange={(e) => setShowOnlyChanges(e.target.checked)}
          />
          Changes only
        </label>

        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
          <span style={{ color: 'var(--success)' }}>+{stats.added}</span>
          {' / '}
          <span style={{ color: 'var(--error)' }}>-{stats.removed}</span>
          {' / '}
          <span>{stats.same} unchanged</span>
        </span>
      </div>

      {/* Paste input for paste mode */}
      {mode === 'paste' && (
        <textarea
          style={{
            background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)',
            borderRadius: 'var(--radius)', padding: 8, fontFamily: 'var(--font-mono)',
            fontSize: 11, color: 'var(--text-primary)', resize: 'vertical',
            minHeight: 80, maxHeight: 200, marginBottom: 8,
          }}
          placeholder="Paste an older SRX config here for comparison..."
          value={pasteText}
          onChange={(e) => setPasteText(e.target.value)}
        />
      )}

      {/* No comparison available */}
      {!compareText && (
        <div className="empty-state" style={{ flex: 1 }}>
          <p>
            {mode === 'previous'
              ? 'No previous conversion saved (or it expired after 24 hours). Click "Save Current as Baseline" after converting, then convert again to see differences.'
              : 'Paste an older config in the text area above to compare.'}
          </p>
        </div>
      )}

      {/* Diff output */}
      {compareText && (
        <pre className="output-code" style={{ flex: 1, minHeight: 0, overflow: 'auto', margin: 0, fontSize: 11 }}>
          {displayDiff.map((entry, i) => {
            const style = DIFF_COLORS[entry.type];
            return (
              <div
                key={i}
                style={{
                  background: style.bg,
                  color: style.color,
                  padding: '0 8px',
                  whiteSpace: 'pre',
                  minHeight: 18,
                  lineHeight: '18px',
                }}
              >
                <span style={{ display: 'inline-block', width: 16, textAlign: 'center', opacity: 0.6 }}>
                  {style.prefix}
                </span>
                {entry.line}
              </div>
            );
          })}
        </pre>
      )}
    </div>
  );
}

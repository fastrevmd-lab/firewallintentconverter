/**
 * Full PDF Report Generator — self-contained HTML document for print-to-PDF export.
 *
 * Generates a color-coded migration report covering the full conversion lifecycle:
 *   1. Migration Overview (model-to-model, port mapping, stats)
 *   2. Original Configuration Input
 *   3. Analysis Changes (removed/modified rules, unused objects)
 *   4. LLM Changes (field-level diffs, AI-disabled rules)
 *   5. User Changes (accepted, deleted, modified, moved rules)
 *   6. Final SRX Output
 *   7. Unconverted / Unsupported Commands
 *
 * Color coding follows the Mechub brand system: provider-neutral plum for
 * model activity, caution for analysis, teal for actions, and Juniper green
 * only for the target platform.
 */
import { getConversionOutputText } from '../../src/conversion/conversion-output.js';
import { BRAND, BRAND_COLORS as B, reportBrandLockup } from './brand.js';
import { APP_VERSION } from '../../src/version.js';

const VENDOR_LABELS = {
  panos: 'PAN-OS', srx: 'SRX', fortigate: 'FortiGate',
  cisco_asa: 'Cisco ASA', checkpoint: 'Check Point',
  sonicwall: 'SonicWall', huawei_usg: 'Huawei USG',
  aws_sg: 'AWS Security Groups', azure_nsg: 'Azure NSG', gcp_fw: 'GCP Firewall',
  greenfield: 'Greenfield', srx_healthcheck: 'SRX Best Practice',
};

const MAX_CONFIG_LINES = 5000;
const MAX_OUTPUT_LINES = 8000;

/** HTML-escape a string. */
function esc(str) {
  if (str == null) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function arr(v) { return Array.isArray(v) ? v : []; }

/** Build an HTML table from headers + rows (supports raw HTML cells via {html:...}). */
function table(headers, rows, opts = {}) {
  if (!rows.length) return '<p class="empty">None</p>';
  const cls = opts.className ? ` class="${opts.className}"` : '';
  let h = `<table${cls}><thead><tr>` + headers.map(h => `<th>${esc(h)}</th>`).join('') + '</tr></thead><tbody>';
  for (const row of rows) {
    const trCls = row._rowClass ? ` class="${row._rowClass}"` : '';
    const cells = Array.isArray(row) ? row : row.cells || [];
    h += `<tr${trCls}>` + cells.map(c => {
      if (c && typeof c === 'object' && c.html) return `<td>${c.html}</td>`;
      return `<td>${esc(c)}</td>`;
    }).join('') + '</tr>';
  }
  return h + '</tbody></table>';
}

/** Wrap content in a numbered section with page-break and optional color accent. */
function section(num, title, content, opts = {}) {
  const badge = opts.count != null ? ` <span class="badge" style="${opts.badgeStyle || ''}">${opts.count}</span>` : '';
  const pageBreak = num > 1 ? ' page-break' : '';
  const accent = opts.accent || C.accent;
  return `<div class="section${pageBreak}">
    <h2 class="section-title" style="border-bottom-color: ${accent};">
      <span class="section-num" style="background: ${accent};">${num}</span> ${esc(title)}${badge}
    </h2>
    <div class="section-body">${content}</div>
  </div>`;
}

/** Truncate text to a max number of lines. */
function truncateLines(text, max) {
  if (!text) return '';
  const lines = text.split('\n');
  if (lines.length <= max) return esc(text);
  const kept = lines.slice(0, max);
  return esc(kept.join('\n')) + `\n\n<span class="truncated">[... ${lines.length - max} lines omitted — ${lines.length} total lines ...]</span>`;
}

/** Create a colored pill/tag. */
function pill(text, bg, fg) {
  return `<span style="display:inline-block;padding:1px 7px;border-radius:10px;font-size:9px;font-weight:600;background:${bg};color:${fg};">${esc(text)}</span>`;
}

/** Format a list of strings as comma-separated, with 'any' highlighted. */
function fmtList(items) {
  const list = arr(items);
  if (!list.length) return '-';
  return list.map(i => i === 'any' ? `<em style="color:#999;">any</em>` : esc(i)).join(', ');
}

// ---------------------------------------------------------------------------
// Print-safe Mechub color roles
// ---------------------------------------------------------------------------
const C = {
  llmCloud: B.plum,
  llmCloudBg: 'rgba(124,58,237,.10)',
  llmLocal: B.plum,
  llmLocalBg: 'rgba(124,58,237,.10)',
  caution: '#B45309',
  cautionBg: 'rgba(180,83,9,.10)',
  juniper: B.juniper,
  juniperBg: 'rgba(144,198,65,.10)',
  accent: B.tealDeep,
  success: '#047857',
  error: '#B91C1C',
  muted: '#6B7280',
  info: '#1D4ED8',
};

// ---------------------------------------------------------------------------
// Section 1: Migration Overview
// ---------------------------------------------------------------------------

function buildOverview(data) {
  const {
    sourceVendor, sourceModel, targetModel, siteName, siteGroup,
    intermediateConfig: ic, interfaceMappings, conversionSummary: cs,
    sourceModelData, targetModelData, isLocalLLM,
  } = data;

  const vendorLabel = VENDOR_LABELS[sourceVendor] || sourceVendor || 'Unknown';
  let html = '';

  // --- Model-to-model card ---
  html += '<div class="model-comparison">';
  html += buildModelCard('Source', vendorLabel, sourceModel, sourceModelData, '#e0e0e0');
  html += '<div class="model-arrow">&rarr;</div>';
  html += buildModelCard('Target', 'Juniper SRX', targetModel, targetModelData, C.juniperBg);
  html += '</div>';

  // --- Site metadata ---
  if (siteName || siteGroup) {
    html += '<div class="overview-meta">';
    if (siteName) html += `<span><strong>Site:</strong> ${esc(siteName)}</span>`;
    if (siteGroup) html += `<span><strong>Group:</strong> ${esc(siteGroup)}</span>`;
    html += '</div>';
  }

  // --- Conversion stats grid ---
  if (cs) {
    html += '<div class="stats-bar">';
    const items = [
      ['Zones', cs.zones_converted],
      ['Policies', cs.policies_converted],
      ['NAT Rules', cs.nat_rules_converted],
      ['Addresses', cs.addresses_converted],
      ['Services', cs.services_converted],
      ['Static Routes', cs.static_routes_converted],
      ['Warnings', cs.total_warnings],
      ['Unsupported', cs.unsupported_items],
    ].filter(([, v]) => v != null && v !== 0);
    for (const [label, val] of items) {
      const isWarn = label === 'Warnings' || label === 'Unsupported';
      html += `<div class="stat"><span class="stat-val" style="${isWarn && val > 0 ? 'color:' + C.caution : ''}">${val}</span><span class="stat-label">${label}</span></div>`;
    }
    html += '</div>';
  }

  // --- Color legend ---
  html += '<div class="color-legend">';
  html += `<span class="legend-item">${pill('LLM / Cloud', C.llmCloud, '#fff')} LLM-driven changes</span>`;
  html += `<span class="legend-item">${pill('Local LLM', C.llmLocal, '#fff')} Local LLM changes</span>`;
  html += `<span class="legend-item">${pill('Analysis', C.caution, '#fff')} App-driven analysis</span>`;
  html += `<span class="legend-item">${pill('SRX', C.juniper, '#fff')} Target platform</span>`;
  html += '</div>';

  // --- Interface / Port Mapping ---
  const mappings = interfaceMappings || {};
  const mappingEntries = Object.entries(mappings);
  if (mappingEntries.length > 0) {
    html += `<h3>Interface Port Mapping <span class="badge">${mappingEntries.length}</span></h3>`;
    const ifaces = arr(ic?.interfaces);
    const lagIfaces = arr(ic?.lag_interfaces);
    const lagMemberSet = new Set();
    for (const lag of lagIfaces) {
      for (const m of arr(lag.source_members)) lagMemberSet.add(m);
    }

    const rows = mappingEntries.map(([src, tgt]) => {
      const srcIface = ifaces.find(i => i.name === src);
      const srcDetail = srcIface ? [srcIface.zone || '', srcIface.ip || ''].filter(Boolean).join(' / ') : '';
      const isLag = lagMemberSet.has(src);
      const lagParent = lagIfaces.find(l => l.source_name === src);
      let typeTag = '';
      if (lagParent) typeTag = pill('LAG Parent', 'rgba(29,78,216,.10)', C.info);
      else if (isLag) typeTag = pill('LAG Member', 'rgba(29,78,216,.10)', C.info);
      else if (/^tunnel/i.test(src)) typeTag = pill('Tunnel', '#1e40af', '#93c5fd');
      else if (/^loopback/i.test(src)) typeTag = pill('Loopback', '#065f46', '#6ee7b7');

      return [
        src,
        { html: `${esc(tgt)}` },
        srcDetail || '-',
        { html: typeTag || '-' },
      ];
    });
    html += table(['Source Interface', 'SRX Interface', 'Zone / IP', 'Type'], rows);
  }

  return html;
}

function buildModelCard(role, vendor, model, modelData, bgColor) {
  let html = `<div class="model-card" style="background:${bgColor};">`;
  html += `<div class="model-role">${esc(role)}</div>`;
  html += `<div class="model-vendor">${esc(vendor)}</div>`;
  if (model) html += `<div class="model-name">${esc(model)}</div>`;
  if (modelData) {
    if (modelData.description) html += `<div class="model-desc">${esc(modelData.description)}</div>`;
    const tp = modelData.throughput;
    if (tp) {
      html += '<div class="model-throughput">';
      if (tp.l4 && tp.l4 !== 'N/A') html += `<span>L4: ${esc(tp.l4)}</span>`;
      if (tp.l7 && tp.l7 !== 'N/A') html += `<span>L7: ${esc(tp.l7)}</span>`;
      if (tp.threat && tp.threat !== 'N/A') html += `<span>Threat: ${esc(tp.threat)}</span>`;
      html += '</div>';
    }
    const portCount = arr(modelData.ports).length;
    if (portCount) html += `<div class="model-ports">${portCount} ports</div>`;
    if (modelData.eol) html += `<div style="color:${C.error};font-weight:600;font-size:10px;">End of Life</div>`;
  }
  html += '</div>';
  return html;
}

// ---------------------------------------------------------------------------
// Section 2: Original Configuration
// ---------------------------------------------------------------------------

function buildOriginalConfig(configText) {
  if (!configText) return '<p class="empty">No original configuration was loaded.</p>';
  const lineCount = configText.split('\n').length;
  return `<p class="meta">${lineCount.toLocaleString()} lines</p>
    <pre class="config-block">${truncateLines(configText, MAX_CONFIG_LINES)}</pre>`;
}

// ---------------------------------------------------------------------------
// Section 3: Analysis Changes (orange accent)
// ---------------------------------------------------------------------------

function buildAnalysisChanges(intermediateConfig, originalPolicies) {
  const findings = arr(intermediateConfig?._analysisFindings);
  if (!findings.length) {
    return '<p class="empty">Analysis was not run on this configuration.</p>';
  }

  const ACTION_LABELS = {
    include: 'Keep All', exclude: 'Remove', keep_all: 'Keep All (Annotate)',
    consolidate: 'Consolidate', remove: 'Remove', remove_all: 'Remove All',
    disable: 'Disable', include_disabled: 'Keep Disabled', include_enabled: 'Re-enable',
    enable_logging: 'Enable Logging', enable_all: 'Enable All', report_only: 'Report Only',
    flag: 'Warning Flag', ignore: 'Ignored',
  };

  // Advisory findings the user chose to Ignore are suppressed from the report.
  const isIgnored = (f) => f.selected === 'ignore';

  // Determine per-item effective status based on bulk action + per-item overrides
  const REMOVE_ACTIONS = new Set(['exclude', 'remove', 'remove_all']);
  const MODIFY_ACTIONS = new Set(['enable_all', 'include_enabled', 'consolidate']);

  function getItemStatus(finding, item) {
    const override = (finding.itemOverrides || {})[item.key];
    const bulkRemove = REMOVE_ACTIONS.has(finding.selected);
    const bulkModify = MODIFY_ACTIONS.has(finding.selected);

    if (override === 'exclude') return { label: 'Removed (override)', color: C.error };
    if (override === 'include' || override === 'include_enabled') return { label: 'Kept (override)', color: C.success };

    if (bulkRemove) return { label: 'Removed', color: C.error };
    if (bulkModify) return { label: ACTION_LABELS[finding.selected] || 'Modified', color: C.caution };
    return { label: 'Kept', color: C.success };
  }

  let html = '';

  // Summary table (ignored advisory findings are suppressed)
  const summaryRows = findings.filter(f => f.count > 0 && !isIgnored(f)).map(f => {
    const action = ACTION_LABELS[f.selected] || f.selected || 'No action';
    const isRemove = REMOVE_ACTIONS.has(f.selected);
    const actionHtml = isRemove
      ? `<span style="color:${C.error};font-weight:600;">${esc(action)}</span>`
      : esc(action);
    const overrideCount = f.itemOverrides ? Object.keys(f.itemOverrides).filter(k => f.itemOverrides[k] != null).length : 0;
    const overrideNote = overrideCount > 0 ? ` <span style="color:${C.muted};">(${overrideCount} override${overrideCount !== 1 ? 's' : ''})</span>` : '';
    return [
      f.id.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      String(f.count),
      { html: actionHtml + overrideNote },
    ];
  });
  html += table(['Finding Category', 'Count', 'Action Taken'], summaryRows);

  // Detailed item list for EVERY finding with items
  const activeFindings = findings.filter(f => f.count > 0 && !isIgnored(f) && arr(f.items).length > 0);
  for (const f of activeFindings) {
    const label = f.id.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    const isRemove = REMOVE_ACTIONS.has(f.selected);
    const headerColor = isRemove ? C.error : MODIFY_ACTIONS.has(f.selected) ? C.caution : C.accent;
    const actionLabel = ACTION_LABELS[f.selected] || f.selected || '';

    html += `<h3 style="color:${headerColor};">${esc(label)} <span class="badge" style="background:${headerColor};">${f.count}</span></h3>`;
    html += `<p class="meta">Action: ${esc(actionLabel)}</p>`;

    const items = arr(f.items);
    const displayItems = items.slice(0, 100);
    const rows = displayItems.map(item => {
      const status = getItemStatus(f, item);
      const statusHtml = `<span style="color:${status.color};font-weight:600;">${esc(status.label)}</span>`;
      return [
        item.label || item.key || '-',
        item.kind || '-',
        { html: statusHtml },
      ];
    });
    if (items.length > 100) {
      rows.push([`... and ${items.length - 100} more items`, '', '']);
    }
    html += table(['Item', 'Type', 'Status'], rows);
  }

  return html;
}

// ---------------------------------------------------------------------------
// Section 4: LLM Changes (violet accent)
// ---------------------------------------------------------------------------

function buildLLMChanges(srxTranslatedPolicies, originalPolicies, isLocalLLM) {
  const translated = arr(srxTranslatedPolicies);
  const original = arr(originalPolicies);

  if (!translated.length) {
    return '<p class="empty">LLM translation was not used for this conversion.</p>';
  }

  const llmColor = isLocalLLM ? C.llmLocal : C.llmCloud;
  const llmBg = isLocalLLM ? C.llmLocalBg : C.llmCloudBg;
  const llmLabel = isLocalLLM ? 'Local LLM' : 'Cloud LLM';

  // Build original lookup by rule index or name
  const origMap = new Map();
  for (const p of original) {
    origMap.set(p._rule_index ?? p.name, p);
  }

  // Find all LLM-touched rules
  const llmReviewed = translated.filter(p => p._review_status === 'llm_reviewed' || p._was_disabled_by_ai);

  if (!llmReviewed.length) {
    return `<p class="empty">${esc(llmLabel)} was invoked but made no changes to any rules.</p>`;
  }

  let html = '';
  html += `<p class="meta">${pill(llmLabel, llmColor, '#fff')} ${llmReviewed.length} rule${llmReviewed.length !== 1 ? 's' : ''} modified</p>`;

  // AI-Disabled rules
  const aiDisabled = llmReviewed.filter(p => p._was_disabled_by_ai);
  if (aiDisabled.length) {
    html += `<h3 style="color:${C.error};">AI-Disabled Rules <span class="badge" style="background:${C.error};">${aiDisabled.length}</span></h3>`;
    html += '<p class="meta">These rules were disabled by the LLM based on risk analysis.</p>';
    const rows = aiDisabled.map(p => [
      p.name || '-',
      { html: fmtList(p.src_zones) },
      { html: fmtList(p.dst_zones) },
      p.action || '-',
      p._translation_notes || 'No rationale provided',
    ]);
    html += table(['Rule Name', 'From Zone', 'To Zone', 'Original Action', 'Rationale'], rows);
  }

  // Changed rules — show field-level diffs
  const changed = llmReviewed.filter(p => !p._was_disabled_by_ai);
  if (changed.length) {
    html += `<h3 style="color:${llmColor};">Changed Rules <span class="badge" style="background:${llmColor};">${changed.length}</span></h3>`;

    const rows = [];
    for (const rule of changed) {
      const orig = origMap.get(rule._rule_index) || origMap.get(rule.name);
      const diffs = orig ? diffRuleFields(orig, rule) : [];
      const diffHtml = diffs.length
        ? diffs.map(d => `<span class="field-diff"><strong>${esc(d.field)}:</strong> <span class="diff-old">${esc(d.from)}</span> → <span class="diff-new">${esc(d.to)}</span></span>`).join('<br>')
        : '<span style="color:#999;">No field diffs (new rule or index mismatch)</span>';

      rows.push([
        rule.name || '-',
        { html: fmtList(rule.src_zones) + ' → ' + fmtList(rule.dst_zones) },
        rule.action || '-',
        { html: diffHtml },
        rule._translation_notes || '-',
      ]);
    }
    html += table(['Rule', 'Zones', 'Action', 'Changes', 'LLM Notes'], rows);
  }

  return html;
}

/** Compare two rule objects and return field-level diffs. */
function diffRuleFields(orig, translated) {
  const diffs = [];
  const fields = [
    { key: 'action', label: 'Action' },
    { key: 'disabled', label: 'Disabled', fmt: v => v ? 'Yes' : 'No' },
    { key: 'src_zones', label: 'Src Zones', fmt: v => arr(v).join(', ') || 'any' },
    { key: 'dst_zones', label: 'Dst Zones', fmt: v => arr(v).join(', ') || 'any' },
    { key: 'src_addresses', label: 'Src Addresses', fmt: v => arr(v).join(', ') || 'any' },
    { key: 'dst_addresses', label: 'Dst Addresses', fmt: v => arr(v).join(', ') || 'any' },
    { key: 'applications', label: 'Applications', fmt: v => arr(v).join(', ') || '-' },
    { key: 'services', label: 'Services', fmt: v => arr(v).join(', ') || '-' },
    { key: 'log_start', label: 'Log Start', fmt: v => v ? 'Yes' : 'No' },
    { key: 'log_end', label: 'Log End', fmt: v => v ? 'Yes' : 'No' },
  ];

  for (const { key, label, fmt } of fields) {
    const origVal = fmt ? fmt(orig[key]) : String(orig[key] ?? '');
    const newVal = fmt ? fmt(translated[key]) : String(translated[key] ?? '');
    if (origVal !== newVal) {
      diffs.push({ field: label, from: origVal, to: newVal });
    }
  }
  return diffs;
}

// ---------------------------------------------------------------------------
// Section 5: User Changes
// ---------------------------------------------------------------------------

function buildUserChanges(srxTranslatedPolicies, originalPolicies, sectionAcceptance) {
  const translated = arr(srxTranslatedPolicies);
  const original = arr(originalPolicies);
  const acceptance = sectionAcceptance || {};
  const hasAcceptance = Object.keys(acceptance).length > 0;

  // Categorize rules
  const accepted = translated.filter(p => p._review_status === 'accepted');
  const disabled = translated.filter(p => p.disabled && !original.find(o =>
    (o._rule_index === p._rule_index || o.name === p.name) && o.disabled,
  ));

  // Detect deleted rules (in original but not in translated)
  const translatedNames = new Set(translated.map(p => p._rule_index ?? p.name));
  const deleted = original.filter(p => !translatedNames.has(p._rule_index ?? p.name));

  // Detect moved rules (different position)
  const moved = [];
  for (let i = 0; i < translated.length; i++) {
    const rule = translated[i];
    const origIdx = original.findIndex(o => o._rule_index === rule._rule_index || o.name === rule.name);
    if (origIdx >= 0 && origIdx !== i && Math.abs(origIdx - i) > 0) {
      moved.push({ rule, from: origIdx + 1, to: i + 1 });
    }
  }

  const hasChanges = hasAcceptance || accepted.length || deleted.length || disabled.length || moved.length;

  if (!hasChanges) {
    return '<p class="empty">No manual user changes were made during this conversion.</p>';
  }

  let html = '';

  // Section acceptance
  if (hasAcceptance) {
    html += '<h3>Section Review Status</h3>';
    const rows = Object.entries(acceptance).map(([sectionId, isAccepted]) => {
      const statusHtml = isAccepted
        ? `<span style="color:${C.success};font-weight:600;">✓ Accepted</span>`
        : `<span style="color:${C.muted};">Pending</span>`;
      return [
        sectionId.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
        { html: statusHtml },
      ];
    });
    html += table(['Section', 'Status'], rows);
  }

  // Accepted rules
  if (accepted.length) {
    html += `<h3 style="color:${C.success};">Accepted Rules <span class="badge" style="background:${C.success};">${accepted.length}</span></h3>`;
    const rows = accepted.map(p => [
      p.name || '-',
      { html: fmtList(p.src_zones) + ' → ' + fmtList(p.dst_zones) },
      p.action || '-',
      p._translation_notes || '-',
    ]);
    html += table(['Rule', 'Zones', 'Action', 'Notes'], rows);
  }

  // Deleted rules
  if (deleted.length) {
    html += `<h3 style="color:${C.error};">Deleted Rules <span class="badge" style="background:${C.error};">${deleted.length}</span></h3>`;
    const rows = deleted.map(p => [
      p.name || '-',
      { html: fmtList(p.src_zones) + ' → ' + fmtList(p.dst_zones) },
      p.action || '-',
      arr(p.applications || p.services).join(', ') || '-',
    ]);
    html += table(['Rule', 'Zones', 'Action', 'Apps / Services'], rows);
  }

  // Moved rules
  if (moved.length) {
    html += `<h3>Reordered Rules <span class="badge">${moved.length}</span></h3>`;
    const rows = moved.map(({ rule, from, to }) => [
      rule.name || '-',
      `#${from}`,
      `#${to}`,
      from > to ? '↑ Moved up' : '↓ Moved down',
    ]);
    html += table(['Rule', 'Original Position', 'New Position', 'Direction'], rows);
  }

  // User-disabled rules
  if (disabled.length) {
    html += `<h3 style="color:${C.caution};">User-Disabled Rules <span class="badge" style="background:${C.caution};">${disabled.length}</span></h3>`;
    const rows = disabled.map(p => [
      p.name || '-',
      { html: fmtList(p.src_zones) + ' → ' + fmtList(p.dst_zones) },
      p.action || '-',
    ]);
    html += table(['Rule', 'Zones', 'Action'], rows);
  }

  return html;
}

// ---------------------------------------------------------------------------
// Section 6: Final SRX Output
// ---------------------------------------------------------------------------

function buildFinalOutput(srxOutput, outputFormat) {
  if (!srxOutput) return '<p class="empty">No SRX output was generated. Run the conversion first.</p>';

  const text = getConversionOutputText(srxOutput);
  const isXml = srxOutput.format === 'xml';

  if (!text) return '<p class="empty">Output is empty.</p>';

  const lineCount = text.split('\n').length;
  const formatLabel = isXml ? 'XML' : 'Set Commands';

  return `<p class="meta">${formatLabel} — ${lineCount.toLocaleString()} lines</p>
    <pre class="config-block">${truncateLines(text, MAX_OUTPUT_LINES)}</pre>`;
}

// ---------------------------------------------------------------------------
// Section 7: Unconverted / Unsupported
// ---------------------------------------------------------------------------

function buildUnconverted(parseWarnings, convertWarnings) {
  const allWarnings = [...arr(parseWarnings), ...arr(convertWarnings)];

  const unsupported = allWarnings.filter(w =>
    typeof w === 'object' && (w.severity === 'unsupported' || w.severity === 'error'),
  );
  const interview = allWarnings.filter(w =>
    typeof w === 'object' && w.severity === 'interview_required',
  );
  const warnings = allWarnings.filter(w =>
    typeof w === 'object' && w.severity === 'warning',
  );

  if (!unsupported.length && !interview.length && !warnings.length) {
    return '<p class="empty">All commands were successfully converted. No unsupported items detected.</p>';
  }

  let html = '';

  if (unsupported.length) {
    html += `<h3 style="color:${C.error};">Unsupported / Failed <span class="badge" style="background:${C.error};">${unsupported.length}</span></h3>`;
    html += table(
      ['Element', 'Issue', 'Suggestion'],
      unsupported.map(w => [
        w.element || '-',
        w.message || (typeof w === 'string' ? w : '-'),
        w.suggestion || '-',
      ]),
    );
  }

  if (interview.length) {
    html += `<h3 style="color:${C.caution};">Requires Manual Intervention <span class="badge" style="background:${C.caution};">${interview.length}</span></h3>`;
    html += table(
      ['Element', 'Issue', 'Suggestion'],
      interview.map(w => [
        w.element || '-',
        w.message || '-',
        w.suggestion || '-',
      ]),
    );
  }

  if (warnings.length) {
    html += `<h3>Warnings <span class="badge">${warnings.length}</span></h3>`;
    html += table(
      ['Element', 'Issue', 'Suggestion'],
      warnings.map(w => [
        w.element || '-',
        w.message || '-',
        w.suggestion || '-',
      ]),
    );
  }

  return html;
}

// ---------------------------------------------------------------------------
// Audit Trail (per-command disposition)
// ---------------------------------------------------------------------------

function buildAuditTrail(intermediateConfig, srxTranslatedPolicies) {
  const srcPolicies = arr(intermediateConfig?.security_policies);
  if (srcPolicies.length === 0) {
    return '<p class="empty">No source policies to audit.</p>';
  }

  const dstPolicies = arr(srxTranslatedPolicies);
  const dstByName = {};
  for (const p of dstPolicies) {
    if (p.name) dstByName[p.name] = p;
  }

  const rows = srcPolicies.map((src, i) => {
    const dst = dstByName[src.name];
    let decision = '';
    if (!dst && src._deleted_by === 'analysis') decision = 'Deleted by analysis';
    else if (!dst && src._deleted_by === 'user') decision = 'Deleted by user';
    else if (!dst && src._deleted_by === 'ai') decision = 'Deleted by AI';
    else if (dst && dst._review_status === 'llm_reviewed') decision = 'Modified by AI';
    else if (dst && dst._review_status === 'accepted') decision = 'Accepted';
    else if (dst) decision = 'Direct conversion';
    else decision = 'Not in output';

    const comment = src._deletion_reason || dst?._translation_notes || '';
    const zones = `${arr(src.src_zones).join(',')} → ${arr(src.dst_zones).join(',')}`;
    const services = arr(src.services || src.applications).join(', ') || 'any';

    return [
      i + 1,
      esc(src.name || `Rule ${i + 1}`),
      src.action || '-',
      esc(zones),
      esc(services),
      decision,
      esc(comment),
    ];
  });

  return table(
    ['#', 'Rule Name', 'Action', 'Zone Flow', 'Services', 'Decision', 'Notes'],
    rows,
  );
}


// ---------------------------------------------------------------------------
// Main generator
// ---------------------------------------------------------------------------

/**
 * Generate a complete self-contained HTML document for print-to-PDF export.
 * @param {Object} data - Assembled app state
 * @returns {string} Complete HTML document
 */
export function generateFullPdfHtml(data) {
  const {
    configText = '',
    sourceVendor = '', sourceModel = '', targetModel = '',
    siteName = '', siteGroup = '',
    intermediateConfig,
    srxTranslatedPolicies,
    sectionAcceptance,
    srxOutput,
    outputFormat = 'set',
    parseWarnings = [],
    convertWarnings = [],
    conversionSummary,
    sourceModelData,
    targetModelData,
    isLocalLLM = false,
  } = data || {};

  const vendorLabel = VENDOR_LABELS[sourceVendor] || sourceVendor || 'Unknown';
  const now = new Date().toLocaleString();

  // Original policies for diff comparison (before LLM/analysis)
  const originalPolicies = arr(intermediateConfig?.security_policies);

  // Build 7 sections with color-coded accents
  const sections = [
    section(1, 'Migration Overview', buildOverview(data), { accent: C.accent }),
    section(2, 'Original Configuration', buildOriginalConfig(configText), { accent: '#555' }),
    section(3, 'Analysis Changes', buildAnalysisChanges(intermediateConfig, originalPolicies), { accent: C.caution }),
    section(4, 'LLM Changes', buildLLMChanges(srxTranslatedPolicies, originalPolicies, isLocalLLM), { accent: isLocalLLM ? C.llmLocal : C.llmCloud }),
    section(5, 'User Changes', buildUserChanges(srxTranslatedPolicies, originalPolicies, sectionAcceptance), { accent: C.accent }),
    section(6, 'Final SRX Output', buildFinalOutput(srxOutput, outputFormat), { accent: C.juniper }),
    section(7, 'Unconverted / Unsupported Commands', buildUnconverted(parseWarnings, convertWarnings), { accent: C.error }),
    section(8, 'Conversion Audit Trail', buildAuditTrail(intermediateConfig, srxTranslatedPolicies), { accent: C.caution }),
  ];

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Full Migration Report — ${esc(siteName || vendorLabel)}</title>
<style>
  @page {
    margin: 1.5cm;
    size: A4 landscape;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Geist Variable', 'Geist', 'Inter', system-ui, sans-serif;
    background: #fff;
    color: #1a1a1a;
    padding: 24px;
    line-height: 1.5;
    font-size: 11px;
  }

  /* --- Cover / Header --- */
  .report-header {
    text-align: center;
    padding: 20px 0 16px;
    border-bottom: 3px solid ${C.accent};
    margin-bottom: 20px;
  }
  .report-brand { display: flex; align-items: center; justify-content: center; gap: 8px; margin-bottom: 8px; font-family: 'Geist Variable', 'Inter', system-ui, sans-serif; }
  .mechub-report-mark { width: 34px; height: 34px; }
  .report-brand-name { font-weight: 700; letter-spacing: -.045em; }
  .brand-intent { color: ${B.plum}; }
  .report-endorsement { color: #6B7280; font: 500 10px 'Geist Mono Variable', monospace; }
  .report-header h1 { font-size: 22px; color: ${C.accent}; margin-bottom: 4px; }
  .report-header .subtitle { font-size: 12px; color: #666; }
  .target-platform { color: ${C.juniper}; font-weight: 600; }

  /* --- Model comparison --- */
  .model-comparison {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 20px;
    margin-bottom: 16px;
  }
  .model-card {
    flex: 1;
    max-width: 320px;
    padding: 14px 18px;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    text-align: center;
  }
  .model-role { font-size: 9px; text-transform: uppercase; letter-spacing: 1px; color: #888; margin-bottom: 4px; }
  .model-vendor { font-size: 14px; font-weight: 700; color: #333; }
  .model-name { font-size: 18px; font-weight: 800; color: ${C.accent}; margin: 2px 0; }
  .model-desc { font-size: 10px; color: #666; margin-bottom: 6px; }
  .model-throughput { display: flex; gap: 10px; justify-content: center; font-size: 10px; color: #555; }
  .model-throughput span { background: #f0f2f5; padding: 2px 8px; border-radius: 4px; }
  .model-ports { font-size: 10px; color: #888; margin-top: 4px; }
  .model-arrow { font-size: 28px; color: ${C.juniper}; font-weight: 700; }
  .overview-meta { text-align: center; font-size: 11px; color: #555; margin-bottom: 12px; }
  .overview-meta span { margin: 0 10px; }

  /* --- Color legend --- */
  .color-legend {
    display: flex;
    gap: 16px;
    justify-content: center;
    flex-wrap: wrap;
    margin: 12px 0 16px;
    padding: 8px 16px;
    background: #fafbfc;
    border: 1px solid #e8e8e8;
    border-radius: 6px;
    font-size: 10px;
    color: #555;
  }
  .legend-item { display: inline-flex; align-items: center; gap: 5px; }

  /* --- Stats bar --- */
  .stats-bar {
    display: flex;
    gap: 12px;
    justify-content: center;
    flex-wrap: wrap;
    margin-bottom: 16px;
    padding: 12px;
    background: #f7f8fa;
    border-radius: 6px;
    border: 1px solid #e0e0e0;
  }
  .stat { text-align: center; min-width: 80px; }
  .stat-val { display: block; font-size: 18px; font-weight: 700; color: ${C.accent}; }
  .stat-label { display: block; font-size: 9px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }

  /* --- Sections --- */
  .section { margin-bottom: 16px; }
  .section.page-break { page-break-before: always; }
  .section-title {
    font-size: 15px;
    font-weight: 700;
    color: #1a1a1a;
    border-bottom: 3px solid ${C.accent};
    padding-bottom: 6px;
    margin-bottom: 10px;
  }
  .section-num {
    display: inline-block;
    width: 24px;
    height: 24px;
    line-height: 24px;
    text-align: center;
    background: ${C.accent};
    color: #fff;
    border-radius: 50%;
    font-size: 12px;
    margin-right: 6px;
  }
  .section-body h3 {
    font-size: 13px;
    color: #333;
    margin: 14px 0 6px;
  }
  .section-body h4 {
    font-size: 11px;
    color: #555;
    margin: 8px 0 4px;
  }

  /* --- Tables --- */
  table { width: 100%; border-collapse: collapse; font-size: 10px; margin-top: 6px; }
  th {
    background: #f0f2f5;
    padding: 5px 7px;
    text-align: left;
    font-weight: 600;
    border-bottom: 2px solid #ccc;
    white-space: nowrap;
    color: #333;
  }
  td {
    padding: 4px 7px;
    border-bottom: 1px solid #e8e8e8;
    word-break: break-word;
    max-width: 350px;
    vertical-align: top;
  }
  tr { page-break-inside: avoid; }
  tr:nth-child(even) td { background: #fafbfc; }

  /* --- Config blocks --- */
  .config-block {
    background: #f7f8fa;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 10px 12px;
    font-family: 'Geist Mono Variable', 'Geist Mono', 'JetBrains Mono', monospace;
    font-size: 8.5px;
    line-height: 1.4;
    white-space: pre-wrap;
    word-break: break-all;
    overflow: hidden;
    max-height: none;
  }

  /* --- Field-level diffs --- */
  .field-diff { display: inline-block; margin-bottom: 2px; font-size: 9px; }
  .diff-old { text-decoration: line-through; color: ${C.error}; background: rgba(220,38,38,0.08); padding: 0 3px; border-radius: 2px; }
  .diff-new { color: ${C.success}; font-weight: 600; background: rgba(5,150,105,0.08); padding: 0 3px; border-radius: 2px; }

  /* --- Misc --- */
  .badge {
    background: ${C.accent};
    color: #fff;
    font-size: 10px;
    padding: 1px 7px;
    border-radius: 10px;
    font-weight: 600;
    margin-left: 4px;
  }
  .meta { font-size: 11px; color: #666; margin-bottom: 6px; }
  .empty { color: #999; font-style: italic; font-size: 11px; }
  .truncated { color: #b45309; font-style: italic; font-weight: 600; }
  .report-footer {
    text-align: center;
    padding: 12px 0;
    margin-top: 20px;
    border-top: 1px solid #ccc;
    font-size: 10px;
    color: #888;
    page-break-before: avoid;
  }

  /* --- Print overrides --- */
  @media print {
    body { padding: 0; }
    .config-block { border-color: #ccc; }
    .stats-bar { border-color: #ccc; background: #f4f4f4; }
    .model-card { border-color: #ccc; }
    .color-legend { border-color: #ccc; }
  }
</style>
</head>
<body>
<div class="report-header">
  ${reportBrandLockup()}
  <h1>Firewall migration report</h1>
  <div class="subtitle">${esc(vendorLabel)}${sourceModel ? ' (' + esc(sourceModel) + ')' : ''} &rarr; <span class="target-platform">Juniper SRX${targetModel ? ' (' + esc(targetModel) + ')' : ''}</span>${siteName ? ' | Site: ' + esc(siteName) : ''}${siteGroup ? ' (' + esc(siteGroup) + ')' : ''} | Generated: ${esc(now)} | Tool v${esc(APP_VERSION)}</div>
</div>
${sections.join('\n')}
<div class="report-footer">Generated by ${BRAND.product} v${esc(APP_VERSION)} &middot; ${BRAND.endorsement} &mdash; ${esc(now)}</div>
<script>window.onload=function(){window.print();}<\/script>
</body>
</html>`;
}

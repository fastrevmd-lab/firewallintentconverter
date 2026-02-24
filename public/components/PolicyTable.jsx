/**
 * PolicyTable Component
 *
 * Sortable, filterable, editable security rules table.
 * Supports inline cell editing (double-click), add/delete rows.
 * Shows review status labels (Disabled/Unreviewed/LLM Reviewed/Accepted).
 *
 * viewMode: 'panos' shows PAN-OS terminology, 'srx' shows SRX terminology.
 */
import React, { useState, useMemo } from 'react';
import { mapActionToSrx, buildApplicationServices } from '../utils/srx-view-transforms.js';

export default function PolicyTable({
  policies,
  warnings,
  selectedRule,
  onSelectRule,
  onUpdateRule,
  onDeleteRule,
  onAddRule,
  viewMode,
  platformView,
}) {
  const [sortField, setSortField] = useState('_rule_index');
  const [sortDir, setSortDir] = useState('asc');
  const [filter, setFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [editingCell, setEditingCell] = useState(null); // { index, field }
  const [editValue, setEditValue] = useState('');

  const isSrx = viewMode === 'srx';
  const isFortigate = viewMode === 'fortigate';
  const isCisco = viewMode === 'cisco';
  const isCheckpoint = viewMode === 'checkpoint';
  const isSonicwall = viewMode === 'sonicwall';
  const isHuawei = viewMode === 'huawei';

  // Build a lookup of warning counts per rule
  const warningsByRule = useMemo(() => {
    const map = {};
    for (const w of (warnings || [])) {
      const match = w.element?.match(/security-rule\/(.+)/);
      if (match) {
        const ruleName = match[1];
        if (!map[ruleName]) map[ruleName] = [];
        map[ruleName].push(w);
      }
    }
    return map;
  }, [warnings]);

  /** Get the review status for display */
  const getRuleStatus = (rule) => {
    if (rule.disabled) return 'disabled';
    if (rule._review_status === 'accepted') return 'accepted';
    if (rule._review_status === 'llm-reviewed') return 'llm-reviewed';
    return 'unreviewed';
  };

  /** Get the warning-based sub-status */
  const getWarningStatus = (rule) => {
    const ruleWarnings = warningsByRule[rule.name] || [];
    if (ruleWarnings.some(w => w.severity === 'unsupported')) return 'unsupported';
    if (ruleWarnings.some(w => w.severity === 'interview_required')) return 'interview';
    if (ruleWarnings.some(w => w.severity === 'warning')) return 'warning';
    return 'clean';
  };

  const statusLabels = {
    disabled: 'Disabled',
    unreviewed: 'Unreviewed',
    'llm-reviewed': 'LLM Reviewed',
    accepted: 'Accepted',
  };

  const warningTooltips = {
    warning: 'Conversion warning — feature partially supported',
    unsupported: 'Unsupported — feature not available on target platform',
    interview: 'Needs review — manual input required to resolve',
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const displayPolicies = useMemo(() => {
    let result = [...policies];

    // Text filter
    if (filter.trim()) {
      const f = filter.toLowerCase();
      result = result.filter(p =>
        p.name.toLowerCase().includes(f) ||
        p.src_zones.join(' ').toLowerCase().includes(f) ||
        p.dst_zones.join(' ').toLowerCase().includes(f) ||
        p.src_addresses.join(' ').toLowerCase().includes(f) ||
        p.dst_addresses.join(' ').toLowerCase().includes(f) ||
        p.applications.join(' ').toLowerCase().includes(f) ||
        p.action.toLowerCase().includes(f)
      );
    }

    // Status filter
    if (statusFilter !== 'all') {
      result = result.filter(p => getRuleStatus(p) === statusFilter);
    }

    result.sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];
      if (Array.isArray(aVal)) aVal = aVal.join(', ');
      if (Array.isArray(bVal)) bVal = bVal.join(', ');
      if (typeof aVal === 'string') aVal = aVal.toLowerCase();
      if (typeof bVal === 'string') bVal = bVal.toLowerCase();
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [policies, filter, statusFilter, sortField, sortDir]);

  /** Start editing a cell */
  const startEdit = (realIndex, field, currentValue) => {
    setEditingCell({ index: realIndex, field });
    setEditValue(Array.isArray(currentValue) ? currentValue.join(', ') : String(currentValue || ''));
  };

  /** Commit edit */
  const commitEdit = () => {
    if (!editingCell) return;
    const { index, field } = editingCell;
    const rule = policies[index];
    let value = editValue;

    // Convert comma-separated strings back to arrays for array fields
    const arrayFields = ['src_zones', 'dst_zones', 'src_addresses', 'dst_addresses', 'applications', 'services'];
    if (arrayFields.includes(field)) {
      value = editValue.split(',').map(s => s.trim()).filter(Boolean);
    }

    onUpdateRule(index, { ...rule, [field]: value });
    setEditingCell(null);
    setEditValue('');
  };

  const cancelEdit = () => {
    setEditingCell(null);
    setEditValue('');
  };

  const handleEditKeyDown = (e) => {
    if (e.key === 'Enter') commitEdit();
    if (e.key === 'Escape') cancelEdit();
  };

  /** Find real index in policies array for a display policy */
  const getRealIndex = (policy) => {
    return policies.findIndex(p => p === policy || (p.name === policy.name && p._rule_index === policy._rule_index));
  };

  const renderCellValues = (values) => {
    if (!values || values.length === 0) return <span className="cell-chip">any</span>;
    return values.map((v, i) => (
      <span key={i} className="cell-chip">{v}</span>
    ));
  };

  /** Render security profiles / application services for a policy row */
  const renderProfileCell = (policy) => {
    // PAN-OS view: show profile type abbreviations
    const sp = policy.security_profiles || {};
    const profileEntries = Object.entries(sp);
    const hasGroup = !!policy.profile_group;
    const hasProfiles = profileEntries.length > 0;

    if (!hasGroup && !hasProfiles) {
      return <span className="cell-chip" style={{ opacity: 0.4 }}>none</span>;
    }

    const chips = [];

    if (hasProfiles) {
      const shortLabels = {
        'virus': 'AV', 'wildfire-analysis': 'WF', 'url-filtering': 'URL',
        'file-blocking': 'FB', 'spyware': 'AS', 'vulnerability': 'VP',
        // FortiGate-originated
        'application-control': 'App', 'email-filter': 'EM', 'dlp': 'DLP',
        'dns-security': 'DNS', 'decryption': 'SSL', 'waf': 'WAF',
        'casb': 'CASB', 'voip': 'VoIP',
      };
      for (const [pType, pName] of profileEntries) {
        const label = shortLabels[pType] || pType;
        chips.push(
          <span key={pType} className="cell-chip profile-chip" title={`${pType}: ${pName}`}>
            {label}
          </span>
        );
      }
    }

    if (hasGroup && !hasProfiles) {
      chips.push(
        <span key="group" className="cell-chip profile-chip profile-group-chip" title={`Profile group: ${policy.profile_group}`}>
          {policy.profile_group}
        </span>
      );
    }

    return chips;
  };

  /** SRX view: render Security Subscriptions column (vertical label/value pairs) */
  const renderSrxSubscriptions = (policy) => {
    const sp = policy.security_profiles || {};
    const hasSecIntel = policy._srx_secintel !== undefined
      ? !!policy._srx_secintel
      : (policy._secIntelAddresses?.length > 0);
    const rows = [];

    // IPS = spyware + vulnerability (maps to IDP on SRX)
    if (sp.spyware || sp.vulnerability) {
      const parts = [sp.vulnerability, sp.spyware].filter(Boolean).join(', ');
      rows.push({ label: 'IPS', cls: 'ips', value: parts });
    }

    // Content Security = url-filtering + file-blocking
    if (sp['url-filtering'] || sp['file-blocking']) {
      const parts = [sp['url-filtering'], sp['file-blocking']].filter(Boolean).join(', ');
      rows.push({ label: 'Content Security', cls: 'urlfilter', value: parts });
    }

    // Decrypt
    if (policy._srx_decrypt) {
      rows.push({ label: 'Decrypt', cls: 'ips', value: 'SSL Proxy' });
    }

    // Flow-based AV
    if (policy._srx_flow_av) {
      rows.push({ label: 'Flow-based AV', cls: 'antimalware', value: 'enabled' });
    }

    // Anti-virus = virus + wildfire (SRX term — no WildFire on SRX)
    if (sp.virus || sp['wildfire-analysis']) {
      const parts = [sp.virus, sp['wildfire-analysis']].filter(Boolean).join(', ');
      rows.push({ label: 'Anti-virus', cls: 'antimalware', value: parts });
    }

    // SecIntel
    if (hasSecIntel) {
      rows.push({ label: 'SecIntel', cls: 'secintel', value: 'Security Intelligence' });
    }

    // Secure Web Proxy
    if (policy._srx_secure_web_proxy) {
      rows.push({ label: 'Secure Web Proxy', cls: 'secintel', value: 'enabled' });
    }

    // ICAP Redirect
    if (policy._srx_icap_redirect) {
      rows.push({ label: 'ICAP Redirect', cls: 'fileblock', value: 'enabled' });
    }

    // Anti-spam (from FortiGate email filter)
    if (sp['email-filter']) {
      rows.push({ label: 'Anti-spam', cls: 'urlfilter', value: sp['email-filter'] });
    }

    // AppSecure (from FortiGate app control)
    if (sp['application-control']) {
      rows.push({ label: 'AppSecure', cls: 'ips', value: sp['application-control'] });
    }

    // DLP (informational — requires ICAP on SRX)
    if (sp['dlp']) {
      rows.push({ label: 'DLP (ICAP)', cls: 'fileblock', value: sp['dlp'] });
    }

    // DNS Security (from FortiGate DNS filter)
    if (sp['dns-security']) {
      rows.push({ label: 'DNS Security', cls: 'secintel', value: sp['dns-security'] });
    }

    if (rows.length === 0) {
      return <span className="srx-sub-none">none</span>;
    }

    return (
      <div className="srx-subscriptions">
        {rows.map((r, i) => (
          <div key={i} className="srx-sub-row">
            <span className={`srx-sub-label ${r.cls}`}>{r.label}</span>
            <span className="srx-sub-value">{r.value}</span>
          </div>
        ))}
      </div>
    );
  };

  /** SRX view: render combined source/destination cell with type icons */
  const renderSrxSourceDest = (policy, type) => {
    const zones = type === 'src' ? policy.src_zones : policy.dst_zones;
    const addrs = type === 'src' ? policy.src_addresses : policy.dst_addresses;
    const isNegated = type === 'src' ? policy.negate_source : policy.negate_destination;
    const MAX_SHOW = 2;
    // URL filtering profile — show under destinations
    const urlFilter = type === 'dst' ? (policy.security_profiles || {})['url-filtering'] : null;

    return (
      <div className="srx-cell-stack">
        {/* Zones */}
        {(zones || []).length === 0 ? (
          <div className="srx-cell-row">
            <span className="srx-cell-icon zone">Z</span>
            <span className="srx-cell-value" style={{ opacity: 0.5 }}>any</span>
          </div>
        ) : (
          zones.map((z, i) => (
            <div key={`z-${i}`} className="srx-cell-row">
              <span className="srx-cell-icon zone">Z</span>
              <span className="srx-cell-value">{z}</span>
            </div>
          ))
        )}
        {/* Negate indicator */}
        {isNegated && (
          <div className="srx-cell-row">
            <span className="srx-cell-icon negate">!</span>
            <span className="srx-cell-value negate-label">EXCEPT</span>
          </div>
        )}
        {/* Addresses */}
        {(addrs || []).length === 0 ? (
          <div className="srx-cell-row">
            <span className="srx-cell-icon addr">A</span>
            <span className="srx-cell-value" style={{ opacity: 0.5 }}>Any</span>
          </div>
        ) : (
          <>
            {addrs.slice(0, MAX_SHOW).map((a, i) => (
              <div key={`a-${i}`} className="srx-cell-row">
                <span className="srx-cell-icon addr">A</span>
                <span className="srx-cell-value">{a}</span>
              </div>
            ))}
            {addrs.length > MAX_SHOW && (
              <div className="srx-cell-row">
                <span className="srx-cell-icon addr">A</span>
                <span className="srx-cell-extra" title={addrs.slice(MAX_SHOW).join(', ')}>
                  +{addrs.length - MAX_SHOW}
                </span>
              </div>
            )}
          </>
        )}
        {/* URL Filtering (destinations only) */}
        {urlFilter && (
          <div className="srx-cell-row">
            <span className="srx-cell-icon url">U</span>
            <span className="srx-cell-value" style={{ fontSize: 11 }}>{urlFilter}</span>
          </div>
        )}
      </div>
    );
  };

  /** SRX view: render action with circle icon */
  const renderSrxAction = (policy) => {
    const action = mapActionToSrx(policy.action);
    const cls = action === 'permit' ? 'permit' : action === 'reject' ? 'reject' : 'deny';
    const icon = action === 'permit' ? '\u2713' : action === 'reject' ? '!' : '\u2715';
    return (
      <div className="srx-action">
        <span className={`srx-action-icon ${cls}`}>{icon}</span>
        <span className={`srx-action-text action-${cls}`}>{action.charAt(0).toUpperCase() + action.slice(1)}</span>
      </div>
    );
  };

  /** SRX view: render applications/services cell — split into Application + Port */
  const renderSrxApps = (policy) => {
    const apps = policy.applications || [];
    const svcs = (policy.services || []).filter(s => s !== 'application-default');
    const hasSvcDefault = (policy.services || []).includes('application-default');
    const MAX_APP = 2;
    const MAX_SVC = 2;

    return (
      <div className="srx-cell-stack">
        {/* Applications section */}
        {apps.length === 0 ? (
          <div className="srx-cell-row">
            <span className="srx-cell-icon app">A</span>
            <span className="srx-cell-value" style={{ opacity: 0.5 }}>any</span>
          </div>
        ) : (
          <>
            {apps.slice(0, MAX_APP).map((a, i) => (
              <div key={`a-${i}`} className="srx-cell-row">
                <span className="srx-cell-icon app">A</span>
                <span className="srx-cell-value">{a}</span>
              </div>
            ))}
            {apps.length > MAX_APP && (
              <div className="srx-cell-row">
                <span className="srx-cell-icon app">A</span>
                <span className="srx-cell-extra" title={apps.slice(MAX_APP).join(', ')}>
                  +{apps.length - MAX_APP}
                </span>
              </div>
            )}
          </>
        )}
        {/* Port / Services section */}
        {svcs.length === 0 && hasSvcDefault ? (
          <div className="srx-cell-row">
            <span className="srx-cell-icon svc">P</span>
            <span className="srx-cell-value" style={{ opacity: 0.5 }}>defaults</span>
          </div>
        ) : svcs.length === 0 ? null : (
          <>
            {svcs.slice(0, MAX_SVC).map((s, i) => (
              <div key={`s-${i}`} className="srx-cell-row">
                <span className="srx-cell-icon svc">P</span>
                <span className="srx-cell-value">{s}</span>
              </div>
            ))}
            {svcs.length > MAX_SVC && (
              <div className="srx-cell-row">
                <span className="srx-cell-icon svc">P</span>
                <span className="srx-cell-extra" title={svcs.slice(MAX_SVC).join(', ')}>
                  +{svcs.length - MAX_SVC}
                </span>
              </div>
            )}
          </>
        )}
      </div>
    );
  };

  /** Render an editable cell */
  const renderEditableCell = (policy, field, content) => {
    const realIndex = getRealIndex(policy);
    const isEditing = editingCell?.index === realIndex && editingCell?.field === field;

    if (isEditing) {
      return (
        <input
          className="cell-edit-input"
          value={editValue}
          onChange={(e) => setEditValue(e.target.value)}
          onKeyDown={handleEditKeyDown}
          onBlur={commitEdit}
          autoFocus
          onClick={(e) => e.stopPropagation()}
        />
      );
    }

    return (
      <div
        className="editable-cell"
        onDoubleClick={(e) => {
          e.stopPropagation();
          startEdit(realIndex, field, policy[field]);
        }}
        title="Double-click to edit"
      >
        {content}
      </div>
    );
  };

  const sortIndicator = (field) => {
    if (sortField !== field) return '';
    return sortDir === 'asc' ? ' \u25B2' : ' \u25BC';
  };

  /** Get display action text based on view mode */
  const getDisplayAction = (policy) => {
    if (isSrx) return mapActionToSrx(policy.action);
    return policy.action;
  };

  /** Get display log text based on view mode */
  const getDisplayLog = (policy) => {
    if (isSrx) {
      const parts = [];
      if (policy.log_end) parts.push('close');
      if (policy.log_start) parts.push('init');
      return parts.join('/') || '-';
    }
    return (
      <>
        {policy.log_start && 'S'}
        {policy.log_end && 'E'}
      </>
    );
  };

  /** Group policies by zone-pair for SRX view */
  const groupByZonePair = (pols) => {
    const groups = [];
    const groupMap = {};
    for (const p of pols) {
      const from = (p.src_zones || []).join(', ') || 'any';
      const to = (p.dst_zones || []).join(', ') || 'any';
      const key = `${from} → ${to}`;
      if (!groupMap[key]) {
        groupMap[key] = { key, from, to, policies: [] };
        groups.push(groupMap[key]);
      }
      groupMap[key].policies.push(p);
    }
    return groups;
  };

  /** Render the PAN-OS view table (original layout) */
  const renderPanosTable = () => (
    <table className="policy-table">
      <thead>
        <tr>
          <th onClick={() => handleSort('_rule_index')}>#{sortIndicator('_rule_index')}</th>
          <th onClick={() => handleSort('name')}>Name{sortIndicator('name')}</th>
          <th onClick={() => handleSort('src_zones')}>Src Zone{sortIndicator('src_zones')}</th>
          <th onClick={() => handleSort('dst_zones')}>Dst Zone{sortIndicator('dst_zones')}</th>
          <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
          <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
          <th onClick={() => handleSort('applications')}>App / Service{sortIndicator('applications')}</th>
          <th>Profiles</th>
          <th onClick={() => handleSort('action')}>Action{sortIndicator('action')}</th>
          <th>Log</th>
          <th style={{ width: 36 }}></th>
        </tr>
      </thead>
      <tbody>
        {displayPolicies.map((policy) => {
          const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
          const realIndex = getRealIndex(policy);

          return (
            <tr
              key={`${policy.name}-${policy._rule_index}`}
              className={`${isSelected ? 'selected' : ''} ${policy.disabled ? 'disabled-rule' : ''} ${policy._implicit ? 'implicit-rule' : ''}`}
              onClick={() => onSelectRule(isSelected ? null : policy)}
              style={{ cursor: 'pointer' }}
            >
              <td>{policy._rule_index}</td>
              <td title={policy.name}>
                {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
                {renderEditableCell(policy, 'name', policy.name)}
              </td>
              <td>{renderEditableCell(policy, 'src_zones', renderCellValues(policy.src_zones))}</td>
              <td>{renderEditableCell(policy, 'dst_zones', renderCellValues(policy.dst_zones))}</td>
              <td>{renderEditableCell(policy, 'src_addresses', <>{policy.negate_source && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.src_addresses)}</>)}</td>
              <td>{renderEditableCell(policy, 'dst_addresses', <>{policy.negate_destination && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.dst_addresses)}</>)}</td>
              <td>{renderEditableCell(policy, 'applications', renderCellValues([...policy.applications, ...policy.services.filter(s => s !== 'application-default')]))}</td>
              <td>{renderProfileCell(policy)}</td>
              <td>
                <span className={`action-${policy.action === 'allow' ? 'permit' : 'deny'}`}>
                  {policy.action}
                </span>
              </td>
              <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                {getDisplayLog(policy)}
              </td>
              <td>
                <button
                  className="btn-icon btn-icon-danger"
                  onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }}
                  title="Delete rule"
                >
                  x
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );

  /** Render the SRX Security Director-style table */
  const renderSrxTable = () => {
    const zonePairGroups = groupByZonePair(displayPolicies);
    const srxColCount = 8;

    return (
      <table className="policy-table srx-table">
        <thead>
          <tr>
            <th onClick={() => handleSort('_rule_index')} style={{ width: 52 }}>Seq{sortIndicator('_rule_index')}</th>
            <th onClick={() => handleSort('name')}>Name{sortIndicator('name')}</th>
            <th>Sources</th>
            <th>Destinations</th>
            <th onClick={() => handleSort('applications')}>Applications / Ports{sortIndicator('applications')}</th>
            <th onClick={() => handleSort('action')} style={{ width: 100 }}>Action{sortIndicator('action')}</th>
            <th>Security Subscriptions</th>
            <th style={{ width: 70 }}>Options</th>
          </tr>
        </thead>
        <tbody>
          {zonePairGroups.map((group) => (
            <React.Fragment key={group.key}>
              {/* Zone-pair group header */}
              <tr className="srx-zone-group-row">
                <td colSpan={srxColCount}>
                  <div className="srx-zone-group-label">
                    <span className="srx-zone-group-arrow">{'\u25BC'}</span>
                    <span>ZONE</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{group.from}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{'\u2192'}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{group.to}</span>
                    <span className="srx-zone-group-count">({group.policies.length} {group.policies.length === 1 ? 'Rule' : 'Rules'})</span>
                  </div>
                </td>
              </tr>
              {/* Policies in this group */}
              {group.policies.map((policy) => {
                const status = getRuleStatus(policy);
                const warnStatus = getWarningStatus(policy);
                const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
                const realIndex = getRealIndex(policy);

                return (
                  <tr
                    key={`${policy.name}-${policy._rule_index}`}
                    className={`${isSelected ? 'selected' : ''} ${policy.disabled ? 'disabled-rule' : ''} ${policy._implicit ? 'implicit-rule' : ''}`}
                    onClick={() => onSelectRule(isSelected ? null : policy)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <div className="srx-seq">{policy._rule_index}</div>
                    </td>
                    <td>
                      <div>
                        {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
                        {renderEditableCell(policy, 'name', (
                          <span style={{ fontWeight: 500 }}>{policy.name}</span>
                        ))}
                      </div>
                      <div style={{ marginTop: 4 }}>
                        <span className={`status-label status-${status}`}>
                          {statusLabels[status]}
                        </span>
                        {warnStatus !== 'clean' && (
                          <span className={`status-dot ${warnStatus}`} data-tooltip={warningTooltips[warnStatus] || warnStatus} style={{ marginLeft: 4 }} />
                        )}
                      </div>
                    </td>
                    <td>
                      <div
                        className="editable-cell"
                        onDoubleClick={(e) => {
                          e.stopPropagation();
                          startEdit(realIndex, 'src_addresses', policy.src_addresses);
                        }}
                        title="Double-click to edit addresses"
                      >
                        {renderSrxSourceDest(policy, 'src')}
                      </div>
                    </td>
                    <td>
                      <div
                        className="editable-cell"
                        onDoubleClick={(e) => {
                          e.stopPropagation();
                          startEdit(realIndex, 'dst_addresses', policy.dst_addresses);
                        }}
                        title="Double-click to edit addresses"
                      >
                        {renderSrxSourceDest(policy, 'dst')}
                      </div>
                    </td>
                    <td>
                      <div
                        className="editable-cell"
                        onDoubleClick={(e) => {
                          e.stopPropagation();
                          startEdit(realIndex, 'applications', policy.applications);
                        }}
                        title="Double-click to edit"
                      >
                        {renderSrxApps(policy)}
                      </div>
                    </td>
                    <td>{renderSrxAction(policy)}</td>
                    <td>{renderSrxSubscriptions(policy)}</td>
                    <td style={{ textAlign: 'center' }}>
                      <button
                        className="btn-icon btn-icon-danger"
                        onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }}
                        title="Delete policy"
                      >
                        x
                      </button>
                    </td>
                  </tr>
                );
              })}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    );
  };

  /** FortiGate action display */
  const renderFortigateAction = (policy) => {
    const action = policy.action === 'allow' ? 'ACCEPT' : policy.action === 'deny' ? 'DENY' : policy.action.toUpperCase();
    const cls = policy.action === 'allow' ? 'fg-accept' : 'fg-deny';
    const icon = policy.action === 'allow' ? '\u2713' : '\u2715';
    return (
      <div className={`fg-action ${cls}`}>
        <span className="fg-action-icon">{icon}</span>
        <span className="fg-action-text">{action}</span>
      </div>
    );
  };

  /** FortiGate security profile icons */
  const renderFortigateProfiles = (policy) => {
    const sp = policy.security_profiles || {};
    const fg = policy._fortigate || {};
    if (!fg.utm_status && Object.keys(sp).length === 0 && !policy.profile_group) {
      return <span className="fg-profile-none">-</span>;
    }

    const profiles = [];
    if (sp.virus) profiles.push({ key: 'av', label: 'AV', title: `Antivirus: ${sp.virus}`, cls: 'fg-prof-av' });
    if (sp['url-filtering']) profiles.push({ key: 'wf', label: 'WF', title: `Web Filter: ${sp['url-filtering']}`, cls: 'fg-prof-wf' });
    if (sp.vulnerability) profiles.push({ key: 'ips', label: 'IPS', title: `IPS: ${sp.vulnerability}`, cls: 'fg-prof-ips' });
    if (sp['application-control']) profiles.push({ key: 'app', label: 'App', title: `App Control: ${sp['application-control']}`, cls: 'fg-prof-app' });
    if (sp.decryption) profiles.push({ key: 'ssl', label: 'SSL', title: `SSL Inspection: ${sp.decryption}`, cls: 'fg-prof-ssl' });
    if (sp['dns-security']) profiles.push({ key: 'dns', label: 'DNS', title: `DNS Filter: ${sp['dns-security']}`, cls: 'fg-prof-dns' });
    if (sp['email-filter']) profiles.push({ key: 'email', label: 'EM', title: `Email Filter: ${sp['email-filter']}`, cls: 'fg-prof-email' });
    if (sp['dlp']) profiles.push({ key: 'dlp', label: 'DLP', title: `DLP: ${sp['dlp']}`, cls: 'fg-prof-dlp' });

    if (profiles.length === 0 && policy.profile_group) {
      return <span className="fg-profile-group" title={`Profile Group: ${policy.profile_group}`}>{policy.profile_group}</span>;
    }

    return (
      <div className="fg-profiles">
        {profiles.map(p => (
          <span key={p.key} className={`fg-prof-icon ${p.cls}`} title={p.title}>{p.label}</span>
        ))}
      </div>
    );
  };

  /** FortiGate NAT badge */
  const renderFortigateNat = (policy) => {
    const fg = policy._fortigate || {};
    return fg.nat
      ? <span className="fg-nat-on" title="Source NAT enabled">Enabled</span>
      : <span className="fg-nat-off">-</span>;
  };

  /** FortiGate status toggle indicator */
  const renderFortigateStatus = (policy) => {
    return policy.disabled
      ? <span className="fg-status-disabled" title="Policy disabled">OFF</span>
      : <span className="fg-status-enabled" title="Policy enabled">ON</span>;
  };

  /** Render the FortiGate / FortiOS view table */
  const renderFortigateTable = () => (
    <table className="policy-table fg-table">
      <thead>
        <tr>
          <th onClick={() => handleSort('_rule_index')} style={{ width: 44 }}>Seq{sortIndicator('_rule_index')}</th>
          <th onClick={() => handleSort('name')}>Name{sortIndicator('name')}</th>
          <th onClick={() => handleSort('src_zones')}>From{sortIndicator('src_zones')}</th>
          <th onClick={() => handleSort('dst_zones')}>To{sortIndicator('dst_zones')}</th>
          <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
          <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
          <th>Schedule</th>
          <th onClick={() => handleSort('services')}>Service{sortIndicator('services')}</th>
          <th onClick={() => handleSort('action')} style={{ width: 90 }}>Action{sortIndicator('action')}</th>
          <th style={{ width: 52 }}>NAT</th>
          <th>Security Profiles</th>
          <th style={{ width: 40 }}>Log</th>
          <th style={{ width: 36 }}></th>
        </tr>
      </thead>
      <tbody>
        {displayPolicies.map((policy) => {
          const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
          const realIndex = getRealIndex(policy);
          const fg = policy._fortigate || {};

          return (
            <tr
              key={`${policy.name}-${policy._rule_index}`}
              className={`${isSelected ? 'selected' : ''} ${policy.disabled ? 'disabled-rule fg-disabled-row' : ''} ${policy._implicit ? 'implicit-rule' : ''}`}
              onClick={() => onSelectRule(isSelected ? null : policy)}
              style={{ cursor: 'pointer' }}
            >
              <td>
                <div className="fg-seq">
                  {renderFortigateStatus(policy)}
                  <span className="fg-seq-id">{fg.policyid || policy._rule_index}</span>
                </div>
              </td>
              <td>
                {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
                {renderEditableCell(policy, 'name', (
                  <span className="fg-name">{policy.name}</span>
                ))}
              </td>
              <td>{renderEditableCell(policy, 'src_zones', renderCellValues(policy.src_zones))}</td>
              <td>{renderEditableCell(policy, 'dst_zones', renderCellValues(policy.dst_zones))}</td>
              <td>
                {renderEditableCell(policy, 'src_addresses', (
                  <>{policy.negate_source && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.src_addresses)}</>
                ))}
              </td>
              <td>
                {renderEditableCell(policy, 'dst_addresses', (
                  <>{policy.negate_destination && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.dst_addresses)}</>
                ))}
              </td>
              <td>
                <span className="fg-schedule">{fg.schedule || 'always'}</span>
              </td>
              <td>{renderEditableCell(policy, 'services', renderCellValues(policy.services))}</td>
              <td>{renderFortigateAction(policy)}</td>
              <td>{renderFortigateNat(policy)}</td>
              <td>{renderFortigateProfiles(policy)}</td>
              <td style={{ fontSize: '11px', color: 'var(--text-muted)', textAlign: 'center' }}>
                {policy.log_start && policy.log_end ? 'All' : policy.log_end ? 'UTM' : '-'}
              </td>
              <td>
                <button
                  className="btn-icon btn-icon-danger"
                  onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }}
                  title="Delete policy"
                >
                  x
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );

  /** Render Check Point SmartConsole-style table */
  const renderCheckpointTable = () => (
    <table className="policy-table cp-table">
      <thead>
        <tr>
          <th onClick={() => handleSort('_rule_index')} style={{ width: 44 }}>#{sortIndicator('_rule_index')}</th>
          <th onClick={() => handleSort('name')}>Name{sortIndicator('name')}</th>
          <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
          <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
          <th onClick={() => handleSort('services')}>Services &amp; Apps{sortIndicator('services')}</th>
          <th onClick={() => handleSort('action')} style={{ width: 80 }}>Action{sortIndicator('action')}</th>
          <th>Track</th>
          <th>Install On</th>
          <th style={{ width: 36 }}></th>
        </tr>
      </thead>
      <tbody>
        {displayPolicies.map((policy) => {
          const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
          const realIndex = getRealIndex(policy);
          const cp = policy._checkpoint || {};

          return (
            <tr
              key={`${policy.name}-${policy._rule_index}`}
              className={`${isSelected ? 'selected' : ''} ${policy.disabled ? 'disabled-rule' : ''} ${policy._implicit ? 'implicit-rule' : ''}`}
              onClick={() => onSelectRule(isSelected ? null : policy)}
              style={{ cursor: 'pointer' }}
            >
              <td>{cp.ruleNumber || policy._rule_index}</td>
              <td>
                {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
                {renderEditableCell(policy, 'name', policy.name)}
                {cp.section && <span className="cell-chip" style={{ background: 'var(--bg-alt)', fontSize: '9px' }}>{cp.section}</span>}
              </td>
              <td>
                {renderEditableCell(policy, 'src_addresses', (
                  <>{policy.negate_source && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.src_addresses)}</>
                ))}
              </td>
              <td>
                {renderEditableCell(policy, 'dst_addresses', (
                  <>{policy.negate_destination && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.dst_addresses)}</>
                ))}
              </td>
              <td>{renderEditableCell(policy, 'services', renderCellValues(policy.services))}</td>
              <td>
                <span className={`action-${policy.action === 'allow' ? 'permit' : 'deny'}`}>
                  {policy.action === 'allow' ? 'Accept' : 'Drop'}
                </span>
              </td>
              <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                {policy.log_end ? 'Log' : 'None'}
              </td>
              <td style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                {(cp.installOn || []).join(', ') || 'Policy Targets'}
              </td>
              <td>
                <button
                  className="btn-icon btn-icon-danger"
                  onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }}
                  title="Delete rule"
                >
                  x
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );

  /** Render SonicWall-style table (zone-pair, similar to SRX but with priority + DPI columns) */
  const renderSonicwallTable = () => (
    <table className="policy-table sw-table">
      <thead>
        <tr>
          <th onClick={() => handleSort('_rule_index')} style={{ width: 50 }}>Pri{sortIndicator('_rule_index')}</th>
          <th onClick={() => handleSort('name')}>Name{sortIndicator('name')}</th>
          <th onClick={() => handleSort('src_zones')}>From{sortIndicator('src_zones')}</th>
          <th onClick={() => handleSort('dst_zones')}>To{sortIndicator('dst_zones')}</th>
          <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
          <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
          <th onClick={() => handleSort('services')}>Service{sortIndicator('services')}</th>
          <th onClick={() => handleSort('action')} style={{ width: 80 }}>Action{sortIndicator('action')}</th>
          <th style={{ width: 40 }}>DPI</th>
          <th style={{ width: 40 }}>Log</th>
          <th style={{ width: 36 }}></th>
        </tr>
      </thead>
      <tbody>
        {displayPolicies.map((policy) => {
          const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
          const realIndex = getRealIndex(policy);
          const sw = policy._sonicwall || {};

          return (
            <tr
              key={`${policy.name}-${policy._rule_index}`}
              className={`${isSelected ? 'selected' : ''} ${policy.disabled ? 'disabled-rule' : ''} ${policy._implicit ? 'implicit-rule' : ''}`}
              onClick={() => onSelectRule(isSelected ? null : policy)}
              style={{ cursor: 'pointer' }}
            >
              <td>{sw.priority || policy._rule_index}</td>
              <td>
                {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
                {renderEditableCell(policy, 'name', policy.name)}
              </td>
              <td>{renderEditableCell(policy, 'src_zones', renderCellValues(policy.src_zones))}</td>
              <td>{renderEditableCell(policy, 'dst_zones', renderCellValues(policy.dst_zones))}</td>
              <td>{renderEditableCell(policy, 'src_addresses', renderCellValues(policy.src_addresses))}</td>
              <td>{renderEditableCell(policy, 'dst_addresses', renderCellValues(policy.dst_addresses))}</td>
              <td>{renderEditableCell(policy, 'services', renderCellValues(policy.services))}</td>
              <td>
                <span className={`action-${policy.action === 'allow' ? 'permit' : 'deny'}`}>
                  {policy.action === 'allow' ? 'Allow' : policy.action === 'deny' ? 'Deny' : policy.action}
                </span>
              </td>
              <td style={{ textAlign: 'center', fontSize: '11px' }}>
                {sw.dpi ? <span style={{ color: 'var(--accent)' }}>On</span> : <span style={{ opacity: 0.4 }}>-</span>}
              </td>
              <td style={{ textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)' }}>
                {policy.log_end ? 'Yes' : '-'}
              </td>
              <td>
                <button
                  className="btn-icon btn-icon-danger"
                  onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }}
                  title="Delete rule"
                >
                  x
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );

  /** Render Huawei USG-style table (zone-pair, named rules, profiles) */
  const renderHuaweiTable = () => (
    <table className="policy-table hw-table">
      <thead>
        <tr>
          <th onClick={() => handleSort('_rule_index')} style={{ width: 44 }}>#{sortIndicator('_rule_index')}</th>
          <th onClick={() => handleSort('name')}>Rule Name{sortIndicator('name')}</th>
          <th onClick={() => handleSort('src_zones')}>Src Zone{sortIndicator('src_zones')}</th>
          <th onClick={() => handleSort('dst_zones')}>Dst Zone{sortIndicator('dst_zones')}</th>
          <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
          <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
          <th onClick={() => handleSort('services')}>Service{sortIndicator('services')}</th>
          <th>Profiles</th>
          <th onClick={() => handleSort('action')} style={{ width: 80 }}>Action{sortIndicator('action')}</th>
          <th style={{ width: 40 }}>Log</th>
          <th style={{ width: 36 }}></th>
        </tr>
      </thead>
      <tbody>
        {displayPolicies.map((policy) => {
          const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
          const realIndex = getRealIndex(policy);

          return (
            <tr
              key={`${policy.name}-${policy._rule_index}`}
              className={`${isSelected ? 'selected' : ''} ${policy.disabled ? 'disabled-rule' : ''} ${policy._implicit ? 'implicit-rule' : ''}`}
              onClick={() => onSelectRule(isSelected ? null : policy)}
              style={{ cursor: 'pointer' }}
            >
              <td>{policy._rule_index}</td>
              <td>
                {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
                {renderEditableCell(policy, 'name', policy.name)}
              </td>
              <td>{renderEditableCell(policy, 'src_zones', renderCellValues(policy.src_zones))}</td>
              <td>{renderEditableCell(policy, 'dst_zones', renderCellValues(policy.dst_zones))}</td>
              <td>{renderEditableCell(policy, 'src_addresses', renderCellValues(policy.src_addresses))}</td>
              <td>{renderEditableCell(policy, 'dst_addresses', renderCellValues(policy.dst_addresses))}</td>
              <td>{renderEditableCell(policy, 'services', renderCellValues(policy.services))}</td>
              <td>{renderProfileCell(policy)}</td>
              <td>
                <span className={`action-${policy.action === 'allow' ? 'permit' : 'deny'}`}>
                  {policy.action === 'allow' ? 'Permit' : 'Deny'}
                </span>
              </td>
              <td style={{ textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)' }}>
                {policy.log_end ? 'Yes' : '-'}
              </td>
              <td>
                <button
                  className="btn-icon btn-icon-danger"
                  onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }}
                  title="Delete rule"
                >
                  x
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );

  /** Cisco ASDM/FMC action display */
  const renderCiscoAction = (policy) => {
    const cisco = policy._cisco || {};
    const isPermit = policy.action === 'allow';
    const label = isPermit ? 'Permit' : 'Deny';
    const cls = isPermit ? 'cisco-permit' : 'cisco-deny';
    const icon = isPermit ? '\u2713' : '\u2715';
    return (
      <div className={`cisco-action ${cls}`}>
        <span className="cisco-action-icon">{icon}</span>
        <span className="cisco-action-text">{label}</span>
      </div>
    );
  };

  /** Cisco protocol display */
  const renderCiscoProtocol = (policy) => {
    const cisco = policy._cisco || {};
    const proto = cisco.protocol || 'ip';
    return <span className="cisco-protocol">{proto.toUpperCase()}</span>;
  };

  /** Cisco security level badge */
  const renderCiscoSecLevel = (policy) => {
    const cisco = policy._cisco || {};
    const level = cisco.securityLevel;
    if (level === undefined || level === null) return null;
    const cls = level >= 80 ? 'cisco-sec-high' : level >= 40 ? 'cisco-sec-med' : 'cisco-sec-low';
    return <span className={`cisco-sec-badge ${cls}`} title={`Security Level ${level}`}>L{level}</span>;
  };

  /** Cisco port/service display */
  const renderCiscoService = (policy) => {
    const cisco = policy._cisco || {};
    const svcs = policy.services || [];
    if (svcs.length === 0) return <span style={{ opacity: 0.5 }}>any</span>;
    return svcs.map((s, i) => (
      <span key={i} className="cisco-svc-chip">{s}</span>
    ));
  };

  /** Cisco log level display */
  const renderCiscoLog = (policy) => {
    const cisco = policy._cisco || {};
    if (!policy.log_end && !policy.log_start) return <span className="cisco-log-off">-</span>;
    return (
      <span className="cisco-log-on" title={cisco.logLevel ? `Level: ${cisco.logLevel}` : 'Logging enabled'}>
        {cisco.logLevel || 'Yes'}
      </span>
    );
  };

  /** Cisco hit count placeholder */
  const renderCiscoHitCount = (policy) => {
    return <span className="cisco-hitcount">-</span>;
  };

  /** Render the Cisco ASDM-style table */
  const renderCiscoTable = () => (
    <table className="policy-table cisco-table">
      <thead>
        <tr>
          <th onClick={() => handleSort('_rule_index')} style={{ width: 50 }}>#ACE{sortIndicator('_rule_index')}</th>
          <th onClick={() => handleSort('action')} style={{ width: 80 }}>Action{sortIndicator('action')}</th>
          <th onClick={() => handleSort('name')}>Name / Remark{sortIndicator('name')}</th>
          <th>Protocol</th>
          <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
          <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
          <th>Service / Port</th>
          <th style={{ width: 52 }}>Log</th>
          <th style={{ width: 50 }}>Hits</th>
          <th style={{ width: 36 }}></th>
        </tr>
      </thead>
      <tbody>
        {displayPolicies.map((policy) => {
          const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
          const realIndex = getRealIndex(policy);
          const cisco = policy._cisco || {};

          return (
            <tr
              key={`${policy.name}-${policy._rule_index}`}
              className={`${isSelected ? 'selected' : ''} ${policy.disabled ? 'disabled-rule cisco-inactive-row' : ''} ${policy._implicit ? 'implicit-rule' : ''}`}
              onClick={() => onSelectRule(isSelected ? null : policy)}
              style={{ cursor: 'pointer' }}
            >
              <td>
                <div className="cisco-ace-num">
                  {policy._rule_index}
                  {policy.disabled && <span className="cisco-inactive-badge">X</span>}
                </div>
              </td>
              <td>{renderCiscoAction(policy)}</td>
              <td>
                <div className="cisco-name-cell">
                  {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
                  {renderEditableCell(policy, 'name', (
                    <span className="cisco-rule-name">{policy.name}</span>
                  ))}
                  {cisco.aclName && (
                    <span className="cisco-acl-badge" title={`ACL: ${cisco.aclName}`}>{cisco.aclName}</span>
                  )}
                  {renderCiscoSecLevel(policy)}
                </div>
              </td>
              <td>{renderCiscoProtocol(policy)}</td>
              <td>
                {renderEditableCell(policy, 'src_addresses', (
                  <div className="cisco-addr-cell">
                    {(policy.src_zones || []).length > 0 && (
                      <span className="cisco-iface-label" title={`Interface: ${policy.src_zones.join(', ')}`}>
                        {policy.src_zones.join(', ')}
                      </span>
                    )}
                    {policy.negate_source && <span className="cell-chip negate-chip">NOT</span>}
                    {renderCellValues(policy.src_addresses)}
                  </div>
                ))}
              </td>
              <td>
                {renderEditableCell(policy, 'dst_addresses', (
                  <div className="cisco-addr-cell">
                    {(policy.dst_zones || []).length > 0 && (
                      <span className="cisco-iface-label" title={`Interface: ${policy.dst_zones.join(', ')}`}>
                        {policy.dst_zones.join(', ')}
                      </span>
                    )}
                    {policy.negate_destination && <span className="cell-chip negate-chip">NOT</span>}
                    {renderCellValues(policy.dst_addresses)}
                  </div>
                ))}
              </td>
              <td>{renderEditableCell(policy, 'services', renderCiscoService(policy))}</td>
              <td style={{ textAlign: 'center' }}>{renderCiscoLog(policy)}</td>
              <td style={{ textAlign: 'center' }}>{renderCiscoHitCount(policy)}</td>
              <td>
                <button
                  className="btn-icon btn-icon-danger"
                  onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }}
                  title="Delete ACE"
                >
                  x
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
      {/* Filter bar */}
      <div className="filter-toolbar">
        <input
          className="filter-input"
          type="text"
          placeholder={isCisco ? 'Filter ACEs...' : (isFortigate || isSrx || isSonicwall || isHuawei) ? 'Filter policies...' : isCheckpoint ? 'Filter rules...' : 'Filter rules...'}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        {platformView === 'srx' && (
          <select
            className="status-filter-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">All Status</option>
            <option value="unreviewed">Unreviewed</option>
            <option value="llm-reviewed">LLM Reviewed</option>
            <option value="accepted">Accepted</option>
            <option value="disabled">Disabled</option>
          </select>
        )}
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          {displayPolicies.length} of {policies.length}
        </span>
        <button className="btn btn-secondary btn-sm" onClick={onAddRule}>
          {isCisco ? '+ Add ACE' : (isSrx || isFortigate || isSonicwall || isHuawei) ? '+ Add Policy' : '+ Add Rule'}
        </button>
      </div>

      {/* Table */}
      <div className="policy-table-container">
        {isCisco ? renderCiscoTable() : isCheckpoint ? renderCheckpointTable() : isSonicwall ? renderSonicwallTable() : isHuawei ? renderHuaweiTable() : isFortigate ? renderFortigateTable() : isSrx ? renderSrxTable() : renderPanosTable()}

        {displayPolicies.length === 0 && (
          <div className="empty-state">
            <p>{isCisco ? 'No access control entries match your filter.' : (isSrx || isFortigate || isSonicwall || isHuawei) ? 'No security policies match your filter.' : 'No security rules match your filter.'}</p>
          </div>
        )}
      </div>
    </div>
  );
}

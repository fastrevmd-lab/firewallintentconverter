/**
 * PolicyTable Component
 *
 * Sortable, filterable, editable security rules table.
 * Supports inline cell editing (double-click), add/delete rows.
 * Shows review status labels (Disabled/Unreviewed/LLM Reviewed/Accepted).
 */
import React, { useState, useMemo } from 'react';

export default function PolicyTable({
  policies,
  warnings,
  selectedRule,
  onSelectRule,
  onUpdateRule,
  onDeleteRule,
  onAddRule,
}) {
  const [sortField, setSortField] = useState('_rule_index');
  const [sortDir, setSortDir] = useState('asc');
  const [filter, setFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [editingCell, setEditingCell] = useState(null); // { index, field }
  const [editValue, setEditValue] = useState('');

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

  /** Render security profiles for a policy row */
  const renderProfileCell = (policy) => {
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
      {/* Filter bar */}
      <div className="filter-toolbar">
        <input
          className="filter-input"
          type="text"
          placeholder="Filter rules..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
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
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          {displayPolicies.length} of {policies.length}
        </span>
        <button className="btn btn-secondary btn-sm" onClick={onAddRule}>+ Add Rule</button>
      </div>

      {/* Table */}
      <div className="policy-table-container">
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
              <th>Status</th>
              <th style={{ width: 36 }}></th>
            </tr>
          </thead>
          <tbody>
            {displayPolicies.map((policy) => {
              const status = getRuleStatus(policy);
              const warnStatus = getWarningStatus(policy);
              const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
              const realIndex = getRealIndex(policy);

              return (
                <tr
                  key={`${policy.name}-${policy._rule_index}`}
                  className={`${isSelected ? 'selected' : ''} ${policy.disabled ? 'disabled-rule' : ''}`}
                  onClick={() => onSelectRule(isSelected ? null : policy)}
                  style={{ cursor: 'pointer' }}
                >
                  <td>{policy._rule_index}</td>
                  <td title={policy.name}>
                    {renderEditableCell(policy, 'name', policy.name)}
                  </td>
                  <td>{renderEditableCell(policy, 'src_zones', renderCellValues(policy.src_zones))}</td>
                  <td>{renderEditableCell(policy, 'dst_zones', renderCellValues(policy.dst_zones))}</td>
                  <td>{renderEditableCell(policy, 'src_addresses', renderCellValues(policy.src_addresses))}</td>
                  <td>{renderEditableCell(policy, 'dst_addresses', renderCellValues(policy.dst_addresses))}</td>
                  <td>{renderEditableCell(policy, 'applications', renderCellValues([...policy.applications, ...policy.services.filter(s => s !== 'application-default')]))}</td>
                  <td>{renderProfileCell(policy)}</td>
                  <td>
                    <span className={`action-${policy.action === 'allow' ? 'permit' : 'deny'}`}>
                      {policy.action}
                    </span>
                  </td>
                  <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {policy.log_start && 'S'}
                    {policy.log_end && 'E'}
                  </td>
                  <td>
                    <span className={`status-label status-${status}`}>
                      {statusLabels[status]}
                    </span>
                    {warnStatus !== 'clean' && (
                      <span className={`status-dot ${warnStatus}`} title={warnStatus} style={{ marginLeft: 4 }} />
                    )}
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

        {displayPolicies.length === 0 && (
          <div className="empty-state">
            <p>No security rules match your filter.</p>
          </div>
        )}
      </div>
    </div>
  );
}

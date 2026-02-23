/**
 * ObjectEditor Component
 *
 * Tabbed editor for the "Objects" tab in the center panel.
 * Three sub-tabs:
 *   1. Address Objects — name, type, value, description
 *   2. Address Groups — name, members, description
 *   3. Service Objects — name, protocol, port_range, description
 *
 * All editable inline with add/delete support.
 */
import React, { useState } from 'react';
import { ChipEditor } from './ZoneEditor.jsx';
import { mapAppToJunos } from '../../src/parsers/parser-utils.js';

export default function ObjectEditor({ intermediateConfig, onConfigUpdate, viewMode }) {
  const [subTab, setSubTab] = useState('addresses');
  const isSrx = viewMode === 'srx';

  const addresses = intermediateConfig?.address_objects || [];
  const groups = intermediateConfig?.address_groups || [];
  const services = intermediateConfig?.service_objects || [];
  const customApps = intermediateConfig?.applications || [];
  const appGroups = intermediateConfig?.application_groups || [];
  const secProfiles = intermediateConfig?.security_profile_objects || [];
  const schedules = intermediateConfig?.schedules || [];
  const policies = intermediateConfig?.security_policies || [];

  // Count unique apps: referenced in policies + custom definitions not already referenced + app groups
  const referencedAppNames = new Set();
  for (const p of policies) {
    for (const a of (p.applications || [])) {
      if (a !== 'any') referencedAppNames.add(a);
    }
  }
  const appCount = referencedAppNames.size
    + customApps.filter(a => !referencedAppNames.has(a.name)).length
    + appGroups.filter(g => !referencedAppNames.has(g.name)).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Sub-tab bar */}
      <div className="sub-tab-bar">
        <button
          className={`sub-tab-btn ${subTab === 'addresses' ? 'active' : ''}`}
          onClick={() => setSubTab('addresses')}
        >
          {isSrx ? 'Addresses (Global)' : 'Addresses'} ({addresses.length})
        </button>
        <button
          className={`sub-tab-btn ${subTab === 'groups' ? 'active' : ''}`}
          onClick={() => setSubTab('groups')}
        >
          {isSrx ? 'Address Sets' : 'Groups'} ({groups.length})
        </button>
        <button
          className={`sub-tab-btn ${subTab === 'services' ? 'active' : ''}`}
          onClick={() => setSubTab('services')}
        >
          Services ({services.length})
        </button>
        <button
          className={`sub-tab-btn ${subTab === 'applications' ? 'active' : ''}`}
          onClick={() => setSubTab('applications')}
        >
          Applications ({appCount})
        </button>
        <button
          className={`sub-tab-btn ${subTab === 'profiles' ? 'active' : ''}`}
          onClick={() => setSubTab('profiles')}
        >
          {isSrx ? 'UTM / IDP Policies' : 'Security Profiles'} ({secProfiles.length})
        </button>
        <button
          className={`sub-tab-btn ${subTab === 'schedules' ? 'active' : ''}`}
          onClick={() => setSubTab('schedules')}
        >
          {isSrx ? 'Schedulers' : 'Schedules'} ({schedules.length})
        </button>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        {subTab === 'addresses' && (
          <AddressObjectTable
            items={addresses}
            onUpdate={(items) => onConfigUpdate('address_objects', items)}
          />
        )}
        {subTab === 'groups' && (
          <AddressGroupTable
            items={groups}
            onUpdate={(items) => onConfigUpdate('address_groups', items)}
          />
        )}
        {subTab === 'services' && (
          <ServiceObjectTable
            items={services}
            onUpdate={(items) => onConfigUpdate('service_objects', items)}
          />
        )}
        {subTab === 'applications' && (
          <ApplicationTable
            policies={policies}
            customApps={customApps}
            appGroups={appGroups}
            onUpdate={(items) => onConfigUpdate('applications', items)}
            onGroupsUpdate={(items) => onConfigUpdate('application_groups', items)}
            isSrx={isSrx}
          />
        )}
        {subTab === 'profiles' && (
          <SecurityProfileTable
            items={secProfiles}
            onUpdate={(items) => onConfigUpdate('security_profile_objects', items)}
          />
        )}
        {subTab === 'schedules' && (
          <ScheduleTable
            items={schedules}
            policies={policies}
            onUpdate={(items) => onConfigUpdate('schedules', items)}
            isSrx={isSrx}
          />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Address Objects Table
// ---------------------------------------------------------------------------

function AddressObjectTable({ items, onUpdate }) {
  const handleChange = (index, field, value) => {
    const updated = items.map((item, i) =>
      i === index ? { ...item, [field]: value } : item
    );
    onUpdate(updated);
  };

  const handleAdd = () => {
    onUpdate([...items, {
      name: `addr-${items.length + 1}`,
      type: 'host',
      value: '',
      description: '',
      tags: [],
    }]);
  };

  const handleDelete = (index) => {
    onUpdate(items.filter((_, i) => i !== index));
  };

  return (
    <div>
      <table className="editor-table">
        <thead>
          <tr>
            <th style={{ width: 180 }}>Name</th>
            <th style={{ width: 90 }}>Type</th>
            <th>Value</th>
            <th style={{ width: 180 }}>Description</th>
            <th style={{ width: 36 }}></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, i) => (
            <tr key={i}>
              <td>
                <input
                  className="cell-input"
                  value={item.name}
                  onChange={(e) => handleChange(i, 'name', e.target.value)}
                />
              </td>
              <td>
                <select
                  className="cell-select"
                  value={item.type}
                  onChange={(e) => handleChange(i, 'type', e.target.value)}
                >
                  <option value="host">Host</option>
                  <option value="subnet">Subnet</option>
                  <option value="range">Range</option>
                  <option value="fqdn">FQDN</option>
                </select>
              </td>
              <td>
                <input
                  className="cell-input"
                  value={item.value}
                  onChange={(e) => handleChange(i, 'value', e.target.value)}
                  placeholder={item.type === 'host' ? '10.0.0.1/32' : item.type === 'subnet' ? '10.0.0.0/24' : item.type === 'fqdn' ? 'example.com' : '10.0.0.1-10.0.0.254'}
                />
              </td>
              <td>
                <input
                  className="cell-input"
                  value={item.description || ''}
                  onChange={(e) => handleChange(i, 'description', e.target.value)}
                  placeholder="Description"
                />
              </td>
              <td>
                <button className="btn-icon btn-icon-danger" onClick={() => handleDelete(i)} title="Delete">x</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ padding: '8px 12px' }}>
        <button className="btn btn-secondary btn-sm" onClick={handleAdd}>+ Add Address</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Address Groups Table
// ---------------------------------------------------------------------------

function AddressGroupTable({ items, onUpdate }) {
  const handleChange = (index, field, value) => {
    const updated = items.map((item, i) =>
      i === index ? { ...item, [field]: value } : item
    );
    onUpdate(updated);
  };

  const handleAddMember = (index, member) => {
    const item = items[index];
    if (item.members.includes(member)) return;
    handleChange(index, 'members', [...item.members, member]);
  };

  const handleRemoveMember = (index, member) => {
    const item = items[index];
    handleChange(index, 'members', item.members.filter(m => m !== member));
  };

  const handleAdd = () => {
    onUpdate([...items, {
      name: `group-${items.length + 1}`,
      members: [],
      description: '',
      tags: [],
    }]);
  };

  const handleDelete = (index) => {
    onUpdate(items.filter((_, i) => i !== index));
  };

  return (
    <div>
      <table className="editor-table">
        <thead>
          <tr>
            <th style={{ width: 180 }}>Name</th>
            <th>Members</th>
            <th style={{ width: 180 }}>Description</th>
            <th style={{ width: 36 }}></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, i) => (
            <tr key={i}>
              <td>
                <input
                  className="cell-input"
                  value={item.name}
                  onChange={(e) => handleChange(i, 'name', e.target.value)}
                />
              </td>
              <td>
                <ChipEditor
                  values={item.members}
                  onAdd={(val) => handleAddMember(i, val)}
                  onRemove={(val) => handleRemoveMember(i, val)}
                  placeholder="Add member..."
                />
              </td>
              <td>
                <input
                  className="cell-input"
                  value={item.description || ''}
                  onChange={(e) => handleChange(i, 'description', e.target.value)}
                />
              </td>
              <td>
                <button className="btn-icon btn-icon-danger" onClick={() => handleDelete(i)} title="Delete">x</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ padding: '8px 12px' }}>
        <button className="btn btn-secondary btn-sm" onClick={handleAdd}>+ Add Group</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Service Objects Table
// ---------------------------------------------------------------------------

function ServiceObjectTable({ items, onUpdate }) {
  const handleChange = (index, field, value) => {
    const updated = items.map((item, i) =>
      i === index ? { ...item, [field]: value } : item
    );
    onUpdate(updated);
  };

  const handleAdd = () => {
    onUpdate([...items, {
      name: `svc-${items.length + 1}`,
      protocol: 'tcp',
      port_range: '',
      source_port: '',
      description: '',
    }]);
  };

  const handleDelete = (index) => {
    onUpdate(items.filter((_, i) => i !== index));
  };

  return (
    <div>
      <table className="editor-table">
        <thead>
          <tr>
            <th style={{ width: 160 }}>Name</th>
            <th style={{ width: 80 }}>Protocol</th>
            <th style={{ width: 120 }}>Port(s)</th>
            <th style={{ width: 120 }}>Source Port</th>
            <th>Description</th>
            <th style={{ width: 36 }}></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, i) => (
            <tr key={i}>
              <td>
                <input className="cell-input" value={item.name} onChange={(e) => handleChange(i, 'name', e.target.value)} />
              </td>
              <td>
                <select className="cell-select" value={item.protocol} onChange={(e) => handleChange(i, 'protocol', e.target.value)}>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="sctp">SCTP</option>
                </select>
              </td>
              <td>
                <input className="cell-input" value={item.port_range} onChange={(e) => handleChange(i, 'port_range', e.target.value)} placeholder="80 or 1024-65535" />
              </td>
              <td>
                <input className="cell-input" value={item.source_port || ''} onChange={(e) => handleChange(i, 'source_port', e.target.value)} placeholder="Optional" />
              </td>
              <td>
                <input className="cell-input" value={item.description || ''} onChange={(e) => handleChange(i, 'description', e.target.value)} />
              </td>
              <td>
                <button className="btn-icon btn-icon-danger" onClick={() => handleDelete(i)} title="Delete">x</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ padding: '8px 12px' }}>
        <button className="btn btn-secondary btn-sm" onClick={handleAdd}>+ Add Service</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Security Profile Objects Table
// ---------------------------------------------------------------------------

const PROFILE_TYPE_OPTIONS = [
  { value: 'virus', label: 'Antivirus' },
  { value: 'spyware', label: 'Anti-Spyware' },
  { value: 'vulnerability', label: 'Vulnerability' },
  { value: 'url-filtering', label: 'URL Filtering' },
  { value: 'file-blocking', label: 'File Blocking' },
  { value: 'wildfire-analysis', label: 'WildFire' },
];

const PROFILE_FEATURE_MAP = {
  'virus':              { srxFeature: 'utm', srxType: 'anti-virus',        label: 'Antivirus' },
  'wildfire-analysis':  { srxFeature: 'utm', srxType: 'anti-virus',        label: 'WildFire' },
  'url-filtering':      { srxFeature: 'utm', srxType: 'web-filtering',     label: 'URL Filtering' },
  'file-blocking':      { srxFeature: 'utm', srxType: 'content-filtering', label: 'File Blocking' },
  'spyware':            { srxFeature: 'idp', srxType: 'idp-policy',        label: 'Anti-Spyware' },
  'vulnerability':      { srxFeature: 'idp', srxType: 'idp-policy',        label: 'Vulnerability' },
};

function SecurityProfileTable({ items, onUpdate }) {
  const handleChange = (index, field, value) => {
    const updated = items.map((item, i) => {
      if (i !== index) return item;
      const newItem = { ...item, [field]: value };
      // Auto-update SRX mapping when profile_type changes
      if (field === 'profile_type') {
        const info = PROFILE_FEATURE_MAP[value];
        if (info) {
          newItem.srx_feature = info.srxFeature;
          newItem.srx_type = info.srxType;
          newItem.profile_type_label = info.label;
        }
      }
      return newItem;
    });
    onUpdate(updated);
  };

  const handleAdd = () => {
    onUpdate([...items, {
      name: `profile-${items.length + 1}`,
      profile_type: 'virus',
      profile_type_label: 'Antivirus',
      profile_name: 'default',
      srx_feature: 'utm',
      srx_type: 'anti-virus',
      source: 'manual',
      attached_rules: [],
    }]);
  };

  const handleDelete = (index) => {
    onUpdate(items.filter((_, i) => i !== index));
  };

  return (
    <div>
      <table className="editor-table">
        <thead>
          <tr>
            <th style={{ width: 160 }}>Name</th>
            <th style={{ width: 130 }}>Type</th>
            <th style={{ width: 140 }}>Profile Name</th>
            <th style={{ width: 60 }}>SRX</th>
            <th style={{ width: 120 }}>SRX Type</th>
            <th style={{ width: 80 }}>Source</th>
            <th>Attached Rules</th>
            <th style={{ width: 36 }}></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, i) => (
            <tr key={i}>
              <td>
                <input
                  className="cell-input"
                  value={item.name}
                  onChange={(e) => handleChange(i, 'name', e.target.value)}
                />
              </td>
              <td>
                <select
                  className="cell-select"
                  value={item.profile_type}
                  onChange={(e) => handleChange(i, 'profile_type', e.target.value)}
                >
                  {PROFILE_TYPE_OPTIONS.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </td>
              <td>
                <input
                  className="cell-input"
                  value={item.profile_name}
                  onChange={(e) => handleChange(i, 'profile_name', e.target.value)}
                  placeholder="default"
                />
              </td>
              <td>
                <span className={`cell-chip ${item.srx_feature === 'utm' ? 'profile-chip-utm' : 'profile-chip-idp'}`}>
                  {item.srx_feature.toUpperCase()}
                </span>
              </td>
              <td style={{ fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                {item.srx_type}
              </td>
              <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {item.source === 'individual' ? 'rule' : item.source?.startsWith('group:') ? 'group' : item.source}
              </td>
              <td>
                {(item.attached_rules || []).map((r, j) => (
                  <span key={j} className="cell-chip" style={{ fontSize: 10 }}>{r}</span>
                ))}
              </td>
              <td>
                <button className="btn-icon btn-icon-danger" onClick={() => handleDelete(i)} title="Delete">x</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ padding: '8px 12px' }}>
        <button className="btn btn-secondary btn-sm" onClick={handleAdd}>+ Add Profile</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Applications Table
// ---------------------------------------------------------------------------

function ApplicationTable({ policies, customApps, appGroups = [], onUpdate, onGroupsUpdate, isSrx }) {
  const [expandedGroups, setExpandedGroups] = useState({});

  // Build map of appName → [policyNames] from all policies
  const appUsage = {};
  for (const p of policies) {
    for (const a of (p.applications || [])) {
      if (a === 'any') continue;
      if (!appUsage[a]) appUsage[a] = [];
      appUsage[a].push(p.name);
    }
  }

  // Build app group lookup
  const appGroupMap = {};
  for (const g of appGroups) {
    appGroupMap[g.name] = g;
  }

  // Build unified rows: referenced apps + custom definitions
  const customAppMap = {};
  for (const ca of customApps) {
    customAppMap[ca.name] = ca;
  }

  const rows = [];
  // First: application groups (from parser)
  for (const group of appGroups) {
    rows.push({
      name: group.name,
      type: 'group',
      members: group.members,
      protocol: '',
      port: '',
      description: group.description || '',
      usedBy: appUsage[group.name] || [],
      isCustom: false,
      isGroup: true,
    });
  }
  // Then: all referenced apps from policies (skip group names already shown)
  for (const [name, policyNames] of Object.entries(appUsage)) {
    if (appGroupMap[name]) continue; // already shown as group row
    const custom = customAppMap[name];
    rows.push({
      name,
      type: custom ? 'custom' : 'referenced',
      protocol: custom?.protocol || '',
      port: custom?.port_range || custom?.port || '',
      description: custom?.description || '',
      usedBy: policyNames,
      isCustom: !!custom,
      isGroup: false,
    });
  }
  // Then: custom apps not referenced by any policy
  for (const ca of customApps) {
    if (!appUsage[ca.name]) {
      rows.push({
        name: ca.name,
        type: 'custom',
        protocol: ca.protocol || '',
        port: ca.port_range || ca.port || '',
        description: ca.description || '',
        usedBy: [],
        isCustom: true,
        isGroup: false,
      });
    }
  }

  const handleCustomChange = (appName, field, value) => {
    const existing = customApps.find(a => a.name === appName);
    if (existing) {
      onUpdate(customApps.map(a => a.name === appName ? { ...a, [field]: value } : a));
    } else {
      onUpdate([...customApps, { name: appName, protocol: 'tcp', port: '', description: '', [field]: value }]);
    }
  };

  const handleAdd = () => {
    onUpdate([...customApps, {
      name: `app-${customApps.length + 1}`,
      protocol: 'tcp',
      port: '',
      description: '',
    }]);
  };

  const handleDelete = (appName) => {
    onUpdate(customApps.filter(a => a.name !== appName));
  };

  const toggleGroup = (name) => {
    setExpandedGroups(prev => ({ ...prev, [name]: !prev[name] }));
  };

  // Helper: get SRX mapping display for a single app name
  const getSrxMapping = (appName) => {
    const junos = mapAppToJunos(appName);
    if (junos) return { mapped: true, value: junos };
    return { mapped: false, value: `custom:app:'${appName}'` };
  };

  const colCount = isSrx ? 8 : 7;

  // Type badge styling
  const typeBadge = (type) => {
    const styles = {
      group: { bg: 'rgba(100,149,237,0.15)', color: '#6495ED' },
      custom: { bg: 'rgba(74,208,200,0.15)', color: 'var(--accent)' },
      referenced: { bg: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)' },
    };
    const labels = { group: 'App Group', custom: 'Custom', referenced: 'Referenced' };
    const s = styles[type] || styles.referenced;
    return (
      <span className="cell-chip" style={{ fontSize: 10, background: s.bg, color: s.color }}>
        {labels[type] || type}
      </span>
    );
  };

  return (
    <div>
      <table className="editor-table">
        <thead>
          <tr>
            <th style={{ width: 180 }}>Name</th>
            <th style={{ width: 90 }}>Type</th>
            {isSrx && <th style={{ width: 180 }}>SRX Mapping</th>}
            <th style={{ width: 70 }}>Protocol</th>
            <th style={{ width: 120 }}>Port(s)</th>
            <th style={{ width: 160 }}>Description</th>
            <th>Used By</th>
            <th style={{ width: 36 }}></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <React.Fragment key={row.name + i}>
              <tr>
                <td>
                  {row.isGroup ? (
                    <span
                      style={{ fontFamily: 'var(--font-mono)', fontSize: 12, cursor: 'pointer' }}
                      onClick={() => toggleGroup(row.name)}
                      title={`${row.members.length} member(s) — click to ${expandedGroups[row.name] ? 'collapse' : 'expand'}`}
                    >
                      {expandedGroups[row.name] ? '▾' : '▸'} {row.name}
                    </span>
                  ) : row.isCustom ? (
                    <input
                      className="cell-input"
                      value={row.name}
                      onChange={(e) => {
                        const oldName = row.name;
                        const newName = e.target.value;
                        onUpdate(customApps.map(a => a.name === oldName ? { ...a, name: newName } : a));
                      }}
                    />
                  ) : (
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{row.name}</span>
                  )}
                </td>
                <td>{typeBadge(row.type)}</td>
                {isSrx && (
                  <td>
                    {row.isGroup ? (
                      <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                        {row.members.length} member(s)
                      </span>
                    ) : (() => {
                      const mapping = getSrxMapping(row.name);
                      return (
                        <span
                          className="cell-chip"
                          style={{
                            fontSize: 10,
                            background: mapping.mapped ? 'rgba(74,208,200,0.12)' : 'rgba(255,165,0,0.12)',
                            color: mapping.mapped ? 'var(--accent)' : '#FFA500',
                            maxWidth: 170,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            display: 'inline-block',
                          }}
                          title={mapping.value}
                        >
                          {mapping.value}
                        </span>
                      );
                    })()}
                  </td>
                )}
                <td>
                  {row.isCustom ? (
                    <select
                      className="cell-select"
                      value={row.protocol}
                      onChange={(e) => handleCustomChange(row.name, 'protocol', e.target.value)}
                    >
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                      <option value="icmp">ICMP</option>
                    </select>
                  ) : (
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>--</span>
                  )}
                </td>
                <td>
                  {row.isCustom ? (
                    <input
                      className="cell-input"
                      value={row.port}
                      onChange={(e) => handleCustomChange(row.name, 'port', e.target.value)}
                      placeholder="80 or 443"
                    />
                  ) : (
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>--</span>
                  )}
                </td>
                <td>
                  {row.isCustom ? (
                    <input
                      className="cell-input"
                      value={row.description}
                      onChange={(e) => handleCustomChange(row.name, 'description', e.target.value)}
                      placeholder="Description"
                    />
                  ) : (
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {row.isGroup ? `${row.members.length} apps` : ''}
                    </span>
                  )}
                </td>
                <td>
                  {row.usedBy.length > 0 ? (
                    row.usedBy.map((r, j) => (
                      <span key={j} className="cell-chip" style={{ fontSize: 10 }}>{r}</span>
                    ))
                  ) : (
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>unused</span>
                  )}
                </td>
                <td>
                  {row.isCustom && (
                    <button className="btn-icon btn-icon-danger" onClick={() => handleDelete(row.name)} title="Delete">x</button>
                  )}
                </td>
              </tr>
              {/* Expanded group members */}
              {row.isGroup && expandedGroups[row.name] && row.members.map((member, mi) => {
                const mapping = isSrx ? getSrxMapping(member) : null;
                return (
                  <tr key={`${row.name}-member-${mi}`} style={{ background: 'rgba(100,149,237,0.04)' }}>
                    <td style={{ paddingLeft: 28 }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)' }}>
                        ↳ {member}
                      </span>
                    </td>
                    <td>
                      <span className="cell-chip" style={{ fontSize: 9, background: 'rgba(255,255,255,0.04)', color: 'var(--text-muted)' }}>
                        Member
                      </span>
                    </td>
                    {isSrx && (
                      <td>
                        <span
                          className="cell-chip"
                          style={{
                            fontSize: 10,
                            background: mapping.mapped ? 'rgba(74,208,200,0.12)' : 'rgba(255,165,0,0.12)',
                            color: mapping.mapped ? 'var(--accent)' : '#FFA500',
                            maxWidth: 170,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            display: 'inline-block',
                          }}
                          title={mapping.value}
                        >
                          {mapping.value}
                        </span>
                      </td>
                    )}
                    <td><span style={{ fontSize: 11, color: 'var(--text-muted)' }}>--</span></td>
                    <td><span style={{ fontSize: 11, color: 'var(--text-muted)' }}>--</span></td>
                    <td></td>
                    <td></td>
                    <td></td>
                  </tr>
                );
              })}
            </React.Fragment>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={colCount} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 20, fontSize: 12 }}>
                No applications referenced in policies
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <div style={{ padding: '8px 12px' }}>
        <button className="btn btn-secondary btn-sm" onClick={handleAdd}>+ Add Custom Application</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Schedules Table
// ---------------------------------------------------------------------------

const DAY_OPTIONS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

function ScheduleTable({ items, policies, onUpdate, isSrx }) {
  const handleChange = (index, field, value) => {
    const updated = items.map((item, i) =>
      i === index ? { ...item, [field]: value } : item
    );
    onUpdate(updated);
  };

  const handleAdd = () => {
    onUpdate([...items, {
      name: `schedule-${items.length + 1}`,
      type: 'recurring',
      days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
      start: '08:00',
      end: '17:00',
    }]);
  };

  const handleDelete = (index) => {
    onUpdate(items.filter((_, i) => i !== index));
  };

  // Build map of schedule name → attached rule names
  const attachedRules = {};
  for (const p of policies) {
    if (p.schedule) {
      if (!attachedRules[p.schedule]) attachedRules[p.schedule] = [];
      attachedRules[p.schedule].push(p.name);
    }
  }

  return (
    <div>
      <table className="editor-table">
        <thead>
          <tr>
            <th style={{ width: 160 }}>Name</th>
            <th style={{ width: 90 }}>Type</th>
            <th style={{ width: 180 }}>{isSrx ? 'Days' : 'Days / Date'}</th>
            <th style={{ width: 100 }}>Start</th>
            <th style={{ width: 100 }}>End</th>
            <th>Attached Rules</th>
            <th style={{ width: 36 }}></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, i) => (
            <tr key={i}>
              <td>
                <input
                  className="cell-input"
                  value={item.name}
                  onChange={(e) => handleChange(i, 'name', e.target.value)}
                />
              </td>
              <td>
                <select
                  className="cell-select"
                  value={item.type}
                  onChange={(e) => handleChange(i, 'type', e.target.value)}
                >
                  <option value="recurring">Recurring</option>
                  <option value="onetime">One-time</option>
                </select>
              </td>
              <td>
                {item.type === 'recurring' ? (
                  <div style={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                    {DAY_OPTIONS.map(d => (
                      <label key={d} style={{ fontSize: 10, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 1 }}>
                        <input
                          type="checkbox"
                          checked={(item.days || []).includes(d)}
                          onChange={(e) => {
                            const days = item.days || [];
                            const next = e.target.checked
                              ? [...days, d]
                              : days.filter(x => x !== d);
                            handleChange(i, 'days', next);
                          }}
                          style={{ width: 12, height: 12 }}
                        />
                        {d}
                      </label>
                    ))}
                  </div>
                ) : (
                  <input
                    className="cell-input"
                    value={(item.days || []).join(', ') || ''}
                    onChange={(e) => handleChange(i, 'days', [])}
                    placeholder="N/A"
                    disabled
                    style={{ opacity: 0.5 }}
                  />
                )}
              </td>
              <td>
                <input
                  className="cell-input"
                  value={item.start || ''}
                  onChange={(e) => handleChange(i, 'start', e.target.value)}
                  placeholder={item.type === 'recurring' ? 'HH:MM' : 'YYYY/MM/DD HH:MM'}
                />
              </td>
              <td>
                <input
                  className="cell-input"
                  value={item.end || ''}
                  onChange={(e) => handleChange(i, 'end', e.target.value)}
                  placeholder={item.type === 'recurring' ? 'HH:MM' : 'YYYY/MM/DD HH:MM'}
                />
              </td>
              <td>
                {(attachedRules[item.name] || []).length > 0 ? (
                  (attachedRules[item.name]).map((r, j) => (
                    <span key={j} className="cell-chip" style={{ fontSize: 10 }}>{r}</span>
                  ))
                ) : (
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>none</span>
                )}
              </td>
              <td>
                <button className="btn-icon btn-icon-danger" onClick={() => handleDelete(i)} title="Delete">x</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ padding: '8px 12px' }}>
        <button className="btn btn-secondary btn-sm" onClick={handleAdd}>+ Add Schedule</button>
      </div>
    </div>
  );
}

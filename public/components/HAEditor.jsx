/**
 * HAEditor Component
 *
 * Single-object editor for HA / Chassis Cluster configuration.
 * When ha_config is null, shows empty state with "Enable HA" button.
 * When present, shows a single card form for editing all HA fields.
 *
 * Supports two HA types:
 *   - chassis-cluster: Traditional SRX chassis cluster (RG0/RG1, fabric links)
 *   - mnha: Multinode High Availability (SRX4700 required, uses ICL + SRGs)
 */
import React, { useEffect } from 'react';
import { ChipEditor } from './ZoneEditor.jsx';

export default function HAEditor({ haConfig, onHAUpdate, viewMode, targetModel }) {
  const isSrx = viewMode === 'srx';
  const isSrx4700 = (targetModel || '').startsWith('SRX4700');
  const haType = haConfig?.ha_type || 'chassis-cluster';

  // Force MNHA when SRX4700 is target and HA is enabled
  useEffect(() => {
    if (isSrx4700 && haConfig?.enabled && haConfig.ha_type !== 'mnha') {
      onHAUpdate({ ...haConfig, ha_type: 'mnha' });
    }
  }, [isSrx4700, haConfig?.enabled]);

  const handleChange = (field, value) => {
    if (field === 'ha_type' && value === 'mnha' && !haConfig.local_id) {
      // Switching to MNHA — populate defaults for MNHA fields
      onHAUpdate({
        ...haConfig,
        ha_type: 'mnha',
        local_id: 1,
        local_ip: haConfig.local_ip || '',
        peer_id: 2,
        peer_ip: haConfig.peer_ip || haConfig.peer_ip || '',
        icl_interface: '',
        vpn_profile: 'IPSEC_VPN_ICL',
        liveness_interval: 400,
        liveness_multiplier: 5,
        deployment_type: 'routing',
        activeness_priority: haConfig.priority || 200,
        preemption: haConfig.preempt ?? true,
      });
      return;
    }
    onHAUpdate({ ...haConfig, [field]: value });
  };

  const handleEnable = () => {
    if (isSrx4700) {
      onHAUpdate({
        enabled: true,
        ha_type: 'mnha',
        mode: 'active-passive',
        local_id: 1,
        local_ip: '',
        peer_id: 2,
        peer_ip: '',
        icl_interface: '',
        vpn_profile: 'IPSEC_VPN_ICL',
        liveness_interval: 400,
        liveness_multiplier: 5,
        deployment_type: 'routing',
        activeness_priority: 200,
        preemption: true,
        ha_interfaces: [],
        monitoring: { link_groups: [], path_groups: [] },
        description: '',
      });
    } else {
      onHAUpdate({
        enabled: true,
        ha_type: 'chassis-cluster',
        mode: 'active-passive',
        group_id: 1,
        priority: 100,
        preempt: true,
        peer_ip: '',
        ha_interfaces: [],
        monitoring: { link_groups: [], path_groups: [] },
        description: '',
      });
    }
  };

  const handleDisable = () => {
    onHAUpdate(null);
  };

  /* ---- HA Interface handlers ---- */
  const handleInterfaceAdd = () => {
    const ifaces = [...(haConfig.ha_interfaces || []), { name: '', ip: '', netmask: '', interface: '' }];
    onHAUpdate({ ...haConfig, ha_interfaces: ifaces });
  };

  const handleInterfaceDelete = (idx) => {
    onHAUpdate({ ...haConfig, ha_interfaces: haConfig.ha_interfaces.filter((_, i) => i !== idx) });
  };

  const handleInterfaceChange = (idx, field, value) => {
    const ifaces = haConfig.ha_interfaces.map((iface, i) =>
      i === idx ? { ...iface, [field]: value } : iface
    );
    onHAUpdate({ ...haConfig, ha_interfaces: ifaces });
  };

  /* ---- Link Group handlers ---- */
  const handleLinkGroupAdd = () => {
    const monitoring = { ...haConfig.monitoring };
    monitoring.link_groups = [...(monitoring.link_groups || []), { name: 'default', enabled: true, interfaces: [] }];
    onHAUpdate({ ...haConfig, monitoring });
  };

  const handleLinkGroupDelete = (idx) => {
    const monitoring = { ...haConfig.monitoring };
    monitoring.link_groups = monitoring.link_groups.filter((_, i) => i !== idx);
    onHAUpdate({ ...haConfig, monitoring });
  };

  const handleLinkGroupChange = (idx, field, value) => {
    const monitoring = { ...haConfig.monitoring };
    monitoring.link_groups = monitoring.link_groups.map((g, i) =>
      i === idx ? { ...g, [field]: value } : g
    );
    onHAUpdate({ ...haConfig, monitoring });
  };

  const handleLinkGroupInterfaceAdd = (groupIdx, value) => {
    const monitoring = { ...haConfig.monitoring };
    monitoring.link_groups = monitoring.link_groups.map((g, i) =>
      i === groupIdx ? { ...g, interfaces: [...(g.interfaces || []), value] } : g
    );
    onHAUpdate({ ...haConfig, monitoring });
  };

  const handleLinkGroupInterfaceRemove = (groupIdx, value) => {
    const monitoring = { ...haConfig.monitoring };
    monitoring.link_groups = monitoring.link_groups.map((g, i) =>
      i === groupIdx ? { ...g, interfaces: (g.interfaces || []).filter(v => v !== value) } : g
    );
    onHAUpdate({ ...haConfig, monitoring });
  };

  /* ---- Path Group handlers ---- */
  const handlePathGroupAdd = () => {
    const monitoring = { ...haConfig.monitoring };
    monitoring.path_groups = [...(monitoring.path_groups || []), { name: 'default', enabled: true }];
    onHAUpdate({ ...haConfig, monitoring });
  };

  const handlePathGroupDelete = (idx) => {
    const monitoring = { ...haConfig.monitoring };
    monitoring.path_groups = monitoring.path_groups.filter((_, i) => i !== idx);
    onHAUpdate({ ...haConfig, monitoring });
  };

  const handlePathGroupChange = (idx, field, value) => {
    const monitoring = { ...haConfig.monitoring };
    monitoring.path_groups = monitoring.path_groups.map((g, i) =>
      i === idx ? { ...g, [field]: value } : g
    );
    onHAUpdate({ ...haConfig, monitoring });
  };

  /* ---- Empty state ---- */
  if (!haConfig || !haConfig.enabled) {
    return (
      <div className="panel-body">
        <div className="empty-state">
          <p>No HA / Chassis Cluster configuration defined.</p>
          <button className="btn btn-primary btn-sm" onClick={handleEnable}>Enable HA</button>
        </div>
      </div>
    );
  }

  const sectionLabel = { fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4, display: 'block' };

  return (
    <div style={{ overflow: 'auto', flex: 1 }}>
      <div className="editor-list">
        <div className="editor-card">
          <div className="editor-card-header">
            {/* HA Type Toggle */}
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, cursor: isSrx4700 ? 'default' : 'pointer', color: haType === 'chassis-cluster' ? 'var(--accent)' : 'var(--text-secondary)' }}>
                <input
                  type="radio"
                  name="haType"
                  value="chassis-cluster"
                  checked={haType === 'chassis-cluster'}
                  onChange={() => handleChange('ha_type', 'chassis-cluster')}
                  disabled={isSrx4700}
                />
                Chassis Cluster
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, cursor: 'pointer', color: haType === 'mnha' ? 'var(--accent)' : 'var(--text-secondary)' }}>
                <input
                  type="radio"
                  name="haType"
                  value="mnha"
                  checked={haType === 'mnha'}
                  onChange={() => handleChange('ha_type', 'mnha')}
                />
                MNHA
              </label>
            </div>
            <span style={{ flex: 1 }} />
            <button className="btn-icon btn-icon-danger" onClick={handleDisable} title="Disable HA">x</button>
          </div>

          {isSrx4700 && haType === 'mnha' && (
            <div style={{ padding: '6px 12px', background: 'rgba(59, 130, 246, 0.1)', borderBottom: '1px solid rgba(59, 130, 246, 0.2)', fontSize: 11, color: '#60a5fa' }}>
              SRX4700 requires Multinode High Availability (MNHA) — chassis cluster is not supported.
            </div>
          )}

          <div className="editor-card-body">
            {haType === 'mnha' ? (
              /* ---- MNHA Fields ---- */
              <>
                {/* Mode */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>Mode</label>
                  <select
                    className="cell-select"
                    value={haConfig.mode || 'active-passive'}
                    onChange={(e) => handleChange('mode', e.target.value)}
                    style={{ width: 160 }}
                  >
                    <option value="active-passive">Active / Backup</option>
                    <option value="active-active">Active / Active</option>
                  </select>
                </div>

                {/* Local Node */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>Local Node</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={{ width: 80 }}>
                      <label>Local ID</label>
                      <input className="cell-input" type="number" value={haConfig.local_id ?? 1}
                        onChange={(e) => handleChange('local_id', parseInt(e.target.value, 10) || 1)} />
                    </div>
                    <div className="editor-field" style={{ flex: 1 }}>
                      <label>Local IP</label>
                      <input className="cell-input" value={haConfig.local_ip || ''}
                        onChange={(e) => handleChange('local_ip', e.target.value)} placeholder="10.22.0.1 (loopback IP)" />
                    </div>
                  </div>
                </div>

                {/* Peer Node */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>Peer Node</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={{ width: 80 }}>
                      <label>Peer ID</label>
                      <input className="cell-input" type="number" value={haConfig.peer_id ?? 2}
                        onChange={(e) => handleChange('peer_id', parseInt(e.target.value, 10) || 2)} />
                    </div>
                    <div className="editor-field" style={{ flex: 1 }}>
                      <label>Peer IP</label>
                      <input className="cell-input" value={haConfig.peer_ip || ''}
                        onChange={(e) => handleChange('peer_ip', e.target.value)} placeholder="10.22.0.2" />
                    </div>
                  </div>
                  <div className="editor-field-row" style={{ marginTop: 4 }}>
                    <div className="editor-field" style={{ flex: 1 }}>
                      <label>ICL Interface</label>
                      <input className="cell-input" value={haConfig.icl_interface || ''}
                        onChange={(e) => handleChange('icl_interface', e.target.value)} placeholder="ge-0/0/2.0" />
                    </div>
                    <div className="editor-field" style={{ flex: 1 }}>
                      <label>VPN Profile</label>
                      <input className="cell-input" value={haConfig.vpn_profile || ''}
                        onChange={(e) => handleChange('vpn_profile', e.target.value)} placeholder="IPSEC_VPN_ICL" />
                    </div>
                  </div>
                </div>

                {/* Liveness Detection */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>Liveness Detection</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={{ width: 140 }}>
                      <label>Min Interval (ms)</label>
                      <input className="cell-input" type="number" value={haConfig.liveness_interval ?? 400}
                        onChange={(e) => handleChange('liveness_interval', parseInt(e.target.value, 10) || 400)} />
                    </div>
                    <div className="editor-field" style={{ width: 100 }}>
                      <label>Multiplier</label>
                      <input className="cell-input" type="number" value={haConfig.liveness_multiplier ?? 5}
                        onChange={(e) => handleChange('liveness_multiplier', parseInt(e.target.value, 10) || 5)} />
                    </div>
                  </div>
                </div>

                {/* SRG1 Settings */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>Services Redundancy Group 1</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={{ width: 140 }}>
                      <label>Deployment Type</label>
                      <select className="cell-select" value={haConfig.deployment_type || 'routing'}
                        onChange={(e) => handleChange('deployment_type', e.target.value)}>
                        <option value="routing">Routing (L3)</option>
                        <option value="switching">Switching (L2)</option>
                        <option value="hybrid">Hybrid</option>
                      </select>
                    </div>
                    <div className="editor-field" style={{ width: 120 }}>
                      <label>Priority (1-254)</label>
                      <input className="cell-input" type="number" min={1} max={254}
                        value={haConfig.activeness_priority ?? 200}
                        onChange={(e) => handleChange('activeness_priority', parseInt(e.target.value, 10) || 200)} />
                    </div>
                    <div className="editor-field" style={{ width: 'auto', flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                      <input type="checkbox" checked={haConfig.preemption ?? true}
                        onChange={(e) => handleChange('preemption', e.target.checked)} />
                      <label>Preemption</label>
                    </div>
                  </div>
                </div>

                {/* Monitoring - Link Groups */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>
                    Monitoring — Link Groups ({(haConfig.monitoring?.link_groups || []).length})
                  </label>
                  {(haConfig.monitoring?.link_groups || []).map((group, idx) => (
                    <div key={idx} style={{ marginBottom: 8, paddingLeft: 8, borderLeft: '2px solid var(--border-color)' }}>
                      <div className="editor-field-row" style={{ marginBottom: 4 }}>
                        <div className="editor-field" style={{ flex: 1 }}>
                          <label>Name</label>
                          <input className="cell-input" value={group.name || ''}
                            onChange={(e) => handleLinkGroupChange(idx, 'name', e.target.value)} />
                        </div>
                        <div className="editor-field" style={{ width: 'auto', flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                          <input type="checkbox" checked={group.enabled ?? true}
                            onChange={(e) => handleLinkGroupChange(idx, 'enabled', e.target.checked)} />
                          <label>Enabled</label>
                        </div>
                        <button className="btn-icon btn-icon-danger" onClick={() => handleLinkGroupDelete(idx)}
                          title="Remove" style={{ alignSelf: 'flex-end', marginBottom: 4 }}>x</button>
                      </div>
                      <div style={{ marginLeft: 4 }}>
                        <label style={{ fontSize: 10, color: '#64748b' }}>Interfaces</label>
                        <ChipEditor
                          values={group.interfaces || []}
                          onAdd={(val) => handleLinkGroupInterfaceAdd(idx, val)}
                          onRemove={(val) => handleLinkGroupInterfaceRemove(idx, val)}
                          placeholder="Add interface"
                        />
                      </div>
                    </div>
                  ))}
                  <button className="btn btn-secondary btn-sm" onClick={handleLinkGroupAdd}
                    style={{ marginTop: 4, fontSize: 11 }}>+ Add Link Group</button>
                </div>

                {/* Description */}
                <div className="editor-field-row">
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Description</label>
                    <input className="editor-inline-input" value={haConfig.description || ''}
                      onChange={(e) => handleChange('description', e.target.value)} placeholder="MNHA description" />
                  </div>
                </div>
              </>
            ) : (
              /* ---- Chassis Cluster Fields (original) ---- */
              <>
                {/* General */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>General</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={{ width: 80 }}>
                      <label>Group ID</label>
                      <input className="cell-input" type="number" value={haConfig.group_id ?? 0}
                        onChange={(e) => handleChange('group_id', parseInt(e.target.value, 10) || 0)} />
                    </div>
                    <div className="editor-field" style={{ width: 80 }}>
                      <label>Priority</label>
                      <input className="cell-input" type="number" value={haConfig.priority ?? 100}
                        onChange={(e) => handleChange('priority', parseInt(e.target.value, 10) || 0)} />
                    </div>
                    <div className="editor-field" style={{ width: 'auto', flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                      <input type="checkbox" checked={haConfig.preempt ?? false}
                        onChange={(e) => handleChange('preempt', e.target.checked)} />
                      <label>Preempt</label>
                    </div>
                    <div className="editor-field" style={{ flex: 1 }}>
                      <label>Peer IP</label>
                      <input className="cell-input" value={haConfig.peer_ip || ''}
                        onChange={(e) => handleChange('peer_ip', e.target.value)} placeholder="Peer node address" />
                    </div>
                  </div>
                </div>

                {/* HA Interfaces */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>
                    HA Interfaces ({(haConfig.ha_interfaces || []).length})
                  </label>
                  {(haConfig.ha_interfaces || []).map((iface, idx) => (
                    <div key={idx} className="editor-field-row" style={{ marginBottom: 4 }}>
                      <div className="editor-field" style={{ flex: 1 }}>
                        <label>Role</label>
                        <input className="cell-input" value={iface.name || ''}
                          onChange={(e) => handleInterfaceChange(idx, 'name', e.target.value)}
                          placeholder={isSrx ? 'fab0, fxp0' : 'HA1, HA2'} />
                      </div>
                      <div className="editor-field" style={{ flex: 1 }}>
                        <label>IP</label>
                        <input className="cell-input" value={iface.ip || ''}
                          onChange={(e) => handleInterfaceChange(idx, 'ip', e.target.value)} />
                      </div>
                      <div className="editor-field" style={{ width: 120 }}>
                        <label>Netmask</label>
                        <input className="cell-input" value={iface.netmask || ''}
                          onChange={(e) => handleInterfaceChange(idx, 'netmask', e.target.value)} />
                      </div>
                      <div className="editor-field" style={{ flex: 1 }}>
                        <label>Interface</label>
                        <input className="cell-input" value={iface.interface || ''}
                          onChange={(e) => handleInterfaceChange(idx, 'interface', e.target.value)}
                          placeholder={isSrx ? 'ge-0/0/0' : 'ethernet1/1'} />
                      </div>
                      <button className="btn-icon btn-icon-danger" onClick={() => handleInterfaceDelete(idx)}
                        title="Remove" style={{ alignSelf: 'flex-end', marginBottom: 4 }}>x</button>
                    </div>
                  ))}
                  <button className="btn btn-secondary btn-sm" onClick={handleInterfaceAdd}
                    style={{ marginTop: 4, fontSize: 11 }}>+ Add HA Interface</button>
                </div>

                {/* Monitoring - Link Groups */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>
                    Monitoring — Link Groups ({(haConfig.monitoring?.link_groups || []).length})
                  </label>
                  {(haConfig.monitoring?.link_groups || []).map((group, idx) => (
                    <div key={idx} style={{ marginBottom: 8, paddingLeft: 8, borderLeft: '2px solid var(--border-color)' }}>
                      <div className="editor-field-row" style={{ marginBottom: 4 }}>
                        <div className="editor-field" style={{ flex: 1 }}>
                          <label>Name</label>
                          <input className="cell-input" value={group.name || ''}
                            onChange={(e) => handleLinkGroupChange(idx, 'name', e.target.value)} />
                        </div>
                        <div className="editor-field" style={{ width: 'auto', flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                          <input type="checkbox" checked={group.enabled ?? true}
                            onChange={(e) => handleLinkGroupChange(idx, 'enabled', e.target.checked)} />
                          <label>Enabled</label>
                        </div>
                        <button className="btn-icon btn-icon-danger" onClick={() => handleLinkGroupDelete(idx)}
                          title="Remove" style={{ alignSelf: 'flex-end', marginBottom: 4 }}>x</button>
                      </div>
                      <div style={{ marginLeft: 4 }}>
                        <label style={{ fontSize: 10, color: '#64748b' }}>Interfaces</label>
                        <ChipEditor
                          values={group.interfaces || []}
                          onAdd={(val) => handleLinkGroupInterfaceAdd(idx, val)}
                          onRemove={(val) => handleLinkGroupInterfaceRemove(idx, val)}
                          placeholder="Add interface"
                        />
                      </div>
                    </div>
                  ))}
                  <button className="btn btn-secondary btn-sm" onClick={handleLinkGroupAdd}
                    style={{ marginTop: 4, fontSize: 11 }}>+ Add Link Group</button>
                </div>

                {/* Monitoring - Path Groups */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>
                    Monitoring — Path Groups ({(haConfig.monitoring?.path_groups || []).length})
                  </label>
                  {(haConfig.monitoring?.path_groups || []).map((group, idx) => (
                    <div key={idx} className="editor-field-row" style={{ marginBottom: 4 }}>
                      <div className="editor-field" style={{ flex: 1 }}>
                        <label>Name</label>
                        <input className="cell-input" value={group.name || ''}
                          onChange={(e) => handlePathGroupChange(idx, 'name', e.target.value)} />
                      </div>
                      <div className="editor-field" style={{ width: 'auto', flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                        <input type="checkbox" checked={group.enabled ?? true}
                          onChange={(e) => handlePathGroupChange(idx, 'enabled', e.target.checked)} />
                        <label>Enabled</label>
                      </div>
                      <button className="btn-icon btn-icon-danger" onClick={() => handlePathGroupDelete(idx)}
                        title="Remove" style={{ alignSelf: 'flex-end', marginBottom: 4 }}>x</button>
                    </div>
                  ))}
                  <button className="btn btn-secondary btn-sm" onClick={handlePathGroupAdd}
                    style={{ marginTop: 4, fontSize: 11 }}>+ Add Path Group</button>
                </div>

                {/* Description */}
                <div className="editor-field-row">
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Description</label>
                    <input className="editor-inline-input" value={haConfig.description || ''}
                      onChange={(e) => handleChange('description', e.target.value)} placeholder="HA description" />
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

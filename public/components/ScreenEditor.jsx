/**
 * ScreenEditor Component
 *
 * Card-based editor for Screen / DDoS protection profiles.
 * Each card shows: ICMP, TCP, UDP, IP protections + session limits.
 * Includes "Apply Best Practice" preset toolbar for auto-generating
 * screens on internet-facing zones with speed-scaled thresholds.
 */
import React, { useState, useMemo } from 'react';
import {
  SCREEN_PRESETS, SPEED_TIERS,
  detectInternetZones, resolveZoneSpeedTiers, generateScreenConfig,
} from '../utils/screen-presets.js';
import { SRX_MODELS, getSrx4700Ports } from '../data/hardware-db.js';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import { useUIContext } from '../contexts/UIContext.jsx';

export default function ScreenEditor({
  screenConfig, onScreenUpdate, viewMode,
  zones, staticRoutes, interfaces, targetModel, interfaceMappings,
}) {

  const { state: cfgState, dispatch: cfgDispatch } = useConfigContext();
  const { state: uiState } = useUIContext();
  const isSrxView = uiState.platformView === 'srx';

  // Preset panel state
  const [showPresetPanel, setShowPresetPanel] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState('standard');
  const [selectedSpeed, setSelectedSpeed] = useState('1g');
  const [selectedZones, setSelectedZones] = useState([]);
  const [replaceMode, setReplaceMode] = useState(true);

  // Auto-detect internet-facing zones
  const detection = useMemo(() => {
    return detectInternetZones(zones, staticRoutes, interfaces);
  }, [zones, staticRoutes, interfaces]);

  // Resolve target model ports
  const targetPorts = useMemo(() => {
    const model = SRX_MODELS?.[targetModel];
    if (!model) return [];
    if (model.hasPortProfiles) {
      // SRX4700 — use default profile
      const profileKey = Object.keys(model.portProfiles || {})[0];
      return profileKey ? getSrx4700Ports(profileKey) : [];
    }
    return model.ports || [];
  }, [targetModel]);

  // Resolve valid speed tiers for selected zones
  const speedInfo = useMemo(() => {
    return resolveZoneSpeedTiers(selectedZones, zones, interfaceMappings, targetPorts);
  }, [selectedZones, zones, interfaceMappings, targetPorts]);

  const handleOpenPresetPanel = () => {
    // Pre-select detected zones
    const preSelected = detection.confidence === 'high' ? detection.detected : detection.allZones;
    setSelectedZones(preSelected);

    // Resolve speed from hardware DB + interface mappings
    const info = resolveZoneSpeedTiers(preSelected, zones, interfaceMappings, targetPorts);
    setSelectedSpeed(info.maxTier);

    setShowPresetPanel(true);
  };

  const handleApplyPreset = () => {
    const newScreens = generateScreenConfig(selectedPreset, selectedSpeed, selectedZones);
    if (replaceMode) {
      const existingForOtherZones = (screenConfig || []).filter(
        s => !selectedZones.includes(s.zone)
      );
      onScreenUpdate([...existingForOtherZones, ...newScreens]);
    } else {
      onScreenUpdate([...(screenConfig || []), ...newScreens]);
    }
    setShowPresetPanel(false);
  };

  /** Deep update using dot-path (e.g., 'icmp.flood_threshold') */
  const handleChange = (index, path, value) => {
    const updated = screenConfig.map((screen, i) => {
      if (i !== index) return screen;
      const parts = path.split('.');
      if (parts.length === 1) {
        return { ...screen, [parts[0]]: value };
      }
      const clone = { ...screen };
      clone[parts[0]] = { ...clone[parts[0]], [parts[1]]: value };
      return clone;
    });
    onScreenUpdate(updated);
    // Auto-revoke acceptance for this screen's zone
    if (isSrxView && screenConfig[index]?.zone) {
      cfgDispatch({ type: 'REVOKE_SECTION', sectionId: `screen:${screenConfig[index].zone}` });
    }
  };

  const handleAdd = () => {
    onScreenUpdate([...(screenConfig || []), {
      name: `screen-${(screenConfig || []).length + 1}`,
      zone: '',
      icmp: { flood_threshold: null, ping_death: false, fragment: false },
      tcp: { syn_flood_alarm_threshold: null, syn_flood_threshold: null, syn_flood_timeout: null, land_attack: false, winnuke: false, tcp_no_flag: false },
      udp: { flood_threshold: null },
      ip: { spoofing: false, source_route: false, tear_drop: false, record_route: false, timestamp: false },
      limit_session: { source_based: null, destination_based: null },
      description: '',
    }]);
  };

  const handleDelete = (index) => {
    onScreenUpdate(screenConfig.filter((_, i) => i !== index));
  };

  /** Convert empty string to null, otherwise to number */
  const toNullableNum = (val) => val === '' ? null : Number(val);

  const sectionLabel = { fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4, display: 'block' };
  const checkField = { width: 'auto', flexDirection: 'row', alignItems: 'center', gap: 6 };

  // --- Preset Toolbar ---
  const presetToolbar = (
    <>
      <div style={{
        padding: '8px 16px',
        background: 'var(--bg-tertiary)',
        borderBottom: '1px solid var(--border-color)',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
      }}>
        <button className="btn btn-primary btn-sm" onClick={handleOpenPresetPanel}>
          {showPresetPanel ? 'Close Presets' : 'Apply Best Practice'}
        </button>
        {isSrxView && screenConfig && screenConfig.length > 0 && (
          (() => {
            const allAccepted = screenConfig.every(s => s.zone && cfgState.sectionAcceptance[`screen:${s.zone}`]);
            return allAccepted ? (
              <button className="btn btn-sm btn-accepted" disabled>All Screens Accepted</button>
            ) : (
              <button className="btn btn-sm btn-accept" onClick={() => {
                cfgDispatch({
                  type: 'ACCEPT_SECTIONS',
                  sectionIds: screenConfig.filter(s => s.zone).map(s => `screen:${s.zone}`),
                });
              }}>Accept All Screens</button>
            );
          })()
        )}
        {detection.confidence === 'low' && detection.allZones.length > 0 && !showPresetPanel && (
          <span style={{ fontSize: 11, color: 'var(--caution)' }}>
            No internet-facing zones auto-detected — select zones manually
          </span>
        )}
        {detection.confidence === 'high' && !showPresetPanel && (
          <span style={{ fontSize: 11, color: 'var(--success)' }}>
            Detected: {detection.detected.join(', ')}
          </span>
        )}
      </div>

      {showPresetPanel && (
        <div style={{
          padding: '12px 16px',
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border-color)',
        }}>
          <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start', flexWrap: 'wrap' }}>
            {/* Preset selector */}
            <div style={{ minWidth: 160 }}>
              <label style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Preset</label>
              <select className="cell-input" value={selectedPreset}
                onChange={e => setSelectedPreset(e.target.value)}
                style={{ width: '100%' }}>
                {Object.entries(SCREEN_PRESETS).map(([key, p]) => (
                  <option key={key} value={key}>{p.label} — {p.description}</option>
                ))}
              </select>
            </div>

            {/* Speed selector — filtered to valid port speeds */}
            <div style={{ minWidth: 140 }}>
              <label style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                Interface Speed
                {speedInfo.portDetails && (
                  <span style={{ color: 'var(--accent)', marginLeft: 6, textTransform: 'none' }}>{speedInfo.portDetails}</span>
                )}
              </label>
              <select className="cell-input" value={selectedSpeed}
                onChange={e => setSelectedSpeed(e.target.value)}
                style={{ width: '100%' }}>
                {speedInfo.validTiers.map(key => (
                  <option key={key} value={key}>{speedInfo.tierLabels?.[key] || SPEED_TIERS[key].label}</option>
                ))}
              </select>
            </div>

            {/* Zone checkboxes */}
            <div style={{ flex: 1, minWidth: 200 }}>
              <label style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                Apply to Zones
                {detection.confidence === 'high' && (
                  <span style={{ color: 'var(--success)', marginLeft: 6, textTransform: 'none' }}>auto-detected</span>
                )}
              </label>
              {detection.allZones.length === 0 ? (
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>No zones defined — parse a config first</span>
              ) : (
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  {detection.allZones.map(z => (
                    <label key={z} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                      <input type="checkbox"
                        checked={selectedZones.includes(z)}
                        onChange={e => {
                          const next = e.target.checked
                            ? [...selectedZones, z]
                            : selectedZones.filter(x => x !== z);
                          setSelectedZones(next);
                          // Auto-update speed to match new zone selection
                          const info = resolveZoneSpeedTiers(next, zones, interfaceMappings, targetPorts);
                          if (!info.validTiers.includes(selectedSpeed)) {
                            setSelectedSpeed(info.maxTier);
                          }
                        }} />
                      <span style={detection.detected.includes(z) ? { color: 'var(--caution)', fontWeight: 600 } : undefined}>{z}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Preview + Replace + Apply/Cancel */}
          <div style={{ display: 'flex', gap: 10, marginTop: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
              <input type="checkbox" checked={replaceMode}
                onChange={e => setReplaceMode(e.target.checked)} />
              Replace existing screens for selected zones
            </label>

            {/* Threshold preview */}
            {selectedZones.length > 0 && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 8 }}>
                SYN:{Math.round(SCREEN_PRESETS[selectedPreset].base.tcp.syn_flood_threshold * (SPEED_TIERS[selectedSpeed]?.multiplier || 1))}pps
                {' '}UDP:{Math.round(SCREEN_PRESETS[selectedPreset].base.udp.flood_threshold * (SPEED_TIERS[selectedSpeed]?.multiplier || 1))}pps
                {' '}ICMP:{Math.round(SCREEN_PRESETS[selectedPreset].base.icmp.flood_threshold * (SPEED_TIERS[selectedSpeed]?.multiplier || 1))}pps
              </span>
            )}

            <div style={{ flex: 1 }} />
            <button className="btn btn-sm" onClick={() => setShowPresetPanel(false)}>Cancel</button>
            <button className="btn btn-primary btn-sm"
              disabled={selectedZones.length === 0}
              onClick={handleApplyPreset}>
              Apply {SCREEN_PRESETS[selectedPreset]?.label} Preset
            </button>
          </div>
        </div>
      )}
    </>
  );

  // --- Empty state ---
  if (!screenConfig || screenConfig.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
        {presetToolbar}
        <div className="panel-body" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="empty-state">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <h3>No screen / DDoS profiles defined</h3>
            <p>Apply a best practice preset or add a manual screen profile.</p>
            <button className="btn btn-secondary btn-sm" onClick={handleAdd} style={{ marginTop: 8 }}>+ Add Manual Screen</button>
          </div>
        </div>
      </div>
    );
  }

  // --- Screen cards ---
  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
      {presetToolbar}
      <div style={{ overflow: 'auto', flex: 1 }}>
        <div className="editor-list">
          {screenConfig.map((screen, index) => (
            <div key={index} className="editor-card">
              <div className="editor-card-header">
                <input className="editor-inline-input editor-name-input"
                  value={screen.name || ''}
                  onChange={(e) => handleChange(index, 'name', e.target.value)} />
                <div className="editor-field" style={{ width: 140, margin: 0 }}>
                  <input className="cell-input" value={screen.zone || ''}
                    onChange={(e) => handleChange(index, 'zone', e.target.value)}
                    placeholder="Zone" />
                </div>
                {isSrxView && screen.zone && (
                  cfgState.sectionAcceptance[`screen:${screen.zone}`] ? (
                    <button className="btn btn-sm btn-accepted" disabled style={{ marginLeft: 'auto' }}>Accepted</button>
                  ) : (
                    <button className="btn btn-sm btn-accept" style={{ marginLeft: 'auto' }}
                      onClick={() => cfgDispatch({ type: 'ACCEPT_SECTION', sectionId: `screen:${screen.zone}` })}>
                      Accept
                    </button>
                  )
                )}
                <button className="btn-icon btn-icon-danger" onClick={() => handleDelete(index)} title="Delete">x</button>
              </div>

              <div className="editor-card-body">
                {/* ICMP */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>ICMP Protection</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={{ width: 140 }}>
                      <label>Flood Threshold</label>
                      <input className="cell-input" type="number"
                        value={screen.icmp?.flood_threshold ?? ''}
                        onChange={(e) => handleChange(index, 'icmp.flood_threshold', toNullableNum(e.target.value))}
                        placeholder="pps" />
                    </div>
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.icmp?.ping_death ?? false}
                        onChange={(e) => handleChange(index, 'icmp.ping_death', e.target.checked)} />
                      <label>Ping of Death</label>
                    </div>
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.icmp?.fragment ?? false}
                        onChange={(e) => handleChange(index, 'icmp.fragment', e.target.checked)} />
                      <label>Fragment</label>
                    </div>
                  </div>
                </div>

                {/* TCP */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>TCP Protection</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={{ width: 140 }}>
                      <label>SYN Attack Threshold</label>
                      <input className="cell-input" type="number"
                        value={screen.tcp?.syn_flood_threshold ?? ''}
                        onChange={(e) => handleChange(index, 'tcp.syn_flood_threshold', toNullableNum(e.target.value))}
                        placeholder="pps" />
                    </div>
                    <div className="editor-field" style={{ width: 140 }}>
                      <label>SYN Alarm Threshold</label>
                      <input className="cell-input" type="number"
                        value={screen.tcp?.syn_flood_alarm_threshold ?? ''}
                        onChange={(e) => handleChange(index, 'tcp.syn_flood_alarm_threshold', toNullableNum(e.target.value))}
                        placeholder="auto (5x attack)" />
                    </div>
                    <div className="editor-field" style={{ width: 120 }}>
                      <label>SYN Timeout (s)</label>
                      <input className="cell-input" type="number"
                        value={screen.tcp?.syn_flood_timeout ?? ''}
                        onChange={(e) => handleChange(index, 'tcp.syn_flood_timeout', toNullableNum(e.target.value))}
                        placeholder="sec" />
                    </div>
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.tcp?.land_attack ?? false}
                        onChange={(e) => handleChange(index, 'tcp.land_attack', e.target.checked)} />
                      <label>Land Attack</label>
                    </div>
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.tcp?.winnuke ?? false}
                        onChange={(e) => handleChange(index, 'tcp.winnuke', e.target.checked)} />
                      <label>WinNuke</label>
                    </div>
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.tcp?.tcp_no_flag ?? false}
                        onChange={(e) => handleChange(index, 'tcp.tcp_no_flag', e.target.checked)} />
                      <label>No Flag</label>
                    </div>
                  </div>
                </div>

                {/* UDP */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>UDP Protection</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={{ width: 140 }}>
                      <label>Flood Threshold</label>
                      <input className="cell-input" type="number"
                        value={screen.udp?.flood_threshold ?? ''}
                        onChange={(e) => handleChange(index, 'udp.flood_threshold', toNullableNum(e.target.value))}
                        placeholder="pps" />
                    </div>
                  </div>
                </div>

                {/* IP */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>IP Protection</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.ip?.spoofing ?? false}
                        onChange={(e) => handleChange(index, 'ip.spoofing', e.target.checked)} />
                      <label>Spoofing</label>
                    </div>
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.ip?.source_route ?? false}
                        onChange={(e) => handleChange(index, 'ip.source_route', e.target.checked)} />
                      <label>Source Route</label>
                    </div>
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.ip?.tear_drop ?? false}
                        onChange={(e) => handleChange(index, 'ip.tear_drop', e.target.checked)} />
                      <label>Tear Drop</label>
                    </div>
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.ip?.record_route ?? false}
                        onChange={(e) => handleChange(index, 'ip.record_route', e.target.checked)} />
                      <label>Record Route</label>
                    </div>
                    <div className="editor-field" style={checkField}>
                      <input type="checkbox" checked={screen.ip?.timestamp ?? false}
                        onChange={(e) => handleChange(index, 'ip.timestamp', e.target.checked)} />
                      <label>Timestamp</label>
                    </div>
                  </div>
                </div>

                {/* Session Limits */}
                <div style={{ marginBottom: 8 }}>
                  <label style={sectionLabel}>Session Limits</label>
                  <div className="editor-field-row">
                    <div className="editor-field" style={{ width: 160 }}>
                      <label>Source-Based</label>
                      <input className="cell-input" type="number"
                        value={screen.limit_session?.source_based ?? ''}
                        onChange={(e) => handleChange(index, 'limit_session.source_based', toNullableNum(e.target.value))}
                        placeholder="Max sessions" />
                    </div>
                    <div className="editor-field" style={{ width: 160 }}>
                      <label>Destination-Based</label>
                      <input className="cell-input" type="number"
                        value={screen.limit_session?.destination_based ?? ''}
                        onChange={(e) => handleChange(index, 'limit_session.destination_based', toNullableNum(e.target.value))}
                        placeholder="Max sessions" />
                    </div>
                  </div>
                </div>

                {/* Description */}
                <div className="editor-field-row">
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Description</label>
                    <input className="editor-inline-input" value={screen.description || ''}
                      onChange={(e) => handleChange(index, 'description', e.target.value)}
                      placeholder="Optional description" />
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div style={{ padding: '12px 16px' }}>
          <button className="btn btn-secondary btn-sm" onClick={handleAdd}>+ Add Screen Profile</button>
        </div>
      </div>
    </div>
  );
}

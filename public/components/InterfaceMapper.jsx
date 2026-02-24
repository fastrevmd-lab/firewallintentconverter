/**
 * InterfaceMapper Component
 *
 * Modal for mapping each zone's PAN-OS interface(s) to SRX interfaces.
 *
 * For each zone, shows:
 *   - Zone name
 *   - PAN-OS interface(s) with type/speed badge (from source model DB)
 *   - Arrow indicator
 *   - Dropdown of available SRX ports (from target model DB) — or tunnel
 *     interface builder for PAN-OS tunnel.X interfaces
 *   - SRX port type/speed badge
 *   - Compatibility indicator (speed mismatch = warning)
 *
 * Tunnel interfaces:
 *   PAN-OS tunnel.X → SRX st0.X (IPsec), gr-0/0/0.X (GRE), or ip-0/0/0.X (IP-IP)
 *   Loopback interfaces:
 *   PAN-OS loopback.X → SRX lo0.X
 *
 * Available ports auto-filter: once a port is assigned to one zone,
 * it's removed from other dropdowns.
 */
import React, { useState, useMemo } from 'react';
import {
  PANOS_MODELS, SRX_MODELS, SRX_SOURCE_MODELS,
  FORTIGATE_SOURCE_MODELS, CISCO_SOURCE_MODELS,
  CHECKPOINT_SOURCE_MODELS, SONICWALL_SOURCE_MODELS, HUAWEI_SOURCE_MODELS,
  getSrx4700Ports,
} from '../data/hardware-db.js';

/** Look up the correct source model database for a given vendor */
function getSourceModelDb(vendor) {
  switch (vendor) {
    case 'srx': return SRX_SOURCE_MODELS;
    case 'fortigate': return FORTIGATE_SOURCE_MODELS;
    case 'cisco_asa': return CISCO_SOURCE_MODELS;
    case 'checkpoint': return CHECKPOINT_SOURCE_MODELS;
    case 'sonicwall': return SONICWALL_SOURCE_MODELS;
    case 'huawei_usg': return HUAWEI_SOURCE_MODELS;
    default: return PANOS_MODELS;
  }
}

/** SRX tunnel interface types for the dropdown */
const SRX_TUNNEL_TYPES = [
  { value: 'st0',       label: 'st0 (IPsec Secure Tunnel)', description: 'Standard IPsec VPN tunnel' },
  { value: 'gr-0/0/0',  label: 'gr-0/0/0 (GRE Tunnel)',     description: 'Generic Routing Encapsulation' },
  { value: 'ip-0/0/0',  label: 'ip-0/0/0 (IP-IP Tunnel)',   description: 'IP-in-IP encapsulation' },
];

/** Detect if a PAN-OS interface is a tunnel */
function isTunnelInterface(ifaceName) {
  return /^tunnel\.\d+$/i.test(ifaceName);
}

/** Detect if an interface is a loopback (PAN-OS loopback.X, Huawei LoopBackN) */
function isLoopbackInterface(ifaceName) {
  return /^loopback\.\d+$/i.test(ifaceName) || /^LoopBack\d+$/i.test(ifaceName);
}

/** Extract unit number from PAN-OS logical interface */
function getUnit(ifaceName) {
  const m = ifaceName.match(/\.(\d+)$/);
  return m ? m[1] : '0';
}

export default function InterfaceMapper({
  intermediateConfig,
  sourceModel,
  targetModel,
  portProfile,
  interfaceMappings: existingMappings,
  onMappingComplete,
  onClose,
}) {
  /** Resolve target model data, applying SRX4700 port profile override if applicable */
  const targetModelData = useMemo(() => {
    const raw = targetModel ? SRX_MODELS[targetModel] : null;
    if (!raw) return null;
    if (raw.hasPortProfiles && portProfile) {
      return { ...raw, ports: getSrx4700Ports(portProfile) };
    }
    return raw;
  }, [targetModel, portProfile]);

  // Initialize mappings from existing or build fresh
  const [mappings, setMappings] = useState(() => {
    if (existingMappings && Object.keys(existingMappings).length > 0) {
      // Filter out stale mappings that reference ports not on the current target model
      const validPortNames = targetModelData ? new Set(targetModelData.ports.map(p => p.name)) : null;
      const cleaned = {};
      for (const [panos, srx] of Object.entries(existingMappings)) {
        if (isTunnelInterface(panos) || isLoopbackInterface(panos)) {
          cleaned[panos] = srx; // virtual interfaces are always valid
        } else if (!validPortNames || validPortNames.has(srx)) {
          cleaned[panos] = srx;
        }
        // else: stale mapping from a different model — drop it
      }
      if (Object.keys(cleaned).length > 0) {
        return cleaned;
      }
    }
    return buildDefaultMappings(intermediateConfig, targetModelData);
  });

  // Track tunnel type selections separately (prefix before the unit)
  const [tunnelTypes, setTunnelTypes] = useState(() => {
    const types = {};
    for (const zone of (intermediateConfig?.zones || [])) {
      for (const iface of (zone.interfaces || [])) {
        if (isTunnelInterface(iface)) {
          // Parse existing mapping to detect type, or default to st0
          const existing = existingMappings?.[iface] || '';
          if (existing.startsWith('gr-')) {
            types[iface] = 'gr-0/0/0';
          } else if (existing.startsWith('ip-')) {
            types[iface] = 'ip-0/0/0';
          } else {
            types[iface] = 'st0';
          }
        }
      }
    }
    return types;
  });

  // Track custom tunnel unit numbers
  const [tunnelUnits, setTunnelUnits] = useState(() => {
    const units = {};
    for (const zone of (intermediateConfig?.zones || [])) {
      for (const iface of (zone.interfaces || [])) {
        if (isTunnelInterface(iface)) {
          const existing = existingMappings?.[iface] || '';
          const m = existing.match(/\.(\d+)$/);
          units[iface] = m ? m[1] : getUnit(iface);
        }
      }
    }
    return units;
  });

  const sourceVendor = intermediateConfig?.metadata?.source_vendor;
  const sourceModelDb = getSourceModelDb(sourceVendor);
  const sourceModelData = sourceModel ? sourceModelDb[sourceModel] : null;
  const targetPorts = targetModelData?.ports || [];

  // Build L2 interface lookup from intermediateConfig
  const l2InterfaceSet = useMemo(() => {
    const s = new Set();
    for (const l2if of (intermediateConfig?.l2_interfaces || [])) {
      s.add(l2if.name);
    }
    // Also mark interfaces in virtual-wire pairs
    for (const vw of (intermediateConfig?.vwire_pairs || [])) {
      if (vw.interface1) s.add(vw.interface1);
      if (vw.interface2) s.add(vw.interface2);
    }
    return s;
  }, [intermediateConfig]);

  // Get all PAN-OS interfaces from zones
  const zoneInterfaces = useMemo(() => {
    const result = [];
    for (const zone of (intermediateConfig?.zones || [])) {
      for (const iface of (zone.interfaces || [])) {
        result.push({ zoneName: zone.name, panosIface: iface, isL2: l2InterfaceSet.has(iface) || zone.zone_type === 'layer2' || zone.zone_type === 'virtual-wire' });
      }
    }
    return result;
  }, [intermediateConfig, l2InterfaceSet]);

  // Track which SRX ports are already assigned (only physical ones)
  const assignedSrxPorts = useMemo(() => {
    return new Set(
      Object.entries(mappings)
        .filter(([panos]) => !isTunnelInterface(panos) && !isLoopbackInterface(panos))
        .map(([, srx]) => srx)
    );
  }, [mappings]);

  /** Lookup PAN-OS port info from the model DB */
  const getSourcePortInfo = (ifaceName) => {
    if (isTunnelInterface(ifaceName)) return { name: ifaceName, type: 'tunnel', speed: 'virtual', label: ifaceName };
    if (isLoopbackInterface(ifaceName)) return { name: ifaceName, type: 'loopback', speed: 'virtual', label: ifaceName };
    if (!sourceModelData) return null;
    const base = ifaceName.split('.')[0];
    return sourceModelData.ports.find(p => p.name === base) || null;
  };

  /** Lookup SRX port info from the model DB */
  const getTargetPortInfo = (ifaceName) => {
    if (!ifaceName) return null;
    // Virtual/tunnel interfaces
    if (ifaceName.startsWith('st0') || ifaceName.startsWith('gr-') || ifaceName.startsWith('ip-') || ifaceName.startsWith('lo0')) {
      return { name: ifaceName, type: 'tunnel', speed: 'virtual', label: ifaceName };
    }
    if (!targetModelData) return null;
    const base = ifaceName.split('.')[0];
    return targetModelData.ports.find(p => p.name === base) || null;
  };

  /** Update a single physical mapping */
  const handleMappingChange = (panosIface, srxIface) => {
    setMappings(prev => ({
      ...prev,
      [panosIface]: srxIface,
    }));
  };

  /** Update tunnel type for a tunnel interface */
  const handleTunnelTypeChange = (panosIface, tunnelType) => {
    setTunnelTypes(prev => ({ ...prev, [panosIface]: tunnelType }));
    // Update the mapping with new type + existing unit
    const unit = tunnelUnits[panosIface] || getUnit(panosIface);
    setMappings(prev => ({
      ...prev,
      [panosIface]: `${tunnelType}.${unit}`,
    }));
  };

  /** Update tunnel unit number */
  const handleTunnelUnitChange = (panosIface, unit) => {
    setTunnelUnits(prev => ({ ...prev, [panosIface]: unit }));
    const tunnelType = tunnelTypes[panosIface] || 'st0';
    setMappings(prev => ({
      ...prev,
      [panosIface]: `${tunnelType}.${unit}`,
    }));
  };

  /** Apply mappings and close */
  const handleApply = () => {
    // Ensure all tunnel mappings are built before applying
    const finalMappings = { ...mappings };
    for (const zone of (intermediateConfig?.zones || [])) {
      for (const iface of (zone.interfaces || [])) {
        if (isTunnelInterface(iface) && !finalMappings[iface]) {
          const type = tunnelTypes[iface] || 'st0';
          const unit = tunnelUnits[iface] || getUnit(iface);
          finalMappings[iface] = `${type}.${unit}`;
        }
        if (isLoopbackInterface(iface) && !finalMappings[iface]) {
          finalMappings[iface] = `lo0.${getUnit(iface)}`;
        }
      }
    }
    onMappingComplete(finalMappings);
  };

  /** Extract max speed from a multi-rate string like "1/2.5/5/10G" → 10 */
  const maxSpeedGbps = (speedStr) => {
    const speedOrder = { '1G': 1, '2.5G': 2.5, '5G': 5, '10G': 10, '25G': 25, '40G': 40, '50G': 50, '100G': 100, '400G': 400 };
    if (speedOrder[speedStr]) return speedOrder[speedStr];
    // Multi-rate: "1/2.5/5/10G" or "40/100G"
    const parts = speedStr.replace(/G$/i, '').split('/');
    return Math.max(...parts.map(Number).filter(n => !isNaN(n)));
  };

  /** CSS-safe speed class from multi-rate string: "1/2.5/5/10G" → "speed-10G" */
  const speedClass = (speedStr) => {
    const gbps = maxSpeedGbps(speedStr);
    return `speed-${gbps}G`;
  };

  /** Check if port speeds are compatible */
  const getCompatibility = (sourcePort, targetPort) => {
    if (!sourcePort || !targetPort) return 'unknown';
    // Tunnel-to-tunnel is always fine
    if (sourcePort.type === 'tunnel' || sourcePort.type === 'loopback') return 'match';
    if (sourcePort.speed === targetPort.speed) return 'match';
    const srcSpeed = maxSpeedGbps(sourcePort.speed);
    const tgtSpeed = maxSpeedGbps(targetPort.speed);
    if (srcSpeed === tgtSpeed) return 'match';
    if (tgtSpeed >= srcSpeed) return 'upgrade';
    return 'downgrade';
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ width: 750 }}>
        <div className="modal-header">
          <h2>Interface Mapping</h2>
          <button className="modal-close" onClick={onClose}>x</button>
        </div>

        <div className="modal-subheader">
          <span>
            {sourceModel || 'PAN-OS'} <span style={{ color: 'var(--accent)', margin: '0 8px' }}>-&gt;</span> {targetModel || 'SRX'}
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Map each zone's interface to an SRX port or tunnel
          </span>
        </div>

        <div className="modal-body" style={{ maxHeight: '55vh', overflow: 'auto' }}>
          {zoneInterfaces.length === 0 ? (
            <div className="empty-state">
              <p>No zone interfaces found in the parsed config.</p>
            </div>
          ) : (
            <table className="mapping-table">
              <thead>
                <tr>
                  <th>Zone</th>
                  <th>PAN-OS Interface</th>
                  <th></th>
                  <th>SRX Interface</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {zoneInterfaces.map(({ zoneName, panosIface, isL2 }) => {
                  const isTunnel = isTunnelInterface(panosIface);
                  const isLoopback = isLoopbackInterface(panosIface);
                  const currentSrx = mappings[panosIface] || '';
                  const srcPort = getSourcePortInfo(panosIface);
                  const tgtPort = currentSrx ? getTargetPortInfo(currentSrx) : null;
                  const compat = getCompatibility(srcPort, tgtPort);

                  return (
                    <tr key={`${zoneName}-${panosIface}`} className={isTunnel ? 'tunnel-row' : isLoopback ? 'loopback-row' : ''}>
                      <td>
                        <span style={{ fontWeight: 600, color: 'var(--accent)' }}>{zoneName}</span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <code>{panosIface}</code>
                          {srcPort && (
                            <span className={`port-badge ${speedClass(srcPort.speed)}`}>
                              {srcPort.type === 'tunnel' ? 'Tunnel' : srcPort.type === 'loopback' ? 'Loopback' : `${srcPort.speed} ${srcPort.type}`}
                            </span>
                          )}
                          {isL2 && (
                            <span className="port-badge" style={{ background: '#1e40af', color: '#93c5fd', fontSize: 10, padding: '1px 5px' }}>
                              L2
                            </span>
                          )}
                        </div>
                      </td>
                      <td style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 16 }}>
                        -&gt;
                      </td>
                      <td>
                        {isTunnel ? (
                          /* Tunnel interface builder */
                          <div className="tunnel-builder">
                            <select
                              className="mapping-select tunnel-type-select"
                              value={tunnelTypes[panosIface] || 'st0'}
                              onChange={(e) => handleTunnelTypeChange(panosIface, e.target.value)}
                            >
                              {SRX_TUNNEL_TYPES.map(t => (
                                <option key={t.value} value={t.value} title={t.description}>
                                  {t.label}
                                </option>
                              ))}
                            </select>
                            <span className="tunnel-dot">.</span>
                            <input
                              type="number"
                              className="tunnel-unit-input"
                              value={tunnelUnits[panosIface] || getUnit(panosIface)}
                              onChange={(e) => handleTunnelUnitChange(panosIface, e.target.value)}
                              min="0"
                              max="9999"
                              title="Tunnel unit number"
                            />
                            <span className="port-badge speed-virtual" style={{ marginLeft: 6 }}>
                              {(tunnelTypes[panosIface] || 'st0') === 'st0' ? 'IPsec' :
                               (tunnelTypes[panosIface] || 'st0').startsWith('gr') ? 'GRE' : 'IP-IP'}
                            </span>
                          </div>
                        ) : isLoopback ? (
                          /* Loopback — auto-mapped to lo0.X */
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <code className="loopback-mapped">lo0.{getUnit(panosIface)}</code>
                            <span className="port-badge speed-virtual">Loopback</span>
                          </div>
                        ) : (
                          /* Physical port dropdown */
                          <>
                            <select
                              className="mapping-select"
                              value={currentSrx}
                              onChange={(e) => handleMappingChange(panosIface, e.target.value)}
                            >
                              <option value="">-- Select SRX Port --</option>
                              {targetPorts.map(port => {
                                const isAssigned = assignedSrxPorts.has(port.name) && mappings[panosIface] !== port.name;
                                return (
                                  <option
                                    key={port.name}
                                    value={port.name}
                                    disabled={isAssigned}
                                  >
                                    {port.name} ({port.speed} {port.type}){isAssigned ? ' [assigned]' : ''}
                                  </option>
                                );
                              })}
                            </select>
                            {tgtPort && tgtPort.type !== 'tunnel' && (
                              <span className={`port-badge ${speedClass(tgtPort.speed)}`} style={{ marginLeft: 6 }}>
                                {tgtPort.speed} {tgtPort.type}
                              </span>
                            )}
                          </>
                        )}
                      </td>
                      <td>
                        {isTunnel && (
                          <span style={{ color: 'var(--info)', fontSize: 12 }}>Create tunnel</span>
                        )}
                        {isLoopback && (
                          <span style={{ color: 'var(--info)', fontSize: 12 }}>Auto-mapped</span>
                        )}
                        {!isTunnel && !isLoopback && !currentSrx && (
                          <span style={{ color: 'var(--warning)', fontSize: 12 }}>Unmapped</span>
                        )}
                        {!isTunnel && !isLoopback && currentSrx && compat === 'match' && (
                          <span style={{ color: 'var(--success)', fontSize: 12 }}>Match</span>
                        )}
                        {!isTunnel && !isLoopback && currentSrx && compat === 'upgrade' && (
                          <span style={{ color: 'var(--info)', fontSize: 12 }}>Upgrade</span>
                        )}
                        {!isTunnel && !isLoopback && currentSrx && compat === 'downgrade' && (
                          <span style={{ color: 'var(--warning)', fontSize: 12 }}>Speed down</span>
                        )}
                        {isL2 && !isTunnel && !isLoopback && (
                          <span style={{ color: '#93c5fd', fontSize: 11, display: 'block' }}>family bridge</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        <div className="modal-footer">
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {Object.values(mappings).filter(v => v).length} of {zoneInterfaces.length} interfaces mapped
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary" onClick={handleApply}>
              Apply Mappings
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Builds a default mapping by assigning SRX ports in order.
 * Tunnel interfaces get st0.X, loopbacks get lo0.X.
 */
function buildDefaultMappings(intermediateConfig, targetModelData) {
  const mappings = {};

  const availablePorts = targetModelData ? [...targetModelData.ports] : [];
  const usedPorts = new Set();

  for (const zone of (intermediateConfig?.zones || [])) {
    for (const iface of (zone.interfaces || [])) {
      if (isTunnelInterface(iface)) {
        // Default tunnel mapping: st0.{unit}
        const unit = getUnit(iface);
        mappings[iface] = `st0.${unit}`;
      } else if (isLoopbackInterface(iface)) {
        // Default loopback mapping: lo0.{unit}
        const unit = getUnit(iface);
        mappings[iface] = `lo0.${unit}`;
      } else {
        // Find a matching physical port
        const port = availablePorts.find(p => !usedPorts.has(p.name));
        if (port) {
          mappings[iface] = port.name;
          usedPorts.add(port.name);
        }
      }
    }
  }

  return mappings;
}

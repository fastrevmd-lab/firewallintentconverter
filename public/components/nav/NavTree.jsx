import React, { useState, useCallback } from 'react';
import { useConfigContext } from '../../contexts/ConfigContext.jsx';
import { useConversionContext } from '../../contexts/ConversionContext.jsx';
import { useUIContext } from '../../contexts/UIContext.jsx';

/* ── Inline SVG Icons (16x16, stroke-based) ──────────────────────── */
const ICONS = {
  clipboard: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2" />
      <rect x="8" y="2" width="8" height="4" rx="1" />
    </svg>
  ),
  shield: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  box: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z" />
      <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
      <line x1="12" y1="22.08" x2="12" y2="12" />
    </svg>
  ),
  globe: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
    </svg>
  ),
  settings: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
    </svg>
  ),
  export: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  ),
};

/* ── Navigation structure ────────────────────────────────────────── */
const NAV_STRUCTURE = [
  { id: 'import', label: 'Import / Config', icon: 'clipboard', leaf: true },
  { id: 'sanitized', label: 'Sanitized Objects', icon: 'shield', leaf: true, sanitizedCount: true },
  { id: 'security', label: 'Security', icon: 'shield', children: [
    { id: 'rules', label: 'Policies', countKey: 'security_policies' },
    { id: 'nat', label: 'NAT Rules', countKey: 'nat_rules' },
    { id: 'zones', label: 'Zones', countKey: 'zones' },
    { id: 'screen', label: 'Screens', countKey: 'screen_config' },
    { id: 'decryption', label: 'SSL B&I', countKey: 'decryption_rules' },
    { id: 'pbf', label: 'PBF', countKey: 'pbf_rules' },
  ]},
  { id: 'objects', label: 'Objects', icon: 'box', children: [
    { id: 'objects', label: 'Addr/Svc/App', countFn: (ic) =>
      (ic?.address_objects?.length || 0) +
      (ic?.service_objects?.length || 0) +
      (ic?.applications?.length || 0)
    },
  ]},
  { id: 'network', label: 'Network', icon: 'globe', children: [
    { id: 'routing', label: 'Intf / Routing', countFn: (ic) =>
      (ic?.interfaces?.length || 0) + (ic?.static_routes?.length || 0)
    },
    { id: 'vpn', label: 'VPN', countKey: 'vpn_tunnels' },
    { id: 'dhcp', label: 'DHCP', countKey: 'dhcp_config' },
    { id: 'flow-monitoring', label: 'Flow Monitoring', countFn: (ic) => ic?.flow_monitoring_config?.collectors?.length || 0 },
  ]},
  { id: 'system', label: 'System', icon: 'settings', children: [
    { id: 'ha', label: 'HA', countFn: (ic) => ic?.ha_config?.enabled ? 1 : 0 },
    { id: 'qos', label: 'QoS', countKey: 'qos_config' },
    { id: 'syslog', label: 'Syslog', countKey: 'syslog_config' },
  ]},
  { id: 'output', label: 'Output', icon: 'export', children: [
    { id: 'output', label: 'SRX Config' },
    { id: 'warnings', label: 'Warnings', warnCount: true },
    { id: 'diff', label: 'Diff View' },
  ]},
];

/* ── Helper: get count for a child item ──────────────────────────── */
function getCount(child, intermediateConfig) {
  if (child.countFn) return child.countFn(intermediateConfig);
  if (child.countKey) {
    const val = intermediateConfig?.[child.countKey];
    if (Array.isArray(val)) return val.length;
    if (val && typeof val === 'object') return 1;
    return 0;
  }
  return 0;
}

/* ── NavTree Component ───────────────────────────────────────────── */
export default function NavTree({ collapsed }) {
  const { state: cfg } = useConfigContext();
  const { state: conv } = useConversionContext();
  const { state: ui, dispatch: uiDispatch } = useUIContext();

  const { intermediateConfig, isSanitized, sanitizationTable } = cfg;
  const { convertWarnings } = conv;
  const { editTab } = ui;
  const sanitizedCount = (isSanitized && sanitizationTable?.length) || 0;

  // All groups expanded by default
  const [expandedGroups, setExpandedGroups] = useState(
    () => new Set(NAV_STRUCTURE.filter(g => g.children).map(g => g.id))
  );

  const toggleGroup = useCallback((groupId) => {
    setExpandedGroups(prev => {
      const next = new Set(prev);
      if (next.has(groupId)) next.delete(groupId);
      else next.add(groupId);
      return next;
    });
  }, []);

  const setTab = useCallback((tabId) => {
    uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: tabId });
  }, [uiDispatch]);

  const warnCount = convertWarnings?.length || 0;

  return (
    <ul className="nav-tree">
      {NAV_STRUCTURE.map(group => {
        // Top-level leaf item (e.g., Import, Sanitized Objects)
        if (group.leaf) {
          // Hide Sanitized Objects when there's nothing to show
          if (group.sanitizedCount && sanitizedCount === 0) return null;

          return (
            <li key={group.id} className="nav-group">
              <div
                className={`nav-item${editTab === group.id ? ' active' : ''}`}
                style={{ paddingLeft: 12 }}
                onClick={() => setTab(group.id)}
              >
                <span className="nav-icon">{ICONS[group.icon]}</span>
                <span>{group.label}</span>
                {group.sanitizedCount && sanitizedCount > 0 && (
                  <span className="nav-badge">{sanitizedCount}</span>
                )}
              </div>
            </li>
          );
        }

        // Group with children
        const isExpanded = expandedGroups.has(group.id);

        return (
          <li key={group.id} className={`nav-group${isExpanded ? '' : ' collapsed'}`}>
            <button
              className="nav-group-header"
              onClick={() => toggleGroup(group.id)}
            >
              <span className="arrow">{'\u25BC'}</span>
              <span className="group-icon">{ICONS[group.icon]}</span>
              <span>{group.label}</span>
            </button>
            <ul className="nav-group-items">
              {group.children.map(child => {
                const count = child.warnCount ? warnCount : getCount(child, intermediateConfig);
                return (
                  <li
                    key={child.id}
                    className={`nav-item${editTab === child.id ? ' active' : ''}`}
                    onClick={() => setTab(child.id)}
                  >
                    <span>{child.label}</span>
                    {count > 0 && (
                      <span className={`nav-badge${child.warnCount && warnCount > 0 ? ' warn' : ''}`}>
                        {count}
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
          </li>
        );
      })}
    </ul>
  );
}

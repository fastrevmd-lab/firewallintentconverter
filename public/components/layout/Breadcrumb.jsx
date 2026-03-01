import React from 'react';
import { useUIContext } from '../../contexts/UIContext.jsx';

const PATHS = {
  import:     ['Import'],
  sanitized:  ['Sanitized Objects'],
  rules:      ['Security', 'Policies'],
  nat:        ['Security', 'NAT Rules'],
  zones:      ['Security', 'Zones'],
  screen:     ['Security', 'Screens'],
  objects:    ['Objects'],
  routing:    ['Network', 'Interfaces / Routing'],
  vpn:        ['Network', 'VPN'],
  dhcp:       ['Network', 'DHCP'],
  ha:         ['System', 'HA'],
  qos:        ['System', 'QoS'],
  syslog:     ['System', 'Syslog'],
  output:     ['Output', 'SRX Config'],
  warnings:   ['Output', 'Warnings'],
  diff:       ['Output', 'Diff View'],
  decryption: ['Security', 'SSL B&I'],
  pbf:        ['Security', 'PBF'],
};

export default function Breadcrumb() {
  const { state } = useUIContext();
  const parts = PATHS[state.editTab] || [state.editTab];

  return (
    <div className="breadcrumb">
      {parts.map((part, i) => {
        const isLast = i === parts.length - 1;
        return (
          <React.Fragment key={i}>
            {i > 0 && <span className="sep">/</span>}
            <span className={isLast ? 'current' : ''}>{part}</span>
          </React.Fragment>
        );
      })}
    </div>
  );
}

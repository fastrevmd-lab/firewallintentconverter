/**
 * SectionAcceptBar — Toolbar for section acceptance in SRX view.
 * Shows "Accept [label]" or "Accepted" button above each editor section.
 */
import React from 'react';
import { useConfigContext } from '../../contexts/ConfigContext.jsx';
import { useUIContext } from '../../contexts/UIContext.jsx';

export default function SectionAcceptBar({ sectionId, label }) {
  const { state: cfg, dispatch } = useConfigContext();
  const { state: ui } = useUIContext();

  if (ui.platformView !== 'srx') return null;

  const isAccepted = !!cfg.sectionAcceptance[sectionId];

  return (
    <div className="section-accept-bar">
      <button
        className={`btn btn-sm ${isAccepted ? 'btn-accepted' : 'btn-accept'}`}
        onClick={() => dispatch({ type: 'ACCEPT_SECTION', sectionId })}
        disabled={isAccepted}
      >
        {isAccepted ? `${label} Accepted` : `Accept ${label}`}
      </button>
    </div>
  );
}

import React from 'react';
import { useUIContext } from '../../contexts/UIContext.jsx';
import NavTree from '../nav/NavTree.jsx';

/**
 * LeftSidebar — Wraps NavTree in a collapsible sidebar container.
 */
export default function LeftSidebar() {
  const { state, dispatch } = useUIContext();
  const { leftSidebarCollapsed } = state;

  return (
    <div className={`app-sidebar${leftSidebarCollapsed ? ' collapsed' : ''}`}>
      <div className="sidebar-header">
        {!leftSidebarCollapsed && <span className="sidebar-title">Navigator</span>}
        <button
          className="sidebar-toggle"
          onClick={() => dispatch({ type: 'TOGGLE_SIDEBAR' })}
          title="Toggle sidebar (Ctrl+B)"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            {leftSidebarCollapsed
              ? <polyline points="9 18 15 12 9 6" />
              : <polyline points="15 18 9 12 15 6" />
            }
          </svg>
        </button>
      </div>
      <NavTree collapsed={leftSidebarCollapsed} />
    </div>
  );
}

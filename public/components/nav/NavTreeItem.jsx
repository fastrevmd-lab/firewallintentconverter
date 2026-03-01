import React from 'react';

/**
 * NavTreeItem — Single item in the navigation tree.
 *
 * @param {{ id: string, label: string, badge?: number|string, warn?: boolean }} item
 * @param {boolean} active
 * @param {() => void} onClick
 * @param {boolean} collapsed — sidebar is icon-only
 */
export default function NavTreeItem({ item, active, onClick, collapsed }) {
  return (
    <li
      className={`nav-item${active ? ' active' : ''}`}
      onClick={onClick}
      data-tooltip={collapsed ? item.label : undefined}
      data-tooltip-pos="right"
    >
      <span>{item.label}</span>
      {item.badge !== undefined && (
        <span className={`nav-badge${item.warn ? ' warn' : ''}`}>{item.badge}</span>
      )}
    </li>
  );
}

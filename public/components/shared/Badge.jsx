import React from 'react';

/**
 * Badge — Count badge for nav tree and tables.
 *
 * @param {number} count          — The count to display
 * @param {'default'|'warning'|'error'} type — Visual style
 */
export default function Badge({ count, type = 'default' }) {
  if (!count || count <= 0) return null;

  return (
    <span className={`nav-badge${type !== 'default' ? ` ${type}` : ''}`}>
      {count}
    </span>
  );
}

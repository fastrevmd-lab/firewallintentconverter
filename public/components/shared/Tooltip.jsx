import React from 'react';

/**
 * Tooltip — CSS-only hover tooltip.
 *
 * Wraps children in a span with data-tooltip/data-tooltip-pos attributes.
 * The actual tooltip rendering is handled by CSS in layout.css using
 * [data-tooltip]:hover::after.
 *
 * @param {string}                       text     — Tooltip text
 * @param {React.ReactNode}              children — Element to wrap
 * @param {'top'|'bottom'|'left'|'right'} position — Tooltip position (default: "top")
 */
export default function Tooltip({ text, children, position = 'top' }) {
  if (!text) return children;

  return (
    <span
      data-tooltip={text}
      data-tooltip-pos={position}
      style={{ display: 'inline-flex' }}
    >
      {children}
    </span>
  );
}

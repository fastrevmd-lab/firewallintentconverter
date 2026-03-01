import React, { useRef, useCallback } from 'react';

/**
 * ResizeHandle — Draggable divider between panels.
 *
 * @param {'vertical'|'horizontal'} direction
 * @param {(delta: number) => void} onResize
 * @param {() => void}              onDoubleClick — collapse toggle
 * @param {string}                  className     — extra classes
 */
export default function ResizeHandle({ direction = 'vertical', onResize, onDoubleClick, className = '' }) {
  const ref = useRef(null);
  const startPos = useRef(0);

  const handleMouseDown = useCallback((e) => {
    e.preventDefault();
    startPos.current = direction === 'vertical' ? e.clientX : e.clientY;
    ref.current?.classList.add('active');

    const onMouseMove = (ev) => {
      const current = direction === 'vertical' ? ev.clientX : ev.clientY;
      const delta = current - startPos.current;
      startPos.current = current;
      if (onResize) onResize(delta);
    };

    const onMouseUp = () => {
      ref.current?.classList.remove('active');
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
    };

    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
  }, [direction, onResize]);

  const cls = [
    'resize-handle',
    direction === 'vertical' ? 'resize-handle-v' : 'resize-handle-h',
    className,
  ].filter(Boolean).join(' ');

  return (
    <div
      ref={ref}
      className={cls}
      onMouseDown={handleMouseDown}
      onDoubleClick={onDoubleClick}
    />
  );
}

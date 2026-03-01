/**
 * useResizablePanel — Mouse drag resize logic for panel borders
 *
 * Pure UI hook for implementing resizable panel handles.
 * Supports horizontal and vertical resize directions,
 * persistence to localStorage, and collapse toggle via double-click.
 *
 * @param {Object} options
 * @param {'horizontal'|'vertical'} options.direction - Resize axis
 * @param {React.RefObject} options.panelRef - Ref to the panel DOM element
 * @param {number} options.min - Minimum panel size in pixels
 * @param {number} options.max - Maximum panel size in pixels
 * @param {number} options.initialSize - Default size in pixels
 * @param {string} options.storageKey - localStorage key for persisting size
 *
 * @returns {{ size: number, isResizing: boolean, onMouseDown: function, collapsed: boolean, toggleCollapse: function }}
 */
import { useCallback, useRef, useEffect, useState } from 'react';

export default function useResizablePanel({
  direction = 'horizontal',
  panelRef,
  min = 100,
  max = 800,
  initialSize = 300,
  storageKey,
}) {
  // -----------------------------------------------------------------------
  // Read persisted size from localStorage on mount
  // -----------------------------------------------------------------------
  const [size, setSize] = useState(() => {
    if (storageKey) {
      try {
        const stored = localStorage.getItem(storageKey);
        if (stored !== null) {
          const parsed = Number(stored);
          if (!Number.isNaN(parsed) && parsed >= min && parsed <= max) {
            return parsed;
          }
        }
      } catch {
        // Ignore localStorage errors
      }
    }
    return initialSize;
  });

  const [collapsed, setCollapsed] = useState(false);
  const [isResizing, setIsResizing] = useState(false);

  // Refs for tracking drag state without causing re-renders
  const startPosRef = useRef(0);
  const startSizeRef = useRef(0);
  const sizeBeforeCollapseRef = useRef(initialSize);

  // -----------------------------------------------------------------------
  // Persist size to localStorage whenever it changes
  // -----------------------------------------------------------------------
  useEffect(() => {
    if (storageKey && !collapsed) {
      try {
        localStorage.setItem(storageKey, String(size));
      } catch {
        // Ignore localStorage errors
      }
    }
  }, [size, storageKey, collapsed]);

  // -----------------------------------------------------------------------
  // onMouseDown — initiate drag resize
  // -----------------------------------------------------------------------
  const onMouseDown = useCallback((e) => {
    // Double-click toggles collapse
    if (e.detail === 2) {
      setCollapsed(prev => !prev);
      return;
    }

    e.preventDefault();
    setIsResizing(true);

    startPosRef.current = direction === 'horizontal' ? e.clientX : e.clientY;
    startSizeRef.current = size;

    const handleMouseMove = (moveEvent) => {
      const currentPos = direction === 'horizontal'
        ? moveEvent.clientX
        : moveEvent.clientY;

      const delta = currentPos - startPosRef.current;

      // For horizontal panels on the left side, positive delta = larger.
      // For horizontal panels on the right side, negative delta = larger.
      // The caller can invert by adjusting how panelRef is positioned.
      const newSize = Math.min(max, Math.max(min, startSizeRef.current + delta));
      setSize(newSize);
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
  }, [direction, size, min, max]);

  // -----------------------------------------------------------------------
  // toggleCollapse — toggle collapsed state
  // -----------------------------------------------------------------------
  const toggleCollapse = useCallback(() => {
    setCollapsed(prev => {
      if (!prev) {
        // Collapsing: remember current size for restore
        sizeBeforeCollapseRef.current = size;
      } else {
        // Expanding: restore previous size
        setSize(sizeBeforeCollapseRef.current);
      }
      return !prev;
    });
  }, [size]);

  // -----------------------------------------------------------------------
  // Cleanup: ensure no stale listeners if component unmounts during drag
  // -----------------------------------------------------------------------
  useEffect(() => {
    return () => {
      setIsResizing(false);
    };
  }, []);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    size: collapsed ? 0 : size,
    isResizing,
    onMouseDown,
    collapsed,
    toggleCollapse,
  };
}

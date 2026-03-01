/**
 * useVirtualScroll — Windowed rendering for large lists
 *
 * Renders only a viewport window of items from a flat list,
 * using spacer elements to maintain correct scroll position.
 * Supports fixed and variable row heights with measurement fallback.
 *
 * @param {Object} options
 * @param {Array}  options.items - Flat list of items to virtualize
 * @param {React.RefObject} options.containerRef - Ref to the scroll container element
 * @param {number} options.estimatedRowHeight - Default height per row in pixels
 * @param {number} [options.overscan=20] - Extra rows rendered above/below viewport
 * @param {function} [options.getItemKey] - (item, index) => string, for height cache keys
 * @param {function} [options.getItemHeight] - (item) => number|null, override for specific items
 *
 * @returns {{
 *   visibleItems: Array<{item: any, index: number}>,
 *   topSpacerHeight: number,
 *   bottomSpacerHeight: number,
 *   totalHeight: number,
 *   onScroll: function,
 *   measureRow: function,
 *   scrollToIndex: function,
 *   resetCache: function,
 * }}
 */
import { useState, useRef, useCallback, useEffect, useMemo } from 'react';

export default function useVirtualScroll({
  items,
  containerRef,
  estimatedRowHeight = 32,
  overscan = 20,
  getItemKey,
  getItemHeight,
}) {
  // ---------------------------------------------------------------------------
  // Refs for transient state (avoid re-render on every scroll frame)
  // ---------------------------------------------------------------------------
  const scrollTopRef = useRef(0);
  const rowHeightCache = useRef(new Map());
  const lastRangeRef = useRef({ start: 0, end: 0 });
  const rafIdRef = useRef(null);

  // ---------------------------------------------------------------------------
  // State — only updated when visible range changes or container resizes
  // ---------------------------------------------------------------------------
  const [containerHeight, setContainerHeight] = useState(600);
  const [renderTick, setRenderTick] = useState(0);

  // ---------------------------------------------------------------------------
  // Height lookup for a single item
  // ---------------------------------------------------------------------------
  const getHeight = useCallback((item, index) => {
    // Check override function first (for headers with known fixed height)
    if (getItemHeight) {
      const h = getItemHeight(item);
      if (h != null) return h;
    }
    // Check measurement cache
    const key = getItemKey ? getItemKey(item, index) : String(index);
    const cached = rowHeightCache.current.get(key);
    if (cached != null) return cached;
    // Fallback to estimate
    return estimatedRowHeight;
  }, [estimatedRowHeight, getItemKey, getItemHeight]);

  // ---------------------------------------------------------------------------
  // Compute visible range from current scroll position
  // ---------------------------------------------------------------------------
  const computeVisibleRange = useCallback(() => {
    const scrollTop = scrollTopRef.current;
    const count = items.length;
    if (count === 0) return { start: 0, end: 0, topSpacer: 0, bottomSpacer: 0, total: 0 };

    let accumulated = 0;
    let startIndex = 0;
    let topSpacer = 0;

    // Find first visible item
    for (let i = 0; i < count; i++) {
      const h = getHeight(items[i], i);
      if (accumulated + h > scrollTop) {
        startIndex = i;
        topSpacer = accumulated;
        break;
      }
      accumulated += h;
      if (i === count - 1) {
        startIndex = count;
        topSpacer = accumulated;
      }
    }

    // Find last visible item
    let endIndex = startIndex;
    const viewportEnd = scrollTop + containerHeight;
    accumulated = topSpacer;
    for (let i = startIndex; i < count; i++) {
      accumulated += getHeight(items[i], i);
      endIndex = i;
      if (accumulated >= viewportEnd) break;
    }

    // Apply overscan
    const overscanStart = Math.max(0, startIndex - overscan);
    const overscanEnd = Math.min(count - 1, endIndex + overscan);

    // Recalculate top spacer for overscan start
    let actualTopSpacer = 0;
    for (let i = 0; i < overscanStart; i++) {
      actualTopSpacer += getHeight(items[i], i);
    }

    // Calculate total height and bottom spacer
    let totalHeight = 0;
    for (let i = 0; i < count; i++) {
      totalHeight += getHeight(items[i], i);
    }
    let visibleHeight = 0;
    for (let i = overscanStart; i <= overscanEnd; i++) {
      visibleHeight += getHeight(items[i], i);
    }
    const bottomSpacer = totalHeight - actualTopSpacer - visibleHeight;

    return {
      start: overscanStart,
      end: overscanEnd,
      topSpacer: actualTopSpacer,
      bottomSpacer: Math.max(0, bottomSpacer),
      total: totalHeight,
    };
  }, [items, containerHeight, overscan, getHeight]);

  // ---------------------------------------------------------------------------
  // Current range (computed on every render tick)
  // ---------------------------------------------------------------------------
  const range = useMemo(() => {
    void renderTick; // dependency
    return computeVisibleRange();
  }, [computeVisibleRange, renderTick]);

  // ---------------------------------------------------------------------------
  // Build the visible items slice
  // ---------------------------------------------------------------------------
  const visibleItems = useMemo(() => {
    if (items.length === 0) return [];
    const result = [];
    for (let i = range.start; i <= Math.min(range.end, items.length - 1); i++) {
      result.push({ item: items[i], index: i });
    }
    return result;
  }, [items, range.start, range.end]);

  // ---------------------------------------------------------------------------
  // Scroll handler — RAF-batched, only re-renders when range changes
  // ---------------------------------------------------------------------------
  const onScroll = useCallback(() => {
    if (rafIdRef.current) cancelAnimationFrame(rafIdRef.current);
    rafIdRef.current = requestAnimationFrame(() => {
      const el = containerRef.current;
      if (!el) return;
      scrollTopRef.current = el.scrollTop;
      const newRange = computeVisibleRange();
      if (newRange.start !== lastRangeRef.current.start ||
          newRange.end !== lastRangeRef.current.end) {
        lastRangeRef.current = { start: newRange.start, end: newRange.end };
        setRenderTick(t => t + 1);
      }
    });
  }, [containerRef, computeVisibleRange]);

  // ---------------------------------------------------------------------------
  // measureRow — ref callback for each rendered <tr>
  // ---------------------------------------------------------------------------
  const measureRow = useCallback((index, element) => {
    if (!element || index < 0 || index >= items.length) return;
    const measured = element.getBoundingClientRect().height;
    if (measured <= 0) return;
    const key = getItemKey ? getItemKey(items[index], index) : String(index);
    const cached = rowHeightCache.current.get(key);
    if (cached != null && Math.abs(cached - measured) <= 2) return;
    rowHeightCache.current.set(key, measured);
    // Schedule recalculation if height changed significantly
    if (cached != null && Math.abs(cached - measured) > 2) {
      setRenderTick(t => t + 1);
    }
  }, [items, getItemKey]);

  // ---------------------------------------------------------------------------
  // scrollToIndex — programmatic scroll to make an item visible
  // ---------------------------------------------------------------------------
  const scrollToIndex = useCallback((index) => {
    const el = containerRef.current;
    if (!el || index < 0 || index >= items.length) return;
    let offset = 0;
    for (let i = 0; i < index; i++) {
      offset += getHeight(items[i], i);
    }
    const itemHeight = getHeight(items[index], index);
    const scrollTop = el.scrollTop;
    const viewportBottom = scrollTop + el.clientHeight;

    // Only scroll if the item is not already fully visible
    if (offset < scrollTop) {
      el.scrollTop = offset;
    } else if (offset + itemHeight > viewportBottom) {
      el.scrollTop = offset + itemHeight - el.clientHeight;
    }
  }, [containerRef, items, getHeight]);

  // ---------------------------------------------------------------------------
  // resetCache — clear measured heights (call on view mode change)
  // ---------------------------------------------------------------------------
  const resetCache = useCallback(() => {
    rowHeightCache.current.clear();
    lastRangeRef.current = { start: 0, end: 0 };
    setRenderTick(t => t + 1);
  }, []);

  // ---------------------------------------------------------------------------
  // ResizeObserver — update containerHeight when panel resizes
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    setContainerHeight(el.clientHeight);

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const h = entry.contentRect.height;
        if (h > 0) setContainerHeight(h);
      }
    });
    observer.observe(el);

    return () => {
      observer.disconnect();
      if (rafIdRef.current) cancelAnimationFrame(rafIdRef.current);
    };
  }, [containerRef]);

  // ---------------------------------------------------------------------------
  // Return public API
  // ---------------------------------------------------------------------------
  return {
    visibleItems,
    topSpacerHeight: range.topSpacer,
    bottomSpacerHeight: range.bottomSpacer,
    totalHeight: range.total,
    onScroll,
    measureRow,
    scrollToIndex,
    resetCache,
  };
}

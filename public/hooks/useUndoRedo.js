/**
 * useUndoRedo — Undo/redo operations hook
 *
 * Manages an undo/redo stack for intermediateConfig snapshots.
 * Uses UndoContext for stack state and ConfigContext for applying
 * snapshots back to the config.
 */
import { useCallback } from 'react';
import { useUndoContext } from '../contexts/UndoContext.jsx';
import { useConfigContext } from '../contexts/ConfigContext.jsx';

export default function useUndoRedo() {
  const { state: undoState, dispatch: undoDispatch } = useUndoContext();
  const { state: configState, dispatch: configDispatch } = useConfigContext();

  const { past, future } = undoState;

  // -----------------------------------------------------------------------
  // pushSnapshot — deep-clone current intermediateConfig onto the undo stack
  // -----------------------------------------------------------------------
  const pushSnapshot = useCallback(() => {
    if (!configState.intermediateConfig) return;
    const snapshot = structuredClone(configState.intermediateConfig);
    undoDispatch({ type: 'PUSH', snapshot });
  }, [configState.intermediateConfig, undoDispatch]);

  // -----------------------------------------------------------------------
  // undo — pop from past, push current to future, apply snapshot to config
  // -----------------------------------------------------------------------
  const undo = useCallback(() => {
    if (!past || past.length === 0) return;

    // Save current state to future
    const currentSnapshot = configState.intermediateConfig
      ? structuredClone(configState.intermediateConfig)
      : null;

    // Pop from past
    const previousSnapshot = past[past.length - 1];

    undoDispatch({ type: 'UNDO', currentConfig: currentSnapshot });

    // Apply the previous snapshot to config
    if (previousSnapshot) {
      configDispatch({
        type: 'SET_FIELD',
        field: 'intermediateConfig',
        value: previousSnapshot,
      });
    }
  }, [past, configState.intermediateConfig, undoDispatch, configDispatch]);

  // -----------------------------------------------------------------------
  // redo — pop from future, push current to past, apply snapshot to config
  // -----------------------------------------------------------------------
  const redo = useCallback(() => {
    if (!future || future.length === 0) return;

    // Save current state to past
    const currentSnapshot = configState.intermediateConfig
      ? structuredClone(configState.intermediateConfig)
      : null;

    // Pop from future
    const nextSnapshot = future[future.length - 1];

    undoDispatch({ type: 'REDO', currentConfig: currentSnapshot });

    // Apply the next snapshot to config
    if (nextSnapshot) {
      configDispatch({
        type: 'SET_FIELD',
        field: 'intermediateConfig',
        value: nextSnapshot,
      });
    }
  }, [future, configState.intermediateConfig, undoDispatch, configDispatch]);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    undo,
    redo,
    pushSnapshot,
    canUndo: !!(past && past.length > 0),
    canRedo: !!(future && future.length > 0),
    historySize: (past?.length || 0) + (future?.length || 0),
  };
}

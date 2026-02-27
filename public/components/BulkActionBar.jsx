/**
 * BulkActionBar Component
 *
 * Floating action bar that appears when 2+ rules are selected in the PolicyTable.
 * Provides batch operations: accept, enable/disable, move, and delete.
 */
import React from 'react';

export default function BulkActionBar({
  selectedCount,
  onAcceptAll,
  onDeleteSelected,
  onToggleDisable,
  onMoveUp,
  onMoveDown,
  onClearSelection,
}) {
  if (selectedCount < 2) return null;

  return (
    <div className="bulk-action-bar">
      <span className="bulk-action-count">{selectedCount} rules selected</span>
      <div className="bulk-action-buttons">
        <button className="btn btn-sm bulk-btn bulk-btn-accept" onClick={onAcceptAll} title="Accept all selected rules">
          Accept All
        </button>
        <button className="btn btn-sm bulk-btn bulk-btn-disable" onClick={onToggleDisable} title="Toggle enable/disable on selected">
          Enable/Disable
        </button>
        <button className="btn btn-sm bulk-btn bulk-btn-move" onClick={onMoveUp} title="Move selected rules up">
          Move Up
        </button>
        <button className="btn btn-sm bulk-btn bulk-btn-move" onClick={onMoveDown} title="Move selected rules down">
          Move Down
        </button>
        <button className="btn btn-sm bulk-btn bulk-btn-delete" onClick={onDeleteSelected} title="Delete all selected rules">
          Delete Selected
        </button>
      </div>
      <button className="btn-icon" onClick={onClearSelection} title="Clear selection">
        x
      </button>
    </div>
  );
}

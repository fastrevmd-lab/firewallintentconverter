import React, { useState } from 'react';

export default function SaveProjectModal({ defaultName, onSave, onClose }) {
  const [name, setName] = useState(defaultName);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 440 }}>
        <div className="modal-header">
          <h2>Save Project</h2>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body" style={{ padding: '16px 20px' }}>
          <label style={{ display: 'block' }}>
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>
              Project Name
            </span>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              className="input-field"
              style={{ width: '100%' }}
              placeholder="my-firewall-project"
              autoFocus
              onKeyDown={e => { if (e.key === 'Enter' && name.trim()) onSave(name.trim()); }}
            />
          </label>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
            Saves all parsed data, interface mappings, model selections, review status,
            warnings, and any LLM-translated policies to a .fpic.json file.
          </p>
        </div>
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-primary"
            onClick={() => name.trim() && onSave(name.trim())}
            disabled={!name.trim()}
          >
            Save Project
          </button>
        </div>
      </div>
    </div>
  );
}

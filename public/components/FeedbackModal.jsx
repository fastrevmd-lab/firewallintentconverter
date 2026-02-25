import React, { useState } from 'react';

const CATEGORIES = [
  { value: 'feature', label: 'Feature Request', ghLabel: 'enhancement' },
  { value: 'bug', label: 'Bug Report', ghLabel: 'bug' },
  { value: 'improvement', label: 'Improvement', ghLabel: 'improvement' },
];

const REPO_URL = 'https://github.com/fastrevmd-lab/firewall-intent-converter';

export default function FeedbackModal({ onClose }) {
  const [category, setCategory] = useState('feature');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');

  const handleSubmit = () => {
    const cat = CATEGORIES.find(c => c.value === category);
    const issueTitle = encodeURIComponent(title || `[${cat.label}]`);
    const issueBody = encodeURIComponent(description);
    const labels = encodeURIComponent(cat.ghLabel);
    const url = `${REPO_URL}/issues/new?title=${issueTitle}&body=${issueBody}&labels=${labels}`;
    window.open(url, '_blank', 'noopener');
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 500 }}>
        <div className="modal-header">
          <h2>Send Feedback</h2>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body" style={{ padding: '16px 20px' }}>
          <label style={{ display: 'block', marginBottom: 12 }}>
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Category</span>
            <select
              value={category}
              onChange={e => setCategory(e.target.value)}
              className="input-field"
              style={{ width: '100%' }}
            >
              {CATEGORIES.map(c => (
                <option key={c.value} value={c.value}>{c.label}</option>
              ))}
            </select>
          </label>

          <label style={{ display: 'block', marginBottom: 12 }}>
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Title</span>
            <input
              type="text"
              value={title}
              onChange={e => setTitle(e.target.value)}
              placeholder="Brief summary..."
              className="input-field"
              style={{ width: '100%' }}
            />
          </label>

          <label style={{ display: 'block' }}>
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Description</span>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Describe the bug, feature idea, or improvement..."
              rows={6}
              className="input-field"
              style={{ width: '100%', resize: 'vertical', fontFamily: 'inherit' }}
            />
          </label>

          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
            Opens a pre-filled GitHub Issue in a new tab. You can review and edit before submitting.
          </p>
        </div>
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-primary"
            onClick={handleSubmit}
            disabled={!description.trim()}
          >
            Open GitHub Issue
          </button>
        </div>
      </div>
    </div>
  );
}

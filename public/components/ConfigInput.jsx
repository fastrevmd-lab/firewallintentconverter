/**
 * ConfigInput Component
 *
 * Left panel for PAN-OS configuration input.
 * Supports:
 *   - Paste raw XML config text
 *   - Upload a config file (.xml, .txt)
 *   - Select a pre-loaded sample config for testing
 *   - Sanitize configuration to strip sensitive data
 *   - Show source/target model badges after parsing
 */
import React, { useRef } from 'react';
import { SAMPLE_CONFIGS } from './sample-configs.jsx';

export default function ConfigInput({
  configText,
  onConfigChange,
  onParse,
  onSanitize,
  isLoading,
  isParsed,
  isSanitized,
  sourceModel,
  targetModel,
  onOpenModels,
}) {
  const fileInputRef = useRef(null);

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      onConfigChange(event.target.result);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const loadSample = (sampleKey) => {
    const sample = SAMPLE_CONFIGS[sampleKey];
    if (sample) {
      onConfigChange(sample.xml);
    }
  };

  return (
    <div className="panel config-input-panel">
      <div className="panel-header">
        <h2>Source Configuration</h2>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>PAN-OS XML / Junos SRX</span>
      </div>

      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column' }}>
        {/* Model badges — shown after models are selected */}
        {isParsed && (sourceModel || targetModel) && (
          <div
            className="model-badges-bar"
            onClick={onOpenModels}
            title="Click to change models"
          >
            <div className="model-badge-item">
              <span className="model-badge-label">Source</span>
              <span className="model-badge-value">{sourceModel || 'Auto'}</span>
            </div>
            <span style={{ color: 'var(--accent)', fontSize: 14 }}>&rarr;</span>
            <div className="model-badge-item">
              <span className="model-badge-label">Target</span>
              <span className="model-badge-value">{targetModel || 'Not set'}</span>
            </div>
          </div>
        )}

        {/* Sanitization status badge */}
        {isSanitized && (
          <div className="sanitize-badge">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            Configuration sanitized — sensitive data replaced with placeholders
          </div>
        )}

        {/* File upload area */}
        <div
          className="file-upload-area"
          onClick={() => fileInputRef.current?.click()}
        >
          <p>Click to upload config file (.xml, .txt)</p>
          <p style={{ fontSize: '10px', marginTop: '4px' }}>or drag and drop</p>
          <input
            ref={fileInputRef}
            type="file"
            accept=".xml,.txt,.conf"
            onChange={handleFileUpload}
          />
        </div>

        {/* Sample config selector */}
        <div className="sample-selector">
          <label>Load Sample Config</label>
          <div className="sample-buttons">
            {Object.entries(SAMPLE_CONFIGS).map(([key, sample]) => (
              <button
                key={key}
                className="sample-btn"
                onClick={() => loadSample(key)}
                title={sample.description}
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>

        {/* Config textarea */}
        <textarea
          className="config-textarea"
          value={configText}
          onChange={(e) => onConfigChange(e.target.value)}
          placeholder={"Paste your firewall configuration here...\n\nSupported formats:\n• PAN-OS XML configuration\n• Junos SRX set commands\n• Junos SRX hierarchical config"}
          spellCheck={false}
          style={{ flex: 1 }}
        />

        {/* Sanitize button — above Parse */}
        <button
          className={`btn btn-block ${isSanitized ? 'btn-sanitized' : 'btn-sanitize'}`}
          onClick={onSanitize}
          disabled={isLoading || !configText.trim() || isSanitized}
          title="Remove passwords, hashes, public IPs, usernames — replaced with placeholders"
        >
          {isSanitized ? (
            <>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: 6 }}>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Configuration Sanitized
            </>
          ) : (
            'Sanitize Configuration'
          )}
        </button>

        {/* Parse button */}
        <button
          className="btn btn-primary btn-block"
          onClick={onParse}
          disabled={isLoading || !configText.trim()}
          style={{ marginTop: 4 }}
        >
          {isLoading ? (
            <>
              <span className="loading-spinner" style={{ width: 14, height: 14 }} />
              Parsing...
            </>
          ) : isParsed ? (
            'Re-Parse Configuration'
          ) : (
            'Parse Configuration'
          )}
        </button>
      </div>
    </div>
  );
}

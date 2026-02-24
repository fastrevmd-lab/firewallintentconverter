/**
 * ConfigInput Component
 *
 * Left panel for firewall configuration input.
 * Supports:
 *   - Greenfield mode: start a guided LLM interview (no existing config needed)
 *   - Paste raw config text (PAN-OS XML, SRX, FortiOS, Cisco ASA)
 *   - Upload a config file (.xml, .txt)
 *   - Select a pre-loaded sample config for testing
 *   - Sanitize configuration to strip sensitive data
 *   - Show source/target model badges after parsing
 */
import React, { useRef, useState } from 'react';
import { SAMPLE_CONFIGS } from './sample-configs.jsx';

export default function ConfigInput({
  configText,
  onConfigChange,
  onParse,
  onSanitize,
  onStartGreenfield,
  greenfieldMode,
  isLoading,
  isParsed,
  isSanitized,
  sourceModel,
  targetModel,
  onOpenModels,
}) {
  const fileInputRef = useRef(null);
  const [selectedVendor, setSelectedVendor] = useState('greenfield');

  const isGreenfield = selectedVendor === 'greenfield';

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
        <select
          className="vendor-select"
          value={selectedVendor}
          onChange={(e) => setSelectedVendor(e.target.value)}
          disabled={greenfieldMode || isParsed}
        >
          <option value="greenfield">Greenfield (New Config)</option>
          <option value="srx">Junos SRX</option>
          <option value="panos">PAN-OS</option>
          <option value="fortigate">FortiGate</option>
          <option value="cisco_asa">Cisco ASA/FTD</option>
          <option value="checkpoint">Check Point R80+</option>
          <option value="sonicwall">SonicWall SonicOS</option>
          <option value="huawei_usg">Huawei USG</option>
        </select>
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
              <span className="model-badge-value">{greenfieldMode ? 'Greenfield' : sourceModel || 'Auto'}</span>
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

        {isGreenfield ? (
          /* ---- Greenfield mode ---- */
          greenfieldMode ? (
            <div className="empty-state" style={{ flex: 1 }}>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
              </svg>
              <h3>Greenfield Interview Active</h3>
              <p>The LLM is building your SRX configuration in the center panel. Toggle between "from LLM Interview" and "to SRX" tabs to see the config building in real-time.</p>
            </div>
          ) : (
            <div className="empty-state" style={{ flex: 1 }}>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                <line x1="8" y1="21" x2="16" y2="21" />
                <line x1="12" y1="17" x2="12" y2="21" />
              </svg>
              <h3>Build a New SRX Configuration</h3>
              <p>Start a guided interview with an AI assistant to build your SRX firewall configuration from scratch. No existing configuration needed.</p>
              <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: 8 }}>
                The AI will ask about your deployment use case, network architecture, and security requirements, then progressively build the configuration for you.
              </p>
              <button
                className="btn btn-primary btn-block"
                onClick={onStartGreenfield}
                disabled={isLoading}
                style={{ marginTop: 16 }}
              >
                Start Interview
              </button>
            </div>
          )
        ) : (
          /* ---- Normal import mode ---- */
          <>
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

            {/* Sample config selector — filtered by selected vendor */}
            <div className="sample-selector">
              <label>Load Sample Config</label>
              <div className="sample-buttons">
                {Object.entries(SAMPLE_CONFIGS)
                  .filter(([, sample]) => sample.vendor === selectedVendor)
                  .map(([key, sample]) => (
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
              placeholder={selectedVendor === 'srx'
                ? "Paste your Junos SRX configuration here...\n\nSupported formats:\n\u2022 SRX set commands\n\u2022 SRX hierarchical config"
                : selectedVendor === 'fortigate'
                ? "Paste your FortiGate configuration here...\n\nSupported format:\n\u2022 FortiOS config (config/edit/set/next/end)"
                : selectedVendor === 'cisco_asa'
                ? "Paste your Cisco ASA/FTD configuration here...\n\nSupported formats:\n\u2022 ASA running-config (access-list, object, nat)\n\u2022 FTD show running-config output"
                : selectedVendor === 'checkpoint'
                ? "Paste your Check Point configuration here...\n\nSupported formats:\n\u2022 mgmt_cli JSON (show-access-rulebase)\n\u2022 ShowPolicyPackage JSON export\n\u2022 Optional: Gaia clish after JSON"
                : selectedVendor === 'sonicwall'
                ? "Paste your SonicWall configuration here...\n\nSupported formats:\n\u2022 REST API JSON (/api/sonicos/* combined)\n\u2022 CLI text (show current-config)"
                : selectedVendor === 'huawei_usg'
                ? "Paste your Huawei USG configuration here...\n\nSupported format:\n\u2022 VRP CLI (display current-configuration)"
                : "Paste your PAN-OS configuration here...\n\nSupported format:\n\u2022 PAN-OS XML configuration"
              }
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
          </>
        )}
      </div>
    </div>
  );
}

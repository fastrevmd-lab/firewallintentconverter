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
import { GREENFIELD_TEMPLATES } from '../data/greenfield-templates.js';

const TEMPLATE_ICONS = {
  building: (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="4" y="2" width="16" height="20" rx="1" />
      <line x1="8" y1="6" x2="8" y2="6.01" /><line x1="12" y1="6" x2="12" y2="6.01" /><line x1="16" y1="6" x2="16" y2="6.01" />
      <line x1="8" y1="10" x2="8" y2="10.01" /><line x1="12" y1="10" x2="12" y2="10.01" /><line x1="16" y1="10" x2="16" y2="10.01" />
      <line x1="8" y1="14" x2="8" y2="14.01" /><line x1="12" y1="14" x2="12" y2="14.01" /><line x1="16" y1="14" x2="16" y2="14.01" />
      <rect x="9" y="18" width="6" height="4" />
    </svg>
  ),
  server: (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  ),
  globe: (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
    </svg>
  ),
  user: (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" />
    </svg>
  ),
  cloud: (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z" />
    </svg>
  ),
  plus: (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  ),
};

const SANITIZE_TYPE_LABELS = {
  hash: 'Hash', key: 'Key', community: 'SNMP', username: 'User', public_ip: 'Public IP',
};

function maskSensitiveValue(entry) {
  if (entry.type === 'public_ip') return entry.original;
  const val = entry.original || '';
  if (val.length <= 4) return '****';
  return val.substring(0, 3) + '****';
}

function formatSanitizeStats(table) {
  const counts = {};
  for (const entry of table) {
    const label = SANITIZE_TYPE_LABELS[entry.type] || entry.type;
    counts[label] = (counts[label] || 0) + 1;
  }
  return Object.entries(counts).map(([label, count]) => `${count} ${label}${count > 1 ? 's' : ''}`).join(', ');
}

export default function ConfigInput({
  configText,
  onConfigChange,
  onParse,
  onFileLoaded,
  onStartGreenfield,
  onStartGreenfieldWithTemplate,
  greenfieldMode,
  isLoading,
  isParsed,
  isSanitized,
  sanitizationTable,
  sourceModel,
  targetModel,
  onOpenModels,
  // Merge mode props
  mergeMode,
  configSlots = [],
  activeSlotIndex = 0,
  onActivateSlot,
  onAddSlot,
  onRemoveSlot,
  onUpdateSlotLsName,
}) {
  const fileInputRef = useRef(null);
  const [selectedVendor, setSelectedVendor] = useState('greenfield');
  const [showSanitizeTable, setShowSanitizeTable] = useState(false);

  const isGreenfield = selectedVendor === 'greenfield';

  const [uploadError, setUploadError] = useState('');

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadError('');

    // Validate file size (10 MB max — matches server payload limit)
    const MAX_FILE_SIZE = 10 * 1024 * 1024;
    if (file.size > MAX_FILE_SIZE) {
      setUploadError(`File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum is 10 MB.`);
      e.target.value = '';
      return;
    }

    // Validate file type — allow config-related extensions and plain text MIME
    const allowedExtensions = ['.xml', '.txt', '.conf', '.cfg', '.log', '.json'];
    const ext = file.name.toLowerCase().slice(file.name.lastIndexOf('.'));
    const allowedMimes = ['text/', 'application/xml', 'application/json', 'application/octet-stream', ''];
    if (!allowedExtensions.includes(ext) && !allowedMimes.some(m => (file.type || '').startsWith(m))) {
      setUploadError(`Unsupported file type "${ext}". Use .xml, .txt, .conf, .cfg, or .json files.`);
      e.target.value = '';
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      onConfigChange(event.target.result);
      // Auto-trigger sanitize + parse after file load
      if (onFileLoaded) onFileLoaded(event.target.result, selectedVendor);
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
    <div className="panel config-input-panel" data-tour="config-input" style={{ flex: 1, minHeight: 0 }}>
      <div className="panel-header">
        <h2>Source Configuration</h2>
        <select
          className="vendor-select"
          value={selectedVendor}
          onChange={(e) => setSelectedVendor(e.target.value)}
          disabled={greenfieldMode || isParsed}
        >
          <option value="greenfield">Greenfield (New Config)</option>
          <option value="srx_healthcheck">Junos SRX Best Practice</option>
          <option value="srx">Junos SRX</option>
          <option value="panos">PAN-OS</option>
          <option value="fortigate">FortiGate</option>
          <option value="cisco_asa">Cisco ASA/FTD</option>
          <option value="checkpoint">Check Point R80+</option>
          <option value="sonicwall">SonicWall SonicOS</option>
          <option value="huawei_usg">Huawei USG</option>
        </select>
      </div>

      {/* Merge mode: slot tab bar */}
      {mergeMode && (
        <div className="merge-slot-tabs">
          {configSlots.map((slot, i) => {
            const vendorLabel = { panos: 'PA', srx: 'SRX', fortigate: 'FG', cisco_asa: 'ASA', checkpoint: 'CP', sonicwall: 'SW', huawei_usg: 'HW' }[slot.sourceVendor] || '';
            return (
              <div
                key={slot.id}
                className={`merge-slot-tab ${i === activeSlotIndex ? 'active' : ''}`}
                onClick={() => onActivateSlot(i)}
              >
                <input
                  className="merge-slot-name"
                  value={slot.lsName}
                  onChange={(e) => onUpdateSlotLsName(i, e.target.value)}
                  onClick={(e) => e.stopPropagation()}
                />
                {slot.intermediateConfig ? (
                  <span className="merge-slot-vendor-badge">{vendorLabel}</span>
                ) : (
                  <span className="merge-slot-empty-badge">--</span>
                )}
                {configSlots.length > 2 && (
                  <button
                    className="merge-slot-remove"
                    onClick={(e) => { e.stopPropagation(); onRemoveSlot(i); }}
                    title="Remove this config slot"
                  >
                    x
                  </button>
                )}
              </div>
            );
          })}
          <button className="merge-slot-add" onClick={onAddSlot} title="Add another config slot">
            +
          </button>
        </div>
      )}

      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
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
            <div className="template-picker" style={{ flex: 1, overflow: 'auto', padding: '12px' }}>
              <h3 style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12, textAlign: 'center', fontWeight: 500 }}>
                Choose a starting template
              </h3>
              <div className="template-grid">
                {Object.entries(GREENFIELD_TEMPLATES).map(([id, tpl]) => (
                  <button
                    key={id}
                    className="template-card"
                    onClick={() => id === 'blank' ? onStartGreenfield() : onStartGreenfieldWithTemplate(id)}
                    disabled={isLoading}
                  >
                    <div className="template-card-icon">
                      {TEMPLATE_ICONS[tpl.icon] || TEMPLATE_ICONS.plus}
                    </div>
                    <div className="template-card-title">{tpl.label}</div>
                    <div className="template-card-desc">{tpl.description}</div>
                    {id !== 'blank' && tpl.config && (
                      <div className="template-card-stats">
                        <span>{tpl.config.zones?.length || 0} zones</span>
                        <span>{tpl.config.security_policies?.length || 0} rules</span>
                      </div>
                    )}
                  </button>
                ))}
              </div>
              <p style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: 10, textAlign: 'center', lineHeight: 1.5 }}>
                Templates pre-fill zones, policies, NAT, and system basics.
                The AI chat will open for customization.
              </p>
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
                accept=".xml,.txt,.conf,.cfg,.json"
                onChange={handleFileUpload}
              />
            </div>
            {uploadError && (
              <div className="upload-error" style={{ color: 'var(--error, #e74c3c)', fontSize: 11, padding: '4px 8px', background: 'rgba(231,76,60,0.08)', borderRadius: 4 }}>
                {uploadError}
              </div>
            )}

            {/* Sample config selector — filtered by selected vendor */}
            <div className="sample-selector">
              <label>Load Sample Config</label>
              <div className="sample-buttons">
                {Object.entries(SAMPLE_CONFIGS)
                  .filter(([, sample]) => sample.vendor === (selectedVendor === 'srx_healthcheck' ? 'srx' : selectedVendor))
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

            {/* Parse button */}
            <button
              className="btn btn-primary btn-block"
              data-tour="parse-btn"
              onClick={() => onParse(selectedVendor)}
              disabled={isLoading || !configText.trim()}
              style={{ marginBottom: 4 }}
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

            {/* Config textarea */}
            <textarea
              className="config-textarea"
              value={configText}
              maxLength={10 * 1024 * 1024}
              onChange={(e) => onConfigChange(e.target.value)}
              placeholder={selectedVendor === 'srx_healthcheck'
                ? "Paste your Junos SRX configuration here for a best practice audit...\n\nThe audit will assess:\n\u2022 PCI DSS v4.0 compliance\n\u2022 NIST SP 800-41r1 compliance\n\u2022 CIS Juniper OS Benchmark\n\u2022 Logging completeness\n\u2022 Security profile coverage\n\u2022 Rule hygiene & optimization"
                : selectedVendor === 'srx'
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

          </>
        )}
      </div>
    </div>
  );
}

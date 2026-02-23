/**
 * ModelSelector Component
 *
 * Modal shown after parsing to select:
 *   1. Source PAN-OS firewall model (auto-detected with confidence, overridable)
 *   2. Target Juniper SRX model (required, with throughput-based recommendation)
 *
 * Throughput metric toggle: L4 Firewall / L7 Application / IPS/Threat
 * Changing the metric re-calculates the recommended SRX model.
 *
 * Also collects SRX license level (A1/A2/P1/P2) for feature gating.
 */
import React, { useState, useEffect, useMemo } from 'react';
import {
  PANOS_MODELS,
  SRX_MODELS,
  SRX_SOURCE_MODELS,
  FORTIGATE_SOURCE_MODELS,
  CISCO_SOURCE_MODELS,
  detectPanosModel,
  detectSrxModel,
  detectFortigateModel,
  detectCiscoModel,
  suggestSrxModel,
  getThroughputDisplay,
  THROUGHPUT_LABELS,
  METRIC_PREFIX,
  SRX4700_PORT_PROFILES,
  SRX4700_DEFAULT_PROFILE,
  getSrx4700Ports,
} from '../data/hardware-db.js';
import { SRX_LICENSE_TIERS } from '../utils/srx-view-transforms.js';

export default function ModelSelector({
  intermediateConfig,
  sourceModel,
  targetModel,
  srxLicense,
  sourceVendor,
  onModelSelection,
  onContinue,
  onClose,
}) {
  const [selectedSource, setSelectedSource] = useState(sourceModel || '');
  const [selectedTarget, setSelectedTarget] = useState(targetModel || '');
  const [selectedLicense, setSelectedLicense] = useState(srxLicense || '');
  const [selectedPortProfile, setSelectedPortProfile] = useState(SRX4700_DEFAULT_PROFILE);
  const [detection, setDetection] = useState(null);
  const [throughputMetric, setThroughputMetric] = useState('l7');
  const [recommendedSrx, setRecommendedSrx] = useState(null); // { model, recommended }
  const [subscriptionError, setSubscriptionError] = useState('');

  const isSrxSource = sourceVendor === 'srx';
  const isFortigateSource = sourceVendor === 'fortigate';
  const isCiscoSource = sourceVendor === 'cisco_asa';

  // Auto-detect source model on mount
  useEffect(() => {
    if (intermediateConfig && !sourceModel) {
      let detected;
      if (isSrxSource) {
        detected = detectSrxModel(intermediateConfig);
      } else if (isFortigateSource) {
        detected = detectFortigateModel(intermediateConfig);
      } else if (isCiscoSource) {
        detected = detectCiscoModel(intermediateConfig);
      } else {
        detected = detectPanosModel(intermediateConfig);
      }
      setDetection(detected);
      if (detected) {
        setSelectedSource(detected.model);
      }
    }
  }, [intermediateConfig, sourceModel, isSrxSource, isFortigateSource, isCiscoSource]);

  // Re-suggest SRX whenever source or metric changes
  useEffect(() => {
    if (selectedSource) {
      const suggestion = suggestSrxModel(selectedSource, throughputMetric);
      setRecommendedSrx(suggestion);
      if (suggestion) {
        setSelectedTarget(suggestion.model);
      }
    }
  }, [selectedSource, throughputMetric]);

  const sourceModelsDb = isSrxSource ? SRX_SOURCE_MODELS : isFortigateSource ? FORTIGATE_SOURCE_MODELS : isCiscoSource ? CISCO_SOURCE_MODELS : PANOS_MODELS;
  const sourceInfo = sourceModelsDb[selectedSource];
  const targetRaw = SRX_MODELS[selectedTarget];
  // Override ports when an SRX4700 port profile is selected
  const targetInfo = useMemo(() => {
    if (!targetRaw?.hasPortProfiles) return targetRaw;
    return { ...targetRaw, ports: getSrx4700Ports(selectedPortProfile) };
  }, [targetRaw, selectedPortProfile]);

  // Group models by tier for dropdown optgroups
  const sourceGroups = useMemo(() => groupByTier(sourceModelsDb), [isSrxSource, isFortigateSource, isCiscoSource]);
  const srxGroups = useMemo(() => groupByTier(SRX_MODELS), []);

  const metricLabel = METRIC_PREFIX[throughputMetric] || 'L7';

  const handleContinue = () => {
    if (selectedTarget && !selectedLicense) {
      setSubscriptionError('Please select an SRX subscription before continuing to interface mapping.');
      return;
    }
    setSubscriptionError('');
    onModelSelection({
      sourceModel: selectedSource || null,
      targetModel: selectedTarget || null,
      srxLicense: selectedLicense || null,
      portProfile: targetRaw?.hasPortProfiles ? selectedPortProfile : null,
    });
    onContinue();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ width: 580 }}>
        <div className="modal-header">
          <h2>Hardware Model Selection</h2>
          <button className="modal-close" onClick={onClose}>x</button>
        </div>

        <div className="modal-body">
          <p style={{ fontSize: 10, color: 'var(--text-muted)', margin: '0 0 10px', lineHeight: 1.4 }}>
            Throughput numbers are best effort based on publicly available data. Do your own research.
          </p>
          {/* Throughput metric toggle */}
          <div className="throughput-toggle">
            <span className="throughput-toggle-label">Show throughput as:</span>
            <div className="throughput-toggle-options">
              {[
                { key: 'l4', label: 'L4 Firewall' },
                { key: 'l7', label: 'L7 Application' },
                { key: 'threat', label: 'IPS / Threat' },
              ].map(opt => (
                <label key={opt.key} className={`throughput-radio${throughputMetric === opt.key ? ' active' : ''}`}>
                  <input
                    type="radio"
                    name="throughputMetric"
                    value={opt.key}
                    checked={throughputMetric === opt.key}
                    onChange={() => setThroughputMetric(opt.key)}
                  />
                  {opt.label}
                </label>
              ))}
            </div>
          </div>

          {/* Source Model */}
          <div className="model-section">
            <h3 className="model-section-title">
              Source Firewall ({isSrxSource ? 'Juniper SRX' : isFortigateSource ? 'FortiGate' : isCiscoSource ? 'Cisco ASA/FTD' : 'PAN-OS'})
            </h3>

            {detection && (
              <div className="detection-banner">
                Auto-detected: <strong>{detection.model}</strong>
                <span className="confidence-badge">
                  {Math.round(detection.confidence * 100)}% confidence
                </span>
              </div>
            )}

            <select
              className="model-select"
              value={selectedSource}
              onChange={(e) => setSelectedSource(e.target.value)}
            >
              <option value="">-- Select {isSrxSource ? 'SRX' : isFortigateSource ? 'FortiGate' : isCiscoSource ? 'Cisco' : 'PAN-OS'} Model (optional) --</option>
              {Object.entries(sourceGroups).map(([tier, models]) => (
                <optgroup key={tier} label={tierLabel(tier)}>
                  {models.map(m => (
                    <option key={m.name} value={m.name}>
                      {m.name}{m.eol ? ' (EoS)' : ''} — {m.ports.length} ports ({metricLabel}: {getThroughputDisplay(m, throughputMetric)})
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>

            {sourceInfo && (
              <ModelInfoCard model={sourceInfo} vendor={isSrxSource ? 'srx' : isFortigateSource ? 'fortigate' : isCiscoSource ? 'cisco_asa' : 'panos'} metric={throughputMetric} />
            )}
          </div>

          {/* Target SRX Model */}
          <div className="model-section" style={{ marginTop: 20 }}>
            <h3 className="model-section-title">Target Firewall (Juniper SRX)</h3>

            <select
              className="model-select"
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
            >
              <option value="">-- Select SRX Model --</option>
              {Object.entries(srxGroups).map(([tier, models]) => (
                <optgroup key={tier} label={tierLabel(tier)}>
                  {models.map(m => {
                    const isRec = recommendedSrx?.model === m.name && recommendedSrx?.recommended;
                    return (
                      <option
                        key={m.name}
                        value={m.name}
                        style={m.current ? { color: '#34d399' } : undefined}
                      >
                        {m.name} — {m.ports.length} ports ({metricLabel}: {getThroughputDisplay(m, throughputMetric)}){isRec ? ' (Recommended)' : ''}
                      </option>
                    );
                  })}
                </optgroup>
              ))}
            </select>

            {recommendedSrx && recommendedSrx.recommended && selectedTarget === recommendedSrx.model && (
              <div className="recommended-banner">
                Recommended: matches or exceeds source {metricLabel} throughput
              </div>
            )}

            {targetInfo && (
              <ModelInfoCard model={targetInfo} vendor="srx" metric={throughputMetric} />
            )}
          </div>

          {/* SRX4700 Port Profile Selector */}
          {targetRaw?.hasPortProfiles && (
            <div className="model-section" style={{ marginTop: 16 }}>
              <h3 className="model-section-title">Port Profile</h3>
              <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '0 0 8px', lineHeight: 1.4 }}>
                The SRX4700 supports configurable port profiles per PIC. Each PIC uses the same profile. Totals shown are for both PICs combined.
              </p>
              <div className="license-tier-grid" style={{ gridTemplateColumns: '1fr' }}>
                {Object.entries(SRX4700_PORT_PROFILES).map(([key, profile]) => {
                  const ports = getSrx4700Ports(key);
                  const groups = {};
                  for (const p of ports) {
                    const k = `${p.speed} ${p.type}`;
                    groups[k] = (groups[k] || 0) + 1;
                  }
                  return (
                    <label
                      key={key}
                      className={`license-tier-card${selectedPortProfile === key ? ' active' : ''}`}
                      style={{ padding: '8px 12px' }}
                    >
                      <input
                        type="radio"
                        name="portProfile"
                        value={key}
                        checked={selectedPortProfile === key}
                        onChange={() => setSelectedPortProfile(key)}
                      />
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                        <div>
                          <div className="license-tier-name" style={{ fontSize: 13 }}>{profile.label}</div>
                          <div className="license-tier-desc" style={{ fontSize: 11 }}>{profile.description}</div>
                        </div>
                        <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                          {Object.entries(groups).map(([k, count]) => (
                            <span key={k} className="port-badge" style={{ fontSize: 10 }}>{count}x {k}</span>
                          ))}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
          )}

          {/* SRX Subscriptions */}
          {selectedTarget && (
            <div className="model-section" style={{ marginTop: 16 }}>
              <h3 className="model-section-title">SRX Subscriptions</h3>
              <div className="license-tier-grid">
                {Object.entries(SRX_LICENSE_TIERS).map(([key, tier]) => (
                  <label
                    key={key}
                    className={`license-tier-card${selectedLicense === key ? ' active' : ''}`}
                  >
                    <input
                      type="radio"
                      name="srxLicense"
                      value={key}
                      checked={selectedLicense === key}
                      onChange={() => { setSelectedLicense(key); setSubscriptionError(''); }}
                    />
                    <div className="license-tier-name">{tier.name}</div>
                    <div className="license-tier-desc">{tier.description}</div>
                  </label>
                ))}
              </div>
              <div className="subscription-footnote">
                <strong>SDC</strong> = Security Director Cloud &nbsp;|&nbsp; <strong>ATP</strong> = Advanced Threat Protection (Advanced Antimalware with ML on SRX, Adaptive Threat Profiling, Reverse Shell Detection, Encrypted Traffic Insights, Dynamic Signature Generation, and ML DNS Security)
              </div>
            </div>
          )}
        </div>

        {subscriptionError && (
          <div style={{
            padding: '8px 16px',
            background: 'rgba(248, 113, 113, 0.1)',
            borderTop: '1px solid rgba(248, 113, 113, 0.3)',
            color: 'var(--error)',
            fontSize: 13,
            fontWeight: 500,
          }}>
            {subscriptionError}
          </div>
        )}

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Skip</button>
          <button
            className="btn btn-primary"
            onClick={handleContinue}
            disabled={!selectedTarget}
          >
            {selectedTarget ? 'Continue to Interface Mapping' : 'Select Target Model'}
          </button>
        </div>
      </div>
    </div>
  );
}

/** Compact card showing model port summary + throughput breakdown */
function ModelInfoCard({ model, vendor = 'srx', metric }) {
  const portGroups = {};
  for (const port of model.ports) {
    const key = `${port.speed} ${port.type}`;
    portGroups[key] = (portGroups[key] || 0) + 1;
  }

  const labels = THROUGHPUT_LABELS[vendor] || THROUGHPUT_LABELS.srx;

  return (
    <div className="model-info-card">
      {model.eol && (
        <div className="model-info-row" style={{ color: '#e5a00d' }}>
          <span className="model-info-label">Status</span>
          <span className="model-info-value" style={{ fontWeight: 600 }}>End of Sale</span>
        </div>
      )}
      {model.current && (
        <div className="model-info-row" style={{ color: '#34d399' }}>
          <span className="model-info-label">Status</span>
          <span className="model-info-value" style={{ fontWeight: 600 }}>Current Model</span>
        </div>
      )}
      <div className="model-info-row">
        <span className="model-info-label">Tier</span>
        <span className="model-info-value">{tierLabel(model.tier)}</span>
      </div>
      {['l4', 'l7', 'threat'].map(key => {
        const val = getThroughputDisplay(model, key);
        const isActive = key === metric;
        return (
          <div
            key={key}
            className={`model-info-row${isActive ? ' throughput-active' : ''}`}
          >
            <span className="model-info-label">{labels[key]}</span>
            <span className="model-info-value">{val}</span>
          </div>
        );
      })}
      <div className="model-info-row">
        <span className="model-info-label">Ports</span>
        <span className="model-info-value">
          {Object.entries(portGroups).map(([key, count]) => (
            <span key={key} className="port-badge">{count}x {key}</span>
          ))}
        </span>
      </div>
    </div>
  );
}

function groupByTier(models) {
  const groups = {};
  for (const model of Object.values(models)) {
    if (!groups[model.tier]) groups[model.tier] = [];
    groups[model.tier].push(model);
  }
  return groups;
}

function tierLabel(tier) {
  const labels = {
    branch: 'Branch',
    midrange: 'Mid-Range',
    enterprise: 'Enterprise',
    datacenter: 'Data Center',
    chassis: 'Chassis-Based',
    virtual: 'Virtual',
  };
  return labels[tier] || tier;
}

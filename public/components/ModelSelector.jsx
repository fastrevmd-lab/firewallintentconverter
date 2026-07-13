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
import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  PANOS_MODELS,
  SRX_MODELS,
  SRX_SOURCE_MODELS,
  FORTIGATE_SOURCE_MODELS,
  CISCO_SOURCE_MODELS,
  CHECKPOINT_SOURCE_MODELS,
  SONICWALL_SOURCE_MODELS,
  HUAWEI_SOURCE_MODELS,
  detectPanosModel,
  detectSrxModel,
  detectFortigateModel,
  detectCiscoModel,
  detectCheckpointModel,
  detectSonicwallModel,
  detectHuaweiModel,
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
  siteName,
  siteGroup,
  sourceVendor,
  greenfieldMode,
  onModelSelection,
  onContinue,
  onClose,
}) {
  const [selectedSource, setSelectedSource] = useState(sourceModel || '');
  const [selectedTarget, setSelectedTarget] = useState(targetModel || '');
  const [selectedLicense, setSelectedLicense] = useState(srxLicense || '');
  const [selectedPortProfile, setSelectedPortProfile] = useState(SRX4700_DEFAULT_PROFILE);
  const [localSiteName, setLocalSiteName] = useState(siteName || '');
  const [localSiteGroup, setLocalSiteGroup] = useState(siteGroup || '');
  const [detection, setDetection] = useState(null);
  const [throughputMetric, setThroughputMetric] = useState('l7');
  const [recommendedSrx, setRecommendedSrx] = useState(null); // { model, recommended }
  const [showDatasheets, setShowDatasheets] = useState(false);
  const subscriptionRef = useRef(null);
  const targetRef = useRef(null);

  const isHealthCheckMode = sourceVendor === 'srx_healthcheck';
  const isSrxSource = sourceVendor === 'srx' || isHealthCheckMode;
  const isFortigateSource = sourceVendor === 'fortigate';
  const isCiscoSource = sourceVendor === 'cisco_asa';
  const isCheckpointSource = sourceVendor === 'checkpoint';
  const isSonicwallSource = sourceVendor === 'sonicwall';
  const isHuaweiSource = sourceVendor === 'huawei_usg';

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
      } else if (isCheckpointSource) {
        detected = detectCheckpointModel(intermediateConfig);
      } else if (isSonicwallSource) {
        detected = detectSonicwallModel(intermediateConfig);
      } else if (isHuaweiSource) {
        detected = detectHuaweiModel(intermediateConfig);
      } else {
        detected = detectPanosModel(intermediateConfig);
      }
      setDetection(detected);
      if (detected) {
        setSelectedSource(detected.model);
      }
    }
  }, [intermediateConfig, sourceModel, isSrxSource, isFortigateSource, isCiscoSource, isCheckpointSource, isSonicwallSource, isHuaweiSource]);

  // Re-suggest SRX whenever source or metric changes
  useEffect(() => {
    if (isHealthCheckMode) {
      // Health check: target = source (same hardware)
      setSelectedTarget(selectedSource);
      setRecommendedSrx(null);
    } else if (selectedSource) {
      const suggestion = suggestSrxModel(selectedSource, throughputMetric);
      setRecommendedSrx(suggestion);
      if (suggestion) {
        setSelectedTarget(suggestion.model);
      }
    }
  }, [selectedSource, throughputMetric, isHealthCheckMode]);

  // Auto-scroll to next incomplete step
  useEffect(() => {
    if (selectedSource && !selectedTarget && targetRef.current) {
      targetRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [selectedSource, selectedTarget]);

  useEffect(() => {
    if (selectedTarget && !selectedLicense && subscriptionRef.current) {
      subscriptionRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [selectedTarget, selectedLicense]);

  const sourceModelsDb = isSrxSource ? SRX_SOURCE_MODELS : isFortigateSource ? FORTIGATE_SOURCE_MODELS : isCiscoSource ? CISCO_SOURCE_MODELS : isCheckpointSource ? CHECKPOINT_SOURCE_MODELS : isSonicwallSource ? SONICWALL_SOURCE_MODELS : isHuaweiSource ? HUAWEI_SOURCE_MODELS : PANOS_MODELS;
  const sourceInfo = sourceModelsDb[selectedSource];
  const targetRaw = SRX_MODELS[selectedTarget];
  // Override ports when an SRX4700 port profile is selected
  const targetInfo = useMemo(() => {
    if (!targetRaw?.hasPortProfiles) return targetRaw;
    return { ...targetRaw, ports: getSrx4700Ports(selectedPortProfile) };
  }, [targetRaw, selectedPortProfile]);

  // Group models by tier for dropdown optgroups
  const sourceGroups = useMemo(() => groupByTier(sourceModelsDb), [isSrxSource, isFortigateSource, isCiscoSource, isCheckpointSource, isSonicwallSource, isHuaweiSource]);
  const srxGroups = useMemo(() => groupByTier(SRX_MODELS), []);

  const metricLabel = METRIC_PREFIX[throughputMetric] || 'L7';

  const canContinue = isHealthCheckMode
    ? !!selectedSource
    : !!selectedTarget && !!selectedLicense;

  const continueLabel = isHealthCheckMode
    ? (selectedSource ? 'Continue' : 'Select Source Model')
    : !selectedTarget ? 'Select Target Model'
    : !selectedLicense ? 'Select Subscription to Continue'
    : 'Continue to Interface Mapping';

  // Step numbering shifts in greenfield (no source step)
  const stepOffset = greenfieldMode ? 0 : 1;

  const handleContinue = () => {
    onModelSelection({
      sourceModel: selectedSource || null,
      targetModel: selectedTarget || null,
      srxLicense: selectedLicense || null,
      portProfile: targetRaw?.hasPortProfiles ? selectedPortProfile : null,
      siteName: localSiteName || null,
      siteGroup: localSiteGroup || null,
    });
    onContinue();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', maxHeight: '85vh' }} onClick={(e) => e.stopPropagation()}>
      <div className="modal-content" style={{ width: 580 }}>
        <div className="modal-header">
          <h2>{isHealthCheckMode ? 'Best Practice Audit — Model & License' : 'Hardware Model Selection'}</h2>
          <button className="modal-close" onClick={onClose}>x</button>
        </div>

        <div className="modal-body">
          <p style={{ fontSize: 10, color: 'var(--text-muted)', margin: '0 0 10px', lineHeight: 1.4 }}>
            Throughput numbers are best effort based on publicly available data. Do your own research.
            {' '}
            <a
              href="#"
              onClick={(e) => { e.preventDefault(); setShowDatasheets(!showDatasheets); }}
              style={{ color: 'var(--accent)', textDecoration: 'underline', cursor: 'pointer', fontSize: 10 }}
            >
              HPE Juniper SRX Spec Sheets
            </a>
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

          {/* Step 1: Source Model — hidden in greenfield mode */}
          {!greenfieldMode && (
          <div className="model-section">
            <StepHeader
              number={1}
              title={`Source Firewall (${isSrxSource ? 'Juniper SRX' : isFortigateSource ? 'FortiGate' : isCiscoSource ? 'Cisco ASA/FTD' : isCheckpointSource ? 'Check Point' : isSonicwallSource ? 'SonicWall' : isHuaweiSource ? 'Huawei USG' : 'PAN-OS'})`}
              complete={!!selectedSource}
            />

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
              <option value="">-- Select {isSrxSource ? 'SRX' : isFortigateSource ? 'FortiGate' : isCiscoSource ? 'Cisco' : isCheckpointSource ? 'Check Point' : isSonicwallSource ? 'SonicWall' : isHuaweiSource ? 'Huawei' : 'PAN-OS'} Model (optional) --</option>
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
              <ModelInfoCard model={sourceInfo} vendor={isSrxSource ? 'srx' : isFortigateSource ? 'fortigate' : isCiscoSource ? 'cisco_asa' : isCheckpointSource ? 'checkpoint' : isSonicwallSource ? 'sonicwall' : isHuaweiSource ? 'huawei_usg' : 'panos'} metric={throughputMetric} />
            )}
          </div>
          )}

          {/* Step 2: Target SRX Model — hidden in health check mode (target = source) */}
          {!isHealthCheckMode && (
          <div className="model-section" ref={targetRef}>
            {!greenfieldMode && <div className="model-step-divider" />}
            <StepHeader
              number={1 + stepOffset}
              title="Target Firewall (Juniper SRX)"
              complete={!!selectedTarget}
            />

            <select
              className="model-select"
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              style={/^(SRX1600|SRX4120|SRX4300|SRX4700|vSRX)/.test(selectedTarget) ? { color: 'var(--juniper-green)', borderColor: 'var(--juniper-green)' } : undefined}
            >
              <option value="">-- Select SRX Model --</option>
              {Object.entries(srxGroups).map(([tier, models]) => (
                <optgroup key={tier} label={tierLabel(tier)}>
                  {models.map(m => {
                    const isRec = recommendedSrx?.model === m.name && recommendedSrx?.recommended;
                    return (
                      <option key={m.name} value={m.name}>
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
          )}

          {/* SRX4700 Port Profile Selector — hidden in health check mode */}
          {targetRaw?.hasPortProfiles && !isHealthCheckMode && (
            <div className="model-section">
              <div className="model-step-divider" />
              <StepHeader number={2 + stepOffset} title="Port Profile" complete={!!selectedPortProfile} />
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

          {/* Step 3: SRX Subscriptions */}
          {selectedTarget && (
            <div className="model-section" ref={subscriptionRef}>
              <div className="model-step-divider" />
              <StepHeader
                number={(targetRaw?.hasPortProfiles ? 3 : 2) + stepOffset}
                title="SRX Subscription"
                complete={!!selectedLicense}
                required
              />
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
                      onChange={() => setSelectedLicense(key)}
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

        {/* Step 4: Site Identification (optional — for SDC/Mist integration) — hidden in health check mode */}
        {!isHealthCheckMode && (
        <div className="model-section" style={{ padding: '12px 20px', borderTop: '1px solid var(--border-color)' }}>
          <StepHeader
            number={(targetRaw?.hasPortProfiles ? 4 : 3) + stepOffset}
            title="Site Identification"
            optional
          />
          <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '0 0 8px 0' }}>
            Added as header comments in the SRX output. Useful for SDC / Mist integration.
          </p>
          <div style={{ display: 'flex', gap: 12 }}>
            <label style={{ flex: 1 }}>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Site Name</span>
              <input
                type="text"
                className="input-field"
                value={localSiteName}
                onChange={e => setLocalSiteName(e.target.value)}
                placeholder="e.g. branch-office-seattle"
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </label>
            <label style={{ flex: 1 }}>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Site Group</span>
              <input
                type="text"
                className="input-field"
                value={localSiteGroup}
                onChange={e => setLocalSiteGroup(e.target.value)}
                placeholder="e.g. west-coast-branches"
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </label>
          </div>
        </div>
        )}

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Skip</button>
          <button
            className="btn btn-primary"
            onClick={handleContinue}
            disabled={!canContinue}
            title={!canContinue ? continueLabel : ''}
          >
            {continueLabel}
          </button>
        </div>
      </div>

      {showDatasheets && <DatasheetPanel onClose={() => setShowDatasheets(false)} />}
      </div>
    </div>
  );
}

const SRX_DATASHEETS = [
  { tier: 'Branch', models: [
    { name: 'SRX300 Line (SRX300/SRX320/SRX340/SRX345/SRX380)', url: 'https://www.juniper.net/us/en/products/security/srx-series/srx300-line-firewalls-branch-datasheet.html' },
  ]},
  { tier: 'Enterprise', models: [
    { name: 'SRX1600', url: 'https://www.juniper.net/us/en/products/security/srx-series/srx1600-firewall-datasheet.html' },
    { name: 'SRX4100/SRX4200', url: 'https://www.juniper.net/us/en/products/security/srx-series/srx4100-srx4200-firewall-datasheet.html' },
    { name: 'SRX4120', url: 'https://www.juniper.net/us/en/products/security/srx-series/srx4120-firewall-datasheet.html' },
    { name: 'SRX4300', url: 'https://www.juniper.net/us/en/products/security/srx-series/srx4300-firewall-datasheet.html' },
  ]},
  { tier: 'Data Center', models: [
    { name: 'SRX4600', url: 'https://www.juniper.net/us/en/products/security/srx-series/srx4600-firewall-datasheet.html' },
    { name: 'SRX4700', url: 'https://www.juniper.net/us/en/products/security/srx-series/srx4700-firewall-datasheet.html' },
  ]},
  { tier: 'Chassis-Based', models: [
    { name: 'SRX5400/SRX5600/SRX5800', url: 'https://www.juniper.net/us/en/products/security/srx-series/srx5400-srx5600-srx5800-firewall-datasheet.html' },
  ]},
  { tier: 'Virtual', models: [
    { name: 'vSRX Virtual Firewall', url: 'https://www.juniper.net/us/en/products/security/srx-series/vsrx-virtual-firewall-datasheet.html' },
  ]},
  { tier: 'Comparison', models: [
    { name: 'SRX Series Comparison', url: 'https://www.juniper.net/us/en/products/security/srx-series/compare.html' },
  ]},
];

function DatasheetPanel({ onClose }) {
  return (
    <div className="modal-content" style={{ width: 320, flexShrink: 0 }}>
      <div className="modal-header" style={{ padding: '12px 16px' }}>
        <h2 style={{ fontSize: 14 }}>HPE Juniper SRX Spec Sheets</h2>
        <button className="modal-close" onClick={onClose} style={{ fontSize: 14 }}>x</button>
      </div>
      <div className="modal-body" style={{ padding: '12px 16px' }}>
        {SRX_DATASHEETS.map(group => (
          <div key={group.tier} style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 6 }}>
              {group.tier}
            </div>
            {group.models.map(ds => (
              <a
                key={ds.name}
                href={ds.url}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'block',
                  padding: '6px 8px',
                  marginBottom: 2,
                  borderRadius: 'var(--radius)',
                  color: 'var(--accent)',
                  fontSize: 12,
                  textDecoration: 'none',
                  transition: 'background 0.15s',
                }}
                onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-hover)'}
                onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
              >
                {ds.name}
                <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 4 }}>↗</span>
              </a>
            ))}
          </div>
        ))}
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 8, lineHeight: 1.4 }}>
          All links open official juniper.net datasheets in a new window.
        </div>
      </div>
    </div>
  );
}

/** Step header with numbered circle, title, and optional required/optional badge */
function StepHeader({ number, title, complete, required, optional }) {
  return (
    <div className="model-step-header">
      <span className={`step-number${complete ? ' complete' : ''}`}>
        {complete ? '\u2713' : number}
      </span>
      <span className="step-title">{title}</span>
      {required && <span className="step-required">Required</span>}
      {optional && <span className="step-optional">Optional</span>}
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
        <div className="model-info-row" style={{ color: vendor === 'srx' ? 'var(--juniper-green)' : 'var(--success)' }}>
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

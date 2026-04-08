/**
 * InterviewPanel Component
 *
 * Right panel showing editable rule details.
 * When a rule is selected, all fields are editable inline.
 * "Accept Rule" marks the rule as accepted in the review workflow.
 */
import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  mapActionToSrx,
  mapActionToPanos,
  buildApplicationServices,
  getMinimumLicenseForRule,
  getLicenseGaps,
  SRX_LICENSE_TIERS,
} from '../utils/srx-view-transforms.js';
import AutocompleteInput from './shared/AutocompleteInput.jsx';
import { getLLMStatus } from '../utils/llm-client.js';

const PROVIDER_LABELS = {
  claude: 'Claude', openai: 'OpenAI', gemini: 'Gemini',
  ollama: 'Ollama', lmstudio: 'LM Studio', custom: 'Custom',
};
const LOCAL_PROVIDERS = new Set(['ollama', 'lmstudio']);

function getHitColor(hitCount, disabled) {
  if (disabled) return 'var(--text-muted)';
  if (hitCount === 0) return 'var(--error)';
  if (hitCount < 100) return 'var(--caution)';
  return 'var(--juniper-green)';
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export default function InterviewPanel({
  selectedRule,
  intermediateConfig,
  warnings,
  onUpdateRule,
  targetModel,
  onAcceptRule,
  viewMode,
  platformView,
  srxLicense,
  isTranslating,
  translationProgress,
}) {
  const isSrx = viewMode === 'srx';
  const isToSrxTab = platformView === 'srx'; // true only on the "to SRX" tab

  const ruleWarnings = selectedRule
    ? (warnings || []).filter(w => w.element?.includes(selectedRule.name))
    : [];

  /** Update a field on the selected rule */
  const handleFieldChange = (field, value) => {
    if (!selectedRule || !onUpdateRule) return;
    onUpdateRule({ ...selectedRule, [field]: value });
  };

  /** Handle toggling boolean fields */
  const handleToggle = (field) => {
    handleFieldChange(field, !selectedRule[field]);
  };

  /** Handle individual security profile changes */
  const handleProfileChange = (profileType, value) => {
    const profiles = { ...(selectedRule.security_profiles || {}) };
    if (value) {
      profiles[profileType] = value;
    } else {
      delete profiles[profileType];
    }
    handleFieldChange('security_profiles', profiles);
  };

  const isAccepted = selectedRule?._review_status === 'accepted';
  const zoneNames = (intermediateConfig?.zones || []).map(z => z.name);

  const addressNames = useMemo(() => [
    ...(intermediateConfig?.address_objects || []).map(a => a.name),
    ...(intermediateConfig?.address_groups || []).map(g => g.name),
  ], [intermediateConfig]);

  const serviceNames = useMemo(() =>
    (intermediateConfig?.service_objects || []).map(s => s.name),
  [intermediateConfig]);

  const applicationNames = useMemo(() => [
    ...(intermediateConfig?.applications || []).map(a => a.name),
    ...(intermediateConfig?.application_groups || []).map(g => g.name),
  ], [intermediateConfig]);

  // --- Live elapsed timer for translation ---
  const [elapsedSecs, setElapsedSecs] = useState(0);
  const timerRef = useRef(null);

  useEffect(() => {
    if (isTranslating) {
      setElapsedSecs(0);
      const start = Date.now();
      timerRef.current = setInterval(() => {
        setElapsedSecs(Math.floor((Date.now() - start) / 1000));
      }, 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [isTranslating]);

  // --- Translation in progress ---
  if (isTranslating) {
    const p = translationProgress || {};
    const mins = Math.floor(elapsedSecs / 60);
    const secs = elapsedSecs % 60;
    const timeStr = mins > 0 ? `${mins}m ${String(secs).padStart(2, '0')}s` : `${secs}s`;

    const phaseLabels = {
      building_prompt: 'Preparing prompt',
      calling_llm: 'Waiting for LLM',
      parsing_response: 'Parsing response',
      complete: 'Complete',
    };
    const phaseLabel = phaseLabels[p.phase] || 'Starting';

    // Progress bar for chunked translations
    const progressPct = p.totalChunks > 1 && p.chunk > 0
      ? Math.round((p.chunk / p.totalChunks) * 100)
      : p.phase === 'calling_llm' ? null : (p.phase === 'parsing_response' ? 80 : (p.phase === 'complete' ? 100 : 10));

    // LLM provider/model info
    const llmInfo = getLLMStatus();
    const isLocal = LOCAL_PROVIDERS.has(llmInfo.provider);
    const providerLabel = PROVIDER_LABELS[llmInfo.provider] || llmInfo.provider;
    const providerColor = isLocal ? 'var(--llm-local)' : 'var(--llm-cloud)';

    return (
      <div className="panel interview-panel">
        <div className="panel-header">
          <h2>LLM Translation</h2>
          <span className="spinner" style={{ width: 14, height: 14 }} />
        </div>
        <div className="panel-body" style={{ padding: 16 }}>
          <div style={{
            background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-lg)',
            padding: 20, marginBottom: 16,
          }}>
            {/* Provider / Model badge */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14,
              padding: '6px 10px', background: 'var(--bg-primary)', borderRadius: 'var(--radius)',
              fontSize: 11, fontFamily: 'var(--font-mono)',
            }}>
              <span style={{
                width: 7, height: 7, borderRadius: '50%', background: providerColor, flexShrink: 0,
              }} />
              <span style={{ color: providerColor, fontWeight: 600 }}>{providerLabel}</span>
              <span style={{ color: 'var(--text-muted)' }}>&middot;</span>
              <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {llmInfo.model}
              </span>
              <span style={{
                marginLeft: 'auto', fontSize: 9, padding: '1px 6px', borderRadius: 8,
                background: isLocal ? 'rgba(144,198,65,0.12)' : 'rgba(255,165,0,0.12)',
                color: providerColor, flexShrink: 0,
              }}>
                {isLocal ? 'Local' : 'Cloud'}
              </span>
            </div>

            {/* Phase indicator */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
              <div style={{
                width: 10, height: 10, borderRadius: '50%',
                background: p.phase === 'calling_llm' ? 'var(--accent)' : (p.phase === 'complete' ? 'var(--success)' : 'var(--warning)'),
                animation: p.phase === 'calling_llm' ? 'pulse 1.5s infinite' : 'none',
              }} />
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                {phaseLabel}{p.phase === 'calling_llm' && <span className="animated-ellipsis" />}
              </span>
            </div>

            {/* Detail message */}
            {p.detail && (
              <div style={{
                fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16,
                fontFamily: 'var(--font-mono)', lineHeight: 1.6,
              }}>
                {p.detail}
              </div>
            )}

            {/* Progress bar */}
            {progressPct !== null ? (
              <div style={{
                height: 6, background: 'var(--bg-primary)', borderRadius: 3,
                marginBottom: 16, overflow: 'hidden',
              }}>
                <div style={{
                  height: '100%', borderRadius: 3,
                  background: 'var(--accent)',
                  width: `${progressPct}%`,
                  transition: 'width 0.5s ease',
                }} />
              </div>
            ) : p.phase === 'calling_llm' && (
              <div style={{
                height: 6, background: 'var(--bg-primary)', borderRadius: 3,
                marginBottom: 16, overflow: 'hidden',
              }}>
                <div style={{
                  height: '100%', borderRadius: 3, width: '30%',
                  background: 'var(--accent)',
                  animation: 'indeterminate 1.5s ease-in-out infinite',
                }} />
              </div>
            )}

            {/* Stats grid */}
            <div style={{
              display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px 20px',
              fontSize: 11, fontFamily: 'var(--font-mono)',
            }}>
              <div>
                <div style={{ color: 'var(--text-muted)', marginBottom: 2 }}>Elapsed</div>
                <div style={{ color: 'var(--text-primary)', fontSize: 14, fontWeight: 600 }}>{timeStr}</div>
              </div>
              {p.totalChunks > 1 && (
                <div>
                  <div style={{ color: 'var(--text-muted)', marginBottom: 2 }}>Chunk</div>
                  <div style={{ color: 'var(--text-primary)', fontSize: 14, fontWeight: 600 }}>{p.chunk || 0} / {p.totalChunks}</div>
                </div>
              )}
              <div>
                <div style={{ color: 'var(--text-muted)', marginBottom: 2 }}>Prompt tokens</div>
                <div style={{ color: 'var(--accent)', fontSize: 14, fontWeight: 600 }}>{(p.promptTokens || 0).toLocaleString()}</div>
              </div>
              <div>
                <div style={{ color: 'var(--text-muted)', marginBottom: 2 }}>Response tokens</div>
                <div style={{ color: 'var(--accent)', fontSize: 14, fontWeight: 600 }}>{(p.responseTokens || 0).toLocaleString()}</div>
              </div>
            </div>
          </div>

          <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
            Rules will appear in the table when translation completes.
            <br />Each rule will be marked "LLM Reviewed" for your acceptance.
          </div>
        </div>
      </div>
    );
  }

  // --- No rule selected ---
  if (!selectedRule) {
    return (
      <div className="panel interview-panel">
        <div className="panel-header">
          <h2>{isSrx ? 'Policy Details' : 'Rule Details'}</h2>
        </div>
        <div className="panel-body">
          {intermediateConfig ? (
            <div className="empty-state">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
                <path d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5" />
              </svg>
              <p>Click a {isSrx ? 'policy' : 'rule'} in the table to see its full details and edit fields.</p>
            </div>
          ) : (
            <div className="empty-state">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
                <circle cx="12" cy="12" r="10" />
                <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              <h3>Interview Engine</h3>
              <p>After parsing, this panel will show rule details and inline editing.</p>
            </div>
          )}
        </div>
      </div>
    );
  }

  // --- Rule detail view with editing ---
  return (
    <div className="panel interview-panel">
      <div className="panel-header">
        <h2>{isSrx ? 'Policy Details' : 'Rule Details'}</h2>
        <span style={{ fontSize: '11px', color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
          #{selectedRule._rule_index}
        </span>
      </div>
      <div className="panel-body">
        {/* Review Action Bar — "to SRX" tab only */}
        {isToSrxTab && (
          <div className="rule-review-actions">
            <button
              className={`btn btn-sm ${isAccepted ? 'btn-accepted' : 'btn-accept'}`}
              onClick={() => onAcceptRule && onAcceptRule()}
              disabled={isAccepted}
            >
              {isAccepted ? 'Accepted' : 'Accept Policy'}
            </button>
          </div>
        )}

        {/* Live Traffic */}
        {typeof selectedRule._hit_count === 'number' && (
          <div style={{ marginBottom: 16, padding: 12, background: 'var(--bg-elevated)', borderRadius: 8, border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: 'var(--caution)' }}>Live Traffic</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginBottom: 8 }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 18, fontWeight: 600, color: getHitColor(selectedRule._hit_count, selectedRule.disabled) }}>
                  {selectedRule._hit_count.toLocaleString()}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Hits</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 18, fontWeight: 600 }}>
                  {(selectedRule._session_count || 0).toLocaleString()}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Sessions</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 18, fontWeight: 600 }}>
                  {formatBytes(selectedRule._byte_count || 0)}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Bytes</div>
              </div>
            </div>

            {/* Matched Applications */}
            {selectedRule._matched_apps?.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Matched Applications:</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {selectedRule._matched_apps.map(app => (
                    <span key={app} style={{ background: 'var(--bg-input)', padding: '2px 8px', borderRadius: 10, fontSize: 11 }}>{app}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Suggestion: tighten 'any' apps */}
            {selectedRule.applications?.includes('any') && selectedRule._matched_apps?.length > 0 && (
              <div style={{ marginTop: 8, padding: 8, background: 'rgba(245, 158, 11, 0.1)', borderRadius: 6, fontSize: 11 }}>
                <span style={{ color: 'var(--caution)' }}>Suggestion:</span> This rule permits <strong>any</strong> application but only {selectedRule._matched_apps.length} specific app(s) were observed.
                <button
                  className="btn btn-sm"
                  style={{ marginLeft: 8, fontSize: 10, padding: '2px 8px' }}
                  onClick={() => onUpdateRule({ ...selectedRule, applications: [...selectedRule._matched_apps] })}
                >
                  Replace with observed apps
                </button>
              </div>
            )}

            {/* Last updated */}
            {selectedRule._stats_timestamp && (
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 6, textAlign: 'right' }}>
                Updated: {new Date(selectedRule._stats_timestamp).toLocaleTimeString()}
              </div>
            )}
          </div>
        )}

        {/* General */}
        <div className="detail-section">
          <h3>General</h3>
          <EditableField label="Name" value={selectedRule.name} onChange={(v) => handleFieldChange('name', v)} />
          <div className="detail-field">
            <span className="field-label">Action</span>
            {isSrx ? (
              <select
                className="field-select"
                value={mapActionToSrx(selectedRule.action)}
                onChange={(e) => handleFieldChange('action', mapActionToPanos(e.target.value))}
              >
                <option value="permit">permit</option>
                <option value="deny">deny</option>
                <option value="reject">reject</option>
              </select>
            ) : (
              <select
                className="field-select"
                value={selectedRule.action}
                onChange={(e) => handleFieldChange('action', e.target.value)}
              >
                <option value="allow">allow</option>
                <option value="deny">deny</option>
                <option value="drop">drop</option>
                <option value="reset-client">reset-client</option>
                <option value="reset-server">reset-server</option>
                <option value="reset-both">reset-both</option>
              </select>
            )}
          </div>
          <div className="detail-field">
            <span className="field-label">Disabled</span>
            <label className="toggle-label">
              <input
                type="checkbox"
                checked={selectedRule.disabled || false}
                onChange={() => handleToggle('disabled')}
              />
              <span>{selectedRule.disabled ? 'Yes' : 'No'}</span>
            </label>
          </div>
          <EditableField
            label="Description"
            value={selectedRule.description || ''}
            onChange={(v) => handleFieldChange('description', v)}
            placeholder="Add description..."
          />
        </div>

        {/* Zones */}
        <div className="detail-section">
          <h3>Zones</h3>
          <ZoneChipsField
            label={isSrx ? 'From Zone' : 'Source'}
            values={selectedRule.src_zones}
            onChange={(v) => handleFieldChange('src_zones', v)}
            availableZones={zoneNames}
          />
          <ZoneChipsField
            label={isSrx ? 'To Zone' : 'Destination'}
            values={selectedRule.dst_zones}
            onChange={(v) => handleFieldChange('dst_zones', v)}
            availableZones={zoneNames}
          />
        </div>

        {/* Addresses */}
        <div className="detail-section">
          <h3>Addresses</h3>
          <EditableChipsField
            label="Source"
            values={selectedRule.src_addresses}
            onChange={(v) => handleFieldChange('src_addresses', v)}
            suggestions={addressNames}
          />
          {isSrx ? (
            <div className="srx-toggle-row" style={{ padding: '2px 0' }}>
              <div>
                <div className="srx-toggle-label">Negate source</div>
                <div className="srx-toggle-sublabel">Match all EXCEPT listed addresses</div>
              </div>
              <label className="srx-toggle">
                <input type="checkbox" checked={selectedRule.negate_source || false} onChange={() => handleToggle('negate_source')} />
                <span className="srx-toggle-track" />
              </label>
            </div>
          ) : (
            <div className="detail-field">
              <span className="field-label">Negate Source</span>
              <label className="toggle-label">
                <input type="checkbox" checked={selectedRule.negate_source || false} onChange={() => handleToggle('negate_source')} />
                <span>{selectedRule.negate_source ? 'Yes (all EXCEPT listed)' : 'No'}</span>
              </label>
            </div>
          )}
          <EditableChipsField
            label="Destination"
            values={selectedRule.dst_addresses}
            onChange={(v) => handleFieldChange('dst_addresses', v)}
            suggestions={addressNames}
          />
          {isSrx ? (
            <div className="srx-toggle-row" style={{ padding: '2px 0' }}>
              <div>
                <div className="srx-toggle-label">Negate destination</div>
                <div className="srx-toggle-sublabel">Match all EXCEPT listed addresses</div>
              </div>
              <label className="srx-toggle">
                <input type="checkbox" checked={selectedRule.negate_destination || false} onChange={() => handleToggle('negate_destination')} />
                <span className="srx-toggle-track" />
              </label>
            </div>
          ) : (
            <div className="detail-field">
              <span className="field-label">Negate Dest</span>
              <label className="toggle-label">
                <input type="checkbox" checked={selectedRule.negate_destination || false} onChange={() => handleToggle('negate_destination')} />
                <span>{selectedRule.negate_destination ? 'Yes (all EXCEPT listed)' : 'No'}</span>
              </label>
            </div>
          )}
        </div>

        {/* Source Users / Identity (only when rule has identity references) */}
        {(selectedRule.source_users && selectedRule.source_users.length > 0) && (
          <div className="detail-section">
            <h3>{isSrx ? 'Source Identity' : 'User / Group Identity'}</h3>
            <EditableChipsField
              label={isSrx ? 'Source Identity' : 'Source Users'}
              values={selectedRule.source_users}
              onChange={(v) => handleFieldChange('source_users', v)}
            />
            {isSrx && (
              <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '4px 0' }}>
                Requires JIMS integration for user identification
              </div>
            )}
          </div>
        )}

        {/* Applications / Services */}
        <div className="detail-section">
          <h3>{isSrx ? 'Applications / Ports' : 'Applications & Services'}</h3>
          <EditableChipsField
            label="Applications"
            values={selectedRule.applications}
            onChange={(v) => handleFieldChange('applications', v)}
            suggestions={applicationNames}
          />
          <EditableChipsField
            label={isSrx ? 'Ports' : 'Services'}
            values={selectedRule.services}
            onChange={(v) => handleFieldChange('services', v)}
            suggestions={serviceNames}
          />
        </div>

        {/* Logging */}
        <div className="detail-section">
          <h3>Logging</h3>
          {isSrx ? (
            <>
              <div className="srx-toggle-row">
                <div>
                  <div className="srx-toggle-label">Session initiate logs</div>
                  <div className="srx-toggle-sublabel">Log at session creation</div>
                </div>
                <label className="srx-toggle">
                  <input type="checkbox" checked={selectedRule.log_start || false} onChange={() => handleToggle('log_start')} />
                  <span className="srx-toggle-track" />
                </label>
              </div>
              <div className="srx-toggle-row">
                <div>
                  <div className="srx-toggle-label">Session close logs</div>
                  <div className="srx-toggle-sublabel">Log at session teardown</div>
                </div>
                <label className="srx-toggle">
                  <input type="checkbox" checked={selectedRule.log_end || false} onChange={() => handleToggle('log_end')} />
                  <span className="srx-toggle-track" />
                </label>
              </div>
              <div className="srx-toggle-row">
                <div>
                  <div className="srx-toggle-label">Log count</div>
                  <div className="srx-toggle-sublabel">Enable packet/byte counters</div>
                </div>
                <label className="srx-toggle">
                  <input type="checkbox" checked={selectedRule._srx_log_count !== false} onChange={() => handleToggle('_srx_log_count')} />
                  <span className="srx-toggle-track" />
                </label>
              </div>
              <div className="srx-toggle-row">
                <div>
                  <div className="srx-toggle-label">Rule options</div>
                  <div className="srx-toggle-sublabel">Attach options profile</div>
                </div>
                <label className="srx-toggle">
                  <input type="checkbox" checked={!!selectedRule._srx_rule_options || false} onChange={() => handleFieldChange('_srx_rule_options', selectedRule._srx_rule_options ? '' : 'default')} />
                  <span className="srx-toggle-track" />
                </label>
              </div>
              {selectedRule._srx_rule_options && (
                <div className="detail-field" style={{ marginTop: 4 }}>
                  <span className="field-label" style={{ fontSize: 11 }}>Profile</span>
                  <input
                    className="field-edit-input"
                    value={selectedRule._srx_rule_options || ''}
                    onChange={(e) => handleFieldChange('_srx_rule_options', e.target.value)}
                    placeholder="default"
                    style={{ fontSize: 11 }}
                  />
                </div>
              )}
            </>
          ) : (
            <>
              <div className="detail-field">
                <span className="field-label">Log Start</span>
                <label className="toggle-label">
                  <input type="checkbox" checked={selectedRule.log_start || false} onChange={() => handleToggle('log_start')} />
                  <span>{selectedRule.log_start ? 'Yes' : 'No'}</span>
                </label>
              </div>
              <div className="detail-field">
                <span className="field-label">Log End</span>
                <label className="toggle-label">
                  <input type="checkbox" checked={selectedRule.log_end || false} onChange={() => handleToggle('log_end')} />
                  <span>{selectedRule.log_end ? 'Yes' : 'No'}</span>
                </label>
              </div>
            </>
          )}
        </div>

        {/* Security Profiles / Application Services */}
        <div className="detail-section">
          <h3>{isSrx ? 'Security Subscriptions' : 'Security Profiles'}</h3>

          {/* License warning — "to SRX" tab only */}
          {isToSrxTab && srxLicense && (() => {
            const gaps = getLicenseGaps(selectedRule, srxLicense);
            if (gaps.length === 0) return null;
            return (
              <div className="license-warning">
                This rule requires features beyond your {srxLicense} license:
                {gaps.map((g, i) => (
                  <div key={i} style={{ fontSize: 11, marginTop: 2 }}>
                    {g.feature} requires {g.required}
                  </div>
                ))}
              </div>
            );
          })()}

          {isSrx ? (
            <SrxSecurityToggles
              rule={selectedRule}
              onProfileChange={handleProfileChange}
              onFieldChange={handleFieldChange}
              onUpdateRule={onUpdateRule}
            />
          ) : (
            <>
              {selectedRule.profile_group && (
                <div className="detail-field">
                  <span className="field-label">Profile Group</span>
                  <span className="field-value-badge">{selectedRule.profile_group}</span>
                </div>
              )}
              {(VENDOR_PROFILE_TYPES[viewMode] || VENDOR_PROFILE_TYPES.panos).map(pType => {
                const val = (selectedRule.security_profiles || {})[pType] || '';
                return (
                  <div className="detail-field" key={pType}>
                    <span className="field-label">{formatProfileLabel(pType)}</span>
                    <input
                      className="field-edit-input"
                      value={val}
                      onChange={(e) => handleProfileChange(pType, e.target.value)}
                      placeholder="none"
                    />
                  </div>
                );
              })}
            </>
          )}
          {selectedRule._secIntelAddresses?.length > 0 && (
            <div className="secIntel-notice">
              SecIntel: {selectedRule._secIntelAddresses.join(', ')} &rarr; SRX Security Intelligence
            </div>
          )}
        </div>

        {/* Tags */}
        <div className="detail-section">
          <h3>Tags</h3>
          <EditableChipsField
            label="Tags"
            values={selectedRule.tags || []}
            onChange={(v) => handleFieldChange('tags', v)}
          />
        </div>

        {/* Translation Notes — shown on LLM-translated rules */}
        {selectedRule._translation_notes && (
          <div className="detail-section">
            <h3>Translation Notes</h3>
            <div className="translation-notes">
              {selectedRule._translation_notes}
            </div>
          </div>
        )}

        {/* Warnings for this rule */}
        {ruleWarnings.length > 0 && (
          <div className="detail-section">
            <h3>Conversion Notes ({ruleWarnings.length})</h3>
            {ruleWarnings.map((w, i) => (
              <div key={i} className="warning-item" style={{ padding: '8px 0' }}>
                <WarningIcon severity={w.severity} />
                <div className="warning-body">
                  <div className="warning-message">{w.message}</div>
                  {w.suggestion && (
                    <div className="warning-suggestion">{w.suggestion}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

      </div>
    </div>
  );
}

/** Vendor-aware profile type lists for the detail panel */
const VENDOR_PROFILE_TYPES = {
  panos:     ['virus', 'wildfire-analysis', 'url-filtering', 'file-blocking', 'spyware', 'vulnerability'],
  fortigate: ['virus', 'url-filtering', 'vulnerability', 'application-control', 'dns-security', 'email-filter', 'dlp', 'decryption'],
  cisco:     ['virus', 'url-filtering', 'vulnerability', 'spyware'],
  srx:       ['virus', 'url-filtering', 'spyware', 'vulnerability'],
};

/** Format profile type to friendly label */
function formatProfileLabel(type) {
  const labels = {
    'virus': 'Antivirus',
    'wildfire-analysis': 'WildFire Analysis',
    'url-filtering': 'URL Filtering',
    'file-blocking': 'File Blocking',
    'spyware': 'Anti-Spyware',
    'vulnerability': 'Vulnerability Protection',
    // FortiGate-originated
    'application-control': 'Application Control',
    'email-filter': 'Email Filter',
    'dlp': 'DLP',
    'dns-security': 'DNS Filter',
    'decryption': 'SSL Inspection',
    'waf': 'WAF',
    'casb': 'CASB',
    'voip': 'VoIP',
  };
  return labels[type] || type;
}

/** Check if a rule has any individual security profiles set */
function hasSecurityProfiles(rule) {
  return rule.security_profiles && Object.keys(rule.security_profiles).length > 0;
}

/** Format a value for display */
function formatValue(val) {
  if (val === true) return 'true';
  if (val === false) return 'false';
  if (Array.isArray(val)) return val.join(', ');
  if (val === null || val === undefined) return '(none)';
  return String(val);
}

/** Editable text field */
function EditableField({ label, value, onChange, placeholder }) {
  return (
    <div className="detail-field">
      <span className="field-label">{label}</span>
      <input
        className="field-edit-input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}

/** Editable chips field for arrays */
function EditableChipsField({ label, values, onChange, suggestions }) {
  const [inputValue, setInputValue] = useState('');

  const handleAdd = () => {
    const trimmed = inputValue.trim();
    if (!trimmed || (values || []).includes(trimmed)) return;
    onChange([...(values || []), trimmed]);
    setInputValue('');
  };

  const handleRemove = (val) => {
    onChange((values || []).filter(v => v !== val));
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAdd();
    }
  };

  // Filter out already-selected values from suggestions
  const filteredSuggestions = suggestions && suggestions.length > 0
    ? suggestions.filter(s => !(values || []).includes(s))
    : null;

  return (
    <div className="detail-field" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 4 }}>
      <span className="field-label">{label}</span>
      <div className="field-chips-container">
        {(values || []).length === 0 && (
          <span className="cell-chip" style={{ opacity: 0.5 }}>any</span>
        )}
        {(values || []).map((v, i) => (
          <span key={i} className="chip">
            {v}
            <button className="chip-remove" onClick={() => handleRemove(v)}>x</button>
          </span>
        ))}
        {filteredSuggestions && filteredSuggestions.length > 0 ? (
          <AutocompleteInput
            value={inputValue}
            onChange={setInputValue}
            onCommit={handleAdd}
            suggestions={filteredSuggestions}
            multiToken={false}
            className="chip-input"
            placeholder="Add..."
          />
        ) : (
          <input
            className="chip-input"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Add..."
            style={{ minWidth: 60, flex: 1 }}
          />
        )}
      </div>
    </div>
  );
}

/** Zone chips field with dropdown selector for available zones */
function ZoneChipsField({ label, values, onChange, availableZones }) {
  const [inputValue, setInputValue] = useState('');
  const selected = values || [];
  const unselected = (availableZones || []).filter(z => !selected.includes(z));

  const handleAdd = (zone) => {
    if (!zone || selected.includes(zone)) return;
    onChange([...selected, zone]);
  };

  const handleRemove = (val) => {
    onChange(selected.filter(v => v !== val));
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const trimmed = inputValue.trim();
      if (trimmed) {
        handleAdd(trimmed);
        setInputValue('');
      }
    }
  };

  return (
    <div className="detail-field" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 4 }}>
      <span className="field-label">{label}</span>
      <div className="field-chips-container">
        {selected.length === 0 && (
          <span className="cell-chip" style={{ opacity: 0.5 }}>any</span>
        )}
        {selected.map((v, i) => (
          <span key={i} className="chip">
            {v}
            <button className="chip-remove" onClick={() => handleRemove(v)}>x</button>
          </span>
        ))}
        {unselected.length > 0 ? (
          <select
            className="field-select"
            value=""
            onChange={(e) => { if (e.target.value) handleAdd(e.target.value); }}
            style={{ minWidth: 80, flex: 1 }}
          >
            <option value="">Add zone...</option>
            {unselected.map(z => (
              <option key={z} value={z}>{z}</option>
            ))}
          </select>
        ) : (
          <input
            className="chip-input"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Add..."
            style={{ minWidth: 60, flex: 1 }}
          />
        )}
      </div>
    </div>
  );
}

/**
 * JunOS-style Security Subscriptions toggles.
 * Maps PAN-OS security_profiles and SRX-specific flags to toggle switches
 * matching Security Director Cloud layout.
 */
const SRX_SUBSCRIPTION_TOGGLES = [
  { key: 'ips',              label: 'IPS',              sub: 'IDP Policy',                 srxField: '_srx_idp',              initFrom: ['spyware', 'vulnerability'] },
  { key: 'content-security', label: 'Content Security', sub: 'UTM Content Filtering',      srxField: '_srx_content_security', initFrom: ['url-filtering'] },
  { key: 'decrypt',          label: 'Decrypt',          sub: 'SSL/TLS Inspection',         srxField: '_srx_decrypt' },
  { key: 'flow-av',          label: 'Flow-based AV',    sub: 'Flow-mode Antivirus',        srxField: '_srx_flow_av' },
  { key: 'antimalware',      label: 'Anti-malware',     sub: 'Anti-malware Protection',    srxField: '_srx_antimalware',      initFrom: ['virus', 'wildfire-analysis'] },
  { key: 'secintel',         label: 'SecIntel',         sub: 'Security Intelligence',      srxField: '_srx_secintel', initFromSecIntel: true },
  { key: 'secure-web-proxy', label: 'Secure Web Proxy', sub: 'Explicit/Transparent Proxy', srxField: '_srx_secure_web_proxy' },
  { key: 'icap-redirect',    label: 'ICAP Redirect',    sub: 'ICAP Content Adaptation',    srxField: '_srx_icap_redirect' },
];

function SrxSecurityToggles({ rule, onProfileChange, onFieldChange, onUpdateRule }) {
  const sp = rule.security_profiles || {};

  const isEnabled = (toggle) => {
    // If the srxField is explicitly set, use that
    if (rule[toggle.srxField] !== undefined) return !!rule[toggle.srxField];
    // Initialize from source-vendor profiles (e.g. spyware/vulnerability → IPS)
    if (toggle.initFrom) return toggle.initFrom.some(p => !!sp[p]);
    // SecIntel: initialize from EDL addresses
    if (toggle.initFromSecIntel) return (rule._secIntelAddresses || []).length > 0;
    return false;
  };

  const getProfile = (toggle) => {
    // Explicit profile value
    if (rule[toggle.srxField + '_profile']) return rule[toggle.srxField + '_profile'];
    // Derive from source-vendor profiles
    if (toggle.initFrom) {
      const names = toggle.initFrom.map(p => sp[p]).filter(Boolean);
      return names[0] || '';
    }
    return '';
  };

  const handleToggleChange = (toggle, checked) => {
    // Batch both field changes into a single update to avoid race condition
    // where the second onFieldChange overwrites the first
    if (!checked) {
      onUpdateRule({ ...rule, [toggle.srxField]: false, [toggle.srxField + '_profile']: '' });
    } else {
      onFieldChange(toggle.srxField, true);
    }
  };

  return (
    <div>
      {SRX_SUBSCRIPTION_TOGGLES.map(toggle => {
        const enabled = isEnabled(toggle);
        return (
          <React.Fragment key={toggle.key}>
            <div className="srx-toggle-row">
              <div>
                <div className="srx-toggle-label">{toggle.label}</div>
                <div className="srx-toggle-sublabel">{toggle.sub}</div>
              </div>
              <label className="srx-toggle">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => handleToggleChange(toggle, e.target.checked)}
                />
                <span className="srx-toggle-track" />
              </label>
            </div>
            {/* Single profile name input below toggle when enabled */}
            {enabled && (
              <div className="detail-field srx-profile-inline">
                <span className="field-label">Profile</span>
                <input
                  className="field-edit-input"
                  value={getProfile(toggle)}
                  onChange={(e) => onFieldChange(toggle.srxField + '_profile', e.target.value)}
                  placeholder="default"
                />
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

/** Small severity icon */
function WarningIcon({ severity }) {
  const symbols = {
    clean: '\u2705',
    warning: '\u26A0\uFE0F',
    unsupported: '\u274C',
    interview_required: '\uD83D\uDCAC',
  };
  return (
    <span className={`warning-icon ${severity}`}>
      {symbols[severity] || '?'}
    </span>
  );
}

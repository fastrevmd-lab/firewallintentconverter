/**
 * InterviewPanel Component
 *
 * Right panel showing editable rule details + AI-powered suggestions.
 * When a rule is selected, all fields are editable inline.
 * "LLM Review" calls the configured LLM for structured best-practice advice.
 * "Accept Rule" marks the rule as accepted in the review workflow.
 */
import React, { useState } from 'react';
import {
  getLLMSuggestion,
  getLLMStatus,
  buildStructuredRuleSuggestionPrompt,
} from '../utils/llm-client.js';
import {
  mapActionToSrx,
  mapActionToPanos,
  buildApplicationServices,
  getMinimumLicenseForRule,
  getLicenseGaps,
  SRX_LICENSE_TIERS,
} from '../utils/srx-view-transforms.js';

export default function InterviewPanel({
  selectedRule,
  intermediateConfig,
  warnings,
  onUpdateRule,
  targetModel,
  isSanitized,
  llmWarningDismissed,
  onLLMWarning,
  onAcceptRule,
  onSetLLMReviewed,
  viewMode,
  platformView,
  srxLicense,
}) {
  const isSrx = viewMode === 'srx';
  const isToSrxTab = platformView === 'srx'; // true only on the "to SRX" tab
  const [structuredSuggestion, setStructuredSuggestion] = useState(null);
  const [rawSuggestion, setRawSuggestion] = useState('');
  const [isLoadingSuggestion, setIsLoadingSuggestion] = useState(false);
  const [suggestionError, setSuggestionError] = useState('');
  const [itemStates, setItemStates] = useState({}); // { 'suggestion-0': 'accepted'|'rejected', 'note-0': 'accepted'|'rejected' }

  const ruleWarnings = selectedRule
    ? (warnings || []).filter(w => w.element?.includes(selectedRule.name))
    : [];

  const llmStatus = getLLMStatus();

  /** Request structured LLM review for the selected rule */
  const handleLLMReview = async () => {
    if (!selectedRule) return;

    // Warn user if config hasn't been sanitized (skip if already dismissed)
    if (!isSanitized && !llmWarningDismissed && onLLMWarning) {
      onLLMWarning();
      return;
    }

    setIsLoadingSuggestion(true);
    setSuggestionError('');
    setStructuredSuggestion(null);
    setRawSuggestion('');
    setItemStates({});

    try {
      // Build SRX context so the LLM sees both original PAN-OS and SRX translation
      const sp = selectedRule.security_profiles || {};
      const srxAppServices = [];
      if (sp.spyware || sp.vulnerability) srxAppServices.push('IPS/IDP');
      if (sp['url-filtering'] || sp['file-blocking']) srxAppServices.push('Content Security (UTM)');
      if (sp.virus || sp['wildfire-analysis']) srxAppServices.push('Anti-malware');
      if (selectedRule._srx_decrypt) srxAppServices.push('Decrypt/SSL Proxy');
      if (selectedRule._srx_flow_av) srxAppServices.push('Flow-based AV');
      if (selectedRule._srx_secintel || (selectedRule._secIntelAddresses || []).length > 0) srxAppServices.push('SecIntel');
      if (selectedRule._srx_secure_web_proxy) srxAppServices.push('Secure Web Proxy');
      if (selectedRule._srx_icap_redirect) srxAppServices.push('ICAP Redirect');

      const srxLogging = [];
      if (selectedRule.log_end) srxLogging.push('session-close');
      if (selectedRule.log_start) srxLogging.push('session-init');
      if (selectedRule._srx_log_count) srxLogging.push('count');

      const srxContext = {
        action: mapActionToSrx(selectedRule.action),
        applicationServices: srxAppServices,
        logging: srxLogging,
      };

      const prompt = buildStructuredRuleSuggestionPrompt(
        selectedRule,
        targetModel,
        intermediateConfig?.zones,
        srxLicense,
        srxContext,
        intermediateConfig?.metadata?.source_vendor
      );
      const result = await getLLMSuggestion(prompt.user, prompt.system);

      // Try to parse structured JSON response
      try {
        // Strip markdown fences if present
        let jsonStr = result.trim();
        if (jsonStr.startsWith('```')) {
          jsonStr = jsonStr.replace(/^```(?:json)?\s*\n?/, '').replace(/\n?```\s*$/, '');
        }
        const parsed = JSON.parse(jsonStr);
        if (parsed.analysis && (parsed.suggestions || parsed.notes)) {
          setStructuredSuggestion(parsed);
        } else {
          setRawSuggestion(result);
        }
      } catch {
        // JSON parse failed — show raw text
        setRawSuggestion(result);
      }

      // Mark as LLM reviewed
      if (onSetLLMReviewed) {
        onSetLLMReviewed();
      }
    } catch (err) {
      setSuggestionError(err.message);
    } finally {
      setIsLoadingSuggestion(false);
    }
  };

  /** Update a field on the selected rule */
  const handleFieldChange = (field, value) => {
    if (!selectedRule || !onUpdateRule) return;
    onUpdateRule({ ...selectedRule, [field]: value });
  };

  /** Accept a suggestion — apply the field change */
  const handleAcceptSuggestion = (suggestion, index) => {
    if (!selectedRule || !onUpdateRule) return;
    handleFieldChange(suggestion.field, suggestion.suggested);
    setItemStates(prev => ({ ...prev, [`suggestion-${index}`]: 'accepted' }));
  };

  /** Reject a suggestion — dismiss without applying */
  const handleRejectSuggestion = (index) => {
    setItemStates(prev => ({ ...prev, [`suggestion-${index}`]: 'rejected' }));
  };

  /** Accept a note — save to rule's _llm_notes array */
  const handleAcceptNote = (noteText, index) => {
    if (!selectedRule || !onUpdateRule) return;
    const existing = selectedRule._llm_notes || [];
    if (!existing.includes(noteText)) {
      handleFieldChange('_llm_notes', [...existing, noteText]);
    }
    setItemStates(prev => ({ ...prev, [`note-${index}`]: 'accepted' }));
  };

  /** Dismiss a note — don't save */
  const handleDismissNote = (index) => {
    setItemStates(prev => ({ ...prev, [`note-${index}`]: 'rejected' }));
  };

  /** Remove a persisted note from the rule */
  const handleRemoveNote = (noteIndex) => {
    if (!selectedRule || !onUpdateRule) return;
    const updated = (selectedRule._llm_notes || []).filter((_, i) => i !== noteIndex);
    handleFieldChange('_llm_notes', updated);
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
              <p>Click a {isSrx ? 'policy' : 'rule'} in the table to see its full details, edit fields, and get AI suggestions.</p>
            </div>
          ) : (
            <div className="empty-state">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
                <circle cx="12" cy="12" r="10" />
                <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              <h3>Interview Engine</h3>
              <p>After parsing, this panel will show rule details, inline editing, and AI-powered best-practice suggestions.</p>
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
              className="btn btn-secondary btn-sm"
              onClick={handleLLMReview}
              disabled={isLoadingSuggestion || !llmStatus.configured}
            >
              {isLoadingSuggestion ? (
                <>
                  <span className="loading-spinner" style={{ width: 12, height: 12 }} />
                  Analyzing...
                </>
              ) : (
                'LLM Review'
              )}
            </button>
            <button
              className={`btn btn-sm ${isAccepted ? 'btn-accepted' : 'btn-accept'}`}
              onClick={() => onAcceptRule && onAcceptRule()}
              disabled={isAccepted}
            >
              {isAccepted ? 'Accepted' : 'Accept Policy'}
            </button>
            {!llmStatus.configured && (
              <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                Configure LLM in Settings
              </span>
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

        {/* Persistent LLM Notes */}
        {(selectedRule._llm_notes || []).length > 0 && (
          <div className="detail-section">
            <h3>Notes</h3>
            {selectedRule._llm_notes.map((note, i) => (
              <div key={i} className="llm-note-item" style={{
                display: 'flex', alignItems: 'flex-start', gap: 6,
                padding: '6px 8px', marginBottom: 4,
                background: 'rgba(0, 91, 90, 0.08)', borderRadius: 4,
                fontSize: '12px', lineHeight: '1.4', color: 'var(--text-secondary)'
              }}>
                <span style={{ flex: 1 }}>{note}</span>
                <button
                  className="chip-remove"
                  onClick={() => handleRemoveNote(i)}
                  title="Remove note"
                  style={{ flexShrink: 0 }}
                >x</button>
              </div>
            ))}
          </div>
        )}

        {/* Addresses */}
        <div className="detail-section">
          <h3>Addresses</h3>
          <EditableChipsField
            label="Source"
            values={selectedRule.src_addresses}
            onChange={(v) => handleFieldChange('src_addresses', v)}
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

        {/* Applications / Services */}
        <div className="detail-section">
          <h3>{isSrx ? 'Applications / Ports' : 'Applications & Services'}</h3>
          <EditableChipsField
            label="Applications"
            values={selectedRule.applications}
            onChange={(v) => handleFieldChange('applications', v)}
          />
          <EditableChipsField
            label={isSrx ? 'Ports' : 'Services'}
            values={selectedRule.services}
            onChange={(v) => handleFieldChange('services', v)}
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
                  <input type="checkbox" checked={selectedRule._srx_log_count || false} onChange={() => handleToggle('_srx_log_count')} />
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

        {/* AI Review Section — "to SRX" tab only */}
        {isToSrxTab && (
          <div className="detail-section">
            <h3>AI Review</h3>

            {llmStatus.configured && !isSanitized && (
              <p style={{ fontSize: '11px', color: 'var(--warning)', marginBottom: 8 }}>
                Configuration not sanitized — you will be warned before sending data to an LLM.
              </p>
            )}

            {suggestionError && (
              <div className="suggestion-error">
                {suggestionError}
              </div>
            )}

            {/* Structured suggestion display */}
            {structuredSuggestion && (
              <div className="suggestion-card" style={{ padding: '10px 12px' }}>
                <div className="suggestion-analysis">{structuredSuggestion.analysis}</div>
                {structuredSuggestion.verdict && (
                  <span className={`suggestion-verdict ${structuredSuggestion.verdict}`}>
                    {structuredSuggestion.verdict === 'looks_good' ? 'Looks Good' : 'Needs Changes'}
                  </span>
                )}

                {/* Actionable field change suggestions */}
                {structuredSuggestion.suggestions?.map((s, i) => {
                  const state = itemStates[`suggestion-${i}`];
                  return (
                    <div key={`s-${i}`} className="suggestion-field-change" style={{
                      opacity: state === 'rejected' ? 0.4 : 1,
                      borderLeft: state === 'accepted' ? '3px solid var(--accent)' : state === 'rejected' ? '3px solid var(--text-muted)' : '3px solid transparent',
                      paddingLeft: 8
                    }}>
                      <div className="suggestion-field-name">{s.field}</div>
                      <div className="suggestion-values">
                        <span className="suggestion-current">{formatValue(s.current)}</span>
                        <span className="suggestion-arrow">&rarr;</span>
                        <span className="suggestion-new">{formatValue(s.suggested)}</span>
                      </div>
                      <div className="suggestion-reason">{s.reason}</div>
                      {state ? (
                        <span style={{
                          fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: 3,
                          background: state === 'accepted' ? 'rgba(0, 91, 90, 0.15)' : 'rgba(128,128,128,0.15)',
                          color: state === 'accepted' ? 'var(--accent)' : 'var(--text-muted)'
                        }}>
                          {state === 'accepted' ? 'Applied' : 'Dismissed'}
                        </span>
                      ) : (
                        <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                          <button className="suggestion-import-btn" onClick={() => handleAcceptSuggestion(s, i)}>
                            Accept
                          </button>
                          <button className="suggestion-import-btn" onClick={() => handleRejectSuggestion(i)}
                            style={{ background: 'rgba(128,128,128,0.15)', color: 'var(--text-secondary)' }}>
                            Reject
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}

                {/* Informational notes */}
                {structuredSuggestion.notes?.map((note, i) => {
                  const state = itemStates[`note-${i}`];
                  return (
                    <div key={`n-${i}`} className="suggestion-field-change" style={{
                      opacity: state === 'rejected' ? 0.4 : 1,
                      borderLeft: state === 'accepted' ? '3px solid var(--accent)' : state === 'rejected' ? '3px solid var(--text-muted)' : '3px solid rgba(0, 91, 90, 0.3)',
                      paddingLeft: 8, marginTop: 6
                    }}>
                      <div className="suggestion-field-name" style={{ color: 'var(--text-secondary)' }}>Note</div>
                      <div className="suggestion-reason">{note}</div>
                      {state ? (
                        <span style={{
                          fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: 3,
                          background: state === 'accepted' ? 'rgba(0, 91, 90, 0.15)' : 'rgba(128,128,128,0.15)',
                          color: state === 'accepted' ? 'var(--accent)' : 'var(--text-muted)'
                        }}>
                          {state === 'accepted' ? 'Saved' : 'Dismissed'}
                        </span>
                      ) : (
                        <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                          <button className="suggestion-import-btn" onClick={() => handleAcceptNote(note, i)}>
                            Accept
                          </button>
                          <button className="suggestion-import-btn" onClick={() => handleDismissNote(i)}
                            style={{ background: 'rgba(128,128,128,0.15)', color: 'var(--text-secondary)' }}>
                            Dismiss
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Raw text fallback */}
            {rawSuggestion && !structuredSuggestion && (
              <div className="suggestion-card">
                <div className="suggestion-content">{rawSuggestion}</div>
              </div>
            )}
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
function EditableChipsField({ label, values, onChange }) {
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
        <input
          className="chip-input"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Add..."
          style={{ minWidth: 60, flex: 1 }}
        />
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

function SrxSecurityToggles({ rule, onProfileChange, onFieldChange }) {
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
    onFieldChange(toggle.srxField, checked);
    if (!checked) onFieldChange(toggle.srxField + '_profile', '');
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

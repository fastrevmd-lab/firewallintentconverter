/**
 * Main Application Component
 *
 * Orchestrates the four-panel layout:
 *   LEFT:   ConfigInput   — paste/upload PAN-OS config
 *   CENTER: Tabbed editor — Security Rules / Zones / Objects / NAT
 *   RIGHT:  InterviewPanel — editable rule details + LLM suggestions
 *           ReviewChatPanel — full-ruleset LLM review chat (when in review mode)
 *   BOTTOM: SRXOutput     — generated SRX commands + warnings
 *
 * State flow:
 *   1. User pastes/uploads config  →  configText
 *   2. Click "Parse" sends to /api/parse  →  intermediateConfig + parseWarnings
 *   3. ModelSelector auto-opens  →  sourceModel + targetModel
 *   4. InterfaceMapper opens  →  interfaceMappings
 *   5. User edits config in tabbed panels
 *   6. User reviews rules (LLM Review + Accept per rule)
 *   7. When all accepted, "Review" opens full-ruleset chat
 *   8. Click "Convert" sends to /api/convert  →  srxOutput + convertWarnings
 */
import React, { useState, useCallback, useMemo } from 'react';
import ConfigInput from './components/ConfigInput.jsx';
import PolicyTable from './components/PolicyTable.jsx';
import InterviewPanel from './components/InterviewPanel.jsx';
import ReviewChatPanel from './components/ReviewChatPanel.jsx';
import SRXOutput from './components/SRXOutput.jsx';
import WarningsPanel from './components/WarningsPanel.jsx';
import LLMSettings from './components/LLMSettings.jsx';
import ModelSelector from './components/ModelSelector.jsx';
import InterfaceMapper from './components/InterfaceMapper.jsx';
import ZoneEditor from './components/ZoneEditor.jsx';
import ObjectEditor from './components/ObjectEditor.jsx';
import NATEditor from './components/NATEditor.jsx';

export default function App() {
  // --- Config input state ---
  const [configText, setConfigText] = useState('');

  // --- Parsed data state ---
  const [intermediateConfig, setIntermediateConfig] = useState(null);
  const [parseWarnings, setParseWarnings] = useState([]);
  const [parseStats, setParseStats] = useState(null);

  // --- Hardware model state ---
  const [sourceModel, setSourceModel] = useState('');
  const [targetModel, setTargetModel] = useState('');
  const [srxLicense, setSrxLicense] = useState('');
  const [interfaceMappings, setInterfaceMappings] = useState({});

  // --- Modal state ---
  const [showModelSelector, setShowModelSelector] = useState(false);
  const [showInterfaceMapper, setShowInterfaceMapper] = useState(false);

  // --- Center panel tab state ---
  const [editTab, setEditTab] = useState('rules');
  const [platformView, setPlatformView] = useState('panos'); // 'panos' | 'srx'

  // --- Review mode state ---
  const [reviewMode, setReviewMode] = useState(false);

  // --- Conversion output state ---
  const [srxOutput, setSrxOutput] = useState(null);
  const [convertWarnings, setConvertWarnings] = useState([]);
  const [conversionSummary, setConversionSummary] = useState(null);
  const [outputFormat, setOutputFormat] = useState('set');

  // --- Sanitization state ---
  const [isSanitized, setIsSanitized] = useState(false);
  const [sanitizationTable, setSanitizationTable] = useState(null);
  const [showLLMWarning, setShowLLMWarning] = useState(false);
  const [llmWarningDismissed, setLlmWarningDismissed] = useState(false);

  // --- UI state ---
  const [isLoading, setIsLoading] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState('');
  const [selectedRule, setSelectedRule] = useState(null);
  const [showSettings, setShowSettings] = useState(false);
  const [bottomTab, setBottomTab] = useState('output');
  const [error, setError] = useState(null);

  // --- All warnings combined (parse + convert) ---
  const allWarnings = [...parseWarnings, ...convertWarnings];

  // --- Review progress ---
  const reviewProgress = useMemo(() => {
    const policies = intermediateConfig?.security_policies || [];
    const accepted = policies.filter(r => r._review_status === 'accepted' || r.disabled).length;
    return { accepted, total: policies.length };
  }, [intermediateConfig]);

  const allRulesAccepted = reviewProgress.total > 0 && reviewProgress.accepted === reviewProgress.total;

  // ------------------------------------------------------------------
  // Sanitize handler: strips sensitive data from config text
  // ------------------------------------------------------------------
  const handleSanitize = useCallback(async () => {
    if (!configText.trim()) return;
    setIsLoading(true);
    setLoadingMessage('Sanitizing configuration...');
    setError(null);

    try {
      const response = await fetch('/api/sanitize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ configText }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Sanitization failed');
      }

      setConfigText(data.sanitizedText);
      setSanitizationTable(data.replacements);
      setIsSanitized(true);
    } catch (err) {
      setError(`Sanitize error: ${err.message}`);
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  }, [configText]);

  // Reset sanitization flag when user changes config text manually
  const handleConfigChange = useCallback((text) => {
    setConfigText(text);
    if (isSanitized) {
      setIsSanitized(false);
      setSanitizationTable(null);
      setLlmWarningDismissed(false);
    }
  }, [isSanitized]);

  // ------------------------------------------------------------------
  // Parse handler: sends config to /api/parse
  // ------------------------------------------------------------------
  const handleParse = useCallback(async () => {
    if (!configText.trim()) return;
    setIsLoading(true);
    setLoadingMessage('Parsing PAN-OS configuration...');
    setError(null);
    setSrxOutput(null);
    setConvertWarnings([]);
    setConversionSummary(null);
    setSelectedRule(null);
    setEditTab('rules');
    setReviewMode(false);

    try {
      const response = await fetch('/api/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ configText }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Parse failed');
      }

      // Inject _review_status on every rule
      const policies = data.intermediateConfig.security_policies || [];
      policies.forEach(rule => {
        rule._review_status = 'unreviewed';
      });

      setIntermediateConfig(data.intermediateConfig);
      setParseWarnings(data.warnings || []);
      setParseStats(data.parseStats || null);

      // Auto-open model selector after successful parse
      setShowModelSelector(true);
    } catch (err) {
      setError(`Parse error: ${err.message}`);
      setIntermediateConfig(null);
      setParseWarnings([]);
      setParseStats(null);
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  }, [configText]);

  // ------------------------------------------------------------------
  // Convert handler: sends intermediate config to /api/convert
  // ------------------------------------------------------------------
  const handleConvert = useCallback(async (format = 'set') => {
    if (!intermediateConfig) return;
    setIsLoading(true);
    setLoadingMessage('Converting to SRX format...');
    setError(null);

    try {
      const response = await fetch('/api/convert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ intermediateConfig, format, interfaceMappings }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Conversion failed');
      }

      setSrxOutput(data.output);
      setConvertWarnings(data.output.warnings || []);
      setConversionSummary(data.output.summary || null);
      setOutputFormat(format);
      setBottomTab('output');
    } catch (err) {
      setError(`Conversion error: ${err.message}`);
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  }, [intermediateConfig, interfaceMappings]);

  // ------------------------------------------------------------------
  // Config update handlers (mutable editing)
  // ------------------------------------------------------------------

  /** Update a single security rule by index */
  const handleUpdateRule = useCallback((index, updatedRule) => {
    setIntermediateConfig(prev => {
      const policies = [...prev.security_policies];
      policies[index] = updatedRule;
      return { ...prev, security_policies: policies };
    });
  }, []);

  /** Delete a security rule by index */
  const handleDeleteRule = useCallback((index) => {
    setIntermediateConfig(prev => ({
      ...prev,
      security_policies: prev.security_policies.filter((_, i) => i !== index),
    }));
    setSelectedRule(null);
  }, []);

  /** Add a new security rule */
  const handleAddRule = useCallback(() => {
    setIntermediateConfig(prev => {
      const newIndex = (prev.security_policies?.length || 0) + 1;
      const newRule = {
        name: `new-rule-${newIndex}`,
        _rule_index: newIndex,
        action: 'deny',
        src_zones: [],
        dst_zones: [],
        src_addresses: [],
        dst_addresses: [],
        applications: [],
        services: [],
        log_start: false,
        log_end: true,
        disabled: false,
        description: '',
        tags: [],
        profile_group: '',
        security_profiles: {},
        _review_status: 'unreviewed',
      };
      return {
        ...prev,
        security_policies: [...(prev.security_policies || []), newRule],
      };
    });
  }, []);

  /** Update zones */
  const handleZonesUpdate = useCallback((zones) => {
    setIntermediateConfig(prev => ({ ...prev, zones }));
  }, []);

  /** Update NAT rules */
  const handleNATUpdate = useCallback((natRules) => {
    setIntermediateConfig(prev => ({ ...prev, nat_rules: natRules }));
  }, []);

  /** Update a config section (for ObjectEditor) */
  const handleConfigUpdate = useCallback((field, items) => {
    setIntermediateConfig(prev => ({ ...prev, [field]: items }));
  }, []);

  // ------------------------------------------------------------------
  // Review handlers
  // ------------------------------------------------------------------

  /** Accept the currently selected rule */
  const handleAcceptRule = useCallback((index) => {
    setIntermediateConfig(prev => {
      const policies = [...prev.security_policies];
      policies[index] = { ...policies[index], _review_status: 'accepted' };
      return { ...prev, security_policies: policies };
    });
    // Update selectedRule to reflect the change
    setSelectedRule(prev => prev ? { ...prev, _review_status: 'accepted' } : prev);
  }, []);

  /** Mark the currently selected rule as LLM reviewed */
  const handleSetLLMReviewed = useCallback((index) => {
    setIntermediateConfig(prev => {
      const policies = [...prev.security_policies];
      if (policies[index]._review_status !== 'accepted') {
        policies[index] = { ...policies[index], _review_status: 'llm-reviewed' };
      }
      return { ...prev, security_policies: policies };
    });
    setSelectedRule(prev => {
      if (prev && prev._review_status !== 'accepted') {
        return { ...prev, _review_status: 'llm-reviewed' };
      }
      return prev;
    });
  }, []);

  /** Get current rule index for the selected rule */
  const getCurrentRuleIndex = useCallback(() => {
    if (!selectedRule || !intermediateConfig) return -1;
    return intermediateConfig.security_policies.findIndex(
      r => r.name === selectedRule.name && r._rule_index === selectedRule._rule_index
    );
  }, [selectedRule, intermediateConfig]);

  /** Handle Review button click — only available in SRX view */
  const handleReviewClick = useCallback(() => {
    if (platformView !== 'srx') {
      setError('Switch to the SRX view to start the full-ruleset review.');
      return;
    }
    if (!allRulesAccepted) {
      setError(`All rules must be accepted before full review (${reviewProgress.accepted}/${reviewProgress.total} accepted)`);
      return;
    }
    setReviewMode(true);
  }, [allRulesAccepted, reviewProgress, platformView]);

  /** Switch platform view — exit review mode when leaving SRX */
  const handlePlatformViewChange = useCallback((view) => {
    setPlatformView(view);
    if (view !== 'srx' && reviewMode) {
      setReviewMode(false);
    }
  }, [reviewMode]);

  // ------------------------------------------------------------------
  // Model / mapping handlers
  // ------------------------------------------------------------------

  const handleModelSelection = useCallback(({ sourceModel: src, targetModel: tgt, srxLicense: lic }) => {
    setSourceModel(src || '');
    setTargetModel(tgt || '');
    setSrxLicense(lic || '');
  }, []);

  const handleModelContinue = useCallback(() => {
    setShowModelSelector(false);
    if (targetModel || true) {
      setShowInterfaceMapper(true);
    }
  }, [targetModel]);

  const handleMappingComplete = useCallback((mappings) => {
    setInterfaceMappings(mappings);
    setShowInterfaceMapper(false);
  }, []);

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------
  return (
    <div className="app-container">
      {/* --- Top Navigation Bar --- */}
      <nav className="navbar">
        <div className="navbar-brand">
          <h1>
            Firewall Policy to <span className="brand-accent">Intent Converter</span>
          </h1>
        </div>

        {/* Stats badges — shown after parsing */}
        {parseStats && (
          <div className="navbar-stats">
            {sourceModel && (
              <span className="stat-badge model-badge" onClick={() => setShowModelSelector(true)} style={{ cursor: 'pointer' }}>
                {sourceModel} <span style={{ color: 'var(--accent)', margin: '0 4px' }}>&rarr;</span> {targetModel || '?'}
              </span>
            )}
            {srxLicense && (
              <span className="stat-badge license-badge" onClick={() => setShowModelSelector(true)} style={{ cursor: 'pointer' }}>
                License <span className="stat-value">{srxLicense}</span>
              </span>
            )}
            <span className="stat-badge">
              Zones <span className="stat-value">{parseStats.zone_count}</span>
            </span>
            <span className="stat-badge">
              Rules <span className="stat-value">{parseStats.rule_count}</span>
            </span>
            <span className="stat-badge">
              Objects <span className="stat-value">{parseStats.object_count}</span>
            </span>
            <span className="stat-badge">
              NAT <span className="stat-value">{parseStats.nat_rule_count}</span>
            </span>
            {allWarnings.length > 0 && (
              <span className="stat-badge">
                Warnings <span className="stat-value" style={{ color: 'var(--warning)' }}>
                  {allWarnings.length}
                </span>
              </span>
            )}
            {intermediateConfig && (
              <span className="review-progress">
                {reviewProgress.accepted}/{reviewProgress.total} accepted
              </span>
            )}
          </div>
        )}

        <div className="navbar-actions">
          {intermediateConfig && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setShowModelSelector(true)}
              title="Change hardware models"
            >
              Models
            </button>
          )}
          {intermediateConfig && targetModel && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setShowInterfaceMapper(true)}
              title="Edit interface mappings"
            >
              Interfaces
            </button>
          )}
          <button
            className="settings-btn"
            onClick={() => setShowSettings(true)}
            title="LLM Settings"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="3" />
              <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
            </svg>
          </button>
        </div>
      </nav>

      {/* --- Error banner --- */}
      {error && (
        <div style={{
          background: 'rgba(248, 113, 113, 0.1)',
          borderBottom: '1px solid rgba(248, 113, 113, 0.3)',
          padding: '8px 20px',
          fontSize: '13px',
          color: 'var(--error)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <span>{error}</span>
          <button
            onClick={() => setError(null)}
            style={{ background: 'none', border: 'none', color: 'var(--error)', cursor: 'pointer', fontSize: '16px' }}
          >
            x
          </button>
        </div>
      )}

      {/* --- Loading bar --- */}
      {isLoading && (
        <div className="progress-bar">
          <div className="progress-bar-fill" style={{ width: '60%', animation: 'indeterminate 1.5s infinite' }} />
        </div>
      )}

      {/* --- Main Content Grid --- */}
      <div className="main-content">
        {/* LEFT: Config Input */}
        <ConfigInput
          configText={configText}
          onConfigChange={handleConfigChange}
          onParse={handleParse}
          onSanitize={handleSanitize}
          isLoading={isLoading}
          isParsed={!!intermediateConfig}
          isSanitized={isSanitized}
          sourceModel={sourceModel}
          targetModel={targetModel}
          onOpenModels={() => setShowModelSelector(true)}
        />

        {/* CENTER: Tabbed Editor Panel */}
        <div className="panel policy-table-panel">
          {intermediateConfig ? (
            <>
              {/* Platform view toggle + Tab bar */}
              <div className="panel-header" style={{ flexDirection: 'column', alignItems: 'stretch', padding: 0 }}>
                {/* Platform view toggle */}
                <div className="platform-view-bar">
                  <button
                    className={`platform-view-btn ${platformView === 'panos' ? 'active' : ''}`}
                    onClick={() => handlePlatformViewChange('panos')}
                  >
                    from {sourceModel || 'PAN-OS'}
                  </button>
                  <button
                    className={`platform-view-btn ${platformView === 'srx' ? 'active' : ''}`}
                    onClick={() => handlePlatformViewChange('srx')}
                  >
                    to {targetModel || 'SRX'}
                  </button>
                </div>

                <div className="center-tab-bar">
                  <button
                    className={`center-tab-btn ${editTab === 'rules' ? 'active' : ''}`}
                    onClick={() => setEditTab('rules')}
                  >
                    {platformView === 'srx' ? 'Security Policies' : 'Security Rules'} ({intermediateConfig.security_policies?.length || 0})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'zones' ? 'active' : ''}`}
                    onClick={() => setEditTab('zones')}
                  >
                    {platformView === 'srx' ? 'Security Zones' : 'Zones'} ({intermediateConfig.zones?.length || 0})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'objects' ? 'active' : ''}`}
                    onClick={() => setEditTab('objects')}
                  >
                    {platformView === 'srx' ? 'Address Book' : 'Objects'}
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'nat' ? 'active' : ''}`}
                    onClick={() => setEditTab('nat')}
                  >
                    NAT ({intermediateConfig.nat_rules?.length || 0})
                  </button>
                  <div style={{ flex: 1 }} />
                  {platformView === 'srx' && (
                    <>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={handleReviewClick}
                        style={{
                          margin: '6px 4px',
                          opacity: allRulesAccepted ? 1 : 0.5,
                        }}
                        title={
                          allRulesAccepted
                            ? 'Start full ruleset review with LLM'
                            : `${reviewProgress.accepted}/${reviewProgress.total} rules accepted`
                        }
                      >
                        Review
                      </button>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => handleConvert('set')}
                        disabled={isLoading}
                        style={{ margin: '6px 12px 6px 4px' }}
                      >
                        Convert to SRX
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Tab content */}
              <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                {editTab === 'rules' && (
                  <PolicyTable
                    policies={intermediateConfig.security_policies || []}
                    warnings={allWarnings}
                    selectedRule={selectedRule}
                    onSelectRule={setSelectedRule}
                    onUpdateRule={handleUpdateRule}
                    onDeleteRule={handleDeleteRule}
                    onAddRule={handleAddRule}
                    viewMode={platformView}
                  />
                )}
                {editTab === 'zones' && (
                  <ZoneEditor
                    zones={intermediateConfig.zones || []}
                    onZonesUpdate={handleZonesUpdate}
                    viewMode={platformView}
                    interfaceMappings={interfaceMappings}
                  />
                )}
                {editTab === 'objects' && (
                  <ObjectEditor
                    intermediateConfig={intermediateConfig}
                    onConfigUpdate={handleConfigUpdate}
                    viewMode={platformView}
                  />
                )}
                {editTab === 'nat' && (
                  <NATEditor
                    natRules={intermediateConfig.nat_rules || []}
                    onNATUpdate={handleNATUpdate}
                    viewMode={platformView}
                  />
                )}
              </div>
            </>
          ) : (
            <>
              <div className="panel-header">
                <h2>Security Policies</h2>
              </div>
              <div className="panel-body">
                <div className="empty-state">
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
                    <rect x="3" y="3" width="18" height="18" rx="2" />
                    <line x1="3" y1="9" x2="21" y2="9" />
                    <line x1="9" y1="21" x2="9" y2="9" />
                  </svg>
                  <h3>No configuration loaded</h3>
                  <p>Paste a PAN-OS XML configuration in the left panel and click "Parse" to view security policies here.</p>
                </div>
              </div>
            </>
          )}
        </div>

        {/* RIGHT: Interview / Rule Details / Review Chat */}
        {reviewMode ? (
          <ReviewChatPanel
            intermediateConfig={intermediateConfig}
            onUpdateRule={handleUpdateRule}
            targetModel={targetModel}
            srxLicense={srxLicense}
            isSanitized={isSanitized}
            llmWarningDismissed={llmWarningDismissed}
            onLLMWarning={() => setShowLLMWarning(true)}
            onExitReview={() => setReviewMode(false)}
          />
        ) : (
          <InterviewPanel
            selectedRule={selectedRule}
            intermediateConfig={intermediateConfig}
            warnings={allWarnings}
            onUpdateRule={(updatedRule) => {
              if (!selectedRule || !intermediateConfig) return;
              const index = intermediateConfig.security_policies.findIndex(
                r => r.name === selectedRule.name && r._rule_index === selectedRule._rule_index
              );
              if (index >= 0) {
                handleUpdateRule(index, updatedRule);
                setSelectedRule(updatedRule);
              }
            }}
            targetModel={targetModel}
            srxLicense={srxLicense}
            viewMode={platformView}
            isSanitized={isSanitized}
            llmWarningDismissed={llmWarningDismissed}
            onLLMWarning={() => setShowLLMWarning(true)}
            onAcceptRule={() => {
              const index = getCurrentRuleIndex();
              if (index >= 0) handleAcceptRule(index);
            }}
            onSetLLMReviewed={() => {
              const index = getCurrentRuleIndex();
              if (index >= 0) handleSetLLMReviewed(index);
            }}
          />
        )}

        {/* BOTTOM: SRX Output + Warnings */}
        <div className="panel output-panel">
          <div className="panel-header">
            <div className="tab-bar">
              <button
                className={`tab-btn ${bottomTab === 'output' ? 'active' : ''}`}
                onClick={() => setBottomTab('output')}
              >
                SRX Output
              </button>
              <button
                className={`tab-btn ${bottomTab === 'warnings' ? 'active' : ''}`}
                onClick={() => setBottomTab('warnings')}
              >
                Warnings
                {allWarnings.length > 0 && (
                  <span className="tab-badge warning-count">{allWarnings.length}</span>
                )}
              </button>
            </div>
            {bottomTab === 'output' && srxOutput && (
              <div className="output-toolbar">
                <div className="output-format-toggle">
                  <button
                    className={`format-btn ${outputFormat === 'set' ? 'active' : ''}`}
                    onClick={() => handleConvert('set')}
                  >
                    Set Commands
                  </button>
                  <button
                    className={`format-btn ${outputFormat === 'xml' ? 'active' : ''}`}
                    onClick={() => handleConvert('xml')}
                  >
                    XML
                  </button>
                </div>
              </div>
            )}
          </div>
          <div className="panel-body">
            {bottomTab === 'output' ? (
              <SRXOutput
                output={srxOutput}
                format={outputFormat}
                summary={conversionSummary}
                isParsed={!!intermediateConfig}
                sanitizationTable={sanitizationTable}
              />
            ) : (
              <WarningsPanel warnings={allWarnings} />
            )}
          </div>
        </div>
      </div>

      {/* --- Modals --- */}
      {showSettings && (
        <LLMSettings onClose={() => setShowSettings(false)} />
      )}

      {showModelSelector && intermediateConfig && (
        <ModelSelector
          intermediateConfig={intermediateConfig}
          sourceModel={sourceModel}
          targetModel={targetModel}
          srxLicense={srxLicense}
          onModelSelection={handleModelSelection}
          onContinue={handleModelContinue}
          onClose={() => setShowModelSelector(false)}
        />
      )}

      {showInterfaceMapper && intermediateConfig && (
        <InterfaceMapper
          intermediateConfig={intermediateConfig}
          sourceModel={sourceModel}
          targetModel={targetModel}
          interfaceMappings={interfaceMappings}
          onMappingComplete={handleMappingComplete}
          onClose={() => setShowInterfaceMapper(false)}
        />
      )}

      {/* LLM Warning Modal — shown when user tries AI suggestions without sanitizing */}
      {showLLMWarning && (
        <div className="modal-overlay" onClick={() => setShowLLMWarning(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ width: 480 }}>
            <div className="modal-header" style={{ borderBottomColor: 'rgba(248, 113, 113, 0.3)' }}>
              <h2 style={{ color: 'var(--warning)' }}>Security Warning</h2>
              <button className="modal-close" onClick={() => setShowLLMWarning(false)}>x</button>
            </div>
            <div className="modal-body">
              <div className="llm-warning-content">
                <p style={{ fontWeight: 600, marginBottom: 8 }}>
                  Your configuration has not been sanitized.
                </p>
                <p>
                  Sending firewall configurations to LLM providers may expose sensitive information including:
                </p>
                <ul>
                  <li>Public and private IP addresses</li>
                  <li>Usernames, password hashes, and API keys</li>
                  <li>Network topology and security architecture</li>
                  <li>VPN pre-shared keys and certificates</li>
                </ul>
                <p style={{ marginTop: 8 }}>
                  Use the <strong>Sanitize Configuration</strong> button to replace sensitive data with
                  placeholders before using AI suggestions. Originals are restored on export.
                </p>
              </div>
            </div>
            <div className="modal-footer" style={{ gap: 8 }}>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  setShowLLMWarning(false);
                  handleSanitize();
                }}
              >
                Sanitize First
              </button>
              <button
                className="btn btn-primary"
                onClick={() => {
                  setLlmWarningDismissed(true);
                  setShowLLMWarning(false);
                }}
                style={{ background: 'var(--warning)', borderColor: 'var(--warning)' }}
              >
                Proceed Without Sanitizing
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

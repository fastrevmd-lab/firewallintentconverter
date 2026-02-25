/**
 * Main Application Component
 *
 * Orchestrates the four-panel layout:
 *   LEFT:   ConfigInput   — paste/upload PAN-OS config
 *   CENTER: Tabbed editor — Security Rules / Zones / Objects / NAT
 *   RIGHT:  InterviewPanel — editable rule details + LLM suggestions
 *   BOTTOM: SRXOutput     — generated SRX commands + warnings
 *
 * State flow:
 *   1. User pastes/uploads config  →  configText
 *   2. Click "Parse" sends to /api/parse  →  intermediateConfig + parseWarnings
 *   3. ModelSelector auto-opens  →  sourceModel + targetModel
 *   4. InterfaceMapper opens  →  interfaceMappings
 *   5. User edits config in tabbed panels
 *   6. User reviews/accepts translated rules
 *   7. Click "Convert" sends to /api/convert  →  srxOutput + convertWarnings
 */
import React, { useState, useCallback, useMemo } from 'react';
import ConfigInput from './components/ConfigInput.jsx';
import PolicyTable from './components/PolicyTable.jsx';
import InterviewPanel from './components/InterviewPanel.jsx';
import SRXOutput from './components/SRXOutput.jsx';
import WarningsPanel from './components/WarningsPanel.jsx';
import LLMSettings from './components/LLMSettings.jsx';
import ModelSelector from './components/ModelSelector.jsx';
import InterfaceMapper from './components/InterfaceMapper.jsx';
import ZoneEditor from './components/ZoneEditor.jsx';
import ObjectEditor from './components/ObjectEditor.jsx';
import NATEditor from './components/NATEditor.jsx';
import RoutingEditor from './components/RoutingEditor.jsx';
import VPNEditor from './components/VPNEditor.jsx';
import HAEditor from './components/HAEditor.jsx';
import ScreenEditor from './components/ScreenEditor.jsx';
import SyslogEditor from './components/SyslogEditor.jsx';
import DHCPEditor from './components/DHCPEditor.jsx';
import QoSEditor from './components/QoSEditor.jsx';
import GreenfieldChat from './components/GreenfieldChat.jsx';
import FeedbackModal from './components/FeedbackModal.jsx';
import { translatePolicies, getLLMStatus } from './utils/llm-client.js';

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
  const [portProfile, setPortProfile] = useState(null);
  const [siteName, setSiteName] = useState('');
  const [siteGroup, setSiteGroup] = useState('');
  const [interfaceMappings, setInterfaceMappings] = useState({});
  const [sourceVendor, setSourceVendor] = useState('panos'); // 'panos' | 'srx' | 'fortigate' | 'cisco_asa' | 'greenfield'
  const [greenfieldMode, setGreenfieldMode] = useState(false);

  // --- Modal state ---
  const [showModelSelector, setShowModelSelector] = useState(false);
  const [showInterfaceMapper, setShowInterfaceMapper] = useState(false);

  // --- Center panel tab state ---
  const [editTab, setEditTab] = useState('rules');
  const [platformView, setPlatformView] = useState('panos'); // 'panos' | 'srx'

  // --- Conversion output state ---
  const [srxOutput, setSrxOutput] = useState(null);
  const [convertWarnings, setConvertWarnings] = useState([]);
  const [conversionSummary, setConversionSummary] = useState(null);
  const [outputFormat, setOutputFormat] = useState('set');

  // --- Routing context state ---
  const [targetContext, setTargetContext] = useState({ type: 'none', name: '' });

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
  const [showFeedback, setShowFeedback] = useState(false);
  const [showConvertConfirm, setShowConvertConfirm] = useState(false);
  const [showPushToast, setShowPushToast] = useState('');
  const [bottomTab, setBottomTab] = useState('output');
  const [error, setError] = useState(null);

  // --- LLM Translation state (feature/llm-translate) ---
  const [srxTranslatedPolicies, setSrxTranslatedPolicies] = useState(null);
  const [isTranslating, setIsTranslating] = useState(false);
  const [translationError, setTranslationError] = useState(null);
  const [translationProgress, setTranslationProgress] = useState(null);

  // --- All warnings combined (parse + convert) ---
  const allWarnings = [...parseWarnings, ...convertWarnings];

  // --- Review progress ---
  const reviewProgress = useMemo(() => {
    // When translated policies exist and we're on SRX tab, count those
    const policies = (platformView === 'srx' && srxTranslatedPolicies)
      ? srxTranslatedPolicies
      : (intermediateConfig?.security_policies || []);
    const accepted = policies.filter(r => r._review_status === 'accepted' || r.disabled).length;
    const llmReviewed = policies.filter(r => r._review_status === 'llm_reviewed').length;
    return { accepted, llmReviewed, total: policies.length };
  }, [intermediateConfig, srxTranslatedPolicies, platformView]);

  const allRulesAccepted = reviewProgress.total > 0 && reviewProgress.accepted === reviewProgress.total;

  // Compute effective viewMode: 'from' tab uses vendor-specific style
  const effectiveViewMode = platformView === 'srx' ? 'srx'
    : sourceVendor === 'srx' ? 'srx'
    : sourceVendor === 'fortigate' ? 'fortigate'
    : sourceVendor === 'cisco_asa' ? 'cisco'
    : sourceVendor === 'checkpoint' ? 'checkpoint'
    : sourceVendor === 'sonicwall' ? 'sonicwall'
    : sourceVendor === 'huawei_usg' ? 'huawei'
    : 'panos';

  // Display stats: use live metadata in greenfield mode, parseStats otherwise
  const displayStats = useMemo(() => {
    if (greenfieldMode && intermediateConfig?.metadata) return intermediateConfig.metadata;
    return parseStats;
  }, [greenfieldMode, intermediateConfig?.metadata, parseStats]);

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
    setLoadingMessage('Parsing configuration...');
    setError(null);
    setSrxOutput(null);
    setConvertWarnings([]);
    setConversionSummary(null);
    setSelectedRule(null);
    setEditTab('rules');
    setSrxTranslatedPolicies(null);
    setTranslationError(null);

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

      // Store detected vendor
      const detectedVendor = data.detectedVendor || data.intermediateConfig?.metadata?.source_vendor || 'panos';
      setSourceVendor(detectedVendor);

      // If source is not PAN-OS, default to 'panos' platform view (shows the "from" tab)
      if (['srx', 'fortigate', 'cisco_asa', 'checkpoint', 'sonicwall', 'huawei_usg'].includes(detectedVendor)) {
        setPlatformView('panos');
      }

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
  // Convert button click — warn if not all policies accepted
  // ------------------------------------------------------------------
  const handleConvertClick = useCallback((format = 'set') => {
    if (!allRulesAccepted) {
      setShowConvertConfirm(true);
      return;
    }
    handleConvert(format);
  }, [allRulesAccepted]);

  // ------------------------------------------------------------------
  // Convert handler: sends intermediate config to /api/convert
  // ------------------------------------------------------------------
  const handleConvert = useCallback(async (format = 'set') => {
    if (!intermediateConfig) return;
    setIsLoading(true);
    setLoadingMessage('Converting to SRX format...');
    setError(null);

    try {
      // Merge translated policies into the config sent to /api/convert
      const configForConversion = srxTranslatedPolicies
        ? { ...intermediateConfig, security_policies: srxTranslatedPolicies }
        : intermediateConfig;

      // Inject site identification metadata for output headers
      if (siteName || siteGroup) {
        configForConversion.metadata = {
          ...configForConversion.metadata,
          siteName: siteName || undefined,
          siteGroup: siteGroup || undefined,
        };
      }

      const response = await fetch('/api/convert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ intermediateConfig: configForConversion, format, interfaceMappings, targetContext: targetContext.type !== 'none' ? targetContext : null }),
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
  }, [intermediateConfig, interfaceMappings, srxTranslatedPolicies, siteName, siteGroup]);

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
        negate_source: false,
        negate_destination: false,
        applications: [],
        services: [],
        log_start: false,
        log_end: true,
        disabled: false,
        description: '',
        tags: ['added_by_fpic'],
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

  /** Update VPN tunnels */
  const handleVPNUpdate = useCallback((vpnTunnels) => {
    setIntermediateConfig(prev => ({ ...prev, vpn_tunnels: vpnTunnels }));
  }, []);

  /** Update HA config */
  const handleHAUpdate = useCallback((haConfig) => {
    setIntermediateConfig(prev => ({ ...prev, ha_config: haConfig }));
  }, []);

  /** Update Screen config */
  const handleScreenUpdate = useCallback((screenConfig) => {
    setIntermediateConfig(prev => ({ ...prev, screen_config: screenConfig }));
  }, []);

  /** Update Syslog config */
  const handleSyslogUpdate = useCallback((syslogConfig) => {
    setIntermediateConfig(prev => ({ ...prev, syslog_config: syslogConfig }));
  }, []);

  /** Update DHCP config */
  const handleDHCPUpdate = useCallback((dhcpConfig) => {
    setIntermediateConfig(prev => ({ ...prev, dhcp_config: dhcpConfig }));
  }, []);

  /** Update QoS config */
  const handleQoSUpdate = useCallback((qosConfig) => {
    setIntermediateConfig(prev => ({ ...prev, qos_config: qosConfig }));
  }, []);

  /** Update a config section (for ObjectEditor) */
  const handleConfigUpdate = useCallback((field, items) => {
    setIntermediateConfig(prev => ({ ...prev, [field]: items }));
  }, []);

  // ------------------------------------------------------------------
  // Greenfield handlers
  // ------------------------------------------------------------------

  /** Start greenfield interview — creates empty config skeleton */
  const handleStartGreenfield = useCallback(() => {
    const emptyConfig = {
      metadata: {
        source_vendor: 'greenfield',
        source_version: '',
        zone_count: 0,
        rule_count: 0,
        nat_rule_count: 0,
        object_count: 0,
        vpn_tunnel_count: 0,
        static_route_count: 0,
      },
      zones: [],
      security_policies: [],
      nat_rules: [],
      addresses: [],
      address_groups: [],
      services: [],
      service_groups: [],
      applications: [],
      vpn_tunnels: [],
      static_routes: [],
      interfaces: [],
      routing_contexts: [],
      ha_config: { enabled: false },
      screen_config: [],
      syslog_config: [],
      dhcp_config: [],
      qos_config: [],
    };

    setIntermediateConfig(emptyConfig);
    setSourceVendor('greenfield');
    setGreenfieldMode(true);
    setParseWarnings([]);
    setParseStats(emptyConfig.metadata);
    setSrxOutput(null);
    setConvertWarnings([]);
    setSelectedRule(null);
    setEditTab('rules');
    setLlmWarningDismissed(true); // Greenfield configs have no sensitive data
    setPlatformView('panos'); // Start on the "from LLM Interview" tab
    setShowModelSelector(true);
  }, []);

  /** Apply an action from the greenfield LLM interview */
  const handleGreenfieldAction = useCallback((action, data) => {
    setIntermediateConfig(prev => {
      const updated = { ...prev };

      switch (action) {
        case 'add_zone':
          updated.zones = [...(updated.zones || []), {
            name: data.name,
            description: data.description || '',
            interfaces: data.interfaces || [],
            screen: data.screen || '',
            host_inbound_traffic: data.host_inbound_traffic || {},
          }];
          break;

        case 'add_address':
          updated.addresses = [...(updated.addresses || []), {
            name: data.name,
            ip: data.ip || '',
            description: data.description || '',
          }];
          break;

        case 'add_address_group':
          updated.address_groups = [...(updated.address_groups || []), {
            name: data.name,
            members: data.members || [],
            description: data.description || '',
          }];
          break;

        case 'add_service':
          updated.services = [...(updated.services || []), {
            name: data.name,
            protocol: data.protocol || 'tcp',
            port: data.port || '',
            description: data.description || '',
          }];
          break;

        case 'add_policy': {
          const newIndex = (updated.security_policies?.length || 0) + 1;
          updated.security_policies = [...(updated.security_policies || []), {
            name: data.name,
            _rule_index: newIndex,
            action: data.action || 'deny',
            src_zones: data.src_zones || [],
            dst_zones: data.dst_zones || [],
            src_addresses: data.src_addresses || ['any'],
            dst_addresses: data.dst_addresses || ['any'],
            negate_source: false,
            negate_destination: false,
            applications: data.applications || [],
            services: data.services || ['any'],
            log_start: data.log_start || false,
            log_end: data.log_end !== false,
            disabled: false,
            description: data.description || '',
            tags: ['greenfield'],
            profile_group: '',
            security_profiles: {},
            _review_status: 'accepted',
          }];
          break;
        }

        case 'add_nat':
          updated.nat_rules = [...(updated.nat_rules || []), {
            name: data.name,
            type: data.type || 'source',
            src_zones: data.src_zones || [],
            dst_zones: data.dst_zones || [],
            src_addresses: data.src_addresses || ['any'],
            dst_addresses: data.dst_addresses || ['any'],
            translated_src: data.translated_src || null,
            translated_dst: data.translated_dst || null,
            translated_port: data.translated_port || null,
            description: data.description || '',
          }];
          break;

        case 'add_screen':
          updated.screen_config = [...(updated.screen_config || []), {
            name: data.name,
            zone: data.zone || '',
            ...(data.options || {}),
          }];
          break;

        case 'set_syslog':
          updated.syslog_config = [...(updated.syslog_config || []), {
            host: data.host,
            port: data.port || 514,
            protocol: data.protocol || 'udp',
            facility: data.facility || 'local0',
            source_address: data.source_address || '',
          }];
          break;

        case 'add_route':
          updated.static_routes = [...(updated.static_routes || []), {
            destination: data.destination,
            next_hop: data.next_hop,
            description: data.description || '',
          }];
          break;

        default:
          break;
      }

      // Update metadata counts
      updated.metadata = {
        ...updated.metadata,
        zone_count: updated.zones?.length || 0,
        rule_count: updated.security_policies?.length || 0,
        nat_rule_count: updated.nat_rules?.length || 0,
        object_count: (updated.addresses?.length || 0) + (updated.address_groups?.length || 0) + (updated.services?.length || 0),
        vpn_tunnel_count: updated.vpn_tunnels?.length || 0,
        static_route_count: updated.static_routes?.length || 0,
      };

      return updated;
    });
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


  // ------------------------------------------------------------------
  // Translated policy handlers (for LLM-translated SRX policies)
  // ------------------------------------------------------------------

  /** Update a translated policy by index */
  const handleUpdateTranslatedRule = useCallback((index, updatedRule) => {
    setSrxTranslatedPolicies(prev => {
      if (!prev) return prev;
      const policies = [...prev];
      policies[index] = updatedRule;
      return policies;
    });
  }, []);

  /** Accept a translated policy by index */
  const handleAcceptTranslatedRule = useCallback((index) => {
    setSrxTranslatedPolicies(prev => {
      if (!prev) return prev;
      const policies = [...prev];
      policies[index] = { ...policies[index], _review_status: 'accepted' };
      return policies;
    });
    setSelectedRule(prev => prev ? { ...prev, _review_status: 'accepted' } : prev);
  }, []);

  /** Delete a translated policy by index */
  const handleDeleteTranslatedRule = useCallback((index) => {
    setSrxTranslatedPolicies(prev => {
      if (!prev) return prev;
      return prev.filter((_, i) => i !== index).map((p, i) => ({ ...p, _rule_index: i }));
    });
    setSelectedRule(null);
  }, []);

  /** Add a new rule to translated policies */
  const handleAddTranslatedRule = useCallback(() => {
    setSrxTranslatedPolicies(prev => {
      const arr = prev || [];
      const newIndex = arr.length;
      return [...arr, {
        name: `new-rule-${newIndex + 1}`,
        _rule_index: newIndex,
        action: 'deny',
        src_zones: [],
        dst_zones: [],
        src_addresses: [],
        dst_addresses: [],
        negate_source: false,
        negate_destination: false,
        applications: [],
        services: [],
        log_start: false,
        log_end: true,
        disabled: false,
        description: '',
        tags: [],
        profile_group: '',
        security_profiles: {},
        _review_status: 'accepted',
        _translation_notes: 'Manually added rule',
      }];
    });
  }, []);

  /** Translate policies with LLM */
  const handleTranslateWithLLM = useCallback(async () => {
    if (!intermediateConfig?.security_policies?.length) return;

    // Check sanitization
    if (!isSanitized && !llmWarningDismissed) {
      setShowLLMWarning(true);
      return;
    }

    // Check LLM is configured
    const status = getLLMStatus();
    if (!status.configured) {
      setError('No LLM provider configured. Open Settings to configure one.');
      return;
    }

    setIsTranslating(true);
    setTranslationError(null);
    setTranslationProgress(null);
    setError(null);
    setIsLoading(true);
    setLoadingMessage('Translating policies with LLM...');

    try {
      const translated = await translatePolicies(intermediateConfig, targetModel, srxLicense, (progress) => {
        setTranslationProgress(progress);
      });
      setSrxTranslatedPolicies(translated);
      // Auto-switch to SRX view and rules tab
      setPlatformView('srx');
      setEditTab('rules');
      setSelectedRule(null);
    } catch (err) {
      setTranslationError(err.message);
      setError(`Translation error: ${err.message}`);
    } finally {
      setIsTranslating(false);
      setIsLoading(false);
      setLoadingMessage('');
    }
  }, [intermediateConfig, targetModel, srxLicense, isSanitized, llmWarningDismissed]);

  /** Get current rule index for the selected rule */
  const getCurrentRuleIndex = useCallback(() => {
    if (!selectedRule || !intermediateConfig) return -1;
    // Check translated policies first when on SRX tab
    const policies = (platformView === 'srx' && srxTranslatedPolicies)
      ? srxTranslatedPolicies
      : intermediateConfig.security_policies;
    return policies.findIndex(
      r => r.name === selectedRule.name && r._rule_index === selectedRule._rule_index
    );
  }, [selectedRule, intermediateConfig, srxTranslatedPolicies, platformView]);

  /** Switch platform view */
  const handlePlatformViewChange = useCallback((view) => {
    setPlatformView(view);
  }, []);

  // ------------------------------------------------------------------
  // Model / mapping handlers
  // ------------------------------------------------------------------

  const handleModelSelection = useCallback(({ sourceModel: src, targetModel: tgt, srxLicense: lic, portProfile: pp, siteName: sn, siteGroup: sg }) => {
    setSourceModel(src || '');
    // Clear interface mappings if target model or port profile changed
    if (tgt !== targetModel || pp !== portProfile) {
      setInterfaceMappings({});
    }
    setTargetModel(tgt || '');
    setSrxLicense(lic || '');
    setPortProfile(pp || null);
    setSiteName(sn || '');
    setSiteGroup(sg || '');
  }, [targetModel, portProfile]);

  const handleModelContinue = useCallback(() => {
    setShowModelSelector(false);
    // Skip InterfaceMapper in greenfield mode (no source interfaces to map)
    if (!greenfieldMode) {
      setShowInterfaceMapper(true);
    }
  }, [greenfieldMode]);

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
          <img src="/logo.png" alt="Intent Converter" className="brand-logo" />
          <h1>
            Firewall Policy to <span className="brand-accent">Intent Converter</span>
          </h1>
        </div>

        {/* Stats badges — shown after parsing */}
        {displayStats && (
          <div className="navbar-stats">
            {(sourceModel || greenfieldMode) && (
              <span className="stat-badge model-badge" onClick={() => setShowModelSelector(true)} style={{ cursor: 'pointer' }}>
                {greenfieldMode ? 'Greenfield' : sourceModel} <span style={{ color: 'var(--accent)', margin: '0 4px' }}>&rarr;</span> {targetModel || '?'}
              </span>
            )}
            {srxLicense && (
              <span className="stat-badge license-badge" onClick={() => setShowModelSelector(true)} style={{ cursor: 'pointer' }}>
                License <span className="stat-value">{srxLicense}</span>
              </span>
            )}
            {siteName && (
              <span className="stat-badge" onClick={() => setShowModelSelector(true)} style={{ cursor: 'pointer' }}>
                Site <span className="stat-value">{siteName}</span>
              </span>
            )}
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
                {reviewProgress.llmReviewed > 0 && (
                  <span style={{ color: 'var(--accent)', marginLeft: 6 }}>
                    ({reviewProgress.llmReviewed} LLM reviewed)
                  </span>
                )}
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
            onClick={() => setShowFeedback(true)}
            title="Send feedback or suggest a feature"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
            </svg>
          </button>
          <button
            className="settings-btn"
            onClick={() => setShowSettings('llm')}
            title="Settings"
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
          onStartGreenfield={handleStartGreenfield}
          greenfieldMode={greenfieldMode}
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
                    {greenfieldMode
                      ? 'from LLM Interview'
                      : `from ${sourceModel || ({ srx: 'SRX', fortigate: 'FortiGate', cisco_asa: 'Cisco ASA', checkpoint: 'Check Point', sonicwall: 'SonicWall', huawei_usg: 'Huawei USG' }[sourceVendor] || 'PAN-OS')}`
                    }
                  </button>
                  <button
                    className="btn btn-translate"
                    onClick={handleTranslateWithLLM}
                    disabled={isTranslating || !intermediateConfig?.security_policies?.length}
                    title="Translate source policies to SRX format using LLM"
                  >
                    {isTranslating ? (
                      <><span className="spinner" /> {greenfieldMode ? 'Importing...' : 'Translating...'}</>
                    ) : (
                      greenfieldMode ? 'Import LLM Config' : 'Translate with LLM'
                    )}
                  </button>
                  <button
                    className={`platform-view-btn ${platformView === 'srx' ? 'active' : ''}`}
                    onClick={() => handlePlatformViewChange('srx')}
                  >
                    to {targetModel || 'SRX'}
                  </button>
                  {platformView === 'srx' && (
                    <div className="platform-view-actions">
                      <select
                        className="btn btn-secondary btn-sm"
                        value={targetContext.type}
                        onChange={(e) => setTargetContext(prev => ({ ...prev, type: e.target.value, name: e.target.value === 'none' ? '' : prev.name }))}
                        style={{ maxWidth: 130 }}
                        title="Target context for SRX output"
                      >
                        <option value="none">Flat Config</option>
                        <option value="logical-system">Logical System</option>
                        <option value="tenant">Tenant</option>
                      </select>
                      {targetContext.type !== 'none' && (
                        <input
                          type="text"
                          className="btn btn-secondary btn-sm"
                          placeholder="Name..."
                          value={targetContext.name}
                          onChange={(e) => setTargetContext(prev => ({ ...prev, name: e.target.value }))}
                          style={{ maxWidth: 100, textAlign: 'left' }}
                        />
                      )}
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => handleConvertClick('set')}
                        disabled={isLoading}
                      >
                        Convert to SRX
                      </button>
                      <button
                        className="btn btn-secondary btn-sm push-btn"
                        onClick={() => setShowSettings('mcp')}
                        title="Push config to SRX via MCP"
                      >
                        Push MCP
                      </button>
                      <button
                        className="btn btn-secondary btn-sm push-btn"
                        onClick={() => setShowPushToast('SDC')}
                        title="Push to Security Director Cloud"
                      >
                        Push SDC
                      </button>
                      <button
                        className="btn btn-secondary btn-sm push-btn"
                        onClick={() => setShowPushToast('Mist')}
                        title="Push to Juniper Mist"
                      >
                        Push Mist
                      </button>
                    </div>
                  )}
                </div>

                {/* Hide tab bar when greenfield + "from LLM Interview" tab */}
                {!(greenfieldMode && platformView === 'panos') && (
                <div className="center-tab-bar">
                  <button
                    className={`center-tab-btn ${editTab === 'rules' ? 'active' : ''}`}
                    onClick={() => setEditTab('rules')}
                  >
                    {effectiveViewMode === 'srx' ? 'Security Policies' : effectiveViewMode === 'fortigate' ? 'Firewall Policies' : effectiveViewMode === 'cisco' ? 'Access Control' : effectiveViewMode === 'checkpoint' ? 'Access Rules' : effectiveViewMode === 'sonicwall' ? 'Access Rules' : effectiveViewMode === 'huawei' ? 'Security Policies' : 'Security Rules'} ({intermediateConfig.security_policies?.length || 0})
                  </button>
                  {platformView !== 'srx' && (
                  <button
                    className={`center-tab-btn ${editTab === 'decryption' ? 'active' : ''}`}
                    onClick={() => setEditTab('decryption')}
                  >
                    SSL B&amp;I ({intermediateConfig.decryption_rules?.length || 0})
                  </button>
                  )}
                  {platformView !== 'srx' && (
                  <button
                    className={`center-tab-btn ${editTab === 'pbf' ? 'active' : ''}`}
                    onClick={() => setEditTab('pbf')}
                  >
                    PBF ({intermediateConfig.pbf_rules?.length || 0})
                  </button>
                  )}
                  <button
                    className={`center-tab-btn ${editTab === 'objects' ? 'active' : ''}`}
                    onClick={() => setEditTab('objects')}
                  >
                    {effectiveViewMode === 'srx' ? 'Address Book' : 'Objects'} ({(intermediateConfig.address_objects?.length || 0) + (intermediateConfig.address_groups?.length || 0) + (intermediateConfig.service_objects?.length || 0) + (intermediateConfig.service_groups?.length || 0)})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'zones' ? 'active' : ''}`}
                    onClick={() => setEditTab('zones')}
                  >
                    {effectiveViewMode === 'srx' ? 'Security Zones' : 'Zones'} ({intermediateConfig.zones?.length || 0})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'screen' ? 'active' : ''}`}
                    onClick={() => setEditTab('screen')}
                  >
                    Screens ({intermediateConfig.screen_config?.length || 0})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'nat' ? 'active' : ''}`}
                    onClick={() => setEditTab('nat')}
                  >
                    NAT ({intermediateConfig.nat_rules?.length || 0})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'vpn' ? 'active' : ''}`}
                    onClick={() => setEditTab('vpn')}
                  >
                    VPN ({intermediateConfig.vpn_tunnels?.length || 0})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'routing' ? 'active' : ''}`}
                    onClick={() => setEditTab('routing')}
                  >
                    Intf/Routing ({intermediateConfig.interfaces?.length || 0}/{intermediateConfig.static_routes?.length || 0})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'dhcp' ? 'active' : ''}`}
                    onClick={() => setEditTab('dhcp')}
                  >
                    DHCP ({intermediateConfig.dhcp_config?.length || 0})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'qos' ? 'active' : ''}`}
                    onClick={() => setEditTab('qos')}
                  >
                    QoS ({intermediateConfig.qos_config?.length || 0})
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'ha' ? 'active' : ''}`}
                    onClick={() => setEditTab('ha')}
                  >
                    HA {intermediateConfig.ha_config?.enabled ? '(On)' : '(Off)'}
                  </button>
                  <button
                    className={`center-tab-btn ${editTab === 'syslog' ? 'active' : ''}`}
                    onClick={() => setEditTab('syslog')}
                  >
                    Syslog ({intermediateConfig.syslog_config?.length || 0})
                  </button>
                </div>
                )}
              </div>

              {/* Greenfield chat — always mounted in greenfield mode, hidden when on SRX tab */}
              {greenfieldMode && (
                <div style={{
                  display: platformView === 'panos' ? 'flex' : 'none',
                  flexDirection: 'column', flex: 1, overflow: 'hidden',
                }}>
                  <GreenfieldChat
                    intermediateConfig={intermediateConfig}
                    targetModel={targetModel}
                    srxLicense={srxLicense}
                    onApplyAction={handleGreenfieldAction}
                  />
                </div>
              )}

              {/* Normal tab content — shown when not greenfield, or on SRX tab */}
              <div style={{
                flex: 1, overflow: 'hidden', display: (greenfieldMode && platformView === 'panos') ? 'none' : 'flex', flexDirection: 'column',
              }}>
                {editTab === 'rules' && (
                  platformView === 'srx' && !srxTranslatedPolicies ? (
                    <div className="panel-body">
                      <div className="empty-state">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
                          <path d="M12 2L2 7l10 5 10-5-10-5z" />
                          <path d="M2 17l10 5 10-5" />
                          <path d="M2 12l10 5 10-5" />
                        </svg>
                        <h3>No translated policies yet</h3>
                        <p>Click "{greenfieldMode ? 'Import LLM Config' : 'Translate with LLM'}" to send the source ruleset to the LLM for translation to SRX format.</p>
                        <button
                          className="btn btn-translate"
                          onClick={handleTranslateWithLLM}
                          disabled={isTranslating || !intermediateConfig?.security_policies?.length}
                          style={{ marginTop: 12 }}
                        >
                          {isTranslating ? (greenfieldMode ? 'Importing...' : 'Translating...') : (greenfieldMode ? 'Import LLM Config' : 'Translate with LLM')}
                        </button>
                      </div>
                    </div>
                  ) : (
                    <PolicyTable
                      policies={
                        platformView === 'srx'
                          ? (srxTranslatedPolicies || [])
                          : (intermediateConfig.security_policies || [])
                      }
                      warnings={allWarnings}
                      selectedRule={selectedRule}
                      onSelectRule={setSelectedRule}
                      onUpdateRule={platformView === 'srx' && srxTranslatedPolicies ? handleUpdateTranslatedRule : handleUpdateRule}
                      onDeleteRule={platformView === 'srx' && srxTranslatedPolicies ? handleDeleteTranslatedRule : handleDeleteRule}
                      onAddRule={platformView === 'srx' && srxTranslatedPolicies ? handleAddTranslatedRule : handleAddRule}
                      viewMode={effectiveViewMode}
                      platformView={platformView}
                    />
                  )
                )}
                {editTab === 'decryption' && (
                  <div className="panel-body" style={{ overflow: 'auto', flex: 1 }}>
                    <table className="policy-table">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Name</th>
                          <th>Src Zone</th>
                          <th>Dst Zone</th>
                          <th>Source</th>
                          <th>Destination</th>
                          <th>Service</th>
                          <th>URL Category</th>
                          <th>Type</th>
                          <th>Action</th>
                          <th>Profile</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(intermediateConfig.decryption_rules || []).map((rule, i) => (
                          <tr key={i} className={rule.disabled ? 'disabled-row' : ''}>
                            <td>{rule._rule_index}</td>
                            <td className="rule-name">{rule.name}</td>
                            <td>{rule.src_zones?.join(', ') || 'any'}</td>
                            <td>{rule.dst_zones?.join(', ') || 'any'}</td>
                            <td>{rule.src_addresses?.join(', ') || 'any'}</td>
                            <td>{rule.dst_addresses?.join(', ') || 'any'}</td>
                            <td>{rule.services?.join(', ') || 'any'}</td>
                            <td>{rule.url_categories?.join(', ') || 'any'}</td>
                            <td><span className="badge">{rule.decryption_type || '—'}</span></td>
                            <td><span className={`action-badge ${rule.action === 'decrypt' ? 'allow' : 'deny'}`}>{rule.action}</span></td>
                            <td>{rule.decryption_profile || '—'}</td>
                            <td className="desc-cell">{rule.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {editTab === 'pbf' && (
                  <div className="panel-body" style={{ overflow: 'auto', flex: 1 }}>
                    <table className="policy-table">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Name</th>
                          <th>From ({'{type}'})</th>
                          <th>Source</th>
                          <th>Destination</th>
                          <th>Application</th>
                          <th>Service</th>
                          <th>Action</th>
                          <th>Egress Intf</th>
                          <th>Next Hop</th>
                          <th>Monitor</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(intermediateConfig.pbf_rules || []).map((rule, i) => (
                          <tr key={i} className={rule.disabled ? 'disabled-row' : ''}>
                            <td>{rule._rule_index}</td>
                            <td className="rule-name">{rule.name}</td>
                            <td>{rule.from_value?.join(', ') || '—'} <span className="badge">{rule.from_type}</span></td>
                            <td>{rule.src_addresses?.join(', ') || 'any'}</td>
                            <td>{rule.dst_addresses?.join(', ') || 'any'}</td>
                            <td>{rule.applications?.join(', ') || 'any'}</td>
                            <td>{rule.services?.join(', ') || 'any'}</td>
                            <td><span className={`action-badge ${rule.action === 'forward' ? 'allow' : rule.action === 'discard' ? 'deny' : ''}`}>{rule.action}</span></td>
                            <td>{rule.egress_interface || '—'}</td>
                            <td>{rule.next_hop_value ? `${rule.next_hop_type}: ${rule.next_hop_value}` : '—'}</td>
                            <td>{rule.monitor_ip ? `${rule.monitor_ip}${rule.monitor_disable_if_unreachable ? ' (failover)' : ''}` : '—'}</td>
                            <td className="desc-cell">{rule.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {editTab === 'zones' && (
                  <ZoneEditor
                    zones={intermediateConfig.zones || []}
                    onZonesUpdate={handleZonesUpdate}
                    viewMode={effectiveViewMode}
                    interfaceMappings={interfaceMappings}
                  />
                )}
                {editTab === 'objects' && (
                  <ObjectEditor
                    intermediateConfig={intermediateConfig}
                    onConfigUpdate={handleConfigUpdate}
                    viewMode={effectiveViewMode}
                  />
                )}
                {editTab === 'nat' && (
                  <NATEditor
                    natRules={intermediateConfig.nat_rules || []}
                    onNATUpdate={handleNATUpdate}
                    viewMode={effectiveViewMode}
                  />
                )}
                {editTab === 'routing' && (
                  <RoutingEditor
                    routingContexts={intermediateConfig.routing_contexts || []}
                    staticRoutes={intermediateConfig.static_routes || []}
                    interfaces={intermediateConfig.interfaces || []}
                    bridgeDomains={intermediateConfig.bridge_domains || []}
                    l2Interfaces={intermediateConfig.l2_interfaces || []}
                    vwirePairs={intermediateConfig.vwire_pairs || []}
                    onRoutesUpdate={(routes) => {
                      const updated = { ...intermediateConfig, static_routes: routes };
                      setIntermediateConfig(updated);
                    }}
                    onInterfacesUpdate={(interfaces) => {
                      setIntermediateConfig(prev => ({ ...prev, interfaces }));
                    }}
                    onBridgeDomainsUpdate={(bridgeDomains) => {
                      setIntermediateConfig(prev => ({ ...prev, bridge_domains: bridgeDomains }));
                    }}
                    onL2InterfacesUpdate={(l2Interfaces) => {
                      setIntermediateConfig(prev => ({ ...prev, l2_interfaces: l2Interfaces }));
                    }}
                    onVwirePairsUpdate={(vwirePairs) => {
                      setIntermediateConfig(prev => ({ ...prev, vwire_pairs: vwirePairs }));
                    }}
                  />
                )}
                {editTab === 'vpn' && (
                  <VPNEditor
                    vpnTunnels={intermediateConfig.vpn_tunnels || []}
                    onVPNUpdate={handleVPNUpdate}
                    viewMode={effectiveViewMode}
                  />
                )}
                {editTab === 'ha' && (
                  <HAEditor
                    haConfig={intermediateConfig.ha_config}
                    onHAUpdate={handleHAUpdate}
                    viewMode={effectiveViewMode}
                    targetModel={targetModel}
                  />
                )}
                {editTab === 'screen' && (
                  <ScreenEditor
                    screenConfig={intermediateConfig.screen_config || []}
                    onScreenUpdate={handleScreenUpdate}
                    viewMode={effectiveViewMode}
                  />
                )}
                {editTab === 'syslog' && (
                  <SyslogEditor
                    syslogConfig={intermediateConfig.syslog_config || []}
                    onSyslogUpdate={handleSyslogUpdate}
                    viewMode={effectiveViewMode}
                  />
                )}
                {editTab === 'dhcp' && (
                  <DHCPEditor
                    dhcpConfig={intermediateConfig.dhcp_config || []}
                    onDHCPUpdate={handleDHCPUpdate}
                    viewMode={effectiveViewMode}
                  />
                )}
                {editTab === 'qos' && (
                  <QoSEditor
                    qosConfig={intermediateConfig.qos_config || []}
                    onQoSUpdate={handleQoSUpdate}
                    viewMode={effectiveViewMode}
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
                  <p>Select "Greenfield" to build a new SRX config from scratch, or paste an existing firewall configuration and click "Parse".</p>
                </div>
              </div>
            </>
          )}
        </div>

        {/* RIGHT: Interview / Rule Details */}
        <InterviewPanel
          selectedRule={selectedRule}
          intermediateConfig={intermediateConfig}
          warnings={allWarnings}
          isTranslating={isTranslating}
          translationProgress={translationProgress}
          onUpdateRule={(updatedRule) => {
            if (!selectedRule) return;
            const isTranslated = platformView === 'srx' && srxTranslatedPolicies;
            const policies = isTranslated
              ? srxTranslatedPolicies
              : intermediateConfig?.security_policies;
            if (!policies) return;
            const index = policies.findIndex(
              r => r.name === selectedRule.name && r._rule_index === selectedRule._rule_index
            );
            if (index >= 0) {
              if (isTranslated) {
                handleUpdateTranslatedRule(index, updatedRule);
              } else {
                handleUpdateRule(index, updatedRule);
              }
              setSelectedRule(updatedRule);
            }
          }}
          targetModel={targetModel}
          srxLicense={srxLicense}
          viewMode={effectiveViewMode}
          platformView={platformView}
          onAcceptRule={() => {
            const index = getCurrentRuleIndex();
            if (index < 0) return;
            if (platformView === 'srx' && srxTranslatedPolicies) {
              handleAcceptTranslatedRule(index);
            } else {
              handleAcceptRule(index);
            }
          }}
        />

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
      {showFeedback && (
        <FeedbackModal onClose={() => setShowFeedback(false)} />
      )}

      {showSettings && (
        <LLMSettings
          initialTab={showSettings === 'mcp' ? 'mcp' : 'llm'}
          onClose={() => setShowSettings(false)}
        />
      )}

      {/* Convert confirmation — not all policies accepted */}
      {showConvertConfirm && (
        <div className="modal-overlay" onClick={() => setShowConvertConfirm(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ width: 440 }}>
            <div className="modal-header" style={{ borderBottomColor: 'rgba(234, 179, 8, 0.3)' }}>
              <h2 style={{ color: 'var(--warning)' }}>Unaccepted Policies</h2>
              <button className="modal-close" onClick={() => setShowConvertConfirm(false)}>x</button>
            </div>
            <div className="modal-body">
              <p style={{ marginBottom: 8 }}>
                <strong>{reviewProgress.total - reviewProgress.accepted}</strong> of {reviewProgress.total} policies
                have not been accepted yet.
              </p>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                Converting without reviewing all policies may produce output that hasn't been fully validated.
              </p>
            </div>
            <div className="modal-footer" style={{ gap: 8 }}>
              <button className="btn btn-secondary" onClick={() => setShowConvertConfirm(false)}>
                Go Back
              </button>
              <button className="btn btn-primary" onClick={() => { setShowConvertConfirm(false); handleConvert('set'); }}>
                Convert Anyway
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Push coming-soon toasts */}
      {showPushToast && (
        <div className="modal-overlay" onClick={() => setShowPushToast('')}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ width: 400 }}>
            <div className="modal-header">
              <h2>Push to {showPushToast}</h2>
              <button className="modal-close" onClick={() => setShowPushToast('')}>x</button>
            </div>
            <div className="modal-body" style={{ textAlign: 'center', padding: '24px 16px' }}>
              <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.4 }}>
                {showPushToast === 'SDC' ? '\uD83D\uDEE1\uFE0F' : '\u2601\uFE0F'}
              </div>
              <p style={{ fontWeight: 600, marginBottom: 8 }}>
                Feature Coming Soon
              </p>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                {showPushToast === 'SDC'
                  ? 'Push to Security Director Cloud via SDC API — coming in a future release.'
                  : 'Push to Juniper Mist Cloud via Mist API — coming in a future release.'}
              </p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-primary" onClick={() => setShowPushToast('')}>OK</button>
            </div>
          </div>
        </div>
      )}

      {showModelSelector && intermediateConfig && (
        <ModelSelector
          intermediateConfig={intermediateConfig}
          sourceModel={sourceModel}
          targetModel={targetModel}
          srxLicense={srxLicense}
          siteName={siteName}
          siteGroup={siteGroup}
          sourceVendor={sourceVendor}
          greenfieldMode={greenfieldMode}
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
          portProfile={portProfile}
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

import React, { Suspense, useMemo, useCallback } from 'react';
import { useConfigContext } from '../../contexts/ConfigContext.jsx';
import { useConversionContext } from '../../contexts/ConversionContext.jsx';
import { useUIContext } from '../../contexts/UIContext.jsx';
import { useMergeContext } from '../../contexts/MergeContext.jsx';

// Editor components — lazy-loaded per tab (only one visible at a time)
const ConfigInput = React.lazy(() => import('../ConfigInput.jsx'));
const PolicyTable = React.lazy(() => import('../PolicyTable.jsx'));
const BulkActionBar = React.lazy(() => import('../BulkActionBar.jsx'));
const ZoneEditor = React.lazy(() => import('../ZoneEditor.jsx'));
const ObjectEditor = React.lazy(() => import('../ObjectEditor.jsx'));
const NATEditor = React.lazy(() => import('../NATEditor.jsx'));
const RoutingEditor = React.lazy(() => import('../RoutingEditor.jsx'));
const VPNEditor = React.lazy(() => import('../VPNEditor.jsx'));
const HAEditor = React.lazy(() => import('../HAEditor.jsx'));
const ScreenEditor = React.lazy(() => import('../ScreenEditor.jsx'));
const SyslogEditor = React.lazy(() => import('../SyslogEditor.jsx'));
const DHCPEditor = React.lazy(() => import('../DHCPEditor.jsx'));
const QoSEditor = React.lazy(() => import('../QoSEditor.jsx'));
const GreenfieldChat = React.lazy(() => import('../GreenfieldChat.jsx'));
const SRXOutput = React.lazy(() => import('../SRXOutput.jsx'));
const WarningsPanel = React.lazy(() => import('../WarningsPanel.jsx'));
const DiffPanel = React.lazy(() => import('../DiffPanel.jsx'));

const LoadingTab = () => (
  <div className="center-content" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1, color: 'var(--text-muted)' }}>
    <span className="spinner" style={{ marginRight: 8 }} />Loading...
  </div>
);

// Hooks
import useConfig from '../../hooks/useConfig.js';
import useConversion from '../../hooks/useConversion.js';
import useLLM from '../../hooks/useLLM.js';

/* ── Sanitization helpers ──────────────────────────────────────── */
const SANITIZE_TYPE_LABELS = {
  hash: 'Hash', key: 'Key', community: 'SNMP', username: 'User', public_ip: 'Public IP',
  certificate: 'Certificate', hostname: 'Hostname', bgp: 'BGP AS',
};

function maskSensitiveValue(entry) {
  if (entry.type === 'public_ip') return entry.original;
  const val = entry.original || '';
  if (val.length <= 4) return '****';
  return val.substring(0, 3) + '****';
}

/**
 * ContentRouter — Maps editTab to the appropriate editor, bridging
 * context data to existing prop-based components.
 */
export default function ContentRouter({
  onStartGreenfield,
  onStartGreenfieldWithTemplate,
  onGreenfieldAction,
  onModeSwitch,
  onAddSlot,
  onRemoveSlot,
  onUpdateSlotLsName,
  onParseSlot,
}) {
  const { state: cfg, dispatch: cfgDispatch } = useConfigContext();
  const { state: conv, dispatch: convDispatch } = useConversionContext();
  const { state: ui, dispatch: uiDispatch } = useUIContext();
  const { state: merge, dispatch: mergeDispatch } = useMergeContext();

  const config = useConfig();
  const conversion = useConversion();
  const llm = useLLM();

  const {
    intermediateConfig, sourceVendor, sourceModel, targetModel,
    srxLicense, greenfieldMode, greenfieldTemplate,
    isSanitized, sanitizationTable, parseWarnings,
    interfaceMappings, warningStatuses,
    srxTranslatedPolicies, ruleGroups,
  } = cfg;
  const { srxOutput, convertWarnings, conversionSummary, outputFormat, targetContext } = conv;
  const { editTab, platformView, selectedRule, isLoading, isTranslating, translationProgress } = ui;
  const { mergeMode, configSlots, activeSlotIndex, crossLsLinks } = merge;

  const isHealthCheckMode = sourceVendor === 'srx_healthcheck';
  const activeConfig = mergeMode
    ? configSlots[activeSlotIndex]?.intermediateConfig
    : intermediateConfig;

  // Compute effective view mode
  const effectiveViewMode = platformView === 'srx' ? 'srx'
    : sourceVendor === 'srx' || isHealthCheckMode ? 'srx'
    : sourceVendor === 'fortigate' ? 'fortigate'
    : sourceVendor === 'cisco_asa' ? 'cisco'
    : sourceVendor === 'checkpoint' ? 'checkpoint'
    : sourceVendor === 'sonicwall' ? 'sonicwall'
    : sourceVendor === 'huawei_usg' ? 'huawei'
    : 'panos';

  const allWarnings = useMemo(() => [...(parseWarnings || []), ...(convertWarnings || [])], [parseWarnings, convertWarnings]);

  const suggestionsData = useMemo(() => {
    if (!activeConfig) return null;
    return {
      src_zones: (activeConfig.zones || []).map(z => z.name),
      dst_zones: (activeConfig.zones || []).map(z => z.name),
      src_addresses: [
        ...(activeConfig.address_objects || []).map(a => a.name),
        ...(activeConfig.address_groups || []).map(g => g.name),
      ],
      dst_addresses: [
        ...(activeConfig.address_objects || []).map(a => a.name),
        ...(activeConfig.address_groups || []).map(g => g.name),
      ],
      services: (activeConfig.service_objects || []).map(s => s.name),
      applications: [
        ...(activeConfig.applications || []).map(a => a.name),
        ...(activeConfig.application_groups || []).map(g => g.name),
      ],
    };
  }, [activeConfig]);

  const handleWarningAction = useCallback((index, action) => {
    cfgDispatch({
      type: 'SET_FIELD', field: 'warningStatuses',
      value: { ...warningStatuses, ...(action ? { [index]: action } : (() => { const v = { ...warningStatuses }; delete v[index]; return v; })()) },
    });
  }, [warningStatuses, cfgDispatch]);

  // --- Import / Config Input ---
  if (editTab === 'import') {
    return (
      <div className="center-content" style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, overflow: 'hidden' }}>
        <ConfigInput
          configText={mergeMode ? (configSlots[activeSlotIndex]?.configText || '') : cfg.configText}
          onConfigChange={mergeMode
            ? (text) => mergeDispatch({ type: 'UPDATE_SLOT', index: activeSlotIndex, slot: { configText: text } })
            : config.handleConfigChange
          }
          onParse={mergeMode ? (() => onParseSlot(activeSlotIndex)) : config.handleParse}
          onFileLoaded={mergeMode ? undefined : (text, vendor) => config.handleParse(vendor, text)}
          onStartGreenfield={onStartGreenfield}
          onStartGreenfieldWithTemplate={onStartGreenfieldWithTemplate}
          greenfieldMode={greenfieldMode}
          isLoading={isLoading}
          isParsed={mergeMode ? !!configSlots[activeSlotIndex]?.intermediateConfig : !!intermediateConfig}
          isSanitized={mergeMode ? (configSlots[activeSlotIndex]?.isSanitized || false) : isSanitized}
          sanitizationTable={mergeMode ? (configSlots[activeSlotIndex]?.sanitizationTable || null) : sanitizationTable}
          sourceModel={sourceModel}
          targetModel={targetModel}
          onOpenModels={() => uiDispatch({ type: 'SHOW_MODAL', name: 'modelSelector' })}
          mergeMode={mergeMode}
          configSlots={configSlots}
          activeSlotIndex={activeSlotIndex}
          onActivateSlot={(i) => mergeDispatch({ type: 'SET_FIELD', field: 'activeSlotIndex', value: i })}
          onAddSlot={onAddSlot}
          onRemoveSlot={onRemoveSlot}
          onUpdateSlotLsName={onUpdateSlotLsName}
        />
      </div>
    );
  }

  // --- Sanitized Objects ---
  if (editTab === 'sanitized') {
    const table = mergeMode
      ? (configSlots[activeSlotIndex]?.sanitizationTable || [])
      : (sanitizationTable || []);

    if (!table.length) {
      return (
        <div className="center-content" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1 }}>
          <div className="empty-state">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <h3>No sanitized objects</h3>
            <p>Parse a configuration to see sanitized items here.</p>
          </div>
        </div>
      );
    }

    const typeCounts = {};
    for (const entry of table) {
      const label = SANITIZE_TYPE_LABELS[entry.type] || entry.type;
      typeCounts[label] = (typeCounts[label] || 0) + 1;
    }

    return (
      <div className="center-content" style={{ flex: 1, overflow: 'auto' }}>
        <div className="panel-body" style={{ padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--success)" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <h2 style={{ margin: 0, fontSize: 16 }}>Sanitized Objects</h2>
            <span className="nav-badge">{table.length}</span>
          </div>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
            {Object.entries(typeCounts).map(([label, count]) => (
              <span key={label} className="stat-badge">{count} {label}{count > 1 ? 's' : ''}</span>
            ))}
          </div>

          <div className="sanitize-table-container" style={{ maxHeight: 'none' }}>
            <table className="sanitize-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Original</th>
                  <th>Placeholder</th>
                  <th>Restore</th>
                </tr>
              </thead>
              <tbody>
                {table.map((entry, i) => (
                  <tr key={i}>
                    <td>
                      <span className={`sanitize-type-badge ${entry.type}`}>
                        {SANITIZE_TYPE_LABELS[entry.type] || entry.type}
                      </span>
                    </td>
                    <td className="sanitize-original">{maskSensitiveValue(entry)}</td>
                    <td className="sanitize-placeholder"><code>{entry.placeholder}</code></td>
                    <td>
                      {entry.restore
                        ? <span className="sanitize-restore-yes">Yes</span>
                        : <span className="sanitize-restore-no">No</span>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  }

  // If no config loaded, show empty state
  if (!activeConfig && editTab !== 'output' && editTab !== 'warnings' && editTab !== 'diff') {
    return (
      <div className="center-content" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1 }}>
        <div className="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <line x1="3" y1="9" x2="21" y2="9" />
            <line x1="9" y1="21" x2="9" y2="9" />
          </svg>
          <h3>No configuration loaded</h3>
          <p>Navigate to Import to paste a config or start a Greenfield interview.</p>
        </div>
      </div>
    );
  }

  // --- Platform view bar + tab content ---
  const renderPlatformBar = () => (
    <div className="platform-view-bar">
      <button
        className={`platform-view-btn ${platformView === 'panos' ? 'active' : ''}`}
        onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: 'panos' })}
      >
        {greenfieldMode ? 'from LLM Interview'
          : isHealthCheckMode ? 'Original Config'
          : `from ${sourceModel || ({ panos: 'PAN-OS', srx: 'SRX', fortigate: 'FortiGate', cisco_asa: 'Cisco ASA', checkpoint: 'Check Point', sonicwall: 'SonicWall', huawei_usg: 'Huawei USG' }[sourceVendor] || 'PAN-OS')}`
        }
      </button>
      <button
        className="btn btn-translate"
        onClick={llm.handleTranslateWithLLM}
        disabled={isTranslating || !intermediateConfig?.security_policies?.length}
        title={isHealthCheckMode ? 'Check best practices using LLM' : 'Translate source policies to SRX format using LLM'}
      >
        {isTranslating
          ? <><span className="spinner" /> {isHealthCheckMode ? 'Checking...' : greenfieldMode ? 'Importing...' : 'Translating...'}</>
          : (isHealthCheckMode ? 'Check Best Practice w/LLM' : greenfieldMode ? 'Import LLM Config' : 'Translate with LLM')
        }
      </button>
      <button
        className={`platform-view-btn ${platformView === 'srx' ? 'active' : ''}`}
        onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: 'srx' })}
      >
        {isHealthCheckMode ? 'Best Practice Status' : `to ${targetModel || 'SRX'}`}
      </button>
      {platformView === 'srx' && (
        <div className="platform-view-actions">
          <select
            className="btn btn-secondary btn-sm"
            value={targetContext.type}
            onChange={(e) => convDispatch({ type: 'SET_FIELD', field: 'targetContext', value: { ...targetContext, type: e.target.value, name: e.target.value === 'none' ? '' : targetContext.name } })}
            style={{ maxWidth: 130 }}
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
              onChange={(e) => convDispatch({ type: 'SET_FIELD', field: 'targetContext', value: { ...targetContext, name: e.target.value } })}
              style={{ maxWidth: 100, textAlign: 'left' }}
            />
          )}
          <button
            className="btn btn-primary btn-sm"
            onClick={() => mergeMode ? conversion.handleMergeConvert('set') : conversion.handleConvertClick('set')}
            disabled={isLoading}
          >
            {mergeMode ? 'Merge & Convert' : 'Convert to SRX'}
          </button>
          <button className="btn btn-secondary btn-sm push-btn" onClick={() => uiDispatch({ type: 'SHOW_MODAL', name: 'settings', value: 'mcp' })} title="Push config to SRX via MCP">Push MCP</button>
          <button className="btn btn-secondary btn-sm push-btn" onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'showPushToast', value: 'SDC' })}>Push SDC</button>
          <button className="btn btn-secondary btn-sm push-btn" onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'showPushToast', value: 'Mist' })}>Push Mist</button>
        </div>
      )}
    </div>
  );

  // --- Security Policies ---
  if (editTab === 'rules') {
    if (greenfieldMode && platformView === 'panos') {
      return (
        <div className="center-content" style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
          {renderPlatformBar()}
          <GreenfieldChat
            intermediateConfig={intermediateConfig}
            targetModel={targetModel}
            srxLicense={srxLicense}
            greenfieldTemplate={greenfieldTemplate}
            onApplyAction={onGreenfieldAction}
          />
        </div>
      );
    }

    if (platformView === 'srx' && !srxTranslatedPolicies) {
      return (
        <div className="center-content" style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
          {renderPlatformBar()}
          <div className="panel-body">
            <div className="empty-state">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
                <path d="M12 2L2 7l10 5 10-5-10-5z" />
                <path d="M2 17l10 5 10-5" />
                <path d="M2 12l10 5 10-5" />
              </svg>
              <h3>No translated policies yet</h3>
              <p>Click "{greenfieldMode ? 'Import LLM Config' : 'Translate with LLM'}" to send the source ruleset to the LLM for translation to SRX format.</p>
              <button className="btn btn-translate" onClick={llm.handleTranslateWithLLM} disabled={isTranslating || !intermediateConfig?.security_policies?.length} style={{ marginTop: 12 }}>
                {isTranslating ? (greenfieldMode ? 'Importing...' : 'Translating...') : (greenfieldMode ? 'Import LLM Config' : 'Translate with LLM')}
              </button>
            </div>
          </div>
        </div>
      );
    }

    const policies = platformView === 'srx'
      ? (srxTranslatedPolicies || [])
      : (activeConfig?.security_policies || []);
    const isTranslated = platformView === 'srx' && srxTranslatedPolicies;

    return (
      <div className="center-content" style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
        {renderPlatformBar()}
        <PolicyTable
          policies={policies}
          warnings={allWarnings}
          selectedRule={selectedRule}
          onSelectRule={(r) => uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: r })}
          onUpdateRule={isTranslated ? llm.handleUpdateTranslatedRule : config.handleUpdateRule}
          onDeleteRule={isTranslated ? llm.handleDeleteTranslatedRule : config.handleDeleteRule}
          onAddRule={isTranslated ? llm.handleAddTranslatedRule : config.handleAddRule}
          viewMode={effectiveViewMode}
          platformView={platformView}
          selectedRuleKeys={cfg.selectedRuleKeys}
          onToggleRuleSelect={llm.handleToggleRuleSelect}
          onSelectAllRules={llm.handleSelectAllRules}
          ruleGroups={ruleGroups}
          onUpdateGroups={(groups) => cfgDispatch({ type: 'SET_RULE_GROUPS', groups })}
          onGroupWithAI={llm.handleGroupWithAI}
          groupingInProgress={ui.groupingInProgress}
          suggestionsData={suggestionsData}
        />
        <BulkActionBar
          selectedCount={cfg.selectedRuleKeys.size}
          onAcceptAll={llm.handleBulkAccept}
          onDeleteSelected={llm.handleBulkDelete}
          onToggleDisable={llm.handleBulkToggleDisable}
          onMoveUp={() => llm.handleBulkMove('up')}
          onMoveDown={() => llm.handleBulkMove('down')}
          onClearSelection={() => cfgDispatch({ type: 'SET_SELECTED_KEYS', keys: [] })}
        />
      </div>
    );
  }

  // --- Inline table views ---
  if (editTab === 'decryption') {
    return (
      <div className="center-content" style={{ flex: 1, overflow: 'auto' }}>
        {renderPlatformBar()}
        <div className="panel-body" style={{ overflow: 'auto', flex: 1 }}>
          <table className="policy-table">
            <thead><tr><th>#</th><th>Name</th><th>Src Zone</th><th>Dst Zone</th><th>Source</th><th>Destination</th><th>Service</th><th>URL Category</th><th>Type</th><th>Action</th><th>Profile</th><th>Description</th></tr></thead>
            <tbody>
              {(intermediateConfig?.decryption_rules || []).map((rule, i) => (
                <tr key={i} className={rule.disabled ? 'disabled-row' : ''}>
                  <td>{rule._rule_index}</td>
                  <td className="rule-name">{rule.name}</td>
                  <td>{rule.src_zones?.join(', ') || 'any'}</td>
                  <td>{rule.dst_zones?.join(', ') || 'any'}</td>
                  <td>{rule.src_addresses?.join(', ') || 'any'}</td>
                  <td>{rule.dst_addresses?.join(', ') || 'any'}</td>
                  <td>{rule.services?.join(', ') || 'any'}</td>
                  <td>{rule.url_categories?.join(', ') || 'any'}</td>
                  <td><span className="badge">{rule.decryption_type || '\u2014'}</span></td>
                  <td><span className={`action-badge ${rule.action === 'decrypt' ? 'allow' : 'deny'}`}>{rule.action}</span></td>
                  <td>{rule.decryption_profile || '\u2014'}</td>
                  <td className="desc-cell">{rule.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  if (editTab === 'pbf') {
    return (
      <div className="center-content" style={{ flex: 1, overflow: 'auto' }}>
        {renderPlatformBar()}
        <div className="panel-body" style={{ overflow: 'auto', flex: 1 }}>
          <table className="policy-table">
            <thead><tr><th>#</th><th>Name</th><th>From (type)</th><th>Source</th><th>Destination</th><th>Application</th><th>Service</th><th>Action</th><th>Egress Intf</th><th>Next Hop</th><th>Monitor</th><th>Description</th></tr></thead>
            <tbody>
              {(intermediateConfig?.pbf_rules || []).map((rule, i) => (
                <tr key={i} className={rule.disabled ? 'disabled-row' : ''}>
                  <td>{rule._rule_index}</td>
                  <td className="rule-name">{rule.name}</td>
                  <td>{rule.from_value?.join(', ') || '\u2014'} <span className="badge">{rule.from_type}</span></td>
                  <td>{rule.src_addresses?.join(', ') || 'any'}</td>
                  <td>{rule.dst_addresses?.join(', ') || 'any'}</td>
                  <td>{rule.applications?.join(', ') || 'any'}</td>
                  <td>{rule.services?.join(', ') || 'any'}</td>
                  <td><span className={`action-badge ${rule.action === 'forward' ? 'allow' : rule.action === 'discard' ? 'deny' : ''}`}>{rule.action}</span></td>
                  <td>{rule.egress_interface || '\u2014'}</td>
                  <td>{rule.next_hop_value ? `${rule.next_hop_type}: ${rule.next_hop_value}` : '\u2014'}</td>
                  <td>{rule.monitor_ip ? `${rule.monitor_ip}${rule.monitor_disable_if_unreachable ? ' (failover)' : ''}` : '\u2014'}</td>
                  <td className="desc-cell">{rule.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // --- Editor components ---
  if (editTab === 'zones') {
    return <div className="center-content" style={{ flex: 1, overflow: 'auto' }}><ZoneEditor zones={activeConfig?.zones || []} onZonesUpdate={config.handleZonesUpdate} viewMode={effectiveViewMode} interfaceMappings={interfaceMappings} /></div>;
  }

  if (editTab === 'objects') {
    return <div className="center-content" style={{ flex: 1, overflow: 'auto' }}><ObjectEditor intermediateConfig={activeConfig} onConfigUpdate={config.handleConfigUpdate} viewMode={effectiveViewMode} /></div>;
  }

  if (editTab === 'nat') {
    return <div className="center-content" style={{ flex: 1, overflow: 'auto' }}><NATEditor natRules={activeConfig?.nat_rules || []} onNATUpdate={config.handleNATUpdate} viewMode={effectiveViewMode} /></div>;
  }

  if (editTab === 'routing') {
    return (
      <div className="center-content" style={{ flex: 1, overflow: 'auto' }}>
        <RoutingEditor
          routingContexts={activeConfig?.routing_contexts || []}
          staticRoutes={activeConfig?.static_routes || []}
          interfaces={activeConfig?.interfaces || []}
          bridgeDomains={activeConfig?.bridge_domains || []}
          l2Interfaces={activeConfig?.l2_interfaces || []}
          vwirePairs={activeConfig?.vwire_pairs || []}
          onRoutesUpdate={(routes) => config.updateConfig(prev => ({ ...prev, static_routes: routes }))}
          onInterfacesUpdate={(ifs) => config.updateConfig(prev => ({ ...prev, interfaces: ifs }))}
          onBridgeDomainsUpdate={(bd) => config.updateConfig(prev => ({ ...prev, bridge_domains: bd }))}
          onL2InterfacesUpdate={(l2) => config.updateConfig(prev => ({ ...prev, l2_interfaces: l2 }))}
          onVwirePairsUpdate={(vw) => config.updateConfig(prev => ({ ...prev, vwire_pairs: vw }))}
          bgpConfig={activeConfig?.bgp_config || []}
          ospfConfig={activeConfig?.ospf_config || []}
          ospf3Config={activeConfig?.ospf3_config || []}
          evpnConfig={activeConfig?.evpn_config || []}
          vxlanConfig={activeConfig?.vxlan_config || []}
          onBgpConfigUpdate={(bgp) => config.updateConfig(prev => ({ ...prev, bgp_config: bgp }))}
          onOspfConfigUpdate={(ospf) => config.updateConfig(prev => ({ ...prev, ospf_config: ospf }))}
        />
      </div>
    );
  }

  if (editTab === 'vpn') {
    return <div className="center-content" style={{ flex: 1, overflow: 'auto' }}><VPNEditor vpnTunnels={activeConfig?.vpn_tunnels || []} onVPNUpdate={config.handleVPNUpdate} viewMode={effectiveViewMode} /></div>;
  }

  if (editTab === 'ha') {
    return <div className="center-content" style={{ flex: 1, overflow: 'auto' }}><HAEditor haConfig={activeConfig?.ha_config} onHAUpdate={config.handleHAUpdate} viewMode={effectiveViewMode} targetModel={targetModel} /></div>;
  }

  if (editTab === 'screen') {
    return <div className="center-content" style={{ flex: 1, overflow: 'auto' }}><ScreenEditor screenConfig={activeConfig?.screen_config || []} onScreenUpdate={config.handleScreenUpdate} viewMode={effectiveViewMode} /></div>;
  }

  if (editTab === 'syslog') {
    return <div className="center-content" style={{ flex: 1, overflow: 'auto' }}><SyslogEditor syslogConfig={activeConfig?.syslog_config || []} onSyslogUpdate={config.handleSyslogUpdate} viewMode={effectiveViewMode} /></div>;
  }

  if (editTab === 'dhcp') {
    return <div className="center-content" style={{ flex: 1, overflow: 'auto' }}><DHCPEditor dhcpConfig={activeConfig?.dhcp_config || []} onDHCPUpdate={config.handleDHCPUpdate} viewMode={effectiveViewMode} /></div>;
  }

  if (editTab === 'qos') {
    return <div className="center-content" style={{ flex: 1, overflow: 'auto' }}><QoSEditor qosConfig={activeConfig?.qos_config || []} onQoSUpdate={config.handleQoSUpdate} viewMode={effectiveViewMode} /></div>;
  }

  // --- Output / Warnings / Diff ---
  if (editTab === 'output') {
    return (
      <div className="center-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
        {srxOutput && (
          <div style={{ display: 'flex', gap: 4, padding: '8px 12px', borderBottom: '1px solid var(--border-color)', flexShrink: 0 }}>
            <button className={`format-btn ${outputFormat === 'set' ? 'active' : ''}`} onClick={() => conversion.handleConvert('set')}>Set Commands</button>
            <button className={`format-btn ${outputFormat === 'xml' ? 'active' : ''}`} onClick={() => conversion.handleConvert('xml')}>XML</button>
          </div>
        )}
        <SRXOutput output={srxOutput} format={outputFormat} summary={conversionSummary} isParsed={!!intermediateConfig} sanitizationTable={sanitizationTable} />
      </div>
    );
  }

  if (editTab === 'warnings') {
    return (
      <div className="center-content" style={{ flex: 1, overflow: 'auto' }}>
        <WarningsPanel warnings={allWarnings} warningStatuses={warningStatuses} onWarningAction={handleWarningAction} />
      </div>
    );
  }

  if (editTab === 'diff') {
    return (
      <div className="center-content" style={{ flex: 1, overflow: 'auto' }}>
        <DiffPanel sourcePolicies={intermediateConfig?.security_policies || []} translatedPolicies={srxTranslatedPolicies} />
      </div>
    );
  }

  // Fallback
  return (
    <div className="center-content" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1, color: 'var(--text-muted)' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 24, marginBottom: 8 }}>{editTab}</div>
        <div style={{ fontSize: 13 }}>Editor not yet wired for this tab</div>
      </div>
    </div>
  );
}

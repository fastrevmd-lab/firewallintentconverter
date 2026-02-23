/**
 * Junos SRX Configuration Parser
 * ================================
 *
 * Parses Junos SRX configurations (set commands and hierarchical format)
 * into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - Security zones and interfaces
 *   - Address objects (global address-book)
 *   - Address sets (groups)
 *   - Service/application references
 *   - Security policies (with match criteria, actions, logging)
 *   - NAT rules (source, destination, static)
 *   - Security profiles (UTM, IDP)
 *
 * Supports both:
 *   - "set" commands format (show configuration | display set)
 *   - Hierarchical curly-brace format (show configuration)
 */

import { createWarning } from './parser-utils.js';

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a Junos SRX configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw Junos configuration text (set or hierarchical)
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseSrxConfig(configText) {
  const warnings = [];

  // Normalize to set commands if hierarchical format detected
  const setCommands = normalizeToSetCommands(configText);

  // Parse set commands into a tree structure
  const tree = buildConfigTree(setCommands);

  // Extract each config section
  const zones = parseZones(tree, warnings);
  const addressObjects = parseAddressObjects(tree, warnings);
  const addressGroups = parseAddressGroups(tree, warnings);
  const serviceObjects = parseServiceObjects(tree, warnings);
  const serviceGroups = parseServiceGroups(tree, warnings);
  const securityPolicies = parseSecurityPolicies(tree, warnings);
  const natRules = parseNatRules(tree, warnings);
  const applications = parseApplications(tree, warnings);
  const schedules = parseSchedulers(setCommands, warnings);
  const { staticRoutes, routingContexts } = parseSrxStaticRoutes(tree, warnings);
  const haConfig = parseSrxHaConfig(tree, warnings);
  const screenConfig = parseSrxScreenConfig(tree, zones, warnings);

  // Extract version info if available
  const version = extractVersion(tree);

  // Append SRX implicit default deny
  securityPolicies.push({
    name: 'Implicit: Default Deny',
    src_zones: ['any'],
    dst_zones: ['any'],
    src_addresses: ['any'],
    dst_addresses: ['any'],
    negate_source: false,
    negate_destination: false,
    applications: ['any'],
    services: ['any'],
    action: 'deny',
    log_start: false,
    log_end: false,
    profile_group: '',
    security_profiles: {},
    description: 'SRX default: implicit deny for unmatched traffic',
    tags: ['added_by_fpic'],
    disabled: false,
    _rule_index: securityPolicies.length + 1,
    _implicit: true,
  });

  // Parse VPN/IPsec tunnel configuration
  const vpnTunnels = parseSrxVpnConfig(tree, warnings);

  // Parse syslog, DHCP, QoS
  const syslogConfig = parseSrxSyslogConfig(tree, warnings);
  const dhcpConfig = parseSrxDhcpConfig(tree, warnings);
  const qosConfig = parseSrxQosConfig(tree, warnings);

  const intermediateConfig = {
    zones,
    address_objects: addressObjects,
    address_groups: addressGroups,
    service_objects: serviceObjects,
    service_groups: serviceGroups,
    security_policies: securityPolicies,
    nat_rules: natRules,
    applications,
    application_groups: [],
    schedules,
    security_profile_objects: [],
    external_lists: [],
    vpn_tunnels: vpnTunnels,
    ha_config: haConfig,
    screen_config: screenConfig,
    syslog_config: syslogConfig,
    dhcp_config: dhcpConfig,
    qos_config: qosConfig,
    routing_contexts: routingContexts,
    static_routes: staticRoutes,
    target_context: null,
    metadata: {
      source_vendor: 'srx',
      source_version: version,
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: natRules.length,
      object_count: addressObjects.length + addressGroups.length + serviceObjects.length + serviceGroups.length,
      zone_count: zones.length,
      vpn_tunnel_count: vpnTunnels.length,
      syslog_server_count: syslogConfig.length,
      dhcp_config_count: dhcpConfig.length,
      qos_profile_count: qosConfig.length,
      routing_context_count: routingContexts.length,
      static_route_count: staticRoutes.length,
      ha_enabled: !!(haConfig && haConfig.enabled),
      multi_vsys: false,
    },
  };

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}

// ---------------------------------------------------------------------------
// Normalize hierarchical config to set commands
// ---------------------------------------------------------------------------

/**
 * Converts hierarchical Junos config to set commands.
 * If already in set format, returns lines as-is.
 */
function normalizeToSetCommands(configText) {
  const lines = configText.split('\n').map(l => l.trimEnd());

  // Check if already set commands
  const setLines = lines.filter(l => l.trim().startsWith('set '));
  if (setLines.length > lines.filter(l => l.trim().length > 0).length * 0.5) {
    // Mostly set commands — use them directly
    return setLines.map(l => l.trim());
  }

  // Convert hierarchical to set commands
  return hierarchicalToSet(lines);
}

/**
 * Converts hierarchical curly-brace Junos config to flat set commands.
 */
function hierarchicalToSet(lines) {
  const setCommands = [];
  const pathStack = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip empty lines, comments, annotations
    if (!line || line.startsWith('#') || line.startsWith('/*') || line.startsWith('*')) continue;

    // Handle closing brace
    if (line === '}') {
      pathStack.pop();
      continue;
    }

    // Handle "inactive:" prefix
    const inactiveMatch = line.match(/^inactive:\s*(.+)$/);
    const activeLine = inactiveMatch ? inactiveMatch[1].trim() : line;
    const deactivatePrefix = inactiveMatch ? 'deactivate ' : 'set ';

    // Handle opening brace: "keyword {" or "keyword value {"
    if (activeLine.endsWith('{')) {
      const path = activeLine.slice(0, -1).trim();
      pathStack.push(path);
      continue;
    }

    // Handle leaf value ending with ";"
    if (activeLine.endsWith(';')) {
      const value = activeLine.slice(0, -1).trim();
      const fullPath = [...pathStack, value].join(' ');
      setCommands.push(`${deactivatePrefix}${fullPath}`);
      continue;
    }

    // Handle bracket lists: [value1 value2 value3];
    const bracketMatch = activeLine.match(/^(.+?)\s+\[([^\]]+)\];?$/);
    if (bracketMatch) {
      const prefix = bracketMatch[1].trim();
      const values = bracketMatch[2].trim().split(/\s+/);
      for (const val of values) {
        const fullPath = [...pathStack, prefix, val].join(' ');
        setCommands.push(`set ${fullPath}`);
      }
      continue;
    }
  }

  return setCommands;
}

// ---------------------------------------------------------------------------
// Build config tree from set commands
// ---------------------------------------------------------------------------

/**
 * Builds a nested object tree from flat set commands.
 * Each path segment becomes a key, leaf values are stored as arrays.
 */
function buildConfigTree(setCommands) {
  const tree = {};

  for (const cmd of setCommands) {
    // Remove "set " or "deactivate " prefix
    let path;
    let isDeactivate = false;
    if (cmd.startsWith('set ')) {
      path = cmd.substring(4);
    } else if (cmd.startsWith('deactivate ')) {
      path = cmd.substring(11);
      isDeactivate = true;
    } else {
      continue;
    }

    // Tokenize respecting quoted strings
    const tokens = tokenize(path);
    if (tokens.length === 0) continue;

    // Navigate/create tree nodes
    let node = tree;
    for (let i = 0; i < tokens.length - 1; i++) {
      const token = tokens[i];
      if (!node[token]) node[token] = {};
      if (typeof node[token] === 'string') {
        // Convert leaf to branch
        node[token] = { _value: node[token] };
      }
      node = node[token];
    }

    // Set leaf value
    const lastToken = tokens[tokens.length - 1];
    if (node[lastToken] === undefined) {
      node[lastToken] = true; // flag-style value
    }
    // Mark deactivated paths
    if (isDeactivate) {
      node._deactivated = true;
    }
  }

  return tree;
}

/**
 * Tokenizes a Junos set command path, respecting quoted strings.
 */
function tokenize(path) {
  const tokens = [];
  let current = '';
  let inQuote = false;
  let quoteChar = '';

  for (let i = 0; i < path.length; i++) {
    const ch = path[i];

    if (inQuote) {
      if (ch === quoteChar) {
        inQuote = false;
        // Don't include quote chars in token
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      inQuote = true;
      quoteChar = ch;
    } else if (ch === ' ') {
      if (current) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);
  return tokens;
}

// ---------------------------------------------------------------------------
// Zone Parser
// ---------------------------------------------------------------------------

function parseZones(tree, warnings) {
  const zonesNode = tree?.security?.zones?.['security-zone'];
  if (!zonesNode) return [];

  const zones = [];
  for (const [zoneName, zoneData] of Object.entries(zonesNode)) {
    if (zoneName.startsWith('_')) continue;

    const interfaces = [];
    if (zoneData?.interfaces) {
      for (const ifName of Object.keys(zoneData.interfaces)) {
        if (!ifName.startsWith('_')) {
          interfaces.push(ifName);
        }
      }
    }

    const description = extractStringValue(zoneData?.description) || '';

    zones.push({
      name: zoneName,
      description,
      interfaces,
    });
  }

  return zones;
}

// ---------------------------------------------------------------------------
// Address Object Parser (global address-book)
// ---------------------------------------------------------------------------

function parseAddressObjects(tree, warnings) {
  const addrBook = tree?.security?.['address-book']?.global;
  if (!addrBook) return [];

  const objects = [];
  const addressNode = addrBook.address;
  if (!addressNode) return [];

  for (const [name, data] of Object.entries(addressNode)) {
    if (name.startsWith('_')) continue;

    let type = 'unknown';
    let value = '';

    if (data && typeof data === 'object') {
      // IP prefix
      const ipPrefix = findKeyValue(data);
      if (ipPrefix) {
        value = ipPrefix;
        if (value.endsWith('/32')) {
          type = 'host';
        } else if (value.includes('/')) {
          type = 'subnet';
        }
      }

      // dns-name
      if (data['dns-name']) {
        type = 'fqdn';
        value = extractStringValue(data['dns-name']) || Object.keys(data['dns-name'])[0] || '';
      }

      // range-address
      if (data['range-address']) {
        type = 'range';
        const rangeKeys = Object.keys(data['range-address']).filter(k => !k.startsWith('_'));
        if (rangeKeys.length > 0) {
          const rangeName = rangeKeys[0];
          const rangeData = data['range-address'][rangeName];
          const lower = rangeName;
          const upper = rangeData?.to ? Object.keys(rangeData.to).filter(k => !k.startsWith('_'))[0] || '' : '';
          value = upper ? `${lower}-${upper}` : lower;
        }
      }

      // Wildcard-address
      if (data['wildcard-address']) {
        type = 'wildcard';
        const wcKeys = Object.keys(data['wildcard-address']).filter(k => !k.startsWith('_'));
        value = wcKeys[0] || '';
      }

      // Simple IP/subnet as direct key
      if (type === 'unknown') {
        const keys = Object.keys(data).filter(k => !k.startsWith('_') && k !== 'description');
        for (const k of keys) {
          if (k.match(/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/)) {
            value = k;
            type = k.endsWith('/32') ? 'host' : 'subnet';
            break;
          }
        }
      }
    } else if (typeof data === 'string') {
      value = data;
      type = value.includes('/') ? (value.endsWith('/32') ? 'host' : 'subnet') : 'host';
    }

    const description = (data && typeof data === 'object') ?
      (extractStringValue(data.description) || '') : '';

    objects.push({ name, type, value, description, tags: [] });
  }

  return objects;
}

// ---------------------------------------------------------------------------
// Address Group Parser (address-set in global address-book)
// ---------------------------------------------------------------------------

function parseAddressGroups(tree, warnings) {
  const addrBook = tree?.security?.['address-book']?.global;
  if (!addrBook) return [];

  const groups = [];
  const setNode = addrBook['address-set'];
  if (!setNode) return [];

  for (const [name, data] of Object.entries(setNode)) {
    if (name.startsWith('_')) continue;

    const members = [];
    if (data?.address) {
      for (const memberName of Object.keys(data.address)) {
        if (!memberName.startsWith('_')) {
          members.push(memberName);
        }
      }
    }
    if (data?.['address-set']) {
      for (const subSetName of Object.keys(data['address-set'])) {
        if (!subSetName.startsWith('_')) {
          members.push(subSetName);
        }
      }
    }

    const description = (data && typeof data === 'object') ?
      (extractStringValue(data.description) || '') : '';

    groups.push({ name, members, description, tags: [] });
  }

  return groups;
}

// ---------------------------------------------------------------------------
// Service Object Parser
// ---------------------------------------------------------------------------

function parseServiceObjects(tree, warnings) {
  const appNode = tree?.applications?.application;
  if (!appNode) return [];

  const services = [];
  for (const [name, data] of Object.entries(appNode)) {
    if (name.startsWith('_') || !data || typeof data !== 'object') continue;

    let protocol = '';
    let portRange = '';
    let sourcePort = '';

    if (data.protocol) {
      protocol = extractStringValue(data.protocol) || Object.keys(data.protocol).filter(k => !k.startsWith('_'))[0] || '';
    }

    if (data['destination-port']) {
      portRange = extractStringValue(data['destination-port']) || Object.keys(data['destination-port']).filter(k => !k.startsWith('_'))[0] || '';
    }

    if (data['source-port']) {
      sourcePort = extractStringValue(data['source-port']) || Object.keys(data['source-port']).filter(k => !k.startsWith('_'))[0] || '';
    }

    if (protocol || portRange) {
      services.push({
        name,
        protocol,
        port_range: portRange,
        source_port: sourcePort,
        description: extractStringValue(data.description) || '',
      });
    }
  }

  return services;
}

// ---------------------------------------------------------------------------
// Service Group Parser (application-set)
// ---------------------------------------------------------------------------

function parseServiceGroups(tree, warnings) {
  const setNode = tree?.applications?.['application-set'];
  if (!setNode) return [];

  const groups = [];
  for (const [name, data] of Object.entries(setNode)) {
    if (name.startsWith('_') || !data || typeof data !== 'object') continue;

    const members = [];
    if (data.application) {
      for (const memberName of Object.keys(data.application)) {
        if (!memberName.startsWith('_')) {
          members.push(memberName);
        }
      }
    }

    groups.push({
      name,
      members,
      description: extractStringValue(data.description) || '',
    });
  }

  return groups;
}

// ---------------------------------------------------------------------------
// Application Parser
// ---------------------------------------------------------------------------

function parseApplications(tree, warnings) {
  const appNode = tree?.applications?.application;
  if (!appNode) return [];

  const apps = [];
  for (const [name, data] of Object.entries(appNode)) {
    if (name.startsWith('_') || !data || typeof data !== 'object') continue;

    let protocol = '';
    let port = '';

    if (data.protocol) {
      protocol = extractStringValue(data.protocol) || Object.keys(data.protocol).filter(k => !k.startsWith('_'))[0] || '';
    }
    if (data['destination-port']) {
      port = extractStringValue(data['destination-port']) || Object.keys(data['destination-port']).filter(k => !k.startsWith('_'))[0] || '';
    }

    apps.push({
      name,
      protocol,
      port,
      description: extractStringValue(data.description) || '',
    });
  }

  return apps;
}

// ---------------------------------------------------------------------------
// Security Policies Parser
// ---------------------------------------------------------------------------

function parseSecurityPolicies(tree, warnings) {
  const policiesNode = tree?.security?.policies;
  if (!policiesNode) return [];

  const policies = [];
  let ruleIndex = 0;

  // Junos policies are organized as:
  // security policies from-zone <src> to-zone <dst> policy <name> ...
  for (const [key, value] of Object.entries(policiesNode)) {
    if (!key.startsWith('from-zone') && key !== 'global') continue;

    if (key === 'global') {
      // Global policies
      const policyNode = value?.policy;
      if (policyNode) {
        for (const [policyName, policyData] of Object.entries(policyNode)) {
          if (policyName.startsWith('_')) continue;
          ruleIndex++;
          policies.push(parseSinglePolicy(policyName, policyData, ['any'], ['any'], ruleIndex, warnings));
        }
      }
      continue;
    }

    // Parse "from-zone <src> to-zone <dst>"
    // The key format in tree could be nested: tree.security.policies["from-zone"]["<src>"]["to-zone"]["<dst>"]
    // Or it could be a single compound key depending on tokenization
    // Let's handle both cases

    if (key === 'from-zone') {
      // Nested format: security.policies.from-zone.<srcZone>.to-zone.<dstZone>.policy.<name>
      for (const [srcZone, srcData] of Object.entries(value)) {
        if (srcZone.startsWith('_') || !srcData || typeof srcData !== 'object') continue;
        const toZoneNode = srcData['to-zone'];
        if (!toZoneNode) continue;

        for (const [dstZone, dstData] of Object.entries(toZoneNode)) {
          if (dstZone.startsWith('_') || !dstData || typeof dstData !== 'object') continue;
          const policyNode = dstData.policy;
          if (!policyNode) continue;

          for (const [policyName, policyData] of Object.entries(policyNode)) {
            if (policyName.startsWith('_')) continue;
            ruleIndex++;
            policies.push(parseSinglePolicy(policyName, policyData, [srcZone], [dstZone], ruleIndex, warnings));
          }
        }
      }
    }
  }

  return policies;
}

/**
 * Parse a single security policy entry.
 */
function parseSinglePolicy(name, data, srcZones, dstZones, ruleIndex, warnings) {
  if (!data || typeof data !== 'object') {
    data = {};
  }

  const matchNode = data.match || {};

  // Source addresses
  const srcAddresses = collectKeys(matchNode['source-address']);
  // Destination addresses
  const dstAddresses = collectKeys(matchNode['destination-address']);
  // Applications
  const applications = collectKeys(matchNode.application);

  // Action
  let action = 'deny';
  const thenNode = data.then || {};
  if (thenNode.permit !== undefined) action = 'permit';
  else if (thenNode.deny !== undefined) action = 'deny';
  else if (thenNode.reject !== undefined) action = 'reject';

  // Logging
  let logStart = false;
  let logEnd = false;
  if (thenNode.log) {
    if (thenNode.log['session-init'] !== undefined) logStart = true;
    if (thenNode.log['session-close'] !== undefined) logEnd = true;
  }

  // Count: if thenNode.count exists, note it
  const hasCount = thenNode.count !== undefined;

  // Disabled
  const disabled = data._deactivated === true;

  // Description
  const description = extractStringValue(data.description) || '';

  // Security profiles from then → permit → application-services
  const security_profiles = {};
  let profileGroup = '';
  const appServices = thenNode.permit?.['application-services'] || thenNode['application-services'] || {};

  if (appServices['utm-policy']) {
    const utmPolicyName = extractStringValue(appServices['utm-policy']) ||
      Object.keys(appServices['utm-policy']).filter(k => !k.startsWith('_'))[0] || 'default';
    security_profiles['url-filtering'] = utmPolicyName;
    security_profiles['virus'] = utmPolicyName;
  }
  if (appServices['idp-policy']) {
    const idpPolicyName = extractStringValue(appServices['idp-policy']) ||
      Object.keys(appServices['idp-policy']).filter(k => !k.startsWith('_'))[0] || 'default';
    security_profiles['spyware'] = idpPolicyName;
    security_profiles['vulnerability'] = idpPolicyName;
  }

  // Map SRX action to intermediate (PAN-OS-compatible) action
  const actionMap = { permit: 'allow', deny: 'deny', reject: 'reset-both' };
  const intermediateAction = actionMap[action] || action;

  // Scheduler
  const schedulerName = extractStringValue(data['scheduler-name']) || '';

  return {
    name,
    src_zones: srcZones,
    dst_zones: dstZones,
    src_addresses: srcAddresses.length > 0 ? srcAddresses : ['any'],
    dst_addresses: dstAddresses.length > 0 ? dstAddresses : ['any'],
    negate_source: false,
    negate_destination: false,
    applications: applications.length > 0 ? applications : ['any'],
    services: ['application-default'],
    action: intermediateAction,
    log_start: logStart,
    log_end: logEnd,
    profile_group: profileGroup,
    security_profiles,
    description,
    tags: [],
    disabled,
    schedule: schedulerName,
    _rule_index: ruleIndex,
  };
}

// ---------------------------------------------------------------------------
// NAT Rules Parser
// ---------------------------------------------------------------------------

function parseNatRules(tree, warnings) {
  const natNode = tree?.security?.nat;
  if (!natNode) return [];

  const rules = [];
  let ruleIndex = 0;

  // Source NAT
  if (natNode.source) {
    const ruleSets = natNode.source['rule-set'];
    if (ruleSets) {
      for (const [rsName, rsData] of Object.entries(ruleSets)) {
        if (rsName.startsWith('_') || !rsData || typeof rsData !== 'object') continue;

        const srcZones = collectKeys(rsData.from?.zone);
        const dstZones = collectKeys(rsData.to?.zone);

        const ruleNode = rsData.rule;
        if (!ruleNode) continue;

        for (const [ruleName, ruleData] of Object.entries(ruleNode)) {
          if (ruleName.startsWith('_') || !ruleData || typeof ruleData !== 'object') continue;
          ruleIndex++;

          const matchNode = ruleData.match || {};
          const srcAddrs = collectKeys(matchNode['source-address']);
          const dstAddrs = collectKeys(matchNode['destination-address']);

          let translatedSrc = null;
          const thenNode = ruleData.then || {};

          if (thenNode['source-nat']) {
            const snat = thenNode['source-nat'];
            if (snat.interface !== undefined) {
              translatedSrc = { type: 'interface', interface: '' };
            } else if (snat.pool) {
              const poolName = extractStringValue(snat.pool) ||
                Object.keys(snat.pool).filter(k => !k.startsWith('_'))[0] || '';
              translatedSrc = { type: 'dynamic-ip-pool', addresses: [poolName] };
            } else if (snat.off !== undefined) {
              translatedSrc = { type: 'no-nat' };
            }
          }

          rules.push({
            name: `${rsName}/${ruleName}`,
            type: 'source',
            src_zones: srcZones,
            dst_zones: dstZones,
            src_addresses: srcAddrs.length > 0 ? srcAddrs : ['any'],
            dst_addresses: dstAddrs.length > 0 ? dstAddrs : ['any'],
            translated_src: translatedSrc,
            translated_dst: null,
            translated_port: null,
            description: extractStringValue(ruleData.description) || '',
            _rule_index: ruleIndex,
          });
        }
      }
    }
  }

  // Destination NAT
  if (natNode.destination) {
    const ruleSets = natNode.destination['rule-set'];
    if (ruleSets) {
      for (const [rsName, rsData] of Object.entries(ruleSets)) {
        if (rsName.startsWith('_') || !rsData || typeof rsData !== 'object') continue;

        const srcZones = collectKeys(rsData.from?.zone);
        const dstZones = collectKeys(rsData.to?.zone);

        const ruleNode = rsData.rule;
        if (!ruleNode) continue;

        for (const [ruleName, ruleData] of Object.entries(ruleNode)) {
          if (ruleName.startsWith('_') || !ruleData || typeof ruleData !== 'object') continue;
          ruleIndex++;

          const matchNode = ruleData.match || {};
          const srcAddrs = collectKeys(matchNode['source-address']);
          const dstAddrs = collectKeys(matchNode['destination-address']);
          const dstPort = extractStringValue(matchNode['destination-port']) ||
            Object.keys(matchNode['destination-port'] || {}).filter(k => !k.startsWith('_'))[0] || null;

          let translatedDst = null;
          let translatedPort = null;
          const thenNode = ruleData.then || {};

          if (thenNode['destination-nat']) {
            const dnat = thenNode['destination-nat'];
            if (dnat.pool) {
              const poolNode = dnat.pool;
              const poolName = extractStringValue(poolNode) ||
                Object.keys(poolNode).filter(k => !k.startsWith('_'))[0] || '';
              translatedDst = poolName;
            }
          }

          rules.push({
            name: `${rsName}/${ruleName}`,
            type: 'destination',
            src_zones: srcZones,
            dst_zones: dstZones,
            src_addresses: srcAddrs.length > 0 ? srcAddrs : ['any'],
            dst_addresses: dstAddrs.length > 0 ? dstAddrs : ['any'],
            translated_src: null,
            translated_dst: translatedDst,
            translated_port: translatedPort,
            description: extractStringValue(ruleData.description) || '',
            _rule_index: ruleIndex,
          });
        }
      }
    }
  }

  // Static NAT
  if (natNode.static) {
    const ruleSets = natNode.static['rule-set'];
    if (ruleSets) {
      for (const [rsName, rsData] of Object.entries(ruleSets)) {
        if (rsName.startsWith('_') || !rsData || typeof rsData !== 'object') continue;

        const srcZones = collectKeys(rsData.from?.zone);
        const dstZones = collectKeys(rsData.to?.zone);

        const ruleNode = rsData.rule;
        if (!ruleNode) continue;

        for (const [ruleName, ruleData] of Object.entries(ruleNode)) {
          if (ruleName.startsWith('_') || !ruleData || typeof ruleData !== 'object') continue;
          ruleIndex++;

          const matchNode = ruleData.match || {};
          const dstAddrs = collectKeys(matchNode['destination-address']);

          let translatedSrc = null;
          const thenNode = ruleData.then || {};
          if (thenNode['static-nat']) {
            const staticNat = thenNode['static-nat'];
            if (staticNat.prefix) {
              const prefixKeys = Object.keys(staticNat.prefix).filter(k => !k.startsWith('_'));
              translatedSrc = { type: 'static', address: prefixKeys[0] || '' };
            }
          }

          rules.push({
            name: `${rsName}/${ruleName}`,
            type: 'static',
            src_zones: srcZones,
            dst_zones: dstZones,
            src_addresses: ['any'],
            dst_addresses: dstAddrs.length > 0 ? dstAddrs : ['any'],
            translated_src: translatedSrc,
            translated_dst: null,
            translated_port: null,
            description: extractStringValue(ruleData.description) || '',
            _rule_index: ruleIndex,
          });
        }
      }
    }
  }

  return rules;
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Scheduler Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX schedulers directly from set commands.
 *
 * Junos syntax:
 *   set schedulers scheduler <name> <day> start-time <HH:MM:SS> stop-time <HH:MM:SS>
 *   set schedulers scheduler <name> start-date "<datetime>" stop-date "<datetime>"
 *
 * Parses from raw commands instead of the config tree because the tree
 * nests `start-time <val> stop-time <val>` as a deep path, making extraction fragile.
 */
function parseSchedulers(setCommands, warnings) {
  const schedMap = {}; // name → { type, days: Set, start, end }

  const dayNames = new Set([
    'sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday',
    'daily', 'weekdays', 'weekend',
  ]);

  for (const cmd of setCommands) {
    if (!cmd.startsWith('set schedulers scheduler ')) continue;
    const rest = cmd.substring(24); // after "set schedulers scheduler "
    const tokens = tokenize(rest);
    if (tokens.length < 2) continue;

    const name = tokens[0];
    if (!schedMap[name]) {
      schedMap[name] = { type: 'unknown', days: new Set(), start: '', end: '' };
    }
    const sched = schedMap[name];

    // Check for one-time schedule
    if (tokens[1] === 'start-date' && tokens.length >= 3) {
      sched.type = 'onetime';
      sched.start = tokens[2];
      continue;
    }
    if (tokens[1] === 'stop-date' && tokens.length >= 3) {
      sched.type = 'onetime';
      sched.end = tokens[2];
      continue;
    }

    // Recurring schedule: <name> <day> start-time <val> stop-time <val>
    if (dayNames.has(tokens[1].toLowerCase())) {
      sched.type = 'recurring';
      sched.days.add(tokens[1].toLowerCase());

      // Extract start-time and stop-time from remaining tokens
      for (let i = 2; i < tokens.length - 1; i++) {
        if (tokens[i] === 'start-time') sched.start = tokens[i + 1];
        if (tokens[i] === 'stop-time') sched.end = tokens[i + 1];
      }
    }
  }

  const dayShortMap = { monday: 'Mon', tuesday: 'Tue', wednesday: 'Wed', thursday: 'Thu', friday: 'Fri', saturday: 'Sat', sunday: 'Sun', daily: 'Daily', weekdays: 'Weekdays', weekend: 'Weekend' };
  return Object.entries(schedMap).map(([name, s]) => ({
    name,
    type: s.type === 'unknown' ? 'recurring' : s.type,
    days: [...s.days].map(d => dayShortMap[d.toLowerCase()] || d),
    start: s.start,
    end: s.end,
  }));
}

/**
 * Extracts a string value from a tree node.
 * The value could be stored as a key (when tree was built from set commands).
 */
function extractStringValue(node) {
  if (!node) return '';
  if (typeof node === 'string') return node;
  if (typeof node === 'boolean') return '';
  if (typeof node === 'object') {
    if (node._value) return node._value;
    const keys = Object.keys(node).filter(k => !k.startsWith('_'));
    // If single key and its value is true, the key IS the value
    if (keys.length === 1 && node[keys[0]] === true) return keys[0];
    return keys[0] || '';
  }
  return String(node);
}

/**
 * Collects all non-underscore keys from a node (used for member lists).
 */
function collectKeys(node) {
  if (!node) return [];
  if (typeof node !== 'object') return [String(node)];
  return Object.keys(node).filter(k => !k.startsWith('_'));
}

/**
 * Find a value that looks like an IP address or subnet from object keys.
 */
function findKeyValue(data) {
  if (!data || typeof data !== 'object') return null;
  const keys = Object.keys(data).filter(k => !k.startsWith('_') && k !== 'description');
  for (const k of keys) {
    if (k.match(/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/)) return k;
    // IPv6
    if (k.includes(':') && k.match(/^[0-9a-fA-F:\/]+$/)) return k;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Static Route Parser
// ---------------------------------------------------------------------------

function parseSrxStaticRoutes(tree, warnings) {
  const staticRoutes = [];
  const routingContexts = [];

  // Global routing-options
  const globalRoutes = tree?.['routing-options']?.static?.route;
  if (globalRoutes && typeof globalRoutes === 'object') {
    for (const [dest, data] of Object.entries(globalRoutes)) {
      if (dest.startsWith('_')) continue;
      staticRoutes.push(buildSrxRoute(dest, data, '', ''));
    }
  }

  // Build default routing context
  routingContexts.push({
    name: 'default',
    type: 'default',
    virtual_routers: [],
    zones: [],
  });

  // Routing instances (VRFs)
  const instances = tree?.['routing-instances'];
  if (instances && typeof instances === 'object') {
    for (const [instName, instData] of Object.entries(instances)) {
      if (instName.startsWith('_') || typeof instData !== 'object') continue;

      const instRoutes = instData?.['routing-options']?.static?.route;
      if (instRoutes && typeof instRoutes === 'object') {
        for (const [dest, data] of Object.entries(instRoutes)) {
          if (dest.startsWith('_')) continue;
          staticRoutes.push(buildSrxRoute(dest, data, instName, instName));
        }
      }

      routingContexts.push({
        name: instName,
        type: 'default',
        virtual_routers: [{
          name: instName,
          interfaces: [],
          static_routes: instRoutes ? Object.entries(instRoutes)
            .filter(([k]) => !k.startsWith('_'))
            .map(([d, v]) => buildSrxRoute(d, v, instName, instName)) : [],
        }],
        zones: [],
      });
    }
  }

  return { staticRoutes, routingContexts };
}

function buildSrxRoute(dest, data, vrf, routingContext) {
  let nextHop = '';
  let nextHopType = 'ip-address';

  if (typeof data === 'string') {
    nextHop = data;
  } else if (typeof data === 'object') {
    if (data['next-hop']) {
      nextHop = extractStringValue(data['next-hop']);
    } else if (data.discard !== undefined) {
      nextHopType = 'discard';
    } else if (data.reject !== undefined) {
      nextHopType = 'discard';
    }
  }

  return {
    name: dest,
    destination: dest,
    next_hop: nextHop,
    next_hop_type: nextHopType,
    interface: '',
    metric: typeof data === 'object' && data.metric ? parseInt(extractStringValue(data.metric)) || 10 : 10,
    admin_distance: null,
    description: '',
    vrf,
    routing_context: routingContext,
  };
}

// ---------------------------------------------------------------------------
// HA (Chassis Cluster) Configuration
// ---------------------------------------------------------------------------
// Screen / DDoS Protection Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX screen (ids-option) config into the screen_config schema.
 * Screens at: security > screen > ids-option > <screen-name>
 * Zone assignment: security > zones > security-zone > <zone-name> > screen
 */
function parseSrxScreenConfig(tree, zones, warnings) {
  const screenConfigs = [];

  const idsOptions = tree?.security?.screen?.['ids-option'];
  if (!idsOptions || typeof idsOptions !== 'object') return screenConfigs;

  // Build map of zone → screen name from zone config
  const zoneToScreen = {};
  const zonesNode = tree?.security?.zones?.['security-zone'];
  if (zonesNode && typeof zonesNode === 'object') {
    for (const [zoneName, zoneData] of Object.entries(zonesNode)) {
      if (typeof zoneData !== 'object' || zoneName.startsWith('_')) continue;
      if (zoneData.screen) {
        const screenName = extractStringValue(zoneData.screen);
        if (screenName) {
          zoneToScreen[screenName] = zoneName;
        }
      }
    }
  }

  for (const [screenName, screenData] of Object.entries(idsOptions)) {
    if (typeof screenData !== 'object' || screenName.startsWith('_')) continue;

    const icmpNode = screenData.icmp || {};
    const tcpNode = screenData.tcp || {};
    const udpNode = screenData.udp || {};
    const ipNode = screenData.ip || {};
    const limitNode = screenData['limit-session'] || {};

    const screen = {
      name: screenName,
      zone: zoneToScreen[screenName] || '',
      icmp: {
        flood_threshold: parseInt(extractStringValue(icmpNode['flood']?.threshold)) || null,
        ping_death: !!(icmpNode['ping-death'] === true || icmpNode['ping-death'] === 'true'),
        fragment: !!(icmpNode['fragment'] === true || icmpNode['fragment'] === 'true'),
      },
      tcp: {
        syn_flood_threshold: null,
        syn_flood_timeout: null,
        land_attack: !!(tcpNode['land'] === true || tcpNode['land'] === 'true'),
        winnuke: !!(tcpNode['winnuke'] === true || tcpNode['winnuke'] === 'true'),
        tcp_no_flag: !!(tcpNode['tcp-no-flag'] === true || tcpNode['tcp-no-flag'] === 'true'),
      },
      udp: {
        flood_threshold: parseInt(extractStringValue(udpNode['flood']?.threshold)) || null,
      },
      ip: {
        spoofing: !!(ipNode['spoofing'] === true || ipNode['spoofing'] === 'true'),
        source_route: !!(ipNode['source-route-option'] === true || ipNode['source-route-option'] === 'true'),
        tear_drop: !!(ipNode['tear-drop'] === true || ipNode['tear-drop'] === 'true'),
        record_route: !!(ipNode['record-route-option'] === true || ipNode['record-route-option'] === 'true'),
        timestamp: !!(ipNode['timestamp-option'] === true || ipNode['timestamp-option'] === 'true'),
      },
      limit_session: {
        source_based: parseInt(extractStringValue(limitNode['source-ip-based'])) || null,
        destination_based: parseInt(extractStringValue(limitNode['destination-ip-based'])) || null,
      },
      description: '',
    };

    // Parse SYN flood sub-tree
    const synFlood = tcpNode['syn-flood'];
    if (synFlood && typeof synFlood === 'object') {
      screen.tcp.syn_flood_threshold =
        parseInt(extractStringValue(synFlood['attack-threshold'])) ||
        parseInt(extractStringValue(synFlood['alarm-threshold'])) ||
        null;
      screen.tcp.syn_flood_timeout =
        parseInt(extractStringValue(synFlood['timeout'])) || null;
    }

    // Parse ICMP ip-sweep threshold (maps to icmp flood_threshold if not already set)
    const ipSweep = icmpNode['ip-sweep'];
    if (ipSweep && typeof ipSweep === 'object' && !screen.icmp.flood_threshold) {
      screen.icmp.flood_threshold = parseInt(extractStringValue(ipSweep.threshold)) || null;
    }

    screenConfigs.push(screen);
  }

  if (screenConfigs.length > 0) {
    warnings.push(createWarning('info', 'screen-config',
      `Parsed ${screenConfigs.length} screen ids-option profile(s)`,
      'Review screen/DDoS settings in the generated config'));
  }

  return screenConfigs;
}


// ---------------------------------------------------------------------------

function parseSrxHaConfig(tree, warnings) {
  const chassis = tree['chassis'];
  if (!chassis) return null;
  const cluster = chassis['cluster'];
  if (!cluster) return null;

  const clusterId = parseInt(extractStringValue(cluster['cluster-id'])) || 1;

  // Redundancy groups
  const haInterfaces = [];
  const rg = cluster['redundancy-group'];
  let primaryPriority = 200;
  if (rg && typeof rg === 'object') {
    for (const [rgId, rgData] of Object.entries(rg)) {
      if (typeof rgData !== 'object') continue;
      const node = rgData['node'];
      if (node && typeof node === 'object') {
        for (const [nodeId, nodeData] of Object.entries(node)) {
          if (typeof nodeData !== 'object') continue;
          const prio = parseInt(extractStringValue(nodeData['priority']));
          if (nodeId === '0' && rgId === '0' && prio) primaryPriority = prio;
        }
      }
    }
  }

  // Fabric interfaces
  const interfaces = tree['interfaces'] || {};
  for (const ifName of ['fab0', 'fab1']) {
    const fab = interfaces[ifName];
    if (fab && typeof fab === 'object') {
      const opts = fab['fabric-options'] || {};
      const members = opts['member-interfaces'];
      haInterfaces.push({
        name: ifName,
        ip: '',
        netmask: '',
        interface: members ? (typeof members === 'string' ? members : Object.keys(members)[0] || '') : '',
      });
    }
  }

  // Control link (fxp0 for management, fxp1 for control)
  for (const ifName of ['fxp0', 'fxp1']) {
    const fxp = interfaces[ifName];
    if (fxp && typeof fxp === 'object') {
      haInterfaces.push({
        name: ifName,
        ip: '',
        netmask: '',
        interface: ifName,
      });
    }
  }

  return {
    enabled: true,
    mode: 'cluster',
    group_id: clusterId,
    priority: primaryPriority,
    preempt: false,
    peer_ip: '',
    ha_interfaces: haInterfaces,
    monitoring: { link_groups: [], path_groups: [] },
    description: `SRX chassis cluster id ${clusterId}`,
  };
}

/**
 * Extract Junos version from tree.
 */

// ---------------------------------------------------------------------------
// VPN / IPsec Tunnel Parser
// ---------------------------------------------------------------------------

/**
 * Parses Junos SRX VPN/IPsec configuration from the config tree.
 * IKE: tree.security.ike (proposals, policies, gateways)
 * IPsec: tree.security.ipsec (proposals, policies, vpns)
 */
function parseSrxVpnConfig(tree, warnings) {
  const vpnTunnels = [];
  const ikeNode = tree && tree.security ? tree.security.ike : null;
  const ipsecNode = tree && tree.security ? tree.security.ipsec : null;

  // ---- IKE proposals ----
  const ikeProposals = {};
  if (ikeNode && ikeNode.proposal) {
    for (const [name, data] of Object.entries(ikeNode.proposal)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      ikeProposals[name] = {
        name,
        auth_method: extractStringValue(data['authentication-method']) || 'pre-shared-keys',
        dh_group: extractStringValue(data['dh-group']) || 'group14',
        encryption: extractStringValue(data['encryption-algorithm']) || 'aes-256-cbc',
        authentication: extractStringValue(data['authentication-algorithm']) || 'sha-256',
        lifetime: parseInt(extractStringValue(data['lifetime-seconds']), 10) || 28800,
      };
    }
  }

  // ---- IKE policies ----
  const ikePolicies = {};
  if (ikeNode && ikeNode.policy) {
    for (const [name, data] of Object.entries(ikeNode.policy)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      const proposalRefs = collectKeys(data.proposals);
      const hasPsk = data['pre-shared-key'];
      if (hasPsk) {
        warnings.push(createWarning(
          'info', 'ike-policy/' + name,
          'IKE policy ' + name + ' pre-shared key sanitized',
          'Pre-shared keys are never included in parsed output'
        ));
      }
      ikePolicies[name] = {
        name,
        mode: extractStringValue(data.mode) || 'main',
        proposals: proposalRefs,
      };
    }
  }


  // ---- IKE gateways ----
  const ikeGateways = {};
  if (ikeNode && ikeNode.gateway) {
    for (const [name, data] of Object.entries(ikeNode.gateway)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      const address = extractStringValue(data.address);
      const extInterface = extractStringValue(data['external-interface']);
      const ikePolicyRef = extractStringValue(data['ike-policy']);
      const policy = ikePolicies[ikePolicyRef];
      const ikeVersion = data.version ? extractStringValue(data.version) : 'v2';

      ikeGateways[name] = {
        name, address,
        local_address: extInterface,
        pre_shared_key: 'SANITIZED',
        ike_version: ikeVersion.startsWith('v') ? ikeVersion : 'v' + ikeVersion,
        proposal: ikePolicyRef,
        _proposalRefs: policy ? policy.proposals : [],
      };
    }
  }

  // ---- IPsec proposals ----
  const ipsecProposals = {};
  if (ipsecNode && ipsecNode.proposal) {
    for (const [name, data] of Object.entries(ipsecNode.proposal)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      ipsecProposals[name] = {
        name,
        protocol: extractStringValue(data.protocol) || 'esp',
        encryption: extractStringValue(data['encryption-algorithm']) || 'aes-256-cbc',
        authentication: extractStringValue(data['authentication-algorithm']) || 'hmac-sha-256-128',
        lifetime: parseInt(extractStringValue(data['lifetime-seconds']), 10) || 3600,
        pfs_group: 'group14',
      };
    }
  }

  // ---- IPsec policies ----
  const ipsecPolicies = {};
  if (ipsecNode && ipsecNode.policy) {
    for (const [name, data] of Object.entries(ipsecNode.policy)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      const pfsNode = data['perfect-forward-secrecy'];
      const pfs = pfsNode ? pfsNode.keys : null;
      const proposalRefs = collectKeys(data.proposals);
      ipsecPolicies[name] = {
        name,
        pfs_group: pfs ? extractStringValue(pfs) : 'group14',
        proposals: proposalRefs,
      };
    }
  }


  // ---- IPsec VPNs ----
  if (ipsecNode && ipsecNode.vpn) {
    for (const [name, data] of Object.entries(ipsecNode.vpn)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;

      const bindInterface = extractStringValue(data['bind-interface']);
      const ikeData = data.ike || {};
      const gwRef = extractStringValue(ikeData.gateway);
      const ipsecPolicyRef = extractStringValue(ikeData['ipsec-policy']);

      // Traffic selectors
      const proxyIds = [];
      const tsNode = data['traffic-selector'];
      if (tsNode && typeof tsNode === 'object') {
        for (const [tsName, tsData] of Object.entries(tsNode)) {
          if (tsName.startsWith('_') || typeof tsData !== 'object') continue;
          proxyIds.push({
            local: extractStringValue(tsData['local-ip']) || '',
            remote: extractStringValue(tsData['remote-ip']) || '',
            protocol: 'any',
          });
        }
      }

      // Resolve gateway
      const gw = ikeGateways[gwRef] || {
        name: gwRef, address: '', local_address: '',
        pre_shared_key: 'SANITIZED', ike_version: 'v2', proposal: '', _proposalRefs: [],
      };

      // Resolve IKE proposal
      const firstIkeProposalName = gw._proposalRefs && gw._proposalRefs[0] ? gw._proposalRefs[0] : '';
      const ikeProposal = ikeProposals[firstIkeProposalName] || {
        name: firstIkeProposalName || 'default',
        auth_method: 'pre-shared-keys', dh_group: 'group14',
        encryption: 'aes-256-cbc', authentication: 'sha-256', lifetime: 28800,
      };

      // Resolve IPsec proposal
      const ipsecPolicy = ipsecPolicies[ipsecPolicyRef];
      const firstIpsecProposalName = ipsecPolicy && ipsecPolicy.proposals[0] ? ipsecPolicy.proposals[0] : '';
      const ipsecProposal = ipsecProposals[firstIpsecProposalName] || {
        name: firstIpsecProposalName || 'default', protocol: 'esp',
        encryption: 'aes-256-cbc', authentication: 'hmac-sha-256-128',
        lifetime: 3600, pfs_group: 'group14',
      };
      if (ipsecPolicy && ipsecPolicy.pfs_group) {
        ipsecProposal.pfs_group = ipsecPolicy.pfs_group;
      }

      vpnTunnels.push({
        name,
        ike_gateway: {
          name: gw.name, address: gw.address, local_address: gw.local_address,
          pre_shared_key: 'SANITIZED', ike_version: gw.ike_version, proposal: gw.proposal,
        },
        ike_proposal: ikeProposal,
        ipsec_proposal: ipsecProposal,
        proxy_id: proxyIds,
        tunnel_interface: bindInterface,
        description: '',
      });
    }
  }

  if (vpnTunnels.length > 0) {
    warnings.push(createWarning(
      'info', 'vpn',
      'Parsed ' + vpnTunnels.length + ' VPN/IPsec tunnel(s)',
      'VPN tunnel configuration detected and included in intermediate output'
    ));
  }

  return vpnTunnels;
}


function extractVersion(tree) {
  // version statement
  if (tree.version) {
    return extractStringValue(tree.version);
  }
  // system host-name can help identify
  if (tree.system?.['host-name']) {
    return 'unknown (host: ' + extractStringValue(tree.system['host-name']) + ')';
  }
  return 'unknown';
}


// ---------------------------------------------------------------------------
// Syslog Configuration Parser
// ---------------------------------------------------------------------------

function parseSrxSyslogConfig(tree, warnings) {
  const servers = [];
  const syslog = tree.system?.syslog;
  if (!syslog) return servers;

  // SRX: set system syslog host <ip> <facility> <level>
  const hosts = syslog.host;
  if (hosts && typeof hosts === 'object') {
    for (const [hostAddr, hostConfig] of Object.entries(hosts)) {
      if (typeof hostConfig !== 'object') continue;
      const rawTransport = hostConfig['transport']?.protocol;
      const transport = typeof rawTransport === 'object' ? Object.keys(rawTransport)[0] || 'udp' : rawTransport || 'udp';
      const rawPort = hostConfig.port;
      const port = parseInt(typeof rawPort === 'object' ? Object.keys(rawPort)[0] || '514' : rawPort || (hostConfig['transport']?.['tls-profile'] ? '6514' : '514'), 10);

      // Parse facility/severity pairs
      const facilities = [];
      for (const [key, val] of Object.entries(hostConfig)) {
        if (['transport', 'port', 'source-address', 'structured-data'].includes(key)) continue;
        if (typeof val === 'string') {
          facilities.push({ facility: key, level: val });
        } else if (typeof val === 'object') {
          facilities.push({ facility: key, level: Object.keys(val)[0] || 'any' });
        }
      }

      servers.push({
        name: `syslog-${hostAddr}`,
        server: hostAddr,
        port,
        transport,
        facilities,
        source_address: hostConfig['source-address'] || '',
        structured_data: !!hostConfig['structured-data'],
      });
    }
  }

  // SRX: set system syslog file <name> <facility> <level>
  const files = syslog.file;
  if (files && typeof files === 'object') {
    for (const [fileName, fileConfig] of Object.entries(files)) {
      if (typeof fileConfig !== 'object') continue;
      const facilities = [];
      for (const [key, val] of Object.entries(fileConfig)) {
        if (['archive', 'match', 'structured-data'].includes(key)) continue;
        if (typeof val === 'string') {
          facilities.push({ facility: key, level: val });
        }
      }
      servers.push({
        name: `file-${fileName}`,
        server: `file:${fileName}`,
        port: 0,
        transport: 'file',
        facilities,
      });
    }
  }

  if (servers.length > 0) {
    warnings.push(createWarning('info', 'syslog', `Parsed ${servers.length} syslog destination(s)`, 'Syslog configuration detected'));
  }
  return servers;
}


// ---------------------------------------------------------------------------
// DHCP Configuration Parser
// ---------------------------------------------------------------------------

function parseSrxDhcpConfig(tree, warnings) {
  const dhcpConfigs = [];

  // SRX: set system services dhcp-local-server group <name> interface <if>
  const dhcpLocal = tree.system?.services?.['dhcp-local-server'];
  if (dhcpLocal) {
    const groups = dhcpLocal.group;
    if (groups && typeof groups === 'object') {
      for (const [groupName, groupConfig] of Object.entries(groups)) {
        if (typeof groupConfig !== 'object') continue;
        const ifaces = [];
        const ifSection = groupConfig.interface;
        if (ifSection) {
          if (typeof ifSection === 'string') ifaces.push(ifSection);
          else if (typeof ifSection === 'object') ifaces.push(...Object.keys(ifSection));
        }
        dhcpConfigs.push({
          type: 'server',
          group: groupName,
          interfaces: ifaces,
        });
      }
    }
  }

  // SRX: set forwarding-options helpers bootp interface <if> server <ip>
  const bootp = tree['forwarding-options']?.helpers?.bootp;
  if (bootp) {
    const ifSection = bootp.interface;
    if (ifSection && typeof ifSection === 'object') {
      for (const [ifName, ifConfig] of Object.entries(ifSection)) {
        if (typeof ifConfig !== 'object') continue;
        const relayServers = [];
        const serverSection = ifConfig.server;
        if (typeof serverSection === 'string') relayServers.push(serverSection);
        else if (typeof serverSection === 'object') relayServers.push(...Object.keys(serverSection));

        dhcpConfigs.push({
          type: 'relay',
          interface: ifName,
          servers: relayServers,
        });
      }
    }
  }

  // SRX: set access address-assignment pool <name> family inet range <range> low/high
  const pools = tree.access?.['address-assignment']?.pool;
  if (pools && typeof pools === 'object') {
    for (const [poolName, poolConfig] of Object.entries(pools)) {
      if (typeof poolConfig !== 'object') continue;
      const network = poolConfig.family?.inet?.network || '';
      const ranges = [];
      const rangeSection = poolConfig.family?.inet?.range;
      if (rangeSection && typeof rangeSection === 'object') {
        for (const [rangeName, rangeConfig] of Object.entries(rangeSection)) {
          if (typeof rangeConfig !== 'object') continue;
          ranges.push({ name: rangeName, low: rangeConfig.low || '', high: rangeConfig.high || '' });
        }
      }
      const dns = [];
      const dnsSection = poolConfig.family?.inet?.['dhcp-attributes']?.['name-server'];
      if (dnsSection) {
        if (typeof dnsSection === 'string') dns.push(dnsSection);
        else if (typeof dnsSection === 'object') dns.push(...Object.keys(dnsSection));
      }
      const router = poolConfig.family?.inet?.['dhcp-attributes']?.router || '';

      dhcpConfigs.push({
        type: 'pool',
        name: poolName,
        network,
        ranges,
        dns_servers: dns,
        router,
      });
    }
  }

  if (dhcpConfigs.length > 0) {
    warnings.push(createWarning('info', 'dhcp', `Parsed ${dhcpConfigs.length} DHCP config(s)`, 'DHCP configuration detected'));
  }
  return dhcpConfigs;
}


// ---------------------------------------------------------------------------
// QoS / CoS Configuration Parser
// ---------------------------------------------------------------------------

function parseSrxQosConfig(tree, warnings) {
  const qosProfiles = [];

  // SRX: set class-of-service ...
  const cos = tree['class-of-service'];
  if (!cos) return qosProfiles;

  // Forwarding classes
  const fwdClasses = cos['forwarding-classes'];
  const classMap = {};
  if (fwdClasses) {
    const classSection = fwdClasses.class || fwdClasses['queue'];
    if (classSection && typeof classSection === 'object') {
      for (const [name, config] of Object.entries(classSection)) {
        classMap[name] = {
          name,
          queue: typeof config === 'object' ? (config['queue-num'] || '') : config,
          priority: typeof config === 'object' ? (config.priority || '') : '',
        };
      }
    }
  }

  // Schedulers
  const schedulers = cos.schedulers;
  if (schedulers && typeof schedulers === 'object') {
    for (const [name, config] of Object.entries(schedulers)) {
      if (typeof config !== 'object') continue;
      qosProfiles.push({
        name,
        type: 'scheduler',
        transmit_rate: extractStringValue(config['transmit-rate']),
        buffer_size: extractStringValue(config['buffer-size']),
        priority: extractStringValue(config.priority),
        drop_profile: extractStringValue(config['drop-profile-map']?.['loss-priority']?.['any']?.protocol?.any),
      });
    }
  }

  // Interfaces with CoS
  const interfaces = cos.interfaces;
  if (interfaces && typeof interfaces === 'object') {
    for (const [ifName, ifConfig] of Object.entries(interfaces)) {
      if (typeof ifConfig !== 'object') continue;
      qosProfiles.push({
        name: `cos-${ifName}`,
        type: 'interface-cos',
        interface: ifName,
        scheduler_map: extractStringValue(ifConfig['scheduler-map']),
        shaping_rate: extractStringValue(ifConfig['shaping-rate']),
      });
    }
  }

  if (qosProfiles.length > 0) {
    warnings.push(createWarning('info', 'qos', `Parsed ${qosProfiles.length} CoS/QoS config(s)`, 'Class-of-service configuration detected'));
  }
  return qosProfiles;
}

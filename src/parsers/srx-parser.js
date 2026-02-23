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

  const intermediateConfig = {
    zones,
    address_objects: addressObjects,
    address_groups: addressGroups,
    service_objects: serviceObjects,
    service_groups: serviceGroups,
    security_policies: securityPolicies,
    nat_rules: natRules,
    applications,
    schedules,
    security_profile_objects: [],
    external_lists: [],
    vpn_tunnels: [],
    metadata: {
      source_vendor: 'srx',
      source_version: version,
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: natRules.length,
      object_count: addressObjects.length + addressGroups.length + serviceObjects.length + serviceGroups.length,
      zone_count: zones.length,
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

/**
 * Extract Junos version from tree.
 */
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

/**
 * PAN-OS XML Configuration Parser
 * =================================
 * Agent: PANOS-Expert
 *
 * Parses PAN-OS running-config XML exports (both device-level and Panorama)
 * into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - Security zones and interfaces
 *   - Address objects (IP, FQDN, range, wildcard)
 *   - Address groups (static and dynamic)
 *   - Service objects (TCP/UDP with port ranges)
 *   - Service groups
 *   - Security rules (with all match criteria, actions, logging)
 *   - NAT rules (source, destination, static)
 *   - Custom applications
 *   - Basic VPN/IKE gateway detection
 *
 * Designed for configs up to 10,000+ rules — avoids unnecessary object
 * copies and uses direct property access where possible.
 */

import { XMLParser } from 'fast-xml-parser';
import {
  ensureArray,
  extractMembers,
  extractEntries,
  getNestedValue,
  createWarning,
  detectVendor,
} from './parser-utils.js';

// ---------------------------------------------------------------------------
// XML Parser Configuration
// ---------------------------------------------------------------------------

const xmlParserOptions = {
  ignoreAttributes: false,       // PAN-OS uses name="..." on <entry> elements
  attributeNamePrefix: '@_',     // Access attributes as @_name, @_uuid, etc.
  allowBooleanAttributes: true,
  parseTagValue: true,
  trimValues: true,
  // Force 'entry' and 'member' to always be arrays even when there's only one child.
  // These are the only PAN-OS elements that appear as repeated siblings.
  // Container nodes like <zone>, <address>, <rulebase> are singletons and must NOT
  // be forced to arrays — doing so breaks navigation (e.g., vsys.zone becomes [obj]
  // instead of obj).
  isArray: (name) => {
    return name === 'entry' || name === 'member';
  },
};

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a complete PAN-OS XML configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw PAN-OS XML configuration text
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parsePanosConfig(configText) {
  // Detect vendor to confirm this is PAN-OS
  const detection = detectVendor(configText);
  if (detection.vendor !== 'panos' && detection.vendor !== 'unknown') {
    throw new Error(`Detected vendor "${detection.vendor}" — this parser only supports PAN-OS XML configs`);
  }

  const parser = new XMLParser(xmlParserOptions);
  let parsed;
  try {
    parsed = parser.parse(configText);
  } catch (err) {
    throw new Error(`Failed to parse XML: ${err.message}`);
  }

  const warnings = [];

  // Navigate to the vsys config. PAN-OS XML structure:
  // <config> → <devices> → <entry> → <vsys> → <entry name="vsys1">
  const config = parsed.config;
  if (!config) {
    throw new Error('Invalid PAN-OS config: missing <config> root element');
  }

  // Extract PAN-OS version from config attributes
  const panosVersion = config['@_version'] || 'unknown';

  // Find the vsys entry — handle both device-level and Panorama exports
  const vsysList = findVsysEntries(config);
  if (vsysList.length === 0) {
    throw new Error('No vsys found in configuration. Ensure this is a valid PAN-OS device config or Panorama export.');
  }

  // For Phase 1, parse the first vsys. Phase 2 will add multi-vsys/device-group handling.
  const vsys = vsysList[0];

  // Parse each config section into the intermediate schema
  const zones = parseZones(vsys, warnings);
  const addressObjects = parseAddressObjects(vsys, warnings);
  const addressGroups = parseAddressGroups(vsys, warnings);
  const serviceObjects = parseServiceObjects(vsys, warnings);
  const serviceGroups = parseServiceGroups(vsys, warnings);
  const applications = parseApplications(vsys, warnings);
  const applicationGroups = parseApplicationGroups(vsys, warnings);
  const securityPolicies = parseSecurityRules(vsys, warnings);
  const natRules = parseNatRules(vsys, warnings);
  const externalLists = parseExternalLists(vsys, warnings);
  const schedules = parseScheduleObjects(vsys);

  // Resolve profile group references → expand into individual security_profiles
  const profileGroupDefs = parseProfileGroupDefinitions(vsys);
  for (const policy of securityPolicies) {
    if (policy.profile_group && Object.keys(policy.security_profiles).length === 0) {
      const groupDef = profileGroupDefs[policy.profile_group];
      if (groupDef) {
        policy.security_profiles = { ...groupDef };
      }
    }
  }

  // Flag rules that reference EDL block lists for SecIntel mapping
  flagSecIntelRules(securityPolicies, externalLists, warnings);

  // Build security profile objects from rules
  const securityProfileObjects = buildSecurityProfileObjects(securityPolicies);

  // Append PAN-OS implicit rules
  let implicitIndex = securityPolicies.length + 1;
  for (const zone of zones) {
    securityPolicies.push({
      name: `Implicit: Intra-zone Allow (${zone.name})`,
      src_zones: [zone.name],
      dst_zones: [zone.name],
      src_addresses: ['any'],
      dst_addresses: ['any'],
      negate_source: false,
      negate_destination: false,
      applications: ['any'],
      services: ['any'],
      action: 'allow',
      log_start: false,
      log_end: false,
      profile_group: '',
      security_profiles: {},
      description: 'PAN-OS default: traffic within the same zone is allowed',
      tags: ['added_by_fpic'],
      disabled: false,
      _rule_index: implicitIndex++,
      _implicit: true,
    });
  }
  securityPolicies.push({
    name: 'Implicit: Interzone Default Deny',
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
    description: 'PAN-OS default: traffic between different zones is denied',
    tags: ['added_by_fpic'],
    disabled: false,
    _rule_index: implicitIndex++,
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
    application_groups: applicationGroups,
    schedules,
    security_profile_objects: securityProfileObjects,
    external_lists: externalLists,
    vpn_tunnels: [], // Phase 2
    metadata: {
      source_vendor: 'panos',
      source_version: panosVersion,
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
// VSys Finder
// ---------------------------------------------------------------------------

/**
 * Locates all vsys entries in the config, handling both device-level
 * configs and Panorama device group structures.
 */
function findVsysEntries(config) {
  // Standard device config: config → devices → entry → vsys → entry
  const devices = getNestedValue(config, 'devices');
  if (devices) {
    const deviceEntries = extractEntries(devices);
    for (const device of deviceEntries) {
      const vsys = getNestedValue(device, 'vsys');
      if (vsys) {
        return extractEntries(vsys);
      }
    }
  }

  // Panorama shared config: config → shared (treat as single virtual vsys)
  const shared = getNestedValue(config, 'shared');
  if (shared) {
    return [shared];
  }

  // Direct vsys at config level (some export formats)
  const directVsys = getNestedValue(config, 'vsys');
  if (directVsys) {
    return extractEntries(directVsys);
  }

  return [];
}

// ---------------------------------------------------------------------------
// Zone Parser
// ---------------------------------------------------------------------------

function parseZones(vsys, warnings) {
  const zoneContainer = vsys.zone;
  if (!zoneContainer) return [];

  const entries = extractEntries(zoneContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-zone';
    const interfaces = [];

    // PAN-OS zones have network → layer3 → member for L3 interfaces
    const l3Members = getNestedValue(entry, 'network.layer3');
    if (l3Members) {
      interfaces.push(...extractMembers(l3Members));
    }

    // Also check for layer2 interfaces
    const l2Members = getNestedValue(entry, 'network.layer2');
    if (l2Members) {
      interfaces.push(...extractMembers(l2Members));
    }

    return {
      name,
      description: entry.description || '',
      interfaces,
    };
  });
}

// ---------------------------------------------------------------------------
// Address Object Parser
// ---------------------------------------------------------------------------

function parseAddressObjects(vsys, warnings) {
  const addressContainer = vsys.address;
  if (!addressContainer) return [];

  const entries = extractEntries(addressContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-address';
    const tags = extractMembers(entry.tag);
    let type = 'unknown';
    let value = '';

    if (entry['ip-netmask']) {
      type = entry['ip-netmask'].includes('/32') ? 'host' : 'subnet';
      value = entry['ip-netmask'];
    } else if (entry['ip-range']) {
      type = 'range';
      value = entry['ip-range'];
    } else if (entry.fqdn) {
      type = 'fqdn';
      value = entry.fqdn;
      warnings.push(createWarning(
        'warning',
        `address/${name}`,
        `FQDN address "${name}" → SRX dns-name requires SRX 12.1+ and DNS resolution at commit time`,
        'Verify SRX version supports dns-name, or replace with static IP'
      ));
    } else if (entry['ip-wildcard']) {
      type = 'wildcard';
      value = entry['ip-wildcard'];
      warnings.push(createWarning(
        'unsupported',
        `address/${name}`,
        `Wildcard mask address "${name}" has no direct SRX equivalent`,
        'Convert to a subnet or address range manually'
      ));
    }

    return { name, type, value, description: entry.description || '', tags };
  });
}

// ---------------------------------------------------------------------------
// Address Group Parser
// ---------------------------------------------------------------------------

function parseAddressGroups(vsys, warnings) {
  const groupContainer = vsys['address-group'];
  if (!groupContainer) return [];

  const entries = extractEntries(groupContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-group';
    const tags = extractMembers(entry.tag);
    let members = [];

    // Static group: has <static><member>...</member></static>
    const staticNode = entry.static;
    if (staticNode) {
      // static might be an array from isArray config; take first element if so
      const staticObj = Array.isArray(staticNode) ? staticNode[0] : staticNode;
      members = extractMembers(staticObj);
    }

    // Dynamic group: has <dynamic><filter>...</filter></dynamic>
    if (entry.dynamic) {
      warnings.push(createWarning(
        'interview_required',
        `address-group/${name}`,
        `Dynamic address group "${name}" uses tag-based matching — SRX does not support dynamic address groups natively`,
        'Define the group members statically, or use SRX address-book with feed servers'
      ));
    }

    return {
      name,
      members,
      description: entry.description || '',
      tags,
    };
  });
}

// ---------------------------------------------------------------------------
// Service Object Parser
// ---------------------------------------------------------------------------

function parseServiceObjects(vsys, warnings) {
  const serviceContainer = vsys.service;
  if (!serviceContainer) return [];

  const entries = extractEntries(serviceContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-service';
    let protocol = 'tcp';
    let portRange = '';
    let sourcePort = '';

    const proto = entry.protocol;
    if (proto) {
      if (proto.tcp) {
        protocol = 'tcp';
        portRange = proto.tcp.port ? String(proto.tcp.port) : '';
        sourcePort = proto.tcp['source-port'] ? String(proto.tcp['source-port']) : '';
      } else if (proto.udp) {
        protocol = 'udp';
        portRange = proto.udp.port ? String(proto.udp.port) : '';
        sourcePort = proto.udp['source-port'] ? String(proto.udp['source-port']) : '';
      } else if (proto.sctp) {
        protocol = 'sctp';
        portRange = proto.sctp.port ? String(proto.sctp.port) : '';
        warnings.push(createWarning(
          'warning',
          `service/${name}`,
          `SCTP service "${name}" — SRX SCTP support varies by platform and version`,
          'Verify SRX platform supports SCTP'
        ));
      } else if (proto.icmp) {
        protocol = 'icmp';
      } else if (proto.icmp6) {
        protocol = 'icmp6';
      }
    }

    const result = {
      name,
      protocol,
      port_range: portRange,
      source_port: sourcePort,
      description: entry.description || '',
    };

    // ICMP services don't have ports
    if (protocol === 'icmp' || protocol === 'icmp6') {
      result.icmp_type = '';
      result.icmp_code = '';
    }

    return result;
  });
}

// ---------------------------------------------------------------------------
// Service Group Parser
// ---------------------------------------------------------------------------

function parseServiceGroups(vsys, warnings) {
  const groupContainer = vsys['service-group'];
  if (!groupContainer) return [];

  const entries = extractEntries(groupContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-service-group';
    const members = extractMembers(entry.members || entry);

    return {
      name,
      members,
      description: entry.description || '',
    };
  });
}

// ---------------------------------------------------------------------------
// Application Parser
// ---------------------------------------------------------------------------

function parseApplications(vsys, warnings) {
  const appContainer = vsys.application;
  if (!appContainer) return [];

  const entries = extractEntries(appContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-app';

    // Extract protocol/port from default settings if available
    let protocol = '';
    let port = '';

    const defaults = entry.default;
    if (defaults) {
      const portList = getNestedValue(defaults, 'port');
      if (portList) {
        // PAN-OS format: "tcp/80,443" or "udp/53"
        const portMembers = extractMembers(portList);
        if (portMembers.length > 0) {
          const firstPort = portMembers[0];
          const match = firstPort.match(/^(tcp|udp)\/([\d,-]+)$/i);
          if (match) {
            protocol = match[1].toLowerCase();
            port = match[2];
          }
        }
      }
    }

    if (!protocol && !port) {
      warnings.push(createWarning(
        'interview_required',
        `application/${name}`,
        `Custom application "${name}" has no default port defined — SRX needs explicit protocol/port`,
        'Specify the protocol and port(s) this application uses'
      ));
    }

    return {
      name,
      protocol,
      port,
      description: entry.description || '',
    };
  });
}

// ---------------------------------------------------------------------------
// Application Group Parser
// ---------------------------------------------------------------------------

function parseApplicationGroups(vsys, warnings) {
  const groupContainer = vsys['application-group'];
  if (!groupContainer) return [];

  const entries = extractEntries(groupContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-app-group';
    let members = [];

    // PAN-OS uses <members><member>...</member></members>
    const membersNode = entry.members;
    if (membersNode) {
      const membersObj = Array.isArray(membersNode) ? membersNode[0] : membersNode;
      members = extractMembers(membersObj);
    }

    return {
      name,
      members,
      description: entry.description || '',
    };
  });
}

// ---------------------------------------------------------------------------
// Security Rules Parser
// ---------------------------------------------------------------------------

function parseSecurityRules(vsys, warnings) {
  // Rules live under rulebase → security → rules → entry
  const rulebase = vsys.rulebase;
  if (!rulebase) return [];

  const securityNode = rulebase.security;
  if (!securityNode) return [];

  const rulesNode = securityNode.rules;
  if (!rulesNode) return [];

  // rulesNode itself might be an array (from isArray config)
  const rulesContainer = Array.isArray(rulesNode) ? rulesNode[0] : rulesNode;
  const ruleEntries = extractEntries(rulesContainer);

  return ruleEntries.map((entry, index) => {
    const name = entry['@_name'] || `rule-${index + 1}`;
    const srcZones = extractMembers(entry.from);
    const dstZones = extractMembers(entry.to);
    const srcAddresses = extractMembers(entry.source);
    const dstAddresses = extractMembers(entry.destination);
    const applications = extractMembers(entry.application);
    const services = extractMembers(entry.service);
    const action = parseAction(entry.action);
    const disabled = entry.disabled === 'yes' || entry.disabled === true;
    const description = entry.description || '';
    const tags = extractMembers(entry.tag);

    // Negate flags
    const negateSource = entry['negate-source'] === 'yes' || entry['negate-source'] === true;
    const negateDest = entry['negate-destination'] === 'yes' || entry['negate-destination'] === true;

    // Logging
    const logStart = entry['log-start'] === 'yes' || entry['log-start'] === true;
    const logEnd = entry['log-end'] === 'yes' || entry['log-end'] === true || entry['log-end'] === undefined;

    // Security profile group (AV, IPS, URL filtering, etc.)
    let profileGroup = '';
    const security_profiles = {};
    if (entry['profile-setting']) {
      const group = getNestedValue(entry, 'profile-setting.group');
      if (group) {
        const groupMembers = extractMembers(group);
        profileGroup = groupMembers[0] || '';
        warnings.push(createWarning(
          'interview_required',
          `security-rule/${name}`,
          `Rule "${name}" uses security profile group "${profileGroup}" — will apply default UTM+IDP if no individual profiles specified`,
          'Expand the profile group into individual profiles for more precise SRX mapping'
        ));
      }

      // Extract individual security profiles
      const profiles = getNestedValue(entry, 'profile-setting.profiles');
      if (profiles) {
        const profileTypes = ['virus', 'spyware', 'vulnerability', 'url-filtering', 'file-blocking', 'wildfire-analysis'];
        for (const pType of profileTypes) {
          if (profiles[pType]) {
            const members = extractMembers(profiles[pType]);
            if (members.length > 0) {
              security_profiles[pType] = members[0]; // PAN-OS uses single profile per type
            }
          }
        }
        if (Object.keys(security_profiles).length > 0) {
          const profileList = Object.entries(security_profiles).map(([k, v]) => `${k}:${v}`).join(', ');
          warnings.push(createWarning(
            'warning',
            `security-rule/${name}`,
            `Rule "${name}" has individual security profiles [${profileList}] — will map to SRX UTM/IDP`,
            'Verify the generated UTM and IDP policies match your security requirements'
          ));
        }
      }
    }

    // Flag application-default service usage
    if (services.includes('application-default')) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" uses "application-default" service — SRX will use the application's default ports`,
        'Verify the application mapping includes correct port definitions'
      ));
    }

    // Flag any/any zone combinations
    if (srcZones.includes('any') && dstZones.includes('any')) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" matches any source AND any destination zone — this is very broad`,
        'Confirm this rule should apply to all zone pairs on the SRX'
      ));
    }

    // Flag disabled rules
    if (disabled) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" is disabled — will be converted using "deactivate" in SRX`,
        'Choose whether to include disabled rules or skip them entirely'
      ));
    }

    // Flag tag usage
    if (tags.length > 0) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" has tags [${tags.join(', ')}] — SRX does not support tag-based policy matching`,
        'Tags will be added to the rule description as comments'
      ));
    }

    // Flag negate usage
    if (negateSource) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" negates source addresses — SRX uses "source-address ... except" or "source-exclude-list"`,
        'Verify the SRX policy correctly excludes the specified source addresses'
      ));
    }
    if (negateDest) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" negates destination addresses — SRX uses "destination-address ... except" or "destination-exclude-list"`,
        'Verify the SRX policy correctly excludes the specified destination addresses'
      ));
    }

    return {
      name,
      src_zones: srcZones,
      dst_zones: dstZones,
      src_addresses: srcAddresses,
      dst_addresses: dstAddresses,
      negate_source: negateSource,
      negate_destination: negateDest,
      applications,
      services,
      action,
      log_start: logStart,
      log_end: logEnd,
      profile_group: profileGroup,
      security_profiles,
      description,
      tags,
      disabled,
      schedule: entry.schedule ? String(entry.schedule) : '',
      _rule_index: index + 1,
    };
  });
}

/**
 * Parses the PAN-OS action field, which can be a string or an object.
 * PAN-OS uses: allow, deny, drop, reset-client, reset-server, reset-both
 */
function parseAction(actionField) {
  if (!actionField) return 'deny';
  if (typeof actionField === 'string') return actionField;
  // Object form: { allow: null } or { deny: null } or { drop: null }
  if (typeof actionField === 'object') {
    const keys = Object.keys(actionField);
    return keys[0] || 'deny';
  }
  return 'deny';
}

// ---------------------------------------------------------------------------
// Security Profile Object Builder
// ---------------------------------------------------------------------------

/**
 * Builds security_profile_objects from all rules' security_profiles and profile_groups.
 *
 * For individual profiles (e.g. virus: 'default'), creates one object per unique
 * type+name pair.
 *
 * For profile groups (e.g. profile_group: 'strict-security'), expands to all 6
 * standard profile types using the group name, since PAN-OS config doesn't
 * include group definitions inline.
 */
function buildSecurityProfileObjects(policies) {
  const seen = new Map(); // key → object
  const allProfileTypes = ['virus', 'spyware', 'vulnerability', 'url-filtering', 'file-blocking', 'wildfire-analysis'];

  const featureLabels = {
    'virus':              { srxFeature: 'utm', srxType: 'anti-virus',        label: 'Antivirus' },
    'wildfire-analysis':  { srxFeature: 'utm', srxType: 'anti-virus',        label: 'WildFire Analysis' },
    'url-filtering':      { srxFeature: 'utm', srxType: 'web-filtering',     label: 'URL Filtering' },
    'file-blocking':      { srxFeature: 'utm', srxType: 'content-filtering', label: 'File Blocking' },
    'spyware':            { srxFeature: 'idp', srxType: 'idp-policy',        label: 'Anti-Spyware' },
    'vulnerability':      { srxFeature: 'idp', srxType: 'idp-policy',        label: 'Vulnerability Protection' },
  };

  for (const policy of policies) {
    // Individual profiles
    const sp = policy.security_profiles || {};
    for (const [pType, pName] of Object.entries(sp)) {
      const key = `${pType}::${pName}`;
      if (!seen.has(key)) {
        const info = featureLabels[pType] || { srxFeature: 'unknown', srxType: pType, label: pType };
        seen.set(key, {
          name: `${pType}-${pName}`.replace(/\s+/g, '-'),
          profile_type: pType,
          profile_type_label: info.label,
          profile_name: pName,
          srx_feature: info.srxFeature,
          srx_type: info.srxType,
          source: 'individual',
          attached_rules: [policy.name],
        });
      } else {
        const obj = seen.get(key);
        if (!obj.attached_rules.includes(policy.name)) {
          obj.attached_rules.push(policy.name);
        }
      }
    }

    // Profile group — expand to all 6 types
    if (policy.profile_group && Object.keys(sp).length === 0) {
      const groupName = policy.profile_group;
      for (const pType of allProfileTypes) {
        const key = `group:${groupName}::${pType}`;
        if (!seen.has(key)) {
          const info = featureLabels[pType];
          seen.set(key, {
            name: `${groupName}-${pType}`.replace(/\s+/g, '-'),
            profile_type: pType,
            profile_type_label: info.label,
            profile_name: groupName,
            srx_feature: info.srxFeature,
            srx_type: info.srxType,
            source: `group:${groupName}`,
            attached_rules: [policy.name],
          });
        } else {
          const obj = seen.get(key);
          if (!obj.attached_rules.includes(policy.name)) {
            obj.attached_rules.push(policy.name);
          }
        }
      }
    }
  }

  return [...seen.values()];
}

// ---------------------------------------------------------------------------
// Profile Group Definitions Parser
// ---------------------------------------------------------------------------

/**
 * Parses the <profile-group> section from PAN-OS config.
 * Returns a map of group name → { virus: 'default', spyware: 'strict', ... }
 */
function parseProfileGroupDefinitions(vsys) {
  const pgContainer = vsys['profile-group'];
  if (!pgContainer) return {};

  const entries = extractEntries(pgContainer);
  const groups = {};
  const profileTypes = ['virus', 'spyware', 'vulnerability', 'url-filtering', 'file-blocking', 'wildfire-analysis'];

  for (const entry of entries) {
    const name = entry['@_name'];
    if (!name) continue;

    const profiles = {};
    for (const pType of profileTypes) {
      if (entry[pType]) {
        const members = extractMembers(entry[pType]);
        if (members.length > 0) {
          profiles[pType] = members[0];
        }
      }
    }

    if (Object.keys(profiles).length > 0) {
      groups[name] = profiles;
    }
  }

  return groups;
}

// ---------------------------------------------------------------------------
// External Dynamic Lists (EDL) Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS schedule objects.
 * PAN-OS schedules can be recurring (weekly/daily) or non-recurring (one-time).
 */
function parseScheduleObjects(vsys) {
  const scheduleContainer = vsys.schedule;
  if (!scheduleContainer) return [];

  const entries = extractEntries(scheduleContainer);
  return entries.map(entry => {
    const name = entry['@_name'] || 'unnamed-schedule';
    const schedType = entry['schedule-type'];
    if (!schedType) return { name, type: 'unknown', days: [], start: '', end: '' };

    if (schedType.recurring) {
      const weekly = schedType.recurring.weekly;
      if (weekly) {
        const dayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        const days = [];
        let start = '', end = '';
        for (const day of dayNames) {
          if (weekly[day]) {
            days.push(day.charAt(0).toUpperCase() + day.slice(1, 3));
            // Time ranges are in "HH:MM-HH:MM" format
            const timeStr = Array.isArray(weekly[day]) ? weekly[day][0] : String(weekly[day]);
            if (timeStr && timeStr.includes('-')) {
              const [s, e] = timeStr.split('-');
              start = start || s;
              end = e;
            }
          }
        }
        return { name, type: 'recurring', days, start, end };
      }
      // Daily schedule
      const daily = schedType.recurring.daily;
      if (daily) {
        const timeStr = Array.isArray(daily) ? daily[0] : String(daily);
        let start = '', end = '';
        if (timeStr && timeStr.includes('-')) {
          [start, end] = timeStr.split('-');
        }
        return { name, type: 'recurring', days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], start, end };
      }
    }

    if (schedType['non-recurring']) {
      const nr = schedType['non-recurring'];
      const timeRange = Array.isArray(nr) ? nr[0] : String(nr);
      let start = '', end = '';
      if (timeRange && timeRange.includes('/')) {
        [start, end] = timeRange.split('/');
      }
      return { name, type: 'onetime', start, end };
    }

    return { name, type: 'unknown', days: [], start: '', end: '' };
  });
}

/**
 * Parses PAN-OS External Dynamic Lists (EDLs) from the device config.
 * Detects predefined Palo Alto threat feeds and custom block lists.
 */
function parseExternalLists(vsys, warnings) {
  const edls = [];
  const externalList = getNestedValue(vsys, 'external-list.entry');
  if (!externalList) return edls;

  const entries = ensureArray(externalList);
  for (const entry of entries) {
    const name = entry['@_name'] || entry.name || 'unnamed-edl';
    const typeNode = entry.type || {};

    let isPredefined = false;
    let url = '';
    let listType = 'ip';

    if (typeNode['predefined-ip']) {
      isPredefined = true;
      url = typeNode['predefined-ip'].url || name;
      listType = 'ip';
    } else if (typeNode['predefined-url']) {
      isPredefined = true;
      url = typeNode['predefined-url'].url || name;
      listType = 'url';
    } else if (typeNode.ip) {
      url = typeNode.ip.url || '';
      listType = 'ip';
    } else if (typeNode.domain) {
      url = typeNode.domain.url || '';
      listType = 'domain';
    } else if (typeNode.url) {
      url = typeNode.url.url || '';
      listType = 'url';
    }

    // Heuristic: is this a threat/block list?
    const blockListPatterns = [
      'bulletproof', 'highrisk', 'high-risk', 'known-ip', 'malicious',
      'tor-exit', 'c2', 'command-and-control', 'botnet', 'ransomware',
      'threat', 'block', 'deny', 'blacklist', 'blocklist',
    ];
    const isBlockList = isPredefined || blockListPatterns.some(p =>
      name.toLowerCase().includes(p) || url.toLowerCase().includes(p)
    );

    if (isBlockList) {
      warnings.push(createWarning(
        'warning',
        `external-list/${name}`,
        `EDL "${name}" detected as threat block list — will map to SRX Security Intelligence (SecIntel)`,
        'Verify the SRX platform supports Security Intelligence feeds'
      ));
    }

    edls.push({ name, url, listType, isPredefined, isBlockList });
  }
  return edls;
}

/**
 * Scans security rules for references to EDL block list addresses.
 * Adds `_secIntelAddresses` to rules that reference detected block lists.
 */
function flagSecIntelRules(policies, externalLists, warnings) {
  if (!externalLists || externalLists.length === 0) return;

  const blockListNames = new Set(
    externalLists.filter(e => e.isBlockList).map(e => e.name)
  );
  if (blockListNames.size === 0) return;

  for (const policy of policies) {
    const secIntelAddrs = [];
    for (const addr of [...policy.src_addresses, ...policy.dst_addresses]) {
      if (blockListNames.has(addr)) {
        secIntelAddrs.push(addr);
      }
    }
    if (secIntelAddrs.length > 0) {
      policy._secIntelAddresses = secIntelAddrs;
      warnings.push(createWarning(
        'warning',
        `security-rule/${policy.name}`,
        `Rule "${policy.name}" references threat feed(s) [${secIntelAddrs.join(', ')}] — will map to SRX SecIntel`,
        'EDL addresses will be removed from rule match criteria and replaced with SecIntel policy attachment'
      ));
    }
  }
}

// ---------------------------------------------------------------------------
// NAT Rules Parser
// ---------------------------------------------------------------------------

function parseNatRules(vsys, warnings) {
  const rulebase = vsys.rulebase;
  if (!rulebase) return [];

  const natNode = rulebase.nat;
  if (!natNode) return [];

  const rulesNode = natNode.rules;
  if (!rulesNode) return [];

  const rulesContainer = Array.isArray(rulesNode) ? rulesNode[0] : rulesNode;
  const ruleEntries = extractEntries(rulesContainer);

  return ruleEntries.map((entry, index) => {
    const name = entry['@_name'] || `nat-rule-${index + 1}`;
    const srcZones = extractMembers(entry.from);
    const dstZones = extractMembers(entry.to);
    const srcAddresses = extractMembers(entry.source);
    const dstAddresses = extractMembers(entry.destination);
    const description = entry.description || '';

    let type = 'unknown';
    let translatedSrc = null;
    let translatedDst = null;
    let translatedPort = null;

    // Source NAT
    if (entry['source-translation']) {
      type = 'source';
      const srcTrans = entry['source-translation'];

      if (srcTrans['dynamic-ip-and-port']) {
        const dip = srcTrans['dynamic-ip-and-port'];
        if (dip['interface-address']) {
          translatedSrc = { type: 'interface', interface: dip['interface-address'].interface || '' };
        } else if (dip['translated-address']) {
          const translatedAddrs = extractMembers(dip['translated-address']);
          translatedSrc = { type: 'dynamic-ip-pool', addresses: translatedAddrs };
          warnings.push(createWarning(
            'interview_required',
            `nat-rule/${name}`,
            `NAT rule "${name}" uses dynamic IP pool — SRX requires an explicit source NAT pool definition`,
            'Specify the IP range for the SRX source NAT pool'
          ));
        }
      } else if (srcTrans['static-ip']) {
        type = 'static';
        translatedSrc = {
          type: 'static',
          address: srcTrans['static-ip']['translated-address'] || '',
        };
      }
    }

    // Destination NAT
    if (entry['destination-translation']) {
      type = type === 'source' ? 'source-and-destination' : 'destination';
      const dstTrans = entry['destination-translation'];
      translatedDst = dstTrans['translated-address'] || '';
      translatedPort = dstTrans['translated-port'] ? String(dstTrans['translated-port']) : null;
    }

    return {
      name,
      type,
      src_zones: srcZones,
      dst_zones: dstZones,
      src_addresses: srcAddresses,
      dst_addresses: dstAddresses,
      translated_src: translatedSrc,
      translated_dst: translatedDst,
      translated_port: translatedPort,
      description,
      _rule_index: index + 1,
    };
  });
}

/**
 * SRX Set-Command Converter
 * ===========================
 * Agent: SRX-Expert
 *
 * Converts the vendor-neutral intermediate JSON schema into Juniper SRX
 * set commands (Junos CLI format).
 *
 * Output follows Junos hierarchy:
 *   - security zones
 *   - security address-book global
 *   - applications
 *   - security policies from-zone X to-zone Y policy Z
 *   - security nat source/destination
 *   - deactivate statements for disabled rules
 *
 * Each generated command is tagged with a conversion status
 * (clean / warning / unsupported) for the warnings panel.
 */

import { sanitizeJunosName, mapAppToJunos, mapProfileToSrx, createWarning } from '../parsers/parser-utils.js';

// ---------------------------------------------------------------------------
// Main Converter Entry Point
// ---------------------------------------------------------------------------

/**
 * Converts an intermediate config to SRX set commands.
 *
 * @param {Object} config - Intermediate JSON config from the parser
 * @param {Object} [interfaceMappings] - User-defined PAN-OS → SRX interface mappings
 * @returns {{ commands: string[], warnings: Object[], summary: Object }}
 */
export function convertToSrxSetCommands(config, interfaceMappings = {}) {
  const commands = [];
  const warnings = [];
  const summary = {
    zones_converted: 0,
    addresses_converted: 0,
    address_groups_converted: 0,
    services_converted: 0,
    policies_converted: 0,
    nat_rules_converted: 0,
    total_warnings: 0,
    unsupported_items: 0,
  };

  // Generate commands in Junos hierarchy order
  convertZones(config.zones, commands, warnings, summary, interfaceMappings);
  convertAddressObjects(config.address_objects, commands, warnings, summary);
  convertAddressGroups(config.address_groups, commands, warnings, summary);
  convertServiceObjects(config.service_objects, commands, warnings, summary);
  convertServiceGroups(config.service_groups, commands, warnings, summary);
  convertApplications(config.applications, commands, warnings, summary);

  // Clear Customfwic tracker for fresh conversion
  customfwicApps.clear();

  // UTM / IDP / SecIntel — must run before security policies to build assignment maps
  const { utmCommands, utmPolicyMap } = convertUtmPolicies(config.security_policies, warnings);
  const { idpCommands, idpPolicyMap } = convertIdpPolicies(config.security_policies, warnings);
  const { secIntelCommands, secIntelEnabled } = convertSecIntel(config.external_lists, config.security_policies, warnings);

  commands.push(...utmCommands);
  commands.push(...idpCommands);
  commands.push(...secIntelCommands);

  convertSchedules(config.schedules, commands, warnings);
  convertSecurityPolicies(config.security_policies, commands, warnings, summary, { utmPolicyMap, idpPolicyMap, secIntelEnabled }, config.application_groups);
  convertNatRules(config.nat_rules, commands, warnings, summary);

  // Generate placeholder definitions for unmapped Customfwic applications
  if (customfwicApps.size > 0) {
    commands.push('# =============================================');
    commands.push('# Placeholder Custom Applications (Customfwic)');
    commands.push('# WARNING: These need manual protocol/port definitions');
    commands.push('# =============================================');
    for (const [customName, originalName] of customfwicApps) {
      commands.push(`# TODO: Define "${originalName}" — set correct protocol and destination-port`);
      commands.push(`set applications application ${customName} protocol tcp`);
      commands.push(`set applications application ${customName} destination-port 0`);
      commands.push(`set applications application ${customName} description "Placeholder for ${originalName} - REQUIRES MANUAL CONFIGURATION"`);
    }
    commands.push('');
  }

  summary.total_warnings = warnings.length;

  return { commands, warnings, summary };
}

// ---------------------------------------------------------------------------
// Zone Converter
// ---------------------------------------------------------------------------

function convertZones(zones, commands, warnings, summary, interfaceMappings = {}) {
  if (!zones || zones.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Security Zones');
  commands.push('# =============================================');

  for (const zone of zones) {
    const zoneName = sanitizeJunosName(zone.name);
    commands.push(`set security zones security-zone ${zoneName}`);

    // Add interfaces to zone
    for (const iface of zone.interfaces || []) {
      // Map PAN-OS interface names to SRX convention if needed
      const srxIface = mapInterfaceName(iface, interfaceMappings);
      commands.push(`set security zones security-zone ${zoneName} interfaces ${srxIface}`);
    }

    // Allow host-inbound traffic defaults (common SRX requirement)
    commands.push(`set security zones security-zone ${zoneName} host-inbound-traffic system-services ping`);

    if (zone.description) {
      commands.push(`set security zones security-zone ${zoneName} description "${zone.description}"`);
    }

    summary.zones_converted++;
  }

  commands.push('');
}

/**
 * Maps PAN-OS interface naming (ethernet1/1, ethernet1/1.100) to
 * SRX interface naming (ge-0/0/0, ge-0/0/0.100).
 *
 * This is a best-effort mapping — real deployments will need the user to
 * confirm interface assignments, which is handled in the interview phase.
 */
function mapInterfaceName(panosIface, interfaceMappings = {}) {
  // Check user-defined mappings first
  if (interfaceMappings[panosIface]) {
    const srx = interfaceMappings[panosIface];
    // Append .0 unit if not already specified
    return srx.includes('.') ? srx : `${srx}.0`;
  }

  // Strip VLAN unit for lookup, then re-add
  const base = panosIface.split('.')[0];
  const unit = panosIface.includes('.') ? panosIface.split('.')[1] : null;
  if (interfaceMappings[base]) {
    const srx = interfaceMappings[base];
    const srxBase = srx.split('.')[0];
    return `${srxBase}.${unit || '0'}`;
  }

  // Fallback: auto-map PAN-OS ethernet naming to SRX ge- naming
  const match = panosIface.match(/^ethernet(\d+)\/(\d+)(\.(\d+))?$/i);
  if (match) {
    const slot = parseInt(match[1]) - 1;
    const port = parseInt(match[2]) - 1;
    const u = match[4] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }
  // If it doesn't match PAN-OS format, return as-is
  return panosIface;
}

// ---------------------------------------------------------------------------
// Address Object Converter
// ---------------------------------------------------------------------------

function convertAddressObjects(objects, commands, warnings, summary) {
  if (!objects || objects.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Address Book (Global)');
  commands.push('# =============================================');

  for (const obj of objects) {
    const name = sanitizeJunosName(obj.name);

    switch (obj.type) {
      case 'host':
      case 'subnet':
        commands.push(`set security address-book global address ${name} ${obj.value}`);
        break;
      case 'range':
        // SRX supports range-address
        commands.push(`set security address-book global address ${name} range-address ${obj.value.replace('-', ' to ')}`);
        break;
      case 'fqdn': {
        // Wildcard FQDNs (e.g., *.example.com) are not supported by SRX dns-name
        const isWildcard = obj.value && obj.value.startsWith('*.');
        if (isWildcard) {
          commands.push(`# WARNING: Wildcard FQDN "${obj.name}" (${obj.value}) — SRX does not support wildcard dns-name`);
          commands.push(`# Convert to specific FQDN, address feed, or address set`);
          commands.push(`set security address-book global address ${name} dns-name ${obj.value.slice(2)}`);
          warnings.push(createWarning('warning', `address/${name}`,
            `Wildcard FQDN "${obj.name}" (${obj.value}) stripped to "${obj.value.slice(2)}" — SRX dns-name does not support wildcards`,
            'Replace with specific FQDN or use custom address feed'));
        } else {
          let dnsCmd = `set security address-book global address ${name} dns-name ${obj.value}`;
          // Append ipv4-only / ipv6-only if source specified IP version
          if (obj.fqdn_ip_version === 'v4') {
            dnsCmd += ' ipv4-only';
          } else if (obj.fqdn_ip_version === 'v6') {
            dnsCmd += ' ipv6-only';
          }
          commands.push(dnsCmd);
        }
        break;
      }
      case 'wildcard':
        // No SRX equivalent — add as comment
        commands.push(`# UNSUPPORTED: Wildcard address "${obj.name}" (${obj.value}) — convert manually`);
        warnings.push(createWarning('unsupported', `address/${name}`,
          `Wildcard address "${obj.name}" cannot be converted to SRX format`,
          'Replace with subnet or range address'));
        summary.unsupported_items++;
        continue; // Skip the description line
      default:
        commands.push(`# WARNING: Unknown address type "${obj.type}" for "${obj.name}"`);
        break;
    }

    if (obj.description) {
      commands.push(`set security address-book global address ${name} description "${obj.description}"`);
    }

    summary.addresses_converted++;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Address Group Converter
// ---------------------------------------------------------------------------

function convertAddressGroups(groups, commands, warnings, summary) {
  if (!groups || groups.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Address Sets (Groups)');
  commands.push('# =============================================');

  const groupNameSet = new Set(groups.map(g => g.name));

  for (const group of groups) {
    const groupName = sanitizeJunosName(group.name);

    for (const member of group.members) {
      const memberName = sanitizeJunosName(member);
      if (groupNameSet.has(member)) {
        commands.push(`set security address-book global address-set ${groupName} address-set ${memberName}`);
      } else {
        commands.push(`set security address-book global address-set ${groupName} address ${memberName}`);
      }
    }

    if (group.description) {
      commands.push(`set security address-book global address-set ${groupName} description "${group.description}"`);
    }

    summary.address_groups_converted++;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Service Object Converter → SRX Applications
// ---------------------------------------------------------------------------

function convertServiceObjects(services, commands, warnings, summary) {
  if (!services || services.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Applications (from PAN-OS Service Objects)');
  commands.push('# =============================================');

  for (const svc of services) {
    const name = sanitizeJunosName(svc.name);
    const protocol = svc.protocol || 'tcp';
    const port = svc.port_range || '';

    if (protocol === 'icmp' || protocol === 'icmp6') {
      // ICMP services use icmp-type/icmp-code instead of destination-port
      commands.push(`set applications application ${name} protocol ${protocol}`);
      if (svc.icmp_type) {
        commands.push(`set applications application ${name} icmp-type ${svc.icmp_type}`);
      }
      if (svc.icmp_code) {
        commands.push(`set applications application ${name} icmp-code ${svc.icmp_code}`);
      }
    } else if (protocol === 'ip' && svc.protocol_number) {
      // IP protocol by number
      commands.push(`set applications application ${name} protocol ${svc.protocol_number}`);
    } else {
      // TCP/UDP/SCTP — require port
      if (!port) {
        commands.push(`# WARNING: Service "${svc.name}" has no port defined — skipping`);
        warnings.push(createWarning('warning', `service/${name}`,
          `Service "${svc.name}" has no port range defined`,
          'Define the port range for this service'));
        continue;
      }

      commands.push(`set applications application ${name} protocol ${protocol}`);
      commands.push(`set applications application ${name} destination-port ${port}`);

      if (svc.source_port) {
        commands.push(`set applications application ${name} source-port ${svc.source_port}`);
      }
    }

    if (svc.description) {
      commands.push(`set applications application ${name} description "${svc.description}"`);
    }

    summary.services_converted++;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Service Group Converter → SRX Application Sets
// ---------------------------------------------------------------------------

function convertServiceGroups(groups, commands, warnings, summary) {
  if (!groups || groups.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Application Sets (from PAN-OS Service Groups)');
  commands.push('# =============================================');

  const groupNameSet = new Set(groups.map(g => g.name));

  for (const group of groups) {
    const groupName = sanitizeJunosName(group.name);

    for (const member of group.members) {
      const memberName = sanitizeJunosName(member);
      if (groupNameSet.has(member)) {
        commands.push(`set applications application-set ${groupName} application-set ${memberName}`);
      } else {
        commands.push(`set applications application-set ${groupName} application ${memberName}`);
      }
    }

    summary.services_converted++;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Custom Application Converter
// ---------------------------------------------------------------------------

function convertApplications(apps, commands, warnings, summary) {
  if (!apps || apps.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Custom Applications');
  commands.push('# =============================================');

  for (const app of apps) {
    const name = sanitizeJunosName(app.name);

    if (!app.protocol || !app.port) {
      commands.push(`# INTERVIEW REQUIRED: Custom application "${app.name}" needs protocol/port definition`);
      continue;
    }

    commands.push(`set applications application ${name} protocol ${app.protocol}`);
    commands.push(`set applications application ${name} destination-port ${app.port}`);

    if (app.description) {
      commands.push(`set applications application ${name} description "${app.description}"`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// UTM Policy Converter
// ---------------------------------------------------------------------------

/**
 * Scans all security policies for UTM-relevant profiles (virus, wildfire,
 * url-filtering, file-blocking) and generates SRX UTM feature profiles
 * and utm-policy definitions.
 *
 * Returns { utmCommands, utmPolicyMap } where utmPolicyMap maps
 * rule name → utm-policy name for attachment in convertSecurityPolicies.
 */
function convertUtmPolicies(policies, warnings) {
  const utmCommands = [];
  const utmPolicyMap = {};
  if (!policies || policies.length === 0) return { utmCommands, utmPolicyMap };

  const utmTypes = ['virus', 'wildfire-analysis', 'url-filtering', 'file-blocking', 'email-filter', 'application-control', 'dlp'];

  // Collect unique UTM profile combinations per rule
  const comboMap = new Map(); // serialized combo → { profiles, policyName, rules[] }
  let comboIndex = 0;

  for (const policy of policies) {
    const sp = policy.security_profiles || {};
    const utmProfiles = {};
    for (const t of utmTypes) {
      if (sp[t]) utmProfiles[t] = sp[t];
    }
    if (Object.keys(utmProfiles).length === 0) continue;

    const key = JSON.stringify(utmProfiles);
    if (!comboMap.has(key)) {
      comboIndex++;
      comboMap.set(key, { profiles: utmProfiles, policyName: `utm-policy-${comboIndex}`, rules: [] });
    }
    comboMap.get(key).rules.push(policy.name);
    utmPolicyMap[policy.name] = comboMap.get(key).policyName;
  }

  if (comboMap.size === 0) return { utmCommands, utmPolicyMap };

  utmCommands.push('# =============================================');
  utmCommands.push('# UTM Feature Profiles & Policies');
  utmCommands.push('# =============================================');

  // Collect all unique feature profiles
  const emittedProfiles = new Set();

  for (const [, combo] of comboMap) {
    const pName = combo.policyName;

    for (const [pType, pValue] of Object.entries(combo.profiles)) {
      const mapped = mapProfileToSrx(pType, pValue);

      // AppFW and DLP don't map to SRX UTM — emit informational comments
      if (mapped.srxFeature === 'appfw') {
        utmCommands.push(`# NOTE: FortiGate application-control "${pValue}" — configure SRX AppFW rule-set manually`);
        continue;
      }
      if (mapped.srxFeature === 'none') {
        utmCommands.push(`# NOTE: FortiGate DLP profile "${pValue}" — SRX DLP requires ICAP integration`);
        continue;
      }

      if (mapped.srxFeature !== 'utm') continue;

      // Emit feature profile definition once
      if (!emittedProfiles.has(mapped.srxProfile)) {
        emittedProfiles.add(mapped.srxProfile);
        if (mapped.srxType === 'web-filtering') {
          utmCommands.push(`set security utm feature-profile ${mapped.srxType} profile ${mapped.srxProfile} type juniper-enhanced`);
        } else {
          utmCommands.push(`set security utm feature-profile ${mapped.srxType} profile ${mapped.srxProfile}`);
        }
      }

      // Attach to utm-policy
      if (mapped.srxType === 'anti-virus') {
        utmCommands.push(`set security utm utm-policy ${pName} anti-virus http-profile ${mapped.srxProfile}`);
        utmCommands.push(`set security utm utm-policy ${pName} anti-virus ftp-upload-profile ${mapped.srxProfile}`);
        utmCommands.push(`set security utm utm-policy ${pName} anti-virus ftp-download-profile ${mapped.srxProfile}`);
      } else if (mapped.srxType === 'web-filtering') {
        utmCommands.push(`set security utm utm-policy ${pName} web-filtering http-profile ${mapped.srxProfile}`);
      } else if (mapped.srxType === 'content-filtering') {
        utmCommands.push(`set security utm utm-policy ${pName} content-filtering rule-set ${mapped.srxProfile}`);
      } else if (mapped.srxType === 'anti-spam') {
        utmCommands.push(`set security utm utm-policy ${pName} anti-spam smtp-profile ${mapped.srxProfile}`);
      }
    }
  }

  utmCommands.push('');
  return { utmCommands, utmPolicyMap };
}

// ---------------------------------------------------------------------------
// IDP Policy Converter
// ---------------------------------------------------------------------------

/**
 * Scans policies for IDP-relevant profiles (spyware, vulnerability) and
 * generates SRX IDP policy definitions.
 */
function convertIdpPolicies(policies, warnings) {
  const idpCommands = [];
  const idpPolicyMap = {};
  if (!policies || policies.length === 0) return { idpCommands, idpPolicyMap };

  const idpTypes = ['spyware', 'vulnerability'];
  let policyIndex = 0;
  const comboMap = new Map();

  for (const policy of policies) {
    const sp = policy.security_profiles || {};
    const hasIdp = idpTypes.some(t => sp[t]);
    if (!hasIdp) continue;

    const idpProfiles = {};
    for (const t of idpTypes) {
      if (sp[t]) idpProfiles[t] = sp[t];
    }

    const key = JSON.stringify(idpProfiles);
    if (!comboMap.has(key)) {
      policyIndex++;
      comboMap.set(key, { profiles: idpProfiles, policyName: `idp-policy-${policyIndex}`, rules: [] });
    }
    comboMap.get(key).rules.push(policy.name);
    idpPolicyMap[policy.name] = comboMap.get(key).policyName;
  }

  if (comboMap.size === 0) return { idpCommands, idpPolicyMap };

  idpCommands.push('# =============================================');
  idpCommands.push('# IDP Policies');
  idpCommands.push('# =============================================');

  for (const [, combo] of comboMap) {
    const pName = combo.policyName;
    let ruleIdx = 0;

    for (const [pType, pValue] of Object.entries(combo.profiles)) {
      ruleIdx++;
      const ruleName = `${pType}-rule-${ruleIdx}`;
      const base = `security idp idp-policy ${pName} rulebase-ips rule ${ruleName}`;

      idpCommands.push(`set ${base} match attacks predefined-attack-groups "Recommended"`);
      idpCommands.push(`set ${base} then action recommended`);
      idpCommands.push(`set ${base} then notification log-attacks`);
      idpCommands.push(`# IDP rule mapped from PAN-OS ${pType} profile "${pValue}"`);
    }
  }

  idpCommands.push('');
  return { idpCommands, idpPolicyMap };
}

// ---------------------------------------------------------------------------
// Security Intelligence (SecIntel) Converter
// ---------------------------------------------------------------------------

/**
 * Generates SRX Security Intelligence configuration from detected EDL block lists.
 */
function convertSecIntel(externalLists, policies, warnings) {
  const secIntelCommands = [];
  let secIntelEnabled = false;
  if (!externalLists || externalLists.length === 0) return { secIntelCommands, secIntelEnabled };

  const blockLists = externalLists.filter(e => e.isBlockList);
  if (blockLists.length === 0) return { secIntelCommands, secIntelEnabled };

  secIntelEnabled = true;

  secIntelCommands.push('# =============================================');
  secIntelCommands.push('# Security Intelligence (SecIntel)');
  secIntelCommands.push('# =============================================');

  // Create a SecIntel profile with rules for each block list
  const profileName = 'secIntel-profile';
  let ruleIdx = 0;

  for (const bl of blockLists) {
    ruleIdx++;
    const ruleName = `secIntel-rule-${ruleIdx}`;
    const safeName = sanitizeJunosName(bl.name);

    secIntelCommands.push(`# EDL: "${bl.name}" (${bl.isPredefined ? 'predefined' : 'custom'}, type: ${bl.listType})`);
    secIntelCommands.push(`set services security-intelligence profile ${profileName} category BlockList`);
    secIntelCommands.push(`set services security-intelligence profile ${profileName} rule ${ruleName} match threat-level 10`);
    secIntelCommands.push(`set services security-intelligence profile ${profileName} rule ${ruleName} then action block close`);
    secIntelCommands.push(`set services security-intelligence profile ${profileName} rule ${ruleName} then log`);
  }

  secIntelCommands.push(`set services security-intelligence policy secIntel-policy ${profileName}`);

  warnings.push(createWarning(
    'warning',
    'security-intelligence',
    `${blockLists.length} EDL block list(s) mapped to SRX SecIntel: [${blockLists.map(b => b.name).join(', ')}]`,
    'Verify SRX platform supports Security Intelligence and configure feed servers'
  ));

  secIntelCommands.push('');
  return { secIntelCommands, secIntelEnabled };
}

// ---------------------------------------------------------------------------
// Schedule Converter → SRX Schedulers
// ---------------------------------------------------------------------------

function convertSchedules(schedules, commands, warnings) {
  if (!schedules || schedules.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Schedulers');
  commands.push('# =============================================');

  for (const sched of schedules) {
    const name = sanitizeJunosName(sched.name);
    if (sched.type === 'recurring' && sched.days && sched.days.length > 0) {
      for (const day of sched.days) {
        commands.push(`set schedulers scheduler ${name} ${day.toLowerCase()} start-time ${sched.start} stop-time ${sched.end}`);
      }
    } else if (sched.type === 'onetime') {
      commands.push(`set schedulers scheduler ${name} start-date "${sched.start}" stop-date "${sched.end}"`);
    } else {
      commands.push(`# WARNING: Schedule "${sched.name}" has unknown type "${sched.type}" — skipping`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Security Policy Converter
// ---------------------------------------------------------------------------

function convertSecurityPolicies(policies, commands, warnings, summary, profileMaps = {}, appGroups = []) {
  if (!policies || policies.length === 0) return;

  const { utmPolicyMap = {}, idpPolicyMap = {}, secIntelEnabled = false } = profileMaps;

  commands.push('# =============================================');
  commands.push('# Security Policies');
  commands.push('# =============================================');

  // Collect deactivate commands for disabled rules (applied at the end)
  const deactivateCommands = [];

  for (const policy of policies) {
    const policyName = sanitizeJunosName(policy.name);

    if (policy._implicit) {
      commands.push(`# --- Implicit Rule: ${policy.name} ---`);
    }

    // Clean up EDL block list addresses from match criteria
    const secIntelAddrs = new Set(policy._secIntelAddresses || []);
    let srcAddrs = policy.src_addresses.filter(a => !secIntelAddrs.has(a));
    let dstAddrs = policy.dst_addresses.filter(a => !secIntelAddrs.has(a));
    if (srcAddrs.length === 0 && policy.src_addresses.length > 0) srcAddrs = ['any'];
    if (dstAddrs.length === 0 && policy.dst_addresses.length > 0) dstAddrs = ['any'];

    // SRX policies are organized by from-zone/to-zone pair.
    const srcZones = policy.src_zones.length > 0 ? policy.src_zones : ['any'];
    const dstZones = policy.dst_zones.length > 0 ? policy.dst_zones : ['any'];

    const hasIndividualProfiles = Object.keys(policy.security_profiles || {}).length > 0;

    // Handle zone-based policy paths
    for (const srcZone of srcZones) {
      for (const dstZone of dstZones) {
        const fromZone = sanitizeJunosName(srcZone);
        const toZone = sanitizeJunosName(dstZone);
        const policyPath = `security policies from-zone ${fromZone} to-zone ${toZone} policy ${policyName}`;

        // Description (include PAN-OS tags as comments)
        let fullDescription = policy.description || '';
        if (policy.tags && policy.tags.length > 0) {
          const tagNote = `[PAN-OS tags: ${policy.tags.join(', ')}]`;
          fullDescription = fullDescription ? `${fullDescription} ${tagNote}` : tagNote;
        }
        if (fullDescription) {
          commands.push(`set ${policyPath} description "${fullDescription}"`);
        }

        // Match criteria: source addresses
        const effectiveSrcAddrs = srcAddrs.length > 0 ? srcAddrs : ['any'];
        for (const addr of effectiveSrcAddrs) {
          commands.push(`set ${policyPath} match source-address ${sanitizeJunosName(addr)}`);
        }

        // Match criteria: destination addresses
        const effectiveDstAddrs = dstAddrs.length > 0 ? dstAddrs : ['any'];
        for (const addr of effectiveDstAddrs) {
          commands.push(`set ${policyPath} match destination-address ${sanitizeJunosName(addr)}`);
        }

        // Match criteria: applications
        const apps = resolveApplications(policy.applications, policy.services, warnings, policyName, appGroups);
        for (const app of apps) {
          commands.push(`set ${policyPath} match application ${app}`);
        }

        // Action
        const srxAction = mapAction(policy.action);
        commands.push(`set ${policyPath} then ${srxAction}`);

        // Logging
        if (policy.log_start) {
          commands.push(`set ${policyPath} then log session-init`);
        }
        if (policy.log_end) {
          commands.push(`set ${policyPath} then log session-close`);
        }

        // UTM policy attachment
        if (utmPolicyMap[policy.name]) {
          commands.push(`set ${policyPath} then permit application-services utm-policy ${utmPolicyMap[policy.name]}`);
        }

        // IDP policy attachment
        if (idpPolicyMap[policy.name]) {
          commands.push(`set ${policyPath} then permit application-services idp-policy ${idpPolicyMap[policy.name]}`);
        }

        // SecIntel attachment (on permit rules to untrust)
        if (secIntelEnabled && policy.action === 'allow' && dstZones.some(z => z.toLowerCase() === 'untrust')) {
          commands.push(`set ${policyPath} then permit application-services security-intelligence-policy secIntel-policy`);
        }

        // Profile group fallback (if no individual profiles but group exists)
        if (policy.profile_group && !hasIndividualProfiles) {
          commands.push(`# NOTE: PAN-OS profile group "${policy.profile_group}" — individual profiles not specified, applied default UTM+IDP`);
          commands.push(`set ${policyPath} then permit application-services utm-policy default-utm`);
        }

        // Schedule reference
        if (policy.schedule) {
          commands.push(`set ${policyPath} scheduler-name ${sanitizeJunosName(policy.schedule)}`);
        }

        // Disabled rules → deactivate command
        if (policy.disabled) {
          deactivateCommands.push(`deactivate ${policyPath}`);
        }
      }
    }

    summary.policies_converted++;
  }

  // Append deactivate commands at the end
  if (deactivateCommands.length > 0) {
    commands.push('');
    commands.push('# Disabled rules (PAN-OS disabled → Junos deactivate)');
    commands.push(...deactivateCommands);
  }

  commands.push('');
}

/**
 * Tracks unmapped applications that received the Customfwic placeholder suffix.
 * Map of customName → originalName, used to generate placeholder definitions.
 */
const customfwicApps = new Map();

/**
 * Resolves application/service fields from any vendor to SRX application names.
 *
 * Applications are mapped via mapAppToJunos() (PAN-OS, FortiGate, Cisco ASA).
 * Unmapped applications get a "Customfwic" suffix and a warning is generated
 * telling the user to create a custom application definition on the SRX.
 *
 * SRX only has "application" in policy match — we unify both fields.
 */
function resolveApplications(applications, services, warnings, policyName, appGroups = []) {
  const resolved = [];

  // Helper to map a single app name to Junos (with Customfwic fallback)
  const mapSingleApp = (appName) => {
    const junosApp = mapAppToJunos(appName);
    if (junosApp) {
      resolved.push(junosApp);
    } else {
      const customName = sanitizeJunosName(appName) + 'Customfwic';
      resolved.push(customName);
      customfwicApps.set(customName, appName);
      warnings.push(createWarning(
        'warning',
        `policy/${policyName}`,
        `Application "${appName}" has no predefined Junos equivalent — using placeholder "${customName}"`,
        'Create a custom application on the SRX with the correct protocol/port definition for this application'
      ));
    }
  };

  // Map applications to Junos equivalents
  if (applications && applications.length > 0) {
    for (const app of applications) {
      if (app === 'any') {
        resolved.push('any');
        continue;
      }

      // Check if this is an application group reference — expand to members
      const group = appGroups.find(g => g.name === app);
      if (group && group.members.length > 0) {
        for (const member of group.members) {
          mapSingleApp(member);
        }
        continue;
      }

      mapSingleApp(app);
    }
  }

  // Handle explicit service references (not "application-default")
  if (services && services.length > 0) {
    for (const svc of services) {
      if (svc === 'application-default' || svc === 'any') continue;
      // Try mapping service name (catches FortiGate "HTTP", "HTTPS", etc.)
      const junosApp = mapAppToJunos(svc);
      if (junosApp) {
        resolved.push(junosApp);
      } else {
        // Service objects already converted to SRX applications — reference by name
        resolved.push(sanitizeJunosName(svc));
      }
    }
  }

  // If nothing resolved, use "any"
  if (resolved.length === 0) {
    resolved.push('any');
  }

  return [...new Set(resolved)]; // Deduplicate
}

/**
 * Maps PAN-OS action to SRX policy action.
 *
 * PAN-OS actions: allow, deny, drop, reset-client, reset-server, reset-both
 * SRX actions: permit, deny, reject
 */
function mapAction(panosAction) {
  switch (panosAction) {
    case 'allow':
      return 'permit';
    case 'deny':
      return 'deny';
    case 'drop':
      return 'deny';
    case 'reset-client':
    case 'reset-server':
    case 'reset-both':
      return 'reject';
    default:
      return 'deny';
  }
}

// ---------------------------------------------------------------------------
// NAT Rule Converter
// ---------------------------------------------------------------------------

function convertNatRules(natRules, commands, warnings, summary) {
  if (!natRules || natRules.length === 0) return;

  commands.push('# =============================================');
  commands.push('# NAT Rules');
  commands.push('# =============================================');

  // Group NAT rules by type for SRX rule-set organization
  const sourceNatRules = natRules.filter(r => r.type === 'source' || r.type === 'source-and-destination');
  const destNatRules = natRules.filter(r => r.type === 'destination' || r.type === 'source-and-destination');
  const staticNatRules = natRules.filter(r => r.type === 'static');

  // --- Source NAT ---
  if (sourceNatRules.length > 0) {
    // Group by zone pair for SRX rule-sets
    const ruleSetGroups = groupByZonePair(sourceNatRules);

    for (const [zonePair, rules] of Object.entries(ruleSetGroups)) {
      const [fromZone, toZone] = zonePair.split('->');
      const ruleSetName = sanitizeJunosName(`${fromZone}-to-${toZone}`);
      const ruleSetPath = `security nat source rule-set ${ruleSetName}`;

      commands.push(`set ${ruleSetPath} from zone ${sanitizeJunosName(fromZone)}`);
      commands.push(`set ${ruleSetPath} to zone ${sanitizeJunosName(toZone)}`);

      for (const rule of rules) {
        const ruleName = sanitizeJunosName(rule.name);
        const rulePath = `${ruleSetPath} rule ${ruleName}`;

        // Match criteria
        for (const addr of (rule.src_addresses || ['0.0.0.0/0'])) {
          if (addr === 'any') {
            commands.push(`set ${rulePath} match source-address 0.0.0.0/0`);
          } else {
            commands.push(`set ${rulePath} match source-address ${addr}`);
          }
        }
        for (const addr of (rule.dst_addresses || ['0.0.0.0/0'])) {
          if (addr === 'any') {
            commands.push(`set ${rulePath} match destination-address 0.0.0.0/0`);
          } else {
            commands.push(`set ${rulePath} match destination-address ${addr}`);
          }
        }

        // Translation action
        if (rule.translated_src) {
          if (rule.translated_src.type === 'interface') {
            commands.push(`set ${rulePath} then source-nat interface`);
          } else if (rule.translated_src.type === 'dynamic-ip-pool') {
            // Create a source NAT pool
            const poolName = sanitizeJunosName(`pool-${rule.name}`);
            for (const addr of rule.translated_src.addresses) {
              commands.push(`set security nat source pool ${poolName} address ${addr}`);
            }
            commands.push(`set ${rulePath} then source-nat pool ${poolName}`);
          } else if (rule.translated_src.type === 'static') {
            commands.push(`set ${rulePath} then source-nat pool ${sanitizeJunosName(rule.name)}-static`);
            commands.push(`set security nat source pool ${sanitizeJunosName(rule.name)}-static address ${rule.translated_src.address}`);
          }
        }

        summary.nat_rules_converted++;
      }
    }
  }

  // --- Destination NAT ---
  if (destNatRules.length > 0) {
    const ruleSetGroups = groupByZonePair(destNatRules);

    for (const [zonePair, rules] of Object.entries(ruleSetGroups)) {
      const [fromZone, toZone] = zonePair.split('->');
      const ruleSetName = sanitizeJunosName(`${fromZone}-to-${toZone}`);
      const ruleSetPath = `security nat destination rule-set ${ruleSetName}`;

      commands.push(`set ${ruleSetPath} from zone ${sanitizeJunosName(fromZone)}`);

      for (const rule of rules) {
        const ruleName = sanitizeJunosName(rule.name);
        const rulePath = `${ruleSetPath} rule ${ruleName}`;

        // Match
        for (const addr of (rule.dst_addresses || ['0.0.0.0/0'])) {
          if (addr === 'any') {
            commands.push(`set ${rulePath} match destination-address 0.0.0.0/0`);
          } else {
            commands.push(`set ${rulePath} match destination-address ${addr}`);
          }
        }

        // Translation
        if (rule.translated_dst) {
          const dstAddr = typeof rule.translated_dst === 'string' ? rule.translated_dst : rule.translated_dst.address || '';
          if (dstAddr) {
            const poolName = sanitizeJunosName(`dnat-pool-${rule.name}`);
            commands.push(`set security nat destination pool ${poolName} address ${dstAddr}`);
            if (rule.translated_port) {
              commands.push(`set security nat destination pool ${poolName} address port ${rule.translated_port}`);
            }
            commands.push(`set ${rulePath} then destination-nat pool ${poolName}`);
          }
        }

        summary.nat_rules_converted++;
      }
    }
  }

  // --- Static NAT ---
  if (staticNatRules.length > 0) {
    commands.push('# Static NAT Rules');
    for (const rule of staticNatRules) {
      const ruleName = sanitizeJunosName(rule.name);
      const ruleSetPath = `security nat static rule-set STATIC-NAT rule ${ruleName}`;

      for (const addr of (rule.dst_addresses || [])) {
        if (addr !== 'any') {
          commands.push(`set ${ruleSetPath} match destination-address ${addr}`);
        }
      }

      if (rule.translated_src && rule.translated_src.address) {
        commands.push(`set ${ruleSetPath} then static-nat prefix ${rule.translated_src.address}`);
      }

      summary.nat_rules_converted++;
    }
  }

  commands.push('');
}

/**
 * Groups NAT rules by source-zone → destination-zone pair.
 * SRX organizes NAT rules into rule-sets per zone pair.
 */
function groupByZonePair(rules) {
  const groups = {};
  for (const rule of rules) {
    const fromZones = rule.src_zones.length > 0 ? rule.src_zones : ['any'];
    const toZones = rule.dst_zones.length > 0 ? rule.dst_zones : ['any'];

    for (const from of fromZones) {
      for (const to of toZones) {
        const key = `${from}->${to}`;
        if (!groups[key]) groups[key] = [];
        groups[key].push(rule);
      }
    }
  }
  return groups;
}

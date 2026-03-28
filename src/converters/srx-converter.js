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

import { sanitizeJunosName, mapAppToJunos, mapProfileToSrx, createWarning, isPredefEquivalent, JUNOS_PREDEFINED_APPS } from '../parsers/parser-utils.js';

/**
 * Returns the correct ANY address for NAT rules based on whether the rule
 * contains IPv6 addresses. Uses '::/0' for IPv6, '0.0.0.0/0' for IPv4.
 */
function natAnyAddress(rule) {
  const allAddrs = [
    ...(rule.src_addresses || []),
    ...(rule.dst_addresses || []),
    ...(rule.translated_src?.addresses || []),
    ...(rule.translated_src?.address ? [rule.translated_src.address] : []),
    ...(rule.translated_dst?.address ? [rule.translated_dst.address] : []),
  ];
  return allAddrs.some(a => a && typeof a === 'string' && a.includes(':')) ? '::/0' : '0.0.0.0/0';
}

/**
 * Generates a descriptive rule name from policy content when the original
 * name is generic (e.g., "Rule-1", "policy_23") or missing.
 * Pattern: {action}-{srcZone}-to-{dstZone}-{primaryApp}-{index}
 */
function generateDescriptiveName(policy, pIdx) {
  const name = policy.name || '';

  // Only generate if name looks generic
  const isGeneric = !name ||
    /^(rule|policy|permit|deny)[-_]?\d+$/i.test(name) ||
    /^\d+$/.test(name);

  if (!isGeneric) return sanitizeJunosName(name);

  const action = (policy.action === 'allow' || policy.action === 'permit') ? 'permit' : 'deny';
  const srcZ = (policy.src_zones?.[0] || 'any').toLowerCase();
  const dstZ = (policy.dst_zones?.[0] || 'any').toLowerCase();

  let appHint = '';
  if (policy.applications?.length > 0 && policy.applications[0] !== 'any') {
    appHint = policy.applications[0].toLowerCase().replace(/^junos-/, '');
  } else if (policy.services?.length > 0 && policy.services[0] !== 'any') {
    appHint = policy.services[0].toLowerCase();
  }

  const parts = [action, srcZ, 'to', dstZ];
  if (appHint) parts.push(appHint);

  let generated = parts.join('-');
  generated = sanitizeJunosName(generated);

  return `${generated}-${pIdx + 1}`;
}

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
export function convertToSrxSetCommands(config, interfaceMappings = {}, targetContext = null) {
  const commands = [];
  const warnings = [];
  const summary = {
    zones_converted: 0,
    addresses_converted: 0,
    address_groups_converted: 0,
    services_converted: 0,
    policies_converted: 0,
    nat_rules_converted: 0,
    static_routes_converted: 0,
    bgp_groups_converted: 0,
    bgp_neighbors_converted: 0,
    ospf_areas_converted: 0,
    ospf_interfaces_converted: 0,
    lag_interfaces_converted: 0,
    total_warnings: 0,
    unsupported_items: 0,
  };

  // Site identification header (for SDC/Mist integration)
  const siteN = config.metadata?.siteName;
  const siteG = config.metadata?.siteGroup;
  if (siteN || siteG) {
    commands.push('# =============================================');
    commands.push('# Site Identification');
    commands.push('# =============================================');
    if (siteN) commands.push(`# Site: ${siteN}`);
    if (siteG) commands.push(`# Site Group: ${siteG}`);
    commands.push('');
  }

  // Clear trackers from any previous conversion (module-level state)
  customfwicApps.clear();
  predefServiceMap.clear();

  // Generate commands in Junos hierarchy order
  convertSystemConfig(config.system_config, commands, warnings, summary);
  convertZones(config.zones, commands, warnings, summary, interfaceMappings);
  convertInterfaceAddresses(config.interfaces, commands, warnings, summary, interfaceMappings);
  convertLagInterfaces(config.lag_interfaces, commands, warnings, summary, interfaceMappings);
  convertAddressObjects(config.address_objects, commands, warnings, summary);
  convertAddressGroups(config.address_groups, commands, warnings, summary);
  convertServiceObjects(config.service_objects, commands, warnings, summary);
  convertServiceGroups(config.service_groups, commands, warnings, summary);
  convertApplications(config.applications, commands, warnings, summary);

  // Detect source vendor for 1:1 passthrough (SRX→SRX needs no app mapping)
  const sourceVendor = config.metadata?.source_vendor || '';

  // UTM / IDP / SecIntel — must run before security policies to build assignment maps
  const profileDefs = config.security_profile_definitions || {};
  const { utmCommands, utmPolicyMap } = convertUtmPolicies(config.security_policies, warnings, profileDefs);
  const { idpCommands, idpPolicyMap } = convertIdpPolicies(config.security_policies, warnings, profileDefs);
  const { secIntelCommands, secIntelEnabled } = convertSecIntel(config.external_lists, config.security_policies, warnings);

  commands.push(...utmCommands);
  commands.push(...idpCommands);
  commands.push(...secIntelCommands);

  convertSchedules(config.schedules, commands, warnings);
  convertSecurityPolicies(config.security_policies, commands, warnings, summary, { utmPolicyMap, idpPolicyMap, secIntelEnabled }, config.application_groups, sourceVendor, config._rule_groups);
  convertNatRules(config.nat_rules, commands, warnings, summary);
  convertStaticRoutes(config.static_routes, commands, warnings, summary);
  convertBgpConfig(config.bgp_config, commands, warnings, summary);
  convertOspfConfig(config.ospf_config, commands, warnings, summary);
  convertOspf3Config(config.ospf3_config, commands, warnings, summary);
  convertEvpnConfig(config.evpn_config, commands, warnings, summary);
  convertVxlanConfig(config.vxlan_config, commands, warnings, summary);
  convertHaConfig(config.ha_config, commands, warnings, summary);
  convertScreenConfig(config.screen_config, commands, warnings, summary);
  convertVpnTunnels(config.vpn_tunnels, commands, warnings, summary);
  convertSyslogConfig(config.syslog_config, commands, warnings, summary);
  convertDhcpConfig(config.dhcp_config, commands, warnings, summary);
  convertQosConfig(config.qos_config, commands, warnings, summary);
  convertL2Config(config, commands, warnings, summary, interfaceMappings);
  convertPbfConfig(config.pbf_rules, commands, warnings, summary, interfaceMappings, config.address_objects);
  convertSslProxyConfig(config, commands, warnings, summary);
  convertFlowMonitoringConfig(config.flow_monitoring_config, commands, warnings, summary, interfaceMappings);
  convertUserIdentification(config.security_policies, commands, warnings);

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

  // Unsupported feature notices
  commands.push('# =============================================');
  commands.push('# NOT CONVERTED — Manual Configuration Required');
  commands.push('# =============================================');
  commands.push('# AAA / Authentication (RADIUS, TACACS+, LDAP) — not converted by this tool');
  commands.push('# Configure manually: set system authentication-order, set access profile, etc.');
  commands.push('');

  summary.total_warnings = warnings.length;

  // Logical-system / tenant wrapping
  const ctx = targetContext || config.target_context;
  if (ctx && ctx.type && ctx.type !== 'none' && ctx.name) {
    const ctxName = sanitizeJunosName(ctx.name);
    const prefix = ctx.type === 'logical-system'
      ? `logical-systems ${ctxName}`
      : `tenants ${ctxName}`;

    for (let i = 0; i < commands.length; i++) {
      const cmd = commands[i];
      if (cmd.startsWith('set ')) {
        commands[i] = `set ${prefix} ${cmd.slice(4)}`;
      } else if (cmd.startsWith('deactivate ')) {
        commands[i] = `deactivate ${prefix} ${cmd.slice(11)}`;
      }
    }
  }

  return { commands, warnings, summary };
}

// ---------------------------------------------------------------------------
// System Configuration Converter (Day-0)
// ---------------------------------------------------------------------------

function convertSystemConfig(systemConfig, commands, warnings, summary) {
  if (!systemConfig) return;

  const hasContent = systemConfig.hostname || systemConfig.domain_name ||
    (systemConfig.dns_servers && systemConfig.dns_servers.length > 0) ||
    (systemConfig.ntp_servers && systemConfig.ntp_servers.length > 0) ||
    systemConfig.timezone || systemConfig.login_banner;

  if (!hasContent) return;

  commands.push('# =============================================');
  commands.push('# System Configuration (Day-0)');
  commands.push('# =============================================');

  if (systemConfig.hostname) {
    commands.push(`set system host-name ${systemConfig.hostname}`);
  }
  if (systemConfig.domain_name) {
    commands.push(`set system domain-name ${systemConfig.domain_name}`);
  }
  for (const dns of (systemConfig.dns_servers || [])) {
    commands.push(`set system name-server ${dns}`);
  }
  for (const ntp of (systemConfig.ntp_servers || [])) {
    commands.push(`set system ntp server ${ntp}`);
  }
  if (systemConfig.timezone) {
    commands.push(`set system time-zone ${systemConfig.timezone}`);
  }
  if (systemConfig.login_banner) {
    const escaped = systemConfig.login_banner.replace(/"/g, '\\"');
    commands.push(`set system login message "${escaped}"`);
  }

  const mgmt = systemConfig.management_services || {};
  if (mgmt.ssh) {
    commands.push('set system services ssh');
  }
  if (mgmt.https) {
    commands.push('set system services web-management https system-generated-certificate');
  }
  if (mgmt.netconf) {
    commands.push('set system services netconf ssh');
  }

  commands.push('');
  summary.system_config_converted = 1;
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

  // Fallback: auto-map vendor interface naming to SRX ge-/xe- naming

  // PAN-OS: ethernet1/2 → ge-0/0/1.0  (slot-1, port-1)
  const panos = panosIface.match(/^ethernet(\d+)\/(\d+)(\.(\d+))?$/i);
  if (panos) {
    const slot = parseInt(panos[1]) - 1;
    const port = parseInt(panos[2]) - 1;
    const u = panos[4] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }

  // FortiGate: port1 → ge-0/0/0.0  (N-1)
  const forti = panosIface.match(/^port(\d+)(\.(\d+))?$/i);
  if (forti) {
    const port = parseInt(forti[1]) - 1;
    const u = forti[3] || '0';
    return `ge-0/0/${port}.${u}`;
  }

  // Check Point Gaia: eth0 → ge-0/0/0.0, bond0 passes through
  const cpEth = panosIface.match(/^eth(\d+)(\.(\d+))?$/i);
  if (cpEth) {
    const port = parseInt(cpEth[1]);
    const u = cpEth[3] || '0';
    return `ge-0/0/${port}.${u}`;
  }

  // SonicWall: X0 → ge-0/0/0.0
  const swX = panosIface.match(/^X(\d+)(\.(\d+))?$/i);
  if (swX) {
    const port = parseInt(swX[1]);
    const u = swX[3] || '0';
    return `ge-0/0/${port}.${u}`;
  }

  // Huawei: GigabitEthernet0/0/1 → ge-0/0/1.0
  const hwGe = panosIface.match(/^GigabitEthernet(\d+)\/(\d+)\/(\d+)(\.(\d+))?$/i);
  if (hwGe) {
    const slot = parseInt(hwGe[2]);
    const port = parseInt(hwGe[3]);
    const u = hwGe[5] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }

  // Huawei: XGigabitEthernet0/0/0 → xe-0/0/0.0
  const hwXe = panosIface.match(/^XGigabitEthernet(\d+)\/(\d+)\/(\d+)(\.(\d+))?$/i);
  if (hwXe) {
    const slot = parseInt(hwXe[2]);
    const port = parseInt(hwXe[3]);
    const u = hwXe[5] || '0';
    return `xe-0/${slot}/${port}.${u}`;
  }

  // If it doesn't match any known format, return as-is
  return panosIface;
}

// ---------------------------------------------------------------------------
// Interface Address Converter (IPv4 + IPv6)
// ---------------------------------------------------------------------------

function convertInterfaceAddresses(interfaces, commands, warnings, summary, interfaceMappings = {}) {
  if (!interfaces || interfaces.length === 0) return;

  const hasAddresses = interfaces.some(i => i.ip || i.ipv6);
  if (!hasAddresses) return;

  commands.push('# =============================================');
  commands.push('# Interface Addresses');
  commands.push('# =============================================');

  for (const iface of interfaces) {
    if (!iface.ip && !iface.ipv6) continue;

    const srxName = mapInterfaceName(iface.name || '', interfaceMappings);
    const [base, unit = '0'] = srxName.split('.');

    if (iface.ip) {
      commands.push(`set interfaces ${base} unit ${unit} family inet address ${iface.ip}`);
    }
    if (iface.ipv6) {
      commands.push(`set interfaces ${base} unit ${unit} family inet6 address ${iface.ipv6}`);
    }
    if (iface.description) {
      commands.push(`set interfaces ${base} unit ${unit} description "${iface.description}"`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// LAG / Aggregate Ethernet Converter
// ---------------------------------------------------------------------------

/**
 * Generates SRX ae (aggregate ethernet) interface configuration from parsed
 * LAG data in the intermediate config.
 *
 * Output:
 *   set chassis aggregated-devices ethernet device-count {N}
 *   set interfaces ae{N} aggregated-ether-options lacp {active|passive}
 *   set interfaces ae{N} description "{description}"
 *   set interfaces {member} ether-options 802.3ad ae{N}
 *
 * @param {Object[]} lagInterfaces - Array of lag_interfaces from intermediate config
 * @param {string[]} commands - Output commands array
 * @param {Object[]} warnings - Warnings array
 * @param {Object} summary - Summary counters
 * @param {Object} interfaceMappings - User-defined interface mappings
 */
function convertLagInterfaces(lagInterfaces, commands, warnings, summary, interfaceMappings = {}) {
  if (!lagInterfaces || lagInterfaces.length === 0) return;

  commands.push('# =============================================');
  commands.push('# LAG / Aggregate Ethernet Interfaces');
  commands.push('# =============================================');

  // Device count must accommodate the highest ae index
  let maxAeIndex = 0;
  for (const lag of lagInterfaces) {
    const aeMatch = lag.name.match(/^ae(\d+)$/);
    if (aeMatch) {
      const idx = parseInt(aeMatch[1], 10);
      if (idx >= maxAeIndex) maxAeIndex = idx + 1;
    }
  }

  commands.push(`set chassis aggregated-devices ethernet device-count ${maxAeIndex}`);

  for (const lag of lagInterfaces) {
    const aeName = lag.name;

    // LACP mode
    if (lag.lacp_mode === 'active' || lag.lacp_mode === 'passive') {
      commands.push(`set interfaces ${aeName} aggregated-ether-options lacp ${lag.lacp_mode}`);
    }

    // LACP system priority
    if (lag.lacp_priority) {
      commands.push(`set interfaces ${aeName} aggregated-ether-options lacp system-priority ${lag.lacp_priority}`);
    }

    // Description
    if (lag.description) {
      const escaped = lag.description.replace(/"/g, '\\"');
      commands.push(`set interfaces ${aeName} description "${escaped}"`);
    }

    // Member interface bindings
    for (const member of lag.members) {
      // Apply interface mapping if available
      const mappedMember = mapInterfaceName(member, interfaceMappings);
      const memberBase = mappedMember.split('.')[0];
      commands.push(`set interfaces ${memberBase} ether-options 802.3ad ${aeName}`);
    }

    summary.lag_interfaces_converted++;

    // Source name annotation for traceability
    if (lag.source_name && lag.source_name !== aeName) {
      commands.push(`# Source: ${lag.source_name} (${lag.source_members.join(', ')})`);
    }
  }

  commands.push('');

  warnings.push(createWarning('info', 'lag',
    `Converted ${lagInterfaces.length} LAG interface(s) to SRX ae configuration`,
    'Verify ae interface settings and member port assignments'));
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
      case 'geography':
        commands.push(`# UNSUPPORTED: Geography address "${obj.name}" (country: ${obj.value}) — SRX requires Security Intelligence feeds for geo-IP`);
        warnings.push(createWarning('unsupported', `address/${name}`,
          `Geography address "${obj.name}" (${obj.value}) has no direct SRX equivalent`,
          'Replace with static IP ranges or configure SRX Security Intelligence geo-IP feeds'));
        summary.unsupported_items++;
        continue;
      case 'dynamic':
        commands.push(`# UNSUPPORTED: Dynamic/SDN address "${obj.name}" (${obj.value}) — SRX requires manual configuration`);
        warnings.push(createWarning('unsupported', `address/${name}`,
          `Dynamic/SDN address "${obj.name}" (${obj.value}) has no direct SRX equivalent`,
          'Replace with static addresses or use SRX Security Intelligence feeds'));
        summary.unsupported_items++;
        continue;
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
    if (group._dynamic) {
      commands.push(`# UNSUPPORTED: Dynamic address group "${group.name}" — SRX does not support tag-based dynamic groups`);
      commands.push(`# Define members statically or use SRX address-book with feed servers`);
      continue;
    }
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

  predefServiceMap.clear();

  commands.push('# =============================================');
  commands.push('# Applications (from Service Objects)');
  commands.push('# =============================================');

  for (const svc of services) {
    const name = sanitizeJunosName(svc.name);
    const protocol = svc.protocol || 'tcp';
    const port = svc.port_range || '';

    // Check if this service maps to a predefined Junos application
    const predefApp = isPredefEquivalent(svc.name, protocol, port);
    if (predefApp) {
      predefServiceMap.set(svc.name, predefApp);
      predefServiceMap.set(name, predefApp);
      commands.push(`# Skipped: "${svc.name}" (${protocol}/${port}) → predefined ${predefApp}`);
      summary.services_converted++;
      continue;
    }

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
      // Check if member maps to a predefined Junos app
      const predefName = predefServiceMap.get(member);
      if (predefName) {
        commands.push(`set applications application-set ${groupName} application ${predefName}`);
      } else if (groupNameSet.has(member)) {
        commands.push(`set applications application-set ${groupName} application-set ${sanitizeJunosName(member)}`);
      } else {
        commands.push(`set applications application-set ${groupName} application ${sanitizeJunosName(member)}`);
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
function convertUtmPolicies(policies, warnings, profileDefs = {}) {
  const utmCommands = [];
  const utmPolicyMap = {};
  if (!policies || policies.length === 0) return { utmCommands, utmPolicyMap };

  const utmTypes = ['virus', 'wildfire-analysis', 'url-filtering', 'file-blocking', 'email-filter',
    'application-control', 'dlp', 'dns-security', 'decryption', 'waf', 'casb', 'voip'];

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
  utmCommands.push('# NOTE: Generated profiles use recommended defaults — review and customize for your environment');
  utmCommands.push('# =============================================');

  // Collect all unique feature profiles
  const emittedProfiles = new Set();

  for (const [, combo] of comboMap) {
    const pName = combo.policyName;

    for (const [pType, pValue] of Object.entries(combo.profiles)) {
      const mapped = mapProfileToSrx(pType, pValue);

      const defKey = `${pType}:${pValue}`;
      const profileDef = profileDefs[defKey];

      // AppFW: generate actual rule-set if we have category data
      if (mapped.srxFeature === 'appfw') {
        if (profileDef && profileDef.categories && Object.keys(profileDef.categories).length > 0) {
          const rsName = sanitizeJunosName(`appfw-${pValue}`);
          utmCommands.push(`# Application Firewall rule-set from application-control "${pValue}"`);
          let ruleNum = 0;
          for (const [category, action] of Object.entries(profileDef.categories)) {
            if (action === 'block' || action === 'block-all' || action === 'reset') {
              ruleNum++;
              utmCommands.push(`set security application-firewall rule-sets ${rsName} rule appfw-r${ruleNum} match dynamic-application-group junos:${sanitizeJunosName(category)}`);
              utmCommands.push(`set security application-firewall rule-sets ${rsName} rule appfw-r${ruleNum} then deny`);
            }
          }
          if (ruleNum > 0) {
            utmCommands.push(`set security application-firewall rule-sets ${rsName} default-rule permit`);
          } else {
            utmCommands.push(`# No blocked categories found in "${pValue}" — configure AppFW manually if needed`);
          }
        } else {
          utmCommands.push(`# NOTE: application-control "${pValue}" — configure SRX AppFW rule-set manually`);
        }
        continue;
      }
      if (mapped.srxFeature === 'none') {
        utmCommands.push(`# NOTE: DLP profile "${pValue}" — SRX DLP requires ICAP integration`);
        warnings.push(createWarning('unsupported', `profile/dlp/${pValue}`,
          `DLP profile "${pValue}" requires ICAP integration on SRX`,
          'Configure an ICAP server and redirect profile for DLP inspection'));
        continue;
      }

      if (mapped.srxFeature === 'ssl-proxy') {
        // SSL Proxy profiles are now generated by convertSslProxyConfig()
        continue;
      }
      if (mapped.srxFeature === 'unsupported') {
        utmCommands.push(`# NOTE: file-blocking profile "${pValue}" — not supported in SRX conversion`);
        warnings.push(createWarning('unsupported', `profile/${pType}/${pValue}`,
          `File-blocking profile "${pValue}" is not supported in Junos SRX conversion`,
          'SRX does not have an equivalent file-blocking feature — review UTM content-filtering or ICAP for similar functionality'));
        continue;
      }
      if (mapped.srxFeature === 'unknown') {
        warnings.push(createWarning('unsupported', `profile/${pType}/${pValue}`,
          `${pType} profile "${pValue}" has no SRX equivalent`,
          `Review SRX capabilities for ${pType} and configure manually`));
        utmCommands.push(`# UNSUPPORTED: ${pType} profile "${pValue}" — no direct SRX equivalent`);
        continue;
      }

      if (mapped.srxFeature !== 'utm') continue;

      // Emit feature profile definition once (uses source-derived params when available)
      if (!emittedProfiles.has(mapped.srxProfile)) {
        emittedProfiles.add(mapped.srxProfile);
        if (mapped.srxType === 'anti-virus') {
          const sizeLimit = (profileDef && profileDef.scanMode === 'full') ? 40000 : 20000;
          utmCommands.push(`set security utm feature-profile anti-virus profile ${mapped.srxProfile} fallback-options default log-and-permit`);
          utmCommands.push(`set security utm feature-profile anti-virus profile ${mapped.srxProfile} fallback-options content-size log-and-permit`);
          utmCommands.push(`set security utm feature-profile anti-virus profile ${mapped.srxProfile} scan-options content-size-limit ${sizeLimit}`);
          utmCommands.push(`set security utm feature-profile anti-virus profile ${mapped.srxProfile} scan-options timeout 180`);
        } else if (mapped.srxType === 'web-filtering') {
          utmCommands.push(`set security utm feature-profile web-filtering juniper-enhanced profile ${mapped.srxProfile}`);
          if (profileDef && profileDef.blockCategories && profileDef.blockCategories.length > 0) {
            utmCommands.push(`# Block categories from source: ${profileDef.blockCategories.join(', ')}`);
            utmCommands.push(`set security utm feature-profile web-filtering juniper-enhanced profile ${mapped.srxProfile} default block`);
          } else {
            utmCommands.push(`set security utm feature-profile web-filtering juniper-enhanced profile ${mapped.srxProfile} default log-and-permit`);
          }
        } else if (mapped.srxType === 'content-filtering') {
          if (profileDef && profileDef.blockedExtensions && profileDef.blockedExtensions.length > 0) {
            for (const ext of profileDef.blockedExtensions) {
              utmCommands.push(`set security utm feature-profile content-filtering profile ${mapped.srxProfile} block-extension ${sanitizeJunosName(ext)}`);
            }
          } else {
            utmCommands.push(`set security utm feature-profile content-filtering profile ${mapped.srxProfile} permit-command file-extension exe`);
            utmCommands.push(`set security utm feature-profile content-filtering profile ${mapped.srxProfile} permit-command file-extension zip`);
          }
        } else if (mapped.srxType === 'dns-security') {
          utmCommands.push(`# DNS Security from "${pValue}" — requires ATP Cloud license`);
          if (profileDef && profileDef.blockedDomains && profileDef.blockedDomains.length > 0) {
            for (const domain of profileDef.blockedDomains) {
              utmCommands.push(`set services dns-filtering dns-filtering-rule ${sanitizeJunosName(pValue)} match-name ${domain}`);
              utmCommands.push(`set services dns-filtering dns-filtering-rule ${sanitizeJunosName(pValue)} then action block`);
            }
          }
          utmCommands.push(`set services dns-filtering default-action allow`);
        } else if (mapped.srxType === 'anti-spam') {
          utmCommands.push(`set security utm feature-profile anti-spam profile ${mapped.srxProfile} sbl-default-server`);
        } else {
          utmCommands.push(`set security utm feature-profile ${mapped.srxType} profile ${mapped.srxProfile}`);
        }
      }

      // Attach to utm-policy
      if (mapped.srxType === 'anti-virus') {
        utmCommands.push(`set security utm utm-policy ${pName} anti-virus http-profile ${mapped.srxProfile}`);
        utmCommands.push(`set security utm utm-policy ${pName} anti-virus smtp-profile ${mapped.srxProfile}`);
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
function convertIdpPolicies(policies, warnings, profileDefs = {}) {
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
  idpCommands.push('# NOTE: Actions derived from source profile name heuristics — review for your environment');
  idpCommands.push('# =============================================');

  const idpActionMap = {
    'reset-both': 'drop-connection', 'reset-client': 'drop-connection',
    'reset-server': 'drop-connection', 'drop': 'drop-packet',
    'block': 'drop-connection', 'block-all': 'drop-connection',
    'alert': 'no-action', 'monitor': 'no-action',
    'pass': 'no-action', 'default': 'recommended',
  };

  for (const [, combo] of comboMap) {
    const pName = combo.policyName;
    let ruleIdx = 0;

    for (const [pType, pValue] of Object.entries(combo.profiles)) {
      const defKey = `${pType}:${pValue}`;
      const profileDef = profileDefs[defKey];

      if (profileDef && profileDef.severityActions && Object.keys(profileDef.severityActions).length > 0) {
        // Generate severity-specific IDP rules from source profile data
        const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
        for (const severity of severityOrder) {
          const sourceAction = profileDef.severityActions[severity];
          if (!sourceAction) continue;

          ruleIdx++;
          const ruleName = `${pType}-${severity}-r${ruleIdx}`;
          const base = `security idp idp-policy ${pName} rulebase-ips rule ${ruleName}`;
          const idpAction = idpActionMap[sourceAction] || 'recommended';
          const attackGroup = severity.charAt(0).toUpperCase() + severity.slice(1);

          idpCommands.push(`set ${base} match attacks predefined-attack-groups "${attackGroup} - Recommended"`);
          idpCommands.push(`set ${base} then action ${idpAction}`);
          idpCommands.push(`set ${base} then notification log-attacks`);
          idpCommands.push(`# Mapped from ${pType} "${pValue}" severity ${severity} (${sourceAction}) → SRX ${idpAction}`);
        }
      } else {
        // Fallback: name-based heuristics when no profile definitions available
        ruleIdx++;
        const ruleName = `${pType}-rule-${ruleIdx}`;
        const base = `security idp idp-policy ${pName} rulebase-ips rule ${ruleName}`;

        const nameLower = pValue.toLowerCase();
        let idpAction = 'recommended';
        if (nameLower.includes('strict') || nameLower.includes('critical')) {
          idpAction = 'drop-connection';
        } else if (nameLower.includes('alert') || nameLower.includes('monitor')) {
          idpAction = 'no-action';
        }

        idpCommands.push(`set ${base} match attacks predefined-attack-groups "Recommended"`);
        idpCommands.push(`set ${base} then action ${idpAction}`);
        idpCommands.push(`set ${base} then notification log-attacks`);
        idpCommands.push(`# IDP rule mapped from ${pType} profile "${pValue}" → action: ${idpAction}`);
      }
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

const DAY_NAME_MAP = {
  sun: 'sunday', mon: 'monday', tue: 'tuesday', wed: 'wednesday',
  thu: 'thursday', fri: 'friday', sat: 'saturday',
  sunday: 'sunday', monday: 'monday', tuesday: 'tuesday', wednesday: 'wednesday',
  thursday: 'thursday', friday: 'friday', saturday: 'saturday',
};

function convertSchedules(schedules, commands, warnings) {
  if (!schedules || schedules.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Schedulers');
  commands.push('# =============================================');

  for (const sched of schedules) {
    const name = sanitizeJunosName(sched.name);
    if (sched.type === 'recurring' && sched.days && sched.days.length > 0) {
      for (const day of sched.days) {
        const junosDay = DAY_NAME_MAP[day.toLowerCase()] || day.toLowerCase();
        commands.push(`set schedulers scheduler ${name} ${junosDay} start-time ${sched.start} stop-time ${sched.end}`);
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
// User Identification (JIMS) — emitted when policies use source_users
// ---------------------------------------------------------------------------

function convertUserIdentification(policies, commands, warnings) {
  if (!policies || policies.length === 0) return;
  const identityPolicies = policies.filter(p => p.source_users && p.source_users.length > 0);
  if (identityPolicies.length === 0) return;

  commands.push('# =============================================');
  commands.push('# User Identification (JIMS Integration)');
  commands.push('# =============================================');
  commands.push('# NOTE: JIMS server connection details must be configured manually');
  commands.push('set services user-identification identity-management connection connect-method https');
  commands.push('set services user-identification identity-management connection port 1443');
  commands.push('# set services user-identification identity-management connection primary address <JIMS_SERVER_IP>');
  commands.push('# set services user-identification identity-management connection primary client-id <CLIENT_ID>');
  commands.push('# set services user-identification identity-management connection primary client-secret <SECRET>');
  commands.push('set services user-identification device-information authentication-source active-directory-authentication-table');
  commands.push('');

  // Document all unique identity references
  const allIdentities = new Set();
  for (const p of identityPolicies) {
    for (const id of p.source_users) allIdentities.add(id);
  }
  commands.push(`# Identity references used in ${identityPolicies.length} policies:`);
  for (const id of allIdentities) {
    commands.push(`#   - ${id}`);
  }
  commands.push('');

  warnings.push(createWarning(
    'interview_required',
    'services/user-identification',
    `${identityPolicies.length} policies use identity-based match (source_users) — JIMS server configuration required`,
    'Configure JIMS server IP, client-id, and client-secret. Ensure AD user/group names match the source firewall identities.'
  ));
}

// ---------------------------------------------------------------------------
// Security Policy Converter
// ---------------------------------------------------------------------------

function convertSecurityPolicies(policies, commands, warnings, summary, profileMaps = {}, appGroups = [], sourceVendor = '', ruleGroups = []) {
  if (!policies || policies.length === 0) return;

  const { utmPolicyMap = {}, idpPolicyMap = {}, secIntelEnabled = false } = profileMaps;

  commands.push('# =============================================');
  commands.push('# Security Policies');
  commands.push('# =============================================');

  // Build rule-index→group map for group comment insertion
  const groupByIndex = {};
  if (ruleGroups && ruleGroups.length > 0) {
    for (const g of ruleGroups) {
      for (const idx of (g.rule_indices || [])) {
        groupByIndex[idx] = g.group_name;
      }
    }
  }
  let currentGroup = null;

  // Collect deactivate commands for disabled rules (applied at the end)
  const deactivateCommands = [];

  for (let pIdx = 0; pIdx < policies.length; pIdx++) {
    const policy = policies[pIdx];
    const policyName = generateDescriptiveName(policy, pIdx);

    // Emit group comment when entering a new group (JUNOS preserves /* */ comments)
    const ruleGroup = groupByIndex[pIdx] || policy._group || null;
    if (ruleGroup && ruleGroup !== currentGroup) {
      commands.push('');
      commands.push(`/* ===== Group: ${ruleGroup} ===== */`);
      currentGroup = ruleGroup;
    }

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
        const apps = resolveApplications(policy.applications, policy.services, warnings, policyName, appGroups, sourceVendor);
        for (const app of apps) {
          commands.push(`set ${policyPath} match application ${app}`);
        }

        // Match criteria: source identity (user/group via JIMS)
        if (policy.source_users && policy.source_users.length > 0) {
          for (const identity of policy.source_users) {
            commands.push(`set ${policyPath} match source-identity "${sanitizeJunosName(identity)}"`);
          }
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

        // Count (enabled by default)
        if (policy._srx_log_count !== false) {
          commands.push(`set ${policyPath} then count`);
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

        // SSL Proxy attachment (for policies flagged by LLM or safety net)
        if (policy._srx_decrypt && policy.action === 'allow') {
          const sslProfile = policy._srx_decrypt_profile
            ? sanitizeJunosName(policy._srx_decrypt_profile)
            : 'ssl-fwd-proxy';
          commands.push(`set ${policyPath} then permit application-services ssl-proxy profile-name ${sslProfile}`);
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
 * Tracks service objects that are equivalent to predefined Junos applications.
 * Map of serviceName → junosPredefinedName (e.g., "SSH" → "junos-ssh").
 * Built during convertServiceObjects(), consumed by resolveApplications().
 */
const predefServiceMap = new Map();

/**
 * Resolves application/service fields from any vendor to SRX application names.
 *
 * For SRX→SRX conversions, applications pass through 1:1 (already Junos names).
 * For other vendors, applications are mapped via mapAppToJunos().
 * Unmapped applications get a "Customfwic" suffix and a warning is generated
 * telling the user to create a custom application definition on the SRX.
 *
 * SRX only has "application" in policy match — we unify both fields.
 */
function resolveApplications(applications, services, warnings, policyName, appGroups = [], sourceVendor = '') {
  const resolved = [];
  const isSrxSource = sourceVendor === 'srx' || sourceVendor === 'greenfield' || sourceVendor === 'srx_healthcheck';

  // Helper to map a single app name to Junos (with Customfwic fallback)
  const mapSingleApp = (appName) => {
    // SRX→SRX: pass through as-is (already a Junos application name)
    if (isSrxSource) {
      resolved.push(appName);
      return;
    }
    const junosApp = mapAppToJunos(appName, sourceVendor);
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
      // Check if this service was mapped to a predefined app during convertServiceObjects
      const predefName = predefServiceMap.get(svc);
      if (predefName) {
        resolved.push(predefName);
        continue;
      }
      // Try mapping service name (catches FortiGate "HTTP", "HTTPS", etc.)
      const junosApp = mapAppToJunos(svc, sourceVendor);
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
        const anyAddr = natAnyAddress(rule);
        for (const addr of (rule.src_addresses || [anyAddr])) {
          if (addr === 'any') {
            commands.push(`set ${rulePath} match source-address ${anyAddr}`);
          } else {
            commands.push(`set ${rulePath} match source-address ${addr}`);
          }
        }
        for (const addr of (rule.dst_addresses || [anyAddr])) {
          if (addr === 'any') {
            commands.push(`set ${rulePath} match destination-address ${anyAddr}`);
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

        // U-turn/hairpin NAT: add persistent-nat for return traffic
        if (rule._uturn) {
          commands.push(`set ${rulePath} then persistent-nat permit target-host`);
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
        const dnatAny = natAnyAddress(rule);
        for (const addr of (rule.dst_addresses || [dnatAny])) {
          if (addr === 'any') {
            commands.push(`set ${rulePath} match destination-address ${dnatAny}`);
          } else {
            commands.push(`set ${rulePath} match destination-address ${addr}`);
          }
        }
        // Port-forward matching (FortiGate VIP extport)
        if (rule.match_port) {
          commands.push(`set ${rulePath} match destination-port ${rule.match_port}`);
        }
        if (rule.match_protocol) {
          const proto = rule.match_protocol.toLowerCase();
          if (proto === 'tcp' || proto === 'udp') {
            commands.push(`set ${rulePath} match protocol ${proto}`);
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

function convertStaticRoutes(routes, commands, warnings, summary) {
  if (!routes || routes.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Static Routes');
  commands.push('# =============================================');

  for (const route of routes) {
    if (!route.destination) continue;

    const dest = route.destination;

    if (route.vrf) {
      // Routing instance
      const instName = sanitizeJunosName(route.vrf);
      if (route.next_hop_type === 'discard') {
        commands.push(`set routing-instances ${instName} routing-options static route ${dest} discard`);
      } else if (route.next_hop_type === 'next-vr' && route.next_hop) {
        commands.push(`set routing-instances ${instName} routing-options static route ${dest} next-table ${route.next_hop}.inet.0`);
      } else if (route.next_hop) {
        commands.push(`set routing-instances ${instName} routing-options static route ${dest} next-hop ${route.next_hop}`);
      }
      if (route.metric && route.metric !== 10) {
        commands.push(`set routing-instances ${instName} routing-options static route ${dest} metric ${route.metric}`);
      }
    } else {
      // Global routing-options
      if (route.next_hop_type === 'discard') {
        commands.push(`set routing-options static route ${dest} discard`);
      } else if (route.next_hop_type === 'next-vr' && route.next_hop) {
        commands.push(`set routing-options static route ${dest} next-table ${route.next_hop}.inet.0`);
      } else if (route.next_hop) {
        commands.push(`set routing-options static route ${dest} next-hop ${route.next_hop}`);
      }
      if (route.metric && route.metric !== 10) {
        commands.push(`set routing-options static route ${dest} metric ${route.metric}`);
      }
    }

    summary.static_routes_converted++;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// BGP Configuration
// ---------------------------------------------------------------------------

function convertBgpConfig(bgpConfig, commands, warnings, summary) {
  if (!bgpConfig || bgpConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# BGP Configuration');
  commands.push('# =============================================');

  for (const bgp of bgpConfig) {
    const prefix = bgp.instance
      ? `set routing-instances ${sanitizeJunosName(bgp.instance)} `
      : 'set ';

    // Autonomous system and router-id
    if (bgp.local_as) {
      commands.push(`${prefix}routing-options autonomous-system ${bgp.local_as}`);
    }
    if (bgp.router_id) {
      commands.push(`${prefix}routing-options router-id ${bgp.router_id}`);
    }

    // Peer groups and neighbors
    for (const group of bgp.peer_groups || []) {
      const gName = sanitizeJunosName(group.name);
      commands.push(`${prefix}protocols bgp group ${gName} type ${group.type || 'external'}`);

      for (const neighbor of group.neighbors || []) {
        const nBase = `${prefix}protocols bgp group ${gName} neighbor ${neighbor.address}`;
        if (neighbor.peer_as) {
          commands.push(`${nBase} peer-as ${neighbor.peer_as}`);
        }
        if (neighbor.description) {
          commands.push(`${nBase} description "${neighbor.description}"`);
        }
        if (neighbor.local_address) {
          commands.push(`${nBase} local-address ${neighbor.local_address}`);
        }
        if (neighbor.import_policy) {
          commands.push(`${nBase} import ${neighbor.import_policy}`);
        }
        if (neighbor.export_policy) {
          commands.push(`${nBase} export ${neighbor.export_policy}`);
        }
        if (neighbor.authentication_key) {
          commands.push(`${nBase} authentication-key "${neighbor.authentication_key}"`);
        }
        if (neighbor.enabled === false) {
          warnings.push(createWarning(
            'info',
            `BGP neighbor ${neighbor.address} in group ${gName} is disabled — deactivate command not generated (requires manual config)`,
            neighbor.address,
            'bgp_neighbor_disabled'
          ));
        }
        summary.bgp_neighbors_converted = (summary.bgp_neighbors_converted || 0) + 1;
      }
      summary.bgp_groups_converted = (summary.bgp_groups_converted || 0) + 1;
    }

    // Network advertisements via policy-options
    if (bgp.networks && bgp.networks.length > 0) {
      for (const net of bgp.networks) {
        if (net.policy) {
          // Reference existing policy
          commands.push(`${prefix}protocols bgp group ${bgp.peer_groups?.[0]?.name ? sanitizeJunosName(bgp.peer_groups[0].name) : 'BGP-PEERS'} export ${net.policy}`);
        }
      }
    }

    // Redistribution via policy-options
    for (const redist of bgp.redistribute || []) {
      const stmtName = `BGP-REDIST-${redist.protocol.toUpperCase()}`;
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 from protocol ${redist.protocol}`);
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then accept`);
      if (redist.policy) {
        commands.push(`# Source policy reference: ${redist.policy}`);
      }
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// OSPF Configuration
// ---------------------------------------------------------------------------

function convertOspfConfig(ospfConfig, commands, warnings, summary) {
  if (!ospfConfig || ospfConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# OSPF Configuration');
  commands.push('# =============================================');

  for (const ospf of ospfConfig) {
    const prefix = ospf.instance
      ? `set routing-instances ${sanitizeJunosName(ospf.instance)} `
      : 'set ';

    // Router-id (may overlap with BGP — SRX uses routing-options router-id for both)
    if (ospf.router_id) {
      commands.push(`${prefix}routing-options router-id ${ospf.router_id}`);
    }

    // Reference bandwidth
    if (ospf.reference_bandwidth) {
      commands.push(`${prefix}protocols ospf reference-bandwidth ${ospf.reference_bandwidth}`);
    }

    // Areas
    for (const area of ospf.areas || []) {
      const areaId = area.area_id;

      // Area type
      if (area.area_type === 'stub') {
        commands.push(`${prefix}protocols ospf area ${areaId} stub`);
      } else if (area.area_type === 'totally-stub') {
        commands.push(`${prefix}protocols ospf area ${areaId} stub no-summaries`);
      } else if (area.area_type === 'nssa') {
        commands.push(`${prefix}protocols ospf area ${areaId} nssa`);
      } else if (area.area_type === 'totally-nssa') {
        commands.push(`${prefix}protocols ospf area ${areaId} nssa no-summaries`);
      }

      // Interfaces
      for (const iface of area.interfaces || []) {
        const ifBase = `${prefix}protocols ospf area ${areaId} interface ${iface.name}`;
        commands.push(ifBase);

        if (iface.cost != null) {
          commands.push(`${ifBase} metric ${iface.cost}`);
        }
        if (iface.hello_interval != null) {
          commands.push(`${ifBase} hello-interval ${iface.hello_interval}`);
        }
        if (iface.dead_interval != null) {
          commands.push(`${ifBase} dead-interval ${iface.dead_interval}`);
        }
        if (iface.passive) {
          commands.push(`${ifBase} passive`);
        }
        if (iface.network_type) {
          commands.push(`${ifBase} interface-type ${iface.network_type}`);
        }

        // Authentication
        if (iface.authentication) {
          if (iface.authentication.type === 'md5') {
            const keyId = iface.authentication.key_id || 1;
            commands.push(`${ifBase} authentication md5 ${keyId} key "${iface.authentication.key || ''}"`);
          } else if (iface.authentication.type === 'simple') {
            commands.push(`${ifBase} authentication simple-password "${iface.authentication.key || ''}"`);
          }
        }

        summary.ospf_interfaces_converted = (summary.ospf_interfaces_converted || 0) + 1;
      }

      // Network statements (from Cisco/Huawei — converted to interface references with warning)
      for (const net of area.networks || []) {
        warnings.push(createWarning(
          'info',
          `OSPF network statement ${net.prefix} in area ${areaId} — SRX uses per-interface OSPF config. Add the appropriate interface to area ${areaId} manually.`,
          net.prefix,
          'ospf_network_to_interface'
        ));
      }

      summary.ospf_areas_converted = (summary.ospf_areas_converted || 0) + 1;
    }

    // Redistribution via export policy
    for (const redist of ospf.redistribute || []) {
      const stmtName = `OSPF-REDIST-${redist.protocol.toUpperCase()}`;
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 from protocol ${redist.protocol}`);
      if (redist.metric_type) {
        commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then external type ${redist.metric_type}`);
      }
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then accept`);
      commands.push(`${prefix}protocols ospf export ${stmtName}`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// OSPFv3 Configuration
// ---------------------------------------------------------------------------

function convertOspf3Config(ospf3Config, commands, warnings, summary) {
  if (!ospf3Config || ospf3Config.length === 0) return;

  commands.push('# =============================================');
  commands.push('# OSPFv3 (IPv6 OSPF) Configuration');
  commands.push('# =============================================');

  for (const ospf of ospf3Config) {
    const prefix = ospf.instance
      ? `set routing-instances ${sanitizeJunosName(ospf.instance)} `
      : 'set ';

    if (ospf.router_id) {
      commands.push(`${prefix}routing-options router-id ${ospf.router_id}`);
    }

    if (ospf.reference_bandwidth) {
      commands.push(`${prefix}protocols ospf3 reference-bandwidth ${ospf.reference_bandwidth}`);
    }

    for (const area of ospf.areas || []) {
      const areaId = area.area_id;

      if (area.area_type === 'stub') {
        commands.push(`${prefix}protocols ospf3 area ${areaId} stub`);
      } else if (area.area_type === 'totally-stub') {
        commands.push(`${prefix}protocols ospf3 area ${areaId} stub no-summaries`);
      } else if (area.area_type === 'nssa') {
        commands.push(`${prefix}protocols ospf3 area ${areaId} nssa`);
      } else if (area.area_type === 'totally-nssa') {
        commands.push(`${prefix}protocols ospf3 area ${areaId} nssa no-summaries`);
      }

      for (const iface of area.interfaces || []) {
        const ifBase = `${prefix}protocols ospf3 area ${areaId} interface ${iface.name}`;
        commands.push(ifBase);

        if (iface.cost != null) {
          commands.push(`${ifBase} metric ${iface.cost}`);
        }
        if (iface.hello_interval != null) {
          commands.push(`${ifBase} hello-interval ${iface.hello_interval}`);
        }
        if (iface.dead_interval != null) {
          commands.push(`${ifBase} dead-interval ${iface.dead_interval}`);
        }
        if (iface.passive) {
          commands.push(`${ifBase} passive`);
        }
        if (iface.network_type) {
          commands.push(`${ifBase} interface-type ${iface.network_type}`);
        }
        if (iface.instance_id != null) {
          commands.push(`${ifBase} instance-id ${iface.instance_id}`);
        }

        summary.ospf3_interfaces_converted = (summary.ospf3_interfaces_converted || 0) + 1;
      }

      for (const net of area.networks || []) {
        warnings.push(createWarning(
          'info',
          `OSPFv3 network statement ${net.prefix} in area ${areaId} — SRX uses per-interface OSPFv3 config. Add the appropriate interface to area ${areaId} manually.`,
          net.prefix,
          'ospf3_network_to_interface'
        ));
      }

      summary.ospf3_areas_converted = (summary.ospf3_areas_converted || 0) + 1;
    }

    for (const redist of ospf.redistribute || []) {
      const stmtName = `OSPF3-REDIST-${redist.protocol.toUpperCase()}`;
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 from protocol ${redist.protocol}`);
      if (redist.metric_type) {
        commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then external type ${redist.metric_type}`);
      }
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then accept`);
      commands.push(`${prefix}protocols ospf3 export ${stmtName}`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// EVPN Configuration
// ---------------------------------------------------------------------------

function convertEvpnConfig(evpnConfig, commands, warnings, summary) {
  if (!evpnConfig || evpnConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# EVPN / VxLAN Fabric Configuration');
  commands.push('# =============================================');

  for (const evpn of evpnConfig) {
    const prefix = evpn.instance
      ? `set routing-instances ${sanitizeJunosName(evpn.instance)} `
      : 'set ';

    // Instance type for routing-instances (mac-vrf, virtual-switch)
    if (evpn.instance && evpn.instance_type) {
      commands.push(`${prefix}instance-type ${evpn.instance_type}`);
    }

    // EVPN protocol settings
    commands.push(`${prefix}protocols evpn encapsulation ${evpn.encapsulation || 'vxlan'}`);

    if (evpn.multicast_mode) {
      commands.push(`${prefix}protocols evpn multicast-mode ${evpn.multicast_mode}`);
    }

    if (evpn.extended_vni_list && evpn.extended_vni_list.length > 0) {
      for (const vni of evpn.extended_vni_list) {
        commands.push(`${prefix}protocols evpn extended-vni-list ${vni}`);
      }
    }

    // Switch-options (global or per-instance)
    if (evpn.route_distinguisher) {
      const swPrefix = evpn.instance ? prefix : 'set ';
      commands.push(`${swPrefix}switch-options vtep-source-interface ${evpn.vtep_source_interface || 'lo0.0'}`);
      commands.push(`${swPrefix}switch-options route-distinguisher ${evpn.route_distinguisher}`);
    }

    if (evpn.vrf_target) {
      const swPrefix = evpn.instance ? prefix : 'set ';
      commands.push(`${swPrefix}switch-options vrf-target ${evpn.vrf_target}`);
    }

    // Route targets (explicit import/export)
    for (const rt of evpn.route_targets || []) {
      if (rt.direction === 'import' || rt.direction === 'both') {
        commands.push(`${prefix}vrf-import ${rt.target}`);
      }
      if (rt.direction === 'export' || rt.direction === 'both') {
        commands.push(`${prefix}vrf-export ${rt.target}`);
      }
    }

    // VLANs with VxLAN VNI mappings
    for (const vlan of evpn.vlans || []) {
      const vlanName = sanitizeJunosName(vlan.name);
      commands.push(`set vlans ${vlanName} vlan-id ${vlan.vlan_id}`);
      commands.push(`set vlans ${vlanName} vxlan vni ${vlan.vni}`);
      if (vlan.ingress_node_replication) {
        commands.push(`set vlans ${vlanName} vxlan ingress-node-replication`);
      }
      summary.evpn_vlans_converted = (summary.evpn_vlans_converted || 0) + 1;
    }

    summary.evpn_instances_converted = (summary.evpn_instances_converted || 0) + 1;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// VxLAN Configuration (standalone, non-EVPN)
// ---------------------------------------------------------------------------

function convertVxlanConfig(vxlanConfig, commands, warnings, summary) {
  if (!vxlanConfig || vxlanConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# VxLAN Tunnel Configuration');
  commands.push('# =============================================');
  commands.push('# Note: SRX typically uses EVPN for VxLAN. These are standalone VxLAN tunnels.');

  for (const tunnel of vxlanConfig) {
    const prefix = tunnel.instance
      ? `set routing-instances ${sanitizeJunosName(tunnel.instance)} `
      : 'set ';

    // VTEP source interface
    if (tunnel.vtep_source_interface || tunnel.source_interface) {
      commands.push(`${prefix}switch-options vtep-source-interface ${tunnel.vtep_source_interface || tunnel.source_interface}`);
    }

    // VNI entries
    for (const vni of tunnel.vnis || []) {
      const vniId = vni.vni;
      commands.push(`# VxLAN VNI ${vniId}${tunnel.name ? ` (source: ${tunnel.name})` : ''}`);

      if (vni.vlan_id) {
        commands.push(`set vlans VXLAN-${vniId} vlan-id ${vni.vlan_id}`);
        commands.push(`set vlans VXLAN-${vniId} vxlan vni ${vniId}`);
      }

      if (vni.ingress_replication) {
        commands.push(`set vlans VXLAN-${vniId} vxlan ingress-node-replication`);
      }

      // Static remote VTEPs (flood list)
      for (const vtep of vni.remote_vteps || []) {
        warnings.push(createWarning(
          'info',
          `VxLAN VNI ${vniId} has static remote VTEP ${vtep}. SRX EVPN uses BGP for VTEP discovery — consider migrating to EVPN.`,
          tunnel.name || `VNI-${vniId}`,
          'vxlan_static_vtep'
        ));
      }
    }

    // UDP port
    if (tunnel.udp_port && tunnel.udp_port !== 4789) {
      warnings.push(createWarning(
        'info',
        `VxLAN tunnel ${tunnel.name || ''} uses non-standard UDP port ${tunnel.udp_port} (default: 4789). SRX uses standard port 4789.`,
        tunnel.name || 'vxlan',
        'vxlan_nonstandard_port'
      ));
    }

    summary.vxlan_tunnels_converted = (summary.vxlan_tunnels_converted || 0) + 1;
  }

  commands.push('');
}

/**
 * Converts HA configuration to SRX chassis cluster or MNHA set commands.
 */
function convertHaConfig(haConfig, commands, warnings, summary) {
  if (!haConfig || !haConfig.enabled) return;

  if (haConfig.ha_type === 'mnha') {
    convertMnhaConfig(haConfig, commands, warnings, summary);
    return;
  }

  commands.push('# =============================================');
  commands.push('# Chassis Cluster / HA Configuration');
  commands.push('# =============================================');
  commands.push(`# Source HA: ${haConfig.description || haConfig.mode}`);

  const clusterId = haConfig.group_id || 1;

  // Chassis cluster setup
  commands.push(`set chassis cluster cluster-id ${clusterId}`);

  // Redundancy group 0 (control plane) — always needed
  commands.push(`set chassis cluster redundancy-group 0 node 0 priority ${haConfig.priority || 200}`);
  const secondaryPrio = (haConfig.priority || 200) > 100 ? 100 : (haConfig.priority || 200) - 1;
  commands.push(`set chassis cluster redundancy-group 0 node 1 priority ${secondaryPrio}`);

  // Redundancy group 1 (data plane) — mirrors RG0 priorities
  commands.push(`set chassis cluster redundancy-group 1 node 0 priority ${haConfig.priority || 200}`);
  commands.push(`set chassis cluster redundancy-group 1 node 1 priority ${secondaryPrio}`);

  if (haConfig.preempt) {
    commands.push('set chassis cluster redundancy-group 0 preempt');
    commands.push('set chassis cluster redundancy-group 1 preempt');
  }

  // Heartbeat interval
  commands.push('set chassis cluster heartbeat-interval 1000');
  commands.push('set chassis cluster heartbeat-threshold 3');

  // HA interfaces — map to SRX fabric and control links
  for (const iface of haConfig.ha_interfaces) {
    const name = (iface.name || '').toLowerCase();
    if (name === 'fab0' || name === 'fab1' || name.includes('fabric')) {
      if (iface.interface) {
        commands.push(`set interfaces ${name.startsWith('fab') ? name : 'fab0'} fabric-options member-interfaces ${iface.interface}`);
      }
    } else if (name.includes('ha1') || name.includes('heartbeat') || name.includes('failover') || name.includes('control')) {
      // Map to SRX control-link (fxp1) — add as comment since fxp1 is implicit
      commands.push(`# Source HA control link: ${iface.name} on ${iface.interface || 'N/A'} (${iface.ip || 'no IP'})`);
    } else if (name.includes('ha2') || name.includes('state') || name.includes('stateful')) {
      commands.push(`# Source HA data link: ${iface.name} on ${iface.interface || 'N/A'} (${iface.ip || 'no IP'})`);
    } else if (iface.interface) {
      commands.push(`# Source HA interface: ${iface.name} on ${iface.interface} (${iface.ip || 'no IP'})`);
    }
  }

  // Monitoring
  if (haConfig.monitoring) {
    for (const lg of (haConfig.monitoring.link_groups || [])) {
      if (lg.interfaces && lg.interfaces.length > 0) {
        commands.push(`# Source link monitoring group "${lg.name}": ${lg.interfaces.join(', ')}`);
      }
    }
  }

  commands.push('# NOTE: Review chassis cluster config — verify fabric interfaces, reth interfaces,');
  commands.push('# and redundancy-group assignments match your target SRX hardware topology');

  warnings.push(createWarning('ha', 'HA converted to chassis cluster — verify fabric/reth mappings for target hardware', 'info'));
  summary.ha_converted = 1;
  commands.push('');
}

/**
 * Builds the list of MNHA peers from haConfig for 2-, 3-, or 4-node topologies.
 * For 2-node: uses legacy peer_id/peer_ip fields or additional_peers[0].
 * For 3/4-node: uses additional_peers array for all peers beyond the first.
 * @param {Object} haConfig - HA configuration object
 * @param {number} nodeCount - Total node count (2, 3, or 4)
 * @returns {Array<Object>} Array of peer objects with peer_id, peer_ip, icl_interface, vpn_profile, etc.
 */
function buildMnhaPeerList(haConfig, nodeCount) {
  const peers = [];
  const additionalPeers = haConfig.additional_peers || [];

  // First peer — always from top-level fields (backward compatible with 2-node)
  peers.push({
    peer_id: haConfig.peer_id || 2,
    peer_ip: haConfig.peer_ip || '',
    icl_interface: haConfig.icl_interface || '',
    vpn_profile: haConfig.vpn_profile || 'IPSEC_VPN_ICL',
    liveness_interval: haConfig.liveness_interval || 400,
    liveness_multiplier: haConfig.liveness_multiplier || 5,
    deployment_type: haConfig.deployment_type || 'routing',
    activeness_priority: haConfig.activeness_priority || 200,
    preemption: haConfig.preemption,
  });

  // Additional peers for 3-node and 4-node
  for (let i = 0; i < nodeCount - 2; i++) {
    const extra = additionalPeers[i] || {};
    peers.push({
      peer_id: extra.peer_id || (3 + i),
      peer_ip: extra.peer_ip || '',
      icl_interface: extra.icl_interface || '',
      vpn_profile: extra.vpn_profile || 'IPSEC_VPN_ICL',
      liveness_interval: extra.liveness_interval || haConfig.liveness_interval || 400,
      liveness_multiplier: extra.liveness_multiplier || haConfig.liveness_multiplier || 5,
      deployment_type: extra.deployment_type || haConfig.deployment_type || 'routing',
      activeness_priority: extra.activeness_priority || Math.max(100, (haConfig.activeness_priority || 200) - (50 * (i + 1))),
      preemption: extra.preemption ?? haConfig.preemption,
    });
  }

  return peers;
}

/**
 * Converts MNHA (Multinode High Availability) configuration to SRX set commands.
 * Uses `set chassis high-availability` instead of `set chassis cluster`.
 * Supports 2-node, 3-node, and 4-node MNHA topologies.
 */
function convertMnhaConfig(haConfig, commands, warnings, summary) {
  const nodeCount = haConfig.node_count || 2;
  commands.push('# =============================================');
  commands.push(`# Multinode High Availability (MNHA) — ${nodeCount}-Node Configuration`);
  commands.push('# =============================================');
  commands.push(`# ${haConfig.description || 'MNHA ' + (haConfig.mode || 'active-passive')}`);

  const localId = haConfig.local_id || 1;
  const prefix = 'set chassis high-availability';

  // Local node
  commands.push(`${prefix} local-id ${localId}`);
  if (haConfig.local_ip) {
    commands.push(`${prefix} local-id local-ip ${haConfig.local_ip}`);
  }

  // Build list of all peers (supports 2-, 3-, and 4-node topologies)
  const peers = buildMnhaPeerList(haConfig, nodeCount);

  for (const peer of peers) {
    // Peer node identity
    if (peer.peer_ip) {
      commands.push(`${prefix} peer-id ${peer.peer_id} peer-ip ${peer.peer_ip}`);
    }
    if (peer.icl_interface) {
      commands.push(`${prefix} peer-id ${peer.peer_id} interface ${peer.icl_interface}`);
    }
    if (peer.vpn_profile) {
      commands.push(`${prefix} peer-id ${peer.peer_id} vpn-profile ${peer.vpn_profile}`);
    }

    // Liveness detection per peer
    const livenessInterval = peer.liveness_interval || haConfig.liveness_interval || 400;
    const livenessMultiplier = peer.liveness_multiplier || haConfig.liveness_multiplier || 5;
    commands.push(`${prefix} peer-id ${peer.peer_id} liveness-detection minimum-interval ${livenessInterval}`);
    commands.push(`${prefix} peer-id ${peer.peer_id} liveness-detection multiplier ${livenessMultiplier}`);

    // SRG0 (control plane) — associate each peer
    commands.push(`${prefix} services-redundancy-group 0 peer-id ${peer.peer_id}`);

    // SRG1 (data plane) — associate each peer
    const deployType = peer.deployment_type || haConfig.deployment_type || 'routing';
    commands.push(`${prefix} services-redundancy-group 1 deployment-type ${deployType}`);
    commands.push(`${prefix} services-redundancy-group 1 peer-id ${peer.peer_id}`);

    const activePrio = peer.activeness_priority || haConfig.activeness_priority || 200;
    commands.push(`${prefix} services-redundancy-group 1 activeness-priority ${activePrio}`);

    if (peer.preemption ?? haConfig.preemption) {
      commands.push(`${prefix} services-redundancy-group 1 preemption`);
    }
  }

  // Monitoring (applies to all peers)
  if (haConfig.monitoring) {
    for (const lg of (haConfig.monitoring.link_groups || [])) {
      if (lg.enabled && lg.interfaces && lg.interfaces.length > 0) {
        for (const iface of lg.interfaces) {
          commands.push(`${prefix} services-redundancy-group 1 interface-monitor ${iface} weight 255`);
        }
      }
    }
  }

  if (nodeCount > 2) {
    commands.push(`# NOTE: ${nodeCount}-node MNHA requires full mesh ICL connectivity between all nodes.`);
    commands.push('# Ensure each node has dedicated ICL interfaces to every other peer.');
  }
  commands.push('# NOTE: Review MNHA config — verify ICL interface, VPN profile, and virtual-IP');
  commands.push('# assignments match your target SRX4700 topology');

  warnings.push(createWarning('ha', `${nodeCount}-node MNHA configured — verify ICL, VPN profile, and SRG settings for target topology`, 'info'));
  summary.ha_converted = 1;
  summary.mnha_node_count = nodeCount;
  commands.push('');
}

/**
 * Converts screen/DDoS protection configuration to SRX screen ids-option set commands.
 */
function convertScreenConfig(screens, commands, warnings, summary) {
  if (!screens || screens.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Security Screen (IDS Options)');
  commands.push('# =============================================');

  for (const screen of screens) {
    const name = sanitizeJunosName(screen.name || 'default-screen');
    const prefix = `set security screen ids-option ${name}`;

    // ICMP protections
    if (screen.icmp) {
      if (screen.icmp.ping_death) commands.push(`${prefix} icmp ping-death`);
      if (screen.icmp.fragment) commands.push(`${prefix} icmp fragment`);
      if (screen.icmp.flood_threshold) commands.push(`${prefix} icmp flood threshold ${screen.icmp.flood_threshold}`);
    }

    // TCP protections
    if (screen.tcp) {
      if (screen.tcp.syn_flood_threshold) {
        const alarmVal = screen.tcp.syn_flood_alarm_threshold || Math.round(screen.tcp.syn_flood_threshold * 5) || 1024;
        commands.push(`${prefix} tcp syn-flood alarm-threshold ${alarmVal}`);
        commands.push(`${prefix} tcp syn-flood attack-threshold ${screen.tcp.syn_flood_threshold}`);
      }
      if (screen.tcp.syn_flood_timeout) commands.push(`${prefix} tcp syn-flood timeout ${screen.tcp.syn_flood_timeout}`);
      if (screen.tcp.land_attack) commands.push(`${prefix} tcp land`);
      if (screen.tcp.winnuke) commands.push(`${prefix} tcp winnuke`);
      if (screen.tcp.tcp_no_flag) commands.push(`${prefix} tcp tcp-no-flag`);
    }

    // UDP protections
    if (screen.udp && screen.udp.flood_threshold) {
      commands.push(`${prefix} udp flood threshold ${screen.udp.flood_threshold}`);
    }

    // IP protections
    if (screen.ip) {
      if (screen.ip.spoofing) commands.push(`${prefix} ip spoofing`);
      if (screen.ip.source_route) commands.push(`${prefix} ip source-route-option`);
      if (screen.ip.tear_drop) commands.push(`${prefix} ip tear-drop`);
      if (screen.ip.record_route) commands.push(`${prefix} ip record-route-option`);
      if (screen.ip.timestamp) commands.push(`${prefix} ip timestamp-option`);
    }

    // Session limits
    if (screen.limit_session) {
      if (screen.limit_session.source_based) commands.push(`${prefix} limit-session source-ip-based ${screen.limit_session.source_based}`);
      if (screen.limit_session.destination_based) commands.push(`${prefix} limit-session destination-ip-based ${screen.limit_session.destination_based}`);
    }

    // Apply screen to zone if known
    if (screen.zone) {
      commands.push(`set security zones security-zone ${sanitizeJunosName(screen.zone)} screen ${name}`);
    }

    summary.screens_converted = (summary.screens_converted || 0) + 1;
  }

  commands.push('');
}

/**
 * Converts VPN/IPsec tunnel configuration to SRX set commands.
 */
/**
 * Maps common authentication algorithm names to valid Junos IKE/IPsec identifiers.
 * @param {string} algo - The source authentication algorithm name
 * @returns {string} Valid Junos authentication-algorithm value
 */
function mapAuthAlgorithm(algo) {
  const map = {
    'sha256': 'hmac-sha-256-128',
    'sha-256': 'hmac-sha-256-128',
    'sha1': 'hmac-sha1-96',
    'sha-1': 'hmac-sha1-96',
    'sha384': 'hmac-sha-384',
    'sha-384': 'hmac-sha-384',
    'sha512': 'hmac-sha-512',
    'sha-512': 'hmac-sha-512',
    'md5': 'hmac-md5-96',
  };
  return map[algo.toLowerCase()] || algo;
}

function convertVpnTunnels(tunnels, commands, warnings, summary) {
  if (!tunnels || tunnels.length === 0) return;

  commands.push('# =============================================');
  commands.push('# VPN / IPsec Configuration');
  commands.push('# =============================================');

  const emittedProposals = new Set();
  const emittedPolicies = new Set();
  const emittedGateways = new Set();

  for (const vpn of tunnels) {
    const vpnName = sanitizeJunosName(vpn.name || 'vpn-1');

    // IKE Proposal
    if (vpn.ike_proposal && !emittedProposals.has(vpn.ike_proposal.name)) {
      const propName = sanitizeJunosName(vpn.ike_proposal.name || `ike-prop-${vpnName}`);
      emittedProposals.add(vpn.ike_proposal.name);
      commands.push(`set security ike proposal ${propName} authentication-method ${vpn.ike_proposal.auth_method || 'pre-shared-keys'}`);
      commands.push(`set security ike proposal ${propName} dh-group ${vpn.ike_proposal.dh_group || 'group14'}`);
      commands.push(`set security ike proposal ${propName} encryption-algorithm ${vpn.ike_proposal.encryption || 'aes-256-cbc'}`);
      commands.push(`set security ike proposal ${propName} authentication-algorithm ${mapAuthAlgorithm(vpn.ike_proposal.authentication || 'sha-256')}`);
      if (vpn.ike_proposal.lifetime) {
        commands.push(`set security ike proposal ${propName} lifetime-seconds ${vpn.ike_proposal.lifetime}`);
      }
    }

    // IKE Policy
    const polName = sanitizeJunosName(`ike-pol-${vpnName}`);
    if (!emittedPolicies.has(polName)) {
      emittedPolicies.add(polName);
      const propRef = sanitizeJunosName(vpn.ike_proposal?.name || `ike-prop-${vpnName}`);
      commands.push(`set security ike policy ${polName} proposals ${propRef}`);
      commands.push(`set security ike policy ${polName} pre-shared-key ascii-text "CHANGE-ME"`);
    }

    // IKE Gateway
    const gwName = sanitizeJunosName(vpn.ike_gateway?.name || `gw-${vpnName}`);
    if (!emittedGateways.has(gwName)) {
      emittedGateways.add(gwName);
      if (vpn.ike_gateway?.address) {
        commands.push(`set security ike gateway ${gwName} address ${vpn.ike_gateway.address}`);
      }
      commands.push(`set security ike gateway ${gwName} ike-policy ${polName}`);
      if (vpn.ike_gateway?.local_address) {
        const extIf = vpn.ike_gateway.local_address.includes('.') && !vpn.ike_gateway.local_address.includes('/') ? vpn.ike_gateway.local_address : 'ge-0/0/0.0';
        commands.push(`set security ike gateway ${gwName} external-interface ${extIf}`);
      }
      if (vpn.ike_gateway?.ike_version === 'v2') {
        commands.push(`set security ike gateway ${gwName} version v2-only`);
      }
    }

    // IPsec Proposal
    if (vpn.ipsec_proposal && !emittedProposals.has('ipsec-' + vpn.ipsec_proposal.name)) {
      const ipropName = sanitizeJunosName(vpn.ipsec_proposal.name || `ipsec-prop-${vpnName}`);
      emittedProposals.add('ipsec-' + vpn.ipsec_proposal.name);
      commands.push(`set security ipsec proposal ${ipropName} protocol ${vpn.ipsec_proposal.protocol || 'esp'}`);
      commands.push(`set security ipsec proposal ${ipropName} encryption-algorithm ${vpn.ipsec_proposal.encryption || 'aes-256-cbc'}`);
      commands.push(`set security ipsec proposal ${ipropName} authentication-algorithm ${mapAuthAlgorithm(vpn.ipsec_proposal.authentication || 'hmac-sha-256-128')}`);
      if (vpn.ipsec_proposal.lifetime) {
        commands.push(`set security ipsec proposal ${ipropName} lifetime-seconds ${vpn.ipsec_proposal.lifetime}`);
      }
    }

    // IPsec Policy
    const ipsecPolName = sanitizeJunosName(`ipsec-pol-${vpnName}`);
    const ipropRef = sanitizeJunosName(vpn.ipsec_proposal?.name || `ipsec-prop-${vpnName}`);
    commands.push(`set security ipsec policy ${ipsecPolName} proposals ${ipropRef}`);
    if (vpn.ipsec_proposal?.pfs_group) {
      commands.push(`set security ipsec policy ${ipsecPolName} perfect-forward-secrecy keys ${vpn.ipsec_proposal.pfs_group}`);
    }

    // IPsec VPN
    commands.push(`set security ipsec vpn ${vpnName} ike gateway ${gwName}`);
    commands.push(`set security ipsec vpn ${vpnName} ike ipsec-policy ${ipsecPolName}`);
    if (vpn.tunnel_interface) {
      const bindIf = vpn.tunnel_interface.startsWith('st0') ? vpn.tunnel_interface : 'st0.0';
      commands.push(`set security ipsec vpn ${vpnName} bind-interface ${bindIf}`);
    }

    // Traffic selectors / Proxy IDs
    if (vpn.proxy_id && vpn.proxy_id.length > 0) {
      for (let i = 0; i < vpn.proxy_id.length; i++) {
        const pid = vpn.proxy_id[i];
        const tsName = `ts${i + 1}`;
        if (pid.local) commands.push(`set security ipsec vpn ${vpnName} traffic-selector ${tsName} local-ip ${pid.local}`);
        if (pid.remote) commands.push(`set security ipsec vpn ${vpnName} traffic-selector ${tsName} remote-ip ${pid.remote}`);
      }
    }

    summary.vpn_tunnels_converted = (summary.vpn_tunnels_converted || 0) + 1;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Syslog Configuration Converter
// ---------------------------------------------------------------------------

function convertSyslogConfig(syslogConfig, commands, warnings, summary) {
  if (!syslogConfig || syslogConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Syslog / Logging Configuration');
  commands.push('# =============================================');

  for (const srv of syslogConfig) {
    if (!srv.server || srv.transport === 'file') continue;

    const host = srv.server;
    commands.push(`set system syslog host ${host} any any`);

    if (srv.port && srv.port !== 514) {
      commands.push(`set system syslog host ${host} port ${srv.port}`);
    }

    if (srv.transport === 'tcp' || srv.transport === 'tls') {
      commands.push(`set system syslog host ${host} transport protocol tcp`);
    }

    if (srv.source_address) {
      commands.push(`set system syslog host ${host} source-address ${srv.source_address}`);
    }

    if (srv.structured_data) {
      commands.push(`set system syslog host ${host} structured-data`);
    }

    // Facility-specific entries
    if (srv.facilities && srv.facilities.length > 0) {
      for (const fac of srv.facilities) {
        commands.push(`set system syslog host ${host} ${fac.facility} ${fac.level}`);
      }
    }

    summary.syslog_servers_converted = (summary.syslog_servers_converted || 0) + 1;
  }

  commands.push('');
}


// ---------------------------------------------------------------------------
// DHCP Configuration Converter
// ---------------------------------------------------------------------------

function convertDhcpConfig(dhcpConfig, commands, warnings, summary) {
  if (!dhcpConfig || dhcpConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# DHCP Configuration');
  commands.push('# =============================================');

  for (const cfg of dhcpConfig) {
    if (cfg.type === 'relay') {
      // DHCP Relay: set forwarding-options helpers bootp interface <if> server <ip>
      const iface = cfg.interface || 'ge-0/0/0.0';
      const servers = cfg.servers || [];
      for (const srv of servers) {
        commands.push(`set forwarding-options helpers bootp interface ${iface} server ${srv}`);
      }
      summary.dhcp_configs_converted = (summary.dhcp_configs_converted || 0) + 1;
    } else if (cfg.type === 'server' || cfg.type === 'pool') {
      // DHCP Server pool
      const poolName = sanitizeJunosName(cfg.name || cfg.interface || 'dhcp-pool');

      if (cfg.pools) {
        for (let i = 0; i < cfg.pools.length; i++) {
          const pool = cfg.pools[i];
          if (pool.includes('-')) {
            const [low, high] = pool.split('-');
            commands.push(`set access address-assignment pool ${poolName} family inet range range${i + 1} low ${low}`);
            commands.push(`set access address-assignment pool ${poolName} family inet range range${i + 1} high ${high}`);
          }
        }
      }

      if (cfg.ranges) {
        for (const range of cfg.ranges) {
          const rName = sanitizeJunosName(range.name || 'range1');
          if (range.low) commands.push(`set access address-assignment pool ${poolName} family inet range ${rName} low ${range.low}`);
          if (range.high) commands.push(`set access address-assignment pool ${poolName} family inet range ${rName} high ${range.high}`);
        }
      }

      if (cfg.network) {
        commands.push(`set access address-assignment pool ${poolName} family inet network ${cfg.network}`);
      }

      if (cfg.gateway || cfg.router) {
        commands.push(`set access address-assignment pool ${poolName} family inet dhcp-attributes router ${cfg.gateway || cfg.router}`);
      }

      const dnsServers = cfg.dns_servers || [];
      for (const dns of dnsServers) {
        commands.push(`set access address-assignment pool ${poolName} family inet dhcp-attributes name-server ${dns}`);
      }

      if (cfg.lease_time && cfg.lease_time !== 86400) {
        commands.push(`set access address-assignment pool ${poolName} family inet dhcp-attributes maximum-lease-time ${cfg.lease_time}`);
      }

      if (cfg.interfaces || cfg.interface) {
        const ifList = cfg.interfaces || [cfg.interface];
        for (const iface of ifList.filter(Boolean)) {
          commands.push(`set system services dhcp-local-server group ${poolName} interface ${iface}`);
        }
      }

      summary.dhcp_configs_converted = (summary.dhcp_configs_converted || 0) + 1;
    }
  }

  commands.push('');
}


// ---------------------------------------------------------------------------
// QoS / CoS Configuration Converter
// ---------------------------------------------------------------------------

function convertQosConfig(qosConfig, commands, warnings, summary) {
  if (!qosConfig || qosConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# QoS / Class-of-Service Configuration');
  commands.push('# =============================================');

  for (const qos of qosConfig) {
    if (qos.type === 'scheduler') {
      // SRX CoS scheduler
      const name = sanitizeJunosName(qos.name);
      if (qos.transmit_rate) commands.push(`set class-of-service schedulers ${name} transmit-rate ${qos.transmit_rate}`);
      if (qos.buffer_size) commands.push(`set class-of-service schedulers ${name} buffer-size ${qos.buffer_size}`);
      if (qos.priority) commands.push(`set class-of-service schedulers ${name} priority ${qos.priority}`);
      summary.qos_configs_converted = (summary.qos_configs_converted || 0) + 1;
    } else if (qos.type === 'interface-cos') {
      // Interface CoS binding
      const ifName = qos.interface || 'ge-0/0/0';
      if (qos.scheduler_map) commands.push(`set class-of-service interfaces ${ifName} scheduler-map ${sanitizeJunosName(qos.scheduler_map)}`);
      if (qos.shaping_rate) commands.push(`set class-of-service interfaces ${ifName} shaping-rate ${qos.shaping_rate}`);
      summary.qos_configs_converted = (summary.qos_configs_converted || 0) + 1;
    } else if (qos.type === 'shaping-profile' || qos.type === 'policy-map') {
      // Generic QoS from FortiGate/Cisco — map to CoS scheduler-map
      const name = sanitizeJunosName(qos.name);
      const classes = qos.classes || [];
      if (classes.length > 0) {
        commands.push(`set class-of-service scheduler-maps ${name}`);
        for (const cls of classes) {
          const clsName = sanitizeJunosName(cls.name || 'default');
          if (cls.guaranteed_bandwidth) {
            commands.push(`set class-of-service schedulers ${clsName} transmit-rate percent ${cls.guaranteed_bandwidth}`);
          }
          if (cls.maximum_bandwidth) {
            commands.push(`set class-of-service schedulers ${clsName} transmit-rate percent ${cls.maximum_bandwidth} exact`);
          }
          if (cls.priority === true || cls.priority === 'high') {
            commands.push(`set class-of-service schedulers ${clsName} priority high`);
          }
          if (cls.police_rate) {
            commands.push(`set class-of-service schedulers ${clsName} transmit-rate ${cls.police_rate}`);
          }
          commands.push(`set class-of-service scheduler-maps ${name} forwarding-class ${clsName} scheduler ${clsName}`);
        }
      }
      if (qos.interface) {
        commands.push(`set class-of-service interfaces ${qos.interface} scheduler-map ${name}`);
      }
      summary.qos_configs_converted = (summary.qos_configs_converted || 0) + 1;
    } else {
      // Max bandwidth style (PAN-OS)
      const name = sanitizeJunosName(qos.name);
      if (qos.max_bandwidth) {
        commands.push(`# QoS profile "${qos.name}" — max-bandwidth: ${qos.max_bandwidth}`);
        commands.push(`set class-of-service scheduler-maps ${name}`);
      }
      const classes = qos.classes || [];
      for (const cls of classes) {
        const clsName = sanitizeJunosName(cls.name || 'default');
        if (cls.guaranteed_bandwidth) {
          commands.push(`set class-of-service schedulers ${clsName} transmit-rate ${cls.guaranteed_bandwidth}`);
        }
        if (cls.maximum_bandwidth) {
          commands.push(`set class-of-service schedulers ${clsName} transmit-rate ${cls.maximum_bandwidth}`);
        }
        if (cls.priority) {
          commands.push(`set class-of-service schedulers ${clsName} priority ${cls.priority}`);
        }
        commands.push(`set class-of-service scheduler-maps ${name} forwarding-class ${clsName} scheduler ${clsName}`);
      }
      summary.qos_configs_converted = (summary.qos_configs_converted || 0) + 1;
    }
  }

  commands.push('');
}


// ---------------------------------------------------------------------------
// L2 / Bridge Domain / Virtual-Wire Configuration
// ---------------------------------------------------------------------------

/**
 * Generates SRX bridge-domain and L2 interface (family bridge) commands.
 *
 * Maps:
 *   - bridge_domains → set bridge-domains <name> domain-type bridge, vlan-id, routing-interface
 *   - l2_interfaces → set interfaces <base> unit <n> family bridge [bridge-domain-name] [vlan-id]
 *   - vwire_pairs → bridge-domain mapping with TODO comments (SRX has no direct vwire equivalent)
 */
function convertL2Config(config, commands, warnings, summary, interfaceMappings = {}) {
  const bridgeDomains = config.bridge_domains || [];
  const l2Interfaces = config.l2_interfaces || [];
  const vwirePairs = config.vwire_pairs || [];
  const transparentMode = config.transparent_mode || false;

  if (bridgeDomains.length === 0 && l2Interfaces.length === 0 && vwirePairs.length === 0 && !transparentMode) {
    return;
  }

  commands.push('# =============================================');
  commands.push('# L2 / Bridge Domain Configuration');
  commands.push('# =============================================');

  if (transparentMode) {
    commands.push('# Source firewall was in transparent/L2 mode');
    commands.push('# SRX equivalent: bridge-domains with family bridge interfaces');
    commands.push('');
  }

  // Bridge domains
  for (const bd of bridgeDomains) {
    const bdName = sanitizeJunosName(bd.name);
    commands.push(`set bridge-domains ${bdName} domain-type bridge`);
    if (bd.vlan_id) {
      commands.push(`set bridge-domains ${bdName} vlan-id ${bd.vlan_id}`);
    }
    if (bd.irb_interface) {
      commands.push(`set bridge-domains ${bdName} routing-interface ${bd.irb_interface}`);
    }
    summary.bridge_domains_converted = (summary.bridge_domains_converted || 0) + 1;
  }

  if (bridgeDomains.length > 0) commands.push('');

  // L2 interfaces — set family bridge
  for (const l2if of l2Interfaces) {
    const parts = l2if.name.match(/^(.+?)\.(\d+)$/);
    if (parts) {
      const [, base, unit] = parts;
      commands.push(`set interfaces ${base} unit ${unit} family bridge`);
      if (l2if.bridge_domain) {
        commands.push(`set interfaces ${base} unit ${unit} family bridge bridge-domain-name ${sanitizeJunosName(l2if.bridge_domain)}`);
      }
      if (l2if.vlan) {
        commands.push(`set interfaces ${base} unit ${unit} vlan-id ${l2if.vlan}`);
      }
    } else {
      // No unit specified — default to unit 0
      const base = l2if.name;
      commands.push(`set interfaces ${base} unit 0 family bridge`);
      if (l2if.bridge_domain) {
        commands.push(`set interfaces ${base} unit 0 family bridge bridge-domain-name ${sanitizeJunosName(l2if.bridge_domain)}`);
      }
    }
    summary.l2_interfaces_converted = (summary.l2_interfaces_converted || 0) + 1;
  }

  if (l2Interfaces.length > 0) commands.push('');

  // Virtual-wire pairs — SRX has no direct equivalent; map to bridge-domain
  for (const vw of vwirePairs) {
    const bdName = sanitizeJunosName(`vwire-${vw.name}`);
    commands.push(`# Virtual-wire pair "${vw.name}": ${vw.interface1} <-> ${vw.interface2}`);
    commands.push(`set bridge-domains ${bdName} domain-type bridge`);

    // Resolve mapped SRX interfaces
    const srxIf1 = mapInterfaceName(vw.interface1, interfaceMappings);
    const srxIf2 = mapInterfaceName(vw.interface2, interfaceMappings);
    const resolved1 = srxIf1 !== (vw.interface1.includes('.') ? vw.interface1 : `${vw.interface1}.0`);
    const resolved2 = srxIf2 !== (vw.interface2.includes('.') ? vw.interface2 : `${vw.interface2}.0`);

    if (vw.tag_allowed && vw.tag_allowed.length > 1) {
      // Multiple VLANs — trunk mode
      commands.push(`set bridge-domains ${bdName} vlan-id-list ${vw.tag_allowed.join(' ')}`);
      if (resolved1) {
        const [base1, unit1] = srxIf1.split('.');
        commands.push(`set interfaces ${base1} unit ${unit1 || 0} family bridge interface-mode trunk`);
        commands.push(`set interfaces ${base1} unit ${unit1 || 0} family bridge vlan-id-list ${vw.tag_allowed.join(' ')}`);
      }
      if (resolved2) {
        const [base2, unit2] = srxIf2.split('.');
        commands.push(`set interfaces ${base2} unit ${unit2 || 0} family bridge interface-mode trunk`);
        commands.push(`set interfaces ${base2} unit ${unit2 || 0} family bridge vlan-id-list ${vw.tag_allowed.join(' ')}`);
      }
    } else {
      // Single or no VLAN — access mode with bridge-domain-name
      if (vw.tag_allowed && vw.tag_allowed.length === 1 && vw.tag_allowed[0] !== '0') {
        commands.push(`set bridge-domains ${bdName} vlan-id ${vw.tag_allowed[0]}`);
      }
      if (resolved1) {
        const [base1, unit1] = srxIf1.split('.');
        commands.push(`set interfaces ${base1} unit ${unit1 || 0} family bridge bridge-domain-name ${bdName}`);
      }
      if (resolved2) {
        const [base2, unit2] = srxIf2.split('.');
        commands.push(`set interfaces ${base2} unit ${unit2 || 0} family bridge bridge-domain-name ${bdName}`);
      }
    }

    if (resolved1 && resolved2) {
      warnings.push(createWarning(
        'info', `l2/vwire/${vw.name}`,
        `Virtual-wire pair "${vw.name}" mapped to bridge-domain ${bdName} with interfaces ${srxIf1} and ${srxIf2}`,
        'Verify bridge-domain configuration after deployment'
      ));
    } else {
      const unresolved = [];
      if (!resolved1) unresolved.push(vw.interface1);
      if (!resolved2) unresolved.push(vw.interface2);
      commands.push(`# NOTE: Could not resolve interface(s): ${unresolved.join(', ')} — map them in Interface Mapper`);
      warnings.push(createWarning(
        'warning', `l2/vwire/${vw.name}`,
        `Virtual-wire pair "${vw.name}": interface(s) ${unresolved.join(', ')} not mapped — assign in Interface Mapper`,
        'Open Interface Mapper and assign SRX ports for the unmapped interfaces'
      ));
    }
    commands.push('');

    summary.vwire_pairs_converted = (summary.vwire_pairs_converted || 0) + 1;
  }

  commands.push('');
}


// ---------------------------------------------------------------------------
// Policy-Based Forwarding → Filter-Based Forwarding
// ---------------------------------------------------------------------------

/**
 * Converts PBF rules to SRX filter-based forwarding configuration.
 *
 * For each PBF "forward" rule with a next-hop:
 *   1. Creates a routing-instance of type forwarding with a default route to the next-hop
 *   2. Creates a firewall filter term matching the rule's criteria
 *   3. Binds the filter to the from-interface(s)
 *
 * Discard rules → firewall filter term with "then discard"
 * No-PBF rules → firewall filter term with "then accept" (default routing)
 */
function convertPbfConfig(pbfRules, commands, warnings, summary, interfaceMappings = {}, addressObjects = []) {
  if (!pbfRules || pbfRules.length === 0) return;

  // Build lookup map from address object names to their IP values
  const addrLookup = new Map();
  for (const obj of (addressObjects || [])) {
    if (obj.name && obj.value && (obj.type === 'host' || obj.type === 'subnet')) {
      addrLookup.set(obj.name, obj.value);
      addrLookup.set(sanitizeJunosName(obj.name), obj.value);
    }
  }

  commands.push('# =============================================');
  commands.push('# Policy-Based Forwarding (Filter-Based Forwarding)');
  commands.push('# =============================================');

  // 1. Collect unique forwarding routing-instances per next-hop
  const instances = new Map(); // next-hop → instance name
  for (const rule of pbfRules) {
    if (rule.disabled) continue;
    if (rule.action === 'forward' && rule.next_hop_value) {
      const key = rule.next_hop_value;
      if (!instances.has(key)) {
        instances.set(key, sanitizeJunosName(`PBF-${rule.name}`));
      }
    }
  }

  // Emit routing instances
  for (const [nextHop, instName] of instances) {
    commands.push(`set routing-instances ${instName} instance-type forwarding`);
    // Determine IPv4 vs IPv6 default route
    const defaultRoute = nextHop.includes(':') ? '::/0' : '0.0.0.0/0';
    commands.push(`set routing-instances ${instName} routing-options static route ${defaultRoute} next-hop ${nextHop}`);
  }
  if (instances.size > 0) commands.push('');

  // 2. Build firewall filter terms
  const filterName = 'PBF-FILTER';
  const filterInterfaces = new Set();
  let termCount = 0;

  for (const rule of pbfRules) {
    if (rule.disabled) continue;
    const termName = sanitizeJunosName(rule.name);
    const termBase = `set firewall filter ${filterName} term ${termName}`;

    // Match: source addresses (resolve named objects to IP values for firewall filters)
    for (const src of (rule.src_addresses || []).filter(a => a !== 'any')) {
      const isIp = /^[\d.:\/]+$/.test(src);
      if (isIp) {
        commands.push(`${termBase} from source-address ${src}`);
      } else if (addrLookup.has(src)) {
        commands.push(`${termBase} from source-address ${addrLookup.get(src)}`);
      } else {
        commands.push(`# WARNING: skipping source-address "${src}" — named object not resolvable to IP for firewall filter`);
        warnings.push(createWarning('warning', `pbf/${rule.name}`,
          `PBF filter term "${rule.name}" references named address "${src}" which could not be resolved to an IP`,
          'Firewall filters require raw IP addresses — add the address manually'));
      }
    }
    // Match: destination addresses (resolve named objects to IP values for firewall filters)
    for (const dst of (rule.dst_addresses || []).filter(a => a !== 'any')) {
      const isIp = /^[\d.:\/]+$/.test(dst);
      if (isIp) {
        commands.push(`${termBase} from destination-address ${dst}`);
      } else if (addrLookup.has(dst)) {
        commands.push(`${termBase} from destination-address ${addrLookup.get(dst)}`);
      } else {
        commands.push(`# WARNING: skipping destination-address "${dst}" — named object not resolvable to IP for firewall filter`);
        warnings.push(createWarning('warning', `pbf/${rule.name}`,
          `PBF filter term "${rule.name}" references named address "${dst}" which could not be resolved to an IP`,
          'Firewall filters require raw IP addresses — add the address manually'));
      }
    }
    // Match: applications/services (map to protocol/port if possible)
    for (const svc of (rule.services || []).filter(s => s !== 'any' && s !== 'application-default')) {
      const m = svc.match(/^(tcp|udp)\/(\d+)(?:-(\d+))?$/i);
      if (m) {
        commands.push(`${termBase} from protocol ${m[1].toLowerCase()}`);
        commands.push(`${termBase} from destination-port ${m[3] ? `${m[2]}-${m[3]}` : m[2]}`);
      }
    }

    // Action
    if (rule.action === 'forward' && rule.next_hop_value) {
      const instName = instances.get(rule.next_hop_value);
      commands.push(`${termBase} then routing-instance ${instName}`);
    } else if (rule.action === 'discard') {
      commands.push(`${termBase} then discard`);
    } else {
      // no-pbf or forward-to-vsys → accept (use default routing)
      commands.push(`${termBase} then accept`);
    }

    // Track from-interfaces for filter binding
    if (rule.from_type === 'interface') {
      for (const iface of (rule.from_value || [])) {
        const srxIface = mapInterfaceName(iface, interfaceMappings);
        filterInterfaces.add(srxIface);
      }
    }

    // Forward-to-vsys → warning (no direct SRX equivalent)
    if (rule.action === 'forward-to-vsys') {
      warnings.push(createWarning(
        'warning', `pbf/${rule.name}`,
        `PBF rule "${rule.name}" forwards to vsys "${rule.forward_vsys}" — SRX cross-logical-system routing requires manual lt- interface config`,
        'Configure lt- tunnel interfaces between logical-systems for cross-LS forwarding'
      ));
    }

    termCount++;
  }

  // Default accept term (allow unmatched traffic to use default routing)
  if (termCount > 0) {
    commands.push(`set firewall filter ${filterName} term default then accept`);
    commands.push('');
  }

  // 3. Bind filter to from-interfaces
  for (const iface of filterInterfaces) {
    const [base, unit = '0'] = iface.split('.');
    commands.push(`set interfaces ${base} unit ${unit} family inet filter input ${filterName}`);
  }

  if (filterInterfaces.size > 0) commands.push('');

  summary.pbf_rules_converted = termCount;
  summary.pbf_routing_instances = instances.size;
}


// ---------------------------------------------------------------------------
// SSL Proxy / PKI Configuration
// ---------------------------------------------------------------------------

/**
 * Generates SRX SSL proxy profiles and PKI configuration from decryption rules.
 *
 * For ssl-forward-proxy rules → root-ca based profile
 * For ssl-inbound-inspection → server-certificate based profile
 * Also generates PKI ca-profile placeholders and no-decrypt exclusion notes.
 */
function convertSslProxyConfig(config, commands, warnings, summary) {
  const decryptionRules = config.decryption_rules || [];
  if (decryptionRules.length === 0) return;

  // Also check security_policies for _srx_decrypt without explicit decryption rules
  const hasDecryptPolicies = (config.security_policies || []).some(p => p._srx_decrypt);
  const hasDecryptRules = decryptionRules.some(r => r.action === 'decrypt');

  if (!hasDecryptRules && !hasDecryptPolicies) {
    // Only no-decrypt rules — no SSL proxy needed, just note it
    commands.push('# =============================================');
    commands.push('# SSL/TLS Decryption — All rules are no-decrypt');
    commands.push('# No SSL Proxy configuration required');
    commands.push('# =============================================');
    commands.push('');
    return;
  }

  commands.push('# =============================================');
  commands.push('# SSL Proxy / PKI Configuration');
  commands.push('# =============================================');

  // Collect unique profiles by decryption type
  const fwdProxyProfiles = new Set();
  const inboundProfiles = new Map(); // profile-name → certificate
  const noDecryptNames = [];

  for (const rule of decryptionRules) {
    if (rule.disabled) continue;

    if (rule.action === 'decrypt' || rule.action === 'decrypt-and-forward') {
      if (rule.decryption_type === 'ssl-forward-proxy') {
        const profileName = rule.decryption_profile
          ? sanitizeJunosName(`ssl-fwd-${rule.decryption_profile}`)
          : 'ssl-fwd-proxy';
        fwdProxyProfiles.add(profileName);
      } else if (rule.decryption_type === 'ssl-inbound-inspection') {
        const profileName = rule.decryption_profile
          ? sanitizeJunosName(`ssl-inbound-${rule.decryption_profile}`)
          : 'ssl-inbound-proxy';
        inboundProfiles.set(profileName, rule.ssl_certificate || 'SERVER-CERT');
      } else if (rule.decryption_type === 'ssh-proxy') {
        // SSH proxy → SRX doesn't have direct equivalent
        warnings.push(createWarning(
          'unsupported', `decrypt/${rule.name}`,
          `SSH proxy decryption rule "${rule.name}" has no direct SRX equivalent`,
          'SRX does not support SSH traffic decryption — configure SSH-based controls at the application layer'
        ));
      } else {
        // Generic decrypt — use forward proxy as default
        fwdProxyProfiles.add('ssl-fwd-proxy');
      }
    } else if (rule.action === 'no-decrypt') {
      noDecryptNames.push(rule.name);
    }
  }

  // If no explicit forward-proxy profiles but policies have _srx_decrypt, create default
  if (fwdProxyProfiles.size === 0 && hasDecryptPolicies) {
    fwdProxyProfiles.add('ssl-fwd-proxy');
  }

  // 1. PKI CA profile placeholder (needed for forward proxy)
  if (fwdProxyProfiles.size > 0) {
    commands.push('');
    commands.push('# PKI Configuration — CA profile for SSL forward proxy');
    commands.push('set security pki ca-profile FPIC-CA ca-identity FPIC-CA');
    commands.push('# NOTE: Import the CA certificate after commit:');
    commands.push('#   request security pki ca-certificate load ca-profile FPIC-CA filename /var/tmp/ca-cert.pem');
    commands.push('# NOTE: Generate key pair for signing:');
    commands.push('#   request security pki generate-key-pair certificate-id FPIC-CA size 2048');
    commands.push('#   request security pki local-certificate generate-self-signed certificate-id FPIC-CA \\');
    commands.push('#     subject "CN=FPIC-CA,OU=Security,O=Organization" domain-name example.com');
    commands.push('');
  }

  // 2. PKI local-certificate placeholder (for inbound inspection)
  if (inboundProfiles.size > 0) {
    for (const [, certName] of inboundProfiles) {
      commands.push(`# NOTE: Import server certificate for inbound SSL inspection:`);
      commands.push(`#   request security pki local-certificate load certificate-id ${certName} filename /var/tmp/${certName}.pem key /var/tmp/${certName}-key.pem`);
    }
    commands.push('');
  }

  // 3. SSL Forward Proxy profiles
  for (const profileName of fwdProxyProfiles) {
    commands.push(`set services ssl proxy profile ${profileName} root-ca FPIC-CA`);
    commands.push(`set services ssl proxy profile ${profileName} protocol-version tls12-and-above`);
    commands.push(`set services ssl proxy profile ${profileName} actions log`);
    commands.push(`set services ssl proxy profile ${profileName} actions crl-disable`);
  }

  // 4. SSL Inbound Inspection profiles
  for (const [profileName, certName] of inboundProfiles) {
    commands.push(`set services ssl proxy profile ${profileName} server-certificate ${certName}`);
    commands.push(`set services ssl proxy profile ${profileName} protocol-version tls12-and-above`);
    commands.push(`set services ssl proxy profile ${profileName} actions log`);
  }

  if (fwdProxyProfiles.size > 0 || inboundProfiles.size > 0) commands.push('');

  // 5. No-decrypt exclusion notes
  if (noDecryptNames.length > 0) {
    commands.push('# No-decrypt exclusions (traffic explicitly excluded from SSL inspection):');
    for (const name of noDecryptNames) {
      commands.push(`#   - ${name}`);
    }
    commands.push('# NOTE: Implement no-decrypt via SRX security policy exemptions (match-then-bypass)');
    commands.push('# or SSL proxy whitelist entries for specific domains/addresses');
    commands.push('');
  }

  // Summary
  summary.ssl_proxy_profiles = fwdProxyProfiles.size + inboundProfiles.size;
  summary.ssl_fwd_proxy_count = fwdProxyProfiles.size;
  summary.ssl_inbound_count = inboundProfiles.size;
  summary.ssl_no_decrypt_count = noDecryptNames.length;

  warnings.push(createWarning(
    'info', 'ssl-proxy/config',
    `Generated ${fwdProxyProfiles.size} SSL forward-proxy and ${inboundProfiles.size} inbound-inspection profiles`,
    'Import CA certificate and server certificates before committing. Test with a small policy scope first.'
  ));
}


// ---------------------------------------------------------------------------
// Flow Monitoring / Inline-Jflow Configuration
// ---------------------------------------------------------------------------

/**
 * Generates SRX inline-jflow configuration from flow monitoring config.
 *
 * Produces:
 *   set forwarding-options sampling instance <name> input rate <rate>
 *   set forwarding-options sampling instance <name> family inet output flow-server <addr> port <port>
 *   set forwarding-options sampling instance <name> family inet output flow-server <addr> version-ipfix template <tpl>
 *   set forwarding-options sampling instance <name> family inet output inline-jflow source-address <src>
 *   set services flow-monitoring version-ipfix template <tpl> flow-active-timeout <sec>
 *   set services flow-monitoring version-ipfix template <tpl> template-refresh-rate packets <num>
 *   set interfaces <iface> unit 0 family inet sampling input
 */
function convertFlowMonitoringConfig(flowConfig, commands, warnings, summary, interfaceMappings = {}) {
  if (!flowConfig || !flowConfig.collectors || flowConfig.collectors.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Flow Monitoring (Inline Jflow)');
  commands.push('# =============================================');

  const instanceName = flowConfig.instance_name || 'FLOW-SAMPLE';
  const sampling = flowConfig.sampling || {};
  const rate = sampling.input_rate || 1000;
  const runLength = sampling.run_length || 0;

  // Sampling instance input
  commands.push(`set forwarding-options sampling instance ${instanceName} input rate ${rate}`);
  if (runLength > 0) {
    commands.push(`set forwarding-options sampling instance ${instanceName} input run-length ${runLength}`);
  }

  // Flow servers and templates
  const templates = flowConfig.templates || [];
  let tplIndex = 0;

  for (const collector of flowConfig.collectors) {
    const addr = collector.address;
    const port = collector.port || 2055;
    const protocol = (collector.protocol || 'ipfix').toLowerCase();
    const isIpfix = protocol === 'ipfix' || protocol === 'netflow-v10';
    const versionKey = isIpfix ? 'version-ipfix' : 'version9';

    // Get matching template or create default
    const tpl = templates[tplIndex] || { name: `flow-tpl-${tplIndex + 1}`, flow_type: 'ipv4', active_timeout: 60, refresh_rate: 1000 };
    const tplName = sanitizeJunosName(tpl.name);

    commands.push(`set forwarding-options sampling instance ${instanceName} family inet output flow-server ${addr} port ${port}`);
    commands.push(`set forwarding-options sampling instance ${instanceName} family inet output flow-server ${addr} ${versionKey} template ${tplName}`);

    // IPv6 family if specified
    if (tpl.flow_type === 'ipv6') {
      commands.push(`set forwarding-options sampling instance ${instanceName} family inet6 output flow-server ${addr} port ${port}`);
      commands.push(`set forwarding-options sampling instance ${instanceName} family inet6 output flow-server ${addr} ${versionKey} template ${tplName}`);
    }

    // Inline jflow source address
    if (collector.source_address) {
      commands.push(`set forwarding-options sampling instance ${instanceName} family inet output inline-jflow source-address ${collector.source_address}`);
    }

    tplIndex++;
  }

  commands.push('');

  // Template definitions
  for (const tpl of templates) {
    const tplName = sanitizeJunosName(tpl.name);
    const isIpfix = true; // Default to IPFIX for SRX
    const versionKey = isIpfix ? 'version-ipfix' : 'version9';

    commands.push(`set services flow-monitoring ${versionKey} template ${tplName} flow-active-timeout ${tpl.active_timeout || 60}`);
    commands.push(`set services flow-monitoring ${versionKey} template ${tplName} template-refresh-rate packets ${tpl.refresh_rate || 1000}`);

    if (tpl.flow_type === 'ipv6') {
      commands.push(`set services flow-monitoring ${versionKey} template ${tplName} ipv6-template`);
    }
  }

  commands.push('');

  // Interface sampling bindings
  const samplingInterfaces = sampling.interfaces || [];
  for (const iface of samplingInterfaces) {
    const srxIface = mapInterfaceName(iface, interfaceMappings);
    const [base, unit = '0'] = srxIface.split('.');
    commands.push(`set interfaces ${base} unit ${unit} family inet sampling input`);
  }

  if (samplingInterfaces.length > 0) commands.push('');

  summary.flow_collectors = flowConfig.collectors.length;
  summary.flow_templates = templates.length;

  warnings.push(createWarning('info', 'flow-monitoring/config',
    `Generated inline-jflow config with ${flowConfig.collectors.length} collector(s) and ${templates.length} template(s)`,
    'Verify flow-server addresses and template parameters after deployment'));
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

// ---------------------------------------------------------------------------
// Multi-Firewall Merge Converter
// ---------------------------------------------------------------------------

/**
 * Converts multiple intermediate configs into a merged SRX output
 * with per-logical-system sections and shared chassis-level config.
 *
 * @param {Array<{lsName: string, intermediateConfig: Object, interfaceMappings: Object}>} configSlots
 * @param {Array<{ls1: string, ls2: string, sharedZone: string, lt1Unit: number, lt2Unit: number}>} crossLsLinks
 * @param {Object} globalConfig - Chassis-level config (HA, syslog)
 * @returns {{ commands: string[], warnings: Object[], summary: Object }}
 */
export function convertMergedToSrxSetCommands(configSlots, crossLsLinks = [], globalConfig = {}) {
  const allCommands = [];
  const allWarnings = [];
  const perLsSummaries = [];

  // 1. Global chassis-level config (not inside any LS)
  allCommands.push('# =============================================');
  allCommands.push('# Multi-Firewall Merge — Chassis-Level Config');
  allCommands.push('# =============================================');
  allCommands.push(`# Logical-systems: ${configSlots.map(s => s.lsName).join(', ')}`);
  allCommands.push('');

  // HA config at chassis level
  if (globalConfig.ha_config && globalConfig.ha_config.enabled) {
    const haCommands = [];
    const haWarnings = [];
    const haSummary = {};
    convertHaConfig(globalConfig.ha_config, haCommands, haWarnings, haSummary);
    allCommands.push(...haCommands);
    allWarnings.push(...haWarnings);
    allCommands.push('');
  }

  // Syslog at chassis level
  if (globalConfig.syslog_config && globalConfig.syslog_config.length > 0) {
    const sysCommands = [];
    convertSyslogConfig(globalConfig.syslog_config, sysCommands, allWarnings, {});
    allCommands.push(...sysCommands);
    allCommands.push('');
  }

  // 2. Per-LS sections
  for (const slot of configSlots) {
    const { lsName, intermediateConfig: config, interfaceMappings = {} } = slot;

    allCommands.push('# =============================================');
    allCommands.push(`# Logical-System: ${lsName}`);
    allCommands.push('# =============================================');

    // Use existing converter with targetContext set to logical-system
    const targetContext = { type: 'logical-system', name: lsName };
    const result = convertToSrxSetCommands(config, interfaceMappings, targetContext);

    allCommands.push(...result.commands);
    allWarnings.push(...result.warnings.map(w => ({ ...w, _ls: lsName })));
    perLsSummaries.push({ lsName, summary: result.summary });
    allCommands.push('');
  }

  // 3. Cross-LS lt- tunnel interfaces
  if (crossLsLinks.length > 0) {
    allCommands.push('# =============================================');
    allCommands.push('# Cross-Logical-System Tunnel Interfaces (lt-)');
    allCommands.push('# =============================================');
    allCommands.push('# Auto-detected from shared zone names across logical-systems');
    allCommands.push('');

    for (const link of crossLsLinks) {
      const ls1 = sanitizeJunosName(link.ls1);
      const ls2 = sanitizeJunosName(link.ls2);
      const u1 = link.lt1Unit;
      const u2 = link.lt2Unit;
      const zone = sanitizeJunosName(link.sharedZone);

      allCommands.push(`# ${link.ls1} <-> ${link.ls2} via zone "${link.sharedZone}"`);

      // Side A
      allCommands.push(`set logical-systems ${ls1} interfaces lt-0/0/0 unit ${u1} encapsulation ethernet`);
      allCommands.push(`set logical-systems ${ls1} interfaces lt-0/0/0 unit ${u1} peer-unit ${u2}`);
      allCommands.push(`set logical-systems ${ls1} interfaces lt-0/0/0 unit ${u1} family inet`);
      allCommands.push(`set logical-systems ${ls1} security zones security-zone ${zone} interfaces lt-0/0/0.${u1}`);

      // Side B
      allCommands.push(`set logical-systems ${ls2} interfaces lt-0/0/0 unit ${u2} encapsulation ethernet`);
      allCommands.push(`set logical-systems ${ls2} interfaces lt-0/0/0 unit ${u2} peer-unit ${u1}`);
      allCommands.push(`set logical-systems ${ls2} interfaces lt-0/0/0 unit ${u2} family inet`);
      allCommands.push(`set logical-systems ${ls2} security zones security-zone ${zone} interfaces lt-0/0/0.${u2}`);

      allCommands.push('');
    }
  }

  // 4. Merged summary
  const mergedSummary = {
    logical_systems: configSlots.length,
    cross_ls_links: crossLsLinks.length,
    per_ls: perLsSummaries,
    total_policies: perLsSummaries.reduce((sum, ls) => sum + (ls.summary.policies_converted || 0), 0),
    total_warnings: allWarnings.length,
  };

  return { commands: allCommands, warnings: allWarnings, summary: mergedSummary };
}

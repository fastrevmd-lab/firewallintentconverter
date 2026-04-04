/**
 * SRX XML Configuration Builder
 * ================================
 * Agent: SRX-Expert
 *
 * Converts the vendor-neutral intermediate JSON schema into Junos XML
 * configuration format, suitable for "load merge" or "load replace" on SRX.
 *
 * Phase 1: Basic XML structure with security zones, address book, and policies.
 * Phase 2+: Full XML with NAT, routing, VPN, UTM.
 */

import { sanitizeJunosName, mapAppToJunos, mapProfileToSrx, createWarning, isPredefEquivalent } from '../parsers/parser-utils.js';

/**
 * Returns the correct ANY address for NAT rules based on whether the rule
 * contains IPv6 addresses.
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
 * Builds a Junos XML configuration from the intermediate config.
 *
 * @param {Object} config - Intermediate JSON config
 * @param {Object} [interfaceMappings] - User-defined PAN-OS → SRX interface mappings
 * @returns {{ xml: string, warnings: Object[] }}
 */
export function buildSrxXml(config, interfaceMappings = {}, targetContext = null, options = {}) {
  const warnings = [];
  const lines = [];
  xmlCustomfwicApps.clear();
  xmlPredefServiceMap.clear();

  // Detect source vendor for 1:1 passthrough (SRX→SRX needs no app mapping)
  const sourceVendor = config.metadata?.source_vendor || '';

  // Compute UTM/IDP/SecIntel assignment maps (mirrors srx-converter logic)
  const { utmPolicyMap, utmProfiles } = computeUtmMap(config.security_policies);
  const { idpPolicyMap } = computeIdpMap(config.security_policies);
  const blockLists = (config.external_lists || []).filter(e => e.isBlockList);
  const secIntelEnabled = blockLists.length > 0;

  // Determine context wrapping
  const ctx = targetContext || config.target_context;
  const useContext = ctx && ctx.type && ctx.type !== 'none' && ctx.name;
  const indent = useContext ? '    ' : '  ';

  const omitWrapper = options.omitConfigurationWrapper || false;

  if (!omitWrapper) {
    lines.push('<?xml version="1.0" encoding="UTF-8"?>');

    // Site identification header (for SDC/Mist integration)
    const siteN = config.metadata?.siteName;
    const siteG = config.metadata?.siteGroup;
    if (siteN || siteG) {
      let siteComment = '<!-- Site Identification:';
      if (siteN) siteComment += ` Site: ${escapeXml(siteN)}`;
      if (siteG) siteComment += ` | Site Group: ${escapeXml(siteG)}`;
      siteComment += ' -->';
      lines.push(siteComment);
    }

    lines.push('<configuration>');
  }

  // Open logical-system or tenant wrapper
  if (useContext) {
    const ctxTag = ctx.type === 'logical-system' ? 'logical-systems' : 'tenants';
    lines.push(`  <${ctxTag}>`);
    lines.push(`    <name>${escapeXml(sanitizeJunosName(ctx.name))}</name>`);
  }

  // System configuration (Day-0)
  buildSystemConfigXml(config.system_config, lines, indent);

  // Interface addresses (IPv4 + IPv6)
  buildInterfaceAddressesXml(config.interfaces, lines, interfaceMappings, indent);

  // Security section
  lines.push(`${indent}<security>`);

  // Zones
  buildZonesXml(config.zones, lines, interfaceMappings);

  // Address book
  buildAddressBookXml(config.address_objects, config.address_groups, lines);

  // UTM
  buildUtmXml(utmProfiles, lines);

  // Policies
  buildPoliciesXml(config.security_policies, lines, warnings, { utmPolicyMap, idpPolicyMap, secIntelEnabled }, config.application_groups, sourceVendor, config._rule_groups);

  // NAT
  buildNatXml(config.nat_rules, lines, warnings);

  // IDP
  buildIdpXml(config.security_policies, lines);

  lines.push(`${indent}</security>`);

  // Routing (static routes, BGP, OSPF)
  buildRoutingXml(config, lines);

  // Chassis Cluster / HA
  buildHaXml(config.ha_config, lines);

  // Security Screens
  buildScreenXml(config.screen_config, lines);

  // VPN / IPsec
  buildVpnXml(config.vpn_tunnels, lines);

  // Syslog
  buildSyslogXml(config.syslog_config, lines);

  // SNMP
  buildSnmpXml(config.snmp_config, lines);

  // AAA
  buildAaaXml(config.aaa_config, lines);

  // DHCP
  buildDhcpXml(config.dhcp_config, lines);

  // QoS / CoS
  buildQosXml(config.qos_config, lines);

  // L2 / Bridge Domains / Virtual-Wire
  buildL2Xml(config, lines, interfaceMappings);

  // Policy-Based Forwarding (filter-based forwarding)
  buildPbfXml(config.pbf_rules, lines, interfaceMappings);

  // SSL Proxy / PKI
  buildSslProxyXml(config, lines);

  // Flow Monitoring (Inline Jflow)
  buildFlowMonitoringXml(config.flow_monitoring_config, lines);

  // Applications (includes Customfwic placeholders for unmapped apps)
  buildApplicationsXml(config.service_objects, config.applications, config.service_groups, lines, xmlCustomfwicApps);

  // Schedulers
  buildSchedulersXml(config.schedules, lines);

  // Services (SecIntel)
  if (secIntelEnabled) {
    buildSecIntelXml(blockLists, lines);
  }

  // User Identification (JIMS) — when policies use source-identity
  buildUserIdentificationXml(config.security_policies, lines);

  // Unsupported feature notices
  lines.push('<!--');
  lines.push('  NOT CONVERTED — Manual Configuration Required');
  if (!config.aaa_config || config.aaa_config.length === 0) {
    lines.push('  AAA / Authentication (RADIUS, TACACS+, LDAP) — no AAA config detected in source.');
    lines.push('  If needed, configure manually: system authentication-order, access profile, etc.');
  }
  lines.push('-->');

  // Close context wrapper
  if (useContext) {
    const ctxTag = ctx.type === 'logical-system' ? 'logical-systems' : 'tenants';
    lines.push(`  </${ctxTag}>`);
  }

  if (!omitWrapper) {
    lines.push('</configuration>');
  }

  return {
    xml: lines.join('\n'),
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Zone XML Builder
// ---------------------------------------------------------------------------

function buildZonesXml(zones, lines, interfaceMappings = {}) {
  if (!zones || zones.length === 0) return;

  lines.push('    <zones>');
  for (const zone of zones) {
    const name = sanitizeJunosName(zone.name);
    lines.push(`      <security-zone>`);
    lines.push(`        <name>${escapeXml(name)}</name>`);
    if (zone.description) {
      lines.push(`        <description>${escapeXml(zone.description)}</description>`);
    }
    for (const iface of zone.interfaces || []) {
      // Use user-defined mapping if available, otherwise use as-is
      let srxIface = iface;
      if (interfaceMappings[iface]) {
        srxIface = interfaceMappings[iface];
        if (!srxIface.includes('.')) srxIface += '.0';
      } else {
        const base = iface.split('.')[0];
        if (interfaceMappings[base]) {
          const unit = iface.includes('.') ? iface.split('.')[1] : '0';
          srxIface = `${interfaceMappings[base].split('.')[0]}.${unit}`;
        }
      }
      lines.push(`        <interfaces>`);
      lines.push(`          <name>${escapeXml(srxIface)}</name>`);
      lines.push(`        </interfaces>`);
    }
    lines.push(`      </security-zone>`);
  }
  lines.push('    </zones>');
}

// ---------------------------------------------------------------------------
// Address Book XML Builder
// ---------------------------------------------------------------------------

function buildAddressBookXml(addressObjects, addressGroups, lines) {
  if ((!addressObjects || addressObjects.length === 0) &&
      (!addressGroups || addressGroups.length === 0)) return;

  lines.push('    <address-book>');
  lines.push('      <name>global</name>');

  // Address entries
  for (const obj of (addressObjects || [])) {
    const name = sanitizeJunosName(obj.name);
    lines.push('      <address>');
    lines.push(`        <name>${escapeXml(name)}</name>`);

    switch (obj.type) {
      case 'host':
      case 'subnet':
        lines.push(`        <ip-prefix>${escapeXml(obj.value)}</ip-prefix>`);
        break;
      case 'fqdn': {
        const fqdnValue = (obj.value && obj.value.startsWith('*.')) ? obj.value.slice(2) : obj.value;
        lines.push(`        <dns-name>`);
        lines.push(`          <name>${escapeXml(fqdnValue)}</name>`);
        if (obj.fqdn_ip_version === 'v4') {
          lines.push(`          <ipv4-only/>`);
        } else if (obj.fqdn_ip_version === 'v6') {
          lines.push(`          <ipv6-only/>`);
        }
        lines.push(`        </dns-name>`);
        break;
      }
      case 'range':
        lines.push(`        <range-address>`);
        lines.push(`          <name>${escapeXml(name)}</name>`);
        const [low, high] = obj.value.split('-').map(s => s.trim());
        lines.push(`          <low>${escapeXml(low)}</low>`);
        lines.push(`          <high>${escapeXml(high)}</high>`);
        lines.push(`        </range-address>`);
        break;
      case 'geography':
      case 'dynamic':
      case 'wildcard':
        lines.push(`        <!-- UNSUPPORTED: ${obj.type} address "${obj.name}" (${obj.value}) -->`);
        continue;
    }

    if (obj.description) {
      lines.push(`        <description>${escapeXml(obj.description)}</description>`);
    }

    lines.push('      </address>');
  }

  // Address sets (groups)
  const addrGroupNameSet = new Set((addressGroups || []).map(g => g.name));
  for (const group of (addressGroups || [])) {
    if (group._dynamic) {
      lines.push(`      <!-- UNSUPPORTED: Dynamic address group "${group.name}" — SRX does not support tag-based dynamic groups -->`);
      continue;
    }
    const groupName = sanitizeJunosName(group.name);
    lines.push('      <address-set>');
    lines.push(`        <name>${escapeXml(groupName)}</name>`);
    for (const member of group.members) {
      if (addrGroupNameSet.has(member)) {
        lines.push('        <address-set>');
        lines.push(`          <name>${escapeXml(sanitizeJunosName(member))}</name>`);
        lines.push('        </address-set>');
      } else {
        lines.push('        <address>');
        lines.push(`          <name>${escapeXml(sanitizeJunosName(member))}</name>`);
        lines.push('        </address>');
      }
    }
    lines.push('      </address-set>');
  }

  lines.push('    </address-book>');
}

// ---------------------------------------------------------------------------
// User Identification (JIMS) XML Builder
// ---------------------------------------------------------------------------

function buildUserIdentificationXml(policies, lines) {
  if (!policies || policies.length === 0) return;
  const identityPolicies = policies.filter(p => p.source_users && p.source_users.length > 0);
  if (identityPolicies.length === 0) return;

  lines.push('  <services>');
  lines.push('    <user-identification>');
  lines.push('      <identity-management>');
  lines.push('        <connection>');
  lines.push('          <connect-method>https</connect-method>');
  lines.push('          <port>1443</port>');
  lines.push('          <!-- Configure JIMS server address and credentials -->');
  lines.push('        </connection>');
  lines.push('      </identity-management>');
  lines.push('    </user-identification>');
  lines.push('  </services>');
}

// ---------------------------------------------------------------------------
// Security Policies XML Builder
// ---------------------------------------------------------------------------

function buildPoliciesXml(policies, lines, warnings, profileMaps = {}, appGroups = [], sourceVendor = '', ruleGroups = []) {
  if (!policies || policies.length === 0) return;

  const { utmPolicyMap = {}, idpPolicyMap = {}, secIntelEnabled = false } = profileMaps;

  // Build rule-index→group map for group comment insertion
  const groupByIndex = {};
  if (ruleGroups && ruleGroups.length > 0) {
    for (const g of ruleGroups) {
      for (const idx of (g.rule_indices || [])) {
        groupByIndex[idx] = g.group_name;
      }
    }
  }

  // Group policies by zone pair
  const zonePairs = {};
  for (const policy of policies) {
    const srcZones = policy.src_zones.length > 0 ? policy.src_zones : ['any'];
    const dstZones = policy.dst_zones.length > 0 ? policy.dst_zones : ['any'];

    for (const src of srcZones) {
      for (const dst of dstZones) {
        const key = `${src}|${dst}`;
        if (!zonePairs[key]) zonePairs[key] = { from: src, to: dst, policies: [] };
        zonePairs[key].policies.push(policy);
      }
    }
  }

  lines.push('    <policies>');

  for (const pair of Object.values(zonePairs)) {
    lines.push('      <policy>');
    lines.push(`        <from-zone-name>${escapeXml(sanitizeJunosName(pair.from))}</from-zone-name>`);
    lines.push(`        <to-zone-name>${escapeXml(sanitizeJunosName(pair.to))}</to-zone-name>`);

    let currentGroup = null;
    for (const policy of pair.policies) {
      // Emit XML comment for group boundaries
      const pIdx = policies.indexOf(policy);
      const ruleGroup = groupByIndex[pIdx] || policy._group || null;
      if (ruleGroup && ruleGroup !== currentGroup) {
        lines.push(`        <!-- ===== Group: ${escapeXml(ruleGroup)} ===== -->`);
        currentGroup = ruleGroup;
      }
      const name = sanitizeJunosName(policy.name);

      // Clean EDL addresses from match criteria
      const secIntelAddrs = new Set(policy._secIntelAddresses || []);
      let srcAddrs = policy.src_addresses.filter(a => !secIntelAddrs.has(a));
      let dstAddrs = policy.dst_addresses.filter(a => !secIntelAddrs.has(a));
      if (srcAddrs.length === 0 && policy.src_addresses.length > 0) srcAddrs = ['any'];
      if (dstAddrs.length === 0 && policy.dst_addresses.length > 0) dstAddrs = ['any'];

      lines.push('        <policy>');
      lines.push(`          <name>${escapeXml(name)}</name>`);

      // Match
      lines.push('          <match>');
      for (const addr of (srcAddrs.length > 0 ? srcAddrs : ['any'])) {
        lines.push(`            <source-address>${escapeXml(sanitizeJunosName(addr))}</source-address>`);
      }
      for (const addr of (dstAddrs.length > 0 ? dstAddrs : ['any'])) {
        lines.push(`            <destination-address>${escapeXml(sanitizeJunosName(addr))}</destination-address>`);
      }

      const apps = resolveApps(policy.applications, policy.services, warnings, policy.name, appGroups, sourceVendor);
      for (const app of apps) {
        lines.push(`            <application>${escapeXml(app)}</application>`);
      }
      if (policy.source_users && policy.source_users.length > 0) {
        for (const identity of policy.source_users) {
          lines.push(`            <source-identity>${escapeXml(sanitizeJunosName(identity))}</source-identity>`);
        }
      }
      lines.push('          </match>');

      // Then
      lines.push('          <then>');
      const action = policy.action === 'allow' ? 'permit' : (policy.action === 'drop' ? 'deny' : (policy.action === 'deny' ? 'deny' : 'reject'));
      lines.push(`            <${action}/>`);
      if (policy.log_start || policy.log_end) {
        lines.push('            <log>');
        if (policy.log_start) lines.push('              <session-init/>');
        if (policy.log_end) lines.push('              <session-close/>');
        lines.push('            </log>');
      }
      if (policy._srx_log_count !== false) {
        lines.push('            <count/>');
      }

      // Application services (UTM / IDP / SecIntel)
      const hasUtm = !!utmPolicyMap[policy.name];
      const hasIdp = !!idpPolicyMap[policy.name];
      const hasProfileGroup = policy.profile_group && Object.keys(policy.security_profiles || {}).length === 0;
      const hasSecIntel = secIntelEnabled && policy.action === 'allow' &&
        policy.dst_zones.some(z => z.toLowerCase() === 'untrust');

      const hasSslProxy = policy._srx_decrypt && policy.action === 'allow';

      if (hasUtm || hasIdp || hasSecIntel || hasProfileGroup || hasSslProxy) {
        lines.push('            <application-services>');
        if (hasUtm) {
          lines.push(`              <utm-policy>${escapeXml(utmPolicyMap[policy.name])}</utm-policy>`);
        } else if (hasProfileGroup) {
          lines.push('              <utm-policy>default-utm</utm-policy>');
        }
        if (hasIdp) {
          lines.push(`              <idp-policy>${escapeXml(idpPolicyMap[policy.name])}</idp-policy>`);
        }
        if (hasSecIntel) {
          lines.push('              <security-intelligence-policy>secIntel-policy</security-intelligence-policy>');
        }
        if (hasSslProxy) {
          const sslProfile = policy._srx_decrypt_profile
            ? sanitizeJunosName(policy._srx_decrypt_profile)
            : 'ssl-fwd-proxy';
          lines.push('              <ssl-proxy>');
          lines.push(`                <profile-name>${escapeXml(sslProfile)}</profile-name>`);
          lines.push('              </ssl-proxy>');
        }
        lines.push('            </application-services>');
      }

      lines.push('          </then>');

      // Scheduler
      if (policy.schedule) {
        lines.push(`          <scheduler-name>${escapeXml(sanitizeJunosName(policy.schedule))}</scheduler-name>`);
      }

      lines.push('        </policy>');
    }

    lines.push('      </policy>');
  }

  lines.push('    </policies>');
}

// ---------------------------------------------------------------------------
// NAT XML Builder (basic Phase 1 structure)
// ---------------------------------------------------------------------------

function groupNatByZonePair(rules) {
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

function buildNatXml(natRules, lines, warnings) {
  if (!natRules || natRules.length === 0) return;

  lines.push('    <nat>');

  const sourceRules = natRules.filter(r => r.type === 'source' || r.type === 'source-and-destination');
  const destRules = natRules.filter(r => r.type === 'destination' || r.type === 'source-and-destination');
  const staticRules = natRules.filter(r => r.type === 'static');

  // --- Source NAT ---
  if (sourceRules.length > 0) {
    lines.push('      <source>');
    const groups = groupNatByZonePair(sourceRules);
    for (const [zonePair, rules] of Object.entries(groups)) {
      const [fromZone, toZone] = zonePair.split('->');
      const ruleSetName = sanitizeJunosName(`${fromZone}-to-${toZone}`);
      lines.push('        <rule-set>');
      lines.push(`          <name>${escapeXml(ruleSetName)}</name>`);
      lines.push(`          <from><zone>${escapeXml(sanitizeJunosName(fromZone))}</zone></from>`);
      lines.push(`          <to><zone>${escapeXml(sanitizeJunosName(toZone))}</zone></to>`);

      for (const rule of rules) {
        const ruleName = sanitizeJunosName(rule.name);
        lines.push('          <rule>');
        lines.push(`            <name>${escapeXml(ruleName)}</name>`);
        const anyAddr = natAnyAddress(rule);
        lines.push('            <src-nat-rule-match>');
        for (const addr of (rule.src_addresses || [anyAddr])) {
          lines.push(`              <source-address>${escapeXml(addr === 'any' ? anyAddr : addr)}</source-address>`);
        }
        for (const addr of (rule.dst_addresses || [anyAddr])) {
          lines.push(`              <destination-address>${escapeXml(addr === 'any' ? anyAddr : addr)}</destination-address>`);
        }
        lines.push('            </src-nat-rule-match>');
        lines.push('            <then>');
        if (rule.translated_src) {
          if (rule.translated_src.type === 'interface') {
            lines.push('              <source-nat><interface/></source-nat>');
          } else if (rule.translated_src.type === 'dynamic-ip-pool') {
            const poolName = sanitizeJunosName(`pool-${rule.name}`);
            lines.push(`              <source-nat><pool><pool-name>${escapeXml(poolName)}</pool-name></pool></source-nat>`);
          } else if (rule.translated_src.type === 'static') {
            const poolName = sanitizeJunosName(`${rule.name}-static`);
            lines.push(`              <source-nat><pool><pool-name>${escapeXml(poolName)}</pool-name></pool></source-nat>`);
          }
        }
        if (rule._uturn) {
          lines.push('              <persistent-nat><permit>target-host</permit></persistent-nat>');
        }
        lines.push('            </then>');
        lines.push('          </rule>');
      }
      lines.push('        </rule-set>');
    }

    // Source NAT pools
    for (const rule of sourceRules) {
      if (rule.translated_src && rule.translated_src.type === 'dynamic-ip-pool') {
        const poolName = sanitizeJunosName(`pool-${rule.name}`);
        lines.push('        <pool>');
        lines.push(`          <name>${escapeXml(poolName)}</name>`);
        for (const addr of rule.translated_src.addresses) {
          lines.push(`          <address><name>${escapeXml(addr)}</name></address>`);
        }
        lines.push('        </pool>');
      } else if (rule.translated_src && rule.translated_src.type === 'static' && rule.translated_src.address) {
        const poolName = sanitizeJunosName(`${rule.name}-static`);
        lines.push('        <pool>');
        lines.push(`          <name>${escapeXml(poolName)}</name>`);
        lines.push(`          <address><name>${escapeXml(rule.translated_src.address)}</name></address>`);
        lines.push('        </pool>');
      }
    }
    lines.push('      </source>');
  }

  // --- Destination NAT ---
  if (destRules.length > 0) {
    lines.push('      <destination>');
    const groups = groupNatByZonePair(destRules);
    for (const [zonePair, rules] of Object.entries(groups)) {
      const [fromZone] = zonePair.split('->');
      const ruleSetName = sanitizeJunosName(`${fromZone}-dnat`);
      lines.push('        <rule-set>');
      lines.push(`          <name>${escapeXml(ruleSetName)}</name>`);
      lines.push(`          <from><zone>${escapeXml(sanitizeJunosName(fromZone))}</zone></from>`);

      for (const rule of rules) {
        const ruleName = sanitizeJunosName(rule.name);
        lines.push('          <rule>');
        lines.push(`            <name>${escapeXml(ruleName)}</name>`);
        const dnatAny = natAnyAddress(rule);
        lines.push('            <dest-nat-rule-match>');
        for (const addr of (rule.dst_addresses || [dnatAny])) {
          lines.push(`              <destination-address>${escapeXml(addr === 'any' ? dnatAny : addr)}</destination-address>`);
        }
        if (rule.match_port) {
          lines.push(`              <destination-port>${escapeXml(rule.match_port)}</destination-port>`);
        }
        lines.push('            </dest-nat-rule-match>');
        lines.push('            <then>');
        const dstAddr = typeof rule.translated_dst === 'string' ? rule.translated_dst : (rule.translated_dst?.address || '');
        if (dstAddr) {
          const poolName = sanitizeJunosName(`dnat-pool-${rule.name}`);
          lines.push(`              <destination-nat><pool><pool-name>${escapeXml(poolName)}</pool-name></pool></destination-nat>`);
        }
        lines.push('            </then>');
        lines.push('          </rule>');
      }
      lines.push('        </rule-set>');
    }

    // Destination NAT pools
    for (const rule of destRules) {
      const dstAddr = typeof rule.translated_dst === 'string' ? rule.translated_dst : (rule.translated_dst?.address || '');
      if (dstAddr) {
        const poolName = sanitizeJunosName(`dnat-pool-${rule.name}`);
        lines.push('        <pool>');
        lines.push(`          <name>${escapeXml(poolName)}</name>`);
        lines.push(`          <address><ip-prefix>${escapeXml(dstAddr)}</ip-prefix></address>`);
        if (rule.translated_port) {
          lines.push(`          <address><port>${escapeXml(String(rule.translated_port))}</port></address>`);
        }
        lines.push('        </pool>');
      }
    }
    lines.push('      </destination>');
  }

  // --- Static NAT ---
  if (staticRules.length > 0) {
    lines.push('      <static>');
    lines.push('        <rule-set>');
    lines.push('          <name>STATIC-NAT</name>');
    for (const rule of staticRules) {
      const ruleName = sanitizeJunosName(rule.name);
      lines.push('          <rule>');
      lines.push(`            <name>${escapeXml(ruleName)}</name>`);
      lines.push('            <match>');
      for (const addr of (rule.dst_addresses || []).filter(a => a !== 'any')) {
        lines.push(`              <destination-address>${escapeXml(addr)}</destination-address>`);
      }
      lines.push('            </match>');
      lines.push('            <then>');
      if (rule.translated_src && rule.translated_src.address) {
        lines.push('              <static-nat>');
        lines.push(`                <prefix><addr-prefix>${escapeXml(rule.translated_src.address)}</addr-prefix></prefix>`);
        lines.push('              </static-nat>');
      }
      lines.push('            </then>');
      lines.push('          </rule>');
    }
    lines.push('        </rule-set>');
    lines.push('      </static>');
  }

  lines.push('    </nat>');
}

// ---------------------------------------------------------------------------
// Applications XML Builder
// ---------------------------------------------------------------------------

function buildApplicationsXml(serviceObjects, applications, serviceGroups, lines, customfwicMap) {
  const allApps = [...(serviceObjects || []), ...(applications || [])];
  const groups = serviceGroups || [];
  const hasCustomfwic = customfwicMap && customfwicMap.size > 0;
  if (allApps.length === 0 && groups.length === 0 && !hasCustomfwic) return;

  lines.push('  <applications>');

  for (const app of allApps) {
    const name = sanitizeJunosName(app.name);
    const protocol = app.protocol || 'tcp';
    const port = app.port_range || app.port || '';

    // Check if this service maps to a predefined Junos application — skip if so
    const predefApp = isPredefEquivalent(app.name, protocol, port);
    if (predefApp) {
      xmlPredefServiceMap.set(app.name, predefApp);
      xmlPredefServiceMap.set(name, predefApp);
      lines.push(`    <!-- Skipped: "${app.name}" (${protocol}/${port}) → predefined ${predefApp} -->`);
      continue;
    }

    if (protocol === 'icmp' || protocol === 'icmp6') {
      lines.push('    <application>');
      lines.push(`      <name>${escapeXml(name)}</name>`);
      lines.push(`      <protocol>${escapeXml(protocol)}</protocol>`);
      if (app.icmp_type) {
        lines.push(`      <icmp-type>${escapeXml(app.icmp_type)}</icmp-type>`);
      }
      if (app.icmp_code) {
        lines.push(`      <icmp-code>${escapeXml(app.icmp_code)}</icmp-code>`);
      }
      if (app.description) {
        lines.push(`      <description>${escapeXml(app.description)}</description>`);
      }
      lines.push('    </application>');
    } else if (protocol === 'ip' && app.protocol_number) {
      lines.push('    <application>');
      lines.push(`      <name>${escapeXml(name)}</name>`);
      lines.push(`      <protocol>${escapeXml(app.protocol_number)}</protocol>`);
      if (app.description) {
        lines.push(`      <description>${escapeXml(app.description)}</description>`);
      }
      lines.push('    </application>');
    } else {
      if (!port) continue;
      lines.push('    <application>');
      lines.push(`      <name>${escapeXml(name)}</name>`);
      lines.push(`      <protocol>${escapeXml(protocol)}</protocol>`);
      lines.push(`      <destination-port>${escapeXml(port)}</destination-port>`);
      if (app.description) {
        lines.push(`      <description>${escapeXml(app.description)}</description>`);
      }
      lines.push('    </application>');
    }
  }

  // Application sets (service groups)
  const svcGroupNameSet = new Set(groups.map(g => g.name));
  for (const group of groups) {
    const groupName = sanitizeJunosName(group.name);
    lines.push('    <application-set>');
    lines.push(`      <name>${escapeXml(groupName)}</name>`);
    for (const member of group.members) {
      const predefName = xmlPredefServiceMap.get(member);
      if (predefName) {
        lines.push('      <application>');
        lines.push(`        <name>${escapeXml(predefName)}</name>`);
        lines.push('      </application>');
      } else if (svcGroupNameSet.has(member)) {
        lines.push('      <application-set>');
        lines.push(`        <name>${escapeXml(sanitizeJunosName(member))}</name>`);
        lines.push('      </application-set>');
      } else {
        lines.push('      <application>');
        lines.push(`        <name>${escapeXml(sanitizeJunosName(member))}</name>`);
        lines.push('      </application>');
      }
    }
    lines.push('    </application-set>');
  }

  // Placeholder Customfwic applications for unmapped apps
  if (hasCustomfwic) {
    lines.push('    <!-- Placeholder applications (Customfwic) - REQUIRES MANUAL CONFIGURATION -->');
    for (const [customName, originalName] of customfwicMap) {
      lines.push('    <application>');
      lines.push(`      <name>${escapeXml(customName)}</name>`);
      lines.push('      <protocol>tcp</protocol>');
      lines.push('      <destination-port>0</destination-port>');
      lines.push(`      <description>Placeholder for ${escapeXml(originalName)} - REQUIRES MANUAL CONFIGURATION</description>`);
      lines.push('    </application>');
    }
  }

  lines.push('  </applications>');
}

// ---------------------------------------------------------------------------
// Schedulers XML Builder
// ---------------------------------------------------------------------------

function buildSchedulersXml(schedules, lines) {
  if (!schedules || schedules.length === 0) return;

  lines.push('  <schedulers>');

  for (const sched of schedules) {
    const name = sanitizeJunosName(sched.name);
    lines.push('    <scheduler>');
    lines.push(`      <name>${escapeXml(name)}</name>`);

    if (sched.type === 'recurring' && sched.days && sched.days.length > 0) {
      for (const day of sched.days) {
        lines.push(`      <${day.toLowerCase()}>`)
        if (sched.start) lines.push(`        <start-time>${escapeXml(sched.start)}</start-time>`);
        if (sched.end) lines.push(`        <stop-time>${escapeXml(sched.end)}</stop-time>`);
        lines.push(`      </${day.toLowerCase()}>`);
      }
    } else if (sched.type === 'onetime') {
      if (sched.start) lines.push(`      <start-date>${escapeXml(sched.start)}</start-date>`);
      if (sched.end) lines.push(`      <stop-date>${escapeXml(sched.end)}</stop-date>`);
    }

    lines.push('    </scheduler>');
  }

  lines.push('  </schedulers>');
}

// ---------------------------------------------------------------------------
// UTM XML Builder
// ---------------------------------------------------------------------------

function computeUtmMap(policies) {
  const utmPolicyMap = {};
  const utmProfiles = []; // { policyName, profiles: { type → mapped } }
  if (!policies) return { utmPolicyMap, utmProfiles };

  const utmTypes = ['virus', 'wildfire-analysis', 'url-filtering', 'file-blocking', 'email-filter',
    'application-control', 'dlp', 'dns-security', 'decryption', 'waf', 'casb', 'voip'];
  const comboMap = new Map();
  let idx = 0;

  for (const policy of policies) {
    const sp = policy.security_profiles || {};
    const utmP = {};
    for (const t of utmTypes) {
      if (t === 'file-blocking') continue; // Not supported in SRX conversion
      if (sp[t]) utmP[t] = sp[t];
    }
    if (Object.keys(utmP).length === 0) continue;

    const key = JSON.stringify(utmP);
    if (!comboMap.has(key)) {
      idx++;
      const pName = `utm-policy-${idx}`;
      const mapped = {};
      for (const [pt, pv] of Object.entries(utmP)) {
        mapped[pt] = mapProfileToSrx(pt, pv);
      }
      comboMap.set(key, { policyName: pName, profiles: mapped });
      utmProfiles.push({ policyName: pName, profiles: mapped });
    }
    utmPolicyMap[policy.name] = comboMap.get(key).policyName;
  }
  return { utmPolicyMap, utmProfiles };
}

function computeIdpMap(policies) {
  const idpPolicyMap = {};
  if (!policies) return { idpPolicyMap };

  const idpTypes = ['spyware', 'vulnerability'];
  const comboMap = new Map();
  let idx = 0;

  for (const policy of policies) {
    const sp = policy.security_profiles || {};
    const hasIdp = idpTypes.some(t => sp[t]);
    if (!hasIdp) continue;

    const idpP = {};
    for (const t of idpTypes) {
      if (sp[t]) idpP[t] = sp[t];
    }
    const key = JSON.stringify(idpP);
    if (!comboMap.has(key)) {
      idx++;
      comboMap.set(key, `idp-policy-${idx}`);
    }
    idpPolicyMap[policy.name] = comboMap.get(key);
  }
  return { idpPolicyMap };
}

function buildUtmXml(utmProfiles, lines) {
  if (!utmProfiles || utmProfiles.length === 0) return;

  lines.push('    <utm>');

  // Feature profiles
  const emitted = new Set();
  lines.push('      <!-- NOTE: Generated profiles use recommended defaults — review and customize -->');
  lines.push('      <feature-profile>');
  for (const combo of utmProfiles) {
    for (const mapped of Object.values(combo.profiles)) {
      if (mapped.srxFeature !== 'utm' || emitted.has(mapped.srxProfile)) continue;
      emitted.add(mapped.srxProfile);

      if (mapped.srxType === 'anti-virus') {
        lines.push('        <anti-virus>');
        lines.push(`          <profile>`);
        lines.push(`            <name>${escapeXml(mapped.srxProfile)}</name>`);
        lines.push('            <fallback-options><default>log-and-permit</default><content-size>log-and-permit</content-size></fallback-options>');
        lines.push('            <scan-options><content-size-limit>20000</content-size-limit><timeout>180</timeout></scan-options>');
        lines.push('          </profile>');
        lines.push('        </anti-virus>');
      } else if (mapped.srxType === 'web-filtering') {
        lines.push('        <web-filtering>');
        lines.push(`          <profile>`);
        lines.push(`            <name>${escapeXml(mapped.srxProfile)}</name>`);
        lines.push('            <type>juniper-enhanced</type>');
        lines.push('            <default>block</default>');
        lines.push('          </profile>');
        lines.push('        </web-filtering>');
      } else if (mapped.srxType === 'content-filtering') {
        lines.push('        <content-filtering>');
        lines.push(`          <profile>`);
        lines.push(`            <name>${escapeXml(mapped.srxProfile)}</name>`);
        lines.push('          </profile>');
        lines.push('        </content-filtering>');
      } else if (mapped.srxType === 'anti-spam') {
        lines.push('        <anti-spam>');
        lines.push(`          <profile>`);
        lines.push(`            <name>${escapeXml(mapped.srxProfile)}</name>`);
        lines.push('          </profile>');
        lines.push('        </anti-spam>');
      } else if (mapped.srxType === 'dns-security') {
        lines.push(`        <!-- DNS Security: configure SRX DNS Security (requires ATP license) -->`);
      }
    }
  }
  lines.push('      </feature-profile>');

  // UTM policies
  for (const combo of utmProfiles) {
    lines.push(`      <utm-policy name="${escapeXml(combo.policyName)}">`);
    for (const mapped of Object.values(combo.profiles)) {
      if (mapped.srxFeature !== 'utm') continue;
      if (mapped.srxType === 'anti-virus') {
        lines.push(`        <anti-virus><http-profile>${escapeXml(mapped.srxProfile)}</http-profile></anti-virus>`);
      } else if (mapped.srxType === 'web-filtering') {
        lines.push(`        <web-filtering><http-profile>${escapeXml(mapped.srxProfile)}</http-profile></web-filtering>`);
      } else if (mapped.srxType === 'content-filtering') {
        lines.push(`        <content-filtering><rule-set>${escapeXml(mapped.srxProfile)}</rule-set></content-filtering>`);
      } else if (mapped.srxType === 'anti-spam') {
        lines.push(`        <anti-spam><smtp-profile>${escapeXml(mapped.srxProfile)}</smtp-profile></anti-spam>`);
      }
    }
    lines.push('      </utm-policy>');
  }

  lines.push('    </utm>');
}

// ---------------------------------------------------------------------------
// IDP XML Builder
// ---------------------------------------------------------------------------

function buildIdpXml(policies, lines) {
  if (!policies) return;

  const idpTypes = ['spyware', 'vulnerability'];
  const comboMap = new Map();
  let idx = 0;

  for (const policy of policies) {
    const sp = policy.security_profiles || {};
    const hasIdp = idpTypes.some(t => sp[t]);
    if (!hasIdp) continue;

    const idpP = {};
    for (const t of idpTypes) {
      if (sp[t]) idpP[t] = sp[t];
    }
    const key = JSON.stringify(idpP);
    if (!comboMap.has(key)) {
      idx++;
      comboMap.set(key, { profiles: idpP, policyName: `idp-policy-${idx}` });
    }
  }

  if (comboMap.size === 0) return;

  lines.push('    <idp>');

  for (const [, combo] of comboMap) {
    lines.push(`      <idp-policy>`);
    lines.push(`        <name>${escapeXml(combo.policyName)}</name>`);
    lines.push('        <rulebase-ips>');

    let ruleIdx = 0;
    for (const [pType, pValue] of Object.entries(combo.profiles)) {
      ruleIdx++;
      const ruleName = `${pType}-rule-${ruleIdx}`;

      // Determine action from source profile name
      const nameLower = pValue.toLowerCase();
      let idpAction = 'recommended';
      if (nameLower.includes('strict') || nameLower.includes('critical')) {
        idpAction = 'drop-connection';
      } else if (nameLower.includes('alert') || nameLower.includes('monitor')) {
        idpAction = 'no-action';
      }

      lines.push('          <rule>');
      lines.push(`            <name>${escapeXml(ruleName)}</name>`);
      lines.push('            <match>');
      lines.push('              <attacks>');
      lines.push('                <predefined-attack-groups>Recommended</predefined-attack-groups>');
      lines.push('              </attacks>');
      lines.push('            </match>');
      lines.push('            <then>');
      lines.push(`              <action><${idpAction}/></action>`);
      lines.push('              <notification><log-attacks/></notification>');
      lines.push('            </then>');
      lines.push('          </rule>');
    }

    lines.push('        </rulebase-ips>');
    lines.push('      </idp-policy>');
  }

  lines.push('    </idp>');
}

// ---------------------------------------------------------------------------
// SecIntel XML Builder
// ---------------------------------------------------------------------------

function buildSecIntelXml(blockLists, lines) {
  if (!blockLists || blockLists.length === 0) return;

  lines.push('  <services>');
  lines.push('    <security-intelligence>');

  lines.push('      <profile>');
  lines.push('        <name>secIntel-profile</name>');
  lines.push('        <category>BlockList</category>');
  blockLists.forEach((bl, i) => {
    const ruleName = `secIntel-rule-${i + 1}`;
    lines.push(`        <rule>`);
    lines.push(`          <name>${escapeXml(ruleName)}</name>`);
    lines.push('          <match><threat-level>10</threat-level></match>');
    lines.push('          <then><action>block close</action><log/></then>');
    lines.push('        </rule>');
  });
  lines.push('      </profile>');

  lines.push('      <policy>');
  lines.push('        <name>secIntel-policy</name>');
  lines.push('        <profile>secIntel-profile</profile>');
  lines.push('      </policy>');

  lines.push('    </security-intelligence>');
  lines.push('  </services>');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Tracks unmapped apps for placeholder XML generation */
const xmlCustomfwicApps = new Map();

/** Tracks service objects that map to predefined Junos apps (XML path) */
const xmlPredefServiceMap = new Map();

function resolveApps(applications, services, warnings, policyName, appGroups = [], sourceVendor = '') {
  const resolved = [];
  const isSrxSource = sourceVendor === 'srx' || sourceVendor === 'greenfield' || sourceVendor === 'srx_healthcheck';

  // Helper to map a single app name to Junos (with Customfwic fallback)
  const mapSingleApp = (appName) => {
    // SRX→SRX: pass through as-is (already a Junos application name)
    if (isSrxSource) {
      resolved.push(appName);
      return;
    }
    const junos = mapAppToJunos(appName);
    if (junos) {
      resolved.push(junos);
    } else {
      const customName = sanitizeJunosName(appName) + 'Customfwic';
      resolved.push(customName);
      xmlCustomfwicApps.set(customName, appName);
      if (warnings) {
        warnings.push(createWarning(
          'warning',
          `policy/${policyName}`,
          `Application "${appName}" has no predefined Junos equivalent — using placeholder "${customName}"`,
          'Create a custom application on the SRX with the correct protocol/port definition for this application'
        ));
      }
    }
  };

  if (applications && applications.length > 0) {
    for (const app of applications) {
      if (app === 'any') { resolved.push('any'); continue; }

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
  if (services && services.length > 0) {
    for (const svc of services) {
      if (svc === 'application-default' || svc === 'any') continue;
      // Check if this service was mapped to a predefined app during buildApplicationsXml
      const predefName = xmlPredefServiceMap.get(svc);
      if (predefName) {
        resolved.push(predefName);
        continue;
      }
      const junos = mapAppToJunos(svc);
      if (junos) {
        resolved.push(junos);
      } else {
        resolved.push(sanitizeJunosName(svc));
      }
    }
  }
  if (resolved.length === 0) resolved.push('any');
  return [...new Set(resolved)];
}

// ---------------------------------------------------------------------------
// Static Routes XML Builder
// ---------------------------------------------------------------------------

function buildRoutingXml(config, lines) {
  const routes = config.static_routes || [];
  const bgpConfigs = config.bgp_config || [];
  const ospfConfigs = config.ospf_config || [];
  const ospf3Configs = config.ospf3_config || [];
  const evpnConfigs = config.evpn_config || [];
  const vxlanConfigs = config.vxlan_config || [];

  const globalRoutes = routes.filter(r => !r.vrf);
  const vrfGroups = {};
  for (const r of routes.filter(r => r.vrf)) {
    if (!vrfGroups[r.vrf]) vrfGroups[r.vrf] = [];
    vrfGroups[r.vrf].push(r);
  }

  // Find global BGP/OSPF/OSPFv3/EVPN (instance === '')
  const globalBgp = bgpConfigs.find(b => !b.instance);
  const globalOspf = ospfConfigs.find(o => !o.instance);
  const globalOspf3 = ospf3Configs.find(o => !o.instance);
  const globalEvpn = evpnConfigs.find(e => !e.instance);

  const hasGlobalRoutingOpts = globalRoutes.length > 0 || globalBgp;
  const hasGlobalProtocols = globalBgp || globalOspf || globalOspf3 || globalEvpn;

  // Global routing-options (static routes + BGP AS/router-id)
  if (hasGlobalRoutingOpts) {
    lines.push('  <routing-options>');

    // Autonomous system and router-id from BGP
    if (globalBgp) {
      if (globalBgp.local_as) {
        lines.push('    <autonomous-system>');
        lines.push(`      <as-number>${globalBgp.local_as}</as-number>`);
        lines.push('    </autonomous-system>');
      }
      if (globalBgp.router_id) {
        lines.push(`    <router-id>${escapeXml(globalBgp.router_id)}</router-id>`);
      }
    } else if (globalOspf?.router_id) {
      lines.push(`    <router-id>${escapeXml(globalOspf.router_id)}</router-id>`);
    }

    // Static routes
    if (globalRoutes.length > 0) {
      lines.push('    <static>');
      for (const route of globalRoutes) {
        lines.push('      <route>');
        lines.push(`        <name>${escapeXml(route.destination)}</name>`);
        if (route.next_hop_type === 'discard') {
          lines.push('        <discard/>');
        } else if (route.next_hop_type === 'next-vr' && route.next_hop) {
          lines.push(`        <next-table>${escapeXml(route.next_hop)}.inet.0</next-table>`);
        } else if (route.next_hop) {
          lines.push(`        <next-hop>${escapeXml(route.next_hop)}</next-hop>`);
        }
        if (route.metric && route.metric !== 10) {
          lines.push(`        <metric>${route.metric}</metric>`);
        }
        lines.push('      </route>');
      }
      lines.push('    </static>');
    }

    lines.push('  </routing-options>');
  }

  // Global protocols (BGP + OSPF)
  if (hasGlobalProtocols) {
    lines.push('  <protocols>');

    // BGP
    if (globalBgp) {
      lines.push('    <bgp>');
      for (const group of globalBgp.peer_groups || []) {
        lines.push('      <group>');
        lines.push(`        <name>${escapeXml(group.name)}</name>`);
        lines.push(`        <type>${escapeXml(group.type || 'external')}</type>`);
        for (const neighbor of group.neighbors || []) {
          lines.push('        <neighbor>');
          lines.push(`          <name>${escapeXml(neighbor.address)}</name>`);
          if (neighbor.peer_as) {
            lines.push(`          <peer-as>${neighbor.peer_as}</peer-as>`);
          }
          if (neighbor.description) {
            lines.push(`          <description>${escapeXml(neighbor.description)}</description>`);
          }
          if (neighbor.local_address) {
            lines.push(`          <local-address>${escapeXml(neighbor.local_address)}</local-address>`);
          }
          if (neighbor.import_policy) {
            lines.push(`          <import>${escapeXml(neighbor.import_policy)}</import>`);
          }
          if (neighbor.export_policy) {
            lines.push(`          <export>${escapeXml(neighbor.export_policy)}</export>`);
          }
          if (neighbor.authentication_key) {
            lines.push(`          <authentication-key>${escapeXml(neighbor.authentication_key)}</authentication-key>`);
          }
          lines.push('        </neighbor>');
        }
        lines.push('      </group>');
      }
      lines.push('    </bgp>');
    }

    // OSPF
    if (globalOspf) {
      lines.push('    <ospf>');
      if (globalOspf.reference_bandwidth) {
        lines.push(`      <reference-bandwidth>${escapeXml(String(globalOspf.reference_bandwidth))}</reference-bandwidth>`);
      }
      for (const area of globalOspf.areas || []) {
        lines.push('      <area>');
        lines.push(`        <name>${escapeXml(area.area_id)}</name>`);
        if (area.area_type === 'stub' || area.area_type === 'totally-stub') {
          lines.push('        <stub>');
          if (area.area_type === 'totally-stub') lines.push('          <no-summaries/>');
          lines.push('        </stub>');
        } else if (area.area_type === 'nssa' || area.area_type === 'totally-nssa') {
          lines.push('        <nssa>');
          if (area.area_type === 'totally-nssa') lines.push('          <no-summaries/>');
          lines.push('        </nssa>');
        }
        for (const iface of area.interfaces || []) {
          lines.push('        <interface>');
          lines.push(`          <name>${escapeXml(iface.name)}</name>`);
          if (iface.cost != null) lines.push(`          <metric>${iface.cost}</metric>`);
          if (iface.hello_interval != null) lines.push(`          <hello-interval>${iface.hello_interval}</hello-interval>`);
          if (iface.dead_interval != null) lines.push(`          <dead-interval>${iface.dead_interval}</dead-interval>`);
          if (iface.passive) lines.push('          <passive/>');
          if (iface.network_type) lines.push(`          <interface-type>${escapeXml(iface.network_type)}</interface-type>`);
          if (iface.authentication) {
            lines.push('          <authentication>');
            if (iface.authentication.type === 'md5') {
              lines.push('            <md5>');
              lines.push(`              <name>${iface.authentication.key_id || 1}</name>`);
              lines.push(`              <key>${escapeXml(iface.authentication.key || '')}</key>`);
              lines.push('            </md5>');
            } else if (iface.authentication.type === 'simple') {
              lines.push(`            <simple-password>${escapeXml(iface.authentication.key || '')}</simple-password>`);
            }
            lines.push('          </authentication>');
          }
          lines.push('        </interface>');
        }
        lines.push('      </area>');
      }
      for (const redist of globalOspf.redistribute || []) {
        const stmtName = `OSPF-REDIST-${redist.protocol.toUpperCase()}`;
        lines.push(`      <export>${escapeXml(stmtName)}</export>`);
      }
      lines.push('    </ospf>');
    }

    // OSPFv3
    if (globalOspf3) {
      lines.push('    <ospf3>');
      if (globalOspf3.reference_bandwidth) {
        lines.push(`      <reference-bandwidth>${escapeXml(String(globalOspf3.reference_bandwidth))}</reference-bandwidth>`);
      }
      for (const area of globalOspf3.areas || []) {
        lines.push('      <area>');
        lines.push(`        <name>${escapeXml(area.area_id)}</name>`);
        if (area.area_type === 'stub' || area.area_type === 'totally-stub') {
          lines.push('        <stub>');
          if (area.area_type === 'totally-stub') lines.push('          <no-summaries/>');
          lines.push('        </stub>');
        } else if (area.area_type === 'nssa' || area.area_type === 'totally-nssa') {
          lines.push('        <nssa>');
          if (area.area_type === 'totally-nssa') lines.push('          <no-summaries/>');
          lines.push('        </nssa>');
        }
        for (const iface of area.interfaces || []) {
          lines.push('        <interface>');
          lines.push(`          <name>${escapeXml(iface.name)}</name>`);
          if (iface.cost != null) lines.push(`          <metric>${iface.cost}</metric>`);
          if (iface.hello_interval != null) lines.push(`          <hello-interval>${iface.hello_interval}</hello-interval>`);
          if (iface.dead_interval != null) lines.push(`          <dead-interval>${iface.dead_interval}</dead-interval>`);
          if (iface.passive) lines.push('          <passive/>');
          if (iface.network_type) lines.push(`          <interface-type>${escapeXml(iface.network_type)}</interface-type>`);
          if (iface.instance_id != null) lines.push(`          <instance-id>${iface.instance_id}</instance-id>`);
          lines.push('        </interface>');
        }
        lines.push('      </area>');
      }
      for (const redist of globalOspf3.redistribute || []) {
        const stmtName = `OSPF3-REDIST-${redist.protocol.toUpperCase()}`;
        lines.push(`      <export>${escapeXml(stmtName)}</export>`);
      }
      lines.push('    </ospf3>');
    }

    // EVPN
    if (globalEvpn) {
      lines.push('    <evpn>');
      lines.push(`      <encapsulation>${escapeXml(globalEvpn.encapsulation || 'vxlan')}</encapsulation>`);
      if (globalEvpn.multicast_mode) {
        lines.push(`      <multicast-mode>${escapeXml(globalEvpn.multicast_mode)}</multicast-mode>`);
      }
      if (globalEvpn.extended_vni_list && globalEvpn.extended_vni_list.length > 0) {
        for (const vni of globalEvpn.extended_vni_list) {
          lines.push(`      <extended-vni-list>${vni}</extended-vni-list>`);
        }
      }
      lines.push('    </evpn>');
    }

    lines.push('  </protocols>');
  }

  // Switch-options (for EVPN/VxLAN — vtep-source-interface, route-distinguisher, vrf-target)
  if (globalEvpn && globalEvpn.route_distinguisher) {
    lines.push('  <switch-options>');
    lines.push(`    <vtep-source-interface>${escapeXml(globalEvpn.vtep_source_interface || 'lo0.0')}</vtep-source-interface>`);
    lines.push(`    <route-distinguisher>`);
    lines.push(`      <rd-type>${escapeXml(globalEvpn.route_distinguisher)}</rd-type>`);
    lines.push(`    </route-distinguisher>`);
    if (globalEvpn.vrf_target) {
      lines.push(`    <vrf-target>`);
      lines.push(`      <community>${escapeXml(globalEvpn.vrf_target)}</community>`);
      lines.push(`    </vrf-target>`);
    }
    lines.push('  </switch-options>');
  }

  // VLANs (for EVPN VxLAN VNI mappings)
  const allVlans = [
    ...(globalEvpn?.vlans || []),
    ...evpnConfigs.filter(e => e.instance).flatMap(e => e.vlans || []),
  ];
  if (allVlans.length > 0) {
    lines.push('  <vlans>');
    for (const vlan of allVlans) {
      const vlanName = sanitizeJunosName(vlan.name);
      lines.push(`    <vlan>`);
      lines.push(`      <name>${escapeXml(vlanName)}</name>`);
      lines.push(`      <vlan-id>${vlan.vlan_id}</vlan-id>`);
      lines.push('      <vxlan>');
      lines.push(`        <vni>${vlan.vni}</vni>`);
      if (vlan.ingress_node_replication) {
        lines.push('        <ingress-node-replication/>');
      }
      lines.push('      </vxlan>');
      lines.push('    </vlan>');
    }
    lines.push('  </vlans>');
  }

  // Routing instances (VRFs — static routes + per-instance BGP/OSPF/OSPFv3/EVPN)
  const instBgpMap = {};
  const instOspfMap = {};
  const instOspf3Map = {};
  const instEvpnMap = {};
  for (const b of bgpConfigs.filter(b => b.instance)) instBgpMap[b.instance] = b;
  for (const o of ospfConfigs.filter(o => o.instance)) instOspfMap[o.instance] = o;
  for (const o of ospf3Configs.filter(o => o.instance)) instOspf3Map[o.instance] = o;
  for (const e of evpnConfigs.filter(e => e.instance)) instEvpnMap[e.instance] = e;

  const allInstNames = new Set([
    ...Object.keys(vrfGroups),
    ...Object.keys(instBgpMap),
    ...Object.keys(instOspfMap),
    ...Object.keys(instOspf3Map),
    ...Object.keys(instEvpnMap),
  ]);

  if (allInstNames.size > 0) {
    lines.push('  <routing-instances>');
    for (const instName of allInstNames) {
      const name = sanitizeJunosName(instName);
      const instRoutes = vrfGroups[instName] || [];
      const instBgp = instBgpMap[instName];
      const instOspf = instOspfMap[instName];
      const instOspf3 = instOspf3Map[instName];
      const instEvpn = instEvpnMap[instName];

      lines.push('    <instance>');
      lines.push(`      <name>${escapeXml(name)}</name>`);
      const instType = instEvpn?.instance_type || 'virtual-router';
      lines.push(`      <instance-type>${escapeXml(instType)}</instance-type>`);

      // Routing-options (static + BGP AS/router-id)
      if (instRoutes.length > 0 || instBgp) {
        lines.push('      <routing-options>');
        if (instBgp?.local_as) {
          lines.push('        <autonomous-system>');
          lines.push(`          <as-number>${instBgp.local_as}</as-number>`);
          lines.push('        </autonomous-system>');
        }
        if (instBgp?.router_id || instOspf?.router_id) {
          lines.push(`        <router-id>${escapeXml(instBgp?.router_id || instOspf?.router_id)}</router-id>`);
        }
        if (instRoutes.length > 0) {
          lines.push('        <static>');
          for (const route of instRoutes) {
            lines.push('          <route>');
            lines.push(`            <name>${escapeXml(route.destination)}</name>`);
            if (route.next_hop_type === 'discard') {
              lines.push('            <discard/>');
            } else if (route.next_hop) {
              lines.push(`            <next-hop>${escapeXml(route.next_hop)}</next-hop>`);
            }
            lines.push('          </route>');
          }
          lines.push('        </static>');
        }
        lines.push('      </routing-options>');
      }

      // Protocols (BGP + OSPF + OSPFv3 + EVPN)
      if (instBgp || instOspf || instOspf3 || instEvpn) {
        lines.push('      <protocols>');
        if (instBgp) {
          lines.push('        <bgp>');
          for (const group of instBgp.peer_groups || []) {
            lines.push('          <group>');
            lines.push(`            <name>${escapeXml(group.name)}</name>`);
            lines.push(`            <type>${escapeXml(group.type || 'external')}</type>`);
            for (const neighbor of group.neighbors || []) {
              lines.push('            <neighbor>');
              lines.push(`              <name>${escapeXml(neighbor.address)}</name>`);
              if (neighbor.peer_as) lines.push(`              <peer-as>${neighbor.peer_as}</peer-as>`);
              if (neighbor.description) lines.push(`              <description>${escapeXml(neighbor.description)}</description>`);
              lines.push('            </neighbor>');
            }
            lines.push('          </group>');
          }
          lines.push('        </bgp>');
        }
        if (instOspf) {
          lines.push('        <ospf>');
          for (const area of instOspf.areas || []) {
            lines.push('          <area>');
            lines.push(`            <name>${escapeXml(area.area_id)}</name>`);
            for (const iface of area.interfaces || []) {
              lines.push('            <interface>');
              lines.push(`              <name>${escapeXml(iface.name)}</name>`);
              if (iface.cost != null) lines.push(`              <metric>${iface.cost}</metric>`);
              if (iface.passive) lines.push('              <passive/>');
              lines.push('            </interface>');
            }
            lines.push('          </area>');
          }
          lines.push('        </ospf>');
        }
        if (instOspf3) {
          lines.push('        <ospf3>');
          for (const area of instOspf3.areas || []) {
            lines.push('          <area>');
            lines.push(`            <name>${escapeXml(area.area_id)}</name>`);
            for (const iface of area.interfaces || []) {
              lines.push('            <interface>');
              lines.push(`              <name>${escapeXml(iface.name)}</name>`);
              if (iface.cost != null) lines.push(`              <metric>${iface.cost}</metric>`);
              if (iface.passive) lines.push('              <passive/>');
              if (iface.instance_id != null) lines.push(`              <instance-id>${iface.instance_id}</instance-id>`);
              lines.push('            </interface>');
            }
            lines.push('          </area>');
          }
          lines.push('        </ospf3>');
        }
        if (instEvpn) {
          lines.push('        <evpn>');
          lines.push(`          <encapsulation>${escapeXml(instEvpn.encapsulation || 'vxlan')}</encapsulation>`);
          if (instEvpn.multicast_mode) {
            lines.push(`          <multicast-mode>${escapeXml(instEvpn.multicast_mode)}</multicast-mode>`);
          }
          lines.push('        </evpn>');
        }
        lines.push('      </protocols>');
      }

      lines.push('    </instance>');
    }
    lines.push('  </routing-instances>');
  }
}

function buildVpnXml(tunnels, lines) {
  if (!tunnels || tunnels.length === 0) return;

  // IKE section
  lines.push('  <security>');
  lines.push('    <ike>');

  const emittedProposals = new Set();
  for (const vpn of tunnels) {
    // IKE proposal
    if (vpn.ike_proposal && !emittedProposals.has(vpn.ike_proposal.name)) {
      emittedProposals.add(vpn.ike_proposal.name);
      lines.push('      <proposal>');
      lines.push(`        <name>${escapeXml(vpn.ike_proposal.name)}</name>`);
      lines.push(`        <authentication-method>${vpn.ike_proposal.auth_method || 'pre-shared-keys'}</authentication-method>`);
      lines.push(`        <dh-group>${vpn.ike_proposal.dh_group || 'group14'}</dh-group>`);
      lines.push(`        <encryption-algorithm>${vpn.ike_proposal.encryption || 'aes-256-cbc'}</encryption-algorithm>`);
      lines.push(`        <authentication-algorithm>${vpn.ike_proposal.authentication || 'sha-256'}</authentication-algorithm>`);
      if (vpn.ike_proposal.lifetime) lines.push(`        <lifetime-seconds>${vpn.ike_proposal.lifetime}</lifetime-seconds>`);
      lines.push('      </proposal>');
    }

    // IKE gateway
    const gwName = vpn.ike_gateway?.name || `gw-${vpn.name}`;
    lines.push('      <gateway>');
    lines.push(`        <name>${escapeXml(gwName)}</name>`);
    if (vpn.ike_gateway?.address) lines.push(`        <address>${vpn.ike_gateway.address}</address>`);
    lines.push(`        <ike-policy>ike-pol-${escapeXml(vpn.name)}</ike-policy>`);
    if (vpn.ike_gateway?.ike_version === 'v2') lines.push('        <version>v2-only</version>');
    lines.push('      </gateway>');
  }
  lines.push('    </ike>');

  // IPsec section
  lines.push('    <ipsec>');
  const emittedIpsec = new Set();
  for (const vpn of tunnels) {
    if (vpn.ipsec_proposal && !emittedIpsec.has(vpn.ipsec_proposal.name)) {
      emittedIpsec.add(vpn.ipsec_proposal.name);
      lines.push('      <proposal>');
      lines.push(`        <name>${escapeXml(vpn.ipsec_proposal.name)}</name>`);
      lines.push(`        <protocol>${vpn.ipsec_proposal.protocol || 'esp'}</protocol>`);
      lines.push(`        <encryption-algorithm>${vpn.ipsec_proposal.encryption || 'aes-256-cbc'}</encryption-algorithm>`);
      lines.push(`        <authentication-algorithm>${vpn.ipsec_proposal.authentication || 'hmac-sha-256-128'}</authentication-algorithm>`);
      if (vpn.ipsec_proposal.lifetime) lines.push(`        <lifetime-seconds>${vpn.ipsec_proposal.lifetime}</lifetime-seconds>`);
      lines.push('      </proposal>');
    }

    // VPN definition
    lines.push('      <vpn>');
    lines.push(`        <name>${escapeXml(vpn.name)}</name>`);
    lines.push(`        <ike><gateway>${escapeXml(vpn.ike_gateway?.name || 'gw-' + vpn.name)}</gateway></ike>`);
    if (vpn.tunnel_interface) {
      const bindIf = vpn.tunnel_interface.startsWith('st0') ? vpn.tunnel_interface : 'st0.0';
      lines.push(`        <bind-interface>${bindIf}</bind-interface>`);
    }
    if (vpn.proxy_id && vpn.proxy_id.length > 0) {
      for (let i = 0; i < vpn.proxy_id.length; i++) {
        lines.push(`        <traffic-selector><name>ts${i + 1}</name>`);
        if (vpn.proxy_id[i].local) lines.push(`          <local-ip>${vpn.proxy_id[i].local}</local-ip>`);
        if (vpn.proxy_id[i].remote) lines.push(`          <remote-ip>${vpn.proxy_id[i].remote}</remote-ip>`);
        lines.push('        </traffic-selector>');
      }
    }
    lines.push('      </vpn>');
  }
  lines.push('    </ipsec>');
  lines.push('  </security>');
}

function buildScreenXml(screens, lines) {
  if (!screens || screens.length === 0) return;

  // Screen definitions go inside <security><screen>
  lines.push('  <security>');
  lines.push('    <screen>');

  for (const screen of screens) {
    const name = screen.name || 'default-screen';
    lines.push('      <ids-option>');
    lines.push(`        <name>${escapeXml(name)}</name>`);

    // ICMP
    if (screen.icmp && (screen.icmp.ping_death || screen.icmp.flood_threshold)) {
      lines.push('        <icmp>');
      if (screen.icmp.ping_death) lines.push('          <ping-death/>');
      if (screen.icmp.flood_threshold) lines.push(`          <flood><threshold>${screen.icmp.flood_threshold}</threshold></flood>`);
      lines.push('        </icmp>');
    }

    // TCP
    if (screen.tcp) {
      const hasTcp = screen.tcp.syn_flood_threshold || screen.tcp.land_attack || screen.tcp.winnuke || screen.tcp.tcp_no_flag;
      if (hasTcp) {
        lines.push('        <tcp>');
        if (screen.tcp.syn_flood_threshold) {
          lines.push('          <syn-flood>');
          const alarmVal = screen.tcp.syn_flood_alarm_threshold || Math.round(screen.tcp.syn_flood_threshold * 5) || 1024;
          lines.push(`            <alarm-threshold>${alarmVal}</alarm-threshold>`);
          lines.push(`            <attack-threshold>${screen.tcp.syn_flood_threshold}</attack-threshold>`);
          if (screen.tcp.syn_flood_timeout) lines.push(`            <timeout>${screen.tcp.syn_flood_timeout}</timeout>`);
          lines.push('          </syn-flood>');
        }
        if (screen.tcp.land_attack) lines.push('          <land/>');
        if (screen.tcp.winnuke) lines.push('          <winnuke/>');
        if (screen.tcp.tcp_no_flag) lines.push('          <tcp-no-flag/>');
        lines.push('        </tcp>');
      }
    }

    // UDP
    if (screen.udp && screen.udp.flood_threshold) {
      lines.push('        <udp>');
      lines.push(`          <flood><threshold>${screen.udp.flood_threshold}</threshold></flood>`);
      lines.push('        </udp>');
    }

    // IP
    if (screen.ip) {
      const hasIp = screen.ip.spoofing || screen.ip.source_route || screen.ip.tear_drop;
      if (hasIp) {
        lines.push('        <ip>');
        if (screen.ip.spoofing) lines.push('          <spoofing/>');
        if (screen.ip.source_route) lines.push('          <source-route-option/>');
        if (screen.ip.tear_drop) lines.push('          <tear-drop/>');
        lines.push('        </ip>');
      }
    }

    // Session limits
    if (screen.limit_session) {
      if (screen.limit_session.source_based || screen.limit_session.destination_based) {
        lines.push('        <limit-session>');
        if (screen.limit_session.source_based) lines.push(`          <source-ip-based>${screen.limit_session.source_based}</source-ip-based>`);
        if (screen.limit_session.destination_based) lines.push(`          <destination-ip-based>${screen.limit_session.destination_based}</destination-ip-based>`);
        lines.push('        </limit-session>');
      }
    }

    lines.push('      </ids-option>');
  }

  lines.push('    </screen>');
  lines.push('  </security>');
}

function buildHaXml(haConfig, lines) {
  if (!haConfig || !haConfig.enabled) return;

  if (haConfig.ha_type === 'mnha') {
    buildMnhaXml(haConfig, lines);
    return;
  }

  const clusterId = haConfig.group_id || 1;
  const pri = haConfig.priority || 200;
  const secPri = pri > 100 ? 100 : pri - 1;

  lines.push('  <chassis>');
  lines.push('    <cluster>');
  lines.push(`      <cluster-id>${clusterId}</cluster-id>`);

  // Redundancy group 0
  lines.push('      <redundancy-group>');
  lines.push('        <name>0</name>');
  lines.push(`        <node><name>0</name><priority>${pri}</priority></node>`);
  lines.push(`        <node><name>1</name><priority>${secPri}</priority></node>`);
  if (haConfig.preempt) lines.push('        <preempt/>');
  lines.push('      </redundancy-group>');

  // Redundancy group 1
  lines.push('      <redundancy-group>');
  lines.push('        <name>1</name>');
  lines.push(`        <node><name>0</name><priority>${pri}</priority></node>`);
  lines.push(`        <node><name>1</name><priority>${secPri}</priority></node>`);
  if (haConfig.preempt) lines.push('        <preempt/>');
  lines.push('      </redundancy-group>');

  lines.push('      <heartbeat-interval>1000</heartbeat-interval>');
  lines.push('      <heartbeat-threshold>3</heartbeat-threshold>');
  lines.push('    </cluster>');
  lines.push('  </chassis>');

  // Fabric interfaces
  for (const iface of (haConfig.ha_interfaces || [])) {
    const name = (iface.name || '').toLowerCase();
    if ((name === 'fab0' || name === 'fab1') && iface.interface) {
      lines.push('  <interfaces>');
      lines.push(`    <interface><name>${name}</name>`);
      lines.push(`      <fabric-options><member-interfaces><name>${escapeXml(iface.interface)}</name></member-interfaces></fabric-options>`);
      lines.push('    </interface>');
      lines.push('  </interfaces>');
    }
  }

  lines.push(`  <!-- Source HA: ${escapeXml(haConfig.description || haConfig.mode)} -->`);
  lines.push('  <!-- NOTE: Review chassis cluster config for target hardware -->');
}

function buildMnhaXml(haConfig, lines) {
  const localId = haConfig.local_id || 1;
  const peerId = haConfig.peer_id || 2;

  lines.push('  <chassis>');
  lines.push('    <high-availability>');

  // Local node
  lines.push('      <local-id>');
  lines.push(`        <id>${localId}</id>`);
  if (haConfig.local_ip) {
    lines.push(`        <local-ip>${escapeXml(haConfig.local_ip)}</local-ip>`);
  }
  lines.push('      </local-id>');

  // Peer node
  lines.push('      <peer-id>');
  lines.push(`        <id>${peerId}</id>`);
  if (haConfig.peer_ip) {
    lines.push(`        <peer-ip>${escapeXml(haConfig.peer_ip)}</peer-ip>`);
  }
  if (haConfig.icl_interface) {
    lines.push(`        <interface>${escapeXml(haConfig.icl_interface)}</interface>`);
  }
  if (haConfig.vpn_profile) {
    lines.push(`        <vpn-profile>${escapeXml(haConfig.vpn_profile)}</vpn-profile>`);
  }
  lines.push('        <liveness-detection>');
  lines.push(`          <minimum-interval>${haConfig.liveness_interval || 400}</minimum-interval>`);
  lines.push(`          <multiplier>${haConfig.liveness_multiplier || 5}</multiplier>`);
  lines.push('        </liveness-detection>');
  lines.push('      </peer-id>');

  // SRG0
  lines.push('      <services-redundancy-group>');
  lines.push('        <name>0</name>');
  lines.push(`        <peer-id>${peerId}</peer-id>`);
  lines.push('      </services-redundancy-group>');

  // SRG1
  lines.push('      <services-redundancy-group>');
  lines.push('        <name>1</name>');
  lines.push(`        <deployment-type>${escapeXml(haConfig.deployment_type || 'routing')}</deployment-type>`);
  lines.push(`        <peer-id>${peerId}</peer-id>`);
  lines.push(`        <activeness-priority>${haConfig.activeness_priority || 200}</activeness-priority>`);
  if (haConfig.preemption) {
    lines.push('        <preemption/>');
  }
  // Interface monitoring
  if (haConfig.monitoring) {
    for (const lg of (haConfig.monitoring.link_groups || [])) {
      if (lg.enabled && lg.interfaces) {
        for (const iface of lg.interfaces) {
          lines.push(`        <interface-monitor><name>${escapeXml(iface)}</name><weight>255</weight></interface-monitor>`);
        }
      }
    }
  }
  lines.push('      </services-redundancy-group>');

  lines.push('    </high-availability>');
  lines.push('  </chassis>');
  lines.push(`  <!-- MNHA: ${escapeXml(haConfig.description || haConfig.mode || 'active-passive')} -->`);
  lines.push('  <!-- NOTE: Review MNHA config — verify ICL, VPN profile, and SRG settings -->');
}

// ---------------------------------------------------------------------------
// Syslog XML Builder
// ---------------------------------------------------------------------------

function buildSyslogXml(syslogConfig, lines) {
  if (!syslogConfig || syslogConfig.length === 0) return;

  lines.push('  <system>');
  lines.push('    <syslog>');

  for (const srv of syslogConfig) {
    if (!srv.server || srv.transport === 'file') continue;

    lines.push('      <host>');
    lines.push(`        <name>${escapeXml(srv.server)}</name>`);
    lines.push('        <any><any/></any>');

    if (srv.port && srv.port !== 514) {
      lines.push(`        <port>${srv.port}</port>`);
    }

    if (srv.transport === 'tcp' || srv.transport === 'tls') {
      lines.push('        <transport><protocol>tcp</protocol></transport>');
    }

    if (srv.source_address) {
      lines.push(`        <source-address>${escapeXml(srv.source_address)}</source-address>`);
    }

    if (srv.structured_data) {
      lines.push('        <structured-data/>');
    }

    lines.push('      </host>');
  }

  lines.push('    </syslog>');
  lines.push('  </system>');
}


// ---------------------------------------------------------------------------
// SNMP XML Builder
// ---------------------------------------------------------------------------

function buildSnmpXml(snmpConfig, lines) {
  if (!snmpConfig || snmpConfig.length === 0) return;

  lines.push('  <snmp>');

  // Contact / location from first entry
  const contactEntry = snmpConfig.find(e => e.contact);
  const locationEntry = snmpConfig.find(e => e.location);
  if (contactEntry?.contact) {
    lines.push(`    <contact>${escapeXml(contactEntry.contact)}</contact>`);
  }
  if (locationEntry?.location) {
    lines.push(`    <location>${escapeXml(locationEntry.location)}</location>`);
  }

  for (const entry of snmpConfig) {
    if (entry.type === 'community') {
      lines.push('    <community>');
      lines.push(`      <name>${escapeXml(entry.name)}</name>`);
      const auth = entry.authorization === 'read-write' ? 'read-write' : 'read-only';
      lines.push(`      <authorization>${auth}</authorization>`);
      if (entry.clients && entry.clients.length > 0) {
        lines.push('      <clients>');
        for (const client of entry.clients) {
          lines.push(`        <name>${escapeXml(client)}</name>`);
        }
        lines.push('      </clients>');
      }
      lines.push('    </community>');
    }

    if (entry.type === 'trap-group') {
      lines.push('    <trap-group>');
      lines.push(`      <name>${escapeXml(entry.name)}</name>`);
      if (entry.version) {
        lines.push(`      <version>${escapeXml(entry.version)}</version>`);
      }
      for (const target of (entry.targets || [])) {
        lines.push(`      <targets><name>${escapeXml(target)}</name></targets>`);
      }
      for (const cat of (entry.categories || [])) {
        lines.push(`      <categories><${escapeXml(cat)}/></categories>`);
      }
      lines.push('    </trap-group>');
    }

    if (entry.type === 'v3-user') {
      const VALID_AUTH = ['md5', 'sha'];
      const VALID_PRIV = ['des', 'aes128'];
      lines.push('    <v3>');
      lines.push('      <usm>');
      lines.push('        <local-engine>');
      lines.push('          <user>');
      lines.push(`            <name>${escapeXml(entry.name)}</name>`);
      if (entry.auth_protocol && entry.auth_protocol !== 'none' && VALID_AUTH.includes(entry.auth_protocol)) {
        lines.push(`            <authentication-${entry.auth_protocol}/>`);
      }
      if (entry.privacy_protocol && entry.privacy_protocol !== 'none' && VALID_PRIV.includes(entry.privacy_protocol)) {
        lines.push(`            <privacy-${entry.privacy_protocol}/>`);
      }
      lines.push('          </user>');
      lines.push('        </local-engine>');
      lines.push('      </usm>');
      lines.push('    </v3>');
    }
  }

  lines.push('  </snmp>');
}


// ---------------------------------------------------------------------------
// AAA XML Builder
// ---------------------------------------------------------------------------

function buildAaaXml(aaaConfig, lines) {
  if (!aaaConfig || aaaConfig.length === 0) return;

  const radiusServers = aaaConfig.filter(e => e.type === 'radius' && e.server);
  const tacplusServers = aaaConfig.filter(e => e.type === 'tacplus' && e.server);
  const profiles = aaaConfig.filter(e => e.type === 'profile');
  const authOrders = aaaConfig.filter(e => e.type === 'auth-order');

  if (radiusServers.length > 0 || tacplusServers.length > 0 || authOrders.length > 0) {
    lines.push('  <system>');

    for (const srv of radiusServers) {
      lines.push('    <radius-server>');
      lines.push(`      <name>${escapeXml(srv.server)}</name>`);
      lines.push(`      <port>${srv.port || 1812}</port>`);
      if (srv.secret) {
        lines.push(`      <secret>${escapeXml(srv.secret)}</secret>`);
      }
      if (srv.timeout) {
        lines.push(`      <timeout>${srv.timeout}</timeout>`);
      }
      if (srv.source_address) {
        lines.push(`      <source-address>${escapeXml(srv.source_address)}</source-address>`);
      }
      lines.push('    </radius-server>');
    }

    for (const srv of tacplusServers) {
      lines.push('    <tacplus-server>');
      lines.push(`      <name>${escapeXml(srv.server)}</name>`);
      lines.push(`      <port>${srv.port || 49}</port>`);
      if (srv.secret) {
        lines.push(`      <secret>${escapeXml(srv.secret)}</secret>`);
      }
      if (srv.timeout) {
        lines.push(`      <timeout>${srv.timeout}</timeout>`);
      }
      if (srv.single_connection) {
        lines.push('      <single-connection/>');
      }
      lines.push('    </tacplus-server>');
    }

    for (const ao of authOrders) {
      if (ao.authentication_order) {
        for (const method of ao.authentication_order) {
          lines.push(`    <authentication-order>${escapeXml(method)}</authentication-order>`);
        }
      }
    }

    lines.push('  </system>');
  }

  if (profiles.length > 0) {
    lines.push('  <access>');
    for (const profile of profiles) {
      lines.push('    <profile>');
      lines.push(`      <name>${escapeXml(profile.name)}</name>`);
      if (profile.authentication_order) {
        for (const method of profile.authentication_order) {
          lines.push(`      <authentication-order>${escapeXml(method)}</authentication-order>`);
        }
      }
      lines.push('    </profile>');
    }
    lines.push('  </access>');
  }
}


// ---------------------------------------------------------------------------
// DHCP XML Builder
// ---------------------------------------------------------------------------

function buildDhcpXml(dhcpConfig, lines) {
  if (!dhcpConfig || dhcpConfig.length === 0) return;

  let hasRelay = false;
  let hasPool = false;

  for (const cfg of dhcpConfig) {
    if (cfg.type === 'relay') hasRelay = true;
    if (cfg.type === 'server' || cfg.type === 'pool') hasPool = true;
  }

  // DHCP Relay: forwarding-options
  if (hasRelay) {
    lines.push('  <forwarding-options>');
    lines.push('    <helpers>');
    lines.push('      <bootp>');
    for (const cfg of dhcpConfig) {
      if (cfg.type !== 'relay') continue;
      const iface = cfg.interface || 'ge-0/0/0.0';
      lines.push(`        <interface><name>${escapeXml(iface)}</name>`);
      for (const srv of (cfg.servers || [])) {
        lines.push(`          <server>${escapeXml(srv)}</server>`);
      }
      lines.push('        </interface>');
    }
    lines.push('      </bootp>');
    lines.push('    </helpers>');
    lines.push('  </forwarding-options>');
  }

  // DHCP Server: access address-assignment pool
  if (hasPool) {
    lines.push('  <access>');
    lines.push('    <address-assignment>');
    for (const cfg of dhcpConfig) {
      if (cfg.type !== 'server' && cfg.type !== 'pool') continue;
      const poolName = cfg.name || cfg.interface || 'dhcp-pool';
      lines.push(`      <pool><name>${escapeXml(poolName)}</name>`);
      lines.push('        <family><inet>');

      if (cfg.network) {
        lines.push(`          <network>${escapeXml(cfg.network)}</network>`);
      }

      if (cfg.ranges) {
        for (const range of cfg.ranges) {
          lines.push(`          <range><name>${escapeXml(range.name || 'range1')}</name>`);
          if (range.low) lines.push(`            <low>${range.low}</low>`);
          if (range.high) lines.push(`            <high>${range.high}</high>`);
          lines.push('          </range>');
        }
      }

      if (cfg.pools) {
        for (let i = 0; i < cfg.pools.length; i++) {
          const pool = cfg.pools[i];
          if (pool.includes('-')) {
            const [low, high] = pool.split('-');
            lines.push(`          <range><name>range${i + 1}</name><low>${low}</low><high>${high}</high></range>`);
          }
        }
      }

      const gw = cfg.gateway || cfg.router;
      const dns = cfg.dns_servers || [];
      if (gw || dns.length > 0) {
        lines.push('          <dhcp-attributes>');
        if (gw) lines.push(`            <router>${escapeXml(gw)}</router>`);
        for (const d of dns) {
          lines.push(`            <name-server>${escapeXml(d)}</name-server>`);
        }
        lines.push('          </dhcp-attributes>');
      }

      lines.push('        </inet></family>');
      lines.push('      </pool>');
    }
    lines.push('    </address-assignment>');
    lines.push('  </access>');
  }
}


// ---------------------------------------------------------------------------
// QoS / CoS XML Builder
// ---------------------------------------------------------------------------

function buildQosXml(qosConfig, lines) {
  if (!qosConfig || qosConfig.length === 0) return;

  lines.push('  <class-of-service>');

  for (const qos of qosConfig) {
    if (qos.type === 'scheduler') {
      lines.push('    <schedulers>');
      lines.push(`      <name>${escapeXml(qos.name)}</name>`);
      if (qos.transmit_rate) lines.push(`      <transmit-rate>${escapeXml(qos.transmit_rate)}</transmit-rate>`);
      if (qos.buffer_size) lines.push(`      <buffer-size>${escapeXml(qos.buffer_size)}</buffer-size>`);
      if (qos.priority) lines.push(`      <priority>${escapeXml(qos.priority)}</priority>`);
      lines.push('    </schedulers>');
    } else if (qos.type === 'interface-cos') {
      lines.push('    <interfaces>');
      lines.push(`      <interface><name>${escapeXml(qos.interface)}</name>`);
      if (qos.scheduler_map) lines.push(`        <scheduler-map>${escapeXml(qos.scheduler_map)}</scheduler-map>`);
      if (qos.shaping_rate) lines.push(`        <shaping-rate>${escapeXml(qos.shaping_rate)}</shaping-rate>`);
      lines.push('      </interface>');
      lines.push('    </interfaces>');
    } else {
      // Generic scheduler-map from PAN-OS/FortiGate/Cisco
      const classes = qos.classes || [];
      if (classes.length > 0) {
        lines.push('    <scheduler-maps>');
        lines.push(`      <name>${escapeXml(qos.name)}</name>`);
        for (const cls of classes) {
          const clsName = cls.name || 'default';
          lines.push(`      <forwarding-class><class-name>${escapeXml(clsName)}</class-name>`);
          lines.push(`        <scheduler>${escapeXml(clsName)}</scheduler>`);
          lines.push('      </forwarding-class>');
        }
        lines.push('    </scheduler-maps>');

        // Emit scheduler definitions for each class
        for (const cls of classes) {
          const clsName = cls.name || 'default';
          lines.push('    <schedulers>');
          lines.push(`      <name>${escapeXml(clsName)}</name>`);
          if (cls.guaranteed_bandwidth || cls.maximum_bandwidth || cls.police_rate) {
            lines.push(`      <transmit-rate>${cls.police_rate || cls.maximum_bandwidth || cls.guaranteed_bandwidth}</transmit-rate>`);
          }
          if (cls.priority === true || cls.priority === 'high') {
            lines.push('      <priority>high</priority>');
          }
          lines.push('    </schedulers>');
        }
      }
    }
  }

  lines.push('  </class-of-service>');
}


// ---------------------------------------------------------------------------
// L2 / Bridge Domains / Virtual-Wire
// ---------------------------------------------------------------------------

function buildL2Xml(config, lines, interfaceMappings = {}) {
  const bridgeDomains = config.bridge_domains || [];
  const l2Interfaces = config.l2_interfaces || [];
  const vwirePairs = config.vwire_pairs || [];

  if (bridgeDomains.length === 0 && l2Interfaces.length === 0 && vwirePairs.length === 0) return;

  lines.push('  <!-- L2 / Bridge Domains -->');
  lines.push('  <bridge-domains>');

  // Explicit bridge domains
  for (const bd of bridgeDomains) {
    const bdName = sanitizeJunosName(bd.name);
    lines.push('    <domain>');
    lines.push(`      <name>${escapeXml(bdName)}</name>`);
    lines.push('      <domain-type>bridge</domain-type>');
    if (bd.vlan_id) lines.push(`      <vlan-id>${escapeXml(String(bd.vlan_id))}</vlan-id>`);
    if (bd.irb_interface) lines.push(`      <routing-interface>${escapeXml(bd.irb_interface)}</routing-interface>`);
    lines.push('    </domain>');
  }

  // Virtual-wire bridge domains
  for (const vw of vwirePairs) {
    const bdName = sanitizeJunosName(`vwire-${vw.name}`);
    lines.push('    <domain>');
    lines.push(`      <name>${escapeXml(bdName)}</name>`);
    lines.push('      <domain-type>bridge</domain-type>');
    if (vw.tag_allowed && vw.tag_allowed.length === 1 && vw.tag_allowed[0] !== '0') {
      lines.push(`      <vlan-id>${escapeXml(String(vw.tag_allowed[0]))}</vlan-id>`);
    }
    if (vw.tag_allowed && vw.tag_allowed.length > 1) {
      lines.push(`      <vlan-id-list>${escapeXml(vw.tag_allowed.join(' '))}</vlan-id-list>`);
    }
    lines.push('    </domain>');
  }

  lines.push('  </bridge-domains>');

  // Interface family bridge assignments for resolved vwire interfaces
  const bridgeInterfaces = [];
  for (const vw of vwirePairs) {
    const bdName = sanitizeJunosName(`vwire-${vw.name}`);
    for (const srcIf of [vw.interface1, vw.interface2]) {
      let srxName = srcIf;
      if (interfaceMappings[srcIf]) {
        srxName = interfaceMappings[srcIf];
        if (!srxName.includes('.')) srxName += '.0';
      } else {
        const base = srcIf.split('.')[0];
        if (interfaceMappings[base]) {
          srxName = `${interfaceMappings[base].split('.')[0]}.0`;
        }
      }
      // Only emit if actually mapped (not the original name)
      const origNorm = srcIf.includes('.') ? srcIf : `${srcIf}.0`;
      if (srxName !== origNorm) {
        bridgeInterfaces.push({ srxName, bdName, vlanList: vw.tag_allowed });
      }
    }
  }
  for (const l2if of l2Interfaces) {
    const parts = l2if.name.match(/^(.+?)\.(\d+)$/);
    const srxName = parts ? l2if.name : `${l2if.name}.0`;
    bridgeInterfaces.push({ srxName, bdName: l2if.bridge_domain });
  }

  if (bridgeInterfaces.length > 0) {
    lines.push('  <!-- L2 Interface Assignments -->');
    lines.push('  <interfaces>');
    for (const bi of bridgeInterfaces) {
      const [baseName, unitNum = '0'] = bi.srxName.split('.');
      lines.push('    <interface>');
      lines.push(`      <name>${escapeXml(baseName)}</name>`);
      lines.push('      <unit>');
      lines.push(`        <name>${escapeXml(unitNum)}</name>`);
      lines.push('        <family>');
      lines.push('          <bridge>');
      if (bi.vlanList && bi.vlanList.length > 1) {
        lines.push('            <interface-mode>trunk</interface-mode>');
        lines.push(`            <vlan-id-list>${escapeXml(bi.vlanList.join(' '))}</vlan-id-list>`);
      } else if (bi.bdName) {
        lines.push(`            <bridge-domain-name>${escapeXml(sanitizeJunosName(bi.bdName))}</bridge-domain-name>`);
      }
      lines.push('          </bridge>');
      lines.push('        </family>');
      lines.push('      </unit>');
      lines.push('    </interface>');
    }
    lines.push('  </interfaces>');
  }
}


// ---------------------------------------------------------------------------
// Policy-Based Forwarding (Filter-Based Forwarding)
// ---------------------------------------------------------------------------

function buildPbfXml(pbfRules, lines, interfaceMappings = {}) {
  if (!pbfRules || pbfRules.length === 0) return;

  const activeRules = pbfRules.filter(r => !r.disabled);
  if (activeRules.length === 0) return;

  // Collect routing instances (type forwarding)
  const instances = new Map();
  for (const rule of activeRules) {
    if (rule.action === 'forward' && rule.next_hop_value) {
      if (!instances.has(rule.next_hop_value)) {
        instances.set(rule.next_hop_value, sanitizeJunosName(`PBF-${rule.name}`));
      }
    }
  }

  // Emit routing-instances for PBF
  if (instances.size > 0) {
    lines.push('  <!-- PBF Routing Instances -->');
    lines.push('  <routing-instances>');
    for (const [nextHop, instName] of instances) {
      const defaultRoute = nextHop.includes(':') ? '::/0' : '0.0.0.0/0';
      lines.push('    <instance>');
      lines.push(`      <name>${escapeXml(instName)}</name>`);
      lines.push('      <instance-type>forwarding</instance-type>');
      lines.push('      <routing-options>');
      lines.push('        <static>');
      lines.push('          <route>');
      lines.push(`            <name>${escapeXml(defaultRoute)}</name>`);
      lines.push(`            <next-hop>${escapeXml(nextHop)}</next-hop>`);
      lines.push('          </route>');
      lines.push('        </static>');
      lines.push('      </routing-options>');
      lines.push('    </instance>');
    }
    lines.push('  </routing-instances>');
  }

  // Emit firewall filter
  lines.push('  <!-- PBF Firewall Filter -->');
  lines.push('  <firewall>');
  lines.push('    <filter>');
  lines.push('      <name>PBF-FILTER</name>');

  for (const rule of activeRules) {
    const termName = sanitizeJunosName(rule.name);
    lines.push('      <term>');
    lines.push(`        <name>${escapeXml(termName)}</name>`);

    // from clause
    const hasSrc = (rule.src_addresses || []).some(a => a !== 'any');
    const hasDst = (rule.dst_addresses || []).some(a => a !== 'any');
    if (hasSrc || hasDst) {
      lines.push('        <from>');
      for (const src of (rule.src_addresses || []).filter(a => a !== 'any')) {
        lines.push(`          <source-address>${escapeXml(src)}</source-address>`);
      }
      for (const dst of (rule.dst_addresses || []).filter(a => a !== 'any')) {
        lines.push(`          <destination-address>${escapeXml(dst)}</destination-address>`);
      }
      lines.push('        </from>');
    }

    // then clause
    lines.push('        <then>');
    if (rule.action === 'forward' && rule.next_hop_value) {
      const instName = instances.get(rule.next_hop_value);
      lines.push(`          <routing-instance>${escapeXml(instName)}</routing-instance>`);
    } else if (rule.action === 'discard') {
      lines.push('          <discard/>');
    } else {
      lines.push('          <accept/>');
    }
    lines.push('        </then>');
    lines.push('      </term>');
  }

  // Default accept term
  lines.push('      <term>');
  lines.push('        <name>default</name>');
  lines.push('        <then><accept/></then>');
  lines.push('      </term>');
  lines.push('    </filter>');
  lines.push('  </firewall>');
}


// ---------------------------------------------------------------------------
// SSL Proxy / PKI XML
// ---------------------------------------------------------------------------

/**
 * Builds SSL proxy profile and PKI ca-profile XML from decryption rules.
 */
function buildSslProxyXml(config, lines) {
  const decryptionRules = config.decryption_rules || [];
  const hasDecryptPolicies = (config.security_policies || []).some(p => p._srx_decrypt);
  const hasDecryptRules = decryptionRules.some(r => r.action === 'decrypt');

  if (!hasDecryptRules && !hasDecryptPolicies) return;

  // Collect profiles
  const fwdProxyProfiles = new Set();
  const inboundProfiles = new Map();

  for (const rule of decryptionRules) {
    if (rule.disabled) continue;
    if (rule.action === 'decrypt' || rule.action === 'decrypt-and-forward') {
      if (rule.decryption_type === 'ssl-forward-proxy') {
        fwdProxyProfiles.add(rule.decryption_profile
          ? sanitizeJunosName(`ssl-fwd-${rule.decryption_profile}`)
          : 'ssl-fwd-proxy');
      } else if (rule.decryption_type === 'ssl-inbound-inspection') {
        const pName = rule.decryption_profile
          ? sanitizeJunosName(`ssl-inbound-${rule.decryption_profile}`)
          : 'ssl-inbound-proxy';
        inboundProfiles.set(pName, rule.ssl_certificate || 'SERVER-CERT');
      } else if (rule.decryption_type !== 'ssh-proxy') {
        fwdProxyProfiles.add('ssl-fwd-proxy');
      }
    }
  }

  if (fwdProxyProfiles.size === 0 && hasDecryptPolicies) {
    fwdProxyProfiles.add('ssl-fwd-proxy');
  }

  if (fwdProxyProfiles.size === 0 && inboundProfiles.size === 0) return;

  // PKI ca-profile (inside <security>)
  if (fwdProxyProfiles.size > 0) {
    lines.push('  <!-- PKI CA Profile for SSL Forward Proxy -->');
    lines.push('  <security>');
    lines.push('    <pki>');
    lines.push('      <ca-profile>');
    lines.push('        <name>FPIC-CA</name>');
    lines.push('        <ca-identity>FPIC-CA</ca-identity>');
    lines.push('      </ca-profile>');
    lines.push('    </pki>');
    lines.push('  </security>');
  }

  // Services SSL proxy profiles
  lines.push('  <!-- SSL Proxy Profiles -->');
  lines.push('  <services>');
  lines.push('    <ssl>');
  lines.push('      <proxy>');

  for (const profileName of fwdProxyProfiles) {
    lines.push('        <profile>');
    lines.push(`          <name>${escapeXml(profileName)}</name>`);
    lines.push('          <root-ca>FPIC-CA</root-ca>');
    lines.push('          <protocol-version>tls12-and-above</protocol-version>');
    lines.push('          <actions>');
    lines.push('            <log/>');
    lines.push('            <crl-disable/>');
    lines.push('          </actions>');
    lines.push('        </profile>');
  }

  for (const [profileName, certName] of inboundProfiles) {
    lines.push('        <profile>');
    lines.push(`          <name>${escapeXml(profileName)}</name>`);
    lines.push(`          <server-certificate>${escapeXml(certName)}</server-certificate>`);
    lines.push('          <protocol-version>tls12-and-above</protocol-version>');
    lines.push('          <actions>');
    lines.push('            <log/>');
    lines.push('          </actions>');
    lines.push('        </profile>');
  }

  lines.push('      </proxy>');
  lines.push('    </ssl>');
  lines.push('  </services>');
}


// ---------------------------------------------------------------------------
// Flow Monitoring XML (Inline Jflow)
// ---------------------------------------------------------------------------

/**
 * Builds SRX inline-jflow XML configuration from flow monitoring config.
 */
function buildFlowMonitoringXml(flowConfig, lines) {
  if (!flowConfig || !flowConfig.collectors || flowConfig.collectors.length === 0) return;

  const instanceName = flowConfig.instance_name || 'FLOW-SAMPLE';
  const sampling = flowConfig.sampling || {};
  const rate = sampling.input_rate || 1000;
  const templates = flowConfig.templates || [];

  // forwarding-options > sampling
  lines.push('  <!-- Flow Monitoring (Inline Jflow) -->');
  lines.push('  <forwarding-options>');
  lines.push('    <sampling>');
  lines.push('      <instance>');
  lines.push(`        <name>${escapeXml(instanceName)}</name>`);
  lines.push('        <input>');
  lines.push(`          <rate>${rate}</rate>`);
  lines.push('        </input>');
  lines.push('        <family>');
  lines.push('          <inet>');
  lines.push('            <output>');

  for (let i = 0; i < flowConfig.collectors.length; i++) {
    const collector = flowConfig.collectors[i];
    const tpl = templates[i] || { name: `flow-tpl-${i + 1}` };
    const tplName = sanitizeJunosName(tpl.name);
    const isIpfix = !collector.protocol || collector.protocol === 'ipfix' || collector.protocol === 'netflow-v10';

    lines.push('              <flow-server>');
    lines.push(`                <name>${escapeXml(collector.address)}</name>`);
    lines.push(`                <port>${collector.port || 2055}</port>`);
    if (isIpfix) {
      lines.push('                <version-ipfix>');
      lines.push(`                  <template>${escapeXml(tplName)}</template>`);
      lines.push('                </version-ipfix>');
    } else {
      lines.push('                <version9>');
      lines.push(`                  <template>${escapeXml(tplName)}</template>`);
      lines.push('                </version9>');
    }
    lines.push('              </flow-server>');
  }

  // Inline jflow source address
  const srcAddr = flowConfig.collectors.find(c => c.source_address)?.source_address;
  if (srcAddr) {
    lines.push('              <inline-jflow>');
    lines.push(`                <source-address>${escapeXml(srcAddr)}</source-address>`);
    lines.push('              </inline-jflow>');
  }

  lines.push('            </output>');
  lines.push('          </inet>');
  lines.push('        </family>');
  lines.push('      </instance>');
  lines.push('    </sampling>');
  lines.push('  </forwarding-options>');

  // services > flow-monitoring templates
  if (templates.length > 0) {
    lines.push('  <services>');
    lines.push('    <flow-monitoring>');

    for (const tpl of templates) {
      const tplName = sanitizeJunosName(tpl.name);
      lines.push('      <version-ipfix>');
      lines.push('        <template>');
      lines.push(`          <name>${escapeXml(tplName)}</name>`);
      lines.push(`          <flow-active-timeout>${tpl.active_timeout || 60}</flow-active-timeout>`);
      lines.push('          <template-refresh-rate>');
      lines.push(`            <packets>${tpl.refresh_rate || 1000}</packets>`);
      lines.push('          </template-refresh-rate>');
      if (tpl.flow_type === 'ipv6') {
        lines.push('          <ipv6-template/>');
      }
      lines.push('        </template>');
      lines.push('      </version-ipfix>');
    }

    lines.push('    </flow-monitoring>');
    lines.push('  </services>');
  }
}


// ---------------------------------------------------------------------------
// System Configuration (Day-0)
// ---------------------------------------------------------------------------

function buildInterfaceAddressesXml(interfaces, lines, interfaceMappings = {}, indent = '  ') {
  if (!interfaces || interfaces.length === 0) return;

  const withAddrs = interfaces.filter(i => i.ip || i.ipv6);
  if (withAddrs.length === 0) return;

  lines.push(`${indent}<!-- Interface Addresses -->`);
  lines.push(`${indent}<interfaces>`);

  for (const iface of withAddrs) {
    // Map source interface name to SRX name
    let srxName = iface.name || '';
    if (interfaceMappings[srxName]) {
      srxName = interfaceMappings[srxName];
      if (!srxName.includes('.')) srxName += '.0';
    } else {
      const base = srxName.split('.')[0];
      const unit = srxName.includes('.') ? srxName.split('.')[1] : null;
      if (interfaceMappings[base]) {
        srxName = `${interfaceMappings[base].split('.')[0]}.${unit || '0'}`;
      }
    }

    const [baseName, unitNum = '0'] = srxName.split('.');
    lines.push(`${indent}  <interface>`);
    lines.push(`${indent}    <name>${escapeXml(baseName)}</name>`);
    lines.push(`${indent}    <unit>`);
    lines.push(`${indent}      <name>${escapeXml(unitNum)}</name>`);
    if (iface.description) {
      lines.push(`${indent}      <description>${escapeXml(iface.description)}</description>`);
    }
    if (iface.ip) {
      lines.push(`${indent}      <family>`);
      lines.push(`${indent}        <inet>`);
      lines.push(`${indent}          <address><name>${escapeXml(iface.ip)}</name></address>`);
      lines.push(`${indent}        </inet>`);
      if (iface.ipv6) {
        lines.push(`${indent}        <inet6>`);
        lines.push(`${indent}          <address><name>${escapeXml(iface.ipv6)}</name></address>`);
        lines.push(`${indent}        </inet6>`);
      }
      lines.push(`${indent}      </family>`);
    } else if (iface.ipv6) {
      lines.push(`${indent}      <family>`);
      lines.push(`${indent}        <inet6>`);
      lines.push(`${indent}          <address><name>${escapeXml(iface.ipv6)}</name></address>`);
      lines.push(`${indent}        </inet6>`);
      lines.push(`${indent}      </family>`);
    }
    lines.push(`${indent}    </unit>`);
    lines.push(`${indent}  </interface>`);
  }

  lines.push(`${indent}</interfaces>`);
}

function buildSystemConfigXml(systemConfig, lines, indent = '  ') {
  if (!systemConfig) return;

  const hasContent = systemConfig.hostname || systemConfig.domain_name ||
    (systemConfig.dns_servers && systemConfig.dns_servers.length > 0) ||
    (systemConfig.ntp_servers && systemConfig.ntp_servers.length > 0) ||
    systemConfig.timezone || systemConfig.login_banner;

  if (!hasContent) return;

  lines.push(`${indent}<!-- System Configuration (Day-0) -->`);
  lines.push(`${indent}<system>`);

  if (systemConfig.hostname) {
    lines.push(`${indent}  <host-name>${escapeXml(systemConfig.hostname)}</host-name>`);
  }
  if (systemConfig.domain_name) {
    lines.push(`${indent}  <domain-name>${escapeXml(systemConfig.domain_name)}</domain-name>`);
  }
  for (const dns of (systemConfig.dns_servers || [])) {
    lines.push(`${indent}  <name-server><name>${escapeXml(dns)}</name></name-server>`);
  }
  if (systemConfig.timezone) {
    lines.push(`${indent}  <time-zone>${escapeXml(systemConfig.timezone)}</time-zone>`);
  }
  if (systemConfig.login_banner) {
    lines.push(`${indent}  <login>`);
    lines.push(`${indent}    <message>${escapeXml(systemConfig.login_banner)}</message>`);
    lines.push(`${indent}  </login>`);
  }

  const mgmt = systemConfig.management_services || {};
  if (mgmt.ssh || mgmt.https || mgmt.netconf) {
    lines.push(`${indent}  <services>`);
    if (mgmt.ssh) lines.push(`${indent}    <ssh/>`);
    if (mgmt.https) {
      lines.push(`${indent}    <web-management>`);
      lines.push(`${indent}      <https><system-generated-certificate/></https>`);
      lines.push(`${indent}    </web-management>`);
    }
    if (mgmt.netconf) {
      lines.push(`${indent}    <netconf><ssh/></netconf>`);
    }
    lines.push(`${indent}  </services>`);
  }

  if (systemConfig.ntp_servers && systemConfig.ntp_servers.length > 0) {
    lines.push(`${indent}  <ntp>`);
    for (const ntp of systemConfig.ntp_servers) {
      lines.push(`${indent}    <server><name>${escapeXml(ntp)}</name></server>`);
    }
    lines.push(`${indent}  </ntp>`);
  }

  lines.push(`${indent}</system>`);
}

// ---------------------------------------------------------------------------
// Multi-Firewall Merge XML Builder
// ---------------------------------------------------------------------------

/**
 * Builds a merged Junos XML configuration from multiple config slots,
 * each wrapped in a logical-system section.
 *
 * @param {Array<{lsName: string, intermediateConfig: Object, interfaceMappings: Object}>} configSlots
 * @param {Array<{ls1: string, ls2: string, sharedZone: string, lt1Unit: number, lt2Unit: number}>} crossLsLinks
 * @param {Object} globalConfig - Chassis-level config
 * @returns {{ xml: string, warnings: Object[], summary: Object }}
 */
export function buildMergedSrxXml(configSlots, crossLsLinks = [], globalConfig = {}) {
  const allLines = [];
  const allWarnings = [];
  const perLsSummaries = [];

  allLines.push('<?xml version="1.0" encoding="UTF-8"?>');
  allLines.push(`<!-- Multi-Firewall Merge: ${configSlots.map(s => s.lsName).join(', ')} -->`);
  allLines.push('<configuration>');

  // Per-LS sections
  for (const slot of configSlots) {
    const ctx = { type: 'logical-system', name: slot.lsName };
    const result = buildSrxXml(
      slot.intermediateConfig,
      slot.interfaceMappings || {},
      ctx,
      { omitConfigurationWrapper: true }
    );
    allLines.push('');
    allLines.push(`  <!-- Logical-System: ${escapeXml(slot.lsName)} -->`);
    allLines.push(result.xml);
    allWarnings.push(...result.warnings.map(w => ({ ...w, _ls: slot.lsName })));
    perLsSummaries.push({ lsName: slot.lsName });
  }

  // Cross-LS lt- tunnel interfaces
  if (crossLsLinks.length > 0) {
    allLines.push('');
    allLines.push('  <!-- Cross-Logical-System Tunnel Interfaces (lt-) -->');
    for (const link of crossLsLinks) {
      const ls1 = escapeXml(sanitizeJunosName(link.ls1));
      const ls2 = escapeXml(sanitizeJunosName(link.ls2));
      const zone = escapeXml(sanitizeJunosName(link.sharedZone));
      const u1 = link.lt1Unit;
      const u2 = link.lt2Unit;

      // Side A lt- interface in LS1
      allLines.push(`  <logical-systems>`);
      allLines.push(`    <name>${ls1}</name>`);
      allLines.push(`    <interfaces>`);
      allLines.push(`      <interface>`);
      allLines.push(`        <name>lt-0/0/0</name>`);
      allLines.push(`        <unit>`);
      allLines.push(`          <name>${u1}</name>`);
      allLines.push(`          <encapsulation>ethernet</encapsulation>`);
      allLines.push(`          <peer-unit>${u2}</peer-unit>`);
      allLines.push(`          <family><inet/></family>`);
      allLines.push(`        </unit>`);
      allLines.push(`      </interface>`);
      allLines.push(`    </interfaces>`);
      allLines.push(`    <security>`);
      allLines.push(`      <zones>`);
      allLines.push(`        <security-zone>`);
      allLines.push(`          <name>${zone}</name>`);
      allLines.push(`          <interfaces>`);
      allLines.push(`            <name>lt-0/0/0.${u1}</name>`);
      allLines.push(`          </interfaces>`);
      allLines.push(`        </security-zone>`);
      allLines.push(`      </zones>`);
      allLines.push(`    </security>`);
      allLines.push(`  </logical-systems>`);

      // Side B lt- interface in LS2
      allLines.push(`  <logical-systems>`);
      allLines.push(`    <name>${ls2}</name>`);
      allLines.push(`    <interfaces>`);
      allLines.push(`      <interface>`);
      allLines.push(`        <name>lt-0/0/0</name>`);
      allLines.push(`        <unit>`);
      allLines.push(`          <name>${u2}</name>`);
      allLines.push(`          <encapsulation>ethernet</encapsulation>`);
      allLines.push(`          <peer-unit>${u1}</peer-unit>`);
      allLines.push(`          <family><inet/></family>`);
      allLines.push(`        </unit>`);
      allLines.push(`      </interface>`);
      allLines.push(`    </interfaces>`);
      allLines.push(`    <security>`);
      allLines.push(`      <zones>`);
      allLines.push(`        <security-zone>`);
      allLines.push(`          <name>${zone}</name>`);
      allLines.push(`          <interfaces>`);
      allLines.push(`            <name>lt-0/0/0.${u2}</name>`);
      allLines.push(`          </interfaces>`);
      allLines.push(`        </security-zone>`);
      allLines.push(`      </zones>`);
      allLines.push(`    </security>`);
      allLines.push(`  </logical-systems>`);
    }
  }

  allLines.push('</configuration>');

  const summary = {
    logical_systems: configSlots.length,
    cross_ls_links: crossLsLinks.length,
    per_ls: perLsSummaries,
  };

  return { xml: allLines.join('\n'), warnings: allWarnings, summary };
}

function escapeXml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

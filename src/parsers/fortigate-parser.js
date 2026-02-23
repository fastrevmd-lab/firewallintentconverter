/**
 * FortiGate / FortiOS Configuration Parser
 * ==========================================
 *
 * Parses FortiOS configurations (config/edit/set/next/end block format)
 * into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - System zones and interfaces
 *   - Address objects (ipmask, iprange, fqdn, wildcard, geography, wildcard-fqdn)
 *   - Address groups
 *   - Service objects (custom) and service groups
 *   - Firewall policies (with UTM profiles, NAT, schedule, logging)
 *   - VIP objects (destination NAT)
 *   - IP pools (source NAT)
 *   - Central SNAT maps
 *
 * FortiOS config format:
 *   config <section>
 *       edit <id-or-name>
 *           set <key> <value...>
 *       next
 *   end
 */

import { createWarning } from './parser-utils.js';

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a FortiOS configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw FortiOS configuration text
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseFortigateConfig(configText) {
  const warnings = [];

  // Parse config text into a structured tree
  const tree = buildConfigTree(configText);

  // Extract each config section
  const zones = parseZones(tree, warnings);
  const interfaces = parseInterfaces(tree, warnings);
  const addressObjects = parseAddressObjects(tree, warnings);
  const addressGroups = parseAddressGroups(tree, warnings);
  const serviceObjects = parseServiceObjects(tree, warnings);
  const serviceGroups = parseServiceGroups(tree, warnings);
  const securityPolicies = parseSecurityPolicies(tree, warnings);
  const natRules = parseNatRules(tree, warnings);
  const vipObjects = parseVipObjects(tree, warnings);
  const schedules = parseSchedules(tree, warnings);
  const profileGroups = parseProfileGroups(tree, warnings);
  const staticRoutes = parseStaticRoutes(tree, warnings);
  const haConfig = parseHaConfig(tree, warnings);
  const screenConfig = parseScreenConfig(tree, warnings);

  // Promote schedules to intermediate format (normalize day names to short form)
  const dayShortMap = { monday: 'Mon', tuesday: 'Tue', wednesday: 'Wed', thursday: 'Thu', friday: 'Fri', saturday: 'Sat', sunday: 'Sun' };
  const intermediateSchedules = Object.values(schedules).map(s => ({
    name: s.name,
    type: s.type,
    days: (s.day || []).map(d => dayShortMap[d.toLowerCase()] || d),
    start: s.start || '',
    end: s.end || '',
  }));

  // Expand profile group references into individual profiles on policies
  for (const policy of securityPolicies) {
    if (policy.profile_group && Object.keys(policy.security_profiles).length === 0) {
      const groupDef = profileGroups[policy.profile_group];
      if (groupDef) {
        if (groupDef['av-profile']) policy.security_profiles.virus = groupDef['av-profile'];
        if (groupDef['webfilter-profile']) policy.security_profiles['url-filtering'] = groupDef['webfilter-profile'];
        if (groupDef['ips-sensor']) policy.security_profiles.vulnerability = groupDef['ips-sensor'];
        if (groupDef['application-list']) policy.security_profiles['application-control'] = groupDef['application-list'];
        if (groupDef['dnsfilter-profile']) policy.security_profiles['dns-security'] = groupDef['dnsfilter-profile'];
        if (groupDef['emailfilter-profile']) policy.security_profiles['email-filter'] = groupDef['emailfilter-profile'];
        if (groupDef['dlp-profile']) policy.security_profiles.dlp = groupDef['dlp-profile'];
        if (groupDef['ssl-ssh-profile']) policy.security_profiles.decryption = groupDef['ssl-ssh-profile'];
      } else {
        warnings.push(createWarning('warning', `policy/${policy.name}`,
          `Profile group "${policy.profile_group}" referenced but not found in config`,
          'Define the profile group or assign individual profiles'));
      }
    }
  }

  // Merge zone and interface data — FortiGate can use interfaces directly as zones
  const mergedZones = mergeZonesAndInterfaces(zones, interfaces, securityPolicies);

  // Detect VDOM context
  const routingContexts = detectVdomContext(tree, mergedZones, interfaces);

  // Tag policies with VDOM if interfaces have vdom info
  const ifVdomMap = {};
  for (const iface of interfaces) {
    if (iface.vdom && iface.vdom !== 'root') ifVdomMap[iface.name] = iface.vdom;
  }
  if (Object.keys(ifVdomMap).length > 0) {
    for (const policy of securityPolicies) {
      const srcIf = (policy.src_zones || [])[0];
      if (srcIf && ifVdomMap[srcIf]) {
        if (!policy._fortigate) policy._fortigate = {};
        policy._fortigate.vdom = ifVdomMap[srcIf];
      }
    }
  }

  // Detect FortiOS version from config
  const version = extractVersion(tree);

  // Append FortiGate implicit rules
  let implicitIndex = securityPolicies.length + 1;
  const implicitFortigateBase = { policyid: 0, schedule: 'always', nat: false, utm_status: false, inspection_mode: 'flow', profile_type: '', users: [], groups: [], uuid: '' };
  for (const zone of mergedZones) {
    const intrazoneAction = zone._intrazone || 'deny';
    securityPolicies.push({
      name: `Implicit: Intra-zone ${intrazoneAction === 'allow' ? 'Allow' : 'Deny'} (${zone.name})`,
      src_zones: [zone.name],
      dst_zones: [zone.name],
      src_addresses: ['all'],
      dst_addresses: ['all'],
      negate_source: false,
      negate_destination: false,
      applications: [],
      services: ['ALL'],
      action: intrazoneAction === 'allow' ? 'allow' : 'deny',
      log_start: false,
      log_end: false,
      profile_group: '',
      security_profiles: {},
      description: `FortiGate intrazone-traffic default: ${intrazoneAction}`,
      tags: ['added_by_fpic'],
      disabled: false,
      _rule_index: implicitIndex++,
      _implicit: true,
      _fortigate: { ...implicitFortigateBase },
    });
  }
  securityPolicies.push({
    name: 'Implicit: Default Deny',
    src_zones: ['any'],
    dst_zones: ['any'],
    src_addresses: ['all'],
    dst_addresses: ['all'],
    negate_source: false,
    negate_destination: false,
    applications: [],
    services: ['ALL'],
    action: 'deny',
    log_start: false,
    log_end: false,
    profile_group: '',
    security_profiles: {},
    description: 'FortiGate default: implicit deny at end of policy list',
    tags: ['added_by_fpic'],
    disabled: false,
    _rule_index: implicitIndex++,
    _implicit: true,
    _fortigate: { ...implicitFortigateBase },
  });

  // Parse VPN/IPsec tunnel configuration
  const vpnTunnels = parseVpnConfig(tree, warnings);

  // Parse syslog, DHCP, QoS
  const syslogConfig = parseFortiSyslogConfig(tree, warnings);
  const dhcpConfig = parseFortiDhcpConfig(tree, warnings);
  const qosConfig = parseFortiQosConfig(tree, warnings);

  const intermediateConfig = {
    zones: mergedZones,
    address_objects: addressObjects,
    address_groups: addressGroups,
    service_objects: serviceObjects,
    service_groups: serviceGroups,
    security_policies: securityPolicies,
    nat_rules: natRules,
    applications: [],
    application_groups: [],
    schedules: intermediateSchedules,
    security_profile_objects: buildProfileObjects(securityPolicies, profileGroups),
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
    // FortiGate-specific extras (for the FortiGate view)
    _fortigate: {
      vips: vipObjects,
      schedules,
      profileGroups,
    },
    metadata: {
      source_vendor: 'fortigate',
      source_version: version,
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: natRules.length,
      object_count: addressObjects.length + serviceObjects.length,
      zone_count: mergedZones.length,
      vpn_tunnel_count: vpnTunnels.length,
      syslog_server_count: syslogConfig.length,
      dhcp_config_count: dhcpConfig.length,
      qos_profile_count: qosConfig.length,
      routing_context_count: routingContexts.length,
      static_route_count: staticRoutes.length,
      ha_enabled: !!(haConfig && haConfig.enabled),
      multi_vsys: routingContexts.length > 1,
    },
  };

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}


// ---------------------------------------------------------------------------
// Static Route Parser
// ---------------------------------------------------------------------------

function parseStaticRoutes(tree, warnings) {
  const routeSection = tree['router static'];
  if (!routeSection) return [];

  const routes = [];
  for (const [id, entry] of Object.entries(routeSection)) {
    if (typeof entry !== 'object' || entry === null) continue;

    const dstVal = entry['dst'];
    const gateway = getString(entry['gateway']) || '';
    const device = getString(entry['device']) || '';
    const distance = parseInt(getString(entry['distance'])) || 10;
    const comment = getString(entry['comment']) || getString(entry['comments']) || '';
    const isBlackhole = getString(entry['blackhole']) === 'enable';

    // FortiGate dst is "ip mask" — stored as array ['ip','mask'] or string "ip mask"
    let destination = '0.0.0.0/0';
    if (Array.isArray(dstVal) && dstVal.length >= 2) {
      destination = `${dstVal[0]}/${maskToCidr(dstVal[1])}`;
    } else if (typeof dstVal === 'string') {
      const parts = dstVal.split(/\s+/);
      if (parts.length === 2) {
        destination = `${parts[0]}/${maskToCidr(parts[1])}`;
      } else {
        destination = dstVal;
      }
    }

    routes.push({
      name: id,
      destination,
      next_hop: gateway,
      next_hop_type: isBlackhole ? 'discard' : (gateway ? 'ip-address' : 'none'),
      interface: device,
      metric: distance,
      admin_distance: distance,
      description: comment,
      vrf: '',
      routing_context: '',
    });
  }

  return routes;
}

// ---------------------------------------------------------------------------
// VDOM Context Detection
// ---------------------------------------------------------------------------

function detectVdomContext(tree, zones, interfaces) {
  const routingContexts = [];

  // Check for explicit VDOM config
  const vdomSection = tree['vdom'];
  if (vdomSection && typeof vdomSection === 'object') {
    for (const [vdomName, vdomData] of Object.entries(vdomSection)) {
      if (typeof vdomData !== 'object') continue;
      routingContexts.push({
        name: vdomName,
        type: 'vdom',
        virtual_routers: [],
        zones: zones.filter(z => {
          // Match zones to VDOM via interface vdom field
          const matchIf = interfaces.find(i => i.name === z.name);
          return matchIf && matchIf.vdom === vdomName;
        }).map(z => z.name),
      });
    }
  }

  // If no explicit VDOMs detected, create a single default context
  if (routingContexts.length === 0) {
    // Check if interfaces have different vdom values
    const vdoms = new Set();
    for (const iface of interfaces) {
      if (iface.vdom) vdoms.add(iface.vdom);
    }

    if (vdoms.size > 1) {
      for (const vdomName of vdoms) {
        routingContexts.push({
          name: vdomName,
          type: 'vdom',
          virtual_routers: [],
          zones: zones.filter(z => {
            const matchIf = interfaces.find(i => i.name === z.name);
            return matchIf && matchIf.vdom === vdomName;
          }).map(z => z.name),
        });
      }
    } else {
      routingContexts.push({
        name: vdoms.size === 1 ? [...vdoms][0] : 'default',
        type: 'default',
        virtual_routers: [],
        zones: zones.map(z => z.name),
      });
    }
  }

  return routingContexts;
}

// ---------------------------------------------------------------------------
// HA Configuration
// ---------------------------------------------------------------------------

function parseHaConfig(tree, warnings) {
  const haSection = tree['system ha'];
  if (!haSection) return null;

  const modeMap = { 'standalone': 'standalone', 'a-p': 'active-passive', 'a-a': 'active-active' };
  const modeStr = getString(haSection['mode']) || 'standalone';
  const mode = modeMap[modeStr] || modeStr;
  if (mode === 'standalone') return { enabled: false, mode: 'standalone', group_id: 0, priority: 128, preempt: false, peer_ip: '', ha_interfaces: [], monitoring: { link_groups: [], path_groups: [] }, description: 'HA standalone' };

  const groupId = parseInt(getString(haSection['group-id'])) || 0;
  const groupName = getString(haSection['group-name']) || '';
  const priority = parseInt(getString(haSection['priority'])) || 128;
  const preempt = getString(haSection['override']) === 'enable';
  const password = ''; // sanitized

  // Heartbeat device
  const haInterfaces = [];
  const hbdev = haSection['hbdev'];
  if (hbdev) {
    // hbdev can be "port5" 50 or array
    const hbParts = Array.isArray(hbdev) ? hbdev : [hbdev];
    for (let i = 0; i < hbParts.length; i += 2) {
      const ifName = typeof hbParts[i] === 'string' ? hbParts[i].replace(/"/g, '') : String(hbParts[i]);
      haInterfaces.push({
        name: 'heartbeat',
        ip: '',
        netmask: '',
        interface: ifName,
      });
    }
  }

  // HA management interface
  const haMgmtIf = haSection['ha-mgmt-interfaces'];
  if (haMgmtIf && typeof haMgmtIf === 'object') {
    for (const [id, entry] of Object.entries(haMgmtIf)) {
      if (typeof entry !== 'object') continue;
      haInterfaces.push({
        name: 'management',
        ip: getString(entry['gateway']) || '',
        netmask: '',
        interface: getString(entry['interface']) || '',
      });
    }
  }

  // Link monitoring
  const monitoring = { link_groups: [], path_groups: [] };
  const monitor = haSection['monitor'];
  if (monitor) {
    const monParts = Array.isArray(monitor) ? monitor : [monitor];
    monitoring.link_groups.push({
      name: 'default',
      enabled: true,
      interfaces: monParts.map(m => typeof m === 'string' ? m.replace(/"/g, '') : String(m)),
    });
  }

  return {
    enabled: true,
    mode,
    group_id: groupId,
    priority,
    preempt,
    peer_ip: '',
    ha_interfaces: haInterfaces,
    monitoring,
    description: `FortiGate HA ${mode}${groupName ? ` (${groupName})` : ''} group ${groupId}`,
  };
}

// ---------------------------------------------------------------------------
// Config Tree Builder
// ---------------------------------------------------------------------------
// Screen / DDoS Protection Parser
// ---------------------------------------------------------------------------

/**
 * Parses FortiGate DoS policy and anomaly settings into the screen_config schema.
 * DoS policies: config firewall DoS-policy
 * Anomaly settings: config firewall anomaly
 */
function parseScreenConfig(tree, warnings) {
  const screenConfigs = [];

  // Parse "firewall DoS-policy" entries
  const dosSection = tree['firewall DoS-policy'];
  if (dosSection && typeof dosSection === 'object') {
    for (const [id, entry] of Object.entries(dosSection)) {
      if (typeof entry !== 'object') continue;

      const iface = getString(entry.interface) || '';
      const name = `dos-policy-${id}`;

      const screen = {
        name,
        zone: iface,
        icmp: {
          flood_threshold: null,
          ping_death: false,
          fragment: false,
        },
        tcp: {
          syn_flood_threshold: null,
          syn_flood_timeout: null,
          land_attack: false,
          winnuke: false,
          tcp_no_flag: false,
        },
        udp: {
          flood_threshold: null,
        },
        ip: {
          spoofing: false,
          source_route: false,
          tear_drop: false,
          record_route: false,
          timestamp: false,
        },
        limit_session: {
          source_based: null,
          destination_based: null,
        },
        description: `DoS policy ${id} on interface ${iface}`,
      };

      // Parse anomaly sub-entries within the DoS policy
      const anomaly = entry.anomaly;
      if (anomaly && typeof anomaly === 'object') {
        for (const [anomalyName, anomalyData] of Object.entries(anomaly)) {
          if (typeof anomalyData !== 'object') continue;
          const status = getString(anomalyData.status);
          if (status !== 'enable') continue;
          const threshold = parseInt(getString(anomalyData.threshold)) || null;

          switch (anomalyName) {
            case 'tcp_syn_flood':
              screen.tcp.syn_flood_threshold = threshold;
              break;
            case 'udp_flood':
              screen.udp.flood_threshold = threshold;
              break;
            case 'icmp_flood':
              screen.icmp.flood_threshold = threshold;
              break;
            case 'icmp_sweep':
            case 'icmp_fragment':
              screen.icmp.fragment = true;
              break;
            case 'tcp_land':
              screen.tcp.land_attack = true;
              break;
            case 'tcp_winnuke':
              screen.tcp.winnuke = true;
              break;
            case 'tcp_no_flag':
              screen.tcp.tcp_no_flag = true;
              break;
            case 'ip_spoofing':
              screen.ip.spoofing = true;
              break;
            case 'ip_source_route':
              screen.ip.source_route = true;
              break;
          }
        }
      }

      screenConfigs.push(screen);
    }
  }

  // Parse standalone "firewall anomaly" entries (global anomaly protection)
  const anomalySection = tree['firewall anomaly'];
  if (anomalySection && typeof anomalySection === 'object') {
    const globalScreen = {
      name: 'global-anomaly',
      zone: '',
      icmp: {
        flood_threshold: null,
        ping_death: false,
        fragment: false,
      },
      tcp: {
        syn_flood_threshold: null,
        syn_flood_timeout: null,
        land_attack: false,
        winnuke: false,
        tcp_no_flag: false,
      },
      udp: {
        flood_threshold: null,
      },
      ip: {
        spoofing: false,
        source_route: false,
        tear_drop: false,
        record_route: false,
        timestamp: false,
      },
      limit_session: {
        source_based: null,
        destination_based: null,
      },
      description: 'FortiGate global anomaly protection settings',
    };

    let hasAny = false;
    for (const [anomalyName, anomalyData] of Object.entries(anomalySection)) {
      if (typeof anomalyData !== 'object') continue;
      const status = getString(anomalyData.status);
      if (status !== 'enable') continue;
      hasAny = true;
      const threshold = parseInt(getString(anomalyData.threshold)) || null;

      switch (anomalyName) {
        case 'tcp_syn_flood':
          globalScreen.tcp.syn_flood_threshold = threshold;
          break;
        case 'udp_flood':
          globalScreen.udp.flood_threshold = threshold;
          break;
        case 'icmp_flood':
          globalScreen.icmp.flood_threshold = threshold;
          break;
        case 'tcp_land':
          globalScreen.tcp.land_attack = true;
          break;
        case 'tcp_winnuke':
          globalScreen.tcp.winnuke = true;
          break;
        case 'tcp_no_flag':
          globalScreen.tcp.tcp_no_flag = true;
          break;
        case 'ip_spoofing':
          globalScreen.ip.spoofing = true;
          break;
        case 'ip_source_route':
          globalScreen.ip.source_route = true;
          break;
      }
    }

    if (hasAny) {
      screenConfigs.push(globalScreen);
    }
  }

  if (screenConfigs.length > 0) {
    warnings.push(createWarning('info', 'screen-config',
      `Parsed ${screenConfigs.length} DoS/anomaly protection profile(s)`,
      'Review screen/DDoS settings in the generated config'));
  }

  return screenConfigs;
}


// ---------------------------------------------------------------------------

/**
 * Parses FortiOS config text into a nested tree structure.
 *
 * FortiOS uses:
 *   config <path>        → opens a config section
 *       edit <id>         → opens a named entry
 *           set <k> <v>   → sets a key-value
 *           unset <k>     → clears a key
 *           config <sub>  → nested config block
 *       next              → closes current edit block
 *   end                   → closes current config block
 *
 * Result structure:
 *   { 'firewall policy': { '1': { name: 'Allow-Web', srcintf: ['port1'], ... }, ... } }
 */
function buildConfigTree(configText) {
  const lines = configText.split('\n');
  const root = {};
  const stack = []; // stack of { node, type: 'config'|'edit' }
  let current = root;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;

    if (line.startsWith('config ')) {
      const sectionName = line.slice(7).trim();
      if (!current[sectionName]) {
        current[sectionName] = {};
      }
      stack.push({ node: current, type: 'config' });
      current = current[sectionName];

    } else if (line.startsWith('edit ')) {
      const rawId = line.slice(5).trim();
      const entryId = unquote(rawId);
      if (!current[entryId]) {
        current[entryId] = {};
      }
      stack.push({ node: current, type: 'edit' });
      current = current[entryId];

    } else if (line === 'next') {
      // Close edit block — pop back to parent config
      if (stack.length > 0) {
        const frame = stack.pop();
        current = frame.node;
      }

    } else if (line === 'end') {
      // Close config block — pop back to parent
      if (stack.length > 0) {
        const frame = stack.pop();
        current = frame.node;
      }

    } else if (line.startsWith('set ')) {
      const parts = tokenize(line.slice(4));
      if (parts.length >= 2) {
        const key = parts[0];
        const values = parts.slice(1).map(unquote);
        // Single value → string; multiple values → array
        current[key] = values.length === 1 ? values[0] : values;
      } else if (parts.length === 1) {
        current[parts[0]] = 'enable';
      }

    } else if (line.startsWith('unset ')) {
      const key = line.slice(6).trim();
      delete current[key];
    }
  }

  return root;
}


// ---------------------------------------------------------------------------
// Tokenizer (respects quoted strings)
// ---------------------------------------------------------------------------

function tokenize(input) {
  const tokens = [];
  let i = 0;
  while (i < input.length) {
    // Skip whitespace
    while (i < input.length && /\s/.test(input[i])) i++;
    if (i >= input.length) break;

    if (input[i] === '"') {
      // Quoted string
      i++; // skip opening quote
      let token = '';
      while (i < input.length && input[i] !== '"') {
        if (input[i] === '\\' && i + 1 < input.length) {
          token += input[i + 1];
          i += 2;
        } else {
          token += input[i];
          i++;
        }
      }
      i++; // skip closing quote
      tokens.push(token);
    } else {
      // Unquoted token
      let token = '';
      while (i < input.length && !/\s/.test(input[i])) {
        token += input[i];
        i++;
      }
      tokens.push(token);
    }
  }
  return tokens;
}

function unquote(s) {
  if (typeof s !== 'string') return s;
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    return s.slice(1, -1);
  }
  return s;
}

function ensureArray(val) {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

function getString(val) {
  if (Array.isArray(val)) return val[0] || '';
  return val || '';
}

// ---------------------------------------------------------------------------
// Section Parsers
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// VPN / IPsec Tunnel Parser
// ---------------------------------------------------------------------------

/**
 * Parses FortiGate VPN/IPsec configuration from the config tree.
 * Phase1: tree['vpn ipsec phase1-interface']
 * Phase2: tree['vpn ipsec phase2-interface']
 */
function parseVpnConfig(tree, warnings) {
  const vpnTunnels = [];
  const phase1Section = tree['vpn ipsec phase1-interface'] || {};
  const phase2Section = tree['vpn ipsec phase2-interface'] || {};

  // Parse phase1 (IKE) entries into a lookup map
  const phase1Map = {};
  for (const [name, entry] of Object.entries(phase1Section)) {
    if (typeof entry !== 'object' || !entry) continue;
    const ikeVersion = getString(entry['ike-version']) === '1' ? 'v1' : 'v2';
    const remoteGw = getString(entry['remote-gw']);
    const iface = getString(entry['interface']);
    const proposal = getString(entry['proposal']);

    if (entry['psksecret']) {
      warnings.push(createWarning(
        'info', 'vpn-phase1/' + name,
        'VPN phase1 ' + name + ' pre-shared key sanitized',
        'Pre-shared keys are never included in parsed output'
      ));
    }

    const proposalParts = parseFortiProposal(proposal);

    phase1Map[name] = {
      name, remoteGw, iface, ikeVersion, proposal,
      encryption: proposalParts.encryption,
      authentication: proposalParts.authentication,
      dhGroup: getString(entry['dhgrp']) || '14',
      keylife: parseInt(getString(entry['keylife']), 10) || 28800,
    };
  }

  // Parse phase2 (IPsec) entries and link to phase1
  for (const [name, entry] of Object.entries(phase2Section)) {
    if (typeof entry !== 'object' || !entry) continue;
    const phase1name = getString(entry['phase1name']);
    const p1 = phase1Map[phase1name];
    if (!p1) {
      warnings.push(createWarning(
        'warning', 'vpn-phase2/' + name,
        'VPN phase2 ' + name + ' references unknown phase1 ' + phase1name,
        'Phase1 definition not found in config'
      ));
    }

    const p2proposal = getString(entry['proposal']);
    const p2parts = parseFortiProposal(p2proposal);
    const pfsEnabled = getString(entry['pfs']) === 'enable';
    const dhgrp = getString(entry['dhgrp']);
    const keylifeseconds = parseInt(getString(entry['keylifeseconds']), 10) || 3600;

    const proxyIds = [];
    const srcSubnetRaw = entry['src-subnet'];
    const dstSubnetRaw = entry['dst-subnet'];
    const srcSubnet = Array.isArray(srcSubnetRaw) ? srcSubnetRaw.join(" ") : getString(srcSubnetRaw);
    const dstSubnet = Array.isArray(dstSubnetRaw) ? dstSubnetRaw.join(" ") : getString(dstSubnetRaw);
    if (srcSubnet || dstSubnet) {
      proxyIds.push({
        local: fortiSubnetToCidr(srcSubnet),
        remote: fortiSubnetToCidr(dstSubnet),
        protocol: getString(entry['protocol']) || 'any',
      });
    }

    const dhGroupStr = pfsEnabled && dhgrp ? 'group' + dhgrp : 'group14';

    vpnTunnels.push({
      name,
      ike_gateway: {
        name: phase1name,
        address: p1 ? p1.remoteGw : '',
        local_address: p1 ? p1.iface : '',
        pre_shared_key: 'SANITIZED',
        ike_version: p1 ? p1.ikeVersion : 'v2',
        proposal: p1 ? p1.proposal : '',
      },
      ike_proposal: {
        name: p1 ? p1.proposal : 'default',
        auth_method: 'pre-shared-keys',
        dh_group: p1 ? 'group' + p1.dhGroup : 'group14',
        encryption: p1 ? p1.encryption : 'aes-256-cbc',
        authentication: p1 ? p1.authentication : 'sha256',
        lifetime: p1 ? p1.keylife : 28800,
      },
      ipsec_proposal: {
        name: p2proposal || 'default',
        protocol: 'esp',
        encryption: p2parts.encryption,
        authentication: p2parts.authentication,
        lifetime: keylifeseconds,
        pfs_group: dhGroupStr,
      },
      proxy_id: proxyIds,
      tunnel_interface: phase1name,
      description: '',
    });
  }

  // Phase1 entries without matching phase2 -> stub tunnels
  const usedPhase1 = new Set(vpnTunnels.map(t => t.ike_gateway.name));
  for (const [name, p1] of Object.entries(phase1Map)) {
    if (usedPhase1.has(name)) continue;
    vpnTunnels.push({
      name: name + '-tunnel',
      ike_gateway: {
        name, address: p1.remoteGw, local_address: p1.iface,
        pre_shared_key: 'SANITIZED', ike_version: p1.ikeVersion, proposal: p1.proposal,
      },
      ike_proposal: {
        name: p1.proposal, auth_method: 'pre-shared-keys',
        dh_group: 'group' + p1.dhGroup, encryption: p1.encryption,
        authentication: p1.authentication, lifetime: p1.keylife,
      },
      ipsec_proposal: {
        name: 'default', protocol: 'esp', encryption: 'aes-256-cbc',
        authentication: 'sha256', lifetime: 3600, pfs_group: 'group14',
      },
      proxy_id: [],
      tunnel_interface: name,
      description: 'Phase1 only (no matching phase2 found)',
    });
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

/** Parses FortiGate proposal strings like 'aes256-sha256'. */
function parseFortiProposal(proposal) {
  if (!proposal) return { encryption: 'aes-256-cbc', authentication: 'sha256' };
  const first = proposal.split(/\s+/)[0] || proposal;
  const encMap = {
    'aes128': 'aes-128-cbc', 'aes192': 'aes-192-cbc',
    'aes256': 'aes-256-cbc', '3des': '3des-cbc', 'des': 'des-cbc',
    'aes128gcm': 'aes-128-gcm', 'aes256gcm': 'aes-256-gcm',
  };
  const hashMap = {
    'sha256': 'sha256', 'sha384': 'sha384', 'sha512': 'sha512',
    'sha1': 'sha1', 'md5': 'md5',
  };
  const parts = first.split('-');
  const enc = parts[0] || '';
  const hash = parts.slice(1).join('-') || '';
  return {
    encryption: encMap[enc] || enc || 'aes-256-cbc',
    authentication: hashMap[hash] || hash || 'sha256',
  };
}

/** Converts FortiGate subnet notation (e.g. '10.0.0.0 255.0.0.0') to CIDR. */
function fortiSubnetToCidr(subnetStr) {
  if (!subnetStr) return '';
  const parts = subnetStr.trim().split(/\s+/);
  if (parts.length === 2) {
    const mask = parts[1];
    const bits = mask.split('.').reduce((acc, octet) => {
      return acc + (parseInt(octet, 10) >>> 0).toString(2).replace(/0/g, '').length;
    }, 0);
    return parts[0] + '/' + bits;
  }
  return subnetStr;
}


function extractVersion(tree) {
  const global = tree['system global'] || {};
  // Sometimes version is at top-level as a comment: #config-version=...
  // For tree-based approach, check if there's a version key
  return global['version'] || global['fgt-version'] || '';
}

// --- Zones ---
function parseZones(tree, warnings) {
  const zonesSection = tree['system zone'] || {};
  const zones = [];

  for (const [name, entry] of Object.entries(zonesSection)) {
    if (typeof entry !== 'object') continue;
    zones.push({
      name,
      description: getString(entry['description']) || '',
      interfaces: ensureArray(entry['interface']),
      _intrazone: getString(entry['intrazone-traffic']) || 'deny',
    });
  }
  return zones;
}

// --- Interfaces ---
function parseInterfaces(tree, warnings) {
  const ifaceSection = tree['system interface'] || {};
  const interfaces = [];

  for (const [name, entry] of Object.entries(ifaceSection)) {
    if (typeof entry !== 'object') continue;
    interfaces.push({
      name,
      alias: getString(entry['alias']) || '',
      ip: getString(entry['ip']) || '',
      type: getString(entry['type']) || 'physical',
      vdom: getString(entry['vdom']) || 'root',
      zone: '', // will be filled by zone data
    });
  }
  return interfaces;
}

// --- Merge zones and interfaces ---
function mergeZonesAndInterfaces(zones, interfaces, policies) {
  // Build a map of interface-name → zone
  const ifaceToZone = {};
  for (const zone of zones) {
    for (const iface of zone.interfaces) {
      ifaceToZone[iface] = zone.name;
    }
  }

  // Collect all interfaces referenced in policies
  const usedInterfaces = new Set();
  for (const policy of policies) {
    policy.src_zones.forEach(z => usedInterfaces.add(z));
    policy.dst_zones.forEach(z => usedInterfaces.add(z));
  }

  // For interfaces used in policies that aren't part of a zone, create implicit zones
  const zoneMap = {};
  for (const zone of zones) {
    zoneMap[zone.name] = zone;
  }

  for (const ifaceName of usedInterfaces) {
    if (ifaceName === 'any') continue;
    if (!zoneMap[ifaceName] && !ifaceToZone[ifaceName]) {
      // Interface used directly as zone — create a zone for it
      const iface = interfaces.find(i => i.name === ifaceName);
      zoneMap[ifaceName] = {
        name: ifaceName,
        description: iface?.alias || '',
        interfaces: [ifaceName],
      };
    }
  }

  return Object.values(zoneMap);
}


// --- Address Objects ---
function parseAddressObjects(tree, warnings) {
  const addrSection = tree['firewall address'] || {};
  const objects = [];

  for (const [name, entry] of Object.entries(addrSection)) {
    if (typeof entry !== 'object') continue;
    const addrType = getString(entry['type']) || 'ipmask';
    let type = 'subnet';
    let value = '';

    switch (addrType) {
      case 'ipmask': {
        const subnet = getString(entry['subnet']);
        if (subnet) {
          // FortiOS uses "10.1.1.0 255.255.255.0" format
          const parts = subnet.split(/\s+/);
          if (parts.length === 2) {
            value = `${parts[0]}/${maskToCidr(parts[1])}`;
          } else {
            value = subnet;
          }
          type = value.endsWith('/32') ? 'host' : 'subnet';
        }
        break;
      }
      case 'iprange':
        type = 'range';
        value = `${getString(entry['start-ip'])}-${getString(entry['end-ip'])}`;
        break;
      case 'fqdn':
        type = 'fqdn';
        value = getString(entry['fqdn']) || '';
        warnings.push(createWarning(
          'info',
          `address:${name}`,
          `FQDN address "${name}" → SRX dns-name requires SRX 12.1+ and DNS resolution at commit time`,
          'Verify SRX version supports dns-name, or replace with static IP'
        ));
        break;
      case 'wildcard':
        type = 'wildcard';
        value = getString(entry['wildcard']) || '';
        break;
      case 'wildcard-fqdn':
        type = 'fqdn';
        value = getString(entry['wildcard-fqdn']) || '';
        warnings.push(createWarning(
          'warning',
          `address:${name}`,
          `Wildcard FQDN "${name}" (${value}) — SRX dns-name does not support wildcards`,
          'Replace with specific FQDN or use custom feed / address set'
        ));
        break;
      case 'geography':
        type = 'geography';
        value = getString(entry['country']) || '';
        warnings.push(createWarning('unsupported', `address:${name}`, `Geography address "${name}" (country: ${value}) — SRX does not support geo-IP address objects natively`, 'Replace with static IP ranges or use SRX Security Intelligence feeds'));
        break;
      case 'dynamic':
        type = 'dynamic';
        value = getString(entry['sdn']) || 'unknown';
        warnings.push(createWarning('unsupported', `address:${name}`, `Dynamic/SDN address "${name}" (${value}) — SRX does not support SDN-based address objects natively`, 'Replace with static addresses or use SRX Security Intelligence feeds'));
        break;
      default:
        warnings.push(createWarning('warning', `address:${name}`, `Unknown address type: ${addrType}`, 'Review manually'));
        value = 'unknown';
    }

    objects.push({
      name,
      type,
      value,
      description: getString(entry['comment']) || getString(entry['comments']) || '',
      tags: ensureArray(entry['tags'] || entry['tag']),
    });
  }

  return objects;
}


// --- Address Groups ---
function parseAddressGroups(tree, warnings) {
  const groupSection = tree['firewall addrgrp'] || {};
  const groups = [];

  for (const [name, entry] of Object.entries(groupSection)) {
    if (typeof entry !== 'object') continue;
    groups.push({
      name,
      members: ensureArray(entry['member']),
      description: getString(entry['comment']) || getString(entry['comments']) || '',
      tags: ensureArray(entry['tags'] || entry['tag']),
    });
  }

  return groups;
}


// --- Service Objects ---
function parseServiceObjects(tree, warnings) {
  const svcSection = tree['firewall service custom'] || {};
  const services = [];

  for (const [name, entry] of Object.entries(svcSection)) {
    if (typeof entry !== 'object') continue;
    const protocol = getString(entry['protocol']) || 'TCP/UDP/SCTP';

    if (protocol === 'ICMP' || protocol === 'ICMP6') {
      services.push({
        name,
        protocol: protocol.toLowerCase(),
        port_range: '',
        source_port: '',
        icmp_type: getString(entry['icmptype']) || '',
        icmp_code: getString(entry['icmpcode']) || '',
        description: getString(entry['comment']) || '',
      });
    } else if (protocol === 'IP') {
      services.push({
        name,
        protocol: 'ip',
        port_range: '',
        source_port: '',
        protocol_number: getString(entry['protocol-number']) || '',
        description: getString(entry['comment']) || '',
      });
    } else {
      // TCP/UDP/SCTP
      const tcpPorts = getString(entry['tcp-portrange']) || '';
      const udpPorts = getString(entry['udp-portrange']) || '';
      const sctpPorts = getString(entry['sctp-portrange']) || '';

      if (tcpPorts) {
        services.push({
          name: udpPorts ? `${name}_tcp` : name,
          protocol: 'tcp',
          port_range: normalizePortRange(tcpPorts),
          source_port: '',
          description: getString(entry['comment']) || '',
        });
      }
      if (udpPorts) {
        services.push({
          name: tcpPorts ? `${name}_udp` : name,
          protocol: 'udp',
          port_range: normalizePortRange(udpPorts),
          source_port: '',
          description: getString(entry['comment']) || '',
        });
      }
      if (sctpPorts) {
        services.push({
          name,
          protocol: 'sctp',
          port_range: normalizePortRange(sctpPorts),
          source_port: '',
          description: getString(entry['comment']) || '',
        });
      }
      // If no ports specified, it's a protocol-level match
      if (!tcpPorts && !udpPorts && !sctpPorts) {
        services.push({
          name,
          protocol: 'tcp',
          port_range: '1-65535',
          source_port: '',
          description: getString(entry['comment']) || '',
        });
      }
    }
  }

  return services;
}


// --- Service Groups ---
function parseServiceGroups(tree, warnings) {
  const groupSection = tree['firewall service group'] || {};
  const groups = [];

  for (const [name, entry] of Object.entries(groupSection)) {
    if (typeof entry !== 'object') continue;
    groups.push({
      name,
      members: ensureArray(entry['member']),
      description: getString(entry['comment']) || '',
    });
  }

  return groups;
}


// --- Security Policies ---
function parseSecurityPolicies(tree, warnings) {
  const policySection = tree['firewall policy'] || {};
  const policies = [];
  let ruleIndex = 1;

  // Sort entries by policy ID (numeric order)
  const entries = Object.entries(policySection)
    .filter(([, v]) => typeof v === 'object')
    .sort(([a], [b]) => {
      const na = parseInt(a, 10);
      const nb = parseInt(b, 10);
      if (!isNaN(na) && !isNaN(nb)) return na - nb;
      return a.localeCompare(b);
    });

  for (const [id, entry] of entries) {
    const action = mapAction(getString(entry['action']));
    const disabled = getString(entry['status']) === 'disable';

    // Security profiles
    const securityProfiles = {};
    const profileType = getString(entry['profile-type']);
    if (profileType === 'group' && entry['profile-group']) {
      // Profile group reference — will be resolved later
    }
    if (entry['av-profile']) securityProfiles.virus = getString(entry['av-profile']);
    if (entry['webfilter-profile']) securityProfiles['url-filtering'] = getString(entry['webfilter-profile']);
    if (entry['ips-sensor']) securityProfiles.vulnerability = getString(entry['ips-sensor']);
    if (entry['application-list']) securityProfiles['application-control'] = getString(entry['application-list']);
    if (entry['dnsfilter-profile']) securityProfiles['dns-security'] = getString(entry['dnsfilter-profile']);
    if (entry['emailfilter-profile']) securityProfiles['email-filter'] = getString(entry['emailfilter-profile']);
    if (entry['dlp-profile']) securityProfiles['dlp'] = getString(entry['dlp-profile']);
    if (entry['ssl-ssh-profile']) securityProfiles.decryption = getString(entry['ssl-ssh-profile']);
    if (entry['waf-profile']) securityProfiles.waf = getString(entry['waf-profile']);
    if (entry['casb-profile']) securityProfiles.casb = getString(entry['casb-profile']);
    if (entry['voip-profile']) securityProfiles.voip = getString(entry['voip-profile']);

    const logTraffic = getString(entry['logtraffic']) || 'utm';

    // Schedule
    const schedule = getString(entry['schedule']) || 'always';

    // NAT in policy
    const natEnabled = getString(entry['nat']) === 'enable';

    const policy = {
      name: getString(entry['name']) || `Policy_${id}`,
      src_zones: ensureArray(entry['srcintf']),
      dst_zones: ensureArray(entry['dstintf']),
      src_addresses: ensureArray(entry['srcaddr']),
      dst_addresses: ensureArray(entry['dstaddr']),
      negate_source: getString(entry['srcaddr-negate']) === 'enable',
      negate_destination: getString(entry['dstaddr-negate']) === 'enable',
      applications: ensureArray(entry['application-list'] ? entry['application-list'] : undefined),
      services: ensureArray(entry['service']),
      action,
      log_start: logTraffic === 'all' || getString(entry['logtraffic-start']) === 'enable',
      log_end: logTraffic === 'all' || logTraffic === 'utm',
      profile_group: profileType === 'group' ? getString(entry['profile-group']) : '',
      security_profiles: securityProfiles,
      description: getString(entry['comments']) || getString(entry['comment']) || '',
      tags: ensureArray(entry['label']),
      disabled,
      schedule: schedule === 'always' ? '' : schedule,
      _rule_index: ruleIndex++,
      // FortiGate-specific fields for the FortiGate view
      _fortigate: {
        policyid: parseInt(id, 10) || id,
        schedule,
        nat: natEnabled,
        utm_status: getString(entry['utm-status']) === 'enable',
        inspection_mode: getString(entry['inspection-mode']) || 'flow',
        profile_type: profileType || 'single',
        users: ensureArray(entry['users']),
        groups: ensureArray(entry['groups']),
        uuid: getString(entry['uuid']) || '',
      },
    };

    policies.push(policy);
  }

  return policies;
}


// --- NAT Rules (VIP + IP Pool + Central SNAT) ---
function parseNatRules(tree, warnings) {
  const natRules = [];
  let ruleIndex = 1;

  // Central SNAT map
  const csnatSection = tree['firewall central-snat-map'] || {};
  for (const [id, entry] of Object.entries(csnatSection)) {
    if (typeof entry !== 'object') continue;
    natRules.push({
      name: getString(entry['comments']) || `Central-SNAT-${id}`,
      type: 'source',
      src_zones: ensureArray(entry['srcintf']),
      dst_zones: ensureArray(entry['dstintf']),
      src_addresses: ensureArray(entry['orig-addr']),
      dst_addresses: ensureArray(entry['dst-addr']),
      translated_src: {
        type: entry['nat-ippool'] ? 'dynamic-ip-pool' : 'interface',
        addresses: ensureArray(entry['nat-ippool']),
      },
      translated_dst: null,
      translated_port: getString(entry['nat-port']) || null,
      description: getString(entry['comments']) || '',
      _rule_index: ruleIndex++,
    });
  }

  // VIP-based DNAT
  const vipSection = tree['firewall vip'] || {};
  for (const [name, entry] of Object.entries(vipSection)) {
    if (typeof entry !== 'object') continue;
    const extIp = getString(entry['extip']) || '';
    const mappedIp = getString(entry['mappedip']);
    const mappedIpArr = ensureArray(entry['mappedip']);
    const portForward = getString(entry['portforward']) === 'enable';
    const extPort = getString(entry['extport']) || '';
    const mappedPort = getString(entry['mappedport']) || '';
    const vipProtocol = getString(entry['protocol']) || '';

    natRules.push({
      name,
      type: 'destination',
      src_zones: [],
      dst_zones: [getString(entry['extintf']) || 'any'],
      src_addresses: ['any'],
      dst_addresses: [extIp || name],
      translated_src: null,
      translated_dst: mappedIpArr[0] || mappedIp || '',
      translated_port: portForward ? mappedPort : null,
      match_port: portForward ? extPort : null,
      match_protocol: vipProtocol || null,
      description: getString(entry['comment']) || getString(entry['comments']) || '',
      _rule_index: ruleIndex++,
    });
  }

  // IP Pools (informational — SNAT pools)
  const poolSection = tree['firewall ippool'] || {};
  for (const [name, entry] of Object.entries(poolSection)) {
    if (typeof entry !== 'object') continue;
    natRules.push({
      name,
      type: 'source',
      src_zones: [],
      dst_zones: [],
      src_addresses: ['any'],
      dst_addresses: ['any'],
      translated_src: {
        type: 'dynamic-ip-pool',
        addresses: [`${getString(entry['startip'])}-${getString(entry['endip'])}`],
      },
      translated_dst: null,
      translated_port: null,
      description: `IP Pool (${getString(entry['type']) || 'overload'})`,
      _rule_index: ruleIndex++,
    });
  }

  return natRules;
}


// --- VIP Objects (for FortiGate view) ---
function parseVipObjects(tree, warnings) {
  const vipSection = tree['firewall vip'] || {};
  const vips = [];

  for (const [name, entry] of Object.entries(vipSection)) {
    if (typeof entry !== 'object') continue;
    vips.push({
      name,
      extip: getString(entry['extip']),
      mappedip: ensureArray(entry['mappedip']),
      extintf: getString(entry['extintf']) || 'any',
      portforward: getString(entry['portforward']) === 'enable',
      extport: getString(entry['extport']) || '',
      mappedport: getString(entry['mappedport']) || '',
      type: getString(entry['type']) || 'static-nat',
      comment: getString(entry['comment']) || getString(entry['comments']) || '',
    });
  }

  return vips;
}


// --- Schedules ---
function parseSchedules(tree, warnings) {
  const schedules = {};
  const recurring = tree['firewall schedule recurring'] || {};
  const onetime = tree['firewall schedule onetime'] || {};

  for (const [name, entry] of Object.entries(recurring)) {
    if (typeof entry !== 'object') continue;
    schedules[name] = {
      name,
      type: 'recurring',
      day: ensureArray(entry['day']),
      start: getString(entry['start']) || '00:00',
      end: getString(entry['end']) || '23:59',
    };
  }

  for (const [name, entry] of Object.entries(onetime)) {
    if (typeof entry !== 'object') continue;
    schedules[name] = {
      name,
      type: 'onetime',
      start: getString(entry['start']) || '',
      end: getString(entry['end']) || '',
    };
  }

  return schedules;
}


// --- Profile Groups ---
function parseProfileGroups(tree, warnings) {
  const groupSection = tree['firewall profile-group'] || {};
  const groups = {};

  for (const [name, entry] of Object.entries(groupSection)) {
    if (typeof entry !== 'object') continue;
    groups[name] = {
      name,
      'av-profile': getString(entry['av-profile']) || '',
      'webfilter-profile': getString(entry['webfilter-profile']) || '',
      'ips-sensor': getString(entry['ips-sensor']) || '',
      'application-list': getString(entry['application-list']) || '',
      'dnsfilter-profile': getString(entry['dnsfilter-profile']) || '',
      'emailfilter-profile': getString(entry['emailfilter-profile']) || '',
      'dlp-profile': getString(entry['dlp-profile']) || '',
      'ssl-ssh-profile': getString(entry['ssl-ssh-profile']) || '',
    };
  }

  return groups;
}


// --- Build security profile objects list ---
function buildProfileObjects(policies, profileGroups) {
  const profileSet = new Map();

  for (const policy of policies) {
    const profiles = policy.security_profiles || {};
    for (const [type, name] of Object.entries(profiles)) {
      if (!name) continue;
      const key = `${type}:${name}`;
      if (!profileSet.has(key)) {
        profileSet.set(key, {
          name,
          profile_type: type,
          profile_type_label: getProfileLabel(type),
          profile_name: name,
          srx_feature: mapProfileToSrxFeature(type),
          srx_type: mapProfileToSrxType(type),
          source: policy.profile_group ? `group:${policy.profile_group}` : 'individual',
          attached_rules: [],
        });
      }
      profileSet.get(key).attached_rules.push(policy.name);
    }
  }

  return Array.from(profileSet.values());
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mapAction(fortiAction) {
  switch ((fortiAction || '').toLowerCase()) {
    case 'accept': return 'allow';
    case 'deny': return 'deny';
    case 'ipsec': return 'allow'; // IPsec tunnel action
    case 'learn': return 'allow';
    default: return 'allow';
  }
}

function maskToCidr(mask) {
  if (!mask) return '32';
  // Handle CIDR format already (e.g. "24")
  if (/^\d+$/.test(mask) && parseInt(mask) <= 32) return mask;
  // Convert dotted-decimal mask to CIDR
  const parts = mask.split('.');
  if (parts.length !== 4) return '32';
  let cidr = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    cidr += (n >>> 0).toString(2).split('1').length - 1;
  }
  return String(cidr);
}

function normalizePortRange(portStr) {
  // FortiOS port ranges: "80" or "443" or "8080-8090" or "80 443 8080-8090"
  // May include source port: "80:1024-65535" (dst:src)
  if (!portStr) return '';
  return portStr.split(/\s+/).map(p => {
    // Strip source port portion (after colon)
    const colonIdx = p.indexOf(':');
    return colonIdx >= 0 ? p.slice(0, colonIdx) : p;
  }).join(',');
}

function getProfileLabel(profileType) {
  const labels = {
    virus: 'Antivirus',
    'url-filtering': 'Web Filter',
    vulnerability: 'IPS',
    'application-control': 'App Control',
    'dns-security': 'DNS Filter',
    'email-filter': 'Email Filter',
    'dlp': 'DLP',
    decryption: 'SSL Inspection',
    waf: 'WAF',
    casb: 'CASB',
    voip: 'VoIP',
  };
  return labels[profileType] || profileType;
}

function mapProfileToSrxFeature(profileType) {
  const map = {
    virus: 'utm',
    'url-filtering': 'utm',
    vulnerability: 'idp',
    'application-control': 'appfw',
    'dns-security': 'utm',
    'email-filter': 'utm',
    'dlp': 'none',
    decryption: 'ssl-proxy',
    waf: 'utm',
  };
  return map[profileType] || 'utm';
}

function mapProfileToSrxType(profileType) {
  const map = {
    virus: 'utm-policy',
    'url-filtering': 'utm-policy',
    vulnerability: 'idp-policy',
    'application-control': 'application-firewall',
    'dns-security': 'utm-policy',
    'email-filter': 'anti-spam',
    'dlp': 'dlp',
    decryption: 'ssl-proxy',
  };
  return map[profileType] || 'utm-policy';
}


// ---------------------------------------------------------------------------
// Syslog Configuration Parser
// ---------------------------------------------------------------------------

function parseFortiSyslogConfig(tree, warnings) {
  const servers = [];
  // FortiGate: config log syslogd setting / config log syslogd2 setting, etc.
  for (const key of Object.keys(tree)) {
    if (!key.startsWith('log syslogd')) continue;
    const section = tree[key];
    if (!section) continue;

    const server = section.server || '';
    if (!server) continue;

    servers.push({
      name: key.replace('log ', '').replace(' setting', ''),
      server,
      port: parseInt(section.port || '514', 10),
      transport: section.mode === 'reliable' ? 'tcp' : 'udp',
      facility: section.facility || 'local7',
      profile: key,
      source_ip: section['source-ip'] || '',
    });
  }

  if (servers.length > 0) {
    warnings.push(createWarning('info', 'syslog', `Parsed ${servers.length} syslog server(s)`, 'Syslog server configuration detected'));
  }
  return servers;
}


// ---------------------------------------------------------------------------
// DHCP Configuration Parser
// ---------------------------------------------------------------------------

function parseFortiDhcpConfig(tree, warnings) {
  const dhcpConfigs = [];
  // FortiGate: config system dhcp server
  const dhcpServer = tree['system dhcp server'];
  if (dhcpServer) {
    for (const [id, entry] of Object.entries(dhcpServer)) {
      if (!entry || typeof entry !== 'object') continue;
      const iface = entry.interface || '';
      const pools = [];
      // ip-range sub-entries
      const ipRange = entry['ip-range'];
      if (ipRange && typeof ipRange === 'object') {
        for (const [, range] of Object.entries(ipRange)) {
          if (range && range['start-ip'] && range['end-ip']) {
            pools.push(`${range['start-ip']}-${range['end-ip']}`);
          }
        }
      }

      const dns1 = entry['dns-server1'] || '';
      const dns2 = entry['dns-server2'] || '';
      const gateway = entry['default-gateway'] || '';
      const netmask = entry.netmask || '';

      dhcpConfigs.push({
        type: 'server',
        interface: iface,
        pools,
        gateway,
        netmask,
        dns_servers: [dns1, dns2].filter(Boolean),
        lease_time: parseInt(entry['lease-time'] || '86400', 10),
        domain: entry.domain || '',
      });
    }
  }

  // FortiGate: config system dhcp6 server (IPv6 — just detect)
  // FortiGate doesn't have explicit DHCP relay in config (it uses helper addresses on interfaces)

  if (dhcpConfigs.length > 0) {
    warnings.push(createWarning('info', 'dhcp', `Parsed ${dhcpConfigs.length} DHCP server config(s)`, 'DHCP server configuration detected'));
  }
  return dhcpConfigs;
}


// ---------------------------------------------------------------------------
// QoS / Traffic Shaping Configuration Parser
// ---------------------------------------------------------------------------

function parseFortiQosConfig(tree, warnings) {
  const qosProfiles = [];
  // FortiGate: config firewall shaping-profile
  const shapingProfile = tree['firewall shaping-profile'];
  if (shapingProfile) {
    for (const [name, entry] of Object.entries(shapingProfile)) {
      if (!entry || typeof entry !== 'object') continue;
      const classes = [];
      const shapingEntries = entry['shaping-entries'];
      if (shapingEntries && typeof shapingEntries === 'object') {
        for (const [, se] of Object.entries(shapingEntries)) {
          if (se && typeof se === 'object') {
            classes.push({
              name: se['class-id'] || '',
              priority: se.priority || 'medium',
              guaranteed_bandwidth: parseInt(se['guaranteed-bandwidth-percentage'] || '0', 10),
              maximum_bandwidth: parseInt(se['maximum-bandwidth-percentage'] || '0', 10),
            });
          }
        }
      }
      qosProfiles.push({
        name,
        type: 'shaping-profile',
        classes,
      });
    }
  }

  // FortiGate: config firewall shaping-policy
  const shapingPolicy = tree['firewall shaping-policy'];
  if (shapingPolicy) {
    for (const [id, entry] of Object.entries(shapingPolicy)) {
      if (!entry || typeof entry !== 'object') continue;
      qosProfiles.push({
        name: entry.name || `shaping-policy-${id}`,
        type: 'shaping-policy',
        traffic_shaper: entry['traffic-shaper'] || '',
        traffic_shaper_reverse: entry['traffic-shaper-reverse'] || '',
        per_ip_shaper: entry['per-ip-shaper'] || '',
        srcintf: entry.srcintf || '',
        dstintf: entry.dstintf || '',
      });
    }
  }

  if (qosProfiles.length > 0) {
    warnings.push(createWarning('info', 'qos', `Parsed ${qosProfiles.length} QoS/shaping config(s)`, 'Traffic shaping configuration detected'));
  }
  return qosProfiles;
}

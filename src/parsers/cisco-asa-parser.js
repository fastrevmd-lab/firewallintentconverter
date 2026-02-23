/**
 * Cisco ASA / FTD Configuration Parser
 * =====================================
 *
 * Parses Cisco ASA (and FTD/FMC-style) configurations into the vendor-neutral
 * intermediate JSON schema.
 *
 * Handles:
 *   - Interface definitions (nameif, security-level, ip address)
 *   - Object network / object service definitions
 *   - Object-group network / service / protocol definitions
 *   - Access-list extended ACL entries
 *   - Access-group (ACL → interface binding)
 *   - NAT statements (object nat, twice nat, manual nat)
 *   - Service objects and service groups
 *
 * Cisco ASA config format is line-oriented with indented sub-commands
 * under object/object-group blocks.
 */

import { createWarning } from './parser-utils.js';

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a Cisco ASA configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw Cisco ASA configuration text
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseCiscoAsaConfig(configText) {
  const warnings = [];
  const lines = configText.split('\n').map(l => l.trimEnd());

  // Build structured blocks
  const blocks = buildBlocks(lines);

  // Extract sections
  const interfaces = parseInterfaces(blocks, warnings);
  const objectNetworks = parseObjectNetworks(blocks, warnings);
  const objectServices = parseObjectServices(blocks, warnings);
  const objectGroupNetworks = parseObjectGroupNetworks(blocks, warnings);
  const objectGroupServices = parseObjectGroupServices(blocks, warnings);
  const objectGroupProtocols = parseObjectGroupProtocols(blocks, warnings);
  const accessLists = parseAccessLists(lines, warnings);
  const accessGroups = parseAccessGroups(lines, warnings);
  const natRules = parseNatRules(blocks, lines, warnings);
  const timeRanges = parseTimeRanges(blocks);

  // Build zones from interfaces (ASA uses nameif + security-level as zones)
  const zones = buildZones(interfaces);

  // Build address objects from object network + object-group network
  const addressObjects = buildAddressObjects(objectNetworks);
  const addressGroups = buildAddressGroups(objectGroupNetworks);

  // Build service objects
  const serviceObjects = buildServiceObjects(objectServices, objectGroupProtocols);
  const serviceGroups = buildServiceGroups(objectGroupServices);

  // Build security policies from access-lists + access-groups
  const securityPolicies = buildSecurityPolicies(accessLists, accessGroups, interfaces, warnings);

  // Detect version
  const version = extractVersion(lines);

  const intermediateConfig = {
    zones,
    address_objects: addressObjects,
    address_groups: addressGroups,
    service_objects: serviceObjects,
    service_groups: serviceGroups,
    security_policies: securityPolicies,
    nat_rules: natRules,
    applications: [],
    application_groups: [],
    schedules: timeRanges,
    security_profile_objects: [],
    external_lists: [],
    vpn_tunnels: [],
    _cisco: {
      interfaces,
      objectGroupProtocols,
      accessGroups,
    },
    metadata: {
      source_vendor: 'cisco_asa',
      source_version: version,
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: natRules.length,
      object_count: addressObjects.length + serviceObjects.length,
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
// Block Builder
// ---------------------------------------------------------------------------

/**
 * Groups indented lines under their parent command.
 * ASA config uses single-space indentation for sub-commands under
 * object, object-group, interface blocks.
 *
 * Returns array of { command, children: [string] }
 */
function buildBlocks(lines) {
  const blocks = [];
  let current = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('!') || trimmed.startsWith(':')) continue;

    // Check if this is a top-level command (no leading space) that starts a block
    const isIndented = line.length > 0 && (line[0] === ' ' || line[0] === '\t');

    if (!isIndented) {
      // Top-level command — start a new block
      if (current) blocks.push(current);
      current = { command: trimmed, children: [] };
    } else if (current) {
      current.children.push(trimmed);
    }
  }
  if (current) blocks.push(current);

  return blocks;
}


// ---------------------------------------------------------------------------
// Interface Parser
// ---------------------------------------------------------------------------

function parseInterfaces(blocks, warnings) {
  const interfaces = [];

  for (const block of blocks) {
    if (!block.command.startsWith('interface ')) continue;
    const ifaceName = block.command.slice(10).trim();
    const iface = {
      hardware: ifaceName,
      nameif: '',
      securityLevel: 0,
      ip: '',
      shutdown: false,
      description: '',
      vlan: '',
    };

    for (const child of block.children) {
      if (child.startsWith('nameif ')) {
        iface.nameif = child.slice(7).trim();
      } else if (child.startsWith('security-level ')) {
        iface.securityLevel = parseInt(child.slice(15).trim(), 10) || 0;
      } else if (child.startsWith('ip address ')) {
        iface.ip = child.slice(11).trim();
      } else if (child === 'shutdown') {
        iface.shutdown = true;
      } else if (child.startsWith('description ')) {
        iface.description = child.slice(12).trim();
      } else if (child.startsWith('vlan ')) {
        iface.vlan = child.slice(5).trim();
      }
    }

    if (iface.nameif) {
      interfaces.push(iface);
    }
  }

  return interfaces;
}


// ---------------------------------------------------------------------------
// Object Network Parser
// ---------------------------------------------------------------------------

function parseObjectNetworks(blocks, warnings) {
  const objects = [];

  for (const block of blocks) {
    if (!block.command.startsWith('object network ')) continue;
    const name = block.command.slice(15).trim();
    const obj = { name, type: '', value: '', description: '', natType: null, natValue: null };

    for (const child of block.children) {
      if (child.startsWith('host ')) {
        obj.type = 'host';
        obj.value = child.slice(5).trim();
      } else if (child.startsWith('subnet ')) {
        obj.type = 'subnet';
        const parts = child.slice(7).trim().split(/\s+/);
        if (parts.length === 2) {
          obj.value = `${parts[0]}/${maskToCidr(parts[1])}`;
        } else {
          obj.value = child.slice(7).trim();
        }
      } else if (child.startsWith('range ')) {
        obj.type = 'range';
        obj.value = child.slice(6).trim().replace(/\s+/, '-');
      } else if (child.startsWith('fqdn ')) {
        obj.type = 'fqdn';
        const parts = child.slice(5).trim().split(/\s+/);
        obj.value = parts[parts.length - 1]; // domain is always last
        // Preserve v4/v6 prefix for SRX ipv4-only/ipv6-only
        if (parts.length > 1 && (parts[0] === 'v4' || parts[0] === 'v6')) {
          obj.fqdn_ip_version = parts[0];
        }
        warnings.push(createWarning(
          'info',
          `address/${obj.name}`,
          `FQDN address "${obj.name}" → SRX dns-name requires SRX 12.1+ and DNS resolution at commit time`,
          'Verify SRX version supports dns-name, or replace with static IP'
        ));
      } else if (child.startsWith('description ')) {
        obj.description = child.slice(12).trim();
      } else if (child.startsWith('nat ')) {
        obj.natType = 'object';
        obj.natValue = child;
      }
    }

    if (obj.type) {
      objects.push(obj);
    }
  }

  return objects;
}


// ---------------------------------------------------------------------------
// Object Service Parser
// ---------------------------------------------------------------------------

function parseObjectServices(blocks, warnings) {
  const objects = [];

  for (const block of blocks) {
    if (!block.command.startsWith('object service ')) continue;
    const name = block.command.slice(15).trim();
    const obj = { name, protocol: '', srcPort: '', dstPort: '', description: '' };

    for (const child of block.children) {
      if (child.startsWith('service ')) {
        const parts = child.slice(8).trim().split(/\s+/);
        obj.protocol = parts[0] || '';
        // Parse source/destination port combinations
        for (let i = 1; i < parts.length; i++) {
          if (parts[i] === 'source' && parts[i + 1]) {
            obj.srcPort = normalizeAsaPort(parts[i + 1], parts[i + 2]);
            i += parts[i + 2] && !['destination', 'source'].includes(parts[i + 2]) ? 2 : 1;
          } else if (parts[i] === 'destination' && parts[i + 1]) {
            obj.dstPort = normalizeAsaPort(parts[i + 1], parts[i + 2]);
            i += parts[i + 2] && !['destination', 'source'].includes(parts[i + 2]) ? 2 : 1;
          } else if (parts[i] === 'eq' || parts[i] === 'range' || parts[i] === 'gt' || parts[i] === 'lt') {
            obj.dstPort = normalizeAsaPort(parts[i], parts[i + 1], parts[i + 2]);
            break;
          }
        }
      } else if (child.startsWith('description ')) {
        obj.description = child.slice(12).trim();
      }
    }

    objects.push(obj);
  }

  return objects;
}


// ---------------------------------------------------------------------------
// Object-Group Network Parser
// ---------------------------------------------------------------------------

function parseObjectGroupNetworks(blocks, warnings) {
  const groups = [];

  for (const block of blocks) {
    if (!block.command.startsWith('object-group network ')) continue;
    const name = block.command.slice(21).trim();
    const members = [];
    let description = '';

    for (const child of block.children) {
      if (child.startsWith('network-object host ')) {
        members.push(child.slice(20).trim());
      } else if (child.startsWith('network-object object ')) {
        members.push(child.slice(22).trim());
      } else if (child.startsWith('network-object ')) {
        // network-object 10.0.0.0 255.255.255.0
        const parts = child.slice(15).trim().split(/\s+/);
        if (parts.length === 2) {
          members.push(`${parts[0]}/${maskToCidr(parts[1])}`);
        } else {
          members.push(parts[0]);
        }
      } else if (child.startsWith('group-object ')) {
        members.push(child.slice(13).trim());
      } else if (child.startsWith('description ')) {
        description = child.slice(12).trim();
      }
    }

    groups.push({ name, members, description });
  }

  return groups;
}


// ---------------------------------------------------------------------------
// Object-Group Service Parser
// ---------------------------------------------------------------------------

function parseObjectGroupServices(blocks, warnings) {
  const groups = [];

  for (const block of blocks) {
    if (!block.command.startsWith('object-group service ')) continue;
    const rest = block.command.slice(21).trim();
    const parts = rest.split(/\s+/);
    const name = parts[0];
    const protocol = parts[1] || ''; // may be tcp, udp, tcp-udp, or empty
    const members = [];
    let description = '';

    for (const child of block.children) {
      if (child.startsWith('port-object ')) {
        const portParts = child.slice(12).trim().split(/\s+/);
        members.push(normalizeAsaPort(portParts[0], portParts[1], portParts[2]));
      } else if (child.startsWith('service-object ')) {
        const svcParts = child.slice(15).trim().split(/\s+/);
        if (svcParts[0] === 'object') {
          members.push(svcParts[1]);
        } else {
          members.push(child.slice(15).trim());
        }
      } else if (child.startsWith('group-object ')) {
        members.push(child.slice(13).trim());
      } else if (child.startsWith('description ')) {
        description = child.slice(12).trim();
      }
    }

    groups.push({ name, protocol, members, description });
  }

  return groups;
}


// ---------------------------------------------------------------------------
// Object-Group Protocol Parser
// ---------------------------------------------------------------------------

function parseObjectGroupProtocols(blocks, warnings) {
  const groups = [];

  for (const block of blocks) {
    if (!block.command.startsWith('object-group protocol ')) continue;
    const name = block.command.slice(22).trim();
    const members = [];

    for (const child of block.children) {
      if (child.startsWith('protocol-object ')) {
        members.push(child.slice(16).trim());
      }
    }

    groups.push({ name, members });
  }

  return groups;
}


// ---------------------------------------------------------------------------
// Access-List Parser
// ---------------------------------------------------------------------------

function parseAccessLists(lines, warnings) {
  const aclMap = {}; // aclName → [entries]

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('access-list ')) continue;

    const tokens = tokenize(trimmed);
    if (tokens.length < 3) continue;

    const aclName = tokens[1];
    if (!aclMap[aclName]) aclMap[aclName] = [];

    // Check for remarks — can appear as:
    //   access-list <name> remark <text>
    //   access-list <name> extended remark <text>
    if (tokens[2] === 'remark') {
      aclMap[aclName].push({
        type: 'remark',
        text: tokens.slice(3).join(' '),
      });
      continue;
    }
    if (tokens[2] === 'extended' && tokens[3] === 'remark') {
      aclMap[aclName].push({
        type: 'remark',
        text: tokens.slice(4).join(' '),
      });
      continue;
    }

    // access-list <name> extended <permit|deny> <protocol> <src> <dst> [ports] [log] [inactive]
    if (tokens[2] !== 'extended') {
      // standard or webtype ACLs — skip for now
      warnings.push(createWarning('warning', `acl:${aclName}`, `Non-extended ACL type "${tokens[2]}" not fully supported`, 'Review manually'));
      continue;
    }

    const entry = parseAclEntry(tokens.slice(3), aclName, warnings);
    if (entry) {
      aclMap[aclName].push(entry);
    }
  }

  return aclMap;
}

function parseAclEntry(tokens, aclName, warnings) {
  let i = 0;
  const entry = {
    type: 'rule',
    action: '',
    protocol: 'ip',
    srcAddr: 'any',
    srcPort: '',
    dstAddr: 'any',
    dstPort: '',
    log: false,
    logLevel: '',
    inactive: false,
    remark: '',
    _aclName: aclName,
  };

  if (i >= tokens.length) return null;

  // Action
  entry.action = tokens[i++]; // permit or deny

  // Protocol
  if (i < tokens.length) {
    entry.protocol = tokens[i++];
  }

  // Source address
  const srcResult = parseAclAddress(tokens, i);
  entry.srcAddr = srcResult.addr;
  i = srcResult.nextIndex;

  // Source port (for tcp/udp)
  if (['tcp', 'udp', 'tcp-udp'].includes(entry.protocol.toLowerCase())) {
    const srcPortResult = parseAclPort(tokens, i);
    if (srcPortResult.port && !srcPortResult.isDestPort) {
      entry.srcPort = srcPortResult.port;
      i = srcPortResult.nextIndex;
    }
  }

  // Destination address
  const dstResult = parseAclAddress(tokens, i);
  entry.dstAddr = dstResult.addr;
  i = dstResult.nextIndex;

  // Destination port (for tcp/udp)
  if (['tcp', 'udp', 'tcp-udp'].includes(entry.protocol.toLowerCase())) {
    const dstPortResult = parseAclPort(tokens, i);
    if (dstPortResult.port) {
      entry.dstPort = dstPortResult.port;
      i = dstPortResult.nextIndex;
    }
  }

  // ICMP type and code (for icmp/icmp6 protocols)
  if (['icmp', 'icmp6'].includes(entry.protocol.toLowerCase())) {
    const trailingFlags = ['log', 'inactive', 'time-range'];
    if (i < tokens.length && !trailingFlags.includes(tokens[i].toLowerCase())) {
      entry.icmpType = tokens[i++];
      if (i < tokens.length && !trailingFlags.includes(tokens[i].toLowerCase())) {
        entry.icmpCode = tokens[i++];
      }
    }
  }

  // Trailing flags: log, inactive, time-range
  while (i < tokens.length) {
    const tok = tokens[i].toLowerCase();
    if (tok === 'log') {
      entry.log = true;
      i++;
      // optional log level
      if (i < tokens.length && !['inactive', 'time-range'].includes(tokens[i].toLowerCase())) {
        entry.logLevel = tokens[i++];
      }
    } else if (tok === 'inactive') {
      entry.inactive = true;
      i++;
    } else if (tok === 'time-range') {
      i++;
      if (i < tokens.length) {
        entry.timeRange = tokens[i++];
      }
    } else {
      i++;
    }
  }

  return entry;
}

function parseAclAddress(tokens, i) {
  if (i >= tokens.length) return { addr: 'any', nextIndex: i };

  const tok = tokens[i];

  if (tok === 'any' || tok === 'any4' || tok === 'any6') {
    return { addr: 'any', nextIndex: i + 1 };
  }

  if (tok === 'host') {
    return { addr: tokens[i + 1] || 'any', nextIndex: i + 2 };
  }

  if (tok === 'object' || tok === 'object-group') {
    return { addr: tokens[i + 1] || 'any', nextIndex: i + 2 };
  }

  // Network/mask pair: 10.0.0.0 255.255.255.0
  if (isIpAddress(tok) && i + 1 < tokens.length && isIpAddress(tokens[i + 1])) {
    return { addr: `${tok}/${maskToCidr(tokens[i + 1])}`, nextIndex: i + 2 };
  }

  // Interface
  if (tok === 'interface') {
    return { addr: `interface:${tokens[i + 1] || ''}`, nextIndex: i + 2 };
  }

  return { addr: tok, nextIndex: i + 1 };
}

function parseAclPort(tokens, i) {
  if (i >= tokens.length) return { port: '', nextIndex: i, isDestPort: false };

  const tok = tokens[i];
  if (tok === 'eq' && i + 1 < tokens.length) {
    return { port: tokens[i + 1], nextIndex: i + 2 };
  }
  if (tok === 'neq' && i + 1 < tokens.length) {
    return { port: `!${tokens[i + 1]}`, nextIndex: i + 2 };
  }
  if (tok === 'range' && i + 2 < tokens.length) {
    return { port: `${tokens[i + 1]}-${tokens[i + 2]}`, nextIndex: i + 3 };
  }
  if (tok === 'gt' && i + 1 < tokens.length) {
    return { port: `>${tokens[i + 1]}`, nextIndex: i + 2 };
  }
  if (tok === 'lt' && i + 1 < tokens.length) {
    return { port: `<${tokens[i + 1]}`, nextIndex: i + 2 };
  }
  if (tok === 'object-group' && i + 1 < tokens.length) {
    return { port: tokens[i + 1], nextIndex: i + 2 };
  }

  return { port: '', nextIndex: i };
}


// ---------------------------------------------------------------------------
// Access-Group Parser
// ---------------------------------------------------------------------------

function parseAccessGroups(lines, warnings) {
  const groups = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('access-group ')) continue;
    // access-group <acl-name> <in|out> interface <nameif>
    const tokens = tokenize(trimmed);
    if (tokens.length >= 5 && tokens[3] === 'interface') {
      groups.push({
        aclName: tokens[1],
        direction: tokens[2], // in or out
        interface: tokens[4],
      });
    } else if (tokens.length >= 3 && tokens[2] === 'global') {
      groups.push({
        aclName: tokens[1],
        direction: 'in',
        interface: 'global',
      });
    }
  }

  return groups;
}


// ---------------------------------------------------------------------------
// NAT Parser
// ---------------------------------------------------------------------------

function parseNatRules(blocks, lines, warnings) {
  const natRules = [];
  let ruleIndex = 1;

  // Object NAT (auto nat) — defined inside object network blocks
  for (const block of blocks) {
    if (!block.command.startsWith('object network ')) continue;
    const objName = block.command.slice(15).trim();

    for (const child of block.children) {
      if (!child.startsWith('nat ')) continue;
      // nat (inside,outside) dynamic interface
      // nat (inside,outside) static 203.0.113.10
      const match = child.match(/nat\s+\(([^,]+),([^)]+)\)\s+(dynamic|static)\s+(.*)/);
      if (match) {
        const [, srcIf, dstIf, natType, rest] = match;
        natRules.push({
          name: `Auto-NAT-${objName}`,
          type: natType === 'static' ? 'static' : 'source',
          src_zones: [srcIf.trim()],
          dst_zones: [dstIf.trim()],
          src_addresses: [objName],
          dst_addresses: ['any'],
          translated_src: {
            type: natType === 'static' ? 'static-ip' : rest.trim() === 'interface' ? 'interface' : 'dynamic-ip-pool',
            addresses: rest.trim() === 'interface' ? [] : [rest.trim().split(/\s+/)[0]],
          },
          translated_dst: null,
          translated_port: null,
          description: `Auto NAT for ${objName}`,
          _rule_index: ruleIndex++,
        });
      }
    }
  }

  // Manual/Twice NAT — top-level nat statements
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('nat ') || trimmed.includes('description')) continue;
    // Skip indented nat lines (those are inside object blocks)
    if (line[0] === ' ' || line[0] === '\t') continue;

    // nat (inside,outside) source dynamic any interface
    // nat (inside,outside) source static obj-internal obj-external destination static obj-dmz obj-dmz
    const match = trimmed.match(/nat\s+\(([^,]+),([^)]+)\)\s+(.*)/);
    if (match) {
      const [, srcIf, dstIf, rest] = match;
      natRules.push({
        name: `Manual-NAT-${ruleIndex}`,
        type: 'source',
        src_zones: [srcIf.trim()],
        dst_zones: [dstIf.trim()],
        src_addresses: ['any'],
        dst_addresses: ['any'],
        translated_src: { type: 'manual', addresses: [] },
        translated_dst: null,
        translated_port: null,
        description: rest.trim(),
        _rule_index: ruleIndex++,
      });
    }
  }

  return natRules;
}


// ---------------------------------------------------------------------------
// Build functions: transform parsed data into intermediate schema
// ---------------------------------------------------------------------------

function buildZones(interfaces) {
  return interfaces
    .filter(iface => !iface.shutdown)
    .map(iface => ({
      name: iface.nameif,
      description: iface.description || `Security Level ${iface.securityLevel}`,
      interfaces: [iface.hardware],
      _cisco: {
        securityLevel: iface.securityLevel,
        hardware: iface.hardware,
        ip: iface.ip,
      },
    }));
}

function buildAddressObjects(objectNetworks) {
  return objectNetworks.map(obj => {
    const result = {
      name: obj.name,
      type: obj.type === 'host' ? 'host' : obj.type,
      value: obj.type === 'host' ? `${obj.value}/32` : obj.value,
      description: obj.description,
      tags: [],
    };
    // Preserve FQDN IP version for SRX ipv4-only/ipv6-only
    if (obj.fqdn_ip_version) {
      result.fqdn_ip_version = obj.fqdn_ip_version;
    }
    return result;
  });
}

function buildAddressGroups(objectGroupNetworks) {
  return objectGroupNetworks.map(g => ({
    name: g.name,
    members: g.members,
    description: g.description,
    tags: [],
  }));
}

function buildServiceObjects(objectServices, objectGroupProtocols) {
  const services = [];

  for (const obj of objectServices) {
    services.push({
      name: obj.name,
      protocol: obj.protocol.toLowerCase(),
      port_range: obj.dstPort || 'any',
      source_port: obj.srcPort || '',
      description: obj.description,
    });
  }

  return services;
}

function buildServiceGroups(objectGroupServices) {
  return objectGroupServices.map(g => ({
    name: g.name,
    members: g.members,
    description: g.description,
    _protocol: g.protocol,
  }));
}

function parseTimeRanges(blocks) {
  const ranges = [];
  for (const block of blocks) {
    if (!block.command.startsWith('time-range ')) continue;
    const name = block.command.slice(11).trim();
    let type = 'unknown';
    let start = '', end = '', days = [];

    for (const child of block.children) {
      const trimmed = child.trim();
      if (trimmed.startsWith('absolute')) {
        type = 'onetime';
        // "absolute start HH:MM DD Month YYYY end HH:MM DD Month YYYY"
        const match = trimmed.match(/start\s+(.+?)\s+end\s+(.+)/);
        if (match) { start = match[1].trim(); end = match[2].trim(); }
      } else if (trimmed.startsWith('periodic')) {
        type = 'recurring';
        // "periodic weekdays 08:00 to 17:00" or "periodic Monday Wednesday 08:00 to 17:00"
        const parts = trimmed.slice(9).trim();
        const dayNames = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday', 'weekdays', 'weekend', 'daily'];
        const tokens = parts.split(/\s+/);
        for (const tok of tokens) {
          const lower = tok.toLowerCase();
          if (lower === 'weekdays') {
            days.push('Mon', 'Tue', 'Wed', 'Thu', 'Fri');
          } else if (lower === 'weekend') {
            days.push('Sat', 'Sun');
          } else if (lower === 'daily') {
            days.push('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun');
          } else if (dayNames.includes(lower)) {
            days.push(lower.charAt(0).toUpperCase() + lower.slice(1, 3));
          }
        }
        // Extract time range: "HH:MM to HH:MM"
        const timeMatch = parts.match(/(\d{1,2}:\d{2})\s+to\s+(\d{1,2}:\d{2})/);
        if (timeMatch) { start = timeMatch[1]; end = timeMatch[2]; }
      }
    }
    ranges.push({ name, type, days, start, end });
  }
  return ranges;
}

function buildSecurityPolicies(accessLists, accessGroups, interfaces, warnings) {
  const policies = [];
  let ruleIndex = 1;

  // Map interfaces by nameif for security-level lookup
  const ifaceMap = {};
  for (const iface of interfaces) {
    ifaceMap[iface.nameif] = iface;
  }

  // Build from access-groups first (these bind ACLs to interfaces with direction)
  const processedAcls = new Set();

  for (const ag of accessGroups) {
    const entries = accessLists[ag.aclName];
    if (!entries) continue;
    processedAcls.add(ag.aclName);

    let remarkAccum = '';

    for (const entry of entries) {
      if (entry.type === 'remark') {
        remarkAccum = entry.text;
        continue;
      }

      // Determine src/dst zones from access-group binding
      const srcZone = ag.direction === 'in' ? ag.interface : '';
      const dstZone = ag.direction === 'out' ? ag.interface : '';

      const policy = {
        name: remarkAccum || `${ag.aclName}-${ruleIndex}`,
        src_zones: srcZone ? [srcZone] : [],
        dst_zones: dstZone ? [dstZone] : [],
        src_addresses: entry.srcAddr === 'any' ? ['any'] : [entry.srcAddr],
        dst_addresses: entry.dstAddr === 'any' ? ['any'] : [entry.dstAddr],
        negate_source: false,
        negate_destination: false,
        applications: [],
        services: buildServiceFromAcl(entry),
        action: entry.action === 'permit' ? 'allow' : 'deny',
        log_start: false,
        log_end: entry.log,
        profile_group: '',
        security_profiles: {},
        description: remarkAccum,
        tags: [],
        disabled: entry.inactive,
        schedule: entry.timeRange || '',
        _rule_index: ruleIndex++,
        _cisco: {
          aclName: ag.aclName,
          interface: ag.interface,
          direction: ag.direction,
          protocol: entry.protocol,
          srcPort: entry.srcPort,
          dstPort: entry.dstPort,
          icmpType: entry.icmpType || '',
          icmpCode: entry.icmpCode || '',
          timeRange: entry.timeRange || '',
          securityLevel: ifaceMap[ag.interface]?.securityLevel,
          logLevel: entry.logLevel,
        },
      };

      policies.push(policy);
      remarkAccum = '';
    }
  }

  // Process any ACLs not bound to access-groups
  for (const [aclName, entries] of Object.entries(accessLists)) {
    if (processedAcls.has(aclName)) continue;

    let remarkAccum = '';
    for (const entry of entries) {
      if (entry.type === 'remark') {
        remarkAccum = entry.text;
        continue;
      }

      const policy = {
        name: remarkAccum || `${aclName}-${ruleIndex}`,
        src_zones: [],
        dst_zones: [],
        src_addresses: entry.srcAddr === 'any' ? ['any'] : [entry.srcAddr],
        dst_addresses: entry.dstAddr === 'any' ? ['any'] : [entry.dstAddr],
        negate_source: false,
        negate_destination: false,
        applications: [],
        services: buildServiceFromAcl(entry),
        action: entry.action === 'permit' ? 'allow' : 'deny',
        log_start: false,
        log_end: entry.log,
        profile_group: '',
        security_profiles: {},
        description: remarkAccum,
        tags: [],
        disabled: entry.inactive,
        schedule: entry.timeRange || '',
        _rule_index: ruleIndex++,
        _cisco: {
          aclName,
          interface: '',
          direction: '',
          protocol: entry.protocol,
          srcPort: entry.srcPort,
          dstPort: entry.dstPort,
          icmpType: entry.icmpType || '',
          icmpCode: entry.icmpCode || '',
          timeRange: entry.timeRange || '',
        },
      };

      policies.push(policy);
      remarkAccum = '';
    }
  }

  // --- Implicit Rules ---

  // Build set of interfaces with inbound ACLs (ACL overrides security-level behavior)
  const interfacesWithInboundAcl = new Set(
    accessGroups.filter(ag => ag.direction === 'in').map(ag => ag.interface)
  );

  // Security-level implicit allows for interfaces WITHOUT inbound ACLs
  const activeIfaces = interfaces.filter(i => i.nameif && !i.shutdown);
  for (const srcIface of activeIfaces) {
    if (interfacesWithInboundAcl.has(srcIface.nameif)) continue;
    for (const dstIface of activeIfaces) {
      if (srcIface.nameif === dstIface.nameif) continue;
      if (srcIface.securityLevel > dstIface.securityLevel) {
        policies.push({
          name: `Implicit: ${srcIface.nameif}(${srcIface.securityLevel}) → ${dstIface.nameif}(${dstIface.securityLevel}) Allow`,
          src_zones: [srcIface.nameif],
          dst_zones: [dstIface.nameif],
          src_addresses: ['any'],
          dst_addresses: ['any'],
          negate_source: false,
          negate_destination: false,
          applications: [],
          services: ['any'],
          action: 'allow',
          log_start: false,
          log_end: false,
          profile_group: '',
          security_profiles: {},
          description: `ASA implicit: higher security-level (${srcIface.securityLevel}) to lower (${dstIface.securityLevel})`,
          tags: ['added_by_fpic'],
          disabled: false,
          _rule_index: ruleIndex++,
          _implicit: true,
          _cisco: {
            aclName: '',
            interface: srcIface.nameif,
            direction: '',
            protocol: 'ip',
            srcPort: '',
            dstPort: '',
            icmpType: '',
            icmpCode: '',
            timeRange: '',
            securityLevel: srcIface.securityLevel,
            logLevel: '',
          },
        });
      }
    }
  }

  // Global implicit deny
  policies.push({
    name: 'Implicit: Default Deny',
    src_zones: ['any'],
    dst_zones: ['any'],
    src_addresses: ['any'],
    dst_addresses: ['any'],
    negate_source: false,
    negate_destination: false,
    applications: [],
    services: ['any'],
    action: 'deny',
    log_start: false,
    log_end: false,
    profile_group: '',
    security_profiles: {},
    description: 'ASA implicit deny at end of all access-lists',
    tags: ['added_by_fpic'],
    disabled: false,
    _rule_index: ruleIndex++,
    _implicit: true,
    _cisco: {
      aclName: '',
      interface: '',
      direction: '',
      protocol: 'ip',
      srcPort: '',
      dstPort: '',
      icmpType: '',
      icmpCode: '',
      timeRange: '',
      securityLevel: 0,
      logLevel: '',
    },
  });

  return policies;
}

function buildServiceFromAcl(entry) {
  const proto = (entry.protocol || 'ip').toLowerCase();
  if (proto === 'ip' || proto === 'object-group') {
    return [entry.protocol === 'object-group' ? entry.srcAddr : 'any'];
  }
  if (proto === 'icmp' || proto === 'icmp6') {
    if (entry.icmpType) {
      return [`icmp/${entry.icmpType}${entry.icmpCode ? '/' + entry.icmpCode : ''}`];
    }
    return ['icmp'];
  }

  const port = entry.dstPort || 'any';
  if (port === 'any' || port === '') {
    return [`${proto}`];
  }

  // Map well-known port names
  const portName = mapWellKnownPort(port);
  return [`${proto}/${portName}`];
}


// ---------------------------------------------------------------------------
// Version Extraction
// ---------------------------------------------------------------------------

function extractVersion(lines) {
  for (const line of lines) {
    const trimmed = line.trim();
    // ASA Version 9.x
    if (trimmed.startsWith('ASA Version ')) {
      return trimmed.slice(12).trim();
    }
    // FXOS / FTD
    if (trimmed.startsWith('Cisco Adaptive Security Appliance Software Version')) {
      return trimmed.split('Version')[1]?.trim() || '';
    }
  }
  return '';
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tokenize(line) {
  const tokens = [];
  let i = 0;
  while (i < line.length) {
    while (i < line.length && /\s/.test(line[i])) i++;
    if (i >= line.length) break;

    if (line[i] === '"') {
      i++;
      let token = '';
      while (i < line.length && line[i] !== '"') {
        token += line[i++];
      }
      i++; // skip closing quote
      tokens.push(token);
    } else {
      let token = '';
      while (i < line.length && !/\s/.test(line[i])) {
        token += line[i++];
      }
      tokens.push(token);
    }
  }
  return tokens;
}

function isIpAddress(s) {
  if (!s) return false;
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s);
}

function maskToCidr(mask) {
  if (!mask) return '32';
  if (/^\d+$/.test(mask) && parseInt(mask) <= 32) return mask;
  const parts = mask.split('.');
  if (parts.length !== 4) return '32';
  let cidr = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    cidr += (n >>> 0).toString(2).split('1').length - 1;
  }
  return String(cidr);
}

function normalizeAsaPort(op, val1, val2) {
  if (!op) return '';
  if (op === 'eq') return val1 || '';
  if (op === 'range') return `${val1}-${val2 || ''}`;
  if (op === 'gt') return `>${val1}`;
  if (op === 'lt') return `<${val1}`;
  if (op === 'neq') return `!${val1}`;
  return op; // literal port name or number
}

function mapWellKnownPort(port) {
  const portMap = {
    'www': '80', 'http': '80', 'https': '443',
    'ssh': '22', 'telnet': '23', 'ftp': '21', 'ftp-data': '20',
    'smtp': '25', 'pop3': '110', 'imap4': '143',
    'dns': '53', 'domain': '53',
    'ntp': '123', 'snmp': '161', 'snmptrap': '162',
    'syslog': '514', 'tftp': '69',
    'ldap': '389', 'ldaps': '636',
    'h323': '1720', 'sip': '5060',
    'sqlnet': '1521', 'mysql': '3306',
    'rdp': '3389',
  };
  return portMap[port.toLowerCase()] || port;
}

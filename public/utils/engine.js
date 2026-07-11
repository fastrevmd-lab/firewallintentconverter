/**
 * Engine — client-side replacements for the former Express API endpoints.
 *
 * All parsers, converters, validators, and the sanitizer run entirely
 * in the browser.  No server required.
 */

import { detectVendor } from '../../src/parsers/parser-utils.js';
import { normalizeConversionOutput } from '../../src/conversion/conversion-output.js';

// All parsers, converters, validators, and analysis modules are loaded on
// demand via dynamic import() — see parseConfig / convertConfig / mergeConvert.

// ---------------------------------------------------------------------------
// parseConfig  (replaces POST /api/parse)
// ---------------------------------------------------------------------------
export async function parseConfig(configText) {
  if (!configText || typeof configText !== 'string') {
    throw new Error('configText is required and must be a string');
  }

  const detection = detectVendor(configText);
  let result;

  const parserMap = {
    srx:        () => import('../../src/parsers/srx-parser.js'),
    fortigate:  () => import('../../src/parsers/fortigate-parser.js'),
    cisco_asa:  () => import('../../src/parsers/cisco-asa-parser.js'),
    checkpoint: () => import('../../src/parsers/checkpoint-parser.js'),
    sonicwall:  () => import('../../src/parsers/sonicwall-parser.js'),
    huawei_usg: () => import('../../src/parsers/huawei-parser.js'),
    aws_sg:     () => import('../../src/parsers/aws-sg-parser.js'),
    azure_nsg:  () => import('../../src/parsers/azure-nsg-parser.js'),
    gcp_fw:     () => import('../../src/parsers/gcp-fw-parser.js'),
  };

  const fnNameMap = {
    srx:        'parseSrxConfig',
    fortigate:  'parseFortigateConfig',
    cisco_asa:  'parseCiscoAsaConfig',
    checkpoint: 'parseCheckPointConfig',
    sonicwall:  'parseSonicWallConfig',
    huawei_usg: 'parseHuaweiConfig',
    aws_sg:     'parseAwsSecurityGroups',
    azure_nsg:  'parseAzureNsg',
    gcp_fw:     'parseGcpFirewallRules',
  };

  if (parserMap[detection.vendor]) {
    const mod = await parserMap[detection.vendor]();
    result = mod[fnNameMap[detection.vendor]](configText);
  } else {
    const mod = await import('../../src/parsers/panos-parser.js');
    result = mod.parsePanosConfig(configText);
  }

  result.detectedVendor = detection.vendor;
  return result;
}

// ---------------------------------------------------------------------------
// convertConfig  (replaces POST /api/convert)
// ---------------------------------------------------------------------------
export async function convertConfig(intermediateConfig, format = 'set', interfaceMappings = {}, targetContext = null) {
  if (!intermediateConfig) {
    throw new Error('intermediateConfig is required');
  }
  if (!['set', 'xml'].includes(format)) {
    throw new Error("format must be 'set' or 'xml'");
  }

  const [converterMod, xmlMod, validatorMod, shadowMod, appMappingsMod, parserUtilsMod, outputValidatorMod] = await Promise.all([
    import('../../src/converters/srx-converter.js'),
    import('../../src/converters/srx-xml-builder.js'),
    import('../../src/validators/srx-validator.js'),
    import('../../src/analysis/shadow-detector.js'),
    import('../../src/utils/app-mappings.js'),
    import('../../src/parsers/parser-utils.js'),
    import('../../src/security/junos-output-validation.js'),
  ]);

  // Preload app mappings and inject into parser-utils for enhanced app resolution
  try {
    await appMappingsMod.loadAppMappings();
    parserUtilsMod.setMapVendorApp(appMappingsMod.mapVendorApp);
  } catch (_) { /* app mappings load failure is non-fatal */ }

  let output;
  if (format === 'xml') {
    output = xmlMod.buildSrxXml(intermediateConfig, interfaceMappings, targetContext);
  } else {
    output = converterMod.convertToSrxSetCommands(intermediateConfig, interfaceMappings, targetContext);
  }
  if (format === 'xml') outputValidatorMod.validateXmlOutput(output.xml);
  else outputValidatorMod.validateSetOutput(output.commands);
  if (format === 'set') {
    output = {
      ...output,
      commands: output.commands.filter(command => typeof command !== 'string' || command.trim().length > 0),
    };
  }
  output = normalizeConversionOutput(output, format);

  // Detect shadowed rules and optimization opportunities
  const analysis = shadowMod.detectShadowedRules(intermediateConfig.security_policies, output.warnings);
  if (output.summary) {
    output.summary.shadowed_rules = analysis.shadowedCount;
    output.summary.reorder_issues = analysis.reorderCount;
    output.summary.optimization_suggestions =
      (analysis.redundantCount || 0) + (analysis.mergeableCount || 0) + (analysis.consolidateCount || 0);
  }

  // Run validation on the generated output
  const validation = validatorMod.validateSrxOutput(intermediateConfig, output);

  return { output, format: output.format, validation };
}

// ---------------------------------------------------------------------------
// mergeConvert  (replaces POST /api/merge-convert)
// ---------------------------------------------------------------------------
export async function mergeConvert(configSlots, crossLsLinks = [], format = 'set', globalConfig = {}) {
  if (!configSlots || !Array.isArray(configSlots) || configSlots.length < 1) {
    throw new Error('configSlots array is required with at least 1 entry');
  }
  if (!['set', 'xml'].includes(format)) {
    throw new Error("format must be 'set' or 'xml'");
  }

  const [converterMod, xmlMod, outputValidatorMod] = await Promise.all([
    import('../../src/converters/srx-converter.js'),
    import('../../src/converters/srx-xml-builder.js'),
    import('../../src/security/junos-output-validation.js'),
  ]);

  let output;
  if (format === 'xml') {
    output = xmlMod.buildMergedSrxXml(configSlots, crossLsLinks, globalConfig);
  } else {
    output = converterMod.convertMergedToSrxSetCommands(configSlots, crossLsLinks, globalConfig);
  }
  if (format === 'xml') outputValidatorMod.validateXmlOutput(output.xml);
  else outputValidatorMod.validateSetOutput(output.commands);
  if (format === 'set') {
    output = {
      ...output,
      commands: output.commands.filter(command => typeof command !== 'string' || command.trim().length > 0),
    };
  }
  output = normalizeConversionOutput(output, format);

  return { output, format: output.format };
}

// ---------------------------------------------------------------------------
// sanitizeConfig  (replaces POST /api/sanitize)
// ---------------------------------------------------------------------------

/** Valid contiguous subnet masks — never sanitize these. */
const SUBNET_MASKS = new Set([
  '0.0.0.0', '128.0.0.0', '192.0.0.0', '224.0.0.0', '240.0.0.0',
  '248.0.0.0', '252.0.0.0', '254.0.0.0', '255.0.0.0', '255.128.0.0',
  '255.192.0.0', '255.224.0.0', '255.240.0.0', '255.248.0.0', '255.252.0.0',
  '255.254.0.0', '255.255.0.0', '255.255.128.0', '255.255.192.0',
  '255.255.224.0', '255.255.240.0', '255.255.248.0', '255.255.252.0',
  '255.255.254.0', '255.255.255.0', '255.255.255.128', '255.255.255.192',
  '255.255.255.224', '255.255.255.240', '255.255.255.248', '255.255.255.252',
  '255.255.255.254', '255.255.255.255',
]);

/** Zone names that should never be sanitized. */
const ZONE_SKIP = new Set(['any', 'global', 'local', 'self']);

/** Built-in service / object names that should never be sanitized. */
const BUILTIN_SKIP = new Set([
  'any', 'all', 'none', 'tcp', 'udp', 'icmp', 'http', 'https', 'ssh', 'ftp',
  'dns', 'smtp', 'snmp', 'bgp', 'ospf', 'ldap', 'ntp', 'dhcp', 'tftp',
  'pop3', 'imap', 'sip', 'rtsp', 'gre', 'ipsec', 'l2tp', 'pptp', 'ping',
  'traceroute',
]);

/** Structural interface names — hardware-oriented, not topology-revealing. */
const STRUCTURAL_INTF_RE = /^(port\d+|wan\d*|lan\d*|dmz\d*|mgmt\d*|lo\d*|loopback\d*|ge-\d+\/\d+\/\d+|xe-\d+\/\d+\/\d+|et-\d+\/\d+\/\d+|ae\d+|irb\d*|vlan\d*|st\d+|reth\d+|em\d+|fxp\d+|me\d+|management\d*|ethernet\d*|gigabitethernet\d*|fastethernet\d*|tengigabitethernet\d*|tunnel\d*|bvi\d*|null\d*|any|self)$/i;

/**
 * Sanitize sensitive data in a firewall configuration string.
 * Supports PAN-OS XML, FortiGate, Cisco ASA, Juniper SRX, and generic formats.
 * @param {string} configText - Raw configuration text.
 * @returns {{ sanitizedText: string, replacements: Array, stats: Object }}
 */
export function sanitizeConfig(configText) {
  if (!configText || typeof configText !== 'string') {
    throw new Error('configText is required and must be a string');
  }
  const MAX_SANITIZE_LENGTH = 10 * 1024 * 1024; // 10 MB
  if (configText.length > MAX_SANITIZE_LENGTH) {
    throw new Error(`Config too large to sanitize (${(configText.length / 1024 / 1024).toFixed(1)} MB, max ${MAX_SANITIZE_LENGTH / 1024 / 1024} MB)`);
  }

  const replacements = [];
  const counter = {
    hash: 0, key: 0, user: 0, ip: 0, community: 0, cert: 0, host: 0, bgp: 0,
    device_hostname: 0, domain: 0, zone: 0, object: 0, private_ip: 0,
    ipv6: 0, email: 0, url: 0, description: 0, interface: 0,
  };

  // Deterministic maps — same input always gets the same placeholder.
  const ipMap = new Map();
  const privateIpMap = new Map();
  const ipv6Map = new Map();
  const domainMap = new Map();
  const emailMap = new Map();
  const zoneMap = new Map();
  const objectMap = new Map();
  const interfaceMap = new Map();

  let sanitized = configText;

  // --- Helpers ---------------------------------------------------------------

  /** Next RFC 5737 documentation IP (rotates 192.0.2.x / 198.51.100.x / 203.0.113.x). */
  const nextDocIp = () => {
    const idx = counter.ip++;
    const nets = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];
    const net = nets[idx % 3];
    const host = (Math.floor(idx / 3) % 254) + 1;
    return `${net[0]}.${net[1]}.${net[2]}.${host}`;
  };

  /** Next synthetic private IP in the 10.x.x.x range. */
  const nextPrivateIp = () => {
    const idx = counter.private_ip++;
    const host = (idx % 254) + 1;
    const third = Math.floor(idx / 254) % 256;
    const second = Math.floor(idx / (254 * 256));
    return `10.${second}.${third}.${host}`;
  };

  const isPrivateRfc1918 = (ip) => {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    return false;
  };

  const isPrivateOrReserved = (ip) => {
    const [a, b, c] = ip.split('.').map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a >= 224) return true;
    if (a === 0) return true;
    // RFC 5737 documentation ranges — avoid re-sanitizing our own placeholders.
    if (a === 192 && b === 0 && c === 2) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    return false;
  };

  const isSanitized = (v) => v.startsWith('SANITIZED_') || v.startsWith('zone-') ||
    v.startsWith('obj-') || v.startsWith('intf-') || v.startsWith('example-') ||
    v === 'sanitized-fw' || v === '(sanitized)';

  const getOrCreateDomain = (original) => {
    if (domainMap.has(original)) return domainMap.get(original);
    const idx = counter.domain++;
    const placeholder = `example-${idx}.net`;
    domainMap.set(original, placeholder);
    replacements.push({ type: 'domain', placeholder, original });
    return placeholder;
  };

  const getOrCreateZone = (original) => {
    if (ZONE_SKIP.has(original.toLowerCase())) return null;
    if (isSanitized(original)) return null;
    if (zoneMap.has(original)) return zoneMap.get(original);
    const idx = counter.zone++;
    const placeholder = `zone-${idx}`;
    zoneMap.set(original, placeholder);
    replacements.push({ type: 'zone', placeholder, original, restore: true });
    return placeholder;
  };

  const getOrCreateObject = (original) => {
    if (BUILTIN_SKIP.has(original.toLowerCase())) return null;
    if (isSanitized(original)) return null;
    if (objectMap.has(original)) return objectMap.get(original);
    const idx = counter.object++;
    const placeholder = `obj-${idx}`;
    objectMap.set(original, placeholder);
    replacements.push({ type: 'object', placeholder, original, restore: true });
    return placeholder;
  };

  const getOrCreateInterface = (original) => {
    if (STRUCTURAL_INTF_RE.test(original)) return null;
    if (isSanitized(original)) return null;
    if (interfaceMap.has(original)) return interfaceMap.get(original);
    const idx = counter.interface++;
    const placeholder = `intf-${idx}`;
    interfaceMap.set(original, placeholder);
    replacements.push({ type: 'interface', placeholder, original, restore: true });
    return placeholder;
  };

  // ==========================================================================
  // PASS 1: Descriptions / comments (early — remove free text before IPs etc.)
  // ==========================================================================

  // ASA: description <text>
  sanitized = sanitized.replace(
    /^(\s*description\s+)(.+)$/gm,
    (match, prefix, value) => {
      if (value.trim() === '(sanitized)') return match;
      counter.description++;
      replacements.push({ type: 'description', placeholder: '(sanitized)', original: value.trim() });
      return `${prefix}(sanitized)`;
    }
  );

  // ASA: remark <text>
  sanitized = sanitized.replace(
    /^(\s*remark\s+)(.+)$/gm,
    (match, prefix, value) => {
      if (value.trim() === '(sanitized)') return match;
      counter.description++;
      replacements.push({ type: 'description', placeholder: '(sanitized)', original: value.trim() });
      return `${prefix}(sanitized)`;
    }
  );

  // FortiGate: set comment "..." or set comments "..."
  sanitized = sanitized.replace(
    /(set\s+comments?\s+)"([^"]+)"/gi,
    (match, prefix, value) => {
      if (value === '(sanitized)') return match;
      counter.description++;
      replacements.push({ type: 'description', placeholder: '(sanitized)', original: value });
      return `${prefix}"(sanitized)"`;
    }
  );

  // PAN-OS XML: <description>text</description>
  sanitized = sanitized.replace(
    /(<description>)([^<]+)(<\/description>)/gi,
    (match, open, value, close) => {
      if (value.trim() === '(sanitized)') return match;
      counter.description++;
      replacements.push({ type: 'description', placeholder: '(sanitized)', original: value.trim() });
      return `${open}(sanitized)${close}`;
    }
  );

  // SRX / generic: description "text"
  sanitized = sanitized.replace(
    /^(\s*description\s+)"([^"]+)"/gm,
    (match, prefix, value) => {
      if (value === '(sanitized)') return match;
      counter.description++;
      replacements.push({ type: 'description', placeholder: '(sanitized)', original: value });
      return `${prefix}"(sanitized)"`;
    }
  );

  // ==========================================================================
  // PASS 2: Password hashes
  // ==========================================================================

  // XML tags: <phash>, <password-hash>, <encrypted-secret>
  sanitized = sanitized.replace(
    /(<(?:phash|password-hash|encrypted-secret)>)([^<]+)(<\/)/gi,
    (match, open, value, close) => {
      const idx = counter.hash++;
      const placeholder = `SANITIZED_HASH_${idx}`;
      replacements.push({ type: 'hash', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  // Hashes in attribute-style: password "$1$..."
  sanitized = sanitized.replace(
    /(password|secret|pre-shared-key|auth-key)\s+"(\$[^"]+)"/gi,
    (match, keyword, value) => {
      const idx = counter.hash++;
      const placeholder = `SANITIZED_HASH_${idx}`;
      replacements.push({ type: 'hash', placeholder, original: value });
      return `${keyword} "${placeholder}"`;
    }
  );

  // ASA: password <hash> encrypted
  sanitized = sanitized.replace(
    /(password\s+)(\S+)(\s+encrypted)/gi,
    (match, prefix, value, suffix) => {
      if (value.startsWith('SANITIZED_')) return match;
      const idx = counter.hash++;
      const placeholder = `SANITIZED_HASH_${idx}`;
      replacements.push({ type: 'hash', placeholder, original: value });
      return `${prefix}${placeholder}${suffix}`;
    }
  );

  // FortiGate: set password ENC <base64> — capture the whole ENC block
  sanitized = sanitized.replace(
    /(set\s+password\s+)(ENC\s+\S+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      const idx = counter.hash++;
      const placeholder = `SANITIZED_HASH_${idx}`;
      replacements.push({ type: 'hash', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  // ==========================================================================
  // PASS 3: Pre-shared keys and API keys
  // ==========================================================================

  // Nested XML: <pre-shared-key><key>VALUE</key>
  sanitized = sanitized.replace(
    /(<(?:pre-shared-key|api-key|auth-key|secret|key)>)\s*(<key>)([^<]+)(<\/key>)/gi,
    (match, outerOpen, innerOpen, value, innerClose) => {
      const idx = counter.key++;
      const placeholder = `SANITIZED_KEY_${idx}`;
      replacements.push({ type: 'key', placeholder, original: value.trim() });
      return `${outerOpen}${innerOpen}${placeholder}${innerClose}`;
    }
  );

  // Simple key value tags
  sanitized = sanitized.replace(
    /(<(?:pre-shared-key|api-key|auth-key|community|secret-key)>)([^<]+)(<\/)/gi,
    (match, open, value, close) => {
      if (value.trim().startsWith('SANITIZED_')) return match;
      const idx = counter.key++;
      const placeholder = `SANITIZED_KEY_${idx}`;
      replacements.push({ type: 'key', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  // IKE pre-shared keys: ikev1/ikev2 pre-shared-key
  sanitized = sanitized.replace(
    /(ikev[12]\s+(?:local-authentication\s+)?pre-shared-key\s+)(\S+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      const idx = counter.key++;
      const placeholder = `SANITIZED_KEY_${idx}`;
      replacements.push({ type: 'key', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  // ==========================================================================
  // PASS 4: SNMP communities (XML + CLI)
  // ==========================================================================

  sanitized = sanitized.replace(
    /(<community>)([^<]+)(<\/community>)/gi,
    (match, open, value, close) => {
      if (value.trim().startsWith('SANITIZED_')) return match;
      const idx = counter.community++;
      const placeholder = `SANITIZED_COMMUNITY_${idx}`;
      replacements.push({ type: 'community', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  // ASA/FTD: snmp-server community <name>
  sanitized = sanitized.replace(
    /(snmp-server\s+community\s+)(\S+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      const idx = counter.community++;
      const placeholder = `SANITIZED_COMMUNITY_${idx}`;
      replacements.push({ type: 'community', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  // SRX: set snmp community <name>
  sanitized = sanitized.replace(
    /(set\s+snmp\s+community\s+)(\S+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      const idx = counter.community++;
      const placeholder = `SANITIZED_COMMUNITY_${idx}`;
      replacements.push({ type: 'community', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  // ==========================================================================
  // PASS 5: Usernames
  // ==========================================================================

  sanitized = sanitized.replace(
    /(<(?:admin-username|radius-username|tacplus-username|ldap-bind-dn)>)([^<]+)(<\/)/gi,
    (match, open, value, close) => {
      const idx = counter.user++;
      const placeholder = `SANITIZED_USER_${idx}`;
      replacements.push({ type: 'username', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  // PAN-OS <users><entry name="xxx">
  sanitized = sanitized.replace(
    /(<users>\s*(?:<entry\s+name="))([^"]+)(")/gi,
    (match, prefix, name, suffix) => {
      if (name === 'admin' || name.startsWith('SANITIZED_')) return match;
      const idx = counter.user++;
      const placeholder = `SANITIZED_USER_${idx}`;
      replacements.push({ type: 'username', placeholder, original: name });
      return `${prefix}${placeholder}${suffix}`;
    }
  );

  // ASA: username <name> password/privilege/attributes
  sanitized = sanitized.replace(
    /^(\s*username\s+)(\S+)(\s+(?:password|privilege|attributes))/gm,
    (match, prefix, name, suffix) => {
      if (name === 'admin' || name.startsWith('SANITIZED_')) return match;
      const idx = counter.user++;
      const placeholder = `SANITIZED_USER_${idx}`;
      replacements.push({ type: 'username', placeholder, original: name });
      return `${prefix}${placeholder}${suffix}`;
    }
  );

  // FortiGate: config system admin → edit "name"
  sanitized = sanitized.replace(
    /(config\s+system\s+admin[\s\S]*?edit\s+)"([^"]+)"/gi,
    (match, prefix, name) => {
      if (name === 'admin' || name.startsWith('SANITIZED_')) return match;
      const idx = counter.user++;
      const placeholder = `SANITIZED_USER_${idx}`;
      replacements.push({ type: 'username', placeholder, original: name });
      return `${prefix}"${placeholder}"`;
    }
  );

  // SRX: set system login user <name>
  sanitized = sanitized.replace(
    /(set\s+system\s+login\s+user\s+)(\S+)/gi,
    (match, prefix, name) => {
      if (name === 'admin' || name.startsWith('SANITIZED_')) return match;
      const idx = counter.user++;
      const placeholder = `SANITIZED_USER_${idx}`;
      replacements.push({ type: 'username', placeholder, original: name });
      return `${prefix}${placeholder}`;
    }
  );

  // ==========================================================================
  // PASS 6: Certificates
  // ==========================================================================

  sanitized = sanitized.replace(
    /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----/g,
    (match) => {
      const idx = counter.cert++;
      const placeholder = `SANITIZED_CERT_${idx}`;
      replacements.push({ type: 'certificate', placeholder, original: match });
      return placeholder;
    }
  );

  sanitized = sanitized.replace(
    /(<(?:private-key|certificate-key|ssl-key)>)([^<]+)(<\/)/gi,
    (match, open, value, close) => {
      if (value.trim().startsWith('SANITIZED_')) return match;
      const idx = counter.cert++;
      const placeholder = `SANITIZED_CERT_${idx}`;
      replacements.push({ type: 'certificate', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  // ==========================================================================
  // PASS 7: Server hostnames / FQDNs
  // ==========================================================================

  sanitized = sanitized.replace(
    /(<(?:ldap-server-address|radius-server-ip|tacplus-server-ip|ntp-server-address|dns-server-address|server-address|server-name|server-host|syslog-server)>)([^<]+)(<\/)/gi,
    (match, open, value, close) => {
      if (value.trim().startsWith('SANITIZED_')) return match;
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value.trim())) return match;
      const idx = counter.host++;
      const placeholder = `SANITIZED_HOST_${idx}`;
      replacements.push({ type: 'hostname', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  sanitized = sanitized.replace(
    /(set\s+system\s+(?:radius-server|tacplus-server|name-server|ntp\s+server|syslog\s+host)\s+)(\S+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return match;
      const idx = counter.host++;
      const placeholder = `SANITIZED_HOST_${idx}`;
      replacements.push({ type: 'hostname', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  // ASA: logging host <interface> <hostname>
  sanitized = sanitized.replace(
    /(logging\s+host\s+\S+\s+)(\S+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return match;
      const idx = counter.host++;
      const placeholder = `SANITIZED_HOST_${idx}`;
      replacements.push({ type: 'hostname', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  // ==========================================================================
  // PASS 8: BGP AS numbers
  // ==========================================================================

  sanitized = sanitized.replace(
    /(<(?:local-as|peer-as|autonomous-system|local-as-number|remote-as)>)(\d+)(<\/)/gi,
    (match, open, value, close) => {
      const idx = counter.bgp++;
      const placeholder = `SANITIZED_BGP_AS_${idx}`;
      replacements.push({ type: 'bgp', placeholder, original: value });
      return `${open}${placeholder}${close}`;
    }
  );

  sanitized = sanitized.replace(
    /(autonomous-system\s+)(\d+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      const idx = counter.bgp++;
      const placeholder = `SANITIZED_BGP_AS_${idx}`;
      replacements.push({ type: 'bgp', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  // CLI: router bgp <num>, neighbor X remote-as <num>
  sanitized = sanitized.replace(
    /(router\s+bgp\s+)(\d+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      const idx = counter.bgp++;
      const placeholder = `SANITIZED_BGP_AS_${idx}`;
      replacements.push({ type: 'bgp', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  sanitized = sanitized.replace(
    /(neighbor\s+\S+\s+remote-as\s+)(\d+)/gi,
    (match, prefix, value) => {
      const idx = counter.bgp++;
      const placeholder = `SANITIZED_BGP_AS_${idx}`;
      replacements.push({ type: 'bgp', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  // ==========================================================================
  // PASS 9: Plaintext secrets in set-command format
  // ==========================================================================

  sanitized = sanitized.replace(
    /(set\s+(?:password|passwd|secret|secondary-secret|auth-password|privacy-password)\s+)"([^"]+)"/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      const idx = counter.key++;
      const placeholder = `SANITIZED_KEY_${idx}`;
      replacements.push({ type: 'key', placeholder, original: value });
      return `${prefix}"${placeholder}"`;
    }
  );

  sanitized = sanitized.replace(
    /(set\s+(?:password|passwd|secret|secondary-secret|auth-password|privacy-password)\s+)(\S+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_') || value === '"') return match;
      const idx = counter.key++;
      const placeholder = `SANITIZED_KEY_${idx}`;
      replacements.push({ type: 'key', placeholder, original: value });
      return `${prefix}${placeholder}`;
    }
  );

  sanitized = sanitized.replace(
    /((?:radius-server|tacplus-server|tacacs-server)\s+\S+\s+secret\s+)"([^"]+)"/gi,
    (match, prefix, value) => {
      if (value.startsWith('SANITIZED_')) return match;
      const idx = counter.key++;
      const placeholder = `SANITIZED_KEY_${idx}`;
      replacements.push({ type: 'key', placeholder, original: value });
      return `${prefix}"${placeholder}"`;
    }
  );

  // ==========================================================================
  // PASS 10: Device hostname
  // ==========================================================================

  // ASA: hostname DEVICE_NAME
  sanitized = sanitized.replace(
    /^(\s*hostname\s+)(\S+)/gm,
    (match, prefix, value) => {
      if (value === 'sanitized-fw') return match;
      counter.device_hostname++;
      replacements.push({ type: 'device_hostname', placeholder: 'sanitized-fw', original: value });
      return `${prefix}sanitized-fw`;
    }
  );

  // FortiGate: set hostname "NAME" or set hostname NAME
  sanitized = sanitized.replace(
    /(set\s+hostname\s+)"?([^"\n]+)"?/gi,
    (match, prefix, value) => {
      const trimmed = value.trim().replace(/^"|"$/g, '');
      if (trimmed === 'sanitized-fw') return match;
      counter.device_hostname++;
      replacements.push({ type: 'device_hostname', placeholder: 'sanitized-fw', original: trimmed });
      return `${prefix}"sanitized-fw"`;
    }
  );

  // PAN-OS XML: <hostname>NAME</hostname>
  sanitized = sanitized.replace(
    /(<hostname>)([^<]+)(<\/hostname>)/gi,
    (match, open, value, close) => {
      if (value.trim() === 'sanitized-fw') return match;
      counter.device_hostname++;
      replacements.push({ type: 'device_hostname', placeholder: 'sanitized-fw', original: value.trim() });
      return `${open}sanitized-fw${close}`;
    }
  );

  // SRX: set system host-name NAME  OR  host-name NAME;
  sanitized = sanitized.replace(
    /((?:set\s+system\s+)?host-name\s+)(\S+)/gi,
    (match, prefix, value) => {
      const clean = value.replace(/;$/, '');
      if (clean === 'sanitized-fw') return match;
      counter.device_hostname++;
      replacements.push({ type: 'device_hostname', placeholder: 'sanitized-fw', original: clean });
      return `${prefix}sanitized-fw${value.endsWith(';') ? ';' : ''}`;
    }
  );

  // ==========================================================================
  // PASS 11: Domain names
  // ==========================================================================

  // FortiGate: set fqdn "domain.com"
  sanitized = sanitized.replace(
    /(set\s+fqdn\s+)"([^"]+)"/gi,
    (match, prefix, value) => {
      if (value.startsWith('example-') && value.endsWith('.net')) return match;
      return `${prefix}"${getOrCreateDomain(value)}"`;
    }
  );

  // ASA: fqdn v4 domain.com / fqdn v6 domain.com
  sanitized = sanitized.replace(
    /(fqdn\s+v[46]\s+)(\S+)/gi,
    (match, prefix, value) => {
      if (value.startsWith('example-') && value.endsWith('.net')) return match;
      return `${prefix}${getOrCreateDomain(value)}`;
    }
  );

  // PAN-OS: <fqdn>domain.com</fqdn>
  sanitized = sanitized.replace(
    /(<fqdn>)([^<]+)(<\/fqdn>)/gi,
    (match, open, value, close) => {
      const trimmed = value.trim();
      if (trimmed.startsWith('example-') && trimmed.endsWith('.net')) return match;
      return `${open}${getOrCreateDomain(trimmed)}${close}`;
    }
  );

  // Generic: domain-name <fqdn> / set domain-name <fqdn>
  sanitized = sanitized.replace(
    /((?:set\s+)?domain-name\s+)(\S+)/gi,
    (match, prefix, value) => {
      const clean = value.replace(/;$/, '');
      if (clean.startsWith('example-') && clean.endsWith('.net')) return match;
      return `${prefix}${getOrCreateDomain(clean)}${value.endsWith(';') ? ';' : ''}`;
    }
  );

  // ==========================================================================
  // PASS 12: Email addresses
  // ==========================================================================

  sanitized = sanitized.replace(
    /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g,
    (match) => {
      if (match.endsWith('@example.net')) return match;
      if (emailMap.has(match)) return emailMap.get(match);
      const idx = counter.email++;
      const placeholder = `user-${idx}@example.net`;
      emailMap.set(match, placeholder);
      replacements.push({ type: 'email', placeholder, original: match });
      return placeholder;
    }
  );

  // ==========================================================================
  // PASS 13: URLs
  // ==========================================================================

  sanitized = sanitized.replace(
    /((?:https?|ldaps?|ftp):\/\/)([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})((?::\d+)?(?:\/[^\s"<>]*)?)/gi,
    (match, protocol, domain, pathAndPort) => {
      if (domain.startsWith('example-') && domain.endsWith('.net')) return match;
      const replacementDomain = domainMap.has(domain) ? domainMap.get(domain) : getOrCreateDomain(domain);
      counter.url++;
      replacements.push({ type: 'url', placeholder: `${protocol}${replacementDomain}${pathAndPort}`, original: match });
      return `${protocol}${replacementDomain}${pathAndPort}`;
    }
  );

  // ==========================================================================
  // PASS 14: Public IPv4 → RFC 5737 documentation IPs
  // ==========================================================================

  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

  sanitized = sanitized.replace(ipRegex, (match) => {
    const parts = match.split('.').map(Number);
    if (parts.some(p => p > 255)) return match;
    if (isPrivateOrReserved(match)) return match;
    if (SUBNET_MASKS.has(match)) return match;

    if (ipMap.has(match)) return ipMap.get(match);

    const placeholder = nextDocIp();
    ipMap.set(match, placeholder);
    replacements.push({ type: 'public_ip', placeholder, original: match, restore: true });
    return placeholder;
  });

  // ==========================================================================
  // PASS 15: Private IPv4 → synthetic 10.x.x.x
  // ==========================================================================

  sanitized = sanitized.replace(ipRegex, (match) => {
    const parts = match.split('.').map(Number);
    if (parts.some(p => p > 255)) return match;
    if (!isPrivateRfc1918(match)) return match;
    if (SUBNET_MASKS.has(match)) return match;

    if (privateIpMap.has(match)) return privateIpMap.get(match);

    const placeholder = nextPrivateIp();
    privateIpMap.set(match, placeholder);
    replacements.push({ type: 'private_ip', placeholder, original: match, restore: true });
    return placeholder;
  });

  // ==========================================================================
  // PASS 16: IPv6 addresses → RFC 3849 documentation prefix
  // ==========================================================================

  const ipv6Regex = /(?<![:\w])([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})(?:\/\d{1,3})?(?![:\w])/g;

  sanitized = sanitized.replace(ipv6Regex, (match) => {
    const bare = match.replace(/\/\d+$/, '').toLowerCase();
    if (bare === '::1' || bare === '::') return match;
    if (bare.startsWith('fe80:') || bare.startsWith('fe80::')) return match;
    if (bare.startsWith('2001:db8:') || bare.startsWith('2001:db8::')) return match;
    if (ipv6Map.has(match)) return ipv6Map.get(match);

    const idx = counter.ipv6++;
    const cidr = match.includes('/') ? '/' + match.split('/')[1] : '';
    const placeholder = `2001:db8::${idx + 1}${cidr}`;
    ipv6Map.set(match, placeholder);
    replacements.push({ type: 'ipv6', placeholder, original: match, restore: true });
    return placeholder;
  });

  // ==========================================================================
  // PASS 17: Zone names
  // ==========================================================================

  // ASA: nameif <zone>
  sanitized = sanitized.replace(
    /(nameif\s+)(\S+)/gi,
    (match, prefix, value) => {
      const rep = getOrCreateZone(value);
      return rep ? `${prefix}${rep}` : match;
    }
  );

  // ASA: access-group ... in interface <zone>
  sanitized = sanitized.replace(
    /(access-group\s+\S+\s+in\s+interface\s+)(\S+)/gi,
    (match, prefix, value) => {
      const rep = getOrCreateZone(value);
      return rep ? `${prefix}${rep}` : match;
    }
  );

  // FortiGate: set srcintf "zone", set dstintf "zone", set associated-interface "zone"
  sanitized = sanitized.replace(
    /^(\s*set\s+(?:srcintf|dstintf|associated-interface)\s+)((?:"[^"]+"\s*)+)$/gm,
    (match, prefix, quotedBlock) => {
      const replaced = quotedBlock.replace(/"([^"]+)"/g, (qm, name) => {
        const rep = getOrCreateZone(name);
        return rep ? `"${rep}"` : qm;
      });
      return `${prefix}${replaced}`;
    }
  );

  // FortiGate: config system zone → edit "zone"
  sanitized = sanitized.replace(
    /(config\s+system\s+zone[\s\S]*?edit\s+)"([^"]+)"/gi,
    (match, prefix, value) => {
      const rep = getOrCreateZone(value);
      return rep ? `${prefix}"${rep}"` : match;
    }
  );

  // PAN-OS: <zone><entry name="zone">
  sanitized = sanitized.replace(
    /(<zone>\s*<entry\s+name=")([^"]+)(")/gi,
    (match, prefix, value, suffix) => {
      const rep = getOrCreateZone(value);
      return rep ? `${prefix}${rep}${suffix}` : match;
    }
  );

  // PAN-OS: <to><member>zone</member>, <from><member>zone</member>
  sanitized = sanitized.replace(
    /(<(?:to|from)>\s*<member>)([^<]+)(<\/member>)/gi,
    (match, open, value, close) => {
      const rep = getOrCreateZone(value.trim());
      return rep ? `${open}${rep}${close}` : match;
    }
  );

  // SRX: security-zone <name>, from-zone <name>, to-zone <name>
  sanitized = sanitized.replace(
    /((?:security-zone|from-zone|to-zone)\s+)(\S+)/gi,
    (match, prefix, value) => {
      const clean = value.replace(/[{;]$/, '');
      const rep = getOrCreateZone(clean);
      if (!rep) return match;
      const trail = value.endsWith('{') ? ' {' : value.endsWith(';') ? ';' : '';
      return `${prefix}${rep}${trail}`;
    }
  );

  // ==========================================================================
  // PASS 18: Interface names
  // ==========================================================================

  // FortiGate: set interface "name"
  sanitized = sanitized.replace(
    /(set\s+interface\s+)"([^"]+)"/gi,
    (match, prefix, value) => {
      const rep = getOrCreateInterface(value);
      return rep ? `${prefix}"${rep}"` : match;
    }
  );

  // PAN-OS: <interface><entry name="name">
  sanitized = sanitized.replace(
    /(<interface>\s*<entry\s+name=")([^"]+)(")/gi,
    (match, prefix, value, suffix) => {
      const rep = getOrCreateInterface(value);
      return rep ? `${prefix}${rep}${suffix}` : match;
    }
  );

  // SRX: set interfaces <name> unit ...
  sanitized = sanitized.replace(
    /(set\s+interfaces\s+)(\S+)(\s+unit)/gi,
    (match, prefix, value, suffix) => {
      const rep = getOrCreateInterface(value);
      return rep ? `${prefix}${rep}${suffix}` : match;
    }
  );

  // ==========================================================================
  // PASS 19: Object / group names
  // ==========================================================================

  // ASA: object network <name>, object-group network <name>, object service <name>
  sanitized = sanitized.replace(
    /(object(?:-group)?\s+(?:network|service)\s+)(\S+)/gi,
    (match, prefix, value) => {
      const rep = getOrCreateObject(value);
      return rep ? `${prefix}${rep}` : match;
    }
  );

  // ASA: access-list <name>, access-group <name>
  sanitized = sanitized.replace(
    /(access-(?:list|group)\s+)(\S+)/gi,
    (match, prefix, value) => {
      const rep = getOrCreateObject(value);
      return rep ? `${prefix}${rep}` : match;
    }
  );

  // FortiGate: config firewall address/addrgrp/service/vip → edit "name"
  sanitized = sanitized.replace(
    /(config\s+firewall\s+(?:address|addrgrp|service\s+custom|service\s+group|vip|ippool)[\s\S]*?edit\s+)"([^"]+)"/gi,
    (match, prefix, value) => {
      const rep = getOrCreateObject(value);
      return rep ? `${prefix}"${rep}"` : match;
    }
  );

  // FortiGate: set srcaddr/dstaddr/service "name1" "name2" (multi-value)
  sanitized = sanitized.replace(
    /^(\s*set\s+(?:srcaddr|dstaddr|service|poolname|groups|member)\s+)((?:"[^"]+"\s*)+)$/gm,
    (match, prefix, quotedBlock) => {
      const replaced = quotedBlock.replace(/"([^"]+)"/g, (qm, name) => {
        const rep = getOrCreateObject(name);
        return rep ? `"${rep}"` : qm;
      });
      return `${prefix}${replaced}`;
    }
  );

  // PAN-OS: <address|address-group|service|service-group><entry name="name">
  sanitized = sanitized.replace(
    /(<(?:address|address-group|service|service-group|application-group|tag)>\s*<entry\s+name=")([^"]+)(")/gi,
    (match, prefix, value, suffix) => {
      const rep = getOrCreateObject(value);
      return rep ? `${prefix}${rep}${suffix}` : match;
    }
  );

  // PAN-OS: <source><member>name</member>, <destination><member>name</member>
  sanitized = sanitized.replace(
    /(<(?:source|destination|source-user|tag)>\s*<member>)([^<]+)(<\/member>)/gi,
    (match, open, value, close) => {
      const rep = getOrCreateObject(value.trim());
      return rep ? `${open}${rep}${close}` : match;
    }
  );

  // SRX: address-set <name>, address <name> (address-set first to avoid partial match)
  sanitized = sanitized.replace(
    /(address-set\s+)(\S+)/gi,
    (match, prefix, value) => {
      const clean = value.replace(/[{;]$/, '');
      const rep = getOrCreateObject(clean);
      if (!rep) return match;
      const trail = value.endsWith('{') ? ' {' : value.endsWith(';') ? ';' : '';
      return `${prefix}${rep}${trail}`;
    }
  );

  sanitized = sanitized.replace(
    /((?:^|\s)address\s+)(\S+)/gim,
    (match, prefix, value) => {
      const clean = value.replace(/[{;]$/, '');
      // Skip IP addresses and CIDR notation — this isn't an object name
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(clean)) return match;
      const rep = getOrCreateObject(clean);
      if (!rep) return match;
      const trail = value.endsWith('{') ? ' {' : value.endsWith(';') ? ';' : '';
      return `${prefix}${rep}${trail}`;
    }
  );

  // SRX: application-set / application
  sanitized = sanitized.replace(
    /(application-set\s+)(\S+)/gi,
    (match, prefix, value) => {
      const clean = value.replace(/[{;]$/, '');
      const rep = getOrCreateObject(clean);
      if (!rep) return match;
      const trail = value.endsWith('{') ? ' {' : value.endsWith(';') ? ';' : '';
      return `${prefix}${rep}${trail}`;
    }
  );

  sanitized = sanitized.replace(
    /((?:^|\s)application\s+)(\S+)/gim,
    (match, prefix, value) => {
      const clean = value.replace(/[{;]$/, '');
      const rep = getOrCreateObject(clean);
      if (!rep) return match;
      const trail = value.endsWith('{') ? ' {' : value.endsWith(';') ? ';' : '';
      return `${prefix}${rep}${trail}`;
    }
  );

  // ==========================================================================
  // Return
  // ==========================================================================

  return {
    sanitizedText: sanitized,
    replacements,
    stats: {
      hashes: counter.hash,
      keys: counter.key,
      communities: counter.community,
      usernames: counter.user,
      publicIPs: counter.ip,
      certificates: counter.cert,
      hostnames: counter.host,
      bgpAS: counter.bgp,
      deviceHostnames: counter.device_hostname,
      domains: counter.domain,
      zones: counter.zone,
      objects: counter.object,
      privateIPs: counter.private_ip,
      ipv6s: counter.ipv6,
      emails: counter.email,
      urls: counter.url,
      descriptions: counter.description,
      interfaces: counter.interface,
      total: replacements.length,
    },
  };
}

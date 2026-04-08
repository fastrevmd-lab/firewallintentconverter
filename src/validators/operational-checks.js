/**
 * Operational Checks Module
 * =========================
 * Agent: SRX-Expert
 *
 * Runs operational/design-quality checks against parsed intermediate config
 * and the generated SRX set commands. Checks O1–O9.
 */

import { createWarning } from '../parsers/parser-utils.js';

/** Matches internet-facing zone names. */
const INTERNET_ZONE_PATTERN = /untrust|outside|wan|dmz|internet|external/i;

/**
 * Extract unique "fromZone>toZone" pairs from set security policies commands.
 *
 * @param {string[]} commands
 * @returns {Set<string>}
 */
function extractPolicyZonePairs(commands) {
  const pairs = new Set();
  const re = /set security policies from-zone (\S+) to-zone (\S+)/i;
  for (const cmd of commands) {
    const match = cmd.match(re);
    if (match) pairs.add(`${match[1]}>${match[2]}`);
  }
  return pairs;
}

/**
 * Extract all defined security-zone names from set commands.
 *
 * @param {string[]} commands
 * @returns {Set<string>}
 */
function extractDefinedZones(commands) {
  const zones = new Set();
  const re = /set security zones security-zone (\S+)/i;
  for (const cmd of commands) {
    const match = cmd.match(re);
    if (match) zones.add(match[1]);
  }
  return zones;
}

/**
 * Extract zone pairs referenced in NAT rules from intermediateConfig.
 *
 * @param {Object} intermediateConfig
 * @returns {Set<string>}
 */
function extractNatZonePairs(intermediateConfig) {
  const pairs = new Set();
  const natRules = intermediateConfig.nat_rules ?? [];
  for (const rule of natRules) {
    // Array form (src_zones / dst_zones)
    const srcZones = rule.src_zones ?? (rule.from_zone ? [rule.from_zone] : []);
    const dstZones = rule.dst_zones ?? (rule.to_zone ? [rule.to_zone] : []);
    for (const src of srcZones) {
      for (const dst of dstZones) {
        pairs.add(`${src}>${dst}`);
      }
    }
  }
  return pairs;
}

/**
 * Return true if the last policy for the given zone pair is an explicit deny-all.
 *
 * @param {string[]} commands
 * @param {string} fromZone
 * @param {string} toZone
 * @returns {boolean}
 */
function hasExplicitDenyAll(commands, fromZone, toZone) {
  const prefix = new RegExp(
    `set security policies from-zone ${escapeRegExp(fromZone)} to-zone ${escapeRegExp(toZone)} policy`,
    'i'
  );

  // Collect all policy names for this zone pair in order
  const policyNames = [];
  for (const cmd of commands) {
    const match = cmd.match(
      new RegExp(
        `set security policies from-zone ${escapeRegExp(fromZone)} to-zone ${escapeRegExp(toZone)} policy (\\S+)`,
        'i'
      )
    );
    if (match && !policyNames.includes(match[1])) {
      policyNames.push(match[1]);
    }
  }

  if (policyNames.length === 0) return false;

  const lastPolicy = policyNames[policyNames.length - 1];

  // Check that last policy: matches any src/dst/app AND action is deny
  const denyAnyPattern = new RegExp(
    `set security policies from-zone ${escapeRegExp(fromZone)} to-zone ${escapeRegExp(toZone)} policy ${escapeRegExp(lastPolicy)} then deny`,
    'i'
  );
  const hasDeny = commands.some((cmd) => denyAnyPattern.test(cmd));

  const srcAnyPattern = new RegExp(
    `set security policies from-zone ${escapeRegExp(fromZone)} to-zone ${escapeRegExp(toZone)} policy ${escapeRegExp(lastPolicy)} match source-address any`,
    'i'
  );
  const dstAnyPattern = new RegExp(
    `set security policies from-zone ${escapeRegExp(fromZone)} to-zone ${escapeRegExp(toZone)} policy ${escapeRegExp(lastPolicy)} match destination-address any`,
    'i'
  );
  const appAnyPattern = new RegExp(
    `set security policies from-zone ${escapeRegExp(fromZone)} to-zone ${escapeRegExp(toZone)} policy ${escapeRegExp(lastPolicy)} match application any`,
    'i'
  );

  return (
    hasDeny &&
    commands.some((cmd) => srcAnyPattern.test(cmd)) &&
    commands.some((cmd) => dstAnyPattern.test(cmd)) &&
    commands.some((cmd) => appAnyPattern.test(cmd))
  );
}

/** Escape special regex characters in a string. */
function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

/** O1: Zone pairs with permit policies but no explicit deny-all at end. */
function checkMissingDefaultDeny(commands, policyZonePairs) {
  const warnings = [];
  for (const pair of policyZonePairs) {
    const [fromZone, toZone] = pair.split('>');
    // Only flag if there is at least one permit in this zone pair
    const permitPattern = new RegExp(
      `set security policies from-zone ${escapeRegExp(fromZone)} to-zone ${escapeRegExp(toZone)} policy \\S+ then permit`,
      'i'
    );
    const hasPermit = commands.some((cmd) => permitPattern.test(cmd));
    if (!hasPermit) continue;

    if (!hasExplicitDenyAll(commands, fromZone, toZone)) {
      warnings.push(
        createWarning(
          'warning',
          `zone-pair:${fromZone}>${toZone}`,
          `Zone pair ${fromZone}→${toZone} has permit policies but no explicit deny-all at the end.`,
          `Add a final catch-all deny policy: set security policies from-zone ${fromZone} to-zone ${toZone} policy deny-all match source-address any destination-address any application any then deny`
        )
      );
    }
  }
  return warnings;
}

/** O2: Zone pairs with no policies where at least one zone is internet-facing. */
function checkEmptyZonePairs(commands, definedZones, policyZonePairs) {
  const warnings = [];
  for (const fromZone of definedZones) {
    for (const toZone of definedZones) {
      if (fromZone === toZone) continue;
      const pair = `${fromZone}>${toZone}`;
      if (policyZonePairs.has(pair)) continue;
      // Only flag if at least one zone is internet-facing
      if (!INTERNET_ZONE_PATTERN.test(fromZone) && !INTERNET_ZONE_PATTERN.test(toZone)) continue;
      warnings.push(
        createWarning(
          'info',
          `zone-pair:${pair}`,
          `Zone pair ${fromZone}→${toZone} has no security policies defined (at least one zone is internet-facing).`,
          'Define explicit policies for this zone pair or verify the omission is intentional.'
        )
      );
    }
  }
  return warnings;
}

/** O3: NAT rules referencing zone pairs that have no security policy. */
function checkNatUncoveredZonePairs(natZonePairs, policyZonePairs) {
  const warnings = [];
  for (const pair of natZonePairs) {
    if (!policyZonePairs.has(pair)) {
      const [fromZone, toZone] = pair.split('>');
      warnings.push(
        createWarning(
          'warning',
          `nat-zone-pair:${pair}`,
          `NAT rule references zone pair ${fromZone}→${toZone} but no security policy exists for that pair.`,
          'Add a security policy for this zone pair to allow NATted traffic through.'
        )
      );
    }
  }
  return warnings;
}

/** O4: Internet-facing zones without a screen binding. */
function checkMissingScreens(commands, definedZones) {
  const warnings = [];
  for (const zone of definedZones) {
    if (!INTERNET_ZONE_PATTERN.test(zone)) continue;
    const screenPattern = new RegExp(
      `set security zones security-zone ${escapeRegExp(zone)} screen`,
      'i'
    );
    if (!commands.some((cmd) => screenPattern.test(cmd))) {
      warnings.push(
        createWarning(
          'warning',
          `zone:${zone}`,
          `Internet-facing zone "${zone}" has no screen profile bound.`,
          `Bind a screen profile: set security zones security-zone ${zone} screen <screen-name>`
        )
      );
    }
  }
  return warnings;
}

/** O5: Permit rules without session-close logging. */
function checkPermitWithoutLogging(commands) {
  const warnings = [];
  // Collect all policy identifiers (from-zone/to-zone/policy-name) that have "then permit"
  const permitRe = /set security policies from-zone (\S+) to-zone (\S+) policy (\S+) then permit/i;
  const logRe = /set security policies from-zone (\S+) to-zone (\S+) policy (\S+) then log session-close/i;

  const permitPolicies = new Set();
  const loggedPolicies = new Set();

  for (const cmd of commands) {
    const pm = cmd.match(permitRe);
    if (pm) permitPolicies.add(`${pm[1]}>${pm[2]}>${pm[3]}`);
    const lm = cmd.match(logRe);
    if (lm) loggedPolicies.add(`${lm[1]}>${lm[2]}>${lm[3]}`);
  }

  for (const key of permitPolicies) {
    if (!loggedPolicies.has(key)) {
      const [fromZone, toZone, policyName] = key.split('>');
      warnings.push(
        createWarning(
          'warning',
          `policy:${policyName}`,
          `Policy "${policyName}" (${fromZone}→${toZone}) permits traffic but does not log session-close.`,
          `Add: set security policies from-zone ${fromZone} to-zone ${toZone} policy ${policyName} then log session-close`
        )
      );
    }
  }
  return warnings;
}

/** O6: Duplicate address objects (different names, same type+value). */
function checkDuplicateAddressObjects(intermediateConfig) {
  const warnings = [];
  const addressObjects = intermediateConfig.address_objects ?? [];
  /** @type {Map<string, string>} signature → first seen name */
  const seen = new Map();

  for (const obj of addressObjects) {
    const signature = `${obj.type ?? 'unknown'}:${obj.value ?? obj.prefix ?? obj.ip ?? ''}`;
    if (seen.has(signature)) {
      warnings.push(
        createWarning(
          'info',
          `address-object:${obj.name}`,
          `Address object "${obj.name}" is a duplicate of "${seen.get(signature)}" (same type and value: ${signature}).`,
          `Consider consolidating into a single address object to reduce policy complexity.`
        )
      );
    } else {
      seen.set(signature, obj.name);
    }
  }
  return warnings;
}

/** O7: BGP/OSPF routing protocols configured without an export policy-statement. */
function checkRoutingWithoutExportPolicy(commands) {
  const hasBgp = commands.some((cmd) => /set protocols bgp/i.test(cmd));
  const hasOspf = commands.some((cmd) => /set protocols ospf/i.test(cmd));
  const hasPolicyStatement = commands.some((cmd) => /set policy-options policy-statement/i.test(cmd));

  if (!(hasBgp || hasOspf)) return [];
  if (hasPolicyStatement) return [];

  const proto = [hasBgp && 'BGP', hasOspf && 'OSPF'].filter(Boolean).join('/');
  return [
    createWarning(
      'warning',
      'routing-protocols',
      `${proto} is configured but no policy-options policy-statement is defined.`,
      'Define an export policy to control route advertisements and prevent accidental full-table exports.'
    ),
  ];
}

/** O8: IPsec VPN configured without a matching "then permit tunnel ipsec-vpn" policy. */
function checkVpnWithoutPolicy(commands) {
  const hasVpn = commands.some((cmd) => /set security ipsec vpn/i.test(cmd));
  if (!hasVpn) return [];

  const hasTunnelPolicy = commands.some((cmd) =>
    /set security policies .+ then permit tunnel ipsec-vpn/i.test(cmd)
  );

  if (hasTunnelPolicy) return [];

  return [
    createWarning(
      'warning',
      'ipsec-vpn',
      'IPsec VPN is configured but no security policy with "then permit tunnel ipsec-vpn" was found.',
      'Add a policy that references the VPN tunnel: set security policies from-zone <z> to-zone <z> policy <name> then permit tunnel ipsec-vpn <vpn-name>'
    ),
  ];
}

/** O9: Overlapping NAT rules (same type + zone pair + src/dst addresses). */
function checkOverlappingNatRules(intermediateConfig) {
  const warnings = [];
  const natRules = intermediateConfig.nat_rules ?? [];
  /** @type {Map<string, string[]>} signature → rule names */
  const sigMap = new Map();

  for (const rule of natRules) {
    const srcZones = rule.src_zones ?? (rule.from_zone ? [rule.from_zone] : ['*']);
    const dstZones = rule.dst_zones ?? (rule.to_zone ? [rule.to_zone] : ['*']);
    const srcAddrs = [...(rule.src_addresses ?? [])].sort().join(',') || '*';
    const dstAddrs = [...(rule.dst_addresses ?? [])].sort().join(',') || '*';
    const type = rule.type ?? 'unknown';

    const signature = `${type}:${srcZones.join(',')}>${dstZones.join(',')}:${srcAddrs}:${dstAddrs}`;
    if (!sigMap.has(signature)) {
      sigMap.set(signature, []);
    }
    sigMap.get(signature).push(rule.name ?? '(unnamed)');
  }

  for (const [signature, names] of sigMap) {
    if (names.length < 2) continue;
    warnings.push(
      createWarning(
        'warning',
        `nat-rules:${names.join(',')}`,
        `NAT rules [${names.join(', ')}] have identical match criteria (${signature}).`,
        'Remove or consolidate duplicate NAT rules to avoid unpredictable match order behaviour.'
      )
    );
  }
  return warnings;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Run all operational checks (O1–O9) against the intermediate config and
 * generated SRX set commands.
 *
 * @param {Object} intermediateConfig - Parsed config with zones[], nat_rules[],
 *   address_objects[], security_policies[]
 * @param {string[]} commands - Array of SRX set command strings
 * @returns {Object[]} Array of warning objects
 */
export function runOperationalChecks(intermediateConfig, commands) {
  const cmds = Array.isArray(commands) ? commands : [];
  const cfg = intermediateConfig ?? {};

  const policyZonePairs = extractPolicyZonePairs(cmds);
  const definedZones = extractDefinedZones(cmds);
  const natZonePairs = extractNatZonePairs(cfg);

  return [
    ...checkMissingDefaultDeny(cmds, policyZonePairs),           // O1
    ...checkEmptyZonePairs(cmds, definedZones, policyZonePairs), // O2
    ...checkNatUncoveredZonePairs(natZonePairs, policyZonePairs),// O3
    ...checkMissingScreens(cmds, definedZones),                  // O4
    ...checkPermitWithoutLogging(cmds),                          // O5
    ...checkDuplicateAddressObjects(cfg),                        // O6
    ...checkRoutingWithoutExportPolicy(cmds),                    // O7
    ...checkVpnWithoutPolicy(cmds),                              // O8
    ...checkOverlappingNatRules(cfg),                            // O9
  ];
}

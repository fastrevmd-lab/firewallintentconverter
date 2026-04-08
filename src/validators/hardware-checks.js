import { createWarning } from '../parsers/parser-utils.js';

const PHYSICAL_PREFIXES = ['ge', 'xe', 'et', 'mge'];
const EXCLUDED_PREFIXES = ['lo', 'irb', 'st', 'ae'];

/**
 * Extract unique interface names from SRX set commands.
 * @param {string[]} commands
 * @returns {string[]} unique interface names
 */
function extractInterfaces(commands) {
  const seen = new Set();
  const ifaceRegex = /set interfaces ((?:ge|xe|et|mge|ae|lo|irb|st|reth|fxp)-[\w/.]+)/;
  for (const cmd of commands) {
    const match = cmd.match(ifaceRegex);
    if (match) seen.add(match[1]);
  }
  return [...seen];
}

/**
 * Get speed prefixes (ge, xe, et, mge) present in a model's port list.
 * @param {{ ports: Array<{name: string, type: string, speed: string}> }} model
 * @returns {string[]}
 */
function getModelPortPrefixes(model) {
  const prefixes = new Set();
  for (const port of model.ports ?? []) {
    const prefix = port.name?.split('-')[0];
    if (prefix && PHYSICAL_PREFIXES.includes(prefix)) {
      prefixes.add(prefix);
    }
  }
  return [...prefixes];
}

/**
 * Parse a throughput string like "12 Gbps" or "500 Mbps" to Mbps.
 * @param {string} str
 * @returns {number} throughput in Mbps, or 0 if unparseable
 */
function parseThroughputMbps(str) {
  if (!str) return 0;
  const match = String(str).match(/([\d.]+)\s*(Gbps|Mbps)/i);
  if (!match) return 0;
  const value = parseFloat(match[1]);
  return match[2].toLowerCase() === 'gbps' ? value * 1000 : value;
}

/**
 * Count total physical ports on a model.
 * @param {{ ports: Array<{name: string}> }} model
 * @returns {number}
 */
function countModelPorts(model) {
  return (model.ports ?? []).filter(port => {
    const prefix = port.name?.split('-')[0];
    return prefix && PHYSICAL_PREFIXES.includes(prefix);
  }).length;
}

/**
 * Run hardware compatibility checks against a target SRX model.
 *
 * @param {string[]} commands - Array of SRX set command strings
 * @param {string|null} targetModel - Target model name (e.g. 'SRX345') or null
 * @param {Object} modelDb - SRX_MODELS from hardware-db.js
 * @param {Object} capacityLimits - SRX_CAPACITY_LIMITS from hardware-db.js
 * @param {{ security_policies: any[], zones: any[], nat_rules: any[], address_objects: any[], address_groups: any[] }} intermediateConfig
 * @param {{ throughput?: { l4?: string } }|null} sourceModel - Source model entry with throughput or null
 * @returns {Array<{ severity: string, element: string, message: string, suggestion: string, timestamp: string }>}
 */
export function runHardwareChecks(
  commands,
  targetModel,
  modelDb,
  capacityLimits,
  intermediateConfig,
  sourceModel,
) {
  const warnings = [];

  // H7 — No target model selected
  if (!targetModel) {
    warnings.push(
      createWarning(
        'info',
        'hardware',
        'No target SRX model selected — hardware compatibility checks skipped.',
        'Select a target model to enable interface, capacity, and throughput checks.',
      ),
    );
    return warnings;
  }

  const model = modelDb[targetModel];
  if (!model) {
    warnings.push(
      createWarning(
        'info',
        'hardware',
        `Target model '${targetModel}' not found in model database — hardware checks skipped.`,
        'Verify the model name or update the hardware database.',
      ),
    );
    return warnings;
  }

  const allInterfaces = extractInterfaces(commands);
  const physicalInterfaces = allInterfaces.filter(iface => {
    const prefix = iface.split('-')[0];
    return PHYSICAL_PREFIXES.includes(prefix) && !EXCLUDED_PREFIXES.includes(prefix);
  });

  // H1 — Interface count vs model ports
  const modelPortCount = countModelPorts(model);
  if (modelPortCount > 0 && physicalInterfaces.length > modelPortCount) {
    warnings.push(
      createWarning(
        'unsupported',
        'interfaces',
        `Configuration uses ${physicalInterfaces.length} physical interfaces but ${targetModel} only has ${modelPortCount} ports.`,
        'Reduce the number of interfaces or choose a higher-density model.',
      ),
    );
  }

  // H2 — Interface type mismatch
  const modelPrefixes = getModelPortPrefixes(model);
  const hasOnlyGe = modelPrefixes.length > 0 && modelPrefixes.every(p => p === 'ge');
  if (hasOnlyGe) {
    const highSpeedInterfaces = physicalInterfaces.filter(iface => {
      const prefix = iface.split('-')[0];
      return prefix === 'xe' || prefix === 'et';
    });
    if (highSpeedInterfaces.length > 0) {
      warnings.push(
        createWarning(
          'warning',
          'interfaces',
          `Configuration references ${highSpeedInterfaces.length} xe-/et- interface(s) but ${targetModel} only has ge- slots.`,
          'Review interface assignments; xe-/et- ports are not available on this model.',
        ),
      );
    }
  }

  const limits = capacityLimits[targetModel];

  if (limits) {
    const policyCount = intermediateConfig?.security_policies?.length ?? 0;
    const zoneCount = intermediateConfig?.zones?.length ?? 0;
    const natCount = intermediateConfig?.nat_rules?.length ?? 0;

    // H3 — Policy count threshold
    if (limits.max_policies > 0 && policyCount > 0) {
      const ratio = policyCount / limits.max_policies;
      if (ratio >= 1) {
        warnings.push(
          createWarning(
            'unsupported',
            'security-policies',
            `Policy count (${policyCount}) meets or exceeds the ${targetModel} limit of ${limits.max_policies}.`,
            'Consolidate or reduce policies, or choose a model with a higher policy limit.',
          ),
        );
      } else if (ratio >= 0.8) {
        warnings.push(
          createWarning(
            'warning',
            'security-policies',
            `Policy count (${policyCount}) is at ${Math.round(ratio * 100)}% of the ${targetModel} limit (${limits.max_policies}).`,
            'Consider consolidating policies or choosing a model with more headroom.',
          ),
        );
      }
    }

    // H4 — Zone count threshold
    if (limits.max_zones > 0 && zoneCount > 0) {
      const ratio = zoneCount / limits.max_zones;
      if (ratio >= 1) {
        warnings.push(
          createWarning(
            'unsupported',
            'zones',
            `Zone count (${zoneCount}) meets or exceeds the ${targetModel} limit of ${limits.max_zones}.`,
            'Reduce the number of zones or choose a model with a higher zone limit.',
          ),
        );
      } else if (ratio >= 0.8) {
        warnings.push(
          createWarning(
            'warning',
            'zones',
            `Zone count (${zoneCount}) is at ${Math.round(ratio * 100)}% of the ${targetModel} limit (${limits.max_zones}).`,
            'Consider reducing zones or choosing a model with more headroom.',
          ),
        );
      }
    }

    // H5 — NAT rule count threshold
    if (limits.max_nat_rules > 0 && natCount > 0) {
      const ratio = natCount / limits.max_nat_rules;
      if (ratio >= 1) {
        warnings.push(
          createWarning(
            'unsupported',
            'nat-rules',
            `NAT rule count (${natCount}) meets or exceeds the ${targetModel} limit of ${limits.max_nat_rules}.`,
            'Consolidate NAT rules or choose a model with a higher NAT limit.',
          ),
        );
      } else if (ratio >= 0.8) {
        warnings.push(
          createWarning(
            'warning',
            'nat-rules',
            `NAT rule count (${natCount}) is at ${Math.round(ratio * 100)}% of the ${targetModel} limit (${limits.max_nat_rules}).`,
            'Consider consolidating NAT rules or choosing a model with more headroom.',
          ),
        );
      }
    }
  }

  // H6 — Throughput advisory
  const targetL4Mbps = parseThroughputMbps(model.throughput?.l4);
  const sourceL4Mbps = parseThroughputMbps(sourceModel?.throughput?.l4);
  if (targetL4Mbps > 0 && sourceL4Mbps > 0 && targetL4Mbps < sourceL4Mbps) {
    warnings.push(
      createWarning(
        'info',
        'throughput',
        `${targetModel} L4 throughput (${model.throughput.l4}) is lower than the source device (${sourceModel.throughput.l4}).`,
        'Verify that the target model meets your throughput requirements, or choose a higher-tier model.',
      ),
    );
  }

  return warnings;
}

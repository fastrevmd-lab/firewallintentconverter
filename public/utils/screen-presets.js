/**
 * SRX Screen Best Practice Presets
 *
 * Provides preset definitions, internet-facing zone detection,
 * and screen config generation for SRX security screens.
 */

// Speed tier multipliers relative to 1G base
export const SPEED_TIERS = {
  '1g':   { label: '1G',      multiplier: 1 },
  '10g':  { label: '10G',     multiplier: 10 },
  '25g':  { label: '25G/40G', multiplier: 25 },
  '100g': { label: '100G',    multiplier: 100 },
};

// Base thresholds at 1G speed
export const SCREEN_PRESETS = {
  standard: {
    label: 'Standard',
    description: 'Balanced protection suitable for most deployments',
    base: {
      tcp: {
        syn_flood_alarm_threshold: 1024,
        syn_flood_threshold: 200,
        syn_flood_timeout: 20,
        land_attack: true,
        winnuke: false,
        tcp_no_flag: false,
      },
      udp: { flood_threshold: 5000 },
      icmp: { flood_threshold: 1000, ping_death: true, fragment: false },
      ip: {
        spoofing: false,
        source_route: true,
        tear_drop: true,
        record_route: false,
        timestamp: false,
      },
      limit_session: { source_based: 512, destination_based: 1024 },
    },
  },
  strict: {
    label: 'Strict',
    description: 'Aggressive protection with all screens enabled and lower thresholds',
    base: {
      tcp: {
        syn_flood_alarm_threshold: 512,
        syn_flood_threshold: 100,
        syn_flood_timeout: 20,
        land_attack: true,
        winnuke: true,
        tcp_no_flag: true,
      },
      udp: { flood_threshold: 2500 },
      icmp: { flood_threshold: 500, ping_death: true, fragment: true },
      ip: {
        spoofing: true,
        source_route: true,
        tear_drop: true,
        record_route: true,
        timestamp: true,
      },
      limit_session: { source_based: 256, destination_based: 512 },
    },
  },
};

const INTERNET_ZONE_PATTERNS = [
  /untrust/i, /outside/i, /internet/i, /^wan$/i, /public/i, /guest/i, /dmz/i,
];

/**
 * Detect which zones are internet-facing using heuristics:
 * 1. Zone name matching (untrust, outside, internet, wan, public, guest, dmz)
 * 2. Default route (0.0.0.0/0) next-hop interface → zone lookup
 * 3. If neither matches, return all zones with low confidence
 */
export function detectInternetZones(zones, routes, interfaces) {
  const allZoneNames = (zones || []).map(z => z.name).filter(Boolean);
  const detected = new Set();

  // Heuristic 1: Zone name matching
  for (const zone of (zones || [])) {
    if (INTERNET_ZONE_PATTERNS.some(p => p.test(zone.name))) {
      detected.add(zone.name);
    }
  }

  // Heuristic 2: Default route interface → zone lookup
  const defaultRoutes = (routes || []).filter(r =>
    r.destination === '0.0.0.0/0' || r.destination === '::/0'
  );
  for (const route of defaultRoutes) {
    const iface = route.interface || route.next_hop_interface;
    if (iface) {
      // Check zones[].interfaces array
      const matchedZone = (zones || []).find(z =>
        (z.interfaces || []).some(i => i === iface || i.name === iface)
      );
      if (matchedZone) detected.add(matchedZone.name);

      // Also check interfaces[] for zone mapping
      const matchedIf = (interfaces || []).find(i => i.name === iface);
      if (matchedIf?.zone) detected.add(matchedIf.zone);
    }
  }

  if (detected.size > 0) {
    return { detected: [...detected], confidence: 'high', allZones: allZoneNames };
  }

  return { detected: [], confidence: 'low', allZones: allZoneNames };
}

// Maps hardware DB speed strings like "1/10/25G" to our speed tier keys
const SPEED_TO_TIERS = {
  '1': '1g', '2.5': '1g', '5': '10g', '10': '10g',
  '25': '25g', '40': '25g', '50': '25g', '100': '100g', '400': '100g',
};

/**
 * Parse a hardware DB speed string (e.g., "1/10/25G") into valid speed tier keys.
 * Returns a Set of tier keys like {'1g', '10g', '25g'}.
 */
function parsePortSpeedTiers(speedStr) {
  if (!speedStr || speedStr === 'virtual') return new Set(Object.keys(SPEED_TIERS));
  const tiers = new Set();
  const parts = speedStr.replace(/G$/i, '').split('/');
  for (const p of parts) {
    const tier = SPEED_TO_TIERS[p];
    if (tier) tiers.add(tier);
  }
  return tiers.size > 0 ? tiers : new Set(['1g']);
}

/**
 * Resolve valid speed tiers for zones based on interface mappings and hardware port data.
 *
 * @param {string[]} zoneNames - Selected zone names
 * @param {Array} zones - intermediateConfig.zones[]
 * @param {Object} interfaceMappings - { "ethernet1/1": "ge-0/0/0", ... }
 * @param {Array} targetPorts - SRX_MODELS[targetModel].ports[] with {name, speed}
 * @returns {{ validTiers: string[], maxTier: string, portDetails: string }}
 */
export function resolveZoneSpeedTiers(zoneNames, zones, interfaceMappings, targetPorts) {
  if (!targetPorts?.length || !interfaceMappings) {
    return { validTiers: Object.keys(SPEED_TIERS), maxTier: '1g', portDetails: '' };
  }

  const allTiers = new Set();
  const portInfos = [];

  for (const zoneName of zoneNames) {
    const zone = (zones || []).find(z => z.name === zoneName);
    if (!zone) continue;

    for (const srcIface of (zone.interfaces || [])) {
      const ifName = typeof srcIface === 'string' ? srcIface : srcIface?.name || '';
      // Resolve source interface → SRX interface via mappings
      const srxIface = interfaceMappings[ifName] || interfaceMappings[ifName.split('.')[0]];
      if (!srxIface) continue;

      // Strip .unit to get base port name
      const baseName = srxIface.split('.')[0];
      const port = targetPorts.find(p => p.name === baseName);
      if (port) {
        const tiers = parsePortSpeedTiers(port.speed);
        for (const t of tiers) allTiers.add(t);
        portInfos.push(`${baseName} (${port.speed})`);
      }
    }
  }

  if (allTiers.size === 0) {
    return { validTiers: Object.keys(SPEED_TIERS), maxTier: '1g', portDetails: '' };
  }

  // Sort tiers by rank
  const tierOrder = ['1g', '10g', '25g', '100g'];
  const validTiers = tierOrder.filter(t => allTiers.has(t));
  const maxTier = validTiers[validTiers.length - 1] || '1g';

  return {
    validTiers,
    maxTier,
    portDetails: [...new Set(portInfos)].join(', '),
  };
}

/**
 * Infer speed tier from SRX interface naming convention (fallback when no hardware DB).
 * ge-* = 1G, xe-* = 10G, et-* = 25G+
 */
export function inferSpeedFromInterfaces(zoneInterfaces, interfaces) {
  let maxSpeed = '1g';
  const speedRank = { '1g': 1, '10g': 2, '25g': 3, '100g': 4 };

  for (const item of (zoneInterfaces || [])) {
    const ifName = typeof item === 'string' ? item : item?.name || '';
    let speed = '1g';
    if (ifName.startsWith('et-')) speed = '25g';
    else if (ifName.startsWith('xe-')) speed = '10g';
    else if (ifName.startsWith('ge-')) speed = '1g';

    const ifObj = (interfaces || []).find(i => i.name === ifName);
    if (ifObj?.speed) {
      const s = ifObj.speed.toLowerCase();
      if (s.includes('100')) speed = '100g';
      else if (s.includes('40') || s.includes('25')) speed = '25g';
      else if (s.includes('10')) speed = '10g';
    }

    if (speedRank[speed] > speedRank[maxSpeed]) maxSpeed = speed;
  }
  return maxSpeed;
}

/**
 * Generate screen_config array from preset, speed tier, and zone names.
 */
export function generateScreenConfig(presetKey, speedTier, zoneNames) {
  const preset = SCREEN_PRESETS[presetKey];
  if (!preset) return [];

  const multiplier = SPEED_TIERS[speedTier]?.multiplier || 1;
  const base = preset.base;

  return zoneNames.map(zoneName => ({
    name: `${zoneName}-screen`,
    zone: zoneName,
    icmp: {
      flood_threshold: Math.round(base.icmp.flood_threshold * multiplier),
      ping_death: base.icmp.ping_death,
      fragment: base.icmp.fragment,
    },
    tcp: {
      syn_flood_alarm_threshold: Math.round(base.tcp.syn_flood_alarm_threshold * multiplier),
      syn_flood_threshold: Math.round(base.tcp.syn_flood_threshold * multiplier),
      syn_flood_timeout: base.tcp.syn_flood_timeout,
      land_attack: base.tcp.land_attack,
      winnuke: base.tcp.winnuke,
      tcp_no_flag: base.tcp.tcp_no_flag,
    },
    udp: {
      flood_threshold: Math.round(base.udp.flood_threshold * multiplier),
    },
    ip: { ...base.ip },
    limit_session: {
      source_based: Math.round(base.limit_session.source_based * multiplier),
      destination_based: Math.round(base.limit_session.destination_based * multiplier),
    },
    description: `${preset.label} best-practice screen (${SPEED_TIERS[speedTier]?.label || speedTier})`,
  }));
}

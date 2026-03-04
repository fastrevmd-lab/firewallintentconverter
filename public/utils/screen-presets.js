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

/**
 * Infer speed tier from SRX interface naming convention:
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

    // Check interfaces[] for explicit speed field
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

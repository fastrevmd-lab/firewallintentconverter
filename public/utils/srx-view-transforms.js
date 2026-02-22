/**
 * SRX View Transform Layer
 *
 * Converts intermediateConfig (PAN-OS terms) ↔ SRX display terms.
 * No separate state — just transformation functions.
 * Also provides SRX license tier definitions and coverage checks.
 */

// ---------------------------------------------------------------------------
// SRX License Tiers
// ---------------------------------------------------------------------------

export const SRX_LICENSE_TIERS = {
  Base: {
    name: 'Base (No License)',
    short: 'Base',
    description: 'Stateful firewall only — no subscriptions',
    features: ['stateful-firewall'],
  },
  A1: {
    name: 'A1 (AppSecure 1)',
    short: 'A1',
    description: 'Base + AppID, basic IPS, stateful firewall',
    features: ['appid', 'basic-ips', 'stateful-firewall'],
  },
  A2: {
    name: 'A2 (AppSecure 2)',
    short: 'A2',
    description: 'A1 + advanced IPS, AppQoS',
    features: ['appid', 'basic-ips', 'advanced-ips', 'stateful-firewall', 'appqos'],
  },
  P1: {
    name: 'P1 (Premium 1)',
    short: 'P1',
    description: 'A2 + UTM (AV, anti-spam, web filtering), SecIntel',
    features: ['appid', 'basic-ips', 'advanced-ips', 'stateful-firewall', 'appqos',
               'utm-av', 'utm-antispam', 'utm-webfiltering', 'secintel'],
  },
  P2: {
    name: 'P2 (Premium 2)',
    short: 'P2',
    description: 'P1 + ATP Cloud, encrypted traffic analysis',
    features: ['appid', 'basic-ips', 'advanced-ips', 'stateful-firewall', 'appqos',
               'utm-av', 'utm-antispam', 'utm-webfiltering', 'secintel',
               'atp-cloud', 'encrypted-traffic-analysis'],
  },
};

// ---------------------------------------------------------------------------
// Action Mapping
// ---------------------------------------------------------------------------

const PANOS_TO_SRX_ACTION = {
  'allow': 'permit',
  'deny': 'deny',
  'drop': 'deny',
  'reset-client': 'reject',
  'reset-server': 'reject',
  'reset-both': 'reject',
};

const SRX_TO_PANOS_ACTION = {
  'permit': 'allow',
  'deny': 'deny',
  'reject': 'reset-both',
};

export function mapActionToSrx(panosAction) {
  return PANOS_TO_SRX_ACTION[panosAction] || panosAction;
}

export function mapActionToPanos(srxAction) {
  return SRX_TO_PANOS_ACTION[srxAction] || srxAction;
}

// ---------------------------------------------------------------------------
// Interface Name Mapping (client-side mirror of server-side logic)
// ---------------------------------------------------------------------------

export function mapInterfaceToSrx(panosIface, interfaceMappings = {}) {
  // Check explicit user mappings first
  if (interfaceMappings[panosIface]) {
    const srx = interfaceMappings[panosIface];
    return srx.includes('.') ? srx : `${srx}.0`;
  }

  // Check base interface (without unit)
  const base = panosIface.split('.')[0];
  const unit = panosIface.includes('.') ? panosIface.split('.')[1] : null;
  if (interfaceMappings[base]) {
    const srx = interfaceMappings[base];
    const srxBase = srx.split('.')[0];
    return `${srxBase}.${unit || '0'}`;
  }

  // Auto-map ethernet{slot}/{port} → ge-0/{slot-1}/{port-1}.0
  const match = panosIface.match(/^ethernet(\d+)\/(\d+)(\.(\d+))?$/i);
  if (match) {
    const slot = parseInt(match[1]) - 1;
    const port = parseInt(match[2]) - 1;
    const u = match[4] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }

  return panosIface;
}

// ---------------------------------------------------------------------------
// Application Services (from security profiles)
// ---------------------------------------------------------------------------

export function buildApplicationServices(rule) {
  const services = [];
  const profiles = rule.security_profiles || {};

  const hasUtm = profiles['virus'] || profiles['wildfire-analysis'] ||
                 profiles['url-filtering'] || profiles['file-blocking'];
  const hasIdp = profiles['spyware'] || profiles['vulnerability'];

  if (hasUtm) services.push('utm-policy');
  if (hasIdp) services.push('idp-policy');

  // SecIntel from EDL references
  if (rule._secIntelAddresses && rule._secIntelAddresses.length > 0) {
    services.push('secIntel');
  }

  return services;
}

// ---------------------------------------------------------------------------
// Log Display
// ---------------------------------------------------------------------------

export function buildSrxLogDisplay(rule) {
  const parts = [];
  if (rule.log_end) parts.push('session-close');
  if (rule.log_start) parts.push('session-init');
  return parts;
}

// ---------------------------------------------------------------------------
// NAT Type Labels
// ---------------------------------------------------------------------------

const NAT_TYPE_SRX = {
  'source': 'source-nat rule-set',
  'destination': 'destination-nat rule-set',
  'static': 'static-nat rule-set',
};

export function mapNatTypeToSrx(panosType) {
  return NAT_TYPE_SRX[panosType] || panosType;
}

// ---------------------------------------------------------------------------
// License Tier Checks
// ---------------------------------------------------------------------------

const TIER_ORDER = { 'A1': 1, 'A2': 2, 'P1': 3, 'P2': 4 };

/**
 * Returns true if `haveTier` covers `needTier`.
 */
export function licenseTierCovers(haveTier, needTier) {
  return (TIER_ORDER[haveTier] || 0) >= (TIER_ORDER[needTier] || 0);
}

/**
 * Given a rule's security profiles, determine the minimum license needed.
 */
export function getMinimumLicenseForRule(rule) {
  const profiles = rule.security_profiles || {};
  const keys = Object.keys(profiles);
  if (keys.length === 0 && !rule.profile_group) return 'A1';

  // Check for P2-level features
  if (profiles['wildfire-analysis']) return 'P2';

  // Check for P1-level features (UTM)
  if (profiles['virus'] || profiles['url-filtering'] || profiles['file-blocking']) return 'P1';

  // Check for A2-level features (advanced IDP)
  if (profiles['spyware'] || profiles['vulnerability']) return 'A2';

  // Profile group assumed to need at least P1 (could contain UTM)
  if (rule.profile_group) return 'P1';

  return 'A1';
}

/**
 * Get the features that exceed the given license tier for a rule.
 */
export function getLicenseGaps(rule, haveTier) {
  const gaps = [];
  const profiles = rule.security_profiles || {};

  if (!haveTier) return gaps;

  const checks = [
    { key: 'wildfire-analysis', need: 'P2', label: 'WildFire / ATP Cloud' },
    { key: 'virus',            need: 'P1', label: 'Antivirus (UTM)' },
    { key: 'url-filtering',    need: 'P1', label: 'URL Filtering (UTM)' },
    { key: 'file-blocking',    need: 'P1', label: 'File Blocking (UTM)' },
    { key: 'spyware',          need: 'A2', label: 'Anti-Spyware (IDP)' },
    { key: 'vulnerability',    need: 'A2', label: 'Vulnerability Protection (IDP)' },
  ];

  for (const c of checks) {
    if (profiles[c.key] && !licenseTierCovers(haveTier, c.need)) {
      gaps.push({ feature: c.label, required: c.need });
    }
  }

  return gaps;
}

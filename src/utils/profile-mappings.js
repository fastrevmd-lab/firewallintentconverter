/**
 * Deterministic security profile → SRX mapping table.
 * Maps vendor-specific security profile types to SRX UTM/IDP equivalents.
 */

const PROFILE_MAPPINGS = {
  // PAN-OS profiles
  'antivirus':                { srxType: 'utm', srxAction: 'anti-virus', default: 'junos-av-defaults', tier: 'A1' },
  'anti-spyware':             { srxType: 'idp', srxAction: 'idp-policy', default: 'recommended', tier: 'A1' },
  'vulnerability-protection': { srxType: 'idp', srxAction: 'idp-policy', default: 'recommended', tier: 'A1' },
  'vulnerability':            { srxType: 'idp', srxAction: 'idp-policy', default: 'recommended', tier: 'A1' },
  'url-filtering':            { srxType: 'utm', srxAction: 'web-filtering', default: 'custom-wf-local-default', tier: 'A2' },
  'file-blocking':            { srxType: 'utm', srxAction: 'content-filtering', default: 'junos-cf-default', tier: 'A2', note: 'SRX uses MIME/extension-based only, no true file-type detection' },
  'wildfire-analysis':        { srxType: 'utm', srxAction: 'anti-virus', default: 'junos-av-defaults', tier: 'P1', note: 'No direct SRX equivalent. ATP Cloud (P1/P2) for cloud sandboxing — async, not inline hold' },
  'data-filtering':           { srxType: 'none', tier: 'A2', note: 'No direct SRX equivalent. Requires ICAP + third-party DLP server' },
  'spyware':                  { srxType: 'idp', srxAction: 'idp-policy', default: 'recommended', tier: 'A1' },

  // FortiGate profiles
  'av':                   { srxType: 'utm', srxAction: 'anti-virus', default: 'junos-av-defaults', tier: 'A1' },
  'webfilter':            { srxType: 'utm', srxAction: 'web-filtering', default: 'custom-wf-local-default', tier: 'A2' },
  'ips':                  { srxType: 'idp', srxAction: 'idp-policy', default: 'recommended', tier: 'A1' },
  'ips-sensor':           { srxType: 'idp', srxAction: 'idp-policy', default: 'recommended', tier: 'A1' },
  'application-control':  { srxType: 'appfw', srxAction: 'application-firewall', default: 'appfw-default', tier: 'A1', note: 'SRX uses AppFW/AppID, different model than FortiGate application control' },
  'application-list':     { srxType: 'appfw', srxAction: 'application-firewall', default: 'appfw-default', tier: 'A1' },
  'email-filter':         { srxType: 'utm', srxAction: 'anti-spam', default: 'junos-as-defaults', tier: 'A2' },
  'emailfilter':          { srxType: 'utm', srxAction: 'anti-spam', default: 'junos-as-defaults', tier: 'A2' },
  'dlp':                  { srxType: 'none', tier: 'A2', note: 'No direct SRX equivalent. Requires ICAP + third-party DLP' },
  'dlp-sensor':           { srxType: 'none', tier: 'A2', note: 'No direct SRX equivalent. Requires ICAP + third-party DLP' },
  'dns-filter':           { srxType: 'utm', srxAction: 'dns-security', default: 'dns-security-default', tier: 'P1', note: 'Requires ATP Cloud subscription' },
  'dnsfilter':            { srxType: 'utm', srxAction: 'dns-security', default: 'dns-security-default', tier: 'P1' },
  'webfilter-profile':    { srxType: 'utm', srxAction: 'web-filtering', default: 'custom-wf-local-default', tier: 'A2' },

  // Cisco ASA / generic
  'inspect':    { srxType: 'idp', srxAction: 'idp-policy', default: 'recommended', tier: 'A1', note: 'ASA inspect maps loosely to SRX IDP' },

  // Generic profile types
  'idp':        { srxType: 'idp', srxAction: 'idp-policy', default: 'recommended', tier: 'A1' },
  'utm':        { srxType: 'utm', srxAction: 'utm-policy', default: 'utm-default', tier: 'A1' },
};

/**
 * Maps a vendor security profile to SRX equivalent deterministically.
 * @param {string} profileType - Vendor profile type name
 * @param {string} profileName - Vendor profile name (for naming)
 * @returns {{ srxType: string, srxAction: string, srxProfileName: string, tier: string, note?: string }}
 */
export function mapProfileDeterministic(profileType, profileName) {
  const normalized = (profileType || '').toLowerCase().replace(/[_\s]+/g, '-');
  const mapping = PROFILE_MAPPINGS[normalized];
  if (!mapping) {
    return {
      srxType: 'unknown',
      srxAction: profileType,
      srxProfileName: profileName || profileType,
      tier: 'unknown',
      note: `No deterministic mapping for "${profileType}". Manual configuration required.`,
    };
  }
  return {
    srxType: mapping.srxType,
    srxAction: mapping.srxAction,
    srxProfileName: mapping.default,
    tier: mapping.tier,
    note: mapping.note || null,
  };
}

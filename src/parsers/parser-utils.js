/**
 * Shared parsing utilities used across all vendor parsers.
 *
 * These helpers normalize data from XML parsing libraries (which may return
 * strings instead of arrays for single-element lists) and provide common
 * validation / transformation functions.
 */

/**
 * Ensures the value is always an array.
 * XML parsers often return a single string instead of an array when there is
 * only one <member> element.  This normalizes that behavior.
 *
 * @param {*} value - The value to normalize
 * @returns {Array} - Always returns an array
 */
export function ensureArray(value) {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value;
  return [value];
}

/**
 * Extracts <member> elements from a PAN-OS XML node.
 * Handles both single-member and multi-member cases.
 *
 * @param {Object} node - Parsed XML node that may contain a `member` property
 * @returns {string[]} - Array of member strings
 */
export function extractMembers(node) {
  if (!node) return [];
  if (node.member !== undefined) {
    return ensureArray(node.member).map(String);
  }
  return [];
}

/**
 * Extracts <entry> elements from a PAN-OS XML container node.
 * PAN-OS uses <entry name="..."> extensively throughout its config.
 *
 * @param {Object} node - Parsed XML node that may contain `entry` elements
 * @returns {Array<Object>} - Array of entry objects, each with at least a `name` attribute
 */
export function extractEntries(node) {
  if (!node) return [];
  if (node.entry !== undefined) {
    return ensureArray(node.entry);
  }
  return [];
}

/**
 * Safely retrieves a nested property from an object using a dot-separated path.
 *
 * @param {Object} obj - Source object
 * @param {string} path - Dot-separated path (e.g. "devices.entry.vsys")
 * @param {*} defaultValue - Value to return if path doesn't resolve
 * @returns {*} - The resolved value or defaultValue
 */
export function getNestedValue(obj, path, defaultValue = undefined) {
  const keys = path.split('.');
  let current = obj;
  for (const key of keys) {
    if (current === undefined || current === null) return defaultValue;
    current = current[key];
  }
  return current !== undefined ? current : defaultValue;
}

/**
 * Generates a conversion warning object.
 *
 * @param {'clean'|'warning'|'unsupported'|'interview_required'} severity
 * @param {string} element - The config element this warning pertains to
 * @param {string} message - Human-readable description of the issue
 * @param {string} [suggestion] - Suggested resolution or manual step
 * @returns {Object} - Warning object
 */
export function createWarning(severity, element, message, suggestion = '') {
  return {
    severity,
    element,
    message,
    suggestion,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Sanitizes a name for use in Junos configuration.
 * SRX names must be alphanumeric plus hyphens, underscores, and periods.
 * Max length is 63 characters.
 *
 * @param {string} name - Original name from the source config
 * @returns {string} - Sanitized name safe for Junos
 */
export function sanitizeJunosName(name) {
  if (!name) return 'unnamed';
  // Replace spaces and invalid characters with hyphens
  let sanitized = name.replace(/[^a-zA-Z0-9._-]/g, '-');
  // Collapse consecutive hyphens
  sanitized = sanitized.replace(/-{2,}/g, '-');
  // Remove leading/trailing hyphens
  sanitized = sanitized.replace(/^-+|-+$/g, '');
  // Truncate to 63 characters (Junos limit)
  sanitized = sanitized.substring(0, 63);
  return sanitized || 'unnamed';
}

/**
 * Maps well-known PAN-OS application names to Junos built-in application names.
 * Returns null if no mapping exists (indicating a custom application or
 * one that requires interview clarification).
 *
 * @param {string} panosApp - PAN-OS application name
 * @returns {string|null} - Junos application name or null
 */
export function mapPanosAppToJunos(panosApp) {
  const appMap = {
    // Web
    'web-browsing': 'junos-http',
    'ssl': 'junos-https',
    // DNS
    'dns': 'junos-dns-udp',
    // Mail
    'smtp': 'junos-smtp',
    'pop3': 'junos-pop3',
    'imap': 'junos-imap',
    // File transfer
    'ftp': 'junos-ftp',
    'tftp': 'junos-tftp',
    // Remote access
    'ssh': 'junos-ssh',
    'telnet': 'junos-telnet',
    'rdp': 'junos-rdp',
    // Network services
    'ping': 'junos-ping',
    'ntp': 'junos-ntp',
    'snmp': 'junos-snmp',
    'syslog': 'junos-syslog',
    'dhcp': 'junos-dhcp-client',
    // VPN
    'ike': 'junos-ike',
    'ipsec': 'junos-ipsec',
    // Database
    'ms-sql-db': 'junos-ms-sql',
    'mysql': 'junos-mysql',
    // LDAP / Directory
    'ldap': 'junos-ldap',
    'active-directory': 'junos-ldap',
    // ICMP
    'icmp': 'junos-icmp-all',
    // HTTP/2
    'http2': 'junos-http',
  };

  const normalized = panosApp.toLowerCase().trim();
  return appMap[normalized] || null;
}

/**
 * Maps a PAN-OS security profile type to the corresponding SRX feature and profile name.
 *
 * PAN-OS profiles map to SRX as follows:
 *   virus, wildfire-analysis → UTM anti-virus
 *   url-filtering            → UTM web-filtering
 *   file-blocking            → UTM content-filtering
 *   spyware, vulnerability   → IDP
 *
 * @param {string} profileType - PAN-OS profile type (e.g. 'virus', 'spyware')
 * @param {string} profileName - PAN-OS profile name (e.g. 'default', 'strict')
 * @returns {{ srxFeature: string, srxType: string, srxProfile: string }}
 */
export function mapPanosProfileToSrx(profileType, profileName) {
  const safeName = sanitizeJunosName(profileName);
  const mapping = {
    'virus':              { srxFeature: 'utm', srxType: 'anti-virus',        srxProfile: `junos-av-${safeName}` },
    'wildfire-analysis':  { srxFeature: 'utm', srxType: 'anti-virus',        srxProfile: `junos-av-${safeName}` },
    'url-filtering':      { srxFeature: 'utm', srxType: 'web-filtering',     srxProfile: `junos-wf-${safeName}` },
    'file-blocking':      { srxFeature: 'utm', srxType: 'content-filtering', srxProfile: `junos-cf-${safeName}` },
    'spyware':            { srxFeature: 'idp', srxType: 'idp-policy',        srxProfile: `idp-${safeName}` },
    'vulnerability':      { srxFeature: 'idp', srxType: 'idp-policy',        srxProfile: `idp-${safeName}` },
  };
  return mapping[profileType] || { srxFeature: 'unknown', srxType: profileType, srxProfile: safeName };
}

/**
 * Detects the source vendor/format from raw config text.
 * Currently supports PAN-OS XML detection; will be extended for
 * FortiGate, Cisco ASA, and Check Point in later phases.
 *
 * @param {string} configText - Raw configuration text
 * @returns {{ vendor: string, format: string, confidence: number }}
 */
export function detectVendor(configText) {
  const trimmed = configText.trim();

  // PAN-OS: XML with <config> root element and typical PAN-OS markers
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<config')) {
    if (trimmed.includes('<vsys>') || trimmed.includes('<devices>') || trimmed.includes('<panorama>')) {
      return { vendor: 'panos', format: 'xml', confidence: 0.95 };
    }
    // Generic XML with PAN-OS-like content
    if (trimmed.includes('paloaltonetworks') || trimmed.includes('pan-os')) {
      return { vendor: 'panos', format: 'xml', confidence: 0.85 };
    }
  }

  // Placeholder: FortiGate detection (future)
  if (trimmed.includes('config system global') || trimmed.includes('config firewall policy')) {
    return { vendor: 'fortigate', format: 'text', confidence: 0.8 };
  }

  // Placeholder: Cisco ASA detection (future)
  if (trimmed.includes('access-list') && trimmed.includes('access-group')) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.7 };
  }

  // Junos SRX: set commands format
  if (trimmed.includes('set security policies') || trimmed.includes('set security zones')) {
    return { vendor: 'srx', format: 'set', confidence: 0.95 };
  }
  if (trimmed.includes('set security') && (trimmed.includes('from-zone') || trimmed.includes('address-book'))) {
    return { vendor: 'srx', format: 'set', confidence: 0.9 };
  }

  // Junos SRX: hierarchical format
  if (trimmed.includes('security {') && (trimmed.includes('policies {') || trimmed.includes('zones {'))) {
    return { vendor: 'srx', format: 'hierarchical', confidence: 0.9 };
  }
  if (trimmed.includes('security-zone') && trimmed.includes('interfaces {')) {
    return { vendor: 'srx', format: 'hierarchical', confidence: 0.85 };
  }

  // Junos generic (could be SRX or other Junos device)
  if (/^set\s+(system|interfaces|routing-options|protocols|security)\s/m.test(trimmed)) {
    return { vendor: 'srx', format: 'set', confidence: 0.7 };
  }

  // Default: assume PAN-OS XML if it looks like XML
  if (trimmed.startsWith('<')) {
    return { vendor: 'panos', format: 'xml', confidence: 0.5 };
  }

  return { vendor: 'unknown', format: 'unknown', confidence: 0 };
}

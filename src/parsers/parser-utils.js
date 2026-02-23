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
 * Predefined Junos policy application names from official Juniper documentation.
 * Source: https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-predefined-applications.html
 */
export const JUNOS_PREDEFINED_APPS = new Set([
  // Internet
  'junos-aol', 'junos-dhcp-relay', 'junos-dhcp-client', 'junos-dhcp-server',
  'junos-dns-udp', 'junos-dns-tcp', 'junos-ftp', 'junos-ftp-data',
  'junos-gopher', 'junos-http', 'junos-http-ext', 'junos-https',
  'junos-internet-locator-service', 'junos-irc', 'junos-ldap',
  'junos-pc-anywhere', 'junos-tftp', 'junos-wais',
  // Microsoft
  'junos-ms-rpc-epm', 'junos-ms-rpc', 'junos-ms-rpc-msexchange',
  'junos-ms-rpc-msexchange-database', 'junos-ms-rpc-msexchange-directory',
  'junos-ms-rpc-msexchange-info-store', 'junos-ms-rpc-tcp', 'junos-ms-rpc-udp',
  'junos-ms-sql', 'junos-msn',
  // Dynamic Routing
  'junos-rip', 'junos-ospf', 'junos-bgp',
  // Streaming Video
  'junos-h323', 'junos-netmeeting', 'junos-realaudio', 'junos-rtsp',
  'junos-sip', 'junos-vdo-live',
  // Sun RPC
  'junos-sun-rpc-portmapper', 'junos-sun-rpc-any',
  'junos-sun-rpc-program-mountd', 'junos-sun-rpc-program-nfs',
  'junos-sun-rpc-program-nlockmgr', 'junos-sun-rpc-program-rquotad',
  'junos-sun-rpc-program-rstatd', 'junos-sun-rpc-program-ruserd',
  'junos-sun-rpc-program-sadmind', 'junos-sun-rpc-program-sprayd',
  'junos-sun-rpc-program-status', 'junos-sun-rpc-program-walld',
  'junos-sun-rpc-program-ypbind',
  // Security & Tunnel
  'junos-ike', 'junos-ike-nat', 'junos-l2tp', 'junos-pptp',
  // IP catch-all
  'junos-tcp-any', 'junos-udp-any',
  // IM / P2P
  'junos-gnutella', 'junos-nntp', 'junos-smb', 'junos-ymsg',
  // Management
  'junos-nbname', 'junos-nbds', 'junos-nfs', 'junos-ns-global',
  'junos-ns-global-pro', 'junos-nsm', 'junos-ntp', 'junos-rlogin',
  'junos-rsh', 'junos-snmp', 'junos-sqlnet-v1', 'junos-sqlnet-v2',
  'junos-ssh', 'junos-syslog', 'junos-talk', 'junos-telnet',
  'junos-winframe', 'junos-x-windows',
  // Mail
  'junos-imap', 'junos-imaps', 'junos-smtp', 'junos-smtps',
  'junos-pop3', 'junos-pop3s',
  // UNIX
  'junos-finger', 'junos-uucp',
  // Misc
  'junos-chargen', 'junos-discard', 'junos-ident', 'junos-lpr',
  'junos-radius', 'junos-radius-accounting', 'junos-sqlmon',
  'junos-vnc', 'junos-whois', 'junos-sccp',
  // ICMP
  'junos-icmp-any', 'junos-icmp-all', 'junos-icmp-address-mask',
  'junos-icmp-dest-unreach', 'junos-icmp-fragment-needed',
  'junos-icmp-fragment-reassembly', 'junos-icmp-host-unreach',
  'junos-icmp-info', 'junos-icmp-parameter-problem',
  'junos-icmp-port-unreach', 'junos-icmp-protocol-unreach',
  'junos-icmp-redirect', 'junos-icmp-redirect-host',
  'junos-icmp-redirect-tos-host', 'junos-icmp-redirect-tos-net',
  'junos-icmp-source-quench', 'junos-icmp-source-route-fail',
  'junos-icmp-time-exceeded', 'junos-icmp-timestamp',
  'junos-ping', 'junos-traceroute',
  // Additional common (widely available on modern Junos)
  'junos-rdp', 'junos-mysql', 'junos-ipsec',
  'junos-smb-session', 'junos-netbios-session', 'junos-twamp',
  'junos-stun', 'junos-quic',
]);

/**
 * Multi-vendor application name → Junos predefined application mapping.
 * Covers PAN-OS, FortiGate service names (uppercase), and Cisco ASA names.
 * Returns null if no mapping exists.
 *
 * @param {string} appName - Application or service name from any vendor
 * @returns {string|null} - Junos application name or null
 */
const APP_MAP = {
  // ── PAN-OS Application Names ──────────────────────────────
  // Web
  'web-browsing': 'junos-http',
  'ssl': 'junos-https',
  'http2': 'junos-http',
  'http': 'junos-http',
  'https': 'junos-https',
  // DNS
  'dns': 'junos-dns-udp',
  'dns-base': 'junos-dns-udp',
  // Mail
  'smtp': 'junos-smtp',
  'smtp-base': 'junos-smtp',
  'pop3': 'junos-pop3',
  'imap': 'junos-imap',
  'imap4': 'junos-imap',
  'pop3s': 'junos-pop3s',
  'imaps': 'junos-imaps',
  'smtps': 'junos-smtps',
  // File transfer
  'ftp': 'junos-ftp',
  'ftp-data': 'junos-ftp-data',
  'tftp': 'junos-tftp',
  // Remote access
  'ssh': 'junos-ssh',
  'telnet': 'junos-telnet',
  'rdp': 'junos-rdp',
  'ms-rdp': 'junos-rdp',
  'rlogin': 'junos-rlogin',
  'rsh': 'junos-rsh',
  'vnc': 'junos-vnc',
  'vnc-base': 'junos-vnc',
  'pc-anywhere': 'junos-pc-anywhere',
  'pcanywhere': 'junos-pc-anywhere',
  // Network services
  'ping': 'junos-ping',
  'traceroute': 'junos-traceroute',
  'ntp': 'junos-ntp',
  'ntp-base': 'junos-ntp',
  'snmp': 'junos-snmp',
  'snmpv1': 'junos-snmp',
  'snmpv2c': 'junos-snmp',
  'snmpv3': 'junos-snmp',
  'syslog': 'junos-syslog',
  'dhcp': 'junos-dhcp-client',
  'dhcp-relay': 'junos-dhcp-relay',
  // VPN / Tunnel
  'ike': 'junos-ike',
  'ike-base': 'junos-ike',
  'ike-nat-traversal': 'junos-ike-nat',
  'ipsec': 'junos-ipsec',
  'ipsec-esp': 'junos-ipsec',
  'l2tp': 'junos-l2tp',
  'pptp': 'junos-pptp',
  // STUN / QUIC
  'stun': 'junos-stun',
  'stun-base': 'junos-stun',
  'quic': 'junos-quic',
  'quic-base': 'junos-quic',
  // Database
  'ms-sql-db': 'junos-ms-sql',
  'mssql-db': 'junos-ms-sql',
  'mssql': 'junos-ms-sql',
  'mssql-mon': 'junos-sqlmon',
  'mysql': 'junos-mysql',
  'oracle-db': 'junos-sqlnet-v2',
  'oracle': 'junos-sqlnet-v2',
  'sqlnet': 'junos-sqlnet-v2',
  // Secure file transfer (over SSH)
  'scp': 'junos-ssh',
  'sftp': 'junos-ssh',
  // LDAP / Directory
  'ldap': 'junos-ldap',
  'ldap-base': 'junos-ldap',
  'active-directory': 'junos-ldap',
  'ms-ds-smbv2': 'junos-smb',
  'ms-ds-smbv3': 'junos-smb',
  'ms-ds-smb-base': 'junos-smb',
  // ICMP
  'icmp': 'junos-icmp-all',
  'icmp6': 'junos-icmp-any',
  // Streaming / VoIP
  'sip': 'junos-sip',
  'sip-base': 'junos-sip',
  'h323': 'junos-h323',
  'h.323': 'junos-h323',
  'rtsp': 'junos-rtsp',
  'rtsp-base': 'junos-rtsp',
  'sccp': 'junos-sccp',
  'skinny': 'junos-sccp',
  'netmeeting': 'junos-netmeeting',
  'real-audio': 'junos-realaudio',
  'realaudio': 'junos-realaudio',
  'vdo-live': 'junos-vdo-live',
  // Routing
  'bgp': 'junos-bgp',
  'ospf': 'junos-ospf',
  'rip': 'junos-rip',
  // IM / P2P
  'irc': 'junos-irc',
  'msn-messenger': 'junos-msn',
  'ymsg': 'junos-ymsg',
  'yahoo-messenger': 'junos-ymsg',
  'gnutella': 'junos-gnutella',
  'aol-instant-messenger': 'junos-aol',
  'aim': 'junos-aol',
  // Microsoft RPC
  'ms-rpc': 'junos-ms-rpc-epm',
  'msrpc': 'junos-ms-rpc-epm',
  'ms-exchange': 'junos-ms-rpc-msexchange',
  // NetBIOS / SMB
  'netbios-ns': 'junos-nbname',
  'netbios-dg': 'junos-nbds',
  'netbios-ss': 'junos-smb',
  'netbios-ssn': 'junos-smb',
  'smb': 'junos-smb',
  'cifs': 'junos-smb',
  // Additional management / network
  'radius-accounting': 'junos-radius-accounting',
  'twamp': 'junos-twamp',
  'snmp-trap': 'junos-snmp',
  'dhcp-server': 'junos-dhcp-server',
  'dhcp-client': 'junos-dhcp-client',
  'syslog-ng': 'junos-syslog',
  'citrix': 'junos-winframe',
  'citrix-online': 'junos-winframe',
  'gre': 'junos-udp-any',  // GRE is IP protocol 47 — no junos-gre predefined
  // Misc management
  'finger': 'junos-finger',
  'gopher': 'junos-gopher',
  'whois': 'junos-whois',
  'ident': 'junos-ident',
  'lpr': 'junos-lpr',
  'radius': 'junos-radius',
  'nntp': 'junos-nntp',
  'x11': 'junos-x-windows',
  'x-windows': 'junos-x-windows',
  'nfs': 'junos-nfs',
  'sun-rpc': 'junos-sun-rpc-any',
  'rpc-portmapper': 'junos-sun-rpc-portmapper',
  'chargen': 'junos-chargen',
  'discard': 'junos-discard',
  'wais': 'junos-wais',
  'uucp': 'junos-uucp',
  'talk': 'junos-talk',

  // ── FortiGate Service Object Names (case-sensitive uppercase) ──
  'HTTP': 'junos-http',
  'HTTPS': 'junos-https',
  'DNS': 'junos-dns-udp',
  'FTP': 'junos-ftp',
  'FTP_GET': 'junos-ftp',
  'FTP_PUT': 'junos-ftp',
  'TFTP': 'junos-tftp',
  'SSH': 'junos-ssh',
  'TELNET': 'junos-telnet',
  'SMTP': 'junos-smtp',
  'SMTPS': 'junos-smtps',
  'POP3': 'junos-pop3',
  'POP3S': 'junos-pop3s',
  'IMAP': 'junos-imap',
  'IMAPS': 'junos-imaps',
  'SNMP': 'junos-snmp',
  'NTP': 'junos-ntp',
  'SYSLOG': 'junos-syslog',
  'RDP': 'junos-rdp',
  'SIP': 'junos-sip',
  'SIP-MSNmessenger': 'junos-sip',
  'H.323': 'junos-h323',
  'PING': 'junos-ping',
  'PING6': 'junos-icmp-any',
  'TRACEROUTE': 'junos-traceroute',
  'IKE': 'junos-ike',
  'IKE_NAT_TRAVERSAL': 'junos-ike-nat',
  'L2TP': 'junos-l2tp',
  'PPTP': 'junos-pptp',
  'IRC': 'junos-irc',
  'LDAP': 'junos-ldap',
  'LDAP_UDP': 'junos-ldap',
  'SMB': 'junos-smb',
  'SAMBA': 'junos-smb',
  'DCE-RPC': 'junos-ms-rpc-epm',
  'MS-SQL': 'junos-ms-sql',
  'MYSQL': 'junos-mysql',
  'RADIUS': 'junos-radius',
  'RADIUS-OLD': 'junos-radius',
  'WINS': 'junos-nbname',
  'NBNAME': 'junos-nbname',
  'NBDATAGRAM': 'junos-nbds',
  'NBSESSION': 'junos-smb',
  'NFS': 'junos-nfs',
  'X-WINDOWS': 'junos-x-windows',
  'VNC': 'junos-vnc',
  'BGP': 'junos-bgp',
  'OSPF': 'junos-ospf',
  'RIP': 'junos-rip',
  'GRE': 'junos-udp-any',  // GRE is IP protocol 47 — not PPTP
  'STUN': 'junos-stun',
  'QUIC': 'junos-quic',
  'FINGER': 'junos-finger',
  'GOPHER': 'junos-gopher',
  'NNTP': 'junos-nntp',
  'WHOIS': 'junos-whois',
  'AH': 'junos-ipsec',
  'ESP': 'junos-ipsec',
  'ALL': 'any',
  'ALL_TCP': 'junos-tcp-any',
  'ALL_UDP': 'junos-udp-any',
  'ALL_ICMP': 'junos-icmp-any',
  'ALL_ICMP6': 'junos-icmp-any',
  'webproxy': 'junos-http',
  'DHCP': 'junos-dhcp-client',
  'SCP': 'junos-ssh',
  'SFTP': 'junos-ssh',
  'TWAMP': 'junos-twamp',
  'SNMP_TRAP': 'junos-snmp',
  'RADIUS_ACCOUNTING': 'junos-radius-accounting',
  'TIMESTAMP': 'junos-icmp-timestamp',
  'INFO_REQUEST': 'junos-icmp-info',
  'INFO_ADDRESS': 'junos-icmp-address-mask',
  'SCCP': 'junos-sccp',
  'PC-Anywhere': 'junos-pc-anywhere',
  'LPR': 'junos-lpr',
  'UUCP': 'junos-uucp',
  'TALK': 'junos-talk',

  // ── Cisco ASA Common Service Names ────────────────────────
  'www': 'junos-http',
  'domain': 'junos-dns-udp',
  'sunrpc': 'junos-sun-rpc-any',
  'login': 'junos-rlogin',
  'shell': 'junos-rsh',
  'exec': 'junos-rsh',
  'lpd': 'junos-lpr',
};

export function mapAppToJunos(appName) {
  if (!appName) return null;
  // Try exact match first (preserves case for FortiGate uppercase names)
  if (APP_MAP[appName]) return APP_MAP[appName];
  // Then try lowercase normalized
  const normalized = appName.toLowerCase().trim();
  return APP_MAP[normalized] || null;
}

// Backward-compatible alias
export const mapPanosAppToJunos = mapAppToJunos;

/**
 * Maps a PAN-OS security profile type to the corresponding SRX feature and profile name.
 *
 * Security profiles map to SRX as follows:
 *   virus, wildfire-analysis       → UTM anti-virus
 *   url-filtering                  → UTM web-filtering
 *   file-blocking                  → UTM content-filtering
 *   spyware, vulnerability         → IDP
 *   application-control (FortiGate) → AppFW (manual)
 *   email-filter (FortiGate)       → UTM anti-spam
 *   dlp (FortiGate)                → DLP (ICAP)
 *
 * @param {string} profileType - profile type (e.g. 'virus', 'application-control')
 * @param {string} profileName - profile name (e.g. 'default', 'strict')
 * @returns {{ srxFeature: string, srxType: string, srxProfile: string }}
 */
export function mapProfileToSrx(profileType, profileName) {
  const safeName = sanitizeJunosName(profileName);
  const mapping = {
    // PAN-OS originated
    'virus':              { srxFeature: 'utm', srxType: 'anti-virus',        srxProfile: `junos-av-${safeName}` },
    'wildfire-analysis':  { srxFeature: 'utm', srxType: 'anti-virus',        srxProfile: `junos-av-${safeName}` },
    'url-filtering':      { srxFeature: 'utm', srxType: 'web-filtering',     srxProfile: `junos-wf-${safeName}` },
    'file-blocking':      { srxFeature: 'utm', srxType: 'content-filtering', srxProfile: `junos-cf-${safeName}` },
    'spyware':            { srxFeature: 'idp', srxType: 'idp-policy',        srxProfile: `idp-${safeName}` },
    'vulnerability':      { srxFeature: 'idp', srxType: 'idp-policy',        srxProfile: `idp-${safeName}` },
    // FortiGate originated
    'application-control': { srxFeature: 'appfw', srxType: 'application-firewall', srxProfile: `appfw-${safeName}` },
    'email-filter':        { srxFeature: 'utm',   srxType: 'anti-spam',            srxProfile: `junos-as-${safeName}` },
    'dlp':                 { srxFeature: 'none',  srxType: 'dlp',                  srxProfile: safeName },
    'dns-security':        { srxFeature: 'utm',   srxType: 'anti-spam',            srxProfile: `dns-${safeName}` },
  };
  return mapping[profileType] || { srxFeature: 'unknown', srxType: profileType, srxProfile: safeName };
}

// Backward-compatible alias
export const mapPanosProfileToSrx = mapProfileToSrx;

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

  // FortiGate / FortiOS: config/edit/set/next/end block format
  if (trimmed.includes('config firewall policy') && (trimmed.includes('set srcintf') || trimmed.includes('set dstintf'))) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.95 };
  }
  if (trimmed.includes('config system global') && (trimmed.includes('set hostname') || trimmed.includes('config firewall'))) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.95 };
  }
  if (trimmed.includes('config firewall address') && trimmed.includes('set subnet')) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.9 };
  }
  if (trimmed.includes('config firewall') && /\bedit\s+\d+\b/.test(trimmed) && trimmed.includes('\nnext')) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.85 };
  }
  if (trimmed.includes('set uuid') && trimmed.includes('config firewall')) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.85 };
  }

  // Cisco ASA: access-list + access-group + nameif/security-level markers
  if (trimmed.includes('access-list') && trimmed.includes('access-group') && (trimmed.includes('nameif') || trimmed.includes('security-level'))) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.95 };
  }
  if (trimmed.includes('ASA Version') && trimmed.includes('access-list')) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.95 };
  }
  if (trimmed.includes('access-list') && trimmed.includes('extended') && (trimmed.includes('nameif') || trimmed.includes('object network'))) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.9 };
  }
  if (trimmed.includes('object network') && trimmed.includes('object-group network') && trimmed.includes('access-list')) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.85 };
  }
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

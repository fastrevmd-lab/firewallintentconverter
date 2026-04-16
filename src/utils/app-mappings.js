/**
 * App Mappings — Multi-vendor L7 application mapping table.
 *
 * Adapted from fatcat/converter's app-mappings.json data file.
 * Provides bidirectional lookup: vendorApp → junosApp and vendorApp → canonical.
 */

// Our vendor IDs → fatcat vendor keys
const VENDOR_KEY_MAP = {
  panos: 'panos',
  fortigate: 'fortios',
  cisco_asa: 'ftd',
  srx: 'junos',
  checkpoint: 'checkpoint',
  sonicwall: 'sonicwall',
  huawei_usg: 'huawei',
};

let _appData = null;
let _vendorIndex = null; // Map<ourVendor, Map<vendorAppNameLower, entry>>

function _buildIndex() {
  _vendorIndex = {};
  for (const [ourVendor, fatcatKey] of Object.entries(VENDOR_KEY_MAP)) {
    if (!fatcatKey) continue;
    const map = new Map();
    for (const app of _appData.apps) {
      const vendorEntry = app.vendors[fatcatKey];
      if (vendorEntry) {
        map.set(vendorEntry.name.toLowerCase(), app);
      }
    }
    _vendorIndex[ourVendor] = map;
  }
}

/**
 * Loads and indexes the app-mappings.json file.
 * Called lazily on first use. Caches the result.
 */
export async function loadAppMappings() {
  if (_appData) return _appData;
  const mod = await import('../data/app-mappings.json', { with: { type: 'json' } });
  _appData = mod.default || mod;
  _buildIndex();
  return _appData;
}

/**
 * Converts fatcat's "junos:HTTPS" format to our "junos-https" style.
 */
function normalizeJunosName(name) {
  if (!name) return name;
  if (name.startsWith('junos:')) {
    return 'junos-' + name.slice(6).toLowerCase();
  }
  return name;
}

/**
 * Maps a vendor-specific application name to a Junos application name.
 *
 * @param {string} vendorAppName - The app name from the source config
 * @param {string} sourceVendor - Our vendor ID (panos, fortigate, cisco_asa, etc.)
 * @returns {{ junosApp: string, confidence: number, canonical: string, category: string } | null}
 */
export function mapVendorApp(vendorAppName, sourceVendor) {
  if (!vendorAppName || !_vendorIndex) return null;
  const index = _vendorIndex[sourceVendor];
  if (!index) return null;

  const entry = index.get(vendorAppName.toLowerCase());
  if (!entry) return null;

  const junosEntry = entry.vendors.junos;
  if (!junosEntry) return null;

  return {
    junosApp: normalizeJunosName(junosEntry.name),
    confidence: junosEntry.confidence,
    canonical: entry.canonical,
    category: entry.category,
    description: entry.description,
    ports: entry.ports,
  };
}

/**
 * Gets the canonical app info for a vendor-specific app name.
 *
 * @param {string} vendorAppName - App name from source config
 * @param {string} sourceVendor - Our vendor ID
 * @returns {{ canonical: string, ports: string[], category: string, description: string } | null}
 */
export function getCanonicalApp(vendorAppName, sourceVendor) {
  if (!vendorAppName || !_vendorIndex) return null;
  const index = _vendorIndex[sourceVendor];
  if (!index) return null;

  const entry = index.get(vendorAppName.toLowerCase());
  if (!entry) return null;

  return {
    canonical: entry.canonical,
    ports: entry.ports,
    category: entry.category,
    description: entry.description,
    protocols: entry.protocols,
  };
}

/**
 * Returns the total number of mapped applications.
 */
export function getAppCount() {
  return _appData?.apps?.length || 0;
}

/**
 * Returns true if the app mappings have been loaded.
 */
export function isLoaded() {
  return _appData !== null;
}

/**
 * Returns how a vendor app should be emitted as a Junos application reference.
 *
 *   { kind: 'predefined', name: 'junos-https' }
 *     → policy references this name directly; no applications-section emission needed.
 *
 *   { kind: 'custom', protocol: 'tcp', ports: ['5223','2195','2196'], canonical: '...' }
 *     → caller emits `set applications application <name> protocol tcp destination-port <p>`
 *       (for each port, possibly wrapped in an application-set for multi-port).
 *
 *   null
 *     → no knowledge; caller should fall through to sync APP_MAP then INTERVIEW block.
 *
 * Confidence threshold: 0.8, matching mapAppToJunos().
 *
 * @param {string} vendorAppName - The app name from the source config
 * @param {string} sourceVendor - Our vendor ID (panos, fortigate, cisco_asa, etc.)
 * @returns {{ kind: 'predefined', name: string } | { kind: 'custom', protocol: string, ports: string[], canonical: string } | null}
 */
export function getJunosEmission(vendorAppName, sourceVendor) {
  if (!vendorAppName || !_vendorIndex) return null;
  const index = _vendorIndex[sourceVendor];
  if (!index) return null;
  const entry = index.get(vendorAppName.toLowerCase());
  if (!entry) return null;

  const junosEntry = entry.vendors.junos;
  if (junosEntry && junosEntry.confidence >= 0.8) {
    return { kind: 'predefined', name: normalizeJunosName(junosEntry.name) };
  }

  // No high-confidence Junos predefined — emit as custom app if we know ports/protocols
  if (Array.isArray(entry.protocols) && entry.protocols.length > 0 &&
      Array.isArray(entry.ports) && entry.ports.length > 0) {
    // Prefer TCP if multi-protocol (simpler custom-app emission); protocols are uppercase in JSON
    const protoRaw = entry.protocols.includes('TCP') ? 'TCP' : entry.protocols[0];
    return {
      kind: 'custom',
      protocol: protoRaw.toLowerCase(),
      ports: entry.ports.slice(),
      canonical: entry.canonical,
    };
  }

  return null;
}

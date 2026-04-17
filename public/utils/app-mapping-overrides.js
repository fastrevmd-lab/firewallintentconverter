/**
 * App Mapping Overrides — browser-side CRUD wrapper over the
 * 'app-mappings-overrides' localStorage key consumed by
 * src/utils/app-mappings.js.
 *
 * Override record shape (per vendor, per app name — all keys lower-cased):
 *   {
 *     _deleted?: true,           // hides a bundled entry
 *     kind?: 'predefined' | 'custom',
 *     name?: string,             // for kind='predefined' (e.g. "junos-https")
 *     protocol?: 'tcp' | 'udp',  // for kind='custom'
 *     ports?: string[],          // for kind='custom'
 *     junosApp?: string,         // back-compat shape for mapVendorApp consumers
 *     canonical?: string,
 *     category?: string,
 *     description?: string
 *   }
 */
import { safeJsonParse } from './safe-json.js';
import { invalidateOverridesCache } from '../../src/utils/app-mappings.js';

const STORAGE_KEY = 'app-mappings-overrides';

/**
 * Reads the entire override map (all vendors).
 * Returns `{}` on missing/corrupt data.
 */
export function readOverrides() {
  if (typeof localStorage === 'undefined') return {};
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = safeJsonParse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * Persists the full override map and invalidates the in-memory cache
 * in app-mappings.js so the next lookup reflects the change.
 */
export function writeOverrides(overrides) {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(overrides ?? {}));
  invalidateOverridesCache();
}

/**
 * Upserts a single override for a vendor/app pair.
 * `vendorAppName` is normalised to lower-case.
 */
export function setOverride(sourceVendor, vendorAppName, record) {
  if (!sourceVendor || !vendorAppName || !record) return;
  const all = readOverrides();
  const vendorMap = all[sourceVendor] && typeof all[sourceVendor] === 'object' ? all[sourceVendor] : {};
  vendorMap[vendorAppName.toLowerCase()] = record;
  all[sourceVendor] = vendorMap;
  writeOverrides(all);
}

/**
 * Removes an override. If `suppressBundled` is true, leaves a `_deleted: true`
 * tombstone so the bundled entry is hidden; otherwise fully removes the key,
 * letting the bundled entry reappear.
 */
export function removeOverride(sourceVendor, vendorAppName, { suppressBundled = false } = {}) {
  if (!sourceVendor || !vendorAppName) return;
  const all = readOverrides();
  const vendorMap = all[sourceVendor];
  if (!vendorMap) return;
  const key = vendorAppName.toLowerCase();
  if (suppressBundled) {
    vendorMap[key] = { _deleted: true };
  } else {
    delete vendorMap[key];
    if (Object.keys(vendorMap).length === 0) delete all[sourceVendor];
  }
  writeOverrides(all);
}

/**
 * Wipes all overrides (with confirmation handled by the caller).
 */
export function resetAllOverrides() {
  if (typeof localStorage === 'undefined') return;
  localStorage.removeItem(STORAGE_KEY);
  invalidateOverridesCache();
}

/**
 * Exports overrides as a pretty-printed JSON string for the Download button.
 */
export function exportOverridesAsJson() {
  return JSON.stringify(readOverrides(), null, 2);
}

/**
 * Imports overrides from a JSON string. Validates the outer shape; individual
 * records are trusted to be well-formed (the editor UI enforces shape).
 * Returns `{ ok: true }` on success, `{ ok: false, error }` on parse failure.
 */
export function importOverridesFromJson(jsonText) {
  try {
    const parsed = safeJsonParse(jsonText);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, error: 'Expected a JSON object keyed by vendor id' };
    }
    writeOverrides(parsed);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/**
 * Count helper for badge display in the TopBar menu entry.
 */
export function countOverrides() {
  const all = readOverrides();
  let total = 0;
  for (const vendorMap of Object.values(all)) {
    if (vendorMap && typeof vendorMap === 'object') {
      total += Object.keys(vendorMap).length;
    }
  }
  return total;
}

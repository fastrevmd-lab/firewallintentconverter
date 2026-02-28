/**
 * Engine — client-side replacements for the former Express API endpoints.
 *
 * All parsers, converters, validators, and the sanitizer run entirely
 * in the browser.  No server required.
 */

import { detectVendor } from '../../src/parsers/parser-utils.js';
import { parsePanosConfig } from '../../src/parsers/panos-parser.js';
import { parseSrxConfig } from '../../src/parsers/srx-parser.js';
import { parseFortigateConfig } from '../../src/parsers/fortigate-parser.js';
import { parseCiscoAsaConfig } from '../../src/parsers/cisco-asa-parser.js';
import { parseCheckPointConfig } from '../../src/parsers/checkpoint-parser.js';
import { parseSonicWallConfig } from '../../src/parsers/sonicwall-parser.js';
import { parseHuaweiConfig } from '../../src/parsers/huawei-parser.js';
import { convertToSrxSetCommands, convertMergedToSrxSetCommands } from '../../src/converters/srx-converter.js';
import { buildSrxXml, buildMergedSrxXml } from '../../src/converters/srx-xml-builder.js';
import { validateSrxOutput } from '../../src/validators/srx-validator.js';
import { detectShadowedRules } from '../../src/analysis/shadow-detector.js';

// ---------------------------------------------------------------------------
// parseConfig  (replaces POST /api/parse)
// ---------------------------------------------------------------------------
export function parseConfig(configText) {
  if (!configText || typeof configText !== 'string') {
    throw new Error('configText is required and must be a string');
  }

  const detection = detectVendor(configText);
  let result;

  if (detection.vendor === 'srx') {
    result = parseSrxConfig(configText);
  } else if (detection.vendor === 'fortigate') {
    result = parseFortigateConfig(configText);
  } else if (detection.vendor === 'cisco_asa') {
    result = parseCiscoAsaConfig(configText);
  } else if (detection.vendor === 'checkpoint') {
    result = parseCheckPointConfig(configText);
  } else if (detection.vendor === 'sonicwall') {
    result = parseSonicWallConfig(configText);
  } else if (detection.vendor === 'huawei_usg') {
    result = parseHuaweiConfig(configText);
  } else {
    result = parsePanosConfig(configText);
  }

  result.detectedVendor = detection.vendor;
  return result;
}

// ---------------------------------------------------------------------------
// convertConfig  (replaces POST /api/convert)
// ---------------------------------------------------------------------------
export function convertConfig(intermediateConfig, format = 'set', interfaceMappings = {}, targetContext = null) {
  if (!intermediateConfig) {
    throw new Error('intermediateConfig is required');
  }
  if (!['set', 'xml'].includes(format)) {
    throw new Error("format must be 'set' or 'xml'");
  }

  let output;
  if (format === 'xml') {
    output = buildSrxXml(intermediateConfig, interfaceMappings, targetContext);
  } else {
    output = convertToSrxSetCommands(intermediateConfig, interfaceMappings, targetContext);
  }

  // Detect shadowed rules and optimization opportunities
  const analysis = detectShadowedRules(intermediateConfig.security_policies, output.warnings);
  if (output.summary) {
    output.summary.shadowed_rules = analysis.shadowedCount;
    output.summary.reorder_issues = analysis.reorderCount;
    output.summary.optimization_suggestions =
      (analysis.redundantCount || 0) + (analysis.mergeableCount || 0) + (analysis.consolidateCount || 0);
  }

  // Run validation on the generated output
  const validation = validateSrxOutput(intermediateConfig, output);

  return { output, format, validation };
}

// ---------------------------------------------------------------------------
// mergeConvert  (replaces POST /api/merge-convert)
// ---------------------------------------------------------------------------
export function mergeConvert(configSlots, crossLsLinks = [], format = 'set', globalConfig = {}) {
  if (!configSlots || !Array.isArray(configSlots) || configSlots.length < 1) {
    throw new Error('configSlots array is required with at least 1 entry');
  }
  if (!['set', 'xml'].includes(format)) {
    throw new Error("format must be 'set' or 'xml'");
  }

  let output;
  if (format === 'xml') {
    output = buildMergedSrxXml(configSlots, crossLsLinks, globalConfig);
  } else {
    output = convertMergedToSrxSetCommands(configSlots, crossLsLinks, globalConfig);
  }

  return { output, format };
}

// ---------------------------------------------------------------------------
// sanitizeConfig  (replaces POST /api/sanitize)
// ---------------------------------------------------------------------------
export function sanitizeConfig(configText) {
  if (!configText || typeof configText !== 'string') {
    throw new Error('configText is required and must be a string');
  }

  const replacements = [];
  let counter = { hash: 0, key: 0, user: 0, ip: 0, community: 0 };
  let sanitized = configText;

  // --- 1. Password hashes (phash, $1$, $5$, $6$, $sha1$, etc.) ---
  sanitized = sanitized.replace(
    /(<(?:phash|password-hash|encrypted-secret)>)([^<]+)(<\/)/gi,
    (match, open, value, close) => {
      const idx = counter.hash++;
      const placeholder = `SANITIZED_HASH_${idx}`;
      replacements.push({ type: 'hash', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  // Hashes in attribute-style: password "..."
  sanitized = sanitized.replace(
    /(password|secret|pre-shared-key|auth-key)\s+"(\$[^"]+)"/gi,
    (match, keyword, value) => {
      const idx = counter.hash++;
      const placeholder = `SANITIZED_HASH_${idx}`;
      replacements.push({ type: 'hash', placeholder, original: value });
      return `${keyword} "${placeholder}"`;
    }
  );

  // --- 2. Pre-shared keys and API keys ---
  sanitized = sanitized.replace(
    /(<(?:pre-shared-key|api-key|auth-key|secret|key)>)\s*(<key>)([^<]+)(<\/key>)/gi,
    (match, outerOpen, innerOpen, value, innerClose) => {
      const idx = counter.key++;
      const placeholder = `SANITIZED_KEY_${idx}`;
      replacements.push({ type: 'key', placeholder, original: value.trim() });
      return `${outerOpen}${innerOpen}${placeholder}${innerClose}`;
    }
  );

  // Simple key value tags
  sanitized = sanitized.replace(
    /(<(?:pre-shared-key|api-key|auth-key|community|secret-key)>)([^<]+)(<\/)/gi,
    (match, open, value, close) => {
      if (value.trim().startsWith('SANITIZED_')) return match;
      const idx = counter.key++;
      const placeholder = `SANITIZED_KEY_${idx}`;
      replacements.push({ type: 'key', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  // --- 3. SNMP communities ---
  sanitized = sanitized.replace(
    /(<community>)([^<]+)(<\/community>)/gi,
    (match, open, value, close) => {
      if (value.trim().startsWith('SANITIZED_')) return match;
      const idx = counter.community++;
      const placeholder = `SANITIZED_COMMUNITY_${idx}`;
      replacements.push({ type: 'community', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  // --- 4. Usernames in authentication contexts ---
  sanitized = sanitized.replace(
    /(<(?:admin-username|radius-username|tacplus-username|ldap-bind-dn)>)([^<]+)(<\/)/gi,
    (match, open, value, close) => {
      const idx = counter.user++;
      const placeholder = `SANITIZED_USER_${idx}`;
      replacements.push({ type: 'username', placeholder, original: value.trim() });
      return `${open}${placeholder}${close}`;
    }
  );

  // User entries under <users><entry name="xxx">
  sanitized = sanitized.replace(
    /(<users>\s*(?:<entry\s+name="))([^"]+)(")/gi,
    (match, prefix, name, suffix) => {
      if (name === 'admin' || name.startsWith('SANITIZED_')) return match;
      const idx = counter.user++;
      const placeholder = `SANITIZED_USER_${idx}`;
      replacements.push({ type: 'username', placeholder, original: name });
      return `${prefix}${placeholder}${suffix}`;
    }
  );

  // --- 5. Public IP addresses ---
  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const isPrivateOrReserved = (ip) => {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a >= 224) return true;
    if (a === 0) return true;
    return false;
  };

  const ipMap = new Map();
  sanitized = sanitized.replace(ipRegex, (match) => {
    const parts = match.split('.').map(Number);
    if (parts.some(p => p > 255)) return match;
    if (isPrivateOrReserved(match)) return match;

    if (ipMap.has(match)) return ipMap.get(match);

    const idx = counter.ip++;
    const placeholder = `PUBLIC_IP_${idx}`;
    ipMap.set(match, placeholder);
    replacements.push({ type: 'public_ip', placeholder, original: match, restore: true });
    return placeholder;
  });

  return {
    sanitizedText: sanitized,
    replacements,
    stats: {
      hashes: counter.hash,
      keys: counter.key,
      communities: counter.community,
      usernames: counter.user,
      publicIPs: counter.ip,
      total: replacements.length,
    },
  };
}

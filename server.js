/**
 * Express server for Firewall Policy Converter.
 *
 * In development:  Vite is attached as middleware so a single `node server.js`
 *                  serves both the React app (with HMR) and the API.
 * In production:   The pre-built Vite output in dist/ is served as static files.
 *
 * API endpoints:
 *   POST /api/parse    – accepts { configText, vendor? } → intermediate JSON
 *   POST /api/convert  – accepts { intermediateConfig, format? } → SRX output
 */

import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { parsePanosConfig } from './src/parsers/panos-parser.js';
import { parseSrxConfig } from './src/parsers/srx-parser.js';
import { parseFortigateConfig } from './src/parsers/fortigate-parser.js';
import { parseCiscoAsaConfig } from './src/parsers/cisco-asa-parser.js';
import { parseCheckPointConfig } from './src/parsers/checkpoint-parser.js';
import { parseSonicWallConfig } from './src/parsers/sonicwall-parser.js';
import { parseHuaweiConfig } from './src/parsers/huawei-parser.js';
import { detectVendor } from './src/parsers/parser-utils.js';
import { convertToSrxSetCommands } from './src/converters/srx-converter.js';
import { buildSrxXml } from './src/converters/srx-xml-builder.js';
import { validateSrxOutput } from './src/validators/srx-validator.js';
import { detectShadowedRules } from './src/analysis/shadow-detector.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const isDev = process.env.NODE_ENV !== 'production';

// PAN-OS configs can be very large (10k+ rules), so allow generous payloads
app.use(express.json({ limit: '50mb' }));

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------

/**
 * POST /api/parse
 * Accepts raw PAN-OS XML config text and returns a vendor-neutral
 * intermediate JSON representation.
 */
app.post('/api/parse', (req, res) => {
  try {
    const { configText } = req.body;
    if (!configText || typeof configText !== 'string') {
      return res.status(400).json({ error: 'configText is required and must be a string' });
    }

    // Detect vendor to route to the correct parser
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

    // Include detected vendor in response
    result.detectedVendor = detection.vendor;
    res.json(result);
  } catch (error) {
    console.error('[parse] Error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

/**
 * POST /api/sanitize
 * Strips sensitive data from raw config text and returns sanitized version
 * plus a replacement table for later restoration on export.
 *
 * Replaces: password hashes, pre-shared keys, SNMP communities, API keys,
 *           usernames in auth contexts, and public IP addresses.
 */
app.post('/api/sanitize', (req, res) => {
  try {
    const { configText } = req.body;
    if (!configText || typeof configText !== 'string') {
      return res.status(400).json({ error: 'configText is required and must be a string' });
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
    // Match <username>...</username> inside management/auth config sections
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
    // Replace public IPv4 addresses (not RFC1918, not loopback, not link-local, not multicast)
    const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
    const isPrivateOrReserved = (ip) => {
      const [a, b] = ip.split('.').map(Number);
      if (a === 10) return true;                           // 10.0.0.0/8
      if (a === 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
      if (a === 192 && b === 168) return true;             // 192.168.0.0/16
      if (a === 127) return true;                          // loopback
      if (a === 169 && b === 254) return true;             // link-local
      if (a >= 224) return true;                           // multicast & reserved
      if (a === 0) return true;                            // default/unspecified
      return false;
    };

    // Track which IPs map to which placeholders so the same IP always gets the same placeholder
    const ipMap = new Map();
    sanitized = sanitized.replace(ipRegex, (match) => {
      const parts = match.split('.').map(Number);
      // Validate it's a real IP (each octet 0-255)
      if (parts.some(p => p > 255)) return match;
      if (isPrivateOrReserved(match)) return match;

      if (ipMap.has(match)) return ipMap.get(match);

      const idx = counter.ip++;
      const placeholder = `PUBLIC_IP_${idx}`;
      ipMap.set(match, placeholder);
      replacements.push({ type: 'public_ip', placeholder, original: match, restore: true });
      return placeholder;
    });

    res.json({
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
    });
  } catch (error) {
    console.error('[sanitize] Error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

/**
 * POST /api/convert
 * Accepts an intermediate JSON config and converts it to SRX output.
 * Query param `format` can be "set" (default) or "xml".
 */
app.post('/api/convert', (req, res) => {
  try {
    const { intermediateConfig, format = 'set', interfaceMappings = {}, targetContext = null } = req.body;
    if (!intermediateConfig) {
      return res.status(400).json({ error: 'intermediateConfig is required' });
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
      output.summary.optimization_suggestions = (analysis.redundantCount || 0) + (analysis.mergeableCount || 0) + (analysis.consolidateCount || 0);
    }

    // Run validation on the generated output
    const validation = validateSrxOutput(intermediateConfig, output);

    res.json({
      output,
      format,
      validation,
    });
  } catch (error) {
    console.error('[convert] Error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// Frontend Serving
// ---------------------------------------------------------------------------

if (isDev) {
  // In dev mode, attach Vite as Express middleware for HMR + JSX transforms
  const { createServer: createViteServer } = await import('vite');
  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'spa',
  });
  app.use(vite.middlewares);
} else {
  // In production, serve the pre-built Vite output
  app.use(express.static(resolve(__dirname, 'dist')));
  app.get('*', (_req, res) => {
    res.sendFile(resolve(__dirname, 'dist', 'index.html'));
  });
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`Firewall Policy Converter running at http://localhost:${PORT}`);
  if (isDev) {
    console.log('Development mode — Vite HMR active');
  }
});

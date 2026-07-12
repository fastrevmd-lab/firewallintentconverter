# Sanitized Project Export Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent every original or supported secret from appearing in a sanitized project file while providing explicit encrypted reversible backups and warned plaintext unsanitized exports.

**Architecture:** Move project export behind a single fail-closed security boundary. A shared declarative secret registry powers sanitizer redaction and export detection; strict v5 project schemas distinguish sanitized, reversible-encrypted, and unsanitized files; Web Crypto protects reversible payloads; hook and modal code can download only bytes returned by the validated boundary.

**Tech Stack:** JavaScript ES modules, React 18, Vitest 4, Node 22 Web Crypto, browser Web Crypto, Vite 8, existing safe JSON and conversion-output validators. Add no runtime or test dependency.

## Global Constraints

- Work only in `/home/mharman/Projects/fwintentconverter/.worktrees/issue-11-sanitized-project-secrets` on branch `agent/issue-11-sanitized-project-secrets`.
- Design authority: `docs/superpowers/specs/2026-07-12-sanitized-project-export-security-design.md`.
- Project format advances to version 5. Valid exported modes are exactly `sanitized`, `reversible-encrypted`, and `unsanitized`.
- A version 5 sanitized file has no `sanitizationTable` at any depth, no known original in raw or JSON-escaped form, and `restorationAvailable: false`.
- A reversible file is AES-256-GCM authenticated ciphertext derived with PBKDF2-HMAC-SHA-256, exactly 600,000 iterations, a fresh 16-byte salt, a fresh 12-byte nonce, and a 128-bit tag.
- Passphrases require at least 16 Unicode code points, at most 1,024 UTF-8 bytes, and exact confirmation. Never persist or log a passphrase, derived key, source secret, matched original, or raw cryptographic exception.
- Maximum plaintext/decrypted payload is 48 MiB; maximum imported file is 65 MiB; recursive scans allow at most depth 128 and 1,000,000 nodes.
- Sanitized export is available only when every populated active or merge-slot source is explicitly sanitized. Populated greenfield, raw, and mixed workspaces are unsanitized.
- Secret entries never receive `restore: true`.
- Project JSON serialization and project Blob construction are forbidden outside the approved security/download boundary.
- Every production change follows strict red-green-refactor TDD. Capture the failing output before implementation.
- After each task, commit only its intended files and run an independent task review before starting the next task.
- Do not push until Tasks 1–8 and the final whole-branch review are clean. Never force-push.

---

### Task 1: Shared Vendor Secret Registry

**Files:**
- Create: `public/utils/secret-detection.js`
- Create: `tests/secret-detection.test.js`
- Modify: `public/utils/engine.js:156-1115`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: raw configuration text accepted by `sanitizeConfig(configText)`.
- Produces:
  - `redactConfigSecrets(text: string): { text: string, replacements: Array<{type, placeholder, original}>, counts: {hash, key, community, cert} }`
  - `findSecretsInText(text: string): Array<{category: string, ruleId: string}>`
  - `isSanitizedSecretValue(value: unknown): boolean`
  - `isSecretBearingKey(key: string): boolean`
- `sanitizeConfig` must merge secret replacements and counts from this module, then run its existing non-secret passes.

- [ ] **Step 1: Add the failing vendor syntax matrix**

Create `tests/secret-detection.test.js` with real input strings and unique markers:

```js
import { describe, expect, it } from 'vitest';
import {
  findSecretsInText,
  isSanitizedSecretValue,
  isSecretBearingKey,
  redactConfigSecrets,
} from '../public/utils/secret-detection.js';
import { sanitizeConfig } from '../public/utils/engine.js';

const CASES = [
  ['panos nested PSK', '<pre-shared-key><key>PANOS-PSK-ORIGINAL</key></pre-shared-key>', 'PANOS-PSK-ORIGINAL', 'key'],
  ['panos phash', '<phash>$6$PANOS-HASH-ORIGINAL</phash>', '$6$PANOS-HASH-ORIGINAL', 'hash'],
  ['panos private key', '<private-key>PANOS-PRIVATE-ORIGINAL</private-key>', 'PANOS-PRIVATE-ORIGINAL', 'certificate'],
  ['panos certificate key', '<certificate-key>PANOS-CERT-SECRET-ORIGINAL</certificate-key>', 'PANOS-CERT-SECRET-ORIGINAL', 'certificate'],
  ['fortigate encrypted password', 'set password ENC FGT-PASSWORD-ORIGINAL', 'ENC FGT-PASSWORD-ORIGINAL', 'hash'],
  ['fortigate psksecret', 'set psksecret \"FGT-PSK-ORIGINAL\"', 'FGT-PSK-ORIGINAL', 'key'],
  ['fortigate SNMP', 'set community \"FGT-SNMP-ORIGINAL\"', 'FGT-SNMP-ORIGINAL', 'community'],
  ['fortigate RADIUS secret', 'set secret \"FGT-RADIUS-ORIGINAL\"', 'FGT-RADIUS-ORIGINAL', 'key'],
  ['asa ISAKMP key', 'crypto isakmp key ASA-PSK-ORIGINAL address 203.0.113.9', 'ASA-PSK-ORIGINAL', 'key'],
  ['asa enable secret', 'enable secret ASA-HASH-ORIGINAL', 'ASA-HASH-ORIGINAL', 'hash'],
  ['asa username password', 'username operator password ASA-PASSWORD-ORIGINAL', 'ASA-PASSWORD-ORIGINAL', 'hash'],
  ['asa RADIUS key', 'radius-server host 192.0.2.2 key ASA-RADIUS-ORIGINAL', 'ASA-RADIUS-ORIGINAL', 'key'],
  ['asa TACACS key', 'tacacs-server host 192.0.2.3 key ASA-TACACS-ORIGINAL', 'ASA-TACACS-ORIGINAL', 'key'],
  ['junos set ascii PSK', 'set security ike policy branch pre-shared-key ascii-text \"JUNOS-PSK-ORIGINAL\"', 'JUNOS-PSK-ORIGINAL', 'key'],
  ['junos encrypted password', 'set system login user ops authentication encrypted-password \"$6$JUNOS-HASH-ORIGINAL\"', '$6$JUNOS-HASH-ORIGINAL', 'hash'],
  ['junos SNMP community', 'set snmp community JUNOS-SNMP-ORIGINAL authorization read-only', 'JUNOS-SNMP-ORIGINAL', 'community'],
  ['junos RADIUS secret', 'set system radius-server 192.0.2.4 secret \"JUNOS-RADIUS-ORIGINAL\"', 'JUNOS-RADIUS-ORIGINAL', 'key'],
  ['junos TACPLUS secret', 'set system tacplus-server 192.0.2.5 secret \"JUNOS-TACACS-ORIGINAL\"', 'JUNOS-TACACS-ORIGINAL', 'key'],
  ['junos authentication password', 'set snmp v3 usm local-engine user ops authentication-sha authentication-password \"JUNOS-AUTH-ORIGINAL\"', 'JUNOS-AUTH-ORIGINAL', 'key'],
  ['junos privacy password', 'set snmp v3 usm local-engine user ops privacy-aes128 privacy-password \"JUNOS-PRIVACY-ORIGINAL\"', 'JUNOS-PRIVACY-ORIGINAL', 'key'],
  ['checkpoint JSON shared secret', '\"shared-secret\":\"CHECKPOINT-PSK-ORIGINAL\"', 'CHECKPOINT-PSK-ORIGINAL', 'key'],
  ['checkpoint JSON password hash', '\"password-hash\":\"CHECKPOINT-HASH-ORIGINAL\"', 'CHECKPOINT-HASH-ORIGINAL', 'hash'],
  ['sonicwall shared secret', 'Shared Secret: SONICWALL-PSK-ORIGINAL', 'SONICWALL-PSK-ORIGINAL', 'key'],
  ['sonicwall password', 'Password: SONICWALL-PASSWORD-ORIGINAL', 'SONICWALL-PASSWORD-ORIGINAL', 'hash'],
  ['generic OpenSSH private key', '-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE-KEY-ORIGINAL\n-----END OPENSSH PRIVATE KEY-----', 'PRIVATE-KEY-ORIGINAL', 'certificate'],
];

describe('firewall secret registry', () => {
  it.each(CASES)('detects and redacts %s', (_label, text, original, type) => {
    const findings = findSecretsInText(text);
    const redacted = redactConfigSecrets(text);
    expect(findings).toHaveLength(1);
    expect(redacted.text).not.toContain(original);
    expect(redacted.replacements).toEqual([
      expect.objectContaining({ type }),
    ]);
    expect(redacted.replacements[0].original).toContain(original);
    expect(redacted.replacements[0]).not.toHaveProperty('restore');
    expect(findSecretsInText(redacted.text)).toEqual([]);
  });

  it('keeps detection and sanitizeConfig redaction in parity', () => {
    for (const [, text, original] of CASES) {
      const result = sanitizeConfig(text);
      expect(result.sanitizedText).not.toContain(original);
      expect(result.replacements.some(entry => entry.original === original)).toBe(true);
    }
  });

  it.each([
    'SANITIZED_HASH_0',
    'SANITIZED_KEY_19',
    'SANITIZED_COMMUNITY_2',
    'SANITIZED_CERT_4',
  ])('recognizes placeholder %s', value => {
    expect(isSanitizedSecretValue(value)).toBe(true);
    expect(findSecretsInText('set password \"' + value + '\"')).toEqual([]);
  });

  it('allocates after existing placeholder indexes', () => {
    const result = redactConfigSecrets(
      'set psksecret "SANITIZED_KEY_19"\nset secret "NEW-ORIGINAL"',
    );
    expect(result.text).toContain('SANITIZED_KEY_19');
    expect(result.replacements[0].placeholder).toBe('SANITIZED_KEY_20');
  });

  it.each(['password', 'password_hash', 'pre-shared-key', 'psksecret', 'snmpCommunity', 'radius_secret', 'tacplus-key', 'privateKey', 'certificate-key'])(
    'recognizes secret-bearing key %s',
    key => expect(isSecretBearingKey(key)).toBe(true),
  );

  it.each([
    'set security ike proposal ike authentication-method pre-shared-keys',
    '<certificate>PUBLIC-CERTIFICATE-DATA</certificate>',
    'set applications application tacacs-plus protocol tcp',
  ])('does not classify non-secret syntax: %s', text => {
    expect(findSecretsInText(text)).toEqual([]);
  });
});
```

- [ ] **Step 2: Run the matrix and capture RED**

Run:

```bash
npx vitest run tests/secret-detection.test.js
```

Expected: FAIL because `public/utils/secret-detection.js` does not exist.

- [ ] **Step 3: Implement the declarative registry and bounded replacement engine**

Create `public/utils/secret-detection.js`. Use one regex definition for detection and replacement; clone regexes before execution so global `lastIndex` cannot leak between calls:

```js
const PLACEHOLDER_RE = /^SANITIZED_(?:HASH|KEY|COMMUNITY|CERT)_\d+$/;
const KEY_RE = /^(?:password|passwd|passwordhash|phash|encryptedpassword|secret|sharedsecret|secondarysecret|psk|presharedkey|psksecret|authkey|authenticationkey|authenticationpassword|privacykey|privacypassword|apikey|snmpcommunity|radiussecret|radiuskey|tacacssecret|tacacskey|tacplussecret|tacpluskey|privatekey|certificatekey)$/;

function normalizedKey(key) {
  return String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function syntax(ruleId, category, placeholderKind, regex, valueGroup, render) {
  return Object.freeze({ ruleId, category, placeholderKind, regex, valueGroup, render });
}

const SECRET_SYNTAXES = Object.freeze([
  syntax('xml-nested-key', 'key', 'KEY', /(<(?:pre-shared-key|api-key|auth-key|secret|key)>\s*<key>)([^<]+)(<\/key>)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('xml-direct-key', 'key', 'KEY', /(<(?:pre-shared-key|api-key|auth-key)>)(?!\s*<key>)([^<]+)(<\/[^>]+>)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('xml-hash', 'hash', 'HASH', /(<(?:phash|password-hash|encrypted-secret)>)([^<]+)(<\/[^>]+>)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('xml-private-key', 'certificate', 'CERT', /(<(?:private-key|certificate-key|ssl-key|secret-key)>)([^<]+)(<\/[^>]+>)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('fortigate-enc-password', 'hash', 'HASH', /(set\s+(?:password|passwd)\s+)(ENC\s+\S+)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder),
  syntax('fortigate-quoted-secret', 'key', 'KEY', /(set\s+(?:secret|psksecret|auth-password|privacy-password)\s+)\"([^\"]+)\"/gi, 2,
    (groups, placeholder) => groups[1] + '\"' + placeholder + '\"'),
  syntax('fortigate-unquoted-secret', 'key', 'KEY', /(set\s+(?:secret|psksecret|auth-password|privacy-password)\s+)(?!ENC\s|\")(\S+)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder),
  syntax('snmp-community-cli', 'community', 'COMMUNITY', /((?:set\s+snmp\s+community|snmp-server\s+community|set\s+community)\s+)\"?([^\"\s]+)\"?/gi, 2,
    (groups, placeholder) => groups[1] + placeholder),
  syntax('aaa-secret-cli', 'key', 'KEY', /((?:radius-server|tacacs-server|tacplus-server|set\s+system\s+(?:radius-server|tacplus-server))\s+(?:host\s+)?\S+\s+(?:secret|key)\s+)\"?([^\"\s]+)\"?/gi, 2,
    (groups, placeholder) => groups[1] + '\"' + placeholder + '\"'),
  syntax('junos-psk', 'key', 'KEY', /(pre-shared-key\s+(?:ascii-text\s+)?)(?:\"([^\"]+)\"|(\S+))/gi, 2,
    (groups, placeholder) => groups[1] + '\"' + placeholder + '\"'),
  syntax('encrypted-password', 'hash', 'HASH', /((?:encrypted-password|enable\s+secret)\s+)\"?([^\"\s]+)\"?/gi, 2,
    (groups, placeholder) => groups[1] + '\"' + placeholder + '\"'),
  syntax('username-password', 'hash', 'HASH', /(username\s+\S+\s+(?:password|secret)\s+)\"?([^\"\s]+)\"?/gi, 2,
    (groups, placeholder) => groups[1] + placeholder),
  syntax('auth-privacy-password', 'key', 'KEY', /((?:authentication-password|privacy-password|authentication-key)\s+)\"?([^\"\s]+)\"?/gi, 2,
    (groups, placeholder) => groups[1] + '\"' + placeholder + '\"'),
  syntax('asa-isakmp-key', 'key', 'KEY', /(crypto\s+isakmp\s+key\s+)(\S+)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder),
  syntax('json-secret', 'key', 'KEY', /(\"(?:shared-secret|pre-shared-key|psksecret|radius-secret|tacacs-secret)\"\s*:\s*\")([^\"]+)(\")/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('json-password-hash', 'hash', 'HASH', /(\"(?:password|password-hash|phash|encrypted-password)\"\s*:\s*\")([^\"]+)(\")/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('sonicwall-secret', 'key', 'KEY', /((?:Shared Secret|Pre-Shared Key)\s*:\s*)(\S+)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder),
  syntax('sonicwall-password', 'hash', 'HASH', /(Password\s*:\s*)(\S+)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder),
  syntax('pem-private-key', 'certificate', 'CERT', /-----BEGIN\s+(?:(?:RSA|EC|DSA|ENCRYPTED|OPENSSH)\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:(?:RSA|EC|DSA|ENCRYPTED|OPENSSH)\s+)?PRIVATE\s+KEY-----/g, 0,
    (_groups, placeholder) => placeholder),
]);

function cloneRegex(regex) {
  return new RegExp(regex.source, regex.flags);
}

export function isSanitizedSecretValue(value) {
  return typeof value === 'string' && PLACEHOLDER_RE.test(value);
}

export function isSecretBearingKey(key) {
  return KEY_RE.test(normalizedKey(key));
}

export function findSecretsInText(text) {
  if (typeof text !== 'string') return [];
  const findings = [];
  for (const spec of SECRET_SYNTAXES) {
    const regex = cloneRegex(spec.regex);
    for (const match of text.matchAll(regex)) {
      const original = match[spec.valueGroup];
      if (!original || isSanitizedSecretValue(original.trim())) continue;
      findings.push({ category: spec.category, ruleId: spec.ruleId });
    }
  }
  return findings;
}

export function redactConfigSecrets(text) {
  if (typeof text !== 'string') throw new TypeError('configuration text must be a string');
  const counters = { HASH: 0, KEY: 0, COMMUNITY: 0, CERT: 0 };
  for (const match of text.matchAll(/SANITIZED_(HASH|KEY|COMMUNITY|CERT)_(\d+)/g)) {
    counters[match[1]] = Math.max(counters[match[1]], Number(match[2]) + 1);
  }
  const counts = { hash: 0, key: 0, community: 0, cert: 0 };
  const replacements = [];
  let output = text;
  for (const spec of SECRET_SYNTAXES) {
    output = output.replace(cloneRegex(spec.regex), (...args) => {
      const groups = args.slice(0, -2);
      const original = groups[spec.valueGroup]?.trim();
      if (!original || isSanitizedSecretValue(original)) return groups[0];
      const placeholder = 'SANITIZED_' + spec.placeholderKind + '_' + counters[spec.placeholderKind]++;
      replacements.push({ type: spec.category, placeholder, original });
      counts[spec.category === 'certificate' ? 'cert' : spec.category] += 1;
      return spec.render(groups, placeholder);
    });
  }
  return { text: output, replacements, counts };
}
```

Before GREEN, extend `CASES` and `SECRET_SYNTAXES` together for every form required by the design: PAN-OS direct PSK/API/auth/encrypted-secret/secret-key fields; FortiGate `passwd`, IPsec, TACACS, quoted/unquoted/`ENC` forms; ASA/FTD tunnel-group, IKEv1/IKEv2, SNMP, AAA, and certificate/private-key blocks; Junos encrypted PSKs, hierarchical syntax, AAA, SNMPv3, and private/certificate-key fields; Check Point and SonicWall SNMP, AAA, hash, and private/certificate fields; and generic RSA, EC, DSA, encrypted PKCS#8, unencrypted PKCS#8, and OpenSSH PEM blocks. Each row uses a unique `*-ORIGINAL` marker and must pass the same detection/redaction/idempotence assertions above. Do not mark Task 1 GREEN while any design-listed syntax lacks a positive row.

Keep registry entries mutually exclusive: `secret-key`, `private-key`, `certificate-key`, and `ssl-key` belong to the certificate/private-key entry, not the generic XML key entry. For optional alternations with multiple secret capture groups, normalize the match into one `original` before rendering rather than relying on an absent group. A whole-block PEM replacement records the whole matched block as `original`; the marker assertion therefore uses `toContain`.

- [ ] **Step 4: Integrate the registry into `sanitizeConfig`**

At the beginning of `sanitizeConfig` after input limits, call the registry:

```js
const secretResult = redactConfigSecrets(configText);
const replacements = [...secretResult.replacements];
const counter = {
  hash: secretResult.counts.hash,
  key: secretResult.counts.key,
  community: secretResult.counts.community,
  cert: secretResult.counts.cert,
  user: 0, ip: 0, host: 0, bgp: 0, device_hostname: 0, domain: 0,
  zone: 0, object: 0, private_ip: 0, ipv6: 0, email: 0, url: 0,
  description: 0, interface: 0,
};
let sanitized = secretResult.text;
```

Remove the superseded password/hash, PSK/API-key, SNMP-community, certificate/private-key, and plaintext-secret replacement blocks from `engine.js`. Do not retain two regex implementations.

- [ ] **Step 5: Run focused GREEN and existing sanitizer consumers**

Run:

```bash
npx vitest run tests/secret-detection.test.js tests/credential-security.test.js tests/conversion-security.test.js
node tests/llm-translate.test.js
```

Expected: all selected suites pass; every matrix original is absent after `sanitizeConfig`.

- [ ] **Step 6: Add the suite to required CI**

Add `tests/secret-detection.test.js` to the explicit Vitest command in `.github/workflows/ci.yml`.

- [ ] **Step 7: Commit Task 1**

```bash
git add public/utils/secret-detection.js public/utils/engine.js tests/secret-detection.test.js .github/workflows/ci.yml
git diff --cached --check
git commit -m "fix: expand firewall secret sanitization"
```

Expected: one commit containing only the shared registry, engine integration, tests, and CI inclusion.

---

### Task 2: Fail-Closed Project State Boundary

**Files:**
- Create: `public/utils/project-security.js`
- Create: `tests/project-security.test.js`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the complete state bag assembled by `useProject` and secret helpers from Task 1.
- Produces:
  - `ProjectSecurityError` with fixed `code` and fixed `message`.
  - `classifyProjectSecurity(stateBag): { mode, sanitizedEligible, reversibleAvailable, restorationAvailable }`.
  - `prepareSanitizedProjectState(stateBag): { state, originals }`.
  - `prepareUnsanitizedProjectState(stateBag): { state, restorationAvailable }`.
  - `assertSanitizedProjectSafe(project, originals): string` returning the sole final JSON serialization.
  - `boundedProjectStringify(project): string` for explicitly unsanitized plaintext output after safe-shape and byte-limit validation.
  - constants for modes and all resource limits.

- [ ] **Step 1: Write failing classification and recursive leak tests**

Create `tests/project-security.test.js`:

```js
import { describe, expect, it } from 'vitest';
import {
  ProjectSecurityError,
  assertSanitizedProjectSafe,
  classifyProjectSecurity,
  prepareSanitizedProjectState,
} from '../public/utils/project-security.js';

const table = original => [{
  type: 'key',
  placeholder: 'SANITIZED_KEY_0',
  original,
}];

const sanitizedState = {
  configText: 'set system login password SANITIZED_KEY_0',
  intermediateConfig: { metadata: { note: 'safe' } },
  isSanitized: true,
  sanitizationTable: table('TOP-LEVEL-ORIGINAL'),
  mergeMode: true,
  configSlots: [{
    configText: 'set snmp community SANITIZED_COMMUNITY_0',
    intermediateConfig: { metadata: {} },
    isSanitized: true,
    sanitizationTable: table('NESTED-ORIGINAL'),
  }],
};

describe('project security boundary', () => {
  it('classifies every populated source, including merge slots', () => {
    expect(classifyProjectSecurity(sanitizedState)).toMatchObject({
      mode: 'sanitized',
      sanitizedEligible: true,
      reversibleAvailable: true,
      restorationAvailable: true,
    });
    expect(classifyProjectSecurity({
      ...sanitizedState,
      configSlots: [{ ...sanitizedState.configSlots[0], isSanitized: false }],
    })).toMatchObject({
      mode: 'unsanitized',
      sanitizedEligible: false,
    });
    expect(classifyProjectSecurity({
      ...sanitizedState,
      greenfieldMode: true,
      isSanitized: false,
    }).sanitizedEligible).toBe(false);
  });

  it('removes all restoration tables without mutating live state', () => {
    const before = structuredClone(sanitizedState);
    const prepared = prepareSanitizedProjectState(sanitizedState);
    expect(prepared.originals).toEqual(['NESTED-ORIGINAL', 'TOP-LEVEL-ORIGINAL']);
    expect(JSON.stringify(prepared.state)).not.toContain('sanitizationTable');
    expect(sanitizedState).toEqual(before);
  });

  it.each([
    ['metadata', project => { project.state.intermediateConfig.metadata.note = 'TOP-LEVEL-ORIGINAL'; }],
    ['warning', project => { project.state.parseWarnings = [{ message: 'NESTED-ORIGINAL' }]; }],
    ['raw secret syntax', project => { project.state.future = 'set password \"RAW-SECRET\"'; }],
    ['structured secret', project => { project.state.future = { radius_secret: 'RAW-SECRET' }; }],
  ])('rejects a leak injected into %s', (_label, mutate) => {
    const prepared = prepareSanitizedProjectState(sanitizedState);
    const project = {
      fpic_version: 5,
      name: 'safe',
      savedAt: '2026-07-12T00:00:00.000Z',
      security: {
        schema: 1, mode: 'sanitized', containsOriginals: false,
        reversible: false, restorationAvailable: false,
      },
      state: prepared.state,
    };
    mutate(project);
    expect(() => assertSanitizedProjectSafe(project, prepared.originals))
      .toThrow(ProjectSecurityError);
  });
});
```

- [ ] **Step 2: Run focused RED**

Run:

```bash
npx vitest run tests/project-security.test.js
```

Expected: FAIL because `project-security.js` does not exist.

- [ ] **Step 3: Implement fixed errors, limits, and prototype-safe traversal**

Create `public/utils/project-security.js` with exact constants:

```js
import {
  findSecretsInText,
  isSanitizedSecretValue,
  isSecretBearingKey,
} from './secret-detection.js';

export const PROJECT_SECURITY_MODES = Object.freeze({
  SANITIZED: 'sanitized',
  REVERSIBLE: 'reversible-encrypted',
  UNSANITIZED: 'unsanitized',
  LEGACY: 'legacy-secret-bearing',
});
export const MAX_PROJECT_PLAINTEXT_BYTES = 48 * 1024 * 1024;
export const MAX_PROJECT_FILE_BYTES = 65 * 1024 * 1024;
export const MAX_PROJECT_DEPTH = 128;
export const MAX_PROJECT_NODES = 1_000_000;

const ERROR_MESSAGES = Object.freeze({
  unsafe_state: 'Project state contains an unsupported value.',
  invalid_restoration: 'Project restoration data is invalid.',
  unsanitized_source: 'Sanitized export requires every populated source to be sanitized.',
  original_leak: 'Sanitized export was blocked because an original value remains.',
  secret_leak: 'Sanitized export was blocked because secret-bearing content remains.',
  oversized_project: 'Project data exceeds the supported size limit.',
});

export class ProjectSecurityError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] || 'Project security validation failed.');
    this.name = 'ProjectSecurityError';
    this.code = Object.hasOwn(ERROR_MESSAGES, code) ? code : 'unsafe_state';
  }
}

function assertPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.getPrototypeOf(value) === Object.prototype;
}

function walk(value, visitor, path = [], state = { depth: 0, nodes: 0, seen: new WeakSet() }) {
  state.nodes += 1;
  if (state.nodes > MAX_PROJECT_NODES || state.depth > MAX_PROJECT_DEPTH) {
    throw new ProjectSecurityError('unsafe_state');
  }
  visitor(value, path);
  if (value === null || typeof value !== 'object') return;
  if (state.seen.has(value)) throw new ProjectSecurityError('unsafe_state');
  state.seen.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const descriptor of Object.values(descriptors)) {
    if (descriptor.get || descriptor.set) throw new ProjectSecurityError('unsafe_state');
  }
  const entries = Array.isArray(value)
    ? value.map((child, index) => [String(index), child])
    : Object.entries(value);
  state.depth += 1;
  for (const [key, child] of entries) {
    state.nodes += 1; // keys count toward the one-million-node budget
    if (state.nodes > MAX_PROJECT_NODES) throw new ProjectSecurityError('unsafe_state');
    if (['__proto__', 'constructor', 'prototype'].includes(key)) {
      throw new ProjectSecurityError('unsafe_state');
    }
    walk(child, visitor, [...path, key], state);
  }
  state.depth -= 1;
}
```

Before enumerating, reject holes in arrays, non-plain objects, functions, symbols, bigint, undefined values, non-finite numbers, and unsupported primitives. Count every container, primitive, and property key toward `MAX_PROJECT_NODES`, as required by the design. Do not invoke getters while validating or cloning.

- [ ] **Step 4: Implement classification, restoration validation, and non-mutating stripping**

Use explicit populated-source checks and deterministic original sorting:

```js
function isPopulatedSource(source) {
  if (!source || typeof source !== 'object') return false;
  const nonEmptyArray = value => Array.isArray(value) && value.length > 0;
  const nonEmptyObject = value => value && typeof value === 'object'
    && !Array.isArray(value) && Object.keys(value).length > 0;
  return Boolean(
    typeof source.configText === 'string' && source.configText.trim()
    || source.intermediateConfig !== null && source.intermediateConfig !== undefined
    || source.srxOutput !== null && source.srxOutput !== undefined
    || nonEmptyArray(source.srxTranslatedPolicies)
    || nonEmptyArray(source.ruleGroups)
    || nonEmptyObject(source.interfaceMappings)
    || source.greenfieldMode === true
    || source.greenfieldTemplate !== null && source.greenfieldTemplate !== undefined
  );
}

function validatedTable(value) {
  if (!Array.isArray(value)) throw new ProjectSecurityError('invalid_restoration');
  return value.map(entry => {
    if (!assertPlainObject(entry)
        || !Object.keys(entry).every(key => ['type', 'placeholder', 'original', 'restore'].includes(key))
        || typeof entry.type !== 'string'
        || typeof entry.placeholder !== 'string'
        || typeof entry.original !== 'string'
        || entry.original.length === 0
        || entry.restore !== undefined && typeof entry.restore !== 'boolean') {
      throw new ProjectSecurityError('invalid_restoration');
    }
    return entry;
  });
}

export function classifyProjectSecurity(stateBag) {
  walk(stateBag, () => {});
  if (stateBag === null || typeof stateBag !== 'object' || Array.isArray(stateBag)
      || stateBag.configSlots !== undefined && !Array.isArray(stateBag.configSlots)) {
    throw new ProjectSecurityError('unsafe_state');
  }
  const sources = [stateBag, ...(stateBag.configSlots || []).filter(isPopulatedSource)];
  const populated = sources.filter(isPopulatedSource);
  const sanitizedEligible = populated.length > 0
    && populated.every(source => source.isSanitized === true && source.greenfieldMode !== true);
  let restorationAvailable = false;
  walk(stateBag, (value, path) => {
    if (path.at(-1) === 'sanitizationTable' && value !== null) {
      restorationAvailable ||= validatedTable(value).length > 0;
    }
  });
  return Object.freeze({
    mode: sanitizedEligible ? PROJECT_SECURITY_MODES.SANITIZED : PROJECT_SECURITY_MODES.UNSANITIZED,
    sanitizedEligible,
    reversibleAvailable: sanitizedEligible && restorationAvailable,
    restorationAvailable,
  });
}
```

Implement `prepareSanitizedProjectState` using the same walker semantics, recursively omitting every `sanitizationTable` key and cloning every remaining value. Collect `original` values before omission, deduplicate exact duplicates, sort with the default code-unit `.sort()` order, and throw `unsanitized_source` when classification is not eligible.

Implement `prepareUnsanitizedProjectState` with the same safe-shape walker and clone rules but preserve validated restoration tables. Return the clone and the computed `restorationAvailable` flag. Implement `boundedProjectStringify` by safe-walking, serializing once, measuring UTF-8 bytes, and throwing `oversized_project` above 48 MiB.

Bound restoration entry fields before retaining or scanning them: `type` at 64 UTF-8 bytes, `placeholder` at 1,024 UTF-8 bytes, and `original` at 1 MiB. Reject an entry with `restore: true` when normalized `type` is `password`, `hash`, `key`, `community`, `certificate`, or `cert`; secret entries are never restorable.

- [ ] **Step 5: Implement structured and serialized leak gates**

`assertSanitizedProjectSafe` must:

```js
export function assertSanitizedProjectSafe(project, originals) {
  walk(project, (value, path) => {
    if (path.includes('sanitizationTable')) throw new ProjectSecurityError('original_leak');
    if (typeof value !== 'string') return;
    if (findSecretsInText(value).length > 0) throw new ProjectSecurityError('secret_leak');
    const key = path.at(-1) || '';
    if (isSecretBearingKey(key) && value && !isSanitizedSecretValue(value)) {
      throw new ProjectSecurityError('secret_leak');
    }
    if (originals.some(original => value.includes(original))) {
      throw new ProjectSecurityError('original_leak');
    }
  });
  const serialized = JSON.stringify(project, null, 2);
  if (new TextEncoder().encode(serialized).length > MAX_PROJECT_PLAINTEXT_BYTES) {
    throw new ProjectSecurityError('oversized_project');
  }
  for (const original of originals) {
    const escaped = JSON.stringify(original).slice(1, -1);
    if (serialized.includes(original) || serialized.includes(escaped)) {
      throw new ProjectSecurityError('original_leak');
    }
  }
  if (serialized.includes('\"sanitizationTable\"')) {
    throw new ProjectSecurityError('original_leak');
  }
  if (findSecretsInText(serialized).length > 0) {
    throw new ProjectSecurityError('secret_leak');
  }
  return serialized;
}
```

Add path-aware rules for SNMP `name` fields, AAA server objects, VPN/IKE objects, and certificate containers. Keep algorithm descriptor fields such as `auth_method` out of the secret-value path list.

- [ ] **Step 6: Add adversarial state-shape tests and run GREEN**

Extend `tests/project-security.test.js` with cycles, getters, sparse arrays, prototype keys, non-finite values, depth 129, and JSON-escaped originals containing newlines or quotes. Exercise the real node ceiling with `new Array(MAX_PROJECT_NODES).fill(null)` nested under a root object; the array, keys, and primitives exceed the limit. Also reject overlong restoration fields and `restore: true` on every secret type. Do not add test-only production methods or lower production limits for tests.

Run:

```bash
npx vitest run tests/project-security.test.js tests/secret-detection.test.js
```

Expected: all tests pass.

- [ ] **Step 7: Add the suite to CI and commit**

Add `tests/project-security.test.js` to the explicit CI Vitest list, then:

```bash
git add public/utils/project-security.js tests/project-security.test.js .github/workflows/ci.yml
git diff --cached --check
git commit -m "feat: add fail-closed project security boundary"
```

---

### Task 3: Authenticated Reversible Project Encryption

**Files:**
- Create: `public/utils/project-crypto.js`
- Create: `tests/project-crypto.test.js`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: strict `payloadSchema: 1` reversible payloads and Web Crypto.
- Produces:
  - `isProjectCryptoAvailable(cryptoImpl = globalThis.crypto): boolean`
  - `validateProjectPassphrase(passphrase): void`
  - `encryptReversiblePayload(payload, passphrase, cryptoImpl): Promise<object>`
  - `decryptReversibleEnvelope(envelope, passphrase, cryptoImpl): Promise<object>`
  - `inspectEncryptedEnvelope(envelope): Readonly<object>`
  - `ProjectCryptoError` with fixed non-reflective messages.

- [ ] **Step 1: Write real Web Crypto RED tests**

Create `tests/project-crypto.test.js` using `globalThis.crypto`:

```js
import { describe, expect, it } from 'vitest';
import {
  ProjectCryptoError,
  decryptReversibleEnvelope,
  encryptReversiblePayload,
  inspectEncryptedEnvelope,
  isProjectCryptoAvailable,
  validateProjectPassphrase,
} from '../public/utils/project-crypto.js';

const payload = {
  payloadSchema: 1,
  name: 'UNIQUE-PROJECT-NAME',
  savedAt: '2026-07-12T00:00:00.000Z',
  sourceMode: 'sanitized',
  state: {
    configText: 'set system login password SANITIZED_KEY_0',
    sanitizationTable: [{
      type: 'key', placeholder: 'SANITIZED_KEY_0', original: 'UNIQUE-ORIGINAL-SECRET',
    }],
  },
};
const passphrase = 'correct horse battery staple';

describe('reversible project crypto', () => {
  it('round-trips a strict payload without exposing plaintext', async () => {
    expect(isProjectCryptoAvailable()).toBe(true);
    const envelope = await encryptReversiblePayload(payload, passphrase);
    const serialized = JSON.stringify(envelope);
    expect(Object.keys(envelope)).toEqual(['fpic_version', 'security', 'ciphertext']);
    expect(serialized).not.toContain('UNIQUE-PROJECT-NAME');
    expect(serialized).not.toContain('UNIQUE-ORIGINAL-SECRET');
    await expect(decryptReversibleEnvelope(envelope, passphrase)).resolves.toEqual(payload);
  });

  it('uses fresh salt, nonce, and ciphertext', async () => {
    const first = await encryptReversiblePayload(payload, passphrase);
    const second = await encryptReversiblePayload(payload, passphrase);
    expect(first.security.salt).not.toBe(second.security.salt);
    expect(first.security.nonce).not.toBe(second.security.nonce);
    expect(first.ciphertext).not.toBe(second.ciphertext);
  });

  it.each(['wrong passphrase value', 'another wrong value'])('uses one error for wrong passphrase', async wrong => {
    const envelope = await encryptReversiblePayload(payload, passphrase);
    await expect(decryptReversibleEnvelope(envelope, wrong)).rejects.toMatchObject({
      name: 'ProjectCryptoError',
      code: 'decryption_failed',
      message: 'Encrypted project could not be opened.',
    });
  });

  it.each(['ciphertext', 'nonce', 'salt', 'iterations'])('rejects tampered %s', async field => {
    const envelope = structuredClone(await encryptReversiblePayload(payload, passphrase));
    if (field === 'ciphertext') {
      envelope.ciphertext = (envelope.ciphertext[0] === 'A' ? 'B' : 'A')
        + envelope.ciphertext.slice(1);
    }
    else if (field === 'iterations') envelope.security.iterations += 1;
    else {
      envelope.security[field] = (envelope.security[field][0] === 'A' ? 'B' : 'A')
        + envelope.security[field].slice(1);
    }
    await expect(decryptReversibleEnvelope(envelope, passphrase)).rejects.toMatchObject({
      name: 'ProjectCryptoError',
      code: 'decryption_failed',
      message: 'Encrypted project could not be opened.',
    });
  });

  it('validates passphrase bounds without returning the value', () => {
    expect(() => validateProjectPassphrase('short')).toThrow(ProjectCryptoError);
    expect(() => validateProjectPassphrase('sixteen-characters')).not.toThrow();
  });
});
```

- [ ] **Step 2: Run RED**

Run:

```bash
npx vitest run tests/project-crypto.test.js
```

Expected: FAIL because `project-crypto.js` does not exist.

- [ ] **Step 3: Implement strict encoding and schema validation**

Create `public/utils/project-crypto.js` with:

```js
import {
  MAX_PROJECT_FILE_BYTES,
  MAX_PROJECT_PLAINTEXT_BYTES,
} from './project-security.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const ITERATIONS = 600_000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;

const CRYPTO_MESSAGES = Object.freeze({
  invalid_passphrase: 'Passphrase must contain at least 16 characters.',
  unsupported_crypto: 'Encrypted project export is unavailable in this browser.',
  invalid_envelope: 'Encrypted project file is invalid.',
  decryption_failed: 'Encrypted project could not be opened.',
});

export class ProjectCryptoError extends Error {
  constructor(code) {
    super(CRYPTO_MESSAGES[code] || CRYPTO_MESSAGES.invalid_envelope);
    this.name = 'ProjectCryptoError';
    this.code = Object.hasOwn(CRYPTO_MESSAGES, code) ? code : 'invalid_envelope';
  }
}

export function isProjectCryptoAvailable(cryptoImpl = globalThis.crypto) {
  return Boolean(cryptoImpl?.getRandomValues && cryptoImpl?.subtle);
}

export function validateProjectPassphrase(passphrase) {
  if (typeof passphrase !== 'string'
      || Array.from(passphrase).length < 16
      || encoder.encode(passphrase).length > 1024) {
    throw new ProjectCryptoError('invalid_passphrase');
  }
}
```

Implement canonical base64 using byte loops in bounded chunks, reject whitespace and non-canonical encodings, and strictly enumerate outer and security keys before key derivation.

- [ ] **Step 4: Implement AAD, PBKDF2, AES-GCM, and payload validation**

Use exact algorithms:

```js
async function deriveKey(passphrase, salt, cryptoImpl) {
  const material = await cryptoImpl.subtle.importKey(
    'raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey'],
  );
  return cryptoImpl.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function aadObject(security) {
  return {
    fpic_version: 5,
    security: {
      schema: 1,
      mode: 'reversible-encrypted',
      containsOriginals: true,
      reversible: true,
      cipher: 'AES-256-GCM',
      tagBits: 128,
      kdf: 'PBKDF2-HMAC-SHA-256',
      iterations: ITERATIONS,
      salt: security.salt,
      nonce: security.nonce,
      aadVersion: 1,
    },
  };
}

function aadBytes(security) {
  return encoder.encode(JSON.stringify(aadObject(security)));
}
```

Encrypt with `{ name: 'AES-GCM', iv: nonce, additionalData: aadBytes(security), tagLength: 128 }`. Before encryption, validate the strict payload keys, `payloadSchema === 1`, `sourceMode === 'sanitized'`, ISO timestamp, non-empty bounded name, and plaintext byte limit.

`inspectEncryptedEnvelope` reports malformed shape, unknown fields, non-canonical base64, wrong identifiers, and impossible lengths as `invalid_envelope`. `decryptReversibleEnvelope` must normalize any post-recognition authentication/tamper failure—including a changed but syntactically valid salt, nonce, iteration value, AAD field, truncated ciphertext, ciphertext, UTF-8, JSON, or inner payload—to `new ProjectCryptoError('decryption_failed')` without retaining `cause`. Enforce the schema-1 iteration value before PBKDF2 so a tampered work factor cannot cause denial of service. After decryption, fatal-decode UTF-8, enforce the plaintext size, safe-parse JSON, strictly validate payload keys, and return a fresh validated object.

- [ ] **Step 5: Add malformed envelope and resource-limit tests**

Test unknown fields, non-canonical base64, wrong salt/nonce lengths, wrong identifiers, absent crypto, invalid UTF-8 ciphertext produced with the correct key, invalid inner JSON, invalid payload schema, >65 MiB input metadata rejection before PBKDF2, and exact iteration enforcement.

Run:

```bash
npx vitest run tests/project-crypto.test.js tests/project-security.test.js
```

Expected: all tests pass.

- [ ] **Step 6: Add CI coverage and commit**

Add `tests/project-crypto.test.js` to CI, then:

```bash
git add public/utils/project-crypto.js tests/project-crypto.test.js .github/workflows/ci.yml
git diff --cached --check
git commit -m "feat: encrypt reversible project backups"
```

---

### Task 4: Version 5 Project Export, Import, and Legacy Migration

**Files:**
- Modify: `public/utils/project-io.js`
- Modify: `tests/project-io.test.js`
- Modify: `public/utils/project-security.js`
- Modify: `tests/project-security.test.js`

**Interfaces:**
- Consumes: Task 2 state preparation and Task 3 encryption.
- Produces:
  - `buildProjectCore(stateBag, name, security): object`
  - `validateProjectStateCore(project): {project, warnings}` and the existing legacy conversion-output migration in `project-io.js`.
  - `serializeProjectExport(stateBag, name, options): Promise<{serialized, filename, security}>` from `project-security.js`.
  - `inspectProjectImport(serialized): { kind, security, envelope, warnings }` from `project-security.js`.
  - `openProjectImport(serialized, {passphrase}): Promise<{project, security, warnings, requiresConfirmation}>` from `project-security.js`.
  - `validateProjectFile` remains in `project-io.js` as a compatibility entry for already-parsed plaintext/legacy projects and performs only core state/output validation, never download decisions.

- [ ] **Step 1: Replace version 4 expectations with failing v5 mode tests**

In `tests/project-io.test.js`:

```js
it('writes an irreversible sanitized v5 file by default', async () => {
  const state = {
    ...baseState,
    isSanitized: true,
    sanitizationTable: [{
      type: 'device_hostname',
      placeholder: 'sanitized-fw',
      original: 'UNIQUE-ORIGINAL-HOST',
    }],
  };
  const result = await serializeProjectExport(state, 'safe project', { mode: 'sanitized' });
  const parsed = JSON.parse(result.serialized);
  expect(parsed).toMatchObject({
    fpic_version: 5,
    security: {
      mode: 'sanitized',
      containsOriginals: false,
      reversible: false,
      restorationAvailable: false,
    },
  });
  expect(result.filename).toBe('safe-project.sanitized.fpic.json');
  expect(result.serialized).not.toContain('UNIQUE-ORIGINAL-HOST');
  expect(result.serialized).not.toContain('sanitizationTable');
});

it('requires exact confirmation for unsanitized v5 export', async () => {
  await expect(serializeProjectExport(baseState, 'unsafe', {
    mode: 'unsanitized',
    confirmation: '',
  })).rejects.toMatchObject({ code: 'invalid_confirmation' });
  await expect(serializeProjectExport(baseState, 'unsafe', {
    mode: 'unsanitized',
    confirmation: 'EXPORT UNSANITIZED',
  })).resolves.toMatchObject({
    filename: 'unsafe.unsanitized.fpic.json',
  });
});

it('enforces reversible passphrase confirmation at the boundary', async () => {
  const state = {
    ...baseState,
    isSanitized: true,
    sanitizationTable: [{
      type: 'device_hostname', placeholder: 'sanitized-fw', original: 'ORIGINAL-FW',
    }],
  };
  await expect(serializeProjectExport(state, 'backup', {
    mode: 'reversible-encrypted',
    passphrase: 'correct horse battery staple',
    confirmationPassphrase: 'correct horse battery stapler',
    acknowledgement: true,
  })).rejects.toMatchObject({ code: 'invalid_confirmation' });
});

it('imports sanitized files with no restoration capability', async () => {
  const exported = await serializeProjectExport({
    ...baseState,
    isSanitized: true,
    sanitizationTable: [{
      type: 'key', placeholder: 'SANITIZED_KEY_0', original: 'IMPORT-ORIGINAL',
    }],
  }, 'safe', { mode: 'sanitized' });
  const opened = await openProjectImport(exported.serialized, {});
  expect(opened.security.mode).toBe('sanitized');
  expect(opened.project.state.sanitizationTable).toBeNull();
  expect(JSON.stringify(opened.project)).not.toContain('IMPORT-ORIGINAL');
});
```

Add cases for encrypted export round-trip, plaintext unsanitized metadata, mixed merge slots, greenfield classification, malformed v5 metadata, version 1–4 sanitized-with-table classification as legacy secret-bearing, legacy sanitized-without-table rescan, and mapped conversion-output migration.

- [ ] **Step 2: Run RED**

Run:

```bash
npx vitest run tests/project-io.test.js tests/project-security.test.js
```

Expected: FAIL because exports are synchronous v4 payloads and security modes do not exist.

- [ ] **Step 3: Split canonical core construction from security decisions**

In `project-io.js`, export `CURRENT_VERSION = 5` and create:

```js
export function buildProjectCore(stateBag, projectName, security) {
  const state = {};
  for (const key of STATE_KEYS) state[key] = stateBag[key] ?? STATE_DEFAULTS[key];
  if (state.srxOutput !== null) {
    state.srxOutput = assertConversionOutput(state.srxOutput);
    state.outputFormat = state.srxOutput.format;
  }
  return {
    fpic_version: CURRENT_VERSION,
    name: projectName,
    savedAt: new Date().toISOString(),
    security,
    state,
  };
}
```

Add `projectSecurityMode: 'unsanitized'` to ConfigContext/`STATE_KEYS` only when Task 6 wires loaded state; do not place passphrases or encrypted bytes in project state.

- [ ] **Step 4: Implement export orchestration in `project-security.js`**

Define the exact metadata, reversible payload, and filename helpers before orchestration:

```js
const SANITIZED_METADATA = Object.freeze({
  schema: 1,
  mode: 'sanitized',
  containsOriginals: false,
  reversible: false,
  restorationAvailable: false,
});

function unsanitizedMetadata(restorationAvailable) {
  return Object.freeze({
    schema: 1,
    mode: 'unsanitized',
    containsOriginals: true,
    reversible: false,
    restorationAvailable: restorationAvailable === true,
  });
}

function buildReversiblePayload(stateBag, name) {
  const prepared = prepareUnsanitizedProjectState(stateBag);
  return {
    payloadSchema: 1,
    name,
    savedAt: new Date().toISOString(),
    sourceMode: 'sanitized',
    state: { ...prepared.state, projectSecurityMode: 'reversible-encrypted' },
  };
}

function projectFilename(name, mode) {
  const base = String(name).replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^[-_.]+|[-_.]+$/g, '').slice(0, 100) || 'project';
  const suffix = mode === 'sanitized'
    ? 'sanitized.fpic.json'
    : mode === 'reversible'
      ? 'reversible.fpic.enc.json'
      : 'unsanitized.fpic.json';
  return base + '.' + suffix;
}
```

`serializeProjectExport` selects exact behavior and overwrites display-only mode state from the selected validated mode:

```js
export async function serializeProjectExport(stateBag, name, options = {}) {
  const classification = classifyProjectSecurity(stateBag);
  if (options.mode === PROJECT_SECURITY_MODES.SANITIZED) {
    const prepared = prepareSanitizedProjectState(stateBag);
    const project = buildProjectCore(
      { ...prepared.state, projectSecurityMode: 'sanitized' },
      name,
      SANITIZED_METADATA,
    );
    return {
      serialized: assertSanitizedProjectSafe(project, prepared.originals),
      filename: projectFilename(name, 'sanitized'),
      security: project.security,
    };
  }
  if (options.mode === PROJECT_SECURITY_MODES.REVERSIBLE) {
    if (!classification.reversibleAvailable) throw new ProjectSecurityError('invalid_restoration');
    if (options.acknowledgement !== true
        || options.passphrase !== options.confirmationPassphrase) {
      throw new ProjectSecurityError('invalid_confirmation');
    }
    const payload = buildReversiblePayload(stateBag, name);
    const envelope = await encryptReversiblePayload(payload, options.passphrase);
    return {
      serialized: JSON.stringify(envelope, null, 2),
      filename: projectFilename(name, 'reversible'),
      security: envelope.security,
    };
  }
  if (options.mode === PROJECT_SECURITY_MODES.UNSANITIZED) {
    if (options.confirmation !== 'EXPORT UNSANITIZED') {
      throw new ProjectSecurityError('invalid_confirmation');
    }
    const project = buildProjectCore(
      {
        ...prepareUnsanitizedProjectState(stateBag).state,
        projectSecurityMode: 'unsanitized',
      },
      name,
      unsanitizedMetadata(classification.restorationAvailable),
    );
    return {
      serialized: boundedProjectStringify(project),
      filename: projectFilename(name, 'unsanitized'),
      security: project.security,
    };
  }
  throw new ProjectSecurityError('unsupported_mode');
}
```

Add fixed non-reflective messages for `invalid_confirmation`, `unsupported_mode`, `unsupported_version`, and `invalid_project`. Extend the Task 4 tests so a reversible export without `acknowledgement: true`, with absent confirmation, or with a mismatch fails before encryption. The modal is defense in depth; the project-security API is the authoritative confirmation gate.

- [ ] **Step 5: Implement strict import inspection and transactional migration**

`inspectProjectImport` checks byte limits before parsing and returns only safe metadata. `openProjectImport` validates/decrypts before calling migration. Never dispatch from these functions.

For a version 5 sanitized plaintext import, strictly validate the exact outer and security keys, recursively confirm that no `sanitizationTable` key exists, require `classifyProjectSecurity(project.state).sanitizedEligible === true`, run the structured/raw secret scan across the complete state, serialize through `assertSanitizedProjectSafe(project, [])`, and then normalize every application-expected restoration field to `null` in the returned in-memory state. Do not trust the metadata claim alone.

For a reversible envelope, decrypt to the strict payload, construct an internal canonical core from its `name`, `savedAt`, and `state`, and run `validateProjectStateCore` plus conversion-output migration before returning it. Preserve the externally authenticated mode as `reversible-encrypted`; never reinterpret decrypted restoration-bearing state as a plaintext v5 envelope. Return `requiresConfirmation: true` for reversible, unsanitized, and legacy secret-bearing imports and `false` only for sanitized imports.

For legacy migration, calculate:

```js
function classifyLegacyProject(project) {
  const hasRestoration = containsNonEmptyRestorationTable(project.state);
  if (project.state?.isSanitized === true && hasRestoration) {
    return { mode: 'legacy-secret-bearing', requiresConfirmation: true };
  }
  if (project.state?.isSanitized === true) {
    assertLegacySanitizedStateSafe(project.state);
    return { mode: 'sanitized', requiresConfirmation: false };
  }
  return { mode: 'unsanitized', requiresConfirmation: true };
}
```

Migrate ordinary state/defaults and canonical conversion output exactly as current v1–v4 logic does. A sanitized import recursively writes `sanitizationTable: null` wherever the application expects the key.

- [ ] **Step 6: Run GREEN and compatibility suites**

Run:

```bash
npx vitest run tests/project-io.test.js tests/project-security.test.js tests/project-crypto.test.js tests/conversion-output.test.js tests/conversion-consumers.test.js
```

Expected: all selected suites pass; legacy output behavior remains intact.

- [ ] **Step 7: Commit Task 4**

```bash
git add public/utils/project-io.js public/utils/project-security.js tests/project-io.test.js tests/project-security.test.js
git diff --cached --check
git commit -m "feat: add secure version 5 project formats"
```

---

### Task 5: Transactional Hook and Download Orchestration

**Files:**
- Modify: `public/hooks/useProject.js`
- Create: `tests/project-workflow.test.js`
- Modify: `public/contexts/UIContext.jsx`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `serializeProjectExport`, `inspectProjectImport`, and `openProjectImport` from Task 4.
- Produces from `useProject`:
  - `getExportDescriptor(): classification`
  - `handleExportProject({name, mode, confirmation, passphrase, confirmationPassphrase, acknowledgement}): Promise<void>`
  - `handleLoadProjectFile(event): void`
  - `confirmPendingImport({passphrase, acknowledgement}): Promise<void>`
  - `applyLoadedProject(project, security): void`
  - `cancelPendingImport(): void`
- Passphrases are callback arguments only; they never enter contexts, refs, storage, logs, or returned descriptors.

- [ ] **Step 1: Extract and test pure state assembly/download helpers**

Export pure helpers from `useProject.js`:

```js
export function assembleProjectStateBag(configState, conversionState, uiState, mergeState) {
  return {
    configText: configState.configText,
    intermediateConfig: configState.intermediateConfig,
    sourceVendor: configState.sourceVendor,
    sourceModel: configState.sourceModel,
    targetModel: configState.targetModel,
    srxLicense: configState.srxLicense,
    portProfile: configState.portProfile,
    siteName: configState.siteName,
    siteGroup: configState.siteGroup,
    interfaceMappings: configState.interfaceMappings,
    isSanitized: configState.isSanitized,
    sanitizationTable: configState.sanitizationTable,
    parseWarnings: configState.parseWarnings,
    parseStats: configState.parseStats,
    warningStatuses: configState.warningStatuses,
    srxTranslatedPolicies: configState.srxTranslatedPolicies,
    ruleGroups: configState.ruleGroups,
    sectionAcceptance: configState.sectionAcceptance,
    greenfieldMode: configState.greenfieldMode,
    greenfieldTemplate: configState.greenfieldTemplate,
    srxOutput: conversionState.srxOutput,
    convertWarnings: conversionState.convertWarnings,
    conversionSummary: conversionState.conversionSummary,
    outputFormat: conversionState.outputFormat,
    targetContext: conversionState.targetContext,
    editTab: uiState.editTab,
    platformView: uiState.platformView,
    bottomTab: uiState.bottomTab,
    mergeMode: mergeState.mergeMode,
    configSlots: mergeState.configSlots,
    activeSlotIndex: mergeState.activeSlotIndex,
    crossLsLinks: mergeState.crossLsLinks,
  };
}
```

In `tests/project-workflow.test.js`, prove nested merge tables are included in the boundary input, and test `downloadValidatedProject` with fake `URL` and `document` objects so only a pre-serialized result can create a Blob and click.

- [ ] **Step 2: Run workflow RED**

Run:

```bash
npx vitest run tests/project-workflow.test.js
```

Expected: FAIL because the helpers and secure workflow do not exist.

- [ ] **Step 3: Replace direct serialization with async secure export**

`handleExportProject` must:

```js
const handleExportProject = useCallback(async request => {
  uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Preparing project export...' });
  uiDispatch({ type: 'CLEAR_ERROR' });
  try {
    const stateBag = assembleProjectStateBag(
      configState, conversionState, uiState, mergeState,
    );
    const result = await serializeProjectExport(stateBag, request.name, request);
    downloadValidatedProject(result);
    uiDispatch({ type: 'HIDE_MODAL', name: 'saveModal' });
  } catch (error) {
    uiDispatch({
      type: 'SET_FIELD',
      field: 'error',
      value: projectSecurityMessage(error),
    });
  } finally {
    uiDispatch({ type: 'SET_LOADING', isLoading: false });
  }
}, [configState, conversionState, uiState, mergeState, uiDispatch]);
```

`projectSecurityMessage` maps only recognized local error codes. It never appends `error.message` for unknown errors.

- [ ] **Step 4: Make import inspection and application transactional**

Reject `file.size > MAX_PROJECT_FILE_BYTES` before calling `FileReader.readAsText`. Store pending file text in a hook-local ref and only safe envelope metadata in `ui.showProjectSecurityImport`. For plaintext sanitized projects, still show the ordinary replace-current-work confirmation after validation. For encrypted, unsanitized, and legacy secret-bearing files, show the security import modal first.

`confirmPendingImport({passphrase, acknowledgement})` rejects unless `acknowledgement === true` for reversible, unsanitized, and legacy secret-bearing descriptors, opens encrypted files with the callback passphrase, clears the passphrase by returning from the callback, places the validated project in the existing load-confirm modal, and clears the pending ref. On any error, keep application contexts unchanged. Clear the pending file ref on success, cancel, reset, replacement by another file, terminal validation failure, and hook unmount.

- [ ] **Step 5: Add modal state and reset hygiene**

Add `showProjectSecurityImport: null` to UI state and `projectSecurityImport` to `MODAL_KEYS`. Reset/hide it in workspace reset and successful load. Do not put file bytes or passphrases in UIContext.

- [ ] **Step 6: Run GREEN and existing consumers**

Run:

```bash
npx vitest run tests/project-workflow.test.js tests/project-io.test.js tests/project-security.test.js tests/conversion-consumers.test.js
```

Expected: all pass; tests prove no Blob/click occurs on boundary failure and no dispatch occurs before import confirmation.

- [ ] **Step 7: Add CI coverage and commit**

Add `tests/project-workflow.test.js` to CI, then:

```bash
git add public/hooks/useProject.js public/contexts/UIContext.jsx tests/project-workflow.test.js .github/workflows/ci.yml
git diff --cached --check
git commit -m "fix: route project files through security boundary"
```

---

### Task 6: Explicit Export and Import Security UI

**Files:**
- Modify: `public/components/SaveProjectModal.jsx`
- Create: `public/components/ProjectSecurityImportModal.jsx`
- Modify: `public/app.jsx`
- Modify: `public/contexts/ConfigContext.jsx`
- Modify: `public/utils/project-io.js`
- Modify: `public/styles/main.css`
- Create: `tests/project-security-ui.test.jsx`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: export descriptor and callbacks from Task 5.
- Produces:
  - `SaveProjectModal({defaultName, descriptor, cryptoAvailable, onExport, onSanitizeFirst, onClose})`.
  - `ProjectSecurityImportModal({descriptor, onConfirm, onClose})`.
  - pure exported `deriveProjectExportFormState(input)` and `deriveProjectImportFormState(input)` for node-environment tests; import submit is disabled for dangerous modes until acknowledgement is checked and, for encrypted mode, a non-empty passphrase is present.
- Config state gains `projectSecurityMode` with reset default `unsanitized` and project-load values from validated metadata.

- [ ] **Step 1: Write failing pure view-model and server-render tests**

Create `tests/project-security-ui.test.jsx` using `react-dom/server`:

```jsx
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import SaveProjectModal, {
  deriveProjectExportFormState,
} from '../public/components/SaveProjectModal.jsx';
import ProjectSecurityImportModal from '../public/components/ProjectSecurityImportModal.jsx';

describe('project security UI', () => {
  it('defaults eligible workspaces to irreversible sanitized export', () => {
    const state = deriveProjectExportFormState({
      descriptor: { sanitizedEligible: true, reversibleAvailable: true },
      cryptoAvailable: true,
      mode: 'sanitized',
      name: 'branch',
      passphrase: '',
      confirmationPassphrase: '',
      acknowledgement: false,
      unsanitizedConfirmation: '',
    });
    expect(state.canSubmit).toBe(true);
    expect(state.filenameSuffix).toBe('.sanitized.fpic.json');
  });

  it('requires passphrase confirmation and no-recovery acknowledgement', () => {
    const base = {
      descriptor: { sanitizedEligible: true, reversibleAvailable: true },
      cryptoAvailable: true,
      mode: 'reversible-encrypted',
      name: 'branch',
      passphrase: 'correct horse battery staple',
      confirmationPassphrase: 'correct horse battery staple',
      acknowledgement: false,
      unsanitizedConfirmation: '',
    };
    expect(deriveProjectExportFormState(base).canSubmit).toBe(false);
    expect(deriveProjectExportFormState({ ...base, acknowledgement: true }).canSubmit).toBe(true);
  });

  it('requires typed confirmation for unsanitized export', () => {
    const state = deriveProjectExportFormState({
      descriptor: { sanitizedEligible: false, reversibleAvailable: false },
      cryptoAvailable: true,
      mode: 'unsanitized',
      name: 'branch',
      passphrase: '',
      confirmationPassphrase: '',
      acknowledgement: false,
      unsanitizedConfirmation: 'EXPORT UNSANITIZED',
    });
    expect(state.canSubmit).toBe(true);
  });

  it('renders unambiguous export and import warnings', () => {
    const exportHtml = renderToStaticMarkup(
      <SaveProjectModal
        defaultName="branch"
        descriptor={{ sanitizedEligible: false, reversibleAvailable: false }}
        cryptoAvailable
        onExport={() => {}}
        onSanitizeFirst={() => {}}
        onClose={() => {}}
      />,
    );
    const importHtml = renderToStaticMarkup(
      <ProjectSecurityImportModal
        descriptor={{ mode: 'legacy-secret-bearing' }}
        onConfirm={() => {}}
        onClose={() => {}}
      />,
    );
    expect(exportHtml).toContain('contains sensitive data');
    expect(exportHtml).toContain('EXPORT UNSANITIZED');
    expect(importHtml).toContain('legacy');
    expect(importHtml).not.toContain('safe to share');
  });
});
```

- [ ] **Step 2: Run UI RED**

Run:

```bash
npx vitest run tests/project-security-ui.test.jsx
```

Expected: FAIL because the new props, view model, and import modal do not exist.

- [ ] **Step 3: Implement the export modal state machine**

`deriveProjectExportFormState` must force allowed modes from the descriptor rather than trusting caller state:

```js
export function deriveProjectExportFormState(input) {
  const allowedModes = input.descriptor.sanitizedEligible
    ? [
      'sanitized',
      ...(input.descriptor.reversibleAvailable && input.cryptoAvailable
        ? ['reversible-encrypted'] : []),
    ]
    : ['unsanitized'];
  const mode = allowedModes.includes(input.mode) ? input.mode : allowedModes[0];
  const validName = input.name.trim().length > 0;
  const reversibleReady = Array.from(input.passphrase).length >= 16
    && new TextEncoder().encode(input.passphrase).length <= 1024
    && input.passphrase === input.confirmationPassphrase
    && input.acknowledgement === true;
  const unsanitizedReady = input.unsanitizedConfirmation === 'EXPORT UNSANITIZED';
  return {
    allowedModes,
    mode,
    canSubmit: validName && (
      mode === 'sanitized'
      || mode === 'reversible-encrypted' && reversibleReady
      || mode === 'unsanitized' && unsanitizedReady
    ),
    filenameSuffix: mode === 'sanitized'
      ? '.sanitized.fpic.json'
      : mode === 'reversible-encrypted'
        ? '.reversible.fpic.enc.json'
        : '.unsanitized.fpic.json',
  };
}
```

The modal owns passphrase fields only while mounted. After awaiting `onExport`, overwrite both passphrase state variables with empty strings in `finally` before closing or showing another state.

Call `onExport` with exactly `{ name, mode, passphrase, confirmationPassphrase, acknowledgement, confirmation: unsanitizedConfirmation }`; never infer acknowledgement from the presence of a passphrase. This duplicates the project-security boundary checks deliberately and cannot replace them.

- [ ] **Step 4: Implement import warning/passphrase modal and app wiring**

The import modal shows:

- sanitized: irreversible and no restoration;
- reversible-encrypted: passphrase field plus an explicit acknowledgement of the encrypted-file warning and no-recovery condition;
- unsanitized: explicit sensitive-data confirmation;
- legacy-secret-bearing: plaintext restoration-table warning.

Lazy-load it in `app.jsx`, wire `ui.showProjectSecurityImport`, pass `project.confirmPendingImport`, and call `project.cancelPendingImport` on close. The modal calls `onConfirm` with exactly `{ passphrase, acknowledgement }`, and clears its passphrase state in `finally` and on unmount.

Pass `project.getExportDescriptor()` and `isProjectCryptoAvailable()` into `SaveProjectModal`. `onSanitizeFirst` closes the modal and selects the import/edit workflow without claiming the mixed workspace was sanitized.

- [ ] **Step 5: Persist safe classification, never credentials**

Add `projectSecurityMode` to ConfigContext initial state and project state defaults. `applyLoadedProject` sets it from validated import metadata. Export does not trust this display field for classification; it recomputes from actual sources.

- [ ] **Step 6: Style mode cards and run GREEN**

Add scoped `.project-security-*` classes with existing color variables. Warning mode uses `--warning`/`--error`; sanitized uses `--success`; encrypted uses `--info`. Do not rely on color alone: include visible mode names and warning text.

Run:

```bash
npx vitest run tests/project-security-ui.test.jsx tests/project-workflow.test.js tests/project-io.test.js tests/context-reducers.test.js
npm run build
```

Expected: all tests and build pass.

- [ ] **Step 7: Add CI coverage and commit**

Add `tests/project-security-ui.test.jsx` to CI, then:

```bash
git add public/components/SaveProjectModal.jsx public/components/ProjectSecurityImportModal.jsx public/app.jsx public/contexts/ConfigContext.jsx public/utils/project-io.js public/styles/main.css tests/project-security-ui.test.jsx .github/workflows/ci.yml
git diff --cached --check
git commit -m "feat: distinguish secure project export modes"
```

---

### Task 7: Permanent Enforcement and Acceptance Hardening

**Files:**
- Create: `tests/project-security-enforcement.test.js`
- Modify: `tests/project-security.test.js`
- Modify: `tests/project-io.test.js`
- Modify: `tests/secret-detection.test.js`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: completed production boundary from Tasks 1–6.
- Produces: permanent static and randomized gates that fail when a future project path bypasses secure serialization or when a required issue criterion lacks behavior coverage.

- [ ] **Step 1: Write the failing static boundary test**

Create `tests/project-security-enforcement.test.js`:

```js
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const SERIALIZATION_APPROVED = new Set([
  'public/utils/project-security.js',
  'public/utils/project-crypto.js',
]);
const DOWNLOAD_APPROVED = new Set([
  'public/hooks/useProject.js',
]);
const CANDIDATES = [
  'public/hooks/useProject.js',
  'public/utils/project-io.js',
  'public/utils/project-security.js',
  'public/utils/project-crypto.js',
  'public/components/SaveProjectModal.jsx',
  'public/app.jsx',
];

describe('project export security enforcement', () => {
  it('allows project serialization and Blob download only at approved boundaries', () => {
    const violations = [];
    for (const relative of CANDIDATES) {
      const source = readFileSync(resolve(ROOT, relative), 'utf8');
      if (!SERIALIZATION_APPROVED.has(relative)
          && /JSON\.stringify\([^)]*(?:project|stateBag)/si.test(source)) {
        violations.push(relative + ': project serialization');
      }
      if (!DOWNLOAD_APPROVED.has(relative) && /new\s+Blob\s*\(.*fpic/si.test(source)) {
        violations.push(relative + ': project download');
      }
    }
    expect(violations).toEqual([]);
  });

  it('does not expose plaintext reversible project mode', () => {
    for (const relative of CANDIDATES) {
      const source = readFileSync(resolve(ROOT, relative), 'utf8');
      expect(source).not.toMatch(/mode\s*:\s*['\"]reversible['\"]/);
    }
  });
});
```

Replace this initial lexical scan with an Acorn AST walk before GREEN. Use the operation-specific allowlists above: project/payload/AAD serialization is limited to `project-security.js` and `project-crypto.js`; project Blob construction and `URL.createObjectURL` are limited to `useProject.js`. Transform `.jsx` candidates to JavaScript first with Vite 8's existing `transformWithOxc(source, filename, { lang: 'jsx', sourcemap: true })`, then parse with Acorn; add no dependency. The AST gate must resolve direct imports and local aliases for `JSON.stringify`, `Blob`, `URL.createObjectURL`, and project-export functions; reject computed constant-property access; and map diagnostics back through the transform source map to exact source lines. Add in-memory negative fixtures for each direct, aliased, and computed bypass plus a v5 sanitized object containing `sanitizationTable`; all fixtures must be rejected before the repository scan is accepted.

- [ ] **Step 2: Run enforcement RED**

Run:

```bash
npx vitest run tests/project-security-enforcement.test.js
```

Expected: FAIL against the old direct `JSON.stringify`/Blob path until Task 5 changes are visible; if Task 5 already removed it, intentionally insert the old pattern into an in-memory fixture passed to the analyzer and prove that fixture fails before accepting the repository scan.

- [ ] **Step 3: Add randomized nested leak tests**

In `tests/project-security.test.js`, use a seeded generator to place unique originals and secret-bearing objects at paths across objects/arrays, merge slots, warnings, mappings, and metadata. For 200 seeds:

```js
for (let seed = 1; seed <= 200; seed += 1) {
  const marker = 'ORIGINAL-MARKER-' + seed;
  const state = randomizedNestedState(seed, marker);
  expect(() => exportSanitizedFixture(state, marker), 'seed ' + seed)
    .toThrow(ProjectSecurityError);
}
```

Keep the generator deterministic and bounded. Assert raw and escaped markers, including quote, slash, newline, tab, and Unicode cases.

- [ ] **Step 4: Add the issue #11 acceptance matrix tests**

Add named tests proving:

- default sanitized export has no originals or table;
- sanitized import cannot restore;
- complete serialized file including metadata and nested objects is searched;
- PSK, SNMP, password/hash, RADIUS/TACACS, private-key, and certificate-secret matrices all redact;
- reversible export requires encryption, passphrase confirmation, and acknowledgement;
- unsanitized export requires typed confirmation;
- legacy plaintext restoration tables are warned;
- merge slots cannot bypass eligibility;
- wrong passphrase and all tamper cases fail uniformly;
- no passphrase or secret reaches returned descriptors, errors, storage, logs, or dispatch actions.

- [ ] **Step 5: Run all security-focused suites**

Run:

```bash
npx vitest run \
  tests/secret-detection.test.js \
  tests/project-security.test.js \
  tests/project-crypto.test.js \
  tests/project-io.test.js \
  tests/project-workflow.test.js \
  tests/project-security-ui.test.jsx \
  tests/project-security-enforcement.test.js \
  tests/credential-security.test.js \
  tests/conversion-security.test.js \
  tests/conversion-output.test.js
```

Expected: all files and tests pass with no skipped security tests.

- [ ] **Step 6: Add enforcement to CI and commit**

Add `tests/project-security-enforcement.test.js` to the explicit CI Vitest list, then:

```bash
git add tests/project-security-enforcement.test.js tests/project-security.test.js tests/project-io.test.js tests/secret-detection.test.js .github/workflows/ci.yml
git diff --cached --check
git commit -m "test: enforce secure project export boundary"
```

---

### Task 8: Full Verification and Issue Acceptance Audit

**Files:**
- Modify only if a verified defect is found. Do not change production code merely to silence a gate.
- Write ignored evidence under `.superpowers/sdd/`, never tracked.

**Interfaces:**
- Consumes: clean Task 7 HEAD and issue #11 acceptance criteria.
- Produces: fresh full-gate evidence, a criterion-to-test acceptance matrix, clean diff/status, and a whole-branch review package.

- [ ] **Step 1: Run the complete Vitest suite**

```bash
npx vitest run
```

Expected: every discovered Vitest file and test passes; no security test is skipped.

- [ ] **Step 2: Run every self-running JavaScript suite**

```bash
for test_file in tests/*.test.js; do
  if rg -q \"from 'vitest'\" \"$test_file\"; then
    continue
  fi
  node \"$test_file\"
done
```

Expected: every standalone harness reports zero failures.

- [ ] **Step 3: Run Python bridge and dependency integrity**

```bash
venv/bin/python -m unittest discover tools/pyez-bridge/tests -v
venv/bin/python -m pip check
npm audit --audit-level=high
```

Expected: 85 Python tests pass, Python dependencies are consistent, and npm reports zero high/critical vulnerabilities.

- [ ] **Step 4: Run build, syntax, and repository hygiene**

```bash
npm run build
git diff --name-only main...HEAD -- '*.js' | xargs -r -n1 node --check
git diff main...HEAD --check
git status --short
```

Expected: build succeeds; every changed `.js` file passes `node --check`; changed `.jsx` files pass Vite's production parse/build gate; diff check and status are clean.

- [ ] **Step 5: Build the acceptance matrix**

Map each issue #11 acceptance line to exact passing test names and preserve counts:

```text
default sanitized export contains no originals
sanitized import cannot restore
complete serialized file scan includes metadata and nested objects
PSK coverage
SNMP coverage
password/hash coverage
RADIUS/TACACS coverage
private-key coverage
certificate-secret coverage
reversible warning and explicit confirmation
authenticated encryption and tamper rejection
unsanitized metadata and typed confirmation
legacy secret-bearing migration warning
merge-slot recursive coverage
```

Any unmapped line is a failed gate. Add a behavior test first, capture RED, implement only if the test proves a real defect, and commit the minimal correction.

- [ ] **Step 6: Request independent whole-branch security review**

Create the review package from merge base `652dae14e58f98f025a7d03cd1f6e038b9b30fec` to final HEAD. Reviewer focus:

- secret-registry bypasses and regex backtracking;
- structured-key false negatives and dangerous false positives;
- restoration-table recursion and live-state mutation;
- JSON raw/escaped leak detection;
- Web Crypto schema/AAD/base64/tamper correctness;
- passphrase lifetime and error reflection;
- v1–v5 migration and transactional import;
- UI mode confusion and unsafe fallback;
- static enforcement blind spots;
- test discovery and CI coverage.

Fix every Critical and Important finding in one bounded correction task, rerun affected and full gates, and re-review until clean.

If no correction is needed, create no empty commit. When review does require correction, the bounded correction task must name its exact files and include its own explicit staging, diff-check, and `fix: close secure project export review gaps` commit step. Never use `git add -A` in a mixed worktree.

---

### Task 9: Publish Through the Standard GitHub Workflow

**Files:**
- No source changes expected.

**Interfaces:**
- Consumes: clean, fully verified `agent/issue-11-sanitized-project-secrets` branch.
- Produces: pushed branch, issue-linked PR, green CI, squash merge, green post-merge `main`, synchronized primary checkout, and removed feature worktree/branches.

- [ ] **Step 1: Fetch and compare current main**

```bash
git fetch origin
git rev-list --left-right --count origin/main...HEAD
git log --oneline --decorate --max-count=8 HEAD origin/main
```

Expected: relationship is understood. If `origin/main` advanced, integrate it non-destructively and rerun Task 8.

- [ ] **Step 2: Push without force**

```bash
git push -u origin agent/issue-11-sanitized-project-secrets
```

Expected: remote tracking branch is created.

- [ ] **Step 3: Open the issue-linked pull request**

Title:

```text
fix: prevent secrets in sanitized project exports
```

Body must summarize the v5 modes, recursive leak gate, vendor secret registry, encrypted reversible workflow, legacy migration, UI confirmations, and fresh verification. Include:

```text
Closes #11
```

- [ ] **Step 4: Monitor and fix CI**

Inspect every required check and log. For a failure, reproduce locally, use systematic debugging, write a failing regression when behavior is wrong, commit the minimal fix, push, and wait for all checks again.

Expected: all PR checks pass.

- [ ] **Step 5: Inspect published diff and review threads**

Confirm the PR contains only issue #11 changes. Fetch thread-aware review data and resolve every actionable Critical or Important item through local commits and rerun gates. Do not merge with unresolved requested changes.

- [ ] **Step 6: Squash merge**

Resolve the PR number and use the repository's squash subject:

```bash
PR_NUMBER=$(gh pr view --json number --jq .number)
gh pr merge "$PR_NUMBER" --squash \
  --subject "fix: prevent secrets in sanitized project exports (#${PR_NUMBER})"
```

Verify PR state is merged and issue #11 is closed.

- [ ] **Step 7: Verify post-merge main and clean up**

Wait for the merge-triggered `main` CI run and confirm every job succeeds. Then:

```bash
git -C /home/mharman/Projects/fwintentconverter pull --ff-only origin main
git -C /home/mharman/Projects/fwintentconverter worktree remove /home/mharman/Projects/fwintentconverter/.worktrees/issue-11-sanitized-project-secrets
git -C /home/mharman/Projects/fwintentconverter worktree prune
git -C /home/mharman/Projects/fwintentconverter branch -d agent/issue-11-sanitized-project-secrets
git -C /home/mharman/Projects/fwintentconverter push origin --delete agent/issue-11-sanitized-project-secrets
```

If squash history prevents ordinary local deletion, first reconfirm the merged PR SHA and green post-merge run, then delete the already-published feature branch using the least-destructive command that succeeds. Final evidence must show clean synchronized `main`, one primary worktree, deleted feature refs, merged PR, closed issue #11, and the next open security issue.

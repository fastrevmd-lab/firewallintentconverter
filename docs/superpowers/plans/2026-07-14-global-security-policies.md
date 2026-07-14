# `security policies global` Output Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit SRX `security policies global` with `match from-zone`/`match to-zone` as the default output structure, keeping the existing zone-pair form available via a UI toggle.

**Architecture:** Extract the shared policy match/action body into one helper, then branch policy emission on a new `options.policyStructure` (`'global'` default | `'zone-pair'`). Thread the option from a new UI dropdown through `useConversion` → `engine.convertConfig` → `convertToSrxSetCommands`. Global mode emits one consolidated rule per source policy into a single ordered rulebase.

**Tech Stack:** JavaScript (ESM), React 18, Vitest.

## Global Constraints

- Default policy structure is `'global'`; `'zone-pair'` is opt-in. Any unrecognized/absent `options.policyStructure` falls back to `'global'`.
- Global mode: one consolidated rule per source policy (multi-zone → `match from-zone A B` / `match to-zone C D`), emitted in `_rule_index` order (source order preserved).
- Zone-pair mode output must remain byte-identical to today (regression-locked).
- Only the set-command converter (`convertToSrxSetCommands`) changes. The XML builder (`buildSrxXml`) is out of scope and unchanged.
- `match/action` body logic must be shared between modes so UTM/IDP/SecIntel/logging cannot drift.
- `const` over `let`; JSDoc on new exported/module functions; early returns.
- Tests run with `npx vitest run` (there is NO `npm test` script).

---

### Task 1: Extract shared `emitPolicyBody` helper (pure refactor, regression-locked)

**Files:**
- Modify: `src/converters/srx-converter.js` (extract body from `convertSecurityPolicies`, lines ~1722-1828)
- Test: `tests/srx-policy-structure.test.js` (create — regression snapshot)

**Interfaces:**
- Produces: module-level function
  `emitPolicyBody(commands, policyPath, policyName, ctx)` where `ctx` is
  `{ policy, pIdx, srcAddrs, dstAddrs, dstZones, appGroups, sourceVendor, utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName, identifiers, identifierPath, warnings, deactivateCommands }`.
  It pushes the description → disabled-deactivate lines (everything after the `security policies ... policy <name>` prefix line) to `commands` / `deactivateCommands`. Returns nothing.
- Consumes: existing helpers `resolveApplications`, `mapAction`, `setQuoted`, `sanitizeJunosName` already imported/defined in the file.

- [ ] **Step 1: Write the regression test**

Create `tests/srx-policy-structure.test.js`:

```js
import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

/** A config exercising multi-zone, apps, logging, deny — for structure tests. */
export const MULTIZONE_CONFIG = {
  zones: [
    { name: 'trust', interfaces: [] }, { name: 'dmz', interfaces: [] },
    { name: 'untrust', interfaces: [] }, { name: 'partner', interfaces: [] },
  ],
  address_objects: [
    { name: 'web', type: 'ip-netmask', value: '10.0.0.10/32' },
  ],
  service_objects: [],
  security_policies: [
    {
      name: 'allow-web', _rule_index: 0, action: 'allow',
      src_zones: ['trust', 'dmz'], dst_zones: ['untrust', 'partner'],
      src_addresses: ['web'], dst_addresses: ['any'],
      applications: ['junos-https'], services: [], log_end: true,
    },
    {
      name: 'deny-all', _rule_index: 1, action: 'deny',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['any'], services: [],
    },
  ],
  nat_rules: [],
};

/** Extract only the policy set-lines from converter output text. */
export function policyLines(out) {
  const text = Array.isArray(out.commands) ? out.commands.join('\n') : String(out);
  return text.split('\n').filter(l => l.includes('security policies') || l.startsWith('deactivate security policies'));
}

describe('policy body extraction is behavior-preserving (zone-pair)', () => {
  it('zone-pair output contains the expected per-pair policy lines', () => {
    const out = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'zone-pair' });
    const lines = policyLines(out).join('\n');
    // allow-web spans 2x2 zone pairs in zone-pair mode
    expect(lines).toContain('set security policies from-zone trust to-zone untrust policy allow-web then permit');
    expect(lines).toContain('set security policies from-zone dmz to-zone partner policy allow-web then permit');
    // logging carried through the shared body
    expect(lines).toContain('set security policies from-zone trust to-zone untrust policy allow-web then log session-close');
  });
});
```

> Note: this test passes `{ policyStructure: 'zone-pair' }`, an option that does not exist until Task 2. Task 1 adds ONLY the `emitPolicyBody` extraction; to make this test runnable in Task 1, also accept and honor the option's `'zone-pair'` value as a no-op passthrough is NOT required — instead, in Task 1 run the test with the 4th arg omitted by temporarily changing the call to `convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null)` for the Task-1 fail/pass cycle, then restore the `{ policyStructure: 'zone-pair' }` arg in Task 2 when the option lands. Simpler: in Task 1, assert against the current default (zone-pair) with the 4th arg omitted; Task 2 switches this test to pass the explicit option.

To keep Task 1 self-contained, use this Task-1 form of the test call (no 4th arg):

```js
    const out = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null);
```

- [ ] **Step 2: Run test to verify current behavior is captured**

Run: `npx vitest run tests/srx-policy-structure.test.js`
Expected: PASS against today's zone-pair default (this establishes the baseline the refactor must preserve).

- [ ] **Step 3: Extract `emitPolicyBody`**

In `src/converters/srx-converter.js`, add a module-level function (place it just above `convertSecurityPolicies`). Move the body that currently spans from the `// Description (include PAN-OS tags as comments)` comment through the `// Disabled rules → deactivate command` block (lines ~1722-1828) into it verbatim, replacing the closure variables with `ctx.` fields and keeping `policyPath` / `policyName` as parameters:

```js
/**
 * Emit the match/action body for one security policy (everything after the
 * `security policies ... policy <name>` prefix line). Shared by both the
 * zone-pair and global emission paths so their behavior cannot drift.
 *
 * @param {string[]} commands - output accumulator
 * @param {string} policyPath - e.g. `security policies global policy P` or
 *   `security policies from-zone X to-zone Y policy P`
 * @param {string} policyName - resolved policy identifier
 * @param {object} ctx - see plan Task 1 Interfaces block
 */
function emitPolicyBody(commands, policyPath, policyName, ctx) {
  const {
    policy, pIdx, srcAddrs, dstAddrs, dstZones, appGroups, sourceVendor,
    utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName,
    identifiers, identifierPath, warnings, deactivateCommands,
  } = ctx;

  // Description (include PAN-OS tags as comments)
  let fullDescription = policy.description || '';
  if (policy.tags && policy.tags.length > 0) {
    const tagNote = `[PAN-OS tags: ${policy.tags.join(', ')}]`;
    fullDescription = fullDescription ? `${fullDescription} ${tagNote}` : tagNote;
  }
  if (fullDescription) {
    commands.push(`set ${policyPath} description ${setQuoted(fullDescription, `security_policies[${pIdx}].description`)}`);
  }

  const effectiveSrcAddrs = srcAddrs.length > 0 ? srcAddrs : [{ value: 'any', index: null }];
  for (const { index: addressIndex } of effectiveSrcAddrs) {
    const addressName = addressIndex === null
      ? 'any'
      : identifiers.nameForReference(identifierPath(`security_policies[${pIdx}].src_addresses[${addressIndex}]`));
    commands.push(`set ${policyPath} match source-address ${addressName}`);
  }

  const effectiveDstAddrs = dstAddrs.length > 0 ? dstAddrs : [{ value: 'any', index: null }];
  for (const { index: addressIndex } of effectiveDstAddrs) {
    const addressName = addressIndex === null
      ? 'any'
      : identifiers.nameForReference(identifierPath(`security_policies[${pIdx}].dst_addresses[${addressIndex}]`));
    commands.push(`set ${policyPath} match destination-address ${addressName}`);
  }

  let apps = resolveApplications(policy.applications, policy.services, warnings, policyName, appGroups, sourceVendor, pIdx, identifiers, identifierPath);
  if (apps.includes('any')) apps = ['any'];
  for (const app of apps) {
    commands.push(`set ${policyPath} match application ${app}`);
  }

  if (policy.source_users && policy.source_users.length > 0) {
    for (const identity of policy.source_users) {
      commands.push(`set ${policyPath} match source-identity ${setQuoted(sanitizeJunosName(identity), `security_policies[${pIdx}].source_users`)}`);
    }
  }

  const srxAction = mapAction(policy.action);
  commands.push(`set ${policyPath} then ${srxAction}`);

  if (policy.log_start) commands.push(`set ${policyPath} then log session-init`);
  if (policy.log_end) commands.push(`set ${policyPath} then log session-close`);
  if (policy._srx_log_count !== false) commands.push(`set ${policyPath} then count`);

  if (utmPolicyMap[pIdx]) {
    const utmPolicyName = identifiers.nameForReference(identifierPath(`security_policies[${pIdx}]#utm-policy`));
    commands.push(`set ${policyPath} then permit application-services utm-policy ${utmPolicyName}`);
  }
  if (idpPolicyMap[pIdx]) {
    const idpPolicyName = identifiers.nameForReference(identifierPath(`security_policies[${pIdx}]#idp-policy`));
    commands.push(`set ${policyPath} then permit application-services idp-policy ${idpPolicyName}`);
  }
  if (secIntelEnabled && policy.action === 'allow' && dstZones.some(z => z.toLowerCase() === 'untrust')) {
    commands.push(`set ${policyPath} then permit application-services security-intelligence-policy ${secIntelPolicyName}`);
  }

  if (policy._srx_decrypt && policy.action === 'allow') {
    const sslProfile = identifiers.nameForReference(identifierPath(
      policy._srx_decrypt_profile
        ? `security_policies[${pIdx}]._srx_decrypt_profile`
        : `security_policies[${pIdx}]#ssl-proxy-profile`,
    ));
    commands.push(`# NOTE: SSL proxy skipped — profile "${sslProfile}" requires manual PKI setup before enabling`);
    commands.push(`# set ${policyPath} then permit application-services ssl-proxy profile-name ${sslProfile}`);
  }

  if (policy.schedule) {
    const scheduleName = identifiers.nameForReference(identifierPath(`security_policies[${pIdx}].schedule`));
    commands.push(`set ${policyPath} scheduler-name ${scheduleName}`);
  }

  if (policy.disabled) deactivateCommands.push(`deactivate ${policyPath}`);
}
```

- [ ] **Step 4: Call `emitPolicyBody` from the zone-pair loop**

In `convertSecurityPolicies`, replace the moved body (the description→disabled block inside the `destinationEntries` loop) with a single call, right after the `policyPath` is computed (line ~1720):

```js
        emitPolicyBody(commands, policyPath, policyName, {
          policy, pIdx, srcAddrs, dstAddrs, dstZones, appGroups, sourceVendor,
          utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName,
          identifiers, identifierPath, warnings, deactivateCommands,
        });
```

Leave everything else (zone loops, `policyNamesByContext`, `policyPath` construction, group comments, `deactivateCommands` flush at the end) unchanged.

- [ ] **Step 5: Run tests to verify no behavior change**

Run: `npx vitest run tests/srx-policy-structure.test.js`
Expected: PASS (identical output — the refactor is behavior-preserving).

Run: `npx vitest run`
Expected: all pass (existing zone-pair tests unchanged).

- [ ] **Step 6: Commit**

```bash
git add src/converters/srx-converter.js tests/srx-policy-structure.test.js
git commit -m "refactor(convert): extract shared emitPolicyBody from policy emission (#29)"
```

---

### Task 2: Add `options.policyStructure` and global emission

**Files:**
- Modify: `src/converters/srx-converter.js` (`convertToSrxSetCommands` signature use of `options`; `convertSecurityPolicies` branch)
- Modify: `tests/srx-policy-structure.test.js` (add global-mode tests; switch the Task-1 test call to explicit `'zone-pair'`)
- Modify: `tests/validation-engine.test.js`, `tests/junos-identifier-integration.test.js`, `tests/junos-validation.test.js` (pass `{ policyStructure: 'zone-pair' }` at their `convertToSrxSetCommands` set-command call sites to preserve intent under the new global default)

**Interfaces:**
- Consumes: `emitPolicyBody(...)` from Task 1; existing `orderedZoneEntries`, `generatedPolicyRole`, `encodeJunosZonePair`, `identifiers`.
- Produces: `convertSecurityPolicies(policies, commands, warnings, summary, profileMaps, appGroups, sourceVendor, ruleGroups, identifiers, identifierPath, policyStructure)` — new trailing `policyStructure` parameter (`'global'` | `'zone-pair'`, default `'global'`).

- [ ] **Step 1: Write the failing global-mode tests**

Add to `tests/srx-policy-structure.test.js`:

```js
describe('global policy structure (default)', () => {
  it('emits one consolidated global rule per policy with match from/to zones', () => {
    const out = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'global' });
    const lines = policyLines(out);
    const joined = lines.join('\n');
    // allow-web is ONE global policy, not four zone-pair entries
    expect(joined).toContain('set security policies global policy allow-web match from-zone trust');
    expect(joined).toContain('set security policies global policy allow-web match from-zone dmz');
    expect(joined).toContain('set security policies global policy allow-web match to-zone untrust');
    expect(joined).toContain('set security policies global policy allow-web match to-zone partner');
    expect(joined).toContain('set security policies global policy allow-web then permit');
    // No zone-pair container lines in global mode
    expect(joined).not.toMatch(/from-zone \S+ to-zone \S+ policy/);
    // default-policy present for global
    const allText = Array.isArray(out.commands) ? out.commands.join('\n') : String(out);
    expect(allText).toContain('set security policies default-policy permit-all');
  });

  it('preserves source rule order in the single global list', () => {
    const out = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'global' });
    const joined = policyLines(out).join('\n');
    expect(joined.indexOf('policy allow-web')).toBeLessThan(joined.indexOf('policy deny-all'));
  });

  it('defaults to global when no policyStructure option is given', () => {
    const withOpt = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'global' });
    const noOpt = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null);
    expect(policyLines(noOpt)).toEqual(policyLines(withOpt));
  });
});
```

Also change the Task-1 regression test's call from `convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null)` to `convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'zone-pair' })` (now that the option exists, the zone-pair regression must pin the explicit option, since the default is global).

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/srx-policy-structure.test.js`
Expected: FAIL — global lines not emitted (default still routes to zone-pair; the `not.toMatch` and default tests fail).

- [ ] **Step 3: Thread `policyStructure` into `convertSecurityPolicies`**

In `src/converters/srx-converter.js`:

(a) In `convertToSrxSetCommands`, near the top where `options` is available, resolve the mode and pass it to the policy converter. Find the existing call `convertSecurityPolicies(config.security_policies, policyCommands, warnings, summary, { ... }, config.application_groups, sourceVendor, config._rule_groups, identifiers, identifierPath);` (line ~170) and append the resolved structure:

```js
  const policyStructure = options.policyStructure === 'zone-pair' ? 'zone-pair' : 'global';
```
then add `, policyStructure` as the final argument of that `convertSecurityPolicies(...)` call.

(b) Update the `convertSecurityPolicies` signature to accept it:

```js
function convertSecurityPolicies(policies, commands, warnings, summary, profileMaps = {}, appGroups = [], sourceVendor = '', ruleGroups = [], identifiers, identifierPath, policyStructure = 'global') {
```

- [ ] **Step 4: Branch the per-policy emission on `policyStructure`**

Inside `convertSecurityPolicies`, the per-policy code currently computes `srcZones`, `dstZones`, `sourceEntries`, `destinationEntries` and then runs the zone-pair double loop. Wrap the emission in a branch. Keep all the pre-zone setup (group comments, `secIntelAddrs`, `srcAddrs`/`dstAddrs`, zone-field resolution) unchanged, then:

```js
    if (policyStructure === 'zone-pair') {
      // ---- existing zone-pair emission (unchanged) ----
      let definitionIndex = 0;
      const policyNamesByContext = new Map();
      for (const { zone: srcZone, index: sourceIndex } of sourceEntries) {
        const sourcePath = policy[sourceZoneField]?.length > 0
          ? `security_policies[${pIdx}].${sourceZoneField}[${sourceIndex}]`
          : `security_policies[${pIdx}]#effective-source-zone`;
        const fromZone = identifiers.nameForReference(identifierPath(sourcePath));
        for (const { zone: dstZone, index: destinationIndex } of destinationEntries) {
          const destinationPath = policy[destinationZoneField]?.length > 0
            ? `security_policies[${pIdx}].${destinationZoneField}[${destinationIndex}]`
            : `security_policies[${pIdx}]#effective-destination-zone`;
          const toZone = identifiers.nameForReference(identifierPath(destinationPath));
          const isGlobal = fromZone === 'any' || toZone === 'any';
          const policyContext = isGlobal ? 'global' : encodeJunosZonePair(srcZone, dstZone);
          let policyName;
          if (policyNamesByContext.has(policyContext)) {
            policyName = policyNamesByContext.get(policyContext);
          } else {
            definitionIndex += 1;
            const genericName = !policy.name
              || /^(rule|policy|permit|deny)[-_]?\d+$/i.test(policy.name)
              || /^\d+$/.test(policy.name);
            policyName = genericName
              ? identifiers.nameForGenerated(identifierPath(`security_policies[${pIdx}]`), generatedPolicyRole(srcZone, dstZone))
              : identifiers.nameForDefinition(identifierPath(
                definitionIndex === 1
                  ? `security_policies[${pIdx}].name`
                  : `security_policies[${pIdx}].name#zone-pair:${encodeJunosZonePair(srcZone, dstZone)}`,
              ));
            policyNamesByContext.set(policyContext, policyName);
          }
          const policyPath = isGlobal
            ? `security policies global policy ${policyName}`
            : `security policies from-zone ${fromZone} to-zone ${toZone} policy ${policyName}`;
          emitPolicyBody(commands, policyPath, policyName, {
            policy, pIdx, srcAddrs, dstAddrs, dstZones, appGroups, sourceVendor,
            utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName,
            identifiers, identifierPath, warnings, deactivateCommands,
          });
        }
      }
    } else {
      // ---- global emission: one consolidated rule per policy ----
      const genericName = !policy.name
        || /^(rule|policy|permit|deny)[-_]?\d+$/i.test(policy.name)
        || /^\d+$/.test(policy.name);
      const firstSrc = sourceEntries[0]?.zone ?? 'any';
      const firstDst = destinationEntries[0]?.zone ?? 'any';
      const policyName = genericName
        ? identifiers.nameForGenerated(identifierPath(`security_policies[${pIdx}]`), generatedPolicyRole(firstSrc, firstDst))
        : identifiers.nameForDefinition(identifierPath(`security_policies[${pIdx}].name`));
      const policyPath = `security policies global policy ${policyName}`;

      for (const { zone: srcZone, index: sourceIndex } of sourceEntries) {
        const sourcePath = policy[sourceZoneField]?.length > 0
          ? `security_policies[${pIdx}].${sourceZoneField}[${sourceIndex}]`
          : `security_policies[${pIdx}]#effective-source-zone`;
        const fromZone = identifiers.nameForReference(identifierPath(sourcePath));
        commands.push(`set ${policyPath} match from-zone ${fromZone}`);
      }
      for (const { zone: dstZone, index: destinationIndex } of destinationEntries) {
        const destinationPath = policy[destinationZoneField]?.length > 0
          ? `security_policies[${pIdx}].${destinationZoneField}[${destinationIndex}]`
          : `security_policies[${pIdx}]#effective-destination-zone`;
        const toZone = identifiers.nameForReference(identifierPath(destinationPath));
        commands.push(`set ${policyPath} match to-zone ${toZone}`);
      }

      emitPolicyBody(commands, policyPath, policyName, {
        policy, pIdx, srcAddrs, dstAddrs, dstZones, appGroups, sourceVendor,
        utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName,
        identifiers, identifierPath, warnings, deactivateCommands,
      });
    }
```

> The zone-pair branch is the code that existed before this task — moved verbatim under the `if`. Do not alter its lines.

- [ ] **Step 5: Migrate existing zone-pair tests to the explicit option**

The default is now global, so tests that assert zone-pair set output must pass the option. In each of `tests/validation-engine.test.js`, `tests/junos-identifier-integration.test.js`, and `tests/junos-validation.test.js`, find every call to `convertToSrxSetCommands(...)` whose assertions expect `security policies from-zone ... policy` (set-command) output, and add `{ policyStructure: 'zone-pair' }` as the 4th argument (add `null` for the 3rd `targetContext` arg if omitted). Do NOT change the expected strings. (XML-builder tests using `buildSrxXml` are unaffected — leave them.)

- [ ] **Step 6: Run tests to verify pass**

Run: `npx vitest run tests/srx-policy-structure.test.js`
Expected: PASS (global + zone-pair + default).

Run: `npx vitest run`
Expected: all pass (migrated zone-pair tests green under explicit option).

- [ ] **Step 7: Commit**

```bash
git add src/converters/srx-converter.js tests/srx-policy-structure.test.js tests/validation-engine.test.js tests/junos-identifier-integration.test.js tests/junos-validation.test.js
git commit -m "feat(convert): add security policies global output mode, default global (#29)"
```

---

### Task 3: Thread `policyStructure` from the UI hook to the converter

**Files:**
- Modify: `public/utils/engine.js` (`convertConfig` signature + converter call, ~line 105)
- Modify: `public/hooks/useConversion.js` (`handleConvert` passes the option)
- Test: `tests/conversion-policy-structure.test.js` (create)

**Interfaces:**
- Consumes: `convertToSrxSetCommands(config, mappings, ctx, options)` from Task 2.
- Produces: `convertConfig(intermediateConfig, format, interfaceMappings, targetContext, options)` — new trailing `options = {}` forwarded to the set-command converter.

- [ ] **Step 1: Write the failing test**

Create `tests/conversion-policy-structure.test.js`:

```js
import { describe, it, expect } from 'vitest';
import { convertConfig } from '../public/utils/engine.js';
import { MULTIZONE_CONFIG, policyLines } from './srx-policy-structure.test.js';

describe('convertConfig forwards policyStructure', () => {
  it('produces global output when policyStructure=global', async () => {
    const data = await convertConfig(MULTIZONE_CONFIG, 'set', {}, null, { policyStructure: 'global' });
    const joined = policyLines(data.output).join('\n');
    expect(joined).toContain('set security policies global policy allow-web match from-zone trust');
  });

  it('produces zone-pair output when policyStructure=zone-pair', async () => {
    const data = await convertConfig(MULTIZONE_CONFIG, 'set', {}, null, { policyStructure: 'zone-pair' });
    const joined = policyLines(data.output).join('\n');
    expect(joined).toMatch(/from-zone \S+ to-zone \S+ policy allow-web/);
  });
});
```

> If `convertConfig`'s returned shape differs (e.g. `data.output` is a string vs `{ commands }`), adjust `policyLines`' usage accordingly — `policyLines` already handles both array-`.commands` and string forms. Confirm by reading `convertConfig`'s return near the end of `public/utils/engine.js`.

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/conversion-policy-structure.test.js`
Expected: FAIL — `convertConfig` ignores the 5th arg, so both cases yield the default (global); the zone-pair assertion fails.

- [ ] **Step 3: Forward `options` through `convertConfig`**

In `public/utils/engine.js`, change the signature:

```js
export async function convertConfig(intermediateConfig, format = 'set', interfaceMappings = {}, targetContext = null, options = {}) {
```

and the set-command branch call (line ~105) from
`output = converterMod.convertToSrxSetCommands(intermediateConfig, interfaceMappings, targetContext);`
to:

```js
    output = converterMod.convertToSrxSetCommands(intermediateConfig, interfaceMappings, targetContext, options);
```

(Leave the `xml` branch unchanged — XML is out of scope.)

- [ ] **Step 4: Pass the option from `handleConvert`**

In `public/hooks/useConversion.js`, in `handleConvert`, add the option to the `convertConfig` call (line ~95). The hook already has access to the UI state that will hold `policyStructure` (added in Task 4); read it defensively so this task's tests pass before Task 4 exists:

```js
      const data = await convertConfig(
        configForConversion,
        format,
        interfaceMappings,
        targetContext.type !== 'none' ? targetContext : null,
        { policyStructure: uiState?.policyStructure || 'global' },
      );
```

If `uiState` is not already destructured in this hook, read it from the same context the hook uses for `uiDispatch` (search the file for how `uiDispatch` is obtained and take `state` from the same `useUIContext()` result). Add `uiState?.policyStructure` to the `useCallback` dependency array for `handleConvert`.

- [ ] **Step 5: Run tests to verify pass**

Run: `npx vitest run tests/conversion-policy-structure.test.js`
Expected: PASS (both global and zone-pair).

Run: `npx vitest run`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add public/utils/engine.js public/hooks/useConversion.js tests/conversion-policy-structure.test.js
git commit -m "feat(convert): thread policyStructure option from hook through engine (#29)"
```

---

### Task 4: UI — Policy structure dropdown (Global default / Zone-pair)

**Files:**
- Modify: `public/contexts/UIContext.jsx` (add `policyStructure: 'global'` to `initialState`)
- Modify: `public/components/SRXOutput.jsx` (add the dropdown; dispatch + re-convert)
- Test: `tests/ui-policy-structure.test.js` (create — reducer/default behavior)

**Interfaces:**
- Consumes: the existing `SET_FIELD` reducer action (`dispatch({ type: 'SET_FIELD', field, value })`) and `uiState.policyStructure` read in Task 3.
- Produces: UI state field `policyStructure` (`'global'` default), surfaced via a dropdown that re-runs conversion.

- [ ] **Step 1: Write the failing test**

Create `tests/ui-policy-structure.test.js`:

```js
import { describe, it, expect } from 'vitest';
import { uiReducer, initialState } from '../public/contexts/UIContext.jsx';

describe('UI policy structure state', () => {
  it('defaults to global', () => {
    expect(initialState.policyStructure).toBe('global');
  });

  it('SET_FIELD updates policyStructure', () => {
    const next = uiReducer(initialState, { type: 'SET_FIELD', field: 'policyStructure', value: 'zone-pair' });
    expect(next.policyStructure).toBe('zone-pair');
  });
});
```

> If `uiReducer`/`initialState` are not currently exported from `UIContext.jsx`, add named exports for them (the provider keeps using them internally). Do not change their behavior otherwise.

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/ui-policy-structure.test.js`
Expected: FAIL — `initialState.policyStructure` is undefined (and possibly `uiReducer`/`initialState` not exported).

- [ ] **Step 3: Add the state field and exports**

In `public/contexts/UIContext.jsx`, add to `initialState`:

```js
  policyStructure: 'global',
```

Ensure `initialState` and `uiReducer` are exported (add `export` to their declarations if not already). No reducer change is needed — `SET_FIELD` already sets arbitrary fields.

- [ ] **Step 4: Add the dropdown to SRXOutput**

In `public/components/SRXOutput.jsx`, near the existing output controls (where the render-mode/presentation controls live), add a Policy-structure selector. Read state and dispatch via the context the component already uses (`useUIContext`), and trigger a re-conversion using the convert handler the component/app already exposes for re-running conversion. Concretely:

```jsx
        <label className="policy-structure-select">
          Policy structure:
          <select
            value={uiState?.policyStructure || 'global'}
            onChange={(e) => {
              uiDispatch({ type: 'SET_FIELD', field: 'policyStructure', value: e.target.value });
              if (typeof onReconvert === 'function') onReconvert();
            }}
          >
            <option value="global">Global (security policies global)</option>
            <option value="zone-pair">Zone-pair (from-zone / to-zone)</option>
          </select>
        </label>
```

Wire `uiState` from `useUIContext()` (the component already pulls `dispatch`; also take `state`). For re-conversion: if the component receives a convert callback via props or context, call it; otherwise pass an `onReconvert` prop from the parent that maps to `handleConvert('set')`. If no such wiring exists, add an `onReconvert` prop to `SRXOutput` and have its parent (the component that renders `<SRXOutput .../>`) pass `() => handleConvert('set')` from `useConversion`.

> This step touches whichever parent renders `SRXOutput`. Keep the change minimal: add the one prop and pass the existing `handleConvert('set')`.

- [ ] **Step 5: Run tests to verify pass**

Run: `npx vitest run tests/ui-policy-structure.test.js`
Expected: PASS.

Run: `npx vitest run`
Expected: all pass.

- [ ] **Step 6: Manual smoke (drive the real app)**

Dev server is running (http://192.168.1.127:5173/). Load a PAN-OS config, Convert to SRX, confirm default output uses `security policies global ... match from-zone/to-zone`. Switch the dropdown to Zone-pair and confirm the output re-renders as `from-zone X to-zone Y policy`. (Verification only — no code change expected.)

- [ ] **Step 7: Commit**

```bash
git add public/contexts/UIContext.jsx public/components/SRXOutput.jsx tests/ui-policy-structure.test.js
git commit -m "feat(ui): add policy structure toggle (global default / zone-pair) (#29)"
```

---

## Spec Coverage Check

- Spec §1 Converter (`options.policyStructure`, global consolidated emission, order, default-policy) → **Task 2** (emission + branch) built on **Task 1** (shared body).
- Spec §1 "shared body builder so modes can't drift" (Risks) → **Task 1** (`emitPolicyBody`).
- Spec §2 Options plumbing (engine + hook) → **Task 3**.
- Spec §3 UI toggle (state + dropdown, re-convert) → **Task 4**.
- Spec §4 Testing bullets (global shape, default===global, zone-pair regression, plumbing forwarding, UI toggle) → covered across Tasks 1–4.
- Spec Risks (consolidation equivalence, ordering, legacy regression, body divergence) → Task 2 tests (consolidation + order), Task 1 regression lock, Task 1 shared body.

## Notes / Out of Scope

- XML output (`buildSrxXml`) is unchanged; the toggle affects set-command output only. If XML global support is wanted later, it's a separate issue.
- Zone-pair mode remains fully supported via the dropdown for legacy/branch-SRX workflows.

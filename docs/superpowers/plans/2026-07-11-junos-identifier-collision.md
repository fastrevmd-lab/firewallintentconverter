# Junos Identifier Collision Defense Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent distinct source names from silently sharing a generated Junos identifier while preserving deterministic Set, XML, merge, warning, and project behavior.

**Architecture:** Build one dependency-free allocator that consumes a declarative, conversion-scoped catalog of definitions and references. Both converters receive the resulting immutable plan and retrieve every Junos symbol from it; canonical output persists the validated mapping, while legacy projects without mappings lose only stale generated artifacts.

**Tech Stack:** JavaScript ES modules, Vitest 4.1.10, React 18 contexts/hooks, Vite 8, existing Junos serialization/output validators, GitHub Actions.

## Global Constraints

- Preserve case: `Web` and `web` remain distinct.
- Preserve the existing `sanitizeJunosName()` result for every non-colliding definition.
- Rename every member of a collision group; allocation must not depend on array order.
- Use FNV-1a 64-bit over UTF-8 with offset `14695981039346656037`, prime `1099511628211`, and mask `0xffffffffffffffff`.
- Use the versioned hash input `junos-id-v1\0<context>\0<namespace>\0<kind>\0<stableKey>\0<retry>` and a 13-character lower-case base36 suffix.
- Keep output identifiers at or below 63 characters and fail after 32 conflict rounds.
- Do not add runtime dependencies.
- Exact duplicate definitions and ambiguous references block conversion.
- Missing references retain existing warning/error semantics but receive reserved non-binding names.
- Set and XML must emit deeply equal `identifierMappings` for the same semantic input.
- Every non-null new canonical output requires identifier mapping version `1`.
- Increment project format version from `3` to `4`.
- Version 1-3 projects without a valid mapping preserve editable state but clear `srxOutput`, `convertWarnings`, and `conversionSummary`.
- Continue using the existing Warnings panel; do not add a collision-specific panel.
- Use `apply_patch` for source edits, one red-green-refactor cycle per task, and commit only the files listed by that task.

---

## File Structure

- Create `src/security/junos-identifiers.js`: typed errors, FNV allocation, reference binding, immutable lookups, mapping validation, and public planning entry points.
- Create `src/security/junos-identifier-catalog.js`: namespace constants and complete traversal of intermediate/merge configuration into definition/reference/generated symbol records.
- Create `tests/junos-identifiers.test.js`: allocator, mapping validator, order-independence, collision, duplicate, and forced-hash tests.
- Create `tests/junos-identifier-integration.test.js`: Set/XML/merge reference integrity, namespace scoping, warnings, and randomized uniqueness tests.
- Create `tests/parser-name-preservation.test.js`: Check Point and SonicWall exact-name preservation.
- Modify `src/parsers/checkpoint-parser.js`: stop pre-normalizing symbol definitions and references.
- Modify `src/parsers/sonicwall-parser.js`: stop pre-normalizing policy, NAT, and object names.
- Modify `src/converters/srx-converter.js`: construct/accept a plan and replace cataloged Set identifier normalization with lookups.
- Modify `src/converters/srx-xml-builder.js`: construct/accept the same plan and replace cataloged XML identifier normalization with lookups.
- Modify `src/conversion/conversion-output.js`: require and preserve a validated identifier mapping on new canonical output.
- Modify `public/utils/engine.js`: validate mapping-bearing converter output at the public boundary.
- Modify `public/hooks/useConversion.js`: format `JunosIdentifierPlanningError` safely.
- Modify `public/utils/project-io.js`: project v4 save/load validation and legacy artifact invalidation.
- Modify `tests/conversion-output.test.js`, `tests/conversion-security.test.js`, `tests/project-io.test.js`, and `tests/srx-injection-defense.test.js`: update canonical fixtures and regression expectations.

### Public interfaces shared by all tasks

```js
export class JunosIdentifierPlanningError extends Error {
  constructor(code, details = {})
}

export const JUNOS_IDENTIFIER_MAPPING_VERSION = 1;

export function createJunosIdentifierPlan({ definitions, references }, options = {})

export function planJunosIdentifiers(config, options = {})

export function planMergedJunosIdentifiers(configSlots, crossLsLinks = [], globalConfig = {}, options = {})

export function validateIdentifierMappings(mapping)
```

The returned plan has this exact read-only interface:

```js
{
  mapping,                 // validated { version: 1, entries: Array }
  warnings,                // identifier_collision warnings
  collisionCount,          // number of renamed definitions
  nameForDefinition(path),
  nameForReference(path),
  nameForGenerated(path, role),
}
```

`JunosIdentifierPlanningError` exposes `code`, `namespace`, `context`, `sourceName`, `definitionPaths`, `referencePaths`, and `reason`. Every field is a safe scalar or array copied from validated identifier metadata; it never contains generated artifact text.

Catalog records use these exact shapes:

```js
{
  catalogKey, context, namespace, kind, sourceName,
  definitionPath, generated, role, stableParentKey,
}

{
  catalogKey, context, namespace, compatibleKinds, sourceName,
  referencePath, literals,
}
```

## Task 1: Build the Deterministic Allocator and Mapping Validator

**Files:**
- Create: `src/security/junos-identifiers.js`
- Create: `tests/junos-identifiers.test.js`

**Interfaces:**
- Consumes: `sanitizeJunosName(name)` and safe scalar behavior from the existing security modules.
- Produces: `JunosIdentifierPlanningError`, `createJunosIdentifierPlan()`, `validateIdentifierMappings()`, and the plan lookup interface documented above.

- [ ] **Step 1: Write failing allocator tests**

Create fixtures through a local helper so paths are diagnostic only:

```js
const definition = (sourceName, definitionPath, overrides = {}) => ({
  catalogKey: 'address-book',
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  kind: 'address',
  sourceName,
  definitionPath,
  generated: false,
  role: null,
  stableParentKey: null,
  ...overrides,
});

it.each([
  ['Web Server', 'Web@Server'],
  ['Web  Server', 'Web--Server'],
  ['!!!', '???'],
  ['1 edge', 'n-1-edge'],
  [`${'a'.repeat(63)}x`, `${'a'.repeat(63)}y`],
])('renames both definitions for %s and %s', (left, right) => {
  const plan = createJunosIdentifierPlan({
    definitions: [definition(left, 'defs[0]'), definition(right, 'defs[1]')],
    references: [],
  });
  expect(plan.nameForDefinition('defs[0]')).not.toBe(plan.nameForDefinition('defs[1]'));
  expect(plan.mapping.entries.every(entry => entry.resolution === 'collision-renamed')).toBe(true);
});

it('preserves case-only and other non-colliding names', () => {
  const plan = createJunosIdentifierPlan({
    definitions: [definition('Web', 'defs[0]'), definition('web', 'defs[1]')],
    references: [],
  });
  expect(plan.nameForDefinition('defs[0]')).toBe('Web');
  expect(plan.nameForDefinition('defs[1]')).toBe('web');
});
```

Add tests for reordered inputs, an unchanged singleton matching a first candidate, exact duplicates, an ambiguous address/address-set reference, an unresolved external reference, missing lookup coverage, mapping validation, a one-round injected hash conflict, and a hash stub that remains constant for 32 rounds.

- [ ] **Step 2: Run the focused test and confirm red state**

Run: `npx vitest run tests/junos-identifiers.test.js`

Expected: FAIL because `src/security/junos-identifiers.js` does not exist.

- [ ] **Step 3: Implement the allocator primitives**

Implement the hash without Node-only APIs so it works in the browser:

```js
const FNV_OFFSET = 14695981039346656037n;
const FNV_PRIME = 1099511628211n;
const FNV_MASK = 0xffffffffffffffffn;

function fnv1a64(value) {
  let hash = FNV_OFFSET;
  for (const byte of new TextEncoder().encode(value)) {
    hash ^= BigInt(byte);
    hash = (hash * FNV_PRIME) & FNV_MASK;
  }
  return hash;
}

function suffixFor(identity, retry, hash64 = fnv1a64) {
  const input = ['junos-id-v1', identity.context, identity.namespace,
    identity.kind, identity.stableKey, String(retry)].join('\0');
  return hash64(input).toString(36).padStart(13, '0');
}

function collisionName(base, suffix) {
  const prefix = base.slice(0, 63 - suffix.length - 1);
  return `${prefix}-${suffix}`;
}
```

Build exact source-name reference indexes before normalization. Reject duplicate `(context, namespace, kind, sourceName)` definitions with `duplicate_definition`; reject more than one compatible match with `ambiguous_reference`. Represent each unresolved reference as one synthetic symbol per `(context, namespace, compatibleKinds, sourceName)` and include it in allocation so it cannot share an output name with a real definition.

Allocate fixed singleton bases first. Allocate every collision-group member together, retry every conflicting candidate, and throw `allocation_failed` after 32 complete rounds. Construct maps keyed by definition path, reference path, and `${path}\0${role}` for generated lookups. Every missing lookup throws `missing_catalog_coverage`.

Generated mapping entries use `${ownerPath}#generated:${role}` as their auditable synthetic `definitionPath`; callers still retrieve them with `nameForGenerated(ownerPath, role)`. `collisionCount` counts renamed definitions, including generated definitions, but excludes unresolved external symbols.

Emit one exact warning per renamed definition:

```js
{
  type: 'warning',
  category: 'identifier',
  subType: 'identifier_collision',
  element: definitionPath,
  message: `Resolved ${namespace} identifier collision for "${sourceName}" as "${outputName}".`,
  suggestion: 'Review the identifier mapping before deployment.',
  context,
  namespace,
  sourceName,
  normalizedBase,
  outputName,
  definitionPath,
  referenceCount,
}
```

- [ ] **Step 4: Implement strict mapping validation and freezing**

Use this exact entry field allowlist and resolution set:

```js
const ENTRY_FIELDS = [
  'context', 'namespace', 'kind', 'sourceName', 'outputName',
  'definitionPath', 'referencePaths', 'resolution',
];
const RESOLUTIONS = new Set([
  'unchanged', 'collision-renamed', 'generated',
  'generated-collision-renamed', 'unresolved-reference',
  'unresolved-collision-renamed',
]);
```

`validateIdentifierMappings()` must return a deep-frozen defensive copy, reject unknown versions/fields/resolutions, unsafe strings, invalid output names, duplicate semantic definitions, duplicate output names, non-null definition paths on unresolved entries, null paths on definitions, and unsorted/duplicate reference paths. Errors use `invalid_identifier_mapping` and never include full config artifacts.

- [ ] **Step 5: Run allocator tests and the existing serializer suite**

Run: `npx vitest run tests/junos-identifiers.test.js tests/junos-serialization.test.js`

Expected: both files PASS; forced persistent collision produces `allocation_failed` rather than a shared name.

- [ ] **Step 6: Commit the allocator**

```bash
git add src/security/junos-identifiers.js tests/junos-identifiers.test.js
git commit -m "feat: add deterministic Junos identifier allocator"
```

## Task 2: Build the Complete Identifier Catalog

**Files:**
- Create: `src/security/junos-identifier-catalog.js`
- Modify: `src/security/junos-identifiers.js`
- Modify: `tests/junos-identifiers.test.js`

**Interfaces:**
- Consumes: `createJunosIdentifierPlan({ definitions, references }, options)` from Task 1.
- Produces: `collectJunosIdentifierSymbols()`, `collectMergedJunosIdentifierSymbols()`, `planJunosIdentifiers()`, `planMergedJunosIdentifiers()`, and exported catalog keys.

- [ ] **Step 1: Add failing catalog collection tests**

Use one fixture containing zones, address/address-set, services/service-groups, applications/application-groups, schedules, policies, all NAT types, routing, VPN, screen, profiles, L2, PBF, DHCP, QoS, flow monitoring, AAA, and SNMP. Assert exact path coverage:

```js
const symbols = collectJunosIdentifierSymbols(fullConfig(), {
  targetContext: { type: 'logical-system', name: 'branch a' },
});
const paths = new Set([
  ...symbols.definitions.map(item => item.definitionPath),
  ...symbols.references.map(item => item.referencePath),
]);

expect([...paths]).toEqual(expect.arrayContaining([
  'targetContext.name',
  'zones[0].name',
  'address_objects[0].name',
  'address_groups[0].members[0]',
  'security_policies[0].name',
  'security_policies[0].dst_addresses[0]',
  'nat_rules[0].name',
  'vpn_tunnels[0].name',
  'bridge_domains[0].name',
  'pbf_rules[0].name',
]));
```

Assert address/address-set share `address-book-entry`, policies use a zone-pair context, BGP groups include routing-instance context, and predefined application literals do not produce definitions.

- [ ] **Step 2: Run the catalog test and confirm red state**

Run: `npx vitest run tests/junos-identifiers.test.js -t "catalog"`

Expected: FAIL because the catalog module and planning wrappers do not exist.

- [ ] **Step 3: Implement declarative catalog helpers**

Export frozen keys rather than string literals scattered through converters:

```js
export const JUNOS_IDENTIFIER_CATALOG = Object.freeze({
  TARGET_CONTEXT: 'target-context',
  ZONE: 'zone',
  ADDRESS_BOOK: 'address-book',
  APPLICATION: 'application',
  POLICY: 'security-policy',
  SCHEDULER: 'scheduler',
  NAT_RULE_SET: 'nat-rule-set',
  NAT_RULE: 'nat-rule',
  NAT_POOL: 'nat-pool',
  ROUTING_INSTANCE: 'routing-instance',
  ROUTING_POLICY: 'routing-policy',
  BGP_GROUP: 'bgp-group',
  SCREEN: 'screen-profile',
  IKE: 'ike',
  IPSEC: 'ipsec',
  SECURITY_PROFILE: 'security-profile',
  VLAN: 'vlan',
  BRIDGE_DOMAIN: 'bridge-domain',
  PBF: 'pbf',
  DHCP: 'dhcp',
  QOS: 'qos',
  FLOW: 'flow-monitoring',
  AAA: 'aaa',
  SNMP: 'snmp',
});
```

Implement `addDefinition()`, `addReference()`, and `addGenerated()` as the only ways traversal adds records. Normalize arrays with `value || []`, preserve exact source strings, derive context with explicit helpers, and supply literal sets for `any`, Junos predefined applications, and other existing built-ins.

- [ ] **Step 4: Cover every current converter namespace**

Use this coverage matrix while writing the traversal; every row must create definitions and matching references/generated children where the converter emits them:

| Converter area | Namespace/context |
|---|---|
| target wrapper, merge slots | root logical-system/tenant |
| zones, cross-link zones | per logical-system zone |
| addresses + address sets | per address book shared namespace |
| services/apps + groups | applications namespace with compatible kinds |
| policies | per logical-system and resolved zone pair |
| schedulers | per logical-system scheduler |
| source/destination/static NAT | rule-set, rule-per-set, pool namespaces |
| static/BGP/OSPF/EVPN/VXLAN/PBF routing | routing instance, BGP group, policy/filter/term scopes |
| screen | screen profile and zone reference |
| IKE/IPsec/VPN | proposal, policy, gateway, VPN namespaces |
| UTM/IDP/SecIntel/SSL | each Junos profile/rule-set namespace |
| VLAN/L2/vwire | VLAN and bridge-domain namespaces |
| DHCP | pool and range-per-pool namespaces |
| QoS | classifier, scheduler, scheduler-map namespaces |
| flow monitoring | instance and template namespaces |
| AAA/SNMP | access profile/user and community/trap-group namespaces |

Register generated names from the same preferred-name expressions currently used by emitters, including `pool-${rule.name}`, `dnat-pool-${rule.name}`, `ike-pol-${vpnName}`, `ipsec-pol-${vpnName}`, `PBF-${rule.name}`, `ssl-fwd-${profile}`, and `ssl-inbound-${profile}`.

- [ ] **Step 5: Wire the public planning wrappers**

Add exact wrappers to `junos-identifiers.js`:

```js
export function planJunosIdentifiers(config, options = {}) {
  return createJunosIdentifierPlan(
    collectJunosIdentifierSymbols(config, options),
    options,
  );
}

export function planMergedJunosIdentifiers(configSlots, crossLsLinks = [], globalConfig = {}, options = {}) {
  return createJunosIdentifierPlan(
    collectMergedJunosIdentifierSymbols(configSlots, crossLsLinks, globalConfig, options),
    options,
  );
}
```

- [ ] **Step 6: Run catalog and allocator tests**

Run: `npx vitest run tests/junos-identifiers.test.js`

Expected: PASS with every coverage-matrix namespace represented and no order-dependent output names.

- [ ] **Step 7: Commit the catalog**

```bash
git add src/security/junos-identifier-catalog.js src/security/junos-identifiers.js tests/junos-identifiers.test.js
git commit -m "feat: catalog Junos identifier namespaces"
```

## Task 3: Preserve Exact Names in Check Point and SonicWall Parsers

**Files:**
- Create: `tests/parser-name-preservation.test.js`
- Modify: `src/parsers/checkpoint-parser.js`
- Modify: `src/parsers/sonicwall-parser.js`

**Interfaces:**
- Consumes: existing `parseCheckPointConfig(text)` and `parseSonicWallConfig(text)`.
- Produces: intermediate definitions/references with exact source spelling; no planner API changes.

- [ ] **Step 1: Write failing parser regression tests**

Use JSON exports with colliding names and exact member references:

```js
it('preserves Check Point object and member spelling', () => {
  const input = JSON.stringify({
    'objects-dictionary': [
      { uid: 'h1', type: 'host', name: 'Web Server', 'ipv4-address': '192.0.2.10' },
      { uid: 'h2', type: 'host', name: 'Web@Server', 'ipv4-address': '192.0.2.11' },
      { uid: 'g1', type: 'group', name: 'Prod Group', members: ['h1', 'h2'] },
    ],
    rulebase: [],
  });
  const config = parseCheckPointConfig(input).intermediateConfig;
  expect(config.address_objects.map(item => item.name)).toEqual(['Web Server', 'Web@Server']);
  expect(config.address_groups[0]).toMatchObject({
    name: 'Prod Group',
    members: ['Web Server', 'Web@Server'],
  });
});

it('preserves SonicWall object and rule spelling', () => {
  const input = JSON.stringify({
    address_objects: { ipv4: [{ name: 'Web Server', ip: '192.0.2.10', mask: '255.255.255.255' }] },
    access_rules: { ipv4: [{ name: 'Allow Web @ HQ', source: { address: 'any' }, destination: { address: 'Web Server' } }] },
  });
  const config = parseSonicWallConfig(input).intermediateConfig;
  expect(config.address_objects[0].name).toBe('Web Server');
  expect(config.security_policies[0].name).toBe('Allow Web @ HQ');
});
```

- [ ] **Step 2: Run tests and confirm normalized output causes failure**

Run: `npx vitest run tests/parser-name-preservation.test.js`

Expected: FAIL because current parser code changes spaces/punctuation to dashes.

- [ ] **Step 3: Remove premature symbol normalization**

Remove `sanitizeJunosName` from parser imports when no non-symbol use remains. Replace every definition/reference call in Check Point object, group, service, service-group, access-rule, NAT-rule, and derived-zone construction with the exact source string. For DNS-domain objects, preserve the established semantic removal of the leading dot but do not otherwise normalize:

```js
name: name.replace(/^\./, ''),
members: members,
src_addresses: srcAddrs,
dst_addresses: dstAddrs,
services: serviceNames,
```

Apply the same rule to SonicWall object, policy, and NAT names. Keep descriptive fallback generation such as `Rule-${index}` and `NAT-${index}` intact; the planner handles its resulting identifier.

- [ ] **Step 4: Run parser and conversion security tests**

Run: `npx vitest run tests/parser-name-preservation.test.js tests/conversion-security.test.js tests/srx-injection-defense.test.js`

Expected: PASS; unsafe controls still fail in input validation even though printable punctuation survives parsing.

- [ ] **Step 5: Commit parser preservation**

```bash
git add tests/parser-name-preservation.test.js src/parsers/checkpoint-parser.js src/parsers/sonicwall-parser.js
git commit -m "fix: preserve source identifiers during parsing"
```

## Task 4: Integrate Core Symbols into Set Conversion

**Files:**
- Create: `tests/junos-identifier-integration.test.js`
- Modify: `src/converters/srx-converter.js`

**Interfaces:**
- Consumes: `planJunosIdentifiers()` and plan lookup methods.
- Produces: Set output `{ commands, warnings, summary, identifierMappings }` for zones, addresses/groups, applications/groups, schedules, policies, and NAT.

- [ ] **Step 1: Write failing Set collision/reference tests**

Build a config with `Web Server` and `Web@Server`, a group referencing both, and two policies referencing one each. Assert definitions and every reference use mapping output names:

```js
const result = convertToSrxSetCommands(collisionConfig());
const addressEntries = result.identifierMappings.entries.filter(
  entry => entry.namespace === 'address-book-entry' && entry.kind === 'address',
);
expect(new Set(addressEntries.map(entry => entry.outputName)).size).toBe(2);
for (const entry of addressEntries) {
  expect(result.commands).toContain(
    `set security address-book global address ${entry.outputName} ${entry.sourceName === 'Web Server' ? '192.0.2.10/32' : '192.0.2.11/32'}`,
  );
  expect(result.commands.some(command => command.endsWith(` ${entry.outputName}`))).toBe(true);
}
expect(result.summary.identifier_collisions_resolved).toBe(2);
expect(result.warnings.filter(item => item.subType === 'identifier_collision')).toHaveLength(2);
```

Add same-zone-pair duplicate policy failure, different-zone-pair policy allowance, NAT rule/pool collision, and predefined application bypass cases.

- [ ] **Step 2: Run focused integration tests and confirm red state**

Run: `npx vitest run tests/junos-identifier-integration.test.js -t "Set"`

Expected: FAIL because Set output has no mapping and still normalizes definitions/references independently.

- [ ] **Step 3: Create one plan at the Set entry point**

Extend the function only with an internal options parameter so existing callers remain compatible:

```js
export function convertToSrxSetCommands(
  config,
  interfaceMappings = {},
  targetContext = null,
  options = {},
) {
  const identifiers = options.identifierPlan || planJunosIdentifiers(config, { targetContext });
  const identifierPath = localPath => `${options.pathPrefix || ''}${localPath}`;
  const targetContextPath = options.targetContextPath || 'targetContext.name';
  const warnings = [...identifiers.warnings];
  const summary = {
    identifier_collisions_resolved: identifiers.collisionCount,
    zones_converted: 0,
    addresses_converted: 0,
    address_groups_converted: 0,
    services_converted: 0,
    policies_converted: 0,
    nat_rules_converted: 0,
    static_routes_converted: 0,
    bgp_groups_converted: 0,
    bgp_neighbors_converted: 0,
    ospf_areas_converted: 0,
    ospf_interfaces_converted: 0,
    lag_interfaces_converted: 0,
    total_warnings: 0,
    unsupported_items: 0,
  };
```

Return `identifierMappings: identifiers.mapping`. Pass `identifiers` and `identifierPath` into conversion helpers. Resolve a target wrapper through `targetContextPath`; do not treat a merged logical-system output name as new source input.

- [ ] **Step 4: Replace core definition/reference normalization**

Use lookups rather than a second sanitizer call:

```js
const name = identifiers.nameForDefinition(identifierPath(`address_objects[${index}].name`));
const memberName = identifiers.nameForReference(
  identifierPath(`address_groups[${groupIndex}].members[${memberIndex}]`),
);
const policyName = identifiers.nameForDefinition(identifierPath(`security_policies[${policyIndex}].name`));
const addressName = identifiers.nameForReference(
  identifierPath(`security_policies[${policyIndex}].dst_addresses[${addressIndex}]`),
);
const poolName = identifiers.nameForGenerated(
  identifierPath(`nat_rules[${ruleIndex}].name`),
  'source-nat-pool',
);
```

Apply this pattern to target context, zones, address objects/groups, service/application definitions/groups, generated custom applications, schedules, policy zone/address/application/schedule/profile references, NAT rule sets/rules/pools, and NAT zone/address references. Keep `sanitizeJunosName()` only at catalog-declared non-symbol scalar positions.

- [ ] **Step 5: Run Set integration and existing converter suites**

Run: `npx vitest run tests/junos-identifier-integration.test.js tests/srx-converter-apps.test.js tests/srx-injection-defense.test.js`

Expected: PASS; Set mappings are complete for core symbols and all generated commands pass artifact validation.

- [ ] **Step 6: Commit core Set integration**

```bash
git add tests/junos-identifier-integration.test.js src/converters/srx-converter.js
git commit -m "feat: apply identifier plans to Set conversion"
```

## Task 5: Integrate Advanced Set Namespaces

**Files:**
- Modify: `src/converters/srx-converter.js`
- Modify: `tests/junos-identifier-integration.test.js`

**Interfaces:**
- Consumes: the Set entry-point plan from Task 4 and catalog paths from Task 2.
- Produces: planner-only naming for every remaining advanced Set identifier.

- [ ] **Step 1: Add failing table-driven advanced namespace tests**

Create a table whose mutate callback adds two punctuation-colliding definitions and whose command pattern proves both outputs are emitted:

```js
it.each([
  ['routing instance', addRoutingInstanceCollision, /set routing-instances /],
  ['BGP group', addBgpGroupCollision, / protocols bgp group /],
  ['screen profile', addScreenCollision, / screen ids-option /],
  ['VPN', addVpnCollision, / security ipsec vpn /],
  ['SNMP community', addSnmpCollision, /set snmp community /],
  ['DHCP pool', addDhcpCollision, / access address-assignment pool /],
  ['bridge domain', addBridgeDomainCollision, /set bridge-domains /],
  ['PBF term', addPbfCollision, / firewall family inet filter /],
  ['flow template', addFlowTemplateCollision, / services flow-monitoring version/],
])('keeps colliding %s identifiers distinct', (_label, mutate, commandPattern) => {
  const config = baseAdvancedConfig();
  mutate(config);
  const result = convertToSrxSetCommands(config);
  expect(result.commands.some(command => commandPattern.test(command))).toBe(true);
  expectNamespaceOutputsUnique(result.identifierMappings);
});
```

Include UTM/IDP/SecIntel/AppFW/SSL, IKE/IPsec proposals/policies/gateways, VLAN, QoS, AAA, and generated routing-policy coverage in the table.

- [ ] **Step 2: Run advanced tests and confirm remaining bypasses**

Run: `npx vitest run tests/junos-identifier-integration.test.js -t "colliding"`

Expected: FAIL for advanced areas still calling `sanitizeJunosName()` directly.

- [ ] **Step 3: Thread plan lookups through advanced helper functions**

Add `identifiers` and stable path/index arguments to routing, screen, VPN, SNMP, AAA, DHCP, QoS, L2, PBF, SSL, flow-monitoring, and security-profile helpers. Replace each definition, reference, and generated preferred name with `nameForDefinition`, `nameForReference`, or `nameForGenerated` using the exact path registered in the catalog.

Do not plan interface names, IP/prefix values, protocol enums, ports, numeric IDs, extension match values, or free text. Keep their existing serializers.

- [ ] **Step 4: Prove no advanced Set collision remains**

Run: `npx vitest run tests/junos-identifier-integration.test.js tests/srx-injection-defense.test.js tests/junos-validation.test.js`

Expected: PASS; all mapping namespaces have unique output names and Set artifact validation remains green.

- [ ] **Step 5: Commit advanced Set integration**

```bash
git add src/converters/srx-converter.js tests/junos-identifier-integration.test.js
git commit -m "feat: plan advanced Set identifiers"
```

## Task 6: Integrate the Same Plan into XML Conversion

**Files:**
- Modify: `src/converters/srx-xml-builder.js`
- Modify: `tests/junos-identifier-integration.test.js`

**Interfaces:**
- Consumes: `planJunosIdentifiers()` and the same catalog paths used by Set.
- Produces: XML output `{ xml, warnings, summary, identifierMappings }` with mapping deep-equal to Set for the same input.

- [ ] **Step 1: Add failing Set/XML parity tests**

```js
it('uses identical identifier mappings in Set and XML', () => {
  const config = fullCollisionConfig();
  const setResult = convertToSrxSetCommands(config);
  const xmlResult = buildSrxXml(config);
  expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
  expect(xmlResult.summary.identifier_collisions_resolved)
    .toBe(setResult.summary.identifier_collisions_resolved);
  for (const entry of xmlResult.identifierMappings.entries) {
    if (entry.definitionPath !== null) {
      expect(xmlResult.xml).toContain(`>${entry.outputName}<`);
    }
  }
});
```

Add a test that malformed exact duplicate input throws the same `code`, `namespace`, and `context` in both formats.

- [ ] **Step 2: Run XML parity tests and confirm red state**

Run: `npx vitest run tests/junos-identifier-integration.test.js -t "XML|identical"`

Expected: FAIL because XML independently normalizes symbols and returns no mapping.

- [ ] **Step 3: Create or accept one plan at the XML entry point**

Preserve existing XML options while allowing a supplied plan:

```js
export function buildSrxXml(config, interfaceMappings = {}, targetContext = null, options = {}) {
  const identifiers = options.identifierPlan || planJunosIdentifiers(config, { targetContext });
  const identifierPath = localPath => `${options.pathPrefix || ''}${localPath}`;
  const targetContextPath = options.targetContextPath || 'targetContext.name';
  const warnings = [...identifiers.warnings];
  const summary = {
    identifier_collisions_resolved: identifiers.collisionCount,
  };
```

Return `summary` and `identifierMappings: identifiers.mapping` beside `xml` and `warnings`.

- [ ] **Step 4: Replace all XML symbol normalization with plan lookups**

Thread `identifiers` and exact path/index arguments through `buildZonesXml`, `buildAddressBookXml`, `buildPoliciesXml`, `buildNatXml`, `buildApplicationsXml`, `buildSchedulersXml`, and every advanced builder listed in Task 5. Use `xmlText(plannedName, path)` only after lookup:

```js
const path = identifierPath(`address_objects[${index}].name`);
const outputName = identifiers.nameForDefinition(path);
lines.push(`        <name>${xmlText(outputName, path)}</name>`);
```

Do not call `sanitizeJunosName()` or `setIdentifier()` again for a cataloged symbol.

- [ ] **Step 5: Run parity, injection, and XML validation suites**

Run: `npx vitest run tests/junos-identifier-integration.test.js tests/srx-injection-defense.test.js tests/junos-validation.test.js`

Expected: PASS; Set/XML mappings are deeply equal and both artifacts reference the mapped names.

- [ ] **Step 6: Commit XML integration**

```bash
git add src/converters/srx-xml-builder.js tests/junos-identifier-integration.test.js
git commit -m "feat: apply identifier plans to XML conversion"
```

## Task 7: Plan Merged Logical Systems and Cross-Links Once

**Files:**
- Modify: `src/converters/srx-converter.js`
- Modify: `src/converters/srx-xml-builder.js`
- Modify: `tests/junos-identifier-integration.test.js`

**Interfaces:**
- Consumes: `planMergedJunosIdentifiers()` and single-converter `options.identifierPlan`.
- Produces: one mapping for root logical systems, slot-local symbols, global config, and cross-link references.

- [ ] **Step 1: Add failing merge-scope tests**

```js
it('isolates local namespaces and keeps cross-link references correct', () => {
  const slots = [
    mergeSlot('Branch A', configWithAddress('Web Server')),
    mergeSlot('Branch@A', configWithAddress('Web Server')),
  ];
  const links = [{
    ls1: 'Branch A', ls2: 'Branch@A', sharedZone: 'Shared Zone',
    lt1Unit: 1, lt2Unit: 2,
  }];
  const setResult = convertMergedToSrxSetCommands(slots, links);
  const xmlResult = buildMergedSrxXml(slots, links);
  expect(setResult.identifierMappings).toEqual(xmlResult.identifierMappings);
  expectNamespaceOutputsUnique(setResult.identifierMappings);
  expect(localEntries(setResult, 'Web Server').map(item => item.outputName))
    .toEqual(['Web-Server', 'Web-Server']);
  expect(rootLogicalSystems(setResult).map(item => item.outputName))
    .toHaveLength(2);
});
```

Add reordered slot/link tests proving output-name association is stable, and an ambiguous/unknown logical-system endpoint test that fails or remains non-binding according to existing link validation.

- [ ] **Step 2: Run merge tests and confirm red state**

Run: `npx vitest run tests/junos-identifier-integration.test.js -t "merge|logical"`

Expected: FAIL because each slot currently creates its own plan and cross-links use independent serialization.

- [ ] **Step 3: Build a merged plan before any output emission**

At each merged entry point:

```js
const identifiers = planMergedJunosIdentifiers(
  configSlots,
  crossLsLinks,
  globalConfig,
);
```

Derive each slot's logical-system output name from the merged plan. Pass the same plan into the single converter instead of replanning the slot, using this exact options contract:

```js
{
  identifierPlan: identifiers,
  pathPrefix: `configSlots[${slotIndex}].intermediateConfig.`,
  targetContextPath: `configSlots[${slotIndex}].lsName`,
}
```

Keep the target-context source value as `slot.lsName`; the single converter emits its planned name through `targetContextPath`. Resolve `crossLsLinks[*].ls1`, `ls2`, and `sharedZone` from the plan. Pass the merged plan and `globalConfig.` prefix through named global helpers so any global SNMP, AAA, or security symbols use the root namespace rather than bypassing planning.

- [ ] **Step 4: Return merged mapping, warnings, and summary**

Prepend planner warnings once, attach logical-system metadata to ordinary per-slot warnings as today, and set:

```js
mergedSummary.identifier_collisions_resolved = identifiers.collisionCount;
return {
  commands: allCommands,
  warnings: allWarnings,
  summary: mergedSummary,
  identifierMappings: identifiers.mapping,
};
```

Return the equivalent fields from merged XML.

- [ ] **Step 5: Run all identifier and merge security tests**

Run: `npx vitest run tests/junos-identifiers.test.js tests/junos-identifier-integration.test.js tests/srx-injection-defense.test.js tests/conversion-security.test.js`

Expected: PASS for both formats and stable merged mappings.

- [ ] **Step 6: Commit merged planning**

```bash
git add src/converters/srx-converter.js src/converters/srx-xml-builder.js tests/junos-identifier-integration.test.js
git commit -m "feat: plan merged logical-system identifiers"
```

## Task 8: Enforce Mapping-Bearing Canonical Output and Project v4 Migration

**Files:**
- Modify: `src/conversion/conversion-output.js`
- Modify: `public/utils/project-io.js`
- Modify: `tests/conversion-output.test.js`
- Modify: `tests/project-io.test.js`

**Interfaces:**
- Consumes: `validateIdentifierMappings()` and mapping-bearing converter results.
- Produces: strict canonical output and project version `4` migration behavior.

- [ ] **Step 1: Add failing canonical-output tests**

Create one reusable valid mapping:

```js
const IDENTIFIER_MAPPINGS = {
  version: 1,
  entries: [{
    context: 'root', namespace: 'zone', kind: 'zone',
    sourceName: 'trust', outputName: 'trust',
    definitionPath: 'zones[0].name', referencePaths: [],
    resolution: 'unchanged',
  }],
};

it('requires and defensively copies identifier mappings', () => {
  expect(() => normalizeConversionOutput({ commands: SET_COMMANDS }, 'set'))
    .toThrow(/identifier mapping/i);
  const output = normalizeConversionOutput({
    commands: SET_COMMANDS,
    identifierMappings: IDENTIFIER_MAPPINGS,
  }, 'set');
  expect(output.identifierMappings).toEqual(IDENTIFIER_MAPPINGS);
  expect(Object.isFrozen(output.identifierMappings)).toBe(true);
});
```

Update all existing canonical fixtures in this file to include an empty valid mapping `{ version: 1, entries: [] }` unless the test specifically asserts missing/invalid rejection.

- [ ] **Step 2: Add failing project v4 migration tests**

```js
it('clears unmapped legacy artifacts but preserves editable state', () => {
  const result = validateProjectFile({
    fpic_version: 3,
    name: 'legacy',
    state: {
      ...baseState,
      srxOutput: { format: 'set', commands: ['set system host-name edge'] },
      convertWarnings: [{ type: 'warning' }],
      conversionSummary: { policies_converted: 1 },
      outputFormat: 'set',
    },
  });
  expect(result.valid).toBe(true);
  expect(result.project.fpic_version).toBe(4);
  expect(result.project.state.intermediateConfig).toEqual(baseState.intermediateConfig);
  expect(result.project.state.srxOutput).toBeNull();
  expect(result.project.state.convertWarnings).toEqual([]);
  expect(result.project.state.conversionSummary).toBeNull();
  expect(result.warnings.join(' ')).toMatch(/reconvert/i);
});
```

Add v4 round-trip, legacy valid-mapping retention, v4 missing-mapping rejection, and malformed claimed legacy mapping rejection.

- [ ] **Step 3: Run output/project tests and confirm red state**

Run: `npx vitest run tests/conversion-output.test.js tests/project-io.test.js`

Expected: FAIL because mappings are optional and the current project version is 3.

- [ ] **Step 4: Enforce mappings in the canonical output module**

Import `validateIdentifierMappings`. In both Set and XML normalizer branches, require an own `identifierMappings` field and replace it with the validated frozen copy before artifact validation. `replaceSetCommands()` retains the mapping through object spread and revalidation.

- [ ] **Step 5: Implement project version 4 migration**

Set `CURRENT_VERSION = 4`. Make migration return whether stale output was cleared so `validateProjectFile()` can append exactly:

```js
'Generated output from this older project was cleared because it has no validated identifier mapping. Reconvert before export or device push.'
```

For v1-3: retain null output; retain and normalize output only when `validateIdentifierMappings()` succeeds; clear absent mappings; reject a present but malformed mapping. For v4: reject every non-null missing or invalid mapping. Clear `convertWarnings` and `conversionSummary` only when output is cleared.

- [ ] **Step 6: Run canonical output, project, and consumer tests**

Run: `npx vitest run tests/conversion-output.test.js tests/project-io.test.js tests/conversion-consumers.test.js tests/conversion-enforcement.test.js`

Expected: PASS with v4 saves and safe legacy invalidation.

- [ ] **Step 7: Commit output and project enforcement**

```bash
git add src/conversion/conversion-output.js public/utils/project-io.js tests/conversion-output.test.js tests/project-io.test.js
git commit -m "fix: require identifier mappings in saved output"
```

## Task 9: Integrate Engine Boundaries, Safe Errors, Warnings, and Summary

**Files:**
- Modify: `public/utils/engine.js`
- Modify: `public/hooks/useConversion.js`
- Modify: `tests/conversion-security.test.js`

**Interfaces:**
- Consumes: mapping-bearing converters, canonical normalizer, and `JunosIdentifierPlanningError`.
- Produces: safe browser errors and mapping/warning metadata through single and merged engine paths.

- [ ] **Step 1: Add failing public-boundary tests**

```js
it('formats identifier planning errors without configuration content', () => {
  const error = new JunosIdentifierPlanningError('ambiguous_reference', {
    namespace: 'address-book-entry',
    context: 'root/address-book:global',
    sourceName: 'Web Server',
    referencePaths: ['security_policies[0].dst_addresses[0]'],
    reason: 'reference matches more than one definition',
  });
  const message = formatJunosSerializationError(error, 'Conversion');
  expect(message).toContain('Conversion blocked');
  expect(message).toContain('ambiguous_reference');
  expect(message).not.toContain('set security');
});

it('returns mappings and collision metadata through public engines', async () => {
  const single = await convertConfig(collisionConfig(), 'set');
  const merged = await mergeConvert([mergeSlot('Branch', collisionConfig())], [], 'xml');
  expect(single.output.identifierMappings.version).toBe(1);
  expect(single.output.summary.identifier_collisions_resolved).toBeGreaterThan(0);
  expect(merged.output.identifierMappings.version).toBe(1);
});
```

- [ ] **Step 2: Run boundary tests and confirm red state**

Run: `npx vitest run tests/conversion-security.test.js`

Expected: FAIL until planning errors are recognized and engine output retains validated mappings.

- [ ] **Step 3: Format planning errors safely**

Import `JunosIdentifierPlanningError` in `useConversion.js` and add this branch before the generic error:

```js
if (error instanceof JunosIdentifierPlanningError) {
  const location = error.referencePaths?.[0] || error.definitionPaths?.[0] || error.context;
  return `${prefix} blocked: ${error.code}${location ? ` at ${location}` : ''} — ${error.reason}`;
}
```

Keep stale-output clearing in both conversion catch paths.

- [ ] **Step 4: Assert engine normalization preserves planner metadata**

Ensure `normalizeEngineOutput()` passes the entire converter result to `normalizeConversionOutput()` rather than reconstructing only content/warnings/summary. Keep artifact validation before normalization. Verify analysis counters mutate only `output.summary`, never `identifierMappings`.

- [ ] **Step 5: Run boundary, context, and workflow tests**

Run: `npx vitest run tests/conversion-security.test.js tests/context-reducers.test.js tests/workflow-steps.test.js`

Expected: PASS; the existing Warnings panel receives `identifier_collision` items through `convertWarnings` without a new component.

- [ ] **Step 6: Commit boundary integration**

```bash
git add public/utils/engine.js public/hooks/useConversion.js tests/conversion-security.test.js
git commit -m "fix: surface identifier planning failures safely"
```

## Task 10: Add Catalog-Bypass and Randomized Integrity Gates

**Files:**
- Modify: `tests/junos-identifier-integration.test.js`
- Modify: `tests/srx-injection-defense.test.js`

**Interfaces:**
- Consumes: complete converter integration from Tasks 4-7.
- Produces: regression gates that reject future direct normalization and probabilistically exercise uniqueness/order invariants.

- [ ] **Step 1: Add a failing source-contract test**

Read both converter sources and require every remaining sanitizer call to carry the explicit marker `// identifier-catalog: non-symbol <reason>` on the same line or immediately above:

```js
for (const relativePath of [
  '../src/converters/srx-converter.js',
  '../src/converters/srx-xml-builder.js',
]) {
  const source = fs.readFileSync(new URL(relativePath, import.meta.url), 'utf8');
  const lines = source.split('\n');
  lines.forEach((line, index) => {
    if (!/sanitizeJunosName\(|setIdentifier\(/.test(line)) return;
    const documented = `${lines[index - 1] || ''}\n${line}`
      .includes('identifier-catalog: non-symbol');
    expect(documented, `${relativePath}:${index + 1}`).toBe(true);
  });
}
```

The planner module itself is excluded because it owns base normalization. Cataloged symbols must have no exception marker.

- [ ] **Step 2: Run the source-contract test and confirm red state**

Run: `npx vitest run tests/srx-injection-defense.test.js -t "identifier catalog"`

Expected: FAIL and list every remaining unclassified sanitizer call by file and line.

- [ ] **Step 3: Classify or remove every reported call**

Replace any symbol call with a plan lookup. For genuine non-symbol uses such as extension match values, dynamic-application category tokens, or constrained scalar validation, add a precise marker, for example:

```js
// identifier-catalog: non-symbol block-extension match value
const extension = sanitizeJunosName(ext);
```

The reason must name the Junos scalar field; generic markers fail review.

- [ ] **Step 4: Add deterministic randomized tests**

Use a local seeded generator, not `Math.random()`, to create 200 names from punctuation, whitespace, repeated dashes, numeric prefixes, case variants, and common 70-character prefixes. For each seed:

```js
const first = createJunosIdentifierPlan(makeRandomSymbols(seed));
const second = createJunosIdentifierPlan(reverseSymbols(makeRandomSymbols(seed)));
expect(mappingBySource(first.mapping)).toEqual(mappingBySource(second.mapping));
expectNamespaceOutputsUnique(first.mapping);
for (const reference of generatedReferencePaths(seed)) {
  expect(first.nameForReference(reference.path)).toBe(
    first.nameForDefinition(reference.definitionPath),
  );
}
```

Include unresolved references and generated children in at least 25 seeds.

- [ ] **Step 5: Run all JavaScript security and identifier tests**

Run: `npx vitest run tests/junos-identifiers.test.js tests/junos-identifier-integration.test.js tests/parser-name-preservation.test.js tests/srx-injection-defense.test.js tests/conversion-security.test.js tests/conversion-output.test.js tests/project-io.test.js`

Expected: all listed files PASS and source-contract scan reports no unclassified call.

- [ ] **Step 6: Commit the regression gates**

```bash
git add tests/junos-identifier-integration.test.js tests/srx-injection-defense.test.js src/converters/srx-converter.js src/converters/srx-xml-builder.js
git commit -m "test: enforce Junos identifier catalog coverage"
```

## Task 11: Full Verification and Issue Acceptance Audit

**Files:**
- Modify only if a verification failure reveals an issue in files already listed above.

**Interfaces:**
- Consumes: all completed tasks.
- Produces: evidence that the branch meets issue #10 and introduces no regression.

- [ ] **Step 1: Run formatting and repository hygiene checks**

Run:

```bash
git diff main...HEAD --check
git status --short
```

Expected: no whitespace errors; only intentional uncommitted verification fixes, or a clean worktree.

- [ ] **Step 2: Run the complete Vitest suite**

Run: `npx vitest run`

Expected: all Vitest files and tests PASS with no failed or skipped security tests.

- [ ] **Step 3: Run all self-running JavaScript suites**

Run:

```bash
node tests/app-mappings.test.js
node tests/bridge-client.test.js
node tests/day2-ops.test.js
node tests/llm-translate.test.js
node tests/srx-converter-apps.test.js
node tests/validation-engine.test.js
```

Expected: 87 app-mapping, 17 bridge-client, 56 day-2, 113 LLM-translate, 5 converter-app, and 60 validation tests PASS, adjusted only upward if this branch adds cases.

- [ ] **Step 4: Run Python bridge tests and dependency checks**

Run:

```bash
venv/bin/python -m pytest tools/pyez-bridge/tests -q
venv/bin/python -m pip check
npm audit --audit-level=high
```

Expected: 85 or more Python tests PASS, `pip check` reports no broken requirements, and npm reports 0 high/critical vulnerabilities.

- [ ] **Step 5: Build production artifacts**

Run: `npm run build`

Expected: Vite production build succeeds; only the pre-existing dynamic-import warning is acceptable.

- [ ] **Step 6: Audit every issue acceptance item against evidence**

Record the exact passing test names for:

```text
no silent shared identifier
stable deterministic rename
definition/reference parity
Set/XML equality
merge logical-system isolation
warnings and summary
project v4 migration
punctuation, whitespace, case, dash collapse, empty, numeric prefix, truncation
exact duplicate, ambiguous reference, forced collision, catalog coverage
```

If any line lacks a named test, add the missing test, run it red against the pre-fix behavior where practical, implement the smallest correction, rerun the focused and complete suites, and commit that correction separately.

- [ ] **Step 7: Commit any verification correction and confirm clean state**

```bash
git add src/security/junos-identifiers.js src/security/junos-identifier-catalog.js src/converters/srx-converter.js src/converters/srx-xml-builder.js src/parsers/checkpoint-parser.js src/parsers/sonicwall-parser.js src/conversion/conversion-output.js public/utils/engine.js public/hooks/useConversion.js public/utils/project-io.js tests/junos-identifiers.test.js tests/junos-identifier-integration.test.js tests/parser-name-preservation.test.js tests/conversion-output.test.js tests/conversion-security.test.js tests/project-io.test.js tests/srx-injection-defense.test.js
git commit -m "fix: close identifier collision verification gap"
git status --short
```

Expected: clean worktree. If no correction was needed, do not create an empty commit.

## Task 12: Publish Through the Standard GitHub Workflow

**Files:**
- No source changes expected.

**Interfaces:**
- Consumes: clean, fully verified `agent/issue-10-identifier-collisions` branch.
- Produces: pushed branch, issue-linked PR, green CI, squash merge, green post-merge `main`, and cleaned worktree/branches.

- [ ] **Step 1: Rebase or merge the latest remote main safely**

Run:

```bash
git fetch origin
git log --oneline --decorate --max-count=5 HEAD origin/main
```

Expected: branch relationship is understood. If `origin/main` advanced, integrate it non-destructively, resolve only issue-related conflicts, and rerun Task 11 verification.

- [ ] **Step 2: Push the issue branch**

Run: `git push -u origin agent/issue-10-identifier-collisions`

Expected: remote tracking branch is created without force push.

- [ ] **Step 3: Open an issue-linked pull request**

Use the GitHub publishing workflow with title `fix: prevent normalized Junos identifier collisions`. The body must summarize the symbol plan, fail-closed cases, mapping/project migration, test evidence, and include `Closes #10`.

Expected: a new PR targets `main` from `agent/issue-10-identifier-collisions`.

- [ ] **Step 4: Monitor and fix CI until green**

Inspect every required GitHub Actions check and its logs. For any failure, reproduce locally, use systematic debugging, commit the minimal fix, push, and rerun the relevant local gates before waiting for CI again.

Expected: every required PR check passes.

- [ ] **Step 5: Review the final PR diff and merge**

Confirm the PR contains only issue #10 changes, has no unresolved review threads, and retains all required commits/tests. Squash merge using the repository's established convention.

Expected: PR merged and issue #10 closed.

- [ ] **Step 6: Verify post-merge main and clean up**

Wait for the `main` workflow triggered by the merge and confirm all jobs pass. Then update the primary checkout, remove the issue worktree, and delete local/remote feature branches only after merge and CI confirmation.

Expected: primary `main` is clean and synchronized, no issue #10 worktree remains, and issue #11 is next in sequence.

# Sub-Interfaces as Tagged Units Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Map PAN-OS 802.1Q sub-interfaces to tagged units on the parent's SRX physical port (`ethernet1/13.100 → ge-0/0/3.100 vlan-id 100`) instead of separate physical ports, and emit correct SRX VLAN tagging.

**Architecture:** Fix `buildDefaultMappings` to map sub-interfaces onto their parent's port; add VLAN-tagging emission (`flexible-vlan-tagging`, `vlan-id`, inferred `native-vlan-id`) to the converter; render sub-interface rows as derived units that follow the parent's port selection.

**Tech Stack:** JavaScript (ESM), React 18, Vitest.

## Global Constraints

- A sub-interface maps to `<parentSrxPortBase>.<unit>`; it never consumes its own physical port. If the parent is unmapped, leave the sub-interface unmapped (the converter's `mapInterfaceName` derives `parent.unit`).
- VLAN tag source is the parser's `iface.vlan` (string, e.g. `"100"`); a parent's own untagged IP has `iface.vlan === ''`.
- Native VLAN: when a physical port has tagged sub-units AND an untagged parent IP (a unit-0 interface with an IP and no vlan), emit `native-vlan-id <N>` where `N` is the lowest 1–4094 not in that port's sub-unit tag set, plus an "inferred — verify" caveat comment and warning. Keep the parent IP on unit 0 with no `vlan-id`.
- A physical port with tagged sub-units but no untagged parent IP: emit `flexible-vlan-tagging` and give every unit a `vlan-id`; no `native-vlan-id`.
- Plain interfaces with no tagged siblings: unchanged (no `flexible-vlan-tagging`).
- `const` over `let`; JSDoc on exported functions; early returns. Tests: `npx vitest run` (no `npm test`).

---

### Task 1: Sub-interface helpers and `buildDefaultMappings` two-pass

**Files:**
- Modify: `public/components/InterfaceMapper.jsx` (add helpers; rewrite `buildDefaultMappings`; export all three)
- Test: `tests/interface-mapper-subif.test.js` (create)

**Interfaces:**
- Produces (named exports from `InterfaceMapper.jsx`):
  - `isSubInterface(ifaceName: string) → boolean` — true for `ethernet1/13.100`, false for tunnels/loopbacks/parents.
  - `parentInterface(ifaceName: string) → string` — `ethernet1/13.100 → ethernet1/13`.
  - `buildDefaultMappings(intermediateConfig, targetModelData) → { [panosIface]: srxName }` — parents get physical ports; sub-interfaces get `<parentBase>.<unit>`.
- Consumes: existing `isTunnelInterface`, `isLoopbackInterface`, `getUnit` in the same file.

- [ ] **Step 1: Write the failing test**

Create `tests/interface-mapper-subif.test.js`:

```js
import { describe, it, expect } from 'vitest';
import { isSubInterface, parentInterface, buildDefaultMappings } from '../public/components/InterfaceMapper.jsx';

const TARGET = { ports: [
  { name: 'ge-0/0/0', speed: '1G', type: 'copper' },
  { name: 'ge-0/0/1', speed: '1G', type: 'copper' },
  { name: 'ge-0/0/2', speed: '1G', type: 'copper' },
] };

const CONFIG = { zones: [
  { name: 'INSIDE', interfaces: ['ethernet1/13', 'ethernet1/13.100', 'ethernet1/13.206'] },
] };

describe('sub-interface mapping helpers', () => {
  it('detects sub-interfaces and parents', () => {
    expect(isSubInterface('ethernet1/13.100')).toBe(true);
    expect(isSubInterface('ethernet1/13')).toBe(false);
    expect(isSubInterface('tunnel.10')).toBe(false);
    expect(isSubInterface('loopback.1')).toBe(false);
    expect(parentInterface('ethernet1/13.100')).toBe('ethernet1/13');
  });

  it('maps sub-interfaces onto the parent port, not new physical ports', () => {
    const m = buildDefaultMappings(CONFIG, TARGET);
    expect(m['ethernet1/13']).toBe('ge-0/0/0');            // parent → first port
    expect(m['ethernet1/13.100']).toBe('ge-0/0/0.100');    // sub → parent port + unit
    expect(m['ethernet1/13.206']).toBe('ge-0/0/0.206');
    // only ONE physical port consumed
    const physUsed = new Set(Object.values(m).map(v => v.split('.')[0]));
    expect(physUsed.has('ge-0/0/1')).toBe(false);
  });

  it('leaves a sub-interface unmapped when its parent has no mapping', () => {
    const m = buildDefaultMappings({ zones: [{ name: 'Z', interfaces: ['ethernet1/9.50'] }] }, { ports: [] });
    expect(m['ethernet1/9.50']).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/interface-mapper-subif.test.js`
Expected: FAIL — the three functions are not exported (and current `buildDefaultMappings` assigns separate ports).

- [ ] **Step 3: Add the helpers and rewrite `buildDefaultMappings`**

In `public/components/InterfaceMapper.jsx`, add near the other module helpers (after `getUnit`):

```js
/** PAN-OS logical L3 sub-interface, e.g. ethernet1/13.100 (parent + unit). */
export function isSubInterface(ifaceName) {
  return /\.\d+$/.test(ifaceName) && !isTunnelInterface(ifaceName) && !isLoopbackInterface(ifaceName);
}

/** Parent physical name of a sub-interface (ethernet1/13.100 → ethernet1/13). */
export function parentInterface(ifaceName) {
  return ifaceName.replace(/\.\d+$/, '');
}
```

Replace the existing `function buildDefaultMappings(...)` with an exported two-pass version:

```js
/**
 * Build default PAN-OS→SRX interface mappings. Parents and tunnels/loopbacks
 * get their own target; sub-interfaces map to a unit on their parent's port.
 * @param {object} intermediateConfig
 * @param {object} targetModelData - { ports: [{ name, speed, type }] }
 * @returns {{ [panosIface: string]: string }}
 */
export function buildDefaultMappings(intermediateConfig, targetModelData) {
  const mappings = {};
  const availablePorts = targetModelData ? [...targetModelData.ports] : [];
  const usedPorts = new Set();

  // Pass 1: tunnels, loopbacks, and parent physical interfaces.
  for (const zone of (intermediateConfig?.zones || [])) {
    for (const iface of (zone.interfaces || [])) {
      if (isTunnelInterface(iface)) {
        mappings[iface] = `st0.${getUnit(iface)}`;
      } else if (isLoopbackInterface(iface)) {
        mappings[iface] = `lo0.${getUnit(iface)}`;
      } else if (isSubInterface(iface)) {
        continue; // handled in pass 2
      } else {
        const port = availablePorts.find(p => !usedPorts.has(p.name));
        if (port) {
          mappings[iface] = port.name;
          usedPorts.add(port.name);
        }
      }
    }
  }

  // Pass 2: sub-interfaces → parent's SRX port base + this sub-interface's unit.
  for (const zone of (intermediateConfig?.zones || [])) {
    for (const iface of (zone.interfaces || [])) {
      if (!isSubInterface(iface)) continue;
      const parentSrx = mappings[parentInterface(iface)];
      if (!parentSrx) continue; // parent unmapped → let the converter derive it
      const parentBase = parentSrx.split('.')[0];
      const unit = iface.split('.').pop();
      mappings[iface] = `${parentBase}.${unit}`;
    }
  }

  return mappings;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run tests/interface-mapper-subif.test.js`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full suite**

Run: `npx vitest run`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add public/components/InterfaceMapper.jsx tests/interface-mapper-subif.test.js
git commit -m "feat(mapper): map PAN-OS sub-interfaces to parent port units (#24)"
```

---

### Task 2: Converter VLAN-tagging emission

**Files:**
- Modify: `src/converters/srx-converter.js` (`convertInterfaceAddresses`)
- Test: `tests/srx-subinterface-vlan.test.js` (create)

**Interfaces:**
- Consumes: existing `mapInterfaceName`, `createWarning`, `setQuoted`, and `iface.vlan` from the intermediate config.
- Produces: additional `set interfaces <base> flexible-vlan-tagging` / `native-vlan-id <N>` / `unit <u> vlan-id <tag>` output; no signature change.

- [ ] **Step 1: Write the failing test**

Create `tests/srx-subinterface-vlan.test.js`:

```js
import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

function ifaceLines(out) {
  const cmds = Array.isArray(out.commands) ? out.commands : [];
  return cmds.filter(l => l.startsWith('set interfaces ge-0/0/3'));
}

const MAPPINGS = { 'ethernet1/13': 'ge-0/0/3' };

describe('sub-interface VLAN tagging', () => {
  it('native case: parent untagged IP + tagged sub-units', () => {
    const cfg = {
      zones: [{ name: 'INSIDE', interfaces: ['ethernet1/13', 'ethernet1/13.100', 'ethernet1/13.206'] }],
      security_policies: [], service_objects: [], address_objects: [], nat_rules: [],
      interfaces: [
        { name: 'ethernet1/13', zone: 'INSIDE', ip: '172.16.0.2/16', vlan: '' },
        { name: 'ethernet1/13.100', zone: 'INSIDE', ip: '10.0.0.1/24', vlan: '100' },
        { name: 'ethernet1/13.206', zone: 'INSIDE', ip: '10.0.6.1/24', vlan: '206' },
      ],
    };
    const lines = ifaceLines(convertToSrxSetCommands(cfg, MAPPINGS, null)).join('\n');
    expect(lines).toContain('set interfaces ge-0/0/3 flexible-vlan-tagging');
    expect(lines).toContain('set interfaces ge-0/0/3 native-vlan-id 1');   // 1 ∉ {100,206}
    expect(lines).toContain('set interfaces ge-0/0/3 unit 0 family inet address 172.16.0.2/16');
    expect(lines).not.toMatch(/unit 0 vlan-id/);                            // native unit has no vlan-id
    expect(lines).toContain('set interfaces ge-0/0/3 unit 100 vlan-id 100');
    expect(lines).toContain('set interfaces ge-0/0/3 unit 206 vlan-id 206');
  });

  it('no-native case: tagged sub-units, no parent IP', () => {
    const cfg = {
      zones: [{ name: 'INSIDE', interfaces: ['ethernet1/13.100'] }],
      security_policies: [], service_objects: [], address_objects: [], nat_rules: [],
      interfaces: [{ name: 'ethernet1/13.100', zone: 'INSIDE', ip: '10.0.0.1/24', vlan: '100' }],
    };
    const lines = ifaceLines(convertToSrxSetCommands(cfg, MAPPINGS, null)).join('\n');
    expect(lines).toContain('set interfaces ge-0/0/3 flexible-vlan-tagging');
    expect(lines).toContain('set interfaces ge-0/0/3 unit 100 vlan-id 100');
    expect(lines).not.toMatch(/native-vlan-id/);
  });

  it('regression: plain interface with no tagged siblings gets no flexible-vlan-tagging', () => {
    const cfg = {
      zones: [{ name: 'DMZ', interfaces: ['ethernet1/13'] }],
      security_policies: [], service_objects: [], address_objects: [], nat_rules: [],
      interfaces: [{ name: 'ethernet1/13', zone: 'DMZ', ip: '10.9.9.1/24', vlan: '' }],
    };
    const lines = ifaceLines(convertToSrxSetCommands(cfg, MAPPINGS, null)).join('\n');
    expect(lines).not.toMatch(/flexible-vlan-tagging/);
    expect(lines).toContain('set interfaces ge-0/0/3 unit 0 family inet address 10.9.9.1/24');
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/srx-subinterface-vlan.test.js`
Expected: FAIL — no `flexible-vlan-tagging` / `vlan-id` / `native-vlan-id` emitted today.

- [ ] **Step 3: Add the tagging pre-pass and per-unit vlan-id**

In `src/converters/srx-converter.js`, inside `convertInterfaceAddresses`, immediately AFTER the `# Interface Addresses` header pushes and BEFORE `const configuredInterfaces = new Set();`, insert the pre-pass:

```js
  // --- VLAN tagging pre-pass ---
  // Group by SRX physical base to detect tagged sub-units (802.1Q).
  const vlanByBase = new Map();       // base -> Map(unit -> tag)
  const baseHasNativeIp = new Map();  // base -> true when a unit-0 iface has an IP and no tag
  for (const iface of interfaces) {
    if (!iface.ip && !iface.ipv6) continue;
    const [base, unit = '0'] = mapInterfaceName(iface.name || '', interfaceMappings).split('.');
    const tag = iface.vlan ? String(iface.vlan) : '';
    if (tag) {
      if (!vlanByBase.has(base)) vlanByBase.set(base, new Map());
      vlanByBase.get(base).set(unit, tag);
    } else if (unit === '0') {
      baseHasNativeIp.set(base, true);
    }
  }
  for (const [base, unitTags] of vlanByBase) {
    commands.push(`set interfaces ${base} flexible-vlan-tagging`);
    if (baseHasNativeIp.get(base)) {
      const usedTags = new Set([...unitTags.values()].map(Number));
      let nativeVlan = 1;
      while (usedTags.has(nativeVlan) && nativeVlan < 4094) nativeVlan += 1;
      commands.push(`set interfaces ${base} native-vlan-id ${nativeVlan}`);
      commands.push(`# NOTE: native-vlan-id ${nativeVlan} inferred for the untagged parent IP on ${base} — verify against your VLAN plan`);
      warnings.push(createWarning('warning', `interfaces/${base}`,
        `native-vlan-id ${nativeVlan} was inferred for the untagged parent IP on ${base}`,
        'PAN-OS does not specify a native VLAN — confirm this id fits your VLAN plan'));
    }
  }
```

Then, inside the existing `for (const iface of interfaces)` loop, AFTER `configuredInterfaces.add(ifKey);` and BEFORE the `if (iface.ip)` block, add the per-unit vlan-id:

```js
    if (iface.vlan) {
      commands.push(`set interfaces ${base} unit ${unit} vlan-id ${String(iface.vlan)}`);
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run tests/srx-subinterface-vlan.test.js`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full suite**

Run: `npx vitest run`
Expected: all pass (plain-interface tests unaffected — no tagged siblings ⇒ no new lines).

- [ ] **Step 6: Commit**

```bash
git add src/converters/srx-converter.js tests/srx-subinterface-vlan.test.js
git commit -m "feat(convert): emit VLAN tagging for sub-interface units (#24)"
```

---

### Task 3: UI — render sub-interfaces as derived units following the parent

**Files:**
- Modify: `public/components/InterfaceMapper.jsx` (`handleMappingChange` re-derivation; render branch)
- Test: `tests/interface-mapper-subif.test.js` (extend from Task 1)

**Interfaces:**
- Consumes: `isSubInterface`, `parentInterface` (Task 1).
- Produces: named export `deriveSubInterfaceMappings(mappings, parentPanos, srxIface) → mappings` — returns a copy of `mappings` with every sub-interface of `parentPanos` re-pointed to `<srxBase>.<unit>`.

- [ ] **Step 1: Write the failing test**

Add to `tests/interface-mapper-subif.test.js`:

```js
import { deriveSubInterfaceMappings } from '../public/components/InterfaceMapper.jsx';

describe('deriveSubInterfaceMappings', () => {
  it('re-points a parent\'s sub-interfaces to the new port', () => {
    const before = {
      'ethernet1/13': 'ge-0/0/0',
      'ethernet1/13.100': 'ge-0/0/0.100',
      'ethernet1/13.206': 'ge-0/0/0.206',
      'ethernet1/9': 'ge-0/0/1',
    };
    const after = deriveSubInterfaceMappings(before, 'ethernet1/13', 'ge-0/0/5');
    expect(after['ethernet1/13.100']).toBe('ge-0/0/5.100');
    expect(after['ethernet1/13.206']).toBe('ge-0/0/5.206');
    expect(after['ethernet1/9']).toBe('ge-0/0/1');   // unrelated untouched
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/interface-mapper-subif.test.js`
Expected: FAIL — `deriveSubInterfaceMappings` not exported.

- [ ] **Step 3: Add `deriveSubInterfaceMappings` and use it in `handleMappingChange`**

In `public/components/InterfaceMapper.jsx`, add the exported helper near the others:

```js
/**
 * Re-point every sub-interface of `parentPanos` to a unit on `srxIface`'s base.
 * @param {{ [k: string]: string }} mappings
 * @param {string} parentPanos - PAN-OS parent name (e.g. ethernet1/13)
 * @param {string} srxIface - the parent's new SRX target (e.g. ge-0/0/5)
 * @returns {{ [k: string]: string }} updated copy
 */
export function deriveSubInterfaceMappings(mappings, parentPanos, srxIface) {
  const base = String(srxIface || '').split('.')[0];
  if (!base) return { ...mappings };
  const updated = { ...mappings };
  for (const key of Object.keys(updated)) {
    if (isSubInterface(key) && parentInterface(key) === parentPanos) {
      updated[key] = `${base}.${key.split('.').pop()}`;
    }
  }
  return updated;
}
```

In `handleMappingChange`, after the LAG block builds `updated`, re-derive sub-interfaces before returning. Change the `setMappings(prev => { ... return updated; })` body so the final steps are:

```js
      // Re-point this parent's sub-interfaces to the new port.
      const withSubs = deriveSubInterfaceMappings(updated, panosIface, srxIface);
      return withSubs;
```

(Keep the existing LAG logic that populates `updated` before this.)

- [ ] **Step 4: Add the render branch for sub-interfaces**

In the mapping-target `<td>` conditional chain (the `isLagParent ? ... : isLagMember ? ... : isTunnel ? ... : (physical dropdown)` structure), add a sub-interface branch immediately BEFORE the final physical-dropdown `: (` fallback:

```jsx
                        ) : isSubInterface(panosIface) ? (
                          /* Sub-interface — a unit on its parent's port (no separate port) */
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <code style={{ color: 'var(--accent)', fontWeight: 600 }}>
                              {currentSrx || `${(mappings[parentInterface(panosIface)] || '').split('.')[0]}.${panosIface.split('.').pop()}`}
                            </code>
                            {parsedIfaceMap[panosIface]?.vlan && (
                              <span className="port-badge" style={{ fontSize: 10, padding: '1px 5px' }}>
                                vlan {parsedIfaceMap[panosIface].vlan}
                              </span>
                            )}
                            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                              unit on {parentInterface(panosIface)}
                            </span>
                          </div>
```

(`currentSrx` is the row's current mapping value; `parsedIfaceMap` and `mappings` are already in scope in the render — confirm the exact local names while editing and match them.)

- [ ] **Step 5: Run tests to verify pass**

Run: `npx vitest run tests/interface-mapper-subif.test.js`
Expected: PASS (all, including `deriveSubInterfaceMappings`).

Run: `npx vitest run`
Expected: all pass.

- [ ] **Step 6: Manual smoke (drive the real app)**

Dev server is running (http://192.168.1.127:5173/). Load a PAN-OS config with a tagged parent (e.g. `ethernet1/13` + `.100` + `.206`), open Interface Mapping, and confirm: the parent has a port dropdown; each sub-interface row shows `ge-0/0/N.<unit> · vlan <tag>` (no independent port dropdown); changing the parent's port updates the sub-interface displays. Then Convert & Export and confirm `flexible-vlan-tagging` + `vlan-id` + `native-vlan-id` appear. (Verification only.)

- [ ] **Step 7: Commit**

```bash
git add public/components/InterfaceMapper.jsx tests/interface-mapper-subif.test.js
git commit -m "feat(mapper): render sub-interfaces as units following the parent port (#24)"
```

---

## Spec Coverage Check

- Spec §1 mapper (`buildDefaultMappings` two-pass, helpers, parent-relative units, unmapped-parent fallback) → **Task 1**.
- Spec §1 UI presentation (sub-if rows as derived units following parent) → **Task 3**.
- Spec §2 converter (`flexible-vlan-tagging`, `vlan-id`, `native-vlan-id` with inferred-N + caveat, no-native case, native unit 0) → **Task 2**.
- Spec §3 testing (mapper mapping, converter native/no-native/regression, end-to-end) → Task 1 + Task 2 tests; end-to-end covered by Task 3 manual smoke and the converter tests.

## Notes / Out of Scope

- L2/switching (`vlans`, bridge-domains) is unchanged.
- The native VLAN id is inferred (lowest free); the caveat + warning make that explicit for the engineer to verify.

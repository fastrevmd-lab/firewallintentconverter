# PAN-OS Sub-Interfaces → Tagged Units on Parent SRX Port (Issue #24)

**Date:** 2026-07-14
**Issue:** [#24](https://github.com/mechubsec/firewallintentconverter/issues/24)
**Status:** Approved — ready for implementation planning

## Problem

PAN-OS 802.1Q sub-interfaces (e.g. `ethernet1/13.100`, `ethernet1/13.206`)
share one physical parent (`ethernet1/13`) carrying multiple VLANs. Today the
Interface Mapping tool assigns **each sub-interface its own separate physical
SRX port** (`.100 → ge-0/0/4`, `.206 → ge-0/0/5`), which breaks the trunk model
and drops the VLAN structure.

Two defects:

1. **Mapper (`buildDefaultMappings`)** treats every entry in `zone.interfaces`
   — including sub-interfaces — as a physical interface and assigns each the
   next free port.
2. **Converter** already places a sub-interface unit on the parent port via
   `mapInterfaceName` when the sub-interface has no explicit mapping, but it
   emits **no VLAN tagging** (`vlan-id`, `flexible-vlan-tagging`,
   `native-vlan-id`), so tagged traffic would not match on SRX.

## Goal

Map PAN-OS sub-interfaces to **tagged units on the parent's SRX physical port**
(`ethernet1/13.100 → ge-0/0/3.100 vlan-id 100`), and emit correct SRX VLAN
tagging — including `native-vlan-id` when the parent also carries an untagged
IP.

## Non-Goals

- L2/switching (`vlans`, bridge-domains) conversion — this is L3 sub-interfaces.
- Changing tunnel/loopback mapping behavior.

## Design

### 1. Interface Mapper UI — `public/components/InterfaceMapper.jsx`

Add a sub-interface detector:

```js
/** PAN-OS logical sub-interface, e.g. ethernet1/13.100 (has a parent + unit). */
function isSubInterface(ifaceName) {
  return /\.\d+$/.test(ifaceName) && !isTunnelInterface(ifaceName) && !isLoopbackInterface(ifaceName);
}
/** Parent physical name of a sub-interface (ethernet1/13.100 → ethernet1/13). */
function parentInterface(ifaceName) {
  return ifaceName.replace(/\.\d+$/, '');
}
```

**`buildDefaultMappings`:** map only parent physical interfaces to physical
ports. For a sub-interface, set its mapping to `<parentSrxPort>.<unit>` derived
from the parent's chosen port. Concretely:

- First pass: assign a free physical port to every non-tunnel, non-loopback,
  non-sub-interface (the parents), as today.
- Second pass: for each sub-interface, look up its parent's assigned SRX port
  (`mappings[parent]`), take that port's base, and set
  `mappings[subIf] = <parentBase>.<unit>`. If the parent has no mapping (e.g.
  the parent isn't in any zone's interface list), fall back to leaving the
  sub-interface unmapped so the converter's `mapInterfaceName` derives it.

The mapping value for a sub-interface is therefore always a valid SRX unit
string `<phys>.<unit>`, keeping the mappings object complete (survives
save/load, visible to report/validation).

**Presentation:** sub-interface rows render nested under their parent, showing
the derived unit and VLAN (e.g. `ge-0/0/3.100 · vlan 100`) as read-only text
instead of an independent physical-port dropdown. When the user changes the
parent's port, its sub-units re-derive to the new port. (Re-derivation reuses
the same second-pass logic keyed off the parent's current mapping.)

### 2. Converter — VLAN tagging emission (`src/converters/srx-converter.js`)

In `convertInterfaceAddresses` (or a dedicated helper it calls), after
resolving each interface's SRX name, group interfaces by their SRX **physical
base** (`ge-0/0/3`). For each physical base that has at least one unit with a
VLAN tag (`iface.vlan` non-empty), emit tagging on the physical and its units:

- `set interfaces <phys> flexible-vlan-tagging`
- For each tagged sub-unit: `set interfaces <phys> unit <u> vlan-id <tag>`
  (in addition to the existing `family inet address` / `description` lines).
- **Native VLAN:** if the parent physical interface also carries an untagged
  IP (an interface object whose SRX name is exactly `<phys>.0` — i.e. the
  parent's own `ip`), emit `set interfaces <phys> native-vlan-id <N>`, keep the
  parent IP on unit 0 (no `vlan-id`, so it is the native unit), and choose `N`
  as the lowest integer in 1–4094 **not** present in that interface's set of
  sub-unit tags. Emit a caveat comment and a warning that the native VLAN id
  was inferred (PAN-OS does not specify one).
- If the physical has tagged sub-units but **no** untagged parent IP, emit
  `flexible-vlan-tagging` and give every unit a `vlan-id`; do **not** emit
  `native-vlan-id`.

The VLAN tag source is the parser's `iface.vlan` (already populated per
sub-interface as `String(tag)`). Interfaces with no tagged siblings are
unchanged (no `flexible-vlan-tagging`).

**Ordering:** emit the physical-level `flexible-vlan-tagging` /
`native-vlan-id` lines before (or alongside) the unit lines; Junos set-order is
not significant, but keep them grouped for readability.

### 3. Data Flow

```
Parser: ethernet1/13 (ip 172.16.0.2/16), ethernet1/13.100 (vlan 100), .206 (vlan 206)
   │
   ▼
Mapper buildDefaultMappings:
   ethernet1/13     -> ge-0/0/3            (parent → physical port)
   ethernet1/13.100 -> ge-0/0/3.100        (sub-if → parent port + unit)
   ethernet1/13.206 -> ge-0/0/3.206
   │
   ▼
Converter convertInterfaceAddresses:
   set interfaces ge-0/0/3 flexible-vlan-tagging
   set interfaces ge-0/0/3 native-vlan-id <N>          # N ∉ {100,206}; caveat
   set interfaces ge-0/0/3 unit 0 family inet address 172.16.0.2/16   # native
   set interfaces ge-0/0/3 unit 100 vlan-id 100 family inet address ...
   set interfaces ge-0/0/3 unit 206 vlan-id 206 family inet address ...
```

## Testing

- **Mapper:** `buildDefaultMappings` on a config with a parent + two
  sub-interfaces maps the parent to a physical port and each sub-interface to
  `<parentPort>.<unit>` (NOT a new physical port); no physical port is consumed
  by a sub-interface. Changing the parent's port re-derives the sub-units.
- **Converter (native case):** parent with untagged IP + two tagged sub-ifs →
  output has `flexible-vlan-tagging`, `native-vlan-id N` with `N` not in
  {100,206}, unit 0 native IP (no vlan-id), `unit 100 vlan-id 100`,
  `unit 206 vlan-id 206`, and the inferred-native caveat/warning.
- **Converter (no-native case):** parent with no untagged IP + tagged sub-ifs →
  `flexible-vlan-tagging`, every unit has `vlan-id`, no `native-vlan-id`.
- **Regression:** a plain physical interface with no tagged siblings emits no
  `flexible-vlan-tagging`.
- **End-to-end:** parse→map→convert on the `ethernet1/13(.100/.206)` shape;
  output passes `validateSetOutput`.

## Risks / Mitigations

- **Inferred native VLAN id:** PAN-OS does not carry a native VLAN, so `N` is
  chosen (lowest free id). Mitigated by a caveat comment + warning so the
  engineer verifies it.
- **Parent not in a zone:** if a sub-interface's parent isn't mapped, fall back
  to leaving the sub-interface unmapped and let `mapInterfaceName` derive the
  unit (existing behavior), so no regression.
- **Mapper save/load:** sub-interface mappings are stored as explicit
  `<phys>.<unit>` strings, so a saved template round-trips; the second-pass
  re-derivation only runs when building defaults, not when loading an explicit
  mapping.

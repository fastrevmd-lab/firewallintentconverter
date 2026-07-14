# SRX `security policies global` Output Mode (Issue #29)

**Date:** 2026-07-14
**Issue:** [#29](https://github.com/fastrevmd-lab/firewallintentconverter/issues/29)
**Status:** Approved — ready for implementation planning

## Problem

The SRX converter emits security policies in the **zone-pair container** form
(`security policies from-zone X to-zone Y policy Z ...`) for any policy with
specific zones, and only uses `security policies global` when a source or
destination zone is `any` (`src/converters/srx-converter.js:1695-1720`). This
fragments the rulebase across many independent zone-pair lists and mixes two
policy structures in one config.

Modern SRX best practice (Junos 23.x+; the `srx-policy` skill) favors the
**global** structure — one ordered rulebase where every policy carries
explicit `match from-zone` / `match to-zone`. It mirrors how PAN-OS and other
NGFWs order rules, makes migration parity and shadow/consolidation analysis
faithful, and lets a cross-zone rule be expressed once.

## Goal

Emit `security policies global` with `match from-zone` / `match to-zone` as the
**default** output, while keeping the existing zone-pair form available via a
user-selectable toggle. A multi-zone source policy becomes **one** consolidated
global rule.

## Non-Goals

- Changing NAT, address-book, or any non-policy output.
- Changing policy match/action semantics — only the structural container.
- Reordering rules — source `_rule_index` order is preserved.

## Design

### 1. Converter — `options.policyStructure` (`src/converters/srx-converter.js`)

`convertToSrxSetCommands(config, interfaceMappings, targetContext, options)`
already accepts `options`. Read `options.policyStructure`:

- Allowed values: `'global'` (default) and `'zone-pair'`.
- Any unrecognized/absent value falls back to `'global'`.

Pass the resolved value into `convertSecurityPolicies(...)`, which branches:

**`'zone-pair'` mode** — behaviorally identical to today, locked by a
regression test. The per-zone-pair emission (the
`sourceEntries × destinationEntries` loop building
`security policies from-zone ... to-zone ... policy ...`, with the `any`→global
special case at line 1695) is preserved. If the plan factors a shared
match/action body builder (see Risks), the zone-pair path is rewired to call it
but its emitted output must not change — the regression test is the gate.

**`'global'` mode** — for each source policy, emit exactly **one** global
policy:

```
set security policies global policy <name> match from-zone [ <srcZone1> <srcZone2> ... ]
set security policies global policy <name> match to-zone   [ <dstZone1> <dstZone2> ... ]
set security policies global policy <name> match source-address <...>
set security policies global policy <name> match destination-address <...>
set security policies global policy <name> match application <...>
set security policies global policy <name> then <permit|deny> <...>
```

Rules are emitted in `_rule_index` order into the single global list. Junos
evaluates global policies strictly top-to-bottom, so source order is preserved.

Details:

- **Zones:** collect the policy's source zones and destination zones (the same
  `src_zones`/`source_zones` and `dst_zones`/`destination_zones` resolution the
  current code uses). Emit them as `match from-zone` / `match to-zone` lists. A
  policy whose effective zone set is `any` emits `from-zone any` (resp.
  `to-zone any`). Zone identifiers are resolved through the existing
  `identifiers.nameForReference(...)` path so identifier collision handling is
  unchanged.
- **Consolidation (approved):** a policy with src `{A,B}` and dst `{C,D}`
  becomes ONE global rule with `match from-zone A B` and `match to-zone C D`.
  This is semantically identical to today's four zone-pair containers (Junos
  matches `from-zone ∈ {A,B}` AND `to-zone ∈ {C,D}`), with fewer rules.
- **One name per policy:** global mode produces exactly one policy name per
  source policy (no per-zone-pair name duplication). The name is derived by the
  same `identifiers.nameForDefinition` / `nameForGenerated` logic used today,
  keyed once per source policy.
- **Match/action body:** source-address, destination-address, application, and
  `then` emission (including UTM/IDP/SecIntel attachment, logging, and rule
  descriptions/tags) reuse the current per-policy body-building logic
  unchanged — only the leading `security policies ... policy <name>` prefix and
  the `match from-zone`/`to-zone` lines differ from zone-pair mode. The
  UTM/IDP/SecIntel maps and the disabled-rule `deactivate` handling key off the
  policy index, so they carry over without change.

**`default-policy`** handling (`srx-converter.js:258-261`) is unchanged: global
policies require `set security policies default-policy permit-all`, which is
already emitted whenever a global policy is present — true for every config in
global mode.

### 2. Options plumbing (thread `policyStructure` from UI to converter)

The `options` argument is currently dropped between the UI and the converter.
Thread it:

- `public/utils/engine.js` (`convertConfig`, ~line 105): add an `options`
  parameter (default `{}`) and forward it:
  `convertToSrxSetCommands(intermediateConfig, interfaceMappings, targetContext, options)`.
  If `convertConfig` has multiple call sites, the added parameter is optional so
  existing callers are unaffected.
- `public/hooks/useConversion.js` (`handleConvert`): read the selected policy
  structure from UI state and pass `{ policyStructure }` into `convertConfig`.
  When no selection exists, omit it (converter defaults to `'global'`).

### 3. UI toggle (`public/components/SRXOutput.jsx` + UI state)

- Add a **Policy structure** dropdown with two options: `Global` (default) and
  `Zone-pair`, rendered near the existing SRX output controls.
- Store the selection in the existing UI context/state (the same store that
  holds `renderMode`), defaulting to `'global'`.
- Changing the selection triggers a re-conversion (call the existing convert
  handler) so the output reflects the chosen structure.

### 4. Testing

- **Converter (global):** a config with a multi-zone policy (src `{A,B}`, dst
  `{C,D}`) plus a single-zone policy, converted in `'global'` mode, produces:
  one global rule per source policy; the multi-zone policy has
  `match from-zone A B` and `match to-zone C D` (one rule, not four); rules
  appear in `_rule_index` order; `default-policy permit-all` present.
- **Converter (default):** calling with no `options` yields the same output as
  explicit `{ policyStructure: 'global' }`.
- **Converter (zone-pair regression):** `{ policyStructure: 'zone-pair' }`
  reproduces the pre-change zone-pair output for a representative config (locks
  the legacy path).
- **Plumbing:** `convertConfig` forwards a passed `policyStructure` to the
  converter (spy/asserted output difference between global and zone-pair).
- **UI:** selecting `Zone-pair` in the dropdown updates state and causes the
  conversion to run with `policyStructure: 'zone-pair'`; default state is
  `global`.

## Data Flow

```
UI: Policy-structure dropdown (Global default)
      │  selection stored in UI state
      ▼
useConversion.handleConvert → convertConfig(config, maps, ctx, { policyStructure })
      │
      ▼
engine.convertConfig → convertToSrxSetCommands(config, maps, ctx, { policyStructure })
      │
      ▼
convertSecurityPolicies(..., policyStructure)
      ├─ 'global'    → one ordered `security policies global` rulebase, consolidated match zones
      └─ 'zone-pair' → existing from-zone/to-zone containers (unchanged)
```

## Risks / Mitigations

- **Semantic drift from consolidation:** mitigated by the equivalence argument
  above and a converter test asserting the consolidated match sets equal the
  union of the source policy's zones.
- **Ordering:** global mode relies on a single ordered list; emitting in
  `_rule_index` order preserves evaluation order. Test asserts order.
- **Legacy path regression:** the `'zone-pair'` branch is the untouched current
  code; a regression test locks its output.
- **Body-logic divergence:** global and zone-pair modes must share the same
  match/action body builder so UTM/IDP/SecIntel/logging behavior can't drift
  between modes. The plan factors the shared body emission so both prefixes feed
  one body builder.

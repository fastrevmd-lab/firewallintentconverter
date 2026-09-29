# Target Architecture as Explicit Input + Correct MNHA Output (Issue #37)

**Date:** 2026-07-15
**Issue:** [#37](https://github.com/mechubsec/firewallintentconverter/issues/37)
**Status:** Approved (autonomous) — MNHA output validated against the `srx-mnha` skill

## Problem

The HA output is driven by the source `ha_config.ha_type`, which PAN-OS never
sets to `mnha` (PAN is chassis-cluster-oriented). So there is no way to
explicitly target a deployment architecture, and the existing `convertMnhaConfig`
(only reachable via a synthetic `ha_type: 'mnha'`) is **incorrect** against the
`srx-mnha` skill:

- No `activeness-probe dest-ip <X> src-ip <Y>` — **mandatory** for an SRG with
  `deployment-type routing`; commit fails `activeness-probe … mandatory` without it.
- Uses chassis-cluster `interface-monitor <if> weight` — the skill states cluster
  monitor weights do **not** map 1:1 to SRG monitoring; MNHA uses the SRG
  `monitor monitor-object` model.
- No ICL security zone (`host-inbound-traffic system-services high-availability`)
  — MNHA/HA link services are silently blocked without it.
- No caveats for the release-dependent flat-vs-grid config model or the
  reboot-gated activation, and no per-node reminder.

## Scope

1. **Explicit deployment-mode input** — `options.deploymentMode` ∈
   `{'standalone','chassis-cluster','mnha'}` (undefined = auto/legacy behavior),
   threaded from a UI selector through `engine.convertConfig` →
   `convertToSrxSetCommands` → `convertHaConfig`, exactly like `policyStructure`
   (#29).
2. **Correct MNHA output** per the skill (flat model, ≤24.x-oriented, with a
   release caveat).

## Design

### 1. Converter — deployment-mode dispatch (`convertHaConfig`)

Resolve `deploymentMode`:

- `'standalone'` → emit no HA config; push a comment
  `# Target: standalone — no HA/chassis-cluster/MNHA config emitted.`
- `'chassis-cluster'` → chassis-cluster emission (existing `convertHaConfig`
  body), even if the source had no HA (emit from `ha_config` or sensible
  defaults with a caveat when fields are absent).
- `'mnha'` → `convertMnhaConfig`, mapping the source `ha_config` fields
  (`peer_ip`, `priority`, `ha_interfaces`, `local_ip`) into MNHA parameters.
- undefined → current behavior (`ha_type`-driven).

Thread `deploymentMode` from `convertToSrxSetCommands(options)` into
`convertHaConfig`.

### 2. Converter — correct MNHA emission (`convertMnhaConfig`)

Emit the flat MNHA model (skill "ICL" + "SRG" sections), with these
**correctness additions**:

- **ICL** (unchanged skeleton): `local-id <n>`, `local-id local-ip <ip>`,
  `peer-id <p> peer-ip <ip>`, `peer-id <p> interface <icl-ifl>`,
  `liveness-detection minimum-interval/multiplier`,
  `services-redundancy-group 0 peer-id <p>`.
- **SRG1 routing + mandatory activeness-probe:**
  ```
  set chassis high-availability services-redundancy-group 1 deployment-type routing
  set chassis high-availability services-redundancy-group 1 peer-id <p>
  set chassis high-availability services-redundancy-group 1 activeness-priority <prio>
  set chassis high-availability services-redundancy-group 1 activeness-probe dest-ip <PROBE_DST> src-ip <PROBE_SRC>
  ```
  Use `ha_config.activeness_probe_dest`/`_src` when present; otherwise emit
  documentation-range placeholders (`192.0.2.1` / `192.0.2.2`) plus a warning +
  caveat: the probe must point at a **real reachable data-segment address**
  (not the ICL), and it is mandatory for `deployment-type routing`.
- **SRG interface monitoring via monitor-object** (replace the chassis-cluster
  `interface-monitor`): for each monitored interface, emit
  ```
  set chassis high-availability services-redundancy-group 1 monitor monitor-object <name> interface interface-name <ifd> weight <w>
  set chassis high-availability services-redundancy-group 1 monitor monitor-object <name> interface threshold 100
  set chassis high-availability services-redundancy-group 1 monitor monitor-object <name> object-threshold 100
  set chassis high-availability services-redundancy-group 1 monitor srg-threshold 100
  ```
  with a caveat that cluster monitor weights were not ported 1:1 and monitoring
  should be re-validated.
- **ICL security zone:**
  ```
  set security zones security-zone ICL interfaces <icl-ifl>
  set security zones security-zone ICL host-inbound-traffic system-services high-availability
  ```
- **Caveats (comments + a warning):** the flat model targets ≤24.x; **Junos 26.x
  requires the grid model** (`grid-id`/`local-domain-id`/`peer-domain-id`) —
  verify against the target release; enabling `chassis high-availability` is
  **reboot-gated**; this is the **node-local** config for one node — the peer
  node mirrors it with swapped local/peer IDs and IPs and a lower
  activeness-priority; MNHA does not auto-sync full config.

### 3. Options plumbing + UI

- `engine.convertConfig(intermediateConfig, format, interfaceMappings,
  targetContext, options)` already forwards `options`; ensure `deploymentMode`
  rides in `options` (it already passes the whole object).
- `useConversion.handleConvert` adds `deploymentMode: uiState?.deploymentMode ||
  undefined` to the options it passes (alongside `policyStructure`).
- `UIContext` gains `deploymentMode: 'standalone'` (default) in `initialState`.
- `SRXOutput` (or the parent) gets a **Target architecture** dropdown
  (Standalone / Chassis Cluster / MNHA) that dispatches `SET_FIELD
  deploymentMode` and re-runs conversion, mirroring the #29 policy-structure
  toggle.

## Testing

- **Converter (MNHA correctness):** with `deploymentMode: 'mnha'` and a source
  `ha_config` (peer_ip, priority, one ha_interface as ICL), output contains:
  `chassis high-availability local-id`, `peer-id … peer-ip`, `peer-id … interface`,
  `services-redundancy-group 0 peer-id`, `services-redundancy-group 1
  deployment-type routing`, `activeness-probe dest-ip … src-ip …`, the ICL
  `security-zone ICL … system-services high-availability`, and a
  `monitor monitor-object` line when an interface is monitored; NO chassis-cluster
  `interface-monitor` line; a warning about the placeholder probe when defaults
  are used.
- **Deployment-mode switching:** `'standalone'` → no `chassis` HA lines;
  `'chassis-cluster'` → `set chassis cluster …`; `'mnha'` → `chassis
  high-availability …`.
- **UI:** `initialState.deploymentMode === 'standalone'`; `SET_FIELD` updates it.
- Output passes `validateSetOutput`; full suite green.

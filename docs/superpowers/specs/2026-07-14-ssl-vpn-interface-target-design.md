# SSL-VPN / Remote-Access Interface Target (Issue #23)

**Date:** 2026-07-14
**Issue:** [#23](https://github.com/fastrevmd-lab/firewallintentconverter/issues/23)
**Status:** Approved — ready for implementation planning

## Problem

The Interface Mapping tool (PAN-OS → SRX) only offers physical ports and the
three tunnel encapsulation types (`st0` IPsec, `gr-0/0/0` GRE, `ip-0/0/0`
IP-IP) as SRX targets. Real PAN-OS configs commonly use **GlobalProtect**
(SSL-VPN) for remote access, whose tunnel interfaces currently map to a plain
`st0` IPsec tunnel. That misrepresents the source: GlobalProtect is SSL-VPN,
and the SRX equivalent (Juniper Secure Connect / IPsec dial-up) is a different
transport and auth model that cannot be auto-derived from the PAN-OS config.

## Goal

Let a user designate a tunnel as **SSL-VPN / remote-access**, auto-detect it
from parsed GlobalProtect config, emit an honest `st0` placeholder plus a
`manual-not-converted` report entry. **No fabricated VPN crypto or auth is
generated.**

## Non-Goals

- Generating IKE/IPsec/access configuration for the remote-access VPN.
- Converting GlobalProtect portal, client config, HIP checks, or MFA (Duo).
- Any change to how site-to-site IPsec tunnels are handled.

## Design

### 1. Parser — `src/parsers/panos-parser.js`

Add `parseGlobalProtect(config, warnings)`, invoked from the main parse
alongside the existing `parseVpnConfig` / `parseInterfaceConfig` calls.

It reads GlobalProtect gateways from the PAN-OS XML at
`.../global-protect/global-protect-gateway/entry`, extracting for each:

- `name` — the gateway entry name (e.g. `G41-GP-GW`)
- `tunnel_interface` — the `<tunnel-interface>` value (e.g. `tunnel.10`)

Outputs:

- `config.global_protect = { gateways: [{ name, tunnel_interface }] }` — the
  source of truth used by the report layer.
- Each parsed **tunnel interface object** whose name matches a gateway's
  `tunnel_interface` is stamped with `remote_access_role: 'ssl-vpn'`.

**Defensive behavior:** if the `global-protect` node is absent, or a gateway
has no `<tunnel-interface>`, that gateway is skipped. No GlobalProtect present
⇒ `global_protect.gateways` is `[]` and no interface is stamped — zero
behavior change for non-GP configs.

**Schema note:** `remote_access_role` is an optional string field on interface
objects. `config.global_protect` is optional. Neither is required by any
existing consumer, so absence is safe. The only value the parser writes for
`remote_access_role` is the literal `'ssl-vpn'`. These fields travel through
`validateJunosInput`, where `remote_access_role` and the `global_protect`
gateway names/tunnels are covered by the generic safe-scalar walk (no new
validator rule required).

### 2. UI — `public/components/InterfaceMapper.jsx`

- Add a fourth entry to `SRX_TUNNEL_TYPES`:

  ```js
  {
    value: 'st0-ra',
    label: 'st0 (SSL-VPN / Remote Access)',
    description: 'GlobalProtect → Juniper Secure Connect / IPsec dial-up (manual rebuild)',
  }
  ```

  It still binds to an `st0.N` unit; the distinction is **intent + reporting**,
  not a different Junos interface family. The emitted interface token remains
  `st0.<unit>` — `st0-ra` is a UI/mapping-layer marker only.

- Default selection: when initializing the `tunnelTypes` state for a tunnel
  interface, if that interface has `remote_access_role === 'ssl-vpn'`, default
  its type to `st0-ra` instead of `st0`. The user can override in either
  direction via the dropdown.

- Badge: the row badge reads **SSL-VPN** (instead of **IPsec**) when the type
  is `st0-ra`.

- Mapping serialization: `st0-ra` must resolve to an `st0.<unit>` string in the
  interface-mapping value the converter consumes, while the `st0-ra` marker is
  preserved in the mapping metadata (`tunnelTypes`) so the converter/report can
  distinguish it. (See §3 for how the converter learns the SSL-VPN intent.)

### 3. Converter — `src/converters/srx-converter.js` and `srx-xml-builder.js`

When a tunnel's mapping is marked `st0-ra` (SSL-VPN):

- Emit the same `st0.N` placeholder unit the tool already emits for tunnels
  (so downstream `bind-interface` references stay valid), **plus** a comment:

  ```
  # SSL-VPN (GlobalProtect '<gateway>') — remote-access VPN not auto-converted;
  # rebuild as Juniper Secure Connect / IPsec dial-up
  ```

  The `<gateway>` name comes from `config.global_protect.gateways` matched by
  tunnel interface; if unknown, the comment omits the gateway name.

- **No** IKE gateway, IPsec VPN, proposal, or access-profile configuration is
  generated for this tunnel.

The converter learns SSL-VPN intent from the mapping metadata (the `st0-ra`
marker in `tunnelTypes`) and/or the interface's `remote_access_role`. Both
paths converge on the same behavior.

### 4. Report — fidelity / conversion report

For each SSL-VPN tunnel, add a **`manual-not-converted`** entry:

```
REMOTE-ACCESS tunnel.10 → SSL-VPN
  Rebuild as Juniper Secure Connect / IPsec dial-up.
  GlobalProtect gateway '<name>'; re-implement MFA (e.g. Duo) via RADIUS.
```

This satisfies issue AC #3 and makes the non-conversion explicit rather than
silently producing a misleading IPsec tunnel.

## Data Flow

```
PAN-OS XML
  └─ parseGlobalProtect → config.global_protect.gateways[]
                        → interface.remote_access_role = 'ssl-vpn'
         │
         ▼
InterfaceMapper UI
  └─ tunnel with remote_access_role='ssl-vpn' → default type 'st0-ra' (badge: SSL-VPN)
  └─ user may override → mapping value 'st0.<unit>' + tunnelTypes marker 'st0-ra'
         │
         ▼
Converter
  └─ st0-ra → st0.<unit> placeholder + descriptive comment (no VPN config)
         │
         ▼
Report
  └─ manual-not-converted entry per SSL-VPN tunnel
```

## Testing

- **Parser:** GP gateway with `tunnel-interface` → `global_protect.gateways`
  populated and matching interface stamped `remote_access_role: 'ssl-vpn'`;
  config with no GlobalProtect → empty/absent, no interface stamped; gateway
  missing `<tunnel-interface>` → skipped.
- **UI:** tunnel with `remote_access_role: 'ssl-vpn'` defaults to `st0-ra`;
  user override to `st0` and back works; badge reflects type.
- **Converter:** `st0-ra` mapping emits `st0.N` placeholder + SSL-VPN comment
  and emits **no** IKE/IPsec/access config for that tunnel; a normal `st0`
  tunnel is unaffected.
- **Report:** SSL-VPN tunnel produces exactly one `manual-not-converted`
  entry naming the gateway; non-GP configs produce none.
- **Regression:** existing tunnel/IPsec conversion tests still pass; no change
  for configs without GlobalProtect.

## Risks / Mitigations

- **PAN-OS variance in GP XML:** gateway tunnel binding is read defensively;
  unrecognized shapes fall back to no stamp (interface behaves as today).
- **Marker plumbing (`st0-ra`) leaking into Junos output:** the mapping value
  the converter serializes is always a real `st0.<unit>` token; `st0-ra` lives
  only in mapping metadata. Covered by a converter test asserting emitted
  tokens are valid Junos interfaces.

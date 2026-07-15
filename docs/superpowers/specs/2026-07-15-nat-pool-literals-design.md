# NAT Pool Literal Addresses (Issue #35 — core correctness)

**Date:** 2026-07-15
**Issue:** [#35](https://github.com/fastrevmd-lab/firewallintentconverter/issues/35)
**Status:** Approved (autonomous) — implementing the correctness core

## Problem

Junos NAT pools require **literal IP/prefix** addresses. The converter's
static-source and destination NAT paths fall back to the **raw** translated
value (`resolved || raw`) when an address object can't be resolved, emitting
an object name / FQDN as a pool address — invalid, non-committable config. The
output gate doesn't catch it (non-IP tokens aren't IPv4-shaped). Reproduced:

```
set security nat source pool snat-static-static address UNDEFINED-POOL-OBJ   # invalid
set security nat destination pool dnat-pool-dnat1 address GHOST-SERVER        # invalid
```

(The dynamic-ip-pool source path already handles this correctly — it skips to
interface NAT when addresses don't resolve.)

## Scope (this PR)

Fix the two leaking paths so a NAT pool never receives a non-literal address,
plus a defense-in-depth output-gate check. Larger #35 items — **provider NAT by
egress interface**, **NAT shadow analysis**, and **preserving source
match groups/protocols/ports** — are deferred to follow-ups (noted in the PR).

## Design

### 1. Converter — `convertNatRules` (`src/converters/srx-converter.js`)

`translatedAddress(raw)` already resolves an object name to its literal value
via the address lookup and returns `null` when it can't (unknown object or
FQDN). Change the two callers to respect that null instead of falling back to
the raw value:

- **Static source NAT** (`translated_src.type === 'static'`): resolve first;
  - if resolved to a literal → ensure a bare host IP gets `/32`, emit
    `set security nat source pool <P> address <literal>` and
    `then source-nat pool <P>`;
  - if `null` → emit a caveat comment + a `nat` warning naming the
    unresolved address, and fall back to `then source-nat interface`
    (source NAT always has a safe interface fallback). Do NOT emit a pool.
- **Destination NAT** (`translated_dst`): resolve first;
  - if resolved to a literal → `/32` for bare host, emit the destination pool
    (+ optional `address port <translated_port>`) and `then destination-nat
    pool <P>`;
  - if `null` → emit a caveat comment + `nat` warning naming the unresolved
    address, and **skip** the destination translation (destination NAT has no
    interface fallback; better to emit nothing than an invalid pool). The
    rule's match lines may remain, but no `then destination-nat` / pool is
    emitted for the unresolved translation.

Also make static source honor the `/32` normalization already used for
destination (bare `a.b.c.d` → `a.b.c.d/32`) so source pools are well-formed.

### 2. Output gate hardening — `validateSetOutput` (`src/security/junos-output-validation.js`)

Add a targeted check: for a line matching
`set security nat (source|destination) pool <name> address <X>` where `<X>` is
the final token and is **not** the keyword `port`, `<X>` must be a valid IPv4
address/prefix, IPv6 address/prefix, or an `a-b` range. Otherwise **fail
closed** (reuse the existing `fail(...)`). This catches any object-name/FQDN
leak into a NAT pool regardless of origin, consistent with the #32 malformed-IP
gate. Do not touch `address port <n>` lines (that's a port, not an address).

## Testing

- **Converter:** a static source NAT and a destination NAT whose translated
  address is an **undefined** object → no `nat ... pool ... address <name>`
  line is emitted; a caveat/warning is produced; source falls back to
  `then source-nat interface`; destination emits no `then destination-nat`.
- A static source / destination NAT whose translated address **resolves** to a
  literal (via a defined address object) → the pool uses the literal (with
  `/32` for a bare host), unchanged good behavior.
- **Gate:** `validateSetOutput(['set security nat source pool P address FOO'])`
  throws; `['... address 203.0.113.10/32']` and `['... address port 8080']`
  pass.
- Full suite green; output passes `validateSetOutput`.

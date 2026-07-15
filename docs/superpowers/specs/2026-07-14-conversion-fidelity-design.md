# Conversion Fidelity: Reference-Integrity Gate + Completeness Manifest (Issue #34)

**Date:** 2026-07-14
**Issue:** [#34](https://github.com/fastrevmd-lab/firewallintentconverter/issues/34)
**Status:** Approved (autonomous) — implementing

## Problem

External audit found active policies referencing undefined objects (~220
unresolved references) and source rules disappearing with no disposition. Two
gaps:

1. **Reference integrity:** a security policy can reference an address /
   address-group / service / service-group name that is not defined anywhere,
   producing SRX config that fails commit ("address X not defined").
2. **Completeness:** nothing records that a rule was dropped/deactivated, so
   loss is silent.

Applications are already handled (issue #33: an unmapped App-ID becomes an
inactive placeholder and its policies are deactivated). This work covers the
remaining **address and service** references and adds a disposition manifest.

## Design

### 1. Detection — `src/security/policy-reference-integrity.js` (new)

```js
export function findPolicyReferenceIssues(config)
  → Map<policyIndex, { addresses: string[], services: string[] }>
```

For each non-implicit `security_policies[i]`, a referenced name is **undefined**
when it is none of:

- `'any'`;
- a literal address (IPv4/IPv6 address, prefix, or `a-b` range) — for address
  fields; or a literal service (`'application-default'`, or a `proto/port`
  shape) — for service fields;
- a defined name in the relevant sets:
  - **addresses:** `address_objects[].name` ∪ `address_groups[].name`
  - **services:** `service_objects[].name` ∪ `service_groups[].name`

Checked fields: `src_addresses`, `dst_addresses` (addresses); `services`
(services). Applications are intentionally NOT checked here (covered by #33).
Only policies with at least one undefined address or service are returned.

### 2. Converter integration — `src/converters/srx-converter.js`

- Compute the issues map once at the top of `convertToSrxSetCommands`.
- Pass the set of offending policy indices into `convertSecurityPolicies` →
  `emitPolicyBody` (alongside the existing `deactivateCommands` mechanism).
- In `emitPolicyBody`, deactivate the policy when it has an undefined reference
  (join the existing `policy.disabled || hasUnmappedApp` condition), and emit a
  caveat comment naming the undefined reference(s). Consistent with #33: the
  uncertain rule becomes **inactive**, never silently dropped or emitted with a
  dangling reference.
- Add a `# ===== Conversion Fidelity Manifest =====` comment block after the
  policy section summarising dispositions:
  ```
  # Source security policies: N
  #   active (converted): A
  #   inactive (disabled in source): D
  #   inactive (unmapped application): U
  #   inactive (undefined reference): R
  # Undefined references (rule → missing object):
  #   - <policy>: address "GHOST-OBJ"
  ```
- Summary counters: add `total_source_policies` and
  `policies_deactivated_undefined_ref` to the `summary` object; emit a warning
  per undefined reference so it surfaces in the report's Warnings section.

### 3. Not in scope (documented follow-ups)

- **Address-sets over 10,000 members split** — distinct concern; separate
  follow-up.
- **Deferred IPv6/App-ID/VPN rules inactive** — App-ID already handled (#33);
  the rest is out of scope here.

## Testing

- **Detection:** a policy referencing a defined object → no issue; a policy
  referencing an undefined address (`GHOST-OBJ`) → reported; literals (`any`,
  `10.0.0.1/32`, `a-b` range) and defined group names → not flagged; undefined
  service name → reported; `application-default`/`any` services → not flagged.
- **Converter:** a config with a policy referencing an undefined address emits
  `deactivate ... policy <P>`, a caveat comment naming `GHOST-OBJ`, a warning,
  and the manifest counts it as `inactive (undefined reference)`; a clean config
  is unaffected (no deactivations, manifest shows all active).
- Output passes `validateSetOutput`; full suite green.

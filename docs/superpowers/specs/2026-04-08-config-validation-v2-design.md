# Config Validation v2 — Design Spec

**Date:** 2026-04-08
**Status:** Approved
**Scope:** Post-conversion SRX output validation with hardware limits, operational checks, compliance hardening, and license gating

---

## Overview

Config Validation v2 is an on-demand post-conversion auditor that validates the generated SRX output against the target hardware model, selected license tier, operational best practices, and compliance/hardening standards. Findings integrate into the existing WarningsPanel using the standard ack/fix/ignore workflow.

## Requirements

- **Post-conversion auditor** — validates generated SRX output, not intermediate config
- **Existing warning system** — findings appear as warnings in WarningsPanel (no new panels)
- **License gating toggle** — user chooses warn-only vs strip+warn for license-gated features
- **Three check tiers** — hardware limits, operational best practices, compliance/hardening
- **On-demand** — user clicks a "Validate" button (like Analysis), not automatic

## Architecture

### File Structure

```
src/validators/
  srx-validator.js            # existing (unchanged, runs during conversion)
  srx-validation-engine.js    # NEW — orchestrator
  hardware-checks.js          # NEW — tier 1: model limits
  operational-checks.js       # NEW — tier 2: operational best practices
  compliance-checks.js        # NEW — tier 3: STIG/hardening
```

### Orchestrator (`srx-validation-engine.js`)

Entry point: `runValidation(intermediateConfig, srxOutput, targetModel, srxLicense, options)`

- `options.enforceLicense` (boolean) — controls strip+warn vs warn-only
- Calls all three check modules in sequence
- Each module returns `Finding[]`
- Findings converted to warnings via existing `createWarning()` — each finding's own severity (`warning`/`unsupported`/`info`) is used, and `_source: 'validation'` is set to identify them
- Returns `{ findings[], strippedCommands[] }`
- `strippedCommands` only populated when `enforceLicense === true`

### Check Module Interface

Each module exports a single function returning `Finding[]`:

```js
runHardwareChecks(srxOutput, targetModel)       → Finding[]
runOperationalChecks(intermediateConfig, srxOutput) → Finding[]
runComplianceChecks(srxOutput)                  → Finding[]
```

Each `Finding` has:

```js
{
  severity: 'warning' | 'unsupported' | 'info',
  element: string,      // e.g., "hardware/interface-count"
  message: string,      // human-readable description
  suggestion: string,   // recommended action
  tier: 'hardware' | 'operational' | 'compliance',
}
```

---

## Tier 1: Hardware Checks (`hardware-checks.js`)

Validates SRX output against the selected target model from `hardware-db.js`.

Thresholds stored in a `MODEL_LIMITS` map keyed by tier (`branch`/`midrange`/`datacenter`/`virtual`).

| # | Check | Severity | Detail |
|---|-------|----------|--------|
| H1 | Interface count vs model ports | `unsupported` | Unique interfaces in output vs `SRX_MODELS[target].ports.length` |
| H2 | Interface type mismatch | `warning` | Output uses `xe-`/`et-` ports on a model with only `ge-` slots |
| H3 | Policy count threshold | `warning` | Branch >2000, midrange >10,000, datacenter >50,000 |
| H4 | Zone count threshold | `warning` | Branch >16, midrange >64, datacenter >256 |
| H5 | NAT rule count threshold | `warning` | Branch >500, midrange >5000, datacenter >20,000 |
| H6 | Throughput advisory | `info` | Target L4 throughput < source model throughput (when source data available) |
| H7 | No target model selected | `info` | Skips all hardware checks, emits single advisory to select a model |

---

## Tier 2: Operational Checks (`operational-checks.js`)

Catches configs that are technically valid but will cause operational issues.

| # | Check | Severity | Detail |
|---|-------|----------|--------|
| O1 | Missing default-deny | `warning` | Zone pairs with permit policies but no explicit deny-all at the end (no logging on drops) |
| O2 | Zone pairs with no policies | `info` | Zones exist but have zero policies between them — traffic silently dropped |
| O3 | NAT referencing uncovered zone pair | `warning` | NAT rule for a zone pair with no matching security policy — NAT never triggers |
| O4 | Screen missing on internet-facing zones | `warning` | Zones matching `untrust\|outside\|wan\|dmz\|internet\|external` with no screen binding |
| O5 | Permit rules without logging | `warning` | `action permit` without `then log session-close`, skips rules with `_srx_log_count` |
| O6 | Duplicate address objects | `info` | Different names resolving to same IP/subnet — consolidation opportunity |
| O7 | BGP/OSPF without export policy | `warning` | Routing protocols configured but no policy-statement — routes won't advertise |
| O8 | VPN tunnel with no matching policy | `warning` | IPsec VPN configured but no policy permits tunnel traffic |
| O9 | Overlapping NAT rules | `warning` | Multiple NAT rules matching same criteria — later rules are dead |

---

## Tier 3: Compliance Checks (`compliance-checks.js`)

STIG/hardening-guide style checks via regex scans against the SRX output command array.

| # | Check | Severity | Detail |
|---|-------|----------|--------|
| C1 | No NTP configured | `warning` | Missing `set system ntp server` — clock drift breaks logs and certs |
| C2 | No DNS configured | `info` | Missing `set system name-server` — URL filtering and ATP Cloud won't resolve |
| C3 | No syslog configured | `warning` | Missing `set system syslog host` — no off-box log retention |
| C4 | SNMP community is public/private | `warning` | Default community strings are a known attack vector |
| C5 | No login banner | `info` | Missing `set system login message` — required for legal/compliance |
| C6 | No console/aux timeout | `info` | Missing `set system ports console timeout` — unattended sessions stay open |
| C7 | Telnet enabled | `warning` | `set system services telnet` — plaintext management protocol |
| C8 | No SSH configured | `info` | Missing `set system services ssh` — no secure remote management |
| C9 | Weak password policy | `info` | Users exist but no `set system login password minimum-length` |
| C10 | No login retry/lockout | `info` | Missing `set system login retry-options` — no brute-force protection |
| C11 | HTTP management enabled | `warning` | `set system services web-management http` (not https) — plaintext web admin |
| C12 | No root authentication | `warning` | Missing `set system root-authentication` — default credentials risk |

---

## License Gating

Builds on existing `SRX_LICENSE_TIERS` and `licenseTierCovers()` from `srx-view-transforms.js`.

### Feature Detection in SRX Output

| Command pattern | Required tier |
|----------------|--------------|
| `set services idp` | A1+ |
| `set services application-identification` / `match application` (non-`any`) | A1+ |
| `set security utm` / `set services content-security` | A2+ |
| `set services security-intelligence` | A1+ |
| `set services advanced-anti-malware` / `application-services ... atp` | P1+ |
| `set security policies ... ssl-proxy` | Base (included) |

### Behavior Modes

- **`enforceLicense: false`** (default) — emit `warning` findings for each gap, leave output intact
- **`enforceLicense: true`** — emit `unsupported` findings, remove gated command lines from output, return stripped commands list
- **No license selected** — skip license checks, emit single `info`: "Select a license tier in Model Selector for license validation"

---

## UI Integration

### Validate Button

- Added to the 5-button platform bar, after "Convert to SRX"
- Styled in orange (`--caution`) — app-driven, not LLM
- Shows finding count badge after first run
- Disabled when no SRX output exists
- Adjacent checkbox: `Enforce license gating` (off by default)

### Trigger Flow

1. User clicks Validate
2. Engine lazy-loads via `import()` (code-split like analysis engine)
3. Runs all three check modules against `srxOutput`, `targetModel`, `srxLicense`
4. Findings converted to warnings, appended to warnings array in `ConversionContext`
5. If license enforcement on + commands stripped → update `srxOutput` in state
6. Badge updates with finding count
7. User navigates to WarningsPanel to review

### Warning Management

- Validation warnings tagged with `_source: 'validation'` for identification
- Cleared and regenerated on each Validate run (prevents stacking)
- New `validation` severity filter added to WarningsPanel filter buttons
- Existing ack/fix/ignore workflow works unchanged on validation findings

### WarningsPanel Changes

- Add `validation` source filter button (orange badge) to filter warnings by `_source === 'validation'`
- Validation findings use their natural severity (`warning`/`unsupported`/`info`) — no new severity value needed
- No other panel changes needed — existing infrastructure handles display and status tracking

---

## What This Does NOT Include

- No changes to `srx-validator.js` (existing validation during conversion stays as-is)
- No automatic validation on conversion (on-demand only)
- No new nav items or panels (everything goes through WarningsPanel)
- No schema validation of intermediate config (out of scope)
- No changes to the Analysis Engine (separate concern)

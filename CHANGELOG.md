# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0.0] - 2026-03-28

### Added
- **DESIGN.md** — Design system documentation with color conventions, typography, spacing, and component patterns
- **LAG/aggregate interface support** — All 7 vendor parsers (PAN-OS, FortiGate, Cisco ASA, SRX, Huawei, SonicWall, Check Point) now parse LAG/LACP/port-channel/bond interfaces, with SRX ae converter output and Interface Mapper visual grouping
- **Conversion Report** — 8-section tabbed report under Output: rule count comparison, unused objects, shadowed rules, AI-disabled rules, migration delta dashboard, exportable summary, per-command decision tracking, rollback plan generation
- **Light/dark theme toggle** — User-selectable themes with OS preference detection, TopBar toggle, and localStorage persistence
- **3-node and 4-node MNHA support** — Extended chassis cluster / MNHA generation beyond 2-node configurations
- **Hardware capacity validation** — Post-conversion validation against SRX model limits (policies, sessions, zones, NAT rules, address objects)
- **Pre/post migration checklist** — Auto-generated task checklist based on parsed config features (certificates, JIMS, IDP, SecIntel, RADIUS, VPN, NAT, HA, syslog)
- **Interface mapping templates** — Save/load mapping profiles per source→target model pair for repeated migrations
- **Config version diff** — Side-by-side diff comparison of SRX outputs with LCS-based line diff and green/red highlighting
- **Policy dependency graph** — Interactive SVG showing address/service object relationships to policies with force-directed layout
- **Terraform/Ansible export** — Generate Junos Terraform provider resources or Ansible junos_config playbooks from SRX output
- **vSRX integration test harness** — PyEZ-based test script that pushes all 11 sample configs to a live vSRX and verifies commit

### Fixed
- **~45 SRX converter bugs** found during live vSRX testing (11/11 sample configs now commit clean):
  - UTM profile names avoid Junos reserved identifiers (`junos-av-*` → `custom-av-*`)
  - UTM web-filtering uses correct `juniper-enhanced profile` hierarchy
  - IKE proposals use `sha-256` (not `hmac-sha-256-128`)
  - IPsec proposals use `hmac-sha-256-128` correctly
  - NAT match addresses resolved from names to IPs
  - NAT pool addresses resolved for all vendor address field variants
  - Global policies use `security policies global policy` syntax when zone is `any`
  - Default-policy `permit-all` emitted when global policies exist
  - OSPF/OSPF3 interface names mapped through `mapInterfaceName` (loopback→lo0)
  - OSPF areas with no mapped interfaces skipped to prevent commit errors
  - Application-sets avoid name conflicts with member applications
  - `any` deduplicated in policy match (Junos constraint)
  - Interface deduplication prevents same interface in multiple zones
  - Address-book entries with host IP + non-host mask corrected to /32
  - Platform-dependent `junos-*` apps (mysql, mssql, oracle, postgres, quic, ocsp) auto-defined as `custom-*` aliases
  - Uppercase app names mapped for Huawei (HTTP→junos-http)
  - Firewall filter addresses resolved from names to IPs
  - Static route `metric` corrected to `preference`
  - Screen/IDP values clamped to Junos-valid ranges
  - SSL proxy and JIMS/user-ID generation skipped (requires manual PKI/server setup)
  - Custom application names sanitized (no leading digits, no dots)
  - Service objects with comma-separated ports converted to application-sets

### Changed
- **CSS transitions** — All 22 `transition: all` instances replaced with specific property transitions
- **Touch targets** — Toolbar buttons increased to 36px min, sidebar toggle to 32px min
- **Font sizes** — Status labels 9→10px, btn-sm 11→12px, nav items 12→13px, sidebar headers 11→12px
- **Empty states** — Added SVG icons and headings to WarningsPanel, SRXOutput, ContentRouter empty states
- **Accessibility** — Added `prefers-reduced-motion` media query

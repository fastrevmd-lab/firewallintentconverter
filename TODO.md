# Firewall to Intent Converter — Roadmap & TODO

## Completed Revisions

### Rev1 — Core Multi-Vendor Parsing & SRX Conversion
- [x] PAN-OS XML parser (zones, policies, NAT, address/service objects, application groups)
- [x] Junos SRX parser (set commands + hierarchical curly-brace format)
- [x] FortiGate / FortiOS parser (config/edit/set/next/end block format)
- [x] Cisco ASA / FTD parser (interfaces, objects, ACLs, NAT)
- [x] SRX set command converter with address-book, applications, policies, NAT rule-sets
- [x] SRX XML builder (hierarchical XML output)
- [x] Auto-detection of source vendor format
- [x] Implicit rule generation (PAN-OS intra-zone/interzone, FortiGate intrazone/deny, Cisco security-level, SRX deny)
- [x] FQDN / dns-name address objects (all vendors)
- [x] ICMP type/code preservation through full pipeline
- [x] Schedule support (FortiGate recurring/onetime, PAN-OS, Cisco time-ranges, SRX schedulers)
- [x] Nested address/service groups with correct set/application-set references
- [x] 120+ cross-vendor application mappings (PAN-OS, FortiGate, Cisco → Junos predefined apps)
- [x] Application group parsing and expansion
- [x] Sanitization (IPs, hostnames, keys → placeholders; restore on export)
- [x] Interactive React UI with dual platform view, inline editing, sortable/filterable tables
- [x] Hardware model selector with auto-detection (PAN-OS, SRX, FortiGate, Cisco models + EOS)
- [x] Interface mapper with auto-mapping and tunnel/loopback support
- [x] Per-rule LLM review with structured suggestion cards
- [x] Full-ruleset LLM review with multi-turn chat
- [x] Multiple LLM providers (Claude, OpenAI, Ollama, LM Studio, custom)
- [x] NAT editor (source, destination, static NAT with zone-pair rule sets)
- [x] Address/service object editors with tabbed interface
- [x] Zone editor with reusable chip editor

### Rev2 — HA, Screens, VPN, Infrastructure
- [x] HA → Chassis Cluster / MNHA (PAN-OS, FortiGate, Cisco failover, SRX)
- [x] Screen / DDoS profiles (zone protection, DoS policies → SRX screen ids-option)
- [x] VPN / IPsec (IKE + IPsec from all vendors → SRX vpn config)
- [x] Syslog forwarding (all vendors → SRX system syslog)
- [x] DHCP server pools and relay (all vendors → SRX DHCP/bootp)
- [x] QoS / CoS (traffic shaping, scheduler maps → SRX class-of-service)
- [x] Static routes with VRF/routing-instance, multi-vsys, VDOM contexts
- [x] Routing editor UI with routing context display
- [x] VPN editor UI with card-based tunnel editing
- [x] SRX subscription selection (Base, A1, A2, P1, P2) with feature gating

### Rev3 — Greenfield Builder & LLM Enhancements
- [x] Greenfield mode — LLM-guided interview builds SRX config from scratch
- [x] JSON action blocks (add_zone, add_policy, add_address, add_nat, add_route, add_screen)
- [x] Inline action cards in chat UI
- [x] Three independent system prompts (per-rule, full-ruleset, greenfield)
- [x] Use-case-aware interview (branch, data center, campus edge, remote/teleworker, cloud gateway)
- [x] Real-time preview of config in normal editors during interview

### Rev4 — Conversion Accuracy & L2 Support
- [x] **Predefined Junos app mapping** — Services matching Junos predefined apps (junos-ssh, junos-http, etc.) no longer generate redundant custom definitions. `WELL_KNOWN_PORTS` reverse lookup in parser-utils.js with `isPredefEquivalent()`. Policies correctly reference predefined names
- [x] **UTM/IDP enhanced generation** — Security profile definitions parsed from source configs (PAN-OS virus/spyware/vulnerability/url-filtering/file-blocking, FortiGate AV/IPS/app-control/webfilter/dnsfilter). UTM commands use source-derived parameters (web-filtering categories, content-filtering extensions, AV scan settings). IDP rules generated with severity-specific actions mapped from source (reset-both → drop-connection, alert → no-action, etc.)
- [x] **L2 / transparent / virtual-wire support** — All four parsers detect L2 mode: PAN-OS virtual-wire pairs + L2 zones, FortiGate transparent opmode + virtual-switch + forward-domain grouping, Cisco ASA `firewall transparent` + bridge-groups + BVI interfaces, SRX bridge-domains + family bridge. Converter generates `set bridge-domains` + `set interfaces ... family bridge` commands. UI shows Bridge Domains / L2 Interfaces / Virtual-Wire Pairs sections in RoutingEditor, L2 badges in InterfaceMapper
- [x] **Rule optimization / consolidation** — Extended shadow detector with 4 new analysis categories: redundant rules (subset of earlier permit), mergeable rules (adjacent, differ in one dimension), reorder recommendations (deny after broader permit), consolidation opportunities (3+ rules combinable into address group). Warnings panel updated with `info` severity and Optimization filter

### Rev5 — Multi-Firewall Logical Systems
- [x] (Skipped — deferred to future revision)

### Rev6 — Additional Vendor Parsers
- [x] **Check Point R80+/R81+ parser** — SmartConsole JSON export with UID-based object resolution from `objects-dictionary`, nested access-sections and inline-layer flattening, host/network/range/FQDN/group objects, service-tcp/udp/icmp/group objects, NAT rulebase (hide/static), optional Gaia clish text for interfaces and static routes, gateway topology zone derivation
- [x] **SonicWall SonicOS parser** — Dual-format support: REST API JSON (preferred) and CLI text fallback. Zones with security-type mapping (trusted/untrusted/public), IPv4/IPv6 address objects (host/network/range/FQDN/MAC with warnings), address groups, service objects with protocol/port, service groups, access rules with priority ordering, NAT policies (source/destination/combined), interfaces, route policies, built-in object resolution (X0 IP, X1 Subnet, etc.)
- [x] **Huawei USG parser** — VRP CLI (`display current-configuration`) with `#`-delimited section parsing. Firewall zones with priority, `ip address-set` type object (host/network/range/FQDN) and type group, `ip service-set` type object and group, `security-policy` rules with zone-pair routing, `nat-policy` SNAT and `nat server` DNAT, `time-range` schedules, IKE/IPsec VPN detection, `hrp` HA configuration, predefined service mapping (HTTP, HTTPS, DNS, SSH, etc.), static routes
- [x] **Vendor-specific sample configs** — Realistic sample configs for Check Point (6 rules, objects-dictionary + rulebase JSON with Gaia clish), SonicWall (6 rules, REST API JSON with zones/objects/NAT), and Huawei USG (6 rules, VRP CLI with zones/address-sets/security-policy)
- [x] **Hardware model databases** — Check Point (CP-1600 through CP-28000), SonicWall (TZ-270 through NSsp-13700), Huawei (USG6510E through USG6680E) with throughput specs, port counts, and auto-detection heuristics
- [x] **Interface auto-mapping** — Check Point `eth` → `ge-`, SonicWall `X` → `ge-`, Huawei `GigabitEthernet` → `ge-` and `XGigabitEthernet` → `xe-`, FortiGate `port` → `ge-` naming auto-mapped to SRX interfaces
- [x] **Vendor-specific platform views** — Check Point SmartConsole-style table (sections, Accept/Drop, Track, Install On), SonicWall zone-pair table (priority, DPI, Allow/Deny), Huawei USG zone-pair table (Permit/Deny, profiles)
- [x] **Full UI integration** — ModelSelector vendor labels, InterfaceMapper source model lookup, THROUGHPUT_LABELS, LLM vendorLabel, auto-detection routing, ConfigInput dropdown entries with help text

---

## Planned Revisions

### Rev7 — Multi-Firewall Logical Systems
- [ ] Multi-firewall collapse into logical-systems/tenants
- [ ] Import multiple configs and merge into a single SRX with logical-system separation
- [ ] Logical-system-aware address books, policies, and NAT
- [ ] Cross-logical-system traffic handling (lt- tunnel interfaces)

### Rev8 — UX & Workflow Enhancements
- [ ] **"I am new here" guided walkthrough** — Dismissible tooltip bubbles that walk first-time users through the import → review → convert workflow
- [ ] **Enhanced sanitization + mapping table** — Strip corporate branding, show before/after mapping table, provide pre-branded sample configs
- [ ] **Post-conversion diff view** — Side-by-side comparison of source vs generated SRX policy coverage with match highlighting
- [ ] **Save/load projects** — JSON export/import of full state (intermediate config, interface mappings, review status, LLM history)
- [ ] **Bulk rule operations** — Multi-select rules for batch accept/edit/delete/move
- [ ] **Greenfield templates** — Pre-built config templates for common deployments (branch office, DC edge, remote access VPN, hub-and-spoke)
- [ ] **Config syntax validation** — SRX commit-check equivalent (syntax validation, reference checks, conflict detection)

### Rev9 — Dynamic Routing & Identity
- [ ] **Dynamic routing protocols** — Parse and convert BGP, OSPF, EVPN, and VxLAN configurations from all supported source vendors to SRX equivalents:
  - BGP: neighbor config, AS numbers, route policies, address families, communities, peer groups
  - OSPF: areas, interfaces, authentication, stub/NSSA, route redistribution
  - EVPN: VXLAN tunnel endpoints (VTEPs), route targets, route distinguishers, MAC-VRF instances
  - VxLAN: VTEP interfaces, VNI mappings, underlay routing integration
  - Source vendors: PAN-OS (virtual-router BGP/OSPF), FortiGate (router bgp/ospf), Cisco ASA (router bgp/ospf), SRX round-trip
  - SRX output: `set protocols bgp`, `set protocols ospf`, `set protocols evpn`, `set interfaces vtep`, `set switch-options`
- [ ] **User-ID / identity-based policies** — Parse and convert user/group identity references in security policies:
  - PAN-OS: User-ID (`source-user` field, user/group references, User-ID agent config)
  - FortiGate: FSSO (Fortinet Single Sign-On) user/group policies, LDAP/RADIUS identity sources
  - Cisco ASA: Identity firewall (IDFW), AD agent, user-based ACLs
  - SRX output: `set services user-identification`, JIMS (Juniper Identity Management Service) integration, `source-identity` in policies
  - Intermediate schema: `source_users` / `source_user_groups` fields on security policies
  - UI: User/group display in policy table, identity source configuration in Settings

### Blocked — Waiting on Vendor APIs
- [ ] **Push to SDC / SD On-Prem / Mist** — Direct deployment to Juniper management platforms. Requires HPE Juniper public REST APIs. UI placeholder already present ("Push via MCP" button)

---

## Known Limitations

- **AAA / Authentication** — RADIUS, TACACS+, LDAP server config not converted (noted in output comments)
- **SSL/TLS Decryption** — SSL proxy, certificate management, PKI not converted
- **NetFlow / Telemetry** — sFlow, streaming telemetry not converted
- **Management Access** — Admin users, SNMP communities, SSH/API access not converted
- **Dynamic Routing** — Only static routes currently (Rev9 planned)
- **User Identity** — User-ID / FSSO / IDFW not converted currently (Rev9 planned)
- **Virtual-Wire** — SRX has no native vwire; mapped to bridge-domain with TODO comments for interface assignment
- **MNHA** — Only 2-node configurations supported
- **Application Mapping** — ~120 apps mapped; unmapped apps get `Customfwic` suffix + warning

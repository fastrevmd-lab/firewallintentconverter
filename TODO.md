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

### Post-Rev6 Enhancements
- [x] **CC BY-NC-ND 4.0 license** — Added license file, README badge, and package.json license field
- [x] **Zone dropdown selector** — Zone fields in the rule editor right panel now show a dropdown of available zones from the intermediate config instead of free-text input
- [x] **Per-rule LLM review overhaul** — Replaced Import/Import All buttons with individual Accept/Reject per suggestion. Added `notes` array to LLM response schema for informational observations (migration caveats, best-practice reminders) that don't map to a field change. Accepted notes persist on the rule in a `_llm_notes` field, display in a Notes section in the rule editor with remove capability, and emit as `# NOTE:` comments above the policy in SRX set command output
- [x] **Rich LLM context** — Per-rule review now sends the full SRX policy path, zone pairs, match criteria (source/dest addresses, applications), action, application services (UTM/IDP mapped from profiles), logging, description with tags, schedule, and disabled status. Referenced address and service objects are resolved from the intermediate config and included with their definitions (IP/subnet, port/protocol). Capped at 50 resolved objects
- [x] **Security profiles in LLM suggestions** — `security_profiles` added as a valid field for LLM suggestions, allowing the LLM to recommend adding or changing individual security profiles (virus, spyware, url-filtering, etc.)
- [x] **Type coercion on LLM suggestions** — `coerceSuggestionValue()` normalizes LLM output before applying: strings wrapped to arrays for array fields, string "true"/"false" coerced to booleans, invalid security_profiles values auto-rejected
- [x] **Editable system prompt files** — LLM system prompts extracted to plain-text files in `static/prompts/` (translate.txt, full-review.txt, greenfield.txt). Loaded on page init with localStorage > file > hardcoded default priority chain
- [x] **LLM translation workflow** — "Translate with LLM" button sends all source policies to the LLM for one-shot translation to optimized SRX format. Replaces the old per-rule review + full-ruleset review workflow. Translated rules get `_review_status: 'llm_reviewed'` and must be manually accepted. Translation prompt includes vendor action mapping, SRX subscription tiers (Base/A1/A2/P1/P2), security profile mapping, logging best practices, and rule optimization guidance
- [x] **Vendor-aware translation prompts** — Translation system prompt includes vendor-specific migration pitfalls for all 6 source vendors (PAN-OS, FortiGate, Cisco ASA, Check Point, SonicWall, Huawei USG) plus a cross-vendor gap summary with 8 key gaps ranked by conversion impact
- [x] **Translation progress panel** — Real-time progress indicator in the right pane during LLM translation showing live elapsed timer (min:sec), phase indicator with pulse animation, chunk progress bar, and estimated prompt/response token counts
- [x] **Subscription-aware translation** — SRX license tier passed in both system prompt (detailed tier breakdown) and user prompt (explicit instruction). LLM maps security profiles to correct tier and flags features requiring upgrades in `_translation_notes`
- [x] **Greenfield "Import LLM Config"** — "Translate with LLM" button renamed to "Import LLM Config" in greenfield mode. Greenfield "Start Interview" auto-opens model selection
- [x] **Per-vendor translate prompts** — 7 vendor-specific translate prompt files (PAN-OS, FortiGate, Cisco ASA, Check Point, SonicWall, Huawei USG, SRX-to-SRX) each containing that vendor's full feature equivalency matrix, specific migration pitfalls, action mapping, and security profile mapping. Auto-selected at translation time based on detected source vendor. SRX-to-SRX prompt focuses on optimization, modernization, and best-practice cleanup
- [x] **Vendor prompt Settings UI** — Dropdown selector in Settings > "Translate Ruleset LLM Instructions" to view/edit per-vendor prompts independently. Each vendor prompt is stored separately in localStorage and loaded from `static/prompts/translate-{vendor}.txt` on disk
- [x] **PAN-OS EDL block list handling** — LLM prompt instructs disabling rules referencing PAN-OS proprietary EDLs (panw-bulletproof-ip-list, panw-highrisk-ip-list, etc.) and enabling SecIntel on all allow rules as replacement
- [x] **PAN-OS Panorama/management app detection** — LLM prompt instructs disabling rules whose only purpose is PAN-OS infrastructure (panorama, paloalto-updates, paloalto-wildfire-cloud, etc.) with "No longer needed rule, by LLM" description
- [x] **PAN-OS SSL Decryption parser** — Parses `<rulebase><decryption>` rules from PAN-OS configs including action (decrypt/no-decrypt), type (ssl-forward-proxy/ssh-proxy/ssl-inbound-inspection), certificate references, URL categories, and decryption profiles. Displayed in a new "SSL B&I" tab in the from-PA view
- [x] **PAN-OS Policy-Based Forwarding parser** — Parses `<rulebase><pbf>` rules from PAN-OS configs including from-zone/interface, forwarding action (forward/discard/no-pbf), egress interface, next-hop, monitor settings, and symmetric return. Displayed in a new "PBF" tab in the from-PA view
- [x] **SSL B&I and PBF tabs** — Two new tabs in the center panel between Security Rules and Objects (from-PA view only). Read-only display tables showing decryption and PBF rules parsed from the source PAN-OS config
- [x] **PAN-OS → SRX security profile mapping fix** — Corrected the PAN-OS security profile to SRX subscription mapping: Antivirus→Flow-based AV, Anti-Spyware→Anti-malware, Vulnerability→IPS, URL Filtering→Content Security (destination object), File Blocking→Content Security (Content Filtering), WildFire→no direct mapping (note ATP). Updated translate-panos.txt prompt to instruct LLM to set `_srx_*` boolean flags. Added safety-net mapping in `parseTranslationResponse()` so UI toggles display correctly regardless of LLM output format
- [x] **PAN-OS SSL Decryption → SRX SSL Proxy mapping** — Hybrid LLM + deterministic approach. Decryption rules are now sent as context alongside security policies in the LLM translation prompt, instructing the LLM to set `_srx_decrypt: true` on security rules whose traffic scope matches a decrypt-action decryption rule. A zone-pair safety net (`applyDecryptionSafetyNet()`) runs after LLM translation as fallback, auto-setting `_srx_decrypt` on allow rules in zone-pairs covered by decryption rules that the LLM may have missed. Handles ssh-proxy gaps, ssl-inbound-inspection cert notes, and no-decrypt exclusions
- [x] **Warning review actions** — Navbar warnings badge is now clickable (switches to Warnings tab), shows unresolved/total count (e.g., `3/12`), and turns green when all resolved. Each warning has Ack/Fixed/Ignore action buttons with click-to-undo support. WarningsPanel adds Unresolved/Resolved status filter alongside existing severity filters. Resolved warnings are dimmed
- [x] **Navbar policy label clarity** — Review progress counter now reads `Policies: X/Y accepted` instead of just `X/Y accepted` to make it clear it refers to security policies

### Rev7 — Multi-Firewall Logical Systems & Minor Features
- [x] **Feedback/suggestion box** — Chat-bubble icon in the navbar opens a modal where users pick a category (Bug Report, Feature Request, Improvement), write a description, and submit as a pre-filled GitHub Issue in a new tab
- [x] **Site Name / Site Group** — Optional text fields in Model Selection for site identification. Values are emitted as header comments at the top of SRX set-command and XML output (e.g. `# Site: branch-office-seattle`). Prep for future SDC/Mist integration with site/group concepts
- [x] **Per-vendor conversion system prompts** — 7 vendor-specific translate prompt files with full feature equivalency matrices, migration pitfalls, action mapping, and security profile mapping. Auto-selected at translation time based on detected source vendor
- [x] **PAN-OS parser: SSL B&I and PBF rules** — PAN-OS parser now extracts SSL Decryption (`<rulebase><decryption>`) and Policy-Based Forwarding (`<rulebase><pbf>`) rules. Displayed in dedicated from-PA tabs
- [x] **Multi-firewall collapse into logical-systems/tenants** — Multi-LS Merge mode with mode toggle in navbar. Import N configs (one per slot), each assigned to a logical-system. Auto-detect multi-vsys (PAN-OS), multi-VDOM (FortiGate), and multi-LS/tenant (SRX) configs with auto-split prompt. Cross-LS traffic detection from shared zone names generates lt- tunnel interface pairs. Merged output wraps each config in `set logical-systems ...` / `<logical-systems>` with cross-LS lt- commands
- [x] **Import multiple configs and merge** — Slot-based UI in ConfigInput with tab bar for each logical-system. Center panel config selector switches between slots. Each slot independently parsed with its own vendor/model/interface mappings
- [x] **Logical-system-aware address books, policies, and NAT** — SRX parser detects `logical-systems` and `tenants` sub-trees, parses each context independently using existing parse functions, tags policies and NAT rules with `_logical_system` field
- [x] **Cross-logical-system traffic handling** — Auto-detection of shared zone names across logical-systems. Generates `lt-0/0/0` tunnel interface pairs with `encapsulation ethernet`, `peer-unit`, `family inet`, and zone bindings. Displayed as cross-LS link badges in merge config selector
- [x] **Enhanced sanitization + mapping table** — Clickable sanitize badge expands a collapsible mapping table showing all replacements: type-colored badges (Hash/Key/SNMP/User/Public IP), masked originals for secrets (full values for IPs), placeholder codes, and restore-on-export indicator. Inline stats summary (e.g., "3 Public IPs, 2 Hashes")
- [x] **Post-conversion diff view** — New "Diff" tab in bottom panel comparing source vs LLM-translated policies. Three-pass rule matching (index, exact name, fuzzy Levenshtein). Field-level diff table (12 fields) with color coding: green=added, red=removed, amber=modified, dimmed=unchanged. Expandable rows show per-field source→translated changes, LLM translation notes, and rule summaries. Filter bar for status categories
- [x] **Save/load projects** — JSON export/import of full state (intermediate config, interface mappings, model selections, review status, warnings, LLM-translated policies) as `.fpic.json` files. Navbar save/load icons, auto-generated project names, version-safe migration, load confirmation modal with project details and "replace current work" warning
- [x] **Greenfield templates + day-0 system config** — 4 pre-built deployment templates (Branch Office, Data Center, Campus Edge, Cloud Gateway) plus Blank, with template picker UI. Each template pre-fills zones, security policies, NAT, address objects, screen profiles, syslog, static routes, and day-0 system config (hostname, DNS, NTP, timezone, login banner, management services). System config emitted as SRX set commands and XML. Template-aware LLM interview skips use-case discovery and jumps to refinements. Fixed greenfield address/service field name bug (`addresses`→`address_objects`, `services`→`service_objects`)
- [x] **SRX Health Check** — Audit mode for existing SRX configurations. New "SRX Health Check" vendor dropdown option with dedicated audit prompt covering 12 assessment categories: PCI DSS v4.0, NIST SP 800-41r1, CIS Juniper OS Benchmark, logging completeness, security profile assessment, screen profile coverage, rule hygiene, application modernization, naming conventions, NAT best practices, zone architecture, and system infrastructure. Simplified model selector (source model + license only, target auto-matches, no interface mapping). Policies returned unchanged with severity-tagged findings in `_translation_notes`
- [x] **Security hardening** — Genericized API error messages in production (all endpoints), prototype pollution guards via `safeJsonParse()` on untrusted input (project files, LLM responses, localStorage), production CSP `connectSrc` restricted to remote APIs only, format parameter validation on `/api/convert` and `/api/merge-convert`, dependency vulnerability fixes (rollup, fast-xml-parser)

### Rev8 — UX & Workflow Enhancements
- [x] **"I am new here" guided walkthrough** — 6-step spotlight tour highlighting Config Input, Parse button, Center panel, Translate with LLM, Rule Details, and SRX Output. CSS mask overlay with positioned tooltips, Next/Skip/Finish navigation, "Don't show again" checkbox with localStorage persistence, and navbar `?` help button to re-trigger the tour anytime. Graceful fallback when target elements are not in DOM
- [x] **Bulk rule operations** — Multi-select rules with checkbox column across all 7 vendor table renderers (PAN-OS, SRX, FortiGate, Check Point, Cisco ASA, SonicWall, Huawei USG). Ctrl/Cmd+click toggle, Shift+click range selection, header checkbox select-all with indeterminate state. Floating BulkActionBar with Accept All, Enable/Disable, Move Up, Move Down, Delete Selected. Selection auto-clears on view/tab/slot change
- [x] **Multi-logical-system vendor detection fix** — SRX configs using only `set logical-systems` or `set tenants` prefixed commands now correctly detected as Junos SRX instead of falling through to PAN-OS parser

---

## Planned Revisions

### Rev9 — Dynamic Routing & Identity
- [x] **Dynamic routing protocols (BGP + OSPF)** — Parse and convert BGP and OSPF configurations from 5 vendors to SRX equivalents:
  - BGP: peer groups, neighbors, AS numbers, route redistribution, per-instance support
  - OSPF: areas (normal/stub/NSSA), interfaces, cost/hello/dead intervals, passive, authentication, redistribution
  - Source vendors: PAN-OS (virtual-router BGP/OSPF), FortiGate (`config router bgp`/`ospf`), Cisco ASA (`router bgp`/`ospf`), Huawei USG (`bgp`/`ospf` sections), SRX round-trip
  - SRX output: `set protocols bgp group`, `set protocols ospf area`, `set routing-options autonomous-system`
  - SRX XML builder: unified `buildRoutingXml()` emits `<routing-options>` + `<protocols>` with per-instance support
  - RoutingEditor UI: BGP section (peer groups, neighbors, networks) + OSPF section (areas, interfaces)
  - Check Point + SonicWall: empty defaults (no dynamic routing in policy exports)
  - Sample configs: BGP/OSPF added to PAN-OS, FortiGate, SRX, Cisco ASA, Huawei samples
- [x] **OSPFv3 (IPv6 OSPF)** — Parse and convert OSPFv3 from 5 vendors:
  - Separate `ospf3_config[]` schema (mirrors OSPF, no MD5 auth, adds `instance_id`)
  - SRX: `set protocols ospf3`, FortiGate: `config router ospf6`, Cisco ASA: `ipv6 router ospf` + interface-level
  - PAN-OS: `<ospfv3>` XML in virtual-router, Huawei: `ospfv3` section headers
  - Check Point + SonicWall: stubs only (no native OSPFv3 in policy exports)
  - RoutingEditor UI: OSPFv3 section (indigo badge, Instance ID column, no Auth)
- [x] **EVPN/VxLAN** — Core EVPN-VxLAN parsing and conversion:
  - `evpn_config[]` schema: instance-type, encapsulation, multicast-mode, VNI list, RD, RT, VRF target, VLAN-VNI mappings
  - `vxlan_config[]` schema: standalone VxLAN tunnels (VTEP source, VNIs, remote VTEPs, mcast groups)
  - SRX parser: full EVPN (`protocols evpn`, `switch-options`, `vlans` with `vxlan vni`)
  - FortiGate: `config system vxlan` (VNI, remote-ip, dstport)
  - Cisco ASA: `nve` blocks (source-interface, member vni, mcast-group)
  - SRX converter: `set protocols evpn`, `set switch-options`, `set vlans <name> vxlan vni`
  - SRX XML builder: `<evpn>`, `<switch-options>`, `<vlans>` top-level, per-instance `mac-vrf`
  - RoutingEditor UI: EVPN section (RD/RT/VRF target, VLAN-VNI table), VxLAN tunnels section
- [x] **User-ID / identity-based policies** — Parse and convert user/group identity references in security policies:
  - `source_users` field on intermediate schema, extracted from all 7 vendors
  - PAN-OS: `<source-user>` extraction (DOMAIN\user, group references, special values)
  - FortiGate: FSSO users/groups (`set users`, `set groups`)
  - Cisco ASA: IDFW `user`/`user-group`/`object-group-user` tokens in ACLs
  - Check Point: Access Role objects (`type: 'access-role'`) separated from address sources
  - SonicWall: `source.user` and `source.group` from JSON rules
  - Huawei USG: `source-user` and `source-user-group` lines in security policies
  - SRX parser: `source-identity` round-trip support
  - SRX converter: `set ... match source-identity`, JIMS service config (placeholder)
  - SRX XML builder: `<source-identity>` elements + `<user-identification>` service block
  - PolicyTable: conditional "Users" column across all 7 vendor views
  - InterviewPanel: editable Source Users chips field
  - DiffPanel: source_users field comparison
  - LLM: schema, translation rules, normalization, greenfield prompt
  - Shadow detector: identity-aware shadow analysis

### Rev10 — LLM Rule Grouping
- [x] **AI-powered policy grouping** — LLM analyzes rulesets and organizes them into logical groups (Security Director-style):
  - `groupPolicies()` in `llm-client.js` — system prompt analyzes zone pairs, applications, naming conventions, descriptions
  - Chunked support for large rulesets (50 rules/chunk, cross-chunk group merging)
  - Structured JSON output: `[{ group_name, rule_indices[], reasoning }]`
  - Response parsing with validation, duplicate detection, and ungrouped rule handling
- [x] **Grouped PolicyTable UI** — Collapsible group sections across all vendor views:
  - Group headers with arrow toggle, rule count, LLM reasoning tooltip
  - Rename group (inline edit), dissolve group (move to Ungrouped), clear all groups
  - "Auto-Group" button in filter toolbar (shows progress, group count when active)
  - SRX view renders grouped rules with full zone-pair sub-grouping
  - Other vendor views render generic grouped tables
- [x] **Group comments in SRX output** — JUNOS-preserved comments marking group boundaries:
  - Set commands: `/* ===== Group: Internet Access ===== */`
  - XML: `<!-- ===== Group: Internet Access ===== -->`
  - Comments survive JUNOS `commit` and `show configuration`
- [x] **Project persistence** — Groups saved/loaded in `.fpic.json` project files (`ruleGroups` state key)
- [x] **Groups cleared on re-parse** — Ensures stale groups don't persist across different configs

### Rev11 — Incremental IPv6 Support
- [x] **`detectIpVersion()` helper** — Auto-detects IPv4 vs IPv6 from address strings (`parser-utils.js`)
- [x] **IPv6 interface parsing (all 7 parsers)** — Dual-stack `ipv6` field extracted alongside IPv4:
  - SRX: `family.inet6.address` | FortiGate: `ipv6.ip6-address` | PAN-OS: `layer3.ipv6.address`
  - Cisco ASA: `ipv6 address` command | Huawei: `ipv6 address` regex
  - Check Point: `set interface ... ipv6-address` | SonicWall: `config.interfaces.ipv6`
- [x] **NAT ANY address fix** — 6 locations in `srx-converter.js` and `srx-xml-builder.js` now use `::/0` for IPv6 NAT rules instead of hardcoded `0.0.0.0/0`
- [x] **`ip_version` auto-tagging** — All address objects auto-tagged with `ip_version: 'v4'|'v6'|null` via `detectIpVersion(obj.value)` post-processing in all 7 parsers
- [x] **Interface address output** — SRX converter emits `set interfaces ... family inet6 address` for IPv6 interfaces; XML builder emits `<inet6><address>` elements
- [x] **InterfaceMapper IPv6 display** — Shows `v6:` prefix with IPv6 address below interface name in mapping table
- [x] **Dual-stack sample configs** — SRX, FortiGate, Cisco ASA, PAN-OS samples updated with IPv6 interface addresses

### Rev12 — Migration Report Generation
- [x] **`generateReportHtml()` utility** — Self-contained HTML report generator with 12 sections (executive summary, zones, interfaces, policies, NAT, address/service objects, routing, warnings, conversion stats). Dark theme with print-friendly `@media print` overrides. Collapsible sections. XSS-safe HTML escaping.
- [x] **ReportModal component** — Modal with summary stats grid and "Generate & Download" button. Blob download as `.html` file.
- [x] **Navbar Report button** — Appears alongside Interfaces button when config is parsed and target model selected. Opens ReportModal.
- [x] **Rule group support** — Report displays policies grouped by LLM-generated rule groups when available, with ungrouped policies in a separate section.

### Rev13 — IDE-Style GUI Redesign
- [x] **Context architecture** — Decomposed monolithic `app.jsx` (2382 lines, ~50 useState calls) into 5 React Contexts with `useReducer`:
  - `ConfigContext` — Core data model (intermediate config, source/target vendor, sanitization, rule groups, warning statuses)
  - `UIContext` — Visual state (active tab, selected rule, modals, loading, panel dimensions, command palette)
  - `ConversionContext` — Output state (SRX output, warnings, summary, format, target context)
  - `MergeContext` — Multi-firewall merge mode (config slots, active slot, cross-LS links)
  - `UndoContext` — History stack (max 50 snapshots of intermediate config, undo/redo)
- [x] **Custom hooks** — 7 hooks extracting handler logic from app.jsx:
  - `useConfig` — parse, sanitize, CRUD rules, update zones/NAT/VPN/HA/etc.
  - `useConversion` — convert to SRX, merge convert
  - `useLLM` — translate with LLM, group with AI, bulk accept/delete/toggle/move
  - `useProject` — save/load project files
  - `useUndoRedo` — undo, redo, push snapshot
  - `useResizablePanel` — mouse drag resize with min/max constraints, localStorage persistence
  - `useKeyboardShortcuts` — 39 keyboard shortcuts with centralized registry
- [x] **IDE-style 4-panel layout** — Flex-based layout replacing CSS Grid:
  - TopBar: brand, stats badges, action buttons
  - Left sidebar: collapsible NavTree with icon-only mode (48px collapsed, 260px expanded)
  - Center: breadcrumb + content router rendering all 17 editor views
  - Right inspector: InterviewPanel with rule details, collapsible with visible re-expand tab
  - Bottom status bar: source/target model, rule progress, warning count, undo depth
- [x] **Navigation tree** — Hierarchical nav replacing 13 flat tabs:
  - Import / Config, Sanitized Objects, Security (Policies, NAT, Zones, Screens), Objects, Network (Intf/Routing, VPN, DHCP), System (HA, QoS, Syslog), Output (SRX Config, Warnings, Diff)
  - Inline SVG icons, count badges auto-updated from intermediate config
  - Groups expand/collapse with arrow toggle
- [x] **Sanitized Objects nav item** — Dedicated persistent view (second in left nav after Import) showing full sanitization mapping table with type badges, summary counts, and restore status. Only appears after parsing when sanitization produced results
- [x] **Right inspector wired to InterviewPanel** — Full rule details on click: editable fields, zone dropdowns, security profiles, translation notes, accept button. Routes to correct update handler (translated vs source view)
- [x] **Collapsible panels** — Left sidebar and right inspector both collapsible. Right panel shows 24px clickable tab strip when collapsed for re-expansion. Double-click resize handle to toggle
- [x] **Command palette** — Ctrl+P overlay with fuzzy search across 21+ commands and dynamic zone commands
- [x] **ContentRouter** — Maps `editTab` to all 17 editor components, bridging context data to existing prop-based components
- [x] **Keyboard shortcuts** — 39 shortcuts including Ctrl+Z/Y undo/redo, Ctrl+P command palette, Ctrl+B/Shift+B panel toggles, Ctrl+1-4 nav, j/k/a/n rule navigation
- [x] **Default to Import** — App opens on Import/Config view instead of empty Policies tab
- [x] **app.jsx reduced from 2382 to ~450 lines** — Layout shell with context hooks, remaining greenfield/merge handlers, modal rendering
- [x] **Virtualized tables** — `useVirtualScroll` hook with spacer-based table windowing. Renders only ~60-80 visible rows regardless of total count. RAF-batched scroll handler, ResizeObserver-driven container measurement, per-row height caching with measurement fallback for variable-height SRX rows. Flat virtual list model unifies grouped mode, SRX zone-pair headers, and flat mode into a single scroll container. Auto-scroll on keyboard navigation (j/k), height cache reset on vendor view switch. Zero external dependencies

### Blocked — Waiting on Vendor APIs
- [ ] **Push to SDC / SD On-Prem / Mist** — Direct deployment to Juniper management platforms. Requires HPE Juniper public REST APIs. UI placeholder already present ("Push via MCP" button)

---

## Known Limitations

- **AAA / Authentication** — RADIUS, TACACS+, LDAP server config not converted (noted in output comments)
- **SSL/TLS Decryption** — PAN-OS SSL B&I rules parsed, displayed in dedicated tab, and used during LLM translation to set `_srx_decrypt` on matching security rules. Full SRX SSL Proxy config generation not yet automated (certificate management, PKI, proxy profiles require manual setup)
- **Policy-Based Forwarding** — PAN-OS PBF rules now parsed and displayed in dedicated tab; SRX filter-based forwarding generation not yet automated
- **NetFlow / Telemetry** — sFlow, streaming telemetry not converted
- **Management Access** — Admin users, SNMP communities, SSH/API access not converted
- **Dynamic Routing** — BGP, OSPF, OSPFv3, EVPN/VxLAN supported across applicable vendors
- **User Identity** — User-ID / FSSO / IDFW parsed and converted to SRX `source-identity` — requires manual JIMS server configuration
- **Virtual-Wire** — SRX has no native vwire; mapped to bridge-domain with TODO comments for interface assignment
- **MNHA** — Only 2-node configurations supported
- **Application Mapping** — ~120 apps mapped; unmapped apps get `Customfwic` suffix + warning

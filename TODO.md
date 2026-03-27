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
- [x] **Context-aware autocomplete** — Shared `AutocompleteInput` component providing filtered suggestion dropdowns when editing policy fields. Suggestions sourced from parsed `intermediateConfig` (zones, address objects/groups, service objects, applications/groups). Integrated into PolicyTable inline cell editing (double-click) and InterviewPanel chip fields. Keyboard navigation (Arrow Up/Down, Enter, Tab, Escape), multi-token support for comma-separated values, case-insensitive prefix matching. Zero external dependencies
- [x] **LLM risk disclaimer** — Mandatory startup warning screen with 5 risk categories (data retention, topology disclosure, attack surface, credential exposure, compliance). Three acceptance modes: accept all risk, accept local LLM only (disables cloud providers in Settings), or reject (blocks app usage with reconsider option). Built-in sanitization documentation with coverage summary. Persisted in localStorage
- [x] **Expanded sanitization** — 8 sanitization categories: password hashes, pre-shared/API keys, SNMP communities, usernames, public IPs, certificate private keys (PEM blocks + XML), server hostnames/FQDNs (LDAP/RADIUS/NTP/DNS), BGP AS numbers, plaintext set-command secrets (FortiGate/SRX), RADIUS/TACACS shared secrets. Color-coded type badges in Sanitized Objects view
- [x] **Strict Content Security Policy** — Production-only CSP via Vite `transformIndexHtml` plugin. No `'unsafe-inline'` — all scripts and CSS are external hashed bundles. Directives: `script-src 'self'`, `style-src 'self'`, `connect-src` allows LLM APIs + localhost, `object-src 'none'`, `base-uri 'self'`. Dev mode skips CSP for HMR compatibility
- [x] **Code splitting** — Dynamic `import()` for all 7 vendor parsers, 2 converters, validator, and shadow detector in `engine.js` (loaded on demand per user action). `React.lazy()` for 17 editor tab components in ContentRouter and 7 modal components in app.jsx with `Suspense` boundaries. Initial bundle reduced from 1,192 KB to 358 KB (70% reduction, 40 lazy-loaded chunks). No Vite config changes — Vite auto-splits on dynamic imports

### Rev14 — PyEZ Bridge Push-to-Device
- [x] **PyEZ Bridge service** — Lightweight Python Flask service (`tools/pyez-bridge/`) wrapping Juniper PyEZ for NETCONF device management. REST API on localhost:8830 with 12 endpoints: health, device CRUD, config load, diff, commit-check, commit (with confirm timer), confirm, rollback. Device credentials stored server-side in `devices.yaml`
- [x] **Push to SRX workflow** — Multi-step PushModal component with 4-step wizard: device selection, config load + diff preview, commit check validation, and commit with optional commit-confirm timer and auto-rollback countdown. usePush hook manages push state and bridge API calls. Sanitized IPs automatically restored before push
- [x] **SRX Device Connection settings** — Renamed MCP Connection tab to SRX Device Connection. PyEZ Bridge URL configuration with connection testing. Device add/remove management via bridge API. localStorage migration from old mcp-settings key
- [x] **Push to SRX button** — Renamed "Push MCP" to "Push to SRX" with smart routing: opens PushModal when bridge is configured, Settings tab when not. Disabled when no SRX output exists

### Rev15 — Virtual-Wire, SSL Proxy, PBF, NetFlow
- [x] **Virtual-Wire completion** — PAN-OS vwire pairs now auto-assign SRX interfaces via Interface Mapper. Generates `bridge-domain` + `family bridge` interface bindings. FortiGate transparent-mode virtual-switch also synthesizes vwire pairs. Unresolved interfaces get actionable warnings
- [x] **Full SRX SSL Proxy generation** — Decryption rules (PAN-OS, FortiGate ssl-ssh-profile) now generate `set services ssl proxy profile` commands with PKI ca-profile placeholders. SSL forward-proxy and inbound-inspection profiles. Policy `_srx_decrypt` attachment via `application-services ssl-proxy profile-name`. FortiGate deep-inspection profiles auto-set `_srx_decrypt` on matching policies
- [x] **Policy-Based Forwarding conversion** — PAN-OS PBF, FortiGate `config router policy`, and SRX firewall filter round-trip. Generates routing-instances (type forwarding), firewall filter terms, and interface filter bindings. Nav sidebar shows PBF tab with badge count
- [x] **NetFlow / Flow Monitoring** — End-to-end support: PAN-OS ip-flow-export, FortiGate netflow/sflow, Cisco ASA flow-export, Huawei NetStream, SRX inline-jflow round-trip. Converter generates `forwarding-options sampling` + `services flow-monitoring`. New FlowMonitoringEditor UI with collectors, sampling, and template sections. Nav sidebar shows Flow Monitoring under Network
- [x] **SSL B&I and PBF nav items** — Added missing sidebar navigation entries for SSL B&I (decryption) and PBF tabs under Security section

### Rev16 — No-AI Deterministic Mode & Analysis Engine
- [x] **No-AI / Deterministic mode** — Third LLM risk acceptance mode ("No AI Mode") bypasses all LLM calls entirely. Clickable "No AI" badge in TopBar returns to risk disclaimer to switch modes. Greenfield and SRX Health Check hidden in deterministic mode. Auto-Group button hidden when no LLM configured
- [x] **Configuration Analysis Engine** — 7-check pre-conversion analysis engine (ported from fatcat-converter, credited):
  - Unused objects: address/service objects not referenced by any policy
  - Shadowed policies: rules fully covered by earlier rules (never matched)
  - Duplicate policies: rules with identical match criteria and action
  - Disabled rules: policies marked disabled in source config
  - Logging disabled: permit rules with no logging enabled
  - Overly permissive: rules with `any` source, destination, and application
  - Empty groups: address/service groups with zero members
  - AnalysisApplicator for one-click remediation (remove/disable flagged items)
- [x] **L7 application mapping table** — 236-entry vendor-to-Junos application mapping database (from fatcat-converter, credited). Covers PAN-OS, FortiGate, Cisco ASA/FTD, Check Point, SonicWall, Huawei USG → Junos predefined apps with confidence scores. Runtime injection pattern (`setMapVendorApp`) for async-loaded data in synchronous parser pipeline
- [x] **Deterministic security profile mapping** — Built-in profile-to-SRX mapping table for converting security profiles without LLM. Maps source vendor profile types (AV, IPS, URL filtering, etc.) to SRX subscription features (flow-based AV, IDP, content-security, ATP)
- [x] **Descriptive SRX rule naming** — `generateDescriptiveName()` creates human-readable policy names from zone pairs, addresses, apps, and action (e.g., `trust-to-untrust_webservers_http-permit`) when source rule names are generic or missing
- [x] **4-button platform bar on all tabs** — Redesigned platform bar with From-XXX, Analysis, Review w/LLM, and To-SRX buttons visible on all 16+ editor tabs (not just rules/decryption/PBF). Analysis button shows finding count badge, runs analysis on first click, navigates to results on subsequent clicks. Review w/LLM greyed out with tooltip in deterministic mode
- [x] **Analysis → SRX view population** — "Apply Analysis" copies cleaned policies into `srxTranslatedPolicies` and auto-switches to SRX rules view for review before export. Deterministic SRX fallback shows source policies when no LLM translation exists
- [x] **LLM prompt enhancement** — App mapping hints injected into LLM translation prompts (vendor app → Junos app at confidence >= 0.7). Pre-filter unused objects before sending to LLM to reduce token usage
- [x] **Analysis findings in inspector** — Right panel shows clickable analysis finding badges when on rules tab, linking to full analysis view
- [x] **MCP → PyEZ Bridge documentation** — README updated to replace all MCP Server references with PyEZ Bridge terminology throughout

### Rev17 — UX Polish & SRX Screen Best Practices
- [x] **Color-coded LLM risk indicators** — Orange (`--llm-cloud`) for cloud LLM features, lime (`--llm-local`) for local LLM, green for No AI. Applied to risk disclaimer buttons, Review w/LLM, Auto-group w/LLM, Greenfield dropdown. Hover tooltips warn about data sharing
- [x] **Violet caution color for warnings/analysis** — New `--caution: #a78bfa` (violet) CSS variable distinguishes warnings and analysis badges from orange LLM indicators. Applied to platform bar, nav tree, TopBar, RightPanel findings, AnalysisPanel, WarningsPanel, SRXOutput
- [x] **TopBar stat badge improvements** — Per-status warning counters (ack/fix/ign) with matching colors and teal arrows. Policies badge: `Policies N → Accepted N` with violet labels and green accepted count. Improved contrast (white text on dark backgrounds)
- [x] **Juniper brand green** — `--juniper-green: #90C641` (from SRX datasheet) applied to target model names in TopBar, platform bar, StatusBar, ConfigInput, and ModelSelector
- [x] **5-button platform bar workflow** — Redesigned from 3 buttons to seamless 5-button strip: From-XXX › Analysis › Review w/LLM › To-SRX › Convert to SRX. Chevrons between buttons, inline Convert button in Juniper green. Removed Push SDC/Mist buttons
- [x] **Log count enabled by default** — `_srx_log_count` defaults to true for all SRX policies. Outputs `then count` in set commands and `<count/>` in XML. Toggle still available per-rule
- [x] **Sanitized Objects blank screen fix** — Fixed temporal dead zone bug where `renderPlatformBar` (const arrow function) was called before its declaration in early-return code paths. Hoisted above all early returns
- [x] **SRX Screen Best Practice Presets** — "Apply Best Practice" toolbar in ScreenEditor with Standard/Strict presets:
  - Auto-detect internet-facing zones (name matching: untrust/outside/wan/dmz + default route analysis)
  - Interface speed inference from naming (ge=1G, xe=10G, et=25G+)
  - Speed-scaled thresholds: 1G/10G/25G-40G/100G tiers (1x/10x/25x/100x multipliers)
  - Standard: balanced protection (SYN attack 200pps, UDP 5000pps, core boolean protections)
  - Strict: aggressive protection (lower thresholds, all boolean screens enabled including spoofing/winnuke/tcp-no-flag)
  - Preset/speed/zone selection panel with threshold preview, replace vs merge toggle
  - Separate SYN alarm threshold field (optional, falls back to 5x attack threshold)
  - Generated screens appear as fully editable cards with zone bindings

### Rev18 — Section Acceptance Workflow & Speed Tier Fix
- [x] **Section acceptance workflow** — Review & accept tracking extended from policies to all config sections (NAT, Zones, Objects, Screens, Routing, VPN, DHCP, Flow Monitoring, HA, QoS, Syslog, SSL B&I, PBF). `sectionAcceptance` state in ConfigContext with `ACCEPT_SECTION`, `ACCEPT_SECTIONS`, `REVOKE_SECTION` actions
- [x] **Nav tree color-coded review progress** — Left nav items colored teal (needs review) or lime-green (accepted) when in SRX view. `useSectionAcceptance` hook derives per-item and parent-group rollup state. Parent groups (Security, Objects, Network, System) only go green when all children with content are accepted
- [x] **Accept buttons in every section** — Shared `SectionAcceptBar` component rendered above each editor section in SRX view. "Accept [Section]" button with lime-green styling, "Accepted" disabled state. Wired into 12 editor tabs via ContentRouter
- [x] **Per-zone screen acceptance** — Screen cards each have individual Accept/Accepted button per zone. "Accept All Screens" toolbar button for bulk acceptance. Auto-revoke on screen edit
- [x] **Auto-revoke on edit** — Editing any section automatically revokes its acceptance (reverts to teal). All `useConfig` update handlers dispatch `REVOKE_SECTION`. Routing inline callbacks in ContentRouter also revoke. Reset all acceptance on re-parse
- [x] **Speed tier label fix** — `resolveZoneSpeedTiers()` now returns `tierLabels` map with accurate labels based on actual port speeds. 1/10/25G SFP28 ports show "25G" instead of "25G/40G". Tracks raw speed numbers from hardware DB port strings
- [x] **Project save/load** — `sectionAcceptance` included in `.fpic.json` project save/load

### Rev19 — UX Polish & Accessibility
- [x] **Form input hover & focus states** — Added `:hover` border highlights to `.editor-inline-input`, `.cell-input`, `.chip-editor`. Added `:focus-visible` outlines on all buttons, sub-tabs, and modal close for keyboard accessibility
- [x] **OS-aware keyboard shortcut labels** — StatusBar detects macOS and shows `Cmd+P` instead of `Ctrl+P`
- [x] **Section accept bar polish** — Checkmark icon on accepted state, smooth transition between accept/accepted states
- [x] **Empty state messages** — All 6 ObjectEditor sub-tab tables show "No [items] defined" when empty instead of blank table
- [x] **NavTree group state persistence** — Collapsed/expanded nav groups saved to localStorage and restored on reload
- [x] **SRX output filename timestamp** — Download filename includes time (`srx-config-YYYY-MM-DD_HHmmss.txt`) to avoid overwrites
- [x] **Copy-to-clipboard feedback** — Copy button flashes green with checkmark for 2 seconds on success
- [x] **TopBar warning label tooltips** — `ack`/`fix`/`ign` shorthand labels show full words on hover (Acknowledged, Fixed, Ignored)
- [x] **TopBar model badge hover** — Clickable stat badges show hover background to indicate interactivity
- [x] **StatusBar progress percentage** — Policy review progress bar shows percentage value
- [x] **Transition consistency** — Standardized all CSS transitions to 0.15s (was mixed 0.1s/0.2s/0.15s)
- [x] **Gemini LLM provider** — Added Google Gemini as LLM provider with Flash 3, Flash-Lite 3.1, Pro 3.1, and 2.5 stable models

### Planned — 3-Node & 4-Node MNHA
- [ ] **3-node MNHA support** — Extend chassis cluster / MNHA generation to support 3-node configurations (active/active/standby or active/active/active topologies)
- [ ] **4-node MNHA support** — Extend chassis cluster / MNHA generation to support 4-node configurations with full mesh redundancy

### Planned — Light / Dark Mode
- [ ] **Light/dark theme toggle** — User-selectable light and dark themes with TopBar toggle button. CSS custom property swap (all `--bg-*`, `--text-*`, `--accent` vars). Light palette with white backgrounds, dark text, adjusted accent contrast. `prefers-color-scheme` media query for OS default. Persisted in localStorage

### Planned — Enhanced Migration Report
- [ ] **Rule count comparison** — Source vs converted rule counts with delta (e.g., "Source: 247 → SRX: 203 (-44)"). Breakdown by action (permit/deny), zone pair, and disabled status
- [ ] **Unused objects cleaned summary** — Report section listing address/service objects identified as unused by analysis engine and removed/flagged during conversion, with count and object names
- [ ] **Shadowed rules removed summary** — Report section listing rules identified as fully shadowed by earlier rules, with the shadowing rule reference and removal status
- [ ] **AI-disabled rules report** — Report section for rules disabled by LLM with "No longer needed" rationale (e.g., vendor management rules, EDL references). Shows LLM reasoning from `_translation_notes`
- [ ] **Migration delta dashboard** — Visual summary card at top of report: rules added/removed/modified/disabled, objects consolidated, zones merged, NAT rules changed. Before/after comparison chart
- [ ] **Exportable migration summary** — One-page PDF/HTML executive summary suitable for change management approval, with risk assessment and rollback instructions

### Planned — Aggregate Interface (LAG/LACP) Support
- [ ] **PAN-OS aggregate-ethernet parser** — Parse `<ae>` aggregate-ethernet interfaces, LACP mode, member links, and LACP system priority from PAN-OS XML
- [ ] **FortiGate LAG parser** — Parse `config system interface` with `type aggregate` / `type redundant`, `set member`, LACP mode (static/active/passive)
- [ ] **Cisco ASA port-channel parser** — Parse `interface Port-channel`, `channel-group` member assignments, LACP mode
- [ ] **SRX ae interface round-trip** — Parse and preserve `set interfaces ae0`, `set chassis aggregated-devices ethernet device-count`, `ether-options 802.3ad`, LACP config
- [ ] **Huawei Eth-Trunk parser** — Parse `interface Eth-Trunk`, `trunkport`, LACP mode/priority
- [ ] **SonicWall LAG parser** — Parse link aggregation from REST API JSON interface config
- [ ] **Check Point bond interface parser** — Parse Gaia clish `add bonding group`, `set bonding group` member interfaces
- [ ] **SRX ae converter** — Generate `set chassis aggregated-devices ethernet device-count`, `set interfaces ae0 aggregated-ether-options lacp`, member `ether-options 802.3ad ae0` bindings
- [ ] **Interface Mapper LAG support** — Display aggregate interfaces with member link expansion, map source LAG → SRX ae with member auto-mapping, visual grouping of member ports under parent ae

### Planned — Additional Improvements
- [ ] **Responsive layout for tablet/small screens** — Add breakpoints below 1280px: auto-collapse sidebar and inspector at 1024px, stack panels vertically at 768px. Desktop-first tool but should be functional on smaller viewports without horizontal scroll
- [ ] **Config validation v2: license gating, conflict detection, best practices** — After validation MVP ships (syntax + references + zone consistency), add: SRX subscription tier feature gating (IDP/UTM rules require P1/P2 — data source: `hardware-db.js`), conflicting policy detection (overlapping rules with different actions), and best-practice recommendations (deny-all final rule, logging on permits). Depends on: validation engine v1
- [ ] **Force-directed topology layout** — Upgrade the radial zone topology map to d3-force with dynamic node positioning based on connection density, drag-to-rearrange, and pan/zoom. Better for complex configs with 10+ zones. Depends on: zone topology map v1
- [ ] **Hardware capacity validation** — Compare converted config against target SRX model limits (max policies, NAT rules, address objects, zones, interfaces) from hardware-db. Warn when approaching or exceeding capacity
- [ ] **Rollback plan generation** — Auto-generate `delete` commands for every `set` command in the SRX output, producing a ready-to-paste rollback script. Include in migration report
- [ ] **Conversion report** — Exportable report documenting every command from the original source firewall config and the decision made during conversion. Each line maps to one of: (1) Deleted by analysis — rule removed by the deterministic analysis engine (shadow/redundant/unreachable), (2) Deleted by user — manually removed during review, (3) Modified by user/AI to `<SRX command>` — changed during review with the resulting SRX output shown, (4) Deleted by AI — removed by LLM translation (should be uncommon, flag for review), (5) Other with comment — catch-all for edge cases with free-text explanation. Displayed in a new "Conversion Report" sub-section under Output, exportable as CSV/PDF
- [ ] **Policy dependency graph** — Visual graph showing rule dependencies: which address objects feed which policies, zone-pair groupings, NAT→policy relationships. Interactive SVG/canvas with click-to-navigate
- [ ] **Config comparison / version diff** — Compare two SRX outputs or project files side-by-side, highlighting added/removed/changed set commands. Useful for iterating on translations
- [ ] **Export to Terraform / Ansible** — Generate Junos Terraform provider resources (`junos_security_policy`, `junos_security_zone`) or Ansible `junos_config` playbooks from the converted config for IaC workflows
- [ ] **Pre/post migration checklist** — Auto-generated task checklist based on parsed config features: certificate imports needed, JIMS setup required, SecIntel license verification, RADIUS server config, etc. Checkbox tracking with export
- [ ] **Interface mapping templates** — Save/load interface mapping profiles for repeated migrations of the same platform type. E.g., save a "PA-3260 → SRX4600" mapping template and reuse across sites
- [ ] **Batch migration mode** — Process multiple config files in sequence, each producing independent SRX output. Summary dashboard showing conversion status across all files. Useful for multi-site rollouts

### Blocked — Waiting on Vendor APIs
- [ ] **Push to SDC / SD On-Prem / Mist** — Direct deployment to Juniper management platforms. Requires HPE Juniper public REST APIs

---

## Known Limitations

- **AAA / Authentication** — RADIUS, TACACS+, LDAP server config not converted (noted in output comments)
- **SSL/TLS Decryption** — Full SSL Proxy generation automated (PKI ca-profile, ssl proxy profiles, policy attachment). Certificate import requires manual `request security pki` commands after commit
- **Management Access** — Admin users, SNMP communities, SSH/API access not converted
- **Dynamic Routing** — BGP, OSPF, OSPFv3, EVPN/VxLAN supported across applicable vendors
- **User Identity** — User-ID / FSSO / IDFW parsed and converted to SRX `source-identity` — requires manual JIMS server configuration
- **Virtual-Wire** — SRX maps vwire to bridge-domain; auto-assigns interfaces when mapped in Interface Mapper
- **MNHA** — Only 2-node configurations supported (3-node and 4-node planned)
- **Aggregate Interfaces** — LAG/LACP/port-channel/bond/Eth-Trunk not yet parsed or converted (planned)
- **Application Mapping** — ~120 built-in + 236 extended mappings (from fatcat-converter); unmapped apps get `Customfwic` suffix + warning

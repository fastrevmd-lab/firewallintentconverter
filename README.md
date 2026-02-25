<p align="center">
  <img src="static/logo.png" alt="Intent Converter" height="80">
</p>

<h1 align="center"><span style="color: #005b5a;">Firewall to Intent Converter</span></h1>

<p align="center">A browser-based tool that converts firewall configurations into an intermediate format for review, editing, and conversion to Juniper SRX. Supports <b>PAN-OS XML</b>, <b>Junos SRX</b>, <b>FortiGate / FortiOS</b>, <b>Cisco ASA / FTD</b>, <b>Check Point R80+</b>, <b>SonicWall SonicOS</b>, and <b>Huawei USG</b> as source formats, plus a <b>Greenfield</b> mode that builds an SRX configuration from scratch via LLM-guided interview. Paste or upload a config (or start a greenfield interview), review and edit the parsed rules through an interactive UI, optionally get AI-powered best-practice suggestions, then export as SRX set commands or XML.</p>

<p align="center">
  <a href="https://creativecommons.org/licenses/by-nc-nd/4.0/"><img src="https://img.shields.io/badge/License-CC%20BY--NC--ND%204.0-lightgrey.svg" alt="License: CC BY-NC-ND 4.0"></a>
</p>
# Quick Start

### Prerequisites

- **Node.js** 18+ (tested with Node 24)
- **npm** (comes with Node.js)

### Install & Run

```bash
git clone <repo-url> firewall-intent-converter
cd firewall-intent-converter
npm install
node server.js
```

Open **http://localhost:3000** in your browser.

That's it — a single command runs both the Express API server and the Vite dev server (with hot module replacement) on port 3000.

### Production Build

```bash
npm run build          # Vite compiles to dist/
NODE_ENV=production node server.js   # Serves static dist/ + API
```

## Usage

### 1a. Load a Configuration (Import Mode)

Select your source vendor from the dropdown (Junos SRX, PAN-OS, FortiGate, Cisco ASA/FTD, Check Point, SonicWall, or Huawei USG), then paste a configuration into the left panel or click one of the built-in sample configs. Then click **Parse**. The tool auto-detects the source format.

### 1b. Greenfield Mode (Build from Scratch)

Select **Greenfield (New Config)** from the vendor dropdown (preselected by default). Click **Start Interview** to begin an LLM-guided conversation that builds your SRX configuration from scratch. The LLM walks you through a structured interview:

1. **Use Case Discovery** — Deployment type (branch office, data center, campus edge, remote/teleworker, cloud gateway), connectivity details, and requirements
2. **Configuration Building** — Zones, interfaces, address objects, security policies, and NAT rules are built progressively as you answer questions
3. **Best Practices** — Use-case-aware recommendations for screen profiles, logging, default-deny rules, and more

Toggle between **from LLM Interview** and **to SRX** tabs to see the configuration building in real-time. The chat preserves its state when switching tabs.

### 2. Select Hardware Models

After parsing, a modal prompts you to select the source model and target SRX model. The tool auto-detects the likely source model from interface names (PAN-OS, SRX, FortiGate, Cisco, Check Point, SonicWall, or Huawei). For FortiGate sources, all current F/G-series and legacy E-series models are available. For Cisco sources, all Firepower 1000/2100/3100/4100/4200 series, virtual appliances, and EOS ASA 5500-X models are available. For Check Point, SonicWall, and Huawei USG, full model ranges are available with throughput specs. You can also select the SRX subscription (Base/A1/A2/P1/P2). Skip this or change it later via the **Models** button.

### 3. Map Interfaces

The interface mapper shows every source interface found in the config alongside the available SRX ports on the target model. The tool auto-maps `ethernet{slot}/{port}` to `ge-0/{slot-1}/{port-1}.0` by default. Adjust as needed and click **Done**.

### 4. Review & Edit Rules

The center panel shows all security rules in a sortable, filterable table. Use the **from/to** toggle above the tabs to switch between source and target views. Click any rule to see its full details in the right panel, where every field is editable. Use the tabs to also edit Zones, Objects/Address Book, and NAT rules.

### 5. Translate with LLM (Optional)

Configure an LLM provider in **Settings** (gear icon). Click **Translate with LLM** above the policy table to send all source policies to the LLM for translation into optimized SRX-compatible policies. The LLM:

- Translates actions, zones, addresses, applications, and services to SRX equivalents
- Applies vendor-specific migration knowledge (PAN-OS, FortiGate, Cisco ASA, Check Point, SonicWall, Huawei USG)
- Maps security profiles to SRX subscription tiers (Base/A1/A2/P1/P2) and flags features requiring upgrades
- Optimizes rule ordering, merges redundant rules, and adds default deny-all cleanup rules
- Sets logging best practices (log-end for permit, log-start for deny)

During translation, the right panel shows a live progress indicator with elapsed time, chunk progress, and token estimates. In **Greenfield** mode, this button is labeled **Import LLM Config**.

### 6. Review & Accept Translated Rules

After translation, all rules appear in the "to SRX" table with **LLM Reviewed** status (blue). Click any rule to see its full details and translation notes in the right panel. Review each rule and click **Accept** to mark it as accepted. A progress counter in the navbar tracks accepted vs LLM-reviewed rules.

### 7. Convert

Click **Convert to SRX** to generate the output. Switch between **Set Commands** and **XML** formats in the bottom panel. The **Warnings** tab shows any conversion notes. Use **Push via MCP** to deploy directly to SRX devices.

## Features

### Greenfield Configuration Builder
- **LLM-guided interview** — Build an SRX configuration from scratch through a structured conversation with an AI assistant
- **Progressive config building** — Zones, addresses, policies, NAT, routes, and screens are added to the intermediate config in real-time as the LLM collects answers
- **JSON action blocks** — LLM responses include structured action blocks (`add_zone`, `add_policy`, `add_address`, `add_nat`, `add_route`, `add_screen`, etc.) that auto-apply to the configuration
- **Inline action cards** — Each applied action renders as a visual card in the chat with the action type, name, and description
- **Use-case-aware** — The interview adapts to your deployment scenario (branch office, data center, campus edge, remote/teleworker) with tailored zone layouts and policy recommendations
- **Real-time preview** — Toggle to the "to SRX" tab at any time to see all normal editors (Security Policies, Zones, Objects, NAT) populated with the configuration built so far
- **Seamless review** — After the interview, click **Review** to have the LLM analyze the complete built configuration for best practices and security posture

### Multi-Vendor Source Import
- **PAN-OS XML parser** — Extracts security policies, NAT rules, zones, address objects, address groups, service objects, service groups, and security profile groups from PAN-OS XML configs
- **Junos SRX parser** — Parses SRX `set` commands and hierarchical curly-brace format into the same intermediate schema (zones, address-book objects, address sets, security policies, NAT rule-sets, applications)
- **FortiGate / FortiOS parser** — Parses FortiOS `config`/`edit`/`set`/`next`/`end` block format including firewall policies, address objects, address groups, service objects, service groups, zones, VIPs (destination NAT), IP pools, central SNAT maps, and security profiles (AV, web filter, IPS, application control, SSL inspection, DNS filter, DLP, email filter)
- **Cisco ASA / FTD parser** — Parses Cisco ASA/FTD configuration including interfaces (nameif, security-level, IP), object network/service definitions, object-group network/service/protocol groups, extended access-lists with remarks, access-group bindings, and object NAT (dynamic/static). Zones are derived from interface nameif + security-level
- **Check Point R80+/R81+ parser** — Parses Check Point SmartConsole JSON export (`mgmt_cli show-access-rulebase`) including objects-dictionary with UID resolution, nested access-sections and inline layers, host/network/range/FQDN/group objects, service-tcp/udp/icmp objects, service groups, NAT rulebase (hide/static), and optional Gaia clish text for interfaces and static routes
- **SonicWall SonicOS parser** — Parses SonicWall REST API JSON export (preferred) or CLI text fallback. Handles zones with security-type mapping, IPv4/IPv6 address objects (host/network/range/FQDN/MAC), address groups, service objects, service groups, access rules with priority ordering, NAT policies (source/destination/combined), interfaces, and route policies
- **Huawei USG parser** — Parses Huawei VRP CLI (`display current-configuration`) including firewall zones with priority, `ip address-set` objects (type object and type group), `ip service-set` definitions, `security-policy` rules with zone-pair routing, `nat-policy` and `nat server` rules, `time-range` schedules, basic IKE/IPsec VPN detection, `hrp` HA configuration, and static routes
- **Auto-detection** — Automatically identifies the source format (PAN-OS XML, Junos SRX, FortiOS, Cisco ASA, Check Point JSON, SonicWall JSON/CLI, or Huawei VRP) and routes to the correct parser
- **SRX output** — Generates Juniper SRX `set` commands or hierarchical XML, including zones, address books, application mappings, security policies, NAT rule-sets, schedulers, UTM profiles (anti-virus, web-filtering, content-filtering), IDP policies, and L2 bridge-domain/family-bridge config. FortiGate Application Control generates AppFW rule-set; FortiGate DLP notes ICAP integration requirement
- **Implicit rules** — Automatically generates vendor-specific implicit rules (PAN-OS intra-zone allow + interzone deny, FortiGate intrazone per-zone + default deny, Cisco ASA security-level permits for unbound interfaces + default deny, SRX default deny). Implicit rules are visually distinguished in the UI (dimmed, italic, with "Implicit" chip) and tagged `added_by_fpic`
- **FQDN support** — Parses FQDN/dns-name address objects from all vendors and converts to SRX `dns-name`. Cisco ASA `fqdn v4`/`v6` maps to SRX `ipv4-only`/`ipv6-only`. FortiGate wildcard-fqdn (`*.example.com`) generates a warning since SRX does not support wildcard dns-name
- **L2 / transparent / virtual-wire** — Detects and converts L2 mode configurations from all vendors: PAN-OS virtual-wire pairs and L2 zones, FortiGate transparent opmode with virtual-switch and forward-domain grouping, Cisco ASA `firewall transparent` with bridge-groups and BVI interfaces, SRX bridge-domains with family bridge (round-trip). Generates SRX `set bridge-domains` and `set interfaces ... family bridge` commands. Virtual-wire pairs are mapped to bridge-domains with manual interface assignment TODOs since SRX has no native virtual-wire equivalent
- **ICMP details** — Preserves ICMP type/code through the full pipeline (parser → intermediate → converter). Generates SRX `icmp-type`/`icmp-code` instead of `destination-port` for ICMP services
- **Schedule support** — Parses schedules from all vendors (FortiGate recurring/onetime, PAN-OS schedule objects, Cisco ASA time-ranges, SRX schedulers) and converts to SRX `set schedulers scheduler` commands with `scheduler-name` references on policies
- **Nested object groups** — Correctly resolves nested address groups and service groups, emitting `address-set` (not `address`) and `application-set` (not `application`) references for group members that are themselves groups
- **Vendor-native security profiles** — FortiGate profiles (Application Control, Email Filter, DLP, DNS Filter) use FortiGate-native field names in the intermediate schema and display with correct FortiGate terminology. SRX view shows correct Junos terms (Anti-virus instead of WildFire, Anti-spam, AppSecure, DNS Security). PAN-OS profiles are mapped to SRX subscriptions: Antivirus→Flow-based AV, Anti-Spyware→Anti-malware, Vulnerability→IPS, URL Filtering→Content Security, File Blocking→Content Filtering, WildFire→noted as ATP Cloud (no direct equivalent). LLM translation sets `_srx_*` boolean flags for UI toggles with safety-net mapping from PAN-OS keys
- **Predefined Junos app detection** — Services matching Junos predefined applications (junos-ssh, junos-http, junos-https, junos-dns-udp, etc.) are automatically detected and referenced instead of generating redundant custom definitions
- **Application mapping** — 120+ cross-vendor application mappings (PAN-OS, FortiGate, Cisco ASA) to Junos predefined applications. Unmapped applications receive a `Customfwic` placeholder suffix with a warning to create a custom application definition on the SRX
- **Application groups** — PAN-OS `<application-group>` entries are parsed with their members and expanded during conversion. The Applications tab shows groups with expandable member lists, and the SRX view displays per-app Junos mapping (e.g., `junos-ssh`) or `custom:app:'name'` for unmapped apps
- **Sanitization** — One-click replacement of sensitive data (IPs, hostnames, keys) with placeholders before sharing or sending to an LLM. Originals are restored on export

### Dual Platform View
- **"from" / "to" toggle** — Switch between source view ("from PAN-OS", "from SRX", "from FortiGate", "from Cisco ASA", "from Check Point", "from SonicWall", or "from Huawei") and target view ("to SRX") above the tab bar
- **SRX-style table** — When source is SRX (or viewing the "to SRX" tab), policies display in a zone-grouped table with SRX terminology (permit/deny/reject, security-zone, address-book)
- **PAN-OS-style table** — When source is PAN-OS, the "from" tab shows the familiar PAN-OS table layout with allow/deny actions
- **FortiGate-style table** — When source is FortiGate, the "from" tab shows a FortiOS-style policy table with FortiGate terminology (ACCEPT/DENY, From/To interfaces, Schedule, NAT toggle, security profile icons for AV/WF/IPS/App/SSL/DNS/EM/DLP)
- **Cisco ASDM-style table** — When source is Cisco ASA/FTD, the "from" tab shows a Cisco ASDM-style access control table with ACE numbering, Permit/Deny actions, ACL name badges, security level indicators, protocol chips, interface labels, log status, and hit counts
- **Check Point SmartConsole-style table** — When source is Check Point, the "from" tab shows a SmartConsole-style table with section grouping, Accept/Drop actions, Track type, and Install On targets
- **SonicWall-style table** — When source is SonicWall, the "from" tab shows a zone-pair table with priority ordering, DPI status column, and Allow/Deny actions
- **Huawei USG-style table** — When source is Huawei, the "from" tab shows a zone-pair named-rule table with Permit/Deny actions and security profile indicators
- **Negate support** — Source/destination address negation flags (PAN-OS `negate-source`/`negate-destination`, SRX `except`) displayed and editable in both views
- **Profile group expansion** — PAN-OS profile group references are automatically resolved into individual security profiles

### Interactive Editing
- **Tabbed center panel** — Switch between Security Policies/Rules, Security Zones, Address Book/Objects (with Addresses, Groups, Services, Applications, Security Profiles, and Schedules sub-tabs), NAT, Routing, and VPN editors
- **Inline table editing** — Double-click any cell in the policy table to edit directly
- **Right panel rule details** — Full editable form for the selected rule: action, zones, addresses, applications, services, logging, security profiles, tags, description
- **Schedule editor** — View, edit, add, and delete schedules from the Objects > Schedules tab. Each schedule shows its type (recurring/onetime), days, time range, and which rules reference it
- **Routing editor** — View, edit, add, and delete static routes from the Routing tab. Displays routing contexts (vsys/VDOM/routing-instance) and routes with destination, next-hop, type, interface, metric, and VRF
- **VPN editor** — View, edit, add, and delete VPN/IPsec tunnels from the VPN tab. Card-based editor showing IKE gateway (peer address, local interface, IKE version), IKE proposal (encryption, authentication, DH group, lifetime, auth method), IPsec proposal (protocol, encryption, authentication, PFS group, lifetime), tunnel interface, and traffic selectors/proxy IDs
- **Add / delete rules** — Create new rules or remove existing ones from the UI

### Hardware Awareness
- **Model selector** — Pick source firewall model (PAN-OS, SRX, FortiGate, Cisco, Check Point, SonicWall, or Huawei USG, including EOS/legacy models) and target SRX model from a built-in hardware database with port counts and throughput specs. Throughput numbers are best-effort from publicly available data
- **Auto-detection** — Heuristics detect the likely source model from interface naming in the config (PAN-OS `ethernet`, SRX `ge-`/`xe-`/`et-`, FortiGate `port`/`wan`/`internal`/`dmz`, Cisco `GigabitEthernet`/`Ethernet1/`/`TenGigabitEthernet`, Check Point `eth`, SonicWall `X`, Huawei `GigabitEthernet`/`XGigabitEthernet` formats)
- **FortiGate models** — Full F-series (40F through 4400F), G-series (70G through 900G), and EOS E-series (30E through 500E) with port counts and throughput specs
- **Cisco models** — Firepower 1000 series (FPR-1010 through FPR-1150), 2100 series (FPR-2110 through FPR-2140), 3100 series (FPR-3105 through FPR-3140), 4100 series (FPR-4112 through FPR-4145), 4200 series (FPR-4215 through FPR-4245), virtual (ASAv, FTDv), and EOS ASA 5500-X series (ASA-5506-X through ASA-5555-X)
- **Check Point models** — Branch through data center appliances (CP-1600 through CP-28000) with throughput specs
- **SonicWall models** — TZ series (TZ-270 through TZ-670), NSa series (NSa-2700 through NSa-6700), and NSsp series (NSsp-10700, NSsp-13700) with throughput specs
- **Huawei USG models** — USG6000E series (USG6510E through USG6680E) with GigabitEthernet and XGigabitEthernet port counts
- **EOS SRX models** — Legacy/End-of-Sale SRX models (SRX100, SRX210, SRX240, SRX550, SRX650, SRX1400, SRX3400, SRX3600, etc.) available as source models for migration projects
- **Interface mapper** — Per-zone mapping of source interfaces to SRX interfaces with auto-mapping, tunnel, and loopback support
- **SRX subscriptions** — Select the target SRX subscription level (Base, A1 Advanced Data Protection, A2 Advanced Edge Protection, P1 Premium Data Protection, P2 Premium Edge Protection) to gate feature availability and inform LLM reviews. Includes footnote explaining SDC (Security Director Cloud) and ATP (Advanced Threat Protection) capabilities
- **SRX datasheet links** — Quick-access popup with links to official HPE Juniper SRX spec sheets for all current models, grouped by tier (Branch, Enterprise, Data Center, Chassis-Based, Virtual)
- **Site identification** — Optional Site Name and Site Group fields in the model selector. Values are emitted as header comments at the top of SRX set-command and XML output, preparing for future SDC/Mist integration

### LLM Translation & Review Workflow
- **Translate with LLM** — One-click translation of all source policies to optimized SRX format using vendor-aware, subscription-aware LLM prompts. The translation prompt includes vendor-specific migration pitfalls and cross-vendor gap analysis for all 6 supported source vendors
- **Translation progress** — Real-time progress panel in the right pane showing elapsed time (live ticking timer), chunk progress, and estimated prompt/response token counts
- **Review status tracking** — Every translated rule starts as *LLM Reviewed* and must be manually accepted. Status labels are color-coded: blue for LLM Reviewed, green for Accepted, grey for Disabled
- **Status filtering** — Filter the policy table by review status (All / Unreviewed / LLM Reviewed / Accepted / Disabled) — available on the "to SRX" tab
- **Accept rules** — Click any rule to review its details and translation notes, then click Accept. A progress counter in the navbar tracks accepted vs LLM-reviewed policies (`Policies: X/Y accepted`)
- **Warning review workflow** — Clickable warnings badge in the navbar shows unresolved/total count and switches to the Warnings tab on click. Each warning has Ack/Fixed/Ignore action buttons to track resolution. Resolved warnings are dimmed and filterable (All/Unresolved/Resolved). Badge turns green when all warnings are addressed
- **Subscription-aware translation** — SRX subscription tier (Base/A1/A2/P1/P2) is passed to the LLM, which maps security profiles to the correct tier and flags features requiring upgrades in `_translation_notes`
- **SSL Decryption → SSL Proxy mapping** — PAN-OS decryption rules (separate rulebase) are sent as context to the LLM during translation. The LLM sets `_srx_decrypt: true` on security rules whose traffic matches decrypt-action decryption rules. A zone-pair safety net auto-applies the flag on any allow rules the LLM missed

### LLM Integration
- **Multiple providers** — Claude (Anthropic), OpenAI, Ollama, LM Studio, or any OpenAI-compatible endpoint
- **Browser-only API keys** — All credentials stay in `localStorage` and never touch the server
- **Editable system prompts** — Separate prompts for ruleset translation (per-vendor) and greenfield interview. Prompts are stored as plain-text files in `static/prompts/` (editable on disk) with Settings UI overrides and hardcoded fallback defaults. Each has its own sub-tab in Settings with independent Reset to Default
- **Per-vendor translation prompts** — 7 vendor-specific translate prompts (PAN-OS, FortiGate, Cisco ASA, Check Point, SonicWall, Huawei USG, SRX-to-SRX) each containing that vendor's full feature equivalency matrix, specific migration pitfalls, action mapping, and security profile translation rules. Auto-selected at translation time based on detected source vendor. Editable per-vendor in Settings via dropdown selector
- **Subscription-aware translation** — SRX subscription tier is included in both the system prompt and user prompt, ensuring security profiles are correctly mapped to available features
- **Real-time progress** — Translation progress panel shows live elapsed time, chunk progress, and token estimates during LLM calls

### Conversion Features
- **Security policies** — Zone-based firewall rules with source/dest addresses, applications, services, actions, logging
- **NAT** — Source NAT, destination NAT, static NAT with zone-pair rule sets
- **Address & service objects** — Named objects, groups, FQDN addresses
- **Application mapping** — PAN-OS App-ID → Junos application, custom application placeholders
- **Security profiles** — UTM policy generation from source AV, web filter, file blocking profiles using source-derived parameters (block categories, file extensions, scan settings); IDP policies with severity-specific actions mapped from source vulnerability/spyware profiles (reset-both → drop-connection, alert → no-action); SecIntel from EDL/threat feeds
- **L2 / bridge domains** — Bridge domain definitions, L2 interfaces with family bridge, VLAN IDs, IRB routing interfaces. Virtual-wire pairs mapped to bridge-domains
- **Rule optimization** — Shadow detection (fully shadowed rules), reorder recommendations (deny after broader permit), redundant rule detection (subset of earlier permit), mergeable rule suggestions (adjacent rules differing in one dimension), consolidation opportunities (3+ rules combinable with address groups)
- **Static routes** — Virtual router routes, VRF/routing-instance support, blackhole routes
- **VPN / IPsec** — IKE proposals/policies/gateways, IPsec proposals/policies/VPNs, traffic selectors, proxy IDs
- **HA → Chassis Cluster / MNHA** — Active/passive and active/active HA to SRX chassis cluster with redundancy groups, or Multinode High Availability (MNHA) for SRX4700 and supported models (SRX1500, SRX1600, SRX4100/4120/4200/4300, SRX4600, SRX5400/5600/5800, vSRX). MNHA generates `set chassis high-availability` commands with ICL, liveness detection, and services redundancy groups. SRX4700 targets automatically require MNHA. Only 2-node MNHA is supported at this time
- **Screens / DDoS** — Zone protection profiles, DoS policies, threat detection → SRX screen ids-option
- **Syslog** — Syslog server forwarding, facility/severity mapping, TCP/TLS transport
- **DHCP** — DHCP server pools, relay helpers, address assignment
- **QoS / CoS** — Traffic shaping profiles, policy maps, scheduler maps, interface CoS bindings
- **Schedules** — Time-based rule scheduling with day-of-week and time-range support

### Push & Integration
- **Push via MCP** — Connect to an MCP server to push configurations directly to SRX devices (configurable in Settings)
- **Push to SDC** — Security Director Cloud integration (coming soon)
- **Push to Mist** — Juniper Mist Cloud integration (coming soon)
- **Convert confirmation** — Warning dialog when converting with unaccepted policies
- **Feedback / suggestions** — Chat-bubble icon in the navbar opens a feedback modal where users can submit bug reports, feature requests, or improvement ideas as pre-filled GitHub Issues

### Not Supported (Manual Migration Required)

The following features are **not converted** by this tool and must be configured manually on the target SRX:

- **AAA / Authentication** — RADIUS, TACACS+, LDAP server configuration and authentication policies
- **Dynamic Routing Protocols** — BGP, OSPF, EVPN, VxLAN (only static routes are converted; planned for Rev8)
- **User-ID / Identity Policies** — PAN-OS User-ID, FortiGate FSSO, Cisco IDFW user/group-based policies (planned for Rev8)
- **SSL/TLS Decryption** — PAN-OS decryption rules are parsed, displayed in the SSL B&I tab, and used during LLM translation to set `_srx_decrypt` on matching security rules. However, full SRX SSL Proxy config generation (certificate management, PKI, proxy profiles) is not yet automated
- **Policy-Based Forwarding** — PAN-OS PBF rules are parsed and displayed in the PBF tab but not converted to SRX filter-based forwarding
- **NetFlow / Telemetry** — sFlow, traffic monitoring, streaming telemetry
- **Management Access** — Admin users, SNMP communities, SSH/API access restrictions

See [TODO.md](TODO.md) for the full roadmap and planned features.

## Project Structure

```
firewall-intent-converter/
├── server.js                     # Express server (API + Vite middleware)
├── vite.config.js                # Vite config (React, publicDir: 'static')
├── package.json
├── TODO.md                       # Roadmap & TODO (Rev1–Rev8+)
├── index.html                    # Entry HTML
├── static/                       # Static assets served as-is (Vite publicDir)
│   ├── logo.png                  # Application logo
│   └── prompts/                  # Editable LLM system prompts (plain text)
│       ├── translate.txt         # Default translation prompt — generic SRX rules, subscription tiers
│       ├── translate-panos.txt   # PAN-OS → SRX — 19-feature equivalency matrix + pitfalls
│       ├── translate-fortigate.txt # FortiGate → SRX — 21-feature equivalency matrix + pitfalls
│       ├── translate-cisco_asa.txt # Cisco ASA → SRX — 27-feature equivalency matrix + pitfalls
│       ├── translate-checkpoint.txt # Check Point → SRX — 20-feature equivalency matrix + pitfalls
│       ├── translate-sonicwall.txt # SonicWall → SRX — 27-feature equivalency matrix + pitfalls
│       ├── translate-huawei_usg.txt # Huawei USG → SRX — 26-feature equivalency matrix + pitfalls
│       ├── translate-srx.txt     # SRX → SRX — optimization, modernization, best practices
│       ├── full-review.txt       # Translation instructions — vendor pitfalls, cross-vendor gaps
│       └── greenfield.txt        # Greenfield interview prompt — guided SRX config builder
├── src/                          # Server-side modules
│   ├── parsers/
│   │   ├── panos-parser.js       # PAN-OS XML → intermediate JSON
│   │   ├── srx-parser.js         # Junos SRX set/hierarchical → intermediate JSON
│   │   ├── fortigate-parser.js   # FortiOS config/edit/set → intermediate JSON
│   │   ├── cisco-asa-parser.js   # Cisco ASA/FTD → intermediate JSON
│   │   ├── checkpoint-parser.js  # Check Point R80+/R81+ JSON → intermediate JSON
│   │   ├── sonicwall-parser.js   # SonicWall SonicOS JSON/CLI → intermediate JSON
│   │   ├── huawei-parser.js      # Huawei USG VRP CLI → intermediate JSON
│   │   └── parser-utils.js       # Shared parsing helpers + vendor detection
│   ├── converters/
│   │   ├── srx-converter.js      # Intermediate JSON → SRX set commands
│   │   └── srx-xml-builder.js    # Intermediate JSON → SRX XML
│   ├── analysis/
│   │   └── shadow-detector.js    # Rule shadowing, optimization, and consolidation analysis
│   ├── validators/
│   │   └── srx-validator.js      # SRX output validation
│   └── interview/
│       ├── llm-client.js         # Server-side LLM client (unused in browser mode)
│       └── question-engine.js    # Interview question logic
├── public/                       # React frontend (transpiled by Vite)
│   ├── main.jsx                  # React entry point
│   ├── app.jsx                   # Root component — layout, state, routing
│   ├── styles/
│   │   └── main.css              # All styles (dark theme, components, layout)
│   ├── components/
│   │   ├── ConfigInput.jsx       # Left panel — paste/upload config, parse/sanitize, greenfield start
│   │   ├── PolicyTable.jsx       # Center panel — sortable/filterable/editable rule table
│   │   ├── ZoneEditor.jsx        # Center panel tab — zone editing
│   │   ├── ObjectEditor.jsx      # Center panel tab — address/service object editing
│   │   ├── NATEditor.jsx         # Center panel tab — NAT rule editing
│   │   ├── RoutingEditor.jsx     # Center panel tab — static route + routing context editing
│   │   ├── VPNEditor.jsx         # Center panel tab — VPN/IPsec tunnel editing
│   │   ├── GreenfieldChat.jsx    # Center panel — LLM-guided greenfield config builder
│   │   ├── InterviewPanel.jsx    # Right panel — rule details, LLM review, accept
│   │   ├── SRXOutput.jsx         # Bottom panel — SRX output display
│   │   ├── WarningsPanel.jsx     # Bottom panel — conversion warnings + optimization suggestions
│   │   ├── ModelSelector.jsx     # Modal — source/target hardware model picker + site identification
│   │   ├── InterfaceMapper.jsx   # Modal — per-zone interface mapping
│   │   ├── FeedbackModal.jsx     # Modal — feedback/suggestion submission via GitHub Issues
│   │   ├── LLMSettings.jsx       # Modal — LLM provider config, MCP connection, system prompts
│   │   └── sample-configs.jsx    # Built-in sample configs (PAN-OS, SRX, FortiGate, Cisco, Check Point, SonicWall, Huawei)
│   ├── utils/
│   │   ├── llm-client.js         # Browser-side LLM API client (multi-provider)
│   │   └── srx-view-transforms.js # SRX display transforms + license tier data
│   └── data/
│       └── hardware-db.js        # PAN-OS, SRX, FortiGate, Cisco, Check Point, SonicWall + Huawei model database (current + EOS)
└── dist/                         # Production build output (generated)
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/parse` | Parse config text (PAN-OS XML, Junos SRX, FortiOS, Cisco ASA, Check Point JSON, SonicWall JSON/CLI, or Huawei VRP) into vendor-neutral intermediate JSON. Auto-detects source format. |
| `POST` | `/api/convert` | Convert intermediate JSON to SRX output (set commands or XML) |
| `POST` | `/api/sanitize` | Replace sensitive data in config text with placeholders |

## Configuration

### LLM Settings

All LLM configuration is stored in `localStorage` under the key `llm-settings`. No API keys are ever sent to the server. Supported providers:

| Provider | Key Required | Default URL |
|----------|-------------|-------------|
| Claude (Anthropic) | Yes | `api.anthropic.com` |
| OpenAI | Yes | `api.openai.com` |
| Ollama | No | `localhost:11434` |
| LM Studio | No | `localhost:1234` |
| Custom | Optional | User-specified |

### LLM System Prompts

Editable plain-text prompt files control how the LLM behaves during translation and greenfield interviews. Edit these files directly on disk — changes take effect on page reload:

| File | Purpose |
|------|---------|
| `static/prompts/translate.txt` | **Default translate** — Generic SRX translation rules, subscription tiers, security profile mapping (fallback when no vendor-specific prompt exists) |
| `static/prompts/translate-{vendor}.txt` | **Per-vendor translate** — Full feature equivalency matrix, vendor-specific pitfalls, action mapping, profile translation for each source vendor (panos, fortigate, cisco_asa, checkpoint, sonicwall, huawei_usg, srx) |
| `static/prompts/full-review.txt` | **Translate LLM instructions** — Cross-vendor migration pitfalls summary, SRX best practices, translation priorities |
| `static/prompts/greenfield.txt` | **Greenfield interview** — guided SRX config builder with use-case discovery, progressive config building via JSON action blocks, best-practice recommendations |

**Priority order:** For translation, vendor-specific prompts take precedence: user edits in Settings UI (per-vendor localStorage) > vendor-specific file (`translate-{vendor}.txt`) > generic user edits > generic file (`translate.txt`) > hardcoded defaults. Select a vendor in the Settings prompt dropdown to view or edit its prompt. Click "Reset to Default" to revert to the on-disk version.

### MCP Settings

MCP server configuration is stored in `localStorage` under the key `mcp-settings`. Use the Settings modal (MCP Connection tab) to configure the server URL, test the connection, and view connected SRX devices.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server listen port |
| `NODE_ENV` | — | Set to `production` to serve static build instead of Vite HMR |

## Tech Stack

- **Frontend**: React 18, JSX (no TypeScript, no bundled CSS framework)
- **Backend**: Express 4, fast-xml-parser
- **Build**: Vite 5 with `@vitejs/plugin-react`
- **Styling**: Custom CSS with dark theme (CSS variables, no preprocessor)
- **LLM**: Direct browser-to-provider API calls (no server proxy)

<p align="center">
  <img src="static/logo.png" alt="Intent Converter" height="80">
</p>

<h1 align="center"><span style="color: #005b5a;">Firewall to Intent Converter</span></h1>

<p align="center">A browser-based tool that converts firewall configurations into an intermediate format for review, editing, and conversion to Juniper SRX. Supports <b>PAN-OS XML</b>, <b>Junos SRX</b>, <b>FortiGate / FortiOS</b>, and <b>Cisco ASA / FTD</b> as source formats, plus a <b>Greenfield</b> mode that builds an SRX configuration from scratch via LLM-guided interview. Paste or upload a config (or start a greenfield interview), review and edit the parsed rules through an interactive UI, optionally get AI-powered best-practice suggestions, then export as SRX set commands or XML.</p>
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

Select your source vendor from the dropdown (Junos SRX, PAN-OS, FortiGate, or Cisco ASA/FTD), then paste a configuration into the left panel or click one of the built-in sample configs. Then click **Parse**. The tool auto-detects the source format.

### 1b. Greenfield Mode (Build from Scratch)

Select **Greenfield (New Config)** from the vendor dropdown (preselected by default). Click **Start Interview** to begin an LLM-guided conversation that builds your SRX configuration from scratch. The LLM walks you through a structured interview:

1. **Use Case Discovery** — Deployment type (branch office, data center, campus edge, remote/teleworker, cloud gateway), connectivity details, and requirements
2. **Configuration Building** — Zones, interfaces, address objects, security policies, and NAT rules are built progressively as you answer questions
3. **Best Practices** — Use-case-aware recommendations for screen profiles, logging, default-deny rules, and more

Toggle between **from LLM Interview** and **to SRX** tabs to see the configuration building in real-time. The chat preserves its state when switching tabs.

### 2. Select Hardware Models

After parsing, a modal prompts you to select the source model and target SRX model. The tool auto-detects the likely source model from interface names (PAN-OS, SRX, FortiGate, or Cisco). For FortiGate sources, all current F/G-series and legacy E-series models are available. For Cisco sources, all Firepower 1000/2100/3100/4100/4200 series, virtual appliances, and EOS ASA 5500-X models are available. You can also select the SRX subscription (Base/A1/A2/P1/P2). Skip this or change it later via the **Models** button.

### 3. Map Interfaces

The interface mapper shows every source interface found in the config alongside the available SRX ports on the target model. The tool auto-maps `ethernet{slot}/{port}` to `ge-0/{slot-1}/{port-1}.0` by default. Adjust as needed and click **Done**.

### 4. Review & Edit Rules

The center panel shows all security rules in a sortable, filterable table. Use the **from/to** toggle above the tabs to switch between source and target views. Click any rule to see its full details in the right panel, where every field is editable. Use the tabs to also edit Zones, Objects/Address Book, and NAT rules.

### 5. LLM Review (Optional)

Configure an LLM provider in **Settings** (gear icon). On the "to SRX" tab, for each rule:

1. Select the rule in the table
2. Click **LLM Review** in the right panel
3. Review the structured suggestions — each shows the field, current value, suggested value, and reasoning
4. Click **Import** on suggestions you agree with, or **Import All**
5. Click **Accept Policy** when satisfied

### 6. Full-Ruleset Review (Optional)

Once all rules are accepted, the **Review** button in the tab bar becomes active. Click it to open a chat interface where the LLM analyzes the entire ruleset for:

- Rule ordering and shadowed rules
- Missing deny-all cleanup rules
- Inconsistent logging
- Zone coverage gaps
- Security profile and license recommendations

Accept or reject individual suggestions inline, and ask follow-up questions.

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
- **Auto-detection** — Automatically identifies the source format (PAN-OS XML, Junos SRX, FortiOS, or Cisco ASA) and routes to the correct parser
- **SRX output** — Generates Juniper SRX `set` commands or hierarchical XML, including zones, address books, application mappings, security policies, NAT rule-sets, schedulers, UTM profiles (anti-virus, web-filtering, content-filtering), IDP policies, and L2 bridge-domain/family-bridge config. FortiGate Application Control generates AppFW rule-set; FortiGate DLP notes ICAP integration requirement
- **Implicit rules** — Automatically generates vendor-specific implicit rules (PAN-OS intra-zone allow + interzone deny, FortiGate intrazone per-zone + default deny, Cisco ASA security-level permits for unbound interfaces + default deny, SRX default deny). Implicit rules are visually distinguished in the UI (dimmed, italic, with "Implicit" chip) and tagged `added_by_fpic`
- **FQDN support** — Parses FQDN/dns-name address objects from all vendors and converts to SRX `dns-name`. Cisco ASA `fqdn v4`/`v6` maps to SRX `ipv4-only`/`ipv6-only`. FortiGate wildcard-fqdn (`*.example.com`) generates a warning since SRX does not support wildcard dns-name
- **L2 / transparent / virtual-wire** — Detects and converts L2 mode configurations from all vendors: PAN-OS virtual-wire pairs and L2 zones, FortiGate transparent opmode with virtual-switch and forward-domain grouping, Cisco ASA `firewall transparent` with bridge-groups and BVI interfaces, SRX bridge-domains with family bridge (round-trip). Generates SRX `set bridge-domains` and `set interfaces ... family bridge` commands. Virtual-wire pairs are mapped to bridge-domains with manual interface assignment TODOs since SRX has no native virtual-wire equivalent
- **ICMP details** — Preserves ICMP type/code through the full pipeline (parser → intermediate → converter). Generates SRX `icmp-type`/`icmp-code` instead of `destination-port` for ICMP services
- **Schedule support** — Parses schedules from all vendors (FortiGate recurring/onetime, PAN-OS schedule objects, Cisco ASA time-ranges, SRX schedulers) and converts to SRX `set schedulers scheduler` commands with `scheduler-name` references on policies
- **Nested object groups** — Correctly resolves nested address groups and service groups, emitting `address-set` (not `address`) and `application-set` (not `application`) references for group members that are themselves groups
- **Vendor-native security profiles** — FortiGate profiles (Application Control, Email Filter, DLP, DNS Filter) use FortiGate-native field names in the intermediate schema and display with correct FortiGate terminology. SRX view shows correct Junos terms (Anti-virus instead of WildFire, Anti-spam, AppSecure, DNS Security). PAN-OS profiles (WildFire, File Blocking) remain unchanged
- **Predefined Junos app detection** — Services matching Junos predefined applications (junos-ssh, junos-http, junos-https, junos-dns-udp, etc.) are automatically detected and referenced instead of generating redundant custom definitions
- **Application mapping** — 120+ cross-vendor application mappings (PAN-OS, FortiGate, Cisco ASA) to Junos predefined applications. Unmapped applications receive a `Customfwic` placeholder suffix with a warning to create a custom application definition on the SRX
- **Application groups** — PAN-OS `<application-group>` entries are parsed with their members and expanded during conversion. The Applications tab shows groups with expandable member lists, and the SRX view displays per-app Junos mapping (e.g., `junos-ssh`) or `custom:app:'name'` for unmapped apps
- **Sanitization** — One-click replacement of sensitive data (IPs, hostnames, keys) with placeholders before sharing or sending to an LLM. Originals are restored on export

### Dual Platform View
- **"from" / "to" toggle** — Switch between source view ("from PAN-OS", "from SRX", "from FortiGate", or "from Cisco ASA") and target view ("to SRX") above the tab bar
- **SRX-style table** — When source is SRX (or viewing the "to SRX" tab), policies display in a zone-grouped table with SRX terminology (permit/deny/reject, security-zone, address-book)
- **PAN-OS-style table** — When source is PAN-OS, the "from" tab shows the familiar PAN-OS table layout with allow/deny actions
- **FortiGate-style table** — When source is FortiGate, the "from" tab shows a FortiOS-style policy table with FortiGate terminology (ACCEPT/DENY, From/To interfaces, Schedule, NAT toggle, security profile icons for AV/WF/IPS/App/SSL/DNS/EM/DLP)
- **Cisco ASDM-style table** — When source is Cisco ASA/FTD, the "from" tab shows a Cisco ASDM-style access control table with ACE numbering, Permit/Deny actions, ACL name badges, security level indicators, protocol chips, interface labels, log status, and hit counts
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
- **Model selector** — Pick source firewall model (PAN-OS, SRX, FortiGate, or Cisco, including EOS/legacy models) and target SRX model from a built-in hardware database with port counts and throughput specs. Throughput numbers are best-effort from publicly available data
- **Auto-detection** — Heuristics detect the likely source model from interface naming in the config (PAN-OS `ethernet`, SRX `ge-`/`xe-`/`et-`, FortiGate `port`/`wan`/`internal`/`dmz`, Cisco `GigabitEthernet`/`Ethernet1/`/`TenGigabitEthernet` formats)
- **FortiGate models** — Full F-series (40F through 4400F), G-series (70G through 900G), and EOS E-series (30E through 500E) with port counts and throughput specs
- **Cisco models** — Firepower 1000 series (FPR-1010 through FPR-1150), 2100 series (FPR-2110 through FPR-2140), 3100 series (FPR-3105 through FPR-3140), 4100 series (FPR-4112 through FPR-4145), 4200 series (FPR-4215 through FPR-4245), virtual (ASAv, FTDv), and EOS ASA 5500-X series (ASA-5506-X through ASA-5555-X)
- **EOS SRX models** — Legacy/End-of-Sale SRX models (SRX100, SRX210, SRX240, SRX550, SRX650, SRX1400, SRX3400, SRX3600, etc.) available as source models for migration projects
- **Interface mapper** — Per-zone mapping of source interfaces to SRX interfaces with auto-mapping, tunnel, and loopback support
- **SRX subscriptions** — Select the target SRX subscription level (Base, A1 Advanced Data Protection, A2 Advanced Edge Protection, P1 Premium Data Protection, P2 Premium Edge Protection) to gate feature availability and inform LLM reviews. Includes footnote explaining SDC (Security Director Cloud) and ATP (Advanced Threat Protection) capabilities
- **SRX datasheet links** — Quick-access popup with links to official HPE Juniper SRX spec sheets for all current models, grouped by tier (Branch, Enterprise, Data Center, Chassis-Based, Virtual)

### Rule Review Workflow
- **Review status tracking** — Every rule starts as *Unreviewed* and can progress through *LLM Reviewed* to *Accepted*. Disabled rules show a *Disabled* label. Status labels are color-coded in the policy table
- **Status filtering** — Filter the policy table by review status (All / Unreviewed / LLM Reviewed / Accepted / Disabled) — available on the "to SRX" tab
- **Per-rule LLM review** — Click "LLM Review" on any rule to get structured AI suggestions with specific field changes, reasons, and one-click Import buttons
- **Accept rules** — Mark rules as accepted individually. A progress counter in the navbar tracks how many rules are accepted
- **Full-ruleset review** — Once all rules are accepted, the "Review" button opens a chat interface for multi-turn LLM conversation about the entire ruleset, with inline suggestion cards you can accept or reject

### LLM Integration
- **Multiple providers** — Claude (Anthropic), OpenAI, Ollama, LM Studio, or any OpenAI-compatible endpoint
- **Browser-only API keys** — All credentials stay in `localStorage` and never touch the server
- **Three editable system prompts** — Separate prompts for per-rule review (multi-vendor migration guidance), full-ruleset review (SRX expert security posture analysis), and greenfield interview (structured config builder). Each has its own sub-tab in Settings with independent Reset to Default
- **Structured responses** — LLM returns JSON with analysis, per-field suggestions, and a verdict — parsed into interactive cards with Import buttons
- **Multi-turn chat** — The full-ruleset review panel maintains conversation history so you can ask follow-up questions
- **Vendor-aware prompts** — LLM prompts dynamically reference the detected source vendor (PAN-OS, FortiGate, Cisco ASA, or SRX) with vendor-specific migration pitfall guidance
- **Subscription-aware prompts** — SRX subscription level is included in LLM prompts so suggestions account for available features

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

### Not Supported (Manual Migration Required)

The following features are **not converted** by this tool and must be configured manually on the target SRX:

- **AAA / Authentication** — RADIUS, TACACS+, LDAP server configuration and authentication policies
- **Dynamic Routing Protocols** — BGP, OSPF, EVPN, VxLAN (only static routes are converted; planned for Rev8)
- **User-ID / Identity Policies** — PAN-OS User-ID, FortiGate FSSO, Cisco IDFW user/group-based policies (planned for Rev8)
- **SSL/TLS Decryption** — SSL proxy, certificate management, PKI configuration
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
├── src/                          # Server-side modules
│   ├── parsers/
│   │   ├── panos-parser.js       # PAN-OS XML → intermediate JSON
│   │   ├── srx-parser.js         # Junos SRX set/hierarchical → intermediate JSON
│   │   ├── fortigate-parser.js   # FortiOS config/edit/set → intermediate JSON
│   │   ├── cisco-asa-parser.js   # Cisco ASA/FTD → intermediate JSON
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
│   │   ├── ReviewChatPanel.jsx   # Right panel — full-ruleset LLM chat review
│   │   ├── SRXOutput.jsx         # Bottom panel — SRX output display
│   │   ├── WarningsPanel.jsx     # Bottom panel — conversion warnings + optimization suggestions
│   │   ├── ModelSelector.jsx     # Modal — source/target hardware model picker
│   │   ├── InterfaceMapper.jsx   # Modal — per-zone interface mapping
│   │   ├── LLMSettings.jsx       # Modal — LLM provider config, MCP connection, 3 system prompts
│   │   └── sample-configs.jsx    # Built-in sample configs (PAN-OS, SRX, FortiGate, Cisco)
│   ├── utils/
│   │   ├── llm-client.js         # Browser-side LLM API client (multi-provider)
│   │   └── srx-view-transforms.js # SRX display transforms + license tier data
│   └── data/
│       └── hardware-db.js        # PAN-OS, SRX, FortiGate + Cisco model database (current + EOS)
└── dist/                         # Production build output (generated)
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/parse` | Parse config text (PAN-OS XML, Junos SRX, FortiOS, or Cisco ASA) into vendor-neutral intermediate JSON. Auto-detects source format. |
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

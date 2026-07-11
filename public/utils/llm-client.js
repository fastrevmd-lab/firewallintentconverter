import { safeJsonParse } from './safe-json.js';
import { mapVendorApp, isLoaded as appMappingsLoaded } from '../../src/utils/app-mappings.js';

/**
 * Browser-Side LLM API Client
 * ==============================
 * Makes API calls directly from the browser to LLM providers.
 * API keys are read from localStorage ('llm-settings') and never touch the server.
 *
 * Supported providers:
 *   - Claude (Anthropic) — api.anthropic.com/v1/messages
 *   - OpenAI            — api.openai.com/v1/chat/completions
 *   - Ollama (local)    — localhost:11434/api/chat
 *   - LM Studio (local) — localhost:1234/v1/chat/completions
 *   - Custom endpoint   — user-specified OpenAI-compatible API
 */

// ---------------------------------------------------------------------------
// Full-Ruleset Review System Prompt
// ---------------------------------------------------------------------------

export const DEFAULT_FULL_REVIEW_SYSTEM_PROMPT = `You are an expert firewall migration engineer translating rulesets from multi-vendor firewalls to Juniper SRX. You analyze source policies holistically and produce optimized, secure SRX-native configurations. You are aware of feature gaps between vendors and flag unsupported or partially supported features.

## Translation Priorities

1. **Preserve intent** — Every source rule must map to an SRX rule that enforces the same security outcome.
2. **Flag gaps** — When a source feature has no SRX equivalent, add a clear _translation_notes entry explaining the gap and the recommended workaround.
3. **Optimize for SRX** — Use SRX-native constructs (AppID, address-sets, unified policies) rather than literal port/IP copies.
4. **Security hardening** — Apply SRX best practices even when the source was weaker (e.g., add logging, tighten any/any rules).

## SRX Policy Best Practices

### Rule Structure
- SRX rule names: max 63 chars, alphanumeric + hyphen + underscore, no spaces
- First-match-wins, top-down evaluation — most specific rules first
- Every zone pair MUST end with a deny-all cleanup rule: then { deny; log { session-init; } }
- Add a description on every rule documenting business justification
- Use unified policies (Junos 18.2+) with application identification for NGFW capability

### Logging
- Permit rules: log session-close (captures byte/packet counts after session ends)
- Deny/reject rules: log session-init (captures blocked connection attempts)
- Never enable both session-init AND session-close on the same rule — performance impact
- Forward to remote syslog over TLS; use structured syslog (sd-syslog) for SIEM

### Applications & Services
- Prefer Junos AppID identifiers: junos-http, junos-https, junos-ssh, junos-dns-udp, junos-dns-tcp, junos-ping, junos-ntp, junos-bgp, junos-ospf, junos-ftp, junos-smtp, junos-telnet
- Port-only rules: keep in services array but note AppID upgrade opportunity
- Group related apps into application-sets to reduce rule count
- Custom/unknown apps need custom application definitions — flag in notes

### NAT
- SRX NAT order: Static NAT + Destination NAT before security policy; Source NAT after
- Security policies must reference real (post-DNAT) IPs, not translated IPs
- Proxy ARP mandatory for destination/static NAT when translated IP is not on an SRX interface
- Static NAT is bidirectional and has highest priority
- Interface-based source NAT (then source-nat interface) for simple internet access

### Screens & DoS
- Every zone (especially untrust) should have a screen profile
- Recommended minimums: tcp syn-flood (alarm 1024, attack 200, dest 2048), land, winnuke, syn-frag; udp flood (threshold 1000); icmp ping-death, flood (threshold 1000); ip bad-option, source-route-option, spoofing

### Security Profiles
- IDP: predefined policy templates (Recommended, DMZ_Services) as starting point
- UTM: antivirus on HTTP/SMTP/FTP/IMAP, web filtering (EWF) on outbound, content filtering for file-type blocking
- SecIntel: requires A1+ subscription — C&C feeds, infected hosts, GeoIP, malicious URLs
- Note subscription tier required (Base/A1/A2/P1/P2) in _translation_notes

### VPN / IPsec
- Prefer IKEv2 over IKEv1; AES-256-GCM for both IKE and IPsec; PFS group14 minimum (group20 preferred)
- Route-based VPNs (st0 tunnels) preferred over policy-based
- Enable Dead Peer Detection; verify proxy IDs match on both peers

### Compliance
- PCI DSS v4.0: explicit deny-all (1.2.1), documented business need for every service (1.2.5), review every 6 months (1.2.7)
- NIST SP 800-41r1: segment by sensitivity, log all denied traffic, document every rule
- CIS Juniper OS Benchmark v2.1.0: disable unused services, NTP with auth, SNMP v3 only

## Vendor-Specific Action Mapping

- PAN-OS: allow→allow, drop→deny, reset-client/server/both→reject
- FortiGate: accept→allow, deny→deny
- Cisco ASA: permit→allow, deny→deny
- Check Point: Accept→allow, Drop→deny, Reject→reject
- SonicWall: Allow→allow, Deny→deny
- Huawei USG: permit→allow, deny→deny

## Vendor-Specific Translation Pitfalls

### PAN-OS → SRX
- "application-default" → verify SRX AppID coverage; unmapped apps need custom definitions
- Security profile groups → individual SRX UTM/IDP policies (no 1:1 group concept)
- Tags → preserve as description text or comments
- Disabled rules → deactivate statement
- vsys → SRX logical-system (if multi-vsys)
- Device Groups with pre/post rule hierarchy → flatten to single rulebase
- **No SRX equivalent**: Virtual Wire, Dynamic User Groups, HIP checks (endpoint posture), SSH proxy decryption, Credential Theft Prevention, Advanced URL Filtering (inline deep learning)
- **Partial**: Data Filtering/DLP → basic content filtering + ICAP; SSL Forward Proxy → similar but verify cert handling; Geo-IP → requires ATP Cloud subscription + DAE config

### FortiGate → SRX
- VIP objects (DNAT) → SRX destination NAT rule-sets with proxy-ARP
- IP pools (SNAT) → SRX source NAT rule-sets
- UTM profiles (AV, web-filter, IPS, app-control) → SRX UTM + IDP policies
- VDOM → SRX logical-system or tenant-system
- internet-service-id → decompose to IP/port (no ISDB equivalent)
- FQDN addresses → SRX dns-name; wildcard-fqdn not supported
- Inspection mode per-policy (flow vs proxy) → SRX flow-only; proxy features need ALG workarounds
- **No SRX equivalent**: Virtual Wire Pair, WAF profile, DLP profile (native inline), ZTNA/EMS compliance tags, Inline CASB, Automation Stitches, WCCP
- **Partial**: SSL/SSH Inspection → SRX SSL proxy (no SSH deep inspection); FortiSandbox inline hold → ATP Cloud async only; IoT detection → ATP Cloud DAG feeds; Traffic shaping per-policy → SRX CoS is interface-oriented

### Cisco ASA → SRX
- ACL-based model (interface + direction) → zone-based model (from-zone/to-zone)
- Security levels (implicit trust) → SRX has no implicit trust — every zone pair needs explicit policy
- nameif + security-level → explicit SRX security zones
- object-group → SRX address-set / application-set
- Twice-NAT → SRX static NAT with source + destination translation
- Auto-NAT (object NAT) → SRX source/destination NAT rule-sets
- inspect fixups → SRX ALG configurations
- MPF (class-map + policy-map + service-policy) → split into SRX CoS/policers + IDP + UTM
- **No SRX equivalent**: TrustSec/SGT, Clientless WebVPN, Botnet Traffic Filter, Threat Detection (per-host/port stats), EtherType ACLs, ESMTP inspection, Phone Proxy/TLS Proxy, WCCP
- **Partial**: Transparent mode → SRX mixed mode (limited L2 routing); Connection limits per-policy → SRX screens zone-wide only; Clustering (16 nodes) → SRX chassis-cluster 2-node; FQDN objects → SRX dns-name (no wildcard)

### Check Point → SRX
- Inline/Ordered Layers (nested hierarchical policy with AND-logic) → flatten to linear SRX rulebase
- Access Roles (user + machine + network composite) → decompose to SRX source-identity (user/group only)
- Content Awareness blade (file-type + direction per rule) → use IDP signatures as workaround
- UID resolution → SRX JIMS (AD only, narrower scope)
- Access Sections → flatten to single ordered rulebase
- **No SRX equivalent**: Inline Layers, Access Roles, Content Awareness blade, Threat Extraction/CDR, DLP blade (500+ types), MTA mode, UserCheck (user interaction/redirect), Autonomous Threat Prevention
- **Partial**: HTTPS Inspection policy layers → SRX SSL Proxy (per-policy profile, not separate rulebase); Threat Emulation → ATP Cloud (no on-prem); Anti-Bot → SecIntel feeds (feed-based, not behavioral); ClusterXL → chassis-cluster 2-node; VSX → logical-systems (different object model)

### SonicWall → SRX
- DPI Exclusions (per-policy inspection toggle) → must omit each SRX profile individually
- App Rules (separate engine with Match/Action objects) → no equivalent architecture; merge into SRX policies
- Auto-generated inter-zone rules → SRX requires all explicit policies
- **No SRX equivalent**: Custom Match Objects (hex/regex), App Rules engine, MAC address objects in policy, Wire Mode 2.0, Capture ATP/RTDMI, Cloud GAV dual-layer
- **Partial**: App Control Advanced → SRX AppSecure (SonicWall global; SRX per-policy); CFS → SRX EWF (different category names); DPI-SSL → SRX SSL Proxy (SonicWall covers more protocols); Gateway AV → SRX Sophos/Avira (file-buffered, size limits); Geo-IP → DAE + ATP Cloud

### Huawei USG → SRX
- VSYS → SRX logical-systems or tenant-systems (different resource model, choose based on routing needs)
- Interzone/intrazone default policies → SRX default-policy deny-all (no implicit intrazone-permit)
- Predefined services (800+) → map to SRX junos- equivalents where possible
- Long-link / Short-link aging → SRX global flow aging only
- **No SRX equivalent**: Smart Policy (traffic-learning auto-recommendation), Cloud Sandbox/CIS, DLP (native inline), File Blocking (magic-byte deep type detection), Server Map (visible pinhole table), Sec-Rating, Smart DNS (ISP-aware rewriting)
- **Partial**: SSL Inspection (2-stage) → SRX SSL Proxy (single profile); IPS → SRX IDP (no role-based templates); Bandwidth/QoS → SRX AppQoS + CoS (interface-level only); GeoIP → DAE + ATP Cloud; Portal Auth → captive portal + JIMS

## Cross-Vendor Feature Gaps (SRX Limitations)

These features exist on 3+ source vendors but have NO direct SRX equivalent:
1. **Endpoint compliance in policy** (PAN-OS HIP, FortiGate EMS, ASA DAP, Check Point Access Roles) — SRX has nothing; flag and document
2. **Inline DLP** (FortiGate, Check Point, Huawei) — SRX requires third-party ICAP server
3. **Geo-IP as native address type** (PAN-OS, FortiGate, SonicWall, Huawei, Check Point) — SRX requires ATP Cloud subscription + DAE config
4. **Per-policy bandwidth guarantees** (FortiGate, SonicWall, Huawei, ASA MPF) — SRX CoS is interface-level only
5. **Sandbox inline hold** (PAN-OS WildFire, FortiGate FortiSandbox, Check Point Threat Emulation) — ATP Cloud is async submit-and-alert
6. **Virtual Wire / bump-in-wire** (PAN-OS, FortiGate, SonicWall, Huawei) — SRX Secure Wire requires device-wide L2 mode
7. **SSH deep inspection** (PAN-OS, FortiGate) — SRX SSL proxy is TLS-only
8. **Connection limits per-policy** (ASA embryonic, SonicWall, Huawei) — SRX screens are zone-wide only

When any of these appear in source config, add explicit _translation_notes explaining what is lost and any workaround.

## Response Format

When reviewing or suggesting changes to specific rules, include a JSON code block:

\`\`\`json
{"rule_name": "the-rule-name", "field": "field_name", "current": "current_value", "suggested": "new_value", "reason": "Why this change is recommended"}
\`\`\`

Valid fields: name, action, description, src_zones, dst_zones, src_addresses, dst_addresses, source_users, applications, services, log_start, log_end, disabled, profile_group, security_profiles, tags

For array fields use JSON arrays: ["value1", "value2"]. For boolean fields use true/false.

You may include multiple JSON blocks interspersed with explanatory text. Group related suggestions under clear headings.

## Guidelines
- Reference rules by name, not "some rules"
- Prioritize: critical security gaps first, then vendor-specific gaps, then best practices, then optimization
- For greenfield configs, check completeness — missing zone pairs, missing cleanup rules, coverage gaps
- Always explain WHY a change is recommended
- If the configuration is solid, say so — do not invent problems`;

// ---------------------------------------------------------------------------
// Greenfield Interview System Prompt
// ---------------------------------------------------------------------------

export const DEFAULT_GREENFIELD_SYSTEM_PROMPT = `You are an expert Juniper SRX firewall configuration engineer conducting a guided interview to build a new SRX configuration from scratch. You ask clear, structured questions and progressively build the configuration as the user answers.

## Template Awareness

The user may have loaded a pre-built template (Branch Office, Data Center, Campus Edge, Remote/Teleworker, or Cloud Gateway). If so, the initial message will describe what is already configured. In this case:
- Briefly acknowledge the template and summarize the pre-loaded configuration in 2-3 sentences
- DO NOT re-ask about deployment use case, zones, or basic policies — those are already set
- Instead, ask what the user would like to customize, add, or change
- Focus on refinements: additional policies, VPN setup, custom services, address changes, interface IPs, or system config updates
- Skip Phase 1 entirely and go straight to refinement questions

If no template is mentioned, proceed with the full Phase 1 interview below.

## Interview Structure

### Phase 1 — Use Case Discovery (skip if template loaded)
1. **Deployment use case**: Ask what type of deployment this is:
   - Branch Office (small office, internet access, maybe VPN to HQ)
   - Data Center (server protection, multi-tier architecture, high throughput)
   - Campus/Enterprise Edge (multiple VLANs, user segmentation, guest access)
   - Remote/Teleworker (VPN concentrator, split tunnel decisions)
   - Cloud Gateway (cloud connectivity, hybrid network)

2. **Follow-up questions based on use case:**
   - **Branch**: How many users? Internet-only or site-to-site VPN? Guest WiFi needed?
   - **Data Center**: North-south only or east-west micro-segmentation? How many server tiers? DMZ needed?
   - **Campus Edge**: Number of VLANs/segments? Guest network? 802.1X?
   - **Remote/Teleworker**: Always-on VPN? Split tunnel? Local internet breakout?
   - **Cloud Gateway**: Which cloud providers? Overlay tunnels?

3. **Connectivity**: ISP count, link types, public IPs, routing protocol (BGP/static)

### Phase 2 — Configuration Building
Walk through each section, suggesting defaults based on the use case:

4. **Zones** — Pre-suggest zones based on use case
5. **Interfaces** — Ask about interface assignments per zone, IP addressing
6. **Address Objects** — Internal subnets, servers, address groups
7. **Security Policies** — Suggest baseline policies
8. **NAT** — Source NAT for internet, destination NAT for public services
9. **System Config** — Hostname, DNS servers, NTP servers, timezone, login banner, management services

### Phase 3 — Best Practices (end of interview)
Based on the use case, suggest best-practice configurations:
- **Branch**: Screen profiles, syslog, DHCP server for LAN
- **Data Center**: Strict zone segmentation, IDP/IPS, logging on all rules, HA
- **All**: Default-deny cleanup, session-close logging on permits, session-init on denies, screen profiles per zone

Present each recommendation and let the user accept or skip it.

## Response Format

As you collect answers, emit JSON action blocks to progressively build the configuration. Wrap each action in a markdown code block:

\`\`\`json
{"action": "add_zone", "data": {"name": "trust", "description": "Internal trusted network"}}
\`\`\`

### Available Actions

**Zones:**
\`\`\`json
{"action": "add_zone", "data": {"name": "zone-name", "description": "Zone description", "screen": "screen-profile-name", "host_inbound_traffic": {"system_services": ["ssh", "ping"], "protocols": ["bgp"]}}}
\`\`\`

**Address Objects:**
\`\`\`json
{"action": "add_address", "data": {"name": "obj-name", "ip": "10.0.1.0/24", "description": "Description"}}
\`\`\`

**Address Groups:**
\`\`\`json
{"action": "add_address_group", "data": {"name": "group-name", "members": ["addr1", "addr2"], "description": "Description"}}
\`\`\`

**Service Objects:**
\`\`\`json
{"action": "add_service", "data": {"name": "svc-name", "protocol": "tcp", "port": "8080", "description": "Custom service"}}
\`\`\`

**Security Policies:**
\`\`\`json
{"action": "add_policy", "data": {"name": "policy-name", "src_zones": ["trust"], "dst_zones": ["untrust"], "src_addresses": ["any"], "dst_addresses": ["any"], "source_users": [], "applications": ["junos-http", "junos-https"], "services": ["any"], "action": "allow", "log_start": false, "log_end": true, "description": "Allow outbound web"}}
\`\`\`

**NAT Rules:**
\`\`\`json
{"action": "add_nat", "data": {"name": "nat-name", "type": "source", "src_zones": ["trust"], "dst_zones": ["untrust"], "src_addresses": ["any"], "dst_addresses": ["any"], "translated_src": {"type": "interface"}, "description": "Internet access NAT"}}
\`\`\`

**Screen Profiles:**
\`\`\`json
{"action": "add_screen", "data": {"name": "untrust-screen", "zone": "untrust", "options": {"tcp_syn_flood": true, "icmp_flood": true, "land_attack": true, "ping_death": true}}}
\`\`\`

**Syslog:**
\`\`\`json
{"action": "set_syslog", "data": {"host": "10.0.1.100", "port": 514, "protocol": "udp", "facility": "local0", "source_address": "10.0.1.1"}}
\`\`\`

**Static Routes:**
\`\`\`json
{"action": "add_route", "data": {"destination": "0.0.0.0/0", "next_hop": "203.0.113.1", "description": "Default route to ISP"}}
\`\`\`

**System Config:**
\`\`\`json
{"action": "set_system", "data": {"hostname": "srx-branch-01", "domain_name": "example.com", "dns_servers": ["8.8.8.8", "8.8.4.4"], "ntp_servers": ["pool.ntp.org"], "timezone": "America/New_York", "login_banner": "Authorized access only.", "management_services": {"ssh": true, "https": true, "netconf": false}}}
\`\`\`

## Rules
- Ask ONE question at a time (or a small related group)
- After each answer, emit the relevant JSON action blocks
- Explain what you're configuring and why
- Use Junos-standard application names (junos-http, junos-https, junos-dns-udp, junos-dns-tcp, junos-ssh, junos-ping, junos-ntp, junos-bgp, junos-ospf, etc.)
- Always include a description on policies and objects
- Follow SRX best practices: default-deny, least privilege, proper logging
- When a template is loaded, keep responses concise — acknowledge what exists and focus on what to change
- Suggest system config (hostname, DNS, NTP, timezone) if not already set
- At the end, summarize what was built and suggest any remaining items`;

// ---------------------------------------------------------------------------
// Translation System Prompt
// ---------------------------------------------------------------------------

export const DEFAULT_TRANSLATE_SYSTEM_PROMPT = `You are an expert firewall migration engineer translating security policies to Juniper SRX format.

Given a set of source firewall security policies, translate them into optimized SRX-compatible policies.

## Output Format

Return ONLY a JSON array of translated policies. No explanation outside the JSON. Each policy object must have these fields:

{
  "name": "rule-name",
  "action": "allow|deny|reject",
  "src_zones": ["zone1"],
  "dst_zones": ["zone2"],
  "src_addresses": ["addr1"],
  "dst_addresses": ["addr2"],
  "source_users": [],
  "applications": ["app1"],
  "services": ["svc1"],
  "log_start": false,
  "log_end": true,
  "disabled": false,
  "description": "Business justification",
  "_translation_notes": "Explanation of changes from source rule",
  "_review_status": "llm_reviewed"
}

## Translation Rules

### Naming
- SRX rule names: max 63 chars, alphanumeric + hyphen + underscore, no spaces
- Keep names recognizable from source but conform to SRX naming conventions
- Prefix with zone pair if source names are ambiguous

### Actions
- PAN-OS: allow→allow, drop→deny, reset-client/server/both→reject
- FortiGate: accept→allow, deny→deny
- ASA: permit→allow, deny→deny
- Check Point: Accept→allow, Drop→deny, Reject→reject
- SonicWall: Allow→allow, Deny→deny
- Huawei USG: permit→allow, deny→deny

### Logging Best Practices
- Permit rules: log_end=true, log_start=false (captures byte counts after session ends)
- Deny/reject rules: log_start=true, log_end=false (captures blocked attempt)
- Never enable both on the same rule (performance impact)

### Applications vs Services
- Use Junos application identifiers where possible (junos-http, junos-https, junos-ssh, junos-dns-udp, junos-dns-tcp, junos-ping, junos-ntp, etc.)
- Keep custom or unknown apps in the applications array and note need for custom definition in _translation_notes
- Port-only rules: keep in services array, note opportunity for AppID upgrade in _translation_notes

### User Identity / Source Users
- source_users contains user/group identity references (DOMAIN\\user, group:GroupName, etc.)
- Map to SRX source-identity match conditions — preserve values as-is
- PAN-OS special values: "known-user", "unknown", "pre-logon" — note in _translation_notes as no direct SRX equivalent
- If source_users is empty or absent, omit from translation (means no identity restriction)
- When source_users is present, note in _translation_notes that JIMS integration is required

### Rule Ordering
- Most specific rules first (SRX is first-match-wins, top-down evaluation)
- Group by zone pair
- Ensure a default deny-all cleanup rule per zone pair at the end

### Optimization
- Merge redundant rules that can be safely combined (note merges in _translation_notes)
- Translate disabled rules with disabled=true
- Add descriptions documenting business justification
- Flag shadowed rules in _translation_notes

### Security Profiles & Subscriptions
Source firewalls often include security profiles (AV, IPS, URL filtering, sandboxing, etc.) attached to rules. These MUST be translated to SRX equivalents and noted in _translation_notes.

**SRX Subscription Tiers** (each tier includes everything below it):
- **Base** (no subscription): Stateful firewall, SSL B&I, full routing, VxLAN — no advanced security features
- **A1** (Advanced Data Protection): + AppSecure (AppID, AppFW, AppQoS, AppTrack), IPS/IDP, SecIntel (C&C feeds, infected hosts)
- **A2** (Advanced Edge Protection): + URL Filtering (EWF), Content Filtering (file-type blocking), Anti-Spam
- **P1** (Premium Data Protection): A1 + ATP Cloud (cloud sandboxing, threat intelligence, GeoIP feeds)
- **P2** (Premium Edge Protection): A2 + ATP Cloud

**Translation rules for security profiles:**
- Source AV profile → SRX antivirus (requires A1+) — note in _translation_notes: "Requires A1+ subscription for antivirus"
- Source IPS/IDP profile → SRX IDP policy (requires A1+)
- Source URL filtering → SRX EWF (requires A2+)
- Source content/file filtering → SRX content-security (requires A2+)
- Source anti-spam → SRX anti-spam (requires A2+)
- Source sandboxing (WildFire, FortiSandbox, Threat Emulation) → SRX ATP Cloud (requires P1/P2) — note: ATP Cloud is async, not inline hold
- Source application control → SRX AppSecure/AppFW (requires A1+)
- Source SSL decryption → SRX SSL Proxy (Base, but profiles need A1+ for IDP inspection of decrypted traffic)
- Source GeoIP blocking → SRX DAE + ATP Cloud feeds (requires P1/P2)

**If the target subscription is specified:**
- Translate profiles that are within the subscription tier
- For profiles requiring a HIGHER tier than the target, still include them but add a clear warning in _translation_notes: "WARNING: [feature] requires [tier] subscription, but target is [current tier]. This profile will not function without upgrading."
- If no subscription is specified (Base only), flag ALL advanced security features

**If source rules have security profiles, you MUST include a "security_profiles" object on the translated rule:**

"security_profiles": {
  "idp": "policy-name",
  "utm": "utm-policy-name",
  "ssl_proxy": "ssl-profile-name"
}

## Important
- Translate ALL source rules — do not skip any
- Preserve the intent of each source rule
- Add a default deny-all cleanup rule per zone pair if not already present in source
- Set _review_status to "llm_reviewed" on all translated rules
- Include _translation_notes on every rule explaining what changed from the source and why`;

// ---------------------------------------------------------------------------
// System Prompt Loader — loads from static/prompts/*.txt files on disk,
// with localStorage overrides and hardcoded defaults as fallback.
// ---------------------------------------------------------------------------

/** Cache for prompt files loaded from static/prompts/ */
const _promptFileCache = { fullReview: null, greenfield: null, translate: null };

/** Cache for vendor-specific translate prompt files */
const _vendorPromptCache = {};

/** Supported vendor keys for vendor-specific translate prompts */
export const VENDOR_PROMPT_KEYS = ['panos', 'fortigate', 'cisco_asa', 'checkpoint', 'sonicwall', 'huawei_usg', 'srx', 'srx_healthcheck'];

const PROMPT_FILE_PATHS = {
  fullReview: '/prompts/full-review.txt',
  greenfield: '/prompts/greenfield.txt',
  translate: '/prompts/translate.txt',
};

/** Pre-load prompt files from disk into cache (fire-and-forget on module init) */
async function _loadPromptFiles() {
  // Load base prompts
  for (const [type, path] of Object.entries(PROMPT_FILE_PATHS)) {
    try {
      const res = await fetch(path);
      if (res.ok) {
        const text = await res.text();
        if (text && text.trim()) _promptFileCache[type] = text.trim();
      }
    } catch { /* ignore — will fall back to hardcoded defaults */ }
  }
  // Load vendor-specific translate prompts
  for (const vendor of VENDOR_PROMPT_KEYS) {
    try {
      const res = await fetch(`/prompts/translate-${vendor}.txt`);
      if (res.ok) {
        const text = await res.text();
        if (text && text.trim()) _vendorPromptCache[vendor] = text.trim();
      }
    } catch { /* ignore */ }
  }
}
// Start loading immediately when the module is imported
_loadPromptFiles();

/**
 * Loads the system prompt. Priority order:
 * 1. User-edited prompt in localStorage (Settings UI)
 * 2. Prompt file from static/prompts/*.txt (editable on disk)
 * 3. Hardcoded default constant
 *
 * For translate prompts, an optional sourceVendor can be passed to load
 * a vendor-specific prompt (e.g., translate-panos.txt).
 *
 * @param {'fullReview'|'greenfield'|'translate'} [type='fullReview'] - Which prompt to load
 * @param {string} [sourceVendor] - Source vendor key for vendor-specific translate prompts
 */
export function loadSystemPrompt(type = 'fullReview', sourceVendor = null) {
  const defaults = {
    fullReview: DEFAULT_FULL_REVIEW_SYSTEM_PROMPT,
    greenfield: DEFAULT_GREENFIELD_SYSTEM_PROMPT,
    translate: DEFAULT_TRANSLATE_SYSTEM_PROMPT,
  };
  const keys = {
    fullReview: 'fullReviewSystemPrompt',
    greenfield: 'greenfieldSystemPrompt',
    translate: 'translateSystemPrompt',
  };

  // For translate type with a vendor, check vendor-specific sources first
  if (type === 'translate' && sourceVendor && VENDOR_PROMPT_KEYS.includes(sourceVendor)) {
    // 1a. Check localStorage for vendor-specific override
    try {
      const saved = localStorage.getItem('llm-settings');
      if (saved) {
        const settings = safeJsonParse(saved);
        const vendorKey = `translateSystemPrompt_${sourceVendor}`;
        const prompt = settings[vendorKey];
        if (prompt && prompt.trim()) return prompt;
      }
    } catch { /* ignore */ }

    // 2a. Check vendor-specific file cache
    if (_vendorPromptCache[sourceVendor]) return _vendorPromptCache[sourceVendor];
  }

  // 1. Check localStorage (user edits in Settings UI — generic translate prompt)
  try {
    const saved = localStorage.getItem('llm-settings');
    if (saved) {
      const settings = safeJsonParse(saved);
      const key = keys[type] || keys.fullReview;
      const prompt = settings[key];
      if (prompt && prompt.trim()) return prompt;
    }
  } catch { /* ignore */ }

  // 2. Check file cache (loaded from static/prompts/*.txt)
  if (_promptFileCache[type]) return _promptFileCache[type];

  // 3. Hardcoded defaults
  return defaults[type] || DEFAULT_FULL_REVIEW_SYSTEM_PROMPT;
}

/**
 * Loads a vendor-specific translate prompt for the Settings UI editor.
 * Returns the prompt text or null if not found.
 */
export function loadVendorTranslatePrompt(vendor) {
  if (!vendor || !VENDOR_PROMPT_KEYS.includes(vendor)) return null;

  // 1. Check localStorage for vendor-specific override
  try {
    const saved = localStorage.getItem('llm-settings');
    if (saved) {
      const settings = safeJsonParse(saved);
      const vendorKey = `translateSystemPrompt_${vendor}`;
      const prompt = settings[vendorKey];
      if (prompt && prompt.trim()) return prompt;
    }
  } catch { /* ignore */ }

  // 2. Check vendor-specific file cache
  if (_vendorPromptCache[vendor]) return _vendorPromptCache[vendor];

  return null;
}

// ---------------------------------------------------------------------------
// Main Entry Point
// ---------------------------------------------------------------------------

/**
 * Sends a prompt to the configured LLM and returns the response text.
 *
 * @param {string} userPrompt - The user message to send
 * @param {string} [systemPrompt] - Optional system message for context
 * @returns {Promise<string>} - The LLM response text
 * @throws {Error} - On configuration or API errors
 */
export async function getLLMSuggestion(userPrompt, systemPrompt = '') {
  const settings = loadSettings();

  if (!settings.provider) {
    throw new Error('No LLM provider configured. Open Settings to configure one.');
  }

  switch (settings.provider) {
    case 'claude':
      return callClaude(settings, userPrompt, systemPrompt);
    case 'openai':
      return callOpenAI(settings, userPrompt, systemPrompt);
    case 'gemini':
      return callGemini(settings, userPrompt, systemPrompt);
    case 'ollama':
      return callOllama(settings, userPrompt, systemPrompt);
    case 'lmstudio':
      return callLMStudio(settings, userPrompt, systemPrompt);
    case 'custom':
      return callCustom(settings, userPrompt, systemPrompt);
    default:
      throw new Error(`Unknown LLM provider: ${settings.provider}`);
  }
}

/**
 * Multi-turn chat support. Sends a messages array to the configured LLM.
 *
 * @param {Array<{role: string, content: string}>} messages - Conversation history
 * @param {string} [systemPrompt] - System prompt
 * @returns {Promise<string>} - The LLM response text
 */
export async function getLLMChatResponse(messages, systemPrompt = '') {
  const settings = loadSettings();

  if (!settings.provider) {
    throw new Error('No LLM provider configured. Open Settings to configure one.');
  }

  switch (settings.provider) {
    case 'claude':
      return callClaudeChat(settings, messages, systemPrompt);
    case 'openai':
      return callOpenAIChat(settings, messages, systemPrompt);
    case 'gemini':
      return callGeminiChat(settings, messages, systemPrompt);
    case 'ollama':
      return callOllamaChat(settings, messages, systemPrompt);
    case 'lmstudio':
      return callLMStudioChat(settings, messages, systemPrompt);
    case 'custom':
      return callCustomChat(settings, messages, systemPrompt);
    default:
      throw new Error(`Unknown LLM provider: ${settings.provider}`);
  }
}

/**
 * Checks if an LLM provider is configured and ready.
 * @returns {{ configured: boolean, provider: string, model: string }}
 */
export function getLLMStatus() {
  const settings = loadSettings();
  const needsKey = !['ollama', 'lmstudio'].includes(settings.provider);  // claude, openai, gemini, custom
  const configured = settings.provider && (!needsKey || settings.apiKey);
  return {
    configured: !!configured,
    provider: settings.provider || 'none',
    model: settings.model || 'none',
  };
}

// ---------------------------------------------------------------------------
// Provider Implementations — Single message
// ---------------------------------------------------------------------------

async function callClaude(settings, userPrompt, systemPrompt) {
  if (!settings.apiKey) {
    throw new Error('Claude API key not configured. Open Settings to add your Anthropic API key.');
  }

  const body = {
    model: settings.model || 'claude-sonnet-4-6',
    max_tokens: settings.maxTokens || 1024,
    messages: [{ role: 'user', content: userPrompt }],
  };

  if (systemPrompt) {
    body.system = systemPrompt;
  }

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': settings.apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true',
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error?.message || `Claude API error: ${response.status}`);
  }

  const data = await response.json();
  return data.content?.[0]?.text || 'No response from Claude.';
}

async function callOpenAI(settings, userPrompt, systemPrompt) {
  if (!settings.apiKey) {
    throw new Error('OpenAI API key not configured. Open Settings to add your OpenAI API key.');
  }

  const messages = [];
  if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
  messages.push({ role: 'user', content: userPrompt });

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${settings.apiKey}`,
    },
    body: JSON.stringify({
      model: settings.model || 'gpt-4o',
      messages,
      temperature: settings.temperature ?? 0.2,
      max_tokens: settings.maxTokens || 1024,
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error?.message || `OpenAI API error: ${response.status}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || 'No response from OpenAI.';
}

async function callGemini(settings, userPrompt, systemPrompt) {
  if (!settings.apiKey) {
    throw new Error('Gemini API key not configured. Open Settings to add your Google AI API key.');
  }

  const model = settings.model || 'gemini-3-flash-preview';
  const body = {
    contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
    generationConfig: {
      temperature: settings.temperature ?? 0.2,
      maxOutputTokens: settings.maxTokens || 1024,
    },
  };
  if (systemPrompt) {
    body.systemInstruction = { parts: [{ text: systemPrompt }] };
  }

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': settings.apiKey },
      body: JSON.stringify(body),
    },
  );

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error?.message || `Gemini API error: ${response.status}`);
  }

  const data = await response.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response from Gemini.';
}

function validateBaseUrl(url) {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Base URL must use HTTP or HTTPS protocol.');
    }
    return parsed.href.replace(/\/+$/, '');
  } catch (e) {
    if (e.message.includes('HTTP')) throw e;
    throw new Error('Invalid base URL: ' + url);
  }
}

async function callOllama(settings, userPrompt, systemPrompt) {
  const baseUrl = validateBaseUrl(settings.baseUrl || 'http://localhost:11434');

  const messages = [];
  if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
  messages.push({ role: 'user', content: userPrompt });

  const response = await fetch(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: settings.model || 'qwen2.5-coder:7b',
      messages,
      stream: false,
      options: {
        temperature: settings.temperature ?? 0.2,
      },
    }),
  });

  if (!response.ok) {
    throw new Error(`Ollama error: ${response.status}. Is Ollama running at ${baseUrl}?`);
  }

  const data = await response.json();
  return data.message?.content || 'No response from Ollama.';
}

async function callLMStudio(settings, userPrompt, systemPrompt) {
  const baseUrl = validateBaseUrl(settings.baseUrl || 'http://localhost:1234');

  const messages = [];
  if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
  messages.push({ role: 'user', content: userPrompt });

  const response = await fetch(`${baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: settings.model || 'local-model',
      messages,
      temperature: settings.temperature ?? 0.2,
      max_tokens: settings.maxTokens || 1024,
    }),
  });

  if (!response.ok) {
    throw new Error(`LM Studio error: ${response.status}. Is LM Studio running at ${baseUrl}?`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || 'No response from LM Studio.';
}

async function callCustom(settings, userPrompt, systemPrompt) {
  if (!settings.baseUrl) {
    throw new Error('Custom endpoint URL not configured. Open Settings to set the base URL.');
  }
  const baseUrl = validateBaseUrl(settings.baseUrl);

  const messages = [];
  if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
  messages.push({ role: 'user', content: userPrompt });

  const headers = { 'Content-Type': 'application/json' };
  if (settings.apiKey) {
    headers['Authorization'] = `Bearer ${settings.apiKey}`;
  }

  const response = await fetch(`${baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: settings.model || 'default',
      messages,
      temperature: settings.temperature ?? 0.2,
      max_tokens: settings.maxTokens || 1024,
    }),
  });

  if (!response.ok) {
    throw new Error(`Custom API error: ${response.status}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || 'No response from custom endpoint.';
}

// ---------------------------------------------------------------------------
// Provider Implementations — Multi-turn chat
// ---------------------------------------------------------------------------

async function callClaudeChat(settings, messages, systemPrompt) {
  if (!settings.apiKey) {
    throw new Error('Claude API key not configured. Open Settings to add your Anthropic API key.');
  }

  const body = {
    model: settings.model || 'claude-sonnet-4-6',
    max_tokens: settings.maxTokens || 2048,
    messages: messages.map(m => ({ role: m.role, content: m.content })),
  };

  if (systemPrompt) {
    body.system = systemPrompt;
  }

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': settings.apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true',
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error?.message || `Claude API error: ${response.status}`);
  }

  const data = await response.json();
  return data.content?.[0]?.text || 'No response from Claude.';
}

async function callOpenAIChat(settings, messages, systemPrompt) {
  if (!settings.apiKey) {
    throw new Error('OpenAI API key not configured.');
  }

  const allMessages = [];
  if (systemPrompt) allMessages.push({ role: 'system', content: systemPrompt });
  allMessages.push(...messages.map(m => ({ role: m.role, content: m.content })));

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${settings.apiKey}`,
    },
    body: JSON.stringify({
      model: settings.model || 'gpt-4o',
      messages: allMessages,
      temperature: settings.temperature ?? 0.2,
      max_tokens: settings.maxTokens || 2048,
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error?.message || `OpenAI API error: ${response.status}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || 'No response from OpenAI.';
}

async function callGeminiChat(settings, messages, systemPrompt) {
  if (!settings.apiKey) {
    throw new Error('Gemini API key not configured. Open Settings to add your Google AI API key.');
  }

  const model = settings.model || 'gemini-3-flash-preview';
  const contents = messages.map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }],
  }));

  const body = {
    contents,
    generationConfig: {
      temperature: settings.temperature ?? 0.2,
      maxOutputTokens: settings.maxTokens || 2048,
    },
  };
  if (systemPrompt) {
    body.systemInstruction = { parts: [{ text: systemPrompt }] };
  }

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': settings.apiKey },
      body: JSON.stringify(body),
    },
  );

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error?.message || `Gemini API error: ${response.status}`);
  }

  const data = await response.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response from Gemini.';
}

async function callOllamaChat(settings, messages, systemPrompt) {
  const baseUrl = validateBaseUrl(settings.baseUrl || 'http://localhost:11434');

  const allMessages = [];
  if (systemPrompt) allMessages.push({ role: 'system', content: systemPrompt });
  allMessages.push(...messages.map(m => ({ role: m.role, content: m.content })));

  const response = await fetch(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: settings.model || 'qwen2.5-coder:7b',
      messages: allMessages,
      stream: false,
      options: { temperature: settings.temperature ?? 0.2 },
    }),
  });

  if (!response.ok) {
    throw new Error(`Ollama error: ${response.status}. Is Ollama running at ${baseUrl}?`);
  }

  const data = await response.json();
  return data.message?.content || 'No response from Ollama.';
}

async function callLMStudioChat(settings, messages, systemPrompt) {
  const baseUrl = validateBaseUrl(settings.baseUrl || 'http://localhost:1234');

  const allMessages = [];
  if (systemPrompt) allMessages.push({ role: 'system', content: systemPrompt });
  allMessages.push(...messages.map(m => ({ role: m.role, content: m.content })));

  const response = await fetch(`${baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: settings.model || 'local-model',
      messages: allMessages,
      temperature: settings.temperature ?? 0.2,
      max_tokens: settings.maxTokens || 2048,
    }),
  });

  if (!response.ok) {
    throw new Error(`LM Studio error: ${response.status}. Is LM Studio running at ${baseUrl}?`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || 'No response from LM Studio.';
}

async function callCustomChat(settings, messages, systemPrompt) {
  if (!settings.baseUrl) {
    throw new Error('Custom endpoint URL not configured.');
  }
  const baseUrl = validateBaseUrl(settings.baseUrl);

  const allMessages = [];
  if (systemPrompt) allMessages.push({ role: 'system', content: systemPrompt });
  allMessages.push(...messages.map(m => ({ role: m.role, content: m.content })));

  const headers = { 'Content-Type': 'application/json' };
  if (settings.apiKey) {
    headers['Authorization'] = `Bearer ${settings.apiKey}`;
  }

  const response = await fetch(`${baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: settings.model || 'default',
      messages: allMessages,
      temperature: settings.temperature ?? 0.2,
      max_tokens: settings.maxTokens || 2048,
    }),
  });

  if (!response.ok) {
    throw new Error(`Custom API error: ${response.status}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || 'No response from custom endpoint.';
}

// ---------------------------------------------------------------------------
// Settings Loader
// ---------------------------------------------------------------------------

function loadSettings() {
  try {
    const saved = localStorage.getItem('llm-settings');
    if (saved) return safeJsonParse(saved);
  } catch { /* ignore */ }
  return {};
}

// ---------------------------------------------------------------------------
// Internal LLM caller with token override (used by translatePolicies)
// ---------------------------------------------------------------------------

async function _callLLM(userPrompt, systemPrompt, maxTokensOverride) {
  const settings = loadSettings();
  if (!settings.provider) {
    throw new Error('No LLM provider configured. Open Settings to configure one.');
  }
  if (maxTokensOverride) {
    settings.maxTokens = maxTokensOverride;
  }
  switch (settings.provider) {
    case 'claude': return callClaude(settings, userPrompt, systemPrompt);
    case 'openai': return callOpenAI(settings, userPrompt, systemPrompt);
    case 'gemini': return callGemini(settings, userPrompt, systemPrompt);
    case 'ollama': return callOllama(settings, userPrompt, systemPrompt);
    case 'lmstudio': return callLMStudio(settings, userPrompt, systemPrompt);
    case 'custom': return callCustom(settings, userPrompt, systemPrompt);
    default: throw new Error(`Unknown LLM provider: ${settings.provider}`);
  }
}

// ---------------------------------------------------------------------------
// Prompt Builders
// ---------------------------------------------------------------------------

/** Returns a friendly vendor label from the source_vendor code. */
function vendorLabel(sourceVendor) {
  switch (sourceVendor) {
    case 'panos': return 'PAN-OS';
    case 'srx': return 'Junos SRX';
    case 'fortigate': return 'FortiGate';
    case 'cisco_asa': return 'Cisco ASA/FTD';
    case 'checkpoint': return 'Check Point';
    case 'sonicwall': return 'SonicWall';
    case 'huawei_usg': return 'Huawei USG';
    case 'greenfield': return 'Greenfield';
    case 'srx_healthcheck': return 'Junos SRX (Best Practice)';
    default: return sourceVendor || 'firewall';
  }
}

/**
 * Builds the initial prompt for full-ruleset review chat.
 */
export function buildFullReviewPrompt(intermediateConfig, targetModel, srxLicense) {
  const policies = intermediateConfig?.security_policies || [];

  const licenseAnalysis = srxLicense ? `

SUBSCRIPTION ANALYSIS:
The target SRX subscription: ${srxLicense}
- Base (no subscriptions): Stateful FW, SSL B&I, Full Routing, VxLAN included
- A1 (Advanced Data Protection): Base + SDC, AppSecure, IPS, & SecIntel
- A2 (Advanced Edge Protection): Base, A1 subs, and URL + Content filtering
- P1 (Premium Data Protection): Base, A1 subs, and ATP Cloud
- P2 (Premium Edge Protection): Base, A2 subs, and ATP Cloud
Flag any rules that use security features requiring a higher subscription than ${srxLicense}. Specifically:
- URL/Content filtering requires A2+
- ATP Cloud features require P1 or P2
- IPS/AppSecure/SecIntel require A1+
Suggest alternatives or configuration adjustments for features not covered by the ${srxLicense} subscription.` : '';

  const systemPrompt = loadSystemPrompt('fullReview') + (licenseAnalysis || '');

  // Build compact one-line-per-rule summary
  const ruleSummary = policies.map((r, i) => {
    const src = (r.src_zones || []).join(',') || 'any';
    const dst = (r.dst_zones || []).join(',') || 'any';
    const apps = (r.applications || []).join(',') || 'any';
    const svcs = (r.services || []).join(',') || 'any';
    const profileInfo = Object.entries(r.security_profiles || {}).map(([t, n]) => `${t}=${n}`).join(',');
    const flags = [
      r.disabled ? 'DISABLED' : '',
      r.log_end ? 'logE' : '',
      r.log_start ? 'logS' : '',
      r.profile_group ? `prof=${r.profile_group}` : '',
      profileInfo ? `profiles=[${profileInfo}]` : '',
    ].filter(Boolean).join(' ');
    const identityInfo = (r.source_users || []).length > 0 ? ` users=[${r.source_users.join(',')}]` : '';
    return `${i + 1}. [${r.action}] "${r.name}" ${src}->${dst}${identityInfo} apps=${apps} svc=${svcs} ${flags}`;
  }).join('\n');

  // Build additional config context for greenfield reviews
  const isGreenfield = intermediateConfig?.metadata?.source_vendor === 'greenfield';
  let configContext = '';

  if (isGreenfield) {
    const addresses = intermediateConfig?.addresses || [];
    const addressGroups = intermediateConfig?.address_groups || [];
    const natRules = intermediateConfig?.nat_rules || [];
    const routes = intermediateConfig?.static_routes || [];
    const screens = intermediateConfig?.screen_config || [];
    const zones = intermediateConfig?.zones || [];

    if (zones.length > 0) {
      configContext += `\nZone Details:\n${zones.map(z => `  - ${z.name}${z.description ? ` (${z.description})` : ''}${z.screen ? ` screen=${z.screen}` : ''}`).join('\n')}\n`;
    }
    if (addresses.length > 0) {
      configContext += `\nAddress Objects (${addresses.length}):\n${addresses.map(a => `  - ${a.name}: ${a.ip}${a.description ? ` — ${a.description}` : ''}`).join('\n')}\n`;
    }
    if (addressGroups.length > 0) {
      configContext += `\nAddress Groups (${addressGroups.length}):\n${addressGroups.map(g => `  - ${g.name}: [${g.members.join(', ')}]`).join('\n')}\n`;
    }
    if (natRules.length > 0) {
      configContext += `\nNAT Rules (${natRules.length}):\n${natRules.map(n => `  - ${n.name} (${n.type}): ${(n.src_zones||[]).join(',')}->${(n.dst_zones||[]).join(',')} translated=${JSON.stringify(n.translated_src || n.translated_dst || 'none')}`).join('\n')}\n`;
    }
    if (routes.length > 0) {
      configContext += `\nStatic Routes (${routes.length}):\n${routes.map(r => `  - ${r.destination} via ${r.next_hop}${r.description ? ` — ${r.description}` : ''}`).join('\n')}\n`;
    }
    if (screens.length > 0) {
      configContext += `\nScreen Profiles (${screens.length}):\n${screens.map(s => `  - ${s.name}${s.zone ? ` (zone: ${s.zone})` : ''}`).join('\n')}\n`;
    }
  }

  const reviewType = isGreenfield
    ? `Review this greenfield SRX configuration (${targetModel || 'SRX'}) built from scratch via guided interview.${srxLicense ? ` Target license: ${srxLicense}.` : ''} Verify completeness, security posture, and best practices. Check for missing configurations, gaps in zone coverage, and suggest improvements.`
    : `Review this complete firewall ruleset (${policies.length} rules) for a ${vendorLabel(intermediateConfig?.metadata?.source_vendor)} to SRX (${targetModel || 'SRX'}) migration.${srxLicense ? ` Target license: ${srxLicense}.` : ''} Identify issues, suggest improvements, and flag any security concerns.`;

  return {
    system: systemPrompt,
    user: `${reviewType}

Target Model: ${targetModel || 'SRX'}${srxLicense ? `\nSubscription: ${srxLicense}` : ''}

Ruleset (${policies.length} policies):
${ruleSummary}

Zones: ${(intermediateConfig?.zones || []).map(z => z.name).join(', ')}
${configContext}
Provide a thorough analysis with specific, actionable recommendations. Use JSON code blocks for rule-specific changes.`,
  };
}

// ---------------------------------------------------------------------------
// Policy Translation (LLM-driven)
// ---------------------------------------------------------------------------

/**
 * Builds the prompt for translating source policies to SRX format.
 */
export function buildTranslationPrompt(intermediateConfig, targetModel, srxLicense) {
  const policies = intermediateConfig?.security_policies || [];
  const vendor = vendorLabel(intermediateConfig?.metadata?.source_vendor);
  const zones = (intermediateConfig?.zones || []).map(z => z.name);

  // Address objects summary for context
  const addresses = intermediateConfig?.addresses || [];
  const addressGroups = intermediateConfig?.address_groups || [];
  const addressSummary = addresses.length > 0
    ? `\n\nAddress Objects (${addresses.length}):\n${addresses.map(a => `  ${a.name}: ${a.ip}`).join('\n')}`
    : '';
  const groupSummary = addressGroups.length > 0
    ? `\n\nAddress Groups (${addressGroups.length}):\n${addressGroups.map(g => `  ${g.name}: [${g.members.join(', ')}]`).join('\n')}`
    : '';

  const licenseNote = srxLicense
    ? `\n\nIMPORTANT — Target SRX Subscription: ${srxLicense}
- Base (no subscriptions): Stateful FW, SSL B&I, Full Routing, VxLAN
- A1 (Advanced Data Protection): + AppSecure, IPS, SecIntel
- A2 (Advanced Edge Protection): + URL/Content filtering
- P1 (Premium Data Protection): A1 + ATP Cloud
- P2 (Premium Edge Protection): A2 + ATP Cloud
Flag features requiring a higher subscription than ${srxLicense} in _translation_notes.`
    : '';

  const sourceVendor = intermediateConfig?.metadata?.source_vendor || null;
  const systemPrompt = loadSystemPrompt('translate', sourceVendor) + licenseNote;

  // Strip internal metadata fields to reduce token usage
  const cleanPolicies = policies.map(p => {
    const clean = { ...p };
    delete clean._rule_index;
    delete clean._review_status;
    delete clean._llm_reviewed;
    // Remove all _srx_* internal flags
    for (const key of Object.keys(clean)) {
      if (key.startsWith('_srx_')) delete clean[key];
    }
    // Remove empty arrays/objects to save tokens
    if (clean.tags && clean.tags.length === 0) delete clean.tags;
    if (clean.security_profiles && Object.keys(clean.security_profiles).length === 0) delete clean.security_profiles;
    return clean;
  });
  const policyJson = JSON.stringify(cleanPolicies);

  // Include decryption rules for SSL Proxy mapping (PAN-OS only)
  const decryptionRules = intermediateConfig?.decryption_rules || [];
  const decryptionContext = decryptionRules.length > 0
    ? `\n\nPAN-OS SSL Decryption Rules (${decryptionRules.length}):\n${JSON.stringify(decryptionRules.filter(r => !r.disabled).map(r => ({
        name: r.name, src_zones: r.src_zones, dst_zones: r.dst_zones,
        src_addresses: r.src_addresses, dst_addresses: r.dst_addresses,
        services: r.services, url_categories: r.url_categories,
        action: r.action, decryption_type: r.decryption_type
      })))}\n\nFor each security rule whose traffic would match a decryption rule with action="decrypt", set _srx_decrypt: true and note the matching decryption rule in _translation_notes. For "no-decrypt" rules, note that traffic is explicitly excluded from decryption.`
    : '';

  // Build app mapping hints for LLM (deterministic starting points reduce hallucination)
  let appMappingHints = '';
  if (appMappingsLoaded() && sourceVendor && sourceVendor !== 'srx_healthcheck') {
    const uniqueApps = new Set();
    for (const p of policies) {
      for (const app of (p.applications || [])) {
        if (app && app !== 'any') uniqueApps.add(app);
      }
    }
    const hints = [];
    for (const app of uniqueApps) {
      const result = mapVendorApp(app, sourceVendor);
      if (result && result.confidence >= 0.7) {
        hints.push(`${app} → ${result.junosApp} (${result.confidence})`);
      }
    }
    if (hints.length > 0) {
      appMappingHints = `\n\nApp mapping hints (vendor → SRX/Junos equivalent, confidence):\n${hints.join('\n')}\nUse these as a starting point for application translation. Override if you know a better mapping.`;
    }
  }

  const isHealthCheck = (sourceVendor === 'srx_healthcheck');

  const licenseUserNote = srxLicense
    ? `\nSRX subscription: ${srxLicense} — ${isHealthCheck ? 'assess security profiles against this tier, flag features requiring a higher tier' : 'translate security profiles within this tier, flag features requiring a higher tier'} in _translation_notes.`
    : `\nSRX subscription: Base (none) — flag ALL advanced security features (IDP, UTM, EWF, ATP Cloud) as requiring a subscription upgrade in _translation_notes.`;

  const userMessage = isHealthCheck
    ? `Audit these ${policies.length} existing SRX security policies for best practices, compliance, and security posture.

Platform: Juniper SRX ${targetModel || ''}${licenseUserNote}
Available zones: ${zones.join(', ')}${addressSummary}${groupSummary}

Current policies (JSON):
${policyJson}

CRITICAL: Return ONLY a valid JSON array. No markdown fences, no explanation, no text before or after. Start with [ and end with ].`
    : `Translate these ${policies.length} security policies from ${vendor} to Juniper SRX (${targetModel || 'SRX'}).

Source vendor: ${vendor}
Target platform: Juniper SRX ${targetModel || ''}${licenseUserNote}
Available zones: ${zones.join(', ')}${addressSummary}${groupSummary}${decryptionContext}${appMappingHints}

Source policies (JSON):
${policyJson}

CRITICAL: Return ONLY a valid JSON array. No markdown fences, no explanation, no text before or after. Start with [ and end with ].`;

  return {
    system: systemPrompt,
    user: userMessage,
  };
}

/**
 * Parses the LLM translation response into a validated policy array.
 */
export function parseTranslationResponse(response) {
  let policies;
  const preview = (response || '').slice(0, 300);

  // Strategy 1: Extract JSON from markdown fences (```json ... ```)
  const fenceMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (fenceMatch) {
    try {
      policies = safeJsonParse(fenceMatch[1].trim());
    } catch { /* fall through */ }
  }

  // Strategy 2: Parse the entire response as JSON
  if (!policies) {
    try {
      policies = safeJsonParse(response.trim());
    } catch { /* fall through */ }
  }

  // Strategy 3: Find a JSON array starting with [ and ending with ]
  if (!policies) {
    const startIdx = response.indexOf('[');
    if (startIdx !== -1) {
      // Walk backwards from end to find the last ]
      const endIdx = response.lastIndexOf(']');
      if (endIdx > startIdx) {
        try {
          policies = safeJsonParse(response.slice(startIdx, endIdx + 1));
        } catch { /* fall through */ }
      }
    }
  }

  // Strategy 4: Truncated response — try to repair by closing open brackets
  if (!policies) {
    const startIdx = response.indexOf('[');
    if (startIdx !== -1) {
      let jsonStr = response.slice(startIdx);
      // Remove trailing text after the last complete object
      const lastBrace = jsonStr.lastIndexOf('}');
      if (lastBrace !== -1) {
        jsonStr = jsonStr.slice(0, lastBrace + 1) + ']';
        try {
          policies = safeJsonParse(jsonStr);
          console.warn('[translate] Repaired truncated JSON response — output may be incomplete.');
        } catch { /* fall through */ }
      }
    }
  }

  if (!policies) {
    throw new Error(
      'Could not parse LLM translation response as JSON.\n' +
      'Response preview: ' + preview + (response.length > 300 ? '...' : '') +
      '\n\nTip: The response may have been truncated. Try increasing Max Tokens in LLM Settings (8192+ recommended).'
    );
  }

  if (!Array.isArray(policies)) {
    throw new Error('LLM response was not an array of policies. Got: ' + typeof policies);
  }

  // Validate and normalize each policy
  return policies.map((p, i) => {
    if (!p.name) p.name = `translated-rule-${i + 1}`;
    if (!p.action) p.action = 'deny';

    // Normalize arrays
    p.src_zones = Array.isArray(p.src_zones) ? p.src_zones : (p.src_zones ? [p.src_zones] : ['any']);
    p.dst_zones = Array.isArray(p.dst_zones) ? p.dst_zones : (p.dst_zones ? [p.dst_zones] : ['any']);
    p.src_addresses = Array.isArray(p.src_addresses) ? p.src_addresses : (p.src_addresses ? [p.src_addresses] : ['any']);
    p.dst_addresses = Array.isArray(p.dst_addresses) ? p.dst_addresses : (p.dst_addresses ? [p.dst_addresses] : ['any']);
    p.applications = Array.isArray(p.applications) ? p.applications : (p.applications ? [p.applications] : []);
    p.services = Array.isArray(p.services) ? p.services : (p.services ? [p.services] : []);
    p.source_users = Array.isArray(p.source_users) ? p.source_users : (p.source_users ? [p.source_users] : []);

    // Normalize booleans
    p.log_start = !!p.log_start;
    p.log_end = p.log_end !== undefined ? !!p.log_end : true;
    p.disabled = !!p.disabled;

    // Map security_profiles (PAN-OS keys) → _srx_* boolean flags as safety net
    // The LLM prompt asks for _srx_* flags directly, but if PAN-OS keys survive
    // (virus, spyware, vulnerability, url-filtering, file-blocking, wildfire-analysis)
    // we still want the UI to show the correct subscriptions.
    const sp = p.security_profiles || {};
    if (sp.virus && p._srx_flow_av === undefined) p._srx_flow_av = true;
    if (sp.spyware && p._srx_antimalware === undefined) p._srx_antimalware = true;
    if (sp.vulnerability && p._srx_idp === undefined) p._srx_idp = true;
    if ((sp['url-filtering'] || sp['file-blocking']) && p._srx_content_security === undefined) p._srx_content_security = true;
    if (sp.secintel && p._srx_secintel === undefined) p._srx_secintel = true;
    // LLM-style keys (idp, utm, ssl_proxy) → _srx_* flags
    if (sp.idp && p._srx_idp === undefined) p._srx_idp = true;
    if (sp.utm && p._srx_content_security === undefined) p._srx_content_security = true;
    if (sp.ssl_proxy && p._srx_decrypt === undefined) p._srx_decrypt = true;

    // Ensure translation metadata
    p._translation_notes = p._translation_notes || '';
    p._review_status = 'llm_reviewed'; // Always force — LLM must not control review status
    p._rule_index = i;

    return p;
  });
}

/**
 * Safety net: apply _srx_decrypt to allow rules in zone-pairs covered by
 * PAN-OS decryption rules, if the LLM didn't already set the flag.
 */
function applyDecryptionSafetyNet(translatedRules, intermediateConfig) {
  const decryptionRules = intermediateConfig?.decryption_rules || [];
  if (decryptionRules.length === 0) return;

  // Build a set of zone-pairs that have decrypt action
  const decryptZonePairs = new Set();
  for (const dr of decryptionRules) {
    if (dr.action === 'decrypt' && !dr.disabled) {
      const srcZones = dr.src_zones?.length ? dr.src_zones : ['any'];
      const dstZones = dr.dst_zones?.length ? dr.dst_zones : ['any'];
      for (const sz of srcZones) {
        for (const dz of dstZones) {
          decryptZonePairs.add(`${sz}\u2192${dz}`);
        }
      }
    }
  }
  if (decryptZonePairs.size === 0) return;

  for (const rule of translatedRules) {
    if (rule._srx_decrypt || rule.disabled || rule.action === 'deny' || rule.action === 'reject') continue;
    const srcZones = rule.src_zones?.length ? rule.src_zones : ['any'];
    const dstZones = rule.dst_zones?.length ? rule.dst_zones : ['any'];
    let matched = false;
    for (const sz of srcZones) {
      for (const dz of dstZones) {
        if (decryptZonePairs.has(`${sz}\u2192${dz}`) || decryptZonePairs.has(`any\u2192${dz}`)
            || decryptZonePairs.has(`${sz}\u2192any`) || decryptZonePairs.has('any\u2192any')) {
          matched = true;
          break;
        }
      }
      if (matched) break;
    }
    if (matched) {
      rule._srx_decrypt = true;
      if (!rule._translation_notes?.includes('SSL')) {
        rule._translation_notes = (rule._translation_notes || '') +
          ' SSL Proxy enabled \u2014 matched PAN-OS decryption rule covering this zone pair.';
      }
    }
  }
}

/**
 * Translates source security policies to SRX format via LLM.
 * Automatically chunks large rulesets (>30 rules) into smaller batches.
 *
 * @param {object} intermediateConfig - The full parsed intermediate config
 * @param {string} targetModel - Target SRX model name
 * @param {string} srxLicense - Target subscription level
 * @param {function} [onProgress] - Optional callback: ({ phase, detail, chunk, totalChunks, promptTokens, responseTokens, elapsed })
 * @returns {Promise<Array>} - Array of translated SRX policy objects
 */
export async function translatePolicies(intermediateConfig, targetModel, srxLicense, onProgress) {
  const policies = intermediateConfig?.security_policies || [];
  if (policies.length === 0) {
    throw new Error('No security policies to translate.');
  }

  const CHUNK_SIZE = 25;
  const OVERLAP = 2;
  const MAX_TOKENS = 16384;
  const t0 = Date.now();
  let totalPromptTokens = 0;
  let totalResponseTokens = 0;

  const report = (data) => onProgress?.({ ...data, elapsed: Date.now() - t0 });

  if (policies.length <= 30) {
    // Single call for small rulesets
    report({ phase: 'building_prompt', detail: `Preparing ${policies.length} rules for translation`, chunk: 1, totalChunks: 1, promptTokens: 0, responseTokens: 0 });
    const { system, user } = buildTranslationPrompt(intermediateConfig, targetModel, srxLicense);
    const promptEstimate = Math.round((system.length + user.length) / 4);
    totalPromptTokens = promptEstimate;
    report({ phase: 'calling_llm', detail: `Sending to LLM (~${promptEstimate.toLocaleString()} prompt tokens)`, chunk: 1, totalChunks: 1, promptTokens: promptEstimate, responseTokens: 0 });
    const response = await _callLLM(user, system, MAX_TOKENS);
    const responseEstimate = Math.round(response.length / 4);
    totalResponseTokens = responseEstimate;
    if (import.meta.env?.DEV) {
      console.log('[translate] Raw LLM response length:', response.length, 'chars');
    }
    report({ phase: 'parsing_response', detail: `Parsing LLM response (~${responseEstimate.toLocaleString()} tokens)`, chunk: 1, totalChunks: 1, promptTokens: promptEstimate, responseTokens: responseEstimate });
    const result = parseTranslationResponse(response);
    applyDecryptionSafetyNet(result, intermediateConfig);
    report({ phase: 'complete', detail: `Translated ${result.length} rules`, chunk: 1, totalChunks: 1, promptTokens: totalPromptTokens, responseTokens: totalResponseTokens });
    return result;
  }

  // Chunked translation for large rulesets
  const chunks = [];
  for (let i = 0; i < policies.length; i += CHUNK_SIZE - OVERLAP) {
    const end = Math.min(i + CHUNK_SIZE, policies.length);
    chunks.push({ start: i, end, policies: policies.slice(i, end) });
    if (end >= policies.length) break;
  }

  report({ phase: 'building_prompt', detail: `Splitting ${policies.length} rules into ${chunks.length} chunks`, chunk: 0, totalChunks: chunks.length, promptTokens: 0, responseTokens: 0 });

  const allTranslated = [];
  const seenNames = new Set();

  for (let ci = 0; ci < chunks.length; ci++) {
    const chunk = chunks[ci];
    const chunkConfig = {
      ...intermediateConfig,
      security_policies: chunk.policies,
    };
    const { system, user } = buildTranslationPrompt(chunkConfig, targetModel, srxLicense);

    // Add chunk context
    const chunkUser = `${user}\n\nNote: This is chunk ${ci + 1}/${chunks.length} (rules ${chunk.start + 1}–${chunk.end} of ${policies.length} total). Translate all rules in this chunk.`;

    const promptEstimate = Math.round((system.length + chunkUser.length) / 4);
    totalPromptTokens += promptEstimate;
    report({ phase: 'calling_llm', detail: `Chunk ${ci + 1}/${chunks.length}: rules ${chunk.start + 1}–${chunk.end}`, chunk: ci + 1, totalChunks: chunks.length, promptTokens: totalPromptTokens, responseTokens: totalResponseTokens });

    const response = await _callLLM(chunkUser, system, MAX_TOKENS);
    const responseEstimate = Math.round(response.length / 4);
    totalResponseTokens += responseEstimate;
    if (import.meta.env?.DEV) {
      console.log(`[translate] Chunk ${ci + 1}/${chunks.length} response length:`, response.length, 'chars');
    }

    report({ phase: 'parsing_response', detail: `Parsing chunk ${ci + 1}/${chunks.length} response`, chunk: ci + 1, totalChunks: chunks.length, promptTokens: totalPromptTokens, responseTokens: totalResponseTokens });
    const translated = parseTranslationResponse(response);

    // Deduplicate overlap rules by name
    for (const rule of translated) {
      if (!seenNames.has(rule.name)) {
        seenNames.add(rule.name);
        allTranslated.push(rule);
      }
    }
  }

  // Re-index all rules sequentially
  const result = allTranslated.map((p, i) => ({ ...p, _rule_index: i }));
  applyDecryptionSafetyNet(result, intermediateConfig);
  report({ phase: 'complete', detail: `Translated ${result.length} rules from ${policies.length} source rules`, chunk: chunks.length, totalChunks: chunks.length, promptTokens: totalPromptTokens, responseTokens: totalResponseTokens });
  return result;
}

// ---------------------------------------------------------------------------
// LLM Rule Grouping — Security Director-style logical grouping
// ---------------------------------------------------------------------------

const RULE_GROUPING_SYSTEM_PROMPT = `You are an expert firewall policy analyst. Your task is to organize a flat list of firewall security policies into logical groups, similar to how Juniper Security Director or Panorama organizes policies.

## Grouping Strategy

Analyze the rules and group them by their **business intent**. Consider these signals:

1. **Zone pair patterns** — Rules with the same source→destination zone pair often serve the same purpose
2. **Application/service similarity** — Rules allowing the same applications (web, DNS, email, VPN) belong together
3. **Naming conventions** — Rule names often encode intent (e.g., "INET-ACCESS-*", "DC-EAST-WEST-*", "VPN-*")
4. **Address patterns** — Rules referencing the same address objects/groups serve related functions
5. **Action similarity** — Deny/cleanup rules form their own group; permit rules group by purpose
6. **Description keywords** — Parse descriptions for business context

## Group Naming

- Use clear, concise business-oriented names: "Internet Access", "East-West Data Center", "Management Access", "VPN Traffic", "DNS Services", "Cleanup Deny Rules"
- Avoid generic names like "Group 1" or "Miscellaneous"
- Aim for 3-8 groups for typical rulesets. Fewer for small rulesets (<15 rules), more for large ones (100+)
- Every rule must be assigned to exactly one group

## Output Format

Return ONLY a JSON array, no other text. Each element:

\`\`\`json
[
  {
    "group_name": "Internet Access",
    "rule_indices": [0, 1, 4, 7],
    "reasoning": "Rules permitting outbound web/DNS/email traffic from trust to untrust zone"
  },
  {
    "group_name": "Cleanup Rules",
    "rule_indices": [14, 15],
    "reasoning": "Implicit deny-all rules at the end of each zone pair"
  }
]
\`\`\`

Rules are 0-indexed. Every rule index from the input must appear exactly once across all groups.`;

/**
 * Builds a compact rule summary for the grouping prompt.
 */
function buildGroupingRuleSummary(policies) {
  return policies.map((r, i) => {
    const src = (r.src_zones || r.source_zones || []).join(',') || 'any';
    const dst = (r.dst_zones || r.destination_zones || []).join(',') || 'any';
    const srcAddr = (r.src_addresses || r.source_addresses || []).join(',') || 'any';
    const dstAddr = (r.dst_addresses || r.destination_addresses || []).join(',') || 'any';
    const apps = (r.applications || []).join(',') || 'any';
    const svcs = (r.services || []).join(',') || 'any';
    const flags = [
      r.disabled ? 'DISABLED' : '',
      r._implicit || r.added_by_fpic ? 'IMPLICIT' : '',
    ].filter(Boolean).join(' ');
    const desc = r.description ? ` "${r.description}"` : '';
    return `${i}. [${r.action}] "${r.name}" ${src}->${dst} src=${srcAddr} dst=${dstAddr} apps=${apps} svc=${svcs}${desc} ${flags}`.trim();
  }).join('\n');
}

/**
 * Parses the LLM grouping response, extracting JSON from markdown fences if needed.
 */
function parseGroupingResponse(response, ruleCount) {
  // Try to extract JSON from markdown code fence
  let jsonStr = response;
  const fenceMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (fenceMatch) {
    jsonStr = fenceMatch[1].trim();
  } else {
    // Try to find raw JSON array
    const arrayMatch = response.match(/\[\s*\{[\s\S]*\}\s*\]/);
    if (arrayMatch) {
      jsonStr = arrayMatch[0];
    }
  }

  const groups = safeJsonParse(jsonStr);
  if (!Array.isArray(groups)) {
    throw new Error('LLM response is not a JSON array');
  }

  // Validate structure
  const allIndices = new Set();
  for (const g of groups) {
    if (!g.group_name || !Array.isArray(g.rule_indices)) {
      throw new Error(`Invalid group structure: ${JSON.stringify(g).slice(0, 100)}`);
    }
    for (const idx of g.rule_indices) {
      if (typeof idx !== 'number' || idx < 0 || idx >= ruleCount) {
        throw new Error(`Invalid rule index ${idx} (ruleset has ${ruleCount} rules)`);
      }
      allIndices.add(idx);
    }
  }

  // Check for unassigned rules — assign to "Ungrouped" if any
  if (allIndices.size < ruleCount) {
    const missing = [];
    for (let i = 0; i < ruleCount; i++) {
      if (!allIndices.has(i)) missing.push(i);
    }
    if (missing.length > 0) {
      groups.push({
        group_name: 'Ungrouped',
        rule_indices: missing,
        reasoning: 'Rules not assigned by the LLM analysis',
      });
    }
  }

  return groups;
}

/**
 * Requests LLM-powered rule grouping for a set of security policies.
 *
 * @param {Array} policies - Security policies array from intermediate config
 * @param {Function} [onProgress] - Progress callback: ({ phase, detail, chunk, totalChunks })
 * @returns {Promise<Array<{group_name: string, rule_indices: number[], reasoning: string}>>}
 */
export async function groupPolicies(policies, onProgress) {
  if (!policies || policies.length === 0) {
    throw new Error('No security policies to group.');
  }

  const CHUNK_SIZE = 50; // Grouping can handle larger chunks (less output per rule)
  const MAX_TOKENS = 8192;
  const t0 = Date.now();
  const report = (data) => onProgress?.({ ...data, elapsed: Date.now() - t0 });

  if (policies.length <= 60) {
    // Single call for small-to-medium rulesets
    const ruleSummary = buildGroupingRuleSummary(policies);
    const userPrompt = `Analyze and group these ${policies.length} firewall rules:\n\n${ruleSummary}`;

    report({ phase: 'calling_llm', detail: `Grouping ${policies.length} rules`, chunk: 1, totalChunks: 1 });
    const response = await _callLLM(userPrompt, RULE_GROUPING_SYSTEM_PROMPT, MAX_TOKENS);
    report({ phase: 'parsing_response', detail: 'Parsing grouping response', chunk: 1, totalChunks: 1 });

    const groups = parseGroupingResponse(response, policies.length);
    report({ phase: 'complete', detail: `Created ${groups.length} groups`, chunk: 1, totalChunks: 1 });
    return groups;
  }

  // Chunked grouping for large rulesets
  // Phase 1: Get groups for each chunk independently
  const chunks = [];
  for (let i = 0; i < policies.length; i += CHUNK_SIZE) {
    const end = Math.min(i + CHUNK_SIZE, policies.length);
    chunks.push({ start: i, end, policies: policies.slice(i, end) });
  }

  report({ phase: 'building_prompt', detail: `Splitting ${policies.length} rules into ${chunks.length} chunks`, chunk: 0, totalChunks: chunks.length + 1 });

  // Collect per-chunk group assignments (using global indices)
  const perChunkGroups = [];

  for (let ci = 0; ci < chunks.length; ci++) {
    const chunk = chunks[ci];
    const ruleSummary = buildGroupingRuleSummary(chunk.policies);
    const userPrompt = `Analyze and group these ${chunk.policies.length} firewall rules (rules ${chunk.start}–${chunk.end - 1} of ${policies.length} total):\n\n${ruleSummary}`;

    report({ phase: 'calling_llm', detail: `Chunk ${ci + 1}/${chunks.length}: rules ${chunk.start}–${chunk.end - 1}`, chunk: ci + 1, totalChunks: chunks.length + 1 });
    const response = await _callLLM(userPrompt, RULE_GROUPING_SYSTEM_PROMPT, MAX_TOKENS);

    const chunkGroups = parseGroupingResponse(response, chunk.policies.length);
    // Remap local indices to global indices
    for (const g of chunkGroups) {
      g.rule_indices = g.rule_indices.map(idx => idx + chunk.start);
    }
    perChunkGroups.push(...chunkGroups);
  }

  // Phase 2: Merge groups with similar names across chunks
  report({ phase: 'merging', detail: `Merging ${perChunkGroups.length} chunk groups`, chunk: chunks.length + 1, totalChunks: chunks.length + 1 });

  const mergedMap = new Map(); // normalized_name → { group_name, rule_indices[], reasoning }
  for (const g of perChunkGroups) {
    const key = g.group_name.toLowerCase().replace(/[^a-z0-9]/g, '-');
    if (mergedMap.has(key)) {
      const existing = mergedMap.get(key);
      existing.rule_indices.push(...g.rule_indices);
      if (g.reasoning && !existing.reasoning.includes(g.reasoning)) {
        existing.reasoning += '; ' + g.reasoning;
      }
    } else {
      mergedMap.set(key, { ...g });
    }
  }

  const groups = Array.from(mergedMap.values());
  report({ phase: 'complete', detail: `Created ${groups.length} groups from ${policies.length} rules`, chunk: chunks.length + 1, totalChunks: chunks.length + 1 });
  return groups;
}

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
// Default System Prompt
// ---------------------------------------------------------------------------

export const DEFAULT_RULE_SYSTEM_PROMPT = `You are an expert firewall policy engineer specializing in migrations to Juniper SRX. You support Junos SRX as source platforms. You provide concise, actionable best-practice suggestions grounded in specific Junos CLI syntax.

## Zone Architecture
- Strict zone segmentation: trust, untrust, dmz, management, and dedicated partner/vendor zones
- host-inbound-traffic restricted per zone — only allow required protocols (e.g., ssh/ping on management; nothing unnecessary on untrust)
- Never bind management interface (fxp0) to a transit zone
- Every zone should have a screen profile applied for DoS protection
- Prefer global address-book for simplicity — addresses available across all zones and NAT rules

## Policy Design
- Default deny-all cleanup rule per zone pair: then { deny; log { session-init; } }
- Most specific rules first, broadest last — SRX evaluates top-down, first match wins
- Use unified policies (Junos 18.2+) with application identification for NGFW capability
- Avoid any/any/any open rules — flag as critical security issues
- Descriptive names (max 63 chars, alphanumeric + hyphen + underscore, no spaces)
- Add description on every rule explaining business justification
- Review disabled/deactivated rules for removal — audit flags and configuration clutter
- Use address-sets and application-sets to reduce rule count

## Logging
- log session-close on all permit rules (captures byte/packet counts after session ends)
- log session-init on all deny/reject rules (captures blocked connection attempts)
- Avoid enabling both session-init AND session-close on same rule — performance impact
- Forward to remote syslog over TLS for encryption in transit
- Use structured syslog (sd-syslog) for SIEM ingestion
- Always set source-address on syslog forwarding to identify the SRX device

## Security Profiles
### IDP
- Use predefined policy templates as starting point (Recommended, DMZ_Services)
- Apply IDP on trust→untrust and dmz→untrust zone pairs minimum
- Install signature database: request security idp security-package install
- For Junos 18.2+, assign IDP policies per rule via unified policies

### UTM
- Antivirus on HTTP, SMTP, FTP, IMAP protocols
- Web filtering (EWF or local) on outbound web traffic
- Content filtering for file-type blocking
- Anti-spam on inbound SMTP
- Bundle profiles into UTM policy, reference with: then permit { application-services { utm-policy <name>; } }

### Application Firewall / AppID
- Prefer AppID over port-only matching
- SSL proxy may be required to identify encrypted applications
- For Junos 18.2+, use unified policies instead of legacy AppFW rule-sets

### SecIntel (requires A1+ subscription)
- Provides threat intelligence feeds: C&C IPs, infected hosts, GeoIP, malicious URLs
- Requires ATP Cloud enrollment for full functionality (P1/P2)

## NAT
- SRX NAT order of operations: Static NAT and Destination NAT before security policy; Source NAT after policy
- Security policies must reference the real (post-NAT) IP for destination NAT, not the translated IP
- Proxy ARP is mandatory for destination/static NAT when translated IP is not on an SRX interface
- Static NAT is bidirectional and has highest priority
- Use rule-set organization by zone pair for clarity
- Interface-based source NAT (then source-nat interface) for simple internet access

## VPN / IPsec
- Prefer IKEv2 over IKEv1 — fewer exchanges, better DoS resistance, faster SA setup
- Enable Perfect Forward Secrecy (PFS) — minimum group14 (DH-2048)
- Use strong encryption: AES-256-GCM for IKE and IPsec; avoid 3DES, DES, MD5
- Route-based VPNs (st0 tunnels) preferred over policy-based for flexibility
- Ensure st0 tunnel unit is in the correct security zone
- Enable Dead Peer Detection: set security ike gateway <name> dead-peer-detection
- Proxy IDs / traffic selectors must match on both peers — common migration pitfall
- Recommended IKE: sha-256+, aes-256-gcm, group20 (group14 minimum)
- Recommended IPsec: esp, aes-256-gcm, lifetime 3600s

## Screens / DDoS Protection
- Screens are processed before security policy — minimal performance impact
- Apply per zone; untrust needs strictest settings
- Recommended minimums: tcp syn-flood (alarm 1024, attack 200, dest 2048), land, winnuke, syn-frag; udp flood (threshold 1000); icmp ping-death, flood (threshold 1000); ip bad-option, source-route-option, spoofing

## HA / Chassis Cluster
- Both nodes must have identical hardware, software versions, and license keys
- Redundancy group 0 for routing engine; group 1+ for interface (reth) redundancy
- Active/passive for simplicity; active/active only when traffic engineering requires it
- Control link and fabric link must be on dedicated physical ports

## Routing
- Static routes: set routing-options static route <dest> next-hop <nh>
- VRF / routing-instances for network segmentation
- Logical systems for multi-vsys migration from PAN-OS (multiple routing instances, advanced routing)
- Tenant systems for VDOM migration from FortiGate (one routing instance per tenant, scales to more tenants)

## Vendor-Specific Migration Pitfalls

### PAN-OS → SRX
- "application-default" → verify SRX AppID coverage; unmapped apps need custom application definitions
- Security profile groups → individual SRX UTM/IDP policies (no 1:1 group concept)
- Tags → preserve as description fields or comments
- "drop" → "deny" (silent drop), "reset-client/server/both" → "reject"
- Disabled rules → "deactivate" statement
- PAN-OS vsys → SRX logical-system (if multi-vsys)

### FortiGate → SRX
- "accept" → "permit", "deny" → "deny"
- VIP objects (DNAT) → SRX destination NAT rule-sets with proxy-ARP
- IP pools (SNAT) → SRX source NAT rule-sets with pools
- UTM profiles (AV, web-filter, IPS, app-control) → SRX UTM policies + IDP policies
- VDOM → SRX logical-system or tenant-system
- internet-service-id has no direct SRX equivalent — decompose to IP/port
- FQDN addresses → SRX dns-name; wildcard-fqdn not supported on SRX

### Cisco ASA/FTD → SRX
- ACL-based model (interface + direction + ACL) → SRX zone-based model (from-zone/to-zone)
- Security levels determine implicit trust — SRX has no implicit trust, every zone pair needs explicit policy
- nameif + security-level → explicit SRX security zones
- object-group → SRX address-set / application-set
- Twice-NAT (manual NAT) → SRX static NAT with source + destination translation
- Auto-NAT (object NAT) → SRX source/destination NAT rule-sets
- inspect fixups → SRX ALG configurations
- threat-detection → SRX screen options

### SRX → SRX
- Validate deprecated syntax (zone-based vs global address-book)
- Check AppID signature compatibility between Junos versions
- Verify chassis cluster compatibility if upgrading hardware

## Rule Shadowing
- A shadowed rule never matches because a broader rule above already handles all matching packets
- Flag: fully shadowed, partially shadowed, redundant, and contradictory rules
- Resolution: place most specific rules higher; remove fully shadowed; merge redundant
- Same zones + overlapping addresses + overlapping services but different action = contradiction

## Compliance
- PCI DSS v4.0 (mandatory since March 2025): explicit deny-all (1.2.1), all allowed services/ports must have documented business need (1.2.5), review configs at least every 6 months (1.2.7), inbound/outbound CDE traffic limited to necessity (1.3.1/1.3.2)
- NIST SP 800-41r1: segment by sensitivity, log all denied traffic, annual review, test rules before deployment, document every rule with business justification
- CIS Juniper OS Benchmark v2.1.0: disable unused services, restrict management access, enforce password complexity, NTP with auth, SNMP v3 only`;

// Backwards-compatible alias
export const DEFAULT_SYSTEM_PROMPT = DEFAULT_RULE_SYSTEM_PROMPT;

// ---------------------------------------------------------------------------
// Full-Ruleset Review System Prompt
// ---------------------------------------------------------------------------

export const DEFAULT_FULL_REVIEW_SYSTEM_PROMPT = `You are an expert firewall policy engineer specializing in migrations to Juniper SRX. You support Junos SRX as source platforms. You provide concise, actionable best-practice suggestions grounded in specific Junos CLI syntax.

## Your Review Process

Analyze the entire configuration holistically — policies, zones, objects, NAT, routing — and identify:

### 1. Security Posture
- **Default deny**: Every zone pair MUST end with a deny-all cleanup rule (then { deny; log { session-init; } })
- **Overly permissive rules**: Flag any/any/any rules, source=any to sensitive zones, or action=permit with no application restriction
- **Zone segmentation**: Verify proper isolation between trust, untrust, dmz, management zones
- **Management access**: fxp0 must not be in a transit zone; management zone should only allow ssh/https from specific sources
- **Disabled rules**: Flag for removal or justification — they add clutter and audit risk

### 2. Logging & Visibility
- **Permit rules**: Must have \`log { session-close; }\` to capture byte/packet counts
- **Deny/reject rules**: Must have \`log { session-init; }\` to capture blocked attempts
- **Avoid both**: Do not enable session-init AND session-close on the same rule — performance impact
- **Count**: Recommend enabling count on high-traffic rules for monitoring

### 3. Rule Ordering & Optimization
- **Most specific first**: SRX evaluates top-down, first match wins — specific rules must precede broad ones
- **Shadowed rules**: Identify rules that can never match because a broader rule above handles all their traffic
- **Redundant rules**: Flag rules with identical match criteria that can be consolidated
- **Contradictions**: Same zone pair + overlapping addresses + different actions = conflict

### 4. Application & Service Usage
- **AppID over ports**: Prefer Junos application identifiers (junos-http, junos-https, junos-dns-udp) over raw port numbers
- **Unmapped applications**: Flag custom or unknown application names that may need definitions
- **Application sets**: Group related apps into application-sets to reduce rule count

### 5. Address Objects & Groups
- **Naming**: Descriptive names, max 63 chars, alphanumeric + hyphen + underscore
- **Address sets**: Group related addresses to simplify policies
- **Unused objects**: Flag objects not referenced by any policy or NAT rule
- **Descriptions**: Every object should have a description for audit purposes

### 6. NAT Configuration
- **Source NAT**: Verify interface NAT or pool NAT for outbound traffic
- **Destination NAT**: Verify proxy-ARP is configured for translated IPs not on SRX interfaces
- **Policy references**: Security policies must reference real (post-DNAT) IPs, not translated IPs
- **Rule-set organization**: Organize by zone pair for clarity

### 7. Zone & Screen Configuration
- **Screen profiles**: Every zone (especially untrust) should have a screen profile for DoS protection
- **Recommended screens**: tcp syn-flood, land, winnuke, syn-frag; udp flood; icmp ping-death, flood; ip bad-option, source-route-option, spoofing
- **Host-inbound-traffic**: Restrict per zone — only allow required protocols (ssh/ping on management; nothing on untrust unless needed)

### 8. HA & Resilience
- **Chassis cluster**: Both nodes identical hardware/software/licenses
- **Redundancy groups**: RG0 for RE, RG1+ for reth interfaces
- **MNHA**: If applicable, verify ICL, liveness detection, services-redundancy-group config

### 9. Compliance
- **PCI DSS v4.0**: Explicit deny-all (1.2.1), documented business need for every allowed service (1.2.5), review every 6 months (1.2.7)
- **NIST SP 800-41r1**: Segment by sensitivity, log all denied traffic, document every rule
- **CIS Juniper OS Benchmark**: Disable unused services, NTP with auth, SNMP v3 only

## Response Format

When suggesting changes to specific rules, you MUST include a JSON code block so the user can click to accept the change:

\`\`\`json
{"rule_name": "the-rule-name", "field": "field_name", "current": "current_value", "suggested": "new_value", "reason": "Why this change is recommended"}
\`\`\`

Valid fields: name, action, description, src_zones, dst_zones, src_addresses, dst_addresses, applications, services, log_start, log_end, disabled, profile_group, tags

For array fields use JSON arrays: ["value1", "value2"]
For boolean fields use true/false

You may include multiple JSON blocks in your response, interspersed with explanatory text. Group related suggestions together under clear headings.

## Guidelines
- Be specific — reference rules by name, not just "some rules"
- Prioritize findings: critical security issues first, then best practices, then optimization
- For greenfield configs, also check for completeness — are there missing zone pairs, missing cleanup rules, or gaps in coverage?
- Always explain WHY a change is recommended, not just what to change
- If the configuration looks solid, say so — don't invent problems`;

// ---------------------------------------------------------------------------
// Greenfield Interview System Prompt
// ---------------------------------------------------------------------------

export const DEFAULT_GREENFIELD_SYSTEM_PROMPT = `You are an expert Juniper SRX firewall configuration engineer conducting a guided interview to build a new SRX configuration from scratch. You ask clear, structured questions and progressively build the configuration as the user answers.

## Interview Structure

### Phase 1 — Use Case Discovery (ask these first)
1. **Deployment use case**: Ask what type of deployment this is:
   - Branch Office (small office, internet access, maybe VPN to HQ)
   - Data Center (server protection, multi-tier architecture, high throughput)
   - Campus/Enterprise Edge (multiple VLANs, user segmentation, guest access)
   - Remote/Teleworker (VPN concentrator, split tunnel decisions)
   - Cloud Gateway (cloud connectivity, hybrid network)

2. **Follow-up questions based on use case:**
   - **Branch**: How many users? Internet-only or site-to-site VPN? Guest WiFi needed? SD-WAN?
   - **Data Center**: North-south only or east-west micro-segmentation? How many server tiers? DMZ needed?
   - **Campus Edge**: Number of VLANs/segments? Guest network? 802.1X?
   - **Remote/Teleworker**: Always-on VPN? Split tunnel? Local internet breakout?
   - **Cloud Gateway**: Which cloud providers? Overlay tunnels?

3. **Connectivity**: ISP count, link types, public IPs, routing protocol (BGP/static)

### Phase 2 — Configuration Building
Walk through each section, suggesting defaults based on the use case:

4. **Zones** — Pre-suggest zones based on use case:
   - Branch → trust, untrust, guest (if WiFi)
   - Data Center → trust, untrust, dmz, management
   - Campus → trust, untrust, guest, management, server
   - All → management zone for device admin

5. **Interfaces** — Ask about interface assignments per zone, IP addressing

6. **Address Objects** — Internal subnets, servers, address groups

7. **Security Policies** — Suggest baseline policies:
   - Default deny-all cleanup rule per zone pair
   - Allow outbound web (trust → untrust)
   - Allow DNS/NTP basics
   - Management access policies

8. **NAT** — Source NAT for internet, destination NAT for public services

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

\`\`\`json
{"action": "add_zone", "data": {"name": "untrust", "description": "External untrusted network (internet)"}}
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
{"action": "add_policy", "data": {"name": "policy-name", "src_zones": ["trust"], "dst_zones": ["untrust"], "src_addresses": ["any"], "dst_addresses": ["any"], "applications": ["junos-http", "junos-https"], "services": ["any"], "action": "allow", "log_start": false, "log_end": true, "description": "Allow outbound web"}}
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

## Rules
- Ask ONE question at a time (or a small related group)
- After each answer, emit the relevant JSON action blocks
- Explain what you're configuring and why
- Use Junos-standard application names (junos-http, junos-https, junos-dns-udp, junos-dns-tcp, junos-ssh, junos-ping, junos-ntp, junos-bgp, junos-ospf, etc.)
- Always include a description on policies and objects
- Follow SRX best practices: default-deny, least privilege, proper logging
- At the end, summarize what was built and suggest any remaining items`;

// ---------------------------------------------------------------------------
// System Prompt Loader
// ---------------------------------------------------------------------------

/**
 * Loads the system prompt from localStorage or falls back to the default.
 * @param {'rule'|'fullReview'|'greenfield'} [type='rule'] - Which prompt to load
 */
export function loadSystemPrompt(type = 'rule') {
  const defaults = {
    rule: DEFAULT_RULE_SYSTEM_PROMPT,
    fullReview: DEFAULT_FULL_REVIEW_SYSTEM_PROMPT,
    greenfield: DEFAULT_GREENFIELD_SYSTEM_PROMPT,
  };
  const keys = {
    rule: 'ruleSystemPrompt',
    fullReview: 'fullReviewSystemPrompt',
    greenfield: 'greenfieldSystemPrompt',
  };

  try {
    const saved = localStorage.getItem('llm-settings');
    if (saved) {
      const settings = JSON.parse(saved);
      const key = keys[type] || keys.rule;
      const prompt = settings[key];
      if (prompt && prompt.trim()) return prompt;
      // Backwards compat: old systemPrompt field → rule prompt
      if (type === 'rule' && settings.systemPrompt && settings.systemPrompt.trim()) {
        return settings.systemPrompt;
      }
    }
  } catch { /* ignore */ }
  return defaults[type] || DEFAULT_RULE_SYSTEM_PROMPT;
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
  const needsKey = !['ollama', 'lmstudio'].includes(settings.provider);
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

async function callOllama(settings, userPrompt, systemPrompt) {
  const baseUrl = settings.baseUrl || 'http://localhost:11434';

  const messages = [];
  if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
  messages.push({ role: 'user', content: userPrompt });

  const response = await fetch(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: settings.model || 'llama3',
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
  const baseUrl = settings.baseUrl || 'http://localhost:1234';

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

  const messages = [];
  if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
  messages.push({ role: 'user', content: userPrompt });

  const headers = { 'Content-Type': 'application/json' };
  if (settings.apiKey) {
    headers['Authorization'] = `Bearer ${settings.apiKey}`;
  }

  const response = await fetch(`${settings.baseUrl}/v1/chat/completions`, {
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

async function callOllamaChat(settings, messages, systemPrompt) {
  const baseUrl = settings.baseUrl || 'http://localhost:11434';

  const allMessages = [];
  if (systemPrompt) allMessages.push({ role: 'system', content: systemPrompt });
  allMessages.push(...messages.map(m => ({ role: m.role, content: m.content })));

  const response = await fetch(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: settings.model || 'llama3',
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
  const baseUrl = settings.baseUrl || 'http://localhost:1234';

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

  const allMessages = [];
  if (systemPrompt) allMessages.push({ role: 'system', content: systemPrompt });
  allMessages.push(...messages.map(m => ({ role: m.role, content: m.content })));

  const headers = { 'Content-Type': 'application/json' };
  if (settings.apiKey) {
    headers['Authorization'] = `Bearer ${settings.apiKey}`;
  }

  const response = await fetch(`${settings.baseUrl}/v1/chat/completions`, {
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
    if (saved) return JSON.parse(saved);
  } catch { /* ignore */ }
  return {};
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
    default: return sourceVendor || 'firewall';
  }
}

/**
 * Builds a prompt asking the LLM to review a security rule (legacy free-text).
 */
export function buildRuleSuggestionPrompt(rule, targetModel, zones, sourceVendor) {
  const zoneList = (zones || []).map(z => z.name).join(', ');
  const vendor = vendorLabel(sourceVendor);
  return {
    system: loadSystemPrompt('rule'),
    user: `Review this firewall security rule for a ${vendor} to SRX (${targetModel || 'SRX'}) migration and suggest improvements:

Rule: "${rule.name}"
  Action: ${rule.action}
  From zones: ${rule.src_zones?.join(', ') || 'any'}
  To zones: ${rule.dst_zones?.join(', ') || 'any'}
  Source addresses: ${rule.src_addresses?.join(', ') || 'any'}
  Destination addresses: ${rule.dst_addresses?.join(', ') || 'any'}
  Applications: ${rule.applications?.join(', ') || 'any'}
  Services: ${rule.services?.join(', ') || 'any'}
  Logging: start=${rule.log_start}, end=${rule.log_end}
  Disabled: ${rule.disabled}
  ${rule.profile_group ? `Security profile: ${rule.profile_group}` : ''}
  ${rule.tags?.length ? `Tags: ${rule.tags.join(', ')}` : ''}

Available zones: ${zoneList}

Provide 2-4 specific, actionable suggestions for this rule. Focus on security best practices and SRX conversion considerations.`,
  };
}

/**
 * Builds a structured rule suggestion prompt that instructs the LLM to respond with JSON.
 */
export function buildStructuredRuleSuggestionPrompt(rule, targetModel, zones, srxLicense, srxContext, sourceVendor) {
  const zoneList = (zones || []).map(z => z.name).join(', ');
  const systemPrompt = loadSystemPrompt('rule');

  const licenseContext = srxLicense ? `

SUBSCRIPTION CONTEXT:
The target SRX subscription: ${srxLicense}
- Base (no subscriptions): Stateful FW, SSL B&I, Full Routing, VxLAN included
- A1 (Advanced Data Protection): Base + SDC, AppSecure, IPS, & SecIntel
- A2 (Advanced Edge Protection): Base, A1 subs, and URL + Content filtering
- P1 (Premium Data Protection): Base, A1 subs, and ATP Cloud
- P2 (Premium Edge Protection): Base, A2 subs, and ATP Cloud
If this rule uses security features requiring a higher subscription than ${srxLicense}, flag this in your analysis and suggest alternatives available at the ${srxLicense} subscription.` : '';

  // Build security profiles summary
  const profileEntries = Object.entries(rule.security_profiles || {});
  const profileSummary = profileEntries.length > 0
    ? profileEntries.map(([t, n]) => `${t}=${n}`).join(', ')
    : rule.profile_group || '(none)';

  return {
    system: systemPrompt + `

IMPORTANT: You MUST respond with ONLY valid JSON in the exact format below. No markdown fences, no extra text.

{
  "analysis": "Brief 1-2 sentence review of the rule",
  "suggestions": [
    {
      "field": "field_name",
      "current": "current_value",
      "suggested": "new_value",
      "reason": "Why this change is recommended"
    }
  ],
  "notes": [
    "Informational observation or migration note that does not require a field change"
  ],
  "verdict": "needs_changes" or "looks_good"
}

Use "suggestions" ONLY for actionable field changes the user should apply to the rule.
Use "notes" for informational observations, migration caveats, best-practice reminders, or anything that does not map to a specific field change. Notes will be saved as comments in the SRX config output.

Valid field names for suggestions and their types:
- name (string), action (string: allow/deny/drop/reject), description (string)
- src_zones (array), dst_zones (array), src_addresses (array), dst_addresses (array)
- applications (array), services (array)
- log_start (boolean), log_end (boolean), disabled (boolean)
- profile_group (string), tags (array)

For array fields, use JSON arrays like ["value1", "value2"].
For boolean fields, use true or false (no quotes).
Both "suggestions" and "notes" arrays may be empty if nothing applies.` + licenseContext,

    user: `Review this firewall security rule being migrated from ${vendorLabel(sourceVendor)} to SRX (${targetModel || 'SRX'})${srxLicense ? ` (license: ${srxLicense})` : ''}:

=== ORIGINAL ${vendorLabel(sourceVendor).toUpperCase()} RULE ===
Rule: "${rule.name}"
  Action: ${rule.action}
  From zones: ${(rule.src_zones || []).join(', ') || 'any'}
  To zones: ${(rule.dst_zones || []).join(', ') || 'any'}
  Source addresses: ${(rule.src_addresses || []).join(', ') || 'any'}${rule.negate_source ? ' [NEGATED — match all EXCEPT these]' : ''}
  Destination addresses: ${(rule.dst_addresses || []).join(', ') || 'any'}${rule.negate_destination ? ' [NEGATED — match all EXCEPT these]' : ''}
  Applications: ${(rule.applications || []).join(', ') || 'any'}
  Services: ${(rule.services || []).join(', ') || 'any'}
  Logging: start=${rule.log_start}, end=${rule.log_end}
  Disabled: ${rule.disabled}
  Description: ${rule.description || '(none)'}
  Security profiles: ${profileSummary}${rule.profile_group ? ` (from group: ${rule.profile_group})` : ''}
  Tags: ${(rule.tags || []).join(', ') || '(none)'}
${srxContext ? `
=== SRX TRANSLATION (current user edits) ===
  Action: ${srxContext.action}
  Application Services: ${srxContext.applicationServices?.join(', ') || 'none'}
  Logging: ${srxContext.logging?.join(', ') || 'none'}
` : ''}
Available zones: ${zoneList}

Review both the original ${vendorLabel(sourceVendor)} rule and its SRX translation. Identify any issues with the migration mapping, missing security features, or best-practice violations on the SRX side. Respond with ONLY the JSON object.`,
  };
}

/**
 * Builds a prompt for reviewing a NAT rule.
 */
export function buildNATSuggestionPrompt(rule, targetModel, sourceVendor) {
  const vendor = vendorLabel(sourceVendor);
  return {
    system: loadSystemPrompt('rule'),
    user: `Review this NAT rule for a ${vendor} to SRX (${targetModel || 'SRX'}) migration:

NAT Rule: "${rule.name}"
  Type: ${rule.type}
  From zones: ${rule.src_zones?.join(', ') || 'any'}
  To zones: ${rule.dst_zones?.join(', ') || 'any'}
  Source addresses: ${rule.src_addresses?.join(', ') || 'any'}
  Destination addresses: ${rule.dst_addresses?.join(', ') || 'any'}
  Translated source: ${JSON.stringify(rule.translated_src) || 'none'}
  Translated destination: ${rule.translated_dst || 'none'}
  Translated port: ${rule.translated_port || 'none'}

Provide 2-3 specific suggestions for this NAT rule. Focus on SRX NAT rule-set best practices and common pitfalls.`,
  };
}

/**
 * Builds a prompt for general config review.
 */
export function buildConfigReviewPrompt(intermediateConfig, targetModel) {
  const stats = intermediateConfig?.metadata || {};
  const vendor = vendorLabel(stats.source_vendor);
  return {
    system: loadSystemPrompt('rule'),
    user: `Review this firewall policy migration overview for ${vendor} to SRX (${targetModel || 'SRX'}):

Configuration stats:
  Source: ${vendor} ${stats.source_version || 'unknown'}
  Zones: ${stats.zone_count || 0}
  Security rules: ${stats.rule_count || 0}
  NAT rules: ${stats.nat_rule_count || 0}
  Objects: ${stats.object_count || 0}
  VPN tunnels: ${stats.vpn_tunnel_count || 0}
  Static routes: ${stats.static_route_count || 0}

Zone names: ${(intermediateConfig?.zones || []).map(z => z.name).join(', ')}

Provide 3-4 high-level migration recommendations and potential issues to watch for.`,
  };
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
    return `${i + 1}. [${r.action}] "${r.name}" ${src}->${dst} apps=${apps} svc=${svcs} ${flags}`;
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

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

export const DEFAULT_SYSTEM_PROMPT = `You are an expert firewall policy engineer specializing in PAN-OS to Juniper SRX migrations. You provide concise, actionable best-practice suggestions.

## Juniper SRX Security Best Practices

### Zone Architecture
- Strict zone segmentation (trust/untrust/dmz/management)
- Dedicated zones for partner/vendor connectivity
- host-inbound-traffic restricted per zone

### Policy Design
- Default deny-all cleanup rule per zone pair with logging
- Most specific rules first, broadest last
- Application-based policies preferred over port-based
- Avoid any-any-any open rules
- Descriptive names and descriptions on every rule
- Review disabled rules for removal

### Logging
- log session-close on all permit rules
- log session-init on deny/reject rules
- Forward to SIEM/syslog

### Security Profiles (UTM)
- IDP on trust→untrust and dmz→untrust
- Anti-malware on HTTP/SMTP/FTP/IMAP
- URL filtering on outbound web traffic
- AppFW for application category restrictions

### NAT
- SRX rule-set based NAT by zone pairs
- Interface-based source NAT for simple internet access
- Destination NAT with explicit pools

### SRX-Specific
- Use AppID over port-only matching
- Screen options per zone for DoS protection
- Consistent address-book usage (zone-level or global)
- Junos names: max 63 chars, no spaces

### Migration Guidance
- PAN-OS "application-default" → verify SRX AppID coverage
- Profile groups → SRX UTM policies (manual config needed)
- Tags → preserve as description/comments
- "drop" → "deny" (silent drop), "reset-*" → "reject"
- Disabled rules → "deactivate" statement

### Compliance
- PCI-DSS: explicit deny-all, documented justification, quarterly review
- NIST 800-41: segment by sensitivity, log denied traffic, annual review
- CIS: disable unused interfaces, restrict management access`;

// ---------------------------------------------------------------------------
// System Prompt Loader
// ---------------------------------------------------------------------------

/**
 * Loads the system prompt from localStorage or falls back to DEFAULT_SYSTEM_PROMPT.
 */
export function loadSystemPrompt() {
  try {
    const saved = localStorage.getItem('llm-settings');
    if (saved) {
      const settings = JSON.parse(saved);
      if (settings.systemPrompt && settings.systemPrompt.trim()) {
        return settings.systemPrompt;
      }
    }
  } catch { /* ignore */ }
  return DEFAULT_SYSTEM_PROMPT;
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

/**
 * Builds a prompt asking the LLM to review a security rule (legacy free-text).
 */
export function buildRuleSuggestionPrompt(rule, targetModel, zones) {
  const zoneList = (zones || []).map(z => z.name).join(', ');
  return {
    system: loadSystemPrompt(),
    user: `Review this firewall security rule for a PAN-OS to SRX (${targetModel || 'SRX'}) migration and suggest improvements:

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
export function buildStructuredRuleSuggestionPrompt(rule, targetModel, zones, srxLicense, srxContext) {
  const zoneList = (zones || []).map(z => z.name).join(', ');
  const systemPrompt = loadSystemPrompt();

  const licenseContext = srxLicense ? `

LICENSE CONTEXT:
The target SRX has license level: ${srxLicense}
- A1: AppID, basic IPS, stateful firewall
- A2: A1 + advanced IPS, AppQoS
- P1: A2 + UTM (antivirus, anti-spam, web filtering), SecIntel
- P2: P1 + ATP Cloud, encrypted traffic analysis
If this rule uses security features requiring a higher license tier than ${srxLicense}, flag this in your analysis and suggest alternatives available at the ${srxLicense} tier.` : '';

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
  "verdict": "needs_changes" or "looks_good"
}

Valid field names and their types:
- name (string), action (string: allow/deny/drop/reject), description (string)
- src_zones (array), dst_zones (array), src_addresses (array), dst_addresses (array)
- applications (array), services (array)
- log_start (boolean), log_end (boolean), disabled (boolean)
- profile_group (string), tags (array)

For array fields, use JSON arrays like ["value1", "value2"].
For boolean fields, use true or false (no quotes).` + licenseContext,

    user: `Review this firewall security rule being migrated from PAN-OS to SRX (${targetModel || 'SRX'})${srxLicense ? ` (license: ${srxLicense})` : ''}:

=== ORIGINAL PAN-OS RULE ===
Rule: "${rule.name}"
  Action: ${rule.action}
  From zones: ${(rule.src_zones || []).join(', ') || 'any'}
  To zones: ${(rule.dst_zones || []).join(', ') || 'any'}
  Source addresses: ${(rule.src_addresses || []).join(', ') || 'any'}
  Destination addresses: ${(rule.dst_addresses || []).join(', ') || 'any'}
  Applications: ${(rule.applications || []).join(', ') || 'any'}
  Services: ${(rule.services || []).join(', ') || 'any'}
  Logging: start=${rule.log_start}, end=${rule.log_end}
  Disabled: ${rule.disabled}
  Description: ${rule.description || '(none)'}
  Security profiles: ${profileSummary}
  Tags: ${(rule.tags || []).join(', ') || '(none)'}
${srxContext ? `
=== SRX TRANSLATION (current user edits) ===
  Action: ${srxContext.action}
  Application Services: ${srxContext.applicationServices?.join(', ') || 'none'}
  Logging: ${srxContext.logging?.join(', ') || 'none'}
` : ''}
Available zones: ${zoneList}

Review both the original PAN-OS rule and its SRX translation. Identify any issues with the migration mapping, missing security features, or best-practice violations on the SRX side. Respond with ONLY the JSON object.`,
  };
}

/**
 * Builds a prompt for reviewing a NAT rule.
 */
export function buildNATSuggestionPrompt(rule, targetModel) {
  return {
    system: loadSystemPrompt(),
    user: `Review this NAT rule for a PAN-OS to SRX (${targetModel || 'SRX'}) migration:

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
  return {
    system: loadSystemPrompt(),
    user: `Review this firewall policy migration overview for PAN-OS to SRX (${targetModel || 'SRX'}):

Configuration stats:
  Source: PAN-OS ${stats.source_version || 'unknown'}
  Zones: ${stats.zone_count || 0}
  Security rules: ${stats.rule_count || 0}
  NAT rules: ${stats.nat_rule_count || 0}
  Objects: ${stats.object_count || 0}

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

LICENSE TIER ANALYSIS:
The target SRX has license level: ${srxLicense}
- A1: AppID, basic IPS, stateful firewall
- A2: A1 + advanced IPS, AppQoS
- P1: A2 + UTM (antivirus, anti-spam, web filtering), SecIntel
- P2: P1 + ATP Cloud, encrypted traffic analysis
Flag any rules that use security profiles requiring a higher license tier than ${srxLicense}. Specifically:
- Antivirus/URL-filtering/file-blocking/anti-spam require P1+
- WildFire/ATP Cloud features require P2
- Advanced IPS requires A2+
Suggest alternatives or configuration adjustments for features not covered by the ${srxLicense} license.` : '';

  const systemPrompt = loadSystemPrompt() + `

When reviewing the full ruleset, also analyze:
- Rule ordering: are most-specific rules first?
- Redundancy: are there overlapping or shadowed rules?
- Missing cleanup rules: is there a deny-all at the end of each zone pair?
- Inconsistent logging: are all permits logging session-close?
- Zone gaps: are there zone pairs with no policies?
- Security profile coverage: which rules lack UTM/IDP profiles?

When suggesting changes to specific rules, include a JSON code block with this format:
\`\`\`json
{"rule_name": "the-rule-name", "field": "field_name", "current": "current_value", "suggested": "new_value", "reason": "Why this change"}
\`\`\`

You may include multiple JSON blocks in your response, interspersed with explanatory text.` + licenseAnalysis;

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

  return {
    system: systemPrompt,
    user: `Review this complete firewall ruleset (${policies.length} rules) for a PAN-OS to SRX (${targetModel || 'SRX'}) migration.${srxLicense ? ` Target license: ${srxLicense}.` : ''} Identify issues, suggest improvements, and flag any security concerns.

Ruleset:
${ruleSummary}

Zones: ${(intermediateConfig?.zones || []).map(z => z.name).join(', ')}

Provide a thorough analysis with specific, actionable recommendations. Use JSON code blocks for rule-specific changes.`,
  };
}

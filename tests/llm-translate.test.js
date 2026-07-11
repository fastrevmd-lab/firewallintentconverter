/**
 * Tests for LLM-driven policy translation feature (feature/llm-translate)
 *
 * Covers:
 *   - buildTranslationPrompt()
 *   - parseTranslationResponse()
 *   - translatePolicies() (mocked LLM call)
 *   - Edge cases: chunking, malformed responses, missing fields
 */

// ---------------------------------------------------------------------------
// Minimal DOM/storage stubs for the browser-side module
// ---------------------------------------------------------------------------
const _store = {};
global.localStorage = {
  getItem: (k) => _store[k] || null,
  setItem: (k, v) => { _store[k] = v; },
  removeItem: (k) => { delete _store[k]; },
};
const _sessionStore = {};
global.sessionStorage = {
  getItem: (k) => _sessionStore[k] || null,
  setItem: (k, v) => { _sessionStore[k] = v; },
  removeItem: (k) => { delete _sessionStore[k]; },
};
global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}) });

// ---------------------------------------------------------------------------
// Import the functions under test
// ---------------------------------------------------------------------------
import {
  buildTranslationPrompt,
  parseTranslationResponse,
  translatePolicies,
  DEFAULT_TRANSLATE_SYSTEM_PROMPT,
  loadSystemPrompt,
} from '../public/utils/llm-client.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal intermediateConfig for testing */
function makeConfig(overrides = {}) {
  return {
    metadata: { source_vendor: 'panos' },
    zones: [{ name: 'trust' }, { name: 'untrust' }],
    addresses: [{ name: 'web-server', ip: '10.0.1.10/32' }],
    address_groups: [{ name: 'servers', members: ['web-server'] }],
    security_policies: [
      {
        name: 'allow-web',
        _rule_index: 0,
        action: 'allow',
        src_zones: ['trust'],
        dst_zones: ['untrust'],
        src_addresses: ['any'],
        dst_addresses: ['any'],
        applications: ['web-browsing', 'ssl'],
        services: [],
        log_start: false,
        log_end: true,
        disabled: false,
        description: 'Allow outbound web',
      },
      {
        name: 'deny-all',
        _rule_index: 1,
        action: 'deny',
        src_zones: ['trust'],
        dst_zones: ['untrust'],
        src_addresses: ['any'],
        dst_addresses: ['any'],
        applications: [],
        services: [],
        log_start: true,
        log_end: false,
        disabled: false,
        description: 'Cleanup rule',
      },
    ],
    ...overrides,
  };
}

/** Build a valid LLM JSON response */
function makeLLMResponse(policies) {
  return '```json\n' + JSON.stringify(policies) + '\n```';
}

// =========================================================================
// Test suite
// =========================================================================

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error(`  FAIL: ${msg}`);
  }
}

function section(name) {
  console.log(`\n--- ${name} ---`);
}

// ---------------------------------------------------------------------------
// 1. DEFAULT_TRANSLATE_SYSTEM_PROMPT
// ---------------------------------------------------------------------------
section('DEFAULT_TRANSLATE_SYSTEM_PROMPT');

assert(typeof DEFAULT_TRANSLATE_SYSTEM_PROMPT === 'string', 'prompt is a string');
assert(DEFAULT_TRANSLATE_SYSTEM_PROMPT.length > 500, 'prompt is substantial');
assert(DEFAULT_TRANSLATE_SYSTEM_PROMPT.includes('JSON array'), 'prompt mentions JSON array output');
assert(DEFAULT_TRANSLATE_SYSTEM_PROMPT.includes('_translation_notes'), 'prompt mentions _translation_notes');
assert(DEFAULT_TRANSLATE_SYSTEM_PROMPT.includes('PAN-OS'), 'prompt includes PAN-OS mapping');
assert(DEFAULT_TRANSLATE_SYSTEM_PROMPT.includes('FortiGate'), 'prompt includes FortiGate mapping');
assert(DEFAULT_TRANSLATE_SYSTEM_PROMPT.includes('Check Point'), 'prompt includes Check Point mapping');

// ---------------------------------------------------------------------------
// 2. loadSystemPrompt('translate')
// ---------------------------------------------------------------------------
section('loadSystemPrompt("translate")');

const translatePrompt = loadSystemPrompt('translate');
assert(typeof translatePrompt === 'string', 'returns a string');
assert(translatePrompt.includes('_translation_notes'), 'translate prompt loads correctly');

// Check that localStorage override works
localStorage.setItem('llm-settings', JSON.stringify({ translateSystemPrompt: 'CUSTOM TRANSLATE PROMPT' }));
const customPrompt = loadSystemPrompt('translate');
assert(customPrompt === 'CUSTOM TRANSLATE PROMPT', 'localStorage override works for translate');
localStorage.removeItem('llm-settings');

// ---------------------------------------------------------------------------
// 3. buildTranslationPrompt
// ---------------------------------------------------------------------------
section('buildTranslationPrompt');

const config = makeConfig();
const result = buildTranslationPrompt(config, 'SRX345', 'A1');

assert(result.system && result.user, 'returns system + user');
assert(result.system.includes('_translation_notes'), 'system prompt includes translate instructions');
assert(result.system.includes('A1'), 'system prompt includes license note');
assert(result.user.includes('PAN-OS'), 'user prompt includes vendor label');
assert(result.user.includes('SRX345'), 'user prompt includes target model');
assert(result.user.includes('trust'), 'user prompt includes zone names');
assert(result.user.includes('untrust'), 'user prompt includes all zones');
assert(result.user.includes('web-server'), 'user prompt includes address objects');
assert(result.user.includes('servers'), 'user prompt includes address groups');
assert(result.user.includes('allow-web'), 'user prompt includes policy data');
assert(result.user.includes('2 security policies'), 'user prompt includes policy count');
assert(result.user.includes('CRITICAL'), 'user prompt includes CRITICAL JSON-only instruction');
assert(result.user.includes('Start with ['), 'user prompt tells LLM to start with [');

// Internal metadata stripped from policy JSON
assert(!result.user.includes('_rule_index'), 'strips _rule_index from source policies');
assert(!result.user.includes('_review_status'), 'strips _review_status from source policies');

// Without license
const noLicResult = buildTranslationPrompt(config, 'SRX345', '');
assert(!noLicResult.system.includes('IMPORTANT — Target SRX Subscription'), 'no license note when no license');

// Without addresses
const noAddrConfig = makeConfig({ addresses: [], address_groups: [] });
const noAddrResult = buildTranslationPrompt(noAddrConfig, 'SRX345', '');
assert(!noAddrResult.user.includes('Address Objects'), 'no address section when empty');
assert(!noAddrResult.user.includes('Address Groups'), 'no group section when empty');

// Different vendors
for (const [vendor, label] of [
  ['fortigate', 'FortiGate'],
  ['cisco_asa', 'Cisco ASA/FTD'],
  ['checkpoint', 'Check Point'],
  ['sonicwall', 'SonicWall'],
  ['huawei_usg', 'Huawei USG'],
]) {
  const vendorConfig = makeConfig({ metadata: { source_vendor: vendor } });
  const vendorResult = buildTranslationPrompt(vendorConfig, 'SRX', '');
  assert(vendorResult.user.includes(label), `vendor ${vendor} maps to "${label}"`);
}

// ---------------------------------------------------------------------------
// 4. parseTranslationResponse — valid responses
// ---------------------------------------------------------------------------
section('parseTranslationResponse — valid');

// 4a. Fenced JSON
const fencedPolicies = [
  { name: 'rule-1', action: 'allow', src_zones: ['trust'], dst_zones: ['untrust'], _translation_notes: 'Test note' },
];
const fencedResult = parseTranslationResponse(makeLLMResponse(fencedPolicies));
assert(Array.isArray(fencedResult), 'parses fenced JSON');
assert(fencedResult.length === 1, 'correct count from fenced');
assert(fencedResult[0].name === 'rule-1', 'preserves rule name');
assert(fencedResult[0]._translation_notes === 'Test note', 'preserves _translation_notes');
assert(fencedResult[0]._review_status === 'llm_reviewed', 'sets _review_status to llm_reviewed');
assert(fencedResult[0]._rule_index === 0, 'sets _rule_index');

// 4b. Raw JSON (no fences)
const rawResult = parseTranslationResponse(JSON.stringify(fencedPolicies));
assert(rawResult.length === 1, 'parses raw JSON');
assert(rawResult[0].name === 'rule-1', 'raw JSON preserves name');

// 4c. JSON embedded in text
const embeddedResult = parseTranslationResponse('Here are the translated policies:\n' + JSON.stringify(fencedPolicies) + '\nDone.');
assert(embeddedResult.length === 1, 'parses JSON embedded in text');

// 4d. Fenced without "json" tag
const fencedNoTag = '```\n' + JSON.stringify(fencedPolicies) + '\n```';
const noTagResult = parseTranslationResponse(fencedNoTag);
assert(noTagResult.length === 1, 'parses fenced JSON without json tag');

// ---------------------------------------------------------------------------
// 5. parseTranslationResponse — normalization
// ---------------------------------------------------------------------------
section('parseTranslationResponse — normalization');

// 5a. Missing name → auto-generated
const noNameResult = parseTranslationResponse(JSON.stringify([{ action: 'allow' }]));
assert(noNameResult[0].name === 'translated-rule-1', 'auto-generates name when missing');

// 5b. Missing action → defaults to deny
const noActionResult = parseTranslationResponse(JSON.stringify([{ name: 'test' }]));
assert(noActionResult[0].action === 'deny', 'defaults action to deny');

// 5c. String zones → wrapped in array
const stringZoneResult = parseTranslationResponse(JSON.stringify([
  { name: 'r1', action: 'allow', src_zones: 'trust', dst_zones: 'untrust' },
]));
assert(Array.isArray(stringZoneResult[0].src_zones), 'wraps string src_zones in array');
assert(stringZoneResult[0].src_zones[0] === 'trust', 'preserves zone value');
assert(Array.isArray(stringZoneResult[0].dst_zones), 'wraps string dst_zones in array');

// 5d. Missing zones → default to ['any']
const noZoneResult = parseTranslationResponse(JSON.stringify([{ name: 'r1', action: 'allow' }]));
assert(noZoneResult[0].src_zones[0] === 'any', 'defaults src_zones to ["any"]');
assert(noZoneResult[0].dst_zones[0] === 'any', 'defaults dst_zones to ["any"]');
assert(noZoneResult[0].src_addresses[0] === 'any', 'defaults src_addresses to ["any"]');
assert(noZoneResult[0].dst_addresses[0] === 'any', 'defaults dst_addresses to ["any"]');

// 5e. Boolean normalization
const boolResult = parseTranslationResponse(JSON.stringify([
  { name: 'r1', action: 'deny', log_start: 1, log_end: 0, disabled: '' },
]));
assert(boolResult[0].log_start === true, 'normalizes truthy log_start to true');
assert(boolResult[0].log_end === false, 'normalizes falsy log_end to false');
assert(boolResult[0].disabled === false, 'normalizes empty string disabled to false');

// 5f. log_end defaults to true when not provided
const defaultLogResult = parseTranslationResponse(JSON.stringify([
  { name: 'r1', action: 'allow' },
]));
assert(defaultLogResult[0].log_end === true, 'log_end defaults to true');

// 5g. Multiple policies get sequential _rule_index
const multiResult = parseTranslationResponse(JSON.stringify([
  { name: 'r1', action: 'allow' },
  { name: 'r2', action: 'deny' },
  { name: 'r3', action: 'reject' },
]));
assert(multiResult[0]._rule_index === 0, 'first policy index = 0');
assert(multiResult[1]._rule_index === 1, 'second policy index = 1');
assert(multiResult[2]._rule_index === 2, 'third policy index = 2');

// 5h. Empty _translation_notes defaults to empty string
assert(multiResult[0]._translation_notes === '', '_translation_notes defaults to empty string');

// 5i. Applications/services normalization
const appResult = parseTranslationResponse(JSON.stringify([
  { name: 'r1', action: 'allow', applications: 'junos-http', services: 'any' },
]));
assert(Array.isArray(appResult[0].applications), 'wraps string applications in array');
assert(appResult[0].applications[0] === 'junos-http', 'preserves application value');
assert(Array.isArray(appResult[0].services), 'wraps string services in array');

// ---------------------------------------------------------------------------
// 6. parseTranslationResponse — error cases
// ---------------------------------------------------------------------------
section('parseTranslationResponse — errors');

// 6a. Completely invalid
let threw = false;
try { parseTranslationResponse('This is not JSON at all.'); } catch (e) {
  threw = true;
  assert(e.message.includes('Could not parse'), 'error message for non-JSON');
}
assert(threw, 'throws on non-JSON response');

// 6b. Valid JSON but not an array
threw = false;
try { parseTranslationResponse('{"name": "not-an-array"}'); } catch (e) {
  threw = true;
  assert(e.message.includes('not an array'), 'error message for non-array JSON');
}
assert(threw, 'throws on non-array JSON');

// 6c. Empty string
threw = false;
try { parseTranslationResponse(''); } catch (e) {
  threw = true;
}
assert(threw, 'throws on empty string');

// 6d. Malformed JSON in fences
threw = false;
try { parseTranslationResponse('```json\n{broken json}\n```'); } catch (e) {
  threw = true;
}
assert(threw, 'throws on malformed JSON in fences');

// 6e. Error message includes response preview
threw = false;
try { parseTranslationResponse('I cannot translate these policies because...'); } catch (e) {
  threw = true;
  assert(e.message.includes('Response preview:'), 'error includes response preview');
  assert(e.message.includes('I cannot translate'), 'preview shows actual response content');
  assert(e.message.includes('Max Tokens'), 'error includes max tokens tip');
}
assert(threw, 'throws with helpful error on text-only response');

// 6f. Truncated JSON array — repair strategy
const truncatedResponse = '[{"name":"r1","action":"allow","src_zones":["trust"]},{"name":"r2","action":"deny","src_zones":["untrust"]},{"name":"r3","acti';
const repairResult = parseTranslationResponse(truncatedResponse);
assert(Array.isArray(repairResult), 'repairs truncated JSON');
assert(repairResult.length === 2, 'recovers complete objects from truncated response');
assert(repairResult[0].name === 'r1', 'first repaired policy correct');
assert(repairResult[1].name === 'r2', 'second repaired policy correct');

// 6g. Truncated with markdown fences that don't close
const truncFenced = '```json\n[{"name":"only-rule","action":"allow"}';
const truncFencedResult = parseTranslationResponse(truncFenced);
assert(truncFencedResult.length === 1, 'repairs truncated fenced JSON');
assert(truncFencedResult[0].name === 'only-rule', 'preserves rule from truncated fences');

// 6h. JSON with text before and after
const wrappedResponse = 'Here are the translated policies:\n\n[{"name":"wrapped","action":"deny"}]\n\nLet me know if you need changes.';
const wrappedResult = parseTranslationResponse(wrappedResponse);
assert(wrappedResult.length === 1, 'parses JSON wrapped in explanatory text');
assert(wrappedResult[0].name === 'wrapped', 'preserves name from wrapped response');

// ---------------------------------------------------------------------------
// 7. translatePolicies — mocked LLM call
// ---------------------------------------------------------------------------
section('translatePolicies — mocked');

// Setup storage with a provider so getLLMStatus passes
localStorage.setItem('llm-settings', JSON.stringify({
  provider: 'custom',
  baseUrl: 'http://localhost:9999',
}));
sessionStorage.setItem('llm-api-key', 'test-key');

// Mock fetch to return a valid LLM translation response
const translatedPolicies = [
  {
    name: 'allow-web-srx',
    action: 'allow',
    src_zones: ['trust'],
    dst_zones: ['untrust'],
    src_addresses: ['any'],
    dst_addresses: ['any'],
    applications: ['junos-http', 'junos-https'],
    services: [],
    log_start: false,
    log_end: true,
    disabled: false,
    description: 'Allow outbound web traffic',
    _translation_notes: 'Translated from PAN-OS allow-web. Mapped web-browsing→junos-http, ssl→junos-https.',
    _review_status: 'accepted',
  },
  {
    name: 'deny-all-srx',
    action: 'deny',
    src_zones: ['trust'],
    dst_zones: ['untrust'],
    src_addresses: ['any'],
    dst_addresses: ['any'],
    applications: [],
    services: [],
    log_start: true,
    log_end: false,
    disabled: false,
    description: 'Cleanup deny rule',
    _translation_notes: 'Cleanup rule preserved. Added session-init logging.',
    _review_status: 'accepted',
  },
];

// Custom endpoint returns OpenAI-compatible format
global.fetch = async (url, opts) => {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      choices: [{ message: { content: makeLLMResponse(translatedPolicies) } }],
    }),
  };
};

async function testTranslatePolicies() {
  const config = makeConfig();

  // 7a. Successful translation
  const result = await translatePolicies(config, 'SRX345', 'A1');
  assert(Array.isArray(result), 'translatePolicies returns an array');
  assert(result.length === 2, 'returns correct number of policies');
  assert(result[0].name === 'allow-web-srx', 'first policy name correct');
  assert(result[1].name === 'deny-all-srx', 'second policy name correct');
  assert(result[0]._translation_notes.includes('junos-http'), 'translation notes preserved');
  assert(result[0]._rule_index === 0, 'rule indices are sequential');
  assert(result[1]._rule_index === 1, 'second rule index correct');

  // 7b. Empty policies throws
  let threw = false;
  try {
    await translatePolicies({ ...config, security_policies: [] }, 'SRX', '');
  } catch (e) {
    threw = true;
    assert(e.message.includes('No security policies'), 'error message for empty policies');
  }
  assert(threw, 'throws on empty security_policies');

  // 7c. No provider configured
  localStorage.removeItem('llm-settings');
  threw = false;
  try {
    await translatePolicies(config, 'SRX', '');
  } catch (e) {
    threw = true;
    assert(e.message.includes('No LLM provider'), 'error message for no provider');
  }
  assert(threw, 'throws when no provider configured');

  // Restore provider for remaining tests
  localStorage.setItem('llm-settings', JSON.stringify({
    provider: 'custom',
    baseUrl: 'http://localhost:9999',
  }));
  sessionStorage.setItem('llm-api-key', 'test-key');

  // 7d. Large ruleset triggers chunking (>30 rules)
  const bigPolicies = [];
  for (let i = 0; i < 35; i++) {
    bigPolicies.push({
      name: `rule-${i}`,
      _rule_index: i,
      action: 'allow',
      src_zones: ['trust'],
      dst_zones: ['untrust'],
      src_addresses: ['any'],
      dst_addresses: ['any'],
      applications: [],
      services: [],
      log_start: false,
      log_end: true,
      disabled: false,
      description: `Rule ${i}`,
    });
  }

  // Track fetch calls to verify chunking
  let fetchCallCount = 0;
  global.fetch = async (url, opts) => {
    fetchCallCount++;
    // Return a small translated chunk
    const body = JSON.parse(opts.body);
    const userMsg = body.messages.find(m => m.role === 'user')?.content || '';
    // Extract rule count from user message to return matching number
    const chunkPolicies = [];
    for (let i = 0; i < 5; i++) {
      chunkPolicies.push({
        name: `translated-chunk${fetchCallCount}-rule-${i}`,
        action: 'allow',
        src_zones: ['trust'],
        dst_zones: ['untrust'],
      });
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        choices: [{ message: { content: JSON.stringify(chunkPolicies) } }],
      }),
    };
  };

  const bigConfig = makeConfig({ security_policies: bigPolicies });
  const bigResult = await translatePolicies(bigConfig, 'SRX', '');
  assert(fetchCallCount >= 2, `chunked into ${fetchCallCount} LLM calls (expected >= 2)`);
  assert(Array.isArray(bigResult), 'chunked result is an array');
  assert(bigResult.length > 0, 'chunked result has policies');
  // Verify sequential re-indexing
  bigResult.forEach((p, i) => {
    assert(p._rule_index === i, `chunked policy ${i} has correct _rule_index`);
  });

  // 7e. Verify deduplication in chunked results
  // All policies should have unique names (the mock gives unique names per chunk)
  const names = bigResult.map(p => p.name);
  const uniqueNames = new Set(names);
  assert(names.length === uniqueNames.size, 'no duplicate names in chunked result');
}

// ---------------------------------------------------------------------------
// 8. parseTranslationResponse — edge cases
// ---------------------------------------------------------------------------
section('parseTranslationResponse — edge cases');

// 8a. Empty array is valid
const emptyArrayResult = parseTranslationResponse('[]');
assert(Array.isArray(emptyArrayResult), 'empty array is valid');
assert(emptyArrayResult.length === 0, 'empty array returns empty');

// 8b. Policy with all fields already correct (no normalization needed)
const fullPolicy = {
  name: 'full-rule',
  action: 'allow',
  src_zones: ['trust'],
  dst_zones: ['untrust'],
  src_addresses: ['10.0.0.0/8'],
  dst_addresses: ['any'],
  applications: ['junos-http'],
  services: ['any'],
  log_start: false,
  log_end: true,
  disabled: false,
  description: 'Full policy',
  _translation_notes: 'No changes needed',
  _review_status: 'accepted',
};
const fullResult = parseTranslationResponse(JSON.stringify([fullPolicy]));
assert(fullResult[0].name === 'full-rule', 'full policy passes through');
assert(fullResult[0].src_zones[0] === 'trust', 'full policy preserves zones');
assert(fullResult[0]._translation_notes === 'No changes needed', 'full policy preserves notes');

// 8c. Extra fields are preserved (LLM might add custom fields)
const extraFieldPolicy = { name: 'extra', action: 'allow', custom_field: 'custom_value' };
const extraResult = parseTranslationResponse(JSON.stringify([extraFieldPolicy]));
assert(extraResult[0].custom_field === 'custom_value', 'extra fields are preserved');

// 8d. JSON with leading/trailing whitespace
const wsResult = parseTranslationResponse('   \n' + JSON.stringify([{ name: 'ws', action: 'allow' }]) + '\n   ');
assert(wsResult[0].name === 'ws', 'handles whitespace-padded JSON');

// ---------------------------------------------------------------------------
// Run async tests and report
// ---------------------------------------------------------------------------

testTranslatePolicies().then(() => {
  console.log(`\n========================================`);
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log(`========================================\n`);
  if (failed > 0) process.exit(1);
}).catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});

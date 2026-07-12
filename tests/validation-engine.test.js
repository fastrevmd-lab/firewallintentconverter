/**
 * Tests for validation modules:
 *   - src/validators/hardware-checks.js
 *   - src/validators/operational-checks.js
 *   - src/validators/compliance-checks.js
 *   - src/validators/srx-validation-engine.js
 *
 * Run with: node tests/validation-engine.test.js
 */

// ---------------------------------------------------------------------------
// Minimal localStorage stub (required by imported modules)
// ---------------------------------------------------------------------------
const _store = {};
global.localStorage = {
  getItem: (k) => _store[k] || null,
  setItem: (k, v) => { _store[k] = v; },
  removeItem: (k) => { delete _store[k]; },
};

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------
import { runHardwareChecks } from '../src/validators/hardware-checks.js';
import { runOperationalChecks } from '../src/validators/operational-checks.js';
import { runComplianceChecks } from '../src/validators/compliance-checks.js';
import { runValidation } from '../src/validators/srx-validation-engine.js';
import { normalizeConversionOutput } from '../src/conversion/conversion-output.js';

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const MOCK_MODEL_DB = {
  'SRX300': {
    name: 'SRX300',
    tier: 'branch',
    throughput: { l4: '500 Mbps', l7: 'N/A', threat: '200 Mbps' },
    ports: [
      { name: 'ge-0/0/0', type: 'copper', speed: '1G' },
      { name: 'ge-0/0/1', type: 'copper', speed: '1G' },
      { name: 'ge-0/0/2', type: 'copper', speed: '1G' },
      { name: 'ge-0/0/3', type: 'copper', speed: '1G' },
    ],
  },
  'SRX4100': {
    name: 'SRX4100',
    tier: 'datacenter',
    throughput: { l4: '20 Gbps', l7: '10 Gbps', threat: '13.9 Gbps' },
    ports: [
      { name: 'ge-0/0/0', type: 'copper', speed: '1G' },
      { name: 'ge-0/0/1', type: 'copper', speed: '1G' },
      { name: 'xe-0/0/0', type: 'SFP+', speed: '10G' },
      { name: 'xe-0/0/1', type: 'SFP+', speed: '10G' },
    ],
  },
};

const MOCK_CAPACITY = {
  'SRX300': {
    max_policies: 1024,
    max_sessions: 64000,
    max_zones: 16,
    max_nat_rules: 1024,
    max_address_objects: 2048,
  },
  'SRX4100': {
    max_policies: 65536,
    max_sessions: 10000000,
    max_zones: 512,
    max_nat_rules: 32768,
    max_address_objects: 131072,
  },
};

const EMPTY_IC = {
  security_policies: [],
  zones: [],
  nat_rules: [],
  address_objects: [],
  address_groups: [],
};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
let currentTest = '';

function assert(condition, msg) {
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error(`  FAIL [${currentTest}]: ${msg}`);
  }
}

function test(name, fn) {
  currentTest = name;
  try {
    fn();
  } catch (err) {
    failed++;
    console.error(`  ERROR [${name}]: ${err.message}`);
  }
}

function section(name) {
  console.log(`\n--- ${name} ---`);
}

const EMPTY_IDENTIFIER_MAPPINGS = Object.freeze({
  version: 1,
  entries: Object.freeze([]),
});

const setOutput = text => normalizeConversionOutput({
  format: 'set',
  commands: text.split('\n'),
  identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
});

// ---------------------------------------------------------------------------
// Hardware Checks
// ---------------------------------------------------------------------------
section('Hardware Checks');

test('H7: no model → 1 info finding with element hardware/no-model', () => {
  const findings = runHardwareChecks([], null, MOCK_MODEL_DB, MOCK_CAPACITY, EMPTY_IC, null);
  assert(findings.length === 1, 'exactly 1 finding');
  assert(findings[0].severity === 'info', 'severity is info');
  assert(findings[0].element === 'hardware/no-model', 'element is hardware/no-model');
});

test('H1: 5 interfaces on 4-port model → unsupported with element hardware/interface-count', () => {
  const commands = [
    'set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24',
    'set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24',
    'set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24',
    'set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24',
    'set interfaces ge-0/0/4 unit 0 family inet address 10.0.4.1/24',
  ];
  const findings = runHardwareChecks(commands, 'SRX300', MOCK_MODEL_DB, MOCK_CAPACITY, EMPTY_IC, null);
  const ifFinding = findings.find(f => f.element === 'hardware/interface-count');
  assert(ifFinding !== undefined, 'interface-count finding exists');
  assert(ifFinding.severity === 'unsupported', 'severity is unsupported');
});

test('H1: 2 interfaces on 4-port model → no interface-count finding', () => {
  const commands = [
    'set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24',
    'set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24',
  ];
  const findings = runHardwareChecks(commands, 'SRX300', MOCK_MODEL_DB, MOCK_CAPACITY, EMPTY_IC, null);
  const ifFinding = findings.find(f => f.element === 'hardware/interface-count');
  assert(ifFinding === undefined, 'no interface-count finding');
});

test('H2: xe- on ge-only model → warning with element hardware/interface-type', () => {
  const commands = [
    'set interfaces xe-0/0/0 unit 0 family inet address 10.0.0.1/24',
  ];
  const findings = runHardwareChecks(commands, 'SRX300', MOCK_MODEL_DB, MOCK_CAPACITY, EMPTY_IC, null);
  const typeFinding = findings.find(f => f.element === 'hardware/interface-type');
  assert(typeFinding !== undefined, 'interface-type finding exists');
  assert(typeFinding.severity === 'warning', 'severity is warning');
});

test('H3: 1100 policies on 1024-limit model → unsupported with element hardware/policy-count', () => {
  const ic = {
    ...EMPTY_IC,
    security_policies: Array.from({ length: 1100 }, (_, i) => ({ name: `p${i}` })),
  };
  const findings = runHardwareChecks([], 'SRX300', MOCK_MODEL_DB, MOCK_CAPACITY, ic, null);
  const policyFinding = findings.find(f => f.element === 'hardware/policy-count');
  assert(policyFinding !== undefined, 'policy-count finding exists');
  assert(policyFinding.severity === 'unsupported', 'severity is unsupported');
});

test('H6: target throughput < source → info with element hardware/throughput', () => {
  const sourceModel = { throughput: { l4: '10 Gbps' } };
  const findings = runHardwareChecks([], 'SRX300', MOCK_MODEL_DB, MOCK_CAPACITY, EMPTY_IC, sourceModel);
  const tpFinding = findings.find(f => f.element === 'hardware/throughput');
  assert(tpFinding !== undefined, 'throughput finding exists');
  assert(tpFinding.severity === 'info', 'severity is info');
});

// ---------------------------------------------------------------------------
// Operational Checks
// ---------------------------------------------------------------------------
section('Operational Checks');

test('O1: permit without deny-all → warning with element starting operational/missing-deny/', () => {
  const commands = [
    'set security zones security-zone trust',
    'set security zones security-zone untrust',
    'set security policies from-zone trust to-zone untrust policy allow-web then permit',
  ];
  const findings = runOperationalChecks(EMPTY_IC, commands);
  const denyFinding = findings.find(f => f.element.startsWith('operational/missing-deny/'));
  assert(denyFinding !== undefined, 'missing-deny finding exists');
  assert(denyFinding.severity === 'warning', 'severity is warning');
});

test('O1: explicit deny-all passes (no missing-deny finding)', () => {
  const commands = [
    'set security zones security-zone trust',
    'set security zones security-zone untrust',
    'set security policies from-zone trust to-zone untrust policy allow-web then permit',
    'set security policies from-zone trust to-zone untrust policy deny-all match source-address any',
    'set security policies from-zone trust to-zone untrust policy deny-all match destination-address any',
    'set security policies from-zone trust to-zone untrust policy deny-all match application any',
    'set security policies from-zone trust to-zone untrust policy deny-all then deny',
  ];
  const findings = runOperationalChecks(EMPTY_IC, commands);
  const denyFinding = findings.find(f => f.element.startsWith('operational/missing-deny/'));
  assert(denyFinding === undefined, 'no missing-deny finding when explicit deny-all present');
});

test('O4: untrust zone without screen → warning with element operational/no-screen/untrust', () => {
  const commands = [
    'set security zones security-zone untrust',
  ];
  const findings = runOperationalChecks(EMPTY_IC, commands);
  const screenFinding = findings.find(f => f.element === 'operational/no-screen/untrust');
  assert(screenFinding !== undefined, 'no-screen/untrust finding exists');
  assert(screenFinding.severity === 'warning', 'severity is warning');
});

test('O4: screen bound → no finding for that zone', () => {
  const commands = [
    'set security zones security-zone untrust',
    'set security zones security-zone untrust screen internet-screen',
  ];
  const findings = runOperationalChecks(EMPTY_IC, commands);
  const screenFinding = findings.find(f => f.element === 'operational/no-screen/untrust');
  assert(screenFinding === undefined, 'no screen finding when screen is bound');
});

test('O5: permit without log → warning with element starting operational/no-logging/', () => {
  const commands = [
    'set security policies from-zone trust to-zone untrust policy allow-web then permit',
  ];
  const findings = runOperationalChecks(EMPTY_IC, commands);
  const logFinding = findings.find(f => f.element.startsWith('operational/no-logging/'));
  assert(logFinding !== undefined, 'no-logging finding exists');
  assert(logFinding.severity === 'warning', 'severity is warning');
});

test('O5: permit with log → no no-logging finding', () => {
  const commands = [
    'set security policies from-zone trust to-zone untrust policy allow-web then permit',
    'set security policies from-zone trust to-zone untrust policy allow-web then log session-close',
  ];
  const findings = runOperationalChecks(EMPTY_IC, commands);
  const logFinding = findings.find(f => f.element === 'operational/no-logging/allow-web');
  assert(logFinding === undefined, 'no no-logging finding when log session-close present');
});

test('O6: duplicate address objects → info with element starting operational/duplicate-address/', () => {
  const ic = {
    ...EMPTY_IC,
    address_objects: [
      { name: 'server-a', type: 'host', value: '10.0.0.1' },
      { name: 'server-b', type: 'host', value: '10.0.0.1' },
    ],
  };
  const findings = runOperationalChecks(ic, []);
  const dupFinding = findings.find(f => f.element.startsWith('operational/duplicate-address/'));
  assert(dupFinding !== undefined, 'duplicate-address finding exists');
  assert(dupFinding.severity === 'info', 'severity is info');
});

test('O7: BGP without policy-statement → warning with element operational/routing-no-export', () => {
  const commands = [
    'set protocols bgp group external neighbor 192.168.1.1',
  ];
  const findings = runOperationalChecks(EMPTY_IC, commands);
  const bgpFinding = findings.find(f => f.element === 'operational/routing-no-export');
  assert(bgpFinding !== undefined, 'routing-no-export finding exists');
  assert(bgpFinding.severity === 'warning', 'severity is warning');
});

test('O8: VPN without tunnel policy → warning with element operational/vpn-no-policy', () => {
  const commands = [
    'set security ipsec vpn my-vpn bind-interface st0.0',
  ];
  const findings = runOperationalChecks(EMPTY_IC, commands);
  const vpnFinding = findings.find(f => f.element === 'operational/vpn-no-policy');
  assert(vpnFinding !== undefined, 'vpn-no-policy finding exists');
  assert(vpnFinding.severity === 'warning', 'severity is warning');
});

test('O9: overlapping NAT → warning with element starting operational/overlapping-nat/', () => {
  const ic = {
    ...EMPTY_IC,
    nat_rules: [
      { name: 'nat-1', type: 'source', from_zone: 'trust', to_zone: 'untrust', src_addresses: ['10.0.0.0/24'], dst_addresses: [] },
      { name: 'nat-2', type: 'source', from_zone: 'trust', to_zone: 'untrust', src_addresses: ['10.0.0.0/24'], dst_addresses: [] },
    ],
  };
  const findings = runOperationalChecks(ic, []);
  const natFinding = findings.find(f => f.element.startsWith('operational/overlapping-nat/'));
  assert(natFinding !== undefined, 'overlapping-nat finding exists');
  assert(natFinding.severity === 'warning', 'severity is warning');
});

// ---------------------------------------------------------------------------
// Compliance Checks
// ---------------------------------------------------------------------------
section('Compliance Checks');

test('Empty commands → flags no-ntp, no-dns, no-syslog, no-ssh, no-root-auth', () => {
  const findings = runComplianceChecks([]);
  const elements = findings.map(f => f.element);
  assert(elements.includes('compliance/no-ntp'), 'no-ntp flagged');
  assert(elements.includes('compliance/no-dns'), 'no-dns flagged');
  assert(elements.includes('compliance/no-syslog'), 'no-syslog flagged');
  assert(elements.includes('compliance/no-ssh'), 'no-ssh flagged');
  assert(elements.includes('compliance/no-root-auth'), 'no-root-auth flagged');
});

test('NTP configured → no-ntp NOT flagged', () => {
  const findings = runComplianceChecks(['set system ntp server 192.0.2.1']);
  const ntpFinding = findings.find(f => f.element === 'compliance/no-ntp');
  assert(ntpFinding === undefined, 'no-ntp not present when NTP is configured');
});

test('Default SNMP community → flagged', () => {
  const findings = runComplianceChecks(['set snmp community public authorization read-only']);
  const snmpFinding = findings.find(f => f.element === 'compliance/default-snmp');
  assert(snmpFinding !== undefined, 'default-snmp flagged for "public"');
  assert(snmpFinding.severity === 'warning', 'severity is warning');
});

test('Custom SNMP community → NOT flagged', () => {
  const findings = runComplianceChecks(['set snmp community mysecretcommunity authorization read-only']);
  const snmpFinding = findings.find(f => f.element === 'compliance/default-snmp');
  assert(snmpFinding === undefined, 'default-snmp NOT flagged for custom community');
});

test('Telnet → flagged', () => {
  const findings = runComplianceChecks(['set system services telnet']);
  const telnetFinding = findings.find(f => f.element === 'compliance/telnet-enabled');
  assert(telnetFinding !== undefined, 'telnet-enabled flagged');
  assert(telnetFinding.severity === 'warning', 'severity is warning');
});

test('Users without password policy → weak-password-policy flagged', () => {
  const findings = runComplianceChecks(['set system login user admin class super-user']);
  const pwFinding = findings.find(f => f.element === 'compliance/weak-password-policy');
  assert(pwFinding !== undefined, 'weak-password-policy flagged');
});

test('Users with password policy → weak-password-policy NOT flagged', () => {
  const findings = runComplianceChecks([
    'set system login user admin class super-user',
    'set system login password minimum-length 12',
  ]);
  const pwFinding = findings.find(f => f.element === 'compliance/weak-password-policy');
  assert(pwFinding === undefined, 'weak-password-policy NOT flagged when minimum-length set');
});

test('HTTP without HTTPS → http-management flagged', () => {
  const findings = runComplianceChecks(['set system services web-management http port 80']);
  const httpFinding = findings.find(f => f.element === 'compliance/http-management');
  assert(httpFinding !== undefined, 'http-management flagged');
  assert(httpFinding.severity === 'warning', 'severity is warning');
});

test('No root-auth → no-root-auth flagged', () => {
  const findings = runComplianceChecks([]);
  const rootFinding = findings.find(f => f.element === 'compliance/no-root-auth');
  assert(rootFinding !== undefined, 'no-root-auth flagged');
  assert(rootFinding.severity === 'warning', 'severity is warning');
});

// ---------------------------------------------------------------------------
// Validation Engine
// ---------------------------------------------------------------------------
section('Validation Engine');

test('All findings tagged with _source: "validation"', () => {
  const srxOutput = '';
  const result = runValidation({
    intermediateConfig: EMPTY_IC,
    conversionOutput: setOutput(srxOutput || 'set system host-name validation-fixture'),
    targetModel: null,
    srxLicense: null,
    enforceLicense: false,
    modelDb: MOCK_MODEL_DB,
    capacityLimits: MOCK_CAPACITY,
    sourceModel: null,
  });
  assert(result.findings.length > 0, 'has findings');
  const untagged = result.findings.filter(f => f._source !== 'validation');
  assert(untagged.length === 0, 'all findings have _source: "validation"');
});

test('No license tier → info finding at license/no-tier', () => {
  const srxOutput = '';
  const result = runValidation({
    intermediateConfig: EMPTY_IC,
    conversionOutput: setOutput(srxOutput || 'set system host-name validation-fixture'),
    targetModel: null,
    srxLicense: null,
    enforceLicense: false,
    modelDb: MOCK_MODEL_DB,
    capacityLimits: MOCK_CAPACITY,
    sourceModel: null,
  });
  const licenseFinding = result.findings.find(f => f.element === 'license/no-tier');
  assert(licenseFinding !== undefined, 'license/no-tier finding exists');
  assert(licenseFinding.severity === 'info', 'severity is info');
});

test('Warn-only mode: IDP on Base → warning severity, no stripping, filteredCommands null', () => {
  const srxOutput = 'set services idp active-policy recommended';
  const result = runValidation({
    intermediateConfig: EMPTY_IC,
    conversionOutput: setOutput(srxOutput || 'set system host-name validation-fixture'),
    targetModel: null,
    srxLicense: 'Base',
    enforceLicense: false,
    modelDb: MOCK_MODEL_DB,
    capacityLimits: MOCK_CAPACITY,
    sourceModel: null,
  });
  const idpFinding = result.findings.find(f => f.element === 'license/A1');
  assert(idpFinding !== undefined, 'license/A1 finding exists');
  assert(idpFinding.severity === 'warning', 'severity is warning in warn-only mode');
  // strippedCommands tracks offending commands even in warn-only; output is not filtered
  assert(result.filteredCommands === null, 'filteredCommands is null in warn-only mode');
});

test('Enforce mode: IDP on Base → unsupported severity, 1 stripped command, filteredCommands without IDP', () => {
  const srxOutput = [
    'set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24',
    'set services idp active-policy recommended',
  ].join('\n');
  const result = runValidation({
    intermediateConfig: EMPTY_IC,
    conversionOutput: setOutput(srxOutput || 'set system host-name validation-fixture'),
    targetModel: null,
    srxLicense: 'Base',
    enforceLicense: true,
    modelDb: MOCK_MODEL_DB,
    capacityLimits: MOCK_CAPACITY,
    sourceModel: null,
  });
  const idpFinding = result.findings.find(f => f.element === 'license/A1');
  assert(idpFinding !== undefined, 'license/A1 finding exists in enforce mode');
  assert(idpFinding.severity === 'unsupported', 'severity is unsupported in enforce mode');
  assert(result.strippedCommands.length === 1, '1 command stripped');
  assert(Array.isArray(result.filteredCommands), 'filteredCommands is an array');
  assert(!result.filteredCommands.some(command => command.includes('set services idp')), 'filteredCommands excludes IDP command');
});

test('P2 covers everything → no license gaps', () => {
  const srxOutput = [
    'set services idp active-policy recommended',
    'set security utm default-configuration',
    'set services advanced-anti-malware connection primary',
  ].join('\n');
  const result = runValidation({
    intermediateConfig: EMPTY_IC,
    conversionOutput: setOutput(srxOutput || 'set system host-name validation-fixture'),
    targetModel: null,
    srxLicense: 'P2',
    enforceLicense: true,
    modelDb: MOCK_MODEL_DB,
    capacityLimits: MOCK_CAPACITY,
    sourceModel: null,
  });
  const licenseGaps = result.findings.filter(f => f.element.startsWith('license/') && f.element !== 'license/no-tier');
  assert(licenseGaps.length === 0, 'no license gap findings for P2');
  assert(result.strippedCommands.length === 0, 'no commands stripped for P2');
});

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------
console.log(`\n========================================`);
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);
if (failed > 0) process.exit(1);

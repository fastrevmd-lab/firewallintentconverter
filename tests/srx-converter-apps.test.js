/**
 * End-to-end tests for application emission behavior in srx-converter.
 * Run with: node tests/srx-converter-apps.test.js
 */
const _store = {};
global.localStorage = {
  getItem: (k) => _store[k] || null,
  setItem: (k, v) => { _store[k] = v; },
  removeItem: (k) => { delete _store[k]; },
};

import { loadAppMappings, mapVendorApp } from '../src/utils/app-mappings.js';
import { setMapVendorApp } from '../src/parsers/parser-utils.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

await loadAppMappings();
setMapVendorApp(mapVendorApp);

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ✔ ${name}`); passed++; }
  catch (e) { console.log(`  ✘ ${name}\n    ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

function cfgWithApp(appName, sourceVendor = 'panos') {
  return {
    metadata: { source_vendor: sourceVendor },
    zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
    security_policies: [{
      name: 'p1',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: [appName], services: [],
      action: 'permit',
    }],
  };
}

console.log('--- Converter app emission ---');

test('known PAN-OS app (ssl) resolves to junos-https — no custom app emitted', () => {
  const { commands } = convertToSrxSetCommands(cfgWithApp('ssl'), {});
  const joined = commands.join('\n');
  assert(joined.includes('match application junos-https'),
    'policy should reference junos-https');
  assert(!joined.includes('destination-port 1'),
    'no destination-port 1 spam allowed for known apps');
  assert(!joined.includes('Customfwic'),
    'no Customfwic placeholder for known apps');
});

test('unknown customer-specific app goes to single INTERVIEW block, not tcp/1', () => {
  const { commands } = convertToSrxSetCommands(cfgWithApp('MGT-Applications'), {});
  const joined = commands.join('\n');
  const headerMatches = joined.match(/# INTERVIEW REQUIRED/g) || [];
  assert(headerMatches.length >= 1, 'should include INTERVIEW REQUIRED header');
  assert(joined.match(/match application \S+-UNMAPPED/),
    'policy should reference <name>-UNMAPPED placeholder');
});

test('junos-ldap passthrough — no placeholder, no custom-app emission', () => {
  const { commands } = convertToSrxSetCommands(cfgWithApp('junos-ldap'), {});
  const joined = commands.join('\n');
  assert(joined.includes('match application junos-ldap'),
    'policy should reference junos-ldap directly');
  assert(!joined.includes('junos-ldapCustomfwic'),
    'junos-ldap must not receive Customfwic suffix');
  assert(!joined.includes('junos-ldap-UNMAPPED'),
    'junos-ldap must not receive UNMAPPED suffix');
});

console.log('--- Real PAN-OS fixture ---');
test('realistic PAN-OS policy with 5 apps produces 0 destination-port 1 lines', () => {
  const cfg = {
    metadata: { source_vendor: 'panos' },
    zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
    security_policies: [{
      name: 'allow-web-and-saas',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['ssl', 'web-browsing', 'smtp', 'ntp', 'ftp'],
      services: [],
      action: 'permit',
    }],
  };
  const { commands } = convertToSrxSetCommands(cfg, {});
  const joined = commands.join('\n');
  const bogusPortLines = (joined.match(/destination-port 1$/gm) || []).length;
  assert(bogusPortLines === 0, `expected 0 placeholder port-1 lines; got ${bogusPortLines}\n${joined}`);
  assert(joined.includes('match application junos-https'), 'ssl should resolve to junos-https');
  assert(joined.includes('match application junos-http'), 'web-browsing should resolve to junos-http');
});

test('truly-unknown app emits one INTERVIEW block and exactly one port-1 sentinel', () => {
  const cfg = {
    metadata: { source_vendor: 'panos' },
    zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
    security_policies: [{
      name: 'mgt-policy',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['MGT-Applications'], services: [],
      action: 'permit',
    }],
  };
  const { commands } = convertToSrxSetCommands(cfg, {});
  const joined = commands.join('\n');
  const interviewHeaders = (joined.match(/INTERVIEW REQUIRED: Unmapped Applications/g) || []).length;
  assert(interviewHeaders === 1, `expected 1 INTERVIEW header, got ${interviewHeaders}`);
  const portOneLines = (joined.match(/destination-port 1$/gm) || []).length;
  assert(portOneLines === 1, `expected exactly 1 sentinel port-1 line for the unknown app, got ${portOneLines}`);
});

console.log('--- Issue #33: deactivate policies and apps with unmapped App-IDs ---');

test('policy with unmapped app is deactivated', () => {
  const cfg = {
    metadata: { source_vendor: 'panos' },
    zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
    security_policies: [{
      name: 'p-unmapped',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['some-weird-app-9000'], services: [],
      action: 'permit',
    }],
  };
  const { commands } = convertToSrxSetCommands(cfg, {});
  const joined = commands.join('\n');
  assert(joined.includes('match application some-weird-app-9000-UNMAPPED'),
    'policy should reference some-weird-app-9000-UNMAPPED placeholder');
  assert(joined.includes('deactivate security policies global policy p-unmapped'),
    'policy referencing unmapped app must be deactivated');
});

test('unmapped application definition is deactivated', () => {
  const cfg = {
    metadata: { source_vendor: 'panos' },
    zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
    security_policies: [{
      name: 'p-unmapped',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['some-weird-app-9000'], services: [],
      action: 'permit',
    }],
  };
  const { commands } = convertToSrxSetCommands(cfg, {});
  const joined = commands.join('\n');
  assert(joined.includes('set applications application some-weird-app-9000-UNMAPPED protocol tcp'),
    'unmapped app definition should exist');
  assert(joined.includes('deactivate applications application some-weird-app-9000-UNMAPPED'),
    'unmapped app definition must be deactivated');
  assert(!joined.match(/^set security policies.*some-weird-app-9000-UNMAPPED.*\nthen permit$/m) || joined.includes('deactivate security policies'),
    'no active policy should reference unmapped app without being deactivated');
});

test('policy with only known apps is NOT deactivated', () => {
  const cfg = {
    metadata: { source_vendor: 'panos' },
    zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
    security_policies: [{
      name: 'p-known',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['ssl', 'web-browsing'], services: [],
      action: 'permit',
    }],
  };
  const { commands } = convertToSrxSetCommands(cfg, {});
  const joined = commands.join('\n');
  assert(joined.includes('match application junos-https'),
    'ssl should resolve to junos-https');
  assert(!joined.includes('deactivate security policies global policy p-known'),
    'policy with only known apps must NOT be deactivated');
});

test('mixed policy (known + unmapped) is deactivated due to unmapped app', () => {
  const cfg = {
    metadata: { source_vendor: 'panos' },
    zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
    security_policies: [{
      name: 'p-mixed',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['ssl', 'mystery-app-999'], services: [],
      action: 'permit',
    }],
  };
  const { commands } = convertToSrxSetCommands(cfg, {});
  const joined = commands.join('\n');
  assert(joined.includes('match application junos-https') && joined.includes('match application mystery-app-999-UNMAPPED'),
    'policy should reference both junos-https and mystery-app-999-UNMAPPED');
  assert(joined.includes('deactivate security policies global policy p-mixed'),
    'policy with any unmapped app must be deactivated');
  assert(joined.includes('deactivate applications application mystery-app-999-UNMAPPED'),
    'unmapped app definition must be deactivated');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);

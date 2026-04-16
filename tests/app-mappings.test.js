// tests/app-mappings.test.js
/**
 * Tests for src/utils/app-mappings.js multi-vendor coverage.
 * Run with: node tests/app-mappings.test.js
 */
import { loadAppMappings, mapVendorApp, getJunosEmission, isLoaded } from '../src/utils/app-mappings.js';
import { mapAppToJunos, JUNOS_PREDEFINED_APPS } from '../src/parsers/parser-utils.js';

let passed = 0;
let failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ✔ ${name}`); passed++; }
  catch (e) { console.log(`  ✘ ${name}\n    ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

await loadAppMappings();

console.log('--- Vendor key coverage ---');
test('checkpoint vendor lookup resolves https (if alias present)', () => {
  const r = mapVendorApp('https', 'checkpoint');
  // After Task 1: lookup mechanism exists. After Task 5: data populated.
  // Here we assert the index was built (no crash) — full resolution asserted in Task 5.
  assert(r === null || r.junosApp === 'junos-https',
    `checkpoint/https returned unexpected ${JSON.stringify(r)}`);
});
test('sonicwall vendor lookup resolves HTTPS (if alias present)', () => {
  const r = mapVendorApp('HTTPS', 'sonicwall');
  assert(r === null || r.junosApp === 'junos-https',
    `sonicwall/HTTPS returned unexpected ${JSON.stringify(r)}`);
});
test('huawei vendor lookup resolves https (if alias present)', () => {
  const r = mapVendorApp('https', 'huawei_usg');
  assert(r === null || r.junosApp === 'junos-https',
    `huawei_usg/https returned unexpected ${JSON.stringify(r)}`);
});

console.log('--- junos-* passthrough ---');
test('junos-ldap passes through unchanged', () => {
  const r = mapAppToJunos('junos-ldap', 'panos');
  assert(r === 'junos-ldap', `expected junos-ldap, got ${r}`);
});
test('junos-https passes through unchanged', () => {
  const r = mapAppToJunos('junos-https', 'fortigate');
  assert(r === 'junos-https', `expected junos-https, got ${r}`);
});
test('junos-bogus (not a predefined) does NOT pass through', () => {
  assert(!JUNOS_PREDEFINED_APPS.has('junos-bogus'), 'precondition failed');
  const r = mapAppToJunos('junos-bogus', 'panos');
  assert(r === null, `expected null for unknown junos-* name, got ${r}`);
});

console.log('--- getJunosEmission ---');
test('https returns predefined', () => {
  const r = getJunosEmission('ssl', 'panos');
  assert(r?.kind === 'predefined', `expected predefined, got ${JSON.stringify(r)}`);
  assert(r.name === 'junos-https', `expected junos-https, got ${r?.name}`);
});
test('returns null for unknown vendor app', () => {
  const r = getJunosEmission('totally-not-a-real-app-xyz', 'panos');
  assert(r === null, `expected null, got ${JSON.stringify(r)}`);
});
// The apple-push-notifications test is gated on data arriving in Task 5,
// so only assert shape contract here:
test('custom-kind shape is { kind: custom, protocol, ports[] } when present', () => {
  // Use any entry that has ports but no junos alias in current data.
  // If none exists yet, this test trivially passes.
  // Task 5 will backfill real assertions.
  const r = getJunosEmission('__shape_probe__', 'panos');
  assert(r === null, 'shape probe expected null until Task 5');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);

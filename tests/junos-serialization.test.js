import { describe, expect, it } from 'vitest';

import {
  JunosSerializationError,
  assertSafeScalar,
  setAddressOrPrefix,
  setCommand,
  setComment,
  setEnum,
  setIdentifier,
  setInteger,
  setPort,
  setQuoted,
  setToken,
  xmlAttribute,
  xmlComment,
  xmlElementName,
  xmlText,
} from '../src/security/junos-serialization.js';

describe('Junos scalar serialization', () => {
  it.each([
    'x\ny',
    'x\ry',
    'x\0y',
    'x\u001fy',
    'x\u007fy',
    'x\u0085y',
    'x\u2028y',
    'x\u2029y',
  ])('rejects control characters without reflecting their value', value => {
    expect(() => assertSafeScalar(value, 'metadata.siteName')).toThrow(JunosSerializationError);

    try {
      assertSafeScalar(value, 'metadata.siteName');
    } catch (error) {
      expect(error).toMatchObject({
        fieldPath: 'metadata.siteName',
        valueKind: 'scalar',
      });
      expect(error.message).not.toContain(value);
    }
  });

  it('preserves printable text through context-specific escaping', () => {
    const value = 'Ops "A" \\ 東京 & <x>';

    expect(setQuoted(value, 'system_config.login_banner'))
      .toBe('"Ops \\"A\\" \\\\ 東京 & <x>"');
    expect(xmlText(value, 'system_config.login_banner'))
      .toBe('Ops &quot;A&quot; \\ 東京 &amp; &lt;x&gt;');
    expect(xmlAttribute('"<&\'', 'field')).toBe('&quot;&lt;&amp;&apos;');
  });

  it('enforces token, identifier, enum, integer, and port domains', () => {
    expect(setToken('ge-0/0/0.0', 'interfaces[0].name', /^[A-Za-z0-9_.:/-]+$/))
      .toBe('ge-0/0/0.0');
    expect(setIdentifier('Allow Web', 'security_policies[0].name')).toBe('Allow-Web');
    expect(setEnum('permit', ['permit', 'deny'], 'security_policies[0].action'))
      .toBe('permit');
    expect(setInteger('4094', { min: 1, max: 4094 }, 'vlans[0].vlan_id'))
      .toBe('4094');
    expect(setPort('443', 'service_objects[0].dst_port')).toBe('443');
    expect(() => setInteger('1</name>', { min: 0 }, 'metric'))
      .toThrow(JunosSerializationError);
    expect(() => setPort(65536, 'service_objects[0].dst_port'))
      .toThrow(JunosSerializationError);
  });

  it('accepts valid IPv4 and IPv6 addresses and prefixes', () => {
    expect(setAddressOrPrefix('192.0.2.10/32', 'address_objects[0].value'))
      .toBe('192.0.2.10/32');
    expect(setAddressOrPrefix('2001:db8::/64', 'address_objects[1].value'))
      .toBe('2001:db8::/64');
    expect(setAddressOrPrefix('::ffff:192.0.2.1', 'address_objects[2].value'))
      .toBe('::ffff:192.0.2.1');
  });

  it.each([
    '999.0.2.1',
    '192.0.2.1/33',
    '2001:db8::/129',
    '2001:::1',
    '192.0.2.1 set system root-authentication',
  ])('rejects invalid address or prefix %s', value => {
    expect(() => setAddressOrPrefix(value, 'address_objects[0].value'))
      .toThrow(JunosSerializationError);
  });

  it('builds one command from already serialized pieces', () => {
    expect(setCommand('set', ['system', 'host-name', 'edge-1']))
      .toBe('set system host-name edge-1');
    expect(setCommand('set', ['system', 'login', 'message', setQuoted('Ops team', 'banner')]))
      .toBe('set system login message "Ops team"');
    expect(() => setCommand('delete', ['system', 'host-name', 'edge-1']))
      .toThrow(JunosSerializationError);
    expect(() => setCommand('set', ['system', 'host-name', 'edge-1\nset system services ssh']))
      .toThrow(JunosSerializationError);
    expect(() => setCommand('set', ['system', 'host-name', '$(request-system-reboot)']))
      .toThrow(JunosSerializationError);
  });

  it('serializes comments without permitting line or XML-comment termination', () => {
    expect(setComment('Site: HQ', 'metadata.siteName')).toBe('# Site: HQ');
    expect(() => setComment('Site: HQ\nset system services telnet', 'metadata.siteName'))
      .toThrow(JunosSerializationError);
    const comment = xmlComment('Site --> <system/>', 'metadata.siteName');
    expect(comment).toBe('<!-- Site - -> <system/> -->');
    expect(comment.slice(4, -3)).not.toContain('--');
  });

  it('allows only explicit XML element names', () => {
    expect(xmlElementName('permit', ['permit', 'deny'], 'security_policies[0].action'))
      .toBe('permit');
    expect(() => xmlElementName(
      'permit/><system>',
      ['permit', 'deny'],
      'security_policies[0].action',
    )).toThrow(JunosSerializationError);
  });
});

import { describe, expect, it } from 'vitest';

import { validateJunosInput } from '../src/security/junos-input-validation.js';
import {
  validateSetOutput,
  validateXmlOutput,
} from '../src/security/junos-output-validation.js';

describe('Junos intermediate-input validation', () => {
  it.each([
    [{ metadata: { siteName: 'A\nset system services telnet' } }, 'metadata.siteName'],
    [{ security_policies: [{ action: 'permit/><system>' }] }, 'security_policies[0].action'],
    [{ address_objects: [{ type: 'ip-netmask', value: '192.0.2.1 set system services telnet' }] }, 'address_objects[0].value'],
    [{ service_objects: [{ port_range: '443</name>' }] }, 'service_objects[0].port_range'],
    [{ static_routes: [{ next_hop: '192.0.2.1\u2028set system services telnet' }] }, 'static_routes[0].next_hop'],
    [{ vlans: [{ vlan_id: '1</name>' }] }, 'vlans[0].vlan_id'],
  ])('rejects an invalid field at its safe path %#', (config, fieldPath) => {
    expect(() => validateJunosInput(config)).toThrow(expect.objectContaining({ fieldPath }));
  });

  it('accepts punctuation and Unicode in free text', () => {
    const config = {
      metadata: { siteName: '東京 — HQ & Ops' },
      system_config: { login_banner: 'Ops "A" \\ <notice>' },
    };

    expect(validateJunosInput(config)).toBe(config);
  });

  it('accepts valid address object domains and port expressions', () => {
    const config = {
      address_objects: [
        { type: 'ip-netmask', value: '192.0.2.10/32' },
        { type: 'range', value: '192.0.2.10-192.0.2.20' },
        { type: 'fqdn', value: 'api.example.com' },
      ],
      service_objects: [
        { port_range: '80,443,8000-8080', source_port: '1024-65535' },
      ],
    };

    expect(validateJunosInput(config)).toBe(config);
  });

  it('uses the supplied root path for non-config objects', () => {
    expect(() => validateJunosInput(
      { 'ethernet1/1': 'ge-0/0/0\nset system services telnet' },
      'interfaceMappings',
    )).toThrow(expect.objectContaining({ fieldPath: 'interfaceMappings.ethernet1/1' }));
  });

  it('allows UI metadata _analysisFindings with NUL delimiters in duplicate keys', () => {
    const config = {
      address_objects: [
        { name: 'server1', type: 'ip-netmask', value: '192.0.2.10/32' },
      ],
      _analysisFindings: [
        {
          id: 'duplicates',
          count: 1,
          items: [
            { key: 'objA\x00objB', label: 'objA / objB' },
          ],
        },
      ],
    };

    expect(validateJunosInput(config)).toBe(config);
  });

  it('allows UI metadata _review_status without validating it', () => {
    const config = {
      address_objects: [
        { name: 'server1', type: 'ip-netmask', value: '192.0.2.10/32' },
      ],
      _review_status: { reviewed: true, timestamp: 1234567890 },
    };

    expect(validateJunosInput(config)).toBe(config);
  });

  it('still validates control chars in real serializable fields', () => {
    const config = {
      address_objects: [
        { name: 'bad\x00name', type: 'ip-netmask', value: '192.0.2.10/32' },
      ],
    };

    expect(() => validateJunosInput(config)).toThrow(
      expect.objectContaining({ fieldPath: 'address_objects[0].name' }),
    );
  });
});

describe('Junos set-output validation', () => {
  it('accepts comments, blanks, supported set commands, and deactivate commands', () => {
    const commands = [
      '# Site: safe',
      '',
      'set system host-name edge-1',
      'set system login message "Ops; $(review) team"',
      'set logical-systems tenant-a security zones security-zone trust',
      'deactivate security policies from-zone trust to-zone untrust policy old',
    ];

    expect(validateSetOutput(commands)).toBe(commands);
  });

  it('accepts firewall-filter and scheduler roots emitted by the converter', () => {
    const commands = [
      'set firewall family inet filter pbf term forward then routing-instance vr-a',
      'set schedulers scheduler business-hours daily start-time 08:00 stop-time 17:00',
    ];

    expect(validateSetOutput(commands)).toBe(commands);
  });

  it.each([
    ['embedded line', ['set system host-name edge\nset system services telnet']],
    ['unterminated quote', ['set system host-name "unterminated']],
    ['semicolon outside quotes', ['set system host-name edge; set system services telnet']],
    ['substitution outside quotes', ['set system host-name $(request system reboot)']],
    ['backticks outside quotes', ['set system host-name `request-system-reboot`']],
    ['inline comment delimiter', ['set system host-name edge # injected']],
    ['unsupported verb', ['delete security policies']],
    ['unsupported top-level hierarchy', ['set groups attacker system services ssh']],
    ['root authentication', ['set system root-authentication plain-text-password-value secret']],
    ['clear-text service', ['set system services telnet']],
    ['scripts', ['set system scripts commit file attacker.slax']],
    ['nested clear-text service', ['set logical-systems tenant-a system services rlogin']],
    ['event automation', ['set event-options policy persist events UI_COMMIT']],
  ])('rejects %s', (_name, commands) => {
    expect(() => validateSetOutput(commands)).toThrow();
  });

  it('reports a one-based output line without reflecting the command', () => {
    const command = 'set system services telnet';
    try {
      validateSetOutput(['# safe', command]);
      throw new Error('expected validation to fail');
    } catch (error) {
      expect(error.fieldPath).toBe('line 2');
      expect(error.message).not.toContain(command);
    }
  });
});

describe('Junos XML-output validation', () => {
  it('accepts one supported configuration root and logical-system wrapper', () => {
    const xml = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<configuration>',
      '  <logical-systems>',
      '    <name>tenant-a</name>',
      '    <system><host-name>edge-1</host-name></system>',
      '  </logical-systems>',
      '</configuration>',
    ].join('\n');

    expect(validateXmlOutput(xml)).toBe(xml);
  });

  it('accepts firewall-filter and scheduler XML roots emitted by the converter', () => {
    const xml = '<configuration><firewall/><schedulers/></configuration>';

    expect(validateXmlOutput(xml)).toBe(xml);
  });

  it.each([
    ['DTD and entity', '<!DOCTYPE configuration [<!ENTITY x SYSTEM "file:///etc/passwd">]><configuration>&x;</configuration>'],
    ['multiple roots', '<configuration/><configuration/>'],
    ['outside-root comment', '<!-- unsafe --><configuration/>'],
    ['unsupported root hierarchy', '<configuration><groups><name>x</name></groups></configuration>'],
    ['clear-text service', '<configuration><system><services><telnet/></services></system></configuration>'],
    ['nested clear-text service', '<configuration><logical-systems><name>a</name><system><services><rlogin/></services></system></logical-systems></configuration>'],
    ['scripts', '<configuration><system><scripts><commit><file>x</file></commit></scripts></system></configuration>'],
    ['CDATA', '<configuration><![CDATA[<system/>]]></configuration>'],
    ['processing instruction', '<?evil data?><configuration/>'],
  ])('rejects %s', (_name, xml) => {
    expect(() => validateXmlOutput(xml)).toThrow();
  });

  it('rejects forbidden XML controls but permits formatting newlines', () => {
    expect(() => validateXmlOutput('<configuration>\0</configuration>')).toThrow();
    expect(validateXmlOutput('<configuration>\n</configuration>'))
      .toBe('<configuration>\n</configuration>');
  });
});

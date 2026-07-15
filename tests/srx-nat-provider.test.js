/**
 * Tests for issue #56: Provider source NAT by egress interface (multi-ISP)
 *
 * Validates that interface-type source NAT pins to the specific provider interface's
 * address when available, or falls back to generic interface NAT when the interface
 * has no static IP.
 */

import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { validateSetOutput } from '../src/security/junos-output-validation.js';

describe('Provider source NAT (issue #56)', () => {
  it('should pin interface-type source NAT to provider interface address when available', () => {
    const config = {
      name: 'provider-nat-test',
      zones: [
        { name: 'trust', interfaces: ['ge-0/0/0.0'] },
        { name: 'isp1', interfaces: ['ge-0/0/1.0'] },
      ],
      interfaces: [
        { name: 'ethernet1/17', ip: '203.0.113.2/30' },
      ],
      nat_rules: [
        {
          name: 'isp1-provider-nat',
          enabled: true,
          src_zone: 'trust',
          dst_zone: 'isp1',
          src_addresses: ['10.0.0.0/8'],
          dst_addresses: ['any'],
          translated_src: {
            type: 'interface',
            interface: 'ethernet1/17',
          },
        },
      ],
    };

    const interfaceMappings = { 'ethernet1/17': 'ge-0/0/1.0' };
    const result = convertToSrxSetCommands(config, interfaceMappings);

    // Should create a provider-specific pool with the interface's /32 address
    const poolCommand = result.commands.find(cmd =>
      cmd.includes('set security nat source pool') && cmd.includes('203.0.113.2/32')
    );
    expect(poolCommand).toBeDefined();
    expect(poolCommand).toMatch(/set security nat source pool \S+ address 203\.0\.113\.2\/32/);

    // Should use that pool instead of bare interface NAT
    const poolReferenceCommand = result.commands.find(cmd =>
      cmd.includes('then source-nat pool') && cmd.match(/pool \S+/)
    );
    expect(poolReferenceCommand).toBeDefined();

    // Should include provider comment
    const providerComment = result.commands.find(cmd =>
      cmd.includes('NAT: source translated to provider interface ge-0/0/1.0')
    );
    expect(providerComment).toBeDefined();

    // Should NOT have bare "then source-nat interface" for this rule
    const bareInterfaceNat = result.commands.find(cmd =>
      cmd.includes('then source-nat interface') && !cmd.includes('using egress interface NAT')
    );
    expect(bareInterfaceNat).toBeUndefined();

    validateSetOutput(result.commands);
  });

  it('should create distinct pools for multiple provider interfaces', () => {
    const config = {
      name: 'multi-isp-test',
      zones: [
        { name: 'trust', interfaces: ['ge-0/0/0.0'] },
        { name: 'isp1', interfaces: ['ge-0/0/1.0'] },
        { name: 'isp2', interfaces: ['ge-0/0/2.0'] },
      ],
      interfaces: [
        { name: 'ethernet1/17', ip: '203.0.113.2/30' },
        { name: 'ethernet1/18', ip: '198.51.100.2/30' },
      ],
      nat_rules: [
        {
          name: 'isp1-nat',
          enabled: true,
          src_zone: 'trust',
          dst_zone: 'isp1',
          src_addresses: ['10.0.0.0/8'],
          dst_addresses: ['any'],
          translated_src: {
            type: 'interface',
            interface: 'ethernet1/17',
          },
        },
        {
          name: 'isp2-nat',
          enabled: true,
          src_zone: 'trust',
          dst_zone: 'isp2',
          src_addresses: ['10.0.0.0/8'],
          dst_addresses: ['any'],
          translated_src: {
            type: 'interface',
            interface: 'ethernet1/18',
          },
        },
      ],
    };

    const interfaceMappings = {
      'ethernet1/17': 'ge-0/0/1.0',
      'ethernet1/18': 'ge-0/0/2.0',
    };
    const result = convertToSrxSetCommands(config, interfaceMappings);

    // Should have both provider addresses
    const isp1Pool = result.commands.find(cmd =>
      cmd.includes('address 203.0.113.2/32')
    );
    const isp2Pool = result.commands.find(cmd =>
      cmd.includes('address 198.51.100.2/32')
    );
    expect(isp1Pool).toBeDefined();
    expect(isp2Pool).toBeDefined();

    // Pool names should be distinct
    const poolCommands = result.commands.filter(cmd =>
      cmd.match(/^set security nat source pool \S+ address/)
    );
    expect(poolCommands.length).toBeGreaterThanOrEqual(2);

    const poolNames = poolCommands.map(cmd => {
      const match = cmd.match(/^set security nat source pool (\S+) address/);
      return match ? match[1] : null;
    }).filter(Boolean);
    const uniquePoolNames = new Set(poolNames);
    expect(uniquePoolNames.size).toBe(2);

    validateSetOutput(result.commands);
  });

  it('should fall back to interface NAT when interface has no IP', () => {
    const config = {
      name: 'no-ip-fallback-test',
      zones: [
        { name: 'trust', interfaces: ['ge-0/0/0.0'] },
        { name: 'isp-dhcp', interfaces: ['ge-0/0/1.0'] },
      ],
      interfaces: [
        { name: 'ethernet1/17', ip: '' }, // No static IP (e.g., DHCP)
      ],
      nat_rules: [
        {
          name: 'dhcp-isp-nat',
          enabled: true,
          src_zone: 'trust',
          dst_zone: 'isp-dhcp',
          src_addresses: ['10.0.0.0/8'],
          dst_addresses: ['any'],
          translated_src: {
            type: 'interface',
            interface: 'ethernet1/17',
          },
        },
      ],
    };

    const interfaceMappings = { 'ethernet1/17': 'ge-0/0/1.0' };
    const result = convertToSrxSetCommands(config, interfaceMappings);

    // Should fall back to interface NAT
    const interfaceNatCommand = result.commands.find(cmd =>
      cmd.includes('then source-nat interface')
    );
    expect(interfaceNatCommand).toBeDefined();

    // Should include caveat comment about verifying routing
    const caveatComment = result.commands.find(cmd =>
      cmd.includes('no static IP found') && cmd.includes('verify routing')
    );
    expect(caveatComment).toBeDefined();

    // Should NOT create a provider pool
    const providerPool = result.commands.find(cmd =>
      cmd.includes('provider-source-nat-pool')
    );
    expect(providerPool).toBeUndefined();

    validateSetOutput(result.commands);
  });

  it('should fall back to interface NAT when interface not in config.interfaces', () => {
    const config = {
      name: 'missing-interface-test',
      zones: [
        { name: 'trust', interfaces: ['ge-0/0/0.0'] },
        { name: 'isp1', interfaces: ['ge-0/0/1.0'] },
      ],
      interfaces: [
        // ethernet1/17 is NOT defined here
      ],
      nat_rules: [
        {
          name: 'unknown-isp-nat',
          enabled: true,
          src_zone: 'trust',
          dst_zone: 'isp1',
          src_addresses: ['10.0.0.0/8'],
          dst_addresses: ['any'],
          translated_src: {
            type: 'interface',
            interface: 'ethernet1/17',
          },
        },
      ],
    };

    const interfaceMappings = { 'ethernet1/17': 'ge-0/0/1.0' };
    const result = convertToSrxSetCommands(config, interfaceMappings);

    // Should fall back to interface NAT
    const interfaceNatCommand = result.commands.find(cmd =>
      cmd.includes('then source-nat interface')
    );
    expect(interfaceNatCommand).toBeDefined();

    // Should include caveat comment
    const caveatComment = result.commands.find(cmd =>
      cmd.includes('no static IP found')
    );
    expect(caveatComment).toBeDefined();

    validateSetOutput(result.commands);
  });

  it('should fall back to interface NAT when no interface field specified', () => {
    const config = {
      name: 'no-interface-field-test',
      zones: [
        { name: 'trust', interfaces: ['ge-0/0/0.0'] },
        { name: 'untrust', interfaces: ['ge-0/0/1.0'] },
      ],
      interfaces: [],
      nat_rules: [
        {
          name: 'generic-nat',
          enabled: true,
          src_zone: 'trust',
          dst_zone: 'untrust',
          src_addresses: ['10.0.0.0/8'],
          dst_addresses: ['any'],
          translated_src: {
            type: 'interface',
            // No interface field
          },
        },
      ],
    };

    const result = convertToSrxSetCommands(config, {});

    // Should use plain interface NAT
    const interfaceNatCommand = result.commands.find(cmd =>
      cmd.includes('then source-nat interface')
    );
    expect(interfaceNatCommand).toBeDefined();

    // Should NOT have the caveat comment (no interface specified, so no warning needed)
    const caveatComment = result.commands.find(cmd =>
      cmd.includes('no static IP found')
    );
    expect(caveatComment).toBeUndefined();

    validateSetOutput(result.commands);
  });

  it('should handle IPv6 provider interface addresses', () => {
    const config = {
      name: 'ipv6-provider-test',
      zones: [
        { name: 'trust', interfaces: ['ge-0/0/0.0'] },
        { name: 'isp-v6', interfaces: ['ge-0/0/1.0'] },
      ],
      interfaces: [
        { name: 'ethernet1/17', ipv6: '2001:db8::1/64' },
      ],
      nat_rules: [
        {
          name: 'ipv6-provider-nat',
          enabled: true,
          src_zone: 'trust',
          dst_zone: 'isp-v6',
          src_addresses: ['2001:db8:1::/48'],
          dst_addresses: ['any'],
          translated_src: {
            type: 'interface',
            interface: 'ethernet1/17',
          },
        },
      ],
    };

    const interfaceMappings = { 'ethernet1/17': 'ge-0/0/1.0' };
    const result = convertToSrxSetCommands(config, interfaceMappings);

    // Should create pool with /128 IPv6 address
    const poolCommand = result.commands.find(cmd =>
      cmd.includes('2001:db8::1/128')
    );
    expect(poolCommand).toBeDefined();

    validateSetOutput(result.commands);
  });

  it('should validate all output passes validateSetOutput', () => {
    const config = {
      name: 'full-validation-test',
      zones: [
        { name: 'trust', interfaces: ['ge-0/0/0.0'] },
        { name: 'isp1', interfaces: ['ge-0/0/1.0'] },
        { name: 'isp2', interfaces: ['ge-0/0/2.0'] },
      ],
      interfaces: [
        { name: 'ethernet1/17', ip: '203.0.113.2/30' },
        { name: 'ethernet1/18', ip: '' },
      ],
      nat_rules: [
        {
          name: 'provider-nat-with-ip',
          enabled: true,
          src_zone: 'trust',
          dst_zone: 'isp1',
          src_addresses: ['10.0.0.0/8'],
          dst_addresses: ['any'],
          translated_src: {
            type: 'interface',
            interface: 'ethernet1/17',
          },
        },
        {
          name: 'provider-nat-no-ip',
          enabled: true,
          src_zone: 'trust',
          dst_zone: 'isp2',
          src_addresses: ['10.0.0.0/8'],
          dst_addresses: ['any'],
          translated_src: {
            type: 'interface',
            interface: 'ethernet1/18',
          },
        },
      ],
    };

    const interfaceMappings = {
      'ethernet1/17': 'ge-0/0/1.0',
      'ethernet1/18': 'ge-0/0/2.0',
    };
    const result = convertToSrxSetCommands(config, interfaceMappings);

    // Should not throw
    expect(() => validateSetOutput(result.commands)).not.toThrow();
  });
});

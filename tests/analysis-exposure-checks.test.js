/**
 * Tests for exposure & dangerous-service checks (GitHub issue #30, Group A)
 * Three new checks: inbound_any, exposed_services, broad_address
 */
import { describe, test, expect } from 'vitest';
import { AnalysisEngine } from '../src/analysis/config-analyzer.js';

describe('Exposure checks (issue #30 Group A)', () => {
  describe('inbound_any', () => {
    test('flags permit from external zone with any source', () => {
      const config = {
        zones: [
          { name: 'untrust', zone_type: 'external' },
          { name: 'trust', zone_type: 'internal' },
        ],
        security_policies: [
          {
            name: 'allow-inbound',
            _rule_index: 1,
            disabled: false,
            action: 'allow',
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['10.0.0.0/8'],
            applications: [],
            services: ['any'],
          },
        ],
      };
      const result = AnalysisEngine._inboundAny(config);
      expect(result.count).toBe(1);
      expect(result.id).toBe('inbound_any');
      expect(result.items).toHaveLength(1);
      expect(result.items[0].label).toMatch(/#1 allow-inbound/);
      expect(result.description).toMatch(/1 permit rule/);
    });

    test('does not flag when source zone is internal', () => {
      const config = {
        zones: [{ name: 'trust', zone_type: 'internal' }],
        security_policies: [
          {
            name: 'allow-trust',
            _rule_index: 2,
            disabled: false,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['any'],
            applications: [],
            services: ['any'],
          },
        ],
      };
      const result = AnalysisEngine._inboundAny(config);
      expect(result.count).toBe(0);
      expect(result.description).toMatch(/No inbound any-source rules/);
    });

    test('does not flag deny rules', () => {
      const config = {
        zones: [{ name: 'untrust', zone_type: 'external' }],
        security_policies: [
          {
            name: 'deny-all',
            _rule_index: 10,
            disabled: false,
            action: 'deny',
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['any'],
            applications: [],
            services: ['any'],
          },
        ],
      };
      const result = AnalysisEngine._inboundAny(config);
      expect(result.count).toBe(0);
    });

    test('does not flag disabled rules', () => {
      const config = {
        zones: [{ name: 'untrust', zone_type: 'external' }],
        security_policies: [
          {
            name: 'disabled-rule',
            _rule_index: 5,
            disabled: true,
            action: 'allow',
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['any'],
            applications: [],
            services: ['any'],
          },
        ],
      };
      const result = AnalysisEngine._inboundAny(config);
      expect(result.count).toBe(0);
    });

    test('handles multiple external zones', () => {
      const config = {
        zones: [
          { name: 'untrust', zone_type: 'external' },
          { name: 'internet', zone_type: 'external' },
          { name: 'trust', zone_type: 'internal' },
        ],
        security_policies: [
          {
            name: 'from-internet',
            _rule_index: 3,
            disabled: false,
            action: 'allow',
            src_zones: ['internet'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['10.0.0.0/8'],
            applications: [],
            services: ['http'],
          },
        ],
      };
      const result = AnalysisEngine._inboundAny(config);
      expect(result.count).toBe(1);
    });
  });

  describe('exposed_services', () => {
    test('flags permit from external zone with risky application (ms-rdp)', () => {
      const config = {
        zones: [{ name: 'untrust', zone_type: 'external' }],
        security_policies: [
          {
            name: 'allow-rdp',
            _rule_index: 10,
            disabled: false,
            action: 'allow',
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['10.1.1.1/32'],
            applications: ['ms-rdp'],
            services: [],
          },
        ],
      };
      const result = AnalysisEngine._exposedServices(config);
      expect(result.count).toBe(1);
      expect(result.id).toBe('exposed_services');
      expect(result.items[0].label).toMatch(/ms-rdp/);
      expect(result.description).toMatch(/1/);
    });

    test('flags permit from external zone with risky service object (port 3389)', () => {
      const config = {
        zones: [{ name: 'untrust', zone_type: 'external' }],
        service_objects: [
          { name: 'svc-rdp', protocol: 'tcp', port_range: '3389' },
        ],
        security_policies: [
          {
            name: 'allow-rdp-svc',
            _rule_index: 11,
            disabled: false,
            action: 'allow',
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['10.1.1.1/32'],
            applications: [],
            services: ['svc-rdp'],
          },
        ],
      };
      const result = AnalysisEngine._exposedServices(config);
      expect(result.count).toBe(1);
      expect(result.items[0].label).toMatch(/svc-rdp/);
    });

    test('flags permit from external zone with risky port range (low end matches)', () => {
      const config = {
        zones: [{ name: 'untrust', zone_type: 'external' }],
        service_objects: [
          { name: 'ssh-range', protocol: 'tcp', port_range: '22-23' },
        ],
        security_policies: [
          {
            name: 'allow-ssh',
            _rule_index: 12,
            disabled: false,
            action: 'allow',
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['10.1.1.1/32'],
            applications: [],
            services: ['ssh-range'],
          },
        ],
      };
      const result = AnalysisEngine._exposedServices(config);
      expect(result.count).toBe(1);
    });

    test('does not flag safe web service from external zone', () => {
      const config = {
        zones: [{ name: 'untrust', zone_type: 'external' }],
        service_objects: [
          { name: 'https', protocol: 'tcp', port_range: '443' },
        ],
        security_policies: [
          {
            name: 'allow-https',
            _rule_index: 20,
            disabled: false,
            action: 'allow',
            src_zones: ['untrust'],
            dst_zones: ['dmz'],
            src_addresses: ['any'],
            dst_addresses: ['10.2.2.2/32'],
            applications: [],
            services: ['https'],
          },
        ],
      };
      const result = AnalysisEngine._exposedServices(config);
      expect(result.count).toBe(0);
      expect(result.description).toMatch(/No exposed/);
    });

    test('does not flag risky service from internal zone', () => {
      const config = {
        zones: [{ name: 'trust', zone_type: 'internal' }],
        security_policies: [
          {
            name: 'allow-ssh-internal',
            _rule_index: 15,
            disabled: false,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['10.1.1.1/32'],
            applications: ['ssh'],
            services: [],
          },
        ],
      };
      const result = AnalysisEngine._exposedServices(config);
      expect(result.count).toBe(0);
    });

    test('handles multiple risky apps in one policy', () => {
      const config = {
        zones: [{ name: 'untrust', zone_type: 'external' }],
        security_policies: [
          {
            name: 'multi-risky',
            _rule_index: 30,
            disabled: false,
            action: 'allow',
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['10.1.1.1/32'],
            applications: ['ssh', 'ms-rdp', 'telnet'],
            services: [],
          },
        ],
      };
      const result = AnalysisEngine._exposedServices(config);
      expect(result.count).toBe(1);
      expect(result.items[0].label).toMatch(/ssh|ms-rdp|telnet/);
    });

    test('does not flag application-default or any keywords', () => {
      const config = {
        zones: [{ name: 'untrust', zone_type: 'external' }],
        security_policies: [
          {
            name: 'app-default',
            _rule_index: 40,
            disabled: false,
            action: 'allow',
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['10.1.1.1/32'],
            applications: [],
            services: ['application-default'],
          },
        ],
      };
      const result = AnalysisEngine._exposedServices(config);
      expect(result.count).toBe(0);
    });
  });

  describe('broad_address', () => {
    test('flags permit with literal 0.0.0.0/0 in src_addresses', () => {
      const config = {
        security_policies: [
          {
            name: 'any-src',
            _rule_index: 50,
            disabled: false,
            action: 'allow',
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['0.0.0.0/0'],
            dst_addresses: ['10.1.1.1/32'],
            applications: [],
            services: ['http'],
          },
        ],
      };
      const result = AnalysisEngine._broadAddresses(config);
      expect(result.count).toBe(1);
      expect(result.id).toBe('broad_address');
      expect(result.items[0].label).toMatch(/any-src/);
      expect(result.items[0].label).toMatch(/source/i);
    });

    test('flags permit with address object resolving to 0.0.0.0/0', () => {
      const config = {
        address_objects: [
          { name: 'net-any', type: 'network', value: '0.0.0.0/0' },
        ],
        security_policies: [
          {
            name: 'dst-any',
            _rule_index: 51,
            disabled: false,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.0.0/24'],
            dst_addresses: ['net-any'],
            applications: [],
            services: ['http'],
          },
        ],
      };
      const result = AnalysisEngine._broadAddresses(config);
      expect(result.count).toBe(1);
      expect(result.items[0].label).toMatch(/net-any/);
      expect(result.items[0].label).toMatch(/destination/i);
    });

    test('flags permit with /8 supernet (broad prefix)', () => {
      const config = {
        address_objects: [
          { name: 'net-10', type: 'network', value: '10.0.0.0/8' },
        ],
        security_policies: [
          {
            name: 'broad-src',
            _rule_index: 52,
            disabled: false,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['net-10'],
            dst_addresses: ['192.168.1.1/32'],
            applications: [],
            services: ['http'],
          },
        ],
      };
      const result = AnalysisEngine._broadAddresses(config);
      expect(result.count).toBe(1);
      expect(result.items[0].label).toMatch(/net-10/);
    });

    test('does not flag literal "any" keyword (covered by permissive check)', () => {
      const config = {
        security_policies: [
          {
            name: 'any-keyword',
            _rule_index: 60,
            disabled: false,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['any'],
            dst_addresses: ['any'],
            applications: [],
            services: ['http'],
          },
        ],
      };
      const result = AnalysisEngine._broadAddresses(config);
      expect(result.count).toBe(0);
    });

    test('does not flag /24 network (not broad)', () => {
      const config = {
        address_objects: [
          { name: 'net-24', type: 'network', value: '10.1.1.0/24' },
        ],
        security_policies: [
          {
            name: 'specific-net',
            _rule_index: 61,
            disabled: false,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['net-24'],
            dst_addresses: ['192.168.1.1/32'],
            applications: [],
            services: ['http'],
          },
        ],
      };
      const result = AnalysisEngine._broadAddresses(config);
      expect(result.count).toBe(0);
    });

    test('flags IPv6 ::/0', () => {
      const config = {
        address_objects: [
          { name: 'ipv6-any', type: 'network', value: '::/0' },
        ],
        security_policies: [
          {
            name: 'ipv6-dst',
            _rule_index: 70,
            disabled: false,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['2001:db8::/64'],
            dst_addresses: ['ipv6-any'],
            applications: [],
            services: ['http'],
          },
        ],
      };
      const result = AnalysisEngine._broadAddresses(config);
      expect(result.count).toBe(1);
      expect(result.items[0].label).toMatch(/ipv6-any/);
    });

    test('does not flag disabled rules', () => {
      const config = {
        address_objects: [
          { name: 'net-any', type: 'network', value: '0.0.0.0/0' },
        ],
        security_policies: [
          {
            name: 'disabled-broad',
            _rule_index: 80,
            disabled: true,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['net-any'],
            dst_addresses: ['any'],
            applications: [],
            services: ['http'],
          },
        ],
      };
      const result = AnalysisEngine._broadAddresses(config);
      expect(result.count).toBe(0);
    });

    test('flags both src and dst broad in one policy (counts as one finding)', () => {
      const config = {
        address_objects: [
          { name: 'net-any', type: 'network', value: '0.0.0.0/0' },
        ],
        security_policies: [
          {
            name: 'both-broad',
            _rule_index: 90,
            disabled: false,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['0.0.0.0/0'],
            dst_addresses: ['net-any'],
            applications: [],
            services: ['http'],
          },
        ],
      };
      const result = AnalysisEngine._broadAddresses(config);
      expect(result.count).toBe(1);
      expect(result.items[0].label).toMatch(/both-broad/);
      expect(result.items[0].label).toMatch(/source|destination/i);
    });
  });
});

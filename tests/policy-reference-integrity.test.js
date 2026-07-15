import { describe, expect, it } from 'vitest';

import { findPolicyReferenceIssues } from '../src/security/policy-reference-integrity.js';

describe('findPolicyReferenceIssues', () => {
  it('returns empty map when policy references defined address object', () => {
    const config = {
      address_objects: [
        { name: 'Server-1', type: 'host', value: '192.0.2.10/32' },
      ],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_addresses: ['Server-1'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  it('flags policy with undefined address reference', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_addresses: ['GHOST-OBJ'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(1);
    expect(issues.has(0)).toBe(true);
    expect(issues.get(0).addresses).toEqual(['GHOST-OBJ']);
    expect(issues.get(0).services).toEqual([]);
  });

  it('does not flag literal addresses (any, IPv4/IPv6, prefix, range)', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_addresses: ['any'],
          dst_addresses: ['10.0.0.1'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-2',
          src_addresses: ['192.168.1.0/24'],
          dst_addresses: ['10.0.0.1-10.0.0.10'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-3',
          src_addresses: ['2001:db8::1'],
          dst_addresses: ['2001:db8::1/64'],
          services: ['any'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  it('does not flag defined address group name', () => {
    const config = {
      address_objects: [],
      address_groups: [
        { name: 'Web-Servers', members: ['192.0.2.10'] },
      ],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_addresses: ['any'],
          dst_addresses: ['Web-Servers'],
          services: ['any'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  it('flags undefined service reference', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['GHOST-SERVICE'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(1);
    expect(issues.has(0)).toBe(true);
    expect(issues.get(0).addresses).toEqual([]);
    expect(issues.get(0).services).toEqual(['GHOST-SERVICE']);
  });

  it('does not flag literal services (any, application-default, proto/port, port number)', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-2',
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['application-default'],
          applications: [],
        },
        {
          name: 'Rule-3',
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['tcp/443', 'udp/53', '8080'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  it('skips implicit policies', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Implicit-Rule',
          _implicit: true,
          src_addresses: ['GHOST-OBJ'],
          dst_addresses: ['any'],
          services: ['GHOST-SERVICE'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  it('excludes policy with only defined references from the map', () => {
    const config = {
      address_objects: [
        { name: 'Server-1', type: 'host', value: '192.0.2.10/32' },
      ],
      address_groups: [],
      service_objects: [
        { name: 'HTTP', protocol: 'tcp', port: '80' },
      ],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_addresses: ['Server-1'],
          dst_addresses: ['any'],
          services: ['HTTP'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  it('handles missing src_addresses/dst_addresses/services fields as empty arrays', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-1',
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  it('flags both undefined addresses and services in same policy', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_addresses: ['GHOST-OBJ'],
          dst_addresses: ['any'],
          services: ['GHOST-SERVICE'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(1);
    expect(issues.has(0)).toBe(true);
    expect(issues.get(0).addresses).toEqual(['GHOST-OBJ']);
    expect(issues.get(0).services).toEqual(['GHOST-SERVICE']);
  });

  it('does not flag defined service group name', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [
        { name: 'Web-Services', members: ['tcp/80', 'tcp/443'] },
      ],
      security_policies: [
        {
          name: 'Rule-1',
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['Web-Services'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  it('preserves source order of policies in map', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-0',
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-1',
          src_addresses: ['GHOST-1'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-2',
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-3',
          src_addresses: ['GHOST-3'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(2);
    const keys = Array.from(issues.keys());
    expect(keys).toEqual([1, 3]);
  });

  // Fix 2: Tighten IPv4 literal detection
  it('flags incomplete IPv4-like strings as undefined when not in address_objects', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-Partial-1',
          src_addresses: ['10'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-Partial-2',
          src_addresses: ['1.2.3'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-Partial-3',
          src_addresses: ['10-20'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(3);
    expect(issues.get(0).addresses).toEqual(['10']);
    expect(issues.get(1).addresses).toEqual(['1.2.3']);
    expect(issues.get(2).addresses).toEqual(['10-20']);
  });

  it('does not flag full IPv4 addresses and ranges as undefined', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-Full-1',
          src_addresses: ['10.0.0.1'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-Full-2',
          src_addresses: ['10.0.0.0/8'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-Full-3',
          src_addresses: ['10.0.0.1-10.0.0.10'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  // Fix 3: Tighten IPv6 literal detection
  it('flags bare hex as undefined when not in address_objects', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-Bare-Hex-1',
          src_addresses: ['abcd'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-Bare-Hex-2',
          src_addresses: ['fe80'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(2);
    expect(issues.get(0).addresses).toEqual(['abcd']);
    expect(issues.get(1).addresses).toEqual(['fe80']);
  });

  it('does not flag IPv6 addresses with colons as undefined', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-IPv6-1',
          src_addresses: ['2001:db8::1'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
        {
          name: 'Rule-IPv6-2',
          src_addresses: ['2001:db8::/32'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });

  // Fix 4: Prefer defined names over literal for services
  it('treats defined numeric service object as defined, not literal', () => {
    const config = {
      address_objects: [],
      address_groups: [],
      service_objects: [
        { name: '8080', protocol: 'tcp', port: '8080' },
      ],
      service_groups: [],
      security_policies: [
        {
          name: 'Rule-Defined-Numeric',
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['8080'],
          applications: [],
        },
      ],
    };

    const issues = findPolicyReferenceIssues(config);
    expect(issues.size).toBe(0);
  });
});

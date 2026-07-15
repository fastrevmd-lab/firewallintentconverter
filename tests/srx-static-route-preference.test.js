/**
 * Static Route Qualified Next-Hop Tests (Issue #36)
 * Tests that backup routes use qualified-next-hop with preference, not ECMP
 */

import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

describe('Static Routes: qualified-next-hop for backup routes (issue #36)', () => {
  it('should use qualified-next-hop for backup route (metrics 10 & 20)', () => {
    const config = {
      metadata: { source_vendor: 'paloalto' },
      static_routes: [
        { destination: '0.0.0.0/0', next_hop: '203.0.113.1', next_hop_type: 'ip-address', metric: 10 },
        { destination: '0.0.0.0/0', next_hop: '198.51.100.1', next_hop_type: 'ip-address', metric: 20 },
      ],
      zones: [],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      security_policies: [],
      nat_rules: [],
    };

    const result = convertToSrxSetCommands(config);
    const routeCommands = result.commands.filter(cmd => cmd.includes('routing-options static route'));

    // Should have: primary next-hop, qualified-next-hop with preference 20, NO route-level preference
    expect(routeCommands).toContain('set routing-options static route 0.0.0.0/0 next-hop 203.0.113.1');
    expect(routeCommands).toContain('set routing-options static route 0.0.0.0/0 qualified-next-hop 198.51.100.1 preference 20');
    // Should NOT have a plain next-hop for the backup
    expect(routeCommands.filter(cmd => cmd.includes('next-hop 198.51.100.1') && !cmd.includes('qualified-next-hop'))).toHaveLength(0);
    // Should NOT have route-level preference (min metric is 10, which is default)
    expect(routeCommands.filter(cmd => cmd.match(/^set routing-options static route 0\.0\.0\.0\/0 preference \d+$/))).toHaveLength(0);
  });

  it('should use route-level preference for non-default min metric (metrics 20 & 30)', () => {
    const config = {
      metadata: { source_vendor: 'paloalto' },
      static_routes: [
        { destination: '10.0.0.0/8', next_hop: '192.0.2.1', next_hop_type: 'ip-address', metric: 20 },
        { destination: '10.0.0.0/8', next_hop: '192.0.2.2', next_hop_type: 'ip-address', metric: 30 },
      ],
      zones: [],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      security_policies: [],
      nat_rules: [],
    };

    const result = convertToSrxSetCommands(config);
    const routeCommands = result.commands.filter(cmd => cmd.includes('routing-options static route 10.0.0.0/8'));

    expect(routeCommands).toContain('set routing-options static route 10.0.0.0/8 next-hop 192.0.2.1');
    expect(routeCommands).toContain('set routing-options static route 10.0.0.0/8 preference 20');
    expect(routeCommands).toContain('set routing-options static route 10.0.0.0/8 qualified-next-hop 192.0.2.2 preference 30');
    // Should NOT have plain next-hop for backup
    expect(routeCommands.filter(cmd => cmd.includes('next-hop 192.0.2.2') && !cmd.includes('qualified-next-hop'))).toHaveLength(0);
  });

  it('should preserve single route behavior: metric 10 → just next-hop', () => {
    const config = {
      metadata: { source_vendor: 'paloalto' },
      static_routes: [
        { destination: '172.16.0.0/12', next_hop: '203.0.113.10', next_hop_type: 'ip-address', metric: 10 },
      ],
      zones: [],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      security_policies: [],
      nat_rules: [],
    };

    const result = convertToSrxSetCommands(config);
    const routeCommands = result.commands.filter(cmd => cmd.includes('routing-options static route 172.16.0.0/12'));

    expect(routeCommands).toContain('set routing-options static route 172.16.0.0/12 next-hop 203.0.113.10');
    // No preference (metric 10 is default)
    expect(routeCommands.filter(cmd => cmd.includes('preference'))).toHaveLength(0);
    // No qualified-next-hop (only one route)
    expect(routeCommands.filter(cmd => cmd.includes('qualified-next-hop'))).toHaveLength(0);
  });

  it('should preserve single route behavior: metric 20 → next-hop + preference 20', () => {
    const config = {
      metadata: { source_vendor: 'paloalto' },
      static_routes: [
        { destination: '192.168.0.0/16', next_hop: '203.0.113.20', next_hop_type: 'ip-address', metric: 20 },
      ],
      zones: [],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      security_policies: [],
      nat_rules: [],
    };

    const result = convertToSrxSetCommands(config);
    const routeCommands = result.commands.filter(cmd => cmd.includes('routing-options static route 192.168.0.0/16'));

    expect(routeCommands).toContain('set routing-options static route 192.168.0.0/16 next-hop 203.0.113.20');
    expect(routeCommands).toContain('set routing-options static route 192.168.0.0/16 preference 20');
    // No qualified-next-hop (only one route)
    expect(routeCommands.filter(cmd => cmd.includes('qualified-next-hop'))).toHaveLength(0);
  });

  it('should keep equal-metric routes as ECMP (metrics 10 & 10)', () => {
    const config = {
      metadata: { source_vendor: 'paloalto' },
      static_routes: [
        { destination: '0.0.0.0/0', next_hop: '203.0.113.1', next_hop_type: 'ip-address', metric: 10 },
        { destination: '0.0.0.0/0', next_hop: '203.0.113.2', next_hop_type: 'ip-address', metric: 10 },
      ],
      zones: [],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      security_policies: [],
      nat_rules: [],
    };

    const result = convertToSrxSetCommands(config);
    const routeCommands = result.commands.filter(cmd => cmd.includes('routing-options static route 0.0.0.0/0'));

    // Both should be plain next-hop (ECMP)
    expect(routeCommands).toContain('set routing-options static route 0.0.0.0/0 next-hop 203.0.113.1');
    expect(routeCommands).toContain('set routing-options static route 0.0.0.0/0 next-hop 203.0.113.2');
    // No qualified-next-hop (equal metric = ECMP)
    expect(routeCommands.filter(cmd => cmd.includes('qualified-next-hop'))).toHaveLength(0);
    // No route-level preference (metric 10 is default)
    expect(routeCommands.filter(cmd => cmd.includes('preference'))).toHaveLength(0);
  });

  it('should handle VRF routes with primary+backup (routing-instances)', () => {
    const config = {
      metadata: { source_vendor: 'paloalto' },
      static_routes: [
        { destination: '10.1.0.0/16', next_hop: '172.16.1.1', next_hop_type: 'ip-address', metric: 10, vrf: 'CUST-A' },
        { destination: '10.1.0.0/16', next_hop: '172.16.1.2', next_hop_type: 'ip-address', metric: 20, vrf: 'CUST-A' },
      ],
      zones: [],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      security_policies: [],
      nat_rules: [],
    };

    const result = convertToSrxSetCommands(config);
    const routeCommands = result.commands.filter(cmd => cmd.includes('routing-instances CUST-A routing-options static route 10.1.0.0/16'));

    expect(routeCommands).toContain('set routing-instances CUST-A routing-options static route 10.1.0.0/16 next-hop 172.16.1.1');
    expect(routeCommands).toContain('set routing-instances CUST-A routing-options static route 10.1.0.0/16 qualified-next-hop 172.16.1.2 preference 20');
    // Should NOT have plain next-hop for backup
    expect(routeCommands.filter(cmd => cmd.includes('next-hop 172.16.1.2') && !cmd.includes('qualified-next-hop'))).toHaveLength(0);
    // Should NOT have route-level preference (min metric is 10)
    expect(routeCommands.filter(cmd => cmd.match(/preference \d+$/) && !cmd.includes('qualified-next-hop'))).toHaveLength(0);
  });

  it('counts each route once in the summary, including grouped backups', () => {
    const mk = (n) => ({ destination: '0.0.0.0/0', next_hop: `${n}.0.0.1`, next_hop_type: 'ip-address', metric: n * 10, vrf: '' });
    const base = { zones: [], address_objects: [], service_objects: [], security_policies: [], nat_rules: [] };
    const count = (routes) => convertToSrxSetCommands({ ...base, static_routes: routes }).summary.static_routes_converted;
    expect(count([mk(1)])).toBe(1);            // single
    expect(count([mk(1), mk(2)])).toBe(2);     // primary + 1 backup
    expect(count([mk(1), mk(2), mk(3)])).toBe(3); // primary + 2 backups (was 4 before the fix)
  });

  it('handles mixed ip-address group + discard route for same destination', () => {
    const config = {
      metadata: { source_vendor: 'paloalto' },
      static_routes: [
        { destination: '10.0.0.0/8', next_hop: '192.0.2.1', next_hop_type: 'ip-address', metric: 10 },
        { destination: '10.0.0.0/8', next_hop: '192.0.2.2', next_hop_type: 'ip-address', metric: 20 },
        { destination: '10.0.0.0/8', next_hop_type: 'discard', metric: 30 },
      ],
      zones: [],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      security_policies: [],
      nat_rules: [],
    };

    const result = convertToSrxSetCommands(config);
    const routeCommands = result.commands.filter(cmd => cmd.includes('routing-options static route 10.0.0.0/8'));

    // ip-address group: primary + qualified-next-hop backup
    expect(routeCommands).toContain('set routing-options static route 10.0.0.0/8 next-hop 192.0.2.1');
    expect(routeCommands).toContain('set routing-options static route 10.0.0.0/8 qualified-next-hop 192.0.2.2 preference 20');

    // Summary should count all 3 routes (before fix: discard was silently dropped & not counted)
    expect(result.summary.static_routes_converted).toBe(3);

    // The discard route (metric 30) is deduped from emission (destination already has a concrete
    // next-hop) and must NOT leak a route-level `preference 30`, which would corrupt the primary's
    // preference and invert the failover. Only the qualified-next-hop carries a preference.
    expect(routeCommands.filter(cmd => cmd.match(/^set routing-options static route 10\.0\.0\.0\/8 preference \d+$/))).toHaveLength(0);
  });
});

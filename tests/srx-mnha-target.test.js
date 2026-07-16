/**
 * Tests for deploymentMode dispatch and correct MNHA output (Issue #37)
 */

import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

/**
 * Base HA config for testing MNHA output correctness
 */
const baseHaConfig = {
  enabled: true,
  mode: 'active-passive',
  peer_ip: '10.255.0.2',
  local_ip: '10.255.0.1',
  priority: 200,
  ha_interfaces: [
    {
      name: 'ICL',
      interface: 'ethernet1/5',
      ip: '10.255.0.1/30'
    }
  ],
  monitoring: {
    link_groups: [
      {
        enabled: true,
        name: 'data-plane-mon',
        interfaces: ['ethernet1/1']
      }
    ]
  }
};

/**
 * Interface mappings for testing
 */
const testInterfaceMappings = {
  'ethernet1/1': 'ge-0/0/0',
  'ethernet1/5': 'ge-0/0/4'
};

describe('deploymentMode dispatch (Part A)', () => {
  it('deploymentMode: mnha — emits MNHA config (chassis high-availability)', () => {
    const config = { ha_config: baseHaConfig };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'mnha' });
    const output = result.commands.join('\n');

    // Should contain MNHA-specific config
    expect(output).toContain('set chassis high-availability local-id');
    expect(output).toContain('peer-id');
    expect(output).toContain('peer-ip 10.255.0.2');
    expect(output).toContain('services-redundancy-group 0');
    expect(output).toContain('services-redundancy-group 1 deployment-type routing');

    // Should NOT contain chassis cluster
    expect(output).not.toContain('set chassis cluster');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('deploymentMode: standalone — emits no HA config', () => {
    const config = { ha_config: baseHaConfig };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'standalone' });
    const output = result.commands.join('\n');

    // Should contain standalone comment
    expect(output).toContain('# Target: standalone — no HA/chassis-cluster/MNHA config emitted.');

    // Should NOT contain any HA config
    expect(output).not.toContain('set chassis cluster');
    expect(output).not.toContain('set chassis high-availability');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('deploymentMode: chassis-cluster — emits chassis cluster config', () => {
    const config = { ha_config: baseHaConfig };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'chassis-cluster' });
    const output = result.commands.join('\n');

    // Should contain chassis cluster
    expect(output).toContain('set chassis cluster cluster-id');
    expect(output).toContain('set chassis cluster redundancy-group 0');
    expect(output).toContain('set chassis cluster redundancy-group 1');

    // Should NOT contain MNHA
    expect(output).not.toContain('set chassis high-availability');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('auto mode (no deploymentMode, ha_type not mnha) — emits chassis cluster (existing behavior)', () => {
    const config = { ha_config: { ...baseHaConfig, ha_type: 'chassis-cluster' } };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, {});
    const output = result.commands.join('\n');

    // Should contain chassis cluster (existing default behavior)
    expect(output).toContain('set chassis cluster cluster-id');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('auto mode (no deploymentMode, ha_type=mnha) — emits MNHA (legacy behavior)', () => {
    const config = { ha_config: { ...baseHaConfig, ha_type: 'mnha' } };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, {});
    const output = result.commands.join('\n');

    // Should contain MNHA (existing ha_type path)
    expect(output).toContain('set chassis high-availability local-id');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('explicit chassis-cluster works even with no ha_config.enabled', () => {
    const config = { ha_config: { ...baseHaConfig, enabled: false } };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'chassis-cluster' });
    const output = result.commands.join('\n');

    // Should still emit chassis cluster when explicitly requested
    expect(output).toContain('set chassis cluster cluster-id');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('explicit mnha works even when source has no HA', () => {
    const config = {}; // No ha_config at all
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'mnha' });
    const output = result.commands.join('\n');

    // Should emit MNHA with defaults
    expect(output).toContain('set chassis high-availability local-id');
    expect(output).toContain('services-redundancy-group 0');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });
});

describe('Correct MNHA output (Part B)', () => {
  it('emits mandatory activeness-probe with dest-ip and src-ip', () => {
    const config = {
      ha_config: {
        ...baseHaConfig,
        activeness_probe_dest: '192.168.100.1',
        activeness_probe_src: '192.168.100.2'
      }
    };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'mnha' });
    const output = result.commands.join('\n');

    // Should contain activeness-probe with both dest-ip and src-ip
    expect(output).toMatch(/set chassis high-availability services-redundancy-group 1 activeness-probe dest-ip 192\.168\.100\.1 src-ip 192\.168\.100\.2/);

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('uses placeholder activeness-probe IPs when not provided and emits warning', () => {
    const config = { ha_config: baseHaConfig };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'mnha' });
    const output = result.commands.join('\n');

    // Should contain placeholder IPs (192.0.2.0/24 documentation range)
    expect(output).toMatch(/set chassis high-availability services-redundancy-group 1 activeness-probe dest-ip 192\.0\.2\.1 src-ip 192\.0\.2\.2/);

    // Should have caveat comment
    expect(output).toContain('# CAVEAT: activeness-probe uses placeholder IPs — set to a REAL reachable data-segment address (not the ICL); mandatory for deployment-type routing.');

    // Should have a warning about placeholder probe
    expect(result.warnings.some(w => w.element && w.element.includes('placeholder'))).toBe(true);

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('uses SRG monitor-object syntax instead of chassis-cluster interface-monitor', () => {
    const config = { ha_config: baseHaConfig };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'mnha' });
    const output = result.commands.join('\n');

    // Should contain monitor-object syntax
    expect(output).toMatch(/set chassis high-availability services-redundancy-group 1 monitor monitor-object mon-ge-0-0-0 interface interface-name ge-0\/0\/0 weight 100/);
    expect(output).toMatch(/set chassis high-availability services-redundancy-group 1 monitor monitor-object mon-ge-0-0-0 interface threshold 100/);
    expect(output).toMatch(/set chassis high-availability services-redundancy-group 1 monitor monitor-object mon-ge-0-0-0 object-threshold 100/);
    expect(output).toMatch(/set chassis high-availability services-redundancy-group 1 monitor srg-threshold 100/);

    // Should NOT contain chassis-cluster interface-monitor
    expect(output).not.toMatch(/interface-monitor ge-0\/0\/0 weight/);

    // Should have caveat
    expect(output).toContain('# CAVEAT: chassis-cluster interface-monitor weights were NOT ported 1:1 — SRG monitoring redesigned; re-validate failover.');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('emits ICL security zone with system-services high-availability', () => {
    const config = { ha_config: baseHaConfig };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'mnha' });
    const output = result.commands.join('\n');

    // Should contain ICL zone for the ICL interface (ge-0/0/4.0 unit 0)
    expect(output).toMatch(/set security zones security-zone ICL interfaces ge-0\/0\/4\.0/);
    expect(output).toContain('set security zones security-zone ICL host-inbound-traffic system-services high-availability');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('emits MNHA caveats (flat model, reboot-gated, node-local)', () => {
    const config = { ha_config: baseHaConfig };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'mnha' });
    const output = result.commands.join('\n');

    // Should contain the three caveats
    expect(output).toContain('# CAVEAT: flat MNHA config model targets Junos <= 24.x; Junos 26.x requires the GRID model (grid-id/local-domain-id/peer-domain-id) + reboot — verify against the target release.');
    expect(output).toContain('# CAVEAT: enabling chassis high-availability is reboot-gated (may need two cycles) to activate.');
    expect(output).toContain('# CAVEAT: this is NODE-LOCAL config for one node; the peer node mirrors it with swapped local/peer IDs + IPs and a lower activeness-priority. MNHA does not auto-sync full config.');

    // Should have a general warning
    expect(result.warnings.some(w => w.element && w.element.includes('node-local scaffold'))).toBe(true);

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('complete MNHA output with all correctness elements', () => {
    const config = { ha_config: baseHaConfig };
    const result = convertToSrxSetCommands(config, testInterfaceMappings, null, { deploymentMode: 'mnha' });
    const output = result.commands.join('\n');

    // Check for all required elements
    expect(output).toContain('set chassis high-availability local-id');
    expect(output).toContain('peer-id');
    expect(output).toContain('peer-ip 10.255.0.2');
    expect(output).toContain('peer-id 2 interface ge-0/0/4');
    expect(output).toContain('services-redundancy-group 0 peer-id 2');
    expect(output).toContain('services-redundancy-group 1 deployment-type routing');
    expect(output).toContain('services-redundancy-group 1 activeness-priority');
    expect(output).toMatch(/activeness-probe dest-ip.*src-ip/);
    expect(output).toMatch(/monitor monitor-object.*interface interface-name/);
    expect(output).toContain('security-zone ICL');
    expect(output).toContain('host-inbound-traffic system-services high-availability');

    // Basic syntax check (starts with set or #)
    expect(result.commands.every(cmd => cmd.startsWith('set ') || cmd.startsWith('#') || cmd.trim() === '')).toBe(true);
  });

  it('does not emit a dangling ICL vpn-profile by default (only when explicitly set)', () => {
    const cfg = { zones: [], security_policies: [], service_objects: [], address_objects: [], address_groups: [], nat_rules: [],
      ha_config: { enabled: true, peer_ip: '10.255.0.2', local_ip: '10.255.0.1', priority: 200, ha_interfaces: [{ interface: 'ethernet1/5' }], monitoring: { link_groups: [] } } };
    const noVpn = convertToSrxSetCommands(cfg, { 'ethernet1/5': 'ge-0/0/4' }, null, { deploymentMode: 'mnha' });
    expect(noVpn.commands.filter(l => l.includes('vpn-profile'))).toHaveLength(0);
    const cfg2 = { ...cfg, ha_config: { ...cfg.ha_config, vpn_profile: 'MY-ICL-VPN' } };
    const withVpn = convertToSrxSetCommands(cfg2, { 'ethernet1/5': 'ge-0/0/4' }, null, { deploymentMode: 'mnha' });
    expect(withVpn.commands.some(l => l.includes('vpn-profile MY-ICL-VPN'))).toBe(true);
    expect(withVpn.commands.some(l => /CAVEAT.*vpn-profile/.test(l))).toBe(true);
  });


  it('emits SRG1 deployment-type/activeness-priority/activeness-probe once for multi-node MNHA', () => {
    const cfg = { zones: [], security_policies: [], service_objects: [], address_objects: [], address_groups: [], nat_rules: [],
      ha_config: { enabled: true, node_count: 3, local_id: 1, local_ip: '10.255.0.1', priority: 200, peer_id: 2, peer_ip: '10.255.0.2',
        ha_interfaces: [{ interface: 'ethernet1/5' }], additional_peers: [{ peer_id: 3, peer_ip: '10.255.0.3', icl_interface: 'ethernet1/6' }], monitoring: { link_groups: [] } } };
    const o = convertToSrxSetCommands(cfg, { 'ethernet1/5': 'ge-0/0/4', 'ethernet1/6': 'ge-0/0/5' }, null, { deploymentMode: 'mnha' });
    const setLines = o.commands.filter(l => l.startsWith('set '));
    expect(setLines.filter(l => /services-redundancy-group 1 deployment-type/.test(l))).toHaveLength(1);
    expect(setLines.filter(l => /services-redundancy-group 1 activeness-priority/.test(l))).toHaveLength(1);
    expect(setLines.filter(l => /services-redundancy-group 1 activeness-probe/.test(l))).toHaveLength(1);
    // peer associations ARE per-peer
    expect(setLines.filter(l => /services-redundancy-group 1 peer-id/.test(l))).toHaveLength(2);
    expect(setLines.filter(l => /services-redundancy-group 0 peer-id/.test(l))).toHaveLength(2);
  });

});

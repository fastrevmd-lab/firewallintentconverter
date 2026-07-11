import fs from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  convertMergedToSrxSetCommands,
  convertToSrxSetCommands,
} from '../src/converters/srx-converter.js';
import { JunosSerializationError } from '../src/security/junos-serialization.js';
import { validateSetOutput } from '../src/security/junos-output-validation.js';

function baseConfig() {
  return {
    metadata: { source_vendor: 'panos' },
    system_config: {
      hostname: 'edge-1',
      login_banner: 'Authorized "Ops" \\ 東京',
    },
    zones: [
      { name: 'trust', interfaces: [] },
      { name: 'untrust', interfaces: [] },
    ],
    address_objects: [{
      name: 'web',
      type: 'ip-netmask',
      value: '192.0.2.10/32',
      description: 'Web & API',
    }],
    security_policies: [{
      name: 'allow-web',
      description: 'Owner: "Blue Team" \\ primary',
      src_zones: ['trust'],
      dst_zones: ['untrust'],
      src_addresses: ['any'],
      dst_addresses: ['web'],
      applications: ['junos-https'],
      services: [],
      action: 'permit',
    }],
  };
}

describe('set converter injection defense', () => {
  it('escapes printable quoted text and returns structurally valid output', () => {
    const { commands } = convertToSrxSetCommands(baseConfig());
    const joined = commands.join('\n');

    expect(joined).toContain('login message "Authorized \\"Ops\\" \\\\ 東京"');
    expect(joined).toContain('description "Owner: \\"Blue Team\\" \\\\ primary"');
    expect(validateSetOutput(commands)).toBe(commands);
  });

  it.each([
    ['metadata.siteName', config => { config.metadata.siteName = 'HQ\nset system services telnet'; }],
    ['system_config.hostname', config => { config.system_config.hostname = 'edge set system services telnet'; }],
    ['address_objects[0].description', config => { config.address_objects[0].description = 'x\u2028set system services telnet'; }],
    ['security_policies[0].action', config => { config.security_policies[0].action = 'permit deactivate system'; }],
    ['security_policies[0].name', config => { config.security_policies[0].name = 'p\rset system root-authentication'; }],
    ['address_objects[0].value', config => { config.address_objects[0].value = '192.0.2.1 set system services telnet'; }],
    ['interfaces[0].ip', config => { config.interfaces = [{ name: 'ethernet1/1', ip: '192.0.2.1/24 set system services telnet' }]; }],
    ['service_objects[0].protocol', config => { config.service_objects = [{ name: 'web', protocol: 'tcp set system services telnet', port_range: '443' }]; }],
    ['bgp_config[0].peer_groups[0].neighbors[0].address', config => {
      config.bgp_config = [{ peer_groups: [{ name: 'upstream', type: 'external', neighbors: [{ address: '192.0.2.1 set system services telnet' }] }] }];
    }],
    ['vpn_tunnels[0].ike_gateway.address', config => {
      config.vpn_tunnels = [{ name: 'branch', ike_gateway: { external_interface: 'ge-0/0/0.0', address: '192.0.2.1 set system services telnet' } }];
    }],
    ['ha_config.group_id', config => { config.ha_config = { enabled: true, group_id: '1 set system services telnet' }; }],
    ['nat_rules[0].match_port', config => {
      config.nat_rules = [{ name: 'dnat', type: 'destination', src_zones: ['untrust'], dst_zones: ['trust'], dst_addresses: ['any'], match_port: '443 set system services telnet' }];
    }],
    ['flow_monitoring_config.collectors[0].address', config => {
      config.flow_monitoring_config = { collectors: [{ address: '192.0.2.1 set system services telnet', port: 2055 }] };
    }],
    ['system_config.domain_name', config => { config.system_config.domain_name = 'example.com set system services telnet'; }],
    ['schedules[0].days[0]', config => { config.schedules = [{ name: 'hours', type: 'recurring', days: ['monday set system services telnet'], start: '08:00', end: '17:00' }]; }],
    ['ospf_config[0].router_id', config => { config.ospf_config = [{ router_id: '192.0.2.1 set system services telnet', areas: [] }]; }],
    ['syslog_config[0].server', config => { config.syslog_config = [{ server: 'logs.example.com set system services telnet', transport: 'udp' }]; }],
    ['aaa_config[0].server', config => { config.aaa_config = [{ type: 'radius', server: '192.0.2.1 set system services telnet', port: 1812 }]; }],
    ['snmp_config[0].clients[0]', config => { config.snmp_config = [{ type: 'community', name: 'monitor', clients: ['192.0.2.1/32 set system services telnet'] }]; }],
    ['dhcp_config[0].network', config => { config.dhcp_config = [{ type: 'pool', name: 'lan', network: '192.0.2.0/24 set system services telnet' }]; }],
    ['qos_config[0].transmit_rate', config => { config.qos_config = [{ type: 'scheduler', name: 'gold', transmit_rate: '1g set system services telnet' }]; }],
    ['bridge_domains[0].vlan_id', config => { config.bridge_domains = [{ name: 'users', vlan_id: '10 set system services telnet' }]; }],
    ['pbf_rules[0].next_hop_value', config => { config.pbf_rules = [{ name: 'route', action: 'forward', next_hop_value: '192.0.2.1 set system services telnet' }]; }],
    ['evpn_config[0].route_distinguisher', config => { config.evpn_config = [{ route_distinguisher: '192.0.2.1:1 set system services telnet' }]; }],
    ['vxlan_config[0].vtep_source_interface', config => { config.vxlan_config = [{ vtep_source_interface: 'lo0.0 set system services telnet', vnis: [] }]; }],
    ['ha_config.local_ip', config => { config.ha_config = { enabled: true, ha_type: 'mnha', local_ip: '192.0.2.1 set system services telnet' }; }],
    ['screen_config[0].tcp.syn_flood_threshold', config => { config.screen_config = [{ name: 'edge', tcp: { syn_flood_threshold: '10 set system services telnet' } }]; }],
    ['l2_interfaces[0].name', config => { config.l2_interfaces = [{ name: 'ge-0/0/0.10 set system services telnet' }]; }],
    ['nat_rules[0].translated_src.address', config => {
      config.nat_rules = [{ name: 'snat', type: 'source', src_zones: ['trust'], dst_zones: ['untrust'], src_addresses: ['any'], dst_addresses: ['any'], translated_src: { type: 'static', address: '192.0.2.1 set system services telnet' } }];
    }],
    ['security_profile_definitions.dns-security:strict.blockedDomains[0]', config => {
      config.security_policies[0].security_profiles = { 'dns-security': 'strict' };
      config.security_profile_definitions = { 'dns-security:strict': { blockedDomains: ['bad.example set system services telnet'] } };
    }],
  ])('blocks an attack at %s without reflecting its value', (fieldPath, mutate) => {
    const config = baseConfig();
    mutate(config);

    try {
      convertToSrxSetCommands(config);
      throw new Error('expected conversion to fail');
    } catch (error) {
      expect(error).toMatchObject({
        name: 'JunosSerializationError',
        fieldPath,
      });
      expect(error.message).not.toContain('set system');
    }
  });

  it('validates target context before adding a hierarchy wrapper', () => {
    expect(() => convertToSrxSetCommands(
      baseConfig(),
      {},
      { type: 'logical-system', name: 'tenant\nset system services telnet' },
    )).toThrow(expect.objectContaining({ fieldPath: 'targetContext.name' }));
    expect(() => convertToSrxSetCommands(
      baseConfig(),
      {},
      { type: 'logical-system set system services telnet', name: 'tenant-a' },
    )).toThrow(expect.objectContaining({ fieldPath: 'targetContext.type' }));
  });

  it('validates user-supplied SRX interface mappings', () => {
    expect(() => convertToSrxSetCommands(
      baseConfig(),
      { 'ethernet1/1': 'ge-0/0/0.0 set system services telnet' },
    )).toThrow(expect.objectContaining({ fieldPath: 'interfaceMappings.ethernet1/1' }));
  });

  it('validates merged slot names and cross-link numeric fields', () => {
    const unsafeSlots = [{
      lsName: 'tenant\nset system services telnet',
      intermediateConfig: baseConfig(),
      interfaceMappings: {},
    }];
    expect(() => convertMergedToSrxSetCommands(unsafeSlots))
      .toThrow(JunosSerializationError);

    const safeSlots = [{
      lsName: 'tenant-a',
      intermediateConfig: baseConfig(),
      interfaceMappings: {},
    }];
    const unsafeLinks = [{
      ls1: 'tenant-a',
      ls2: 'tenant-b',
      sharedZone: 'shared',
      lt1Unit: '1 set system services telnet',
      lt2Unit: 2,
    }];
    expect(() => convertMergedToSrxSetCommands(safeSlots, unsafeLinks))
      .toThrow(expect.objectContaining({ fieldPath: 'crossLsLinks[0].lt1Unit' }));
  });

  it('keeps valid advanced converter domains compatible with final validation', () => {
    const config = baseConfig();
    Object.assign(config, {
      system_config: {
        ...config.system_config,
        domain_name: 'example.com',
        dns_servers: ['192.0.2.53'],
        ntp_servers: ['time.example.com'],
        timezone: 'America/New_York',
      },
      interfaces: [{ name: 'ethernet1/1', ip: '192.0.2.1/24' }],
      service_objects: [{ name: 'flow', protocol: 'netflow-v9', port_range: '2055' }],
      schedules: [{ name: 'hours', type: 'recurring', days: ['Mon'], start: '08:00', end: '17:00' }],
      static_routes: [{ destination: '0.0.0.0/0', next_hop: '192.0.2.254', metric: 10 }],
      bgp_config: [{
        local_as: 64512,
        router_id: '192.0.2.1',
        peer_groups: [{ type: 'external', name: 'upstream', neighbors: [{ address: '198.51.100.1', peer_as: 64496, description: 'Transit "A"' }] }],
      }],
      ospf_config: [{
        router_id: '192.0.2.1',
        areas: [{ area_id: '0.0.0.0', area_type: 'normal', interfaces: [{ name: 'ethernet1/1', cost: 10 }] }],
      }],
      evpn_config: [{
        instance: 'fabric',
        instance_type: 'virtual-switch',
        encapsulation: 'vxlan',
        route_distinguisher: '192.0.2.1:1',
        vrf_target: 'target:64512:1',
        vtep_source_interface: 'lo0.0',
        extended_vni_list: [10010],
      }],
      vxlan_config: [{ vtep_source_interface: 'lo0.0', udp_port: 4789, vnis: [{ vni: 10010, vlan_id: 10, remote_vteps: ['198.51.100.10'] }] }],
      ha_config: { enabled: true, group_id: 1, priority: 200, ha_interfaces: [] },
      screen_config: [{ name: 'edge', tcp: { syn_flood_threshold: 1000 } }],
      vpn_tunnels: [{
        name: 'branch',
        tunnel_interface: 'st0.1',
        ike_gateway: { name: 'branch', external_interface: 'ge-0/0/0.0', address: '198.51.100.2', ike_version: 'v2' },
        ike_proposal: { name: 'ike', auth_method: 'pre-shared-keys', dh_group: 'group14', encryption: 'aes-256-cbc', authentication: 'sha-256', lifetime: 28800 },
        ipsec_proposal: { name: 'ipsec', protocol: 'esp', encryption: 'aes-256-cbc', authentication: 'hmac-sha-256-128', lifetime: 3600 },
        proxy_id: [{ local: '192.0.2.0/24', remote: '198.51.100.0/24' }],
      }],
      syslog_config: [{ server: 'logs.example.com', port: 514, transport: 'udp', source_address: '192.0.2.1' }],
      aaa_config: [{ type: 'radius', server: '192.0.2.20', port: 1812, timeout: 5 }],
      snmp_config: [{ type: 'community', name: 'monitor', clients: ['192.0.2.0/24'] }],
      dhcp_config: [{ type: 'pool', name: 'lan', network: '192.0.2.0/24', gateway: '192.0.2.1', dns_servers: ['192.0.2.53'] }],
      qos_config: [{ type: 'scheduler', name: 'gold', transmit_rate: '10 percent', buffer_size: '20%' }],
      bridge_domains: [{ name: 'users', vlan_id: 10, irb_interface: 'irb.10' }],
      l2_interfaces: [{ name: 'ge-0/0/1.10', bridge_domain: 'users', vlan: 10 }],
      pbf_rules: [{ name: 'route', action: 'forward', next_hop_value: '192.0.2.254', src_addresses: ['any'], dst_addresses: ['any'], services: [], from_type: 'zone', from_value: [] }],
      flow_monitoring_config: { collectors: [{ address: '192.0.2.30', port: 2055, protocol: 'ipfix', source_address: '192.0.2.1' }], templates: [] },
    });

    const { commands } = convertToSrxSetCommands(config);
    expect(commands.length).toBeGreaterThan(50);
    expect(validateSetOutput(commands)).toBe(commands);
  });

  it('does not directly interpolate protected set free-text sites', () => {
    const source = fs.readFileSync(
      new URL('../src/converters/srx-converter.js', import.meta.url),
      'utf8',
    );

    expect(source).not.toMatch(/description \"\$\{[^}]*(?:description|comment|note|banner)/);
    expect(source).not.toMatch(/login message \"\$\{/);
    expect(source).toContain('validateSetOutput(commands)');
    expect(source).toContain('validateSetOutput(allCommands)');
  });
});

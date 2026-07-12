import { describe, expect, it } from 'vitest';

import {
  JUNOS_IDENTIFIER_MAPPING_VERSION,
  JunosIdentifierPlanningError,
  createJunosIdentifierPlan,
  planJunosIdentifiers,
  planMergedJunosIdentifiers,
  validateIdentifierMappings,
} from '../src/security/junos-identifiers.js';
import {
  JUNOS_IDENTIFIER_CATALOG,
  collectJunosIdentifierSymbols,
  collectMergedJunosIdentifierSymbols,
} from '../src/security/junos-identifier-catalog.js';

function fullConfig() {
  return {
    zones: [{ name: 'trust zone' }, { name: 'untrust zone' }],
    address_objects: [{ name: 'web host', value: '192.0.2.10' }],
    address_groups: [{ name: 'web group', members: ['web host'] }],
    service_objects: [{ name: 'custom web', protocol: 'tcp', port_range: '8080,8443' }],
    service_groups: [{ name: 'web services', members: ['custom web'] }],
    applications: [{ name: 'custom app', protocol: 'tcp', port: '9000,9001' }],
    application_groups: [{ name: 'app bundle', members: ['custom app'] }],
    schedules: [{ name: 'business hours', days: ['mon'], start: '09:00', end: '17:00' }],
    security_policies: [{
      name: 'allow web',
      src_zones: ['trust zone'],
      dst_zones: ['untrust zone'],
      src_addresses: ['web group'],
      dst_addresses: ['web host'],
      applications: ['junos-https'],
      services: ['web services'],
      schedule: 'business hours',
      action: 'allow',
      security_profiles: {
        virus: 'virus profile',
        spyware: 'spyware profile',
      },
    }],
    nat_rules: [
      {
        name: 'source web', type: 'source',
        src_zones: ['trust zone'], dst_zones: ['untrust zone'],
        src_addresses: ['web host'], dst_addresses: ['any'],
        translated_src: { type: 'dynamic-ip-pool', addresses: ['web host'] },
      },
      {
        name: 'destination web', type: 'destination',
        src_zones: ['untrust zone'], dst_zones: ['trust zone'],
        dst_addresses: ['web host'], translated_dst: { address: '192.0.2.10' },
      },
      {
        name: 'static web', type: 'static',
        src_zones: ['untrust zone'], dst_zones: ['trust zone'],
        dst_addresses: ['web host'], translated_src: { address: '192.0.2.10' },
      },
    ],
    static_routes: [{ destination: '0.0.0.0/0', next_hop: '192.0.2.1', vrf: 'blue vrf' }],
    bgp_config: [{
      instance: 'blue vrf',
      peer_groups: [{
        name: 'edge peers',
        neighbors: [{ address: '192.0.2.2', import_policy: 'IMPORT EDGE', export_policy: 'EXPORT EDGE' }],
      }],
      networks: [{ prefix: '192.0.2.0/24', policy: 'EXPORT EDGE' }],
      redistribute: [{ protocol: 'static' }],
    }],
    ospf_config: [{ instance: 'blue vrf', redistribute: [{ protocol: 'static' }] }],
    ospf3_config: [{ instance: 'blue vrf', redistribute: [{ protocol: 'direct' }] }],
    evpn_config: [{ instance: 'evpn vrf', vlans: [{ name: 'tenant vlan', vlan_id: 100, vni: 10100 }] }],
    vxlan_config: [{ instance: 'evpn vrf', name: 'overlay', vnis: [{ vni: 10200, vlan_id: 200 }] }],
    screen_config: [{ name: 'edge screen', zone: 'untrust zone', tcp: { land_attack: true } }],
    vpn_tunnels: [{
      name: 'branch vpn',
      ike_proposal: { name: 'ike proposal' },
      ike_gateway: { name: 'ike gateway', address: '198.51.100.10' },
      ipsec_proposal: { name: 'ipsec proposal' },
    }],
    external_lists: [{ name: 'bad hosts', isBlockList: true, listType: 'ip' }],
    decryption_rules: [
      { name: 'decrypt outbound', action: 'decrypt', decryption_type: 'ssl-forward-proxy', decryption_profile: 'corp tls' },
      { name: 'decrypt inbound', action: 'decrypt', decryption_type: 'ssl-inbound-inspection', decryption_profile: 'server tls' },
    ],
    bridge_domains: [{ name: 'bridge tenant', vlan_id: 300 }],
    l2_interfaces: [{ name: 'ge-0/0/1.0', bridge_domain: 'bridge tenant' }],
    vwire_pairs: [{ name: 'transparent pair', interface1: 'ge-0/0/2', interface2: 'ge-0/0/3' }],
    pbf_rules: [{
      name: 'prefer isp', action: 'forward', next_hop_value: '203.0.113.1',
      src_addresses: ['web host'], dst_addresses: ['any'],
    }],
    dhcp_config: [{
      type: 'server', name: 'branch pool', network: '10.0.0.0/24',
      pools: ['10.0.0.10-10.0.0.20'], ranges: [{ name: 'printers', low: '10.0.0.30', high: '10.0.0.40' }],
    }],
    qos_config: [
      { type: 'scheduler', name: 'voice scheduler' },
      { type: 'shaping-profile', name: 'branch qos', classes: [{ name: 'voice class' }] },
      { type: 'interface-cos', interface: 'ge-0/0/0', scheduler_map: 'branch qos' },
      { type: 'classifier', name: 'dscp edge' },
    ],
    flow_monitoring_config: {
      instance_name: 'branch flow',
      collectors: [{ address: '192.0.2.50', protocol: 'ipfix' }],
      templates: [{ name: 'branch template' }],
    },
    aaa_config: [{ type: 'profile', name: 'admin access', authentication_order: ['radius'] }],
    snmp_config: [
      { type: 'community', name: 'monitor community' },
      { type: 'trap-group', name: 'noc traps', targets: ['192.0.2.60'] },
      { type: 'v3-user', name: 'monitor user' },
    ],
  };
}

const definition = (sourceName, definitionPath, overrides = {}) => ({
  catalogKey: 'address-book',
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  kind: 'address',
  sourceName,
  definitionPath,
  generated: false,
  role: null,
  stableParentKey: null,
  ...overrides,
});

const reference = (sourceName, referencePath, overrides = {}) => ({
  catalogKey: 'address-book',
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  compatibleKinds: ['address', 'address-set'],
  sourceName,
  referencePath,
  literals: [],
  ...overrides,
});

const validEntry = (overrides = {}) => ({
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  kind: 'address',
  sourceName: 'Web Server',
  outputName: 'Web-Server',
  definitionPath: 'address_objects[0].name',
  referencePaths: ['security_policies[0].src_addresses[0]'],
  resolution: 'unchanged',
  ...overrides,
});

const mapping = (...entries) => ({
  version: JUNOS_IDENTIFIER_MAPPING_VERSION,
  entries,
});

function capturePlanningError(callback) {
  try {
    callback();
  } catch (error) {
    expect(error).toBeInstanceOf(JunosIdentifierPlanningError);
    return error;
  }
  throw new Error('Expected JunosIdentifierPlanningError');
}

describe('Junos identifier allocation', () => {
  it.each([
    ['Web Server', 'Web@Server'],
    ['Web  Server', 'Web--Server'],
    ['!!!', '???'],
    ['1 edge', 'n-1-edge'],
    [`${'a'.repeat(63)}x`, `${'a'.repeat(63)}y`],
  ])('renames both definitions for %s and %s', (left, right) => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition(left, 'defs[0]'), definition(right, 'defs[1]')],
      references: [],
    });

    expect(plan.nameForDefinition('defs[0]')).not.toBe(plan.nameForDefinition('defs[1]'));
    expect(plan.mapping.entries.every(entry => entry.resolution === 'collision-renamed'))
      .toBe(true);
    expect(plan.collisionCount).toBe(2);
    expect(plan.warnings).toHaveLength(2);
    expect(plan.warnings[0]).toMatchObject({
      type: 'warning',
      category: 'identifier',
      subType: 'identifier_collision',
      suggestion: 'Review the identifier mapping before deployment.',
    });
  });

  it('preserves case-only and other non-colliding names', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition('Web', 'defs[0]'), definition('web', 'defs[1]')],
      references: [],
    });

    expect(plan.nameForDefinition('defs[0]')).toBe('Web');
    expect(plan.nameForDefinition('defs[1]')).toBe('web');
    expect(plan.mapping.entries.map(entry => entry.resolution)).toEqual([
      'unchanged',
      'unchanged',
    ]);
  });

  it('is stable when definitions and references are reordered', () => {
    const definitions = [
      definition('Web Server', 'defs.web-space'),
      definition('Web@Server', 'defs.web-at'),
      definition('Database', 'defs.database'),
    ];
    const references = [
      reference('Web Server', 'refs.web-space'),
      reference('Web@Server', 'refs.web-at'),
      reference('Outside Name', 'refs.external'),
    ];

    const forward = createJunosIdentifierPlan({ definitions, references });
    const reversed = createJunosIdentifierPlan({
      definitions: [...definitions].reverse(),
      references: [...references].reverse(),
    });

    expect(reversed.mapping).toEqual(forward.mapping);
    expect(reversed.warnings).toEqual(forward.warnings);
    for (const path of definitions.map(item => item.definitionPath)) {
      expect(reversed.nameForDefinition(path)).toBe(forward.nameForDefinition(path));
    }
    for (const path of references.map(item => item.referencePath)) {
      expect(reversed.nameForReference(path)).toBe(forward.nameForReference(path));
    }
  });

  it('keeps a singleton unchanged when it matches a first collision candidate', () => {
    const colliding = [
      definition('Web Server', 'defs.web-space'),
      definition('Web@Server', 'defs.web-at'),
    ];
    const firstPlan = createJunosIdentifierPlan({ definitions: colliding, references: [] });
    const firstCandidate = firstPlan.nameForDefinition('defs.web-space');

    const plan = createJunosIdentifierPlan({
      definitions: [...colliding, definition(firstCandidate, 'defs.singleton')],
      references: [],
    });

    expect(plan.nameForDefinition('defs.singleton')).toBe(firstCandidate);
    expect(plan.nameForDefinition('defs.web-space')).not.toBe(firstCandidate);
    expect(plan.nameForDefinition('defs.web-at')).not.toBe(firstCandidate);
  });

  it('rejects exact duplicate semantic definitions', () => {
    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Server', 'defs[0]'),
        definition('Web Server', 'defs[1]'),
      ],
      references: [],
    }));

    expect(error).toMatchObject({
      code: 'duplicate_definition',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      sourceName: 'Web Server',
      definitionPaths: ['defs[0]', 'defs[1]'],
    });
  });

  it('rejects duplicate generated stable identities before allocation', () => {
    let hashCalls = 0;
    const generated = {
      kind: 'source-nat-pool',
      generated: true,
      role: 'source-nat-pool',
      stableParentKey: 'source-rule:Web Rule',
    };

    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Pool', 'nat.rules[0]', generated),
        definition('Web@Pool', 'nat.rules[1]', generated),
      ],
      references: [],
    }, {
      hash64: () => {
        hashCalls += 1;
        return 0n;
      },
    }));

    expect(error).toMatchObject({
      code: 'duplicate_definition',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      definitionPaths: [
        'nat.rules[0]#generated:source-nat-pool',
        'nat.rules[1]#generated:source-nat-pool',
      ],
    });
    expect(hashCalls).toBe(0);
  });

  it('rejects exact source duplicates for generated definitions before allocation', () => {
    let hashCalls = 0;
    const generated = {
      kind: 'source-nat-pool',
      generated: true,
      role: 'source-nat-pool',
    };

    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Pool', 'nat.rules[0]', {
          ...generated,
          stableParentKey: 'source-rule:Web Rule',
        }),
        definition('Web Pool', 'nat.rules[1]', {
          ...generated,
          stableParentKey: 'source-rule:Other Rule',
        }),
      ],
      references: [],
    }, {
      hash64: () => {
        hashCalls += 1;
        return 0n;
      },
    }));

    expect(error).toMatchObject({
      code: 'duplicate_definition',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      sourceName: 'Web Pool',
      definitionPaths: [
        'nat.rules[0]#generated:source-nat-pool',
        'nat.rules[1]#generated:source-nat-pool',
      ],
    });
    expect(hashCalls).toBe(0);
  });

  it('rejects a reference that can bind to both an address and address set', () => {
    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Shared', 'addresses[0]'),
        definition('Shared', 'address_sets[0]', { kind: 'address-set' }),
      ],
      references: [reference('Shared', 'policies[0].src_addresses[0]')],
    }));

    expect(error).toMatchObject({
      code: 'ambiguous_reference',
      namespace: 'address-book-entry',
      sourceName: 'Shared',
      definitionPaths: ['address_sets[0]', 'addresses[0]'],
      referencePaths: ['policies[0].src_addresses[0]'],
    });
  });

  it('reserves an unresolved external reference without binding by normalized spelling', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition('Web Server', 'defs[0]')],
      references: [reference('Web@Server', 'refs[0]')],
    });

    expect(plan.nameForDefinition('defs[0]')).toBe('Web-Server');
    expect(plan.nameForReference('refs[0]')).not.toBe('Web-Server');
    expect(plan.mapping.entries).toContainEqual(expect.objectContaining({
      sourceName: 'Web@Server',
      definitionPath: null,
      referencePaths: ['refs[0]'],
      resolution: 'unresolved-collision-renamed',
    }));
    expect(plan.collisionCount).toBe(0);
  });

  it('returns explicit literals without adding mapping entries', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [],
      references: [reference('any', 'refs.any', { literals: ['any'] })],
    });

    expect(plan.nameForReference('refs.any')).toBe('any');
    expect(plan.mapping.entries).toEqual([]);
  });

  it('catalogs generated names by owner and role with auditable paths', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition('Web Pool', 'nat.rules[0]', {
        kind: 'source-nat-pool',
        generated: true,
        role: 'source-nat-pool',
        stableParentKey: 'source-rule:Web Rule',
      })],
      references: [],
    });

    expect(plan.nameForGenerated('nat.rules[0]', 'source-nat-pool')).toBe('Web-Pool');
    expect(plan.mapping.entries).toEqual([expect.objectContaining({
      definitionPath: 'nat.rules[0]#generated:source-nat-pool',
      resolution: 'generated',
    })]);
  });

  it('fails closed for every missing lookup type', () => {
    const plan = createJunosIdentifierPlan({ definitions: [], references: [] });

    for (const lookup of [
      () => plan.nameForDefinition('missing.definition'),
      () => plan.nameForReference('missing.reference'),
      () => plan.nameForGenerated('missing.owner', 'missing-role'),
    ]) {
      expect(capturePlanningError(lookup)).toMatchObject({
        code: 'missing_catalog_coverage',
      });
    }
  });

  it('retries all candidates involved in a one-round injected hash conflict', () => {
    const calls = [];
    const hash64 = input => {
      calls.push(input);
      const retry = input.split('\0').at(-1);
      if (retry === '0') return 0n;
      return input.includes('Web Server') ? 1n : 2n;
    };

    const plan = createJunosIdentifierPlan({
      definitions: [
        definition('Web Server', 'defs[0]'),
        definition('Web@Server', 'defs[1]'),
      ],
      references: [],
    }, { hash64 });

    expect(plan.nameForDefinition('defs[0]')).not.toBe(plan.nameForDefinition('defs[1]'));
    expect(calls.some(input => input.endsWith('\0' + '1'))).toBe(true);
  });

  it('throws allocation_failed after 32 complete conflict rounds', () => {
    let calls = 0;
    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Server', 'defs[0]'),
        definition('Web@Server', 'defs[1]'),
      ],
      references: [],
    }, {
      hash64: () => {
        calls += 1;
        return 0n;
      },
    }));

    expect(error).toMatchObject({
      code: 'allocation_failed',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
    });
    expect(calls).toBe(64);
  });
});

describe('Junos identifier mapping validation', () => {
  it('returns a deeply frozen defensive copy', () => {
    const original = mapping(validEntry());
    const validated = validateIdentifierMappings(original);

    expect(validated).toEqual(original);
    expect(validated).not.toBe(original);
    expect(validated.entries[0]).not.toBe(original.entries[0]);
    expect(Object.isFrozen(validated)).toBe(true);
    expect(Object.isFrozen(validated.entries)).toBe(true);
    expect(Object.isFrozen(validated.entries[0])).toBe(true);
    expect(Object.isFrozen(validated.entries[0].referencePaths)).toBe(true);

    original.entries[0].sourceName = 'Changed';
    original.entries[0].referencePaths.push('security_policies[1].src_addresses[0]');
    expect(validated.entries[0].sourceName).toBe('Web Server');
    expect(validated.entries[0].referencePaths).toEqual([
      'security_policies[0].src_addresses[0]',
    ]);
  });

  it.each([
    ['unknown version', { version: 2, entries: [] }],
    ['unknown mapping field', { version: 1, entries: [], artifact: 'secret' }],
    ['unknown entry field', mapping(validEntry({ artifact: 'secret' }))],
    ['unknown resolution', mapping(validEntry({ resolution: 'renamed' }))],
    ['unsafe scalar', mapping(validEntry({ sourceName: 'Web\nServer' }))],
    ['invalid output name', mapping(validEntry({ outputName: '1-invalid' }))],
    ['null definition path', mapping(validEntry({ definitionPath: null }))],
    ['unresolved definition path', mapping(validEntry({
      definitionPath: 'defs[0]',
      resolution: 'unresolved-reference',
    }))],
    ['unsorted reference paths', mapping(validEntry({
      referencePaths: ['refs[1]', 'refs[0]'],
    }))],
    ['duplicate reference paths', mapping(validEntry({
      referencePaths: ['refs[0]', 'refs[0]'],
    }))],
    ['unchanged output mismatch', mapping(validEntry({ outputName: 'Other' }))],
    ['collision output unchanged', mapping(validEntry({
      outputName: 'Web-Server',
      resolution: 'collision-renamed',
    }))],
  ])('rejects %s', (_label, invalidMapping) => {
    const error = capturePlanningError(() => validateIdentifierMappings(invalidMapping));
    expect(error).toMatchObject({ code: 'invalid_identifier_mapping' });
    expect(error.message).not.toContain('secret');
  });

  it('rejects duplicate semantic definitions', () => {
    const error = capturePlanningError(() => validateIdentifierMappings(mapping(
      validEntry({ definitionPath: 'defs[0]', referencePaths: [] }),
      validEntry({ definitionPath: 'defs[1]', referencePaths: [] }),
    )));

    expect(error.code).toBe('invalid_identifier_mapping');
  });

  it('rejects duplicate output names across kinds and unresolved entries', () => {
    const error = capturePlanningError(() => validateIdentifierMappings(mapping(
      validEntry({ definitionPath: 'defs[0]', referencePaths: [] }),
      validEntry({
        kind: 'address-set',
        sourceName: 'Web-Server',
        definitionPath: null,
        referencePaths: ['refs[0]'],
        resolution: 'unresolved-reference',
      }),
    )));

    expect(error.code).toBe('invalid_identifier_mapping');
  });
});

describe('Junos identifier catalog', () => {
  it('catalogs every converter namespace with exact auditable paths and contexts', () => {
    const symbols = collectJunosIdentifierSymbols(fullConfig(), {
      targetContext: { type: 'logical-system', name: 'branch a' },
    });
    const paths = new Set([
      ...symbols.definitions.map(item => item.definitionPath),
      ...symbols.references.map(item => item.referencePath),
    ]);

    expect([...paths]).toEqual(expect.arrayContaining([
      'targetContext.name',
      'zones[0].name',
      'address_objects[0].name',
      'address_groups[0].members[0]',
      'service_objects[0].name',
      'service_groups[0].members[0]',
      'applications[0].name',
      'application_groups[0].members[0]',
      'schedules[0].name',
      'security_policies[0].name',
      'security_policies[0].dst_addresses[0]',
      'nat_rules[0].name',
      'static_routes[0].vrf',
      'bgp_config[0].peer_groups[0].name',
      'screen_config[0].name',
      'vpn_tunnels[0].name',
      'external_lists[0].name',
      'decryption_rules[0].decryption_profile',
      'bridge_domains[0].name',
      'l2_interfaces[0].bridge_domain',
      'pbf_rules[0].name',
      'dhcp_config[0].name',
      'qos_config[0].name',
      'flow_monitoring_config.instance_name',
      'aaa_config[0].name',
      'snmp_config[0].name',
    ]));

    const address = symbols.definitions.find(item => item.definitionPath === 'address_objects[0].name');
    const addressSet = symbols.definitions.find(item => item.definitionPath === 'address_groups[0].name');
    expect(address).toMatchObject({ namespace: 'address-book-entry', kind: 'address' });
    expect(addressSet).toMatchObject({ namespace: 'address-book-entry', kind: 'address-set' });
    expect(addressSet.context).toBe(address.context);

    const policy = symbols.definitions.find(item => item.definitionPath === 'security_policies[0].name');
    expect(policy).toMatchObject({
      namespace: 'security-policy',
      context: expect.stringContaining('zone-pair:trust zone->untrust zone'),
    });

    const bgpGroup = symbols.definitions.find(item => item.definitionPath === 'bgp_config[0].peer_groups[0].name');
    expect(bgpGroup).toMatchObject({
      namespace: 'bgp-group',
      context: expect.stringContaining('routing-instance:blue vrf'),
    });

    expect(symbols.definitions).not.toContainEqual(expect.objectContaining({ sourceName: 'junos-https' }));
    expect(symbols.references).toContainEqual(expect.objectContaining({
      referencePath: 'security_policies[0].applications[0]',
      sourceName: 'junos-https',
      literals: expect.arrayContaining(['junos-https']),
    }));
  });

  it('catalogs current generated preferred names with owner paths and stable roles', () => {
    const symbols = collectJunosIdentifierSymbols(fullConfig(), {
      targetContext: { type: 'logical-system', name: 'branch a' },
    });

    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        sourceName: 'pool-source web',
        definitionPath: 'nat_rules[0]',
        generated: true,
        role: 'source-nat-pool',
        stableParentKey: expect.stringContaining('source web'),
      }),
      expect.objectContaining({
        sourceName: 'dnat-pool-destination web',
        definitionPath: 'nat_rules[1]',
        role: 'destination-nat-pool',
      }),
      expect.objectContaining({
        sourceName: 'ike-pol-branch-vpn',
        definitionPath: 'vpn_tunnels[0]',
        role: 'ike-policy',
      }),
      expect.objectContaining({
        sourceName: 'ipsec-pol-branch-vpn',
        definitionPath: 'vpn_tunnels[0]',
        role: 'ipsec-policy',
      }),
      expect.objectContaining({
        sourceName: 'PBF-prefer isp',
        definitionPath: 'pbf_rules[0]',
        role: 'pbf-routing-instance',
      }),
      expect.objectContaining({
        sourceName: 'ssl-fwd-corp tls',
        definitionPath: 'decryption_rules[0]',
        role: 'ssl-forward-profile',
      }),
      expect.objectContaining({
        sourceName: 'ssl-inbound-server tls',
        definitionPath: 'decryption_rules[1]',
        role: 'ssl-inbound-profile',
      }),
      expect.objectContaining({
        sourceName: 'ike proposal',
        definitionPath: 'vpn_tunnels[0].ike_proposal.name',
        generated: false,
      }),
      expect.objectContaining({
        sourceName: 'ike gateway',
        definitionPath: 'vpn_tunnels[0].ike_gateway.name',
        generated: false,
      }),
      expect.objectContaining({
        sourceName: 'ipsec proposal',
        definitionPath: 'vpn_tunnels[0].ipsec_proposal.name',
        generated: false,
      }),
    ]));

    const plan = planJunosIdentifiers(fullConfig(), {
      targetContext: { type: 'logical-system', name: 'branch a' },
    });
    expect(plan.nameForReference('service_groups[0].members[0]'))
      .toBe(plan.nameForGenerated('service_objects[0]', 'service-multi-port-set'));
    expect(plan.nameForReference('application_groups[0].members[0]'))
      .toBe(plan.nameForGenerated('applications[0]', 'application-multi-port-set'));
  });

  it('deduplicates shared NAT rule sets and catalogs PBF filter children', () => {
    const config = fullConfig();
    config.nat_rules.push({
      name: 'source api', type: 'source',
      src_zones: ['trust zone'], dst_zones: ['untrust zone'],
      translated_src: { type: 'interface' },
    });
    config.pbf_rules.push({
      name: 'prefer api', action: 'forward', next_hop_value: '203.0.113.1',
    });

    const symbols = collectJunosIdentifierSymbols(config);
    const sourceRuleSets = symbols.definitions.filter(item => (
      item.role === 'source-nat-rule-set'
      && item.sourceName === 'trust zone-to-untrust zone'
    ));
    expect(sourceRuleSets).toHaveLength(1);
    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ sourceName: 'PBF-FILTER', role: 'pbf-filter' }),
      expect.objectContaining({ sourceName: 'default', role: 'pbf-default-term' }),
      expect.objectContaining({ sourceName: 'dscp edge', namespace: 'cos-classifier' }),
    ]));
    expect(symbols.references).toContainEqual(expect.objectContaining({
      referencePath: 'pbf_rules[0].next_hop_value#routing-instance',
      sourceName: 'PBF-prefer api',
    }));
    expect(() => planJunosIdentifiers(config)).not.toThrow();
  });

  it('scopes every static NAT rule to the one STATIC-NAT rule set', () => {
    const config = {
      zones: [{ name: 'outside a' }, { name: 'outside b' }, { name: 'inside' }],
      nat_rules: [
        { name: 'static a', type: 'static', src_zones: ['outside a'], dst_zones: ['inside'] },
        { name: 'static b', type: 'static', src_zones: ['outside b'], dst_zones: ['inside'] },
      ],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const ruleSets = symbols.definitions.filter(item => item.role === 'static-nat-rule-set');
    const rules = symbols.definitions.filter(item => item.kind === 'static-nat-rule');

    expect(ruleSets).toHaveLength(1);
    expect(new Set(rules.map(item => item.context)).size).toBe(1);
    expect(() => planJunosIdentifiers(config)).not.toThrow();
  });

  it('scopes every any-zone policy to the shared global policy namespace', () => {
    const config = {
      security_policies: [
        { name: 'same global', src_zones: ['any'], dst_zones: ['dmz'] },
        { name: 'same global', src_zones: ['trust'], dst_zones: ['any'] },
      ],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const policies = symbols.definitions.filter(item => item.kind === 'security-policy');

    expect(new Set(policies.map(item => item.context)).size).toBe(1);
    expect(capturePlanningError(() => planJunosIdentifiers(config)).code)
      .toBe('duplicate_definition');

    expect(() => planJunosIdentifiers({
      security_policies: [{
        name: 'one global', src_zones: ['any'], dst_zones: ['dmz', 'outside'],
      }],
    })).not.toThrow();
  });

  it('deduplicates shared explicit VPN and SSL profile definitions', () => {
    const config = {
      vpn_tunnels: [
        {
          name: 'vpn one',
          ike_proposal: { name: 'shared ike' },
          ike_gateway: { name: 'shared gateway' },
          ipsec_proposal: { name: 'shared ipsec' },
        },
        {
          name: 'vpn two',
          ike_proposal: { name: 'shared ike' },
          ike_gateway: { name: 'shared gateway' },
          ipsec_proposal: { name: 'shared ipsec' },
        },
      ],
      decryption_rules: [
        { action: 'decrypt', decryption_type: 'ssl-forward-proxy', decryption_profile: 'shared tls' },
        { action: 'decrypt', decryption_type: 'ssl-forward-proxy', decryption_profile: 'shared tls' },
      ],
    };
    const symbols = collectJunosIdentifierSymbols(config);

    expect(symbols.definitions.filter(item => item.sourceName === 'shared ike')).toHaveLength(1);
    expect(symbols.definitions.filter(item => item.sourceName === 'ssl-fwd-shared tls')).toHaveLength(1);
    expect(() => planJunosIdentifiers(config)).not.toThrow();
  });

  it('assigns shared UTM and IDP generated names by semantic combination', () => {
    const policies = [
      { name: 'one', security_profiles: { virus: 'z av', spyware: 'strict spyware', 'application-control': 'edge apps' } },
      { name: 'two', security_profiles: { virus: 'a av', vulnerability: 'alert vuln' } },
      { name: 'three', security_profiles: { virus: 'z av', spyware: 'strict spyware', 'application-control': 'edge apps' } },
    ];
    const config = {
      security_policies: policies,
      security_profile_definitions: {
        'application-control:edge apps': { categories: { risky: 'block' } },
        'spyware:strict spyware': { severityActions: { critical: 'block' } },
      },
    };
    const forward = collectJunosIdentifierSymbols(config);
    const reversed = collectJunosIdentifierSymbols({
      ...config,
      security_policies: [policies[1], policies[0], policies[2]],
    });
    const generatedPolicies = symbols => new Map(symbols.definitions
      .filter(item => ['utm-policy', 'idp-policy'].includes(item.role))
      .map(item => [item.stableParentKey, item.sourceName]));

    expect(generatedPolicies(reversed)).toEqual(generatedPolicies(forward));
    expect(forward.references).toEqual(expect.arrayContaining([
      expect.objectContaining({ referencePath: 'security_policies[2]#utm-policy' }),
      expect.objectContaining({ referencePath: 'security_policies[2]#idp-policy' }),
      expect.objectContaining({
        referencePath: 'security_policies[0].security_profiles.virus',
        sourceName: 'custom-av-z av',
      }),
      expect.objectContaining({
        referencePath: 'security_policies[0].security_profiles.application-control',
        sourceName: 'appfw-edge apps',
      }),
    ]));
    expect(forward.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ namespace: 'application-firewall-rule', sourceName: 'appfw-r1' }),
      expect.objectContaining({ namespace: 'idp-rule', sourceName: 'spyware-critical-r1' }),
    ]));
  });

  it('preserves fallback zone field paths for policies and NAT', () => {
    const symbols = collectJunosIdentifierSymbols({
      security_policies: [{ name: 'fallback policy', source_zones: ['inside'], destination_zones: ['outside'] }],
      nat_rules: [{ name: 'fallback nat', type: 'source', source_zones: ['inside'], destination_zones: ['outside'] }],
    });
    const paths = symbols.references.map(item => item.referencePath);

    expect(paths).toEqual(expect.arrayContaining([
      'security_policies[0].source_zones[0]',
      'security_policies[0].destination_zones[0]',
      'nat_rules[0].source_zones[0]',
      'nat_rules[0].destination_zones[0]',
    ]));
  });

  it('catalogs emitter-compatible generic policy and VPN generated names', () => {
    const symbols = collectJunosIdentifierSymbols({
      security_policies: [{
        name: 'Rule-1', action: 'allow', src_zones: ['Trust Zone'],
        dst_zones: ['DMZ'], applications: ['junos-https'],
      }],
      vpn_tunnels: [{ name: '9 branch' }],
    });

    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        sourceName: 'permit-trust-zone-to-dmz-https-1',
        definitionPath: 'security_policies[0]',
        role: 'security-policy-1',
      }),
      expect.objectContaining({
        sourceName: 'ike-pol-n-9-branch',
        definitionPath: 'vpn_tunnels[0]',
        role: 'ike-policy',
      }),
    ]));
  });

  it('keeps PBF shared-next-hop identity stable when rules are reordered', () => {
    const rules = [
      { name: 'z route', action: 'forward', next_hop_value: '192.0.2.1' },
      { name: 'a route', action: 'forward', next_hop_value: '192.0.2.1' },
    ];
    const generated = symbols => symbols.definitions.find(item => item.role === 'pbf-routing-instance');
    const forward = generated(collectJunosIdentifierSymbols({ pbf_rules: rules }));
    const reversed = generated(collectJunosIdentifierSymbols({ pbf_rules: [...rules].reverse() }));

    expect(forward.sourceName).toBe('PBF-a route');
    expect(reversed.sourceName).toBe(forward.sourceName);
    expect(reversed.stableParentKey).toBe(forward.stableParentKey);
  });

  it('collects merged logical-system slots and cross-link references', () => {
    const slots = [
      { lsName: 'branch a', intermediateConfig: fullConfig(), interfaceMappings: {} },
      { lsName: 'branch b', intermediateConfig: { zones: [{ name: 'inside b' }] }, interfaceMappings: {} },
    ];
    const links = [{ ls1: 'branch a', ls2: 'branch b', sharedZone: 'transit zone' }];
    const symbols = collectMergedJunosIdentifierSymbols(slots, links);

    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ definitionPath: 'configSlots[0].lsName', sourceName: 'branch a' }),
      expect.objectContaining({ definitionPath: 'configSlots[1].lsName', sourceName: 'branch b' }),
      expect.objectContaining({ definitionPath: 'configSlots[0].intermediateConfig.zones[0].name' }),
      expect.objectContaining({ definitionPath: 'crossLsLinks[0].sharedZone', role: 'cross-link-zone-ls1' }),
      expect.objectContaining({ definitionPath: 'crossLsLinks[0].sharedZone', role: 'cross-link-zone-ls2' }),
    ]));
    expect(symbols.references).toEqual(expect.arrayContaining([
      expect.objectContaining({ referencePath: 'crossLsLinks[0].ls1', sourceName: 'branch a' }),
      expect.objectContaining({ referencePath: 'crossLsLinks[0].ls2', sourceName: 'branch b' }),
    ]));
  });

  it('exposes frozen catalog keys and deterministic public planning wrappers', () => {
    expect(Object.isFrozen(JUNOS_IDENTIFIER_CATALOG)).toBe(true);
    expect(JUNOS_IDENTIFIER_CATALOG).toMatchObject({
      TARGET_CONTEXT: 'target-context',
      ADDRESS_BOOK: 'address-book',
      POLICY: 'security-policy',
      FLOW: 'flow-monitoring',
    });

    const config = fullConfig();
    const options = { targetContext: { type: 'logical-system', name: 'branch a' } };
    const forward = planJunosIdentifiers(config, options);
    const reordered = planJunosIdentifiers({
      ...config,
      zones: [...config.zones].reverse(),
      address_objects: [...config.address_objects].reverse(),
    }, options);
    expect(reordered.mapping.entries.map(({ definitionPath, ...entry }) => entry))
      .toEqual(forward.mapping.entries.map(({ definitionPath, ...entry }) => entry));

    const merged = planMergedJunosIdentifiers([
      { lsName: 'branch a', intermediateConfig: { zones: [{ name: 'inside' }] } },
    ]);
    expect(merged.nameForDefinition('configSlots[0].lsName')).toBe('branch-a');
  });
});

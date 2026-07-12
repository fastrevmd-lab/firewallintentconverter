import { describe, expect, it } from 'vitest';

import {
  convertMergedToSrxSetCommands,
  convertToSrxSetCommands,
} from '../src/converters/srx-converter.js';
import {
  buildMergedSrxXml,
  buildSrxXml,
} from '../src/converters/srx-xml-builder.js';
import { setMapVendorApp } from '../src/parsers/parser-utils.js';
import {
  JunosIdentifierPlanningError,
  createJunosIdentifierPlan,
  planJunosIdentifiers,
  planMergedJunosIdentifiers,
} from '../src/security/junos-identifiers.js';
import { getJunosEmission, loadAppMappings, mapVendorApp } from '../src/utils/app-mappings.js';

const storage = {};
global.localStorage = {
  getItem: key => storage[key] || null,
  setItem: (key, value) => { storage[key] = value; },
  removeItem: key => { delete storage[key]; },
};

await loadAppMappings();
setMapVendorApp(mapVendorApp);

function baseConfig(overrides = {}) {
  return {
    metadata: { source_vendor: 'panos' },
    zones: [],
    address_objects: [],
    address_groups: [],
    service_objects: [],
    service_groups: [],
    applications: [],
    application_groups: [],
    schedules: [],
    security_policies: [],
    nat_rules: [],
    ...overrides,
  };
}

function policy(name, fromZone, toZone, destination, extra = {}) {
  return {
    name,
    src_zones: [fromZone],
    dst_zones: [toZone],
    src_addresses: ['any'],
    dst_addresses: [destination],
    applications: ['junos-https'],
    services: [],
    action: 'allow',
    ...extra,
  };
}

function collisionConfig() {
  return baseConfig({
    zones: [
      { name: 'trust', interfaces: [] },
      { name: 'untrust', interfaces: [] },
    ],
    address_objects: [
      { name: 'Web Server', type: 'host', value: '192.0.2.10/32' },
      { name: 'Web@Server', type: 'host', value: '192.0.2.11/32' },
    ],
    address_groups: [{
      name: 'Web Farm',
      members: ['Web Server', 'Web@Server'],
    }],
    security_policies: [
      policy('Allow Web One', 'trust', 'untrust', 'Web Server'),
      policy('Allow Web Two', 'trust', 'untrust', 'Web@Server'),
    ],
  });
}

function mergeSlot(lsName, intermediateConfig) {
  return { lsName, intermediateConfig, interfaceMappings: {} };
}

function configWithAddress(name, extra = {}) {
  return baseConfig({
    address_objects: [{ name, type: 'host', value: '192.0.2.10/32' }],
    ...extra,
  });
}

function configWithMissingNatZone(zoneName) {
  return baseConfig({
    zones: [{ name: 'outside', interfaces: [] }],
    nat_rules: [{
      name: 'Transit NAT',
      type: 'source',
      src_zones: [zoneName],
      dst_zones: ['outside'],
      src_addresses: ['any'],
      dst_addresses: ['any'],
      translated_src: { type: 'interface' },
    }],
  });
}

function stableMappingAssociations(mapping) {
  return mapping.entries.map(entry => ({
    context: entry.context,
    namespace: entry.namespace,
    kind: entry.kind,
    sourceName: entry.sourceName,
    outputName: entry.outputName,
    resolution: entry.resolution,
  })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

function genericPolicyOrderConfig() {
  const policies = [
    policy('Rule-1', 'trust', 'dmz', 'any', {
      src_zones: ['trust', 'guest'],
      dst_zones: ['dmz', 'untrust'],
      description: 'alpha semantic policy',
      applications: ['junos-https'],
    }),
    policy('', 'trust', 'dmz', 'any', {
      src_zones: ['trust', 'guest'],
      dst_zones: ['dmz', 'untrust'],
      description: 'beta semantic policy',
      applications: ['junos-ssh'],
    }),
  ];
  return baseConfig({ security_policies: policies });
}

function reversedGenericPolicyOrderConfig() {
  const config = genericPolicyOrderConfig();
  return {
    ...config,
    security_policies: [...config.security_policies].reverse().map(policyItem => ({
      ...policyItem,
      src_zones: [...policyItem.src_zones].reverse(),
      dst_zones: [...policyItem.dst_zones].reverse(),
    })),
  };
}

function sortedPolicyAssociations(associations) {
  return [...associations].sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

function setPolicyAssociations(result) {
  return sortedPolicyAssociations(result.commands.flatMap(command => {
    const match = command.match(
      /^set security policies from-zone (\S+) to-zone (\S+) policy (\S+) description "([^"]+)"$/,
    );
    return match ? [{ semantic: match[4], fromZone: match[1], toZone: match[2], outputName: match[3] }] : [];
  }));
}

function xmlPolicyAssociations(result) {
  const associations = [];
  const pairPattern = /<policy>\s*<from-zone-name>([^<]+)<\/from-zone-name>\s*<to-zone-name>([^<]+)<\/to-zone-name>([\s\S]*?)\n      <\/policy>/g;
  for (const pair of result.xml.matchAll(pairPattern)) {
    const policyPattern = /<policy>\s*<name>([^<]+)<\/name>\s*<description>([^<]+)<\/description>/g;
    for (const item of pair[3].matchAll(policyPattern)) {
      associations.push({
        semantic: item[2], fromZone: pair[1], toZone: pair[2], outputName: item[1],
      });
    }
  }
  return sortedPolicyAssociations(associations);
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state += 0x6d2b79f5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function randomToken(random, length = 8) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from(
    { length },
    () => alphabet[Math.floor(random() * alphabet.length)],
  ).join('');
}

function hostileNamePair(seed, pairIndex, random) {
  const token = randomToken(random);
  const numericPrefix = String(1 + Math.floor(random() * 9));
  const commonPrefix = `shared-${seed}-${'x'.repeat(70)}`;
  switch ((pairIndex + Math.floor(random() * 7)) % 7) {
    case 0:
      return { category: 'whitespace', names: [`${token} ${pairIndex}`, `${token}@${pairIndex}`] };
    case 1:
      return { category: 'repeated-dashes', names: [`${token}--${pairIndex}`, `${token}  ${pairIndex}`] };
    case 2:
      return { category: 'numeric-prefix', names: [`${numericPrefix} ${token}`, `${numericPrefix}@${token}`] };
    case 3:
      return { category: 'case-variant', names: [`Case${token} ${pairIndex}`, `case${token}@${pairIndex}`] };
    case 4:
      return { category: 'long-common-prefix-truncation', names: [`${commonPrefix} ${token}`, `${commonPrefix}@${token}`] };
    case 5:
      return { category: 'punctuation', names: [`!!!${token}...${pairIndex}`, `???${token}...${pairIndex}`] };
    default:
      return {
        category: 'empty-normalizing',
        names: ['!'.repeat(pairIndex + 1), '?'.repeat(pairIndex + 1)],
      };
  }
}

function makeRandomSymbols(seed) {
  const random = seededRandom(seed);
  const definitions = [];
  const references = [];
  const boundReferences = [];
  const generatedReferences = [];
  const unresolvedReferencePaths = [];
  const categoryCounts = new Map();
  const namespaces = ['address-entry', 'application-entry', 'policy', 'routing-policy'];

  for (let pairIndex = 0; pairIndex < 100; pairIndex++) {
    const { category, names } = hostileNamePair(seed, pairIndex, random);
    categoryCounts.set(category, (categoryCounts.get(category) || 0) + names.length);
    for (const [side, sourceName] of names.entries()) {
      const index = pairIndex * 2 + side;
      const namespace = namespaces[pairIndex % namespaces.length];
      const context = `root/random-context-${pairIndex % 2}`;
      const kind = `random-kind-${pairIndex % 3}`;
      const definitionPath = `seed[${seed}].definitions[${index}]`;
      const referencePath = `seed[${seed}].references[${index}]`;
      const generated = seed <= 25 && index >= 180;
      const role = generated ? `generated-child-${index}` : null;
      definitions.push({
        catalogKey: `random-${namespace}`,
        context,
        namespace,
        kind,
        sourceName,
        definitionPath,
        generated,
        role,
        stableParentKey: generated ? `seed:${seed}:owner:${index}` : null,
      });
      references.push({
        catalogKey: `random-${namespace}`,
        context,
        namespace,
        compatibleKinds: [kind],
        sourceName,
        referencePath,
        literals: [],
      });
      const binding = { definitionPath, referencePath, role };
      (generated ? generatedReferences : boundReferences).push(binding);
    }
  }

  if (seed <= 25) {
    for (let index = 0; index < 10; index++) {
      const referencePath = `seed[${seed}].unresolved[${index}]`;
      references.push({
        catalogKey: 'random-address-entry',
        context: 'root/random-context-0',
        namespace: 'address-entry',
        compatibleKinds: ['external-address'],
        sourceName: index % 2 === 0
          ? `Missing ${seed} ${Math.floor(index / 2)}`
          : `Missing@${seed}@${Math.floor(index / 2)}`,
        referencePath,
        literals: [],
      });
      unresolvedReferencePaths.push(referencePath);
    }
  }

  return {
    definitions,
    references,
    reservations: [],
    boundReferences,
    generatedReferences,
    unresolvedReferencePaths,
    categoryCounts: Object.fromEntries([...categoryCounts].sort(([left], [right]) => (
      left.localeCompare(right)
    ))),
  };
}

function reverseSymbols(symbols) {
  return {
    ...symbols,
    definitions: [...symbols.definitions].reverse(),
    references: [...symbols.references].reverse(),
    reservations: [...symbols.reservations].reverse(),
  };
}

function mappingBySource(mapping) {
  return mapping.entries.map(entry => ({
    sourceKey: [
      entry.context,
      entry.namespace,
      entry.kind,
      entry.sourceName,
      entry.definitionPath ?? '',
    ].join('\0'),
    outputName: entry.outputName,
    referencePaths: entry.referencePaths,
    resolution: entry.resolution,
  })).sort((left, right) => left.sourceKey.localeCompare(right.sourceKey));
}

function baseAdvancedConfig() {
  return baseConfig({
    zones: [
      { name: 'trust', interfaces: [] },
      { name: 'untrust', interfaces: [] },
    ],
  });
}

function addRoutingInstanceCollision(config) {
  config.static_routes = [
    { destination: '192.0.2.0/24', next_hop: '198.51.100.1', vrf: 'Blue VRF' },
    { destination: '198.51.100.0/24', next_hop: '198.51.100.2', vrf: 'Blue@VRF' },
  ];
}

function addBgpGroupCollision(config) {
  config.bgp_config = [{
    peer_groups: [
      { name: 'Edge Peers', type: 'external', neighbors: [] },
      { name: 'Edge@Peers', type: 'external', neighbors: [] },
    ],
  }];
}

function addBgpFallbackGroupCollision(config) {
  config.bgp_config = [
    { networks: [{ policy: 'EXPORT-FALLBACK' }] },
    { peer_groups: [{ name: 'BGP@PEERS', type: 'external', neighbors: [] }] },
  ];
}

function addScreenCollision(config) {
  config.screen_config = [
    { name: 'Edge Screen', tcp: { land_attack: true } },
    { name: 'Edge@Screen', tcp: { land_attack: true } },
  ];
}

function collidingVpn(separator) {
  return {
    name: `Branch${separator}VPN`,
    ike_proposal: {
      name: `IKE${separator}Proposal`,
      auth_method: 'pre-shared-keys',
      dh_group: 'group14',
      encryption: 'aes-256-cbc',
      authentication: 'sha-256',
    },
    ike_gateway: {
      name: `IKE${separator}Gateway`,
      external_interface: 'ge-0/0/0.0',
      address: separator === ' ' ? '198.51.100.1' : '198.51.100.2',
    },
    ipsec_proposal: {
      name: `IPsec${separator}Proposal`,
      protocol: 'esp',
      encryption: 'aes-256-cbc',
      authentication: 'hmac-sha-256-128',
    },
  };
}

function addVpnCollision(config) {
  config.vpn_tunnels = [collidingVpn(' '), collidingVpn('@')];
}

function addSnmpCollision(config) {
  config.snmp_config = [
    { type: 'community', name: 'Monitor Community' },
    { type: 'community', name: 'Monitor@Community' },
  ];
}

function addDhcpCollision(config) {
  config.dhcp_config = [
    { type: 'pool', name: 'Branch Pool', network: '10.0.0.0/24' },
    { type: 'pool', name: 'Branch@Pool', network: '10.0.1.0/24' },
  ];
}

function addBridgeDomainCollision(config) {
  config.bridge_domains = [
    { name: 'Tenant Bridge', vlan_id: 100 },
    { name: 'Tenant@Bridge', vlan_id: 200 },
  ];
}

function addPbfCollision(config) {
  config.pbf_rules = [
    { name: 'Prefer ISP', action: 'discard', src_addresses: ['any'], dst_addresses: ['any'] },
    { name: 'Prefer@ISP', action: 'discard', src_addresses: ['any'], dst_addresses: ['any'] },
  ];
}

function addFlowTemplateCollision(config) {
  config.flow_monitoring_config = {
    instance_name: 'FLOW-SAMPLE',
    collectors: [
      { address: '192.0.2.10', protocol: 'ipfix' },
      { address: '192.0.2.11', protocol: 'ipfix' },
    ],
    templates: [
      { name: 'Branch Template', active_timeout: 60, refresh_rate: 1000 },
      { name: 'Branch@Template', active_timeout: 60, refresh_rate: 1000 },
    ],
  };
}

function addUtmCollision(config) {
  config.security_policies = [
    policy('UTM One', 'trust', 'untrust', 'any', { security_profiles: { virus: 'Strict AV' } }),
    policy('UTM Two', 'trust', 'untrust', 'any', { security_profiles: { virus: 'Strict@AV' } }),
  ];
}

function addIdpCoverage(config) {
  config.security_policies = [
    policy('IDP One', 'trust', 'untrust', 'any', { security_profiles: { spyware: 'Strict Spyware' } }),
    policy('IDP Two', 'trust', 'untrust', 'any', { security_profiles: { spyware: 'Strict@Spyware' } }),
  ];
}

function addSecIntelCoverage(config) {
  config.external_lists = [
    { name: 'Bad Hosts', isBlockList: true, listType: 'ip' },
    { name: 'Bad@Hosts', isBlockList: true, listType: 'ip' },
  ];
}

function addAppFwCollision(config) {
  config.security_policies = [
    policy('AppFW One', 'trust', 'untrust', 'any', { security_profiles: { 'application-control': 'Risky Apps' } }),
    policy('AppFW Two', 'trust', 'untrust', 'any', { security_profiles: { 'application-control': 'Risky@Apps' } }),
  ];
  config.security_profile_definitions = {
    'application-control:Risky Apps': { categories: { malware: 'block' } },
    'application-control:Risky@Apps': { categories: { tunneling: 'block' } },
  };
}

function addSslCollision(config) {
  config.decryption_rules = [
    { name: 'Decrypt One', action: 'decrypt', decryption_type: 'ssl-forward-proxy', decryption_profile: 'Corp TLS' },
    { name: 'Decrypt Two', action: 'decrypt', decryption_type: 'ssl-forward-proxy', decryption_profile: 'Corp@TLS' },
  ];
}

function addSslPolicyReferenceCollision(config) {
  config.security_policies = [
    policy('Decrypt Policy One', 'trust', 'untrust', 'any', {
      _srx_decrypt: true,
      _srx_decrypt_profile: 'Corp TLS',
    }),
    policy('Decrypt Policy Two', 'trust', 'untrust', 'any', {
      _srx_decrypt: true,
      _srx_decrypt_profile: 'Corp@TLS',
    }),
  ];
}

function addVlanCollision(config) {
  config.evpn_config = [{
    vlans: [
      { name: 'Tenant VLAN', vlan_id: 100, vni: 10100 },
      { name: 'Tenant@VLAN', vlan_id: 200, vni: 10200 },
    ],
  }];
}

function addQosCollision(config) {
  config.qos_config = [
    { type: 'scheduler', name: 'Voice Scheduler', transmit_rate: '10 percent' },
    { type: 'scheduler', name: 'Voice@Scheduler', transmit_rate: '20 percent' },
  ];
}

function addQosClassifierMapCollision(config) {
  config.qos_config = [
    {
      type: 'classifier',
      name: 'Branch Map',
      classes: [{ name: 'Voice Class', guaranteed_bandwidth: 10 }],
    },
    {
      type: 'shaping-profile',
      name: 'Branch@Map',
      classes: [{ name: 'Voice@Class', guaranteed_bandwidth: 20 }],
    },
  ];
}

function addAaaCollision(config) {
  config.aaa_config = [
    { type: 'profile', name: 'Admin Access', authentication_order: ['radius'] },
    { type: 'profile', name: 'Admin@Access', authentication_order: ['tacacs'] },
  ];
}

function addGeneratedRoutingPolicyCollision(config) {
  const shared = 'a'.repeat(60);
  config.bgp_config = [{
    redistribute: [
      { protocol: `${shared}x` },
      { protocol: `${shared}y` },
    ],
  }];
}

function expectNamespaceOutputsUnique(mapping, namespace, commands, commandPattern, predicate = () => true) {
  if (namespace === undefined) {
    const entriesByNamespace = new Map();
    for (const entry of mapping.entries) {
      const key = `${entry.context}\0${entry.namespace}`;
      const entries = entriesByNamespace.get(key) || [];
      entries.push(entry);
      entriesByNamespace.set(key, entries);
    }
    for (const [key, entries] of entriesByNamespace) {
      expect(
        new Set(entries.map(entry => entry.outputName)).size,
        `duplicate output in ${key}`,
      ).toBe(entries.length);
      for (const entry of entries) {
        expect(entry.outputName, `${key}:${entry.sourceName}`)
          .toMatch(/^[A-Za-z][A-Za-z0-9._-]{0,62}$/);
      }
    }
    return;
  }
  const entries = mapping.entries.filter(entry => (
    entry.namespace === namespace && predicate(entry)
  ));
  expect(entries).toHaveLength(2);
  expect(new Set(entries.map(entry => entry.outputName)).size).toBe(2);
  for (const entry of entries) {
    expect(commands.some(command => (
      commandPattern.test(command) && command.split(/\s+/).includes(entry.outputName)
    ))).toBe(true);
  }
}

describe('Randomized Junos identifier allocation integrity', () => {
  it('preserves order, namespace uniqueness, and reference bindings across hostile names', () => {
    let seedsWithGeneratedAndUnresolved = 0;
    for (let seed = 1; seed <= 32; seed++) {
      const symbols = makeRandomSymbols(seed);
      const reversedSymbols = reverseSymbols(makeRandomSymbols(seed));
      expect(symbols.definitions, `seed ${seed} randomized name count`).toHaveLength(200);
      expect(Object.keys(symbols.categoryCounts), `seed ${seed} hostile-name categories`).toEqual([
        'case-variant',
        'empty-normalizing',
        'long-common-prefix-truncation',
        'numeric-prefix',
        'punctuation',
        'repeated-dashes',
        'whitespace',
      ]);
      expect(
        Object.values(symbols.categoryCounts).every(count => count > 0),
        `seed ${seed} hostile-name category counts`,
      ).toBe(true);
      if (symbols.generatedReferences.length > 0 && symbols.unresolvedReferencePaths.length > 0) {
        seedsWithGeneratedAndUnresolved++;
      }

      const first = createJunosIdentifierPlan(symbols);
      const second = createJunosIdentifierPlan(reversedSymbols);

      expect(mappingBySource(first.mapping), `seed ${seed} order independence`)
        .toEqual(mappingBySource(second.mapping));
      expectNamespaceOutputsUnique(first.mapping);

      for (const reference of symbols.boundReferences) {
        expect(first.nameForReference(reference.referencePath))
          .toBe(first.nameForDefinition(reference.definitionPath));
      }
      for (const reference of symbols.generatedReferences) {
        expect(first.nameForReference(reference.referencePath))
          .toBe(first.nameForGenerated(reference.definitionPath, reference.role));
      }
      for (const referencePath of symbols.unresolvedReferencePaths) {
        const entry = first.mapping.entries.find(candidate => (
          candidate.definitionPath === null
          && candidate.referencePaths.includes(referencePath)
        ));
        expect(entry, `seed ${seed} unresolved ${referencePath}`).toMatchObject({
          definitionPath: null,
        });
        expect(entry.resolution).toMatch(/^unresolved-/);
        expect(first.nameForReference(referencePath)).toBe(entry.outputName);
      }
    }
    expect(seedsWithGeneratedAndUnresolved).toBeGreaterThanOrEqual(25);
  });
});

describe('Set identifier-plan integration', () => {
  it('keeps generic policy output names associated with semantics when policies and zones reorder', () => {
    const forward = setPolicyAssociations(convertToSrxSetCommands(genericPolicyOrderConfig()));
    const reversed = setPolicyAssociations(convertToSrxSetCommands(reversedGenericPolicyOrderConfig()));

    expect(forward).toHaveLength(8);
    expect(reversed).toEqual(forward);
  });

  it.each([
    ['routing instance', addRoutingInstanceCollision, /set routing-instances /, 'routing-instance'],
    ['BGP group', addBgpGroupCollision, / protocols bgp group |set protocols bgp group /, 'bgp-group'],
    ['BGP fallback group', addBgpFallbackGroupCollision, / protocols bgp group |set protocols bgp group /, 'bgp-group'],
    ['screen profile', addScreenCollision, / screen ids-option /, 'screen-profile'],
    ['VPN', addVpnCollision, / security ipsec vpn /, 'ipsec-vpn'],
    ['IKE proposal', addVpnCollision, / security ike proposal /, 'ike-proposal'],
    ['IKE policy', addVpnCollision, / security ike policy /, 'ike-policy'],
    ['IKE gateway', addVpnCollision, / security ike gateway /, 'ike-gateway'],
    ['IPsec proposal', addVpnCollision, / security ipsec proposal /, 'ipsec-proposal'],
    ['IPsec policy', addVpnCollision, / security ipsec policy /, 'ipsec-policy'],
    ['SNMP community', addSnmpCollision, /set snmp community /, 'snmp-community'],
    ['DHCP pool', addDhcpCollision, / access address-assignment pool /, 'dhcp-pool'],
    ['bridge domain', addBridgeDomainCollision, /set bridge-domains /, 'bridge-domain'],
    ['PBF term', addPbfCollision, / firewall family inet filter .* term /, 'firewall-filter-term', entry => entry.definitionPath?.endsWith('.name')],
    ['flow template', addFlowTemplateCollision, / services flow-monitoring version/, 'flow-template'],
    ['UTM profile', addUtmCollision, / utm feature-profile anti-virus profile /, 'utm-anti-virus-profile'],
    ['IDP policy', addIdpCoverage, / security idp idp-policy /, 'idp-policy'],
    ['SecIntel rule', addSecIntelCoverage, / security-intelligence profile .* rule /, 'security-intelligence-rule'],
    ['AppFW rule set', addAppFwCollision, / application-firewall rule-sets /, 'application-firewall-rule-set'],
    ['SSL profile', addSslCollision, / services ssl proxy profile /, 'ssl-proxy-profile'],
    ['SSL policy profile reference', addSslPolicyReferenceCollision, / ssl-proxy profile-name /, 'ssl-proxy-profile'],
    ['VLAN', addVlanCollision, /set vlans /, 'vlan'],
    ['QoS scheduler', addQosCollision, / class-of-service schedulers /, 'cos-scheduler'],
    ['QoS classifier scheduler map', addQosClassifierMapCollision, / class-of-service scheduler-maps /, 'cos-scheduler-map'],
    ['AAA profile', addAaaCollision, /set access profile /, 'access-profile'],
    ['generated routing policy', addGeneratedRoutingPolicyCollision, / policy-options policy-statement /, 'routing-policy'],
  ])('keeps colliding %s identifiers distinct', (_label, mutate, commandPattern, namespace, predicate) => {
    const config = baseAdvancedConfig();
    mutate(config);
    const result = convertToSrxSetCommands(config);

    expect(result.commands.some(command => commandPattern.test(command))).toBe(true);
    expectNamespaceOutputsUnique(
      result.identifierMappings,
      namespace,
      result.commands,
      commandPattern,
      predicate,
    );
  });

  it('keeps routing-instance lookup roles aligned when an earlier route is not emitted', () => {
    const config = baseAdvancedConfig();
    config.static_routes = [{ vrf: 'Shared VRF' }];
    config.bgp_config = [{ instance: 'Shared VRF', local_as: 64512 }];

    const result = convertToSrxSetCommands(config);
    const instance = result.identifierMappings.entries.find(
      entry => entry.namespace === 'routing-instance',
    );

    expect(result.commands).toContain(
      `set routing-instances ${instance.outputName} routing-options autonomous-system 64512`,
    );
  });

  it('does not look up PBF filter identifiers when every rule is disabled', () => {
    const config = baseAdvancedConfig();
    config.pbf_rules = [{
      name: 'Disabled PBF',
      disabled: true,
      action: 'discard',
      src_addresses: ['any'],
      dst_addresses: ['any'],
    }];

    const result = convertToSrxSetCommands(config);

    expect(result.commands.some(command => command.startsWith('set firewall family inet filter '))).toBe(false);
    expect(result.identifierMappings.entries.some(entry => entry.catalogKey === 'pbf')).toBe(false);
  });

  it('keeps raw PBF IP prefixes outside identifier planning', () => {
    const config = baseAdvancedConfig();
    config.pbf_rules = [{
      name: 'Raw IPv4 Prefixes',
      action: 'discard',
      src_addresses: ['192.0.2.0/24'],
      dst_addresses: ['198.51.100.0/24'],
    }, {
      name: 'Raw IPv6 Prefixes',
      action: 'discard',
      src_addresses: ['::ffff:192.0.2.0/120'],
      dst_addresses: ['2001:db8::/64'],
    }];

    const result = convertToSrxSetCommands(config);
    const term = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'firewall-filter-term' && entry.sourceName === 'Raw IPv4 Prefixes'
    )).outputName;
    const ipv6Term = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'firewall-filter-term' && entry.sourceName === 'Raw IPv6 Prefixes'
    )).outputName;

    expect(result.commands).toContain(
      `set firewall family inet filter PBF-FILTER term ${term} from source-address 192.0.2.0/24`,
    );
    expect(result.commands).toContain(
      `set firewall family inet6 filter PBF-FILTER term ${ipv6Term} from source-address ::ffff:192.0.2.0/120`,
    );
    expect(result.commands).toContain(
      `set firewall family inet6 filter PBF-FILTER term ${ipv6Term} from destination-address 2001:db8::/64`,
    );
    expect(result.identifierMappings.entries.some(entry => (
      ['192.0.2.0/24', '198.51.100.0/24', '::ffff:192.0.2.0/120', '2001:db8::/64'].includes(entry.sourceName)
    ))).toBe(false);
  });

  it('emits IPv6-only named PBF matches under family inet6', () => {
    const config = baseAdvancedConfig();
    config.address_objects = [{
      name: 'IPv6 Segment',
      type: 'subnet',
      value: '2001:db8:1::/64',
    }];
    config.pbf_rules = [{
      name: 'IPv6 Route',
      action: 'discard',
      src_addresses: ['IPv6 Segment'],
      dst_addresses: ['any'],
    }];

    const result = convertToSrxSetCommands(config);
    const term = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'firewall-filter-term' && entry.sourceName === 'IPv6 Route'
    )).outputName;

    expect(result.commands).toContain(
      `set firewall family inet6 filter PBF-FILTER term ${term} from source-address 2001:db8:1::/64`,
    );
    expect(result.commands.some(command => command.includes(
      `firewall family inet filter PBF-FILTER term ${term}`,
    ))).toBe(false);
  });

  it('rejects mixed-family PBF matches at the conflicting safe field path', () => {
    const config = baseAdvancedConfig();
    config.address_objects = [{
      name: 'IPv6 Segment',
      type: 'subnet',
      value: '2001:db8:1::/64',
    }];
    config.pbf_rules = [{
      name: 'Mixed Route',
      action: 'discard',
      src_addresses: ['192.0.2.0/24'],
      dst_addresses: ['IPv6 Segment'],
    }];

    expect(() => convertToSrxSetCommands(config)).toThrow(expect.objectContaining({
      name: 'JunosSerializationError',
      fieldPath: 'pbf_rules[0].dst_addresses[0]',
    }));
  });

  it('infers family inet6 from an IPv6 PBF next hop when all matches are any', () => {
    const config = baseAdvancedConfig();
    config.pbf_rules = [{
      name: 'IPv6 Default Route',
      action: 'forward',
      next_hop_value: '2001:db8::1',
      src_addresses: ['any'],
      dst_addresses: ['any'],
      from_type: 'interface',
      from_value: ['ge-0/0/1.0'],
    }];

    const result = convertToSrxSetCommands(config);
    const term = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'firewall-filter-term' && entry.sourceName === 'IPv6 Default Route'
    )).outputName;

    expect(result.commands.some(command => command.includes(
      `set firewall family inet6 filter PBF-FILTER term ${term}`,
    ))).toBe(true);
    expect(result.commands).toContain(
      'set interfaces ge-0/0/1 unit 0 family inet6 filter input PBF-FILTER',
    );
  });

  it.each([
    ['IPv4 match with IPv6 next hop', '192.0.2.0/24', '2001:db8::1'],
    ['IPv6 match with IPv4 next hop', '2001:db8:1::/64', '192.0.2.1'],
  ])('rejects a PBF family conflict for %s at the next-hop field', (_label, source, nextHop) => {
    const config = baseAdvancedConfig();
    config.pbf_rules = [{
      name: 'Conflicting Route',
      action: 'forward',
      next_hop_value: nextHop,
      src_addresses: [source],
      dst_addresses: ['any'],
    }];

    expect(() => convertToSrxSetCommands(config)).toThrow(expect.objectContaining({
      name: 'JunosSerializationError',
      fieldPath: 'pbf_rules[0].next_hop_value',
    }));
  });

  it('uses the planned SSL profile for decrypt-and-forward rules', () => {
    const config = baseAdvancedConfig();
    config.decryption_rules = [{
      name: 'Decrypt Forward',
      action: 'decrypt-and-forward',
      decryption_type: 'ssl-forward-proxy',
      decryption_profile: 'Forward TLS',
    }];

    const result = convertToSrxSetCommands(config);
    const profile = result.identifierMappings.entries.find(
      entry => entry.namespace === 'ssl-proxy-profile',
    );

    expect(result.commands).toContain(
      `#   set services ssl proxy profile ${profile.outputName} root-ca <CA_PROFILE>`,
    );
  });

  it('plans and emits the default UTM fallback definition and policy reference', () => {
    const config = baseAdvancedConfig();
    config.security_policies = [policy('Grouped Security', 'trust', 'untrust', 'any', {
      profile_group: 'Strict Group',
    })];

    const result = convertToSrxSetCommands(config);
    const fallback = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'utm-policy' && entry.sourceName === 'default-utm'
    ));

    expect(result.commands).toContain(`set security utm utm-policy ${fallback.outputName}`);
    expect(result.commands.some(command => command.endsWith(
      `application-services utm-policy ${fallback.outputName}`,
    ))).toBe(true);
  });

  it('uses planned PKI CA profile and identity names in active SSL configuration', () => {
    const config = baseAdvancedConfig();
    config.decryption_rules = [{
      name: 'Decrypt Forward',
      action: 'decrypt',
      decryption_type: 'ssl-forward-proxy',
      decryption_profile: 'Forward TLS',
    }];

    const result = convertToSrxSetCommands(config);
    const caProfile = result.identifierMappings.entries.find(entry => entry.namespace === 'pki-ca-profile');
    const caIdentity = result.identifierMappings.entries.find(entry => entry.namespace === 'pki-ca-identity');

    expect(result.commands).toContain(
      `set security pki ca-profile ${caProfile.outputName} ca-identity ${caIdentity.outputName}`,
    );
  });

  it('plans and emits the policy-only fallback SSL profile and PKI identities', () => {
    const config = baseAdvancedConfig();
    config.security_policies = [policy('Decrypt Policy', 'trust', 'untrust', 'any', {
      _srx_decrypt: true,
    })];

    const result = convertToSrxSetCommands(config);
    const sslProfile = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'ssl-proxy-profile' && entry.sourceName === 'ssl-fwd-proxy'
    ));
    const caProfile = result.identifierMappings.entries.find(entry => entry.namespace === 'pki-ca-profile');
    const caIdentity = result.identifierMappings.entries.find(entry => entry.namespace === 'pki-ca-identity');

    expect(result.commands).toContain(
      `set security pki ca-profile ${caProfile.outputName} ca-identity ${caIdentity.outputName}`,
    );
    expect(result.commands).toContain(
      `#   set services ssl proxy profile ${sslProfile.outputName} root-ca <CA_PROFILE>`,
    );
  });

  it('reuses a rule-owned ssl-fwd-proxy definition for a fallback decrypt policy', () => {
    const config = baseAdvancedConfig();
    config.decryption_rules = [{
      name: 'Explicit Default Name',
      action: 'decrypt',
      decryption_type: 'ssl-forward-proxy',
      decryption_profile: 'ssl-fwd-proxy',
    }];
    config.security_policies = [policy('Decrypt Policy', 'trust', 'untrust', 'any', {
      _srx_decrypt: true,
    })];

    const result = convertToSrxSetCommands(config);
    const sslProfile = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'ssl-proxy-profile' && entry.sourceName === 'ssl-fwd-proxy'
    ));

    expect(sslProfile.definitionPath).toContain('decryption_rules[0]#generated:');
    expect(result.commands).toContain(
      `#   set services ssl proxy profile ${sslProfile.outputName} root-ca <CA_PROFILE>`,
    );
  });

  it('does not catalog or emit SSL fallback state without rules or decrypt policies', () => {
    const config = baseAdvancedConfig();
    config.security_policies = [policy('Plain Policy', 'trust', 'untrust', 'any')];

    const result = convertToSrxSetCommands(config);

    expect(result.identifierMappings.entries.some(entry => (
      entry.namespace === 'ssl-proxy-profile' || entry.namespace.startsWith('pki-ca-')
    ))).toBe(false);
    expect(result.commands.some(command => command.includes('SSL Proxy / PKI Configuration'))).toBe(false);
  });

  it('uses the planned semantic traffic-selector name for each VPN proxy ID', () => {
    const config = baseAdvancedConfig();
    const vpn = collidingVpn(' ');
    vpn.proxy_id = [
      { local: '10.2.0.0/16', remote: '172.16.2.0/24' },
      { local: '10.1.0.0/16', remote: '172.16.1.0/24' },
    ];
    config.vpn_tunnels = [vpn];

    const result = convertToSrxSetCommands(config);
    const vpnName = result.identifierMappings.entries.find(entry => entry.namespace === 'ipsec-vpn').outputName;
    const secondInputSelector = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'traffic-selector'
      && entry.definitionPath.startsWith('vpn_tunnels[0].proxy_id[1]#generated:')
    ));

    expect(result.commands).toContain(
      `set security ipsec vpn ${vpnName} traffic-selector ${secondInputSelector.outputName} local-ip 10.1.0.0/16`,
    );
  });

  it.each([
    ['missing', undefined],
    ['all-allow', { categories: { business: 'allow' } }],
  ])('does not look up an unregistered AppFW profile when categories are %s', (_label, definition) => {
    const config = baseAdvancedConfig();
    config.security_policies = [policy('AppFW Edge', 'trust', 'untrust', 'any', {
      security_profiles: { 'application-control': 'Edge Apps' },
    })];
    if (definition) {
      config.security_profile_definitions = {
        'application-control:Edge Apps': definition,
      };
    }

    const result = convertToSrxSetCommands(config);

    expect(result.identifierMappings.entries.some(
      entry => entry.namespace === 'application-firewall-rule-set',
    )).toBe(false);
  });

  it('fails closed when a QoS classifier child lookup is missing', () => {
    const config = baseAdvancedConfig();
    addQosClassifierMapCollision(config);
    const plan = planJunosIdentifiers(config);
    const identifierPlan = {
      ...plan,
      nameForDefinition(path) {
        if (path === 'qos_config[0].classes[0].name#forwarding-class') {
          throw new JunosIdentifierPlanningError('missing_catalog_coverage', {
            definitionPaths: [path],
          });
        }
        return plan.nameForDefinition(path);
      },
    };

    expect(() => convertToSrxSetCommands(config, {}, null, { identifierPlan }))
      .toThrow(expect.objectContaining({ code: 'missing_catalog_coverage' }));
  });

  it('uses collision-safe address names for definitions, groups, and policies', () => {
    const result = convertToSrxSetCommands(collisionConfig());
    const addressEntries = result.identifierMappings.entries.filter(
      entry => entry.namespace === 'address-book-entry' && entry.kind === 'address',
    );

    expect(new Set(addressEntries.map(entry => entry.outputName)).size).toBe(2);
    for (const entry of addressEntries) {
      const value = entry.sourceName === 'Web Server' ? '192.0.2.10/32' : '192.0.2.11/32';
      expect(result.commands).toContain(
        `set security address-book global address ${entry.outputName} ${value}`,
      );
      expect(result.commands.some(command => command.endsWith(` ${entry.outputName}`))).toBe(true);
    }
    expect(result.summary.identifier_collisions_resolved).toBe(2);
    expect(result.warnings.filter(item => item.subType === 'identifier_collision')).toHaveLength(2);
  });

  it('rejects duplicate policy names within one zone pair', () => {
    const config = baseConfig({
      security_policies: [
        policy('Repeated Policy', 'trust', 'untrust', 'any'),
        policy('Repeated Policy', 'trust', 'untrust', 'any'),
      ],
    });

    expect(() => convertToSrxSetCommands(config)).toThrow(expect.objectContaining({
      name: 'JunosIdentifierPlanningError',
      code: 'duplicate_definition',
    }));
  });

  it('allows the same policy name in different zone pairs', () => {
    const config = baseConfig({
      security_policies: [
        policy('Repeated Policy', 'trust', 'untrust', 'any'),
        policy('Repeated Policy', 'dmz', 'untrust', 'any'),
      ],
    });

    const result = convertToSrxSetCommands(config);
    const policies = result.identifierMappings.entries.filter(
      entry => entry.namespace === 'security-policy',
    );

    expect(policies).toHaveLength(2);
    expect(policies.map(entry => entry.outputName)).toEqual(['Repeated-Policy', 'Repeated-Policy']);
    expect(result.commands).toContain(
      'set security policies from-zone trust to-zone untrust policy Repeated-Policy then permit',
    );
    expect(result.commands).toContain(
      'set security policies from-zone dmz to-zone untrust policy Repeated-Policy then permit',
    );
  });

  it('uses collision-safe NAT rule and pool names for definitions and references', () => {
    const config = baseConfig({
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [
        { name: 'Pool-One', type: 'host', value: '198.51.100.10/32' },
        { name: 'Pool-Two', type: 'host', value: '198.51.100.11/32' },
      ],
      nat_rules: [
        {
          name: 'Outbound NAT', type: 'source',
          src_zones: ['trust'], dst_zones: ['untrust'],
          src_addresses: ['any'], dst_addresses: ['any'],
          translated_src: { type: 'dynamic-ip-pool', addresses: ['Pool-One'] },
        },
        {
          name: 'Outbound@NAT', type: 'source',
          src_zones: ['trust'], dst_zones: ['untrust'],
          src_addresses: ['any'], dst_addresses: ['any'],
          translated_src: { type: 'dynamic-ip-pool', addresses: ['Pool-Two'] },
        },
      ],
    });

    const result = convertToSrxSetCommands(config);
    const rules = result.identifierMappings.entries.filter(entry => entry.namespace === 'nat-rule');
    const pools = result.identifierMappings.entries.filter(
      entry => entry.namespace === 'source-nat-pool',
    );

    expect(new Set(rules.map(entry => entry.outputName)).size).toBe(2);
    expect(new Set(pools.map(entry => entry.outputName)).size).toBe(2);
    for (const rule of rules) {
      expect(result.commands.some(command => command.includes(` rule ${rule.outputName} `))).toBe(true);
    }
    for (const pool of pools) {
      expect(result.commands.some(command => (
        command.startsWith(`set security nat source pool ${pool.outputName} address `)
      ))).toBe(true);
      expect(result.commands.some(command => command.endsWith(` source-nat pool ${pool.outputName}`)))
        .toBe(true);
    }
  });

  it('keeps predefined applications as literals without allocating custom definitions', () => {
    const config = baseConfig({
      service_objects: [{ name: 'HTTPS', protocol: 'tcp', port_range: '443' }],
      security_policies: [policy('Allow HTTPS', 'trust', 'untrust', 'any', {
        applications: ['junos-https'],
        services: ['HTTPS'],
      })],
    });

    const result = convertToSrxSetCommands(config);
    const applicationEntries = result.identifierMappings.entries.filter(
      entry => entry.namespace === 'application-entry',
    );

    expect(applicationEntries).toHaveLength(0);
    expect(result.commands).toContain(
      'set security policies from-zone trust to-zone untrust policy Allow-HTTPS match application junos-https',
    );
    expect(result.commands.some(command => command.startsWith('set applications application HTTPS ')))
      .toBe(false);
  });

  it('uses planned target, zone, service, application, and schedule names end to end', () => {
    const config = baseConfig({
      zones: [
        { name: 'Inside Zone', interfaces: [] },
        { name: 'Inside@Zone', interfaces: [] },
        { name: 'Outside', interfaces: [] },
      ],
      service_objects: [
        { name: 'Service One', protocol: 'tcp', port_range: '8080' },
        { name: 'Service@One', protocol: 'tcp', port_range: '8081' },
      ],
      service_groups: [{
        name: 'Service Bundle',
        members: ['Service One', 'Service@One'],
      }],
      applications: [
        { name: 'Application One', protocol: 'tcp', port: '9000' },
        { name: 'Application@One', protocol: 'tcp', port: '9001' },
      ],
      schedules: [
        { name: 'Night Window', type: 'recurring', days: ['mon'], start: '20:00', end: '21:00' },
        { name: 'Night@Window', type: 'recurring', days: ['tue'], start: '20:00', end: '21:00' },
      ],
      security_policies: [
        policy('First Core', 'Inside Zone', 'Outside', 'any', {
          applications: ['Application One'],
          services: ['Service Bundle'],
          schedule: 'Night Window',
        }),
        policy('Second Core', 'Inside@Zone', 'Outside', 'any', {
          applications: ['Application@One'],
          services: ['Service@One'],
          schedule: 'Night@Window',
        }),
      ],
    });

    const result = convertToSrxSetCommands(
      config,
      {},
      { type: 'logical-system', name: 'Branch Office' },
    );
    const entries = result.identifierMappings.entries;
    const targetName = entries.find(entry => entry.namespace === 'target-context').outputName;

    expect(result.commands.filter(command => command.startsWith('set ')).every(command => (
      command.startsWith(`set logical-systems ${targetName} `)
    ))).toBe(true);
    for (const namespace of ['zone', 'application-entry', 'scheduler']) {
      for (const entry of entries.filter(item => item.namespace === namespace && item.definitionPath)) {
        expect(result.commands.some(command => command.includes(` ${entry.outputName}`))).toBe(true);
      }
    }
    for (const entry of entries.filter(item => item.referencePaths.length > 0)) {
      expect(result.commands.some(command => command.includes(` ${entry.outputName}`))).toBe(true);
    }
  });

  it('honors injected path prefixes and target paths without replanning output names', () => {
    const first = baseConfig({ zones: [{ name: 'Inside Zone', interfaces: [] }] });
    const second = baseConfig({ zones: [{ name: 'Inside@Zone', interfaces: [] }] });
    const slots = [
      { lsName: 'Branch Office', intermediateConfig: first },
      { lsName: 'Branch@Office', intermediateConfig: second },
    ];
    const identifierPlan = planMergedJunosIdentifiers(slots);
    const result = convertToSrxSetCommands(
      first,
      {},
      { type: 'logical-system', name: slots[0].lsName },
      {
        identifierPlan,
        pathPrefix: 'configSlots[0].intermediateConfig.',
        targetContextPath: 'configSlots[0].lsName',
      },
    );
    const targetName = identifierPlan.nameForDefinition('configSlots[0].lsName');
    const zoneName = identifierPlan.nameForDefinition(
      'configSlots[0].intermediateConfig.zones[0].name',
    );

    expect(result.commands).toContain(
      `set logical-systems ${targetName} security zones security-zone ${zoneName}`,
    );
    expect(targetName).not.toBe(identifierPlan.nameForDefinition('configSlots[1].lsName'));
  });

  it('uses planned generated names for multi-port, custom, and unmapped applications', () => {
    const config = baseConfig({
      service_objects: [{ name: 'Discrete Service', protocol: 'tcp', port_range: '8443,9443' }],
      applications: [{ name: 'Discrete App', protocol: 'udp', port: '5000,5001' }],
      security_policies: [policy('Generated Apps', 'trust', 'untrust', 'any', {
        applications: ['Discrete App', 'adobe-cloud', 'foo bar', 'foo@bar'],
        services: ['Discrete Service'],
      })],
    });

    const result = convertToSrxSetCommands(config);
    const generated = result.identifierMappings.entries.filter(entry => (
      entry.namespace === 'application-entry' && entry.resolution.startsWith('generated')
    ));

    expect(generated.length).toBeGreaterThanOrEqual(9);
    for (const entry of generated) {
      expect(result.commands.some(command => command.includes(` ${entry.outputName}`))).toBe(true);
    }
    const unmapped = generated.filter(entry => ['foo bar', 'foo@bar'].includes(entry.sourceName));
    expect(new Set(unmapped.map(entry => entry.outputName)).size).toBe(2);
    for (const entry of unmapped) {
      expect(result.commands.some(command => command.endsWith(` application ${entry.outputName}`)))
        .toBe(true);
    }
  });

  it('emits planned generated applications discovered through expanded application groups', () => {
    const config = baseConfig({
      application_groups: [{
        name: 'Expanded Group',
        members: ['adobe-cloud', 'group-only unknown'],
      }],
    });

    const result = convertToSrxSetCommands(config);
    const generated = result.identifierMappings.entries.filter(entry => (
      entry.namespace === 'application-entry' && entry.resolution.startsWith('generated')
    ));

    expect(generated.length).toBeGreaterThanOrEqual(2);
    for (const entry of generated) {
      expect(result.commands.some(command => command.includes(` ${entry.outputName} `)))
        .toBe(true);
    }
  });

  it('uses planned security-profile and generated policy names in definitions and attachments', () => {
    const config = baseConfig({
      security_policies: [
        policy('Profile One', 'trust', 'untrust', 'any', {
          security_profiles: { virus: 'Strict AV' },
        }),
        policy('Profile Two', 'trust', 'untrust', 'any', {
          security_profiles: { virus: 'Strict@AV' },
        }),
      ],
    });

    const result = convertToSrxSetCommands(config);
    const profiles = result.identifierMappings.entries.filter(
      entry => entry.namespace === 'utm-anti-virus-profile',
    );
    const utmPolicies = result.identifierMappings.entries.filter(
      entry => entry.namespace === 'utm-policy',
    );

    expect(new Set(profiles.map(entry => entry.outputName)).size).toBe(2);
    for (const profile of profiles) {
      expect(result.commands.some(command => command.includes(` profile ${profile.outputName} `)))
        .toBe(true);
      expect(result.commands.some(command => command.endsWith(`-profile ${profile.outputName}`)))
        .toBe(true);
    }
    for (const utmPolicy of utmPolicies) {
      expect(result.commands.some(command => command.includes(` utm-policy ${utmPolicy.outputName} `)))
        .toBe(true);
      expect(result.commands.some(command => command.endsWith(` utm-policy ${utmPolicy.outputName}`)))
        .toBe(true);
    }
  });

  it('does not emit placeholder applications for explicit multi-port definitions', () => {
    const config = baseConfig({
      service_objects: [{ name: 'Explicit Service', protocol: 'tcp', port_range: '8080,8081' }],
      applications: [{ name: 'Explicit App', protocol: 'udp', port: '9000,9001' }],
      security_policies: [policy('Explicit Multi', 'trust', 'untrust', 'any', {
        applications: ['Explicit App'],
        services: ['Explicit Service'],
      })],
    });
    const result = convertToSrxSetCommands(config);
    const setEntries = result.identifierMappings.entries.filter(entry => (
      entry.namespace === 'application-entry'
      && entry.kind === 'application-set'
    ));

    expect(setEntries).toHaveLength(2);
    for (const entry of setEntries) {
      expect(result.commands.some(command => (
        command.startsWith(`set applications application-set ${entry.outputName} application `)
      ))).toBe(true);
      expect(result.commands.some(command => (
        command.startsWith(`set applications application ${entry.outputName} `)
      ))).toBe(false);
    }
    expect(result.commands.join('\n')).not.toContain('INTERVIEW REQUIRED: Explicit App');
  });

  it('consumes exact UTM feature definition and every shared profile reference path', () => {
    const config = baseAdvancedConfig();
    config.security_policies = [
      policy('Shared UTM One', 'trust', 'untrust', 'any', {
        security_profiles: { virus: 'Shared AV' },
      }),
      policy('Shared UTM Two', 'trust', 'untrust', 'any', {
        security_profiles: { virus: 'Shared AV' },
      }),
    ];
    const plan = planJunosIdentifiers(config);
    let definitionLookup = false;
    let secondReferenceLookup = false;
    const identifierPlan = {
      ...plan,
      nameForGenerated(path, role) {
        if (path === 'security_policies[0]' && role === 'security-feature:utm-anti-virus-profile') {
          definitionLookup = true;
        }
        return plan.nameForGenerated(path, role);
      },
      nameForReference(path) {
        if (path === 'security_policies[1].security_profiles.virus') {
          secondReferenceLookup = true;
        }
        return plan.nameForReference(path);
      },
    };

    convertToSrxSetCommands(config, {}, null, { identifierPlan });

    expect(definitionLookup).toBe(true);
    expect(secondReferenceLookup).toBe(true);
  });

  it('uses the canonical shared AppFW owner across different UTM combinations', () => {
    const config = baseAdvancedConfig();
    config.security_policies = [
      policy('Shared AppFW Z', 'trust', 'untrust', 'any', {
        security_profiles: {
          virus: 'Zed AV',
          'application-control': 'Shared Apps',
        },
      }),
      policy('Shared AppFW A', 'trust', 'untrust', 'any', {
        security_profiles: {
          virus: 'Alpha AV',
          'application-control': 'Shared Apps',
        },
      }),
    ];
    config.security_profile_definitions = {
      'application-control:Shared Apps': {
        categories: { tunneling: 'block' },
      },
    };

    const result = convertToSrxSetCommands(config);
    const ruleSet = result.identifierMappings.entries.find(
      entry => entry.namespace === 'application-firewall-rule-set',
    );
    const child = result.identifierMappings.entries.find(
      entry => entry.namespace === 'application-firewall-rule',
    );

    expect(result.commands).toContain(
      `set security application-firewall rule-sets ${ruleSet.outputName} rule ${child.outputName} then deny`,
    );
    expect(result.commands.filter(command => command.includes(
      `application-firewall rule-sets ${ruleSet.outputName} rule ${child.outputName}`,
    ))).toHaveLength(4);
  });

  it('uses exact generated child lookups in an injected multi-context plan', () => {
    const customName = 'apple-push-notifications';
    const ports = getJunosEmission(customName, 'panos').ports.map(String);
    const collidingApplications = ports.map(port => ({
      name: `${customName}-p${port}`,
      protocol: 'tcp',
      port: '65000',
    }));
    const configFor = applications => baseConfig({
      applications,
      security_policies: [policy('Apple Push', 'trust', 'untrust', 'any', {
        applications: [customName],
      })],
    });
    const first = configFor(collidingApplications);
    const second = configFor([]);
    const slots = [
      { lsName: 'branch-a', intermediateConfig: first },
      { lsName: 'branch-b', intermediateConfig: second },
    ];
    const identifierPlan = planMergedJunosIdentifiers(slots);
    const result = convertToSrxSetCommands(
      second,
      {},
      { type: 'logical-system', name: 'branch-b' },
      {
        identifierPlan,
        pathPrefix: 'configSlots[1].intermediateConfig.',
        targetContextPath: 'configSlots[1].lsName',
      },
    );
    const firstOwner = 'configSlots[0].intermediateConfig.security_policies[0].applications[0]';
    const secondOwner = 'configSlots[1].intermediateConfig.security_policies[0].applications[0]';

    for (const port of ports) {
      const role = `custom-application-port:${port}`;
      const firstName = identifierPlan.nameForGenerated(firstOwner, role);
      const secondName = identifierPlan.nameForGenerated(secondOwner, role);
      expect(secondName).not.toBe(firstName);
      expect(result.commands.some(command => command.includes(` application ${secondName}`)))
        .toBe(true);
      expect(result.commands.some(command => command.includes(` application ${firstName}`)))
        .toBe(false);
    }
  });

  it('preserves planned mysql literals beside colliding custom names', () => {
    const config = baseConfig({
      applications: [{ name: 'custom-mysql', protocol: 'tcp', port: '13306' }],
      security_policies: [policy('Database', 'trust', 'untrust', 'any', {
        applications: ['mysql'],
      })],
    });
    const result = convertToSrxSetCommands(config);

    expect(result.commands).toContain(
      'set security policies from-zone trust to-zone untrust policy Database match application junos-mysql',
    );
    expect(result.commands).toContain('set applications application custom-mysql destination-port 13306');
    expect(result.commands).not.toContain('set applications application custom-mysql destination-port 3306');
    expect(result.commands.join('\n')).not.toContain('Auto-generated Missing Application Definitions');
  });

  it('catalogs and emits DNS-security rule names through exact profile references', () => {
    const config = baseConfig({
      security_policies: [policy('DNS Security', 'trust', 'untrust', 'any', {
        security_profiles: { 'dns-security': 'Strict DNS' },
      })],
      security_profile_definitions: {
        'dns-security:Strict DNS': { blockedDomains: ['bad.example'] },
      },
    });
    const result = convertToSrxSetCommands(config);
    const dnsRule = result.identifierMappings.entries.find(
      entry => entry.namespace === 'dns-filtering-rule',
    );

    expect(dnsRule.referencePaths).toContain(
      'security_policies[0].security_profiles.dns-security',
    );
    expect(result.commands).toContain(
      `set services dns-filtering dns-filtering-rule ${dnsRule.outputName} match-name bad.example`,
    );
  });

  it('keeps NAT zone pairs structured when a zone contains the old delimiter', () => {
    const config = baseConfig({
      zones: [
        { name: 'a->b', interfaces: [] },
        { name: 'outside', interfaces: [] },
      ],
      nat_rules: [{
        name: 'Arrow NAT', type: 'source',
        src_zones: ['a->b'], dst_zones: ['outside'],
        src_addresses: ['any'], dst_addresses: ['any'],
        translated_src: { type: 'interface' },
      }],
    });
    const result = convertToSrxSetCommands(config);
    const fromZone = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'zone' && entry.sourceName === 'a->b'
    )).outputName;
    const ruleSet = result.identifierMappings.entries.find(
      entry => entry.namespace === 'nat-rule-set',
    ).outputName;
    const rule = result.identifierMappings.entries.find(
      entry => entry.namespace === 'nat-rule',
    ).outputName;

    expect(result.commands).toContain(`set security nat source rule-set ${ruleSet} from zone ${fromZone}`);
    expect(result.commands.some(command => command.includes(
      `security nat source rule-set ${ruleSet} rule ${rule} `,
    ))).toBe(true);
  });

  it('uses alias-form NAT zone fields and effective paths for empty arrays', () => {
    const config = baseConfig({
      zones: [
        { name: 'inside', interfaces: [] },
        { name: 'outside', interfaces: [] },
      ],
      nat_rules: [
        {
          name: 'Alias NAT', type: 'source',
          source_zones: ['inside'], destination_zones: ['outside'],
          src_addresses: ['any'], dst_addresses: ['any'],
          translated_src: { type: 'interface' },
        },
        {
          name: 'Empty Alias NAT', type: 'source',
          source_zones: [], destination_zones: [],
          src_addresses: ['any'], dst_addresses: ['any'],
          translated_src: { type: 'interface' },
        },
      ],
    });
    const plan = planJunosIdentifiers(config);
    const referenceLookups = [];
    const identifierPlan = {
      ...plan,
      nameForReference(path) {
        referenceLookups.push(path);
        return plan.nameForReference(path);
      },
    };
    const result = convertToSrxSetCommands(config, {}, null, { identifierPlan });

    expect(referenceLookups).toEqual(expect.arrayContaining([
      'nat_rules[0].source_zones[0]',
      'nat_rules[0].destination_zones[0]',
      'nat_rules[1]#effective-source-zone',
      'nat_rules[1]#effective-destination-zone',
    ]));
    const aliasRuleSet = result.identifierMappings.entries.find(entry => (
      entry.namespace === 'nat-rule-set' && entry.sourceName === 'inside-to-outside'
    )).outputName;
    expect(result.commands).toContain(`set security nat source rule-set ${aliasRuleSet} from zone inside`);
    expect(result.commands).toContain(`set security nat source rule-set ${aliasRuleSet} to zone outside`);
  });

  it('preserves periods in explicit multi-port preferred names', () => {
    const config = baseConfig({
      service_objects: [{ name: 'Foo.Bar', protocol: 'tcp', port_range: '8080,8081' }],
      applications: [{ name: 'Baz.Qux', protocol: 'udp', port: '9000,9001' }],
    });
    const result = convertToSrxSetCommands(config);

    expect(result.commands).toContain('set applications application-set Foo.Bar-set application Foo.Bar-8080');
    expect(result.commands).toContain('set applications application-set Baz.Qux-set application Baz.Qux-9000');
  });

  it('maps only interface operands when source identifiers resemble interface names', () => {
    const config = baseConfig({
      zones: [{
        name: 'port1',
        interfaces: ['port1'],
        description: 'zone port1 keeps port10 text',
      }],
      interfaces: [{ name: 'port1', ip: '192.0.2.1/24' }],
      address_objects: [
        { name: 'port1', type: 'host', value: '192.0.2.10/32' },
        { name: 'port10', type: 'host', value: '192.0.2.11/32' },
      ],
      applications: [
        { name: 'port1', protocol: 'tcp', port: '8080' },
        { name: 'port10', protocol: 'tcp', port: '8081' },
      ],
      security_policies: [policy('port1', 'port1', 'port1', 'port1', {
        applications: ['port1'],
        description: 'policy port1 keeps port10 text',
      })],
    });
    const mappedInterface = 'ge-0/0/0.0';
    const result = convertToSrxSetCommands(config, { port1: mappedInterface });
    const portOneEntries = result.identifierMappings.entries.filter(entry => (
      entry.sourceName === 'port1'
    ));

    expect(portOneEntries.length).toBeGreaterThanOrEqual(4);
    expect(portOneEntries.every(entry => entry.outputName === 'port1')).toBe(true);
    expect(result.commands).toEqual(expect.arrayContaining([
      `set security zones security-zone port1 interfaces ${mappedInterface}`,
      'set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24',
      'set security address-book global address port1 192.0.2.10/32',
      'set security address-book global address port10 192.0.2.11/32',
      'set applications application port1 destination-port 8080',
      'set applications application port10 destination-port 8081',
      'set security policies from-zone port1 to-zone port1 policy port1 match destination-address port1',
      'set security policies from-zone port1 to-zone port1 policy port1 match application port1',
      'set security zones security-zone port1 description "zone port1 keeps port10 text"',
      'set security policies from-zone port1 to-zone port1 policy port1 description "policy port1 keeps port10 text"',
    ]));
    expect(result.commands.filter(command => command.includes(mappedInterface))).toEqual([
      `set security zones security-zone port1 interfaces ${mappedInterface}`,
    ]);
  });

  it('emits collision-safe planned definitions for NAT-referenced missing zones', () => {
    const config = baseConfig({
      zones: [{ name: 'outside', interfaces: [] }],
      nat_rules: [
        {
          name: 'Branch One', type: 'source',
          src_zones: ['Branch Zone'], dst_zones: ['outside'],
          src_addresses: ['any'], dst_addresses: ['any'],
          translated_src: { type: 'interface' },
        },
        {
          name: 'Branch Two', type: 'source',
          src_zones: ['Branch@Zone'], dst_zones: ['outside'],
          src_addresses: ['any'], dst_addresses: ['any'],
          translated_src: { type: 'interface' },
        },
      ],
    });
    const result = convertToSrxSetCommands(config);
    const generatedZones = result.identifierMappings.entries.filter(entry => (
      entry.namespace === 'zone'
      && entry.definitionPath?.includes('#generated:nat-missing-zone:')
    ));

    expect(generatedZones).toHaveLength(2);
    expect(new Set(generatedZones.map(entry => entry.outputName)).size).toBe(2);
    for (const entry of generatedZones) {
      expect(entry.referencePaths).toHaveLength(1);
      expect(result.commands.filter(command => (
        command === `set security zones security-zone ${entry.outputName}`
      ))).toHaveLength(1);
      expect(result.commands.some(command => command.endsWith(` from zone ${entry.outputName}`)))
        .toBe(true);
    }
  });

  it('fails closed when an injected plan does not cover a core definition path', () => {
    const config = collisionConfig();
    const emptyPlan = {
      warnings: [],
      collisionCount: 0,
      mapping: { version: 1, entries: [] },
      nameForDefinition: path => { throw new JunosIdentifierPlanningError('missing_catalog_coverage', { definitionPaths: [path] }); },
      nameForReference: path => { throw new JunosIdentifierPlanningError('missing_catalog_coverage', { referencePaths: [path] }); },
      nameForGenerated: path => { throw new JunosIdentifierPlanningError('missing_catalog_coverage', { definitionPaths: [path] }); },
    };

    expect(() => convertToSrxSetCommands(config, {}, null, { identifierPlan: emptyPlan }))
      .toThrow(expect.objectContaining({ code: 'missing_catalog_coverage' }));
  });
});

describe('XML identifier-plan integration', () => {
  it('keeps generic policy output names associated with semantics when policies and zones reorder', () => {
    const forward = xmlPolicyAssociations(buildSrxXml(genericPolicyOrderConfig()));
    const reversed = xmlPolicyAssociations(buildSrxXml(reversedGenericPolicyOrderConfig()));

    expect(forward).toHaveLength(8);
    expect(reversed).toEqual(forward);
  });

  it.each([
    ['file-blocking only', { 'file-blocking': 'Strict Files' }],
    ['mixed file-blocking', { virus: 'Strict AV', 'file-blocking': 'Strict Files' }],
  ])('retains planned UTM ownership and warnings for %s', (_label, securityProfiles) => {
    const config = baseAdvancedConfig();
    config.security_policies = [policy('File Inspection', 'trust', 'untrust', 'any', {
      security_profiles: securityProfiles,
    })];
    const setResult = convertToSrxSetCommands(config);
    const xmlResult = buildSrxXml(config);
    const utmPolicy = setResult.identifierMappings.entries.find(
      entry => entry.namespace === 'utm-policy',
    );
    const setUnsupported = setResult.warnings.filter(warning => (
      warning.severity === 'unsupported' && warning.message.toLowerCase().includes('file-blocking')
    ));
    const xmlUnsupported = xmlResult.warnings.filter(warning => (
      warning.severity === 'unsupported' && warning.message.toLowerCase().includes('file-blocking')
    ));
    const warningSemantics = warning => ({
      severity: warning.severity,
      element: warning.element,
      message: warning.message,
      suggestion: warning.suggestion,
    });

    expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
    expect(utmPolicy).toBeDefined();
    expect(xmlResult.xml).toContain(`<utm-policy name="${utmPolicy.outputName}">`);
    expect(xmlResult.xml).toContain(`<utm-policy>${utmPolicy.outputName}</utm-policy>`);
    expect(setUnsupported).toHaveLength(1);
    expect(xmlUnsupported).toHaveLength(1);
    expect(xmlUnsupported.map(warningSemantics)).toEqual(setUnsupported.map(warningSemantics));
  });

  it('treats a missing NAT type as implicit source NAT in Set and XML', () => {
    const config = baseAdvancedConfig();
    config.nat_rules = [{
      name: 'Implicit Source',
      src_zones: ['trust'],
      dst_zones: ['untrust'],
      src_addresses: ['any'],
      dst_addresses: ['any'],
      translated_src: { type: 'interface' },
    }];
    const setResult = convertToSrxSetCommands(config);
    const xmlResult = buildSrxXml(config);
    const natRule = setResult.identifierMappings.entries.find(entry => entry.namespace === 'nat-rule');
    const ruleSet = setResult.identifierMappings.entries.find(entry => entry.namespace === 'nat-rule-set');

    expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
    expect(setResult.commands.some(command => command.includes(
      `security nat source rule-set ${ruleSet.outputName}`,
    ))).toBe(true);
    expect(xmlResult.xml).toContain('<source>');
    expect(xmlResult.xml).toContain(`<name>${ruleSet.outputName}</name>`);
    expect(xmlResult.xml).toContain(`<name>${natRule.outputName}</name>`);
  });

  it.each([
    ['OSPF', 'ospf_config'],
    ['OSPFv3', 'ospf3_config'],
  ])('retains every same-instance %s record and export policy', (_label, field) => {
    const config = baseAdvancedConfig();
    config[field] = [
      { instance: 'Blue', reference_bandwidth: 10000, redistribute: [{ protocol: 'static' }] },
      { instance: 'Blue', reference_bandwidth: 20000, redistribute: [{ protocol: 'direct' }] },
    ];
    const setResult = convertToSrxSetCommands(config);
    const result = buildSrxXml(config);
    const policies = result.identifierMappings.entries.filter(entry => entry.namespace === 'routing-policy');
    const role = field === 'ospf3_config'
      ? 'ospf3-redistribution-policy'
      : 'ospf-redistribution-policy';
    const expectedPolicies = [0, 1].map(index => result.identifierMappings.entries.find(entry => (
      entry.definitionPath === `${field}[${index}].redistribute[0]#generated:${role}`
    )));

    expect(result.identifierMappings).toEqual(setResult.identifierMappings);
    expect(policies).toHaveLength(2);
    expect(result.xml).toContain('<reference-bandwidth>10000</reference-bandwidth>');
    expect(result.xml).toContain('<reference-bandwidth>20000</reference-bandwidth>');
    for (const entry of policies) {
      expect(setResult.commands.some(command => command.endsWith(` export ${entry.outputName}`)))
        .toBe(true);
      expect(result.xml).toContain(`<export>${entry.outputName}</export>`);
      expect(result.xml).toContain(`<name>${entry.outputName}</name>`);
    }
    expect(result.xml.indexOf('<reference-bandwidth>10000</reference-bandwidth>'))
      .toBeLessThan(result.xml.indexOf('<reference-bandwidth>20000</reference-bandwidth>'));
    expect(result.xml.indexOf(`<export>${expectedPolicies[0].outputName}</export>`))
      .toBeLessThan(result.xml.indexOf(`<export>${expectedPolicies[1].outputName}</export>`));
    expect(result.xml.indexOf(`<name>${expectedPolicies[0].outputName}</name>`))
      .toBeLessThan(result.xml.indexOf(`<name>${expectedPolicies[1].outputName}</name>`));
  });

  it.each([
    ['OSPF', 'ospf_config'],
    ['OSPFv3', 'ospf3_config'],
  ])('retains every global %s record and export policy', (_label, field) => {
    const config = baseAdvancedConfig();
    config[field] = [
      { reference_bandwidth: 10000, redistribute: [{ protocol: 'static' }] },
      { reference_bandwidth: 20000, redistribute: [{ protocol: 'direct' }] },
    ];
    const setResult = convertToSrxSetCommands(config);
    const result = buildSrxXml(config);
    const policies = result.identifierMappings.entries.filter(entry => entry.namespace === 'routing-policy');
    const role = field === 'ospf3_config'
      ? 'ospf3-redistribution-policy'
      : 'ospf-redistribution-policy';
    const expectedPolicies = [0, 1].map(index => result.identifierMappings.entries.find(entry => (
      entry.definitionPath === `${field}[${index}].redistribute[0]#generated:${role}`
    )));

    expect(result.identifierMappings).toEqual(setResult.identifierMappings);
    expect(policies).toHaveLength(2);
    expect(result.xml).toContain('<reference-bandwidth>10000</reference-bandwidth>');
    expect(result.xml).toContain('<reference-bandwidth>20000</reference-bandwidth>');
    for (const entry of policies) {
      expect(setResult.commands.some(command => command.endsWith(` export ${entry.outputName}`)))
        .toBe(true);
      expect(result.xml).toContain(`<export>${entry.outputName}</export>`);
      expect(result.xml).toContain(`<name>${entry.outputName}</name>`);
    }
    expect(result.xml.indexOf('<reference-bandwidth>10000</reference-bandwidth>'))
      .toBeLessThan(result.xml.indexOf('<reference-bandwidth>20000</reference-bandwidth>'));
    expect(result.xml.indexOf(`<export>${expectedPolicies[0].outputName}</export>`))
      .toBeLessThan(result.xml.indexOf(`<export>${expectedPolicies[1].outputName}</export>`));
    expect(result.xml.indexOf(`<name>${expectedPolicies[0].outputName}</name>`))
      .toBeLessThan(result.xml.indexOf(`<name>${expectedPolicies[1].outputName}</name>`));
  });

  it('reuses one planned XML policy name across global any-zone combinations', () => {
    const config = baseConfig({
      zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
      security_policies: [policy('Global Access', 'any', 'trust', 'any', {
        dst_zones: ['trust', 'untrust'],
      })],
    });
    const setResult = convertToSrxSetCommands(config);
    const xmlResult = buildSrxXml(config);

    expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
    const policyEntry = xmlResult.identifierMappings.entries.find(
      entry => entry.namespace === 'security-policy',
    );
    expect(xmlResult.xml).toContain(`>${policyEntry.outputName}<`);
  });

  it.each(['Named Multi Pair', 'rule-1'])(
    'captures each planned XML policy occurrence for %s',
    policyName => {
      const config = baseConfig({
        zones: [
          { name: 'trust', interfaces: [] },
          { name: 'untrust', interfaces: [] },
          { name: 'dmz', interfaces: [] },
        ],
        security_policies: [policy(policyName, 'trust', 'untrust', 'any', {
          dst_zones: ['untrust', 'dmz'],
        })],
      });
      const setResult = convertToSrxSetCommands(config);
      const xmlResult = buildSrxXml(config);

      expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
      for (const entry of xmlResult.identifierMappings.entries.filter(
        item => item.namespace === 'security-policy',
      )) {
        expect(xmlResult.xml).toContain(`>${entry.outputName}<`);
      }
    },
  );

  it('treats built-in routing instances as planned literals', () => {
    const config = baseAdvancedConfig();
    config.static_routes = [{
      destination: '192.0.2.0/24', next_hop: '198.51.100.1', vrf: 'default',
    }];

    expect(() => buildSrxXml(config)).not.toThrow();
    expect(buildSrxXml(config).identifierMappings).toEqual(
      convertToSrxSetCommands(config).identifierMappings,
    );
  });

  it('keeps same-name BGP groups and policies scoped to their routing instances', () => {
    const config = baseAdvancedConfig();
    config.bgp_config = [
      {
        instance: 'Blue', peer_groups: [{ name: 'Peers', type: 'external', neighbors: [] }],
        redistribute: [{ protocol: 'static' }],
      },
      {
        instance: 'Red', peer_groups: [{ name: 'Peers', type: 'external', neighbors: [] }],
        redistribute: [{ protocol: 'static' }],
      },
    ];
    const result = buildSrxXml(config);

    expect(result.xml.match(/<name>Peers<\/name>/g)).toHaveLength(2);
    expect(result.xml.match(/<name>BGP-REDIST-STATIC<\/name>/g)).toHaveLength(2);
    const rootTail = result.xml.slice(result.xml.lastIndexOf('</routing-instances>') + 20);
    expect(rootTail).not.toContain('<name>Peers</name>');
    expect(rootTail).not.toContain('<name>BGP-REDIST-STATIC</name>');
  });

  it('emits every BGP record that shares one routing instance', () => {
    const config = baseAdvancedConfig();
    config.bgp_config = [
      { instance: 'Blue', peer_groups: [{ name: 'First', type: 'external', neighbors: [] }] },
      { instance: 'Blue', peer_groups: [{ name: 'Second', type: 'external', neighbors: [] }] },
    ];
    const result = buildSrxXml(config);

    expect(result.xml).toContain('<name>First</name>');
    expect(result.xml).toContain('<name>Second</name>');
    const rootTail = result.xml.slice(result.xml.lastIndexOf('</routing-instances>') + 20);
    expect(rootTail).not.toContain('<name>First</name>');
    expect(rootTail).not.toContain('<name>Second</name>');
  });

  it('consumes references from secondary global BGP records', () => {
    const config = baseAdvancedConfig();
    config.bgp_config = [
      { peer_groups: [{ name: 'Primary', type: 'external', neighbors: [] }] },
      {
        peer_groups: [{
          name: 'Secondary',
          type: 'external',
          neighbors: [{
            address: '192.0.2.2', import_policy: 'IMPORT-SECONDARY', export_policy: 'EXPORT-SECONDARY',
          }],
        }],
        networks: [{ prefix: '198.51.100.0/24', policy: 'NETWORK-SECONDARY' }],
      },
    ];
    const plan = planJunosIdentifiers(config);
    const seen = new Set();
    const identifierPlan = {
      ...plan,
      nameForReference(path) {
        seen.add(path);
        return plan.nameForReference(path);
      },
    };
    const result = buildSrxXml(config, {}, null, { identifierPlan });

    for (const path of [
      'bgp_config[1].peer_groups[0].neighbors[0].import_policy',
      'bgp_config[1].peer_groups[0].neighbors[0].export_policy',
      'bgp_config[1].networks[0].policy',
    ]) {
      expect(seen).toContain(path);
      expect(result.xml).toContain(plan.nameForReference(path));
    }
  });

  it('emits planned fallback proposal definitions for minimal VPNs', () => {
    const config = baseAdvancedConfig();
    config.vpn_tunnels = [{ name: 'Minimal VPN' }];
    const result = buildSrxXml(config);
    const proposals = result.identifierMappings.entries.filter(entry => (
      ['ike-proposal', 'ipsec-proposal'].includes(entry.namespace)
    ));

    expect(proposals).toHaveLength(2);
    for (const proposal of proposals) {
      expect(result.xml.match(new RegExp(`<proposal>\\s*<name>${proposal.outputName}</name>`)))
        .not.toBeNull();
    }
  });

  it('matches Set guards for any and service-set application operands', () => {
    const config = baseConfig({
      zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
      application_groups: [{ name: 'Mixed Group', members: ['service-set', 'any'] }],
      security_policies: [policy('Operand Guards', 'trust', 'untrust', 'any', {
        applications: ['any', 'service-set', 'Mixed Group'],
        services: ['service-set'],
      })],
    });
    const setResult = convertToSrxSetCommands(config);
    const xmlResult = buildSrxXml(config);

    expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
    expect(xmlResult.xml).toContain('<application>any</application>');
  });

  it('emits application-group-owned generated definitions structurally', () => {
    const config = baseConfig({
      zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
      application_groups: [{ name: 'Customer Group', members: ['unknown group app'] }],
      security_policies: [policy('Grouped App', 'trust', 'untrust', 'any', {
        applications: ['Customer Group'],
      })],
    });
    const result = buildSrxXml(config);
    const generated = result.identifierMappings.entries.find(entry => (
      entry.definitionPath?.startsWith('application_groups[0].members[0]#generated:')
    ));

    expect(generated).toBeDefined();
    expect(result.xml).toMatch(new RegExp(
      `<application>\\s*<name>${generated.outputName}</name>`,
    ));
  });

  it('emits every planned generated application and NAT definition', () => {
    const config = baseConfig({
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      service_objects: [{ name: 'Discrete Service', protocol: 'tcp', port_range: '8443,9443' }],
      applications: [{ name: 'Discrete App', protocol: 'udp', port: '5000,5001' }],
      security_policies: [policy('Generated Apps', 'trust', 'untrust', 'any', {
        applications: ['Discrete App', 'foo bar', 'foo@bar'],
        services: ['Discrete Service'],
      })],
      nat_rules: [
        {
          name: 'Outbound NAT', type: 'source', src_zones: ['trust'], dst_zones: ['untrust'],
          src_addresses: ['any'], dst_addresses: ['any'],
          translated_src: { type: 'dynamic-ip-pool', addresses: ['198.51.100.10/32'] },
        },
        {
          name: 'Outbound@NAT', type: 'source', src_zones: ['trust'], dst_zones: ['untrust'],
          src_addresses: ['any'], dst_addresses: ['any'],
          translated_src: { type: 'dynamic-ip-pool', addresses: ['198.51.100.11/32'] },
        },
      ],
    });
    const result = buildSrxXml(config);

    for (const entry of result.identifierMappings.entries) {
      if (entry.definitionPath !== null) {
        expect(result.xml).toContain(`>${entry.outputName}<`);
      }
    }
  });

  it('honors supplied plans, path prefixes, and target context paths', () => {
    const first = baseConfig({ zones: [{ name: 'Inside Zone', interfaces: [] }] });
    const second = baseConfig({ zones: [{ name: 'Inside@Zone', interfaces: [] }] });
    const slots = [
      { lsName: 'Branch Office', intermediateConfig: first },
      { lsName: 'Branch@Office', intermediateConfig: second },
    ];
    const identifierPlan = planMergedJunosIdentifiers(slots);
    const result = buildSrxXml(
      first,
      {},
      { type: 'logical-system', name: slots[0].lsName },
      {
        identifierPlan,
        pathPrefix: 'configSlots[0].intermediateConfig.',
        targetContextPath: 'configSlots[0].lsName',
      },
    );
    const targetName = identifierPlan.nameForDefinition('configSlots[0].lsName');
    const zoneName = identifierPlan.nameForDefinition(
      'configSlots[0].intermediateConfig.zones[0].name',
    );

    expect(result.identifierMappings).toBe(identifierPlan.mapping);
    expect(result.xml).toContain(`<name>${targetName}</name>`);
    expect(result.xml).toContain(`<name>${zoneName}</name>`);
  });

  it('fails closed when a supplied plan omits an XML definition lookup', () => {
    const config = collisionConfig();
    const plan = planJunosIdentifiers(config);
    const identifierPlan = {
      ...plan,
      nameForDefinition(path) {
        if (path === 'zones[0].name') {
          throw new JunosIdentifierPlanningError('missing_catalog_coverage', {
            definitionPaths: [path],
          });
        }
        return plan.nameForDefinition(path);
      },
    };

    expect(() => buildSrxXml(config, {}, null, { identifierPlan }))
      .toThrow(expect.objectContaining({ code: 'missing_catalog_coverage' }));
  });

  it.each([
    ['reference', 'security_policies[0].dst_addresses[0]', null],
    ['generated', 'security_policies[0].applications[0]', 'unmapped-application'],
  ])('fails closed when a supplied plan omits an XML %s lookup', (lookup, missingPath, missingRole) => {
    const config = baseConfig({
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [{ name: 'Web Server', type: 'host', value: '192.0.2.10/32' }],
      security_policies: [policy('Guarded XML', 'trust', 'untrust', 'Web Server', {
        applications: ['customer unknown app'],
      })],
    });
    const plan = planJunosIdentifiers(config);
    const identifierPlan = {
      ...plan,
      nameForReference(path) {
        if (lookup === 'reference' && path === missingPath) {
          throw new JunosIdentifierPlanningError('missing_catalog_coverage', { referencePaths: [path] });
        }
        return plan.nameForReference(path);
      },
      nameForGenerated(path, role) {
        if (lookup === 'generated' && path === missingPath && role === missingRole) {
          throw new JunosIdentifierPlanningError('missing_catalog_coverage', { definitionPaths: [path] });
        }
        return plan.nameForGenerated(path, role);
      },
    };

    expect(() => buildSrxXml(config, {}, null, { identifierPlan }))
      .toThrow(expect.objectContaining({ code: 'missing_catalog_coverage' }));
  });

  it.each([
    ['routing instance', addRoutingInstanceCollision],
    ['BGP group', addBgpGroupCollision],
    ['BGP fallback group', addBgpFallbackGroupCollision],
    ['screen profile', addScreenCollision],
    ['VPN', addVpnCollision],
    ['SNMP', addSnmpCollision],
    ['DHCP', addDhcpCollision],
    ['bridge domain', addBridgeDomainCollision],
    ['PBF', addPbfCollision],
    ['flow template', addFlowTemplateCollision],
    ['UTM', addUtmCollision],
    ['IDP', addIdpCoverage],
    ['SecIntel', addSecIntelCoverage],
    ['AppFW', addAppFwCollision],
    ['SSL', addSslCollision],
    ['SSL policy reference', addSslPolicyReferenceCollision],
    ['VLAN', addVlanCollision],
    ['QoS', addQosCollision],
    ['QoS classifier', addQosClassifierMapCollision],
    ['AAA', addAaaCollision],
    ['generated routing policy', addGeneratedRoutingPolicyCollision],
  ])('emits every planned %s definition and shares the Set mapping', (_label, mutate) => {
    const config = baseAdvancedConfig();
    mutate(config);
    const setResult = convertToSrxSetCommands(config);
    const plan = planJunosIdentifiers(config);
    const definitionLookups = new Set();
    const referenceLookups = new Set();
    const identifierPlan = {
      ...plan,
      nameForDefinition(path) {
        definitionLookups.add(path);
        return plan.nameForDefinition(path);
      },
      nameForReference(path) {
        referenceLookups.add(path);
        return plan.nameForReference(path);
      },
      nameForGenerated(path, role) {
        definitionLookups.add(`${path}#generated:${role}`);
        return plan.nameForGenerated(path, role);
      },
    };
    const xmlResult = buildSrxXml(config, {}, null, { identifierPlan });

    expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
    for (const entry of xmlResult.identifierMappings.entries) {
      if (entry.definitionPath !== null) {
        expect(xmlResult.xml).toContain(`>${entry.outputName}<`);
        expect(definitionLookups).toContain(entry.definitionPath);
      }
      for (const referencePath of entry.referencePaths) {
        expect(referenceLookups).toContain(referencePath);
      }
    }
  });

  it('uses identical identifier mappings in Set and XML', () => {
    const config = collisionConfig();
    const setResult = convertToSrxSetCommands(config);
    const xmlResult = buildSrxXml(config);

    expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
    expect(xmlResult.summary.identifier_collisions_resolved)
      .toBe(setResult.summary.identifier_collisions_resolved);
    for (const entry of xmlResult.identifierMappings.entries) {
      if (entry.definitionPath !== null) {
        expect(xmlResult.xml).toContain(`>${entry.outputName}<`);
      }
    }
  });

  it('rejects malformed exact duplicates with the same planning details in Set and XML', () => {
    const config = baseConfig({
      security_policies: [
        policy('Repeated Policy', 'trust', 'untrust', 'any'),
        policy('Repeated Policy', 'trust', 'untrust', 'any'),
      ],
    });
    const capture = converter => {
      try {
        converter(config);
      } catch (error) {
        return error;
      }
      throw new Error('expected duplicate-definition planning failure');
    };

    const setError = capture(convertToSrxSetCommands);
    const xmlError = capture(buildSrxXml);

    expect(xmlError).toEqual(expect.objectContaining({
      code: setError.code,
      namespace: setError.namespace,
      context: setError.context,
    }));
  });
});

describe('merged Set and XML identifier-plan integration', () => {
  it('rejects non-concrete cross-link zones before Set or XML emission', () => {
    const slots = [
      mergeSlot('Branch A', baseConfig()),
      mergeSlot('Branch B', baseConfig()),
    ];
    const links = [{
      ls1: 'Branch A', ls2: 'Branch B', sharedZone: 'any', lt1Unit: 1, lt2Unit: 2,
    }];

    for (const convert of [convertMergedToSrxSetCommands, buildMergedSrxXml]) {
      expect(() => convert(slots, links)).toThrow(expect.objectContaining({
        name: 'JunosSerializationError',
        fieldPath: 'crossLsLinks[0].sharedZone',
        valueKind: 'zone',
      }));
    }
  });

  it('isolates local namespaces and keeps cross-link references correct', () => {
    const slots = [
      mergeSlot('Branch Office', configWithAddress('Web Server')),
      mergeSlot('Branch@Office', configWithAddress('Web Server')),
    ];
    const links = [{
      ls1: 'Branch Office',
      ls2: 'Branch@Office',
      sharedZone: 'Shared Zone',
      lt1Unit: 1,
      lt2Unit: 2,
    }];
    const setResult = convertMergedToSrxSetCommands(slots, links);
    const xmlResult = buildMergedSrxXml(slots, links);
    const entries = setResult.identifierMappings.entries;
    const localAddresses = entries.filter(entry => (
      entry.namespace === 'address-book-entry' && entry.sourceName === 'Web Server'
    ));
    const logicalSystems = entries.filter(entry => entry.namespace === 'target-context');
    const linkSides = ['ls1', 'ls2'].map(side => ({
      logicalSystem: setResult.identifierMappings.entries.find(entry => (
        entry.referencePaths.includes(`crossLsLinks[0].${side}`)
      )).outputName,
      zone: setResult.identifierMappings.entries.find(entry => (
        entry.referencePaths.includes(`crossLsLinks[0].sharedZone#${side}`)
      )).outputName,
    }));

    expect(setResult.identifierMappings).toEqual(xmlResult.identifierMappings);
    expect(localAddresses.map(entry => entry.outputName)).toEqual(['Web-Server', 'Web-Server']);
    expect(new Set(localAddresses.map(entry => entry.context)).size).toBe(2);
    expect(logicalSystems).toHaveLength(2);
    expect(new Set(logicalSystems.map(entry => entry.outputName)).size).toBe(2);
    for (const { logicalSystem, zone } of linkSides) {
      expect(setResult.commands.some(command => command.includes(
        `set logical-systems ${logicalSystem} security zones security-zone ${zone} `,
      ))).toBe(true);
      expect(xmlResult.xml).toMatch(new RegExp(
        `<logical-systems>\\s*<name>${logicalSystem}</name>[\\s\\S]*?<security>[\\s\\S]*?<name>${zone}</name>`,
      ));
    }
    expect(setResult.summary.identifier_collisions_resolved).toBe(2);
    expect(xmlResult.summary.identifier_collisions_resolved).toBe(2);
    expect(setResult.warnings.filter(warning => warning.subType === 'identifier_collision'))
      .toHaveLength(2);
    expect(xmlResult.warnings.filter(warning => warning.subType === 'identifier_collision'))
      .toHaveLength(2);
  });

  it('keeps output-name associations stable when slots and links are reordered', () => {
    const slots = [
      mergeSlot('Branch Office', configWithAddress('Web Server')),
      mergeSlot('Branch@Office', configWithAddress('Web Server')),
      mergeSlot('Datacenter', configWithAddress('Database')),
    ];
    const links = [
      { ls1: 'Branch Office', ls2: 'Datacenter', sharedZone: 'Transit One', lt1Unit: 1, lt2Unit: 2 },
      { ls1: 'Branch@Office', ls2: 'Datacenter', sharedZone: 'Transit Two', lt1Unit: 3, lt2Unit: 4 },
    ];
    const reorderedSlots = [slots[2], slots[1], slots[0]];
    const reorderedLinks = [links[1], links[0]];

    const forwardSet = convertMergedToSrxSetCommands(slots, links);
    const reorderedSet = convertMergedToSrxSetCommands(reorderedSlots, reorderedLinks);
    const forwardXml = buildMergedSrxXml(slots, links);
    const reorderedXml = buildMergedSrxXml(reorderedSlots, reorderedLinks);

    expect(stableMappingAssociations(reorderedSet.identifierMappings))
      .toEqual(stableMappingAssociations(forwardSet.identifierMappings));
    expect(stableMappingAssociations(reorderedXml.identifierMappings))
      .toEqual(stableMappingAssociations(forwardXml.identifierMappings));
  });

  it('emits each side-specific cross-link zone collision name', () => {
    const slots = [
      mergeSlot('Branch A', configWithAddress('Web Server', {
        zones: [{ name: 'Shared Zone', interfaces: [] }, { name: 'Shared@Zone', interfaces: [] }],
      })),
      mergeSlot('Branch B', configWithAddress('Web Server', {
        zones: [{ name: 'Shared@Zone', interfaces: [] }],
      })),
    ];
    const links = [{
      ls1: 'Branch A', ls2: 'Branch B', sharedZone: 'Shared Zone', lt1Unit: 1, lt2Unit: 2,
    }];
    const setResult = convertMergedToSrxSetCommands(slots, links);
    const xmlResult = buildMergedSrxXml(slots, links);
    const side = sideName => ({
      logicalSystem: setResult.identifierMappings.entries.find(entry => (
        entry.referencePaths.includes(`crossLsLinks[0].${sideName}`)
      )).outputName,
      zone: setResult.identifierMappings.entries.find(entry => (
        entry.referencePaths.includes(`crossLsLinks[0].sharedZone#${sideName}`)
      )).outputName,
    });
    const first = side('ls1');
    const second = side('ls2');

    expect(first.zone).not.toBe(second.zone);
    expect(setResult.commands).toContain(
      `set logical-systems ${first.logicalSystem} security zones security-zone ${first.zone} interfaces lt-0/0/0.1`,
    );
    expect(setResult.commands).toContain(
      `set logical-systems ${second.logicalSystem} security zones security-zone ${second.zone} interfaces lt-0/0/0.2`,
    );
    expect(xmlResult.xml).toContain(`<name>${first.zone}</name>`);
    expect(xmlResult.xml).toContain(`<name>${second.zone}</name>`);
  });

  it('reuses NAT-generated missing zones across cross-links and input reordering', () => {
    const slots = [
      mergeSlot('Branch A', configWithMissingNatZone('Transit Zone')),
      mergeSlot('Branch B', configWithMissingNatZone('Transit Zone')),
    ];
    const links = [{
      ls1: 'Branch A', ls2: 'Branch B', sharedZone: 'Transit Zone', lt1Unit: 1, lt2Unit: 2,
    }];
    const setResult = convertMergedToSrxSetCommands(slots, links);
    const xmlResult = buildMergedSrxXml(slots, links);
    const reorderedSet = convertMergedToSrxSetCommands([...slots].reverse(), links);
    const reorderedXml = buildMergedSrxXml([...slots].reverse(), links);
    const zones = setResult.identifierMappings.entries.filter(entry => (
      entry.namespace === 'zone' && entry.sourceName === 'Transit Zone'
    ));

    expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
    expect(zones).toHaveLength(2);
    for (const [slotIndex, side] of ['ls1', 'ls2'].entries()) {
      const logicalSystem = setResult.identifierMappings.entries.find(entry => (
        entry.definitionPath === `configSlots[${slotIndex}].lsName`
      )).outputName;
      const zone = zones.find(entry => (
        entry.context === `logical-system:${slots[slotIndex].lsName}`
      ));
      expect(zone.definitionPath).toContain('#generated:nat-missing-zone:Transit Zone');
      expect(zone.referencePaths).toEqual([
        `configSlots[${slotIndex}].intermediateConfig.nat_rules[0].src_zones[0]`,
        `crossLsLinks[0].sharedZone#${side}`,
      ]);
      expect(setResult.commands).toContain(
        `set logical-systems ${logicalSystem} security zones security-zone ${zone.outputName}`,
      );
      expect(setResult.commands.some(command => command.startsWith(
        `set logical-systems ${logicalSystem} security zones security-zone ${zone.outputName} interfaces lt-0/0/0.`,
      ))).toBe(true);
      expect(xmlResult.xml).toContain(`<name>${zone.outputName}</name>`);
    }
    expect(stableMappingAssociations(reorderedSet.identifierMappings))
      .toEqual(stableMappingAssociations(setResult.identifierMappings));
    expect(stableMappingAssociations(reorderedXml.identifierMappings))
      .toEqual(stableMappingAssociations(xmlResult.identifierMappings));
  });

  it('plans root global named configuration once in both formats', () => {
    const slots = [mergeSlot('Branch', baseConfig())];
    const globalConfig = baseConfig({
      snmp_config: [
        { type: 'community', name: 'Operations Team', authorization: 'read-only' },
        { type: 'community', name: 'Operations@Team', authorization: 'read-only' },
      ],
      aaa_config: [
        { type: 'profile', name: 'Admin Access', authentication_order: ['radius'] },
        { type: 'profile', name: 'Admin@Access', authentication_order: ['tacplus'] },
      ],
    });
    const setResult = convertMergedToSrxSetCommands(slots, [], globalConfig);
    const xmlResult = buildMergedSrxXml(slots, [], globalConfig);
    const globalEntries = setResult.identifierMappings.entries.filter(entry => (
      entry.definitionPath?.startsWith('globalConfig.')
    ));

    expect(xmlResult.identifierMappings).toEqual(setResult.identifierMappings);
    expect(globalEntries).toHaveLength(4);
    for (const entry of globalEntries) {
      expect(entry.context.startsWith('root')).toBe(true);
      expect(setResult.commands.some(command => command.includes(` ${entry.outputName} `)))
        .toBe(true);
      expect(xmlResult.xml).toContain(`<name>${entry.outputName}</name>`);
    }
  });

  it.each([
    ['unknown', [mergeSlot('Branch', baseConfig())], [{
      ls1: 'Missing', ls2: 'Branch', sharedZone: 'Transit', lt1Unit: 1, lt2Unit: 2,
    }]],
    ['ambiguous', [mergeSlot('Branch', baseConfig()), mergeSlot('Branch', baseConfig())], [{
      ls1: 'Branch', ls2: 'Branch', sharedZone: 'Transit', lt1Unit: 1, lt2Unit: 2,
    }]],
  ])('fails closed for %s merged logical-system endpoints', (_label, slots, links) => {
    expect(() => convertMergedToSrxSetCommands(slots, links)).toThrow();
    expect(() => buildMergedSrxXml(slots, links)).toThrow();
  });
});

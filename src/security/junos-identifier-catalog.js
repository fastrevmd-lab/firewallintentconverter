import {
  JUNOS_PREDEFINED_APPS,
  isPredefEquivalent,
  mapAppToJunos,
  mapProfileToSrx,
  sanitizeJunosName,
} from '../parsers/parser-utils.js';
import { getJunosEmission } from '../utils/app-mappings.js';

export const JUNOS_IDENTIFIER_CATALOG = Object.freeze({
  TARGET_CONTEXT: 'target-context',
  ZONE: 'zone',
  ADDRESS_BOOK: 'address-book',
  APPLICATION: 'application',
  POLICY: 'security-policy',
  SCHEDULER: 'scheduler',
  NAT_RULE_SET: 'nat-rule-set',
  NAT_RULE: 'nat-rule',
  NAT_POOL: 'nat-pool',
  ROUTING_INSTANCE: 'routing-instance',
  ROUTING_POLICY: 'routing-policy',
  BGP_GROUP: 'bgp-group',
  SCREEN: 'screen-profile',
  IKE: 'ike',
  IPSEC: 'ipsec',
  SECURITY_PROFILE: 'security-profile',
  VLAN: 'vlan',
  BRIDGE_DOMAIN: 'bridge-domain',
  PBF: 'pbf',
  DHCP: 'dhcp',
  QOS: 'qos',
  FLOW: 'flow-monitoring',
  AAA: 'aaa',
  SNMP: 'snmp',
});

const ANY_LITERAL = Object.freeze(['any']);
const APPLICATION_LITERALS = Object.freeze(['any', ...JUNOS_PREDEFINED_APPS]);
const BUILT_IN_ROUTING_INSTANCES = Object.freeze(['default', 'master']);

function joinedPath(prefix, path) {
  return prefix ? `${prefix}.${path}` : path;
}

function deviceContext(targetContext) {
  if (!targetContext || !targetContext.type || targetContext.type === 'none') return 'root';
  return `${targetContext.type}:${targetContext.name}`;
}

function targetNamespaceContext() {
  return 'root/target-context';
}

function addressBookContext(device) {
  return `${device}/address-book:global`;
}

function applicationsContext(device) {
  return `${device}/applications`;
}

function zonePairContext(device, fromZone, toZone) {
  if (fromZone === 'any' || toZone === 'any') return `${device}/global-policy`;
  return `${device}/zone-pair:${fromZone}->${toZone}`;
}

function natRuleSetContext(device, type, fromZone, toZone) {
  return `${device}/nat:${type}/rule-set:${fromZone}->${toZone}`;
}

function routingInstanceContext(device, instance) {
  return `${device}/routing-instance:${instance || 'default'}`;
}

function nestedContext(parent, scope, name) {
  return `${parent}/${scope}:${name}`;
}

function sourceZones(item) {
  const zones = item.src_zones ?? item.source_zones;
  return Array.isArray(zones) && zones.length > 0 ? zones : ['any'];
}

function destinationZones(item) {
  const zones = item.dst_zones ?? item.destination_zones;
  return Array.isArray(zones) && zones.length > 0 ? zones : ['any'];
}

function sourceZoneField(item) {
  return item.src_zones !== undefined ? 'src_zones' : 'source_zones';
}

function destinationZoneField(item) {
  return item.dst_zones !== undefined ? 'dst_zones' : 'destination_zones';
}

function effectiveZoneReferencePath(prefix, ownerPath, item, direction, index) {
  const field = direction === 'source' ? sourceZoneField(item) : destinationZoneField(item);
  const values = item[field];
  return Array.isArray(values) && values.length > 0
    ? joinedPath(prefix, `${ownerPath}.${field}[${index}]`)
    : joinedPath(prefix, `${ownerPath}#effective-${direction}-zone`);
}

function preferredScreenName(screen) {
  return screen.name || 'default-screen';
}

function preferredVpnName(vpn) {
  return vpn.name || 'vpn-1';
}

function preferredDhcpPoolName(item) {
  return item.name || item.interface || 'dhcp-pool';
}

function isEmittedDhcpPoolRange(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split('-');
  return parts.length === 2 && parts.every(part => part.trim().length > 0);
}

function flowCollectorKey(collector) {
  return JSON.stringify([
    collector.address || '',
    collector.port || 2055,
    collector.protocol || 'ipfix',
    collector.source_address || '',
  ]);
}

function natZonePairs(rule, type) {
  if (type === 'static') return [{ fromZone: 'STATIC-NAT', toZone: '*' }];
  return sourceZones(rule).flatMap(fromZone => (
    destinationZones(rule).map(toZone => ({ fromZone, toZone }))
  ));
}

function preferredNatRuleSetName(type, fromZone, toZone) {
  return type === 'static' ? 'STATIC-NAT' : `${fromZone}-to-${toZone}`;
}

function preferredVpnNames(vpn) {
  const vpnName = preferredVpnName(vpn);
  return {
    vpnName,
    ikeProposal: vpn.ike_proposal?.name || `ike-prop-${vpnName}`,
    ikeGateway: vpn.ike_gateway?.name || `gw-${vpnName}`,
    ipsecProposal: vpn.ipsec_proposal?.name || `ipsec-prop-${vpnName}`,
    ikePolicy: `ike-pol-${vpnName}`,
    ipsecPolicy: `ipsec-pol-${vpnName}`,
  };
}

function canonicalFlowTemplateNames(collectors) {
  const keys = [...new Set((collectors || []).map(flowCollectorKey))].sort();
  return new Map(keys.map((key, index) => [key, `flow-tpl-${index + 1}`]));
}

function generatedPolicyName(policy, index) {
  const name = policy.name || '';
  const generic = !name
    || /^(rule|policy|permit|deny)[-_]?\d+$/i.test(name)
    || /^\d+$/.test(name);
  if (!generic) return null;
  const action = ['allow', 'permit'].includes(policy.action) ? 'permit' : 'deny';
  const fromZone = String(sourceZones(policy)[0] || 'any').toLowerCase();
  const toZone = String(destinationZones(policy)[0] || 'any').toLowerCase();
  const application = (policy.applications || [])[0];
  const service = (policy.services || [])[0];
  const hint = application && application !== 'any'
    ? String(application).toLowerCase().replace(/^junos-/, '')
    : service && service !== 'any' ? String(service).toLowerCase() : '';
  const parts = [action, fromZone, 'to', toZone];
  if (hint) parts.push(hint);
  return `${sanitizeJunosName(parts.join('-'))}-${index + 1}`;
}

function createSymbolCollector() {
  const definitions = [];
  const references = [];
  const reservations = [];
  const reservationKeys = new Set();

  function addDefinition({
    catalogKey, context, namespace, kind, sourceName, definitionPath,
  }) {
    if (sourceName === undefined || sourceName === null) return;
    definitions.push({
      catalogKey,
      context,
      namespace,
      kind,
      sourceName,
      definitionPath,
      generated: false,
      role: null,
      stableParentKey: null,
    });
  }

  function addReference({
    catalogKey, context, namespace, compatibleKinds, sourceName, referencePath,
    literals = [], bindingSourceName, literalOutputName,
  }) {
    if (sourceName === undefined || sourceName === null) return;
    references.push({
      catalogKey,
      context,
      namespace,
      compatibleKinds,
      sourceName,
      ...(bindingSourceName === undefined ? {} : { bindingSourceName }),
      ...(literalOutputName === undefined ? {} : { literalOutputName }),
      referencePath,
      literals,
    });
  }

  function addGenerated({
    catalogKey, context, namespace, kind, sourceName, definitionPath, role,
    stableParentKey, preferredOutputName,
  }) {
    if (sourceName === undefined || sourceName === null) return;
    definitions.push({
      catalogKey,
      context,
      namespace,
      kind,
      sourceName,
      definitionPath,
      generated: true,
      role,
      stableParentKey,
      ...(preferredOutputName === undefined ? {} : { preferredOutputName }),
    });
  }

  function addReservation({ context, namespace, outputName }) {
    const key = `${context}\0${namespace}\0${outputName}`;
    if (reservationKeys.has(key)) return;
    reservationKeys.add(key);
    reservations.push({ context, namespace, outputName });
  }

  return {
    definitions, references, reservations,
    addDefinition, addReference, addGenerated, addReservation,
  };
}

function addLiteralReservations(collector, device) {
  for (const [context, namespace, outputNames] of [
    [device, 'zone', ANY_LITERAL],
    [addressBookContext(device), 'address-book-entry', ANY_LITERAL],
    [applicationsContext(device), 'application-entry', APPLICATION_LITERALS],
    [device, 'routing-instance', BUILT_IN_ROUTING_INSTANCES],
  ]) {
    for (const outputName of outputNames) {
      collector.addReservation({ context, namespace, outputName });
    }
  }
}

function addZoneReference(collector, device, sourceName, referencePath) {
  collector.addReference({
    catalogKey: JUNOS_IDENTIFIER_CATALOG.ZONE,
    context: device,
    namespace: 'zone',
    compatibleKinds: ['zone'],
    sourceName,
    referencePath,
    literals: ANY_LITERAL,
  });
}

function addAddressReference(
  collector,
  device,
  sourceName,
  referencePath,
  compatibleKinds = ['address', 'address-set'],
) {
  collector.addReference({
    catalogKey: JUNOS_IDENTIFIER_CATALOG.ADDRESS_BOOK,
    context: addressBookContext(device),
    namespace: 'address-book-entry',
    compatibleKinds,
    sourceName,
    referencePath,
    literals: ANY_LITERAL,
  });
}

function addApplicationReference(
  collector,
  device,
  sourceName,
  referencePath,
  options = {},
) {
  collector.addReference({
    catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
    context: applicationsContext(device),
    namespace: 'application-entry',
    compatibleKinds: options.compatibleKinds || ['application', 'application-set'],
    sourceName,
    referencePath,
    literals: APPLICATION_LITERALS,
    ...(options.bindingSourceName === undefined
      ? {} : { bindingSourceName: options.bindingSourceName }),
    ...(options.literalOutputName === undefined
      ? {} : { literalOutputName: options.literalOutputName }),
  });
}

function suffixPreservingApplicationName(sourceName, suffix = '') {
  let preferred = sanitizeJunosName(sourceName).replace(/\./g, '-');
  if (/^\d/.test(preferred)) preferred = `app-${preferred}`;
  const baseLength = Math.max(1, 63 - suffix.length);
  return `${preferred.slice(0, baseLength)}${suffix}`.slice(0, 63);
}

function preferredCustomApplicationName(sourceName) {
  return suffixPreservingApplicationName(sourceName);
}

function preferredUnmappedApplicationName(sourceName) {
  return suffixPreservingApplicationName(sourceName, '-UNMAPPED');
}

function addGeneratedApplicationUse(state, sourceName, referencePath) {
  const {
    collector, device, generatedApplications, sourceVendor,
  } = state;
  const appContext = applicationsContext(device);
  const mapped = mapAppToJunos(sourceName, sourceVendor);
  if (mapped) {
    addApplicationReference(collector, device, sourceName, referencePath, {
      literalOutputName: mapped,
    });
    return;
  }

  const emission = getJunosEmission(sourceName, sourceVendor);
  const preferredName = emission?.kind === 'custom'
    ? preferredCustomApplicationName(sourceName)
    : preferredUnmappedApplicationName(sourceName);
  const definitionRole = emission?.kind === 'custom'
    ? emission.ports.length > 1 ? 'custom-application-set' : 'custom-application'
    : 'unmapped-application';
  const definitionKey = `${appContext}\0${definitionRole}\0${sourceName}`;
  if (!generatedApplications.has(definitionKey)) {
    generatedApplications.add(definitionKey);
    if (emission?.kind === 'custom' && emission.ports.length > 1) {
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
        context: appContext,
        namespace: 'application-entry',
        kind: 'application-set',
        sourceName,
        preferredOutputName: preferredName,
        definitionPath: referencePath,
        role: definitionRole,
        stableParentKey: `custom-application:${sourceName}`,
      });
      for (const port of [...emission.ports].map(String).sort()) {
        collector.addGenerated({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
          context: appContext,
          namespace: 'application-entry',
          kind: 'application',
          sourceName: `${sourceName}:port:${port}`,
          preferredOutputName: suffixPreservingApplicationName(sourceName, `-p${port}`),
          definitionPath: referencePath,
          role: `custom-application-port:${port}`,
          stableParentKey: `custom-application:${sourceName}`,
        });
      }
    } else {
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
        context: appContext,
        namespace: 'application-entry',
        kind: 'application',
        sourceName,
        preferredOutputName: preferredName,
        definitionPath: referencePath,
        role: definitionRole,
        stableParentKey: `${emission?.kind === 'custom' ? 'custom' : 'unmapped'}-application:${sourceName}`,
      });
    }
  }
  addApplicationReference(collector, device, sourceName, referencePath, {
    bindingSourceName: sourceName,
    compatibleKinds: emission?.kind === 'custom' && emission.ports.length > 1
      ? ['application-set'] : ['application'],
  });
}

function addPassthroughApplicationUse(state, sourceName, referencePath, role) {
  const appContext = applicationsContext(state.device);
  const definitionKey = `${appContext}\0${role}\0${sourceName}`;
  if (!state.generatedApplications.has(definitionKey)) {
    state.generatedApplications.add(definitionKey);
    state.collector.addGenerated({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
      context: appContext,
      namespace: 'application-entry',
      kind: 'application',
      sourceName,
      definitionPath: referencePath,
      role,
      stableParentKey: `${role}:${sourceName}`,
    });
  }
  addApplicationReference(state.collector, state.device, sourceName, referencePath, {
    bindingSourceName: sourceName,
    compatibleKinds: ['application'],
  });
}

function addResolvedApplicationUse(state, sourceName, referencePath, options = {}) {
  if (sourceName === 'service-set') return;
  if (sourceName === 'any') {
    addApplicationReference(state.collector, state.device, sourceName, referencePath);
    return;
  }
  const alias = state.applicationAliases.get(sourceName);
  if (alias) {
    addApplicationReference(state.collector, state.device, sourceName, referencePath, alias);
    return;
  }
  if (!options.service
      && ['srx', 'greenfield', 'srx_healthcheck'].includes(state.sourceVendor)) {
    addPassthroughApplicationUse(
      state,
      sourceName,
      referencePath,
      'passthrough-application',
    );
    return;
  }
  const mapped = mapAppToJunos(sourceName, state.sourceVendor);
  if (mapped) {
    addApplicationReference(state.collector, state.device, sourceName, referencePath, {
      literalOutputName: mapped,
      compatibleKinds: ['application'],
    });
    return;
  }
  if (options.service) {
    addPassthroughApplicationUse(
      state,
      sourceName,
      referencePath,
      'unresolved-service-application',
    );
    return;
  }
  addGeneratedApplicationUse(state, sourceName, referencePath);
}

function addRoutingInstanceSymbol(state, sourceName, path) {
  if (!sourceName) return;
  const { collector, device, routingInstances } = state;
  if (BUILT_IN_ROUTING_INSTANCES.includes(sourceName)) {
    collector.addReference({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.ROUTING_INSTANCE,
      context: device,
      namespace: 'routing-instance',
      compatibleKinds: ['routing-instance'],
      sourceName,
      referencePath: path,
      literals: BUILT_IN_ROUTING_INSTANCES,
    });
    return;
  }
  const key = `${device}\0${sourceName}`;
  if (!routingInstances.has(key)) {
    routingInstances.set(key, path);
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.ROUTING_INSTANCE,
      context: device,
      namespace: 'routing-instance',
      kind: 'routing-instance',
      sourceName,
      definitionPath: path,
    });
    return;
  }
  collector.addReference({
    catalogKey: JUNOS_IDENTIFIER_CATALOG.ROUTING_INSTANCE,
    context: device,
    namespace: 'routing-instance',
    compatibleKinds: ['routing-instance'],
    sourceName,
    referencePath: path,
    literals: BUILT_IN_ROUTING_INSTANCES,
  });
}

function addRoutingPolicyReference(collector, context, sourceName, path) {
  collector.addReference({
    catalogKey: JUNOS_IDENTIFIER_CATALOG.ROUTING_POLICY,
    context,
    namespace: 'routing-policy',
    compatibleKinds: ['policy-statement'],
    sourceName,
    referencePath: path,
    literals: [],
  });
}

function collectBaseObjects(config, state) {
  const { collector, device, prefix } = state;
  const addressGroupNames = new Set((config.address_groups || []).map(group => group.name));
  for (let index = 0; index < (config.zones || []).length; index += 1) {
    const zone = config.zones[index];
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.ZONE,
      context: device,
      namespace: 'zone',
      kind: 'zone',
      sourceName: zone.name,
      definitionPath: joinedPath(prefix, `zones[${index}].name`),
    });
  }

  for (let index = 0; index < (config.address_objects || []).length; index += 1) {
    const item = config.address_objects[index];
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.ADDRESS_BOOK,
      context: addressBookContext(device),
      namespace: 'address-book-entry',
      kind: 'address',
      sourceName: item.name,
      definitionPath: joinedPath(prefix, `address_objects[${index}].name`),
    });
  }

  for (let index = 0; index < (config.address_groups || []).length; index += 1) {
    const group = config.address_groups[index];
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.ADDRESS_BOOK,
      context: addressBookContext(device),
      namespace: 'address-book-entry',
      kind: 'address-set',
      sourceName: group.name,
      definitionPath: joinedPath(prefix, `address_groups[${index}].name`),
    });
    for (let memberIndex = 0; memberIndex < (group.members || []).length; memberIndex += 1) {
      addAddressReference(
        collector,
        device,
        group.members[memberIndex],
        joinedPath(prefix, `address_groups[${index}].members[${memberIndex}]`),
        addressGroupNames.has(group.members[memberIndex]) ? ['address-set'] : ['address'],
      );
    }
  }
}

function collectApplications(config, state) {
  const {
    collector, device, prefix, applicationAliases, applicationGroups,
  } = state;
  const appContext = applicationsContext(device);
  function addCommaPortItem(item, rootPath, kind, index, port) {
    const ownerPath = joinedPath(prefix, `${rootPath}[${index}]`);
    const setIdentity = `${item.name}:set`;
    const setName = suffixPreservingApplicationName(item.name, '-set');
    applicationAliases.set(item.name, {
      bindingSourceName: setIdentity,
      compatibleKinds: ['application-set'],
    });
    collector.addGenerated({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
      context: appContext,
      namespace: 'application-entry',
      kind: 'application-set',
      sourceName: setIdentity,
      preferredOutputName: setName,
      definitionPath: ownerPath,
      role: `${kind}-multi-port-set`,
      stableParentKey: `${kind}:${item.name}`,
    });
    const parts = [...new Set(port.split(',').map(part => part.trim()))].sort();
    for (const part of parts) {
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
        context: appContext,
        namespace: 'application-entry',
        kind: 'application',
        sourceName: `${item.name}:port:${part}`,
        preferredOutputName: suffixPreservingApplicationName(
          item.name, `-${part.replace('-', 'to')}`,
        ),
        definitionPath: ownerPath,
        role: `${kind}-port:${part}`,
        stableParentKey: `${kind}:${item.name}`,
      });
    }
    addApplicationReference(
      collector,
      device,
      item.name,
      joinedPath(prefix, `${rootPath}[${index}].name`),
      applicationAliases.get(item.name),
    );
  }

  for (let index = 0; index < (config.service_objects || []).length; index += 1) {
    const item = config.service_objects[index];
    const protocol = item.protocol || 'tcp';
    const port = item.port_range || '';
    const predefined = isPredefEquivalent(item.name, protocol, port);
    if (predefined) {
      applicationAliases.set(item.name, {
        literalOutputName: predefined,
        compatibleKinds: ['application'],
      });
      continue;
    }
    if (port.includes(',')) {
      addCommaPortItem(item, 'service_objects', 'service', index, port);
      continue;
    }
    const emitsWithoutPort = ['icmp', 'icmp6'].includes(protocol)
      || (protocol === 'ip' && item.protocol_number);
    if (!port && !emitsWithoutPort) continue;
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
      context: appContext,
      namespace: 'application-entry',
      kind: 'application',
      sourceName: item.name,
      definitionPath: joinedPath(prefix, `service_objects[${index}].name`),
    });
    applicationAliases.set(item.name, {
      bindingSourceName: item.name,
      compatibleKinds: ['application'],
    });
  }

  for (let index = 0; index < (config.applications || []).length; index += 1) {
    const item = config.applications[index];
    const port = item.port || '';
    if (port.includes(',')) {
      addCommaPortItem(item, 'applications', 'application', index, port);
      continue;
    }
    if (!item.protocol || !port) continue;
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
      context: appContext,
      namespace: 'application-entry',
      kind: 'application',
      sourceName: item.name,
      definitionPath: joinedPath(prefix, `applications[${index}].name`),
    });
    applicationAliases.set(item.name, {
      bindingSourceName: item.name,
      compatibleKinds: ['application'],
    });
  }

  const serviceGroups = config.service_groups || [];
  const serviceGroupNames = new Set(serviceGroups.map(group => group.name));
  for (let index = 0; index < serviceGroups.length; index += 1) {
    const group = serviceGroups[index];
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
      context: appContext,
      namespace: 'application-entry',
      kind: 'application-set',
      sourceName: group.name,
      definitionPath: joinedPath(prefix, `service_groups[${index}].name`),
    });
    applicationAliases.set(group.name, {
      bindingSourceName: group.name,
      compatibleKinds: ['application-set'],
    });
    for (let memberIndex = 0; memberIndex < (group.members || []).length; memberIndex += 1) {
      const member = group.members[memberIndex];
      const path = joinedPath(prefix, `service_groups[${index}].members[${memberIndex}]`);
      if (serviceGroupNames.has(member)) {
        addApplicationReference(collector, device, member, path, {
          compatibleKinds: ['application-set'],
        });
      } else if (applicationAliases.has(member)) {
        addApplicationReference(collector, device, member, path, applicationAliases.get(member));
      } else {
        const mapped = mapAppToJunos(member, state.sourceVendor);
        addApplicationReference(collector, device, member, path, mapped
          ? { literalOutputName: mapped, compatibleKinds: ['application'] }
          : { compatibleKinds: ['application'] });
      }
    }
  }

  for (let index = 0; index < (config.application_groups || []).length; index += 1) {
    const group = config.application_groups[index];
    applicationGroups.set(group.name, { ...group, index });
    for (let memberIndex = 0; memberIndex < (group.members || []).length; memberIndex += 1) {
      addResolvedApplicationUse(
        state,
        group.members[memberIndex],
        joinedPath(prefix, `application_groups[${index}].members[${memberIndex}]`),
      );
    }
  }
}

function collectSecurityProfiles(config, state) {
  const { collector, device, prefix, sharedDefinitions } = state;
  const profileContext = `${device}/security-profiles`;
  const utmTypes = [
    'virus', 'wildfire-analysis', 'url-filtering', 'file-blocking', 'email-filter',
    'application-control', 'dlp', 'dns-security', 'decryption', 'waf', 'casb', 'voip',
  ];
  const idpTypes = ['spyware', 'vulnerability'];
  const utmCombos = new Map();
  const idpCombos = new Map();
  const featureProfiles = new Set();

  for (let policyIndex = 0; policyIndex < (config.security_policies || []).length; policyIndex += 1) {
    const policy = config.security_policies[policyIndex];
    const securityProfiles = policy.security_profiles || {};
    const utm = {};
    const idp = {};
    for (const type of utmTypes) {
      if (securityProfiles[type]) utm[type] = securityProfiles[type];
    }
    for (const type of idpTypes) {
      if (securityProfiles[type]) idp[type] = securityProfiles[type];
    }
    for (const [type, value] of Object.entries(utm)) {
      const mapped = mapProfileToSrx(type, value);
      let namespace;
      let kind;
      const preferredName = mapped.srxProfile;
      let applicationFirewallRules = [];
      if (mapped.srxFeature === 'utm' && mapped.srxType === 'anti-virus') {
        namespace = 'utm-anti-virus-profile';
        kind = 'anti-virus-profile';
      } else if (mapped.srxFeature === 'utm' && mapped.srxType === 'web-filtering') {
        namespace = 'utm-web-filtering-profile';
        kind = 'web-filtering-profile';
      } else if (mapped.srxFeature === 'utm' && mapped.srxType === 'anti-spam') {
        namespace = 'utm-anti-spam-profile';
        kind = 'anti-spam-profile';
      } else if (mapped.srxFeature === 'appfw') {
        const definition = config.security_profile_definitions?.[`${type}:${value}`];
        const blocked = Object.entries(definition?.categories || {})
          .filter(([, action]) => ['block', 'block-all', 'reset'].includes(action))
          .sort(([left], [right]) => left.localeCompare(right));
        if (blocked.length === 0) continue;
        namespace = 'application-firewall-rule-set';
        kind = 'application-firewall-rule-set';
        applicationFirewallRules = blocked;
      } else {
        continue;
      }
      const featureKey = `${namespace}\0${value}`;
      if (!featureProfiles.has(featureKey)) {
        featureProfiles.add(featureKey);
        collector.addGenerated({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
          context: profileContext,
          namespace,
          kind,
          sourceName: value,
          preferredOutputName: preferredName,
          definitionPath: joinedPath(prefix, `security_policies[${policyIndex}]`),
          role: `security-profile-${type}`,
          stableParentKey: `${type}:${value}`,
        });
        for (let ruleIndex = 0; ruleIndex < applicationFirewallRules.length; ruleIndex += 1) {
          collector.addGenerated({
            catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
            context: nestedContext(profileContext, 'application-firewall-rule-set', value),
            namespace: 'application-firewall-rule',
            kind: 'application-firewall-rule',
            sourceName: `appfw-r${ruleIndex + 1}`,
            definitionPath: joinedPath(prefix, `security_policies[${policyIndex}]`),
            role: `application-firewall-rule-${ruleIndex + 1}`,
            stableParentKey: `application-control:${value}:${applicationFirewallRules[ruleIndex][0]}`,
          });
        }
      }
      collector.addReference({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
        context: profileContext,
        namespace,
        compatibleKinds: [kind],
        sourceName: value,
        bindingSourceName: value,
        referencePath: joinedPath(prefix, `security_policies[${policyIndex}].security_profiles.${type}`),
        literals: [],
      });
    }

    const utmKey = JSON.stringify(utm);
    if (Object.keys(utm).length > 0) {
      const combo = utmCombos.get(utmKey) || { profiles: utm, policyIndexes: [] };
      combo.policyIndexes.push(policyIndex);
      utmCombos.set(utmKey, combo);
    }
    const idpKey = JSON.stringify(idp);
    if (Object.keys(idp).length > 0) {
      const combo = idpCombos.get(idpKey) || { profiles: idp, policyIndexes: [] };
      combo.policyIndexes.push(policyIndex);
      idpCombos.set(idpKey, combo);
    }
  }

  function addProfileCombinations(combos, type) {
    const ordered = [...combos.entries()].sort(([left], [right]) => left.localeCompare(right));
    for (let comboIndex = 0; comboIndex < ordered.length; comboIndex += 1) {
      const [comboKey, combo] = ordered[comboIndex];
      const sourceName = `${type}-policy-${comboIndex + 1}`;
      const ownerIndex = combo.policyIndexes[0];
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
        context: profileContext,
        namespace: `${type}-policy`,
        kind: `${type}-policy`,
        sourceName,
        definitionPath: joinedPath(prefix, `security_policies[${ownerIndex}]`),
        role: `${type}-policy`,
        stableParentKey: `${type}-combination:${comboKey}`,
      });
      for (const policyIndex of combo.policyIndexes) {
        collector.addReference({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
          context: profileContext,
          namespace: `${type}-policy`,
          compatibleKinds: [`${type}-policy`],
          sourceName,
          referencePath: joinedPath(prefix, `security_policies[${policyIndex}]#${type}-policy`),
          literals: [],
        });
      }
      if (type !== 'idp') continue;
      let ruleIndex = 0;
      for (const [profileType, profileValue] of Object.entries(combo.profiles)) {
        const definition = config.security_profile_definitions?.[`${profileType}:${profileValue}`];
        const severityActions = definition?.severityActions || {};
        const severities = ['critical', 'high', 'medium', 'low', 'info']
          .filter(severity => severityActions[severity]);
        const ruleParts = severities.length > 0 ? severities : [null];
        for (const severity of ruleParts) {
          ruleIndex += 1;
          const ruleName = severity
            ? `${profileType}-${severity}-r${ruleIndex}`
            : `${profileType}-rule-${ruleIndex}`;
          collector.addGenerated({
            catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
            context: nestedContext(profileContext, 'idp-policy', sourceName),
            namespace: 'idp-rule',
            kind: 'idp-rule',
            sourceName: ruleName,
            definitionPath: joinedPath(prefix, `security_policies[${ownerIndex}]`),
            role: `idp-rule-${ruleIndex}`,
            stableParentKey: `idp-combination:${comboKey}:${profileType}:${severity || 'fallback'}`,
          });
        }
      }
    }
  }
  addProfileCombinations(utmCombos, 'utm');
  addProfileCombinations(idpCombos, 'idp');

  const blockLists = (config.external_lists || [])
    .map((list, index) => ({ list, index }))
    .filter(({ list }) => list.isBlockList)
    .sort((left, right) => String(left.list.name).localeCompare(String(right.list.name)));
  for (let blockIndex = 0; blockIndex < blockLists.length; blockIndex += 1) {
    const { list, index } = blockLists[blockIndex];
    const ownerPath = joinedPath(prefix, `external_lists[${index}]`);
    collector.addGenerated({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
      context: profileContext,
      namespace: 'security-intelligence-rule',
      kind: 'security-intelligence-rule',
      sourceName: `secIntel-rule-${blockIndex + 1}`,
      definitionPath: joinedPath(prefix, `external_lists[${index}].name`),
      role: 'security-intelligence-rule',
      stableParentKey: `external-list:${list.name}`,
    });
    if (blockIndex === 0) {
      for (const [sourceName, role, namespace] of [
        ['secIntel-profile', 'security-intelligence-profile', 'security-intelligence-profile'],
        ['secIntel-policy', 'security-intelligence-policy', 'security-intelligence-policy'],
      ]) {
        collector.addGenerated({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
          context: profileContext,
          namespace,
          kind: namespace,
          sourceName,
          definitionPath: ownerPath,
          role,
          stableParentKey: 'security-intelligence:block-lists',
        });
      }
    }
  }

  for (let index = 0; index < (config.decryption_rules || []).length; index += 1) {
    const rule = config.decryption_rules[index];
    if (rule.disabled || !['decrypt', 'decrypt-and-forward'].includes(rule.action)) continue;
    let role;
    let sourceName;
    if (rule.decryption_type === 'ssl-forward-proxy') {
      role = 'ssl-forward-profile';
      sourceName = rule.decryption_profile ? `ssl-fwd-${rule.decryption_profile}` : 'ssl-fwd-proxy';
    } else if (rule.decryption_type === 'ssl-inbound-inspection') {
      role = 'ssl-inbound-profile';
      sourceName = rule.decryption_profile ? `ssl-inbound-${rule.decryption_profile}` : 'ssl-inbound-proxy';
    } else if (rule.decryption_type !== 'ssh-proxy') {
      role = 'ssl-forward-profile';
      sourceName = 'ssl-fwd-proxy';
    }
    if (!role) continue;
    const sharedKey = `${device}\0ssl-proxy-profile\0${sourceName}`;
    if (!sharedDefinitions.has(sharedKey)) {
      sharedDefinitions.add(sharedKey);
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
        context: profileContext,
        namespace: 'ssl-proxy-profile',
        kind: 'ssl-proxy-profile',
        sourceName,
        definitionPath: joinedPath(prefix, `decryption_rules[${index}]`),
        role,
        stableParentKey: `decryption-profile:${rule.decryption_profile || role}`,
      });
    }
    if (rule.decryption_profile) {
      collector.addReference({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
        context: profileContext,
        namespace: 'ssl-proxy-profile',
        compatibleKinds: ['ssl-proxy-profile'],
        sourceName,
        referencePath: joinedPath(prefix, `decryption_rules[${index}].decryption_profile`),
        literals: [],
      });
    }
  }
}

function collectPoliciesAndSchedules(config, state) {
  const {
    collector, device, prefix, applicationGroups,
  } = state;
  for (let index = 0; index < (config.schedules || []).length; index += 1) {
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.SCHEDULER,
      context: device,
      namespace: 'scheduler',
      kind: 'scheduler',
      sourceName: config.schedules[index].name,
      definitionPath: joinedPath(prefix, `schedules[${index}].name`),
    });
  }

  for (let index = 0; index < (config.security_policies || []).length; index += 1) {
    const policy = config.security_policies[index];
    const preferredGeneratedName = generatedPolicyName(policy, index);
    let definitionIndex = 0;
    const definedContexts = new Set();
    for (let sourceIndex = 0; sourceIndex < sourceZones(policy).length; sourceIndex += 1) {
      const fromZone = sourceZones(policy)[sourceIndex];
      addZoneReference(collector, device, fromZone, effectiveZoneReferencePath(
        prefix, `security_policies[${index}]`, policy, 'source', sourceIndex,
      ));
      for (let destinationIndex = 0; destinationIndex < destinationZones(policy).length; destinationIndex += 1) {
        const toZone = destinationZones(policy)[destinationIndex];
        if (sourceIndex === 0) {
          addZoneReference(collector, device, toZone, effectiveZoneReferencePath(
            prefix, `security_policies[${index}]`, policy, 'destination', destinationIndex,
          ));
        }
        const context = zonePairContext(device, fromZone, toZone);
        if (definedContexts.has(context)) continue;
        definedContexts.add(context);
        definitionIndex += 1;
        if (preferredGeneratedName) {
          collector.addGenerated({
            catalogKey: JUNOS_IDENTIFIER_CATALOG.POLICY,
            context,
            namespace: 'security-policy',
            kind: 'security-policy',
            sourceName: preferredGeneratedName,
            definitionPath: joinedPath(prefix, `security_policies[${index}]`),
            role: `security-policy-${definitionIndex}`,
            stableParentKey: `security-policy:${policy.name || preferredGeneratedName}`,
          });
        } else {
          collector.addDefinition({
            catalogKey: JUNOS_IDENTIFIER_CATALOG.POLICY,
            context,
            namespace: 'security-policy',
            kind: 'security-policy',
            sourceName: policy.name,
            definitionPath: definitionIndex === 1
              ? joinedPath(prefix, `security_policies[${index}].name`)
              : joinedPath(prefix, `security_policies[${index}].name#zone-pair:${fromZone}->${toZone}`),
          });
        }
      }
    }

    for (let addressIndex = 0; addressIndex < (policy.src_addresses || []).length; addressIndex += 1) {
      addAddressReference(collector, device, policy.src_addresses[addressIndex], joinedPath(prefix, `security_policies[${index}].src_addresses[${addressIndex}]`));
    }
    for (let addressIndex = 0; addressIndex < (policy.dst_addresses || []).length; addressIndex += 1) {
      addAddressReference(collector, device, policy.dst_addresses[addressIndex], joinedPath(prefix, `security_policies[${index}].dst_addresses[${addressIndex}]`));
    }
    for (let appIndex = 0; appIndex < (policy.applications || []).length; appIndex += 1) {
      const sourceName = policy.applications[appIndex];
      const path = joinedPath(prefix, `security_policies[${index}].applications[${appIndex}]`);
      const group = applicationGroups.get(sourceName);
      if (group && (group.members || []).length > 0) {
        for (let memberIndex = 0; memberIndex < group.members.length; memberIndex += 1) {
          addResolvedApplicationUse(
            state,
            group.members[memberIndex],
            `${path}#member:${memberIndex}`,
          );
        }
      } else {
        addResolvedApplicationUse(state, sourceName, path);
      }
    }
    for (let serviceIndex = 0; serviceIndex < (policy.services || []).length; serviceIndex += 1) {
      const sourceName = policy.services[serviceIndex];
      if (['application-default', 'any', 'service-set'].includes(sourceName)) continue;
      addResolvedApplicationUse(
        state,
        sourceName,
        joinedPath(prefix, `security_policies[${index}].services[${serviceIndex}]`),
        { service: true },
      );
    }
    if (policy.schedule) {
      collector.addReference({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.SCHEDULER,
        context: device,
        namespace: 'scheduler',
        compatibleKinds: ['scheduler'],
        sourceName: policy.schedule,
        referencePath: joinedPath(prefix, `security_policies[${index}].schedule`),
        literals: [],
      });
    }
  }
}

function collectNat(config, state) {
  const { collector, device, prefix, natRuleSets } = state;
  for (let index = 0; index < (config.nat_rules || []).length; index += 1) {
    const rule = config.nat_rules[index];
    const types = rule.type === 'source-and-destination'
      ? ['source', 'destination']
      : [rule.type || 'source'];
    let occurrence = 0;
    for (const type of types) {
      const zonePairs = natZonePairs(rule, type);
      for (const { fromZone, toZone } of zonePairs) {
        const ruleSetName = preferredNatRuleSetName(type, fromZone, toZone);
        const ruleSetPath = joinedPath(prefix, `nat_rules[${index}]`);
        const ruleSetKey = `${device}\0${type}\0${fromZone}\0${toZone}`;
        if (!natRuleSets.has(ruleSetKey)) {
          natRuleSets.add(ruleSetKey);
          const role = type === 'static'
            ? 'static-nat-rule-set'
            : `${type}-nat-rule-set:${fromZone}->${toZone}`;
          collector.addGenerated({
            catalogKey: JUNOS_IDENTIFIER_CATALOG.NAT_RULE_SET,
            context: `${device}/nat:${type}`,
            namespace: 'nat-rule-set',
            kind: `${type}-nat-rule-set`,
            sourceName: ruleSetName,
            definitionPath: ruleSetPath,
            role,
            stableParentKey: `${type}-zone-pair:${fromZone}->${toZone}`,
          });
        }
        occurrence += 1;
        collector.addDefinition({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.NAT_RULE,
          context: natRuleSetContext(device, type, fromZone, toZone),
          namespace: 'nat-rule',
          kind: `${type}-nat-rule`,
          sourceName: rule.name,
          definitionPath: occurrence === 1
            ? joinedPath(prefix, `nat_rules[${index}].name`)
            : joinedPath(prefix, `nat_rules[${index}].name#${type}:${fromZone}->${toZone}`),
        });
      }
    }

    for (let zoneIndex = 0; zoneIndex < sourceZones(rule).length; zoneIndex += 1) {
      addZoneReference(collector, device, sourceZones(rule)[zoneIndex], effectiveZoneReferencePath(
        prefix, `nat_rules[${index}]`, rule, 'source', zoneIndex,
      ));
    }
    for (let zoneIndex = 0; zoneIndex < destinationZones(rule).length; zoneIndex += 1) {
      addZoneReference(collector, device, destinationZones(rule)[zoneIndex], effectiveZoneReferencePath(
        prefix, `nat_rules[${index}]`, rule, 'destination', zoneIndex,
      ));
    }

    for (const field of ['src_addresses', 'dst_addresses']) {
      for (let addressIndex = 0; addressIndex < (rule[field] || []).length; addressIndex += 1) {
        addAddressReference(collector, device, rule[field][addressIndex], joinedPath(prefix, `nat_rules[${index}].${field}[${addressIndex}]`));
      }
    }

    const ownerPath = joinedPath(prefix, `nat_rules[${index}]`);
    if (rule.translated_src?.type === 'dynamic-ip-pool') {
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.NAT_POOL,
        context: `${device}/nat:source`,
        namespace: 'source-nat-pool',
        kind: 'source-nat-pool',
        sourceName: `pool-${rule.name}`,
        definitionPath: ownerPath,
        role: 'source-nat-pool',
        stableParentKey: `source-rule:${rule.name}`,
      });
    } else if (rule.translated_src?.type === 'static') {
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.NAT_POOL,
        context: `${device}/nat:source`,
        namespace: 'source-nat-pool',
        kind: 'source-nat-pool',
        sourceName: `${rule.name}-static`,
        definitionPath: ownerPath,
        role: 'static-source-nat-pool',
        stableParentKey: `source-rule:${rule.name}`,
      });
    }
    if (rule.translated_dst) {
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.NAT_POOL,
        context: `${device}/nat:destination`,
        namespace: 'destination-nat-pool',
        kind: 'destination-nat-pool',
        sourceName: `dnat-pool-${rule.name}`,
        definitionPath: ownerPath,
        role: 'destination-nat-pool',
        stableParentKey: `destination-rule:${rule.name}`,
      });
    }
  }
}

function collectRouting(config, state) {
  const { collector, device, prefix } = state;
  for (let index = 0; index < (config.static_routes || []).length; index += 1) {
    const route = config.static_routes[index];
    if (route.vrf) addRoutingInstanceSymbol(state, route.vrf, joinedPath(prefix, `static_routes[${index}].vrf`));
    if (route.next_hop_type === 'next-vr' && route.next_hop) {
      addRoutingInstanceSymbol(state, route.next_hop, joinedPath(prefix, `static_routes[${index}].next_hop`));
    }
  }

  for (let index = 0; index < (config.bgp_config || []).length; index += 1) {
    const bgp = config.bgp_config[index];
    if (bgp.instance) addRoutingInstanceSymbol(state, bgp.instance, joinedPath(prefix, `bgp_config[${index}].instance`));
    const context = routingInstanceContext(device, bgp.instance);
    for (let groupIndex = 0; groupIndex < (bgp.peer_groups || []).length; groupIndex += 1) {
      const group = bgp.peer_groups[groupIndex];
      collector.addDefinition({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.BGP_GROUP,
        context,
        namespace: 'bgp-group',
        kind: 'bgp-group',
        sourceName: group.name,
        definitionPath: joinedPath(prefix, `bgp_config[${index}].peer_groups[${groupIndex}].name`),
      });
      for (let neighborIndex = 0; neighborIndex < (group.neighbors || []).length; neighborIndex += 1) {
        const neighbor = group.neighbors[neighborIndex];
        for (const field of ['import_policy', 'export_policy']) {
          if (neighbor[field]) addRoutingPolicyReference(collector, context, neighbor[field], joinedPath(prefix, `bgp_config[${index}].peer_groups[${groupIndex}].neighbors[${neighborIndex}].${field}`));
        }
      }
    }
    for (let networkIndex = 0; networkIndex < (bgp.networks || []).length; networkIndex += 1) {
      if (bgp.networks[networkIndex].policy) addRoutingPolicyReference(collector, context, bgp.networks[networkIndex].policy, joinedPath(prefix, `bgp_config[${index}].networks[${networkIndex}].policy`));
    }
    for (let redistIndex = 0; redistIndex < (bgp.redistribute || []).length; redistIndex += 1) {
      const redist = bgp.redistribute[redistIndex];
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.ROUTING_POLICY,
        context,
        namespace: 'routing-policy',
        kind: 'policy-statement',
        sourceName: `BGP-REDIST-${redist.protocol.toUpperCase()}`,
        definitionPath: joinedPath(prefix, `bgp_config[${index}].redistribute[${redistIndex}]`),
        role: 'bgp-redistribution-policy',
        stableParentKey: `bgp:${bgp.instance || 'default'}:${redist.protocol}`,
      });
    }
  }

  for (const [field, protocol, prefixName] of [
    ['ospf_config', 'ospf', 'OSPF'],
    ['ospf3_config', 'ospf3', 'OSPF3'],
  ]) {
    for (let index = 0; index < (config[field] || []).length; index += 1) {
      const item = config[field][index];
      if (item.instance) addRoutingInstanceSymbol(state, item.instance, joinedPath(prefix, `${field}[${index}].instance`));
      const context = routingInstanceContext(device, item.instance);
      for (let redistIndex = 0; redistIndex < (item.redistribute || []).length; redistIndex += 1) {
        const redist = item.redistribute[redistIndex];
        collector.addGenerated({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.ROUTING_POLICY,
          context,
          namespace: 'routing-policy',
          kind: 'policy-statement',
          sourceName: `${prefixName}-REDIST-${redist.protocol.toUpperCase()}`,
          definitionPath: joinedPath(prefix, `${field}[${index}].redistribute[${redistIndex}]`),
          role: `${protocol}-redistribution-policy`,
          stableParentKey: `${protocol}:${item.instance || 'default'}:${redist.protocol}`,
        });
      }
    }
  }

  for (let index = 0; index < (config.evpn_config || []).length; index += 1) {
    const evpn = config.evpn_config[index];
    if (evpn.instance) addRoutingInstanceSymbol(state, evpn.instance, joinedPath(prefix, `evpn_config[${index}].instance`));
    for (let vlanIndex = 0; vlanIndex < (evpn.vlans || []).length; vlanIndex += 1) {
      collector.addDefinition({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.VLAN,
        context: device,
        namespace: 'vlan',
        kind: 'vlan',
        sourceName: evpn.vlans[vlanIndex].name,
        definitionPath: joinedPath(prefix, `evpn_config[${index}].vlans[${vlanIndex}].name`),
      });
    }
  }

  for (let index = 0; index < (config.vxlan_config || []).length; index += 1) {
    const tunnel = config.vxlan_config[index];
    if (tunnel.instance) addRoutingInstanceSymbol(state, tunnel.instance, joinedPath(prefix, `vxlan_config[${index}].instance`));
    for (let vniIndex = 0; vniIndex < (tunnel.vnis || []).length; vniIndex += 1) {
      const vni = tunnel.vnis[vniIndex];
      if (!vni.vlan_id) continue;
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.VLAN,
        context: device,
        namespace: 'vlan',
        kind: 'vlan',
        sourceName: `VXLAN-${vni.vni}`,
        definitionPath: joinedPath(prefix, `vxlan_config[${index}].vnis[${vniIndex}]`),
        role: 'vxlan-vlan',
        stableParentKey: `vxlan-vni:${vni.vni}`,
      });
    }
  }
}

function collectScreenAndVpn(config, state) {
  const { collector, device, prefix } = state;
  for (let index = 0; index < (config.screen_config || []).length; index += 1) {
    const screen = config.screen_config[index];
    const common = {
      catalogKey: JUNOS_IDENTIFIER_CATALOG.SCREEN,
      context: device,
      namespace: 'screen-profile',
      kind: 'screen-profile',
      sourceName: preferredScreenName(screen),
    };
    if (screen.name) {
      collector.addDefinition({
        ...common,
        definitionPath: joinedPath(prefix, `screen_config[${index}].name`),
      });
    } else {
      collector.addGenerated({
        ...common,
        definitionPath: joinedPath(prefix, `screen_config[${index}]`),
        role: 'default-screen-profile',
        stableParentKey: `screen:${screen.zone || 'unbound'}`,
      });
    }
    if (screen.zone) addZoneReference(collector, device, screen.zone, joinedPath(prefix, `screen_config[${index}].zone`));
  }

  for (let index = 0; index < (config.vpn_tunnels || []).length; index += 1) {
    const vpn = config.vpn_tunnels[index];
    const {
      vpnName: sourceVpnName,
      ikeProposal,
      ikeGateway,
      ipsecProposal,
      ikePolicy,
      ipsecPolicy,
    } = preferredVpnNames(vpn);
    const ownerPath = joinedPath(prefix, `vpn_tunnels[${index}]`);
    for (const item of [
      [JUNOS_IDENTIFIER_CATALOG.IKE, 'ike-policy', 'ike-policy', ikePolicy, 'ike-policy'],
      [JUNOS_IDENTIFIER_CATALOG.IPSEC, 'ipsec-policy', 'ipsec-policy', ipsecPolicy, 'ipsec-policy'],
    ]) {
      collector.addGenerated({
        catalogKey: item[0],
        context: device,
        namespace: item[1],
        kind: item[2],
        sourceName: item[3],
        definitionPath: ownerPath,
        role: item[4],
        stableParentKey: `vpn:${sourceVpnName}`,
      });
    }
    for (const item of [
      [JUNOS_IDENTIFIER_CATALOG.IKE, 'ike-proposal', 'ike-proposal', ikeProposal, 'ike-proposal', vpn.ike_proposal?.name, 'ike_proposal.name'],
      [JUNOS_IDENTIFIER_CATALOG.IKE, 'ike-gateway', 'ike-gateway', ikeGateway, 'ike-gateway', vpn.ike_gateway?.name, 'ike_gateway.name'],
      [JUNOS_IDENTIFIER_CATALOG.IPSEC, 'ipsec-proposal', 'ipsec-proposal', ipsecProposal, 'ipsec-proposal', vpn.ipsec_proposal?.name, 'ipsec_proposal.name'],
    ]) {
      if (item[5]) {
        collector.addDefinition({
          catalogKey: item[0],
          context: device,
          namespace: item[1],
          kind: item[2],
          sourceName: item[3],
          definitionPath: joinedPath(prefix, `vpn_tunnels[${index}].${item[6]}`),
        });
      } else {
        collector.addGenerated({
          catalogKey: item[0],
          context: device,
          namespace: item[1],
          kind: item[2],
          sourceName: item[3],
          definitionPath: ownerPath,
          role: item[4],
          stableParentKey: `vpn:${sourceVpnName}`,
        });
      }
    }
    const vpnDefinition = {
      catalogKey: JUNOS_IDENTIFIER_CATALOG.IPSEC,
      context: device,
      namespace: 'ipsec-vpn',
      kind: 'ipsec-vpn',
      sourceName: sourceVpnName,
    };
    if (vpn.name) {
      collector.addDefinition({
        ...vpnDefinition,
        definitionPath: joinedPath(prefix, `vpn_tunnels[${index}].name`),
      });
    } else {
      collector.addGenerated({
        ...vpnDefinition,
        definitionPath: ownerPath,
        role: 'ipsec-vpn',
        stableParentKey: 'vpn:fallback:vpn-1',
      });
    }
    for (const [catalogKey, namespace, kind, sourceName, referencePath] of [
      [JUNOS_IDENTIFIER_CATALOG.IKE, 'ike-proposal', 'ike-proposal', ikeProposal, 'ike_proposal.name'],
      [JUNOS_IDENTIFIER_CATALOG.IKE, 'ike-policy', 'ike-policy', ikePolicy, 'name#ike-policy'],
      [JUNOS_IDENTIFIER_CATALOG.IKE, 'ike-gateway', 'ike-gateway', ikeGateway, 'ike_gateway.name'],
      [JUNOS_IDENTIFIER_CATALOG.IPSEC, 'ipsec-proposal', 'ipsec-proposal', ipsecProposal, 'ipsec_proposal.name'],
      [JUNOS_IDENTIFIER_CATALOG.IPSEC, 'ipsec-policy', 'ipsec-policy', ipsecPolicy, 'name#ipsec-policy'],
    ]) {
      collector.addReference({
        catalogKey,
        context: device,
        namespace,
        compatibleKinds: [kind],
        sourceName,
        referencePath: joinedPath(prefix, `vpn_tunnels[${index}].${referencePath}`),
        literals: [],
      });
    }
  }
}

function collectL2AndPbf(config, state) {
  const { collector, device, prefix, pbfInstances } = state;
  for (let index = 0; index < (config.bridge_domains || []).length; index += 1) {
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.BRIDGE_DOMAIN,
      context: device,
      namespace: 'bridge-domain',
      kind: 'bridge-domain',
      sourceName: config.bridge_domains[index].name,
      definitionPath: joinedPath(prefix, `bridge_domains[${index}].name`),
    });
  }
  for (let index = 0; index < (config.l2_interfaces || []).length; index += 1) {
    const item = config.l2_interfaces[index];
    if (!item.bridge_domain) continue;
    collector.addReference({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.BRIDGE_DOMAIN,
      context: device,
      namespace: 'bridge-domain',
      compatibleKinds: ['bridge-domain'],
      sourceName: item.bridge_domain,
      referencePath: joinedPath(prefix, `l2_interfaces[${index}].bridge_domain`),
      literals: [],
    });
  }
  for (let index = 0; index < (config.vwire_pairs || []).length; index += 1) {
    const item = config.vwire_pairs[index];
    collector.addGenerated({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.BRIDGE_DOMAIN,
      context: device,
      namespace: 'bridge-domain',
      kind: 'bridge-domain',
      sourceName: `vwire-${item.name}`,
      definitionPath: joinedPath(prefix, `vwire_pairs[${index}]`),
      role: 'vwire-bridge-domain',
      stableParentKey: `vwire:${item.name}`,
    });
  }

  const activePbfRules = (config.pbf_rules || []).filter(rule => !rule.disabled);
  if (activePbfRules.length > 0) {
    collector.addGenerated({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.PBF,
      context: device,
      namespace: 'firewall-filter',
      kind: 'firewall-filter',
      sourceName: 'PBF-FILTER',
      definitionPath: joinedPath(prefix, 'pbf_rules'),
      role: 'pbf-filter',
      stableParentKey: 'pbf-filter:input',
    });
    collector.addGenerated({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.PBF,
      context: nestedContext(device, 'firewall-filter', 'PBF-FILTER'),
      namespace: 'firewall-filter-term',
      kind: 'firewall-filter-term',
      sourceName: 'default',
      definitionPath: joinedPath(prefix, 'pbf_rules'),
      role: 'pbf-default-term',
      stableParentKey: 'pbf-filter:input',
    });
  }
  const forwardingByNextHop = new Map();
  for (let index = 0; index < (config.pbf_rules || []).length; index += 1) {
    const rule = config.pbf_rules[index];
    if (rule.disabled || rule.action !== 'forward' || !rule.next_hop_value) continue;
    const candidates = forwardingByNextHop.get(rule.next_hop_value) || [];
    candidates.push({ rule, index });
    forwardingByNextHop.set(rule.next_hop_value, candidates);
  }
  for (const [nextHop, candidates] of forwardingByNextHop) {
    const canonical = [...candidates].sort((left, right) => (
      String(left.rule.name).localeCompare(String(right.rule.name))
    ))[0];
    const instanceKey = `${device}\0${nextHop}`;
    if (pbfInstances.has(instanceKey)) continue;
    const instance = {
      sourceName: `PBF-${canonical.rule.name}`,
      ownerPath: joinedPath(prefix, `pbf_rules[${canonical.index}]`),
      stableParentKey: `pbf-rule:${canonical.rule.name}`,
    };
    pbfInstances.set(instanceKey, instance);
    collector.addGenerated({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.PBF,
      context: device,
      namespace: 'routing-instance',
      kind: 'routing-instance',
      sourceName: instance.sourceName,
      definitionPath: instance.ownerPath,
      role: 'pbf-routing-instance',
      stableParentKey: instance.stableParentKey,
    });
  }
  for (let index = 0; index < (config.pbf_rules || []).length; index += 1) {
    const rule = config.pbf_rules[index];
    if (rule.disabled) continue;
    const filterContext = nestedContext(device, 'firewall-filter', 'PBF-FILTER');
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.PBF,
      context: filterContext,
      namespace: 'firewall-filter-term',
      kind: 'firewall-filter-term',
      sourceName: rule.name,
      definitionPath: joinedPath(prefix, `pbf_rules[${index}].name`),
    });
    if (rule.action === 'forward' && rule.next_hop_value) {
      const instanceKey = `${device}\0${rule.next_hop_value}`;
      const instance = pbfInstances.get(instanceKey);
      collector.addReference({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.PBF,
        context: device,
        namespace: 'routing-instance',
        compatibleKinds: ['routing-instance'],
        sourceName: instance.sourceName,
        referencePath: joinedPath(prefix, `pbf_rules[${index}].next_hop_value#routing-instance`),
        literals: [],
      });
    }
    for (const field of ['src_addresses', 'dst_addresses']) {
      for (let addressIndex = 0; addressIndex < (rule[field] || []).length; addressIndex += 1) {
        addAddressReference(collector, device, rule[field][addressIndex], joinedPath(prefix, `pbf_rules[${index}].${field}[${addressIndex}]`));
      }
    }
  }
}

function collectDhcpQosFlow(config, state) {
  const { collector, device, prefix } = state;
  for (let index = 0; index < (config.dhcp_config || []).length; index += 1) {
    const item = config.dhcp_config[index];
    if (!['server', 'pool'].includes(item.type)) continue;
    const poolName = preferredDhcpPoolName(item);
    const ownerPath = joinedPath(prefix, `dhcp_config[${index}]`);
    const poolDefinition = {
      catalogKey: JUNOS_IDENTIFIER_CATALOG.DHCP,
      context: device,
      namespace: 'dhcp-pool',
      kind: 'dhcp-pool',
      sourceName: poolName,
    };
    if (item.name) {
      collector.addDefinition({
        ...poolDefinition,
        definitionPath: joinedPath(prefix, `dhcp_config[${index}].name`),
      });
    } else {
      collector.addGenerated({
        ...poolDefinition,
        definitionPath: ownerPath,
        role: 'dhcp-pool',
        stableParentKey: `dhcp-pool:${item.interface || item.network || item.subnet || 'default'}`,
      });
    }
    const poolContext = nestedContext(device, 'dhcp-pool', poolName);
    const poolRanges = (item.pools || [])
      .map((value, rangeIndex) => ({ value, rangeIndex }))
      .filter(({ value }) => isEmittedDhcpPoolRange(value))
      .sort((left, right) => String(left.value).localeCompare(String(right.value)));
    for (let canonicalIndex = 0; canonicalIndex < poolRanges.length; canonicalIndex += 1) {
      const { value, rangeIndex } = poolRanges[canonicalIndex];
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.DHCP,
        context: poolContext,
        namespace: 'dhcp-range',
        kind: 'dhcp-range',
        sourceName: `range${canonicalIndex + 1}`,
        definitionPath: joinedPath(prefix, `dhcp_config[${index}].pools[${rangeIndex}]`),
        role: 'dhcp-pool-range',
        stableParentKey: `dhcp-pool:${poolName}:range:${value}`,
      });
    }
    for (let rangeIndex = 0; rangeIndex < (item.ranges || []).length; rangeIndex += 1) {
      const range = item.ranges[rangeIndex];
      const definition = {
        catalogKey: JUNOS_IDENTIFIER_CATALOG.DHCP,
        context: poolContext,
        namespace: 'dhcp-range',
        kind: 'dhcp-range',
        sourceName: range.name || 'range1',
      };
      if (range.name) {
        collector.addDefinition({
          ...definition,
          definitionPath: joinedPath(prefix, `dhcp_config[${index}].ranges[${rangeIndex}].name`),
        });
      } else {
        collector.addGenerated({
          ...definition,
          definitionPath: joinedPath(prefix, `dhcp_config[${index}].ranges[${rangeIndex}]`),
          role: 'dhcp-named-range',
          stableParentKey: `dhcp-pool:${poolName}:named-range:${range.low || ''}-${range.high || ''}`,
        });
      }
    }
  }

  for (let index = 0; index < (config.qos_config || []).length; index += 1) {
    const qos = config.qos_config[index];
    const path = joinedPath(prefix, `qos_config[${index}].name`);
    if (qos.type === 'classifier') {
      collector.addDefinition({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'cos-classifier', kind: 'cos-classifier', sourceName: qos.name, definitionPath: path });
    } else if (qos.type === 'scheduler') {
      collector.addDefinition({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'cos-scheduler', kind: 'cos-scheduler', sourceName: qos.name, definitionPath: path });
    } else if (qos.type === 'interface-cos') {
      if (qos.scheduler_map) {
        collector.addReference({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'cos-scheduler-map', compatibleKinds: ['cos-scheduler-map'], sourceName: qos.scheduler_map, referencePath: joinedPath(prefix, `qos_config[${index}].scheduler_map`), literals: [] });
      }
    } else {
      collector.addDefinition({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'cos-scheduler-map', kind: 'cos-scheduler-map', sourceName: qos.name, definitionPath: path });
      for (let classIndex = 0; classIndex < (qos.classes || []).length; classIndex += 1) {
        const qosClass = qos.classes[classIndex];
        const className = qosClass.name || 'default';
        const classPath = joinedPath(prefix, `qos_config[${index}].classes[${classIndex}]`);
        if (qosClass.name) {
          collector.addDefinition({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'cos-scheduler', kind: 'cos-scheduler', sourceName: className, definitionPath: `${classPath}.name` });
          collector.addDefinition({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'forwarding-class', kind: 'forwarding-class', sourceName: className, definitionPath: `${classPath}.name#forwarding-class` });
        } else {
          collector.addGenerated({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'cos-scheduler', kind: 'cos-scheduler', sourceName: className, definitionPath: classPath, role: 'qos-default-scheduler', stableParentKey: `qos-map:${qos.name}:class:default` });
          collector.addGenerated({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'forwarding-class', kind: 'forwarding-class', sourceName: className, definitionPath: classPath, role: 'qos-default-forwarding-class', stableParentKey: `qos-map:${qos.name}:class:default` });
        }
      }
    }
  }

  const flow = config.flow_monitoring_config;
  if (flow && (flow.collectors || []).length > 0) {
    const instanceName = flow.instance_name || 'FLOW-SAMPLE';
    const instanceDefinition = {
      catalogKey: JUNOS_IDENTIFIER_CATALOG.FLOW,
      context: device,
      namespace: 'sampling-instance',
      kind: 'sampling-instance',
      sourceName: instanceName,
    };
    if (flow.instance_name) {
      collector.addDefinition({
        ...instanceDefinition,
        definitionPath: joinedPath(prefix, 'flow_monitoring_config.instance_name'),
      });
    } else {
      collector.addGenerated({
        ...instanceDefinition,
        definitionPath: joinedPath(prefix, 'flow_monitoring_config'),
        role: 'sampling-instance',
        stableParentKey: 'flow-monitoring:default-instance',
      });
    }
    for (let index = 0; index < (flow.templates || []).length; index += 1) {
      collector.addDefinition({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.FLOW,
        context: device,
        namespace: 'flow-template',
        kind: 'flow-template',
        sourceName: flow.templates[index].name,
        definitionPath: joinedPath(prefix, `flow_monitoring_config.templates[${index}].name`),
      });
    }
    const fallbackTemplates = canonicalFlowTemplateNames(flow.collectors || []);
    const emittedFallbacks = new Set();
    for (let index = 0; index < (flow.collectors || []).length; index += 1) {
      const collectorItem = flow.collectors[index];
      const collectorKey = flowCollectorKey(collectorItem);
      const explicitTemplate = (flow.templates || [])[index];
      const templateName = explicitTemplate?.name || fallbackTemplates.get(collectorKey);
      if (!explicitTemplate && !emittedFallbacks.has(collectorKey)) {
        emittedFallbacks.add(collectorKey);
        collector.addGenerated({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.FLOW,
          context: device,
          namespace: 'flow-template',
          kind: 'flow-template',
          sourceName: templateName,
          definitionPath: joinedPath(prefix, `flow_monitoring_config.collectors[${index}]`),
          role: 'collector-flow-template',
          stableParentKey: `collector:${collectorKey}`,
        });
      }
      collector.addReference({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.FLOW,
        context: device,
        namespace: 'flow-template',
        compatibleKinds: ['flow-template'],
        sourceName: templateName,
        referencePath: joinedPath(prefix, `flow_monitoring_config.collectors[${index}]#template`),
        literals: [],
      });
    }
  }
}

function collectAaaAndSnmp(config, state) {
  const { collector, device, prefix } = state;
  for (let index = 0; index < (config.aaa_config || []).length; index += 1) {
    const item = config.aaa_config[index];
    if (item.type !== 'profile') continue;
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.AAA,
      context: device,
      namespace: 'access-profile',
      kind: 'access-profile',
      sourceName: item.name,
      definitionPath: joinedPath(prefix, `aaa_config[${index}].name`),
    });
  }
  const snmpKinds = Object.freeze({
    community: 'snmp-community',
    'trap-group': 'snmp-trap-group',
    'v3-user': 'snmp-user',
  });
  for (let index = 0; index < (config.snmp_config || []).length; index += 1) {
    const item = config.snmp_config[index];
    const namespace = snmpKinds[item.type];
    if (!namespace) continue;
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.SNMP,
      context: device,
      namespace,
      kind: namespace,
      sourceName: item.name,
      definitionPath: joinedPath(prefix, `snmp_config[${index}].name`),
    });
  }
}

function collectConfig(config, state) {
  addLiteralReservations(state.collector, state.device);
  collectBaseObjects(config, state);
  collectApplications(config, state);
  collectSecurityProfiles(config, state);
  collectPoliciesAndSchedules(config, state);
  collectNat(config, state);
  collectRouting(config, state);
  collectScreenAndVpn(config, state);
  collectL2AndPbf(config, state);
  collectDhcpQosFlow(config, state);
  collectAaaAndSnmp(config, state);
}

export function collectJunosIdentifierSymbols(config = {}, options = {}) {
  const collector = createSymbolCollector();
  const targetContext = options.targetContext || config.target_context || null;
  const device = deviceContext(targetContext);
  if (targetContext && targetContext.type && targetContext.type !== 'none' && targetContext.name) {
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.TARGET_CONTEXT,
      context: targetNamespaceContext(),
      namespace: 'target-context',
      kind: targetContext.type,
      sourceName: targetContext.name,
      definitionPath: options.targetPath || joinedPath(options.pathPrefix || '', 'targetContext.name'),
    });
  }
  collectConfig(config || {}, {
    collector,
    device,
    prefix: options.pathPrefix || '',
    routingInstances: new Map(),
    natRuleSets: new Set(),
    pbfInstances: new Map(),
    applicationAliases: new Map(),
    applicationGroups: new Map(),
    generatedApplications: new Set(),
    sourceVendor: config.metadata?.source_vendor || '',
    sharedDefinitions: new Set(),
  });
  return Object.freeze({
    definitions: Object.freeze(collector.definitions),
    references: Object.freeze(collector.references),
    reservations: Object.freeze(collector.reservations),
  });
}

export function collectMergedJunosIdentifierSymbols(
  configSlots,
  crossLsLinks = [],
  globalConfig = {},
  options = {},
) {
  const collector = createSymbolCollector();
  const routingInstances = new Map();
  const natRuleSets = new Set();
  const pbfInstances = new Map();
  const sharedDefinitions = new Set();
  for (let index = 0; index < (configSlots || []).length; index += 1) {
    const slot = configSlots[index];
    const targetContext = { type: 'logical-system', name: slot.lsName };
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.TARGET_CONTEXT,
      context: targetNamespaceContext(),
      namespace: 'target-context',
      kind: 'logical-system',
      sourceName: slot.lsName,
      definitionPath: `configSlots[${index}].lsName`,
    });
    collectConfig(slot.intermediateConfig || {}, {
      collector,
      device: deviceContext(targetContext),
      prefix: `configSlots[${index}].intermediateConfig`,
      routingInstances,
      natRuleSets,
      pbfInstances,
      applicationAliases: new Map(),
      applicationGroups: new Map(),
      generatedApplications: new Set(),
      sourceVendor: slot.intermediateConfig?.metadata?.source_vendor || '',
      sharedDefinitions,
    });
  }

  for (let index = 0; index < (crossLsLinks || []).length; index += 1) {
    const link = crossLsLinks[index];
    for (const side of ['ls1', 'ls2']) {
      collector.addReference({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.TARGET_CONTEXT,
        context: targetNamespaceContext(),
        namespace: 'target-context',
        compatibleKinds: ['logical-system'],
        sourceName: link[side],
        referencePath: `crossLsLinks[${index}].${side}`,
        literals: [],
      });
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.ZONE,
        context: deviceContext({ type: 'logical-system', name: link[side] }),
        namespace: 'zone',
        kind: 'zone',
        sourceName: link.sharedZone,
        definitionPath: `crossLsLinks[${index}].sharedZone`,
        role: `cross-link-zone-${side}`,
        stableParentKey: `cross-link:${link.ls1}->${link.ls2}:${link.sharedZone}`,
      });
    }
  }

  if (globalConfig && Object.keys(globalConfig).length > 0) {
    collectConfig(globalConfig, {
      collector,
      device: 'root',
      prefix: 'globalConfig',
      routingInstances,
      natRuleSets,
      pbfInstances,
      applicationAliases: new Map(),
      applicationGroups: new Map(),
      generatedApplications: new Set(),
      sourceVendor: globalConfig.metadata?.source_vendor || '',
      sharedDefinitions,
    });
  }
  void options;
  return Object.freeze({
    definitions: Object.freeze(collector.definitions),
    references: Object.freeze(collector.references),
    reservations: Object.freeze(collector.reservations),
  });
}

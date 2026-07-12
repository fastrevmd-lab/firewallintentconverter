import { JUNOS_PREDEFINED_APPS, sanitizeJunosName } from '../parsers/parser-utils.js';

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
  return item.src_zones || item.source_zones || ['any'];
}

function destinationZones(item) {
  return item.dst_zones || item.destination_zones || ['any'];
}

function sourceZoneField(item) {
  return item.src_zones ? 'src_zones' : 'source_zones';
}

function destinationZoneField(item) {
  return item.dst_zones ? 'dst_zones' : 'destination_zones';
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
    literals = [],
  }) {
    if (sourceName === undefined || sourceName === null) return;
    references.push({
      catalogKey,
      context,
      namespace,
      compatibleKinds,
      sourceName,
      referencePath,
      literals,
    });
  }

  function addGenerated({
    catalogKey, context, namespace, kind, sourceName, definitionPath, role,
    stableParentKey,
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
    });
  }

  return { definitions, references, addDefinition, addReference, addGenerated };
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

function addAddressReference(collector, device, sourceName, referencePath) {
  collector.addReference({
    catalogKey: JUNOS_IDENTIFIER_CATALOG.ADDRESS_BOOK,
    context: addressBookContext(device),
    namespace: 'address-book-entry',
    compatibleKinds: ['address', 'address-set'],
    sourceName,
    referencePath,
    literals: ANY_LITERAL,
  });
}

function addApplicationReference(collector, device, sourceName, referencePath) {
  collector.addReference({
    catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
    context: applicationsContext(device),
    namespace: 'application-entry',
    compatibleKinds: ['application', 'application-set'],
    sourceName,
    referencePath,
    literals: APPLICATION_LITERALS,
  });
}

function addRoutingInstanceSymbol(state, sourceName, path) {
  if (!sourceName) return;
  const { collector, device, routingInstances } = state;
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
      );
    }
  }
}

function collectApplications(config, state) {
  const { collector, device, prefix, applicationAliases } = state;
  const appContext = applicationsContext(device);

  function collectApplicationItems(items, rootPath, kind) {
    for (let index = 0; index < (items || []).length; index += 1) {
      const item = items[index];
      const port = item.port_range || item.port || '';
      const ownerPath = joinedPath(prefix, `${rootPath}[${index}]`);
      if (port.includes(',')) {
        applicationAliases.set(item.name, `${item.name}-set`);
        collector.addGenerated({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
          context: appContext,
          namespace: 'application-entry',
          kind: 'application-set',
          sourceName: `${item.name}-set`,
          definitionPath: ownerPath,
          role: `${kind}-multi-port-set`,
          stableParentKey: `${kind}:${item.name}`,
        });
        const parts = port.split(',').map(part => part.trim());
        for (let partIndex = 0; partIndex < parts.length; partIndex += 1) {
          collector.addGenerated({
            catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
            context: appContext,
            namespace: 'application-entry',
            kind: 'application',
            sourceName: `${item.name}-${parts[partIndex].replace('-', 'to')}`,
            definitionPath: ownerPath,
            role: `${kind}-port-${partIndex + 1}`,
            stableParentKey: `${kind}:${item.name}`,
          });
        }
        collector.addReference({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
          context: appContext,
          namespace: 'application-entry',
          compatibleKinds: ['application-set'],
          sourceName: `${item.name}-set`,
          referencePath: joinedPath(prefix, `${rootPath}[${index}].name`),
          literals: [],
        });
      } else {
        collector.addDefinition({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
          context: appContext,
          namespace: 'application-entry',
          kind: 'application',
          sourceName: item.name,
          definitionPath: joinedPath(prefix, `${rootPath}[${index}].name`),
        });
      }
    }
  }

  collectApplicationItems(config.service_objects || [], 'service_objects', 'service');
  collectApplicationItems(config.applications || [], 'applications', 'application');

  const groupCollections = [
    ['service_groups', config.service_groups || []],
    ['application_groups', config.application_groups || []],
  ];
  for (const [rootPath, groups] of groupCollections) {
    for (let index = 0; index < groups.length; index += 1) {
      const group = groups[index];
      collector.addDefinition({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.APPLICATION,
        context: appContext,
        namespace: 'application-entry',
        kind: 'application-set',
        sourceName: group.name,
        definitionPath: joinedPath(prefix, `${rootPath}[${index}].name`),
      });
      for (let memberIndex = 0; memberIndex < (group.members || []).length; memberIndex += 1) {
        addApplicationReference(
          collector,
          device,
          applicationAliases.get(group.members[memberIndex]) || group.members[memberIndex],
          joinedPath(prefix, `${rootPath}[${index}].members[${memberIndex}]`),
        );
      }
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
      let namespace;
      let kind;
      let preferredName;
      let applicationFirewallRules = [];
      if (type === 'virus' || type === 'wildfire-analysis') {
        namespace = 'utm-anti-virus-profile';
        kind = 'anti-virus-profile';
        preferredName = `custom-av-${value}`;
      } else if (type === 'url-filtering') {
        namespace = 'utm-web-filtering-profile';
        kind = 'web-filtering-profile';
        preferredName = `custom-wf-${value}`;
      } else if (type === 'email-filter') {
        namespace = 'utm-anti-spam-profile';
        kind = 'anti-spam-profile';
        preferredName = `junos-as-${value}`;
      } else if (type === 'application-control') {
        const definition = config.security_profile_definitions?.[`${type}:${value}`];
        const blocked = Object.entries(definition?.categories || {})
          .filter(([, action]) => ['block', 'block-all', 'reset'].includes(action));
        if (blocked.length === 0) continue;
        namespace = 'application-firewall-rule-set';
        kind = 'application-firewall-rule-set';
        preferredName = `appfw-${value}`;
        applicationFirewallRules = blocked;
      } else {
        continue;
      }
      const featureKey = `${namespace}\0${preferredName}`;
      if (!featureProfiles.has(featureKey)) {
        featureProfiles.add(featureKey);
        collector.addGenerated({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
          context: profileContext,
          namespace,
          kind,
          sourceName: preferredName,
          definitionPath: joinedPath(prefix, `security_policies[${policyIndex}]`),
          role: `security-profile-${type}`,
          stableParentKey: `${type}:${value}`,
        });
        for (let ruleIndex = 0; ruleIndex < applicationFirewallRules.length; ruleIndex += 1) {
          collector.addGenerated({
            catalogKey: JUNOS_IDENTIFIER_CATALOG.SECURITY_PROFILE,
            context: nestedContext(profileContext, 'application-firewall-rule-set', preferredName),
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
        sourceName: preferredName,
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
  const { collector, device, prefix, applicationAliases } = state;
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
      addZoneReference(collector, device, fromZone, joinedPath(prefix, `security_policies[${index}].${sourceZoneField(policy)}[${sourceIndex}]`));
      for (let destinationIndex = 0; destinationIndex < destinationZones(policy).length; destinationIndex += 1) {
        const toZone = destinationZones(policy)[destinationIndex];
        if (sourceIndex === 0) {
          addZoneReference(collector, device, toZone, joinedPath(prefix, `security_policies[${index}].${destinationZoneField(policy)}[${destinationIndex}]`));
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
    for (const field of ['applications', 'services']) {
      for (let appIndex = 0; appIndex < (policy[field] || []).length; appIndex += 1) {
        const sourceName = applicationAliases.get(policy[field][appIndex]) || policy[field][appIndex];
        addApplicationReference(collector, device, sourceName, joinedPath(prefix, `security_policies[${index}].${field}[${appIndex}]`));
      }
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
      const fromZone = sourceZones(rule)[0] || 'any';
      const toZone = destinationZones(rule)[0] || 'any';
      const ruleSetName = type === 'static' ? 'STATIC-NAT' : `${fromZone}-to-${toZone}`;
      const contextFrom = type === 'static' ? 'STATIC-NAT' : fromZone;
      const contextTo = type === 'static' ? '*' : toZone;
      const ruleSetPath = joinedPath(prefix, `nat_rules[${index}]`);
      const ruleSetKey = `${device}\0${type}\0${contextFrom}\0${contextTo}`;
      if (!natRuleSets.has(ruleSetKey)) {
        natRuleSets.add(ruleSetKey);
        collector.addGenerated({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.NAT_RULE_SET,
          context: `${device}/nat:${type}`,
          namespace: 'nat-rule-set',
          kind: `${type}-nat-rule-set`,
          sourceName: ruleSetName,
          definitionPath: ruleSetPath,
          role: `${type}-nat-rule-set`,
          stableParentKey: `${type}-zone-pair:${contextFrom}->${contextTo}`,
        });
      }
      occurrence += 1;
      collector.addDefinition({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.NAT_RULE,
        context: natRuleSetContext(device, type, contextFrom, contextTo),
        namespace: 'nat-rule',
        kind: `${type}-nat-rule`,
        sourceName: rule.name,
        definitionPath: occurrence === 1
          ? joinedPath(prefix, `nat_rules[${index}].name`)
          : joinedPath(prefix, `nat_rules[${index}].name#${type}`),
      });
    }

    for (let zoneIndex = 0; zoneIndex < sourceZones(rule).length; zoneIndex += 1) {
      addZoneReference(collector, device, sourceZones(rule)[zoneIndex], joinedPath(prefix, `nat_rules[${index}].${sourceZoneField(rule)}[${zoneIndex}]`));
    }
    for (let zoneIndex = 0; zoneIndex < destinationZones(rule).length; zoneIndex += 1) {
      addZoneReference(collector, device, destinationZones(rule)[zoneIndex], joinedPath(prefix, `nat_rules[${index}].${destinationZoneField(rule)}[${zoneIndex}]`));
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
  const { collector, device, prefix, sharedDefinitions } = state;
  for (let index = 0; index < (config.screen_config || []).length; index += 1) {
    const screen = config.screen_config[index];
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.SCREEN,
      context: device,
      namespace: 'screen-profile',
      kind: 'screen-profile',
      sourceName: screen.name || 'default-screen',
      definitionPath: joinedPath(prefix, `screen_config[${index}].name`),
    });
    if (screen.zone) addZoneReference(collector, device, screen.zone, joinedPath(prefix, `screen_config[${index}].zone`));
  }

  for (let index = 0; index < (config.vpn_tunnels || []).length; index += 1) {
    const vpn = config.vpn_tunnels[index];
    const sourceVpnName = vpn.name || 'vpn-1';
    const vpnName = sanitizeJunosName(sourceVpnName);
    const ownerPath = joinedPath(prefix, `vpn_tunnels[${index}]`);
    const ikeProposal = vpn.ike_proposal?.name || `ike-prop-${vpnName}`;
    const ikeGateway = vpn.ike_gateway?.name || `gw-${vpnName}`;
    const ipsecProposal = vpn.ipsec_proposal?.name || `ipsec-prop-${vpnName}`;
    const ikePolicy = `ike-pol-${vpnName}`;
    const ipsecPolicy = `ipsec-pol-${vpnName}`;
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
        const sharedKey = `${device}\0${item[1]}\0${item[3]}`;
        if (!sharedDefinitions.has(sharedKey)) {
          sharedDefinitions.add(sharedKey);
          collector.addDefinition({
            catalogKey: item[0],
            context: device,
            namespace: item[1],
            kind: item[2],
            sourceName: item[3],
            definitionPath: joinedPath(prefix, `vpn_tunnels[${index}].${item[6]}`),
          });
        }
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
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.IPSEC,
      context: device,
      namespace: 'ipsec-vpn',
      kind: 'ipsec-vpn',
      sourceName: sourceVpnName,
      definitionPath: joinedPath(prefix, `vpn_tunnels[${index}].name`),
    });
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
    const poolName = item.name || item.interface || 'dhcp-pool';
    const ownerPath = joinedPath(prefix, `dhcp_config[${index}]`);
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.DHCP,
      context: device,
      namespace: 'dhcp-pool',
      kind: 'dhcp-pool',
      sourceName: poolName,
      definitionPath: joinedPath(prefix, `dhcp_config[${index}].name`),
    });
    const poolContext = nestedContext(device, 'dhcp-pool', poolName);
    for (let rangeIndex = 0; rangeIndex < (item.pools || []).length; rangeIndex += 1) {
      collector.addGenerated({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.DHCP,
        context: poolContext,
        namespace: 'dhcp-range',
        kind: 'dhcp-range',
        sourceName: `range${rangeIndex + 1}`,
        definitionPath: ownerPath,
        role: `dhcp-pool-range-${rangeIndex + 1}`,
        stableParentKey: `dhcp-pool:${poolName}`,
      });
    }
    for (let rangeIndex = 0; rangeIndex < (item.ranges || []).length; rangeIndex += 1) {
      collector.addDefinition({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.DHCP,
        context: poolContext,
        namespace: 'dhcp-range',
        kind: 'dhcp-range',
        sourceName: item.ranges[rangeIndex].name || 'range1',
        definitionPath: joinedPath(prefix, `dhcp_config[${index}].ranges[${rangeIndex}].name`),
      });
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
        const className = qos.classes[classIndex].name || 'default';
        collector.addDefinition({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'cos-scheduler', kind: 'cos-scheduler', sourceName: className, definitionPath: joinedPath(prefix, `qos_config[${index}].classes[${classIndex}].name`) });
        collector.addDefinition({ catalogKey: JUNOS_IDENTIFIER_CATALOG.QOS, context: device, namespace: 'forwarding-class', kind: 'forwarding-class', sourceName: className, definitionPath: joinedPath(prefix, `qos_config[${index}].classes[${classIndex}].name#forwarding-class`) });
      }
    }
  }

  const flow = config.flow_monitoring_config;
  if (flow && (flow.collectors || []).length > 0) {
    const instanceName = flow.instance_name || 'FLOW-SAMPLE';
    collector.addDefinition({
      catalogKey: JUNOS_IDENTIFIER_CATALOG.FLOW,
      context: device,
      namespace: 'sampling-instance',
      kind: 'sampling-instance',
      sourceName: instanceName,
      definitionPath: joinedPath(prefix, 'flow_monitoring_config.instance_name'),
    });
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
    for (let index = 0; index < (flow.collectors || []).length; index += 1) {
      const template = (flow.templates || [])[index] || { name: `flow-tpl-${index + 1}` };
      if (!(flow.templates || [])[index]) {
        collector.addGenerated({
          catalogKey: JUNOS_IDENTIFIER_CATALOG.FLOW,
          context: device,
          namespace: 'flow-template',
          kind: 'flow-template',
          sourceName: template.name,
          definitionPath: joinedPath(prefix, `flow_monitoring_config.collectors[${index}]`),
          role: 'collector-flow-template',
          stableParentKey: `collector:${flow.collectors[index].address}`,
        });
      }
      collector.addReference({
        catalogKey: JUNOS_IDENTIFIER_CATALOG.FLOW,
        context: device,
        namespace: 'flow-template',
        compatibleKinds: ['flow-template'],
        sourceName: template.name,
        referencePath: joinedPath(prefix, `flow_monitoring_config.collectors[${index}].template`),
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
    sharedDefinitions: new Set(),
  });
  return Object.freeze({
    definitions: Object.freeze(collector.definitions),
    references: Object.freeze(collector.references),
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
      sharedDefinitions,
    });
  }
  void options;
  return Object.freeze({
    definitions: Object.freeze(collector.definitions),
    references: Object.freeze(collector.references),
  });
}

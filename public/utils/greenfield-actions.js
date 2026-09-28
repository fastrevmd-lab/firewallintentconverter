/**
 * applyGreenfieldAction — pure reducer for JSON action blocks emitted by the
 * Greenfield chat LLM (see components/GreenfieldChat.jsx).
 *
 * Security policies proposed here are LLM output, not a human decision, so
 * they are stamped `_review_status: 'llm_reviewed'` — the same status the
 * LLM-translate flow uses (see utils/llm-client.js) — never `'accepted'`.
 * Only the human "Accept Policy" action (layout/RightPanel.jsx) may set
 * `'accepted'`, which is what every export/push/acceptance gate checks for.
 */
export function applyGreenfieldAction(prevConfig, action, data) {
  const updated = { ...prevConfig };
  switch (action) {
    case 'add_zone':
      updated.zones = [...(updated.zones || []), { name: data.name, description: data.description || '', interfaces: data.interfaces || [], screen: data.screen || '', host_inbound_traffic: data.host_inbound_traffic || {} }];
      break;
    case 'add_address': {
      const ip = data.ip || data.value || '';
      updated.address_objects = [...(updated.address_objects || []), { name: data.name, type: data.type || (ip.endsWith('/32') ? 'host' : 'subnet'), value: ip, description: data.description || '' }];
      break;
    }
    case 'add_address_group':
      updated.address_groups = [...(updated.address_groups || []), { name: data.name, members: data.members || [], description: data.description || '' }];
      break;
    case 'add_service':
      updated.service_objects = [...(updated.service_objects || []), { name: data.name, protocol: data.protocol || 'tcp', port: data.port || '', description: data.description || '' }];
      break;
    case 'add_policy': {
      const idx = (updated.security_policies?.length || 0) + 1;
      updated.security_policies = [...(updated.security_policies || []), { name: data.name, _rule_index: idx, action: data.action || 'deny', src_zones: data.src_zones || [], dst_zones: data.dst_zones || [], src_addresses: data.src_addresses || ['any'], dst_addresses: data.dst_addresses || ['any'], negate_source: false, negate_destination: false, applications: data.applications || [], services: data.services || ['any'], log_start: data.log_start || false, log_end: data.log_end !== false, disabled: false, description: data.description || '', tags: ['greenfield'], profile_group: '', security_profiles: {}, _review_status: 'llm_reviewed' }];
      break;
    }
    case 'add_nat':
      updated.nat_rules = [...(updated.nat_rules || []), { name: data.name, type: data.type || 'source', src_zones: data.src_zones || [], dst_zones: data.dst_zones || [], src_addresses: data.src_addresses || ['any'], dst_addresses: data.dst_addresses || ['any'], translated_src: data.translated_src || null, translated_dst: data.translated_dst || null, translated_port: data.translated_port || null, description: data.description || '' }];
      break;
    case 'add_screen': {
      const screenOpts = data.options || {};
      updated.screen_config = [...(updated.screen_config || []), {
        name: data.name, zone: data.zone || '',
        icmp_flood: screenOpts.icmp_flood, udp_flood: screenOpts.udp_flood,
        syn_flood: screenOpts.syn_flood, port_scan: screenOpts.port_scan,
        ip_sweep: screenOpts.ip_sweep, land_attack: screenOpts.land_attack,
        ping_death: screenOpts.ping_death, tear_drop: screenOpts.tear_drop,
        winnuke: screenOpts.winnuke, ip_spoofing: screenOpts.ip_spoofing,
      }];
      break;
    }
    case 'set_syslog':
      updated.syslog_config = [...(updated.syslog_config || []), { host: data.host, port: data.port || 514, protocol: data.protocol || 'udp', facility: data.facility || 'local0', source_address: data.source_address || '' }];
      break;
    case 'add_route':
      updated.static_routes = [...(updated.static_routes || []), { destination: data.destination, next_hop: data.next_hop, description: data.description || '' }];
      break;
    case 'set_system': {
      const mgmt = data.management_services || {};
      updated.system_config = {
        ...(updated.system_config || {}),
        hostname: data.hostname ?? updated.system_config?.hostname,
        domain_name: data.domain_name ?? updated.system_config?.domain_name,
        timezone: data.timezone ?? updated.system_config?.timezone,
        login_banner: data.login_banner ?? updated.system_config?.login_banner,
        dns_servers: data.dns_servers || updated.system_config?.dns_servers || [],
        ntp_servers: data.ntp_servers || updated.system_config?.ntp_servers || [],
        management_services: {
          ...(updated.system_config?.management_services || {}),
          ssh: mgmt.ssh ?? updated.system_config?.management_services?.ssh,
          https: mgmt.https ?? updated.system_config?.management_services?.https,
          netconf: mgmt.netconf ?? updated.system_config?.management_services?.netconf,
          snmp: mgmt.snmp ?? updated.system_config?.management_services?.snmp,
        },
      };
      break;
    }
    default: break;
  }
  updated.metadata = { ...updated.metadata, zone_count: updated.zones?.length || 0, rule_count: updated.security_policies?.length || 0, nat_rule_count: updated.nat_rules?.length || 0, object_count: (updated.address_objects?.length || 0) + (updated.address_groups?.length || 0) + (updated.service_objects?.length || 0), vpn_tunnel_count: updated.vpn_tunnels?.length || 0, static_route_count: updated.static_routes?.length || 0 };
  return updated;
}

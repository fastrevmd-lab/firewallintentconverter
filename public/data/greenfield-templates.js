/**
 * Greenfield Template Scaffolds
 * ===============================
 * Pre-built intermediateConfig objects for common deployment use cases.
 * Each template pre-fills ~80% of a typical config so the LLM chat
 * only handles refinements.
 */

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function makePolicy(name, idx, opts) {
  return {
    name,
    _rule_index: idx,
    action: opts.action || 'allow',
    src_zones: opts.src_zones || [],
    dst_zones: opts.dst_zones || [],
    src_addresses: opts.src_addresses || ['any'],
    dst_addresses: opts.dst_addresses || ['any'],
    applications: opts.applications || [],
    services: opts.services || ['any'],
    log_start: opts.log_start || false,
    log_end: opts.log_end !== false,
    disabled: false,
    negate_source: false,
    negate_destination: false,
    description: opts.description || '',
    tags: ['greenfield'],
    profile_group: '',
    security_profiles: {},
    _review_status: 'accepted',
  };
}

function makeZone(name, description, iface, opts = {}) {
  return {
    name,
    description,
    interfaces: iface ? [iface] : [],
    screen: opts.screen || '',
    host_inbound_traffic: opts.host_inbound_traffic || { system_services: ['ping'], protocols: [] },
  };
}

function makeAddress(name, ip, description) {
  const type = ip.endsWith('/32') ? 'host' : 'subnet';
  return { name, type, value: ip, description };
}

function makeSystemConfig(hostname, extras = {}) {
  return {
    hostname,
    domain_name: extras.domain_name || 'example.com',
    dns_servers: extras.dns_servers || ['8.8.8.8', '8.8.4.4'],
    ntp_servers: extras.ntp_servers || ['pool.ntp.org'],
    timezone: extras.timezone || 'UTC',
    login_banner: extras.login_banner || 'Authorized access only. All activity is monitored.',
    management_services: {
      ssh: true,
      https: extras.https || false,
      netconf: extras.netconf || false,
    },
  };
}

const emptySystemConfig = {
  hostname: '',
  domain_name: '',
  dns_servers: [],
  ntp_servers: [],
  timezone: '',
  login_banner: '',
  management_services: { ssh: true, https: false, netconf: false },
};

// ---------------------------------------------------------------------------
// Branch Office
// ---------------------------------------------------------------------------

const branchConfig = {
  metadata: {
    source_vendor: 'greenfield',
    template_id: 'branch',
    template_label: 'Branch Office',
    source_version: '',
    zone_count: 3,
    rule_count: 6,
    nat_rule_count: 1,
    object_count: 4,
    vpn_tunnel_count: 0,
    static_route_count: 1,
  },
  system_config: makeSystemConfig('srx-branch-01'),
  zones: [
    makeZone('trust', 'Internal LAN', 'ge-0/0/1.0', {
      screen: 'trust-screen',
      host_inbound_traffic: { system_services: ['ssh', 'ping', 'dhcp'], protocols: [] },
    }),
    makeZone('untrust', 'Internet-facing', 'ge-0/0/0.0', {
      screen: 'untrust-screen',
      host_inbound_traffic: { system_services: ['ping'], protocols: [] },
    }),
    makeZone('management', 'Out-of-band management', 'fxp0.0', {
      host_inbound_traffic: { system_services: ['ssh', 'https', 'ping'], protocols: [] },
    }),
  ],
  address_objects: [
    makeAddress('lan-subnet', '192.168.1.0/24', 'Branch LAN subnet'),
    makeAddress('dns-google-primary', '8.8.8.8/32', 'Google DNS primary'),
    makeAddress('dns-google-secondary', '8.8.4.4/32', 'Google DNS secondary'),
    makeAddress('mgmt-subnet', '10.255.0.0/24', 'Management network'),
  ],
  address_groups: [
    { name: 'dns-servers', members: ['dns-google-primary', 'dns-google-secondary'], description: 'DNS server group' },
  ],
  service_objects: [],
  service_groups: [],
  applications: [],
  application_groups: [],
  security_policies: [
    makePolicy('allow-outbound-web', 1, {
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['lan-subnet'], dst_addresses: ['any'],
      applications: ['junos-http', 'junos-https'],
      description: 'Allow outbound web access',
    }),
    makePolicy('allow-dns', 2, {
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['lan-subnet'], dst_addresses: ['dns-servers'],
      applications: ['junos-dns-udp', 'junos-dns-tcp'],
      description: 'Allow DNS resolution',
    }),
    makePolicy('allow-ntp', 3, {
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['junos-ntp'],
      description: 'Allow NTP time sync',
    }),
    makePolicy('allow-mgmt-ssh', 4, {
      src_zones: ['management'], dst_zones: ['junos-host'],
      src_addresses: ['mgmt-subnet'], dst_addresses: ['any'],
      applications: ['junos-ssh'],
      description: 'Allow SSH management access',
    }),
    makePolicy('allow-icmp', 5, {
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['junos-ping'],
      description: 'Allow ICMP for troubleshooting',
    }),
    makePolicy('deny-all-cleanup', 6, {
      action: 'deny',
      src_zones: ['any'], dst_zones: ['any'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: [], log_start: true, log_end: false,
      description: 'Default deny all — cleanup rule',
    }),
  ],
  nat_rules: [
    {
      name: 'source-nat-internet', type: 'source',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      translated_src: { type: 'interface' }, translated_dst: null, translated_port: null,
      description: 'PAT to egress interface for internet access',
    },
  ],
  vpn_tunnels: [],
  static_routes: [
    { destination: '0.0.0.0/0', next_hop: '203.0.113.1', description: 'Default route to ISP gateway' },
  ],
  interfaces: [],
  routing_contexts: [],
  ha_config: { enabled: false },
  screen_config: [
    { name: 'untrust-screen', zone: 'untrust', tcp_syn_flood: true, icmp_flood: true, land_attack: true, ping_death: true },
  ],
  syslog_config: [
    { host: '10.0.1.100', port: 514, protocol: 'udp', facility: 'local0', source_address: '192.168.1.1' },
  ],
  dhcp_config: [],
  qos_config: [],
};

// ---------------------------------------------------------------------------
// Data Center
// ---------------------------------------------------------------------------

const datacenterConfig = {
  metadata: {
    source_vendor: 'greenfield',
    template_id: 'datacenter',
    template_label: 'Data Center',
    source_version: '',
    zone_count: 5,
    rule_count: 9,
    nat_rule_count: 1,
    object_count: 5,
    vpn_tunnel_count: 0,
    static_route_count: 1,
  },
  system_config: makeSystemConfig('srx-dc-01', { https: true, netconf: true }),
  zones: [
    makeZone('trust', 'Internal server network', 'ge-0/0/1.0', {
      screen: 'trust-screen',
      host_inbound_traffic: { system_services: ['ssh', 'ping'], protocols: [] },
    }),
    makeZone('untrust', 'Internet / external', 'ge-0/0/0.0', {
      screen: 'untrust-screen',
      host_inbound_traffic: { system_services: ['ping'], protocols: [] },
    }),
    makeZone('dmz', 'DMZ — public-facing servers', 'ge-0/0/2.0', {
      screen: 'dmz-screen',
      host_inbound_traffic: { system_services: ['ping'], protocols: [] },
    }),
    makeZone('server', 'Protected backend servers', 'ge-0/0/3.0', {
      host_inbound_traffic: { system_services: ['ping'], protocols: [] },
    }),
    makeZone('management', 'Out-of-band management', 'fxp0.0', {
      host_inbound_traffic: { system_services: ['ssh', 'https', 'ping', 'netconf'], protocols: [] },
    }),
  ],
  address_objects: [
    makeAddress('dc-trust-subnet', '10.0.1.0/24', 'Data center trust network'),
    makeAddress('dmz-subnet', '10.0.2.0/24', 'DMZ network'),
    makeAddress('server-subnet', '10.0.3.0/24', 'Backend server network'),
    makeAddress('mgmt-subnet', '10.255.0.0/24', 'Management network'),
    makeAddress('dmz-web-server', '10.0.2.10/32', 'DMZ web server'),
  ],
  address_groups: [
    { name: 'internal-networks', members: ['dc-trust-subnet', 'server-subnet'], description: 'All internal networks' },
  ],
  service_objects: [],
  service_groups: [],
  applications: [],
  application_groups: [],
  security_policies: [
    makePolicy('allow-untrust-to-dmz-web', 1, {
      src_zones: ['untrust'], dst_zones: ['dmz'],
      src_addresses: ['any'], dst_addresses: ['dmz-web-server'],
      applications: ['junos-http', 'junos-https'],
      description: 'Allow inbound web traffic to DMZ',
    }),
    makePolicy('allow-dmz-to-server', 2, {
      src_zones: ['dmz'], dst_zones: ['server'],
      src_addresses: ['dmz-web-server'], dst_addresses: ['server-subnet'],
      applications: ['junos-https'],
      description: 'Allow DMZ web server to backend API',
    }),
    makePolicy('deny-dmz-to-trust', 3, {
      action: 'deny',
      src_zones: ['dmz'], dst_zones: ['trust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: [], log_start: true, log_end: false,
      description: 'Block DMZ from reaching trust network',
    }),
    makePolicy('allow-trust-to-untrust', 4, {
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['dc-trust-subnet'], dst_addresses: ['any'],
      applications: ['junos-http', 'junos-https', 'junos-dns-udp', 'junos-dns-tcp'],
      description: 'Allow trust outbound web and DNS',
    }),
    makePolicy('allow-trust-to-server', 5, {
      src_zones: ['trust'], dst_zones: ['server'],
      src_addresses: ['dc-trust-subnet'], dst_addresses: ['server-subnet'],
      applications: ['junos-ssh', 'junos-https'],
      description: 'Allow admin access to backend servers',
    }),
    makePolicy('allow-server-dns-ntp', 6, {
      src_zones: ['server'], dst_zones: ['untrust'],
      src_addresses: ['server-subnet'], dst_addresses: ['any'],
      applications: ['junos-dns-udp', 'junos-ntp'],
      description: 'Allow servers DNS and NTP',
    }),
    makePolicy('allow-mgmt-ssh', 7, {
      src_zones: ['management'], dst_zones: ['junos-host'],
      src_addresses: ['mgmt-subnet'], dst_addresses: ['any'],
      applications: ['junos-ssh', 'junos-https'],
      description: 'Allow management access to firewall',
    }),
    makePolicy('allow-icmp-all', 8, {
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['junos-ping'],
      description: 'Allow ICMP for troubleshooting',
    }),
    makePolicy('deny-all-cleanup', 9, {
      action: 'deny',
      src_zones: ['any'], dst_zones: ['any'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: [], log_start: true, log_end: false,
      description: 'Default deny all — cleanup rule',
    }),
  ],
  nat_rules: [
    {
      name: 'source-nat-internet', type: 'source',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      translated_src: { type: 'interface' }, translated_dst: null, translated_port: null,
      description: 'PAT for outbound internet access',
    },
  ],
  vpn_tunnels: [],
  static_routes: [
    { destination: '0.0.0.0/0', next_hop: '203.0.113.1', description: 'Default route to upstream router' },
  ],
  interfaces: [],
  routing_contexts: [],
  ha_config: { enabled: false },
  screen_config: [
    { name: 'untrust-screen', zone: 'untrust', tcp_syn_flood: true, icmp_flood: true, land_attack: true, ping_death: true },
    { name: 'dmz-screen', zone: 'dmz', tcp_syn_flood: true, icmp_flood: true, land_attack: true, ping_death: true },
    { name: 'trust-screen', zone: 'trust', tcp_syn_flood: true, land_attack: true, ping_death: true },
  ],
  syslog_config: [
    { host: '10.255.0.50', port: 514, protocol: 'udp', facility: 'local0', source_address: '10.0.1.1' },
  ],
  dhcp_config: [],
  qos_config: [],
};

// ---------------------------------------------------------------------------
// Campus / Enterprise Edge
// ---------------------------------------------------------------------------

const campusConfig = {
  metadata: {
    source_vendor: 'greenfield',
    template_id: 'campus',
    template_label: 'Campus / Enterprise Edge',
    source_version: '',
    zone_count: 5,
    rule_count: 9,
    nat_rule_count: 2,
    object_count: 5,
    vpn_tunnel_count: 0,
    static_route_count: 1,
  },
  system_config: makeSystemConfig('srx-campus-01', { https: true }),
  zones: [
    makeZone('trust', 'Employee network', 'ge-0/0/1.0', {
      screen: 'trust-screen',
      host_inbound_traffic: { system_services: ['ssh', 'ping', 'dhcp'], protocols: [] },
    }),
    makeZone('untrust', 'Internet uplink', 'ge-0/0/0.0', {
      screen: 'untrust-screen',
      host_inbound_traffic: { system_services: ['ping'], protocols: [] },
    }),
    makeZone('guest', 'Guest / BYOD network', 'ge-0/0/2.0', {
      screen: 'guest-screen',
      host_inbound_traffic: { system_services: ['ping', 'dhcp'], protocols: [] },
    }),
    makeZone('voip', 'Voice over IP VLAN', 'ge-0/0/3.0', {
      host_inbound_traffic: { system_services: ['ping'], protocols: [] },
    }),
    makeZone('management', 'Network management', 'fxp0.0', {
      host_inbound_traffic: { system_services: ['ssh', 'https', 'ping'], protocols: [] },
    }),
  ],
  address_objects: [
    makeAddress('employee-subnet', '10.10.0.0/16', 'Employee network'),
    makeAddress('guest-subnet', '10.20.0.0/24', 'Guest WiFi network'),
    makeAddress('voip-subnet', '10.30.0.0/24', 'VoIP VLAN'),
    makeAddress('mgmt-subnet', '10.255.0.0/24', 'Management network'),
    makeAddress('sip-server', '10.30.0.10/32', 'SIP/PBX server'),
  ],
  address_groups: [
    { name: 'internal-all', members: ['employee-subnet', 'voip-subnet'], description: 'All internal user networks' },
  ],
  service_objects: [],
  service_groups: [],
  applications: [],
  application_groups: [],
  security_policies: [
    makePolicy('allow-employee-web', 1, {
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['employee-subnet'], dst_addresses: ['any'],
      applications: ['junos-http', 'junos-https'],
      description: 'Allow employee internet access',
    }),
    makePolicy('allow-employee-dns-ntp', 2, {
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['employee-subnet'], dst_addresses: ['any'],
      applications: ['junos-dns-udp', 'junos-dns-tcp', 'junos-ntp'],
      description: 'Allow employee DNS and NTP',
    }),
    makePolicy('allow-guest-web-only', 3, {
      src_zones: ['guest'], dst_zones: ['untrust'],
      src_addresses: ['guest-subnet'], dst_addresses: ['any'],
      applications: ['junos-http', 'junos-https', 'junos-dns-udp'],
      description: 'Guest — web and DNS only, no internal access',
    }),
    makePolicy('deny-guest-to-trust', 4, {
      action: 'deny',
      src_zones: ['guest'], dst_zones: ['trust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: [], log_start: true, log_end: false,
      description: 'Block guest from reaching internal network',
    }),
    makePolicy('deny-guest-to-voip', 5, {
      action: 'deny',
      src_zones: ['guest'], dst_zones: ['voip'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: [], log_start: true, log_end: false,
      description: 'Block guest from reaching VoIP network',
    }),
    makePolicy('allow-voip-sip', 6, {
      src_zones: ['voip'], dst_zones: ['untrust'],
      src_addresses: ['voip-subnet'], dst_addresses: ['any'],
      applications: ['junos-sip'],
      description: 'Allow VoIP SIP traffic to provider',
    }),
    makePolicy('allow-trust-to-voip', 7, {
      src_zones: ['trust'], dst_zones: ['voip'],
      src_addresses: ['employee-subnet'], dst_addresses: ['sip-server'],
      applications: ['junos-sip'],
      description: 'Allow employees to reach PBX',
    }),
    makePolicy('allow-mgmt-ssh', 8, {
      src_zones: ['management'], dst_zones: ['junos-host'],
      src_addresses: ['mgmt-subnet'], dst_addresses: ['any'],
      applications: ['junos-ssh', 'junos-https'],
      description: 'Allow management access to firewall',
    }),
    makePolicy('deny-all-cleanup', 9, {
      action: 'deny',
      src_zones: ['any'], dst_zones: ['any'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: [], log_start: true, log_end: false,
      description: 'Default deny all — cleanup rule',
    }),
  ],
  nat_rules: [
    {
      name: 'source-nat-employee', type: 'source',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      translated_src: { type: 'interface' }, translated_dst: null, translated_port: null,
      description: 'PAT for employee internet access',
    },
    {
      name: 'source-nat-guest', type: 'source',
      src_zones: ['guest'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      translated_src: { type: 'interface' }, translated_dst: null, translated_port: null,
      description: 'PAT for guest internet access',
    },
  ],
  vpn_tunnels: [],
  static_routes: [
    { destination: '0.0.0.0/0', next_hop: '203.0.113.1', description: 'Default route to ISP' },
  ],
  interfaces: [],
  routing_contexts: [],
  ha_config: { enabled: false },
  screen_config: [
    { name: 'untrust-screen', zone: 'untrust', tcp_syn_flood: true, icmp_flood: true, land_attack: true, ping_death: true },
    { name: 'guest-screen', zone: 'guest', tcp_syn_flood: true, icmp_flood: true, land_attack: true, ping_death: true },
    { name: 'trust-screen', zone: 'trust', tcp_syn_flood: true, land_attack: true, ping_death: true },
  ],
  syslog_config: [
    { host: '10.255.0.50', port: 514, protocol: 'udp', facility: 'local0', source_address: '10.10.0.1' },
  ],
  dhcp_config: [
    {
      name: 'guest-dhcp',
      type: 'server',
      interface: 'ge-0/0/2.0',
      pool_name: 'guest-pool',
      network: '10.20.0.0/24',
      range_low: '10.20.0.100',
      range_high: '10.20.0.200',
      gateway: '10.20.0.1',
      dns_servers: ['8.8.8.8', '8.8.4.4'],
      lease_time: 3600,
    },
  ],
  qos_config: [],
};

// ---------------------------------------------------------------------------
// Cloud Gateway
// ---------------------------------------------------------------------------

const cloudConfig = {
  metadata: {
    source_vendor: 'greenfield',
    template_id: 'cloud',
    template_label: 'Cloud Gateway',
    source_version: '',
    zone_count: 4,
    rule_count: 8,
    nat_rule_count: 1,
    object_count: 5,
    vpn_tunnel_count: 0,
    static_route_count: 3,
  },
  system_config: makeSystemConfig('srx-cloud-gw-01', { https: true, netconf: true }),
  zones: [
    makeZone('trust', 'On-premises network', 'ge-0/0/1.0', {
      screen: 'trust-screen',
      host_inbound_traffic: { system_services: ['ssh', 'ping'], protocols: ['bgp'] },
    }),
    makeZone('untrust', 'Internet / WAN', 'ge-0/0/0.0', {
      screen: 'untrust-screen',
      host_inbound_traffic: { system_services: ['ping', 'ike'], protocols: [] },
    }),
    makeZone('cloud-east', 'Cloud region east (VPN overlay)', 'st0.0', {
      host_inbound_traffic: { system_services: ['ping'], protocols: ['bgp'] },
    }),
    makeZone('cloud-west', 'Cloud region west (VPN overlay)', 'st0.1', {
      host_inbound_traffic: { system_services: ['ping'], protocols: ['bgp'] },
    }),
  ],
  address_objects: [
    makeAddress('onprem-network', '10.0.0.0/8', 'On-premises corporate network'),
    makeAddress('cloud-east-vpc', '172.16.0.0/16', 'Cloud east VPC range'),
    makeAddress('cloud-west-vpc', '172.17.0.0/16', 'Cloud west VPC range'),
    makeAddress('mgmt-subnet', '10.255.0.0/24', 'Management network'),
    makeAddress('shared-services', '10.100.0.0/16', 'On-prem shared services (DNS, AD, NTP)'),
  ],
  address_groups: [
    { name: 'all-cloud-vpcs', members: ['cloud-east-vpc', 'cloud-west-vpc'], description: 'All cloud VPC ranges' },
  ],
  service_objects: [],
  service_groups: [],
  applications: [],
  application_groups: [],
  security_policies: [
    makePolicy('allow-onprem-to-cloud-east', 1, {
      src_zones: ['trust'], dst_zones: ['cloud-east'],
      src_addresses: ['onprem-network'], dst_addresses: ['cloud-east-vpc'],
      applications: [],
      services: ['any'],
      description: 'Allow on-prem to cloud east VPC',
    }),
    makePolicy('allow-onprem-to-cloud-west', 2, {
      src_zones: ['trust'], dst_zones: ['cloud-west'],
      src_addresses: ['onprem-network'], dst_addresses: ['cloud-west-vpc'],
      applications: [],
      services: ['any'],
      description: 'Allow on-prem to cloud west VPC',
    }),
    makePolicy('allow-cloud-to-shared-services', 3, {
      src_zones: ['cloud-east', 'cloud-west'], dst_zones: ['trust'],
      src_addresses: ['all-cloud-vpcs'], dst_addresses: ['shared-services'],
      applications: ['junos-dns-udp', 'junos-dns-tcp', 'junos-ntp', 'junos-ldap'],
      description: 'Allow cloud to on-prem shared services (DNS, NTP, AD)',
    }),
    makePolicy('allow-cloud-east-to-west', 4, {
      src_zones: ['cloud-east'], dst_zones: ['cloud-west'],
      src_addresses: ['cloud-east-vpc'], dst_addresses: ['cloud-west-vpc'],
      applications: [],
      services: ['any'],
      description: 'Allow cross-region cloud traffic (east to west)',
    }),
    makePolicy('allow-cloud-west-to-east', 5, {
      src_zones: ['cloud-west'], dst_zones: ['cloud-east'],
      src_addresses: ['cloud-west-vpc'], dst_addresses: ['cloud-east-vpc'],
      applications: [],
      services: ['any'],
      description: 'Allow cross-region cloud traffic (west to east)',
    }),
    makePolicy('allow-outbound-web', 6, {
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['onprem-network'], dst_addresses: ['any'],
      applications: ['junos-http', 'junos-https', 'junos-dns-udp', 'junos-ntp'],
      description: 'Allow on-prem outbound web, DNS, NTP',
    }),
    makePolicy('allow-mgmt-ssh', 7, {
      src_zones: ['trust'], dst_zones: ['junos-host'],
      src_addresses: ['mgmt-subnet'], dst_addresses: ['any'],
      applications: ['junos-ssh', 'junos-https'],
      description: 'Allow management access to firewall',
    }),
    makePolicy('deny-all-cleanup', 8, {
      action: 'deny',
      src_zones: ['any'], dst_zones: ['any'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: [], log_start: true, log_end: false,
      description: 'Default deny all — cleanup rule',
    }),
  ],
  nat_rules: [
    {
      name: 'source-nat-internet', type: 'source',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      translated_src: { type: 'interface' }, translated_dst: null, translated_port: null,
      description: 'PAT for outbound internet access',
    },
  ],
  vpn_tunnels: [],
  static_routes: [
    { destination: '0.0.0.0/0', next_hop: '203.0.113.1', description: 'Default route to ISP' },
    { destination: '172.16.0.0/16', next_hop: 'st0.0', description: 'Route to cloud east VPC via VPN' },
    { destination: '172.17.0.0/16', next_hop: 'st0.1', description: 'Route to cloud west VPC via VPN' },
  ],
  interfaces: [],
  routing_contexts: [],
  ha_config: { enabled: false },
  screen_config: [
    { name: 'untrust-screen', zone: 'untrust', tcp_syn_flood: true, icmp_flood: true, land_attack: true, ping_death: true },
    { name: 'trust-screen', zone: 'trust', tcp_syn_flood: true, land_attack: true, ping_death: true },
  ],
  syslog_config: [
    { host: '10.255.0.50', port: 514, protocol: 'udp', facility: 'local0', source_address: '10.0.0.1' },
  ],
  dhcp_config: [],
  qos_config: [],
};

// ---------------------------------------------------------------------------
// Blank (current behavior — empty config)
// ---------------------------------------------------------------------------

const blankConfig = {
  metadata: {
    source_vendor: 'greenfield',
    template_id: 'blank',
    template_label: 'Blank',
    source_version: '',
    zone_count: 0,
    rule_count: 0,
    nat_rule_count: 0,
    object_count: 0,
    vpn_tunnel_count: 0,
    static_route_count: 0,
  },
  system_config: { ...emptySystemConfig },
  zones: [],
  address_objects: [],
  address_groups: [],
  service_objects: [],
  service_groups: [],
  applications: [],
  application_groups: [],
  security_policies: [],
  nat_rules: [],
  vpn_tunnels: [],
  static_routes: [],
  interfaces: [],
  routing_contexts: [],
  ha_config: { enabled: false },
  screen_config: [],
  syslog_config: [],
  dhcp_config: [],
  qos_config: [],
};

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export const GREENFIELD_TEMPLATES = {
  branch: {
    id: 'branch',
    label: 'Branch Office',
    description: 'Small office with internet access, optional VPN to HQ',
    icon: 'building',
    config: branchConfig,
  },
  datacenter: {
    id: 'datacenter',
    label: 'Data Center',
    description: 'Multi-tier server protection with DMZ and strict segmentation',
    icon: 'server',
    config: datacenterConfig,
  },
  campus: {
    id: 'campus',
    label: 'Campus / Enterprise Edge',
    description: 'Multi-VLAN with guest isolation, VoIP, and user segmentation',
    icon: 'globe',
    config: campusConfig,
  },
  cloud: {
    id: 'cloud',
    label: 'Cloud Gateway',
    description: 'Hybrid cloud connectivity with multi-region VPN overlays',
    icon: 'cloud',
    config: cloudConfig,
  },
  blank: {
    id: 'blank',
    label: 'Blank (Custom)',
    description: 'Start from scratch with a full LLM-guided interview',
    icon: 'plus',
    config: blankConfig,
  },
};

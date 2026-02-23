/**
 * Hardware Port Database
 * ========================
 * Comprehensive port/interface data for PAN-OS and SRX firewall models.
 *
 * Used by:
 *   - ModelSelector to present source/target model choices
 *   - InterfaceMapper to show available ports for zone mapping
 *   - detectPanosModel() to auto-detect source hardware from parsed config
 *
 * Port naming conventions:
 *   PAN-OS:  ethernet{slot}/{port}          e.g., ethernet1/1, ethernet1/2
 *   SRX:     ge-{fpc}/{pic}/{port}          e.g., ge-0/0/0 (1GbE)
 *            xe-{fpc}/{pic}/{port}          e.g., xe-0/0/0 (10GbE)
 *            et-{fpc}/{pic}/{port}          e.g., et-0/0/0 (25/40/100GbE)
 */

// ---------------------------------------------------------------------------
// Helper: generate a range of ports
// ---------------------------------------------------------------------------

function genPorts(prefix, start, end, type, speed) {
  const ports = [];
  for (let i = start; i <= end; i++) {
    const name = prefix.replace('{}', i);
    ports.push({ name, type, speed, label: name });
  }
  return ports;
}

function genSrxPorts(ifPrefix, fpc, pic, start, end, type, speed) {
  const ports = [];
  for (let i = start; i <= end; i++) {
    const name = `${ifPrefix}-${fpc}/${pic}/${i}`;
    ports.push({ name, type, speed, label: name });
  }
  return ports;
}

// ---------------------------------------------------------------------------
// SRX4700 Port Profiles — configurable via chassis fpc port-profile
// Each profile defines port layout per PIC (both PICs are identical).
// ---------------------------------------------------------------------------
export const SRX4700_PORT_PROFILES = {
  'D-2X400G-4X100G-4X50G': {
    label: '2x400G + 4x100G + 4x50G',
    description: 'Max 400G density — two 400G, four 100G, four 50G',
    perPic: (fpc, pic) => [
      ...genSrxPorts('et', fpc, pic, 0, 0, 'QSFP56-DD', '400G'),
      ...genSrxPorts('et', fpc, pic, 1, 1, 'QSFP56-DD', '400G'),
      ...genSrxPorts('et', fpc, pic, 2, 3, 'QSFP28', '100G'),
      ...genSrxPorts('et', fpc, pic, 6, 7, 'SFP56', '50G'),
    ],
  },
  'D-2X400G-2X100G-8X50G': {
    label: '2x400G + 2x100G + 8x50G',
    description: 'Balanced 400G — two 400G, two 100G, eight 50G',
    perPic: (fpc, pic) => [
      ...genSrxPorts('et', fpc, pic, 0, 0, 'QSFP56-DD', '400G'),
      ...genSrxPorts('et', fpc, pic, 1, 1, 'QSFP56-DD', '400G'),
      ...genSrxPorts('et', fpc, pic, 2, 2, 'QSFP28', '100G'),
      ...genSrxPorts('et', fpc, pic, 6, 9, 'SFP56', '50G'),
    ],
  },
  'D-12X100G-4X50G': {
    label: '12x100G + 4x50G',
    description: 'Max 100G density — twelve 100G, four 50G',
    perPic: (fpc, pic) => [
      ...genSrxPorts('et', fpc, pic, 0, 5, 'QSFP28', '100G'),
      ...genSrxPorts('et', fpc, pic, 6, 7, 'SFP56', '50G'),
    ],
  },
  'D-6X100G-16X50G': {
    label: '6x100G + 16x50G',
    description: 'Max 50G density — six 100G, sixteen 50G',
    perPic: (fpc, pic) => [
      ...genSrxPorts('et', fpc, pic, 0, 2, 'QSFP28', '100G'),
      ...genSrxPorts('et', fpc, pic, 6, 13, 'SFP56', '50G'),
    ],
  },
  'D-8X100G-12X50G': {
    label: '8x100G + 12x50G',
    description: 'Balanced — eight 100G, twelve 50G',
    perPic: (fpc, pic) => [
      ...genSrxPorts('et', fpc, pic, 0, 3, 'QSFP28', '100G'),
      ...genSrxPorts('et', fpc, pic, 6, 11, 'SFP56', '50G'),
    ],
  },
};

export const SRX4700_DEFAULT_PROFILE = 'D-6X100G-16X50G';

/** Generate SRX4700 ports for a given profile key (both PICs on FPC 1) */
export function getSrx4700Ports(profileKey) {
  const profile = SRX4700_PORT_PROFILES[profileKey || SRX4700_DEFAULT_PROFILE];
  if (!profile) return [];
  return [
    ...profile.perPic(1, 0),
    ...profile.perPic(1, 1),
  ];
}

// ---------------------------------------------------------------------------
// PAN-OS Firewall Models
// ---------------------------------------------------------------------------

export const PANOS_MODELS = {
  // ---- Branch / Entry ----
  'PA-220': {
    name: 'PA-220',
    tier: 'branch',
    description: 'Entry-level branch firewall (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '500 Mbps', threat: '150 Mbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
    ],
  },

  // ---- PA-400 Series ----
  'PA-410': {
    name: 'PA-410',
    tier: 'branch',
    description: 'Entry-level next-gen firewall',
    throughput: { l4: 'N/A', l7: '1.4 Gbps', threat: '800 Mbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 4, 'copper', '1G'),
    ],
  },

  'PA-415': {
    name: 'PA-415',
    tier: 'branch',
    description: 'Branch firewall with SFP combo and PoE',
    throughput: { l4: 'N/A', l7: '1.5 Gbps', threat: '800 Mbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 7, 'copper', '1G'),
      { name: 'ethernet1/8', type: 'SFP', speed: '1G', label: 'ethernet1/8 (combo)' },
    ],
  },

  'PA-415-5G': {
    name: 'PA-415-5G',
    tier: 'branch',
    description: 'Branch firewall with integrated 5G modem',
    throughput: { l4: 'N/A', l7: '1.5 Gbps', threat: '800 Mbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 7, 'copper', '1G'),
      { name: 'ethernet1/8', type: 'SFP', speed: '1G', label: 'ethernet1/8 (combo)' },
    ],
  },

  'PA-440': {
    name: 'PA-440',
    tier: 'branch',
    description: 'Branch firewall with 8 copper ports',
    throughput: { l4: 'N/A', l7: '2.4 Gbps', threat: '1.0 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
    ],
  },

  'PA-445': {
    name: 'PA-445',
    tier: 'branch',
    description: 'Branch firewall with SFP combo and PoE',
    throughput: { l4: 'N/A', l7: '2.2 Gbps', threat: '1.0 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 6, 'copper', '1G'),
      { name: 'ethernet1/7', type: 'SFP', speed: '1G', label: 'ethernet1/7 (combo)' },
      { name: 'ethernet1/8', type: 'SFP', speed: '1G', label: 'ethernet1/8 (combo)' },
    ],
  },

  'PA-450': {
    name: 'PA-450',
    tier: 'branch',
    description: 'High-performance branch firewall',
    throughput: { l4: 'N/A', l7: '2.9 Gbps', threat: '1.6 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
    ],
  },

  'PA-455': {
    name: 'PA-455',
    tier: 'branch',
    description: 'Branch firewall with SFP combo and PoE',
    throughput: { l4: 'N/A', l7: '3.6 Gbps', threat: '2.3 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 6, 'copper', '1G'),
      { name: 'ethernet1/7', type: 'SFP', speed: '1G', label: 'ethernet1/7 (combo)' },
      { name: 'ethernet1/8', type: 'SFP', speed: '1G', label: 'ethernet1/8 (combo)' },
    ],
  },

  'PA-460': {
    name: 'PA-460',
    tier: 'branch',
    description: 'Premium branch firewall',
    throughput: { l4: 'N/A', l7: '4.6 Gbps', threat: '3.0 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 9, 12, 'SFP', '1G'),
    ],
  },

  // ---- PA-800 Series (End of Sale) ----
  'PA-820': {
    name: 'PA-820',
    tier: 'midrange',
    description: 'Mid-range firewall for small enterprise (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '1.6 Gbps', threat: '900 Mbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 9, 12, 'SFP', '1G'),
    ],
  },

  'PA-850': {
    name: 'PA-850',
    tier: 'midrange',
    description: 'Mid-range firewall with 10G uplinks (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '2.1 Gbps', threat: '1.2 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 4, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 5, 8, 'SFP', '1G'),
      ...genPorts('ethernet1/{}', 9, 12, 'SFP+', '10G'),
    ],
  },

  // ---- PA-1400 Series ----
  'PA-1410': {
    name: 'PA-1410',
    tier: 'midrange',
    description: 'Mid-range firewall, 1400 series',
    throughput: { l4: 'N/A', l7: '8.5 Gbps', threat: '4.5 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 9, 12, 'copper', '2.5G'),
      ...genPorts('ethernet1/{}', 13, 18, 'SFP', '1G'),
      ...genPorts('ethernet1/{}', 19, 22, 'SFP+', '10G'),
    ],
  },

  'PA-1420': {
    name: 'PA-1420',
    tier: 'midrange',
    description: 'Mid-range firewall, 1400 series enhanced',
    throughput: { l4: 'N/A', l7: '9.5 Gbps', threat: '6.2 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 9, 12, 'copper', '2.5G'),
      ...genPorts('ethernet1/{}', 13, 18, 'SFP', '1G'),
      ...genPorts('ethernet1/{}', 19, 22, 'SFP+', '10G'),
    ],
  },

  // ---- PA-3200 Series (End of Sale) ----
  'PA-3220': {
    name: 'PA-3220',
    tier: 'enterprise',
    description: 'Enterprise firewall, 3200 series base (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '5.0 Gbps', threat: '2.8 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 12, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 13, 16, 'SFP', '1G'),
      ...genPorts('ethernet1/{}', 17, 20, 'SFP+', '10G'),
    ],
  },

  'PA-3250': {
    name: 'PA-3250',
    tier: 'enterprise',
    description: 'Enterprise firewall, 3200 series mid (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '6.2 Gbps', threat: '3.4 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 12, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 13, 20, 'SFP', '1G'),
      ...genPorts('ethernet1/{}', 21, 24, 'SFP+', '10G'),
    ],
  },

  'PA-3260': {
    name: 'PA-3260',
    tier: 'enterprise',
    description: 'Enterprise firewall, 3200 series top (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '9.2 Gbps', threat: '5.0 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 12, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 13, 24, 'SFP', '1G'),
      ...genPorts('ethernet1/{}', 25, 28, 'QSFP+', '40G'),
    ],
  },

  // ---- PA-3400 Series ----
  'PA-3410': {
    name: 'PA-3410',
    tier: 'enterprise',
    description: 'Enterprise firewall, 3400 series base',
    throughput: { l4: 'N/A', l7: '14 Gbps', threat: '7.5 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 12, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 13, 16, 'SFP', '1G'),
      ...genPorts('ethernet1/{}', 17, 20, 'SFP+', '10G'),
    ],
  },

  'PA-3420': {
    name: 'PA-3420',
    tier: 'enterprise',
    description: 'Enterprise firewall, 3400 series mid',
    throughput: { l4: 'N/A', l7: '19 Gbps', threat: '10 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 12, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 13, 16, 'SFP', '1G'),
      ...genPorts('ethernet1/{}', 17, 20, 'SFP+', '10G'),
    ],
  },

  'PA-3430': {
    name: 'PA-3430',
    tier: 'enterprise',
    description: 'Enterprise firewall, 3400 series enhanced',
    throughput: { l4: 'N/A', l7: '29 Gbps', threat: '15 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 12, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 13, 22, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 23, 26, 'SFP28', '25G'),
    ],
  },

  'PA-3440': {
    name: 'PA-3440',
    tier: 'enterprise',
    description: 'Enterprise firewall, 3400 series top',
    throughput: { l4: 'N/A', l7: '35 Gbps', threat: '20 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 12, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 13, 22, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 23, 26, 'SFP28', '25G'),
      ...genPorts('ethernet1/{}', 27, 28, 'QSFP28', '100G'),
    ],
  },

  // ---- PA-5200 Series (End of Sale) ----
  'PA-5220': {
    name: 'PA-5220',
    tier: 'datacenter',
    description: 'Data center firewall, 5200 series base (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '18 Gbps', threat: '10 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 4, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 5, 12, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 13, 16, 'QSFP+', '40G'),
    ],
  },

  'PA-5250': {
    name: 'PA-5250',
    tier: 'datacenter',
    description: 'Data center firewall, 5200 series mid (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '37 Gbps', threat: '24 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 4, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 5, 20, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 21, 24, 'QSFP+', '40G'),
    ],
  },

  'PA-5260': {
    name: 'PA-5260',
    tier: 'datacenter',
    description: 'Data center firewall, 5200 series enhanced (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '65 Gbps', threat: '36 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 4, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 5, 20, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 21, 28, 'QSFP+', '40G'),
    ],
  },

  'PA-5280': {
    name: 'PA-5280',
    tier: 'datacenter',
    description: 'Data center firewall, 5200 series top (End of Sale)',
    eol: true,
    throughput: { l4: 'N/A', l7: '65 Gbps', threat: '36 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 4, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 5, 20, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 21, 32, 'QSFP+', '40G'),
    ],
  },

  // ---- PA-5400 Series ----
  'PA-5410': {
    name: 'PA-5410',
    tier: 'datacenter',
    description: 'Data center firewall, 5400 series base',
    throughput: { l4: 'N/A', l7: '52 Gbps', threat: '35 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 9, 20, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 21, 24, 'SFP28', '25G'),
      ...genPorts('ethernet1/{}', 25, 28, 'QSFP28', '100G'),
    ],
  },

  'PA-5420': {
    name: 'PA-5420',
    tier: 'datacenter',
    description: 'Data center firewall, 5400 series mid',
    throughput: { l4: 'N/A', l7: '70 Gbps', threat: '50 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 9, 20, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 21, 24, 'SFP28', '25G'),
      ...genPorts('ethernet1/{}', 25, 28, 'QSFP28', '100G'),
    ],
  },

  'PA-5430': {
    name: 'PA-5430',
    tier: 'datacenter',
    description: 'Data center firewall, 5400 series enhanced',
    throughput: { l4: 'N/A', l7: '82 Gbps', threat: '60 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 9, 20, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 21, 24, 'SFP28', '25G'),
      ...genPorts('ethernet1/{}', 25, 28, 'QSFP28', '100G'),
    ],
  },

  'PA-5440': {
    name: 'PA-5440',
    tier: 'datacenter',
    description: 'Data center firewall, 5400 series top',
    throughput: { l4: 'N/A', l7: '90 Gbps', threat: '70 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 9, 20, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 21, 24, 'SFP28', '25G'),
      ...genPorts('ethernet1/{}', 25, 28, 'QSFP28', '100G'),
    ],
  },

  'PA-5445': {
    name: 'PA-5445',
    tier: 'datacenter',
    description: 'Data center firewall, 5400 series max',
    throughput: { l4: 'N/A', l7: '90 Gbps', threat: '76 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'copper', '1G'),
      ...genPorts('ethernet1/{}', 9, 20, 'SFP+', '10G'),
      ...genPorts('ethernet1/{}', 21, 24, 'SFP28', '25G'),
      ...genPorts('ethernet1/{}', 25, 28, 'QSFP28', '100G'),
    ],
  },

  // ---- VM-Series (Virtual) ----
  'VM-50': {
    name: 'VM-50',
    tier: 'virtual',
    description: 'Virtual firewall, small workloads',
    throughput: { l4: 'N/A', l7: '200 Mbps', threat: '100 Mbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'virtual', 'virtual'),
    ],
  },

  'VM-100': {
    name: 'VM-100',
    tier: 'virtual',
    description: 'Virtual firewall, medium workloads',
    throughput: { l4: 'N/A', l7: '2 Gbps', threat: '1 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 8, 'virtual', 'virtual'),
    ],
  },

  'VM-300': {
    name: 'VM-300',
    tier: 'virtual',
    description: 'Virtual firewall, large workloads',
    throughput: { l4: 'N/A', l7: '4 Gbps', threat: '2 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 10, 'virtual', 'virtual'),
    ],
  },

  'VM-500': {
    name: 'VM-500',
    tier: 'virtual',
    description: 'Virtual firewall, high-performance',
    throughput: { l4: 'N/A', l7: '8 Gbps', threat: '4 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 24, 'virtual', 'virtual'),
    ],
  },

  'VM-700': {
    name: 'VM-700',
    tier: 'virtual',
    description: 'Virtual firewall, max performance',
    throughput: { l4: 'N/A', l7: '16 Gbps', threat: '8 Gbps' },
    ports: [
      ...genPorts('ethernet1/{}', 1, 24, 'virtual', 'virtual'),
    ],
  },
};

// ---------------------------------------------------------------------------
// Juniper SRX Models
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Juniper SRX EOS/Legacy Models (source import only)
// ---------------------------------------------------------------------------

export const SRX_EOS_MODELS = {
  'SRX100': {
    name: 'SRX100',
    tier: 'branch',
    eol: true,
    description: 'Entry-level branch gateway (End of Life)',
    throughput: { l4: '150 Mbps', l7: 'N/A', threat: '45 Mbps' },
    ports: [
      ...genSrxPorts('fe', 0, 0, 0, 7, 'copper', '100M'),
    ],
  },

  'SRX110': {
    name: 'SRX110',
    tier: 'branch',
    eol: true,
    description: 'Small branch gateway with wireless (End of Life)',
    throughput: { l4: '150 Mbps', l7: 'N/A', threat: '45 Mbps' },
    ports: [
      ...genSrxPorts('fe', 0, 0, 0, 7, 'copper', '100M'),
    ],
  },

  'SRX210': {
    name: 'SRX210',
    tier: 'branch',
    eol: true,
    description: 'Small branch gateway (End of Life)',
    throughput: { l4: '350 Mbps', l7: 'N/A', threat: '70 Mbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 1, 'copper', '1G'),
      ...genSrxPorts('fe', 0, 0, 2, 9, 'copper', '100M'),
    ],
  },

  'SRX220': {
    name: 'SRX220',
    tier: 'branch',
    eol: true,
    description: 'Branch gateway with 8 GbE (End of Life)',
    throughput: { l4: '350 Mbps', l7: 'N/A', threat: '100 Mbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 7, 'copper', '1G'),
    ],
  },

  'SRX240': {
    name: 'SRX240',
    tier: 'branch',
    eol: true,
    description: 'Branch gateway with 16 GbE + expansion (End of Life)',
    throughput: { l4: '750 Mbps', l7: 'N/A', threat: '250 Mbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
    ],
  },

  'SRX550': {
    name: 'SRX550',
    tier: 'midrange',
    eol: true,
    description: 'Mid-range firewall, 12 GbE + expansion (End of Life)',
    throughput: { l4: '3 Gbps', l7: 'N/A', threat: '700 Mbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 11, 'copper', '1G'),
      ...genSrxPorts('ge', 0, 0, 12, 15, 'SFP', '1G'),
    ],
  },

  'SRX550M': {
    name: 'SRX550M',
    tier: 'midrange',
    eol: true,
    description: 'Mid-range firewall, enhanced (End of Life)',
    throughput: { l4: '5.5 Gbps', l7: 'N/A', threat: '1.2 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 11, 'copper', '1G'),
      ...genSrxPorts('ge', 0, 0, 12, 17, 'SFP', '1G'),
      ...genSrxPorts('xe', 0, 0, 0, 1, 'SFP+', '10G'),
    ],
  },

  'SRX650': {
    name: 'SRX650',
    tier: 'midrange',
    eol: true,
    description: 'Mid-range firewall with high port density (End of Life)',
    throughput: { l4: '6 Gbps', l7: 'N/A', threat: '1.5 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
      ...genSrxPorts('ge', 0, 0, 16, 19, 'SFP', '1G'),
      ...genSrxPorts('xe', 0, 0, 0, 3, 'SFP+', '10G'),
    ],
  },

  'SRX1400': {
    name: 'SRX1400',
    tier: 'datacenter',
    eol: true,
    description: 'Data center firewall, fixed (End of Life)',
    throughput: { l4: '10 Gbps', l7: 'N/A', threat: '3 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
      ...genSrxPorts('xe', 0, 0, 0, 3, 'SFP+', '10G'),
    ],
  },

  'SRX1500': {
    name: 'SRX1500',
    tier: 'midrange',
    eol: true,
    description: 'Enterprise edge firewall (End of Life)',
    throughput: { l4: '6 Gbps', l7: '3 Gbps', threat: '4 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
      ...genSrxPorts('xe', 0, 0, 0, 3, 'SFP+', '10G'),
    ],
  },

  'SRX3400': {
    name: 'SRX3400',
    tier: 'datacenter',
    eol: true,
    description: 'Data center firewall, modular (End of Life)',
    throughput: { l4: '30 Gbps', l7: 'N/A', threat: '7 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
      ...genSrxPorts('xe', 0, 0, 0, 7, 'SFP+', '10G'),
    ],
  },

  'SRX3600': {
    name: 'SRX3600',
    tier: 'datacenter',
    eol: true,
    description: 'Data center firewall, high performance (End of Life)',
    throughput: { l4: '60 Gbps', l7: 'N/A', threat: '15 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
      ...genSrxPorts('xe', 0, 0, 0, 15, 'SFP+', '10G'),
    ],
  },
};

// ---------------------------------------------------------------------------
// Juniper SRX Models (current, used as target + source)
// ---------------------------------------------------------------------------

export const SRX_MODELS = {
  // ---- Branch ----
  'SRX300': {
    name: 'SRX300',
    tier: 'branch',
    description: 'Branch office firewall, 8-port',
    throughput: { l4: '500 Mbps', l7: 'N/A', threat: '200 Mbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 7, 'copper', '1G'),
    ],
  },

  'SRX320': {
    name: 'SRX320',
    tier: 'branch',
    description: 'Branch office with WAN diversity',
    throughput: { l4: '500 Mbps', l7: 'N/A', threat: '200 Mbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 7, 'copper', '1G'),
    ],
  },

  'SRX340': {
    name: 'SRX340',
    tier: 'branch',
    description: 'Medium branch, 16-port',
    throughput: { l4: '1 Gbps', l7: 'N/A', threat: '400 Mbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
    ],
  },

  'SRX345': {
    name: 'SRX345',
    tier: 'branch',
    description: 'Medium branch with SFP+ uplinks',
    throughput: { l4: '1.7 Gbps', l7: 'N/A', threat: '600 Mbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
      ...genSrxPorts('xe', 0, 0, 16, 19, 'SFP+', '10G'),
    ],
  },

  'SRX380': {
    name: 'SRX380',
    tier: 'branch',
    description: 'Large branch with 10G and PoE',
    throughput: { l4: '4 Gbps', l7: '6 Gbps', threat: '2 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
      ...genSrxPorts('ge', 0, 0, 16, 19, 'SFP', '1G'),
      ...genSrxPorts('xe', 0, 0, 20, 23, 'SFP+', '10G'),
    ],
  },

  // ---- Mid-Range ----
  'SRX1600': {
    name: 'SRX1600',
    tier: 'midrange',
    current: true,
    description: 'Next-gen enterprise edge firewall with MACsec',
    throughput: { l4: '12 Gbps', l7: '7.5 Gbps', threat: '8 Gbps' },
    ports: [
      // PIC 0: 16x RJ-45 BASE-T (1G copper)
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '1G'),
      // PIC 1: 2x SFP28 (1/10/25G)
      ...genSrxPorts('et', 0, 1, 0, 1, 'SFP28', '1/10/25G'),
      // PIC 2: 4x SFP+ (1/10G)
      ...genSrxPorts('xe', 0, 2, 0, 3, 'SFP+', '1/10G'),
    ],
  },

  // ---- Data Center / High-End ----
  'SRX4100': {
    name: 'SRX4100',
    tier: 'datacenter',
    description: 'Data center firewall, fixed 10G/40G',
    throughput: { l4: '20 Gbps', l7: '10 Gbps', threat: '13.9 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 1, 'copper', '1G'),
      ...genSrxPorts('xe', 0, 0, 0, 15, 'SFP+', '10G'),
      ...genSrxPorts('et', 0, 0, 0, 1, 'QSFP+', '40G'),
    ],
  },

  'SRX4120': {
    name: 'SRX4120',
    tier: 'datacenter',
    current: true,
    description: 'Next-gen data center firewall with MACsec',
    throughput: { l4: '28 Gbps', l7: '14 Gbps', threat: '20 Gbps' },
    ports: [
      // PIC 0: 8x multirate BASE-T RJ-45 (1/2.5/5/10G)
      ...genSrxPorts('mge', 0, 0, 0, 7, 'copper', '1/2.5/5/10G'),
      // PIC 1: 8x SFP+ (1/10G)
      ...genSrxPorts('xe', 0, 1, 0, 7, 'SFP+', '1/10G'),
      // PIC 2: 4x SFP28 (1/10/25G)
      ...genSrxPorts('et', 0, 2, 0, 3, 'SFP28', '1/10/25G'),
      // PIC 3: 2x QSFP28 (40/100G)
      ...genSrxPorts('et', 0, 3, 0, 1, 'QSFP28', '40/100G'),
    ],
  },

  'SRX4200': {
    name: 'SRX4200',
    tier: 'datacenter',
    description: 'Data center firewall, high density 10G/40G',
    throughput: { l4: '40 Gbps', l7: '18 Gbps', threat: '27.7 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 1, 'copper', '1G'),
      ...genSrxPorts('xe', 0, 0, 0, 15, 'SFP+', '10G'),
      ...genSrxPorts('et', 0, 0, 0, 3, 'QSFP+', '40G'),
    ],
  },

  'SRX4300': {
    name: 'SRX4300',
    tier: 'datacenter',
    current: true,
    description: 'High-performance data center firewall with MACsec',
    throughput: { l4: '90 Gbps', l7: '83 Gbps', threat: '83 Gbps' },
    ports: [
      // PIC 0: 8x multirate BASE-T RJ-45 (1/2.5/5/10G)
      ...genSrxPorts('mge', 0, 0, 0, 7, 'copper', '1/2.5/5/10G'),
      // PIC 1: 8x SFP+ (1/10G)
      ...genSrxPorts('xe', 0, 1, 0, 7, 'SFP+', '1/10G'),
      // PIC 2: 4x SFP28 (1/10/25G)
      ...genSrxPorts('et', 0, 2, 0, 3, 'SFP28', '1/10/25G'),
      // PIC 3: 6x QSFP28 (40/100G)
      ...genSrxPorts('et', 0, 3, 0, 5, 'QSFP28', '40/100G'),
    ],
  },

  'SRX4600': {
    name: 'SRX4600',
    tier: 'datacenter',
    description: 'High-performance data center firewall',
    throughput: { l4: '400 Gbps', l7: '20 Gbps', threat: '20 Gbps' },
    ports: [
      // FPC 1, PIC 0: 4x QSFP28/QSFP+ (40/100G)
      ...genSrxPorts('et', 1, 0, 0, 3, 'QSFP28', '40/100G'),
      // FPC 1, PIC 1: 8x SFP+ (1/10G)
      ...genSrxPorts('xe', 1, 1, 0, 7, 'SFP+', '1/10G'),
    ],
  },

  'SRX4700-700': {
    name: 'SRX4700-700',
    tier: 'datacenter',
    current: true,
    hasPortProfiles: true,
    description: '1U datacenter firewall, Trio ASIC, MACsec, 700G L4 license',
    throughput: { l4: '700 Gbps', l7: '160 Gbps', threat: '60 Gbps' },
    ports: getSrx4700Ports(SRX4700_DEFAULT_PROFILE),
  },

  'SRX4700': {
    name: 'SRX4700',
    tier: 'datacenter',
    current: true,
    hasPortProfiles: true,
    description: 'Highest throughput 1U firewall, Trio ASIC, MACsec, full license',
    throughput: { l4: '1.4 Tbps', l7: '160 Gbps', threat: '60 Gbps' },
    ports: getSrx4700Ports(SRX4700_DEFAULT_PROFILE),
  },

  // ---- Chassis-Based ----
  'SRX5400': {
    name: 'SRX5400',
    tier: 'chassis',
    description: 'Chassis-based, 3 IOC slots',
    throughput: { l4: '960 Gbps', l7: '100 Gbps', threat: '172 Gbps' },
    ports: [
      // Common IOC-III module: 40x 10GbE SFP+
      ...genSrxPorts('xe', 0, 0, 0, 39, 'SFP+', '10G'),
      // Management
      ...genSrxPorts('ge', 0, 0, 0, 1, 'copper', '1G'),
    ],
  },

  'SRX5600': {
    name: 'SRX5600',
    tier: 'chassis',
    description: 'Chassis-based, 6 IOC slots',
    throughput: { l4: '1.44 Tbps', l7: '210 Gbps', threat: '245 Gbps' },
    ports: [
      ...genSrxPorts('xe', 0, 0, 0, 47, 'SFP+', '10G'),
      ...genSrxPorts('et', 0, 0, 0, 11, 'QSFP+', '40G'),
      ...genSrxPorts('ge', 0, 0, 0, 1, 'copper', '1G'),
    ],
  },

  'SRX5800': {
    name: 'SRX5800',
    tier: 'chassis',
    description: 'Chassis-based, 12 IOC slots, carrier-grade',
    throughput: { l4: '3.36 Tbps', l7: '400 Gbps', threat: '638 Gbps' },
    ports: [
      ...genSrxPorts('xe', 0, 0, 0, 95, 'SFP+', '10G'),
      ...genSrxPorts('et', 0, 0, 0, 23, 'QSFP+', '40G'),
      ...genSrxPorts('ge', 0, 0, 0, 1, 'copper', '1G'),
    ],
  },

  // ---- Virtual ----
  'vSRX3.0': {
    name: 'vSRX3.0',
    tier: 'virtual',
    current: true,
    description: 'Virtual SRX firewall for cloud and NFV',
    throughput: { l4: '200 Gbps', l7: '100 Gbps', threat: '30 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 6, 'virtual', 'virtual'),
    ],
  },
};

// ---------------------------------------------------------------------------
// Throughput display helper
// ---------------------------------------------------------------------------

/**
 * Returns the throughput value for a given metric key.
 * @param {Object} model - Model object from PANOS_MODELS or SRX_MODELS
 * @param {'l4'|'l7'|'threat'} metric - Which throughput metric to show
 * @returns {string}
 */
export function getThroughputDisplay(model, metric = 'l7') {
  if (!model?.throughput) return 'N/A';
  return model.throughput[metric] || 'N/A';
}

/**
 * Labels for throughput metrics, vendor-aware.
 * PAN-OS: L4 = N/A, L7 = App-ID, Threat = Threat Prevention
 * SRX:    L4 = Firewall (IMIX), L7 = NGFW/AppSecure, Threat = IPS/Threat
 */
export const THROUGHPUT_LABELS = {
  panos:     { l4: 'L4 Firewall', l7: 'L7 App-ID', threat: 'Threat Prevention' },
  srx:       { l4: 'L4 Firewall (IMIX)', l7: 'L7 NGFW', threat: 'IPS/Threat' },
  fortigate: { l4: 'L4 Firewall', l7: 'NGFW', threat: 'Threat Protection' },
  cisco_asa: { l4: 'L4 Firewall', l7: 'NGFW (FTD)', threat: 'IPS/Threat' },
};

/** Short metric prefix for dropdown labels */
export const METRIC_PREFIX = { l4: 'L4', l7: 'L7', threat: 'IPS' };

/**
 * Parse a throughput string like "500 Mbps", "1.4 Tbps", "N/A" into Mbps number.
 * Returns 0 for N/A or unparseable values.
 */
export function parseThroughput(str) {
  if (!str || str === 'N/A') return 0;
  const m = str.match(/^([\d.]+)\s*(Mbps|Gbps|Tbps)/i);
  if (!m) return 0;
  const val = parseFloat(m[1]);
  const unit = m[2].toLowerCase();
  if (unit === 'tbps') return val * 1000000;
  if (unit === 'gbps') return val * 1000;
  return val; // Mbps
}

// ---------------------------------------------------------------------------
// Model Detection Heuristic
// ---------------------------------------------------------------------------

/**
 * Attempts to detect the PAN-OS hardware model from the parsed config.
 *
 * Heuristic: examines zone interfaces to determine the highest ethernet port
 * number used, then matches against known port counts per model.
 *
 * @param {Object} intermediateConfig - The parsed intermediate JSON
 * @returns {{ model: string, confidence: number } | null}
 */
export function detectPanosModel(intermediateConfig) {
  if (!intermediateConfig?.zones) return null;

  // Collect all interface names from zones
  const allInterfaces = [];
  for (const zone of intermediateConfig.zones) {
    for (const iface of (zone.interfaces || [])) {
      allInterfaces.push(iface);
    }
  }

  if (allInterfaces.length === 0) return null;

  // Parse the highest ethernet port number
  let maxPort = 0;
  let maxSlot = 1;
  for (const iface of allInterfaces) {
    const match = iface.match(/^ethernet(\d+)\/(\d+)/i);
    if (match) {
      const slot = parseInt(match[1]);
      const port = parseInt(match[2]);
      if (slot > maxSlot) maxSlot = slot;
      if (port > maxPort) maxPort = port;
    }
  }

  if (maxPort === 0) return null;

  const totalIfaceCount = allInterfaces.length;

  // Match against known models by port count and characteristics
  // Look for the smallest model that fits all observed ports
  const candidates = [];

  for (const [modelName, model] of Object.entries(PANOS_MODELS)) {
    // Skip virtual models for hardware detection
    if (model.tier === 'virtual') continue;

    const modelMaxPort = model.ports.length;
    // Check if the model has enough ports
    const highestNeeded = maxPort; // e.g., if ethernet1/12 is used, need at least 12 ports

    if (modelMaxPort >= highestNeeded) {
      // Check if the model's ports include the naming we see
      const portNames = model.ports.map(p => p.name);
      const allFound = allInterfaces.every(iface => {
        const base = iface.split('.')[0]; // strip VLAN unit
        return portNames.includes(base);
      });

      if (allFound) {
        // Closer match = ports count is closer to what we actually use
        const fitScore = modelMaxPort - highestNeeded;
        // Prefer non-EoS models by adding penalty
        const eolPenalty = model.eol ? 100 : 0;
        candidates.push({ model: modelName, fitScore: fitScore + eolPenalty, portCount: modelMaxPort });
      }
    }
  }

  if (candidates.length === 0) return null;

  // Sort by fit score (smaller = tighter fit = higher confidence)
  candidates.sort((a, b) => a.fitScore - b.fitScore);

  const best = candidates[0];
  // Confidence: higher when port count tightly matches usage
  const confidence = Math.max(0.4, Math.min(0.95, 1 - (best.fitScore / best.portCount)));

  return {
    model: best.model,
    confidence: Math.round(confidence * 100) / 100,
  };
}

/**
 * All SRX models available as source (current + EOS).
 * Used in ModelSelector when source vendor is SRX.
 */
export const SRX_SOURCE_MODELS = { ...SRX_EOS_MODELS, ...SRX_MODELS };


// ---------------------------------------------------------------------------
// FortiGate / FortiNet Firewall Models
// ---------------------------------------------------------------------------

function genFortiPorts(names, type, speed) {
  return names.map(n => ({ name: n, type, speed, label: n }));
}

function genFortiNumberedPorts(prefix, start, end, type, speed) {
  const ports = [];
  for (let i = start; i <= end; i++) {
    const name = `${prefix}${i}`;
    ports.push({ name, type, speed, label: name });
  }
  return ports;
}

/**
 * EOS / Legacy FortiGate models (E-series and older).
 * Common migration sources.
 */
export const FORTIGATE_EOS_MODELS = {
  'FG-30E': {
    name: 'FG-30E', tier: 'branch', eol: true,
    description: 'Entry-level branch firewall (End of Order)',
    throughput: { l4: '950 Mbps', l7: '150 Mbps', threat: '150 Mbps' },
    ports: [
      ...genFortiPorts(['wan1'], 'copper', '1G'),
      ...genFortiNumberedPorts('internal', 1, 4, 'copper', '1G'),
    ],
  },
  'FG-50E': {
    name: 'FG-50E', tier: 'branch', eol: true,
    description: 'Branch firewall with 7 GE ports (End of Order)',
    throughput: { l4: '2.5 Gbps', l7: '350 Mbps', threat: '350 Mbps' },
    ports: [
      ...genFortiPorts(['wan1', 'wan2'], 'copper', '1G'),
      ...genFortiNumberedPorts('internal', 1, 5, 'copper', '1G'),
    ],
  },
  'FG-60E': {
    name: 'FG-60E', tier: 'branch', eol: true,
    description: 'Branch firewall with 10 GE ports (End of Order)',
    throughput: { l4: '3 Gbps', l7: '300 Mbps', threat: '300 Mbps' },
    ports: [
      ...genFortiPorts(['wan1', 'wan2', 'dmz'], 'copper', '1G'),
      ...genFortiNumberedPorts('internal', 1, 7, 'copper', '1G'),
    ],
  },
  'FG-80E': {
    name: 'FG-80E', tier: 'branch', eol: true,
    description: 'Branch firewall with 14 ports (End of Order)',
    throughput: { l4: '4 Gbps', l7: '360 Mbps', threat: '360 Mbps' },
    ports: [
      ...genFortiPorts(['wan1', 'wan2', 'dmz1', 'dmz2'], 'copper', '1G'),
      ...genFortiNumberedPorts('internal', 1, 8, 'copper', '1G'),
      ...genFortiPorts(['wan1-sfp', 'wan2-sfp'], 'SFP', '1G'),
    ],
  },
  'FG-100E': {
    name: 'FG-100E', tier: 'midrange', eol: true,
    description: 'Mid-range firewall with 20 GE ports (End of Order)',
    throughput: { l4: '7.4 Gbps', l7: '800 Mbps', threat: '800 Mbps' },
    ports: [
      ...genFortiPorts(['wan1', 'wan2', 'dmz', 'mgmt', 'ha1', 'ha2'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 14, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 2, 'SFP', '1G'),
    ],
  },
  'FG-200E': {
    name: 'FG-200E', tier: 'midrange', eol: true,
    description: 'Mid-range firewall with 18 GE + 4 SFP (End of Order)',
    throughput: { l4: '12 Gbps', l7: '1.8 Gbps', threat: '1.8 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt', 'ha'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 4, 'SFP', '1G'),
    ],
  },
  'FG-300E': {
    name: 'FG-300E', tier: 'midrange', eol: true,
    description: 'Mid-range firewall with 10GE (End of Order)',
    throughput: { l4: '32 Gbps', l7: '3.5 Gbps', threat: '3.5 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt', 'ha'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 4, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 4, 'SFP+', '10G'),
    ],
  },
  'FG-500E': {
    name: 'FG-500E', tier: 'enterprise', eol: true,
    description: 'Enterprise firewall with 10GE (End of Order)',
    throughput: { l4: '36 Gbps', l7: '4.7 Gbps', threat: '4.7 Gbps' },
    ports: [
      ...genFortiNumberedPorts('port', 1, 8, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 8, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 4, 'SFP+', '10G'),
    ],
  },
};

/**
 * Current FortiGate models (F-series and G-series).
 */
export const FORTIGATE_MODELS = {
  // ---- Entry-Level / Branch (F-Series) ----
  'FG-40F': {
    name: 'FG-40F', tier: 'branch',
    description: 'Entry-level branch firewall',
    throughput: { l4: '5 Gbps', l7: '800 Mbps', threat: '600 Mbps' },
    ports: [
      ...genFortiPorts(['wan'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 4, 'copper', '1G'),
    ],
  },
  'FG-60F': {
    name: 'FG-60F', tier: 'branch',
    description: 'Branch firewall with 10 GE ports',
    throughput: { l4: '10 Gbps', l7: '1 Gbps', threat: '700 Mbps' },
    ports: [
      ...genFortiPorts(['wan1', 'wan2', 'dmz'], 'copper', '1G'),
      ...genFortiNumberedPorts('internal', 1, 7, 'copper', '1G'),
    ],
  },
  'FG-70F': {
    name: 'FG-70F', tier: 'branch',
    description: 'Branch firewall with 10 GE ports + FortiLink',
    throughput: { l4: '10 Gbps', l7: '1 Gbps', threat: '800 Mbps' },
    ports: [
      ...genFortiPorts(['wan1', 'wan2', 'dmz'], 'copper', '1G'),
      ...genFortiNumberedPorts('internal', 1, 5, 'copper', '1G'),
      ...genFortiPorts(['a', 'b'], 'copper', '1G'),
    ],
  },
  'FG-80F': {
    name: 'FG-80F', tier: 'branch',
    description: 'Branch firewall with SFP combo WAN',
    throughput: { l4: '10 Gbps', l7: '1 Gbps', threat: '900 Mbps' },
    ports: [
      ...genFortiPorts(['wan1', 'wan2'], 'copper', '1G'),
      ...genFortiNumberedPorts('internal', 1, 6, 'copper', '1G'),
      ...genFortiPorts(['wan1-sfp', 'wan2-sfp'], 'SFP', '1G'),
    ],
  },

  // ---- Entry-Level / Branch (G-Series) ----
  'FG-70G': {
    name: 'FG-70G', tier: 'branch', current: true,
    description: 'G-series branch firewall',
    throughput: { l4: '12 Gbps', l7: '1.5 Gbps', threat: '1.3 Gbps' },
    ports: [
      ...genFortiPorts(['wan1', 'wan2', 'dmz'], 'copper', '1G'),
      ...genFortiNumberedPorts('internal', 1, 7, 'copper', '1G'),
    ],
  },
  'FG-90G': {
    name: 'FG-90G', tier: 'branch', current: true,
    description: 'G-series branch firewall with 10G WAN',
    throughput: { l4: '28 Gbps', l7: '2.5 Gbps', threat: '2 Gbps' },
    ports: [
      ...genFortiNumberedPorts('port', 1, 8, 'copper', '1G'),
      ...genFortiPorts(['wan1', 'wan2'], 'SFP+', '10G'),
    ],
  },
  'FG-120G': {
    name: 'FG-120G', tier: 'midrange', current: true,
    description: 'G-series mid-range with 10GE SFP+',
    throughput: { l4: '39 Gbps', l7: '3.1 Gbps', threat: '2.8 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt', 'ha'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 8, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 4, 'SFP+', '10G'),
    ],
  },
  'FG-200G': {
    name: 'FG-200G', tier: 'midrange', current: true,
    description: 'G-series mid-range with 5GE + 10GE',
    throughput: { l4: '39 Gbps', l7: '7 Gbps', threat: '6.5 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt', 'ha'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 8, 'copper', '1G'),
      ...genFortiNumberedPorts('5g-port', 1, 8, 'copper', '5G'),
      ...genFortiNumberedPorts('sfp', 1, 4, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 8, 'SFP+', '10G'),
    ],
  },

  // ---- Mid-Range (F-Series) ----
  'FG-100F': {
    name: 'FG-100F', tier: 'midrange',
    description: 'Mid-range firewall with 22 GE + 2 SFP+',
    throughput: { l4: '20 Gbps', l7: '1.6 Gbps', threat: '1 Gbps' },
    ports: [
      ...genFortiPorts(['wan1', 'wan2', 'dmz', 'mgmt', 'ha1', 'ha2'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 4, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 2, 'SFP+', '10G'),
    ],
  },
  'FG-200F': {
    name: 'FG-200F', tier: 'midrange',
    description: 'Mid-range firewall with 18 GE + 4 SFP+',
    throughput: { l4: '27 Gbps', l7: '3 Gbps', threat: '2.2 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt', 'ha'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 8, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 4, 'SFP+', '10G'),
    ],
  },
  'FG-400F': {
    name: 'FG-400F', tier: 'enterprise',
    description: 'Enterprise firewall with 18 GE + 8 SFP+',
    throughput: { l4: '79.5 Gbps', l7: '10 Gbps', threat: '9 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt', 'ha'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 8, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 8, 'SFP+', '10G'),
    ],
  },
  'FG-600F': {
    name: 'FG-600F', tier: 'enterprise',
    description: 'Enterprise firewall with 25GE SFP28',
    throughput: { l4: '80 Gbps', l7: '11.5 Gbps', threat: '10.5 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt1', 'mgmt2'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 8, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 4, 'SFP+', '10G'),
      ...genFortiNumberedPorts('sfp28-', 1, 4, 'SFP28', '25G'),
    ],
  },

  // ---- Mid-Range (G-Series) ----
  'FG-700G': {
    name: 'FG-700G', tier: 'enterprise', current: true,
    description: 'G-series enterprise with 25GE SFP28',
    throughput: { l4: '164 Gbps', l7: '29 Gbps', threat: '27 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 8, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 4, 'SFP+', '10G'),
      ...genFortiNumberedPorts('sfp28-', 1, 4, 'SFP28', '25G'),
    ],
  },
  'FG-900G': {
    name: 'FG-900G', tier: 'enterprise', current: true,
    description: 'G-series enterprise with 25GE SFP28 + HA',
    throughput: { l4: '164 Gbps', l7: '31 Gbps', threat: '30 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt'], 'copper', '1G'),
      ...genFortiPorts(['ha'], 'copper', '2.5G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 8, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp+', 1, 4, 'SFP+', '10G'),
      ...genFortiNumberedPorts('sfp28-', 1, 4, 'SFP28', '25G'),
    ],
  },

  // ---- High-End / Data Center (F-Series) ----
  'FG-1000F': {
    name: 'FG-1000F', tier: 'datacenter',
    description: 'Data center firewall with 100GE QSFP28',
    throughput: { l4: '198 Gbps', l7: '15 Gbps', threat: '13 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt'], 'copper', '1G'),
      ...genFortiPorts(['ha'], 'copper', '2.5G'),
      ...genFortiNumberedPorts('port', 1, 8, 'copper', '10G'),
      ...genFortiNumberedPorts('sfp+', 1, 16, 'SFP+', '10G'),
      ...genFortiNumberedPorts('sfp28-', 1, 8, 'SFP28', '25G'),
      ...genFortiNumberedPorts('qsfp28-', 1, 2, 'QSFP28', '100G'),
    ],
  },
  'FG-1800F': {
    name: 'FG-1800F', tier: 'datacenter',
    description: 'Data center firewall with 100GE QSFP28',
    throughput: { l4: '198 Gbps', l7: '17 Gbps', threat: '15 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt1', 'mgmt2'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '1G'),
      ...genFortiNumberedPorts('sfp', 1, 8, 'SFP', '1G'),
      ...genFortiNumberedPorts('sfp28-', 1, 12, 'SFP28', '25G'),
      ...genFortiNumberedPorts('qsfp28-', 1, 4, 'QSFP28', '100G'),
    ],
  },
  'FG-2600F': {
    name: 'FG-2600F', tier: 'datacenter',
    description: 'Data center firewall, 2600 series',
    throughput: { l4: '397 Gbps', l7: '27 Gbps', threat: '24 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt1', 'mgmt2'], 'copper', '1G'),
      ...genFortiNumberedPorts('port', 1, 16, 'copper', '10G'),
      ...genFortiNumberedPorts('sfp28-', 1, 16, 'SFP28', '25G'),
      ...genFortiNumberedPorts('qsfp28-', 1, 4, 'QSFP28', '100G'),
    ],
  },
  'FG-3200F': {
    name: 'FG-3200F', tier: 'datacenter',
    description: 'Data center firewall with 400GE QSFP-DD',
    throughput: { l4: '595 Gbps', l7: '47 Gbps', threat: '45 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt1', 'mgmt2'], 'copper', '10G'),
      ...genFortiNumberedPorts('sfp56-', 1, 10, 'SFP56', '50G'),
      ...genFortiNumberedPorts('sfp28-', 1, 4, 'SFP28', '25G'),
      ...genFortiNumberedPorts('qsfp-dd-', 1, 4, 'QSFP-DD', '400G'),
    ],
  },
  'FG-3500F': {
    name: 'FG-3500F', tier: 'datacenter',
    description: 'Data center firewall with 100GE QSFP28',
    throughput: { l4: '595 Gbps', l7: '65 Gbps', threat: '60 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt1', 'mgmt2'], 'copper', '10G'),
      ...genFortiNumberedPorts('sfp28-', 1, 32, 'SFP28', '25G'),
      ...genFortiNumberedPorts('qsfp28-', 1, 6, 'QSFP28', '100G'),
    ],
  },
  'FG-3700F': {
    name: 'FG-3700F', tier: 'datacenter',
    description: 'Data center firewall with 400GE QSFP-DD',
    throughput: { l4: '589 Gbps', l7: '80 Gbps', threat: '75 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt1', 'mgmt2'], 'copper', '10G'),
      ...genFortiNumberedPorts('sfp28-', 1, 4, 'SFP28', '25G'),
      ...genFortiNumberedPorts('sfp56-', 1, 20, 'SFP56', '50G'),
      ...genFortiNumberedPorts('qsfp-dd-', 1, 4, 'QSFP-DD', '400G'),
    ],
  },
  'FG-4200F': {
    name: 'FG-4200F', tier: 'datacenter',
    description: 'High-end data center firewall',
    throughput: { l4: '800 Gbps', l7: '47 Gbps', threat: '45 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt1', 'mgmt2'], 'copper', '1G'),
      ...genFortiNumberedPorts('sfp28-', 1, 18, 'SFP28', '25G'),
      ...genFortiNumberedPorts('qsfp28-', 1, 8, 'QSFP28', '100G'),
    ],
  },
  'FG-4400F': {
    name: 'FG-4400F', tier: 'datacenter',
    description: 'Hyperscale data center firewall',
    throughput: { l4: '1.2 Tbps', l7: '82 Gbps', threat: '70 Gbps' },
    ports: [
      ...genFortiPorts(['mgmt1', 'mgmt2'], 'copper', '1G'),
      ...genFortiNumberedPorts('sfp28-', 1, 18, 'SFP28', '25G'),
      ...genFortiNumberedPorts('qsfp28-', 1, 12, 'QSFP28', '100G'),
    ],
  },
};

/**
 * All FortiGate models available as source (current + EOS).
 */
export const FORTIGATE_SOURCE_MODELS = { ...FORTIGATE_EOS_MODELS, ...FORTIGATE_MODELS };

/**
 * Attempts to detect the FortiGate hardware model from the parsed config.
 * Examines zone/interface names to match against known port layouts.
 *
 * @param {Object} intermediateConfig - The parsed intermediate JSON
 * @returns {{ model: string, confidence: number } | null}
 */
export function detectFortigateModel(intermediateConfig) {
  if (!intermediateConfig?.zones) return null;

  const allInterfaces = new Set();
  for (const zone of intermediateConfig.zones) {
    for (const iface of (zone.interfaces || [])) {
      allInterfaces.add(iface);
    }
  }

  if (allInterfaces.size === 0) return null;

  // Detect naming patterns
  const hasWan = [...allInterfaces].some(i => /^wan\d?$/i.test(i));
  const hasInternal = [...allInterfaces].some(i => /^internal\d*$/i.test(i));
  const hasDmz = [...allInterfaces].some(i => /^dmz\d?$/i.test(i));
  const hasPort = [...allInterfaces].some(i => /^port\d+$/i.test(i));
  const hasSfpPlus = [...allInterfaces].some(i => /^sfp\+/i.test(i));
  const hasSfp28 = [...allInterfaces].some(i => /^sfp28/i.test(i));
  const hasQsfp = [...allInterfaces].some(i => /^qsfp/i.test(i));

  // Count numbered ports
  const portNumbers = [...allInterfaces]
    .filter(i => /^port\d+$/i.test(i))
    .map(i => parseInt(i.replace(/^port/i, ''), 10));
  const maxPort = portNumbers.length > 0 ? Math.max(...portNumbers) : 0;

  const internalNumbers = [...allInterfaces]
    .filter(i => /^internal\d+$/i.test(i))
    .map(i => parseInt(i.replace(/^internal/i, ''), 10));
  const maxInternal = internalNumbers.length > 0 ? Math.max(...internalNumbers) : 0;

  // Match patterns to models
  if (hasQsfp || hasSfp28) {
    // Data center class
    if (maxPort >= 16) return { model: 'FG-2600F', confidence: 0.6 };
    return { model: 'FG-1000F', confidence: 0.5 };
  }
  if (hasSfpPlus && maxPort >= 16) {
    return { model: 'FG-400F', confidence: 0.6 };
  }
  if (hasPort && maxPort >= 16) {
    return { model: 'FG-200F', confidence: 0.6 };
  }
  if (hasPort && maxPort >= 8) {
    return { model: 'FG-100F', confidence: 0.6 };
  }
  if (hasWan && hasInternal && hasDmz) {
    if (maxInternal >= 7) return { model: 'FG-60F', confidence: 0.7 };
    if (maxInternal >= 5) return { model: 'FG-70F', confidence: 0.7 };
    return { model: 'FG-60F', confidence: 0.5 };
  }
  if (hasWan && hasInternal) {
    if (maxInternal >= 7) return { model: 'FG-60F', confidence: 0.6 };
    if (maxInternal >= 4) return { model: 'FG-50E', confidence: 0.5 };
    return { model: 'FG-40F', confidence: 0.5 };
  }
  if (hasPort) {
    return { model: 'FG-90G', confidence: 0.4 };
  }

  return { model: 'FG-60F', confidence: 0.3 };
}

/**
 * Attempts to detect the SRX hardware model from the parsed config.
 * Examines zone interfaces to match against known SRX port counts.
 *
 * @param {Object} intermediateConfig - The parsed intermediate JSON
 * @returns {{ model: string, confidence: number } | null}
 */
export function detectSrxModel(intermediateConfig) {
  if (!intermediateConfig?.zones) return null;

  const allInterfaces = [];
  for (const zone of intermediateConfig.zones) {
    for (const iface of (zone.interfaces || [])) {
      allInterfaces.push(iface);
    }
  }

  if (allInterfaces.length === 0) return null;

  // Determine interface types and max port numbers
  let maxPort = 0;
  let hasXe = false;
  let hasEt = false;
  let hasFe = false;

  for (const iface of allInterfaces) {
    const base = iface.split('.')[0]; // strip unit
    const match = base.match(/^(ge|xe|et|fe)-(\d+)\/(\d+)\/(\d+)$/);
    if (match) {
      const port = parseInt(match[4]);
      if (port > maxPort) maxPort = port;
      if (match[1] === 'xe') hasXe = true;
      if (match[1] === 'et') hasEt = true;
      if (match[1] === 'fe') hasFe = true;
    }
  }

  if (maxPort === 0 && !hasXe && !hasEt && !hasFe) return null;

  // Search through all SRX models (current + EOS)
  const allModels = { ...SRX_EOS_MODELS, ...SRX_MODELS };
  const candidates = [];

  for (const [modelName, model] of Object.entries(allModels)) {
    if (model.tier === 'virtual') continue;

    const portNames = model.ports.map(p => p.name);
    const allFound = allInterfaces.every(iface => {
      const base = iface.split('.')[0];
      return portNames.includes(base);
    });

    if (allFound) {
      const fitScore = model.ports.length - allInterfaces.length;
      const eolPenalty = model.eol ? 50 : 0;
      candidates.push({ model: modelName, fitScore: Math.abs(fitScore) + eolPenalty, portCount: model.ports.length });
    }
  }

  if (candidates.length === 0) return null;
  candidates.sort((a, b) => a.fitScore - b.fitScore);

  const best = candidates[0];
  const confidence = Math.max(0.4, Math.min(0.95, 1 - (best.fitScore / Math.max(best.portCount, 1))));

  return {
    model: best.model,
    confidence: Math.round(confidence * 100) / 100,
  };
}

/**
 * Suggests a compatible SRX model based on the source PAN-OS model's throughput.
 *
 * Logic:
 *   - Virtual PAN-OS → always vSRX3.0 (recommended)
 *   - Otherwise, find the SRX model with the next higher throughput in the
 *     selected metric. Mark it as recommended.
 *   - If no SRX has higher throughput, fall back to SRX4700-700 (not recommended).
 *
 * @param {string} panosModel - PAN-OS model name
 * @param {'l4'|'l7'|'threat'} metric - Which throughput metric to compare
 * @returns {{ model: string, recommended: boolean } | null}
 */
export function suggestSrxModel(panosModel, metric = 'l7') {
  // Look up source model from PAN-OS, SRX, FortiGate, or Cisco databases
  const source = PANOS_MODELS[panosModel] || SRX_SOURCE_MODELS[panosModel] || FORTIGATE_SOURCE_MODELS[panosModel] || CISCO_SOURCE_MODELS[panosModel];
  if (!source) return null;

  // Virtual always maps to vSRX
  if (source.tier === 'virtual') {
    return { model: 'vSRX3.0', recommended: true };
  }

  const sourceThroughput = parseThroughput(getThroughputDisplay(source, metric));

  // Build list of SRX candidates (exclude virtual for hardware sources)
  const candidates = [];
  for (const [name, srx] of Object.entries(SRX_MODELS)) {
    if (name === 'vSRX3.0') continue; // skip virtual for physical sources
    const srxVal = parseThroughput(getThroughputDisplay(srx, metric));
    if (srxVal > 0) {
      candidates.push({ name, throughput: srxVal });
    }
  }

  // Sort by throughput ascending
  candidates.sort((a, b) => a.throughput - b.throughput);

  // Prefer current-generation models over older ones in the same class
  const PREFER_CURRENT = {
    'SRX4100': 'SRX4120',
    'SRX4200': 'SRX4300',
    'SRX4600': 'SRX4700-700',
    'SRX4700': 'SRX4700-700',
  };

  // Prefer SRX4700-700 over chassis models (5400/5600/5800)
  const PREFER_OVER_CHASSIS = ['SRX5400', 'SRX5600', 'SRX5800'];

  // Find the first SRX with throughput >= source throughput
  // (next higher means strictly greater or equal)
  if (sourceThroughput > 0) {
    const match = candidates.find(c => c.throughput >= sourceThroughput);
    if (match) {
      // If matched a chassis model, recommend SRX4700-700 instead
      if (PREFER_OVER_CHASSIS.includes(match.name)) {
        return { model: 'SRX4700-700', recommended: true };
      }
      const model = PREFER_CURRENT[match.name] || match.name;
      return { model, recommended: true };
    }
  }

  // No match or source throughput is N/A — fall back to SRX4700-700, not recommended
  return { model: 'SRX4700-700', recommended: false };
}


// ---------------------------------------------------------------------------
// Cisco Firewall Models
// ---------------------------------------------------------------------------

function genCiscoPorts(prefix, start, end, type, speed) {
  const ports = [];
  for (let i = start; i <= end; i++) {
    const name = `${prefix}${i}`;
    ports.push({ name, type, speed, label: name });
  }
  return ports;
}

function genCiscoNamedPorts(names, type, speed) {
  return names.map(n => ({ name: n, type, speed, label: n }));
}

/**
 * Cisco ASA 5500-X Series (End of Sale / End of Support — last 10 years)
 */
export const CISCO_EOS_MODELS = {
  'ASA-5506-X': {
    name: 'ASA-5506-X', tier: 'branch', eol: true,
    description: 'Desktop form factor branch firewall (End of Sale)',
    throughput: { l4: '750 Mbps', l7: '250 Mbps', threat: '125 Mbps' },
    ports: [
      ...genCiscoPorts('GigabitEthernet1/', 1, 8, 'copper', '1G'),
    ],
  },
  'ASA-5508-X': {
    name: 'ASA-5508-X', tier: 'branch', eol: true,
    description: 'Branch firewall with 8 GbE ports (End of Sale)',
    throughput: { l4: '1 Gbps', l7: '450 Mbps', threat: '250 Mbps' },
    ports: [
      ...genCiscoPorts('GigabitEthernet1/', 1, 8, 'copper', '1G'),
    ],
  },
  'ASA-5516-X': {
    name: 'ASA-5516-X', tier: 'branch', eol: true,
    description: 'Branch firewall with 8 GbE ports (End of Sale)',
    throughput: { l4: '1.8 Gbps', l7: '850 Mbps', threat: '450 Mbps' },
    ports: [
      ...genCiscoPorts('GigabitEthernet1/', 1, 8, 'copper', '1G'),
    ],
  },
  'ASA-5525-X': {
    name: 'ASA-5525-X', tier: 'midrange', eol: true,
    description: 'Mid-range firewall with 8 GbE + 2 SFP (End of Sale)',
    throughput: { l4: '2 Gbps', l7: '1.1 Gbps', threat: '650 Mbps' },
    ports: [
      ...genCiscoPorts('GigabitEthernet0/', 0, 7, 'copper', '1G'),
      ...genCiscoNamedPorts(['GigabitEthernet0/8', 'GigabitEthernet0/9'], 'SFP', '1G'),
    ],
  },
  'ASA-5545-X': {
    name: 'ASA-5545-X', tier: 'midrange', eol: true,
    description: 'Mid-range firewall with 8 GbE + 4 SFP (End of Sale)',
    throughput: { l4: '3 Gbps', l7: '1.5 Gbps', threat: '1 Gbps' },
    ports: [
      ...genCiscoPorts('GigabitEthernet0/', 0, 7, 'copper', '1G'),
      ...genCiscoPorts('GigabitEthernet0/', 8, 11, 'SFP', '1G'),
    ],
  },
  'ASA-5555-X': {
    name: 'ASA-5555-X', tier: 'midrange', eol: true,
    description: 'Mid-range firewall with 8 GbE + 4 SFP+ (End of Sale)',
    throughput: { l4: '4 Gbps', l7: '1.75 Gbps', threat: '1.25 Gbps' },
    ports: [
      ...genCiscoPorts('GigabitEthernet0/', 0, 7, 'copper', '1G'),
      ...genCiscoPorts('TenGigabitEthernet0/', 8, 11, 'SFP+', '10G'),
    ],
  },
};

/**
 * Cisco Secure Firewall / Firepower Models (current, last 10 years, no chassis)
 */
export const CISCO_MODELS = {
  // ---- Firepower 1000 Series ----
  'FPR-1010': {
    name: 'FPR-1010', tier: 'branch',
    description: 'Desktop form factor NGFW, 8 GbE',
    throughput: { l4: '2 Gbps', l7: '890 Mbps', threat: '880 Mbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
    ],
  },
  'FPR-1010E': {
    name: 'FPR-1010E', tier: 'branch',
    description: 'Desktop NGFW with PoE, 8 GbE',
    throughput: { l4: '2 Gbps', l7: '890 Mbps', threat: '880 Mbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
    ],
  },
  'FPR-1120': {
    name: 'FPR-1120', tier: 'branch',
    description: 'Branch NGFW with 8 GbE + 4 SFP',
    throughput: { l4: '3 Gbps', l7: '1.5 Gbps', threat: '1.5 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 12, 'SFP', '1G'),
    ],
  },
  'FPR-1140': {
    name: 'FPR-1140', tier: 'branch',
    description: 'Branch NGFW with 8 GbE + 4 SFP',
    throughput: { l4: '5 Gbps', l7: '2.2 Gbps', threat: '2.2 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 12, 'SFP', '1G'),
    ],
  },
  'FPR-1150': {
    name: 'FPR-1150', tier: 'branch',
    description: 'Branch NGFW with 8 GbE + 2 SFP+',
    throughput: { l4: '7.5 Gbps', l7: '3 Gbps', threat: '3 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoNamedPorts(['Ethernet1/9', 'Ethernet1/10'], 'SFP+', '10G'),
    ],
  },

  // ---- Firepower 2100 Series ----
  'FPR-2110': {
    name: 'FPR-2110', tier: 'midrange',
    description: 'Mid-range NGFW, 12 GbE + 4 SFP',
    throughput: { l4: '3 Gbps', l7: '2 Gbps', threat: '2 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 12, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 13, 16, 'SFP', '1G'),
    ],
  },
  'FPR-2120': {
    name: 'FPR-2120', tier: 'midrange',
    description: 'Mid-range NGFW, 12 GbE + 4 SFP',
    throughput: { l4: '6 Gbps', l7: '3 Gbps', threat: '3 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 12, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 13, 16, 'SFP', '1G'),
    ],
  },
  'FPR-2130': {
    name: 'FPR-2130', tier: 'midrange',
    description: 'Mid-range NGFW with SFP+ uplinks',
    throughput: { l4: '10 Gbps', l7: '5 Gbps', threat: '5 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 12, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 13, 16, 'SFP+', '10G'),
    ],
  },
  'FPR-2140': {
    name: 'FPR-2140', tier: 'midrange',
    description: 'Mid-range NGFW with SFP+ uplinks',
    throughput: { l4: '20 Gbps', l7: '8.5 Gbps', threat: '8.5 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 12, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 13, 16, 'SFP+', '10G'),
    ],
  },

  // ---- Firepower 3100 Series ----
  'FPR-3105': {
    name: 'FPR-3105', tier: 'enterprise',
    description: 'Enterprise NGFW, 8 GbE + 8 SFP+ + 2 NM',
    throughput: { l4: '20 Gbps', l7: '10 Gbps', threat: '10 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 16, 'SFP+', '10G'),
    ],
  },
  'FPR-3110': {
    name: 'FPR-3110', tier: 'enterprise',
    description: 'Enterprise NGFW, 8 GbE + 8 SFP+ + 2 NM',
    throughput: { l4: '22.5 Gbps', l7: '11 Gbps', threat: '11 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 16, 'SFP+', '10G'),
    ],
  },
  'FPR-3120': {
    name: 'FPR-3120', tier: 'enterprise',
    description: 'Enterprise NGFW with 25G SFP28',
    throughput: { l4: '38 Gbps', l7: '15 Gbps', threat: '15 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 16, 'SFP+', '10G'),
      ...genCiscoNamedPorts(['Ethernet1/17', 'Ethernet1/18'], 'SFP28', '25G'),
    ],
  },
  'FPR-3130': {
    name: 'FPR-3130', tier: 'enterprise',
    description: 'Enterprise NGFW with 25G SFP28 + NM slots',
    throughput: { l4: '45 Gbps', l7: '22 Gbps', threat: '22 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 16, 'SFP+', '10G'),
      ...genCiscoPorts('Ethernet1/', 17, 20, 'SFP28', '25G'),
    ],
  },
  'FPR-3140': {
    name: 'FPR-3140', tier: 'enterprise',
    description: 'Enterprise NGFW, top of 3100 series',
    throughput: { l4: '57 Gbps', l7: '30 Gbps', threat: '30 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 16, 'SFP+', '10G'),
      ...genCiscoPorts('Ethernet1/', 17, 20, 'SFP28', '25G'),
    ],
  },

  // ---- Firepower 4100 Series ----
  'FPR-4112': {
    name: 'FPR-4112', tier: 'datacenter',
    description: 'Data center NGFW, 4100 series entry',
    throughput: { l4: '40 Gbps', l7: '20 Gbps', threat: '20 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 16, 'SFP+', '10G'),
      ...genCiscoPorts('Ethernet1/', 17, 20, 'QSFP+', '40G'),
    ],
  },
  'FPR-4115': {
    name: 'FPR-4115', tier: 'datacenter',
    description: 'Data center NGFW with 40G uplinks',
    throughput: { l4: '60 Gbps', l7: '30 Gbps', threat: '30 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 16, 'SFP+', '10G'),
      ...genCiscoPorts('Ethernet1/', 17, 20, 'QSFP+', '40G'),
    ],
  },
  'FPR-4125': {
    name: 'FPR-4125', tier: 'datacenter',
    description: 'Data center NGFW with 40G uplinks',
    throughput: { l4: '80 Gbps', l7: '50 Gbps', threat: '50 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 20, 'SFP+', '10G'),
      ...genCiscoPorts('Ethernet1/', 21, 24, 'QSFP+', '40G'),
    ],
  },
  'FPR-4145': {
    name: 'FPR-4145', tier: 'datacenter',
    description: 'Data center NGFW, top of 4100 series',
    throughput: { l4: '115 Gbps', l7: '70 Gbps', threat: '70 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '1G'),
      ...genCiscoPorts('Ethernet1/', 9, 20, 'SFP+', '10G'),
      ...genCiscoPorts('Ethernet1/', 21, 26, 'QSFP+', '40G'),
    ],
  },

  // ---- Firepower 4200 Series (newest) ----
  'FPR-4215': {
    name: 'FPR-4215', tier: 'datacenter', current: true,
    description: 'Next-gen data center NGFW, 4200 series',
    throughput: { l4: '80 Gbps', l7: '35 Gbps', threat: '35 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '10G'),
      ...genCiscoPorts('Ethernet1/', 9, 16, 'SFP28', '25G'),
      ...genCiscoNamedPorts(['Ethernet1/17', 'Ethernet1/18'], 'QSFP28', '100G'),
    ],
  },
  'FPR-4225': {
    name: 'FPR-4225', tier: 'datacenter', current: true,
    description: 'Next-gen data center NGFW with 100G',
    throughput: { l4: '120 Gbps', l7: '54 Gbps', threat: '54 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '10G'),
      ...genCiscoPorts('Ethernet1/', 9, 16, 'SFP28', '25G'),
      ...genCiscoPorts('Ethernet1/', 17, 20, 'QSFP28', '100G'),
    ],
  },
  'FPR-4245': {
    name: 'FPR-4245', tier: 'datacenter', current: true,
    description: 'Next-gen data center NGFW, top of 4200 series',
    throughput: { l4: '190 Gbps', l7: '90 Gbps', threat: '90 Gbps' },
    ports: [
      ...genCiscoPorts('Ethernet1/', 1, 8, 'copper', '10G'),
      ...genCiscoPorts('Ethernet1/', 9, 20, 'SFP28', '25G'),
      ...genCiscoPorts('Ethernet1/', 21, 24, 'QSFP28', '100G'),
    ],
  },

  // ---- Virtual ----
  'ASAv': {
    name: 'ASAv', tier: 'virtual',
    description: 'Virtual ASA for cloud/virtualization',
    throughput: { l4: '10 Gbps', l7: 'N/A', threat: 'N/A' },
    ports: [
      ...genCiscoPorts('GigabitEthernet0/', 0, 9, 'virtual', 'virtual'),
    ],
  },
  'FTDv': {
    name: 'FTDv', tier: 'virtual', current: true,
    description: 'Virtual Firepower Threat Defense for cloud',
    throughput: { l4: '15.5 Gbps', l7: '10 Gbps', threat: '10 Gbps' },
    ports: [
      ...genCiscoPorts('GigabitEthernet0/', 0, 9, 'virtual', 'virtual'),
    ],
  },
};

/**
 * All Cisco models available as source (current + EOS).
 */
export const CISCO_SOURCE_MODELS = { ...CISCO_EOS_MODELS, ...CISCO_MODELS };

/**
 * Attempts to detect the Cisco hardware model from the parsed config.
 * Examines interface names (GigabitEthernet, Ethernet, Management, etc.)
 * to match against known port layouts.
 *
 * @param {Object} intermediateConfig - The parsed intermediate JSON
 * @returns {{ model: string, confidence: number } | null}
 */
export function detectCiscoModel(intermediateConfig) {
  if (!intermediateConfig?.zones) return null;

  const allInterfaces = new Set();
  for (const zone of intermediateConfig.zones) {
    for (const iface of (zone.interfaces || [])) {
      allInterfaces.add(iface);
    }
  }

  if (allInterfaces.size === 0) return null;

  const hasGig = [...allInterfaces].some(i => /^GigabitEthernet/i.test(i));
  const hasTenGig = [...allInterfaces].some(i => /^TenGigabitEthernet/i.test(i));
  const hasEthernet = [...allInterfaces].some(i => /^Ethernet1\//i.test(i));
  const hasQsfp = [...allInterfaces].some(i => /QSFP|40G|100G/i.test(i));

  // Count max port number
  const portNumbers = [...allInterfaces]
    .map(i => {
      const m = i.match(/(\d+)$/);
      return m ? parseInt(m[1], 10) : 0;
    })
    .filter(n => n > 0);
  const maxPort = portNumbers.length > 0 ? Math.max(...portNumbers) : 0;

  // FPR-4200 series: Ethernet naming + high port numbers + 100G
  if (hasEthernet && maxPort >= 17) {
    return { model: 'FPR-4225', confidence: 0.6 };
  }

  // FPR-3100 series: Ethernet naming + 10G range
  if (hasEthernet && maxPort >= 9 && maxPort < 17) {
    return { model: 'FPR-3110', confidence: 0.6 };
  }

  // FPR-1000 series: Ethernet naming + small port count
  if (hasEthernet && maxPort <= 8) {
    return { model: 'FPR-1010', confidence: 0.5 };
  }

  // ASA 5500-X: TenGigabitEthernet present
  if (hasTenGig) {
    return { model: 'ASA-5555-X', confidence: 0.5 };
  }

  // ASA 5500-X: GigabitEthernet naming
  if (hasGig) {
    if (maxPort >= 10) return { model: 'ASA-5545-X', confidence: 0.5 };
    if (maxPort >= 8) return { model: 'ASA-5516-X', confidence: 0.5 };
    return { model: 'ASA-5506-X', confidence: 0.4 };
  }

  return { model: 'FPR-1010', confidence: 0.3 };
}

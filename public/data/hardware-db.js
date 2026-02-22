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
      // PIC 0: 16x multirate RJ-45 (1/2.5/5/10G)
      ...genSrxPorts('ge', 0, 0, 0, 15, 'copper', '10G'),
      // PIC 1: 2x SFP28 (25G)
      ...genSrxPorts('et', 0, 1, 0, 1, 'SFP28', '25G'),
      // PIC 2: 4x SFP+ (10G)
      ...genSrxPorts('xe', 0, 2, 0, 3, 'SFP+', '10G'),
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
      // PIC 0: 8x multirate RJ-45 (1/2.5/5/10G)
      ...genSrxPorts('ge', 0, 0, 0, 7, 'copper', '10G'),
      // PIC 1: 8x SFP+ (1/10G)
      ...genSrxPorts('xe', 0, 1, 0, 7, 'SFP+', '10G'),
      // PIC 2: 4x SFP28 (1/10/25G)
      ...genSrxPorts('et', 0, 2, 0, 3, 'SFP28', '25G'),
      // PIC 3: 2x QSFP28 (40/100G)
      ...genSrxPorts('et', 0, 3, 0, 1, 'QSFP28', '100G'),
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
      // PIC 0: 8x multirate RJ-45 (1/2.5/5/10G)
      ...genSrxPorts('ge', 0, 0, 0, 7, 'copper', '10G'),
      // PIC 1: 8x SFP+ (1/10G)
      ...genSrxPorts('xe', 0, 1, 0, 7, 'SFP+', '10G'),
      // PIC 2: 4x SFP28 (1/10/25G)
      ...genSrxPorts('et', 0, 2, 0, 3, 'SFP28', '25G'),
      // PIC 3: 6x QSFP28 (40/100G)
      ...genSrxPorts('et', 0, 3, 0, 5, 'QSFP28', '100G'),
    ],
  },

  'SRX4600': {
    name: 'SRX4600',
    tier: 'datacenter',
    description: 'High-performance data center firewall',
    throughput: { l4: '400 Gbps', l7: '20 Gbps', threat: '20 Gbps' },
    ports: [
      ...genSrxPorts('ge', 0, 0, 0, 1, 'copper', '1G'),
      ...genSrxPorts('xe', 0, 0, 0, 23, 'SFP+', '10G'),
      ...genSrxPorts('et', 0, 0, 0, 5, 'QSFP+', '40G'),
    ],
  },

  'SRX4700': {
    name: 'SRX4700',
    tier: 'datacenter',
    current: true,
    description: 'Highest throughput 1U firewall, Trio ASIC, MACsec',
    throughput: { l4: '1.4 Tbps', l7: '700 Gbps', threat: '700 Gbps' },
    ports: [
      // PIC 0: 1x QSFP56-DD (400G) + 5x QSFP28 (100G) + 8x SFP56 (50G)
      ...genSrxPorts('et', 0, 0, 0, 0, 'QSFP56-DD', '400G'),
      ...genSrxPorts('et', 0, 0, 1, 5, 'QSFP28', '100G'),
      ...genSrxPorts('et', 0, 0, 6, 13, 'SFP56', '50G'),
      // PIC 1: identical layout
      ...genSrxPorts('et', 0, 1, 0, 0, 'QSFP56-DD', '400G'),
      ...genSrxPorts('et', 0, 1, 1, 5, 'QSFP28', '100G'),
      ...genSrxPorts('et', 0, 1, 6, 13, 'SFP56', '50G'),
    ],
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
  panos: { l4: 'L4 Firewall', l7: 'L7 App-ID', threat: 'Threat Prevention' },
  srx:   { l4: 'L4 Firewall (IMIX)', l7: 'L7 NGFW', threat: 'IPS/Threat' },
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
 *   - If no SRX has higher throughput, fall back to SRX4700 (not recommended).
 *
 * @param {string} panosModel - PAN-OS model name
 * @param {'l4'|'l7'|'threat'} metric - Which throughput metric to compare
 * @returns {{ model: string, recommended: boolean } | null}
 */
export function suggestSrxModel(panosModel, metric = 'l7') {
  // Look up source model from PAN-OS or SRX databases
  const source = PANOS_MODELS[panosModel] || SRX_SOURCE_MODELS[panosModel];
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
    'SRX4600': 'SRX4700',
  };

  // Find the first SRX with throughput >= source throughput
  // (next higher means strictly greater or equal)
  if (sourceThroughput > 0) {
    const match = candidates.find(c => c.throughput >= sourceThroughput);
    if (match) {
      const model = PREFER_CURRENT[match.name] || match.name;
      return { model, recommended: true };
    }
  }

  // No match or source throughput is N/A — fall back to SRX4700, not recommended
  return { model: 'SRX4700', recommended: false };
}

import { describe, it, expect } from 'vitest';
import { generateReportHtml } from '../public/utils/report-generator.js';

const base = {
  sourceVendor: 'panos', targetModel: 'SRX1600',
  intermediateConfig: {
    zones: [], interfaces: [], security_policies: [], nat_rules: [],
    address_objects: [], service_objects: [], static_routes: [],
  },
};

describe('report SSL-VPN section', () => {
  it('renders a Remote Access VPN section when GlobalProtect is present', () => {
    const data = {
      ...base,
      intermediateConfig: {
        ...base.intermediateConfig,
        global_protect: { gateways: [{ name: 'G41-GP-GW', tunnel_interface: 'tunnel.10' }] },
      },
    };
    const html = generateReportHtml(data);
    expect(html).toContain('Remote Access VPN');
    expect(html).toContain('G41-GP-GW');
    expect(html).toContain('tunnel.10');
    expect(html).toMatch(/Secure Connect|manual/i);
  });

  it('omits the section when no GlobalProtect is present', () => {
    const html = generateReportHtml(base);
    expect(html).not.toContain('Remote Access VPN');
  });
});

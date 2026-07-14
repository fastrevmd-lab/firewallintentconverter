import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const CONFIG = {
  zones: [{ name: 'REMOTE-ACCESS', interfaces: ['tunnel.10'] }],
  interfaces: [
    { name: 'tunnel.10', zone: 'REMOTE-ACCESS', type: 'tunnel',
      description: 'Remote Access GP Tunnel', remote_access_role: 'ssl-vpn' },
  ],
  global_protect: { gateways: [{ name: 'G41-GP-GW', tunnel_interface: 'tunnel.10' }] },
  security_policies: [], nat_rules: [], address_objects: [], service_objects: [],
  vpn_tunnels: [],
};
const MAPPINGS = { 'tunnel.10': 'st0.10' };

describe('SRX SSL-VPN remote-access placeholder', () => {
  it('emits an SSL-VPN caveat comment naming the gateway', () => {
    const out = convertToSrxSetCommands(CONFIG, MAPPINGS);
    const text = Array.isArray(out.commands) ? out.commands.join('\n') : String(out);
    expect(text).toMatch(/SSL-VPN \(GlobalProtect 'G41-GP-GW'\)/);
    expect(text).toMatch(/not auto-converted/i);
  });

  it('does not emit IKE/IPsec config for the SSL-VPN tunnel', () => {
    const out = convertToSrxSetCommands(CONFIG, MAPPINGS);
    const text = Array.isArray(out.commands) ? out.commands.join('\n') : String(out);
    expect(text).not.toMatch(/set security ike gateway/);
    expect(text).not.toMatch(/set security ipsec vpn/);
  });
});

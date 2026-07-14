import { describe, it, expect } from 'vitest';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';

/** Minimal PAN-OS XML with one GlobalProtect gateway bound to tunnel.10. */
const GP_XML = `<?xml version="1.0"?>
<config version="11.1.0">
  <devices><entry name="localhost.localdomain">
    <network><interface><tunnel>
      <entry name="tunnel.10"><comment>Remote Access GP Tunnel</comment></entry>
    </tunnel></interface></network>
    <vsys><entry name="vsys1">
      <zone><entry name="REMOTE-ACCESS"><network><layer3>
        <member>tunnel.10</member>
      </layer3></network></entry></zone>
      <global-protect><global-protect-gateway>
        <entry name="G41-GP-GW"><tunnel-interface>tunnel.10</tunnel-interface></entry>
      </global-protect-gateway></global-protect>
    </entry></vsys>
  </entry></devices>
</config>`;

const NO_GP_XML = `<?xml version="1.0"?>
<config version="11.1.0">
  <devices><entry name="localhost.localdomain">
    <network><interface><tunnel>
      <entry name="tunnel.1"><comment>Site VPN</comment></entry>
    </tunnel></interface></network>
    <vsys><entry name="vsys1">
      <zone><entry name="VPN"><network><layer3>
        <member>tunnel.1</member>
      </layer3></network></entry></zone>
    </entry></vsys>
  </entry></devices>
</config>`;

describe('PAN-OS GlobalProtect detection', () => {
  it('records GP gateways and stamps the bound tunnel interface', () => {
    const { intermediateConfig } = parsePanosConfig(GP_XML);
    expect(intermediateConfig.global_protect.gateways).toEqual([
      { name: 'G41-GP-GW', tunnel_interface: 'tunnel.10' },
    ]);
    const tun = intermediateConfig.interfaces.find(i => i.name === 'tunnel.10');
    expect(tun).toBeDefined();
    expect(tun.remote_access_role).toBe('ssl-vpn');
  });

  it('leaves non-GlobalProtect configs unchanged', () => {
    const { intermediateConfig } = parsePanosConfig(NO_GP_XML);
    expect(intermediateConfig.global_protect.gateways).toEqual([]);
    const tun = intermediateConfig.interfaces.find(i => i.name === 'tunnel.1');
    expect(tun?.remote_access_role).toBeUndefined();
  });
});

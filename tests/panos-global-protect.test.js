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

  it('records multiple GP gateways and stamps each bound tunnel', () => {
    const xml = `<?xml version="1.0"?>
<config version="11.1.0">
  <devices><entry name="localhost.localdomain">
    <network><interface><tunnel>
      <entry name="tunnel.10"><comment>GP A</comment></entry>
      <entry name="tunnel.12"><comment>GP B</comment></entry>
    </tunnel></interface></network>
    <vsys><entry name="vsys1">
      <zone><entry name="REMOTE-ACCESS"><network><layer3>
        <member>tunnel.10</member><member>tunnel.12</member>
      </layer3></network></entry></zone>
      <global-protect><global-protect-gateway>
        <entry name="G41-GP-GW"><tunnel-interface>tunnel.10</tunnel-interface></entry>
        <entry name="D41-GP-GW-DUO"><tunnel-interface>tunnel.12</tunnel-interface></entry>
      </global-protect-gateway></global-protect>
    </entry></vsys>
  </entry></devices>
</config>`;
    const { intermediateConfig } = parsePanosConfig(xml);
    expect(intermediateConfig.global_protect.gateways).toEqual([
      { name: 'G41-GP-GW', tunnel_interface: 'tunnel.10' },
      { name: 'D41-GP-GW-DUO', tunnel_interface: 'tunnel.12' },
    ]);
    expect(intermediateConfig.interfaces.find(i => i.name === 'tunnel.10').remote_access_role).toBe('ssl-vpn');
    expect(intermediateConfig.interfaces.find(i => i.name === 'tunnel.12').remote_access_role).toBe('ssl-vpn');
  });

  it('skips a GP gateway that has no tunnel-interface, records the valid one', () => {
    const xml = `<?xml version="1.0"?>
<config version="11.1.0">
  <devices><entry name="localhost.localdomain">
    <network><interface><tunnel>
      <entry name="tunnel.10"><comment>GP A</comment></entry>
    </tunnel></interface></network>
    <vsys><entry name="vsys1">
      <zone><entry name="REMOTE-ACCESS"><network><layer3>
        <member>tunnel.10</member>
      </layer3></network></entry></zone>
      <global-protect><global-protect-gateway>
        <entry name="NO-TUNNEL-GW"></entry>
        <entry name="G41-GP-GW"><tunnel-interface>tunnel.10</tunnel-interface></entry>
      </global-protect-gateway></global-protect>
    </entry></vsys>
  </entry></devices>
</config>`;
    const { intermediateConfig } = parsePanosConfig(xml);
    // The gateway with no <tunnel-interface> is skipped; only the valid one is recorded.
    expect(intermediateConfig.global_protect.gateways).toEqual([
      { name: 'G41-GP-GW', tunnel_interface: 'tunnel.10' },
    ]);
    expect(intermediateConfig.interfaces.find(i => i.name === 'tunnel.10').remote_access_role).toBe('ssl-vpn');
  });

  it('records a gateway referencing an absent tunnel without crashing or stamping', () => {
    const xml = `<?xml version="1.0"?>
<config version="11.1.0">
  <devices><entry name="localhost.localdomain">
    <network><interface><tunnel>
      <entry name="tunnel.10"><comment>GP A</comment></entry>
    </tunnel></interface></network>
    <vsys><entry name="vsys1">
      <zone><entry name="REMOTE-ACCESS"><network><layer3>
        <member>tunnel.10</member>
      </layer3></network></entry></zone>
      <global-protect><global-protect-gateway>
        <entry name="G41-GP-GW"><tunnel-interface>tunnel.10</tunnel-interface></entry>
        <entry name="GHOST-GW"><tunnel-interface>tunnel.99</tunnel-interface></entry>
      </global-protect-gateway></global-protect>
    </entry></vsys>
  </entry></devices>
</config>`;
    const { intermediateConfig } = parsePanosConfig(xml);
    // The gateway is recorded (for the report) even though tunnel.99 is not a
    // parsed interface; nothing is stamped for the absent tunnel and no crash.
    expect(intermediateConfig.global_protect.gateways).toEqual([
      { name: 'G41-GP-GW', tunnel_interface: 'tunnel.10' },
      { name: 'GHOST-GW', tunnel_interface: 'tunnel.99' },
    ]);
    expect(intermediateConfig.interfaces.find(i => i.name === 'tunnel.99')).toBeUndefined();
    expect(intermediateConfig.interfaces.find(i => i.name === 'tunnel.10').remote_access_role).toBe('ssl-vpn');
  });
});

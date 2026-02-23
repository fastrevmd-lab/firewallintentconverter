/**
 * VPNEditor Component
 *
 * Card-based editor for VPN/IPsec tunnels in the center panel "VPN" tab.
 * Each tunnel shows: IKE gateway, IKE proposal, IPsec proposal, tunnel interface, proxy IDs.
 * Supports add/edit/delete.
 */
import React from 'react';

export default function VPNEditor({ vpnTunnels, onVPNUpdate, viewMode }) {
  const isSrx = viewMode === 'srx';

  /** Deep update a nested field using dot-path (e.g., 'ike_gateway.address') */
  const handleChange = (index, path, value) => {
    const updated = vpnTunnels.map((tunnel, i) => {
      if (i !== index) return tunnel;
      const parts = path.split('.');
      if (parts.length === 1) {
        return { ...tunnel, [parts[0]]: value };
      }
      // Nested update (e.g., ike_gateway.address)
      const clone = { ...tunnel };
      clone[parts[0]] = { ...clone[parts[0]], [parts[1]]: value };
      return clone;
    });
    onVPNUpdate(updated);
  };

  const handleAdd = () => {
    onVPNUpdate([...vpnTunnels, {
      name: `vpn-tunnel-${vpnTunnels.length + 1}`,
      ike_gateway: {
        name: `ike-gw-${vpnTunnels.length + 1}`,
        address: '',
        local_address: '',
        pre_shared_key: 'SANITIZED',
        ike_version: 'v2',
        proposal: '',
      },
      ike_proposal: {
        name: `ike-proposal-${vpnTunnels.length + 1}`,
        auth_method: 'pre-shared-keys',
        dh_group: 'group14',
        encryption: 'aes-256-cbc',
        authentication: 'sha-256',
        lifetime: 28800,
      },
      ipsec_proposal: {
        name: `ipsec-proposal-${vpnTunnels.length + 1}`,
        protocol: 'esp',
        encryption: 'aes-256-cbc',
        authentication: 'hmac-sha-256-128',
        lifetime: 3600,
        pfs_group: 'group14',
      },
      proxy_id: [],
      tunnel_interface: '',
      description: '',
    }]);
  };

  const handleDelete = (index) => {
    onVPNUpdate(vpnTunnels.filter((_, i) => i !== index));
  };

  const handleProxyIdAdd = (tunnelIndex) => {
    const tunnel = vpnTunnels[tunnelIndex];
    const updated = vpnTunnels.map((t, i) =>
      i === tunnelIndex
        ? { ...t, proxy_id: [...(t.proxy_id || []), { local: '', remote: '', protocol: 'any' }] }
        : t
    );
    onVPNUpdate(updated);
  };

  const handleProxyIdRemove = (tunnelIndex, pidIndex) => {
    const updated = vpnTunnels.map((t, i) =>
      i === tunnelIndex
        ? { ...t, proxy_id: (t.proxy_id || []).filter((_, j) => j !== pidIndex) }
        : t
    );
    onVPNUpdate(updated);
  };

  const handleProxyIdChange = (tunnelIndex, pidIndex, field, value) => {
    const updated = vpnTunnels.map((t, i) => {
      if (i !== tunnelIndex) return t;
      const newProxyIds = (t.proxy_id || []).map((pid, j) =>
        j === pidIndex ? { ...pid, [field]: value } : pid
      );
      return { ...t, proxy_id: newProxyIds };
    });
    onVPNUpdate(updated);
  };

  if (!vpnTunnels || vpnTunnels.length === 0) {
    return (
      <div className="panel-body">
        <div className="empty-state">
          <p>No VPN tunnels defined.</p>
          <button className="btn btn-primary btn-sm" onClick={handleAdd}>Add VPN Tunnel</button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ overflow: 'auto', flex: 1 }}>
      <div className="editor-list">
        {vpnTunnels.map((tunnel, index) => (
          <div key={index} className="editor-card">
            <div className="editor-card-header">
              <input
                className="editor-inline-input editor-name-input"
                value={tunnel.name}
                onChange={(e) => handleChange(index, 'name', e.target.value)}
              />
              <button className="btn-icon btn-icon-danger" onClick={() => handleDelete(index)} title="Delete">x</button>
            </div>

            <div className="editor-card-body">
              {/* IKE Gateway */}
              <div style={{ marginBottom: 8 }}>
                <label style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4, display: 'block' }}>
                  {isSrx ? 'IKE Gateway' : 'IKE Gateway'}
                </label>
                <div className="editor-field-row">
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Gateway Name</label>
                    <input
                      className="cell-input"
                      value={tunnel.ike_gateway?.name || ''}
                      onChange={(e) => handleChange(index, 'ike_gateway.name', e.target.value)}
                    />
                  </div>
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Remote Address</label>
                    <input
                      className="cell-input"
                      value={tunnel.ike_gateway?.address || ''}
                      onChange={(e) => handleChange(index, 'ike_gateway.address', e.target.value)}
                      placeholder="Peer IP"
                    />
                  </div>
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Local Interface</label>
                    <input
                      className="cell-input"
                      value={tunnel.ike_gateway?.local_address || ''}
                      onChange={(e) => handleChange(index, 'ike_gateway.local_address', e.target.value)}
                      placeholder="e.g. ge-0/0/0.0"
                    />
                  </div>
                  <div className="editor-field" style={{ width: 80 }}>
                    <label>IKE Ver.</label>
                    <select
                      className="cell-select"
                      value={tunnel.ike_gateway?.ike_version || 'v2'}
                      onChange={(e) => handleChange(index, 'ike_gateway.ike_version', e.target.value)}
                    >
                      <option value="v1">v1</option>
                      <option value="v2">v2</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* IKE Proposal */}
              <div style={{ marginBottom: 8 }}>
                <label style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4, display: 'block' }}>
                  IKE Proposal ({tunnel.ike_proposal?.name || ''})
                </label>
                <div className="editor-field-row">
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Encryption</label>
                    <select
                      className="cell-select"
                      value={tunnel.ike_proposal?.encryption || 'aes-256-cbc'}
                      onChange={(e) => handleChange(index, 'ike_proposal.encryption', e.target.value)}
                    >
                      <option value="aes-128-cbc">AES-128-CBC</option>
                      <option value="aes-256-cbc">AES-256-CBC</option>
                      <option value="aes-128-gcm">AES-128-GCM</option>
                      <option value="aes-256-gcm">AES-256-GCM</option>
                      <option value="3des-cbc">3DES-CBC</option>
                    </select>
                  </div>
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Authentication</label>
                    <select
                      className="cell-select"
                      value={tunnel.ike_proposal?.authentication || 'sha-256'}
                      onChange={(e) => handleChange(index, 'ike_proposal.authentication', e.target.value)}
                    >
                      <option value="sha-256">SHA-256</option>
                      <option value="sha-384">SHA-384</option>
                      <option value="sha-512">SHA-512</option>
                      <option value="sha1">SHA-1</option>
                      <option value="md5">MD5</option>
                    </select>
                  </div>
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>DH Group</label>
                    <select
                      className="cell-select"
                      value={tunnel.ike_proposal?.dh_group || 'group14'}
                      onChange={(e) => handleChange(index, 'ike_proposal.dh_group', e.target.value)}
                    >
                      <option value="group1">Group 1</option>
                      <option value="group2">Group 2</option>
                      <option value="group5">Group 5</option>
                      <option value="group14">Group 14</option>
                      <option value="group19">Group 19</option>
                      <option value="group20">Group 20</option>
                      <option value="group21">Group 21</option>
                      <option value="group24">Group 24</option>
                    </select>
                  </div>
                  <div className="editor-field" style={{ width: 100 }}>
                    <label>Lifetime (s)</label>
                    <input
                      className="cell-input"
                      type="number"
                      value={tunnel.ike_proposal?.lifetime || 28800}
                      onChange={(e) => handleChange(index, 'ike_proposal.lifetime', parseInt(e.target.value, 10) || 0)}
                    />
                  </div>
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Auth Method</label>
                    <select
                      className="cell-select"
                      value={tunnel.ike_proposal?.auth_method || 'pre-shared-keys'}
                      onChange={(e) => handleChange(index, 'ike_proposal.auth_method', e.target.value)}
                    >
                      <option value="pre-shared-keys">Pre-Shared Keys</option>
                      <option value="rsa-signatures">RSA Signatures</option>
                      <option value="dsa-signatures">DSA Signatures</option>
                      <option value="ecdsa-signatures-256">ECDSA-256</option>
                      <option value="ecdsa-signatures-384">ECDSA-384</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* IPsec Proposal */}
              <div style={{ marginBottom: 8 }}>
                <label style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4, display: 'block' }}>
                  IPsec Proposal ({tunnel.ipsec_proposal?.name || ''})
                </label>
                <div className="editor-field-row">
                  <div className="editor-field" style={{ width: 90 }}>
                    <label>Protocol</label>
                    <select
                      className="cell-select"
                      value={tunnel.ipsec_proposal?.protocol || 'esp'}
                      onChange={(e) => handleChange(index, 'ipsec_proposal.protocol', e.target.value)}
                    >
                      <option value="esp">ESP</option>
                      <option value="ah">AH</option>
                    </select>
                  </div>
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Encryption</label>
                    <select
                      className="cell-select"
                      value={tunnel.ipsec_proposal?.encryption || 'aes-256-cbc'}
                      onChange={(e) => handleChange(index, 'ipsec_proposal.encryption', e.target.value)}
                    >
                      <option value="aes-128-cbc">AES-128-CBC</option>
                      <option value="aes-256-cbc">AES-256-CBC</option>
                      <option value="aes-128-gcm">AES-128-GCM</option>
                      <option value="aes-256-gcm">AES-256-GCM</option>
                      <option value="3des-cbc">3DES-CBC</option>
                    </select>
                  </div>
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>Authentication</label>
                    <select
                      className="cell-select"
                      value={tunnel.ipsec_proposal?.authentication || 'hmac-sha-256-128'}
                      onChange={(e) => handleChange(index, 'ipsec_proposal.authentication', e.target.value)}
                    >
                      <option value="hmac-sha-256-128">HMAC-SHA-256-128</option>
                      <option value="hmac-sha-384">HMAC-SHA-384</option>
                      <option value="hmac-sha-512">HMAC-SHA-512</option>
                      <option value="hmac-sha1-96">HMAC-SHA1-96</option>
                      <option value="hmac-md5-96">HMAC-MD5-96</option>
                    </select>
                  </div>
                  <div className="editor-field" style={{ flex: 1 }}>
                    <label>PFS Group</label>
                    <select
                      className="cell-select"
                      value={tunnel.ipsec_proposal?.pfs_group || 'group14'}
                      onChange={(e) => handleChange(index, 'ipsec_proposal.pfs_group', e.target.value)}
                    >
                      <option value="group1">Group 1</option>
                      <option value="group2">Group 2</option>
                      <option value="group5">Group 5</option>
                      <option value="group14">Group 14</option>
                      <option value="group19">Group 19</option>
                      <option value="group20">Group 20</option>
                      <option value="group21">Group 21</option>
                      <option value="group24">Group 24</option>
                    </select>
                  </div>
                  <div className="editor-field" style={{ width: 100 }}>
                    <label>Lifetime (s)</label>
                    <input
                      className="cell-input"
                      type="number"
                      value={tunnel.ipsec_proposal?.lifetime || 3600}
                      onChange={(e) => handleChange(index, 'ipsec_proposal.lifetime', parseInt(e.target.value, 10) || 0)}
                    />
                  </div>
                </div>
              </div>

              {/* Tunnel Interface + Description */}
              <div className="editor-field-row">
                <div className="editor-field" style={{ width: 180 }}>
                  <label>Tunnel Interface</label>
                  <input
                    className="cell-input"
                    value={tunnel.tunnel_interface || ''}
                    onChange={(e) => handleChange(index, 'tunnel_interface', e.target.value)}
                    placeholder="e.g. st0.0"
                  />
                </div>
                <div className="editor-field" style={{ flex: 1 }}>
                  <label>Description</label>
                  <input
                    className="editor-inline-input"
                    value={tunnel.description || ''}
                    onChange={(e) => handleChange(index, 'description', e.target.value)}
                    placeholder="Optional description"
                  />
                </div>
              </div>

              {/* Proxy IDs / Traffic Selectors */}
              <div style={{ marginTop: 8 }}>
                <label style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4, display: 'block' }}>
                  {isSrx ? 'Traffic Selectors' : 'Proxy IDs'} ({(tunnel.proxy_id || []).length})
                </label>
                {(tunnel.proxy_id || []).map((pid, pidIndex) => (
                  <div key={pidIndex} className="editor-field-row" style={{ marginBottom: 4 }}>
                    <div className="editor-field" style={{ flex: 1 }}>
                      <label>Local</label>
                      <input
                        className="cell-input"
                        value={pid.local || ''}
                        onChange={(e) => handleProxyIdChange(index, pidIndex, 'local', e.target.value)}
                        placeholder="Local subnet"
                      />
                    </div>
                    <div className="editor-field" style={{ flex: 1 }}>
                      <label>Remote</label>
                      <input
                        className="cell-input"
                        value={pid.remote || ''}
                        onChange={(e) => handleProxyIdChange(index, pidIndex, 'remote', e.target.value)}
                        placeholder="Remote subnet"
                      />
                    </div>
                    <div className="editor-field" style={{ width: 90 }}>
                      <label>Protocol</label>
                      <input
                        className="cell-input"
                        value={pid.protocol || 'any'}
                        onChange={(e) => handleProxyIdChange(index, pidIndex, 'protocol', e.target.value)}
                      />
                    </div>
                    <button
                      className="btn-icon btn-icon-danger"
                      onClick={() => handleProxyIdRemove(index, pidIndex)}
                      title="Remove"
                      style={{ alignSelf: 'flex-end', marginBottom: 4 }}
                    >x</button>
                  </div>
                ))}
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => handleProxyIdAdd(index)}
                  style={{ marginTop: 4, fontSize: 11 }}
                >
                  + Add {isSrx ? 'Traffic Selector' : 'Proxy ID'}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div style={{ padding: '12px 16px' }}>
        <button className="btn btn-secondary btn-sm" onClick={handleAdd}>+ Add VPN Tunnel</button>
      </div>
    </div>
  );
}

/**
 * PullModal — Pull running config from a live SRX device via the PyEZ Bridge.
 *
 * Reuses the same bridge URL and device store as the PushModal.
 * Calls GET /devices/<name>/pull-config and returns the config text
 * to the caller via onConfigPulled callback.
 */
import React, { useState, useCallback } from 'react';
import {
  bridgeFetch,
  bridgeResponseError,
  loadBridgeSettings,
  normalizeBridgeUrl,
  saveBridgeSettings,
} from '../utils/bridge-client.js';

export default function PullModal({ onClose, onConfigPulled }) {
  const [bridgeUrl, setBridgeUrl] = useState(
    () => loadBridgeSettings().url || 'http://127.0.0.1:8830',
  );
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [pullFormat, setPullFormat] = useState('set');
  const [status, setStatus] = useState(''); // idle, loading-devices, pulling, done, error
  const [error, setError] = useState('');
  const [pulledConfig, setPulledConfig] = useState('');

  /** Fetch device list from bridge */
  const handleLoadDevices = useCallback(async () => {
    const url = normalizeBridgeUrl(bridgeUrl);
    if (!url) { setError('Invalid bridge URL'); return; }
    setStatus('loading-devices');
    setError('');

    try {
      saveBridgeSettings({ url, token: loadBridgeSettings().token });
      setBridgeUrl(url);
      const resp = await bridgeFetch(`${url}/devices`);
      if (!resp.ok) throw await bridgeResponseError(resp);
      const data = await resp.json();
      setDevices(data.devices || []);
      if (data.devices?.length > 0) setSelectedDevice(data.devices[0].name);
      setStatus('');
    } catch (err) {
      setError(`Failed to connect to bridge: ${err.message}`);
      setStatus('error');
    }
  }, [bridgeUrl]);

  /** Pull config from selected device */
  const handlePull = useCallback(async () => {
    if (!selectedDevice) { setError('Select a device'); return; }
    const url = normalizeBridgeUrl(bridgeUrl);
    setStatus('pulling');
    setError('');
    setPulledConfig('');

    try {
      const resp = await bridgeFetch(
        `${url}/devices/${encodeURIComponent(selectedDevice)}/pull-config?format=${pullFormat}`,
        {},
        { timeout: 60000 },
      );
      if (!resp.ok) throw await bridgeResponseError(resp);
      const data = await resp.json();
      if (!data.ok) throw new Error(data.error || 'Pull failed');
      setPulledConfig(data.config || '');
      setStatus('done');
    } catch (err) {
      setError(`Pull failed: ${err.message}`);
      setStatus('error');
    }
  }, [selectedDevice, bridgeUrl, pullFormat]);

  /** Send pulled config to ConfigInput */
  const handleUsePulledConfig = useCallback(() => {
    if (pulledConfig && onConfigPulled) {
      onConfigPulled(pulledConfig);
      onClose();
    }
  }, [pulledConfig, onConfigPulled, onClose]);

  const modalStyle = {
    position: 'fixed', inset: 0, zIndex: 9999,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(2px)',
  };

  const panelStyle = {
    background: 'var(--bg-primary)', border: '1px solid var(--border-color)',
    borderRadius: 'var(--radius)', width: 520, maxHeight: '80vh',
    overflow: 'auto', padding: 20,
  };

  const labelStyle = { fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 };
  const inputStyle = {
    width: '100%', padding: '6px 10px', background: 'var(--bg-tertiary)',
    border: '1px solid var(--border-color)', borderRadius: 'var(--radius)',
    color: 'var(--text-primary)', fontSize: 12,
  };

  return (
    <div style={modalStyle} onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={panelStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, fontSize: 15 }}>Pull Config from Device</h3>
          <button className="btn-icon" onClick={onClose} title="Close">x</button>
        </div>

        {/* Bridge URL */}
        <div style={{ marginBottom: 12 }}>
          <label style={labelStyle}>PyEZ Bridge URL</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input style={{ ...inputStyle, flex: 1 }} value={bridgeUrl}
              onChange={(e) => setBridgeUrl(e.target.value)}
              placeholder="http://127.0.0.1:8830" />
            <button className="btn btn-primary btn-sm" onClick={handleLoadDevices}
              disabled={status === 'loading-devices'}>
              {status === 'loading-devices' ? 'Loading...' : 'Connect'}
            </button>
          </div>
        </div>

        {/* Device selector */}
        {devices.length > 0 && (
          <div style={{ marginBottom: 12 }}>
            <label style={labelStyle}>Device</label>
            <select style={inputStyle} value={selectedDevice}
              onChange={(e) => setSelectedDevice(e.target.value)}>
              {devices.map(d => (
                <option key={d.name} value={d.name}>{d.name} ({d.host})</option>
              ))}
            </select>
          </div>
        )}

        {/* Format selector */}
        {devices.length > 0 && (
          <div style={{ marginBottom: 12 }}>
            <label style={labelStyle}>Config Format</label>
            <select style={inputStyle} value={pullFormat}
              onChange={(e) => setPullFormat(e.target.value)}>
              <option value="set">Set commands</option>
              <option value="xml">XML</option>
              <option value="text">Hierarchical text</option>
            </select>
          </div>
        )}

        {/* Pull button */}
        {devices.length > 0 && (
          <button className="btn btn-primary" style={{ width: '100%', marginBottom: 12 }}
            onClick={handlePull} disabled={status === 'pulling'}>
            {status === 'pulling' ? 'Pulling configuration...' : 'Pull Configuration'}
          </button>
        )}

        {/* Error */}
        {error && (
          <div style={{ padding: 8, background: 'rgba(231,76,60,0.08)', borderRadius: 4, color: 'var(--error, #e74c3c)', fontSize: 12, marginBottom: 12 }}>
            {error}
          </div>
        )}

        {/* Result preview */}
        {pulledConfig && (
          <div style={{ marginBottom: 12 }}>
            <label style={labelStyle}>Pulled Config Preview ({pulledConfig.split('\n').length} lines)</label>
            <pre style={{
              background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)',
              borderRadius: 4, padding: 8, maxHeight: 200, overflow: 'auto',
              fontSize: 11, fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap',
            }}>
              {pulledConfig.slice(0, 5000)}{pulledConfig.length > 5000 ? '\n... (truncated preview)' : ''}
            </pre>
            <button className="btn btn-primary" style={{ width: '100%', marginTop: 8 }}
              onClick={handleUsePulledConfig}>
              Use This Configuration
            </button>
          </div>
        )}

        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
          Requires the PyEZ Bridge to be running. See tools/pyez-bridge/README.md
        </div>
      </div>
    </div>
  );
}

/**
 * LLMSettings Component
 *
 * Modal dialog for configuring the LLM provider used by the interview engine.
 * Includes provider selection, API key, model, temperature, and editable system prompt.
 *
 * Settings are stored in localStorage only — API keys never leave the browser.
 */
import React, { useState, useEffect } from 'react';
import {
  DEFAULT_FULL_REVIEW_SYSTEM_PROMPT,
  DEFAULT_GREENFIELD_SYSTEM_PROMPT,
  VENDOR_PROMPT_KEYS,
  loadVendorTranslatePrompt,
} from '../utils/llm-client.js';
import { safeJsonParse } from '../utils/safe-json.js';
import {
  bridgeFetch,
  bridgeResponseError,
  loadBridgeSettings,
  normalizeBridgeUrl,
  saveBridgeSettings,
} from '../utils/bridge-client.js';
import { useUIContext } from '../contexts/UIContext.jsx';

const CLOUD_PROVIDER_IDS = ['claude', 'openai', 'gemini'];

const VENDOR_LABELS = {
  '': 'Default (Generic)',
  panos: 'PAN-OS → SRX',
  fortigate: 'FortiGate → SRX',
  cisco_asa: 'Cisco ASA → SRX',
  checkpoint: 'Check Point → SRX',
  sonicwall: 'SonicWall → SRX',
  huawei_usg: 'Huawei USG → SRX',
  srx: 'SRX → SRX (Optimize)',
  srx_healthcheck: 'SRX Best Practice (Audit)',
};

const PROVIDERS = [
  { id: 'claude', name: 'Claude (Anthropic)', defaultModel: 'claude-sonnet-4-6', models: [
    { id: 'claude-opus-4-8', name: 'Claude Opus 4.8 (Most Capable)' },
    { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6 (Balanced)' },
    { id: 'claude-haiku-4-5-20251001', name: 'Claude Haiku 4.5 (Fast)' },
  ]},
  { id: 'openai', name: 'OpenAI', defaultModel: 'gpt-4o', models: [
    { id: 'gpt-4o', name: 'GPT-4o (Recommended)' },
    { id: 'gpt-4o-mini', name: 'GPT-4o Mini (Fast)' },
    { id: 'gpt-4.1', name: 'GPT-4.1' },
    { id: 'gpt-4.1-mini', name: 'GPT-4.1 Mini' },
    { id: 'gpt-4.1-nano', name: 'GPT-4.1 Nano (Fastest)' },
    { id: 'o3', name: 'o3 (Reasoning)' },
    { id: 'o4-mini', name: 'o4-mini (Reasoning, Fast)' },
  ]},
  { id: 'gemini', name: 'Gemini (Google)', defaultModel: 'gemini-3-flash-preview', models: [
    { id: 'gemini-3-flash-preview', name: 'Gemini 3 Flash (Recommended)' },
    { id: 'gemini-3.1-flash-lite-preview', name: 'Gemini 3.1 Flash-Lite (Fastest)' },
    { id: 'gemini-3.1-pro-preview', name: 'Gemini 3.1 Pro (Most Capable)' },
    { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash (Stable)' },
    { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro (Stable)' },
  ]},
  { id: 'ollama', name: 'Ollama (Local)', defaultModel: 'qwen2.5-coder:7b', models: [] },
  { id: 'lmstudio', name: 'LM Studio (Local)', defaultModel: 'local-model', models: [] },
  { id: 'custom', name: 'Custom OpenAI-Compatible', defaultModel: '', models: [] },
];

export default function LLMSettings({ onClose, initialTab }) {
  const { state: ui, dispatch: uiDispatch } = useUIContext();
  const localOnly = ui.llmRiskAcceptance === 'local-only';
  const availableProviders = localOnly
    ? PROVIDERS.filter(p => !CLOUD_PROVIDER_IDS.includes(p.id))
    : PROVIDERS;

  const [activeTab, setActiveTab] = useState(initialTab || 'llm');
  const [provider, setProvider] = useState(localOnly ? 'ollama' : 'claude');
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState('claude-sonnet-4-6');
  const [baseUrl, setBaseUrl] = useState('');
  const [temperature, setTemperature] = useState(0.2);
  const [fullReviewSystemPrompt, setFullReviewSystemPrompt] = useState(DEFAULT_FULL_REVIEW_SYSTEM_PROMPT);
  const [greenfieldSystemPrompt, setGreenfieldSystemPrompt] = useState(DEFAULT_GREENFIELD_SYSTEM_PROMPT);
  const [promptSubTab, setPromptSubTab] = useState('fullReview');
  const [vendorPromptSelection, setVendorPromptSelection] = useState('');
  const [vendorPrompts, setVendorPrompts] = useState({});

  // PyEZ Bridge state
  const [bridgeUrl, setBridgeUrl] = useState(() => loadBridgeSettings().url);
  const [bridgeToken, setBridgeToken] = useState(() => loadBridgeSettings().token);
  const [bridgeConnected, setBridgeConnected] = useState(false);
  const [bridgeTesting, setBridgeTesting] = useState(false);
  const [bridgeTestResult, setBridgeTestResult] = useState('');
  const [bridgeResultOk, setBridgeResultOk] = useState(true);
  const [bridgeDevices, setBridgeDevices] = useState([]);
  const [showAddDevice, setShowAddDevice] = useState(false);
  const [newDevice, setNewDevice] = useState({ name: '', host: '', port: 830, username: '', password: '', ssh_key: '' });

  // Load saved settings from localStorage on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem('llm-settings');
      if (saved) {
        const settings = safeJsonParse(saved);
        const savedProvider = settings.provider || 'claude';
        // If local-only mode and saved provider is cloud, switch to ollama
        if (localOnly && CLOUD_PROVIDER_IDS.includes(savedProvider)) {
          setProvider('ollama');
          setModel('qwen2.5-coder:7b');
          setBaseUrl('http://localhost:11434');
        } else {
          setProvider(savedProvider);
          setModel(settings.model || 'claude-sonnet-4-6');
        }
        setApiKey(settings.apiKey || '');
        setBaseUrl(settings.baseUrl || '');
        setTemperature(settings.temperature ?? 0.2);
        setFullReviewSystemPrompt(settings.fullReviewSystemPrompt || DEFAULT_FULL_REVIEW_SYSTEM_PROMPT);
        setGreenfieldSystemPrompt(settings.greenfieldSystemPrompt || DEFAULT_GREENFIELD_SYSTEM_PROMPT);
        // Load vendor-specific translate prompts from localStorage
        const vp = {};
        for (const v of VENDOR_PROMPT_KEYS) {
          const k = `translateSystemPrompt_${v}`;
          if (settings[k]) vp[v] = settings[k];
        }
        if (Object.keys(vp).length > 0) setVendorPrompts(vp);
      }
    } catch {
      // Ignore parse errors
    }
    const savedBridge = loadBridgeSettings();
    const savedBridgeUrl = savedBridge.url;
    setBridgeUrl(savedBridge.url);
    setBridgeToken(savedBridge.token);
    // Auto-connect to bridge if URL is saved
    if (savedBridgeUrl && savedBridge.token) {
      const base = normalizeBridgeUrl(savedBridgeUrl);
      bridgeFetch(base + '/health', {}, { authenticated: false })
        .then(async (healthResponse) => {
          if (!healthResponse.ok) throw await bridgeResponseError(healthResponse);
          const health = await healthResponse.json();
          if (health.status !== 'ok' || health.service !== 'pyez-bridge') return;
          const deviceResponse = await bridgeFetch(base + '/devices');
          if (!deviceResponse.ok) throw await bridgeResponseError(deviceResponse);
          const devices = await deviceResponse.json();
          setBridgeDevices(Array.isArray(devices) ? devices : devices.devices || []);
          setBridgeConnected(true);
          return bridgeFetch(
            base + '/devices?probe=true',
            {},
            { timeout: 60000 },
          );
        })
        .then(async (probeResponse) => {
          if (!probeResponse?.ok) return;
          const devices = await probeResponse.json();
          setBridgeDevices(Array.isArray(devices) ? devices : devices.devices || []);
        })
        .catch(() => setBridgeConnected(false));
    }
  }, []);

  /** Save settings to localStorage */
  const handleSave = () => {
    const settings = {
      provider, apiKey, model, baseUrl, temperature,
      fullReviewSystemPrompt, greenfieldSystemPrompt,
    };
    // Save vendor-specific translate prompts
    for (const [v, prompt] of Object.entries(vendorPrompts)) {
      if (prompt && prompt.trim()) settings[`translateSystemPrompt_${v}`] = prompt;
    }
    localStorage.setItem('llm-settings', JSON.stringify(settings));
    saveBridgeSettings({ url: bridgeUrl, token: bridgeToken });
    onClose();
  };

  /** Test PyEZ Bridge connection */
  const handleBridgeTest = async () => {
    const base = normalizeBridgeUrl(bridgeUrl);
    if (!base) {
      setBridgeResultOk(false);
      setBridgeTestResult('Enter the PyEZ Bridge URL first.');
      return;
    }
    // Update the input to the normalized URL
    if (base !== bridgeUrl) setBridgeUrl(base);
    saveBridgeSettings({ url: base, token: bridgeToken });
    setBridgeTesting(true);
    setBridgeTestResult('');
    setBridgeDevices([]);
    try {
      const resp = await bridgeFetch(
        base + '/health',
        { method: 'GET' },
        { authenticated: false },
      );
      if (!resp.ok) {
        throw await bridgeResponseError(resp);
      }
      // Verify it's actually the PyEZ Bridge (not a Vite SPA fallback)
      let data;
      try { data = await resp.json(); } catch {
        setBridgeConnected(false);
        setBridgeResultOk(false);
        setBridgeTestResult('URL responded with non-JSON content. Check the URL and port — it may be pointing at the wrong service.');
        return;
      }
      if (data.status !== 'ok' || data.service !== 'pyez-bridge') {
        setBridgeConnected(false);
        setBridgeResultOk(false);
        setBridgeTestResult('URL responded but is not a PyEZ Bridge service. Check the URL and port.');
        return;
      }
      const devResp = await bridgeFetch(base + '/devices', { method: 'GET' });
      if (!devResp.ok) throw await bridgeResponseError(devResp);
      const devData = await devResp.json();
      setBridgeDevices(Array.isArray(devData) ? devData : devData.devices || []);
      setBridgeConnected(true);
      setBridgeResultOk(true);
      setBridgeTestResult('Connected successfully with access token.');
      bridgeFetch(
        base + '/devices?probe=true',
        {},
        { timeout: 60000 },
      ).then(async (probeResponse) => {
        if (!probeResponse.ok) return;
        const probed = await probeResponse.json();
        setBridgeDevices(Array.isArray(probed) ? probed : probed.devices || []);
      }).catch(() => {});
    } catch (err) {
      setBridgeConnected(false);
      setBridgeResultOk(false);
      setBridgeTestResult(`Connection failed: ${err.message}`);
    } finally {
      setBridgeTesting(false);
    }
  };

  /** Add device via PyEZ Bridge */
  const handleAddDevice = async () => {
    if (!newDevice.name.trim() || !newDevice.host.trim() || !newDevice.username.trim()) return;
    if (!bridgeConnected) {
      setBridgeResultOk(false);
      setBridgeTestResult('PyEZ Bridge is not connected. Start the bridge service first.');
      return;
    }
    const base = normalizeBridgeUrl(bridgeUrl);
    const url = base + '/devices';
    // Strip empty optional fields before sending
    const payload = { name: newDevice.name.trim(), host: newDevice.host.trim(), port: newDevice.port || 830, username: newDevice.username.trim() };
    if (newDevice.password) payload.password = newDevice.password;
    if (newDevice.ssh_key) payload.ssh_key = newDevice.ssh_key.trim();
    setBridgeResultOk(true);
    setBridgeTestResult('Adding device...');
    try {
      const resp = await bridgeFetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!resp.ok && [401, 403, 429].includes(resp.status)) {
        throw await bridgeResponseError(resp);
      }
      const data = await resp.json();
      if (data.ok) {
        setNewDevice({ name: '', host: '', port: 830, username: '', password: '', ssh_key: '' });
        setShowAddDevice(false);
        setBridgeResultOk(true);
        setBridgeTestResult('Device added successfully.');
        // Refresh device list
        try {
          const devResp = await bridgeFetch(base + '/devices');
          if (!devResp.ok) throw await bridgeResponseError(devResp);
          const devData = await devResp.json();
          setBridgeDevices(Array.isArray(devData) ? devData : devData.devices || []);
        } catch { /* ignore refresh failure */ }
      } else {
        setBridgeResultOk(false);
        setBridgeTestResult(data.error || 'Failed to add device.');
      }
    } catch (err) {
      setBridgeResultOk(false);
      setBridgeTestResult(`Failed to add device: ${err.message}`);
    }
  };

  /** Remove device via PyEZ Bridge */
  const handleRemoveDevice = async (deviceName) => {
    const base = bridgeUrl.replace(/\/+$/, '');
    try {
      const resp = await bridgeFetch(
        base + `/devices/${encodeURIComponent(deviceName)}`,
        { method: 'DELETE' },
      );
      if (!resp.ok) throw await bridgeResponseError(resp);
      if (resp.ok) {
        setBridgeDevices(prev => prev.filter(d => (d.name || d.hostname) !== deviceName));
      }
    } catch (error) {
      setBridgeResultOk(false);
      setBridgeTestResult(`Failed to remove device: ${error.message}`);
    }
  };

  /** Update defaults when provider changes */
  const handleProviderChange = (newProvider) => {
    setProvider(newProvider);
    const p = PROVIDERS.find(pr => pr.id === newProvider);
    if (p) setModel(p.defaultModel);
    // Set default base URLs for local providers
    if (newProvider === 'ollama') setBaseUrl('http://localhost:11434');
    else if (newProvider === 'lmstudio') setBaseUrl('http://localhost:1234');
    else setBaseUrl('');
  };

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0, 0, 0, 0.6)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bg-secondary)',
        borderRadius: 'var(--radius-lg)',
        border: '1px solid var(--border-color)',
        padding: '24px',
        width: '600px',
        maxHeight: '85vh',
        overflow: 'auto',
      }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '16px' }}>Settings</h2>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '18px' }}
          >
            x
          </button>
        </div>

        {/* Tab bar */}
        <div style={{ display: 'flex', gap: 0, marginBottom: 16, borderBottom: '1px solid var(--border-color)' }}>
          <button
            onClick={() => setActiveTab('llm')}
            style={{
              padding: '8px 16px', background: 'none', border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 500,
              color: activeTab === 'llm' ? 'var(--accent)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'llm' ? '2px solid var(--accent)' : '2px solid transparent',
            }}
          >
            LLM Configuration
          </button>
          <button
            onClick={() => setActiveTab('mcp')}
            style={{
              padding: '8px 16px', background: 'none', border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 500,
              color: activeTab === 'mcp' ? 'var(--accent)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'mcp' ? '2px solid var(--accent)' : '2px solid transparent',
            }}
          >
            SRX Device Connection
          </button>
        </div>

        {activeTab === 'mcp' && (
          <>
            <SettingsField label="PyEZ Bridge URL">
              <input
                type="text"
                value={bridgeUrl}
                onChange={(e) => setBridgeUrl(e.target.value)}
                placeholder="http://localhost:8830"
                style={inputStyle}
              />
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                URL of the PyEZ Bridge service. Run <code style={{ fontSize: 10 }}>python tools/pyez-bridge/app.py</code> locally.
              </div>
            </SettingsField>

            <SettingsField label="Bridge Access Token">
              <input
                type="password"
                value={bridgeToken}
                onChange={(e) => setBridgeToken(e.target.value)}
                autoComplete="off"
                placeholder="Paste the token printed when the bridge starts"
                style={inputStyle}
              />
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Kept only for this browser session and removed when the session ends.
              </div>
            </SettingsField>

            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 16 }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={handleBridgeTest}
                disabled={bridgeTesting}
              >
                {bridgeTesting ? 'Testing...' : 'Test Connection'}
              </button>
              {bridgeTestResult && (
                <span style={{
                  fontSize: 11,
                  color: bridgeResultOk ? 'var(--success)' : 'var(--error)',
                }}>
                  {bridgeTestResult}
                </span>
              )}
            </div>

            {/* Connected SRX devices list */}
            <SettingsField label="SRX Devices">
              {bridgeDevices.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {bridgeDevices.map((dev, i) => (
                    <div key={i} style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '6px 10px', background: 'var(--bg-tertiary)',
                      borderRadius: 'var(--radius)', fontSize: 12,
                    }}>
                      <span style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: dev.status === 'connected' ? 'var(--success)' : 'var(--text-muted)',
                      }} />
                      <span style={{ fontWeight: 500 }}>{dev.hostname || dev.name || dev.host || `Device ${i + 1}`}</span>
                      {dev.model && <span style={{ color: 'var(--text-muted)' }}>({dev.model})</span>}
                      {dev.version && <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>v{dev.version}</span>}
                      <span style={{ color: 'var(--text-muted)', marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{dev.host || dev.ip || ''}</span>
                      <button
                        onClick={() => handleRemoveDevice(dev.name || dev.hostname)}
                        style={{
                          background: 'none', border: 'none', cursor: 'pointer',
                          color: 'var(--text-muted)', fontSize: 14, padding: '0 4px', lineHeight: 1,
                        }}
                        title="Remove device"
                      >x</button>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{
                  padding: '16px', textAlign: 'center', background: 'var(--bg-tertiary)',
                  borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--text-muted)',
                }}>
                  {bridgeConnected ? 'No devices configured. Add one below or edit devices.yaml.' : 'Test connection to discover devices.'}
                </div>
              )}
            </SettingsField>

            {/* Add Device */}
            {bridgeConnected && (
              <div style={{ marginBottom: 16 }}>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => setShowAddDevice(!showAddDevice)}
                  style={{ fontSize: 11, marginBottom: showAddDevice ? 8 : 0 }}
                >
                  {showAddDevice ? 'Cancel' : '+ Add Device'}
                </button>
                {showAddDevice && (
                  <div style={{
                    display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8,
                    padding: 12, background: 'var(--bg-tertiary)',
                    borderRadius: 'var(--radius)', border: '1px solid var(--border-color)',
                  }}>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>Name *</label>
                      <input type="text" value={newDevice.name} onChange={e => setNewDevice(p => ({ ...p, name: e.target.value }))} placeholder="srx-lab-01" style={{ ...inputStyle, fontSize: 11, padding: '4px 8px' }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>Host/IP *</label>
                      <input type="text" value={newDevice.host} onChange={e => setNewDevice(p => ({ ...p, host: e.target.value }))} placeholder="192.168.1.1" style={{ ...inputStyle, fontSize: 11, padding: '4px 8px' }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>Port</label>
                      <input type="number" value={newDevice.port} onChange={e => setNewDevice(p => ({ ...p, port: parseInt(e.target.value) || 830 }))} style={{ ...inputStyle, fontSize: 11, padding: '4px 8px' }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>Username *</label>
                      <input type="text" value={newDevice.username} onChange={e => setNewDevice(p => ({ ...p, username: e.target.value }))} placeholder="admin" style={{ ...inputStyle, fontSize: 11, padding: '4px 8px' }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>Password</label>
                      <input type="password" value={newDevice.password} onChange={e => setNewDevice(p => ({ ...p, password: e.target.value }))} style={{ ...inputStyle, fontSize: 11, padding: '4px 8px' }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>SSH Key Path</label>
                      <input type="text" value={newDevice.ssh_key} onChange={e => setNewDevice(p => ({ ...p, ssh_key: e.target.value }))} placeholder="~/.ssh/id_rsa" style={{ ...inputStyle, fontSize: 11, padding: '4px 8px' }} />
                    </div>
                    <div style={{ gridColumn: '1 / -1', display: 'flex', justifyContent: 'flex-end' }}>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={handleAddDevice}
                        disabled={!newDevice.name.trim() || !newDevice.host.trim() || !newDevice.username.trim()}
                        style={{ fontSize: 11 }}
                      >
                        Add Device
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Setup Guide */}
            <div style={{
              marginTop: 8, padding: 14, background: 'var(--bg-tertiary)',
              borderRadius: 'var(--radius)', border: '1px solid var(--border-color)',
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: 'var(--text-primary)' }}>
                Setup Guide
              </div>
              <div style={{ fontSize: 11, lineHeight: 1.7, color: 'var(--text-secondary)' }}>
                <div style={{ marginBottom: 8 }}>
                  <strong style={{ color: 'var(--text-primary)' }}>1. Install the PyEZ Bridge</strong>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, background: 'var(--bg-primary)', padding: '6px 10px', borderRadius: 'var(--radius)', marginTop: 4 }}>
                    cd tools/pyez-bridge<br />
                    pip install -r requirements.txt
                  </div>
                </div>
                <div style={{ marginBottom: 8 }}>
                  <strong style={{ color: 'var(--text-primary)' }}>2. Add your SRX devices</strong> (choose one method)
                  <ul style={{ margin: '4px 0 0 16px', padding: 0, fontSize: 11 }}>
                    <li>Edit <code style={{ fontSize: 10 }}>tools/pyez-bridge/devices.yaml</code> directly, or</li>
                    <li>Use the "+ Add Device" form above after connecting</li>
                  </ul>
                </div>
                <div style={{ marginBottom: 8 }}>
                  <strong style={{ color: 'var(--text-primary)' }}>3. Start the bridge</strong>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, background: 'var(--bg-primary)', padding: '6px 10px', borderRadius: 'var(--radius)', marginTop: 4 }}>
                    python app.py
                  </div>
                  <div style={{ marginTop: 4 }}>Copy the access token printed at startup.</div>
                </div>
                <div>
                  <strong style={{ color: 'var(--text-primary)' }}>4. Connect</strong>
                  <span> — Enter <code style={{ fontSize: 10 }}>http://localhost:8830</code>, paste the access token, and click Test Connection.</span>
                </div>
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 10, borderTop: '1px solid var(--border-color)', paddingTop: 8 }}>
                <strong style={{ fontSize: 11, color: 'var(--text-primary)' }}>SRX Device Setup</strong>

                <div style={{ marginTop: 6, marginBottom: 6, lineHeight: 1.5 }}>
                  <strong>A. Generate an SSH key pair</strong> (on your workstation)
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, background: 'var(--bg-primary)', padding: '6px 10px', borderRadius: 'var(--radius)', lineHeight: 1.8 }}>
                  ssh-keygen -t rsa -b 4096 -f ~/.ssh/pyez_rsa -C "pyez-bridge"<br />
                  cat ~/.ssh/pyez_rsa.pub
                </div>
                <div style={{ marginTop: 2, lineHeight: 1.5 }}>
                  Press Enter for no passphrase (required for unattended automation). Copy the public key output.
                </div>

                <div style={{ marginTop: 8, marginBottom: 6, lineHeight: 1.5 }}>
                  <strong>B. Configure the SRX</strong> (in configuration mode)
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, background: 'var(--bg-primary)', padding: '6px 10px', borderRadius: 'var(--radius)', lineHeight: 1.8 }}>
                  set system services netconf ssh<br />
                  set system services netconf rfc-compliant<br />
                  set system login user <em style={{ color: 'var(--accent)' }}>pyez</em> class super-user<br />
                  set system login user <em style={{ color: 'var(--accent)' }}>pyez</em> authentication ssh-rsa "<em style={{ color: 'var(--accent)' }}>paste-public-key-here</em>"<br />
                  commit
                </div>
                <div style={{ marginTop: 2, lineHeight: 1.5 }}>
                  Creates a dedicated NETCONF user. Use <strong>super-user</strong> class for full commit access, or <strong>read-only</strong> for diff/check only.
                </div>

                <div style={{ marginTop: 8, marginBottom: 6, lineHeight: 1.5 }}>
                  <strong>C. Verify connectivity</strong> (from your workstation)
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, background: 'var(--bg-primary)', padding: '6px 10px', borderRadius: 'var(--radius)', lineHeight: 1.8 }}>
                  ssh -i ~/.ssh/pyez_rsa <em style={{ color: 'var(--accent)' }}>pyez</em>@<em style={{ color: 'var(--accent)' }}>device-ip</em> -p 830 -s netconf
                </div>
                <div style={{ marginTop: 2, lineHeight: 1.5 }}>
                  You should see an XML <code style={{ fontSize: 9 }}>&lt;hello&gt;</code> response. Press Ctrl+C to exit.
                  Then reference the private key path in the device config above (SSH Key Path: <code style={{ fontSize: 9 }}>~/.ssh/pyez_rsa</code>).
                </div>

                <div style={{ marginTop: 8, padding: '4px 0', lineHeight: 1.5 }}>
                  <strong>Password auth alternative:</strong> Skip step A. On the SRX, replace the ssh-rsa line with:<br />
                  <code style={{ fontSize: 9 }}>set system login user pyez authentication plain-text-password</code> and enter a password at the prompt.
                  Then use the Password field above instead of SSH Key Path.
                </div>
              </div>
            </div>
          </>
        )}

        {activeTab === 'llm' && (
        <>
        {/* Provider selector */}
        <SettingsField label="Provider">
          <select
            value={provider}
            onChange={(e) => handleProviderChange(e.target.value)}
            style={selectStyle}
          >
            {availableProviders.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          {localOnly && (
            <div style={{ fontSize: '10px', color: 'var(--warning)', marginTop: '4px' }}>
              Cloud LLM providers disabled per your risk acceptance choice.
            </div>
          )}
        </SettingsField>

        {/* API Key (not shown for local providers) */}
        {!['ollama', 'lmstudio'].includes(provider) && (
          <SettingsField label="API Key">
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Enter your API key..."
              style={inputStyle}
            />
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Stored in browser localStorage only — never sent to our server.
            </div>
          </SettingsField>
        )}

        {/* Base URL (for local/custom providers) */}
        {['ollama', 'lmstudio', 'custom'].includes(provider) && (
          <SettingsField label="Base URL">
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://localhost:11434"
              style={inputStyle}
            />
          </SettingsField>
        )}

        {/* Model */}
        <SettingsField label="Model">
          {(() => {
            const providerData = PROVIDERS.find(p => p.id === provider);
            const modelList = providerData?.models || [];
            // Providers with no preset list (Ollama, LM Studio, Custom) get a plain text box.
            if (modelList.length === 0) {
              return (
                <input
                  type="text"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder="Model name..."
                  style={inputStyle}
                />
              );
            }
            // Preset providers: dropdown plus a "Custom / Other…" escape hatch so
            // users can type a model that isn't listed yet (e.g. an upcoming release).
            const isKnownModel = modelList.some(m => m.id === model);
            return (
              <>
                <select
                  value={isKnownModel ? model : '__custom__'}
                  onChange={(e) => setModel(e.target.value === '__custom__' ? '' : e.target.value)}
                  style={selectStyle}
                >
                  {modelList.map(m => (
                    <option key={m.id} value={m.id}>{m.name}</option>
                  ))}
                  <option value="__custom__">Custom / Other…</option>
                </select>
                {!isKnownModel && (
                  <input
                    type="text"
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    placeholder="Enter model name (e.g. a newly released model)…"
                    style={{ ...inputStyle, marginTop: 6 }}
                  />
                )}
              </>
            );
          })()}
        </SettingsField>

        {/* Temperature */}
        <SettingsField label={`Temperature: ${temperature}`}>
          <input
            type="range"
            min="0"
            max="1"
            step="0.1"
            value={temperature}
            onChange={(e) => setTemperature(parseFloat(e.target.value))}
            style={{ width: '100%' }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)' }}>
            <span>Precise (0.0)</span>
            <span>Creative (1.0)</span>
          </div>
        </SettingsField>

        {/* System Prompts — 3 sub-tabs */}
        <SettingsField label="System Prompts">
          <div style={{ display: 'flex', gap: 0, marginBottom: 8, borderBottom: '1px solid var(--border-color)' }}>
            {[
              { id: 'fullReview', label: 'Translate Ruleset LLM Instructions' },
              { id: 'greenfield', label: 'Greenfield Interview' },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setPromptSubTab(tab.id)}
                style={{
                  padding: '6px 12px', background: 'none', border: 'none', cursor: 'pointer',
                  fontSize: 11, fontWeight: 500,
                  color: promptSubTab === tab.id ? 'var(--accent)' : 'var(--text-muted)',
                  borderBottom: promptSubTab === tab.id ? '2px solid var(--accent)' : '2px solid transparent',
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {promptSubTab === 'fullReview' && (
            <>
              <div style={{ marginBottom: 8 }}>
                <select
                  value={vendorPromptSelection}
                  onChange={(e) => setVendorPromptSelection(e.target.value)}
                  style={{ ...selectStyle, fontSize: 11 }}
                >
                  {['', ...VENDOR_PROMPT_KEYS].map(v => (
                    <option key={v} value={v}>{VENDOR_LABELS[v] || v}</option>
                  ))}
                </select>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                  {vendorPromptSelection
                    ? `Editing vendor-specific prompt for ${VENDOR_LABELS[vendorPromptSelection]}. Auto-selected at translation time.`
                    : 'Default prompt used when no vendor-specific prompt exists. Select a vendor to edit its prompt.'}
                </div>
              </div>
              {vendorPromptSelection === '' ? (
                <>
                  <textarea
                    value={fullReviewSystemPrompt}
                    onChange={(e) => setFullReviewSystemPrompt(e.target.value)}
                    style={promptTextareaStyle}
                  />
                  <PromptFooter
                    length={fullReviewSystemPrompt.length}
                    onReset={() => setFullReviewSystemPrompt(DEFAULT_FULL_REVIEW_SYSTEM_PROMPT)}
                  />
                </>
              ) : (
                <>
                  <textarea
                    value={vendorPrompts[vendorPromptSelection] || loadVendorTranslatePrompt(vendorPromptSelection) || '(No prompt file found for this vendor)'}
                    onChange={(e) => setVendorPrompts(prev => ({ ...prev, [vendorPromptSelection]: e.target.value }))}
                    style={promptTextareaStyle}
                  />
                  <PromptFooter
                    length={(vendorPrompts[vendorPromptSelection] || loadVendorTranslatePrompt(vendorPromptSelection) || '').length}
                    onReset={() => setVendorPrompts(prev => {
                      const next = { ...prev };
                      delete next[vendorPromptSelection];
                      return next;
                    })}
                  />
                </>
              )}
            </>
          )}

          {promptSubTab === 'greenfield' && (
            <>
              <textarea
                value={greenfieldSystemPrompt}
                onChange={(e) => setGreenfieldSystemPrompt(e.target.value)}
                style={promptTextareaStyle}
              />
              <PromptFooter
                length={greenfieldSystemPrompt.length}
                onReset={() => setGreenfieldSystemPrompt(DEFAULT_GREENFIELD_SYSTEM_PROMPT)}
              />
            </>
          )}
        </SettingsField>
        </>
        )}

        {/* Buttons */}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '20px', alignItems: 'center' }}>
          {activeTab === 'llm' && (
            <button
              className="btn btn-secondary"
              onClick={() => { onClose(); uiDispatch({ type: 'SET_LLM_RISK_ACCEPTANCE', value: null }); }}
              style={{ marginRight: 'auto', fontSize: 11, color: 'var(--warning)' }}
              title="Re-evaluate your LLM risk acceptance choice"
            >
              Reconsider Risk
            </button>
          )}
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={handleSave}>Save Settings</button>
        </div>
      </div>
    </div>
  );
}

function SettingsField({ label, children }) {
  return (
    <div style={{ marginBottom: '16px' }}>
      <label style={{
        display: 'block',
        fontSize: '12px',
        fontWeight: '500',
        color: 'var(--text-secondary)',
        marginBottom: '6px',
      }}>
        {label}
      </label>
      {children}
    </div>
  );
}

const inputStyle = {
  width: '100%',
  padding: '8px 12px',
  background: 'var(--bg-tertiary)',
  border: '1px solid var(--border-color)',
  borderRadius: 'var(--radius)',
  color: 'var(--text-primary)',
  fontSize: '13px',
  outline: 'none',
};

const selectStyle = {
  ...inputStyle,
  cursor: 'pointer',
};

const promptTextareaStyle = {
  ...inputStyle,
  minHeight: '160px',
  maxHeight: '300px',
  resize: 'vertical',
  fontFamily: 'var(--font-mono)',
  fontSize: '11px',
  lineHeight: '1.5',
};

function PromptFooter({ length, onReset }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
      <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
        {length} characters
      </span>
      <button
        className="btn btn-secondary btn-sm"
        onClick={onReset}
        style={{ fontSize: '10px', padding: '2px 8px' }}
      >
        Reset to Default
      </button>
    </div>
  );
}

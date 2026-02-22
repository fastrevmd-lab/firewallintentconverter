/**
 * LLMSettings Component
 *
 * Modal dialog for configuring the LLM provider used by the interview engine.
 * Includes provider selection, API key, model, temperature, and editable system prompt.
 *
 * Settings are stored in localStorage only — API keys never leave the browser.
 */
import React, { useState, useEffect } from 'react';
import { DEFAULT_SYSTEM_PROMPT } from '../utils/llm-client.js';

const PROVIDERS = [
  { id: 'claude', name: 'Claude (Anthropic)', defaultModel: 'claude-sonnet-4-6' },
  { id: 'openai', name: 'OpenAI', defaultModel: 'gpt-4o' },
  { id: 'ollama', name: 'Ollama (Local)', defaultModel: 'llama3' },
  { id: 'lmstudio', name: 'LM Studio (Local)', defaultModel: 'local-model' },
  { id: 'custom', name: 'Custom OpenAI-Compatible', defaultModel: '' },
];

export default function LLMSettings({ onClose, initialTab }) {
  const [activeTab, setActiveTab] = useState(initialTab || 'llm');
  const [provider, setProvider] = useState('claude');
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState('claude-sonnet-4-6');
  const [baseUrl, setBaseUrl] = useState('');
  const [temperature, setTemperature] = useState(0.2);
  const [systemPrompt, setSystemPrompt] = useState(DEFAULT_SYSTEM_PROMPT);

  // MCP state
  const [mcpUrl, setMcpUrl] = useState('');
  const [mcpConnected, setMcpConnected] = useState(false);
  const [mcpTesting, setMcpTesting] = useState(false);
  const [mcpTestResult, setMcpTestResult] = useState('');
  const [mcpDevices, setMcpDevices] = useState([]);

  // Load saved settings from localStorage on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem('llm-settings');
      if (saved) {
        const settings = JSON.parse(saved);
        setProvider(settings.provider || 'claude');
        setApiKey(settings.apiKey || '');
        setModel(settings.model || 'claude-sonnet-4-6');
        setBaseUrl(settings.baseUrl || '');
        setTemperature(settings.temperature ?? 0.2);
        setSystemPrompt(settings.systemPrompt || DEFAULT_SYSTEM_PROMPT);
      }
    } catch {
      // Ignore parse errors
    }
    try {
      const mcpSaved = localStorage.getItem('mcp-settings');
      if (mcpSaved) {
        const mcpSettings = JSON.parse(mcpSaved);
        setMcpUrl(mcpSettings.url || '');
      }
    } catch { /* ignore */ }
  }, []);

  /** Save settings to localStorage */
  const handleSave = () => {
    const settings = { provider, apiKey, model, baseUrl, temperature, systemPrompt };
    localStorage.setItem('llm-settings', JSON.stringify(settings));
    const mcpSettings = { url: mcpUrl };
    localStorage.setItem('mcp-settings', JSON.stringify(mcpSettings));
    onClose();
  };

  /** Test MCP connection */
  const handleMcpTest = async () => {
    if (!mcpUrl.trim()) {
      setMcpTestResult('Enter an MCP server URL first.');
      return;
    }
    setMcpTesting(true);
    setMcpTestResult('');
    setMcpDevices([]);
    try {
      const resp = await fetch(mcpUrl.replace(/\/$/, '') + '/health', { method: 'GET' });
      if (resp.ok) {
        setMcpConnected(true);
        setMcpTestResult('Connected successfully.');
        // Try to list devices
        try {
          const devResp = await fetch(mcpUrl.replace(/\/$/, '') + '/devices', { method: 'GET' });
          if (devResp.ok) {
            const devData = await devResp.json();
            setMcpDevices(Array.isArray(devData) ? devData : devData.devices || []);
          }
        } catch { /* devices endpoint optional */ }
      } else {
        setMcpConnected(false);
        setMcpTestResult(`Connection failed: HTTP ${resp.status}`);
      }
    } catch (err) {
      setMcpConnected(false);
      setMcpTestResult(`Connection failed: ${err.message}`);
    } finally {
      setMcpTesting(false);
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
            MCP Connection
          </button>
        </div>

        {activeTab === 'mcp' && (
          <>
            <SettingsField label="MCP Server URL">
              <input
                type="text"
                value={mcpUrl}
                onChange={(e) => setMcpUrl(e.target.value)}
                placeholder="http://localhost:8080"
                style={inputStyle}
              />
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                URL of the MCP server that connects to your SRX devices.
              </div>
            </SettingsField>

            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 16 }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={handleMcpTest}
                disabled={mcpTesting}
              >
                {mcpTesting ? 'Testing...' : 'Test Connection'}
              </button>
              {mcpTestResult && (
                <span style={{
                  fontSize: 11,
                  color: mcpConnected ? 'var(--success)' : 'var(--error)',
                }}>
                  {mcpTestResult}
                </span>
              )}
            </div>

            {/* Connected SRX devices list */}
            <SettingsField label="Connected SRX Devices">
              {mcpDevices.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {mcpDevices.map((dev, i) => (
                    <div key={i} style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '6px 10px', background: 'var(--bg-tertiary)',
                      borderRadius: 'var(--radius)', fontSize: 12,
                    }}>
                      <span style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: dev.status === 'connected' ? 'var(--success)' : 'var(--text-muted)',
                      }} />
                      <span style={{ fontWeight: 500 }}>{dev.hostname || dev.name || dev.ip || `Device ${i + 1}`}</span>
                      {dev.model && <span style={{ color: 'var(--text-muted)' }}>({dev.model})</span>}
                      {dev.ip && <span style={{ color: 'var(--text-muted)', marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{dev.ip}</span>}
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{
                  padding: '16px', textAlign: 'center', background: 'var(--bg-tertiary)',
                  borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--text-muted)',
                }}>
                  {mcpConnected ? 'No devices reported by MCP server.' : 'Test connection to discover devices.'}
                </div>
              )}
            </SettingsField>
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
            {PROVIDERS.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
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
          <input
            type="text"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder="Model name..."
            style={inputStyle}
          />
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

        {/* System Prompt */}
        <SettingsField label="Review System Prompt">
          <textarea
            value={systemPrompt}
            onChange={(e) => setSystemPrompt(e.target.value)}
            style={{
              ...inputStyle,
              minHeight: '160px',
              maxHeight: '300px',
              resize: 'vertical',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              lineHeight: '1.5',
            }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
            <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
              {systemPrompt.length} characters
            </span>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setSystemPrompt(DEFAULT_SYSTEM_PROMPT)}
              style={{ fontSize: '10px', padding: '2px 8px' }}
            >
              Reset to Default
            </button>
          </div>
        </SettingsField>
        </>
        )}

        {/* Buttons */}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '20px' }}>
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

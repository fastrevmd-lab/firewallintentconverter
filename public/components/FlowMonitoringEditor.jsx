/**
 * FlowMonitoringEditor Component
 *
 * Card-based editor for flow monitoring / NetFlow / jFlow configuration.
 * Sections: Collectors, Sampling, Templates.
 */
import React from 'react';

export default function FlowMonitoringEditor({ flowConfig, onFlowUpdate, viewMode }) {
  const config = flowConfig || { collectors: [], sampling: { input_rate: 1000, run_length: 0, interfaces: [] }, templates: [] };

  const update = (patch) => onFlowUpdate({ ...config, ...patch });

  // --- Collector handlers ---
  const handleCollectorChange = (index, field, value) => {
    const updated = config.collectors.map((c, i) => i === index ? { ...c, [field]: value } : c);
    update({ collectors: updated });
  };

  const handleAddCollector = () => {
    update({ collectors: [...config.collectors, { address: '', port: 2055, protocol: 'ipfix', source_address: '' }] });
  };

  const handleDeleteCollector = (index) => {
    update({ collectors: config.collectors.filter((_, i) => i !== index) });
  };

  // --- Sampling handlers ---
  const handleSamplingChange = (field, value) => {
    update({ sampling: { ...config.sampling, [field]: value } });
  };

  const handleAddSamplingInterface = () => {
    const name = prompt('Interface name (e.g. ge-0/0/0.0):');
    if (!name) return;
    update({ sampling: { ...config.sampling, interfaces: [...(config.sampling.interfaces || []), name] } });
  };

  const handleRemoveSamplingInterface = (index) => {
    update({ sampling: { ...config.sampling, interfaces: (config.sampling.interfaces || []).filter((_, i) => i !== index) } });
  };

  // --- Template handlers ---
  const handleTemplateChange = (index, field, value) => {
    const updated = config.templates.map((t, i) => i === index ? { ...t, [field]: value } : t);
    update({ templates: updated });
  };

  const handleAddTemplate = () => {
    update({ templates: [...config.templates, { name: `flow-tpl-${config.templates.length + 1}`, flow_type: 'ipv4', active_timeout: 60, refresh_rate: 1000 }] });
  };

  const handleDeleteTemplate = (index) => {
    update({ templates: config.templates.filter((_, i) => i !== index) });
  };

  const isEmpty = config.collectors.length === 0 && config.templates.length === 0;

  return (
    <div style={{ padding: '16px 20px', maxWidth: 900 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Flow Monitoring / NetFlow</h3>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          SRX Inline Jflow
        </span>
      </div>

      {isEmpty && (
        <div style={{ textAlign: 'center', padding: '32px 0', color: 'var(--text-muted)' }}>
          <p style={{ marginBottom: 12 }}>No flow monitoring configuration detected.</p>
          <button className="btn btn-primary btn-sm" onClick={handleAddCollector}>
            Add Collector
          </button>
        </div>
      )}

      {/* ── Collectors Section ── */}
      {config.collectors.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <h4 style={{ margin: 0, fontSize: 13, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)' }}>
              Collectors ({config.collectors.length})
            </h4>
            <button className="btn btn-sm" onClick={handleAddCollector} style={{ fontSize: 12 }}>+ Add</button>
          </div>
          {config.collectors.map((collector, i) => (
            <div key={i} className="card" style={{ padding: 12, marginBottom: 8, border: '1px solid var(--border-color)', borderRadius: 6 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px 120px 1fr auto', gap: 8, alignItems: 'end' }}>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Address
                  <input type="text" value={collector.address} onChange={(e) => handleCollectorChange(i, 'address', e.target.value)}
                    placeholder="10.0.0.1" style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }} />
                </label>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Port
                  <input type="number" value={collector.port} onChange={(e) => handleCollectorChange(i, 'port', parseInt(e.target.value) || 2055)}
                    style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }} />
                </label>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Protocol
                  <select value={collector.protocol || 'ipfix'} onChange={(e) => handleCollectorChange(i, 'protocol', e.target.value)}
                    style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }}>
                    <option value="ipfix">IPFIX</option>
                    <option value="netflow-v9">NetFlow v9</option>
                    <option value="sflow">sFlow</option>
                  </select>
                </label>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Source Address
                  <input type="text" value={collector.source_address || ''} onChange={(e) => handleCollectorChange(i, 'source_address', e.target.value)}
                    placeholder="lo0 IP" style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }} />
                </label>
                <button onClick={() => handleDeleteCollector(i)} title="Remove collector"
                  style={{ padding: '4px 8px', fontSize: 12, color: 'var(--color-danger)', background: 'none', border: 'none', cursor: 'pointer', alignSelf: 'end' }}>
                  Del
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Sampling Section ── */}
      {(config.collectors.length > 0 || (config.sampling.interfaces || []).length > 0) && (
        <div style={{ marginBottom: 20 }}>
          <h4 style={{ margin: '0 0 8px', fontSize: 13, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)' }}>
            Sampling
          </h4>
          <div className="card" style={{ padding: 12, border: '1px solid var(--border-color)', borderRadius: 6 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
              <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Input Rate (1:N)
                <input type="number" value={config.sampling.input_rate || 1000} onChange={(e) => handleSamplingChange('input_rate', parseInt(e.target.value) || 1000)}
                  style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }} />
              </label>
              <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Run Length
                <input type="number" value={config.sampling.run_length || 0} onChange={(e) => handleSamplingChange('run_length', parseInt(e.target.value) || 0)}
                  style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }} />
              </label>
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Sampled Interfaces</span>
                <button className="btn btn-sm" onClick={handleAddSamplingInterface} style={{ fontSize: 11, padding: '2px 6px' }}>+ Add</button>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {(config.sampling.interfaces || []).map((iface, i) => (
                  <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', fontSize: 12, background: 'var(--bg-hover)', borderRadius: 12, border: '1px solid var(--border-color)' }}>
                    {iface}
                    <button onClick={() => handleRemoveSamplingInterface(i)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 10, padding: 0 }}>x</button>
                  </span>
                ))}
                {(config.sampling.interfaces || []).length === 0 && (
                  <span style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>None — sampling will apply globally</span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Templates Section ── */}
      {(config.collectors.length > 0 || config.templates.length > 0) && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <h4 style={{ margin: 0, fontSize: 13, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)' }}>
              Templates ({config.templates.length})
            </h4>
            <button className="btn btn-sm" onClick={handleAddTemplate} style={{ fontSize: 12 }}>+ Add</button>
          </div>
          {config.templates.map((tpl, i) => (
            <div key={i} className="card" style={{ padding: 12, marginBottom: 8, border: '1px solid var(--border-color)', borderRadius: 6 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px 120px 120px auto', gap: 8, alignItems: 'end' }}>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Name
                  <input type="text" value={tpl.name} onChange={(e) => handleTemplateChange(i, 'name', e.target.value)}
                    style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }} />
                </label>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Flow Type
                  <select value={tpl.flow_type || 'ipv4'} onChange={(e) => handleTemplateChange(i, 'flow_type', e.target.value)}
                    style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }}>
                    <option value="ipv4">IPv4</option>
                    <option value="ipv6">IPv6</option>
                  </select>
                </label>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Active Timeout
                  <input type="number" value={tpl.active_timeout || 60} onChange={(e) => handleTemplateChange(i, 'active_timeout', parseInt(e.target.value) || 60)}
                    style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }} />
                </label>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Refresh Rate
                  <input type="number" value={tpl.refresh_rate || 1000} onChange={(e) => handleTemplateChange(i, 'refresh_rate', parseInt(e.target.value) || 1000)}
                    style={{ width: '100%', marginTop: 2, padding: '4px 6px', fontSize: 13, border: '1px solid var(--border-color)', borderRadius: 4, background: 'var(--bg-input)' }} />
                </label>
                <button onClick={() => handleDeleteTemplate(i)} title="Remove template"
                  style={{ padding: '4px 8px', fontSize: 12, color: 'var(--color-danger)', background: 'none', border: 'none', cursor: 'pointer', alignSelf: 'end' }}>
                  Del
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

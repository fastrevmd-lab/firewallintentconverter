import React from 'react';
import { generateReportHtml } from '../utils/report-generator.js';

export default function ReportModal({ data, onClose }) {
  const ic = data?.intermediateConfig;
  const policies = Array.isArray(ic?.security_policies) ? ic.security_policies : [];
  const natRules = Array.isArray(ic?.nat_rules) ? ic.nat_rules : [];
  const addressObjects = Array.isArray(ic?.address_objects) ? ic.address_objects : [];
  const serviceObjects = Array.isArray(ic?.service_objects) ? ic.service_objects : [];
  const zones = Array.isArray(ic?.zones) ? ic.zones : [];
  const interfaces = Array.isArray(ic?.interfaces) ? ic.interfaces : [];
  const parseWarnings = Array.isArray(data?.parseWarnings) ? data.parseWarnings : [];
  const convertWarnings = Array.isArray(data?.convertWarnings) ? data.convertWarnings : [];
  const totalWarnings = parseWarnings.length + convertWarnings.length;

  const handleDownload = () => {
    const html = generateReportHtml(data);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `migration-report-${data?.siteName || 'untitled'}-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 480 }}>
        <div className="modal-header">
          <h2>Migration Report</h2>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body" style={{ padding: '16px 20px' }}>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12 }}>
            Generate a self-contained HTML report of this migration.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
            <Stat label="Zones" value={zones.length} />
            <Stat label="Interfaces" value={interfaces.length} />
            <Stat label="Policies" value={policies.length} />
            <Stat label="NAT Rules" value={natRules.length} />
            <Stat label="Addresses" value={addressObjects.length} />
            <Stat label="Services" value={serviceObjects.length} />
          </div>
          {totalWarnings > 0 && (
            <div style={{ marginTop: 10, fontSize: 12, color: 'var(--warning-color, #f1c40f)' }}>
              {totalWarnings} warning{totalWarnings !== 1 ? 's' : ''} will be included
            </div>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={handleDownload}>
            Generate &amp; Download
          </button>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div style={{
      background: 'var(--bg-tertiary, #16213e)', padding: '8px 10px', borderRadius: 5, textAlign: 'center',
    }}>
      <div style={{ fontSize: 18, fontWeight: 700 }}>{value}</div>
      <div style={{ fontSize: 10, color: 'var(--text-muted, #888)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</div>
    </div>
  );
}

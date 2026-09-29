/**
 * LLMRiskDisclaimer — Startup warning about risks of sharing firewall configs with LLMs.
 * Shows on first launch, persists acceptance in localStorage.
 */
import React from 'react';

const RISK_SECTIONS = [
  {
    title: 'Data Retention & Training Exposure',
    body: 'Public LLMs (ChatGPT, Claude.ai, Gemini, etc.) often store your inputs and may use them for training or fine-tuning. If your config is ingested into training data, another user querying the same model could inadvertently receive details about your infrastructure. This is the highest risk for cloud-hosted LLMs.',
    icon: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15v-2h2v2h-2zm0-4V7h2v6h-2z',
  },
  {
    title: 'Network Topology Disclosure',
    body: 'A firewall config reveals your full internal network topology \u2014 IP schemes, VLAN segmentation, interface names, and routing relationships. An attacker who obtains this information gains a significant advantage in understanding how to move laterally if they breach any perimeter.',
    icon: 'M15 4H5v16h14V8h-4V4zM3 2.992C3 2.444 3.447 2 3.999 2H16l5 5v13.993A1 1 0 0120.007 22H3.993A1 1 0 013 21.008V2.992z',
  },
  {
    title: 'Attack Surface Mapping',
    body: 'Your policy rules explicitly show what ports, protocols, and services are permitted \u2014 essentially a ready-made vulnerability map. Overly permissive or misconfigured rules are already a compliance risk; exposing them externally compounds that risk significantly.',
    icon: 'M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm-1-11v6h2v-6h-2zm0-4v2h2V7h-2z',
  },
  {
    title: 'Credential and Secret Exposure',
    body: 'Many configs contain embedded secrets \u2014 VPN pre-shared keys, SNMP community strings, API tokens, local user hashes, or certificate private keys \u2014 that grant direct access to your infrastructure if leaked.',
    icon: 'M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z',
  },
  {
    title: 'Compliance and Regulatory Risk',
    body: 'Sharing configs containing internal IP schemes, user account data, or network segmentation details tied to regulated environments (PCI, HIPAA, FedRAMP) could constitute a compliance violation regardless of whether a breach occurs.',
    icon: 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z',
  },
];

export default function LLMRiskDisclaimer({ onAcceptAll, onAcceptLocalOnly, onDeterministicMode, onReject }) {
  return (
    <div className="risk-disclaimer-overlay">
      <div className="risk-disclaimer-content">
        <div className="risk-disclaimer-header">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" strokeWidth="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          <h2>Risks of Sharing Firewall Configs with an LLM</h2>
        </div>

        <p className="risk-disclaimer-intro">
          Sharing firewall configurations with an LLM carries real risk because the config is essentially
          a roadmap of your entire network's security posture &mdash; it reveals what's protected, what's not,
          and how to navigate around defenses. Here's a comprehensive breakdown of the risks and what to sanitize.
        </p>

        <div className="risk-sections">
          {RISK_SECTIONS.map((section, i) => (
            <div key={i} className="risk-section">
              <div className="risk-section-header">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="var(--warning)" opacity="0.7">
                  <path d={section.icon} />
                </svg>
                <h4>{section.title}</h4>
              </div>
              <p>{section.body}</p>
            </div>
          ))}
        </div>

        <div className="sanitize-info-box">
          <div className="sanitize-info-header">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--success)" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <h4>Built-in Sanitization Tool</h4>
          </div>
          <p>
            Before sending a configuration to an LLM (for translation or AI grouping), this tool warns you if it
            hasn't been sanitized and offers a one-click <strong>Sanitize Configuration</strong> action that replaces
            sensitive data with safe placeholders. Sanitizing is not automatic and not enforced — you can dismiss the
            warning and proceed with an unsanitized config. The tool detects and can redact these categories:
          </p>
          <ul>
            <li><strong>Credentials &amp; Secrets</strong> &mdash; Pre-shared keys, SNMP community strings, passwords/hashes, API keys, certificate private keys, RADIUS/TACACS shared secrets</li>
            <li><strong>Network Identifiers</strong> &mdash; Public IP addresses, server hostnames/FQDNs (LDAP, RADIUS, NTP, DNS), BGP AS numbers</li>
            <li><strong>Authentication</strong> &mdash; Usernames, LDAP bind DNs, RADIUS/TACACS usernames</li>
          </ul>
          <p className="sanitize-info-note">
            <strong>Manual review recommended:</strong> Internal RFC-1918 subnets, zone names, rule comments/descriptions,
            VLAN IDs, and interface descriptions are preserved for config functionality but may contain
            sensitive organizational context. Review these before sharing with a public LLM.
          </p>
        </div>

        <div className="deterministic-info-box" style={{
          margin: '16px 0', padding: '12px 16px', borderRadius: 8,
          border: '1px solid var(--success)', background: 'var(--bg-secondary)',
        }}>
          <h4 style={{ margin: '0 0 6px', color: 'var(--success)' }}>No AI Mode Available</h4>
          <p style={{ margin: 0, fontSize: 13, color: 'var(--text-muted)' }}>
            If your security policy prohibits sending firewall data to any LLM provider,
            you can use <strong>Deterministic Mode</strong>. This disables ALL AI features and uses
            built-in mapping tables and analysis algorithms instead. No data leaves your browser.
          </p>
        </div>

        <div className="risk-disclaimer-actions">
          <button className="btn risk-btn-accept" onClick={onAcceptAll}>
            Accept this Risk
          </button>
          <button className="btn risk-btn-local" onClick={onAcceptLocalOnly}>
            Accept only for Local LLM
          </button>
          <button className="btn risk-btn-deterministic" onClick={onDeterministicMode} style={{
            background: 'var(--success)', color: '#fff', border: 'none',
          }}>
            No AI Mode (Deterministic Only)
          </button>
          <button className="btn risk-btn-reject" onClick={onReject}>
            Reject due to Risk
          </button>
        </div>
      </div>
    </div>
  );
}

export function RejectedScreen({ onReconsider }) {
  return (
    <div className="rejected-screen">
      <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" strokeWidth="1.5" opacity="0.6">
        <circle cx="12" cy="12" r="10" />
        <line x1="15" y1="9" x2="9" y2="15" />
        <line x1="9" y1="9" x2="15" y2="15" />
      </svg>
      <h2>Access Restricted</h2>
      <p>
        You have rejected the LLM risk disclaimer. This application requires acknowledgment
        of the risks associated with sharing firewall configurations with LLMs before it can be used.
      </p>
      <button className="btn btn-secondary" onClick={onReconsider}>
        Reconsider
      </button>
    </div>
  );
}

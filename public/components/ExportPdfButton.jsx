import React from 'react';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import { useConversionContext } from '../contexts/ConversionContext.jsx';
import { generateFullPdfHtml } from '../utils/pdf-report-generator.js';
import { loadLLMSettings } from '../utils/llm-settings.js';
import { PANOS_MODELS, SRX_MODELS } from '../data/hardware-db.js';

/**
 * "Export All to PDF" button — reads full app state from contexts and opens
 * a print-friendly HTML document in a new window for Save-as-PDF.
 */
export default function ExportPdfButton() {
  const { state: cfg } = useConfigContext();
  const { state: conv } = useConversionContext();

  const disabled = !cfg.intermediateConfig || !conv.srxOutput;

  const handleExport = () => {
    // Resolve model metadata from hardware-db
    const allSourceModels = { ...PANOS_MODELS, ...SRX_MODELS };
    const sourceModelData = cfg.sourceModel ? allSourceModels[cfg.sourceModel] || null : null;
    const targetModelData = cfg.targetModel ? SRX_MODELS[cfg.targetModel] || null : null;

    // Detect if LLM is local (ollama/lmstudio)
    let isLocalLLM = false;
    try {
      isLocalLLM = ['ollama', 'lmstudio'].includes(loadLLMSettings().provider);
    } catch { /* settings unavailable: use the non-local default */ }

    const html = generateFullPdfHtml({
      configText: cfg.configText,
      sourceVendor: cfg.sourceVendor,
      sourceModel: cfg.sourceModel,
      targetModel: cfg.targetModel,
      siteName: cfg.siteName,
      siteGroup: cfg.siteGroup,
      intermediateConfig: cfg.intermediateConfig,
      srxTranslatedPolicies: cfg.srxTranslatedPolicies,
      sectionAcceptance: cfg.sectionAcceptance,
      interfaceMappings: cfg.interfaceMappings,
      srxOutput: conv.srxOutput,
      outputFormat: conv.outputFormat,
      parseWarnings: cfg.parseWarnings,
      convertWarnings: conv.convertWarnings,
      conversionSummary: conv.conversionSummary,
      sourceModelData,
      targetModelData,
      isLocalLLM,
    });

    const win = window.open('', '_blank');
    if (!win) return; // popup blocked
    win.document.write(html);
    win.document.close();
  };

  return (
    <button
      className="btn btn-sm"
      onClick={handleExport}
      disabled={disabled}
      data-tooltip={disabled ? 'Convert config first' : 'Export full report as PDF'}
      data-tooltip-pos="bottom"
      style={{ flexShrink: 0, display: 'inline-flex', alignItems: 'center', gap: 5 }}
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="12" y1="18" x2="12" y2="12" />
        <polyline points="9 15 12 18 15 15" />
      </svg>
      Export PDF
    </button>
  );
}

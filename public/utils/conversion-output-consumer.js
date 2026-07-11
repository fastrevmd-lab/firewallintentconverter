import { assertConversionOutput } from '../../src/conversion/conversion-output.js';

function inspectConversionOutput(output) {
  const canonical = assertConversionOutput(output);
  const text = canonical.format === 'set'
    ? canonical.commands.join('\n')
    : canonical.xml;

  return { canonical, text };
}

export function getConversionOutputPresentation(output) {
  const { canonical, text } = inspectConversionOutput(output);
  const isXml = canonical.format === 'xml';

  return {
    text,
    format: canonical.format,
    extension: isXml ? 'xml' : 'txt',
    mimeType: isXml ? 'application/xml' : 'text/plain',
    renderMode: canonical.format,
    setExportEligible: !isXml,
  };
}

export function getSetExportCommands(output) {
  const { canonical } = inspectConversionOutput(output);
  return canonical.format === 'set' ? [...canonical.commands] : null;
}

export function buildDeviceLoadPayload(output, restoreText = text => text) {
  const { canonical, text } = inspectConversionOutput(output);
  let config = restoreText(text);

  if (canonical.format === 'set') {
    config = config
      .split('\n')
      .filter(line => {
        const trimmed = line.trim();
        return trimmed && !trimmed.startsWith('#');
      })
      .join('\n');
  }

  return { config, format: canonical.format };
}

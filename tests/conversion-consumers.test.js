import fs from 'node:fs';

import { describe, expect, it, vi } from 'vitest';

import { hasConversionOutput } from '../src/conversion/conversion-output.js';
import {
  buildDeviceLoadPayload,
  getConversionOutputPresentation,
  getSetExportCommands,
} from '../public/utils/conversion-output-consumer.js';

const read = relativePath => fs.readFileSync(new URL(`../${relativePath}`, import.meta.url), 'utf8');

const setOutput = {
  format: 'set',
  commands: [
    '# generated configuration',
    'set system host-name edge-1',
    '',
    'set system services ssh',
  ].filter(Boolean),
};

const xmlOutput = {
  format: 'xml',
  xml: '<configuration><system><host-name>edge-1</host-name></system></configuration>',
};

describe('canonical conversion output consumer behavior', () => {
  it('builds a Set device payload from one canonical output despite a conflicting former format hint', () => {
    const restoreText = vi.fn(text => text.replace('edge-1', 'edge-public'));

    const payload = buildDeviceLoadPayload(setOutput, restoreText, 'xml');

    expect(payload).toEqual({
      config: 'set system host-name edge-public\nset system services ssh',
      format: 'set',
    });
    expect(restoreText).toHaveBeenCalledOnce();
    expect(restoreText).toHaveBeenCalledWith(setOutput.commands.join('\n'));
  });

  it('builds an XML device payload with XML format despite a conflicting former format hint', () => {
    expect(buildDeviceLoadPayload(xmlOutput, text => text, 'set')).toEqual({
      config: xmlOutput.xml,
      format: 'xml',
    });
  });

  it.each([
    null,
    { format: 'set', commands: [] },
    { format: 'set', commands: ['set system host-name edge-1'], xml: '<configuration />' },
    { format: 'xml', xml: '<configuration />', commands: ['set system host-name edge-1'] },
  ])('rejects malformed device output before restoration or payload creation: %j', malformedOutput => {
    const restoreText = vi.fn(text => text);

    expect(() => buildDeviceLoadPayload(malformedOutput, restoreText, 'set')).toThrow();
    expect(restoreText).not.toHaveBeenCalled();
    expect(hasConversionOutput(malformedOutput)).toBe(false);
  });

  it.each([
    {
      output: setOutput,
      conflictingHint: 'xml',
      expected: {
        text: setOutput.commands.join('\n'),
        format: 'set',
        extension: 'txt',
        mimeType: 'text/plain',
        renderMode: 'set',
        setExportEligible: true,
      },
    },
    {
      output: xmlOutput,
      conflictingHint: 'set',
      expected: {
        text: xmlOutput.xml,
        format: 'xml',
        extension: 'xml',
        mimeType: 'application/xml',
        renderMode: 'xml',
        setExportEligible: false,
      },
    },
  ])('derives presentation only from canonical $output.format output', ({ output, conflictingHint, expected }) => {
    expect(getConversionOutputPresentation(output, conflictingHint)).toEqual(expected);
  });

  it('does not run Set-only command extraction for canonical XML', () => {
    // The core Set extractor throws for XML; a null result proves this adapter gates before extraction.
    expect(getSetExportCommands(xmlOutput, 'set')).toBeNull();
    expect(getSetExportCommands(setOutput, 'xml')).toEqual(setOutput.commands);
  });

  it('cannot produce presentation, push, or Set-export data from malformed output', () => {
    const malformedOutput = { format: 'xml', xml: '<configuration />', commands: ['set system host-name bypass'] };

    expect(hasConversionOutput(malformedOutput)).toBe(false);
    expect(() => getConversionOutputPresentation(malformedOutput, 'set')).toThrow();
    expect(() => buildDeviceLoadPayload(malformedOutput, text => text, 'set')).toThrow();
    expect(() => getSetExportCommands(malformedOutput, 'set')).toThrow();
  });
});

describe('canonical conversion output consumer wiring', () => {
  it('routes presentation and device payloads through the production adapter without stale format reads', () => {
    const outputSource = read('public/components/SRXOutput.jsx');
    const pushSource = read('public/hooks/usePush.js');

    expect(outputSource).toContain('getConversionOutputPresentation(output)');
    expect(outputSource).toContain('getSetExportCommands(output)');
    expect(outputSource).not.toMatch(/function SRXOutput\(\{[^}]*\bformat\b/);
    expect(pushSource).toMatch(/buildDeviceLoadPayload\(\s*srxOutput/);
    expect(pushSource).not.toContain('const { srxOutput, outputFormat } = convState');
    expect(pushSource).not.toContain('outputFormat ===');
  });

  it('keeps diff, PDF, report, workflow, and batch consumers on the canonical envelope', () => {
    expect(read('public/components/ConfigDiff.jsx')).toContain('getConversionOutputText(currentOutput)');
    expect(read('public/utils/pdf-report-generator.js')).toContain('getConversionOutputText(srxOutput)');
    expect(read('public/components/ConversionReport.jsx')).toContain('getSetCommands(srxOutput)');
    expect(read('public/components/layout/WorkflowStepper.jsx')).toContain('hasConversionOutput(srxOutput)');

    const batchSource = read('public/components/BatchMigrationPanel.jsx');
    expect(batchSource).toContain('getConversionOutputText(convertResult.output)');
    expect(batchSource).toContain('convertResult.output.warnings');
    expect(batchSource).not.toContain('(convertResult.commands || [])');
  });

  it('removes permissive output fallbacks from security-sensitive paths', () => {
    const combined = [
      read('public/components/SRXOutput.jsx'),
      read('public/hooks/usePush.js'),
      read('public/components/ConfigDiff.jsx'),
      read('public/utils/pdf-report-generator.js'),
    ].join('\n');

    expect(combined).not.toMatch(/srxOutput\?\.srxCommands|srxOutput\.srxCommands/);
    expect(combined).not.toContain("(srxOutput.commands || []).join('\\n')");
    expect(combined).not.toContain("output.xml || ''");
  });
});

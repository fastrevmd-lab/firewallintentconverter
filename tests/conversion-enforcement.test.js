import fs from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  filterEffectiveSetCommands,
  normalizeConversionOutput,
  replaceSetCommands,
} from '../src/conversion/conversion-output.js';
import { runValidation } from '../src/validators/srx-validation-engine.js';

const modelDb = {};
const capacityLimits = {};
const IDENTIFIER_MAPPINGS = { version: 1, entries: [] };
const intermediateConfig = {
  security_policies: [],
  zones: [],
  interfaces: [],
  address_objects: [],
};

describe('canonical license enforcement', () => {
  it('detects and removes the command that the former srxCommands typo skipped', () => {
    const output = normalizeConversionOutput({
      commands: [
        'set system host-name edge-1',
        'set services idp active-policy recommended',
      ],
      warnings: [{ type: 'warning', message: 'preserve me' }],
      summary: { policies_converted: 1 },
      identifierMappings: IDENTIFIER_MAPPINGS,
    }, 'set');

    const result = runValidation({
      intermediateConfig,
      conversionOutput: output,
      targetModel: null,
      srxLicense: 'Base',
      enforceLicense: true,
      modelDb,
      capacityLimits,
      sourceModel: null,
    });
    const filtered = replaceSetCommands(output, result.filteredCommands);

    expect(result.strippedCommands).toEqual(['set services idp active-policy recommended']);
    expect(filtered.commands).toEqual(['set system host-name edge-1']);
    expect(filtered.warnings).toEqual(output.warnings);
    expect(filtered.summary).toEqual(output.summary);
  });

  it('blocks XML and malformed output instead of validating an empty string', () => {
    const xml = normalizeConversionOutput({
      xml: '<configuration><system><host-name>edge-1</host-name></system></configuration>',
      identifierMappings: IDENTIFIER_MAPPINGS,
    }, 'xml');

    expect(() => runValidation({
      intermediateConfig,
      conversionOutput: xml,
      targetModel: null,
      srxLicense: 'Base',
      modelDb,
      capacityLimits,
      sourceModel: null,
    })).toThrow(/Set Commands/);

    expect(() => runValidation({
      intermediateConfig,
      conversionOutput: { commands: [] },
      targetModel: null,
      srxLicense: 'Base',
      modelDb,
      capacityLimits,
      sourceModel: null,
    })).toThrow(/Canonical conversion output/);
  });

  it('reports an empty filtered command list when enforcement removes everything', () => {
    const output = normalizeConversionOutput({
      commands: ['set services idp active-policy recommended'],
      identifierMappings: IDENTIFIER_MAPPINGS,
    }, 'set');
    const result = runValidation({
      intermediateConfig,
      conversionOutput: output,
      targetModel: null,
      srxLicense: 'Base',
      enforceLicense: true,
      modelDb,
      capacityLimits,
      sourceModel: null,
    });

    expect(result.filteredCommands).toEqual([]);
    expect(() => replaceSetCommands(output, result.filteredCommands)).toThrow(/at least one command/);
  });

  it('treats comments left after license enforcement as no effective device output', () => {
    const output = normalizeConversionOutput({
      commands: [
        '# generated configuration',
        '# license-gated feature follows',
        'set services idp active-policy recommended',
      ],
      identifierMappings: IDENTIFIER_MAPPINGS,
    }, 'set');
    const result = runValidation({
      intermediateConfig,
      conversionOutput: output,
      targetModel: null,
      srxLicense: 'Base',
      enforceLicense: true,
      modelDb,
      capacityLimits,
      sourceModel: null,
    });

    expect(result.filteredCommands).toEqual([
      '# generated configuration',
      '# license-gated feature follows',
    ]);
    expect(filterEffectiveSetCommands(result.filteredCommands)).toEqual([]);
  });

  it('removes every srxCommands read and write from the conversion hook', () => {
    const source = fs.readFileSync(new URL('../public/hooks/useConversion.js', import.meta.url), 'utf8');

    expect(source).not.toContain('srxCommands');
    expect(source).toContain('conversionOutput: srxOutput');
    expect(source).toContain('replaceSetCommands(srxOutput, result.filteredCommands)');
    expect(source).toContain('filterEffectiveSetCommands(result.filteredCommands).length === 0');
    expect(source).toContain("conversionDispatch({ type: 'CLEAR_OUTPUT' })");
  });
});

import { describe, expect, it } from 'vitest';

import { buildProjectPayload, validateProjectFile } from '../public/utils/project-io.js';
import { ConversionOutputError } from '../src/conversion/conversion-output.js';

const IDENTIFIER_MAPPINGS = { version: 1, entries: [] };
const RECONVERT_WARNING = 'Generated output from this older project was cleared because it has no validated identifier mapping. Reconvert before export or device push.';

const baseState = {
  configText: 'set system host-name source',
  intermediateConfig: { metadata: {} },
};

function project(version, srxOutput, outputFormat = 'set', state = {}) {
  return {
    fpic_version: version,
    name: 'project',
    savedAt: '2026-07-11T00:00:00.000Z',
    state: { ...baseState, srxOutput, outputFormat, ...state },
  };
}

describe('canonical project output', () => {
  it('writes version 4 projects with canonical output', () => {
    const payload = buildProjectPayload({
      ...baseState,
      srxOutput: {
        format: 'set',
        commands: ['set system host-name edge-1'],
        identifierMappings: IDENTIFIER_MAPPINGS,
      },
      outputFormat: 'set',
    }, 'canonical');

    expect(payload.fpic_version).toBe(4);
    expect(payload.state.srxOutput).toEqual({
      format: 'set',
      commands: ['set system host-name edge-1'],
      identifierMappings: IDENTIFIER_MAPPINGS,
    });
  });

  it('round-trips version 4 mapping-bearing output', () => {
    const payload = buildProjectPayload({
      ...baseState,
      srxOutput: {
        format: 'set',
        commands: ['set system host-name edge-1'],
        identifierMappings: IDENTIFIER_MAPPINGS,
      },
    }, 'round-trip');
    const result = validateProjectFile(JSON.parse(JSON.stringify(payload)));

    expect(result.valid).toBe(true);
    expect(result.project).toMatchObject({
      fpic_version: 4,
      name: 'round-trip',
      state: {
        outputFormat: 'set',
        srxOutput: {
          format: 'set',
          commands: ['set system host-name edge-1'],
          identifierMappings: IDENTIFIER_MAPPINGS,
        },
      },
    });
    expect(Object.isFrozen(result.project.state.srxOutput.identifierMappings)).toBe(true);
    expect(result.warnings).toEqual([]);
  });

  it('rejects legacy string output at the new-project save boundary', () => {
    expect(() => buildProjectPayload({
      ...baseState,
      srxOutput: 'set system host-name legacy',
      outputFormat: 'set',
    }, 'legacy-string')).toThrow(ConversionOutputError);
  });

  it('rejects pre-discriminant command output at the new-project save boundary', () => {
    expect(() => buildProjectPayload({
      ...baseState,
      srxOutput: {
        commands: ['set system host-name legacy-object'],
        identifierMappings: IDENTIFIER_MAPPINGS,
      },
      outputFormat: 'set',
    }, 'legacy-object')).toThrow(ConversionOutputError);
  });

  it('rejects srxCommands output at the new-project save boundary', () => {
    expect(() => buildProjectPayload({
      ...baseState,
      srxOutput: {
        srxCommands: 'set system host-name bypass',
        identifierMappings: IDENTIFIER_MAPPINGS,
      },
      outputFormat: 'set',
    }, 'unsupported-field')).toThrow(ConversionOutputError);
  });

  it('corrects a stale output format when saving canonical Set Commands output', () => {
    const payload = buildProjectPayload({
      ...baseState,
      srxOutput: {
        format: 'set',
        commands: ['set system host-name edge-1'],
        identifierMappings: IDENTIFIER_MAPPINGS,
      },
      outputFormat: 'xml',
    }, 'stale-format');

    expect(payload.state.outputFormat).toBe('set');
  });

  it('clears unmapped legacy artifacts but preserves editable state', () => {
    const result = validateProjectFile(project(3, {
      format: 'set',
      commands: ['set system host-name edge'],
    }, 'set', {
      convertWarnings: [{ type: 'warning' }],
      conversionSummary: { policies_converted: 1 },
      sourceVendor: 'fortigate',
      targetModel: 'srx1600',
      parseWarnings: [{ type: 'parser-warning' }],
    }));

    expect(result.valid).toBe(true);
    expect(result.project.fpic_version).toBe(4);
    expect(result.project.state.intermediateConfig).toEqual(baseState.intermediateConfig);
    expect(result.project.state.configText).toBe(baseState.configText);
    expect(result.project.state.sourceVendor).toBe('fortigate');
    expect(result.project.state.targetModel).toBe('srx1600');
    expect(result.project.state.parseWarnings).toEqual([{ type: 'parser-warning' }]);
    expect(result.project.state.outputFormat).toBe('set');
    expect(result.project.state.srxOutput).toBeNull();
    expect(result.project.state.convertWarnings).toEqual([]);
    expect(result.project.state.conversionSummary).toBeNull();
    expect(result.warnings).toEqual([RECONVERT_WARNING]);
  });

  it('retains legacy output with a valid identifier mapping', () => {
    const result = validateProjectFile(project(2, {
      commands: ['set system host-name edge-2'],
      warnings: [],
      identifierMappings: IDENTIFIER_MAPPINGS,
    }));

    expect(result.valid).toBe(true);
    expect(result.project.fpic_version).toBe(4);
    expect(result.project.state.srxOutput).toEqual({
      format: 'set',
      commands: ['set system host-name edge-2'],
      warnings: [],
      identifierMappings: IDENTIFIER_MAPPINGS,
    });
    expect(result.warnings).toEqual([]);
  });

  it('rejects a malformed claimed legacy identifier mapping', () => {
    const result = validateProjectFile(project(3, {
      commands: ['set system host-name edge-1'],
      identifierMappings: { version: 2, entries: [] },
    }));

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/identifier mapping/i);
  });

  it('rejects version 4 output missing an identifier mapping', () => {
    const result = validateProjectFile(project(4, {
      format: 'set',
      commands: ['set system host-name edge-1'],
    }));

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/identifier mapping/i);
  });

  it('rejects version 4 output with an invalid identifier mapping', () => {
    const result = validateProjectFile(project(4, {
      format: 'set',
      commands: ['set system host-name edge-1'],
      identifierMappings: { version: 1, entries: [], artifact: 'SECRET-MAPPING-FIELD' },
    }));

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/identifier mapping/i);
    expect(result.error).not.toContain('SECRET-MAPPING-FIELD');
  });

  it('rejects malformed legacy output that claims a valid mapping', () => {
    const result = validateProjectFile(project(2, {
      commands: [],
      identifierMappings: IDENTIFIER_MAPPINGS,
    }));

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/conversion output/i);
  });

  it('preserves null output without clearing unrelated conversion state', () => {
    const result = validateProjectFile(project(2, null, 'xml', {
      convertWarnings: [{ type: 'retained' }],
      conversionSummary: { policies_converted: 1 },
    }));

    expect(result.valid).toBe(true);
    expect(result.project.fpic_version).toBe(4);
    expect(result.project.state.srxOutput).toBeNull();
    expect(result.project.state.outputFormat).toBe('xml');
    expect(result.project.state.convertWarnings).toEqual([{ type: 'retained' }]);
    expect(result.project.state.conversionSummary).toEqual({ policies_converted: 1 });
    expect(result.warnings).toEqual([]);
  });
});

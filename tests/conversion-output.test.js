import { describe, expect, it } from 'vitest';

import {
  ConversionOutputError,
  assertConversionOutput,
  filterEffectiveSetCommands,
  getConversionOutputText,
  getSetCommands,
  hasConversionOutput,
  normalizeConversionOutput,
  replaceSetCommands,
} from '../src/conversion/conversion-output.js';

const SET_COMMANDS = [
  'set system host-name edge-1',
  'set system services ssh',
];
const XML = '<configuration><system><host-name>edge-1</host-name></system></configuration>';
const EMPTY_IDENTIFIER_MAPPINGS = { version: 1, entries: [] };
const IDENTIFIER_MAPPINGS = {
  version: 1,
  entries: [{
    context: 'root',
    namespace: 'zone',
    kind: 'zone',
    sourceName: 'trust',
    outputName: 'trust',
    definitionPath: 'zones[0].name',
    referencePaths: [],
    resolution: 'unchanged',
  }],
};

describe('canonical conversion output', () => {
  it('normalizes converter set output and preserves metadata', () => {
    const summary = { policies_converted: 2 };
    const output = normalizeConversionOutput({
      commands: SET_COMMANDS,
      warnings: [],
      summary,
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    }, 'set');

    expect(output).toEqual({
      format: 'set',
      commands: SET_COMMANDS,
      warnings: [],
      summary,
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    });
    expect(output.commands).not.toBe(SET_COMMANDS);
    expect(getConversionOutputText(output)).toBe(SET_COMMANDS.join('\n'));
    expect(getSetCommands(output)).toEqual(SET_COMMANDS);
  });

  it('normalizes converter XML output', () => {
    const output = normalizeConversionOutput({
      xml: XML,
      warnings: [],
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    }, 'xml');

    expect(output).toEqual({
      format: 'xml',
      xml: XML,
      warnings: [],
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    });
    expect(getConversionOutputText(output)).toBe(XML);
    expect(() => getSetCommands(output)).toThrow(/Set Commands/);
  });

  it('rejects a legacy set string even with an explicit hint because it has no mapping', () => {
    expect(() => normalizeConversionOutput(SET_COMMANDS.join('\n'), 'set'))
      .toThrow(/identifier mapping/i);
    expect(() => normalizeConversionOutput(SET_COMMANDS.join('\n'))).toThrow(ConversionOutputError);
    expect(() => normalizeConversionOutput(XML, 'xml')).toThrow(ConversionOutputError);
  });

  it('requires and defensively copies identifier mappings', () => {
    expect(() => normalizeConversionOutput({ commands: SET_COMMANDS }, 'set'))
      .toThrow(/identifier mapping/i);
    const output = normalizeConversionOutput({
      commands: SET_COMMANDS,
      identifierMappings: IDENTIFIER_MAPPINGS,
    }, 'set');

    expect(output.identifierMappings).toEqual(IDENTIFIER_MAPPINGS);
    expect(output.identifierMappings).not.toBe(IDENTIFIER_MAPPINGS);
    expect(Object.isFrozen(output.identifierMappings)).toBe(true);
  });

  it('preserves metadata when replacing filtered commands', () => {
    const original = normalizeConversionOutput({
      commands: SET_COMMANDS,
      warnings: [{ type: 'warning' }],
      summary: { policies_converted: 2 },
      auditId: 'conversion-7',
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    }, 'set');

    const filtered = replaceSetCommands(original, [SET_COMMANDS[0]]);

    expect(filtered).toEqual({
      format: 'set',
      commands: [SET_COMMANDS[0]],
      warnings: [{ type: 'warning' }],
      summary: { policies_converted: 2 },
      auditId: 'conversion-7',
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    });
    expect(original.commands).toEqual(SET_COMMANDS);
  });

  it('identifies only effective Set and deactivate device commands', () => {
    expect(filterEffectiveSetCommands([
      '# generated configuration',
      '  # retained converter note',
      'set system host-name edge-1',
      'deactivate system services ssh',
    ])).toEqual([
      'set system host-name edge-1',
      'deactivate system services ssh',
    ]);
  });

  it.each([
    null,
    '',
    '   ',
    {},
    { format: 'set', commands: [], identifierMappings: EMPTY_IDENTIFIER_MAPPINGS },
    { format: 'set', commands: [''], identifierMappings: EMPTY_IDENTIFIER_MAPPINGS },
    { format: 'set', commands: [7], identifierMappings: EMPTY_IDENTIFIER_MAPPINGS },
    { format: 'xml', xml: '', identifierMappings: EMPTY_IDENTIFIER_MAPPINGS },
    { format: 'xml', xml: 7, identifierMappings: EMPTY_IDENTIFIER_MAPPINGS },
    {
      format: 'set',
      commands: SET_COMMANDS,
      xml: XML,
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    },
    {
      format: 'xml',
      xml: XML,
      commands: SET_COMMANDS,
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    },
    { format: 'yaml', commands: SET_COMMANDS, identifierMappings: EMPTY_IDENTIFIER_MAPPINGS },
    {
      format: 'set',
      srxCommands: SET_COMMANDS.join('\n'),
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    },
  ])('rejects missing, empty, mixed, or malformed output: %j', value => {
    expect(() => assertConversionOutput(value)).toThrow(ConversionOutputError);
    expect(hasConversionOutput(value)).toBe(false);
  });

  it('rejects mismatched format hints and unsafe artifacts', () => {
    expect(() => normalizeConversionOutput({
      format: 'set',
      commands: SET_COMMANDS,
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    }, 'xml'))
      .toThrow(/does not match/);
    expect(() => normalizeConversionOutput({
      commands: ['set system host-name safe', 'set system services telnet'],
      identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
    }, 'set')).toThrow(ConversionOutputError);
  });

  it('does not include rejected configuration in errors', () => {
    const secret = 'set system root-authentication encrypted-password SECRET-HASH';
    let error;
    try {
      normalizeConversionOutput({
        commands: [secret],
        identifierMappings: EMPTY_IDENTIFIER_MAPPINGS,
      }, 'set');
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(ConversionOutputError);
    expect(error.message).not.toContain(secret);
    expect(error.message).not.toContain('SECRET-HASH');
  });
});

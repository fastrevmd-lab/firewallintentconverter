import fs from 'node:fs';

import { describe, expect, it } from 'vitest';

import { convertConfig, mergeConvert } from '../public/utils/engine.js';
import { JunosSerializationError } from '../src/security/junos-serialization.js';

const storage = new Map();
globalThis.localStorage = {
  getItem: key => storage.get(key) ?? null,
  setItem: (key, value) => storage.set(key, String(value)),
  removeItem: key => storage.delete(key),
};

const { formatJunosSerializationError } = await import('../public/hooks/useConversion.js');

describe('conversion fail-closed behavior', () => {
  it('formats a typed error with its safe path and reason', () => {
    const error = new JunosSerializationError(
      'metadata.siteName',
      'scalar',
      'control characters are not allowed',
    );

    expect(formatJunosSerializationError(error, 'Conversion')).toBe(
      'Conversion blocked: metadata.siteName — control characters are not allowed',
    );
  });

  it('does not reflect a rejected value in typed error output', () => {
    const rejectedValue = 'attacker\nset system services telnet';
    const error = new JunosSerializationError(
      'metadata.siteName',
      'scalar',
      'control characters are not allowed',
    );

    expect(formatJunosSerializationError(error, 'Conversion'))
      .not.toContain(rejectedValue);
  });

  it('blocks unsafe data through both public engine paths', async () => {
    await expect(convertConfig(
      { metadata: { siteName: 'x\nset system services telnet' } },
      'set',
    )).rejects.toMatchObject({ fieldPath: 'metadata.siteName' });

    await expect(mergeConvert(
      [{ lsName: 'x\nset system services telnet', intermediateConfig: {} }],
      [],
      'xml',
    )).rejects.toHaveProperty('name', 'JunosSerializationError');
  });

  it('clears stale output before work and in both error handlers', () => {
    const source = fs.readFileSync(
      new URL('../public/hooks/useConversion.js', import.meta.url),
      'utf8',
    );
    const clearCalls = source.match(/conversionDispatch\(\{ type: 'CLEAR_OUTPUT' \}\)/g) || [];

    expect(clearCalls).toHaveLength(4);
    expect(source).toContain("formatJunosSerializationError(err, 'Conversion')");
    expect(source).toContain("formatJunosSerializationError(err, 'Merge conversion')");
  });

  it('keeps completed-artifact validation at the public engine boundary', () => {
    const source = fs.readFileSync(
      new URL('../public/utils/engine.js', import.meta.url),
      'utf8',
    );

    expect(source).toContain('validateSetOutput(output.commands)');
    expect(source).toContain('validateXmlOutput(output.xml)');
  });

  it('returns canonical discriminated output through both public engine paths', async () => {
    const intermediate = {
      metadata: {},
      zones: [],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [],
      nat_rules: [],
      interfaces: [],
    };

    const setResult = await convertConfig(intermediate, 'set');
    const xmlResult = await mergeConvert([
      { lsName: 'site-a', intermediateConfig: intermediate, interfaceMappings: {} },
    ], [], 'xml');

    expect(setResult.output.format).toBe('set');
    expect(setResult.output.commands.length).toBeGreaterThan(0);
    expect(xmlResult.output.format).toBe('xml');
    expect(xmlResult.output.xml).toContain('<configuration>');
  });
});

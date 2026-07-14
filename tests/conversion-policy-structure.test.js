import { describe, it, expect } from 'vitest';
import { convertConfig } from '../public/utils/engine.js';
import { MULTIZONE_CONFIG, policyLines } from './srx-policy-structure.test.js';

describe('convertConfig forwards policyStructure', () => {
  it('produces global output when policyStructure=global', async () => {
    const data = await convertConfig(MULTIZONE_CONFIG, 'set', {}, null, { policyStructure: 'global' });
    const joined = policyLines(data.output).join('\n');
    expect(joined).toContain('set security policies global policy allow-web match from-zone trust');
  });

  it('produces zone-pair output when policyStructure=zone-pair', async () => {
    const data = await convertConfig(MULTIZONE_CONFIG, 'set', {}, null, { policyStructure: 'zone-pair' });
    const joined = policyLines(data.output).join('\n');
    expect(joined).toMatch(/from-zone \S+ to-zone \S+ policy allow-web/);
  });
});

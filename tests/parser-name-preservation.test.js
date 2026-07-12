import { expect, it } from 'vitest';

import { parseCheckPointConfig } from '../src/parsers/checkpoint-parser.js';
import { parseSonicWallConfig } from '../src/parsers/sonicwall-parser.js';

it('preserves Check Point object and member spelling', () => {
  const input = JSON.stringify({
    'objects-dictionary': [
      { uid: 'h1', type: 'host', name: 'Web Server', 'ipv4-address': '192.0.2.10' },
      { uid: 'h2', type: 'host', name: 'Web@Server', 'ipv4-address': '192.0.2.11' },
      { uid: 'g1', type: 'group', name: 'Prod Group', members: ['h1', 'h2'] },
    ],
    rulebase: [],
  });
  const config = parseCheckPointConfig(input).intermediateConfig;
  expect(config.address_objects.map(item => item.name)).toEqual(['Web Server', 'Web@Server']);
  expect(config.address_groups[0]).toMatchObject({
    name: 'Prod Group',
    members: ['Web Server', 'Web@Server'],
  });
});

it('preserves SonicWall object and rule spelling', () => {
  const input = JSON.stringify({
    address_objects: { ipv4: [{ name: 'Web Server', host: { ip: '192.0.2.10' } }] },
    access_rules: { ipv4: [{ name: 'Allow Web @ HQ', source: { address: 'any' }, destination: { address: 'Web Server' } }] },
  });
  const config = parseSonicWallConfig(input).intermediateConfig;
  expect(config.address_objects[0].name).toBe('Web Server');
  expect(config.security_policies[0].name).toBe('Allow Web @ HQ');
});

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

it('keeps Check Point DNS-domain references aligned with their definition', () => {
  const input = JSON.stringify({
    'objects-dictionary': [
      { uid: 'dns1', type: 'dns-domain', name: '.Example.COM' },
      { uid: 'group1', type: 'group', name: 'DNS @ Group', members: ['dns1'] },
    ],
    rulebase: [{
      type: 'access-rule',
      name: 'Allow DNS @ HQ',
      source: ['dns1'],
      destination: ['dns1'],
      service: [],
    }],
    'nat-rulebase': {
      rulebase: [
        {
          type: 'nat-rule',
          name: 'DNS Original @ HQ',
          'original-source': 'dns1',
          'original-destination': 'dns1',
        },
        {
          type: 'nat-rule',
          name: 'DNS Translated @ HQ',
          method: 'static',
          'original-source': 'any',
          'original-destination': 'any',
          'translated-source': 'dns1',
          'translated-destination': 'dns1',
        },
      ],
    },
  });
  const config = parseCheckPointConfig(input).intermediateConfig;

  expect(config.address_objects[0].name).toBe('Example.COM');
  expect(config.address_groups[0]).toMatchObject({
    name: 'DNS @ Group',
    members: ['Example.COM'],
  });
  expect(config.security_policies[0]).toMatchObject({
    name: 'Allow DNS @ HQ',
    src_addresses: ['Example.COM'],
    dst_addresses: ['Example.COM'],
  });
  expect(config.nat_rules[0]).toMatchObject({
    name: 'DNS Original @ HQ',
    src_addresses: ['Example.COM'],
    dst_addresses: ['Example.COM'],
  });
  expect(config.nat_rules[1]).toMatchObject({
    name: 'DNS Translated @ HQ',
    translated_src: {
      address: 'Example.COM',
      addresses: ['Example.COM'],
    },
    translated_dst: 'Example.COM',
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

import { describe, it, expect } from 'vitest';
import { isSubInterface, parentInterface, buildDefaultMappings, deriveSubInterfaceMappings } from '../public/components/InterfaceMapper.jsx';

const TARGET = { ports: [
  { name: 'ge-0/0/0', speed: '1G', type: 'copper' },
  { name: 'ge-0/0/1', speed: '1G', type: 'copper' },
  { name: 'ge-0/0/2', speed: '1G', type: 'copper' },
] };

const CONFIG = { zones: [
  { name: 'INSIDE', interfaces: ['ethernet1/13', 'ethernet1/13.100', 'ethernet1/13.206'] },
] };

describe('sub-interface mapping helpers', () => {
  it('detects sub-interfaces and parents', () => {
    expect(isSubInterface('ethernet1/13.100')).toBe(true);
    expect(isSubInterface('ethernet1/13')).toBe(false);
    expect(isSubInterface('tunnel.10')).toBe(false);
    expect(isSubInterface('loopback.1')).toBe(false);
    expect(parentInterface('ethernet1/13.100')).toBe('ethernet1/13');
  });

  it('maps sub-interfaces onto the parent port, not new physical ports', () => {
    const m = buildDefaultMappings(CONFIG, TARGET);
    expect(m['ethernet1/13']).toBe('ge-0/0/0');            // parent → first port
    expect(m['ethernet1/13.100']).toBe('ge-0/0/0.100');    // sub → parent port + unit
    expect(m['ethernet1/13.206']).toBe('ge-0/0/0.206');
    // only ONE physical port consumed
    const physUsed = new Set(Object.values(m).map(v => v.split('.')[0]));
    expect(physUsed.has('ge-0/0/1')).toBe(false);
  });

  it('leaves a sub-interface unmapped when its parent has no mapping', () => {
    const m = buildDefaultMappings({ zones: [{ name: 'Z', interfaces: ['ethernet1/9.50'] }] }, { ports: [] });
    expect(m['ethernet1/9.50']).toBeUndefined();
  });
});

describe('deriveSubInterfaceMappings', () => {
  it('re-points a parent\'s sub-interfaces to the new port', () => {
    const before = {
      'ethernet1/13': 'ge-0/0/0',
      'ethernet1/13.100': 'ge-0/0/0.100',
      'ethernet1/13.206': 'ge-0/0/0.206',
      'ethernet1/9': 'ge-0/0/1',
    };
    const after = deriveSubInterfaceMappings(before, 'ethernet1/13', 'ge-0/0/5');
    expect(after['ethernet1/13.100']).toBe('ge-0/0/5.100');
    expect(after['ethernet1/13.206']).toBe('ge-0/0/5.206');
    expect(after['ethernet1/9']).toBe('ge-0/0/1');   // unrelated untouched
  });
});

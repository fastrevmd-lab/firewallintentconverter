import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { exportToAnsible, exportToTerraform } from '../public/utils/iac-export.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = path => readFileSync(join(root, path), 'utf8');

describe('Mechub browser identity assets', () => {
  it('ships safe canonical mark variants and removes the generic raster', () => {
    for (const path of [
      'static/brand/mechub-mark.svg',
      'static/brand/mechub-mark-light.svg',
      'static/brand/mechub-favicon.svg',
      'static/licenses/geist-OFL-1.1.txt',
      'static/licenses/geist-mono-OFL-1.1.txt',
    ]) expect(existsSync(join(root, path)), path).toBe(true);

    expect(existsSync(join(root, 'static/logo.png'))).toBe(false);
    for (const path of ['static/brand/mechub-mark.svg', 'static/brand/mechub-mark-light.svg', 'static/brand/mechub-favicon.svg']) {
      const svg = read(path);
      expect(svg).toContain('viewBox="0 0 120 120"');
      expect(svg).toContain('M18,96 L18,32 L60,74 L102,32 L102,96');
      expect(svg).not.toMatch(/<script|(?:xlink:)?href\s*=\s*["']https?:|src\s*=\s*["']https?:/i);
    }
    expect(read('static/brand/mechub-favicon.svg')).not.toContain('<circle');
  });

  it.each(['index.html', 'standalone/index.html'])('brands %s without a network dependency', path => {
    const html = read(path);
    expect(html).toContain('<title>firewallintentconverter · a mechub project</title>');
    expect(html).toContain('name="description"');
    expect(html).toContain('%BASE_URL%brand/mechub-favicon.svg');
    expect(html).not.toContain('🔥');
    expect(html).not.toMatch(/fonts\.googleapis|fonts\.gstatic/);
  });

  it('pins and imports the variable Geist families', () => {
    const pkg = JSON.parse(read('package.json'));
    expect(pkg.devDependencies['@fontsource-variable/geist']).toBe('5.2.9');
    expect(pkg.devDependencies['@fontsource-variable/geist-mono']).toBe('5.2.8');
    for (const path of ['public/main.jsx', 'standalone/main.jsx']) {
      const source = read(path);
      expect(source).toContain('@fontsource-variable/geist/wght.css');
      expect(source).toContain('@fontsource-variable/geist-mono/wght.css');
    }
  });

  it('brands the standalone guide and generated IaC artifacts', () => {
    const identity = 'firewallintentconverter · a mechub project';
    const outputs = [
      read('standalone/README.txt'),
      exportToTerraform(['set system host-name branch-a']),
      exportToAnsible(['set system host-name branch-a']),
    ];

    for (const output of outputs) {
      expect(output).toContain(identity);
      expect(output).not.toContain('Firewall Policy Converter');
      expect(output).not.toContain('Firewall Intent Converter');
    }
  });

  it('uses the canonical identity in maintained documentation and push workflows', () => {
    const sources = [
      read('DESIGN.md'),
      read('tools/pyez-bridge/app.py'),
      read('tools/pyez-bridge/README.md'),
      read('public/components/PushModal.jsx'),
      read('public/hooks/usePush.js'),
    ];

    for (const source of sources) {
      expect(source).not.toContain('Firewall Policy Converter');
      expect(source).not.toContain('Firewall Intent Converter');
      expect(source).toContain('firewallintentconverter');
    }
  });
});

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = path => readFileSync(join(root, path), 'utf8');

describe('Mechub style contract', () => {
  it('defines the exact dark identity tokens and semantic aliases', () => {
    const css = read('public/styles/main.css');
    for (const declaration of [
      '--ink-0: #0B0D12', '--ink-1: #12151C', '--ink-2: #171A22',
      '--border-color: #262B38', '--text-primary: #F8F9FA',
      '--text-secondary: #C9CED5', '--text-muted: #9AA2AD',
      '--model-plum: #7C3AED', '--model-text: #C4B5FD',
      '--juniper-green: #90C641',
    ]) expect(css).toContain(declaration);
    expect(css).toContain('--llm-cloud: var(--model-plum)');
    expect(css).toContain('--llm-local: var(--model-plum)');
  });

  it('defines light-mode accessible brand roles', () => {
    const css = read('public/styles/main.css');
    expect(css).toContain('--bg-primary: #F5F6F8');
    expect(css).toContain('--accent: #0D9488');
    expect(css).toContain('--accent-text: #005B5A');
    expect(css).toContain('--model-text: #7C3AED');
  });

  it('loads the final shared control layer in both application entries', () => {
    const brandCss = read('public/styles/brand.css');
    expect(brandCss).toContain('font-family: var(--font-mono)');
    expect(brandCss).toContain('min-height: var(--control-height)');
    expect(brandCss).toContain('border-radius: var(--control-radius)');
    for (const path of ['public/main.jsx', 'standalone/main.jsx']) {
      expect(read(path)).toContain('styles/brand.css');
    }
  });

  it('gives every native and ARIA control the Mechub keyboard focus ring', () => {
    const brandCss = read('public/styles/brand.css');
    expect(brandCss).toContain(':focus-visible');
    expect(brandCss).toContain('outline: 2px solid var(--accent) !important');
    for (const selector of ['button', '[role="button"]', 'a', 'input', 'select', 'textarea']) {
      expect(brandCss).toContain(selector);
    }
  });

  it('uses branded scrollbars in Firefox as well as WebKit browsers', () => {
    const css = read('public/styles/main.css');
    expect(css).toContain('scrollbar-width: thin');
    expect(css).toContain('scrollbar-color: var(--bg-elevated) var(--bg-secondary)');
  });
});

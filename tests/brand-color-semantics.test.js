import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, extname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
function sourceFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : ['.css', '.jsx'].includes(extname(path)) ? [path] : [];
  });
}

describe('Mechub color semantics', () => {
  const componentAndStyleSource = sourceFiles(join(root, 'public'))
    .filter(path => !path.includes('/utils/'))
    .map(path => readFileSync(path, 'utf8'))
    .join('\n');

  it.each(['#1a1d23', '#22262e', '#2a2f38', '#31363f', '#383e48', '#3a3f48', '#2a333d'])('removes legacy core surface %s', color => {
    expect(componentAndStyleSource.toLowerCase()).not.toContain(color);
  });

  it.each(['#84b135', '#a78bfa', '#db2777', '#be185d', '#c084fc', '#d8b4fe', '#a5b4fc', '#4c1d95', '#3b0764', '#312e81', '#4a1d6a', '#a855f7', '#6366f1', '#ec4899', '#f472b6'])('removes noncanonical decorative/model color %s', color => {
    expect(componentAndStyleSource.toLowerCase()).not.toContain(color);
  });

  it('keeps model identity tokenized and provider-neutral', () => {
    const css = readFileSync(join(root, 'public/styles/main.css'), 'utf8');
    expect(css).toContain('--model-plum: #7C3AED');
    expect(css).toContain('--model-text: #C4B5FD');
    expect(css).toContain('--llm-cloud: var(--model-plum)');
    expect(css).toContain('--llm-local: var(--model-plum)');
  });

  it('uses semantic tokens for target identity and current-model status', () => {
    const selector = readFileSync(join(root, 'public/components/ModelSelector.jsx'), 'utf8');
    expect(selector).toContain("color: 'var(--juniper-green)'");
    expect(selector).toContain("color: vendor === 'srx' ? 'var(--juniper-green)' : 'var(--success)'");
  });
});

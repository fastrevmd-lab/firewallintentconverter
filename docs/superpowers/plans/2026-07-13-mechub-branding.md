# Mechub Branding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebrand the complete application, browser identity, and generated reports to the Mechub brand system, replacing the generic icon with the official topology M while preserving all converter behavior and offline builds.

**Architecture:** Add canonical static brand assets and a small identity module, render a reusable theme-aware lockup in the existing top bar, and move global visual decisions into canonical CSS tokens plus a final brand control layer. Keep domain components and state contracts intact; update only off-brand presentation, then reuse safe inline SVG identity primitives in the two self-contained report generators.

**Tech Stack:** React 18, Vite 8, Vitest 4, server-side React test rendering, CSS custom properties, Fontsource variable WOFF2 packages, self-contained HTML report templates.

## Global Constraints

- Brand authority is Mechub brand system v1.1 at `https://command.mechub.org/branding`.
- Product identity is `firewallintentconverter · a mechub project`; product names remain lowercase and `intent` is plum in visual lockups.
- Dark palette is exactly ink/0 `#0B0D12`, ink/1 `#12151C`, ink/2 `#171A22`, border `#262B38`, text/1 `#F8F9FA`, text/2 `#C9CED5`, and text/3 `#9AA2AD`.
- Teal `#4DD0C8` is identity/primary action; deep teal `#0D9488` is the light-mode fill/large-text accent; dim teal `#005B5A` is light-mode body text.
- Plum `#7C3AED` and plum/light `#C4B5FD` are reserved for model/LLM content and actions.
- Juniper `#90C641` identifies SRX devices and target data only; success remains semantically green.
- Standard controls use Geist Mono, a 34 px height, and full-pill geometry; compact icon controls may be 28 px.
- Geist and Geist Mono must be bundled WOFF2 assets with no runtime CDN request; the standard and standalone builds must both work offline.
- Preserve reducer/context contracts, event behavior, conversion data, exported firewall configuration content, theme persistence, keyboard behavior, and reduced-motion behavior.
- Generated reports remain self-contained, safely escaped, printable, and meaningful without color.
- Do not introduce logo animation, external SVG references, or scripts inside brand SVGs.

---

## File Structure

### New files

- `static/brand/mechub-mark.svg` — canonical gradient M for ink backgrounds.
- `static/brand/mechub-mark-light.svg` — canonical deep-teal M for light backgrounds.
- `static/brand/mechub-favicon.svg` — strokes-only M for sub-20 px favicon rendering.
- `static/licenses/geist-OFL-1.1.txt` — distributed OFL license shipped by the Geist package.
- `static/licenses/geist-mono-OFL-1.1.txt` — distributed OFL license shipped by the Geist Mono package.
- `public/utils/brand.js` — immutable identity strings, approved report colors, asset URL selection, and safe inline report lockup markup.
- `public/components/brand/BrandLockup.jsx` — pure theme-aware React product lockup.
- `public/styles/brand.css` — final-cascade typography and shared control shape language.
- `tests/branding-assets.test.js` — static asset, metadata, font dependency, and offline-path contract.
- `tests/brand-lockup.test.jsx` — server-rendered lockup contract.
- `tests/brand-style-contract.test.js` — canonical token and control-language contract.
- `tests/brand-color-semantics.test.js` — regression scan for legacy surfaces and non-model plum use.
- `tests/report-branding.test.js` — identity and semantic-color contract for both report generators.

### Modified files

- `package.json`, `package-lock.json` — exact Geist variable font build dependencies.
- `index.html`, `standalone/index.html` — title, description, and strokes-only M favicon.
- `public/main.jsx`, `standalone/main.jsx` — bundled fonts and final brand stylesheet imports.
- `public/components/layout/TopBar.jsx` — reusable official lockup in place of `/logo.png` and the legacy title.
- `public/styles/main.css` — canonical theme aliases and removal of off-brand/model-provider colors.
- `public/styles/layout.css` — top-bar lockup layout and 1200 px endorsement breakpoint.
- `public/components/InterfaceMapper.jsx` — information-colored LAG styling instead of model plum.
- `public/components/PolicyTable.jsx` — non-model subscription colors and class-based LLM action treatment.
- `public/components/PolicyDependencyGraph.jsx` — semantic warning surface instead of violet decoration.
- `public/components/layout/RightPanel.jsx` — semantic analysis finding surface.
- `public/components/RoutingEditor.jsx` — shared neutral/semantic tokens in place of a parallel slate/indigo theme.
- `public/utils/report-generator.js` — branded self-contained HTML report.
- `public/utils/pdf-report-generator.js` — branded print/PDF report and unified model plum.
- `docs/superpowers/specs/2026-07-13-mechub-branding-design.md` — reviewed status.

### Removed file

- `static/logo.png` — obsolete 1.4 MB generic arrow/checkmark raster.

---

### Task 1: Canonical Assets, Offline Fonts, and Browser Metadata

**Files:**
- Create: `static/brand/mechub-mark.svg`
- Create: `static/brand/mechub-mark-light.svg`
- Create: `static/brand/mechub-favicon.svg`
- Create: `static/licenses/geist-OFL-1.1.txt`
- Create: `static/licenses/geist-mono-OFL-1.1.txt`
- Create: `tests/branding-assets.test.js`
- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `index.html`
- Modify: `standalone/index.html`
- Modify: `public/main.jsx`
- Modify: `standalone/main.jsx`
- Delete: `static/logo.png`

**Interfaces:**
- Consumes: Vite `publicDir: 'static'` and `base: './'` from both Vite configurations.
- Produces: `%BASE_URL%brand/mechub-favicon.svg`, `${import.meta.env.BASE_URL}brand/mechub-mark.svg`, `${import.meta.env.BASE_URL}brand/mechub-mark-light.svg`, and bundled `Geist Variable` / `Geist Mono Variable` font families.

- [ ] **Step 1: Write the failing asset and metadata contract**

```js
// tests/branding-assets.test.js
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

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
      expect(svg).not.toMatch(/<script|https?:|xlink:href/i);
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
      expect(source).toContain("@fontsource-variable/geist/wght.css");
      expect(source).toContain("@fontsource-variable/geist-mono/wght.css");
    }
  });
});
```

- [ ] **Step 2: Run the contract and confirm the expected failures**

Run: `npx vitest run tests/branding-assets.test.js`

Expected: FAIL because the three SVGs, font license, dependencies, metadata, and font imports do not exist and `static/logo.png` still exists.

- [ ] **Step 3: Install exact build-time font packages**

```bash
npm install --save-dev --save-exact @fontsource-variable/geist@5.2.9 @fontsource-variable/geist-mono@5.2.8
mkdir -p static/brand static/licenses
install -m 0644 node_modules/@fontsource-variable/geist/LICENSE static/licenses/geist-OFL-1.1.txt
install -m 0644 node_modules/@fontsource-variable/geist-mono/LICENSE static/licenses/geist-mono-OFL-1.1.txt
```

Add these imports before the application CSS imports in both entry points:

```js
import '@fontsource-variable/geist/wght.css';
import '@fontsource-variable/geist-mono/wght.css';
```

- [ ] **Step 4: Add exact SVG assets and remove the raster**

Primary mark:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" role="img" aria-label="Mechub mark">
  <defs><linearGradient id="mesh" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4DD0C8"/><stop offset="1" stop-color="#0D9488"/></linearGradient></defs>
  <path d="M18,96 L18,32 L60,74 L102,32 L102,96" fill="none" stroke="url(#mesh)" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="18" cy="96" r="7" fill="#4DD0C8"/><circle cx="18" cy="32" r="7" fill="#4DD0C8"/><circle cx="102" cy="32" r="7" fill="#4DD0C8"/><circle cx="102" cy="96" r="7" fill="#4DD0C8"/>
  <circle cx="60" cy="74" r="11" fill="#0D9488"/><circle cx="60" cy="74" r="5.5" fill="#B7F5F0"/>
</svg>
```

Light-background mark:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" role="img" aria-label="Mechub mark">
  <path d="M18,96 L18,32 L60,74 L102,32 L102,96" fill="none" stroke="#0D9488" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="18" cy="96" r="7" fill="#0D9488"/><circle cx="18" cy="32" r="7" fill="#0D9488"/><circle cx="102" cy="32" r="7" fill="#0D9488"/><circle cx="102" cy="96" r="7" fill="#0D9488"/>
  <circle cx="60" cy="74" r="11" fill="#0D9488"/><circle cx="60" cy="74" r="5.5" fill="#B7F5F0"/>
</svg>
```

The favicon contains only:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" role="img" aria-label="Mechub mark">
  <rect width="120" height="120" rx="18" fill="#0B0D12"/>
  <path d="M18,96 L18,32 L60,74 L102,32 L102,96" fill="none" stroke="#4DD0C8" stroke-width="10" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
```

Remove the obsolete binary with `rm static/logo.png`.

- [ ] **Step 5: Replace browser metadata in both HTML entries**

Use this exact head content in each entry, preserving the standard entry’s existing early theme script and each entry’s existing module script:

```html
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="description" content="Browser-based, deterministic firewall configuration translation to Juniper SRX — a migration draft requiring review." />
<title>firewallintentconverter · a mechub project</title>
<link rel="icon" type="image/svg+xml" href="%BASE_URL%brand/mechub-favicon.svg" />
```

- [ ] **Step 6: Run the focused test and both builds**

Run:

```bash
npx vitest run tests/branding-assets.test.js
npm run build
npm run build:standalone
```

Expected: 3 asset tests PASS; both builds exit 0; `dist/brand/` and `dist-standalone/brand/` contain the three SVGs; emitted CSS/assets contain local WOFF2 fonts.

- [ ] **Step 7: Commit the identity inputs**

```bash
git add package.json package-lock.json index.html standalone/index.html public/main.jsx standalone/main.jsx static/brand static/licenses tests/branding-assets.test.js
git add -u static/logo.png
git commit -m "feat(brand): add Mechub identity assets and fonts"
```

---

### Task 2: Reusable Product Lockup and Top-Bar Integration

**Files:**
- Create: `public/utils/brand.js`
- Create: `public/components/brand/BrandLockup.jsx`
- Create: `tests/brand-lockup.test.jsx`
- Modify: `public/components/layout/TopBar.jsx:1-145`
- Modify: `public/styles/layout.css:24-35`

**Interfaces:**
- Consumes: `theme: 'dark' | 'light'` from `TopBar`’s existing `useTheme()` hook and the Task 1 asset paths.
- Produces: `BRAND` immutable constant, `brandAssetUrl(filename, baseUrl?) -> string`, `brandMarkFilename(theme) -> string`, and `<BrandLockup theme />`.

- [ ] **Step 1: Write the failing server-rendered lockup tests**

```jsx
// tests/brand-lockup.test.jsx
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import BrandLockup from '../public/components/brand/BrandLockup.jsx';
import { BRAND, brandAssetUrl, brandMarkFilename } from '../public/utils/brand.js';

describe('Mechub product lockup', () => {
  it('exposes the approved immutable identity', () => {
    expect(BRAND).toEqual({
      product: 'firewallintentconverter',
      endorsement: 'a mechub project',
      accessibleName: 'firewallintentconverter · a mechub project',
    });
    expect(Object.isFrozen(BRAND)).toBe(true);
  });

  it.each([
    ['dark', 'mechub-mark.svg'],
    ['light', 'mechub-mark-light.svg'],
  ])('renders the %s-theme asset and semantic wordmark', (theme, filename) => {
    const html = renderToStaticMarkup(<BrandLockup theme={theme} />);
    expect(brandMarkFilename(theme)).toBe(filename);
    expect(brandAssetUrl(filename, './')).toBe(`./brand/${filename}`);
    expect(html).toContain(`brand/${filename}`);
    expect(html).toContain('aria-label="firewallintentconverter · a mechub project"');
    expect(html).toContain('class="brand-intent"');
    expect(html).toContain('class="brand-endorsement"');
    expect(html).not.toContain('Intent Converter');
  });
});
```

- [ ] **Step 2: Run the test and confirm missing-module failure**

Run: `npx vitest run tests/brand-lockup.test.jsx`

Expected: FAIL with module resolution errors for `BrandLockup.jsx` and `brand.js`.

- [ ] **Step 3: Add the identity module and lockup component**

```js
// public/utils/brand.js
export const BRAND = Object.freeze({
  product: 'firewallintentconverter',
  endorsement: 'a mechub project',
  accessibleName: 'firewallintentconverter · a mechub project',
});

export function brandMarkFilename(theme) {
  return theme === 'light' ? 'mechub-mark-light.svg' : 'mechub-mark.svg';
}

export function brandAssetUrl(filename, baseUrl = import.meta.env.BASE_URL) {
  return `${baseUrl}brand/${filename}`;
}
```

```jsx
// public/components/brand/BrandLockup.jsx
import React from 'react';
import { BRAND, brandAssetUrl, brandMarkFilename } from '../../utils/brand.js';

export default function BrandLockup({ theme = 'dark' }) {
  return (
    <div className="brand-lockup" aria-label={BRAND.accessibleName}>
      <img className="brand-mark" src={brandAssetUrl(brandMarkFilename(theme))} alt="" aria-hidden="true" />
      <span className="brand-copy">
        <span className="brand-product">firewall<span className="brand-intent">intent</span>converter</span>
        <span className="brand-endorsement"> · {BRAND.endorsement}</span>
      </span>
    </div>
  );
}
```

- [ ] **Step 4: Integrate the lockup and exact responsive styles**

Import `BrandLockup` into `TopBar.jsx` and replace the existing inline brand `<div>` with:

```jsx
<BrandLockup theme={theme} />
```

Add to `layout.css`:

```css
.brand-lockup { display:flex; align-items:center; gap:10px; padding:0 16px; flex:0 0 auto; min-width:0; }
.brand-mark { width:28px; height:28px; flex:0 0 28px; }
.brand-copy { display:flex; align-items:baseline; min-width:0; white-space:nowrap; }
.brand-product { color:var(--text-primary); font-family:var(--font-sans); font-size:14px; font-weight:700; letter-spacing:-0.045em; }
.brand-intent { color:var(--model-text); }
.brand-endorsement { color:var(--text-muted); font-family:var(--font-mono); font-size:10px; letter-spacing:0; }
@media (max-width: 1200px) { .brand-endorsement { display:none; } }
```

- [ ] **Step 5: Run the lockup and existing UI tests**

Run:

```bash
npx vitest run tests/brand-lockup.test.jsx tests/project-security-ui.test.jsx
```

Expected: all lockup and project-security UI tests PASS.

- [ ] **Step 6: Commit the lockup**

```bash
git add public/utils/brand.js public/components/brand/BrandLockup.jsx public/components/layout/TopBar.jsx public/styles/layout.css tests/brand-lockup.test.jsx
git commit -m "feat(brand): add the Mechub product lockup"
```

---

### Task 3: Canonical Theme Tokens, Typography, and Control Language

**Files:**
- Create: `public/styles/brand.css`
- Create: `tests/brand-style-contract.test.js`
- Modify: `public/styles/main.css:1-126,447-505,1289-1358,2990-3090`
- Modify: `public/main.jsx:12-19`
- Modify: `standalone/main.jsx:14-22`

**Interfaces:**
- Consumes: existing `--bg-*`, `--text-*`, `--accent*`, `--llm-*`, `--juniper-green`, and semantic token consumers.
- Produces: canonical `--ink-*`, `--model-*`, `--control-*` tokens while preserving compatibility aliases used by existing components.

- [ ] **Step 1: Write the failing CSS contract**

```js
// tests/brand-style-contract.test.js
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
      expect(read(path)).toContain("styles/brand.css");
    }
  });
});
```

- [ ] **Step 2: Run the CSS contract and confirm failure**

Run: `npx vitest run tests/brand-style-contract.test.js`

Expected: FAIL on missing canonical tokens and missing `brand.css`.

- [ ] **Step 3: Replace the dark root with canonical tokens and aliases**

Use these declarations in `:root`:

```css
--ink-0:#0B0D12; --ink-1:#12151C; --ink-2:#171A22;
--bg-primary:var(--ink-0); --bg-secondary:var(--ink-1); --bg-tertiary:var(--ink-2); --bg-elevated:var(--ink-2);
--bg-hover:color-mix(in srgb, var(--ink-2) 84%, var(--text-primary));
--border-color:#262B38;
--text-primary:#F8F9FA; --text-secondary:#C9CED5; --text-muted:#9AA2AD;
--accent:#4DD0C8; --accent-dim:#005B5A; --accent-text:#4DD0C8; --accent-glow:rgba(77,208,200,.15);
--model-plum:#7C3AED; --model-text:#C4B5FD; --model-surface:rgba(124,58,237,.14);
--llm-cloud:var(--model-plum); --llm-local:var(--model-plum);
--success:#34D399; --warning:#FBBF24; --error:#F87171; --info:#60A5FA; --caution:#FBBF24;
--juniper-green:#90C641;
--control-height:34px; --control-compact:28px; --control-radius:999px;
--font-sans:'Geist Variable','Geist','Inter',system-ui,sans-serif;
--font-mono:'Geist Mono Variable','Geist Mono','JetBrains Mono',ui-monospace,monospace;
```

Retain existing status aliases, but point them to the semantic tokens. Set the explicit light selector and OS-preference light block to the same values:

```css
--bg-primary:#F5F6F8; --bg-secondary:#FFFFFF; --bg-tertiary:#EBEDF0; --bg-elevated:#E0E3E8; --bg-hover:#D5D8DE;
--border-color:#C9CDD4; --text-primary:#171A22; --text-secondary:#4B5563; --text-muted:#6B7280;
--accent:#0D9488; --accent-dim:#005B5A; --accent-text:#005B5A; --accent-glow:rgba(13,148,136,.12);
--model-plum:#7C3AED; --model-text:#7C3AED; --model-surface:rgba(124,58,237,.10);
--llm-cloud:var(--model-plum); --llm-local:var(--model-plum);
--success:#047857; --warning:#B45309; --error:#B91C1C; --info:#1D4ED8; --caution:#B45309; --juniper-green:#3F6212;
```

Change the `main.css` file header to `firewallintentconverter — Mechub brand system` so the obsolete “Firewall Policy Converter” identity is not retained in source or build output.

- [ ] **Step 4: Add the final-cascade control layer**

```css
/* public/styles/brand.css */
button, [role="button"], .stat-badge, .badge { font-family:var(--font-mono); }
:where(.btn,.btn-primary,.btn-secondary,.btn-sm,.btn-translate,.risk-btn-accept,.risk-btn-local,.risk-btn-reject) {
  min-height:var(--control-height); border-radius:var(--control-radius) !important; font-family:var(--font-mono); font-size:12.5px;
}
:where(.settings-btn,.btn-icon,.modal-close) { min-width:var(--control-compact); min-height:var(--control-compact); border-radius:var(--control-radius); }
:where(.stat-badge,.tab-badge,.nav-badge,.status-label,.profile-chip,.project-security-badge) { border-radius:var(--control-radius); font-family:var(--font-mono); }
.btn-primary { background:var(--accent); color:var(--ink-0); }
.btn-primary:hover { background:color-mix(in srgb,var(--accent) 82%,white); }
.btn-translate,.risk-btn-accept,.risk-btn-local {
  background:var(--model-surface) !important; border:1px solid var(--model-plum) !important; color:var(--model-text) !important;
}
.btn-translate:hover:not(:disabled),.risk-btn-accept:hover,.risk-btn-local:hover { background:color-mix(in srgb,var(--model-plum) 22%,transparent) !important; }
.llm-local { --llm-local:var(--model-plum); }
```

Import `brand.css` after every existing local stylesheet in both application entry points.

- [ ] **Step 5: Remove inline solid-model button styling**

In `PolicyTable.jsx`, remove the inline `background`, `color`, and `borderColor` object from “Auto-group w/LLM” and add `btn-translate` plus conditional `llm-local` to its class list. In `main.css`, change workflow model number text from hard-coded `#0f1419` to `var(--text-primary)` and let the final brand layer style model action buttons.

- [ ] **Step 6: Run style and behavioral tests**

Run:

```bash
npx vitest run tests/brand-style-contract.test.js tests/brand-lockup.test.jsx tests/workflow-steps.test.js
```

Expected: all focused tests PASS.

- [ ] **Step 7: Commit the visual foundation**

```bash
git add public/styles/main.css public/styles/brand.css public/main.jsx standalone/main.jsx public/components/PolicyTable.jsx tests/brand-style-contract.test.js
git commit -m "feat(brand): apply Mechub tokens and control language"
```

---

### Task 4: Enforce Plum and Surface Semantics Across Feature Views

**Files:**
- Create: `tests/brand-color-semantics.test.js`
- Modify: `public/styles/main.css`
- Modify: `public/components/InterfaceMapper.jsx`
- Modify: `public/components/PolicyTable.jsx`
- Modify: `public/components/PolicyDependencyGraph.jsx`
- Modify: `public/components/layout/RightPanel.jsx`
- Modify: `public/components/RoutingEditor.jsx`

**Interfaces:**
- Consumes: Task 3’s neutral, model, information, warning, and semantic CSS tokens.
- Produces: no new runtime API; establishes that raw plum appears only through model tokens and core view surfaces use shared tokens.

- [ ] **Step 1: Write the failing semantic-color regression scan**

```js
// tests/brand-color-semantics.test.js
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, extname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
function sourceFiles(dir) {
  return readdirSync(dir, { withFileTypes:true }).flatMap(entry => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : ['.css','.jsx'].includes(extname(path)) ? [path] : [];
  });
}

describe('Mechub color semantics', () => {
  const componentAndStyleSource = sourceFiles(join(root, 'public')).filter(path => !path.includes('/utils/')).map(path => readFileSync(path, 'utf8')).join('\n');

  it.each(['#1a1d23','#22262e','#2a2f38','#31363f','#383e48','#3a3f48','#2a333d'])('removes legacy core surface %s', color => {
    expect(componentAndStyleSource.toLowerCase()).not.toContain(color);
  });

  it.each(['#a78bfa','#db2777','#be185d','#c084fc','#d8b4fe','#a5b4fc','#4c1d95','#3b0764','#312e81','#4a1d6a','#a855f7','#6366f1','#ec4899','#f472b6'])('removes noncanonical decorative/model color %s', color => {
    expect(componentAndStyleSource.toLowerCase()).not.toContain(color);
  });

  it('keeps model identity tokenized and provider-neutral', () => {
    const css = readFileSync(join(root, 'public/styles/main.css'), 'utf8');
    expect(css).toContain('--model-plum: #7C3AED');
    expect(css).toContain('--model-text: #C4B5FD');
    expect(css).toContain('--llm-cloud: var(--model-plum)');
    expect(css).toContain('--llm-local: var(--model-plum)');
  });
});
```

- [ ] **Step 2: Run the scan and confirm it reports current legacy literals**

Run: `npx vitest run tests/brand-color-semantics.test.js`

Expected: FAIL and name the legacy surface/plum literals still present in the component and style sources.

- [ ] **Step 3: Convert non-model purple applications to approved roles**

Apply these exact semantic mappings:

```text
InterfaceMapper LAG parent/member text and pills -> var(--info), color-mix(in srgb,var(--info) 15%,transparent)
PolicyTable Decrypt subscription -> #60A5FA; ICAP Redirect -> #4DD0C8
PolicyDependencyGraph performance-limit notice -> var(--caution) and a warning-derived translucent background
RightPanel warning findings -> var(--caution) and a warning-derived translucent background
sanitize community/hostname/domain/url/email badges -> info/accent semantic tokens, never plum literals
profile group/app/DLP, SRX application icon, Cisco protocol, diff-renamed badge -> info/accent semantic tokens
RoutingEditor OSPFv3/EVPN/VXLAN purple pills -> var(--info) on an info-derived translucent surface
```

For example, replace every InterfaceMapper inline LAG purple style with:

```jsx
style={{ background:'color-mix(in srgb, var(--info) 15%, transparent)', color:'var(--info)', fontSize:10, padding:'1px 5px' }}
```

- [ ] **Step 4: Replace RoutingEditor’s parallel slate theme with shared tokens**

Perform these literal-to-token substitutions throughout `RoutingEditor.jsx`:

```text
#0f172a -> var(--bg-primary)      #1e293b -> var(--bg-tertiary)
#334155 -> var(--border-color)    #475569 -> var(--text-muted)
#64748b -> var(--text-muted)      #94a3b8 -> var(--text-secondary)
#e2e8f0 -> var(--text-primary)    #38bdf8 -> var(--info)
#ef4444 -> var(--error)           #22c55e -> var(--success)
#f59e0b/#fbbf24 -> var(--warning)
```

Replace the former purple protocol pills with:

```jsx
style={{ background:'color-mix(in srgb, var(--info) 15%, transparent)', color:'var(--info)' }}
```

Keep orange protocol-specific badges only where they communicate a warning; convert neutral cards and table borders to the shared surface tokens.

- [ ] **Step 5: Run semantic and focused component tests**

Run:

```bash
npx vitest run tests/brand-color-semantics.test.js tests/brand-style-contract.test.js tests/triage.test.js
```

Expected: all tests PASS and the forbidden-literal table reports no failures.

- [ ] **Step 6: Commit semantic cleanup**

```bash
git add public/styles/main.css public/components/InterfaceMapper.jsx public/components/PolicyTable.jsx public/components/PolicyDependencyGraph.jsx public/components/layout/RightPanel.jsx public/components/RoutingEditor.jsx tests/brand-color-semantics.test.js
git commit -m "fix(brand): reserve plum for model activity"
```

---

### Task 5: Shared Report Identity and HTML Migration Report

**Files:**
- Modify: `public/utils/brand.js`
- Create: `tests/report-branding.test.js`
- Modify: `public/utils/report-generator.js`

**Interfaces:**
- Consumes: `BRAND` and the authoritative M geometry.
- Produces: `BRAND_COLORS` frozen object and `reportBrandLockup() -> string` for both report generators.

- [ ] **Step 1: Write the failing standard-report identity test**

```js
// tests/report-branding.test.js
import { describe, expect, it } from 'vitest';
import { generateReportHtml } from '../public/utils/report-generator.js';

const reportInput = {
  sourceVendor:'panos', sourceModel:'PA-440', targetModel:'SRX1600', siteName:'branch-a',
  intermediateConfig:{ zones:[], interfaces:[], security_policies:[], nat_rules:[], address_objects:[], service_objects:[], static_routes:[] },
};

describe('Mechub report branding', () => {
  it('brands the self-contained HTML migration report', () => {
    const html = generateReportHtml(reportInput);
    expect(html).toContain('class="mechub-report-mark"');
    expect(html).toContain('M18,96 L18,32 L60,74 L102,32 L102,96');
    expect(html).toContain('firewall<span class="brand-intent">intent</span>converter');
    expect(html).toContain('a mechub project');
    expect(html).toContain('#0B0D12');
    expect(html).toContain('#4DD0C8');
    expect(html).toContain('#90C641');
    expect(html).not.toContain('Generated by Firewall Intent Converter');
    expect(html).not.toMatch(/<svg[^>]+(?:href|src)=|<script/i);
  });
});
```

- [ ] **Step 2: Run the report test and confirm legacy-brand failure**

Run: `npx vitest run tests/report-branding.test.js`

Expected: FAIL because the report has no M lockup and still uses the legacy product footer/palette.

- [ ] **Step 3: Add safe shared report primitives**

Append to `public/utils/brand.js`:

```js
export const BRAND_COLORS = Object.freeze({
  ink0:'#0B0D12', ink1:'#12151C', ink2:'#171A22', border:'#262B38',
  text1:'#F8F9FA', text2:'#C9CED5', text3:'#9AA2AD', teal:'#4DD0C8',
  tealDeep:'#0D9488', plum:'#7C3AED', plumLight:'#C4B5FD', juniper:'#90C641',
  success:'#34D399', warning:'#FBBF24', error:'#F87171', info:'#60A5FA',
});

export function reportBrandLockup() {
  return `<div class="report-brand" aria-label="${BRAND.accessibleName}">
    <svg class="mechub-report-mark" viewBox="0 0 120 120" aria-hidden="true">
      <path d="M18,96 L18,32 L60,74 L102,32 L102,96" fill="none" stroke="#0D9488" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="18" cy="96" r="7" fill="#0D9488"/><circle cx="18" cy="32" r="7" fill="#0D9488"/><circle cx="102" cy="32" r="7" fill="#0D9488"/><circle cx="102" cy="96" r="7" fill="#0D9488"/><circle cx="60" cy="74" r="11" fill="#0D9488"/><circle cx="60" cy="74" r="5.5" fill="#B7F5F0"/>
    </svg>
    <span class="report-brand-name">firewall<span class="brand-intent">intent</span>converter</span><span class="report-endorsement"> · ${BRAND.endorsement}</span>
  </div>`;
}
```

The helper accepts no user-controlled strings and contains no scripts or external references.

- [ ] **Step 4: Apply the identity and palette to `generateReportHtml`**

Import `BRAND`, `BRAND_COLORS as B`, and `reportBrandLockup`. Replace the dark report core with `B.ink0`, `B.ink1`, `B.ink2`, `B.border`, `B.text1`, `B.text2`, `B.text3`, and `B.teal`. Add these report-lockup rules:

```css
.report-brand{display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:8px;font-family:'Geist Variable','Inter',system-ui,sans-serif}
.mechub-report-mark{width:34px;height:34px}.report-brand-name{font-weight:700;letter-spacing:-.045em}.brand-intent{color:#7C3AED}.report-endorsement{color:#6B7280;font:500 10px 'Geist Mono Variable',monospace}
```

Render `${reportBrandLockup()}` before the report `<h1>`, keep the descriptive “Firewall migration report” heading, and replace the footer with:

```js
`Generated by ${BRAND.product} &middot; ${BRAND.endorsement} &mdash; ${esc(now)}`
```

- [ ] **Step 5: Run the standard-report contract and escaping tests**

Run:

```bash
npx vitest run tests/report-branding.test.js tests/conversion-security.test.js
```

Expected: all tests PASS; report input remains escaped.

- [ ] **Step 6: Commit shared report identity**

```bash
git add public/utils/brand.js public/utils/report-generator.js tests/report-branding.test.js
git commit -m "feat(brand): brand HTML migration reports"
```

---

### Task 6: Branded Full PDF Report and Unified Model Semantics

**Files:**
- Modify: `tests/report-branding.test.js`
- Modify: `public/utils/pdf-report-generator.js`

**Interfaces:**
- Consumes: `BRAND`, `BRAND_COLORS`, and `reportBrandLockup()` from Task 5.
- Produces: unchanged `generateFullPdfHtml(data) -> string` API with brand-compliant presentation.

- [ ] **Step 1: Extend the test with the full PDF report contract**

```js
import { generateFullPdfHtml } from '../public/utils/pdf-report-generator.js';

it.each([false, true])('brands the full PDF report with provider-neutral plum (local=%s)', isLocalLLM => {
  const html = generateFullPdfHtml({
    ...reportInput,
    configText:'set system host-name branch-a',
    srxTranslatedPolicies:[],
    srxOutput:{ format:'set', commands:['set system host-name branch-a'] },
    outputFormat:'set',
    isLocalLLM,
  });
  expect(html).toContain('class="mechub-report-mark"');
  expect(html).toContain('firewall<span class="brand-intent">intent</span>converter');
  expect(html).toContain('a mechub project');
  expect(html).toContain('#7C3AED');
  expect(html).toContain('#90C641');
  expect(html).not.toContain('#a78bfa');
  expect(html).not.toContain('#db2777');
  expect(html).not.toContain('Generated by Firewall Intent Converter');
});
```

- [ ] **Step 2: Run the PDF cases and confirm current-brand failures**

Run: `npx vitest run tests/report-branding.test.js`

Expected: the standard-report case PASS and both PDF cases FAIL on missing lockup and legacy cloud/local colors.

- [ ] **Step 3: Replace the PDF color constants and provider color split**

Import the Task 5 brand exports and replace `C` with:

```js
const C = {
  llmCloud:B.plum, llmCloudBg:'rgba(124,58,237,.10)',
  llmLocal:B.plum, llmLocalBg:'rgba(124,58,237,.10)',
  caution:'#B45309', cautionBg:'rgba(180,83,9,.10)',
  juniper:B.juniper, juniperBg:'rgba(144,198,65,.10)',
  accent:B.tealDeep, success:'#047857', error:'#B91C1C', muted:'#6B7280', info:'#1D4ED8',
};
```

Keep “LLM / Cloud” and “Local LLM” labels for provider clarity, but render both with the same plum. Replace LAG pill purple with `C.info` and a pale information background because LAG is not model activity.

- [ ] **Step 4: Add the lockup and print-safe type hierarchy**

Render `${reportBrandLockup()}` before the PDF `<h1>`, add the same lockup CSS with `B.plum` for `.brand-intent`, use Geist/Geist Mono first in report font stacks, and change the footer to `Generated by ${BRAND.product} &middot; ${BRAND.endorsement}`. Preserve `window.print()`, escaping, section order, page breaks, and output rendering.

- [ ] **Step 5: Run report and conversion-output tests**

Run:

```bash
npx vitest run tests/report-branding.test.js tests/conversion-output.test.js tests/conversion-consumers.test.js
```

Expected: all tests PASS.

- [ ] **Step 6: Commit PDF branding**

```bash
git add public/utils/pdf-report-generator.js tests/report-branding.test.js
git commit -m "feat(brand): brand full PDF reports"
```

---

### Task 7: Completion Audit, Builds, and Rendered Verification

**Files:**
- Verify: all files named in Tasks 1–6
- Inspect and refresh if the checked-in captures remain stale: `docs/images/source-chooser.png`, `docs/images/policy-review.png`

**Interfaces:**
- Consumes: the finished application, standard report, and full PDF report.
- Produces: evidence that all ten design acceptance criteria hold; no runtime API changes.

- [ ] **Step 1: Run the complete automated suite**

Run: `npx vitest run`

Expected: all 22 baseline files plus the five new branding test files PASS; the test count is greater than the 1,017-test baseline with zero failures.

- [ ] **Step 2: Build both distribution forms from a clean output state**

Run:

```bash
rm -rf dist dist-standalone
npm run build
npm run build:standalone
```

Expected: both commands exit 0. `find dist dist-standalone -type f` shows each build’s `brand/mechub-*.svg`, both `licenses/*-OFL-1.1.txt` files, and emitted `.woff2` assets.

- [ ] **Step 3: Audit source and build output for obsolete identity**

Run:

```bash
rg -n "/logo\.png|Firewall Policy to Intent Converter|Firewall Policy Converter|Generated by Firewall Intent Converter|🔥|#a78bfa|#db2777|#be185d" public static index.html standalone dist dist-standalone
```

Expected: no matches. Product descriptions that use the generic domain phrase “firewall policy converter” are reviewed separately and are not visible product lockups.

- [ ] **Step 4: Verify asset resolution and offline references**

Run:

```bash
rg -n "mechub-(mark|favicon)|Geist" dist dist-standalone
rg -n "fonts\.googleapis|fonts\.gstatic|https://command\.mechub\.org/branding" dist dist-standalone
```

Expected: the first command finds local brand/font references; the second finds no runtime network references.

- [ ] **Step 5: Inspect dark, light, constrained, and populated application states**

Start the app with `npm run dev -- --port 4173`. In Firefox:

1. At `http://127.0.0.1:4173`, select dark theme and inspect 1440×900: gradient M, lowercase lockup, ink surfaces, Geist typography, pill controls, and no clipped top-bar actions.
2. Select light theme at 1440×900: deep-teal M, accessible teal/plum/Juniper text, and no primary mark on a light surface.
3. Resize to 1100×800: endorsement hidden, M and product name present, statistics/actions usable.
4. Load a built-in PAN-OS sample, parse it, choose PA-440 → SRX1600, and inspect Policies after LLM review or the deterministic equivalent: plum occurs only on model content, SRX data is Juniper green, warning/success colors remain distinct, and the table density is intact.
5. Open both report types: M lockup and endorsement present, report content unchanged, print preview legible without relying on color.

Save temporary screenshots outside the repository for dark, light, constrained, and populated evidence. Refresh the two committed README screenshots only if their old generic icon/legacy lockup makes the documentation materially misleading.

- [ ] **Step 6: Inspect accessibility behavior**

Using Firefox keyboard navigation, tab through the top bar, source chooser, modal controls, and workflow actions. Expected: every actionable control has a visible teal focus ring, compact controls retain at least a 28 px box, the decorative M is not announced separately from the accessible lockup, theme switching persists, and reduced-motion mode adds no logo animation.

- [ ] **Step 7: Review the final diff and commit any verification-only corrections**

Run:

```bash
git diff --check
git status --short
git diff --stat origin/main...HEAD
```

Expected: no whitespace errors or unintended generated build outputs. If visual verification required CSS or screenshot corrections, stage only those corrections and commit with:

```bash
git add public/styles public/components docs/images
git commit -m "fix(brand): resolve visual verification findings"
```

If no corrections were needed, do not create an empty commit.

---

## Final Acceptance Mapping

| Design criterion | Evidence |
| --- | --- |
| Official M replaces generic icon | Tasks 1–2 asset and lockup tests; rendered top bar; obsolete-reference audit |
| Official lowercase product identity | Task 2 SSR test; both HTML metadata files; report tests |
| Geist works offline | Task 1 pinned dependencies, license, build output WOFF2 inspection |
| Both themes use approved roles | Task 3 token contract; Task 7 dark/light renders |
| Mono-pill shared controls preserve density | Task 3 CSS contract; Task 7 populated/constrained renders |
| Plum only marks models; Juniper is not success | Task 4 regression scan; Task 6 report cases; populated render |
| HTML/PDF reports share identity | Tasks 5–6 tests and report inspection |
| No behavior/accessibility regression | Full Vitest suite and Task 7 keyboard/reduced-motion checks |
| Standard and standalone builds pass | Tasks 1 and 7 clean builds |
| Representative renders have no defects | Task 7 four-state visual inspection |

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

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

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

export const BRAND_COLORS = Object.freeze({
  ink0: '#0B0D12',
  ink1: '#12151C',
  ink2: '#171A22',
  border: '#262B38',
  text1: '#F8F9FA',
  text2: '#C9CED5',
  text3: '#9AA2AD',
  teal: '#4DD0C8',
  tealDeep: '#0D9488',
  plum: '#7C3AED',
  plumLight: '#C4B5FD',
  juniper: '#90C641',
  success: '#34D399',
  warning: '#FBBF24',
  error: '#F87171',
  info: '#60A5FA',
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

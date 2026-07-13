import React from 'react';

export function readProjectSecurityDescriptor(getDescriptor) {
  try {
    return typeof getDescriptor === 'function' ? getDescriptor() : null;
  } catch {
    return null;
  }
}

export default function ProjectSecurityBadge({ mode, descriptor }) {
  const liveSanitized = descriptor?.mode === 'sanitized'
    && descriptor?.sanitizedEligible === true;
  const safe = mode === 'sanitized' && liveSanitized;
  const reversible = mode === 'reversible-encrypted'
    && liveSanitized
    && descriptor?.reversibleAvailable === true;
  const copy = mode === 'legacy-secret-bearing'
    ? 'Legacy secret-bearing — sensitive'
    : reversible
      ? 'Encrypted reversible — sensitive'
      : safe
        ? 'Sanitized — safe to share'
        : 'Unsanitized or stale — sensitive';
  return (
    <div
      className={`project-security-badge project-security-badge--${safe && !reversible ? 'safe' : 'danger'}`}
      role="status"
      aria-label={`Workspace security: ${copy}`}
    >
      {copy}
    </div>
  );
}

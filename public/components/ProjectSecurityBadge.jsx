import React from 'react';

export function readProjectSecurityDescriptor(getDescriptor) {
  try {
    return typeof getDescriptor === 'function' ? getDescriptor() : null;
  } catch {
    return null;
  }
}

export default function ProjectSecurityBadge({ mode, descriptor }) {
  const safe = descriptor?.mode === 'sanitized'
    && descriptor?.sanitizedEligible === true;
  const reversible = safe
    && mode === 'reversible-encrypted'
    && descriptor?.reversibleAvailable === true;
  const copy = reversible
    ? 'Encrypted reversible — sensitive'
    : safe
      ? 'Sanitized — safe to share'
      : mode === 'legacy-secret-bearing'
        ? 'Legacy secret-bearing — sensitive'
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

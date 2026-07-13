import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import SaveProjectModal, {
  deriveProjectExportFormState,
} from '../public/components/SaveProjectModal.jsx';
import ProjectSecurityImportModal, {
  deriveProjectImportFormState,
  ProjectSecurityNotice,
} from '../public/components/ProjectSecurityImportModal.jsx';
import ProjectSecurityBadge, {
  readProjectSecurityDescriptor,
} from '../public/components/ProjectSecurityBadge.jsx';
import { classifyProjectSecurity } from '../public/utils/project-security.js';

const exportInput = {
  descriptor: { sanitizedEligible: true, reversibleAvailable: true },
  cryptoAvailable: true,
  mode: 'sanitized',
  name: 'branch',
  passphrase: '',
  confirmationPassphrase: '',
  acknowledgement: false,
  unsanitizedConfirmation: '',
};

describe('project security UI', () => {
  it.each([
    ['sanitized', { mode: 'sanitized', sanitizedEligible: true, reversibleAvailable: false }, 'Sanitized — safe to share', true],
    ['reversible-encrypted', { mode: 'sanitized', sanitizedEligible: true, reversibleAvailable: true }, 'Encrypted reversible — sensitive', false],
    ['unsanitized', { mode: 'unsanitized', sanitizedEligible: false, reversibleAvailable: false }, 'Unsanitized or stale — sensitive', false],
    ['legacy-secret-bearing', { mode: 'unsanitized', sanitizedEligible: false, reversibleAvailable: false }, 'Legacy secret-bearing — sensitive', false],
    ['future-unknown-mode', null, 'Unsanitized or stale — sensitive', false],
  ])('renders persistent workspace classification for %s', (mode, descriptor, copy, safe) => {
    const html = renderToStaticMarkup(
      <ProjectSecurityBadge mode={mode} descriptor={descriptor} />,
    );
    expect(html).toContain(copy);
    if (safe) expect(html).toContain('safe to share');
    else expect(html).not.toMatch(/>[^<]*safe to share[^<]*</);
  });

  it.each([
    ['config text', { configText: 'set system host-name retained' }],
    ['intermediate config', { intermediateConfig: { metadata: {} } }],
    ['generated collection', { srxTranslatedPolicies: [{ name: 'retained-rule' }] }],
    ['editable collection', { ruleGroups: [{ name: 'retained-group' }] }],
    ['mapping', { interfaceMappings: { ethernet1: 'ge-0/0/0' } }],
    ['greenfield state', { greenfieldMode: true, greenfieldTemplate: { hostname: 'retained' } }],
  ])('never labels sanitized top-level state safe when a retained %s slot is unsanitized', (_label, populated) => {
    const descriptor = classifyProjectSecurity({
      configText: 'set system host-name SANITIZED_HOST_0',
      intermediateConfig: { metadata: {} },
      isSanitized: true,
      mergeMode: false,
      configSlots: [{
        configText: '',
        intermediateConfig: null,
        isSanitized: false,
        ...populated,
      }],
    });
    expect(descriptor.sanitizedEligible).toBe(false);
    const html = renderToStaticMarkup(
      <ProjectSecurityBadge mode="sanitized" descriptor={descriptor} />,
    );
    expect(html).toContain('Unsanitized or stale — sensitive');
    expect(html).not.toMatch(/>[^<]*safe to share[^<]*</);
  });

  it('fails badge descriptor errors conservatively to sensitive/stale', () => {
    const descriptor = readProjectSecurityDescriptor(() => {
      throw new Error('descriptor internals must not escape');
    });
    const html = renderToStaticMarkup(
      <ProjectSecurityBadge mode="sanitized" descriptor={descriptor} />,
    );
    expect(descriptor).toBeNull();
    expect(html).toContain('Unsanitized or stale — sensitive');
    expect(html).not.toContain('safe to share');
  });
  it('defaults eligible workspaces to irreversible sanitized export', () => {
    const state = deriveProjectExportFormState(exportInput);

    expect(state.allowedModes).toEqual(['sanitized', 'reversible-encrypted']);
    expect(state.mode).toBe('sanitized');
    expect(state.canSubmit).toBe(true);
    expect(state.filenameSuffix).toBe('.sanitized.fpic.json');
  });

  it('forces export modes from descriptor and crypto eligibility', () => {
    expect(deriveProjectExportFormState({
      ...exportInput,
      descriptor: { sanitizedEligible: true, reversibleAvailable: false },
      mode: 'unsanitized',
    })).toMatchObject({ allowedModes: ['sanitized'], mode: 'sanitized' });

    expect(deriveProjectExportFormState({
      ...exportInput,
      cryptoAvailable: false,
      mode: 'reversible-encrypted',
    })).toMatchObject({ allowedModes: ['sanitized'], mode: 'sanitized' });

    expect(deriveProjectExportFormState({
      ...exportInput,
      descriptor: { sanitizedEligible: false, reversibleAvailable: true },
      mode: 'sanitized',
      unsanitizedConfirmation: 'EXPORT UNSANITIZED',
    })).toMatchObject({ allowedModes: ['unsanitized'], mode: 'unsanitized', canSubmit: true });
  });

  it('requires passphrase confirmation and no-recovery acknowledgement', () => {
    const base = {
      ...exportInput,
      mode: 'reversible-encrypted',
      passphrase: 'correct horse battery staple',
      confirmationPassphrase: 'correct horse battery staple',
    };

    expect(deriveProjectExportFormState(base).canSubmit).toBe(false);
    expect(deriveProjectExportFormState({ ...base, acknowledgement: true }).canSubmit).toBe(true);
    expect(deriveProjectExportFormState({
      ...base,
      confirmationPassphrase: 'different horse battery staple',
      acknowledgement: true,
    }).canSubmit).toBe(false);
  });

  it('validates reversible passphrases by code points and UTF-8 bytes', () => {
    const reversible = {
      ...exportInput,
      mode: 'reversible-encrypted',
      acknowledgement: true,
    };
    const sixteenCodePoints = '🛡️'.repeat(8);
    const oversizedUtf8 = '🛡'.repeat(257);

    expect(deriveProjectExportFormState({
      ...reversible,
      passphrase: sixteenCodePoints,
      confirmationPassphrase: sixteenCodePoints,
    }).canSubmit).toBe(true);
    expect(deriveProjectExportFormState({
      ...reversible,
      passphrase: oversizedUtf8,
      confirmationPassphrase: oversizedUtf8,
    }).canSubmit).toBe(false);
  });

  it('requires typed confirmation for unsanitized export', () => {
    const state = deriveProjectExportFormState({
      ...exportInput,
      descriptor: { sanitizedEligible: false, reversibleAvailable: false },
      mode: 'unsanitized',
      unsanitizedConfirmation: 'EXPORT UNSANITIZED',
    });

    expect(state.canSubmit).toBe(true);
    expect(state.filenameSuffix).toBe('.unsanitized.fpic.json');
  });

  it('requires acknowledgement and a passphrase for encrypted import', () => {
    const base = {
      descriptor: { kind: 'reversible-encrypted' },
      passphrase: '',
      acknowledgement: false,
    };

    expect(deriveProjectImportFormState(base)).toMatchObject({
      mode: 'reversible-encrypted',
      canSubmit: false,
    });
    expect(deriveProjectImportFormState({
      ...base,
      passphrase: 'correct horse battery staple',
    }).canSubmit).toBe(false);
    expect(deriveProjectImportFormState({
      ...base,
      passphrase: 'correct horse battery staple',
      acknowledgement: true,
    }).canSubmit).toBe(true);
  });

  it('derives dangerous import modes only from the inspected descriptor', () => {
    expect(deriveProjectImportFormState({
      descriptor: { mode: 'unsanitized' },
      mode: 'sanitized',
      passphrase: '',
      acknowledgement: false,
    })).toMatchObject({ mode: 'unsanitized', canSubmit: false });

    expect(deriveProjectImportFormState({
      descriptor: { security: { mode: 'legacy-secret-bearing' } },
      passphrase: '',
      acknowledgement: true,
    })).toMatchObject({ mode: 'legacy-secret-bearing', canSubmit: true });

    expect(deriveProjectImportFormState({
      descriptor: { mode: 'sanitized' },
      passphrase: '',
      acknowledgement: false,
    })).toMatchObject({ mode: 'sanitized', canSubmit: true });
  });

  it('renders unambiguous unsanitized export warnings', () => {
    const exportHtml = renderToStaticMarkup(
      <SaveProjectModal
        defaultName="branch"
        descriptor={{ sanitizedEligible: false, reversibleAvailable: false }}
        cryptoAvailable
        onExport={() => {}}
        onSanitizeFirst={() => {}}
        onClose={() => {}}
      />,
    );

    expect(exportHtml).toContain('Unsanitized');
    expect(exportHtml).toContain('contains sensitive data');
    expect(exportHtml).toContain('EXPORT UNSANITIZED');
    expect(exportHtml).toContain('Sanitize before export');
    expect(exportHtml).not.toContain('safe to share');
  });

  it('derives sanitize-first routing without changing sanitization state', async () => {
    const localStorageDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      value: { getItem: () => null },
    });
    let deriveSanitizeFirstActions;
    try {
      ({ deriveSanitizeFirstActions } = await import('../public/app.jsx'));
    } finally {
      if (localStorageDescriptor) {
        Object.defineProperty(globalThis, 'localStorage', localStorageDescriptor);
      } else {
        delete globalThis.localStorage;
      }
    }

    expect(deriveSanitizeFirstActions()).toEqual([
      { type: 'HIDE_MODAL', name: 'saveModal' },
      { type: 'SET_FIELD', field: 'editTab', value: 'import' },
    ]);
  });

  it('renders safe-to-share sanitized export and precise reversible requirements', () => {
    const html = renderToStaticMarkup(
      <SaveProjectModal
        defaultName="branch"
        descriptor={{ sanitizedEligible: true, reversibleAvailable: true }}
        cryptoAvailable
        onExport={() => {}}
        onSanitizeFirst={() => {}}
        onClose={() => {}}
      />,
    );

    expect(html).toContain('Irreversible sanitized');
    expect(html).toContain('safe to share');
    expect(html).toContain('restoration data are removed');
    expect(html).toContain('Encrypted reversible');
    expect(html).toContain('No passphrase recovery');
    expect(html).toContain('16 Unicode code points');
    expect(html).toContain('.sanitized.fpic.json');
  });

  it('renders the sanitized security notice used by live load confirmation', () => {
    const html = renderToStaticMarkup(
      <ProjectSecurityNotice descriptor={{ mode: 'sanitized' }} />,
    );

    expect(html).toContain('Irreversible sanitized project');
    expect(html).toContain('safe to share');
    expect(html).toContain('No restoration data');
  });

  it.each([
    'reversible-encrypted',
    'unsanitized',
    'legacy-secret-bearing',
  ])('never labels the dangerous %s notice safe to share', mode => {
    const html = renderToStaticMarkup(
      <ProjectSecurityNotice descriptor={{ mode }} />,
    );

    expect(html).not.toContain('safe to share');
  });

  it.each([
    ['sanitized', 'Irreversible sanitized project', 'No restoration data'],
    ['reversible-encrypted', 'Encrypted reversible project', 'No passphrase recovery'],
    ['unsanitized', 'Unsanitized sensitive project', 'contains sensitive data'],
    ['legacy-secret-bearing', 'Legacy plaintext restoration data', 'plaintext restoration'],
  ])('renders explicit %s import copy', (mode, heading, warning) => {
    const html = renderToStaticMarkup(
      <ProjectSecurityImportModal
        descriptor={{ mode }}
        onConfirm={() => {}}
        onClose={() => {}}
      />,
    );

    expect(html).toContain(heading);
    expect(html).toContain(warning);
    if (mode !== 'sanitized') expect(html).toContain('acknowledge');
    if (mode === 'sanitized') {
      expect(html).toContain('safe to share');
    } else {
      expect(html).not.toContain('safe to share');
    }
  });
});

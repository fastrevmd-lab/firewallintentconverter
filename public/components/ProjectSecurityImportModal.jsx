import React, { useEffect, useRef, useState } from 'react';

const SANITIZED = 'sanitized';
const REVERSIBLE = 'reversible-encrypted';
const UNSANITIZED = 'unsanitized';
const LEGACY = 'legacy-secret-bearing';
const KNOWN_MODES = new Set([SANITIZED, REVERSIBLE, UNSANITIZED, LEGACY]);

function descriptorMode(descriptor) {
  const candidates = [descriptor?.kind, descriptor?.mode, descriptor?.security?.mode];
  return candidates.find(mode => KNOWN_MODES.has(mode)) || UNSANITIZED;
}

export function deriveProjectImportFormState(input = {}) {
  const mode = descriptorMode(input.descriptor);
  const requiresAcknowledgement = mode !== SANITIZED;
  const requiresPassphrase = mode === REVERSIBLE;
  const passphrase = typeof input.passphrase === 'string' ? input.passphrase : '';

  return {
    mode,
    requiresAcknowledgement,
    requiresPassphrase,
    canSubmit: (!requiresAcknowledgement || input.acknowledgement === true)
      && (!requiresPassphrase || passphrase.length > 0),
  };
}

const IMPORT_COPY = {
  [SANITIZED]: {
    title: 'Irreversible sanitized project',
    warning: 'No restoration data or original values are included. This project is safe to share, but loading cannot restore removed originals.',
    acknowledgement: '',
  },
  [REVERSIBLE]: {
    title: 'Encrypted reversible project',
    warning: 'This file contains encrypted restoration data. No passphrase recovery is available.',
    acknowledgement: 'I acknowledge the encrypted-file warning and that a lost passphrase cannot be recovered.',
  },
  [UNSANITIZED]: {
    title: 'Unsanitized sensitive project',
    warning: 'This project contains sensitive data in plaintext and must be handled as a sensitive file.',
    acknowledgement: 'I acknowledge that this project contains sensitive data and want to continue.',
  },
  [LEGACY]: {
    title: 'Legacy plaintext restoration data',
    warning: 'This legacy project contains a plaintext restoration table with original sensitive values.',
    acknowledgement: 'I acknowledge the legacy plaintext restoration-data risk and want to continue.',
  },
};

export function ProjectSecurityNotice({ descriptor }) {
  const mode = descriptorMode(descriptor);
  const copy = IMPORT_COPY[mode];

  return (
    <section className={`project-security-import project-security-import--${mode}`}>
      <h3>{copy.title}</h3>
      <p>{copy.warning}</p>
    </section>
  );
}

export default function ProjectSecurityImportModal({ descriptor, onConfirm, onClose }) {
  const [passphrase, setPassphrase] = useState('');
  const [acknowledgement, setAcknowledgement] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const passphraseRef = useRef('');
  const form = deriveProjectImportFormState({ descriptor, passphrase, acknowledgement });
  const copy = IMPORT_COPY[form.mode];

  useEffect(() => () => {
    passphraseRef.current = '';
  }, []);

  const updatePassphrase = value => {
    passphraseRef.current = value;
    setPassphrase(value);
  };

  const submit = async () => {
    if (!form.canSubmit || submitting) return;
    setSubmitting(true);
    try {
      await onConfirm({ passphrase, acknowledgement });
    } finally {
      passphraseRef.current = '';
      setPassphrase('');
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content project-security-modal"
        onClick={event => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="project-import-title"
      >
        <div className="modal-header">
          <h2 id="project-import-title">Review Project Security</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">&times;</button>
        </div>
        <div className="modal-body project-security-body">
          <ProjectSecurityNotice descriptor={descriptor} />

          {form.requiresPassphrase && (
            <label className="project-security-field">
              <span>Project passphrase</span>
              <input
                type="password"
                value={passphrase}
                onChange={event => updatePassphrase(event.target.value)}
                className="input-field"
                autoComplete="current-password"
                autoFocus
              />
            </label>
          )}

          {form.requiresAcknowledgement && (
            <label className="project-security-acknowledgement">
              <input
                type="checkbox"
                checked={acknowledgement}
                onChange={event => setAcknowledgement(event.target.checked)}
              />
              <span>{copy.acknowledgement}</span>
            </label>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-primary"
            onClick={submit}
            disabled={!form.canSubmit || submitting}
          >
            {submitting ? 'Opening…' : 'Continue to Project Review'}
          </button>
        </div>
      </div>
    </div>
  );
}

import React, { useEffect, useRef, useState } from 'react';

const SANITIZED = 'sanitized';
const REVERSIBLE = 'reversible-encrypted';
const UNSANITIZED = 'unsanitized';
const UNSANITIZED_CONFIRMATION = 'EXPORT UNSANITIZED';
const textEncoder = new TextEncoder();

export function deriveProjectExportFormState(input = {}) {
  const descriptor = input.descriptor && typeof input.descriptor === 'object'
    ? input.descriptor
    : {};
  const allowedModes = descriptor.sanitizedEligible === true
    ? [
      SANITIZED,
      ...(descriptor.reversibleAvailable === true && input.cryptoAvailable === true
        ? [REVERSIBLE]
        : []),
    ]
    : [UNSANITIZED];
  const mode = allowedModes.includes(input.mode) ? input.mode : allowedModes[0];
  const name = typeof input.name === 'string' ? input.name : '';
  const passphrase = typeof input.passphrase === 'string' ? input.passphrase : '';
  const confirmationPassphrase = typeof input.confirmationPassphrase === 'string'
    ? input.confirmationPassphrase
    : '';
  const validName = name.trim().length > 0;
  const reversibleReady = Array.from(passphrase).length >= 16
    && textEncoder.encode(passphrase).length <= 1024
    && passphrase === confirmationPassphrase
    && input.acknowledgement === true;
  const unsanitizedReady = input.unsanitizedConfirmation === UNSANITIZED_CONFIRMATION;

  return {
    allowedModes,
    mode,
    canSubmit: validName && (
      mode === SANITIZED
      || mode === REVERSIBLE && reversibleReady
      || mode === UNSANITIZED && unsanitizedReady
    ),
    filenameSuffix: mode === SANITIZED
      ? '.sanitized.fpic.json'
      : mode === REVERSIBLE
        ? '.reversible.fpic.enc.json'
        : '.unsanitized.fpic.json',
  };
}

const MODE_COPY = {
  [SANITIZED]: {
    title: 'Irreversible sanitized',
    description: 'Original values and restoration data are removed. This irreversible export is safe to share.',
  },
  [REVERSIBLE]: {
    title: 'Encrypted reversible',
    description: 'Restoration data is encrypted. Use matching passphrases of at least 16 Unicode code points. No passphrase recovery is available.',
  },
  [UNSANITIZED]: {
    title: 'Unsanitized — contains sensitive data',
    description: 'This raw or mixed workspace may expose credentials, addresses, and network details.',
  },
};

export default function SaveProjectModal({
  defaultName,
  descriptor,
  cryptoAvailable,
  onExport,
  onSanitizeFirst,
  onClose,
}) {
  const [name, setName] = useState(defaultName);
  const [mode, setMode] = useState(
    descriptor?.sanitizedEligible === true ? SANITIZED : UNSANITIZED,
  );
  const [passphrase, setPassphrase] = useState('');
  const [confirmationPassphrase, setConfirmationPassphrase] = useState('');
  const [acknowledgement, setAcknowledgement] = useState(false);
  const [unsanitizedConfirmation, setUnsanitizedConfirmation] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const passphraseRef = useRef('');
  const confirmationPassphraseRef = useRef('');

  useEffect(() => () => {
    passphraseRef.current = '';
    confirmationPassphraseRef.current = '';
  }, []);

  const form = deriveProjectExportFormState({
    descriptor,
    cryptoAvailable,
    mode,
    name,
    passphrase,
    confirmationPassphrase,
    acknowledgement,
    unsanitizedConfirmation,
  });

  const updatePassphrase = value => {
    passphraseRef.current = value;
    setPassphrase(value);
  };

  const updateConfirmationPassphrase = value => {
    confirmationPassphraseRef.current = value;
    setConfirmationPassphrase(value);
  };

  const submit = async () => {
    if (!form.canSubmit || submitting) return;
    setSubmitting(true);
    try {
      await onExport({
        name: name.trim(),
        mode: form.mode,
        passphrase,
        confirmationPassphrase,
        acknowledgement,
        confirmation: unsanitizedConfirmation,
      });
    } finally {
      passphraseRef.current = '';
      confirmationPassphraseRef.current = '';
      setPassphrase('');
      setConfirmationPassphrase('');
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
        aria-labelledby="project-export-title"
      >
        <div className="modal-header">
          <h2 id="project-export-title">Export Project</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">&times;</button>
        </div>
        <div className="modal-body project-security-body">
          <label className="project-security-field">
            <span>Project name</span>
            <input
              type="text"
              value={name}
              onChange={event => setName(event.target.value)}
              className="input-field"
              placeholder="my-firewall-project"
              autoFocus
              onKeyDown={event => {
                if (event.key === 'Enter') submit();
              }}
            />
          </label>

          <fieldset className="project-security-modes">
            <legend>Export security mode</legend>
            {form.allowedModes.map(allowedMode => (
              <label
                className={`project-security-mode project-security-mode--${allowedMode}`}
                key={allowedMode}
              >
                <input
                  type="radio"
                  name="project-security-export-mode"
                  value={allowedMode}
                  checked={form.mode === allowedMode}
                  onChange={() => setMode(allowedMode)}
                />
                <span>
                  <strong>{MODE_COPY[allowedMode].title}</strong>
                  <small>{MODE_COPY[allowedMode].description}</small>
                </span>
              </label>
            ))}
          </fieldset>

          {descriptor?.reversibleAvailable === true && cryptoAvailable !== true && (
            <p className="project-security-notice project-security-notice--warning">
              Encrypted reversible export is unavailable because Web Crypto is not available.
            </p>
          )}

          {form.mode === REVERSIBLE && (
            <div className="project-security-details project-security-details--encrypted">
              <p><strong>Encrypted reversible — No passphrase recovery</strong></p>
              <p>Use at least 16 Unicode code points. The UTF-8 encoded passphrase must not exceed 1024 bytes.</p>
              <label className="project-security-field">
                <span>Passphrase</span>
                <input
                  type="password"
                  value={passphrase}
                  onChange={event => updatePassphrase(event.target.value)}
                  className="input-field"
                  autoComplete="new-password"
                />
              </label>
              <label className="project-security-field">
                <span>Confirm passphrase</span>
                <input
                  type="password"
                  value={confirmationPassphrase}
                  onChange={event => updateConfirmationPassphrase(event.target.value)}
                  className="input-field"
                  autoComplete="new-password"
                />
              </label>
              <label className="project-security-acknowledgement">
                <input
                  type="checkbox"
                  checked={acknowledgement}
                  onChange={event => setAcknowledgement(event.target.checked)}
                />
                <span>I acknowledge that there is no passphrase recovery and losing it makes restoration impossible.</span>
              </label>
            </div>
          )}

          {form.mode === UNSANITIZED && (
            <div className="project-security-details project-security-details--danger">
              <p><strong>Unsanitized export contains sensitive data</strong></p>
              <p>This is the only raw or mixed export mode. Protect the resulting file as sensitive.</p>
              <label className="project-security-field">
                <span>Type <code>{UNSANITIZED_CONFIRMATION}</code> to continue</span>
                <input
                  type="text"
                  value={unsanitizedConfirmation}
                  onChange={event => setUnsanitizedConfirmation(event.target.value)}
                  className="input-field"
                  autoComplete="off"
                />
              </label>
              <button className="btn btn-secondary" type="button" onClick={onSanitizeFirst}>
                Sanitize before export
              </button>
            </div>
          )}

          <p className="project-security-filename">
            File suffix: <code>{form.filenameSuffix}</code>
          </p>
        </div>
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-primary"
            onClick={submit}
            disabled={!form.canSubmit || submitting}
          >
            {submitting ? 'Exporting…' : 'Export Project'}
          </button>
        </div>
      </div>
    </div>
  );
}

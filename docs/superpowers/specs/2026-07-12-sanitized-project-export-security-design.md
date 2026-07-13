# Sanitized Project Export Security Design

## Status

Approved design for GitHub issue #11, `security: prevent original secrets from leaking in sanitized project exports`.

## Problem

Version 4 project files serialize the complete application state, including every `sanitizationTable`. Each table entry retains an `original` value so the running application can restore selected placeholders for output and device operations. A project can therefore be labeled sanitized while its JSON file contains the exact values that sanitization was meant to remove. Merge slots can carry additional nested tables.

The current sanitizer also recognizes only a subset of supported password, pre-shared-key, SNMP, AAA, private-key, and certificate-secret syntax. Project export has no final recursive security boundary: any state field, warning, parsed object, output, or future nested field can reintroduce an original value immediately before download.

## Goals

- Make the default sanitized project export irreversible and safe to share.
- Ensure no restoration table or known original value appears anywhere in a sanitized file.
- Detect supported secret syntax in raw text and structured project state.
- Preserve reversible backups only as explicitly named, passphrase-protected authenticated ciphertext.
- Preserve plaintext unsanitized export only as an explicitly dangerous workflow.
- Make file metadata, import behavior, and UI copy distinguish the three formats unambiguously.
- Fail closed before download if sanitization, validation, encryption, or leak detection cannot prove the selected result safe.
- Cover ordinary and merge-mode projects, including every populated configuration slot.

## Non-goals

- No server-side key escrow, account recovery, cloud storage, or passphrase recovery.
- No automatic conversion of an already-parsed unsanitized workspace into a sanitized project during export.
- No automatic restoration of passwords, hashes, PSKs, SNMP communities, AAA secrets, or private keys into generated output.
- No silent upgrade of a legacy plaintext reversible file into an encrypted file.
- No change to firewall conversion semantics unrelated to secret handling.

## Security terminology

### Sanitized

A plaintext project whose populated source configurations were sanitized before parsing, whose restoration data has been removed recursively, and whose final serialized representation passes the export leak gate. It cannot restore removed originals after import.

### Reversible encrypted

An authenticated encrypted backup of a sanitized workspace, including its in-memory restoration data. The plaintext exists only during the explicit export or import operation. The file must never be described as sanitized or safe to share.

### Unsanitized

A plaintext project containing a raw, mixed, or otherwise unproven-safe workspace. It may contain secrets and other sensitive configuration data. Export requires an explicit typed confirmation.

### Legacy secret-bearing

An in-memory classification for version 1 through 4 files that claim sanitization while carrying a plaintext restoration table or other original-bearing state. It is not a valid version 5 export mode. Import requires a warning, and re-export must use one of the version 5 workflows.

## Project version 5

Version 5 requires security metadata. Version 5 plaintext and encrypted shapes are disjoint and strictly validated.

### Sanitized plaintext envelope

```json
{
  "fpic_version": 5,
  "name": "branch-migration",
  "savedAt": "2026-07-12T20:00:00.000Z",
  "security": {
    "schema": 1,
    "mode": "sanitized",
    "containsOriginals": false,
    "reversible": false,
    "restorationAvailable": false
  },
  "state": {}
}
```

The `state` object cannot contain a `sanitizationTable` property at any depth. Every current and nested `isSanitized` flag for a populated source is `true`. Restoration is unavailable after import.

### Unsanitized plaintext envelope

```json
{
  "fpic_version": 5,
  "name": "branch-migration",
  "savedAt": "2026-07-12T20:00:00.000Z",
  "security": {
    "schema": 1,
    "mode": "unsanitized",
    "containsOriginals": true,
    "reversible": false,
    "restorationAvailable": true
  },
  "state": {}
}
```

This is a plaintext snapshot of an unsanitized or mixed workspace. `restorationAvailable` is a strict boolean reflecting whether any validated restoration table is present in the snapshot; it is `false` when none is present. The exporter does not call the file reversible because no complete restoration contract is promised. It is intentionally secret-bearing and requires typed confirmation.

### Reversible encrypted envelope

```json
{
  "fpic_version": 5,
  "security": {
    "schema": 1,
    "mode": "reversible-encrypted",
    "containsOriginals": true,
    "reversible": true,
    "cipher": "AES-256-GCM",
    "tagBits": 128,
    "kdf": "PBKDF2-HMAC-SHA-256",
    "iterations": 600000,
    "salt": "base64-encoded-16-byte-value",
    "nonce": "base64-encoded-12-byte-value",
    "aadVersion": 1
  },
  "ciphertext": "base64-encoded-ciphertext-and-tag"
}
```

The outer envelope contains neither `name`, `savedAt`, nor `state`. Those fields are inside the ciphertext. The schema allows no unknown outer or security fields. Base64 must be canonical and decode to the exact required salt and nonce lengths. Ciphertext must be non-empty.

The decrypted plaintext has this strict shape and no unknown top-level fields:

```json
{
  "payloadSchema": 1,
  "name": "branch-migration",
  "savedAt": "2026-07-12T20:00:00.000Z",
  "sourceMode": "sanitized",
  "state": {}
}
```

`sourceMode` is exactly `sanitized` in schema 1 because reversible export is available only from an eligible sanitized workspace. The decrypted `state` can contain validated restoration tables. This plaintext object is not accepted as a standalone project file; only the authenticated encrypted envelope can carry it.

## Cryptographic boundary

- Web Crypto is the only cryptographic implementation. There is no custom cipher and no plaintext fallback.
- The writer derives a non-extractable 256-bit AES-GCM key from the UTF-8 passphrase using PBKDF2-HMAC-SHA-256, a fresh 16-byte random salt, and exactly 600,000 iterations.
- The writer generates a fresh 12-byte AES-GCM nonce for every export and uses a 128-bit authentication tag.
- `buildProjectAadBytes()` constructs a new insertion-ordered object containing `fpic_version` and every `security` field in the order shown above, including the canonical base64 `salt` and `nonce`, but excluding `ciphertext`. UTF-8 `JSON.stringify` bytes of that object are the AES-GCM additional data. Any metadata change therefore invalidates authentication.
- The passphrase must contain at least 16 Unicode code points and encode to no more than 1,024 UTF-8 bytes. Confirmation must match exactly.
- Passphrases, imported key material, and derived keys are local variables in the modal operation. They are never written to application context, browser storage, logs, URLs, analytics, errors, or files.
- Wrong passphrase, altered metadata, altered nonce, altered salt, truncated ciphertext, or altered ciphertext produces the same fixed local decryption error.
- The decrypted bytes must be valid UTF-8, parse as the strict `payloadSchema: 1` reversible payload above, and produce state that passes ordinary version 5 project validation before any context is mutated.
- If `globalThis.crypto`, `crypto.getRandomValues`, or `crypto.subtle` is unavailable, the reversible option is disabled. The application never downgrades to plaintext.
- There is no passphrase recovery mechanism.

## Resource limits

- Maximum serialized plaintext project or decrypted reversible payload: `48 * 1024 * 1024` UTF-8 bytes.
- Maximum imported project file, including base64 expansion: `65 * 1024 * 1024` bytes.
- Maximum recursive state depth: 128 containers.
- Maximum recursive state nodes: 1,000,000 values, counting every object, array, key value, and primitive.
- Maximum individual passphrase size: 1,024 UTF-8 bytes.
- PBKDF2 iterations are exactly 600,000 for security schema 1; imports cannot supply a larger denial-of-service work factor.

Limits are checked before expensive parsing, cloning, scanning, encryption, or key derivation wherever the representation makes that possible. Exceeding a limit fails with a fixed local error.

## Workspace classification

`classifyProjectSecurity(stateBag)` returns one of `sanitized`, `unsanitized`, or `legacy-secret-bearing` plus availability information for reversible export.

A source is populated when it has non-blank `configText`, a non-null `intermediateConfig`, generated conversion state derived from configuration, or non-empty editable configuration collections. Empty placeholder merge slots are ignored.

A workspace is eligible for sanitized export only when:

- the active populated source has `isSanitized === true`;
- every populated merge slot has `isSanitized === true`;
- no populated greenfield, raw, or mixed source lacks an explicit sanitized state; and
- the completed candidate passes the final leak gate.

An imported version 5 sanitized project remains eligible even though its restoration tables are absent. A populated greenfield project is not assumed safe merely because it was generated locally; it must be sanitized before a safe-to-share export.

A reversible encrypted export is offered only for an eligible sanitized workspace with at least one non-empty valid restoration table. A raw or mixed workspace can be saved only as explicitly unsanitized plaintext under this issue's approved scope.

## Central export security boundary

Project UI code cannot directly stringify state or construct a download blob. A single project-security boundary owns classification, candidate construction, leak validation, encryption selection, serialization, filename suffixes, and the final byte string returned for download.

The boundary exposes these conceptual operations:

```js
classifyProjectSecurity(stateBag)
buildSanitizedProject(stateBag, projectName)
buildUnsanitizedProject(stateBag, projectName, confirmation)
encryptReversibleProject(stateBag, projectName, passphrase)
inspectProjectEnvelope(parsedJson)
decryptReversibleProject(envelope, passphrase)
```

`useProject` assembles the state bag and calls the boundary. It never calls `JSON.stringify` on project state and never creates a project blob until the boundary returns a validated serialized result.

## Sanitized export algorithm

1. Classify the entire workspace. Reject sanitized mode if any populated source is not proven sanitized.
2. Validate every restoration table before using it as evidence. Each entry must be a plain object with bounded string `type`, `placeholder`, and `original` fields and an optional boolean `restore` field. Malformed tables fail closed.
3. Recursively collect every `original` string from every restoration table, including tables in merge slots and future nested containers.
4. Build the ordinary canonical project payload and conversion output.
5. Deep-clone the payload with a cycle-detecting, prototype-safe walker. Reject accessors, functions, symbols, bigint values, non-finite numbers, sparse arrays, dangerous prototype keys, cycles, and depth or node-count overflows.
6. Remove every property named `sanitizationTable` at every depth. Set relevant restoration state to unavailable without mutating the live application state.
7. Attach the version 5 sanitized security metadata.
8. Scan the complete candidate object for restoration fields, known originals, and secret-bearing structured values.
9. Serialize the complete candidate once using JSON.
10. Scan the exact final serialized string for raw and JSON-escaped representations of every known original and for forbidden restoration-field spellings.
11. Abort with a fixed local error if any check is inconclusive or finds a match. Only a fully validated string can reach the download helper.

Known-original scanning is intentionally fail-closed. An ambiguous very short original can prevent sanitized export; the UI directs the user to correct or re-sanitize the source rather than silently weaken the check. Encrypted reversible export remains available when its prerequisites are met.

## Secret detection and redaction

One declarative secret registry drives both `sanitizeConfig` redaction and final-export detection. Every syntax definition supplies a stable category, a bounded matcher, a capture describing the secret value, a placeholder family, and a redaction operation. Detection and redaction tests iterate the same registry.

The registry covers supported forms of:

- PAN-OS nested and direct XML PSKs, API/auth keys, `phash`, password hashes, encrypted secrets, private keys, certificate keys, and secret keys;
- FortiGate `set password`, `set passwd`, `set secret`, `set psksecret`, IPsec PSKs, SNMP communities, RADIUS secrets, and TACACS secrets, including quoted, unquoted, and `ENC` forms;
- ASA/FTD usernames and enable passwords/secrets, tunnel-group and ISAKMP keys, IKEv1/IKEv2 PSKs, SNMP communities, RADIUS keys, TACACS keys, and certificate/private-key blocks;
- SRX/Junos `pre-shared-key` `ascii-text` and encrypted forms, `encrypted-password`, authentication/privacy passwords, RADIUS/TACPLUS secrets, SNMP communities, authentication keys, private keys, and certificate-key fields in set and hierarchical syntax;
- Check Point shared-secret, password, hash, SNMP, AAA, and certificate/private-key JSON or text fields supported by the parser inputs;
- SonicWall shared-secret, password/hash, SNMP, AAA, private-key, and certificate-secret forms supported by the parser inputs;
- generic PEM RSA, EC, DSA, encrypted, PKCS#8, and OpenSSH private-key blocks.

Already-sanitized placeholders are idempotent and are not re-recorded as originals. Secret entries never receive `restore: true`, so output and device workflows cannot automatically restore them.

## Structured-state scan

The final candidate walker checks both values and their semantic paths. A non-empty scalar under a secret-bearing key is rejected unless it is a recognized sanitizer placeholder. Key matching is normalized across camel case, snake case, hyphenation, and vendor spelling.

Secret-bearing keys include password, passwd, password-hash, phash, encrypted-password, secret, shared-secret, secondary-secret, PSK/pre-shared-key/psksecret, auth-key, authentication-key/password, privacy-key/password, API key, SNMP community, RADIUS secret/key, TACACS/TACPLUS secret/key, private key, certificate key, and equivalent parser fields.

Path-aware rules cover structured shapes whose field name alone is generic, including SNMP community objects stored under `name`, AAA server objects with `secret` or `key`, VPN/IKE objects, credential metadata, and certificate containers. Values that describe an algorithm, such as `auth_method: "pre-shared-keys"`, are not mistaken for the key material itself.

Every nested string is also checked with the raw-text registry so secret syntax hidden in metadata, warnings, descriptions, generated output, or future fields cannot bypass the structured scan.

## Import and migration

Import first inspects the envelope without applying state.

- Version 5 `sanitized` validates the plaintext schema, confirms no restoration fields, reruns the sanitized leak gate without unavailable historical originals, and loads with restoration unavailable.
- Version 5 `unsanitized` validates the schema and requires a warning confirmation before applying state.
- Version 5 `reversible-encrypted` prompts for the passphrase, decrypts and validates the inner project, then requires the reversible warning confirmation before applying state.
- Version 1 through 4 files are migrated only after classification. A claimed sanitized file with any plaintext restoration data becomes `legacy-secret-bearing` and requires a prominent warning. A sanitized legacy file without restoration data becomes sanitized only after the current structural and secret scan. All other legacy files become unsanitized.
- Loading any file is transactional. No context dispatch occurs until parsing, envelope validation, optional decryption, migration, conversion-output validation, and security classification all succeed.
- A sanitized import sets every reachable restoration table to `null` or omits it and cannot restore removed secrets or other originals.

## UI behavior

The current Save Project modal becomes Export Project and always shows the selected mode.

### Sanitized workspace

- `Sanitized — safe to share` is selected by default.
- The copy states that original values and restoration capability will be permanently removed from the file.
- `Encrypted reversible backup` is available only when a valid non-empty restoration table exists.
- Reversible mode requires a passphrase, matching confirmation, and an explicit acknowledgement that there is no recovery.
- Plaintext unsanitized export is not offered because the live source is already sanitized.

### Unsanitized or mixed workspace

- The modal states that the file can contain passwords, keys, communities, private addresses, hostnames, and other sensitive data.
- `Unsanitized — contains sensitive data` is the only export mode.
- The download button remains disabled until the user types `EXPORT UNSANITIZED` exactly.
- A `Sanitize first` action closes the export path and returns the user to the existing sanitization workflow.

### Import

- Sanitized files display an irreversible safe-to-share badge.
- Encrypted files prompt for a passphrase and show the no-recovery warning.
- Unsanitized and legacy secret-bearing files require an explicit warning confirmation.
- Loaded-project navigation and subsequent export UI retain the security classification so a dangerous project cannot be mistaken for sanitized.

### Filenames

- Sanitized: `<name>.sanitized.fpic.json`
- Reversible encrypted: `<name>.reversible.fpic.enc.json`
- Unsanitized: `<name>.unsanitized.fpic.json`

Project names are sanitized for filesystem use independently of configuration sanitization.

## Error handling

All security-boundary errors use fixed local codes and messages. They do not interpolate source values, matched secrets, passphrases, table entries, parsed remote text, paths containing user values, ciphertext, or cryptographic exception messages.

Required failure classes include unsupported mode, unsanitized-source rejection, invalid confirmation, malformed restoration data, unsafe state shape, original-value leak, secret-syntax leak, unsupported crypto, invalid envelope, decryption failure, unsupported version, oversized file, and invalid project state.

The UI may identify a safe structural location such as `merge slot 2` but not a source-derived value. The download helper is not called after any failure.

## File and component boundaries

- `public/utils/project-security.js`: modes, strict metadata schemas, workspace classification, safe cloning, recursive table collection/removal, structured scan, final serialized leak gate, and filename selection.
- `public/utils/project-crypto.js`: strict encrypted envelope validation, base64 conversion, AAD construction, PBKDF2 key derivation, AES-GCM encryption/decryption, and fixed cryptographic errors.
- `public/utils/secret-detection.js`: declarative vendor secret registry, idempotent secret redaction, raw-text detection, structured key normalization, and placeholder recognition.
- `public/utils/engine.js`: retain non-secret sanitization passes and delegate secret passes to `secret-detection.js`.
- `public/utils/project-io.js`: version 5 canonical project construction, strict import/migration, and conversion-output validation; delegate security decisions to the security boundary.
- `public/hooks/useProject.js`: assemble state, invoke the boundary asynchronously, download only returned validated bytes, inspect/decrypt imports transactionally, and coordinate confirmation modals.
- `public/components/SaveProjectModal.jsx`: explicit export-mode UI, passphrase confirmation, typed unsanitized confirmation, and no-recovery acknowledgement.
- `public/components/ProjectSecurityImportModal.jsx`: sanitized information, encrypted passphrase entry, and unsanitized/legacy warning confirmation.
- `public/contexts/ConfigContext.jsx` and related project-load state: retain the loaded security classification without persisting passphrases or keys.
- Tests live in focused sanitizer, project-security, crypto, project-I/O, hook/component, migration, and enforcement suites.

## Permanent enforcement

A static test enumerates project-download call sites and rejects project JSON serialization or project Blob construction outside the approved project-security/download boundary. It also rejects use of plaintext reversible mode names and version 5 sanitized schemas containing `sanitizationTable`.

This gate is intentionally narrow to project files; ordinary text, PDF, IaC, and converted-configuration exports retain their existing boundaries unless they attempt to label a project as sanitized.

## Test strategy

### Secret registry

- Parameterized positive cases for every required vendor and secret category.
- Quoted, unquoted, XML, hierarchical, set-format, JSON-field, whitespace, case, and line-ending variations.
- Idempotence for existing placeholders.
- Negative cases for algorithm names, public certificates, non-secret identifiers, empty values, and similarly named fields.
- Redaction and detection parity: every detected secret is replaced and every replacement removes the captured original.

### Sanitized export

- Top-level and nested restoration tables are absent.
- Every raw and JSON-escaped known original is absent from the exact serialized file.
- Tests inject originals into config text, intermediate objects, metadata, warnings, conversion output, mapping data, merge slots, and future-style nested containers.
- Tests inject secret syntax and structured secret keys without a restoration-table entry.
- Malformed tables, cycles, accessors, prototype keys, excessive depth, excessive nodes, and unsupported values fail closed.
- The live React/context state remains unchanged after export.
- Importing the result cannot restore any removed value.

### Reversible encryption

- Real Web Crypto round trips restore the exact inner canonical project.
- Repeated encryption of identical input yields different salt, nonce, and ciphertext.
- The outer object exposes exactly `fpic_version`, `security`, and `ciphertext`; tests use unique project-name, configuration, and restoration markers and prove those plaintext markers are absent from the serialized envelope.
- Wrong passphrase and one-bit changes to metadata, salt, nonce, or ciphertext all fail with the same fixed error.
- Non-canonical base64, wrong lengths, unknown fields, wrong algorithm identifiers, missing Web Crypto, invalid UTF-8, invalid JSON, and invalid inner projects fail closed.
- Passphrases and derived keys never enter returned data, context actions, storage calls, or logs.

### UI and migration

- Sanitized mode is the default only for an eligible workspace.
- Reversible mode is unavailable without valid restoration data or Web Crypto.
- Unsanitized mode requires exact typed confirmation.
- Passphrase confirmation and no-recovery acknowledgement are mandatory.
- File suffix, mode copy, badges, and import prompts match metadata.
- Legacy plaintext restoration tables are classified and warned correctly.
- State is not applied before all confirmations and validations succeed.

### Full gates

- Complete Vitest suite.
- Every self-running JavaScript suite.
- PyEZ bridge unit tests and Python dependency check.
- npm audit at high severity or stricter.
- Production build.
- Changed JavaScript syntax checks.
- Diff hygiene and clean worktree.
- Issue #11 acceptance matrix mapping every issue criterion to named passing tests.
- Independent task reviews and a final whole-branch security review before publication.

## Acceptance criteria

- Default sanitized project files contain no restoration table and none of the known original replacement values in raw or JSON-escaped form.
- A sanitized import has no data or capability with which to restore removed originals.
- Supported PSK, SNMP, password/hash, RADIUS/TACACS, private-key, and certificate-secret forms are detected and redacted.
- The final complete export object and exact serialized bytes are scanned before download.
- Sanitized, reversible encrypted, unsanitized, and legacy secret-bearing classifications cannot be confused in metadata or UI.
- Reversible content is authenticated ciphertext protected by a user passphrase, never plaintext labeled sanitized.
- Unsanitized plaintext requires explicit typed confirmation.
- Malformed, ambiguous, unsupported, or unproven-safe cases fail closed without leaking sensitive context.

## References

- GitHub issue #11: `security: prevent original secrets from leaking in sanitized project exports`
- W3C Web Cryptography API, AES-GCM and PBKDF2 operations: <https://www.w3.org/TR/WebCryptoAPI/>
- OWASP Password Storage Cheat Sheet, PBKDF2-HMAC-SHA-256 work factor: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>

# Secure Credentials and NETCONF Device Identity Design

## Problem

The application currently persists secrets and opens NETCONF connections without a complete device-identity policy:

- Cloud LLM API keys are serialized into the long-lived browser `localStorage` record named `llm-settings`.
- The PyEZ bridge writes device passwords and private-key paths directly into `tools/pyez-bridge/devices.yaml`.
- Inventory writes are neither atomic nor permission-enforced, and reads follow ordinary filesystem paths without rejecting symlinks or unsafe file metadata.
- Junos PyEZ defaults `hostkey_verify` to false, and the bridge does not override it.
- Many bridge handlers reflect raw exception text, configuration commands, and RPC details into HTTP responses or console output.

These behaviors permit long-lived browser credential exposure, unsafe credential storage, device impersonation, and accidental secret disclosure through diagnostics.

## Goals

- Keep cloud LLM API keys only for the current browser tab session.
- Remove legacy API keys from long-lived browser storage without losing the active tab session.
- Store only nonsecret device metadata and credential references in the bridge inventory.
- Use SSH agent/OpenSSH configuration by default and environment-variable references when password authentication is required.
- Reject plaintext password and private-key-path fields in inventory and API requests.
- Enforce atomic, owner-only inventory handling and reject unsafe paths.
- Verify every NETCONF SSH host key through OpenSSH `known_hosts` by default.
- Fail closed for unknown and changed device keys.
- Provide one explicit, startup-only, visibly warned development override.
- Ensure credentials, key paths, configuration text, and raw exception details never appear in bridge responses or logs.

## Non-goals

- Adding an operating-system keyring dependency.
- Building a remote multi-user bridge service.
- Automatically trusting or enrolling first-seen SSH host keys.
- Storing encrypted passwords in the inventory.
- Implementing an SSH certificate authority or a private host-key database.
- Changing the localhost-only bridge, bearer-token, CORS, request-size, or rate-limit model.
- Changing LLM provider request formats except for their settings source.

## Approaches Considered

### Credential references and native SSH facilities

Persist only metadata plus `agent` or `password-env` authentication references. Let PyEZ use the native SSH agent and `~/.ssh/config`; resolve password values from the bridge process environment. Keep browser LLM keys in `sessionStorage`. This is the selected approach because it removes secret-at-rest key management from the project while using mechanisms PyEZ already supports.

### Owner-only plaintext compatibility

Continue storing device passwords and private-key paths in an atomic mode-`0600` inventory. This would be the smallest compatibility change, but the bridge would still own plaintext secrets on disk and backups could retain them.

### OS keyring-backed persistence

Store secret values in a platform keychain and retain references in the inventory. This provides persistent secrets without plaintext project files, but introduces platform-specific dependencies, unavailable or locked keyring backends on headless systems, and a larger deployment/support surface.

## Browser LLM Settings Boundary

A new dependency-free browser module, `public/utils/llm-settings.js`, will be the sole reader and writer of LLM settings.

Storage is split into:

- `localStorage['llm-settings']`: provider, model, base URL, temperature, prompt overrides, and other nonsecret preferences.
- `sessionStorage['llm-api-key']`: the cloud/custom provider API key for the current tab session.

The public interface will provide:

- `loadLLMSettings()`: returns a combined in-memory settings object.
- `saveLLMSettings(settings)`: persists nonsecret fields and separately updates the session key.
- `clearLLMApiKey()`: removes the tab-session key.
- `migrateLegacyLLMSettings()`: strips an old `apiKey` property from `localStorage` and copies it into `sessionStorage` only when that session does not already have a key.

Migration runs on the first settings load. The long-lived record is rewritten even if writing `sessionStorage` fails; leaving a legacy key in persistent storage is not an acceptable fallback. Storage errors produce safe configuration failures and never include the key.

`LLMSettings.jsx` and `llm-client.js` must use this module. Direct API-key reads or writes through `localStorage` are forbidden. Prompt overrides remain persistent through the nonsecret record.

The UI will state: “Stored for this browser tab session; closing the tab/session removes it.” It will not claim that same-origin scripts cannot access the key. The key is never included in project payloads, query strings, URLs, error messages, or development logs.

## Device Inventory Schema

`tools/pyez-bridge/devices.yaml` becomes an untracked runtime file. The tracked file is replaced with `devices.example.yaml` using only safe examples.

The supported schema is:

```yaml
devices:
  - name: srx-lab-01
    host: 192.0.2.10
    port: 830
    username: netops
    auth_method: agent

  - name: srx-prod-01
    host: 198.51.100.10
    port: 830
    username: automation
    auth_method: password-env
    password_env: FIC_SRX_PROD_PASSWORD
```

Rules:

- `auth_method` must be `agent` or `password-env`.
- `password-env` requires an environment-variable name matching `[A-Z_][A-Z0-9_]{0,127}`.
- The environment-variable value is resolved only immediately before connection and is never added to the inventory object.
- `agent` stores no password, key path, or agent socket value. PyEZ uses the process SSH agent, default key lookup, and `~/.ssh/config`.
- `password`, `passwd`, `ssh_key`, `ssh_private_key_file`, private-key material, and unrecognized authentication fields are rejected on load and through `POST /devices`.
- Existing inventories containing forbidden fields fail closed with migration guidance: move identity selection to `~/.ssh/config`, load the key into an agent, or replace a stored password with `password_env`.

Device list responses expose only name, host, port, username, authentication method, and a boolean `credential_ready`. They never return `password_env`, environment values, key paths, fingerprints, or exception text.

## Inventory Filesystem Security

Inventory filesystem operations move into `tools/pyez-bridge/inventory.py` so path validation, schema validation, loading, and saving have one responsibility.

### Read policy

- Use `lstat` and `os.open` with `O_NOFOLLOW` when the platform supports it.
- Reject a symlink, non-regular file, wrong owner, or POSIX mode with any group/other permission bits.
- Require a regular, process-owned parent directory that is not a symlink and is not group/world writable.
- Limit inventory size before parsing.
- Use `yaml.safe_load` and require the exact supported structure.
- Return typed safe inventory errors without including file contents or secret field values.

On POSIX systems, an existing inventory must be mode `0600`. The bridge may create a missing inventory securely, but it does not silently repair an unsafe existing file because doing so could mask prior exposure. On platforms without POSIX ownership/mode semantics, the inventory still contains no secret values; the bridge enforces available no-follow, regular-file, and atomic-write controls and reports that POSIX ownership checks are unavailable.

### Write policy

- Validate the destination and parent before every write.
- Create a randomly named temporary file in the destination directory with mode `0600`.
- Write safe YAML, flush, and `fsync` the temporary file.
- Re-validate the destination type before replacement.
- Use `os.replace` for same-filesystem atomic replacement.
- Enforce mode `0600` on the final file and `fsync` the parent directory on POSIX.
- Remove the temporary file on every failure path.

Python documents `os.replace` as atomic when successful on the same filesystem and provides secure temporary-file primitives through `tempfile`.

## Authentication and Host-Key Verification

`tools/pyez-bridge/connection.py` will construct and open PyEZ devices. All existing bridge endpoints will use this boundary.

Strict connection behavior:

- Always pass `hostkey_verify=True` unless the startup-only development override is active.
- For `agent`, pass no password or private-key path and enable agent/default key lookup.
- For `password-env`, resolve the environment value, set `passwd`, and disable agent/default key discovery to avoid authenticating with an unintended credential.
- Allow PyEZ to consult `~/.ssh/config`, including identity selection and `UserKnownHostsFile`.
- Require an appropriate `known_hosts` entry for the host and NETCONF port. Nonstandard ports use OpenSSH bracket notation such as `[192.0.2.10]:830`.

PyEZ forwards host-key verification to ncclient. With verification enabled, ncclient loads known hosts, compares the negotiated server key, and rejects unknown or mismatched keys. The bridge will classify the wrapped ncclient unknown-host exception as a device-identity failure without returning the presented fingerprint.

The bridge will never run `ssh-keyscan`, modify `known_hosts`, or accept a first-seen key. Documentation may show how to collect a key, but must require independent fingerprint verification before enrollment.

## Development Override

The only public override is the CLI flag:

```text
--insecure-allow-unknown-hosts
```

It is intentionally verbose and unavailable through the device inventory, browser request, URL, or environment variable. When enabled:

- Startup prints a prominent multi-line warning.
- The health response reports `host_key_verification: "disabled-development"`.
- The browser bridge settings panel displays a persistent warning after connection.
- `_connect` passes `hostkey_verify=False`.

Without the flag, health reports `host_key_verification: "strict"`. The override does not disable authentication, localhost binding, bearer authorization, CORS, rate limits, or configuration validation.

## Safe Error and Logging Policy

The bridge will stop serializing raw exception strings. Typed internal exceptions map to stable public categories:

- `DEVICE_IDENTITY_FAILED`: the device host key is unknown or changed.
- `DEVICE_AUTHENTICATION_FAILED`: agent/password authentication failed.
- `DEVICE_CREDENTIAL_UNAVAILABLE`: the referenced environment variable or agent credential is unavailable.
- `DEVICE_UNREACHABLE`: connection refused, timed out, or the host cannot be reached.
- `INVENTORY_UNSAFE`: inventory path, ownership, permission, or schema validation failed.
- `DEVICE_OPERATION_FAILED`: a NETCONF/RPC/configuration operation failed.
- `UNEXPECTED_ERROR`: an unclassified internal failure.

HTTP bodies contain a stable safe message and optional code, line number, or nonsecret XML path. They do not contain `str(exception)`, traceback text, inventory paths, configuration commands, environment-variable values, private-key material, passwords, or presented fingerprints.

Console logging follows the same rule. Device names and operation categories may be logged, but configuration lines, raw RPC output, credentials, key paths, and raw exception messages may not. Line-by-line load diagnostics report line numbers and safe categories only.

The browser displays the bridge’s stable safe errors. It does not concatenate request credentials or settings into errors.

## UI Changes

The device form replaces Password and SSH Key Path with:

- Authentication Method: `SSH Agent / OpenSSH Config` or `Password Environment Variable`.
- Password Environment Variable: shown only for `password-env`.

Setup guidance will cover:

- Loading a key into `ssh-agent`.
- Selecting identities in `~/.ssh/config` without storing paths in the project.
- Defining the password environment variable before bridge startup.
- Adding a verified `[host]:port` key to `known_hosts`.
- Interpreting unknown/changed-key failures.
- The risk and visibility of the development-only override.

The UI clears all device-form state after submission and does not place credential references in error strings.

## Data Flow

### LLM request

1. The UI saves nonsecret preferences to persistent storage and the API key to tab-session storage.
2. The client loads a combined in-memory settings object.
3. Provider code sends the key only in the documented authentication header.
4. Responses and errors contain status/category information, not the key or request headers.

### Device connection

1. An authenticated localhost request selects a device by name.
2. The inventory module safely loads and validates nonsecret metadata.
3. The connection module resolves the credential reference in memory.
4. PyEZ opens with strict known-host verification.
5. The endpoint performs its NETCONF operation.
6. Raw connection/RPC exceptions are mapped to a safe response and safe log event.

### Inventory mutation

1. The authenticated API validates the nonsecret device schema.
2. The inventory module loads the current safe inventory.
3. The module writes a mode-`0600` temporary file, flushes it, and atomically replaces the destination.
4. The API returns only safe device metadata.

## Testing Strategy

Implementation follows red-green-refactor cycles.

### Browser tests

- Save a cloud API key and prove it is absent from `localStorage` and present only in `sessionStorage`.
- Reload within a tab session and recover the key.
- Clear the tab session and prove cloud providers are no longer configured.
- Migrate a legacy persistent key, preserve nonsecret settings/prompts, and rewrite the persistent record without the key.
- Simulate storage failures and prove error text never contains the key.
- Scan project serialization, logs, URLs, and provider errors for sentinel keys.
- Verify local providers remain usable without a key.

### Inventory tests

- Create and replace inventories with POSIX mode `0600`.
- Prove replacement is atomic and temporary files are removed after success and injected failures.
- Reject symlink destinations, symlink parents, non-regular files, wrong ownership, unsafe permissions, oversized input, malformed YAML, duplicate names, forbidden secret fields, and invalid environment references.
- Verify the checked-in runtime inventory is removed and the example contains no real topology or credential path.

### Connection tests

- Assert PyEZ receives `hostkey_verify=True` by default.
- Assert agent mode passes no password/key path and enables agent/config lookup.
- Assert password-env mode resolves only at connection time and disables agent/key lookup.
- Assert missing environment variables fail before constructing/opening a device.
- Simulate accepted known keys, unknown keys, and changed keys.
- Assert the development override alone sets `hostkey_verify=False` and that health/startup/UI warnings are visible.

### Redaction tests

- Inject sentinel passwords, environment values, key paths, private-key material, config lines, and fingerprints into every relevant mocked exception.
- Exercise every bridge endpoint error family and prove HTTP bodies and captured console/log output contain none of the sentinels.
- Prove safe codes, operation categories, line numbers, and nonsecret paths remain actionable.

### Full regression gate

- All Vitest and self-running JavaScript suites.
- All PyEZ bridge unit/integration tests.
- Production Vite build.
- npm audit and Python dependency checks.
- Source scans forbidding persistent API-key storage, stored device secret fields, `hostkey_verify=False` outside the explicit override, and raw exception reflection.

## Acceptance Mapping

- API keys are absent from long-term browser storage by construction and are migrated out of legacy records.
- Device inventory contains only metadata and credential references; it is atomically managed and owner-only on POSIX.
- Unknown and changed NETCONF host keys fail closed under the default strict policy.
- Credentials and private-key material are excluded from API responses and logs through stable typed error mapping.
- Agent/OpenSSH configuration and environment references replace stored passwords and private-key paths.
- The development override is explicit, startup-only, visible, and covered by tests.

## Primary References

- [Juniper PyEZ authentication documentation](https://www.juniper.net/documentation/us/en/software/junos-pyez/junos-pyez-developer/topics/topic-map/junos-pyez-authentication.html)
- [Juniper PyEZ `Device` implementation](https://github.com/Juniper/py-junos-eznc/blob/master/lib/jnpr/junos/device.py)
- [ncclient SSH transport implementation](https://github.com/ncclient/ncclient/blob/master/ncclient/transport/ssh.py)
- [Python `os` documentation](https://docs.python.org/3/library/os.html)
- [Python `tempfile` documentation](https://docs.python.org/3/library/tempfile.html)

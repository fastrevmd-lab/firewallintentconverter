# Secure Credentials and NETCONF Device Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove persisted application secrets, secure the PyEZ inventory, verify NETCONF device identity by default, and expose only stable redacted failures.

**Architecture:** A browser settings boundary splits nonsecret LLM preferences into `localStorage` and the API key into tab-scoped `sessionStorage`. Separate Python inventory and connection modules validate nonsecret credential references, perform owner-only atomic persistence, enforce known-host verification, and map internal failures to safe public errors consumed by the Flask routes and UI.

**Tech Stack:** JavaScript ES modules, React 18, Vitest 4, Python 3 standard library, Flask, PyYAML, Juniper PyEZ/ncclient, unittest.

## Global Constraints

- Keep cloud LLM API keys only in `sessionStorage['llm-api-key']`; `localStorage['llm-settings']` contains nonsecret preferences only.
- Preserve no API key, password, password value, private-key material, private-key path, presented host-key fingerprint, raw command, raw RPC, or raw exception text in project files, HTTP errors, URLs, or logs.
- Device authentication is exactly `agent` or `password-env`; password environment names match `[A-Z_][A-Z0-9_]{0,127}` and values are resolved only immediately before connection.
- Verify NETCONF SSH host keys through OpenSSH known-hosts by default; never enroll or trust a first-seen key automatically.
- The only verification bypass is the startup CLI flag `--insecure-allow-unknown-hosts`, with startup, health, and browser warnings.
- Existing localhost binding, bearer authorization, CORS, request-size, rate-limit, and configuration-validation controls remain enabled.
- Add no TypeScript, browser persistence library, OS keyring dependency, or new Python package.
- Use red-green-refactor for every behavior change, keep commits task-scoped, and run the task's focused tests before committing.

---

## File Map

- `public/utils/llm-settings.js`: sole LLM settings storage and legacy migration boundary.
- `public/utils/llm-client.js`: consumes combined settings without direct browser-storage access.
- `public/components/LLMSettings.jsx`: settings/device UI and visible verification warning.
- `public/components/ExportPdfButton.jsx`: reads provider through the settings boundary.
- `public/utils/device-registration.js`: validates and constructs secret-free device requests.
- `tools/pyez-bridge/inventory.py`: exact schema validation plus safe atomic inventory I/O.
- `tools/pyez-bridge/connection.py`: credential resolution, PyEZ construction, host-key policy, safe exception classification.
- `tools/pyez-bridge/app.py`: route integration, safe responses, startup-only override.
- `tools/pyez-bridge/devices.example.yaml`: tracked RFC 5737 sample; `devices.yaml` becomes runtime-only.
- `tests/llm-settings.test.js`, `tests/credential-security.test.js`: browser boundary and source-regression tests.
- `tools/pyez-bridge/tests/test_inventory.py`, `test_connection.py`, `test_error_redaction.py`: Python security tests.
- `tools/pyez-bridge/tests/test_app_security.py`: Flask integration and override tests.

### Task 1: Tab-session LLM settings boundary

**Files:**
- Create: `public/utils/llm-settings.js`
- Create: `tests/llm-settings.test.js`

**Interfaces:**
- Consumes: browser `localStorage` and `sessionStorage`, each exposing `getItem`, `setItem`, and `removeItem`.
- Produces: `LLM_SETTINGS_STORAGE_KEY`, `LLM_API_KEY_SESSION_KEY`, `LLMSettingsStorageError`, `migrateLegacyLLMSettings()`, `loadLLMSettings()`, `saveLLMSettings(settings)`, and `clearLLMApiKey()`.
- `loadLLMSettings()` returns `{ ...persistentSettings, apiKey: string }`; persistent settings never include `apiKey`.
- `saveLLMSettings(settings)` returns the same combined shape after storing nonsecret properties separately from `apiKey`.

- [ ] **Step 1: Write storage and migration tests that fail before the module exists**

Create `tests/llm-settings.test.js` with an in-memory storage double and tests covering split persistence, reload, clear, legacy migration, existing-session precedence, and redacted storage failures:

```js
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  LLM_API_KEY_SESSION_KEY,
  LLM_SETTINGS_STORAGE_KEY,
  LLMSettingsStorageError,
  clearLLMApiKey,
  loadLLMSettings,
  migrateLegacyLLMSettings,
  saveLLMSettings,
} from '../public/utils/llm-settings.js';

function memoryStorage() {
  const values = new Map();
  return {
    getItem: vi.fn(key => values.get(key) ?? null),
    setItem: vi.fn((key, value) => values.set(key, String(value))),
    removeItem: vi.fn(key => values.delete(key)),
    clear: () => values.clear(),
  };
}

beforeEach(() => {
  globalThis.localStorage = memoryStorage();
  globalThis.sessionStorage = memoryStorage();
});

describe('LLM settings storage boundary', () => {
  it('persists nonsecret preferences and keeps the key in the tab session', () => {
    saveLLMSettings({ provider: 'openai', model: 'gpt-4o', apiKey: 'SENTINEL_KEY' });
    expect(JSON.parse(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY))).toEqual({
      provider: 'openai', model: 'gpt-4o',
    });
    expect(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY)).not.toContain('SENTINEL_KEY');
    expect(sessionStorage.getItem(LLM_API_KEY_SESSION_KEY)).toBe('SENTINEL_KEY');
    expect(loadLLMSettings()).toMatchObject({ provider: 'openai', apiKey: 'SENTINEL_KEY' });
  });

  it('clears only the tab-session key', () => {
    saveLLMSettings({ provider: 'openai', apiKey: 'SENTINEL_KEY' });
    clearLLMApiKey();
    expect(loadLLMSettings()).toEqual({ provider: 'openai', apiKey: '' });
  });

  it('moves a legacy key once while preserving preferences', () => {
    localStorage.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify({
      provider: 'claude', apiKey: 'LEGACY_SENTINEL', translateSystemPrompt_panos: 'prompt',
    }));
    migrateLegacyLLMSettings();
    expect(sessionStorage.getItem(LLM_API_KEY_SESSION_KEY)).toBe('LEGACY_SENTINEL');
    expect(JSON.parse(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY))).toEqual({
      provider: 'claude', translateSystemPrompt_panos: 'prompt',
    });
  });

  it('does not replace a current session key during migration', () => {
    sessionStorage.setItem(LLM_API_KEY_SESSION_KEY, 'CURRENT_SENTINEL');
    localStorage.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify({ apiKey: 'LEGACY_SENTINEL' }));
    migrateLegacyLLMSettings();
    expect(sessionStorage.getItem(LLM_API_KEY_SESSION_KEY)).toBe('CURRENT_SENTINEL');
    expect(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY)).not.toContain('LEGACY_SENTINEL');
  });

  it('removes a legacy persistent key even if session storage rejects it', () => {
    localStorage.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify({ provider: 'openai', apiKey: 'LEGACY_SENTINEL' }));
    sessionStorage.setItem.mockImplementation(() => { throw new Error('LEGACY_SENTINEL'); });
    let caught;
    try { migrateLegacyLLMSettings(); } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(LLMSettingsStorageError);
    expect(caught.message).not.toContain('LEGACY_SENTINEL');
    expect(localStorage.getItem(LLM_SETTINGS_STORAGE_KEY)).toBe('{"provider":"openai"}');
  });
});
```

- [ ] **Step 2: Run the focused test and verify the missing-module failure**

Run: `npx vitest run tests/llm-settings.test.js`

Expected: FAIL because `public/utils/llm-settings.js` does not exist.

- [ ] **Step 3: Implement the settings boundary**

Create `public/utils/llm-settings.js` with these exact storage semantics:

```js
import { safeJsonParse } from './safe-json.js';

export const LLM_SETTINGS_STORAGE_KEY = 'llm-settings';
export const LLM_API_KEY_SESSION_KEY = 'llm-api-key';

export class LLMSettingsStorageError extends Error {
  constructor(message = 'LLM settings storage is unavailable.') {
    super(message);
    this.name = 'LLMSettingsStorageError';
    this.code = 'LLM_SETTINGS_STORAGE_UNAVAILABLE';
  }
}

function stores() {
  return {
    persistent: typeof localStorage === 'undefined' ? null : localStorage,
    session: typeof sessionStorage === 'undefined' ? null : sessionStorage,
  };
}

function readPersistent(persistent) {
  const raw = persistent?.getItem(LLM_SETTINGS_STORAGE_KEY);
  const parsed = raw ? safeJsonParse(raw) : {};
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
}

export function migrateLegacyLLMSettings() {
  const { persistent, session } = stores();
  let settings;
  try { settings = readPersistent(persistent); }
  catch { throw new LLMSettingsStorageError(); }
  if (!Object.prototype.hasOwnProperty.call(settings, 'apiKey')) return settings;

  const legacyKey = typeof settings.apiKey === 'string' ? settings.apiKey : '';
  const { apiKey: removed, ...nonsecret } = settings;
  let sessionFailed = false;
  try {
    if (legacyKey && !session?.getItem(LLM_API_KEY_SESSION_KEY)) {
      session?.setItem(LLM_API_KEY_SESSION_KEY, legacyKey);
    }
  } catch { sessionFailed = true; }
  try { persistent?.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify(nonsecret)); }
  catch { throw new LLMSettingsStorageError(); }
  if (sessionFailed) throw new LLMSettingsStorageError();
  return nonsecret;
}

export function loadLLMSettings() {
  const persistentSettings = migrateLegacyLLMSettings();
  try {
    const { session } = stores();
    return { ...persistentSettings, apiKey: session?.getItem(LLM_API_KEY_SESSION_KEY) || '' };
  } catch { throw new LLMSettingsStorageError(); }
}

export function saveLLMSettings(settings = {}) {
  const { apiKey = '', ...nonsecret } = settings;
  const { persistent, session } = stores();
  try {
    persistent?.setItem(LLM_SETTINGS_STORAGE_KEY, JSON.stringify(nonsecret));
    if (apiKey) session?.setItem(LLM_API_KEY_SESSION_KEY, String(apiKey));
    else session?.removeItem(LLM_API_KEY_SESSION_KEY);
  } catch { throw new LLMSettingsStorageError(); }
  return { ...nonsecret, apiKey: String(apiKey || '') };
}

export function clearLLMApiKey() {
  try { stores().session?.removeItem(LLM_API_KEY_SESSION_KEY); }
  catch { throw new LLMSettingsStorageError(); }
}
```

- [ ] **Step 4: Run the focused test and verify all cases pass**

Run: `npx vitest run tests/llm-settings.test.js`

Expected: PASS with 5 tests and no sentinel value in an error message.

- [ ] **Step 5: Commit the boundary**

```bash
git add public/utils/llm-settings.js tests/llm-settings.test.js
git commit -m "security: scope LLM keys to browser sessions"
```

### Task 2: Route every LLM consumer through the storage boundary

**Files:**
- Modify: `public/components/LLMSettings.jsx`
- Modify: `public/utils/llm-client.js`
- Modify: `public/components/ExportPdfButton.jsx`
- Modify: `tests/llm-translate.test.js`
- Create: `tests/credential-security.test.js`

**Interfaces:**
- Consumes: `loadLLMSettings()` and `saveLLMSettings(settings)` from Task 1.
- Produces: no new public API; all LLM provider, prompt, and PDF reads share one combined in-memory settings object.

- [ ] **Step 1: Update existing translation fixtures and write a source-regression test**

In `tests/llm-translate.test.js`, add a `sessionStorage` double beside the existing `localStorage` double. Replace fixtures such as:

```js
localStorage.setItem('llm-settings', JSON.stringify({
  provider: 'claude',
  model: 'claude-sonnet-4-6',
}));
sessionStorage.setItem('llm-api-key', 'test-key');
```

Create `tests/credential-security.test.js` to prevent future direct secret persistence:

```js
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

describe('credential source invariants', () => {
  it('centralizes LLM storage access', () => {
    for (const path of [
      'public/components/LLMSettings.jsx',
      'public/utils/llm-client.js',
      'public/components/ExportPdfButton.jsx',
    ]) {
      const source = read(path);
      expect(source).not.toMatch(/localStorage\.(?:getItem|setItem)\(['"]llm-settings/);
      expect(source).not.toMatch(/sessionStorage\.(?:getItem|setItem)\(['"]llm-api-key/);
    }
  });

  it('does not serialize apiKey into persistent settings', () => {
    const source = read('public/utils/llm-settings.js');
    expect(source).toContain("const { apiKey = '', ...nonsecret } = settings");
    expect(source).toContain('JSON.stringify(nonsecret)');
  });
});
```

- [ ] **Step 2: Run the focused tests and verify the direct-access test fails**

Run: `npx vitest run tests/llm-settings.test.js tests/credential-security.test.js && node tests/llm-translate.test.js`

Expected: the Vitest source-regression case FAILS on the three direct `localStorage` consumers; the translation suite may also fail until its fixtures and client are migrated.

- [ ] **Step 3: Replace direct storage access in the three consumers**

In `public/components/LLMSettings.jsx`, remove the `safeJsonParse` import, import the boundary, initialize from `loadLLMSettings()`, save through `saveLLMSettings()`, and use this exact session copy:

```js
import { loadLLMSettings, saveLLMSettings } from '../utils/llm-settings.js';

// Inside the mount effect:
try {
  const settings = loadLLMSettings();
  const savedProvider = settings.provider || 'claude';
  // Retain the existing local-only provider fallback and all existing prompt setters.
  setApiKey(settings.apiKey || '');
} catch {
  setApiKey('');
}

// Inside handleSave, after constructing settings and vendor prompt properties:
saveLLMSettings(settings);
```

Change the API-key helper text to this exact statement:

```jsx
<div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
  Stored for this browser tab session; closing the tab/session removes it.
</div>
```

In `public/utils/llm-client.js`, import `loadLLMSettings` and replace its private settings loader plus each prompt override `localStorage` parse with the boundary:

```js
import { loadLLMSettings } from './llm-settings.js';

function loadSettings() {
  try { return loadLLMSettings(); }
  catch { return {}; }
}

// Each prompt loader starts with one settings read:
const settings = loadSettings();
const override = settings[`translateSystemPrompt_${vendor}`];
```

Keep keys only in provider authentication headers. Error construction must use provider/status categories and must never stringify headers, settings, or request options.

In `public/components/ExportPdfButton.jsx`, remove `safeJsonParse`, import the boundary, and replace its storage block:

```js
import { loadLLMSettings } from '../utils/llm-settings.js';

let isLocalLLM = false;
try {
  isLocalLLM = ['ollama', 'lmstudio'].includes(loadLLMSettings().provider);
} catch { /* settings unavailable: use the non-local default */ }
```

- [ ] **Step 4: Run browser-focused tests**

Run: `npx vitest run tests/llm-settings.test.js tests/credential-security.test.js && node tests/llm-translate.test.js`

Expected: both Vitest files PASS and the self-running translation suite reports all assertions passing.

- [ ] **Step 5: Commit consumer migration**

```bash
git add public/components/LLMSettings.jsx public/utils/llm-client.js public/components/ExportPdfButton.jsx tests/llm-translate.test.js tests/credential-security.test.js
git commit -m "security: centralize browser credential access"
```

### Task 3: Secret-free, owner-only, atomic device inventory

**Files:**
- Create: `tools/pyez-bridge/inventory.py`
- Create: `tools/pyez-bridge/tests/test_inventory.py`
- Delete: `tools/pyez-bridge/devices.yaml`
- Create: `tools/pyez-bridge/devices.example.yaml`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `pathlib.Path`, `os`, `stat`, `tempfile`, and `yaml.safe_load/safe_dump`.
- Produces: `InventoryError(code, public_message)`, `validate_device(value) -> dict`, `load_devices(path) -> list[dict]`, and `save_devices(path, devices) -> None`.
- Valid device keys are exactly `name`, `host`, `port`, `username`, `auth_method`, plus `password_env` only for `password-env`.

- [ ] **Step 1: Write schema, metadata, and atomic-write tests**

Create `tools/pyez-bridge/tests/test_inventory.py` using `unittest`, `tempfile.TemporaryDirectory`, `unittest.mock.patch`, and these representative cases:

```python
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

from inventory import InventoryError, load_devices, save_devices, validate_device


AGENT_DEVICE = {
    "name": "edge", "host": "192.0.2.10", "port": 830,
    "username": "netops", "auth_method": "agent",
}


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        os.chmod(self.root, 0o700)
        self.path = self.root / "devices.yaml"

    def test_round_trip_is_owner_only_and_secret_free(self):
        save_devices(self.path, [AGENT_DEVICE])
        self.assertEqual(load_devices(self.path), [AGENT_DEVICE])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn("password:", text)
        self.assertNotIn("ssh_key", text)

    def test_rejects_forbidden_or_unknown_authentication_fields(self):
        for field in ("password", "passwd", "ssh_key", "ssh_private_key_file", "private_key"):
            with self.subTest(field=field), self.assertRaises(InventoryError):
                validate_device({**AGENT_DEVICE, field: "SENTINEL_SECRET"})
        with self.assertRaises(InventoryError):
            validate_device({**AGENT_DEVICE, "username": "-----BEGIN OPENSSH PRIVATE KEY-----"})

    def test_password_env_is_a_reference_not_a_value(self):
        expected = {**AGENT_DEVICE, "auth_method": "password-env", "password_env": "FIC_EDGE_PASSWORD"}
        self.assertEqual(validate_device(expected), expected)
        for invalid in ("", "lowercase", "1PREFIX", "HAS-DASH"):
            with self.subTest(invalid=invalid), self.assertRaises(InventoryError):
                validate_device({**expected, "password_env": invalid})

    def test_rejects_duplicates_unsafe_mode_and_symlink(self):
        save_devices(self.path, [AGENT_DEVICE])
        with self.assertRaises(InventoryError):
            save_devices(self.path, [AGENT_DEVICE, AGENT_DEVICE])
        if os.name == "posix":
            os.chmod(self.path, 0o644)
            with self.assertRaises(InventoryError):
                load_devices(self.path)
            self.path.unlink()
            target = self.root / "target.yaml"
            target.write_text("devices: []\n", encoding="utf-8")
            os.chmod(target, 0o600)
            self.path.symlink_to(target)
            with self.assertRaises(InventoryError):
                load_devices(self.path)

    def test_rejects_oversized_malformed_and_non_mapping_yaml(self):
        self.path.write_bytes(b"x" * ((1024 * 1024) + 1))
        os.chmod(self.path, 0o600)
        with self.assertRaises(InventoryError):
            load_devices(self.path)
        for text in ("devices: [", "- not-a-mapping\n", "devices: {}\n"):
            self.path.write_text(text, encoding="utf-8")
            os.chmod(self.path, 0o600)
            with self.subTest(text=text), self.assertRaises(InventoryError):
                load_devices(self.path)

    def test_cleans_temporary_file_after_replace_failure(self):
        with patch("inventory.os.replace", side_effect=OSError("SENTINEL_SECRET")):
            with self.assertRaises(InventoryError) as raised:
                save_devices(self.path, [AGENT_DEVICE])
        self.assertNotIn("SENTINEL_SECRET", str(raised.exception))
        self.assertEqual(list(self.root.glob(".devices.yaml.*.tmp")), [])
```

Also cover wrong owner by patching `inventory.os.getuid`, group/world-writable parent directories, parent symlinks, FIFO/non-regular destinations, duplicate names, invalid ports outside `1..65535`, empty required strings, `password_env` on agent records, missing `password_env` on password-env records, and a mocked successful `os.replace` call with both file and parent `fsync` observed.

- [ ] **Step 2: Run inventory tests and verify the missing-module failure**

Run: `venv/bin/python -m unittest tools/pyez-bridge/tests/test_inventory.py -v`

Expected: FAIL because `inventory.py` does not exist.

- [ ] **Step 3: Implement exact schema validation and safe reads**

Create `tools/pyez-bridge/inventory.py` with these constants, exception, and validation rules:

```python
import os
import re
import stat
import tempfile
from pathlib import Path

import yaml

MAX_INVENTORY_BYTES = 1024 * 1024
ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,127}\Z")
BASE_KEYS = {"name", "host", "port", "username", "auth_method"}
FORBIDDEN_KEYS = {
    "password", "passwd", "ssh_key", "ssh_private_key_file",
    "private_key", "private_key_file", "private_key_material",
}


class InventoryError(Exception):
    def __init__(self, public_message="Device inventory is unsafe or invalid."):
        super().__init__(public_message)
        self.code = "INVENTORY_UNSAFE"
        self.public_message = public_message


def validate_device(value):
    if not isinstance(value, dict):
        raise InventoryError()
    auth_method = value.get("auth_method")
    allowed = BASE_KEYS | ({"password_env"} if auth_method == "password-env" else set())
    if set(value) & FORBIDDEN_KEYS or set(value) - allowed:
        raise InventoryError("Device inventory contains unsupported credential fields.")
    if any(
        isinstance(item, str) and "PRIVATE KEY-----" in item.upper()
        for item in value.values()
    ):
        raise InventoryError("Device inventory contains unsupported credential fields.")
    if auth_method not in {"agent", "password-env"}:
        raise InventoryError("Device authentication method is invalid.")
    for field in ("name", "host", "username"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise InventoryError("Device inventory contains an invalid required field.")
    port = value.get("port", 830)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise InventoryError("Device port is invalid.")
    if auth_method == "password-env":
        env_name = value.get("password_env")
        if not isinstance(env_name, str) or not ENV_NAME.fullmatch(env_name):
            raise InventoryError("Password environment variable name is invalid.")
    elif "password_env" in value:
        raise InventoryError("Agent authentication cannot contain a password reference.")
    result = {key: value[key] for key in ("name", "host")}
    result["port"] = port
    result["username"] = value["username"]
    result["auth_method"] = auth_method
    if auth_method == "password-env":
        result["password_env"] = value["password_env"]
    return result
```

Implement parent and file metadata checks exactly as follows; every caught OS/YAML/Unicode error is replaced with `InventoryError()` and is never interpolated:

```python
def _check_parent(path):
    parent_stat = path.parent.lstat()
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise InventoryError()
    if os.name == "posix":
        if parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & 0o022:
            raise InventoryError()


def _check_existing(path):
    file_stat = path.lstat()
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise InventoryError()
    if os.name == "posix":
        if file_stat.st_uid != os.getuid() or stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise InventoryError()
    if file_stat.st_size > MAX_INVENTORY_BYTES:
        raise InventoryError()
    return file_stat


def _validated_list(data):
    if not isinstance(data, dict) or set(data) != {"devices"} or not isinstance(data["devices"], list):
        raise InventoryError()
    devices = [validate_device(item) for item in data["devices"]]
    names = [item["name"] for item in devices]
    if len(names) != len(set(names)):
        raise InventoryError("Device names must be unique.")
    return devices


def load_devices(path):
    path = Path(path)
    try:
        _check_parent(path)
        if not path.exists():
            return []
        expected = _check_existing(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise InventoryError()
            raw = os.read(fd, MAX_INVENTORY_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_INVENTORY_BYTES:
            raise InventoryError()
        return _validated_list(yaml.safe_load(raw.decode("utf-8")))
    except InventoryError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError):
        raise InventoryError() from None
```

- [ ] **Step 4: Implement same-directory atomic writes**

Add `save_devices` with pre-validation, secure temporary creation, flush/fsync, destination re-check, atomic replacement, final `0600`, parent fsync on POSIX, and unconditional cleanup:

```python
def save_devices(path, devices):
    path = Path(path)
    normalized = _validated_list({"devices": devices})
    temp_path = None
    try:
        _check_parent(path)
        if path.exists() or path.is_symlink():
            _check_existing(path)
        fd, raw_temp = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temp_path = Path(raw_temp)
        os.fchmod(fd, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as stream:
                yaml.safe_dump({"devices": normalized}, stream, default_flow_style=False, sort_keys=False)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try: os.close(fd)
            except OSError: pass
            raise
        if path.exists() or path.is_symlink():
            _check_existing(path)
        os.replace(temp_path, path)
        temp_path = None
        if os.name == "posix":
            os.chmod(path, 0o600, follow_symlinks=False)
            parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(parent_fd)
            finally: os.close(parent_fd)
    except InventoryError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError):
        raise InventoryError() from None
    finally:
        if temp_path is not None:
            try: temp_path.unlink()
            except FileNotFoundError: pass
```

- [ ] **Step 5: Replace the tracked runtime inventory with a safe example**

Delete `tools/pyez-bridge/devices.yaml`. Create `tools/pyez-bridge/devices.example.yaml`:

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

Add this exact repository-root ignore rule to `.gitignore` while leaving the example tracked:

```gitignore
tools/pyez-bridge/devices.yaml
```

- [ ] **Step 6: Run focused tests and inspect tracked files**

Run:

```bash
venv/bin/python -m unittest tools/pyez-bridge/tests/test_inventory.py -v
git ls-files tools/pyez-bridge/devices.yaml tools/pyez-bridge/devices.example.yaml
```

Expected: inventory tests PASS; `git ls-files` lists only `tools/pyez-bridge/devices.example.yaml` after staging.

- [ ] **Step 7: Commit inventory hardening**

```bash
git add .gitignore tools/pyez-bridge/inventory.py tools/pyez-bridge/tests/test_inventory.py tools/pyez-bridge/devices.example.yaml
git rm tools/pyez-bridge/devices.yaml
git commit -m "security: harden device inventory storage"
```

### Task 4: Verified NETCONF connection boundary

**Files:**
- Create: `tools/pyez-bridge/connection.py`
- Create: `tools/pyez-bridge/tests/test_connection.py`

**Interfaces:**
- Consumes: validated device mappings from `inventory.validate_device`, an optional environment mapping, and PyEZ `Device`.
- Produces: `DeviceConnectionError(code, public_message, status)`, `connect_device(device, allow_unknown_hosts=False, environ=None, device_factory=None)`, and `classify_connection_error(error)`.
- `connect_device` returns an opened PyEZ `Device` whose operation timeout is 30 seconds.

- [ ] **Step 1: Write connection policy and classification tests**

Create `tools/pyez-bridge/tests/test_connection.py`:

```python
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

from jnpr.junos.exception import ConnectAuthError, ConnectRefusedError, ConnectTimeoutError
from connection import DeviceConnectionError, classify_connection_error, connect_device

AGENT = {
    "name": "edge", "host": "192.0.2.10", "port": 830,
    "username": "netops", "auth_method": "agent",
}


class UnknownHost(Exception):
    pass
UnknownHost.__name__ = "SSHUnknownHostError"


class ConnectionTests(unittest.TestCase):
    def test_agent_connection_is_strict_and_has_no_explicit_secret(self):
        device = Mock()
        factory = Mock(return_value=device)
        self.assertIs(connect_device(AGENT, device_factory=factory), device)
        kwargs = factory.call_args.kwargs
        self.assertTrue(kwargs["hostkey_verify"])
        self.assertTrue(kwargs["allow_agent"])
        self.assertTrue(kwargs["look_for_keys"])
        self.assertNotIn("passwd", kwargs)
        self.assertNotIn("ssh_private_key_file", kwargs)
        device.open.assert_called_once_with()
        self.assertEqual(device.timeout, 30)

    def test_password_reference_resolves_only_at_connection_time(self):
        record = {**AGENT, "auth_method": "password-env", "password_env": "FIC_EDGE_PASSWORD"}
        factory = Mock(return_value=Mock())
        connect_device(record, environ={"FIC_EDGE_PASSWORD": "SENTINEL_PASSWORD"}, device_factory=factory)
        kwargs = factory.call_args.kwargs
        self.assertEqual(kwargs["passwd"], "SENTINEL_PASSWORD")
        self.assertFalse(kwargs["allow_agent"])
        self.assertFalse(kwargs["look_for_keys"])
        self.assertNotIn("password_env", kwargs)

    def test_missing_password_reference_fails_before_device_construction(self):
        record = {**AGENT, "auth_method": "password-env", "password_env": "FIC_EDGE_PASSWORD"}
        factory = Mock()
        with self.assertRaises(DeviceConnectionError) as raised:
            connect_device(record, environ={}, device_factory=factory)
        factory.assert_not_called()
        self.assertEqual(raised.exception.code, "DEVICE_CREDENTIAL_UNAVAILABLE")
        self.assertNotIn("FIC_EDGE_PASSWORD", str(raised.exception))

    def test_only_explicit_override_disables_host_key_verification(self):
        factory = Mock(return_value=Mock())
        connect_device(AGENT, allow_unknown_hosts=True, device_factory=factory)
        self.assertFalse(factory.call_args.kwargs["hostkey_verify"])

    def test_classification_is_stable_and_redacted(self):
        cases = (
            (UnknownHost("SHA256:SENTINEL"), "DEVICE_IDENTITY_FAILED"),
            (ConnectAuthError(Mock()), "DEVICE_AUTHENTICATION_FAILED"),
            (ConnectRefusedError(Mock()), "DEVICE_UNREACHABLE"),
            (ConnectTimeoutError(Mock()), "DEVICE_UNREACHABLE"),
            (RuntimeError("SENTINEL_SECRET"), "UNEXPECTED_ERROR"),
        )
        for error, code in cases:
            with self.subTest(code=code):
                classified = classify_connection_error(error)
                self.assertEqual(classified.code, code)
                self.assertNotIn("SENTINEL", str(classified))
```

Add a case where `SSHUnknownHostError` appears in `__cause__` or `__context__` beneath a PyEZ `ConnectError`; it must still classify as `DEVICE_IDENTITY_FAILED` without the fingerprint.

- [ ] **Step 2: Run the focused test and verify the missing-module failure**

Run: `venv/bin/python -m unittest tools/pyez-bridge/tests/test_connection.py -v`

Expected: FAIL because `connection.py` does not exist.

- [ ] **Step 3: Implement strict connection construction**

Create `tools/pyez-bridge/connection.py`:

```python
import os

from jnpr.junos import Device
from jnpr.junos.exception import (
    ConnectAuthError, ConnectError, ConnectRefusedError, ConnectTimeoutError,
)

CONNECT_TIMEOUT = 10
OPERATION_TIMEOUT = 30

PUBLIC_ERRORS = {
    "DEVICE_IDENTITY_FAILED": ("NETCONF device identity verification failed.", 502),
    "DEVICE_AUTHENTICATION_FAILED": ("NETCONF device authentication failed.", 502),
    "DEVICE_CREDENTIAL_UNAVAILABLE": ("The configured device credential is unavailable.", 503),
    "DEVICE_UNREACHABLE": ("The NETCONF device is unreachable.", 502),
    "DEVICE_OPERATION_FAILED": ("The NETCONF device operation failed.", 502),
    "UNEXPECTED_ERROR": ("An unexpected bridge error occurred.", 500),
}


class DeviceConnectionError(Exception):
    def __init__(self, code):
        message, status = PUBLIC_ERRORS[code]
        super().__init__(message)
        self.code = code
        self.public_message = message
        self.status = status


def _error_chain(error):
    seen = set()
    current = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def classify_connection_error(error):
    chain = tuple(_error_chain(error))
    if any(item.__class__.__name__ == "SSHUnknownHostError" for item in chain):
        return DeviceConnectionError("DEVICE_IDENTITY_FAILED")
    if any(isinstance(item, ConnectAuthError) for item in chain):
        return DeviceConnectionError("DEVICE_AUTHENTICATION_FAILED")
    if any(isinstance(item, (ConnectRefusedError, ConnectTimeoutError, ConnectError)) for item in chain):
        return DeviceConnectionError("DEVICE_UNREACHABLE")
    return DeviceConnectionError("UNEXPECTED_ERROR")


def connect_device(device, allow_unknown_hosts=False, environ=None, device_factory=None):
    environ = os.environ if environ is None else environ
    device_factory = Device if device_factory is None else device_factory
    kwargs = {
        "host": device["host"],
        "user": device["username"],
        "port": device.get("port", 830),
        "conn_open_timeout": CONNECT_TIMEOUT,
        "hostkey_verify": not allow_unknown_hosts,
    }
    if device["auth_method"] == "agent":
        kwargs.update(allow_agent=True, look_for_keys=True)
    else:
        value = environ.get(device["password_env"])
        if not value:
            raise DeviceConnectionError("DEVICE_CREDENTIAL_UNAVAILABLE")
        kwargs.update(passwd=value, allow_agent=False, look_for_keys=False)
    try:
        connection = device_factory(**kwargs)
        connection.open()
        connection.timeout = OPERATION_TIMEOUT
        return connection
    except DeviceConnectionError:
        raise
    except Exception as error:
        raise classify_connection_error(error) from None
```

Do not pass a private-key path. Do not inspect or return the unknown key's fingerprint. Preserve PyEZ's standard `~/.ssh/config` and known-host behavior by not overriding its SSH config path.

- [ ] **Step 4: Run focused connection tests**

Run: `venv/bin/python -m unittest tools/pyez-bridge/tests/test_connection.py -v`

Expected: PASS with strict verification in the default call and false only for the explicit boolean argument.

- [ ] **Step 5: Commit the connection boundary**

```bash
git add tools/pyez-bridge/connection.py tools/pyez-bridge/tests/test_connection.py
git commit -m "security: verify NETCONF device identity"
```

### Task 5: Integrate safe inventory, strict connection policy, and redacted route errors

**Files:**
- Modify: `tools/pyez-bridge/app.py`
- Modify: `tools/pyez-bridge/tests/test_app_security.py`
- Create: `tools/pyez-bridge/tests/test_error_redaction.py`

**Interfaces:**
- Consumes: `inventory.load_devices/save_devices/validate_device/InventoryError` and `connection.connect_device/DeviceConnectionError`.
- Produces: health field `host_key_verification`, startup config `ALLOW_UNKNOWN_HOSTS: bool`, and public error bodies `{ ok: false, error: string, code: string }` with optional safe `line` or `path`.

- [ ] **Step 1: Make integration fixtures owner-only and add failing strict-mode tests**

In `tools/pyez-bridge/tests/test_app_security.py`, change every direct inventory fixture write to a helper that enforces `0600`:

```python
def write_inventory(path, text):
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)
```

Add tests for health mode, secret-field rejection, safe list output, and the CLI flag:

```python
def test_health_reports_strict_host_key_verification(self):
    body = self.client.get("/health").get_json()
    self.assertEqual(body["host_key_verification"], "strict")
    expected_permissions = "enforced" if os.name == "posix" else "unavailable-platform"
    self.assertEqual(body["inventory_posix_permissions"], expected_permissions)

def test_device_api_accepts_only_credential_references(self):
    for field in ("password", "passwd", "ssh_key", "ssh_private_key_file"):
        response = self.client.post("/devices", headers=self.auth, json={
            "name": f"edge-{field}", "host": "192.0.2.10", "port": 830,
            "username": "netops", "auth_method": "agent", field: "SENTINEL_SECRET",
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["code"], "INVENTORY_UNSAFE")
        self.assertNotIn("SENTINEL_SECRET", response.get_data(as_text=True))

def test_development_override_is_visible_in_health(self):
    override = create_app({
        "TESTING": True, "BRIDGE_TOKEN": TOKEN,
        "BRIDGE_ALLOWED_ORIGINS": [ALLOWED_ORIGIN],
        "ALLOW_UNKNOWN_HOSTS": True,
    })
    self.assertEqual(
        override.test_client().get("/health").get_json()["host_key_verification"],
        "disabled-development",
    )
```

Patch `app_module.connect_device` and assert `_connect` forwards `allow_unknown_hosts=False` by default and `True` only when the application config contains `ALLOW_UNKNOWN_HOSTS=True`.

- [ ] **Step 2: Add endpoint-wide redaction tests**

Create `tools/pyez-bridge/tests/test_error_redaction.py`. Its setup creates a mode-`0600` agent inventory, authenticated client, and this route table:

```python
ROUTES = (
    ("get", "/devices/edge/facts", None),
    ("post", "/devices/edge/unlock", {}),
    ("post", "/devices/edge/load", {"format": "set", "config": "set system host-name edge"}),
    ("get", "/devices/edge/diff", None),
    ("post", "/devices/edge/commit-check", {}),
    ("post", "/devices/edge/commit", {"comment": "safe"}),
    ("post", "/devices/edge/confirm", {}),
    ("post", "/devices/edge/rollback", {"rollback_id": 0}),
    ("get", "/devices/edge/pull-config", None),
    ("get", "/devices/edge/policy-stats", None),
    ("get", "/devices/edge/app-usage", None),
)
SENTINELS = (
    "SENTINEL_PASSWORD", "/home/user/.ssh/SENTINEL_KEY",
    "-----BEGIN OPENSSH PRIVATE KEY-----", "SHA256:SENTINEL_FINGERPRINT",
    "set system root-authentication SENTINEL_COMMAND",
)
```

For every route, patch `_connect` first with `DeviceConnectionError('DEVICE_IDENTITY_FAILED')`, then with `RuntimeError(' '.join(SENTINELS))`. Assert status is non-2xx, the first response code is `DEVICE_IDENTITY_FAILED`, the second is `UNEXPECTED_ERROR`, and neither response body nor captured stdout/stderr contains any sentinel. Add focused tests that inject `CommitError`, `ConfigLoadError`, and `RpcError` messages containing all sentinels after connection and assert `DEVICE_OPERATION_FAILED` without `details` or raw exception text.

- [ ] **Step 3: Run integration tests and confirm current reflection failures**

Run:

```bash
venv/bin/python -m unittest \
  tools/pyez-bridge/tests/test_app_security.py \
  tools/pyez-bridge/tests/test_error_redaction.py -v
```

Expected: FAIL because the current app uses ordinary inventory I/O, omits strict-mode health, accepts stored secrets, and reflects exception strings.

- [ ] **Step 4: Replace app-local inventory and connection implementations**

In `tools/pyez-bridge/app.py`, remove `yaml`, direct `Device`, connection-timeout constants, and the bodies that read/write YAML or assemble PyEZ keyword arguments. Import:

```python
from flask import Blueprint, Flask, current_app, jsonify, request
from connection import DeviceConnectionError, connect_device
from inventory import InventoryError, load_devices, save_devices, validate_device
```

Keep `DEVICES_FILE`, then implement wrappers so existing route lookup remains small:

```python
def _load_devices():
    return load_devices(DEVICES_FILE)

def _save_devices(devices):
    save_devices(DEVICES_FILE, devices)

def _connect(dev_dict):
    return connect_device(
        dev_dict,
        allow_unknown_hosts=bool(current_app.config.get("ALLOW_UNKNOWN_HOSTS", False)),
    )

def _safe_device_info(dev_dict):
    credential_ready = (
        True if dev_dict["auth_method"] == "agent"
        else bool(os.environ.get(dev_dict["password_env"]))
    )
    return {
        "name": dev_dict["name"], "host": dev_dict["host"],
        "port": dev_dict["port"], "username": dev_dict["username"],
        "auth_method": dev_dict["auth_method"],
        "credential_ready": credential_ready,
    }
```

Do not return `password_env`; the boolean is the only credential readiness information.

- [ ] **Step 5: Centralize stable public error responses**

Replace `_error_response(message, status=400, details=None)` with:

```python
SAFE_FAILURES = {
    "INVENTORY_UNSAFE": ("Device inventory is unsafe or invalid.", 400),
    "DEVICE_IDENTITY_FAILED": ("NETCONF device identity verification failed.", 502),
    "DEVICE_AUTHENTICATION_FAILED": ("NETCONF device authentication failed.", 502),
    "DEVICE_CREDENTIAL_UNAVAILABLE": ("The configured device credential is unavailable.", 503),
    "DEVICE_UNREACHABLE": ("The NETCONF device is unreachable.", 502),
    "DEVICE_OPERATION_FAILED": ("The NETCONF device operation failed.", 502),
    "UNEXPECTED_ERROR": ("An unexpected bridge error occurred.", 500),
}

def _error_response(message, status=400, code=None, line=None, path=None):
    body = {"ok": False, "error": message}
    if code: body["code"] = code
    if isinstance(line, int): body["line"] = line
    if isinstance(path, str): body["path"] = path
    return jsonify(body), status

def _safe_failure(code, line=None, path=None):
    message, status = SAFE_FAILURES[code]
    return _error_response(message, status, code=code, line=line, path=path)
```

Register typed handlers during `create_app` so inventory failures from any route are safe:

```python
@app.errorhandler(InventoryError)
def handle_inventory_error(_error):
    return _safe_failure("INVENTORY_UNSAFE")

@app.errorhandler(DeviceConnectionError)
def handle_connection_error(error):
    return _safe_failure(error.code)
```

Keep existing explicit validation messages only when they contain no request values. Never pass `str(error)` or a request field to `_error_response`.

- [ ] **Step 6: Validate POST records and remove every raw exception reflection**

Build POST entries only through `validate_device`:

```python
try:
    entry = validate_device({
        "name": (data.get("name") or "").strip(),
        "host": (data.get("host") or "").strip(),
        "port": data.get("port", 830),
        "username": (data.get("username") or "").strip(),
        "auth_method": data.get("auth_method"),
        **({"password_env": data.get("password_env")} if "password_env" in data else {}),
        **{key: data[key] for key in data if key not in {
            "name", "host", "port", "username", "auth_method", "password_env"
        }},
    })
except InventoryError:
    return _safe_failure("INVENTORY_UNSAFE")
```

Across `device_facts`, `unlock_config`, `load_config`, `config_diff`, `commit_check`, `commit`, `confirm_commit`, `rollback`, `pull_config`, `policy_stats`, and `app_usage`, use only this catch policy:

```python
except DeviceConnectionError as error:
    return _safe_failure(error.code)
except (CommitError, ConfigLoadError, LockError, UnlockError, RpcError):
    return _safe_failure("DEVICE_OPERATION_FAILED")
except Exception:
    return _safe_failure("UNEXPECTED_ERROR")
```

Preserve endpoint-specific cleanup before returning. In line-by-line configuration load, replace raw logging and raw `errors` entries with safe line metadata:

```python
except ConfigLoadError:
    errors.append({"line": i, "code": "DEVICE_OPERATION_FAILED"})
```

Delete prints of configuration lines and exception messages. In application-usage fallback logic, catch without binding the exception (`except Exception:`) and emit only the existing safe operation category.

- [ ] **Step 7: Add the startup-only development override and warnings**

In `create_app`, record:

```python
app.config["ALLOW_UNKNOWN_HOSTS"] = bool(supplied.get("ALLOW_UNKNOWN_HOSTS", False))
```

Return health mode without exposing configuration paths or credentials:

```python
return jsonify({
    "status": "ok", "version": "1.0.0", "service": "pyez-bridge",
    "inventory_posix_permissions": (
        "enforced" if os.name == "posix" else "unavailable-platform"
    ),
    "host_key_verification": (
        "disabled-development"
        if current_app.config["ALLOW_UNKNOWN_HOSTS"] else "strict"
    ),
})
```

Add only this CLI switch; do not read an environment variable for it:

```python
parser.add_argument(
    "--insecure-allow-unknown-hosts",
    action="store_true",
    help="DEVELOPMENT ONLY: disable NETCONF SSH host-key verification",
)
```

Pass `args.insecure_allow_unknown_hosts` to `create_app` as `ALLOW_UNKNOWN_HOSTS`. When true, print this constant warning, which contains no device detail:

```python
INSECURE_HOST_KEY_WARNING = (
    "WARNING: NETCONF SSH HOST-KEY VERIFICATION IS DISABLED.\n"
    "A network attacker can impersonate managed devices. Development use only."
)
```

Do not print the inventory path. Keep the existing generated bridge access-token startup behavior because localhost bearer authorization is outside this issue's scope.

- [ ] **Step 8: Run Python integration and redaction tests**

Run:

```bash
venv/bin/python -m unittest discover -s tools/pyez-bridge/tests -v
```

Expected: all inventory, connection, Flask security, validation, rate-limit, and redaction tests PASS. No captured output contains a sentinel.

- [ ] **Step 9: Commit route integration**

```bash
git add tools/pyez-bridge/app.py tools/pyez-bridge/tests/test_app_security.py tools/pyez-bridge/tests/test_error_redaction.py
git commit -m "security: redact bridge credential failures"
```

### Task 6: Secret-free device registration UI and verified-host guidance

**Files:**
- Create: `public/utils/device-registration.js`
- Modify: `public/components/LLMSettings.jsx`
- Modify: `tests/credential-security.test.js`
- Modify: `tools/pyez-bridge/README.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: UI form `{ name, host, port, username, auth_method, password_env }` and health field `host_key_verification`.
- Produces: `EMPTY_DEVICE_REGISTRATION`, `DeviceRegistrationError`, and `buildDeviceRegistration(form) -> secret-free request object`.

- [ ] **Step 1: Add failing registration and UI source tests**

Extend `tests/credential-security.test.js`:

```js
import {
  EMPTY_DEVICE_REGISTRATION,
  buildDeviceRegistration,
} from '../public/utils/device-registration.js';

it('builds agent registrations without secret fields', () => {
  expect(buildDeviceRegistration({
    ...EMPTY_DEVICE_REGISTRATION,
    name: ' edge ', host: ' 192.0.2.10 ', username: ' netops ',
  })).toEqual({
    name: 'edge', host: '192.0.2.10', port: 830,
    username: 'netops', auth_method: 'agent',
  });
});

it('includes only the password environment reference for password-env', () => {
  expect(buildDeviceRegistration({
    name: 'edge', host: '192.0.2.10', port: 830, username: 'netops',
    auth_method: 'password-env', password_env: 'FIC_EDGE_PASSWORD',
  })).toMatchObject({ auth_method: 'password-env', password_env: 'FIC_EDGE_PASSWORD' });
});

it('rejects invalid password environment names without echoing input', () => {
  expect(() => buildDeviceRegistration({
    name: 'edge', host: '192.0.2.10', port: 830, username: 'netops',
    auth_method: 'password-env', password_env: 'bad-SENTINEL',
  })).toThrow('Password environment variable name is invalid.');
  try { buildDeviceRegistration({
    name: 'edge', host: '192.0.2.10', port: 830, username: 'netops',
    auth_method: 'password-env', password_env: 'bad-SENTINEL',
  }); } catch (error) { expect(error.message).not.toContain('SENTINEL'); }
});

it('removes password and private-key controls from the bridge UI', () => {
  const source = read('public/components/LLMSettings.jsx');
  expect(source).not.toMatch(/newDevice\.(?:password|ssh_key)/);
  expect(source).not.toContain('SSH Key Path');
  expect(source).toContain('Password Environment Variable');
  expect(source).toContain('disabled-development');
});
```

- [ ] **Step 2: Run the focused test and verify missing helper/legacy UI failures**

Run: `npx vitest run tests/credential-security.test.js`

Expected: FAIL because `device-registration.js` is missing and the UI still contains password/private-key controls.

- [ ] **Step 3: Implement the request builder**

Create `public/utils/device-registration.js`:

```js
const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/;

export const EMPTY_DEVICE_REGISTRATION = Object.freeze({
  name: '', host: '', port: 830, username: '',
  auth_method: 'agent', password_env: '',
});

export class DeviceRegistrationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DeviceRegistrationError';
  }
}

export function buildDeviceRegistration(form = {}) {
  const name = String(form.name || '').trim();
  const host = String(form.host || '').trim();
  const username = String(form.username || '').trim();
  const port = Number(form.port || 830);
  const authMethod = form.auth_method || 'agent';
  if (!name || !host || !username) {
    throw new DeviceRegistrationError('Name, host, and username are required.');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new DeviceRegistrationError('Device port is invalid.');
  }
  if (!['agent', 'password-env'].includes(authMethod)) {
    throw new DeviceRegistrationError('Authentication method is invalid.');
  }
  const result = { name, host, port, username, auth_method: authMethod };
  if (authMethod === 'password-env') {
    const passwordEnv = String(form.password_env || '').trim();
    if (!ENV_NAME.test(passwordEnv)) {
      throw new DeviceRegistrationError('Password environment variable name is invalid.');
    }
    result.password_env = passwordEnv;
  }
  return result;
}
```

- [ ] **Step 4: Replace device credential controls and display override state**

In `public/components/LLMSettings.jsx`, import `EMPTY_DEVICE_REGISTRATION` and `buildDeviceRegistration`, then use:

```js
const [newDevice, setNewDevice] = useState({ ...EMPTY_DEVICE_REGISTRATION });
const [hostKeyVerification, setHostKeyVerification] = useState('strict');
```

In both health success paths, record only the enumerated value:

```js
setHostKeyVerification(
  health.host_key_verification === 'disabled-development'
    ? 'disabled-development' : 'strict'
);
```

Build POST JSON through the helper and clear the whole form on success:

```js
let payload;
try { payload = buildDeviceRegistration(newDevice); }
catch (error) {
  setBridgeResultOk(false);
  setBridgeTestResult(error.message);
  return;
}

// after a successful response
setNewDevice({ ...EMPTY_DEVICE_REGISTRATION });
```

Replace Password and SSH Key Path with an authentication `<select>` containing exact values `agent` and `password-env`. Render a text field labelled `Password Environment Variable` only when `newDevice.auth_method === 'password-env'`. Render this persistent warning whenever the health response reports the override:

```jsx
{hostKeyVerification === 'disabled-development' && (
  <div role="alert" style={{ color: 'var(--error)', marginBottom: 12 }}>
    Warning: NETCONF SSH host-key verification is disabled for development.
    Devices can be impersonated on the network.
  </div>
)}
```

Change the empty list copy to `No devices configured. Add one below or create the runtime devices.yaml.` Never show `password_env` in the list or error message.

- [ ] **Step 5: Replace insecure setup guidance**

Rewrite `tools/pyez-bridge/README.md` device setup to include these exact operational sequences:

```bash
cp devices.example.yaml devices.yaml
chmod 600 devices.yaml

eval "$(ssh-agent -s)"
ssh-add ~/.ssh/pyez_rsa

export FIC_SRX_PROD_PASSWORD='set this in the bridge process environment'

ssh-keyscan -p 830 192.0.2.10 > /tmp/srx-lab-01.hostkey
ssh-keygen -lf /tmp/srx-lab-01.hostkey
```

Immediately after `ssh-keyscan`, state that the collected key is untrusted until its fingerprint is compared through an independent channel such as the device console or asset-management record. Only after a match may the operator add it to `~/.ssh/known_hosts`; nonstandard port entries are stored as `[192.0.2.10]:830`. State that unknown or changed keys fail with `DEVICE_IDENTITY_FAILED` and must be investigated, not deleted/re-enrolled automatically.

Document this OpenSSH example outside the project inventory:

```sshconfig
Host srx-lab-01
  HostName 192.0.2.10
  Port 830
  User netops
  IdentityFile ~/.ssh/pyez_rsa
  IdentitiesOnly yes
```

Document `--insecure-allow-unknown-hosts` under a `Development-only override` heading, including its startup warning and health/UI state. State that it never disables authentication or localhost controls and must not be used for production device access.

Add a `Legacy inventory migration` subsection: a runtime file containing `password`, `passwd`, `ssh_key`, `ssh_private_key_file`, or private-key material is rejected with `INVENTORY_UNSAFE`. Direct operators to load private keys into `ssh-agent` or select them in `~/.ssh/config`, replace stored passwords with `auth_method: password-env` plus `password_env`, remove the secret fields, and restore mode `0600`. State that the bridge does not silently repair an unsafe file because it may already have been exposed.

Update the root `README.md` PyEZ paragraph to say the runtime inventory contains only metadata/credential references, LLM and bridge tokens are tab-session values, and NETCONF host keys are verified by default; link to `tools/pyez-bridge/README.md` for enrollment.

- [ ] **Step 6: Run browser tests and production build**

Run:

```bash
npx vitest run tests/llm-settings.test.js tests/credential-security.test.js
node tests/llm-translate.test.js
npm run build
```

Expected: both Vitest suites PASS, the self-running translation suite passes, and Vite completes a production build.

- [ ] **Step 7: Commit UI and documentation**

```bash
git add public/utils/device-registration.js public/components/LLMSettings.jsx tests/credential-security.test.js tools/pyez-bridge/README.md README.md
git commit -m "security: remove stored device credentials from UI"
```

### Task 7: Extend CI and run the complete security gate

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/credential-security.test.js`

**Interfaces:**
- Consumes: all prior task tests and repository sources.
- Produces: CI execution of both new Vitest suites and regression scans for the accepted security invariants.

- [ ] **Step 1: Add final source-invariant tests before changing CI**

Extend `tests/credential-security.test.js` with repository scans:

```js
it('has no tracked runtime device inventory', () => {
  expect(read('tools/pyez-bridge/devices.example.yaml')).toContain('192.0.2.10');
  expect(read('.gitignore')).toContain('tools/pyez-bridge/devices.yaml');
});

it('contains no raw bridge exception reflection', () => {
  const source = read('tools/pyez-bridge/app.py');
  expect(source).not.toMatch(/details\s*=\s*str\s*\(/);
  expect(source).not.toMatch(/f["'][^"'\n]*\{(?:e|exc|error)\}/);
  expect(source).not.toMatch(/print\([^\n]*(?:line\[|str\()/);
});

it('exposes no inventory password or private-key fields', () => {
  const example = read('tools/pyez-bridge/devices.example.yaml');
  expect(example).not.toMatch(/^\s+(?:password|passwd|ssh_key|ssh_private_key_file):/m);
  const ui = read('public/components/LLMSettings.jsx');
  expect(ui).not.toMatch(/newDevice\.(?:password|ssh_key)/);
});
```

Add this assertion, which proves the runtime file is not tracked without invoking a shell:

```js
it('does not track the runtime inventory', () => {
  expect(() => execFileSync(
    'git',
    ['ls-files', '--error-unmatch', 'tools/pyez-bridge/devices.yaml'],
    { stdio: 'pipe' },
  )).toThrow();
});
```

- [ ] **Step 2: Add the new Vitest files to CI's explicit list**

Append these lines to the `Run Vitest suites` command in `.github/workflows/ci.yml`:

```yaml
          tests/llm-settings.test.js
          tests/credential-security.test.js
```

The Python discovery command already includes every new `test_*.py` file; do not duplicate it.

- [ ] **Step 3: Run the complete local gate from a clean dependency environment**

Run:

```bash
npx vitest run \
  tests/context-reducers.test.js \
  tests/triage.test.js \
  tests/workflow-steps.test.js \
  tests/junos-serialization.test.js \
  tests/junos-validation.test.js \
  tests/srx-injection-defense.test.js \
  tests/conversion-security.test.js \
  tests/conversion-output.test.js \
  tests/conversion-enforcement.test.js \
  tests/project-io.test.js \
  tests/conversion-consumers.test.js \
  tests/llm-settings.test.js \
  tests/credential-security.test.js
for test_file in tests/*.test.js; do
  if grep -q "from 'vitest'" "$test_file"; then continue; fi
  node "$test_file"
done
venv/bin/python -m unittest discover -s tools/pyez-bridge/tests -v
npm run build
npm audit --audit-level=high
venv/bin/python -m pip check
git diff --check
git status --short
```

Expected: 13 Vitest files PASS, every self-running JavaScript assertion passes, every bridge unittest passes, Vite builds, npm reports zero high/critical vulnerabilities, pip reports no broken requirements, diff check is silent, and status lists only the intended CI/test changes before commit.

- [ ] **Step 4: Commit CI coverage**

```bash
git add .github/workflows/ci.yml tests/credential-security.test.js
git commit -m "ci: enforce credential security invariants"
```

### Task 8: Review, publish, merge, and clean up issue #9

**Files:**
- Review: all changes from `main...agent/issue-9-secure-credentials`
- No new source file is expected unless review or CI exposes a concrete defect.

**Interfaces:**
- Consumes: completed task commits and the full local verification output.
- Produces: a reviewed GitHub pull request linked to issue #9, green PR CI, squash merge, green post-merge main CI, and removal of the feature worktree/branches.

- [ ] **Step 1: Perform a fresh security review of the complete branch**

Run:

```bash
git diff --stat main...HEAD
git diff --check main...HEAD
git log --oneline main..HEAD
git grep -nE 'apiKey.*localStorage|localStorage.*apiKey|password:|passwd:|ssh_key:|ssh_private_key_file:' -- ':!docs/superpowers/**' ':!tools/pyez-bridge/devices.example.yaml'
git grep -nE 'details=str\(|f"[^"\n]*\{(e|exc|error)\}' -- tools/pyez-bridge
```

Expected: only intended files/commits appear; diff check is silent; credential grep matches only explicit rejection tests/schema deny-lists or unrelated firewall configuration concepts; raw exception grep returns no route reflections.

- [ ] **Step 2: Use the required review and verification skills**

Invoke `superpowers:requesting-code-review` for a requirements and whole-branch review. Resolve every Critical or Important finding with a focused red-green cycle and a separate commit. Then invoke `superpowers:verification-before-completion` and rerun the entire Task 7 gate from fresh command output.

- [ ] **Step 3: Push the feature branch and open the pull request**

Use `github:yeet` to confirm the commit scope, push `agent/issue-9-secure-credentials`, and open a draft pull request with:

```text
Title: security: secure credentials and verify NETCONF device identity

Body:
## Summary
- keep LLM API keys in tab-session storage and migrate legacy persistent keys
- replace stored device secrets with agent/environment references and atomic owner-only inventory handling
- verify NETCONF host keys by default and redact bridge failures

## Verification
- full Vitest and self-running JavaScript suites
- full PyEZ bridge unittest suite
- production Vite build
- npm audit and pip check

Closes #9
```

- [ ] **Step 4: Inspect PR CI and fix failures systematically**

Use `github:gh-fix-ci` to inspect the pull request checks and logs. If a check fails, invoke `superpowers:systematic-debugging`, reproduce locally, add or update a regression test, commit the minimal fix, push, and wait for the replacement checks. Expected: Web and PyEZ bridge jobs both succeed.

- [ ] **Step 5: Mark ready and squash-merge after green CI**

Confirm the PR diff still contains only issue #9 work, mark it ready for review, and squash-merge with the repository's normal GitHub workflow. Expected: issue #9 closes automatically through `Closes #9`.

- [ ] **Step 6: Verify post-merge main and clean worktree state**

Wait for the CI workflow on the new `main` commit and confirm both jobs succeed. From the primary checkout, fast-forward `main`, remove `.worktrees/issue-9-secure-credentials`, delete the local feature branch, and verify the remote feature branch was removed. Finish with:

```bash
git status --short
git worktree list
git branch --list 'agent/issue-9-secure-credentials'
git ls-remote --heads origin agent/issue-9-secure-credentials
```

Expected: primary `main` is clean at the merged commit, the issue #9 worktree is absent, and neither local nor remote feature branch remains.
